"""Parse ``CMakeLists.txt`` files to extract C/C++ dependency information.

CMake is a build DSL, not a package manifest, so this is a *best-effort* parser:
it recognizes the most common dependency-declaring commands
(``project``, ``find_package``, ``add_library``, ``target_link_libraries``) with
simple argument extraction. It deliberately does NOT evaluate CMake logic
(variables, conditionals, generator expressions) — the goal is to surface the
library names a project depends on so they can be fed to the same online
vulnerability sources used for Java.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional


def _strip_comments(text: str) -> str:
    """Remove ``#`` line comments and merge multi-line parenthesized commands.

    A CMake command such as ``target_link_libraries(app\\n PRIVATE a b c\\n)`` spans
    several physical lines; we join lines while parentheses are unbalanced so the
    per-command regexes see the whole argument list.

    同时处理 CMake 的行续行符 ``\\``：以 ``\\`` 结尾的行视为未完成、继续累积，
    即使其括号已经平衡（例如参数列表跨多行用 ``\\`` 续行的情况）。
    """
    out_lines = []
    depth = 0
    buf = ""
    for raw in text.splitlines():
        line = raw
        hash_idx = line.find("#")
        if hash_idx != -1:
            line = line[:hash_idx]
        line = line.strip()
        if not line:
            continue
        # 行尾反斜杠续行：去掉续行符后继续累积，不立即 flush
        cont = line.endswith("\\")
        if cont:
            line = line[:-1].strip()
            if not line:
                continue
        buf = f"{buf} {line}".strip() if buf else line
        depth += line.count("(") - line.count(")")
        if not cont and depth <= 0:
            out_lines.append(buf)
            buf = ""
    if buf:
        out_lines.append(buf)
    return "\n".join(out_lines)


def _args_of(command: str, line: str) -> Optional[list[str]]:
    """From a line like ``find_package(Foo 1.2 REQUIRED)`` return ['Foo','1.2','REQUIRED'].

    - CMake 命令名不区分大小写（``project`` / ``PROJECT`` / ``Project`` 等价），
      故按 ``re.I`` 忽略大小写。
    - 通过括号深度匹配找到与命令名左括号**配对**的右括号，正确处理生成表达式
      ``$<...>``、嵌套括号等；若（极端情况下）未找到配对的右括号，则退化为取
      左括号后的全部内容，避免整个命令被漏解析而丢失库名/依赖名（例如多行命令
      未被正确合并时，至少仍能拿到第一个参数）。
    """
    m = re.search(r"\b" + re.escape(command) + r"\s*\(", line, re.I)
    if not m:
        return None
    start = m.end()  # 命令名左括号之后的位置
    depth = 1
    i = start
    n = len(line)
    close = -1
    while i < n:
        c = line[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                close = i
                break
        i += 1
    inner = line[start:] if close == -1 else line[start:close]
    # split on whitespace but keep quoted segments together
    parts = re.findall(r'"[^"]*"|\S+', inner)
    return [p.strip('"') for p in parts]


@dataclass
class CMakeProject:
    path: str
    projects: list = field(default_factory=list)        # list[(name, version)]
    find_packages: list = field(default_factory=list)    # list[(name, version)]
    local_libs: set = field(default_factory=set)         # library targets defined here
    link_items: list = field(default_factory=list)       # list[(target, [items])]


def parse_cmake_text(text: str, path: str = "") -> CMakeProject:
    clean = _strip_comments(text)
    proj = CMakeProject(path=path)

    for line in clean.splitlines():
        low = line.strip()
        # CMake 命令名不区分大小写，且允许命令名与左括号之间存在空格
        # （如 `project (Foo)` / `PROJECT(Foo)`），因此用正则忽略大小写并允许 `\s*`。
        if re.match(r"^project\s*\(", low, re.I):
            args = _args_of("project", line)
            if args:
                name = args[0]
                version = None
                if len(args) > 1 and re.match(r"\d", args[1]):
                    version = args[1]
                else:
                    # look for VERSION keyword
                    for i, a in enumerate(args):
                        if a.upper() == "VERSION" and i + 1 < len(args):
                            version = args[i + 1]
                            break
                proj.projects.append((name, version))
        elif re.match(r"^find_package\s*\(", low, re.I):
            args = _args_of("find_package", line)
            if args:
                name = args[0]
                version = None
                for i, a in enumerate(args):
                    if a.upper() == "VERSION" and i + 1 < len(args):
                        version = args[i + 1]
                        break
                    if re.match(r"^\d", a):
                        version = a
                        break
                # skip COMPONENTS / CONFIG / REQUIRED noise by validating name shape
                if re.match(r"^[A-Za-z_][\w.\-:]*$", name):
                    proj.find_packages.append((name, version))
        elif re.match(r"^add_library\s*\(", low, re.I):
            args = _args_of("add_library", line)
            if args:
                target = args[0]
                # alias/imported library names still count as local targets
                proj.local_libs.add(target)
        elif re.match(r"^target_link_libraries\s*\(", low, re.I):
            args = _args_of("target_link_libraries", line)
            if args:
                target = args[0]
                items = [a for a in args[1:]
                         if a.upper() not in ("PRIVATE", "PUBLIC", "INTERFACE", "LINK_PRIVATE", "LINK_PUBLIC")]
                proj.link_items.append((target, items))

    return proj


def parse_cmake_file(path: str) -> CMakeProject:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return parse_cmake_text(f.read(), path=path)


def external_dependencies(projects: list[CMakeProject]) -> list[tuple[str, Optional[str]]]:
    """Return unique external dependency (name, version) pairs.

    An external dependency is a ``find_package`` name or a ``target_link_libraries``
    item that is neither a library target defined in these CMake files nor a
    project target.
    """
    local = set()
    project_names = set()
    for p in projects:
        local |= p.local_libs
        for name, _ in p.projects:
            project_names.add(name)

    found = {}
    for p in projects:
        for name, version in p.find_packages:
            found.setdefault(name, version)
        for _target, items in p.link_items:
            for it in items:
                # skip absolute paths, flags, and locally-defined targets
                if it.startswith(("/ ", "-", "$", "${")) or it.startswith("/"):
                    continue
                if it in local or it in project_names:
                    continue
                if not re.match(r"^[A-Za-z_][\w.\-:]*$", it):
                    continue
                found.setdefault(it, None)
    return [(k, v) for k, v in found.items()]


def collect_cmake(target: str) -> list[CMakeProject]:
    files = []
    if os.path.isfile(target):
        if os.path.basename(target).lower() == "cmakelists.txt":
            files = [target]
    else:
        for root, _dirs, fnames in os.walk(target):
            if "CMakeLists.txt" in fnames:
                files.append(os.path.join(root, "CMakeLists.txt"))
    return [parse_cmake_file(f) for f in sorted(files)]
