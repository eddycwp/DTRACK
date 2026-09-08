"""Scan a directory tree for C/C++ library binaries (dynamic and static).

Extracts the library name and version from the file name using common
conventions (e.g. ``libpng.so.16.0.0``, ``zlib.dll``, ``libssl.a``,
``boost_system.lib``). Produces ``LibFile`` records that the C/C++ analyzer
turns into ``Component`` objects.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

# Skip noisy build/dependency trees.
_SKIP_DIRS = {".git", "node_modules", "build", "target", ".venv", "venv", "__pycache__", ".idea", ".vs"}

_DYNAMIC_UNIX = re.compile(
    r"^(?P<prefix>lib)?(?P<name>[A-Za-z0-9_+.\-]+?)\.(so|dylib)"
    r"(?:\.(?P<ver>\d[\d.]*)(?:[\w.\-]*)?)?$"
)
_DYNAMIC_WIN = re.compile(
    r"^(?P<prefix>lib)?(?P<name>.+?)(?:-(?P<ver>\d[\d.]*))?\.dll$"
)
_STATIC_UNIX = re.compile(
    r"^(?P<prefix>lib)?(?P<name>.+?)(?:-(?P<ver>\d[\d.]*))?\.a$"
)
_STATIC_WIN = re.compile(
    r"^(?P<prefix>lib)?(?P<name>.+?)(?:-(?P<ver>\d[\d.]*))?\.lib$"
)


@dataclass
class LibFile:
    name: str
    version: Optional[str]
    lib_type: str          # "dynamic" | "static"
    path: str


def _strip_prefix(name: str) -> str:
    if name.startswith("lib") and len(name) > 3:
        return name[3:]
    return name


def classify(filename: str) -> Optional[LibFile]:
    base = os.path.basename(filename)
    low = base.lower()

    m = _DYNAMIC_UNIX.match(base)
    if m:
        name = _strip_prefix(m.group("name"))
        return LibFile(name or m.group("name"), m.group("ver"), "dynamic", filename)

    m = _DYNAMIC_WIN.match(base)
    if m:
        name = _strip_prefix(m.group("name"))
        return LibFile(name or m.group("name"), m.group("ver"), "dynamic", filename)

    m = _STATIC_UNIX.match(base)
    if m and not low.endswith(".dylib") and not low.endswith(".dll"):
        name = _strip_prefix(m.group("name"))
        return LibFile(name or m.group("name"), m.group("ver"), "static", filename)

    m = _STATIC_WIN.match(base)
    if m and not low.endswith(".dll"):
        name = _strip_prefix(m.group("name"))
        return LibFile(name or m.group("name"), m.group("ver"), "static", filename)

    return None


def scan_libraries(root: str, max_depth: int = 5) -> list[LibFile]:
    results: list[LibFile] = []
    seen: set[str] = set()

    if os.path.isfile(root):
        lib = classify(root)
        if lib:
            results.append(lib)
        return results

    for cur, dirs, files in os.walk(root):
        depth = cur[len(os.path.commonpath([root, cur])):].count(os.sep)
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        if depth > max_depth:
            dirs[:] = []
            continue
        for fn in files:
            full = os.path.join(cur, fn)
            lib = classify(full)
            if not lib:
                continue
            key = (lib.name, lib.version, lib.lib_type)
            if key in seen:
                continue
            seen.add(key)
            results.append(lib)
    return results
