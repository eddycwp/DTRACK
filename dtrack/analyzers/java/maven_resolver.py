"""Resolve Maven transitive dependencies.

Two strategies:
  * ``MvnTreeResolver``  - shells out to ``mvn dependency:tree`` (used when Maven is
                           installed and ``maven.use_mvn_tree`` is true). Most accurate.
  * ``MavenCentralResolver`` - pure-Python fallback that fetches each artifact's POM from
                           Maven Central and walks ``<dependencies>`` (and
                           ``<dependencyManagement>`` for version resolution). No Maven
                           install required. Bound by ``max_depth`` and a hard artifact cap.

Both return a flat list of ``ResolvedDep`` with ``depth`` and ``direct`` flags, which the
Java analyzer turns into Components.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections import deque
from dataclasses import dataclass
from typing import Optional

from ... import get_logger
from ...config import Config
from ...utils.cache import FileCache
from ...utils.http import HttpClient
from .pom_parser import Dep, Pom, parse_pom_file, parse_pom_text

_LOGGER = get_logger()

_TREE_LINE = re.compile(r"^([^:]+):([^:]+):([^:]+):([^:]+)(?::(\w+))?")

# 常见测试框架 artifactId 关键字，用于剔除被误标为 compile 作用域的测试依赖
# （例如 log4j-core 2.14.0 的 pom 将 junit/mockito 标成了 compile）。
TEST_FRAMEWORK_ARTIFACTS = (
    "junit", "mockito", "hamcrest", "testng", "spock", "assertj", "truth",
    "easymock", "powermock", "scalatest", "specs2", "scalamock", "cucumber",
    "selenide", "arquillian", "rest-assured", "wiremock", "json-unit", "xmlunit",
    "opentest4j", "jmock", "fest-assert",
)


def _norm_scope(scope: Optional[str]) -> str:
    return (scope or "compile").lower()


def _scope_excluded(scope: Optional[str], exclude_scopes: list) -> bool:
    if not exclude_scopes:
        return False
    return _norm_scope(scope) in exclude_scopes


def _is_test_framework(artifact: Optional[str]) -> bool:
    if not artifact:
        return False
    a = artifact.lower()
    return any(k in a for k in TEST_FRAMEWORK_ARTIFACTS)


def resolve_mvn_executable(config: Config) -> str:
    """Compute the ``mvn`` executable path from config (explicit > maven.home > PATH).

    On Windows the runnable launcher is ``mvn.cmd`` — ``bin/mvn`` is a bash script and
    cannot be executed directly by CreateProcess (would raise WinError 193: "%1 不是有效的
    Win32 应用程序"). So when deriving from ``maven.home`` we prefer the ``.cmd``/``.bat``
    launchers on Windows.
    """
    exe = config.get("maven.executable")
    if exe:
        return exe
    home = config.get("maven.home")
    if home:
        bin_dir = os.path.join(home, "bin")
        if os.name == "nt":
            for cand in ("mvn.cmd", "mvn.bat", "mvn"):
                p = os.path.join(bin_dir, cand)
                if os.path.exists(p):
                    return p
        return os.path.join(bin_dir, "mvn")
    return "mvn"


@dataclass
class ResolvedDep:
    group: str
    artifact: str
    version: Optional[str]
    scope: str = "compile"
    depth: int = 0          # 0 == direct dependency of the analyzed project
    direct: bool = False
    parents: list = None    # coordinate path, for tree rendering

    def __post_init__(self):
        if self.parents is None:
            self.parents = []

    @property
    def coord(self) -> str:
        return f"{self.group}:{self.artifact}:{self.version or '?'}"


def _key(group: str, artifact: str, version: Optional[str]) -> str:
    return f"{group}:{artifact}:{version or '?'}"


class MavenCentralResolver:
    def __init__(self, config: Config) -> None:
        self.central = (config.get("maven.central_url") or "https://repo1.maven.org/maven2").rstrip("/")
        self.max_depth = int(config.get("maven.max_depth", 5))
        self.cache_dir = config.get("general.cache_dir")
        ttl = int(config.get("general.cache_ttl", 86400))
        self.cache = FileCache(os.path.join(self.cache_dir, "maven"), ttl=ttl)
        self.http = HttpClient(timeout=float(config.get("general.timeout", 30)), retries=3)
        self.max_artifacts = 3000
        self.exclude_scopes = [s.lower() for s in (config.get("analyze.exclude_scopes") or [])]
        self.exclude_test_fw = bool(config.get("analyze.exclude_test_frameworks", True))
        self.excluded_count = 0

    def _pom_url(self, group: str, artifact: str, version: str) -> str:
        gpath = "/".join(group.split("."))
        return f"{self.central}/{gpath}/{artifact}/{version}/{artifact}-{version}.pom"

    def _fetch_pom(self, group: str, artifact: str, version: str) -> Optional[Pom]:
        key = f"pom:{group}:{artifact}:{version}"
        cached = self.cache.get(key)
        if cached is not None:
            try:
                return parse_pom_text(cached, resolve=True)
            except Exception:  # noqa: BLE001
                pass
        resp = self.http.get(self._pom_url(group, artifact, version))
        if not resp.ok:
            return None
        self.cache.set(key, resp.text)
        try:
            return parse_pom_text(resp.text, resolve=True)
        except Exception:  # noqa: BLE001
            return None

    def _managed_map(self, pom: Pom) -> dict:
        m = {_key(d.group, d.artifact, None): d.version for d in pom.managed_deps if d.group and d.artifact}
        # one level of parent dependencyManagement
        if pom.parent and pom.parent.get("groupId") and pom.parent.get("version"):
            pp = self._fetch_pom(pom.parent["groupId"], pom.parent["artifactId"], pom.parent["version"])
            if pp:
                for d in pp.managed_deps:
                    if d.group and d.artifact and d.version:
                        m.setdefault(_key(d.group, d.artifact, None), d.version)
        return m

    def resolve(self, direct_deps: list[Dep]) -> list[ResolvedDep]:
        results: dict[str, ResolvedDep] = {}
        queue: deque[ResolvedDep] = deque()

        for d in direct_deps:
            if not d.group or not d.artifact:
                continue
            if _scope_excluded(d.scope, self.exclude_scopes):
                self.excluded_count += 1
                continue
            if self.exclude_test_fw and _is_test_framework(d.artifact):
                self.excluded_count += 1
                continue
            r = ResolvedDep(d.group, d.artifact, d.version, d.scope, depth=0, direct=True)
            k = _key(d.group, d.artifact, d.version)
            results.setdefault(k, r)
            queue.append(r)

        processed: set = set()
        while queue:
            cur = queue.popleft()
            if cur.depth >= self.max_depth or cur.version is None:
                continue
            pk = (cur.group, cur.artifact, cur.version)
            if pk in processed:
                continue
            processed.add(pk)

            pom = self._fetch_pom(cur.group, cur.artifact, cur.version)
            if pom is None:
                continue
            managed = self._managed_map(pom)
            for td in pom.direct_deps:
                if _scope_excluded(td.scope, self.exclude_scopes):
                    self.excluded_count += 1
                    continue
                if self.exclude_test_fw and _is_test_framework(td.artifact):
                    self.excluded_count += 1
                    continue
                if td.scope not in ("compile", "runtime", ""):
                    continue
                if td.optional:
                    continue
                if not td.group or not td.artifact:
                    continue
                version = td.version or managed.get(_key(td.group, td.artifact, None))
                r = ResolvedDep(
                    td.group, td.artifact, version, td.scope,
                    depth=cur.depth + 1, direct=False,
                    parents=cur.parents + [cur.coord],
                )
                k = _key(td.group, td.artifact, version)
                if k not in results:
                    results[k] = r
                    queue.append(r)
                if len(results) > self.max_artifacts:
                    break
            if len(results) > self.max_artifacts:
                break
        return list(results.values())


class MvnTreeResolver:
    """Parse ``mvn dependency:tree`` output into ResolvedDep list."""

    # Maven 内置默认中央仓库（与 maven.central_url 默认值等价）。
    # 只有配置的 central_url 与之不同，才需要注入 -s settings.xml 镜像覆盖。
    _DEFAULT_CENTRAL = "https://repo1.maven.org/maven2"

    def __init__(self, config: Config) -> None:
        self.mvn = resolve_mvn_executable(config)
        self.exclude_scopes = [s.lower() for s in (config.get("analyze.exclude_scopes") or [])]
        self.exclude_test_fw = bool(config.get("analyze.exclude_test_frameworks", True))
        self.excluded_count = 0
        self.central = (config.get("maven.central_url") or "").strip()
        self.central_user = (config.get("maven.central_username") or "").strip()
        self.central_pass = config.get("maven.central_password") or ""

    def available(self) -> bool:
        if os.path.exists(self.mvn):
            return True
        if shutil.which(self.mvn):
            return True
        return shutil.which("mvn") is not None

    def _use_custom_central(self) -> bool:
        """True 当配置了与默认不同的 central_url（需通过 mirror 注入）。"""
        return bool(self.central) and self.central.rstrip("/") != self._DEFAULT_CENTRAL.rstrip("/")

    def _build_settings_xml(self, central_url: str) -> str:
        """生成临时 settings.xml：用 mirror 把全部远程仓库重定向到配置的 central_url。

        ``mvn dependency:tree`` 没有"远程仓库 URL"命令行参数，只能通过 settings.xml
        的 <mirror> 覆盖。mirrorOf=* 会把所有远程仓库（含插件仓库）解析重定向到
        central_url。若 central_url 是完整的私有 Nexus/Artifactory 即可正常工作。

        若配置了 central_username / central_password，则追加 <servers> 块（id 与
        mirror 的 id 一致 dtrack-central），用于私有仓库的 Basic 认证，否则会 401/403。
        """
        servers_block = ""
        if self.central_user:
            servers_block = (
                "  <servers>\n"
                "    <server>\n"
                "      <id>dtrack-central</id>\n"
                f"      <username>{self.central_user}</username>\n"
                f"      <password>{self.central_pass}</password>\n"
                "    </server>\n"
                "  </servers>\n"
            )
        content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"\n'
            '          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
            '          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 '
            'https://maven.apache.org/xsd/settings-1.0.0.xsd">\n'
            '  <mirrors>\n'
            '    <mirror>\n'
            '      <id>dtrack-central</id>\n'
            '      <name>DTrack configured central repository</name>\n'
            f'      <url>{central_url}</url>\n'
            '      <mirrorOf>*</mirrorOf>\n'
            '    </mirror>\n'
            '  </mirrors>\n'
            + servers_block
            + '</settings>\n'
        )
        fd, path = tempfile.mkstemp(suffix=".xml", prefix="dtrack-mvn-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    @staticmethod
    def _parse_line(line: str) -> Optional[tuple[int, str, str]]:
        s = line.strip()
        if not s.startswith("[INFO]"):
            return None
        content = s[6:]
        if content.startswith(" "):
            content = content[1:]
        depth = 0
        i = 0
        while i < len(content):
            chunk = content[i:i + 3]
            if chunk in ("   ", "|  "):
                depth += 1
                i += 3
            elif chunk[:2] in ("+-", "\\-") or chunk in ("+- ", "\\- "):
                depth += 1
                i += 3
                break
            else:
                break
        rest = content[i:].strip()
        rest = re.sub(r"\s*->+\s*.*$", "", rest)          # strip "-> [version]" relocations
        rest = re.sub(r"\s*\(.*?\)\s*$", "", rest)          # strip "(optional)", "(scope)"
        rest = re.sub(r"\s*--.*$", "", rest)                # strip "-- omitted for ..."
        m = _TREE_LINE.match(rest)
        if not m:
            return None
        group, artifact, version = m.group(1), m.group(2), m.group(4)
        # 过滤掉 BUILD SUCCESS/FAILURE 等尾部行被误匹配的情况
        if " " in group or " " in artifact or "." not in group:
            return None
        scope = _norm_scope(m.group(5))
        return depth, f"{group}:{artifact}:{version}", scope

    @staticmethod
    def _missing_module_error(text: str) -> bool:
        """Detect Maven reactor failure caused by unreadable child modules."""
        t = text.lower()
        return "child module" in t and "does not exist" in t

    def _aggregator_info(self, project_dir: str) -> tuple[bool, bool]:
        """Return (is_aggregator, has_missing_modules) for the root pom.xml.

        ``is_aggregator`` is True when the root POM has ``<packaging>pom</packaging>``
        and declares one or more ``<modules>``. ``has_missing_modules`` is True when
        at least one declared module directory does not contain a ``pom.xml``.
        """
        pom_path = os.path.join(project_dir, "pom.xml")
        if not os.path.isfile(pom_path):
            return False, False
        try:
            pom = parse_pom_file(pom_path, resolve=False)
        except Exception:  # noqa: BLE001
            return False, False
        is_aggregator = (pom.packaging or "jar").lower() == "pom" and bool(pom.modules)
        if not is_aggregator:
            return False, False
        missing = any(
            not os.path.isfile(os.path.join(project_dir, module, "pom.xml"))
            for module in pom.modules
        )
        return True, missing

    def _run_tree(self, cmd: list[str], project_dir: str) -> str:
        """Execute ``mvn dependency:tree`` and return stdout+stderr text."""
        out = subprocess.run(
            cmd,
            cwd=project_dir, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=600,
        )
        return out.stdout + out.stderr, out.returncode

    def resolve(self, project_dir: str) -> list[ResolvedDep]:
        # 只有配置了非默认 central_url 时，才生成临时 settings.xml 并用 -s 注入，
        # 让 mvn dependency:tree 通过配置的私有仓库/Maven Central 镜像解析依赖，
        # 而不是使用 Maven 内置默认的 repo.maven.apache.org。
        settings_path = None
        cmd = [self.mvn]
        if self._use_custom_central():
            settings_path = self._build_settings_xml(self.central)
            cmd.extend(["-s", settings_path])
        cmd.extend(["dependency:tree", "-Dverbose=false", "-B"])

        is_aggregator, has_missing = self._aggregator_info(project_dir)
        text = ""
        try:
            if is_aggregator and has_missing:
                # 子模块缺失时 Maven reactor 会直接报错退出，使用非递归模式只解析父工程。
                _LOGGER.warning(
                    "检测到聚合父 POM 的 <modules> 中存在缺失子模块，"
                    "将使用非递归模式（-N）运行 mvn dependency:tree。")
                nr_cmd = cmd[:1] + ["-N"] + cmd[1:]
                text, _ = self._run_tree(nr_cmd, project_dir)
            else:
                # Windows 中文环境默认编码常为 gbk，而 Maven 输出可能含 utf-8 字符；
                # 显式指定 utf-8 + replace 避免 UnicodeDecodeError 导致解析崩溃。
                # 注意：不要加 -q，-q 会抑制 dependency:tree 的 [INFO] 输出，导致解析为空。
                text, rc = self._run_tree(cmd, project_dir)
                # 如果是聚合工程且因缺失子模块失败，回退到非递归模式再试一次。
                if is_aggregator and rc != 0 and self._missing_module_error(text):
                    _LOGGER.warning(
                        "mvn dependency:tree 因缺失子模块失败，回退到非递归模式（-N）重试。")
                    nr_cmd = cmd[:1] + ["-N"] + cmd[1:]
                    text, _ = self._run_tree(nr_cmd, project_dir)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"mvn dependency:tree failed: {e}")
        finally:
            if settings_path and os.path.exists(settings_path):
                try:
                    os.remove(settings_path)
                except OSError:
                    pass

        results: dict[str, ResolvedDep] = {}
        for line in text.splitlines():
            parsed = self._parse_line(line)
            if not parsed:
                continue
            depth, coord, scope = parsed
            # depth=0 是项目自身（根节点），不是第三方依赖
            if depth == 0:
                continue
            if _scope_excluded(scope, self.exclude_scopes):
                self.excluded_count += 1
                continue
            group, artifact, version = coord.split(":", 2)
            if self.exclude_test_fw and _is_test_framework(artifact):
                self.excluded_count += 1
                continue
            # Maven dependency:tree 中 depth=1 为直接依赖，depth>=2 为传递依赖
            r = ResolvedDep(group, artifact, version, scope=scope, depth=depth, direct=(depth == 1))
            results.setdefault(coord, r)
        return list(results.values())
