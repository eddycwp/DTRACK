"""Configuration management.

Config precedence (lowest -> highest):
    built-in defaults  <  config file  <  environment variables  <  CLI flags

The file is discovered from (in order): the ``--config`` argument, ``./dtrack.toml``,
``./dtrack.json``, ``~/.dtrack.toml``, ``~/.dtrack.json``. Both TOML and JSON are
supported. All keys are overridable later from a web UI by writing the same file.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

try:  # Python 3.11+
    import tomllib  # type: ignore

    _HAS_TOML = True
except ModuleNotFoundError:  # pragma: no cover
    _HAS_TOML = False

ENV_PREFIX = "DTRACK_"


DEFAULT_CONFIG: dict[str, Any] = {
    "general": {
        "cache_dir": os.path.join(os.path.expanduser("~"), ".dtrack", "cache"),
        "cache_ttl": 60 * 60 * 24,  # 1 day
        "log_level": "INFO",
        "log_file": None,            # 运行日志文件路径；留空则不写文件，仅输出控制台
        "timeout": 30,
        "concurrency": 4,
    },
    "maven": {
        "home": r"D:\mavendown\apache-maven-3.9.6",  # Maven 安装目录；executable 由此推导
        "executable": None,           # 显式指定 mvn 路径；为空则按 home/bin/mvn 推导
        "central_url": "https://repo1.maven.org/maven2",
        "central_username": None,     # 私有仓库（如 Nexus/Artifactory）认证用户名；配合 -s 注入的 settings.xml <servers>
        "central_password": None,     # 私有仓库认证密码
        "resolve_transitive": True,
        "max_depth": 5,
        "use_mvn_tree": True,         # prefer `mvn dependency:tree` if available
        "resolve_license": True,      # best-effort 从 Maven Central 获取依赖 license
        "local_repo": None,           # optional local maven repository path
    },
    "analyze": {
        "exclude_scopes": ["test"],   # Java: 剔除该作用域依赖（如 junit 等测试依赖），不参与漏洞分析
        "exclude_test_frameworks": True,  # 按名称剔除常见测试框架（junit/mockito 等），应对被误标为 compile 的测试依赖
    },
    "repos": {
        "gitlab": {"base_url": "https://gitlab.com", "token": None, "enabled": False},
        "nexus": {"base_url": None, "username": None, "password": None, "enabled": False},
        "harbor": {"base_url": None, "username": None, "password": None, "enabled": False},
    },
    "vuln": {
        "sources": ["nvd", "github", "qianxin", "osv"],
        "nvd": {
            "api_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "api_key": None,
        },
        "github": {
            "api_url": "https://api.github.com/graphql",
            "token": None,
        },
        "qianxin": {
            "base_url": None,             # gateway address, e.g. https://<host>:8449
            "api_path": "/open-api/v3/component/vulnerability",  # OpenAPI endpoint path
            "auth_type": "private-token",  # "private-token" | "basic"
            "username": None,
            "password": None,
            "token": None,
            "verify_ssl": False,
            "page_size": 20,            # 单次请求返回条数；奇安信网关要求 <= 20
            "enabled": None,          # true=强制启用(仍需 base_url); false=强制禁用; 缺省/None=由 base_url 决定
        },
        "osv": {
            "api_url": "https://api.osv.dev/v1/query",
            "cc_ecosystem": "generic",    # C/C++ 在 OSV 中的 ecosystem（可改为某个发行版，如 Debian）
        },
    },
    "scan": {
        # 奇安信开源卫士二进制/镜像扫描（OpenAPI V3）。
        # base_url / auth_type / token / username / password / verify_ssl 若留空，
        # 自动复用 vuln.qianxin 对应配置（与组件漏洞查询共用同一网关与鉴权）。
        "qianxin": {
            "base_url": None,             # 网关地址，如 https://<host>:8449（缺省复用 vuln.qianxin.base_url）
            "auth_type": "private-token",  # "private-token" | "basic"（缺省复用 vuln.qianxin）
            "username": None,
            "password": None,
            "token": None,
            "verify_ssl": False,
            "project_id": None,           # 必填：奇安信项目编号（提交扫描任务所需）
            "poll_interval": 5,           # 轮询检测结果间隔（秒）
            "poll_timeout": 1800,         # 轮询超时（秒）
            "page_size": 100,             # 组件/漏洞列表分页大小
        },
    },
    "report": {
        "out_dir": "./reports",
        "format": "markdown",
        "include_license": True,         # 报告中展示组件 license 信息
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _apply_env(cfg: dict) -> None:
    """Apply DTRACK__SECTION__KEY style environment overrides."""
    for env_key, val in os.environ.items():
        if not env_key.startswith(ENV_PREFIX):
            continue
        parts = env_key[len(ENV_PREFIX):].lower().split("__")
        if len(parts) < 2:
            continue
        node = cfg
        for p in parts[:-1]:
            node = node.setdefault(p, {})
            if not isinstance(node, dict):
                break
        else:
            lowered = val.lower()
            if lowered in ("true", "false"):
                node[parts[-1]] = lowered == "true"
            elif lowered in ("none", "null", ""):
                node[parts[-1]] = None
            elif lowered.isdigit():
                node[parts[-1]] = int(lowered)
            else:
                node[parts[-1]] = val


class Config:
    """Thin wrapper around the merged config dict with dot-path access."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def section(self, name: str) -> dict[str, Any]:
        return self.data.get(name, {}) or {}


def _read_file(path: str) -> dict:
    if path.endswith(".toml"):
        if not _HAS_TOML:
            raise RuntimeError("tomllib unavailable; use a .json config file")
        with open(path, "rb") as f:
            return tomllib.load(f)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def discover_config_path(explicit: Optional[str] = None) -> Optional[str]:
    candidates = []
    if explicit:
        candidates.append(explicit)
    cwd = os.getcwd()
    # 新位置 config/ 优先，旧的根目录位置仍兼容
    for name in ("dtrack.toml", "dtrack.json"):
        candidates.append(os.path.join(cwd, "config", name))
    for name in ("dtrack.toml", "dtrack.json"):
        candidates.append(os.path.join(cwd, name))
    home = os.path.expanduser("~")
    for name in ("dtrack.toml", "dtrack.json"):
        candidates.append(os.path.join(home, name))
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def load_config(explicit_path: Optional[str] = None) -> Config:
    merged = DEFAULT_CONFIG
    path = discover_config_path(explicit_path)
    if path:
        try:
            file_cfg = _read_file(path)
            merged = _deep_merge(DEFAULT_CONFIG, file_cfg)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"Failed to load config '{path}': {e}")
    _normalize_sections(merged)
    _apply_env(merged)
    return Config(merged)


def _to_toml(data: Any, prefix: str = "", indent: int = 1) -> str:
    """Minimal TOML serializer for our (dict/str/int/float/bool/None/list) structure.

    Nested dicts are emitted as proper dotted tables, e.g. ``[vuln.qianxin]``, so the
    file round-trips back into the exact same nested structure when parsed. Scalar/array
    keys of the current table are written before any sub-tables (required by TOML).
    """
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                continue
            if isinstance(v, list):
                items = ", ".join(_toml_scalar(x) for x in v)
                lines.append(f"{pad}{k} = [{items}]")
            else:
                lines.append(f"{pad}{k} = {_toml_scalar(v)}")
        for k, v in data.items():
            if isinstance(v, dict):
                table_name = f"{prefix}.{k}" if prefix else k
                lines.append(f"{pad}[{table_name}]")
                lines.append(_to_toml(v, prefix=table_name, indent=indent + 1))
    return "\n".join(lines)


def _normalize_sections(merged: dict) -> None:
    """Backward-compat shim.

    Older configs (and the example generated before this fix) wrote sub-sources as
    top-level tables, e.g. ``[qianxin]`` instead of ``[vuln.qianxin]``. That placed
    ``qianxin.base_url`` at the top level where the code never looks, so the source
    appeared "configured but not enabled". Promote such top-level tables into their
    proper parent (merging over the defaults) so existing files keep working.
    """
    alias_groups = {
        "vuln": ("nvd", "github", "qianxin", "osv"),
        "repos": ("gitlab", "nexus", "harbor"),
    }
    for parent, children in alias_groups.items():
        pnode = merged.setdefault(parent, {})
        if not isinstance(pnode, dict):
            continue
        for child in children:
            top = merged.get(child)
            if not isinstance(top, dict):
                continue
            existing = pnode.get(child)
            pnode[child] = _deep_merge(existing, top) if isinstance(existing, dict) else top
            del merged[child]


def _toml_scalar(v: Any) -> str:
    if v is None:
        return '""'
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_example_config(path: str) -> None:
    """Write a fully-commented example config (TOML)."""
    header = (
        "# DTrack configuration\n"
        "# All addresses/parameters here are editable; a future web UI will write the same file.\n"
        "# Environment overrides use DTRACK__SECTION__KEY (e.g. DTRACK__VULN__QIANXIN__BASE_URL).\n\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(_to_toml(DEFAULT_CONFIG))
    # Add a couple of explanatory comments appended at the end.
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n# Enable a source by setting enabled=true and filling its credentials.\n")
