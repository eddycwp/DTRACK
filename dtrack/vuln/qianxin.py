"""奇安信开源卫士 (QIANXIN) vulnerability source.

Uses OpenAPI V3 endpoint ``GET /open-api/v3/component/vulnerability`` to look up a
component by name + version and return its vulnerability list. Authentication is
either BasicAuth or a Private-Token (both configurable). The gateway base URL,
auth type and credentials are all config-driven (and will later be editable from
the web UI). See dev manual: 奇安信网神开源卫士系统 OpenAPI-V3.

``build_qx_auth_header`` is also reused by the binary/image scanner
(``dtrack/scan/qianxin_scan.py``) so both modules share the same credentials.
"""
from __future__ import annotations

from typing import Optional

from .. import get_logger
from ..config import Config
from ..core.models import Component, Vulnerability
from ..core.types import Language, Severity, SourceType
from ..utils.http import HttpClient, basic_auth_header
from .base import VulnerabilitySource

_LOGGER = get_logger()

# 奇安信网关要求单次请求 pageSize <= 20
_PAGE_SIZE_MAX = 20


def _clamp_page_size(raw) -> int:
    try:
        val = int(raw)
    except (TypeError, ValueError):
        val = 0
    if val <= 0:
        val = 20
    return min(val, _PAGE_SIZE_MAX)


def qx_level_to_severity(level) -> Severity:
    """Map QIANXIN numeric level to a normalized severity.

    QIANXIN uses 超危/高危/中危/低危/未知. Vulnerability ``level`` is typically 1-5
    (1=超危, 2=高危, 3=中危, 4=低危, 5=未知). Some fields carry a 0-10 risk score
    (e.g. componentLevel); for values >5 we treat them as a CVSS-like score.
    """
    try:
        lv = float(level)
    except (TypeError, ValueError):
        return Severity.UNKNOWN
    if lv == int(lv) and 1 <= int(lv) <= 5:
        return {
            1: Severity.CRITICAL,
            2: Severity.HIGH,
            3: Severity.MEDIUM,
            4: Severity.LOW,
            5: Severity.UNKNOWN,
        }[int(lv)]
    # score-like
    if lv >= 9.0:
        return Severity.CRITICAL
    if lv >= 7.0:
        return Severity.HIGH
    if lv >= 4.0:
        return Severity.MEDIUM
    if lv > 0:
        return Severity.LOW
    return Severity.UNKNOWN


def build_qx_auth_header(config, prefix: str = "vuln.qianxin") -> dict:
    """Build the QIANXIN ``Authorization`` header from config.

    Both BasicAuth and Private-Token are supported. ``prefix`` lets the scan module
    reuse the same credentials under ``scan.qianxin`` (falling back to ``vuln.qianxin``).
    """
    auth_type = (config.get(f"{prefix}.auth_type") or "private-token").lower()
    if auth_type == "basic":
        return basic_auth_header(config.get(f"{prefix}.username"),
                                 config.get(f"{prefix}.password"))
    tok = config.get(f"{prefix}.token") or ""
    return {"Authorization": f"Private-Token {tok}"}


class QianxinSource(VulnerabilitySource):
    name = "qianxin"
    source_type = SourceType.QIANXIN

    def enabled(self) -> bool:
        # vuln.qianxin.enabled 显式为 false 时强制关闭；否则由 base_url 决定（未设置该键时，配了 base_url 即启用）
        if self.config.get("vuln.qianxin.enabled") is False:
            return False
        return bool(self.config.get("vuln.qianxin.base_url"))

    def disabled_reason(self) -> str:
        if self.config.get("vuln.qianxin.enabled") is False:
            return "已在配置中显式禁用（vuln.qianxin.enabled = false）"
        if not self.config.get("vuln.qianxin.base_url"):
            return ("缺少网关地址 vuln.qianxin.base_url（未配置则无法连接奇安信，该源不会启用）。"
                    "常见原因：TOML 里误写成了顶层表 [qianxin]，正确写法是 [vuln.qianxin]。")
        return "缺少鉴权参数（vuln.qianxin.token 或 username/password）"

    def _client(self) -> HttpClient:
        verify = bool(self.config.get("vuln.qianxin.verify_ssl", False))
        return HttpClient(timeout=float(self.config.get("general.timeout", 30)), retries=3,
                           verify_ssl=verify, headers={"User-Agent": "DTrack/0.1"})

    def _auth_header(self) -> dict:
        return build_qx_auth_header(self.config, prefix="vuln.qianxin")

    def _fetch_page(self, client: HttpClient, headers: dict, name: str, version: str, page: int, page_size: int):
        api_path = self.config.get("vuln.qianxin.api_path") or "/open-api/v3/component/vulnerability"
        url = self.config.get("vuln.qianxin.base_url").rstrip("/") + api_path
        resp = client.get(url, params={
            "componentName": name, "versionNo": version,
            "pageIndex": page, "pageSize": page_size,
        }, headers=headers)
        if not resp.ok:
            _LOGGER.warning(
                "奇安信查询失败 (%s): status=%s, url=%s, response=%s",
                name, resp.status, resp.url, resp.text[:200],
            )
            return None
        return resp.json() or {}

    @staticmethod
    def _is_success(data: dict) -> bool:
        """Accept both ``Code`` (legacy) and ``code`` (current) wrappers."""
        code = data.get("Code") if "Code" in data else data.get("code")
        # ``code`` may be missing for plain payloads; treat missing as success.
        return code in (1, "1", None)

    @staticmethod
    def _extract_vulns(data: dict) -> list[dict]:
        """Extract ``vulnerabilityList`` from QIANXIN response body.

        The gateway may return the payload under ``Data`` or ``data``,
        and the inner payload may be either a dict with ``vulnerabilityList``
        or a list of component dicts each carrying its own ``vulnerabilityList``.
        """
        if not data:
            return []
        payload = data.get("Data") if "Data" in data else data.get("data")
        if isinstance(payload, list):
            vlist: list[dict] = []
            for item in payload:
                if isinstance(item, dict):
                    vlist.extend(item.get("vulnerabilityList") or [])
            return vlist
        if isinstance(payload, dict):
            return payload.get("vulnerabilityList") or []
        return []

    def _convert(self, v: dict) -> Optional[Vulnerability]:
        cve = v.get("cve") or None
        qax = v.get("qaxOssId") or v.get("vulnerabilityId") or None
        vid = cve or qax
        if not vid:
            return None
        refs = []
        if cve:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
        return Vulnerability(
            vuln_id=vid,
            source=SourceType.QIANXIN,
            title=v.get("vulnerabilityName") or vid,
            severity=qx_level_to_severity(v.get("level")),
            description=v.get("vulnerabilityDescription") or "",
            fixed_version=None,
            vulnerable_range=None,
            references=refs,
            cve=cve,
            cwe=v.get("cnnvd") or None,  # cnnvd kept as cross-ref
            published=v.get("releaseDate"),
            solution=v.get("solution"),
            raw=v,
        )

    def query(self, component: Component) -> list[Vulnerability]:
        if component.language not in (Language.JAVA, Language.CC):
            return []
        if not (component.name and component.version):
            return []
        client = self._client()
        headers = self._auth_header()
        page_size = _clamp_page_size(self.config.get("vuln.qianxin.page_size"))
        # Try multiple component-name forms; QIANXIN may index by artifactId alone.
        forms = []
        if component.group:
            forms.append(f"{component.group}:{component.name}")
        forms.append(component.name)
        collected: dict[str, Vulnerability] = {}
        for name in forms:
            page = 0
            seen_pages = 0
            while seen_pages < 20:
                data = self._fetch_page(client, headers, name, component.version, page, page_size)
                if not data or not self._is_success(data):
                    break
                vlist = self._extract_vulns(data)
                if not vlist:
                    break
                for v in vlist:
                    vuln = self._convert(v)
                    if vuln:
                        collected[vuln.dedup_key()] = vuln
                if len(vlist) < page_size:
                    break
                page += 1
                seen_pages += 1
        return list(collected.values())
