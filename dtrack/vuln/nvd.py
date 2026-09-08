"""NVD (National Vulnerability Database) vulnerability source.

Uses the NVD 2.0 REST API. Maven coordinates don't map cleanly to CPEs, so we
build a best-effort CPE (vendor = last segment of groupId, product = artifactId)
and additionally filter results by examining the returned CPE match criteria.
For reliable Maven coverage prefer the GitHub Advisory source.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from ..config import Config
from ..core.models import Component, Vulnerability
from ..core.types import Language, Severity, SourceType
from ..utils.http import HttpClient
from ..utils.versions import Bounds, is_affected
from .base import VulnerabilitySource

_LAST_CALL = 0.0
_LOCK = threading.Lock()


class NvdSource(VulnerabilitySource):
    name = "nvd"
    source_type = SourceType.NVD

    def enabled(self) -> bool:
        # NVD 公开 API 无需凭据，默认可用；vuln.nvd.enabled 显式 false 时禁用
        if self.config.get("vuln.nvd.enabled") is False:
            return False
        return True

    def _client(self) -> HttpClient:
        return HttpClient(
            timeout=float(self.config.get("general.timeout", 30)),
            retries=3,
            verify_ssl=True,
            headers={"User-Agent": "DTrack/0.1"},
        )

    @staticmethod
    def _throttle(api_key: Optional[str]) -> None:
        global _LAST_CALL
        with _LOCK:
            min_gap = 0.6 if not api_key else 0.05
            wait = min_gap - (time.time() - _LAST_CALL)
            if wait > 0:
                time.sleep(wait)
            _LAST_CALL = time.time()

    @staticmethod
    def _severity_from_cve(cve: dict) -> Severity:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if arr:
                m = arr[0]
                if key == "cvssMetricV2":
                    sev = m.get("baseSeverity")
                    if sev:
                        return VulnerabilitySource._sx_severity(sev)
                    score = (m.get("cvssData") or {}).get("baseScore")
                    return NvdSource._score_to_sev(score)
                return VulnerabilitySource._sx_severity(m["cvssData"]["baseSeverity"])
        return Severity.UNKNOWN

    @staticmethod
    def _score_to_sev(score) -> Severity:
        # 与 OSV 等源共用同一套 CVSS 分段逻辑，避免多处维护
        return VulnerabilitySource.severity_from_score(score)

    @staticmethod
    def _bounds_from_configurations(cve: dict, artifact: str):
        """Return (bounds, matched) for CPE matches whose product matches the artifact."""
        artifact_l = artifact.lower()
        best: Optional[Bounds] = None
        matched = False
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    cpe_str = cpe.get("criteria", "")
                    parts = cpe_str.split(":")
                    if len(parts) < 5:
                        continue
                    product = parts[4].lower()
                    if product != artifact_l and not artifact_l.startswith(product):
                        continue
                    matched = True
                    b = Bounds(
                        start_incl=cpe.get("versionStartIncluding"),
                        start_excl=cpe.get("versionStartExcluding"),
                        end_incl=cpe.get("versionEndIncluding"),
                        end_excl=cpe.get("versionEndExcluding"),
                    )
                    if best is None:
                        best = b
        return best, matched

    @staticmethod
    def _cpe_candidates(component: Component) -> list:
        g, a, v = component.group, component.name, component.version
        segs = g.split(".")
        last = segs[-1].lower()
        vendors = {last}
        if g.startswith("org.apache."):
            vendors.add("apache")
        elif g.startswith("com.google."):
            vendors.add("google")
        elif g.startswith("org.springframework."):
            vendors.update({"springframework", "pivotal_software", "vmware"})
        elif g.startswith("commons-"):
            vendors.add("apache")
        elif g.startswith("com.fasterxml"):
            vendors.add("fasterxml")
        products = {a.lower()}
        if a.lower().endswith("-core"):
            products.add(a.lower()[:-5])

        cands = []
        for ven in sorted(vendors):
            for prod in sorted(products):
                cands.append(f"cpe:2.3:a:{ven}:{prod}:{v}:*:*:*:*:*:*:*")
        return cands[:6]

    def query(self, component: Component) -> list[Vulnerability]:
        if component.language not in (Language.JAVA, Language.CC):
            return []
        if not component.name or not component.version:
            return []
        if component.language == Language.JAVA:
            if not component.group:
                return []
            candidates = self._cpe_candidates(component)
        else:
            # C/C++: best-effort CPE with vendor == product name
            candidates = [
                f"cpe:2.3:a:{component.name.lower()}:{component.name.lower()}:{component.version}:*:*:*:*:*:*:*"
            ]
        api_url = self.config.get("vuln.nvd.api_url")
        api_key = self.config.get("vuln.nvd.api_key")
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        merged: dict[str, Vulnerability] = {}
        for cpe in candidates:
            self._throttle(api_key)
            resp = self._client().get(api_url, params={"cpeName": cpe}, headers=headers)
            if not resp.ok:
                continue
            data = resp.json() or {}
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cid = cve.get("id")
                if not cid:
                    continue
                bounds, matched = self._bounds_from_configurations(cve, component.name)
                if not matched:
                    continue
                if not is_affected(component.version, bounds):
                    continue
                if cid in merged:
                    continue
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
                merged[cid] = Vulnerability(
                    vuln_id=cid,
                    source=SourceType.NVD,
                    title=cid,
                    severity=self._severity_from_cve(cve),
                    description=desc,
                    vulnerable_range=bounds.text(),
                    references=refs,
                    cve=cid,
                    published=cve.get("published"),
                    raw=cve,
                )
        return list(merged.values())
