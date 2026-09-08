"""OSV.dev vulnerability source.

Queries the OSV batch/query API (https://api.osv.dev/v1/query) which aggregates
advisories from many ecosystems (Maven, PyPI, npm, Go, distros, ...). This gives
us a *second* authoritative feed alongside NVD/GitHub/QIANXIN.

  * Java  -> ecosystem "Maven", package name "groupId:artifactId"
  * C/C++ -> configurable ecosystem (default "generic"), package name = library name

OSV accepts either ``{ecosystem, name}`` or a ``purl``. We use the structured
form so the ecosystem mapping is explicit.
"""
from __future__ import annotations

from typing import Optional

from ..config import Config
from ..core.models import Component, Vulnerability
from ..core.types import Language, Severity, SourceType
from ..utils.http import HttpClient
from .base import VulnerabilitySource


class OsvSource(VulnerabilitySource):
    name = "osv"
    source_type = SourceType.OSV

    def enabled(self) -> bool:
        # OSV 公开 API 无需凭据，默认可用；vuln.osv.enabled 显式 false 时禁用
        if self.config.get("vuln.osv.enabled") is False:
            return False
        return True

    def _client(self) -> HttpClient:
        return HttpClient(timeout=float(self.config.get("general.timeout", 30)), retries=3,
                           verify_ssl=True, headers={"User-Agent": "DTrack/0.1"})

    def _package(self, component: Component) -> Optional[dict]:
        if component.language == Language.JAVA:
            if not (component.group and component.name):
                return None
            return {"ecosystem": "Maven", "name": f"{component.group}:{component.name}"}
        if component.language == Language.CC:
            if not component.name:
                return None
            eco = self.config.get("vuln.osv.cc_ecosystem", "generic")
            return {"ecosystem": eco, "name": component.name}
        return None

    @staticmethod
    def _sev_from_vuln(v: dict) -> Severity:
        for s in v.get("severity", []):
            if s.get("type", "").startswith("CVSS") and s.get("score"):
                sev = VulnerabilitySource.severity_from_score(s["score"])
                if sev != Severity.UNKNOWN:
                    return sev
        ds = (v.get("database_specific") or {}).get("severity")
        if ds:
            return VulnerabilitySource._sx_severity(ds)
        return Severity.UNKNOWN

    @staticmethod
    def _parse_osv_ranges(affected: list) -> tuple[str, Optional[str]]:
        fixes: list = []
        segs: list = []
        for a in affected:
            for r in a.get("ranges", []):
                events = r.get("events", [])
                cur_start = r.get("introduced")
                for ev in events:
                    if "introduced" in ev:
                        cur_start = ev["introduced"]
                    elif "fixed" in ev:
                        fixes.append(ev["fixed"])
                        if cur_start is not None:
                            segs.append(f">={cur_start} <{ev['fixed']}")
                            cur_start = None
                    elif "last_affected" in ev:
                        if cur_start is not None:
                            segs.append(f">={cur_start} <={ev['last_affected']}")
                            cur_start = None
                # legacy flat keys
                if "introduced" in r or "fixed" in r:
                    intro, fix = r.get("introduced"), r.get("fixed")
                    if fix:
                        fixes.append(fix)
                    if intro and fix:
                        segs.append(f">={intro} <{fix}")
                    elif intro:
                        segs.append(f">={intro}")
        return "; ".join(segs), (fixes[0] if fixes else None)

    def _convert(self, v: dict, component: Component) -> Optional[Vulnerability]:
        vid = v.get("id")
        if not vid:
            return None
        cve = next((a for a in v.get("aliases", []) if a.startswith("CVE")), None)
        summary = v.get("summary") or vid
        sev = self._sev_from_vuln(v)

        # Only keep affected entries relevant to this package
        affected = [
            a for a in v.get("affected", [])
            if (a.get("package") or {}).get("name") == component.name
            or (component.group and (a.get("package") or {}).get("name") == f"{component.group}:{component.name}")
        ]
        rng_text, fixed = self._parse_osv_ranges(affected if affected else v.get("affected", []))

        refs = [r.get("url") for r in v.get("references", []) if r.get("url")]
        if cve:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
        solution = f"升级到 {fixed}" if fixed else None

        st = self.source_type
        return Vulnerability(
            vuln_id=cve or vid,
            source=st,
            title=summary,
            severity=sev,
            description=v.get("details") or "",
            fixed_version=fixed,
            vulnerable_range=rng_text,
            references=refs,
            cve=cve,
            published=v.get("published"),
            solution=solution,
            raw=v,
        )

    def query(self, component: Component) -> list[Vulnerability]:
        pkg = self._package(component)
        if not pkg or not component.version:
            return []
        api_url = self.config.get("vuln.osv.api_url")
        resp = self._client().post(api_url, json_body={"package": pkg, "version": component.version})
        if not resp.ok:
            return []
        data = resp.json() or {}
        out: list[Vulnerability] = []
        for v in data.get("vulns", []):
            vuln = self._convert(v, component)
            if vuln:
                out.append(vuln)
        return out
