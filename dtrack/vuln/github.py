"""GitHub Advisory vulnerability source (GraphQL, ecosystem=maven).

This is the most reliable source for Maven coordinates. It queries the GitHub
Advisory Database for a package (``groupId:artifactId``) and maps advisories to
normalized ``Vulnerability`` records, filtering by vulnerable version range.
"""
from __future__ import annotations

from ..config import Config
from ..core.models import Component, Vulnerability
from ..core.types import Severity, SourceType
from ..utils.http import HttpClient
from ..utils.versions import is_affected, parse_range_to_bounds
from .base import VulnerabilitySource

_GRAPHQL = """
query DTrackAdvisories($pkg: String!, $eco: SecurityAdvisoryEcosystem!) {
  securityAdvisories(ecosystem: $eco, package: $pkg, first: 100) {
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      identifiers { type value }
      references { url }
      vulnerabilities(first: 50) {
        nodes {
          package { ecosystem name }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
"""


class GitHubSource(VulnerabilitySource):
    name = "github"
    source_type = SourceType.GITHUB

    def enabled(self) -> bool:
        # GitHub GraphQL 无 token 也可调用（仅被限流），默认可用；vuln.github.enabled 显式 false 时禁用
        if self.config.get("vuln.github.enabled") is False:
            return False
        return True

    def _client(self) -> HttpClient:
        token = self.config.get("vuln.github.token")
        headers = {"Content-Type": "application/json", "User-Agent": "DTrack/0.1"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return HttpClient(timeout=float(self.config.get("general.timeout", 30)), retries=2, headers=headers)

    def query(self, component: Component) -> list[Vulnerability]:
        if component.language.value != "java" or not (component.group and component.name):
            return []
        pkg = f"{component.group}:{component.name}"
        api_url = self.config.get("vuln.github.api_url")
        resp = self._client().post(api_url, json_body={
            "query": _GRAPHQL,
            "variables": {"pkg": pkg, "eco": "MAVEN"},
        })
        if not resp.ok:
            return []
        data = resp.json() or {}
        payload = (data.get("data") or {}).get("securityAdvisories") or {}
        nodes = payload.get("nodes") or []
        out: list[Vulnerability] = []
        for adv in nodes:
            ghsa = adv.get("ghsaId")
            cve = None
            for ident in adv.get("identifiers", []):
                if ident.get("type") == "CVE":
                    cve = ident.get("value")
            sev = self._sx_severity(adv.get("severity") or "")
            # pick the vulnerability entry for this exact maven package
            vuln_range = None
            fixed = None
            for v in adv.get("vulnerabilities", {}).get("nodes", []):
                p = v.get("package") or {}
                if p.get("ecosystem") == "MAVEN" and p.get("name") == pkg:
                    vuln_range = v.get("vulnerableVersionRange")
                    fv = v.get("firstPatchedVersion") or {}
                    fixed = fv.get("identifier")
                    break
            if vuln_range and component.version and not is_affected(component.version, parse_range_to_bounds(vuln_range)):
                continue
            refs = [r.get("url") for r in adv.get("references", []) if r.get("url")]
            solution = f"升级到 {fixed}" if fixed else None
            out.append(Vulnerability(
                vuln_id=cve or ghsa,
                source=SourceType.GITHUB,
                title=adv.get("summary") or ghsa,
                severity=sev,
                description=adv.get("description") or "",
                fixed_version=fixed,
                vulnerable_range=vuln_range,
                references=refs,
                cve=cve,
                published=adv.get("publishedAt"),
                solution=solution,
                raw=adv,
            ))
        return out
