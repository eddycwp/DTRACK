"""Core data models for analysis results."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from .types import DependencyType, Language, Severity, SourceType
from ..utils.license_normalize import normalize_license

# 北京时间固定为 UTC+8（无夏令时）
_BEIJING_TZ = timezone(timedelta(hours=8))


def _now_iso() -> str:
    """报告生成时间，格式：XXXX年XX月XX日  XX:XX"""
    now = datetime.now(_BEIJING_TZ)
    return (
        f"{now.year}年{now.month:02d}月{now.day:02d}日  "
        f"{now.hour:02d}:{now.minute:02d}"
    )


@dataclass
class Vulnerability:
    """A single vulnerability record, normalized across all sources."""

    vuln_id: str                 # canonical id: CVE-xxxx / GHSA-xxxx / QAX-xxxx
    source: SourceType
    title: str = ""
    severity: Severity = Severity.UNKNOWN
    description: str = ""
    fixed_version: Optional[str] = None
    vulnerable_range: Optional[str] = None
    references: list[str] = field(default_factory=list)
    cve: Optional[str] = None
    cwe: Optional[str] = None
    published: Optional[str] = None
    solution: Optional[str] = None       # remediation / fix recommendation
    sources: list = field(default_factory=list)  # which sources reported this vuln
    raw: dict[str, Any] = field(default_factory=dict)

    def dedup_key(self) -> str:
        # Prefer CVE when present so the same bug from NVD+GitHub+QIANXIN collapses to one.
        return self.cve or f"{self.source.value}:{self.vuln_id}"


@dataclass
class Component:
    """A software component (artifact / package / image layer)."""

    group: Optional[str]                 # maven groupId; None for some ecosystems
    name: str
    version: Optional[str]
    language: Language
    purl: Optional[str] = None
    dependency_type: Optional[DependencyType] = None  # direct/transitive (java only)
    direct: bool = False
    transitive: bool = False
    source: Optional[str] = None         # where it was discovered (repo/pom path)
    license: Optional[str] = None        # SPDX id or license name (best-effort)
    lib_type: Optional[str] = None       # C/C++ only: "dynamic" | "static" | None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        g = self.group or ""
        return f"{g}:{self.name}:{self.version or '?'}"

    @property
    def coordinate(self) -> str:
        """Human-friendly coordinate (groupId:artifactId:version)."""
        if self.group:
            return f"{self.group}:{self.name}:{self.version or '?'}"
        return f"{self.name}:{self.version or '?'}"

    @property
    def worst_severity(self) -> Severity:
        if not self.vulnerabilities:
            return Severity.UNKNOWN
        return max((v.severity for v in self.vulnerabilities), key=lambda s: s.rank)


@dataclass
class AnalysisResult:
    """Aggregated result of one analysis run."""

    target: str
    language: Language
    generated_at: str = field(default_factory=_now_iso)
    components: list[Component] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    sources_used: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def enrich_summary(self) -> None:
        sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
        src_counts: dict[str, int] = {}
        lic_counts: dict[str, int] = {}
        vuln_by_component = 0
        for c in self.components:
            if c.license:
                # 统一许可证描述后再统计，使同一许可证的不同写法合并计数
                key = normalize_license(c.license)
                lic_counts[key] = lic_counts.get(key, 0) + 1
            if c.vulnerabilities:
                vuln_by_component += 1
            for v in c.vulnerabilities:
                sev_counts[v.severity.value] += 1
                src_counts[v.source.value] = src_counts.get(v.source.value, 0) + 1
        self.summary = {
            "total_components": len(self.components),
            "components_with_vulns": vuln_by_component,
            "total_vulnerabilities": sum(sev_counts.values()),
            "severity_counts": sev_counts,
            "source_counts": src_counts,
            "license_counts": lic_counts,
            "direct_deps": sum(1 for c in self.components if c.direct),
            "transitive_deps": sum(1 for c in self.components if c.transitive),
        }
