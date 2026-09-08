"""Core enums for the DTrack vulnerability analysis system."""
from __future__ import annotations

from enum import Enum


class Language(str, Enum):
    """Supported (and planned) analysis targets. Extend for c/c++ and docker later."""

    JAVA = "java"
    CC = "c/c++"        # planned
    DOCKER = "docker"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


class DependencyType(str, Enum):
    """Whether a component is a direct or transitive dependency of the target."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"


class Severity(str, Enum):
    """Normalized vulnerability severity. Numeric ranks allow sorting/aggregation."""

    CRITICAL = "critical"   # 严重 / 超危
    HIGH = "high"           # 高危
    MEDIUM = "medium"       # 中危
    LOW = "low"             # 低危
    UNKNOWN = "unknown"     # 未知

    # Higher rank == more severe. Used for sorting and "worst severity" rollups.
    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.UNKNOWN: 1,
        }[self]

    @classmethod
    def from_rank(cls, rank: int) -> "Severity":
        for sev in sorted(cls, key=lambda s: s.rank, reverse=True):
            if rank >= sev.rank:
                return sev
        return Severity.UNKNOWN

    @classmethod
    def max(cls, a: "Severity", b: "Severity") -> "Severity":
        return a if a.rank >= b.rank else b

    def label_zh(self) -> str:
        return {
            Severity.CRITICAL: "超危/严重",
            Severity.HIGH: "高危",
            Severity.MEDIUM: "中危",
            Severity.LOW: "低危",
            Severity.UNKNOWN: "未知",
        }[self]

    def badge(self) -> str:
        """Markdown-friendly badge text."""
        return f"{self.label_zh()} ({self.value})"


class SourceType(str, Enum):
    """Where a vulnerability record originated."""

    NVD = "nvd"
    GITHUB = "github"
    QIANXIN = "qianxin"
    OSV = "osv"
    MANUAL = "manual"

    def __str__(self) -> str:  # pragma: no cover
        return self.value
