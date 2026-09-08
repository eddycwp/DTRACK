"""Vulnerability source plugin interface.

A ``VulnerabilitySource`` turns a ``Component`` into a list of normalized
``Vulnerability`` records. Concrete sources live in their own modules and are
wired up via ``registry.py`` (kept separate to avoid circular imports).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Type

from ..core.models import Component, Vulnerability
from ..core.types import Severity, SourceType

__all__ = [
    "VulnerabilitySource",
    "Severity",
    "SourceType",
]


class VulnerabilitySource(ABC):
    name: str = "base"
    source_type: SourceType = SourceType.MANUAL

    def __init__(self, config) -> None:
        self.config = config

    @abstractmethod
    def enabled(self) -> bool:
        ...

    def disabled_reason(self) -> str:
        """人类可读的未启用原因，供 CLI 诊断输出（默认通用说明）。"""
        return "未满足启用条件（缺少必要配置）"

    @abstractmethod
    def query(self, component: Component) -> list[Vulnerability]:
        ...

    @staticmethod
    def _sx_severity(label: str) -> Severity:
        m = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "moderate": Severity.MEDIUM,
            "low": Severity.LOW,
            "none": Severity.UNKNOWN,
        }
        return m.get((label or "").strip().lower(), Severity.UNKNOWN)

    @staticmethod
    def severity_from_score(score) -> Severity:
        """按 CVSS 评分映射严重程度（与奇安信/业界通用分段一致）。"""
        try:
            s = float(score)
        except (TypeError, ValueError):
            return Severity.UNKNOWN
        if s >= 9.0:
            return Severity.CRITICAL
        if s >= 7.0:
            return Severity.HIGH
        if s >= 4.0:
            return Severity.MEDIUM
        if s > 0:
            return Severity.LOW
        return Severity.UNKNOWN
