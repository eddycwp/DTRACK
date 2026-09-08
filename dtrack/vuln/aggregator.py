"""Aggregate vulnerabilities across all enabled sources and attach to components."""
from __future__ import annotations

import concurrent.futures
from typing import Optional

from ..config import Config
from ..core.models import Component, Vulnerability
from ..core.types import Severity
from .. import get_logger
from .base import VulnerabilitySource
from .registry import get_enabled_sources


_LOGGER = get_logger()


class VulnerabilityAggregator:
    def __init__(self, config: Config, sources: Optional[list[VulnerabilitySource]] = None) -> None:
        self.config = config
        self.sources = sources if sources is not None else get_enabled_sources(config)

    def analyze_component(self, component: Component) -> list[Vulnerability]:
        collected: list[Vulnerability] = []
        for src in self.sources:
            try:
                vs = src.query(component)
            except Exception as e:  # noqa: BLE001 - one bad source must not break the run
                src_name = getattr(src, "name", "?")
                _LOGGER.warning("漏洞源 '%s' 查询 %s 失败: %s", src_name, component.coordinate, e)
                continue
            collected.extend(vs)

        merged: dict[str, Vulnerability] = {}
        for v in collected:
            if not v.sources:
                v.sources = [v.source.value]
            key = v.dedup_key()
            if key in merged:
                existing = merged[key]
                if v.severity.rank > existing.severity.rank:
                    existing.severity = v.severity
                for r in v.references:
                    if r not in existing.references:
                        existing.references.append(r)
                if not existing.solution and v.solution:
                    existing.solution = v.solution
                if not existing.fixed_version and v.fixed_version:
                    existing.fixed_version = v.fixed_version
                if not existing.vulnerable_range and v.vulnerable_range:
                    existing.vulnerable_range = v.vulnerable_range
                if not existing.description and v.description:
                    existing.description = v.description
                for s in v.sources:
                    if s not in existing.sources:
                        existing.sources.append(s)
            else:
                merged[key] = v
        result = list(merged.values())
        result.sort(key=lambda x: x.severity.rank, reverse=True)
        return result

    def analyze_components(self, components: list[Component]) -> None:
        concurrency = max(1, int(self.config.get("general.concurrency", 4)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            future_map = {ex.submit(self.analyze_component, c): c for c in components}
            for fut in concurrent.futures.as_completed(future_map):
                comp = future_map[fut]
                try:
                    comp.vulnerabilities = fut.result()
                except Exception as e:  # noqa: BLE001
                    comp.vulnerabilities = []
                    _LOGGER.warning("分析组件 %s 失败: %s", comp.coordinate, e)
