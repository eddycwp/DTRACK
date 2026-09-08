"""Vulnerability source registry.

Separate from ``base.py`` so concrete sources (which import ``VulnerabilitySource``
from base) don't create a circular import.
"""
from __future__ import annotations

from typing import Type

from .. import get_logger
from .base import VulnerabilitySource
from .github import GitHubSource
from .nvd import NvdSource
from .osv import OsvSource
from .qianxin import QianxinSource

_LOGGER = get_logger()

_REGISTRY: dict[str, Type[VulnerabilitySource]] = {
    "nvd": NvdSource,
    "github": GitHubSource,
    "qianxin": QianxinSource,
    "osv": OsvSource,
}


def get_source(name: str, config) -> VulnerabilitySource:
    cls = _REGISTRY[name]
    return cls(config)


def get_enabled_sources(config) -> list[VulnerabilitySource]:
    wanted = config.get("vuln.sources", ["nvd", "github", "qianxin"])
    out = []
    for name in wanted:
        try:
            src = get_source(name, config)
        except Exception:  # noqa: BLE001
            continue
        if src.enabled():
            out.append(src)
        else:
            # 明确告知被跳过的源及其原因，避免静默失败导致"配置了却不生效"
            _LOGGER.warning(
                "漏洞源 '%s' 已列入 vuln.sources 但未启用：%s",
                name, src.disabled_reason())
    return out
