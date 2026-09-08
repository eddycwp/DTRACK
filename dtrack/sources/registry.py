"""Repository fetcher registry (separate from base to avoid circular imports)."""
from __future__ import annotations

from typing import Type

from .base import SourceFetcher
from .gitlab import GitLabFetcher
from .harbor import HarborFetcher
from .nexus import NexusFetcher

_REGISTRY: dict[str, Type[SourceFetcher]] = {
    "gitlab": GitLabFetcher,
    "nexus": NexusFetcher,
    "harbor": HarborFetcher,
}


def get_fetcher(name: str, config: Config) -> SourceFetcher:
    cls = _REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown repository source '{name}'. Known: {list(_REGISTRY)}")
    return cls(config)


def list_fetchers() -> list[str]:
    return list(_REGISTRY)
