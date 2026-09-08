"""Repository fetcher plugin interface.

A ``SourceFetcher`` pulls projects/components/images from an external repository
(GitLab, Nexus, Harbor, ...). Addresses and credentials are config-driven so the
same logic can later be driven from a web UI.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..config import Config


class SourceFetcher(ABC):
    name: str = "base"

    def __init__(self, config: Config) -> None:
        self.config = config

    @abstractmethod
    def enabled(self) -> bool:
        ...

    @abstractmethod
    def list_projects(self) -> list[dict]:
        """Return a list of {id, name, path, ...} project-like entries."""
        ...

    def list_images(self) -> list[dict]:
        """Optional: list container images (for docker-capable sources)."""
        raise NotImplementedError(f"{self.name} does not support image listing")
