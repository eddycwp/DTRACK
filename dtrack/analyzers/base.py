"""Analyzer plugin interface.

Each language/package type registers a ``PackageAnalyzer`` that turns a target
(a path, artifact, or image reference) into a list of ``Component`` objects.
Java is implemented now; c/c++ and docker are future extension points.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import Component
from ..core.types import Language


class PackageAnalyzer(ABC):
    language: Language = Language.JAVA

    def __init__(self, config) -> None:
        self.config = config

    @abstractmethod
    def analyze(self, target: str) -> list[Component]:
        """Return the components found in ``target`` (without vulnerability data)."""
        raise NotImplementedError

    @abstractmethod
    def describe_target(self, target: str) -> str:
        """A human-readable label for the analyzed target (used in reports)."""
        raise NotImplementedError
