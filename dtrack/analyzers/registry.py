"""Analyzer registry: maps a language to its concrete analyzer implementation.

Kept separate from ``base.py`` to avoid a circular import (concrete analyzers
import ``PackageAnalyzer`` from base, while the registry imports the concretes).
"""
from __future__ import annotations

from typing import Type

from ..core.types import Language
from .base import PackageAnalyzer
from .cc.cc_analyzer import CCAnalyzer
from .java.java_analyzer import JavaAnalyzer

_REGISTRY: dict[Language, Type[PackageAnalyzer]] = {
    Language.JAVA: JavaAnalyzer,
    Language.CC: CCAnalyzer,
}


def register_analyzer(language: Language, cls: Type[PackageAnalyzer]) -> None:
    _REGISTRY[language] = cls


def get_analyzer(language: Language, config) -> PackageAnalyzer:
    cls = _REGISTRY.get(language)
    if cls is None:
        raise ValueError(f"No analyzer registered for language '{language.value}'. "
                         f"Available: {[l.value for l in _REGISTRY]}")
    return cls(config)


def supported_languages() -> list[Language]:
    return list(_REGISTRY.keys())
