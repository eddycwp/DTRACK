"""Artifact (binary / container image) vulnerability scanning.

This package integrates QIANXIN 开源卫士 OpenAPI V3 binary & image scanning so that
``jar``/``dll``/``so``/``lib`` (local, Nexus, Artifactory) and Docker images (local,
Harbor, DockerHub, Nexus, Artifactory) can be submitted for analysis and the results
normalized into DTrack's :class:`Component` / :class:`Vulnerability` models.

See ``docs/references/qianxin_openapi_v3_reference.md`` for the API contract.
"""
from __future__ import annotations

from .qianxin_scan import (
    QianxinScanner,
    ScanKind,
    ScanTarget,
    scan_target,
)

__all__ = ["QianxinScanner", "ScanKind", "ScanTarget", "scan_target"]
