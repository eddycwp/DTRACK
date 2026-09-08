"""Best-effort license lookup for Maven artifacts.

Reads the ``<licenses>`` block of an artifact's POM from Maven Central. Results
are cached on disk (same TTL as the rest of the HTTP cache) so repeated runs are
cheap. Failures are non-fatal — callers treat ``None`` as "license unknown".
"""
from __future__ import annotations

import os
from typing import Optional

from ...config import Config
from ...utils.cache import FileCache
from ...utils.http import HttpClient
from .pom_parser import parse_pom_text


def maven_central_license(config: Config, group: str, name: str, version: str) -> Optional[str]:
    if not (group and name and version):
        return None
    cache_dir = config.get("general.cache_dir")
    ttl = int(config.get("general.cache_ttl", 86400))
    cache = FileCache(os.path.join(cache_dir, "maven-lic"), ttl=ttl)
    key = f"lic:{group}:{name}:{version}"
    cached = cache.get(key)
    if cached is not None:
        return cached or None

    central = (config.get("maven.central_url") or "https://repo1.maven.org/maven2").rstrip("/")
    gpath = "/".join(group.split("."))
    url = f"{central}/{gpath}/{name}/{version}/{name}-{version}.pom"
    http = HttpClient(timeout=float(config.get("general.timeout", 30)), retries=2)
    lic = None
    try:
        resp = http.get(url)
        if resp.ok:
            pom = parse_pom_text(resp.text, resolve=True)
            if pom.licenses:
                lic = "; ".join(pom.licenses)
    except Exception:  # noqa: BLE001 - license is best-effort only
        lic = None
    cache.set(key, lic or "")
    return lic
