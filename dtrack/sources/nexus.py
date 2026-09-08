"""Nexus repository fetcher.

Supports:
  * Maven artifacts  - download a pom/jar by GAV for local analysis.
  * Docker images    - list tags via the Docker Registry v2 API.

Both the base URL and credentials are configurable. (Nexus Raw/other repo formats
can be added later without changing the interface.)
"""
from __future__ import annotations

import os

from ..config import Config
from ..utils.http import HttpClient, basic_auth_header
from .base import SourceFetcher


class NexusFetcher(SourceFetcher):
    name = "nexus"

    def enabled(self) -> bool:
        return bool(self.config.get("repos.nexus.base_url"))

    def _client(self) -> HttpClient:
        user = self.config.get("repos.nexus.username")
        pwd = self.config.get("repos.nexus.password")
        headers = basic_auth_header(user, pwd) if user and pwd else {}
        return HttpClient(timeout=float(self.config.get("general.timeout", 30)), retries=3, headers=headers)

    def _base(self) -> str:
        return (self.config.get("repos.nexus.base_url") or "").rstrip("/")

    def list_projects(self) -> list[dict]:
        # Nexus doesn't have "projects"; surface configured repositories instead.
        url = f"{self._base()}/service/rest/v1/repositories"
        resp = self._client().get(url)
        if not resp.ok:
            return []
        return [{"name": r.get("name"), "format": r.get("format"), "type": r.get("type")}
                for r in (resp.json() or [])]

    def download_maven_artifact(self, repo: str, group: str, artifact: str,
                                version: str, dest_dir: str = ".", ext: str = "pom") -> str:
        """Download a maven artifact (default the .pom) and return its local path."""
        gpath = "/".join(group.split("."))
        url = f"{self._base()}/repository/{repo}/{gpath}/{artifact}/{version}/{artifact}-{version}.{ext}"
        resp = self._client().get(url)
        if not resp.ok:
            raise RuntimeError(f"Nexus download failed ({resp.status}): {url}")
        os.makedirs(dest_dir, exist_ok=True)
        path = os.path.join(dest_dir, f"{artifact}-{version}.{ext}")
        with open(path, "wb") as f:
            f.write(resp.content)
        return path

    def list_docker_tags(self, repo: str) -> list[str]:
        url = f"{self._base()}/v2/{repo}/tags/list"
        resp = self._client().get(url)
        if not resp.ok:
            return []
        return (resp.json() or {}).get("tags") or []
