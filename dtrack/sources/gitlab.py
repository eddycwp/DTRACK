"""GitLab repository fetcher.

Used to list projects and download a repository archive (then analyzed locally by
the Java analyzer). GitLab is a source-code host, so it feeds the *analyze* path
rather than serving maven artifacts directly.
"""
from __future__ import annotations

import os
import urllib.parse

from ..config import Config
from ..utils.http import HttpClient
from .base import SourceFetcher


class GitLabFetcher(SourceFetcher):
    name = "gitlab"

    def enabled(self) -> bool:
        return bool(self.config.get("repos.gitlab.base_url")) and bool(self.config.get("repos.gitlab.token"))

    def _client(self) -> HttpClient:
        token = self.config.get("repos.gitlab.token")
        headers = {"PRIVATE-TOKEN": token} if token else {}
        return HttpClient(timeout=float(self.config.get("general.timeout", 30)), retries=3, headers=headers)

    def _base(self) -> str:
        return (self.config.get("repos.gitlab.base_url") or "https://gitlab.com").rstrip("/")

    def list_projects(self) -> list[dict]:
        url = f"{self._base()}/api/v4/projects"
        out = []
        page = 1
        while page <= 20:
            resp = self._client().get(url, params={"membership": True, "per_page": 100, "page": page})
            if not resp.ok:
                break
            data = resp.json() or []
            if not data:
                break
            for p in data:
                out.append({
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "path": p.get("path_with_namespace"),
                    "default_branch": p.get("default_branch"),
                    "web_url": p.get("web_url"),
                })
            if len(data) < 100:
                break
            page += 1
        return out

    def list_refs(self, project_path: str) -> dict:
        """列出指定项目的分支与标签。

        Returns ``{"branches": [...], "tags": [...]}``（均按名称排序）。
        """
        pid = urllib.parse.quote(project_path, safe="")
        out = {"branches": [], "tags": []}
        for kind, api_path in (("branches", "branches"), ("tags", "tags")):
            url = f"{self._base()}/api/v4/projects/{pid}/repository/{api_path}"
            page = 1
            while page <= 20:
                resp = self._client().get(url, params={"per_page": 100, "page": page})
                if not resp.ok:
                    break
                data = resp.json() or []
                if not data:
                    break
                out[kind].extend(item.get("name") for item in data if item.get("name"))
                if len(data) < 100:
                    break
                page += 1
            out[kind] = sorted(set(out[kind]))
        return out

    def download_repository(self, project_path: str, ref: str = None, dest_dir: str = ".") -> str:
        """Download a repository archive (.tar.gz) for ``project_path`` to ``dest_dir``.

        Returns the local path of the downloaded archive.
        """
        pid = urllib.parse.quote(project_path, safe="")
        url = f"{self._base()}/api/v4/projects/{pid}/repository/archive"
        params = {"sha": ref} if ref else {}
        resp = self._client().get(url, params=params)
        if not resp.ok:
            raise RuntimeError(f"GitLab archive download failed ({resp.status}): {project_path}")
        os.makedirs(dest_dir, exist_ok=True)
        fname = f"{project_path.replace('/', '_')}{('_' + ref) if ref else ''}.tar.gz"
        path = os.path.join(dest_dir, fname)
        with open(path, "wb") as f:
            f.write(resp.content)
        return path
