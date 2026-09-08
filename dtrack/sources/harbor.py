"""Harbor container registry fetcher.

Lists projects, repositories and image tags via the Harbor v2.0 API. The returned
references (``registry/project/repo:tag``) are consumed by the (future) docker
image analyzer. Address and credentials are configurable.
"""
from __future__ import annotations

from ..config import Config
from ..utils.http import HttpClient, basic_auth_header
from .base import SourceFetcher


class HarborFetcher(SourceFetcher):
    name = "harbor"

    def enabled(self) -> bool:
        return bool(self.config.get("repos.harbor.base_url"))

    def _client(self) -> HttpClient:
        user = self.config.get("repos.harbor.username")
        pwd = self.config.get("repos.harbor.password")
        headers = basic_auth_header(user, pwd) if user and pwd else {}
        return HttpClient(timeout=float(self.config.get("general.timeout", 30)), retries=3, headers=headers)

    def _base(self) -> str:
        return (self.config.get("repos.harbor.base_url") or "").rstrip("/")

    def list_projects(self) -> list[dict]:
        url = f"{self._base()}/api/v2.0/projects"
        out = []
        page = 1
        while page <= 20:
            resp = self._client().get(url, params={"page": page, "page_size": 100})
            if not resp.ok:
                break
            data = resp.json() or []
            if not data:
                break
            for p in data:
                out.append({"name": p.get("name"), "project_id": p.get("project_id")})
            if len(data) < 100:
                break
            page += 1
        return out

    def list_images(self) -> list[dict]:
        base = self._base()
        images = []
        for proj in self.list_projects():
            pname = proj["name"]
            repos_url = f"{base}/api/v2.0/projects/{pname}/repositories"
            rresp = self._client().get(repos_url, params={"page": 1, "page_size": 100})
            if not rresp.ok:
                continue
            for repo in (rresp.json() or []):
                rname = repo.get("name")
                arts_url = f"{base}/api/v2.0/projects/{pname}/repositories/{rname.split('/')[-1]}/artifacts"
                aresp = self._client().get(arts_url, params={"with_tag": True, "page": 1, "page_size": 100})
                if not aresp.ok:
                    continue
                for art in (aresp.json() or []):
                    for tag in (art.get("tags") or []):
                        t = tag.get("name")
                        if t:
                            images.append({
                                "reference": f"{base}/{rname}:{t}",
                                "project": pname,
                                "repository": rname,
                                "tag": t,
                                "digest": art.get("digest"),
                            })
        return images
