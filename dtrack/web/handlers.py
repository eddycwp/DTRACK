"""HTTP API + static file server for the DTrack web platform.

A tiny stdlib ``http.server`` router so the whole stack stays dependency-free.
All JSON endpoints live under ``/api``; everything else is served from the built
frontend (``web/dist``) with SPA fallback to ``index.html``.
"""
from __future__ import annotations

import json
import mimetypes
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

from .service import WebService


class _Router:
    """Stateless view functions bound to a single :class:`WebService`."""

    def __init__(self, service: WebService, dist_dir: str) -> None:
        self.svc = service
        self.dist_dir = dist_dir

    # ---- helpers ----
    @staticmethod
    def _json(obj: Any, status: int = 200) -> tuple:
        return (
            status,
            {"Content-Type": "application/json; charset=utf-8"},
            json.dumps(obj, ensure_ascii=False).encode("utf-8"),
        )

    @staticmethod
    def _md(text: str, filename: str) -> tuple:
        return (
            200,
            {
                "Content-Type": "text/markdown; charset=utf-8",
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
            text.encode("utf-8"),
        )

    @staticmethod
    def _err(msg: str, status: int = 400) -> tuple:
        return (
            status,
            {"Content-Type": "application/json; charset=utf-8"},
            json.dumps({"error": msg}, ensure_ascii=False).encode("utf-8"),
        )

    @staticmethod
    def _ref_type(parts: list[str]) -> str:
        """从路径段判断资源类型：whitelist / project。"""
        return "whitelist" if "whitelists" in parts else "project"

    @staticmethod
    def _version_id(parts: list[str]) -> int:
        """从路径段解析 version 后的数字 id（如 /.../version/5/scan）。"""
        return int(parts[parts.index("version") + 1])

    # ---- routing ----
    def dispatch(self, method: str, raw_path: str, body: bytes = b"") -> tuple:
        parsed = urllib.parse.urlparse(raw_path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        payload: dict = {}
        if body:
            try:
                payload = json.loads(body.decode("utf-8", "replace"))
            except (ValueError, TypeError):
                payload = {}
        try:
            if not path.startswith("/api/"):
                return self._serve_static(path)
            p = path[len("/api"):].rstrip("/") or "/"
            if p == "/health":
                return self._json({"status": "ok"})
            if p == "/config" and method == "GET":
                return self._json(self.svc.get_config())
            if p == "/config" and method == "POST":
                return self._json(self.svc.update_config(payload))
            if p == "/gitlab/projects" and method == "GET":
                return self._json(self.svc.list_gitlab_projects())
            if p == "/gitlab/refs" and method == "GET":
                project = (qs.get("project") or [""])[0]
                return self._json(self.svc.list_gitlab_refs(project))

            # components of a specific whitelist/project version
            # (must NOT swallow /components — the component catalogue route)
            if p.endswith("/components") and "/version/" in p and method == "GET":
                parts = [x for x in p.split("/") if x]
                return self._json(self.svc.list_version_components(
                    self._ref_type(parts), self._version_id(parts)))

            # whitelists
            if p == "/whitelists" and method == "GET":
                return self._json(self.svc.list_whitelists())
            if p == "/whitelists/import" and method == "POST":
                if payload.get("source") in ("harbor", "docker", "gitlab-jar"):
                    return self._json(self.svc.import_whitelist_scan(payload), status=201)
                return self._json(self.svc.import_whitelist(
                    payload.get("pom_text"), payload.get("gitlab_project"),
                    payload.get("ref")), status=201)
            if p.startswith("/whitelists/") and method == "GET":
                rest = p[len("/whitelists/"):]
                if "/" in rest:
                    wid, sub = rest.split("/", 1)
                    if sub == "versions":
                        return self._json(self.svc.list_whitelist_versions(int(wid)))
                else:
                    return self._json(self.svc.list_whitelist_versions(int(rest)))
            if p.startswith("/whitelists/version/") and method == "GET" \
                    and not p.endswith(("/report", "/report.pdf", "/scan")):
                vid = int(p.split("/")[-1])
                v = self.svc.get_version("whitelist", vid)
                if v is None:
                    return self._err("not found", 404)
                return self._json(v)

            # projects
            if p == "/projects" and method == "GET":
                return self._json(self.svc.list_projects())
            if p == "/projects/import" and method == "POST":
                if payload.get("source") in ("harbor", "docker", "gitlab-jar"):
                    return self._json(self.svc.import_project_scan(payload), status=201)
                return self._json(self.svc.import_project(
                    payload.get("pom_text"), payload.get("gitlab_project"),
                    payload.get("ref"), payload.get("name")), status=201)
            if p.startswith("/projects/") and method == "GET":
                rest = p[len("/projects/"):]
                if "/" in rest:
                    pid, sub = rest.split("/", 1)
                    if sub == "versions":
                        return self._json(self.svc.list_project_versions(int(pid)))
                else:
                    return self._json(self.svc.list_project_versions(int(rest)))
            if p.startswith("/projects/version/") and method == "GET" \
                    and not p.endswith(("/report", "/report.pdf", "/scan")):
                vid = int(p.split("/")[-1])
                v = self.svc.get_version("project", vid)
                if v is None:
                    return self._err("not found", 404)
                return self._json(v)

            # version scan / delete / report (shared for whitelist & project)
            if p.endswith("/scan") and method == "POST":
                parts = [x for x in p.split("/") if x]
                # .../whitelists/version/<vid>/scan  or .../projects/version/<vid>/scan
                vid = self._version_id(parts)
                self.svc.scan_version_async(self._ref_type(parts), vid)
                return self._json({"ok": True, "version_id": vid,
                                   "scan_status": "scanning"})
            if p.endswith("/report") and method == "GET":
                parts = [x for x in p.split("/") if x]
                ref_type = self._ref_type(parts)
                vid = self._version_id(parts)
                md = self.svc.get_report(ref_type, vid)
                if md is None:
                    return self._err("not found", 404)
                return self._md(md, f"dtrack_report_{ref_type}_{vid}.md")
            if p.endswith("/report.pdf") and method == "GET":
                parts = [x for x in p.split("/") if x]
                ref_type = self._ref_type(parts)
                vid = self._version_id(parts)
                try:
                    pdf = self.svc.get_report_pdf(ref_type, vid)
                except Exception as e:  # noqa: BLE001
                    return self._err(f"生成 PDF 失败：{e}", 400)
                if not pdf:
                    return self._err("not found", 404)
                return (200, {
                    "Content-Type": "application/pdf",
                    "Content-Disposition":
                        f'attachment; filename="dtrack_report_{ref_type}_{vid}.pdf"',
                }, pdf)
            if "/version/" in p and method == "DELETE":
                parts = [x for x in p.split("/") if x]
                self.svc.delete_version(self._ref_type(parts), self._version_id(parts))
                return self._json({"ok": True})

            # components
            if p == "/components" and method == "GET":
                filters = {}
                if qs.get("q"):
                    filters["q"] = qs["q"][0]
                if "is_whitelist" in qs:
                    filters["is_whitelist"] = qs["is_whitelist"][0] in ("1", "true")
                if qs.get("severity"):
                    filters["severity"] = qs["severity"][0]
                return self._json(self.svc.list_components(filters))
            if p == "/components/detail" and method == "GET":
                coord = qs.get("coord", [None])[0]
                if not coord:
                    return self._err("coord required")
                detail = self.svc.get_component_detail(coord)
                if detail is None:
                    return self._err("component not found", 404)
                return self._json(detail)

            return self._err(f"unknown route {method} {p}", 404)
        except ValueError as e:
            # 输入/参数类错误（如缺少字段、非法来源）统一返回 400
            return self._err(f"{e}", 400)
        except RuntimeError as e:
            # 配置/环境类错误（如未配置奇安信/GitLab）统一返回 400
            return self._err(f"{e}", 400)
        except Exception as e:  # noqa: BLE001
            return self._err(f"{type(e).__name__}: {e}", 500)

    # ---- static ----
    def _serve_static(self, path: str) -> tuple:
        if not self.dist_dir or not os.path.isdir(self.dist_dir):
            return self._err("frontend dist not built", 404)
        rel = path.lstrip("/")
        if rel == "" or rel.endswith("/"):
            rel = "index.html"
        # prevent path traversal
        full = os.path.normpath(os.path.join(self.dist_dir, rel))
        if not full.startswith(os.path.normpath(self.dist_dir)):
            return self._err("forbidden", 403)
        if not os.path.isfile(full):
            # SPA fallback
            full = os.path.join(self.dist_dir, "index.html")
        ctype, _ = mimetypes.guess_type(full)
        with open(full, "rb") as f:
            data = f.read()
        return 200, {"Content-Type": ctype or "application/octet-stream"}, data


class Handler(BaseHTTPRequestHandler):
    router: _Router

    def _handle(self):
        body = b""
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            body = self.rfile.read(length)
        status, headers, data = self.router.dispatch(self.command, self.path, body)
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        # 禁止缓存 API 响应，避免刷新页面时拿到旧配置导致开关回退
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.wfile.write(data)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


def run(host: str, port: int, db_path: str, config_path: str, dist_dir: str) -> None:
    from .store import Db
    db = Db(db_path)
    svc = WebService(db, config_path)
    router = _Router(svc, dist_dir)
    Handler.router = router
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[DTrack Web] 服务已启动: http://{host}:{port}")
    print(f"            数据库: {db_path}")
    print(f"            配置:   {config_path}")
    if not dist_dir or not os.path.isdir(dist_dir):
        print("[DTrack Web] 警告: 前端未构建（web/dist 不存在），仅 API 可用。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[DTrack Web] 已停止。")
    finally:
        db.close()
