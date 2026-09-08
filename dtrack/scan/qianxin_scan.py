"""QIANXIN 开源卫士 OpenAPI V3 binary & container-image scanner.

Submits scan tasks for jar/dll/so/lib (local, Nexus, Artifactory) and Docker images
(local, Harbor, DockerHub, Nexus, Artifactory), polls for completion, then fetches
and normalizes the component/vulnerability results into DTrack models.

Full API contract: ``docs/references/qianxin_openapi_v3_reference.md``.
"""
from __future__ import annotations

import io
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from .. import get_logger
from ..config import Config
from ..core.models import AnalysisResult, Component, Vulnerability
from ..core.types import Language, SourceType
from ..utils.archive import zip_directory
from ..utils.http import HttpClient, basic_auth_header
from ..vuln.qianxin import qx_level_to_severity

_LOGGER = get_logger()

# --- OpenAPI V3 endpoint paths (relative to gateway base_url) ---
_P_BINARY_FILE = "/zuul/scan-center/task/binary-file/analysis"
_P_BINARY_DIR = "/scan-center/task/binary-dir/analysis"
_P_BINARY_NEXUS = "/scan-center/task/binary-nexus/analysis"
_P_BINARY_ARTIFACTORY = "/scan-center/task/binary-artifactory/analysis"
_P_IMAGE_FILE = "/zuul/scan-center/task/image-file/analysis"
_P_IMAGE_FEATURE = "/scan-center/task/image-feature/analysis"
_P_IMAGE_ARTIFACTORY = "/scan-center/task/image-artifactory/analysis"
_P_IMAGE_HARBOR = "/scan-center/task/image-harbor/analysis"
_P_IMAGE_DOCKERHUB = "/scan-center/task/image-dockerhub/analysis"
_P_IMAGE_NEXUS = "/scan-center/task/image-nexus/analysis"
_P_RESULT = "/open-api/v3/task/binary/result"
_P_COMPONENT_LIST = "/open-api/v3/task/binary/component/list"
_P_VULN_LIST = "/open-api/v3/task/binary/vulnerability/list"
_P_UNKNOWN_LIST = "/open-api/v3/task/binary/unknown/component/list"
_P_FAIL_FILE = "/open-api/v3/task/binary/fail-file"

_AUTH_TYPE_USERPASS = 1
_AUTH_TYPE_APIKEY = 2
_AUTH_TYPE_IDENTITY = 3


class ScanKind(str, Enum):
    JAR_LOCAL = "jar-local"                 # 本地 jar/war/zip 目录或文件
    JAR_NEXUS = "jar-nexus"                # Nexus 上的二进制制品
    JAR_ARTIFACTORY = "jar-artifactory"     # Artifactory 上的二进制制品
    IMAGE_LOCAL = "image-local"             # 本地 docker save 出来的 tar
    IMAGE_HARBOR = "image-harbor"           # Harbor 镜像
    IMAGE_DOCKERHUB = "image-dockerhub"     # DockerHub 镜像
    IMAGE_NEXUS = "image-nexus"             # Nexus 镜像
    IMAGE_ARTIFACTORY = "image-artifactory" # Artifactory 镜像

    @property
    def is_image(self) -> bool:
        return self.value.startswith("image")


@dataclass
class ScanTarget:
    """Describes what to scan and how to authenticate against the registry."""
    kind: ScanKind
    path: Optional[str] = None           # local file/dir (jar-local / image-local)
    url: Optional[str] = None            # registry artifact/image uri
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None          # api key / identity token
    auth_type: int = _AUTH_TYPE_USERPASS
    language_hint: Optional[str] = None  # override normalized language


def _split_coord(s: Optional[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse ``group:artifact:version`` → (group, artifact, version)."""
    if not s:
        return None, None, None
    parts = s.split(":", 2)
    if len(parts) == 3:
        return parts[0] or None, parts[1] or None, parts[2] or None
    if len(parts) == 2:
        return None, parts[0] or None, parts[1] or None
    return None, parts[0] or None, None


def _lang_for_target(target: ScanTarget) -> Language:
    if target.language_hint:
        try:
            return Language(target.language_hint)
        except ValueError:
            pass
    if target.kind.is_image:
        return Language.DOCKER
    # binary: jar/war => java, everything else (dll/so/lib) => c/c++
    if target.kind in (ScanKind.JAR_LOCAL, ScanKind.JAR_NEXUS, ScanKind.JAR_ARTIFACTORY):
        return Language.JAVA
    return Language.CC


class QianxinScanner:
    """Submit & collect QIANXIN binary/image scans, normalized to DTrack models."""

    def __init__(self, config: Config) -> None:
        self.config = config

    # ---- config helpers (scan.qianxin falls back to vuln.qianxin) ----
    def _cfg(self, key: str, default: Any = None) -> Any:
        v = self.config.get(f"scan.qianxin.{key}")
        if v is None:
            v = self.config.get(f"vuln.qianxin.{key}")
        return v if v is not None else default

    def _base_url(self) -> str:
        url = self._cfg("base_url")
        if not url:
            raise ValueError(
                "缺少奇安信网关地址：请在配置中设置 scan.qianxin.base_url "
                "(或复用 vuln.qianxin.base_url)。"
            )
        return str(url).rstrip("/")

    def _client(self) -> HttpClient:
        return HttpClient(
            timeout=float(self.config.get("general.timeout", 30)),
            retries=3,
            verify_ssl=bool(self._cfg("verify_ssl", False)),
            headers={"User-Agent": "DTrack/0.1"},
        )

    def _auth_header(self) -> dict:
        auth_type = (self._cfg("auth_type") or "private-token").lower()
        if auth_type == "basic":
            return basic_auth_header(self._cfg("username"), self._cfg("password"))
        tok = self._cfg("token") or ""
        return {"Authorization": f"Private-Token {tok}"}

    def _project_id(self) -> str:
        pid = self._cfg("project_id")
        if not pid:
            raise ValueError(
                "缺少奇安信项目编号 scan.qianxin.project_id（提交扫描任务必填）。"
            )
        return str(pid)

    # ---- low-level request helpers ----
    @staticmethod
    def _ok(data: Optional[dict]) -> bool:
        if not data:
            return False
        code = data.get("Code") if "Code" in data else data.get("code")
        return code in (1, "1")

    def _post_json(self, path: str, body: dict) -> dict:
        client = self._client()
        url = self._base_url() + path
        resp = client.post(url, json_body=body, headers=self._auth_header())
        if not resp.ok:
            raise RuntimeError(f"奇安信接口失败 {path}: status={resp.status}, {resp.text[:300]}")
        return resp.json() or {}

    def _post_multipart(self, path: str, fields: dict, files: list) -> dict:
        client = self._client()
        url = self._base_url() + path
        resp = client.post_multipart(url, fields=fields, files=files, headers=self._auth_header())
        if not resp.ok:
            raise RuntimeError(f"奇安信接口失败 {path}: status={resp.status}, {resp.text[:300]}")
        return resp.json() or {}

    def _get(self, path: str, params: dict) -> dict:
        client = self._client()
        url = self._base_url() + path
        resp = client.get(url, params=params, headers=self._auth_header())
        if not resp.ok:
            raise RuntimeError(f"奇安信接口失败 {path}: status={resp.status}, {resp.text[:300]}")
        return resp.json() or {}

    @staticmethod
    def _task_id(data: dict) -> int:
        code = data.get("Code") if "Code" in data else data.get("code")
        msg = data.get("Message") if "Message" in data else data.get("message")
        if code not in (1, "1", None):
            raise RuntimeError(f"奇安信提交扫描任务失败: code={code}, message={msg}")
        payload = data.get("Data") if "Data" in data else data.get("data")
        if isinstance(payload, dict):
            tid = payload.get("taskId")
            if tid is not None:
                return int(tid)
        # some responses nest differently
        tid = data.get("taskId") or (data.get("data") or {}).get("taskId")
        if tid is None:
            raise RuntimeError(f"奇安信响应缺少 taskId: {data}")
        return int(tid)

    # ---- submit ----
    def submit_binary_file(self, content: bytes, filename: str, task_name: str,
                           project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        mime = "application/x-tar" if filename.lower().endswith(".tar") else "application/octet-stream"
        return self._task_id(self._post_multipart(
            _P_BINARY_FILE,
            fields={"projectId": pid, "taskName": task_name},
            files=[("file", filename, content, mime)],
        ))

    def submit_binary_dir(self, dir_path: str, task_name: str,
                          project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_json(_P_BINARY_DIR, {
            "dirPath": dir_path, "projectId": pid, "taskName": task_name,
        }))

    def submit_binary_nexus(self, url: str, username: str, password: str, task_name: str,
                            token: Optional[str] = None, auth_type: int = _AUTH_TYPE_USERPASS,
                            project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_json(_P_BINARY_NEXUS, {
            "projectId": pid, "taskName": task_name, "url": url,
            "username": username, "password": password, "token": token, "authType": auth_type,
        }))

    def submit_binary_artifactory(self, url: str, username: str, password: str, task_name: str,
                                  token: Optional[str] = None, auth_type: int = _AUTH_TYPE_USERPASS,
                                  project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_json(_P_BINARY_ARTIFACTORY, {
            "projectId": pid, "taskName": task_name, "url": url,
            "username": username, "password": password, "token": token, "authType": auth_type,
        }))

    def submit_image_file(self, content: bytes, filename: str, task_name: str,
                          project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_multipart(
            _P_IMAGE_FILE,
            fields={"projectId": pid, "taskName": task_name},
            files=[("file", filename, content, "application/x-tar")],
        ))

    def submit_image_feature(self, content: bytes, filename: str, task_name: str,
                             project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_multipart(
            _P_IMAGE_FEATURE,
            fields={"projectId": pid, "taskName": task_name},
            files=[("file", filename, content, "application/zip")],
        ))

    def submit_image_harbor(self, url: str, username: str, password: str, task_name: str,
                            project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_json(_P_IMAGE_HARBOR, {
            "projectId": pid, "taskName": task_name, "url": url,
            "username": username, "password": password,
        }))

    def submit_image_dockerhub(self, url: str, username: str, password: str, task_name: str,
                               project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_json(_P_IMAGE_DOCKERHUB, {
            "projectId": pid, "taskName": task_name, "url": url,
            "username": username, "password": password,
        }))

    def submit_image_nexus(self, url: str, username: str, password: str, task_name: str,
                           project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_json(_P_IMAGE_NEXUS, {
            "projectId": pid, "taskName": task_name, "url": url,
            "username": username, "password": password,
        }))

    def submit_image_artifactory(self, url: str, username: str, password: str, task_name: str,
                                 project_id: Optional[str] = None) -> int:
        pid = project_id or self._project_id()
        return self._task_id(self._post_json(_P_IMAGE_ARTIFACTORY, {
            "projectId": pid, "taskName": task_name, "url": url,
            "username": username, "password": password,
        }))

    # ---- poll & fetch ----
    def get_result(self, task_id: int) -> dict:
        return self._get(_P_RESULT, {"taskId": task_id})

    def wait_done(self, task_id: int, poll_interval: Optional[int] = None,
                  poll_timeout: Optional[int] = None) -> dict:
        interval = poll_interval or int(self._cfg("poll_interval", 5))
        timeout = poll_timeout or int(self._cfg("poll_timeout", 1800))
        deadline = time.time() + timeout
        last = {}
        while True:
            last = self.get_result(task_id)
            code = last.get("code")
            if code == 9:  # 检测中
                if time.time() > deadline:
                    raise TimeoutError(f"奇安信扫描任务 {task_id} 在 {timeout}s 内未完成。")
                _LOGGER.info("奇安信扫描任务 %s 检测中，%ss 后重试…", task_id, interval)
                time.sleep(interval)
                continue
            if not self._ok(last):
                _LOGGER.warning("奇安信扫描任务 %s 返回非成功状态: %s", task_id, last.get("message"))
            return last

    def _paginate(self, path: str, task_id: int, page_size: int) -> list[dict]:
        out: list[dict] = []
        page = 0
        while True:
            body = {"taskId": task_id, "pageIndex": page, "pageSize": page_size}
            data = self._post_json(path, body)
            content = ((data.get("data") or {}).get("content")) or []
            out.extend(content)
            total = (data.get("data") or {}).get("total", 0)
            if not content or len(out) >= total:
                break
            page += 1
        return out

    def list_components(self, task_id: int) -> list[dict]:
        return self._paginate(_P_COMPONENT_LIST, task_id, int(self._cfg("page_size", 100)))

    def list_vulnerabilities(self, task_id: int) -> list[dict]:
        return self._paginate(_P_VULN_LIST, task_id, int(self._cfg("page_size", 100)))

    def list_unknown_components(self, task_id: int) -> list[dict]:
        return self._paginate(_P_UNKNOWN_LIST, task_id, int(self._cfg("page_size", 100)))

    # ---- normalization ----
    @staticmethod
    def _qx_to_component(qx: dict, language: Language) -> Component:
        group = name = None
        version = qx.get("componentVersion")
        coords = qx.get("coordinates") or []
        if coords:
            g, a, v = _split_coord(coords[0])
            group, name = g, a
            if v:
                version = v
        if not name:
            srcs = qx.get("componentSourceInfos") or []
            if srcs:
                g, a, v = _split_coord(srcs[0].get("source") or "")
                if a:
                    group, name = g, a
                    if v:
                        version = v
        if not name:
            name = qx.get("componentName") or "unknown"
        lic = None
        lis = qx.get("licenseInfos") or []
        if lis:
            lic = lis[0].get("licenseShortName") or lis[0].get("licenseName")
        src_path = None
        if qx.get("componentSourceInfos"):
            src_path = qx["componentSourceInfos"][0].get("path")
        comp = Component(
            group=group, name=name, version=version, language=language,
            license=lic, source=src_path,
            extra={
                "qx_component_id": qx.get("componentId"),
                "recommendedVersion": qx.get("recommendedVersion"),
                "latestVersion": qx.get("latestVersion"),
                "componentType": qx.get("componentType"),
                "projectName": qx.get("projectName"),
                "packageType": qx.get("packageType"),
            },
        )
        return comp

    @staticmethod
    def _vuln_dedup_key(qxv: dict) -> str:
        return qxv.get("cve") or qxv.get("qaxOssId") or str(qxv.get("vulnerabilityId"))

    def _qx_to_vulnerability(self, qxv: dict) -> Vulnerability:
        cve = qxv.get("cve")
        qax = qxv.get("qaxOssId") or qxv.get("vulnerabilityId")
        vid = cve or qax or str(qxv.get("vulnerabilityId"))
        refs = [u.get("url") for u in (qxv.get("referenceUrls") or []) if u.get("url")]
        cvss3 = (qxv.get("cvss3Info") or {}).get("baseScore")
        vuln = Vulnerability(
            vuln_id=vid,
            source=SourceType.QIANXIN,
            title=qxv.get("vulnerabilityName") or vid,
            severity=qx_level_to_severity(qxv.get("level")),
            description=qxv.get("vulnerabilityDescription") or "",
            fixed_version=None,
            vulnerable_range=None,
            references=refs,
            cve=cve,
            cwe=qxv.get("cnnvd"),
            published=qxv.get("releaseDate"),
            solution=qxv.get("solution"),
            sources=["qianxin"],
            raw=qxv,
        )
        if cvss3 is not None:
            vuln.extra = {"cvss3": cvss3}
        return vuln

    def collect(self, task_id: int, language: Language) -> tuple[list[Component], list[Vulnerability]]:
        comps_raw = self.list_components(task_id)
        vulns_raw = self.list_vulnerabilities(task_id)
        unknown_raw = self.list_unknown_components(task_id)

        comp_by_coord: dict[str, Component] = {}
        comp_by_qxid: dict[str, Component] = {}

        for qx in comps_raw:
            comp = self._qx_to_component(qx, language)
            existing = comp_by_coord.get(comp.key)
            if existing is None:
                existing = comp
                comp_by_coord[comp.key] = comp
            cid = qx.get("componentId")
            if cid is not None:
                comp_by_qxid[cid] = existing

        # 未知版本组件（无精确版本）也纳入清单，避免漏报
        for qx in unknown_raw:
            name = qx.get("componentName")
            if not name:
                continue
            coord = f":{name}:?"
            if coord in comp_by_coord:
                continue
            src_path = None
            if qx.get("componentSourceInfos"):
                src_path = qx["componentSourceInfos"][0].get("path")
            comp = Component(
                group=None, name=name, version=None, language=language,
                source=src_path, extra={"qx_unknown_version": True},
            )
            comp_by_coord[coord] = comp

        # 漏洞去重并按 affectVersionList 关联组件
        vuln_by_key: dict[str, Vulnerability] = {}
        for qxv in vulns_raw:
            key = self._vuln_dedup_key(qxv)
            vuln = vuln_by_key.get(key)
            if vuln is None:
                vuln = self._qx_to_vulnerability(qxv)
                vuln_by_key[key] = vuln
            for aff in (qxv.get("affectVersionList") or []):
                comp = comp_by_qxid.get(aff.get("componentId"))
                if comp is not None and vuln not in comp.vulnerabilities:
                    comp.vulnerabilities.append(vuln)

        return list(comp_by_coord.values()), list(vuln_by_key.values())

    # ---- orchestration ----
    def _submit_for_target(self, target: ScanTarget) -> int:
        tn = target.kind.value
        if target.kind == ScanKind.JAR_LOCAL:
            if not target.path or not os.path.exists(target.path):
                raise ValueError(f"本地路径不存在: {target.path}")
            if os.path.isfile(target.path):
                with open(target.path, "rb") as f:
                    content = f.read()
                fn = os.path.basename(target.path)
            else:
                content = zip_directory(target.path)
                fn = (os.path.basename(target.path.rstrip("/\\")) or "libs") + ".zip"
            return self.submit_binary_file(content, fn, tn)
        if target.kind == ScanKind.JAR_NEXUS:
            return self.submit_binary_nexus(target.url, target.username, target.password, tn,
                                            token=target.token, auth_type=target.auth_type)
        if target.kind == ScanKind.JAR_ARTIFACTORY:
            return self.submit_binary_artifactory(target.url, target.username, target.password, tn,
                                                  token=target.token, auth_type=target.auth_type)
        if target.kind == ScanKind.IMAGE_LOCAL:
            if not target.path or not os.path.isfile(target.path):
                raise ValueError(f"本地镜像 tar 不存在: {target.path}")
            with open(target.path, "rb") as f:
                content = f.read()
            return self.submit_image_file(content, os.path.basename(target.path), tn)
        if target.kind == ScanKind.IMAGE_HARBOR:
            return self.submit_image_harbor(target.url, target.username, target.password, tn)
        if target.kind == ScanKind.IMAGE_DOCKERHUB:
            return self.submit_image_dockerhub(target.url, target.username, target.password, tn)
        if target.kind == ScanKind.IMAGE_NEXUS:
            return self.submit_image_nexus(target.url, target.username, target.password, tn)
        if target.kind == ScanKind.IMAGE_ARTIFACTORY:
            return self.submit_image_artifactory(target.url, target.username, target.password, tn)
        raise ValueError(f"不支持的扫描类型: {target.kind}")

    def run(self, target: ScanTarget, task_name: Optional[str] = None) -> AnalysisResult:
        language = _lang_for_target(target)
        tn = task_name or target.kind.value
        _LOGGER.info("提交奇安信扫描任务（%s）…", target.kind.value)
        task_id = self._submit_for_target(target)
        _LOGGER.info("任务已提交 taskId=%s，等待检测完成…", task_id)
        self.wait_done(task_id)
        components, vulnerabilities = self.collect(task_id, language)
        result = AnalysisResult(
            target=task_name or target.kind.value,
            language=language,
            components=components,
            vulnerabilities=vulnerabilities,
            sources_used=["qianxin"],
        )
        result.notes.append(
            f"扫描来源：奇安信开源卫士（taskId={task_id}，类型={target.kind.value}）。"
        )
        result.enrich_summary()
        return result


def scan_target(config: Config, target: ScanTarget, task_name: Optional[str] = None) -> AnalysisResult:
    """Convenience entry point used by the CLI."""
    return QianxinScanner(config).run(target, task_name=task_name)
