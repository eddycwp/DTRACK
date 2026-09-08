"""Web platform service layer.

Orchestrates the high-level operations the REST API exposes:

  * import a whitelist / project from a pom file upload **or** a GitLab project
    (parsed with the existing ``JavaAnalyzer`` → third-party components + transitive
    deps, versioned by the pom's own ``<version>``)
  * run a QIANXIN (开源卫士) vulnerability scan over the imported components and
    persist the normalized results + a markdown report
  * query the third-party component catalogue (with vulnerability info, which
    whitelist versions include a component, and which projects use it)
  * read / write the repository configuration (mirrored to ``dtrack.toml``)

All heavy work (parsing, scanning) reuses the stdlib DTrack analyzers/scanners so
behaviour stays consistent with the CLI.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any, Optional

from .. import get_logger
from ..analyzers.java.java_analyzer import JavaAnalyzer
from ..analyzers.java.maven_resolver import resolve_mvn_executable
from ..analyzers.java.pom_parser import parse_pom_file
from ..config import Config, DEFAULT_CONFIG, _deep_merge, _to_toml
from ..core.models import Component, Vulnerability, AnalysisResult
from ..core.types import Language, Severity
from ..report.markdown import render_markdown
from ..utils.archive import zip_directory
from ..vuln.aggregator import VulnerabilityAggregator
from ..vuln.registry import get_enabled_sources
from .store import Db

_LOGGER = get_logger()

_SEV_RANK = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
             Severity.LOW: 2, Severity.UNKNOWN: 1}


class WebService:
    def __init__(self, db: Db, config_path: str) -> None:
        self.db = db
        self.config_path = config_path
        self.config = self._load_config()
        self._lock = threading.Lock()

    # ---- config ----
    def _load_config(self) -> Config:
        # load_config discovers dtrack.toml/json automatically
        from ..config import load_config
        return load_config(self.config_path if os.path.isfile(self.config_path) else None)

    def get_config(self) -> dict:
        """Return the web-editable subset of the configuration."""
        d = self.config.data
        return {
            "repos": d.get("repos", {}),
            "maven": {k: d.get("maven", {}).get(k) for k in
                      ("home", "executable", "central_url", "local_repo")},
            "vuln": {"qianxin": d.get("vuln", {}).get("qianxin", {})},
            "scan": {"qianxin": d.get("scan", {}).get("qianxin", {})},
        }

    def update_config(self, patch: dict) -> dict:
        """Merge ``patch`` into the live config and persist to dtrack.toml."""
        with self._lock:
            merged = _deep_merge(self.config.data, patch)
            self._write_toml(merged)
            self.config = Config(merged)
        return self.get_config()

    def _write_toml(self, data: dict) -> None:
        path = self.config_path
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        header = (
            "# DTrack configuration (managed by web UI)\n"
            "# Environment overrides use DTRACK__SECTION__KEY.\n\n"
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(header)
            f.write(_to_toml(data))
        _LOGGER.info("配置已写入 %s", path)

    # ---- import helpers ----
    def _resolve_pom_dir(self, pom_text: Optional[str], gitlab_project: Optional[str],
                         ref: Optional[str]) -> tuple[str, dict]:
        """Materialize a pom into a temp dir (or gitlab archive); return (dir, project_coords)."""
        if gitlab_project:
            from ..sources import get_fetcher
            fetcher = get_fetcher("gitlab", self.config)
            if not fetcher.enabled():
                raise RuntimeError("GitLab 未配置（请在配置页填写 base_url 与 token）。")
            archive = fetcher.download_repository(gitlab_project, ref, dest_dir=tempfile.mkdtemp())
            import tarfile
            extract_dir = tempfile.mkdtemp()
            with tarfile.open(archive) as tf:
                tf.extractall(extract_dir)
            # gitlab archives nest under a single top dir
            entries = os.listdir(extract_dir)
            work = os.path.join(extract_dir, entries[0]) if len(entries) == 1 else extract_dir
            pom_dir = work
        else:
            work = tempfile.mkdtemp()
            pom_path = os.path.join(work, "pom.xml")
            with open(pom_path, "w", encoding="utf-8") as f:
                f.write(pom_text or "")
            pom_dir = work

        # discover project self-identity from the first pom that has coords
        proj = self._project_coords(pom_dir)
        return pom_dir, proj

    @staticmethod
    def _project_coords(pom_dir: str) -> dict:
        poms: list[str] = []
        for root, _d, files in os.walk(pom_dir):
            if "pom.xml" in files:
                poms.append(os.path.join(root, "pom.xml"))
        best: Optional[dict] = None
        for p in poms:
            pom = parse_pom_file(p)
            if pom.group_id and pom.artifact_id:
                best = {"group_id": pom.group_id, "artifact_id": pom.artifact_id,
                        "version": pom.version, "name": f"{pom.group_id}:{pom.artifact_id}"}
                break
        if best is None and poms:
            pom = parse_pom_file(poms[0])
            best = {"group_id": pom.group_id, "artifact_id": pom.artifact_id or "(unknown)",
                    "version": pom.version, "name": pom.artifact_id or "(unknown)"}
        return best or {"group_id": None, "artifact_id": "(unknown)",
                        "version": None, "name": "(unknown)"}

    def _analyze_components(self, pom_dir: str) -> list[Component]:
        analyzer = JavaAnalyzer(self.config)
        try:
            return analyzer.analyze(pom_dir)
        except FileNotFoundError:
            return []
        except Exception as e:  # noqa: BLE001
            _LOGGER.warning("pom 解析失败：%s", e)
            return []

    # ---- import entry points ----
    def import_whitelist(self, pom_text: Optional[str], gitlab_project: Optional[str],
                         ref: Optional[str]) -> dict:
        return self._import("whitelist", pom_text, gitlab_project, ref)

    def import_project(self, pom_text: Optional[str], gitlab_project: Optional[str],
                       ref: Optional[str], name: Optional[str] = None) -> dict:
        return self._import("project", pom_text, gitlab_project, ref, name)

    # ---- qianxin 二进制 / 镜像 导入（harbor / docker / gitlab 归档 jar）----
    def import_whitelist_scan(self, payload: dict) -> dict:
        return self._import_qianxin("whitelist", payload)

    def import_project_scan(self, payload: dict) -> dict:
        return self._import_qianxin("project", payload)

    def _import_qianxin(self, ref_type: str, payload: dict) -> dict:
        """通过奇安信开源卫士对二进制/镜像制品发起扫描并入库。

        支持来源（payload['source']）：
          - 'harbor'        : Harbor 镜像（image-harbor）
          - 'docker'        : Docker 镜像（image-dockerhub / 本地 tar）
          - 'gitlab-jar'    : GitLab 归档中的 jar（下载后按 jar-local 提交）
        组件与漏洞完全来自奇安信扫描结果（而非 pom 解析），扫描必须经奇安信完成。
        """
        source = payload.get("source")
        if source not in ("harbor", "docker", "gitlab-jar"):
            raise ValueError(f"不支持的二进制导入来源：{source}")
        # 奇安信扫描为必经路径，必须配置
        d = self.config.data
        scan_cfg = (d.get("scan") or {}).get("qianxin") or {}
        vuln_cfg = (d.get("vuln") or {}).get("qianxin") or {}
        base = scan_cfg.get("base_url") or vuln_cfg.get("base_url")
        pid = scan_cfg.get("project_id")
        if not (base and pid):
            raise RuntimeError(
                "奇安信开源卫士扫描未配置：请在「仓库配置」填写 scan.qianxin.base_url 与 "
                "project_id，二进制/镜像制品必须经奇安信扫描。")

        name = (payload.get("name") or "").strip() or None
        if source == "gitlab-jar":
            gitlab_project = payload.get("gitlab_project")
            ref = payload.get("ref")
            if not gitlab_project:
                raise ValueError("GitLab 归档 jar 导入缺少 gitlab_project 参数。")
            owner_name, version = self._scan_identity(source, gitlab_project, name, ref)
            scan_meta = {"kind": "jar-gitlab", "gitlab_project": gitlab_project, "ref": ref}
            source_ref = gitlab_project
        else:
            image_url = (payload.get("image_url") or "").strip()
            if not image_url:
                raise ValueError("镜像导入缺少 image_url（镜像地址）。")
            owner_name, version = self._scan_identity(source, image_url, name)
            scan_meta = {
                "kind": "image-harbor" if source == "harbor" else "image-dockerhub",
                "url": image_url,
            }
            source_ref = image_url

        if ref_type == "whitelist":
            # 以镜像/归档的制品名作为 artifact_id，避免不同镜像被错误合并到同一个
            # (group=None, artifact=None) 的白名单 owner，导致 owner 名称错乱。
            owner_id = self.db.upsert_whitelist(None, owner_name, owner_name)
            vid = self.db.add_whitelist_version(
                owner_id, version, source, None, "", source_ref,
                json.dumps(scan_meta, ensure_ascii=False))
        else:
            owner_id = self.db.upsert_project(None, owner_name, owner_name)
            vid = self.db.add_project_version(
                owner_id, version, source, None, "", source_ref,
                json.dumps(scan_meta, ensure_ascii=False))

        owner = self.db.get_whitelist(owner_id) if ref_type == "whitelist" else \
            self.db.get_project(owner_id)
        result = {
            "ref_type": ref_type,
            "owner_id": owner_id,
            "version_id": vid,
            "owner": owner,
            "version": version,
            "source": source,
            "source_ref": source_ref,
            "components": 0,
            "scan_status": "pending",
        }
        self.scan_version_async(ref_type, vid)
        return result

    @staticmethod
    def _scan_identity(source: str, url: str, name: Optional[str],
                       ref: Optional[str] = None) -> tuple[str, str]:
        """推导导入产物的名称与版本（项目身份标识）。

        harbor/docker 的版本**始终取自镜像地址的标签（tag）**，无论是否显式传入 name；
        name 仅用于覆盖 owner（制品）名。gitlab-jar 版本取自分支/标签 ref。
        这样「项目名称」只影响展示名，不会吞掉真实版本号（如 :7 / :1.25）。
        """
        if source in ("harbor", "docker"):
            repo, tag = WebService._parse_image(url)
            return name or repo or "image", tag
        if source == "gitlab-jar":
            return name or url or "gitlab-jar", ref or "unknown"
        return "artifact", "unknown"

    @staticmethod
    def _parse_image(url: str) -> tuple[str, str]:
        """从镜像地址解析（仓库路径, 标签）。

        镜像地址形如 ``registry:port/ns/repo:tag``；由于 host:port 的冒号必在首个 ``/`` 之前，
        仅在最后一个路径段内按 ``:`` 切分即可安全区分「端口」与「标签」。
        """
        last = url.rsplit("/", 1)[-1]
        if ":" in last:
            repo, tag = last.rsplit(":", 1)
        else:
            repo, tag = last, "latest"
        return repo, tag

    def _repo_cred(self, name: str, key: str) -> Optional[str]:
        return (self.config.data.get("repos") or {}).get(name, {}).get(key)

    def _build_scan_target(self, meta: dict) -> Any:
        from ..scan.qianxin_scan import ScanKind, ScanTarget
        kind = meta.get("kind")
        if kind == "image-harbor":
            return ScanTarget(
                kind=ScanKind.IMAGE_HARBOR, url=meta.get("url"),
                username=meta.get("username") or self._repo_cred("harbor", "username"),
                password=meta.get("password") or self._repo_cred("harbor", "password"))
        if kind == "image-dockerhub":
            return ScanTarget(
                kind=ScanKind.IMAGE_DOCKERHUB, url=meta.get("url"),
                username=meta.get("username") or self._repo_cred("docker", "username"),
                password=meta.get("password") or self._repo_cred("docker", "password"))
        if kind in ("jar-local", "jar-gitlab"):
            path = meta.get("path") or self._resolve_gitlab_jar(
                meta.get("gitlab_project"), meta.get("ref"))
            return ScanTarget(kind=ScanKind.JAR_LOCAL, path=path)
        raise ValueError(f"不支持的扫描类型：{kind}")

    def _resolve_gitlab_jar(self, gitlab_project: Optional[str],
                            ref: Optional[str]) -> str:
        """下载 GitLab 归档并定位其中的 jar（单个直接用，多个打包为目录）。"""
        from ..sources import get_fetcher
        fetcher = get_fetcher("gitlab", self.config)
        if not fetcher.enabled():
            raise RuntimeError("GitLab 未配置（请在配置页填写 base_url 与 token）。")
        archive = fetcher.download_repository(gitlab_project, ref, dest_dir=tempfile.mkdtemp())
        import tarfile
        extract_dir = tempfile.mkdtemp()
        with tarfile.open(archive) as tf:
            tf.extractall(extract_dir, filter="data")
        entries = os.listdir(extract_dir)
        # 若归档解压后只有一个顶层条目且为目录（如 repo/），则进入该目录扫描；
        # 若顶层条目本身是文件（如 app.jar 直接落在根），则直接以解压目录为工作目录。
        work = extract_dir
        if len(entries) == 1:
            only = os.path.join(extract_dir, entries[0])
            if os.path.isdir(only):
                work = only
        jars: list[str] = []
        for root, _d, files in os.walk(work):
            for f in files:
                if f.endswith(".jar"):
                    jars.append(os.path.join(root, f))
        if not jars:
            raise RuntimeError("GitLab 归档中未找到 .jar 文件，无法以二进制方式扫描。")
        if len(jars) == 1:
            return jars[0]
        import shutil
        jardir = tempfile.mkdtemp(prefix="dtrack_jars_")
        for j in jars:
            shutil.copy(j, jardir)
        return jardir

    def _import(self, ref_type: str, pom_text: Optional[str],
                gitlab_project: Optional[str], ref: Optional[str],
                name: Optional[str] = None) -> dict:
        # 逆向防御：既無 POM 文本也无 GitLab 项目时无法导入，返回清晰错误而非静默建垃圾版本
        if not pom_text and not gitlab_project:
            raise ValueError("缺少 POM 内容或 GitLab 项目，无法导入。")
        pom_dir, proj = self._resolve_pom_dir(pom_text, gitlab_project, ref)
        version = proj.get("version") or "unknown"
        components = self._analyze_components(pom_dir)

        if ref_type == "whitelist":
            owner_id = self.db.upsert_whitelist(
                proj.get("group_id"), proj.get("artifact_id"), proj.get("name"))
            vid = self.db.add_whitelist_version(
                owner_id, version, "gitlab" if gitlab_project else "pom",
                gitlab_project, pom_text or "", None, None)
        else:
            # 项目名称：优先取导入时手动填写的值，留空则回退到 pom 中的名称
            owner_name = (name or "").strip() or proj.get("name") or ""
            owner_id = self.db.upsert_project(
                proj.get("group_id"), proj.get("artifact_id"), owner_name)
            vid = self.db.add_project_version(
                owner_id, version, "gitlab" if gitlab_project else "pom",
                gitlab_project, pom_text or "", None, None)

        # persist components as catalogue + usage (whitelist flag on for whitelist imports)
        for comp in components:
            cid = self.db.upsert_component(
                comp.group, comp.name, comp.version, comp.language.value,
                comp.license, is_whitelist=(ref_type == "whitelist"))
            self.db.add_usage(cid, ref_type, vid,
                              "direct" if comp.direct else "transitive")

        owner = self.db.get_whitelist(owner_id) if ref_type == "whitelist" else \
            self.db.get_project(owner_id)
        result = {
            "ref_type": ref_type,
            "owner_id": owner_id,
            "version_id": vid,
            "owner": owner,
            "version": version,
            "source": "gitlab" if gitlab_project else "pom",
            "components": len(components),
            "scan_status": "pending",
        }
        # kick off scan
        self.scan_version_async(ref_type, vid)
        return result

    def scan_version_async(self, ref_type: str, vid: int) -> None:
        # 二进制/镜像导入（scan_meta 非空）走奇安信扫描；其余走 pom 解析 + 在线源补充
        row = self.db.get_version(ref_type, vid) or {}
        target = self._do_scan_qianxin if row.get("scan_meta") else self._do_scan
        t = threading.Thread(target=target, args=(ref_type, vid), daemon=True)
        t.start()

    def _do_scan_qianxin(self, ref_type: str, vid: int) -> None:
        """奇安信二进制/镜像扫描路径：提交任务→等待→拉取组件与漏洞→入库。

        组件与漏洞完全来自奇安信扫描结果（不再做 pom 解析或在线源查询）。
        """
        self.db.set_version_status(ref_type, vid, "scanning")
        try:
            from ..scan.qianxin_scan import QianxinScanner
            row = self.db.get_version(ref_type, vid) or {}
            meta = json.loads(row.get("scan_meta") or "{}")
            target = self._build_scan_target(meta)
            scanner = QianxinScanner(self.config)
            result = scanner.run(target)  # AnalysisResult（components + vulnerabilities）

            persisted = 0
            for comp in result.components:
                if not comp.name or comp.name == "unknown":
                    continue
                cid = self.db.upsert_component(
                    comp.group, comp.name, comp.version, comp.language.value,
                    comp.license, is_whitelist=(ref_type == "whitelist"))
                self.db.add_usage(cid, ref_type, vid,
                                  "direct" if comp.direct else "transitive")
                for v in comp.vulnerabilities:
                    self.db.add_vulnerability(cid, self._vuln_to_dict(v))
                persisted += 1

            comp_rows = self.db.components_for_version(ref_type, vid)
            vulns_by_coord: dict = {}
            for cr in comp_rows:
                vs = [self._vuln_from_row(r)
                      for r in self.db.vulnerabilities_for_component(cr["id"])]
                if vs:
                    vulns_by_coord[cr["coord"]] = vs

            if not persisted:
                self.db.set_version_status(
                    ref_type, vid, "done",
                    "奇安信扫描完成，但未识别到任何组件（镜像可能不含可识别的开源组件）。")
            else:
                self.db.set_version_status(ref_type, vid, "done")
            self._build_report(ref_type, vid, comp_rows, vulns_by_coord,
                               sources_used=["qianxin"])
            _LOGGER.info("奇安信扫描入库完成 version=%s，组件=%d", vid, persisted)
        except Exception as e:  # noqa: BLE001
            _LOGGER.exception("奇安信扫描失败 version=%s", vid)
            self.db.set_version_status(ref_type, vid, "failed", str(e)[:500])

    def _do_scan(self, ref_type: str, vid: int) -> None:
        self.db.set_version_status(ref_type, vid, "scanning")
        try:
            comp_rows = self.db.components_for_version(ref_type, vid)
            if not comp_rows:
                self.db.set_version_status(ref_type, vid, "done",
                                           "无组件可扫描（pom 解析为空）。")
                self.db.set_version_report(ref_type, vid,
                                            {"total_components": 0, "total_vulnerabilities": 0,
                                             "severity_counts": {}},
                                            "# 无组件\n\n该版本未解析到任何三方组件。")
                return

            # 在线漏洞源（nvd/github/osv）；奇安信开源卫士采用“扫描模式”，从组件查询中排除
            online = [s for s in get_enabled_sources(self.config) if s.name != "qianxin"]
            aggregator = VulnerabilityAggregator(self.config, sources=online)

            vulns_by_coord: dict[str, list[Vulnerability]] = {}
            if aggregator.sources:
                for row in comp_rows:
                    coord = row["coord"]
                    comp = Component(group=row.get("group_id"), name=row["name"],
                                    version=row.get("version"),
                                    language=Language(row.get("language") or "java"))
                    found = aggregator.analyze_component(comp)
                    if found:
                        vulns_by_coord[coord] = found
                        for v in found:
                            self.db.add_vulnerability(row["id"], self._vuln_to_dict(v))
            else:
                _LOGGER.info("未启用任何在线漏洞源（vuln.sources），仅尝试奇安信扫描模式。")

            # 奇安信开源卫士“扫描模式”：下载组件 jar 打包提交二进制扫描并入库
            sources_used = [s.name for s in aggregator.sources]
            qx_comps = self._qianxin_scan_mode(ref_type, vid, comp_rows, vulns_by_coord)
            if qx_comps:
                sources_used.append("qianxin")

            if not sources_used:
                self.db.set_version_status(
                    ref_type, vid, "no_qianxin",
                    "未启用任何漏洞源（vuln.sources 无可用源，奇安信扫描模式也未配置），跳过漏洞扫描。")
                self._build_report(ref_type, vid, comp_rows, vulns_by_coord,
                                   sources_used=[])
                return

            self.db.set_version_status(ref_type, vid, "done")
            self._build_report(
                ref_type, vid, comp_rows, vulns_by_coord,
                sources_used=sources_used)
        except Exception as e:  # noqa: BLE001
            _LOGGER.exception("扫描失败 version=%s", vid)
            self.db.set_version_status(ref_type, vid, "failed", str(e)[:500])

    def _qianxin_scan_mode(self, ref_type: str, vid: int, comp_rows: list[dict],
                           vulns_by_coord: dict) -> list[Component]:
        """奇安信开源卫士“扫描模式”：下载组件 jar 打包提交二进制扫描，结果入库。

        仅在配置了 scan.qianxin.base_url 与 project_id（离线环境内网开源卫士）时执行；
        仓库不可达 / 无 jar 可下载时安全跳过，不影响在线源（nvd/github/osv）结果。
        """
        d = self.config.data
        scan_cfg = (d.get("scan") or {}).get("qianxin") or {}
        vuln_cfg = (d.get("vuln") or {}).get("qianxin") or {}
        base_url = scan_cfg.get("base_url") or vuln_cfg.get("base_url")
        project_id = scan_cfg.get("project_id")
        if not (base_url and project_id):
            _LOGGER.info("奇安信扫描模式未配置（scan.qianxin.base_url / project_id），跳过。")
            return []

        import shutil
        from ..scan.qianxin_scan import QianxinScanner
        tmpdir = tempfile.mkdtemp(prefix="dtrack_qx_")
        try:
            jars = self._download_component_jars(comp_rows, tmpdir)
            if not jars:
                _LOGGER.warning("奇安信扫描模式：未下载到任何组件 jar（central=%s），跳过。",
                                (d.get("maven") or {}).get("central_url"))
                return []
            scanner = QianxinScanner(self.config)
            task_id = scanner.submit_binary_file(
                zip_directory(tmpdir), f"dtrack-{ref_type}-{vid}.zip",
                f"DTrack {ref_type} #{vid} 组件扫描")
            _LOGGER.info("奇安信扫描任务已提交 taskId=%s（%d 个 jar）", task_id, jars)
            scanner.wait_done(task_id)
            comps, _vulns = scanner.collect(task_id, Language.JAVA)
            for comp in comps:
                if not comp.name or comp.name == "unknown" or not comp.version:
                    continue
                cid = self.db.upsert_component(
                    comp.group, comp.name, comp.version, comp.language.value,
                    comp.license, is_whitelist=(ref_type == "whitelist"))
                self.db.add_usage(cid, ref_type, vid,
                                  "direct" if comp.direct else "transitive")
                for v in comp.vulnerabilities:
                    self.db.add_vulnerability(cid, self._vuln_to_dict(v))
                if comp.vulnerabilities:
                    vulns_by_coord.setdefault(comp.key, []).extend(comp.vulnerabilities)
            return comps
        except Exception as e:  # noqa: BLE001
            _LOGGER.warning("奇安信扫描模式失败：%s", e)
            return []
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _download_component_jars(self, comp_rows: list[dict], tmpdir: str) -> int:
        """从配置的 maven 仓库下载 java 组件 jar 到 tmpdir；返回成功下载数量。

        优先使用本地仓库 local_repo，其次 central_url（可为内网 Nexus/Artifactory）。
        """
        import shutil
        import urllib.request
        d = self.config.data
        central = str((d.get("maven") or {}).get("central_url")
                      or "https://repo1.maven.org/maven2").rstrip("/")
        local = str((d.get("maven") or {}).get("local_repo") or "")
        downloaded = 0
        for row in comp_rows:
            group, name, version = row.get("group_id"), row.get("name"), row.get("version")
            lang = str(row.get("language") or "java").lower()
            if not (group and name and version) or lang != "java":
                continue
            fn = f"{name}-{version}.jar"
            dest = os.path.join(tmpdir, fn)
            if local:
                cand = os.path.join(local, str(group).replace(".", os.sep), name, version, fn)
                if os.path.isfile(cand):
                    shutil.copyfile(cand, dest)
                    downloaded += 1
                    continue
            url = f"{central}/{str(group).replace('.', '/')}/{name}/{version}/{fn}"
            try:
                with urllib.request.urlopen(url, timeout=30) as resp:
                    with open(dest, "wb") as f:
                        f.write(resp.read())
                downloaded += 1
            except Exception:  # noqa: BLE001
                continue
        return downloaded

    @staticmethod
    def _vuln_to_dict(v: Vulnerability) -> dict:
        return {
            "vuln_key": v.dedup_key(),
            "vuln_id": v.vuln_id,
            "source": ",".join(v.sources) if v.sources else v.source.value,
            "title": v.title,
            "severity": v.severity.value,
            "description": v.description,
            "fixed_version": v.fixed_version,
            "vulnerable_range": v.vulnerable_range,
            "cwe": v.cwe,
            "cve": v.cve,
            "solution": v.solution,
            "references": v.references,
            "raw": v.raw,
        }

    def _make_result(self, ref_type: str, vid: int, comp_rows: list[dict],
                     vulns_by_coord: dict,
                     sources_used: Optional[list[str]] = None) -> AnalysisResult:
        """根据库中数据重建 AnalysisResult（供 md / pdf 报表复用）。"""
        from ..core.types import Language
        components: list[Component] = []
        for row in comp_rows:
            coord = row["coord"]
            dep_type = row.get("dependency_type") or "transitive"
            comp = Component(group=row.get("group_id"), name=row["name"],
                            version=row.get("version"),
                            language=Language(row.get("language") or "java"),
                            license=row.get("license"),
                            vulnerabilities=vulns_by_coord.get(coord, []))
            comp.direct = dep_type == "direct"
            comp.transitive = dep_type != "direct"
            # 影响项目（「项目管理」维度）：引用该组件的全部业务项目及版本，
            # 供白名单报告第五章「影响项目」列与第二章中危及以上汇总小节使用。
            comp.extra["affected_projects"] = self.db.projects_for_component(coord)
            components.append(comp)
        result = AnalysisResult(
            target=self._resolve_target(ref_type, vid), language=Language.JAVA,
            components=components, sources_used=sources_used or [])
        result.enrich_summary()
        return result

    def _resolve_target(self, ref_type: str, vid: int) -> str:
        """报告「分析目标」显示：项目 -> 名称:版本；白名单 -> groupId:artifactId:version。

        名称/坐标缺失时回退为原始的 ref_type:vid 形式，保证报表始终有可读标识。
        """
        row = self.db.get_version(ref_type, vid) or {}
        version = (row.get("version") or "").strip()
        if ref_type == "whitelist":
            owner = self.db.get_whitelist(row.get("whitelist_id") or 0) or {}
            gid = (owner.get("group_id") or "").strip()
            aid = (owner.get("artifact_id") or "").strip()
            name = (owner.get("name") or "").strip()
            if gid or aid:
                return ":".join(x for x in (gid, aid, version) if x)
            return f"{name}:{version}" if name else f"whitelist:{vid}"
        owner = self.db.get_project(row.get("project_id") or 0) or {}
        name = (owner.get("name") or "").strip()
        if name:
            return f"{name}:{version}" if version else name
        return f"project:{vid}"

    def _build_report(self, ref_type: str, vid: int, comp_rows: list[dict],
                      vulns_by_coord: dict,
                      sources_used: Optional[list[str]] = None) -> None:
        result = self._make_result(ref_type, vid, comp_rows, vulns_by_coord, sources_used)
        md = render_markdown(result)
        self.db.set_version_report(ref_type, vid, result.summary, md)

    # ---- queries ----
    def list_components(self, filters: Optional[dict] = None) -> list[dict]:
        return self.db.list_components(filters)

    def get_component_detail(self, coord: str) -> Optional[dict]:
        return self.db.get_component_detail(coord)

    def list_version_components(self, ref_type: str, vid: int) -> list[dict]:
        return self.db.list_version_components(ref_type, vid)

    def get_report(self, ref_type: str, vid: int) -> Optional[str]:
        row = self.db.get_version(ref_type, vid)
        if not row:
            return None
        md = row.get("report_md") or ""
        # 报告缓存缺失，或「分析目标」仍是旧的 ref_type:vid 形式（如 project:1），
        # 或缺少新增的「2.4 中危及以上汇总 / 第五章影响项目列」章节时，
        # 从库中恢复完整漏洞数据重新生成，保证导出内容与最新格式一致。
        stale = (f"**分析目标**：{ref_type}:{vid}" in md or
                 f"分析目标：{ref_type}:{vid}" in md or
                 "### 2.4" not in md)
        if not md or stale:
            comp_rows = self.db.components_for_version(ref_type, vid)
            vulns_by_coord: dict = {}
            for cr in comp_rows:
                vs = [self._vuln_from_row(r)
                      for r in self.db.vulnerabilities_for_component(cr["id"])]
                if vs:
                    vulns_by_coord[cr["coord"]] = vs
            self._build_report(ref_type, vid, comp_rows, vulns_by_coord,
                               self._sources_from_summary(row))
            row = self.db.get_version(ref_type, vid)
        return row.get("report_md")

    def get_report_pdf(self, ref_type: str, vid: int) -> Optional[bytes]:
        """为版本生成 PDF 报表（需要 reportlab，缺失时抛出清晰异常）。"""
        row = self.db.get_version(ref_type, vid)
        if not row:
            return None
        comp_rows = self.db.components_for_version(ref_type, vid)
        vulns_by_coord: dict = {}
        for cr in comp_rows:
            vs = [self._vuln_from_row(r)
                  for r in self.db.vulnerabilities_for_component(cr["id"])]
            if vs:
                vulns_by_coord[cr["coord"]] = vs
        result = self._make_result(
            ref_type, vid, comp_rows, vulns_by_coord,
            self._sources_from_summary(row))
        from ..report.pdf import render_pdf
        return render_pdf(result)

    @staticmethod
    def _sources_from_summary(row: dict) -> list[str]:
        """从版本已入库的 summary 中恢复 sources_used 列表。"""
        try:
            summary = json.loads(row.get("summary_json") or "{}")
        except Exception:  # noqa: BLE001
            summary = {}
        return [k for k, v in (summary.get("source_counts") or {}).items() if v]

    @staticmethod
    def _vuln_from_row(r: dict) -> Vulnerability:
        """将 vulnerability 表的一行还原为 Vulnerability 对象。"""
        from ..core.types import SourceType
        sources = [s for s in str(r.get("source") or "").split(",") if s]
        src_name = sources[0] if sources else "manual"
        try:
            src = SourceType(src_name)
        except ValueError:
            src = SourceType.MANUAL
        try:
            sev = Severity(str(r.get("severity") or "unknown").lower())
        except ValueError:
            sev = Severity.UNKNOWN
        refs: list = []
        raw_json = r.get("references_json")
        if raw_json:
            try:
                refs = json.loads(raw_json)
            except Exception:  # noqa: BLE001
                refs = [x for x in str(raw_json).splitlines() if x]
        rawd: dict = {}
        raw = r.get("raw_json")
        if raw:
            try:
                rawd = json.loads(raw)
            except Exception:  # noqa: BLE001
                pass
        return Vulnerability(
            vuln_id=r.get("vuln_id") or r.get("cve") or "",
            source=src,
            title=r.get("title") or "",
            severity=sev,
            description=r.get("description") or "",
            fixed_version=r.get("fixed_version"),
            vulnerable_range=r.get("vulnerable_range"),
            references=refs,
            cve=r.get("cve"),
            cwe=r.get("cwe"),
            solution=r.get("solution"),
            sources=sources,
            raw=rawd,
        )

    def list_whitelists(self) -> list[dict]:
        return self.db.list_whitelists()

    def list_whitelist_versions(self, wid: int) -> list[dict]:
        return self.db.list_whitelist_versions(wid)

    def list_projects(self) -> list[dict]:
        return self.db.list_projects()

    def list_project_versions(self, pid: int) -> list[dict]:
        return self.db.list_project_versions(pid)

    def get_version(self, ref_type: str, vid: int) -> Optional[dict]:
        row = self.db.get_version(ref_type, vid)
        if row is None:
            return None
        row["stats"] = self.db.version_stats(ref_type, vid)
        return row

    def delete_version(self, ref_type: str, vid: int) -> None:
        self.db.delete_version(ref_type, vid)

    def delete_owner(self, ref_type: str, owner_id: int) -> None:
        if ref_type == "whitelist":
            self.db.delete_whitelist(owner_id)
        else:
            self.db.delete_project(owner_id)

    def list_gitlab_projects(self) -> list[dict]:
        from ..sources import get_fetcher
        fetcher = get_fetcher("gitlab", self.config)
        if not fetcher.enabled():
            raise RuntimeError("GitLab 未配置（请在配置页填写 base_url 与 token）。")
        return fetcher.list_projects()

    def list_gitlab_refs(self, project: str) -> dict:
        """读取 GitLab 项目的分支/标签，供导入对话框下拉选择。"""
        from ..sources import get_fetcher
        fetcher = get_fetcher("gitlab", self.config)
        if not fetcher.enabled():
            raise RuntimeError("GitLab 未配置（请在配置页填写 base_url 与 token）。")
        if not project:
            raise RuntimeError("缺少 GitLab 项目路径参数。")
        return fetcher.list_refs(project)
