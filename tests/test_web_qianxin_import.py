"""Tests for the qianxin binary/image import paths in the web service.

These cover the new import sources (harbor / docker / gitlab-jar) that scan a
binary or container image through 奇安信开源卫士 and persist the normalized
components + vulnerabilities. The scanner itself is mocked so no live 奇安信
gateway is required.
"""
import json
import os
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

from dtrack.core.models import AnalysisResult, Component, Vulnerability
from dtrack.core.types import Language, Severity, SourceType


def _fake_result() -> AnalysisResult:
    comp = Component(
        group="org.apache", name="commons-fileupload", version="1.3.1",
        language=Language.JAVA, license="Apache-2.0",
        direct=True, vulnerabilities=[
            Vulnerability(
                vuln_id="CVE-2016-1000031", source=SourceType.QIANXIN,
                title="任意文件上传", severity=Severity.CRITICAL,
                description="demo", sources=["qianxin"])
        ])
    return AnalysisResult(
        target="image", language=Language.JAVA, components=[comp],
        vulnerabilities=[], sources_used=["qianxin"])


def _wait_status(db, ref_type, vid, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = db.get_version(ref_type, vid)
        if row and row["scan_status"] in ("done", "failed"):
            return row
        time.sleep(0.1)
    return db.get_version(ref_type, vid)


class QianxinImportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        db_path = os.path.join(self.tmp, "web_test.db")
        cfg_path = os.path.join(self.tmp, "dtrack.toml")
        # 配置奇安信扫描（离线环境内网网关），使导入不报“未配置”
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(
                "[scan.qianxin]\n"
                "base_url = \"https://qianxin.local:8449\"\n"
                "project_id = \"P-123\"\n"
            )
        from dtrack.web.store import Db
        from dtrack.web.service import WebService
        self.db = Db(db_path)
        self.svc = WebService(self.db, cfg_path)
        self.svc.config.data.setdefault("scan", {})["qianxin"] = {
            "base_url": "https://qianxin.local:8449", "project_id": "P-123"}

    def tearDown(self):
        self.db.close()

    # ---- identity helpers ----
    def test_parse_image(self):
        from dtrack.web.service import WebService as S
        self.assertEqual(S._parse_image("my.harbor.com:6443/library/centos:7"),
                         ("centos", "7"))
        self.assertEqual(S._parse_image("nginx:latest"), ("nginx", "latest"))
        self.assertEqual(S._parse_image("registry:5000/foo/bar"), ("bar", "latest"))

    def test_scan_identity_harbor(self):
        from dtrack.web.service import WebService as S
        name, ver = S._scan_identity("harbor",
                                     "my.harbor.com:6443/library/centos:7", None)
        self.assertEqual((name, ver), ("centos", "7"))
        # 显式传入 name 时，只覆盖 owner 名，版本仍需保留镜像 tag（而非 latest）
        name, ver = S._scan_identity("harbor", "x/y:1.0", "my-app")
        self.assertEqual((name, ver), ("my-app", "1.0"))

    def test_scan_identity_docker(self):
        from dtrack.web.service import WebService as S
        name, ver = S._scan_identity("docker", "nginx:1.25", None)
        self.assertEqual((name, ver), ("nginx", "1.25"))

    # ---- requires config ----
    def test_import_requires_qianxin(self):
        self.svc.config.data["scan"]["qianxin"] = {}
        with self.assertRaises(RuntimeError):
            self.svc.import_project_scan(
                {"source": "harbor", "image_url": "nginx:latest"})

    # ---- harbor import end-to-end (mocked scanner) ----
    def test_import_harbor_runs_scan_and_persists(self):
        # 同步执行扫描（避免后台线程脱离 mock 上下文 / 跨线程写库）
        self.svc.scan_version_async = lambda rt, vid: self.svc._do_scan_qianxin(rt, vid)
        with mock.patch("dtrack.scan.qianxin_scan.QianxinScanner") as M:
            inst = M.return_value
            inst.run.return_value = _fake_result()
            res = self.svc.import_project_scan(
                {"source": "harbor", "image_url": "my.harbor.com:6443/lib/cen:7"})
        self.assertEqual(res["source"], "harbor")
        self.assertEqual(res["version"], "7")
        self.assertEqual(res["source_ref"], "my.harbor.com:6443/lib/cen:7")
        self.assertIsNotNone(res["version_id"])
        vid = res["version_id"]
        # scan_meta 应包含镜像地址与类型
        row = self.db.get_version("project", vid)
        meta = json.loads(row["scan_meta"])
        self.assertEqual(meta["kind"], "image-harbor")
        self.assertEqual(meta["url"], "my.harbor.com:6443/lib/cen:7")
        self.assertEqual(row["scan_status"], "done")
        # 组件已入库
        comps = self.db.list_components({})
        self.assertTrue(any(c["name"] == "commons-fileupload" for c in comps))
        # 漏洞已关联
        detail = self.db.get_component_detail("org.apache:commons-fileupload:1.3.1")
        self.assertEqual(len(detail["vulnerabilities"]), 1)
        self.assertEqual(detail["vulnerabilities"][0]["severity"], "critical")

    def test_import_docker_runs_scan(self):
        self.svc.scan_version_async = lambda rt, vid: self.svc._do_scan_qianxin(rt, vid)
        with mock.patch("dtrack.scan.qianxin_scan.QianxinScanner") as M:
            inst = M.return_value
            inst.run.return_value = _fake_result()
            res = self.svc.import_project_scan(
                {"source": "docker", "image_url": "nginx:1.25"})
        self.assertEqual(res["source"], "docker")
        self.assertEqual(res["version"], "1.25")
        self.assertEqual(self.db.get_version("project", res["version_id"])["scan_status"],
                         "done")

    # ---- gitlab-jar: 下载归档→定位 jar→提交扫描 ----
    def test_import_gitlab_jar(self):
        # 构造一个含 .jar 的 tar.gz 归档
        jar_dir = tempfile.mkdtemp()
        jar_path = os.path.join(jar_dir, "app.jar")
        with open(jar_path, "wb") as f:
            f.write(b"\xca\xfe\xba\xbe dummy jar")
        archive = os.path.join(self.tmp, "repo.tar.gz")
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(jar_path, arcname="app.jar")

        class FakeFetcher:
            def enabled(self):
                return True
            def download_repository(self, proj, ref, dest_dir=None):
                import shutil
                dest = dest_dir or tempfile.mkdtemp()
                shutil.copy(archive, os.path.join(dest, "repo.tar.gz"))
                return os.path.join(dest, "repo.tar.gz")

        self.svc.scan_version_async = lambda rt, vid: self.svc._do_scan_qianxin(rt, vid)
        with mock.patch("dtrack.sources.get_fetcher", return_value=FakeFetcher()), \
             mock.patch("dtrack.scan.qianxin_scan.QianxinScanner") as M:
            inst = M.return_value
            inst.run.return_value = _fake_result()
            res = self.svc.import_project_scan({
                "source": "gitlab-jar", "gitlab_project": "grp/app",
                "ref": "v1.0"})
        self.assertEqual(res["source"], "gitlab-jar")
        self.assertEqual(res["version"], "v1.0")
        row = self.db.get_version("project", res["version_id"])
        self.assertIsNotNone(row["scan_meta"])
        self.assertEqual(row["scan_status"], "done")


if __name__ == "__main__":
    unittest.main()
