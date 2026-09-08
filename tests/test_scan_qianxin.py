"""Tests for QIANXIN binary/image scanning (OpenAPI V3)."""
import copy
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dtrack.config import Config, DEFAULT_CONFIG
from dtrack.core.models import AnalysisResult, Component, Vulnerability
from dtrack.core.types import Language, Severity, SourceType
from dtrack.scan import ScanKind, ScanTarget, scan_target
from dtrack.scan.qianxin_scan import (
    QianxinScanner,
    _lang_for_target,
    _split_coord,
)
from dtrack.utils.http import _build_multipart


def _cfg() -> Config:
    return Config(copy.deepcopy(DEFAULT_CONFIG))


class TestMultipart(unittest.TestCase):
    def test_build_multipart_structure(self):
        body, ctype = _build_multipart(
            fields={"projectId": "P1", "taskName": "t"},
            files=[("file", "a.jar", b"JARDATA", "application/octet-stream")],
        )
        self.assertTrue(ctype.startswith("multipart/form-data; boundary="))
        boundary = ctype.split("boundary=")[1]
        text = body.decode("utf-8")
        self.assertIn(f'Content-Disposition: form-data; name="projectId"', text)
        self.assertIn("P1", text)
        self.assertIn(f'name="file"; filename="a.jar"', text)
        self.assertIn("JARDATA", text)
        self.assertTrue(text.endswith(f"--{boundary}--\r\n"))


class TestConfigFallback(unittest.TestCase):
    def test_auth_header_basic_from_scan(self):
        c = _cfg()
        c.data["scan"]["qianxin"]["auth_type"] = "basic"
        c.data["scan"]["qianxin"]["username"] = "u"
        c.data["scan"]["qianxin"]["password"] = "p"
        s = QianxinScanner(c)
        h = s._auth_header()
        self.assertTrue(h["Authorization"].startswith("Basic "))
        # base64("u:p") == dTpw
        self.assertIn("Basic dTpw", h["Authorization"])

    def test_auth_header_private_token_falls_back_to_vuln(self):
        # scan.qianxin has no token; vuln.qianxin.token is set -> fallback
        c = _cfg()
        c.data["vuln"]["qianxin"]["token"] = "TOK123"
        s = QianxinScanner(c)
        h = s._auth_header()
        self.assertEqual(h["Authorization"], "Private-Token TOK123")

    def test_base_url_missing_raises(self):
        c = _cfg()
        c.data["scan"]["qianxin"]["base_url"] = None
        c.data["vuln"]["qianxin"]["base_url"] = None
        s = QianxinScanner(c)
        with self.assertRaises(ValueError):
            s._base_url()


class TestHelpers(unittest.TestCase):
    def test_split_coord(self):
        self.assertEqual(_split_coord("g:a:v"), ("g", "a", "v"))
        self.assertEqual(_split_coord("a:v"), (None, "a", "v"))
        self.assertEqual(_split_coord("only"), (None, "only", None))
        self.assertEqual(_split_coord(None), (None, None, None))

    def test_lang_for_target(self):
        self.assertEqual(_lang_for_target(ScanTarget(kind=ScanKind.JAR_LOCAL)), Language.JAVA)
        self.assertEqual(_lang_for_target(ScanTarget(kind=ScanKind.JAR_NEXUS)), Language.JAVA)
        self.assertEqual(_lang_for_target(ScanTarget(kind=ScanKind.JAR_ARTIFACTORY)), Language.JAVA)
        self.assertEqual(_lang_for_target(ScanTarget(kind=ScanKind.IMAGE_HARBOR)), Language.DOCKER)
        self.assertEqual(_lang_for_target(ScanTarget(kind=ScanKind.IMAGE_LOCAL)), Language.DOCKER)
        # dll/so/lib 等原生库通过 --lang c/c++ 覆盖语言（二进制上传接口与 jar 共用）
        self.assertEqual(
            _lang_for_target(ScanTarget(kind=ScanKind.JAR_LOCAL, language_hint="c/c++")),
            Language.CC,
        )


class TestSubmitBodies(unittest.TestCase):
    def setUp(self):
        self.cfg = _cfg()
        self.cfg.data["scan"]["qianxin"]["base_url"] = "https://qx:8449"
        self.cfg.data["scan"]["qianxin"]["project_id"] = "PID"
        self.cfg.data["vuln"]["qianxin"]["token"] = "T"
        self.s = QianxinScanner(self.cfg)

    def test_submit_binary_nexus_body(self):
        captured = {}
        self.s._post_json = lambda path, body: captured.update({"path": path, "body": body}) or {"data": {"taskId": 1}}
        tid = self.s.submit_binary_nexus("http://nexus/a.jar", "u", "p", "task")
        self.assertEqual(tid, 1)
        self.assertEqual(captured["path"], "/scan-center/task/binary-nexus/analysis")
        self.assertEqual(captured["body"]["url"], "http://nexus/a.jar")
        self.assertEqual(captured["body"]["username"], "u")
        self.assertEqual(captured["body"]["projectId"], "PID")

    def test_submit_image_harbor_body(self):
        captured = {}
        self.s._post_json = lambda path, body: captured.update({"path": path, "body": body}) or {"data": {"taskId": 2}}
        tid = self.s.submit_image_harbor("my.harbor.com/oss/centos", "u", "p", "task")
        self.assertEqual(tid, 2)
        self.assertEqual(captured["path"], "/scan-center/task/image-harbor/analysis")
        self.assertEqual(captured["body"]["url"], "my.harbor.com/oss/centos")

    def test_submit_binary_file_multipart(self):
        captured = {}
        self.s._post_multipart = lambda path, fields, files: captured.update(
            {"path": path, "fields": fields, "files": files}) or {"data": {"taskId": 3}}
        tid = self.s.submit_binary_file(b"DATA", "x.jar", "task")
        self.assertEqual(tid, 3)
        self.assertEqual(captured["path"], "/zuul/scan-center/task/binary-file/analysis")
        self.assertEqual(captured["fields"]["projectId"], "PID")
        self.assertEqual(captured["files"][0][0], "file")
        self.assertEqual(captured["files"][0][1], "x.jar")
        self.assertEqual(captured["files"][0][2], b"DATA")


class TestCollect(unittest.TestCase):
    def setUp(self):
        self.cfg = _cfg()
        self.s = QianxinScanner(self.cfg)

    def _fake_paginate(self, path, task_id, page_size):
        # NB: the unknown path also ends with "/component/list", so check it FIRST.
        if path.endswith("/unknown/component/list"):
            return []
        if path.endswith("/component/list"):
            return [{
                "componentId": "c1", "componentName": "Apache Log4j",
                "componentVersion": "2.14.0",
                "coordinates": ["org.apache.logging.log4j:log4j-core:2.14.0"],
                "licenseInfos": [{"licenseShortName": "Apache-2.0"}],
                "componentSourceInfos": [{"path": "Source/pom.xml",
                                         "source": "org.apache.logging.log4j:log4j-core:2.14.0"}],
                "vulnerabilityCount": 1,
            }]
        if path.endswith("/vulnerability/list"):
            return [{
                "vulnerabilityId": "v1", "cve": "CVE-2021-44228", "qaxOssId": "QAXOSS-1",
                "vulnerabilityName": "Log4Shell", "level": 1,
                "vulnerabilityDescription": "RCE", "solution": "升级",
                "releaseDate": "2021-12-10",
                "referenceUrls": [{"source": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
                "affectVersionList": [{"componentId": "c1", "componentName": "log4j-core",
                                       "componentVersion": "2.14.0"}],
                "cvss3Info": {"baseScore": 10.0},
            }]
        return []

    def test_collect_links_vulns_to_components(self):
        self.s._paginate = self._fake_paginate
        comps, vulns = self.s.collect(999, Language.JAVA)
        self.assertEqual(len(comps), 1)
        comp = comps[0]
        self.assertEqual(comp.coordinate, "org.apache.logging.log4j:log4j-core:2.14.0")
        self.assertEqual(comp.license, "Apache-2.0")
        self.assertEqual(len(comp.vulnerabilities), 1)
        v = comp.vulnerabilities[0]
        self.assertEqual(v.vuln_id, "CVE-2021-44228")
        self.assertEqual(v.severity, Severity.CRITICAL)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", v.references)
        self.assertEqual(len(vulns), 1)

    def test_collect_include_unknown_version(self):
        def pg(path, task_id, page_size):
            if path.endswith("/unknown/component/list"):
                return [{"componentName": "mystery-lib",
                         "componentSourceInfos": [{"path": "Source/x.so"}]}]
            if path.endswith("/component/list"):
                return []
            if path.endswith("/vulnerability/list"):
                return []
            return []
        self.s._paginate = pg
        comps, vulns = self.s.collect(1, Language.CC)
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0].name, "mystery-lib")
        self.assertIsNone(comps[0].version)
        self.assertTrue(comps[0].extra.get("qx_unknown_version"))


class TestWaitDone(unittest.TestCase):
    def setUp(self):
        self.cfg = _cfg()
        self.s = QianxinScanner(self.cfg)

    def test_wait_done_polls_until_success(self):
        states = [{"code": 9}, {"code": 1, "data": {"componentCount": 0}}]
        self.s.get_result = lambda tid: states.pop(0)
        with patch("dtrack.scan.qianxin_scan.time.sleep"):
            res = self.s.wait_done(5)
        self.assertEqual(res["code"], 1)

    def test_wait_done_timeout(self):
        self.s.get_result = lambda tid: {"code": 9}
        self.s._cfg = lambda key, default=None: 0 if key == "poll_timeout" else (1 if key == "poll_interval" else default)
        with patch("dtrack.scan.qianxin_scan.time.sleep"):
            with self.assertRaises(TimeoutError):
                self.s.wait_done(5)


class TestScanTargetCLI(unittest.TestCase):
    def test_cmd_scan_writes_report(self):
        from dtrack import cli
        comps = [
            Component(group="g", name="a", version="1.0", language=Language.JAVA,
                      direct=True, vulnerabilities=[
                    Vulnerability(vuln_id="CVE-1", source=SourceType.QIANXIN,
                                  title="x", severity=Severity.HIGH)])
        ]
        res = AnalysisResult(target="demo", language=Language.JAVA,
                             components=comps, sources_used=["qianxin"])
        res.enrich_summary()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cli, "scan_target", return_value=res):
                args = cli.build_parser().parse_args([
                    "scan", "--kind", "jar-local", "--path", "x.jar",
                    "--project-id", "PID", "--out", tmp, "--report", "r.md",
                ])
                rc = cli.cmd_scan(args, _cfg())
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(os.path.join(tmp, "r.md")))


if __name__ == "__main__":
    unittest.main()
