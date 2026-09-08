"""前后端拉通（front-to-back）集成测试 + 逆向/边界测试。

通过真实的 HTTP 路由层 ``dtrack.web.handlers._Router.dispatch`` 驱动整条链路：
前端请求 -> 路由 -> service -> store，覆盖导入 / 扫描 / 查询 / 报表（md+pdf）
以及各类异常输入、重复导入、缺配置、缺字段、越权路径等逆向场景。

扫码器（奇安信）与 GitLab fetcher 一律 mock，确保离线、无外部依赖即可运行。
"""
import copy
import json
import os
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dtrack.config import Config, DEFAULT_CONFIG
from dtrack.core.models import AnalysisResult, Component, Vulnerability
from dtrack.core.types import DependencyType, Language, Severity, SourceType
from dtrack.report import render_markdown
from dtrack.web.handlers import _Router
from dtrack.web.service import WebService
from dtrack.web.store import Db


def _fake_qx_result() -> AnalysisResult:
    comp = Component(
        group="org.apache", name="commons-fileupload", version="1.3.1",
        language=Language.JAVA, license="Apache-2.0",
        direct=True, vulnerabilities=[
            Vulnerability(vuln_id="CVE-2016-1000031", source=SourceType.QIANXIN,
                          title="任意文件上传", severity=Severity.CRITICAL,
                          description="demo", sources=["qianxin"]),
            Vulnerability(vuln_id="CVE-M", source=SourceType.QIANXIN,
                          title="中危示例", severity=Severity.MEDIUM,
                          sources=["qianxin"]),
        ])
    return AnalysisResult(target="image", language=Language.JAVA,
                          components=[comp], vulnerabilities=[],
                          sources_used=["qianxin"])


def _wait_status(db, ref_type, vid, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = db.get_version(ref_type, vid)
        if row and row["scan_status"] in ("done", "failed", "no_qianxin"):
            return row
        time.sleep(0.05)
    return db.get_version(ref_type, vid)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "web_test.db")
        self.cfg_path = os.path.join(self.tmp, "dtrack.toml")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            f.write(
                "[scan.qianxin]\n"
                "base_url = \"https://qianxin.local:8449\"\n"
                "project_id = \"P-123\"\n"
            )
        self.db = Db(self.db_path)
        self.svc = WebService(self.db, self.cfg_path)
        # 关闭在线漏洞源，避免离线环境触发网络访问（仅走奇安信扫描模式/无源路径）
        self.svc.config.data.setdefault("vuln", {})["sources"] = []
        self.router = _Router(self.svc, None)

    def tearDown(self):
        self.db.close()

    def dispatch(self, method, path, payload=None):
        # 真实前端请求都带 /api 前缀；这里自动补上，便于用例以「资源路径」书写
        if not path.startswith("/api"):
            path = "/api" + path
        if isinstance(payload, (bytes, bytearray)):
            body = bytes(payload)  # 支持原始字节（空 body / 非法 JSON）
        else:
            body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        return self.router.dispatch(method, path, body)

    def mock_scanner(self):
        """patch 奇安信扫描器为同步返回假结果。"""
        patcher = mock.patch("dtrack.scan.qianxin_scan.QianxinScanner")
        M = patcher.start()
        inst = M.return_value
        inst.run.return_value = _fake_qx_result()
        self.addCleanup(patcher.stop)
        # 让扫描同步执行，避免后台线程脱离 mock 上下文 / 跨线程写库
        self.svc.scan_version_async = lambda rt, vid: self.svc._do_scan_qianxin(rt, vid)
        return inst


class FrontendBackendIntegrationTest(_Base):
    """真实路由层驱动的全链路测试。"""

    def test_pom_project_import_full_chain(self):
        # 前端以 pom 文本导入项目 -> 后端解析 -> 报表
        pom = (
            '<?xml version="1.0"?><project>'
            '<groupId>com.demo</groupId><artifactId>oa-system</artifactId>'
            '<version>1.0</version>'
            '<dependencies><dependency>'
            '<groupId>org.apache.logging.log4j</groupId>'
            '<artifactId>log4j-core</artifactId><version>2.14.0</version>'
            '</dependency></dependencies></project>'
        )
        status, _h, data = self.dispatch("POST", "/projects/import",
                                         {"pom_text": pom})
        self.assertEqual(status, 201)
        body = json.loads(data)
        self.assertEqual(body["ref_type"], "project")
        vid = body["version_id"]
        # 版本详情可读
        status, _h, data = self.dispatch("GET", f"/projects/version/{vid}")
        self.assertEqual(status, 200)
        detail = json.loads(data)
        self.assertIn("stats", detail)
        # 报表（markdown）可下载且非空
        status, _h, md = self.dispatch("GET", f"/projects/version/{vid}/report")
        self.assertEqual(status, 200)
        self.assertIn("三方组件漏洞分析报告", md.decode("utf-8"))
        # 报表（PDF）可下载
        status, _h, pdf = self.dispatch("GET", f"/projects/version/{vid}/report.pdf")
        self.assertEqual(status, 200)
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_harbor_import_full_chain(self):
        self.mock_scanner()
        status, _h, data = self.dispatch(
            "POST", "/projects/import",
            {"source": "harbor", "image_url": "my.harbor.com:6443/lib/cen:7"})
        self.assertEqual(status, 201)
        body = json.loads(data)
        self.assertEqual(body["version"], "7")
        self.assertEqual(body["source_ref"], "my.harbor.com:6443/lib/cen:7")
        vid = body["version_id"]
        row = _wait_status(self.db, "project", vid)
        self.assertEqual(row["scan_status"], "done")
        # 组件与漏洞已入库
        comps = self.db.list_components({})
        self.assertTrue(any(c["name"] == "commons-fileupload" for c in comps))
        detail = self.db.get_component_detail("org.apache:commons-fileupload:1.3.1")
        self.assertGreaterEqual(len(detail["vulnerabilities"]), 1)
        # 报表含中危及以上汇总小节（2.4）+ 影响项目（组件未被项目引用时为 —）
        md = self.svc.get_report("project", vid)
        self.assertIn("### 2.4", md)

    def test_whitelist_report_affected_projects_full_chain(self):
        """白名单导入（pom）后，关联一个引用其组件的项目，验证报表的「影响项目」列。

        通过真实导入端点创建白名单版本（前端->后端链路），再补齐关联数据，
        验证 md 与 pdf 报表均正确承载「影响项目」列。
        """
        # 同步扫描，避免后台线程与断言竞争
        self.svc.scan_version_async = lambda rt, vid_: self.svc._do_scan(rt, vid_)
        pom = (
            '<?xml version="1.0"?><project>'
            '<groupId>org.apache.logging.log4j</groupId>'
            '<artifactId>log4j-core</artifactId><version>2.14.0</version>'
            '</project>'
        )
        status, _h, data = self.dispatch("POST", "/whitelists/import", {"pom_text": pom})
        self.assertEqual(status, 201)
        wv = json.loads(data)["version_id"]

        # 关联真实数据：业务项目引用该坐标组件并带超危漏洞
        pid = self.db.upsert_project("com.demo", "oa-system", "com.demo:oa-system")
        pv = self.db.add_project_version(pid, "1.0", "pom", None, "<pom/>")
        cid = self.db.upsert_component("org.apache.logging.log4j", "log4j-core",
                                       "2.14.0", "java", "Apache-2.0", is_whitelist=True)
        self.db.add_usage(cid, "whitelist", wv, "direct")   # 白名单版本引用该组件
        self.db.add_usage(cid, "project", pv, "direct")      # 项目也引用（影响项目来源）
        self.db.add_vulnerability(cid, {"vuln_key": "k1", "vuln_id": "CVE-2021-44228",
                                        "source": "nvd", "title": "Log4Shell",
                                        "severity": "critical", "description": "rce"})
        # 清除扫描阶段生成的旧缓存（无影响项目数据），强制按最新数据重建报表
        self.db.set_version_report("whitelist", wv, {}, "")

        # 报表（md）含影响项目列，且展示被引用的业务项目
        md = self.svc.get_report("whitelist", wv)
        self.assertIn("影响项目", md)
        self.assertIn("oa-system:1.0", md)
        # 报表（pdf）同样含影响项目数据
        pdf = self.svc.get_report_pdf("whitelist", wv)
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_static_path_traversal_blocked(self):
        dist = os.path.join(self.tmp, "dist")
        os.makedirs(dist)
        with open(os.path.join(dist, "index.html"), "w", encoding="utf-8") as f:
            f.write("<html>app</html>")
        secret = os.path.join(self.tmp, "secret.txt")
        with open(secret, "w", encoding="utf-8") as f:
            f.write("TOPSECRET")
        router = _Router(self.svc, dist)
        # 越权读取上层 secret.txt 必须被拒绝
        status, _h, data = router.dispatch("GET", "/../secret.txt")
        self.assertIn(status, (403, 404))
        self.assertNotIn(b"TOPSECRET", data)
        # 正常静态资源可读
        status, _h, data = router.dispatch("GET", "/index.html")
        self.assertEqual(status, 200)
        self.assertIn(b"app", data)


class NegativeImportTest(_Base):
    """逆向导入测试：异常输入、缺字段、重复导入、缺配置等。"""

    def test_duplicate_image_import_does_not_crash(self):
        """重复导入同一镜像（同 tag）应安全复用版本并重扫，而非报 UNIQUE 约束 500。"""
        self.mock_scanner()
        payload = {"source": "harbor", "image_url": "nginx:1.25"}
        s1, _h, d1 = self.dispatch("POST", "/projects/import", payload)
        self.assertEqual(s1, 201)
        vid1 = json.loads(d1)["version_id"]
        s2, _h, d2 = self.dispatch("POST", "/projects/import", payload)
        self.assertEqual(s2, 201)
        vid2 = json.loads(d2)["version_id"]
        self.assertEqual(vid1, vid2, "重复导入同一 tag 应复用同一版本并触发重扫")
        row = _wait_status(self.db, "project", vid1)
        self.assertEqual(row["scan_status"], "done")

    def test_two_different_images_make_two_owners(self):
        """不同镜像不应被错误合并到同一白名单/项目 owner（owner 名称错乱 bug）。"""
        self.mock_scanner()
        self.dispatch("POST", "/whitelists/import",
                      {"source": "harbor", "image_url": "registry/a/centos:7"})
        self.dispatch("POST", "/whitelists/import",
                      {"source": "harbor", "image_url": "registry/b/nginx:1.25"})
        owners = self.db.list_whitelists()
        self.assertEqual(len(owners), 2, "不同镜像应为独立 owner")
        names = {o["name"] for o in owners}
        self.assertIn("centos", names)
        self.assertIn("nginx", names)

    def test_import_missing_qianxin_config_returns_error(self):
        """未配置奇安信扫描时，二进制导入应返回清晰错误（不静默成功）。"""
        self.svc.config.data["scan"]["qianxin"] = {}
        status, _h, data = self.dispatch(
            "POST", "/projects/import",
            {"source": "harbor", "image_url": "nginx:latest"})
        self.assertIn(status, (400, 500))
        self.assertIn("奇安信", data.decode("utf-8"))

    def test_harbor_missing_image_url(self):
        status, _h, data = self.dispatch(
            "POST", "/projects/import", {"source": "harbor"})
        self.assertIn(status, (400, 500))
        self.assertIn("image_url", data.decode("utf-8"))

    def test_gitlab_jar_missing_project(self):
        status, _h, data = self.dispatch(
            "POST", "/projects/import", {"source": "gitlab-jar", "ref": "v1"})
        self.assertIn(status, (400, 500))
        self.assertIn("gitlab_project", data.decode("utf-8"))

    def test_unsupported_source(self):
        status, _h, data = self.dispatch(
            "POST", "/projects/import", {"source": "s3-bucket"})
        self.assertIn(status, (400, 500))

    def test_empty_body_no_crash(self):
        """空/非法 JSON body 不应使进程崩溃（应被路由层吞下并返回错误）。"""
        status, _h, data = self.dispatch("POST", "/projects/import", b"")
        self.assertIn(status, (400, 500))
        status, _h, data = self.dispatch("POST", "/projects/import", b"{not json")
        self.assertIn(status, (400, 500))

    def test_gitlab_import_not_configured(self):
        """GitLab 未配置时导入应返回明确的中文报错，而非未知异常。"""
        with mock.patch("dtrack.sources.get_fetcher") as G:
            fetcher = mock.MagicMock()
            fetcher.enabled.return_value = False
            G.return_value = fetcher
            status, _h, data = self.dispatch(
                "POST", "/projects/import",
                {"gitlab_project": "grp/app", "ref": "main"})
        self.assertIn(status, (400, 500))
        self.assertIn("GitLab", data.decode("utf-8"))

    def test_scan_no_components_sets_done(self):
        """pom 解析为空（无组件）时扫描应置为 done 并生成空报表，而非卡在 pending。"""
        # 同步执行扫描，避免后台线程与断言竞争
        self.svc.scan_version_async = lambda rt, vid_: self.svc._do_scan(rt, vid_)
        pom = ('<?xml version="1.0"?><project>'
               '<groupId>com.empty</groupId><artifactId>empty</artifactId>'
               '<version>1.0</version></project>')
        status, _h, data = self.dispatch("POST", "/projects/import", {"pom_text": pom})
        self.assertEqual(status, 201)
        vid = json.loads(data)["version_id"]
        row = self.db.get_version("project", vid)
        self.assertIn(row["scan_status"], ("done", "no_qianxin"))


class NegativeQueryTest(_Base):
    """逆向查询测试：缺参数、资源不存在、删除后访问等。"""

    def test_detail_missing_coord(self):
        status, _h, data = self.dispatch("GET", "/components/detail")
        self.assertEqual(status, 400)

    def test_detail_not_found(self):
        status, _h, data = self.dispatch("GET", "/components/detail?coord=nope:1.0")
        self.assertEqual(status, 404)

    def test_report_missing_version(self):
        status, _h, data = self.dispatch("GET", "/projects/version/99999/report")
        self.assertEqual(status, 404)

    def test_pdf_missing_version(self):
        status, _h, data = self.dispatch("GET", "/projects/version/99999/report.pdf")
        self.assertEqual(status, 404)

    def test_get_version_not_found_returns_404(self):
        """不存在的版本详情应返回 404 而非 200/null。"""
        status, _h, data = self.dispatch("GET", "/projects/version/99999")
        self.assertEqual(status, 404)

    def test_list_version_components_missing_version(self):
        status, _h, data = self.dispatch("GET", "/projects/version/99999/components")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data), [])

    def test_delete_then_report_404(self):
        self.mock_scanner()
        status, _h, data = self.dispatch(
            "POST", "/projects/import",
            {"source": "harbor", "image_url": "delme:1.0"})
        vid = json.loads(data)["version_id"]
        _wait_status(self.db, "project", vid)
        status, _h, data = self.dispatch("DELETE", f"/projects/version/{vid}")
        self.assertEqual(status, 200)
        status, _h, data = self.dispatch("GET", f"/projects/version/{vid}/report")
        self.assertEqual(status, 404)


class ReportConsistencyTest(_Base):
    """报表一致性：markdown 与 PDF 在「影响项目」列显示规则上必须一致。

    markdown 以纯文本断言；PDF 端因 reportlab 以 2 字节 CID 编码中文字形、
    无法稳定还原中文，故以「影响项目」数据（拉丁标签）是否落地来证明该列已渲染。
    """

    def _vuln_comp(self, affected=None):
        comp = Component(
            group="org.x", name="lib", version="1.0", language=Language.JAVA,
            dependency_type=DependencyType.DIRECT, direct=True,
            vulnerabilities=[Vulnerability(
                vuln_id="CVE-1", source=SourceType.NVD, severity=Severity.HIGH,
                title="t", sources=["nvd"])])
        if affected is not None:
            comp.extra["affected_projects"] = affected
        return comp

    def test_markdown_shows_column_when_vuln_even_without_affected(self):
        """回归点：存在漏洞但无项目引用时，markdown 第五章仍应展示「影响项目」列。"""
        res = AnalysisResult(target="wl:demo:1.0", language=Language.JAVA,
                             components=[self._vuln_comp()], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        self.assertIn("影响项目", md.split("## 五、组件全集")[1])

    def test_markdown_hides_column_when_no_vuln(self):
        clean = Component(group="org.w", name="clean", version="1.0",
                         language=Language.JAVA, direct=True, vulnerabilities=[])
        res = AnalysisResult(target="x", language=Language.JAVA,
                             components=[clean], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        self.assertNotIn("影响项目", md.split("## 五、组件全集")[1])

    def test_pdf_renders_affected_column_with_data(self):
        """PDF 端：存在中危及以上漏洞且带影响项目数据时，该列（含数据）必须渲染进 PDF。

        用拉丁标签 PROJX:1.0 便于从 PDF 内容流稳定还原（中文 CID 不可靠）。
        与 markdown 共用同一 show_affected 判定（中危及以上漏洞 或 传染型 License），
        故 markdown 显示列时 PDF 亦显示列。
        """
        try:
            from dtrack.report.pdf import render_pdf
        except ImportError:
            self.skipTest("reportlab 未安装")
        res = AnalysisResult(
            target="wl:demo:1.0", language=Language.JAVA,
            components=[self._vuln_comp(affected=["PROJX:1.0"])],
            sources_used=["nvd"])
        res.enrich_summary()
        pdf = render_pdf(res)
        self.assertIsInstance(pdf, bytes)
        self.assertIn("PROJX:1.0", _pdf_text(pdf))


def _pdf_text(pdf: bytes) -> str:
    """还原 PDF 内容流中的明文（ASCII 可稳定还原；中文 CID 字形不可靠，故仅用于拉丁断言）。"""
    import base64
    import re
    import zlib

    out = b""
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        data = m.group(1).strip()
        if data.endswith(b"~>"):
            data = data[:-2]
        try:
            decoded = base64.a85decode(data)
        except Exception:
            decoded = data
        try:
            decoded = zlib.decompress(decoded)
        except Exception:
            pass
        out += decoded
    raw = out.decode("latin-1", "ignore")
    raw = re.sub(r"\\([0-7]{1,3})", lambda x: chr(int(x.group(1), 8)), raw)
    chars = []
    i, n = 0, len(raw)
    while i < n:
        if raw[i] == "\x00" and i + 1 < n:
            chars.append(raw[i + 1])
            i += 2
        else:
            i += 1
    return "".join(chars)


class RealHttpRoundTripTest(_Base):
    """真正拉起 http.server + Handler，用 urllib 发起真实 HTTP 请求，
    覆盖 Handler._handle 的请求体读取 / 状态码 / CORS 头等环节（前端真实链路）。"""

    def setUp(self):
        super().setUp()
        from http.server import ThreadingHTTPServer
        from dtrack.web.handlers import Handler
        self.mock_scanner()
        Handler.router = self.router
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self._t = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._t.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}/api{path}"

    def test_harbor_import_then_report_over_http(self):
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            self._url("/projects/import"),
            data=json.dumps({"source": "harbor",
                             "image_url": "my.harbor.com:6443/lib/cen:7"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            self.assertEqual(r.status, 201)
            body = json.loads(r.read())
        self.assertEqual(body["version"], "7")
        vid = body["version_id"]
        # 报表（markdown）经真实 HTTP 下载
        with urllib.request.urlopen(self._url(f"/projects/version/{vid}/report"),
                                    timeout=15) as r:
            self.assertEqual(r.status, 200)
            self.assertIn("三方组件漏洞分析报告", r.read().decode("utf-8"))
        # 不存在的组件详情经真实 HTTP 返回 404（urlopen 对非 2xx 抛 HTTPError）
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(
                self._url("/components/detail?coord=nope:1.0"), timeout=15)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
