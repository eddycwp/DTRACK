"""Tests for 白名单报告新增内容：

1. store.projects_for_component：返回引用组件的全部业务项目（项目名称:版本）。
2. markdown 第二章新增 2.4 小节「中危及以上安全漏洞影响的产品和版本清单汇总」。
3. markdown 第五章新增「影响项目」列。
"""
import copy
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dtrack.config import Config, DEFAULT_CONFIG
from dtrack.core.models import AnalysisResult, Component, Vulnerability
from dtrack.core.types import DependencyType, Language, Severity, SourceType
from dtrack.report import render_markdown
from dtrack.web.service import WebService
from dtrack.web.store import Db


class TestProjectsForComponent(unittest.TestCase):
    def setUp(self):
        self.db = Db(os.path.join(tempfile.mkdtemp(), "t.db"))
        self.svc = WebService(self.db, os.path.join(tempfile.mkdtemp(), "dtrack.toml"))
        self.svc.config = Config(copy.deepcopy(DEFAULT_CONFIG))

    def tearDown(self):
        self.db.close()

    def _seed(self):
        # 组件（来自白名单）
        cid = self.db.upsert_component("org.x", "lib", "1.0", "java", "MIT", is_whitelist=True)
        # 两个业务项目都引用该组件
        p1 = self.db.upsert_project("com.p1", "app-one", "com.p1:app-one")
        v1 = self.db.add_project_version(p1, "1.0", "pom", None, "<pom/>")
        self.db.add_usage(cid, "project", v1, "direct")
        p2 = self.db.upsert_project("com.p2", "app-two", "com.p2:app-two")
        v2 = self.db.add_project_version(p2, "2.3", "pom", None, "<pom/>")
        self.db.add_usage(cid, "project", v2, "transitive")
        return cid

    def test_projects_for_component(self):
        cid = self._seed()
        comp = self.db.get_component("org.x:lib:1.0")
        projs = self.db.projects_for_component(comp["coord"])
        # project.name 字段在库中存为传入的第三个参数（此处为坐标形式）
        self.assertIn("com.p1:app-one:1.0", projs)
        self.assertIn("com.p2:app-two:2.3", projs)
        self.assertEqual(len(projs), 2)

    def test_no_project_returns_empty(self):
        cid = self.db.upsert_component("org.y", "alone", "1.0", "java", "MIT", is_whitelist=False)
        comp = self.db.get_component("org.y:alone:1.0")
        self.assertEqual(self.db.projects_for_component(comp["coord"]), [])

    def test_dual_row_same_coord(self):
        # 同一坐标同时存在于 whitelist 行与 project 行（真实场景：白名单与项目都引用它）。
        # 旧实现取 get_component() 返回的单行 id，可能取到 whitelist 行而漏掉 project 引用。
        coord = "org.x:lib:1.0"
        cid_wl = self.db.upsert_component("org.x", "lib", "1.0", "java", "MIT", is_whitelist=True)
        cid_pj = self.db.upsert_component("org.x", "lib", "1.0", "java", "MIT", is_whitelist=False)
        p1 = self.db.upsert_project("com.p1", "app-one", "com.p1:app-one")
        v1 = self.db.add_project_version(p1, "1.0", "pom", None, "<pom/>")
        # 仅 project 行挂了项目引用（whitelist 行无 project 引用）
        self.db.add_usage(cid_pj, "project", v1, "direct")
        projs = self.db.projects_for_component(coord)
        self.assertEqual(projs, ["com.p1:app-one:1.0"])


class TestReportCacheInvalidation(unittest.TestCase):
    """get_report 必须让缺 2.4 小节的旧缓存失效并重生成，否则看到的是无数据的旧报告。"""

    def setUp(self):
        import tempfile
        self.db = Db(os.path.join(tempfile.mkdtemp(), "t.db"))
        self.svc = WebService(self.db, os.path.join(tempfile.mkdtemp(), "dtrack.toml"))

    def tearDown(self):
        self.db.close()

    def test_stale_cache_without_2_4_regenerates(self):
        # 项目引用组件（含超危漏洞）
        pid = self.db.upsert_project("com.demo", "oa-system", "com.demo:oa-system")
        pv = self.db.add_project_version(pid, "1.0", "pom", None, "<pom/>")
        cid_pj = self.db.upsert_component("org.apache.logging.log4j", "log4j-core",
                                          "2.14.0", "java", "Apache-2.0", is_whitelist=False)
        self.db.add_usage(cid_pj, "project", pv, "direct")
        self.db.add_vulnerability(cid_pj, {"vuln_key": "k1", "vuln_id": "CVE-2021-44228",
                                           "source": "nvd", "title": "Log4Shell",
                                           "severity": "critical", "description": "rce"})
        # 白名单条目（同坐标）
        wid = self.db.upsert_whitelist("org.apache.logging.log4j", "log4j-core",
                                       "org.apache.logging.log4j:log4j-core")
        wv = self.db.add_whitelist_version(wid, "2.14.0", "pom", None, "<pom/>")
        cid_wl = self.db.upsert_component("org.apache.logging.log4j", "log4j-core",
                                          "2.14.0", "java", "Apache-2.0", is_whitelist=True)
        self.db.add_usage(cid_wl, "whitelist", wv, "direct")
        self.db.add_vulnerability(cid_wl, {"vuln_key": "k1", "vuln_id": "CVE-2021-44228",
                                           "source": "nvd", "title": "Log4Shell",
                                           "severity": "critical", "description": "rce"})
        # 写一份「目标格式已是新格式、但缺 2.4 小节」的旧缓存（模拟真实陈旧报告）
        self.db.set_version_report("whitelist", wv, {},
                                   "# 三方组件漏洞分析报告\n**分析目标**："
                                   "org.apache.logging.log4j:log4j-core:2.14.0\n"
                                   "## 二、漏洞分布\n### 2.1\n### 2.2\n### 2.3\n"
                                   "## 五、组件全集\n| # | 组件 | 版本 |\n")

        md = self.svc.get_report("whitelist", wv)
        # 重生成后：含 2.4 小节 + 影响项目列 + 真实项目数据
        self.assertIn("### 2.4 中危及以上安全漏洞影响的产品和版本清单汇总", md)
        self.assertIn("影响项目", md)
        self.assertIn("oa-system:1.0", md)


try:
    from dtrack.report.pdf import render_pdf
    _HAVE_PDF = True
except ImportError:  # pragma: no cover
    _HAVE_PDF = False


@unittest.skipUnless(_HAVE_PDF, "reportlab 未安装，跳过 PDF 报告测试")
class TestPdfAffectedSections(unittest.TestCase):
    def _result(self):
        from dtrack.core.models import AnalysisResult, Component, Vulnerability
        from dtrack.core.types import DependencyType, Language, Severity, SourceType
        log4j = Component(group="org.apache.logging.log4j", name="log4j-core",
                          version="2.14.0", language=Language.JAVA,
                          dependency_type=DependencyType.DIRECT, direct=True, transitive=False,
                          vulnerabilities=[Vulnerability(vuln_id="CVE-2021-44228",
                                                        source=SourceType.NVD,
                                                        severity=Severity.CRITICAL,
                                                        title="Log4Shell", sources=["nvd"],
                                                        description="rce"),
                                          Vulnerability(vuln_id="CVE-M", source=SourceType.NVD,
                                                        severity=Severity.MEDIUM, title="m",
                                                        sources=["nvd"])])
        low = Component(group="org.z", name="lowlib", version="1.0", language=Language.JAVA,
                        dependency_type=DependencyType.DIRECT, direct=True, transitive=False,
                        vulnerabilities=[Vulnerability(vuln_id="CVE-L", source=SourceType.NVD,
                                                       severity=Severity.LOW, title="l",
                                                       sources=["nvd"])])
        log4j.extra["affected_projects"] = ["oa-system:1.0", "gateway:2.3"]
        res = AnalysisResult(target="wl:demo:1.0", language=Language.JAVA,
                             components=[log4j, low], sources_used=["nvd"])
        res.enrich_summary()
        return res

    def test_pdf_has_2_4_and_affected_projects(self):
        pdf = render_pdf(self._result())
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertTrue(len(pdf) > 1000)
        # PDF 内容流经 ASCII85 + Flate 压缩；解压后文本以 CID(UCS2-BE) 编码，
        # ASCII 字符高字节为 0。将其还原为明文后校验影响项目数据已进入 PDF。
        # 中文章节标题的呈现由 markdown 测试覆盖，这里保证 PDF 生成链路与数据注入
        # 不报错且数据落地。
        text = _pdf_ascii_text(pdf)
        self.assertIn("oa-system:1.0", text)
        self.assertIn("gateway:2.3", text)


def _decompress_pdf_streams(pdf: bytes) -> bytes:
    """提取 PDF 中所有内容流，依次做 ASCII85 + Flate 解压，拼接为字节。"""
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
    return out


def _pdf_ascii_text(pdf: bytes) -> str:
    """将 PDF 内容流的 CID(UCS2-BE) 文本还原为 ASCII 明文。

    reportlab 将 CID 文本以 PDF 八进制转义写入内容流（如 ``\\000o\\000a`` 表示
    ``0x00 0x6f 0x00 0x61``），原始字节中并不含真实 null，需先还原八进制转义，
    再把「高字节为 0、低字节为 ASCII」的成对字符提取为明文。
    """
    import re as _re
    raw = _decompress_pdf_streams(pdf).decode("latin-1", "ignore")

    def _oct(m: "re.Match") -> str:  # noqa: F821
        return chr(int(m.group(1), 8))

    raw = _re.sub(r"\\([0-7]{1,3})", _oct, raw)
    out = []
    i = 0
    n = len(raw)
    while i < n:
        if raw[i] == "\x00" and i + 1 < n:
            out.append(raw[i + 1])
            i += 2
        else:
            i += 1
    return "".join(out)


class TestReportAffectedSections(unittest.TestCase):
    def _result(self, with_projects=True):
        # 有中危及以上漏洞的组件（log4j）
        log4j = Component(
            group="org.apache.logging.log4j", name="log4j-core", version="2.14.0",
            language=Language.JAVA, dependency_type=DependencyType.DIRECT, direct=True,
            transitive=False,
            vulnerabilities=[
                Vulnerability(vuln_id="CVE-2021-44228", source=SourceType.NVD,
                              severity=Severity.CRITICAL, title="Log4Shell",
                              sources=["nvd", "github"], description="RCE"),
                Vulnerability(vuln_id="CVE-2021-45046", source=SourceType.NVD,
                              severity=Severity.HIGH, title="DoS", sources=["nvd"]),
                Vulnerability(vuln_id="CVE-2021-45105", source=SourceType.NVD,
                              severity=Severity.MEDIUM, title="DoS2", sources=["nvd"]),
            ],
        )
        # 低危组件（不应出现在 2.4 汇总）
        low = Component(group="org.z", name="lowlib", version="1.0", language=Language.JAVA,
                        dependency_type=DependencyType.DIRECT, direct=True, transitive=False,
                        vulnerabilities=[Vulnerability(vuln_id="CVE-LOW", source=SourceType.NVD,
                                                       severity=Severity.LOW, title="t",
                                                       sources=["nvd"])])
        # 无漏洞组件（不应出现在 2.4，也不应展示影响项目列）
        clean = Component(group="org.w", name="clean", version="1.0", language=Language.JAVA,
                          dependency_type=DependencyType.DIRECT, direct=True, transitive=False,
                          vulnerabilities=[])
        if with_projects:
            log4j.extra["affected_projects"] = ["app-one:1.0", "app-two:2.3"]
            low.extra["affected_projects"] = ["app-one:1.0"]
        res = AnalysisResult(target="wl:demo:1.0", language=Language.JAVA,
                             components=[log4j, low, clean], sources_used=["nvd"])
        res.enrich_summary()
        return res

    def test_2_4_section_present_with_projects(self):
        md = render_markdown(self._result(True))
        self.assertIn("### 2.4 中危及以上安全漏洞影响的产品和版本清单汇总", md)
        self.assertIn("log4j-core", md)
        # 中危及以上：log4j 出现，lowlib(低危)/clean 不出现
        self.assertNotIn("lowlib", md.split("2.4")[1].split("## 三")[0])
        self.assertNotIn("clean", md.split("2.4")[1].split("## 三")[0])
        # 影响项目行展示
        self.assertIn("app-one:1.0", md)
        self.assertIn("app-two:2.3", md)

    def test_2_4_absent_when_no_mid_plus(self):
        # 构造一个只有低危/无漏洞的报告
        low = Component(group="org.z", name="lowlib", version="1.0", language=Language.JAVA,
                        dependency_type=DependencyType.DIRECT, direct=True, transitive=False,
                        vulnerabilities=[Vulnerability(vuln_id="CVE-LOW", source=SourceType.NVD,
                                                       severity=Severity.LOW, title="t",
                                                       sources=["nvd"])])
        res = AnalysisResult(target="x", language=Language.JAVA,
                             components=[low], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        self.assertIn("### 2.4", md)
        self.assertIn("未检测到中危及以上安全漏洞", md)

    def test_chapter5_affected_column(self):
        md = render_markdown(self._result(True))
        # 第五章表头含「影响项目」
        chapter5 = md.split("## 五、组件全集")[1]
        self.assertIn("影响项目", chapter5)
        # 中危及以上组件（log4j）展示影响项目；低危/无漏洞组件标记为 —
        self.assertIn("app-one:1.0", chapter5)
        # 低危组件 lowlib 不应展示影响项目
        for line in chapter5.splitlines():
            if line.startswith("| ") and "lowlib" in line:
                self.assertNotIn("app-one", line)
                self.assertTrue(line.rstrip().endswith("| — |"))
                break
        else:
            self.fail("未找到 lowlib 所在行")

    def test_chapter5_no_affected_column_when_no_vulns(self):
        clean = Component(group="org.w", name="clean", version="1.0", language=Language.JAVA,
                          dependency_type=DependencyType.DIRECT, direct=True, transitive=False,
                          vulnerabilities=[])
        res = AnalysisResult(target="x", language=Language.JAVA,
                             components=[clean], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        chapter5 = md.split("## 五、组件全集")[1]
        self.assertNotIn("影响项目", chapter5)

    def test_chapter5_copyleft_shows_affected_column(self):
        """无漏洞但使用传染型 License 的组件也应展示影响项目列。"""
        gpl = Component(group="com.sun.mail", name="jakarta.mail", version="2.0.1",
                        language=Language.JAVA, dependency_type=DependencyType.DIRECT,
                        direct=True, transitive=False, license="GPL-2.0",
                        vulnerabilities=[])
        gpl.extra["affected_projects"] = ["COUS:1.0.0-beta", "wvmp-web-boot-starter:2.0.2-ccp1"]
        res = AnalysisResult(target="x", language=Language.JAVA,
                             components=[gpl], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        chapter5 = md.split("## 五、组件全集")[1]
        self.assertIn("影响项目", chapter5)
        self.assertIn("COUS:1.0.0-beta", chapter5)
        self.assertIn("wvmp-web-boot-starter:2.0.2-ccp1", chapter5)

    def test_chapter5_clean_component_hides_affected_projects(self):
        """无漏洞组件即使 extra 里携带了 affected_projects，第五章也不应显示。"""
        # 有漏洞组件（log4j）展示影响项目
        log4j = Component(
            group="org.apache.logging.log4j", name="log4j-core", version="2.14.0",
            language=Language.JAVA, dependency_type=DependencyType.DIRECT, direct=True,
            transitive=False,
            vulnerabilities=[Vulnerability(vuln_id="CVE-2021-44228", source=SourceType.NVD,
                                           severity=Severity.CRITICAL, title="Log4Shell",
                                           sources=["nvd"])])
        log4j.extra["affected_projects"] = ["app-one:1.0"]
        # 无漏洞组件（cglib 场景）也带 affected_projects，但不应展示
        clean = Component(group="cglib", name="cglib", version="3.3.0",
                          language=Language.JAVA, dependency_type=DependencyType.DIRECT,
                          direct=True, transitive=False, vulnerabilities=[])
        clean.extra["affected_projects"] = ["COUS:1.0.0-beta", "wvmp-web-boot-starter:2.0.2-ccp1"]
        res = AnalysisResult(target="wl:demo:1.0", language=Language.JAVA,
                             components=[log4j, clean], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        chapter5 = md.split("## 五、组件全集")[1]
        # 表头仍有「影响项目」列（因为 log4j 有漏洞）
        self.assertIn("影响项目", chapter5)
        # log4j 行展示影响项目
        self.assertIn("app-one:1.0", chapter5)
        # clean 行不展示影响项目：取 clean 所在行文本并断言不含项目名
        for line in chapter5.splitlines():
            if line.startswith("| ") and "cglib:cglib" in line:
                self.assertNotIn("COUS", line)
                self.assertNotIn("wvmp-web-boot", line)
                self.assertIn("| 无 |", line)  # 漏洞分级为「无」
                # 该行最后一列应为 —（影响项目）
                self.assertTrue(line.rstrip().endswith("| — |"))
                break
        else:
            self.fail("未找到 cglib:cglib 所在行")


@unittest.skipUnless(_HAVE_PDF, "reportlab 未安装，跳过 PDF 报告测试")
class TestPdfAffectedRules(unittest.TestCase):
    def test_pdf_chapter5_clean_component_no_affected_projects(self):
        """PDF 第五章：无漏洞组件不应显示影响项目。"""
        log4j = Component(
            group="org.apache.logging.log4j", name="log4j-core", version="2.14.0",
            language=Language.JAVA, dependency_type=DependencyType.DIRECT, direct=True,
            transitive=False,
            vulnerabilities=[Vulnerability(vuln_id="CVE-2021-44228", source=SourceType.NVD,
                                           severity=Severity.CRITICAL, title="Log4Shell",
                                           sources=["nvd"])])
        log4j.extra["affected_projects"] = ["app-one:1.0"]
        clean = Component(group="cglib", name="cglib", version="3.3.0",
                          language=Language.JAVA, dependency_type=DependencyType.DIRECT,
                          direct=True, transitive=False, vulnerabilities=[])
        clean.extra["affected_projects"] = ["COUS:1.0.0-beta", "wvmp-web-boot-starter:2.0.2-ccp1"]
        res = AnalysisResult(target="wl:demo:1.0", language=Language.JAVA,
                             components=[log4j, clean], sources_used=["nvd"])
        res.enrich_summary()
        pdf = render_pdf(res)
        text = _pdf_ascii_text(pdf)
        # 有漏洞组件的影响项目应出现在 PDF 中
        self.assertIn("app-one:1.0", text)
        # 无漏洞组件的影响项目不应出现
        self.assertNotIn("COUS", text)
        self.assertNotIn("wvmp-web-boot", text)

    def test_pdf_chapter5_low_severity_hides_affected_projects(self):
        """PDF 第五章：仅有低危漏洞的组件不应显示影响项目。"""
        low = Component(group="io.netty", name="netty-codec-http", version="4.1.135.Final",
                        language=Language.JAVA, dependency_type=DependencyType.DIRECT,
                        direct=True, transitive=False,
                        vulnerabilities=[Vulnerability(vuln_id="CVE-LOW", source=SourceType.NVD,
                                                       severity=Severity.LOW, title="l",
                                                       sources=["nvd"])])
        low.extra["affected_projects"] = ["wvmp-web-boot-starter:2.0.2-ccp1"]
        res = AnalysisResult(target="x", language=Language.JAVA,
                             components=[low], sources_used=["nvd"])
        res.enrich_summary()
        pdf = render_pdf(res)
        text = _pdf_ascii_text(pdf)
        self.assertNotIn("wvmp-web-boot", text)

    def test_pdf_chapter5_copyleft_shows_affected_projects(self):
        """PDF 第五章：传染型 License 组件（无漏洞）应显示影响项目。"""
        gpl = Component(group="com.sun.mail", name="jakarta.mail", version="2.0.1",
                        language=Language.JAVA, dependency_type=DependencyType.DIRECT,
                        direct=True, transitive=False, license="GPL-2.0",
                        vulnerabilities=[])
        gpl.extra["affected_projects"] = ["COUS:1.0.0-beta", "wvmp-web-boot-starter:2.0.2-ccp1"]
        res = AnalysisResult(target="x", language=Language.JAVA,
                             components=[gpl], sources_used=["nvd"])
        res.enrich_summary()
        pdf = render_pdf(res)
        text = _pdf_ascii_text(pdf)
        self.assertIn("COUS:1.0.0-beta", text)
        self.assertIn("wvmp-web-boot-starter:2.0.2-ccp1", text)


if __name__ == "__main__":
    unittest.main()
