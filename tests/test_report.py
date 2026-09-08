import unittest

from dtrack.config import Config, DEFAULT_CONFIG
from dtrack.core.models import AnalysisResult, Component, Vulnerability
from dtrack.core.types import DependencyType, Language, Severity, SourceType
from dtrack.report import render_markdown
from dtrack.vuln.aggregator import VulnerabilityAggregator
from dtrack.vuln.base import VulnerabilitySource


class FakeNVD(VulnerabilitySource):
    name = "nvd"
    source_type = SourceType.NVD

    def enabled(self):
        return True

    def query(self, component):
        return [Vulnerability(vuln_id="CVE-2021-44228", source=SourceType.NVD,
                              severity=Severity.CRITICAL, cve="CVE-2021-44228",
                              title="Log4Shell")]


class FakeGH(VulnerabilitySource):
    name = "github"
    source_type = SourceType.GITHUB

    def enabled(self):
        return True

    def query(self, component):
        return [Vulnerability(vuln_id="CVE-2021-44228", source=SourceType.GITHUB,
                              severity=Severity.HIGH, cve="CVE-2021-44228",
                              fixed_version="2.17.1", solution="升级到 2.17.1")]


class TestAggregator(unittest.TestCase):
    def test_merge_same_cve(self):
        cfg = Config(DEFAULT_CONFIG)
        agg = VulnerabilityAggregator(cfg, sources=[FakeNVD(cfg), FakeGH(cfg)])
        comp = Component(group="g", name="a", version="1.0", language=Language.JAVA)
        vs = agg.analyze_component(comp)
        self.assertEqual(len(vs), 1)
        self.assertEqual(vs[0].severity, Severity.CRITICAL)  # higher severity wins
        self.assertIn("nvd", vs[0].sources)
        self.assertIn("github", vs[0].sources)
        self.assertEqual(vs[0].fixed_version, "2.17.1")


class TestReport(unittest.TestCase):
    def _result(self) -> AnalysisResult:
        comp = Component(
            group="org.apache.logging.log4j", name="log4j-core", version="2.14.0",
            language=Language.JAVA, dependency_type=DependencyType.DIRECT, direct=True,
            transitive=False,
            vulnerabilities=[Vulnerability(
                vuln_id="CVE-2021-44228", source=SourceType.NVD, severity=Severity.CRITICAL,
                title="Log4Shell", solution="升级到 2.17.1", sources=["nvd", "github"],
                description="远程代码执行漏洞", references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            )],
        )
        clean = Component(group="org.springframework", name="spring-core", version="5.3.3",
                          language=Language.JAVA, dependency_type=DependencyType.DIRECT, direct=True,
                          transitive=False, vulnerabilities=[])
        res = AnalysisResult(target="demo-app", language=Language.JAVA,
                             components=[comp, clean], sources_used=["nvd", "github"])
        res.enrich_summary()
        return res

    def test_render(self):
        md = render_markdown(self._result())
        self.assertIn("# 三方组件漏洞分析报告", md)
        self.assertIn("CVE-2021-44228", md)
        self.assertIn("Log4Shell", md)
        self.assertIn("修复建议", md)
        self.assertIn("组件漏洞明细", md)
        self.assertIn("组件全集", md)
        # 需求11：第五章为组件全集，漏洞分级按级别逐行显示，且每行数量为指向该级别第一个漏洞的链接
        self.assertIn("[超危/严重 1](#comp-detail-0-sev-critical)", md)
        # 第三章为每级第一个漏洞设置子锚点
        self.assertIn('<a id="comp-detail-0-sev-critical"></a>', md)

    def test_copyleft_marking(self):
        """需求14：传染型（copyleft）许可证在 §3.1 类型列与第五章 license 列做出标识。"""
        gpl = Component(group="g", name="copyleft-lib", version="1.0", language=Language.JAVA,
                        direct=True, license="GPL-3.0", vulnerabilities=[])
        mit = Component(group="g", name="permissive-lib", version="2.0", language=Language.JAVA,
                        direct=True, license="MIT", vulnerabilities=[])
        unknown = Component(group="g", name="no-lic", version="3.0", language=Language.JAVA,
                            direct=True, vulnerabilities=[])
        res = AnalysisResult(target="t", language=Language.JAVA,
                             components=[gpl, mit, unknown], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        # §3.1 类型列：传染型 / 宽松型
        self.assertIn("| License | 类型 | 组件数 |", md)
        self.assertIn("| GPL-3.0 | 传染型 | 1 |", md)
        self.assertIn("| MIT | 宽松型 | 1 |", md)
        # 第三章拆分为三个小节
        self.assertIn("### 3.1 许可证总体分布", md)
        self.assertIn("### 3.2 传染型（Copyleft）许可证", md)
        self.assertIn("### 3.3 未知/未识别 License 明细", md)
        # 第五章 license 列追加（传染）标记
        self.assertIn("GPL-3.0（传染）", md)
        self.assertIn("未知/未识别 | 未知", md)

    def test_remediation_table_long_solution_truncated(self):
        """修复建议汇总表对过长 solution 进行截断，避免表格列过宽/格式混乱。"""
        long_solution = "升级到 2.17.1" + "，务必注意" * 50  # 生成很长一段文本
        comp = Component(
            group="org.apache.logging.log4j", name="log4j-core", version="2.14.0",
            language=Language.JAVA, dependency_type=DependencyType.DIRECT, direct=True,
            vulnerabilities=[Vulnerability(
                vuln_id="CVE-2021-44228", source=SourceType.NVD, severity=Severity.CRITICAL,
                title="Log4Shell", solution=long_solution,
            )],
        )
        res = AnalysisResult(target="t", language=Language.JAVA,
                             components=[comp], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        # 仅检查「四、修复建议汇总」章节；明细章节保留完整文本
        section_start = md.find("## 四、修复建议汇总")
        section_end = md.find("## 五、")
        self.assertGreater(section_start, -1)
        section = md[section_start:section_end]
        # 汇总表格中不应出现未截断的原始长文本
        self.assertNotIn(long_solution, section)
        # 截断后以省略号结尾
        self.assertIn("…", section)
        # 表格结构保持完整
        self.assertIn("| 组件 | 依赖类型 | 最高严重度 | License | 修复建议 |", section)

    def test_remediation_table_escapes_pipe_and_newline(self):
        """修复建议中的 | 和换行必须被转义，不能破坏 Markdown 表格。"""
        bad_solution = "建议升级到 2.0.0|2.1.0\n或回退到 1.x"
        comp = Component(
            group="g", name="bad-sol", version="1.0", language=Language.JAVA,
            dependency_type=DependencyType.DIRECT, direct=True,
            vulnerabilities=[Vulnerability(
                vuln_id="CVE-2021-99999", source=SourceType.NVD, severity=Severity.HIGH,
                title="Bad", solution=bad_solution,
            )],
        )
        res = AnalysisResult(target="t", language=Language.JAVA,
                             components=[comp], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        # 原始 | 与 \n 不应出现在最终 markdown 中
        self.assertNotIn("升级到 2.0.0|2.1.0\n", md)
        self.assertNotIn("升级到 2.0.0|2.1.0", md)
        # 应被替换为空格并转义管道符
        self.assertIn("升级到 2.0.0\\|2.1.0 或回退到 1.x", md)

    def test_remediation_table_fallback_refers_chapter_six(self):
        """无 fixed_version 且无 solution 时，汇总表应引用第六章。"""
        comp = Component(
            group="g", name="no-fix", version="1.0", language=Language.JAVA,
            dependency_type=DependencyType.DIRECT, direct=True,
            vulnerabilities=[Vulnerability(
                vuln_id="CVE-2021-00000", source=SourceType.NVD, severity=Severity.HIGH,
                title="No fix",
            )],
        )
        res = AnalysisResult(target="t", language=Language.JAVA,
                             components=[comp], sources_used=["nvd"])
        res.enrich_summary()
        md = render_markdown(res)
        self.assertIn("详见第六章「组件漏洞明细」各漏洞修复建议", md)


if __name__ == "__main__":
    unittest.main()
