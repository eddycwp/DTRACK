"""License 归一化与报表合并的单元测试。"""
import unittest

from dtrack.core.models import AnalysisResult, Component
from dtrack.core.types import Language, Severity, SourceType
from dtrack.report import render_markdown
from dtrack.utils.license_normalize import normalize_license


class TestNormalizeLicense(unittest.TestCase):
    def test_apache_variants_all_map_to_same_id(self):
        """用户给出的 Apache 各种写法应统一为 Apache-2.0。"""
        variants = [
            "Apache License, Version 2.0",
            "Apache-2.0",
            "The Apache Software License, Version 2.0",
            "The Apache License, Version 2.0",
            "Apache 2",
            "Apache 2.0",
            "Apache License 2.0",
            "The Apache Software License, Version 2.0",
            "The Apahce License, Version 2.0",  # 拼写错误也需识别
            "apache-2.0",
        ]
        for v in variants:
            with self.subTest(v=v):
                self.assertEqual(normalize_license(v), "Apache-2.0")

    def test_common_licenses(self):
        cases = {
            "MIT": "MIT",
            "The MIT License": "MIT",
            "BSD 3-Clause License": "BSD-3-Clause",
            "BSD-3-Clause": "BSD-3-Clause",
            "New BSD License": "BSD-3-Clause",
            "Simplified BSD License": "BSD-2-Clause",
            "BSD-2-Clause": "BSD-2-Clause",
            "GPL-3.0": "GPL-3.0",
            "GNU General Public License v3": "GPL-3.0",
            "GPLv2": "GPL-2.0",
            "GNU Lesser General Public License 2.1": "LGPL-2.1",
            "LGPL-3.0": "LGPL-3.0",
            "AGPL-3.0": "AGPL-3.0",
            "GNU Affero General Public License v3": "AGPL-3.0",
            "MPL-2.0": "MPL-2.0",
            "Mozilla Public License 2.0": "MPL-2.0",
            "EPL-2.0": "EPL-2.0",
            "Eclipse Public License 2.0": "EPL-2.0",
            "ISC": "ISC",
            "CDDL-1.0": "CDDL-1.0",
            "CC0-1.0": "CC0-1.0",
            "Zlib": "Zlib",
            "The Unlicense": "Unlicense",
            "WTFPL": "WTFPL",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_license(raw), expected)

    def test_multiple_licenses_split_dedupe_and_sort(self):
        """多许可证应拆分、归一化、去重并按字典序稳定拼接。"""
        self.assertEqual(
            normalize_license("Apache License 2.0; The MIT License"),
            "Apache-2.0; MIT",
        )
        self.assertEqual(
            normalize_license("MIT; Apache License, Version 2.0; MIT"),
            "Apache-2.0; MIT",
        )

    def test_unknown_license_kept_as_is(self):
        self.assertEqual(normalize_license("Proprietary"), "Proprietary")
        self.assertEqual(normalize_license("商业许可证"), "商业许可证")
        self.assertEqual(normalize_license("  "), "  ")  # 空白原样保留

    def test_empty_and_none(self):
        self.assertIsNone(normalize_license(None))
        self.assertEqual(normalize_license(""), "")


class TestReportMerge(unittest.TestCase):
    def _result(self):
        """两个组件：Apache License 的不同写法，应合并计数并统一展示。"""
        comps = [
            Component(group="g", name="a", version="1.0", language=Language.JAVA,
                      direct=True, license="Apache License, Version 2.0",
                      vulnerabilities=[self._vuln("CVE-1")]),
            Component(group="g", name="b", version="1.0", language=Language.JAVA,
                      direct=True, license="Apache-2.0",
                      vulnerabilities=[self._vuln("CVE-2")]),
            Component(group="g", name="c", version="1.0", language=Language.JAVA,
                      direct=True, license="The MIT License"),
        ]
        res = AnalysisResult(target="t", language=Language.JAVA, components=comps)
        res.enrich_summary()
        return res

    @staticmethod
    def _vuln(cid):
        from dtrack.core.models import Vulnerability
        return Vulnerability(vuln_id=cid, source=SourceType.NVD, severity=Severity.HIGH)

    def test_license_counts_merged(self):
        res = self._result()
        counts = res.summary["license_counts"]
        self.assertEqual(counts.get("Apache-2.0"), 2)  # 两种写法合并为 2
        self.assertEqual(counts.get("MIT"), 1)
        self.assertNotIn("Apache License, Version 2.0", counts)

    def test_markdown_shows_unified_name(self):
        md = render_markdown(self._result())
        # 分布表：Apache-2.0 组件数为 2，且不再出现原始长写法
        self.assertIn("| Apache-2.0 | 宽松型 | 2 |", md)
        self.assertNotIn("Apache License, Version 2.0", md)
        self.assertNotIn("The Apache License", md)
        # 组件全集 License 列统一为 Apache-2.0
        self.assertIn("g:a", md)
        self.assertIn("g:b", md)
        # MIT 保持原名
        self.assertIn("| MIT | 宽松型 | 1 |", md)


if __name__ == "__main__":
    unittest.main()
