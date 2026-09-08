"""Offline tests for the OSV source parsing logic."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dtrack.core.models import Component  # noqa: E402
from dtrack.core.types import Language, SourceType  # noqa: E402
from dtrack.vuln.osv import OsvSource  # noqa: E402


class _FakeConfig:
    def get(self, key, default=None):
        if key == "vuln.osv.cc_ecosystem":
            return "generic"
        if key == "general.timeout":
            return 30
        return default


class TestOsv(unittest.TestCase):
    def setUp(self):
        self.src = OsvSource(_FakeConfig())

    def test_package_mapping_java(self):
        c = Component(group="org.apache.logging.log4j", name="log4j-core",
                      version="2.14.0", language=Language.JAVA)
        self.assertEqual(self.src._package(c), {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"})

    def test_package_mapping_cc(self):
        c = Component(group=None, name="openssl", version="1.1.1", language=Language.CC)
        self.assertEqual(self.src._package(c), {"ecosystem": "generic", "name": "openssl"})

    def test_parse_ranges(self):
        affected = [{
            "package": {"ecosystem": "Maven", "name": "g:a"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "2.0.0"}, {"fixed": "2.15.0"}]}],
        }]
        text, fixed = OsvSource._parse_osv_ranges(affected)
        self.assertIn(">=2.0.0", text)
        self.assertIn("<2.15.0", text)
        self.assertEqual(fixed, "2.15.0")

    def test_severity_from_cvss(self):
        v = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        self.assertEqual(OsvSource._sev_from_vuln(v), __import__("dtrack.core.types", fromlist=["Severity"]).Severity.CRITICAL)

    def test_convert_builds_vuln(self):
        c = Component(group="g", name="a", version="2.14.0", language=Language.JAVA)
        raw = {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "aliases": ["CVE-2021-44228"],
            "summary": "Remote code execution",
            "details": "Log4Shell",
            "severity": [{"type": "CVSS_V3", "score": "10.0"}],
            "affected": [{"package": {"ecosystem": "Maven", "name": "g:a"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [
                              {"introduced": "2.0"}, {"fixed": "2.15.0"}]}]}],
            "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
            "published": "2021-12-10",
        }
        vuln = self.src._convert(raw, c)
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.cve, "CVE-2021-44228")
        self.assertEqual(vuln.source, SourceType.OSV)
        self.assertEqual(vuln.fixed_version, "2.15.0")
        self.assertIn("https://example.com/advisory", vuln.references)


if __name__ == "__main__":
    unittest.main()
