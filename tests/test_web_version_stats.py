"""Tests for per-version vulnerability statistics in the web layer.

Covers store.version_stats (severity breakdown + component counts) and that
the list / detail endpoints are enriched with ``stats``.
"""
import copy
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dtrack.config import Config, DEFAULT_CONFIG
from dtrack.web.service import WebService
from dtrack.web.store import Db


class TestWebVersionStats(unittest.TestCase):
    def setUp(self):
        self.db = Db(os.path.join(tempfile.mkdtemp(), "t.db"))
        self.svc = WebService(self.db, os.path.join(tempfile.mkdtemp(), "dtrack.toml"))
        self.svc.config = Config(copy.deepcopy(DEFAULT_CONFIG))

    def tearDown(self):
        self.db.close()

    def _seed(self):
        wid = self.db.upsert_whitelist("com.demo", "demo", "com.demo:demo")
        vid = self.db.add_whitelist_version(wid, "1.0", "pom", None, "<pom/>")
        c1 = self.db.upsert_component("org.x", "a", "1.0", "java", "MIT", is_whitelist=True)
        c2 = self.db.upsert_component("org.x", "b", "2.0", "java", "Apache-2.0", is_whitelist=True)
        self.db.add_usage(c1, "whitelist", vid, "direct")
        self.db.add_usage(c2, "whitelist", vid, "transitive")
        self.db.add_vulnerability(c1, {"vuln_key": "K1", "vuln_id": "CVE-1",
                                       "source": "qianxin", "title": "t",
                                       "severity": "critical", "description": "d"})
        self.db.add_vulnerability(c1, {"vuln_key": "K2", "vuln_id": "CVE-2",
                                       "source": "qianxin", "title": "t",
                                       "severity": "high", "description": "d"})
        self.db.add_vulnerability(c2, {"vuln_key": "K3", "vuln_id": "CVE-3",
                                       "source": "qianxin", "title": "t",
                                       "severity": "medium", "description": "d"})
        return wid, vid

    def test_version_stats(self):
        wid, vid = self._seed()
        stats = self.db.version_stats("whitelist", vid)
        self.assertEqual(stats["component_count"], 2)
        self.assertEqual(stats["direct_count"], 1)
        self.assertEqual(stats["transitive_count"], 1)
        self.assertEqual(stats["vuln_counts"]["critical"], 1)
        self.assertEqual(stats["vuln_counts"]["high"], 1)
        self.assertEqual(stats["vuln_counts"]["medium"], 1)
        self.assertEqual(stats["vuln_total"], 3)

    def test_list_versions_enriched(self):
        wid, vid = self._seed()
        rows = self.db.list_versions("whitelist", wid)
        self.assertEqual(len(rows), 1)
        self.assertIn("stats", rows[0])
        self.assertEqual(rows[0]["stats"]["vuln_total"], 3)

    def test_get_version_enriched(self):
        wid, vid = self._seed()
        row = self.svc.get_version("whitelist", vid)
        self.assertIn("stats", row)
        self.assertEqual(row["stats"]["vuln_total"], 3)


if __name__ == "__main__":
    unittest.main()
