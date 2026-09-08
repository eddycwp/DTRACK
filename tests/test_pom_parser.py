import os
import unittest

from dtrack.analyzers.java.pom_parser import parse_pom_file

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "sample-java", "pom.xml")


class TestPomParser(unittest.TestCase):
    def test_parse_direct_and_managed(self):
        pom = parse_pom_file(SAMPLE)
        direct = {(d.group, d.artifact) for d in pom.direct_deps}
        self.assertIn(("org.apache.logging.log4j", "log4j-core"), direct)
        self.assertIn(("commons-collections", "commons-collections"), direct)
        self.assertIn(("org.springframework", "spring-core"), direct)

        managed = {(d.group, d.artifact) for d in pom.managed_deps}
        self.assertIn(("junit", "junit"), managed)
        self.assertEqual(pom.version, "1.0.0")
        self.assertEqual(pom.group_id, "com.example")


if __name__ == "__main__":
    unittest.main()
