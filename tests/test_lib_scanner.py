"""Tests for C/C++ library binary scanning."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dtrack.analyzers.cc.lib_scanner import classify, scan_libraries  # noqa: E402


class TestLibScanner(unittest.TestCase):
    def test_dynamic_unix(self):
        lib = classify("libpng.so.16.0.0")
        self.assertIsNotNone(lib)
        self.assertEqual(lib.name, "png")
        self.assertEqual(lib.version, "16.0.0")
        self.assertEqual(lib.lib_type, "dynamic")

        lib = classify("libz.so.1")
        self.assertEqual(lib.name, "z")
        self.assertEqual(lib.version, "1")
        self.assertEqual(lib.lib_type, "dynamic")

    def test_static_unix(self):
        lib = classify("libssl.a")
        self.assertEqual(lib.name, "ssl")
        self.assertIsNone(lib.version)
        self.assertEqual(lib.lib_type, "static")

    def test_dynamic_win(self):
        lib = classify("zlib.dll")
        self.assertEqual(lib.name, "zlib")
        self.assertIsNone(lib.version)
        self.assertEqual(lib.lib_type, "dynamic")

        lib = classify("libfoo-1.2.dll")
        self.assertEqual(lib.name, "foo")
        self.assertEqual(lib.version, "1.2")
        self.assertEqual(lib.lib_type, "dynamic")

    def test_static_win(self):
        lib = classify("boost_system.lib")
        self.assertEqual(lib.name, "boost_system")
        self.assertEqual(lib.lib_type, "static")

    def test_non_library(self):
        self.assertIsNone(classify("main.cpp"))
        self.assertIsNone(classify("README.md"))

    def test_scan_tree(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "lib"))
            os.makedirs(os.path.join(d, "build"))
            open(os.path.join(d, "lib", "libpng.so.1.6.0"), "w").close()
            open(os.path.join(d, "build", "libleak.so.1"), "w").close()  # should be skipped
            open(os.path.join(d, "lib", "libssl.a"), "w").close()
            libs = scan_libraries(d)
            names = {l.name for l in libs}
            self.assertIn("png", names)
            self.assertIn("ssl", names)
            self.assertNotIn("leak", names)


if __name__ == "__main__":
    unittest.main()
