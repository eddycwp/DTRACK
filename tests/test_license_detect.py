"""Tests for best-effort license detection."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dtrack.utils.license_detect import (  # noqa: E402
    detect_license_file,
    detect_license_text,
    find_license_file,
)


class TestLicenseDetect(unittest.TestCase):
    def test_apache(self):
        self.assertEqual(detect_license_text("Apache License, Version 2.0 ..."), "Apache-2.0")

    def test_mit(self):
        self.assertEqual(detect_license_text("MIT License\nCopyright ..."), "MIT")

    def test_gpl(self):
        self.assertEqual(detect_license_text("GNU General Public License v3"), "GPL")

    def test_unknown(self):
        self.assertIsNone(detect_license_text("proprietary, all rights reserved"))

    def test_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "LICENSE")
            with open(p, "w", encoding="utf-8") as f:
                f.write("ISC License\n\nPermission to use...")
            self.assertEqual(detect_license_file(p), "ISC")
            # find_license_file walks up from a subdir
            sub = os.path.join(d, "src")
            os.makedirs(sub)
            self.assertEqual(find_license_file(sub), p)


if __name__ == "__main__":
    unittest.main()
