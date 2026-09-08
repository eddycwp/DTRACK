"""Lightweight SPDX license detection from LICENSE file text.

This is intentionally heuristic: it scans a LICENSE/COPYING file for well-known
license names and returns the most likely SPDX identifier. It is used as a
best-effort fallback for C/C++ projects (and anywhere a pom/metadata license is
unavailable). ``None`` means "could not determine".
"""
from __future__ import annotations

import os
from typing import Optional

# Ordered most-specific first; the first keyword found wins.
_SPDX_HINTS: list[tuple[str, str]] = [
    ("Apache License, Version 2.0", "Apache-2.0"),
    ("Apache License Version 2.0", "Apache-2.0"),
    ("Apache License", "Apache-2.0"),
    ("Apache-2.0", "Apache-2.0"),
    ("MIT License", "MIT"),
    ("MIT licence", "MIT"),
    ("ISC License", "ISC"),
    ("BSD-3-Clause", "BSD-3-Clause"),
    ("BSD-2-Clause", "BSD-2-Clause"),
    ("BSD License", "BSD"),
    ("Mozilla Public License", "MPL-2.0"),
    ("GNU Lesser General Public License", "LGPL"),
    ("GNU General Public License", "GPL"),
    ("GNU LESSER GENERAL PUBLIC", "LGPL"),
    ("GNU GENERAL PUBLIC", "GPL"),
    ("MIT", "MIT"),
    ("ISC", "ISC"),
]


def detect_license_text(text: str) -> Optional[str]:
    if not text:
        return None
    low = text.lower()
    for hint, spdx in _SPDX_HINTS:
        if hint.lower() in low:
            return spdx
    return None


def find_license_file(directory: str, max_depth: int = 3) -> Optional[str]:
    """Search ``directory`` and up to ``max_depth`` parent dirs for a LICENSE/COPYING file."""
    cur = os.path.abspath(directory)
    for _ in range(max_depth + 1):
        for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt"):
            p = os.path.join(cur, name)
            if os.path.isfile(p):
                return p
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return None


def detect_license_file(path: str, max_chars: int = 12000) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return detect_license_text(f.read(max_chars))
    except Exception:  # noqa: BLE001
        return None


def detect_license_near(path: str, max_depth: int = 3) -> Optional[str]:
    """Find and detect a LICENSE file near ``path`` (a file or directory)."""
    base = path if os.path.isdir(path) else os.path.dirname(path)
    lic_file = find_license_file(base, max_depth=max_depth)
    if lic_file:
        return detect_license_file(lic_file)
    return None
