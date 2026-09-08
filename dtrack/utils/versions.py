"""Best-effort Maven version comparison and range checking.

Maven versions are complex (qualifiers, snapshots, ranges). This implements a
*good-enough* comparator used only to decide whether a component version is
affected by a vulnerability range. When in doubt we err toward "affected" so the
tool never silently drops a real vulnerability (security tools should over-report,
not under-report).
"""
from __future__ import annotations

import re
from typing import Optional

_QUAL_ORDER = {
    "": 6, "ga": 6, "final": 6, "release": 6,
    "sp": 5,
    "snapshot": 4,
    "rc": 3, "cr": 3,
    "milestone": 2, "m": 2,
    "beta": 1, "b": 1,
    "alpha": 0, "a": 0,
}


def _tokenize(version: str):
    """Turn a version string into a comparable list of (kind, value) tokens.

    kind 0 == integer, kind 1 == qualifier string.
    """
    version = (version or "").strip().lower()
    tokens = []
    for part in re.split(r"[.\-]", version):
        if part == "":
            continue
        if part.isdigit():
            tokens.append((0, int(part)))
        else:
            # a token like "0cr1" -> split leading digits
            m = re.match(r"(\d+)(.*)$", part)
            if m and m.group(2) != "":
                tokens.append((0, int(m.group(1))))
                tokens.append((1, m.group(2)))
            else:
                tokens.append((1, part))
    return tokens


def maven_cmp(a: Optional[str], b: Optional[str]) -> int:
    ta, tb = _tokenize(a or ""), _tokenize(b or "")
    n = max(len(ta), len(tb))
    for i in range(n):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        # missing token == 0 / empty qualifier (which ranks highest)
        xk, xv = x if x else (0, 0)
        yk, yv = y if y else (0, 0)
        # numeric vs string: numeric always less than string? In maven, "1.0" < "1.0-alpha"? No:
        # Actually a version with a qualifier is LOWER than the same without. The token kind
        # difference is resolved by the qualifier order, but a bare number vs string: treat
        # number as (0, n) and string as (1, qual). During alignment, a missing token is (0,0)
        # which is the "release" baseline.
        if xk != yk:
            # both normalized to comparable kinds via order lists
            xr = _QUAL_ORDER.get(xv, 1) if xk == 1 else 6
            yr = _QUAL_ORDER.get(yv, 1) if yk == 1 else 6
            if xr != yr:
                return -1 if xr < yr else 1
            # kinds differ but same rank tier -> treat numeric as lower
            return -1 if xk < yk else 1
        if xk == 0:
            if xv != yv:
                return -1 if xv < yv else 1
        else:
            xr = _QUAL_ORDER.get(xv, 1)
            yr = _QUAL_ORDER.get(yv, 1)
            if xr != yr:
                return -1 if xr < yr else 1
    return 0


def maven_le(a: str, b: str) -> bool:
    return maven_cmp(a, b) <= 0


class Bounds:
    def __init__(self, start_incl=None, start_excl=None, end_incl=None, end_excl=None):
        self.start_incl = start_incl
        self.start_excl = start_excl
        self.end_incl = end_incl
        self.end_excl = end_excl

    def text(self) -> str:
        parts = []
        if self.start_incl is not None:
            parts.append(f">= {self.start_incl}")
        if self.start_excl is not None:
            parts.append(f"> {self.start_excl}")
        if self.end_incl is not None:
            parts.append(f"<= {self.end_incl}")
        if self.end_excl is not None:
            parts.append(f"< {self.end_excl}")
        return ", ".join(parts) if parts else ""


def parse_range_to_bounds(rng: str) -> Optional[Bounds]:
    """Parse GitHub-style range strings like '>= 1.0, < 2.0' or '[1.0,2.0)'."""
    rng = (rng or "").strip()
    if not rng:
        return None
    b = Bounds()
    # Maven style [a,b) / (a,b] / [a,b] / (a,b)
    m = re.match(r"^([\[(])\s*([0-9].*?)\s*,\s*([0-9].*?)\s*([\])])$", rng)
    if m:
        lo, hi = m.group(2), m.group(3)
        if m.group(1) == "[":
            b.start_incl = lo
        else:
            b.start_excl = lo
        if m.group(4) == "]":
            b.end_incl = hi
        else:
            b.end_excl = hi
        return b
    for clause in rng.split(","):
        clause = clause.strip()
        if not clause:
            continue
        cm = re.match(r"^(>=|<=|>|<)\s*([0-9][^\s]*)$", clause)
        if not cm:
            return None
        op, ver = cm.group(1), cm.group(2)
        if op == ">=":
            b.start_incl = ver
        elif op == ">":
            b.start_excl = ver
        elif op == "<=":
            b.end_incl = ver
        elif op == "<":
            b.end_excl = ver
    if b.start_incl is b.start_excl is b.end_incl is b.end_excl is None:
        return None
    return b


def is_affected(version: Optional[str], bounds: Optional[Bounds]) -> bool:
    """Return True if ``version`` is affected; False if definitely not; True when unknown."""
    if bounds is None or version is None:
        return True
    if bounds.start_incl is not None and maven_cmp(version, bounds.start_incl) < 0:
        return False
    if bounds.start_excl is not None and maven_cmp(version, bounds.start_excl) <= 0:
        return False
    if bounds.end_incl is not None and maven_cmp(version, bounds.end_incl) > 0:
        return False
    if bounds.end_excl is not None and maven_cmp(version, bounds.end_excl) >= 0:
        return False
    return True
