"""License 名称归一化。

不同项目对同一许可证的拼写常有差异，例如：
    "Apache License, Version 2.0" / "Apache-2.0" /
    "The Apache Software License, Version 2.0" / "Apache 2"
实际都应视为同一个许可证。本模块将这些变体映射为规范的 SPDX 标识，
使报表能够统一描述，并在按许可证统计时合并计数。
"""
from __future__ import annotations

import re
from typing import Optional

# 匹配规则：按顺序匹配，命中即返回规范名。
# 匹配对象为归一化后的小写文本（标点已折叠为空格/连字符）。
_RULES: list[tuple[re.Pattern, str]] = []


def _add(pattern: str, canonical: str) -> None:
    _RULES.append((re.compile(pattern), canonical))


# ---- Apache（容忍 "Apahce" 拼写错误；无版本时默认 2.0）----
_add(r"apache|apahce", "Apache-2.0")

# ---- MIT / ISC（词边界，避免误伤 commit/admit 等）----
_add(r"\bmit\b", "MIT")
_add(r"\bisc\b", "ISC")

# ---- BSD（3 版先于 2 版）----
_add(r"new bsd|bsd.{0,30}3-clause|bsd.{0,30}3", "BSD-3-Clause")
_add(r"simplified bsd|bsd.{0,30}2-clause|bsd.{0,30}2", "BSD-2-Clause")
_add(r"\bbsd\b", "BSD-3-Clause")

# ---- AGPL / LGPL / GPL（顺序：AGPL/LGPL 先于 GPL，版本具体先于通用）----
_add(r"gnu affero.{0,40}3|agpl.{0,30}3", "AGPL-3.0")
_add(r"gnu affero|\bagpl\b", "AGPL-3.0")
_add(r"gnu lesser.{0,40}2\s*\.?\s*1|lgpl.{0,30}2\s*\.?\s*1", "LGPL-2.1")
_add(r"gnu lesser.{0,40}3|lgpl.{0,30}3", "LGPL-3.0")
_add(r"gnu lesser.{0,40}2|lgpl.{0,30}2", "LGPL-2.0")
_add(r"gnu lesser|\blgpl\b", "LGPL")
_add(r"gnu general public.{0,60}3|gpl.{0,30}3", "GPL-3.0")
_add(r"gnu general public.{0,60}2|gpl.{0,30}2", "GPL-2.0")
_add(r"gnu general public|\bgpl\b", "GPL")

# ---- MPL / EPL ----
_add(r"mozilla public.{0,40}2|mpl.{0,20}2", "MPL-2.0")
_add(r"mozilla public|\bmpl\b", "MPL-2.0")
_add(r"eclipse public.{0,40}2|epl.{0,20}2", "EPL-2.0")
_add(r"eclipse public|\bepl\b", "EPL-2.0")

# ---- CDDL / CC0 / CC-BY / Zlib / Unlicense / WTFPL ----
_add(r"cddl", "CDDL-1.0")
_add(r"cc0", "CC0-1.0")
_add(r"cc by.{0,20}4|creative commons.{0,50}by.{0,30}4", "CC-BY-4.0")
_add(r"cc by|creative commons", "CC-BY-4.0")
_add(r"\bzlib\b", "Zlib")
_add(r"unlicense", "Unlicense")
_add(r"wtfpl", "WTFPL")


def _normalize_text(text: str) -> str:
    """折叠标点并转小写，便于规则匹配。"""
    t = text.lower()
    t = re.sub(r"[,.\"'`\u201c\u201d()/+\\]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def _normalize_one(part: str) -> str:
    t = _normalize_text(part)
    if not t:
        return part.strip()
    for pattern, canonical in _RULES:
        if pattern.search(t):
            return canonical
    return part.strip()


def normalize_license(name: Optional[str]) -> Optional[str]:
    """返回 ``name`` 的规范 SPDX 名称；无法识别时返回原始名称（去空白）。

    支持以 ``;`` / ``、`` 分隔的多个许可证：逐段归一化、去重并按字典序
    稳定排序后再以 ``; `` 拼接，保证同一组许可证的统计 key 一致。
    """
    if not name:
        return name
    parts = re.split(r"[;、；]", name)
    seen: set[str] = set()
    out: list[str] = []
    for part in parts:
        canon = _normalize_one(part)
        if canon and canon not in seen:
            seen.add(canon)
            out.append(canon)
    if not out:
        return name
    out.sort()
    return "; ".join(out)
