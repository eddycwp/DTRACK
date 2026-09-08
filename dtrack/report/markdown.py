"""Generate Markdown vulnerability analysis reports.

The report is intentionally structured data-first (distribution tables, per-component
detail, remediation summary) so it can later be rendered in a web UI or exported to
other formats from the same ``AnalysisResult``.
"""
from __future__ import annotations

import os
import re
from typing import Optional

from ..core.models import AnalysisResult, Component, Severity
from ..core.types import Language, Severity as Sev
from ..utils.license_normalize import normalize_license

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN]

# 漏洞源短名 -> 报告中展示的全称（需求13：github 显示为「Github Advisory」）
_SRC_LABELS = {
    "nvd": "NVD",
    "github": "Github Advisory",
    "qianxin": "奇安信开源卫士",
    "osv": "OSV",
    "manual": "手动录入",
}


def _esc(s: Optional[str]) -> str:
    """对 Markdown 表格单元格内容进行转义与规范化。"""
    if s is None:
        return ""
    s = str(s).replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    # 合并连续空白，避免单元格内出现额外换行或宽表格错位
    return re.sub(r"\s+", " ", s).strip()


def _sev_zh(s: Severity) -> str:
    return s.label_zh()


def _src_label(name: Optional[str]) -> str:
    if not name:
        return "未知"
    return _SRC_LABELS.get(name, name)


# 具有 copyleft（传染性）约束的开源许可证关键字（需求14）
_COPYLEFT_KEYWORDS = ("agpl", "gpl", "lgpl", "mpl", "epl", "cddl", "osl", "eupl", "cecill",
                      "mozilla public", "eclipse public", "common public")


def _is_copyleft(lic: Optional[str]) -> bool:
    """判断是否为具有传染性（copyleft）约束的开源许可证。"""
    if not lic:
        return False
    low = lic.lower()
    return any(k in low for k in _COPYLEFT_KEYWORDS)


def _should_show_affected(c: Component) -> bool:
    """判定组件是否应在第五章「影响项目」列展示内容。

    仅当组件存在中危及以上漏洞，或使用了传染型/不安全 License 时才展示；
    仅有低危/未知漏洞或无风险组件不展示。
    """
    has_mid_plus = bool(c.vulnerabilities and
                        any(v.severity.rank >= Severity.MEDIUM.rank for v in c.vulnerabilities))
    return has_mid_plus or _is_copyleft(c.license)


def render_markdown(result: AnalysisResult) -> str:
    s = result.summary or {}
    sev_counts = s.get("severity_counts", {})
    src_counts = s.get("source_counts", {})

    lines: list[str] = []
    lines.append("# 三方组件漏洞分析报告")
    lines.append("")
    lines.append("## 一、概览")
    lines.append("")
    lines.append(f"- **分析目标**：{_esc(result.target)}")
    lines.append(f"- **分析语言**：{result.language.value}")
    lines.append(f"- **生成时间**：{_esc(result.generated_at)}")
    srcs = ", ".join(_src_label(s) for s in result.sources_used) or "（无）"
    lines.append(f"- **使用的漏洞源**：{_esc(srcs)}")
    lines.append(f"- **组件总数**：{s.get('total_components', 0)}")
    lines.append(f"- **存在漏洞的组件数**：{s.get('components_with_vulns', 0)}")
    lines.append(f"- **漏洞总数**：{s.get('total_vulnerabilities', 0)}")
    lines.append(f"- **直接依赖 / 传递依赖**：{s.get('direct_deps', 0)} / {s.get('transitive_deps', 0)}")
    if result.language.value == "c/c++":
        dyn = sum(1 for c in result.components if c.lib_type == "dynamic")
        stat = sum(1 for c in result.components if c.lib_type == "static")
        lines.append(f"- **动态库 / 静态库**：{dyn} / {stat}")
    if result.notes:
        lines.append("")
        lines.append("**备注**：")
        for n in result.notes:
            lines.append(f"  - {_esc(n)}")
    lines.append("")

    # ---- distribution ----
    lines.append("## 二、漏洞分布")
    lines.append("")
    lines.append("### 2.1 按严重程度")
    lines.append("")
    lines.append("| 严重程度 | 数量 |")
    lines.append("| --- | ---: |")
    for sev in _SEV_ORDER:
        lines.append(f"| {_sev_zh(sev)} | {sev_counts.get(sev.value, 0)} |")
    lines.append("")

    lines.append("### 2.2 按漏洞来源")
    lines.append("")
    if src_counts:
        lines.append("| 来源 | 漏洞数 |")
        lines.append("| --- | ---: |")
        for k, v in sorted(src_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {_esc(_src_label(k))} | {v} |")
    else:
        lines.append("_（未从任何在线源获取到漏洞数据；请检查网络与配置）_")
    lines.append("")

    lines.append("### 2.3 依赖类型分布")
    lines.append("")
    lines.append("| 类型 | 组件数 |")
    lines.append("| --- | ---: |")
    lines.append(f"| 直接依赖 | {s.get('direct_deps', 0)} |")
    lines.append(f"| 传递依赖 | {s.get('transitive_deps', 0)} |")
    lines.append("")

    # 2.4 中危及以上安全漏洞影响的产品（组件）和版本清单汇总
    lines.append("### 2.4 中危及以上安全漏洞影响的产品和版本清单汇总")
    lines.append("")
    mid_comps = [c for c in result.components if c.vulnerabilities and
                 any(v.severity.rank >= Severity.MEDIUM.rank for v in c.vulnerabilities)]
    mid_comps.sort(key=lambda c: (c.worst_severity.rank * -1, c.coordinate))
    if not mid_comps:
        lines.append("_未检测到中危及以上安全漏洞。_")
        lines.append("")
    else:
        lines.append("_下表汇总存在中危及以上安全漏洞的组件（产品）及其版本，"
                     "并列出该组件影响的业务项目（项目名称:版本）。_")
        lines.append("")
        lines.append("| 产品（组件） | 版本 | 最高严重度 | 中危及以上漏洞数 | 影响项目 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for c in mid_comps:
            name_cell = (f"{c.group}:{c.name}") if c.group else c.name
            n_mid = sum(1 for v in c.vulnerabilities if v.severity.rank >= Severity.MEDIUM.rank)
            projs = c.extra.get("affected_projects") or []
            affected = "<br>".join(_esc(p) for p in projs) if projs else "—"
            lines.append(
                f"| {_esc(name_cell)} | {_esc(c.version) or '—'} | "
                f"{_sev_zh(c.worst_severity)} | {n_mid} | {affected} |"
            )
        lines.append("")

    # ---- license distribution (requirement #8 / #14) ----
    # 统一为独立章节「三、组件 License 分布」，并拆分为三个小节：
    #   3.1 许可证总体分布（License | 类型 | 组件数）
    #   3.2 传染型（Copyleft）许可证清单与开源义务说明
    #   3.3 未知/未识别 License 明细
    lic_counts = s.get("license_counts", {})
    unknown = sum(1 for c in result.components if not c.license)
    lines.append("## 三、组件 License 分布")
    lines.append("")

    # 3.1 总体分布
    lines.append("### 3.1 许可证总体分布")
    lines.append("")
    lines.append("| License | 类型 | 组件数 |")
    lines.append("| --- | --- | ---: |")
    if lic_counts:
        for lic, n in sorted(lic_counts.items(), key=lambda x: -x[1]):
            ltype = "传染型" if _is_copyleft(lic) else "宽松型"
            lines.append(f"| {_esc(lic)} | {ltype} | {n} |")
    else:
        lines.append("| （暂无 license 数据） | — | 0 |")
    if unknown:
        lines.append(f"| 未知/未识别 | 未知 | {unknown} |")
    lines.append("")

    # 3.2 传染型（Copyleft）许可证
    copyleft_items = [(lic, n) for lic, n in lic_counts.items() if _is_copyleft(lic)]
    lines.append("### 3.2 传染型（Copyleft）许可证")
    lines.append("")
    if copyleft_items:
        lines.append("_以下许可证具有 copyleft（传染性）约束（如 GPL/LGPL/AGPL/MPL/EPL 等），"
                     "使用或分发含此类组件的衍生作品时，需注意对应的开源义务（如源码公开）。_")
        lines.append("")
        lines.append("| License | 组件数 |")
        lines.append("| --- | ---: |")
        for lic, n in sorted(copyleft_items, key=lambda x: -x[1]):
            lines.append(f"| {_esc(lic)} | {n} |")
    else:
        lines.append("_未检测到具有传染性（copyleft）约束的开源许可证。_")
    lines.append("")

    # 3.3 未知/未识别 License 明细
    lines.append("### 3.3 未知/未识别 License 明细")
    lines.append("")
    if unknown:
        lines.append(f"_共 {unknown} 个组件未从清单/元数据中解析到 license（未知或无法识别）：_")
        lines.append("")
        for c in result.components:
            if not c.license:
                name_cell = (f"{c.group}:{c.name}") if c.group else c.name
                lines.append(f"- {_esc(name_cell)} （{_esc(c.version) or '—'}）")
    else:
        lines.append("_所有组件均已解析到 license。_")
    lines.append("")

    # ---- remediation summary ----
    lines.append("## 四、修复建议汇总")
    lines.append("")
    vuln_comps = [c for c in result.components if c.vulnerabilities]
    vuln_comps.sort(key=lambda c: (c.worst_severity.rank * -1, c.coordinate))
    fixable = [c for c in vuln_comps if c.worst_severity.rank >= Severity.HIGH.rank]
    # ---- full component inventory (requirement #11) ----
    # 始终基于全部组件生成「组件全集」，与是否存在需要优先修复的高危漏洞无关。
    all_comps = sorted(
        result.components,
        key=lambda c: (0 if c.vulnerabilities else 1, c.worst_severity.rank * -1, c.coordinate),
    )
    if not fixable:
        lines.append("_无高危/超危漏洞需要优先修复。_")
        lines.append("")
    else:
        lines.append("| 组件 | 依赖类型 | 最高严重度 | License | 修复建议 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for comp in fixable:
            suggestion = _best_fix(comp)
            dep_type = '直接' if comp.direct else '传递'
            lines.append(
                f"| {_esc(comp.coordinate)} | {dep_type} | {_sev_zh(comp.worst_severity)} | "
                f"{_esc(normalize_license(comp.license)) or '—'} | {_esc(suggestion)} |"
            )
        lines.append("")
    lines.append("## 五、组件全集")
    lines.append("")
    lines.append(
        f"_共 {len(all_comps)} 个组件。下表为全部组件汇总：有漏洞的组件在「漏洞分级」列按严重级别"
        f"逐行列出各级别漏洞数量，每一行均为链接，点击可跳转到第三章中该级别的第一个漏洞；"
        f"无漏洞组件标记为「无」。_"
    )
    lines.append("")
    has_lib = any(c.lib_type for c in all_comps)
    # 影响项目列：仅当至少有一个组件存在「中危及以上漏洞」或「传染型/不安全 License」
    # 时才展示该列；无此类风险场景下多出一列空值会造成表格冗余。
    show_affected = any(_should_show_affected(c) for c in all_comps)
    if has_lib:
        header = "| # | 组件 | 依赖类型 | 版本 | 类型 | License | 漏洞分级 |"
        if show_affected:
            header = "| # | 组件 | 依赖类型 | 版本 | 类型 | License | 漏洞分级 | 影响项目 |"
        sep = "| --- | --- | --- | --- | --- | --- | --- | --- |"
    else:
        header = "| # | 组件 | 依赖类型 | 版本 | License | 漏洞分级 |"
        if show_affected:
            header = "| # | 组件 | 依赖类型 | 版本 | License | 漏洞分级 | 影响项目 |"
        sep = "| --- | --- | --- | --- | --- | --- |"
    lines.append(header)
    lines.append(sep)
    detail_anchor = {id(c): f"comp-detail-{i}" for i, c in enumerate(vuln_comps)} or {}
    for idx, c in enumerate(all_comps, 1):
        name_cell = (f"{c.group}:{c.name}") if c.group else c.name
        ltype = ("动态" if c.lib_type == "dynamic" else "静态") if c.lib_type else "—"
        lic_cell = _esc(normalize_license(c.license)) or "—"
        if lic_cell != "—" and _is_copyleft(lic_cell):
            lic_cell = f"{lic_cell}（传染）"
        if c.vulnerabilities:
            counts = {sev.value: 0 for sev in _SEV_ORDER}
            for v in c.vulnerabilities:
                counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
            anchor = detail_anchor.get(id(c))
            rows = []
            for sev in _SEV_ORDER:
                n = counts.get(sev.value, 0)
                if not n:
                    continue
                if anchor:
                    rows.append(f"[{_sev_zh(sev)} {n}](#{anchor}-sev-{sev.value})")
                else:
                    rows.append(f"{_sev_zh(sev)} {n}")
            stats = "<br>".join(rows) if rows else "0"
        else:
            stats = "无"
        # 影响项目：仅对「存在中危及以上漏洞」或「传染型/不安全 License」的组件展示，
        # 每行一个（项目名称:版本）；不满足条件时固定填 —，避免低危/无风险组件
        # 也列出影响项目造成干扰。
        affected = "—"
        if _should_show_affected(c):
            projs = c.extra.get("affected_projects") or []
            affected = "<br>".join(_esc(p) for p in projs) if projs else "—"
        if has_lib:
            line = (
                f"| {idx} | {_esc(name_cell)} | {'直接' if c.direct else '传递'} "
                 f"| {_esc(c.version)} | {ltype} | {lic_cell} | {stats} |"
            )
            if show_affected:
                line += f" {affected} |"
        else:
            line = (
                f"| {idx} | {_esc(name_cell)} | {'直接' if c.direct else '传递'} "
                 f"| {_esc(c.version)} | {lic_cell} | {stats} |"
            )
            if show_affected:
                line += f" {affected} |"
        lines.append(line)
    lines.append("")

    lines.append("---")

    # ---- per component detail ----
    lines.append("## 六、组件漏洞明细")
    lines.append("")

    #detail_anchor: dict = {}
    if not vuln_comps:
        lines.append("_未检测到任何组件漏洞。_")
        lines.append("")
    else:
        #detail_anchor = {id(c): f"comp-detail-{i}" for i, c in enumerate(vuln_comps)}
        for comp in vuln_comps:
            _render_component(lines, comp, detail_anchor[id(comp)])

    lines.append(f"_由 DTrack 生成 · 漏洞数据来源：{_esc(srcs)} · 报告仅供安全加固参考_")
    lines.append("")
    return "\n".join(lines)


def _render_component(lines: list[str], comp: Component, anchor: Optional[str] = None) -> None:
    if anchor:
        lines.append(f'<a id="{anchor}"></a>')
    tag = "直接依赖" if comp.direct else "传递依赖"
    type_tag = ""
    if comp.lib_type:
        type_tag = " · " + ("动态库" if comp.lib_type == "dynamic" else "静态库")
    lines.append(f"### [{_sev_zh(comp.worst_severity)}] {_esc(comp.coordinate)} （{tag}{type_tag}）")
    lines.append("")
    if comp.license:
        lines.append(f"- **License**：{_esc(normalize_license(comp.license))}")
    if comp.lib_type:
        lines.append(f"- **库类型**：{'动态库 (dynamic)' if comp.lib_type == 'dynamic' else '静态库 (static)'}")
    if comp.vulnerabilities:
        lines.append(f"- **漏洞数**：{len(comp.vulnerabilities)}")
        lines.append("- **漏洞列表**：")
        emitted_sev = set()
        for v in comp.vulnerabilities:
            # 为「该严重级别出现的第一个漏洞」添加子锚点，供第五章分级数量链接跳转
            if anchor and v.severity.value not in emitted_sev:
                lines.append(f'<a id="{anchor}-sev-{v.severity.value}"></a>')
                emitted_sev.add(v.severity.value)
            srcs = ", ".join(_src_label(s) for s in v.sources) if v.sources else _src_label(v.source.value)
            cid = v.cve or v.vuln_id
            lines.append(f"  - **{_esc(cid)}** （{_sev_zh(v.severity)}）"
                         f" 来源：[{_esc(srcs)}] — {_esc(v.title)}")
            if v.vulnerable_range:
                lines.append(f"    - 影响版本：{_esc(v.vulnerable_range)}")
            # 每个漏洞都给出明确、可操作的修复建议；修复版本已包含在建议中，避免重复展示
            lines.append(f"    - **修复建议**：{_esc(_vuln_fix(comp, v))}")
            if v.description:
                # 先按原始文本截断再转义，避免边界处切掉 \| 等转义符
                desc = v.description
                if len(desc) > 300:
                    desc = desc[:300] + "…"
                lines.append(f"    - 描述：{_esc(desc)}")
            if v.references:
                refs = " ".join(f"<{_esc(r)}>" for r in v.references[:3])
                lines.append(f"    - 参考：{refs}")
    if comp.extra.get("tree_path") and comp.extra["tree_path"] != "(root)":
        lines.append(f"- **依赖路径**：`{_esc(comp.extra['tree_path'])}`")
    lines.append("")


def _vuln_fix(comp: Component, v) -> str:
    """为单个漏洞生成明确、可操作的修复建议。"""
    if v.fixed_version:
        if comp.version and v.fixed_version != comp.version:
            return f"将 {comp.name} 从 {comp.version} 升级到 {v.fixed_version} 版本"
        return f"升级到 {v.fixed_version} 版本"
    if v.solution:
        return v.solution
    return (
        f"暂无明确修复版本，建议将 {comp.name} 升级到官方发布的最新安全版本，"
        f"并关注厂商安全公告"
    )


def _version_key(v: str):
    """简易版本号排序键：数字段按整数比，非数字段按字符串比。"""
    return [int(p) if p.isdigit() else p for p in re.split(r"[.\-_]+", v)]


def _best_fix(comp: Component, max_len: int = 120) -> str:
    """为组件生成一句最优先的修复建议；过长时截断，避免汇总表格列过宽。"""
    fixed = [v.fixed_version for v in comp.vulnerabilities if v.fixed_version]
    if fixed:
        best = sorted(fixed, key=_version_key)[-1]
        return f"升级 {comp.name} 至 {best}"
    sol = next((v.solution for v in comp.vulnerabilities if v.solution), None)
    if sol:
        # 注意：这里返回原始文本，转义由调用方（markdown/pdf 渲染）各自完成，
        # 避免双重转义导致 | 等字符变成 \\|。
        if len(sol) > max_len:
            sol = sol[:max_len].rstrip() + "…"
        return sol
    # 组件漏洞明细已调整为最后章节（第六章），引用需同步
    return "详见第六章「组件漏洞明细」各漏洞修复建议"


def write_report(result: AnalysisResult, out_dir: str, filename: Optional[str] = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    if not filename:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", result.target).strip("_")
        filename = f"dtrack_report_{safe}.md"
    path = os.path.join(out_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(result))
    return path
