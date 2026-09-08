"""Render vulnerability analysis reports to PDF (optional, via reportlab).

reportlab 是可选依赖：离线部署的核心（纯标准库）不受影响；仅当需要
「导出 PDF 报表」时，预先在联网环境执行 ``pip install reportlab`` 即可。
中文使用 reportlab 内置的 Adobe CID 字体 STSong-Light，无需附带字体文件。
"""
from __future__ import annotations

from io import BytesIO
from typing import Optional
from xml.sax.saxutils import escape as _xml_escape

from ..core.models import AnalysisResult, Component
from ..core.types import Severity
from ..utils.license_normalize import normalize_license
from .markdown import (_SEV_ORDER, _best_fix, _esc, _is_copyleft, _sev_zh,
                       _should_show_affected, _src_label, _vuln_fix)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)
    _REPORTLAB_OK = True
except ImportError:  # pragma: no cover - depends on env
    _REPORTLAB_OK = False

_FONT = "STSong-Light"
_FONT_READY = False

_HEAD = "#1f4e79"       # 深蓝：主标题/表头
_ACCENT = "#2d6da3"     # 蓝：小节标题
_DANGER = "#b03a2e"     # 红：CVE / 严重级别
_GRAY = "#888888"

_USABLE = 504  # A4 宽 595pt - 左右边距(16mm*2≈91pt) 后的可用宽度


def _ensure_font() -> None:
    global _FONT_READY
    if _FONT_READY:
        return
    if not _REPORTLAB_OK:
        raise RuntimeError("PDF 导出需要安装 reportlab：pip install reportlab")
    pdfmetrics.registerFont(UnicodeCIDFont(_FONT))
    _FONT_READY = True


def _p(s: Optional[str]) -> str:
    """对报表文本做 HTML/PDF 段落安全转义（在 markdown _esc 基础上补 <>&）。"""
    return _xml_escape(_esc(s))


def _grid(header: bool = True) -> TableStyle:
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_HEAD)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ]
    return TableStyle(style)


def render_pdf(result: AnalysisResult) -> bytes:
    """将分析结果渲染为 PDF 字节流。"""
    _ensure_font()

    s = result.summary or {}
    sev_counts = s.get("severity_counts", {})
    src_counts = s.get("source_counts", {})
    srcs = ", ".join(_src_label(x) for x in result.sources_used) or "（无）"

    # ---- styles ----
    title = ParagraphStyle("title", fontName=_FONT, fontSize=17, leading=22,
                           alignment=1, textColor=colors.HexColor(_HEAD), spaceAfter=2)
    subtitle = ParagraphStyle("subtitle", fontName=_FONT, fontSize=9, leading=13,
                              alignment=1, textColor=colors.HexColor(_GRAY), spaceAfter=10)
    h2 = ParagraphStyle("h2", fontName=_FONT, fontSize=13, leading=17,
                        textColor=colors.HexColor(_HEAD), spaceBefore=14, spaceAfter=6)
    h3 = ParagraphStyle("h3", fontName=_FONT, fontSize=11, leading=15,
                        textColor=colors.HexColor(_ACCENT), spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("body", fontName=_FONT, fontSize=10, leading=15)
    body2 = ParagraphStyle("body2", parent=body, leftIndent=14)
    bullet = ParagraphStyle("bullet", parent=body, leftIndent=12)
    note = ParagraphStyle("note", fontName=_FONT, fontSize=9, leading=13,
                          textColor=colors.HexColor("#666666"), spaceBefore=2, spaceAfter=6)
    cell = ParagraphStyle("cell", fontName=_FONT, fontSize=9, leading=12)
    cell_c = ParagraphStyle("cellc", parent=cell, alignment=1)
    cell_h = ParagraphStyle("cellh", parent=cell, textColor=colors.white)

    def header_row(*labels: str):
        return [Paragraph(x, cell_h) for x in labels]

    # ---- document ----
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm, topMargin=13 * mm, bottomMargin=16 * mm,
        title="三方组件漏洞分析报告", author="DTrack",
    )
    story: list = []
    story.append(Paragraph("三方组件漏洞分析报告", title))
    story.append(Paragraph(f"分析目标：{_p(result.target)} · 生成时间：{_p(result.generated_at)}",
                           subtitle))

    # 一、概览
    story.append(Paragraph("一、概览", h2))
    overview = [
        ("分析目标", _p(result.target)),
        ("分析语言", _p(result.language.value)),
        ("生成时间", _p(result.generated_at)),
        ("使用的漏洞源", _p(srcs)),
        ("组件总数", str(s.get("total_components", 0))),
        ("存在漏洞的组件数", str(s.get("components_with_vulns", 0))),
        ("漏洞总数", str(s.get("total_vulnerabilities", 0))),
        ("直接依赖 / 传递依赖",
         f"{s.get('direct_deps', 0)} / {s.get('transitive_deps', 0)}"),
    ]
    ov_tbl = Table([[Paragraph(f"<font color='{_HEAD}'>{k}</font>", cell), Paragraph(v, cell)]
                    for k, v in overview], colWidths=[130, _USABLE - 130])
    ov_tbl.setStyle(_grid(header=False))
    story.append(ov_tbl)
    if result.notes:
        story.append(Paragraph("备注：", h3))
        for n in result.notes:
            story.append(Paragraph(f"• {_p(n)}", bullet))

    # 二、漏洞分布
    story.append(Paragraph("二、漏洞分布", h2))
    story.append(Paragraph("2.1 按严重程度", h3))
    sev_data = [header_row("严重程度", "数量")]
    for sev in _SEV_ORDER:
        sev_data.append([Paragraph(_sev_zh(sev), cell),
                         Paragraph(str(sev_counts.get(sev.value, 0)), cell_c)])
    t = Table(sev_data, colWidths=[_USABLE * 0.7, _USABLE * 0.3], repeatRows=1)
    t.setStyle(_grid())
    story.append(t)

    story.append(Paragraph("2.2 按漏洞来源", h3))
    if src_counts:
        src_data = [header_row("来源", "漏洞数")]
        for k, v in sorted(src_counts.items(), key=lambda x: -x[1]):
            src_data.append([Paragraph(_src_label(k), cell),
                             Paragraph(str(v), cell_c)])
        t = Table(src_data, colWidths=[_USABLE * 0.7, _USABLE * 0.3], repeatRows=1)
        t.setStyle(_grid())
        story.append(t)
    else:
        story.append(Paragraph("（未从任何在线源获取到漏洞数据；请检查网络与配置）", note))

    story.append(Paragraph("2.3 依赖类型分布", h3))
    dep_data = [header_row("类型", "组件数"),
                [Paragraph("直接依赖", cell), Paragraph(str(s.get("direct_deps", 0)), cell_c)],
                [Paragraph("传递依赖", cell), Paragraph(str(s.get("transitive_deps", 0)), cell_c)]]
    t = Table(dep_data, colWidths=[_USABLE * 0.7, _USABLE * 0.3], repeatRows=1)
    t.setStyle(_grid())
    story.append(t)

    # 2.4 中危及以上安全漏洞影响的产品和版本清单汇总
    story.append(Paragraph("2.4 中危及以上安全漏洞影响的产品和版本清单汇总", h3))
    mid_comps = [c for c in result.components if c.vulnerabilities and
                 any(v.severity.rank >= Severity.MEDIUM.rank for v in c.vulnerabilities)]
    mid_comps.sort(key=lambda c: (c.worst_severity.rank * -1, c.coordinate))
    if not mid_comps:
        story.append(Paragraph("未检测到中危及以上安全漏洞。", note))
    else:
        story.append(Paragraph("下表汇总存在中危及以上安全漏洞的组件（产品）及其版本，"
                               "并列出该组件影响的业务项目（项目名称:版本）。", note))
        mid_data = [header_row("产品（组件）", "版本", "最高严重度", "中危及以上漏洞数", "影响项目")]
        for c in mid_comps:
            name_cell = f"{c.group}:{c.name}" if c.group else c.name
            n_mid = sum(1 for v in c.vulnerabilities if v.severity.rank >= Severity.MEDIUM.rank)
            projs = c.extra.get("affected_projects") or []
            affected = "<br/>".join(_p(p) for p in projs) if projs else "—"
            mid_data.append([
                Paragraph(_p(name_cell), cell),
                Paragraph(_p(c.version) or "—", cell_c),
                Paragraph(_sev_zh(c.worst_severity), cell_c),
                Paragraph(str(n_mid), cell_c),
                Paragraph(affected, cell),
            ])
        t = Table(mid_data, colWidths=[_USABLE * 0.30, _USABLE * 0.12,
                                       _USABLE * 0.13, _USABLE * 0.15, _USABLE * 0.30],
                  repeatRows=1)
        t.setStyle(_grid())
        story.append(t)

    # 三、License 分布
    lic_counts = s.get("license_counts", {})
    unknown_lic = sum(1 for c in result.components if not c.license)
    story.append(Paragraph("三、组件 License 分布", h2))
    story.append(Paragraph("3.1 许可证总体分布", h3))
    lic_data = [header_row("License", "类型", "组件数")]
    if lic_counts:
        for lic, n in sorted(lic_counts.items(), key=lambda x: -x[1]):
            ltype = "传染型" if _is_copyleft(lic) else "宽松型"
            lic_data.append([Paragraph(_p(lic), cell), Paragraph(ltype, cell),
                             Paragraph(str(n), cell_c)])
    else:
        lic_data.append([Paragraph("（暂无 license 数据）", cell),
                         Paragraph("—", cell), Paragraph("0", cell_c)])
    if unknown_lic:
        lic_data.append([Paragraph("未知/未识别", cell), Paragraph("未知", cell),
                         Paragraph(str(unknown_lic), cell_c)])
    t = Table(lic_data, colWidths=[_USABLE * 0.62, _USABLE * 0.18, _USABLE * 0.20], repeatRows=1)
    t.setStyle(_grid())
    story.append(t)

    story.append(Paragraph("3.2 传染型（Copyleft）许可证", h3))
    story.append(Paragraph("以下许可证具有 copyleft（传染性）约束（如 GPL/LGPL/AGPL/MPL/EPL "
                           "等），使用或分发含此类组件的衍生作品时，需注意对应的开源义务（如源码公开）。", note))
    copyleft_items = [(lic, n) for lic, n in lic_counts.items() if _is_copyleft(lic)]
    if copyleft_items:
        cp_data = [header_row("License", "组件数")]
        for lic, n in sorted(copyleft_items, key=lambda x: -x[1]):
            cp_data.append([Paragraph(_p(lic), cell), Paragraph(str(n), cell_c)])
        t = Table(cp_data, colWidths=[_USABLE * 0.7, _USABLE * 0.3], repeatRows=1)
        t.setStyle(_grid())
        story.append(t)
    else:
        story.append(Paragraph("未检测到具有传染性（copyleft）约束的开源许可证。", note))

    story.append(Paragraph("3.3 未知/未识别 License 明细", h3))
    if unknown_lic:
        story.append(Paragraph(f"共 {unknown_lic} 个组件未从清单/元数据中解析到 license"
                               "（未知或无法识别）：", body))
        for c in result.components:
            if not c.license:
                name_cell = f"{c.group}:{c.name}" if c.group else c.name
                story.append(Paragraph(f"• {_p(name_cell)}（{_p(c.version) or '—'}）", bullet))
    else:
        story.append(Paragraph("所有组件均已解析到 license。", note))

    # 四、修复建议汇总
    story.append(Paragraph("四、修复建议汇总", h2))
    vuln_comps = [c for c in result.components if c.vulnerabilities]
    vuln_comps.sort(key=lambda c: (c.worst_severity.rank * -1, c.coordinate))
    fixable = [c for c in vuln_comps if c.worst_severity.rank >= Severity.HIGH.rank]
    if not fixable:
        story.append(Paragraph("无高危/超危漏洞需要优先修复。", note))
    else:
        fix_data = [header_row("组件", "依赖类型", "最高严重度", "License", "修复建议")]
        for comp in fixable:
            fix_data.append([
                Paragraph(_p(comp.coordinate), cell),
                Paragraph("直接" if comp.direct else "传递", cell_c),
                Paragraph(_sev_zh(comp.worst_severity), cell_c),
                Paragraph(_p(normalize_license(comp.license)) or "—", cell),
                Paragraph(_p(_best_fix(comp)), cell),
            ])
        t = Table(fix_data, colWidths=[_USABLE * 0.30, _USABLE * 0.10,
                                       _USABLE * 0.13, _USABLE * 0.17, _USABLE * 0.30],
                  repeatRows=1)
        t.setStyle(_grid())
        story.append(t)

    # 五、组件全集
    story.append(Paragraph("五、组件全集", h2))
    all_comps = sorted(
        result.components,
        key=lambda c: (0 if c.vulnerabilities else 1, c.worst_severity.rank * -1, c.coordinate),
    )
    story.append(Paragraph(f"共 {len(all_comps)} 个组件。下表为全部组件汇总：有漏洞的组件在"
                           "「漏洞分级」列按严重级别逐行列出各级别漏洞数量；无漏洞组件标记为「无」。", note))
    has_lib = any(c.lib_type for c in all_comps)
    # 与 markdown 保持一致：仅当存在「中危及以上漏洞」或「传染型/不安全 License」的
    # 组件时才展示「影响项目」列（无项目引用时填 —）。
    show_affected = any(_should_show_affected(c) for c in all_comps)
    if has_lib:
        if show_affected:
            inv_head = header_row("#", "组件", "依赖类型", "类型", "版本", "License", "漏洞分级", "影响项目")
            inv_units = [0.05, 0.27, 0.09, 0.07, 0.11, 0.15, 0.10, 0.16]
        else:
            inv_head = header_row("#", "组件", "依赖类型", "类型", "版本", "License", "漏洞分级")
            inv_units = [0.05, 0.30, 0.10, 0.08, 0.12, 0.16, 0.19]
    else:
        if show_affected:
            inv_head = header_row("#", "组件", "依赖类型", "版本", "License", "漏洞分级", "影响项目")
            inv_units = [0.06, 0.31, 0.10, 0.12, 0.17, 0.10, 0.14]
        else:
            inv_head = header_row("#", "组件", "依赖类型", "版本", "License", "漏洞分级")
            inv_units = [0.06, 0.34, 0.11, 0.13, 0.18, 0.18]
    inv_data = [inv_head]
    for idx, c in enumerate(all_comps, 1):
        name_cell = f"{c.group}:{c.name}" if c.group else c.name
        ltype = ("动态" if c.lib_type == "dynamic" else "静态") if c.lib_type else "—"
        lic_cell = _p(normalize_license(c.license)) or "—"
        if lic_cell != "—" and _is_copyleft(lic_cell):
            lic_cell += "（传染）"
        if c.vulnerabilities:
            counts = {sev.value: 0 for sev in _SEV_ORDER}
            for v in c.vulnerabilities:
                counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
            stats = "<br/>".join(f"{_sev_zh(sev)} {counts[sev.value]}"
                                 for sev in _SEV_ORDER if counts[sev.value]) or "0"
        else:
            stats = "无"
        row = [Paragraph(str(idx), cell_c), Paragraph(_p(name_cell), cell),
               Paragraph("直接" if c.direct else "传递", cell_c)]
        if has_lib:
            row.append(Paragraph(ltype, cell_c))
        row += [Paragraph(_p(c.version), cell), Paragraph(lic_cell, cell),
                Paragraph(stats, cell_c)]
        if show_affected:
            # 与 markdown 一致：仅对「中危及以上漏洞」或「传染型 License」组件展示影响项目，
            # 仅有低危/无风险组件该列固定填 —。
            if _should_show_affected(c):
                projs = c.extra.get("affected_projects") or []
                affected = "<br/>".join(_p(p) for p in projs) if projs else "—"
            else:
                affected = "—"
            row.append(Paragraph(affected, cell))
        inv_data.append(row)
    t = Table(inv_data, colWidths=[u * _USABLE for u in inv_units], repeatRows=1)
    t.setStyle(_grid())
    story.append(t)

    # 六、组件漏洞明细
    story.append(Paragraph("六、组件漏洞明细", h2))
    if not vuln_comps:
        story.append(Paragraph("未检测到任何组件漏洞。", note))
    else:
        for comp in vuln_comps:
            _add_component_block(story, comp, h3, body, body2, bullet, note)

    story.append(Spacer(1, 10))
    story.append(Paragraph(f"由 DTrack 生成 · 漏洞数据来源：{_p(srcs)} · 报告仅供安全加固参考", note))

    def _footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont(_FONT, 8)
        canvas.setFillColor(colors.HexColor(_GRAY))
        canvas.drawCentredString(A4[0] / 2, 10 * mm,
                                 f"第 {_doc.page} 页")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def _add_component_block(story: list, comp: Component, h3, body, body2, bullet, note) -> None:
    """向文档追加一个组件（含漏洞明细）的块。"""
    tag = "直接依赖" if comp.direct else "传递依赖"
    type_tag = ""
    if comp.lib_type:
        type_tag = " · " + ("动态库" if comp.lib_type == "dynamic" else "静态库")
    story.append(Paragraph(
        f"<font color='{_DANGER}'>{_sev_zh(comp.worst_severity)}</font> "
        f"{_p(comp.coordinate)}（{tag}{type_tag}）", h3))
    if comp.license:
        story.append(Paragraph(f"License：{_p(normalize_license(comp.license))}", body))
    if comp.vulnerabilities:
        story.append(Paragraph(f"漏洞数：{len(comp.vulnerabilities)}", body))
        story.append(Paragraph("漏洞列表：", body))
        for v in comp.vulnerabilities:
            srcs = ", ".join(_src_label(x) for x in v.sources) if v.sources \
                else _src_label(v.source.value)
            cid = v.cve or v.vuln_id
            head = (f"<font color='{_DANGER}'>{_p(cid)}</font>"
                    f"（{_sev_zh(v.severity)}）来源：{_p(srcs)} — {_p(v.title)}")
            story.append(Paragraph(f"• {head}", bullet))
            if v.vulnerable_range:
                story.append(Paragraph(f"影响版本：{_p(v.vulnerable_range)}", body2))
            story.append(Paragraph(f"修复建议：{_p(_vuln_fix(comp, v))}", body2))
            if v.description:
                # 先按原始文本截断，再整体转义，避免把 &amp;/&lt; 等实体切碎导致 XML 解析失败
                desc = v.description
                if len(desc) > 300:
                    desc = desc[:300] + "…"
                story.append(Paragraph(f"描述：{_p(desc)}", body2))
            if v.references:
                refs = " ".join(f"<{_p(r)}>" for r in v.references[:3])
                story.append(Paragraph(f"参考：{refs}", body2))
    if comp.extra.get("tree_path") and comp.extra["tree_path"] != "(root)":
        story.append(Paragraph(f"依赖路径：{_p(comp.extra['tree_path'])}", body))
