"""Command-line interface for DTrack.

Sub-commands:
  config init        write an example dtrack.toml
  config show        print the resolved configuration
  analyze TARGET     analyze a target (java project / pom) and emit a report
  fetch SOURCE ...   pull projects/components/images from gitlab / nexus / harbor
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, setup_logging, get_logger
from .analyzers import get_analyzer, supported_languages
from .config import load_config, write_example_config
from .core.models import AnalysisResult
from .core.types import Language
from .report.markdown import _src_label
from .report import render_markdown, write_report
from .sources import get_fetcher, list_fetchers
from .vuln import VulnerabilityAggregator
from .scan import ScanKind, ScanTarget, scan_target


_LOGGER = get_logger()


def _print_summary(result: AnalysisResult) -> None:
    s = result.summary
    print("\n" + "=" * 60)
    print(f"  DTrack 分析完成  ·  目标: {result.target}")
    print("=" * 60)
    print(f"  组件总数        : {s.get('total_components', 0)}")
    print(f"  存在漏洞的组件  : {s.get('components_with_vulns', 0)}")
    print(f"  漏洞总数        : {s.get('total_vulnerabilities', 0)}")
    sc = s.get("severity_counts", {})
    for sev in ("critical", "high", "medium", "low", "unknown"):
        if sc.get(sev):
            print(f"    - {sev:8s}: {sc[sev]}")
    print(f"  使用的漏洞源    : {', '.join(_src_label(s) for s in result.sources_used) or '（无）'}")
    print("=" * 60 + "\n")
    # 同步写入日志文件（便于离线查看运行结果）
    _LOGGER.info(
        "分析完成 | 目标=%s 组件总数=%s 有漏洞组件=%s 漏洞总数=%s 源=%s",
        result.target, s.get("total_components", 0), s.get("components_with_vulns", 0),
        s.get("total_vulnerabilities", 0),
        ",".join(_src_label(s) for s in result.sources_used) or "（无）",
    )


def cmd_config(args: argparse.Namespace, config) -> int:
    if args.config_cmd == "init":
        write_example_config(args.path)
        print(f"已写入示例配置: {args.path}\n用编辑器填写仓库地址与奇安信等凭据后，运行 `dtrack analyze ...`。")
        return 0
    if args.config_cmd == "show":
        print(json.dumps(config.data, indent=2, ensure_ascii=False))
        return 0
    return 1


def cmd_analyze(args: argparse.Namespace, config) -> int:
    if args.sources:
        config.data.setdefault("vuln", {})["sources"] = [s.strip() for s in args.sources.split(",") if s.strip()]
    if args.max_depth is not None:
        config.data.setdefault("maven", {})["max_depth"] = args.max_depth
    if args.no_cache:
        config.data.setdefault("general", {})["cache_ttl"] = 0

    lang = Language(args.lang)
    analyzer = get_analyzer(lang, config)
    _LOGGER.info("解析目标: %s (语言=%s)", args.target, lang.value)
    components = analyzer.analyze(args.target)
    _LOGGER.info(
        "解析到 %s 个组件（直接 %s / 传递 %s）",
        len(components),
        sum(1 for c in components if c.direct),
        sum(1 for c in components if c.transitive),
    )

    if args.skip_vuln:
        _LOGGER.info("已跳过在线漏洞分析（--skip-vuln）")
        sources_used = []
    else:
        aggregator = VulnerabilityAggregator(config)
        _LOGGER.info(
            "在线漏洞分析（源: %s）...",
            ", ".join(s.name for s in aggregator.sources) or "无",
        )
        aggregator.analyze_components(components)
        sources_used = [s.name for s in aggregator.sources]

    result = AnalysisResult(
        target=analyzer.describe_target(args.target),
        language=lang,
        components=components,
        sources_used=sources_used,
    )
    excluded = getattr(analyzer, "excluded_count", 0)
    if excluded:
        result.notes.append(
            f"已剔除 {excluded} 个测试相关依赖（test 作用域及 junit/mockito 等测试框架），"
            f"因其不参与发布产物，不计入漏洞分析。"
        )
    result.enrich_summary()

    if args.skip_vuln:
        result.notes.append("已跳过在线漏洞查询（--skip-vuln）。")
    out_dir = args.out or config.get("report.out_dir", "./reports")
    if not args.report:
        base = os.path.basename(os.path.normpath(args.target)).replace(" ", "_")
        args.report = f"dtrack_report_{base}.md"
    path = write_report(result, out_dir, args.report)
    _print_summary(result)
    print(f"[+] 报告已生成: {path}")
    return 0


def cmd_scan(args: argparse.Namespace, config) -> int:
    kind = ScanKind(args.kind)
    # 允许 CLI 覆盖配置中的凭据/项目编号
    scan_cfg = config.data.setdefault("scan", {}).setdefault("qianxin", {})
    if args.project_id:
        scan_cfg["project_id"] = args.project_id
    if args.username:
        scan_cfg["username"] = args.username
    if args.password:
        scan_cfg["password"] = args.password
    if args.token:
        scan_cfg["token"] = args.token

    # 按类型校验必需参数
    if kind in (ScanKind.JAR_LOCAL, ScanKind.IMAGE_LOCAL):
        if not args.path:
            print("[!] 该类型需要 --path（本地文件/目录 或 镜像 tar）。", file=sys.stderr)
            return 2
    else:
        if not args.url:
            print("[!] 该类型需要 --url（仓库制品或镜像地址）。", file=sys.stderr)
            return 2
        if kind in (ScanKind.JAR_NEXUS, ScanKind.JAR_ARTIFACTORY,
                    ScanKind.IMAGE_HARBOR, ScanKind.IMAGE_NEXUS, ScanKind.IMAGE_ARTIFACTORY):
            if not (args.username and args.password):
                print("[!] 该私有仓库类型需要 --username 与 --password。", file=sys.stderr)
                return 2

    target = ScanTarget(
        kind=kind,
        path=args.path,
        url=args.url,
        username=args.username,
        password=args.password,
        token=args.token,
        auth_type=args.auth_type,
        language_hint=args.lang,
    )
    try:
        result = scan_target(config, target, task_name=args.task_name)
    except (ValueError, RuntimeError, TimeoutError) as e:
        print(f"[!] 扫描失败: {e}", file=sys.stderr)
        return 1

    if args.report is None:
        safe = (args.task_name or kind.value).replace(" ", "_").replace("/", "_")
        args.report = f"dtrack_scan_{safe}.md"
    out_dir = args.out or config.get("report.out_dir", "./reports")
    path = write_report(result, out_dir, args.report)
    _print_summary(result)
    print(f"[+] 报告已生成: {path}")
    return 0


def cmd_fetch(args: argparse.Namespace, config) -> int:
    fetcher = get_fetcher(args.source, config)
    if not fetcher.enabled():
        print(f"[!] 仓库源 '{args.source}' 未在配置中启用（请设置对应的 base_url）。", file=sys.stderr)
        return 2
    if args.list_projects:
        data = fetcher.list_projects()
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    if args.list_images:
        try:
            data = fetcher.list_images()
        except NotImplementedError:
            print(f"[!] '{args.source}' 不支持镜像列表。", file=sys.stderr)
            return 2
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    if args.download:
        if args.source == "gitlab":
            p = fetcher.download_repository(args.download, ref=args.ref, dest_dir=args.dest)
            print(f"[+] 已下载仓库归档: {p}")
        elif args.source == "nexus":
            # expect repo:group:artifact:version
            parts = args.download.split(":")
            if len(parts) < 4:
                print("[!] --download 需为 repo:group:artifact:version", file=sys.stderr)
                return 2
            repo, g, a, v = parts[0], parts[1], parts[2], parts[3]
            p = fetcher.download_maven_artifact(repo, g, a, v, dest_dir=args.dest)
            print(f"[+] 已下载 Maven 组件: {p}")
        else:
            print(f"[!] '{args.source}' 暂不支持 --download。", file=sys.stderr)
            return 2
        return 0
    print("[!] 未指定操作，使用 --list-projects / --list-images / --download。", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dtrack", description="DTrack - 开发模块漏洞分析管理系统")
    parser.add_argument("--version", action="version", version=f"dtrack {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    pw = sub.add_parser("web", help="启动 Web 管理平台（Vue3 + SQLite）")
    pw.add_argument("--host", default="127.0.0.1")
    pw.add_argument("--port", type=int, default=8080)
    pw.add_argument("--db", default=None, help="SQLite 数据库路径（缺省 ./db/dtrack.db）")
    pw.add_argument("--config", default=None, help="配置文件路径（缺省 ./config/dtrack.toml）")
    pw.add_argument("--dist", default=None, help="前端构建目录（缺省 web/dist）")

    pc = sub.add_parser("config", help="配置管理")
    pc_sub = pc.add_subparsers(dest="config_cmd", required=True)
    pci = pc_sub.add_parser("init", help="生成示例配置文件")
    pci.add_argument("--path", default="config/dtrack.toml")
    pc_sub.add_parser("show", help="显示当前生效配置")

    pa = sub.add_parser("analyze", help="分析目标并生成漏洞报告")
    pa.add_argument("target", help="项目目录或 pom.xml 路径")
    pa.add_argument("--lang", default="java", choices=[l.value for l in supported_languages()])
    pa.add_argument("--config", default=None, help="配置文件路径")
    pa.add_argument("--out", default=None, help="报告输出目录")
    pa.add_argument("--report", default=None, help="报告文件名")
    pa.add_argument("--sources", default=None, help="启用的漏洞源（逗号分隔），如 nvd,github,qianxin")
    pa.add_argument("--max-depth", type=int, default=None, help="传递依赖解析最大深度")
    pa.add_argument("--skip-vuln", action="store_true", help="仅解析依赖，不查询在线漏洞")
    pa.add_argument("--no-cache", action="store_true", help="禁用 API 响应缓存")

    pf = sub.add_parser("fetch", help="从仓库获取项目/组件/镜像")
    pf.add_argument("source", choices=list_fetchers())
    pf.add_argument("--list-projects", action="store_true")
    pf.add_argument("--list-images", action="store_true")
    pf.add_argument("--download", metavar="ID", default=None, help="gitlab: 项目路径; nexus: repo:g:a:v")
    pf.add_argument("--ref", default=None, help="git 分支/标签")
    pf.add_argument("--dest", default="./_fetch")
    pf.add_argument("--config", default=None)

    ps = sub.add_parser("scan", help="二进制/镜像漏洞扫描（奇安信开源卫士 OpenAPI V3）")
    ps.add_argument("--kind", required=True, choices=[k.value for k in ScanKind],
                    help="jar-local / jar-nexus / jar-artifactory / image-local / "
                         "image-harbor / image-dockerhub / image-nexus / image-artifactory")
    ps.add_argument("--path", default=None, help="本地文件或目录(jar-local) / 本地镜像 tar(image-local)")
    ps.add_argument("--url", default=None, help="仓库制品或镜像 uri（nexus/artifactory/harbor/dockerhub）")
    ps.add_argument("--username", default=None, help="仓库/镜像登录用户名")
    ps.add_argument("--password", default=None, help="仓库/镜像登录密码")
    ps.add_argument("--token", default=None, help="api key / identity token")
    ps.add_argument("--auth-type", type=int, default=1, choices=[1, 2, 3],
                    help="1=用户名密码 2=apikey 3=identity token")
    ps.add_argument("--project-id", default=None, help="覆盖配置中的 scan.qianxin.project_id")
    ps.add_argument("--task-name", default=None, help="奇安信任务名称（缺省用 kind 值）")
    ps.add_argument("--lang", default=None, help="归一化语言覆盖：java / c/c++ / docker")
    ps.add_argument("--out", default=None, help="报告输出目录")
    ps.add_argument("--report", default=None, help="报告文件名")
    ps.add_argument("--config", default=None)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config_path = getattr(args, "config", None)
    config = load_config(config_path)
    setup_logging(config.get("general.log_level", "INFO"), config.get("general.log_file"))

    if args.command == "config":
        return cmd_config(args, config)
    if args.command == "analyze":
        return cmd_analyze(args, config)
    if args.command == "fetch":
        return cmd_fetch(args, config)
    if args.command == "scan":
        return cmd_scan(args, config)
    if args.command == "web":
        from .web.server import (run_web, default_db_path, default_config_path,
                                 default_dist_dir)
        db_path = args.db or default_db_path()
        cfg_path = args.config or config_path or default_config_path()
        dist = args.dist or default_dist_dir()
        run_web(args.host, args.port, db_path, cfg_path, dist)
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
