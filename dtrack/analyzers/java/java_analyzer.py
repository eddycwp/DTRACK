"""Java package analyzer: parse pom.xml, resolve dependencies, classify direct/transitive."""
from __future__ import annotations

import os
from typing import Optional

from ...config import Config
from ...core.models import Component
from ...core.types import DependencyType, Language
from ..base import PackageAnalyzer
from .license import maven_central_license
from .maven_resolver import (
    Dep,
    MvnTreeResolver,
    MavenCentralResolver,
    ResolvedDep,
    _is_test_framework,
    resolve_mvn_executable,
)
from .pom_parser import parse_pom_file
from ... import get_logger

_LOGGER = get_logger()


class JavaAnalyzer(PackageAnalyzer):
    language = Language.JAVA

    def _collect_poms(self, target: str) -> list[str]:
        if os.path.isfile(target):
            return [target]
        # Directory: find all pom.xml (multi-module projects supported)
        poms = []
        for root, _dirs, files in os.walk(target):
            if "pom.xml" in files:
                poms.append(os.path.join(root, "pom.xml"))
        if not poms and os.path.isdir(target):
            # maybe the dir itself is the maven project but no pom found
            pass
        return sorted(poms)

    def _project_dir(self, target: str) -> str:
        if os.path.isfile(target):
            return os.path.dirname(target)
        return target

    @staticmethod
    def _is_bom_import(d: "Dep") -> bool:
        """BOM 导入（type=pom + scope=import）不是真实组件，只是引入另一份 POM 的
        dependencyManagement，不应作为依赖被扫描。"""
        return (d.type or "jar").lower() == "pom" and (d.scope or "").lower() == "import"

    def _collect_declared(self, poms: list[str]):
        """汇总所有 pom.xml 中声明的组件。

        返回:
            direct_keys  - <dependencies> 中声明的 (group, artifact, version) 集合
            managed_keys - <dependencyManagement> 中声明的真实组件（已排除 BOM import）
            managed_decl - [(Dep, pom_path)]，供 mvn dependency:tree 遗漏时回补
            seed_deps    - 全部已声明组件（直接 + 受管，排除 BOM import），作为解析器
                           传递展开的种子
            project_coords, direct_nover - 保持原有语义
        """
        direct_keys: set = set()
        managed_keys: set = set()
        managed_decl: list = []
        seed_map: dict = {}
        source_map: dict = {}      # (group, artifact, version) -> [pom_path, ...]
        project_coords: list = []
        direct_nover: set = set()

        for pom_path in poms:
            pom = parse_pom_file(pom_path)
            if pom.group_id and pom.artifact_id:
                project_coords.append(
                    f"{pom.group_id}:{pom.artifact_id}:{pom.version or '?'}")
            # <dependencies> —— 实际直接依赖
            for d in pom.direct_deps:
                if not d.group or not d.artifact or self._is_bom_import(d):
                    continue
                k = (d.group, d.artifact, d.version)
                direct_keys.add(k)
                seed_map.setdefault(k, d)
                source_map.setdefault(k, []).append(pom_path)
                if d.version is None:
                    direct_nover.add((d.group, d.artifact))
            # <dependencyManagement> —— 版本统一管理的真实组件（BOM import 除外）
            for d in pom.managed_deps:
                if not d.group or not d.artifact or self._is_bom_import(d):
                    continue
                k = (d.group, d.artifact, d.version)
                managed_keys.add(k)
                managed_decl.append((d, pom_path))
                seed_map.setdefault(k, d)
                source_map.setdefault(k, []).append(pom_path)
                if d.version is None:
                    direct_nover.add((d.group, d.artifact))

        seed_deps = list(seed_map.values())
        return (direct_keys, managed_keys, managed_decl, seed_deps,
                source_map, project_coords, direct_nover)

    def analyze(self, target: str) -> list[Component]:
        poms = self._collect_poms(target)
        if not poms:
            raise FileNotFoundError(f"No pom.xml found under target: {target}")

        (direct_keys, managed_keys, managed_decl, seed_deps,
         source_map, project_coords, direct_nover) = self._collect_declared(poms)

        resolved: list[ResolvedDep]
        use_tree = bool(self.config.get("maven.use_mvn_tree", True))
        tree_resolver = MvnTreeResolver(self.config)
        active_resolver = tree_resolver
        if use_tree and tree_resolver.available():
            try:
                resolved = tree_resolver.resolve(self._project_dir(target))
                if not resolved:
                    raise RuntimeError("mvn dependency:tree 返回空结果")
            except Exception as e:  # noqa: BLE001 - broken Maven install etc.
                _LOGGER.warning(
                    "mvn dependency:tree 失败（%s），回退到纯 Python 解析 Maven Central 元数据。", e)
                active_resolver = MavenCentralResolver(self.config)
                resolved = active_resolver.resolve(seed_deps)
        else:
            if use_tree:
                _LOGGER.warning(
                    "未找到可用 Maven（%s），回退到纯 Python 解析 Maven Central 元数据。",
                    resolve_mvn_executable(self.config))
            active_resolver = MavenCentralResolver(self.config)
            resolved = active_resolver.resolve(seed_deps)

        components: list[Component] = []
        seen: set = set()
        for r in resolved:
            k = (r.group, r.artifact, r.version)
            if k in seen:
                continue
            seen.add(k)
            is_direct = (
                r.direct or (k in direct_keys) or (k in managed_keys)
                or (r.group, r.artifact) in direct_nover
            )
            comp = Component(
                group=r.group,
                name=r.artifact,
                version=r.version,
                language=Language.JAVA,
                dependency_type=DependencyType.DIRECT if is_direct else DependencyType.TRANSITIVE,
                direct=is_direct,
                transitive=not is_direct,
                source=";".join(source_map.get(k, [])) or "(transitive)",
                extra={
                    "scope": r.scope,
                    "tree_path": " > ".join(r.parents) or "(root)",
                },
            )
            components.append(comp)

        # 回补：mvn dependency:tree 不会输出仅在 <dependencyManagement> 中声明、
        # 且未被 <dependencies> 实际引用的组件。此处显式补录，确保纳入漏洞分析
        # （这类组件同样由上面的 test 作用域 / 测试框架剔除逻辑统一过滤）。
        resolved_keys = {(r.group, r.artifact) for r in resolved}
        for d, pom_path in managed_decl:
            k = (d.group, d.artifact, d.version)
            if (d.group, d.artifact) in resolved_keys:
                continue
            if k in seen:
                continue
            seen.add(k)
            comp = Component(
                group=d.group,
                name=d.artifact,
                version=d.version,
                language=Language.JAVA,
                dependency_type=DependencyType.DIRECT,
                direct=True,
                transitive=False,
                source=pom_path,
                extra={"scope": d.scope or "compile",
                       "tree_path": "(dependencyManagement)"},
            )
            components.append(comp)

        # 剔除不参与发布产物的依赖：test 作用域 + 常见测试框架（应对被误标为 compile 的测试依赖）
        # 剔除主要在 resolver 层完成（同时避免无谓的传递展开），此处做集中兜底并汇总计数。
        exclude_scopes = [s.lower() for s in (self.config.get("analyze.exclude_scopes") or [])]
        exclude_test_fw = bool(self.config.get("analyze.exclude_test_frameworks", True))
        self.excluded_count = getattr(active_resolver, "excluded_count", 0)
        if exclude_scopes or exclude_test_fw:
            kept: list[Component] = []
            for comp in components:
                scope = (comp.extra.get("scope") or "compile").lower()
                if scope in exclude_scopes:
                    self.excluded_count += 1
                    continue
                if exclude_test_fw and _is_test_framework(comp.name):
                    self.excluded_count += 1
                    continue
                kept.append(comp)
            components = kept
            if self.excluded_count:
                _LOGGER.info(
                    "已剔除 %s 个测试相关依赖（test 作用域 / 测试框架，不计入漏洞分析）。",
                    self.excluded_count)

        if bool(self.config.get("maven.resolve_license", True)):
            for comp in components:
                if comp.group and comp.name and comp.version and not comp.license:
                    comp.license = maven_central_license(
                        self.config, comp.group, comp.name, comp.version
                    )

        self._project_coords = project_coords
        return components

    def describe_target(self, target: str) -> str:
        coords = getattr(self, "_project_coords", None)
        if coords:
            return f"Maven project(s): {', '.join(coords)}"
        return f"Java target: {target}"
