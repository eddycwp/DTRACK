"""C/C++ package analyzer.

Discovers C/C++ dependencies two ways and normalizes them into ``Component``
objects so they flow through the *exact same* vulnerability analysis pipeline as
Java (NVD / GitHub / QIANXIN / OSV) and the *exact same* Markdown report:

  1. CMake-based dependencies  — parse CMakeLists.txt for ``find_package`` and
     ``target_link_libraries`` declarations (dynamic/static libraries declared
     as build dependencies).
  2. On-disk library binaries    — scan for shared objects (``.so``/``.dylib``/
     ``.dll``) and static archives (``.a``/``.lib``), extracting name+version
     from the file name.

Because C/C++ build graphs don't expose a clean direct/transitive split, every
discovered component is marked ``direct`` (it is referenced by the project's own
build files). License is detected best-effort from the nearest LICENSE file.
"""
from __future__ import annotations

import os
from typing import Optional

from ...config import Config
from ...core.models import Component
from ...core.types import Language
from ...utils.license_detect import detect_license_near
from ..base import PackageAnalyzer
from .cmake_parser import collect_cmake, external_dependencies
from .lib_scanner import scan_libraries


class CCAnalyzer(PackageAnalyzer):
    language = Language.CC

    def analyze(self, target: str) -> list[Component]:
        components: list[Component] = []
        seen: set = set()

        # --- CMake-based dependencies ---
        cmake_projs = collect_cmake(target)
        resolve_license = bool(self.config.get("report.include_license", True))
        for name, version in external_dependencies(cmake_projs):
            k = ("cmake", name, version)
            if k in seen:
                continue
            seen.add(k)
            src = cmake_projs[0].path if cmake_projs else target
            lic = detect_license_near(src) if resolve_license else None
            components.append(Component(
                group=None,
                name=name,
                version=version,
                language=Language.CC,
                direct=True,
                transitive=False,
                source=src,
                license=lic,
                lib_type=None,           # CMake doesn't reliably say dynamic vs static
                extra={"kind": "cmake"},
            ))

        # --- On-disk library binaries ---
        libs = scan_libraries(target, max_depth=int(self.config.get("maven.max_depth", 5)) + 1)
        for lib in libs:
            k = ("lib", lib.name, lib.version, lib.lib_type)
            if k in seen:
                continue
            seen.add(k)
            lic = detect_license_near(lib.path) if resolve_license else None
            components.append(Component(
                group=None,
                name=lib.name,
                version=lib.version,
                language=Language.CC,
                direct=True,
                transitive=False,
                source=lib.path,
                license=lic,
                lib_type=lib.lib_type,
                extra={"kind": "binary", "path": lib.path},
            ))

        if not components:
            kind = "CMakeLists.txt" if os.path.isfile(target) else target
            raise FileNotFoundError(
                f"未在目标中发现 C/C++ 依赖（CMake 声明或动态/静态库文件）：{kind}"
            )
        return components

    def describe_target(self, target: str) -> str:
        has_cmake = bool(collect_cmake(target))
        if has_cmake:
            return f"C/C++ (CMake) project: {target}"
        return f"C/C++ library scan: {target}"
