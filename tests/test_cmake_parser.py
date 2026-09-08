"""Tests for the C/C++ CMake parser."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dtrack.analyzers.cc.cmake_parser import (  # noqa: E402
    external_dependencies,
    parse_cmake_text,
)


CMAKE = """
cmake_minimum_required(VERSION 3.14)
project(MyCppApp VERSION 1.0.0 LANGUAGES CXX)
find_package(OpenSSL REQUIRED)
find_package(ZLIB 1.2.11 REQUIRED)
find_package(CURL 7.68.0)
add_library(core STATIC src/core.cpp)
add_library(utils SHARED src/utils.cpp)
add_executable(app src/main.cpp)
target_link_libraries(app
    PRIVATE
        core
        utils
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        CURL::libcurl
        pthread
)
"""


class TestCMakeParser(unittest.TestCase):
    def test_project_version(self):
        p = parse_cmake_text(CMAKE)
        self.assertEqual(p.projects[0][0], "MyCppApp")
        self.assertEqual(p.projects[0][1], "1.0.0")

    def test_find_packages(self):
        p = parse_cmake_text(CMAKE)
        names = {n for n, _ in p.find_packages}
        self.assertIn("OpenSSL", names)
        self.assertIn("ZLIB", names)
        self.assertIn("CURL", names)
        self.assertEqual(dict(p.find_packages)["ZLIB"], "1.2.11")

    def test_local_libs_excluded(self):
        p = parse_cmake_text(CMAKE)
        deps = external_dependencies([p])
        names = {n for n, _ in deps}
        # core/utils are local targets -> excluded
        self.assertNotIn("core", names)
        self.assertNotIn("utils", names)
        # OpenSSL::SSL namespace components are kept under their base name only
        # via target_link; we keep the raw item (OpenSSL::SSL) as a dependency
        self.assertIn("OpenSSL::SSL", names)
        self.assertIn("CURL::libcurl", names)
        self.assertIn("pthread", names)
        self.assertIn("ZLIB::ZLIB", names)

    def test_command_name_space_before_paren(self):
        """CMake 允许命令名与左括号间有空格：project (..) / find_package (..) 等必须能被识别。"""
        spaced = """
        cmake_minimum_required(VERSION 3.14)
        project (SpacedApp VERSION 2.3.4 LANGUAGES CXX)
        find_package (OpenSSL REQUIRED)
        find_package (ZLIB 1.2.11 REQUIRED)
        add_library (core STATIC src/core.cpp)
        target_link_libraries (app
            PRIVATE
                core
                OpenSSL::SSL
        )
        """
        p = parse_cmake_text(spaced)
        self.assertEqual(p.projects[0][0], "SpacedApp")
        self.assertEqual(p.projects[0][1], "2.3.4")
        names = {n for n, _ in p.find_packages}
        self.assertIn("OpenSSL", names)
        self.assertIn("ZLIB", names)
        self.assertEqual(dict(p.find_packages)["ZLIB"], "1.2.11")
        self.assertIn("core", p.local_libs)
        deps = external_dependencies([p])
        dnames = {n for n, _ in deps}
        self.assertNotIn("core", dnames)
        self.assertIn("OpenSSL::SSL", dnames)

    def test_command_case_insensitive(self):
        """CMake 命令名不区分大小写：PROJECT/FIND_PACKAGE/ADD_LIBRARY/TARGET_LINK_LIBRARIES 等均应识别。"""
        upper = """
        CMAKE_MINIMUM_REQUIRED(VERSION 3.14)
        PROJECT(CasedApp VERSION 5.6)
        FIND_PACKAGE(OpenSSL REQUIRED)
        FIND_PACKAGE(ZLIB 1.2.11 REQUIRED)
        ADD_LIBRARY(core STATIC src/core.cpp)
        TARGET_LINK_LIBRARIES(app
            PRIVATE
                core
                OpenSSL::SSL
        )
        """
        p = parse_cmake_text(upper)
        self.assertEqual(p.projects[0][0], "CasedApp")
        self.assertEqual(p.projects[0][1], "5.6")
        names = {n for n, _ in p.find_packages}
        self.assertIn("OpenSSL", names)
        self.assertIn("ZLIB", names)
        self.assertEqual(dict(p.find_packages)["ZLIB"], "1.2.11")
        self.assertIn("core", p.local_libs)
        deps = external_dependencies([p])
        dnames = {n for n, _ in deps}
        self.assertNotIn("core", dnames)
        self.assertIn("OpenSSL::SSL", dnames)

    def test_command_mixed_case_and_space(self):
        """混合大小写 + 空格组合也应被识别。"""
        mixed = """
        Project (MixedApp VERSION 0.1)
        Find_Package (CURL 7.68.0)
        """
        p = parse_cmake_text(mixed)
        self.assertEqual(p.projects[0][0], "MixedApp")
        self.assertEqual(p.projects[0][1], "0.1")
        self.assertIn("CURL", {n for n, _ in p.find_packages})

    def test_backslash_continuation_add_library(self):
        """ADD_LIBRARY 用反斜杠跨多行续行（截图场景），wcsp 必须被正确识别为本地库。"""
        cont = """
        ADD_LIBRARY ( wcsp STATIC ${WCSP_SRCS_LIST} ${WCSP_CA_SRCS_LIST} ${WCSP_SKE_SRCS_LIST} \\
        ${WCSP_CO_GMT0010_SRCS_LIST} ${WCSP_CONNECT_SRCS_LIST} ${WCSP_E2E_SRCS_LIST} )
        TARGET_LINK_LIBRARIES ( app
            PRIVATE
                wcsp
        )
        """
        p = parse_cmake_text(cont)
        # wcsp 必须进入 local_libs，避免被当作外部依赖（version=None）
        self.assertIn("wcsp", p.local_libs)
        deps = external_dependencies([p])
        self.assertNotIn("wcsp", {n for n, _ in deps})

    def test_generator_expression_nested_parens(self):
        """生成表达式 $<...> 含括号时，_args_of 应匹配到真正的配对右括号而非截断。"""
        text = """
        TARGET_LINK_LIBRARIES ( app
            PRIVATE
                $<INSTALL_INTERFACE:libfoo>
                realdep
                boost
        )
        """
        p = parse_cmake_text(text)
        items = {it for _, items in p.link_items for it in items}
        # 不应因生成表达式内部的 ) 而提前截断，realdep / boost 必须保留
        self.assertIn("realdep", items)
        self.assertIn("boost", items)
        self.assertNotIn("$<INSTALL_INTERFACE:libfoo", items)

    def test_unclosed_paren_fallback_keeps_first_arg(self):
        """极端情况下（多行命令未正确合并、缺少配对的右括号），_args_of 仍应返回库名而非 None。"""
        from dtrack.analyzers.cc.cmake_parser import _args_of
        # 仅一行且左括号后无右括号：旧实现返回 None，会导致 add_library 被整条漏解析
        args = _args_of("add_library", "ADD_LIBRARY ( wcsp STATIC src/a.cpp")
        self.assertIsNotNone(args)
        self.assertEqual(args[0], "wcsp")


if __name__ == "__main__":
    unittest.main()
