import os
import copy
import unittest
from unittest.mock import patch

from dtrack.analyzers.java.java_analyzer import JavaAnalyzer
from dtrack.analyzers.java.maven_resolver import ResolvedDep
from dtrack.config import Config, DEFAULT_CONFIG


def _cfg() -> Config:
    # 深拷贝默认配置，避免污染模块级 DEFAULT_CONFIG 与其它测试
    cfg = Config(copy.deepcopy(DEFAULT_CONFIG))
    cfg.data.setdefault("maven", {})["resolve_license"] = False
    cfg.data.setdefault("maven", {})["use_mvn_tree"] = True
    return cfg

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "sample-java", "pom.xml")

# 该示例 pom 的 <dependencyManagement> 声明了两个条目：
#   - org.apache.logging.log4j:log4j-bom  (type=pom, scope=import) → BOM 导入，应忽略
#   - junit:junit:4.13.2                  (scope=test)            → 真实受管组件，应纳入


class TestCollectDeclared(unittest.TestCase):
    def setUp(self):
        self.ana = JavaAnalyzer(_cfg())
        self.poms = [SAMPLE]
        (self.direct_keys, self.managed_keys, self.managed_decl,
         self.seed_deps, _src, _coords, _nover) = self.ana._collect_declared(self.poms)

    def test_direct_includes_dependencies_section(self):
        self.assertIn(("org.apache.logging.log4j", "log4j-core", "2.14.0"), self.direct_keys)
        self.assertIn(("commons-collections", "commons-collections", "3.2.1"), self.direct_keys)
        self.assertIn(("org.springframework", "spring-core", "5.3.3"), self.direct_keys)

    def test_managed_includes_dependency_management(self):
        # junit 来自 <dependencyManagement>，此前被漏掉，现在必须纳入
        self.assertIn(("junit", "junit", "4.13.2"), self.managed_keys)
        seed_coords = {(d.group, d.artifact, d.version) for d in self.seed_deps}
        self.assertIn(("junit", "junit", "4.13.2"), seed_coords)

    def test_bom_import_excluded(self):
        # log4j-bom 是 BOM 导入（type=pom + scope=import），不是真实组件
        seed_coords = {(d.group, d.artifact, d.version) for d in self.seed_deps}
        self.assertNotIn(("org.apache.logging.log4j", "log4j-bom", "2.14.0"), seed_coords)
        self.assertNotIn(("org.apache.logging.log4j", "log4j-bom", "2.14.0"), self.managed_keys)


class FakeCentral:
    """模拟 mvn dependency:tree：只返回实际在依赖树中的直接依赖，遗漏未引用的受管依赖。"""

    DIRECT = {
        ("org.apache.logging.log4j", "log4j-core", "2.14.0"),
        ("commons-collections", "commons-collections", "3.2.1"),
        ("org.springframework", "spring-core", "5.3.3"),
    }

    def __init__(self, config):
        self.config = config

    def resolve(self, seed_deps):
        out = []
        for d in seed_deps:
            if (d.group, d.artifact, d.version) in self.DIRECT:
                out.append(ResolvedDep(d.group, d.artifact, d.version,
                                       scope="compile", depth=0, direct=True))
        return out


class TestAnalyzeIncludesManaged(unittest.TestCase):
    def setUp(self):
        self.cfg = _cfg()
        # 关闭测试相关剔除，避免 junit（受管依赖，test 作用域）被全局规则过滤掉，
        # 以便专门验证 <dependencyManagement> 的回补逻辑（剔除规则另有独立测试覆盖）。
        self.cfg.data.setdefault("analyze", {})["exclude_test_frameworks"] = False
        self.cfg.data.setdefault("analyze", {})["exclude_scopes"] = []

    def test_managed_backfilled_when_tree_omits(self):
        ana = JavaAnalyzer(self.cfg)
        # 强制走 MavenCentralResolver 回退路径（无 mvn 也可用），并用 FakeCentral 模拟
        # mvn tree 遗漏未引用受管依赖的行为。
        with patch("dtrack.analyzers.java.java_analyzer.MvnTreeResolver.available",
                   return_value=False), \
                patch("dtrack.analyzers.java.java_analyzer.MavenCentralResolver", FakeCentral):
            comps = ana.analyze(SAMPLE)

        coords = {(c.group, c.name, c.version): c for c in comps}
        # 直接依赖出现
        self.assertIn(("org.apache.logging.log4j", "log4j-core", "2.14.0"), coords)
        # 受管依赖 junit 被回补
        self.assertIn(("junit", "junit", "4.13.2"), coords)
        junit = coords[("junit", "junit", "4.13.2")]
        self.assertTrue(junit.direct)
        self.assertEqual(junit.extra.get("tree_path"), "(dependencyManagement)")
        # BOM 导入绝不应成为组件
        self.assertNotIn(("org.apache.logging.log4j", "log4j-bom", "2.14.0"), coords)


if __name__ == "__main__":
    unittest.main()
