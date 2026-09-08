import os
import copy
import tempfile
import unittest
from unittest.mock import patch

from dtrack.analyzers.java.maven_resolver import Dep, MavenCentralResolver, MvnTreeResolver
from dtrack.analyzers.java.pom_parser import parse_pom_text
from dtrack.config import Config, DEFAULT_CONFIG

LOG4J_CORE_POM = """
<project>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.14.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.14.0</version>
    </dependency>
  </dependencies>
</project>
"""

EMPTY_POM = """<project><groupId>x</groupId><artifactId>y</artifactId><version>1</version></project>"""


class FakeResolver(MavenCentralResolver):
    """Resolver that returns canned POMs instead of hitting the network."""

    def _fetch_pom(self, g, a, v):
        if (g, a, v) == ("org.apache.logging.log4j", "log4j-core", "2.14.0"):
            return parse_pom_text(LOG4J_CORE_POM)
        if (g, a, v) == ("org.apache.logging.log4j", "log4j-api", "2.14.0"):
            return parse_pom_text(EMPTY_POM)
        return None


class TestMavenResolver(unittest.TestCase):
    def test_transitive_resolution(self):
        cfg = Config(DEFAULT_CONFIG)
        r = FakeResolver(cfg)
        res = r.resolve([Dep("org.apache.logging.log4j", "log4j-core", "2.14.0")])
        coords = {(x.group, x.artifact, x.version, x.direct) for x in res}
        self.assertIn(("org.apache.logging.log4j", "log4j-core", "2.14.0", True), coords)
        self.assertIn(("org.apache.logging.log4j", "log4j-api", "2.14.0", False), coords)

    def test_scope_filtering(self):
        # test scope filtering via a pom with a test-scoped dep
        pom = parse_pom_text("""
        <project><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
          <dependencies>
            <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency>
          </dependencies></project>""")
        cfg = Config(DEFAULT_CONFIG)
        r = FakeResolver(cfg)
        r._fetch_pom = lambda *a: parse_pom_text(EMPTY_POM)
        res = r.resolve([Dep("g", "a", "1")])
        names = {x.artifact for x in res}
        self.assertNotIn("junit", names)

    def test_direct_test_scope_excluded(self):
        # 直接依赖中的 test 作用域（如 junit）也应被剔除（需求：剔除测试组件）
        cfg = Config(DEFAULT_CONFIG)
        r = FakeResolver(cfg)
        r._fetch_pom = lambda *a: parse_pom_text(EMPTY_POM)
        res = r.resolve([Dep("junit", "junit", "4.13", scope="test")])
        self.assertEqual(res, [])  # 直接 test 依赖不进入分析结果

    def test_direct_provided_scope_kept_by_default(self):
        # 默认只剔除 test 作用域；provided 直接依赖仍保留（不被误删）
        cfg = Config(DEFAULT_CONFIG)
        r = FakeResolver(cfg)
        r._fetch_pom = lambda *a: parse_pom_text(EMPTY_POM)
        res = r.resolve([Dep("javax.servlet", "javax.servlet-api", "4.0.1", scope="provided")])
        self.assertEqual([(x.group, x.artifact) for x in res],
                         [("javax.servlet", "javax.servlet-api")])

    def test_test_framework_name_excluded(self):
        # 被误标为 compile 的测试框架依赖（如 log4j-core 中 junit/mockito）也应按名称剔除
        cfg = Config(DEFAULT_CONFIG)
        r = FakeResolver(cfg)
        r._fetch_pom = lambda *a: parse_pom_text(EMPTY_POM)
        res = r.resolve([Dep("org.junit.vintage", "junit-vintage-engine", "5.7.0", scope="compile")])
        self.assertEqual(res, [])
        # 普通 compile 依赖不受影响
        res2 = r.resolve([Dep("com.lmax", "disruptor", "3.4.2", scope="compile")])
        self.assertEqual([(x.group, x.artifact) for x in res2], [("com.lmax", "disruptor")])


class TestMvnTreeCentralUrl(unittest.TestCase):
    """Ensure ``mvn dependency:tree`` honors maven.central_url via a -s settings mirror."""

    def _cfg_with_central(self, central_url: str, username: str = "", password: str = "") -> Config:
        cfg = Config(copy.deepcopy(DEFAULT_CONFIG))  # 避免污染全局 DEFAULT_CONFIG
        cfg.data["maven"]["central_url"] = central_url
        cfg.data["maven"]["central_username"] = username
        cfg.data["maven"]["central_password"] = password
        return cfg

    def _run_resolve(self, cfg: Config):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            # 读取被注入的 settings.xml 内容（resolve 会在 finally 中删除它）
            if "-s" in cmd:
                idx = cmd.index("-s")
                settings_path = cmd[idx + 1]
                with open(settings_path, encoding="utf-8") as f:
                    captured["settings"] = f.read()
            return _FakeMvnOut()

        resolver = MvnTreeResolver(cfg)
        with patch("dtrack.analyzers.java.maven_resolver.subprocess.run", side_effect=fake_run):
            resolver.resolve(os.getcwd())
        return captured

    def test_custom_central_injects_settings_mirror(self):
        cfg = self._cfg_with_central("https://nexus.corp.local/repository/maven-public")
        cap = self._run_resolve(cfg)
        self.assertIn("-s", cap["cmd"], "应注入 -s <settings.xml>")
        self.assertIn("<mirrorOf>*</mirrorOf>", cap["settings"])
        self.assertIn("https://nexus.corp.local/repository/maven-public", cap["settings"])

    def test_default_central_does_not_inject_settings(self):
        cfg = self._cfg_with_central("https://repo1.maven.org/maven2")
        cap = self._run_resolve(cfg)
        self.assertNotIn("-s", cap["cmd"], "默认 central 不应注入额外 settings")

    def test_empty_central_does_not_inject_settings(self):
        cfg = self._cfg_with_central("")
        cap = self._run_resolve(cfg)
        self.assertNotIn("-s", cap["cmd"])

    def test_private_repo_credentials_injected_into_servers(self):
        cfg = self._cfg_with_central(
            "https://nexus.corp.local/repository/maven-private",
            username="mavenuser", password="s3cret",
        )
        cap = self._run_resolve(cfg)
        self.assertIn("-s", cap["cmd"])
        settings = cap["settings"]
        self.assertIn("<servers>", settings)
        self.assertIn("<id>dtrack-central</id>", settings)
        self.assertIn("<username>mavenuser</username>", settings)
        self.assertIn("<password>s3cret</password>", settings)

    def test_no_credentials_when_username_missing(self):
        cfg = self._cfg_with_central("https://nexus.corp.local/repository/maven-public")
        cap = self._run_resolve(cfg)
        self.assertIn("-s", cap["cmd"])
        self.assertNotIn("<servers>", cap["settings"])


class _FakeMvnOut:
    """Minimal stand-in for subprocess.CompletedProcess (stdout/stderr as text)."""
    def __init__(self, returncode: int = 0):
        self.stdout = ""
        self.stderr = ""
        self.returncode = returncode


class TestMvnTreeMultiModule(unittest.TestCase):
    """聚合父 POM 含 <modules> 时，缺失子模块应自动使用 -N 非递归模式。"""

    PARENT_POM = """<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>child-a</module>
    <module>child-b</module>
  </modules>
</project>"""

    CHILD_POM = """<project>
  <groupId>com.example</groupId>
  <artifactId>child</artifactId>
  <version>1.0</version>
</project>"""

    def _write(self, path: str, content: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def test_missing_module_uses_non_recursive(self):
        """子模块缺失时直接带 -N 运行，避免 Maven reactor 报错。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._write(os.path.join(tmp, "pom.xml"), self.PARENT_POM)
            # 只保留 child-a，child-b 缺失
            self._write(os.path.join(tmp, "child-a", "pom.xml"), self.CHILD_POM)

            cfg = Config(copy.deepcopy(DEFAULT_CONFIG))
            resolver = MvnTreeResolver(cfg)
            captured = {}

            def fake_run(cmd, **kwargs):
                captured["cmd"] = list(cmd)
                return _FakeMvnOut(0)

            with patch("dtrack.analyzers.java.maven_resolver.subprocess.run", side_effect=fake_run):
                resolver.resolve(tmp)

            self.assertIn("-N", captured["cmd"])
            # -N 应出现在 mvn 之后、goal 之前
            self.assertLess(captured["cmd"].index("-N"), captured["cmd"].index("dependency:tree"))

    def test_all_modules_present_runs_recursive(self):
        """所有子模块都存在时保持默认递归模式（不带 -N）。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._write(os.path.join(tmp, "pom.xml"), self.PARENT_POM)
            self._write(os.path.join(tmp, "child-a", "pom.xml"), self.CHILD_POM)
            self._write(os.path.join(tmp, "child-b", "pom.xml"), self.CHILD_POM)

            cfg = Config(copy.deepcopy(DEFAULT_CONFIG))
            resolver = MvnTreeResolver(cfg)
            captured = {}

            def fake_run(cmd, **kwargs):
                captured["cmd"] = list(cmd)
                return _FakeMvnOut(0)

            with patch("dtrack.analyzers.java.maven_resolver.subprocess.run", side_effect=fake_run):
                resolver.resolve(tmp)

            self.assertNotIn("-N", captured["cmd"])

    def test_retry_non_recursive_when_reactor_fails(self):
        """即使未预检测到缺失模块，Maven 报错包含 missing child module 时也应重试 -N。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._write(os.path.join(tmp, "pom.xml"), self.PARENT_POM)
            self._write(os.path.join(tmp, "child-a", "pom.xml"), self.CHILD_POM)
            self._write(os.path.join(tmp, "child-b", "pom.xml"), self.CHILD_POM)

            cfg = Config(copy.deepcopy(DEFAULT_CONFIG))
            resolver = MvnTreeResolver(cfg)
            calls = []

            def fake_run(cmd, **kwargs):
                calls.append(list(cmd))
                if "-N" not in cmd:
                    err = _FakeMvnOut(1)
                    err.stderr = "[ERROR] Child module child-b of ... does not exist"
                    return err
                return _FakeMvnOut(0)

            with patch("dtrack.analyzers.java.maven_resolver.subprocess.run", side_effect=fake_run):
                resolver.resolve(tmp)

            self.assertEqual(len(calls), 2)
            self.assertNotIn("-N", calls[0])
            self.assertIn("-N", calls[1])

    def test_non_aggregator_no_non_recursive_flag(self):
        """普通 jar 工程不应被添加 -N。"""
        with tempfile.TemporaryDirectory() as tmp:
            self._write(os.path.join(tmp, "pom.xml"), """<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0</version>
  <packaging>jar</packaging>
</project>""")

            cfg = Config(copy.deepcopy(DEFAULT_CONFIG))
            resolver = MvnTreeResolver(cfg)
            captured = {}

            def fake_run(cmd, **kwargs):
                captured["cmd"] = list(cmd)
                return _FakeMvnOut(0)

            with patch("dtrack.analyzers.java.maven_resolver.subprocess.run", side_effect=fake_run):
                resolver.resolve(tmp)

            self.assertNotIn("-N", captured["cmd"])


if __name__ == "__main__":
    unittest.main()
