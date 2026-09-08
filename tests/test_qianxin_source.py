"""Tests for the QIANXIN vulnerability source."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from dtrack.config import Config
from dtrack.core.models import Component
from dtrack.core.types import Language
from dtrack.vuln.qianxin import QianxinSource


class _FakeResponse:
    def __init__(self, status: int, body: bytes, url: str = "http://test") -> None:
        self.status = status
        self.content = body
        self.url = url
        self.headers = {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self):
        import json
        return json.loads(self.content.decode("utf-8")) if self.content else None

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")


class TestQianxinSource(unittest.TestCase):
    def _source(self, **qianxin_overrides) -> QianxinSource:
        cfg = Config({
            "vuln": {
                "qianxin": {
                    "base_url": "https://10.131.122.120:80",
                    "auth_type": "basic",
                    "username": "user",
                    "password": "pass",
                    "verify_ssl": False,
                    **qianxin_overrides,
                }
            }
        })
        return QianxinSource(cfg)

    def test_default_api_path_is_used(self):
        src = self._source()
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, b'{"Code":1,"Data":{"vulnerabilityList":[]}}')
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            src.query(comp)
            called_url = client.get.call_args[0][0]
            self.assertTrue(called_url.endswith("/open-api/v3/component/vulnerability"))

    def test_page_size_default_is_20(self):
        src = self._source()
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, b'{"Code":1,"Data":{"vulnerabilityList":[]}}')
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            src.query(comp)
            params = client.get.call_args.kwargs.get("params", {})
            self.assertEqual(params.get("pageSize"), 20)

    def test_page_size_is_capped_at_20(self):
        src = self._source(page_size=100)
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, b'{"Code":1,"Data":{"vulnerabilityList":[]}}')
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            src.query(comp)
            params = client.get.call_args.kwargs.get("params", {})
            self.assertEqual(params.get("pageSize"), 20)

    def test_page_size_small_value_is_respected(self):
        src = self._source(page_size=10)
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, b'{"Code":1,"Data":{"vulnerabilityList":[]}}')
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            src.query(comp)
            params = client.get.call_args.kwargs.get("params", {})
            self.assertEqual(params.get("pageSize"), 10)

    def test_custom_api_path_override(self):
        src = self._source(api_path="/api/vuln/component/query")
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, b'{"Code":1,"Data":{"vulnerabilityList":[]}}')
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            src.query(comp)
            called_url = client.get.call_args[0][0]
            self.assertTrue(called_url.endswith("/api/vuln/component/query"))
            self.assertFalse(called_url.endswith("/open-api/v3/component/vulnerability"))

    def test_404_is_logged_and_returns_empty(self):
        src = self._source()
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(404, b"<html>404 Not Found</html>", url="https://10.131.122.120:80/open-api/v3/component/vulnerability?componentName=demo&versionNo=1.0.0&pageIndex=0&pageSize=50")
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            with self.assertLogs("dtrack", level="WARNING") as cm:
                result = src.query(comp)
            self.assertEqual(result, [])
            self.assertTrue(any("404" in msg for msg in cm.output))

    def test_uppercase_data_dict_parsed(self):
        """Original shape: {"Code":1,"Data":{"vulnerabilityList":[...]}}"""
        src = self._source()
        payload = (
            b'{"Code":1,"message":"SUCCESS","Data":{'
            b'"vulnerabilityList":[{"cve":"CVE-2021-44228",'
            b'"qaxOssId":"QAX-001","vulnerabilityName":"log4j2 RCE","level":1}]}}'
        )
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, payload)
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            result = src.query(comp)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].vuln_id, "CVE-2021-44228")
            self.assertEqual(result[0].severity.value, "critical")

    def test_lowercase_data_list_parsed(self):
        """Actual gateway shape: {"code":1,"data":[{"vulnerabilityList":[...]}, ...]}."""
        src = self._source()
        payload = (
            b'{"code":1,"message":"SUCCESS","data":['
            b'{"componentId":"1","componentName":"A","vulnerabilityList":['
            b'{"cve":"CVE-2021-44228","vulnerabilityName":"log4j2 RCE","level":1}]},'
            b'{"componentId":"2","componentName":"B","vulnerabilityList":['
            b'{"qaxOssId":"QAX-002","vulnerabilityName":"xxe","level":2}]}'
            b']}'
        )
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, payload)
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            result = src.query(comp)
            self.assertEqual(len(result), 2)

    def test_lowercase_data_dict_parsed(self):
        """Some gateways return {"code":1,"data":{"vulnerabilityList":[]}}."""
        src = self._source()
        payload = (
            b'{"code":1,"message":"SUCCESS","data":{'
            b'"vulnerabilityList":[{"cve":"CVE-2021-44228",'
            b'"vulnerabilityName":"log4j2 RCE","level":1}]}}'
        )
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, payload)
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            result = src.query(comp)
            self.assertEqual(len(result), 1)

    def test_failure_code_breaks_loop(self):
        src = self._source()
        with patch("dtrack.vuln.qianxin.HttpClient") as MockClient:
            client = MagicMock()
            client.get.return_value = _FakeResponse(200, b'{"code":0,"message":"auth failed"}')
            MockClient.return_value = client
            comp = Component(language=Language.JAVA, group="org.example", name="demo", version="1.0.0")
            result = src.query(comp)
            self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
