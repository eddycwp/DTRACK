"""Lightweight HTTP client (stdlib only) with retries, timeouts and optional TLS skip."""
from __future__ import annotations

import base64
import json
import ssl
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional


def basic_auth_header(username: Optional[str], password: Optional[str]) -> dict[str, str]:
    """构造 HTTP Basic 鉴权头。"""
    token = base64.b64encode(f"{username or ''}:{password or ''}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


@dataclass
class HttpResponse:
    status: int
    content: bytes
    url: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.text) if self.text else None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def _build_multipart(
    fields: Optional[dict[str, str]] = None,
    files: Optional[list[tuple[str, str, bytes, Optional[str]]]] = None,
) -> tuple[bytes, str]:
    """Build a ``multipart/form-data`` body.

    Returns ``(body_bytes, content_type)``. ``files`` is a list of
    ``(field_name, filename, content_bytes, mime_type)``.
    """
    boundary = "----DTrackBoundary" + uuid.uuid4().hex
    chunks: list[bytes] = []
    for key, val in (fields or {}).items():
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        chunks.append(str(val).encode("utf-8"))
        chunks.append(b"\r\n")
    for (name, filename, content, mime) in (files or []):
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode("utf-8")
        )
        chunks.append(f"Content-Type: {mime or 'application/octet-stream'}\r\n\r\n".encode("utf-8"))
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(chunks)
    return body, f"multipart/form-data; boundary={boundary}"


class HttpClient:
    def __init__(
        self,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 1.0,
        verify_ssl: bool = True,
        headers: Optional[dict[str, str]] = None,
        user_agent: str = "DTrack/0.1",
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.verify_ssl = verify_ssl
        self.headers = dict(headers or {})
        self.headers.setdefault("User-Agent", user_agent)

    def _context(self) -> ssl.SSLContext:
        if self.verify_ssl:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> HttpResponse:
        return self.request("GET", url, params=params, headers=headers)

    def post(self, url: str, headers: Optional[dict] = None, data: Optional[bytes] = None,
             json_body: Any = None) -> HttpResponse:
        return self.request("POST", url, headers=headers, data=data, json_body=json_body)

    def post_multipart(
        self,
        url: str,
        fields: Optional[dict[str, str]] = None,
        files: Optional[list[tuple[str, str, bytes, Optional[str]]]] = None,
        headers: Optional[dict] = None,
    ) -> HttpResponse:
        """POST ``multipart/form-data`` (used by QIANXIN binary/image file uploads).

        ``files`` is a list of ``(field_name, filename, content_bytes, mime_type)``.
        ``fields`` are plain text form fields. Returns the standard ``HttpResponse``.
        """
        body, content_type = _build_multipart(fields, files)
        h = dict(self.headers)
        h["Content-Type"] = content_type
        if headers:
            h.update(headers)
        return self.request("POST", url, headers=h, data=body)

    def request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        data: Optional[bytes] = None,
        json_body: Any = None,
    ) -> HttpResponse:
        if params:
            qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
            url = url + ("&" if "?" in url else "?") + qs
        if json_body is not None and data is None:
            data = json.dumps(json_body).encode("utf-8")
            h = dict(self.headers)
            h.setdefault("Content-Type", "application/json")
        else:
            h = dict(self.headers)
        if headers:
            h.update(headers)

        last_err: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            req = urllib.request.Request(url, data=data, method=method.upper())
            for k, v in h.items():
                req.add_header(k, v)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._context()) as resp:
                    content = resp.read()
                    return HttpResponse(
                        status=resp.status,
                        content=content,
                        url=url,
                        headers={k.lower(): v for k, v in resp.getheaders()},
                    )
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")
                # 4xx (except 429) should not be retried
                if 400 <= e.code < 500 and e.code != 429:
                    return HttpResponse(status=e.code, content=body.encode("utf-8", "replace"), url=url)
                last_err = e
            except Exception as e:  # noqa: BLE001 - network errors are retryable
                last_err = e
            if attempt < self.retries:
                time.sleep(self.backoff * attempt)
        # Exhausted retries
        status = getattr(last_err, "code", 0) if isinstance(last_err, urllib.error.HTTPError) else 0
        raw = getattr(last_err, "read", lambda: b"")()
        if not isinstance(raw, bytes):
            raw = str(raw).encode("utf-8", "replace")
        if status == 0:
            raw = str(last_err).encode("utf-8", "replace")
        return HttpResponse(status=status or 0, content=raw, url=url)
