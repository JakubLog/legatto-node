"""Minimal Cloudflare API v4 client for host-side tools (legatto-cf-bootstrap).

Always HTTPS through the host egress proxy (127.0.0.1:4750, CONNECT) and with
the pinned CA bundle as the only trust anchors. Tokens are sent only in the
Authorization header and never logged.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

API_BASE = "https://api.cloudflare.com/client/v4"


class CfError(Exception):
    def __init__(self, status: int, codes: list[int], message: str) -> None:
        super().__init__(message)
        self.status = status
        self.codes = codes


class CfClient:
    def __init__(self, token: str, ca_file: str, proxy: str | None, base: str = API_BASE) -> None:
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=context)]
        handlers.append(urllib.request.ProxyHandler({"https": proxy} if proxy else {}))
        self._opener = urllib.request.build_opener(*handlers)
        self._token = token
        self._base = base

    def call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(f"{self._base}{path}", data=data, method=method)
        request.add_header("Authorization", f"Bearer {self._token}")
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(request, timeout=60) as response:
                status = response.status
                raw = response.read()
        except urllib.error.HTTPError as err:
            status = err.code
            raw = err.read()
        except urllib.error.URLError as err:
            raise CfError(0, [], f"{method} {path}: {err.reason}") from None
        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError:
            raise CfError(status, [], f"{method} {path}: HTTP {status}, body is not JSON") from None
        if status >= 400 or not envelope.get("success"):
            errors = envelope.get("errors") or []
            codes = [int(e.get("code", 0)) for e in errors if isinstance(e, dict)]
            text = "; ".join(f"{e.get('code')} {e.get('message', '')}".strip() for e in errors if isinstance(e, dict))
            raise CfError(status, codes, f"{method} {path}: HTTP {status} {text}")
        return envelope.get("result")

    def list_all(self, path: str) -> list[Any]:
        """Follows page-number pagination (per_page 50)."""
        items: list[Any] = []
        page = 1
        sep = "&" if "?" in path else "?"
        while True:
            chunk = self.call("GET", f"{path}{sep}page={page}&per_page=50")
            if not isinstance(chunk, list):
                raise CfError(0, [], f"GET {path}: expected a list")
            items.extend(chunk)
            if len(chunk) < 50:
                return items
            page += 1
