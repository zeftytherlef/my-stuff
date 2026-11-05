"""HTTP and native HTTP/2 gRPC transports; no retries for state-changing requests."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .errors import ApiError, ConfigurationError, RpcError, TransportError


def checked_origin(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ConfigurationError("Use an HTTPS origin without credentials, a path, query or fragment")
    if parts.scheme == "http":
        try:
            loopback = ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:
            loopback = parts.hostname == "localhost"
        if not loopback:
            raise ConfigurationError("Plain HTTP is supported only for local testing")
    return value.rstrip("/")


def checked_headers(headers):
    result = {}
    for key, value in (headers or {}).items():
        if not isinstance(key, str) or not isinstance(value, str) or not key or any(c in key + value for c in "\r\n\x00"):
            raise ConfigurationError("Headers must be strings without control characters")
        result[key] = value
    return result


@dataclass(frozen=True)
class ApiResponse:
    status: int
    headers: dict[str, str] = field(repr=False)
    body: bytes = field(repr=False)
    response_type: str | None = None

    def json(self):
        return json.loads(self.body)

    @property
    def text(self):
        return self.body.decode("utf-8")

    def message(self, type_name: str | None = None):
        from .messages import get_message_type
        name = type_name or self.response_type
        if not name:
            raise ConfigurationError("No response schema is available; inspect body or provide type_name")
        return get_message_type(name).from_bytes(self.body)

    def raise_for_status(self):
        if not 200 <= self.status < 300:
            raise ApiError(self.status, retry_after=self.headers.get("retry-after"))
        return self


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward API keys or upstream auth tokens to redirect destinations.
        return None


class HttpTransport:
    def __init__(self):
        self._opener = build_opener(_NoRedirect())

    def request(self, method: str, url: str, *, headers=None, body: bytes | None = None, timeout: float = 30) -> ApiResponse:
        request = Request(url, data=body, headers=checked_headers(headers), method=method)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return ApiResponse(response.status, {k.lower(): v for k, v in response.headers.items()}, response.read())
        except HTTPError as error:
            return ApiResponse(error.code, {k.lower(): v for k, v in error.headers.items()}, error.read())
        except (URLError, OSError, TimeoutError):
            raise TransportError("HTTP connection failed") from None

    def close(self):
        pass
