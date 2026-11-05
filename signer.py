"""RUSOCIAL remote signing. This package contains no private signing implementation."""
from __future__ import annotations

import json
import re

from .errors import SignerError, TransportError
from .models import DeviceProfile, SessionInfo, SigningRequest
from .transport import HttpTransport, checked_origin

DEFAULT_SIGNER_URL = "https://free.rusocial.io"


class SigningClient:
    def __init__(self, api_key: str, *, base_url: str = DEFAULT_SIGNER_URL, timeout: float = 30, transport=None):
        if not isinstance(api_key, str) or not api_key.strip() or any(c in api_key for c in "\r\n\x00"):
            raise ValueError("A nonempty RUSOCIAL API key is required")
        self._api_key = api_key
        self.base_url = checked_origin(base_url)
        self.timeout = timeout
        self._transport = transport or HttpTransport()
        self._owns_transport = transport is None

    def sign_request(self, request: SigningRequest) -> str:
        body = json.dumps(request.to_dict(), separators=(",", ":"), allow_nan=False).encode("utf-8")
        response = self._transport.request("POST", self.base_url + "/api/sign", body=body, timeout=self.timeout,
                                           headers={"X-API-Key": self._api_key, "Content-Type": "application/json", "Accept": "application/json"})
        if not 200 <= response.status < 300:
            code = "signing_failed"
            try:
                candidate = response.json().get("code", code)
                if isinstance(candidate, str) and re.fullmatch(r"[a-z_]{1,64}", candidate):
                    code = candidate
            except (ValueError, AttributeError, TypeError):
                pass
            raise SignerError(response.status, code, retry_after=response.headers.get("retry-after"))
        try:
            token = response.json()["x-snapchat-att"]
        except (ValueError, TypeError, KeyError):
            raise TransportError("The signer returned an invalid response") from None
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
            raise TransportError("The signer did not return a URL-safe attestation token")
        return token

    def sign(self, path: str, device: DeviceProfile, session: SessionInfo, *, nonce: str | bytes | None = None) -> str:
        return self.sign_request(SigningRequest(device, session, path, nonce))

    def close(self):
        if self._owns_transport:
            self._transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self):
        return f"SigningClient(base_url={self.base_url!r})"
