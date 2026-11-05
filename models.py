"""The exact public /api/sign contract, with UTC Unix millisecond timestamps."""
from __future__ import annotations

import base64
import re
import time
import uuid
import secrets
from dataclasses import dataclass, field

from .errors import PayloadError

DAY_MS = 86_400_000
CLOCK_TOLERANCE_MS = 30_000


def unix_time_ms() -> int:
    return time.time_ns() // 1_000_000


def _text(value, name, maximum, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise PayloadError(f"{name} must be a string of at most {maximum} characters without control characters")
    if not empty and not value.strip():
        raise PayloadError(f"{name} must be nonempty")


def _integer(value, name, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise PayloadError(f"{name} must be an integer between {lower} and {upper}")


@dataclass(frozen=True)
class PersistentInfo:
    android_id: str
    install_timestamp_ms: int
    dtoken1i: str = field(default="", repr=False)

    @classmethod
    def installed_now(cls, android_id: str, *, dtoken1i: str = "", margin_ms: int = CLOCK_TOLERANCE_MS):
        """Convenience for a new install. For an existing device, use its real install time."""
        _integer(margin_ms, "margin_ms", 0, DAY_MS)
        return cls(android_id, unix_time_ms() - margin_ms, dtoken1i)

    def to_dict(self, *, now_ms: int | None = None):
        now = unix_time_ms() if now_ms is None else now_ms
        if not isinstance(self.android_id, str) or not re.fullmatch(r"[0-9a-fA-F]{16}", self.android_id):
            raise PayloadError("android_id must contain exactly 16 hexadecimal characters")
        _integer(self.install_timestamp_ms, "install_timestamp_ms", 1, now + CLOCK_TOLERANCE_MS)
        _text(self.dtoken1i, "dtoken1i", 16_384, empty=True)
        if self.dtoken1i and not self.dtoken1i.startswith("00001:"):
            raise PayloadError('dtoken1i must start with "00001:" when nonempty')
        return {"androidId": self.android_id, "installTimestamp": self.install_timestamp_ms, "dtoken1i": self.dtoken1i}


@dataclass(frozen=True)
class PhoneInfo:
    android_version: str
    android_sdk: int
    android_model: str
    android_incremental: str

    def to_dict(self):
        if not isinstance(self.android_version, str) or not re.fullmatch(r"1[1-7]", self.android_version):
            raise PayloadError('android_version must be a string from "11" through "17"')
        _integer(self.android_sdk, "android_sdk", 30, 37)
        _text(self.android_model, "android_model", 128)
        _text(self.android_incremental, "android_incremental", 128)
        return {"androidVersion": self.android_version, "androidSDK": self.android_sdk,
                "androidModel": self.android_model, "androidIncremental": self.android_incremental}


@dataclass(frozen=True)
class DeviceProfile:
    persistent: PersistentInfo
    phone: PhoneInfo

    @classmethod
    def create(cls):
        """Create a consistent local Android client profile for a new installation.

        Supplying an existing DeviceProfile remains supported. This describes the
        client; it does not inspect or claim to be a connected physical phone.
        """
        return cls(PersistentInfo.installed_now(secrets.token_hex(8)),
                   PhoneInfo("13", 33, "Pixel 6", "TP1A.221005.002"))


@dataclass(frozen=True)
class SessionInfo:
    session_timestamp_ms: int
    session_id: str

    @classmethod
    def create(cls, *, margin_ms: int = CLOCK_TOLERANCE_MS):
        """Use UTC now minus one day and a 30-second latency/clock margin."""
        _integer(margin_ms, "margin_ms", 0, DAY_MS)
        return cls(unix_time_ms() - DAY_MS - margin_ms, str(uuid.uuid4()))

    def to_dict(self, *, now_ms: int | None = None):
        now = unix_time_ms() if now_ms is None else now_ms
        _integer(self.session_timestamp_ms, "session_timestamp_ms", 1, now - DAY_MS + CLOCK_TOLERANCE_MS)
        if not isinstance(self.session_id, str) or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", self.session_id):
            raise PayloadError("session_id must be a hyphenated UUID")
        return {"sessionTimestamp": self.session_timestamp_ms, "sessionId": self.session_id}


@dataclass(frozen=True)
class SigningRequest:
    device: DeviceProfile
    session: SessionInfo
    path: str
    nonce: str | bytes | None = field(default=None, repr=False)

    def to_dict(self):
        from .catalog import validate_signing_path
        validate_signing_path(self.path)
        now = unix_time_ms()
        result = {"persistent_info": self.device.persistent.to_dict(now_ms=now),
                  "phone_info": self.device.phone.to_dict(),
                  "session_info": self.session.to_dict(now_ms=now),
                  "snapchat_request_info": {"path": self.path}}
        if self.nonce is not None:
            nonce = base64.urlsafe_b64encode(self.nonce).decode().rstrip("=") if isinstance(self.nonce, bytes) else self.nonce
            _text(nonce, "nonce", 4096, empty=True)
            if not re.fullmatch(r"[A-Za-z0-9+/_=-]*", nonce):
                raise PayloadError("nonce must be Base64 or Base64url data")
            normalized = nonce.replace('-', '+').replace('_', '/')
            if '=' not in normalized:
                normalized += '=' * (-len(normalized) % 4)
            try:
                if len(normalized) % 4 or not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', normalized):
                    raise ValueError('Invalid Base64 padding')
                base64.b64decode(normalized, validate=True)
            except ValueError:
                raise PayloadError("nonce must be Base64 or Base64url data") from None
            result["pi_info"] = {"nonce": nonce}
        return result
