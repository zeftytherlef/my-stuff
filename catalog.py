"""Versioned endpoint inventory and the signer policy shipped with this release."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from types import MappingProxyType

from .errors import BlockedPathError, PayloadError


def _data(name):
    return json.loads(files("rusocial_snapchat").joinpath("data", name).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def policy():
    return _data("policy.json")


def validate_path(path: str):
    if not isinstance(path, str) or len(path) > 512 or not re.fullmatch(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path):
        raise PayloadError("Use an absolute request path without a host, query, fragments or encoded separators")
    if any(segment in (".", "..") for segment in path.split("/")):
        raise PayloadError("Path traversal is not allowed")
    if re.search(policy()["blocked_expression"], path, re.IGNORECASE):
        raise BlockedPathError("This endpoint is blocked by this service")


def validate_signing_path(path: str):
    validate_path(path)
    rules = policy()
    if not re.fullmatch(rules["path_expression"], path) and path not in rules["additional_paths"]:
        raise PayloadError("This path is outside the signer's supported mobile paths")


def supports_signing(path: str) -> bool:
    try:
        validate_signing_path(path)
        return True
    except PayloadError:
        return False


@dataclass(frozen=True)
class Endpoint:
    path: str
    service: str
    method: str
    transport: str
    encoding: str
    http_method: str | None
    request_type: str | None
    response_type: str | None
    rpc_kind: str | None = None
    grpc_target: str | None = None
    attestation_field_path: tuple[int, ...] = ()
    attestation: bool = False
    headers: dict = field(default_factory=dict, repr=False)
    source: dict = field(default_factory=dict)

    @property
    def signer_supported(self):
        return supports_signing(self.path)


@lru_cache(maxsize=1)
def endpoints() -> tuple[Endpoint, ...]:
    fields = Endpoint.__dataclass_fields__
    return tuple(Endpoint(**{k: (tuple(v) if k == "attestation_field_path" else MappingProxyType(v) if k in ("headers", "source") else v)
                              for k, v in item.items() if k in fields}) for item in _data("endpoints.json")["endpoints"])


@lru_cache(maxsize=1)
def endpoint_map():
    return MappingProxyType({endpoint.path: endpoint for endpoint in endpoints()})


def get_endpoint(path: str) -> Endpoint:
    try:
        return endpoint_map()[path]
    except KeyError:
        raise PayloadError("Path is not in the audited 12.08.0.29 catalog") from None


@lru_cache(maxsize=1)
def schemas():
    return _data("schemas.json")
