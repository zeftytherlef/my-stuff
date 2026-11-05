"""Internal encoders for the focused actions' form and protobuf requests."""
from __future__ import annotations

import json
import math
import base64
from urllib.parse import urlencode

from google.protobuf.message import Message

from .errors import PayloadError, TransportError
from .messages import ProtoMessage, get_message_type


def bind_attestation(message, field_path, token):
    """Insert the signer's decoded bytes into the source-declared login field."""
    target = message.fields
    for number in field_path[:-1]:
        target = getattr(target, f'f_{number}')
    try:
        raw = base64.b64decode(token + '=' * (-len(token) % 4), altchars=b'-_', validate=True)
    except (ValueError, TypeError):
        raise TransportError('The signer returned an invalid Base64 attestation token') from None
    if not raw:
        raise TransportError('The signer returned an empty attestation token')
    setattr(target, f'f_{field_path[-1]}', raw)
    return message.to_bytes()


def request_strings(value):
    """Values to redact from a server-provided diagnostic, never from requests."""
    if isinstance(value, ProtoMessage):
        value = value.fields
    if isinstance(value, Message):
        for descriptor, item in value.ListFields():
            repeated = descriptor.is_repeated if hasattr(descriptor, 'is_repeated') else descriptor.label == descriptor.LABEL_REPEATED
            yield from request_strings(list(item) if repeated else item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from request_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from request_strings(item)
    elif isinstance(value, str) and value:
        yield value
    elif isinstance(value, bytes) and value:
        yield base64.b64encode(value).decode('ascii')
        yield base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')
        yield value.hex()


def _json_value(value):
    if isinstance(value, dict):
        if any(not isinstance(k, str) for k in value):
            raise PayloadError("JSON object keys must be strings")
        return {k: _json_value(v) for k, v in value.items() if v is not None}
    if isinstance(value, (tuple, list)):
        return [_json_value(v) for v in value]
    if value is None or isinstance(value, (str, bool, int)) or isinstance(value, float) and math.isfinite(value):
        return value
    raise PayloadError("Use JSON-compatible payload values")


def _form_value(value):
    if isinstance(value, str):
        return value
    # Java Boolean.toString(), number.toString(), and Gson JSON for composites.
    return json.dumps(_json_value(value), separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def protobuf_bytes(payload, expected_type: str | None = None) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, ProtoMessage):
        if expected_type and payload.schema_name != expected_type:
            raise PayloadError("Protobuf request type does not match this endpoint")
        return payload.to_bytes()
    if isinstance(payload, dict) and expected_type:
        return get_message_type(expected_type)(**payload).to_bytes()
    raise PayloadError("Supply a protobuf model, wire-field dictionary or serialized bytes")


def encode_payload(endpoint, payload):
    if endpoint.encoding == "protobuf":
        return protobuf_bytes(payload, endpoint.request_type), "application/x-protobuf"
    if endpoint.encoding != "form" or not isinstance(payload, dict):
        raise PayloadError("This action requires named form fields")
    pairs = [(k, _form_value(v)) for k, v in sorted(payload.items()) if v is not None]
    return urlencode(pairs, encoding="utf-8").encode("ascii"), "application/x-www-form-urlencoded; charset=UTF-8"
