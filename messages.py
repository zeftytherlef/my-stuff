"""Protobuf models with field numbers/types recovered from Java writeTo methods.

Use f_<wire_number> where an original proto field name is unavailable. Encoding
and decoding use Google's protobuf runtime, including unknown-field retention.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import Message

from .catalog import schemas
from .errors import PayloadError


@lru_cache(maxsize=1)
def _pool():
    fd = descriptor_pb2.FileDescriptorProto(name="snapchat_12_08_recovered.proto", package="recovered", syntax="proto2")
    definitions = {k: v for k, v in schemas().items() if v["kind"] == "protobuf"}
    for name, schema in definitions.items():
        message = fd.message_type.add(name=name)
        groups = {}
        for item in schema["fields"]:
            field = message.field.add(name=item["name"], number=item["number"])
            field.label = field.LABEL_REPEATED if item["repeated"] else field.LABEL_OPTIONAL
            field_type = item["type"]
            child = item.get("message_type")
            if field_type == "message" and child not in definitions:
                # Unknown nested schemas stay length-delimited bytes; no invented fields.
                field_type = "bytes"
            if field_type == "enum":
                field_type = "int32"  # Preserve unrecognised enum numbers, like the Java int storage.
            field.type = getattr(field, "TYPE_" + field_type.upper())
            if field_type == "message":
                field.type_name = ".recovered." + child
            if item.get("oneof"):
                group = item["oneof"]
                if group not in groups:
                    groups[group] = len(groups)
                    message.oneof_decl.add(name="choice_" + group)
                field.oneof_index = groups[group]
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fd)
    return pool


def _ensure_complete(name: str):
    schema = schemas().get(name)
    if not schema or schema["kind"] != "protobuf":
        raise PayloadError("No protobuf schema is available for this type; supply serialized bytes")
    if not schema["complete"]:
        raise PayloadError(f"{name} has an incomplete recovered schema; supply serialized bytes")
    return schema


def _assign(message, values):
    seen_groups = set()
    assigned = set()
    aliases = {f.get('argument', f['name']): f['name'] for f in schemas()[message.DESCRIPTOR.name]['fields']}
    for key, value in values.items():
        key = aliases.get(key, key)
        if key in assigned:
            raise PayloadError(f'Field {key} was supplied twice')
        assigned.add(key)
        field = message.DESCRIPTOR.fields_by_name.get(key)
        if field is None:
            raise PayloadError(f"Unknown protobuf field {key}")
        if field.containing_oneof:
            group = field.containing_oneof.name
            if group in seen_groups:
                raise PayloadError("Only one field in each protobuf oneof may be set")
            seen_groups.add(group)
        if value is None:
            raise PayloadError("Omit unset protobuf fields instead of passing None")
        # protobuf 5 exposes label; protobuf 7 replaces it with is_repeated.
        is_repeated = field.is_repeated if hasattr(field, "is_repeated") else field.label == field.LABEL_REPEATED
        if is_repeated and not isinstance(value, (list, tuple)):
            raise PayloadError(f"{key} must be a list or tuple")
        if field.type == field.TYPE_MESSAGE:
            child_name = field.message_type.name
            items = value if is_repeated else [value]
            for item in items:
                target = getattr(message, key).add() if is_repeated else getattr(message, key)
                if isinstance(item, ProtoMessage):
                    if item.schema_name != child_name:
                        raise PayloadError("Nested protobuf type does not match the source schema")
                    target.CopyFrom(item._message)
                elif isinstance(item, Message):
                    if item.DESCRIPTOR.full_name != field.message_type.full_name:
                        raise PayloadError('Nested protobuf type does not match the source schema')
                    target.ParseFromString(item.SerializeToString())
                elif isinstance(item, dict):
                    _ensure_complete(child_name)
                    # An explicitly supplied empty message is present on the
                    # wire. Janus includes an empty configuration-ID message.
                    target.SetInParent()
                    _assign(target, item)
                elif isinstance(item, (bytes, bytearray)):
                    target.ParseFromString(bytes(item))
                else:
                    raise PayloadError("Nested messages must be models, field dictionaries or serialized bytes")
        else:
            items = value if is_repeated else [value]
            for item in items:
                if field.type == field.TYPE_BOOL and type(item) is not bool:
                    raise PayloadError(f"{key} must be a bool")
                if field.type in (field.TYPE_INT32, field.TYPE_INT64, field.TYPE_UINT32, field.TYPE_UINT64,
                                  field.TYPE_SINT32, field.TYPE_SINT64, field.TYPE_FIXED32, field.TYPE_FIXED64,
                                  field.TYPE_SFIXED32, field.TYPE_SFIXED64) and type(item) is not int:
                    raise PayloadError(f"{key} must be an integer")
            try:
                if is_repeated:
                    getattr(message, key).extend(value)
                else:
                    setattr(message, key, value)
            except (TypeError, ValueError, OverflowError):
                raise PayloadError(f"Value for {key} does not match its protobuf wire type") from None


class ProtoMessage:
    schema_name: str = ""

    def __init__(self, **values: Any):
        _ensure_complete(self.schema_name)
        self._message = message_factory.GetMessageClass(_pool().FindMessageTypeByName("recovered." + self.schema_name))()
        _assign(self._message, values)

    def to_bytes(self) -> bytes:
        return self._message.SerializeToString(deterministic=True)

    def SerializeToString(self, **kwargs) -> bytes:
        return self._message.SerializeToString(**kwargs)

    @classmethod
    def from_bytes(cls, data: bytes):
        obj = cls.__new__(cls)
        ProtoMessage.__init__(obj)
        try:
            obj._message.ParseFromString(data)
        except Exception as error:
            from google.protobuf.message import DecodeError
            if isinstance(error, DecodeError):
                raise PayloadError("Malformed protobuf response") from None
            raise
        return obj

    @property
    def fields(self):
        """The underlying Google protobuf object, with f_<number> attributes."""
        return self._message

    @classmethod
    def schema(cls):
        return schemas()[cls.schema_name]

    def __repr__(self):
        return f"{self.schema_name}(<protobuf payload>)"


@lru_cache(maxsize=None)
def get_message_type(name: str) -> type[ProtoMessage]:
    _ensure_complete(name)
    return type(name, (ProtoMessage,), {"schema_name": name, "__module__": __name__,
                                       "__doc__": f"Recovered protobuf message {name}; see docs.html for wire fields."})


def __getattr__(name):
    try:
        return get_message_type(name)
    except PayloadError:
        raise AttributeError(name) from None


class PasswordLoginRequest(ProtoMessage):
    """LoginWithPassword: identity oneof 1/2/3, password 4, attempt count 5.

    Context fields 7 (fidelius), 8 (COF configuration) and 15 (request context) must come from
    your mobile session. The source does not prove a minimal login will succeed.
    """
    schema_name = "C42513vR9"

    def __init__(self, identity: str, password: str, *, identity_type: str = "username",
                 attempt_count: int = 0, fidelius=None, configuration=None, context=None, device=None):
        identity_field = {"username": "f_1", "email": "f_2", "phone": "f_3"}.get(identity_type)
        if not identity_field:
            raise PayloadError("identity_type must be username, email or phone")
        values = {identity_field: identity, "f_4": password, "f_5": attempt_count}
        if device is not None and configuration is not None:
            raise PayloadError('Use configuration for field 8; do not supply both aliases.')
        for number, value in ((7, fidelius), (8, configuration if configuration is not None else device), (15, context)):
            if value is not None:
                values[f"f_{number}"] = value
        super().__init__(**values)
