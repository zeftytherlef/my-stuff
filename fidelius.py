"""Local login key material matching the Android 12.08 Fidelius initializer.

UM5 generates a P-256 key pair; C11909Vv6 generates the 32-byte IWEK.
C20207eY6 serializes the public point, HMAC of its X.509 encoding, IWEK,
and protocol version. The EC private key stays local.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .messages import get_message_type


@dataclass(frozen=True)
class LoginKeys:
    wrapping_key: bytes = field(repr=False)
    private_key_der: bytes = field(repr=False)
    public_key_der: bytes = field(repr=False)

    @classmethod
    def create(cls):
        private = ec.generate_private_key(ec.SECP256R1())
        return cls(secrets.token_bytes(32),
            private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()),
            private.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo))

    def payload(self):
        public = serialization.load_der_public_key(self.public_key_der)
        point = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        # C1529Cui.a MACs the complete X.509 encoding, not the raw EC point.
        tag = hmac.new(self.wrapping_key, self.public_key_der, hashlib.sha256).digest()
        return get_message_type('C18015ct6')(f_2={
            'f_1': point, 'f_2': tag, 'f_3': self.wrapping_key, 'f_4': 9,
        })

    def to_state(self, server_keys=None):
        result = {name: base64.b64encode(value).decode('ascii') for name, value in (
            ('wrapping_key', self.wrapping_key), ('private_key_der', self.private_key_der),
            ('public_key_der', self.public_key_der))}
        result['version'] = 9
        if server_keys is not None:
            result['server_keys'] = base64.b64encode(server_keys.SerializeToString()).decode('ascii')
        return result
