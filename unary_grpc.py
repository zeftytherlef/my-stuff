"""Unary gRPC over HTTP/2 with an unmodified application User-Agent.

grpcio always appends its own User-Agent identifier. The mobile app supplies
its version/device header to Cronet; use hyper-h2 for unary calls so the header
we configure is the header we send. Streaming calls still use grpcio.
"""
from __future__ import annotations

import math
import re
import socket
import ssl
import time
import zlib
from urllib.parse import unquote, urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (ConnectionTerminated, DataReceived, ResponseReceived,
                       StreamEnded, StreamReset, TrailersReceived)
from h2.exceptions import H2Error

from .errors import ConfigurationError, RpcError, TransportError
from .transport import ApiResponse, checked_headers


_STATUS_NAMES = (
    'OK', 'CANCELLED', 'UNKNOWN', 'INVALID_ARGUMENT', 'DEADLINE_EXCEEDED',
    'NOT_FOUND', 'ALREADY_EXISTS', 'PERMISSION_DENIED', 'RESOURCE_EXHAUSTED',
    'FAILED_PRECONDITION', 'ABORTED', 'OUT_OF_RANGE', 'UNIMPLEMENTED',
    'INTERNAL', 'UNAVAILABLE', 'DATA_LOSS', 'UNAUTHENTICATED',
)
_HTTP_STATUS = {'400': 'INTERNAL', '401': 'UNAUTHENTICATED', '403': 'PERMISSION_DENIED',
                '404': 'UNIMPLEMENTED', '429': 'UNAVAILABLE', '502': 'UNAVAILABLE',
                '503': 'UNAVAILABLE', '504': 'UNAVAILABLE'}
_RESERVED = {'host', 'content-length', 'connection', 'transfer-encoding', 'te',
             'content-type', 'grpc-timeout', 'grpc-encoding', 'grpc-accept-encoding'}
_MAX_RESPONSE = 16 * 1024 * 1024


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _timeout_header(seconds):
    # gRPC permits at most eight digits. Round up to avoid shortening deadlines.
    for unit, scale in (('m', 1000), ('S', 1), ('M', 1 / 60), ('H', 1 / 3600)):
        count = math.ceil(seconds * scale)
        if count <= 99_999_999:
            return str(max(1, count)) + unit
    raise ConfigurationError('gRPC timeout is too large')


class UnaryGrpcTransport:
    """One TLS connection per request, verified certificates, no automatic retries.

    A custom SSLContext can supply a private CA for testing. It must still verify
    certificates and hostnames. The configured User-Agent is sent exactly once.
    """
    def __init__(self, target: str, *, user_agent=None, ssl_context=None):
        if not target or any(c in target for c in '/?#@\r\n'):
            raise ConfigurationError('grpc_target must be a host:port, without a URL scheme')
        try:
            parts = urlsplit('https://' + target)
            self._host, self._port = parts.hostname, parts.port or 443
            if not self._host or any(c.isspace() for c in target):
                raise ValueError
        except ValueError:
            raise ConfigurationError('grpc_target must be a valid host:port') from None
        self._authority = target
        self._user_agent = user_agent
        self._ssl = ssl_context if ssl_context is not None else ssl.create_default_context()
        if self._ssl.verify_mode != ssl.CERT_REQUIRED or not self._ssl.check_hostname:
            raise ConfigurationError('gRPC TLS must verify certificates and hostnames')
        self._ssl.set_alpn_protocols(['h2'])

    def request(self, path, payload, *, kind='unary_unary', headers=None, timeout=30, response_type=None):
        if kind != 'unary_unary':
            raise ConfigurationError('Use GrpcTransport for streaming RPCs')
        if not isinstance(payload, bytes):
            raise ConfigurationError('Unary gRPC requires serialized protobuf bytes')
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or timeout <= 0:
            raise ConfigurationError('gRPC timeout must be a positive finite number')
        outgoing = {}
        for key, value in checked_headers(headers).items():
            key = key.lower()
            if not re.fullmatch(r'[a-z0-9_.-]+', key) or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise ConfigurationError('gRPC metadata must use ASCII header names and values')
            if key not in _RESERVED:
                outgoing[key] = value
        if self._user_agent is not None and 'user-agent' not in outgoing:
            outgoing['user-agent'] = self._user_agent
        for key, value in outgoing.items():
            if not isinstance(value, str) or any(ord(c) < 32 or ord(c) > 126 for c in value):
                raise ConfigurationError('gRPC metadata must use ASCII header names and values')
        deadline = time.monotonic() + timeout
        try:
            with socket.create_connection((self._host, self._port), timeout=_remaining(deadline)) as raw:
                raw.settimeout(_remaining(deadline))
                with self._ssl.wrap_socket(raw, server_hostname=self._host) as connection:
                    if connection.selected_alpn_protocol() != 'h2':
                        raise TransportError('The server did not negotiate HTTP/2')
                    return self._exchange(connection, path, payload, outgoing, deadline, response_type)
        except TimeoutError:
            raise RpcError('DEADLINE_EXCEEDED', path=path) from None
        except (OSError, H2Error):
            raise TransportError('gRPC HTTP/2 connection failed') from None

    def _exchange(self, connection, path, payload, outgoing, deadline, response_type):
        h2 = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
        h2.initiate_connection()
        stream_id = h2.get_next_available_stream_id()
        headers = [(':method', 'POST'), (':scheme', 'https'), (':path', path),
                   (':authority', self._authority), ('te', 'trailers'),
                   ('content-type', 'application/grpc'),
                   ('grpc-timeout', _timeout_header(_remaining(deadline))),
                   ('grpc-accept-encoding', 'identity,gzip'), *outgoing.items()]
        h2.send_headers(stream_id, headers)
        framed = b'\x00' + len(payload).to_bytes(4, 'big') + payload
        sent = 0
        received = bytearray()
        initial, trailers = {}, {}
        ended = False
        while not ended:
            # Respect both connection and stream flow-control windows. Incoming
            # WINDOW_UPDATE events make progress possible for large requests.
            while sent < len(framed):
                amount = min(h2.local_flow_control_window(stream_id), h2.max_outbound_frame_size,
                             len(framed) - sent)
                if amount <= 0:
                    break
                h2.send_data(stream_id, framed[sent:sent + amount], end_stream=sent + amount == len(framed))
                sent += amount
            pending = h2.data_to_send()
            if pending:
                connection.settimeout(_remaining(deadline))
                connection.sendall(pending)
            connection.settimeout(_remaining(deadline))
            data = connection.recv(65536)
            if not data:
                raise TransportError('gRPC connection closed before response trailers')
            for event in h2.receive_data(data):
                if isinstance(event, ConnectionTerminated):
                    if not ended:
                        raise TransportError('gRPC connection terminated before the response completed')
                elif getattr(event, 'stream_id', None) == stream_id:
                    if isinstance(event, ResponseReceived):
                        initial.update(event.headers)
                    elif isinstance(event, TrailersReceived):
                        trailers.update(event.headers)
                    elif isinstance(event, DataReceived):
                        received.extend(event.data)
                        if len(received) > _MAX_RESPONSE + 5:
                            raise RpcError('RESOURCE_EXHAUSTED', details='gRPC response exceeds 16 MiB', path=path)
                        h2.acknowledge_received_data(event.flow_controlled_length, stream_id)
                    elif isinstance(event, StreamEnded):
                        ended = True
                    elif isinstance(event, StreamReset):
                        raise TransportError('gRPC response stream was reset')
        return self._response(path, initial, trailers, bytes(received), response_type)

    @staticmethod
    def _response(path, initial, trailers, framed, response_type):
        metadata = {**initial, **trailers}
        # Trailers-only failures are valid gRPC. Inspect status before the body;
        # an HTTP 200 alone never means a successful RPC.
        status = metadata.get('grpc-status')
        if status is None:
            code = _HTTP_STATUS.get(initial.get(':status'), 'UNKNOWN')
            raise RpcError(code, details='Server response is missing gRPC status', path=path)
        if not status.isascii() or not status.isdecimal() or not 0 <= int(status) < len(_STATUS_NAMES):
            raise RpcError('UNKNOWN', details='Server returned an invalid gRPC status', path=path)
        code = _STATUS_NAMES[int(status)]
        if code != 'OK':
            raise RpcError(code, details=unquote(metadata.get('grpc-message', '')) or None, path=path)
        content_type = initial.get('content-type', '').split(';', 1)[0].strip()
        if initial.get(':status') != '200' or not (content_type == 'application/grpc' or content_type.startswith('application/grpc+')):
            raise RpcError('INTERNAL', details='Invalid gRPC response headers', path=path)
        if len(framed) < 5 or framed[0] not in (0, 1) or int.from_bytes(framed[1:5], 'big') != len(framed) - 5:
            raise RpcError('INTERNAL', details='Expected exactly one complete gRPC response message', path=path)
        body = framed[5:]
        if framed[0]:
            if initial.get('grpc-encoding') != 'gzip':
                raise RpcError('UNIMPLEMENTED', details='Unsupported gRPC response compression', path=path)
            try:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                body = decoder.decompress(body, _MAX_RESPONSE + 1)
                if len(body) > _MAX_RESPONSE:
                    raise RpcError('RESOURCE_EXHAUSTED', details='gRPC response exceeds 16 MiB', path=path)
                if not decoder.eof or decoder.unused_data:
                    raise ValueError
            except (ValueError, zlib.error):
                raise RpcError('INTERNAL', details='Invalid compressed gRPC response', path=path) from None
        return ApiResponse(200, {k: v for k, v in metadata.items() if not k.startswith(':')}, body, response_type)

    def close(self):
        # Each request closes its own socket, including failures and timeouts.
        pass
