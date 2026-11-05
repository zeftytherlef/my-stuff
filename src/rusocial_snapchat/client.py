"""Focused mobile client; actions construct and sign their own requests."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import uuid
import re

from .actions import EverydayActions
from .catalog import get_endpoint, supports_signing, validate_path
from .errors import ConfigurationError, PayloadError, RpcError
from .models import DeviceProfile, SessionInfo
from .session import ClientState
from .payloads import bind_attestation, encode_payload, request_strings
from .signer import DEFAULT_SIGNER_URL, SigningClient
from .transport import HttpTransport, checked_headers, checked_origin
from .unary_grpc import UnaryGrpcTransport


class SnapchatClient(EverydayActions):
    def __init__(self, api_key: str, device: DeviceProfile | None = None, *, session: SessionInfo | None = None,
                 signer_url: str = DEFAULT_SIGNER_URL, mobile_base_url: str | None = None,
                 grpc_target: str | None = None, headers=None,
                 country_code: str = 'US',
                 session_file: str | Path | None = None, timeout: float = 30,
                 http_transport=None, grpc_transport=None, signer_transport=None):
        state = ClientState.load(session_file) if session_file is not None and Path(session_file).exists() else None
        if state is not None and ((device is not None and device != state.device) or
                                  (session is not None and session != state.session)):
            raise ConfigurationError('Use the saved device/session or choose a new session_file.')
        self.device = device if device is not None else state.device if state else DeviceProfile.create()
        self.session = session if session is not None else state.session if state else SessionInfo.create()
        self._state = state if state is not None else ClientState(self.device, self.session)
        self._session_file = session_file
        self._pending_login = None
        self._login_keys = None
        self._login_identity = None
        self._login_attempts = 0
        self._authentication_session_id = str(uuid.uuid4())
        self._login_session_id = str(uuid.uuid4())
        self.timeout = timeout
        if not isinstance(country_code, str) or not re.fullmatch('[A-Z]{2}', country_code):
            raise ConfigurationError('country_code must be a two-letter uppercase country code, for example US.')
        self.country_code = country_code
        self.mobile_base_url = checked_origin(mobile_base_url or 'https://aws.api.snapchat.com')
        self.grpc_target = grpc_target
        self._headers = checked_headers(headers)
        self._http = http_transport or HttpTransport()
        self._owns_http = http_transport is None
        self._grpc = grpc_transport
        self._grpc_channels = {}
        self._signer = SigningClient(api_key, base_url=signer_url, timeout=timeout, transport=signer_transport)
        self._save_session()

    def _mobile_user_agent(self):
        # C40645u1g.a builds the release's version/device User-Agent.
        phone = self.device.phone
        phone.to_dict()
        return (f'Snapchat/12.08.0.29 ({phone.android_model}; Android '
                f'{phone.android_version}#{phone.android_incremental}#{phone.android_sdk}; gzip)')

    def _request(self, path, payload, *, headers=None, redact=()):
        endpoint = get_endpoint(path)
        validate_path(path)
        should_sign = supports_signing(path)
        if endpoint.attestation and not should_sign:
            raise PayloadError('This action requires a path supported by the remote signer.')
        outgoing = {k: v for k, v in endpoint.headers.items()
                    if not k.startswith('__') and k.lower() not in ('host', 'content-length', 'expect')}
        outgoing.update(self._headers)
        outgoing.update(checked_headers(headers))
        if not any(key.lower() == 'user-agent' for key in outgoing):
            outgoing['User-Agent'] = self._mobile_user_agent()
        if any(k.lower() == 'x-snapchat-att' for k in outgoing):
            raise PayloadError('Attestation is supplied by the configured remote signer')
        # Validate and encode before the remote signer consumes quota.
        body, content_type = encode_payload(endpoint, payload)
        attested_message = None
        if endpoint.attestation_field_path:
            from .messages import get_message_type
            attested_message = get_message_type(endpoint.request_type).from_bytes(body)
        transport = self._grpc
        if endpoint.transport == 'grpc' and transport is None:
            target = self.grpc_target or endpoint.grpc_target
            if not target:
                raise ConfigurationError('This action has no configured service host.')
            agent = next(v for k, v in outgoing.items() if k.lower() == 'user-agent')
            key = (target, agent)
            transport = self._grpc_channels.get(key)
            if transport is None:
                transport = UnaryGrpcTransport(target, user_agent=agent)
                self._grpc_channels[key] = transport
        if should_sign:
            outgoing['x-snapchat-att'] = self._signer.sign(path, self.device, self.session)
        if attested_message is not None:
            body = bind_attestation(attested_message, endpoint.attestation_field_path, outgoing['x-snapchat-att'])
        try:
            if endpoint.transport == 'http':
                if content_type:
                    outgoing = {k: v for k, v in outgoing.items() if k.lower() != 'content-type'}
                    outgoing['Content-Type'] = content_type
                response = self._http.request(endpoint.http_method, self.mobile_base_url + path,
                                              headers=outgoing, body=body, timeout=self.timeout)
                response.raise_for_status()
                return replace(response, response_type=endpoint.response_type)
            return transport.request(path, body, kind='unary_unary', headers=outgoing,
                                     timeout=self.timeout, response_type=endpoint.response_type)
        except RpcError as error:
            values = list(request_strings(attested_message if attested_message is not None else payload))
            values.extend(outgoing.values())
            values.extend(redact)
            values.append(self._signer._api_key)
            raise error.redacted(values, path=path) from None

    def close(self):
        self._signer.close()
        if self._owns_http:
            self._http.close()
        for channel in self._grpc_channels.values():
            channel.close()
        self._grpc_channels.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self):
        return "SnapchatClient(version='12.08.0.29')"
