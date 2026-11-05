"""Everyday operations: callers supply usernames and passwords, not wire fields."""
from __future__ import annotations

import re
import uuid
from dataclasses import replace

from .errors import ActionError, AuthenticationError, LoginChallenge, PayloadError
from .messages import PasswordLoginRequest, get_message_type
from .models import unix_time_ms
from .session import AccessToken, Account, ActionResult, Friend
from .fidelius import LoginKeys
from .social import SocialActions, _string
from .messaging import MessagingActions

API_SCOPE = "https://auth.snapchat.com/snap_token/api/api-gateway"
LOGIN_PATH = "/snapchat.janus.api.LoginService/LoginWithPassword"
VERIFY_PATH = "/snapchat.janus.api.LoginService/VerifyTwoFA"

# C12281Wn0 maps password-login statuses 12/13/14 to classifications
# 1/2/8; AbstractC18655dN5.C names those classifications. These numbers
# belong to C43834wR9 and must not be reused for other response types.
_PASSWORD_LOGIN_ERRORS = {
    12: ('account_not_found_or_invalid_password', 'Account not found or password incorrect'),
    13: ('account_not_found', 'Snapchat could not find this account'),
    14: ('invalid_password', 'Invalid password for this username or email'),
}


def _text(value, label, maximum=512):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise PayloadError(f"Enter a valid {label}.")
    return value


def _field(message, number, default=None):
    name = f"f_{number}"
    descriptor = message.DESCRIPTOR.fields_by_name.get(name)
    if descriptor is None or not message.HasField(name):
        return default
    return getattr(message, name)


class EverydayActions(SocialActions, MessagingActions):
    @property
    def me(self) -> Account | None:
        """The signed-in account, without credentials or tokens."""
        return self._state.account

    @property
    def is_logged_in(self) -> bool:
        return self.me is not None

    def _save_session(self):
        self._state.device, self._state.session = self.device, self.session
        if self._session_file is not None:
            self._state.save(self._session_file)

    def save_session(self, path=None):
        """Optionally keep this login for next time. Passwords and API keys are never saved."""
        if path is not None:
            self._session_file = path
        if self._session_file is None:
            raise PayloadError("Choose a session file, for example save_session('my-session.json').")
        self._save_session()

    def _login_context(self):
        # C22908gb2 constructs these fields from stable IDs and the current
        # request. The remote signer's raw attestation is inserted into field 11
        # immediately before sending, after local validation has succeeded.
        return get_message_type('C39809tO9')(
            f_1=self._state.device_id, f_2=self._login_session_id,
            f_3=self._authentication_session_id,
            f_5=str(uuid.uuid4()), f_6=self._state.instance_id,
            f_7={},
        )

    def _login_configuration(self):
        # C28468ko0.d: field 1 is the routing tag, field 2 is the COF etag.
        return get_message_type('C22550gK2')(
            f_1=self._state.cof_routing_tag, f_2=self._state.cof_etag)

    def _login_fidelius(self):
        if self._login_keys is None:
            self._login_keys = LoginKeys.create()
        return self._login_keys.payload()

    def login(self, username: str, password: str) -> Account:
        """Log in with a username, email address or international phone number.

        Device IDs, session timestamps, protobuf fields and remote signing are
        managed internally. Raises LoginChallenge if Snapchat asks for a code
        or other verification, and AuthenticationError on a rejected login.
        """
        identity = _text(username, 'username, email address or phone number')
        password = _text(password, 'password', 4096)
        identity_type = 'email' if '@' in identity else 'phone' if re.fullmatch(r'\+\d+', identity) else 'username'
        if self._login_identity != identity or self._login_attempts == 0:
            # C43813wQ9.onStartLogin -> VQ9.h(VQ9.d()). Keep this ID during
            # retries and VerifyTwoFA, and begin a new flow for another login.
            self._login_session_id = str(uuid.uuid4())
        self._login_attempts = self._login_attempts + 1 if self._login_identity == identity else 1
        self._login_identity = identity
        self._pending_login = None
        self._login_keys = LoginKeys.create()
        payload = PasswordLoginRequest(identity, password, identity_type=identity_type,
            attempt_count=self._login_attempts, fidelius=self._login_fidelius(),
            configuration=self._login_configuration(), context=self._login_context())
        response = self._request(LOGIN_PATH, payload)
        return self._finish_login(response, identity)

    def verify_login(self, code: str, *, method: str = 'authenticator') -> Account:
        """Complete a two-factor challenge raised by login()."""
        code = _text(code, 'verification code', 128)
        if self._pending_login is None:
            raise AuthenticationError('Call login() before entering a verification code.')
        # EnumC19224do0 / C14529aFd: SMS=1, OTP=2.
        methods = {'sms': 1, 'authenticator': 2}
        if method not in methods:
            raise PayloadError("Choose method='sms' or method='authenticator'.")
        pending = self._pending_login
        payload = get_message_type('XJi')(
            f_1=pending['token'], f_2=methods[method], f_3=code, f_4=False,
            f_5=self._login_fidelius(),
            f_6=self._login_configuration(), f_15=self._login_context())
        return self._finish_login(self._request(VERIFY_PATH, payload), pending['identity'])

    def _finish_login(self, response, identity):
        root = response.message().fields
        status = _field(root, 1, 0)
        if status != 1:
            if status == 2 and response.response_type == 'C43834wR9' and _field(root, 3) is not None:
                challenge = root.f_3 if hasattr(root.f_3, 'DESCRIPTOR') else get_message_type('L3i').from_bytes(root.f_3).fields
                methods = tuple(name for number, name in ((2, 'sms'), (3, 'authenticator')) if _field(challenge, number, False))
                token = _field(challenge, 1, '')
                if token:
                    self._pending_login = {'identity': identity, 'token': token}
                raise LoginChallenge('two_factor_verification', status, methods=methods)
            # Server decisions are surfaced, never silently interpreted as a login.
            if status in (3, 4, 5, 6, 7):
                raise LoginChallenge('additional_verification', status)
            if response.response_type == 'C43834wR9' and status in _PASSWORD_LOGIN_ERRORS:
                code, explanation = _PASSWORD_LOGIN_ERRORS[status]
                raise AuthenticationError(f'{explanation} (Snapchat login status {status}).',
                                          status=status, code=code)
            raise AuthenticationError(f'Snapchat rejected the login (status {status}).',
                                      status=status, code='login_rejected')
        success_bytes = _field(root, 2)
        if success_bytes is None:
            raise AuthenticationError('Snapchat returned an incomplete login response.')
        success = success_bytes if hasattr(success_bytes, 'DESCRIPTOR') else get_message_type('C2856Fg1').from_bytes(success_bytes).fields
        user = _field(success, 1)
        if user is None or not _field(user, 1, ''):
            raise AuthenticationError('Snapchat did not return an account ID.')
        username = _field(user, 2, '') or identity
        session = _field(user, 6)
        if session is None or not (_field(session, 1, '') or len(session.f_2)):
            raise AuthenticationError('Snapchat did not return session tokens. The login was not saved.')
        self._state.account = Account(username, user.f_1)
        self._state.access_tokens.clear()
        self._state.friends.clear()
        self._state.friend_records.clear()
        self._state.added_friend_records.clear()
        self._state.friends_sync_token = ''
        self._state.added_friends_sync_token = ''
        self._state.quick_adds_updated_at_ms = 0
        self._state.refresh_token = _field(session, 1, '') if session is not None else ''
        if self._login_keys is not None:
            self._state.fidelius_keys = self._login_keys.to_state(_field(success, 6))
        if session is not None:
            self._remember_tokens(session.f_2, _field(session, 4))
        device_info = _field(success, 7)
        token_info = _field(device_info, 1) if device_info is not None else None
        device_token = _field(token_info, 1, '') if token_info is not None else ''
        if device_token.startswith('00001:'):
            self.device = replace(self.device, persistent=replace(self.device.persistent, dtoken1i=device_token))
        self._pending_login = None
        self._login_attempts = 0
        self._save_session()
        return self.me

    def _remember_tokens(self, tokens, timing=None):
        # SZf.a: AEf fields are token, scope, lifetime in seconds. EEf field 1
        # accounts for server age; the value is not an absolute Unix timestamp.
        now = unix_time_ms()
        age = _field(timing, 1, 0) if timing is not None else 0
        for token in tokens:
            value, scope = _field(token, 1, ''), _field(token, 2, '')
            if scope and value:
                ttl = _field(token, 3)
                expires = now + max(0, ttl - age) * 1000 if ttl is not None else 0
                self._state.access_tokens[scope] = AccessToken(value, expires)
                if scope == 'https://auth.snapchat.com/snap_token/api/multi-scope' and API_SCOPE not in self._state.access_tokens:
                    self._state.access_tokens[API_SCOPE] = AccessToken(value, expires)

    def _require_login(self):
        if not self.is_logged_in:
            raise AuthenticationError('Log in first with client.login(username, password).')

    def _access_token(self):
        self._require_login()
        token = self._state.access_tokens.get(API_SCOPE)
        if token and (not token.expires_at_ms or token.expires_at_ms > unix_time_ms() + 30_000):
            return token.value
        if not self._state.refresh_token:
            raise AuthenticationError('This session has no API access token. Log in again.')
        request = get_message_type('FEf')(f_1=self._state.refresh_token, f_2=[API_SCOPE])
        response = self._request('/snap_token/pb/snap_access_tokens', request).message().fields
        self._remember_tokens(response.f_1, _field(response, 3))
        token = self._state.access_tokens.get(API_SCOPE)
        if token is None or token.expires_at_ms and token.expires_at_ms <= unix_time_ms():
            raise AuthenticationError('Snapchat did not return an API access token. Log in again.')
        self._save_session()
        return token.value

    def _account_payload(self, **values):
        self._require_login()
        return {'username': self.me.username, 'snapchat_user_id': self.me.user_id,
                'timestamp': str(unix_time_ms() // 60_000 * 60_000), **values}

    def _account_request(self, path, payload):
        response = self._request(path, payload, headers={'X-Snap-Access-Token': self._access_token()})
        if not response.body:
            return {}
        result = response.json()
        if not isinstance(result, dict):
            raise ActionError('Snapchat returned an unexpected response.')
        if result.get('logged') is False or result.get('success') is False:
            raise ActionError('Snapchat did not accept this action.')
        return result

    @staticmethod
    def _friend(value, fallback=''):
        if not isinstance(value, dict):
            return Friend(fallback)
        if isinstance(value.get('friend'), dict):
            value = value['friend']
        return Friend(_string(value, 'mutable_username', 'name', 'username') or fallback,
                      _string(value, 'user_id'), _string(value, 'display', 'display_name'))

    def search_users(self, query: str) -> list[Friend]:
        result = self._account_request('/loq/find_users', self._account_payload(query_text=_text(query, 'search text')))
        items = result.get('results', result.get('users', result.get('friends', [])))
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ActionError('Snapchat returned an invalid search result.')
        return [self._friend(item) for item in items]

    def _friend_action(self, action, username):
        self._require_login()
        friend = username if isinstance(username, Friend) else self._state.friends.get(
            _text(username, 'friend username'), Friend(username))
        values = {'action': action, 'friend': friend.username}
        if action == 'add':
            values['added_by'] = 'ADDED_BY_USERNAME'
        if friend.user_id:
            values['friend_id'] = friend.user_id
        result = self._account_request('/bq/friend', self._account_payload(**values))
        resolved = self._friend(result.get('object'), friend.username)
        resolved = replace(resolved, user_id=resolved.user_id or friend.user_id,
                           display_name=resolved.display_name or friend.display_name)
        if action == 'add':
            self._state.friends.pop(friend.username, None)
            record = self._state.friend_records.pop(friend.username, {})
            record.update(name=resolved.username, user_id=resolved.user_id, display=resolved.display_name)
            if 'mutable_username' in record:
                record['mutable_username'] = resolved.username
            self._state.friend_records[resolved.username] = record
            self._state.friends[resolved.username] = resolved
        elif action in ('delete', 'block'):
            self._state.friends.pop(friend.username, None)
            self._state.friend_records.pop(friend.username, None)
        self._save_session()
        return ActionResult(action, resolved)

    def add_friend(self, username: str | Friend) -> ActionResult:
        return self._friend_action('add', username)

    def remove_friend(self, username: str | Friend) -> ActionResult:
        return self._friend_action('delete', username)

    def block_friend(self, username: str | Friend) -> ActionResult:
        return self._friend_action('block', username)

    def unblock_friend(self, username: str | Friend) -> ActionResult:
        return self._friend_action('unblock', username)

    def mute_friend(self, username: str | Friend) -> ActionResult:
        return self._friend_action('mute_story', username)

    def unmute_friend(self, username: str | Friend) -> ActionResult:
        return self._friend_action('unmute_story', username)

    def logout(self):
        """Log out remotely and clear saved login tokens; retain the client device profile."""
        try:
            if self.is_logged_in:
                self._account_request('/scauth/droid/logout', self._account_payload())
        finally:
            self._state.account = None
            self._state.refresh_token = ''
            self._state.access_tokens.clear()
            self._state.friends.clear()
            self._state.friend_records.clear()
            self._state.added_friend_records.clear()
            self._state.friends_sync_token = ''
            self._state.added_friends_sync_token = ''
            self._state.quick_adds_updated_at_ms = 0
            self._state.fidelius_keys = None
            self._login_keys = None
            self._pending_login = None
            self._save_session()

