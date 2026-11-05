"""Local client state. Saves tokens on request, never passwords or signer keys."""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .errors import ConfigurationError
from .models import DeviceProfile, PersistentInfo, PhoneInfo, SessionInfo


@dataclass(frozen=True)
class Account:
    username: str
    user_id: str


@dataclass(frozen=True)
class Friend:
    username: str
    user_id: str = ""
    display_name: str = ""


@dataclass(frozen=True)
class QuickAdd(Friend):
    reason: str = ""
    metadata: str = field(default="", repr=False)


@dataclass(frozen=True)
class ActionResult:
    action: str
    friend: Friend
    success: bool = True


@dataclass(frozen=True)
class SentMessage:
    action: str
    destination_id: str
    message_id: str
    request_id: int
    success: bool = True


@dataclass
class AccessToken:
    value: str = field(repr=False)
    expires_at_ms: int = 0


@dataclass
class ClientState:
    device: DeviceProfile
    session: SessionInfo
    device_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    instance_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    account: Account | None = None
    refresh_token: str = field(default="", repr=False)
    access_tokens: dict[str, AccessToken] = field(default_factory=dict, repr=False)
    cof_etag: str = ""
    cof_routing_tag: str = ""
    friends_sync_token: str = field(default="", repr=False)
    added_friends_sync_token: str = field(default="", repr=False)
    friends: dict[str, Friend] = field(default_factory=dict)
    friend_records: dict[str, dict] = field(default_factory=dict, repr=False)
    added_friend_records: dict[str, dict] = field(default_factory=dict, repr=False)
    quick_adds_updated_at_ms: int = 0
    fidelius_keys: dict | None = field(default=None, repr=False)

    @classmethod
    def load(cls, path):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if data.get("format") != 1 or data.get("snapchat_version") != "12.08.0.29":
                raise ValueError("Unsupported session format")
            state = cls(DeviceProfile(PersistentInfo(**data['device']['persistent']), PhoneInfo(**data['device']['phone'])),
                        SessionInfo(**data['session']), device_id=data['device_id'], instance_id=data['instance_id'])
            state.device.persistent.to_dict()
            state.device.phone.to_dict()
            state.session.to_dict()
            state.account = Account(**data['account']) if data.get('account') else None
            state.refresh_token = data.get('refresh_token', '')
            state.access_tokens = {key: AccessToken(**value) for key, value in data.get('access_tokens', {}).items()}
            state.cof_etag, state.cof_routing_tag = data.get('cof_etag', ''), data.get('cof_routing_tag', '')
            state.friends_sync_token = data.get('friends_sync_token', '')
            state.added_friends_sync_token = data.get('added_friends_sync_token', '')
            state.friends = {key: Friend(**value) for key, value in data.get('friends', {}).items()}
            state.friend_records = data.get('friend_records', {})
            state.added_friend_records = data.get('added_friend_records', {})
            state.quick_adds_updated_at_ms = data.get('quick_adds_updated_at_ms', 0)
            state.fidelius_keys = data.get('fidelius_keys')
            return state
        except (OSError, ValueError, TypeError, KeyError):
            raise ConfigurationError("Cannot read the saved Snapchat session. Choose another session_file or restore a valid file.") from None

    def save(self, path):
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = {"format": 1, "snapchat_version": "12.08.0.29", **asdict(self)}
        # mkstemp uses restrictive permissions; replace is atomic on the same filesystem.
        descriptor, temporary = tempfile.mkstemp(prefix='.' + destination.name + '.', dir=destination.parent)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
                json.dump(data, stream, indent=2)
                stream.write('\n')
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
