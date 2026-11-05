"""Simple Snapchat Android 12.08.0.29 actions with the RUSOCIAL signer."""
from .client import SnapchatClient
from .errors import (ActionError, ApiError, AuthenticationError, BlockedPathError,
                     ConfigurationError, LoginChallenge, PayloadError, RpcError,
                     SendError, SignerError, SnapchatError, TransportError)
from .models import DeviceProfile, PersistentInfo, PhoneInfo, SessionInfo
from .session import Account, ActionResult, Friend, QuickAdd, SentMessage

__version__ = "12.8.0.29.post6"
SNAPCHAT_VERSION = "12.08.0.29"

__all__ = ['SnapchatClient', 'Account', 'Friend', 'QuickAdd', 'ActionResult', 'SentMessage',
           'DeviceProfile', 'PersistentInfo', 'PhoneInfo', 'SessionInfo', 'SNAPCHAT_VERSION',
           'SnapchatError', 'ActionError', 'SendError', 'AuthenticationError', 'LoginChallenge',
           'ApiError', 'SignerError', 'RpcError', 'TransportError', 'ConfigurationError',
           'PayloadError', 'BlockedPathError']
