"""Public exceptions. Credentials and response bodies are never included in repr/str."""


class SnapchatError(Exception):
    """Base class for client, signer and transport failures."""


class PayloadError(SnapchatError, ValueError):
    """A request cannot be encoded with the selected source schema."""


class BlockedPathError(PayloadError):
    """The path is blocked by the RUSOCIAL service's current policy."""


class ConfigurationError(SnapchatError, ValueError):
    """An explicit upstream target or required option is missing."""


class TransportError(SnapchatError):
    """A connection failed before a valid response was received."""


class ApiError(SnapchatError):
    def __init__(self, status: int, code: str = "http_error", *, retry_after: str | None = None):
        self.status = status
        self.code = code
        self.retry_after = retry_after
        super().__init__(f"HTTP {status} ({code})")


class SignerError(ApiError):
    """The remote signer rejected the request. No automatic retries consume quota."""


class RpcError(SnapchatError):
    def __init__(self, code: str, *, details: str | None = None, path: str | None = None):
        self.code = code
        self.details = details
        self.path = path
        super().__init__(f"gRPC request failed ({code})")

    def redacted(self, values, *, path):
        from urllib.parse import quote, quote_plus
        details = self.details
        if details:
            sensitive = {variant for value in values if value for variant in (value, quote(value), quote_plus(value))}
            for value in sorted(sensitive, key=len, reverse=True):
                details = details.replace(value, '[redacted]')
            details = ' '.join(details.split())[:2000]
        result = RpcError(self.code, details=details, path=path)
        if details:
            # Existing callers that print an exception still see the useful
            # server reason, but only after request secrets have been removed.
            result.args = (f'gRPC request failed ({self.code}): {details}',)
        return result


class AuthenticationError(SnapchatError):
    """Login or a saved session could not be used."""

    def __init__(self, message: str, *, status: int | None = None, code: str | None = None):
        # status is the endpoint's protobuf status, not a gRPC transport code.
        self.status = status
        self.code = code
        super().__init__(message)


class LoginChallenge(AuthenticationError):
    """Snapchat requires an additional login step; never treated as success."""
    def __init__(self, kind: str, status: int, *, methods=()):
        self.kind = kind
        self.status = status
        self.methods = tuple(methods)
        super().__init__("Snapchat requires " + kind.replace('_', ' ') + ".", status=status, code=kind)


class ActionError(SnapchatError):
    """A successful HTTP response reported a failed application action."""


class SendError(ActionError):
    """The service rejected a send or did not confirm its destination."""
    def __init__(self, message, *, request_id, code=None):
        self.request_id = request_id
        self.code = code
        super().__init__(message + (f' (code {code})' if code is not None else ''))
