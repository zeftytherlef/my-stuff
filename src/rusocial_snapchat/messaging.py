"""Simple sends using the 12.08 native StatelessSession message format."""
from __future__ import annotations

import secrets
import uuid

from ._wire import Fields, message
from .errors import ActionError, PayloadError, SendError
from .media import Media, upload
from .session import Friend, SentMessage

QUERY_PATH = '/messagingcoreservice.MessagingCoreService/QueryConversations'
SEND_PATH = '/messagingcoreservice.MessagingCoreService/CreateContentMessage'


def _uuid(value):
    try:
        return uuid.UUID(value).bytes
    except (ValueError, TypeError, AttributeError):
        raise ActionError('Snapchat did not return a valid account or conversation ID.') from None


def _uuid_text(data):
    try:
        return str(uuid.UUID(bytes=data))
    except (ValueError, TypeError):
        raise ActionError('Snapchat returned an invalid conversation ID.') from None


class MessagingActions:
    def _authenticated_rpc(self, path, payload, *, redact=()):
        return self._request(path, payload, headers={'X-Snap-Access-Token': self._access_token()}, redact=redact)

    def _recipient(self, recipient):
        self._require_login()
        if isinstance(recipient, Friend):
            if recipient.user_id:
                return _uuid(recipient.user_id)
            recipient = recipient.username
        if not isinstance(recipient, str) or not recipient.strip() or len(recipient) > 512:
            raise PayloadError('Enter a friend username or pass a Friend from friends().')
        for refresh in (False, True):
            if refresh:
                self.sync_friends()
            matches = [friend for friend in self._state.friends.values()
                       if friend.username.casefold() == recipient.casefold() and friend.user_id]
            if len(matches) == 1:
                return _uuid(matches[0].user_id)
        raise ActionError('That username is not in your synced friends. Add the friend and sync again.')

    def _conversation(self, recipient):
        target = self._recipient(recipient)
        own = _uuid(self.me.user_id)
        cursor = b''
        visited = set()
        for _ in range(100):
            fields = [(1, message((1, own))), (3, 100)]
            if cursor:
                fields.append((4, cursor))
            page = Fields(self._authenticated_rpc(QUERY_PATH, message(*fields)).body)
            matches = []
            for entry in page.children(1):
                # LegacyConversationInfo's oneof: 1=one-to-one, 2=group.
                # Never choose a group merely because it has two members.
                if not entry.child(2).has(1):
                    continue
                participants = {participant.blob(1) for participant in entry.children(7)}
                if participants - {own} != {target}:
                    continue
                info = entry.child(1)
                identifier = info.child(1).blob(1)
                _uuid_text(identifier)
                matches.append((identifier, info.integer(2)))
            if len(matches) > 1:
                raise ActionError('Snapchat returned more than one matching conversation.')
            if matches:
                return matches[0]
            if page.integer(2) == 0:
                break
            cursor = page.blob(4)
            if not cursor or cursor in visited:
                raise ActionError('Snapchat returned an invalid conversation page cursor.')
            visited.add(cursor)
        else:
            raise ActionError('The conversation list exceeded the client page limit.')
        raise ActionError('No one-to-one chat was found. Open a chat with this friend in Snapchat, then try again.')

    def _send_content(self, action, destination_id, destination, content, *, content_type, reference=None):
        request_id = secrets.randbits(64) or 1
        # The native enum uses SNAP=0 and CHAT=1, unlike the Java enum ordinals.
        # SavePolicy.LIFETIME becomes 1 in StatelessSession::sendMessageWithContent.
        envelope = [(2, content_type), (4, content), (7, 1)]
        if reference is not None:
            envelope.append((5, message((1, reference))))
        payload = message((1, message((1, _uuid(self.me.user_id)))), (2, request_id),
                          (3, destination), (4, message(*envelope)))
        # Native protobuf bytes need explicit redaction of nested text and keys.
        decoded = Fields(content)
        redact = [decoded.child(2).text(1)] if content_type == 1 else []
        if reference is not None:
            for layer in decoded.child(11).child(5).children(1):
                encryption = layer.child(1).child(4)
                redact.extend((encryption.text(1), encryption.text(2)))
        response = Fields(self._authenticated_rpc(SEND_PATH, payload, redact=redact).body)
        if response.has(1) and response.integer(1) != request_id:
            raise SendError('The send response did not match this request.', request_id=request_id)
        results = response.children(2)
        if len(results) != 1:
            raise SendError('Snapchat did not confirm delivery to the destination.', request_id=request_id)
        result = results[0]
        if result.integer(2) != 1 or result.has(3):
            code = result.child(3).integer(1) if result.has(3) else None
            raise SendError('Snapchat rejected the send.', request_id=request_id, code=code)
        detail_field = 13 if action == 'post_story' else 12
        details = result.child(detail_field)
        returned_id = details.child(1).blob(1) if result.has(detail_field) else result.child(1).blob(1)
        if returned_id != destination_id:
            raise SendError('Snapchat did not confirm the requested destination.', request_id=request_id)
        message_id = details.text(2) if action == 'post_story' else str(details.integer(3) or result.integer(6) or '')
        return SentMessage(action, _uuid_text(destination_id), message_id, request_id)

    def send_message(self, recipient: str | Friend, text: str) -> SentMessage:
        """Send plain text to an existing one-to-one chat, using a friend username."""
        if not isinstance(text, str) or not text.strip() or len(text.encode('utf-8')) > 16_000 or '\x00' in text:
            raise PayloadError('Enter a nonempty message of at most 16,000 UTF-8 bytes.')
        identifier, version = self._conversation(recipient)
        destination = message((1, message((1, message((1, identifier))), (2, version))))
        # CallableC47898zW5: MC3.text(C8686Pxh.text), with no mentions or attachments.
        return self._send_content('send_message', identifier, destination,
                                  message((2, message((1, text)))), content_type=1)

    def send_snap(self, recipient: str | Friend, filename, *, duration: int = 10) -> SentMessage:
        """Upload a JPEG/PNG or H.264 MP4 and send it to an existing friend's chat.

        duration controls photos (1–10 seconds). Videos use their file duration.
        """
        self._require_login()
        media = Media.read(filename, duration)
        identifier, version = self._conversation(recipient)
        content, reference = upload(self, media)
        destination = message((1, message((1, message((1, identifier))), (2, version))))
        return self._send_content('send_snap', identifier, destination, content,
                                  content_type=0, reference=reference)

    def post_story(self, filename, *, duration: int = 10) -> SentMessage:
        """Upload a JPEG/PNG or H.264 MP4 to My Story; photo duration is 1–10 seconds."""
        self._require_login()
        media = Media.read(filename, duration)
        # R4k.p / C42604vVg.b: My Story is a sentinel, not the account UUID.
        identifier = bytes([1]) * 16
        content, reference = upload(self, media)
        # StoryPostDestinationMetadata.my_story with privacy override 0 keeps
        # the account's story visibility; it does not request Our Story.
        metadata = message((1, message((1, 0))))
        destination = message((2, message((1, message((1, identifier))), (2, metadata))))
        return self._send_content('post_story', identifier, destination, content,
                                  content_type=0, reference=reference)
