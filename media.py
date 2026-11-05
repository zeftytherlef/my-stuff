"""Internal file validation, encrypted uploads and SnapDoc construction."""
from __future__ import annotations

import base64
import io
import math
from pathlib import Path
import secrets
import struct
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ._wire import Fields, message
from .errors import ActionError, PayloadError
from .models import unix_time_ms
from .transport import checked_headers

UPLOAD_PATH = '/snapchat.content.v2.MediaDeliveryService/getUploadLocations'
MAX_MEDIA_BYTES = 32 * 1024 * 1024


def _boxes(data):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise ValueError()
        size, kind = struct.unpack_from('>I4s', data, offset)
        header = 8
        if size == 1:
            if len(data) - offset < 16:
                raise ValueError()
            size = struct.unpack_from('>Q', data, offset + 8)[0]
            header = 16
        elif size == 0:
            size = len(data) - offset
        if size < header or size > len(data) - offset:
            raise ValueError()
        yield kind, data[offset + header:offset + size]
        offset += size


def _box(data, name):
    return next(value for kind, value in _boxes(data) if kind == name)


def _video_info(data):
    """Read ISO BMFF track metadata; accept H.264 video and optional AAC audio."""
    moov = _box(data, b'moov')
    if not _box(data, b'mdat'):
        raise ValueError()
    videos, audio = [], False
    for kind, track in _boxes(moov):
        if kind != b'trak':
            continue
        mdia = _box(track, b'mdia')
        handler = _box(mdia, b'hdlr')[8:12]
        if handler not in (b'vide', b'soun'):
            continue
        stsd = _box(_box(_box(mdia, b'minf'), b'stbl'), b'stsd')
        codecs = [kind for kind, _ in _boxes(stsd[8:])]
        if handler == b'soun':
            if codecs != [b'mp4a']:
                raise ValueError()
            audio = True
            continue
        if codecs != [b'avc1']:
            raise ValueError()
        tkhd = _box(track, b'tkhd')
        if tkhd[0] not in (0, 1):
            raise ValueError()
        width, height = struct.unpack('>II', tkhd[-8:])
        width, height = width >> 16, height >> 16
        mdhd = _box(mdia, b'mdhd')
        if mdhd[0] == 0:
            scale, duration = struct.unpack_from('>II', mdhd, 12)
        elif mdhd[0] == 1:
            scale, duration = struct.unpack_from('>IQ', mdhd, 20)
        else:
            raise ValueError()
        milliseconds = math.ceil(duration * 1000 / scale)
        if not (0 < width <= 8192 and 0 < height <= 8192 and 0 < milliseconds <= 60_000):
            raise ValueError()
        videos.append((width, height, milliseconds))
    if len(videos) != 1:
        raise ValueError()
    return (*videos[0], audio)


@dataclass(frozen=True)
class Media:
    data: bytes = field(repr=False)
    width: int
    height: int
    duration_ms: int
    video: bool = False
    audio: bool = False
    image_codec: int = 1

    @classmethod
    def read(cls, filename, duration):
        if type(duration) is not int or not 1 <= duration <= 10:
            raise PayloadError('duration must be a whole number of seconds from 1 to 10.')
        try:
            path = Path(filename)
            if not path.is_file() or not 0 < path.stat().st_size <= MAX_MEDIA_BYTES:
                raise ValueError()
            with path.open('rb') as stream:
                data = stream.read(MAX_MEDIA_BYTES + 1)
            if len(data) > MAX_MEDIA_BYTES:
                raise ValueError()
        except (OSError, TypeError, ValueError):
            raise PayloadError('Choose an existing media file no larger than 32 MiB.') from None
        if data[4:8] == b'ftyp':
            try:
                width, height, milliseconds, audio = _video_info(data)
            except (ValueError, StopIteration, IndexError, struct.error, ZeroDivisionError):
                raise PayloadError('Use an MP4 with one H.264 video track, optional AAC audio, and a duration of at most 60 seconds.') from None
            return cls(data, width, height, milliseconds, True, audio)
        try:
            from PIL import Image
            with Image.open(io.BytesIO(data)) as picture:
                if picture.format not in ('JPEG', 'PNG') or getattr(picture, 'n_frames', 1) != 1:
                    raise ValueError()
                width, height = picture.size
                if not (0 < width <= 8192 and 0 < height <= 8192):
                    raise ValueError()
                codec = 1 if picture.format == 'JPEG' else 2
                picture.verify()
        except (OSError, ValueError, Image.DecompressionBombError):
            raise PayloadError('Use a valid JPEG, PNG, or H.264 MP4 file.') from None
        return cls(data, width, height, duration * 1000, image_codec=codec)

    def encrypt(self):
        # GJ0 case 12 / C9826Sa2: a fresh 256-bit AES key, CBC IV and PKCS padding.
        key, iv = secrets.token_bytes(32), secrets.token_bytes(16)
        padder = padding.PKCS7(128).padder()
        plaintext = padder.update(self.data) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return encryptor.update(plaintext) + encryptor.finalize(), key, iv

    def content(self, content_object, key, iv):
        # CNf/SnapDoc -> C18410dBc/Playback -> C22392gCc/Layer -> C15353asa.
        # C10737Tra carries UTF-8 Base64 strings, not the raw AES key/IV bytes.
        encryption = message((1, base64.b64encode(key)), (2, base64.b64encode(iv)))
        media_fields = [(2, int(self.video)), (4, encryption),
                        (5, message((1, self.width), (2, self.height))),
                        (15, self.duration_ms), (18, message((1, 1))), (20, 5)]
        if self.video:
            media_fields.append((25, message((1, 1))))  # H.264
            if self.audio:
                media_fields.append((23, message((1, 1))))  # AAC
        else:
            media_fields.append((24, message((1, self.image_codec))))
        display = message((5, int(self.video)), (7, b'')) if self.video else message((5, 0), (8, self.duration_ms // 1000))
        playback = message((1, message((1, message(*media_fields)))), (2, display))
        reference = message((3, content_object), (6, 1), (8, 3 if self.video else 2))
        # SnapDoc field 8 is the last assigned media-reference ID, not a timestamp.
        snapdoc = message((4, reference), (5, playback), (8, 1))
        return message((11, snapdoc)), reference


def _upload_url(value):
    try:
        parts = urlsplit(value)
        valid = (parts.scheme == 'https' and parts.hostname and not parts.username and
                 not parts.password and not parts.fragment and parts.port in (None, 443) and
                 not any(ord(char) <= 32 for char in value))
    except ValueError:
        valid = False
    if not valid:
        raise ActionError('Snapchat returned an invalid media upload URL.')
    return value


def upload(client, media):
    # C23400gy4 case 1: one location, configured country (default US), type 2.
    payload = message((1, message((1, client.country_code))), (2, 1), (4, 2))
    response = client._authenticated_rpc(UPLOAD_PATH, payload)
    locations = Fields(response.body).children(1)
    if len(locations) != 1:
        raise ActionError('Snapchat did not return one media upload location.')
    location = locations[0]
    content_object = location.child(4).blob(3)
    if not content_object:
        raise ActionError('Snapchat did not return a media content object.')
    expiry = location.child(2).integer(1)
    if expiry and expiry <= unix_time_ms() // 1000 + 30:
        raise ActionError('Snapchat returned an expired media upload location.')
    kind = location.integer(5)
    if kind not in (0, 1):
        raise ActionError('Snapchat returned an unsupported media upload type.')
    url = _upload_url(location.text(1))
    # Presigned upload requests contain only upload headers, never session tokens,
    # the signer's API key, or the client's arbitrary global request headers.
    headers = {entry.text(1): entry.text(2) for entry in location.children(6)}
    headers = checked_headers(headers)
    if any(name.lower() in ('authorization', 'cookie', 'host', 'x-api-key', 'x-snap-access-token', 'x-snapchat-att') for name in headers):
        raise ActionError('Snapchat returned unexpected media upload headers.')
    encrypted, key, iv = media.encrypt()
    if kind == 1:
        start = client._http.request('POST', url, body=b'', timeout=client.timeout,
            headers={'Content-Type': 'application/octet-stream', 'Content-Length': '0', 'x-goog-resumable': 'start'})
        start.raise_for_status()
        url = _upload_url(next((value for name, value in start.headers.items() if name.lower() == 'location'), ''))
        headers = {}
    headers = {name: value for name, value in headers.items() if name.lower() not in ('content-length', 'content-type')}
    headers.update({'Content-Type': 'application/octet-stream', 'Content-Length': str(len(encrypted))})
    result = client._http.request('PUT', url, headers=headers, body=encrypted, timeout=client.timeout)
    result.raise_for_status()
    return media.content(content_object, key, iv)
