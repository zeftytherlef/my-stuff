"""Small internal codec for the native client's audited protobuf fields.

Unknown response fields are skipped. This is deliberately not a public payload API.
"""
from .errors import ActionError


def _varint(value):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError('Expected an unsigned 64-bit integer')
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def message(*fields):
    out = bytearray()
    for number, value in fields:
        if not 0 < number < 1 << 29:
            raise ValueError('Invalid protobuf field')
        if isinstance(value, str):
            value = value.encode('utf-8')
        if isinstance(value, bytes):
            out += _varint(number << 3 | 2) + _varint(len(value)) + value
        else:
            out += _varint(number << 3) + _varint(value)
    return bytes(out)


class Fields:
    def __init__(self, data=b''):
        self._values = {}
        offset = 0

        def read_int():
            nonlocal offset
            result = 0
            for shift in range(0, 70, 7):
                if offset >= len(data):
                    raise ValueError()
                byte = data[offset]
                offset += 1
                if shift == 63 and byte > 1:
                    raise ValueError()
                result |= (byte & 127) << shift
                if not byte & 128:
                    return result
            raise ValueError()

        try:
            while offset < len(data):
                tag = read_int()
                number, kind = tag >> 3, tag & 7
                if not 0 < number < 1 << 29:
                    raise ValueError()
                if kind == 0:
                    value = read_int()
                elif kind in (1, 2, 5):
                    size = read_int() if kind == 2 else 8 if kind == 1 else 4
                    if size > len(data) - offset:
                        raise ValueError()
                    value = data[offset:offset + size]
                    offset += size
                else:
                    raise ValueError()
                self._values.setdefault(number, []).append((kind, value))
        except (ValueError, TypeError, IndexError):
            raise ActionError('Snapchat returned a malformed protobuf response.') from None

    def has(self, number):
        return number in self._values

    def _all(self, number, kind):
        rows = self._values.get(number, [])
        if any(wire_type != kind for wire_type, _ in rows):
            raise ActionError('Snapchat returned an unexpected protobuf field type.')
        return [value for _, value in rows]

    def integer(self, number, default=0):
        return (self._all(number, 0) or [default])[-1]

    def blob(self, number, default=b''):
        return (self._all(number, 2) or [default])[-1]

    def text(self, number):
        try:
            return self.blob(number).decode('utf-8')
        except UnicodeError:
            raise ActionError('Snapchat returned invalid response text.') from None

    def child(self, number):
        return Fields(self.blob(number))

    def children(self, number):
        return [Fields(data) for data in self._all(number, 2)]
