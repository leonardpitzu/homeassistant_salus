"""RC4 cipher and binary frame utilities for new Salus gateway firmware.

Firmware versions ≥ 20250715 on UG800 (and possibly newer UGE600) use an
RC4-based protocol with per-session keys and binary framing instead of the
original AES-CBC static-key protocol.

Protocol overview (reverse-engineered by mkrum001, issue #81):
    Cipher ......... RC4
    Session key .... MD5(EUID + first 12 bytes of HS2 response)
    Handshake ...... binary POST /deviceid/read → /deviceid/write
    Frame markers .. 0x16 (continuation) / 0x17 (final frame)
"""

from __future__ import annotations

import logging

_LOGGER = logging.getLogger(__name__)

FRAME_CONT = 0x16  # intermediate frame marker
FRAME_FINAL = 0x17  # last frame marker


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Apply RC4 keystream to *data* (symmetric: encrypt == decrypt)."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    i = j = 0
    out = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[k] = data[k] ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def split_frames(data: bytes) -> list[bytes]:
    """Split a response buffer on 0x16 / 0x17 frame terminators.

    Returns a list of frame payloads with terminators stripped.
    If no terminators are found, returns ``[data]`` as a single frame.
    """
    if not data:
        return []

    frames: list[bytes] = []
    start = 0
    for pos in range(len(data)):
        if data[pos] in (FRAME_CONT, FRAME_FINAL):
            if pos > start:
                frames.append(data[start:pos])
            start = pos + 1
            if data[pos] == FRAME_FINAL:
                break

    if not frames:
        return [data]
    return frames


def wrap_frame(payload: bytes, *, final: bool = True) -> bytes:
    """Wrap *payload* in a single frame with the appropriate terminator."""
    return payload + bytes([FRAME_FINAL if final else FRAME_CONT])
