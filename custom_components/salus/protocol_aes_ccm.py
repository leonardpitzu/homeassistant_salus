"""AES-256-CCM (CCMP) protocol for Salus UG800 gateways (new firmware).

Reverse-engineered from APK v0.116.0 (Dart AOT ARM64 disassembly).

Key derivation:
    key = bytes.fromhex(EUID) + b"9a4ba190ac2b5139b32c3528"
    EUID is the gateway's Zigbee EUI-64 hex string (16 chars → 8 bytes)
    Hardcoded suffix is the ASCII encoding (24 bytes)
    Total key: 8 + 24 = 32 bytes → AES-256

Nonce (8 bytes):
    [3 random bytes][2-byte BE counter][3-byte BE truncated epoch seconds]

Wire format:
    encrypt → [ciphertext + 8-byte MAC][8-byte nonce]
    decrypt ← split at len-8: [:len-8] = ciphertext+MAC, [-8:] = nonce

MAC tag: 64 bits (8 bytes).  No AAD.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import struct
import time
from typing import Any

import aiohttp

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .protocol import GatewayProtocol, parse_frame_33

_LOGGER = logging.getLogger(__name__)

_HARDCODED_SUFFIX = b"9a4ba190ac2b5139b32c3528"  # 24 ASCII bytes
_MAC_SIZE = 8   # bytes (64-bit MAC tag)
_NONCE_SIZE = 8  # bytes


def _derive_key(euid: str) -> bytes:
    """Derive the 32-byte AES-256 key from the gateway EUID.

    For a standard 8-byte EUI-64 (16 hex chars), the key is simply
    ``bytes.fromhex(euid) + _HARDCODED_SUFFIX``.

    If the hex-decoded EUID is 12 bytes, bytes ``[0x09, 0x02]`` are
    inserted at position 3 before appending the suffix.
    """
    euid_bytes = bytearray(bytes.fromhex(euid.strip()))
    if len(euid_bytes) == 12:
        euid_bytes[3:3] = b"\x09\x02"
    return bytes(euid_bytes) + _HARDCODED_SUFFIX


def _build_nonce(counter: int) -> bytes:
    """Build an 8-byte nonce: 3 random + 2 counter BE + 3 timestamp BE."""
    rand_bytes = os.urandom(3)
    counter_bytes = struct.pack(">H", counter & 0xFFFF)
    ts = int(time.time()) & 0xFFFFFF
    ts_bytes = struct.pack(">I", ts)[1:]  # last 3 bytes of 4-byte BE
    return rand_bytes + counter_bytes + ts_bytes


class AesCcmProtocol(GatewayProtocol):
    """AES-256-CCM protocol for new-firmware UG800 gateways."""

    def __init__(self, euid: str) -> None:
        self._euid = euid
        self._key = _derive_key(euid)
        self._aesccm = AESCCM(self._key, tag_length=_MAC_SIZE)
        self._counter = 0

    @property
    def name(self) -> str:
        return "AES-256-CCM (UG800)"

    @property
    def key_fingerprint(self) -> str:
        """Short hex fingerprint of the key — useful in debug logs."""
        return hashlib.md5(self._key).hexdigest()[:8]

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt plaintext with AES-256-CCM.

        Returns wire bytes: ``[ciphertext + 8-byte MAC][8-byte nonce]``.
        """
        nonce = _build_nonce(self._counter)
        self._counter = (self._counter + 1) & 0xFFFF
        ct_and_tag = self._aesccm.encrypt(nonce, plaintext.encode(), None)
        wire = ct_and_tag + nonce
        _LOGGER.debug(
            "[%s] encrypt: %d chars → %d wire bytes (nonce=%s)",
            self.name, len(plaintext), len(wire), nonce.hex(),
        )
        return wire

    def decrypt(self, data: bytes) -> str:
        """Decrypt wire bytes back into a UTF-8 JSON string.

        Wire format: ``[ciphertext + MAC][-8 bytes nonce]``.
        """
        if len(data) <= _NONCE_SIZE + _MAC_SIZE:
            raise ValueError(
                f"Data too short for CCM ({len(data)} bytes, "
                f"need > {_NONCE_SIZE + _MAC_SIZE})"
            )
        ct_and_tag = data[:-_NONCE_SIZE]
        nonce = data[-_NONCE_SIZE:]
        _LOGGER.debug(
            "[%s] decrypt: %d wire bytes (nonce=%s, ct+mac=%d)",
            self.name, len(data), nonce.hex(), len(ct_and_tag),
        )
        plaintext_bytes = self._aesccm.decrypt(nonce, ct_and_tag, None)
        return plaintext_bytes.decode()

    def wrap_request(self, body_json: str) -> bytes:
        """Encrypt the JSON body for the wire."""
        return self.encrypt(body_json)

    def unwrap_response(self, raw: bytes) -> str:
        """Decrypt wire bytes and return JSON string."""
        return self.decrypt(raw)

    async def connect(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        timeout: int,
    ) -> dict[str, Any]:
        """Send an encrypted readall and return the parsed response."""
        url = f"http://{host}:{port}/deviceid/read"
        body = json.dumps({"requestAttr": "readall"})

        _LOGGER.debug(
            "[%s] key_fp=%s, euid_len=%d, key_len=%d",
            self.name, self.key_fingerprint,
            len(bytes.fromhex(self._euid.strip())), len(self._key),
        )

        encrypted = self.encrypt(body)

        _LOGGER.debug(
            "[%s] POST %s (%d→%d bytes, nonce=%s)",
            self.name, url, len(body), len(encrypted),
            encrypted[-_NONCE_SIZE:].hex(),
        )

        t0 = time.monotonic()
        async with asyncio.timeout(timeout):
            resp = await session.post(
                url,
                data=encrypted,
                headers={"content-type": "application/json"},
            )
            raw = await resp.read()
        elapsed_ms = (time.monotonic() - t0) * 1000

        _LOGGER.debug(
            "[%s] Response: HTTP %s, %d bytes, %.0fms, hex=%s",
            self.name, resp.status, len(raw), elapsed_ms,
            raw.hex() if len(raw) <= 512
            else f"{raw[:256].hex()}...({len(raw)} total)",
        )

        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")

        frame = parse_frame_33(raw)
        if frame is not None:
            _LOGGER.debug(
                "[%s] 33-byte frame: type=%s, counter=%d, "
                "tag=%s, payload=%s",
                self.name, frame.trailer_name, frame.counter,
                frame.tag.hex(), frame.payload.hex(),
            )
            if frame.is_reject:
                raise ValueError(
                    "Gateway returned a reject frame (0xAE)"
                )
            raise ValueError(
                f"Gateway returned a new-protocol frame (0xAF, "
                f"counter={frame.counter}, tag={frame.tag.hex()})"
            )

        try:
            text = self.unwrap_response(raw)
        except Exception as exc:
            raise ValueError(
                f"CCM decryption failed ({type(exc).__name__}: {exc})"
            ) from exc

        try:
            result = json.loads(text)
        except json.JSONDecodeError as exc:
            _LOGGER.debug(
                "[%s] Decrypted text is not valid JSON (first 200 chars): %r",
                self.name, text[:200],
            )
            raise ValueError(
                f"Decrypted response is not valid JSON: {exc}"
            ) from exc

        if result.get("status") != "success":
            _LOGGER.debug(
                "[%s] Unexpected response status: %r",
                self.name, result.get("status"),
            )
            raise ValueError(
                f"Unexpected response status: {result.get('status')!r}"
            )

        return result
