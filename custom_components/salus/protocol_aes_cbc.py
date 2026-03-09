"""AES-CBC protocol for Salus iT600 local gateway communication.

Original firmware uses AES-256-CBC with a static key derived from the
gateway EUID and a fixed IV.  Some intermediate firmware versions may
use AES-128-CBC (just the raw 16-byte MD5 key, without zero-padding).

Key derivation:
    md5_key = MD5("Salus-{euid_lowercase}")      # 16 bytes
    AES-256: key = md5_key + 16×0x00              # 32 bytes
    AES-128: key = md5_key                        # 16 bytes

IV: fixed 16-byte vector (see _IV below).
Padding: PKCS7 (block size 128 bits).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any

import aiohttp

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .protocol import GatewayProtocol, is_reject_frame

_LOGGER = logging.getLogger(__name__)

_IV = bytes(
    [0x88, 0xA6, 0xB0, 0x79, 0x5D, 0x85, 0xDB, 0xFC,
     0xE6, 0xE0, 0xB3, 0xE9, 0xA6, 0x29, 0x65, 0x4B]
)


class AesCbcProtocol(GatewayProtocol):
    """AES-CBC protocol (legacy / intermediate firmware)."""

    def __init__(self, euid: str, *, aes128: bool = False) -> None:
        self._euid = euid
        self._aes128 = aes128
        md5_key = hashlib.md5(f"Salus-{euid.lower()}".encode()).digest()
        key = md5_key if aes128 else md5_key + bytes(16)
        self._key = key
        self._cipher = Cipher(algorithms.AES(key), modes.CBC(_IV))

    @property
    def name(self) -> str:
        return "AES-128-CBC" if self._aes128 else "AES-256-CBC"

    @property
    def key_fingerprint(self) -> str:
        """Short hex fingerprint of the key — useful in debug logs."""
        return hashlib.md5(self._key).hexdigest()[:8]

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a UTF-8 string with AES-CBC + PKCS7 padding."""
        encryptor = self._cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded: bytes = padder.update(plaintext.encode()) + padder.finalize()
        return encryptor.update(padded) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt AES-CBC cipher bytes, strip PKCS7 padding, return UTF-8."""
        decryptor = self._cipher.decryptor()
        padded: bytes = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain: bytes = unpadder.update(padded) + unpadder.finalize()
        return plain.decode()

    def wrap_request(self, body_json: str) -> bytes:
        """Encrypt the JSON body — no additional framing for AES-CBC."""
        return self.encrypt(body_json)

    def unwrap_response(self, raw: bytes) -> str:
        """Strip non-block-aligned trailer, decrypt, return JSON string."""
        remainder = len(raw) % 16
        if remainder:
            raw = raw[: len(raw) - remainder]
        return self.decrypt(raw)

    async def connect(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        timeout: int,
    ) -> dict[str, Any]:
        """Send an encrypted ``readall`` and return the parsed response."""
        url = f"http://{host}:{port}/deviceid/read"
        body = json.dumps({"requestAttr": "readall"})
        encrypted = self.encrypt(body)

        _LOGGER.debug(
            "[%s] POST %s (%d→%d bytes, key fp: %s)",
            self.name, url, len(body), len(encrypted), self.key_fingerprint,
        )

        async with asyncio.timeout(timeout):
            resp = await session.post(
                url,
                data=encrypted,
                headers={"content-type": "application/json"},
            )
            raw = await resp.read()

        _LOGGER.debug(
            "[%s] Response: HTTP %s, %d bytes, hex=%s",
            self.name, resp.status, len(raw),
            raw.hex() if len(raw) <= 512
            else f"{raw[:256].hex()}...({len(raw)} total)",
        )

        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")

        # Detect new-firmware reject frame before attempting decryption.
        if is_reject_frame(raw):
            core = raw[:32]
            _LOGGER.debug(
                "[%s] Reject frame detected: %d bytes, "
                "core=%s, trailer=0x%02X",
                self.name, len(raw), core.hex(), raw[-1],
            )
            raise ValueError(
                "Gateway returned a reject frame (33 bytes, 0xAE trailer) — "
                "firmware likely requires a newer protocol (ECDH+AES-CCM)"
            )

        text = self.unwrap_response(raw)
        result = json.loads(text)

        if result.get("status") != "success":
            raise ValueError(f"status={result.get('status')}")

        return result


# Backward-compatible alias used throughout the codebase.
IT600Encryptor = AesCbcProtocol

