"""AES-CBC protocol for new-firmware Salus iT600 gateways (>= 2025).

New-firmware gateways use AES-CBC with a fixed universal key (named
``GENERAL`` in the APK) and a random IV per message.

Key: hardcoded constant extracted from the Salus Smart Home APK
     (``package:smart_home/encryption/enc.dart``).
     The raw hex constant is 16 bytes.  The actual AES key size is
     unknown (128-bit raw, or 256-bit zero-padded).  Both variants
     are exposed so the gateway auto-detection can try each.
IV:  random 16-byte vector generated per request, prepended to the wire
     payload so the receiver can extract it for decryption.
Padding: PKCS7, 128-bit block size.

Wire format (both requests and responses):
    [16-byte IV] + [AES-CBC ciphertext (PKCS7 padded)]

The gateway still uses the same HTTP endpoints as the old firmware:
    POST /deviceid/read   — encrypted ``{"requestAttr": "readall"}``
    POST /deviceid/write  — encrypted command payload
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

import aiohttp

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .protocol import GatewayProtocol, parse_frame_33

_LOGGER = logging.getLogger(__name__)

# Fixed key from the Salus Smart Home APK (enc.dart), named "GENERAL" in binary.
_KEY_RAW = bytes.fromhex("54b544979a4ba190ac2b5139b32c3528")  # 16 bytes

# AES-256 variant: zero-padded to 32 bytes (same pattern as old protocol).
_KEY_256 = _KEY_RAW + bytes(16)

_IV_LENGTH = 16
_BLOCK_SIZE = 128  # bits


class NewAesCbcProtocol(GatewayProtocol):
    """AES-CBC protocol for new-firmware gateways (universal key, random IV).

    Parameters
    ----------
    aes256 : bool
        If *True*, pad the 16-byte key to 32 bytes (AES-256).
        If *False* (default), use the raw 16-byte key (AES-128).
    """

    def __init__(self, *, aes256: bool = False) -> None:
        self._aes256 = aes256
        self._key = _KEY_256 if aes256 else _KEY_RAW

    @property
    def name(self) -> str:  # type: ignore[override]
        return f"NewAES-{'256' if self._aes256 else '128'}-CBC"

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a UTF-8 string with AES-CBC + PKCS7 + random IV.

        Returns ``iv (16 bytes) || ciphertext``.
        """
        iv = os.urandom(_IV_LENGTH)
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(_BLOCK_SIZE).padder()
        padded: bytes = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        wire = iv + ciphertext
        _LOGGER.debug(
            "[%s] encrypt: %d bytes plaintext → %d bytes wire "
            "(iv=%s, ct=%s)",
            self.name, len(plaintext), len(wire),
            iv.hex(),
            ciphertext.hex() if len(ciphertext) <= 128
            else f"{ciphertext[:64].hex()}...({len(ciphertext)}B)",
        )
        return wire

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt ``iv (16 bytes) || ciphertext``, strip PKCS7, return UTF-8.

        Raises ``ValueError`` on padding or length errors.
        """
        if len(ciphertext) <= _IV_LENGTH:
            raise ValueError(
                f"Ciphertext too short ({len(ciphertext)} bytes) — "
                f"need at least {_IV_LENGTH + 1}"
            )
        iv = ciphertext[:_IV_LENGTH]
        encrypted = ciphertext[_IV_LENGTH:]

        remainder = len(encrypted) % 16
        if remainder:
            _LOGGER.debug(
                "[%s] decrypt: trimming %d non-block-aligned trailing "
                "bytes from %d-byte payload",
                self.name, remainder, len(encrypted),
            )
            encrypted = encrypted[: len(encrypted) - remainder]

        _LOGGER.debug(
            "[%s] decrypt: %d bytes total, iv=%s, %d bytes ciphertext "
            "(block-aligned=%s)",
            self.name, len(ciphertext), iv.hex(), len(encrypted),
            len(encrypted) % 16 == 0,
        )

        try:
            cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded: bytes = decryptor.update(encrypted) + decryptor.finalize()
        except Exception as exc:
            _LOGGER.debug(
                "[%s] decrypt: AES decryption failed: %s — "
                "raw first 64 bytes: %s",
                self.name, exc, encrypted[:64].hex(),
            )
            raise

        try:
            unpadder = padding.PKCS7(_BLOCK_SIZE).unpadder()
            plain: bytes = unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            # PKCS7 padding invalid → almost certainly wrong key
            _LOGGER.debug(
                "[%s] decrypt: PKCS7 unpadding failed: %s — "
                "last decrypted block hex: %s",
                self.name, exc, padded[-16:].hex() if len(padded) >= 16 else padded.hex(),
            )
            raise

        try:
            text = plain.decode()
        except UnicodeDecodeError as exc:
            _LOGGER.debug(
                "[%s] decrypt: UTF-8 decode failed: %s — "
                "decrypted bytes (first 128): %s",
                self.name, exc, plain[:128].hex(),
            )
            raise ValueError(f"Decrypted data is not valid UTF-8: {exc}") from exc

        _LOGGER.debug(
            "[%s] decrypt: success, %d chars plaintext",
            self.name, len(text),
        )
        return text

    def wrap_request(self, body_json: str) -> bytes:
        """Encrypt the JSON body with a random IV."""
        return self.encrypt(body_json)

    def unwrap_response(self, raw: bytes) -> str:
        """Decrypt a response (``iv || ciphertext``) and return JSON string."""
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
            "[%s] POST %s (%d→%d bytes, key=%d-bit, sent=%s)",
            self.name, url, len(body), len(encrypted),
            len(self._key) * 8,
            encrypted.hex() if len(encrypted) <= 256
            else f"{encrypted[:128].hex()}...({len(encrypted)}B)",
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

        resp_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() in (
                "server", "content-type", "content-length",
                "x-powered-by", "www-authenticate",
            )
        }
        _LOGGER.debug(
            "[%s] Response: HTTP %s, %d bytes, %.0fms, "
            "headers=%s, hex=%s",
            self.name, resp.status, len(raw), elapsed_ms,
            resp_headers,
            raw.hex() if len(raw) <= 512
            else f"{raw[:256].hex()}...({len(raw)} total)",
        )

        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")

        # Detect 33-byte reject / new-protocol frames.
        frame = parse_frame_33(raw)
        if frame is not None:
            _LOGGER.debug(
                "[%s] 33-byte frame: type=%s, counter=%d, "
                "tag=%s, payload=%s",
                self.name, frame.trailer_name, frame.counter,
                frame.tag.hex(), frame.payload.hex(),
            )
            raise ValueError(
                f"Gateway returned a {frame.trailer_name} frame "
                f"(0x{frame.trailer:02X}) — new AES-CBC key may be "
                f"incorrect or protocol mismatch"
            )

        # Heuristic analysis before attempting decryption.
        _log_response_heuristics(self.name, raw)

        try:
            text = self.unwrap_response(raw)
        except Exception as exc:
            raise ValueError(
                f"Decryption failed ({type(exc).__name__}: {exc})"
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
                "[%s] Gateway returned status=%r (full response: %.500s)",
                self.name, result.get("status"), text,
            )
            raise ValueError(f"status={result.get('status')}")

        return result


def _log_response_heuristics(proto_name: str, raw: bytes) -> None:
    """Log heuristic properties of *raw* to help diagnose wrong-key scenarios."""
    block_aligned = len(raw) % 16 == 0
    try:
        text = raw.decode("utf-8")
        looks_like_json = text.lstrip().startswith("{") or text.lstrip().startswith("[")
        is_ascii = all(32 <= b < 127 or b in (9, 10, 13) for b in raw)
    except UnicodeDecodeError:
        looks_like_json = False
        is_ascii = False

    _LOGGER.debug(
        "[%s] Response heuristics: %d bytes, block_aligned=%s, "
        "is_ascii=%s, looks_like_json=%s",
        proto_name, len(raw), block_aligned, is_ascii, looks_like_json,
    )
    if looks_like_json:
        _LOGGER.debug(
            "[%s] WARNING: response looks like unencrypted JSON — "
            "gateway may not be encrypting at all. First 200 bytes: %r",
            proto_name, raw[:200].decode(errors="replace"),
        )
