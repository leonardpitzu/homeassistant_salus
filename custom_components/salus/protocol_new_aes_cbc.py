"""AES-CBC protocol for new-firmware Salus UG800 gateways.

UG800 uses a fixed universal AES-256 key and fixed IV.

Key: UTF-8 encoded "54b544979a4ba190ac2b5139b32c3528" (32 ASCII bytes)
IV:  UTF-8 encoded "be4480f9c146eaf9" (16 ASCII bytes)
Wire format: hex-encoded ciphertext string (Encrypted.base16 in Dart)
Padding: PKCS7 (block size 128 bits)
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import aiohttp

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .protocol import GatewayProtocol, parse_frame_33

_BLOCK_SIZE = 128  # bits

# Fixed universal key+IV from blutter analysis of UG800 app.
# The Dart code does: Key(Uint8List.fromList(Utf8Codec().encode("54b544...")))
# This means the 32-char string is used as raw UTF-8 bytes (32 bytes for AES-256),
# NOT hex-decoded to 16 bytes.
_KEY = b"54b544979a4ba190ac2b5139b32c3528"  # 32 ASCII bytes → AES-256
_IV = b"be4480f9c146eaf9"                    # 16 ASCII bytes → fixed IV


class NewAesCbcProtocol(GatewayProtocol):
    """AES-CBC protocol for new-firmware UG800 gateways.

    Uses a fixed universal key and fixed IV.  Wire format is a hex-encoded
    ciphertext string (matching ``Encrypted.base16`` in the Dart app).
    """

    def __init__(self) -> None:
        self._key = _KEY
        self._iv = _IV
        self._cipher = Cipher(algorithms.AES(self._key), modes.CBC(self._iv))

    @property
    def name(self) -> str:  # type: ignore[override]
        return "NewAES-CBC (UG800)"

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext with AES-256-CBC + PKCS7.

        Returns the ciphertext as a hex string (matching Dart's
        ``Encrypted.base16``).
        """
        encryptor = self._cipher.encryptor()
        padder = padding.PKCS7(_BLOCK_SIZE).padder()
        padded: bytes = padder.update(plaintext.encode()) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        return ct.hex()

    def decrypt(self, hex_ct: str) -> str:
        """Decrypt a hex-encoded ciphertext string (Dart's ``decrypt16``).

        Accepts the hex string as returned by the gateway.
        """
        try:
            ciphertext = bytes.fromhex(hex_ct)
        except ValueError as exc:
            raise ValueError(f"Response is not valid hex: {exc}") from exc

        decryptor = self._cipher.decryptor()
        padded: bytes = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(_BLOCK_SIZE).unpadder()
        plain: bytes = unpadder.update(padded) + unpadder.finalize()

        try:
            return plain.decode()
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"Decrypted data is not valid UTF-8: {exc}"
            ) from exc

    def wrap_request(self, body_json: str) -> str:
        """Encrypt the JSON body and return a hex string."""
        return self.encrypt(body_json)

    def unwrap_response(self, raw: bytes) -> str:
        """Decode response bytes as a hex string and decrypt."""
        return self.decrypt(raw.decode())

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
        wire_bytes = encrypted.encode()

        async with asyncio.timeout(timeout):
            resp = await session.post(
                url,
                data=wire_bytes,
                headers={"content-type": "application/json"},
            )
            raw = await resp.read()

        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")

        # Detect reject/new-protocol frames
        frame = parse_frame_33(raw)
        if frame:
            if frame.trailer_name == "reject":
                raise ValueError("Reject frame received")
            else:
                raise ValueError(f"Unexpected frame: {frame.trailer_name}")

        # Decode response as text (gateway should return hex string)
        try:
            response_text = raw.decode()
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"Response is not text (expected hex string): {exc}"
            ) from exc

        try:
            decrypted = self.decrypt(response_text)
            result = json.loads(decrypted)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Response is not valid JSON: {exc}") from exc
        except ValueError:
            raise

        if result.get("status") != "success":
            raise ValueError(f"Response status={result.get('status')}")

        return result
