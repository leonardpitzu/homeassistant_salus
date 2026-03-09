"""Abstract base for Salus gateway communication protocols.

Every protocol variant (AES-CBC, ECDH+AES-CCM, or future schemes) must
implement this interface so the gateway can swap protocols transparently.
"""

from __future__ import annotations

import abc
from typing import Any

import aiohttp

# ---------------------------------------------------------------------------
#  Reject-frame detection
# ---------------------------------------------------------------------------

REJECT_FRAME_LENGTH = 33
REJECT_TRAILER = 0xAE


def is_reject_frame(raw: bytes) -> bool:
    """Return True if *raw* is a new-firmware reject frame.

    New-firmware gateways reply with exactly 33\xa0bytes (32\xa0opaque +
    a trailing ``0xAE``) when they receive a request encrypted with a
    protocol they no longer support.
    """
    return len(raw) == REJECT_FRAME_LENGTH and raw[-1] == REJECT_TRAILER


class GatewayProtocol(abc.ABC):
    """Contract that every Salus gateway encryption protocol must fulfil."""

    # Human-readable label used in logs and diagnostics.
    name: str

    @abc.abstractmethod
    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a UTF-8 JSON string into bytes ready for the wire."""

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt wire bytes back into a UTF-8 JSON string.

        Raises ``ValueError`` on padding / authentication errors.
        """

    @abc.abstractmethod
    async def connect(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        timeout: int,
    ) -> dict[str, Any]:
        """Perform the full session setup and return the first *readall* response.

        For stateless protocols (AES-CBC) this is just an encrypted POST.
        For session-based protocols (ECDH+AES-CCM) this includes key exchange.

        Returns the parsed JSON ``{"status": "success", "id": [...]}`` dict.
        Raises on failure.
        """

    @abc.abstractmethod
    def wrap_request(self, body_json: str) -> bytes:
        """Prepare *body_json* for the wire (encrypt + optional framing)."""

    @abc.abstractmethod
    def unwrap_response(self, raw: bytes) -> str:
        """Strip framing, decrypt, and return the JSON string from *raw*.

        Raises ``ValueError`` on decryption / authentication failure.
        """
