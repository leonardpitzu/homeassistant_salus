"""Abstract base for Salus gateway communication protocols.

Every protocol variant (AES-CBC, ECDH+AES-CCM, or future schemes) must
implement this interface so the gateway can swap protocols transparently.
"""

from __future__ import annotations

import abc
import dataclasses
from typing import Any

import aiohttp

# ---------------------------------------------------------------------------
#  33-byte frame parsing
# ---------------------------------------------------------------------------
#
# Both reject and new-protocol responses share a fixed 33-byte layout:
#
#   Bytes  0–27  (28 B)   encrypted payload
#   Byte   28    ( 1 B)   sequence counter (increments per request)
#   Bytes 29–31  ( 3 B)   session / device tag (constant within a session)
#   Byte   32    ( 1 B)   trailer:  0xAE → reject,  0xAF → new-protocol
# ---------------------------------------------------------------------------

REJECT_FRAME_LENGTH = 33          # kept for backward compat
REJECT_TRAILER = 0xAE
NEW_PROTOCOL_TRAILER = 0xAF
_KNOWN_TRAILERS = frozenset({REJECT_TRAILER, NEW_PROTOCOL_TRAILER})


@dataclasses.dataclass(frozen=True)
class Frame33:
    """Parsed 33-byte gateway response frame."""

    payload: bytes   # 28 bytes – encrypted data
    counter: int     # 1 byte  – sequence counter
    tag: bytes       # 3 bytes – session / device tag
    trailer: int     # 1 byte  – 0xAE (reject) or 0xAF (new-protocol)

    @property
    def is_reject(self) -> bool:
        return self.trailer == REJECT_TRAILER

    @property
    def is_new_protocol(self) -> bool:
        return self.trailer == NEW_PROTOCOL_TRAILER

    @property
    def trailer_name(self) -> str:
        if self.trailer == REJECT_TRAILER:
            return "reject"
        if self.trailer == NEW_PROTOCOL_TRAILER:
            return "new-protocol"
        return f"unknown(0x{self.trailer:02X})"


def parse_frame_33(raw: bytes) -> Frame33 | None:
    """Parse a 33-byte response into its components.

    Returns ``None`` when *raw* is not a recognised 33-byte frame.
    """
    if len(raw) != 33 or raw[-1] not in _KNOWN_TRAILERS:
        return None
    return Frame33(
        payload=raw[:28],
        counter=raw[28],
        tag=raw[29:32],
        trailer=raw[32],
    )


def is_reject_frame(raw: bytes) -> bool:
    """Return True if *raw* is a reject frame (trailer ``0xAE``).

    New-firmware gateways reply with exactly 33 bytes when they receive a
    request encrypted with a protocol they no longer support.
    """
    return len(raw) == REJECT_FRAME_LENGTH and raw[-1] == REJECT_TRAILER


def is_new_protocol_frame(raw: bytes) -> bool:
    """Return True if *raw* is a new-protocol response frame (trailer ``0xAF``).

    The gateway processed the request and replied with encrypted data
    using the new ECDH+AES-CCM protocol.
    """
    return len(raw) == REJECT_FRAME_LENGTH and raw[-1] == NEW_PROTOCOL_TRAILER


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
