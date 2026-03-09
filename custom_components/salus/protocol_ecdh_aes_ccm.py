"""ECDH + AES-CCM protocol for Salus gateways with firmware ≥ 2025-07-15.

New-firmware gateways replaced the static AES-CBC scheme with a
session-based protocol:

    1. Key exchange — ECDH (secp256r1 / P-256).
    2. Session key derivation — from the shared ECDH secret.
    3. Authenticated encryption — AES-CCM (AES in Counter-with-CBC-MAC mode).
    4. Request framing — encrypted core + variable-length trailer
       containing a sequence counter and integrity check.

Evidence for this scheme comes from the official Android APK, which
references ``secp256r1``, ``cipherSecretKey``, ``Device public key``,
``Device random``, and ``aes_ccm``.

STATUS: **Skeleton** — the protocol is not yet fully reverse-engineered.
        The key-exchange and session-key-derivation steps are documented
        as placeholders.  Once the exact byte-level flow is known, the
        implementations below can be filled in and the gateway will
        auto-detect the protocol.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from typing import Any

import aiohttp

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from .protocol import (
    REJECT_FRAME_LENGTH,
    REJECT_TRAILER,
    GatewayProtocol,
    is_reject_frame as _is_reject_frame,
)

_LOGGER = logging.getLogger(__name__)

# AES-CCM parameters (to be confirmed by full protocol analysis).
_CCM_TAG_LENGTH = 8  # bytes — common for constrained devices
_CCM_NONCE_LENGTH = 12  # bytes


class EcdhAesCcmProtocol(GatewayProtocol):
    """ECDH key-exchange + AES-CCM authenticated encryption.

    Lifecycle:
        1. ``connect()`` — performs the ECDH handshake with the gateway,
           derives the session key, and returns the first *readall*.
        2. ``wrap_request()`` / ``unwrap_response()`` — use the session
           key for all subsequent traffic until the connection is closed.

    The protocol is **not yet fully implemented**.  ``connect()`` will
    raise ``NotImplementedError`` until the handshake byte-level format
    is reverse-engineered.
    """

    name = "ECDH+AES-CCM"

    # Expose module-level constants as class attributes for convenience.
    REJECT_FRAME_LENGTH = REJECT_FRAME_LENGTH
    REJECT_TRAILER = REJECT_TRAILER

    def __init__(self, euid: str) -> None:
        self._euid = euid
        self._private_key: EllipticCurvePrivateKey | None = None
        self._session_key: bytes | None = None
        self._sequence: int = 0

    # ------------------------------------------------------------------
    #  Key derivation helpers (placeholders — exact KDF TBD)
    # ------------------------------------------------------------------

    def _generate_keypair(self) -> EllipticCurvePrivateKey:
        """Generate an ephemeral ECDH key pair on secp256r1 (P-256)."""
        self._private_key = generate_private_key(SECP256R1())
        return self._private_key

    def get_public_key_bytes(self) -> bytes:
        """Return the uncompressed public key bytes for sending to the gateway."""
        if self._private_key is None:
            raise RuntimeError("Key pair not generated yet")
        return self._private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint,
        )

    def derive_session_key(
        self, peer_public_key: EllipticCurvePublicKey
    ) -> bytes:
        """Derive a 16-byte AES session key from the ECDH shared secret.

        The exact KDF (HKDF, raw SHA-256 truncation, etc.) is still
        under investigation.  This placeholder uses
        ``SHA-256(shared_secret)[:16]``.
        """
        if self._private_key is None:
            raise RuntimeError("Key pair not generated yet")
        shared = self._private_key.exchange(ECDH(), peer_public_key)
        self._session_key = hashlib.sha256(shared).digest()[:16]
        return self._session_key

    # ------------------------------------------------------------------
    #  Frame helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_reject_frame(raw: bytes) -> bool:
        """Return True if *raw* looks like a new-firmware reject frame.

        Delegates to :func:`protocol.is_reject_frame`.
        """
        return _is_reject_frame(raw)

    @staticmethod
    def strip_trailer(raw: bytes) -> tuple[bytes, bytes]:
        """Split a response into its block-aligned core and trailer.

        ``core = raw[0 : len - (len % 16)]``, trailer is the rest.
        """
        remainder = len(raw) % 16
        if remainder == 0:
            return raw, b""
        return raw[: len(raw) - remainder], raw[len(raw) - remainder:]

    def _build_trailer(self) -> bytes:
        """Build the request trailer: ``[seq][0xFD][check_hi][check_lo]``.

        The exact check-byte derivation is unknown.  This placeholder
        returns a 4-byte trailer with the current sequence and zeros
        for the check bytes.
        """
        seq = self._sequence & 0xFF
        self._sequence += 1
        # TODO: derive check_hi / check_lo once the algorithm is known
        return bytes([seq, 0xFD, 0x00, 0x00])

    # ------------------------------------------------------------------
    #  GatewayProtocol interface
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt with AES-CCM using the session key."""
        if self._session_key is None:
            raise RuntimeError("Session not established — call connect() first")
        nonce = os.urandom(_CCM_NONCE_LENGTH)
        aesccm = AESCCM(self._session_key, tag_length=_CCM_TAG_LENGTH)
        ct = aesccm.encrypt(nonce, plaintext.encode(), None)
        # Wire format: nonce ‖ ciphertext+tag
        return nonce + ct

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt AES-CCM ciphertext (nonce ‖ ct+tag)."""
        if self._session_key is None:
            raise RuntimeError("Session not established — call connect() first")
        nonce = ciphertext[:_CCM_NONCE_LENGTH]
        ct = ciphertext[_CCM_NONCE_LENGTH:]
        aesccm = AESCCM(self._session_key, tag_length=_CCM_TAG_LENGTH)
        return aesccm.decrypt(nonce, ct, None).decode()

    def wrap_request(self, body_json: str) -> bytes:
        """Encrypt and frame a request body for the wire."""
        encrypted_core = self.encrypt(body_json)
        return encrypted_core + self._build_trailer()

    def unwrap_response(self, raw: bytes) -> str:
        """Strip trailer, decrypt, and return the JSON string."""
        core, _trailer = self.strip_trailer(raw)
        return self.decrypt(core)

    async def connect(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        timeout: int,
    ) -> dict[str, Any]:
        """Perform the ECDH handshake and return the initial *readall*.

        Raises ``NotImplementedError`` until the byte-level handshake
        format is fully reverse-engineered.

        Sketch of the expected flow::

            1. Generate ephemeral ECDH key pair (P-256).
            2. POST /deviceid/read  with ``setup0Request`` containing
               our public key + random bytes.
            3. Receive ``setup0Response`` with the gateway's public key
               + gateway random.
            4. Derive shared secret via ECDH.
            5. Derive ``cipherSecretKey`` (AES-CCM session key) from the
               shared secret + both randoms.
            6. Send AES-CCM-encrypted ``{"requestAttr":"readall"}`` with
               trailer framing.
            7. Receive and decrypt the response.
        """
        _LOGGER.debug(
            "[%s] Handshake with %s:%d — not yet implemented, "
            "running diagnostic probes",
            self.name, host, port,
        )

        # Step 1 — generate our key pair
        self._generate_keypair()
        our_pub = self.get_public_key_bytes()
        _LOGGER.debug(
            "[%s] Generated ephemeral public key (%d bytes): %s",
            self.name, len(our_pub), our_pub.hex(),
        )

        # --- Diagnostic probes -------------------------------------------
        # We can't complete the handshake yet, but we CAN poke the gateway
        # with a few payloads and log what comes back.  This data is
        # invaluable for anyone reverse-engineering the protocol.
        base = f"http://{host}:{port}"
        probes = [
            # (label, method, url, body)
            ("raw public key POST",
             "POST", f"{base}/deviceid/read", our_pub),
            ("empty POST",
             "POST", f"{base}/deviceid/read", b""),
            ("plaintext JSON POST",
             "POST", f"{base}/deviceid/read",
             b'{"requestAttr":"readall"}'),
        ]

        for label, method, url, body in probes:
            try:
                async with asyncio.timeout(timeout):
                    if method == "POST":
                        resp = await session.post(
                            url, data=body,
                            headers={"content-type": "application/json"},
                        )
                    else:
                        resp = await session.get(url)
                    raw = await resp.read()
                _LOGGER.debug(
                    "[%s] Probe '%s' → HTTP %d, %d bytes, "
                    "reject=%s, hex=%s",
                    self.name, label, resp.status, len(raw),
                    _is_reject_frame(raw),
                    raw.hex() if len(raw) <= 512
                    else f"{raw[:256].hex()}...({len(raw)} total)",
                )
                # Log response headers — Content-Type and Server can
                # reveal firmware version / web-server identity.
                interesting = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() in (
                        "server", "content-type", "x-powered-by",
                        "www-authenticate",
                    )
                }
                if interesting:
                    _LOGGER.debug(
                        "[%s] Probe '%s' headers: %s",
                        self.name, label, interesting,
                    )
            except Exception as exc:
                _LOGGER.debug(
                    "[%s] Probe '%s' failed: %s", self.name, label, exc,
                )

        raise NotImplementedError(
            "ECDH+AES-CCM handshake is not yet implemented.  "
            "The exact byte-level protocol is still being reverse-engineered.  "
            "See https://github.com/epoplavskis/homeassistant_salus/issues/81"
        )
