"""ESP-IDF protocomm Security1 protocol for Salus gateways (firmware ≥ 2025).

New-firmware gateways replaced the static AES-CBC scheme with the ESP-IDF
*protocomm Security1* session protocol:

    1. Key exchange — X25519 (Curve25519 ECDH), 32-byte public keys.
    2. Key derivation — raw ECDH shared secret ⊕ SHA-256(PoP).
    3. Session encryption — AES-256-CTR with a 16-byte device random as IV.
    4. Wire format — protobuf ``SessionData`` messages over HTTP POST.

The handshake is a two-step exchange (SessionCmd0/Resp0, SessionCmd1/Resp1)
after which both sides share a 32-byte symmetric key for AES-256-CTR.

Reference: ``esp-idf/components/protocomm/src/security/security1.c``
Protobuf: ``esp-idf/components/protocomm/proto/{session,sec1,constants}.proto``

The gateway may or may not use a Proof-of-Possession (PoP).  When PoP is
used, ``SHA-256(pop)`` is XORed byte-by-byte into the raw ECDH shared key.
The diagnostic mode tries multiple PoP candidates automatically so the user
does not need to guess.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
from typing import Any

import aiohttp

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from .protocol import (
    REJECT_FRAME_LENGTH,
    REJECT_TRAILER,
    NEW_PROTOCOL_TRAILER,
    GatewayProtocol,
    is_reject_frame as _is_reject_frame,
    parse_frame_33,
)

_LOGGER = logging.getLogger(__name__)

# Protocomm Security1 constants (from ESP-IDF security1.c)
PUBLIC_KEY_LEN = 32  # X25519 public key size
SZ_RANDOM = 16       # device random / AES-CTR IV

# Protobuf field tags (wire type 0 = varint, 2 = length-delimited)
_WIRE_VARINT = 0
_WIRE_LEN = 2


# ---------------------------------------------------------------------------
#  Minimal protobuf encoder/decoder (no dependency required)
# ---------------------------------------------------------------------------

def _encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf varint."""
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts)


def _encode_field_varint(field_number: int, value: int) -> bytes:
    """Encode a field with wire type 0 (varint)."""
    tag = (field_number << 3) | _WIRE_VARINT
    return _encode_varint(tag) + _encode_varint(value)


def _encode_field_bytes(field_number: int, data: bytes) -> bytes:
    """Encode a field with wire type 2 (length-delimited)."""
    tag = (field_number << 3) | _WIRE_LEN
    return _encode_varint(tag) + _encode_varint(len(data)) + data


def _decode_protobuf(data: bytes) -> dict[int, list[tuple[int, bytes | int]]]:
    """Decode protobuf wire format into {field_number: [(wire_type, value)]}."""
    fields: dict[int, list[tuple[int, bytes | int]]] = {}
    pos = 0
    while pos < len(data):
        tag_val, pos = _read_varint(data, pos)
        wire_type = tag_val & 0x07
        field_num = tag_val >> 3

        if wire_type == _WIRE_VARINT:
            value, pos = _read_varint(data, pos)
        elif wire_type == _WIRE_LEN:
            length, pos = _read_varint(data, pos)
            value = data[pos:pos + length]
            pos += length
        elif wire_type == 5:  # 32-bit fixed
            value = data[pos:pos + 4]
            pos += 4
        elif wire_type == 1:  # 64-bit fixed
            value = data[pos:pos + 8]
            pos += 8
        else:
            break  # unknown wire type

        fields.setdefault(field_num, []).append((wire_type, value))
    return fields


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Read a varint starting at *pos*, return (value, new_pos)."""
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _get_bytes_field(fields: dict, field_num: int) -> bytes | None:
    """Extract a length-delimited field as bytes, or None."""
    entries = fields.get(field_num, [])
    for wire_type, value in entries:
        if wire_type == _WIRE_LEN and isinstance(value, bytes):
            return value
    return None


def _get_varint_field(fields: dict, field_num: int) -> int | None:
    """Extract a varint field, or None."""
    entries = fields.get(field_num, [])
    for wire_type, value in entries:
        if wire_type == _WIRE_VARINT and isinstance(value, int):
            return value
    return None


# ---------------------------------------------------------------------------
#  Protobuf message builders and parsers for Security1
# ---------------------------------------------------------------------------
#
#  SessionData { sec_ver=2; oneof proto { sec1=11: Sec1Payload } }
#  Sec1Payload { msg=1; oneof payload { sc0=20; sr0=21; sc1=22; sr1=23 } }
#  SessionCmd0 { client_pubkey=1 }
#  SessionResp0 { status=1; device_pubkey=2; device_random=3 }
#  SessionCmd1 { client_verify_data=2 }
#  SessionResp1 { status=1; device_verify_data=3 }
# ---------------------------------------------------------------------------

# Sec1MsgType enum values
SEC1_SESSION_COMMAND0 = 0
SEC1_SESSION_RESPONSE0 = 1
SEC1_SESSION_COMMAND1 = 2
SEC1_SESSION_RESPONSE1 = 3


def build_session_cmd0(client_pubkey: bytes) -> bytes:
    """Build a SessionData containing SessionCmd0."""
    # SessionCmd0: field 1 = client_pubkey
    sc0 = _encode_field_bytes(1, client_pubkey)
    # Sec1Payload: field 1 = msg (Session_Command0=0), field 20 = sc0
    sec1 = _encode_field_varint(1, SEC1_SESSION_COMMAND0) + _encode_field_bytes(20, sc0)
    # SessionData: field 2 = sec_ver (SecScheme1=1), field 11 = sec1
    return _encode_field_varint(2, 1) + _encode_field_bytes(11, sec1)


def parse_session_resp0(data: bytes) -> tuple[int, bytes, bytes]:
    """Parse a SessionData containing SessionResp0.

    Returns (status, device_pubkey, device_random).
    Raises ValueError on parse failures.
    """
    fields = _decode_protobuf(data)

    # sec_ver (field 2) — optional check
    sec_ver = _get_varint_field(fields, 2)
    if sec_ver is not None and sec_ver != 1:
        raise ValueError(f"Unexpected sec_ver={sec_ver}, expected 1 (Security1)")

    # sec1 (field 11) → Sec1Payload
    sec1_raw = _get_bytes_field(fields, 11)
    if sec1_raw is None:
        raise ValueError("Missing sec1 payload in SessionData")

    sec1_fields = _decode_protobuf(sec1_raw)

    # msg type (field 1)
    msg_type = _get_varint_field(sec1_fields, 1)
    if msg_type != SEC1_SESSION_RESPONSE0:
        raise ValueError(f"Expected Session_Response0 (1), got msg_type={msg_type}")

    # sr0 (field 21) → SessionResp0
    sr0_raw = _get_bytes_field(sec1_fields, 21)
    if sr0_raw is None:
        raise ValueError("Missing sr0 in Sec1Payload")

    sr0_fields = _decode_protobuf(sr0_raw)

    status = _get_varint_field(sr0_fields, 1)
    if status is None:
        status = 0  # proto3 default
    device_pubkey = _get_bytes_field(sr0_fields, 2)
    device_random = _get_bytes_field(sr0_fields, 3)

    if device_pubkey is None:
        raise ValueError("Missing device_pubkey in SessionResp0")
    if device_random is None:
        raise ValueError("Missing device_random in SessionResp0")

    return status, device_pubkey, device_random


def build_session_cmd1(client_verify_data: bytes) -> bytes:
    """Build a SessionData containing SessionCmd1."""
    # SessionCmd1: field 2 = client_verify_data
    sc1 = _encode_field_bytes(2, client_verify_data)
    # Sec1Payload: field 1 = msg (Session_Command1=2), field 22 = sc1
    sec1 = _encode_field_varint(1, SEC1_SESSION_COMMAND1) + _encode_field_bytes(22, sc1)
    # SessionData: field 2 = sec_ver (1), field 11 = sec1
    return _encode_field_varint(2, 1) + _encode_field_bytes(11, sec1)


def parse_session_resp1(data: bytes) -> tuple[int, bytes]:
    """Parse a SessionData containing SessionResp1.

    Returns (status, device_verify_data).
    Raises ValueError on parse failures.
    """
    fields = _decode_protobuf(data)
    sec1_raw = _get_bytes_field(fields, 11)
    if sec1_raw is None:
        raise ValueError("Missing sec1 payload in SessionData")

    sec1_fields = _decode_protobuf(sec1_raw)
    msg_type = _get_varint_field(sec1_fields, 1)
    if msg_type != SEC1_SESSION_RESPONSE1:
        raise ValueError(f"Expected Session_Response1 (3), got msg_type={msg_type}")

    sr1_raw = _get_bytes_field(sec1_fields, 23)
    if sr1_raw is None:
        raise ValueError("Missing sr1 in Sec1Payload")

    sr1_fields = _decode_protobuf(sr1_raw)
    status = _get_varint_field(sr1_fields, 1)
    if status is None:
        status = 0
    device_verify_data = _get_bytes_field(sr1_fields, 3)
    if device_verify_data is None:
        raise ValueError("Missing device_verify_data in SessionResp1")

    return status, device_verify_data


# ---------------------------------------------------------------------------
#  Security1 crypto operations
# ---------------------------------------------------------------------------

def derive_session_key(
    private_key: X25519PrivateKey,
    device_pubkey_bytes: bytes,
    pop: str | bytes | None = None,
) -> bytes:
    """Compute the Security1 session key.

    1. shared = X25519(private_key, device_pubkey)  → 32 bytes
    2. If pop: shared[i] ^= SHA-256(pop)[i] for i in 0..31
    3. Return shared (32 bytes, used as AES-256 key)
    """
    device_pubkey = X25519PublicKey.from_public_bytes(device_pubkey_bytes)
    shared = bytearray(private_key.exchange(device_pubkey))

    if pop is not None:
        pop_bytes = pop.encode() if isinstance(pop, str) else pop
        if pop_bytes:
            pop_hash = hashlib.sha256(pop_bytes).digest()
            for i in range(PUBLIC_KEY_LEN):
                shared[i] ^= pop_hash[i]

    return bytes(shared)


def aes_ctr_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-256-CTR encrypt (same operation as decrypt)."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CTR decrypt (same operation as encrypt)."""
    return aes_ctr_encrypt(key, iv, ciphertext)  # CTR is symmetric


# Known PoP candidates to try during handshake.
# Order: most likely first.  None means "no PoP".
_POP_CANDIDATES_STATIC: list[str | None] = [
    None,                   # no PoP (most common for LAN)
    "",                     # empty string PoP
    "abcd1234",             # Espressif default example
    "Salus",                # brand name
    "salus",                # lowercase
    "iT600",                # product line
    "Caldera Derived Key",  # found in libapp.so
]


def _build_pop_candidates(euid: str) -> list[str | None]:
    """Return ordered PoP candidates, including EUID-derived ones."""
    euid_upper = euid.upper()
    euid_lower = euid.lower()
    md5_euid = hashlib.md5(euid.encode()).hexdigest()  # noqa: S324

    # EUID-based candidates inserted after the static ones
    euid_based: list[str] = [
        euid_upper,                      # raw EUID
        euid_lower,                      # lowercase
        f"Salus-{euid_upper}",           # matches AES-CBC key derivation pattern
        f"Salus-{euid_lower}",
        md5_euid,                        # MD5 hex, matches old key style
        euid_upper[:8],                  # first 8 chars (common truncation)
    ]

    return _POP_CANDIDATES_STATIC + euid_based


class EcdhAesCcmProtocol(GatewayProtocol):
    """ESP-IDF Security1 protocol (X25519 + AES-256-CTR).

    Despite the class name (kept for backward compatibility), the actual
    protocol uses AES-256-CTR, not AES-CCM.  The initial assumption of
    AES-CCM has been superseded by reverse-engineering of the Salus APK
    which revealed the protocol is standard ESP-IDF protocomm Security1.

    Lifecycle:
        1. ``connect()`` — performs the Security1 handshake with the
           gateway, establishes a shared AES-256-CTR session key.
        2. ``encrypt()`` / ``decrypt()`` — use the session key for
           subsequent requests.
    """

    name = "ECDH+AES-CCM"

    # Expose module-level constants as class attributes for convenience.
    REJECT_FRAME_LENGTH = REJECT_FRAME_LENGTH
    REJECT_TRAILER = REJECT_TRAILER
    NEW_PROTOCOL_TRAILER = NEW_PROTOCOL_TRAILER

    def __init__(self, euid: str) -> None:
        self._euid = euid
        self._private_key: X25519PrivateKey | None = None
        self._session_key: bytes | None = None
        self._device_random: bytes | None = None
        self._sequence: int = 0

    # ------------------------------------------------------------------
    #  Key management
    # ------------------------------------------------------------------

    def _generate_keypair(self) -> X25519PrivateKey:
        """Generate an ephemeral X25519 key pair."""
        self._private_key = X25519PrivateKey.generate()
        return self._private_key

    def get_public_key_bytes(self) -> bytes:
        """Return the 32-byte raw X25519 public key."""
        if self._private_key is None:
            raise RuntimeError("Key pair not generated yet")
        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )

    def derive_session_key(
        self,
        device_pubkey_bytes: bytes,
        pop: str | bytes | None = None,
    ) -> bytes:
        """Derive the 32-byte AES-256-CTR session key from ECDH + optional PoP."""
        if self._private_key is None:
            raise RuntimeError("Key pair not generated yet")
        self._session_key = derive_session_key(
            self._private_key, device_pubkey_bytes, pop,
        )
        return self._session_key

    # ------------------------------------------------------------------
    #  Frame helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_reject_frame(raw: bytes) -> bool:
        return _is_reject_frame(raw)

    @staticmethod
    def strip_trailer(raw: bytes) -> tuple[bytes, bytes]:
        """Split a response into its block-aligned core and trailer."""
        remainder = len(raw) % 16
        if remainder == 0:
            return raw, b""
        return raw[: len(raw) - remainder], raw[len(raw) - remainder:]

    # ------------------------------------------------------------------
    #  GatewayProtocol interface
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt with AES-256-CTR using the session key."""
        if self._session_key is None:
            raise RuntimeError("Session not established — call connect() first")
        if self._device_random is None:
            raise RuntimeError("No device_random — session not established")
        return aes_ctr_encrypt(
            self._session_key, self._device_random, plaintext.encode(),
        )

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt AES-256-CTR ciphertext using the session key."""
        if self._session_key is None:
            raise RuntimeError("Session not established — call connect() first")
        if self._device_random is None:
            raise RuntimeError("No device_random — session not established")
        return aes_ctr_decrypt(
            self._session_key, self._device_random, ciphertext,
        ).decode()

    def wrap_request(self, body_json: str) -> bytes:
        """Encrypt the JSON body for the wire."""
        return self.encrypt(body_json)

    def unwrap_response(self, raw: bytes) -> str:
        """Decrypt the response body."""
        return self.decrypt(raw)

    async def connect(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        timeout: int,
    ) -> dict[str, Any]:
        """Perform Security1 handshake and return the initial *readall*.

        Tries multiple PoP candidates.  If the handshake succeeds with
        any of them, stores the session key and returns the parsed JSON.
        If all fail, runs comprehensive diagnostics and raises.
        """
        _LOGGER.debug(
            "[%s] Starting Security1 handshake with %s:%d",
            self.name, host, port,
        )

        base = f"http://{host}:{port}"
        diag = _DiagnosticCollector(self.name)

        # Try the prov-session endpoint first (standard ESP-IDF),
        # fall back to /deviceid/read (Salus custom).
        session_endpoints = [
            f"{base}/prov-session",
            f"{base}/deviceid/read",
        ]

        for endpoint in session_endpoints:
            result = await self._try_handshake_at_endpoint(
                session, endpoint, timeout, diag,
            )
            if result is not None:
                return result

        # All attempts failed — run fallback probes before giving up
        await self._run_fallback_probes(session, base, timeout, diag)

        diag.emit_summary(host, port, self._euid)
        raise NotImplementedError(
            "Security1 handshake failed with all PoP candidates and endpoints.  "
            "See the WARNING log above for the full diagnostic report.  "
            "See https://github.com/leonardpitzu/homeassistant_salus/issues/3"
        )

    async def _try_handshake_at_endpoint(
        self,
        http_session: aiohttp.ClientSession,
        endpoint: str,
        timeout: int,
        diag: _DiagnosticCollector,
    ) -> dict[str, Any] | None:
        """Attempt the Security1 handshake at a single endpoint.

        Returns the readall JSON dict on success, None on failure.
        """
        # --- Step 0: generate fresh keypair ---
        self._generate_keypair()
        our_pubkey = self.get_public_key_bytes()
        diag.log(f"Endpoint: {endpoint}")
        diag.log(f"Client pubkey ({len(our_pubkey)}B): {our_pubkey.hex()}")

        # --- Step 1: SessionCmd0 ---
        cmd0 = build_session_cmd0(our_pubkey)
        diag.log(f"SessionCmd0 ({len(cmd0)}B): {cmd0.hex()}")

        resp0_raw = await self._post(
            http_session, endpoint, cmd0, timeout, diag, "SessionCmd0",
        )
        if resp0_raw is None:
            return None

        # --- Parse SessionResp0 ---
        try:
            status0, device_pubkey, device_random = parse_session_resp0(resp0_raw)
        except ValueError as exc:
            diag.log(f"SessionResp0 parse failed: {exc}")
            diag.log(f"  raw ({len(resp0_raw)}B): {resp0_raw.hex()}")
            diag.log("  Trying to interpret as raw fields...")
            self._try_interpret_raw_resp0(resp0_raw, diag)
            return None

        diag.log(f"SessionResp0: status={status0}")
        diag.log(f"  device_pubkey ({len(device_pubkey)}B): {device_pubkey.hex()}")
        diag.log(f"  device_random ({len(device_random)}B): {device_random.hex()}")

        if status0 != 0:
            diag.log(f"  ⚠ Non-zero status: {status0}")
            return None

        if len(device_pubkey) != PUBLIC_KEY_LEN:
            diag.log(
                f"  ⚠ Unexpected pubkey length: {len(device_pubkey)} "
                f"(expected {PUBLIC_KEY_LEN})"
            )

        if len(device_random) != SZ_RANDOM:
            diag.log(
                f"  ⚠ Unexpected random length: {len(device_random)} "
                f"(expected {SZ_RANDOM})"
            )

        # --- Step 2: Try each PoP candidate for SessionCmd1 ---
        pop_candidates = _build_pop_candidates(self._euid)
        for pop in pop_candidates:
            pop_label = repr(pop) if pop is not None else "None (no PoP)"
            diag.log(f"Trying PoP: {pop_label}")

            try:
                session_key = derive_session_key(
                    self._private_key, device_pubkey, pop,
                )
            except Exception as exc:
                diag.log(f"  Key derivation failed: {exc}")
                continue

            diag.log(f"  session_key: {session_key.hex()}")

            # Encrypt device_pubkey with session_key + device_random as IV
            client_verify = aes_ctr_encrypt(
                session_key, device_random, device_pubkey,
            )
            diag.log(f"  client_verify ({len(client_verify)}B): {client_verify.hex()}")

            cmd1 = build_session_cmd1(client_verify)
            diag.log(f"  SessionCmd1 ({len(cmd1)}B): {cmd1.hex()}")

            resp1_raw = await self._post(
                http_session, endpoint, cmd1, timeout, diag,
                f"SessionCmd1(pop={pop_label})",
            )
            if resp1_raw is None:
                continue

            # --- Parse SessionResp1 ---
            try:
                status1, device_verify = parse_session_resp1(resp1_raw)
            except ValueError as exc:
                diag.log(f"  SessionResp1 parse failed: {exc}")
                diag.log(f"  raw ({len(resp1_raw)}B): {resp1_raw.hex()}")
                continue

            diag.log(f"  SessionResp1: status={status1}")
            diag.log(f"  device_verify ({len(device_verify)}B): {device_verify.hex()}")

            if status1 != 0:
                diag.log("  ⚠ Non-zero status — PoP likely wrong")
                continue

            # Verify: decrypt device_verify should equal our pubkey
            # The CTR stream continues from where cmd1 left off.
            # In Security1, the device uses the same CTR stream that was
            # initialized with device_random.  After encrypting 32 bytes
            # (device_pubkey → client_verify), the next 32 bytes of CTR
            # stream encrypt client_pubkey → device_verify.
            #
            # We need to decrypt device_verify using the CTR state at
            # offset 32 (after the first 32 bytes were consumed).
            # AES-CTR is stateless per-block, so we can compute it by
            # encrypting 64 bytes and taking the last 32:
            combined = aes_ctr_decrypt(
                session_key,
                device_random,
                client_verify + device_verify,
            )
            decrypted_our_pubkey = combined[PUBLIC_KEY_LEN:]

            diag.log(f"  Decrypted device_verify: {decrypted_our_pubkey.hex()}")
            diag.log(f"  Our pubkey:              {our_pubkey.hex()}")

            if decrypted_our_pubkey == our_pubkey:
                diag.log(f"  ✓ HANDSHAKE SUCCESS with pop={pop_label}")
                self._session_key = session_key
                self._device_random = device_random

                # Attempt readall
                return await self._do_readall(
                    http_session, endpoint, timeout, diag,
                )
            else:
                diag.log("  ✗ Verification mismatch — wrong PoP or protocol variant")

        diag.log(f"All PoP candidates exhausted for {endpoint}")
        return None

    async def _post(
        self,
        http_session: aiohttp.ClientSession,
        url: str,
        body: bytes,
        timeout: int,
        diag: _DiagnosticCollector,
        label: str,
    ) -> bytes | None:
        """POST binary data and return the response body, or None on error."""
        try:
            async with asyncio.timeout(timeout):
                resp = await http_session.post(
                    url,
                    data=body,
                    headers={"content-type": "application/x-protocomm"},
                )
                raw = await resp.read()
        except Exception as exc:
            diag.log(f"  HTTP POST {label} failed: {exc}")
            return None

        diag.log(
            f"  HTTP POST {label} → {resp.status}, {len(raw)}B"
        )

        if len(raw) <= 512:
            diag.log(f"  Response hex: {raw.hex()}")
        else:
            diag.log(f"  Response hex: {raw[:128].hex()}... ({len(raw)}B total)")

        interesting = {
            k: v for k, v in resp.headers.items()
            if k.lower() in (
                "server", "content-type", "x-powered-by",
                "www-authenticate",
            )
        }
        if interesting:
            diag.log(f"  Response headers: {interesting}")

        frame = parse_frame_33(raw)
        if frame is not None:
            diag.log(
                f"  ⚠ Got 33-byte frame: type={frame.trailer_name}, "
                f"counter={frame.counter}, tag={frame.tag.hex()}"
            )

        if resp.status != 200:
            diag.log(f"  ⚠ Non-200 status: {resp.status}")
            return None

        return raw

    async def _do_readall(
        self,
        http_session: aiohttp.ClientSession,
        session_endpoint: str,
        timeout: int,
        diag: _DiagnosticCollector,
    ) -> dict[str, Any]:
        """Issue an encrypted readall request after handshake."""
        diag.log("Attempting encrypted readall...")
        body = json.dumps({"requestAttr": "readall"})
        encrypted = self.encrypt(body)

        # Determine the data endpoint:
        # If handshake was on /prov-session, data goes to a different endpoint.
        # If handshake was on /deviceid/read, data stays there.
        base = session_endpoint.rsplit("/", 1)[0]
        data_urls = [
            f"{base}/deviceid/read",
            session_endpoint,
        ]

        for url in data_urls:
            diag.log(f"  POST readall to {url} ({len(encrypted)}B)")
            try:
                async with asyncio.timeout(timeout):
                    resp = await http_session.post(
                        url,
                        data=encrypted,
                        headers={"content-type": "application/x-protocomm"},
                    )
                    raw = await resp.read()
            except Exception as exc:
                diag.log(f"  Readall to {url} failed: {exc}")
                continue

            diag.log(f"  Readall response: HTTP {resp.status}, {len(raw)}B")
            if len(raw) <= 256:
                diag.log(f"  Response hex: {raw.hex()}")

            if resp.status != 200 or not raw:
                continue

            try:
                text = self.decrypt(raw)
                diag.log(f"  Decrypted ({len(text)} chars): {text[:200]}...")
                result = json.loads(text)
                if result.get("status") == "success":
                    diag.log("  ✓ READALL SUCCESS")
                    return result
                diag.log(f"  Unexpected status: {result.get('status')}")
            except Exception as exc:
                diag.log(f"  Decrypt/parse failed: {exc}")
                diag.log("  Trying alternate framing...")
                # Try stripping trailer before decrypting
                core, trailer = self.strip_trailer(raw)
                if core:
                    try:
                        text = self.decrypt(core)
                        result = json.loads(text)
                        if result.get("status") == "success":
                            diag.log("  ✓ READALL SUCCESS (with trailer stripped)")
                            return result
                    except Exception as exc2:
                        diag.log(f"  Still failed after strip: {exc2}")

        raise ValueError("Handshake succeeded but readall failed — see diagnostics")

    async def _run_fallback_probes(
        self,
        http_session: aiohttp.ClientSession,
        base: str,
        timeout: int,
        diag: _DiagnosticCollector,
    ) -> None:
        """Run additional diagnostic probes when Security1 protobuf fails.

        Tries alternative content-types, raw binary payloads, GET requests,
        and other endpoint paths to gather data for manual analysis.
        """
        diag.log("")
        diag.log("=== FALLBACK DIAGNOSTIC PROBES ===")

        our_pubkey = self.get_public_key_bytes()
        our_random = os.urandom(16)
        pub_b64 = base64.b64encode(our_pubkey).decode()
        rand_b64 = base64.b64encode(our_random).decode()

        async def _send(
            label: str,
            url: str,
            *,
            method: str = "POST",
            body: bytes | None = None,
            content_type: str = "application/json",
        ) -> None:
            """Send one probe, log everything."""
            try:
                async with asyncio.timeout(timeout):
                    headers = {"content-type": content_type}
                    if method == "GET":
                        resp = await http_session.get(url, headers=headers)
                    else:
                        resp = await http_session.post(
                            url, data=body, headers=headers,
                        )
                    raw = await resp.read()
            except Exception as exc:
                diag.log(f"  [{label}] {method} → ERROR: {exc}")
                return

            diag.log(f"  [{label}] {method} → HTTP {resp.status}, {len(raw)}B")
            if len(raw) <= 512:
                diag.log(f"    hex: {raw.hex()}")
            else:
                diag.log(f"    hex: {raw[:128].hex()}... ({len(raw)}B total)")

            frame = parse_frame_33(raw)
            if frame is not None:
                diag.log(
                    f"    Frame33: type={frame.trailer_name}, "
                    f"counter={frame.counter}, tag={frame.tag.hex()}"
                )

            interesting_hdrs = {
                k: v for k, v in resp.headers.items()
                if k.lower() in (
                    "server", "content-type", "x-powered-by",
                    "www-authenticate",
                )
            }
            if interesting_hdrs:
                diag.log(f"    headers: {interesting_hdrs}")

        # --- Probe: content-type sensitivity on /deviceid/read ---
        diag.log("-- Content-type sensitivity --")
        read_url = f"{base}/deviceid/read"
        cmd0 = build_session_cmd0(our_pubkey)

        for ct in (
            "application/json",
            "application/octet-stream",
            "application/x-www-form-urlencoded",
        ):
            await _send(f"cmd0 as {ct}", read_url, body=cmd0, content_type=ct)

        # --- Probe: raw binary (no protobuf wrapping) ---
        diag.log("-- Raw binary payloads --")
        await _send(
            "raw-pubkey-32B", read_url,
            body=our_pubkey,
            content_type="application/octet-stream",
        )
        await _send(
            "raw-pubkey+random-48B", read_url,
            body=our_pubkey + our_random,
            content_type="application/octet-stream",
        )

        # --- Probe: JSON-wrapped handshake (APK-style) ---
        diag.log("-- JSON handshake payloads --")
        setup0 = json.dumps({
            "setup0Request": {
                "publicKey": pub_b64,
                "random": rand_b64,
            }
        })
        await _send(
            "setup0Request-JSON", read_url,
            body=setup0.encode(),
            content_type="application/json",
        )
        await _send(
            "readall-JSON", read_url,
            body=b'{"requestAttr":"readall"}',
            content_type="application/json",
        )

        # --- Probe: HTTP GET on key endpoints ---
        diag.log("-- GET requests --")
        for path in ("/deviceid/read", "/prov-session", "/proto-ver", "/deviceid"):
            await _send(f"GET {path}", f"{base}{path}", method="GET")

        # --- Probe: other endpoint paths ---
        diag.log("-- Additional endpoints --")
        for path in (
            "/deviceid/write",
            "/deviceid/setup",
            "/deviceid",
            "/prov-config",
            "/prov-scan",
        ):
            await _send(f"POST {path}", f"{base}{path}", body=b"")

        # --- Probe: empty POST ---
        diag.log("-- Empty POSTs --")
        await _send("empty-to-read", read_url, body=b"")
        await _send(
            "empty-to-prov", f"{base}/prov-session", body=b"",
        )

        diag.log("=== END FALLBACK PROBES ===")
        diag.log("")

    @staticmethod
    def _try_interpret_raw_resp0(raw: bytes, diag: _DiagnosticCollector) -> None:
        """Try to interpret a raw response as SessionResp0 fields.

        Logs any plausible field boundaries for manual inspection.
        """
        if len(raw) >= PUBLIC_KEY_LEN + SZ_RANDOM:
            # Maybe raw = device_pubkey (32) + device_random (16) without protobuf?
            pk = raw[:PUBLIC_KEY_LEN]
            rnd = raw[PUBLIC_KEY_LEN:PUBLIC_KEY_LEN + SZ_RANDOM]
            diag.log(f"  Possible raw fields: pubkey={pk.hex()}, random={rnd.hex()}")
        if len(raw) == 33:
            frame = parse_frame_33(raw)
            if frame:
                diag.log(
                    f"  Looks like a Frame33: {frame.trailer_name}, "
                    f"counter={frame.counter}"
                )

        # Try interpreting as protobuf at different offsets
        for offset in (0, 1, 2, 4):
            if offset >= len(raw):
                break
            try:
                fields = _decode_protobuf(raw[offset:])
                if fields:
                    diag.log(f"  Protobuf at offset {offset}: fields={list(fields.keys())}")
                    for fnum, entries in fields.items():
                        for _wt, val in entries:
                            if isinstance(val, bytes):
                                diag.log(
                                    f"    field {fnum} (len-delim, {len(val)}B): "
                                    f"{val[:32].hex()}{'...' if len(val) > 32 else ''}"
                                )
                            else:
                                diag.log(f"    field {fnum} (varint): {val}")
            except Exception:
                pass


# ---------------------------------------------------------------------------
#  Diagnostic Collector
# ---------------------------------------------------------------------------

class _DiagnosticCollector:
    """Collects diagnostic messages for structured debugging output."""

    def __init__(self, protocol_name: str) -> None:
        self._name = protocol_name
        self._lines: list[str] = []

    def log(self, msg: str) -> None:
        """Record a diagnostic line and emit it at DEBUG level."""
        self._lines.append(msg)
        _LOGGER.debug("[%s] %s", self._name, msg)

    def emit_summary(self, host: str, port: int, euid: str) -> None:
        """Emit the full diagnostic summary at WARNING level."""
        euid_masked = euid[:4] + "…" + euid[-4:]
        header = [
            "",
            "=" * 72,
            "  SALUS GATEWAY SECURITY1 HANDSHAKE DIAGNOSTIC REPORT",
            "=" * 72,
            f"  Host: {host}:{port}",
            f"  EUID: {euid_masked}",
            f"  Diagnostic lines: {len(self._lines)}",
            "-" * 72,
        ]
        footer = [
            "-" * 72,
            "  Copy everything above when reporting issues at:",
            "  https://github.com/leonardpitzu/homeassistant_salus/issues/3",
            "=" * 72,
            "",
        ]
        full = "\n".join(header + self._lines + footer)
        _LOGGER.warning(full)
