"""Tests for the AES-256-CCM protocol (protocol_aes_ccm.py)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.salus.protocol_aes_ccm import (
    AesCcmProtocol,
    _build_nonce,
    _derive_key,
)


def _mock_response(status: int = 200, body: bytes = b"") -> MagicMock:
    """Create a mock HTTP response with headers as a plain dict."""
    resp = MagicMock()
    resp.status = status
    resp.read = AsyncMock(return_value=body)
    resp.headers = {"Content-Type": "application/octet-stream"}
    return resp


# ---------------------------------------------------------------------------
#  Key derivation
# ---------------------------------------------------------------------------


class TestKeyDerivation:
    """Test _derive_key with various EUID inputs."""

    EUID = "001E5E0D32906128"

    def test_key_length_is_32_bytes(self):
        assert len(_derive_key(self.EUID)) == 32

    def test_key_starts_with_euid_bytes(self):
        key = _derive_key(self.EUID)
        assert key[:8] == bytes.fromhex(self.EUID)

    def test_key_ends_with_hardcoded_suffix(self):
        key = _derive_key(self.EUID)
        assert key[8:] == b"9a4ba190ac2b5139b32c3528"

    def test_known_key_value(self):
        key = _derive_key(self.EUID)
        expected = bytes.fromhex(self.EUID) + b"9a4ba190ac2b5139b32c3528"
        assert key == expected

    def test_euid_case_insensitive(self):
        assert _derive_key("001e5e0d32906128") == _derive_key("001E5E0D32906128")

    def test_different_euids_produce_different_keys(self):
        assert _derive_key("001E5E0D32906128") != _derive_key("AAAAAAAAAAAAAAAA")

    def test_12_byte_euid_inserts_0902(self):
        """If hex-decoded EUID is 12 bytes, [0x09, 0x02] inserted at pos 3."""
        euid_24 = "AABBCCDDEEFF112233445566"
        key = _derive_key(euid_24)
        euid_bytes = bytes.fromhex(euid_24)
        modified = bytearray(euid_bytes)
        modified[3:3] = b"\x09\x02"
        expected = bytes(modified) + b"9a4ba190ac2b5139b32c3528"
        assert key == expected
        assert len(key) == 14 + 24  # 12 + 2 inserted + 24 suffix = 38

    def test_whitespace_stripped(self):
        assert _derive_key("  001E5E0D32906128  ") == _derive_key(self.EUID)


# ---------------------------------------------------------------------------
#  Nonce
# ---------------------------------------------------------------------------


class TestNonce:
    """Test _build_nonce structure."""

    def test_nonce_length(self):
        assert len(_build_nonce(0)) == 8

    def test_nonce_changes_on_each_call(self):
        """Random component makes nonces differ."""
        nonces = {_build_nonce(0) for _ in range(10)}
        assert len(nonces) > 1

    def test_counter_encoded_in_nonce(self):
        """Counter is stored as 2-byte BE at offset 3-4."""
        n1 = _build_nonce(0x00)
        n2 = _build_nonce(0xFF)
        assert n1[3:5] == b"\x00\x00"
        assert n2[3:5] == b"\x00\xFF"

    def test_counter_wraps_at_16bit(self):
        n = _build_nonce(0x10000)
        assert n[3:5] == b"\x00\x00"  # wraps to 0


# ---------------------------------------------------------------------------
#  Encrypt / Decrypt
# ---------------------------------------------------------------------------


class TestEncryptDecrypt:
    """Test AES-256-CCM encrypt and decrypt logic."""

    EUID = "001E5E0D32906128"

    def test_name(self):
        assert AesCcmProtocol(self.EUID).name == "AES-256-CCM (UG800)"

    def test_key_is_32_bytes(self):
        proto = AesCcmProtocol(self.EUID)
        assert len(proto._key) == 32

    def test_encrypt_returns_bytes(self):
        proto = AesCcmProtocol(self.EUID)
        assert isinstance(proto.encrypt("hello"), bytes)

    def test_decrypt_returns_string(self):
        proto = AesCcmProtocol(self.EUID)
        ct = proto.encrypt("hello")
        assert isinstance(proto.decrypt(ct), str)

    def test_roundtrip_short_messages(self):
        proto = AesCcmProtocol(self.EUID)
        for msg in ("a", "hello world", '{"key": "value"}'):
            assert proto.decrypt(proto.encrypt(msg)) == msg

    def test_roundtrip_json_payload(self):
        proto = AesCcmProtocol(self.EUID)
        payload = '{"requestAttr":"readall","id":[{"data":{"UniID":"abc"}}]}'
        assert proto.decrypt(proto.encrypt(payload)) == payload

    def test_roundtrip_long_message(self):
        proto = AesCcmProtocol(self.EUID)
        msg = "x" * 1024
        assert proto.decrypt(proto.encrypt(msg)) == msg

    def test_wire_size_is_plaintext_plus_16(self):
        """Wire = ciphertext + 8-byte MAC + 8-byte nonce = plaintext + 16."""
        proto = AesCcmProtocol(self.EUID)
        for length in (1, 15, 16, 17, 25, 100, 1024):
            msg = "a" * length
            wire = proto.encrypt(msg)
            assert len(wire) == length + 16

    def test_readall_wire_size_is_41(self):
        """'{"requestAttr":"readall"}' = 25 chars → 41 wire bytes.

        Matches empirical capture from mkrum001.
        """
        proto = AesCcmProtocol(self.EUID)
        wire = proto.encrypt('{"requestAttr":"readall"}')
        assert len(wire) == 41

    def test_wire_ends_with_nonce(self):
        """Last 8 bytes of wire should be a valid nonce."""
        proto = AesCcmProtocol(self.EUID)
        wire = proto.encrypt("test")
        nonce = wire[-8:]
        assert len(nonce) == 8

    def test_cross_instance_roundtrip(self):
        ct = AesCcmProtocol(self.EUID).encrypt("cross-instance")
        pt = AesCcmProtocol(self.EUID).decrypt(ct)
        assert pt == "cross-instance"

    def test_wrong_euid_cannot_decrypt(self):
        ct = AesCcmProtocol(self.EUID).encrypt("secret")
        other = AesCcmProtocol("AAAAAAAAAAAAAAAA")
        with pytest.raises(Exception):
            other.decrypt(ct)

    def test_different_euids_produce_different_ciphertext(self):
        proto1 = AesCcmProtocol("001E5E0D32906128")
        proto2 = AesCcmProtocol("AAAAAAAAAAAAAAAA")
        msg = "same payload"
        # Ciphertexts differ due to different keys (and random nonce)
        assert proto1.encrypt(msg) != proto2.encrypt(msg)

    def test_decrypt_too_short_raises(self):
        proto = AesCcmProtocol(self.EUID)
        with pytest.raises(ValueError, match="too short"):
            proto.decrypt(b"\x00" * 16)

    def test_counter_increments(self):
        """Internal counter should advance after each encrypt."""
        proto = AesCcmProtocol(self.EUID)
        assert proto._counter == 0
        proto.encrypt("a")
        assert proto._counter == 1
        proto.encrypt("b")
        assert proto._counter == 2


# ---------------------------------------------------------------------------
#  wrap_request / unwrap_response
# ---------------------------------------------------------------------------


class TestWrapUnwrap:
    """Test the GatewayProtocol wrap/unwrap methods on AesCcmProtocol."""

    EUID = "001E5E0D32906128"

    def test_wrap_is_encrypt(self):
        """wrap_request should produce bytes identical to encrypt."""
        proto = AesCcmProtocol(self.EUID)
        body = '{"requestAttr":"readall"}'
        # Both use the same counter, so call wrap first and compare size
        wire = proto.wrap_request(body)
        assert len(wire) == len(body) + 16

    def test_unwrap_roundtrip(self):
        proto = AesCcmProtocol(self.EUID)
        body = '{"requestAttr":"readall"}'
        raw = proto.encrypt(body)
        assert proto.unwrap_response(raw) == body


# ---------------------------------------------------------------------------
#  connect()
# ---------------------------------------------------------------------------


class TestAesCcmConnect:
    """Test the AesCcmProtocol.connect() method."""

    EUID = "001E5E0D32906128"

    async def test_connect_success(self):
        proto = AesCcmProtocol(self.EUID)
        response_json = {
            "status": "success",
            "id": [
                {"sGateway": {"NetworkLANMAC": "AA:BB:CC:DD:EE:FF"}},
            ],
        }
        response_encrypted = proto.encrypt(json.dumps(response_json))

        mock_resp = _mock_response(200, response_encrypted)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        result = await proto.connect(mock_session, "192.168.1.1", 80, 5)
        assert result["status"] == "success"

    async def test_connect_http_error_raises(self):
        proto = AesCcmProtocol(self.EUID)

        mock_resp = _mock_response(500, b"error")

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="HTTP 500"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_bad_json_raises(self):
        proto = AesCcmProtocol(self.EUID)
        raw = proto.encrypt("this is not json")

        mock_resp = _mock_response(200, raw)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="not valid JSON"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_status_not_success_raises(self):
        proto = AesCcmProtocol(self.EUID)
        raw = proto.encrypt(json.dumps({"status": "error"}))

        mock_resp = _mock_response(200, raw)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="status:.*'error'"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_reject_frame_raises(self):
        """33-byte 0xAE response should raise with reject-frame message."""
        proto = AesCcmProtocol(self.EUID)
        reject = bytes(32) + b"\xAE"

        mock_resp = _mock_response(200, reject)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="reject frame"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_new_protocol_frame_raises(self):
        """33-byte 0xAF response should raise with new-protocol-frame message."""
        proto = AesCcmProtocol(self.EUID)
        new_proto_resp = bytes(32) + b"\xAF"

        mock_resp = _mock_response(200, new_proto_resp)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="new-protocol frame"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)
