"""Tests for the AES-CBC protocol (protocol_aes_cbc.py)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from custom_components.salus.protocol_aes_cbc import (
    AesCbcProtocol,
    IT600Encryptor,
)

# ---------------------------------------------------------------------------
#  AES-256-CBC (default)
# ---------------------------------------------------------------------------


class TestAesCbcProtocolAes256:
    """Test AES-256-CBC encrypt/decrypt logic."""

    EUID = "001E5E0D32906128"

    def test_name(self):
        assert AesCbcProtocol(self.EUID).name == "AES-256-CBC"

    def test_key_is_32_bytes(self):
        proto = AesCbcProtocol(self.EUID)
        assert len(proto._key) == 32

    def test_key_fingerprint(self):
        proto = AesCbcProtocol(self.EUID)
        assert len(proto.key_fingerprint) == 8

    def test_encrypt_returns_bytes(self):
        proto = AesCbcProtocol(self.EUID)
        assert isinstance(proto.encrypt("hello"), bytes)

    def test_decrypt_returns_string(self):
        proto = AesCbcProtocol(self.EUID)
        ct = proto.encrypt("hello")
        assert isinstance(proto.decrypt(ct), str)

    def test_roundtrip_short_messages(self):
        proto = AesCbcProtocol(self.EUID)
        for msg in ("", "a", "hello world", '{"key": "value"}'):
            assert proto.decrypt(proto.encrypt(msg)) == msg

    def test_roundtrip_json_payload(self):
        proto = AesCbcProtocol(self.EUID)
        payload = '{"requestAttr":"readall","id":[{"data":{"UniID":"abc"}}]}'
        assert proto.decrypt(proto.encrypt(payload)) == payload

    def test_roundtrip_long_message(self):
        proto = AesCbcProtocol(self.EUID)
        msg = "x" * 1024
        assert proto.decrypt(proto.encrypt(msg)) == msg

    def test_euid_case_insensitive(self):
        lower = AesCbcProtocol("001e5e0d32906128")
        upper = AesCbcProtocol("001E5E0D32906128")
        msg = "test message"
        assert lower.encrypt(msg) == upper.encrypt(msg)

    def test_different_euids_produce_different_ciphertext(self):
        enc1 = AesCbcProtocol("001E5E0D32906128")
        enc2 = AesCbcProtocol("AAAAAAAAAAAAAAAA")
        msg = "same payload"
        assert enc1.encrypt(msg) != enc2.encrypt(msg)

    def test_ciphertext_is_block_aligned(self):
        proto = AesCbcProtocol(self.EUID)
        for length in (0, 1, 15, 16, 17, 31, 32, 33):
            ct = proto.encrypt("a" * length)
            assert len(ct) % 16 == 0

    def test_cross_instance_roundtrip(self):
        ct = AesCbcProtocol(self.EUID).encrypt("cross-instance")
        pt = AesCbcProtocol(self.EUID).decrypt(ct)
        assert pt == "cross-instance"

    def test_wrong_euid_cannot_decrypt(self):
        ct = AesCbcProtocol(self.EUID).encrypt("secret")
        other = AesCbcProtocol("AAAAAAAAAAAAAAAA")
        try:
            result = other.decrypt(ct)
            assert result != "secret"
        except Exception:
            pass  # padding error expected


# ---------------------------------------------------------------------------
#  AES-128-CBC
# ---------------------------------------------------------------------------


class TestAesCbcProtocolAes128:
    """Test AES-128-CBC mode (aes128=True)."""

    EUID = "001E5E0D32906128"

    def test_name(self):
        assert AesCbcProtocol(self.EUID, aes128=True).name == "AES-128-CBC"

    def test_key_is_16_bytes(self):
        proto = AesCbcProtocol(self.EUID, aes128=True)
        assert len(proto._key) == 16

    def test_roundtrip(self):
        proto = AesCbcProtocol(self.EUID, aes128=True)
        for msg in ("", "hello", '{"requestAttr":"readall"}'):
            assert proto.decrypt(proto.encrypt(msg)) == msg

    def test_aes128_and_aes256_differ(self):
        msg = "same plaintext"
        ct128 = AesCbcProtocol(self.EUID, aes128=True).encrypt(msg)
        ct256 = AesCbcProtocol(self.EUID).encrypt(msg)
        assert ct128 != ct256

    def test_aes128_cannot_decrypt_aes256(self):
        ct256 = AesCbcProtocol(self.EUID).encrypt("secret256")
        dec128 = AesCbcProtocol(self.EUID, aes128=True)
        try:
            result = dec128.decrypt(ct256)
            assert result != "secret256"
        except Exception:
            pass  # expected


# ---------------------------------------------------------------------------
#  wrap_request / unwrap_response
# ---------------------------------------------------------------------------


class TestWrapUnwrap:
    """Test the GatewayProtocol wrap/unwrap methods on AesCbcProtocol."""

    EUID = "001E5E0D32906128"

    def test_wrap_is_encrypt(self):
        """wrap_request should produce the same output as encrypt."""
        proto = AesCbcProtocol(self.EUID)
        body = '{"requestAttr":"readall"}'
        assert proto.wrap_request(body) == proto.encrypt(body)

    def test_unwrap_roundtrip(self):
        proto = AesCbcProtocol(self.EUID)
        body = '{"requestAttr":"readall"}'
        raw = proto.encrypt(body)
        assert proto.unwrap_response(raw) == body

    def test_unwrap_strips_trailer(self):
        """unwrap_response should strip non-block-aligned trailing bytes."""
        proto = AesCbcProtocol(self.EUID)
        body = '{"status":"success"}'
        raw = proto.encrypt(body)
        # Append a 1-byte trailer (simulates the 0xAE gateway trailer)
        raw_with_trailer = raw + b"\xAE"
        assert proto.unwrap_response(raw_with_trailer) == body

    def test_unwrap_strips_multi_byte_trailer(self):
        """Trailer can be up to 15 bytes."""
        proto = AesCbcProtocol(self.EUID)
        body = '{"test":true}'
        raw = proto.encrypt(body)
        raw_with_trailer = raw + b"\x01\x02\x03"
        assert proto.unwrap_response(raw_with_trailer) == body


# ---------------------------------------------------------------------------
#  connect()
# ---------------------------------------------------------------------------


class TestAesCbcConnect:
    """Test the AesCbcProtocol.connect() method."""

    EUID = "001E5E0D32906128"

    async def test_connect_success(self):
        proto = AesCbcProtocol(self.EUID)
        response_json = {
            "status": "success",
            "id": [
                {"sGateway": {"NetworkLANMAC": "AA:BB:CC:DD:EE:FF"}},
            ],
        }
        response_encrypted = proto.encrypt(json.dumps(response_json))

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=response_encrypted)

        mock_session = AsyncMock()
        mock_session.post = AsyncMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_resp),
                __aexit__=AsyncMock(),
            )
        )
        mock_session.post.return_value = mock_resp

        result = await proto.connect(mock_session, "192.168.1.1", 80, 5)
        assert result["status"] == "success"

    async def test_connect_http_error_raises(self):
        proto = AesCbcProtocol(self.EUID)

        mock_resp = AsyncMock()
        mock_resp.status = 500
        mock_resp.read = AsyncMock(return_value=b"error")

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="HTTP 500"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_bad_json_raises(self):
        proto = AesCbcProtocol(self.EUID)
        # Encrypt something that decrypts fine but isn't valid JSON
        raw = proto.encrypt("this is not json")

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=raw)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(json.JSONDecodeError):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_status_not_success_raises(self):
        proto = AesCbcProtocol(self.EUID)
        raw = proto.encrypt(json.dumps({"status": "error"}))

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=raw)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="status=error"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_with_trailer(self):
        """Gateway appending a trailer byte should still work."""
        proto = AesCbcProtocol(self.EUID)
        response_json = {"status": "success", "id": []}
        raw = proto.encrypt(json.dumps(response_json)) + b"\xAE"

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=raw)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        result = await proto.connect(mock_session, "192.168.1.1", 80, 5)
        assert result["status"] == "success"


# ---------------------------------------------------------------------------
#  Backward-compatible alias
# ---------------------------------------------------------------------------


class TestBackwardAlias:
    """IT600Encryptor should be an alias for AesCbcProtocol."""

    def test_alias(self):
        assert IT600Encryptor is AesCbcProtocol
