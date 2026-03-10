"""Tests for the new-firmware AES-CBC protocol (protocol_new_aes_cbc.py).

Both AES-128 (raw 16-byte key) and AES-256 (zero-padded to 32 bytes)
variants are exercised via parametrised fixtures.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.salus.protocol_new_aes_cbc import (
    _IV_LENGTH,
    _KEY_256,
    _KEY_RAW,
    NewAesCbcProtocol,
)


def _mock_response(status: int = 200, body: bytes = b"") -> MagicMock:
    """Create a mock HTTP response with headers as a plain dict."""
    resp = MagicMock()
    resp.status = status
    resp.read = AsyncMock(return_value=body)
    resp.headers = {"Content-Type": "application/octet-stream"}
    return resp


@pytest.fixture(params=[False, True], ids=["AES-128", "AES-256"])
def proto(request):
    """Yield a NewAesCbcProtocol instance for each key size."""
    return NewAesCbcProtocol(aes256=request.param)


# ---------------------------------------------------------------------------
#  Encrypt / Decrypt
# ---------------------------------------------------------------------------


class TestNewAesCbcEncryptDecrypt:
    """Test AES-CBC encrypt/decrypt with random IV for both key sizes."""

    def test_name_aes128(self):
        assert NewAesCbcProtocol(aes256=False).name == "NewAES-128-CBC"

    def test_name_aes256(self):
        assert NewAesCbcProtocol(aes256=True).name == "NewAES-256-CBC"

    def test_key_raw_is_16_bytes(self):
        assert len(_KEY_RAW) == 16

    def test_key_256_is_32_bytes(self):
        assert len(_KEY_256) == 32

    def test_key_256_starts_with_raw(self):
        assert _KEY_256[:16] == _KEY_RAW

    def test_key_256_padded_with_zeros(self):
        assert _KEY_256[16:] == bytes(16)

    def test_encrypt_returns_bytes(self, proto):
        assert isinstance(proto.encrypt("hello"), bytes)

    def test_encrypt_prepends_iv(self, proto):
        """Ciphertext should be at least IV_LENGTH + 1 block long."""
        ct = proto.encrypt("hello")
        assert len(ct) >= _IV_LENGTH + 16  # at least 1 AES block

    def test_decrypt_returns_string(self, proto):
        ct = proto.encrypt("hello")
        assert isinstance(proto.decrypt(ct), str)

    def test_roundtrip_short_messages(self, proto):
        for msg in ("", "a", "hello world", '{"key": "value"}'):
            assert proto.decrypt(proto.encrypt(msg)) == msg

    def test_roundtrip_json_payload(self, proto):
        payload = '{"requestAttr":"readall","id":[{"data":{"UniID":"abc"}}]}'
        assert proto.decrypt(proto.encrypt(payload)) == payload

    def test_roundtrip_long_message(self, proto):
        msg = "x" * 1024
        assert proto.decrypt(proto.encrypt(msg)) == msg

    def test_ciphertext_is_block_aligned_plus_iv(self, proto):
        for length in (0, 1, 15, 16, 17, 31, 32, 33):
            ct = proto.encrypt("a" * length)
            ciphertext_part = ct[_IV_LENGTH:]
            assert len(ciphertext_part) % 16 == 0

    def test_each_encrypt_produces_different_ciphertext(self, proto):
        """Random IV means encrypting the same plaintext gives different output."""
        msg = "same message"
        ct1 = proto.encrypt(msg)
        ct2 = proto.encrypt(msg)
        assert ct1 != ct2  # different random IVs

    def test_each_encrypt_produces_different_iv(self, proto):
        """The first 16 bytes (IV) should differ between calls."""
        msg = "same message"
        iv1 = proto.encrypt(msg)[:_IV_LENGTH]
        iv2 = proto.encrypt(msg)[:_IV_LENGTH]
        assert iv1 != iv2

    def test_cross_instance_roundtrip_aes128(self):
        ct = NewAesCbcProtocol(aes256=False).encrypt("cross-instance")
        pt = NewAesCbcProtocol(aes256=False).decrypt(ct)
        assert pt == "cross-instance"

    def test_cross_instance_roundtrip_aes256(self):
        ct = NewAesCbcProtocol(aes256=True).encrypt("cross-instance")
        pt = NewAesCbcProtocol(aes256=True).decrypt(ct)
        assert pt == "cross-instance"

    def test_aes128_cannot_decrypt_aes256(self):
        """AES-128 and AES-256 are not interchangeable."""
        ct = NewAesCbcProtocol(aes256=True).encrypt("mismatch")
        with pytest.raises(ValueError):
            NewAesCbcProtocol(aes256=False).decrypt(ct)

    def test_aes256_cannot_decrypt_aes128(self):
        """AES-256 and AES-128 are not interchangeable."""
        ct = NewAesCbcProtocol(aes256=False).encrypt("mismatch")
        with pytest.raises(ValueError):
            NewAesCbcProtocol(aes256=True).decrypt(ct)

    def test_decrypt_too_short_raises(self, proto):
        with pytest.raises(ValueError, match="too short"):
            proto.decrypt(b"\x00" * _IV_LENGTH)

    def test_decrypt_empty_raises(self, proto):
        with pytest.raises(ValueError, match="too short"):
            proto.decrypt(b"")

    def test_decrypt_corrupted_ciphertext_raises(self, proto):
        ct = proto.encrypt("hello")
        corrupted = ct[:_IV_LENGTH] + bytes(len(ct) - _IV_LENGTH)
        with pytest.raises(ValueError):
            proto.decrypt(corrupted)


# ---------------------------------------------------------------------------
#  wrap_request / unwrap_response
# ---------------------------------------------------------------------------


class TestWrapUnwrap:
    """Test the GatewayProtocol wrap/unwrap methods."""

    def test_wrap_is_encrypt(self, proto):
        """wrap_request should call encrypt internally (same format)."""
        body = '{"requestAttr":"readall"}'
        wrapped = proto.wrap_request(body)
        assert len(wrapped) >= _IV_LENGTH + 16

    def test_unwrap_roundtrip(self, proto):
        body = '{"requestAttr":"readall"}'
        raw = proto.encrypt(body)
        assert proto.unwrap_response(raw) == body


# ---------------------------------------------------------------------------
#  connect()
# ---------------------------------------------------------------------------


class TestNewAesCbcConnect:
    """Test the NewAesCbcProtocol.connect() method."""

    async def test_connect_success(self, proto):
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

    async def test_connect_http_error_raises(self, proto):
        mock_resp = _mock_response(500, b"error")

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="HTTP 500"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_status_not_success_raises(self, proto):
        raw = proto.encrypt(json.dumps({"status": "error"}))

        mock_resp = _mock_response(200, raw)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="status=error"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_reject_frame_raises(self, proto):
        """33-byte 0xAE response should raise."""
        reject = bytes(32) + b"\xAE"

        mock_resp = _mock_response(200, reject)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="reject"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_new_protocol_frame_raises(self, proto):
        """33-byte 0xAF response should raise."""
        new_proto_resp = bytes(32) + b"\xAF"

        mock_resp = _mock_response(200, new_proto_resp)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="frame"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    async def test_connect_bad_json_raises(self, proto):
        raw = proto.encrypt("this is not json")

        mock_resp = _mock_response(200, raw)

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="not valid JSON"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

    def test_aes128_uses_raw_key(self):
        p = NewAesCbcProtocol(aes256=False)
        assert p._key == _KEY_RAW

    def test_aes256_uses_padded_key(self):
        p = NewAesCbcProtocol(aes256=True)
        assert p._key == _KEY_256
