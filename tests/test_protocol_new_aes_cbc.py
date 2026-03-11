"""Tests for the new-firmware AES-CBC protocol (protocol_new_aes_cbc.py).

UG800 AES-256-CBC with fixed universal key and fixed IV.
Wire format is hex-encoded ciphertext.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.salus.protocol_new_aes_cbc import NewAesCbcProtocol


def _mock_response(status: int = 200, body: bytes = b"") -> MagicMock:
    """Create a mock HTTP response with headers as a plain dict."""
    resp = MagicMock()
    resp.status = status
    resp.read = AsyncMock(return_value=body)
    resp.headers = {"Content-Type": "application/json"}
    return resp


@pytest.fixture()
def proto():
    """Yield a NewAesCbcProtocol instance."""
    return NewAesCbcProtocol()


class TestNewAesCbcEncryptDecrypt:
    """Test AES-CBC encrypt/decrypt with fixed universal key."""

    def test_name(self, proto):
        assert "NewAES-CBC" in proto.name and "UG800" in proto.name

    def test_encrypt_returns_hex_string(self, proto):
        result = proto.encrypt("hello")
        assert isinstance(result, str)
        # Verify it's valid hex
        bytes.fromhex(result)

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

    def test_encrypt_deterministic(self, proto):
        """Fixed key + fixed IV → deterministic encryption."""
        msg = "same message"
        ct1 = proto.encrypt(msg)
        ct2 = proto.encrypt(msg)
        assert ct1 == ct2

    def test_cross_instance_roundtrip(self):
        """All instances share the same key/IV → interoperable."""
        ct = NewAesCbcProtocol().encrypt("cross-instance")
        pt = NewAesCbcProtocol().decrypt(ct)
        assert pt == "cross-instance"

    def test_decrypt_invalid_hex_raises(self, proto):
        with pytest.raises(ValueError, match="not valid hex"):
            proto.decrypt("not_hex_at_all!")


class TestWrapUnwrap:
    """Test the GatewayProtocol wrap/unwrap methods."""

    def test_wrap_roundtrip(self, proto):
        body = '{"requestAttr":"readall"}'
        wrapped = proto.wrap_request(body)
        # wrap returns a hex string; unwrap expects bytes (HTTP response body)
        assert proto.unwrap_response(wrapped.encode()) == body


class TestNewAesCbcConnect:
    """Test the NewAesCbcProtocol.connect() method."""

    async def test_connect_success(self, proto):
        response_json = {
            "status": "success",
            "id": [
                {"sGateway": {"NetworkLANMAC": "AA:BB:CC:DD:EE:FF"}},
            ],
        }
        # Gateway responds with hex-encoded encrypted JSON
        response_hex = proto.encrypt(json.dumps(response_json))
        mock_resp = _mock_response(200, response_hex.encode())

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
        mock_resp = _mock_response(200, raw.encode())

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

        with pytest.raises(ValueError, match="(?i)reject"):
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
        mock_resp = _mock_response(200, raw.encode())

        mock_session = AsyncMock()
        mock_session.post.return_value = mock_resp

        with pytest.raises(ValueError, match="not valid JSON"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)
