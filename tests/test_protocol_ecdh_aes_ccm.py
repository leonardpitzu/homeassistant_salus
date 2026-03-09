"""Tests for the ECDH + AES-CCM protocol (protocol_ecdh_aes_ccm.py)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)

from custom_components.salus.protocol_ecdh_aes_ccm import EcdhAesCcmProtocol

# ---------------------------------------------------------------------------
#  Reject-frame detection
# ---------------------------------------------------------------------------


class TestIsRejectFrame:
    """Test the static reject-frame detection helper."""

    def test_valid_reject_frame(self):
        """33 bytes with 0xAE trailer → reject."""
        raw = bytes(32) + b"\xAE"
        assert EcdhAesCcmProtocol.is_reject_frame(raw) is True

    def test_wrong_length(self):
        """32 bytes → not a reject frame."""
        assert EcdhAesCcmProtocol.is_reject_frame(bytes(32)) is False

    def test_wrong_trailer(self):
        """33 bytes with wrong trailer → not a reject frame."""
        raw = bytes(32) + b"\xFF"
        assert EcdhAesCcmProtocol.is_reject_frame(raw) is False

    def test_empty(self):
        assert EcdhAesCcmProtocol.is_reject_frame(b"") is False

    def test_real_world_reject(self):
        """Simulated real-world 33-byte reject from debug logs."""
        raw = bytes.fromhex(
            "ec11595594bacdfbc9a45804b6e123bc"
            "8ed3bdaf14409cfef2afd59c47086bdf"
            "ae"
        )
        assert EcdhAesCcmProtocol.is_reject_frame(raw) is True


# ---------------------------------------------------------------------------
#  Trailer stripping
# ---------------------------------------------------------------------------


class TestStripTrailer:
    """Test the block-alignment trailer stripping."""

    def test_block_aligned_no_trailer(self):
        """Exactly 32 bytes → no trailer."""
        data = bytes(32)
        core, trailer = EcdhAesCcmProtocol.strip_trailer(data)
        assert core == data
        assert trailer == b""

    def test_33_bytes(self):
        """33 bytes → 32-byte core + 1-byte trailer."""
        data = bytes(32) + b"\xAE"
        core, trailer = EcdhAesCcmProtocol.strip_trailer(data)
        assert len(core) == 32
        assert trailer == b"\xAE"

    def test_130_bytes(self):
        """130 bytes → 128-byte core + 2-byte trailer (130 % 16 == 2)."""
        data = bytes(130)
        core, trailer = EcdhAesCcmProtocol.strip_trailer(data)
        assert len(core) == 128
        assert len(trailer) == 2

    def test_3075_bytes(self):
        """3075 bytes → 3072-byte core + 3-byte trailer (3075 % 16 == 3)."""
        data = bytes(3075)
        core, trailer = EcdhAesCcmProtocol.strip_trailer(data)
        assert len(core) == 3072
        assert len(trailer) == 3

    def test_12836_bytes(self):
        """12836 bytes → 12832-byte core + 4-byte trailer (12836 % 16 == 4)."""
        data = bytes(12836)
        core, trailer = EcdhAesCcmProtocol.strip_trailer(data)
        assert len(core) == 12832
        assert len(trailer) == 4

    def test_empty(self):
        core, trailer = EcdhAesCcmProtocol.strip_trailer(b"")
        assert core == b""
        assert trailer == b""


# ---------------------------------------------------------------------------
#  ECDH key pair generation
# ---------------------------------------------------------------------------


class TestKeyPairGeneration:
    """Test ephemeral key pair generation."""

    def test_generate_keypair(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        key = proto._generate_keypair()
        assert key is not None
        assert proto._private_key is key

    def test_public_key_bytes(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        proto._generate_keypair()
        pub_bytes = proto.get_public_key_bytes()
        # Uncompressed P-256 public key: 1 + 32 + 32 = 65 bytes
        assert len(pub_bytes) == 65
        assert pub_bytes[0] == 0x04  # uncompressed point prefix

    def test_public_key_raises_before_generation(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError, match="not generated"):
            proto.get_public_key_bytes()


# ---------------------------------------------------------------------------
#  Session key derivation
# ---------------------------------------------------------------------------


class TestSessionKeyDerivation:
    """Test ECDH shared-secret → session key derivation."""

    def test_derive_session_key(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        proto._generate_keypair()

        # Simulate a gateway key pair
        peer_private = generate_private_key(SECP256R1())
        peer_public = peer_private.public_key()

        session_key = proto.derive_session_key(peer_public)
        assert len(session_key) == 16
        assert proto._session_key == session_key

    def test_different_peers_produce_different_keys(self):
        proto1 = EcdhAesCcmProtocol("001E5E0D32906128")
        proto1._generate_keypair()
        proto2 = EcdhAesCcmProtocol("001E5E0D32906128")
        proto2._generate_keypair()

        peer = generate_private_key(SECP256R1()).public_key()
        k1 = proto1.derive_session_key(peer)
        k2 = proto2.derive_session_key(peer)
        # Different ephemeral keys → different session keys
        assert k1 != k2

    def test_derive_raises_before_generation(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        peer = generate_private_key(SECP256R1()).public_key()
        with pytest.raises(RuntimeError, match="not generated"):
            proto.derive_session_key(peer)


# ---------------------------------------------------------------------------
#  AES-CCM encrypt / decrypt (with manually set session key)
# ---------------------------------------------------------------------------


class TestAesCcmEncryptDecrypt:
    """Test AES-CCM encrypt/decrypt once a session key is established."""

    @staticmethod
    def _proto_with_key() -> EcdhAesCcmProtocol:
        """Create a protocol with a known session key for testing."""
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        proto._session_key = b"\x01" * 16
        return proto

    def test_encrypt_returns_bytes(self):
        proto = self._proto_with_key()
        ct = proto.encrypt("hello")
        assert isinstance(ct, bytes)
        assert len(ct) > len(b"hello")

    def test_roundtrip(self):
        proto = self._proto_with_key()
        for msg in ("", "hello", '{"requestAttr":"readall"}', "x" * 1024):
            ct = proto.encrypt(msg)
            assert proto.decrypt(ct) == msg

    def test_tampered_ciphertext_fails(self):
        proto = self._proto_with_key()
        ct = proto.encrypt("secret")
        tampered = ct[:-1] + bytes([(ct[-1] ^ 0xFF)])
        with pytest.raises(InvalidTag):
            proto.decrypt(tampered)

    def test_encrypt_raises_without_session(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError, match="Session not established"):
            proto.encrypt("hello")

    def test_decrypt_raises_without_session(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError, match="Session not established"):
            proto.decrypt(b"\x00" * 30)

    def test_different_keys_cannot_cross_decrypt(self):
        proto1 = EcdhAesCcmProtocol("001E5E0D32906128")
        proto1._session_key = b"\x01" * 16
        proto2 = EcdhAesCcmProtocol("001E5E0D32906128")
        proto2._session_key = b"\x02" * 16

        ct = proto1.encrypt("secret")
        with pytest.raises(InvalidTag):
            proto2.decrypt(ct)


# ---------------------------------------------------------------------------
#  wrap_request / unwrap_response
# ---------------------------------------------------------------------------


class TestWrapUnwrap:
    """Test wrap_request and unwrap_response with a session key."""

    @staticmethod
    def _proto_with_key() -> EcdhAesCcmProtocol:
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        proto._session_key = b"\xAB" * 16
        return proto

    def test_wrap_includes_trailer(self):
        proto = self._proto_with_key()
        wrapped = proto.wrap_request('{"requestAttr":"readall"}')
        # Should be longer than just the encrypted core
        encrypted_only = proto.encrypt('{"requestAttr":"readall"}')
        assert len(wrapped) == len(encrypted_only) + 4  # 4-byte trailer

    def test_sequence_increments(self):
        proto = self._proto_with_key()
        w1 = proto.wrap_request("body1")
        w2 = proto.wrap_request("body2")
        # Last 4 bytes are the trailer; first byte is the sequence
        assert w1[-4] == 0
        assert w2[-4] == 1

    def test_trailer_format(self):
        proto = self._proto_with_key()
        wrapped = proto.wrap_request("test")
        trailer = wrapped[-4:]
        assert trailer[1] == 0xFD  # marker byte

    def test_wrap_raises_without_session(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError):
            proto.wrap_request("test")


# ---------------------------------------------------------------------------
#  connect() — not yet implemented
# ---------------------------------------------------------------------------


class TestConnect:
    """Test that connect() runs probes and signals not-implemented."""

    @staticmethod
    def _mock_session():
        """Return a mock session whose .post() returns a plausible response."""
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.read = AsyncMock(return_value=bytes(33))
        mock_resp.headers = {"Server": "GoAhead", "Content-Type": "application/octet-stream"}

        mock_session = AsyncMock()
        mock_session.post = AsyncMock(return_value=mock_resp)
        mock_session.get = AsyncMock(return_value=mock_resp)
        return mock_session

    async def test_connect_raises_not_implemented(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        session = self._mock_session()

        with pytest.raises(NotImplementedError, match="not yet implemented"):
            await proto.connect(session, "192.168.1.1", 80, 5)

    async def test_connect_generates_keypair(self):
        """connect() should at least generate the key pair before failing."""
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        session = self._mock_session()

        with pytest.raises(NotImplementedError):
            await proto.connect(session, "192.168.1.1", 80, 5)

        assert proto._private_key is not None

    async def test_connect_sends_probes(self):
        """connect() should POST diagnostic probes before raising."""
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        session = self._mock_session()

        with pytest.raises(NotImplementedError):
            await proto.connect(session, "192.168.1.1", 80, 5)

        # Should have sent 3 probe POSTs
        assert session.post.call_count == 3


# ---------------------------------------------------------------------------
#  Protocol interface compliance
# ---------------------------------------------------------------------------


class TestProtocolInterface:
    """Verify EcdhAesCcmProtocol implements GatewayProtocol."""

    def test_has_name(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        assert proto.name == "ECDH+AES-CCM"

    def test_has_all_abstract_methods(self):
        required = {"encrypt", "decrypt", "connect", "wrap_request", "unwrap_response"}
        actual = set(dir(EcdhAesCcmProtocol))
        assert required.issubset(actual)

    def test_is_subclass(self):
        from custom_components.salus.protocol import GatewayProtocol

        assert issubclass(EcdhAesCcmProtocol, GatewayProtocol)
