"""Tests for the Security1 protocol (protocol_ecdh_aes_ccm.py).

Covers:
  - Protobuf encode/decode helpers
  - X25519 key pair generation
  - PoP-based session key derivation
  - AES-256-CTR encrypt / decrypt
  - wrap_request / unwrap_response
  - Protocol message builders and parsers (SessionCmd0/Resp0/Cmd1/Resp1)
  - Reject-frame detection, trailer stripping
  - connect() handshake flow (mocked)
  - Protocol interface compliance
"""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from custom_components.salus.protocol_ecdh_aes_ccm import (
    PUBLIC_KEY_LEN,
    SZ_RANDOM,
    EcdhAesCcmProtocol,
    _build_pop_candidates,
    _decode_protobuf,
    _encode_field_bytes,
    _encode_field_varint,
    _encode_varint,
    _get_bytes_field,
    _get_varint_field,
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    build_session_cmd0,
    build_session_cmd1,
    derive_session_key,
    parse_session_resp0,
    parse_session_resp1,
)

# ---------------------------------------------------------------------------
#  Protobuf encode / decode primitives
# ---------------------------------------------------------------------------


class TestProtobufEncoding:
    """Test the minimal protobuf wire format encoder/decoder."""

    def test_encode_varint_single_byte(self):
        assert _encode_varint(0) == b"\x00"
        assert _encode_varint(1) == b"\x01"
        assert _encode_varint(127) == b"\x7f"

    def test_encode_varint_multi_byte(self):
        assert _encode_varint(128) == b"\x80\x01"
        assert _encode_varint(300) == b"\xac\x02"

    def test_encode_field_varint(self):
        # field 1, wire type 0, value 0
        result = _encode_field_varint(1, 0)
        assert result == b"\x08\x00"

    def test_encode_field_bytes(self):
        result = _encode_field_bytes(1, b"abc")
        assert result == b"\x0a\x03abc"

    def test_decode_roundtrip(self):
        """Encode then decode should recover the same fields."""
        data = (
            _encode_field_varint(1, 42)
            + _encode_field_bytes(2, b"hello")
        )
        fields = _decode_protobuf(data)
        assert _get_varint_field(fields, 1) == 42
        assert _get_bytes_field(fields, 2) == b"hello"

    def test_decode_empty(self):
        assert _decode_protobuf(b"") == {}

    def test_get_missing_field_returns_none(self):
        fields = _decode_protobuf(b"")
        assert _get_varint_field(fields, 99) is None
        assert _get_bytes_field(fields, 99) is None


# ---------------------------------------------------------------------------
#  Session message builders and parsers
# ---------------------------------------------------------------------------


class TestSessionMessages:
    """Test protobuf message builders and parsers for Security1."""

    def test_build_parse_session_cmd0_resp0_roundtrip(self):
        """Build a SessionCmd0, simulate gateway response, parse it."""
        client_pk = b"\x01" * PUBLIC_KEY_LEN

        # Build SessionCmd0
        cmd0 = build_session_cmd0(client_pk)
        assert len(cmd0) > 0

        # Decode to verify structure
        fields = _decode_protobuf(cmd0)
        assert _get_varint_field(fields, 2) == 1  # sec_ver

        # Build a mock SessionResp0 (device side)
        device_pk = b"\x02" * PUBLIC_KEY_LEN
        device_rand = b"\x03" * SZ_RANDOM
        resp0 = self._build_mock_resp0(0, device_pk, device_rand)

        status, pk, rand = parse_session_resp0(resp0)
        assert status == 0
        assert pk == device_pk
        assert rand == device_rand

    def test_build_parse_session_cmd1_resp1_roundtrip(self):
        """Build a SessionCmd1, simulate gateway response, parse it."""
        verify = b"\x04" * PUBLIC_KEY_LEN

        cmd1 = build_session_cmd1(verify)
        assert len(cmd1) > 0

        # Build a mock SessionResp1
        device_verify = b"\x05" * PUBLIC_KEY_LEN
        resp1 = self._build_mock_resp1(0, device_verify)

        status, dv = parse_session_resp1(resp1)
        assert status == 0
        assert dv == device_verify

    def test_parse_resp0_bad_sec_ver(self):
        """sec_ver != 1 should raise."""
        resp0 = (
            _encode_field_varint(2, 99)  # wrong sec_ver
            + _encode_field_bytes(11, _encode_field_varint(1, 1) + _encode_field_bytes(21, b""))
        )
        with pytest.raises(ValueError, match="sec_ver=99"):
            parse_session_resp0(resp0)

    def test_parse_resp0_missing_sec1(self):
        resp0 = _encode_field_varint(2, 1)  # sec_ver only, no sec1
        with pytest.raises(ValueError, match="Missing sec1"):
            parse_session_resp0(resp0)

    def test_parse_resp0_wrong_msg_type(self):
        # msg_type = 0 (Command0) instead of 1 (Response0)
        sr0 = (
            _encode_field_varint(1, 0)  # status
            + _encode_field_bytes(2, b"\x00" * 32)
            + _encode_field_bytes(3, b"\x00" * 16)
        )
        sec1 = (
            _encode_field_varint(1, 0)  # msg_type = Command0
            + _encode_field_bytes(21, sr0)
        )
        resp0 = _encode_field_varint(2, 1) + _encode_field_bytes(11, sec1)
        with pytest.raises(ValueError, match="Expected Session_Response0"):
            parse_session_resp0(resp0)

    def test_parse_resp1_non_zero_status(self):
        """Non-zero status should still parse (caller checks)."""
        resp1 = self._build_mock_resp1(3, b"\x00" * 32)
        status, _ = parse_session_resp1(resp1)
        assert status == 3

    @staticmethod
    def _build_mock_resp0(status: int, pk: bytes, rand: bytes) -> bytes:
        """Build a well-formed SessionResp0 protobuf."""
        sr0 = (
            _encode_field_varint(1, status)
            + _encode_field_bytes(2, pk)
            + _encode_field_bytes(3, rand)
        )
        sec1 = (
            _encode_field_varint(1, 1)  # Session_Response0
            + _encode_field_bytes(21, sr0)
        )
        return _encode_field_varint(2, 1) + _encode_field_bytes(11, sec1)

    @staticmethod
    def _build_mock_resp1(status: int, verify_data: bytes) -> bytes:
        """Build a well-formed SessionResp1 protobuf."""
        sr1 = (
            _encode_field_varint(1, status)
            + _encode_field_bytes(3, verify_data)
        )
        sec1 = (
            _encode_field_varint(1, 3)  # Session_Response1
            + _encode_field_bytes(23, sr1)
        )
        return _encode_field_varint(2, 1) + _encode_field_bytes(11, sec1)


# ---------------------------------------------------------------------------
#  X25519 key pair generation
# ---------------------------------------------------------------------------


class TestKeyPairGeneration:
    """Test ephemeral X25519 key pair generation."""

    def test_generate_keypair(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        key = proto._generate_keypair()
        assert key is not None
        assert proto._private_key is key

    def test_public_key_bytes(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        proto._generate_keypair()
        pub_bytes = proto.get_public_key_bytes()
        # X25519 public key: exactly 32 bytes
        assert len(pub_bytes) == PUBLIC_KEY_LEN

    def test_public_key_raises_before_generation(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError, match="not generated"):
            proto.get_public_key_bytes()


# ---------------------------------------------------------------------------
#  Session key derivation
# ---------------------------------------------------------------------------


class TestSessionKeyDerivation:
    """Test X25519 shared-secret → session key derivation."""

    def test_derive_session_key_no_pop(self):
        """Without PoP, session key = raw ECDH shared secret."""
        client = X25519PrivateKey.generate()
        device = X25519PrivateKey.generate()
        device_pub = device.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        key = derive_session_key(client, device_pub, pop=None)
        assert len(key) == PUBLIC_KEY_LEN

        # Verify it matches the raw ECDH
        expected = client.exchange(X25519PublicKey.from_public_bytes(device_pub))
        assert key == expected

    def test_derive_session_key_with_pop(self):
        """With PoP, session key = raw ECDH ^ SHA-256(pop)."""
        client = X25519PrivateKey.generate()
        device = X25519PrivateKey.generate()
        device_pub = device.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        key_with_pop = derive_session_key(client, device_pub, pop="test123")
        key_no_pop = derive_session_key(client, device_pub, pop=None)

        assert key_with_pop != key_no_pop  # XOR changes the key
        assert len(key_with_pop) == PUBLIC_KEY_LEN

        # Manually verify XOR
        pop_hash = hashlib.sha256(b"test123").digest()
        expected = bytes(a ^ b for a, b in zip(key_no_pop, pop_hash, strict=True))
        assert key_with_pop == expected

    def test_derive_session_key_empty_pop(self):
        """Empty string pop → same as no pop (empty bytes don't XOR)."""
        client = X25519PrivateKey.generate()
        device = X25519PrivateKey.generate()
        device_pub = device.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        key_none = derive_session_key(client, device_pub, pop=None)
        key_empty = derive_session_key(client, device_pub, pop="")
        assert key_none == key_empty

    def test_derive_via_protocol_method(self):
        """Test the instance method wrapper."""
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        proto._generate_keypair()
        device = X25519PrivateKey.generate()
        device_pub = device.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        key = proto.derive_session_key(device_pub, pop=None)
        assert len(key) == PUBLIC_KEY_LEN
        assert proto._session_key == key

    def test_derive_raises_before_generation(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError, match="not generated"):
            proto.derive_session_key(b"\x00" * 32)


# ---------------------------------------------------------------------------
#  AES-256-CTR encrypt / decrypt
# ---------------------------------------------------------------------------


class TestAesCtrEncryptDecrypt:
    """Test AES-256-CTR with session key and device random."""

    def test_roundtrip(self):
        key = b"\x01" * 32
        iv = b"\x02" * 16
        for msg in (b"", b"hello", b"x" * 1024):
            ct = aes_ctr_encrypt(key, iv, msg)
            assert aes_ctr_decrypt(key, iv, ct) == msg

    def test_different_keys_fail(self):
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        iv = b"\x03" * 16
        ct = aes_ctr_encrypt(key1, iv, b"secret")
        result = aes_ctr_decrypt(key2, iv, ct)
        assert result != b"secret"

    def test_protocol_encrypt_decrypt(self):
        """Test encrypt/decrypt through the protocol instance."""
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        proto._session_key = b"\x01" * 32
        proto._device_random = b"\x02" * 16

        for msg in ("", "hello", '{"requestAttr":"readall"}', "x" * 1024):
            ct = proto.encrypt(msg)
            assert proto.decrypt(ct) == msg

    def test_encrypt_raises_without_session(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError, match="Session not established"):
            proto.encrypt("hello")

    def test_decrypt_raises_without_session(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError, match="Session not established"):
            proto.decrypt(b"\x00" * 30)


# ---------------------------------------------------------------------------
#  wrap_request / unwrap_response
# ---------------------------------------------------------------------------


class TestWrapUnwrap:
    """Test wrap_request and unwrap_response with a session key."""

    @staticmethod
    def _proto_with_key() -> EcdhAesCcmProtocol:
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        proto._session_key = b"\xAB" * 32
        proto._device_random = b"\xCD" * 16
        return proto

    def test_wrap_roundtrip(self):
        proto = self._proto_with_key()
        body = '{"requestAttr":"readall"}'
        wrapped = proto.wrap_request(body)
        unwrapped = proto.unwrap_response(wrapped)
        assert unwrapped == body

    def test_wrap_raises_without_session(self):
        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(RuntimeError):
            proto.wrap_request("test")


# ---------------------------------------------------------------------------
#  PoP candidates
# ---------------------------------------------------------------------------


class TestPopCandidates:
    """Test PoP candidate list generation."""

    def test_includes_none(self):
        pops = _build_pop_candidates("001E5E0D32906128")
        assert None in pops

    def test_includes_euid(self):
        pops = _build_pop_candidates("001E5E0D32906128")
        assert "001E5E0D32906128" in pops

    def test_includes_salus_euid(self):
        pops = _build_pop_candidates("001E5E0D32906128")
        assert "Salus-001E5E0D32906128" in pops

    def test_includes_md5(self):
        pops = _build_pop_candidates("001E5E0D32906128")
        expected_md5 = hashlib.md5(b"001E5E0D32906128").hexdigest()  # noqa: S324
        assert expected_md5 in pops

    def test_order_none_first(self):
        pops = _build_pop_candidates("001E5E0D32906128")
        assert pops[0] is None

    def test_static_candidates_present(self):
        pops = _build_pop_candidates("001E5E0D32906128")
        for expected in ("abcd1234", "Salus", "salus", "iT600"):
            assert expected in pops


# ---------------------------------------------------------------------------
#  Reject-frame detection
# ---------------------------------------------------------------------------


class TestIsRejectFrame:
    """Test the static reject-frame detection helper."""

    def test_valid_reject_frame(self):
        raw = bytes(32) + b"\xAE"
        assert EcdhAesCcmProtocol.is_reject_frame(raw) is True

    def test_wrong_length(self):
        assert EcdhAesCcmProtocol.is_reject_frame(bytes(32)) is False

    def test_wrong_trailer(self):
        raw = bytes(32) + b"\xFF"
        assert EcdhAesCcmProtocol.is_reject_frame(raw) is False

    def test_new_protocol_trailer_not_reject(self):
        raw = bytes(32) + b"\xAF"
        assert EcdhAesCcmProtocol.is_reject_frame(raw) is False

    def test_empty(self):
        assert EcdhAesCcmProtocol.is_reject_frame(b"") is False


# ---------------------------------------------------------------------------
#  Trailer stripping
# ---------------------------------------------------------------------------


class TestStripTrailer:
    """Test the block-alignment trailer stripping."""

    def test_block_aligned_no_trailer(self):
        data = bytes(32)
        core, trailer = EcdhAesCcmProtocol.strip_trailer(data)
        assert core == data
        assert trailer == b""

    def test_33_bytes(self):
        data = bytes(32) + b"\xAE"
        core, trailer = EcdhAesCcmProtocol.strip_trailer(data)
        assert len(core) == 32
        assert trailer == b"\xAE"

    def test_130_bytes(self):
        data = bytes(130)
        core, trailer = EcdhAesCcmProtocol.strip_trailer(data)
        assert len(core) == 128
        assert len(trailer) == 2

    def test_empty(self):
        core, trailer = EcdhAesCcmProtocol.strip_trailer(b"")
        assert core == b""
        assert trailer == b""


# ---------------------------------------------------------------------------
#  Full handshake simulation (mocked HTTP)
# ---------------------------------------------------------------------------


class TestConnectHandshake:
    """Test the Security1 handshake with a simulated gateway."""

    @staticmethod
    def _build_mock_resp0(status: int, pk: bytes, rand: bytes) -> bytes:
        sr0 = (
            _encode_field_varint(1, status)
            + _encode_field_bytes(2, pk)
            + _encode_field_bytes(3, rand)
        )
        sec1 = (
            _encode_field_varint(1, 1)
            + _encode_field_bytes(21, sr0)
        )
        return _encode_field_varint(2, 1) + _encode_field_bytes(11, sec1)

    @staticmethod
    def _build_mock_resp1(status: int, verify_data: bytes) -> bytes:
        sr1 = (
            _encode_field_varint(1, status)
            + _encode_field_bytes(3, verify_data)
        )
        sec1 = (
            _encode_field_varint(1, 3)
            + _encode_field_bytes(23, sr1)
        )
        return _encode_field_varint(2, 1) + _encode_field_bytes(11, sec1)

    async def test_successful_handshake_no_pop(self):
        """Simulate a full Security1 handshake without PoP."""
        device_key = X25519PrivateKey.generate()
        device_pub = device_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        device_random = b"\x42" * SZ_RANDOM

        # We need to intercept the client's pubkey from cmd0 to compute
        # the shared secret.  Use a side_effect that captures the body.
        captured_cmd0_body: list[bytes] = []
        captured_cmd1_body: list[bytes] = []
        call_count = [0]

        async def mock_post(url, data=None, headers=None):
            call_count[0] += 1
            resp = AsyncMock()
            resp.status = 200
            resp.headers = {"Content-Type": "application/x-protocomm"}

            if call_count[0] == 1:
                # SessionCmd0 → parse client pubkey, build SessionResp0
                captured_cmd0_body.append(data)

                # Extract client pubkey from protobuf
                fields = _decode_protobuf(data)
                sec1_raw = _get_bytes_field(fields, 11)
                sec1_fields = _decode_protobuf(sec1_raw)
                sc0_raw = _get_bytes_field(sec1_fields, 20)
                sc0_fields = _decode_protobuf(sc0_raw)
                client_pubkey = _get_bytes_field(sc0_fields, 1)

                # Compute shared secret (no PoP)
                client_pub_obj = X25519PublicKey.from_public_bytes(client_pubkey)
                shared = device_key.exchange(client_pub_obj)

                # Encrypt client_pubkey with shared key + device_random
                device_verify = aes_ctr_encrypt(
                    shared, device_random,
                    # The device encrypts starting at offset=32 in the CTR stream
                    # (after the 32-byte device_pubkey was encrypted by the client):
                    # We concatenate 32 zero-bytes + client_pubkey and take [32:]
                    b"\x00" * PUBLIC_KEY_LEN + client_pubkey,
                )[PUBLIC_KEY_LEN:]

                # Store for resp1
                captured_cmd0_body.append(client_pubkey)
                captured_cmd0_body.append(shared)
                captured_cmd0_body.append(device_verify)

                resp0 = self._build_mock_resp0(0, device_pub, device_random)
                resp.read = AsyncMock(return_value=resp0)

            elif call_count[0] == 2:
                # SessionCmd1 → verify, build SessionResp1
                captured_cmd1_body.append(data)
                device_verify = captured_cmd0_body[3]
                resp1 = self._build_mock_resp1(0, device_verify)
                resp.read = AsyncMock(return_value=resp1)

            else:
                # Readall request → return encrypted JSON
                shared = captured_cmd0_body[2]
                readall_json = '{"status":"success","id":[]}'
                encrypted = aes_ctr_encrypt(shared, device_random, readall_json.encode())
                resp.read = AsyncMock(return_value=encrypted)

            return resp

        mock_session = AsyncMock()
        mock_session.post = mock_post

        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        result = await proto.connect(mock_session, "192.168.1.1", 80, 5)

        assert result["status"] == "success"
        assert proto._session_key is not None
        assert proto._device_random == device_random

    async def test_handshake_wrong_pop_retries(self):
        """When the gateway rejects (status != 0), the protocol tries next PoP."""
        device_key = X25519PrivateKey.generate()
        device_pub = device_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        device_random = b"\x42" * SZ_RANDOM

        cmd1_attempts = [0]

        async def mock_post(url, data=None, headers=None):
            resp = AsyncMock()
            resp.status = 200
            resp.headers = {"Content-Type": "application/x-protocomm"}

            # SessionCmd0
            if data is None or not data:
                resp.read = AsyncMock(return_value=b"")
                return resp

            fields = _decode_protobuf(data)
            sec1_raw = _get_bytes_field(fields, 11)
            if sec1_raw is None:
                # Not a protobuf session message (fallback probe / readall)
                resp.read = AsyncMock(return_value=b"")
                return resp

            sec1_fields = _decode_protobuf(sec1_raw)
            msg_type = _get_varint_field(sec1_fields, 1)

            if msg_type == 0:
                # SessionCmd0
                resp0 = self._build_mock_resp0(0, device_pub, device_random)
                resp.read = AsyncMock(return_value=resp0)
            elif msg_type == 2:
                # SessionCmd1 — always reject
                cmd1_attempts[0] += 1
                resp1 = self._build_mock_resp1(1, b"\x00" * 32)  # status=1 (error)
                resp.read = AsyncMock(return_value=resp1)
            else:
                resp.read = AsyncMock(return_value=b"")

            return resp

        mock_session = AsyncMock()
        mock_session.post = mock_post
        mock_session.get = self._mock_get_handler()

        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(NotImplementedError, match="handshake failed"):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

        # Should have tried all PoP candidates (multiplied by endpoints)
        pop_count = len(_build_pop_candidates("001E5E0D32906128"))
        assert cmd1_attempts[0] >= pop_count

    async def test_connect_generates_keypair(self):
        """connect() should generate the key pair."""
        async def mock_post(url, data=None, headers=None):
            resp = AsyncMock()
            resp.status = 404
            resp.headers = {}
            resp.read = AsyncMock(return_value=b"")
            return resp

        mock_session = AsyncMock()
        mock_session.post = mock_post
        mock_session.get = self._mock_get_handler()

        proto = EcdhAesCcmProtocol("001E5E0D32906128")
        with pytest.raises(NotImplementedError):
            await proto.connect(mock_session, "192.168.1.1", 80, 5)

        assert proto._private_key is not None

    @staticmethod
    def _mock_get_handler():
        """Return a mock GET handler for fallback probes."""
        async def mock_get(url, headers=None):
            resp = AsyncMock()
            resp.status = 404
            resp.headers = {}
            resp.read = AsyncMock(return_value=b"")
            return resp
        return mock_get


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
