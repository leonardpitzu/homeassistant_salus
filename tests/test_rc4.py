"""Tests for the RC4 cipher and frame utilities."""

from __future__ import annotations

from custom_components.salus.rc4 import (
    FRAME_CONT,
    FRAME_FINAL,
    rc4_crypt,
    split_frames,
    wrap_frame,
)

# ---------------------------------------------------------------------------
#  RC4 cipher
# ---------------------------------------------------------------------------


class TestRC4Crypt:
    """Test the RC4 stream cipher implementation."""

    def test_encrypt_decrypt_roundtrip(self):
        """RC4 is symmetric — applying it twice gives back the original."""
        key = b"secret-key"
        plaintext = b"Hello, Salus gateway!"
        ciphertext = rc4_crypt(key, plaintext)
        assert ciphertext != plaintext
        assert rc4_crypt(key, ciphertext) == plaintext

    def test_empty_data(self):
        assert rc4_crypt(b"key", b"") == b""

    def test_single_byte(self):
        ct = rc4_crypt(b"k", b"\x00")
        assert len(ct) == 1
        assert rc4_crypt(b"k", ct) == b"\x00"

    def test_different_keys_produce_different_output(self):
        data = b"same data"
        ct1 = rc4_crypt(b"key1", data)
        ct2 = rc4_crypt(b"key2", data)
        assert ct1 != ct2

    def test_output_length_matches_input(self):
        for length in (0, 1, 15, 16, 100, 1024):
            data = bytes(range(256)) * (length // 256 + 1)
            data = data[:length]
            assert len(rc4_crypt(b"key", data)) == length

    def test_known_vector(self):
        """Verify against a known RC4 test vector (RFC 6229 seed).

        Key = "Key", plaintext = all zeros (5 bytes).
        Expected keystream prefix for RC4("Key"): EB 9F 77 81 B7 ...
        """
        key = b"Key"
        plaintext = b"\x00\x00\x00\x00\x00"
        ct = rc4_crypt(key, plaintext)
        # XOR with zeros = keystream itself
        assert ct == bytes([0xEB, 0x9F, 0x77, 0x81, 0xB7])

    def test_long_payload_roundtrip(self):
        """Simulate a realistic JSON payload size."""
        key = b"md5-derived-key!"
        payload = b'{"requestAttr":"readall"}' * 100
        assert rc4_crypt(key, rc4_crypt(key, payload)) == payload


# ---------------------------------------------------------------------------
#  Frame splitting
# ---------------------------------------------------------------------------


class TestSplitFrames:
    """Test binary frame splitting on 0x16/0x17 terminators."""

    def test_empty_data(self):
        assert split_frames(b"") == []

    def test_no_terminators(self):
        """Data without frame markers is returned as a single frame."""
        data = b"hello world"
        assert split_frames(data) == [data]

    def test_single_final_frame(self):
        data = b"payload" + bytes([FRAME_FINAL])
        assert split_frames(data) == [b"payload"]

    def test_two_continuation_frames_plus_final(self):
        data = (
            b"frame1" + bytes([FRAME_CONT])
            + b"frame2" + bytes([FRAME_CONT])
            + b"frame3" + bytes([FRAME_FINAL])
        )
        assert split_frames(data) == [b"frame1", b"frame2", b"frame3"]

    def test_stops_at_final_marker(self):
        """Data after 0x17 is ignored."""
        data = (
            b"before" + bytes([FRAME_FINAL])
            + b"ignored-tail"
        )
        assert split_frames(data) == [b"before"]

    def test_consecutive_markers(self):
        """Consecutive markers with no data fall back to single-frame."""
        data = bytes([FRAME_CONT, FRAME_CONT, FRAME_FINAL])
        # No payload between markers → fallback returns raw data as-is
        assert split_frames(data) == [data]

    def test_single_byte_frames(self):
        data = b"A" + bytes([FRAME_CONT]) + b"B" + bytes([FRAME_FINAL])
        assert split_frames(data) == [b"A", b"B"]

    def test_realistic_33byte_response(self):
        """Simulate the 33-byte HS2 response: 32 data bytes + 0x17."""
        # Avoid using bytes that are frame markers (0x16, 0x17)
        payload = bytes(b"\xAA" * 32)
        data = payload + bytes([FRAME_FINAL])
        frames = split_frames(data)
        assert frames == [payload]

    def test_large_multi_frame_response(self):
        """Simulate a large HS1 response with continuation frames."""
        chunk = bytes(255) * 256  # 256-byte chunks
        data = b""
        for _i in range(50):
            data += chunk + bytes([FRAME_CONT])
        data += chunk + bytes([FRAME_FINAL])

        frames = split_frames(data)
        assert len(frames) == 51
        assert all(f == chunk for f in frames)


# ---------------------------------------------------------------------------
#  Frame wrapping
# ---------------------------------------------------------------------------


class TestWrapFrame:
    """Test frame wrapping utility."""

    def test_wrap_final(self):
        assert wrap_frame(b"data", final=True) == b"data" + bytes([FRAME_FINAL])

    def test_wrap_continuation(self):
        assert wrap_frame(b"data", final=False) == b"data" + bytes([FRAME_CONT])

    def test_wrap_empty_payload(self):
        assert wrap_frame(b"", final=True) == bytes([FRAME_FINAL])

    def test_default_is_final(self):
        assert wrap_frame(b"x") == b"x" + bytes([FRAME_FINAL])

    def test_roundtrip_wrap_split(self):
        """Wrapping then splitting should recover the original payload."""
        payload = b"test-payload"
        wrapped = wrap_frame(payload, final=True)
        frames = split_frames(wrapped)
        assert frames == [payload]

    def test_multi_frame_roundtrip(self):
        """Build a multi-frame message and split it back."""
        parts = [b"part1", b"part2", b"part3"]
        raw = b""
        for i, part in enumerate(parts):
            raw += wrap_frame(part, final=(i == len(parts) - 1))
        assert split_frames(raw) == parts
