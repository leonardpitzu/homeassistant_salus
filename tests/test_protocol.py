"""Tests for the GatewayProtocol abstract base class (protocol.py)."""

from __future__ import annotations

import pytest

from custom_components.salus.protocol import (
    GatewayProtocol,
    is_new_protocol_frame,
    is_reject_frame,
    parse_frame_33,
)


class TestGatewayProtocolABC:
    """Verify that GatewayProtocol cannot be instantiated directly."""

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError, match="abstract"):
            GatewayProtocol()  # type: ignore[abstract]

    def test_required_abstract_methods(self):
        """All expected abstract methods exist on the ABC."""
        abstracts = GatewayProtocol.__abstractmethods__
        expected = {"encrypt", "decrypt", "connect", "wrap_request", "unwrap_response"}
        assert expected == abstracts

    def test_concrete_subclass_must_implement_all(self):
        """Partially implemented subclass still cannot be instantiated."""

        class Partial(GatewayProtocol):
            def encrypt(self, data: str) -> bytes:
                return b""

        with pytest.raises(TypeError, match="abstract"):
            Partial()  # type: ignore[abstract]


class TestIsRejectFrame:
    """Test the module-level is_reject_frame() helper."""

    def test_valid_reject_frame(self):
        assert is_reject_frame(bytes(32) + b"\xAE") is True

    def test_wrong_length(self):
        assert is_reject_frame(bytes(32)) is False

    def test_wrong_trailer(self):
        assert is_reject_frame(bytes(32) + b"\xFF") is False

    def test_empty(self):
        assert is_reject_frame(b"") is False

    def test_real_world_aes256_reject(self):
        """Actual response from the user's gateway."""
        raw = bytes.fromhex(
            "8b4108b7dcf1ed6bc03180fa566eb857"
            "40db686c8dc55a95b8bd72be640888fd"
            "ae"
        )
        assert is_reject_frame(raw) is True

    def test_real_world_aes128_reject(self):
        raw = bytes.fromhex(
            "beedc470081939c6560c4d7e0034207b"
            "762d64da6055d5a3190fbe96650888fd"
            "ae"
        )
        assert is_reject_frame(raw) is True

    def test_new_protocol_frame_not_reject(self):
        """0xAF trailer is a new-protocol frame, not a reject."""
        raw = bytes(32) + b"\xAF"
        assert is_reject_frame(raw) is False


class TestIsNewProtocolFrame:
    """Test is_new_protocol_frame() helper."""

    def test_valid_new_protocol_frame(self):
        assert is_new_protocol_frame(bytes(32) + b"\xAF") is True

    def test_reject_is_not_new_protocol(self):
        assert is_new_protocol_frame(bytes(32) + b"\xAE") is False

    def test_wrong_length(self):
        assert is_new_protocol_frame(bytes(32)) is False

    def test_empty(self):
        assert is_new_protocol_frame(b"") is False

    def test_real_world_new_protocol(self):
        """Actual 0xAF response from user's gateway."""
        raw = bytes.fromhex(
            "ac1488c2aeab8e40a4487bcf38a03586"
            "3e4d863c551fda99a0e187357b084b1f"
            "af"
        )
        assert is_new_protocol_frame(raw) is True


class TestParseFrame33:
    """Test the parse_frame_33() structured frame parser."""

    def test_reject_frame(self):
        raw = bytes.fromhex(
            "8b4108b7dcf1ed6bc03180fa566eb857"
            "40db686c8dc55a95b8bd72be640888fd"
            "ae"
        )
        frame = parse_frame_33(raw)
        assert frame is not None
        assert frame.is_reject is True
        assert frame.is_new_protocol is False
        assert frame.trailer_name == "reject"
        assert frame.counter == 0x64
        assert frame.tag == bytes.fromhex("0888fd")
        assert len(frame.payload) == 28

    def test_new_protocol_frame(self):
        raw = bytes.fromhex(
            "ac1488c2aeab8e40a4487bcf38a03586"
            "3e4d863c551fda99a0e187357b084b1f"
            "af"
        )
        frame = parse_frame_33(raw)
        assert frame is not None
        assert frame.is_reject is False
        assert frame.is_new_protocol is True
        assert frame.trailer_name == "new-protocol"
        assert frame.counter == 0x7B
        assert frame.tag == bytes.fromhex("084b1f")

    def test_incrementing_counter(self):
        """Consecutive responses have incrementing counters."""
        hex_responses = [
            "ac1488c2aeab8e40a4487bcf38a035863e4d863c551fda99a0e187357b084b1faf",
            "34e2e9bf1eed482d3acd80babf39b61b08a3b193ddb4e9b66330690c7c084b1faf",
            "0906c155dc7216f935731db22e3d46ec28624d4a10d5f6c5e809aa2a7d084b1faf",
        ]
        counters = []
        for h in hex_responses:
            frame = parse_frame_33(bytes.fromhex(h))
            assert frame is not None
            counters.append(frame.counter)
            assert frame.tag == bytes.fromhex("084b1f")
        assert counters == [0x7B, 0x7C, 0x7D]

    def test_wrong_trailer_returns_none(self):
        raw = bytes(32) + b"\xFF"
        assert parse_frame_33(raw) is None

    def test_wrong_length_returns_none(self):
        assert parse_frame_33(bytes(32)) is None

    def test_empty_returns_none(self):
        assert parse_frame_33(b"") is None

    def test_frame33_is_frozen(self):
        raw = bytes(32) + b"\xAE"
        frame = parse_frame_33(raw)
        with pytest.raises(AttributeError):
            frame.counter = 99  # type: ignore[misc]
