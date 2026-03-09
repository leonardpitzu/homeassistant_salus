"""Tests for the GatewayProtocol abstract base class (protocol.py)."""

from __future__ import annotations

import pytest

from custom_components.salus.protocol import GatewayProtocol, is_reject_frame


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
