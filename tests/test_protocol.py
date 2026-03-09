"""Tests for the GatewayProtocol abstract base class (protocol.py)."""

from __future__ import annotations

import pytest

from custom_components.salus.protocol import GatewayProtocol


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
