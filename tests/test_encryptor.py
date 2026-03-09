"""Tests for the encryptor.py backward-compatibility shim."""

from __future__ import annotations

from custom_components.salus.encryptor import (
    IT600Encryptor as IT600EncryptorShim,
)
from custom_components.salus.protocol_aes_cbc import IT600Encryptor


class TestBackwardCompatShim:
    """Ensure encryptor.py re-exports from protocol_aes_cbc.py correctly."""

    def test_shim_is_same_class(self):
        assert IT600EncryptorShim is IT600Encryptor
