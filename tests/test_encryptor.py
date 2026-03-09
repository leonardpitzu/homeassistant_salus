"""Tests for the encryptor.py backward-compatibility shim."""

from __future__ import annotations

from custom_components.salus.aes import IT600Encryptor
from custom_components.salus.encryptor import (
    IT600Encryptor as IT600EncryptorShim,
)


class TestBackwardCompatShim:
    """Ensure encryptor.py re-exports from aes.py correctly."""

    def test_shim_is_same_class(self):
        assert IT600EncryptorShim is IT600Encryptor
