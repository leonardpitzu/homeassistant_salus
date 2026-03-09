"""Backward-compatibility shim — real implementation lives in aes.py."""

from .aes import IT600Encryptor

__all__ = ["IT600Encryptor"]
