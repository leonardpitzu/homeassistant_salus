"""Backward-compatibility shim — real implementation lives in protocol_aes_cbc.py."""

from .protocol_aes_cbc import IT600Encryptor

__all__ = ["IT600Encryptor"]
