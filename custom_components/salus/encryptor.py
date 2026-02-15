"""AES-CBC encryptor for Salus iT600 local gateway communication."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_IV = bytes(
    [0x88, 0xA6, 0xB0, 0x79, 0x5D, 0x85, 0xDB, 0xFC,
     0xE6, 0xE0, 0xB3, 0xE9, 0xA6, 0x29, 0x65, 0x4B]
)


class IT600Encryptor:
    """Encrypt/decrypt JSON payloads for the iT600 gateway."""

    def __init__(self, euid: str) -> None:
        key = hashlib.md5(f"Salus-{euid.lower()}".encode()).digest() + bytes(16)
        self._cipher = Cipher(algorithms.AES(key), modes.CBC(_IV))

    def encrypt(self, plain: str) -> bytes:
        """Encrypt a UTF-8 string with AES-CBC + PKCS7 padding."""
        encryptor = self._cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded: bytes = padder.update(plain.encode()) + padder.finalize()
        return encryptor.update(padded) + encryptor.finalize()

    def decrypt(self, cipher_bytes: bytes) -> str:
        """Decrypt AES-CBC cipher bytes, strip PKCS7 padding, return UTF-8."""
        decryptor = self._cipher.decryptor()
        padded: bytes = decryptor.update(cipher_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain: bytes = unpadder.update(padded) + unpadder.finalize()
        return plain.decode()
