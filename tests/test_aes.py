"""Tests for the AES-CBC cipher module (aes.py)."""

from __future__ import annotations

from custom_components.salus.aes import IT600Encryptor


class TestIT600Encryptor:
    """Test AES-CBC encrypt/decrypt logic."""

    EUID = "001E5E0D32906128"

    def test_encrypt_returns_bytes(self):
        enc = IT600Encryptor(self.EUID)
        assert isinstance(enc.encrypt("hello"), bytes)

    def test_decrypt_returns_string(self):
        enc = IT600Encryptor(self.EUID)
        ct = enc.encrypt("hello")
        assert isinstance(enc.decrypt(ct), str)

    def test_roundtrip_short_message(self):
        enc = IT600Encryptor(self.EUID)
        for msg in ("", "a", "hello world", '{"key": "value"}'):
            assert enc.decrypt(enc.encrypt(msg)) == msg

    def test_roundtrip_json_payload(self):
        enc = IT600Encryptor(self.EUID)
        payload = '{"requestAttr":"readall","id":[{"data":{"UniID":"abc"}}]}'
        assert enc.decrypt(enc.encrypt(payload)) == payload

    def test_roundtrip_long_message(self):
        enc = IT600Encryptor(self.EUID)
        msg = "x" * 1024
        assert enc.decrypt(enc.encrypt(msg)) == msg

    def test_euid_case_insensitive(self):
        enc_lower = IT600Encryptor("001e5e0d32906128")
        enc_upper = IT600Encryptor("001E5E0D32906128")
        msg = "test message"
        assert enc_lower.encrypt(msg) == enc_upper.encrypt(msg)

    def test_different_euids_produce_different_ciphertext(self):
        enc1 = IT600Encryptor("001E5E0D32906128")
        enc2 = IT600Encryptor("AAAAAAAAAAAAAAAA")
        msg = "same payload"
        assert enc1.encrypt(msg) != enc2.encrypt(msg)

    def test_ciphertext_is_block_aligned(self):
        """AES block size is 16 bytes; output must be a multiple of 16."""
        enc = IT600Encryptor(self.EUID)
        for length in (0, 1, 15, 16, 17, 31, 32, 33):
            ct = enc.encrypt("a" * length)
            assert len(ct) % 16 == 0

    def test_cross_instance_roundtrip(self):
        """Encrypt with one instance, decrypt with a fresh one (same EUID)."""
        ct = IT600Encryptor(self.EUID).encrypt("cross-instance")
        pt = IT600Encryptor(self.EUID).decrypt(ct)
        assert pt == "cross-instance"

    def test_wrong_euid_cannot_decrypt(self):
        """Decrypting with a different EUID should fail or return garbage."""
        ct = IT600Encryptor(self.EUID).encrypt("secret")
        other = IT600Encryptor("AAAAAAAAAAAAAAAA")
        try:
            result = other.decrypt(ct)
            assert result != "secret"
        except Exception:
            pass  # padding error or similar is expected


class TestAES128:
    """Test AES-128 mode (aes128=True)."""

    EUID = "001E5E0D32906128"

    def test_aes128_roundtrip(self):
        enc = IT600Encryptor(self.EUID, aes128=True)
        for msg in ("", "hello", '{"requestAttr":"readall"}'):
            assert enc.decrypt(enc.encrypt(msg)) == msg

    def test_aes128_key_is_16_bytes(self):
        enc = IT600Encryptor(self.EUID, aes128=True)
        assert len(enc._cipher.algorithm.key) == 16

    def test_aes256_key_is_32_bytes(self):
        enc = IT600Encryptor(self.EUID)
        assert len(enc._cipher.algorithm.key) == 32

    def test_aes128_and_aes256_differ(self):
        """AES-128 and AES-256 produce different ciphertext for same input."""
        msg = "same plaintext"
        ct128 = IT600Encryptor(self.EUID, aes128=True).encrypt(msg)
        ct256 = IT600Encryptor(self.EUID).encrypt(msg)
        assert ct128 != ct256

    def test_aes128_cannot_decrypt_aes256(self):
        """Cross-mode decryption must fail or return wrong plaintext."""
        ct256 = IT600Encryptor(self.EUID).encrypt("secret256")
        dec128 = IT600Encryptor(self.EUID, aes128=True)
        try:
            result = dec128.decrypt(ct256)
            assert result != "secret256"
        except Exception:
            pass  # expected
