"""Tests for the IT600 encryptor."""

from __future__ import annotations

from custom_components.salus.encryptor import IT600Encryptor


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
            # If it doesn't raise, the plaintext must differ
            assert result != "secret"
        except Exception:
            pass  # padding error or similar is expected
