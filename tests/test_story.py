import os
import sys
import unicodedata
import unittest.mock as mock
import pytest

# ── Import both backends ───────────────────────────────────────────────────────
from jucrypt.story import STORY

try:
    from jucrypt.storyc import STORYC
    C_AVAILABLE = STORYC.C_AVAILABLE
except ImportError:
    STORYC      = None
    C_AVAILABLE = False

# ── Constants ──────────────────────────────────────────────────────────────────
STORY_KEY     = "This is a test story key"
STORY_KEY_2   = "A completely different key"
PLAIN_STR     = "Hello, STORY cipher!"
PLAIN_BYTES   = b"Hello, STORY cipher!"
PLAIN_UNICODE = "Héllo wörld — 日本語テスト 🔐"
FIXED_NONCE   = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"

# ── Helpers ────────────────────────────────────────────────────────────────────
def flip_bit(data: bytes, byte_idx: int = 0) -> bytes:
    """Return a copy of data with one bit flipped."""
    ba = bytearray(data)
    ba[byte_idx % len(ba)] ^= 0x01
    return bytes(ba)


def story_bytes_from_key(key: str) -> bytes:
    return unicodedata.normalize("NFC", key).encode("utf-16-le")


def backends():
    """Parametrize helper — returns (name, cls) pairs for all available backends."""
    pairs = [("Python", STORY)]
    if STORYC is not None:
        pairs.append(("C", STORYC))
    return pairs


# ═══════════════════════════════════════════════════════════════════════════════
#  1. Basic roundtrip
# ═══════════════════════════════════════════════════════════════════════════════
class TestRoundtrip:

    @pytest.mark.parametrize("name,cls", backends())
    def test_str_roundtrip(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_STR, STORY_KEY)
        assert cls.decrypt_str(ct, STORY_KEY, nc, tg) == PLAIN_STR

    @pytest.mark.parametrize("name,cls", backends())
    def test_bytes_roundtrip(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_bytearray_roundtrip(self, name, cls):
        ct, nc, tg = cls.encrypt(bytearray(PLAIN_BYTES), STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_unicode_roundtrip(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_UNICODE, STORY_KEY)
        assert cls.decrypt_str(ct, STORY_KEY, nc, tg) == PLAIN_UNICODE


# ═══════════════════════════════════════════════════════════════════════════════
#  2. Edge cases — message sizes
# ═══════════════════════════════════════════════════════════════════════════════
class TestEdgeCases:

    @pytest.mark.parametrize("name,cls", backends())
    def test_empty_plaintext(self, name, cls):
        ct, nc, tg = cls.encrypt(b"", STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == b""

    @pytest.mark.parametrize("name,cls", backends())
    def test_single_byte(self, name, cls):
        data = b"\xAB"
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == data

    @pytest.mark.parametrize("name,cls", backends())
    @pytest.mark.parametrize("size", [
        1, 7, 15, 16, 17, 31, 32, 33,
        127, 128, 129, 255, 256, 257,
        1023, 1024, 1025,
    ])
    def test_various_sizes(self, name, cls, size):
        data = os.urandom(size)
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == data

    @pytest.mark.parametrize("name,cls", backends())
    def test_exactly_one_block(self, name, cls):
        data = os.urandom(16)
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == data

    @pytest.mark.parametrize("name,cls", backends())
    def test_exactly_two_blocks(self, name, cls):
        data = os.urandom(32)
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == data

    @pytest.mark.parametrize("name,cls", backends())
    def test_all_zeros(self, name, cls):
        data = b"\x00" * 64
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == data
        assert ct != data   # ciphertext must not equal plaintext

    @pytest.mark.parametrize("name,cls", backends())
    def test_all_ones(self, name, cls):
        data = b"\xFF" * 64
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == data


# ═══════════════════════════════════════════════════════════════════════════════
#  3. Authentication — tamper detection
# ═══════════════════════════════════════════════════════════════════════════════
class TestAuthentication:

    @pytest.mark.parametrize("name,cls", backends())
    def test_wrong_key_rejected(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(ct, STORY_KEY_2, nc, tg)

    @pytest.mark.parametrize("name,cls", backends())
    def test_tampered_ciphertext_first_byte(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(flip_bit(ct, 0), STORY_KEY, nc, tg)

    @pytest.mark.parametrize("name,cls", backends())
    def test_tampered_ciphertext_last_byte(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(flip_bit(ct, -1), STORY_KEY, nc, tg)

    @pytest.mark.parametrize("name,cls", backends())
    def test_tampered_nonce(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(ct, STORY_KEY, flip_bit(nc), tg)

    @pytest.mark.parametrize("name,cls", backends())
    def test_tampered_tag(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(ct, STORY_KEY, nc, flip_bit(tg))

    @pytest.mark.parametrize("name,cls", backends())
    def test_swapped_nonce_and_ct(self, name, cls):
        """Tag from message A must not validate message B."""
        ct1, nc1, tg1 = cls.encrypt(b"message one", STORY_KEY)
        ct2, nc2, tg2 = cls.encrypt(b"message two", STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(ct2, STORY_KEY, nc1, tg1)

    @pytest.mark.parametrize("name,cls", backends())
    def test_truncated_ciphertext(self, name, cls):
        ct, nc, tg = cls.encrypt(os.urandom(64), STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(ct[:-1], STORY_KEY, nc, tg)

    @pytest.mark.parametrize("name,cls", backends())
    def test_extended_ciphertext(self, name, cls):
        ct, nc, tg = cls.encrypt(os.urandom(64), STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(ct + b"\x00", STORY_KEY, nc, tg)

    @pytest.mark.parametrize("name,cls", backends())
    def test_zeroed_tag_rejected(self, name, cls):
        ct, nc, _ = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        with pytest.raises(ValueError, match="Authentication Failed"):
            cls.decrypt(ct, STORY_KEY, nc, b"\x00" * 32)


# ═══════════════════════════════════════════════════════════════════════════════
#  4. Output properties
# ═══════════════════════════════════════════════════════════════════════════════
class TestOutputProperties:

    @pytest.mark.parametrize("name,cls", backends())
    def test_return_types(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert isinstance(ct, bytes)
        assert isinstance(nc, bytes)
        assert isinstance(tg, bytes)

    @pytest.mark.parametrize("name,cls", backends())
    @pytest.mark.parametrize("size", [1, 15, 16, 17, 100, 1000])
    def test_ciphertext_length_equals_plaintext(self, name, cls, size):
        """CTR mode — ciphertext must be same length as plaintext."""
        data = os.urandom(size)
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert len(ct) == size

    @pytest.mark.parametrize("name,cls", backends())
    def test_nonce_length(self, name, cls):
        _, nc, _ = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert len(nc) == 8

    @pytest.mark.parametrize("name,cls", backends())
    def test_tag_length(self, name, cls):
        _, _, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert len(tg) == 32  # HMAC-SHA256

    @pytest.mark.parametrize("name,cls", backends())
    def test_nonce_is_random(self, name, cls):
        """Two encryptions must produce different nonces."""
        _, nc1, _ = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        _, nc2, _ = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert nc1 != nc2

    @pytest.mark.parametrize("name,cls", backends())
    def test_ciphertext_is_random(self, name, cls):
        """Same plaintext encrypted twice must produce different ciphertexts."""
        ct1, _, _ = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        ct2, _, _ = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert ct1 != ct2

    @pytest.mark.parametrize("name,cls", backends())
    def test_ciphertext_not_plaintext(self, name, cls):
        data = os.urandom(256)
        ct, _, _ = cls.encrypt(data, STORY_KEY)
        assert ct != data


# ═══════════════════════════════════════════════════════════════════════════════
#  5. Unicode / key normalisation
# ═══════════════════════════════════════════════════════════════════════════════
class TestUnicode:

    @pytest.mark.parametrize("name,cls", backends())
    def test_nfc_nfd_equivalence(self, name, cls):
        """NFC and NFD forms of the same string must produce the same key."""
        key_nfc = unicodedata.normalize("NFC", "café")
        key_nfd = unicodedata.normalize("NFD", "café")
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, key_nfc)
        # NFD key must decrypt what NFC key encrypted
        pt = cls.decrypt(ct, key_nfd, nc, tg)
        assert pt == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_cjk_key(self, name, cls):
        key = "秘密鍵テスト"
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, key)
        assert cls.decrypt(ct, key, nc, tg) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_emoji_key(self, name, cls):
        key = "my 🔐 secret 🗝️ key"
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, key)
        assert cls.decrypt(ct, key, nc, tg) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_very_long_key(self, name, cls):
        key = "x" * 10_000
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, key)
        assert cls.decrypt(ct, key, nc, tg) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_single_char_key(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, "a")
        assert cls.decrypt(ct, "a", nc, tg) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_whitespace_only_key(self, name, cls):
        key = "   "
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, key)
        assert cls.decrypt(ct, key, nc, tg) == PLAIN_BYTES


# ═══════════════════════════════════════════════════════════════════════════════
#  6. Input parameter formats
# ═══════════════════════════════════════════════════════════════════════════════
class TestInputFormats:

    @pytest.mark.parametrize("name,cls", backends())
    def test_hex_nonce_and_tag(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc.hex(), tg.hex()) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_hex_ciphertext(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert cls.decrypt(ct.hex(), STORY_KEY, nc, tg) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_all_hex_params(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        assert cls.decrypt(ct.hex(), STORY_KEY, nc.hex(), tg.hex()) == PLAIN_BYTES

    @pytest.mark.parametrize("name,cls", backends())
    def test_malformed_hex_raises(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        with pytest.raises(ValueError, match="malformed"):
            cls.decrypt(ct, STORY_KEY, "ZZZZZZZZZZZZZZZZ", tg)

    @pytest.mark.parametrize("name,cls", backends())
    def test_wrong_type_nonce_raises(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_BYTES, STORY_KEY)
        with pytest.raises(TypeError):
            cls.decrypt(ct, STORY_KEY, 12345, tg)

    @pytest.mark.parametrize("name,cls", backends())
    def test_wrong_type_plaintext_raises(self, name, cls):
        with pytest.raises(TypeError):
            cls.encrypt(12345, STORY_KEY)


# ═══════════════════════════════════════════════════════════════════════════════
#  7. C / Python parity
# ═══════════════════════════════════════════════════════════════════════════════
@pytest.mark.skipif(not C_AVAILABLE, reason="C extension not available")
class TestCPythonParity:

    def test_c_encrypt_python_decrypt(self):
        ct, nc, tg = STORYC.encrypt(PLAIN_BYTES, STORY_KEY)
        assert STORY.decrypt(ct, STORY_KEY, nc, tg) == PLAIN_BYTES

    def test_python_encrypt_c_decrypt(self):
        ct, nc, tg = STORY.encrypt(PLAIN_BYTES, STORY_KEY)
        assert STORYC.decrypt(ct, STORY_KEY, nc, tg) == PLAIN_BYTES

    @pytest.mark.parametrize("size", [1, 15, 16, 17, 64, 128, 255, 256, 1000, 65536])
    def test_parity_various_sizes(self, size):
        data = os.urandom(size)
        ct, nc, tg = STORYC.encrypt(data, STORY_KEY)
        assert STORY.decrypt(ct, STORY_KEY, nc, tg) == data

    def test_auth_tag_identical_fixed_nonce(self):
        """Both backends must produce the same HMAC tag for the same inputs."""
        with mock.patch("os.urandom", return_value=FIXED_NONCE):
            _, _, tg_c = STORYC.encrypt(PLAIN_BYTES, STORY_KEY)
        with mock.patch("os.urandom", return_value=FIXED_NONCE):
            _, _, tg_py = STORY.encrypt(PLAIN_BYTES, STORY_KEY)
        assert tg_c == tg_py

    def test_ciphertext_identical_fixed_nonce(self):
        """Both backends must produce identical ciphertext for the same nonce."""
        with mock.patch("os.urandom", return_value=FIXED_NONCE):
            ct_c, _, _ = STORYC.encrypt(PLAIN_BYTES, STORY_KEY)
        with mock.patch("os.urandom", return_value=FIXED_NONCE):
            ct_py, _, _ = STORY.encrypt(PLAIN_BYTES, STORY_KEY)
        assert ct_c == ct_py


# ═══════════════════════════════════════════════════════════════════════════════
#  8. Determinism
# ═══════════════════════════════════════════════════════════════════════════════
class TestDeterminism:

    @pytest.mark.parametrize("name,cls", backends())
    def test_fixed_nonce_deterministic(self, name, cls):
        """Same key + same nonce must always produce the same ciphertext."""
        data = os.urandom(64)
        with mock.patch("os.urandom", return_value=FIXED_NONCE):
            ct1, nc1, tg1 = cls.encrypt(data, STORY_KEY)
        with mock.patch("os.urandom", return_value=FIXED_NONCE):
            ct2, nc2, tg2 = cls.encrypt(data, STORY_KEY)
        assert ct1 == ct2
        assert tg1 == tg2

    @pytest.mark.parametrize("name,cls", backends())
    def test_different_keys_different_output(self, name, cls):
        data = os.urandom(64)
        with mock.patch("os.urandom", return_value=FIXED_NONCE):
            ct1, _, _ = cls.encrypt(data, STORY_KEY)
        with mock.patch("os.urandom", return_value=FIXED_NONCE):
            ct2, _, _ = cls.encrypt(data, STORY_KEY_2)
        assert ct1 != ct2

    @pytest.mark.parametrize("name,cls", backends())
    def test_different_nonces_different_output(self, name, cls):
        data = os.urandom(64)
        nonce1 = b"\x00" * 8
        nonce2 = b"\x01" * 8
        with mock.patch("os.urandom", return_value=nonce1):
            ct1, _, _ = cls.encrypt(data, STORY_KEY)
        with mock.patch("os.urandom", return_value=nonce2):
            ct2, _, _ = cls.encrypt(data, STORY_KEY)
        assert ct1 != ct2


# ═══════════════════════════════════════════════════════════════════════════════
#  9. Key schedule — domain separation
# ═══════════════════════════════════════════════════════════════════════════════
class TestKeySchedule:

    @pytest.mark.parametrize("name,cls", backends())
    def test_enc_mac_keys_differ(self, name, cls):
        enc_key, mac_key = cls._derive_master_key(story_bytes_from_key(STORY_KEY))
        assert enc_key != mac_key

    @pytest.mark.parametrize("name,cls", backends())
    def test_all_round_keys_distinct(self, name, cls):
        enc_key, _ = cls._derive_master_key(story_bytes_from_key(STORY_KEY))
        rks = cls._derive_round_keys(enc_key)
        assert len(set(rks)) == len(rks), "duplicate round keys detected"

    @pytest.mark.parametrize("name,cls", backends())
    def test_whitening_differs_from_round_keys(self, name, cls):
        enc_key, _ = cls._derive_master_key(story_bytes_from_key(STORY_KEY))
        rks = cls._derive_round_keys(enc_key)
        wk  = cls._derive_whitening_key(enc_key)
        assert wk not in rks

    @pytest.mark.parametrize("name,cls", backends())
    def test_different_story_keys_different_enc_keys(self, name, cls):
        enc1, _ = cls._derive_master_key(story_bytes_from_key(STORY_KEY))
        enc2, _ = cls._derive_master_key(story_bytes_from_key(STORY_KEY_2))
        assert enc1 != enc2


# ═══════════════════════════════════════════════════════════════════════════════
#  10. Large data
# ═══════════════════════════════════════════════════════════════════════════════
class TestLargeData:

    @pytest.mark.parametrize("name,cls", backends())
    def test_1mb_roundtrip(self, name, cls):
        data = os.urandom(1024 * 1024)
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert cls.decrypt(ct, STORY_KEY, nc, tg) == data

    @pytest.mark.parametrize("name,cls", backends())
    def test_1mb_ciphertext_length(self, name, cls):
        data = os.urandom(1024 * 1024)
        ct, _, _ = cls.encrypt(data, STORY_KEY)
        assert len(ct) == len(data)


# ═══════════════════════════════════════════════════════════════════════════════
#  11. decrypt_str encoding
# ═══════════════════════════════════════════════════════════════════════════════
class TestDecryptStr:

    @pytest.mark.parametrize("name,cls", backends())
    def test_default_utf16le(self, name, cls):
        ct, nc, tg = cls.encrypt(PLAIN_STR, STORY_KEY)
        assert cls.decrypt_str(ct, STORY_KEY, nc, tg) == PLAIN_STR

    @pytest.mark.parametrize("name,cls", backends())
    def test_explicit_utf8(self, name, cls):
        data = PLAIN_STR.encode("utf-8")
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        assert cls.decrypt_str(ct, STORY_KEY, nc, tg, encoding="utf-8") == PLAIN_STR


# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.exit(subprocess.call(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=root
    ))