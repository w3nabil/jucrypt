from __future__ import annotations

import os
import hmac
from typing import List, Union

from .story256 import (
    STORY256,
    EncryptResult,
    _STORY256Keys,
    _load_sboxes,
    _GF,
    _MIX_M,
    _b2,
    _P_MAC_TAG,   
)

# ── Attempt to load st_core ───────────────────────────────────────────────────

try:
    import story256_c as _st

    # Build GF and MDS flat buffers once at import time.
    # gf_flat  : 65 536 bytes, row-major GF[a][b] for a,b in 0..255
    # mds_flat : 1024 bytes,   row-major MDS[i][j] for i,j in 0..31  (PY-FIX-05)
    _gf_flat  = bytes(_GF[a][b]    for a in range(256) for b in range(256))
    _mds_flat = bytes(_MIX_M[i][j] for i in range(32)  for j in range(32))   # PY-FIX-05
    _st.st_build_tables(_gf_flat, _mds_flat)

    _C_AVAILABLE = True

except ImportError:
    _C_AVAILABLE = False


# ── Helper: flatten round keys list to bytes ─────────────────────────────────

def _rk_flat(round_keys: List[bytes]) -> bytes:
    """Concatenate 6 x 32-byte round keys into a single 192-byte buffer."""  
    return b"".join(round_keys)


# ── STORYC256 ─────────────────────────────────────────────────────────────────

class STORYC256(STORY256):                         
    """
    C-accelerated STORY-Raw (256-bit block).

    Inherits all key derivation from STORY256 (_STORY256Keys).
    Overrides _encrypt_block, encrypt, and decrypt to route the SPN
    hot path through st_core when available.

    Wire format is identical to STORY256 v1.1.0.
    Ciphertexts are interchangeable between STORYC256 and STORY256.
    """

    C_AVAILABLE: bool = _C_AVAILABLE

    # ── Block encryption ──────────────────────────────────────────────────────

    @staticmethod
    def _encrypt_block(
        block:      bytes,
        perm:       List[int],
        sbox:       List[int],
        round_keys: List[bytes],
        final_key:  bytes,
    ) -> bytes:
        """
        Encrypt one 32-byte block.

        Routes to st_core.st_encrypt_block() when C is available.
        Falls back to pure-Python STORY256._encrypt_block() otherwise.
        Called per-block from the CTR loop or directly in tests.
        """
        if not _C_AVAILABLE:
            return STORY256._encrypt_block(block, perm, sbox, round_keys, final_key)

        return _st.st_encrypt_block(
            block,
            bytes(perm),
            bytes(sbox),
            _rk_flat(round_keys),
            final_key,
        )

    # ── Encrypt ───────────────────────────────────────────────────────────────

    @staticmethod
    def encrypt(
        plaintext,
        story:    str,
        use_salt: bool = True,             
    ) -> EncryptResult:
        """
        Encrypt plaintext under a story passphrase.

        Parameters
        ----------
        plaintext : str | bytes | bytearray
        story     : str   natural-language narrative passphrase
        use_salt  : bool
            True  (default) — random 4-byte round_salt (production)
            False           — round_salt = 0 (deterministic testing)

        Returns
        -------
        EncryptResult(ciphertext, nonce, tag, round_salt, kdf_salt)
            ciphertext : bytes
            nonce      : bytes(16)   PY-FIX-03: 16 bytes (was 8)
            tag        : bytes(32)   BLAKE2b-256 over nonce||round_salt||kdf_salt||ct
            round_salt : int         4-byte value (0 if use_salt=False)
            kdf_salt   : bytes(16)   PBKDF2 salt for key stretching
        """
        pt_bytes = STORYC256._to_bytes(plaintext)

        kdf_salt = os.urandom(16)
        pool     = _load_sboxes()
        ks       = _STORY256Keys(story, pool, kdf_salt)

        # Round salt 
        round_salt_bytes = os.urandom(4) if use_salt else b'\x00\x00\x00\x00'
        round_salt_int   = int.from_bytes(round_salt_bytes, 'big')

        nonce = os.urandom(16)

        # ── CTR encryption ────────────────────────────────────────────────────
        if _C_AVAILABLE:
            # Full CTR loop in C — fastest path
            ciphertext = _st.st_ctr_crypt(
                pt_bytes,
                nonce,
                bytes(ks.perm),
                bytes(ks.sbox),
                _rk_flat(ks.round_keys),
                ks.final_key,
            )
        else:
            # Pure-Python CTR fallback
            buf     = bytearray()
            counter = 0
            for i in range(0, len(pt_bytes), STORYC256.BLOCK_SIZE):
                block = pt_bytes[i : i + STORYC256.BLOCK_SIZE]
                keystream = STORY256._encrypt_block(
                    nonce + counter.to_bytes(16, 'big'),
                    ks.perm, ks.sbox, ks.round_keys, ks.final_key,
                )
                buf.extend(b ^ k for b, k in zip(block, keystream))
                counter += 1
            ciphertext = bytes(buf)

        # ── Authentication tag ────────────────────────────────────────────────
        tag = _b2(
            nonce + round_salt_bytes + kdf_salt + ciphertext,
            _P_MAC_TAG,
            key         = ks.mac_key,
            digest_size = 32,
        )

        return EncryptResult(ciphertext, nonce, tag, round_salt_int, kdf_salt)

    # ── Decrypt ───────────────────────────────────────────────────────────────

    @staticmethod
    def decrypt(
        ciphertext: Union[str, bytes],
        story:      str,
        nonce:      Union[str, bytes],
        tag:        Union[str, bytes],
        round_salt: Union[int, bytes],
        kdf_salt:   Union[str, bytes],      
    ) -> bytes:
        """
        Authenticate then decrypt a STORY-Raw ciphertext.

        Raises ValueError on authentication failure (wrong key or tampered data).

        Parameters
        ----------
        ciphertext : bytes | hex str
        story      : str
        nonce      : bytes(16) | hex str     PY-FIX-07: must be 16 bytes
        tag        : bytes(32) | hex str
        round_salt : int | bytes(4)
        kdf_salt   : bytes(16) | hex str     PY-FIX-06: required for key schedule
        """
        ct_bytes         = STORYC256._to_bytes_param(ciphertext, "ciphertext")
        nc_bytes         = STORYC256._to_bytes_param(nonce,      "nonce")
        tag_bytes        = STORYC256._to_bytes_param(tag,        "tag")
        round_salt_bytes = STORYC256._salt_to_bytes(round_salt)
        kdf_salt_bytes   = STORYC256._to_bytes_param(kdf_salt,   "kdf_salt")

        if len(nc_bytes) != 16:
            raise ValueError(
                f"nonce must be 16 bytes, got {len(nc_bytes)}. "
                "Ensure you are not mixing v1.0.0 and v1.1.0 ciphertexts."
            )
        if len(tag_bytes) != 32:
            raise ValueError(f"tag must be 32 bytes, got {len(tag_bytes)}")
        if len(round_salt_bytes) != 4:
            raise ValueError(f"round_salt must be 4 bytes, got {len(round_salt_bytes)}")

        pool = _load_sboxes()
        ks   = _STORY256Keys(story, pool, kdf_salt_bytes)

        expected_tag = _b2(
            nc_bytes + round_salt_bytes + kdf_salt_bytes + ct_bytes,
            _P_MAC_TAG,
            key         = ks.mac_key,
            digest_size = 32,
        )
        if not hmac.compare_digest(expected_tag, tag_bytes):
            raise ValueError(
                "Authentication failed.\n"
                "The ciphertext, nonce, tag, round_salt, or kdf_salt has been "
                "tampered with, or the story passphrase is incorrect."
            )

        # ── CTR decryption (XOR is symmetric — same as encryption) ───────────
        if _C_AVAILABLE:
            plaintext = _st.st_ctr_crypt(
                ct_bytes,
                nc_bytes,
                bytes(ks.perm),
                bytes(ks.sbox),
                _rk_flat(ks.round_keys),
                ks.final_key,
            )
        else:
            buf     = bytearray()
            counter = 0
            for i in range(0, len(ct_bytes), STORYC256.BLOCK_SIZE):
                block = ct_bytes[i : i + STORYC256.BLOCK_SIZE]
                keystream = STORY256._encrypt_block(
                    nc_bytes + counter.to_bytes(16, 'big'),
                    ks.perm, ks.sbox, ks.round_keys, ks.final_key,
                )
                buf.extend(b ^ k for b, k in zip(block, keystream))
                counter += 1
            plaintext = bytes(buf)

        return plaintext

    # ── Convenience decoders ──────────────────────────────────────────────────

    @staticmethod
    def decrypt_str(
        ciphertext: Union[str, bytes],
        story:      str,
        nonce:      Union[str, bytes],
        tag:        Union[str, bytes],
        round_salt: Union[int, bytes],
        kdf_salt:   Union[str, bytes],   
        encoding:   str = "utf-16-le",
    ) -> str:
        """Decrypt and decode to string (default: UTF-16-LE)."""
        return STORYC256.decrypt(
            ciphertext, story, nonce, tag, round_salt, kdf_salt,
        ).decode(encoding)

    @staticmethod
    def decrypt_int(
        ciphertext: Union[str, bytes],
        story:      str,
        nonce:      Union[str, bytes],
        tag:        Union[str, bytes],
        round_salt: Union[int, bytes],
        kdf_salt:   Union[str, bytes],
    ) -> int:
        """Decrypt and interpret result as big-endian integer."""
        return int.from_bytes(
            STORYC256.decrypt(ciphertext, story, nonce, tag, round_salt, kdf_salt),
            "big",
        )