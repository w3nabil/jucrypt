import os
import hashlib
import hmac
import json
from typing import Tuple, List, Union
import unicodedata

# Pure Python
# GF(2^8) multiplication table — built once at import time for speed
def _build_gf_table() -> List[List[int]]:
    table = [[0] * 256 for _ in range(256)]
    for a in range(256):
        x = a
        for b in range(256):
            p, y, xx = 0, b, x
            for _ in range(8):
                if y & 1:
                    p ^= xx
                hi = xx & 0x80
                xx = (xx << 1) & 0xFF
                if hi:
                    xx ^= 0x1B
                y >>= 1
            table[a][b] = p
    return table


_GF = _build_gf_table()


# Cauchy MDS matrix derivation
def _derive_cauchy_matrices() -> List[List[int]]:
    # Multiplicative inverse table in GF(2^8)
    gf_inv = [0] * 256
    for a in range(1, 256):
        # Compute a^254 via repeated squaring
        result, base, exp = 1, a, 254
        while exp > 0:
            if exp & 1:
                result = _GF[result][base]
            base = _GF[base][base]
            exp >>= 1
        gf_inv[a] = result

    def pow_alpha(n: int) -> int:
        a = 1
        for _ in range(n):
            a = _GF[a][2]
        return a

    xs = [pow_alpha(i) for i in range(16)]       # α^0  ..... α^15
    ys = [pow_alpha(i + 16) for i in range(16)]  # α^16 ..... α^31

    # Cauchy matrix: all xs distinct, all ys distinct, sets disjoint → invertible
    M = [[gf_inv[xs[i] ^ ys[j]] for j in range(16)] for i in range(16)]

    # Gauss-Jordan inversion over GF(2^8)
    n = 16
    aug = [M[i][:] + [1 if i == j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        piv = next((r for r in range(col, n) if aug[r][col]), -1)
        if piv == -1:
            raise RuntimeError("Cauchy matrix singular")
        aug[col], aug[piv] = aug[piv], aug[col]
        pi = gf_inv[aug[col][col]]
        for k in range(2 * n):
            aug[col][k] = _GF[aug[col][k]][pi]
        for r in range(n):
            if r != col and aug[r][col]:
                f = aug[r][col]
                for k in range(2 * n):
                    aug[r][k] ^= _GF[f][aug[col][k]]
    return M


_MIX_M = _derive_cauchy_matrices()


# Build once at import time alongside _GF and _MIX_M
def _build_mix_table() -> List[List[List[int]]]:
    """
    Precompute MDS contributions:
    _MIX_T[i][j][v] = GF_mul(MIX_M[i][j], v)
    So _mix inner loop becomes pure XOR, zero GF mul at runtime.
    """
    return [
        [
            [_GF[_MIX_M[i][j]][v] for v in range(256)]
            for j in range(16)
        ]
        for i in range(16)
    ]


_MIX_T = _build_mix_table()


# Main Story Class
class STORY:
    # Constants
    BLOCK_SIZE = 16  # 128-bit block
    KEY_SIZE   = 32  # 256-bit derived key
    ROUNDS     = 5

    # S-box cache — shared across all instances
    _SBOXES_CACHE: dict = {}

    # S-box validation
    @classmethod
    def _validate_sbox(cls, idx: int, sbox: list) -> None:
        if len(sbox) != 256:
            raise ValueError(f"S-box {idx}: expected 256 entries, got {len(sbox)}")
        if sorted(sbox) != list(range(256)):
            raise ValueError(
                f"S-box {idx}: not a bijection (not a permutation of 0–255)"
            )

    # S-box loading — checks JSON first, falls back to default pool
    @classmethod
    def _load_sboxes(cls) -> dict:
        if cls._SBOXES_CACHE:
            return cls._SBOXES_CACHE

        base      = os.path.dirname(__file__)
        json_path = os.path.join(base, "customju", "sboxes.json") # usually the package lib file if installed via pypi

        if os.path.isfile(json_path):
            with open(json_path, "r") as f:
                raw = json.load(f)
            for k, v in raw.items():
                sbox = [(int(x) - 1) % 256 for x in v.split(",")]
                cls._validate_sbox(int(k), sbox)
                cls._SBOXES_CACHE[int(k)] = sbox
            return cls._SBOXES_CACHE

        try:
            from .default_sboxes import SBOX_POOL
        except ImportError:
            raise RuntimeError(
                "STORY S-box pool not found.\n"
                "Expected one of:\n"
                "  -> customju/sboxes.json       (your custom pool)\n"
                "  -> jucrypt/default_sboxes.py  (ships with the package)\n"
                "Re-install: pip uninstall jucrypt && pip install jucrypt\n"
                "or place customju/sboxes.json next to story.py."
            )

        for idx, sbox in SBOX_POOL.items():
            cls._validate_sbox(idx, sbox)
            cls._SBOXES_CACHE[idx] = sbox

        return cls._SBOXES_CACHE

    @staticmethod
    def _derive_master_key(story_bytes: bytes) -> Tuple[bytes, bytes]:
        """Derive enc_key and mac_key via HKDF-style SHA256."""
        prk     = hmac.new(b"story_v1_salt", story_bytes, hashlib.sha256).digest()
        enc_key = hmac.new(prk, b"enc||story_v1_master\x01", hashlib.sha256).digest()
        mac_key = hmac.new(prk, b"mac||story_v1_master\x02", hashlib.sha256).digest()
        return enc_key, mac_key

    @staticmethod
    def _derive_sbox(master: bytes) -> List[int]:
        """Select one S-box from the pool deterministically from master key."""
        all_sboxes = STORY._load_sboxes()
        pool_size  = len(all_sboxes)
        threshold  = 65536 - (65536 % pool_size)

        stream = bytearray(hashlib.shake_256(b"story_v1_sbox||" + master).digest(64))
        pos    = 0

        while True:
            if pos + 1 >= len(stream):
                stream = bytearray(
                    hashlib.shake_256(
                        b"story_v1_sbox||" + master + pos.to_bytes(4, "big")
                    ).digest(64)
                )
                pos = 0
            val  = (stream[pos] << 8) | stream[pos + 1]
            pos += 2
            if val < threshold:
                return all_sboxes[val % pool_size]

    @staticmethod
    def _derive_round_keys(master: bytes) -> List[bytes]:
        """Derive ROUNDS x 16-byte round keys from master key."""
        return [
            hashlib.shake_256(
                b"story_v1_roundkey||" + master + i.to_bytes(4, "big")
            ).digest(16)
            for i in range(STORY.ROUNDS)
        ]

    @staticmethod
    def _derive_whitening_key(master: bytes) -> bytes:
        """Final AddRoundKey whitening key — domain-separated from round keys."""
        return hashlib.shake_256(b"story_v1_whitening||" + master).digest(16)

    @staticmethod
    def _derive_perm(master: bytes) -> List[int]:
        """Key-dependent byte permutation via unbiased Fisher-Yates."""
        stream = bytearray(hashlib.shake_256(b"story_v1_perm||" + master).digest(64))
        pos    = 0
        perm   = list(range(16))

        for i in range(15, 0, -1):
            limit     = i + 1
            threshold = 256 - (256 % limit)
            while True:
                if pos >= len(stream):
                    stream = bytearray(
                        hashlib.shake_256(
                            b"story_v1_perm||" + master + pos.to_bytes(4, "big")
                        ).digest(64)
                    )
                    pos = 0
                b   = stream[pos]
                pos += 1
                if b < threshold:
                    j                = b % limit
                    perm[i], perm[j] = perm[j], perm[i]
                    break
        return perm

    # SPN primitives
    @staticmethod
    def _sub_permute(state: List[int], sbox: List[int], perm: List[int]) -> None:
        """Read from permuted position, then apply sbox — single pass."""
        tmp = state[:]
        for i in range(16):
            state[i] = sbox[tmp[perm[i]]]

    @staticmethod
    def _mix(state: List[int]) -> None:
        """Full-state MDS mix over GF(2^8) — zero runtime GF mul via precomputed table."""
        result = [0] * 16
        for i in range(16):
            t   = _MIX_T[i]
            acc = 0
            for j in range(16):
                acc ^= t[j][state[j]]
            result[i] = acc
        state[:] = result

    # Block encryption
    @staticmethod
    def _encrypt_block(
        block      : bytes,
        sbox       : List[int],
        perm       : List[int],
        round_keys : List[bytes],
        final_int  : int,
    ) -> bytes:
        """Encrypt one 16-byte block."""
        state = list(block)
        for rk in round_keys:
            for i in range(16):
                state[i] ^= rk[i]
            STORY._sub_permute(state, sbox, perm)
            STORY._mix(state)
        # Final whitening — single int XOR, no loop
        return (int.from_bytes(bytes(state), "big") ^ final_int).to_bytes(16, "big")

    # Input normalisation
    @staticmethod
    def _to_bytes(data) -> bytes:
        """Convert any supported plaintext type to bytes."""
        if isinstance(data, bytes):
            return data
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, str):
            return data.encode("utf-16-le")
        raise TypeError(
            f"Plaintext must be str, bytes, or bytearray. Got: {type(data).__name__}"
        )

    @staticmethod
    def _to_bytes_param(data, name: str) -> bytes:
        """Convert a hex string or bytes parameter (nonce / tag)."""
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        if isinstance(data, str):
            try:
                return bytes.fromhex(data)
            except ValueError:
                raise ValueError(f"'{name}' hex string is malformed: {data!r}")
        raise TypeError(
            f"'{name}' must be bytes or hex string. Got: {type(data).__name__}"
        )

    # Public API
    @staticmethod
    def encrypt(plaintext, story: str) -> Tuple[bytes, bytes, bytes]:
        """Encrypt plaintext under a story key.

        Returns (ciphertext, nonce, tag) all as bytes.
        """
        pt_bytes    = STORY._to_bytes(plaintext)
        story_norm  = unicodedata.normalize("NFC", story)
        story_bytes = story_norm.encode("utf-16-le")

        enc_key, mac_key = STORY._derive_master_key(story_bytes)

        # Key schedule — paid once per message
        sbox       = STORY._derive_sbox(enc_key)
        perm       = STORY._derive_perm(enc_key)
        round_keys = STORY._derive_round_keys(enc_key)
        final_key  = STORY._derive_whitening_key(enc_key)
        final_int  = int.from_bytes(final_key, "big")  # precomputed once

        # CTR encryption
        nonce      = os.urandom(8)
        ciphertext = bytearray()
        counter    = 0

        for i in range(0, len(pt_bytes), STORY.BLOCK_SIZE):
            block     = pt_bytes[i : i + STORY.BLOCK_SIZE]
            keystream = STORY._encrypt_block(
                nonce + counter.to_bytes(8, "big"),
                sbox,
                perm,
                round_keys,
                final_int,
            )
            # zip handles last partial block naturally — no padding needed in CTR
            ciphertext.extend(ks ^ pb for ks, pb in zip(keystream, block))
            counter += 1

        # Authenticate: HMAC-SHA256 over nonce || ciphertext
        tag = hmac.new(
            mac_key,
            nonce + bytes(ciphertext),
            hashlib.sha256,
        ).digest()

        return bytes(ciphertext), nonce, tag

    @staticmethod
    def decrypt(
        ciphertext : Union[str, bytes],
        story      : str,
        nonce      : Union[str, bytes],
        tag        : Union[str, bytes],
    ) -> bytes:
        """Decrypt and authenticate a STORY ciphertext."""
        ct_bytes  = STORY._to_bytes_param(ciphertext, "ciphertext")
        nc_bytes  = STORY._to_bytes_param(nonce,      "nonce")
        tag_bytes = STORY._to_bytes_param(tag,        "tag")

        story_norm  = unicodedata.normalize("NFC", story)
        story_bytes = story_norm.encode("utf-16-le")

        enc_key, mac_key = STORY._derive_master_key(story_bytes)

        # Key schedule — paid once per message
        sbox       = STORY._derive_sbox(enc_key)
        perm       = STORY._derive_perm(enc_key)
        round_keys = STORY._derive_round_keys(enc_key)
        final_key  = STORY._derive_whitening_key(enc_key)
        final_int  = int.from_bytes(final_key, "big")  # precomputed once

        # Authenticate first — fail fast before any decryption
        check = hmac.new(
            mac_key,
            nc_bytes + ct_bytes,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(check, tag_bytes):
            raise ValueError(
                "Authentication Failed.\n"
                "The ciphertext, nonce, or tag has been tampered with,\n"
                "or the story key is incorrect."
            )
        # CTR decryption
        plaintext = bytearray()
        counter   = 0

        for i in range(0, len(ct_bytes), STORY.BLOCK_SIZE):
            block     = ct_bytes[i : i + STORY.BLOCK_SIZE]
            keystream = STORY._encrypt_block(
                nc_bytes + counter.to_bytes(8, "big"),
                sbox,
                perm,
                round_keys,
                final_int,
            )
            # zip handles last partial block naturally — no padding needed in CTR
            plaintext.extend(ks ^ cb for ks, cb in zip(keystream, block))
            counter += 1

        return bytes(plaintext)

    @staticmethod
    def decrypt_str(
        ciphertext : Union[str, bytes],
        story      : str,
        nonce      : Union[str, bytes],
        tag        : Union[str, bytes],
        encoding   : str = "utf-16-le",
    ) -> str:
        """Decrypt and decode to string. Default encoding is UTF-16-LE."""
        return STORY.decrypt(ciphertext, story, nonce, tag).decode(encoding)
