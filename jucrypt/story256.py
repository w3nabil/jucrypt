from __future__ import annotations

import os
import json
import hmac
import hashlib
import warnings
import unicodedata
from typing import List, NamedTuple, Union


# ── GF(2^8) arithmetic ────────────────────────────────────────────────────────

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


# ── 16x16 Cauchy MDS matrix ───────────────────────────────────────────────────

def _derive_cauchy_matrix() -> List[List[int]]:
    gf_inv = [0] * 256
    for a in range(1, 256):
        result, base, exp = 1, a, 254
        while exp > 0:
            if exp & 1:
                result = _GF[result][base]
            base = _GF[base][base]
            exp >>= 1
        gf_inv[a] = result

    def pow_g(n: int) -> int:
        """
        Compute g^n in GF(2^8) where g=3 is a primitive element of order 255.

        FIX-11: The original code used alpha=2 (pow_alpha), which has order 51
        in GF(2^8) with the AES polynomial (x^8+x^4+x^3+x+1).  With only 51
        distinct powers, the 32+32=64 xs/ys sets inevitably collide, making
        the Cauchy matrix singular and causing a RuntimeError at module load.
        g=3 has order 255 (primitive root), so g^0..g^31 and g^32..g^63 are
        64 distinct non-zero elements — the xs/ys disjointness condition is
        satisfied and the matrix is guaranteed non-singular.
        """
        a = 1
        for _ in range(n % 255):
            a = _GF[a][3]
        return a

    mat_block: int = 32
    xs = [pow_g(i)            for i in range(mat_block)]
    ys = [pow_g(i + mat_block) for i in range(mat_block)]
    M  = [[gf_inv[xs[i] ^ ys[j]] for j in range(mat_block)] for i in range(mat_block)]

    n   = mat_block
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


_MIX_M = _derive_cauchy_matrix()


# ── BLAKE2b domain separation constants ───────────────────────────────────────

_P_ENC_KEY   = b'story_enc_key   '   # master enc key derivation
_P_MAC_KEY   = b'story_mac_key   '   # master mac key derivation
_P_MAC_TAG   = b'story_mac_tag   '   # MAC tag computation  (FIX-04: new label)
_P_SBOX      = b'story_sbox_sel  '   # S-box selection stream
_P_PERM      = b'story_permute   '   # permutation stream
_P_ROUND_KEY = b'story_round_key '   # round keys
_P_FINAL_KEY = b'story_final_key '   # whitening key

_KDF_ITERATIONS = 200_000
_KDF_DKLEN      = 32


def _b2(
    data:        bytes,
    person:      bytes,
    *,
    key:         bytes = b'',
    salt:        bytes = b'',
    digest_size: int   = 32,
) -> bytes:
    """
    Thin wrapper around hashlib.blake2b.

    person and salt are zero-padded/truncated to exactly 16 bytes.
    key may be empty (unkeyed) or up to 64 bytes.
    """
    return hashlib.blake2b(
        data,
        key         = key or b'',
        person      = person.ljust(16, b'\x00')[:16],   # exactly 16 bytes
        salt        = salt.ljust(16,   b'\x00')[:16],   # exactly 16 bytes
        digest_size = digest_size,
    ).digest()


def _stretch_story(story_bytes: bytes, kdf_salt: bytes) -> bytes:
    """
    Harden a potentially low-entropy story string via PBKDF2-HMAC-SHA256.

    Returns a 32-byte stretched key used as the BLAKE2b 'key' for all
    subsequent derivations.  The kdf_salt must be stored/transmitted
    with the ciphertext and passed to decrypt() unchanged.  (FIX-06)
    """
    return hashlib.pbkdf2_hmac(
        hash_name   = 'sha256',
        password    = story_bytes,
        salt        = kdf_salt,
        iterations  = _KDF_ITERATIONS,
        dklen       = _KDF_DKLEN,
    )


# ── S-box pool loader ─────────────────────────────────────────────────────────

_SBOXES_CACHE: dict = {}


def _validate_sbox(idx: int, sbox: list) -> None:
    if len(sbox) != 256:
        raise ValueError(f"S-box {idx}: expected 256 entries, got {len(sbox)}")
    if sorted(sbox) != list(range(256)):
        raise ValueError(f"S-box {idx}: not a bijection (not a permutation of 0-255)")


def _load_sboxes() -> dict:
    """
    Load the S-box pool from disk or the default package.

    The JSON format stores values offset by +1 (1-indexed).  The loader
    subtracts 1 and applies mod-256 to recover the canonical 0-255 range.
    This transform is intentional and matches the pool generator.  (FIX-07)
    """
    global _SBOXES_CACHE
    if _SBOXES_CACHE:
        return _SBOXES_CACHE

    base      = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base, "customju", "sboxes.json")

    if os.path.isfile(json_path):
        warnings.warn(
            "Loading S-box pool from customju/sboxes.json — "
            "values are stored 1-indexed; loader applies (x-1) mod 256. "
            "Ensure the pool was generated with the matching +1 offset.",
            UserWarning,
            stacklevel=3,
        )
        with open(json_path, "r") as f:
            raw = json.load(f)
        for k, v in raw.items():
            sbox = [(int(x) - 1) % 256 for x in v.split(",")]
            _validate_sbox(int(k), sbox)
            _SBOXES_CACHE[int(k)] = sbox
        return _SBOXES_CACHE

    try:
        from jucrypt.default_sboxes import SBOX_POOL
    except ImportError:
        raise RuntimeError(
            "STORY S-box pool not found.\n"
            "Expected one of:\n"
            "  -> customju/sboxes.json   (custom pool)\n"
            "  -> jucrypt/default_sboxes  (ships with the package)\n"
        )

    for idx, sbox in SBOX_POOL.items():
        _validate_sbox(idx, sbox)
        _SBOXES_CACHE[idx] = sbox

    return _SBOXES_CACHE


# ── Key schedule ──────────────────────────────────────────────────────────────

class _STORY256Keys:
    """
    STORY-Raw v1.1.0 key schedule.  Independently importable and testable.

    Usage
    -----
        pool = _load_sboxes()                            # load once externally
        ks   = _STORY256Keys("Once upon a time...", pool, kdf_salt)
        enc_key    = ks.enc_key        # bytes(32)
        mac_key    = ks.mac_key        # bytes(32)
        sbox       = ks.sbox           # List[int] length 256
        perm       = ks.perm           # List[int] length 32
        round_keys = ks.round_keys     # List[bytes(32)] length ROUNDS
        final_key  = ks.final_key      # bytes(32)
    """

    ROUNDS: int = 5  

    def __init__(self, story: str, sbox_pool: dict, kdf_salt: bytes) -> None:
        story_norm  = unicodedata.normalize("NFC", story)
        story_bytes = story_norm.encode("utf-16-le")
        stretched = _stretch_story(story_bytes, kdf_salt)

        # Step 1: derive master keys (keyed BLAKE2b, data=b'').
        # Using stretched key as BLAKE2b 'key'; person provides domain separation.
        # Two distinct person labels give two independent 32-byte keys.
        self.enc_key: bytes = _b2(b'', _P_ENC_KEY, key=stretched, digest_size=32)
        self.mac_key: bytes = _b2(b'', _P_MAC_KEY, key=stretched, digest_size=32)

        # Step 2: derive cipher parameters from enc_key.
        self.sbox:       List[int]   = self._derive_sbox(sbox_pool)
        self.perm:       List[int]   = self._derive_perm()
        self.round_keys: List[bytes] = self._derive_round_keys()
        self.final_key:  bytes       = _b2(
            b'', _P_FINAL_KEY, key=self.enc_key, digest_size=32
        )

    # ── Sbox derivation ──────────────────────────────────────────────────────

    def _derive_sbox(self, pool: dict) -> List[int]:
        """
        Select one S-box from the pool deterministically via rejection sampling.

        Stream: BLAKE2b(data=b'', key=enc_key, person=_P_SBOX, digest_size=64).
        Extended by hashing with an incrementing counter if exhausted.
        """
        pool_size = len(pool)
        threshold = 65536 - (65536 % pool_size)

        stream = bytearray(_b2(b'', _P_SBOX, key=self.enc_key, digest_size=64))
        pos    = 0
        ext    = 0

        while True:
            if pos + 1 >= len(stream):
                ext   += 1
                stream = bytearray(_b2(
                    ext.to_bytes(4, 'big'), _P_SBOX,
                    key=self.enc_key, digest_size=64,
                ))
                pos = 0
            val = (stream[pos] << 8) | stream[pos + 1]
            pos += 2
            if val < threshold:
                return pool[val % pool_size]

    # ── Permutation derivation ───────────────────────────────────────────────

    def _derive_perm(self) -> List[int]:
        """
        Key-dependent Fisher-Yates shuffle for the 32-position permutation.

        Stream: BLAKE2b(data=b'', key=enc_key, person=_P_PERM, digest_size=64).
        Rejection sampling eliminates modular bias.
        """
        stream = bytearray(_b2(b'', _P_PERM, key=self.enc_key, digest_size=64))
        pos    = 0
        ext    = 0
        perm   = list(range(32))

        for i in range(31, 0, -1):
            limit     = i + 1
            threshold = 256 - (256 % limit)
            while True:
                if pos >= len(stream):
                    ext   += 1
                    stream = bytearray(_b2(
                        ext.to_bytes(4, 'big'), _P_PERM,
                        key=self.enc_key, digest_size=64,
                    ))
                    pos = 0
                b = stream[pos]; pos += 1
                if b < threshold:
                    j = b % limit
                    perm[i], perm[j] = perm[j], perm[i]
                    break
        return perm

    # ── Round key expansion ──────────────────────────────────────────────────

    def _derive_round_keys(self) -> List[bytes]:
        """
        Derive ROUNDS=5 independent 32-byte round keys.

        Each key uses:
          BLAKE2b(data=b'', key=enc_key, person=_P_ROUND_KEY,
                  salt=r.to_bytes(16,'big'), digest_size=32)
        """
        return [
            _b2(
                b'', _P_ROUND_KEY,
                key         = self.enc_key,
                salt        = r.to_bytes(16, 'big'),   
                digest_size = 32,
            )
            for r in range(self.ROUNDS)
        ]


# ── Wire format ───────────────────────────────────────────────────────────────

class EncryptResult(NamedTuple):
    """
    Named tuple returned by STORY256.encrypt().

    Fields
    ------
    ciphertext  : bytes       -- encrypted payload
    nonce       : bytes(16)   -- CTR nonce  (FIX-09: 16 bytes, not 8)
    tag         : bytes(32)   -- BLAKE2b authentication tag
    round_salt  : int         -- 4-byte big-endian (Change 3 from v0.3.0)
    kdf_salt    : bytes(16)   -- PBKDF2 salt for key stretching  (FIX-06)
    """
    ciphertext: bytes
    nonce:      bytes
    tag:        bytes
    round_salt: int
    kdf_salt:   bytes


# ── Main cipher class ─────────────────────────────────────────────────────────

class STORY256:
    """
    STORY256 cipher v0.3.2

    Public API
    ----------
    result = STORY256.encrypt(plaintext, story)
        -> EncryptResult(ciphertext, nonce, tag, round_salt, kdf_salt)

    pt     = STORY256.decrypt(ciphertext, story, nonce, tag,
                               round_salt, kdf_salt)

    pt_str = STORY256.decrypt_str(ciphertext, story, nonce, tag,
                                   round_salt, kdf_salt)

    Parameters
    ----------
    plaintext  : str | bytes | bytearray
    story      : str          -- narrative passphrase
    use_salt   : bool         -- True = random round_salt (default),
                                 False = zero salt for deterministic testing.

    """

    BLOCK_SIZE = 32
    KEY_SIZE   = 32
    ROUNDS     = _STORY256Keys.ROUNDS   # 6

    # ── SPN block cipher ─────────────────────────────────────────────────────

    @staticmethod
    def _encrypt_block(
        block:      bytes,
        perm:       List[int],
        sbox:       List[int],
        round_keys: List[bytes],
        final_key:  bytes,
    ) -> bytes:
        """
        Encrypt one 32-byte block through the SPN:
          (ARK -> SubBytes -> Permute -> MDS) × ROUNDS, then final ARK.

        All inputs are 32-byte aligned.  round_keys contains ROUNDS entries.
        final_key is bytes(32).
        """
        state = list(block)
        for rk in round_keys:
            # AddRoundKey
            for i in range(32):
                state[i] ^= rk[i]
            # SubBytes
            for i in range(32):
                state[i] = sbox[state[i]]
            # Permute
            tmp = state[:]
            for i in range(32):
                state[i] = tmp[perm[i]]
            # MDS Mix (32×32 over GF(2^8))
            result = [0] * 32
            for i in range(32):
                acc = 0
                row = _MIX_M[i]
                for j in range(32):
                    acc ^= _GF[row[j]][state[j]]
                result[i] = acc
            state = result

        # Final whitening
        for i in range(32):
            state[i] ^= final_key[i]
        return bytes(state)

    # ── Input helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _to_bytes(data) -> bytes:
        if isinstance(data, bytes):     return data
        if isinstance(data, bytearray): return bytes(data)
        if isinstance(data, str):       return data.encode("utf-16-le")
        raise TypeError(
            f"Plaintext must be str, bytes, or bytearray. Got: {type(data).__name__}"
        )

    @staticmethod
    def _salt_to_bytes(salt) -> bytes:
        """Accept round_salt as int, bytes, or bytearray; return bytes(4)."""
        if isinstance(salt, int):
            return salt.to_bytes(4, 'big')
        if isinstance(salt, (bytes, bytearray)):
            if len(salt) != 4:
                raise ValueError(f"round_salt must be 4 bytes, got {len(salt)}")
            return bytes(salt)
        raise TypeError(f"round_salt must be int or bytes. Got: {type(salt).__name__}")

    @staticmethod
    def _to_bytes_param(data, name: str) -> bytes:
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        if isinstance(data, str):
            try:   return bytes.fromhex(data)
            except ValueError:
                raise ValueError(f"'{name}' hex string is malformed: {data!r}")
        raise TypeError(
            f"'{name}' must be bytes or hex string. Got: {type(data).__name__}"
        )

    # ── Public API ────────────────────────────────────────────────────────────

    @staticmethod
    def encrypt(
        plaintext,
        story:    str,
        use_salt: bool = False,
    ) -> EncryptResult:
        """
        Encrypt *plaintext* under *story*.

        Parameters
        ----------
        plaintext : str | bytes | bytearray
        story     : str
        use_salt  : bool
            True  (default) — random 4-byte round_salt.
            False           — zero salt; deterministic output for testing.

        Returns
        -------
        EncryptResult with fields:
            ciphertext : bytes
            nonce      : bytes(16)   FIX-09: 16 bytes (was documented as 8)
            tag        : bytes(32)   BLAKE2b-MAC over nonce||round_salt||kdf_salt||ct
            round_salt : int         4-byte big-endian unsigned integer
            kdf_salt   : bytes(16)   PBKDF2 salt  (FIX-06: new field)
        """
        pt_bytes = STORY256._to_bytes(plaintext)

        # FIX-06: generate PBKDF2 salt for key stretching
        kdf_salt = os.urandom(16)

        # Load sbox pool externally and pass to key schedule (FIX-10)
        pool = _load_sboxes()
        ks   = _STORY256Keys(story, pool, kdf_salt)

        # Change 3: 4-byte random round salt returned as int
        round_salt_bytes = os.urandom(4) if use_salt else b'\x00\x00\x00\x00'
        round_salt_int   = int.from_bytes(round_salt_bytes, 'big')

        # CTR encryption — nonce is 16 bytes (FIX-09)
        nonce      = os.urandom(16)
        ciphertext = bytearray()
        counter    = 0

        for i in range(0, len(pt_bytes), STORY256.BLOCK_SIZE):
            block     = pt_bytes[i : i + STORY256.BLOCK_SIZE]
            counter_b = nonce + counter.to_bytes(16, 'big')
            keystream = STORY256._encrypt_block(
                counter_b, ks.perm, ks.sbox, ks.round_keys, ks.final_key,
            )
            ciphertext.extend(b ^ k for b, k in zip(block, keystream))
            counter += 1

        ct = bytes(ciphertext)

        # FIX-04: use dedicated _P_MAC_TAG label (not _P_MAC_KEY) for the tag.
        # FIX-06: kdf_salt included in MAC scope to prevent substitution attacks.
        # Covers: nonce || round_salt || kdf_salt || ciphertext
        tag = _b2(
            nonce + round_salt_bytes + kdf_salt + ct,
            _P_MAC_TAG,
            key         = ks.mac_key,
            digest_size = 32,
        )

        return EncryptResult(ct, nonce, tag, round_salt_int, kdf_salt)

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
        Verify authentication tag and decrypt *ciphertext*.

        Parameters
        ----------
        ciphertext : bytes | hex str
        story      : str
        nonce      : bytes(16) | hex str   FIX-09: must be exactly 16 bytes
        tag        : bytes(32) | hex str
        round_salt : int | bytes(4)
        kdf_salt   : bytes(16) | hex str   FIX-06: required for key stretching

        Raises
        ------
        ValueError  on authentication failure or malformed inputs.
        """
        ct_bytes         = STORY256._to_bytes_param(ciphertext, "ciphertext")
        nc_bytes         = STORY256._to_bytes_param(nonce,      "nonce")
        tag_bytes        = STORY256._to_bytes_param(tag,        "tag")
        round_salt_bytes = STORY256._salt_to_bytes(round_salt)
        kdf_salt_bytes   = STORY256._to_bytes_param(kdf_salt,   "kdf_salt")

        # FIX-01: enforce nonce length
        if len(nc_bytes) != 16:
            raise ValueError(
                f"nonce must be exactly 16 bytes, got {len(nc_bytes)}. "
            )

        # FIX-10: load pool externally; pass to key schedule
        pool = _load_sboxes()
        ks   = _STORY256Keys(story, pool, kdf_salt_bytes)

        # FIX-05: constant-time tag verification via hmac.compare_digest()
        check = _b2(
            nc_bytes + round_salt_bytes + kdf_salt_bytes + ct_bytes,
            _P_MAC_TAG,
            key         = ks.mac_key,
            digest_size = 32,
        )
        if not hmac.compare_digest(check, tag_bytes):
            raise ValueError(
                "Authentication failed.\n"
                "The ciphertext, nonce, tag, round_salt, or kdf_salt has been "
                "tampered with, or the story passphrase is incorrect."
            )

        # CTR decryption (XOR is symmetric)
        plaintext = bytearray()
        counter   = 0

        for i in range(0, len(ct_bytes), STORY256.BLOCK_SIZE):
            block     = ct_bytes[i : i + STORY256.BLOCK_SIZE]
            counter_b = nc_bytes + counter.to_bytes(16, 'big')
            keystream = STORY256._encrypt_block(
                counter_b, ks.perm, ks.sbox, ks.round_keys, ks.final_key,
            )
            plaintext.extend(b ^ k for b, k in zip(block, keystream))
            counter += 1

        return bytes(plaintext)

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
        """Decrypt and decode to string (default UTF-16-LE, matching encrypt)."""
        return STORY256.decrypt(
            ciphertext, story, nonce, tag, round_salt, kdf_salt,
        ).decode(encoding)