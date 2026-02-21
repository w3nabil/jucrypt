import os
import hashlib
import hmac
import json
from typing import Tuple, List
import struct

# ══════════════════════════════════════════════════════════════
#  GF(2^8) precomputed multiplication table
#  Irreducible polynomial: x^8 + x^4 + x^3 + x + 1  (0x11B)
#  Built once at import time — used by the STORY _mix layer.
# ══════════════════════════════════════════════════════════════

def _build_gf_table() -> List[List[int]]:
    table = [[0] * 256 for _ in range(256)]
    for a in range(256):
        x = a
        for b in range(256):
            p, y = 0, b
            xx = x
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

# ══════════════════════════════════════════════════════════════
#  16×16 Cauchy MDS matrix over GF(2^8)
#  M[i][j] = 1 / (α^i  XOR  α^(j+16))
#  α = 2  (primitive element, same field as AES)
#
#  Branch number : 17  — theoretical maximum for any 16×16 map.
#  Diffusion     : complete across all 16 bytes in 1 application.
#  Invertible    : guaranteed by the Cauchy determinant theorem.
#
#  Derived at import time from first principles so any reviewer
#  can verify by re-running this file.
# ══════════════════════════════════════════════════════════════

def _derive_cauchy_matrices() -> Tuple[List[List[int]], List[List[int]]]:
    # Multiplicative inverse table in GF(2^8)
    gf_inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _GF[a][b] == 1:
                gf_inv[a] = b
                break

    # Powers of α = 2
    def pow_alpha(n: int) -> int:
        a = 1
        for _ in range(n):
            a = _GF[a][2]
        return a

    xs = [pow_alpha(i) for i in range(16)]  # α^0  .. α^15
    ys = [pow_alpha(i + 16) for i in range(16)]  # α^16 .. α^31

    # All x_i distinct, all y_j distinct, disjoint sets → Cauchy invertible
    M = [[gf_inv[xs[i] ^ ys[j]] for j in range(16)] for i in range(16)]

    # Gauss-Jordan inversion over GF(2^8)
    n = 16
    aug = [M[i][:] + [1 if i == j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        piv = next((r for r in range(col, n) if aug[r][col]), -1)
        if piv == -1:
            raise RuntimeError("Cauchy matrix singular — should never happen")
        aug[col], aug[piv] = aug[piv], aug[col]
        pi = gf_inv[aug[col][col]]
        for k in range(2 * n):
            aug[col][k] = _GF[aug[col][k]][pi]
        for r in range(n):
            if r != col and aug[r][col]:
                f = aug[r][col]
                for k in range(2 * n):
                    aug[r][k] ^= _GF[f][aug[col][k]]

    M_inv = [[aug[i][n + j] for j in range(n)] for i in range(n)]
    return M, M_inv

_MIX_M, _MIX_M_INV = _derive_cauchy_matrices()

class STORY:
    # Parameters
    BLOCK_SIZE = 16 # 16 Block = 128bit 
    KEY_SIZE = 32
    ROUNDS = 12  # converged after 4 
    # Cache Sbox to reduce time, maybe?
    _SBOXES_CACHE: dict = {}

    # Assistants
    @classmethod
    def _validate_sbox(cls, idx: int, sbox: list[int]) -> None:
        """Validate that sbox is a proper permutation of 0-255."""
        if len(sbox) != 256:
            raise ValueError(f"S-box {idx}: expected 256 entries, got {len(sbox)}")
        if sorted(sbox) != list(range(256)):
            raise ValueError(
                f"S-box {idx}: not a bijection (not a permutation of 0-255)"
            )

    @classmethod
    def _load_sboxes(cls) -> dict:
        # Return cache immediately if already loaded
        if cls._SBOXES_CACHE:
            return cls._SBOXES_CACHE

        base = os.path.dirname(__file__)  # {diskname}:\{python_rootfolder}\Lib\site-packages\jucrypt
        json_path = os.path.join(base, "customju", "sboxes.json") # ...\jucrypt\customju\sboxes.json is the correct path for external sboxes

        # 1. look for custom json sboxes
        if os.path.isfile(json_path):
            with open(json_path, "r") as f:
                raw = json.load(f)
            for k, v in raw.items():
                sbox = [(int(x) - 1) % 256 for x in v.split(",")]
                cls._validate_sbox(int(k), sbox)
                cls._SBOXES_CACHE[int(k)] = sbox
            return cls._SBOXES_CACHE

        # 2. not found? now use the default
        try:
            from jucrypt.default_sboxes import SBOX_POOL as story_sbox
        except ImportError:
            raise RuntimeError(
                "STORY S-box pool not found.\n"
                "Expected one of:\n"
                "  • customju/sboxes.json     (your custom pool)\n"
                "  • jucrypt/default_sboxes.py  (ships with the package)\n"
                "Re-install the package or place sboxes.json next to story.py."
            )

        for idx, sbox in story_sbox.items():
            cls._validate_sbox(idx, sbox)
            cls._SBOXES_CACHE[idx] = sbox

        return cls._SBOXES_CACHE

    # Byte permutation
    @staticmethod
    def _derive_perm(master: bytes) -> List[int]:
        seed = hashlib.shake_256(b"story_v1_perm||" + master).digest(32)
        perm = list(range(16))
        for i in range(15, 0, -1):
            j = seed[i] % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        return perm

    @staticmethod
    def _derive_inv_perm(master: bytes) -> List[int]:
        perm = STORY._derive_perm(master)
        inv_perm = [0] * 16
        for i, p in enumerate(perm):
            inv_perm[p] = i
        return inv_perm

    # Key derivation
    @staticmethod
    def _derive_master_key(story: str) -> Tuple[bytes, bytes]:
        ikm = hashlib.shake_256(story.encode()).digest(STORY.KEY_SIZE)
        def hkdf_expand(label: bytes, length: int) -> bytes:
            return hmac.new(ikm, label + b"||story_v1_master", hashlib.sha256).digest()[
                :length
            ]
        enc_key = hkdf_expand(b"enc", 32)
        mac_key = hkdf_expand(b"mac", 32)
        return enc_key, mac_key

    @staticmethod
    def _derive_sbox(master: bytes) -> List[int]:
        all_sboxes = STORY._load_sboxes()
        idx_stream = hashlib.shake_256(b"story_v1_sbox||" + master).digest(2)
        idx = struct.unpack(">H", idx_stream)[0] % len(all_sboxes)
        return all_sboxes[idx]

    @staticmethod
    def _expand_round_keys(master: bytes) -> List[bytes]:
        keys = []
        for r in range(STORY.ROUNDS):
            label = b"story_v1_round||" + r.to_bytes(4, "big")
            rk = hmac.new(master, label, hashlib.sha256).digest()[: STORY.BLOCK_SIZE]
            keys.append(rk)
        return keys

    # SPN cipher primitives
    @staticmethod
    def _sub_bytes(state: List[int], sbox: List[int]) -> None:
        for i in range(16):
            state[i] = sbox[state[i]]

    @staticmethod
    def _permute(state: List[int], perm: List[int]) -> None:
        tmp = state.copy()
        for i in range(16):
            state[i] = tmp[perm[i]]

    @staticmethod
    def _mix(state: list[int]) -> None:
        """
        STORY Novel Full-State MDS Mix over GF(2^8).

        Replaces the AES column mix as the primary diffusion layer.

        Matrix : M[i][j] = 1 / (α^i  XOR  α^(j+16))  in GF(2^8), α = 2
        Branch number  : 17  — maximum possible for any 16×16 linear map.
        Full diffusion : every output byte depends on all 16 input bytes
                         in a single application.
        Invertible     : proved by the Cauchy determinant theorem.

        GF(2^8) addition is XOR
        """
        result = []
        for i in range(16):
            acc = 0
            for j in range(16):
                acc ^= _GF[_MIX_M[i][j]][state[j]]
            result.append(acc)
        # Write result back into state in-place (matches original _mix signature)
        for i in range(16):
            state[i] = result[i]

    @staticmethod
    def _mix_inv(state: list[int]) -> None:
        """Inverse of _mix — applied during decryption."""
        result = []
        for i in range(16):
            acc = 0
            for j in range(16):
                acc ^= _GF[_MIX_M_INV[i][j]][state[j]]
            result.append(acc)
        for i in range(16):
            state[i] = result[i]

    """
    # AES MDS Logic (Uncomment if needed) , Branch 4
    @staticmethod
    def _gf_mul(a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B 
            b >>= 1
        return p

    @staticmethod
    def _mix_column(col: list[int]) -> list[int]:
        a, b, c, d = col
        return [
            STORY._gf_mul(2, a) ^ STORY._gf_mul(3, b) ^ c ^ d,
            a ^ STORY._gf_mul(2, b) ^ STORY._gf_mul(3, c) ^ d,
            a ^ b ^ STORY._gf_mul(2, c) ^ STORY._gf_mul(3, d),
            STORY._gf_mul(3, a) ^ b ^ c ^ STORY._gf_mul(2, d),
        ]

    @staticmethod
    def _mix(state: list[int]) -> None:
        for col in range(4): 
            i = col * 4
            mixed = STORY._mix_column(state[i : i + 4])
            state[i : i + 4] = mixed
    """
    """ 
    # Draft STORY XOR Mixing (Uncomment if needed) , Branch 5
    @staticmethod 
    def _mix(state: List[int]) -> None: 
        tmp = state.copy() 
        for i in range(16): 
            state[i] ^= tmp[(i + 1) % 16] ^ tmp[(i + 4) % 16]
    """
    @staticmethod
    def _encrypt_block(
        block: bytes, master: bytes, sbox: List[int], round_keys: List[bytes] = None
    ) -> bytes:
        if round_keys is None:
            round_keys = STORY._expand_round_keys(master)
        perm = STORY._derive_perm(master)
        state = list(block)
        for r in range(STORY.ROUNDS):
            for i in range(16):
                state[i] ^= round_keys[r][i]
            STORY._sub_bytes(state, sbox)
            STORY._permute(state, perm) 
            STORY._mix(state)
        return bytes(state)

    #  CTR
    @staticmethod
    def _make_counter_block(nonce: bytes, counter: int) -> bytes:
        """Combine 8-byte nonce prefix with 8-byte counter → 16-byte block."""
        return nonce + counter.to_bytes(8, "big")

    # Encrypt
    @staticmethod
    def encrypt(plaintext: bytes, story: str) -> Tuple[bytes, bytes, bytes]:
        enc_key, mac_key = STORY._derive_master_key(story)
        sbox = STORY._derive_sbox(enc_key)
        round_keys = STORY._expand_round_keys(enc_key) 
        nonce = os.urandom(8)
        ciphertext = bytearray()
        counter = 0
        for i in range(0, len(plaintext), 16):
            block = plaintext[i : i + 16]
            keystream = STORY._encrypt_block(
                STORY._make_counter_block(nonce, counter),
                enc_key,
                sbox,
                round_keys,
            )
            ciphertext.extend(b ^ k for b, k in zip(block, keystream))
            counter += 1
        tag = hmac.new(mac_key, nonce + bytes(ciphertext), hashlib.sha256).digest()
        return bytes(ciphertext), nonce, tag

    # Decrypt
    @staticmethod
    def decrypt(ciphertext: bytes, story: str, nonce: bytes, tag: bytes) -> bytes:
        enc_key, mac_key = STORY._derive_master_key(story)
        sbox = STORY._derive_sbox(enc_key)
        round_keys = STORY._expand_round_keys(enc_key) 
        check = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(check, tag):
            raise ValueError("Ju decided to not share the secrets! Because the story was not interesting")
        plaintext = bytearray()
        counter = 0

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i : i + 16]
            keystream = STORY._encrypt_block(
                STORY._make_counter_block(nonce, counter),
                enc_key,
                sbox,
                round_keys,
            )
            plaintext.extend(b ^ k for b, k in zip(block, keystream))
            counter += 1

        return bytes(plaintext)
