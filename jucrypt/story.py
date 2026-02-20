import os
import hashlib
import hmac
import json
from typing import Tuple, List
import struct


class STORY:
    # Parameters
    BLOCK_SIZE = 16 # 16 Block = 128bit 
    KEY_SIZE = 32
    ROUNDS = 12  # converged after 4 
    # Cache Sbox to reduce time, maybe?
    _SBOXES_CACHE: dict = {}

    # Assistants
    @classmethod
    def _validate_sbox(cls, idx: int, sbox: List[int]) -> None:
        """Validate that *sbox* is a proper permutation of 0-255."""
        if len(sbox) != 256:
            raise ValueError(f"S-box {idx}: expected 256 entries, got {len(sbox)}")
        if sorted(sbox) != list(range(256)):
            raise ValueError(
                f"S-box {idx}: not a bijection (not a permutation of 0-255)"
            )

    @classmethod
    def _load_sboxes(cls):
        if cls._SBOXES_CACHE:         
            return cls._SBOXES_CACHE
        path = os.path.join(os.path.dirname(__file__), "customju/sboxes.json")
        try:
            with open(path, "r") as f:
                raw = json.load(f)
            for k, v in raw.items():
                sbox = [(int(x) - 1) % 256 for x in v.split(",")]
                cls._validate_sbox(int(k), sbox)
                cls._SBOXES_CACHE[int(k)] = sbox
            return cls._SBOXES_CACHE
        except FileNotFoundError:
            raise RuntimeError("Requires sboxes.json in customju/ directory")

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
        """Apply the master-key-derived byte permutation to *state* in-place."""
        tmp = state.copy()
        for i in range(16):
            state[i] = tmp[perm[i]]

    # Using AES MDS Logic
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
    # Original STORY Mixing (Uncomment if needed) 
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
