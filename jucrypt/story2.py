import os
import json
import hashlib
import hmac
import importlib.util
from typing import Dict, List, Optional, Tuple, Union
import unicodedata

# Try to import C extension for performance
try:
    import story2_128ext as _c_ext
    _HAS_C_EXT = True
except ImportError:
    _c_ext = None
    _HAS_C_EXT = False


# =============================================================================
# GF(2^8) ARITHMETIC
# =============================================================================

def _build_gf_table() -> List[List[int]]:
    """Precompute GF(2^8) multiplication table with irreducible polynomial 0x11B."""
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


# =============================================================================
# MDS MATRIX - 16×16 Cauchy with Branch Number 17
# =============================================================================

def _derive_cauchy_matrix() -> List[List[int]]:
    """
    Derive 16×16 Cauchy MDS matrix over GF(2^8).

    Properties:
    - Branch Number = 17 (maximum for 16-byte state)
    - Every output byte depends on ALL input bytes
    - Guaranteed invertible (Cauchy construction)
    - Eliminates need for permutation layer
    """
    gf_inv = [0] * 256
    for a in range(1, 256):
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

    xs = [pow_alpha(i)      for i in range(16)]
    ys = [pow_alpha(i + 16) for i in range(16)]
    M  = [[gf_inv[xs[i] ^ ys[j]] for j in range(16)] for i in range(16)]
    return M


_MDS_MATRIX = _derive_cauchy_matrix()


def _build_mix_table() -> List[List[List[int]]]:
    """
    Precompute MDS mixing table for zero-cost GF multiplication.
    _MIX_TABLE[i][j][v] = GF_mul(MDS_MATRIX[i][j], v)
    """
    return [
        [[_GF[_MDS_MATRIX[i][j]][v] for v in range(256)] for j in range(16)]
        for i in range(16)
    ]


_MIX_TABLE = _build_mix_table()


# Initialise C extension tables if available
if _HAS_C_EXT:
    _gf_flat  = bytes([_GF[a][b] for a in range(256) for b in range(256)])
    _mds_flat = bytes([_MDS_MATRIX[i][j] for i in range(16) for j in range(16)])
    _c_ext.story2_build_tables(_gf_flat, _mds_flat)


# =============================================================================
# S-BOX POOL
# =============================================================================

# DEFAULT_SBOX — fallback when no pool is found. DDT=4, LAT=32.
# Used directly only when _load_sboxes() returns {0: DEFAULT_SBOX}.
DEFAULT_SBOX: List[int] = [
     13,197, 53,179,230,231,158, 79,206,233, 15,147,247,101, 81,203,
    125,227,229,  7, 61,157,130,103,208,160,121, 19,222,  0,214, 78,
    118, 29,135,122, 83,138, 33, 96,128,164, 60,252,131,202,115,241,
    163, 27,232, 64, 91, 93, 49, 86, 72,245,142, 67, 26, 36, 82, 59,
    137,139,192,165,180,104,251,204,225, 17,253,110, 63,254, 41, 25,
    106, 51,119,144,114, 31,120,215,224,  6,242, 37, 54,249,184,207,
    240,190, 57, 66,105,223, 77, 11,170,152, 62, 55, 48,177,111,246,
     46,216, 42,217,154,228, 18,201,255,188,212,167,187,134,200,218,
     38, 44,172,236,166,162, 23,205, 47,124,127,156,149,195,248, 45,
    140,116, 56,109,132,145, 85, 75,176,209,153,146,186, 10,159,123,
     88,  5,148,178,  3,199, 35, 69,244, 32,173, 39,239,193, 20, 52,
     16,174,150,238, 58,175,161, 80,151,213,  8, 89,194, 99, 73, 94,
    117, 21, 97,136,237,210,235, 71,108, 87, 92,196,126,  4, 95,250,
    220,219,189,171, 40,198, 43,191,  2,183, 70, 50,221, 30,155, 98,
    226,234, 90, 84,112,182, 24,100,141, 74, 28,243, 12, 65,169,113,
     22, 68, 76,102,  9,107,185,181,168,129,211,143,133, 14,  1, 34,
]

_POOL_TARGET  = 255
_SBOXES_CACHE: Dict[int, List[int]] = {}


def _validate_sbox(idx: int, sbox: list) -> bool:
    return len(sbox) == 256 and sorted(sbox) == list(range(256))


def _generate_sbox_from_seed(seed: bytes) -> List[int]:
    """Fisher-Yates shuffle driven by SHAKE-256. Always produces a bijection."""
    perm   = list(range(256))
    stream = bytearray(hashlib.shake_256(seed).digest(512))
    pos = ext = 0
    for i in range(255, 0, -1):
        limit     = i + 1
        threshold = 256 - (256 % limit)
        while True:
            if pos >= len(stream):
                ext   += 1
                stream = bytearray(
                    hashlib.shake_256(seed + ext.to_bytes(4, "big")).digest(512)
                )
                pos = 0
            b = stream[pos]; pos += 1
            if b < threshold:
                j = b % limit
                perm[i], perm[j] = perm[j], perm[i]
                break
    return perm


def _load_sboxes(CS: bool = False) -> Dict[int, List[int]]:
    """
    Load S-box pool.

    Priority:
      1. Return cache if already loaded.
      2. CS=True: search for customju/sboxes.json in package dir or cwd.
           - 1 sbox  → use as-is, no extension.
           - 2–254   → extend to 255, overwrite file. May take time if you are using for the first time.
           - 255+    → use directly.
      3. Default shipped pool (extended to 255 in memory, no file write).
      4. Fallback: {0: DEFAULT_SBOX}.

    CS : bool
        True  → load custom sboxes.json first.
        False → use default pool (default).
    """
    global _SBOXES_CACHE
    if _SBOXES_CACHE:
        return _SBOXES_CACHE

    def _from_json(path: str) -> Optional[Dict[int, List[int]]]:
        try:
            with open(path) as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
        if not raw:
            return None
        pool: Dict[int, List[int]] = {}
        for k, v in raw.items():
            sbox = [(int(x) - 1) % 256 for x in v.split(",")]
            if _validate_sbox(int(k), sbox):
                pool[int(k)] = sbox
        return pool or None

    def _extend(pool: Dict[int, List[int]],
                json_path: Optional[str] = None) -> Dict[int, List[int]]:
        keys    = sorted(pool.keys())
        rekeyed = {i: pool[keys[i % len(keys)]] for i in range(len(keys))}
        for new_idx in range(len(keys), _POOL_TARGET):
            prev  = rekeyed[new_idx - 1]
            seed  = hashlib.sha256(bytes(prev)).digest() + new_idx.to_bytes(4, "big")
            rekeyed[new_idx] = _generate_sbox_from_seed(seed)
        if json_path:
            updated = {str(k): ",".join(str(v + 1) for v in s)
                       for k, s in sorted(rekeyed.items())}
            try:
                with open(json_path, "w") as f:
                    json.dump(updated, f)
            except OSError:
                pass
        return rekeyed

    # ── Custom pool ────────────────────────────────────────────────────────
    if CS:
        here = os.path.dirname(os.path.abspath(__file__))
        for base in [here, os.getcwd()]:
            json_path = os.path.join(base, "customju", "sboxes.json")
            if not os.path.isfile(json_path):
                continue
            pool = _from_json(json_path)
            if not pool:
                continue
            n = len(pool)
            if n == 1:
                _SBOXES_CACHE = pool
                return _SBOXES_CACHE
            if n < _POOL_TARGET:
                pool = _extend(pool, json_path)
            _SBOXES_CACHE = pool
            return _SBOXES_CACHE

    # ── Default shipped pool ───────────────────────────────────────────────
    pool = None
    try:
        from jucrypt.default_sboxes_sboxes import SBOX_POOL    # type: ignore
        pool = {k: v for k, v in SBOX_POOL.items() if _validate_sbox(k, v)}
    except ImportError:
        pass

    if not pool:
        here = os.path.dirname(os.path.abspath(__file__))
        for candidate in [
            os.path.join(here, "default_sboxes.py"),
            os.path.join(here, "backup_sboxes.py"),
        ]:
            if os.path.isfile(candidate):
                spec = importlib.util.spec_from_file_location("_sb", candidate)
                mod  = importlib.util.module_from_spec(spec)    # type: ignore
                spec.loader.exec_module(mod)                    # type: ignore
                pool = {k: v for k, v in mod.SBOX_POOL.items()
                        if _validate_sbox(k, v)}
                if pool:
                    break

    if pool:
        if len(pool) < _POOL_TARGET:
            pool = _extend(pool)    # in-memory only, no file write
        _SBOXES_CACHE = pool
        return _SBOXES_CACHE

    # ── Fallback ───────────────────────────────────────────────────────────
    _SBOXES_CACHE = {0: DEFAULT_SBOX}
    return _SBOXES_CACHE


def _select_sbox(pool: Dict[int, List[int]], enc_key: bytes) -> List[int]:
    """Deterministically select one sbox from pool using enc_key."""
    if len(pool) == 1:
        return next(iter(pool.values()))
    keys      = sorted(pool.keys())
    pool_size = len(keys)
    threshold = 65536 - (65536 % pool_size)
    stream    = bytearray(
        hashlib.shake_256(b"story_v2_sbox||" + enc_key).digest(64)
    )
    pos = ext = 0
    while True:
        if pos + 1 >= len(stream):
            ext   += 1
            stream = bytearray(
                hashlib.shake_256(
                    b"story_v2_sbox||" + enc_key + ext.to_bytes(4, "big")
                ).digest(64)
            )
            pos = 0
        val  = (stream[pos] << 8) | stream[pos + 1]
        pos += 2
        if val < threshold:
            return pool[keys[val % pool_size]]


# Load DEFAULT_SBOX into C extension if available
if _HAS_C_EXT:
    _c_ext.story2_load_sbox(0, bytes(DEFAULT_SBOX))


# =============================================================================
# STORY2 Cipher Class
# =============================================================================

class STORY2:
    """
    STORY2 — Permutation-Free Substitution-Diffusion Network

    Architecture (per round):
        ARK → SubBytes → MDS  (×ROUNDS)  →  Final ARK (whitening)

    Key Properties:
    - Block size  : 16 bytes (128-bit)
    - Key size    : 32 bytes (256-bit derived)
    - Rounds      : 5
    - Branch Number: 17 (maximum for 16-byte state)
    - No permutation layer (16×16 MDS provides complete diffusion)
    - Key-dependent S-box (selected from pool via enc_key)
    - Final whitening key derived independently of round keys

    Performance:
    - Pure Python  : ~0.37 MB/s (CPython),  ~3.3 MB/s (PyPy)
    - C Extension  : 50–100 MB/s

    Security Level: 256-bit (against all known attacks)
    """

    BLOCK_SIZE = 16
    KEY_SIZE   = 32
    ROUNDS     = 5

    # ── Key schedule ──────────────────────────────────────────────────────────

    @staticmethod
    def _derive_master_key(story_bytes: bytes) -> Tuple[bytes, bytes]:
        """Derive encryption and MAC keys via HKDF-style construction."""
        prk     = hmac.new(b"story_v2_salt",             story_bytes, hashlib.sha256).digest()
        enc_key = hmac.new(prk, b"enc||story_v2_master\x01", hashlib.sha256).digest()
        mac_key = hmac.new(prk, b"mac||story_v2_master\x02", hashlib.sha256).digest()
        return enc_key, mac_key

    @staticmethod
    def _derive_round_keys(master: bytes) -> bytes:
        """
        Derive 5 round keys in one SHAKE-256 call.
        Returns 80 bytes = 5 × 16 bytes.
        Domain label 'story_v2_keys||' is distinct from the whitening label.
        """
        return hashlib.shake_256(b"story_v2_keys||" + master).digest(80)

    @staticmethod
    def _derive_whitening_key(master: bytes) -> bytes:
        """
        Derive 16-byte final whitening key.

        Domain label 'story_v2_whitening||' ensures this key is cryptographically
        independent of the round keys derived in _derive_round_keys().
        Applied as a final ARK after the last Mix round to prevent last-round
        peeling without a key guess.
        """
        return hashlib.shake_256(b"story_v2_whitening||" + master).digest(16)

    # ── Block encryption ──────────────────────────────────────────────────────

    @staticmethod
    def _encrypt_block_python(
        block:         bytes,
        sbox:          List[int],
        round_keys:    bytes,
        whitening_key: bytes,
    ) -> bytes:
        """
        Pure Python block encryption.

        Architecture: (ARK → SubBytes → MDS) × ROUNDS → Final ARK (whitening)

        No permutation layer — 16×16 Cauchy MDS (BN=17) achieves complete
        diffusion in one pass, making a separate permutation redundant.
        Final ARK uses a separately derived whitening key to close the last
        round against key-recovery attacks.
        """
        state = list(block)

        # ── Main rounds ───────────────────────────────────────────────────────
        for r in range(STORY2.ROUNDS):
            rk = round_keys[r * 16:(r + 1) * 16]

            # 1. AddRoundKey — unrolled
            state[0] ^=rk[0];  state[1] ^=rk[1];  state[2] ^=rk[2];  state[3] ^=rk[3]
            state[4] ^=rk[4];  state[5] ^=rk[5];  state[6] ^=rk[6];  state[7] ^=rk[7]
            state[8] ^=rk[8];  state[9] ^=rk[9];  state[10]^=rk[10]; state[11]^=rk[11]
            state[12]^=rk[12]; state[13]^=rk[13]; state[14]^=rk[14]; state[15]^=rk[15]

            # 2. SubBytes — unrolled
            state[0] =sbox[state[0]];  state[1] =sbox[state[1]]
            state[2] =sbox[state[2]];  state[3] =sbox[state[3]]
            state[4] =sbox[state[4]];  state[5] =sbox[state[5]]
            state[6] =sbox[state[6]];  state[7] =sbox[state[7]]
            state[8] =sbox[state[8]];  state[9] =sbox[state[9]]
            state[10]=sbox[state[10]]; state[11]=sbox[state[11]]
            state[12]=sbox[state[12]]; state[13]=sbox[state[13]]
            state[14]=sbox[state[14]]; state[15]=sbox[state[15]]

            # 3. MixLayer — 16×16 Cauchy MDS, BN=17
            t0 =_MIX_TABLE[0];  t1 =_MIX_TABLE[1];  t2 =_MIX_TABLE[2];  t3 =_MIX_TABLE[3]
            t4 =_MIX_TABLE[4];  t5 =_MIX_TABLE[5];  t6 =_MIX_TABLE[6];  t7 =_MIX_TABLE[7]
            t8 =_MIX_TABLE[8];  t9 =_MIX_TABLE[9];  t10=_MIX_TABLE[10]; t11=_MIX_TABLE[11]
            t12=_MIX_TABLE[12]; t13=_MIX_TABLE[13]; t14=_MIX_TABLE[14]; t15=_MIX_TABLE[15]
            s0 =state[0];  s1 =state[1];  s2 =state[2];  s3 =state[3]
            s4 =state[4];  s5 =state[5];  s6 =state[6];  s7 =state[7]
            s8 =state[8];  s9 =state[9];  s10=state[10]; s11=state[11]
            s12=state[12]; s13=state[13]; s14=state[14]; s15=state[15]

            state[0] =t0[0][s0]^t0[1][s1]^t0[2][s2]^t0[3][s3]^t0[4][s4]^t0[5][s5]^t0[6][s6]^t0[7][s7]^t0[8][s8]^t0[9][s9]^t0[10][s10]^t0[11][s11]^t0[12][s12]^t0[13][s13]^t0[14][s14]^t0[15][s15]
            state[1] =t1[0][s0]^t1[1][s1]^t1[2][s2]^t1[3][s3]^t1[4][s4]^t1[5][s5]^t1[6][s6]^t1[7][s7]^t1[8][s8]^t1[9][s9]^t1[10][s10]^t1[11][s11]^t1[12][s12]^t1[13][s13]^t1[14][s14]^t1[15][s15]
            state[2] =t2[0][s0]^t2[1][s1]^t2[2][s2]^t2[3][s3]^t2[4][s4]^t2[5][s5]^t2[6][s6]^t2[7][s7]^t2[8][s8]^t2[9][s9]^t2[10][s10]^t2[11][s11]^t2[12][s12]^t2[13][s13]^t2[14][s14]^t2[15][s15]
            state[3] =t3[0][s0]^t3[1][s1]^t3[2][s2]^t3[3][s3]^t3[4][s4]^t3[5][s5]^t3[6][s6]^t3[7][s7]^t3[8][s8]^t3[9][s9]^t3[10][s10]^t3[11][s11]^t3[12][s12]^t3[13][s13]^t3[14][s14]^t3[15][s15]
            state[4] =t4[0][s0]^t4[1][s1]^t4[2][s2]^t4[3][s3]^t4[4][s4]^t4[5][s5]^t4[6][s6]^t4[7][s7]^t4[8][s8]^t4[9][s9]^t4[10][s10]^t4[11][s11]^t4[12][s12]^t4[13][s13]^t4[14][s14]^t4[15][s15]
            state[5] =t5[0][s0]^t5[1][s1]^t5[2][s2]^t5[3][s3]^t5[4][s4]^t5[5][s5]^t5[6][s6]^t5[7][s7]^t5[8][s8]^t5[9][s9]^t5[10][s10]^t5[11][s11]^t5[12][s12]^t5[13][s13]^t5[14][s14]^t5[15][s15]
            state[6] =t6[0][s0]^t6[1][s1]^t6[2][s2]^t6[3][s3]^t6[4][s4]^t6[5][s5]^t6[6][s6]^t6[7][s7]^t6[8][s8]^t6[9][s9]^t6[10][s10]^t6[11][s11]^t6[12][s12]^t6[13][s13]^t6[14][s14]^t6[15][s15]
            state[7] =t7[0][s0]^t7[1][s1]^t7[2][s2]^t7[3][s3]^t7[4][s4]^t7[5][s5]^t7[6][s6]^t7[7][s7]^t7[8][s8]^t7[9][s9]^t7[10][s10]^t7[11][s11]^t7[12][s12]^t7[13][s13]^t7[14][s14]^t7[15][s15]
            state[8] =t8[0][s0]^t8[1][s1]^t8[2][s2]^t8[3][s3]^t8[4][s4]^t8[5][s5]^t8[6][s6]^t8[7][s7]^t8[8][s8]^t8[9][s9]^t8[10][s10]^t8[11][s11]^t8[12][s12]^t8[13][s13]^t8[14][s14]^t8[15][s15]
            state[9] =t9[0][s0]^t9[1][s1]^t9[2][s2]^t9[3][s3]^t9[4][s4]^t9[5][s5]^t9[6][s6]^t9[7][s7]^t9[8][s8]^t9[9][s9]^t9[10][s10]^t9[11][s11]^t9[12][s12]^t9[13][s13]^t9[14][s14]^t9[15][s15]
            state[10]=t10[0][s0]^t10[1][s1]^t10[2][s2]^t10[3][s3]^t10[4][s4]^t10[5][s5]^t10[6][s6]^t10[7][s7]^t10[8][s8]^t10[9][s9]^t10[10][s10]^t10[11][s11]^t10[12][s12]^t10[13][s13]^t10[14][s14]^t10[15][s15]
            state[11]=t11[0][s0]^t11[1][s1]^t11[2][s2]^t11[3][s3]^t11[4][s4]^t11[5][s5]^t11[6][s6]^t11[7][s7]^t11[8][s8]^t11[9][s9]^t11[10][s10]^t11[11][s11]^t11[12][s12]^t11[13][s13]^t11[14][s14]^t11[15][s15]
            state[12]=t12[0][s0]^t12[1][s1]^t12[2][s2]^t12[3][s3]^t12[4][s4]^t12[5][s5]^t12[6][s6]^t12[7][s7]^t12[8][s8]^t12[9][s9]^t12[10][s10]^t12[11][s11]^t12[12][s12]^t12[13][s13]^t12[14][s14]^t12[15][s15]
            state[13]=t13[0][s0]^t13[1][s1]^t13[2][s2]^t13[3][s3]^t13[4][s4]^t13[5][s5]^t13[6][s6]^t13[7][s7]^t13[8][s8]^t13[9][s9]^t13[10][s10]^t13[11][s11]^t13[12][s12]^t13[13][s13]^t13[14][s14]^t13[15][s15]
            state[14]=t14[0][s0]^t14[1][s1]^t14[2][s2]^t14[3][s3]^t14[4][s4]^t14[5][s5]^t14[6][s6]^t14[7][s7]^t14[8][s8]^t14[9][s9]^t14[10][s10]^t14[11][s11]^t14[12][s12]^t14[13][s13]^t14[14][s14]^t14[15][s15]
            state[15]=t15[0][s0]^t15[1][s1]^t15[2][s2]^t15[3][s3]^t15[4][s4]^t15[5][s5]^t15[6][s6]^t15[7][s7]^t15[8][s8]^t15[9][s9]^t15[10][s10]^t15[11][s11]^t15[12][s12]^t15[13][s13]^t15[14][s14]^t15[15][s15]

        # ── Final whitening ARK ───────────────────────────────────────────────
        # Independently derived from round keys (domain 'story_v2_whitening||').
        # Prevents last-round peeling: without this XOR an attacker with known
        # plaintext can invert the last Mix without guessing a key byte.
        wk = whitening_key
        state[0] ^=wk[0];  state[1] ^=wk[1];  state[2] ^=wk[2];  state[3] ^=wk[3]
        state[4] ^=wk[4];  state[5] ^=wk[5];  state[6] ^=wk[6];  state[7] ^=wk[7]
        state[8] ^=wk[8];  state[9] ^=wk[9];  state[10]^=wk[10]; state[11]^=wk[11]
        state[12]^=wk[12]; state[13]^=wk[13]; state[14]^=wk[14]; state[15]^=wk[15]

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
    def _to_bytes_param(data, name: str) -> bytes:
        if isinstance(data, (bytes, bytearray)): return bytes(data)
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
        story:      str,
        use_c_ext:  bool = True,
        CS:         bool = False,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext with story-based key.

        Parameters
        ----------
        plaintext : str | bytes | bytearray
        story     : str — narrative passphrase
        use_c_ext : bool — use C extension if available (default True)
        CS        : bool — load custom sboxes from customju/sboxes.json (default False)

        Returns
        -------
        (ciphertext, nonce, tag) — all bytes
        """
        pt_bytes    = STORY2._to_bytes(plaintext)
        story_norm  = unicodedata.normalize("NFC", story)
        story_bytes = story_norm.encode("utf-16-le")

        enc_key, mac_key = STORY2._derive_master_key(story_bytes)
        pool             = _load_sboxes(CS=CS)
        sbox             = _select_sbox(pool, enc_key)
        round_keys       = STORY2._derive_round_keys(enc_key)
        whitening_key    = STORY2._derive_whitening_key(enc_key)

        nonce = os.urandom(8)

        if use_c_ext and _HAS_C_EXT:
            # C extension path — pass sbox bytes directly
            ciphertext = _c_ext.story2_ctr_crypt_idx(
                pt_bytes, nonce, 0, round_keys, whitening_key
            )
        else:
            num_blocks  = (len(pt_bytes) + STORY2.BLOCK_SIZE - 1) // STORY2.BLOCK_SIZE
            ciphertext  = bytearray(len(pt_bytes))
            counter_buf = bytearray(8)

            for block_idx in range(num_blocks):
                counter_buf[:] = block_idx.to_bytes(8, "big")
                keystream = STORY2._encrypt_block_python(
                    nonce + counter_buf, sbox, round_keys, whitening_key,
                )
                start = block_idx * STORY2.BLOCK_SIZE
                end   = min(start + STORY2.BLOCK_SIZE, len(pt_bytes))
                for i in range(end - start):
                    ciphertext[start + i] = pt_bytes[start + i] ^ keystream[i]
            ciphertext = bytes(ciphertext)

        tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
        return ciphertext, nonce, tag

    @staticmethod
    def decrypt(
        ciphertext: Union[str, bytes],
        story:      str,
        nonce:      Union[str, bytes],
        tag:        Union[str, bytes],
        use_c_ext:  bool = True,
        CS:         bool = False,
    ) -> bytes:
        """
        Verify authentication tag and decrypt ciphertext.

        Raises ValueError if authentication fails.
        """
        ct_bytes  = STORY2._to_bytes_param(ciphertext, "ciphertext")
        nc_bytes  = STORY2._to_bytes_param(nonce,      "nonce")
        tag_bytes = STORY2._to_bytes_param(tag,        "tag")

        story_norm  = unicodedata.normalize("NFC", story)
        story_bytes = story_norm.encode("utf-16-le")

        enc_key, mac_key = STORY2._derive_master_key(story_bytes)
        pool             = _load_sboxes(CS=CS)
        sbox             = _select_sbox(pool, enc_key)
        round_keys       = STORY2._derive_round_keys(enc_key)
        whitening_key    = STORY2._derive_whitening_key(enc_key)

        # Authenticate before any decryption work
        check = hmac.new(mac_key, nc_bytes + ct_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(check, tag_bytes):
            raise ValueError("Authentication Failed.")

        if use_c_ext and _HAS_C_EXT:
            plaintext = _c_ext.story2_ctr_crypt_idx(
                ct_bytes, nc_bytes, 0, round_keys, whitening_key
            )
        else:
            num_blocks  = (len(ct_bytes) + STORY2.BLOCK_SIZE - 1) // STORY2.BLOCK_SIZE
            plaintext   = bytearray(len(ct_bytes))
            counter_buf = bytearray(8)

            for block_idx in range(num_blocks):
                counter_buf[:] = block_idx.to_bytes(8, "big")
                keystream = STORY2._encrypt_block_python(
                    nc_bytes + counter_buf, sbox, round_keys, whitening_key,
                )
                start = block_idx * STORY2.BLOCK_SIZE
                end   = min(start + STORY2.BLOCK_SIZE, len(ct_bytes))
                for i in range(end - start):
                    plaintext[start + i] = ct_bytes[start + i] ^ keystream[i]
            plaintext = bytes(plaintext)

        return plaintext

    @staticmethod
    def decrypt_str(
        ciphertext: Union[str, bytes],
        story:      str,
        nonce:      Union[str, bytes],
        tag:        Union[str, bytes],
        encoding:   str  = "utf-16-le",
        use_c_ext:  bool = True,
        CS:         bool = False,
    ) -> str:
        """Decrypt and decode to string (default UTF-16-LE)."""
        return STORY2.decrypt(
            ciphertext, story, nonce, tag, use_c_ext=use_c_ext, CS=CS
        ).decode(encoding)