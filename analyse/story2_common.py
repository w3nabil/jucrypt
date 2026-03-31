# =============================================================================
#  STORY Cipher — Shared Test Infrastructure
#  Version : v0.4.0
#  By      : Claude AI (sonnet 4.6)
# =============================================================================

import os
import sys
import csv
import hashlib
import hmac as hmac_mod
import datetime
import math
import time
import unicodedata
import multiprocessing
import platform
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


# __ chi-squared survival function _____________________________________________
def _chi2_sf(x: float, df: int) -> float:
    """P(chi2(df) > x) — regularised upper incomplete gamma."""
    if hasattr(math, "gammaincc"):
        try:
            return float(math.gammaincc(df / 2.0, x / 2.0))
        except Exception:
            return 0.0
    try:
        from scipy.special import gammaincc
        return float(gammaincc(df / 2.0, x / 2.0))
    except ImportError:
        pass
    try:
        from scipy.stats import chi2
        return float(chi2.sf(x, df))
    except ImportError:
        pass
    return 0.0


# __ Cipher loader ______________________________________________________________
def _load_cipher():
    """
    Return (STORY2_class, implementation_label).

    Tries jucrypt package first, then the script directory.
    Label is 'C-accelerated' when story2._HAS_C_EXT is True,
    'pure-python' otherwise.
    """
    def _label(mod):
        return "C-accelerated" if getattr(mod, "_HAS_C_EXT", False) else "pure-python"

    try:
        import jucrypt.story2 as _s2mod
        from jucrypt.story2 import STORY2
        return STORY2, _label(_s2mod)
    except ImportError:
        pass

    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    try:
        import jucrypt.story2 as _s2mod
        from jucrypt.story2 import STORY2
        return STORY2, _label(_s2mod)
    except ImportError:
        pass

    raise ImportError(
        "Cannot find STORY2 (story2.py).\n"
        "Either install jucrypt:  pip install jucrypt\n"
        "or place story2.py in the same directory as the test scripts."
    )


# __ Per-process key cache ______________________________________________________
_KEY_CACHE: Dict[str, Dict[str, Any]] = {}


def _derive_params(story: str, CIPHER) -> Dict[str, Any]:
    """
    Derive and cache all key material for *story*.

    Cached keys
    -----------
    enc_key       : bytes(32)  — encryption master key.
    mac_key       : bytes(32)  — authentication key.
    sbox          : List[int]  — 256-entry key-dependent S-box.
    round_keys    : bytes(80)  — 5 × 16-byte round keys (STORY2 fixed rounds).
    whitening_key : bytes(16)  — final ARK whitening key.

    Note: STORY2 has no permutation layer — perm is not derived or stored.
    Note: round_keys is bytes(80), not List[bytes] — STORY2 slices internally.
    Note: whitening_key is bytes — _encrypt_block_python takes it directly.
    """
    nfc = unicodedata.normalize("NFC", story)
    if nfc in _KEY_CACHE:
        return _KEY_CACHE[nfc]

    import jucrypt.story2 as _s2mod

    story_bytes          = nfc.encode("utf-16-le")
    enc_key, mac_key     = CIPHER._derive_master_key(story_bytes)
    pool                 = _s2mod._load_sboxes(CS=False)
    sbox                 = _s2mod._select_sbox(pool, enc_key)
    round_keys           = CIPHER._derive_round_keys(enc_key)    # bytes(80)
    whitening_key        = CIPHER._derive_whitening_key(enc_key) # bytes(16)

    p = dict(
        enc_key       = enc_key,
        mac_key       = mac_key,
        sbox          = sbox,
        round_keys    = round_keys,
        whitening_key = whitening_key,
    )
    _KEY_CACHE[nfc] = p
    return p


def _fast_enc(
    pt: bytes, story: str, CIPHER
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt *pt* under *story* using cached key material.

    Returns (ciphertext, nonce, tag).

    Calls STORY2._encrypt_block_python(block, sbox, round_keys, whitening_key).
    No perm argument — STORY2 has no permutation layer.
    Counter block inlined as nonce + ctr.to_bytes(8, "big").
    """
    p             = _derive_params(story, CIPHER)
    n             = os.urandom(8)
    ct            = bytearray()
    ctr           = 0
    sbox          = p["sbox"]
    round_keys    = p["round_keys"]
    whitening_key = p["whitening_key"]

    for i in range(0, len(pt), 16):
        counter_block = n + ctr.to_bytes(8, "big")
        ks = CIPHER._encrypt_block_python(
            counter_block,
            sbox,
            round_keys,
            whitening_key,
        )
        ct.extend(b ^ k for b, k in zip(pt[i : i + 16], ks))
        ctr += 1

    tag = hmac_mod.new(
        p["mac_key"], n + bytes(ct), hashlib.sha256
    ).digest()
    return bytes(ct), n, tag


def _enc_block_r(
    block16: bytes,
    r: int,
    p: Dict,
    CIPHER,
    rk: bytes = None,
) -> bytes:
    """
    Encrypt one 16-byte block deterministically (no nonce).

    If *rk* is provided it is used directly (must be bytes, 80 bytes).
    If *rk* is None, round_keys from the cached params dict is used.

    *r* is retained for call-site compatibility but unused —
    STORY2 has fixed rounds (5) baked into _encrypt_block_python.

    Calls STORY2._encrypt_block_python(block, sbox, round_keys, whitening_key).
    No perm argument.
    """
    if rk is None:
        rk = p["round_keys"]

    return CIPHER._encrypt_block_python(
        block16,
        p["sbox"],
        rk,
        p["whitening_key"],
    )


# __ Shared statistics __________________________________________________________

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float64)
    prob = freq[freq > 0] / len(data)
    return float(-np.sum(prob * np.log2(prob)))


def _chi2_uniformity(data: bytes) -> Tuple[float, float, int]:
    if len(data) < 1280:
        return 0.0, 1.0, 1
    freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float64)
    E    = len(data) / 256.0
    chi2 = float(np.sum((freq - E) ** 2 / E))
    pval = _chi2_sf(chi2, df=255)
    return chi2, pval, int(pval >= 0.05)


def _nist_monobit(data: bytes) -> Tuple[float, int]:
    bits  = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    n     = len(bits)
    s_obs = abs(int(bits.sum()) * 2 - n) / math.sqrt(n)
    pval  = math.erfc(s_obs / math.sqrt(2))
    return float(pval), int(pval >= 0.01)


def _serial_corr(data: bytes, lag: int) -> float:
    arr = np.frombuffer(data, dtype=np.uint8).astype(np.float64)
    if len(arr) <= lag + 1:
        return 0.0
    x, y = arr[:-lag], arr[lag:]
    if x.std() == 0.0 or y.std() == 0.0:
        return 0.0
    return float(np.corrcoef(x, y)[0, 1])


def _chi2_two_sample(a: bytes, b: bytes) -> Tuple[float, float]:
    fa   = np.bincount(np.frombuffer(a, dtype=np.uint8), minlength=256).astype(np.float64)
    fb   = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256).astype(np.float64)
    na, nb = fa.sum(), fb.sum()
    nt   = na + nb
    col  = fa + fb
    mask = col > 0
    ea   = na * col[mask] / nt
    eb   = nb * col[mask] / nt
    chi2 = float(
        np.sum((fa[mask] - ea) ** 2 / ea)
        + np.sum((fb[mask] - eb) ** 2 / eb)
    )
    df   = max(int(mask.sum()) - 1, 1)
    return chi2, _chi2_sf(chi2, df=df)


# __ Pool runner ________________________________________________________________

def _n_workers(override: Optional[int] = None) -> int:
    if override is not None:
        return max(1, override)
    if platform.system() == "Windows":
        return min(4, max(1, multiprocessing.cpu_count()))
    return max(1, multiprocessing.cpu_count())


def _new_run_id() -> int:
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return int(hashlib.sha256(ts.encode()).hexdigest()[:8], 16)


def _run_pool(worker_fn, tasks, fields, output_csv, verbose, nw):
    t0      = time.perf_counter()
    results = []

    if os.path.exists(output_csv):
        with open(output_csv, newline="", encoding="utf-8") as _fh:
            existing_fields = next(csv.reader(_fh), [])
        if existing_fields != fields:
            raise ValueError(
                "Schema mismatch — cannot append to " + repr(output_csv) + ".\n"
                "  Existing fields (" + str(len(existing_fields)) + "): "
                    + str(existing_fields) + "\n"
                "  Current  fields (" + str(len(fields)) + "): "
                    + str(fields) + "\n"
                "Use a new output filename or delete the existing file."
            )
        write_hdr = False
    else:
        write_hdr = True

    with open(output_csv, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if write_hdr:
            writer.writeheader()

        with multiprocessing.Pool(processes=nw) as pool:
            for i, row in enumerate(pool.imap_unordered(worker_fn, tasks)):
                writer.writerow(row)
                fh.flush()
                results.append(row)
                if verbose and len(tasks) >= 10:
                    step = max(1, len(tasks) // 20)
                    if (i + 1) % step == 0:
                        el  = time.perf_counter() - t0
                        eta = (len(tasks) - i - 1) / ((i + 1) / el)
                        print(f"  {i+1}/{len(tasks)}  |  {(i+1)/el:.1f} rows/s  |  ETA {eta:.0f}s")

    el = time.perf_counter() - t0
    if verbose:
        print(f"Done. {len(results)} rows in {el:.1f}s ({len(results)/el:.1f} rows/s)  →  {output_csv}")
    return results


def _load_stories(path: Optional[str]) -> List[str]:
    if path is not None:
        try:
            with open(path, encoding="utf-8") as fh:
                stories = [ln.strip() for ln in fh if ln.strip()]
            if not stories:
                raise ValueError(f"Story file '{path}' contains no non-empty lines.")
            return stories
        except OSError as exc:
            raise SystemExit(f"Error reading story file: {exc}") from exc
    return list(DEFAULT_STORIES)


# __ S-box pool diagnostic ______________________________________________________
def diagnose_sbox_pool(CIPHER=None) -> None:
    """Print a DDT / LAT summary for every S-box in the loaded pool."""
    import jucrypt.story2 as _s2mod

    if CIPHER is None:
        CIPHER, _ = _load_cipher()

    # STORY2 uses module-level _load_sboxes(), not CIPHER._load_sboxes()
    all_sboxes = _s2mod._load_sboxes(CS=False)
    X   = np.arange(256, dtype=np.uint8)
    PAR = np.array([bin(v).count("1") % 2 for v in range(256)], dtype=np.uint8)

    ddt_results: Dict[int, int] = {}
    lat_results: Dict[int, int] = {}

    for idx, sbox in sorted(all_sboxes.items()):
        S = np.array(sbox, dtype=np.uint8)
        buf = np.zeros((256, 256), dtype=np.int32)
        for dx in range(1, 256):
            dy = S[X] ^ S[(X ^ np.uint8(dx)).astype(np.uint8)]
            np.add.at(buf[dx], dy, 1)
        ddt_results[idx] = int(buf[1:].max())
        Sx = S[X]
        lm = 0
        for a in range(1, 256):
            px = PAR[(X & np.uint8(a)).astype(np.uint8)]
            for b in range(1, 256):
                pb = PAR[(Sx & np.uint8(b)).astype(np.uint8)]
                v  = abs(int((px == pb).sum()) - 128)
                if v > lm:
                    lm = v
        lat_results[idx] = lm

    ddt_hist: Dict[int, int] = {}
    for v in ddt_results.values():
        ddt_hist[v] = ddt_hist.get(v, 0) + 1
    lat_hist: Dict[int, int] = {}
    for v in lat_results.values():
        lat_hist[v] = lat_hist.get(v, 0) + 1

    best_ddt      = min(ddt_hist)
    worst_indices = [idx for idx, v in ddt_results.items() if v > best_ddt]
    print(f"Pool has {len(all_sboxes)} S-boxes")
    print(f"DDT_max distribution : {dict(sorted(ddt_hist.items()))}")
    print(f"LAT_max distribution : {dict(sorted(lat_hist.items()))}")
    if worst_indices:
        print(f"S-box indices with DDT_max > {best_ddt}: "
              + str(sorted(worst_indices)[:20])
              + (" ..." if len(worst_indices) > 20 else ""))
        print(f"All DDT_max == {best_ddt} : False")
    else:
        print(f"All DDT_max == {best_ddt} : True  (pool is homogeneous)")


# __ Default story list _________________________________________________________
DEFAULT_STORIES: List[str] = [
    "For the first time in my life I felt that the world was mine",
    "During that period the hall of records burned to the ground",
    "It is useless to object here to say that this cannot be so",
    "Anya Forger",
    "Did you ever hear about Ju Wenjun the chess grandmaster",
    "The Full Name of JuCrypt is Ju Wenjun Cryptography project",
    "JuCrypt was made with love, not for money but for knowledge",
    "Ju Wenjun won the womens speed chess world championship twice",
    "Kateryna Lagno was one of the strongest female players ever",
    "Magnus Carlsen is a nightmare to play against at any time control",
    "Japan has their own chess game called Shogi with different rules",
    "One of my dearest friends named Rafi taught me to love chess",
    "JuCrypt was considered as one of the best personal projects ever",
    "JuCrypt was named Project DOVE before we settled on the name",
    "I am eager to try some turkish coffee after this project ships",
]


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(prog="story_common", description="STORY2 cipher — pool diagnostics")
    ap.add_argument("--check-pool", action="store_true",
        help="Print DDT/LAT distribution for every S-box in the loaded pool.")
    args = ap.parse_args()
    if args.check_pool:
        CIPHER, impl = _load_cipher()
        print(f"Implementation : {impl}")
        diagnose_sbox_pool(CIPHER)