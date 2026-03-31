# =============================================================================
#  STORY Cipher — Basic Test Suite
#  Version : v0.4.0
#  By      : Claude AI (sonnet 4.6)
# =============================================================================

from __future__ import annotations

import gc
import os
import time
import datetime
import argparse

import numpy as np

from story2_common import (
    _load_cipher,
    _derive_params,
    _fast_enc,
    _enc_block_r,
    _shannon_entropy,
    _chi2_uniformity,
    _nist_monobit,
    _serial_corr,
    _n_workers,
    _new_run_id,
    _run_pool,
    _load_stories,
)
from typing import Any, Dict, List, Tuple

# ── Timing constants ───────────────────────────────────────────────────────────
_TIMING_WARMUP   = 50     # calls before measurement begins
_TIMING_SAMPLES  = 500    # total measurement calls
_TIMING_TRIM     = 0.90   # keep bottom fraction (right-tail spike removal)

# ── Output schema ──────────────────────────────────────────────────────────────
BASIC_FIELDS: List[str] = [
    "timestamp_utc",
    "run_id",
    "sample_index",
    "story",
    "story_len",
    "plaintext_len",
    "roundtrip_ok",
    # Avalanche — per-INPUT-bit statistics
    "avalanche_pct",
    "avalanche_std",
    "avalanche_min_bit",
    "avalanche_max_bit",
    # SAC — per-OUTPUT-bit statistics
    "sac_avg",
    "sac_std",
    "sac_min_bit",
    "sac_max_bit",
    # BIC
    "bic_avg_corr",
    "bic_max_corr",
    "bic_std_corr",
    "bic_pass",
    # Other
    "key_sensitivity_pct",
    "shannon_entropy",
    "chi2_statistic",
    "chi2_p_value",
    "chi2_pass",
    "nist_p_monobit",
    "nist_pass",
    "ddt_max",
    "lat_max",
    "diff_prob",
    "serial_corr_lag1",
    "serial_corr_lag2",
    "serial_corr_lag4",
    "timing_implementation",
    "timing_mean_ns",
    "timing_median_ns",
    "timing_std_ns",
    "timing_iqr_ns",
    "timing_cv_pct",
]

# ── DDT and LAT ────────────────────────────────────────────────────────────────
_X256      = np.arange(256, dtype=np.uint8)
_PARITY256 = np.array([bin(v).count("1") % 2 for v in range(256)], dtype=np.uint8)
_DDT_BUF   = np.zeros((256, 256), dtype=np.int32)
_LAT_BUF   = np.zeros((256, 256), dtype=np.int32)


def _ddt_lat(sbox: List[int]) -> Tuple[int, int]:
    """
    Compute DDT_max and LAT_max for an 8-bit S-box.

    DDT[Δin][Δout] = #{x : S(x) XOR S(x XOR Δin) = Δout}
    LAT[a][b]      = #{x : parity(x & a) = parity(S(x) & b)} − 128

    AES reference: DDT_max=4, LAT_max=16.
    STORY pool:    DDT_max=4, LAT_max=16.
    """
    S = np.array(sbox, dtype=np.uint8)

    _DDT_BUF[:] = 0
    for dx in range(1, 256):
        dy = S[_X256] ^ S[(_X256 ^ np.uint8(dx)).astype(np.uint8)]
        np.add.at(_DDT_BUF[dx], dy, 1)
    ddt_max = int(_DDT_BUF[1:].max())

    _LAT_BUF[:] = 0
    Sx = S[_X256]
    for a in range(1, 256):
        px = _PARITY256[(_X256 & np.uint8(a)).astype(np.uint8)]
        for b in range(1, 256):
            pb = _PARITY256[(Sx & np.uint8(b)).astype(np.uint8)]
            _LAT_BUF[a, b] = int((px == pb).sum()) - 128
    lat_max = int(np.abs(_LAT_BUF[1:, 1:]).max())

    return ddt_max, lat_max


# ── Avalanche + SAC ────────────────────────────────────────────────────────────
def _avalanche_and_sac(
    story: str,
    pt: bytes,
    CIPHER,
    p_cache: Dict = None,
) -> Tuple[float, float, float, float, float, float, float, float]:
    """
    Compute Avalanche and SAC from one shared set of 129 block-cipher calls.

    Both metrics use the same flip matrix F[bp][j] = 1 if flipping input bit
    bp caused output bit j to change.  Shape: (128, 128).

    Avalanche (per-INPUT-bit view)
    ──────────────────────────────
      row_sums[bp] = fraction of output bits changed when input bit bp flipped.
      avalanche_pct = mean(row_sums) × 100    ideal: 50.0%
      avalanche_std = std(row_sums)           ideal: small ≈ 0.03–0.05
      ava_min       = min(row_sums)           worst input bit (least influence)
      ava_max       = max(row_sums)           worst input bit (most influence)

    SAC (per-OUTPUT-bit view, Webster & Tavares 1985)
    ─────────────────────────────────────────────────
      col_sums[j] = fraction of input-bit flips that changed output bit j.
      sac_avg = mean(col_sums)    ideal: 0.5
      sac_std = std(col_sums)     ideal: small — output-bit uniformity
      sac_min = min(col_sums)     worst under-sensitive output bit
      sac_max = max(col_sums)     worst over-sensitive output bit

    The means are equal by double-counting symmetry.  std/min/max measure
    entirely different things:
      avalanche_std — are all INPUT bits equally influential?
      sac_std       — are all OUTPUT bits equally sensitive?
    """
    p   = p_cache if p_cache is not None else _derive_params(story, CIPHER)
    blk = (pt + bytes(16))[:16]

    ref_b = np.unpackbits(
        np.frombuffer(_enc_block_r(blk, 0, p, CIPHER), dtype=np.uint8)
    )

    F = np.zeros((128, 128), dtype=np.float32)
    for bp in range(128):
        pt2          = bytearray(blk)
        pt2[bp // 8] ^= 1 << (bp % 8)
        fb            = np.unpackbits(
            np.frombuffer(_enc_block_r(bytes(pt2), 0, p, CIPHER), dtype=np.uint8)
        )
        F[bp] = (ref_b ^ fb).astype(np.float32)

    # Avalanche: per-INPUT-bit row statistics
    row_sums      = F.mean(axis=1)
    avalanche_pct = float(row_sums.mean()) * 100.0
    avalanche_std = float(row_sums.std())
    ava_min       = float(row_sums.min())
    ava_max       = float(row_sums.max())

    # SAC: per-OUTPUT-bit column statistics
    col_sums = F.mean(axis=0)
    sac_avg  = float(col_sums.mean())
    sac_std  = float(col_sums.std())
    sac_min  = float(col_sums.min())
    sac_max  = float(col_sums.max())

    return avalanche_pct, avalanche_std, ava_min, ava_max, sac_avg, sac_std, sac_min, sac_max


# ── BIC ────────────────────────────────────────────────────────────────────────
_BIC_N = 128   # random plaintexts → 128 × 128 = 16 384 delta rows
               # SE per correlation ≈ 1/sqrt(16384) = 0.0078
               # E[max|corr|] under H0 ≈ 0.033  →  pass threshold 0.10 (3×)


def _bic(
    story: str,
    CIPHER,
    p_cache: Dict = None,
) -> Tuple[float, float, float, int]:
    """
    Bit Independence Criterion (Webster & Tavares 1986).

    Pooled-delta variant: _BIC_N random plaintexts × 128 single-bit flips
    → (16 384, 128) delta matrix.  Pearson correlation across all C(128,2)=8128
    output-bit pairs.

    Pass threshold: bic_max_corr < 0.10 (3× above null expectation of 0.033).
    """
    p   = p_cache if p_cache is not None else _derive_params(story, CIPHER)
    rows: List[np.ndarray] = []

    for _ in range(_BIC_N):
        pt    = os.urandom(16)
        blk   = (pt + bytes(16))[:16]
        ref_b = np.unpackbits(
            np.frombuffer(_enc_block_r(blk, 0, p, CIPHER), dtype=np.uint8)
        )
        for bp in range(128):
            pt2          = bytearray(blk)
            pt2[bp // 8] ^= 1 << (bp % 8)
            fb            = np.unpackbits(
                np.frombuffer(_enc_block_r(bytes(pt2), 0, p, CIPHER), dtype=np.uint8)
            )
            rows.append((ref_b ^ fb).astype(np.float32))

    D      = np.stack(rows, axis=0)
    D_c    = D - D.mean(axis=0, keepdims=True)
    norms  = np.sqrt((D_c ** 2).sum(axis=0))
    norms[norms == 0] = 1.0
    corr_m = (D_c.T @ D_c) / np.outer(norms, norms)
    np.clip(corr_m, -1.0, 1.0, out=corr_m)

    idx_i, idx_j = np.triu_indices(128, k=1)
    abs_corrs    = np.abs(corr_m[idx_i, idx_j])

    avg_corr = float(abs_corrs.mean())
    max_corr = float(abs_corrs.max())
    std_corr = float(abs_corrs.std())
    bic_pass = int(max_corr < 0.10)

    return avg_corr, max_corr, std_corr, bic_pass


# ── Key sensitivity ────────────────────────────────────────────────────────────
def _key_sensitivity(
    story: str,
    pt: bytes,
    CIPHER,
    p_cache: Dict = None,
) -> float:
    """
    Key sensitivity: mean Hamming distance (%) between encryptions of the same
    block under the original key and a single-bit-flipped story key.

    Tests up to 32 UTF-16-LE bytes (16 characters) = 256 bit positions.
    """
    p_ref = p_cache if p_cache is not None else _derive_params(story, CIPHER)
    blk   = (pt + bytes(16))[:16]
    ref   = np.frombuffer(
        _enc_block_r(blk, 0, p_ref, CIPHER), dtype=np.uint8
    )

    sb      = bytearray(story.encode("utf-16-le"))
    n_bytes = min(32, len(sb))
    results = []

    for i in range(n_bytes):
        for bit in range(8):
            sb2 = bytearray(sb)
            sb2[i] ^= 1 << bit
            try:
                ps = sb2.decode("utf-16-le", errors="replace")
            except Exception:
                continue
            p2  = _derive_params(ps, CIPHER)
            ct2 = np.frombuffer(
                _enc_block_r(blk, 0, p2, CIPHER), dtype=np.uint8
            )
            results.append(int(np.unpackbits(ref ^ ct2).sum()) / 128 * 100)

    return float(np.mean(results)) if results else 50.0


# ── Worker ─────────────────────────────────────────────────────────────────────
def _run_basic_one(args: tuple) -> Dict[str, Any]:
    """Process one (story, sample_index) pair."""
    story, idx, run_id, ts, impl, pt_len = args
    CIPHER, _ = _load_cipher()

    pt = os.urandom(pt_len)

    # Single key-schedule derivation — reused across all downstream functions
    # (avalanche, SAC, BIC, key sensitivity, DDT/LAT) to avoid redundant work.
    p_cache = _derive_params(story, CIPHER)

    # 1. Roundtrip
    ct, n, tag = _fast_enc(pt, story, CIPHER)
    try:
        rt_ok = int(CIPHER.decrypt(ct, story, n, tag, use_c_ext=False) == pt)
    except Exception:
        rt_ok = 0

    # 2+3. Avalanche + SAC (one merged pass — 129 block-cipher calls)
    (aval_pct, aval_std, aval_min, aval_max,
     sac_avg, sac_std, sac_min, sac_max) = _avalanche_and_sac(
        story, pt, CIPHER, p_cache=p_cache
    )

    # 4. BIC
    bic_avg, bic_max, bic_std, bic_ok = _bic(story, CIPHER, p_cache=p_cache)

    # 5. Key sensitivity
    ks = _key_sensitivity(story, pt, CIPHER, p_cache=p_cache)

    # 6. Statistical pool (500 × random pt)
    pool = bytearray()
    for _ in range(500):
        pool.extend(_fast_enc(os.urandom(pt_len), story, CIPHER)[0])
    pb = bytes(pool)

    entropy                  = _shannon_entropy(pb)
    chi2_s, chi2_p, chi2_ok  = _chi2_uniformity(pb)
    nist_p, nist_ok          = _nist_monobit(pb)

    # 7. DDT, LAT — reuse p_cache sbox
    ddt_max, lat_max = _ddt_lat(p_cache["sbox"])
    diff_prob        = ddt_max / 256.0

    # 8. Serial correlation
    lag1 = _serial_corr(pb, 1)
    lag2 = _serial_corr(pb, 2)
    lag4 = _serial_corr(pb, 4)

    # 9. GC before timing — clear pool allocations to prevent mid-loop GC pauses
    del pool, pb
    gc.collect()

    # 10. Timing warmup — _TIMING_WARMUP calls to stabilise CPU cache and
    #     Python frame allocation before measurement begins.
    for _ in range(_TIMING_WARMUP):
        _fast_enc(pt, story, CIPHER)

    # 11. Timing measurement
    #
    #     Distribution properties
    #     ───────────────────────
    #     Timing distributions are right-skewed: OS scheduler interrupts cause
    #     upward spikes; the floor is hard (bounded by cipher cost).
    #
    #     Right-tail-only trim: keep bottom _TIMING_TRIM fraction, discard top
    #     (1 - _TIMING_TRIM).  This preserves all valid LOW measurements that
    #     symmetric trimming discards, giving a stable distribution floor.
    #
    #     IQR-based CV (quartile coefficient of variation)
    #     ─────────────────────────────────────────────────
    #     CV = IQR / (2 × median) × 100
    #
    #     std/mean CV is sensitive to remaining right-tail spikes because std
    #     is quadratic in outlier distance.  IQR = Q75 − Q25 is entirely
    #     unaffected by values outside [Q25, Q75], making it robust to any
    #     spikes that survive the 90%-trim boundary.
    #
    #     Fallback: if median == 0 (genuine timer quantisation collapse on this
    #     platform), fall back to std/mean CV so the column is not NaN/Inf.
    #     The previous guard of q50 >= 500 ns was too aggressive — fast C-ext
    #     calls legitimately complete in ~300 ns and would incorrectly trigger
    #     the fallback, defeating the purpose of IQR-based CV.
    times = []
    for _ in range(_TIMING_SAMPLES):
        t0 = time.perf_counter_ns()
        _fast_enc(pt, story, CIPHER)
        times.append(time.perf_counter_ns() - t0)

    ta = np.array(sorted(times), dtype=np.float64)
    ta = ta[:int(len(ta) * _TIMING_TRIM)]   # right-tail-only trim

    q25  = float(np.percentile(ta, 25))
    q50  = float(np.median(ta))
    q75  = float(np.percentile(ta, 75))
    iqr  = q75 - q25
    mean = float(ta.mean())
    std  = float(ta.std())

    # IQR-CV — fall back only on genuine timer collapse (median == 0)
    if q50 > 0.0:
        iqr_cv = iqr / (2.0 * q50) * 100.0
    else:
        iqr_cv = (std / mean * 100.0) if mean > 0.0 else 0.0

    return {
        "timestamp_utc"        : ts,
        "run_id"               : run_id,
        "sample_index"         : idx,
        "story"                : story,
        "story_len"            : len(story),
        "plaintext_len"        : pt_len,
        "roundtrip_ok"         : rt_ok,
        "avalanche_pct"        : round(aval_pct,  4),
        "avalanche_std"        : round(aval_std,  6),
        "avalanche_min_bit"    : round(aval_min,  6),
        "avalanche_max_bit"    : round(aval_max,  6),
        "sac_avg"              : round(sac_avg,   6),
        "sac_std"              : round(sac_std,   6),
        "sac_min_bit"          : round(sac_min,   6),
        "sac_max_bit"          : round(sac_max,   6),
        "bic_avg_corr"         : round(bic_avg,   6),
        "bic_max_corr"         : round(bic_max,   6),
        "bic_std_corr"         : round(bic_std,   6),
        "bic_pass"             : bic_ok,
        "key_sensitivity_pct"  : round(ks,        4),
        "shannon_entropy"      : round(entropy,   6),
        "chi2_statistic"       : round(chi2_s,    3),
        "chi2_p_value"         : round(chi2_p,    6),
        "chi2_pass"            : chi2_ok,
        "nist_p_monobit"       : round(nist_p,    6),
        "nist_pass"            : nist_ok,
        "ddt_max"              : ddt_max,
        "lat_max"              : lat_max,
        "diff_prob"            : round(diff_prob, 6),
        "serial_corr_lag1"     : round(lag1,      6),
        "serial_corr_lag2"     : round(lag2,      6),
        "serial_corr_lag4"     : round(lag4,      6),
        "timing_implementation": impl,
        "timing_mean_ns"       : round(mean,      2),
        "timing_median_ns"     : round(q50,       2),
        "timing_std_ns"        : round(std,       2),
        "timing_iqr_ns"        : round(iqr,       2),
        "timing_cv_pct"        : round(iqr_cv,    4),
    }


# ── Public API ─────────────────────────────────────────────────────────────────
def run_basic_suite(
    stories    : List[str],
    pt_len     : int  = 44,
    run_id     : int  = None,
    output_csv : str  = "story_basic_fast.csv",
    n_workers  : int  = None,
    verbose    : bool = True,
) -> List[Dict[str, Any]]:
    """Run the basic test suite over *stories* and write results to *output_csv*."""
    if run_id is None:
        run_id = _new_run_id()
    nw      = _n_workers(n_workers)
    _, impl = _load_cipher()
    ts      = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tasks   = [(s, i, run_id, ts, impl, pt_len) for i, s in enumerate(stories)]

    if verbose:
        print(
            f"Basic suite  :  {len(stories)} stories | "
            f"pt_len={pt_len} B | {nw} workers | {impl}"
        )
        print(
            "Note: chi2_pass uses alpha=0.05 (expected ~{:.0f} false failures), "
            "nist_pass uses alpha=0.01 (expected ~{:.0f} false failures).".format(
                len(stories) * 0.05, len(stories) * 0.01
            )
        )

    results = _run_pool(_run_basic_one, tasks, BASIC_FIELDS, output_csv, verbose, nw)

    if verbose and results:
        n   = len(results)
        rt  = sum(r["roundtrip_ok"] for r in results)
        c2  = sum(r["chi2_pass"]    for r in results)
        ns  = sum(r["nist_pass"]    for r in results)
        bic = sum(r["bic_pass"]     for r in results)
        print(f"\nPass-rate summary ({n} stories):")
        print(f"  roundtrip : {rt}/{n}  ({rt/n*100:.1f}%)")
        print(
            "  chi2      : {}/{}  ({:.1f}%)  "
            "[expected ~95% at alpha=0.05]".format(c2, n, c2/n*100)
        )
        print(
            "  nist      : {}/{}  ({:.1f}%)  "
            "[expected ~99% at alpha=0.01]".format(ns, n, ns/n*100)
        )
        print(f"  bic       : {bic}/{n}  ({bic/n*100:.1f}%)")

    return results


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from multiprocessing import freeze_support
    freeze_support()

    ap = argparse.ArgumentParser(
        prog="story_basic",
        description="STORY2 cipher — basic test suite v4.5.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  python story_basic.py
  python story_basic.py --stories stories.txt
  python story_basic.py --stories stories.txt --pt-len 64 --workers 4
  python story_basic.py --output story_basic_run2.csv --quiet

Note
----
  chi2_pass uses alpha=0.05.  At n=2000 stories ~100 failures are expected.
  nist_pass uses alpha=0.01.  At n=2000 stories ~20  failures are expected.
  Neither constitutes a cipher weakness.
        """,
    )
    ap.add_argument("--stories", default=None,
                    help="Text file — one story per line.")
    ap.add_argument("--pt-len",  type=int, default=44,
                    help="Plaintext length in bytes (default 44).")
    ap.add_argument("--workers", type=int, default=None,
                    help="Worker count (default: CPU count).")
    ap.add_argument("--run-id",  type=int, default=None,
                    help="Run identifier integer.")
    ap.add_argument("--output",  default="story_basic_fast.csv",
                    help="Output CSV path.")
    ap.add_argument("--quiet",   action="store_true",
                    help="Suppress progress output.")
    args = ap.parse_args()

    run_basic_suite(
        stories    = _load_stories(args.stories),
        pt_len     = args.pt_len,
        run_id     = args.run_id,
        output_csv = args.output,
        n_workers  = args.workers,
        verbose    = not args.quiet,
    )