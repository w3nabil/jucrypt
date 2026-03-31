import os
import sys
import time
import argparse

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jucrypt.story import STORY

try:
    from jucrypt.storyc import STORYC
    C_AVAILABLE = STORYC.C_AVAILABLE
except ImportError:
    STORYC      = None
    C_AVAILABLE = False

# ── Config ─────────────────────────────────────────────────────────────────────
STORY_KEY   = "This is a test story key for benchmarking purposes"
WARMUP_RUNS = 10
BENCH_RUNS  = 10
SIZES = {
    "1 KB"  : 1    * 1024,
    "10 KB" : 10   * 1024,
    "100 KB": 100  * 1024,
    "1 MB"  : 1024 * 1024,
    "10 MB" : 10   * 1024 * 1024,
}

# ── Formatting helpers ─────────────────────────────────────────────────────────
def fmt_time(s: float) -> str:
    if s >= 1:       return f"{s:.3f} s  "
    if s >= 1e-3:    return f"{s*1e3:.3f} ms "
    return               f"{s*1e6:.1f} µs "

def fmt_speed(size: int, elapsed: float) -> str:
    bps = size / elapsed
    if bps >= 1024**3: return f"{bps/1024**3:.2f} GB/s"
    if bps >= 1024**2: return f"{bps/1024**2:.2f} MB/s"
    if bps >= 1024:    return f"{bps/1024:.2f} KB/s"
    return                    f"{bps:.0f} B/s "

def sep(char="─", w=72): print(char * w)

# ── Roundtrip check ────────────────────────────────────────────────────────────
def check_roundtrip(cls, name: str) -> bool:
    original = "STORY cipher roundtrip verification — 日本語テスト 🔐"
    try:
        ct, nc, tg = cls.encrypt(original, STORY_KEY)
        recovered  = cls.decrypt_str(ct, STORY_KEY, nc, tg)
        ok = recovered == original
        print(f"  {'PASS' if ok else 'FAIL'}  [{name}] roundtrip")
        return ok
    except Exception as exc:
        print(f"  FAIL  [{name}] roundtrip — {exc}")
        return False

# ── Warmup ─────────────────────────────────────────────────────────────────────
def warmup(cls, name: str) -> None:
    data = os.urandom(10 * 1024)
    print(f"  Warming up [{name}] — {WARMUP_RUNS} runs × 10 KB ...", end=" ", flush=True)
    for _ in range(WARMUP_RUNS):
        ct, nc, tg = cls.encrypt(data, STORY_KEY)
        cls.decrypt(ct, STORY_KEY, nc, tg)
    print("done")

# ── Single benchmark pass ──────────────────────────────────────────────────────
def bench_one(cls, data: bytes, op: str) -> tuple:
    times = []
    for _ in range(BENCH_RUNS):
        t = time.perf_counter()
        if op == "encrypt":
            ct, nc, tg = cls.encrypt(data, STORY_KEY)
            result = (ct, nc, tg)
        else:
            ct, nc, tg = _last_encrypt
            cls.decrypt(ct, STORY_KEY, nc, tg)
            result = None
        times.append(time.perf_counter() - t)
    return min(times), sum(times) / len(times), max(times), result

_last_encrypt = None

def bench_backend(cls, name: str) -> None:
    global _last_encrypt
    print(f"\n  [{name}]")
    print(f"  {'Size':<10} {'Op':<10} {'Best':>12} {'Avg':>12} {'Worst':>12}   {'Throughput':>12}")
    sep()

    for label, size in SIZES.items():
        data = os.urandom(size)

        # encrypt
        best, avg, worst, enc_result = bench_one(cls, data, "encrypt")
        _last_encrypt = enc_result
        print(f"  {label:<10} encrypt   "
              f"  {fmt_time(best):>12} {fmt_time(avg):>12} {fmt_time(worst):>12}"
              f"   {fmt_speed(size, avg):>12}")

        # decrypt — uses ciphertext from last encrypt run
        best, avg, worst, _ = bench_one(cls, data, "decrypt")
        print(f"  {label:<10} decrypt   "
              f"  {fmt_time(best):>12} {fmt_time(avg):>12} {fmt_time(worst):>12}"
              f"   {fmt_speed(size, avg):>12}")

    sep()

# ── C vs Python comparison table ───────────────────────────────────────────────
def compare_summary(py_results: dict, c_results: dict) -> None:
    if not c_results:
        return
    print("\n  C vs Python speedup (avg encrypt throughput)")
    sep()
    print(f"  {'Size':<10} {'Python':>14} {'C':>14} {'Speedup':>10}")
    sep()
    for label in py_results:
        py_spd = py_results[label]
        c_spd  = c_results.get(label, 0)
        speedup = c_spd / py_spd if py_spd > 0 else 0
        print(f"  {label:<10} {py_spd:>14} {c_spd:>14} {speedup:>9.1f}x")
    sep()

# ── Main ───────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(prog="bench_story")
    parser.add_argument("--impl", choices=["auto", "c", "python"], default="auto",
                        help="Backend to benchmark (default: auto = both)")
    args = parser.parse_args()

    sep("═")
    print(f"  STORY cipher — benchmark")
    print(f"  Python  : {sys.version.split()[0]}  |  impl : {sys.implementation.name}")
    print(f"  Backend : {args.impl}  |  C available : {C_AVAILABLE}")
    print(f"  Runs    : {BENCH_RUNS} bench + {WARMUP_RUNS} warmup per backend")
    sep("═")

    # ── Roundtrip checks ───────────────────────────────────────────────────────
    print("\nRoundtrip checks...")
    all_ok = True
    if args.impl in ("auto", "python"):
        all_ok &= check_roundtrip(STORY, "Python")
    if args.impl in ("auto", "c") and C_AVAILABLE and STORYC:
        all_ok &= check_roundtrip(STORYC, "C")
    if not all_ok:
        print("\nAborted — roundtrip failure.")
        sys.exit(1)

    # ── Cross-backend parity check ────────────────────────────────────────────
    if args.impl == "auto" and C_AVAILABLE and STORYC:
        print("\nCross-backend parity check...")
        data = os.urandom(256)
        ct, nc, tg = STORYC.encrypt(data, STORY_KEY)
        pt = STORY.decrypt(ct, STORY_KEY, nc, tg)
        ok = pt == data
        print(f"  {'PASS' if ok else 'FAIL'}  C encrypt → Python decrypt")
        ct, nc, tg = STORY.encrypt(data, STORY_KEY)
        pt = STORYC.decrypt(ct, STORY_KEY, nc, tg)
        ok2 = pt == data
        print(f"  {'PASS' if ok2 else 'FAIL'}  Python encrypt → C decrypt")
        if not (ok and ok2):
            print("\nAborted — parity failure.")
            sys.exit(1)

    # ── Warmup ────────────────────────────────────────────────────────────────
    print()
    if args.impl in ("auto", "python"):
        warmup(STORY, "Python")
    if args.impl in ("auto", "c") and C_AVAILABLE and STORYC:
        warmup(STORYC, "C")

    # ── Benchmarks ────────────────────────────────────────────────────────────
    py_speeds = {}
    c_speeds  = {}

    if args.impl in ("auto", "python"):
        bench_backend(STORY, "Python")
        # Collect avg encrypt speeds for comparison table
        for label, size in SIZES.items():
            data = os.urandom(size)
            _, avg, _, _ = bench_one(STORY, data, "encrypt")
            py_speeds[label] = fmt_speed(size, avg)

    if args.impl in ("auto", "c") and C_AVAILABLE and STORYC:
        bench_backend(STORYC, "C")
        for label, size in SIZES.items():
            data = os.urandom(size)
            _, avg, _, _ = bench_one(STORYC, data, "encrypt")
            c_speeds[label] = fmt_speed(size, avg)
    elif args.impl == "c" and not C_AVAILABLE:
        print("\n  C extension not available — install with:")
        print("    STORY_NATIVE=1 pip install -e .")

    # ── Comparison ────────────────────────────────────────────────────────────
    if py_speeds and c_speeds:
        compare_summary(py_speeds, c_speeds)

    sep("═")
    print(f"\n  Note: run under PyPy3 for JIT-optimised Python numbers.")
    print(f"        first encrypt includes S-box pool disk load on CPython.\n")
    sep("═")


if __name__ == "__main__":
    main()