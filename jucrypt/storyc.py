import os
import hashlib
import hmac
import argparse
import sys
import unicodedata
from typing import Tuple, List, Union

from .story import STORY, _GF, _MIX_M

# ── C extension bootstrap ──────────────────────────────────────────────────────
try:
    import story128_c as _core

    # Pass GF and MDS tables to C once — never again
    _gf_flat  = bytes(_GF[a][b]    for a in range(256) for b in range(256))
    _mds_flat = bytes(_MIX_M[i][j] for i in range(16)  for j in range(16))
    _core.story_build_tables(_gf_flat, _mds_flat)
    del _gf_flat, _mds_flat   # free Python-side copies immediately

    # Load entire S-box pool into C — done once, referenced by index thereafter
    def _bootstrap_sbox_pool() -> None:
        all_sboxes = STORY._load_sboxes()
        for idx, sbox in all_sboxes.items():
            _core.story_load_sbox(idx, bytes(sbox))

    _bootstrap_sbox_pool()
    _C_AVAILABLE = True

except ImportError:
    _C_AVAILABLE = False


# ── Key schedule helpers ───────────────────────────────────────────────────────
def _rk_flat(round_keys: List[bytes]) -> bytes:
    """Flatten list of round key bytes into a single bytes object."""
    return b"".join(round_keys)


def _derive_sbox_idx(master: bytes) -> int:
    """Resolve S-box pool index using C-side unbiased selection.
    Falls back to Python _derive_sbox path if C is unavailable.
    """
    if not _C_AVAILABLE:
        return None  # signal to use Python sbox directly

    pool_size = _core.story_sbox_count()
    if pool_size == 0:
        raise RuntimeError("story128_c: S-box pool is empty")

    threshold = 65536 - (65536 % pool_size)
    label     = b"story_v1_sbox||" + master
    pos       = 0
    chunk_no  = 0

    while True:
        stream = hashlib.shake_256(
            label + (chunk_no.to_bytes(4, "big") if chunk_no else b"")
        ).digest(64)

        idx = _core.story_select_sbox(stream, pool_size)
        if idx >= 0:
            return idx
        # stream exhausted — extend (mirrors Python _derive_sbox exactly)
        pos      += 64
        chunk_no += 1


# ── STORYC class ───────────────────────────────────────────────────────────────
class STORYC(STORY):
    """C-accelerated STORY cipher.

    Inherits all key derivation and utility methods from STORY.
    Overrides encrypt / decrypt to route the cipher work to story_core.
    Falls back to pure Python automatically if story_core is not compiled.
    """

    C_AVAILABLE: bool = _C_AVAILABLE

    @staticmethod
    def encrypt(plaintext, story: str) -> Tuple[bytes, bytes, bytes]:
        """Encrypt plaintext under a story key.

        Returns (ciphertext, nonce, tag) — all bytes.
        """
        pt_bytes    = STORYC._to_bytes(plaintext)
        story_norm  = unicodedata.normalize("NFC", story)
        story_bytes = story_norm.encode("utf-16-le")

        # ── Key schedule (Python — hashlib/hmac) ──────────────────────────
        enc_key, mac_key = STORYC._derive_master_key(story_bytes)
        perm       = STORYC._derive_perm(enc_key)
        round_keys = STORYC._derive_round_keys(enc_key)
        final_key  = STORYC._derive_whitening_key(enc_key)
        nonce      = os.urandom(8)

        # ── Cipher (C) ────────────────────────────────────────────────────
        if _C_AVAILABLE:
            sbox_idx   = _derive_sbox_idx(enc_key)
            rk_bytes   = _rk_flat(round_keys)
            perm_bytes = bytes(perm)

            ciphertext = _core.story_ctr_crypt_idx(
                pt_bytes,
                nonce,
                perm_bytes,
                sbox_idx,       # C-side pool index — no 256-byte copy
                rk_bytes,
                final_key,
            )

        # ── Cipher (pure Python fallback) ────────────────────────────────
        else:
            sbox      = STORYC._derive_sbox(enc_key)
            final_int = int.from_bytes(final_key, "big")
            buf       = bytearray()
            counter   = 0
            for i in range(0, len(pt_bytes), STORYC.BLOCK_SIZE):
                block     = pt_bytes[i : i + STORYC.BLOCK_SIZE]
                keystream = STORY._encrypt_block(
                    nonce + counter.to_bytes(8, "big"),
                    sbox, perm, round_keys, final_int,
                )
                buf.extend(ks ^ pb for ks, pb in zip(keystream, block))
                counter += 1
            ciphertext = bytes(buf)

        # ── Authentication (Python — hmac) ────────────────────────────────
        tag = hmac.new(
            mac_key,
            nonce + ciphertext,
            hashlib.sha256,
        ).digest()

        return ciphertext, nonce, tag

    @staticmethod
    def decrypt(
        ciphertext : Union[str, bytes],
        story      : str,
        nonce      : Union[str, bytes],
        tag        : Union[str, bytes],
    ) -> bytes:
        """Decrypt and authenticate a STORY ciphertext."""
        ct_bytes  = STORYC._to_bytes_param(ciphertext, "ciphertext")
        nc_bytes  = STORYC._to_bytes_param(nonce,      "nonce")
        tag_bytes = STORYC._to_bytes_param(tag,        "tag")

        story_norm  = unicodedata.normalize("NFC", story)
        story_bytes = story_norm.encode("utf-16-le")

        # ── Key schedule (Python) ─────────────────────────────────────────
        enc_key, mac_key = STORYC._derive_master_key(story_bytes)
        perm       = STORYC._derive_perm(enc_key)
        round_keys = STORYC._derive_round_keys(enc_key)
        final_key  = STORYC._derive_whitening_key(enc_key)

        # ── Authenticate first — fail before any decryption ───────────────
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

        # ── Cipher (C) ────────────────────────────────────────────────────
        if _C_AVAILABLE:
            sbox_idx   = _derive_sbox_idx(enc_key)
            rk_bytes   = _rk_flat(round_keys)
            perm_bytes = bytes(perm)

            plaintext = _core.story_ctr_crypt_idx(
                ct_bytes,
                nc_bytes,
                perm_bytes,
                sbox_idx,       # C-side pool index — no 256-byte copy
                rk_bytes,
                final_key,
            )

        # ── Cipher (pure Python fallback) ────────────────────────────────
        else:
            sbox      = STORYC._derive_sbox(enc_key)
            final_int = int.from_bytes(final_key, "big")
            buf       = bytearray()
            counter   = 0
            for i in range(0, len(ct_bytes), STORYC.BLOCK_SIZE):
                block     = ct_bytes[i : i + STORYC.BLOCK_SIZE]
                keystream = STORY._encrypt_block(
                    nc_bytes + counter.to_bytes(8, "big"),
                    sbox, perm, round_keys, final_int,
                )
                buf.extend(ks ^ cb for ks, cb in zip(keystream, block))
                counter += 1
            plaintext = bytes(buf)

        return plaintext

    @staticmethod
    def decrypt_str(
        ciphertext : Union[str, bytes],
        story      : str,
        nonce      : Union[str, bytes],
        tag        : Union[str, bytes],
        encoding   : str = "utf-16-le",
    ) -> str:
        """Decrypt and decode to string. Default encoding is UTF-16-LE."""
        return STORYC.decrypt(ciphertext, story, nonce, tag).decode(encoding)

    @staticmethod
    def decrypt_int(
        ciphertext : Union[str, bytes],
        story      : str,
        nonce      : Union[str, bytes],
        tag        : Union[str, bytes],
    ) -> int:
        """Decrypt and decode to integer (big-endian)."""
        return int.from_bytes(
            STORYC.decrypt(ciphertext, story, nonce, tag), "big"
        )


# ── CLI helpers ────────────────────────────────────────────────────────────────
_CHUNK_SEP = "$$"


def _pack_chunk(ct: bytes, nonce: bytes, tag: bytes) -> str:
    return (
        _CHUNK_SEP + "STORY_v1"
        + _CHUNK_SEP + ct.hex()
        + _CHUNK_SEP + nonce.hex()
        + _CHUNK_SEP + tag.hex()
    )


def _unpack_chunk(chunk: str):
    chunk = chunk.strip()
    if not chunk.startswith(_CHUNK_SEP):
        raise ValueError(
            "Chunk must start with '$$'.\n"
            "Expected format: $$STORY_v1$$<ct_hex>$$<nonce_hex>$$<tag_hex>"
        )
    parts = [p for p in chunk.split(_CHUNK_SEP) if p]
    if len(parts) != 4:
        raise ValueError(
            f"Chunk has {len(parts)} field(s), expected 4.\n"
            "Expected format: $$STORY_v1$$<ct_hex>$$<nonce_hex>$$<tag_hex>"
        )
    try:
        ct    = bytes.fromhex(parts[1])
        nonce = bytes.fromhex(parts[2])
        tag   = bytes.fromhex(parts[3])
    except ValueError as exc:
        raise ValueError(f"Chunk contains invalid hex: {exc}") from exc
    if len(nonce) != 8:
        raise ValueError(f"Nonce must be 8 bytes, got {len(nonce)}.")
    if len(tag) != 32:
        raise ValueError(f"Tag must be 32 bytes, got {len(tag)}.")
    return ct, nonce, tag


def _resolve_text(value: str, label: str) -> str:
    if value.endswith(".txt") and os.path.isfile(value):
        try:
            with open(value, "r", encoding="utf-8") as fh:
                content = fh.read()
            if not content.strip():
                raise ValueError(f"The file '{value}' is empty.")
            return content
        except OSError as exc:
            raise ValueError(f"Cannot read {label} '{value}': {exc}") from exc
    return value


def _resolve_chunk(value: str) -> str:
    raw = _resolve_text(value, "chunk")
    if "CHUNK :" in raw:
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("CHUNK :"):
                return line.split("CHUNK :", 1)[1].strip()
    return raw.strip()


# ── Argument parser ────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    julogo = r"""
       __      ______                 __
      / /_  __/ ____/______  ______  / /_
 __  / / / / / /   / ___/ / / / __ \/ __/
/ /_/ / /_/ / /___/ /  / /_/ / /_/ / /_
\____/\__,_/\____/_/   \__, / .___/\__/
                      /____/_/

STORY cipher  |  JuCrypt  |  v0.3.x
"""
    parser = argparse.ArgumentParser(
        prog="storyc",
        description=julogo,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ENCRYPT
  Inline:    python storyc.py --enc "Hello" --story "My key"
  From file: python storyc.py --enc msg.txt --story key.txt
  Save:      python storyc.py --enc msg.txt --story key.txt --out cipher.txt

DECRYPT
  Inline:    python storyc.py --dec "$$STORY_v1$$..." --story "My key"
  From file: python storyc.py --dec cipher.txt --story key.txt
  Save:      python storyc.py --dec cipher.txt --story key.txt --out plain.txt

NOTE
  --enc, --dec, --story accept a literal string or a .txt file path.
  Use --impl c|python to force a backend (default: auto).
""",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--enc", metavar="PLAINTEXT|FILE",
        help="Plaintext to encrypt, or path to a .txt file.")
    mode.add_argument("--dec", metavar="CHUNK|FILE",
        help="Ciphertext chunk or path to a .txt file.")
    parser.add_argument("--story", required=True, metavar="STORY|FILE",
        help="Story key passphrase, or path to a .txt file.")
    parser.add_argument("--out", metavar="FILE", default=None,
        help="Write output to file instead of stdout.")
    parser.add_argument("--impl", choices=["auto", "c", "python"], default="auto",
        help="Force backend: 'c', 'python', or 'auto' (default).")
    return parser


def _write_output(text: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"Output written to: {path}")


def _cmd_encrypt(args) -> None:
    try:
        plaintext = _resolve_text(args.enc,   "plaintext")
        story     = _resolve_text(args.story, "story")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr); sys.exit(1)

    ct, nonce, tag = STORYC.encrypt(plaintext, story)
    chunk  = _pack_chunk(ct, nonce, tag)
    output = f"CHUNK : {chunk}\n"

    if args.out:
        _write_output(output, args.out)
    else:
        print(f"\nCHUNK : {chunk}\n")
        print("Keep the CHUNK — required to decrypt.")


def _cmd_decrypt(args) -> None:
    try:
        chunk_str = _resolve_chunk(args.dec)
        story     = _resolve_text(args.story, "story")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr); sys.exit(1)

    try:
        ct, nonce, tag = _unpack_chunk(chunk_str)
    except ValueError as exc:
        print(f"Error parsing chunk: {exc}", file=sys.stderr); sys.exit(1)

    try:
        pt_bytes = STORYC.decrypt(ct, story, nonce, tag)
    except ValueError as exc:
        print(f"Decryption failed:\n{exc}", file=sys.stderr); sys.exit(1)

    plaintext = None
    for enc in ("utf-16-le", "utf-8"):
        try:
            plaintext = pt_bytes.decode(enc); break
        except UnicodeDecodeError:
            continue

    if plaintext is None:
        if args.out:
            with open(args.out, "wb") as fh: fh.write(pt_bytes)
            print(f"Raw bytes written to: {args.out}")
        else:
            print("Raw bytes (hex):", pt_bytes.hex())
        return

    if args.out:
        _write_output(plaintext, args.out)
    else:
        print(plaintext)


def main() -> None:
    parser = _build_parser()
    if len(sys.argv) == 1:
        parser.print_help(); sys.exit(0)
    args = parser.parse_args()

    global _C_AVAILABLE
    if args.impl == "python":
        _C_AVAILABLE = False
    elif args.impl == "c" and not _C_AVAILABLE:
        print("Warning: C extension unavailable — falling back to pure Python.",
              file=sys.stderr)

    if args.enc is not None:
        _cmd_encrypt(args)
    else:
        _cmd_decrypt(args)


if __name__ == "__main__":
    main()