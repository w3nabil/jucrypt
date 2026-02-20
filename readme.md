# Ju's Story (STORY)

> **Your story is your key.**
> A story-key driven Substitution-Permutation Network cipher.

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/Apace-2.0-green)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-jucrypt-orange?logo=pypi)](https://pypi.org/project/jucrypt/)
[![Status](https://img.shields.io/badge/Status-Educational%20%2F%20Research-yellow)]()

---

## What is STORY?

STORY (Ju's Story) is an experimental symmetric cipher where the **encryption key is a piece of text you write** — a story, a sentence, a memory. The longer and more unique your story, the stronger your encryption.

It is built on a **Substitution-Permutation Network (SPN)**, the same family of designs as AES. STORY is designed for **educational use, personal projects, and cryptography research**. It is not a replacement for AES-GCM or ChaCha20-Poly1305 in production systems. A research paper of this project is also available at [our personal website](https://w3nabil.com/archive/S-NAB-035.pdf) where we stated how we built this cipher.

---

## ⚠️ Security Notice

> STORY is an **educational and research cipher**. It has **not** undergone formal cryptanalysis or peer review. Do not use it to protect sensitive personal data, financial records, medical information, or anything requiring compliance (HIPAA, GDPR, FIPS 140-2, etc.). 
>
> For production security needs, use [AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/) or [ChaCha20-Poly1305](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305) via the `cryptography` library.

**Good uses for STORY:**

- Personal journals and diaries
- Learning how SPN ciphers work
- CTF challenges and cryptography coursework
- Hobbyist encryption experiments
- Prototyping novel key-derivation ideas

---

## Installation

```bash
pip install jucrypt
```

Requires **Python 3.9 or higher**. No external dependencies — pure standard library. Unless you are testing. For testing please install the optional dependencies.

---

## Quick Start

### Encrypt and decrypt a message

```python
from jucrypt import story

mystory = "The first time I watched Ju Wenjun play chess, I knew she was extraordinary."

# Encrypt
ciphertext, nonce, tag = story.encrypt(b"Hello, Zerin!", mystory)

# Decrypt
plaintext = story.decrypt(ciphertext, mystory, nonce, tag)
print(plaintext)  # b"Hello, Zerin!"
```

### Encrypt a file

```python
from jucrypt import story

mystory = "Anya Forger is not smart, she is just a copy cat master."

with open("diary.txt", "rb") as f:
    data = f.read()

ciphertext, nonce, tag = story.encrypt(data, mystory)

# Save everything needed to decrypt later
with open("diary.story", "wb") as f:
    f.write(nonce + tag + ciphertext)   # prepend nonce and tag
```

### Decrypt a file

```python
from jucrypt import story

mystory = "Anya Forger is not smart, she is just a copy cat master."

with open("diary.story", "rb") as f:
    raw = f.read()

nonce      = raw[:8]     # first 8 bytes
tag        = raw[8:40]   # next 32 bytes
ciphertext = raw[40:]    # remainder

plaintext = story.decrypt(ciphertext, mystory, nonce, tag)
```

---

## Command-Line Interface

Planned to introduce in future....

## API Reference

### `story.encrypt(plaintext, yourstory)`

Encrypts plaintext using the given story as the key.

```python
ciphertext, nonce, tag = story.encrypt(plaintext: bytes, story: str)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `plaintext` | `bytes` | The data to encrypt. Any length. |
| `story` | `str` | Your story — the encryption key. Any Unicode string. |

**Returns:** a 3-tuple of `(ciphertext, nonce, tag)` — all `bytes`.

| Return value | Size | Description |
|--------------|------|-------------|
| `ciphertext` | same as plaintext | Encrypted data |
| `nonce` | 12 bytes | Random value generated per encryption. Never reuse. |
| `tag` | 32 bytes | HMAC-SHA256 authentication tag |

> You must store **all three** values to decrypt later.

---

### `story.decrypt(ciphertext, yourstory, nonce, tag)`

Decrypts and authenticates a ciphertext.

```python
plaintext = story.decrypt(ciphertext: bytes, story: str, nonce: bytes, tag: bytes)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `ciphertext` | `bytes` | The encrypted data |
| `story` | `str` | The same story used to encrypt |
| `nonce` | `bytes` | The nonce returned by `encrypt()` |
| `tag` | `bytes` | The tag returned by `encrypt()` |

**Returns:** `bytes` — the original plaintext.

**Raises:** `ValueError` if the story is wrong or the ciphertext has been tampered with. Always handle this exception:

```python
try:
    plaintext = story.decrypt(ciphertext, story, nonce, tag)
except ValueError:
    print("Wrong story or corrupted ciphertext.")
```

---

### Internal methods (advanced use)

These are available for research and analysis but are not part of the stable public API.

| Method | Description |
|--------|-------------|
| `STORY._derive_master_key(story)` | Derives `(enc_key, mac_key)` from a story via HKDF |
| `STORY._derive_sbox(master)` | Derives a 256-byte S-box from key via Fisher-Yates |
| `STORY._derive_perm(master)` | Derives a 16-byte permutation from key |
| `STORY._expand_round_keys(master)` | Expands 13 round keys (12 rounds + output whitening) |
| `STORY._encrypt_block(block, master, sbox, round_keys)` | Encrypts a single 16-byte block |
| `STORY._make_counter_block(nonce, counter)` | Builds a CTR mode counter block |

---

## How STORY Works

### The story as a key

Your story string is passed through `SHAKE-256` to produce a 32-byte Input Keying Material (IKM). From that, two keys are derived using HMAC-SHA256 in an HKDF-like expansion:

```
story  →  SHAKE-256  →  IKM (32 bytes)
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
              enc_key (32B)       mac_key (32B)
```

### The cipher structure

Each 16-byte block goes through 12 rounds of an SPN. Each round applies:

```
1. AddRoundKey   — XOR state with round key
2. SubBytes      — S-box substitution (key-derived, unique per story)
3. ShiftRows     — Fixed byte rotation across columns (guaranteed diffusion)
4. Permute       — Key-derived byte permutation (additional confusion)
5. MixColumns    — AES-style GF(2⁸) mixing (diffusion)
```

After the 12th round, a final `AddRoundKey` (output whitening) is applied using a 13th round key. This ensures the last transformation is key-dependent.

### CTR mode

Blocks are encrypted in Counter (CTR) mode, turning the block cipher into a stream cipher:

```
keystream = Encrypt(nonce || counter)
ciphertext = plaintext XOR keystream
```

This means:

- Encryption and decryption are identical operations
- Plaintext length is preserved exactly (no padding)
- Each nonce must be unique — STORY generates a fresh 8-byte random nonce per `encrypt()` call

### Encrypt-then-MAC

After encryption, an HMAC-SHA256 tag is computed over `nonce || ciphertext` using `mac_key`. Decryption verifies this tag **before** processing any ciphertext. This provides authenticated encryption — tampered ciphertexts are rejected before any data is returned.

```
tag = HMAC-SHA256(mac_key, nonce || ciphertext)
```

---

## Design Properties

| Property | Value | Notes |
|----------|-------|-------|
| Block size | 128 bits (16 bytes) | Same as AES |
| Key size | 256 bits (32 bytes, derived) | Derived from story via SHAKE-256 |
| Rounds | 12 | SAC converges at round ~4; rounds 5–12 are security margin |
| Mode | CTR | Stream cipher mode, no padding required |
| Authentication | HMAC-SHA256 | Encrypt-then-MAC |
| Nonce size | 64 bits (8 bytes) | Random per encryption, 2⁶⁴ block capacity |
| S-box | Key-derived | Fisher-Yates shuffle seeded from master key |
| Diffusion | ShiftRows + key-derived permutation + MixColumns | Guaranteed cross-column diffusion |

---

## Choosing a Good Story

The security of STORY depends entirely on how difficult your story is to guess. A story is stronger when it is:

- **Long** — more characters means more entropy. Aim for at least one full sentence.
- **Personal and specific** — something only you would write, not a famous quote
- **Unique** — not the title of a book, movie, or song
- **Unpredictable** — includes your own phrasing, not generic phrases

```python
# ❌ Weak stories
mystory = "hello"
mystory = "password123"
mystory = "To be or not to be"   # famous quote — guessable

# ✅ Strong stories
mystory = "The summer I turned 14, my grandmother taught me to make dumplings in her small Beijing apartment. No Matter what you say the experience was great and I will always miss her. Her name was Shu Fei Yan."
mystory = "Ju Wenjun's 2023 world championship match lasted 14 games and I watched every one from Singapore."
```

> **There is no password recovery.** If you forget your story, the ciphertext cannot be decrypted. Write it down somewhere safe if it matters. Or perhaps use an unknown book from where you are pasting the story, Maybe from your personal research project? or maybe about yourself? 

---

## Project Background

STORY began as **Project 035** in 2023 — a personal exploration of cipher design. The name JuCrypt comes from the name of Ju Wenjun.

The cipher is dedicated to **Ju Wenjun** (居文君), Women's World Chess Champion, whose name is embedded throughout the codebase as a tribute to her excellence.

> *"JuCrypt was made with love, not to compete against existing ciphers."*

---

## Comparison with Standard Ciphers

| Feature | STORY | AES-GCM | ChaCha20-Poly1305 |
|---------|--------|---------|-------------------|
| Purpose | Education / hobby | Production | Production |
| Peer reviewed | ❌ No | ✅ Yes (NIST) | ✅ Yes |
| Key input | Natural language story | Raw bytes | Raw bytes |
| Block size | 128 bits | 128 bits | Stream |
| Authentication | HMAC-SHA256 | GCM (GHASH) | Poly1305 |
| Speed | Moderate (pure Python) | Very fast (C/hardware) | Very fast |
| Formal security proof | ❌ No | ✅ Yes | ✅ Yes |
| Recommended for secrets | ❌ No | ✅ Yes | ✅ Yes |

---

## Contributing

Contributions are welcome, especially:

- Empirical test results (NIST SP 800-22, differential cryptanalysis)
- Advanced test results
- Performance improvements (while keeping the code readable)
- Documentation improvements
- Bug reports

Please open an issue before submitting a large pull request. If you wish to submit some confidential results of story, please reach me out via mail rather than opening an issue for a smoother conversation.

---

## License

Apache 2.0 License — see [LICENSE](LICENSE) for details.

---

## Thanks to

- **Ju Wenjun** — Women's World Chess Champion, the inspiration for this project
- Shannon, C.E. (1949) — *Communication Theory of Secrecy Systems*, for the basic foundation of this project
- Daemen & Rijmen — *The Design of Rijndael* (AES), for SBox ideas and many more.

---
