# JuCrypt

Where your security is on your hand. We entrust "No one deserves the right to interrupt or spy your secrets"

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/Apace-2.0-green)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-jucrypt-orange?logo=pypi)](https://pypi.org/project/jucrypt/)
---

## What is STORY2?

STORY2 (Ju's Story) is an experimental symmetric cipher where the **encryption key is a piece of text you write** — a story, a sentence, a memory. The longer and more unique your story, the stronger your encryption.

It is built on a **Substitution-Permutation Network (SPN)**, the same family of designs as AES but does not use premute and row shifts. STORY2 is designed for **educational use, personal projects, and cryptography research**. It is not a replacement for AES-GCM or ChaCha20-Poly1305 in production systems yet. A research paper of this project is also available at [DOI : 10.31224/6477](https://doi.org/10.31224/6477) where we stated how we built this cipher. We request you to read our paper at first before you are testing our work.

---

## ⚠️ Security Notice

> STORY is an **educational and research cipher**. It has **not** undergone formal cryptanalysis or peer review. Do not use it to protect sensitive personal data, financial records, medical information, or anything requiring compliance (HIPAA, GDPR, FIPS 140-2, etc.). 
>
> For production security needs, use [AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/) or [ChaCha20-Poly1305](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305) via the `cryptography` library.

---

## Installation

```bash
pip install jucrypt
```

Requires **Python 3.10 or higher**. No external dependencies — pure standard library. Unless you are testing. For testing please install the optional dependencies.

---

## Contributing

Contributions are welcome, especially:

- Empirical test results and scripts (NIST SP 800-22, differential cryptanalysis)
- Advanced test results and scripts
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
