## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| 0.3.2   | :white_check_mark: |
| 0.3.1   | :x:                |
| 0.2.x   | :x:                |
| 0.1.x   | :x:                |

## Note

Any child file containing a version below 1.x.x is not requested to be used for production servers, but reporting is always welcome, and it will be patched in the future. Versions above 1.x.x will be given high priority for fixes.

## Reporting a vulnerability

If you discover a security vulnerability in JuCrypt or any of it's child element, please
**do not open a public GitHub issue**. Public disclosure before a fix is available
puts all users at risk.

Instead, report privately via one of the following channels:

- **GitHub private vulnerability reporting** — use the
  *Security → Report a vulnerability* button on the repository page (preferred).
- **Email** — send a detailed report to the maintainer directly. If you need the
  address, open a regular issue asking for a security contact and we will respond
  within 24 hours with a private channel.

We will acknowledge receipt within **48 hours** and aim to provide a fix or
mitigation plan within **14 days** for confirmed vulnerabilities. You will be
credited in the changelog and release notes unless you prefer to remain anonymous.

---

## Scope

### In scope

- Cryptographic weaknesses in the STORY cipher (S-box, MDS layer, key schedule,
  CTR mode, authentication)
- Key material leakage or side-channel vulnerabilities in the C extension
- Authentication bypass or tag forgery
- Nonce reuse vulnerabilities introduced by the library
- Incorrect domain separation between derived keys
- Vulnerabilities in the S-box pool loading or validation logic

### Out of scope

- Vulnerabilities in user-supplied S-box pools (`customju/sboxes.json`) — the
  library validates bijectivity but cannot guarantee cryptographic strength of
  user-provided boxes
- Timing attacks caused by OS scheduler jitter (documented in the test suite as
  CV% outliers — not cipher-attributable)
- Issues in Python versions below 3.9 (not supported)
- Security of the passphrase / story key itself — key strength is the
  responsibility of the caller

---

## Disclosure policy

We follow **coordinated disclosure**. Once a fix is ready and released, we will
publish a full description of the vulnerability, its impact, and the fix in the
changelog. We request a minimum of **14 days** before public disclosure to allow
users time to upgrade.