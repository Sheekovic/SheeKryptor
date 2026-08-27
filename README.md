<div align="center">
  <img src="assets/SheeKryptor.png" alt="SheeKryptor" width="112">
  <h1>SheeKryptor</h1>
  <p><strong>Private file encryption for desktop and web.</strong></p>
  <p>Your files stay on your device. Your password is never transmitted.</p>

  [![CI](https://github.com/Sheekovic/SheeKryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/Sheekovic/SheeKryptor/actions/workflows/ci.yml)
  [![GitHub Pages](https://github.com/Sheekovic/SheeKryptor/actions/workflows/pages.yml/badge.svg)](https://sheekovic.github.io/SheeKryptor/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-43e6b1.svg)](LICENSE)
</div>

## What is SheeKryptor?

SheeKryptor is an open-source privacy toolbox led by authenticated file encryption.
It includes a Python desktop application and a static browser edition built on the
Web Crypto API. Both editions use the same versioned `.skrypt` file format.

**[Open the private web edition](https://sheekovic.github.io/SheeKryptor/)**

The web edition has no backend, analytics, cookies, or upload endpoint. Its Content
Security Policy blocks network requests, so encryption and decryption happen locally.

> [!IMPORTANT]
> SheeKryptor has not received an independent cryptographic audit. Keep backups and
> do not use it as the only protection for life-critical or very high-value data.

## Security properties

- AES-256-GCM authenticated encryption detects an incorrect password or modified data.
- PBKDF2-HMAC-SHA-256 with 600,000 iterations and a new 128-bit salt per file.
- A new 96-bit AES-GCM nonce per file.
- Authenticated, versioned file headers for safe format evolution.
- Atomic desktop output: failed authentication cannot replace an existing file.
- Chunked desktop I/O avoids loading an entire large file into memory.
- Legacy AES-CBC files can be recovered locally and are clearly marked for migration.
- Password generation uses the operating system's cryptographically secure randomness.

The browser edition currently limits files to 250 MB because Web Crypto processes the
selected file in memory. Use the desktop edition for larger files.

## Desktop quick start

Requirements: Python 3.10 or newer.

```powershell
git clone https://github.com/Sheekovic/SheeKryptor.git
cd SheeKryptor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python SheeKryptor.py
```

On Linux or macOS, activate the environment with `source .venv/bin/activate`.

The desktop toolbox currently includes file encryption, password generation, API
testing, TOTP management, ZIP archives, conversion utilities, temporary
mail integration, and appearance settings. Encryption is the security-reviewed focus;
the other legacy tools are being separated and hardened incrementally.

## Run the web edition locally

No JavaScript dependencies or build step are required.

```bash
python -m http.server 8000
```

Then open `http://localhost:8000/docs/`.

## Validation

```bash
python -m unittest discover -s tests -v
python -m py_compile SheeKryptor.py crypto_core.py
node --check docs/app.js
```

The test suite covers exact byte-for-byte round trips, empty and multi-megabyte files,
wrong passwords, ciphertext tampering, atomic output behavior, and legacy migration.

## Project layout

| Path | Purpose |
| --- | --- |
| `crypto_core.py` | Testable, GUI-independent encryption and migration core |
| `SheeKryptor.py` | Desktop interface and legacy toolbox features |
| `docs/` | Static GitHub Pages web edition |
| `tests/` | Security and regression tests |
| `.github/` | CI, Pages deployment, and contributor templates |

## Roadmap

- Split the remaining desktop toolbox into testable modules.
- Encrypt local TOTP seeds with a user-controlled vault key.
- Add browser streaming support for files larger than 250 MB.
- Package signed desktop releases for Windows, macOS, and Linux.
- Request an independent security review before a stable security claim.

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), use synthetic
test data, and never submit passwords, TOTP seeds, database files, API tokens, or
personal encrypted files.

Please report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## License

SheeKryptor is available under the permissive [MIT License](LICENSE).
