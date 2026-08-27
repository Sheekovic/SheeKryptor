# Contributing to SheeKryptor

Thank you for helping build privacy tools that people can understand and trust.

## Before you start

- For a bug, search existing issues and open a reproducible report if needed.
- For a feature or file-format change, open a proposal before implementation.
- Never submit real passwords, 2FA seeds, encrypted personal files, API tokens, or database files.
- Security vulnerabilities belong in private reporting, not public issues. See [SECURITY.md](SECURITY.md).

## Development setup

1. Fork and clone the repository.
2. Create a virtual environment: `python -m venv .venv`.
3. Activate it and run `python -m pip install -r requirements.txt`.
4. Run the tests: `python -m unittest discover -s tests -v`.
5. Start the desktop application: `python SheeKryptor.py`.

The web edition is dependency-free. Serve the repository root with
`python -m http.server 8000` and open `http://localhost:8000/docs/`.

## Pull requests

- Keep changes focused and explain the user-facing outcome.
- Add tests for cryptography, file-format, and data-integrity changes.
- Preserve compatibility with existing `.skrypt` files unless a versioned migration is included.
- Update documentation when behavior or security properties change.
- Run Python tests, syntax checks, and the web checks before requesting review.

Cryptographic changes require extra scrutiny. Prefer established primitives from
`cryptography` and the browser Web Crypto API; do not design custom primitives.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
