# Security Policy

## Supported versions

Security fixes are provided for the latest release on the default branch. Legacy
AES-CBC files are supported only for local migration into the authenticated format.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's **Report a vulnerability** option in the repository Security tab when
available, or email `sheekovic@gmail.com` with:

- the affected component and version;
- reproduction steps or a minimal proof of concept;
- the expected security impact;
- any suggested mitigation.

Do not include real secrets or personal files. You can expect an acknowledgement
within seven days. Please allow a reasonable remediation window before disclosure.

## Security model

- Encryption and decryption are local operations.
- The current `.skrypt` format uses PBKDF2-HMAC-SHA-256 and AES-256-GCM.
- Password recovery is intentionally impossible; losing a password loses access.
- The browser edition places a 250 MB limit because Web Crypto processes the selected
  file in memory. The desktop core streams file contents.
- Legacy files are unauthenticated. Re-encrypt recovered legacy data immediately.

SheeKryptor has not received an independent cryptographic audit. Do not describe it
as audited or use it as the sole control for high-value or life-critical data.
