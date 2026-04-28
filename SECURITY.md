# Security Policy

WiGuard Nexus handles network evidence, reports, and configuration-derived artifacts. Treat every workspace as sensitive.

## Required production settings

- Set `WIGUARD_SECRET_KEY` to a long random value.
- Set `WIGUARD_ADMIN_USERNAME` and `WIGUARD_ADMIN_PASSWORD_HASH`.
- Keep `FLASK_DEBUG=0`.
- Keep `WIGUARD_AUTH_REQUIRED=1` unless running isolated tests.
- Place the app behind HTTPS when accessed over a network.

## Implemented hardening

- Login gate for application routes.
- CSRF validation for mutating POST actions.
- Upload filename sanitization and UUID-based storage names.
- Upload extension allowlist.
- Flask `MAX_CONTENT_LENGTH` support through `WIGUARD_MAX_UPLOAD_BYTES`.
- Safer ZIP text intake limits for member count and total/member bytes.
- Atomic JSON state writes with backup recovery.
- Evidence manifest with SHA256 hashes and detached manifest checksum.

## Reporting vulnerabilities

Open a private issue or contact the maintainer. Include steps to reproduce, affected route/service, expected impact, and any safe proof-of-concept details.
