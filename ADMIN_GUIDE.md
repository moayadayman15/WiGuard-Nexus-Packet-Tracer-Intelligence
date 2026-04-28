# Admin Guide

## Roles

- `admin`: full settings, backup/restore, project deletion, user operations.
- `engineer`: AP/SSID/client/policy changes.
- `analyst`: imports, simulations, reports.
- `auditor`: read and export evidence.
- `viewer`: read-only workspace access.

## Security Controls

- CSRF protection on POST actions.
- Login/register rate limiting through SQLite `login_attempts`.
- Password policy: 10+ chars, uppercase, lowercase, number, symbol.
- SQLite schema migrations through `schema_migrations`.
- Health endpoint: `/healthz`.
- Error pages for 403/404/500.

## Database Operations

Use Settings to download a DB backup or restore a validated SQLite backup. Restores create a pre-restore safety backup.
