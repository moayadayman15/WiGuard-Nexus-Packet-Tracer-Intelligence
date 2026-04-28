# Test Results — v5.1.0-security-foundation

Date: 2026-04-27

## Executed in this environment

```bash
python3 -m compileall -q app.py wiguard tests
```

Result: PASS

Manual service-level validation executed with Python stdlib environment:

- ConfigExtractor parses interface, DHCP, trunk, and ACL evidence.
- ACL rules bind to interfaces through `ip access-group`.
- Policy Diff includes trunk coverage and gateway/DHCP matching.
- Guest internal simulation uses applied ACL path and returns expected pass.
- Upload path traversal attempt `../evil.cfg` is stored safely under UUID filename.
- Atomic Storage saves, reloads, and creates backup.

Result: PASS

## Added automated tests

```text
tests/test_security_upload.py
tests/test_extraction_accuracy.py
tests/test_storage_atomic.py
tests/test_app_security.py
```

## Full runtime test command

After installing dependencies from `requirements.txt`:

```bash
python -m pytest -q
```

The Flask route/CSRF test requires Flask/Werkzeug installed from the project requirements.

## v5.2.2 Responsive UI Check
- CSS compile/static packaging verified.
- Workspace max-width cap removed.
- Desktop/tablet/mobile responsive breakpoints added.
