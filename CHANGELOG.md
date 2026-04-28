## v5.2.1 - Login/Register UX Hardening

- Added first-run setup panel on the login page.
- Made the register flow clearly create the first SQLite admin account.
- Added visible local-demo fallback guidance only outside production.
- Added WIGUARD_DISABLE_DEMO_FALLBACK to disable emergency/demo fallback after setup.
- Improved login/register links to preserve next redirects.

# Changelog

## 5.1.0-security-foundation

### Security & Foundation
- Fixed upload path traversal by sanitizing original names and storing files as UUID names.
- Disabled Flask debug by default; now controlled by `FLASK_DEBUG`.
- Moved secret/admin/runtime settings to environment variables.
- Added `MAX_CONTENT_LENGTH` via `WIGUARD_MAX_UPLOAD_BYTES`.
- Added login/logout with environment-configured admin credentials.
- Added CSRF validation to all mutating POST forms.
- Replaced direct JSON writes with atomic writes and backup recovery.
- Added core security/extraction/storage tests.

### Extraction Accuracy
- Added ACL parsing normalization for standard/extended rules.
- Added ACL-to-interface binding through `ip access-group` evidence.
- Added DHCP gateway-to-interface/VLAN matching.
- Added missing evidence detector.
- Added extraction confidence summary.

### Intelligence
- Upgraded Policy Diff to include trunk coverage, ACL direction, DHCP gateway matching, and applied guest isolation checks.
- Upgraded Root Cause cards with evidence reason, owner, confidence, verification commands, and recommended fixes.
- Added path-based simulation decisions.
- Added richer topology nodes/edges for SSID, VLAN, interface, ACL, DHCP, and CDP.
- Added snapshot object delta export.

### Reports & Product Polish
- Added HTML report export for every report type.
- Added audience-specific PDF content sections.
- Added evidence manifest detached checksum.
- Added project create/switch/delete actions.
- Added basic settings page for persisted report branding.
- Added security/privacy/disclaimer/license/env docs.

## v5.2.0 — Wireless Policy Manager Upgrade
- Added Wireless Manager page for SSID profiles, AP inventory, client sessions, event simulation, role-change demo, AP load analytics, validation matrix, scenario builder, and event-to-wired correlation.
- Added local SQLite database for registered users, audit trail, and durable wireless snapshots.
- Added Register page; first registered user becomes admin and later users become analysts.
- Added CSV/JSON wireless event import with association, disassociation, authentication failure, roaming, DHCP assignment, and policy violation support.
- Added advanced wireless anomaly engine and wireless risk scoring.
- Added Wireless Event & Policy Report export in JSON, HTML, and PDF.
- Improved UI styling, sticky wireless tabs, AP load cards, anomaly cards, and dashboard polish.

## v5.2.2 Responsive Workspace Patch
- Removed the fixed 1500px workspace cap so pages use available screen width.
- Added adaptive desktop/tablet/mobile grids for KPIs, cards, AP analytics, scenarios, forms, and tables.
- Improved sidebar behavior on tablet/mobile screens.
- Added horizontal-safe handling for large tables and sticky wireless tabs.

## v5.3 Global Product Layer

- Added rate-limited login/register security controls.
- Added strong password policy for SQLite users.
- Added role-aware action protection for admin/engineer/analyst/auditor workflows.
- Added SQLite schema migrations and migration visibility in Settings.
- Added 403/404/500 error pages and `/healthz` endpoint.
- Added database backup/restore workflow with safety backup.
- Added Policy Studio with configurable wireless policy rules.
- Added AP/SSID/client CRUD actions, including delete flows.
- Added client session lifecycle management.
- Added event timeline filters.
- Added evidence confidence scoring.
- Added generated remediation playbooks from wireless anomalies.
- Added connector import scaffold for WLC/AP inventory/RADIUS/DHCP/syslog CSV/JSON.
- Added compliance matrix and custom report builder.
- Added Docker Compose, deployment guide, admin guide, and user guide.
