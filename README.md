# WiGuard Nexus v5.1 — Security Foundation + Evidence Intelligence

WiGuard Nexus is a production-style wireless/wired policy intelligence platform for validating whether an expected wireless policy is actually enforced by the wired network evidence.

Workflow:

```text
Project → Import → Extract → Validate → Analyze → Report → Verify
```

## What changed in v5.1

### Security & Foundation

- Upload path traversal fixed through filename sanitization and UUID-based storage names.
- Flask debug mode disabled by default and controlled only through `FLASK_DEBUG`.
- Runtime secrets and admin settings moved to environment variables.
- Upload size limit added through `WIGUARD_MAX_UPLOAD_BYTES`.
- Basic login/logout added.
- CSRF protection added for mutating POST actions.
- JSON state storage now uses atomic writes plus `.bak` recovery.
- ZIP import hardened with member-count and size limits.
- Security-focused tests added under `tests/`.

### Extraction Accuracy

- ACL parser now normalizes standard/extended ACL expressions.
- ACL rules are bound to interfaces through `ip access-group` evidence.
- DHCP pools are matched to gateway interfaces/VLANs.
- Missing evidence detector warns when trunk, ACL, DHCP, CDP, or interface evidence is absent.
- Extraction confidence summary added.

### Intelligence

- Policy Diff v2 checks SSID/VLAN, DHCP scope, DHCP gateway, trunk coverage, ACL direction, and applied guest isolation.
- Root Cause cards are now evidence-based with owner, confidence, evidence reason, verification commands, and recommended fix.
- Simulation engine now records path-based decisions instead of a pure hardcoded pass/fail.
- Topology graph data now includes SSID, VLAN, interface, ACL, DHCP, and CDP nodes/edges.
- Snapshot comparison exports object-level delta.

### Reports & Product Polish

- JSON, PDF, and HTML report exports are available for every report type.
- Evidence ZIP includes HTML/JSON reports, artifacts, and state snapshot.
- Evidence manifest includes file sizes, SHA256 hashes, source hash, and detached `evidence_manifest.sha256`.
- Project CRUD added: create, switch, delete.
- Settings page added for persisted report branding.
- Added `SECURITY.md`, `PRIVACY.md`, `DISCLAIMER.md`, `LICENSE`, `CHANGELOG.md`, `.env.example`, `pyproject.toml`, and `Dockerfile`.

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

Default local login:

```text
username: admin
password: admin123
```

For production, do not use the fallback password. Configure environment variables first.

## Production environment

Copy `.env.example` and set at least:

```bash
WIGUARD_ENV=production
WIGUARD_SECRET_KEY=<long-random-secret>
WIGUARD_AUTH_REQUIRED=1
WIGUARD_ADMIN_USERNAME=admin
WIGUARD_ADMIN_PASSWORD_HASH=<werkzeug-generated-hash>
FLASK_DEBUG=0
```

Generate a password hash:

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('StrongPasswordHere'))"
```

## Recommended evidence bundle

For best accuracy, upload exported config/show-command text rather than raw `.pkt/.pka` binaries:

```text
show running-config
show vlan brief
show interfaces trunk
show interfaces switchport
show ip interface brief
show access-lists
show ip route
show cdp neighbors detail
show ip dhcp pool
```

Packet Tracer `.pkt/.pka` support remains best-effort because these files are proprietary binary formats. WiGuard can do printable evidence recovery and can use an external converter when `PTEXPLORER_PATH` is configured.

## Reports

The Report Center generates audience-specific exports:

- Executive Report
- Technical Network Report
- Security Escalation Report
- Audit Evidence Report
- Full Evidence Report

Each type supports:

- JSON
- HTML
- PDF

The Evidence ZIP includes artifacts, reports, `state_snapshot.json`, `evidence_manifest.json`, and `evidence_manifest.sha256`.

## Tests

```bash
python -m compileall -q app.py wiguard tests
python -m pytest -q
```

Core test coverage includes upload hardening, ACL binding, guest isolation, policy diff v2, path simulation, atomic storage, and CSRF route behavior.

---

## v5.2 Wireless Policy Manager Upgrade

This build expands WiGuard from a wired evidence validator into a lightweight wireless policy manager for the Project 4 scope.

### New wireless scope covered

- SSID profiles for Staff, Students, and Guests.
- SSID-to-VLAN, DHCP scope, access role, and allowed service mapping.
- AP inventory with uplink, supported VLANs, max clients, location, and status.
- Client session tracking with SSID, AP, VLAN, IP, role, and status.
- Event simulator for association, disassociation, authentication failure, roaming, DHCP assignment, and policy violations.
- CSV/JSON wireless event import.
- Role-change demo: Student to Staff with automatic VLAN/DHCP/access policy refresh.
- AP load analytics and client distribution.
- Wireless validation matrix.
- Event-to-wired correlation from wireless events back to AP uplink/VLAN policy.
- Advanced anomaly engine and wireless risk score.
- Wireless Event & Policy Report in JSON, HTML, and PDF.

### Local accounts and SQLite

WiGuard now creates a local SQLite database at `data/wiguard.sqlite3` by default. The first user registered through `/register` becomes an admin. Later users become analysts. The database stores users, audit log records, and wireless snapshots.

Emergency fallback login is still available for local demos using the environment variables in `.env.example`, but production usage should create registered SQLite users and set a strong `WIGUARD_SECRET_KEY`.

### Demo scenario

1. Open **Wireless Manager**.
2. Run **Student promoted to Staff** from Scenario Builder or use the Role Change Demo form.
3. Observe the user move from `StudentsWiFi / VLAN 20 / 10.10.20.0/24` to `StaffWiFi / VLAN 10 / 10.10.10.0/24`.
4. Review the Wireless Validation Matrix, AP Load Analytics, Event-to-Wired Correlation, and Wireless Report exports.

## v5.3 Global Product Layer Highlights

WiGuard Nexus now includes a stronger product layer around the Wireless Policy Manager:

- Rate-limited authentication, password policy, RBAC-aware actions, and production error pages.
- SQLite migrations, health endpoint, and backup/restore workflow.
- Policy Studio for configurable wireless assurance rules.
- Real AP/SSID/client CRUD and client session lifecycle controls.
- Filterable wireless event timeline.
- Event-to-wired path correlation, confidence scoring, advanced anomalies, and remediation playbooks.
- Vendor connector scaffold for CSV/JSON exports from WLC/AP inventory, RADIUS, DHCP, and syslog sources.
- Compliance matrix and custom report builder.
- Docker Compose, deployment notes, admin guide, and user guide.

### Health Check

```bash
curl http://127.0.0.1:5000/healthz
```

### Production Notes

Create a real admin from `/register`, then set:

```env
WIGUARD_ENV=production
WIGUARD_DISABLE_DEMO_FALLBACK=1
WIGUARD_SECRET_KEY=<strong-random-secret>
```
