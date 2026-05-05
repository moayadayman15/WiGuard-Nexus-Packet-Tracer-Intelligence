# WiGuard Nexus

<p align="center">
  <strong>Network evidence intelligence for Packet Tracer, wireless policy validation, topology review, and professional security reporting.</strong>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-blue">
  <img alt="Flask" src="https://img.shields.io/badge/Flask-3.x-black">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green">
  <img alt="Status" src="https://img.shields.io/badge/Release-v5.16.1-success">
  <img alt="Tests" src="https://img.shields.io/badge/tests-93%20passed-brightgreen">
</p>

---

## Overview

**WiGuard Nexus** is a Flask-based cybersecurity and network analysis platform designed to turn network evidence into a clean analyst workspace.

It helps analysts import Packet Tracer files, exported configs, JSON/XML/CSV evidence, and wireless event data, then normalize the results into devices, interfaces, VLANs, topology links, findings, risk context, reports, and verifiable evidence packages.

```text
Tenant → Project → Upload → Decode → Normalize → Validate → Analyze → Report → Verify
```

WiGuard is built for cybersecurity students, network engineers, wireless analysts, and DFIR-style reviewers who need clear evidence instead of noisy raw exports.

---

## Screenshot Placeholders

> Replace these placeholders with real screenshots before publishing the repository.

| Area | Screenshot to add |
|---|---|
| Command Dashboard | `[SCREENSHOT: Command Dashboard / Overview]` |
| Import Center | `[SCREENSHOT: File upload, validation, and extraction result]` |
| Object Explorer | `[SCREENSHOT: Normalized devices, interfaces, VLANs, and evidence rows]` |
| Topology / Threat Map | `[SCREENSHOT: Topology or threat map view]` |
| System Health | `[SCREENSHOT: Dependency and backend health page]` |
| Report Export | `[SCREENSHOT: Professional HTML/PDF/JSON report output]` |

---

## Core Features

### Evidence Import Pipeline

- Imports JSON, XML, CSV, TXT, LOG, CFG, CONF, ZIP evidence bundles, and Packet Tracer `.pkt/.pka` files.
- Stores uploaded evidence safely with generated filenames and source hashes.
- Validates unsupported, empty, oversized, and unsafe archive inputs with friendly errors.
- Generates normalized data for UI tables, APIs, reports, and future parser layers.

### Packet Tracer Evidence Handling

- Accepts native `.pkt/.pka` files as evidence.
- Supports best-effort decoding, hashing, manifest generation, and recoverable evidence extraction.
- Can merge companion exports such as running-config, show-command output, XML, JSON, or CSV.
- Supports optional external Packet Tracer converter hooks through environment variables.
- Does **not** fake full proprietary Packet Tracer topology extraction when the evidence does not prove it.

### Normalized Network Model

WiGuard converts raw input into structured objects such as:

- Devices and hostnames
- Interfaces and IP addresses
- VLANs and switchport context
- Routes and topology links
- Wireless SSIDs, AP inventory, and client sessions
- Security rules, ACL evidence, and policy controls
- Findings, confidence summaries, and evidence rows

### Wireless Policy Manager

- Manage SSID profiles, expected roles, VLANs, DHCP scopes, AP inventory, and client sessions.
- Import or simulate wireless events such as roaming, authentication failures, DHCP assignment, and policy violations.
- Correlate wireless behavior with wired/network evidence.
- Use scenario builders for demo and validation workflows.

### Risk & Intelligence Layer

- Evidence-based finding generation.
- Conservative severity classification.
- Weak/open wireless security checks.
- Cleartext credential indicators with redaction.
- Duplicate IP candidates.
- Segmentation and missing ACL/firewall evidence indicators.
- Interface hygiene and exposed management service context when evidence exists.

### Reporting & Evidence Exports

- JSON, HTML, and PDF reports.
- Custom report builder with selectable sections.
- Professional normalized analysis exports.
- Evidence package ZIP export.
- Artifact manifest verification.
- Secret redaction for imported evidence and generated reports.

### Administration & Security Controls

- Login-protected routes.
- Role-aware access control.
- CSRF protection for mutating actions.
- SQLite-backed users, sessions, audit logs, API tokens, backups, and restore flow.
- Security headers including `X-Frame-Options`, `X-Content-Type-Options`, CSP, and referrer policy.
- Production mode requires a strong secret key.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask, Werkzeug |
| UI | Jinja2 templates, CSS, vanilla JavaScript |
| Storage | JSON state + SQLite application database |
| Parsing | Python parsers, TextFSM, NTC templates |
| Graph / Topology | NetworkX |
| Reports | HTML, JSON, ReportLab PDF |
| Security | CSRF, session controls, upload validation, redaction |
| Testing | Pytest |

Optional stacks are available for advanced network, AI, and product extensions through separate requirements files.

---

## Project Structure

```text
WiGuard_Nexus/
├── app.py                         # Flask application bootstrap
├── main.py                        # Windows-friendly startup entry point
├── requirements.txt               # Core runtime dependencies
├── requirements-dev.txt           # Development/testing dependencies
├── requirements-network.txt       # Optional network automation stack
├── requirements-ai.txt            # Optional AI/RAG stack
├── openapi.yaml                   # API contract
├── wiguard/
│   ├── routes/                    # UI/API/action routes
│   ├── services/                  # Import, parsing, reporting, storage, intelligence
│   ├── templates/                 # Web interface pages
│   ├── static/                    # CSS and JavaScript assets
│   └── internal_tools/            # Preflight, dependency checks, cleanup tools
├── data/
│   ├── samples/                   # Demo/sample evidence
│   ├── uploads/                   # Runtime upload storage
│   ├── artifacts/                 # Generated extraction artifacts
│   └── reports/                   # Generated reports
├── docs/                          # Architecture, import, parser, reporting, risk docs
└── tests/                         # Regression and release test suite
```

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/wiguard-nexus.git
cd wiguard-nexus
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Windows:

```bat
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Run WiGuard Nexus

```bash
python main.py
```

Open:

```text
http://127.0.0.1:5000
```

Default local demo login:

```text
Username: admin
Password: admin123
```

> Change the default credentials and secret key before using the app outside a local demo environment.

---

## Windows Helpers

The project includes Windows-friendly scripts:

```bat
setup_windows.bat
run_windows.bat
test_windows.bat
START_BACKEND_WINDOWS.bat
```

Typical Windows flow:

```bat
setup_windows.bat
run_windows.bat
```

---

## Running Tests

```bash
python -m pytest -q
```

Release audit status for v5.16.1:

```text
93 tests passed
Startup smoke: PASS
Preflight: PASS
Health endpoint: PASS
```

Run the preflight checker:

```bash
python -m wiguard.internal_tools.preflight_check
```

---

## Supported Import Formats

| Format | Status | Notes |
|---|---:|---|
| `.json` | Supported | Structured exports and nested evidence payloads |
| `.xml` | Supported | Network/export/converter XML evidence |
| `.csv` | Supported | Tables, events, inventory, connector data |
| `.txt`, `.log`, `.cfg`, `.conf` | Supported | Running-config and show-command evidence |
| `.zip` | Supported | Safe bundle intake with limits and validation |
| `.pkt`, `.pka` | Limited native evidence | Hashing, storage, manifest, best-effort recovery, optional converter/companion evidence |

Recommended evidence for strong results:

```text
show running-config
show ip interface brief
show vlan brief
show interfaces trunk
show access-lists
show ip route
show cdp neighbors detail
Packet Tracer XML/JSON exports when available
```

---

## Important Packet Tracer Truth Contract

Packet Tracer native `.pkt` and `.pka` files are proprietary binary formats. WiGuard Nexus can store them, hash them, inspect recoverable content, generate evidence manifests, and merge companion exports.

However, WiGuard does **not** claim full topology extraction from opaque native files unless the evidence proves it.

For professional results, upload companion evidence such as:

- exported running configuration
- show-command output
- XML/JSON export
- CSV inventory
- converter output

This keeps reports honest, reproducible, and defensible.

---

## Key Pages

| Page | Purpose |
|---|---|
| `/` | Command dashboard and project overview |
| `/import` | Evidence upload, validation, and extraction pipeline |
| `/workspace` | Active extraction workspace |
| `/objects` | Normalized object explorer |
| `/topology` | Topology context and relationship view |
| `/threat-map` | Security/risk visualization |
| `/wireless` | Wireless policy manager |
| `/reports` | Report builder and exports |
| `/system-health` | Runtime, dependency, and backend health |
| `/settings` | Users, tokens, jobs, backup/restore, and admin controls |

---

## Useful API / Export Endpoints

| Endpoint | Description |
|---|---|
| `GET /healthz` | Lightweight health check |
| `GET /api/system-health` | Detailed system health payload |
| `GET /api/normalized-data` | Normalized professional data export |
| `POST /api/import` | JSON-friendly evidence import endpoint |
| `GET /api/state` | Current application state summary |
| `GET /api/events` | Event stream data |
| `GET /api/jobs` | Background job status |
| `GET /download/professional-analysis.json` | Professional JSON export |
| `GET /download/professional-analysis.html` | Professional HTML export |
| `GET /download/evidence-package.zip` | Evidence package export |

See `openapi.yaml` and `API.md` for more details.

---

## Configuration

Important environment variables:

| Variable | Purpose |
|---|---|
| `WIGUARD_ENV` | Use `production` for production-like deployment |
| `WIGUARD_SECRET_KEY` | Required strong Flask secret in production |
| `WIGUARD_HOST` | Bind host, default `127.0.0.1` |
| `WIGUARD_PORT` | Bind port, default `5000` |
| `WIGUARD_AUTH_REQUIRED` | Enable/disable route authentication |
| `WIGUARD_DISABLE_DEMO_FALLBACK` | Disable demo fallback authentication |
| `WIGUARD_MAX_UPLOAD_BYTES` | Maximum upload size |
| `WIGUARD_DB_PATH` | SQLite database path |
| `WIGUARD_DATA_FILE` | JSON state file path |
| `WIGUARD_PKT_CONVERTER_PATH` | Optional Packet Tracer converter path |
| `WIGUARD_PKT_CONVERTER_ARGS` | Optional converter argument template |

Production minimum:

```bash
export WIGUARD_ENV=production
export WIGUARD_SECRET_KEY="change-this-to-a-long-random-secret"
export WIGUARD_DISABLE_DEMO_FALLBACK=1
export FLASK_DEBUG=0
```

---

## Docker

```bash
docker compose up --build
```

Health check:

```text
GET /healthz
```

---

## Documentation

| File | Description |
|---|---|
| `docs/ARCHITECTURE.md` | Runtime flow and module design |
| `docs/DATA_IMPORT_GUIDE.md` | Supported evidence types and import behavior |
| `docs/PARSER_GUIDE.md` | Parser design and extension notes |
| `docs/RISK_ENGINE.md` | Finding schema and severity logic |
| `docs/REPORTING.md` | Report/export behavior |
| `docs/TROUBLESHOOTING.md` | Common issues and fixes |
| `SECURITY.md` | Security model and production guidance |
| `DEPLOYMENT.md` | Local and Docker deployment notes |
| `USER_GUIDE.md` | User workflow and wireless manager guide |

---

## Security Notes

WiGuard handles sensitive network evidence. Treat uploads, generated artifacts, reports, and backups as confidential.

Implemented safeguards include:

- authentication gate for application routes
- CSRF checks for mutating requests
- upload extension allowlist
- archive traversal protection
- upload size limits
- safe filename handling
- secret redaction in reports and artifacts
- application security headers
- database backup and restore integrity checks

Before production use:

- set a strong `WIGUARD_SECRET_KEY`
- disable demo fallback authentication
- change default credentials
- run behind HTTPS
- restrict access to trusted users
- keep generated evidence packages private

---

## Current Limitations

- Native `.pkt/.pka` files are proprietary and are handled as limited native evidence unless companion exports or converter output are provided.
- SQLite is the default durable app database for this release.
- PDF reporting requires `reportlab` from `requirements.txt`.
- Some optional advanced stacks require separate installation from the optional requirements files.

---

## Release Status

Current release:

```text
WiGuard Nexus v5.16.1 Professional Hardening
```

Final audit result:

```text
PASS — ready for GitHub/demo/submission after cleanup of generated runtime artifacts.
```

Verified commands:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python main.py
python -m wiguard.internal_tools.preflight_check
```

---

## License

This project is released under the **MIT License**. See `LICENSE` for details.

---

## Suggested Repository Topics

```text
cybersecurity, flask, network-security, packet-tracer, wireless-security, dfir, evidence-analysis, topology, security-reporting, python
```
