# WiGuard Nexus v5.9.3 — Professional Quality Studio

### v5.8.9 Packet Tracer Fidelity + UI Cleanup

`.pkt/.pka` uploads now run automatically through the full background conversion path:

1. preserve the original file and calculate SHA-256,
2. probe `PTEXPLORER_PATH` or another configured converter if available,
3. recover embedded ZIP/XML/JSON/config text, wrapped streams, zlib chunks, and visible Cisco-like evidence,
4. generate `internal_pkt_bridge.xml`,
5. generate `internal_pkt_bridge.normalized.json`,
6. parse the bridge and decoded payloads into devices, interfaces, VLANs, links, IP inventory, policy evidence, and report artifacts.

The UI exposes `Background Auto-Conversion Pipeline` and `Decoded Native Payloads` so the upload result is transparent instead of a vague low understanding percentage.



WiGuard Nexus converts Packet Tracer labs, exported network configurations, and wireless evidence into a verified web workspace for policy validation, topology mapping, reporting, and evidence packaging.

```text
Tenant → Project → Upload → Convert → Validate → Map → Analyze → Report → Verify
```


## What is new in v5.9.1

- Import Diagnostics & Truth Contract: the UI now explains exactly why full-fidelity Packet Tracer claims are allowed or blocked.
- Topology Confidence Insights: confirmed/inferred edge counts, average edge confidence, orphan nodes, and next evidence suggestions.
- Rule Engine Readiness: rule counts, extracted policy controls, failed/review findings, risk atoms, verified input ratio, and rule gaps.
- Extra evidence artifacts: `import_diagnostics.json`, `topology_insights.json`, and `rule_assessment.json`.
- Report Builder Pro can include Packet Tracer diagnostics, topology confidence, and rule readiness in custom exports.

## What is new in v5.8.9


### v5.8.9 Fidelity and Reconstruction Layer

- Reconstructs flattened IOS-like commands from native `.pkt/.pka` printable segments before parsing.
- Adds an Extraction Fidelity Contract: `converter_verified`, `strong_visible_recovery`, `partial_visible_recovery`, or `opaque_native_binary`.
- Adds UI panels for verified object snapshot, reconstructed config lines, printable segment preview, and backend upload status.
- Exports `extraction_fidelity.json`, `reconstructed_config_preview.json`, and `printable_segments_preview.json` in the evidence package.
- Avoids fake 100% certainty for proprietary native binaries; the score reflects what was actually decoded and verified.

### Packet Tracer Conversion Lab

- Native `.pkt/.pka` intake with safe storage and SHA-256 source hash.
- Optional external XML converter support through `PTEXPLORER_PATH`.
- Internal XML → normalized JSON bridge for native `.pkt/.pka` files when no external converter is configured.
- Printable binary recovery fallback with visible IP/MAC/interface/SSID/config hints mapped into structured evidence.
- Conversion Readiness Score that honestly grades how much evidence was confirmed.
- Quality gates for device identity, interfaces, VLANs, ACLs, topology, line mapping, and native Packet Tracer reliability.
- Missing command checklist for `show running-config`, `show vlan brief`, `show interfaces trunk`, `show ip interface brief`, `show access-lists`, `show cdp neighbors detail`, `show spanning-tree`, `show port-security interface`, and `show etherchannel summary`.
- Relationship mapping: Interface ⇄ VLAN, DHCP ⇄ VLAN, ACL ⇄ Interface, and trunk coverage.
- New artifact: `packet_tracer_conversion_profile.json`.

### Deeper Cisco/Packet Tracer parser

The extractor now captures more than the original wired basics:

- Devices and hostnames.
- VLAN blocks and `show vlan brief` hints.
- Interfaces, routed ports, SVIs, dot1q subinterfaces, trunks, native VLANs, access VLANs.
- DHCP scopes and default-router matching.
- ACL rules and applied ACL bindings.
- Static/dynamic routing hints and NAT rules.
- CDP topology edges.
- IP inventory from `show ip interface brief`.
- Port Security configuration and show-output hints.
- Spanning Tree port states.
- EtherChannel summary.
- MAC address table and ARP table evidence.
- Device facts from show-version style output.

### UX/UI improvements

- Rebuilt Import Center into a conversion console.
- Clear readiness ring, quality gates, object coverage, relationship table, and command checklist.
- Upgraded Object Explorer with category tiles and evidence strips.
- Upgraded Topology page with path intelligence and trunk coverage panels.
- Better responsive styling for large dashboards and mobile views.

### Enterprise Core retained from v5.4

- Vendor connector scaffolding for Meraki, UniFi, Aruba Central, Cisco WLC, RADIUS, DHCP, Syslog, AP inventory, and WLC clients.
- Live event ingestion APIs.
- Tenant-aware projects/events/imports/snapshots.
- RBAC-aware UI and protected routes.
- API tokens with scopes.
- Job tracking, connector status, sync history, database backups, and audit logs.
- Evidence ZIP, JSON/HTML/PDF reports, and artifact manifest verification.

## Best accuracy workflow

Native Packet Tracer files are proprietary. WiGuard can safely store `.pkt/.pka` files and recover printable evidence, but the most accurate workflow is:

1. Open the Packet Tracer lab.
2. Export each device running-config as text.
3. Add these command outputs where possible:
   - `show running-config`
   - `show vlan brief`
   - `show interfaces trunk`
   - `show ip interface brief`
   - `show access-lists`
   - `show cdp neighbors detail`
   - `show spanning-tree`
   - `show port-security interface`
   - `show etherchannel summary`
   - `show mac address-table`
   - `show arp`
4. Put the files into one ZIP.
5. Upload the ZIP in the Import Center.
6. Review Conversion Readiness and Missing Command Checklist.
7. Generate reports and Evidence ZIP.

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

Default development fallback:

```text
username: admin
password: admin123
```

For production-like demos, create a real admin account from `/register`, then disable fallback login.

## Production environment

Copy `.env.example` and set at least:

```env
WIGUARD_ENV=production
WIGUARD_SECRET_KEY=<long-random-secret>
WIGUARD_DISABLE_DEMO_FALLBACK=1
WIGUARD_REGISTRATION_ENABLED=0
WIGUARD_SESSION_COOKIE_SECURE=1
```

Optional Packet Tracer converter:

```env
PTEXPLORER_PATH=C:\Tools\pt-explorer\pt-explorer.exe
```

## Validate build

```bash
python -m compileall -q wiguard tests app.py
python -m pytest -q
```

If `pytest` is not installed:

```bash
pip install -r requirements.txt
pip install pytest
python -m pytest -q
```

## Release

```bat
make_release.bat
```

## Important limitation

WiGuard does not claim to fully reverse Cisco Packet Tracer binary internals. It is designed to be evidence-honest: native binary recovery is marked lower confidence, while exported configs/show outputs are treated as evidence-grade inputs.

---

## v5.6 Enterprise Expansion Highlights

This version moves WiGuard closer to a real product layer instead of a visual-only demo:

- **Live ingestion:** UDP syslog listener controls, persistent raw logs, normalized event schema, severity score mapping, and deduplication fingerprints.
- **Background jobs:** worker start/stop, run-next, retry, attempts, progress, and status dashboard.
- **Report Builder Pro:** Executive, Technical, Compliance, Packet Tracer Conversion, Wireless Risk, Audit, Evidence Appendix, Wireless, and Full reports with preview/export paths.
- **Audit Center:** actor/action/severity/query filtering, CSV export, and tamper-evident hash-chain verification.
- **Production Auth:** user disable/enable, force logout, session list, reset tokens, invite tokens, API token revocation, and admin password change.
- **Policy Studio Engine:** condition builder fields, rule scope, severity score, control mapping, action type, remediation text, and rule versioning.
- **Validation Dataset:** Packet Tracer fixtures and tests for VLANs, router-on-a-stick, OSPF, NAT, trunk failure, port security, and EtherChannel evidence.
- **OpenAPI:** `openapi.yaml` documents the tenant-scoped API, event ingestion, polling, and jobs endpoints.



## v5.8 Deep Cleanup + Runtime Evidence Upgrade

This release upgrades WiGuard from a strong demo into a more defensible Packet Tracer evidence platform.

### New extraction layers
- `show vlan brief` parsing with VLAN-to-port mapping.
- `show access-lists` runtime match counters.
- `show interfaces` operational counters: input errors, output errors, CRC and drops.
- STP root bridge/root-port evidence.
- protocol summary signals for OSPF/EIGRP/RIP/BGP/NAT/DHCP/HSRP.
- VLAN crosscheck across configured VLANs, show vlan, DHCP gateway evidence, access/SVI evidence and operational trunks.
- runtime risk atoms for weak management plane, interface errors, missing trunk VLANs and zero-hit ACLs.
- coverage domains for Identity, L2/VLAN, L3/Routing, Security, Topology, Wireless and Operations.

### UI upgrades
- Import Center now shows Coverage Domains, VLAN Crosscheck, Runtime Risk Atoms and Runtime Counters.
- Policy Studio includes a Precision Cookbook and new rule templates for runtime proof and evidence completeness.
- Tables gain client-side search for large datasets.
- Dangerous actions now show confirmation prompts.
- Responsive behavior has been tightened for smaller screens.

### Code cleanup
- `test_connector_credentials` was renamed to `check_connector_credentials`; a non-collectable compatibility alias remains.
- Utility exception handling now uses typed exceptions and debug logging instead of broad silent failure.
- Added `tests/test_v58_cleanup_packet_policy.py`.
- Full test suite passes: 30 passed.

### v5.8.4 Deep Packet Tracer Import Intelligence

This build upgrades Packet Tracer JSON/XML ingestion with a deeper schema normalizer. The importer can now understand nested device/interface/link/VLAN/DHCP/ACL structures, XML child tags, endpoint-array topology links, embedded configs, endpoint inventory, and validation findings. `/import` now shows a schema path map and structured validation findings so analysts can see exactly what the file proved and what still needs stronger evidence.


### v5.8.9 Native PKT XML/JSON Bridge + Fidelity

This build improves the exact weak point that caused low understanding percentages on Packet Tracer uploads. Native `.pkt/.pka` files are still proprietary, so WiGuard stays evidence-honest and does not invent topology from opaque binary noise. However, the importer now creates an internal XML bridge and a normalized JSON profile from every safely recoverable clue: printable strings, zlib chunks, binary signatures, IP candidates, MAC candidates, interface names, SSID/wireless hints, and Cisco-like config lines.

The `/import` page now shows the bridge output directly, including XML preview, normalized JSON preview, visible evidence counts, and artifact files:
- `internal_pkt_bridge.xml`
- `internal_pkt_bridge.normalized.json`
- `internal_xml_bridge.json`
- `packet_tracer_conversion_profile.json`

For exported JSON/XML, the normalizer now understands more Packet Tracer converter shapes such as nested `attributes`, `properties`, `config`, `ports`, `connections`, and `logicalTopology` wrappers, then turns them into devices, interfaces, VLANs, links, endpoint inventory, schema map entries, and validation findings.

## v5.9.0 — Verified Packet Tracer Extraction System

- Added optional companion export upload for native `.pkt/.pka` files so exported configs/XML/JSON/ZIP bundles can be merged with native recovery.
- Added an Evidence Registry that classifies each extracted object as `verified`, `recovered`, `inferred`, or `unmapped` with line/path/source evidence.
- Added a Verified Extraction Contract showing when full-fidelity claims are allowed and which exports are still required.
- Added artifact exports: `evidence_registry.json`, `verified_extraction_contract.json`, and `companion_exports.json`.
- Improved Import and Object Explorer UI with companion-export guidance, fidelity contract cards, and registry tables.
- Added tests for native Packet Tracer + companion export merging and verified export parsing.

### v5.9.3 Professional Quality Studio

This release adds a truth-first quality layer on top of Packet Tracer extraction. Native `.pkt/.pka` parsing is still treated as best-effort unless a companion export/config bundle is supplied, but the UI and reports now make that contract explicit.

New professional gates:

- Evidence Quality Matrix per object category.
- Analyst Sign-off for executive/technical publish readiness.
- Forbidden/allowed claim tracking for full-fidelity Packet Tracer reports.
- Object Explorer filtering by `verified`, `recovered`, `inferred`, and `unmapped` evidence states.
- Dedicated `quality` report type and custom report sections.
