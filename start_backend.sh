# v5.15.0 - Network Intelligence Engine

- Added Intelligence Engine product cockpit.
- Added optional dependency health for NetworkX, TextFSM, NTC Templates, Scapy, Ollama, SentenceTransformers, ChromaDB, FAISS, PyBatfish, Netmiko, NAPALM, and Nornir.
- Added Topology Brain health scoring and critical-node/blast-radius analysis.
- Added AI Root Cause v2 prompt/readiness package.
- Added optional requirements files for product, AI, network, and development stacks.


## v5.13.1-import-cleanup-and-map-json

- Added object-map JSON extraction for `devices: {R1: ...}` and `interfaces: {Gig0/0: ...}` schemas.
- Added endpoint alias support for `sourceId/targetId/srcId/dstId/fromId/toId/localId/remoteId`.
- Fixed `portId/interfaceId` interface extraction from wrapped Packet Tracer exports.
- Hardened export redaction for Cisco `enable secret 5 <hash>` and related credentials.
- Added upload size limits and debug logging for upload stream rewind failures.
- Cleaned release hygiene checks and added v5.13.1 tests.
- Verified full test suite: 76 passed.

# v5.13.0 — JSON + Packet Tracer Data Extraction Upgrade

- Strengthened JSON normalizer for nested Packet Tracer/export schemas.
- Fixed false interfaces created from device/node rows.
- Fixed false topology links created from parent containers.
- Added stronger `nodeId/deviceId/objectId/uuid` to hostname resolution for links.
- Promoted nested `ipv4` and `switchport` blocks into canonical interface fields.
- Improved Packet Tracer converter XML profile so links use real hostnames and preserve local/remote ports.
- Added regression tests in `tests/test_v5130_json_pkt_data_extraction.py`.

# v5.12.9 — Packet Tracer Extraction Fix

- Fixed external `.pkt/.pka → XML` converter execution for ptexplorer/pka2xml-style tools by adding the `-d input output` adapter and safer Python script execution.
- Added local converter auto-discovery in project root, tools/, tools/packet_tracer/, converters/, vendor/, and upload directory.
- Fixed false XML/JSON interface extraction caused by substring matching (`packetTracerExport` was accidentally matching `port`).
- Fixed VLAN naming so interface `vlanId` creates VLAN evidence without using the interface name as the VLAN name, then enriches with real VLAN labels such as `Users`.
- Added live evidence counters for `evidence_registry` and `external_converter_outputs`.

# Changelog

## 5.12.8-diagnose-startup-fix
- Fixed Windows launcher diagnosis so hygiene warnings do not block backend startup.
- Separated fatal syntax errors from release-cleanliness warnings.
- Removed generated cache artifacts from the packaged ZIP.

## v5.12.7 - Diagnose Fix

- Fixed local startup failure caused by code hygiene scanning `.venv` dependency caches.
- Diagnostics now ignore generated virtual environment artifacts while still catching project-level pycache/pyc files.
- Added `DIAGNOSE_FIX_v5_12_7.md`.

## v5.12.6 — Code Cleanup + State Schema Hardening

- Removed Python cache artifacts from the release handoff.
- Added a shared `state_schema` layer so app boot, pages, API state, and tenant views use one normalized JSON shape.
- Added a lightweight `code_quality` scanner and admin `/api/code-quality` endpoint for syntax/cache/TODO hygiene checks.
- Improved diagnostic script so release checks validate upload routes and project hygiene, not only dependencies.
- Replaced several nested silent fallback logging blocks with `log_safely()` so failures stay visible without breaking user workflows.
- Hardened JSON storage loading so invalid/non-dict state recovers to a normalized seed shape instead of blanking the UI.

## v5.12.5 — UI Density + Packet Tracer XML Profile Cleanup

- Added Import Center density modes: Executive, Analyst, and Deep.
- Added `wiguard.services.pkt_xml_profile` to extract real topology objects from non-standard Packet Tracer converter XML.
- XML imports and converter payloads now get a targeted topology pass before regex/universal indexing.
- Removed fake synthetic device creation and replaced it with an honest warning.
- Fixed duplicate `conversion-pipeline-rail` DOM ID and XML `records_walked` diagnostics.

## v5.12.4 — Packet Tracer XML Converter Hardening

- Added a real external `.pkt/.pka` → XML/JSON converter adapter layer with support for `WIGUARD_PKT_CONVERTER_PATH`, `PACKET_TRACER_CONVERTER_PATH`, `PTEXPLORER_PATH`, `PKT2XML_PATH`, `CPT_XML_CONVERTER_PATH`, and customizable `WIGUARD_PKT_CONVERTER_ARGS`.
- Converter output is now merged into the native Packet Tracer pipeline before internal XML bridge generation, normalized JSON generation, object extraction, evidence mapping, and artifacts.
- Import Center shows converter status, adapter attempts, parsed converter outputs, XML preview, and clear next actions instead of silent failure.
- Artifacts now include `external_converter_outputs.json` and external converter XML previews when available.
- Improved package import hygiene by moving app-only service imports inside `create_app()`, keeping parser/import modules lightweight for tests and CLI tooling.

## v5.12.2 — Import UI Cleanup

- Fixed the tall empty Conversion Readiness column by removing forced equal-height behavior and making the meter compact/sticky only on wide screens.
- Added an Import Focus Rail so analysts can jump between Upload, Truth Board, Payload Intelligence, Native Proof, and Artifacts.
- Collapsed the noisy deep extractor sections into an Advanced Evidence Vault to reduce page clutter while keeping all technical detail available.
- Improved live result cards, spacing, hover states, table density, status chips, and responsive behavior.


## v5.12.1 — Live Import Readiness Sync

- Fixed the Import page issue where the left live upload card showed a successful Packet Tracer import while the right Conversion Readiness panel still displayed 0% / Not uploaded yet.
- Added live DOM synchronization for readiness percentage, trust ladder, parser mode, object count, next action, and pipeline rail after AJAX upload.
- Fixed the live result card layout so it spans the full import action row instead of appearing cramped.
- Fixed the readiness panel grid alignment so the quality meter content stays at the top instead of leaving a large empty gap.
- Extended the JSON upload response with source bytes, printable line count, and technical report gate data.


## v5.12.0 — Deep Payload + PKT/XML/JSON Bridge

- Added `universal_import.py`, a recursive payload visibility layer for JSON, XML-derived payloads, and internal Packet Tracer bridge JSON.
- JSON imports now generate a deterministic XML bridge, normalized JSON preview, source tree, key/value evidence index, network fact candidates, and table summaries.
- Native `.pkt/.pka` imports now run the internal bridge JSON through the same universal payload walker, so the UI can expose recovered Packet Tracer details instead of only showing counters.
- Added Import Center panels for Deep Payload Intelligence: payload nodes, leaf values, network facts, tables, key/value rows, and tree preview.
- Added Workspace panels for Deep Data Extraction Layer so analysts can inspect JSON/PKT bridge data without jumping between many pages.
- Added artifacts: `universal_payload_bridge.xml`, `universal_payload.normalized.json`, `source_key_value_index.json`, `universal_network_facts.json`, `payload_tables.json`, and source conversion manifests.
- Updated object counters, conversion profile quality gates, and workspace object sections to include the new universal extraction layers.
- Kept native Packet Tracer claims honest: proprietary `.pkt/.pka` recovery remains best-effort unless exported configs/XML/JSON or a converter is supplied.

## v5.11.0 — Unified Analyst Workspace

- Reorganized the product around five clear workflow surfaces: Command Dashboard, Import & Extraction, Analyst Workspace, Analysis Studio, and Report Builder.
- Added Import Truth Board with What we know / What we extracted / What is missing / Why / How to improve accuracy.
- Added unified Analyst Workspace for topology nodes, object tree, evidence mapping, and timeline in one page.
- Added Analysis & Policy Studio combining policy diff, rule packs, risk scoring, root cause, simulation history, playbooks, and report readiness.
- Simplified sidebar navigation and moved older specialized pages into an Advanced Tools accordion.
- Added report workflow gate to prevent exaggerated Packet Tracer fidelity claims when evidence is partial.
- Added v5.11 UI interactions for workspace object search and node side-panel inspection.

# WiGuard Nexus v5.10.0 — Premium Import Command Center

## Improved
- Redesigned the Import page hero into a product-style Import Command Center.
- Added a four-stage command strip: Intake, Decode, Normalize, Validate.
- Rebuilt the upload cockpit with a stronger Packet Tracer dropzone, native/structured/companion evidence lanes, and selected-file telemetry before upload.
- Added a premium readiness/trust ladder so analysts can see whether the file was accepted, parsed, object-visible, and report-safe.
- Made the Native Import Truth Layer always visible, so weak or opaque Packet Tracer uploads do not look like silent empty failures.
- Improved live upload UX with stronger processing copy and clearer mode styling for native vs structured evidence.

## Verified locally
- Python modules compile successfully.
- Jinja templates parse successfully.
- Full Flask route smoke test could not run in this container because Flask is not installed here; install `requirements.txt` locally and run the backend normally.

## v5.9.9 — Native Import Visibility + Import Studio Polish
- Fixed Packet Tracer native uploads appearing empty by always exposing native source manifest, binary evidence summary, XML bridge, normalized JSON preview, and raw evidence fallback.
- Added native evidence keys to live object counters so the Import Center no longer shows misleading zero results after successful `.pkt/.pka` intake.
- Improved Import Center UI with a stronger dropzone, companion export UX, live native proof cards, and responsive polished import panels.
- Preserved truthful limitations: native `.pkt/.pka` full topology still requires exported show-command/config/XML/JSON evidence or a configured converter.

# v5.9.8 — Deep UI/Data Fidelity Recovery

- Added a deep IOS command index (`all_config_commands`) so useful Packet Tracer/config details are preserved even when they do not map to a classic normalized object.
- Added interface feature extraction for voice VLANs, PortFast, BPDU Guard, storm-control, EtherChannel, helper addresses, speed/duplex/MTU, and protected/private VLAN hints.
- Added management service extraction for default gateway, DNS, domain, NTP, syslog, SNMP, AAA, SSH/HTTP, and VTY access settings with secret redaction.
- Added gateway redundancy extraction for HSRP/VRRP/GLBP.
- Added routing protocol detail extraction for OSPF/EIGRP/RIP/BGP process child commands.
- Added a data fidelity scorecard to the Import Center and Object Explorer.
- Improved native `.pkt/.pka` recovery with UTF-16 payload promotion and deeper high-value config reconstruction.
- Polished Object Explorer, evidence cards, category tiles, table handling, responsive layout, and dark-mode diagnostic panels.
- Updated runtime metadata so the UI no longer appears rolled back after starting from an older state file.


## v5.9.8 — UI Extraction Studio + Deeper Packet Tracer Recovery

- Reworked the workspace UI with a cleaner full-width layout, better responsive behavior, stronger Object Explorer grids, improved filter rows, polished cards, safer table overflow, and a premium login/import experience.
- Strengthened native `.pkt/.pka` recovery with UTF-16 string extraction, broader valid zlib stream discovery, embedded ZIP-at-offset recovery, embedded gzip/bzip2/xz stream recovery, and richer device/IP/interface/VLAN hints.
- Added operational-table promotion so `show ip interface brief`, `show vlan brief`, MAC tables, ARP tables, and interface-status evidence now populate searchable interface, IP, endpoint, and VLAN membership objects.
- Added CDP table parsing in addition to CDP detail parsing.
- Kept the evidence truth contract: native Packet Tracer binary parsing is still marked partial unless exported configs/XML/JSON/converter evidence proves full fidelity.

## v5.9.6 — Login Recovery + Packet Tracer Extraction Repair

- Fixed the Import Center backend/UI contract after the UI refactor by adding JSON/AJAX upload support while keeping the old POST/redirect fallback.
- Added live upload result cards showing source mode, readiness, XML bridge bytes, normalized JSON bytes, object counts, and pipeline stages immediately after upload.
- Hardened file-field compatibility for `network_file`, `packet_file`, `evidence_file`, `file`, `upload`, and `network_upload`.
- Promoted recovered native `.pkt/.pka` conversion text into the active extraction preview so successful native uploads no longer appear blank.
- Improved job progress metadata, error logging, and JSON error responses for failed imports.
- Preserved the truth contract: native Packet Tracer files still run through converter probe → internal XML bridge → normalized JSON → object extraction without fake 100% fidelity claims.

## v5.9.3 — Professional Quality Studio

- Added an Extraction Quality & Analyst Sign-off report type.
- Added evidence quality matrix rendering to reports and custom report exports.
- Added analyst sign-off gates to prevent unsupported 100% Packet Tracer fidelity claims.
- Added object explorer filters for evidence state and high-value evidence.
- Added UI quality gate panels in Import Center and Report Builder.
- Added artifact coverage for `evidence_quality_matrix.json`, `analyst_signoff.json`, and `topology_graph.dot`.

## v5.9.1 — Diagnostics, Topology Confidence, and Rule Readiness

- Added Import Diagnostics & Truth Contract cards that explain why a native `.pkt/.pka` import can or cannot claim full fidelity.
- Added blocker detection for missing companion exports, missing interfaces/VLANs, low verified high-value object ratio, and missing L2 neighbor evidence.
- Added Topology Confidence Insights with node/edge counts, confirmed vs inferred edges, average edge confidence, orphan nodes, and evidence suggestions.
- Added Rule Engine Readiness with enabled rule counts, extracted policy controls, failed/review findings, verified-input ratio, and validation gaps.
- Added new artifacts: `import_diagnostics.json`, `topology_insights.json`, and `rule_assessment.json`.
- Updated report builder and full HTML reports to include diagnostics, topology confidence, and rule readiness sections.
- Added targeted tests for v5.9.1 diagnostic behavior on native Packet Tracer imports and native + companion export workflows.



## v5.9.0 — Verified Packet Tracer Extraction System

- Added optional companion export upload for native `.pkt/.pka` files so exported configs/XML/JSON/ZIP bundles can be merged with native recovery.
- Added an Evidence Registry that classifies each extracted object as `verified`, `recovered`, `inferred`, or `unmapped` with line/path/source evidence.
- Added a Verified Extraction Contract showing when full-fidelity claims are allowed and which exports are still required.
- Added artifact exports: `evidence_registry.json`, `verified_extraction_contract.json`, and `companion_exports.json`.
- Improved Import and Object Explorer UI with companion-export guidance, fidelity contract cards, and registry tables.
- Added tests for native Packet Tracer + companion export merging and verified export parsing.

## 5.8.9 — Packet Tracer Fidelity, Reconstruction, and UI Cleanup

- Added printable segment reconstruction for native `.pkt/.pka` uploads so flattened IOS fragments are rebuilt into parseable command lines before XML/JSON normalization.
- Added an Extraction Fidelity Contract in the UI and artifacts; the system now labels native imports as converter-verified, strong visible recovery, partial visible recovery, or opaque native binary instead of pretending to have perfect certainty.
- Added reconstructed config and printable segment artifacts/previews, improved Native PKT dashboard cards, and cleaned upload status feedback.
- Expanded artifact exports for extraction fidelity and reconstructed previews.
- All tests pass after cleanup.

- Forced every `.pkt/.pka` upload through an automatic background chain: external converter probe → container/compression recovery → internal XML bridge → normalized JSON → object extraction.
- Added decoded native payload tracking for embedded ZIP members, wrapped streams, zlib chunks, printable XML, printable JSON, and config-like Cisco evidence.
- Added `auto_conversion_pipeline` and `decoded_payloads` artifacts plus UI tables so the user can see exactly what ran in the background.
- Updated source mode to `pkt_auto_xml_json_bridge` so native Packet Tracer uploads no longer look like plain binary string inspection.
- Kept honest evidence rules: WiGuard does not invent topology from opaque binary noise; it extracts only converter output, decoded payloads, and recoverable visible evidence.

## 5.8.7 — Native PKT XML/JSON Bridge & Deep JSON Wrapper Understanding
- Added an internal XML → normalized JSON bridge for native `.pkt/.pka` imports. WiGuard now generates `internal_pkt_bridge.xml` and `internal_pkt_bridge.normalized.json` from safely recoverable visible evidence instead of stopping at raw printable strings.
- Improved Packet Tracer-style JSON understanding for nested `attributes`, `properties`, `config`, `ports`, `connections`, `logicalTopology`, and wrapper records.
- Added UI panels on `/import` showing bridge byte counts, visible evidence counts, XML preview, and normalized JSON preview so analysts can see exactly what was understood.
- Filtered raw converter wrapper rows so nested JSON is normalized into real devices/interfaces/VLANs/links instead of being displayed as unreadable raw objects.
- Added artifact exports and regression tests for the XML/JSON bridge and nested Packet Tracer JSON wrappers.

## 5.8.5 — Packet Tracer Lab Matrix Intelligence
- Added first-class understanding for JSON lab-result matrices (`client`, `target`, `service`, `result`, `actual_ssid`, `actual_vlan`, `actual_ip`, `ap_name`).
- Converts observed access checks into access tests, client access matrix rows, endpoint inventory, SSID/VLAN/AP evidence, service inventory, roaming events, policy controls, schema map entries, and validation findings.
- Import UI now shows a dedicated Lab Result Matrix Intelligence panel with client summaries and access-test evidence instead of meaningless zero-heavy topology metrics.
- Added review findings for missing expected policy baselines and DNS/Internet reachability inconsistencies.

## v5.8.3 — Packet Tracer JSON/XML Intelligence

- Rebuilt JSON/XML import handling so exported Packet Tracer evidence is normalized as structured data, not treated as unreadable raw text.
- Added schema-tolerant extraction for devices, interfaces, VLANs, trunk settings, DHCP pools, topology links, routes, ACL-like rules, inventory facts, and wireless/SSID hints.
- Added embedded config/show-output recovery from JSON/XML fields such as `config`, `runningConfig`, `cli`, `output`, `show`, and `commandOutput`, then sends those chunks through the classic Cisco parser.
- Added `json_structured` and `xml_structured` source modes with stronger confidence scoring and visible pipeline status.
- Added a Structured JSON/XML Understanding panel on `/import` showing records walked, embedded config chunks, detected sections, schema hints, and normalizer status.
- Added path-level evidence mapping using `source_path` for structured objects so reports can still prove where a fact came from even when there is no line number.
- Kept native `.pkt/.pka` honest: originals are stored, printable text is recovered, and evidence-grade accuracy still comes from exported XML/JSON/config/show bundles.

## v5.8.2 — Page/Data Hardening Hotfix

- Fixed `/import` 500 caused by Jinja resolving `d.keys` as the built-in dictionary method instead of the coverage-domain `keys` list.
- Added extracted-object sanitization so partial parser output, `None` list rows, or `evidence: null` no longer crash topology/policy/report widgets.
- Hardened `build_topology()` around malformed policy-control rows.
- Import persistence now sanitizes objects before counting/saving and saves JSON state even if dashboard normalization logs an error.

## 5.8.0-deep-cleanup-ui-policy-runtime — 2026-04-28
- Added runtime evidence extraction: VLAN brief, ACL hit counters, interface counters, STP root and protocol summary.
- Added VLAN cross-layer consistency analysis and risk atom generation.
- Added coverage-domain scoring to the Packet Tracer conversion profile.
- Expanded Report/Import UI with domain coverage, VLAN crosscheck, runtime risk atoms and counter evidence.
- Expanded Policy Studio defaults with ACL runtime hits, VLAN trunk crosscheck, interface error health and evidence completeness.
- Added table search, confirmation prompts and responsive UI refinements.
- Renamed `test_connector_credentials` to `check_connector_credentials` while keeping a pytest-safe compatibility alias.
- Added v5.8 regression tests.
- Validation: compileall passed; pytest passed with 30 tests.


## v5.5.0 — Packet Tracer Intelligence

- Rebuilt Import Center into Packet Tracer Conversion Lab.
- Added conversion readiness score and quality gates.
- Added missing command checklist for evidence-grade imports.
- Added relationship mapping for Interface/VLAN/DHCP/ACL/trunks.
- Added extraction categories: IP inventory, port security, spanning tree, EtherChannel, MAC table, ARP table, device facts.
- Added `packet_tracer_conversion_profile.json` artifact.
- Improved Object Explorer and Topology UI.
- Preserved v5.4 enterprise core: connectors, tenants, jobs, API tokens, live ingestion, reports, audit, and RBAC.

## v5.4.0 — P1 Enterprise Core

- Added vendor connector scaffolding, live ingestion APIs, tenant-aware state, job tracking, API tokens, and PostgreSQL-ready configuration.

## v5.3.0 — Global Product Layer

- Added product docs, report builder basics, evidence package verification, RBAC hardening, and release cleanup.

## v5.6 Enterprise Expansion

- Added stdlib background job runner with start/stop controls, run-next action, retry queue, attempts, status polling, and admin dashboard actions.
- Added live UDP syslog ingestion controller with start/stop settings, normalized event schema v2, severity score mapping, persistent raw live logs, and deduplication fingerprints.
- Added tamper-evident audit chain fields with CSV export and Admin Center filters for actor/action/severity/query.
- Added production auth controls: invite tokens, reset tokens, admin password change, user disable/enable, API token revocation, session registry, and forced logout.
- Expanded Report Builder with Executive, Technical, Compliance, Packet Tracer Conversion, Wireless Risk, Audit, Evidence Appendix, Wireless, and Full report templates plus preview routes.
- Expanded Policy Studio rule model with condition builder fields, severity scores, control mapping, action type, versioning, and current-evidence testing table.
- Added OpenAPI 3.0 specification for tenant-scoped state, live event ingestion, events polling, and jobs API.
- Added Packet Tracer validation dataset fixtures and tests for VLANs, router-on-a-stick, OSPF, NAT, trunk failure, port security, and EtherChannel evidence.

## v5.7.0 — Deep Packet Tracer UI + Policy Intelligence

- Added deep Packet Tracer extraction layers beyond basic config parsing:
  - LLDP adjacency extraction.
  - operational interface status extraction.
  - operational trunk state extraction: allowed, active, forwarding VLANs.
  - route table row extraction.
  - OSPF neighbor extraction.
  - show inventory / show version device inventory extraction.
  - management-plane security hardening signals: AAA, SSH, Telnet, SNMP, HTTP, enable secret/password, logging, NTP.
  - wireless hints: SSID/WLAN/RADIUS/AP clues.
  - command block detection for ZIP members and CLI command streams.
  - deep evidence atom index with tagged line-level facts.
  - derived subnet inventory.
  - derived policy control assertions.
- Expanded Packet Tracer conversion profile:
  - more command coverage checks.
  - stronger quality gates for operational state, hardening, policy controls, and CDP/LLDP topology.
  - more high-value object counters.
- Rebuilt topology page around a dynamic SVG evidence graph with node grouping, curved edges, confidence, status, and selectable nodes.
- Upgraded Import Center with a Deep Packet Tracer Intelligence Matrix, policy control assertions, hardening extractor, operational trunk table, and evidence atom preview.
- Strengthened Policy Studio with evidence-required fields, false-positive guards, acceptance criteria, richer default rules, and detailed rule cards.
- Added regression coverage for the deep Packet Tracer parser.

## 5.8.4 — Deep Packet Tracer Structured Intelligence

- Rebuilt the JSON/XML normalizer into `structured_json_xml_v3_lab_matrix`.
- Added deeper Packet Tracer schema support for nodes/devices, endpoint-based links, child-tag XML records, nested interfaces, VLAN references, DHCP pools, routes, ACL rules, wireless hints, MAC/ARP/endpoint inventory, and embedded/base64 config chunks.
- Added source-path schema mapping so the Import Center can explain exactly where every structured object came from.
- Added structured validation findings for orphan interfaces, duplicate IP candidates, undefined link endpoints, trunk ports without allowed VLAN evidence, and VLAN references that need stronger proof.
- Added new conversion quality gate: `Structured schema understanding`.
- Added UI panels for Schema Path Map and Validation Findings inside `/import`.
- Added regression tests for deep JSON topology conversion and XML child-tag flattening.

## 5.8.6 - Native PKT Intelligence

- Added a safe native `.pkt/.pka` binary inspector for Packet Tracer projects.
- Added entropy, printable-ratio, SHA-256, binary signature, zlib probe, visible string preview, and visible hint extraction.
- Prevented misleading synthetic device creation for opaque native Packet Tracer files.
- Added a dedicated Import Center panel explaining native recoverability and exact export steps required for evidence-grade topology/config extraction.
- Added regression tests for native Packet Tracer inspection and upload behavior.

