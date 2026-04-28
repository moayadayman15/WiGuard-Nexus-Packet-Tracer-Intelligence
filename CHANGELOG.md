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

# Changelog

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

