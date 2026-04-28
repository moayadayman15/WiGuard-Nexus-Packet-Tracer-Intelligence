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
