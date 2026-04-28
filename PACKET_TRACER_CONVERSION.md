# Packet Tracer Conversion Intelligence

## Goal

The v5.8.9 conversion layer turns uploaded Packet Tracer labs or exported evidence bundles into a web-based evidence workspace. It focuses on accuracy, traceability, and analyst confidence rather than pretending that every native `.pkt/.pka` file can be perfectly decoded.

## Supported inputs

| Input | Accuracy | Notes |
|---|---:|---|
| ZIP of exported configs/show outputs | Highest | Recommended for final reports. |
| `.cfg`, `.conf`, `.txt`, `.log` | High | Direct text parsing with line evidence. |
| `.json` | High/medium | Uses object model if present, otherwise text parsing. |
| `.xml` | Medium/high | Parsed as structured/text evidence. |
| `.pkt`, `.pka` with `PTEXPLORER_PATH` | Medium/high | Uses external converter output if available. |
| `.pkt`, `.pka` without converter | Partial/variable | Forced background path: printable segment reconstruction → internal XML bridge → normalized JSON. Marked with an explicit fidelity tier. |

## Conversion pipeline

1. File intake and SHA-256 hashing.
2. External converter probe if `PTEXPLORER_PATH` is configured.
3. Embedded ZIP/wrapped stream/zlib/XML/JSON/config recovery.
4. Printable segment reconstruction for flattened IOS-like commands.
5. Internal XML bridge generation.
6. Normalized JSON generation.
7. Object extraction and evidence mapping.
8. Artifact generation.
9. Report/manifest verification.

## Conversion readiness gates

- Device identity.
- Interface coverage.
- VLAN coverage.
- Security policy coverage.
- Topology evidence.
- Line-level traceability.
- Native Packet Tracer confidence.

## New extracted categories

- `ip_inventory.json`
- `port_security.json`
- `spanning_tree.json`
- `etherchannels.json`
- `mac_table.json`
- `arp_table.json`
- `device_facts.json`
- `packet_tracer_conversion_profile.json`

## Recommended demo scenario

Use a ZIP containing:

```text
R1-running-config.txt
SW1-running-config.txt
SW1-show-vlan-brief.txt
SW1-show-interfaces-trunk.txt
SW1-show-cdp-neighbors-detail.txt
SW1-show-spanning-tree.txt
SW1-show-port-security-interface.txt
R1-show-ip-interface-brief.txt
```

Then show:

1. Import Center readiness score.
2. Quality gates and missing commands.
3. Relationship map.
4. Object Explorer evidence lines.
5. Topology page.
6. Full report PDF and Evidence ZIP.

## v5.8.4 Deep JSON/XML Accuracy Notes

The importer now treats JSON/XML as structured evidence, not plain text. It walks every nested record and builds canonical WiGuard objects from common Packet Tracer/export/converter patterns:

- `topology.nodes`, `devices`, `network.devices`, `physical.nodes` → device inventory.
- `interfaces`, `ports`, `adapters`, nested device interfaces → interface inventory and IP inventory.
- `links`, `edges`, `connections`, endpoint arrays such as `endpoints: [{nodeId, port}, {nodeId, port}]` → topology edges.
- `vlans`, `vlanId`, `vid`, access/native/tagged VLAN fields → VLAN inventory and trunk evidence.
- `dhcpPools`, `defaultGateway`, start/end ranges → DHCP scope evidence.
- `aclRules`, firewall rules, permit/deny/effect records → ACL evidence.
- Embedded `runningConfig`, `startupConfig`, `show output`, CLI text, and base64 config chunks → passed into the Cisco parser for line-style extraction.

Accuracy is now reported through:

- Conversion readiness score.
- Structured schema summary.
- Schema path map.
- Validation findings.
- Missing command checklist.
- Cross-layer VLAN consistency.

For the highest possible accuracy, upload a ZIP containing exported running configs and show-command outputs alongside the JSON/XML topology export.

## Native `.pkt/.pka` Handling in v5.8.9

WiGuard now treats native Packet Tracer files as preserved binary evidence instead of pretending that opaque binary noise is a complete topology. The native inspector records file size, SHA-256, entropy, printable ratio, common embedded signatures, zlib probe results, visible string previews, and any trustworthy IP/MAC/interface/config-like hints.

For full topology/config fidelity, export device evidence from Cisco Packet Tracer and upload a ZIP containing commands such as `show running-config`, `show ip interface brief`, `show vlan brief`, `show interfaces trunk`, `show cdp neighbors detail`, `show access-lists`, `show ip route`, `show spanning-tree`, and wireless/lab result matrix exports when available.


## v5.8.9 Native Fidelity Contract

Native `.pkt/.pka` is proprietary, so WiGuard does not claim impossible perfect parsing. Each native upload now gets a clear fidelity tier:

- `converter_verified`: external converter output was used.
- `strong_visible_recovery`: substantial IOS/XML/JSON evidence was recovered from the native binary.
- `partial_visible_recovery`: useful fragments were recovered, but some objects may still be hidden.
- `opaque_native_binary`: the file did not expose enough structured details; exported configs or converter support are required.

The UI and evidence ZIP include the generated XML bridge, normalized JSON, reconstructed config preview, printable segment preview, decoded payload summary, and fidelity JSON.


## v5.9.0 — Verified Packet Tracer Extraction System

- Added optional companion export upload for native `.pkt/.pka` files so exported configs/XML/JSON/ZIP bundles can be merged with native recovery.
- Added an Evidence Registry that classifies each extracted object as `verified`, `recovered`, `inferred`, or `unmapped` with line/path/source evidence.
- Added a Verified Extraction Contract showing when full-fidelity claims are allowed and which exports are still required.
- Added artifact exports: `evidence_registry.json`, `verified_extraction_contract.json`, and `companion_exports.json`.
- Improved Import and Object Explorer UI with companion-export guidance, fidelity contract cards, and registry tables.
- Added tests for native Packet Tracer + companion export merging and verified export parsing.
