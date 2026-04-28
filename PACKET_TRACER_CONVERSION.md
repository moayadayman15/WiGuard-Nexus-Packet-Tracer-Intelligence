# Packet Tracer Conversion Intelligence

## Goal

The v5.5 conversion layer turns uploaded Packet Tracer labs or exported evidence bundles into a web-based evidence workspace. It focuses on accuracy, traceability, and analyst confidence rather than pretending that every native `.pkt/.pka` file can be perfectly decoded.

## Supported inputs

| Input | Accuracy | Notes |
|---|---:|---|
| ZIP of exported configs/show outputs | Highest | Recommended for final reports. |
| `.cfg`, `.conf`, `.txt`, `.log` | High | Direct text parsing with line evidence. |
| `.json` | High/medium | Uses object model if present, otherwise text parsing. |
| `.xml` | Medium/high | Parsed as structured/text evidence. |
| `.pkt`, `.pka` with `PTEXPLORER_PATH` | Medium/high | Uses external converter output if available. |
| `.pkt`, `.pka` without converter | Partial | Printable binary recovery only; marked honestly as lower confidence. |

## Conversion pipeline

1. File intake and SHA-256 hashing.
2. Source decoding.
3. Packet Tracer Intelligence profile.
4. Object extraction.
5. Evidence mapping.
6. Artifact generation.
7. Report/manifest verification.

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
