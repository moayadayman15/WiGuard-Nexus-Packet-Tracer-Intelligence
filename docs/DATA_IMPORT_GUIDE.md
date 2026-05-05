# Data Import Guide

## Supported formats

WiGuard accepts:

- JSON exports
- XML exports
- CSV tables
- TXT/LOG/CFG/CONF network configuration files
- ZIP bundles containing supported text/XML/JSON files
- Packet Tracer `.pkt` / `.pka` files as native evidence manifests and best-effort bridge input

## Recommended evidence for best results

For Cisco/Packet Tracer labs, export or paste:

- `show running-config`
- `show ip interface brief`
- `show vlan brief`
- `show interfaces trunk`
- `show access-lists`
- `show ip route`
- `show cdp neighbors detail`
- Packet Tracer XML/JSON exports if available

## Native `.pkt` limitation

Packet Tracer native files are proprietary binary containers. WiGuard accepts, hashes, stores, and inspects them, but it does not claim full topology extraction unless the evidence proves it. For professional reports, attach companion exported configs/XML/JSON.

## Validation behavior

The import validator rejects missing, empty, oversized, or unsupported files with friendly messages. ZIP extraction limits member count and total bytes to avoid archive abuse.
