# WiGuard Nexus v5.12.4 Backend Login + Extraction Recovery Notes

## Fixed in this build

- Repaired the login recovery path:
  - `/login` no longer dies when SQLite auth inspection fails.
  - Local development fallback accepts `admin / admin123`.
  - Legacy local fallback `admin / admin` is accepted in development only.
  - Runtime metadata is forced to v5.9.6 so the UI no longer shows stale v5.5/v5.7 headers after an update.

- Repaired Packet Tracer extraction visibility:
  - Native `.pkt/.pka` still goes through the safe background chain:
    converter probe → printable/zlib recovery → internal XML bridge → normalized JSON → object extraction.
  - Interface IP assignments now backfill `ip_inventory` and `endpoint_inventory`.
  - Native visible-config confidence now scales with recovered evidence instead of staying stuck at a low fixed score.
  - Stronger decompression/payload limits for hidden XML/JSON/config fragments.
  - Added regression tests for config-derived IP inventory and native Packet Tracer visible evidence recovery.

## Important truth contract

Native Packet Tracer files are proprietary. This build improves recovery from visible/decompressed evidence, but it does not fake 100% fidelity. For maximum accuracy, upload a companion ZIP/export containing:

- `show running-config`
- `show ip interface brief`
- `show vlan brief`
- `show interfaces trunk`
- `show cdp neighbors detail`
- `show access-lists`
- `show ip route`
- `show spanning-tree`
- `show port-security`
- `show etherchannel summary`

This upgrades the result from best-effort native recovery to verified exported evidence.
