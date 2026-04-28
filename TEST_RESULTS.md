# WiGuard Nexus v5.8.9 Test Results

Validation performed after the Packet Tracer fidelity/UI cleanup patch.

## Automated tests

```text
pytest -q
........................................                                 [100%]
40 passed
```

## Focus areas covered

- Native `.pkt/.pka` upload always enters the automatic XML/JSON background conversion path.
- Flattened Packet Tracer binary fragments are reconstructed into IOS-like command lines before parsing.
- Reconstructed lines can produce real devices, interfaces, VLANs, DHCP pools, ACL rules, and trunk evidence when those facts are present in the file.
- Internal XML bridge and normalized JSON previews are generated for native imports.
- Extraction Fidelity Contract prevents fake 100% certainty for opaque proprietary binaries.
- UI additions for upload status, verified extraction snapshot, reconstructed config preview, printable segment preview, and fidelity tier.
- Artifact package now includes fidelity and reconstruction preview JSON outputs.

## Important accuracy note

Native Cisco Packet Tracer `.pkt/.pka` is proprietary. WiGuard now extracts every recoverable visible/decoded detail it can find and clearly reports fidelity, but true 100% native object fidelity requires either exported Packet Tracer evidence/configs or a configured external converter.


## v5.9.0 — Verified Packet Tracer Extraction System

- Added optional companion export upload for native `.pkt/.pka` files so exported configs/XML/JSON/ZIP bundles can be merged with native recovery.
- Added an Evidence Registry that classifies each extracted object as `verified`, `recovered`, `inferred`, or `unmapped` with line/path/source evidence.
- Added a Verified Extraction Contract showing when full-fidelity claims are allowed and which exports are still required.
- Added artifact exports: `evidence_registry.json`, `verified_extraction_contract.json`, and `companion_exports.json`.
- Improved Import and Object Explorer UI with companion-export guidance, fidelity contract cards, and registry tables.
- Added tests for native Packet Tracer + companion export merging and verified export parsing.
