import json
import zipfile
from pathlib import Path
from io import BytesIO
from .util import write_json, sha256_file, now_iso
from .intelligence import (
    get_objects, build_policy_diff, build_root_causes, build_topology,
    build_timeline, build_playbooks, risk_score, build_report, object_counts,
    build_snapshot_diff, build_extraction_diagnostics, build_topology_insights, build_validation_rule_assessment, build_evidence_quality_matrix, build_analyst_signoff, build_topology_dot
)
from .reporting import report_html_bytes
from .wireless import wireless_dashboard


CATEGORY_MAP = {
    "devices.json": ("devices", []),
    "interfaces.json": ("interfaces", []),
    "vlans.json": ("vlans", []),
    "dhcp_scopes.json": ("dhcp_scopes", []),
    "dhcp_excluded.json": ("dhcp_excluded", []),
    "acl_rules.json": ("acl_rules", []),
    "nat_rules.json": ("nat_rules", []),
    "cdp_links.json": ("cdp_links", []),
    "raw_evidence.json": ("raw_evidence", []),
    "dhcp_gateway_matches.json": ("dhcp_gateway_matches", []),
    "ip_inventory.json": ("ip_inventory", []),
    "port_security.json": ("port_security", []),
    "spanning_tree.json": ("spanning_tree", []),
    "etherchannels.json": ("etherchannels", []),
    "mac_table.json": ("mac_table", []),
    "arp_table.json": ("arp_table", []),
    "device_facts.json": ("device_facts", []),
    "internal_xml_bridge.json": ("internal_xml_bridge", []),
    "auto_conversion_pipeline.json": ("auto_conversion_pipeline", []),
    "decoded_payloads.json": ("decoded_payloads", []),
    "extraction_fidelity.json": ("extraction_fidelity", []),
    "printable_segments_preview.json": ("printable_segments_preview", []),
    "reconstructed_config_preview.json": ("reconstructed_config_preview", []),
    "normalized_json_preview.json": ("normalized_json_preview", []),
    "evidence_registry.json": ("evidence_registry", []),
    "verified_extraction_contract.json": ("verified_extraction_contract", []),
    "companion_exports.json": ("companion_exports", []),
}


def clear_artifacts(artifact_dir):
    artifact_dir = Path(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for p in artifact_dir.iterdir():
        if p.is_file():
            p.unlink()


def generate_artifacts(state, artifact_dir):
    artifact_dir = Path(artifact_dir)
    clear_artifacts(artifact_dir)
    objects = get_objects(state)

    files = {}
    files["object_inventory.json"] = write_json(artifact_dir / "object_inventory.json", {
        "generated_at": now_iso(),
        "counts": object_counts(objects),
        "confidence_summary": state.get("active_extraction", {}).get("confidence_summary", {}),
        "missing_evidence": state.get("active_extraction", {}).get("missing_evidence", []),
        "objects": objects,
    })

    for filename, (key, default) in CATEGORY_MAP.items():
        files[filename] = write_json(artifact_dir / filename, objects.get(key, default))

    files["packet_tracer_conversion_profile.json"] = write_json(artifact_dir / "packet_tracer_conversion_profile.json", state.get("active_extraction", {}).get("conversion_profile", objects.get("packet_tracer_profile", {})))
    bridge_xml_rows = objects.get("converted_xml_preview", []) or []
    if bridge_xml_rows and isinstance(bridge_xml_rows[0], dict) and bridge_xml_rows[0].get("content"):
        bridge_xml_path = artifact_dir / "internal_pkt_bridge.xml"
        bridge_xml_path.write_text(bridge_xml_rows[0].get("content", ""), encoding="utf-8")
        files["internal_pkt_bridge.xml"] = str(bridge_xml_path)
    normalized_rows = objects.get("normalized_json_preview", []) or []
    if normalized_rows and isinstance(normalized_rows[0], dict) and normalized_rows[0].get("content"):
        normalized_path = artifact_dir / "internal_pkt_bridge.normalized.json"
        normalized_path.write_text(normalized_rows[0].get("content", ""), encoding="utf-8")
        files["internal_pkt_bridge.normalized.json"] = str(normalized_path)
    files["routing.json"] = write_json(artifact_dir / "routing.json", objects.get("routing", {}))
    files["policy_diff.json"] = write_json(artifact_dir / "policy_diff.json", build_policy_diff(state))
    files["root_causes.json"] = write_json(artifact_dir / "root_causes.json", build_root_causes(state))
    files["topology_map.json"] = write_json(artifact_dir / "topology_map.json", build_topology(state))
    files["topology_insights.json"] = write_json(artifact_dir / "topology_insights.json", build_topology_insights(state))
    files["import_diagnostics.json"] = write_json(artifact_dir / "import_diagnostics.json", build_extraction_diagnostics(state))
    files["rule_assessment.json"] = write_json(artifact_dir / "rule_assessment.json", build_validation_rule_assessment(state))
    files["evidence_quality_matrix.json"] = write_json(artifact_dir / "evidence_quality_matrix.json", build_evidence_quality_matrix(state))
    files["analyst_signoff.json"] = write_json(artifact_dir / "analyst_signoff.json", build_analyst_signoff(state))
    dot_path = artifact_dir / "topology_graph.dot"
    dot_path.write_text(build_topology_dot(state), encoding="utf-8")
    files["topology_graph.dot"] = str(dot_path)
    files["risk_model.json"] = write_json(artifact_dir / "risk_model.json", risk_score(state))
    files["risk_timeline.json"] = write_json(artifact_dir / "risk_timeline.json", build_timeline(state))
    files["playbooks.json"] = write_json(artifact_dir / "playbooks.json", build_playbooks(state))
    files["snapshot_diff.json"] = write_json(artifact_dir / "snapshot_diff.json", build_snapshot_diff(state))
    files["validation_rules.json"] = write_json(artifact_dir / "validation_rules.json", state.get("rules", []))
    files["wireless_policy_manager.json"] = write_json(artifact_dir / "wireless_policy_manager.json", wireless_dashboard(state, build_policy_diff(state)))
    files["wireless_event_report.json"] = write_json(artifact_dir / "wireless_event_report.json", build_report(state, "wireless"))
    files["wired_policy.json"] = write_json(artifact_dir / "wired_policy.json", {
        "metadata": {
            "generated_at": now_iso(),
            "source": state.get("active_extraction", {}).get("filename"),
            "source_hash": state.get("active_extraction", {}).get("source_hash"),
        },
        "wired_network": {
            "devices": objects.get("devices", []),
            "interfaces": objects.get("interfaces", []),
            "links": objects.get("cdp_links", []),
            "ip_inventory": objects.get("ip_inventory", []),
            "spanning_tree": objects.get("spanning_tree", []),
            "etherchannels": objects.get("etherchannels", []),
            "mac_table": objects.get("mac_table", []),
            "arp_table": objects.get("arp_table", []),
        },
        "segmentation": {
            "vlans": objects.get("vlans", []),
            "dhcp_scopes": objects.get("dhcp_scopes", []),
            "dhcp_gateway_matches": objects.get("dhcp_gateway_matches", []),
            "acl_rules": objects.get("acl_rules", []),
            "port_security": objects.get("port_security", []),
        },
        "routing": objects.get("routing", {}),
        "nat": objects.get("nat_rules", []),
    })
    files["full_report.json"] = write_json(artifact_dir / "full_report.json", build_report(state, "full"))
    html_path = artifact_dir / "full_report.html"
    html_path.write_bytes(report_html_bytes(state, "full").getvalue())
    files["full_report.html"] = str(html_path)
    wireless_html_path = artifact_dir / "wireless_event_report.html"
    wireless_html_path.write_bytes(report_html_bytes(state, "wireless").getvalue())
    files["wireless_event_report.html"] = str(wireless_html_path)

    manifest = {
        "generated_at": now_iso(),
        "tool": state.get("meta", {}).get("product", "WiGuard Nexus"),
        "source_file": state.get("active_extraction", {}).get("filename"),
        "source_hash": state.get("active_extraction", {}).get("source_hash"),
        "artifact_count": 0,
        "files": [],
    }
    for name, path in sorted(files.items()):
        manifest["files"].append({
            "name": name,
            "sha256": sha256_file(path),
            "size_bytes": Path(path).stat().st_size,
            "purpose": name.replace(".json", "").replace(".html", "").replace("_", " ").title(),
        })
    manifest["artifact_count"] = len(manifest["files"])
    manifest_path = write_json(artifact_dir / "evidence_manifest.json", manifest)
    files["evidence_manifest.json"] = manifest_path

    # Detached checksum for quick integrity checks.
    (artifact_dir / "evidence_manifest.sha256").write_text(sha256_file(manifest_path), encoding="utf-8")
    files["evidence_manifest.sha256"] = str(artifact_dir / "evidence_manifest.sha256")
    return files, manifest


def verify_manifest(artifact_dir):
    artifact_dir = Path(artifact_dir)
    manifest_path = artifact_dir / "evidence_manifest.json"
    if not manifest_path.exists():
        return {"status": "missing", "valid": 0, "invalid": 0, "missing": 1, "details": ["Manifest not found."]}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    details = []
    valid = invalid = missing = 0
    for item in manifest.get("files", []):
        path = artifact_dir / item["name"]
        if not path.exists():
            missing += 1
            details.append(f"MISSING: {item['name']}")
            continue
        actual = sha256_file(path)
        if actual == item.get("sha256"):
            valid += 1
        else:
            invalid += 1
            details.append(f"MODIFIED: {item['name']}")
    sha_path = artifact_dir / "evidence_manifest.sha256"
    if sha_path.exists():
        recorded = sha_path.read_text(encoding="utf-8").strip()
        actual_manifest = sha256_file(manifest_path)
        if recorded != actual_manifest:
            invalid += 1
            details.append("MODIFIED: evidence_manifest.json does not match detached checksum")
    status = "pass" if invalid == 0 and missing == 0 else "fail"
    return {"status": status, "valid": valid, "invalid": invalid, "missing": missing, "details": details, "manifest": manifest}


def verify_package_bytes(package_bytes):
    """Verify an exported ZIP that contains artifacts/evidence_manifest.json."""
    if hasattr(package_bytes, "read"):
        data = package_bytes.read()
    else:
        data = package_bytes
    details = []
    valid = invalid = missing = 0
    with zipfile.ZipFile(BytesIO(data)) as zf:
        if "artifacts/evidence_manifest.json" not in zf.namelist():
            return {"status": "missing", "valid": 0, "invalid": 0, "missing": 1, "details": ["ZIP manifest not found."]}
        manifest = json.loads(zf.read("artifacts/evidence_manifest.json").decode("utf-8"))
        for item in manifest.get("files", []):
            name = f"artifacts/{item['name']}"
            if name not in zf.namelist():
                missing += 1
                details.append(f"MISSING: {name}")
                continue
            import hashlib
            actual = hashlib.sha256(zf.read(name)).hexdigest()
            if actual == item.get("sha256"):
                valid += 1
            else:
                invalid += 1
                details.append(f"MODIFIED: {name}")
    return {"status": "pass" if invalid == 0 and missing == 0 else "fail", "valid": valid, "invalid": invalid, "missing": missing, "details": details}
