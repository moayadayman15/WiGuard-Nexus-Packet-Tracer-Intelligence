import json
from pathlib import Path
from flask import Blueprint, current_app, request, redirect, url_for, flash, send_file, jsonify
from ..security import login_user, logout_user, verify_login, current_user, require_role
from ..services.extractor import PacketTracerImportService
from ..services.artifacts import generate_artifacts, verify_manifest, verify_package_bytes
from ..services.reporting import report_json_bytes, report_pdf_bytes, report_html_bytes, evidence_zip_bytes, custom_report_html_bytes
from ..services.intelligence import object_counts, build_policy_diff, run_access_simulation
from ..services.util import now_iso
from ..services.connectors import import_connector_payload, SUPPORTED_CONNECTORS
from ..services.wireless import (
    normalize_wireless_state, add_or_update_ssid, add_or_update_ap, apply_role_change,
    simulate_wireless_event, import_events_payload, wireless_dashboard, add_or_update_client, delete_client,
    delete_ap, delete_ssid, add_or_update_policy_rule, delete_policy_rule
)

bp = Blueprint("actions", __name__)


def storage():
    return current_app.extensions["storage"]


def db():
    return current_app.extensions.get("db")


def _save_state(state, audit_action=None, target="", detail=""):
    normalize_wireless_state(state)
    storage().save(state)
    if db() and audit_action:
        db().audit(current_user() or "system", audit_action, target, detail)
        try:
            db().save_snapshot(state.get("current_project", "main-campus"), audit_action, json.dumps({
                "wireless_policy": state.get("wireless_policy"),
                "ap_inventory": state.get("ap_inventory"),
                "clients": state.get("clients"),
                "client_sessions": state.get("client_sessions", [])[:30],
            }, ensure_ascii=False))
        except Exception:
            pass


def _persist_import_result(result, source_note):
    state = storage().load()
    normalize_wireless_state(state)
    objects = result["objects"]
    import_record = {
        "id": f"import-{len(state.get('imports', [])) + 1}",
        "filename": result["filename"],
        "stored_filename": result.get("stored_filename", result["filename"]),
        "source_mode": result["source_mode"],
        "source_note": source_note,
        "imported_at": result["imported_at"],
        "object_count": sum(object_counts(objects).values()),
        "counts": object_counts(objects),
        "source_hash": result.get("source_hash"),
    }
    state["active_extraction"] = {
        "filename": result["filename"],
        "stored_filename": result.get("stored_filename", result["filename"]),
        "source_mode": result["source_mode"],
        "source_hash": result.get("source_hash"),
        "imported_at": result["imported_at"],
        "objects": objects,
        "pipeline": result["pipeline"],
        "raw_text_preview": result["text"][:6000],
        "missing_evidence": result.get("missing_evidence", []),
        "confidence_summary": result.get("confidence_summary", {}),
    }
    state.setdefault("imports", []).insert(0, import_record)
    state.setdefault("events", []).insert(0, {
        "id": len(state.get("events", [])) + 1,
        "type": "import",
        "client": "",
        "severity": "Info",
        "detail": f"{source_note} {result['filename']} and extracted {import_record['object_count']} object/evidence entries.",
        "created_at": now_iso()
    })
    _save_state(state, "import.persist", result["filename"], source_note)

    state = storage().load()
    files, manifest = generate_artifacts(state, current_app.config["ARTIFACT_DIR"])
    state["active_extraction"]["artifacts"] = files
    state["active_extraction"]["manifest"] = manifest
    _save_state(state, "artifacts.generate", result["filename"], "Generated extraction artifacts")
    return import_record


@bp.post("/login")
def login():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    next_url = request.form.get("next") or url_for("pages.overview")
    user = verify_login(username, password)
    if isinstance(user, dict) and user.get("error") == "rate_limited":
        flash("Too many failed login attempts. Try again later or contact an admin.", "error")
        return redirect(url_for("pages.login", next=next_url))
    if user:
        login_user(user)
        flash("Signed in successfully.", "success")
        return redirect(next_url if next_url.startswith("/") else url_for("pages.overview"))
    flash("Invalid username or password.", "error")
    return redirect(url_for("pages.login", next=next_url))


@bp.post("/register")
def register():
    if not current_app.config.get("REGISTRATION_ENABLED", True):
        flash("Registration is disabled by configuration.", "error")
        return redirect(url_for("pages.login"))
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    role = "admin" if db() and db().user_count() == 0 else "analyst"
    if password != confirm:
        flash("Password confirmation does not match.", "error")
        return redirect(url_for("pages.register"))
    try:
        user = db().create_user(username, password, role=role)
        login_user(user)
        flash(f"Account created as {role}. Data is now stored in SQLite.", "success")
        return redirect(url_for("pages.overview"))
    except Exception as exc:
        flash(f"Registration failed: {exc}", "error")
        return redirect(url_for("pages.register"))


@bp.get("/logout")
def logout():
    logout_user()
    flash("Signed out.", "success")
    return redirect(url_for("pages.login"))


@require_role("admin")
@bp.post("/actions/reset")
def reset():
    storage().reset()
    state = storage().load()
    normalize_wireless_state(state)
    _save_state(state, "state.reset", "seed", "State reset to clean wireless seed")
    flash("State reset to a clean wireless policy seed.", "success")
    return redirect(url_for("pages.overview"))


@bp.post("/actions/import")
def import_file():
    uploaded = request.files.get("network_file")
    if not uploaded or not uploaded.filename:
        flash("Choose a Packet Tracer/config file first.", "error")
        return redirect(url_for("pages.import_center"))
    service = PacketTracerImportService(current_app.config["UPLOAD_DIR"])
    try:
        result = service.extract(uploaded)
        import_record = _persist_import_result(result, "Imported")
        flash(f"Import completed. Extracted objects: {import_record['object_count']}.", "success")
    except Exception as exc:
        flash(f"Import failed: {exc}", "error")
    return redirect(url_for("pages.import_center"))


@bp.post("/actions/load-sample")
def load_sample():
    sample = current_app.config["SAMPLE_DIR"] / "campus_production_sample.cfg"

    class FakeUpload:
        filename = "campus_production_sample.cfg"
        def read(self):
            return sample.read_bytes()

    service = PacketTracerImportService(current_app.config["UPLOAD_DIR"])
    try:
        result = service.extract(FakeUpload())
        _persist_import_result(result, "Loaded production sample")
        flash("Production sample loaded and artifacts generated.", "success")
    except Exception as exc:
        flash(f"Sample import failed: {exc}", "error")
    return redirect(url_for("pages.import_center"))


@bp.post("/actions/simulate")
def simulate():
    state = storage().load()
    client = request.form.get("client", "")
    action = request.form.get("action", "")
    result = run_access_simulation(state, client, action)
    state.setdefault("simulations", []).insert(0, {
        "id": f"sim-{len(state.get('simulations', [])) + 1}",
        "client": client,
        "action": action,
        "status": result["status"],
        "severity": result["severity"],
        "detail": result["detail"],
        "path": result.get("path", []),
        "decision_points": result.get("decision_points", []),
        "created_at": now_iso()
    })
    state.setdefault("events", []).insert(0, {"id": len(state.get("events", [])) + 1, "type": "simulation", "client": client, "severity": result["severity"], "detail": result["detail"], "created_at": now_iso()})
    _save_state(state, "simulation.access", client, action)
    flash("Simulation recorded with path-based decision evidence.", "success")
    return redirect(url_for("pages.simulation"))


@bp.post("/actions/wireless/ssid")
def wireless_ssid_save():
    state = storage().load()
    try:
        name = add_or_update_ssid(state, request.form)
        _save_state(state, "wireless.ssid.save", name, "SSID policy updated")
        flash(f"SSID policy saved for {name}.", "success")
    except Exception as exc:
        flash(f"SSID save failed: {exc}", "error")
    return redirect(url_for("pages.wireless_manager") + "#ssid")


@bp.post("/actions/wireless/ap")
def wireless_ap_save():
    state = storage().load()
    try:
        name = add_or_update_ap(state, request.form)
        _save_state(state, "wireless.ap.save", name, "AP inventory updated")
        flash(f"AP inventory saved for {name}.", "success")
    except Exception as exc:
        flash(f"AP save failed: {exc}", "error")
    return redirect(url_for("pages.wireless_manager") + "#ap")


@bp.post("/actions/wireless/event")
def wireless_event():
    state = storage().load()
    ok, msg = simulate_wireless_event(state, request.form)
    if ok:
        _save_state(state, "wireless.event.simulate", request.form.get("client", ""), request.form.get("event_type", ""))
        flash(f"Wireless event recorded: {msg}", "success")
    else:
        flash(msg, "error")
    return redirect(url_for("pages.wireless_manager") + "#events")


@bp.post("/actions/wireless/role-change")
def wireless_role_change():
    state = storage().load()
    ok, msg = apply_role_change(state, request.form.get("client", ""), request.form.get("new_role", ""))
    if ok:
        _save_state(state, "wireless.role.change", request.form.get("client", ""), request.form.get("new_role", ""))
        flash(msg, "success")
    else:
        flash(msg, "error")
    return redirect(url_for("pages.wireless_manager") + "#demo")


@bp.post("/actions/wireless/import-events")
def wireless_import_events():
    uploaded = request.files.get("event_file")
    if not uploaded or not uploaded.filename:
        flash("Choose a CSV or JSON wireless event file.", "error")
        return redirect(url_for("pages.wireless_manager") + "#events")
    if not uploaded.filename.lower().endswith((".csv", ".json")):
        flash("Only CSV/JSON event imports are allowed.", "error")
        return redirect(url_for("pages.wireless_manager") + "#events")
    state = storage().load()
    try:
        count, errors = import_events_payload(state, Path(uploaded.filename).name, uploaded.read())
        _save_state(state, "wireless.events.import", uploaded.filename, f"Imported {count} event(s)")
        flash(f"Imported {count} wireless event(s)." + (f" Errors: {'; '.join(errors)}" if errors else ""), "success" if not errors else "error")
    except Exception as exc:
        flash(f"Event import failed: {exc}", "error")
    return redirect(url_for("pages.wireless_manager") + "#events")


@bp.post("/actions/scenario/<scenario_id>")
def scenario_builder(scenario_id):
    state = storage().load()
    normalize_wireless_state(state)
    if scenario_id == "student-to-staff":
        ok, msg = apply_role_change(state, "student_2044", "Staff")
    elif scenario_id == "guest-internal":
        ok, msg = simulate_wireless_event(state, {"event_type": "policy_violation", "client": "guest_01", "detail": "Guest attempted to reach Internal Portal; isolation validation required."})
    elif scenario_id == "roaming-burst":
        ok = True
        msg = "Generated roaming burst for student_2044."
        for ap in ["AP-01", "AP-02", "AP-01", "AP-02", "AP-03"]:
            simulate_wireless_event(state, {"event_type": "roaming", "client": "student_2044", "to_ap": ap})
    elif scenario_id == "auth-failures":
        ok = True
        msg = "Generated authentication failure spike for guest_01."
        for _ in range(4):
            simulate_wireless_event(state, {"event_type": "authentication_failure", "client": "guest_01", "ssid": "GuestWiFi", "ap": "AP-03"})
    else:
        ok, msg = False, "Unknown scenario."
    if ok:
        _save_state(state, "wireless.scenario", scenario_id, msg)
        flash(msg, "success")
    else:
        flash(msg, "error")
    return redirect(url_for("pages.wireless_manager") + "#scenarios")


@require_role("admin")
@bp.post("/actions/settings")
def update_settings():
    state = storage().load()
    state.setdefault("meta", {})["product"] = request.form.get("product", state.get("meta", {}).get("product", "WiGuard Nexus v5.2")).strip() or "WiGuard Nexus v5.2"
    state.setdefault("meta", {})["tagline"] = request.form.get("tagline", state.get("meta", {}).get("tagline", "Wireless Policy Manager with wired evidence intelligence")).strip()
    wireless_settings = state.setdefault("policy_settings", {}).setdefault("wireless", {})
    for key in ["auth_failure_threshold", "roaming_threshold", "ap_load_warning", "ap_load_critical"]:
        if request.form.get(key):
            wireless_settings[key] = int(request.form.get(key))
    _save_state(state, "settings.update", "global", "Product and wireless thresholds updated")
    flash("Settings updated.", "success")
    return redirect(url_for("pages.settings"))



@bp.post("/actions/wireless/client")
def wireless_client_save():
    state = storage().load()
    try:
        name = add_or_update_client(state, request.form)
        _save_state(state, "wireless.client.save", name, "Client session profile updated")
        flash(f"Client saved: {name}.", "success")
    except Exception as exc:
        flash(f"Client save failed: {exc}", "error")
    return redirect(url_for("pages.wireless_manager") + "#sessions")


@bp.post("/actions/wireless/client/<name>/delete")
@require_role("engineer")
def wireless_client_delete(name):
    state = storage().load()
    if delete_client(state, name):
        _save_state(state, "wireless.client.delete", name, "Client removed")
        flash("Client removed.", "success")
    else:
        flash("Client not found.", "error")
    return redirect(url_for("pages.wireless_manager") + "#sessions")


@bp.post("/actions/wireless/ap/<name>/delete")
@require_role("engineer")
def wireless_ap_delete(name):
    state = storage().load()
    if delete_ap(state, name):
        _save_state(state, "wireless.ap.delete", name, "AP removed")
        flash("AP removed.", "success")
    else:
        flash("AP not found.", "error")
    return redirect(url_for("pages.wireless_manager") + "#ap")


@bp.post("/actions/wireless/ssid/<name>/delete")
@require_role("engineer")
def wireless_ssid_delete(name):
    state = storage().load()
    if delete_ssid(state, name):
        _save_state(state, "wireless.ssid.delete", name, "SSID removed")
        flash("SSID removed.", "success")
    else:
        flash("SSID not found.", "error")
    return redirect(url_for("pages.wireless_manager") + "#ssid")


@bp.post("/actions/policy-studio/rule")
@require_role("engineer")
def policy_studio_rule_save():
    state = storage().load()
    try:
        rid = add_or_update_policy_rule(state, request.form)
        _save_state(state, "policy_studio.rule.save", rid, "Policy Studio rule updated")
        flash(f"Policy rule saved: {rid}.", "success")
    except Exception as exc:
        flash(f"Policy rule save failed: {exc}", "error")
    return redirect(url_for("pages.rules") + "#studio")


@bp.post("/actions/policy-studio/rule/<rule_id>/delete")
@require_role("engineer")
def policy_studio_rule_delete(rule_id):
    state = storage().load()
    if delete_policy_rule(state, rule_id):
        _save_state(state, "policy_studio.rule.delete", rule_id, "Policy Studio rule deleted")
        flash("Policy rule deleted.", "success")
    else:
        flash("Policy rule not found.", "error")
    return redirect(url_for("pages.rules") + "#studio")


@bp.post("/actions/connectors/import")
@require_role("analyst")
def connector_import():
    uploaded = request.files.get("connector_file")
    connector_type = request.form.get("connector_type", "")
    if not uploaded or not uploaded.filename:
        flash("Choose a connector CSV/JSON file.", "error")
        return redirect(url_for("pages.wireless_manager") + "#connectors")
    if not uploaded.filename.lower().endswith((".csv", ".json")):
        flash("Connector imports support CSV/JSON only.", "error")
        return redirect(url_for("pages.wireless_manager") + "#connectors")
    state = storage().load()
    try:
        raw = uploaded.read()
        count, errors = import_connector_payload(state, connector_type, uploaded.filename, raw)
        if db():
            db().connector_run(connector_type, uploaded.filename, count, "ok" if not errors else "partial", "; ".join(errors), current_user() or "system")
        _save_state(state, "connector.import", connector_type, f"Imported {count} records from {uploaded.filename}")
        flash(f"Connector import completed: {count} records." + (f" Errors: {'; '.join(errors)}" if errors else ""), "success" if not errors else "error")
    except Exception as exc:
        if db():
            db().connector_run(connector_type, uploaded.filename, 0, "error", str(exc), current_user() or "system")
        flash(f"Connector import failed: {exc}", "error")
    return redirect(url_for("pages.wireless_manager") + "#connectors")


@bp.get("/download/database-backup.sqlite3")
@require_role("admin")
def download_database_backup():
    backup_path = db().create_backup(current_app.config["DATA_FILE"].parent / "backups", current_user() or "system", "Manual backup from Settings")
    return send_file(backup_path, as_attachment=True, download_name=backup_path.name, mimetype="application/x-sqlite3")


@bp.post("/actions/database/restore")
@require_role("admin")
def restore_database():
    uploaded = request.files.get("database_file")
    if not uploaded or not uploaded.filename:
        flash("Choose a SQLite database backup first.", "error")
        return redirect(url_for("pages.settings") + "#backups")
    tmp = current_app.config["UPLOAD_DIR"] / ("restore-" + Path(uploaded.filename).name)
    uploaded.save(tmp)
    try:
        db().restore_from_upload(tmp)
        flash("Database restored. Restart the app if you changed active users or schema state.", "success")
    except Exception as exc:
        flash(f"Database restore failed: {exc}", "error")
    finally:
        try: tmp.unlink()
        except Exception: pass
    return redirect(url_for("pages.settings") + "#backups")


@bp.post("/download/report/custom.html")
def download_custom_report_html():
    sections = request.form.getlist("sections") or ["summary", "wireless", "anomalies"]
    return send_file(custom_report_html_bytes(storage().load(), sections), download_name="custom_wiguard_report.html", as_attachment=True, mimetype="text/html")


@bp.get("/download/artifact/<name>")
def download_artifact(name):
    state = storage().load()
    artifacts = state.get("active_extraction", {}).get("artifacts", {}) or {}
    if name not in artifacts or Path(name).name != name:
        flash("Artifact not found.", "error")
        return redirect(url_for("pages.import_center"))
    path_obj = Path(artifacts[name])
    if not path_obj.is_absolute():
        path_obj = current_app.config["ROOT_DIR"] / path_obj
    artifact_root = current_app.config["ARTIFACT_DIR"].resolve()
    if not path_obj.resolve().is_relative_to(artifact_root) or not path_obj.exists():
        flash("Artifact not found.", "error")
        return redirect(url_for("pages.import_center"))
    return send_file(path_obj, as_attachment=True)


@bp.get("/download/report/<report_type>.json")
def download_report_json(report_type):
    return send_file(report_json_bytes(storage().load(), report_type), download_name=f"{report_type}_report.json", as_attachment=True, mimetype="application/json")


@bp.get("/download/report/<report_type>.pdf")
def download_report_pdf(report_type):
    return send_file(report_pdf_bytes(storage().load(), report_type), download_name=f"{report_type}_report.pdf", as_attachment=True, mimetype="application/pdf")


@bp.get("/download/report/<report_type>.html")
def download_report_html(report_type):
    return send_file(report_html_bytes(storage().load(), report_type), download_name=f"{report_type}_report.html", as_attachment=True, mimetype="text/html")


@bp.get("/download/evidence-package.zip")
def download_evidence_zip():
    return send_file(evidence_zip_bytes(storage().load(), current_app.config["ARTIFACT_DIR"]), download_name="wiguard_evidence_package.zip", as_attachment=True, mimetype="application/zip")


@bp.post("/actions/verify")
def verify():
    state = storage().load()
    result = verify_manifest(current_app.config["ARTIFACT_DIR"])
    state.setdefault("verifier", {})["last_result"] = result
    _save_state(state, "verifier.run", "artifact_manifest", result["status"])
    flash(f"Verification completed: {result['status'].upper()}.", "success" if result["status"] == "pass" else "error")
    return redirect(url_for("pages.verifier"))


@bp.post("/actions/projects/create")
def create_project():
    state = storage().load()
    name = request.form.get("name", "").strip()
    if not name:
        flash("Project name is required.", "error")
        return redirect(url_for("pages.projects"))
    project_id = "project-" + "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")[:40]
    existing = {p.get("id") for p in state.get("projects", [])}
    base_id = project_id or f"project-{len(existing)+1}"
    n = 2
    while project_id in existing:
        project_id = f"{base_id}-{n}"
        n += 1
    state.setdefault("projects", []).append({
        "id": project_id,
        "name": name,
        "environment": request.form.get("environment", "").strip() or "Network validation workspace",
        "owner": request.form.get("owner", "").strip() or "Network Security Team",
        "created_at": now_iso(),
        "status": "active",
    })
    state["current_project"] = project_id
    _save_state(state, "project.create", project_id, name)
    flash("Project created and selected.", "success")
    return redirect(url_for("pages.projects"))


@bp.post("/actions/projects/<project_id>/switch")
def switch_project(project_id):
    state = storage().load()
    if any(p.get("id") == project_id for p in state.get("projects", [])):
        state["current_project"] = project_id
        _save_state(state, "project.switch", project_id, "Project selected")
        flash("Project switched.", "success")
    else:
        flash("Project not found.", "error")
    return redirect(url_for("pages.projects"))


@require_role("admin")
@bp.post("/actions/projects/<project_id>/delete")
def delete_project(project_id):
    state = storage().load()
    projects = state.get("projects", [])
    if len(projects) <= 1:
        flash("At least one project must remain.", "error")
        return redirect(url_for("pages.projects"))
    state["projects"] = [p for p in projects if p.get("id") != project_id]
    if state.get("current_project") == project_id:
        state["current_project"] = state["projects"][0]["id"]
    _save_state(state, "project.delete", project_id, "Project deleted")
    flash("Project deleted.", "success")
    return redirect(url_for("pages.projects"))


@require_role("auditor")
@bp.get("/api/state")
def api_state():
    return jsonify(storage().load())


@bp.get("/api/diff")
def api_diff():
    return jsonify(build_policy_diff(storage().load()))


@bp.get("/api/wireless")
def api_wireless():
    state = storage().load()
    return jsonify(wireless_dashboard(state, build_policy_diff(state)))
