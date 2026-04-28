import json
from pathlib import Path
from flask import Blueprint, current_app, request, redirect, url_for, flash, send_file, jsonify, Response, render_template
from ..security import (
    login_user, logout_user, verify_login, current_user, current_tenant_id,
    require_role, require_api_scope, safe_redirect_target
)
from ..services.extractor import PacketTracerImportService
from ..services.artifacts import generate_artifacts, verify_manifest, verify_package_bytes
from ..services.reporting import report_json_bytes, report_pdf_bytes, report_html_bytes, evidence_zip_bytes, custom_report_html_bytes
from ..services.intelligence import object_counts, build_policy_diff, run_access_simulation, sanitize_objects
from ..services.util import now_iso
from ..services.connectors import (
    import_connector_payload, SUPPORTED_CONNECTORS, check_connector_credentials, vendor_sync_preview
)
from ..services.wireless import (
    normalize_wireless_state, add_or_update_ssid, add_or_update_ap, apply_role_change,
    simulate_wireless_event, import_events_payload, wireless_dashboard, add_or_update_client, delete_client,
    delete_ap, delete_ssid, add_or_update_policy_rule, delete_policy_rule
)
from ..services.live_ingestion import SyslogListenerConfig

bp = Blueprint("actions", __name__)


def storage():
    return current_app.extensions["storage"]


def db():
    return current_app.extensions.get("db")


def _save_state(state, audit_action=None, target="", detail=""):
    state.setdefault("tenant_id", current_tenant_id())
    state.setdefault("version", "5.9.3-professional-quality-studio")
    try:
        normalize_wireless_state(state)
    except Exception as exc:
        # Persistence must win. A dashboard normalizer problem should be visible in
        # logs but must never discard user changes.
        try:
            current_app.logger.exception("State normalization failed before save: %s", exc)
        except Exception:
            pass
    storage().save(state)
    db_obj = db()
    if db_obj and audit_action:
        try:
            db_obj.audit(current_user() or "system", audit_action, target, detail)
            db_obj.save_snapshot(state.get("current_project", "main-campus"), audit_action, json.dumps({
                "tenant_id": state.get("tenant_id"),
                "wireless_policy": state.get("wireless_policy"),
                "ap_inventory": state.get("ap_inventory"),
                "clients": state.get("clients"),
                "client_sessions": state.get("client_sessions", [])[:30],
            }, ensure_ascii=False))
        except Exception as exc:
            # The JSON state is the source of truth for UI data. A SQLite audit
            # or snapshot issue must not make the user think the form did not save.
            try:
                current_app.logger.exception("State saved but audit/snapshot failed for %s: %s", audit_action, exc)
            except Exception:
                pass


def _tenant_scoped_state(state):
    tenant_id = current_tenant_id()
    scoped = dict(state)
    scoped["tenant_id"] = tenant_id
    for key in ["projects", "imports", "events", "simulations"]:
        if isinstance(scoped.get(key), list):
            scoped[key] = [x for x in scoped[key] if not isinstance(x, dict) or x.get("tenant_id", tenant_id) == tenant_id]
    active = scoped.get("active_extraction") or {}
    if active and active.get("tenant_id", tenant_id) != tenant_id:
        scoped["active_extraction"] = {}
    return scoped

def _persist_import_result(result, source_note):
    state = storage().load()
    normalize_wireless_state(state)
    tenant_id = state.get("tenant_id", current_tenant_id())
    objects = sanitize_objects(result.get("objects", {}))
    result["objects"] = objects
    import_record = {
        "id": f"import-{len(state.get('imports', [])) + 1}",
        "tenant_id": tenant_id,
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
        "tenant_id": tenant_id,
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
        "conversion_profile": result.get("conversion_profile", {}),
    }
    state.setdefault("imports", []).insert(0, import_record)
    state.setdefault("events", []).insert(0, {
        "id": len(state.get("events", [])) + 1,
        "tenant_id": tenant_id,
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


def _run_connector_job(job_id: str, connector_type: str, filename: str, raw: bytes, live: bool = False):
    db_obj = db()
    if db_obj:
        db_obj.update_job(job_id, "running", 15)
    state = storage().load()
    count, errors = import_connector_payload(state, connector_type, filename, raw, db=db_obj, live=live)
    if db_obj:
        status = "completed" if not errors else "partial"
        db_obj.connector_run(connector_type, filename, count, "ok" if not errors else "partial", "; ".join(errors), current_user() or "system")
        db_obj.update_job(job_id, status, 100, {"count": count, "errors": errors})
    _save_state(state, "connector.import", connector_type, f"Imported {count} records from {filename}")
    return count, errors


@bp.post("/login")
def login():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    next_url = request.form.get("next") or url_for("pages.overview")
    user = verify_login(username, password)
    if isinstance(user, dict) and user.get("error") == "rate_limited":
        flash("Too many failed login attempts. Try again later or contact an admin.", "error")
        return redirect(url_for("pages.login", next=safe_redirect_target(next_url)))
    if user:
        login_user(user)
        flash("Signed in successfully.", "success")
        return redirect(safe_redirect_target(next_url))
    flash("Invalid username or password.", "error")
    return redirect(url_for("pages.login", next=safe_redirect_target(next_url)))


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
        user = db().create_user(username, password, role=role, tenant_id=current_app.config.get("DEFAULT_TENANT_ID", "tenant-main"))
        login_user(user)
        flash(f"Account created as {role}. Data is now stored in SQLite.", "success")
        return redirect(url_for("pages.overview"))
    except Exception as exc:
        flash(f"Registration failed: {exc}", "error")
        return redirect(url_for("pages.register"))


@bp.route("/accept-invite", methods=["GET", "POST"])
def accept_invite():
    token = request.values.get("token", "")
    if request.method == "GET":
        return render_template("accept_invite.html", token=token)
    try:
        user = db().accept_invite(token, request.form.get("username", ""), request.form.get("password", ""))
        login_user(user)
        flash("Invite accepted and account created.", "success")
        return redirect(url_for("pages.overview"))
    except Exception as exc:
        flash(f"Invite acceptance failed: {exc}", "error")
        return redirect(url_for("actions.accept_invite", token=token))


@bp.route("/password-reset", methods=["GET", "POST"])
def password_reset_request():
    token = request.values.get("token", "")
    if request.method == "GET":
        return render_template("password_reset.html", token=token)
    try:
        username = db().consume_password_reset_token(token, request.form.get("new_password", ""))
        flash(f"Password reset completed for {username}. Please sign in.", "success")
        return redirect(url_for("pages.login"))
    except Exception as exc:
        flash(f"Password reset failed: {exc}", "error")
        return redirect(url_for("actions.password_reset_request", token=token))


@bp.post("/logout")
def logout():
    logout_user()
    flash("Signed out.", "success")
    return redirect(url_for("pages.login"))


@bp.post("/actions/reset")
@require_role("admin")
def reset():
    storage().reset()
    state = storage().load()
    state["version"] = "5.9.3-professional-quality-studio"
    state["tenant_id"] = current_tenant_id()
    normalize_wireless_state(state)
    _save_state(state, "state.reset", "seed", "State reset to clean wireless seed")
    flash("State reset to a clean wireless policy seed.", "success")
    return redirect(url_for("pages.overview"))


@bp.post("/actions/import")
@require_role("analyst")
def import_file():
    uploaded = request.files.get("network_file")
    companion = request.files.get("companion_file")
    if not uploaded or not uploaded.filename:
        flash("Choose a Packet Tracer/config file first.", "error")
        return redirect(url_for("pages.import_center"))
    service = PacketTracerImportService(current_app.config["UPLOAD_DIR"])
    job_meta = {"filename": uploaded.filename}
    if companion and companion.filename:
        job_meta["companion_filename"] = companion.filename
    job_id = db().create_job("evidence_import", job_meta, current_user() or "system", current_tenant_id()) if db() else "inline"
    try:
        if db():
            db().update_job(job_id, "running", 20)
        result = service.extract(uploaded, companion_file=companion)
        import_record = _persist_import_result(result, "Imported")
        if db():
            db().update_job(job_id, "completed", 100, {"import_id": import_record["id"], "object_count": import_record["object_count"]})
        companion_note = " Companion export merged." if companion and companion.filename else ""
        flash(f"Import completed. Extracted objects: {import_record['object_count']}.{companion_note}", "success")
    except Exception as exc:
        if db():
            db().update_job(job_id, "failed", 100, error=str(exc))
        flash(f"Import failed: {exc}", "error")
    return redirect(url_for("pages.import_center"))


@bp.post("/actions/load-sample")
@require_role("analyst")
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
@require_role("analyst")
def simulate():
    state = storage().load()
    client = request.form.get("client", "")
    action = request.form.get("action", "")
    result = run_access_simulation(state, client, action)
    state.setdefault("simulations", []).insert(0, {
        "id": f"sim-{len(state.get('simulations', [])) + 1}",
        "tenant_id": current_tenant_id(),
        "client": client,
        "action": action,
        "status": result["status"],
        "severity": result["severity"],
        "detail": result["detail"],
        "path": result.get("path", []),
        "decision_points": result.get("decision_points", []),
        "created_at": now_iso()
    })
    state.setdefault("events", []).insert(0, {"id": len(state.get("events", [])) + 1, "tenant_id": current_tenant_id(), "type": "simulation", "client": client, "severity": result["severity"], "detail": result["detail"], "created_at": now_iso()})
    _save_state(state, "simulation.access", client, action)
    flash("Simulation recorded with path-based decision evidence.", "success")
    return redirect(url_for("pages.simulation"))


@bp.post("/actions/wireless/ssid")
@require_role("engineer")
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
@require_role("engineer")
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
@require_role("analyst")
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
@require_role("engineer")
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
@require_role("analyst")
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
@require_role("analyst")
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


@bp.post("/actions/settings")
@require_role("admin")
def update_settings():
    state = storage().load()
    state.setdefault("meta", {})["product"] = request.form.get("product", state.get("meta", {}).get("product", "WiGuard Nexus v5.5")).strip() or "WiGuard Nexus v5.5"
    state.setdefault("meta", {})["tagline"] = request.form.get("tagline", state.get("meta", {}).get("tagline", "Wireless Policy Manager with enterprise evidence intelligence")).strip()
    wireless_settings = state.setdefault("policy_settings", {}).setdefault("wireless", {})
    for key in ["auth_failure_threshold", "roaming_threshold", "ap_load_warning", "ap_load_critical"]:
        if request.form.get(key):
            wireless_settings[key] = int(request.form.get(key))
    _save_state(state, "settings.update", "global", "Product and wireless thresholds updated")
    flash("Settings updated.", "success")
    return redirect(url_for("pages.settings"))


@bp.post("/actions/wireless/client")
@require_role("engineer")
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
    raw = uploaded.read()
    job_id = db().create_job("connector_import", {"connector_type": connector_type, "filename": uploaded.filename}, current_user() or "system", current_tenant_id()) if db() else "inline"
    try:
        count, errors = _run_connector_job(job_id, connector_type, uploaded.filename, raw)
        flash(f"Connector import completed: {count} records." + (f" Errors: {'; '.join(errors)}" if errors else ""), "success" if not errors else "error")
    except Exception as exc:
        if db():
            db().connector_run(connector_type, uploaded.filename, 0, "error", str(exc), current_user() or "system")
            db().update_job(job_id, "failed", 100, error=str(exc))
        flash(f"Connector import failed: {exc}", "error")
    return redirect(url_for("pages.wireless_manager") + "#connectors")


@bp.post("/actions/connectors/test")
@require_role("engineer")
def connector_test():
    connector_type = request.form.get("connector_type", "")
    result = check_connector_credentials(
        connector_type,
        base_url=request.form.get("base_url", ""),
        api_key=request.form.get("api_key", ""),
        username=request.form.get("username", ""),
        password=request.form.get("password", ""),
        verify_tls=request.form.get("verify_tls", "1") == "1",
    )
    if db():
        db().set_connector_status(connector_type, result.get("status", "unknown"), result.get("target", request.form.get("base_url", "")), result.get("detail", ""), current_user() or "system")
    flash(f"Connector test: {result.get('status')} — {result.get('detail')}", "success" if result.get("ok") else "error")
    return redirect(url_for("pages.wireless_manager") + "#connectors")


@bp.post("/actions/connectors/sync")
@require_role("engineer")
def connector_sync():
    connector_type = request.form.get("connector_type", "")
    job_id = db().create_job("connector_sync", {"connector_type": connector_type, "base_url": request.form.get("base_url", "")}, current_user() or "system", current_tenant_id()) if db() else "inline"
    try:
        result = vendor_sync_preview(
            connector_type,
            base_url=request.form.get("base_url", ""),
            api_key=request.form.get("api_key", ""),
            username=request.form.get("username", ""),
            password=request.form.get("password", ""),
            verify_tls=request.form.get("verify_tls", "1") == "1",
        )
        if db():
            db().update_job(job_id, "completed" if result.get("ok") else "failed", 100, result if result.get("ok") else None, None if result.get("ok") else result.get("detail"))
            db().connector_run(connector_type, "api-sync-preview", len(result.get("records", [])), "ok" if result.get("ok") else "error", result.get("detail", ""), current_user() or "system")
        flash(f"Sync preview: {result.get('detail')}", "success" if result.get("ok") else "error")
    except Exception as exc:
        if db():
            db().update_job(job_id, "failed", 100, error=str(exc))
        flash(f"Connector sync failed: {exc}", "error")
    return redirect(url_for("pages.wireless_manager") + "#connectors")


@bp.post("/actions/live-ingestion/settings")
@require_role("admin")
def live_ingestion_settings():
    host = request.form.get("host", "0.0.0.0").strip() or "0.0.0.0"
    port = int(request.form.get("port", 5514) or 5514)
    enabled = request.form.get("enabled") == "1"
    db().set_app_setting("live_ingestion", {"host": host, "port": port, "enabled": enabled}, current_user() or "system")
    db().audit(current_user() or "system", "live.settings", f"{host}:{port}", f"enabled={enabled}")
    flash("Live ingestion settings saved.", "success")
    return redirect(url_for("pages.settings") + "#live-ingestion")


@bp.post("/actions/live-ingestion/start")
@require_role("admin")
def live_ingestion_start():
    settings = db().get_app_setting("live_ingestion", {"host": "0.0.0.0", "port": 5514})
    ctrl = current_app.extensions.get("live_ingestion")
    started = ctrl.start(SyslogListenerConfig(host=settings.get("host", "0.0.0.0"), port=int(settings.get("port", 5514)))) if ctrl else False
    db().audit(current_user() or "system", "live.listener.start", f"{settings.get('host')}:{settings.get('port')}", "started" if started else "already-running")
    flash("Live syslog listener started." if started else "Live syslog listener is already running.", "success")
    return redirect(url_for("pages.settings") + "#live-ingestion")


@bp.post("/actions/live-ingestion/stop")
@require_role("admin")
def live_ingestion_stop():
    ctrl = current_app.extensions.get("live_ingestion")
    stopped = ctrl.stop() if ctrl else False
    db().audit(current_user() or "system", "live.listener.stop", "udp_syslog", "stopped" if stopped else "not-running")
    flash("Live syslog listener stop requested." if stopped else "Live syslog listener was not running.", "success")
    return redirect(url_for("pages.settings") + "#live-ingestion")


@bp.post("/actions/jobs/worker/start")
@require_role("admin")
def job_worker_start():
    runner = current_app.extensions.get("job_runner")
    started = runner.start() if runner else False
    db().audit(current_user() or "system", "job.worker.start", "background", "started" if started else "already-running")
    flash("Background worker started." if started else "Background worker already running.", "success")
    return redirect(url_for("pages.settings") + "#jobs")


@bp.post("/actions/jobs/worker/stop")
@require_role("admin")
def job_worker_stop():
    runner = current_app.extensions.get("job_runner")
    stopped = runner.stop() if runner else False
    db().audit(current_user() or "system", "job.worker.stop", "background", "stopped" if stopped else "not-running")
    flash("Background worker stop requested." if stopped else "Background worker was not running.", "success")
    return redirect(url_for("pages.settings") + "#jobs")


@bp.post("/actions/jobs/run-next")
@require_role("admin")
def job_run_next():
    runner = current_app.extensions.get("job_runner")
    job = runner.run_next() if runner else None
    flash(f"Processed queued job: {job.get('id')}" if job else "No queued jobs to process.", "success")
    return redirect(url_for("pages.settings") + "#jobs")


@bp.post("/actions/jobs/<job_id>/retry")
@require_role("admin")
def job_retry(job_id):
    db().retry_job(job_id)
    db().audit(current_user() or "system", "job.retry.manual", job_id, "Queued for retry")
    flash("Job queued for retry.", "success")
    return redirect(url_for("pages.settings") + "#jobs")


@bp.get("/download/audit.csv")
@require_role("admin")
def download_audit_csv():
    raw = db().audit_csv_bytes(
        query=request.args.get("audit_q", ""),
        action=request.args.get("audit_action", ""),
        actor=request.args.get("audit_actor", ""),
        severity=request.args.get("audit_severity", ""),
    )
    return send_file(__import__("io").BytesIO(raw), as_attachment=True, download_name="wiguard_audit_log.csv", mimetype="text/csv")


@bp.post("/actions/users/<username>/disable")
@require_role("admin")
def disable_user(username):
    reason = request.form.get("reason", "Disabled by admin")
    db().disable_user(username, True, reason)
    db().revoke_sessions_for_user(username)
    db().audit(current_user() or "system", "user.disable", username, reason, severity="High")
    flash(f"User disabled and sessions revoked: {username}", "success")
    return redirect(url_for("pages.settings") + "#users")


@bp.post("/actions/users/<username>/enable")
@require_role("admin")
def enable_user(username):
    db().disable_user(username, False, "")
    db().audit(current_user() or "system", "user.enable", username, "Account re-enabled")
    flash(f"User enabled: {username}", "success")
    return redirect(url_for("pages.settings") + "#users")


@bp.post("/actions/users/<username>/force-logout")
@require_role("admin")
def force_logout_user(username):
    db().revoke_sessions_for_user(username)
    db().audit(current_user() or "system", "auth.force_logout", username, "All known sessions revoked", severity="High")
    flash(f"All sessions revoked for {username}.", "success")
    return redirect(url_for("pages.settings") + "#sessions")


@bp.post("/actions/users/<username>/change-password")
@require_role("admin")
def admin_change_password(username):
    try:
        db().change_password(username, request.form.get("new_password", ""))
        db().revoke_sessions_for_user(username)
        db().audit(current_user() or "system", "auth.password_change.admin", username, "Password changed and sessions revoked", severity="High")
        flash("Password changed and sessions revoked.", "success")
    except Exception as exc:
        flash(f"Password change failed: {exc}", "error")
    return redirect(url_for("pages.settings") + "#users")


@bp.post("/actions/users/invite")
@require_role("admin")
def create_user_invite():
    token = db().create_invite_token(request.form.get("email", ""), request.form.get("role", "analyst"), current_tenant_id(), current_user() or "system")
    db().audit(current_user() or "system", "user.invite", request.form.get("email", ""), f"Role={request.form.get('role', 'analyst')}")
    flash(f"Invite token created. Copy once: {token}", "success")
    return redirect(url_for("pages.settings") + "#users")


@bp.post("/actions/users/<username>/password-reset-token")
@require_role("admin")
def create_password_reset(username):
    token = db().create_password_reset_token(username, current_user() or "system")
    db().audit(current_user() or "system", "auth.password_reset.issue", username, "Manual reset token issued", severity="High")
    flash(f"Password reset token created. Copy once: {token}", "success")
    return redirect(url_for("pages.settings") + "#users")


@bp.post("/actions/api-tokens/<int:token_id>/revoke")
@require_role("admin")
def revoke_api_token(token_id):
    db().revoke_api_token(token_id)
    db().audit(current_user() or "system", "api_token.revoke", str(token_id), "Token disabled", severity="High")
    flash("API token revoked.", "success")
    return redirect(url_for("pages.settings") + "#api-tokens")


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
        flash("Database restored after PRAGMA integrity_check. Restart the app if you changed active users or schema state.", "success")
    except Exception as exc:
        flash(f"Database restore failed: {exc}", "error")
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass
    return redirect(url_for("pages.settings") + "#backups")


@bp.post("/download/report/custom.html")
@require_role("auditor")
def download_custom_report_html():
    sections = request.form.getlist("sections") or ["summary", "wireless", "anomalies"]
    return send_file(custom_report_html_bytes(storage().load(), sections), download_name="custom_wiguard_report.html", as_attachment=True, mimetype="text/html")


@bp.get("/download/artifact/<name>")
@require_role("auditor")
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
@require_role("auditor")
def download_report_json(report_type):
    return send_file(report_json_bytes(storage().load(), report_type), download_name=f"{report_type}_report.json", as_attachment=True, mimetype="application/json")


@bp.get("/download/report/<report_type>.pdf")
@require_role("auditor")
def download_report_pdf(report_type):
    return send_file(report_pdf_bytes(storage().load(), report_type), download_name=f"{report_type}_report.pdf", as_attachment=True, mimetype="application/pdf")


@bp.get("/download/report/<report_type>.html")
@require_role("auditor")
def download_report_html(report_type):
    return send_file(report_html_bytes(storage().load(), report_type), download_name=f"{report_type}_report.html", as_attachment=True, mimetype="text/html")


@bp.get("/download/evidence-package.zip")
@require_role("auditor")
def download_evidence_zip():
    return send_file(evidence_zip_bytes(storage().load(), current_app.config["ARTIFACT_DIR"]), download_name="wiguard_evidence_package.zip", as_attachment=True, mimetype="application/zip")


@bp.post("/actions/verify")
@require_role("auditor")
def verify():
    state = storage().load()
    result = verify_manifest(current_app.config["ARTIFACT_DIR"])
    state.setdefault("verifier", {})["last_result"] = result
    _save_state(state, "verifier.run", "artifact_manifest", result["status"])
    flash(f"Verification completed: {result['status'].upper()}.", "success" if result["status"] == "pass" else "error")
    return redirect(url_for("pages.verifier"))


@bp.post("/actions/projects/create")
@require_role("engineer")
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
        "tenant_id": current_tenant_id(),
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
@require_role("viewer")
def switch_project(project_id):
    state = storage().load()
    tenant_id = current_tenant_id()
    if any(p.get("id") == project_id and p.get("tenant_id", tenant_id) == tenant_id for p in state.get("projects", [])):
        state["current_project"] = project_id
        _save_state(state, "project.switch", project_id, "Project selected")
        flash("Project switched.", "success")
    else:
        flash("Project not found or not available for this tenant.", "error")
    return redirect(url_for("pages.projects"))


@bp.post("/actions/projects/<project_id>/delete")
@require_role("admin")
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


@bp.post("/actions/api-tokens/create")
@require_role("admin")
def create_api_token():
    scopes = request.form.getlist("scopes") or [request.form.get("scope", "read")]
    token = db().create_api_token(request.form.get("name", "WiGuard API Token"), scopes, current_tenant_id(), current_user() or "system")
    flash(f"API token created. Copy now: {token['token']}", "success")
    return redirect(url_for("pages.settings") + "#api-tokens")


@bp.get("/reports/preview/<report_type>")
@require_role("auditor")
def report_preview(report_type):
    return send_file(report_html_bytes(storage().load(), report_type), download_name=f"{report_type}_preview.html", as_attachment=False, mimetype="text/html")


@bp.get("/openapi.yaml")
@require_role("auditor")
def openapi_yaml():
    path = current_app.config["ROOT_DIR"] / "openapi.yaml"
    return send_file(path, as_attachment=False, mimetype="application/yaml")


@bp.get("/api/state")
@require_role("auditor")
def api_state():
    return jsonify(_tenant_scoped_state(storage().load()))


@bp.get("/api/diff")
@require_role("auditor")
def api_diff():
    return jsonify(build_policy_diff(storage().load()))


@bp.get("/api/wireless")
@require_role("auditor")
def api_wireless():
    state = storage().load()
    return jsonify(wireless_dashboard(state, build_policy_diff(state)))


@bp.get("/api/events")
@require_role("auditor")
def api_events():
    state = storage().load()
    limit = min(int(request.args.get("limit", 100)), 500)
    since_id = int(request.args.get("since_id", 0) or 0)
    events = [e for e in state.get("events", []) if e.get("tenant_id", current_tenant_id()) == current_tenant_id() and int(e.get("id", 0) or 0) > since_id]
    return jsonify({"events": events[:limit], "count": len(events[:limit]), "latest_id": max([int(e.get("id", 0) or 0) for e in state.get("events", [])] or [0])})


@bp.get("/api/jobs")
@require_role("auditor")
def api_jobs():
    return jsonify({"jobs": db().list_jobs() if db() else []})


@bp.get("/api/v1/state")
@require_api_scope("read")
def api_v1_state():
    return jsonify({"ok": True, "tenant_id": current_tenant_id(), "state": _tenant_scoped_state(storage().load())})


@bp.post("/api/v1/events")
@require_api_scope("ingest")
def api_v1_ingest_events():
    payload = request.get_json(silent=True) or {}
    connector_type = payload.get("connector_type", "syslog_events")
    raw = json.dumps(payload.get("events") or payload.get("records") or [payload]).encode()
    job_id = db().create_job("api_event_ingest", {"connector_type": connector_type}, current_user() or "api", current_tenant_id()) if db() else "inline"
    try:
        count, errors = _run_connector_job(job_id, connector_type, "api_events.json", raw, live=True)
        return jsonify({"ok": not errors, "job_id": job_id, "count": count, "errors": errors})
    except Exception as exc:
        if db():
            db().update_job(job_id, "failed", 100, error=str(exc))
        return jsonify({"ok": False, "job_id": job_id, "error": str(exc)}), 400
