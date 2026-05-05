from flask import Blueprint, render_template, current_app, request
from ..security import current_tenant_id
from ..version import get_product_label, get_version
from ..services.state_schema import ensure_state_shape
from ..services.intelligence import (
    build_policy_diff, build_root_causes, build_topology, build_timeline,
    build_playbooks, risk_score, object_counts, object_count_breakdown, get_objects, build_snapshot_diff, build_extraction_diagnostics, build_topology_insights, build_validation_rule_assessment, build_evidence_quality_matrix, build_analyst_signoff, build_import_truth_summary, build_workspace_model, build_analysis_studio, build_report_builder_model
)
from ..services.artifacts import verify_manifest
from ..services.reporting import REPORT_TYPES
from ..services.compliance import build_compliance_matrix
from ..services.connectors import SUPPORTED_CONNECTORS, CONNECTOR_SCHEMAS
from ..services.wireless import normalize_wireless_state, wireless_dashboard
from ..services.util import log_safely
from ..services.product_intelligence import build_product_intelligence
from ..services.professional_pipeline import health_report, build_professional_analysis

bp = Blueprint("pages", __name__)


def _safe_context(label, default, func):
    """Never let a broken optional widget/SQLite query take a page down."""
    try:
        return func()
    except Exception as exc:
        log_safely(current_app.logger, "exception", "WiGuard page context failed for %s: %s", label, exc)
        return default


def _safe_db(db_obj, label, default, method_name, *args, **kwargs):
    if not db_obj or not hasattr(db_obj, method_name):
        return default
    return _safe_context(label, default, lambda: getattr(db_obj, method_name)(*args, **kwargs))


def _tenant_state(state):
    return ensure_state_shape(
        state,
        tenant_id=current_tenant_id(),
        version=get_version(),
        product=get_product_label(),
        tagline="Network Intelligence Engine workspace",
    )


def ctx():
    state = _safe_context("storage.load", {}, lambda: current_app.extensions["storage"].load())
    state = _tenant_state(state)
    _safe_context("wireless.normalize", None, lambda: normalize_wireless_state(state))
    objects = _safe_context("objects", {}, lambda: get_objects(state)) or {}
    active = state.get("active_extraction", {}) or {}
    tenant_id = current_tenant_id()
    visible_projects = [p for p in state.get("projects", []) if p.get("tenant_id", tenant_id) == tenant_id]
    if not visible_projects:
        visible_projects = state.get("projects", []) or [{"id": "main-campus", "name": "Main Campus Lab", "tenant_id": tenant_id}]
    current_project = next((p for p in visible_projects if p.get("id") == state.get("current_project")), visible_projects[0])
    counts = _safe_context("object_counts", {}, lambda: object_counts(objects))
    count_breakdown = _safe_context("object_count_breakdown", {}, lambda: object_count_breakdown(objects))
    diffs = _safe_context("policy_diff", [], lambda: build_policy_diff(state))
    wireless = _safe_context("wireless_dashboard", {"matrix": [], "risk": {"score": 0}, "confidence": {}}, lambda: wireless_dashboard(state, diffs))
    event_type_filter = request.args.get("type", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    client_filter = request.args.get("client", "").strip().lower()
    filtered_events = []
    for ev in state.get("events", []):
        if not isinstance(ev, dict):
            continue
        if ev.get("tenant_id", tenant_id) != tenant_id:
            continue
        if event_type_filter and ev.get("type") != event_type_filter:
            continue
        if severity_filter and ev.get("severity") != severity_filter:
            continue
        if client_filter and client_filter not in str(ev.get("client", "")).lower() and client_filter not in str(ev.get("detail", "")).lower():
            continue
        filtered_events.append(ev)
    compliance = _safe_context("compliance", [], lambda: build_compliance_matrix(state, wireless, diffs))
    db_obj = current_app.extensions.get("db")
    audit_query = request.args.get("audit_q", "").strip()
    audit_action = request.args.get("audit_action", "").strip()
    audit_actor = request.args.get("audit_actor", "").strip()
    audit_severity = request.args.get("audit_severity", "").strip()
    live_ctrl = current_app.extensions.get("live_ingestion")
    job_runner = current_app.extensions.get("job_runner")
    live_default = {"host": "0.0.0.0", "port": 5514, "enabled": False}
    live_settings = _safe_db(db_obj, "db.app_settings.live_ingestion", live_default, "get_app_setting", "live_ingestion", live_default)
    return {
        "state": state,
        "active": active,
        "tenant_id": tenant_id,
        "current_project": current_project,
        "visible_projects": visible_projects,
        "artifacts": active.get("artifacts", {}) or {},
        "conversion_profile": active.get("conversion_profile", {}) or objects.get("packet_tracer_profile", {}) or {},
        "objects": objects,
        "counts": counts,
        "count_breakdown": count_breakdown,
        "diffs": diffs,
        "causes": _safe_context("root_causes", [], lambda: build_root_causes(state)),
        "topology": _safe_context("topology", {"nodes": [], "edges": []}, lambda: build_topology(state)),
        "timeline": _safe_context("timeline", [], lambda: build_timeline(state)),
        "playbooks": _safe_context("playbooks", [], lambda: build_playbooks(state)),
        "risk": _safe_context("risk_score", {"score": 0, "label": "Unknown"}, lambda: risk_score(state)),
        "wireless": wireless,
        "verifier": _safe_context("verifier", {"status": "unknown", "items": []}, lambda: verify_manifest(current_app.config["ARTIFACT_DIR"])),
        "report_types": REPORT_TYPES,
        "snapshot_diff": _safe_context("snapshot_diff", [], lambda: build_snapshot_diff(state)),
        "filtered_events": filtered_events,
        "event_type_filter": event_type_filter,
        "severity_filter": severity_filter,
        "client_filter": client_filter,
        "compliance": compliance,
        "connector_types": SUPPORTED_CONNECTORS,
        "connector_schemas": CONNECTOR_SCHEMAS,
        "connector_runs": _safe_db(db_obj, "db.connector_runs", [], "connector_runs"),
        "connector_statuses": _safe_db(db_obj, "db.connector_statuses", [], "connector_statuses"),
        "jobs": _safe_db(db_obj, "db.jobs", [], "list_jobs"),
        "tenants": _safe_db(db_obj, "db.tenants", state.get("tenants", []), "list_tenants"),
        "api_tokens": _safe_db(db_obj, "db.api_tokens", [], "list_api_tokens"),
        "db_health": _safe_db(db_obj, "db.health", {"ok": False, "error": "database unavailable"}, "health"),
        "db_backend": current_app.config.get("DB_BACKEND", "sqlite"),
        "database_url_configured": bool(current_app.config.get("DATABASE_URL")),
        "db_migrations": _safe_db(db_obj, "db.migrations", [], "migrations"),
        "db_backups": _safe_db(db_obj, "db.backups", [], "list_backups"),
        "users": _safe_db(db_obj, "db.users", [], "list_users"),
        "audit_query": audit_query,
        "audit_action": audit_action,
        "audit_actor": audit_actor,
        "audit_severity": audit_severity,
        "audit_tail": _safe_db(db_obj, "db.audit_search", [], "audit_search", audit_query, 100, action=audit_action, actor=audit_actor, severity=audit_severity),
        "audit_chain": _safe_db(db_obj, "db.audit_chain", {"ok": True, "checked": 0}, "verify_audit_chain"),
        "raw_live_events": _safe_db(db_obj, "db.raw_events", [], "raw_events", 100),
        "live_settings": live_settings,
        "live_status": _safe_context("live.status", {"running": False}, lambda: live_ctrl.status() if live_ctrl else {"running": False}),
        "job_runner_status": _safe_context("job_runner.status", {"running": False}, lambda: job_runner.status() if job_runner else {"running": False}),
        "sessions": _safe_db(db_obj, "db.sessions", [], "list_sessions"),
        "invites": _safe_db(db_obj, "db.invites", [], "list_invites"),
        "diagnostics": _safe_context("diagnostics", {}, lambda: build_extraction_diagnostics(state)),
        "topology_insights": _safe_context("topology_insights", {}, lambda: build_topology_insights(state)),
        "rule_assessment": _safe_context("rule_assessment", {}, lambda: build_validation_rule_assessment(state)),
        "evidence_quality_matrix": _safe_context("evidence_quality_matrix", {}, lambda: build_evidence_quality_matrix(state)),
        "analyst_signoff": _safe_context("analyst_signoff", {}, lambda: build_analyst_signoff(state)),
        "import_truth": _safe_context("import_truth", {}, lambda: build_import_truth_summary(state)),
        "workspace_model": _safe_context("workspace_model", {}, lambda: build_workspace_model(state)),
        "analysis_studio": _safe_context("analysis_studio", {}, lambda: build_analysis_studio(state)),
        "report_builder": _safe_context("report_builder", {}, lambda: build_report_builder_model(state, REPORT_TYPES)),
        "product_intelligence": _safe_context("product_intelligence", {}, lambda: build_product_intelligence(state)),
        "professional_health": _safe_context("professional_health", {}, lambda: health_report(current_app.config.get("ROOT_DIR"))),
        "professional_analysis": _safe_context("professional_analysis", {}, lambda: build_professional_analysis(objects, {"filename": active.get("filename"), "source_mode": active.get("source_mode")}).__dict__),
    }


@bp.route("/healthz")
def health():
    db_obj = current_app.extensions.get("db")
    storage_ok = bool(current_app.extensions.get("storage"))
    pro = _safe_context("professional.healthz", {}, lambda: health_report(current_app.config.get("ROOT_DIR")))
    db_health = _safe_context(
        "db.healthz",
        {"ok": False, "error": current_app.config.get("DB_INIT_ERROR", "database unavailable")},
        lambda: db_obj.health() if db_obj else {"ok": False, "error": current_app.config.get("DB_INIT_ERROR", "database unavailable")},
    )
    payload = {"ok": bool(storage_ok and pro.get("ok", True)), "storage": storage_ok, "database": db_health, "professional_pipeline": pro}
    from flask import jsonify
    return jsonify(payload)


@bp.route("/system-health")
def system_health():
    return render_template("system_health.html", page="system-health", **ctx())


@bp.route("/api/system-health")
def api_system_health():
    from flask import jsonify
    return jsonify(health_report(current_app.config.get("ROOT_DIR")))


@bp.route("/api/normalized-data")
def api_normalized_data():
    from flask import jsonify
    state = current_app.extensions["storage"].load()
    active = state.get("active_extraction", {}) or {}
    objects = (active.get("objects") or {}) if isinstance(active, dict) else {}
    result = build_professional_analysis(objects, {"filename": active.get("filename"), "source_mode": active.get("source_mode")})
    return jsonify(result.__dict__)


@bp.route("/login")
def login():
    db_obj = current_app.extensions.get("db")
    user_count = 0
    db_login_error = ""
    if db_obj:
        try:
            user_count = db_obj.user_count()
        except Exception as exc:
            db_login_error = str(exc)
            current_app.logger.exception("Login page could not read SQLite user count; showing fallback login: %s", exc)
    return render_template(
        "login.html",
        next_url=request.args.get("next", "/"),
        user_count=user_count,
        db_login_error=db_login_error,
        registration_enabled=current_app.config.get("REGISTRATION_ENABLED", True),
        demo_fallback_enabled=not current_app.config.get("DISABLE_DEMO_FALLBACK", False),
        admin_username=current_app.config.get("ADMIN_USERNAME", "admin"),
        environment=current_app.config.get("ENVIRONMENT", "development"),
    )


@bp.route("/register")
def register():
    db_obj = current_app.extensions.get("db")
    user_count = db_obj.user_count() if db_obj else 0
    return render_template(
        "register.html",
        next_url=request.args.get("next", "/"),
        user_count=user_count,
        registration_enabled=current_app.config.get("REGISTRATION_ENABLED", True),
    )


@bp.route("/")
def overview():
    return render_template("overview.html", page="overview", **ctx())


@bp.route("/wireless")
def wireless_manager():
    return render_template("wireless.html", page="wireless", **ctx())


@bp.route("/projects")
def projects():
    return render_template("projects.html", page="projects", **ctx())


@bp.route("/import")
def import_center():
    return render_template("import.html", page="import", **ctx())


@bp.route("/workspace")
def workspace():
    return render_template("workspace.html", page="workspace", **ctx())


@bp.route("/analysis")
def analysis_studio_page():
    return render_template("analysis.html", page="analysis", **ctx())


@bp.route("/objects")
def object_explorer():
    query = request.args.get("q", "").lower().strip()
    category = request.args.get("category", "all")
    status_filter = request.args.get("status", "all")
    high_value_only = request.args.get("high_value", "") == "1"
    data = ctx()
    objects = data["objects"] if isinstance(data.get("objects"), dict) else {}
    flat = []

    def normalize_object_for_explorer(obj):
        """Return a template-safe dict for any extracted row."""
        if isinstance(obj, dict):
            normalized = dict(obj)
            if not isinstance(normalized.get("evidence"), dict):
                normalized["evidence"] = {}
            return normalized
        return {"value": str(obj), "evidence": {}, "kind": type(obj).__name__}

    def object_evidence_row(cat, obj):
        obj = normalize_object_for_explorer(obj)
        name_candidates = [obj.get("hostname"), obj.get("id"), obj.get("name"), obj.get("interface"), obj.get("normalized_interface"), obj.get("vlan"), obj.get("ip_address"), obj.get("acl"), obj.get("pool")]
        for candidate in name_candidates:
            if candidate not in (None, "", []):
                found = evidence_status_by_name.get((cat, str(candidate)[:180]))
                if found:
                    return found
        return {}
    def passes_evidence_filters(cat, obj):
        row = object_evidence_row(cat, obj)
        if status_filter != "all" and (row.get("status") or "unmapped") != status_filter:
            return False
        if high_value_only and not row.get("high_value"):
            return False
        return True
    evidence_status_by_name = {}
    for row in objects.get("evidence_registry", []) if isinstance(objects.get("evidence_registry"), list) else []:
        if isinstance(row, dict):
            evidence_status_by_name[(row.get("category"), row.get("name"))] = row
    for key, value in objects.items():
        if isinstance(value, list):
            for obj in value:
                text = str(obj).lower()
                if (category == "all" or key == category) and (not query or query in text) and passes_evidence_filters(key, obj):
                    safe_obj = normalize_object_for_explorer(obj)
                    flat.append({"category": key, "object": safe_obj, "evidence_row": object_evidence_row(key, safe_obj)})
        elif isinstance(value, dict):
            for subkey, subval in value.items():
                if isinstance(subval, list):
                    for obj in subval:
                        text = str(obj).lower()
                        name = f"{key}.{subkey}"
                        if (category == "all" or key == category or name == category) and (not query or query in text) and passes_evidence_filters(key, obj):
                            safe_obj = normalize_object_for_explorer(obj)
                            flat.append({"category": name, "object": safe_obj, "evidence_row": object_evidence_row(key, safe_obj)})
    data.update({"flat_objects": flat, "query": query, "category": category, "status_filter": status_filter, "high_value_only": high_value_only})
    return render_template("objects.html", page="objects", **data)


@bp.route("/topology")
def topology():
    return render_template("topology.html", page="topology", **ctx())


@bp.route("/intelligence")
def product_intelligence():
    return render_template("product_intelligence.html", page="intelligence", **ctx())


@bp.route("/threat-map")
def threat_map():
    return render_template("threat_map.html", page="threat", **ctx())


@bp.route("/diff")
def diff():
    return render_template("diff.html", page="diff", **ctx())


@bp.route("/root-cause")
def root_cause():
    return render_template("root_cause.html", page="root", **ctx())


@bp.route("/rules")
def rules():
    return render_template("rules.html", page="rules", **ctx())


@bp.route("/simulation")
def simulation():
    return render_template("simulation.html", page="simulation", **ctx())


@bp.route("/playbooks")
def playbooks():
    return render_template("playbooks.html", page="playbooks", **ctx())


@bp.route("/history")
def history():
    return render_template("history.html", page="history", **ctx())


@bp.route("/timeline")
def timeline():
    return render_template("timeline.html", page="timeline", **ctx())


@bp.route("/verifier")
def verifier():
    return render_template("verifier.html", page="verifier", **ctx())


@bp.route("/snapshot")
def snapshot():
    return render_template("snapshot.html", page="snapshot", **ctx())


@bp.route("/reports")
def reports():
    return render_template("reports.html", page="reports", **ctx())


@bp.route("/events")
def events():
    return render_template("events.html", page="events", **ctx())


@bp.route("/settings")
def settings():
    return render_template("settings.html", page="settings", **ctx())
