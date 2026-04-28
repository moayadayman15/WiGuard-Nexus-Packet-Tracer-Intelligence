from flask import Blueprint, render_template, current_app, request
from ..services.intelligence import (
    build_policy_diff, build_root_causes, build_topology, build_timeline,
    build_playbooks, risk_score, object_counts, get_objects, build_snapshot_diff
)
from ..services.artifacts import verify_manifest
from ..services.reporting import REPORT_TYPES
from ..services.compliance import build_compliance_matrix
from ..services.connectors import SUPPORTED_CONNECTORS
from ..services.wireless import normalize_wireless_state, wireless_dashboard

bp = Blueprint("pages", __name__)


def ctx():
    state = current_app.extensions["storage"].load()
    normalize_wireless_state(state)
    objects = get_objects(state)
    active = state.get("active_extraction", {}) or {}
    current_project = next((p for p in state.get("projects", []) if p.get("id") == state.get("current_project")), (state.get("projects") or [{}])[0])
    diffs = build_policy_diff(state)
    wireless = wireless_dashboard(state, diffs)
    event_type_filter = request.args.get("type", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    client_filter = request.args.get("client", "").strip().lower()
    filtered_events = []
    for ev in state.get("events", []):
        if event_type_filter and ev.get("type") != event_type_filter:
            continue
        if severity_filter and ev.get("severity") != severity_filter:
            continue
        if client_filter and client_filter not in str(ev.get("client", "")).lower():
            continue
        filtered_events.append(ev)
    compliance = build_compliance_matrix(state, wireless, diffs)
    return {
        "state": state,
        "active": active,
        "current_project": current_project,
        "artifacts": active.get("artifacts", {}) or {},
        "objects": objects,
        "counts": object_counts(objects),
        "diffs": diffs,
        "causes": build_root_causes(state),
        "topology": build_topology(state),
        "timeline": build_timeline(state),
        "playbooks": build_playbooks(state),
        "risk": risk_score(state),
        "wireless": wireless,
        "verifier": verify_manifest(current_app.config["ARTIFACT_DIR"]),
        "report_types": REPORT_TYPES,
        "snapshot_diff": build_snapshot_diff(state),
        "filtered_events": filtered_events,
        "event_type_filter": event_type_filter,
        "severity_filter": severity_filter,
        "client_filter": client_filter,
        "compliance": compliance,
        "connector_types": SUPPORTED_CONNECTORS,
        "connector_runs": current_app.extensions.get("db").connector_runs() if current_app.extensions.get("db") else [],
        "db_health": current_app.extensions.get("db").health() if current_app.extensions.get("db") else {},
        "db_migrations": current_app.extensions.get("db").migrations() if current_app.extensions.get("db") else [],
        "db_backups": current_app.extensions.get("db").list_backups() if current_app.extensions.get("db") else [],
        "users": current_app.extensions.get("db").list_users() if current_app.extensions.get("db") else [],
        "audit_tail": current_app.extensions.get("db").audit_tail(20) if current_app.extensions.get("db") else [],
    }


@bp.route("/healthz")
def health():
    db_obj = current_app.extensions.get("db")
    storage_ok = bool(current_app.extensions.get("storage"))
    payload = {"ok": True, "storage": storage_ok, "database": db_obj.health() if db_obj else {"ok": False}}
    from flask import jsonify
    return jsonify(payload)


@bp.route("/login")
def login():
    db_obj = current_app.extensions.get("db")
    user_count = db_obj.user_count() if db_obj else 0
    return render_template(
        "login.html",
        next_url=request.args.get("next", "/"),
        user_count=user_count,
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


@bp.route("/objects")
def object_explorer():
    query = request.args.get("q", "").lower().strip()
    category = request.args.get("category", "all")
    data = ctx()
    objects = data["objects"]
    flat = []
    for key, value in objects.items():
        if isinstance(value, list):
            for obj in value:
                text = str(obj).lower()
                if (category == "all" or key == category) and (not query or query in text):
                    flat.append({"category": key, "object": obj})
        elif isinstance(value, dict):
            for subkey, subval in value.items():
                if isinstance(subval, list):
                    for obj in subval:
                        text = str(obj).lower()
                        name = f"{key}.{subkey}"
                        if (category == "all" or key == category or name == category) and (not query or query in text):
                            flat.append({"category": name, "object": obj})
    data.update({"flat_objects": flat, "query": query, "category": category})
    return render_template("objects.html", page="objects", **data)


@bp.route("/topology")
def topology():
    return render_template("topology.html", page="topology", **ctx())


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
