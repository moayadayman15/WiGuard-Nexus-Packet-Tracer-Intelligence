import os
from pathlib import Path
from .services.storage import Storage
from .services.database import AppDatabase
from .services.wireless import normalize_wireless_state


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def create_app():
    from flask import Flask
    from .security import csrf_token, current_user, current_role, enforce_request_security

    app = Flask(__name__, instance_relative_config=True)
    root = Path(__file__).resolve().parent.parent
    secret = os.environ.get("WIGUARD_SECRET_KEY") or os.environ.get("SECRET_KEY") or "dev-only-change-me-wiguard-nexus-v5"
    app.config.update(
        SECRET_KEY=secret,
        ROOT_DIR=root,
        DATA_FILE=Path(os.environ.get("WIGUARD_DATA_FILE", root / "data" / "state.json")),
        DB_PATH=Path(os.environ.get("WIGUARD_DB_PATH", root / "data" / "wiguard.sqlite3")),
        ARTIFACT_DIR=Path(os.environ.get("WIGUARD_ARTIFACT_DIR", root / "data" / "artifacts")),
        UPLOAD_DIR=Path(os.environ.get("WIGUARD_UPLOAD_DIR", root / "data" / "uploads")),
        REPORT_DIR=Path(os.environ.get("WIGUARD_REPORT_DIR", root / "data" / "reports")),
        SAMPLE_DIR=Path(os.environ.get("WIGUARD_SAMPLE_DIR", root / "data" / "samples")),
        MAX_CONTENT_LENGTH=int(os.environ.get("WIGUARD_MAX_UPLOAD_BYTES", 20 * 1024 * 1024)),
        AUTH_REQUIRED=_bool_env("WIGUARD_AUTH_REQUIRED", True),
        REGISTRATION_ENABLED=_bool_env("WIGUARD_REGISTRATION_ENABLED", True),
        ADMIN_USERNAME=os.environ.get("WIGUARD_ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD=os.environ.get("WIGUARD_ADMIN_PASSWORD", "admin123"),
        ADMIN_PASSWORD_HASH=os.environ.get("WIGUARD_ADMIN_PASSWORD_HASH"),
        ENVIRONMENT=os.environ.get("WIGUARD_ENV", "development"),
        DISABLE_DEMO_FALLBACK=_bool_env("WIGUARD_DISABLE_DEMO_FALLBACK", False),
        LOGIN_MAX_FAILURES=int(os.environ.get("WIGUARD_LOGIN_MAX_FAILURES", 5)),
        LOGIN_RATE_WINDOW_SECONDS=int(os.environ.get("WIGUARD_LOGIN_RATE_WINDOW_SECONDS", 900)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    for key in ["ARTIFACT_DIR", "UPLOAD_DIR", "REPORT_DIR", "SAMPLE_DIR"]:
        app.config[key].mkdir(parents=True, exist_ok=True)

    storage = Storage(app.config["DATA_FILE"])
    storage.ensure_seed()
    state = storage.load()
    normalize_wireless_state(state)
    storage.save(state)
    app.extensions["storage"] = storage
    app.extensions["db"] = AppDatabase(app.config["DB_PATH"])
    app.permanent_session_lifetime = int(os.environ.get("WIGUARD_SESSION_SECONDS", 3600))

    app.before_request(enforce_request_security)
    app.context_processor(lambda: {"csrf_token": csrf_token, "current_user": current_user(), "current_role": current_role()})

    from .routes.pages import bp as pages_bp
    from .routes.actions import bp as actions_bp
    app.register_blueprint(pages_bp)
    app.register_blueprint(actions_bp)

    @app.errorhandler(403)
    def forbidden(error):
        from flask import render_template
        return render_template("error.html", code=403, title="Access denied", message="Your current role is not allowed to perform this action."), 403

    @app.errorhandler(404)
    def not_found(error):
        from flask import render_template
        return render_template("error.html", code=404, title="Page not found", message="The requested WiGuard workspace route was not found."), 404

    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template
        return render_template("error.html", code=500, title="Server error", message="WiGuard hit an unexpected error. Check the audit log and application logs."), 500

    return app
