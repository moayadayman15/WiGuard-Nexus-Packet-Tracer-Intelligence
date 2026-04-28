import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from .services.storage import Storage
from .services.database import AppDatabase
from .services.wireless import normalize_wireless_state
from .services.live_ingestion import LiveIngestionController
from .services.background import BackgroundJobRunner, noop_job_handler


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def create_app():
    from flask import Flask, request
    from .security import csrf_token, current_user, current_role, current_tenant_id, can_role, enforce_request_security

    app = Flask(__name__, instance_relative_config=True)
    root = Path(__file__).resolve().parent.parent
    env = os.environ.get("WIGUARD_ENV", "development").strip().lower()
    secret = os.environ.get("WIGUARD_SECRET_KEY") or os.environ.get("SECRET_KEY") or "dev-only-change-me-wiguard-nexus-v5"
    if env == "production" and secret == "dev-only-change-me-wiguard-nexus-v5":
        raise RuntimeError("Production mode requires WIGUARD_SECRET_KEY to be set to a strong random value.")

    db_backend = os.environ.get("WIGUARD_DB_BACKEND", "sqlite").strip().lower()
    database_url = os.environ.get("DATABASE_URL", "")
    app.config.update(
        SECRET_KEY=secret,
        ROOT_DIR=root,
        DATA_FILE=Path(os.environ.get("WIGUARD_DATA_FILE", root / "data" / "state.json")),
        DB_PATH=Path(os.environ.get("WIGUARD_DB_PATH", root / "data" / "wiguard.sqlite3")),
        DB_BACKEND=db_backend,
        DATABASE_URL=database_url,
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
        ENVIRONMENT=env,
        DISABLE_DEMO_FALLBACK=_bool_env("WIGUARD_DISABLE_DEMO_FALLBACK", env == "production"),
        LOGIN_MAX_FAILURES=int(os.environ.get("WIGUARD_LOGIN_MAX_FAILURES", 5)),
        LOGIN_RATE_WINDOW_SECONDS=int(os.environ.get("WIGUARD_LOGIN_RATE_WINDOW_SECONDS", 900)),
        DEFAULT_TENANT_ID=os.environ.get("WIGUARD_DEFAULT_TENANT_ID", "tenant-main"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_bool_env("WIGUARD_SESSION_COOKIE_SECURE", env == "production"),
    )
    for key in ["ARTIFACT_DIR", "UPLOAD_DIR", "REPORT_DIR", "SAMPLE_DIR"]:
        app.config[key].mkdir(parents=True, exist_ok=True)
    log_dir = app.config["DATA_FILE"].parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    if not any(getattr(h, "baseFilename", "") == str(log_dir / "wiguard.log") for h in app.logger.handlers):
        handler = RotatingFileHandler(log_dir / "wiguard.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    storage = Storage(app.config["DATA_FILE"])
    storage.ensure_seed()
    state = storage.load()
    state.setdefault("version", "5.9.3-professional-quality-studio")
    state.setdefault("tenant_id", app.config["DEFAULT_TENANT_ID"])
    state.setdefault("tenants", [{"id": app.config["DEFAULT_TENANT_ID"], "name": "Main Tenant", "status": "active"}])
    for p in state.get("projects", []):
        p.setdefault("tenant_id", state.get("tenant_id", app.config["DEFAULT_TENANT_ID"]))
    normalize_wireless_state(state)
    storage.save(state)
    app.extensions["storage"] = storage
    app.extensions["db"] = AppDatabase(app.config["DB_PATH"])
    app.logger.info("WiGuard booted with data_file=%s db_path=%s", app.config["DATA_FILE"], app.config["DB_PATH"])
    app.extensions["live_ingestion"] = LiveIngestionController(app)
    runner = BackgroundJobRunner(app, handlers={"noop": noop_job_handler, "report_generation": noop_job_handler, "connector_sync": noop_job_handler})
    app.extensions["job_runner"] = runner
    if _bool_env("WIGUARD_JOB_WORKER_AUTOSTART", False):
        runner.start()
    app.permanent_session_lifetime = int(os.environ.get("WIGUARD_SESSION_SECONDS", 3600))

    app.before_request(enforce_request_security)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:")
        if app.config.get("ENVIRONMENT") == "production" and request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    app.context_processor(lambda: {
        "csrf_token": csrf_token,
        "current_user": current_user(),
        "current_role": current_role(),
        "current_tenant_id": current_tenant_id(),
        "can_role": can_role,
    })

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
