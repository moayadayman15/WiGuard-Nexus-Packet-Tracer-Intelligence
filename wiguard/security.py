import functools
import hmac
import secrets
import uuid
from urllib.parse import urlparse, urljoin
from flask import current_app, g, redirect, request, session, url_for, abort, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash


AUTH_EXEMPT_ENDPOINTS = {"pages.login", "actions.login", "pages.register", "actions.register", "actions.accept_invite", "actions.password_reset_request", "actions.password_reset_apply", "pages.health", "static"}
CSRF_EXEMPT_ENDPOINTS = {"static", "pages.health"}
ROLE_ORDER = {"viewer": 1, "auditor": 2, "analyst": 3, "engineer": 4, "admin": 5}
API_SCOPE_ORDER = {"read": 1, "ingest": 2, "write": 3, "admin": 4}


def auth_required() -> bool:
    return bool(current_app.config.get("AUTH_REQUIRED", True))


def current_user():
    return getattr(g, "api_actor", None) or session.get("wiguard_user")


def current_role():
    return getattr(g, "api_role", None) or session.get("wiguard_role", "analyst" if current_user() else "anonymous")


def current_tenant_id() -> str:
    return getattr(g, "api_tenant_id", None) or session.get("wiguard_tenant_id") or current_app.config.get("DEFAULT_TENANT_ID", "tenant-main")


def is_authenticated() -> bool:
    return bool(current_user())


def role_at_least(required: str) -> bool:
    return ROLE_ORDER.get(current_role(), 0) >= ROLE_ORDER.get(required, 999)


def can_role(required: str) -> bool:
    return role_at_least(required)


def require_role(required: str):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not is_authenticated():
                return redirect(url_for("pages.login", next=request.full_path if request.query_string else request.path))
            if not role_at_least(required):
                flash(f"This action requires {required} access or higher.", "error")
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def scope_at_least(required: str) -> bool:
    scopes = getattr(g, "api_scopes", []) or []
    if "admin" in scopes:
        return True
    return any(API_SCOPE_ORDER.get(scope, 0) >= API_SCOPE_ORDER.get(required, 999) for scope in scopes)


def require_api_scope(required: str):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not getattr(g, "api_actor", None):
                return jsonify({"ok": False, "error": "API token required"}), 401
            if not scope_at_least(required):
                return jsonify({"ok": False, "error": f"scope '{required}' required"}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


def configured_username() -> str:
    return current_app.config.get("ADMIN_USERNAME", "admin")


def configured_password_hash() -> str:
    """Return the emergency/demo fallback password hash."""
    password_hash = current_app.config.get("ADMIN_PASSWORD_HASH")
    if password_hash:
        return password_hash
    fallback_password = current_app.config.get("ADMIN_PASSWORD", "admin123")
    return generate_password_hash(fallback_password)


def request_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded or request.remote_addr or "unknown"


def is_safe_redirect_url(target: str) -> bool:
    if not target:
        return False
    base_url = request.host_url
    test_url = urljoin(base_url, target)
    base = urlparse(base_url)
    test = urlparse(test_url)
    return test.scheme in {"http", "https"} and base.netloc == test.netloc and not target.startswith("//")


def safe_redirect_target(target: str, fallback: str = "pages.overview") -> str:
    return target if is_safe_redirect_url(target) else url_for(fallback)


def login_rate_allowed(username: str):
    db = current_app.extensions.get("db")
    if not db:
        return True, 0
    return db.login_allowed(
        username=username,
        ip_address=request_ip(),
        max_failures=int(current_app.config.get("LOGIN_MAX_FAILURES", 5)),
        window_seconds=int(current_app.config.get("LOGIN_RATE_WINDOW_SECONDS", 900)),
    )


def verify_login(username: str, password: str):
    username = (username or "").strip().lower()
    if not username or not password:
        return None
    db = current_app.extensions.get("db")
    allowed, remaining = login_rate_allowed(username)
    if not allowed:
        if db:
            db.audit(username, "auth.rate_limited", request_ip(), "Too many login attempts")
        return {"error": "rate_limited", "remaining": remaining}
    if db:
        user = db.verify_user(username, password)
        if user:
            tenant_id = db.default_tenant_for_user(username)
            db.record_login_attempt(username, request_ip(), True, "sqlite")
            db.audit(username, "auth.login", username, "SQLite user login")
            user["tenant_id"] = tenant_id
            return user
    # Local/demo fallback. Disable in production with WIGUARD_DISABLE_DEMO_FALLBACK=1 after creating a real account.
    if not current_app.config.get("DISABLE_DEMO_FALLBACK", False):
        if hmac.compare_digest(username, configured_username().lower()) and check_password_hash(configured_password_hash(), password):
            if db:
                db.record_login_attempt(username, request_ip(), True, "fallback")
                db.audit(username, "auth.login", username, "Emergency/demo fallback login")
            return {"username": username, "role": "admin", "tenant_id": current_app.config.get("DEFAULT_TENANT_ID", "tenant-main")}
    if db:
        db.record_login_attempt(username, request_ip(), False, "invalid_credentials")
        db.audit(username, "auth.failed", username, f"Invalid credentials from {request_ip()}")
    return None


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> bool:
    expected = session.get("csrf_token")
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def authenticate_api_token() -> bool:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return False
    token = auth.split(None, 1)[1].strip()
    db = current_app.extensions.get("db")
    if not db or not token:
        return False
    verified = db.verify_api_token(token, request_ip())
    if not verified:
        return False
    g.api_actor = verified.get("name") or "api-token"
    g.api_role = "admin" if "admin" in verified.get("scopes", []) else "analyst"
    g.api_scopes = verified.get("scopes", [])
    g.api_tenant_id = verified.get("tenant_id") or current_app.config.get("DEFAULT_TENANT_ID", "tenant-main")
    return True


def enforce_request_security():
    endpoint = request.endpoint or ""
    authenticate_api_token()

    if endpoint in CSRF_EXEMPT_ENDPOINTS or endpoint.startswith("static"):
        return None

    if getattr(g, "api_actor", None):
        return None

    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not validate_csrf():
        abort(400, description="Invalid or missing CSRF token.")

    if not auth_required():
        return None

    if endpoint in AUTH_EXEMPT_ENDPOINTS or endpoint.startswith("static"):
        return None

    if not is_authenticated():
        return redirect(url_for("pages.login", next=request.full_path if request.query_string else request.path))
    db = current_app.extensions.get("db")
    sid = session.get("wiguard_session_id")
    if db and sid:
        if db.is_session_revoked(sid):
            session.clear()
            flash("Your session was revoked by an administrator. Please sign in again.", "error")
            return redirect(url_for("pages.login"))
        db.touch_session(sid)
    return None


def login_user(user):
    session.clear()
    sid = uuid.uuid4().hex
    session["wiguard_session_id"] = sid
    if isinstance(user, dict):
        session["wiguard_user"] = user.get("username")
        session["wiguard_role"] = user.get("role", "analyst")
        session["wiguard_tenant_id"] = user.get("tenant_id") or current_app.config.get("DEFAULT_TENANT_ID", "tenant-main")
    else:
        session["wiguard_user"] = str(user)
        session["wiguard_role"] = "admin"
        session["wiguard_tenant_id"] = current_app.config.get("DEFAULT_TENANT_ID", "tenant-main")
    session.permanent = True
    db = current_app.extensions.get("db")
    if db and session.get("wiguard_user"):
        db.register_session(sid, session.get("wiguard_user"), session.get("wiguard_tenant_id"), request_ip(), request.headers.get("User-Agent", ""))
    csrf_token()

def logout_user():
    username = current_user()
    db = current_app.extensions.get("db")
    if db and username:
        db.audit(username, "auth.logout", username, "User logged out")
    session.clear()
