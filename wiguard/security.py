import functools
import hmac
import secrets
from flask import current_app, redirect, request, session, url_for, abort, flash
from werkzeug.security import check_password_hash, generate_password_hash


AUTH_EXEMPT_ENDPOINTS = {"pages.login", "actions.login", "pages.register", "actions.register", "pages.health", "static"}
CSRF_EXEMPT_ENDPOINTS = {"static", "pages.health"}
ROLE_ORDER = {"viewer": 1, "auditor": 2, "analyst": 3, "engineer": 4, "admin": 5}


def auth_required() -> bool:
    return bool(current_app.config.get("AUTH_REQUIRED", True))


def current_user():
    return session.get("wiguard_user")


def current_role():
    return session.get("wiguard_role", "analyst" if current_user() else "anonymous")


def is_authenticated() -> bool:
    return bool(current_user())


def role_at_least(required: str) -> bool:
    return ROLE_ORDER.get(current_role(), 0) >= ROLE_ORDER.get(required, 999)


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
            db.record_login_attempt(username, request_ip(), True, "sqlite")
            db.audit(username, "auth.login", username, "SQLite user login")
            return user
    # Local/demo fallback. Disable in production with WIGUARD_DISABLE_DEMO_FALLBACK=1 after creating a real account.
    if not current_app.config.get("DISABLE_DEMO_FALLBACK", False):
        if hmac.compare_digest(username, configured_username().lower()) and check_password_hash(configured_password_hash(), password):
            if db:
                db.record_login_attempt(username, request_ip(), True, "fallback")
                db.audit(username, "auth.login", username, "Emergency/demo fallback login")
            return {"username": username, "role": "admin"}
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


def enforce_request_security():
    endpoint = request.endpoint or ""
    if endpoint in CSRF_EXEMPT_ENDPOINTS or endpoint.startswith("static"):
        return None

    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not validate_csrf():
        abort(400, description="Invalid or missing CSRF token.")

    if not auth_required():
        return None

    if endpoint in AUTH_EXEMPT_ENDPOINTS or endpoint.startswith("static"):
        return None

    if not is_authenticated():
        return redirect(url_for("pages.login", next=request.full_path if request.query_string else request.path))
    return None


def login_user(user):
    session.clear()
    if isinstance(user, dict):
        session["wiguard_user"] = user.get("username")
        session["wiguard_role"] = user.get("role", "analyst")
    else:
        session["wiguard_user"] = str(user)
        session["wiguard_role"] = "admin"
    session.permanent = True
    csrf_token()


def logout_user():
    username = current_user()
    db = current_app.extensions.get("db")
    if db and username:
        db.audit(username, "auth.logout", username, "User logged out")
    session.clear()
