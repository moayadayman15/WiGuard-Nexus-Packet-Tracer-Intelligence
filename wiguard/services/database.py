import hashlib
import hmac
import json
import re
import secrets
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
try:
    from werkzeug.security import generate_password_hash, check_password_hash
except Exception:  # pragma: no cover - fallback for minimal stdlib validation
    import os
    def generate_password_hash(password):
        salt = os.urandom(16).hex()
        digest = hashlib.pbkdf2_hmac("sha256", str(password).encode(), salt.encode(), 200000).hex()
        return f"pbkdf2:sha256:200000${salt}${digest}"
    def check_password_hash(stored, password):
        try:
            _, salt, digest = str(stored).split("$", 2)
            calc = hashlib.pbkdf2_hmac("sha256", str(password).encode(), salt.encode(), 200000).hex()
            return hmac.compare_digest(calc, digest)
        except Exception:
            return False
from .util import now_iso


MIGRATIONS: List[Tuple[int, str]] = [
    (1, """
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL,
            last_login TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wireless_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            snapshot_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """),
    (2, """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            ok INTEGER NOT NULL DEFAULT 0,
            reason TEXT,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_attempts_window ON login_attempts(username, ip_address, created_at);
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL
        );
    """),
    (3, """
        CREATE TABLE IF NOT EXISTS app_backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_path TEXT NOT NULL,
            source_path TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            note TEXT
        );
        CREATE TABLE IF NOT EXISTS connector_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connector_type TEXT NOT NULL,
            filename TEXT,
            imported_records INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            detail TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL
        );
    """),
    (4, """
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_tenants (
            username TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL,
            PRIMARY KEY(username, tenant_id)
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            scopes TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            last_used_ip TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS job_queue (
            id TEXT PRIMARY KEY,
            job_type TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL,
            result_json TEXT,
            error TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            tenant_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS live_event_fingerprints (
            fingerprint TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS connector_status (
            connector_type TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            checked_by TEXT,
            checked_at TEXT NOT NULL
        );
    """),
    (5, """
        CREATE TABLE IF NOT EXISTS raw_live_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT,
            connector_type TEXT NOT NULL,
            raw_message TEXT NOT NULL,
            normalized_json TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'Info',
            event_type TEXT NOT NULL DEFAULT 'association',
            source_ip TEXT,
            tenant_id TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_raw_live_events_time ON raw_live_events(created_at);
        CREATE INDEX IF NOT EXISTS idx_raw_live_events_fingerprint ON raw_live_events(fingerprint);
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value_json TEXT NOT NULL,
            updated_by TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at REAL NOT NULL,
            used_at TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_invites (
            token_hash TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            expires_at REAL NOT NULL,
            accepted_at TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS session_registry (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            tenant_id TEXT,
            ip_address TEXT,
            user_agent TEXT,
            revoked_at TEXT,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );
    """),
]


PASSWORD_POLICY = {
    "min_length": 10,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": True,
}


# Idempotent repair map used on every startup. This protects local workspaces
# that were opened with older WiGuard builds where schema_migrations may say a
# migration ran even though one table/column was missing. CREATE TABLE IF NOT
# EXISTS is not enough for old tables, so these ALTER checks are intentionally
# conservative and safe to run repeatedly.
REPAIR_COLUMNS = {
    "users": {
        "role": "TEXT NOT NULL DEFAULT 'analyst'",
        "created_at": "TEXT DEFAULT ''",
        "last_login": "TEXT",
        "is_active": "INTEGER NOT NULL DEFAULT 1",
        "disabled_reason": "TEXT DEFAULT ''",
        "locked_until": "REAL DEFAULT 0",
        "mfa_secret": "TEXT DEFAULT ''",
        "must_change_password": "INTEGER NOT NULL DEFAULT 0",
    },
    "audit_log": {
        "actor": "TEXT",
        "target": "TEXT",
        "detail": "TEXT",
        "created_at": "TEXT DEFAULT ''",
        "prev_hash": "TEXT DEFAULT ''",
        "entry_hash": "TEXT DEFAULT ''",
        "severity": "TEXT DEFAULT 'Info'",
        "tenant_id": "TEXT DEFAULT 'tenant-main'",
    },
    "wireless_snapshots": {
        "project_id": "TEXT",
        "snapshot_type": "TEXT DEFAULT ''",
        "payload_json": "TEXT DEFAULT '{}'",
        "created_at": "TEXT DEFAULT ''",
    },
    "login_attempts": {
        "username": "TEXT",
        "ip_address": "TEXT",
        "ok": "INTEGER NOT NULL DEFAULT 0",
        "reason": "TEXT",
        "created_at": "REAL DEFAULT 0",
    },
    "user_sessions": {
        "username": "TEXT",
        "event": "TEXT DEFAULT ''",
        "ip_address": "TEXT",
        "user_agent": "TEXT",
        "created_at": "TEXT DEFAULT ''",
    },
    "app_backups": {
        "backup_path": "TEXT DEFAULT ''",
        "source_path": "TEXT DEFAULT ''",
        "created_by": "TEXT",
        "created_at": "TEXT DEFAULT ''",
        "note": "TEXT",
    },
    "connector_runs": {
        "connector_type": "TEXT DEFAULT ''",
        "filename": "TEXT",
        "imported_records": "INTEGER NOT NULL DEFAULT 0",
        "status": "TEXT DEFAULT 'unknown'",
        "detail": "TEXT",
        "created_by": "TEXT",
        "created_at": "TEXT DEFAULT ''",
    },
    "tenants": {
        "name": "TEXT DEFAULT ''",
        "status": "TEXT NOT NULL DEFAULT 'active'",
        "created_at": "TEXT DEFAULT ''",
    },
    "user_tenants": {
        "role": "TEXT NOT NULL DEFAULT 'analyst'",
        "created_at": "TEXT DEFAULT ''",
    },
    "api_tokens": {
        "name": "TEXT DEFAULT ''",
        "token_hash": "TEXT DEFAULT ''",
        "token_prefix": "TEXT DEFAULT ''",
        "scopes": "TEXT DEFAULT '[]'",
        "tenant_id": "TEXT DEFAULT 'tenant-main'",
        "created_by": "TEXT",
        "created_at": "TEXT DEFAULT ''",
        "last_used_at": "TEXT",
        "last_used_ip": "TEXT",
        "is_active": "INTEGER NOT NULL DEFAULT 1",
    },
    "job_queue": {
        "job_type": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'queued'",
        "progress": "INTEGER NOT NULL DEFAULT 0",
        "payload_json": "TEXT DEFAULT '{}'",
        "result_json": "TEXT",
        "error": "TEXT",
        "attempts": "INTEGER NOT NULL DEFAULT 0",
        "created_by": "TEXT",
        "tenant_id": "TEXT",
        "created_at": "TEXT DEFAULT ''",
        "updated_at": "TEXT DEFAULT ''",
    },
    "connector_status": {
        "status": "TEXT DEFAULT 'unknown'",
        "target": "TEXT",
        "detail": "TEXT",
        "checked_by": "TEXT",
        "checked_at": "TEXT DEFAULT ''",
    },
    "raw_live_events": {
        "fingerprint": "TEXT",
        "connector_type": "TEXT DEFAULT ''",
        "raw_message": "TEXT DEFAULT ''",
        "normalized_json": "TEXT DEFAULT '{}'",
        "severity": "TEXT NOT NULL DEFAULT 'Info'",
        "event_type": "TEXT NOT NULL DEFAULT 'association'",
        "source_ip": "TEXT",
        "tenant_id": "TEXT",
        "created_at": "TEXT DEFAULT ''",
    },
    "app_settings": {
        "value_json": "TEXT DEFAULT '{}'",
        "updated_by": "TEXT",
        "updated_at": "TEXT DEFAULT ''",
    },
    "password_reset_tokens": {
        "username": "TEXT DEFAULT ''",
        "expires_at": "REAL DEFAULT 0",
        "used_at": "TEXT",
        "created_by": "TEXT",
        "created_at": "TEXT DEFAULT ''",
    },
    "user_invites": {
        "email": "TEXT DEFAULT ''",
        "role": "TEXT DEFAULT 'analyst'",
        "tenant_id": "TEXT DEFAULT 'tenant-main'",
        "expires_at": "REAL DEFAULT 0",
        "accepted_at": "TEXT",
        "created_by": "TEXT",
        "created_at": "TEXT DEFAULT ''",
    },
    "session_registry": {
        "username": "TEXT DEFAULT ''",
        "tenant_id": "TEXT",
        "ip_address": "TEXT",
        "user_agent": "TEXT",
        "revoked_at": "TEXT",
        "created_at": "TEXT DEFAULT ''",
        "last_seen_at": "TEXT DEFAULT ''",
    },
}


class AppDatabase:
    """SQLite database with migrations, auth, audit, tenants, API tokens, jobs, and connector history.

    The application keeps SQLite as the local default, while `WIGUARD_DB_BACKEND` and
    `DATABASE_URL` are surfaced in health/settings so the codebase is PostgreSQL-ready
    without forcing SQLAlchemy into the demo dependency chain.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_column(self, conn, table: str, column: str, definition: str):
        try:
            existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        except sqlite3.OperationalError:
            return
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _repair_columns(self, conn):
        for table, columns in REPAIR_COLUMNS.items():
            try:
                exists = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()
            except sqlite3.OperationalError:
                exists = None
            if not exists:
                continue
            for column, definition in columns.items():
                self._ensure_column(conn, table, column, definition)

    def init_schema(self):
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            applied = {int(r[0]) for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
            for version, sql in MIGRATIONS:
                # Always replay idempotent CREATE TABLE/INDEX migrations. This is
                # a self-heal path for local SQLite files from older dev builds.
                conn.executescript(sql)
                if version not in applied:
                    conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", (version, now_iso()))
            self._repair_columns(conn)
            conn.execute(
                "INSERT OR IGNORE INTO tenants(id, name, status, created_at) VALUES (?, ?, ?, ?)",
                ("tenant-main", "Main Tenant", "active", now_iso()),
            )
            conn.commit()

    def migrations(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM schema_migrations ORDER BY version DESC")]

    def user_count(self) -> int:
        with self.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def validate_password_policy(self, password: str) -> List[str]:
        errors = []
        password = password or ""
        if len(password) < PASSWORD_POLICY["min_length"]:
            errors.append(f"Password must be at least {PASSWORD_POLICY['min_length']} characters.")
        if PASSWORD_POLICY["require_upper"] and not re.search(r"[A-Z]", password):
            errors.append("Password must include an uppercase letter.")
        if PASSWORD_POLICY["require_lower"] and not re.search(r"[a-z]", password):
            errors.append("Password must include a lowercase letter.")
        if PASSWORD_POLICY["require_digit"] and not re.search(r"\d", password):
            errors.append("Password must include a number.")
        if PASSWORD_POLICY["require_symbol"] and not re.search(r"[^A-Za-z0-9]", password):
            errors.append("Password must include a symbol.")
        return errors

    def create_tenant(self, tenant_id: str, name: str, status: str = "active") -> Dict[str, Any]:
        tenant_id = re.sub(r"[^a-z0-9_-]+", "-", (tenant_id or name or "tenant").lower()).strip("-")[:64] or "tenant-main"
        with self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO tenants(id, name, status, created_at) VALUES (?, ?, ?, ?)",
                (tenant_id, name or tenant_id, status, now_iso()),
            )
            conn.commit()
        return self.get_tenant(tenant_id) or {"id": tenant_id, "name": name or tenant_id, "status": status}

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
            return dict(row) if row else None

    def list_tenants(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM tenants ORDER BY created_at DESC")]

    def assign_user_tenant(self, username: str, tenant_id: str = "tenant-main", role: str = "analyst"):
        self.create_tenant(tenant_id, tenant_id)
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO user_tenants(username, tenant_id, role, created_at) VALUES (?, ?, ?, ?)",
                ((username or "").lower(), tenant_id, role, now_iso()),
            )
            conn.commit()

    def default_tenant_for_user(self, username: str) -> str:
        with self.connect() as conn:
            row = conn.execute("SELECT tenant_id FROM user_tenants WHERE username=? ORDER BY created_at LIMIT 1", ((username or "").lower(),)).fetchone()
            return row[0] if row else "tenant-main"

    def create_user(self, username: str, password: str, role: str = "analyst", tenant_id: str = "tenant-main") -> Dict[str, Any]:
        username = (username or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_.@-]{3,64}", username):
            raise ValueError("Username must be 3-64 chars using letters, numbers, dot, underscore, dash, or @.")
        policy_errors = self.validate_password_policy(password)
        if policy_errors:
            raise ValueError(" ".join(policy_errors))
        if role not in {"admin", "engineer", "analyst", "auditor", "viewer"}:
            role = "analyst"
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), role, now_iso()),
            )
            conn.commit()
        self.assign_user_tenant(username, tenant_id, role)
        self.audit(username, "user.create", username, f"Created local {role} account in {tenant_id}")
        user = self.get_user(username) or {"username": username, "role": role}
        user["tenant_id"] = tenant_id
        return user

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        username = (username or "").strip().lower()
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,)).fetchone()
            return dict(row) if row else None

    def verify_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        user = self.get_user(username)
        if not user or not check_password_hash(user["password_hash"], password or ""):
            return None
        with self.connect() as conn:
            conn.execute("UPDATE users SET last_login=? WHERE id=?", (now_iso(), user["id"]))
            conn.commit()
        user["tenant_id"] = self.default_tenant_for_user(username)
        return user

    def list_users(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT u.id, u.username, u.role, u.created_at, u.last_login, u.is_active,
                       COALESCE(ut.tenant_id, 'tenant-main') AS tenant_id
                FROM users u
                LEFT JOIN user_tenants ut ON ut.username = u.username
                ORDER BY u.id
            """)
            return [dict(r) for r in rows]

    def set_user_role(self, username: str, role: str):
        if role not in {"admin", "engineer", "analyst", "auditor", "viewer"}:
            raise ValueError("Invalid role.")
        with self.connect() as conn:
            conn.execute("UPDATE users SET role=? WHERE username=?", (role, username))
            conn.commit()

    def audit(self, actor: str, action: str, target: str = "", detail: str = "", severity: str = "Info", tenant_id: str = "tenant-main"):
        timestamp = now_iso()
        actor = actor or "system"
        action = action or "unknown"
        target = target or ""
        detail = detail or ""
        severity = severity or "Info"
        with self.connect() as conn:
            prev = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = prev[0] if prev and prev[0] else "GENESIS"
            material = "|".join([prev_hash, timestamp, actor, action, target, detail, severity, tenant_id or "tenant-main"])
            entry_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
            conn.execute(
                "INSERT INTO audit_log(actor, action, target, detail, created_at, prev_hash, entry_hash, severity, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (actor, action, target, detail, timestamp, prev_hash, entry_hash, severity, tenant_id or "tenant-main"),
            )
            conn.commit()

    def verify_audit_chain(self, limit: int = 500) -> Dict[str, Any]:
        with self.connect() as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id ASC LIMIT ?", (int(limit),))]
        previous = "GENESIS"
        broken = []
        for row in rows:
            expected = hashlib.sha256("|".join([
                previous, row.get("created_at") or "", row.get("actor") or "system", row.get("action") or "unknown",
                row.get("target") or "", row.get("detail") or "", row.get("severity") or "Info", row.get("tenant_id") or "tenant-main"
            ]).encode("utf-8")).hexdigest()
            if row.get("entry_hash") and row.get("entry_hash") != expected:
                broken.append({"id": row.get("id"), "expected": expected, "actual": row.get("entry_hash")})
            if row.get("entry_hash"):
                previous = row.get("entry_hash")
        return {"ok": not broken, "checked": len(rows), "broken": broken[:10], "latest_hash": previous if rows else "GENESIS"}

    def audit_tail(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),))]

    def audit_search(self, query: str = "", limit: int = 100, action: str = "", actor: str = "", severity: str = "") -> List[Dict[str, Any]]:
        query = (query or "").strip()
        clauses = []
        params = []
        if query:
            like = f"%{query}%"
            clauses.append("(actor LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ?)")
            params.extend([like, like, like, like])
        if action:
            clauses.append("action LIKE ?")
            params.append(f"%{action}%")
        if actor:
            clauses.append("actor LIKE ?")
            params.append(f"%{actor}%")
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, params)]

    def audit_csv_bytes(self, query: str = "", action: str = "", actor: str = "", severity: str = "") -> bytes:
        import csv, io
        rows = self.audit_search(query=query, limit=10000, action=action, actor=actor, severity=severity)
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=["id", "created_at", "actor", "action", "target", "severity", "detail", "prev_hash", "entry_hash", "tenant_id"])
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in writer.fieldnames})
        return out.getvalue().encode("utf-8")

    def record_login_attempt(self, username: str, ip_address: str, ok: bool, reason: str = ""):
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO login_attempts(username, ip_address, ok, reason, created_at) VALUES (?, ?, ?, ?, ?)",
                ((username or "").lower(), ip_address or "unknown", 1 if ok else 0, reason, time.time()),
            )
            conn.commit()

    def login_allowed(self, username: str, ip_address: str, max_failures: int = 5, window_seconds: int = 900) -> Tuple[bool, int]:
        since = time.time() - window_seconds
        username = (username or "").lower()
        ip_address = ip_address or "unknown"
        with self.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE ok=0 AND created_at>=? AND (username=? OR ip_address=?)",
                (since, username, ip_address),
            ).fetchone()[0]
        return int(count) < int(max_failures), max(0, int(max_failures) - int(count))

    def save_snapshot(self, project_id: str, snapshot_type: str, payload_json: str):
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO wireless_snapshots(project_id, snapshot_type, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (project_id, snapshot_type, payload_json, now_iso()),
            )
            conn.commit()

    def health(self) -> Dict[str, Any]:
        with self.connect() as conn:
            conn.execute("SELECT 1").fetchone()
            users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            tenants = conn.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
            jobs = conn.execute("SELECT COUNT(*) FROM job_queue").fetchone()[0]
        return {"ok": True, "path": str(self.path), "backend": "sqlite", "users": users, "tenants": tenants, "jobs": jobs, "migrations": len(self.migrations())}

    def create_backup(self, backup_dir: Path, created_by: str = "system", note: str = "") -> Path:
        backup_dir = Path(backup_dir)
        backup_dir.mkdir(parents=True, exist_ok=True)
        ts = now_iso().replace(" ", "_").replace(":", "-")
        dest = backup_dir / f"wiguard-db-backup-{ts}.sqlite3"
        shutil.copy2(self.path, dest)
        for suffix in ["-wal", "-shm"]:
            side = Path(str(self.path) + suffix)
            if side.exists():
                shutil.copy2(side, Path(str(dest) + suffix))
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO app_backups(backup_path, source_path, created_by, created_at, note) VALUES (?, ?, ?, ?, ?)",
                (str(dest), str(self.path), created_by, now_iso(), note),
            )
            conn.commit()
        return dest

    def list_backups(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM app_backups ORDER BY id DESC LIMIT 50")]

    def restore_from_upload(self, uploaded_path: Path):
        # Sanity check and integrity check before replacing the live DB.
        with sqlite3.connect(uploaded_path) as probe:
            integrity = probe.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise ValueError(f"SQLite integrity_check failed: {integrity}")
            names = {r[0] for r in probe.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if names and not ({"users", "audit_log"} & names):
                raise ValueError("Uploaded file does not look like a WiGuard SQLite database.")
        safety = self.create_backup(self.path.parent / "backups", "system", "Automatic pre-restore backup")
        shutil.copy2(uploaded_path, self.path)
        self.init_schema()
        self.audit("system", "database.restore", str(uploaded_path), f"Restored after safety backup {safety.name}")

    def connector_run(self, connector_type: str, filename: str, count: int, status: str, detail: str, created_by: str = "system"):
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO connector_runs(connector_type, filename, imported_records, status, detail, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (connector_type, filename, int(count), status, detail, created_by, now_iso()),
            )
            conn.commit()

    def connector_runs(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM connector_runs ORDER BY id DESC LIMIT 50")]

    def set_connector_status(self, connector_type: str, status: str, target: str = "", detail: str = "", checked_by: str = "system"):
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO connector_status(connector_type, status, target, detail, checked_by, checked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(connector_type) DO UPDATE SET status=excluded.status, target=excluded.target,
                detail=excluded.detail, checked_by=excluded.checked_by, checked_at=excluded.checked_at
                """,
                (connector_type, status, target or "", detail or "", checked_by or "system", now_iso()),
            )
            conn.commit()

    def connector_statuses(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM connector_status ORDER BY checked_at DESC")]

    def create_job(self, job_type: str, payload: Dict[str, Any], created_by: str = "system", tenant_id: str = "tenant-main") -> str:
        job_id = "job_" + secrets.token_hex(8)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO job_queue(id, job_type, status, progress, payload_json, created_by, tenant_id, created_at, updated_at)
                VALUES (?, ?, 'queued', 0, ?, ?, ?, ?, ?)
                """,
                (job_id, job_type, json.dumps(payload, ensure_ascii=False), created_by, tenant_id, now_iso(), now_iso()),
            )
            conn.commit()
        return job_id

    def update_job(self, job_id: str, status: str, progress: int = None, result: Dict[str, Any] = None, error: str = None):
        with self.connect() as conn:
            row = conn.execute("SELECT attempts FROM job_queue WHERE id=?", (job_id,)).fetchone()
            attempts = int(row[0]) + (1 if status in {"running", "failed"} else 0) if row else 0
            conn.execute(
                """
                UPDATE job_queue SET status=?, progress=COALESCE(?, progress), result_json=COALESCE(?, result_json),
                error=?, attempts=?, updated_at=? WHERE id=?
                """,
                (status, progress, json.dumps(result, ensure_ascii=False) if result is not None else None, error, attempts, now_iso(), job_id),
            )
            conn.commit()

    def list_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM job_queue ORDER BY created_at DESC LIMIT ?", (int(limit),))
            result = []
            for row in rows:
                item = dict(row)
                for key in ["payload_json", "result_json"]:
                    try:
                        item[key] = json.loads(item[key]) if item.get(key) else None
                    except Exception:
                        pass
                result.append(item)
            return result

    def event_fingerprint_seen(self, fingerprint: str) -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT fingerprint, count FROM live_event_fingerprints WHERE fingerprint=?", (fingerprint,)).fetchone()
            if row:
                conn.execute("UPDATE live_event_fingerprints SET last_seen=?, count=count+1 WHERE fingerprint=?", (now_iso(), fingerprint))
                conn.commit()
                return True
            conn.execute(
                "INSERT INTO live_event_fingerprints(fingerprint, first_seen, last_seen, count) VALUES (?, ?, ?, 1)",
                (fingerprint, now_iso(), now_iso()),
            )
            conn.commit()
            return False

    def next_queued_job(self, max_attempts: int = 3) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM job_queue WHERE status='queued' AND attempts < ? ORDER BY created_at ASC LIMIT 1",
                (int(max_attempts),),
            ).fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["payload_json"] = json.loads(item.get("payload_json") or "{}")
            except Exception:
                item["payload_json"] = {}
            return item

    def retry_job(self, job_id: str):
        with self.connect() as conn:
            conn.execute("UPDATE job_queue SET status='queued', error=NULL, updated_at=? WHERE id=?", (now_iso(), job_id))
            conn.commit()

    def record_raw_event(self, connector_type: str, raw_message: str, normalized: Dict[str, Any], fingerprint: str = "", source_ip: str = "", tenant_id: str = "tenant-main"):
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO raw_live_events(fingerprint, connector_type, raw_message, normalized_json, severity, event_type, source_ip, tenant_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (fingerprint or "", connector_type, raw_message or "", json.dumps(normalized or {}, ensure_ascii=False), (normalized or {}).get("severity", "Info"), (normalized or {}).get("event_type", "association"), source_ip or "", tenant_id or "tenant-main", now_iso()),
            )
            conn.commit()

    def raw_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM raw_live_events ORDER BY id DESC LIMIT ?", (int(limit),))
            out = []
            for row in rows:
                item = dict(row)
                try:
                    item["normalized"] = json.loads(item.get("normalized_json") or "{}")
                except Exception:
                    item["normalized"] = {}
                out.append(item)
            return out

    def set_app_setting(self, key: str, value: Dict[str, Any], updated_by: str = "system"):
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO app_settings(key, value_json, updated_by, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                (key, json.dumps(value, ensure_ascii=False), updated_by, now_iso()),
            )
            conn.commit()

    def get_app_setting(self, key: str, default=None):
        with self.connect() as conn:
            row = conn.execute("SELECT value_json FROM app_settings WHERE key=?", (key,)).fetchone()
            if not row:
                return default
            try:
                return json.loads(row[0])
            except Exception:
                return default

    def disable_user(self, username: str, disabled: bool = True, reason: str = ""):
        with self.connect() as conn:
            conn.execute("UPDATE users SET is_active=?, disabled_reason=? WHERE username=?", (0 if disabled else 1, reason or "", (username or "").lower()))
            conn.commit()

    def change_password(self, username: str, new_password: str):
        errors = self.validate_password_policy(new_password)
        if errors:
            raise ValueError(" ".join(errors))
        with self.connect() as conn:
            conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username=?", (generate_password_hash(new_password), (username or "").lower()))
            conn.commit()

    def create_password_reset_token(self, username: str, created_by: str = "system", ttl_seconds: int = 3600) -> str:
        token = "rst_" + secrets.token_urlsafe(28)
        with self.connect() as conn:
            conn.execute("INSERT INTO password_reset_tokens(token_hash, username, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?)", (self._hash_token(token), (username or "").lower(), time.time() + int(ttl_seconds), created_by, now_iso()))
            conn.commit()
        return token

    def create_invite_token(self, email: str, role: str, tenant_id: str, created_by: str = "system", ttl_seconds: int = 86400) -> str:
        if role not in {"admin", "engineer", "analyst", "auditor", "viewer"}:
            role = "analyst"
        token = "inv_" + secrets.token_urlsafe(28)
        with self.connect() as conn:
            conn.execute("INSERT INTO user_invites(token_hash, email, role, tenant_id, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (self._hash_token(token), email.lower(), role, tenant_id, time.time() + int(ttl_seconds), created_by, now_iso()))
            conn.commit()
        return token

    def list_invites(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT email, role, tenant_id, expires_at, accepted_at, created_by, created_at FROM user_invites ORDER BY created_at DESC LIMIT 50")]

    def consume_password_reset_token(self, token: str, new_password: str) -> str:
        errors = self.validate_password_policy(new_password)
        if errors:
            raise ValueError(" ".join(errors))
        token_hash = self._hash_token(token or "")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM password_reset_tokens WHERE token_hash=?", (token_hash,)).fetchone()
            if not row or row["used_at"]:
                raise ValueError("Invalid or already used reset token.")
            if float(row["expires_at"]) < time.time():
                raise ValueError("Reset token expired.")
            username = row["username"]
            conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username=?", (generate_password_hash(new_password), username))
            conn.execute("UPDATE password_reset_tokens SET used_at=? WHERE token_hash=?", (now_iso(), token_hash))
            conn.commit()
        self.revoke_sessions_for_user(username)
        self.audit(username, "auth.password_reset.consume", username, "Password reset token consumed", severity="High")
        return username

    def accept_invite(self, token: str, username: str, password: str) -> Dict[str, Any]:
        token_hash = self._hash_token(token or "")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM user_invites WHERE token_hash=?", (token_hash,)).fetchone()
            if not row or row["accepted_at"]:
                raise ValueError("Invalid or already accepted invite.")
            if float(row["expires_at"]) < time.time():
                raise ValueError("Invite expired.")
            email, role, tenant_id = row["email"], row["role"], row["tenant_id"]
        user = self.create_user(username or email, password, role=role, tenant_id=tenant_id)
        with self.connect() as conn:
            conn.execute("UPDATE user_invites SET accepted_at=? WHERE token_hash=?", (now_iso(), token_hash))
            conn.commit()
        self.audit(user.get("username"), "user.invite.accept", email, f"Role={role}")
        return user

    def register_session(self, session_id: str, username: str, tenant_id: str, ip_address: str, user_agent: str):
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO session_registry(session_id, username, tenant_id, ip_address, user_agent, revoked_at, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, COALESCE((SELECT revoked_at FROM session_registry WHERE session_id=?), NULL), COALESCE((SELECT created_at FROM session_registry WHERE session_id=?), ?), ?)", (session_id, username, tenant_id, ip_address, user_agent, session_id, session_id, now_iso(), now_iso()))
            conn.commit()

    def touch_session(self, session_id: str):
        with self.connect() as conn:
            conn.execute("UPDATE session_registry SET last_seen_at=? WHERE session_id=?", (now_iso(), session_id))
            conn.commit()

    def revoke_sessions_for_user(self, username: str):
        with self.connect() as conn:
            conn.execute("UPDATE session_registry SET revoked_at=COALESCE(revoked_at, ?) WHERE username=?", (now_iso(), (username or "").lower()))
            conn.commit()

    def is_session_revoked(self, session_id: str) -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT revoked_at FROM session_registry WHERE session_id=?", (session_id,)).fetchone()
            return bool(row and row[0])

    def list_sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM session_registry ORDER BY last_seen_at DESC LIMIT ?", (int(limit),))]

    def revoke_api_token(self, token_id: int):
        with self.connect() as conn:
            conn.execute("UPDATE api_tokens SET is_active=0 WHERE id=?", (int(token_id),))
            conn.commit()

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def create_api_token(self, name: str, scopes: List[str], tenant_id: str = "tenant-main", created_by: str = "system") -> Dict[str, Any]:
        clean_scopes = [s for s in (scopes or []) if s in {"read", "ingest", "write", "admin"}] or ["read"]
        token = "wgn_" + secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)
        prefix = token[:12]
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO api_tokens(name, token_hash, token_prefix, scopes, tenant_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name or "API Token", token_hash, prefix, ",".join(clean_scopes), tenant_id, created_by, now_iso()),
            )
            conn.commit()
        return {"token": token, "prefix": prefix, "name": name, "scopes": clean_scopes, "tenant_id": tenant_id}

    def list_api_tokens(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT id, name, token_prefix, scopes, tenant_id, created_by, created_at, last_used_at, last_used_ip, is_active FROM api_tokens ORDER BY id DESC")]

    def verify_api_token(self, token: str, ip_address: str = "") -> Optional[Dict[str, Any]]:
        token_hash = self._hash_token(token or "")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM api_tokens WHERE token_hash=? AND is_active=1", (token_hash,)).fetchone()
            if not row:
                return None
            conn.execute("UPDATE api_tokens SET last_used_at=?, last_used_ip=? WHERE id=?", (now_iso(), ip_address or "unknown", row["id"]))
            conn.commit()
        item = dict(row)
        return {"name": item["name"], "scopes": [s for s in item.get("scopes", "").split(",") if s], "tenant_id": item.get("tenant_id")}
