import json
import re
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
try:
    from werkzeug.security import generate_password_hash, check_password_hash
except Exception:  # pragma: no cover - fallback for minimal stdlib validation
    import hashlib, os, hmac
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
]


PASSWORD_POLICY = {
    "min_length": 10,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": True,
}


class AppDatabase:
    """SQLite application database with migrations, auth, audit, backups, and connector run history."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self):
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            applied = {int(r[0]) for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
            for version, sql in MIGRATIONS:
                if version not in applied:
                    conn.executescript(sql)
                    conn.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", (version, now_iso()))
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

    def create_user(self, username: str, password: str, role: str = "analyst") -> Dict[str, Any]:
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
        self.audit(username, "user.create", username, f"Created local {role} account")
        return self.get_user(username) or {"username": username, "role": role}

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
        return user

    def list_users(self) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT id, username, role, created_at, last_login, is_active FROM users ORDER BY id")]

    def set_user_role(self, username: str, role: str):
        if role not in {"admin", "engineer", "analyst", "auditor", "viewer"}:
            raise ValueError("Invalid role.")
        with self.connect() as conn:
            conn.execute("UPDATE users SET role=? WHERE username=?", (role, username))
            conn.commit()

    def audit(self, actor: str, action: str, target: str = "", detail: str = ""):
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log(actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                (actor or "system", action, target or "", detail or "", now_iso()),
            )
            conn.commit()

    def audit_tail(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    def audit_search(self, query: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        query = (query or "").strip()
        with self.connect() as conn:
            if query:
                like = f"%{query}%"
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE actor LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ? ORDER BY id DESC LIMIT ?",
                    (like, like, like, like, limit),
                )
            else:
                rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(r) for r in rows]

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
        return {"ok": True, "path": str(self.path), "users": users, "migrations": len(self.migrations())}

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
        # Minimal sanity check: uploaded file must be a SQLite DB with users/audit tables or empty migratable database.
        with sqlite3.connect(uploaded_path) as probe:
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
