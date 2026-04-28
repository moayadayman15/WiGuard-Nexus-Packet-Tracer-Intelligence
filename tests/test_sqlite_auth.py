from pathlib import Path
from wiguard.services.database import AppDatabase


def test_sqlite_user_registration_and_login(tmp_path):
    db = AppDatabase(Path(tmp_path) / "wiguard.sqlite3")
    assert db.user_count() == 0
    user = db.create_user("analyst", "StrongPass123", "admin")
    assert user["username"] == "analyst"
    assert db.verify_user("analyst", "StrongPass123") is not None
    assert db.verify_user("analyst", "bad-password") is None
    db.audit("analyst", "unit.test", "auth", "ok")
    assert db.audit_tail(1)[0]["action"] == "unit.test"
