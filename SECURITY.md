import importlib.util
import os
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def fail(msg):
    print(f"[FAIL] {msg}")
    raise SystemExit(1)

def ok(msg):
    print(f"[OK] {msg}")

print("WiGuard backend diagnosis")
print("Python:", sys.version.replace("\n", " "))
if sys.version_info < (3, 10):
    fail("Python 3.10+ is required because the project uses modern typing syntax.")
ok("Python version is supported")

for mod in ["flask", "werkzeug", "reportlab"]:
    if importlib.util.find_spec(mod) is None:
        fail(f"Missing dependency: {mod}. Run: python -m pip install -r requirements.txt")
    ok(f"Dependency available: {mod}")

for path in [ROOT / "data", ROOT / "wiguard", ROOT / "wiguard" / "templates", ROOT / "wiguard" / "static"]:
    if not path.exists():
        fail(f"Missing required path: {path}")
    ok(f"Path exists: {path.relative_to(ROOT)}")

host = os.environ.get("WIGUARD_HOST", "127.0.0.1")
port = int(os.environ.get("WIGUARD_PORT", "5000"))
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(0.6)
    if s.connect_ex((host, port)) == 0:
        fail(f"Port {host}:{port} is already in use. Close the old Flask process or change WIGUARD_PORT.")
ok(f"Port is free: {host}:{port}")

try:
    from wiguard import create_app
    from wiguard.services.code_quality import scan_project
    app = create_app()
    route_count = len(list(app.url_map.iter_rules()))
    ok(f"Flask app factory loaded; {route_count} routes registered")
    if not any(str(rule) in {"/actions/import", "/api/import", "/upload"} for rule in app.url_map.iter_rules()):
        fail("Upload routes were not registered")
    ok("Upload routes registered")
    quality = scan_project(ROOT)
    if quality.get("fatal"):
        fail(f"Code syntax check failed: {quality['summary']}")
    if quality["status"] == "warn":
        print(f"[WARN] Code hygiene warnings only: {quality['summary']}")
        print("[WARN] Startup will continue. Clean these before final release if needed.")
    else:
        ok(f"Code hygiene passed: {quality['python_files']} Python files checked")
except Exception as exc:
    fail(f"App import/create failed: {exc}")

print("Diagnosis completed successfully.")
