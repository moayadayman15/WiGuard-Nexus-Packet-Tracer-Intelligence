import os
import sys

try:
    from wiguard import create_app
except ModuleNotFoundError as exc:
    missing = getattr(exc, "name", "dependency")
    print("\n[WiGuard Backend] Missing Python dependency:", missing)
    print("Run one of these commands from the project folder:")
    print("  python -m pip install -r requirements.txt")
    print("  START_BACKEND_WINDOWS.bat")
    if os.environ.get("WIGUARD_VERBOSE_ERRORS", "0").lower() in {"1", "true", "yes", "on"}:
        print("\nFull error:", exc)
    raise

app = create_app()

if __name__ == "__main__":
    print("\nWiGuard Nexus backend is starting...")
    print("Open: http://127.0.0.1:5000")
    print("Default demo login: admin / admin123")
    app.run(
        host=os.environ.get("WIGUARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("WIGUARD_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0").lower() in {"1", "true", "yes", "on"},
    )
