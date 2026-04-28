import os
from wiguard import create_app

app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("WIGUARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("WIGUARD_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0").lower() in {"1", "true", "yes", "on"},
    )
