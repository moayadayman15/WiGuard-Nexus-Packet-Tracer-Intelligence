import json
import os
import shutil
import tempfile
import threading
from pathlib import Path
from .seed import seed_state
from .state_schema import ensure_state_shape


class Storage:
    """Small JSON storage with atomic writes and corruption recovery.

    The project is still lightweight, but writes now use a temp file + os.replace()
    so a crash or concurrent request does not leave half-written JSON behind.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    @property
    def backup_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".bak")

    def ensure_seed(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.save(seed_state())

    def load(self):
        self.ensure_seed()
        with self._lock:
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                if self.backup_path.exists():
                    payload = json.loads(self.backup_path.read_text(encoding="utf-8"))
                else:
                    payload = seed_state()
                    self.save(payload)
            if not isinstance(payload, dict):
                payload = seed_state()
                self.save(payload)
            return ensure_state_shape(payload)

    def save(self, payload):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(payload, indent=2, ensure_ascii=False)
        with self._lock:
            if self.path.exists():
                shutil.copy2(self.path, self.backup_path)
            fd, temp_name = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(temp_name, self.path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)

    def reset(self):
        self.save(seed_state())
