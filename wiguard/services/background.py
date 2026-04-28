"""Small stdlib background job runner for WiGuard.

The runner is intentionally conservative: jobs remain visible in SQLite, failed
jobs can be retried, and every transition is audit-friendly. Long/unsafe work is
not auto-triggered unless the admin starts the worker or runs the next queued job.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Callable, Dict, Any, Optional
from .util import now_iso

JobHandler = Callable[[Dict[str, Any]], Dict[str, Any]]


class BackgroundJobRunner:
    def __init__(self, app, handlers: Optional[Dict[str, JobHandler]] = None, poll_seconds: float = 2.0, max_attempts: int = 3):
        self.app = app
        self.handlers = handlers or {}
        self.poll_seconds = float(poll_seconds)
        self.max_attempts = int(max_attempts)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def register(self, job_type: str, handler: JobHandler):
        self.handlers[job_type] = handler

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "handlers": sorted(self.handlers.keys()),
            "poll_seconds": self.poll_seconds,
            "max_attempts": self.max_attempts,
        }

    def start(self) -> bool:
        if self.running:
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="wiguard-job-runner", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> bool:
        if not self.running:
            return False
        self._stop.set()
        return True

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.run_next()
            except Exception as exc:
                # Individual job errors are persisted by run_next; keep a runtime breadcrumb too.
                log.exception("Background job loop recovered after failure: %s", exc)
            self._stop.wait(self.poll_seconds)

    def run_next(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self.app.app_context():
                db = self.app.extensions.get("db")
                if not db:
                    return None
                job = db.next_queued_job(max_attempts=self.max_attempts)
                if not job:
                    return None
                job_type = job.get("job_type")
                handler = self.handlers.get(job_type)
                if not handler:
                    db.update_job(job["id"], "failed", 100, error=f"No handler registered for {job_type}")
                    db.audit("system", "job.failed", job["id"], f"Missing handler for {job_type}")
                    return job
                db.update_job(job["id"], "running", max(int(job.get("progress") or 0), 10))
                try:
                    result = handler(job)
                    db.update_job(job["id"], "completed", 100, result or {"completed_at": now_iso()})
                    db.audit("system", "job.completed", job["id"], job_type)
                except Exception as exc:
                    attempts = int(job.get("attempts") or 0) + 1
                    status = "failed" if attempts >= self.max_attempts else "queued"
                    progress = 100 if status == "failed" else int(job.get("progress") or 0)
                    db.update_job(job["id"], status, progress, error=str(exc))
                    db.audit("system", "job.retry" if status == "queued" else "job.failed", job["id"], str(exc))
                return job


def noop_job_handler(job: Dict[str, Any]) -> Dict[str, Any]:
    return {"ok": True, "job_id": job.get("id"), "note": "No-op job completed safely."}
