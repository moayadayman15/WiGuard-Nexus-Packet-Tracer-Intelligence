"""Live ingestion, raw log persistence, and listener controls for WiGuard."""
from __future__ import annotations

import hashlib
import json
import re
import socket
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Any, Optional
from .connectors import _event_type_from_message, _severity_from_message
from .util import now_iso


@dataclass
class SyslogListenerConfig:
    host: str = "0.0.0.0"
    port: int = 5514
    max_packet_size: int = 8192
    socket_timeout: float = 1.0


SEVERITY_SCORE = {"Info": 10, "Low": 25, "Medium": 50, "High": 75, "Critical": 95}


def event_fingerprint(event: Dict[str, Any], raw: str = "") -> str:
    keys = [
        event.get("timestamp") or "",
        event.get("client") or event.get("mac") or "",
        event.get("event_type") or "",
        event.get("ap") or "",
        raw or event.get("message") or event.get("detail") or "",
    ]
    return hashlib.sha256("|".join(map(str, keys)).encode("utf-8")).hexdigest()


def parse_syslog_line(line: str) -> Dict[str, Any]:
    text = (line or "").strip()
    mac = ""
    m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", text)
    if m:
        mac = m.group(0).lower().replace("-", ":")
    ssid = ""
    sm = re.search(r"ssid[=: ]+([A-Za-z0-9_. -]+)", text, re.I)
    if sm:
        ssid = sm.group(1).strip().split()[0]
    ap = ""
    am = re.search(r"(?:ap|nas|radio)[=: ]+([A-Za-z0-9_.:-]+)", text, re.I)
    if am:
        ap = am.group(1).strip()
    username = ""
    um = re.search(r"(?:user|username|identity)[=: ]+([A-Za-z0-9_.@-]+)", text, re.I)
    if um:
        username = um.group(1).strip()
    event_type = _event_type_from_message(text)
    severity = _severity_from_message(text)
    return {
        "timestamp": now_iso(),
        "schema_version": "live-event-v2",
        "source": "udp_syslog",
        "event_type": event_type,
        "severity": severity,
        "severity_score": SEVERITY_SCORE.get(severity, 10),
        "client": username or mac or "unknown_syslog_client",
        "username": username,
        "mac": mac,
        "ssid": ssid,
        "ap": ap,
        "message": text,
        "raw_length": len(text),
        "confidence": 0.86 if mac or username or ssid or ap else 0.56,
    }


def run_udp_syslog_listener(config: SyslogListenerConfig, handler: Callable[[Dict[str, Any], str, str], None], stop_event: Optional[threading.Event] = None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(float(config.socket_timeout))
    sock.bind((config.host, int(config.port)))
    try:
        while not (stop_event and stop_event.is_set()):
            try:
                data, addr = sock.recvfrom(int(config.max_packet_size))
            except socket.timeout:
                continue
            raw = data.decode("utf-8", errors="replace")
            handler(parse_syslog_line(raw), raw, addr[0] if addr else "")
    finally:
        sock.close()


class LiveIngestionController:
    def __init__(self, app):
        self.app = app
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_error = ""
        self.last_event_at = ""

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> Dict[str, Any]:
        return {"running": self.running, "last_error": self.last_error, "last_event_at": self.last_event_at}

    def start(self, config: SyslogListenerConfig) -> bool:
        if self.running:
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(config,), name="wiguard-live-syslog", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> bool:
        if not self.running:
            return False
        self._stop.set()
        return True

    def _run(self, config: SyslogListenerConfig):
        try:
            run_udp_syslog_listener(config, self._handle_event, self._stop)
        except Exception as exc:
            self.last_error = str(exc)
            with self.app.app_context():
                db = self.app.extensions.get("db")
                if db:
                    db.audit("system", "live.listener.error", f"{config.host}:{config.port}", str(exc), severity="High")

    def _handle_event(self, event: Dict[str, Any], raw: str, source_ip: str):
        self.last_event_at = now_iso()
        with self.app.app_context():
            db = self.app.extensions.get("db")
            storage = self.app.extensions.get("storage")
            if not storage:
                return
            tenant_id = self.app.config.get("DEFAULT_TENANT_ID", "tenant-main")
            fp = event_fingerprint(event, raw)
            duplicate = db.event_fingerprint_seen(fp) if db else False
            if db:
                db.record_raw_event("syslog_events", raw, event, fingerprint=fp, source_ip=source_ip, tenant_id=tenant_id)
            if duplicate:
                return
            state = storage.load()
            from .connectors import import_connector_payload
            import_connector_payload(state, "syslog_events", "live-syslog.json", json.dumps({"events": [event]}).encode(), db=db, live=True)
            storage.save(state)


def event_to_json_bytes(event: Dict[str, Any]) -> bytes:
    return json.dumps({"connector_type": "syslog_events", "events": [event]}, ensure_ascii=False).encode()
