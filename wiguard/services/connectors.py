import csv
import io
import json
from typing import Dict, Any, Tuple, List
from .wireless import simulate_wireless_event, add_or_update_ap, add_or_update_ssid, normalize_wireless_state, add_event

SUPPORTED_CONNECTORS = {
    "generic_ap_inventory": "Generic AP inventory CSV/JSON",
    "generic_wlc_clients": "Generic WLC/client session CSV/JSON",
    "radius_accounting": "RADIUS accounting CSV/JSON",
    "dhcp_leases": "DHCP lease CSV/JSON",
    "syslog_events": "Wireless syslog event CSV/JSON",
}


def _records(filename: str, raw: bytes) -> List[Dict[str, Any]]:
    text = raw.decode("utf-8", errors="replace")
    if filename.lower().endswith(".json"):
        data = json.loads(text)
        if isinstance(data, list):
            return data
        for key in ("records", "events", "aps", "clients", "leases"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return list(csv.DictReader(io.StringIO(text)))


def import_connector_payload(state: Dict[str, Any], connector_type: str, filename: str, raw: bytes) -> Tuple[int, List[str]]:
    normalize_wireless_state(state)
    if connector_type not in SUPPORTED_CONNECTORS:
        raise ValueError("Unsupported connector type.")
    errors = []
    count = 0
    for item in _records(filename, raw):
        try:
            if connector_type == "generic_ap_inventory":
                add_or_update_ap(state, {
                    "name": item.get("ap") or item.get("name") or item.get("id"),
                    "location": item.get("location", ""),
                    "switch": item.get("switch", ""),
                    "uplink_interface": item.get("uplink") or item.get("uplink_interface", ""),
                    "supported_vlans": item.get("supported_vlans") or item.get("vlans", ""),
                    "max_clients": item.get("max_clients", 25),
                    "status": item.get("status", "online"),
                })
            elif connector_type == "generic_wlc_clients":
                simulate_wireless_event(state, {
                    "event_type": item.get("event_type", "association"),
                    "client": item.get("client") or item.get("username") or item.get("mac"),
                    "mac": item.get("mac", ""),
                    "ssid": item.get("ssid", ""),
                    "to_ap": item.get("ap") or item.get("to_ap"),
                    "vlan": item.get("vlan", ""),
                    "ip": item.get("ip") or item.get("address", ""),
                })
            elif connector_type == "radius_accounting":
                ev = item.get("event_type") or ("disassociation" if item.get("acct_status_type", "").lower() == "stop" else "association")
                simulate_wireless_event(state, {
                    "event_type": ev,
                    "client": item.get("username") or item.get("client") or item.get("calling_station_id"),
                    "ssid": item.get("ssid", ""),
                    "to_ap": item.get("nas_identifier") or item.get("ap", ""),
                    "vlan": item.get("vlan", ""),
                    "ip": item.get("framed_ip_address") or item.get("ip", ""),
                })
            elif connector_type == "dhcp_leases":
                simulate_wireless_event(state, {
                    "event_type": "dhcp_assignment",
                    "client": item.get("client") or item.get("hostname") or item.get("mac"),
                    "mac": item.get("mac", ""),
                    "vlan": item.get("vlan", ""),
                    "ip": item.get("ip") or item.get("address", ""),
                    "ssid": item.get("ssid", ""),
                })
            elif connector_type == "syslog_events":
                message = item.get("message") or item.get("detail") or "syslog wireless event"
                event_type = item.get("event_type") or ("authentication_failure" if "fail" in message.lower() else "roaming" if "roam" in message.lower() else "association")
                simulate_wireless_event(state, {
                    "event_type": event_type,
                    "client": item.get("client") or item.get("username") or item.get("mac") or "unknown_syslog_client",
                    "ssid": item.get("ssid", ""),
                    "to_ap": item.get("ap", ""),
                    "detail": message,
                })
            count += 1
        except Exception as exc:
            errors.append(str(exc))
    add_event(state, "connector_import", "", "Info" if not errors else "Medium", f"Connector {connector_type} imported {count} records from {filename}.", connector=connector_type)
    return count, errors[:10]
