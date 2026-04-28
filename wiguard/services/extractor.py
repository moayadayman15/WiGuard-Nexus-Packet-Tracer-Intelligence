import json
import os
import re
import subprocess
import zipfile
import hashlib
import uuid
from pathlib import Path
from xml.etree import ElementTree as ET
try:
    from werkzeug.utils import secure_filename
except Exception:  # pragma: no cover - fallback for minimal test environments
    def secure_filename(value):
        value = str(value or "uploaded").replace('\\', '/').split('/')[-1]
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "uploaded"
from .util import now_iso, network_cidr, safe_int
from .packet_tracer import build_conversion_profile, normalize_interface_name


ALLOWED_UPLOAD_EXTENSIONS = {".pkt", ".pka", ".xml", ".json", ".txt", ".cfg", ".conf", ".log", ".zip"}
ALLOWED_ZIP_MEMBER_EXTENSIONS = {".txt", ".cfg", ".conf", ".log", ".xml", ".json"}
MAX_ZIP_MEMBERS = 100
MAX_ZIP_TOTAL_BYTES = 8 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 2 * 1024 * 1024


def printable_recovery(raw: bytes) -> str:
    chunks = []
    cur = []
    for b in raw:
        if 32 <= b <= 126 or b in (9, 10, 13):
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                chunks.append("".join(cur))
            cur = []
    if len(cur) >= 4:
        chunks.append("".join(cur))
    return "\n".join(chunks)


def clean_line(line):
    return line.rstrip("\n\r")


def evidence_obj(line_no, line, confidence=0.9):
    return {
        "source_line": line_no,
        "source_text": clean_line(line),
        "confidence": confidence
    }


class ConfigExtractor:
    def __init__(self):
        self.reset()

    def reset(self):
        self.lines = []
        self.text = ""

    def load_text(self, text):
        self.text = text or ""
        self.lines = [(idx + 1, clean_line(line)) for idx, line in enumerate(self.text.splitlines())]

    def parse(self, text):
        self.load_text(text)
        objects = {
            "devices": self.parse_devices(),
            "vlans": self.parse_vlans(),
            "interfaces": self.parse_interfaces(),
            "dhcp_scopes": self.parse_dhcp(),
            "dhcp_excluded": self.parse_dhcp_excluded(),
            "acl_rules": self.parse_acls(),
            "routing": self.parse_routing(),
            "nat_rules": self.parse_nat(),
            "cdp_links": self.parse_cdp(),
            "lldp_links": self.parse_lldp(),
            "services": self.parse_service_hints(),
            "ip_inventory": self.parse_ip_inventory(),
            "interface_status": self.parse_interface_status(),
            "trunk_operational": self.parse_trunk_operational(),
            "route_table": self.parse_route_table(),
            "ospf_neighbors": self.parse_ospf_neighbors(),
            "port_security": self.parse_port_security(),
            "spanning_tree": self.parse_spanning_tree(),
            "etherchannels": self.parse_etherchannels(),
            "mac_table": self.parse_mac_table(),
            "arp_table": self.parse_arp_table(),
            "device_facts": self.parse_device_facts(),
            "device_inventory": self.parse_device_inventory(),
            "security_hardening": self.parse_security_hardening(),
            "wireless_hints": self.parse_wireless_hints(),
            "vlan_brief": self.parse_vlan_brief(),
            "acl_hit_counts": self.parse_acl_hit_counts(),
            "interface_counters": self.parse_interface_counters(),
            "stp_root": self.parse_stp_root(),
            "protocol_summary": self.parse_protocol_summary(),
            "command_blocks": self.parse_command_blocks(),
            "deep_evidence_index": self.deep_evidence_index(),
            "raw_evidence": self.raw_evidence()
        }
        self.bind_acls_to_interfaces(objects)
        objects["dhcp_gateway_matches"] = self.match_dhcp_gateways(objects)
        objects["subnet_inventory"] = self.derive_subnet_inventory(objects)
        objects["vlan_crosscheck"] = self.derive_vlan_crosscheck(objects)
        objects["policy_controls"] = self.derive_policy_controls(objects)
        objects["risk_atoms"] = self.derive_risk_atoms(objects)
        objects["coverage_domains"] = self.coverage_domains(objects)
        objects["evidence_profile"] = self.evidence_profile(objects)
        return objects

    def raw_evidence(self):
        interesting = []
        patterns = [
            "hostname", "interface", "vlan", "switchport", "ip dhcp", "access-list",
            "ip access-group", "ip route", "router ospf", "router eigrp", "router rip",
            "router bgp", "ip nat", "Device ID", "Port ID", "Platform", "Local Intf",
            "Port Security", "spanning-tree", "etherchannel", "mac address-table", "Internet",
            "service password-encryption", "aaa new-model", "username", "enable secret", "snmp-server",
            "transport input", "radius-server", "ssid", "wlan", "show interfaces status"
        ]
        for no, line in self.lines:
            if any(p.lower() in line.lower() for p in patterns):
                interesting.append({"line": no, "text": line})
        return interesting[:2000]

    def get_blocks(self, header_regex):
        blocks = []
        current = None
        for no, line in self.lines:
            if re.match(header_regex, line, flags=re.I):
                if current:
                    blocks.append(current)
                current = {"header_line": no, "header": line, "body": []}
            elif current:
                if re.match(r"^(interface|vlan|ip dhcp pool|router |ip access-list)\b", line, flags=re.I) and not re.match(header_regex, line, flags=re.I):
                    blocks.append(current)
                    current = None
                    if re.match(header_regex, line, flags=re.I):
                        current = {"header_line": no, "header": line, "body": []}
                else:
                    current["body"].append((no, line))
        if current:
            blocks.append(current)
        return blocks

    def parse_devices(self):
        devices = []
        seen = set()
        for no, line in self.lines:
            m = re.match(r"^\s*hostname\s+(\S+)", line, flags=re.I)
            if m:
                name = m.group(1)
                dtype = "router" if re.search(r"(^R\d+|router)", name, re.I) else "switch" if re.search(r"(^SW\d+|switch)", name, re.I) else "device"
                devices.append({
                    "id": name, "hostname": name, "type": dtype, "role": "network_device",
                    "evidence": evidence_obj(no, line, 0.98)
                })
                seen.add(name)
        # CDP device IDs as neighbor objects
        for no, line in self.lines:
            m = re.search(r"Device ID:\s*(.+)", line, flags=re.I)
            if m:
                name = m.group(1).strip()
                if name and name not in seen:
                    devices.append({
                        "id": name, "hostname": name, "type": "neighbor", "role": "cdp_neighbor",
                        "evidence": evidence_obj(no, line, 0.82)
                    })
                    seen.add(name)
        return devices

    def parse_vlans(self):
        vlans = []
        seen = {}
        blocks = self.get_blocks(r"^\s*vlan\s+\d+")
        for block in blocks:
            m = re.match(r"^\s*vlan\s+(\d+)", block["header"], flags=re.I)
            if not m:
                continue
            vlan_id = m.group(1)
            name = f"VLAN_{vlan_id}"
            name_line = block["header_line"]
            for no, line in block["body"]:
                nm = re.match(r"^\s*name\s+(.+)", line, flags=re.I)
                if nm:
                    name = nm.group(1).strip()
                    name_line = no
            seen[vlan_id] = {
                "id": vlan_id, "name": name, "source": "running-config vlan block",
                "evidence": evidence_obj(name_line, f"vlan {vlan_id} name {name}", 0.96)
            }
        # show vlan brief style: "10 STAFF active Fa0/1"
        for no, line in self.lines:
            m = re.match(r"^\s*(\d{1,4})\s+([A-Za-z0-9_.:-]+)\s+(active|act/lshut|suspend)\b(.*)", line, flags=re.I)
            if m and int(m.group(1)) <= 4094:
                vlan_id, name, status, ports = m.groups()
                if vlan_id not in seen:
                    seen[vlan_id] = {
                        "id": vlan_id, "name": name, "status": status,
                        "ports_hint": ports.strip(),
                        "source": "show vlan brief",
                        "evidence": evidence_obj(no, line, 0.88)
                    }
        # dot1q subinterface hints
        for no, line in self.lines:
            m = re.search(r"encapsulation\s+dot1q\s+(\d+)", line, flags=re.I)
            if m and m.group(1) not in seen:
                vid = m.group(1)
                seen[vid] = {
                    "id": vid, "name": f"VLAN_{vid}", "source": "dot1q subinterface hint",
                    "evidence": evidence_obj(no, line, 0.78)
                }
        vlans = list(seen.values())
        return sorted(vlans, key=lambda x: safe_int(x.get("id")))

    def parse_interfaces(self):
        interfaces = []
        blocks = self.get_blocks(r"^\s*interface\s+\S+")
        for block in blocks:
            m = re.match(r"^\s*interface\s+(\S+)", block["header"], flags=re.I)
            if not m:
                continue
            name = m.group(1)
            item = {
                "name": name,
                "normalized_name": normalize_interface_name(name),
                "description": "",
                "ip_address": None,
                "subnet_mask": None,
                "cidr": None,
                "mode": None,
                "access_vlan": None,
                "trunk_allowed_vlans": [],
                "native_vlan": None,
                "dot1q_vlan": None,
                "acl_in": None,
                "acl_out": None,
                "nat_role": None,
                "port_security_enabled": False,
                "port_security_max": None,
                "port_security_violation": None,
                "port_security_sticky": False,
                "shutdown": False,
                "evidence": evidence_obj(block["header_line"], block["header"], 0.95),
                "line_map": []
            }
            for no, line in block["body"]:
                item["line_map"].append({"line": no, "text": line})
                patterns = {
                    "description": re.match(r"^\s*description\s+(.+)", line, flags=re.I),
                    "ip": re.match(r"^\s*ip address\s+(\S+)\s+(\S+)", line, flags=re.I),
                    "mode": re.match(r"^\s*switchport mode\s+(\S+)", line, flags=re.I),
                    "access": re.match(r"^\s*switchport access vlan\s+(\d+)", line, flags=re.I),
                    "trunk_allowed": re.match(r"^\s*switchport trunk allowed vlan\s+(.+)", line, flags=re.I),
                    "native": re.match(r"^\s*switchport trunk native vlan\s+(\d+)", line, flags=re.I),
                    "dot1q": re.match(r"^\s*encapsulation\s+dot1q\s+(\d+)", line, flags=re.I),
                    "acl": re.match(r"^\s*ip access-group\s+(\S+)\s+(in|out)", line, flags=re.I),
                    "nat": re.match(r"^\s*ip nat\s+(inside|outside)", line, flags=re.I),
                    "port_security": re.match(r"^\s*switchport\s+port-security\s*$", line, flags=re.I),
                    "port_security_max": re.match(r"^\s*switchport\s+port-security\s+maximum\s+(\d+)", line, flags=re.I),
                    "port_security_violation": re.match(r"^\s*switchport\s+port-security\s+violation\s+(\S+)", line, flags=re.I),
                    "port_security_sticky": re.match(r"^\s*switchport\s+port-security\s+mac-address\s+sticky", line, flags=re.I),
                    "shutdown": re.match(r"^\s*shutdown\s*$", line, flags=re.I),
                }
                if patterns["description"]:
                    item["description"] = patterns["description"].group(1).strip()
                if patterns["ip"]:
                    item["ip_address"], item["subnet_mask"] = patterns["ip"].groups()
                    item["cidr"] = network_cidr(item["ip_address"], item["subnet_mask"])
                if patterns["mode"]:
                    item["mode"] = patterns["mode"].group(1).lower()
                if patterns["access"]:
                    item["access_vlan"] = patterns["access"].group(1)
                if patterns["trunk_allowed"]:
                    item["trunk_allowed_vlans"] = self.expand_vlan_list(patterns["trunk_allowed"].group(1))
                if patterns["native"]:
                    item["native_vlan"] = patterns["native"].group(1)
                if patterns["dot1q"]:
                    item["dot1q_vlan"] = patterns["dot1q"].group(1)
                    item["mode"] = item["mode"] or "routed-subinterface"
                if patterns["acl"]:
                    acl_name, direction = patterns["acl"].groups()
                    if direction.lower() == "in":
                        item["acl_in"] = acl_name
                    else:
                        item["acl_out"] = acl_name
                if patterns["nat"]:
                    item["nat_role"] = patterns["nat"].group(1).lower()
                if patterns["port_security"]:
                    item["port_security_enabled"] = True
                if patterns["port_security_max"]:
                    item["port_security_max"] = patterns["port_security_max"].group(1)
                if patterns["port_security_violation"]:
                    item["port_security_violation"] = patterns["port_security_violation"].group(1).lower()
                if patterns["port_security_sticky"]:
                    item["port_security_enabled"] = True
                    item["port_security_sticky"] = True
                if patterns["shutdown"]:
                    item["shutdown"] = True
            if item["mode"] is None:
                if item["access_vlan"]:
                    item["mode"] = "access"
                elif item["trunk_allowed_vlans"]:
                    item["mode"] = "trunk"
                elif item["dot1q_vlan"]:
                    item["mode"] = "routed-subinterface"
                elif item["ip_address"]:
                    item["mode"] = "routed"
                else:
                    item["mode"] = "unknown"
            interfaces.append(item)

        # show interfaces trunk style hints
        for no, line in self.lines:
            m = re.match(r"^\s*(\S+)\s+(on|desirable|auto|trunking)\s+(\S+)\s+(\S+)\s+(.+)$", line, flags=re.I)
            if m and "Port" not in line and "Vlans" not in line:
                port = m.group(1)
                # Avoid false positives by requiring common interface naming
                if re.match(r"^(Fa|Gi|Te|Eth|Po)", port, flags=re.I):
                    if not any(x["name"] == port for x in interfaces):
                        interfaces.append({
                            "name": port, "normalized_name": normalize_interface_name(port), "description": "show interfaces trunk hint",
                            "ip_address": None, "subnet_mask": None, "cidr": None, "mode": "trunk",
                            "access_vlan": None, "trunk_allowed_vlans": [], "native_vlan": None,
                            "dot1q_vlan": None, "acl_in": None, "acl_out": None, "nat_role": None,
                            "shutdown": False, "evidence": evidence_obj(no, line, 0.72), "line_map": [{"line": no, "text": line}]
                        })
        return interfaces

    def expand_vlan_list(self, value):
        value = value.strip().replace("add ", "")
        if value.lower() in {"all", "none"}:
            return [value.lower()]
        result = []
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                if a.isdigit() and b.isdigit():
                    result.extend(str(x) for x in range(int(a), int(b) + 1))
            elif part.isdigit():
                result.append(part)
        return sorted(set(result), key=lambda x: safe_int(x))

    def parse_dhcp_excluded(self):
        excluded = []
        for no, line in self.lines:
            m = re.match(r"^\s*ip dhcp excluded-address\s+(\S+)(?:\s+(\S+))?", line, flags=re.I)
            if m:
                start, end = m.groups()
                excluded.append({
                    "start": start, "end": end or start, "evidence": evidence_obj(no, line, 0.94)
                })
        return excluded

    def parse_dhcp(self):
        pools = []
        blocks = self.get_blocks(r"^\s*ip dhcp pool\s+\S+")
        for block in blocks:
            m = re.match(r"^\s*ip dhcp pool\s+(\S+)", block["header"], flags=re.I)
            if not m:
                continue
            item = {
                "name": m.group(1), "network": None, "mask": None, "cidr": None,
                "default_gateway": None, "dns_servers": [], "domain_name": None,
                "evidence": evidence_obj(block["header_line"], block["header"], 0.95),
                "line_map": []
            }
            for no, line in block["body"]:
                item["line_map"].append({"line": no, "text": line})
                nm = re.match(r"^\s*network\s+(\S+)\s+(\S+)", line, flags=re.I)
                gw = re.match(r"^\s*default-router\s+(.+)", line, flags=re.I)
                dns = re.match(r"^\s*dns-server\s+(.+)", line, flags=re.I)
                dom = re.match(r"^\s*domain-name\s+(.+)", line, flags=re.I)
                if nm:
                    item["network"], item["mask"] = nm.groups()
                    item["cidr"] = network_cidr(item["network"], item["mask"])
                if gw:
                    item["default_gateway"] = gw.group(1).split()[0]
                if dns:
                    item["dns_servers"] = dns.group(1).split()
                if dom:
                    item["domain_name"] = dom.group(1).strip()
            pools.append(item)
        return pools

    def parse_acls(self):
        rules = []
        # numbered ACL
        for no, line in self.lines:
            m = re.match(r"^\s*access-list\s+(\S+)\s+(permit|deny)\s+(.+)", line, flags=re.I)
            if m:
                acl, action, expr = m.groups()
                acl_kind = "standard"
                if str(acl).isdigit():
                    acl_number = int(acl)
                    if 100 <= acl_number <= 199 or 2000 <= acl_number <= 2699:
                        acl_kind = "extended"
                else:
                    acl_kind = "extended"
                parsed_expr = self.parse_acl_expression(expr.strip(), acl_kind)
                rules.append({
                    "acl_name": acl, "type": acl_kind, "sequence": None, "action": action.lower(),
                    "expression": expr.strip(), "parsed": parsed_expr, "applied_to": [], "is_applied": False,
                    "evidence": evidence_obj(no, line, 0.94)
                })
        # named ACL blocks
        blocks = self.get_blocks(r"^\s*ip access-list\s+(standard|extended)\s+\S+")
        for block in blocks:
            m = re.match(r"^\s*ip access-list\s+(standard|extended)\s+(\S+)", block["header"], flags=re.I)
            if not m:
                continue
            acl_type, acl_name = m.groups()
            for no, line in block["body"]:
                rm = re.match(r"^\s*(?:(\d+)\s+)?(permit|deny)\s+(.+)", line, flags=re.I)
                if rm:
                    seq, action, expr = rm.groups()
                    parsed_expr = self.parse_acl_expression(expr.strip(), acl_type.lower())
                    rules.append({
                        "acl_name": acl_name, "type": acl_type.lower(), "sequence": seq,
                        "action": action.lower(), "expression": expr.strip(), "parsed": parsed_expr, "applied_to": [], "is_applied": False,
                        "evidence": evidence_obj(no, line, 0.92)
                    })
        return rules

    def parse_acl_expression(self, expr, acl_type):
        tokens = expr.split()
        parsed = {"protocol": None, "source": None, "source_wildcard": None, "destination": None, "destination_wildcard": None, "operator": None, "port": None, "raw_tokens": tokens}
        if not tokens:
            return parsed
        # Standard ACLs usually contain source only. Extended ACLs contain protocol/source/destination.
        if acl_type == "standard":
            parsed["source"] = tokens[0]
            if len(tokens) > 1:
                parsed["source_wildcard"] = tokens[1]
            return parsed
        parsed["protocol"] = tokens[0]
        idx = 1

        def read_addr(i):
            if i >= len(tokens):
                return None, None, i
            value = tokens[i]
            if value.lower() == "any":
                return "any", None, i + 1
            if value.lower() == "host" and i + 1 < len(tokens):
                return tokens[i + 1], "host", i + 2
            wildcard = tokens[i + 1] if i + 1 < len(tokens) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[i + 1]) else None
            return value, wildcard, i + (2 if wildcard else 1)

        parsed["source"], parsed["source_wildcard"], idx = read_addr(idx)
        parsed["destination"], parsed["destination_wildcard"], idx = read_addr(idx)
        if idx < len(tokens):
            parsed["operator"] = tokens[idx]
            if idx + 1 < len(tokens):
                parsed["port"] = tokens[idx + 1]
        return parsed

    def bind_acls_to_interfaces(self, objects):
        bindings = {}
        for interface in objects.get("interfaces", []):
            for direction_key, direction in [("acl_in", "in"), ("acl_out", "out")]:
                acl_name = interface.get(direction_key)
                if acl_name:
                    bindings.setdefault(str(acl_name), []).append({
                        "interface": interface.get("name"),
                        "direction": direction,
                        "evidence_line": interface.get("evidence", {}).get("source_line"),
                    })
        for rule in objects.get("acl_rules", []):
            rule["applied_to"] = bindings.get(str(rule.get("acl_name")), [])
            rule["is_applied"] = bool(rule["applied_to"])
        return objects

    def match_dhcp_gateways(self, objects):
        matches = []
        gateway_map = {i.get("ip_address"): i for i in objects.get("interfaces", []) if i.get("ip_address")}
        for pool in objects.get("dhcp_scopes", []):
            gw = pool.get("default_gateway")
            iface = gateway_map.get(gw)
            matches.append({
                "pool": pool.get("name"),
                "cidr": pool.get("cidr"),
                "default_gateway": gw,
                "matched_interface": iface.get("name") if iface else None,
                "matched_vlan": iface.get("dot1q_vlan") or iface.get("access_vlan") or iface.get("native_vlan") if iface else None,
                "status": "match" if iface else "unmatched",
                "confidence": 0.93 if iface else 0.42,
                "evidence_line": pool.get("evidence", {}).get("source_line"),
            })
        return matches

    def evidence_profile(self, objects):
        raw_count = len(objects.get("raw_evidence", []))
        line_mapped = 0
        total = 0
        for key, value in objects.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        total += 1
                        if (item.get("evidence") or {}).get("source_line") is not None:
                            line_mapped += 1
        ratio = round(line_mapped / total, 3) if total else 0
        deep_count = len(objects.get("deep_evidence_index", []))
        command_count = len(objects.get("command_blocks", []))
        # Derived objects such as policy controls and evidence-index entries can inflate
        # total_list_objects, so confidence also rewards the absolute number of native
        # line-mapped facts. This keeps small but clean Packet Tracer exports from being
        # unfairly scored as low-confidence.
        native_line_confidence = line_mapped / (line_mapped + 2) if line_mapped else 0
        confidence = min(0.99, round(max(native_line_confidence, (ratio * 0.62) + (min(raw_count, 80) / 80 * 0.18) + (min(deep_count, 120) / 120 * 0.12) + (min(command_count, 8) / 8 * 0.08)), 3))
        return {
            "raw_evidence_lines": raw_count,
            "objects_with_line_evidence": line_mapped,
            "total_list_objects": total,
            "line_mapping_ratio": ratio,
            "deep_evidence_lines": deep_count,
            "command_blocks": command_count,
            "confidence": confidence,
        }

    def parse_routing(self):
        routes = []
        protocols = []
        for no, line in self.lines:
            m = re.match(r"^\s*ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?", line, flags=re.I)
            if m:
                dest, mask, next_hop, extra = m.groups()
                routes.append({
                    "type": "static", "destination": dest, "mask": mask, "cidr": network_cidr(dest, mask),
                    "next_hop": next_hop, "extra": extra or "", "evidence": evidence_obj(no, line, 0.94)
                })
            pm = re.match(r"^\s*router\s+(ospf|eigrp|rip|bgp)\s+(.+)?", line, flags=re.I)
            if pm:
                protocols.append({
                    "protocol": pm.group(1).lower(), "process": (pm.group(2) or "").strip(),
                    "evidence": evidence_obj(no, line, 0.90)
                })
        return {"static_routes": routes, "protocols": protocols}

    def parse_nat(self):
        rules = []
        for no, line in self.lines:
            if re.match(r"^\s*ip nat\b", line, flags=re.I):
                rules.append({"expression": line.strip(), "evidence": evidence_obj(no, line, 0.88)})
        return rules

    def parse_cdp(self):
        links = []
        current = {}
        for no, line in self.lines:
            m = re.search(r"Device ID:\s*(.+)", line, flags=re.I)
            if m:
                if current:
                    links.append(current)
                current = {"neighbor": m.group(1).strip(), "local_interface": None, "remote_interface": None, "platform": None, "evidence": evidence_obj(no, line, 0.82)}
            lm = re.search(r"Interface:\s*([^,]+),\s*Port ID.*?:\s*(.+)", line, flags=re.I)
            if lm and current:
                current["local_interface"] = lm.group(1).strip()
                current["remote_interface"] = lm.group(2).strip()
            pm = re.search(r"Platform:\s*([^,]+)", line, flags=re.I)
            if pm and current:
                current["platform"] = pm.group(1).strip()
        if current:
            links.append(current)
        return links


    def parse_lldp(self):
        """Parse common LLDP neighbor detail/table output.

        Packet Tracer labs often include either CDP or LLDP depending on device
        type. Keeping LLDP separate prevents false CDP confidence while still
        adding topology edges when the evidence is present.
        """
        links = []
        current = {}
        for no, line in self.lines:
            dm = re.search(r"(?:System Name|Chassis id|Device ID)\s*:\s*(.+)", line, flags=re.I)
            if dm and "Device ID:" not in line:
                if current:
                    links.append(current)
                current = {"neighbor": dm.group(1).strip(), "local_interface": None, "remote_interface": None, "platform": None, "evidence": evidence_obj(no, line, 0.78)}
            lm = re.search(r"(?:Local Intf|Local Interface)\s*:\s*(\S+)", line, flags=re.I)
            if lm and current:
                current["local_interface"] = lm.group(1).strip()
            rm = re.search(r"(?:Port id|Port ID|Remote Port)\s*:\s*(\S+)", line, flags=re.I)
            if rm and current:
                current["remote_interface"] = rm.group(1).strip()
            pm = re.search(r"(?:System Description|Port Description)\s*:\s*(.+)", line, flags=re.I)
            if pm and current:
                current["platform"] = pm.group(1).strip()[:120]
            tm = re.match(r"^\s*(\S+)\s+(\S+)\s+\d+\s+[A-Z,]+\s+(\S+)\s*$", line, flags=re.I)
            if tm and re.match(r"^(Fa|Gi|Te|Eth|Po|Se)", tm.group(2), flags=re.I):
                neighbor, local, remote = tm.groups()
                links.append({"neighbor": neighbor, "local_interface": local, "remote_interface": remote, "platform": "lldp table", "evidence": evidence_obj(no, line, 0.70)})
        if current:
            links.append(current)
        # Deduplicate by neighbor/local/remote.
        dedup = {}
        for link in links:
            key = (link.get("neighbor"), normalize_interface_name(link.get("local_interface")), normalize_interface_name(link.get("remote_interface")))
            dedup[key] = link
        return list(dedup.values())

    def parse_interface_status(self):
        """Parse show interfaces status and up/down hints from interface summaries."""
        rows = []
        for no, line in self.lines:
            if re.search(r"Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed\s+Type", line, flags=re.I):
                continue
            m = re.match(r"^\s*(\S+)\s+(.{0,20}?)\s+(connected|notconnect|disabled|err-disabled|inactive)\s+(\S+)\s+(a-full|full|half|auto)\s+(a-\S+|\S+)\s*(.*)$", line, flags=re.I)
            if m and re.match(r"^(Fa|Gi|Te|Eth|Po)", m.group(1), flags=re.I):
                port, name, status, vlan, duplex, speed, typ = m.groups()
                rows.append({
                    "interface": port,
                    "normalized_interface": normalize_interface_name(port),
                    "name": name.strip(),
                    "status": status.lower(),
                    "vlan": vlan,
                    "duplex": duplex,
                    "speed": speed,
                    "type": typ.strip(),
                    "evidence": evidence_obj(no, line, 0.82),
                })
                continue
            # show ip interface brief compatible operational row.
            ib = re.match(r"^\s*(\S+)\s+(unassigned|\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(.+?)\s+(up|down|administratively down)\s*$", line, flags=re.I)
            if ib and re.match(r"^(Fa|FastEthernet|Gi|GigabitEthernet|Te|TenGigabitEthernet|Eth|Ethernet|Se|Serial|Lo|Loopback|Vl|Vlan)", ib.group(1), flags=re.I):
                iface, ip, status, protocol = ib.groups()
                rows.append({
                    "interface": iface,
                    "normalized_interface": normalize_interface_name(iface),
                    "name": "ip interface brief",
                    "status": status.strip().lower(),
                    "protocol": protocol.lower(),
                    "ip_address": None if ip.lower() == "unassigned" else ip,
                    "evidence": evidence_obj(no, line, 0.76),
                })
        dedup = {}
        for row in rows:
            key = (row.get("normalized_interface"), row.get("status"), row.get("vlan") or row.get("ip_address"))
            dedup[key] = {**dedup.get(key, {}), **row}
        return list(dedup.values())

    def parse_trunk_operational(self):
        """Parse the operational sections of show interfaces trunk."""
        rows = []
        section = "summary"
        for no, line in self.lines:
            low = line.lower()
            if "vlans allowed on trunk" in low:
                section = "allowed"
                continue
            if "vlans allowed and active" in low:
                section = "active"
                continue
            if "vlans in spanning tree forwarding" in low:
                section = "forwarding"
                continue
            m = re.match(r"^\s*(\S+)\s+(on|desirable|auto|trunking)\s+(\S+)\s+(\S+)\s+(.+)$", line, flags=re.I)
            if m and re.match(r"^(Fa|Gi|Te|Eth|Po)", m.group(1), flags=re.I):
                port, mode, encapsulation, status, native_vlan = m.groups()
                rows.append({
                    "interface": port,
                    "normalized_interface": normalize_interface_name(port),
                    "mode": mode.lower(),
                    "encapsulation": encapsulation,
                    "status": status.lower(),
                    "native_vlan": native_vlan.strip(),
                    "allowed_vlans": [],
                    "active_vlans": [],
                    "forwarding_vlans": [],
                    "evidence": evidence_obj(no, line, 0.86),
                })
                continue
            vm = re.match(r"^\s*(\S+)\s+([0-9,\-]+|all|none)\s*$", line, flags=re.I)
            if vm and rows and re.match(r"^(Fa|Gi|Te|Eth|Po)", vm.group(1), flags=re.I):
                port, vlan_text = vm.groups()
                row = next((r for r in rows if r.get("interface") == port), None)
                if not row:
                    row = {"interface": port, "normalized_interface": normalize_interface_name(port), "allowed_vlans": [], "active_vlans": [], "forwarding_vlans": [], "evidence": evidence_obj(no, line, 0.72)}
                    rows.append(row)
                parsed = self.expand_vlan_list(vlan_text)
                key = "allowed_vlans" if section == "allowed" else "active_vlans" if section == "active" else "forwarding_vlans"
                row[key] = parsed
        return rows

    def parse_route_table(self):
        routes = []
        for no, line in self.lines:
            m = re.match(r"^\s*([A-Z*]{1,3})\s+(\d+\.\d+\.\d+\.\d+)(?:/(\d+)|\s+(\d+\.\d+\.\d+\.\d+))\s*(?:\[(\d+)/(\d+)\])?\s*(?:via\s+(\d+\.\d+\.\d+\.\d+))?,?\s*(?:\S+\s*)?(?:,\s*(\S+))?", line, flags=re.I)
            if m:
                code, network, prefix, mask, ad, metric, next_hop, out_iface = m.groups()
                routes.append({
                    "code": code,
                    "network": network,
                    "prefix": prefix,
                    "mask": mask,
                    "next_hop": next_hop,
                    "out_interface": out_iface,
                    "administrative_distance": safe_int(ad) if ad else None,
                    "metric": safe_int(metric) if metric else None,
                    "evidence": evidence_obj(no, line, 0.75),
                })
        return routes[:1000]

    def parse_ospf_neighbors(self):
        rows = []
        for no, line in self.lines:
            m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(FULL|2WAY|EXSTART|EXCHANGE|LOADING|DOWN)/\S+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)", line, flags=re.I)
            if m:
                neighbor_id, priority, state, address, iface = m.groups()
                rows.append({
                    "neighbor_id": neighbor_id,
                    "priority": safe_int(priority),
                    "state": state.upper(),
                    "address": address,
                    "interface": iface,
                    "normalized_interface": normalize_interface_name(iface),
                    "evidence": evidence_obj(no, line, 0.80),
                })
        return rows

    def parse_device_inventory(self):
        inventory = []
        current = None
        for no, line in self.lines:
            nm = re.match(r"^\s*NAME:\s*\"([^\"]+)\"\s*,\s*DESCR:\s*\"([^\"]*)\"", line, flags=re.I)
            if nm:
                current = {"name": nm.group(1), "description": nm.group(2), "pid": None, "vid": None, "serial": None, "evidence": evidence_obj(no, line, 0.76)}
                inventory.append(current)
                continue
            pm = re.match(r"^\s*PID:\s*([^,]+),\s*VID:\s*([^,]*),\s*SN:\s*(\S+)", line, flags=re.I)
            if pm and current:
                current["pid"], current["vid"], current["serial"] = [x.strip() for x in pm.groups()]
            mm = re.search(r"^\s*cisco\s+(\S+)\s+.*processor", line, flags=re.I)
            if mm:
                inventory.append({"name": "chassis", "description": "show version model", "pid": mm.group(1), "vid": None, "serial": None, "evidence": evidence_obj(no, line, 0.70)})
        return inventory


    def parse_vlan_brief(self):
        """Parse `show vlan brief` rows and map VLANs to visible access ports."""
        rows = []
        header_seen = False
        for no, line in self.lines:
            if re.search(r"\bVLAN\s+Name\s+Status\s+Ports\b", line, flags=re.I):
                header_seen = True
                continue
            m = re.match(r"^\s*(\d{1,4})\s+(.+?)\s+(active|act/unsup|suspended|shutdown)\s*(.*)$", line, flags=re.I)
            if not m:
                continue
            vlan, name, status, ports = m.groups()
            if vlan in {"1002", "1003", "1004", "1005"}:
                confidence = 0.55
            else:
                confidence = 0.84 if header_seen else 0.66
            parsed_ports = [p.strip().rstrip(",") for p in re.split(r"\s*,\s*|\s{2,}", ports.strip()) if p.strip()]
            # Some Cisco outputs separate comma lists with single spaces after wrapping.
            expanded_ports = []
            for item in parsed_ports:
                expanded_ports.extend([x for x in item.split(",") if x])
            rows.append({
                "vlan": vlan,
                "name": name.strip(),
                "status": status.lower(),
                "ports": [normalize_interface_name(p.strip()) or p.strip() for p in expanded_ports],
                "raw_ports": ports.strip(),
                "evidence": evidence_obj(no, line, confidence),
            })
        return rows[:1000]

    def parse_acl_hit_counts(self):
        """Parse `show access-lists` match counters to prove live traffic paths."""
        hits = []
        active_acl = None
        for no, line in self.lines:
            header = re.match(r"^\s*(Standard|Extended)?\s*IP\s+access\s+list\s+(\S+)", line, flags=re.I)
            if header:
                active_acl = header.group(2)
                continue
            named = re.match(r"^\s*ip\s+access-list\s+(standard|extended)\s+(\S+)", line, flags=re.I)
            if named:
                active_acl = named.group(2)
                continue
            m = re.search(r"\((\d+)\s+matches?\)", line, flags=re.I)
            if m:
                seq = None
                seqm = re.match(r"^\s*(\d+)\s+", line)
                if seqm:
                    seq = seqm.group(1)
                hits.append({
                    "acl_name": active_acl,
                    "sequence": seq,
                    "matches": safe_int(m.group(1)),
                    "line_text": line.strip(),
                    "evidence": evidence_obj(no, line, 0.82),
                })
        return hits[:1000]

    def parse_interface_counters(self):
        """Parse compact interface error/counter evidence from show interfaces outputs."""
        counters = []
        current = None
        for no, line in self.lines:
            im = re.match(r"^\s*(\S+)\s+is\s+(up|down|administratively down),\s+line protocol is\s+(up|down)", line, flags=re.I)
            if im and re.match(r"^(Fa|FastEthernet|Gi|GigabitEthernet|Te|TenGigabitEthernet|Eth|Ethernet|Se|Serial|Vl|Vlan|Po|Port-channel)", im.group(1), flags=re.I):
                current = {
                    "interface": im.group(1),
                    "normalized_interface": normalize_interface_name(im.group(1)),
                    "status": im.group(2).lower(),
                    "protocol": im.group(3).lower(),
                    "input_errors": 0,
                    "output_errors": 0,
                    "crc": 0,
                    "drops": 0,
                    "evidence": evidence_obj(no, line, 0.78),
                }
                counters.append(current)
                continue
            if not current:
                continue
            em = re.search(r"(\d+)\s+input errors,\s*(\d+)\s+CRC", line, flags=re.I)
            if em:
                current["input_errors"] = safe_int(em.group(1))
                current["crc"] = safe_int(em.group(2))
                current["error_evidence"] = evidence_obj(no, line, 0.80)
            om = re.search(r"(\d+)\s+output errors", line, flags=re.I)
            if om:
                current["output_errors"] = safe_int(om.group(1))
                current["error_evidence"] = evidence_obj(no, line, 0.80)
            dm = re.search(r"(\d+)\s+(?:input queue drops|total output drops)", line, flags=re.I)
            if dm:
                current["drops"] = current.get("drops", 0) + safe_int(dm.group(1))
                current["drop_evidence"] = evidence_obj(no, line, 0.75)
        return counters[:1000]

    def parse_stp_root(self):
        roots = []
        current_vlan = None
        for no, line in self.lines:
            vm = re.match(r"^\s*VLAN(\d+)\b", line, flags=re.I)
            if vm:
                current_vlan = vm.group(1)
                roots.append({"vlan": current_vlan, "root_bridge": None, "root_port": None, "cost": None, "evidence": evidence_obj(no, line, 0.72)})
                continue
            if not current_vlan or not roots:
                continue
            rm = re.search(r"Root ID\s+Priority\s+(\d+)", line, flags=re.I)
            if rm:
                roots[-1]["root_priority"] = safe_int(rm.group(1))
            am = re.search(r"Address\s+([0-9a-f.:-]+)", line, flags=re.I)
            if am and not roots[-1].get("root_bridge"):
                roots[-1]["root_bridge"] = am.group(1).lower()
            pm = re.search(r"Cost\s+(\d+).*Port\s+(\S+)", line, flags=re.I)
            if pm:
                roots[-1]["cost"] = safe_int(pm.group(1))
                roots[-1]["root_port"] = pm.group(2)
        return roots[:500]

    def parse_protocol_summary(self):
        protocols = []
        patterns = [
            ("ospf", r"^\s*router\s+ospf\s+(\d+)"),
            ("eigrp", r"^\s*router\s+eigrp\s+(\S+)"),
            ("rip", r"^\s*router\s+rip\b"),
            ("bgp", r"^\s*router\s+bgp\s+(\d+)"),
            ("static_route", r"^\s*ip\s+route\s+"),
            ("nat", r"^\s*ip\s+nat\s+"),
            ("dhcp", r"^\s*ip\s+dhcp\s+pool\s+"),
            ("hsrp", r"^\s*standby\s+\d+\s+ip\s+"),
        ]
        for no, line in self.lines:
            for proto, pattern in patterns:
                m = re.match(pattern, line, flags=re.I)
                if m:
                    protocols.append({
                        "protocol": proto,
                        "value": " ".join(m.groups()).strip() if m.groups() else line.strip(),
                        "evidence": evidence_obj(no, line, 0.76),
                    })
        return protocols[:1000]

    def parse_security_hardening(self):
        features = []
        blocks = self.get_blocks(r"^\s*line\s+(vty|console|aux)\b")
        for no, line in self.lines:
            checks = [
                ("service_password_encryption", r"^\s*service\s+password-encryption\b", "positive", 0.86),
                ("aaa_new_model", r"^\s*aaa\s+new-model\b", "positive", 0.86),
                ("local_user", r"^\s*username\s+(\S+)\s+(?:privilege\s+\d+\s+)?(secret|password)\b", "sensitive", 0.82),
                ("enable_secret", r"^\s*enable\s+secret\b", "positive", 0.86),
                ("enable_password", r"^\s*enable\s+password\b", "weak", 0.86),
                ("ssh_domain", r"^\s*ip\s+domain-name\s+(.+)", "positive", 0.78),
                ("ssh_key", r"^\s*crypto\s+key\s+generate\s+rsa\b", "positive", 0.78),
                ("logging_host", r"^\s*logging\s+host\s+(\S+)", "positive", 0.76),
                ("ntp_server", r"^\s*ntp\s+server\s+(\S+)", "positive", 0.76),
                ("snmp_community", r"^\s*snmp-server\s+community\s+(\S+)(.*)", "sensitive", 0.80),
                ("http_server", r"^\s*ip\s+http\s+server\b", "weak", 0.78),
                ("secure_http_server", r"^\s*ip\s+http\s+secure-server\b", "positive", 0.78),
                ("cdp_enabled", r"^\s*cdp\s+run\b", "informational", 0.62),
            ]
            for name, pattern, posture, conf in checks:
                m = re.match(pattern, line, flags=re.I)
                if m:
                    features.append({"name": name, "posture": posture, "value": " ".join(m.groups()).strip() if m.groups() else line.strip(), "evidence": evidence_obj(no, line, conf)})
        for block in blocks:
            header = block["header"].strip()
            text = "\n".join(line for _, line in block["body"]).lower()
            if "transport input telnet" in text or re.search(r"transport\s+input\s+all", text):
                features.append({"name": "vty_telnet_allowed", "posture": "weak", "value": header, "evidence": evidence_obj(block["header_line"], block["header"], 0.88)})
            if "transport input ssh" in text and "telnet" not in text:
                features.append({"name": "vty_ssh_only", "posture": "positive", "value": header, "evidence": evidence_obj(block["header_line"], block["header"], 0.84)})
            if "login local" in text:
                features.append({"name": "vty_login_local", "posture": "positive", "value": header, "evidence": evidence_obj(block["header_line"], block["header"], 0.78)})
        return features

    def parse_wireless_hints(self):
        hints = []
        patterns = [
            ("ssid", r"\bssid\s+([A-Za-z0-9_.:-]+)"),
            ("wlan", r"\bwlan\s+([A-Za-z0-9_.:-]+)"),
            ("ap", r"\b(AP[-_ ]?\d+|Access Point|AIR-[A-Za-z0-9-]+)\b"),
            ("radius", r"\bradius-server\s+host\s+(\S+)"),
            ("wpa", r"\bwpa\b|\bwpa2\b|\bwpa3\b"),
        ]
        for no, line in self.lines:
            for typ, pattern in patterns:
                m = re.search(pattern, line, flags=re.I)
                if m:
                    hints.append({"type": typ, "value": (m.group(1) if m.groups() else line.strip()), "evidence": evidence_obj(no, line, 0.64)})
        return hints[:500]

    def parse_command_blocks(self):
        blocks = []
        active = None
        for no, line in self.lines:
            zipm = re.match(r"^---\s+ZIP MEMBER:\s+(.+?)\s+---$", line.strip(), flags=re.I)
            promptm = re.match(r"^\s*([A-Za-z0-9_.-]+)[>#]\s*(show\s+.+|write\s+term|terminal\s+length\s+\d+)", line, flags=re.I)
            if zipm or promptm:
                if active:
                    active["end_line"] = no - 1
                    active["line_count"] = max(0, active["end_line"] - active["start_line"])
                    blocks.append(active)
                active = {
                    "name": zipm.group(1).strip() if zipm else promptm.group(2).strip(),
                    "device": None if zipm else promptm.group(1),
                    "start_line": no,
                    "evidence": evidence_obj(no, line, 0.70),
                }
        if active:
            active["end_line"] = self.lines[-1][0] if self.lines else active["start_line"]
            active["line_count"] = max(0, active["end_line"] - active["start_line"])
            blocks.append(active)
        if not blocks and self.lines:
            blocks.append({"name": "single evidence stream", "device": None, "start_line": 1, "end_line": self.lines[-1][0], "line_count": len(self.lines), "evidence": evidence_obj(1, self.lines[0][1], 0.50)})
        return blocks[:250]

    def deep_evidence_index(self):
        index = []
        taxonomy = [
            ("identity", ["hostname", "uptime is", "cisco ios", "system image", "configuration register", "processor", "serial"]),
            ("interface", ["interface ", "ip address", "switchport", "duplex", "speed", "line protocol", "input errors", "output errors", "crc"]),
            ("vlan", ["vlan", "encapsulation dot1q", "trunk", "native vlan", "vlans allowed", "show vlan"]),
            ("security", ["access-list", "ip access-list", "ip access-group", "enable secret", "enable password", "username", "aaa", "snmp-server", "transport input", "http server", "matches)"]),
            ("routing", ["ip route", "router ospf", "router eigrp", "router rip", "router bgp", " ospf ", " via ", "gateway of last resort"]),
            ("l2-health", ["spanning-tree", "root", "altn", "etherchannel", "port-channel", "port-security", "mac address-table", "err-disabled"]),
            ("wireless", ["ssid", "wlan", "radius", "access point", "ap-", "wpa", "authentication"]),
            ("operations", ["show interfaces status", "connected", "notconnect", "administratively down", "logging host", "ntp server"]),
        ]
        for no, line in self.lines:
            low = line.lower()
            tags = [name for name, words in taxonomy if any(w in low for w in words)]
            if tags:
                index.append({"line": no, "tags": tags, "text": line[:240], "weight": min(1.0, 0.35 + 0.12 * len(tags))})
        return index[:2500]

    def derive_subnet_inventory(self, objects):
        subnets = {}
        for iface in objects.get("interfaces", []):
            if iface.get("cidr"):
                subnets.setdefault(iface["cidr"], {"cidr": iface["cidr"], "interfaces": [], "dhcp_pools": [], "routes": [], "evidence": iface.get("evidence")})
                subnets[iface["cidr"]]["interfaces"].append(iface.get("name"))
        for pool in objects.get("dhcp_scopes", []):
            if pool.get("cidr"):
                subnets.setdefault(pool["cidr"], {"cidr": pool["cidr"], "interfaces": [], "dhcp_pools": [], "routes": [], "evidence": pool.get("evidence")})
                subnets[pool["cidr"]]["dhcp_pools"].append(pool.get("name"))
        for route in objects.get("routing", {}).get("static_routes", []):
            if route.get("cidr"):
                subnets.setdefault(route["cidr"], {"cidr": route["cidr"], "interfaces": [], "dhcp_pools": [], "routes": [], "evidence": route.get("evidence")})
                subnets[route["cidr"]]["routes"].append(route.get("next_hop"))
        return list(subnets.values())

    def derive_policy_controls(self, objects):
        controls = []
        def add(control, status, severity, evidence, detail, confidence=0.75):
            controls.append({"control": control, "status": status, "severity": severity, "detail": detail, "evidence": evidence, "confidence": confidence})
        applied_acl_count = sum(1 for r in objects.get("acl_rules", []) if r.get("is_applied"))
        add("SEG-ACL-APPLIED", "pass" if applied_acl_count else "review", "High" if not applied_acl_count else "Info", (objects.get("acl_rules") or [{}])[0].get("evidence") if objects.get("acl_rules") else None, f"{applied_acl_count} ACL rule(s) have confirmed interface bindings.", 0.90 if applied_acl_count else 0.45)
        trunks = objects.get("trunk_operational") or [i for i in objects.get("interfaces", []) if i.get("mode") == "trunk" or i.get("trunk_allowed_vlans")]
        add("L2-TRUNK-COVERAGE", "pass" if trunks else "review", "Medium", (trunks[0].get("evidence") if trunks else None), f"{len(trunks)} trunk evidence row(s) extracted.", 0.86 if trunks else 0.40)
        weak = [x for x in objects.get("security_hardening", []) if x.get("posture") == "weak"]
        add("DEVICE-HARDENING", "fail" if weak else "pass", "High" if weak else "Info", (weak[0].get("evidence") if weak else None), f"{len(weak)} weak hardening indicator(s) detected.", 0.88 if weak else 0.70)
        ps = objects.get("port_security")
        add("ACCESS-PORT-SECURITY", "pass" if ps else "review", "Medium", (ps[0].get("evidence") if ps else None), f"{len(ps)} port-security evidence row(s) extracted.", 0.82 if ps else 0.44)
        cdp_lldp = len(objects.get("cdp_links", [])) + len(objects.get("lldp_links", []))
        add("TOPOLOGY-ADJACENCY", "pass" if cdp_lldp else "review", "Medium", None, f"{cdp_lldp} CDP/LLDP adjacency edge(s) extracted.", 0.84 if cdp_lldp else 0.42)
        counters = [c for c in objects.get("interface_counters", []) if int(c.get("input_errors") or 0) or int(c.get("output_errors") or 0) or int(c.get("crc") or 0)]
        add("INTERFACE-ERROR-HEALTH", "fail" if counters else "pass", "Medium" if counters else "Info", (counters[0].get("error_evidence") or counters[0].get("evidence") if counters else None), f"{len(counters)} interface(s) have error/counter evidence.", 0.82 if counters else 0.68)
        acl_hits = [h for h in objects.get("acl_hit_counts", []) if int(h.get("matches") or 0) > 0]
        add("ACL-RUNTIME-HITS", "pass" if acl_hits else "review", "Medium", (acl_hits[0].get("evidence") if acl_hits else None), f"{len(acl_hits)} ACL line(s) include runtime match counters.", 0.83 if acl_hits else 0.42)
        vlan_cross = objects.get("vlan_crosscheck", {}) or {}
        missing = vlan_cross.get("missing_from_trunks") or []
        add("VLAN-TRUNK-CROSSCHECK", "fail" if missing else "pass" if vlan_cross else "review", "High" if missing else "Info", None, f"{len(missing)} VLAN(s) appear configured but not present in trunk forwarding evidence.", 0.84 if vlan_cross else 0.40)
        return controls

    def derive_vlan_crosscheck(self, objects):
        configured = {str(v.get("id") or v.get("vlan")) for v in objects.get("vlans", []) if isinstance(v, dict) and (v.get("id") or v.get("vlan"))}
        brief = {str(v.get("vlan")) for v in objects.get("vlan_brief", []) if isinstance(v, dict) and v.get("vlan")}
        dhcp = set()
        for pool in objects.get("dhcp_gateway_matches", []) or []:
            if isinstance(pool, dict) and pool.get("matched_vlan"):
                dhcp.add(str(pool.get("matched_vlan")))
        trunks = set()
        forwarding = set()
        for t in objects.get("trunk_operational", []) or []:
            for v in t.get("allowed_vlans") or []:
                trunks.add(str(v))
            for v in t.get("forwarding_vlans") or []:
                forwarding.add(str(v))
        access = set()
        for i in objects.get("interfaces", []) or []:
            if isinstance(i, dict):
                for key in ("access_vlan", "dot1q_vlan", "native_vlan"):
                    if i.get(key):
                        access.add(str(i.get(key)))
        observed = configured | brief | dhcp | access
        return {
            "configured_vlans": sorted(configured),
            "show_vlan_vlans": sorted(brief),
            "dhcp_gateway_vlans": sorted(dhcp),
            "access_or_svi_vlans": sorted(access),
            "trunk_allowed_vlans": sorted(trunks),
            "trunk_forwarding_vlans": sorted(forwarding),
            "missing_from_trunks": sorted(v for v in observed if trunks and v not in trunks and v not in {"1", "1002", "1003", "1004", "1005"}),
            "observed_total": len(observed),
        }

    def derive_risk_atoms(self, objects):
        atoms = []
        def atom(key, title, severity, evidence, why, confidence=0.72):
            atoms.append({"key": key, "title": title, "severity": severity, "why": why, "evidence": evidence, "confidence": confidence})
        for item in objects.get("security_hardening", []) or []:
            if item.get("posture") == "weak":
                atom("weak-management-plane", f"Weak management-plane signal: {item.get('name')}", "High", item.get("evidence"), "Weak services or password constructs increase administrative attack surface.", 0.86)
        for row in objects.get("interface_counters", []) or []:
            errors = int(row.get("input_errors") or 0) + int(row.get("output_errors") or 0) + int(row.get("crc") or 0)
            if errors:
                atom("interface-errors", f"Interface errors on {row.get('interface')}", "Medium", row.get("error_evidence") or row.get("evidence"), f"{errors} combined error/CRC counters detected.", 0.78)
        for vlan in (objects.get("vlan_crosscheck", {}) or {}).get("missing_from_trunks", []) or []:
            atom("vlan-not-on-trunk", f"VLAN {vlan} missing from trunk evidence", "High", None, "Policy VLAN is present in configuration/evidence but not confirmed on operational trunks.", 0.76)
        for hit in objects.get("acl_hit_counts", []) or []:
            if int(hit.get("matches") or 0) == 0 and hit.get("acl_name"):
                atom("acl-zero-hit", f"ACL line has zero runtime hits in {hit.get('acl_name')}", "Low", hit.get("evidence"), "Zero-hit rules may be dead policy or need traffic validation.", 0.60)
        return atoms[:1000]

    def coverage_domains(self, objects):
        domains = [
            ("Identity", ["devices", "device_facts", "device_inventory"]),
            ("L2/VLAN", ["vlans", "vlan_brief", "interfaces", "trunk_operational", "spanning_tree", "etherchannels"]),
            ("L3/Routing", ["ip_inventory", "dhcp_scopes", "route_table", "routing", "protocol_summary"]),
            ("Security", ["acl_rules", "acl_hit_counts", "security_hardening", "port_security"]),
            ("Topology", ["cdp_links", "lldp_links", "mac_table", "arp_table"]),
            ("Wireless", ["wireless_hints"]),
            ("Operations", ["interface_status", "interface_counters", "command_blocks"]),
        ]
        result = []
        for name, keys in domains:
            count = sum(len(objects.get(k) or []) for k in keys)
            result.append({
                "domain": name,
                "count": count,
                "status": "excellent" if count >= 8 else "good" if count >= 3 else "needs_more_evidence" if count else "missing",
                "keys": keys,
            })
        return result


    def parse_ip_inventory(self):
        entries = []
        for no, line in self.lines:
            if re.search(r"Interface\s+IP-Address\s+OK\?\s+Method\s+Status\s+Protocol", line, flags=re.I):
                continue
            m = re.match(r"^\s*(\S+)\s+(unassigned|\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(.+?)\s+(up|down|administratively down)\s*$", line, flags=re.I)
            if m and re.match(r"^(Fa|FastEthernet|Gi|GigabitEthernet|Te|TenGigabitEthernet|Eth|Ethernet|Se|Serial|Lo|Loopback|Vl|Vlan)", m.group(1), flags=re.I):
                iface, ip, status, protocol = m.groups()
                entries.append({
                    "interface": iface,
                    "normalized_interface": normalize_interface_name(iface),
                    "ip_address": None if ip.lower() == "unassigned" else ip,
                    "status": status.strip().lower(),
                    "protocol": protocol.lower(),
                    "evidence": evidence_obj(no, line, 0.86),
                })
        return entries

    def parse_port_security(self):
        entries = []
        # Running-config interface hints are taken from the already parsed interface model.
        for iface in self.parse_interfaces():
            if iface.get("port_security_enabled") or iface.get("port_security_max") or iface.get("port_security_violation"):
                entries.append({
                    "interface": iface.get("name"),
                    "normalized_interface": iface.get("normalized_name"),
                    "enabled": bool(iface.get("port_security_enabled")),
                    "maximum": iface.get("port_security_max"),
                    "violation_mode": iface.get("port_security_violation"),
                    "sticky": bool(iface.get("port_security_sticky")),
                    "source": "running-config interface",
                    "evidence": iface.get("evidence", evidence_obj(None, "derived", 0.70)),
                })
        current = None
        item = None
        for no, line in self.lines:
            im = re.match(r"^\s*(?:Secure)?Port\s*:\s*(\S+)", line, flags=re.I)
            if im:
                current = im.group(1)
                item = {"interface": current, "normalized_interface": normalize_interface_name(current), "source": "show port-security", "evidence": evidence_obj(no, line, 0.82)}
                entries.append(item)
                continue
            m = re.match(r"^\s*Port Security\s*:\s*(Enabled|Disabled)", line, flags=re.I)
            if m:
                if not item:
                    item = {"interface": current or "unknown", "normalized_interface": normalize_interface_name(current), "source": "show port-security", "evidence": evidence_obj(no, line, 0.78)}
                    entries.append(item)
                item["enabled"] = m.group(1).lower() == "enabled"
            if item:
                mm = re.match(r"^\s*Maximum MAC Addresses\s*:\s*(\d+)", line, flags=re.I)
                vm = re.match(r"^\s*Violation Mode\s*:\s*(\S+)", line, flags=re.I)
                vc = re.match(r"^\s*Security Violation Count\s*:\s*(\d+)", line, flags=re.I)
                la = re.match(r"^\s*Last Source Address\S*\s*:\s*(\S+)", line, flags=re.I)
                if mm:
                    item["maximum"] = mm.group(1)
                if vm:
                    item["violation_mode"] = vm.group(1).lower()
                if vc:
                    item["violation_count"] = safe_int(vc.group(1))
                if la:
                    item["last_source"] = la.group(1)
        dedup = {}
        for e in entries:
            key = (e.get("normalized_interface"), e.get("source"))
            dedup[key] = {**dedup.get(key, {}), **e}
        return list(dedup.values())

    def parse_spanning_tree(self):
        rows = []
        current_vlan = None
        for no, line in self.lines:
            vm = re.match(r"^\s*(VLAN\d+|vlan\s+\d+)\b", line, flags=re.I)
            if vm:
                digits = re.findall(r"\d+", vm.group(1))
                current_vlan = digits[0] if digits else vm.group(1)
            rm = re.match(r"^\s*(\S+)\s+(Root|Altn|Desg|Back|Mstr|Disabled)\s+(FWD|BLK|LRN|LIS|DIS)\s+\d+\s+\S+\s+(.+)$", line, flags=re.I)
            if rm and re.match(r"^(Fa|Gi|Te|Eth|Po)", rm.group(1), flags=re.I):
                iface, role, state, link_type = rm.groups()
                rows.append({
                    "vlan": current_vlan,
                    "interface": iface,
                    "normalized_interface": normalize_interface_name(iface),
                    "role": role,
                    "state": state,
                    "type": link_type.strip(),
                    "evidence": evidence_obj(no, line, 0.80),
                })
        return rows

    def parse_etherchannels(self):
        rows = []
        for no, line in self.lines:
            m = re.match(r"^\s*(\d+)\s+(Po\d+)\(([^)]+)\)\s+(\S+)\s+(.+)$", line, flags=re.I)
            if m:
                group, port_channel, flags, protocol, ports = m.groups()
                rows.append({
                    "group": group,
                    "port_channel": port_channel,
                    "normalized_port_channel": normalize_interface_name(port_channel),
                    "flags": flags,
                    "protocol": protocol,
                    "member_ports": re.findall(r"(?:Fa|Gi|Te|Eth)\S+\([A-Za-z]+\)", ports),
                    "raw_members": ports.strip(),
                    "evidence": evidence_obj(no, line, 0.80),
                })
        return rows

    def parse_mac_table(self):
        rows = []
        for no, line in self.lines:
            m = re.match(r"^\s*(\d{1,4})\s+([0-9a-f.:-]{8,})\s+(DYNAMIC|STATIC|dynamic|static)\s+(\S+)", line, flags=re.I)
            if m:
                vlan, mac, typ, port = m.groups()
                rows.append({
                    "vlan": vlan,
                    "mac": mac.lower(),
                    "type": typ.lower(),
                    "interface": port,
                    "normalized_interface": normalize_interface_name(port),
                    "evidence": evidence_obj(no, line, 0.75),
                })
        return rows[:1000]

    def parse_arp_table(self):
        rows = []
        for no, line in self.lines:
            m = re.match(r"^\s*Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f.:-]+)\s+\S+\s+(\S+)", line, flags=re.I)
            if m:
                ip, mac, iface = m.groups()
                rows.append({
                    "ip_address": ip,
                    "mac": mac.lower(),
                    "interface": iface,
                    "normalized_interface": normalize_interface_name(iface),
                    "evidence": evidence_obj(no, line, 0.74),
                })
        return rows[:1000]

    def parse_device_facts(self):
        facts = []
        patterns = [
            ("ios_version", r"Cisco IOS Software,\s*(.+)"),
            ("uptime", r"^\s*(\S+)\s+uptime is\s+(.+)"),
            ("image", r"System image file is\s+\"?([^\"]+)\"?"),
            ("config_register", r"Configuration register is\s+(\S+)"),
            ("model", r"^\s*cisco\s+(\S+)\s+\(.+\)\s+processor"),
        ]
        for no, line in self.lines:
            for name, pattern in patterns:
                m = re.search(pattern, line, flags=re.I)
                if m:
                    facts.append({"name": name, "value": " | ".join(g for g in m.groups() if g), "evidence": evidence_obj(no, line, 0.70)})
        return facts

    def parse_service_hints(self):
        services = []
        keywords = {
            "ERP": ["erp"],
            "DNS": ["dns"],
            "File Server": ["file server", "smb"],
            "Internal Portal": ["portal", "intranet"],
            "Internet": ["internet", "default route"]
        }
        for no, line in self.lines:
            low = line.lower()
            for name, vals in keywords.items():
                if any(v in low for v in vals):
                    services.append({"name": name, "hint": line.strip(), "evidence": evidence_obj(no, line, 0.65)})
        return services


class PacketTracerImportService:
    def __init__(self, upload_dir: Path):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def _stored_filename(self, original_name):
        safe = secure_filename(original_name or "uploaded") or "uploaded"
        ext = Path(safe).suffix.lower()
        if ext not in ALLOWED_UPLOAD_EXTENSIONS:
            raise ValueError(f"Unsupported file extension '{ext or 'none'}'. Allowed: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}.")
        return safe, f"{uuid.uuid4().hex}{ext}"

    def _safe_zip_text(self, zip_path: Path):
        text_parts = []
        total = 0
        with zipfile.ZipFile(zip_path) as zf:
            members = zf.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                raise ValueError(f"ZIP contains too many members ({len(members)} > {MAX_ZIP_MEMBERS}).")
            for info in members:
                if info.is_dir():
                    continue
                member_name = Path(info.filename.replace("\\", "/")).name
                if not member_name or Path(member_name).suffix.lower() not in ALLOWED_ZIP_MEMBER_EXTENSIONS:
                    continue
                if info.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise ValueError(f"ZIP member '{member_name}' is too large.")
                total += info.file_size
                if total > MAX_ZIP_TOTAL_BYTES:
                    raise ValueError("ZIP text payload is too large.")
                with zf.open(info) as fh:
                    text_parts.append(f"\n--- ZIP MEMBER: {member_name} ---\n" + fh.read().decode("utf-8", errors="replace"))
        return "\n".join(text_parts)

    def read_upload(self, uploaded_file):
        original_filename = uploaded_file.filename or "uploaded"
        safe_original, stored_name = self._stored_filename(original_filename)
        raw = uploaded_file.read()
        if not raw:
            raise ValueError("Uploaded file is empty.")
        source_hash = hashlib.sha256(raw).hexdigest()
        upload_path = (self.upload_dir / stored_name).resolve()
        upload_root = self.upload_dir.resolve()
        if not upload_path.is_relative_to(upload_root):
            raise ValueError("Unsafe upload path rejected.")
        upload_path.write_bytes(raw)
        ext = Path(safe_original).suffix.lower()

        # Optional external converter for .pkt/.pka
        converter = os.environ.get("PTEXPLORER_PATH")
        xml_from_converter = None
        if ext in {".pkt", ".pka"} and converter and Path(converter).exists():
            try:
                out_xml = self.upload_dir / f"{Path(stored_name).stem}_converted.xml"
                result = subprocess.run([converter, str(upload_path), str(out_xml)], capture_output=True, text=True, timeout=45)
                if result.returncode == 0 and out_xml.exists():
                    xml_from_converter = out_xml.read_text(encoding="utf-8", errors="replace")
            except Exception:
                xml_from_converter = None

        if xml_from_converter:
            return safe_original, stored_name, raw, xml_from_converter, "external_xml_converter", source_hash

        if ext == ".json":
            return safe_original, stored_name, raw, raw.decode("utf-8", errors="replace"), "json", source_hash
        if ext == ".xml":
            return safe_original, stored_name, raw, raw.decode("utf-8", errors="replace"), "xml", source_hash
        if zipfile.is_zipfile(upload_path):
            return safe_original, stored_name, raw, self._safe_zip_text(upload_path), "zip_text", source_hash
        text = raw.decode("utf-8", errors="replace")
        if ext in {".pkt", ".pka"}:
            text += "\n\n--- PRINTABLE_PACKET_TRACER_BINARY_EVIDENCE ---\n" + printable_recovery(raw)
            return safe_original, stored_name, raw, text, "pkt_binary_recovery", source_hash
        return safe_original, stored_name, raw, text, "text_config", source_hash

    def _missing_evidence(self, objects):
        missing = []
        if not objects.get("interfaces"):
            missing.append({"source": "show running-config interfaces", "why": "No interface blocks were extracted; topology and ACL binding may be incomplete.", "severity": "High"})
        if not any(i.get("mode") == "trunk" or i.get("trunk_allowed_vlans") for i in objects.get("interfaces", [])):
            missing.append({"source": "show interfaces trunk", "why": "Trunk coverage cannot be validated without trunk evidence.", "severity": "Medium"})
        if not objects.get("acl_rules"):
            missing.append({"source": "show access-lists / running-config ACL sections", "why": "Segmentation checks cannot confirm deny/permit enforcement without ACL evidence.", "severity": "High"})
        if not objects.get("dhcp_scopes"):
            missing.append({"source": "show running-config | section ip dhcp", "why": "DHCP/subnet matching will remain review-only without DHCP pool evidence.", "severity": "Medium"})
        if not objects.get("cdp_links"):
            missing.append({"source": "show cdp neighbors detail", "why": "Physical adjacency/topology edges are inferred rather than confirmed.", "severity": "Low"})
        if not objects.get("ip_inventory"):
            missing.append({"source": "show ip interface brief", "why": "Interface operational status and L3 reachability cannot be fully verified.", "severity": "Medium"})
        if not objects.get("spanning_tree"):
            missing.append({"source": "show spanning-tree", "why": "Layer-2 loop/blocked-port behavior cannot be validated.", "severity": "Low"})
        return missing

    def _confidence_summary(self, objects, source_mode):
        source_confidence = {
            "text_config": 0.92,
            "json": 0.90,
            "xml": 0.82,
            "zip_text": 0.82,
            "external_xml_converter": 0.86,
            "pkt_binary_recovery": 0.58,
        }.get(source_mode, 0.70)
        evidence_profile = objects.get("evidence_profile", {})
        ratio = evidence_profile.get("line_mapping_ratio", 0)
        applied_acls = sum(1 for r in objects.get("acl_rules", []) if r.get("is_applied"))
        acl_bonus = 0.08 if applied_acls else 0
        score = min(0.99, round((source_confidence * 0.55) + (ratio * 0.35) + acl_bonus, 3))
        return {
            "overall": score,
            "source_confidence": source_confidence,
            "line_mapping_ratio": ratio,
            "applied_acl_rules": applied_acls,
            "mode": source_mode,
        }

    def extract(self, uploaded_file):
        filename, stored_filename, raw, text, source_mode, source_hash = self.read_upload(uploaded_file)
        extractor = ConfigExtractor()

        if source_mode == "json":
            try:
                payload = json.loads(text)
                objects = payload.get("objects") or payload.get("extracted") or payload
                if isinstance(objects, dict) and all(k in objects for k in ["devices", "interfaces"]):
                    parsed = objects
                else:
                    parsed = extractor.parse(text)
            except Exception:
                parsed = extractor.parse(text)
        elif source_mode == "xml":
            # Convert XML text to raw evidence + regex parsing. Real PT XML formats vary.
            parsed = extractor.parse(text)
            parsed["xml_detected"] = True
        else:
            parsed = extractor.parse(text)

        if not parsed.get("devices"):
            parsed["devices"] = [{"id": "Extracted-Reality", "hostname": "Extracted Wired Reality", "type": "network", "role": "synthetic_context", "evidence": {"source_line": None, "source_text": "Synthetic context because no hostname was found.", "confidence": 0.35}}]

        conversion_profile = build_conversion_profile(filename, raw, text, source_mode, parsed)
        parsed["packet_tracer_profile"] = conversion_profile

        pipeline = [
            {"stage": "File Intake", "status": "success", "confidence": 1.0, "items": 1, "detail": f"Accepted {filename} and stored immutable source hash."},
            {"stage": "Source Decoding", "status": "success" if source_mode != "pkt_binary_recovery" else "partial", "confidence": 0.95 if source_mode not in {"pkt_binary_recovery"} else 0.62, "items": len(text.splitlines()), "detail": f"Source mode: {source_mode}."},
            {"stage": "Packet Tracer Intelligence", "status": conversion_profile.get("readiness", "review"), "confidence": conversion_profile.get("readiness_score", 0.5), "items": conversion_profile.get("objects_total", 0), "detail": conversion_profile.get("analyst_next_step", "Conversion profile built.")},
            {"stage": "Object Extraction", "status": "success", "confidence": 0.90, "items": sum(len(v) for k, v in parsed.items() if isinstance(v, list)), "detail": "Parsed devices, interfaces, VLANs, DHCP, ACL, routing, NAT, L2 health, and link hints."},
            {"stage": "Evidence Mapping", "status": "success", "confidence": 0.88, "items": len(parsed.get("raw_evidence", [])), "detail": "Mapped extracted objects to line-level evidence where possible."}
        ]

        confidence = self._confidence_summary(parsed, source_mode)
        confidence["readiness"] = conversion_profile.get("readiness")
        confidence["readiness_score"] = conversion_profile.get("readiness_score")
        return {"filename": filename, "stored_filename": stored_filename, "source_hash": source_hash, "source_mode": source_mode, "text": text, "objects": parsed, "pipeline": pipeline, "imported_at": now_iso(), "missing_evidence": self._missing_evidence(parsed), "confidence_summary": confidence, "conversion_profile": conversion_profile}
