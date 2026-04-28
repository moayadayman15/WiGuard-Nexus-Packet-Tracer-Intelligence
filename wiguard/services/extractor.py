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
            "services": self.parse_service_hints(),
            "raw_evidence": self.raw_evidence()
        }
        self.bind_acls_to_interfaces(objects)
        objects["dhcp_gateway_matches"] = self.match_dhcp_gateways(objects)
        objects["evidence_profile"] = self.evidence_profile(objects)
        return objects

    def raw_evidence(self):
        interesting = []
        patterns = [
            "hostname", "interface", "vlan", "switchport", "ip dhcp", "access-list",
            "ip access-group", "ip route", "router ospf", "router eigrp", "router rip",
            "router bgp", "ip nat", "Device ID", "Port ID", "Platform"
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
                            "name": port, "description": "show interfaces trunk hint",
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
                        if item.get("evidence", {}).get("source_line") is not None:
                            line_mapped += 1
        return {
            "raw_evidence_lines": raw_count,
            "objects_with_line_evidence": line_mapped,
            "total_list_objects": total,
            "line_mapping_ratio": round(line_mapped / total, 3) if total else 0,
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

        pipeline = [
            {"stage": "File Intake", "status": "success", "confidence": 1.0, "items": 1, "detail": f"Accepted {filename}."},
            {"stage": "Source Decoding", "status": "success" if source_mode != "pkt_binary_recovery" else "partial", "confidence": 0.95 if source_mode not in {"pkt_binary_recovery"} else 0.62, "items": len(text.splitlines()), "detail": f"Source mode: {source_mode}."},
            {"stage": "Object Extraction", "status": "success", "confidence": 0.90, "items": sum(len(v) for k, v in parsed.items() if isinstance(v, list)), "detail": "Parsed devices, interfaces, VLANs, DHCP, ACL, routing, NAT, and link hints."},
            {"stage": "Evidence Mapping", "status": "success", "confidence": 0.88, "items": len(parsed.get("raw_evidence", [])), "detail": "Mapped extracted objects to line-level evidence where possible."}
        ]

        return {"filename": filename, "stored_filename": stored_filename, "source_hash": source_hash, "source_mode": source_mode, "text": text, "objects": parsed, "pipeline": pipeline, "imported_at": now_iso(), "missing_evidence": self._missing_evidence(parsed), "confidence_summary": self._confidence_summary(parsed, source_mode)}
