"""Native Packet Tracer `.pkt/.pka` auto-conversion helpers.

Packet Tracer's native project format is proprietary.  This module therefore
runs a deterministic *background conversion pipeline* instead of pretending to
fully reverse-engineer the file:

1. fingerprint and preserve the uploaded binary,
2. probe external converter output when available,
3. recover ZIP/wrapped/zlib/printable XML/JSON/config evidence,
4. build an internal XML bridge from everything recoverable,
5. create normalized JSON for the UI, artifacts, reports and object parser.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import math
import re
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from xml.etree import ElementTree as ET


MAX_STRING_PREVIEW = 220
MAX_STRINGS = 250
MAX_DECOMPRESSED_CHUNKS = 16
MAX_DECOMPRESSED_BYTES = 256_000
MAX_DECODED_PAYLOADS = 40
MAX_PAYLOAD_TEXT = 220_000

COMMON_SIGNATURES: List[Tuple[str, bytes, str]] = [
    ("zip_pk", b"PK\x03\x04", "ZIP container/member header"),
    ("gzip", b"\x1f\x8b", "GZip compressed stream"),
    ("zlib_best_compression", b"\x78\xda", "Zlib compressed stream"),
    ("zlib_default", b"\x78\x9c", "Zlib compressed stream"),
    ("zlib_fast", b"\x78\x01", "Zlib compressed stream"),
    ("bzip2", b"BZh", "BZip2 compressed stream"),
    ("xz", b"\xfd7zXZ\x00", "XZ compressed stream"),
    ("sqlite", b"SQLite format 3\x00", "SQLite database"),
    ("xml", b"<?xml", "XML document"),
    ("json_object", b"{\n", "JSON-like object"),
]

CISCO_CONFIG_PATTERNS = [
    r"\bhostname\s+\S+",
    r"\binterface\s+(?:FastEthernet|GigabitEthernet|TenGigabitEthernet|Ethernet|Serial|Vlan|Port-channel|Loopback|Fa|Gi|Te|Eth|Se|Vl|Po|Lo)\S*",
    r"\bswitchport\b",
    r"\bip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+",
    r"\bip\s+route\s+\d+\.\d+\.\d+\.\d+",
    r"\bip\s+dhcp\s+pool\s+\S+",
    r"\baccess-list\s+\S+",
    r"\bip\s+access-list\b",
    r"\brouter\s+(?:ospf|eigrp|rip|bgp)\b",
    r"\bspanning-tree\b",
    r"\bline\s+vty\b",
    r"\bservice\s+password-encryption\b",
]


CONFIG_COMMAND_STARTERS = (
    "hostname", "interface", "ip dhcp pool", "ip dhcp excluded-address",
    "switchport", "encapsulation dot1q", "ip address", "ip route", "router ospf",
    "router eigrp", "router rip", "router bgp", "access-list", "ip access-list",
    "ip nat", "spanning-tree", "line vty", "service password-encryption",
    "enable secret", "username", "snmp-server", "radius-server", "aaa new-model",
    "description", "shutdown", "no shutdown", "channel-group", "switchport port-security", "switchport voice vlan", "spanning-tree portfast", "standby", "vrrp", "glbp",
    "ssid", "wlan", "crypto", "network", "default-router", "dns-server", "ip helper-address", "ip default-gateway", "ip name-server",
)

CONFIG_RECONSTRUCTION_PATTERNS = [
    r"hostname\s+\S+",
    r"interface\s+(?:FastEthernet|GigabitEthernet|TenGigabitEthernet|Ethernet|Serial|Vlan|Port-channel|Loopback|Fa|Gi|Te|Eth|Se|Vl|Po|Lo)\S*",
    r"switchport\s+trunk\s+allowed\s+vlan\s+[0-9,\-]+",
    r"switchport\s+trunk\s+native\s+vlan\s+\d+",
    r"switchport\s+access\s+vlan\s+\d+",
    r"switchport\s+mode\s+\S+",
    r"switchport\s+(?:voice|port-security|nonegotiate)\b[^\r\n]{0,120}",
    r"encapsulation\s+dot1q\s+\d+",
    r"ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+",
    r"vlan\s+\d+(?:\s+name\s+\S+)?",
    r"ip\s+dhcp\s+pool\s+\S+",
    r"ip\s+dhcp\s+excluded-address\s+\S+(?:\s+\S+)?",
    r"network\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+",
    r"default-router\s+\d+\.\d+\.\d+\.\d+",
    r"dns-server\s+(?:\d+\.\d+\.\d+\.\d+\s*)+",
    r"ip\s+route\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+",
    r"router\s+(?:ospf|eigrp|rip|bgp)\b[^\r\n]{0,120}",
    r"access-list\s+\S+\s+(?:permit|deny)\b[^\r\n]{0,180}",
    r"ip\s+access-list\s+(?:standard|extended)\s+\S+",
    r"ip\s+nat\s+[^\r\n]{0,160}",
    r"spanning-tree\s+[^\r\n]{0,160}",
    r"line\s+vty\s+[^\r\n]{0,80}",
    r"service\s+password-encryption",
    r"enable\s+secret\s+[^\r\n]{0,120}",
    r"username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+[^\r\n]{0,120}",
    r"snmp-server\s+[^\r\n]{0,160}",
    r"radius-server\s+[^\r\n]{0,160}",
    r"aaa\s+new-model",
    r"ssid\s+[^\r\n]{1,80}",
    r"wlan\s+[^\r\n]{1,100}",
    r"ip\s+helper-address\s+\d+\.\d+\.\d+\.\d+",
    r"ip\s+default-gateway\s+\d+\.\d+\.\d+\.\d+",
    r"ip\s+name-server\s+(?:\d+\.\d+\.\d+\.\d+\s*)+",
    r"switchport\s+voice\s+vlan\s+\d+",
    r"spanning-tree\s+portfast\b",
    r"storm-control\s+\S+\s+level\s+[^\r\n]{1,40}",
    r"channel-group\s+\d+(?:\s+mode\s+\S+)?",
    r"standby\s+\d+\s+(?:ip|priority|preempt|track)\b[^\r\n]{0,100}",
    r"vrrp\s+\d+\s+(?:ip|priority|preempt|track)\b[^\r\n]{0,100}",
    r"glbp\s+\d+\s+(?:ip|priority|preempt|weighting)\b[^\r\n]{0,100}",
]


def shannon_entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = Counter(raw)
    total = len(raw)
    return round(-sum((n / total) * math.log2(n / total) for n in counts.values()), 4)


def printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    return round(printable / len(raw), 4)


def recover_printable_strings(raw: bytes, min_len: int = 5) -> List[str]:
    strings: List[str] = []
    current: List[str] = []
    for b in raw:
        if 32 <= b <= 126 or b in (9, 10, 13):
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append("".join(current).strip())
            current = []
    if len(current) >= min_len:
        strings.append("".join(current).strip())
    seen = set()
    cleaned = []
    for item in strings:
        compact = re.sub(r"\s+", " ", item).strip()
        if not compact or compact in seen:
            continue
        seen.add(compact)
        cleaned.append(compact[:MAX_STRING_PREVIEW])
    return cleaned[:MAX_STRINGS]


def recover_unicode_strings(raw: bytes, min_len: int = 5) -> List[str]:
    """Recover UTF-16LE/UTF-16BE strings stored inside native Packet Tracer files."""
    results: List[str] = []
    for encoding in ("utf-16le", "utf-16be"):
        try:
            decoded = raw.decode(encoding, errors="ignore")
        except Exception:
            continue
        buf: List[str] = []
        for ch in decoded:
            if ch in "\t\n\r" or 32 <= ord(ch) <= 126:
                buf.append(ch)
            else:
                if len(buf) >= min_len:
                    results.append("".join(buf).strip())
                buf = []
        if len(buf) >= min_len:
            results.append("".join(buf).strip())
    seen = set()
    cleaned: List[str] = []
    for item in results:
        compact = re.sub(r"\s+", " ", item).strip()
        if len(compact) < min_len or compact in seen:
            continue
        alpha_ratio = sum(1 for c in compact if c.isalnum() or c in "._:-/ ") / max(len(compact), 1)
        if alpha_ratio < 0.55:
            continue
        seen.add(compact)
        cleaned.append(compact[:MAX_STRING_PREVIEW])
    return cleaned[:MAX_STRINGS]


def _dedupe_strings(values: Iterable[str], limit: int = MAX_STRINGS) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        compact = re.sub(r"\s+", " ", str(value or "")).strip()
        if not compact or compact in seen:
            continue
        seen.add(compact)
        out.append(compact[:MAX_STRING_PREVIEW])
        if len(out) >= limit:
            break
    return out




def recover_printable_segments(raw: bytes, min_len: int = 24, max_segments: int = 80) -> List[Dict[str, Any]]:
    """Recover longer printable spans while preserving command separators."""
    segments: List[Dict[str, Any]] = []
    buf: List[str] = []
    start_offset: int | None = None
    for idx, b in enumerate(raw):
        if 32 <= b <= 126 or b in (9, 10, 13):
            if start_offset is None:
                start_offset = idx
            buf.append(chr(b))
        else:
            if start_offset is not None and len(buf) >= min_len:
                text = "".join(buf).strip()
                if text:
                    segments.append({"offset": start_offset, "bytes": len(text.encode("utf-8", errors="replace")), "text": text[:MAX_PAYLOAD_TEXT]})
                    if len(segments) >= max_segments:
                        return segments
            buf = []
            start_offset = None
    if start_offset is not None and len(buf) >= min_len:
        text = "".join(buf).strip()
        if text:
            segments.append({"offset": start_offset, "bytes": len(text.encode("utf-8", errors="replace")), "text": text[:MAX_PAYLOAD_TEXT]})
    return segments[:max_segments]


def reconstruct_cisco_config_text(text: str) -> str:
    """Best-effort recovery for configs flattened inside proprietary binaries.

    The function works in source order: it finds real IOS command starters and
    slices each command until the next starter.  It never invents values; every
    output token must exist in recovered source text.
    """
    if not text:
        return ""
    cleaned = "".join(ch if (ch in "\t\n\r" or ord(ch) >= 32) else "\n" for ch in str(text))
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+", "\n", cleaned)
    candidates: List[str] = []

    # 1) Preserve genuine line-oriented configs first.
    for line in cleaned.splitlines():
        line = re.sub(r"\s+", " ", line).strip()
        if not line:
            continue
        if re.match(r"(?i)^(hostname|interface|vlan|ip dhcp|switchport|encapsulation|ip address|ip route|router |access-list|ip access-list|ip nat|spanning-tree|line vty|service password-encryption|enable secret|username|snmp-server|radius-server|aaa new-model|ssid|wlan)\b", line):
            candidates.append(_trim_reconstructed_command(line))

    # 2) Recover commands flattened onto one long binary string.
    flat = re.sub(r"\s+", " ", cleaned)
    starter_regex = re.compile(r"(?i)\b(" + "|".join(re.escape(x) for x in sorted(CONFIG_COMMAND_STARTERS, key=len, reverse=True)) + r")\b")
    matches = list(starter_regex.finditer(flat))[:1600]
    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else min(len(flat), start + 500)
        line = re.sub(r"\s+", " ", flat[start:end]).strip()
        if line:
            candidates.append(_trim_reconstructed_command(line))

    # 3) Regex fallback for high-value commands missed by starter slicing.
    for pat in CONFIG_RECONSTRUCTION_PATTERNS:
        for m in re.finditer(pat, flat, flags=re.I):
            value = re.sub(r"\s+", " ", m.group(0)).strip()
            if value:
                candidates.append(_trim_reconstructed_command(value))

    seen = set()
    ordered = []
    for line in candidates:
        line = re.sub(r"\s+", " ", line).strip()
        if not line or len(line) < 3:
            continue
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(line[:500])
    return "\n".join(ordered[:1200])


def _trim_reconstructed_command(line: str) -> str:
    line = re.sub(r"\s+", " ", str(line or "")).strip()
    command_trimmers = [
        r"^(hostname\s+\S+)",
        r"^(interface\s+\S+)",
        r"^(vlan\s+\d+)(?:\s+name\s+(\S+))?",
        r"^(name\s+\S+)",
        r"^(ip\s+dhcp\s+pool\s+\S+)",
        r"^(network\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+)",
        r"^(default-router\s+\d+\.\d+\.\d+\.\d+)",
        r"^(dns-server\s+(?:\d+\.\d+\.\d+\.\d+\s*)+)",
        r"^(switchport\s+mode\s+\S+)",
        r"^(switchport\s+access\s+vlan\s+\d+)",
        r"^(switchport\s+trunk\s+allowed\s+vlan\s+[0-9,\-]+)",
        r"^(switchport\s+trunk\s+native\s+vlan\s+\d+)",
        r"^(switchport\s+port-security(?:\s+\S+){0,6})",
        r"^(encapsulation\s+dot1q\s+\d+)",
        r"^(ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+)",
        r"^(ip\s+route\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+)",
        r"^(router\s+(?:ospf|eigrp|rip|bgp)\b(?:\s+\S+)?)",
        r"^(access-list\s+\S+\s+(?:permit|deny)\s+(?:ip|tcp|udp|icmp)?\s*(?:any|host\s+\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+(?:\s+\d+\.\d+\.\d+\.\d+)?)\s*(?:any|host\s+\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+(?:\s+\d+\.\d+\.\d+\.\d+)?)?(?:\s+eq\s+\S+)?)",
        r"^(ip\s+access-list\s+(?:standard|extended)\s+\S+)",
        r"^(ip\s+nat\s+\S+(?:\s+\S+){0,8})",
        r"^(spanning-tree\s+\S+(?:\s+\S+){0,8})",
        r"^(line\s+vty\s+\S+(?:\s+\S+)?)",
        r"^(service\s+password-encryption)",
        r"^(enable\s+secret\s+\S+(?:\s+\S+)?)",
        r"^(username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+\S+(?:\s+\S+)?)",
        r"^(snmp-server\s+\S+(?:\s+\S+){0,8})",
        r"^(radius-server\s+\S+(?:\s+\S+){0,8})",
        r"^(aaa\s+new-model)",
        r"^(ssid\s+\S+(?:\s+\S+){0,4})",
        r"^(wlan\s+\S+(?:\s+\S+){0,4})",
        r"^(ip\s+helper-address\s+\d+\.\d+\.\d+\.\d+)",
        r"^(ip\s+default-gateway\s+\d+\.\d+\.\d+\.\d+)",
        r"^(ip\s+name-server\s+(?:\d+\.\d+\.\d+\.\d+\s*)+)",
        r"^(switchport\s+voice\s+vlan\s+\d+)",
        r"^(spanning-tree\s+portfast\b(?:\s+\S+)?)",
        r"^(storm-control\s+\S+\s+level\s+\S+(?:\s+\S+)?)",
        r"^(channel-group\s+\d+(?:\s+mode\s+\S+)?)",
        r"^(standby\s+\d+\s+(?:ip|priority|preempt|track)\b(?:\s+\S+){0,5})",
        r"^(vrrp\s+\d+\s+(?:ip|priority|preempt|track)\b(?:\s+\S+){0,5})",
        r"^(glbp\s+\d+\s+(?:ip|priority|preempt|weighting)\b(?:\s+\S+){0,5})",
    ]
    for pat in command_trimmers:
        m = re.match(pat, line, flags=re.I)
        if m:
            if pat.startswith('^(vlan') and m.lastindex and m.lastindex >= 2 and m.group(2):
                return f"{m.group(1)}\n name {m.group(2)}"
            return m.group(1).strip()
    return line[:220]


def _safe_status_for_fidelity(profile: Dict[str, Any], payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a truthful fidelity contract for UI/reports; never claims fake 100%."""
    has_external = any(p.get("source") == "external_converter" for p in payloads or [])
    recovered_lines = int(profile.get("reconstructed_config_count") or 0)
    decoded = int(profile.get("decoded_payload_count") or len(payloads or []))
    if has_external:
        tier, score, status = "converter_verified", 0.96, "pass"
        detail = "External converter output was included, so native Packet Tracer object fidelity is high."
    elif recovered_lines >= 20 or decoded >= 3:
        tier, score, status = "strong_visible_recovery", 0.82, "pass"
        detail = "Recovered substantial IOS/XML/JSON evidence directly from the native file."
    elif recovered_lines >= 4 or decoded >= 1:
        tier, score, status = "partial_visible_recovery", 0.63, "review"
        detail = "Recovered useful fragments, but some native topology objects may still be hidden."
    else:
        tier, score, status = "opaque_native_binary", 0.34, "fail"
        detail = "The native file did not expose enough trustworthy structured evidence; upload exported configs or configure a converter."
    return {"tier": tier, "score": score, "status": status, "detail": detail, "no_fake_100": True}

def _signature_hits(raw: bytes) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for name, marker, desc in COMMON_SIGNATURES:
        start = 0
        count = 0
        while True:
            idx = raw.find(marker, start)
            if idx == -1:
                break
            hits.append({"name": name, "offset": idx, "hex_offset": hex(idx), "description": desc})
            count += 1
            if count >= 8:
                break
            start = idx + 1
    return sorted(hits, key=lambda x: x["offset"])[:80]


def _valid_zlib_header(raw: bytes, idx: int) -> bool:
    if idx + 1 >= len(raw) or raw[idx] != 0x78:
        return False
    cmf, flg = raw[idx], raw[idx + 1]
    return ((cmf << 8) + flg) % 31 == 0


def _try_zlib_chunks(raw: bytes) -> Tuple[List[Dict[str, Any]], List[str]]:
    chunks: List[Dict[str, Any]] = []
    recovered_texts: List[str] = []
    offsets: List[int] = []
    for idx, b in enumerate(raw[:-2]):
        if b == 0x78 and _valid_zlib_header(raw, idx):
            offsets.append(idx)
    for idx in sorted(set(offsets))[:180]:
        if len(chunks) >= MAX_DECOMPRESSED_CHUNKS:
            break
        try:
            decomp = zlib.decompressobj()
            data = decomp.decompress(raw[idx:], MAX_DECOMPRESSED_BYTES)
            if not data or len(data) < 32:
                continue
            text = data.decode("utf-8", errors="replace")
            pr = printable_ratio(data)
            config_hits = sum(1 for pat in CISCO_CONFIG_PATTERNS if re.search(pat, text, re.I))
            chunks.append({
                "offset": idx,
                "hex_offset": hex(idx),
                "bytes": len(data),
                "printable_ratio": pr,
                "config_pattern_hits": config_hits,
                "preview": re.sub(r"\s+", " ", text[:900]).strip(),
            })
            if pr >= 0.35 or config_hits:
                recovered_texts.append(f"\n--- PKT ZLIB CHUNK @ {hex(idx)} ---\n{text[:MAX_DECOMPRESSED_BYTES]}")
        except Exception:
            continue
    return chunks, recovered_texts


def _visible_hints(strings: Iterable[str]) -> Dict[str, Any]:
    blob = "\n".join(str(s or "") for s in strings)
    ips = sorted(set(re.findall(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b", blob)))[:100]
    macs = sorted(set(re.findall(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b", blob)))[:100]
    interfaces = sorted(set(re.findall(r"\b(?:FastEthernet|GigabitEthernet|TenGigabitEthernet|Ethernet|Serial|Vlan|Port-channel|Loopback|Fa|Gi|Te|Eth|Se|Vl|Po|Lo)\s*\d+(?:/\d+){0,3}(?:\.\d+)?\b", blob, flags=re.I)))[:160]
    interfaces = [i for i in interfaces if not re.match(r"(?i)^vlan\s+\d+$", str(i).strip())][:120]
    vlan_candidates = sorted(set(re.findall(r"(?i)\bvlan\s+(\d{1,4})\b", blob)))[:120]
    ssids = []
    for m in re.finditer(r"\b(?:ssid|wlan|wireless)\b[^\n\r]{0,80}", blob, flags=re.I):
        ssids.append(m.group(0).strip())
    device_candidates = set()
    for pat in [
        r"(?im)^\s*hostname\s+([^\s!]+)",
        r"(?i)Device ID:\s*([^\r\n]+)",
        r"(?i)System Name:\s*([^\r\n]+)",
        r"(?i)node(?:Name|Label)?[=: ]+([A-Za-z][A-Za-z0-9_.-]{1,80})",
        r"(?i)device(?:Name|Label)?[=: ]+([A-Za-z][A-Za-z0-9_.-]{1,80})",
    ]:
        for m in re.finditer(pat, blob):
            candidate = re.sub(r"[^A-Za-z0-9_.:-].*$", "", m.group(1).strip())
            if candidate and candidate.lower() not in {"id", "name", "router", "switch", "device", "node", "interface"}:
                device_candidates.add(candidate[:80])
    config_lines = []
    for line in blob.splitlines():
        if any(re.search(pat, line, re.I) for pat in CISCO_CONFIG_PATTERNS):
            config_lines.append(line.strip())
    return {
        "ip_candidates": ips,
        "mac_candidates": macs,
        "interface_candidates": interfaces,
        "vlan_candidates": vlan_candidates,
        "wireless_candidates": ssids[:60],
        "device_candidates": sorted(device_candidates)[:120],
        "config_like_lines": config_lines[:260],
    }


def inspect_native_pkt(raw: bytes, filename: str = "uploaded.pkt") -> Tuple[Dict[str, Any], str]:
    """Return a native inspection profile plus best-effort text for parsers."""
    sha256 = hashlib.sha256(raw).hexdigest()
    entropy = shannon_entropy(raw)
    ratio = printable_ratio(raw)
    strings = _dedupe_strings(recover_printable_strings(raw) + recover_unicode_strings(raw), limit=MAX_STRINGS)
    segments = recover_printable_segments(raw)
    signatures = _signature_hits(raw)
    zlib_chunks, zlib_texts = _try_zlib_chunks(raw)
    segment_texts = [s.get("text", "") for s in segments]
    reconstructed_config = reconstruct_cisco_config_text("\n".join(segment_texts + strings + zlib_texts))
    reconstructed_lines = [line for line in reconstructed_config.splitlines() if line.strip()]
    hints = _visible_hints(strings + zlib_texts + reconstructed_lines)
    config_pattern_hits = max(len(hints.get("config_like_lines") or []), len(reconstructed_lines))

    if config_pattern_hits >= 4 or zlib_texts:
        recoverability = "partial_config_recovery"
        # Confidence now scales with real recovered evidence instead of staying
        # fixed at 0.64. This keeps native PKT claims honest, but prevents
        # strong visible IOS exports embedded in a .pkt/.pka from being scored
        # as weak after the backend has already reconstructed meaningful data.
        if len(reconstructed_lines) >= 30 or len(zlib_texts) >= 3:
            confidence = 0.82
        elif len(reconstructed_lines) >= 12 or len(zlib_texts) >= 2:
            confidence = 0.74
        elif len(reconstructed_lines) >= 6 or zlib_texts:
            confidence = 0.68
        else:
            confidence = 0.60
        decision = "Recovered visible/decompressed network evidence; the automatic XML/JSON bridge will parse it in the background."
    elif entropy >= 7.2 and ratio < 0.45:
        recoverability = "opaque_native_binary"
        confidence = 0.34
        decision = "The file is high-entropy native Packet Tracer content. WiGuard will still run the XML/JSON bridge, but exact topology requires exported configs or a converter."
    else:
        recoverability = "low_visible_evidence"
        confidence = 0.44
        decision = "The file exposes limited visible strings. WiGuard will still generate XML/JSON artifacts from recoverable evidence."

    profile = {
        "filename": Path(filename or "uploaded.pkt").name,
        "extension": Path(filename or "").suffix.lower() or ".pkt",
        "bytes": len(raw),
        "sha256": sha256,
        "entropy": entropy,
        "printable_ratio": ratio,
        "native_packet_tracer": True,
        "recoverability": recoverability,
        "confidence": confidence,
        "decision": decision,
        "signature_hits": signatures,
        "zlib_chunks": zlib_chunks,
        "visible_string_count": len(strings),
        "printable_segment_count": len(segments),
        "string_preview": strings[:80],
        "printable_segments_preview": [
            {"offset": seg.get("offset"), "hex_offset": hex(int(seg.get("offset") or 0)), "bytes": seg.get("bytes"), "preview": re.sub(r"\s+", " ", seg.get("text", "")[:700]).strip()}
            for seg in segments[:40]
        ],
        "reconstructed_config_count": len(reconstructed_lines),
        "reconstructed_config_preview": reconstructed_lines[:120],
        "visible_hints": hints,
        "config_pattern_hits": config_pattern_hits,
        "action_plan": [
            "Upload the .pkt/.pka normally; WiGuard runs native inspection, XML bridge generation and JSON normalization automatically in the background.",
            "If accuracy is still low, export/copy show running-config, show ip interface brief, show vlan brief, show interfaces trunk, show cdp neighbors detail, show access-lists, show ip route, show spanning-tree, show port-security and show etherchannel summary into one ZIP.",
            "For highest fidelity, configure PTEXPLORER_PATH or another local converter so native Packet Tracer objects can be converted to XML before WiGuard normalizes them.",
        ],
    }

    synthetic_text = [
        "--- NATIVE_PACKET_TRACER_BINARY_INSPECTION ---",
        f"filename {profile['filename']}",
        f"sha256 {sha256}",
        f"bytes {len(raw)}",
        f"entropy {entropy}",
        f"printable_ratio {ratio}",
        f"recoverability {recoverability}",
        f"decision {decision}",
    ]
    if reconstructed_config:
        synthetic_text.append("\n--- RECONSTRUCTED_CISCO_CONFIG_FROM_NATIVE_PAYLOADS ---")
        synthetic_text.append(reconstructed_config)
    for line in hints.get("config_like_lines") or []:
        synthetic_text.append(line)
    for item in zlib_texts:
        synthetic_text.append(item)
    return profile, "\n".join(synthetic_text)


def _payload_kind(name: str, text: str) -> str:
    suffix = Path(name or "").suffix.lower()
    stripped = (text or "").lstrip()
    if suffix == ".json" or stripped.startswith("{") or stripped.startswith("["):
        return "json"
    if suffix == ".xml" or stripped.startswith("<?xml") or stripped.startswith("<"):
        return "xml"
    if suffix in {".cfg", ".conf", ".txt", ".log"} or any(re.search(pat, text or "", re.I) for pat in CISCO_CONFIG_PATTERNS):
        return "config_text"
    return "text"


def _payload_confidence(kind: str, text: str) -> float:
    hits = sum(1 for pat in CISCO_CONFIG_PATTERNS if re.search(pat, text or "", re.I))
    if kind in {"xml", "json"}:
        return 0.88 if hits else 0.76
    if hits:
        return min(0.90, 0.52 + (hits * 0.06))
    return 0.38


def _add_payload(payloads: List[Dict[str, Any]], name: str, source: str, text: str, offset: int | None = None) -> None:
    if not text:
        return
    clean = "".join(ch for ch in str(text) if ch in "\t\n\r" or ord(ch) >= 32).strip()
    if len(clean) < 12:
        return
    digest = hashlib.sha256(clean.encode("utf-8", errors="replace")).hexdigest()
    if any(p.get("sha256") == digest for p in payloads):
        return
    kind = _payload_kind(name, clean)
    payloads.append({
        "name": name or f"payload_{len(payloads)+1}",
        "source": source,
        "kind": kind,
        "offset": offset,
        "bytes": len(clean.encode("utf-8", errors="replace")),
        "sha256": digest,
        "confidence": _payload_confidence(kind, clean),
        "config_pattern_hits": sum(1 for pat in CISCO_CONFIG_PATTERNS if re.search(pat, clean, re.I)),
        "preview": re.sub(r"\s+", " ", clean[:800]).strip(),
        "content": clean[:MAX_PAYLOAD_TEXT],
    })



def _extract_embedded_zip_payloads(raw: bytes) -> List[Dict[str, Any]]:
    """Recover ZIP members even when a ZIP starts at a non-zero binary offset."""
    payloads: List[Dict[str, Any]] = []
    offsets: List[int] = []
    start = 0
    while True:
        idx = raw.find(b"PK\x03\x04", start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    for offset in offsets[:12]:
        if len(payloads) >= MAX_DECODED_PAYLOADS:
            break
        try:
            with zipfile.ZipFile(io.BytesIO(raw[offset:])) as zf:
                for info in zf.infolist()[:80]:
                    if info.is_dir() or info.file_size > 2_500_000:
                        continue
                    suffix = Path(info.filename).suffix.lower()
                    if suffix not in {".xml", ".json", ".txt", ".cfg", ".conf", ".log"}:
                        continue
                    data = zf.read(info.filename)
                    _add_payload(payloads, f"embedded@{hex(offset)}/{info.filename}", "embedded_zip_at_offset", data.decode("utf-8", errors="replace"), offset)
                    if len(payloads) >= MAX_DECODED_PAYLOADS:
                        break
        except Exception:
            continue
    return payloads[:MAX_DECODED_PAYLOADS]


def _extract_embedded_wrapped_stream_payloads(raw: bytes) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    signatures = [(b"\x1f\x8b", "embedded_gzip_stream", gzip.decompress), (b"BZh", "embedded_bzip2_stream", bz2.decompress), (b"\xfd7zXZ\x00", "embedded_xz_stream", lzma.decompress)]
    for marker, source, decoder in signatures:
        start = 0
        while True:
            idx = raw.find(marker, start)
            if idx == -1 or len(payloads) >= MAX_DECODED_PAYLOADS:
                break
            try:
                decoded = decoder(raw[idx:idx + MAX_DECOMPRESSED_BYTES * 6])
                if decoded and printable_ratio(decoded) >= 0.25:
                    _add_payload(payloads, f"{source}_{hex(idx)}.txt", source, decoded[:MAX_PAYLOAD_TEXT].decode("utf-8", errors="replace"), idx)
            except Exception:
                pass
            start = idx + 1
    return payloads[:MAX_DECODED_PAYLOADS]


def _extract_zlib_payloads(raw: bytes) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    offsets = [idx for idx, b in enumerate(raw[:-2]) if b == 0x78 and _valid_zlib_header(raw, idx)]
    for idx in sorted(set(offsets))[:120]:
        if len(payloads) >= MAX_DECODED_PAYLOADS:
            break
        try:
            data = zlib.decompressobj().decompress(raw[idx:], MAX_DECOMPRESSED_BYTES)
            if not data or len(data) < 32 or printable_ratio(data) < 0.22:
                continue
            text = data.decode("utf-8", errors="replace")
            reconstructed = reconstruct_cisco_config_text(text)
            _add_payload(payloads, f"zlib_payload_{hex(idx)}.cfg" if reconstructed else f"zlib_payload_{hex(idx)}.txt", "zlib_payload_recovery", reconstructed or text, idx)
        except Exception:
            continue
    return payloads[:MAX_DECODED_PAYLOADS]


def _extract_zip_payloads(raw: bytes) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    if not zipfile.is_zipfile(io.BytesIO(raw)):
        return payloads
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for info in zf.infolist()[:120]:
                if info.is_dir() or info.file_size > 2_500_000:
                    continue
                suffix = Path(info.filename).suffix.lower()
                if suffix not in {".xml", ".json", ".txt", ".cfg", ".conf", ".log"}:
                    continue
                try:
                    data = zf.read(info.filename)
                    _add_payload(payloads, info.filename, "embedded_zip_member", data.decode("utf-8", errors="replace"))
                except Exception:
                    continue
                if len(payloads) >= MAX_DECODED_PAYLOADS:
                    break
    except Exception:
        return payloads
    return payloads


def _extract_wrapped_stream_payloads(raw: bytes) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    wrappers = [
        ("gzip_stream", gzip.decompress),
        ("bzip2_stream", bz2.decompress),
        ("xz_stream", lzma.decompress),
    ]
    for source, decoder in wrappers:
        try:
            decoded = decoder(raw[:MAX_DECOMPRESSED_BYTES * 4])
            if decoded and printable_ratio(decoded) >= 0.25:
                _add_payload(payloads, source, source, decoded[:MAX_PAYLOAD_TEXT].decode("utf-8", errors="replace"))
        except Exception:
            continue
    return payloads


def _extract_embedded_xml_json_from_text(text: str) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    if not text:
        return payloads
    for idx, marker in enumerate(["<?xml", "<PacketTracer", "<packetTracer", "<logicalTopology", "<topology", "<network"]):
        start = text.find(marker)
        if start == -1:
            continue
        candidate = text[start:start + MAX_PAYLOAD_TEXT]
        end_positions = [candidate.rfind(tag) for tag in ["</PacketTracer>", "</packetTracer>", "</logicalTopology>", "</topology>", "</network>"]]
        end = max(end_positions)
        if end > 0:
            candidate = candidate[:end + 20]
        _add_payload(payloads, f"embedded_xml_{idx+1}.xml", "embedded_printable_xml", candidate, start)
        if len(payloads) >= 8:
            return payloads
    for m in re.finditer(r'(?i)"(?:devices|nodes|interfaces|connections|logicalTopology|topology)"', text):
        left = text.rfind("{", 0, m.start())
        if left == -1:
            continue
        depth = 0
        in_str = False
        esc = False
        for pos in range(left, min(len(text), left + MAX_PAYLOAD_TEXT)):
            ch = text[pos]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[left:pos + 1]
                    try:
                        json.loads(candidate)
                    except Exception:
                        break
                    _add_payload(payloads, f"embedded_json_{len(payloads)+1}.json", "embedded_printable_json", candidate, left)
                    break
        if len(payloads) >= MAX_DECODED_PAYLOADS:
            break
    return payloads





def _extract_utf16_text_payloads(raw: bytes) -> List[Dict[str, Any]]:
    """Promote UTF-16 Packet Tracer evidence into parseable text payloads.

    Some PT builds and third-party converters store labels/config fragments as
    UTF-16. Earlier versions only used these strings as hints; v5.9.8 also feeds
    reconstructed UTF-16 configs into the normal object parser.
    """
    payloads: List[Dict[str, Any]] = []
    for encoding in ("utf-16le", "utf-16be"):
        try:
            decoded = raw.decode(encoding, errors="ignore")
        except Exception:
            continue
        if not decoded or printable_ratio(decoded.encode("utf-8", errors="replace")) < 0.18:
            continue
        reconstructed = reconstruct_cisco_config_text(decoded)
        hits = sum(1 for pat in CISCO_CONFIG_PATTERNS if re.search(pat, decoded, re.I))
        if reconstructed:
            _add_payload(payloads, f"native_{encoding}_reconstructed_config.cfg", f"{encoding}_reconstruction", reconstructed)
        elif hits:
            _add_payload(payloads, f"native_{encoding}_visible_text.txt", f"{encoding}_visible_text", decoded[:MAX_PAYLOAD_TEXT])
        for item in _extract_embedded_xml_json_from_text(decoded[:MAX_PAYLOAD_TEXT]):
            _add_payload(payloads, item.get("name", f"{encoding}_embedded_payload"), f"{encoding}_{item.get('source', 'embedded')}", item.get("content", ""), item.get("offset"))
        if len(payloads) >= MAX_DECODED_PAYLOADS:
            break
    return payloads[:MAX_DECODED_PAYLOADS]


def _extract_printable_segment_payloads(raw: bytes) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    for idx, seg in enumerate(recover_printable_segments(raw, min_len=48, max_segments=80), start=1):
        text = seg.get("text", "")
        reconstructed = reconstruct_cisco_config_text(text)
        hits = sum(1 for pat in CISCO_CONFIG_PATTERNS if re.search(pat, text, re.I))
        if reconstructed:
            _add_payload(payloads, f"native_reconstructed_config_{idx}.cfg", "printable_segment_reconstruction", reconstructed, seg.get("offset"))
        elif hits:
            _add_payload(payloads, f"native_printable_segment_{idx}.txt", "printable_segment", text, seg.get("offset"))
        for item in _extract_embedded_xml_json_from_text(text):
            _add_payload(payloads, item.get("name", f"embedded_segment_{idx}"), item.get("source", "embedded_printable_segment"), item.get("content", ""), item.get("offset") or seg.get("offset"))
        if len(payloads) >= MAX_DECODED_PAYLOADS:
            break
    return payloads[:MAX_DECODED_PAYLOADS]

def _conversion_pipeline(attempts: List[Dict[str, Any]], profile: Dict[str, Any], payloads: List[Dict[str, Any]], bridge_xml: str | None = None, bridge_json: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    visible = profile.get("visible_hints", {}) or {}
    counts = {
        "ip_candidates": len(visible.get("ip_candidates", []) or []),
        "mac_candidates": len(visible.get("mac_candidates", []) or []),
        "interface_candidates": len(visible.get("interface_candidates", []) or []),
        "config_lines": len(visible.get("config_like_lines", []) or []),
        "reconstructed_config_lines": int(profile.get("reconstructed_config_count") or 0),
        "payloads": len(payloads or []),
    }
    external_ok = any(a.get("status") == "success" and a.get("tool") == "external_converter" for a in attempts)
    return [
        {"stage": "Native Packet Tracer intake", "status": "success", "detail": "Stored source file and calculated immutable hash.", "items": 1, "confidence": 1.0},
        {"stage": "External converter probe", "status": "success" if external_ok else "skipped", "detail": "PTEXPLORER_PATH/native converter used when available; otherwise internal bridge continues automatically.", "items": sum(1 for a in attempts if a.get("tool") == "external_converter"), "confidence": 0.95 if external_ok else 0.35},
        {"stage": "Container and compression recovery", "status": "success" if payloads else "review", "detail": "Probed ZIP members, wrapped streams, zlib chunks, embedded XML, embedded JSON and printable Cisco evidence.", "items": len(payloads or []), "confidence": max([float(p.get("confidence", 0.35) or 0.35) for p in payloads], default=0.42)},
        {"stage": "Internal XML bridge generation", "status": "success" if bridge_xml else "review", "detail": "Converted all recoverable evidence into a deterministic XML bridge.", "items": len((bridge_xml or "").splitlines()), "confidence": 0.78 if bridge_xml else 0.42},
        {"stage": "Normalized JSON generation", "status": "success" if bridge_json else "review", "detail": "Produced normalized JSON from the XML bridge for UI, artifacts, and report generation.", "items": len((bridge_json or {}).keys()) if isinstance(bridge_json, dict) else 0, "confidence": 0.82 if bridge_json else 0.42},
        {"stage": "Visible evidence understanding", "status": "success" if sum(counts.values()) else "limited", "detail": f"Recovered counts: {counts}.", "items": sum(counts.values()), "confidence": float(profile.get("confidence", 0.42) or 0.42)},
    ]


def _xml_safe_text(value: Any, limit: int | None = None) -> str:
    text = "" if value is None else str(value)
    if limit is not None:
        text = text[:limit]
    return "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 32)


def _add_text(parent: ET.Element, tag: str, value: Any, **attrs: Any) -> ET.Element:
    elem = ET.SubElement(parent, tag, {str(k): _xml_safe_text(v, 240) for k, v in attrs.items() if v is not None})
    elem.text = _xml_safe_text(value, 120_000)
    return elem


def build_internal_pkt_xml_bridge(raw: bytes, filename: str, profile: Dict[str, Any], recovered_text: str, decoded_payloads: List[Dict[str, Any]] | None = None) -> Tuple[str, Dict[str, Any]]:
    """Build a deterministic XML bridge + normalized JSON from visible evidence."""
    decoded_payloads = decoded_payloads or []
    visible = profile.get("visible_hints", {}) or {}
    root = ET.Element("packetTracerInternalBridge", {
        "source": "native_pkt_auto_xml_json_bridge",
        "fidelity": "best_effort_visible_and_decoded_payloads",
        "filename": Path(filename or "uploaded.pkt").name,
    })

    meta = ET.SubElement(root, "metadata")
    for key in ["filename", "extension", "bytes", "sha256", "entropy", "printable_ratio", "recoverability", "confidence", "decision", "decoded_payload_count", "printable_segment_count", "reconstructed_config_count"]:
        _add_text(meta, key, profile.get(key))

    pipeline_elem = ET.SubElement(root, "conversionPipeline")
    for idx, stage in enumerate(profile.get("conversion_pipeline", []) or [], start=1):
        node = ET.SubElement(pipeline_elem, "stage", {"index": str(idx), "status": _xml_safe_text(stage.get("status"), 80)})
        for key in ["stage", "detail", "items", "confidence"]:
            _add_text(node, key, stage.get(key))

    inspection = ET.SubElement(root, "inspection")
    signatures = ET.SubElement(inspection, "signatures")
    for sig in profile.get("signature_hits", []) or []:
        ET.SubElement(signatures, "signature", {str(k): _xml_safe_text(v, 400) for k, v in sig.items() if v is not None})
    zlib_chunks = ET.SubElement(inspection, "zlibChunks")
    for chunk in profile.get("zlib_chunks", []) or []:
        elem = ET.SubElement(zlib_chunks, "zlibChunk", {k: _xml_safe_text(chunk.get(k), 240) for k in ["offset", "hex_offset", "bytes", "printable_ratio", "config_pattern_hits"] if chunk.get(k) is not None})
        _add_text(elem, "preview", chunk.get("preview", ""))

    devices_elem = ET.SubElement(root, "devices")
    for dev in visible.get("device_candidates", []) or []:
        node = ET.SubElement(devices_elem, "device")
        _add_text(node, "hostname", dev)
        _add_text(node, "type", "device")
        _add_text(node, "source", "native_visible_device_candidate")

    endpoints = ET.SubElement(root, "endpointInventory")
    for ip in visible.get("ip_candidates", []) or []:
        node = ET.SubElement(endpoints, "endpoint")
        _add_text(node, "ipAddress", ip)
        _add_text(node, "source", "native_visible_ip_candidate")
    mac_inventory = ET.SubElement(root, "macInventory")
    for mac in visible.get("mac_candidates", []) or []:
        node = ET.SubElement(mac_inventory, "macEntry")
        _add_text(node, "macAddress", mac)
        _add_text(node, "source", "native_visible_mac_candidate")
    interfaces = ET.SubElement(root, "interfaces")
    for iface in visible.get("interface_candidates", []) or []:
        node = ET.SubElement(interfaces, "interface")
        _add_text(node, "name", iface)
        _add_text(node, "source", "native_visible_interface_candidate")
    vlans_elem = ET.SubElement(root, "vlans")
    for vlan_id in visible.get("vlan_candidates", []) or []:
        node = ET.SubElement(vlans_elem, "vlan")
        _add_text(node, "id", vlan_id)
        _add_text(node, "source", "native_visible_vlan_candidate")

    wireless = ET.SubElement(root, "wirelessHints")
    for item in visible.get("wireless_candidates", []) or []:
        node = ET.SubElement(wireless, "wireless")
        _add_text(node, "ssid", item)
        _add_text(node, "source", "native_visible_wireless_candidate")

    cfg = ET.SubElement(root, "embeddedConfigs")
    config_lines = visible.get("config_like_lines", []) or []
    reconstructed_lines = profile.get("reconstructed_config_preview", []) or []
    if config_lines:
        _add_text(cfg, "runningConfig", "\n".join(config_lines), type="visible_config_like_lines")
    if reconstructed_lines:
        _add_text(cfg, "reconstructedConfig", "\n".join(reconstructed_lines), type="native_reconstructed_ios_lines")
    if recovered_text:
        _add_text(cfg, "recoveredText", recovered_text, type="native_inspection_text")

    payloads_elem = ET.SubElement(root, "decodedPayloads")
    for idx, payload in enumerate(decoded_payloads[:MAX_DECODED_PAYLOADS], start=1):
        node = ET.SubElement(payloads_elem, "payload", {
            "index": str(idx),
            "name": _xml_safe_text(payload.get("name"), 240),
            "source": _xml_safe_text(payload.get("source"), 240),
            "kind": _xml_safe_text(payload.get("kind"), 60),
            "confidence": _xml_safe_text(payload.get("confidence"), 60),
            "bytes": _xml_safe_text(payload.get("bytes"), 60),
            "configPatternHits": _xml_safe_text(payload.get("config_pattern_hits"), 60),
        })
        _add_text(node, "preview", payload.get("preview", ""))
        _add_text(node, "content", payload.get("content", ""), type=payload.get("kind"))

    strings_elem = ET.SubElement(root, "recoveredStrings")
    for idx, value in enumerate(profile.get("string_preview", []) or [], start=1):
        _add_text(strings_elem, "string", value, index=idx)

    xml_text = ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8", errors="replace")
    normalized = {
        "bridge": {
            "source": "native_pkt_auto_xml_json_bridge",
            "fidelity": "best_effort_visible_and_decoded_payloads",
            "filename": Path(filename or "uploaded.pkt").name,
            "note": "Internal XML bridge generated automatically from native Packet Tracer evidence; exact proprietary object fidelity depends on embedded/exported data or converter output.",
        },
        "metadata": {k: profile.get(k) for k in ["filename", "extension", "bytes", "sha256", "entropy", "printable_ratio", "recoverability", "confidence", "decision", "decoded_payload_count", "printable_segment_count", "reconstructed_config_count"]},
        "counts": {
            "device_candidates": len(visible.get("device_candidates", []) or []),
            "ip_candidates": len(visible.get("ip_candidates", []) or []),
            "mac_candidates": len(visible.get("mac_candidates", []) or []),
            "interface_candidates": len(visible.get("interface_candidates", []) or []),
            "vlan_candidates": len(visible.get("vlan_candidates", []) or []),
            "wireless_candidates": len(visible.get("wireless_candidates", []) or []),
            "config_like_lines": len(config_lines),
            "signatures": len(profile.get("signature_hits", []) or []),
            "zlib_chunks": len(profile.get("zlib_chunks", []) or []),
            "strings": len(profile.get("string_preview", []) or []),
            "printable_segments": int(profile.get("printable_segment_count") or 0),
            "reconstructed_config_lines": int(profile.get("reconstructed_config_count") or 0),
            "decoded_payloads": len(decoded_payloads),
        },
        "visible_hints": visible,
        "reconstructed_config": profile.get("reconstructed_config_preview", []) or [],
        "extraction_fidelity": [_safe_status_for_fidelity(profile, decoded_payloads)],
        "decoded_payloads": [dict(p, content=p.get("content", "")[:5000]) for p in decoded_payloads[:MAX_DECODED_PAYLOADS]],
        "signature_hits": profile.get("signature_hits", []) or [],
        "zlib_chunks": profile.get("zlib_chunks", []) or [],
    }
    return xml_text, normalized


def run_native_pkt_auto_pipeline(raw: bytes, filename: str = "uploaded.pkt", external_xml: str | None = None, attempts: List[Dict[str, Any]] | None = None) -> Tuple[Dict[str, Any], str, str, Dict[str, Any]]:
    """Force native PKT/PKA through automatic XML and JSON conversion stages."""
    attempts = list(attempts or [])
    profile, native_text = inspect_native_pkt(raw, filename)
    payloads: List[Dict[str, Any]] = []

    if external_xml:
        _add_payload(payloads, f"{Path(filename).stem}_external_converter.xml", "external_converter", external_xml)
    for source_payloads in (_extract_zip_payloads(raw), _extract_embedded_zip_payloads(raw), _extract_wrapped_stream_payloads(raw), _extract_embedded_wrapped_stream_payloads(raw), _extract_zlib_payloads(raw), _extract_utf16_text_payloads(raw), _extract_printable_segment_payloads(raw)):
        for item in source_payloads:
            _add_payload(payloads, item.get("name", "payload"), item.get("source", "decoded"), item.get("content", ""), item.get("offset"))
    for chunk in profile.get("zlib_chunks", []) or []:
        preview = chunk.get("preview", "")
        if preview:
            _add_payload(payloads, f"zlib_chunk_{chunk.get('hex_offset','unknown')}.txt", "zlib_decompressed_stream", preview, chunk.get("offset"))
    printable_blob = "\n".join(profile.get("string_preview", []) or [])
    for item in _extract_embedded_xml_json_from_text(printable_blob + "\n" + native_text):
        _add_payload(payloads, item.get("name", "embedded_payload"), item.get("source", "embedded_printable"), item.get("content", ""), item.get("offset"))
    reconstructed = "\n".join(profile.get("reconstructed_config_preview", []) or [])
    if reconstructed:
        _add_payload(payloads, "native_reconstructed_ios_config.cfg", "native_command_reconstruction", reconstructed)
    if native_text:
        _add_payload(payloads, "native_visible_evidence.txt", "native_string_and_zlib_recovery", native_text)

    profile["decoded_payloads"] = [dict(p, content=None) for p in payloads[:MAX_DECODED_PAYLOADS]]
    profile["decoded_payload_count"] = len(payloads)
    profile["extraction_fidelity"] = _safe_status_for_fidelity(profile, payloads)
    profile["auto_converter"] = True
    bridge_xml, bridge_json = build_internal_pkt_xml_bridge(raw, filename, profile, native_text, decoded_payloads=payloads)
    bridge_json["conversion_pipeline"] = _conversion_pipeline(attempts, profile, payloads, bridge_xml, bridge_json)
    bridge_json["decoded_payloads"] = [dict(p, content=p.get("content", "")[:5000]) for p in payloads[:MAX_DECODED_PAYLOADS]]
    profile["conversion_pipeline"] = bridge_json["conversion_pipeline"]
    # Rebuild once so the XML preview itself includes final pipeline stages.
    bridge_xml, bridge_json = build_internal_pkt_xml_bridge(raw, filename, profile, native_text, decoded_payloads=payloads)
    bridge_json["conversion_pipeline"] = profile["conversion_pipeline"]
    bridge_json["decoded_payloads"] = [dict(p, content=p.get("content", "")[:5000]) for p in payloads[:MAX_DECODED_PAYLOADS]]
    combined_text = "\n\n".join([native_text] + [p.get("content", "") for p in payloads])
    return profile, combined_text, bridge_xml, bridge_json


def normalized_json_preview(data: Dict[str, Any], limit: int = 16_000) -> str:
    text = json.dumps(data or {}, ensure_ascii=False, indent=2, default=str)
    return text[:limit]
