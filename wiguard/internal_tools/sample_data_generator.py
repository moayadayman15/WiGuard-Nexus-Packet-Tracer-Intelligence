"""Generate safe demo network evidence for live presentations.

Usage:
  python -m wiguard.internal_tools.sample_data_generator
"""
from __future__ import annotations

from pathlib import Path

DEMO_CFG = """! DEMO DATA ONLY - not real customer evidence
hostname Demo-Core-SW1
ip routing
vlan 10
 name STAFF
vlan 20
 name STUDENTS
vlan 99
 name MGMT
interface GigabitEthernet1/0/1
 description uplink-to-router
 switchport mode trunk
 switchport trunk allowed vlan 10,20,99
interface GigabitEthernet1/0/10
 description staff-workstation
 switchport mode access
 switchport access vlan 10
interface Vlan99
 ip address 10.99.0.2 255.255.255.0
ip access-list extended GUEST-DENY-INTERNAL
 deny ip 10.20.0.0 0.0.0.255 10.10.0.0 0.0.0.255
 permit ip any any
! secret intentionally fake for demo detection
username demo privilege 1 secret demo-not-real-change-me
"""


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    out = root / "data" / "samples" / "professional_demo_network.cfg"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(DEMO_CFG, encoding="utf-8")
    print(f"Generated safe demo evidence: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
