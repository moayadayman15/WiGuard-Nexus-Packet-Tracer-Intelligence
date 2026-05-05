"""Shared state-shape helpers for WiGuard Nexus.

The app stores most workspace data in JSON during local/demo deployments.  Older
builds normalized that JSON in several different places, which made UI bugs easy
to reintroduce: a route could remember to create projects while another route
forgot tenants, imports, or active extraction defaults.  This module is the
single schema-normalization layer used by app boot, page contexts, and tests.
"""
from __future__ import annotations

from typing import Any, Dict, MutableMapping, Optional

DEFAULT_TENANT_ID = "tenant-main"
DEFAULT_PROJECT_ID = "main-campus"
DEFAULT_WORKFLOW = ["Tenant", "Project", "Upload", "Convert", "Validate", "Analyze", "Report"]
DEFAULT_TAGLINE = "Wireless and wired policy evidence intelligence workspace"


LIST_KEYS = (
    "projects",
    "imports",
    "events",
    "simulations",
    "tenants",
    "ap_inventory",
    "clients",
    "client_sessions",
    "audit_log",
)

DICT_KEYS = (
    "meta",
    "active_extraction",
    "wireless_policy",
    "settings",
)


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def ensure_state_shape(
    state: Optional[MutableMapping[str, Any]],
    *,
    tenant_id: Optional[str] = None,
    version: Optional[str] = None,
    product: Optional[str] = None,
    tagline: str = DEFAULT_TAGLINE,
) -> Dict[str, Any]:
    """Return a normalized, UI-safe state dictionary.

    The function is intentionally conservative: it never deletes unknown keys and
    only fills missing/invalid top-level containers.  That keeps backwards
    compatibility with previous project snapshots while preventing blank pages
    caused by missing JSON sections.
    """
    if not isinstance(state, MutableMapping):
        state = {}

    normalized: Dict[str, Any] = dict(state)
    resolved_tenant = tenant_id or normalized.get("tenant_id") or DEFAULT_TENANT_ID
    normalized["tenant_id"] = resolved_tenant

    if version:
        normalized["version"] = version
    else:
        normalized.setdefault("version", "development")

    for key in LIST_KEYS:
        normalized[key] = _as_list(normalized.get(key))
    for key in DICT_KEYS:
        normalized[key] = _as_dict(normalized.get(key))

    meta = normalized["meta"]
    meta.setdefault("product", product or "WiGuard Nexus")
    meta.setdefault("tagline", tagline)
    meta.setdefault("workflow", list(DEFAULT_WORKFLOW))

    if not any(isinstance(t, dict) and t.get("id") == resolved_tenant for t in normalized["tenants"]):
        normalized["tenants"].insert(0, {"id": resolved_tenant, "name": "Main Tenant", "status": "active"})

    if not normalized["projects"]:
        normalized["projects"].append({
            "id": DEFAULT_PROJECT_ID,
            "tenant_id": resolved_tenant,
            "name": "Main Campus Lab",
            "environment": "Wireless Campus Policy Validation",
            "owner": "Network Security Team",
            "status": "active",
        })

    for project in normalized["projects"]:
        if isinstance(project, dict):
            project.setdefault("tenant_id", resolved_tenant)
            project.setdefault("name", project.get("id") or "Workspace")
            project.setdefault("status", "active")

    current_project = normalized.get("current_project")
    if not current_project:
        first_project = next((p for p in normalized["projects"] if isinstance(p, dict)), {})
        normalized["current_project"] = first_project.get("id") or DEFAULT_PROJECT_ID

    active = normalized["active_extraction"]
    active.setdefault("tenant_id", resolved_tenant)
    active.setdefault("objects", {})
    active.setdefault("pipeline", [])

    return normalized


def tenant_scoped_copy(state: MutableMapping[str, Any], tenant_id: str) -> Dict[str, Any]:
    """Build a copy that hides records from other tenants without mutating input."""
    scoped = ensure_state_shape(state, tenant_id=tenant_id)
    scoped = dict(scoped)
    for key in ("projects", "imports", "events", "simulations"):
        rows = scoped.get(key)
        if isinstance(rows, list):
            scoped[key] = [row for row in rows if not isinstance(row, dict) or row.get("tenant_id", tenant_id) == tenant_id]
    active = scoped.get("active_extraction") or {}
    if active and active.get("tenant_id", tenant_id) != tenant_id:
        scoped["active_extraction"] = {"tenant_id": tenant_id, "objects": {}, "pipeline": []}
    return scoped
