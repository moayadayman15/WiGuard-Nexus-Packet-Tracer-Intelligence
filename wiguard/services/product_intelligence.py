"""Product upgrade intelligence for WiGuard Nexus v5.14.

This module is intentionally safe-by-default: optional AI/network packages are
only detected, never required at runtime. The UI can therefore show a serious
product roadmap and enablement status without breaking the student/demo install.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from importlib.util import find_spec
from typing import Any, Dict, Iterable, List, Tuple


OPTIONAL_STACK = [
    {
        "name": "NetworkX",
        "import_name": "networkx",
        "package": "networkx",
        "group": "Topology Brain",
        "priority": "P0",
        "weight": 18,
        "impact": "graph analytics, central nodes, isolated segments, and blast-radius scoring",
    },
    {
        "name": "TextFSM",
        "import_name": "textfsm",
        "package": "textfsm",
        "group": "Cisco Parser",
        "priority": "P0",
        "weight": 12,
        "impact": "structured parsing for show-command outputs instead of brittle text matching",
    },
    {
        "name": "NTC Templates",
        "import_name": "ntc_templates",
        "package": "ntc-templates",
        "group": "Cisco Parser",
        "priority": "P0",
        "weight": 12,
        "impact": "ready-made templates for VLANs, trunks, routes, CDP, interfaces, and security outputs",
    },
    {
        "name": "Scapy",
        "import_name": "scapy",
        "package": "scapy",
        "group": "PCAP Intelligence",
        "priority": "P1",
        "weight": 9,
        "impact": "offline packet/PCAP intelligence for ARP, DNS, DHCP, cleartext, VLAN tags, and suspicious ports",
    },
    {
        "name": "Sentence Transformers",
        "import_name": "sentence_transformers",
        "package": "sentence-transformers",
        "group": "AI Search / RAG",
        "priority": "P1",
        "weight": 10,
        "impact": "semantic search inside configs, imports, evidence rows, and reports",
    },
    {
        "name": "ChromaDB",
        "import_name": "chromadb",
        "package": "chromadb",
        "group": "AI Search / RAG",
        "priority": "P1",
        "weight": 8,
        "impact": "local vector database for searchable evidence knowledge base",
    },
    {
        "name": "FAISS CPU",
        "import_name": "faiss",
        "package": "faiss-cpu",
        "group": "AI Search / RAG",
        "priority": "P2",
        "weight": 6,
        "impact": "fast local similarity search for larger evidence corpora",
    },
    {
        "name": "Ollama Python",
        "import_name": "ollama",
        "package": "ollama",
        "group": "Local AI Copilot",
        "priority": "P1",
        "weight": 9,
        "impact": "privacy-friendly local AI explanations and executive/technical report drafting",
    },
    {
        "name": "PyBatfish",
        "import_name": "pybatfish",
        "package": "pybatfish",
        "group": "Network Simulation",
        "priority": "P2",
        "weight": 6,
        "impact": "configuration validation, reachability questions, policy checks, and route analysis",
    },
    {
        "name": "Netmiko",
        "import_name": "netmiko",
        "package": "netmiko",
        "group": "Live Network Connectors",
        "priority": "P2",
        "weight": 5,
        "impact": "optional SSH collection from real routers and switches",
    },
    {
        "name": "NAPALM",
        "import_name": "napalm",
        "package": "napalm",
        "group": "Live Network Connectors",
        "priority": "P2",
        "weight": 5,
        "impact": "multi-vendor config/state collection through a unified API",
    },
    {
        "name": "Nornir",
        "import_name": "nornir",
        "package": "nornir",
        "group": "Live Network Connectors",
        "priority": "P2",
        "weight": 4,
        "impact": "inventory-driven network automation for larger labs and enterprise demos",
    },
]


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _installed(import_name: str) -> bool:
    try:
        return find_spec(import_name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def dependency_health() -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    groups: Dict[str, Dict[str, Any]] = {}
    installed_weight = 0
    total_weight = 0
    for item in OPTIONAL_STACK:
        ok = _installed(item["import_name"])
        total_weight += int(item["weight"])
        if ok:
            installed_weight += int(item["weight"])
        row = dict(item)
        row["installed"] = ok
        row["status"] = "installed" if ok else "optional"
        rows.append(row)
        group = groups.setdefault(item["group"], {"name": item["group"], "installed": 0, "total": 0, "rows": []})
        group["installed"] += 1 if ok else 0
        group["total"] += 1
        group["rows"].append(row)
    score = round((installed_weight / total_weight) * 100) if total_weight else 0
    missing = [r for r in rows if not r["installed"]]
    installed = [r for r in rows if r["installed"]]
    quick_p0 = [r["package"] for r in missing if r["priority"] == "P0"]
    quick_p1 = [r["package"] for r in missing if r["priority"] in {"P0", "P1"}]
    full = [r["package"] for r in missing]
    return {
        "score": score,
        "grade": "Product-ready" if score >= 70 else "Strong core" if score >= 35 else "Core install",
        "installed_count": len(installed),
        "missing_count": len(missing),
        "total_count": len(rows),
        "rows": rows,
        "groups": list(groups.values()),
        "missing": missing,
        "installed": installed,
        "commands": {
            "p0": "pip install " + " ".join(quick_p0) if quick_p0 else "P0 stack already installed",
            "p1": "pip install " + " ".join(quick_p1) if quick_p1 else "P0/P1 stack already installed",
            "full": "pip install -r requirements-full.txt" if full else "Full optional stack already installed",
        },
    }


def _topology_graph(state: Dict[str, Any]) -> Dict[str, Any]:
    # Import lazily to avoid circular import at module import time.
    from .intelligence import build_topology

    topo = build_topology(state)
    nodes = [n for n in _safe_list(topo.get("nodes")) if isinstance(n, dict)]
    edges = [e for e in _safe_list(topo.get("edges")) if isinstance(e, dict)]
    return {"nodes": nodes, "edges": edges}


def _fallback_components(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Tuple[List[List[str]], Dict[str, int]]:
    ids = [str(n.get("id")) for n in nodes if n.get("id") is not None]
    adjacency: Dict[str, set] = {i: set() for i in ids}
    degree: Dict[str, int] = {i: 0 for i in ids}
    for edge in edges:
        a = str(edge.get("from") or "")
        b = str(edge.get("to") or "")
        if not a or not b:
            continue
        adjacency.setdefault(a, set()).add(b)
        adjacency.setdefault(b, set()).add(a)
        degree[a] = degree.get(a, 0) + 1
        degree[b] = degree.get(b, 0) + 1
    seen = set()
    components: List[List[str]] = []
    for node_id in adjacency:
        if node_id in seen:
            continue
        queue = deque([node_id])
        seen.add(node_id)
        comp: List[str] = []
        while queue:
            cur = queue.popleft()
            comp.append(cur)
            for nxt in adjacency.get(cur, set()):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        components.append(comp)
    return components, degree


def topology_brain(state: Dict[str, Any]) -> Dict[str, Any]:
    topo = _topology_graph(state)
    nodes = topo["nodes"]
    edges = topo["edges"]
    node_by_id = {str(n.get("id")): n for n in nodes if n.get("id") is not None}
    type_counts = Counter(str(n.get("type") or "unknown").lower() for n in nodes)
    confirmed_edges = [e for e in edges if str(e.get("status") or "").lower() in {"confirmed", "enforced", "expected", "pass"}]
    review_edges = [e for e in edges if e not in confirmed_edges]

    components: List[List[str]] = []
    degree: Dict[str, int] = {}
    backend = "builtin"
    if _installed("networkx"):
        try:
            import networkx as nx  # type: ignore
            graph = nx.Graph()
            for node in nodes:
                if node.get("id") is not None:
                    graph.add_node(str(node.get("id")))
            for edge in edges:
                a = edge.get("from")
                b = edge.get("to")
                if a is not None and b is not None:
                    graph.add_edge(str(a), str(b))
            components = [list(c) for c in nx.connected_components(graph)]
            degree = dict(graph.degree())
            backend = "networkx"
        except Exception:
            components, degree = _fallback_components(nodes, edges)
    else:
        components, degree = _fallback_components(nodes, edges)

    isolated = [node_by_id.get(i, {"id": i, "label": i}) for i, d in degree.items() if d == 0]
    critical = []
    for node_id, d in sorted(degree.items(), key=lambda x: x[1], reverse=True):
        if len(critical) >= 8:
            break
        n = node_by_id.get(node_id, {"id": node_id, "label": node_id, "type": "unknown"})
        if d >= 2 or str(n.get("type") or "").lower() in {"router", "switch", "network", "interface", "vlan"}:
            critical.append({
                "id": node_id,
                "label": n.get("label") or node_id,
                "type": n.get("type") or "unknown",
                "degree": d,
                "reason": "high fan-out / likely blast-radius pivot" if d >= 3 else "core path candidate",
            })
    density = round((len(edges) / max(1, len(nodes))) * 100)
    confidence_avg = round((sum(float(e.get("confidence") or 0) for e in edges) / max(1, len(edges))) * 100)
    health = max(0, min(100, round(
        30 + min(35, len(confirmed_edges) * 5) + min(20, len(nodes) * 1.4) - min(25, len(isolated) * 6) - min(15, len(review_edges) * 1.2)
    )))
    return {
        "backend": backend,
        "nodes": len(nodes),
        "edges": len(edges),
        "confirmed_edges": len(confirmed_edges),
        "review_edges": len(review_edges),
        "components": len(components),
        "largest_component": max((len(c) for c in components), default=0),
        "isolated": isolated[:10],
        "critical_nodes": critical,
        "type_counts": dict(type_counts),
        "density_score": min(100, density),
        "confidence_avg": confidence_avg,
        "health_score": health,
        "headline": "Graph is evidence-linked" if confirmed_edges else "Graph needs stronger show-command evidence",
        "recommendations": _topology_recommendations(nodes, edges, isolated, review_edges),
    }


def _topology_recommendations(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], isolated: List[Dict[str, Any]], review_edges: List[Dict[str, Any]]) -> List[str]:
    recs = []
    node_types = {str(n.get("type") or "").lower() for n in nodes}
    if isolated:
        recs.append("Import CDP/LLDP and interface status outputs to connect isolated nodes to real links.")
    if review_edges:
        recs.append("Add line-level evidence for review/inferred edges before claiming full topology fidelity.")
    if "dhcp" not in node_types:
        recs.append("Upload DHCP pool/default-router outputs to validate gateway-to-VLAN correctness.")
    if "acl" not in node_types:
        recs.append("Upload ACL and interface access-group evidence to strengthen security path analysis.")
    if not edges:
        recs.append("Start with running-config or exported Packet Tracer text; then add show vlan brief and show interfaces trunk.")
    return recs[:5]


def ai_copilot_pack(state: Dict[str, Any]) -> Dict[str, Any]:
    from .intelligence import build_policy_diff, build_root_causes, build_extraction_diagnostics, risk_score

    diffs = build_policy_diff(state)
    causes = build_root_causes(state)
    diagnostics = build_extraction_diagnostics(state)
    risk = risk_score(state)
    severity_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    top_findings = sorted(diffs, key=lambda d: severity_rank.get(str(d.get("severity")), 0), reverse=True)[:5]
    prompts = [
        "Explain the top 3 root causes in executive language.",
        "Generate a remediation plan grouped by owner and severity.",
        "Find evidence gaps that block a final technical report.",
        "Summarize the blast radius if a guest VLAN is misconfigured.",
    ]
    local_ready = _installed("ollama")
    rag_ready = _installed("sentence_transformers") and (_installed("chromadb") or _installed("faiss"))
    return {
        "mode": "Local AI ready" if local_ready else "AI blueprint ready",
        "local_ready": local_ready,
        "rag_ready": rag_ready,
        "risk": risk,
        "top_findings": top_findings,
        "root_causes": causes[:5],
        "diagnostic_blockers": _safe_list(diagnostics.get("blockers"))[:5],
        "suggested_prompts": prompts,
        "copilot_message": _copilot_message(risk, top_findings, causes),
    }


def _copilot_message(risk: Dict[str, Any], findings: Iterable[Dict[str, Any]], causes: Iterable[Dict[str, Any]]) -> str:
    findings = list(findings)
    causes = list(causes)
    if findings:
        top = findings[0]
        return f"Highest priority is {top.get('id')} on {top.get('asset')} ({top.get('severity')}). Focus on evidence, path impact, and the suggested fix before exporting."
    if causes:
        return "Root-cause engine has hypotheses; verify source evidence and re-import after remediation."
    return f"Current risk score is {risk.get('score', 0)}. Import more topology/security evidence to unlock deeper AI guidance."


def build_product_intelligence(state: Dict[str, Any]) -> Dict[str, Any]:
    deps = dependency_health()
    graph = topology_brain(state)
    ai = ai_copilot_pack(state)
    maturity = round((deps["score"] * 0.30) + (graph["health_score"] * 0.40) + (35 if ai["local_ready"] else 18) + (15 if ai["rag_ready"] else 6))
    maturity = max(0, min(100, maturity))
    gates = [
        {"title": "Topology Brain", "status": "ready" if graph["nodes"] else "waiting", "detail": f"{graph['nodes']} nodes · {graph['edges']} edges · backend {graph['backend']}"},
        {"title": "Optional Stack", "status": "ready" if deps["score"] >= 45 else "optional", "detail": f"{deps['installed_count']}/{deps['total_count']} product libraries installed"},
        {"title": "AI Copilot", "status": "ready" if ai["local_ready"] else "blueprint", "detail": ai["mode"]},
        {"title": "RAG Evidence Search", "status": "ready" if ai["rag_ready"] else "optional", "detail": "semantic evidence search" if ai["rag_ready"] else "install sentence-transformers + chromadb/faiss"},
    ]
    feature_cards = [
        {"title": "Topology Brain", "tag": "P0", "body": "Graph analytics, critical nodes, isolated assets, and topology health scoring are now surfaced in the UI."},
        {"title": "AI Root Cause v2", "tag": "P1", "body": "Findings, root causes, blockers, and next actions are packaged for a local AI copilot workflow."},
        {"title": "Optional Stack Center", "tag": "P0", "body": "The product shows exactly which libraries are installed and which command unlocks each capability."},
        {"title": "Product Maturity Gate", "tag": "P1", "body": "A single score summarizes code/product readiness from dependencies, topology, AI, and evidence quality."},
    ]
    return {
        "maturity_score": maturity,
        "maturity_label": "Launch-grade demo" if maturity >= 75 else "Strong product prototype" if maturity >= 55 else "Core prototype",
        "dependency_health": deps,
        "topology_brain": graph,
        "ai_copilot": ai,
        "gates": gates,
        "feature_cards": feature_cards,
    }

# ---------------------------------------------------------------------------
# v5.15.0 Product UI cleanup + threat/evidence intelligence layer
# These definitions intentionally live below the v5.14 builders so the public
# build_product_intelligence() contract can be upgraded without breaking older
# imports that still reference this module.
# ---------------------------------------------------------------------------

OPTIONAL_STACK.extend([
    {"name": "Flask Compress", "import_name": "flask_compress", "package": "Flask-Compress", "group": "Product Runtime", "priority": "P1", "weight": 4, "impact": "gzip/brotli compression for heavier dashboards and exported JSON responses"},
    {"name": "Waitress", "import_name": "waitress", "package": "waitress", "group": "Product Runtime", "priority": "P1", "weight": 4, "impact": "stable Windows-friendly production server instead of Flask dev server"},
    {"name": "Python Dotenv", "import_name": "dotenv", "package": "python-dotenv", "group": "Product Runtime", "priority": "P2", "weight": 3, "impact": "clean .env-based setup for demo, staging, and production profiles"},
    {"name": "Pydantic", "import_name": "pydantic", "package": "pydantic", "group": "Data Contracts", "priority": "P1", "weight": 5, "impact": "strict validation for imported objects, report DTOs, and API payloads"},
    {"name": "orjson", "import_name": "orjson", "package": "orjson", "group": "Data Contracts", "priority": "P2", "weight": 3, "impact": "faster local JSON serialization for large Packet Tracer extraction payloads"},
    {"name": "Cryptography", "import_name": "cryptography", "package": "cryptography", "group": "Evidence Integrity", "priority": "P1", "weight": 5, "impact": "future signed evidence packages and stronger chain-of-custody proof"},
    {"name": "Rich", "import_name": "rich", "package": "rich", "group": "Developer Experience", "priority": "P2", "weight": 2, "impact": "better terminal diagnostics for setup, optional stack checks, and release scripts"},
])


def _clean_node_label_v515(node: Dict[str, Any]) -> str:
    return str(node.get("label") or node.get("id") or "node")[:80]


def _graph_adjacency_v515(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Tuple[Dict[str, List[Tuple[str, Dict[str, Any]]]], Dict[str, Dict[str, Any]]]:
    node_by_id = {str(n.get("id")): n for n in nodes if n.get("id") is not None}
    adjacency: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {node_id: [] for node_id in node_by_id}
    for edge in edges:
        a = str(edge.get("from") or "")
        b = str(edge.get("to") or "")
        if not a or not b:
            continue
        adjacency.setdefault(a, []).append((b, edge))
        adjacency.setdefault(b, []).append((a, edge))
        node_by_id.setdefault(a, {"id": a, "label": a, "type": "unknown"})
        node_by_id.setdefault(b, {"id": b, "label": b, "type": "unknown"})
    return adjacency, node_by_id


def _shortest_path_v515(adjacency: Dict[str, List[Tuple[str, Dict[str, Any]]]], start: str, goal: str, max_depth: int = 7) -> List[str]:
    if start == goal:
        return [start]
    queue = deque([(start, [start])])
    seen = {start}
    while queue:
        cur, path = queue.popleft()
        if len(path) > max_depth:
            continue
        for nxt, _edge in adjacency.get(cur, []):
            if nxt in seen:
                continue
            next_path = path + [nxt]
            if nxt == goal:
                return next_path
            seen.add(nxt)
            queue.append((nxt, next_path))
    return []


def attack_path_brain(state: Dict[str, Any]) -> Dict[str, Any]:
    topo = _topology_graph(state)
    nodes = topo["nodes"]
    edges = topo["edges"]
    adjacency, node_by_id = _graph_adjacency_v515(nodes, edges)
    high_value_types = {"router", "switch", "dhcp", "acl", "server", "network", "device", "control"}
    entry_types = {"ssid", "vlan", "endpoint", "client", "policy"}
    entries = [n for n in nodes if str(n.get("type") or "").lower() in entry_types]
    targets = [n for n in nodes if str(n.get("type") or "").lower() in high_value_types]
    if not entries:
        entries = nodes[:5]
    if not targets:
        targets = nodes[-8:]
    paths: List[Dict[str, Any]] = []
    for src in entries[:8]:
        sid = str(src.get("id"))
        for dst in targets[:10]:
            did = str(dst.get("id"))
            if sid == did:
                continue
            path = _shortest_path_v515(adjacency, sid, did, max_depth=7)
            if not path:
                continue
            path_nodes = [node_by_id.get(pid, {"id": pid, "label": pid, "type": "unknown"}) for pid in path]
            labels = [_clean_node_label_v515(n) for n in path_nodes]
            edge_count = max(0, len(path) - 1)
            review_penalty = 0
            confidence_total = 0.0
            for a, b in zip(path, path[1:]):
                match = next((e for nxt, e in adjacency.get(a, []) if nxt == b), {})
                status = str(match.get("status") or "review").lower()
                if status not in {"confirmed", "enforced", "expected", "pass"}:
                    review_penalty += 1
                confidence_total += float(match.get("confidence") or 0.35)
            confidence = round((confidence_total / max(1, edge_count)) * 100)
            risk = max(10, min(100, 92 - edge_count * 7 - review_penalty * 11))
            paths.append({
                "source": labels[0],
                "target": labels[-1],
                "source_type": src.get("type") or "unknown",
                "target_type": dst.get("type") or "unknown",
                "hops": edge_count,
                "confidence": confidence,
                "risk": risk,
                "status": "high" if risk >= 70 else "review" if risk >= 45 else "low",
                "path": labels,
                "why": "short path to a high-value network object" if edge_count <= 3 else "reachable through multiple inferred/evidence links",
            })
    paths = sorted(paths, key=lambda p: (p["risk"], p["confidence"]), reverse=True)[:10]
    exposure_by_node = Counter()
    for path in paths:
        for node in path.get("path", [])[1:-1]:
            exposure_by_node[node] += 1
    choke_points = [{"label": label, "paths": count} for label, count in exposure_by_node.most_common(8)]
    controls = []
    if paths:
        controls.append("Verify ACL/interface access-group evidence on every short path before calling exposure confirmed.")
        controls.append("Use VLAN/trunk evidence to decide whether each path is real, inferred, or blocked.")
    if choke_points:
        controls.append("Prioritize choke-point devices because one fix can reduce multiple possible paths.")
    if not paths:
        controls.append("Import CDP/LLDP, interface trunk, VLAN, route, and ACL outputs to unlock attack-path reasoning.")
    return {
        "paths": paths,
        "path_count": len(paths),
        "choke_points": choke_points,
        "entry_count": len(entries),
        "target_count": len(targets),
        "max_risk": max((p["risk"] for p in paths), default=0),
        "model": "evidence graph BFS",
        "controls": controls[:5],
        "headline": "Attack-path candidates detected" if paths else "Waiting for richer topology to calculate paths",
    }


_STOPWORDS_V515 = {
    "the", "and", "for", "with", "from", "this", "that", "true", "false", "none", "null",
    "interface", "evidence", "status", "line", "source", "config", "device", "vlan", "name",
    "على", "في", "من", "الى", "إلى", "ده", "دي", "او", "أو", "كل", "مش", "لا",
}


def _object_documents_v515(state: Dict[str, Any], limit: int = 900) -> List[Dict[str, Any]]:
    from .intelligence import get_objects

    objects = get_objects(state)
    docs: List[Dict[str, Any]] = []
    for category, value in objects.items():
        rows: List[Any] = value if isinstance(value, list) else []
        if isinstance(value, dict):
            rows = []
            for subkey, subval in value.items():
                if isinstance(subval, list):
                    for row in subval:
                        if isinstance(row, dict):
                            item = dict(row)
                            item["_subcategory"] = subkey
                            rows.append(item)
        for row in rows:
            if not isinstance(row, dict):
                continue
            title = row.get("hostname") or row.get("name") or row.get("interface") or row.get("id") or row.get("vlan") or row.get("ip_address") or category
            text = " ".join(f"{k}={v}" for k, v in row.items() if k != "evidence")
            evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
            docs.append({
                "category": str(category),
                "title": str(title)[:120],
                "text": text[:900],
                "line": evidence.get("line"),
                "confidence": evidence.get("confidence", row.get("confidence", 0.5)),
            })
            if len(docs) >= limit:
                return docs
    return docs


def evidence_search_pack(state: Dict[str, Any]) -> Dict[str, Any]:
    import re

    docs = _object_documents_v515(state)
    words = Counter()
    category_counts = Counter(d.get("category", "unknown") for d in docs)
    for doc in docs:
        for word in re.findall(r"[A-Za-z0-9_./:-]{3,}", doc.get("text", "")):
            lw = word.lower().strip("_:-./")
            if lw and lw not in _STOPWORDS_V515 and not lw.isdigit():
                words[lw] += 1
    top_keywords = [{"term": term, "count": count} for term, count in words.most_common(14)]
    samples = docs[:8]
    suggested_queries = []
    for term, _count in words.most_common(6):
        if len(suggested_queries) >= 4:
            break
        suggested_queries.append(f"Find evidence related to {term}")
    if not suggested_queries:
        suggested_queries = ["Find trunk evidence", "Find DHCP gateway mismatches", "Find insecure management services"]
    return {
        "doc_count": len(docs),
        "category_counts": dict(category_counts.most_common(12)),
        "top_keywords": top_keywords,
        "samples": samples,
        "suggested_queries": suggested_queries,
        "backend": "semantic-ready" if _installed("sentence_transformers") else "keyword index",
        "vector_ready": _installed("sentence_transformers") and (_installed("chromadb") or _installed("faiss")),
        "headline": "Evidence knowledge base is populated" if docs else "Import evidence to populate the knowledge base",
    }


def release_gate_pack(state: Dict[str, Any], deps: Dict[str, Any], graph: Dict[str, Any], ai: Dict[str, Any], attack: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    from .intelligence import build_extraction_diagnostics, build_import_truth_summary, object_count_breakdown, get_objects

    diagnostics = build_extraction_diagnostics(state)
    truth = build_import_truth_summary(state)
    breakdown = object_count_breakdown(get_objects(state))
    blockers = _safe_list(diagnostics.get("blockers"))
    gates = [
        {"title": "Import Truth Contract", "status": "pass" if truth.get("can_publish_technical") or truth.get("can_claim_full_fidelity") else "review", "owner": "Import", "detail": truth.get("claim") or truth.get("tier") or "waiting for import", "next": "Attach companion JSON/XML export when PKT native evidence is limited."},
        {"title": "Real Object Coverage", "status": "pass" if breakdown.get("real_object_count", 0) >= 12 else "review" if breakdown.get("real_object_count", 0) else "fail", "owner": "Parser", "detail": f"{breakdown.get('real_object_count', 0)} real objects · {breakdown.get('evidence_entry_count', 0)} support/evidence rows", "next": "Upload running-config/show-command evidence to increase real topology objects."},
        {"title": "Topology Confidence", "status": "pass" if graph.get("health_score", 0) >= 70 else "review" if graph.get("nodes", 0) else "fail", "owner": "Topology", "detail": f"{graph.get('nodes', 0)} nodes · {graph.get('edges', 0)} edges · {graph.get('backend', 'builtin')}", "next": "Add CDP/LLDP, trunk, interface status, and route evidence."},
        {"title": "Attack Path Readiness", "status": "pass" if attack.get("path_count", 0) >= 3 else "review" if graph.get("edges", 0) else "fail", "owner": "Threat Map", "detail": f"{attack.get('path_count', 0)} candidate path(s), max risk {attack.get('max_risk', 0)}", "next": "Validate paths with ACL and route outputs before claiming exploitability."},
        {"title": "Evidence Knowledge Base", "status": "pass" if evidence.get("doc_count", 0) >= 25 else "review" if evidence.get("doc_count", 0) else "fail", "owner": "Search/RAG", "detail": f"{evidence.get('doc_count', 0)} searchable evidence document(s), backend {evidence.get('backend')}", "next": "Install sentence-transformers + Chroma/FAISS to unlock semantic search."},
        {"title": "Optional Product Stack", "status": "pass" if deps.get("score", 0) >= 55 else "review", "owner": "Setup", "detail": f"{deps.get('installed_count', 0)}/{deps.get('total_count', 0)} optional/product libraries installed", "next": deps.get("commands", {}).get("p1", "pip install -r requirements-full.txt")},
        {"title": "AI Copilot", "status": "pass" if ai.get("local_ready") else "review", "owner": "AI", "detail": ai.get("mode") or "blueprint ready", "next": "Install Ollama and keep configs local for privacy-friendly explanations."},
        {"title": "Report Blockers", "status": "pass" if not blockers else "review", "owner": "QA", "detail": f"{len(blockers)} blocker(s) currently detected", "next": blockers[0].get("detail") if blockers and isinstance(blockers[0], dict) else "Run final report preview and verify evidence chain."},
    ]
    score_map = {"pass": 100, "review": 55, "fail": 15}
    score = round(sum(score_map.get(g["status"], 40) for g in gates) / max(1, len(gates)))
    return {"score": score, "label": "Release-ready demo" if score >= 78 else "Strong but needs evidence" if score >= 55 else "Needs import/data work", "gates": gates, "pass_count": sum(1 for g in gates if g["status"] == "pass"), "review_count": sum(1 for g in gates if g["status"] == "review"), "fail_count": sum(1 for g in gates if g["status"] == "fail")}


def ui_upgrade_pack() -> Dict[str, Any]:
    return {
        "headline": "Cleaner product UI layer is active",
        "upgrades": [
            {"title": "Command Palette", "status": "active", "detail": "Press Ctrl+K to jump between product pages without hunting inside the sidebar."},
            {"title": "Threat Map Page", "status": "active", "detail": "Attack-path candidates and choke points are separated from raw topology tables."},
            {"title": "Launch Gates", "status": "active", "detail": "The product explains exactly what blocks a clean report or release demo."},
            {"title": "Evidence Search Blueprint", "status": "active", "detail": "Keyword evidence index is available now; semantic/RAG upgrades are optional."},
            {"title": "Safer Legacy Navigation", "status": "active", "detail": "Object Explorer, Topology, Root Cause, and Threat Map are accessible from clearer grouped links."},
        ],
    }


def build_product_intelligence(state: Dict[str, Any]) -> Dict[str, Any]:
    deps = dependency_health()
    graph = topology_brain(state)
    ai = ai_copilot_pack(state)
    attack = attack_path_brain(state)
    evidence = evidence_search_pack(state)
    release = release_gate_pack(state, deps, graph, ai, attack, evidence)
    ui = ui_upgrade_pack()
    maturity = round((deps["score"] * 0.22) + (graph["health_score"] * 0.28) + (release["score"] * 0.28) + (12 if ai["local_ready"] else 5) + (10 if evidence["vector_ready"] else 4) + (8 if attack["path_count"] else 3))
    maturity = max(0, min(100, maturity))
    gates = [
        {"title": "Topology Brain", "status": "ready" if graph["nodes"] else "waiting", "detail": f"{graph['nodes']} nodes · {graph['edges']} edges · backend {graph['backend']}"},
        {"title": "Threat Map", "status": "ready" if attack["path_count"] else "blueprint", "detail": f"{attack['path_count']} path candidates · max risk {attack['max_risk']}"},
        {"title": "Evidence Search", "status": "ready" if evidence["doc_count"] else "waiting", "detail": f"{evidence['doc_count']} searchable evidence documents · {evidence['backend']}"},
        {"title": "Optional Stack", "status": "ready" if deps["score"] >= 45 else "optional", "detail": f"{deps['installed_count']}/{deps['total_count']} product libraries installed"},
        {"title": "AI Copilot", "status": "ready" if ai["local_ready"] else "blueprint", "detail": ai["mode"]},
        {"title": "Release Gate", "status": "ready" if release["score"] >= 75 else "review", "detail": f"{release['score']}% · {release['label']}"},
    ]
    feature_cards = [
        {"title": "Topology Brain", "tag": "P0", "body": "Graph analytics, critical nodes, isolated assets, and topology health scoring are surfaced in the UI."},
        {"title": "Threat Map / Blast Radius", "tag": "P0", "body": "Candidate attack paths, choke points, and validation controls are generated from the evidence graph."},
        {"title": "Evidence Knowledge Base", "tag": "P1", "body": "Imported objects become a searchable knowledge index with optional semantic/RAG acceleration."},
        {"title": "AI Root Cause v2", "tag": "P1", "body": "Findings, root causes, blockers, and next actions are packaged for a local AI copilot workflow."},
        {"title": "Launch Gate QA", "tag": "P1", "body": "A release-focused gate explains what is clean, what needs review, and what blocks a professional demo."},
        {"title": "Command Palette UI", "tag": "UX", "body": "Ctrl+K navigation, cleaner sections, and product cockpit cards reduce page clutter."},
    ]
    return {
        "maturity_score": maturity,
        "maturity_label": "Launch-grade demo" if maturity >= 75 else "Strong product prototype" if maturity >= 55 else "Core prototype",
        "dependency_health": deps,
        "topology_brain": graph,
        "ai_copilot": ai,
        "attack_path": attack,
        "evidence_search": evidence,
        "release_gate": release,
        "ui_upgrade": ui,
        "gates": gates,
        "feature_cards": feature_cards,
    }
