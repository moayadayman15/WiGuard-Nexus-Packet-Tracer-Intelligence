import html
import json
import re
import zipfile
from io import BytesIO
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from .intelligence import build_report
from .util import now_iso


SENSITIVE_KEY_RE = re.compile(r"(password|passwd|secret|token|cookie|authorization|api[_-]?key|private[_-]?key|community|psk|radius[_-]?key|shared[_-]?secret)", re.I)
SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]{12,}"),
    re.compile(r"(?i)(authorization:\s*basic\s+)[A-Za-z0-9._\-+/=]{8,}"),
    # Cisco secrets may include a hash type between the command and the real
    # secret, e.g. "enable secret 5 <hash>". Keep the command/hash-type context
    # and redact only the sensitive value.
    re.compile(r"(?i)(enable\s+(?:secret|password)\s+(?:\d+\s+)?)[^\s]+"),
    re.compile(r"(?i)(username\s+\S+\s+(?:password|secret)\s+(?:\d+\s+)?)[^\s]+"),
    re.compile(r"(?i)(snmp-server\s+community\s+)[^\s]+"),
    re.compile(r"(?i)((?:wpa-psk|radius-server\s+key)\s+)[^\s]+"),
    re.compile(r"(?i)((?:token|api[_-]?key|secret|password|passwd|cookie)=)[^\s&]+"),
]


def _redact_string(value: str) -> str:
    text = value
    for pattern in SENSITIVE_VALUE_PATTERNS:
        text = pattern.sub(lambda m: m.group(1) + "[REDACTED]", text)
    return text


def sanitize_export_payload(value):
    """Recursively redact secrets before report/ZIP export.

    The UI can analyze sensitive config evidence, but export packages should not
    leak live passwords, API tokens, cookies, SNMP communities, WPA PSKs, or
    authorization headers by default.
    """
    if isinstance(value, dict):
        cleaned = {}
        for key, inner in value.items():
            if SENSITIVE_KEY_RE.search(str(key)):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = sanitize_export_payload(inner)
        return cleaned
    if isinstance(value, list):
        return [sanitize_export_payload(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


REPORT_TYPES = {
    "executive": "Executive Report",
    "technical": "Technical Network Report",
    "compliance": "Compliance Matrix Report",
    "packet_tracer": "Packet Tracer Conversion Report",
    "wireless_risk": "Wireless Risk Report",
    "security": "Security Escalation Report",
    "audit": "Audit Evidence & Appendix Report",
    "evidence_appendix": "Evidence Appendix",
    "wireless": "Wireless Event & Policy Report",
    "quality": "Extraction Quality & Analyst Sign-off Report",
    "full": "Full Evidence Report"
}


def report_json_bytes(state, report_type):
    payload = sanitize_export_payload(build_report(state, report_type))
    return BytesIO(json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8"))


def _report_sections(report_type):
    if report_type == "executive":
        return ["Executive Summary", "Risk Score", "Top Concerns", "Business Impact"]
    if report_type == "technical":
        return ["Extraction Confidence", "Object Inventory", "Topology", "Policy Diff", "Snapshot Diff"]
    if report_type == "security":
        return ["Critical Findings", "Root Cause", "Remediation Playbooks"]
    if report_type == "audit":
        return ["Evidence Manifest", "Source Hash", "Line-Level Evidence", "Verifier Notes", "Audit Hash Chain"]
    if report_type == "compliance":
        return ["Compliance Controls", "Control Status", "Evidence Mapping", "Risk Ownership"]
    if report_type == "packet_tracer":
        return ["Conversion Profile", "Command Checklist", "Extraction Confidence", "Missing Evidence"]
    if report_type == "wireless_risk":
        return ["Wireless Risk", "AP Load", "Anomaly Severity", "Remediation Priority"]
    if report_type == "evidence_appendix":
        return ["Artifact Manifest", "Line Evidence", "Source Hashes", "Integrity Notes"]
    if report_type == "wireless":
        return ["Wireless Risk", "SSID/AP Inventory", "Client Sessions", "Event Correlation", "Validation Matrix", "Anomalies"]
    if report_type == "quality":
        return ["Evidence Quality Matrix", "Analyst Sign-off", "Import Diagnostics", "Topology Confidence", "Rule Readiness"]
    return ["Executive Summary", "Policy Diff", "Root Cause", "Topology", "Timeline", "Playbooks", "Evidence Appendix"]


def report_pdf_bytes(state, report_type):
    payload = sanitize_export_payload(build_report(state, report_type))
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallMuted", parent=styles["BodyText"], fontSize=8, leading=10, textColor=colors.HexColor("#475569")))
    styles.add(ParagraphStyle(name="Tiny", parent=styles["BodyText"], fontSize=7, leading=9, textColor=colors.HexColor("#334155")))
    story = []

    story.append(Paragraph(REPORT_TYPES.get(report_type, "WiGuard Report"), styles["Title"]))
    project = payload.get("project", {})
    story.append(Paragraph(f"Project: {project.get('name', 'N/A')} | Generated: {now_iso()} | Template: {report_type}", styles["SmallMuted"]))
    story.append(Paragraph("Sections: " + ", ".join(_report_sections(report_type)), styles["SmallMuted"]))
    story.append(Spacer(1, 12))

    risk = payload.get("risk", {})
    summary = payload.get("summary", {})
    confidence = summary.get("confidence", {}) or {}
    conversion = payload.get("packet_tracer_conversion") or summary.get("conversion_profile") or {}
    summary_rows = [
        ["Risk Score", str(risk.get("score", "N/A")), "Grade", risk.get("grade", "N/A")],
        ["Risk Level", risk.get("risk_level", "N/A"), "Failed Checks", str(summary.get("failed", 0))],
        ["Review Checks", str(summary.get("review", 0)), "Passed Checks", str(summary.get("passed", 0))],
        ["Extraction Confidence", str(confidence.get("overall", "N/A")), "Mode", confidence.get("mode", "N/A")],
        ["PT Readiness", str(conversion.get("readiness_score", "N/A")), "Readiness", conversion.get("readiness", "N/A")],
    ]
    t = Table(summary_rows, colWidths=[95, 95, 95, 95])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eef6ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#93c5fd")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    executive = payload.get("executive_summary", {})
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(executive.get("headline", ""), styles["BodyText"]))
    story.append(Paragraph(f"Primary Concern: {executive.get('primary_concern', 'N/A')}", styles["BodyText"]))
    story.append(Paragraph(f"Business Impact: {executive.get('business_impact', 'N/A')}", styles["BodyText"]))
    story.append(Spacer(1, 12))

    missing = summary.get("missing_evidence", [])
    if missing and report_type in {"technical", "audit", "full"}:
        story.append(Paragraph("Missing Evidence Warnings", styles["Heading2"]))
        for m in missing[:8]:
            story.append(Paragraph(f"{m.get('severity')}: {m.get('source')} — {m.get('why')}", styles["SmallMuted"]))
        story.append(Spacer(1, 8))

    diffs = payload.get("policy_diff", [])
    if diffs and report_type != "executive":
        story.append(Paragraph("Policy Diff Matrix", styles["Heading2"]))
        rows = [["ID", "Category", "Actual", "Status", "Confidence"]]
        for d in diffs[:25]:
            rows.append([d.get("id", ""), d.get("category", ""), d.get("actual", ""), d.get("status", ""), str(d.get("confidence", ""))])
        table = Table(rows, repeatRows=1, colWidths=[92, 82, 165, 55, 55])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 12))

    causes = payload.get("root_causes", [])
    if causes and report_type in {"security", "technical", "full"}:
        story.append(Paragraph("Root Cause & Verification", styles["Heading2"]))
        for c in causes[:10]:
            story.append(Paragraph(f"{c.get('finding_id')} — Owner: {c.get('owner')} — Confidence: {int(c.get('confidence', 0)*100)}%", styles["Heading3"]))
            story.append(Paragraph("Evidence reason: " + str(c.get("evidence_reason", "N/A")), styles["SmallMuted"]))
            story.append(Paragraph("Likely causes: " + "; ".join(c.get("hypotheses", [])), styles["Tiny"]))
            story.append(Paragraph("Commands: " + ", ".join(c.get("verification_commands", [])), styles["Tiny"]))
            story.append(Spacer(1, 6))

    if report_type in {"wireless", "full"}:
        wireless = payload.get("wireless", {})
        wrisk = wireless.get("risk", {})
        story.append(Paragraph("Wireless Policy Manager", styles["Heading2"]))
        story.append(Paragraph(f"Wireless score: {wrisk.get('score', 'N/A')} / Grade: {wrisk.get('grade', 'N/A')} / Anomalies: {wrisk.get('anomaly_count', 0)}", styles["BodyText"]))
        matrix = wireless.get("matrix", [])
        if matrix:
            rows = [["Client", "Role", "SSID", "AP", "VLAN", "DHCP", "AP Trunk", "Result"]]
            for r in matrix[:25]:
                rows.append([r.get("client", ""), r.get("role", ""), r.get("ssid", ""), r.get("ap", ""), r.get("vlan_status", ""), r.get("dhcp_status", ""), r.get("ap_trunk_status", ""), r.get("result", "")])
            table = Table(rows, repeatRows=1, colWidths=[65, 50, 70, 50, 45, 45, 55, 45])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(table)

    if report_type in {"packet_tracer", "technical", "full"}:
        checklist = conversion.get("command_checklist", [])
        if checklist:
            story.append(Paragraph("Packet Tracer Conversion Command Checklist", styles["Heading2"]))
            rows = [["Command", "Status", "Severity", "Why"]]
            for item in checklist[:20]:
                rows.append([item.get("command", ""), item.get("status", ""), item.get("severity", ""), item.get("why", "")])
            table = Table(rows, repeatRows=1, colWidths=[120, 55, 55, 220])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(table)
            story.append(Spacer(1, 12))

    if report_type in {"compliance", "full"}:
        controls = payload.get("compliance", [])
        if controls:
            story.append(Paragraph("Compliance Matrix", styles["Heading2"]))
            rows = [["Control", "Status", "Risk", "Evidence"]]
            for c in controls[:30]:
                rows.append([c.get("control", ""), c.get("status", ""), c.get("risk", ""), c.get("evidence", "")])
            table = Table(rows, repeatRows=1, colWidths=[100, 55, 55, 240])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(table)
            story.append(Spacer(1, 12))

    if report_type in {"quality", "packet_tracer", "technical", "full"}:
        eqm = payload.get("evidence_quality_matrix", {})
        rows = eqm.get("rows", [])
        if rows:
            story.append(Paragraph("Evidence Quality Matrix", styles["Heading2"]))
            story.append(Paragraph(f"Grade: {eqm.get('grade', 'N/A')} | Score: {eqm.get('score', 'N/A')}/100", styles["SmallMuted"]))
            qrows = [["Category", "Count", "Status", "Verified", "Action"]]
            for r in rows[:16]:
                qrows.append([r.get("label", ""), str(r.get("count", 0)), r.get("status", ""), str(r.get("verified", 0)), r.get("recommended_action", "")])
            table = Table(qrows, repeatRows=1, colWidths=[95, 40, 50, 45, 220])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(table)
            story.append(Spacer(1, 12))
        signoff = payload.get("analyst_signoff", {})
        if signoff:
            story.append(Paragraph("Analyst Sign-off", styles["Heading2"]))
            story.append(Paragraph(f"Executive publish: {signoff.get('can_publish_executive')} | Technical publish: {signoff.get('can_publish_technical')} | Full fidelity: {signoff.get('can_claim_full_fidelity')}", styles["SmallMuted"]))
            for item in signoff.get("required_actions", [])[:8]:
                story.append(Paragraph(f"{item.get('priority')}: {item.get('action')} — {item.get('why')}", styles["Tiny"]))
            for claim in signoff.get("forbidden_claims", [])[:4]:
                story.append(Paragraph(f"Forbidden claim: {claim}", styles["Tiny"]))
            story.append(Spacer(1, 8))

    if report_type in {"audit", "evidence_appendix"}:
        story.append(Paragraph("Audit Evidence", styles["Heading2"]))
        story.append(Paragraph(f"Source hash: {payload.get('source_hash', 'N/A')}", styles["Tiny"]))
        manifest = payload.get("evidence_manifest", {})
        story.append(Paragraph(f"Manifest files: {manifest.get('artifact_count', 0)}", styles["SmallMuted"]))

    doc.build(story)
    buffer.seek(0)
    return buffer


def report_html_bytes(state, report_type):
    payload = sanitize_export_payload(build_report(state, report_type))
    title = REPORT_TYPES.get(report_type, "WiGuard Report")
    diffs = payload.get("policy_diff", [])
    causes = payload.get("root_causes", [])
    summary = payload.get("summary", {})
    risk = payload.get("risk", {})
    wireless = payload.get('wireless', {})
    wireless_matrix = wireless.get('matrix', [])
    wireless_anomalies = wireless.get('anomalies', [])
    conversion = payload.get("packet_tracer_conversion") or summary.get("conversion_profile") or {}
    command_rows = "".join(f"<tr><td>{html.escape(str(c.get('command','')))}</td><td>{html.escape(str(c.get('status','')))}</td><td>{html.escape(str(c.get('severity','')))}</td><td>{html.escape(str(c.get('why','')))}</td></tr>" for c in conversion.get("command_checklist", []))
    rows = "".join(
        f"<tr><td>{html.escape(str(d.get('id','')))}</td><td>{html.escape(str(d.get('category','')))}</td><td>{html.escape(str(d.get('status','')))}</td><td>{html.escape(str(d.get('severity','')))}</td><td>{html.escape(str(d.get('actual','')))}</td><td>{html.escape(str(d.get('evidence_line','')))}</td></tr>"
        for d in diffs
    )
    wireless_rows = "".join(f"<tr><td>{html.escape(str(r.get('client','')))}</td><td>{html.escape(str(r.get('role','')))}</td><td>{html.escape(str(r.get('ssid','')))}</td><td>{html.escape(str(r.get('ap','')))}</td><td>{html.escape(str(r.get('expected_vlan','')))} / {html.escape(str(r.get('actual_vlan','')))}</td><td>{html.escape(str(r.get('result','')))}</td></tr>" for r in wireless_matrix)
    anomaly_cards = "".join(f"<article class='card'><h3>{html.escape(str(a.get('id','')))}</h3><p><b>{html.escape(str(a.get('severity','')))}</b> · {html.escape(str(a.get('category','')))}</p><p>{html.escape(str(a.get('detail','')))}</p></article>" for a in wireless_anomalies)
    cause_cards = "".join(
        f"<article class='card'><h3>{html.escape(str(c.get('finding_id','')))}</h3><p><b>Owner:</b> {html.escape(str(c.get('owner','')))} · <b>Confidence:</b> {int(c.get('confidence',0)*100)}%</p><p>{html.escape(str(c.get('evidence_reason','')))}</p><pre>{html.escape(chr(10).join(c.get('verification_commands',[])))}</pre></article>"
        for c in causes
    )
    missing = "".join(f"<li><b>{html.escape(m.get('severity',''))}</b> — {html.escape(m.get('source',''))}: {html.escape(m.get('why',''))}</li>" for m in summary.get("missing_evidence", []))
    diagnostics = payload.get("diagnostics", {})
    topology_insights = payload.get("topology_insights", {})
    rule_assessment = payload.get("rule_assessment", {})
    evidence_quality = payload.get("evidence_quality_matrix", {})
    signoff = payload.get("analyst_signoff", {})
    blocker_rows = "".join(f"<tr><td>{html.escape(str(b.get('id','')))}</td><td>{html.escape(str(b.get('severity','')))}</td><td>{html.escape(str(b.get('detail','')))}</td></tr>" for b in diagnostics.get("blockers", []))
    quality_rows = "".join(f"<tr><td>{html.escape(str(r.get('label','')))}</td><td>{html.escape(str(r.get('count',0)))}</td><td>{html.escape(str(r.get('status','')))}</td><td>{html.escape(str(r.get('claim_level','')))}</td><td>{html.escape(str(r.get('verified',0)))}</td><td>{html.escape(str(r.get('recommended_action','')))}</td></tr>" for r in evidence_quality.get("rows", []))
    signoff_actions = "".join(f"<li><b>{html.escape(str(a.get('priority','')))}</b> — {html.escape(str(a.get('action','')))}: {html.escape(str(a.get('why','')))}</li>" for a in signoff.get("required_actions", []))
    forbidden_claims = "".join(f"<li>{html.escape(str(c))}</li>" for c in signoff.get("forbidden_claims", []))
    allowed_claims = "".join(f"<li>{html.escape(str(c))}</li>" for c in signoff.get("allowed_claims", []))
    doc = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>{html.escape(title)}</title>
<style>
body{{font-family:Inter,Arial,sans-serif;background:#f8fafc;color:#0f172a;margin:0;padding:28px}}
.header,.panel{{background:#fff;border:1px solid #e2e8f0;border-radius:18px;padding:22px;margin-bottom:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.kpi{{background:#eff6ff;border-radius:14px;padding:14px}}.kpi b{{font-size:26px;display:block}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{border-bottom:1px solid #e2e8f0;padding:10px;text-align:left;vertical-align:top}}th{{background:#0f172a;color:white}}
.card{{border:1px solid #e2e8f0;border-radius:14px;padding:14px;margin:10px 0}}pre{{white-space:pre-wrap;background:#0f172a;color:#e2e8f0;border-radius:12px;padding:12px}}
</style></head><body>
<section class='header'><h1>{html.escape(title)}</h1><p>Generated: {html.escape(payload.get('generated_at',''))} · Project: {html.escape(payload.get('project',{}).get('name','N/A'))}</p></section>
<section class='panel kpis'><div class='kpi'><span>Risk Score</span><b>{risk.get('score','N/A')}</b></div><div class='kpi'><span>Grade</span><b>{html.escape(str(risk.get('grade','N/A')))}</b></div><div class='kpi'><span>Failed</span><b>{summary.get('failed',0)}</b></div><div class='kpi'><span>Review</span><b>{summary.get('review',0)}</b></div></section>
<section class='panel'><h2>Executive Summary</h2><p>{html.escape(payload.get('executive_summary',{}).get('headline',''))}</p><p><b>Primary concern:</b> {html.escape(payload.get('executive_summary',{}).get('primary_concern',''))}</p></section>
<section class='panel'><h2>Packet Tracer Conversion</h2><p><b>Readiness:</b> {html.escape(str(conversion.get('readiness','N/A')))} · <b>Score:</b> {html.escape(str(conversion.get('readiness_score','N/A')))}</p><p>{html.escape(str(conversion.get('analyst_next_step','')))}</p><table><thead><tr><th>Command</th><th>Status</th><th>Severity</th><th>Why</th></tr></thead><tbody>{command_rows or '<tr><td colspan=4>No conversion profile.</td></tr>'}</tbody></table></section>
<section class='panel'><h2>Import Diagnostics</h2><p><b>Tier:</b> {html.escape(str(diagnostics.get('tier','N/A')))} · <b>Readiness:</b> {html.escape(str(diagnostics.get('readiness_score','N/A')))}% · <b>Full fidelity:</b> {html.escape(str(diagnostics.get('can_claim_full_fidelity', False)))}</p><table><thead><tr><th>Blocker</th><th>Severity</th><th>Detail</th></tr></thead><tbody>{blocker_rows or '<tr><td colspan=3>No blockers.</td></tr>'}</tbody></table></section>
<section class='panel'><h2>Topology Confidence</h2><p><b>Nodes:</b> {topology_insights.get('node_count','N/A')} · <b>Edges:</b> {topology_insights.get('edge_count','N/A')} · <b>Average edge confidence:</b> {int((topology_insights.get('edge_confidence_average') or 0)*100)}%</p></section>
<section class='panel'><h2>Rule Engine Readiness</h2><p><b>Enabled rules:</b> {rule_assessment.get('classic_rules_enabled','N/A')} / {rule_assessment.get('classic_rules_total','N/A')} · <b>Findings:</b> {rule_assessment.get('findings_total','N/A')} · <b>Risk atoms:</b> {rule_assessment.get('risk_atoms','N/A')}</p></section>
<section class='panel'><h2>Evidence Quality Matrix</h2><p><b>Grade:</b> {html.escape(str(evidence_quality.get('grade','N/A')))} · <b>Score:</b> {html.escape(str(evidence_quality.get('score','N/A')))}/100 · <b>Full fidelity allowed:</b> {html.escape(str(evidence_quality.get('full_fidelity_allowed', False)))}</p><table><thead><tr><th>Category</th><th>Count</th><th>Status</th><th>Claim Level</th><th>Verified</th><th>Recommended Action</th></tr></thead><tbody>{quality_rows or '<tr><td colspan=6>No quality matrix.</td></tr>'}</tbody></table></section>
<section class='panel'><h2>Analyst Sign-off</h2><p><b>Executive publish:</b> {html.escape(str(signoff.get('can_publish_executive', False)))} · <b>Technical publish:</b> {html.escape(str(signoff.get('can_publish_technical', False)))} · <b>Evidence grade:</b> {html.escape(str(signoff.get('evidence_grade','N/A')))}</p><h3>Required Actions</h3><ul>{signoff_actions or '<li>No required actions.</li>'}</ul><h3>Allowed Claims</h3><ul>{allowed_claims or '<li>No allowed claims yet.</li>'}</ul><h3>Forbidden Claims</h3><ul>{forbidden_claims or '<li>No forbidden claims.</li>'}</ul></section>
<section class='panel'><h2>Missing Evidence</h2><ul>{missing or '<li>No missing evidence warnings.</li>'}</ul></section>
<section class='panel'><h2>Wireless Validation Matrix</h2><table><thead><tr><th>Client</th><th>Role</th><th>SSID</th><th>AP</th><th>VLAN Expected/Actual</th><th>Result</th></tr></thead><tbody>{wireless_rows or '<tr><td colspan=6>No wireless rows.</td></tr>'}</tbody></table></section>
<section class='panel'><h2>Wireless Anomalies</h2>{anomaly_cards or '<p>No wireless anomalies.</p>'}</section>
<section class='panel'><h2>Policy Diff</h2><table><thead><tr><th>ID</th><th>Category</th><th>Status</th><th>Severity</th><th>Actual</th><th>Line</th></tr></thead><tbody>{rows}</tbody></table></section>
<section class='panel'><h2>Root Cause Cards</h2>{cause_cards or '<p>No root cause cards.</p>'}</section>
</body></html>"""
    return BytesIO(doc.encode("utf-8"))


def evidence_zip_bytes(state, artifact_dir):
    artifact_dir = Path(artifact_dir)
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in artifact_dir.glob("*"):
            if path.is_file():
                zf.write(path, arcname=f"artifacts/{path.name}")
        for key in REPORT_TYPES:
            zf.writestr(f"reports/{key}_report.json", json.dumps(sanitize_export_payload(build_report(state, key)), indent=2, ensure_ascii=False))
            zf.writestr(f"reports/{key}_report.html", report_html_bytes(state, key).getvalue())
        zf.writestr("state_snapshot.redacted.json", json.dumps(sanitize_export_payload(state), indent=2, ensure_ascii=False))
    buffer.seek(0)
    return buffer


def custom_report_html_bytes(state, sections):
    """Small report-builder export used by the UI. Sections are intentionally simple and safe."""
    payload = sanitize_export_payload(build_report(state, "full"))
    sections = set(sections or [])
    wireless = payload.get("wireless", {})
    parts = ["<!doctype html><html><head><meta charset='utf-8'><title>Custom WiGuard Report</title><style>body{font-family:Arial,sans-serif;background:#0f172a;color:#e5eefc;margin:0;padding:28px}section{background:#111c31;border:1px solid #29405f;border-radius:16px;padding:18px;margin:16px 0}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #29405f;padding:8px;text-align:left}.badge{display:inline-block;border:1px solid #38bdf8;border-radius:999px;padding:3px 8px}</style></head><body><h1>Custom WiGuard Report</h1>"]
    if "summary" in sections:
        parts.append(f"<section><h2>Summary</h2><p>Risk score: <b>{html.escape(str(payload.get('risk',{}).get('score','N/A')))}</b></p><p>Generated: {html.escape(now_iso())}</p></section>")
    if "wireless" in sections:
        rows = "".join(f"<tr><td>{html.escape(str(r.get('client','')))}</td><td>{html.escape(str(r.get('ssid','')))}</td><td>{html.escape(str(r.get('ap','')))}</td><td>{html.escape(str(r.get('result','')))}</td></tr>" for r in wireless.get("matrix", []))
        parts.append(f"<section><h2>Wireless Validation Matrix</h2><table><tr><th>Client</th><th>SSID</th><th>AP</th><th>Result</th></tr>{rows}</table></section>")
    if "anomalies" in sections:
        cards = "".join(f"<p><span class='badge'>{html.escape(str(a.get('severity','')))}</span> <b>{html.escape(str(a.get('id','')))}</b> — {html.escape(str(a.get('detail','')))}</p>" for a in wireless.get("anomalies", []))
        parts.append(f"<section><h2>Anomalies</h2>{cards or '<p>No anomalies.</p>'}</section>")
    if "compliance" in sections:
        rows = "".join(f"<tr><td>{html.escape(str(c.get('control','')))}</td><td>{html.escape(str(c.get('status','')))}</td><td>{html.escape(str(c.get('risk','')))}</td><td>{html.escape(str(c.get('evidence','')))}</td></tr>" for c in payload.get("compliance", []))
        parts.append(f"<section><h2>Compliance Matrix</h2><table><tr><th>Control</th><th>Status</th><th>Risk</th><th>Evidence</th></tr>{rows}</table></section>")
    if "diagnostics" in sections:
        diag = payload.get("diagnostics", {})
        rows = "".join(f"<tr><td>{html.escape(str(b.get('id','')))}</td><td>{html.escape(str(b.get('severity','')))}</td><td>{html.escape(str(b.get('detail','')))}</td></tr>" for b in diag.get("blockers", []))
        parts.append(f"<section><h2>Packet Tracer Diagnostics</h2><p>Tier: <b>{html.escape(str(diag.get('tier','N/A')))}</b> | Readiness: <b>{html.escape(str(diag.get('readiness_score','N/A')))}%</b> | Full Fidelity: <b>{html.escape(str(diag.get('can_claim_full_fidelity', False)))}</b></p><table><tr><th>Blocker</th><th>Severity</th><th>Detail</th></tr>{rows or '<tr><td colspan=3>No blockers.</td></tr>'}</table></section>")
    if "topology" in sections:
        tins = payload.get("topology_insights", {})
        parts.append(f"<section><h2>Topology Confidence</h2><p>Nodes: <b>{tins.get('node_count','N/A')}</b> | Edges: <b>{tins.get('edge_count','N/A')}</b> | Confirmed edges: <b>{tins.get('confirmed_edges','N/A')}</b> | Avg confidence: <b>{int((tins.get('edge_confidence_average') or 0)*100)}%</b></p></section>")
    if "rules" in sections:
        ra = payload.get("rule_assessment", {})
        parts.append(f"<section><h2>Rule Engine Readiness</h2><p>Rules: <b>{ra.get('classic_rules_enabled','N/A')} / {ra.get('classic_rules_total','N/A')}</b> | Findings: <b>{ra.get('findings_total','N/A')}</b> | Verified inputs: <b>{int((ra.get('evidence_verified_ratio') or 0)*100)}%</b></p></section>")
    if "quality" in sections:
        eqm = payload.get("evidence_quality_matrix", {})
        rows = "".join(f"<tr><td>{html.escape(str(r.get('label','')))}</td><td>{html.escape(str(r.get('status','')))}</td><td>{html.escape(str(r.get('claim_level','')))}</td><td>{html.escape(str(r.get('recommended_action','')))}</td></tr>" for r in eqm.get("rows", []))
        parts.append(f"<section><h2>Evidence Quality Matrix</h2><p>Grade: <b>{html.escape(str(eqm.get('grade','N/A')))}</b> | Score: <b>{html.escape(str(eqm.get('score','N/A')))} / 100</b></p><table><tr><th>Category</th><th>Status</th><th>Claim</th><th>Action</th></tr>{rows}</table></section>")
    if "signoff" in sections:
        signoff = payload.get("analyst_signoff", {})
        actions = "".join(f"<li><b>{html.escape(str(a.get('priority','')))}</b> — {html.escape(str(a.get('action','')))}</li>" for a in signoff.get("required_actions", []))
        parts.append(f"<section><h2>Analyst Sign-off</h2><p>Executive: <b>{html.escape(str(signoff.get('can_publish_executive', False)))}</b> | Technical: <b>{html.escape(str(signoff.get('can_publish_technical', False)))}</b> | Full fidelity: <b>{html.escape(str(signoff.get('can_claim_full_fidelity', False)))}</b></p><ul>{actions or '<li>No required actions.</li>'}</ul></section>")
    parts.append("</body></html>")
    return BytesIO("".join(parts).encode("utf-8"))
