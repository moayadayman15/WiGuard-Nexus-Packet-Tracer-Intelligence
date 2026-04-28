import html
import json
import zipfile
from io import BytesIO
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from .intelligence import build_report
from .util import now_iso


REPORT_TYPES = {
    "executive": "Executive Report",
    "technical": "Technical Network Report",
    "security": "Security Escalation Report",
    "audit": "Audit Evidence Report",
    "wireless": "Wireless Event & Policy Report",
    "full": "Full Evidence Report"
}


def report_json_bytes(state, report_type):
    payload = build_report(state, report_type)
    return BytesIO(json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8"))


def _report_sections(report_type):
    if report_type == "executive":
        return ["Executive Summary", "Risk Score", "Top Concerns", "Business Impact"]
    if report_type == "technical":
        return ["Extraction Confidence", "Object Inventory", "Topology", "Policy Diff", "Snapshot Diff"]
    if report_type == "security":
        return ["Critical Findings", "Root Cause", "Remediation Playbooks"]
    if report_type == "audit":
        return ["Evidence Manifest", "Source Hash", "Line-Level Evidence", "Verifier Notes"]
    if report_type == "wireless":
        return ["Wireless Risk", "SSID/AP Inventory", "Client Sessions", "Event Correlation", "Validation Matrix", "Anomalies"]
    return ["Executive Summary", "Policy Diff", "Root Cause", "Topology", "Timeline", "Playbooks", "Evidence Appendix"]


def report_pdf_bytes(state, report_type):
    payload = build_report(state, report_type)
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
    summary_rows = [
        ["Risk Score", str(risk.get("score", "N/A")), "Grade", risk.get("grade", "N/A")],
        ["Risk Level", risk.get("risk_level", "N/A"), "Failed Checks", str(summary.get("failed", 0))],
        ["Review Checks", str(summary.get("review", 0)), "Passed Checks", str(summary.get("passed", 0))],
        ["Extraction Confidence", str(confidence.get("overall", "N/A")), "Mode", confidence.get("mode", "N/A")],
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

    if report_type == "audit":
        story.append(Paragraph("Audit Evidence", styles["Heading2"]))
        story.append(Paragraph(f"Source hash: {payload.get('source_hash', 'N/A')}", styles["Tiny"]))
        manifest = payload.get("evidence_manifest", {})
        story.append(Paragraph(f"Manifest files: {manifest.get('artifact_count', 0)}", styles["SmallMuted"]))

    doc.build(story)
    buffer.seek(0)
    return buffer


def report_html_bytes(state, report_type):
    payload = build_report(state, report_type)
    title = REPORT_TYPES.get(report_type, "WiGuard Report")
    diffs = payload.get("policy_diff", [])
    causes = payload.get("root_causes", [])
    summary = payload.get("summary", {})
    risk = payload.get("risk", {})
    wireless = payload.get('wireless', {})
    wireless_matrix = wireless.get('matrix', [])
    wireless_anomalies = wireless.get('anomalies', [])
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
            zf.writestr(f"reports/{key}_report.json", json.dumps(build_report(state, key), indent=2, ensure_ascii=False))
            zf.writestr(f"reports/{key}_report.html", report_html_bytes(state, key).getvalue())
        zf.writestr("state_snapshot.json", json.dumps(state, indent=2, ensure_ascii=False))
    buffer.seek(0)
    return buffer


def custom_report_html_bytes(state, sections):
    """Small report-builder export used by the UI. Sections are intentionally simple and safe."""
    payload = build_report(state, "full")
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
    parts.append("</body></html>")
    return BytesIO("".join(parts).encode("utf-8"))
