"""
PDF Report Generator — Produces professional pentest-style PDF reports
with executive summary, risk scoring, evidence, and remediation guidance.
"""
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path
from rich.console import Console

console = Console()

SEVERITY_ORDER = {"CRITICAL": 0, "critical": 0, "HIGH": 1, "high": 1,
                  "MEDIUM": 2, "medium": 2, "LOW": 3, "low": 3, "INFO": 4, "info": 4}

SEVERITY_COLORS = {
    "critical": "#dc2626", "CRITICAL": "#dc2626",
    "high":     "#ea580c", "HIGH":     "#ea580c",
    "medium":   "#d97706", "MEDIUM":   "#d97706",
    "low":      "#2563eb", "LOW":      "#2563eb",
    "info":     "#6b7280", "INFO":     "#6b7280",
}

REMEDIATION_ADVICE = {
    "CVE-2021-44228": "Upgrade Log4j to ≥2.17.1. Set log4j2.formatMsgNoLookups=true as interim.",
    "CVE-2021-41773": "Upgrade Apache to ≥2.4.51 immediately. Disable mod_cgi if not needed.",
    "CVE-2022-0543":  "Upgrade Redis to ≥6.2.7. Disable Lua scripting if not needed.",
    "EternalBlue":    "Apply MS17-010 patch. Block SMB ports 445/139 at perimeter firewall.",
    "default":        "Apply vendor security patches. Follow principle of least privilege.",
}


class PDFReportGenerator:
    """
    Generates professional PDF pentest reports using ReportLab.
    Falls back to styled HTML if ReportLab is not installed.
    """

    def __init__(self, target: str, scan_results: Dict[str, Any],
                 assessor: str = "NetRecon v3.0", client: str = ""):
        self.target = target
        self.results = scan_results
        self.assessor = assessor
        self.client = client or target
        self.generated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self._all_findings = self._extract_all_findings()
        self._risk_score = self._calculate_risk()

    def _extract_all_findings(self) -> List[Dict]:
        """Flatten all findings from all module results."""
        all_f = []
        for module_name, data in self.results.items():
            if not isinstance(data, dict):
                continue
            for key in ["findings", "alerts", "indicators", "hits", "vulnerabilities", "open_ports"]:
                items = data.get(key, [])
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            item["_module"] = module_name
                            all_f.append(item)
        return sorted(all_f, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 99))

    def _calculate_risk(self) -> Dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._all_findings:
            sev = str(f.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1

        score = min(100, (
            counts["critical"] * 25 +
            counts["high"]     * 10 +
            counts["medium"]   * 3  +
            counts["low"]      * 1
        ))

        if score >= 75:     label, color = "CRITICAL", "#dc2626"
        elif score >= 50:   label, color = "HIGH",     "#ea580c"
        elif score >= 25:   label, color = "MEDIUM",   "#d97706"
        elif score > 0:     label, color = "LOW",      "#2563eb"
        else:               label, color = "NONE",     "#16a34a"

        return {"score": score, "label": label, "color": color, "counts": counts}

    def _get_remediation(self, finding: Dict) -> str:
        cve = finding.get("cve_id", "")
        if cve in REMEDIATION_ADVICE:
            return REMEDIATION_ADVICE[cve]
        desc = str(finding.get("description", "")).lower()
        for key, advice in REMEDIATION_ADVICE.items():
            if key.lower() in desc:
                return advice
        return REMEDIATION_ADVICE["default"]

    def generate_html(self, output_path: str) -> bool:
        """Generate a styled HTML report (always available, no extra deps)."""
        r = self._risk_score
        counts = r["counts"]

        findings_html = ""
        for i, f in enumerate(self._all_findings[:100], 1):
            sev = str(f.get("severity", "info")).lower()
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            desc = f.get("description", f.get("msg", f.get("rule_name", "Finding")))
            src = f.get("src_ip", f.get("target_ip", f.get("url", "")))
            port = f.get("port", f.get("dst_port", f.get("target_port", "")))
            cve = f.get("cve_id", "")
            mitre = f.get("mitre", "")
            module = f.get("_module", "")
            remed = self._get_remediation(f)

            findings_html += f"""
            <div class="finding">
              <div class="finding-header" style="border-left:4px solid {color}">
                <span class="badge" style="background:{color}">{sev.upper()}</span>
                <span class="finding-title">{desc[:120]}</span>
                <span class="finding-meta">{module}</span>
              </div>
              <div class="finding-body">
                <table class="meta-table">
                  <tr><td>Source</td><td>{src or "—"}</td><td>Port</td><td>{port or "—"}</td></tr>
                  <tr><td>CVE</td><td>{cve or "—"}</td><td>MITRE</td><td>{mitre or "—"}</td></tr>
                </table>
                <div class="remediation"><strong>Remediation:</strong> {remed}</div>
              </div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetRecon Security Assessment — {self.target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');
  :root {{
    --bg: #0f1117; --surface: #1a1f2e; --border: #2a3347;
    --text: #e2e8f0; --muted: #64748b; --accent: #06b6d4;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text);
          line-height: 1.6; padding: 40px; max-width: 1100px; margin: 0 auto; }}
  .report-header {{ border-bottom: 2px solid var(--accent); padding-bottom: 24px; margin-bottom: 32px; }}
  .report-title {{ font-size: 28px; font-weight: 700; color: var(--accent); letter-spacing: -0.02em; }}
  .report-meta {{ color: var(--muted); font-size: 13px; margin-top: 6px; font-family: 'JetBrains Mono'; }}
  .section {{ margin-bottom: 32px; }}
  .section-title {{ font-size: 16px; font-weight: 700; color: var(--accent);
                    text-transform: uppercase; letter-spacing: 0.08em;
                    border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 16px; }}
  .risk-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 24px; }}
  .risk-card {{ background: var(--surface); border: 1px solid var(--border);
                padding: 16px; text-align: center; border-radius: 6px; }}
  .risk-card .value {{ font-size: 28px; font-weight: 700; font-family: 'JetBrains Mono'; }}
  .risk-card .label {{ font-size: 10px; color: var(--muted); text-transform: uppercase;
                       letter-spacing: 0.1em; margin-top: 4px; }}
  .finding {{ background: var(--surface); border: 1px solid var(--border);
              border-radius: 6px; margin-bottom: 12px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px;
                     padding: 12px 16px; background: rgba(255,255,255,0.02); }}
  .badge {{ font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 3px;
            color: white; font-family: 'JetBrains Mono'; white-space: nowrap; }}
  .finding-title {{ flex: 1; font-size: 14px; font-weight: 600; }}
  .finding-meta {{ font-size: 11px; color: var(--muted); font-family: 'JetBrains Mono'; }}
  .finding-body {{ padding: 12px 16px; border-top: 1px solid var(--border); }}
  .meta-table {{ width: 100%; border-collapse: collapse; margin-bottom: 8px; font-size: 12px; }}
  .meta-table td {{ padding: 3px 8px; color: var(--muted); }}
  .meta-table td:nth-child(odd) {{ font-weight: 600; color: var(--text); width: 80px; }}
  .remediation {{ font-size: 12px; color: #86efac; background: rgba(134,239,172,0.06);
                  border: 1px solid rgba(134,239,172,0.15); padding: 8px 12px;
                  border-radius: 4px; margin-top: 6px; }}
  .exec-summary {{ background: var(--surface); border: 1px solid var(--border);
                   padding: 20px; border-radius: 6px; font-size: 14px; line-height: 1.8; }}
  footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border);
            font-size: 12px; color: var(--muted); font-family: 'JetBrains Mono'; }}
</style>
</head>
<body>

<div class="report-header">
  <div class="report-title">Security Assessment Report</div>
  <div class="report-meta">
    Target: {self.target} &nbsp;·&nbsp;
    Generated: {self.generated_at} &nbsp;·&nbsp;
    Tool: {self.assessor} &nbsp;·&nbsp;
    Total Findings: {len(self._all_findings)}
  </div>
</div>

<div class="section">
  <div class="section-title">Risk Summary</div>
  <div class="risk-grid">
    <div class="risk-card">
      <div class="value" style="color:{r['color']}">{r['score']}</div>
      <div class="label">Risk Score</div>
    </div>
    <div class="risk-card">
      <div class="value" style="color:{r['color']}">{r['label']}</div>
      <div class="label">Risk Level</div>
    </div>
    <div class="risk-card">
      <div class="value" style="color:#dc2626">{counts['critical']}</div>
      <div class="label">Critical</div>
    </div>
    <div class="risk-card">
      <div class="value" style="color:#ea580c">{counts['high']}</div>
      <div class="label">High</div>
    </div>
    <div class="risk-card">
      <div class="value" style="color:#d97706">{counts['medium']}</div>
      <div class="label">Medium</div>
    </div>
    <div class="risk-card">
      <div class="value" style="color:#2563eb">{counts['low']}</div>
      <div class="label">Low</div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">Executive Summary</div>
  <div class="exec-summary">
    A security assessment was conducted against <strong>{self.target}</strong> on {self.generated_at}
    using NetRecon v3.0. The assessment identified <strong>{len(self._all_findings)} total findings</strong>
    across {len(self.results)} modules. The overall risk level is rated
    <strong style="color:{r['color']}">{r['label']}</strong> with a score of {r['score']}/100.
    {'Immediate remediation is required for ' + str(counts['critical']) + ' critical findings.' if counts['critical'] else
     'No critical findings were identified.' }
    {str(counts['high']) + ' high-severity findings should be addressed within 30 days.' if counts['high'] else ''}
  </div>
</div>

<div class="section">
  <div class="section-title">Findings ({len(self._all_findings)})</div>
  {findings_html if findings_html else '<p style="color:var(--muted)">No findings identified.</p>'}
</div>

<footer>
  Generated by NetRecon v3.0 &nbsp;·&nbsp; {self.generated_at} &nbsp;·&nbsp;
  FOR AUTHORIZED USE ONLY &nbsp;·&nbsp; Confidential
</footer>

</body></html>"""

        try:
            Path(output_path).write_text(html, encoding="utf-8")
            console.print(f"[green]✓ HTML report saved:[/green] {output_path}")
            return True
        except Exception as e:
            console.print(f"[red]✗ Failed to save report: {e}[/red]")
            return False

    def generate_pdf(self, output_path: str) -> bool:
        """Generate PDF using ReportLab. Falls back to HTML if unavailable."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                            Table, TableStyle, HRFlowable)
            from reportlab.lib.units import cm
        except ImportError:
            console.print("[yellow]⚠ ReportLab not installed. Generating HTML report instead.[/yellow]")
            html_path = output_path.replace(".pdf", ".html")
            return self.generate_html(html_path)

        doc = SimpleDocTemplate(output_path, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle("Title", parent=styles["Heading1"],
                                     fontSize=20, textColor=colors.HexColor("#06b6d4"),
                                     spaceAfter=6)
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Paragraph(
            f"Target: {self.target} &nbsp;·&nbsp; {self.generated_at}",
            ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9,
                           textColor=colors.HexColor("#64748b"))
        ))
        story.append(Spacer(1, 0.4*cm))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#06b6d4")))
        story.append(Spacer(1, 0.4*cm))

        # Risk summary table
        r = self._risk_score
        counts = r["counts"]
        risk_data = [
            ["RISK SCORE", "LEVEL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            [str(r["score"]), r["label"], str(counts["critical"]),
             str(counts["high"]), str(counts["medium"]), str(counts["low"])],
        ]
        risk_table = Table(risk_data, colWidths=[3*cm]*6)
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1f2e")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.HexColor("#64748b")),
            ("TEXTCOLOR",  (0,1), (-1,1), colors.HexColor("#e2e8f0")),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("FONTNAME",   (0,0), (-1,-1), "Courier"),
            ("ALIGN",      (0,0), (-1,-1), "CENTER"),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#2a3347")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0f1117")]),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 0.5*cm))

        # Findings
        sev_heading = ParagraphStyle("SevHead", parent=styles["Heading2"],
                                     fontSize=11, textColor=colors.HexColor("#06b6d4"))
        story.append(Paragraph(f"Findings ({len(self._all_findings)})", sev_heading))
        story.append(Spacer(1, 0.2*cm))

        for f in self._all_findings[:50]:
            sev = str(f.get("severity", "info")).upper()
            desc = f.get("description", f.get("msg", f.get("rule_name", "Finding")))[:100]
            cve = f.get("cve_id", "")
            color_hex = SEVERITY_COLORS.get(sev, "#6b7280")

            find_data = [
                [f"[{sev}]", desc, cve or f.get("mitre", "")],
            ]
            find_table = Table(find_data, colWidths=[2*cm, 12*cm, 3*cm])
            find_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (0,-1), colors.HexColor(color_hex)),
                ("TEXTCOLOR",   (0,0), (0,-1), colors.white),
                ("BACKGROUND",  (1,0), (-1,-1), colors.HexColor("#1a1f2e")),
                ("TEXTCOLOR",   (1,0), (-1,-1), colors.HexColor("#e2e8f0")),
                ("FONTSIZE",    (0,0), (-1,-1), 8),
                ("FONTNAME",    (0,0), (-1,-1), "Courier"),
                ("ALIGN",       (0,0), (0,-1), "CENTER"),
                ("GRID",        (0,0), (-1,-1), 0.3, colors.HexColor("#2a3347")),
                ("TOPPADDING",  (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ]))
            story.append(find_table)
            story.append(Spacer(1, 0.1*cm))

        try:
            doc.build(story)
            console.print(f"[green]✓ PDF report saved:[/green] {output_path}")
            return True
        except Exception as e:
            console.print(f"[red]✗ PDF generation failed: {e}[/red]")
            console.print("[yellow]  Falling back to HTML report...[/yellow]")
            return self.generate_html(output_path.replace(".pdf", ".html"))

    def save(self, output_path: str) -> bool:
        if output_path.endswith(".pdf"):
            return self.generate_pdf(output_path)
        else:
            return self.generate_html(output_path if output_path.endswith(".html") else output_path + ".html")
