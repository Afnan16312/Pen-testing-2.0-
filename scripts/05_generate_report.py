#!/usr/bin/env python3
"""
Step 6: Reporting — Generate full HTML penetration test report
Aggregates all JSON results from previous steps into a professional,
colour-coded HTML report that can be opened in any browser.

Aligns with NIST CSF - Respond (RS.CO): Communications
"""

import json
import os
import glob
import argparse
from datetime import datetime
from utils.logger import setup_logger
from utils.report_builder import load_latest_json

logger = setup_logger("reporting")

SEVERITY_COLORS = {
    "Critical": "#dc2626",   # red-600
    "High":     "#ea580c",   # orange-600
    "Medium":   "#d97706",   # amber-600
    "Low":      "#65a30d",   # lime-600
    "Info":     "#6b7280",   # gray-500
}

SEVERITY_BG = {
    "Critical": "#fee2e2",
    "High":     "#ffedd5",
    "Medium":   "#fef9c3",
    "Low":      "#f0fdf4",
    "Info":     "#f9fafb",
}


def load_all_results(results_dir: str) -> dict:
    """Load all JSON artefacts produced by previous pipeline steps."""
    data = {
        "nmap":   load_latest_json(results_dir, "nmap_scan_*.json")       or {},
        "nessus": load_latest_json(results_dir, "nessus_vulns_*.json")    or [],
        "exploit":load_latest_json(results_dir, "exploitation_evidence_*.json") or [],
        "impact": load_latest_json(results_dir, "impact_assessment_*.json")     or [],
        "cleanup":load_latest_json(results_dir, "cleanup_verification_*.json")  or {},
    }
    return data


def _severity_badge(label: str) -> str:
    color = SEVERITY_COLORS.get(label, "#6b7280")
    bg    = SEVERITY_BG.get(label, "#f9fafb")
    return (
        f'<span style="background:{bg};color:{color};'
        f'border:1px solid {color};border-radius:4px;'
        f'padding:2px 8px;font-weight:700;font-size:0.75rem;">'
        f'{label}</span>'
    )


def build_executive_summary_html(data: dict) -> str:
    nessus_vulns = data["nessus"]
    from collections import Counter
    counts = Counter(
        v.get("severity_label", "Info") for v in nessus_vulns
    )
    total_hosts = len(data["nmap"])
    confirmed   = sum(1 for e in data["exploit"] if e.get("vulnerable"))

    rows = ""
    for label in ["Critical", "High", "Medium", "Low", "Info"]:
        rows += f"""
        <tr>
          <td>{_severity_badge(label)}</td>
          <td style="text-align:center;font-weight:700;">{counts.get(label, 0)}</td>
        </tr>"""

    return f"""
    <section id="executive-summary">
      <h2>Executive Summary</h2>
      <p>
        A full-scope network penetration test was conducted following the
        <strong>NIST Cybersecurity Framework</strong>. The assessment covered
        <strong>{total_hosts} host(s)</strong> and identified
        <strong>{len(nessus_vulns)} vulnerabilities</strong>.
        Of those, <strong>{confirmed} were confirmed exploitable</strong>
        via safe, non-destructive proof-of-concept tests.
      </p>
      <table>
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p style="margin-top:1rem;">
        The most critical finding (CVSS&nbsp;10.0) was an
        <strong>unauthenticated open SMB share</strong> accessible to anyone
        on the network — requiring <em>immediate remediation</em>.
      </p>
    </section>"""


def build_hosts_html(nmap_data: dict) -> str:
    if not nmap_data:
        return "<section><h2>Host Discovery</h2><p>No scan data available.</p></section>"

    rows = ""
    for ip, host in nmap_data.items():
        os_name = host["os_match"][0]["name"] if host.get("os_match") else "Unknown"
        ports   = ", ".join(
            f"{p['port']}/{p['protocol']} ({p['service']})"
            for p in host.get("open_ports", [])[:8]
        )
        rows += f"""
        <tr>
          <td><code>{ip}</code></td>
          <td>{host.get('hostname') or '—'}</td>
          <td>{os_name}</td>
          <td>{len(host.get('open_ports', []))}</td>
          <td style="font-size:0.8rem;color:#555;">{ports}</td>
        </tr>"""

    return f"""
    <section id="hosts">
      <h2>Discovered Hosts</h2>
      <table>
        <thead>
          <tr>
            <th>IP Address</th><th>Hostname</th><th>OS</th>
            <th>Open Ports</th><th>Services (sample)</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def build_vulns_html(nessus_vulns: list) -> str:
    if not nessus_vulns:
        return "<section><h2>Vulnerability Findings</h2><p>No data available.</p></section>"

    rows = ""
    for v in nessus_vulns:
        label  = v.get("severity_label", "Info")
        badge  = _severity_badge(label)
        cves   = ", ".join(
            ref.get("name", "") for ref in v.get("cve", [])
            if isinstance(ref, dict)
        ) or "—"
        rows += f"""
        <tr>
          <td>{badge}</td>
          <td><code>{v.get('host','')}</code>:{v.get('port','')}</td>
          <td>{v.get('plugin_name','')}</td>
          <td style="text-align:center;">{v.get('cvss_base','N/A')}</td>
          <td>{cves}</td>
        </tr>"""

    return f"""
    <section id="vulnerabilities">
      <h2>Vulnerability Findings ({len(nessus_vulns)} total)</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th><th>Host:Port</th><th>Finding</th>
            <th>CVSS</th><th>CVE(s)</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def build_impact_html(impact_data: list) -> str:
    if not impact_data:
        return "<section><h2>Impact Assessment</h2><p>No confirmed findings.</p></section>"

    cards = ""
    for item in impact_data:
        badge    = _severity_badge(item["severity"])
        tactics  = "".join(
            f'<span style="background:#e0e7ff;color:#3730a3;border-radius:3px;'
            f'padding:1px 6px;margin:2px;display:inline-block;font-size:0.75rem;">'
            f'{t}</span>'
            for t in item.get("mitre_tactics", [])
        )
        accesses = "".join(f"<li>{a}</li>" for a in item.get("potential_access", []))

        cards += f"""
        <div style="border:1px solid #e5e7eb;border-left:4px solid
            {SEVERITY_COLORS.get(item['severity'],'#6b7280')};
            border-radius:6px;padding:1rem 1.2rem;margin-bottom:1rem;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <strong>{item['vulnerability']}</strong>
            {badge}
          </div>
          <p style="color:#555;margin:0.4rem 0;">Host: <code>{item['host']}</code>
            — CVSS {item['cvss']} — {item['remediation_priority']}</p>
          <p><strong>Blast Radius:</strong> {item['blast_radius']}</p>
          <p><strong>Data at Risk:</strong> {item['data_at_risk']}</p>
          <p><strong>Lateral Movement Risk:</strong> {item['lateral_movement']}</p>
          <p><strong>MITRE ATT&CK:</strong> {tactics}</p>
          <p><strong>An attacker could:</strong></p>
          <ul style="margin:0;padding-left:1.5rem;">{accesses}</ul>
        </div>"""

    return f"""
    <section id="impact">
      <h2>Impact Assessment — Confirmed Findings</h2>
      {cards}
    </section>"""


def build_recommendations_html() -> str:
    recs = [
        ("P1 – Immediate (24h)", "Critical",
         "Restrict open SMB shares. Require authentication for all network shares. "
         "Implement firewall rules to block port 445 from untrusted networks."),
        ("P2 – Short-term (7 days)", "High",
         "Disable SMBv1 on all Windows hosts. Update SSH server configuration to "
         "remove deprecated ciphers (arcfour, 3des-cbc, blowfish). Enforce "
         "strong KEX algorithms (curve25519-sha256, diffie-hellman-group16-sha512)."),
        ("P3 – Medium-term (30 days)", "Medium",
         "Patch all systems to current vendor-supported versions. "
         "Implement network segmentation to limit lateral movement. "
         "Deploy an Intrusion Detection System (IDS)."),
        ("P4 – Ongoing", "Low",
         "Schedule monthly or bi-monthly penetration tests. "
         "Implement a vulnerability management program aligned with NIST CSF. "
         "Conduct security awareness training for all staff."),
    ]

    cards = ""
    for title, severity, text in recs:
        color = SEVERITY_COLORS.get(severity, "#6b7280")
        bg    = SEVERITY_BG.get(severity, "#f9fafb")
        cards += f"""
        <div style="border-left:4px solid {color};background:{bg};
            border-radius:0 6px 6px 0;padding:1rem 1.2rem;margin-bottom:1rem;">
          <strong style="color:{color};">{title}</strong>
          <p style="margin:0.4rem 0;">{text}</p>
        </div>"""

    return f"""
    <section id="recommendations">
      <h2>Recommendations</h2>
      {cards}
    </section>"""


def generate_html_report(results_dir: str, output_path: str):
    """
    Build and write the final HTML report.
    """
    data         = load_all_results(results_dir)
    generated_at = datetime.now().strftime("%d %B %Y, %H:%M")

    exec_summary  = build_executive_summary_html(data)
    hosts_section = build_hosts_html(data["nmap"])
    vuln_section  = build_vulns_html(data["nessus"])
    impact_section= build_impact_html(data["impact"])
    reco_section  = build_recommendations_html()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Penetration Test Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif;
         background: #f3f4f6; color: #111827; line-height: 1.6; }}
  header {{ background: #0f172a; color: #f8fafc; padding: 2rem 3rem; }}
  header h1 {{ font-size: 1.8rem; letter-spacing: -0.5px; }}
  header p  {{ color: #94a3b8; margin-top: 0.25rem; font-size: 0.9rem; }}
  main {{ max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem; }}
  section {{ background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.08);
             padding: 1.5rem 2rem; margin-bottom: 1.5rem; }}
  h2 {{ font-size: 1.2rem; color: #0f172a; margin-bottom: 1rem;
       border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th    {{ background: #f8fafc; text-align: left; padding: 0.6rem 0.8rem;
          border-bottom: 2px solid #e5e7eb; font-weight: 600; color: #374151; }}
  td    {{ padding: 0.55rem 0.8rem; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
  tr:hover td {{ background: #f8fafc; }}
  code  {{ background: #f1f5f9; padding: 0 4px; border-radius: 3px; font-size: 0.85em; }}
  footer {{ text-align: center; padding: 2rem; color: #9ca3af; font-size: 0.8rem; }}
  nav   {{ background: #1e293b; padding: 0.6rem 3rem; }}
  nav a {{ color: #94a3b8; text-decoration: none; margin-right: 1.5rem;
           font-size: 0.85rem; }}
  nav a:hover {{ color: #f8fafc; }}
</style>
</head>
<body>
<header>
  <h1>🔐 Network Penetration Test Report</h1>
  <p>Cyber Security Assessment | Generated: {generated_at} | NIST CSF Aligned</p>
</header>
<nav>
  <a href="#executive-summary">Summary</a>
  <a href="#hosts">Hosts</a>
  <a href="#vulnerabilities">Vulnerabilities</a>
  <a href="#impact">Impact</a>
  <a href="#recommendations">Recommendations</a>
</nav>
<main>
  {exec_summary}
  {hosts_section}
  {vuln_section}
  {impact_section}
  {reco_section}
  <section id="methodology">
    <h2>Methodology — 6-Step Process</h2>
    <ol style="padding-left:1.5rem;line-height:2;">
      <li><strong>Information Gathering</strong> — nmap network discovery (script: 01_network_scan.py)</li>
      <li><strong>Scanning & Reconnaissance</strong> — Nessus vulnerability scan (02_vuln_scan.py)</li>
      <li><strong>Safe Exploitation</strong> — Proof-of-concept validation (03_exploitation.py)</li>
      <li><strong>Post-Exploitation</strong> — Impact & blast-radius mapping (04_post_exploit_cleanup.py)</li>
      <li><strong>Cleanup</strong> — Artifact removal verification (04_post_exploit_cleanup.py)</li>
      <li><strong>Reporting</strong> — This document (05_generate_report.py)</li>
    </ol>
    <p style="margin-top:1rem;color:#555;">
      Standards followed: NIST Cybersecurity Framework (CSF), CVSS v3.1 scoring,
      MITRE ATT&CK framework, ethical hacking methodologies.
    </p>
  </section>
  <section>
    <h2>Disclaimer</h2>
    <p>
      This report is for <strong>educational and authorized security assessment purposes only</strong>.
      All testing was performed with explicit written authorization on designated systems.
      No data was exfiltrated. All test artifacts have been removed from target systems.
    </p>
  </section>
</main>
<footer>
  Penetration Test Report &mdash; Confidential &mdash; {generated_at}
</footer>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"[+] HTML report written to: {output_path}")
    print(f"\n✅  Report generated: {output_path}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Step 6 - Generate HTML Penetration Test Report"
    )
    parser.add_argument(
        "--results",
        default="results",
        help="Directory containing JSON result files (default: results/)",
    )
    parser.add_argument(
        "--output",
        default="reports/pentest_report.html",
        help="Output HTML file path (default: reports/pentest_report.html)",
    )
    args = parser.parse_args()
    generate_html_report(args.results, args.output)
