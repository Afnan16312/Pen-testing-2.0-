#!/usr/bin/env python3
"""
Step 2: Scanning & Reconnaissance - Vulnerability Assessment
Integrates with Nessus REST API to launch scans and pull CVE findings.
Aligns with NIST CSF - Identify (ID.RA): Risk Assessment
"""

import requests
import json
import time
import os
import argparse
from datetime import datetime
from utils.logger import setup_logger
from utils.report_builder import save_json

# Disable SSL warnings for self-signed Nessus certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = setup_logger("vuln_scan")

# ─── Nessus connection defaults ──────────────────────────────────────────────
NESSUS_HOST  = os.getenv("NESSUS_HOST",  "https://localhost:8834")
NESSUS_USER  = os.getenv("NESSUS_USER",  "admin")
NESSUS_PASS  = os.getenv("NESSUS_PASS",  "admin")
POLICY_NAME  = "Basic Network Scan"   # Built-in Nessus policy
SCAN_TIMEOUT = 600                     # Max seconds to wait for scan completion
POLL_INTERVAL = 15                     # Seconds between status polls


class NessusScanner:
    """Thin wrapper around the Nessus REST API."""

    def __init__(self, host: str, username: str, password: str):
        self.host    = host.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False
        self.token   = None
        self._login(username, password)

    # ── Authentication ────────────────────────────────────────────────────
    def _login(self, username: str, password: str):
        url = f"{self.host}/session"
        resp = self.session.post(url, json={"username": username, "password": password})
        resp.raise_for_status()
        self.token = resp.json()["token"]
        self.session.headers.update({"X-Cookie": f"token={self.token}"})
        logger.info("[+] Authenticated with Nessus")

    def logout(self):
        self.session.delete(f"{self.host}/session")
        logger.info("[*] Nessus session closed")

    # ── Policy helpers ────────────────────────────────────────────────────
    def get_policy_id(self, policy_name: str) -> int:
        resp = self.session.get(f"{self.host}/policies")
        resp.raise_for_status()
        for policy in resp.json().get("policies", []):
            if policy["name"] == policy_name:
                logger.info(f"[+] Policy found: '{policy_name}' (id={policy['id']})")
                return policy["id"]
        raise ValueError(f"Policy '{policy_name}' not found in Nessus")

    # ── Scan lifecycle ────────────────────────────────────────────────────
    def create_scan(self, name: str, targets: str, policy_id: int) -> int:
        payload = {
            "uuid": "ab4bacd2-05d6-44c3-9671-0d9052a313eb",
            "settings": {
                "name":        name,
                "text_targets": targets,
                "policy_id":   policy_id,
            },
        }
        resp = self.session.post(f"{self.host}/scans", json=payload)
        resp.raise_for_status()
        scan_id = resp.json()["scan"]["id"]
        logger.info(f"[+] Scan created (id={scan_id})")
        return scan_id

    def launch_scan(self, scan_id: int):
        resp = self.session.post(f"{self.host}/scans/{scan_id}/launch")
        resp.raise_for_status()
        logger.info(f"[*] Scan {scan_id} launched")

    def get_scan_status(self, scan_id: int) -> str:
        resp = self.session.get(f"{self.host}/scans/{scan_id}")
        resp.raise_for_status()
        return resp.json()["info"]["status"]

    def wait_for_completion(self, scan_id: int) -> bool:
        terminal = {"completed", "canceled", "aborted"}
        elapsed  = 0
        logger.info(f"[*] Waiting for scan {scan_id} to complete …")
        while elapsed < SCAN_TIMEOUT:
            status = self.get_scan_status(scan_id)
            logger.info(f"    Status: {status} ({elapsed}s elapsed)")
            if status in terminal:
                return status == "completed"
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
        logger.warning(f"[!] Scan timed out after {SCAN_TIMEOUT}s")
        return False

    # ── Results ───────────────────────────────────────────────────────────
    def get_vulnerabilities(self, scan_id: int) -> list:
        resp = self.session.get(f"{self.host}/scans/{scan_id}")
        resp.raise_for_status()
        data = resp.json()

        vulns = []
        for host in data.get("hosts", []):
            host_id = host["host_id"]
            host_ip = host["hostname"]

            detail_resp = self.session.get(
                f"{self.host}/scans/{scan_id}/hosts/{host_id}"
            )
            detail_resp.raise_for_status()
            host_detail = detail_resp.json()

            for vuln in host_detail.get("vulnerabilities", []):
                plugin_id = vuln["plugin_id"]
                plugin_resp = self.session.get(
                    f"{self.host}/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}"
                )
                plugin_data = plugin_resp.json() if plugin_resp.ok else {}
                plugin_attrs = plugin_data.get("info", {}).get("plugindescription", {}).get("pluginattributes", {})

                vulns.append(
                    {
                        "host":         host_ip,
                        "plugin_id":    plugin_id,
                        "plugin_name":  vuln.get("plugin_name", ""),
                        "severity":     vuln.get("severity", 0),
                        "severity_label": _severity_label(vuln.get("severity", 0)),
                        "cvss_base":    plugin_attrs.get("risk_information", {}).get("cvss_base_score", "N/A"),
                        "cve":          plugin_attrs.get("ref_information", {}).get("ref", []),
                        "description":  plugin_attrs.get("description", ""),
                        "solution":     plugin_attrs.get("solution", ""),
                        "port":         vuln.get("port", 0),
                        "protocol":     vuln.get("protocol", ""),
                    }
                )

        vulns.sort(key=lambda v: v["severity"], reverse=True)
        return vulns


def _severity_label(severity_int: int) -> str:
    mapping = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
    return mapping.get(severity_int, "Unknown")


def run_vulnerability_scan(targets: str, output_dir: str = "results") -> list:
    """
    Full end-to-end vulnerability scan: authenticate → create → launch → wait → extract.

    Args:
        targets:    Comma-separated IPs or ranges e.g. '192.168.1.0/24'
        output_dir: Directory to save results JSON

    Returns:
        List of vulnerability dictionaries sorted by severity (Critical first)
    """
    scanner = NessusScanner(NESSUS_HOST, NESSUS_USER, NESSUS_PASS)

    try:
        policy_id = scanner.get_policy_id(POLICY_NAME)
        scan_name = f"PenTest_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_id   = scanner.create_scan(scan_name, targets, policy_id)

        scanner.launch_scan(scan_id)
        completed = scanner.wait_for_completion(scan_id)

        if not completed:
            logger.error("[!] Scan did not complete successfully.")
            return []

        vulns = scanner.get_vulnerabilities(scan_id)
        logger.info(f"[+] Total vulnerabilities found: {len(vulns)}")

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(output_dir, f"nessus_vulns_{timestamp}.json")
        save_json(vulns, output_path)
        logger.info(f"[+] Vulnerabilities saved to: {output_path}")

        return vulns

    finally:
        scanner.logout()


def print_vuln_summary(vulns: list):
    """Print severity-grouped vulnerability summary."""
    from collections import Counter
    counts = Counter(v["severity_label"] for v in vulns)

    print("\n" + "=" * 60)
    print("  VULNERABILITY SCAN SUMMARY")
    print("=" * 60)
    for label in ["Critical", "High", "Medium", "Low", "Info"]:
        bar = "█" * counts.get(label, 0)
        print(f"  {label:<10}  {counts.get(label, 0):>3}  {bar}")
    print(f"\n  TOTAL: {len(vulns)} findings")
    print("=" * 60)

    print("\n  TOP 10 CRITICAL / HIGH FINDINGS:")
    print("-" * 60)
    shown = 0
    for v in vulns:
        if v["severity_label"] in ("Critical", "High") and shown < 10:
            print(f"  [{v['severity_label']:8}] {v['host']:15}:{v['port']:<5}  CVSS:{v['cvss_base']}")
            print(f"           {v['plugin_name']}")
            print()
            shown += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Step 2 - Vulnerability Scanner (Nessus API)"
    )
    parser.add_argument(
        "--targets",
        required=True,
        help="Target IPs or CIDR range (e.g. 192.168.1.0/24)",
    )
    parser.add_argument(
        "--output",
        default="results",
        help="Output directory (default: results/)",
    )
    args = parser.parse_args()

    vulns = run_vulnerability_scan(args.targets, args.output)
    print_vuln_summary(vulns)
