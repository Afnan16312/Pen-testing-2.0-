#!/usr/bin/env python3
"""
Step 1: Information Gathering & Network Scanning
Uses nmap to discover all live hosts and open ports in the target range.
Aligns with NIST CSF - Identify (ID.AM): Asset Management
"""

import nmap
import json
import os
import argparse
from datetime import datetime
from utils.logger import setup_logger
from utils.report_builder import save_json

logger = setup_logger("network_scan")


def scan_network(target_range: str, output_dir: str = "results") -> dict:
    """
    Perform full network discovery scan on the given IP range.

    Args:
        target_range: CIDR notation e.g. '192.168.1.0/24'
        output_dir:   Directory to save raw scan results

    Returns:
        Dictionary of discovered hosts with open ports and service info
    """
    logger.info(f"[*] Starting network scan on: {target_range}")
    nm = nmap.PortScanner()

    # -sV  : Version detection
    # -O   : OS detection
    # -T4  : Aggressive timing (faster)
    # -Pn  : Skip host discovery (treat all as online)
    # --open : Only show open ports
    scan_args = "-sV -O -T4 -Pn --open"

    try:
        logger.info(f"[*] Running nmap with args: {scan_args}")
        nm.scan(hosts=target_range, arguments=scan_args)
    except nmap.PortScannerError as e:
        logger.error(f"[!] Nmap scan failed: {e}")
        raise

    results = {}

    for host in nm.all_hosts():
        host_info = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "os_match": [],
            "open_ports": [],
            "scan_time": datetime.now().isoformat(),
        }

        # OS Detection results
        if "osmatch" in nm[host]:
            for os_match in nm[host]["osmatch"]:
                host_info["os_match"].append(
                    {
                        "name": os_match.get("name", "Unknown"),
                        "accuracy": os_match.get("accuracy", "0"),
                    }
                )

        # Port & Service enumeration
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                port_data = nm[host][proto][port]
                if port_data["state"] == "open":
                    host_info["open_ports"].append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": port_data["state"],
                            "service": port_data.get("name", "unknown"),
                            "version": port_data.get("version", ""),
                            "product": port_data.get("product", ""),
                            "extrainfo": port_data.get("extrainfo", ""),
                        }
                    )

        results[host] = host_info
        logger.info(
            f"[+] Host: {host} | Ports: {len(host_info['open_ports'])} open"
        )

    # Save raw results
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"nmap_scan_{timestamp}.json")
    save_json(results, output_path)
    logger.info(f"[+] Scan results saved to: {output_path}")

    return results


def print_summary(results: dict):
    """Print a formatted summary of discovered hosts."""
    print("\n" + "=" * 60)
    print("  NETWORK SCAN SUMMARY")
    print("=" * 60)
    print(f"  Total hosts discovered: {len(results)}")
    total_ports = sum(len(h["open_ports"]) for h in results.values())
    print(f"  Total open ports found: {total_ports}")
    print("=" * 60)

    for ip, host in results.items():
        os_name = host["os_match"][0]["name"] if host["os_match"] else "Unknown OS"
        print(f"\n  Host: {ip} ({host['hostname'] or 'no hostname'})")
        print(f"  OS  : {os_name}")
        print(f"  Ports ({len(host['open_ports'])}):")
        for p in host["open_ports"]:
            svc = f"{p['product']} {p['version']}".strip()
            print(f"    [{p['port']}/{p['protocol']}]  {p['service']:15s}  {svc}")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Step 1 - Network Discovery Scanner (nmap)"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP range in CIDR notation (e.g. 192.168.1.0/24)",
    )
    parser.add_argument(
        "--output",
        default="results",
        help="Output directory for scan results (default: results/)",
    )
    args = parser.parse_args()

    scan_results = scan_network(args.target, args.output)
    print_summary(scan_results)
