# 🔐 Network Penetration Testing Toolkit

> **A complete, automated 6-step network penetration testing pipeline built in Python — from host discovery through to a professional HTML report.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NIST CSF](https://img.shields.io/badge/Standard-NIST%20CSF-orange.svg)](https://www.nist.gov/cyberframework)
[![CVSS](https://img.shields.io/badge/Scoring-CVSS%20v3.1-red.svg)](https://www.first.org/cvss/)
[![Ethics](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-critical.svg)](#disclaimer)

---

## 📋 Project Overview

This toolkit automates a real-world **network penetration test** — the kind conducted by professional ethical hackers to find weaknesses before attackers do.

Think of it like hiring a friendly "expert burglar" to try every door and window of your network. This code does exactly that, systematically, following industry standards.

**What it does in plain English:**
- 🔍 Scans your network to find every device (like making a map of all doors/windows)
- 🔬 Tests each device for known security weaknesses
- 🧪 Safely confirms which weaknesses are actually exploitable
- 📊 Maps the real-world impact of each confirmed finding
- 📄 Produces a professional HTML report with prioritised fixes

**Findings format output:**

| Severity | CVSS Score | What It Means |
|----------|-----------|----------------|
| 🚨 Critical | 9.0–10.0 | Attacker can take control right now — fix in 24h |
| ⚠️ High | 7.0–8.9 | Direct data theft/damage risk — fix in 7 days |
| 🔔 Medium | 4.0–6.9 | Indirect risk when combined with other flaws |
| ℹ️ Low | 0.1–3.9 | Poor practice — fix in next maintenance window |

---

## 🏗️ Project Structure

```
pentest-toolkit/
├── run_pentest.py              # 🚀 Master pipeline — run all steps
│
├── scripts/
│   ├── 01_network_scan.py      # Step 1: nmap host + port discovery
│   ├── 02_vuln_scan.py         # Step 2: Nessus vulnerability scan (API)
│   ├── 03_exploitation.py      # Step 3: Safe proof-of-concept checks
│   ├── 04_post_exploit_cleanup.py  # Steps 4+5: Impact mapping + cleanup
│   └── 05_generate_report.py   # Step 6: HTML report generator
│
├── utils/
│   ├── logger.py               # Shared logger (console + file)
│   └── report_builder.py       # JSON save/load helpers
│
├── results/                    # Auto-created — raw JSON outputs per run
│   └── logs/                   # Per-script log files
│
├── reports/                    # Auto-created — final HTML reports
│
├── requirements.txt
└── README.md
```

---

## ⚙️ The 6-Step Pipeline

```
  Target Range
      │
      ▼
┌─────────────────────┐
│  Step 1             │  01_network_scan.py
│  Network Discovery  │  nmap -sV -O -T4
│  (Who is out there?)│
└────────┬────────────┘
         │ host list + open ports
         ▼
┌─────────────────────┐
│  Step 2             │  02_vuln_scan.py
│  Vulnerability Scan │  Nessus REST API
│  (What's broken?)   │
└────────┬────────────┘
         │ CVE findings + CVSS scores
         ▼
┌─────────────────────┐
│  Step 3             │  03_exploitation.py
│  Safe Exploitation  │  impacket + nmap scripts
│  (Is it real?)      │
└────────┬────────────┘
         │ confirmed evidence
         ▼
┌─────────────────────┐
│  Steps 4 + 5        │  04_post_exploit_cleanup.py
│  Impact + Cleanup   │  MITRE ATT&CK mapping
│  (What's at risk?)  │
└────────┬────────────┘
         │ impact assessment + clean state
         ▼
┌─────────────────────┐
│  Step 6             │  05_generate_report.py
│  HTML Report        │  Full professional report
│  (What to do?)      │
└─────────────────────┘
         │
         ▼
  reports/pentest_report.html
```

---

## 🛠️ Tools Used

| Tool | Purpose | Script |
|------|---------|--------|
| **nmap** | Network scanner — discovers hosts, ports, OS, services | Step 1 |
| **Nessus** | Vulnerability scanner — checks 60,000+ known CVEs | Step 2 |
| **impacket** | SMB protocol library — validates null session vulnerabilities | Step 3 |
| **nmap scripts** | SSH/SMB algorithm enumeration | Step 3 |

---

## 🚀 Quick Start

### Prerequisites

```bash
# 1. Python 3.10+
python --version

# 2. nmap installed on your system
nmap --version          # macOS: brew install nmap | Ubuntu: apt install nmap

# 3. Nessus Essentials (free) — https://www.tenable.com/products/nessus/nessus-essentials
#    Start it: sudo /etc/init.d/nessusd start
```

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/pentest-toolkit.git
cd pentest-toolkit
pip install -r requirements.txt
```

### Configure Nessus credentials

```bash
export NESSUS_HOST="https://localhost:8834"
export NESSUS_USER="admin"
export NESSUS_PASS="your_nessus_password"
```

### Run the full pipeline

```bash
# Full pipeline (requires Nessus)
python run_pentest.py --target 192.168.1.0/24

# Skip Nessus if not installed
python run_pentest.py --target 192.168.1.0/24 --skip-nessus

# Custom output locations
python run_pentest.py --target 10.0.0.0/24 --output my_results --report my_report.html
```

### Run individual steps

```bash
# Step 1 only — network discovery
python scripts/01_network_scan.py --target 192.168.1.0/24

# Step 2 only — vulnerability scan
python scripts/02_vuln_scan.py --targets 192.168.1.10,192.168.1.11

# Step 3 only — exploitation checks
python scripts/03_exploitation.py --hosts 192.168.1.10,192.168.1.11

# Step 4+5 — post-exploitation + cleanup
python scripts/04_post_exploit_cleanup.py --evidence results/exploitation_evidence_TIMESTAMP.json

# Step 6 — generate report from existing results
python scripts/05_generate_report.py --results results/ --output reports/report.html
```

---

## 📊 Sample Output

### Terminal output (Step 3 — Exploitation)

```
===========================================================
  EXPLOITATION CHECK RESULTS
===========================================================
  Checks run    : 9
  Confirmed     : 2  ← NEEDS IMMEDIATE FIX
  Not vulnerable: 7
===========================================================

  ❗ SMB Null Session
     Host     : 192.168.1.15
     Severity : Critical  (CVSS 10.0)
     Proof    : Anonymous SMB login succeeded (no credentials required)
     Shares   : SHARE1 (23 files), BACKUP (41 files)

  ❗ SMBv1 Protocol Detection
     Host     : 192.168.1.20
     Severity : High  (CVSS 9.3)
     Proof    : SMBv1 protocol is enabled and supported by this host
```

### HTML Report preview

The generated `reports/pentest_report.html` includes:
- **Executive summary** with severity breakdown table
- **Host inventory** from nmap (OS, ports, services)
- **Full vulnerability table** (sortable by severity/CVSS)
- **Impact assessment cards** with MITRE ATT&CK mapping
- **Colour-coded remediation roadmap** (P1 → P4)
- **Methodology documentation** for compliance

---

## 🔒 Checks Performed (Step 3)

| Check | CVE / Issue | CVSS | Severity |
|-------|------------|------|----------|
| SMB Null Session | Open share without auth | 10.0 | 🚨 Critical |
| SMBv1 Detection | EternalBlue / MS17-010 risk | 9.3 | ⚠️ High |
| Weak SSH Algorithms | arcfour, 3des-cbc, blowfish | 7.4 | ⚠️ High |

---

## 📐 Standards & Frameworks

| Standard | How it's applied |
|----------|-----------------|
| **NIST Cybersecurity Framework** | Each step maps to Identify / Protect / Detect / Respond |
| **CVSS v3.1** | All vulnerabilities scored using industry-standard metric |
| **MITRE ATT&CK** | Confirmed findings mapped to adversary tactics/techniques |
| **Ethical hacking methodology** | 6-step process: Recon → Scan → Exploit → Post → Clean → Report |

---

## 📁 Output Files

After a run, `results/` will contain:

| File | Contents |
|------|----------|
| `nmap_scan_TIMESTAMP.json` | All discovered hosts, ports, services, OS |
| `nessus_vulns_TIMESTAMP.json` | All CVE findings sorted by severity |
| `exploitation_evidence_TIMESTAMP.json` | Proof-of-concept confirmation results |
| `impact_assessment_TIMESTAMP.json` | Blast radius + MITRE mapping per finding |
| `cleanup_verification_TIMESTAMP.json` | Confirmation no artifacts remain |
| `logs/SCRIPT_DATE.log` | Detailed debug log per script |

---

## 🧪 Running Tests

```bash
pytest tests/ -v --cov=scripts --cov=utils
```

---

## ⚠️ Disclaimer

**This toolkit is for authorized penetration testing and educational purposes only.**

- ✅ Only run against systems you own or have explicit written permission to test
- ✅ All exploitation checks are **read-only** and **non-destructive**
- ✅ No data is exfiltrated or modified on target systems
- ❌ Unauthorized use against systems you don't own is **illegal** under computer fraud laws worldwide

By using this tool you agree to use it only in lawful, authorized contexts.

---

## 📚 References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Nessus API Documentation](https://developer.tenable.com/reference/navigate)
- [impacket library](https://github.com/fortra/impacket)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
