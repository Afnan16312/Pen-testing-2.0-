# Pen-testing-2.0-
# Cyber Security Assessment: Network Penetration Testing Report

## Project Overview (In Plain English)

Imagine you have a house. You lock the doors and windows, but how do you know if a burglar could still find a way in? This project is like hiring a friendly, expert burglar (called an "ethical hacker") to try to break into a company's computer network *before* a real criminal does.

This report documents a simulated cyber-attack on a computer network. The goal was to find weaknesses, understand how serious they are, and provide a clear plan to fix them. Think of it as a detailed health check-up for a company's digital security.

## What Was Tested?

A computer network with servers and shared files. The tester was given very little initial information (just a hint about the network's address range), similar to how a real attacker would operate.

## Key Findings (What We Found)

The test discovered **36 potential security gaps**. Think of these as unlocked windows or weak locks. Here are the most important ones, ranked by severity:

| Severity Level | What It Means | Example Finding |
| :--- | :--- | :--- |
| **Critical** 🚨 | Immediate, severe threat. An attacker could take control right now. | An open network file share (like a shared folder) that anyone on the internet could access without a password. |
| **High** ⚠️ | Direct threat. An attacker could steal or damage important information. | Windows file shares that could be accessed without the right permissions. |
| **Medium** 🔔 | Indirect threat. Could be combined with other weaknesses to cause a breach. | Weak encryption methods that could allow an attacker to secretly listen in on communications. |
| **Low** ℹ️ | No immediate threat, but indicates poor security practices. | Using outdated or weak security settings that could become a problem later. |

**The most critical vulnerability had a perfect risk score of 10/10** - meaning it needed to be fixed immediately.

## Tools Used (The Equipment)

Just like a mechanic uses special tools, a penetration tester uses software tools. The main tools for this project were:

- **Nmap** - A network scanner. Used to discover all the devices connected to the network (like finding all the doors and windows in a house).
- **Nessus** - A vulnerability scanner. Used to check each device for known weaknesses (like testing each lock to see if it's broken).

## Recommendations (How to Fix the Problems)

Based on the findings, here is the suggested action plan:

1.  **Fix Critical Issues First:** Immediately secure the open network file shares so only authorized users can access them.
2.  **Strengthen Weak Configurations:** Update the server settings to use modern, strong encryption for all communications (SSH and SMB).
3.  **Regular Testing:** Perform these tests at least once or twice a month. Security is not a one-time fix; it requires continuous checking.
4.  **Keep Software Updated:** Apply security patches to all systems regularly.

## Sample Proof (What the Evidence Looks Like)

During the test, we captured screenshots as proof of the vulnerabilities. Here is an example of discovering an open network share:

*(Note: The actual report contains multiple screenshots showing each step of the discovery process.)*

## The 6-Step Process We Followed

1.  **Information Gathering:** Scanning the network to understand what devices exist.
2.  **Scanning & Reconnaissance:** Identifying potential weak points on those devices.
3.  **Exploitation (Safe):** Attempting to use the weak points to gain access, just like a real attacker would.
4.  **Post-Exploitation:** Documenting what data or systems could be accessed.
5.  **Clean Up:** Removing any changes made during the test so another attacker can't use them.
6.  **Reporting:** Creating this document with clear findings and recommendations.

## Why This Matters

For a business, a single cyber-attack can cost millions of dollars, ruin reputation, and lead to legal problems. This report provides a roadmap to prevent that from happening. It transforms a complex technical problem into a clear, prioritized action list.

## About the Author

This penetration test was conducted as a professional security assessment. The author follows industry standards including the **NIST Cybersecurity Framework** (a respected government guideline for security best practices).

## References & Standards Followed

- NIST Cybersecurity Framework
- Industry-standard vulnerability scoring (CVSS)
- Ethical hacking methodologies

## Disclaimer

This report is for educational and professional security assessment purposes only. All testing was performed with proper authorization on designated systems.

---
*Generated on: [Current Date] | Report Version: 2.2*
