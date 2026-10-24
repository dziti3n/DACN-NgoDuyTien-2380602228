---
name: mitre-attack-mapping
description: >-
  Use this skill to map cyber security observables, logs, and attacker activities to the MITRE ATT&CK
  Enterprise framework (Tactics, Techniques, Sub-techniques), enrich IOCs (IP, domain, hash, URL) with
  Threat Intelligence (AbuseIPDB, VirusTotal, CISA KEV), and structure threat intelligence context for SOC alerts.
---

# MITRE ATT&CK Mapping & Threat Intelligence Correlation

This skill enables SOC analysts and automated agents to systematically translate raw security signals into standardized MITRE ATT&CK techniques, correlate TTPs (Tactics, Techniques, and Procedures), and enrich indicators of compromise (IOCs).

---

## 1. Enterprise MITRE ATT&CK Core Matrix for SOC Operations

When analyzing security alerts, map adversary actions against the primary MITRE ATT&CK tactics:

```
[ TA0001: Initial Access ] ──> [ TA0002: Execution ] ──> [ TA0003: Persistence ] ──> [ TA0004: Priv Esc ]
              │                                                                                │
              ▼                                                                                ▼
[ TA0006: Credential Access ] ──> [ TA0007: Discovery ] ──> [ TA0011: C2 ] ──> [ TA0040: Impact ]
```

### High-Frequency Techniques in Linux/Host SOC Environments

| Technique ID | Technique Name | Common Observable / Log Signature | Detection & Telemetry Source |
| :--- | :--- | :--- | :--- |
| **T1110.001** | Brute Force: Password Guessing | Multiple `Failed password for ...` from same IP within short time window. | `/var/log/auth.log`, Event ID 4625 |
| **T1110.003** | Brute Force: Password Spraying | Low frequency `Failed password` across many distinct usernames from single IP. | `/var/log/auth.log`, Event ID 4625 |
| **T1078.003** | Valid Accounts: Local Accounts | Successful logon to local account (`Accepted password/publickey for root/admin`). | `/var/log/auth.log`, Event ID 4624 |
| **T1548.003** | Sudo and Sudo Caching | Execution of commands via `sudo`, edits to `/etc/sudoers`, or `sudo -l` enumeration. | `/var/log/auth.log`, auditd |
| **T1053.003** | Scheduled Task/Job: Cron | Edits to `/etc/crontab`, `/etc/cron.*`, or `/var/spool/cron/crontabs/<user>`. | Crontab logs, auditd, baseline diff |
| **T1098.004** | Account Manipulation: SSH Authorized Keys | Modifications to `~/.ssh/authorized_keys` or `/root/.ssh/authorized_keys`. | File integrity monitor, auditd |
| **T1059.004** | Command and Scripting: Unix Shell | Execution of bash/sh reverse shells, inline interpreters (`python -c`, `perl -e`). | Process execution telemetry, auditd |
| **T1046** | Network Service Discovery | Rapid port connection attempts, SYN probes across multiple port ranges. | UFW block logs, Suricata/Zeek |
| **T1070.002** | Indicator Removal: Clear Linux Logs | Truncation of `/var/log/auth.log`, `/var/log/wtmp`, `history -c`, rm `.bash_history`. | Shell audit, auditd file watch |
| **T1071.001** | C2: Web Protocols | Unusual HTTP/HTTPS outbound traffic to dynamic DNS or uncommon ports. | Proxy logs, Zeek HTTP, DNS queries |

---

## 2. IOC Extraction & Normalization

Extract and validate Indicators of Compromise (IOCs) using strict regex patterns before enrichment:

```python
import re

# Standard SOC Regex Patterns for IOC Extraction
IPV4_REGEX = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
SHA256_REGEX = r"\b[A-Fa-f0-9]{64}\b"
MD5_REGEX = r"\b[A-Fa-f0-9]{32}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
```

### Whitelist Filtering Before Threat Intel Query:
Always filter out RFC 1918 private IP spaces, loopbacks, and multicast ranges:
- `127.0.0.0/8` (Loopback)
- `10.0.0.0/8` (Private)
- `172.16.0.0/12` (Private)
- `192.168.0.0/16` (Private)
- `169.254.0.0/16` (Link-Local)
- `224.0.0.0/4` (Multicast)

---

## 3. Threat Intelligence Enrichment Playbook

When an external observable (IP, Hash, Domain) is identified:

### 1. IP Reputation (e.g., AbuseIPDB, VirusTotal, AlienVault OTX)
- **Abuse Score > 50%:** High probability of compromised botnet / residential proxy / bulletproof host.
- **Reported Attack Categories:** Check for `SSH Brute-Force (Category 18)`, `Port Scan (Category 14)`, `Web Exploit (Category 21)`.
- **Hosting Provider / ISP:** Classify as Cloud/VPS (DigitalOcean, AWS, OVH, Linode) vs Residential ISP vs Tor Exit Node.

### 2. File Hash Reputation (VirusTotal, MalwareBazaar)
- Positive detections $\ge 5$: Confirmed malicious payload.
- Review Sandbox behavioral tags (e.g., `drops-executable`, `persists-via-cron`, `spawns-shell`).

### 3. CISA Known Exploited Vulnerabilities (KEV) Catalog
- Cross-reference any observed CVE in network logs against the CISA KEV catalog to gauge weaponization level.

---

## 4. Standard MITRE Tagging Schema for Alerts & JSON Outputs

When producing structured SOC investigation output or alert notifications, format MITRE ATT&CK details systematically:

```json
{
  "mitre_attack": {
    "tactic": "Credential Access",
    "tactic_id": "TA0006",
    "technique": "Brute Force",
    "technique_id": "T1110",
    "sub_technique_id": "T1110.001",
    "sub_technique_name": "Password Guessing",
    "adversary_objective": "Attempting to compromise valid user credentials on SSH port 22.",
    "observable_evidence": "142 failed login attempts within 45 seconds targeting users: root, admin, test."
  },
  "threat_intel": {
    "indicator": "203.0.113.45",
    "type": "IPv4",
    "reputation_score": 87,
    "confidence": "HIGH",
    "asn": "AS16509",
    "actor_attribution": "Commodity SSH Botnet"
  }
}
```

---

## 5. Diamond Model Integration

For comprehensive threat reporting, correlate:
1. **Adversary:** IP, ASN, Geolocation, Known APT / Botnet signature.
2. **Capability:** Exploit tools (e.g., Hydra, Nmap, Metasploit, custom Python script).
3. **Infrastructure:** C2 server, Tor node, compromised staging VPS.
4. **Victim:** Targeted host, service (SSH, Web, Database), critical assets.
