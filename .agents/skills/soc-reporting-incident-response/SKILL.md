---
name: soc-reporting-incident-response
description: >-
  Use this skill to author standardized SOC incident reports (NIST SP 800-61, ISO 27035), generate executive
  summaries, format technical evidence tables and timelines, craft HTML alert emails, produce structured SIEM
  audit trails, and structure post-incident reviews (PIR).
---

# SOC Incident Reporting & Incident Response Documentation

This skill provides guidelines, templates, and formatting standards for drafting professional SOC incident reports, executive briefings, real-time alert notifications, and post-incident review (PIR) documentation.

---

## 1. Incident Response Lifecycle (NIST SP 800-61 Rev. 2)

```
[ 1. Preparation ] ──> [ 2. Detection & Analysis ] ──> [ 3. Containment, Eradication & Recovery ]
                                                                      │
                                   [ 4. Post-Incident Activity (Lessons Learned) ] <──┘
```

Every incident report must address the relevant phase of this lifecycle.

---

## 2. Standard SOC Incident Report Template (Markdown)

```markdown
# 🛡️ SOC Incident Investigation Report

**Incident ID:** INC-2026-1024-001  
**Severity:** HIGH (P2)  
**Status:** CONTAINED / RESOLVED  
**Lead Investigator:** SOC Agent / Security Analyst  
**Date & Time (UTC):** 2026-10-24 15:30:00 UTC  
**Affected Assets:** `srv-linux-prod01` (192.168.56.101)  

---

## 1. Executive Summary
Between 15:28:10 UTC and 15:29:45 UTC, an automated brute-force attack originating from IP `203.0.113.88` targeted the SSH service on host `srv-linux-prod01`. Over 140 unauthorized authentication attempts were detected against root and service accounts. The AI SOC defense system successfully detected the anomaly, initiated read-only ReAct investigation, and executed an automated UFW firewall containment rule within 60 seconds of trigger threshold. No administrative session was compromised, and zero unauthorized data access occurred.

---

## 2. Technical Incident Details & Threat Profile

| Field | Detail |
| :--- | :--- |
| **Primary Attacker IP** | `203.0.113.88` (ASN: AS16509, Location: US) |
| **Attack Vector** | External SSH Service (Port 22/tcp) |
| **MITRE ATT&CK Tactic** | Credential Access (TA0006) |
| **MITRE Technique** | Brute Force: Password Guessing (T1110.001) |
| **Secondary Threat** | Potential Sudo Abuse Attempt (T1548.003) |
| **Threat Confidence** | HIGH (98%) |

---

## 3. Chronological Incident Timeline

- **15:28:10 UTC** - First failed SSH login attempt detected from `203.0.113.88` targeting user `root`.
- **15:28:45 UTC** - Alert threshold exceeded (30 failed attempts in 35 seconds).
- **15:28:50 UTC** - Autonomous investigation initiated: `search_auth_logs` executed.
- **15:28:58 UTC** - Policy Engine verified target IP against whitelist (Passed).
- **15:29:02 UTC** - Active Defense: `soc-block-ip 203.0.113.88` executed; UFW rule verified.
- **15:29:05 UTC** - Alert notification dispatched to security distribution list.

---

## 4. Evidence & Artifact Chain of Custody

### Log Excerpt (`/var/log/auth.log`):
```text
Oct 24 15:28:10 srv-linux-prod01 sshd[4012]: Failed password for root from 203.0.113.88 port 51234 ssh2
Oct 24 15:28:11 srv-linux-prod01 sshd[4015]: Failed password for root from 203.0.113.88 port 51235 ssh2
Oct 24 15:28:12 srv-linux-prod01 sshd[4018]: Failed password for invalid user admin from 203.0.113.88 port 51236 ssh2
```

### Active Defense Verification:
```text
$ sudo ufw status numbered
[ 1] DENY IN  203.0.113.88  # Added by SOC Agent at 15:29:02 UTC (TTL: 15m)
```

---

## 5. Root Cause & Strategic Recommendations

### Root Cause:
The host exposed standard SSH port 22/tcp directly without rate-limiting (fail2ban) or IP restriction.

### Hardening Recommendations:
1. **Immediate:** Rotate passwords for any user accounts that received elevated brute-force attempts.
2. **Short-Term:** Enforce public-key authentication only (`PasswordAuthentication no` in `/etc/ssh/sshd_config`).
3. **Mid-Term:** Restrict SSH access to authorized VPN/Jumpbox IP ranges using UFW rules.
```

---

## 3. Real-Time HTML Alert Notification Standard

Alert emails sent by automated SOC systems (e.g., `notifier.py`) must follow high-contrast, clear information hierarchy:

```html
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 650px; background: #0f172a; color: #f8fafc; border-radius: 8px; overflow: hidden; border: 1px solid #334155;">
  <div style="background: #dc2626; padding: 16px 24px;">
    <h2 style="margin: 0; color: #ffffff; font-size: 20px;">🚨 SOC HIGH ALERT: SSH Brute Force Blocked</h2>
  </div>
  <div style="padding: 24px;">
    <p style="font-size: 15px; line-height: 1.5; color: #cbd5e1;">The automated defense system isolated an attacker IP after detecting rapid authentication failures.</p>
    <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
      <tr style="border-bottom: 1px solid #334155;"><td style="padding: 8px 0; color: #94a3b8;">Attacker IP:</td><td style="padding: 8px 0; font-family: monospace; font-weight: bold; color: #38bdf8;">203.0.113.88</td></tr>
      <tr style="border-bottom: 1px solid #334155;"><td style="padding: 8px 0; color: #94a3b8;">MITRE Technique:</td><td style="padding: 8px 0; font-family: monospace;">T1110.001 (Password Guessing)</td></tr>
      <tr style="border-bottom: 1px solid #334155;"><td style="padding: 8px 0; color: #94a3b8;">Action Taken:</td><td style="padding: 8px 0; color: #4ade80;">UFW Rule Inserted (TTL: 15m)</td></tr>
      <tr><td style="padding: 8px 0; color: #94a3b8;">Policy Status:</td><td style="padding: 8px 0; color: #4ade80;">Approved by Deterministic Engine</td></tr>
    </table>
  </div>
</div>
```

---

## 4. Structured Audit Log Standard (SIEM-Ready JSON)

Log every autonomous action in an RFC 5424 / ECS-compatible JSON format:

```json
{
  "@timestamp": "2026-10-24T15:29:02.124Z",
  "event": {
    "category": "intrusion_detection",
    "type": "containment",
    "action": "firewall_rule_applied",
    "outcome": "success"
  },
  "source": {
    "ip": "203.0.113.88"
  },
  "host": {
    "name": "srv-linux-prod01",
    "ip": "192.168.56.101"
  },
  "agent": {
    "id": "soc-autonomous-daemon",
    "version": "2.4.0"
  },
  "rule": {
    "id": "T1110_BRUTE_FORCE",
    "severity": "HIGH"
  }
}
```
