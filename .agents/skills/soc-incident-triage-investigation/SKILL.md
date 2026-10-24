---
name: soc-incident-triage-investigation
description: >-
  Use this skill for SOC alert triage, security incident investigation, root cause analysis,
  evidence extraction across Linux/Windows authentication logs (auth.log, syslog, Event Viewer 4624/4625),
  ReAct-based cyber reasoning, false positive filtering, and determining attacker blast radius.
---

# SOC Incident Triage & Root Cause Investigation

This skill guides SOC Analysts (Tier 1/Tier 2) and Security Engineers through structured alert triage, multi-source evidence extraction, ReAct hypothesis testing, and root-cause analysis (RCA).

---

## 1. The SOC Alert Triage Methodology

Every security alert must pass through a 4-step triage pipeline:

```
[ Ingest Alert ] ──> [ 1. Enrich & Validate ] ──> [ 2. Formulate Hypothesis ] ──> [ 3. Collect Evidence ] ──> [ 4. Classify Verdict ]
```

### Alert Classification Categories:
- **True Positive (TP) - Malicious:** Confirmed adversary activity (e.g., automated brute force attack succeeded by unauthorized sudo privilege escalation).
- **True Positive (TP) - Benign (FP/Authorized):** Authorized administrative actions or benign security scanner (e.g., approved vulnerability scan from internal scanner IP).
- **False Positive (FP):** Erroneous detection trigger due to misconfigured software, benign software bug, or over-sensitive threshold.

---

## 2. ReAct Investigation Framework for Security

When investigating an alert, follow the **ReAct (Reasoning + Acting)** loop:

### Step 1: Thought (Formulate Hypothesis)
- Identify primary observable: Attacker IP, targeted username, target port, timestamp.
- Ask: What is the adversary attempting? (Initial Access, Credential Dumping, Lateral Movement, Persistence).

### Step 2: Action (Execute Read-Only Investigative Tools)
Never guess or hallucinate. Use non-disruptive, read-only inspection commands:

#### Linux Telemetry Inspection:
```bash
# 1. Investigate SSH authentication failures & successes
grep -E "Failed password|Accepted password|Accepted publickey" /var/log/auth.log | grep "<TARGET_IP>" | tail -n 50

# 2. Check for sudo privilege escalation attempts
grep -E "sudo:.*COMMAND" /var/log/auth.log | grep -v "known_benign_user" | tail -n 30

# 3. Inspect active listening ports and established external sockets
ss -tulpn
ss -tupna | grep ESTAB

# 4. Correlate processes running under suspicious users
ps aux --sort=-%mem | head -n 25
ps -ef | grep -E "python|bash|sh|perl|nc|curl|wget"

# 5. Check user session history
w
who
last -n 20
lastlog | grep -v "Never"
```

#### Windows Telemetry Inspection:
```powershell
# 1. Failed Logons (Event ID 4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 30 | 
  Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='Workstation';E={$_.Properties[11].Value}}, @{N='IP';E={$_.Properties[19].Value}}

# 2. Successful Logons (Event ID 4624 - specifically LogonType 3 Network or 10 RDP)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 30 | 
  Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}}, @{N='IP';E={$_.Properties[18].Value}}

# 3. Special Privilege Assignment (Event ID 4672) & New Process Creation (Event ID 4688)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 20 | 
  Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}}
```

### Step 3: Observation (Extract Atomic Evidence)
Document facts explicitly:
- Exact source IP(s), geographical ASN if available.
- Count of failed attempts vs successful logins.
- Specific usernames targeted (`root`, `admin`, `ubuntu`, `service_account`).
- Exact commands executed in the target window.

---

## 3. Severity Rating Matrix

| Severity | Criteria | Response SLA | Action Trigger |
| :--- | :--- | :--- | :--- |
| **CRITICAL (P1)** | Active root/admin compromise, ransomware activity, unauthorized sudo execution, critical baseline file tampering (`/etc/passwd`, `/etc/shadow`, `authorized_keys`). | < 15 minutes | Immediate host isolation, firewall block, emergency call-tree. |
| **HIGH (P2)** | Sustained high-frequency brute force (>20 attempts/min), port scanning coupled with exploit payloads, anomalous outbound connection to known C2 IP. | < 30 minutes | Target IP isolation, credential lock, deep process triage. |
| **MEDIUM (P3)** | Distributed slow-rate password spraying (<5 attempts/hour), policy violations (unauthorized utility usage like nmap/curl), unexpected cron job additions. | < 2 hours | Notify asset owner, inspect crontabs, tune detection rules. |
| **LOW (P4)** | Routine internet background noise, single failed login, benign port probe from unrouted subnet. | < 24 hours | Log for trend correlation, monitor for escalation. |

---

## 4. Blast Radius & Lateral Movement Assessment

Before closing any high-severity incident, determine:
1. **Did the attacker successfully authenticate?**
   - Check if an `Accepted password` or `Accepted publickey` occurred *after* failed attempts.
2. **Were any sessions spawned?**
   - Check `pam_unix(sshd:session): session opened for user ...`.
3. **Were elevated privileges acquired?**
   - Verify `sudo` log entries and `/etc/sudoers.d/` modifications.
4. **Did the adversary touch network shares or other internal hosts?**
   - Inspect internal traffic to RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

---

## 5. Structured Triage Checklist

- [ ] Alert details ingested (Time, Rule Name, Source IP, Affected Asset).
- [ ] Source IP cross-checked against internal whitelists (SOC workstation, monitoring server, gateway).
- [ ] Raw logs extracted for 30 minutes before and after the alert timestamp.
- [ ] Successful compromise confirmed or disproved with verified log evidence.
- [ ] Threat actor techniques categorized and severity assigned.
- [ ] Recommended containment action formulated (e.g., UFW block, session termination, password reset).
- [ ] Full chain of custody and evidence documented in incident notes.
