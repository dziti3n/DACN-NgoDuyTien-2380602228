---
name: threat-hunting-detection-engineering
description: >-
  Use this skill to design, write, test, and tune cyber security detection rules (Sigma, Python regex heuristics,
  YARA, SIEM queries), perform proactive threat hunting across Linux/Windows systems, detect Living-off-the-Land
  Binaries (LOLBins), unauthorized persistence, and file integrity baseline tampering.
---

# Threat Hunting & Detection Engineering

This skill provides methodologies, templates, and procedures for designing high-fidelity detection rules, tuning out false positives, and conducting proactive threat hunting across host and network telemetry.

---

## 1. Detection Engineering Lifecycle

```
[ Threat Intelligence / Hypotheses ] ──> [ Telemetry Validation ] ──> [ Rule Specification (Sigma/Python) ]
                                                                                   │
[ Production Deployment ] <── [ False Positive Tuning ] <── [ Unit & Adversary Emulation Tests ]
```

### Core Design Rules for High-Fidelity Detections:
1. **Focus on Behaviors over Indicators:** Indicators (IPs, hashes) change rapidly. Focus on adversary behaviors, API calls, and command-line patterns.
2. **Deterministic Thresholds & Windows:** Specify exact time sliding windows (e.g., $\ge 5$ failed authentications within 60 seconds from the same source).
3. **Defense Against Evasion:** Account for spaces, case variations, quotation marks, and shell piping (`curl | bash`).
4. **Context Enrichment:** Include MITRE ATT&CK technique IDs, severity, description, and triage steps in rule metadata.

---

## 2. Standard Detection Formats

### Format A: Sigma Rule (Universal SIEM Specification)

```yaml
title: SSH Brute Force and Suspicious Elevation Attempt
id: 8f9b2c34-1234-4567-89ab-cdef01234567
status: production
description: Detects rapid authentication failures followed by suspicious command execution or privileged account activity.
references:
  - https://attack.mitre.org/techniques/T1110/001/
author: SOC Detection Team
date: 2026/10/24
logsource:
  product: linux
  service: auth
detection:
  selection_ssh_fail:
    message|contains: 'Failed password for'
  selection_sudo_abuse:
    message|contains:
      - 'sudo:   '
      - 'COMMAND=/bin/bash'
      - 'COMMAND=/bin/sh'
      - 'COMMAND=/usr/bin/su'
  timeframe: 1m
  condition: selection_ssh_fail | count() > 5 or selection_sudo_abuse
falsepositives:
  - Automated administrative configuration scripts (Ansible, Puppet)
  - Authorized vulnerability penetration tests
level: high
tags:
  - attack.credential_access
  - attack.t1110.001
  - attack.privilege_escalation
  - attack.t1548.003
```

### Format B: Python Stateful Detection Logic (SOC Agent Pattern)

```python
import re
from datetime import datetime, timedelta
from collections import defaultdict

class SSHBruteForceDetector:
    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.ip_failures = defaultdict(list)
        # Regex to capture IP and user
        self.fail_regex = re.compile(
            r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        )

    def analyze_log_line(self, line: str, timestamp: datetime) -> dict | None:
        match = self.fail_regex.search(line)
        if not match:
            return None
            
        ip = match.group("ip")
        user = match.group("user")
        
        # Purge expired records outside sliding window
        cutoff = timestamp - self.window
        self.ip_failures[ip] = [t for t in self.ip_failures[ip] if t >= cutoff]
        self.ip_failures[ip].append(timestamp)
        
        if len(self.ip_failures[ip]) >= self.threshold:
            return {
                "rule_name": "SSH_BRUTEFORCE_DETECTED",
                "severity": "HIGH",
                "source_ip": ip,
                "targeted_user": user,
                "attempt_count": len(self.ip_failures[ip]),
                "window_seconds": self.window.total_seconds(),
                "mitre_id": "T1110.001"
            }
        return None
```

---

## 3. Threat Hunting Playbooks

### Playbook 1: Hunting for Living-off-the-Land Binaries (LOLBins) & Reverse Shells
Adversaries frequently use pre-installed utilities to bypass antivirus:

```bash
# 1. Look for interactive shells spawned from network utilities
ps -ef | grep -E "(nc|netcat|ncat|socat|bash -i|sh -i|python.*pty|perl.*exec)" | grep -v grep

# 2. Check for processes with deleted binaries still running in memory
ls -al /proc/*/exe 2>/dev/null | grep "\(deleted\)"

# 3. Detect outbound connections from unexpected executables
ss -antp | grep -E "ESTAB" | grep -v -E "(sshd|systemd|cron|nginx|apache2)"

# 4. Check writable sticky bit directories for compiled/hidden payloads
find /tmp /var/tmp /dev/shm -type f -perm -111 -exec ls -la {} +
```

### Playbook 2: Hunting for Unauthorized Host Persistence

Adversaries establish persistence across system reboots:

```bash
# 1. Audit crontabs across all users and system drop-in directories
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/crontabs/

# 2. Inspect recently created or enabled systemd units
systemctl list-unit-files --state=enabled --type=service | grep -v -E "systemd|dbus|networking"
find /etc/systemd/system /lib/systemd/system -type f -mtime -7

# 3. Audit SSH authorized_keys modifications
find /home /root -name "authorized_keys" -exec stat -c "%y %n" {} +
# Check for recently injected keys
grep -H "" /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null

# 4. Check for unauthorized sudoers changes
ls -la /etc/sudoers.d/
grep -v "^#" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -E "NOPASSWD|ALL=\(ALL\)"
```

### Playbook 3: Integrity Baseline Auditing

Compare the running host state against a known-good cryptographic baseline (e.g., `baseline.json`):

```bash
# Verify checksums of critical binaries and authentication configuration
sha256sum /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /bin/bash /bin/login

# Compare package manager database integrity (Debian/Ubuntu)
dpkg -V | grep -E "usr/bin|usr/sbin|etc"
```

---

## 4. False Positive Suppression Best Practices

1. **Specific Exception Filters:** Avoid broad suppressions. Match on `source_ip + account + binary_hash`.
2. **Maintenance Windows:** Integrate with orchestration signals to suppress alerts during scheduled system upgrades.
3. **Peer Group Baselines:** If every host in a cluster runs a specific health check script, treat it as a cluster baseline rather than an anomaly.
