import json
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

WINDOW = timedelta(minutes=5)
BRUTEFORCE_THRESHOLD = 5
IGNORED_USERS = {"agent_soc"}

# Các lệnh sudo có tính chất nhạy cảm/nguy hiểm cao
DANGEROUS_SUDO_COMMANDS = [
    (re.compile(r"(?:^|\s)(?:/(?:usr/)?(?:bin|sbin)/)?(?:bash|sh|zsh|dash)(?:\s|$)"), "spawn_root_shell"),
    (re.compile(r"(?:^|\s)(?:/(?:usr/)?(?:bin|sbin)/)?su(?:\s+-)?(?:\s|$)"), "switch_user_root"),
    (re.compile(r"cat\s+.*(?:/etc/shadow|/etc/sudoers|/etc/gshadow)"), "read_sensitive_credentials"),
    (re.compile(r"chmod\s+(?:777|\+s)\s+"), "privilege_file_permission_change"),
    (re.compile(r"(?:useradd|adduser|usermod\s+-aG\s+(?:sudo|root|wheel))"), "privilege_account_tampering"),
    (re.compile(r"rm\s+-rf\s+/var/log"), "log_tampering_erasure"),
]


@dataclass
class Alert:
    rule: str
    severity_hint: str
    summary: str
    first_seen: str
    last_seen: str
    details: dict

    def to_dict(self):
        res = asdict(self)
        flat = {**res.pop("details"), **res}
        return flat


def alert_to_dict(a):
    if isinstance(a, dict):
        return a
    if hasattr(a, "to_dict"):
        return a.to_dict()
    return asdict(a)


# ---------- RULE 1: Phát hiện dò mật khẩu SSH (SSH Bruteforce) ----------
def detect_ssh_bruteforce(events):
    events = sorted(events, key=lambda e: e.ts)
    fails = {}
    for e in events:
        if e.event_type == "ssh_failed" and e.src_ip and e.user not in IGNORED_USERS:
            fails.setdefault(e.src_ip, []).append(e)

    alerts = []
    for ip, evs in fails.items():
        i = 0
        while i < len(evs):
            j = i
            while j + 1 < len(evs) and evs[j + 1].ts - evs[j].ts <= WINDOW:
                j += 1
            burst = evs[i:j + 1]
            i = j + 1

            total_fails = sum(b.count for b in burst)
            if total_fails < BRUTEFORCE_THRESHOLD:
                continue

            first, last = burst[0].ts, burst[-1].ts
            success = sorted({
                a.user for a in events
                if a.event_type == "ssh_accepted" and a.src_ip == ip
                and a.user not in IGNORED_USERS
                and first <= a.ts <= last + WINDOW
            })

            alerts.append(Alert(
                rule="ssh_bruteforce",
                severity_hint="critical" if success else "high",
                summary=f"Phát hiện dò mật khẩu SSH từ {ip}: {total_fails} lần thử thất bại, {len(success)} user thành công sau đó.",
                first_seen=first.isoformat(),
                last_seen=last.isoformat(),
                details={
                    "src_ip": ip,
                    "total_failures": total_fails,
                    "users_tried": sorted({b.user for b in burst if b.user}),
                    "invalid_user_failures": sum(b.count for b in burst if b.user_exists is False),
                    "success_after_failures": success,
                }
            ))
    return alerts


# ---------- RULE 2: Phát hiện lạm dụng / leo thang đặc quyền Sudo (Sudo Abuse) ----------
def detect_sudo_abuse(events):
    events = sorted(events, key=lambda e: e.ts)
    alerts = []

    # 1. Phát hiện user KHÔNG trong sudoers nhưng cố tình chạy lệnh sudo
    unauthorized_attempts = [e for e in events if e.event_type == "sudo_not_in_sudoers" and e.user not in IGNORED_USERS]
    for e in unauthorized_attempts:
        alerts.append(Alert(
            rule="sudo_unauthorized_attempt",
            severity_hint="high",
            summary=f"Tài khoản không có quyền '{e.user}' cố tình thực thi lệnh đặc quyền sudo: {e.detail}",
            first_seen=e.ts.isoformat(),
            last_seen=e.ts.isoformat(),
            details={
                "user": e.user,
                "detail": e.detail,
                "attempt_type": "user_not_in_sudoers",
            }
        ))

    # 2. Phát hiện nhập sai mật khẩu sudo nhiều lần (>= 3 lần thất bại)
    auth_fails = {}
    for e in events:
        if e.event_type == "sudo_auth_failure" and e.user and e.user not in IGNORED_USERS:
            auth_fails.setdefault(e.user, []).append(e)

    for user, evs in auth_fails.items():
        total_fail_count = sum(ev.count for ev in evs)
        if total_fail_count >= 3:
            first, last = evs[0].ts, evs[-1].ts
            alerts.append(Alert(
                rule="sudo_auth_burst_failure",
                severity_hint="medium",
                summary=f"Tài khoản '{user}' nhập sai mật khẩu sudo {total_fail_count} lần liên tiếp.",
                first_seen=first.isoformat(),
                last_seen=last.isoformat(),
                details={
                    "user": user,
                    "total_failures": total_fail_count,
                    "first_seen": first.isoformat(),
                    "last_seen": last.isoformat(),
                }
            ))

    # 3. Phát hiện thực thi các lệnh sudo nguy hiểm cao (spawning shell, tampering creds)
    sudo_commands = [e for e in events if e.event_type == "sudo_command" and e.user not in IGNORED_USERS]
    for e in sudo_commands:
        cmd_text = e.detail or ""
        for pattern, reason in DANGEROUS_SUDO_COMMANDS:
            if pattern.search(cmd_text):
                alerts.append(Alert(
                    rule="sudo_suspicious_command",
                    severity_hint="high",
                    summary=f"Tài khoản '{e.user}' thực thi lệnh sudo có mức độ rủi ro cao ({reason}): {cmd_text}",
                    first_seen=e.ts.isoformat(),
                    last_seen=e.ts.isoformat(),
                    details={
                        "user": e.user,
                        "command": cmd_text,
                        "risk_category": reason,
                    }
                ))
                break

    return alerts


# ---------- RULE 3: Phát hiện thay đổi tài khoản bất thường ngoài Baseline ----------
def detect_baseline_account_tampering(events, baseline_path="baseline.json"):
    if not os.path.exists(baseline_path):
        return []

    try:
        with open(baseline_path, encoding="utf-8") as f:
            b = json.load(f)
    except Exception:
        return []

    allowed_users = set(b.get("allowed_users", []))
    allowed_sudo_members = set(b.get("allowed_sudo_members", []))
    alerts = []

    # 1. Phát hiện tạo user mới không nằm trong baseline
    created_events = [e for e in events if e.event_type == "account_created" and e.user not in IGNORED_USERS]
    for e in created_events:
        if e.user and e.user not in allowed_users:
            alerts.append(Alert(
                rule="unauthorized_account_creation",
                severity_hint="critical",
                summary=f"Phát hiện tạo tài khoản mới '{e.user}' không nằm trong danh mục Baseline được duyệt.",
                first_seen=e.ts.isoformat(),
                last_seen=e.ts.isoformat(),
                details={
                    "created_user": e.user,
                    "detail": e.detail,
                    "baseline_allowed_users": sorted(allowed_users),
                }
            ))

    # 2. Phát hiện cấp quyền nhóm sudo/root cho user không nằm trong baseline
    group_events = [e for e in events if e.event_type == "group_member_added" and e.user not in IGNORED_USERS]
    for e in group_events:
        group_name = (e.detail or "").lower()
        if group_name in ("sudo", "root", "wheel", "adm"):
            if e.user and e.user not in allowed_sudo_members:
                alerts.append(Alert(
                    rule="unauthorized_privileged_group_assignment",
                    severity_hint="critical",
                    summary=f"Tài khoản '{e.user}' vừa được thêm vào nhóm đặc quyền '{group_name}' trái phép (vi phạm baseline).",
                    first_seen=e.ts.isoformat(),
                    last_seen=e.ts.isoformat(),
                    details={
                        "target_user": e.user,
                        "privileged_group": group_name,
                        "baseline_allowed_sudo_members": sorted(allowed_sudo_members),
                    }
                ))

    return alerts


# ---------- HÀM HỢP NHẤT TẤT CẢ CÁC QUY TẮC ----------
def detect_all(events, baseline_path="baseline.json"):
    alerts = []
    alerts.extend(detect_ssh_bruteforce(events))
    alerts.extend(detect_sudo_abuse(events))
    alerts.extend(detect_baseline_account_tampering(events, baseline_path))
    return alerts