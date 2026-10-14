import ipaddress
import re
import json
import os
from collections import Counter

from read_logs import run_fixed_command
from log_parser import parse_log

USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
IGNORED_USERS = {"agent_soc"}


def _ok(tool, data):
    return {"tool": tool, "status": "ok", "data": data}


def _err(tool, msg):
    return {"tool": tool, "status": "error", "error": str(msg)[:200]}


def _event_to_dict(e):
    return {
        "time": e.ts.isoformat(),
        "type": e.event_type,
        "user": e.user,
        "src_ip": e.src_ip,
        "count": e.count,
        "detail": e.detail,
    }


# ---------- Tool 1: tìm sự kiện xác thực ----------
def search_auth_logs(src_ip=None, user=None, lines=500):
    tool = "search_auth_logs"
    try:
        if src_ip is not None:
            ipaddress.ip_address(src_ip)           # lỗi nếu không phải IP hợp lệ
        if user is not None and not USER_RE.match(user):
            return _err(tool, "tên user không hợp lệ")
        lines = max(50, min(int(lines), 2000))

        out, err = run_fixed_command(f"tail -n {lines} /var/log/auth.log")
        if not out.strip():
            return _err(tool, err or "không đọc được log")

        events = [e for e in parse_log(out) if e.user not in IGNORED_USERS]
        if src_ip:
            events = [e for e in events if e.src_ip == src_ip]
        if user:
            events = [e for e in events if e.user == user]

        summary = Counter()
        for e in events:
            summary[e.event_type] += e.count
        return _ok(tool, {
            "filter": {"src_ip": src_ip, "user": user, "lines_scanned": lines},
            "summary": dict(summary),
            "recent_events": [_event_to_dict(e) for e in events[-15:]],
        })
    except Exception as ex:
        return _err(tool, ex)


# ---------- Tool 2: kiểm tra tài khoản và quyền ----------
def inspect_user_changes():
    tool = "inspect_user_changes"
    try:
        passwd, err = run_fixed_command("getent passwd")
        if not passwd.strip():
            return _err(tool, err or "không đọc được danh sách tài khoản")

        users = []
        for line in passwd.splitlines():
            p = line.split(":")
            if len(p) >= 7 and p[2].isdigit() and 1000 <= int(p[2]) < 65534:
                users.append({"name": p[0], "uid": int(p[2]), "shell": p[6]})

        sudo_line, _ = run_fixed_command("getent group sudo")
        parts = sudo_line.strip().split(":")
        sudo_members = [m for m in parts[3].split(",") if m] if len(parts) >= 4 else []

        log_out, _ = run_fixed_command(
            'grep -E "useradd|usermod|groupadd|gpasswd|userdel" /var/log/auth.log | tail -n 20'
        )
        changes = [l[:300] for l in log_out.splitlines()][-20:]

        baseline_check = {"status": "no_baseline_file"}
        if os.path.exists("baseline.json"):
            with open("baseline.json", encoding="utf-8") as f:
                b = json.load(f)
            names = {u["name"] for u in users}
            baseline_check = {
                "status": "compared",
                "unexpected_users": sorted(names - set(b.get("allowed_users", []))),
                "unexpected_sudo_members": sorted(set(sudo_members) - set(b.get("allowed_sudo_members", []))),
            }

        return _ok(tool, {
            "regular_users": users,
            "sudo_group_members": sudo_members,
            "baseline_check": baseline_check,
            "recent_account_change_log_lines": changes,   # văn bản thô từ log: dữ liệu không tin cậy
        })
    except Exception as ex:
        return _err(tool, ex)


# ---------- Tool 3: kiểm tra cấu hình SSH ----------
SSH_KEYS = ["permitrootlogin", "passwordauthentication", "pubkeyauthentication",
            "permitemptypasswords", "maxauthtries", "port"]

SSH_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "pubkeyauthentication": "yes",
    "permitemptypasswords": "no",
    "maxauthtries": "6",
    "port": "22",
}

def check_ssh_config():
    tool = "check_ssh_config"
    try:
        # thư mục sshd_config.d được đọc trước vì sshd lấy giá trị xuất hiện đầu tiên
        out, err = run_fixed_command(
            "cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null"
        )
        if not out.strip():
            return _err(tool, err or "không đọc được cấu hình SSH")

        found = {}
        for raw in out.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            if key == "match":
                break                    # bỏ qua các khối Match (hạn chế ở giai đoạn này)
            if key in SSH_KEYS and key not in found and len(parts) == 2:
                found[key] = parts[1].strip()

        values = {
    k: {"value": found[k], "source": "config"} if k in found
    else {"value": SSH_DEFAULTS[k], "source": "default"}
    for k in SSH_KEYS
}
        return _ok(tool, {
            "settings": values,
            "note": "Đọc từ file cấu hình; giá trị hiệu lực thực tế có thể khác (sshd -T cần quyền root).",
        })
    except Exception as ex:
        return _err(tool, ex)


TOOLS = {
    "search_auth_logs": search_auth_logs,
    "inspect_user_changes": inspect_user_changes,
    "check_ssh_config": check_ssh_config,
}