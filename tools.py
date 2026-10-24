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
            "recent_events": [_event_to_dict(e) for e in events[-5:]],
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
            "recent_account_change_log_lines": changes,
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
                break
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


# ---------- Tool 4: kiểm tra tiến trình đang chạy ----------
SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(r"(?:/dev/tcp/|/dev/udp/)"), "reverse_shell_dev_tcp"),
    (re.compile(r"(?:bash|sh|zsh)\s+-i"), "interactive_reverse_shell"),
    (re.compile(r"(?:nc|netcat|ncat|socat)\s+.*-e"), "netcat_reverse_shell"),
    (re.compile(r"(?:curl|wget)\s+.*\|\s*(?:sh|bash)"), "pipe_download_execute"),
    (re.compile(r"(?:xmrig|minerd|cpuminer)"), "cryptocurrency_miner"),
    (re.compile(r"python(?:\d+)?\s+-c\s+.*socket"), "python_socket_payload"),
]


def inspect_active_processes(limit=25):
    tool = "inspect_active_processes"
    try:
        limit = max(5, min(int(limit), 100))
        out, err = run_fixed_command(
            "ps -eo user,pid,ppid,%cpu,%mem,stat,command --sort=-%cpu"
        )
        if not out.strip():
            return _err(tool, err or "không đọc được danh sách tiến trình")

        proc_lines = out.strip().splitlines()[1:]
        processes = []
        suspicious = []

        for line in proc_lines:
            parts = line.split(None, 6)
            if len(parts) < 7:
                continue
            u, pid, ppid, cpu, mem, stat, cmd = parts
            if u == "agent_soc" and "ps -eo" in cmd:
                continue

            item = {
                "user": u,
                "pid": int(pid) if pid.isdigit() else pid,
                "ppid": int(ppid) if ppid.isdigit() else ppid,
                "cpu": float(cpu) if cpu.replace(".", "", 1).isdigit() else 0.0,
                "mem": float(mem) if mem.replace(".", "", 1).isdigit() else 0.0,
                "stat": stat,
                "command": cmd[:250],
            }

            for pattern, reason in SUSPICIOUS_CMD_PATTERNS:
                if pattern.search(cmd):
                    suspicious.append({**item, "flag": reason})
                    break

            processes.append(item)

        return _ok(tool, {
            "total_running": len(processes),
            "suspicious_processes": suspicious,
            "top_processes_by_cpu": processes[:limit],
        })
    except Exception as ex:
        return _err(tool, ex)


# ---------- Tool 5: kiểm tra cổng mở và kết nối mạng ----------
def inspect_network_connections():
    tool = "inspect_network_connections"
    try:
        listen_out, _ = run_fixed_command("ss -tuln")
        listening = []
        for line in listen_out.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto, state, _, _, local = parts[:5]
                listening.append({"proto": proto, "state": state, "local_address": local})

        conn_out, _ = run_fixed_command("ss -tun state established")
        established = []
        for line in conn_out.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto, _, _, local, peer = parts[:5]
                established.append({"proto": proto, "local": local, "peer": peer})

        return _ok(tool, {
            "listening_services": listening,
            "established_connections": established,
            "total_established": len(established),
        })
    except Exception as ex:
        return _err(tool, ex)


# ---------- Tool 6: kiểm tra persistence qua cron ----------
def inspect_cron_persistence():
    tool = "inspect_cron_persistence"
    try:
        crontab_out, _ = run_fixed_command("cat /etc/crontab 2>/dev/null")
        crontab_entries = []
        for raw in crontab_out.splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                crontab_entries.append(line[:250])

        cron_d_out, _ = run_fixed_command("head -n 20 /etc/cron.d/* 2>/dev/null")
        cron_d_entries = []
        current_file = None
        for raw in cron_d_out.splitlines():
            line = raw.strip()
            if line.startswith("==>") and line.endswith("<=="):
                current_file = line.replace("==>", "").replace("<==", "").strip()
                continue
            if line and not line.startswith("#") and current_file:
                cron_d_entries.append({"file": current_file, "entry": line[:250]})

        scripts_out, _ = run_fixed_command("ls -1 /etc/cron.daily /etc/cron.hourly /etc/cron.weekly 2>/dev/null")
        scripts = [s.strip() for s in scripts_out.splitlines() if s.strip()]

        suspicious = []
        for entry in crontab_entries:
            if any(p in entry for p in ["/tmp", "/dev/shm", "curl", "wget", "nc ", "bash -i"]):
                suspicious.append({"source": "/etc/crontab", "entry": entry})
        for cde in cron_d_entries:
            if any(p in cde["entry"] for p in ["/tmp", "/dev/shm", "curl", "wget", "nc ", "bash -i"]):
                suspicious.append({"source": cde["file"], "entry": cde["entry"]})

        return _ok(tool, {
            "crontab_entries": crontab_entries,
            "cron_d_entries": cron_d_entries,
            "periodic_scripts": scripts[:30],
            "suspicious_cron_jobs": suspicious,
        })
    except Exception as ex:
        return _err(tool, ex)


# ==============================================================
# 🛡️ LỚP PHẢN ỨNG CÓ KIỂM SOÁT (CONTROLLED RESPONSE TOOLS)
# ==============================================================

def get_firewall_status():
    """Lấy danh sách các luật và trạng thái của tường lửa UFW từ máy chủ lab."""
    tool = "get_firewall_status"
    try:
        out, err = run_fixed_command("sudo -n /usr/sbin/ufw status numbered")
        if "a password is required" in err or "password is required" in out:
            return _err(tool, "Yêu cầu mật khẩu sudo. Cần cấu hình NOPASSWD trong /etc/sudoers.d/soc_agent_ufw")
        
        is_active = "Status: active" in out
        rules = []
        for line in out.splitlines():
            line_str = line.strip()
            m = re.match(r"^\[\s*(\d+)\]\s+(.*?)\s+(ALLOW IN|DENY IN|ALLOW|DENY)\s+(.*)$", line_str)
            if m:
                rules.append({
                    "rule_num": int(m.group(1)),
                    "to": m.group(2).strip(),
                    "action": m.group(3).strip(),
                    "from": m.group(4).strip(),
                    "raw": line_str
                })
        return _ok(tool, {
            "active": is_active,
            "raw_output": out.strip(),
            "rules": rules,
            "total_rules": len(rules)
        })
    except Exception as ex:
        return _err(tool, ex)


def block_ip(ip: str):
    """
    Thực thi chặn IP trên tường lửa UFW thông qua Wrapper Script an toàn /usr/local/sbin/soc-block-ip.
    Áp dụng nguyên tắc Defense-in-Depth và Least Privilege.
    """
    tool = "block_ip"
    try:
        ipaddress.ip_address(ip.strip())
        clean_ip = ip.strip()

        # 1. Ưu tiên gọi Wrapper Script an toàn (chỉ root sở hữu, tự kiểm tra IP & cổng SSH)
        cmd_wrapper = f"sudo -n /usr/local/sbin/soc-block-ip {clean_ip}"
        out, err = run_fixed_command(cmd_wrapper)

        if "command not found" in err or "No such file" in err or "not found" in out:
            # Fallback nếu lab chưa chạy setup_lab_guardrails.sh
            cmd_fallback = f"sudo -n /usr/sbin/ufw insert 1 deny from {clean_ip} to any"
            out, err = run_fixed_command(cmd_fallback)

        if "a password is required" in err or "password is required" in out:
            return _err(tool, "Lỗi phân quyền sudo: agent_soc cần được cấp quyền NOPASSWD trong /etc/sudoers.d/soc_agent_ufw")

        if "SECURITY ERROR" in out or "SECURITY ERROR" in err:
            return _err(tool, f"Bị chặn bởi ranh giới an toàn của máy chủ: {out.strip() or err.strip()}")

        if "SUCCESS" in out or "Rule inserted" in out or "Rule updated" in out or "Rule added" in out:
            return _ok(tool, {
                "blocked_ip": clean_ip,
                "command": cmd_wrapper,
                "ufw_message": out.strip()
            })
        else:
            return _err(tool, f"Không thể áp dụng luật chặn: {out.strip() or err.strip()}")
    except ValueError:
        return _err(tool, f"Địa chỉ IP '{ip}' không hợp lệ")
    except Exception as ex:
        return _err(tool, ex)


def unblock_ip(ip: str):
    """Gỡ bỏ quy tắc chặn IP trên tường lửa UFW qua Wrapper Script an toàn /usr/local/sbin/soc-unblock-ip."""
    tool = "unblock_ip"
    try:
        ipaddress.ip_address(ip.strip())
        clean_ip = ip.strip()

        cmd_wrapper = f"sudo -n /usr/local/sbin/soc-unblock-ip {clean_ip}"
        out, err = run_fixed_command(cmd_wrapper)

        if "command not found" in err or "No such file" in err or "not found" in out:
            cmd_fallback = f"sudo -n /usr/sbin/ufw delete deny from {clean_ip}"
            out, err = run_fixed_command(cmd_fallback)

        if "a password is required" in err or "password is required" in out:
            return _err(tool, "Lỗi phân quyền sudo: agent_soc cần được cấp quyền NOPASSWD trong /etc/sudoers.d/soc_agent_ufw")

        return _ok(tool, {
            "unblocked_ip": clean_ip,
            "command": cmd_wrapper,
            "ufw_message": out.strip()
        })
    except ValueError:
        return _err(tool, f"Địa chỉ IP '{ip}' không hợp lệ")
    except Exception as ex:
        return _err(tool, ex)


def verify_response(ip: str, expected_state="blocked"):
    """
    Xác minh xem hành động phản ứng trên tường lửa UFW đã thực sự có hiệu lực hay chưa.
    expected_state: 'blocked' (phải tồn tại rule DENY) hoặc 'unblocked' (không còn rule DENY).
    Kiểm tra cả trạng thái active của dịch vụ tường lửa.
    """
    tool = "verify_response"
    try:
        clean_ip = ip.strip()
        fw_status = get_firewall_status()
        if fw_status.get("status") != "ok":
            return _err(tool, f"Không đọc được trạng thái UFW: {fw_status.get('error')}")

        data = fw_status.get("data", {})
        rules = data.get("rules", [])
        is_active = data.get("active", False)

        matching_deny_rules = [
            r for r in rules
            if clean_ip in r.get("from", "") and "DENY" in r.get("action", "")
        ]

        is_present = len(matching_deny_rules) > 0

        if expected_state == "blocked":
            verified = is_present
            message = (
                f"Xác minh THÀNH CÔNG: IP {clean_ip} đã bị chặn bởi {len(matching_deny_rules)} luật trong UFW."
                if verified else
                f"Xác minh THẤT BẠI: Không tìm thấy luật DENY cho IP {clean_ip} trong UFW."
            )
        else: # unblocked
            verified = not is_present
            message = (
                f"Xác minh THÀNH CÔNG: IP {clean_ip} đã được gỡ bỏ hoàn toàn khỏi bảng chặn của UFW."
                if verified else
                f"Xác minh THẤT BẠI: Vẫn còn luật DENY đối với IP {clean_ip} trong UFW."
            )

        ufw_warning = None
        if not is_active:
            ufw_warning = (
                "⚠️ CẢNH BÁO AN TOÀN: Dịch vụ UFW đang ở trạng thái TẮT (Inactive). "
                "Quy tắc đã có trong bảng nhưng CHƯA CÓ HIỆU LỰC CHẶN THỰC TẾ trên cổng mạng. "
                "Cần kích hoạt tường lửa (lưu ý đảm bảo đã allow 22/tcp)."
            )

        return _ok(tool, {
            "ip": clean_ip,
            "expected_state": expected_state,
            "verified": verified,
            "rules_found": matching_deny_rules,
            "message": message,
            "ufw_active": is_active,
            "ufw_warning": ufw_warning,
        })
    except Exception as ex:
        return _err(tool, ex)


# Danh mục các công cụ điều tra của Agent (Read-Only)
INVESTIGATION_TOOLS = {
    "search_auth_logs": search_auth_logs,
    "inspect_user_changes": inspect_user_changes,
    "check_ssh_config": check_ssh_config,
    "inspect_active_processes": inspect_active_processes,
    "inspect_network_connections": inspect_network_connections,
    "inspect_cron_persistence": inspect_cron_persistence,
}

# Danh mục các công cụ phản ứng (Active Response - Cần thẩm định Policy & HITL)
RESPONSE_TOOLS = {
    "get_firewall_status": get_firewall_status,
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "verify_response": verify_response,
}

# Tương thích ngược
TOOLS = dict(INVESTIGATION_TOOLS)
