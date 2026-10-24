#!/usr/bin/env python3
# ==============================================================================
# scripts/simulate_wazuh_alert.py - Bắn Giả Lập Cảnh Báo Chuẩn Định Dạng Wazuh SIEM
# Hỗ trợ xác thực X-SOC-Token, Rule ID chuẩn Wazuh (5710, 5712, 5401, 5402, 550)
# ==============================================================================

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Đảm bảo UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DEFAULT_AUTH_TOKEN = os.getenv("WEBHOOK_AUTH_TOKEN", "13af718f665e5953f0dc2cf41afca9abe59c2a3ecaeccb53556755d14ab49b47")


def generate_wazuh_payload(alert_type: str = "bruteforce", src_ip: str = "192.168.56.102", target_user: str = "root") -> dict:
    """
    Tạo payload JSON chuẩn cấu trúc Wazuh SIEM Alert với Rule IDs chính xác:
      - 5712: sshd: brute force trying to get access to the system
      - 5710: sshd: Attempt to login using a non-existent user
      - 5401: sudo: user NOT in sudoers executed command
      - 5402: sudo: successful sudo execution to root shell
      - 550:  ossec: Integrity checksum changed (FIM Alert)
    """
    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    if alert_type in ("bruteforce", "ssh_bruteforce"):
        return {
            "timestamp": now_iso,
            "rule": {
                "level": 10,
                "description": "sshd: brute force trying to get access to the system.",
                "id": "5712",
                "mitre": {
                    "id": ["T1110"],
                    "tactic": ["Credential Access"],
                    "technique": ["Brute Force"]
                },
                "groups": ["syslog", "sshd", "authentication_failures"]
            },
            "agent": {
                "id": "001",
                "name": "ubuntu-lab",
                "ip": "192.168.56.101"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "data": {
                "srcip": src_ip,
                "dstuser": target_user
            },
            "full_log": f"Oct 24 16:00:00 ubuntu-lab sshd[28491]: Failed password for {target_user} from {src_ip} port 54321 ssh2"
        }

    elif alert_type in ("invalid_user", "ssh_invalid"):
        return {
            "timestamp": now_iso,
            "rule": {
                "level": 5,
                "description": "sshd: Attempt to login using a non-existent user.",
                "id": "5710",
                "mitre": {
                    "id": ["T1110.001"],
                    "tactic": ["Credential Access"],
                    "technique": ["Password Guessing"]
                },
                "groups": ["syslog", "sshd", "invalid_login"]
            },
            "agent": {
                "id": "001",
                "name": "ubuntu-lab",
                "ip": "192.168.56.101"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "data": {
                "srcip": src_ip,
                "dstuser": target_user
            },
            "full_log": f"Oct 24 16:01:10 ubuntu-lab sshd[28495]: Invalid user {target_user} from {src_ip} port 54325"
        }

    elif alert_type in ("sudo", "sudo_unauthorized", "sudo_abuse", "sudo_not_in_sudoers"):
        return {
            "timestamp": now_iso,
            "rule": {
                "level": 7,
                "description": "sudo: user NOT in sudoers executed command.",
                "id": "5405",
                "mitre": {
                    "id": ["T1548.003"],
                    "tactic": ["Privilege Escalation"],
                    "technique": ["Sudo and Sudo Caching"]
                },
                "groups": ["syslog", "sudo"]
            },
            "agent": {
                "id": "001",
                "name": "ubuntu-lab",
                "ip": "192.168.56.101"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "data": {
                "srcip": src_ip,
                "dstuser": "root"
            },
            "full_log": f"Oct 24 16:02:15 ubuntu-lab sudo[28500]: {target_user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{target_user} ; USER=root ; COMMAND=/bin/bash"
        }

    elif alert_type in ("sudo_failed", "sudo_auth_fail"):
        return {
            "timestamp": now_iso,
            "rule": {
                "level": 5,
                "description": "sudo: Failed attempt to run sudo.",
                "id": "5401",
                "mitre": {
                    "id": ["T1548.003"],
                    "tactic": ["Privilege Escalation"],
                    "technique": ["Sudo and Sudo Caching"]
                },
                "groups": ["syslog", "sudo"]
            },
            "agent": {
                "id": "001",
                "name": "ubuntu-lab",
                "ip": "192.168.56.101"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "data": {
                "srcip": src_ip,
                "dstuser": "root"
            },
            "full_log": f"Oct 24 16:02:30 ubuntu-lab sudo[28502]: {target_user} : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/passwd"
        }

    elif alert_type in ("sudo_success", "root_shell"):
        return {
            "timestamp": now_iso,
            "rule": {
                "level": 3,
                "description": "sudo: successful sudo to ROOT.",
                "id": "5402",
                "mitre": {
                    "id": ["T1548.003"],
                    "tactic": ["Privilege Escalation"],
                    "technique": ["Sudo and Sudo Caching"]
                },
                "groups": ["syslog", "sudo"]
            },
            "agent": {
                "id": "001",
                "name": "ubuntu-lab",
                "ip": "192.168.56.101"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "data": {
                "srcip": src_ip,
                "dstuser": "root"
            },
            "full_log": f"Oct 24 16:03:00 ubuntu-lab sudo[28505]: {target_user} : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
        }

    elif alert_type in ("tamper", "fim"):
        return {
            "timestamp": now_iso,
            "rule": {
                "level": 7,
                "description": "Integrity checksum changed for file /etc/sudoers (FIM Alert).",
                "id": "550",
                "mitre": {
                    "id": ["T1565.001"],
                    "tactic": ["Impact"],
                    "technique": ["Stored Data Manipulation"]
                },
                "groups": ["ossec", "syscheck"]
            },
            "agent": {
                "id": "001",
                "name": "ubuntu-lab",
                "ip": "192.168.56.101"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "data": {
                "srcip": src_ip,
                "file": "/etc/sudoers"
            },
            "full_log": "Oct 24 16:05:00 ubuntu-lab ossec: File '/etc/sudoers' checksum changed. Old md5: e2a... New md5: 8b1..."
        }

    else:
        raise ValueError(f"Loại cảnh báo không hợp lệ: '{alert_type}'. Chọn: bruteforce, invalid_user, sudo, sudo_success, tamper.")


def send_simulated_alert(
    alert_type: str = "bruteforce",
    src_ip: str = "192.168.56.102",
    target_user: str = "root",
    host: str = "127.0.0.1",
    port: int = 5000,
    auth_token: Optional[str] = None
) -> dict:
    """Gửi cảnh báo giả lập kèm Header X-SOC-Token tới Webhook Endpoint của AI SOC Agent."""
    token = auth_token if auth_token is not None else DEFAULT_AUTH_TOKEN
    payload = generate_wazuh_payload(alert_type, src_ip, target_user)
    endpoint = f"http://{host}:{port}/api/v1/wazuh-alert"
    data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    print(f"[*] Đang bắn giả lập cảnh báo Wazuh ({alert_type.upper()})...")
    print(f"    Mục tiêu Webhook: {endpoint}")
    print(f"    IP kẻ tấn công:   {src_ip}")
    print(f"    Tài khoản nhắm:   {target_user}")
    print(f"    Xác thực Token:   {'Có' if token else 'Không'}")

    req = urllib.request.Request(
        endpoint,
        data=data_bytes,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-SOC-Token": token or ""
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_code = response.getcode()
            res_body = response.read().decode("utf-8")
            print(f"✅ Gửi thành công! HTTP {res_code}: {res_body}")
            return {"status": "ok", "code": res_code, "response": json.loads(res_body), "payload": payload}
    except urllib.error.HTTPError as ex:
        err_body = ex.read().decode("utf-8", errors="replace")
        print(f"[-] HTTP Error {ex.code}: {err_body}")
        return {"status": "http_error", "code": ex.code, "error": err_body, "payload": payload}
    except urllib.error.URLError as ex:
        print(f"[-] Không thể kết nối tới Webhook Receiver tại {endpoint}: {ex}")
        print("    👉 Gợi ý: Hãy đảm bảo Webhook Receiver đang chạy bằng lệnh: python wazuh_listener.py hoặc python cli.py listen")
        return {"status": "error", "error": str(ex), "payload": payload}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bắn giả lập cảnh báo Wazuh SIEM tới AI SOC Agent Webhook.")
    parser.add_argument("--type", choices=["bruteforce", "invalid_user", "sudo", "sudo_success", "tamper"], default="bruteforce", help="Loại tấn công mô phỏng")
    parser.add_argument("--ip", default="192.168.56.102", help="Địa chỉ IP nguồn của kẻ tấn công (mặc định: 192.168.56.102)")
    parser.add_argument("--user", default="root", help="Tài khoản bị nhắm tới (mặc định: root)")
    parser.add_argument("--host", default=os.getenv("WEBHOOK_HOST", "127.0.0.1"), help="Địa chỉ host Webhook")
    parser.add_argument("--port", type=int, default=int(os.getenv("WEBHOOK_PORT", "5000")), help="Cổng Webhook")
    parser.add_argument("--token", default=DEFAULT_AUTH_TOKEN, help="Token xác thực bí mật (X-SOC-Token)")
    args = parser.parse_args()

    send_simulated_alert(
        alert_type=args.type,
        src_ip=args.ip,
        target_user=args.user,
        host=args.host,
        port=args.port,
        auth_token=args.token
    )
