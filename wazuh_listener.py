# ==============================================================================
# wazuh_listener.py - Bộ Tiếp Nhận Alert từ Wazuh SIEM (Event-Driven Webhook)
# Bảo mật nâng cao: Xác thực Token, Kiểm tra Schema, Binding Host-Only & Hàng đợi FIFO
# ==============================================================================

import ipaddress
import json
import os
import queue
import re
import sys
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# Hỗ trợ UTF-8 cho Windows PowerShell
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from dotenv import load_dotenv

load_dotenv()

from agent import investigate
from tools import block_ip, unblock_ip, verify_response
from policy_engine import (
    evaluate_action,
    record_audit_log,
    save_active_block,
    remove_active_block,
    load_active_blocks,
    DEFAULT_BLOCK_TTL_MINUTES,
    PolicyDecision,
)
from notifier import build_alert_html, send_alert_email

RUNS_DIR = Path("runs")
WAZUH_ALERTS_FILE = RUNS_DIR / "wazuh_alerts.jsonl"
STATE_FILE = RUNS_DIR / "monitor_state.json"

DEFAULT_WEBHOOK_HOST = os.getenv("WEBHOOK_HOST", "192.168.56.1")
DEFAULT_WEBHOOK_PORT = int(os.getenv("WEBHOOK_PORT", "5000"))
DEFAULT_AUTH_TOKEN = os.getenv("WEBHOOK_AUTH_TOKEN", "13af718f665e5953f0dc2cf41afca9abe59c2a3ecaeccb53556755d14ab49b47")

# Hàng đợi tối đa 200 alert chống tràn bộ nhớ (DoS)
MAX_QUEUE_SIZE = 200
MAX_PAYLOAD_BYTES = 65536  # 64 KB


def is_allowed_client_ip(client_ip: str) -> bool:
    """Chỉ chấp thuận kết nối từ Loopback hoặc dải mạng Host-Only (192.168.56.0/24)."""
    if not client_ip:
        return False
    # Cho phép loopback
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        return True
    try:
        ip_obj = ipaddress.ip_address(client_ip)
        allowed_subnet = ipaddress.ip_network("192.168.56.0/24")
        return ip_obj in allowed_subnet
    except ValueError:
        return False


def validate_ip_format(ip_str: str) -> bool:
    """Kiểm tra địa chỉ IPv4 hợp lệ (4 octet từ 0-255)."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.version == 4
    except ValueError:
        return False


def extract_ip_from_payload(payload: dict) -> Optional[str]:
    """Trích xuất địa chỉ IP kẻ tấn công từ cấu trúc Wazuh Alert hoặc log thô."""
    data = payload.get("data", {})
    if isinstance(data, dict):
        for k in ("srcip", "src_ip", "source_ip", "attacker_ip"):
            val = data.get(k)
            if val and isinstance(val, str) and validate_ip_format(val):
                return val.strip()

    root_ip = payload.get("src_ip") or payload.get("srcip")
    if root_ip and isinstance(root_ip, str) and validate_ip_format(root_ip):
        return root_ip.strip()

    full_log = payload.get("full_log", "")
    if full_log:
        m = re.search(r"\b(?:from|rhost=|src=)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", full_log, re.IGNORECASE)
        if m and validate_ip_format(m.group(1)):
            return m.group(1)
        m2 = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", full_log)
        if m2 and validate_ip_format(m2.group(0)):
            return m2.group(0)

    desc = payload.get("rule", {}).get("description", "") if isinstance(payload.get("rule"), dict) else ""
    if desc:
        m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", desc)
        if m and validate_ip_format(m.group(0)):
            return m.group(0)

    return None


def map_wazuh_level_to_severity(level: int) -> str:
    """Chuyển đổi mức độ cảnh báo của Wazuh (1-16) sang chuẩn SOC severity."""
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    if level >= 3:
        return "low"
    return "info"


def validate_wazuh_payload_schema(payload: Any) -> Tuple[bool, str]:
    """Kiểm tra tính hợp lệ về cấu trúc và dữ liệu của Wazuh Alert Payload."""
    if not isinstance(payload, dict):
        return False, "Payload phải là JSON object (dict)."

    # Bắt buộc phải có thông tin quy tắc (rule)
    rule = payload.get("rule")
    if not rule or not isinstance(rule, dict):
        if not payload.get("rule_id"):
            return False, "Thiếu trường 'rule' hợp lệ trong payload."

    # Kiểm tra level nếu có
    if isinstance(rule, dict) and "level" in rule:
        try:
            lvl = int(rule["level"])
            if not (0 <= lvl <= 16):
                return False, f"Rule level {lvl} không nằm trong dải Wazuh chuẩn (0-16)."
        except (ValueError, TypeError):
            return False, "Rule level phải là số nguyên."

    # Kiểm tra IP nếu được khai báo trong data
    data = payload.get("data")
    if isinstance(data, dict):
        srcip = data.get("srcip") or data.get("src_ip")
        if srcip and not validate_ip_format(srcip):
            return False, f"Địa chỉ srcip không hợp lệ: '{srcip}'."

    return True, "Hợp lệ"


def normalize_wazuh_alert(payload: dict) -> dict:
    """
    Chuẩn hóa JSON payload từ Wazuh thành đối tượng Alert chuẩn của hệ thống AI SOC.
    Đối chiếu các Rule IDs của Wazuh:
      - 5710: sshd: Attempt to login using a non-existent user (Level 5)
      - 5711: sshd: authentication failed (Level 5)
      - 5712: sshd: brute force trying to get access to the system (Level 10 - non-existent user)
      - 5760: sshd: Authentication failed with an existing user (Level 5)
      - 5763: sshd: brute force trying to get access to the system. Authentication failed (Level 10 - existing user)
      - 5401: sudo: Failed attempt to run sudo (Level 5)
      - 5402: sudo: successful sudo to ROOT (Level 3)
      - 5404: sudo: 3 failed attempts to run sudo (Level 10)
      - 5405: sudo: user NOT in sudoers executed command (Level 5/7)
      - 550:  ossec: Integrity checksum changed (Level 7 - FIM)
    Lưu ý: Rule 5715 (Accepted publickey) chỉ dùng trong bộ dữ liệu kiểm thử benchmark.
    """
    rule = payload.get("rule", {}) if isinstance(payload.get("rule"), dict) else {}
    rule_id = str(rule.get("id", payload.get("rule_id", "custom")))
    rule_desc = rule.get("description", payload.get("summary", "Wazuh Security Event"))
    rule_level = int(rule.get("level", payload.get("level", 7)))

    agent_data = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
    agent_name = agent_data.get("name", "lab-endpoint")
    agent_ip = agent_data.get("ip", "192.168.56.101")

    src_ip = extract_ip_from_payload(payload)
    data_dict = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
    src_user = data_dict.get("srcuser")
    dst_user = data_dict.get("dstuser") or payload.get("user") or "unknown"
    cmd_data = data_dict.get("command")
    full_log = payload.get("full_log", "")
    timestamp = payload.get("timestamp") or datetime.now().isoformat()

    mitre_data = rule.get("mitre", {})
    mitre_ids = mitre_data.get("id", []) if isinstance(mitre_data, dict) else []
    mitre_tactics = mitre_data.get("tactic", []) if isinstance(mitre_data, dict) else []
    mitre_techniques = mitre_data.get("technique", []) if isinstance(mitre_data, dict) else []

    severity_hint = map_wazuh_level_to_severity(rule_level)

    # Đóng gói dữ liệu nhật ký không tin cậy để chống Prompt Injection
    sandboxed_log = f"<untrusted_tool_output>\n{full_log}\n</untrusted_tool_output>" if full_log else ""

    normalized = {
        "rule": f"wazuh_rule_{rule_id}",
        "severity_hint": severity_hint,
        "summary": f"[Wazuh Rule {rule_id}] {rule_desc} (Agent: {agent_name}, IP: {src_ip or 'N/A'})",
        "first_seen": timestamp,
        "last_seen": timestamp,
        "src_ip": src_ip,
        "user": dst_user,
        "src_user": src_user,
        "data": data_dict,
        "wazuh": {
            "rule_id": rule_id,
            "level": rule_level,
            "description": rule_desc,
            "mitre_id": mitre_ids,
            "mitre_tactic": mitre_tactics,
            "mitre_technique": mitre_techniques,
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "full_log": full_log,
            "sandboxed_log": sandboxed_log,
            "srcuser": src_user,
            "dstuser": dst_user,
            "command": cmd_data,
            "data": data_dict,
        },
        "details": {
            "src_ip": src_ip,
            "user": dst_user,
            "srcuser": src_user,
            "command": cmd_data,
            "rule_id": rule_id,
            "wazuh_level": rule_level,
            "full_log": full_log,
        }
    }
    return normalized


ALLOWED_SUDO_EXACT_COMMANDS = {
    "/usr/bin/apt update",
    "/usr/sbin/ufw status",
}


def get_baseline_allowed_sudoers() -> set:
    try:
        baseline_path = BASE_DIR / "baseline.json"
        if baseline_path.exists():
            with open(baseline_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return set(data.get("allowed_sudo_members", []))
    except Exception:
        pass
    return {"admin_duytien", "agent_soc", "admin"}


def get_baseline_allowed_users() -> set:
    try:
        baseline_path = BASE_DIR / "baseline.json"
        if baseline_path.exists():
            with open(baseline_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return set(data.get("allowed_users", []))
    except Exception:
        pass
    return {"admin_duytien", "agent_soc", "admin"}


def fast_path_triage(alert: dict) -> Optional[dict]:
    """
    Tier 1.5 Deterministic Fast-Path Triage:
    Lọc các sự kiện bảo trì/quản trị hệ thống lành tính đã biết TRƯỚC KHI gọi Local LLM.
    Phản hồi trong <1ms, giải phóng hàng đợi SOAR, ngăn ngừa cạn kiệt tài nguyên suy luận.

    Nguyên tắc bảo mật:
    - Chỉ cho phép các lệnh khớp CHÍNH XÁC 100% trong ALLOWED_SUDO_EXACT_COMMANDS.
    - Không dùng so khớp tiền tố, không cho phép tham số mở rộng hoặc ký tự điều khiển shell.
    - Bắt buộc kiểm tra user chạy sudo (srcuser) nằm trong allowed_sudo_members của baseline.json.
    - Kiểm tra tính nhất quán giữa full_log và data.command để phòng ngừa log injection (chỉ đúng 1 COMMAND=).
    """
    if not isinstance(alert, dict):
        return None

    # Trích xuất dữ liệu an toàn từ cả raw payload lẫn normalized alert
    rule_obj = alert.get("rule")
    wazuh_obj = alert.get("wazuh", {}) if isinstance(alert.get("wazuh"), dict) else {}
    details_obj = alert.get("details", {}) if isinstance(alert.get("details"), dict) else {}
    data_obj = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    if not data_obj and isinstance(wazuh_obj.get("data"), dict):
        data_obj = wazuh_obj.get("data")

    # rule_id
    if isinstance(rule_obj, dict):
        rule_id = str(rule_obj.get("id", ""))
    elif isinstance(rule_obj, str) and rule_obj.startswith("wazuh_rule_"):
        rule_id = rule_obj.replace("wazuh_rule_", "")
    else:
        rule_id = str(wazuh_obj.get("rule_id", details_obj.get("rule_id", "")))

    # rule_level
    rule_level = None
    if isinstance(rule_obj, dict) and "level" in rule_obj:
        try:
            rule_level = int(rule_obj.get("level"))
        except (ValueError, TypeError):
            pass
    if rule_level is None:
        try:
            lvl_val = wazuh_obj.get("level", details_obj.get("wazuh_level"))
            if lvl_val is not None:
                rule_level = int(lvl_val)
        except (ValueError, TypeError):
            pass

    # full_log
    full_log = alert.get("full_log") or wazuh_obj.get("full_log") or details_obj.get("full_log")
    if not isinstance(full_log, str) or not full_log:
        return None

    # -------------------------------------------------------------------------
    # 1. Hoạt động quản trị bảo trì hệ thống chuẩn qua sudo (Rule 5402 - Level 3)
    # -------------------------------------------------------------------------
    if rule_id == "5402":
        if rule_level != 3:
            return None

        # Kiểm tra chống log injection: chuỗi 'COMMAND=' chỉ được xuất hiện ĐÚNG 1 LẦN
        cmd_matches = re.findall(r"\bCOMMAND=", full_log, flags=re.IGNORECASE)
        if len(cmd_matches) != 1:
            return None

        # Trích xuất command sau 'COMMAND='
        cmd_idx = full_log.upper().find("COMMAND=")
        raw_cmd = full_log[cmd_idx + len("COMMAND="):]

        # Kiểm tra ASCII tuyệt đối (chống giả mạo Cyrillic lookalike)
        if not raw_cmd.isascii():
            return None

        # Nếu có data.command, phải khớp tuyệt đối với raw_cmd (chống tráo đổi trường)
        data_command = data_obj.get("command")
        if data_command is None and isinstance(wazuh_obj.get("command"), str) and wazuh_obj.get("command"):
            data_command = wazuh_obj.get("command")
        if data_command is not None and data_command != raw_cmd:
            return None

        # So khớp chính xác 100% với danh mục lệnh bảo trì được phê duyệt (không tiền tố, không tham số thừa)
        if raw_cmd not in ALLOWED_SUDO_EXACT_COMMANDS:
            return None

        # Xác thực user thực thi (srcuser) phải nằm trong allowed_sudo_members của baseline.json
        src_user = data_obj.get("srcuser") or wazuh_obj.get("srcuser") or details_obj.get("srcuser") or alert.get("src_user")
        log_user_match = re.search(r"\bsudo(?:\[\d+\])?:\s*([a-zA-Z0-9_\-\.]+)\s*:", full_log)
        log_user = log_user_match.group(1) if log_user_match else None

        if src_user and log_user and src_user != log_user:
            return None

        exec_user = src_user or log_user
        if not exec_user:
            return None

        allowed_sudoers = get_baseline_allowed_sudoers()
        if exec_user not in allowed_sudoers:
            return None

        return {
            "action": "conclude",
            "verdict": "benign_likely",
            "severity": "info",
            "confidence": "high",
            "summary": f"Fast-Path: Lệnh bảo trì '{raw_cmd}' bởi user quản trị '{exec_user}' khớp tuyệt đối danh mục an toàn.",
            "evidence": [
                f"Wazuh Rule 5402 (Level 3)",
                f"User '{exec_user}' thuộc danh sách quản trị viên được phê duyệt trong baseline.json.",
                f"Lệnh '{raw_cmd}' khớp chính xác whitelist bảo trì.",
            ],
            "missing_data": [],
            "recommended_actions": [],
            "fast_path": True,
        }

    # -------------------------------------------------------------------------
    # 2. Đăng nhập hợp lệ bằng SSH Public Key (Rule 5715, Level 3/5)
    # -------------------------------------------------------------------------
    if rule_id == "5715" and (rule_level is None or rule_level <= 5):
        full_log_lower = full_log.lower()
        if "accepted publickey" in full_log_lower or "session closed" in full_log_lower:
            login_user = (
                data_obj.get("dstuser")
                or data_obj.get("srcuser")
                or alert.get("user")
                or ""
            )
            if not login_user:
                m = re.search(r"accepted publickey for (\S+)", full_log_lower)
                if m:
                    login_user = m.group(1)

            allowed_users = get_baseline_allowed_users()
            if login_user in allowed_users:
                return {
                    "action": "conclude",
                    "verdict": "benign_likely",
                    "severity": "info",
                    "confidence": "high",
                    "summary": f"Fast-Path: Xác thực SSH bằng Public Key hợp lệ cho tài khoản '{login_user}'.",
                    "evidence": [
                        f"Wazuh Rule 5715",
                        f"User '{login_user}' đăng nhập bằng SSH Key hợp lệ nằm trong baseline."
                    ],
                    "missing_data": [],
                    "recommended_actions": [],
                    "fast_path": True,
                }

    # -------------------------------------------------------------------------
    # 3. Log rotation định kỳ (Rule 550 FIM trên tệp nhật ký nén .gz hoặc .log.1)
    # -------------------------------------------------------------------------
    if rule_id == "550" and (rule_level is None or rule_level <= 7):
        full_log_lower = full_log.lower()
        if ("logrotate" in full_log_lower or ".gz" in full_log_lower or ".log.1" in full_log_lower) and "sudoers" not in full_log_lower and "shadow" not in full_log_lower and "passwd" not in full_log_lower:
            return {
                "action": "conclude",
                "verdict": "benign_likely",
                "severity": "info",
                "confidence": "high",
                "summary": "Fast-Path: Thay đổi tệp do tiến trình xoay vòng nhật ký hệ thống (logrotate) tự động.",
                "evidence": [f"Wazuh Rule 550", "Tệp nén logrotate định kỳ."],
                "missing_data": [],
                "recommended_actions": [],
                "fast_path": True,
            }

    return None


class WazuhWebhookManager:
    """Quản lý tiếp nhận alert từ Wazuh qua hàng đợi tuần tự (FIFO Queue)."""

    def __init__(self, auto_block: bool = True, test_mode: bool = False, cooldown_minutes: int = 15):
        self.auto_block = auto_block
        self.test_mode = test_mode
        self.cooldown_minutes = cooldown_minutes
        self.ip_cooldown: Dict[str, float] = {}
        self.total_alerts_received = 0
        self.total_blocks_executed = 0
        self.total_emails_sent = 0
        self.start_time = datetime.now()
        self.running = False
        self._lock = threading.Lock()

        # Hàng đợi tuần tự FIFO
        self.alert_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._worker_thread: Optional[threading.Thread] = None

        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        self._load_state()

    def _load_state(self):
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.total_alerts_received = data.get("total_alerts_handled", 0)
                    self.total_blocks_executed = data.get("total_blocks_executed", 0)
                    self.total_emails_sent = data.get("total_emails_sent", 0)
            except Exception:
                pass

    def _save_state(self):
        with self._lock:
            state = {
                "is_running": self.running,
                "mode": "event-driven (Authenticated Wazuh SIEM Webhook)",
                "pid": os.getpid(),
                "started_at": self.start_time.isoformat(),
                "last_active_at": datetime.now().isoformat(),
                "auto_block_enabled": self.auto_block,
                "queue_size": self.alert_queue.qsize(),
                "total_alerts_handled": self.total_alerts_received,
                "total_blocks_executed": self.total_blocks_executed,
                "total_emails_sent": self.total_emails_sent,
                "active_cooldowns": {
                    ip: round(time.time() - ts, 1) for ip, ts in self.ip_cooldown.items()
                }
            }
            try:
                with open(STATE_FILE, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

    def is_in_cooldown(self, ip: str) -> bool:
        if not ip:
            return False
        last_time = self.ip_cooldown.get(ip)
        if not last_time:
            return False
        return (time.time() - last_time) < (self.cooldown_minutes * 60)

    def check_and_expire_active_blocks(self):
        """Tự động gỡ bỏ các IP đã hết hạn cách ly 15 phút."""
        active_blocks = load_active_blocks()
        if not active_blocks:
            return

        now = datetime.now()
        for ip, info in list(active_blocks.items()):
            expires_at_str = info.get("expires_at")
            if not expires_at_str:
                continue
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if now >= expires_at:
                    print(f"\n⏰ [TTL EXPIRED] Hết hạn cách ly 15 phút cho IP {ip}!")
                    print(f"[*] Đang tự động gỡ chặn IP {ip} trên tường lửa UFW...")
                    if not self.test_mode:
                        unblock_ip(ip)
                    remove_active_block(ip)
                    eval_dec = evaluate_action("unblock_ip", ip)
                    record_audit_log(
                        action="unblock_ip",
                        target=ip,
                        operator="Wazuh Event-Driven TTL Scheduler",
                        policy_decision=eval_dec,
                        execution_result={"status": "success", "note": "Auto TTL Expiration"},
                        verification_result={"state": "unblocked", "verified": True}
                    )
                    print(f"✅ [UNBLOCKED] Đã gỡ bỏ luật chặn IP {ip} thành công.\n")
            except Exception as ex:
                print(f"[!] Lỗi khi xử lý TTL IP {ip}: {ex}")

    def append_alert_to_history(self, alert: dict, raw_payload: dict):
        """Lưu vết sự kiện nhận được từ Wazuh vào runs/wazuh_alerts.jsonl."""
        entry = {
            "received_at": datetime.now().isoformat(),
            "alert": alert,
            "raw_wazuh": raw_payload
        }
        try:
            with open(WAZUH_ALERTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as ex:
            print(f"[!] Lỗi ghi wazuh_alerts.jsonl: {ex}")

    def enqueue_alert(self, raw_payload: dict) -> Tuple[bool, str, int]:
        """Đưa alert mới vào hàng đợi FIFO để worker xử lý tuần tự."""
        try:
            self.alert_queue.put_nowait(raw_payload)
            q_size = self.alert_queue.qsize()
            return True, "Alert queued successfully", q_size
        except queue.Full:
            return False, "Queue is full (Overload Protection)", self.alert_queue.qsize()

    def start_worker(self):
        """Khởi động luồng worker xử lý tuần tự hàng đợi alert."""
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
            self._worker_thread.start()

    def _worker_loop(self):
        """Vòng lặp lấy alert từ hàng đợi và tiến hành điều tra phản ứng."""
        while self.running:
            try:
                raw_payload = self.alert_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self.process_wazuh_alert(raw_payload)
            except Exception as ex:
                print(f"[!] Lỗi trong worker xử lý alert: {ex}")
            finally:
                self.alert_queue.task_done()

    def process_wazuh_alert(self, raw_payload: dict) -> dict:
        """Xử lý toàn diện một cảnh báo sau khi rút ra từ hàng đợi."""
        alert = normalize_wazuh_alert(raw_payload)
        self.append_alert_to_history(alert, raw_payload)

        src_ip = alert.get("src_ip")
        rule_desc = alert.get("wazuh", {}).get("description", alert.get("summary"))
        rule_id = alert.get("wazuh", {}).get("rule_id", "N/A")
        rule_level = alert.get("wazuh", {}).get("level", 7)
        sev = alert.get("severity_hint", "medium").upper()

        print("\n" + "=" * 75)
        print(f"📥 [WAZUH ALERT TỪ HÀNG ĐỢI] Rule: {rule_id} | Cấp độ: {rule_level} ({sev})")
        print(f"   Mô tả: {rule_desc}")
        print(f"   IP Nguồn: {src_ip or 'N/A'} | Target User: {alert.get('user')}")
        print(f"   Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 75)

        # Kiểm tra IP Cooldown chống bão alert
        if src_ip and self.is_in_cooldown(src_ip):
            print(f"  [COOLDOWN] Bỏ qua điều tra IP {src_ip} (đang trong thời gian làm nguội 15 phút).")
            return {"status": "skipped", "reason": f"IP {src_ip} in cooldown"}

        if src_ip:
            self.ip_cooldown[src_ip] = time.time()

        self.total_alerts_received += 1

        # 1. Thử nghiệm Fast-Path Triage xác định (Tier 1.5 - <1ms)
        fast_conclusion = fast_path_triage(alert)
        if fast_conclusion:
            print(f"⚡ [FAST-PATH TRIAGE] Nhận diện hành vi bảo trì hợp lệ trong <1ms (Bỏ qua LLM queue):")
            print(f"   Verdict: {fast_conclusion['verdict']} | Tóm tắt: {fast_conclusion['summary']}")
            run = {
                "model": "Fast-Path Deterministic Filter (Tier 1.5)",
                "elapsed_sec": 0.001,
                "tool_calls": 0,
                "conclusion": fast_conclusion
            }
            # Ghi nhận kiểm toán cho fast-path bypass để chuyên viên SOC có audit trail hoàn chỉnh
            record_audit_log(
                action="fast_path_triage",
                target=alert.get("src_ip") or alert.get("user") or "system",
                operator="Fast-Path Deterministic Filter (Tier 1.5)",
                policy_decision=PolicyDecision(True, "Fast-path: Hành vi bảo trì/quản trị hợp lệ khớp chữ ký an toàn"),
                execution_result={"status": "bypassed_llm", "verdict": fast_conclusion["verdict"], "rule_id": rule_id},
                verification_result={"fast_path": True}
            )
        else:
            # Kích hoạt AI ReAct Agent điều tra thông minh qua Local Ollama
            print(f"[*] Đang kích hoạt Local AI SOC Agent (Ollama) để phân tích bằng chứng...")
            try:
                run = investigate(alert, verbose=False)
            except Exception as ex:
                print(f"[-] Lỗi trong quá trình AI ReAct điều tra: {ex}")
                run = {
                    "model": "qwen3:4b (Fallback)",
                    "conclusion": {
                        "verdict": "malicious_activity_likely",
                        "severity": sev.lower(),
                        "confidence": "high",
                        "summary": f"Wazuh SIEM phát hiện sự cố: {rule_desc}",
                        "evidence": [f"Wazuh Rule {rule_id}: {rule_desc}"],
                        "recommended_actions": [f"Chặn IP {src_ip}"] if src_ip else []
                    }
                }

        conclusion = run.get("conclusion", {})
        verdict = conclusion.get("verdict", "")
        recs = conclusion.get("recommended_actions", [])
        evidence = conclusion.get("evidence", [])

        print(f"[+] Kết luận điều tra: Verdict={verdict} | Severity={conclusion.get('severity')} | Confidence={conclusion.get('confidence')}")
        print(f"    Tóm tắt: {conclusion.get('summary')}")

        # 2. Thẩm định qua Policy Engine & Quyết định phản ứng
        response_info = {"action": "none", "status": "none"}
        should_block = any("chặn" in r.lower() or "block" in r.lower() for r in recs) or (verdict == "malicious_activity_likely" and src_ip)

        if should_block and src_ip:
            print(f"\n🛡️ [POLICY ENGINE] Thẩm định an toàn cho đề xuất cách ly IP '{src_ip}'...")
            decision = evaluate_action(
                action="block_ip",
                target=src_ip,
                context={
                    "alert": alert,
                    "evidence": evidence,
                    "verdict": verdict,
                    "confidence": conclusion.get("confidence"),
                    "severity": conclusion.get("severity"),
                }
            )

            if decision.allowed:
                print(f"✅ [CHẤP THUẬN] {decision.reason}")
                if self.auto_block:
                    print(f"⚡ [AUTO-BLOCK] Chế độ Tự hành kích hoạt! Đang chặn IP {src_ip} qua UFW Wrapper...")
                    if not self.test_mode:
                        exec_res = block_ip(src_ip)
                        verify_res = verify_response(src_ip, expected_state="blocked")
                    else:
                        exec_res = {"status": "success", "note": "Test/Mock mode"}
                        verify_res = {"state": "blocked", "active": True}

                    save_active_block(src_ip, ttl_minutes=DEFAULT_BLOCK_TTL_MINUTES)
                    record_audit_log(
                        action="block_ip",
                        target=src_ip,
                        operator="Wazuh SIEM Autonomous Webhook",
                        policy_decision=decision,
                        execution_result=exec_res,
                        verification_result=verify_res
                    )
                    self.total_blocks_executed += 1
                    response_info = {
                        "action": "block_ip",
                        "status": "blocked",
                        "target_ip": src_ip,
                        "ttl_minutes": DEFAULT_BLOCK_TTL_MINUTES,
                        "reason": decision.reason,
                    }
                    print(f"🛡️ [HOÀN TẤT CÁCH LY] IP {src_ip} đã bị chặn trên UFW trong {DEFAULT_BLOCK_TTL_MINUTES} phút.")
                else:
                    response_info = {
                        "action": "block_ip",
                        "status": "pending_approval",
                        "target_ip": src_ip,
                        "reason": "Chế độ Auto-Block đang tắt. Chờ chuyên viên bấm duyệt trên Dashboard."
                    }
                    print(f"⏳ [PENDING APPROVAL] Đề xuất chặn IP {src_ip} đang chờ chuyên viên duyệt thủ công.")
            else:
                record_audit_log(
                    action="block_ip",
                    target=src_ip,
                    operator="Wazuh SIEM Autonomous Webhook",
                    policy_decision=decision,
                    execution_result={"status": "rejected"},
                    verification_result=None
                )
                response_info = {
                    "action": "block_ip",
                    "status": "rejected",
                    "target_ip": src_ip,
                    "reason": decision.reason,
                }
                print(f"🛑 [BỊ TỪ CHỐI BẢO MẬT] Không thể chặn IP {src_ip}: {decision.reason}")

        # 3. Soạn và Gửi Email Báo động Cảnh báo
        print(f"\n📧 [THÔNG BÁO] Đang xử lý email báo cáo sự cố...")
        subject = f"🚨 [WAZUH SOC ALERT] {rule_desc} từ {src_ip or 'Hệ thống'} (Cấp độ: {rule_level})"
        html_body = build_alert_html(alert, run, response_info)
        plain_text = f"Cảnh báo Wazuh {rule_desc} từ IP {src_ip}. Verdict: {verdict}. Xem file HTML đính kèm để biết chi tiết."

        email_res = send_alert_email(subject, html_body, plain_text)
        if email_res.get("status") == "sent":
            self.total_emails_sent += 1
            print(f"✅ [EMAIL SENT] Đã gửi thư cảnh báo thành công tới: {email_res.get('recipient')}")
        elif email_res.get("status") == "skipped":
            print(f"ℹ️ [EMAIL SKIPPED] {email_res.get('reason')}")
            print(f"   Bản tin HTML đã được lưu tại: {email_res.get('preview_path')}")
        else:
            print(f"⚠️ [EMAIL ERROR] {email_res.get('error')}")

        print("-" * 75 + "\n")
        self._save_state()

        return {
            "status": "success",
            "alert": alert,
            "investigation": run,
            "response": response_info
        }


# Global Manager Instance
_manager_instance: Optional[WazuhWebhookManager] = None


def get_wazuh_manager(auto_block: bool = True, test_mode: bool = False) -> WazuhWebhookManager:
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = WazuhWebhookManager(auto_block=auto_block, test_mode=test_mode)
    return _manager_instance


class WazuhWebhookHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler tiếp nhận và thẩm định các request từ Wazuh Integration."""

    def log_message(self, format, *args):
        # Ẩn bớt log mặc định để console gọn gàng
        pass

    def _send_json_response(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> bool:
        """Xác thực Token qua Header X-SOC-Token hoặc Authorization Bearer."""
        expected_token = os.getenv("WEBHOOK_AUTH_TOKEN", DEFAULT_AUTH_TOKEN).strip()
        if not expected_token:
            return True  # Nếu không cấu hình token thì bỏ qua (không khuyến nghị)

        # 1. Kiểm tra header X-SOC-Token
        token = self.headers.get("X-SOC-Token")
        if token and token.strip() == expected_token:
            return True

        # 2. Kiểm tra header Authorization: Bearer <token>
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header[7:].strip()
            if bearer_token == expected_token:
                return True

        return False

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-SOC-Token")
        self.end_headers()

    def do_GET(self):
        # 1. Kiểm tra dải IP nguồn của client
        client_ip = self.client_address[0]
        if not is_allowed_client_ip(client_ip):
            self._send_json_response(403, {"error": "Forbidden: Untrusted network origin", "client_ip": client_ip})
            return

        parsed_path = self.path.split("?")[0]
        if parsed_path in ("/api/v1/health", "/health", "/"):
            manager = get_wazuh_manager()
            self._send_json_response(200, {
                "status": "healthy",
                "mode": "event-driven (Authenticated Wazuh SIEM Webhook)",
                "uptime_sec": round((datetime.now() - manager.start_time).total_seconds(), 1),
                "queue_size": manager.alert_queue.qsize(),
                "total_alerts_handled": manager.total_alerts_received,
                "total_blocks_executed": manager.total_blocks_executed,
                "auto_block_enabled": manager.auto_block
            })
        elif parsed_path == "/api/v1/alerts":
            alerts = []
            if WAZUH_ALERTS_FILE.exists():
                try:
                    with open(WAZUH_ALERTS_FILE, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                        for line in lines[-20:]:
                            if line.strip():
                                alerts.append(json.loads(line))
                except Exception:
                    pass
            self._send_json_response(200, {"count": len(alerts), "alerts": list(reversed(alerts))})
        else:
            self._send_json_response(404, {"error": "Not Found", "endpoint": self.path})

    def do_POST(self):
        # 1. Kiểm tra dải IP nguồn của client
        client_ip = self.client_address[0]
        if not is_allowed_client_ip(client_ip):
            self._send_json_response(403, {"error": "Forbidden: Client IP not in allowed host-only subnet", "client_ip": client_ip})
            return

        parsed_path = self.path.split("?")[0]
        if parsed_path not in ("/api/v1/wazuh-alert", "/api/v1/simulate", "/webhook"):
            self._send_json_response(404, {"error": "Unknown endpoint", "path": self.path})
            return

        # 2. Xác thực Token
        if not self._check_auth():
            self._send_json_response(401, {"error": "Unauthorized: Invalid or missing X-SOC-Token / Bearer token"})
            return

        # 3. Kiểm tra kích thước payload (chống DoS / tràn bộ nhớ)
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len == 0:
            self._send_json_response(400, {"error": "Bad Request: Empty body"})
            return
        if content_len > MAX_PAYLOAD_BYTES:
            self._send_json_response(413, {"error": f"Payload Too Large: Exceeds {MAX_PAYLOAD_BYTES} bytes"})
            return

        raw_body = self.rfile.read(content_len).decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw_body)
        except Exception as ex:
            self._send_json_response(400, {"error": f"Invalid JSON payload: {ex}"})
            return

        # 4. Kiểm định Schema của Wazuh Alert Payload
        valid, schema_msg = validate_wazuh_payload_schema(payload)
        if not valid:
            self._send_json_response(422, {"error": f"Unprocessable Entity (Schema Validation Failed): {schema_msg}"})
            return

        # 5. Đưa vào Hàng đợi FIFO và phản hồi HTTP 200 NGAY LẬP TỨC (<5ms)
        manager = get_wazuh_manager()
        ok, msg, qsize = manager.enqueue_alert(payload)

        if ok:
            self._send_json_response(200, {
                "status": "accepted",
                "message": msg,
                "queue_position": qsize,
                "timestamp": datetime.now().isoformat()
            })
        else:
            self._send_json_response(503, {
                "status": "rejected",
                "error": msg,
                "queue_size": qsize
            })


class WazuhWebhookServer:
    """Server đóng gói ThreadingHTTPServer, Worker Thread hàng đợi và TTL Scheduler."""

    def __init__(self, host: str = DEFAULT_WEBHOOK_HOST, port: int = DEFAULT_WEBHOOK_PORT, auto_block: bool = True, test_mode: bool = False):
        self.host = host
        self.port = port
        self.manager = get_wazuh_manager(auto_block=auto_block, test_mode=test_mode)
        self.httpd: Optional[HTTPServer] = None
        self._stop_event = threading.Event()
        self._ttl_thread: Optional[threading.Thread] = None
        self._server_thread: Optional[threading.Thread] = None

    def _ttl_loop(self):
        """Vòng lặp ngầm kiểm tra và giải phóng IP hết hạn TTL 15 phút."""
        while not self._stop_event.is_set():
            try:
                self.manager.check_and_expire_active_blocks()
            except Exception as ex:
                print(f"[!] Lỗi trong TTL loop: {ex}")
            self._stop_event.wait(30)

    def start(self, blocking: bool = True):
        self.manager.running = True
        self.manager._save_state()

        # Khởi động Worker xử lý hàng đợi
        self.manager.start_worker()

        self.httpd = HTTPServer((self.host, self.port), WazuhWebhookHandler)
        self._stop_event.clear()

        # Khởi chạy thread kiểm tra TTL
        self._ttl_thread = threading.Thread(target=self._ttl_loop, daemon=True)
        self._ttl_thread.start()

        print(f"\n{'='*75}")
        print(f"🛡️  AI SOC WAZUH WEBHOOK RECEIVER ĐANG HOẠT ĐỘNG (EVENT-DRIVEN)")
        print(f"   Địa chỉ lắng nghe: http://{self.host}:{self.port}")
        print(f"   Endpoint tiếp nhận: POST http://{self.host}:{self.port}/api/v1/wazuh-alert")
        print(f"   Kiểm tra sức khỏe:   GET  http://{self.host}:{self.port}/api/v1/health")
        print(f"   Bảo mật Webhook:     Xác thực Token (X-SOC-Token / Bearer)")
        print(f"   Hàng đợi xử lý:      FIFO Queue (Xử lý tuần tự, phản hồi HTTP 200 tức thời)")
        print(f"   Chế độ Auto-Block:   {'BẬT (Tự động cách ly qua UFW)' if self.manager.auto_block else 'TẮT (Chờ duyệt thủ công)'}")
        print(f"{'='*75}\n")

        if blocking:
            try:
                self.httpd.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self._server_thread.start()

    def stop(self):
        print("\n[*] Đang dừng Wazuh Webhook Server...")
        self._stop_event.set()
        self.manager.running = False
        self.manager._save_state()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        print("✅ Wazuh Webhook Server đã dừng an toàn.")


def start_wazuh_listener(host: str = DEFAULT_WEBHOOK_HOST, port: int = DEFAULT_WEBHOOK_PORT, auto_block: bool = True, test_mode: bool = False, blocking: bool = True) -> WazuhWebhookServer:
    server = WazuhWebhookServer(host=host, port=port, auto_block=auto_block, test_mode=test_mode)
    server.start(blocking=blocking)
    return server


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Khởi chạy Wazuh Webhook Receiver bảo mật cho AI SOC Agent.")
    parser.add_argument("--host", default=DEFAULT_WEBHOOK_HOST, help=f"Địa chỉ host lắng nghe (mặc định {DEFAULT_WEBHOOK_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_WEBHOOK_PORT, help="Cổng lắng nghe (mặc định 5000)")
    parser.add_argument("--no-block", action="store_true", help="Tắt tự động block IP")
    parser.add_argument("--test-mode", action="store_true", help="Chế độ kiểm thử (không gọi UFW thật)")
    args = parser.parse_args()

    start_wazuh_listener(
        host=args.host,
        port=args.port,
        auto_block=not args.no_block,
        test_mode=args.test_mode,
        blocking=True
    )
