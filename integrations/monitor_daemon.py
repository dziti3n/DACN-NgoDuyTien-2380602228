# ==============================================================================
# monitor_daemon.py - Tiến trình Giám sát An ninh Tự hành (Autonomous SOAR Daemon)
# Tự động phát hiện tấn công ngầm, kích hoạt AI ReAct điều tra, thẩm định qua
# Policy Engine, tự động cô lập IP qua UFW và gửi email cảnh báo về Gmail.
# ==============================================================================

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

# Đảm bảo UTF-8 trên Windows PowerShell
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

try:
    from telemetry.read_logs import run_fixed_command, HOST
    from telemetry.log_parser import parse_log
    from telemetry.detection import detect_all, alert_to_dict
    from core.agent import investigate
    from telemetry.tools import block_ip, unblock_ip, verify_response
    from core.policy_engine import (
        evaluate_action,
        record_audit_log,
        save_active_block,
        remove_active_block,
        load_active_blocks,
        DEFAULT_BLOCK_TTL_MINUTES,
    )
    from integrations.notifier import build_alert_html, send_alert_email
except ImportError:
    from read_logs import run_fixed_command, HOST
    from log_parser import parse_log
    from detection import detect_all, alert_to_dict
    from agent import investigate
    from tools import block_ip, unblock_ip, verify_response
    from policy_engine import (
        evaluate_action,
        record_audit_log,
        save_active_block,
        remove_active_block,
        load_active_blocks,
        DEFAULT_BLOCK_TTL_MINUTES,
    )
    from notifier import build_alert_html, send_alert_email

STATE_FILE = Path("runs/monitor_state.json")
RUNS_DIR = Path("runs")


def extract_ip_from_alert(alert: dict) -> Optional[str]:
    """Trích xuất IP nguồn từ cảnh báo an ninh."""
    ip = alert.get("src_ip") or alert.get("details", {}).get("src_ip")
    if ip:
        return ip
    # Tìm kiếm theo regex nếu không có trường rõ ràng
    summary = alert.get("summary", "")
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", summary)
    return m.group(0) if m else None


class SOCMonitorDaemon:
    def __init__(
        self,
        poll_interval: Optional[int] = None,
        auto_block: Optional[bool] = None,
        lines_to_check: int = 300,
        cooldown_minutes: int = 15,
        test_mode: bool = False
    ):
        self.poll_interval = poll_interval if poll_interval is not None else int(os.getenv("MONITOR_POLL_INTERVAL", "20"))
        if auto_block is not None:
            self.auto_block = auto_block
        else:
            self.auto_block = os.getenv("AUTO_BLOCK_ENABLED", "true").lower() in ("true", "1", "yes")

        self.lines_to_check = lines_to_check
        self.cooldown_minutes = cooldown_minutes
        self.test_mode = test_mode
        self.mode = os.getenv("DAEMON_MODE", "event-driven").lower()

        self.ip_cooldown: Dict[str, float] = {}  # ip -> timestamp lần cuối điều tra
        self.running = False
        self.cycles_count = 0
        self.total_alerts_handled = 0
        self.total_blocks_executed = 0
        self.total_emails_sent = 0
        self.start_time = datetime.now()

        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        self._load_state()

    def _load_state(self):
        """Đọc trạng thái daemon nếu đã từng chạy."""
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.total_alerts_handled = data.get("total_alerts_handled", 0)
                    self.total_blocks_executed = data.get("total_blocks_executed", 0)
                    self.total_emails_sent = data.get("total_emails_sent", 0)
            except Exception:
                pass

    def _save_state(self):
        """Ghi nhận trạng thái hiện thời của daemon."""
        state = {
            "is_running": self.running,
            "pid": os.getpid(),
            "started_at": self.start_time.isoformat(),
            "last_cycle_at": datetime.now().isoformat(),
            "poll_interval_sec": self.poll_interval,
            "auto_block_enabled": self.auto_block,
            "cycles_completed": self.cycles_count,
            "total_alerts_handled": self.total_alerts_handled,
            "total_blocks_executed": self.total_blocks_executed,
            "total_emails_sent": self.total_emails_sent,
            "active_cooldowns": {
                ip: round(time.time() - ts, 1) for ip, ts in self.ip_cooldown.items()
            }
        }
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
        except Exception as ex:
            print(f"[!] Lỗi ghi trạng thái daemon: {ex}")

    def check_and_expire_active_blocks(self):
        """
        Kiểm tra danh sách IP đang bị cách ly tạm thời.
        Nếu thời hạn TTL (15 phút) đã trôi qua, tự động gỡ chặn qua wrapper script UFW.
        """
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
                    print(f"\n⏰ [TTL EXPIRED] Thời hạn cách ly 15 phút cho IP {ip} đã hết!")
                    print(f"[*] Đang tự động gỡ chặn IP {ip} trên tường lửa UFW...")
                    if not self.test_mode:
                        unblock_ip(ip)
                    remove_active_block(ip)
                    eval_dec = evaluate_action("unblock_ip", ip)
                    record_audit_log(
                        action="unblock_ip",
                        target=ip,
                        operator="Autonomous SOAR TTL Scheduler",
                        policy_decision=eval_dec,
                        execution_result={"status": "success", "note": "Auto TTL Expiration"},
                        verification_result={"state": "unblocked", "verified": True}
                    )
                    print(f"✅ [UNBLOCKED] Đã mở khóa IP {ip} thành công.\n")
            except Exception as ex:
                print(f"[!] Lỗi khi kiểm tra TTL IP {ip}: {ex}")

    def is_in_cooldown(self, ip: str) -> bool:
        """Kiểm tra xem IP có đang trong thời gian làm nguội (15 phút) hay không."""
        if not ip:
            return False
        last_time = self.ip_cooldown.get(ip)
        if not last_time:
            return False
        elapsed = time.time() - last_time
        return elapsed < (self.cooldown_minutes * 60)

    def fetch_current_alerts(self) -> List[dict]:
        """Đọc log auth.log từ máy chủ lab qua SSH và chạy bộ phát hiện."""
        try:
            out, err = run_fixed_command(f"tail -n {self.lines_to_check} /var/log/auth.log")
            if not out.strip() and err:
                print(f"[-] [SSH] Lỗi đọc log auth.log: {err}")
                return []
            events = parse_log(out)
            alerts = [alert_to_dict(a) for a in detect_all(events, baseline_path="baseline.json")]
            return alerts
        except Exception as ex:
            print(f"[-] [SSH] Không thể kết nối tới máy chủ lab {HOST}: {ex}")
            return []

    def handle_alert(self, alert: dict):
        """Xử lý trọn gói một cảnh báo an ninh mới xuất hiện."""
        src_ip = extract_ip_from_alert(alert)
        rule = alert.get("rule", "unknown")
        sev = alert.get("severity_hint", "medium").upper()

        # Áp dụng cơ chế chống bão cảnh báo (Cooldown 15 phút)
        if src_ip and self.is_in_cooldown(src_ip):
            print(f"  [COOLDOWN] Bỏ qua cảnh báo lặp lại từ IP {src_ip} (đang trong thời gian làm nguội 15 phút).")
            return

        print("\n" + "=" * 70)
        print(f"🚨 [PHÁT HIỆN TẤN CÔNG MỚI] {rule.upper()} | Mức độ: {sev}")
        print(f"   IP Nguồn: {src_ip or 'N/A'} | Tóm tắt: {alert.get('summary')}")
        print(f"   Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        # Cập nhật mốc làm nguội cho IP ngay lập tức
        if src_ip:
            self.ip_cooldown[src_ip] = time.time()

        self.total_alerts_handled += 1

        # 1. Kích hoạt AI ReAct Agent điều tra ngầm
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
                    "confidence": "medium",
                    "summary": f"Tự động phát hiện bởi rule {rule}: {alert.get('summary')}",
                    "evidence": [f"Log hệ thống phát hiện hành vi {rule}"],
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
                        exec_res = {"status": "success", "note": "Test mode"}
                        verify_res = {"state": "blocked", "active": True}

                    save_active_block(src_ip, ttl_minutes=DEFAULT_BLOCK_TTL_MINUTES)
                    record_audit_log(
                        action="block_ip",
                        target=src_ip,
                        operator="Autonomous SOAR Daemon",
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
                    operator="Autonomous SOAR Daemon",
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

        # 3. Soạn và Gửi Email Cảnh báo Tự động
        print(f"\n📧 [THÔNG BÁO] Đang xử lý email báo cáo sự cố...")
        subject = f"🚨 [SOC ALERT] {rule.upper()} từ {src_ip or 'Máy chủ'} (Mức độ: {sev})"
        html_body = build_alert_html(alert, run, response_info)
        plain_text = f"Cảnh báo an ninh {rule} từ IP {src_ip}. Verdict: {verdict}. Xem file HTML đính kèm để biết chi tiết."

        email_res = send_alert_email(subject, html_body, plain_text)
        if email_res["status"] == "sent":
            self.total_emails_sent += 1
            print(f"✅ [EMAIL SENT] Đã gửi thư cảnh báo thành công tới: {email_res.get('recipient')}")
        elif email_res["status"] == "skipped":
            print(f"ℹ️ [EMAIL SKIPPED] {email_res.get('reason')}")
            print(f"   Bản tin HTML đã được lưu tại: {email_res.get('preview_path')}")
        else:
            print(f"⚠️ [EMAIL ERROR] {email_res.get('error')}")
            print(f"   Bản tin HTML dự phòng đã được lưu tại: {email_res.get('preview_path')}")

        print("-" * 70 + "\n")

    def run_cycle(self):
        """Thực thi một chu kỳ giám sát."""
        self.cycles_count += 1
        now_str = datetime.now().strftime("%H:%M:%S")
        print(f"[{now_str}] Chu kỳ #{self.cycles_count}: Đang kiểm tra an ninh máy chủ {HOST}...")

        # 1. Kiểm tra và gỡ các block IP đã hết hạn 15 phút
        self.check_and_expire_active_blocks()

        # 2. Quét log tìm cảnh báo an ninh mới
        alerts = self.fetch_current_alerts()
        if alerts:
            for alert in alerts:
                self.handle_alert(alert)
        else:
            print(f"         ✅ Không phát hiện bất thường mới. Hệ thống an toàn.")

        self._save_state()

    def start(self, mode: Optional[str] = None):
        """Khởi động Daemon theo chế độ Event-Driven (Wazuh Webhook) hoặc Legacy Polling."""
        active_mode = mode or self.mode
        if active_mode in ("event-driven", "webhook", "wazuh"):
            try:
                from integrations.wazuh_listener import start_wazuh_listener
            except ImportError:
                from wazuh_listener import start_wazuh_listener
            webhook_port = int(os.getenv("WEBHOOK_PORT", "5000"))
            webhook_host = os.getenv("WEBHOOK_HOST", "0.0.0.0")
            print("\n" + "=" * 75)
            print("🚀 KHỞI ĐỘNG TIẾN TRÌNH GIÁM SÁT AN NINH EVENT-DRIVEN (WAZUH SIEM INTEGRATION)")
            print(f"   Chế độ:           SIEM-Push Webhook Receiver (0% CPU khi rảnh)")
            print(f"   Địa chỉ lắng nghe: http://{webhook_host}:{webhook_port}/api/v1/wazuh-alert")
            print(f"   Chế độ Auto-Block: {'BẬT (Full Autonomous)' if self.auto_block else 'TẮT (Semi-Autonomous)'}")
            print(f"   Thời hạn TTL:     15 phút (Tự động gỡ bỏ qua Scheduler)")
            print("=" * 75 + "\n")
            start_wazuh_listener(
                host=webhook_host,
                port=webhook_port,
                auto_block=self.auto_block,
                test_mode=self.test_mode,
                blocking=True
            )
            return

        # Chế độ Legacy Polling qua SSH
        self.running = True
        print("\n" + "=" * 70)
        print("🚀 KHỞI ĐỘNG TIẾN TRÌNH GIÁM SÁT AN NINH (LEGACY SSH POLLING)")
        print(f"   Máy chủ mục tiêu: {HOST}")
        print(f"   Chu kỳ thăm dò:  {self.poll_interval} giây/lần")
        print(f"   Chế độ Auto-Block: {'BẬT (Full Autonomous)' if self.auto_block else 'TẮT (Semi-Autonomous)'}")
        print(f"   Thời gian Cooldown: {self.cooldown_minutes} phút/IP")
        print("   Nhấn Ctrl+C để dừng tiến trình bất kỳ lúc nào.")
        print("=" * 70 + "\n")

        self._save_state()

        try:
            while self.running:
                self.run_cycle()
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Dừng tiến trình giám sát một cách an toàn."""
        self.running = False
        self._save_state()
        print("\n" + "=" * 70)
        print("🛑 TIẾN TRÌNH GIÁM SÁT ĐÃ DỪNG AN TOÀN")
        print(f"   Tổng số chu kỳ đã chạy: {self.cycles_count}")
        print(f"   Tổng số cảnh báo đã xử lý: {self.total_alerts_handled}")
        print(f"   Tổng số IP đã cô lập UFW:  {self.total_blocks_executed}")
        print(f"   Tổng số Email đã gửi:      {self.total_emails_sent}")
        print("=" * 70 + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AI SOC Autonomous Monitor Daemon")
    parser.add_argument("--mode", choices=["event-driven", "poll"], default=os.getenv("DAEMON_MODE", "event-driven"), help="Chế độ giám sát: event-driven (Wazuh Webhook) hoặc poll (SSH polling)")
    parser.add_argument("--no-block", action="store_true", help="Tắt tự động block IP")
    parser.add_argument("--test-mode", action="store_true", help="Chế độ kiểm thử")
    args = parser.parse_args()

    daemon = SOCMonitorDaemon(auto_block=not args.no_block, test_mode=args.test_mode)
    daemon.start(mode=args.mode)
