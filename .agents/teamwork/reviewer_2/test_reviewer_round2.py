import html
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import (
    get_severity_badge,
    get_verdict_badge,
    extract_ip_from_text,
    format_cyber_terminal_html,
)
from policy_engine import (
    evaluate_action,
    check_rate_limit,
    record_audit_log,
    load_protected_ips,
    validate_ip,
    PolicyDecision,
)
from notifier import build_alert_html, send_alert_email, get_email_config

class ReviewerRound2TestSuite(unittest.TestCase):
    def test_check_rate_limit_supports_ok_and_success(self):
        """Kiểm tra check_rate_limit nhận diện cả status 'ok' và 'success'."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            jsonl_path = os.path.join(tmp_dir, "audit_trail.jsonl")
            now = datetime.now()

            # 4 bản ghi: 2 ok, 2 success -> Chưa vượt ngưỡng 5
            entries = [
                {"timestamp": (now - timedelta(minutes=10)).isoformat(), "action": "block_ip", "execution": {"status": "ok"}},
                {"timestamp": (now - timedelta(minutes=20)).isoformat(), "action": "block_ip", "execution": {"status": "success"}},
                {"timestamp": (now - timedelta(minutes=30)).isoformat(), "action": "block_ip", "execution": {"status": "ok"}},
                {"timestamp": (now - timedelta(minutes=40)).isoformat(), "action": "block_ip", "execution": {"status": "success"}},
            ]
            with open(jsonl_path, "w", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e) + "\n")

            allowed, msg = check_rate_limit(max_per_hour=5, log_dir=tmp_dir)
            self.assertTrue(allowed)
            self.assertIn("4/5", msg)

            # Thêm bản ghi thứ 5 có status 'success' -> Phải chạm ngưỡng 5
            with open(jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"timestamp": now.isoformat(), "action": "block_ip", "execution": {"status": "success"}}) + "\n")

            allowed, msg = check_rate_limit(max_per_hour=5, log_dir=tmp_dir)
            self.assertFalse(allowed)
            self.assertIn("5 lần chặn", msg)

    def test_monitor_daemon_mocking_prevents_file_pollution(self):
        """Kiểm tra test_handle_alert_autonomous_block không ghi đè vào file audit thực."""
        from monitor_daemon import SOCMonitorDaemon
        daemon = SOCMonitorDaemon(test_mode=True)
        alert = {
            "rule": "ssh_bruteforce",
            "src_ip": "192.168.56.102",
            "summary": "Brute force test",
            "severity_hint": "critical",
        }

        with patch("monitor_daemon.record_audit_log") as mock_audit, \
             patch("monitor_daemon.save_active_block") as mock_save, \
             patch("monitor_daemon.investigate") as mock_inv, \
             patch("monitor_daemon.send_alert_email") as mock_email:

            mock_inv.return_value = {
                "conclusion": {
                    "verdict": "malicious_activity_likely",
                    "severity": "critical",
                    "confidence": "high",
                    "summary": "Attack",
                    "evidence": ["Failures"],
                    "recommended_actions": ["Chặn IP 192.168.56.102"],
                }
            }
            daemon.handle_alert(alert)
            mock_audit.assert_called_once()
            mock_save.assert_called_once()

    def test_notifier_env_isolation(self):
        """Kiểm tra test_notifier không làm rò rỉ ALERT_EMAIL_ENABLED=false ra môi trường toàn cục."""
        initial_val = os.environ.get("ALERT_EMAIL_ENABLED")
        try:
            with unittest.mock.patch.dict(os.environ, {"ALERT_EMAIL_ENABLED": "false"}):
                self.assertEqual(os.environ.get("ALERT_EMAIL_ENABLED"), "false")
            # Sau khi thoát context, giá trị phải được khôi phục nguyên vẹn
            self.assertEqual(os.environ.get("ALERT_EMAIL_ENABLED"), initial_val)
        finally:
            if initial_val is not None:
                os.environ["ALERT_EMAIL_ENABLED"] = initial_val

    def test_cyber_terminal_regex_and_special_queries(self):
        """Kiểm tra terminal log với các ký tự đặc biệt, regex và HTML."""
        raw_log = (
            "2026-10-23T22:00:00 dacnsoc sshd[123]: Failed password for root from 192.168.56.102 port 22\n"
            "2026-10-23T22:00:01 dacnsoc systemd-logind[456]: session opened for user agent_soc\n"
            "2026-10-23T22:00:02 dacnsoc sudo: agent_soc : TTY=pts/0 ; COMMAND=/bin/bash\n"
        )

        # 1. Regex metacharacters in query
        for special_q in ["[sshd]", "sshd[123]", "(root)", "192.168.56.*", "root|agent"]:
            out = format_cyber_terminal_html(raw_log, query=special_q)
            self.assertIsInstance(out, str)

        # 2. HTML special characters
        out_html = format_cyber_terminal_html(raw_log, query="<root>")
        self.assertNotIn("<script>", out_html)

        # 3. Normal filter match
        out_match = format_cyber_terminal_html(raw_log, query="192.168.56.102")
        self.assertIn("192.168.56.102", out_match)
        self.assertIn("<mark", out_match)

    def test_cyber_terminal_badges(self):
        """Kiểm tra độ phủ các badge mức độ nghiêm trọng và kết luận."""
        for s in ["critical", "high", "medium", "low", "info", "random"]:
            badge = get_severity_badge(s)
            self.assertIn("padding", badge)

        for v in ["malicious_activity_likely", "suspicious_needs_more_data", "benign_likely", "insufficient_data"]:
            badge = get_verdict_badge(v)
            self.assertTrue(any(emoji in badge for emoji in ["🚨", "⚠️", "✅", "❓"]))

    def test_policy_engine_whitelist_and_threshold(self):
        """Kiểm tra Policy Engine bảo vệ host và từ chối benign verdict."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Loopback must be rejected
            dec_lb = evaluate_action("block_ip", "127.0.0.1", log_dir=tmp_dir)
            self.assertFalse(dec_lb.allowed)
            self.assertIn("BẢO VỆ", dec_lb.reason)

            # Benign must be rejected
            dec_b = evaluate_action("block_ip", "192.168.56.102", context={"alert": {"src_ip": "192.168.56.102"}, "verdict": "benign_likely"}, log_dir=tmp_dir)
            self.assertFalse(dec_b.allowed)
            self.assertIn("benign_likely", dec_b.reason)

if __name__ == "__main__":
    unittest.main()
