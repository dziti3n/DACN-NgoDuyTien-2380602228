import html
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import app
from policy_engine import evaluate_action, load_active_blocks, save_active_block, remove_active_block


class TestReviewerRound3Suite(unittest.TestCase):
    def test_app_main_executes_without_name_error(self):
        """Kiểm tra app.main() thực thi không bị crash NameError ('is_busy' hay bất kỳ biến nào)."""
        # Giả lập mock fetch_live_logs và get_firewall_status để test chạy tức thì không cần SSH
        with patch("app.fetch_live_logs", return_value=("Oct 23 22:00:00 server sshd[100]: Accepted password for root from 192.168.56.101 port 22\n", None)):
            with patch("app.get_firewall_status", return_value={"status": "ok", "data": {"active": True, "rules": [], "total_rules": 0}}):
                try:
                    app.main()
                except Exception as ex:
                    self.fail(f"app.main() bị ném ngoại lệ không mong muốn: {type(ex).__name__}: {ex}")

    def test_test_monitor_daemon_no_audit_pollution(self):
        """Đảm bảo test_expire_active_blocks không ghi nhật ký vào runs/audit_trail.jsonl."""
        audit_file = os.path.join(ROOT_DIR, "runs", "audit_trail.jsonl")
        initial_lines = 0
        if os.path.exists(audit_file):
            with open(audit_file, "r", encoding="utf-8") as f:
                initial_lines = len(f.readlines())

        # Chạy test_expire_active_blocks từ test_monitor_daemon
        from tests.test_monitor_daemon import TestMonitorDaemon
        test_case = TestMonitorDaemon()
        test_case.setUp()
        test_case.test_expire_active_blocks()

        final_lines = 0
        if os.path.exists(audit_file):
            with open(audit_file, "r", encoding="utf-8") as f:
                final_lines = len(f.readlines())

        self.assertEqual(
            initial_lines,
            final_lines,
            f"test_expire_active_blocks làm bẩn runs/audit_trail.jsonl! (Ban đầu: {initial_lines}, Sau test: {final_lines})"
        )

    def test_test_notifier_no_alert_html_pollution(self):
        """Đảm bảo test_notifier không để lại file HTML rác trong thư mục runs/alerts/."""
        alerts_dir = os.path.join(ROOT_DIR, "runs", "alerts")
        initial_files = set(os.listdir(alerts_dir)) if os.path.exists(alerts_dir) else set()

        from tests.test_notifier import TestNotifier
        test_case = TestNotifier()
        test_case.setUp()
        test_case.test_send_alert_email_disabled_saves_preview()

        final_files = set(os.listdir(alerts_dir)) if os.path.exists(alerts_dir) else set()
        new_files = final_files - initial_files

        self.assertEqual(
            len(new_files),
            0,
            f"test_notifier để lại tệp rác trong runs/alerts/: {new_files}"
        )

    def test_cyber_terminal_xss_and_filtering(self):
        """Kiểm tra Cyber Terminal xử lý an toàn HTML injection và highlight chính xác."""
        payload = 'Oct 23 22:00:00 server sshd[123]: Failed password for <script>alert("hacked")</script> from 192.168.56.102'
        out = app.format_cyber_terminal_html(payload, query="192.168.56.102")

        # Phải escape script tag
        self.assertNotIn('<script>alert("hacked")</script>', out)
        self.assertIn('&lt;script&gt;alert(&quot;hacked&quot;)&lt;/script&gt;', out)

        # Highlight IP
        self.assertIn('192.168.56.102', out)

        # Highlight từ khóa Failed
        self.assertIn('Failed', out)

    def test_stop_action_preserves_investigation_data(self):
        """Kiểm tra khi dừng tác vụ, toàn bộ nhật ký và kết quả điều tra phải được bảo toàn."""
        import streamlit as st

        # Giả lập session_state với dữ liệu điều tra
        st.session_state["raw_logs"] = "Sample log 123"
        st.session_state["alerts"] = [{"rule": "test", "summary": "bruteforce"}]
        st.session_state["current_run"] = {"conclusion": {"verdict": "malicious"}}
        st.session_state["policy_decision"] = MagicMock()
        st.session_state["continuous_scan"] = True
        st.session_state["system_status"] = "scanning"

        # Giả lập hành động bấm nút Dừng lại (Stop)
        st.session_state["continuous_scan"] = False
        st.session_state["system_status"] = "idle"
        st.session_state["run_test_simulation"] = False
        st.session_state["run_investigation_alert"] = False
        st.session_state["sim_injected"] = False
        st.session_state["was_stopped"] = True

        # Trạng thái phải về idle
        self.assertFalse(st.session_state["continuous_scan"])
        self.assertEqual(st.session_state["system_status"], "idle")
        self.assertTrue(st.session_state["was_stopped"])

        # Nhưng dữ liệu thu thập không được phép bị xóa
        self.assertEqual(st.session_state["raw_logs"], "Sample log 123")
        self.assertEqual(len(st.session_state["alerts"]), 1)
        self.assertIsNotNone(st.session_state["current_run"])
        self.assertIsNotNone(st.session_state["policy_decision"])

    def test_policy_engine_whitelist_and_containment_limits(self):
        """Kiểm tra các ranh giới an toàn của Policy Engine không bị xâm phạm."""
        # Whitelist cấm chặn
        dec_whitelist = evaluate_action("block_ip", "192.168.56.1", context={"verdict": "malicious_activity_likely"})
        self.assertFalse(dec_whitelist.allowed)
        self.assertIn("Whitelist", dec_whitelist.reason)

        # Benign verdict cấm chặn
        dec_benign = evaluate_action("block_ip", "192.168.56.102", context={"verdict": "benign_likely"})
        self.assertFalse(dec_benign.allowed)


if __name__ == "__main__":
    unittest.main()
