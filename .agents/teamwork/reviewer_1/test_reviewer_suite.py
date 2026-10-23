import html
import os
import sys
import tempfile
import unittest

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
    load_protected_ips,
    validate_ip,
    record_audit_log,
    save_active_block,
    load_active_blocks,
    remove_active_block,
    PolicyDecision,
)
from notifier import build_alert_html, get_email_config

class AdversarialReviewerTestSuite(unittest.TestCase):
    def test_badges_exhaustive(self):
        for sev in ["critical", "high", "medium", "low", "info", "UNKNOWN"]:
            badge = get_severity_badge(sev)
            self.assertTrue(badge.startswith("<span"))
            self.assertIn("border-radius", badge)

        for verdict in [
            "malicious_activity_likely",
            "suspicious_needs_more_data",
            "benign_likely",
            "insufficient_data",
            "unknown_verdict",
        ]:
            v_badge = get_verdict_badge(verdict)
            self.assertIsInstance(v_badge, str)
            self.assertGreater(len(v_badge), 5)

    def test_extract_ip(self):
        self.assertEqual(extract_ip_from_text("Connection from 192.168.56.102 on port 22"), "192.168.56.102")
        self.assertEqual(extract_ip_from_text("No IP here"), None)
        self.assertEqual(extract_ip_from_text(""), None)

    def test_cyber_terminal_formatting_and_injection_safety(self):
        # Empty input
        out_empty = format_cyber_terminal_html("")
        self.assertIn("Chưa có dữ liệu nhật ký", out_empty)

        # Normal line
        raw = "2026-10-23T21:00:00 dacnsoc sshd[123]: Failed password for root from 192.168.56.102 port 22\n"
        out_normal = format_cyber_terminal_html(raw)
        self.assertIn("192.168.56.102", out_normal)
        self.assertIn("sshd[123]", out_normal)
        self.assertIn("Failed", out_normal)

        # HTML injection query
        evil_query = "<script>alert(1)</script>"
        raw_evil = f"2026-10-23T21:00:00 dacnsoc sshd[123]: {evil_query} Failed from 192.168.56.102\n"
        out_evil = format_cyber_terminal_html(raw_evil, query=evil_query)
        self.assertNotIn("<script>", out_evil)
        self.assertIn("&lt;script&gt;", out_evil)

        # Keyword collision with CSS attributes (color, span, style)
        raw_keyword = "2026-10-23T21:00:00 dacnsoc sshd[123]: Failed login with color span style from 192.168.56.102\n"
        out_kw = format_cyber_terminal_html(raw_keyword, query="color")
        self.assertIn("<mark", out_kw)
        self.assertNotIn('style="<mark', out_kw)
        self.assertIn("color: #f87171", out_kw)

    def test_policy_engine_guardrails_isolated(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Host Windows is forbidden
            dec_host = evaluate_action("block_ip", "192.168.56.1", log_dir=tmp_dir)
            self.assertFalse(dec_host.allowed)
            self.assertIn("BẢO VỆ", dec_host.reason)

            # 2. Benign verdict is rejected with benign reason
            dec_benign = evaluate_action(
                "block_ip",
                "192.168.56.102",
                context={
                    "alert": {"src_ip": "192.168.56.102"},
                    "verdict": "benign_likely",
                    "confidence": "high",
                },
                log_dir=tmp_dir
            )
            self.assertFalse(dec_benign.allowed)
            self.assertIn("benign_likely", dec_benign.reason)

            # 3. Legitimate block is allowed
            dec_valid = evaluate_action(
                "block_ip",
                "192.168.56.102",
                context={
                    "alert": {"src_ip": "192.168.56.102"},
                    "evidence": ["12 failed attempts from 192.168.56.102"],
                    "verdict": "malicious_activity_likely",
                    "confidence": "high",
                },
                log_dir=tmp_dir
            )
            self.assertTrue(dec_valid.allowed)

    def test_alert_email_html_generation(self):
        alert = {"rule": "ssh_bruteforce", "src_ip": "192.168.56.102", "summary": "SSH Attack"}
        run_res = {
            "model": "qwen3:4b",
            "conclusion": {
                "verdict": "malicious_activity_likely",
                "severity": "critical",
                "summary": "SSH Bruteforce confirmed",
                "evidence": ["Multiple auth failures"],
            }
        }
        resp_info = {"action": "block_ip", "status": "blocked", "target_ip": "192.168.56.102"}
        html_out = build_alert_html(alert, run_res, resp_info)
        self.assertIn("192.168.56.102", html_out)
        self.assertIn("SSH_BRUTEFORCE", html_out)

if __name__ == "__main__":
    unittest.main()
