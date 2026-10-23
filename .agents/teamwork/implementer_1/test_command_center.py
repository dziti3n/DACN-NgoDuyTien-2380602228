import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import (
    get_severity_badge,
    get_verdict_badge,
    format_cyber_terminal_html,
    fetch_live_logs,
)
from policy_engine import evaluate_action, load_protected_ips
from notifier import build_alert_html, get_email_config

class TestCommandCenter(unittest.TestCase):
    def test_badges(self):
        self.assertIn("CRITICAL", get_severity_badge("critical"))
        self.assertIn("HIGH", get_severity_badge("high"))
        self.assertIn("MEDIUM", get_severity_badge("medium"))
        self.assertIn("LOW", get_severity_badge("low"))
        self.assertIn("INFO", get_severity_badge("info"))

        self.assertIn("NGUY HIỂM", get_verdict_badge("malicious_activity_likely"))
        self.assertIn("KHẢ NGHI", get_verdict_badge("suspicious_needs_more_data"))
        self.assertIn("BÌNH THƯỜNG", get_verdict_badge("benign_likely"))
        self.assertIn("CHƯA ĐỦ DỮ LIỆU", get_verdict_badge("insufficient_data"))

    def test_cyber_terminal_rendering(self):
        sample_raw = (
            "2026-10-23T21:00:00 dacnsoc sshd[123]: Failed password for root from 192.168.56.102 port 22\n"
            "2026-10-23T21:00:02 dacnsoc sshd[124]: Accepted password for agent_soc from 192.168.56.1 port 22\n"
        )
        html_out = format_cyber_terminal_html(sample_raw, query="", max_lines=10)
        self.assertIn("192.168.56.102", html_out)
        self.assertIn("Failed", html_out)
        self.assertIn("Accepted", html_out)
        self.assertIn("#f87171", html_out)  # failure red highlight
        self.assertTrue("#4ade80" in html_out or "#34d399" in html_out)  # success green highlight

        # Test filter
        filtered_out = format_cyber_terminal_html(sample_raw, query="192.168.56.102", max_lines=10)
        self.assertIn("192.168.56.102", filtered_out)
        self.assertNotIn("agent_soc", filtered_out)

    def test_policy_engine_simulation_ip(self):
        prot_ips = load_protected_ips()
        self.assertIn("192.168.56.1", prot_ips)
        self.assertNotIn("192.168.56.102", prot_ips)

        # 192.168.56.102 should be allowed for blocking under bruteforce context
        dec = evaluate_action(
            action="block_ip",
            target="192.168.56.102",
            context={
                "alert": {"src_ip": "192.168.56.102", "rule": "ssh_bruteforce"},
                "evidence": ["12 failed attempts"],
                "verdict": "malicious_activity_likely",
                "confidence": "high",
                "severity": "critical",
            }
        )
        self.assertTrue(dec.allowed)

        # Host 192.168.56.1 must be denied
        dec_host = evaluate_action(
            action="block_ip",
            target="192.168.56.1",
            context={
                "alert": {"src_ip": "192.168.56.1"},
                "evidence": ["test"],
                "verdict": "malicious_activity_likely",
            }
        )
        self.assertFalse(dec_host.allowed)

    def test_alert_html_generation(self):
        sample_alert = {
            "rule": "ssh_bruteforce",
            "severity_hint": "critical",
            "summary": "Brute force test",
            "src_ip": "192.168.56.102",
        }
        html_content = build_alert_html(sample_alert, {}, {"action": "block_ip", "status": "blocked"})
        self.assertIn("192.168.56.102", html_content)
        self.assertIn("SSH_BRUTEFORCE", html_content)

if __name__ == "__main__":
    unittest.main()
