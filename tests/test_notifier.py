import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from notifier import build_alert_html, send_alert_email, get_email_config

class TestNotifier(unittest.TestCase):
    def setUp(self):
        self.sample_alert = {
            "rule": "ssh_bruteforce",
            "severity_hint": "critical",
            "summary": "Phát hiện brute force từ 192.168.56.102",
            "src_ip": "192.168.56.102",
            "details": {"src_ip": "192.168.56.102", "total_failures": 10}
        }
        self.sample_run = {
            "model": "qwen3:4b",
            "conclusion": {
                "verdict": "malicious_activity_likely",
                "severity": "critical",
                "confidence": "high",
                "summary": "Tấn công SSH brute force có dấu hiệu xâm nhập.",
                "evidence": ["10 lần đăng nhập sai", "IP lạ từ mạng ngoài"],
                "recommended_actions": ["Chặn IP 192.168.56.102 qua UFW"]
            }
        }

    def test_build_alert_html_blocked(self):
        resp_info = {
            "action": "block_ip",
            "status": "blocked",
            "target_ip": "192.168.56.102",
            "ttl_minutes": 15
        }
        html = build_alert_html(self.sample_alert, self.sample_run, resp_info)
        self.assertIn("192.168.56.102", html)
        self.assertIn("CRITICAL", html)
        self.assertIn("ĐÃ CÁCH LY IP THÀNH CÔNG", html)
        self.assertIn("malicious_activity_likely", html)
        self.assertIn("qwen3:4b", html)

    def test_build_alert_html_rejected(self):
        resp_info = {
            "action": "block_ip",
            "status": "rejected",
            "target_ip": "192.168.56.1",
            "reason": "IP nằm trong danh sách Whitelist quản trị"
        }
        html = build_alert_html(self.sample_alert, self.sample_run, resp_info)
        self.assertIn("HÀNH ĐỘNG BỊ TỪ CHỐI BỞI POLICY ENGINE", html)
        self.assertIn("IP nằm trong danh sách Whitelist", html)

    def test_send_alert_email_disabled_saves_preview(self):
        # Khi chưa bật ALERT_EMAIL_ENABLED, hàm phải lưu preview HTML và trả về status 'skipped'
        with patch.dict(os.environ, {"ALERT_EMAIL_ENABLED": "false"}):
            res = send_alert_email(
                subject="Test Subject",
                html_content="<h1>Test Alert</h1>",
                save_preview=True
            )
            self.assertEqual(res["status"], "skipped")
            preview_p = Path(res["preview_path"])
            self.assertTrue(preview_p.exists())
            # Dọn dẹp file preview sau khi kiểm tra để không làm ô nhiễm runs/alerts/
            try:
                preview_p.unlink(missing_ok=True)
            except Exception:
                pass

if __name__ == "__main__":
    unittest.main()

