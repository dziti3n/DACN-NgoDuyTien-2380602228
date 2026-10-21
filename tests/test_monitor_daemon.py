import json
import os
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from monitor_daemon import SOCMonitorDaemon, extract_ip_from_alert

class TestMonitorDaemon(unittest.TestCase):
    def setUp(self):
        self.daemon = SOCMonitorDaemon(
            poll_interval=5,
            auto_block=True,
            cooldown_minutes=15,
            test_mode=True
        )

    def test_extract_ip_from_alert(self):
        alert1 = {"src_ip": "192.168.56.102"}
        self.assertEqual(extract_ip_from_alert(alert1), "192.168.56.102")

        alert2 = {"details": {"src_ip": "10.0.0.99"}}
        self.assertEqual(extract_ip_from_alert(alert2), "10.0.0.99")

        alert3 = {"summary": "Phát hiện quét cổng từ 172.16.0.5 đến máy chủ"}
        self.assertEqual(extract_ip_from_alert(alert3), "172.16.0.5")

    def test_cooldown_logic(self):
        ip = "192.168.56.102"
        self.assertFalse(self.daemon.is_in_cooldown(ip))

        # Đánh dấu vừa xử lý
        self.daemon.ip_cooldown[ip] = time.time()
        self.assertTrue(self.daemon.is_in_cooldown(ip))

        # Giả lập thời gian đã trôi qua 16 phút (quá 15 phút cooldown)
        self.daemon.ip_cooldown[ip] = time.time() - (16 * 60)
        self.assertFalse(self.daemon.is_in_cooldown(ip))

    @patch("monitor_daemon.send_alert_email")
    @patch("monitor_daemon.investigate")
    def test_handle_alert_autonomous_block(self, mock_investigate, mock_send_email):
        mock_investigate.return_value = {
            "model": "qwen3:4b",
            "conclusion": {
                "verdict": "malicious_activity_likely",
                "severity": "critical",
                "confidence": "high",
                "summary": "Tấn công brute force từ 192.168.56.102",
                "evidence": ["Nhiều lần đăng nhập sai"],
                "recommended_actions": ["Chặn IP 192.168.56.102"]
            }
        }
        mock_send_email.return_value = {"status": "skipped", "preview_path": "runs/alerts/test.html"}

        alert = {
            "rule": "ssh_bruteforce",
            "severity_hint": "critical",
            "summary": "Phát hiện brute force từ 192.168.56.102",
            "src_ip": "192.168.56.102",
            "details": {"src_ip": "192.168.56.102"}
        }

        self.daemon.handle_alert(alert)

        self.assertEqual(self.daemon.total_alerts_handled, 1)
        self.assertEqual(self.daemon.total_blocks_executed, 1)
        self.assertTrue(self.daemon.is_in_cooldown("192.168.56.102"))
        mock_send_email.assert_called_once()

    @patch("monitor_daemon.unblock_ip")
    @patch("monitor_daemon.load_active_blocks")
    @patch("monitor_daemon.remove_active_block")
    def test_expire_active_blocks(self, mock_remove, mock_load, mock_unblock):
        expired_time = (datetime.now() - timedelta(minutes=1)).isoformat()
        mock_load.return_value = {
            "192.168.56.102": {
                "blocked_at": (datetime.now() - timedelta(minutes=16)).isoformat(),
                "expires_at": expired_time,
                "ttl_minutes": 15
            }
        }
        self.daemon.check_and_expire_active_blocks()
        mock_remove.assert_called_with("192.168.56.102")

if __name__ == "__main__":
    unittest.main()

