# ==============================================================================
# tests/test_wazuh_integration.py - Integration Test cho Wazuh Webhook Server
# Kiểm tra: Xác thực Token, Validate Schema, Phản hồi tức thời HTTP 200 và FIFO Queue
# ==============================================================================

import os
import sys
import json
import time
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wazuh_listener import WazuhWebhookServer, WAZUH_ALERTS_FILE, DEFAULT_AUTH_TOKEN
from scripts.simulate_wazuh_alert import send_simulated_alert


class TestWazuhIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 5056
        cls.server = WazuhWebhookServer(host="127.0.0.1", port=cls.port, auto_block=True, test_mode=True)
        cls.server.start(blocking=False)
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_health_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/api/v1/health"
        with urllib.request.urlopen(url, timeout=3) as resp:
            self.assertEqual(resp.getcode(), 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data.get("status"), "healthy")
            self.assertIn("mode", data)
            self.assertIn("queue_size", data)

    def test_unauthorized_request_rejected(self):
        """Request không mang Header X-SOC-Token phải bị từ chối 401."""
        url = f"http://127.0.0.1:{self.port}/api/v1/wazuh-alert"
        payload = {"rule": {"id": "5712", "level": 10}}
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}  # Không có token
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 401)

    def test_invalid_schema_rejected(self):
        """Payload sai cấu trúc (level = 99) phải bị trả về HTTP 422."""
        url = f"http://127.0.0.1:{self.port}/api/v1/wazuh-alert"
        payload = {"rule": {"id": "5712", "level": 99}}
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-SOC-Token": DEFAULT_AUTH_TOKEN
            }
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 422)

    @patch("wazuh_listener.investigate")
    @patch("wazuh_listener.send_alert_email")
    def test_authorized_and_queued_alert(self, mock_email, mock_investigate):
        """Request hợp lệ có Token phải trả về 200 tức thời và được đưa vào hàng đợi."""
        mock_investigate.return_value = {
            "model": "qwen3:4b",
            "conclusion": {
                "verdict": "malicious_activity_likely",
                "severity": "high",
                "confidence": "high",
                "summary": "Phát hiện dò mật khẩu SSH từ 192.168.56.102",
                "evidence": ["Wazuh rule 5712"],
                "recommended_actions": ["Chặn IP 192.168.56.102"]
            }
        }
        mock_email.return_value = {"status": "skipped", "preview_path": "runs/alerts/test.html"}

        t0 = time.time()
        res = send_simulated_alert(
            alert_type="bruteforce",
            src_ip="192.168.56.102",
            target_user="root",
            host="127.0.0.1",
            port=self.port,
            auth_token=DEFAULT_AUTH_TOKEN
        )
        elapsed_http = time.time() - t0

        # Phản hồi HTTP 200 cực nhanh (<0.1s) do xử lý qua hàng đợi
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["code"], 200)
        self.assertLess(elapsed_http, 0.2)
        self.assertEqual(res["response"]["status"], "accepted")
        self.assertIn("queue_position", res["response"])

        # Đợi worker thread hoàn tất
        time.sleep(0.5)
        self.assertTrue(WAZUH_ALERTS_FILE.exists())


if __name__ == "__main__":
    unittest.main()
