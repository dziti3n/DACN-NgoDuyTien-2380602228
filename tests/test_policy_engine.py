#!/usr/bin/env python3
"""
tests/test_policy_engine.py - Bộ kiểm thử tự động cho Lớp kiểm soát phản ứng (Policy Engine Guardrails).
Kiểm tra toàn bộ các kịch bản: Whitelist bảo vệ, Chống Injection, Ngưỡng bằng chứng, và Ghi nhật ký Audit.
"""

import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from policy_engine import (
    validate_ip,
    is_protected_ip,
    evaluate_action,
    record_audit_log,
    PolicyDecision,
    DEFAULT_PROTECTED_IPS,
)


class TestPolicyEngine(unittest.TestCase):
    """Kiểm thử tính đúng đắn và độ an toàn của Policy Engine."""

    def test_validate_ip_valid(self):
        """Kiểm tra nhận diện địa chỉ IPv4 và IPv6 hợp lệ."""
        valid_ips = ["192.168.56.1", "10.0.0.5", "127.0.0.1", "2001:db8::1"]
        for ip in valid_ips:
            ok, msg = validate_ip(ip)
            self.assertTrue(ok, f"IP {ip} phải hợp lệ nhưng bị báo lỗi: {msg}")

    def test_validate_ip_injection_and_invalid(self):
        """Kiểm tra ngăn chặn command injection và IP sai cú pháp."""
        bad_ips = [
            "192.168.56.1; rm -rf /",
            "10.0.0.1 && cat /etc/passwd",
            "not-an-ip",
            "999.999.999.999",
            "192.168.1.1/24",
            "",
            None,
        ]
        for bad in bad_ips:
            ok, _ = validate_ip(bad)
            self.assertFalse(ok, f"Chuỗi nguy hiểm hoặc sai định dạng '{bad}' phải bị từ chối!")

    def test_protected_whitelist_host_windows(self):
        """
        KỊCH BẢN QUAN TRỌNG NHẤT:
        Ngăn chặn tuyệt đối việc chặn máy Host Windows (192.168.56.1).
        Nếu chặn IP này, kết nối SSH sẽ đứt và người dùng bị khóa ra khỏi lab.
        """
        is_prot, msg = is_protected_ip("192.168.56.1")
        self.assertTrue(is_prot, "IP 192.168.56.1 (Host Windows) BẮT BUỘC phải nằm trong Whitelist!")

        decision = evaluate_action("block_ip", "192.168.56.1", {"verdict": "malicious_activity_likely"})
        self.assertFalse(decision.allowed, "Policy Engine PHẢI từ chối hành động chặn IP Host Windows!")
        self.assertEqual(decision.risk_level, "CRITICAL")
        self.assertIn("TỪ CHỐI BẢO MẬT", decision.reason)

    def test_protected_whitelist_loopback_and_server(self):
        """Kiểm tra bảo vệ IP loopback và chính máy chủ lab."""
        decision_loopback = evaluate_action("block_ip", "127.0.0.1")
        self.assertFalse(decision_loopback.allowed)

        decision_server = evaluate_action("block_ip", "192.168.56.101")
        self.assertFalse(decision_server.allowed)

    def test_verdict_threshold_benign(self):
        """Nếu Agent kết luận benign_likely thì KHÔNG được phép block IP."""
        attacker_ip = "198.51.100.99"
        decision = evaluate_action(
            "block_ip",
            attacker_ip,
            {"verdict": "benign_likely", "confidence": "high"}
        )
        self.assertFalse(decision.allowed)
        self.assertIn("benign_likely", decision.reason)

    def test_valid_attacker_ip_allowed_with_hitl(self):
        """Khi phát hiện tấn công thật từ IP ngoài, Policy Engine cho phép nhưng yêu cầu HITL phê duyệt."""
        attacker_ip = "203.0.113.55"
        decision = evaluate_action(
            "block_ip",
            attacker_ip,
            {"verdict": "malicious_activity_likely", "confidence": "high"}
        )
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_approval, "Hành động chặn IP luôn phải yêu cầu người phê duyệt (HITL)!")
        self.assertEqual(decision.risk_level, "HIGH")

    def test_unblock_action(self):
        """Kiểm tra hành động hoàn tác gỡ chặn IP."""
        decision = evaluate_action("unblock_ip", "203.0.113.55")
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_approval)

    def test_unsupported_action(self):
        """Kiểm tra hành động lạ không được phép."""
        decision = evaluate_action("format_hard_drive", "sda1")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.risk_level, "CRITICAL")

    def test_audit_logging(self):
        """Kiểm tra việc ghi nhật ký kiểm toán không thể chối bỏ."""
        decision = PolicyDecision(
            allowed=True,
            action="block_ip",
            target="203.0.113.77",
            reason="Test policy pass",
            requires_approval=True
        )
        test_dir = os.path.join(ROOT_DIR, "runs")
        entry = record_audit_log(
            action="block_ip",
            target="203.0.113.77",
            operator="SOC Analyst (Test)",
            policy_decision=decision,
            execution_result={"status": "ok", "message": "Rule added"},
            verification_result={"verified": True, "rules_found": [{"rule_num": 1}]},
            log_dir=test_dir
        )
        self.assertEqual(entry["action"], "block_ip")
        self.assertEqual(entry["target"], "203.0.113.77")

        # Kiểm tra file audit có tồn tại
        log_file = os.path.join(test_dir, "action_audit.log")
        jsonl_file = os.path.join(test_dir, "audit_trail.jsonl")
        self.assertTrue(os.path.exists(log_file))
        self.assertTrue(os.path.exists(jsonl_file))


if __name__ == "__main__":
    unittest.main()

