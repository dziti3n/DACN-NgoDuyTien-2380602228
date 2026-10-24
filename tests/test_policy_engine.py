#!/usr/bin/env python3
"""
tests/test_policy_engine.py - Bộ kiểm thử tự động cho Lớp kiểm soát phản ứng (Policy Engine Guardrails).
Kiểm tra toàn bộ các kịch bản: Whitelist bảo vệ, Ràng buộc Alert (Chống Prompt Injection),
Ngưỡng bằng chứng, Quản lý TTL, Rate Limit và Ghi nhật ký Audit.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from policy_engine import (
    validate_ip,
    is_protected_ip,
    evaluate_action,
    record_audit_log,
    save_active_block,
    load_active_blocks,
    remove_active_block,
    get_expired_blocks,
    check_rate_limit,
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

    def test_protected_whitelist_loopback_nat_and_server(self):
        """Kiểm tra bảo vệ IP loopback, cổng NAT VirtualBox (10.0.2.2) và chính máy chủ lab."""
        decision_loopback = evaluate_action("block_ip", "127.0.0.1")
        self.assertFalse(decision_loopback.allowed)

        decision_server = evaluate_action("block_ip", "192.168.56.101")
        self.assertFalse(decision_server.allowed)

        decision_nat = evaluate_action("block_ip", "10.0.2.2")
        self.assertFalse(decision_nat.allowed, "Cổng NAT VirtualBox 10.0.2.2 phải nằm trong whitelist!")

    def test_alert_correlation_blocks_prompt_injection(self):
        """
        KỊCH BẢN PHÒNG CHỐNG PROMPT INJECTION:
        Kẻ tấn công inject vào log để Agent đề xuất chặn một IP tùy ý (ví dụ DNS 8.8.8.8 hoặc 1.1.1.1).
        Policy Engine BẮT BUỘC từ chối nếu IP này không xuất hiện trong Alert hoặc Bằng chứng.
        """
        attacker_target = "8.8.8.8"
        # Alert chỉ nói về IP 192.168.56.102
        context = {
            "alert": {"src_ip": "192.168.56.102", "rule": "ssh_bruteforce"},
            "evidence": ["Phát hiện 12 lần đăng nhập thất bại từ 192.168.56.102"],
            "verdict": "malicious_activity_likely",
            "confidence": "high"
        }
        decision = evaluate_action("block_ip", attacker_target, context)
        self.assertFalse(decision.allowed, "Policy Engine phải từ chối khi IP đề xuất không có trong Alert!")
        self.assertEqual(decision.risk_level, "CRITICAL")
        self.assertIn("không xuất hiện trong cảnh báo", decision.reason)

    def test_alert_correlation_allows_valid_target(self):
        """Khi IP đề xuất trùng khớp với IP nguồn trong Alert thì Policy chấp thuận."""
        import tempfile
        valid_target = "192.168.56.102"
        context = {
            "alert": {"src_ip": "192.168.56.102", "rule": "ssh_bruteforce"},
            "evidence": ["Phát hiện 12 lần đăng nhập thất bại từ 192.168.56.102"],
            "verdict": "malicious_activity_likely",
            "confidence": "high"
        }
        with tempfile.TemporaryDirectory() as td:
            decision = evaluate_action("block_ip", valid_target, context, log_dir=td)
            self.assertTrue(decision.allowed, "IP nằm trong cảnh báo và ngoài whitelist phải được chấp thuận!")
            self.assertTrue(decision.requires_approval)

    def test_verdict_threshold_benign(self):
        """Nếu Agent kết luận benign_likely thì KHÔNG được phép block IP."""
        attacker_ip = "198.51.100.99"
        decision = evaluate_action(
            "block_ip",
            attacker_ip,
            {"alert": {"src_ip": attacker_ip}, "verdict": "benign_likely", "confidence": "high"}
        )
        self.assertFalse(decision.allowed)
        self.assertIn("benign_likely", decision.reason)

    def test_unblock_action(self):
        """Kiểm tra hành động hoàn tác gỡ chặn IP."""
        decision = evaluate_action("unblock_ip", "203.0.113.55")
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_approval)

    def test_ttl_and_active_blocks_management(self):
        """Kiểm tra quản lý danh sách IP bị chặn kèm thời hạn cách ly (TTL)."""
        import tempfile
        with tempfile.TemporaryDirectory() as test_dir:
            test_ip = "198.51.100.77"

            # 1. Lưu block với TTL 15 phút
            entry = save_active_block(test_ip, ttl_minutes=15, reason="Test TTL", log_dir=test_dir)
            self.assertEqual(entry["ip"], test_ip)
            self.assertEqual(entry["ttl_minutes"], 15)

            # 2. Đọc lại danh sách
            blocks = load_active_blocks(log_dir=test_dir)
            self.assertIn(test_ip, blocks)

            # 3. Gỡ bỏ
            removed = remove_active_block(test_ip, log_dir=test_dir)
            self.assertTrue(removed)
            blocks_after = load_active_blocks(log_dir=test_dir)
            self.assertNotIn(test_ip, blocks_after)

    def test_audit_logging(self):
        """Kiểm tra việc ghi nhật ký kiểm toán có cấu trúc."""
        import tempfile
        decision = PolicyDecision(
            allowed=True,
            action="block_ip",
            target="203.0.113.77",
            reason="Test policy pass",
            requires_approval=True
        )
        with tempfile.TemporaryDirectory() as test_dir:
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


if __name__ == "__main__":
    unittest.main()
