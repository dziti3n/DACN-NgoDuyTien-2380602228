# ==============================================================================
# tests/test_wazuh_listener.py - Unit Test cho Wazuh Webhook Receiver & Parser
# ==============================================================================

import os
import sys
import json
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wazuh_listener import (
    extract_ip_from_payload,
    map_wazuh_level_to_severity,
    normalize_wazuh_alert,
    validate_wazuh_payload_schema,
    is_allowed_client_ip,
    fast_path_triage,
    WazuhWebhookManager,
)


class TestWazuhListener(unittest.TestCase):

    def test_extract_ip_from_nested_data(self):
        payload = {
            "data": {"srcip": "192.168.56.200", "dstuser": "root"},
            "rule": {"id": "5712", "level": 10}
        }
        ip = extract_ip_from_payload(payload)
        self.assertEqual(ip, "192.168.56.200")

    def test_extract_ip_from_full_log(self):
        payload = {
            "full_log": "Oct 24 10:00:00 lab sshd[123]: Failed password for invalid user admin from 10.0.0.55 port 2222 ssh2",
            "rule": {"id": "5710", "level": 5}
        }
        ip = extract_ip_from_payload(payload)
        self.assertEqual(ip, "10.0.0.55")

    def test_extract_ip_from_summary(self):
        payload = {
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force from 172.16.0.99"}
        }
        ip = extract_ip_from_payload(payload)
        self.assertEqual(ip, "172.16.0.99")

    def test_map_wazuh_level(self):
        self.assertEqual(map_wazuh_level_to_severity(14), "critical")
        self.assertEqual(map_wazuh_level_to_severity(10), "high")
        self.assertEqual(map_wazuh_level_to_severity(6), "medium")
        self.assertEqual(map_wazuh_level_to_severity(4), "low")
        self.assertEqual(map_wazuh_level_to_severity(2), "info")

    def test_normalize_wazuh_alert(self):
        raw = {
            "timestamp": "2026-10-24T15:30:00.000+0000",
            "rule": {
                "id": "5712",
                "level": 10,
                "description": "sshd: brute force attack",
                "mitre": {
                    "id": ["T1110"],
                    "tactic": ["Credential Access"],
                    "technique": ["Brute Force"]
                }
            },
            "agent": {
                "id": "001",
                "name": "ubuntu-lab",
                "ip": "192.168.56.101"
            },
            "data": {
                "srcip": "192.168.56.105",
                "dstuser": "root"
            },
            "full_log": "Oct 24 15:30:00 ubuntu-lab sshd[1234]: Failed password for root from 192.168.56.105 port 43210 ssh2"
        }
        norm = normalize_wazuh_alert(raw)
        self.assertEqual(norm["src_ip"], "192.168.56.105")
        self.assertEqual(norm["severity_hint"], "high")
        self.assertEqual(norm["wazuh"]["rule_id"], "5712")
        self.assertEqual(norm["wazuh"]["agent_name"], "ubuntu-lab")
        self.assertIn("T1110", norm["wazuh"]["mitre_id"])
        self.assertIn("192.168.56.105", norm["summary"])
        self.assertIn("<untrusted_tool_output>", norm["wazuh"]["sandboxed_log"])

    def test_schema_validation_valid(self):
        payload = {
            "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
            "data": {"srcip": "192.168.56.102"}
        }
        valid, msg = validate_wazuh_payload_schema(payload)
        self.assertTrue(valid)
        self.assertEqual(msg, "Hợp lệ")

    def test_schema_validation_invalid(self):
        # 1. Thiếu rule
        valid1, _ = validate_wazuh_payload_schema({})
        self.assertFalse(valid1)

        # 2. Level ngoài dải chuẩn (0-16)
        valid2, _ = validate_wazuh_payload_schema({"rule": {"id": "5712", "level": 99}})
        self.assertFalse(valid2)

        # 3. IP sai cú pháp
        valid3, _ = validate_wazuh_payload_schema({
            "rule": {"id": "5712", "level": 10},
            "data": {"srcip": "999.999.999.999"}
        })
        self.assertFalse(valid3)

    def test_allowed_client_ip(self):
        self.assertTrue(is_allowed_client_ip("127.0.0.1"))
        self.assertTrue(is_allowed_client_ip("192.168.56.101"))
        self.assertTrue(is_allowed_client_ip("192.168.56.200"))
        self.assertFalse(is_allowed_client_ip("8.8.8.8"))
        self.assertFalse(is_allowed_client_ip("10.0.0.1"))

    def test_cooldown_behavior(self):
        manager = WazuhWebhookManager(test_mode=True, cooldown_minutes=5)
        ip = "192.168.56.199"
        self.assertFalse(manager.is_in_cooldown(ip))
        manager.ip_cooldown[ip] = 10000000000
        self.assertTrue(manager.is_in_cooldown(ip))

    def test_fast_path_triage(self):
        # 1. Lệnh bảo trì sudo hợp lệ -> Fast-Path bắt ngay lập tức (<1ms)
        safe_alert = normalize_wazuh_alert({
            "rule": {"id": "5402", "level": 3, "description": "sudo: successful sudo to ROOT."},
            "data": {"srcip": "192.168.56.1", "dstuser": "agent_soc"},
            "full_log": "Oct 24 16:00:00 lab sudo[1]: agent_soc : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update"
        })
        fast_res = fast_path_triage(safe_alert)
        self.assertIsNotNone(fast_res)
        self.assertEqual(fast_res["verdict"], "benign_likely")

        # 2. Lệnh sudo nguy hiểm (su - hoặc /bin/bash) -> Không được fast-path, phải để LLM điều tra
        evil_alert = normalize_wazuh_alert({
            "rule": {"id": "5402", "level": 3, "description": "sudo: successful sudo to ROOT."},
            "data": {"srcip": "192.168.56.102", "dstuser": "evil"},
            "full_log": "Oct 24 16:00:00 lab sudo[1]: evil : TTY=pts/0 ; USER=root ; COMMAND=/bin/su - root"
        })
        self.assertIsNone(fast_path_triage(evil_alert))

        # 3. Sự kiện brute force 5712 -> Không được fast-path
        bf_alert = normalize_wazuh_alert({
            "rule": {"id": "5712", "level": 10, "description": "sshd: brute force."},
            "data": {"srcip": "198.51.100.15", "dstuser": "root"},
            "full_log": "Failed password for root from 198.51.100.15"
        })
        self.assertIsNone(fast_path_triage(bf_alert))


if __name__ == "__main__":
    unittest.main()
