# tests/test_ui_app.py - Kiểm thử toàn diện các hàm bổ trợ UI & Cyber Terminal của app.py
import html
import os
import sys
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import (
    get_severity_badge,
    get_verdict_badge,
    extract_ip_from_text,
    format_cyber_terminal_html,
)


class TestAppUI(unittest.TestCase):
    def test_severity_badges(self):
        critical_badge = get_severity_badge("critical")
        self.assertIn("CRITICAL", critical_badge)
        self.assertIn("rgba(239, 68, 68", critical_badge)

        high_badge = get_severity_badge("high")
        self.assertIn("HIGH", high_badge)

        low_badge = get_severity_badge("low")
        self.assertIn("LOW", low_badge)

        info_badge = get_severity_badge("unknown")
        self.assertIn("INFO", info_badge)

    def test_verdict_badges(self):
        v_mal = get_verdict_badge("malicious_activity_likely")
        self.assertIn("NGUY HIỂM", v_mal)

        v_susp = get_verdict_badge("suspicious_needs_more_data")
        self.assertIn("KHẢ NGHI", v_susp)

        v_ben = get_verdict_badge("benign_likely")
        self.assertIn("BÌNH THƯỜNG", v_ben)

        v_other = get_verdict_badge("insufficient_data")
        self.assertIn("CHƯA ĐỦ DỮ LIỆU", v_other)

    def test_extract_ip_from_text(self):
        self.assertEqual(extract_ip_from_text("Tấn công từ 192.168.56.102 qua port 22"), "192.168.56.102")
        self.assertIsNone(extract_ip_from_text("Không có IP ở đây"))
        self.assertIsNone(extract_ip_from_text(""))

    def test_format_cyber_terminal_empty(self):
        res = format_cyber_terminal_html("")
        self.assertIn("Chưa có dữ liệu nhật ký", res)

    def test_format_cyber_terminal_reversal_newest_on_top(self):
        """
        Kiểm tra R2: Dòng log mới nhất (cuối cùng của file log)
        phải được đảo ngược để xuất hiện ở DÒNG ĐẦU TIÊN (LATEST) của Terminal.
        """
        sample_logs = (
            "2026-10-23T10:00:00 srv sshd[100]: First event\n"
            "2026-10-23T10:01:00 srv sshd[101]: Middle event\n"
            "2026-10-23T10:02:00 srv sshd[102]: Latest newest event\n"
        )
        html_out = format_cyber_terminal_html(sample_logs, max_lines=10)

        # Kiểm tra thứ tự xuất hiện trong HTML: "Latest newest event" phải xuất hiện trước "First event"
        pos_latest = html_out.find("Latest newest event")
        pos_first = html_out.find("First event")

        self.assertNotEqual(pos_latest, -1)
        self.assertNotEqual(pos_first, -1)
        self.assertLess(pos_latest, pos_first, "Dòng mới nhất phải xuất hiện trước (trên cùng)")

        # Kiểm tra dòng đầu tiên (001) có nhãn LATEST và viền phát sáng
        self.assertIn("LATEST", html_out)
        self.assertIn("001", html_out)
        self.assertIn("border-left: 3px solid #38bdf8", html_out)

    def test_format_cyber_terminal_xss_protection(self):
        """Kiểm tra XSS guardrails: các thẻ HTML độc hại trong log phải được escape an toàn."""
        malicious_log = '2026-10-23T10:00:00 srv sshd[100]: Failed password for <script>alert("XSS")</script> from 192.168.56.102'
        html_out = format_cyber_terminal_html(malicious_log)

        self.assertNotIn('<script>', html_out)
        self.assertIn('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;', html_out)

    def test_format_cyber_terminal_search_filter(self):
        sample_logs = (
            "2026-10-23T10:00:00 srv sshd[100]: Failed password for root from 192.168.56.102\n"
            "2026-10-23T10:01:00 srv sshd[101]: Accepted publickey for agent_soc from 192.168.56.1\n"
        )
        # Lọc root
        res_filter = format_cyber_terminal_html(sample_logs, query="root")
        self.assertIn("root", res_filter)
        self.assertIn("<mark", res_filter)
        self.assertNotIn("agent_soc", res_filter)

        # Lọc không khớp
        res_nomatch = format_cyber_terminal_html(sample_logs, query="nonexistent_user")
        self.assertIn("Không tìm thấy dòng log nào", res_nomatch)

    def test_format_cyber_terminal_syntax_highlights(self):
        sample = (
            "2026-10-23T10:00:00 srv sshd[1234]: Failed password from 192.168.56.102\n"
            "2026-10-23T10:01:00 srv sshd[1235]: Accepted publickey for user\n"
        )
        html_out = format_cyber_terminal_html(sample)
        # IP Electric blue highlight
        self.assertIn('color: #38bdf8;', html_out)
        # Failed Crimson highlight
        self.assertIn('color: #f87171;', html_out)
        # Accepted Emerald highlight
        self.assertIn('color: #34d399;', html_out)
        # Daemon Violet highlight
        self.assertIn('color: #c084fc;', html_out)

    def test_r1_css_rules_and_heights_in_app(self):
        """Kiểm tra R1: Các quy tắc CSS định tuyến 100vh và scoped selector trong app.py."""
        app_path = os.path.join(ROOT_DIR, "app.py")
        with open(app_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Kiểm tra 100vh lock
        self.assertIn("max-height: 100vh !important;", content)
        self.assertIn("overflow: hidden !important;", content)

        # Kiểm tra scoped selector cho columns hỗ trợ stColumn & column
        self.assertIn('[data-testid*="olumn"]', content)
        self.assertIn('div[data-baseweb="tab-panel"]', content)
        self.assertIn('max-height: calc(100vh - 170px) !important;', content)

        # Kiểm tra kích thước khối Cyber Terminal (~460px tổng thể, 400px inner)
        self.assertIn('height: 400px; max-height: 400px;', content)

    def test_simulated_lines_deduplication(self):
        """Kiểm tra logic deduplicate sim_lines khi bảo tồn nhật ký tấn công giả lập."""
        raw_logs = (
            "2026-10-23 srv sshd: normal line 1\n"
            "2026-10-23 srv sshd: Failed password from 192.168.56.102\n"
            "2026-10-23 srv sshd: Failed password from 192.168.56.102\n"
        )
        sim_lines = list(dict.fromkeys(l for l in raw_logs.splitlines() if "192.168.56.102" in l))
        self.assertEqual(len(sim_lines), 1, "Các dòng log trùng lặp phải được loại bỏ an toàn")

    def test_format_cyber_terminal_zero_or_negative_max_lines(self):
        """Kiểm tra trường hợp biên max_lines <= 0 không bị lỗi slice [-0:] trả về full log."""
        sample = "Line 1\nLine 2\nLine 3\n"
        out_zero = format_cyber_terminal_html(sample, max_lines=0)
        self.assertEqual(out_zero, "", "max_lines=0 phải trả về chuỗi rỗng")
        out_neg = format_cyber_terminal_html(sample, max_lines=-5)
        self.assertEqual(out_neg, "", "max_lines < 0 phải trả về chuỗi rỗng")


if __name__ == "__main__":
    unittest.main()
