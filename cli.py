#!/usr/bin/env python3
"""
cli.py - Giao diện dòng lệnh hợp nhất (Unified CLI) cho AI SOC Investigation Agent.
Hỗ trợ quét cảnh báo, kích hoạt điều tra tự động, chạy kiểm thử và khởi chạy Web Dashboard.
"""

import argparse
import json
import os
import subprocess
import sys

# Đảm bảo in UTF-8 không lỗi font tiếng Việt trên PowerShell Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from read_logs import run_fixed_command, HOST, USER
from log_parser import parse_log
from detection import detect_all, alert_to_dict
from agent import investigate


def fetch_alerts(lines=1000):
    """Đọc log qua SSH và thực thi các quy tắc phát hiện cảnh báo."""
    try:
        out, err = run_fixed_command(f"tail -n {lines} /var/log/auth.log")
        if not out.strip() and err:
            print(f"[-] Lỗi đọc log từ server lab ({HOST}): {err}")
            return []
        events = parse_log(out)
        alerts = [alert_to_dict(a) for a in detect_all(events, baseline_path="baseline.json")]
        return alerts
    except Exception as ex:
        print(f"[-] Lỗi kết nối SSH đến server lab ({HOST}): {ex}")
        print("    Vui lòng kiểm tra máy ảo lab đã bật và cấu hình SSH trong .env.")
        return None


def cmd_scan(args):
    """Lệnh quét và liệt kê toàn bộ các cảnh báo an ninh."""
    print(f"[*] Đang kết nối đến máy chủ {HOST} (quét {args.lines} dòng log auth.log)...")
    alerts = fetch_alerts(lines=args.lines)
    if alerts is None:
        sys.exit(1)

    print(f"\n[+] Kết quả: Phát hiện tổng cộng {len(alerts)} cảnh báo an ninh:\n")
    if not alerts:
        print("    ✅ Hệ thống an toàn! Không có cảnh báo bất thường.")
        return

    for i, a in enumerate(alerts):
        rule = a.get("rule", "Unknown")
        sev = a.get("severity_hint", "N/A").upper()
        summary = a.get("summary", "")
        print(f"  [{i}] ({rule} | Mức độ: {sev})")
        print(f"      Tóm tắt: {summary}")
        if args.verbose:
            print(f"      Chi tiết: {json.dumps(a, ensure_ascii=False, indent=8)}")
        print()

    print(f"💡 Gợi ý: Gõ 'python cli.py investigate <số_thứ_tự>' để Agent tự động điều tra.")


def cmd_investigate(args):
    """Lệnh kích hoạt Agent điều tra tự động một cảnh báo cụ thể."""
    print(f"[*] Đang thu thập cảnh báo từ máy chủ {HOST}...")
    alerts = fetch_alerts(lines=args.lines)
    if alerts is None:
        sys.exit(1)

    if not alerts:
        print("[-] Không có cảnh báo nào để điều tra.")
        return

    # Xác định chỉ số cảnh báo cần điều tra
    idx = args.index
    if idx is None:
        idx = len(alerts) - 1  # Mặc định lấy cảnh báo mới nhất
    elif idx < 0 or idx >= len(alerts):
        print(f"[-] Chỉ số cảnh báo #{idx} không hợp lệ! Danh sách hiện có từ 0 đến {len(alerts) - 1}.")
        sys.exit(1)

    alert = alerts[idx]
    rule = alert.get("rule", "Unknown")
    sev = alert.get("severity_hint", "N/A")
    print(f"\n" + "=" * 65)
    print(f"🚀 KÍCH HOẠT SOC AGENT ĐIỀU TRA CẢNH BÁO #{idx} [{rule}]")
    print(f"   Mức độ: {sev.upper()} | Tóm tắt: {alert.get('summary')}")
    print("=" * 65 + "\n")

    run = investigate(alert, verbose=not args.quiet)

    c = run.get("conclusion", {})
    print(f"\n" + "=" * 65)
    print(f"📋 BÁO CÁO KẾT LUẬN ĐIỀU TRA ({run.get('model')}, {run.get('elapsed_sec')}s, {run.get('tool_calls')} bước)")
    print("=" * 65)
    print(f"Verdict:     {c.get('verdict')} | Severity: {c.get('severity')} | Confidence: {c.get('confidence')}")
    print(f"\nTóm tắt vụ việc:\n{c.get('summary')}\n")
    
    print("Bằng chứng đã xác thực:")
    for ev in c.get("evidence", []):
        print(f"  - ✅ {ev}")
        
    if c.get("missing_data"):
        print("\nDữ liệu còn thiếu:")
        for md in c.get("missing_data", []):
            print(f"  - ❓ {md}")
            
    print("\nĐề xuất xử lý (Remediation Actions):")
    for act in c.get("recommended_actions", []):
        print(f"  - 👉 {act}")

    print(f"\n[+] Toàn bộ nhật ký phiên điều tra đã lưu tại: {run.get('saved_to')}")


def cmd_ui(args):
    """Khởi chạy Giao diện Web Dashboard (Streamlit)."""
    print("[*] Đang khởi chạy Giao diện Web Dashboard trên Streamlit...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])


def cmd_test(args):
    """Chạy toàn bộ các bộ kiểm thử trong thư mục tests/."""
    print("[*] Đang thực thi toàn bộ bài kiểm thử tự động trong tests/...\n")
    test_files = [
        "tests/test_llm.py",
        "tests/test_detection_rules.py",
        "tests/test_tools.py",
        "security_audit.py",
    ]
    for tf in test_files:
        if os.path.exists(tf):
            print(f"\n--- Đang chạy: {tf} ---")
            subprocess.run([sys.executable, tf])


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ AI SOC Investigation Agent - Công cụ dòng lệnh hợp nhất (Unified CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Lệnh chức năng")

    # Lệnh: scan
    p_scan = subparsers.add_parser("scan", help="Quét và hiển thị toàn bộ cảnh báo an ninh")
    p_scan.add_argument("-l", "--lines", type=int, default=1000, help="Số dòng log auth.log quét (mặc định: 1000)")
    p_scan.add_argument("-v", "--verbose", action="store_true", help="Hiển thị chi tiết JSON từng cảnh báo")
    p_scan.set_defaults(func=cmd_scan)

    # Lệnh: investigate
    p_inv = subparsers.add_parser("investigate", help="Kích hoạt Agent điều tra tự động một cảnh báo")
    p_inv.add_argument("index", type=int, nargs="?", default=None, help="Số thứ tự cảnh báo (mặc định: cảnh báo mới nhất)")
    p_inv.add_argument("-l", "--lines", type=int, default=1000, help="Số dòng log auth.log quét (mặc định: 1000)")
    p_inv.add_argument("-q", "--quiet", action="store_true", help="Ẩn các bước chạy chi tiết của tool")
    p_inv.set_defaults(func=cmd_investigate)

    # Lệnh: ui
    p_ui = subparsers.add_parser("ui", help="Mở giao diện Web Dashboard (Streamlit UI)")
    p_ui.set_defaults(func=cmd_ui)

    # Lệnh: test
    p_test = subparsers.add_parser("test", help="Chạy toàn bộ bộ kiểm thử trong tests/")
    p_test.set_defaults(func=cmd_test)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()

