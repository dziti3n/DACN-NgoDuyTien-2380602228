#!/usr/bin/env python3
"""
cli.py - Giao diện dòng lệnh hợp nhất (Unified CLI) cho AI SOC Investigation & Defense Agent.
Hỗ trợ quét cảnh báo, kích hoạt điều tra tự động, thực thi phản ứng có kiểm soát (Policy Engine & UFW),
chạy kiểm thử và khởi chạy Web Dashboard.
"""

import argparse
import json
import os
import re
import subprocess
import sys

# Đảm bảo in UTF-8 không lỗi font tiếng Việt trên PowerShell Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from read_logs import run_fixed_command, HOST, USER
from log_parser import parse_log
from detection import detect_all, alert_to_dict
from agent import investigate
from tools import (
    TOOLS,
    RESPONSE_TOOLS,
    block_ip,
    unblock_ip,
    verify_response,
    get_firewall_status,
)
from policy_engine import (
    evaluate_action,
    record_audit_log,
    is_protected_ip,
    validate_ip,
    save_active_block,
    remove_active_block,
    load_active_blocks,
    DEFAULT_BLOCK_TTL_MINUTES,
)
from notifier import send_test_email, get_email_config
from monitor_daemon import SOCMonitorDaemon
from wazuh_listener import start_wazuh_listener


def extract_ip(text):
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return m.group(0) if m else None


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
    recs = c.get("recommended_actions", [])
    for act in recs:
        print(f"  - 👉 {act}")

    print(f"\n[+] Toàn bộ nhật ký phiên điều tra đã lưu tại: {run.get('saved_to')}")

    # ==========================================================
    # LỚP PHẢN ỨNG CÓ KIỂM SOÁT (POLICY ENGINE & HITL PROMPT)
    # ==========================================================
    for act in recs:
        target_ip = extract_ip(act) or alert.get("src_ip")
        if any(k in act.lower() for k in ["chặn", "block", "ufw", "cấm"]) and target_ip:
            print("\n" + "-" * 65)
            print(f"🛡️  THẨM ĐỊNH AN TOÀN TỪ POLICY ENGINE CHO HÀNH ĐỘNG CHẶN IP '{target_ip}':")
            decision = evaluate_action(
                action="block_ip",
                target=target_ip,
                context={
                    "alert": alert,
                    "evidence": c.get("evidence", []),
                    "verdict": c.get("verdict"),
                    "confidence": c.get("confidence"),
                    "severity": c.get("severity"),
                }
            )
            if not decision.allowed:
                print(f"🛑 [BỊ TỪ CHỐI BẢO MẬT] {decision.reason}")
                print(f"   Mức độ rủi ro: {decision.risk_level} -> Hủy bỏ hành động chặn.")
            else:
                print(f"✅ [CHẤP THUẬN AN TOÀN] {decision.reason}")
                print(f"⚠️  Hành động có mức rủi ro {decision.risk_level}. Yêu cầu xác nhận con người (HITL).")
                
                try:
                    confirm = input(f"👉 Bạn có đồng ý thực thi chặn IP '{target_ip}' ({DEFAULT_BLOCK_TTL_MINUTES} phút) trên UFW không? [y/N]: ").strip().lower()
                except EOFError:
                    confirm = "n"

                if confirm == "y":
                    print(f"[*] Đang thực thi Wrapper Script chặn UFW và xác minh trên {HOST}...")
                    exec_res = block_ip(target_ip)
                    verify_res = verify_response(target_ip, expected_state="blocked")
                    record_audit_log(
                        action="block_ip",
                        target=target_ip,
                        operator="SOC Analyst (CLI HITL)",
                        policy_decision=decision,
                        execution_result=exec_res,
                        verification_result=verify_res
                    )
                    if exec_res.get("status") == "ok":
                        save_active_block(target_ip, ttl_minutes=DEFAULT_BLOCK_TTL_MINUTES, reason=decision.reason)
                        print(f"[+] {verify_res.get('data', {}).get('message', 'Thành công!')}")
                        if verify_res.get("data", {}).get("ufw_warning"):
                            print(f"[-] {verify_res['data']['ufw_warning']}")
                    else:
                        print(f"[-] Thất bại: {exec_res.get('error')}")
                else:
                    print("[*] Đã bỏ qua hành động phản ứng.")


def cmd_firewall(args):
    """Kiểm tra danh sách quy tắc UFW và danh sách IP đang cách ly trên lab server."""
    print(f"[*] Đang truy vấn trạng thái tường lửa UFW từ {HOST}...")
    res = get_firewall_status()
    if res.get("status") != "ok":
        print(f"[-] Lỗi truy vấn: {res.get('error')}")
        return

    data = res.get("data", {})
    print(f"\n[+] Trạng thái dịch vụ UFW: {'ACTIVE (Đang bật)' if data.get('active') else 'INACTIVE (Chưa bật)'}")
    print(f"[+] Tổng số quy tắc: {data.get('total_rules', 0)}\n")

    rules = data.get("rules", [])
    if not rules:
        print("    (Không có quy tắc tùy chỉnh nào trong bảng UFW)")
        if data.get("raw_output"):
            print(f"    Raw output: {data.get('raw_output')}")
    else:
        for r in rules:
            print(f"  [{r.get('rule_num')}] {r.get('action'):<10} from {r.get('from'):<20} to {r.get('to')}")

    # Hiển thị các IP đang cách ly có thời hạn (TTL)
    active_blocks = load_active_blocks()
    if active_blocks:
        print(f"\n[+] Danh sách IP đang cách ly có thời hạn (Active Blocks & TTL):")
        for b_ip, b_info in active_blocks.items():
            print(f"  - 🔒 {b_ip} (Hết hạn lúc: {b_info.get('expires_at')}, TTL: {b_info.get('ttl_minutes')}p)")


def cmd_block(args):
    """Thực thi chặn IP thủ công qua Policy Engine."""
    target_ip = args.ip
    print(f"[*] Đang thẩm định hành động chặn IP '{target_ip}' qua Policy Engine...")
    decision = evaluate_action("block_ip", target_ip)

    if not decision.allowed:
        print(f"\n🛑 [TỪ CHỐI BẢO MẬT] {decision.reason}")
        sys.exit(1)

    print(f"\n✅ [HỢP LỆ] {decision.reason}")
    if not args.yes:
        confirm = input(f"👉 Bạn có chắc chắn muốn áp dụng luật chặn IP '{target_ip}' ({DEFAULT_BLOCK_TTL_MINUTES} phút) không? [y/N]: ").strip().lower()
        if confirm != "y":
            print("[*] Đã hủy thao tác.")
            return

    print(f"[*] Đang gửi lệnh cấu hình UFW tới {HOST} qua Wrapper Script...")
    exec_res = block_ip(target_ip)
    verify_res = verify_response(target_ip, expected_state="blocked")
    record_audit_log(
        action="block_ip",
        target=target_ip,
        operator="SOC Analyst (Manual CLI)",
        policy_decision=decision,
        execution_result=exec_res,
        verification_result=verify_res
    )
    if exec_res.get("status") == "ok":
        save_active_block(target_ip, ttl_minutes=DEFAULT_BLOCK_TTL_MINUTES, reason=decision.reason)
        print(f"[+] {verify_res.get('data', {}).get('message')}")
        if verify_res.get("data", {}).get("ufw_warning"):
            print(f"[-] {verify_res['data']['ufw_warning']}")
    else:
        print(f"[-] Lỗi: {exec_res.get('error')}")


def cmd_unblock(args):
    """Gỡ bỏ quy tắc chặn IP trên UFW."""
    target_ip = args.ip
    print(f"[*] Đang kiểm tra IP '{target_ip}'...")
    decision = evaluate_action("unblock_ip", target_ip)
    if not decision.allowed:
        print(f"[-] Cú pháp IP không hợp lệ: {decision.reason}")
        return

    print(f"[*] Đang gỡ bỏ quy tắc chặn IP '{target_ip}' trên {HOST}...")
    exec_res = unblock_ip(target_ip)
    verify_res = verify_response(target_ip, expected_state="unblocked")
    remove_active_block(target_ip)
    record_audit_log(
        action="unblock_ip",
        target=target_ip,
        operator="SOC Analyst (Manual Unblock)",
        policy_decision=decision,
        execution_result=exec_res,
        verification_result=verify_res
    )
    if exec_res.get("status") == "ok":
        print(f"[+] {verify_res.get('data', {}).get('message')}")
    else:
        print(f"[-] Lỗi: {exec_res.get('error')}")


def cmd_monitor(args):
    """Khởi chạy tiến trình Giám sát An ninh Tự hành (Autonomous SOAR Daemon)."""
    mode = getattr(args, "mode", "event-driven")
    daemon = SOCMonitorDaemon(
        poll_interval=args.interval,
        auto_block=False if args.no_auto_block else None,
        lines_to_check=args.lines,
        cooldown_minutes=args.cooldown
    )
    daemon.start(mode=mode)


def cmd_listen(args):
    """Khởi chạy Wazuh Webhook Server đón nhận Alert từ SIEM."""
    start_wazuh_listener(
        host=args.host,
        port=args.port,
        auto_block=not args.no_auto_block,
        test_mode=args.test_mode,
        blocking=True
    )


def cmd_benchmark(args):
    """Chạy đánh giá định lượng hệ thống (Accuracy, FPR, Latency)."""
    from scripts.benchmark_wazuh import run_benchmark
    use_mock = not getattr(args, "live", False) or getattr(args, "mock", False)
    run_benchmark(verbose=True, mock_mode=use_mock, limit=getattr(args, "limit", None))


def cmd_test_email(args):
    """Kiểm tra kết nối và gửi thử nghiệm Email cảnh báo qua Gmail SMTP."""
    cfg = get_email_config()
    target = args.to or cfg.get("recipient_email") or cfg.get("sender_email")
    print(f"[*] Đang chuẩn bị gửi email thử nghiệm...")
    print(f"    SMTP Server: {cfg.get('smtp_server')}:{cfg.get('smtp_port')}")
    print(f"    Người gửi:   {cfg.get('sender_email') or '(Chưa cấu hình trong .env)'}")
    print(f"    Người nhận:  {target or '(Chưa cấu hình)'}")
    print(f"    Trạng thái:  {'BẬT (Live SMTP)' if cfg.get('enabled') else 'TẮT (Chỉ lưu file preview HTML)'}\n")

    res = send_test_email(recipient=target)
    if res["status"] == "sent":
        print(f"✅ Gửi email thử nghiệm thành công tới: {res.get('recipient')}!")
        print(f"   Bản tin lưu trữ: {res.get('preview_path')}")
    elif res["status"] == "skipped":
        print(f"ℹ️ Chưa gửi email thật qua SMTP: {res.get('reason')}")
        print(f"   Đã lưu bản tin mẫu giao diện HTML tại: {res.get('preview_path')}")
        print("   👉 Bạn có thể mở file HTML trên bằng trình duyệt để xem trước giao diện báo cáo.")
    else:
        print(f"🛑 Gặp lỗi khi gửi email qua SMTP: {res.get('error')}")
        print(f"   Bản tin dự phòng được lưu tại: {res.get('preview_path')}")


def cmd_ui(args):
    """Khởi chạy Giao diện Web Dashboard (Streamlit)."""
    print("[*] Đang khởi chạy Giao diện Web Dashboard trên Streamlit...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])


def cmd_test(args):
    """Chạy toàn bộ các bộ kiểm thử tự động trong tests/ và kiểm toán bảo mật."""
    print("[*] Đang thực thi toàn bộ bài kiểm thử tự động (Unit & Integration Tests)...\n")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.dirname(__file__))
    subprocess.run([sys.executable, "-m", "unittest", "discover", "tests"], env=env)

    print("\n" + "=" * 65)
    print("[*] Đang thực thi kiểm toán an toàn mã nguồn (security_audit.py)...")
    print("=" * 65)
    subprocess.run([sys.executable, "security_audit.py"], env=env)


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ AI SOC Investigation & Defense Agent - Công cụ dòng lệnh hợp nhất (Unified CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Lệnh chức năng")

    # Lệnh: monitor (Autonomous SOAR Daemon)
    p_mon = subparsers.add_parser("monitor", help="Khởi động tiến trình Giám sát Tự hành liên tục (SOAR Daemon)")
    p_mon.add_argument("-m", "--mode", choices=["event-driven", "poll"], default="event-driven", help="Chế độ giám sát: event-driven (Wazuh Webhook) hoặc poll (SSH polling)")
    p_mon.add_argument("-i", "--interval", type=int, default=None, help="Chu kỳ thăm dò tính theo giây (khi ở chế độ poll)")
    p_mon.add_argument("-l", "--lines", type=int, default=300, help="Số dòng log auth.log kiểm tra mỗi chu kỳ (chế độ poll)")
    p_mon.add_argument("-c", "--cooldown", type=int, default=15, help="Thời gian làm nguội chống bão log tính theo phút (mặc định: 15)")
    p_mon.add_argument("--no-auto-block", action="store_true", help="Tắt tự động chặn IP (chuyển sang chế độ Semi-Autonomous chờ duyệt)")
    p_mon.set_defaults(func=cmd_monitor)

    # Lệnh: listen (Wazuh Webhook Server)
    p_listen = subparsers.add_parser("listen", help="Khởi chạy Webhook Receiver lắng nghe Alert từ Wazuh SIEM")
    p_listen.add_argument("--host", default=os.getenv("WEBHOOK_HOST", "192.168.56.1"), help="Địa chỉ host lắng nghe (mặc định: 192.168.56.1)")
    p_listen.add_argument("-p", "--port", type=int, default=int(os.getenv("WEBHOOK_PORT", "5000")), help="Cổng lắng nghe Webhook (mặc định: 5000)")
    p_listen.add_argument("--no-auto-block", action="store_true", help="Tắt tự động chặn IP")
    p_listen.add_argument("--test-mode", action="store_true", help="Chế độ kiểm thử (không gọi UFW thật)")
    p_listen.set_defaults(func=cmd_listen)

    # Lệnh: test-email (Kiểm tra kết nối SMTP Gmail)
    p_email = subparsers.add_parser("test-email", help="Gửi email thử nghiệm kiểm tra kết nối Gmail SMTP")
    p_email.add_argument("--to", type=str, default=None, help="Địa chỉ email nhận thử nghiệm (mặc định: đọc từ .env)")
    p_email.set_defaults(func=cmd_test_email)

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

    # Lệnh: firewall
    p_fw = subparsers.add_parser("firewall", help="Xem trạng thái và các quy tắc tường lửa UFW")
    p_fw.set_defaults(func=cmd_firewall)

    # Lệnh: block
    p_block = subparsers.add_parser("block", help="Chặn một IP có thẩm định an toàn qua Policy Engine")
    p_block.add_argument("ip", type=str, help="Địa chỉ IP cần chặn")
    p_block.add_argument("-y", "--yes", action="store_true", help="Tự động đồng ý không hỏi lại")
    p_block.set_defaults(func=cmd_block)

    # Lệnh: unblock
    p_unblock = subparsers.add_parser("unblock", help="Gỡ chặn một IP trên UFW")
    p_unblock.add_argument("ip", type=str, help="Địa chỉ IP cần gỡ chặn")
    p_unblock.set_defaults(func=cmd_unblock)

    # Lệnh: ui
    p_ui = subparsers.add_parser("ui", help="Mở giao diện Web Dashboard (Streamlit UI)")
    p_ui.set_defaults(func=cmd_ui)

    # Lệnh: test
    p_test = subparsers.add_parser("test", help="Chạy toàn bộ bộ kiểm thử trong tests/")
    p_test.set_defaults(func=cmd_test)

    # Lệnh: benchmark (Đánh giá định lượng có nhãn)
    p_bench = subparsers.add_parser("benchmark", help="Chạy đánh giá định lượng hệ thống trên tập kịch bản gán nhãn")
    p_bench.add_argument("--mock", action="store_true", help="Chạy chế độ đánh giá mock siêu tốc không phụ thuộc Ollama")
    p_bench.add_argument("--live", action="store_true", help="Chạy chế độ suy luận thực tế với mô hình Ollama qwen3:4b")
    p_bench.add_argument("--limit", type=int, default=None, help="Giới hạn số kịch bản đánh giá (ví dụ: --limit 5)")
    p_bench.set_defaults(func=cmd_benchmark)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
