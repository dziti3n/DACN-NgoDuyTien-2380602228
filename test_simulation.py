"""
test_simulation.py - Kịch bản kiểm thử mô phỏng tấn công toàn trình trên CMD (End-to-End Live Simulation)
Chạy trực tiếp trên Terminal/CMD y hệt như khi bấm nút "🧪 Chạy Test Mô Phỏng" trên Web Dashboard:
Kích hoạt AI ReAct qua Local Ollama -> Thẩm định Policy Engine -> Chặn UFW thật -> Gửi Gmail thật.
"""

import os
import sys
import time
from datetime import datetime

# Đảm bảo in font tiếng Việt chuẩn trên PowerShell / CMD Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from agent import investigate
from policy_engine import (
    evaluate_action,
    record_audit_log,
    save_active_block,
    DEFAULT_BLOCK_TTL_MINUTES,
)
from tools import block_ip, verify_response
from notifier import send_alert_email, build_alert_html
from wazuh_listener import normalize_wazuh_alert
from scripts.simulate_wazuh_alert import generate_wazuh_payload


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mô phỏng tấn công toàn trình trên CMD (Live Simulation)")
    parser.add_argument("--type", choices=["bruteforce", "invalid_user", "sudo", "sudo_success", "tamper"], default="bruteforce", help="Loại tấn công (mặc định: bruteforce)")
    parser.add_argument("--ip", default="192.168.56.102", help="IP nguồn tấn công (mặc định: 192.168.56.102)")
    parser.add_argument("--user", default="root", help="Tài khoản nhắm tới (mặc định: root)")
    args = parser.parse_args()

    target_ip = args.ip
    alert_type = args.type

    print("\n" + "=" * 70)
    print(f"🚨 [MÔ PHỎNG TẤN CÔNG WAZUH SIEM LIVE] {alert_type.upper()}")
    print(f"🎯 Mục tiêu giả lập: Tấn công từ IP {target_ip} (Target: {args.user})")
    print("=" * 70)

    # 1. Kịch bản cảnh báo chuẩn Wazuh SIEM
    raw_payload = generate_wazuh_payload(alert_type=alert_type, src_ip=target_ip, target_user=args.user)
    sim_alert = normalize_wazuh_alert(raw_payload)

    print("\n[*] BƯỚC 1: Kích hoạt Local AI ReAct Agent (Ollama qwen3:4b) để điều tra...")
    t0 = time.time()
    try:
        run_res = investigate(sim_alert, verbose=True)
    except Exception as ex:
        print(f"[-] Lỗi gọi mô hình AI: {ex}")
        return

    elapsed_ai = round(time.time() - t0, 2)
    conc = run_res.get("conclusion", {})

    print(f"\n[+] AI ĐIỀU TRA HOÀN TẤT ({elapsed_ai}s):")
    print(f"    - Phán quyết (Verdict)  : {conc.get('verdict')}")
    print(f"    - Mức độ (Severity)     : {conc.get('severity')}")
    print(f"    - Độ tin cậy (Confidence): {conc.get('confidence')}")
    print(f"    - Tóm tắt               : {conc.get('summary')}")
    print(f"    - Bằng chứng            : {conc.get('evidence')}")
    print(f"    - Đề xuất               : {conc.get('recommended_actions')}")

    # 2. Thẩm định an toàn qua Policy Engine
    print("\n[*] BƯỚC 2: Thẩm định an toàn qua Deterministic Policy Engine...")
    decision = evaluate_action(
        action="block_ip",
        target=target_ip,
        context={
            "alert": sim_alert,
            "evidence": conc.get("evidence", []),
            "verdict": conc.get("verdict"),
            "confidence": conc.get("confidence"),
            "severity": conc.get("severity"),
        }
    )

    if not decision.allowed:
        print(f"[-] Policy Engine TỪ CHỐI hành động: {decision.reason}")
        return

    print(f"[+] Policy Engine CHẤP THUẬN: {decision.reason}")

    # 3. Phản ứng chặn Tường lửa UFW thật
    print(f"\n[*] BƯỚC 3: Kích hoạt Wrapper UFW cô lập IP {target_ip} trên máy ảo Lab...")
    exec_res = block_ip(target_ip)
    verify_res = verify_response(target_ip, expected_state="blocked")
    save_active_block(target_ip, ttl_minutes=DEFAULT_BLOCK_TTL_MINUTES, reason=decision.reason)
    
    record_audit_log(
        action="block_ip",
        target=target_ip,
        operator="CLI Live Simulator (test_simulation.py)",
        policy_decision=decision,
        execution_result=exec_res,
        verification_result=verify_res
    )

    print(f"[+] Kết quả chặn UFW: {exec_res.get('status')}")
    print(f"[+] Trạng thái xác minh: {verify_res.get('state')} (Verified: {verify_res.get('verified')})")
    print(f"[+] Đã ghi nhật ký kiểm toán vào: runs/action_audit.log & runs/audit_trail.jsonl")

    # 4. Gửi Email thông báo thật về Gmail
    print("\n[*] BƯỚC 4: Gửi bản tin cảnh báo HTML về Gmail...")
    resp_info = {
        "action": "block_ip",
        "status": "blocked",
        "target_ip": target_ip,
        "ttl_minutes": DEFAULT_BLOCK_TTL_MINUTES,
        "reason": decision.reason,
        "exec_res": exec_res,
        "verify_res": verify_res,
    }
    subject = f"🚨 [SOC ALERT - CLI TEST] SSH_BRUTEFORCE từ {target_ip} (Mức độ: CRITICAL)"
    html_body = build_alert_html(sim_alert, run_res, resp_info)
    plain_text = f"Cảnh báo tấn công ssh_bruteforce từ {target_ip}. Verdict: {conc.get('verdict')}."
    
    email_res = send_alert_email(subject, html_body, plain_text)
    if email_res.get("status") == "sent":
        print(f"[+] ✅ GỬI GMAIL THÀNH CÔNG! Đã chuyển tới: {email_res.get('recipient')}")
    else:
        print(f"[i] Trạng thái Email: {email_res.get('status')} - {email_res.get('note', '')}")
        print(f"    Bản tin HTML dự phòng: {email_res.get('preview_path')}")

    total_time = round(time.time() - t0, 2)
    print("\n" + "=" * 70)
    print(f"🎉 HOÀN TẤT TOÀN BỘ CHU TRÌNH TEST TRONG: {total_time} GIÂY!")
    print(f"💡 IP {target_ip} hiện ĐANG BỊ CHẶN trên tường lửa UFW trong {DEFAULT_BLOCK_TTL_MINUTES} phút.")
    print(f"👉 Để gỡ chặn IP này, bạn chỉ cần gõ: python cli.py unblock {target_ip}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

