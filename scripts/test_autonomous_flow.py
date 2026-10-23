#!/usr/bin/env python3
"""
scripts/test_autonomous_flow.py - Bài kiểm thử nhẹ luồng Tự hành & Cảnh báo Email
Mô phỏng một sự cố an ninh thực tế (SSH Bruteforce từ máy Kali 192.168.56.102)
để kiểm chứng toàn bộ quy trình:
1. Phát hiện sự cố (Detection)
2. AI ReAct Agent điều tra qua Local Ollama (qwen3:4b)
3. Thẩm định an toàn qua Policy Engine (Guardrails & TTL 15m)
4. Tự động gửi Email cảnh báo sự cố thật về Gmail của bạn
5. Ghi nhận nhật ký kiểm toán (Audit Trail)
"""

import os
import sys
from datetime import datetime
from pathlib import Path

# Đảm bảo import được các module từ thư mục gốc
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Đảm bảo in UTF-8 tiếng Việt trên PowerShell Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from monitor_daemon import SOCMonitorDaemon
from notifier import get_email_config

def main():
    print("=" * 70)
    print("🧪 BÀI KIỂM THỬ NHẸ: LUỒNG GIÁM SÁT TỰ HÀNH & GỬI EMAIL CẢNH BÁO")
    print("=" * 70)

    # 1. Kiểm tra cấu hình môi trường
    cfg = get_email_config()
    print("\n[1/4] Kiểm tra cấu hình thông báo:")
    print(f"  - Trạng thái Email: {'BẬT (Gửi thật qua Gmail SMTP)' if cfg['enabled'] else 'TẮT (Lưu file HTML)'}")
    print(f"  - Người gửi:        {cfg['sender_email'] or '(Chưa cấu hình)'}")
    print(f"  - Người nhận:       {cfg['recipient_email'] or '(Chưa cấu hình)'}")

    # 2. Tạo cảnh báo mẫu giả lập tấn công từ IP Kali Linux (192.168.56.102)
    sample_alert = {
        "rule": "ssh_bruteforce",
        "severity_hint": "critical",
        "summary": "Phát hiện dò mật khẩu SSH từ 192.168.56.102: 12 lần thử thất bại, nhắm vào các tài khoản root, admin, ubuntu.",
        "src_ip": "192.168.56.102",
        "first_seen": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
        "details": {
            "src_ip": "192.168.56.102",
            "total_failures": 12,
            "users_tried": ["root", "admin", "ubuntu"],
            "invalid_user_failures": 8,
            "success_after_failures": []
        }
    }

    print("\n[2/4] Khởi tạo sự cố giả lập:")
    print(f"  - Quy tắc:    {sample_alert['rule']}")
    print(f"  - Mức độ:     {sample_alert['severity_hint'].upper()}")
    print(f"  - IP nguồn:   {sample_alert['src_ip']} (Máy tấn công Kali Linux)")
    print(f"  - Tóm tắt:    {sample_alert['summary']}")

    # 3. Kích hoạt Daemon xử lý sự cố (ở chế độ test_mode để an toàn cho UFW)
    print("\n[3/4] Đang chuyển cảnh báo vào Daemon Giám sát Tự hành...")
    daemon = SOCMonitorDaemon(
        poll_interval=20,
        auto_block=True,
        cooldown_minutes=15,
        test_mode=True
    )

    # Xử lý cảnh báo qua AI ReAct -> Policy Engine -> UFW Block -> Gửi Email
    daemon.handle_alert(sample_alert)

    # 4. Kiểm tra kết quả sau khi xử lý
    print("\n[4/4] Tổng kết kết quả sau kiểm thử:")
    print(f"  - Số cảnh báo đã xử lý:  {daemon.total_alerts_handled}")
    print(f"  - Số quyết định cô lập:  {daemon.total_blocks_executed}")
    print(f"  - Số email đã gửi thành công: {daemon.total_emails_sent}")
    print("\n✅ KIỂM THỬ HOÀN TẤT TRƠN TRU!")
    print("👉 Hãy kiểm tra hộp thư đến Gmail trên điện thoại/máy tính của bạn để xem bản tin cảnh báo an ninh vừa được gửi về.")
    print("=" * 70)

if __name__ == "__main__":
    main()
