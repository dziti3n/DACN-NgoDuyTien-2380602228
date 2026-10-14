import json
import sys

# Đảm bảo in UTF-8 không lỗi font tiếng Việt trên PowerShell Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from read_logs import run_fixed_command
from log_parser import parse_log
from detection import detect_ssh_bruteforce, alert_to_dict
from agent import investigate

try:
    out, err = run_fixed_command("tail -n 500 /var/log/auth.log")
    if not out.strip() and err:
        print(f"[-] Không đọc được log từ server lab qua SSH: {err}")
        sys.exit(1)
except Exception as ex:
    print(f"[-] Lỗi kết nối SSH đến server lab: {ex}")
    print("Vui lòng kiểm tra máy ảo lab và cấu hình SSH trong read_logs.py.")
    sys.exit(1)

alerts = [alert_to_dict(a) for a in detect_ssh_bruteforce(parse_log(out))]
print(f"[*] Tìm thấy {len(alerts)} cảnh báo SSH Bruteforce.")
if not alerts:
    print("[*] Không có cảnh báo nào cần điều tra. Thoát.")
    sys.exit(0)

idx = int(sys.argv[1]) if len(sys.argv) > 1 else len(alerts) - 1   # mặc định: cảnh báo mới nhất
alert = alerts[idx]
print(f"[*] Đang điều tra cảnh báo #{idx}: {alert['total_failures']} lần thất bại từ IP {alert['src_ip']}...\n")

run = investigate(alert)

c = run["conclusion"]
print(f"\n== KẾT LUẬN ({run['model']}, {run['elapsed_sec']}s, {run['tool_calls']} lần gọi tool) ==")
print(f"Verdict:    {c.get('verdict')} | Severity: {c.get('severity')} | Confidence: {c.get('confidence')}")
print(f"Tóm tắt:    {c.get('summary')}")
print(f"Bằng chứng: {json.dumps(c.get('evidence', []), ensure_ascii=False, indent=2)}")
print(f"Còn thiếu:  {json.dumps(c.get('missing_data', []), ensure_ascii=False)}")
print(f"Đề xuất:    {json.dumps(c.get('recommended_actions', []), ensure_ascii=False, indent=2)}")
print(f"\n[+] Chi tiết toàn bộ phiên điều tra đã lưu tại: {run['saved_to']}")