import json
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from read_logs import run_fixed_command
from log_parser import parse_log
from detection import detect_all, alert_to_dict

out, err = run_fixed_command("tail -n 1000 /var/log/auth.log")
events = parse_log(out)
alerts = detect_all(events, baseline_path="baseline.json")

print(f"[*] Quét {len(events)} sự kiện log:")
print(f"[*] Phát hiện tổng cộng {len(alerts)} cảnh báo an ninh:\n")

for i, a in enumerate(alerts):
    d = alert_to_dict(a)
    print(f"--- CẢNH BÁO #{i} [{d.get('rule')}] (Mức độ: {d.get('severity_hint', 'N/A')}) ---")
    print(f"Tóm tắt: {d.get('summary')}")
    print("Chi tiết:")
    print(json.dumps(d, indent=2, ensure_ascii=False))
    print()