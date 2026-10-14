import json
from read_logs import run_fixed_command
from log_parser import parse_log
from detection import detect_ssh_bruteforce, alert_to_dict

out, err = run_fixed_command("tail -n 500 /var/log/auth.log")
events = parse_log(out)
alerts = detect_ssh_bruteforce(events)

print(f"{len(events)} sự kiện, {len(alerts)} cảnh báo")
for a in alerts:
    print(json.dumps(alert_to_dict(a), indent=2, ensure_ascii=False))