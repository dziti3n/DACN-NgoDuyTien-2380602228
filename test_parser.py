from collections import Counter
from read_logs import run_fixed_command
from log_parser import parse_log

out, err = run_fixed_command("tail -n 200 /var/log/auth.log")
events = parse_log(out)

for e in events:
    print(e.ts.strftime("%H:%M:%S"), e.event_type, e.user, e.src_ip, "x%d" % e.count)

print("\nTổng số lần SSH thất bại theo (IP, user):")
fails = Counter()
for e in events:
    if e.event_type == "ssh_failed":
        fails[(e.src_ip, e.user)] += e.count
for k, v in fails.items():
    print(k, v)