import json
from tools import search_auth_logs, inspect_user_changes, check_ssh_config

print("== search_auth_logs (IP 192.168.56.1) ==")
print(json.dumps(search_auth_logs(src_ip="192.168.56.1"), indent=2, ensure_ascii=False))

print("\n== search_auth_logs (tham số xấu) ==")
print(json.dumps(search_auth_logs(src_ip="1.2.3.4; rm -rf /"), indent=2, ensure_ascii=False))

print("\n== inspect_user_changes ==")
print(json.dumps(inspect_user_changes(), indent=2, ensure_ascii=False))

print("\n== check_ssh_config ==")
print(json.dumps(check_ssh_config(), indent=2, ensure_ascii=False))