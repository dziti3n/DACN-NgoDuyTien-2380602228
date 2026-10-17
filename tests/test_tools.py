import os
import sys

# Thêm thư mục gốc vào sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT_DIR, ".env"))

from tools import (
    search_auth_logs,
    inspect_user_changes,
    check_ssh_config,
    inspect_active_processes,
    inspect_network_connections,
    inspect_cron_persistence,
    TOOLS,
)

print(f"[*] Tổng số tools đã đăng ký: {len(TOOLS)}")
for name in TOOLS:
    print(f"  - {name}")

print("\n==========================================")
print("1. TEST inspect_active_processes:")
res_proc = inspect_active_processes(limit=5)
print(f"Status: {res_proc['status']}")
if res_proc['status'] == 'ok':
    print(f"Total running: {res_proc['data']['total_running']}")
    print(f"Suspicious found: {len(res_proc['data']['suspicious_processes'])}")
    print(f"Top 2 processes:")
    for p in res_proc['data']['top_processes_by_cpu'][:2]:
        print(f"  [{p['user']}] PID {p['pid']}: {p['command']} (CPU: {p['cpu']}%)")

print("\n==========================================")
print("2. TEST inspect_network_connections:")
res_net = inspect_network_connections()
print(f"Status: {res_net['status']}")
if res_net['status'] == 'ok':
    print(f"Listening services: {len(res_net['data']['listening_services'])}")
    print(f"Established connections: {res_net['data']['total_established']}")
    for c in res_net['data']['established_connections'][:3]:
        print(f"  {c['proto']} {c['local']} <-> {c['peer']}")

print("\n==========================================")
print("3. TEST inspect_cron_persistence:")
res_cron = inspect_cron_persistence()
print(f"Status: {res_cron['status']}")
if res_cron['status'] == 'ok':
    print(f"Crontab entries: {len(res_cron['data']['crontab_entries'])}")
    print(f"Cron.d entries: {len(res_cron['data']['cron_d_entries'])}")
    print(f"Suspicious cron jobs: {len(res_cron['data']['suspicious_cron_jobs'])}")

print("\n[+] Hoàn thành kiểm tra tất cả các tools mới thành công!")

