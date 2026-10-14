import sys
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from log_parser import Event, parse_log
from detection import (
    detect_ssh_bruteforce,
    detect_sudo_abuse,
    detect_baseline_account_tampering,
    detect_all,
)

passed = 0
failed = 0

def check(name, condition, msg=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} - {msg}")

print("==========================================================")
print("KIỂM THỬ BỘ QUY TẮC PHÁT HIỆN AN NINH (DETECTION RULES)")
print("==========================================================\n")

# --- TEST 1: Kiểm tra parser nhận diện các loại sự kiện mới ---
print("1. Kiểm tra log_parser nhận diện sự kiện:")
raw_sample = """
2026-10-14T08:00:00+00:00 lab-srv sudo: hacker : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
2026-10-14T08:01:00+00:00 lab-srv sudo: testuser : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/bin/bash
2026-10-14T08:02:00+00:00 lab-srv useradd[555]: new user: name=evil_backdoor, UID=1005, GID=1005, home=/home/evil_backdoor, shell=/bin/bash
2026-10-14T08:03:00+00:00 lab-srv usermod[666]: add 'evil_backdoor' to group 'sudo'
2026-10-14T08:04:00+00:00 lab-srv sudo: admin_duytien : TTY=pts/0 ; PWD=/home/admin_duytien ; USER=root ; COMMAND=/usr/bin/su -
"""
events = parse_log(raw_sample)
types = [e.event_type for e in events]

check("1.1 Bắt sự kiện sudo_not_in_sudoers", "sudo_not_in_sudoers" in types)
check("1.2 Bắt sự kiện sudo_auth_failure", "sudo_auth_failure" in types)
check("1.3 Bắt sự kiện account_created", "account_created" in types)
check("1.4 Bắt sự kiện group_member_added", "group_member_added" in types)
check("1.5 Bắt sự kiện sudo_command", "sudo_command" in types)


# --- TEST 2: Kiểm tra Rule phát hiện Sudo Abuse ---
print("\n2. Kiểm tra Rule detect_sudo_abuse:")
alerts_sudo = detect_sudo_abuse(events)
sudo_rules = [a.rule for a in alerts_sudo]

check("2.1 Phát hiện user_not_in_sudoers", "sudo_unauthorized_attempt" in sudo_rules)
check("2.2 Phát hiện nhập sai password sudo dồn dập", "sudo_auth_burst_failure" in sudo_rules)
check("2.3 Phát hiện lệnh sudo nhạy cảm nguy hiểm (su -)", "sudo_suspicious_command" in sudo_rules)


# --- TEST 3: Kiểm tra Rule phát hiện vi phạm Baseline ---
print("\n3. Kiểm tra Rule detect_baseline_account_tampering:")
alerts_baseline = detect_baseline_account_tampering(events, baseline_path="baseline.json")
baseline_rules = [a.rule for a in alerts_baseline]

check("3.1 Phát hiện tạo user lạ ngoài baseline (evil_backdoor)", "unauthorized_account_creation" in baseline_rules)
check("3.2 Phát hiện cấp quyền sudo cho user ngoài baseline", "unauthorized_privileged_group_assignment" in baseline_rules)


# --- TEST 4: Kiểm tra detect_all hợp nhất ---
print("\n4. Kiểm tra detect_all:")
all_alerts = detect_all(events, baseline_path="baseline.json")
check("4.1 Hợp nhất tất cả cảnh báo", len(all_alerts) == 5, f"Mong đợi 5 cảnh báo, có {len(all_alerts)}")

print("\n==========================================================")
print(f"KẾT QUẢ KIỂM THỬ: {passed} PASS, {failed} FAIL")
print("==========================================================")
