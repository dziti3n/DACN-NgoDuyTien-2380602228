from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

WINDOW = timedelta(minutes=5)
THRESHOLD = 5
IGNORED_USERS = {"agent_soc"}


@dataclass
class Alert:
    rule: str
    src_ip: str
    first_seen: str
    last_seen: str
    total_failures: int
    users_tried: list
    invalid_user_failures: int      # số lần thất bại với user không tồn tại
    success_after_failures: list    # user đăng nhập thành công từ IP này sau chuỗi thất bại


def detect_ssh_bruteforce(events):
    events = sorted(events, key=lambda e: e.ts)
    fails = {}
    for e in events:
        if e.event_type == "ssh_failed" and e.src_ip and e.user not in IGNORED_USERS:
            fails.setdefault(e.src_ip, []).append(e)

    alerts = []
    for ip, evs in fails.items():
        i = 0
        while i < len(evs):
            # một chuỗi = các lần thất bại liên tiếp, mỗi lần cách lần trước <= WINDOW
            j = i
            while j + 1 < len(evs) and evs[j + 1].ts - evs[j].ts <= WINDOW:
                j += 1
            burst = evs[i:j + 1]
            i = j + 1

            if sum(b.count for b in burst) < THRESHOLD:
                continue

            first, last = burst[0].ts, burst[-1].ts
            success = sorted({
                a.user for a in events
                if a.event_type == "ssh_accepted" and a.src_ip == ip
                and a.user not in IGNORED_USERS
                and first <= a.ts <= last + WINDOW
            })
            alerts.append(Alert(
                rule="ssh_bruteforce",
                src_ip=ip,
                first_seen=first.isoformat(),
                last_seen=last.isoformat(),
                total_failures=sum(b.count for b in burst),
                users_tried=sorted({b.user for b in burst}),
                invalid_user_failures=sum(b.count for b in burst if b.user_exists is False),
                success_after_failures=success,
            ))
    return alerts


def alert_to_dict(a):
    return asdict(a)