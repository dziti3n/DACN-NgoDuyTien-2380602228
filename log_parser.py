import re
from dataclasses import dataclass
from datetime import datetime

LINE_RE = re.compile(
    r"^(?P<ts>\S+) (?P<host>\S+) (?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?P<inv>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
INVALID_RE = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SUDO_RE = re.compile(r"^(?P<user>\S+) : .*USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
REPEAT_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[ ?(?P<inner>.*?) ?\]$")

@dataclass
class Event:
    ts: datetime
    host: str
    event_type: str          # ssh_failed, ssh_invalid_user, ssh_accepted, sudo_command
    user: str | None = None
    src_ip: str | None = None
    port: int | None = None
    method: str | None = None
    count: int = 1           # số lần thực tế mà dòng log này đại diện
    user_exists: bool | None = None
    detail: str | None = None


def _parse_msg(ts, host, prog, msg, count=1):
    if prog == "sshd":
        m = FAILED_RE.match(msg)
        if m:
            return Event(ts, host, "ssh_failed", m["user"], m["ip"], int(m["port"]),
                         m["method"], count, user_exists=(m["inv"] is None))
        m = INVALID_RE.match(msg)
        if m:
            return Event(ts, host, "ssh_invalid_user", m["user"], m["ip"], int(m["port"]),
                         None, count, user_exists=False)
        m = ACCEPTED_RE.match(msg)
        if m:
            return Event(ts, host, "ssh_accepted", m["user"], m["ip"], int(m["port"]),
                         m["method"], count)
    elif prog == "sudo":
        m = SUDO_RE.match(msg)
        if m:
            return Event(ts, host, "sudo_command", m["user"], None, None, None, count,
                         detail=f'as {m["target"]}: {m["cmd"]}')
    return None


def parse_line(line):
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.fromisoformat(m["ts"])
    rep = REPEAT_RE.match(m["msg"])
    if rep:
        return _parse_msg(ts, m["host"], m["prog"], rep["inner"], count=int(rep["n"]))
    return _parse_msg(ts, m["host"], m["prog"], m["msg"])


def parse_log(text):
    return [e for e in (parse_line(l) for l in text.splitlines()) if e]