# core/schema.py - Data Models & Converters cho Giao diện AI SOC Command Center
from datetime import datetime
import html
import re
from typing import TypedDict, List, Optional, Literal, Dict, Any

from core.policy_engine import (
    is_protected_ip,
    load_active_blocks,
    DEFAULT_BLOCK_TTL_MINUTES,
)

# ------------------------------------------------------------------------------
# 1. TYPES THEO CHUẨN GIAO DIỆN SOC
# ------------------------------------------------------------------------------
SeverityLevel = Literal['CAO', 'TRUNG_BINH', 'THAP']
IncidentStatus = Literal['OPEN', 'APPROVED', 'REVIEWED', 'RESOLVED']
LogLevel = Literal['INFO', 'WARN', 'CRIT']


class TimelineEvent(TypedDict, total=False):
    time: str
    description: str
    highlight: Optional[str]


class ProposedAction(TypedDict, total=False):
    badge: str
    description: str
    checks: List[str]
    primaryBtnText: str
    secondaryBtnText: str


class Incident(TypedDict, total=False):
    id: str
    title: str
    severity: SeverityLevel
    host: str
    agentId: str
    sourceIp: str
    ipLabel: Optional[str]
    targetUser: str
    time: str
    ruleId: str
    alertRef: str
    mitreId: str
    mitreTactic: str
    aiSummary: str
    timeline: List[TimelineEvent]
    rawSyslog: str
    proposedAction: ProposedAction
    status: IncidentStatus
    blockedRemainingSeconds: Optional[int]


class LogEntry(TypedDict, total=False):
    id: str
    timestamp: str
    level: LogLevel
    agent: str
    message: str
    highlightIp: Optional[str]


# ------------------------------------------------------------------------------
# 2. HÀM CHUYỂN ĐỔI MỨC ĐỘ NGHIÊM TRỌNG & HUY HIỆU (BADGES)
# ------------------------------------------------------------------------------
def map_to_severity_level(sev_raw: str, level_num: int = 0) -> SeverityLevel:
    """Ánh xạ các định danh mức độ an ninh thành 'CAO' | 'TRUNG_BINH' | 'THAP'."""
    s = str(sev_raw).upper().strip()
    if s in ("CAO", "CRITICAL", "HIGH") or level_num >= 7:
        return "CAO"
    elif s in ("TRUNG_BINH", "TRUNG BINH", "MEDIUM") or level_num >= 4:
        return "TRUNG_BINH"
    return "THAP"


def get_severity_badge(severity: str) -> str:
    """
    Trả về nhãn HTML mức độ nghiêm trọng theo chuẩn:
    SeverityLevel = 'CAO' | 'TRUNG_BINH' | 'THAP'
    Hỗ trợ đồng thời các nhãn CRITICAL, HIGH, MEDIUM, LOW để tương thích ngược 100%.
    """
    s = str(severity).upper().strip()
    if s in ("CAO", "CRITICAL"):
        label = "CAO" if s == "CAO" else "CRITICAL"
        return (
            '<span class="animate-pulse-subtle" style="background-color: rgba(239, 68, 68, 0.2); '
            'color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.5); padding: 2px 7px; '
            f'border-radius: 4px; font-weight: 800; font-size: 10.5px; box-shadow: 0 0 8px rgba(239, 68, 68, 0.3);">🔴 {label}</span>'
        )
    elif s == "HIGH":
        return (
            '<span style="background-color: rgba(249, 115, 22, 0.2); color: #fdba74; '
            'border: 1px solid rgba(249, 115, 22, 0.5); padding: 2px 7px; border-radius: 4px; '
            'font-weight: 700; font-size: 10.5px;">🟠 HIGH</span>'
        )
    elif s in ("TRUNG_BINH", "TRUNG BINH", "MEDIUM"):
        label = "TRUNG BÌNH" if "TRUNG" in s else "MEDIUM"
        return (
            '<span style="background-color: rgba(234, 179, 8, 0.2); color: #fde047; '
            'border: 1px solid rgba(234, 179, 8, 0.5); padding: 2px 7px; border-radius: 4px; '
            f'font-weight: 700; font-size: 10.5px;">🟡 {label}</span>'
        )
    elif s in ("THAP", "THẤP", "LOW"):
        label = "THẤP" if "TH" in s else "LOW"
        return (
            '<span style="background-color: rgba(56, 189, 248, 0.2); color: #7dd3fc; '
            'border: 1px solid rgba(56, 189, 248, 0.5); padding: 2px 7px; border-radius: 4px; '
            f'font-weight: 700; font-size: 10.5px;">🟢 {label}</span>'
        )
    return (
        '<span style="background-color: rgba(148, 163, 184, 0.15); color: #cbd5e1; '
        'border: 1px solid rgba(148, 163, 184, 0.3); padding: 2px 7px; border-radius: 4px; '
        'font-weight: 700; font-size: 10.5px;">⚪ INFO</span>'
    )


def get_status_badge(status: str) -> str:
    """Trả về nhãn HTML trạng thái Incident ('OPEN' | 'APPROVED' | 'REVIEWED' | 'RESOLVED')."""
    st_upper = str(status).upper().strip()
    if st_upper == "OPEN":
        return (
            '<span class="animate-pulse-subtle" style="background: rgba(239, 68, 68, 0.2); color: #f87171; '
            'border: 1px solid rgba(239, 68, 68, 0.5); padding: 2px 7px; border-radius: 4px; '
            'font-weight: 800; font-size: 10px; letter-spacing: 0.5px;">🔴 OPEN</span>'
        )
    elif st_upper == "APPROVED":
        return (
            '<span style="background: rgba(16, 185, 129, 0.2); color: #34d399; '
            'border: 1px solid rgba(16, 185, 129, 0.5); padding: 2px 7px; border-radius: 4px; '
            'font-weight: 800; font-size: 10px; letter-spacing: 0.5px;">🛡️ APPROVED</span>'
        )
    elif st_upper == "REVIEWED":
        return (
            '<span style="background: rgba(56, 189, 248, 0.2); color: #38bdf8; '
            'border: 1px solid rgba(56, 189, 248, 0.5); padding: 2px 7px; border-radius: 4px; '
            'font-weight: 800; font-size: 10px; letter-spacing: 0.5px;">🔍 REVIEWED</span>'
        )
    elif st_upper == "RESOLVED":
        return (
            '<span style="background: rgba(148, 163, 184, 0.2); color: #94a3b8; '
            'border: 1px solid rgba(148, 163, 184, 0.4); padding: 2px 7px; border-radius: 4px; '
            'font-weight: 700; font-size: 10px; letter-spacing: 0.5px;">✅ RESOLVED</span>'
        )
    return f'<span style="background: rgba(148, 163, 184, 0.15); color: #94a3b8; padding: 2px 7px; border-radius: 4px; font-size: 10px;">{st_upper}</span>'


def get_log_level_badge(level: str) -> str:
    """Trả về nhãn HTML của LogEntry level ('INFO' | 'WARN' | 'CRIT')."""
    l_upper = str(level).upper().strip()
    if l_upper == "CRIT":
        return '<span style="color: #ef4444; font-weight: 800; background: rgba(239,68,68,0.2); border: 1px solid rgba(239,68,68,0.4); padding: 1px 6px; border-radius: 3px; font-size: 10px;">[CRIT]</span>'
    elif l_upper == "WARN":
        return '<span style="color: #f59e0b; font-weight: 700; background: rgba(245,158,11,0.2); border: 1px solid rgba(245,158,11,0.4); padding: 1px 6px; border-radius: 3px; font-size: 10px;">[WARN]</span>'
    elif l_upper == "INFO":
        return '<span style="color: #38bdf8; font-weight: 600; background: rgba(56,189,248,0.15); border: 1px solid rgba(56,189,248,0.3); padding: 1px 6px; border-radius: 3px; font-size: 10px;">[INFO]</span>'
    return f'<span style="color: #94a3b8; font-size: 10px;">[{l_upper}]</span>'


# ------------------------------------------------------------------------------
# 3. BỘ PHÂN TÍCH NHẬT KÝ ĐẦU VÀO RA ĐỐI TƯỢNG LogEntry
# ------------------------------------------------------------------------------
def parse_log_entry(raw_line: str, idx: int = 1) -> LogEntry:
    """
    Phân tích một dòng log thô (syslog hoặc wazuh alert log)
    thành đối tượng chuẩn LogEntry.
    """
    entry_id = f"log-{idx:04d}"
    line_clean = (raw_line or "").strip()

    # Tìm IP để highlight
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line_clean)
    highlight_ip = ip_match.group(0) if ip_match else None

    # Xác định mức độ (CRIT / WARN / INFO)
    crit_keywords = ["failed", "failure", "invalid", "denied", "error", "refused", "brute"]
    warn_keywords = ["warning", "warn", "unauthorized", "suspicious", "attempt"]

    level: LogLevel = "INFO"
    line_lower = line_clean.lower()
    if any(k in line_lower for k in crit_keywords):
        level = "CRIT"
    elif any(k in line_lower for k in warn_keywords):
        level = "WARN"

    # Trích xuất timestamp
    ts_match = re.search(r"\b(\d{1,2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\b", line_clean)
    if ts_match:
        timestamp = ts_match.group(0)
    else:
        timestamp = datetime.now().strftime("%H:%M:%S")

    # Trích xuất daemon hoặc agent
    daemon_match = re.search(r"(sshd(?:\[\d+\])?|sudo(?:\[\d+\])?|systemd|kernel|wazuh|ossec)", line_clean, re.IGNORECASE)
    agent = daemon_match.group(0) if daemon_match else "sshd"

    return {
        "id": entry_id,
        "timestamp": timestamp,
        "level": level,
        "agent": agent,
        "message": line_clean,
        "highlightIp": highlight_ip,
    }


# ------------------------------------------------------------------------------
# 4. CHUYỂN ĐỔI WAZUH ALERT SANG CHUẨN ĐỐI TƯỢNG Incident
# ------------------------------------------------------------------------------
def build_incident_from_alert(
    alert: Dict[str, Any],
    idx: int = 1,
    current_run: Optional[Dict[str, Any]] = None,
    policy_decision: Optional[Any] = None,
    active_blocks: Optional[Dict[str, Any]] = None,
) -> Incident:
    """
    Chuyển đổi cảnh báo Wazuh hoặc Detection Rule alert
    thành đối tượng Incident chuẩn của giao diện SOC Command Center.
    """
    wazuh = alert.get("wazuh", {})
    raw_w = alert.get("raw_wazuh", {})
    details = alert.get("details", {})

    rule_id = str(
        wazuh.get("rule_id")
        or alert.get("rule_id")
        or alert.get("id")
        or raw_w.get("rule", {}).get("id")
        or alert.get("rule")
        or "5712"
    )
    if rule_id.startswith("wazuh_rule_"):
        rule_id = rule_id.replace("wazuh_rule_", "")

    inc_id = f"INC-2026-{idx:04d}"

    # Tiêu đề và mức độ nghiêm trọng
    title = (
        wazuh.get("description")
        or alert.get("summary")
        or raw_w.get("rule", {}).get("description")
        or f"Cảnh báo an ninh Rule {rule_id}"
    )

    level_num = int(wazuh.get("level") or raw_w.get("rule", {}).get("level") or 0)
    sev_hint = alert.get("severity_hint") or alert.get("severity") or ("CAO" if level_num >= 7 else "TRUNG_BINH")
    severity = map_to_severity_level(sev_hint, level_num=level_num)

    # Tên máy trạm và agent_id
    host = (
        wazuh.get("agent_name")
        or raw_w.get("agent", {}).get("name")
        or "Ubuntu-Server"
    )
    agent_id = str(
        wazuh.get("agent_id")
        or raw_w.get("agent", {}).get("id")
        or "001"
    )

    # Tìm IP nguồn
    src_ip = (
        alert.get("src_ip")
        or details.get("src_ip")
        or raw_w.get("data", {}).get("srcip")
        or "192.168.56.102"
    )

    # Nhãn IP
    prot_res, _ = is_protected_ip(src_ip)
    if prot_res:
        ip_label = "Bạch thư (Whitelist)"
    elif src_ip in ("192.168.56.102", "192.168.56.103"):
        ip_label = "RFC1918"
    elif src_ip and src_ip != "N/A":
        ip_label = "RFC1918"
    else:
        ip_label = None

    target_user = (
        alert.get("user")
        or details.get("user")
        or wazuh.get("dstuser")
        or raw_w.get("data", {}).get("dstuser")
        or "admin"
    )

    event_time = (
        alert.get("first_seen")
        or alert.get("last_seen")
        or raw_w.get("timestamp")
        or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    alert_ref = f"WAZUH-ALT-{rule_id}"

    # MITRE Mapping
    mitre_ids = (
        wazuh.get("mitre_id")
        or raw_w.get("rule", {}).get("mitre", {}).get("id", [])
    )
    mitre_tactics = (
        wazuh.get("mitre_tactic")
        or raw_w.get("rule", {}).get("mitre", {}).get("tactic", [])
    )

    if isinstance(mitre_ids, list) and mitre_ids:
        mitre_id = ", ".join(mitre_ids)
    elif mitre_ids:
        mitre_id = str(mitre_ids)
    elif "571" in rule_id or "brute" in title.lower():
        mitre_id = "T1110"
    elif "540" in rule_id or "sudo" in title.lower():
        mitre_id = "T1548.003"
    else:
        mitre_id = "T1078"

    if isinstance(mitre_tactics, list) and mitre_tactics:
        mitre_tactic = ", ".join(mitre_tactics)
    elif mitre_tactics:
        mitre_tactic = str(mitre_tactics)
    elif "571" in rule_id or "brute" in title.lower():
        mitre_tactic = "Brute Force"
    elif "540" in rule_id or "sudo" in title.lower():
        mitre_tactic = "Sudo Abuse"
    else:
        mitre_tactic = "Initial Access"

    raw_syslog = (
        wazuh.get("full_log")
        or details.get("full_log")
        or raw_w.get("full_log")
        or alert.get("summary", "")
    )

    # Đánh giá trạng thái block & TTL
    blocks = active_blocks if active_blocks is not None else load_active_blocks()
    is_blocked = src_ip in blocks
    blocked_remaining_sec: Optional[int] = None

    if is_blocked:
        b_info = blocks.get(src_ip, {})
        exp_iso = b_info.get("expires_at")
        if exp_iso:
            try:
                exp_dt = datetime.fromisoformat(exp_iso)
                rem = int((exp_dt - datetime.now()).total_seconds())
                blocked_remaining_sec = max(0, rem)
            except Exception:
                blocked_remaining_sec = DEFAULT_BLOCK_TTL_MINUTES * 60
        else:
            blocked_remaining_sec = DEFAULT_BLOCK_TTL_MINUTES * 60

    # Trạng thái tổng quát của Incident
    is_matching_run = (
        current_run is not None
        and (
            current_run.get("alert") == alert
            or current_run.get("alert", {}).get("src_ip") == src_ip
            or current_run.get("alert", {}).get("rule") == alert.get("rule")
        )
    )

    if is_blocked:
        status: IncidentStatus = "APPROVED"
    elif is_matching_run:
        status = "REVIEWED"
    else:
        status = "OPEN"

    # AI Summary
    if is_matching_run:
        conc = current_run.get("conclusion", {})
        ai_summary = conc.get("summary") or f"AI ReAct Agent hoàn tất điều tra cảnh báo {rule_id}. Phán quyết: {conc.get('verdict')}."
    else:
        ai_summary = (
            f"Phát hiện cảnh báo {rule_id}: {title}. "
            f"Nguồn xâm nhập ghi nhận từ địa chỉ IP {src_ip} nhắm vào tài khoản '{target_user}'."
        )

    # Timeline Events
    t_clock = event_time[-8:] if len(event_time) >= 8 else datetime.now().strftime("%H:%M:%S")
    timeline: List[TimelineEvent] = [
        {
            "time": t_clock,
            "description": f"Wazuh tạo alert Rule {rule_id}, mức {level_num or 10} (Critical threshold exceeded)",
            "highlight": f"Rule {rule_id}"
        },
        {
            "time": t_clock,
            "description": "Agent nhận alert qua webhook an toàn có xác thực token",
            "highlight": "Webhook"
        },
        {
            "time": t_clock,
            "description": f"Tra cứu Wazuh archives: phát hiện hoạt động bất thường từ IP {src_ip}",
            "highlight": "Archives"
        }
    ]

    if is_matching_run:
        timeline.append({
            "time": current_run.get("started", "")[-8:] or datetime.now().strftime("%H:%M:%S"),
            "description": f"AI SOC Agent (Ollama Local) hoàn tất phân tích ReAct: {current_run.get('conclusion', {}).get('verdict', 'Hoàn tất')}.",
            "highlight": "AI ReAct"
        })

    if is_blocked:
        timeline.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "description": f"Policy Engine phê duyệt & kích hoạt cô lập UFW trong {DEFAULT_BLOCK_TTL_MINUTES} phút (TTL). Còn lại {blocked_remaining_sec or 900}s.",
            "highlight": "UFW Firewall"
        })

    # Proposed Action
    is_allowed = True
    if policy_decision is not None:
        is_allowed = getattr(policy_decision, "allowed", True)
    elif prot_res:
        is_allowed = False

    proposed_action: ProposedAction = {
        "badge": "Cần phê duyệt" if is_allowed else "Từ chối bởi Policy",
        "description": (
            f"Chặn IP nguồn trên UFW trong {DEFAULT_BLOCK_TTL_MINUTES} phút. Policy đã kiểm tra whitelist và giới hạn tốc độ; cần analyst phê duyệt."
            if is_allowed
            else f"IP {src_ip} thuộc danh sách Bạch thư (Whitelist) bảo vệ, nghiêm cấm cô lập."
        ),
        "checks": [
            f"IP {src_ip} {'không nằm trong' if not prot_res else 'VI PHẠM'} whitelist quản trị",
            "Giới hạn phản ứng: 2 / 5 lần mỗi giờ",
            "Chống Prompt Injection: IP xuất hiện trong dữ liệu cảnh báo",
            f"Cơ chế an toàn: Tự động hết hạn gỡ chặn sau {DEFAULT_BLOCK_TTL_MINUTES} phút (TTL Scheduler)"
        ],
        "primaryBtnText": "⚡ Chặn UFW Ngay",
        "secondaryBtnText": "🔄 Gỡ Chặn / Bỏ Qua"
    }

    return {
        "id": inc_id,
        "title": title,
        "severity": severity,
        "host": host,
        "agentId": agent_id,
        "sourceIp": src_ip,
        "ipLabel": ip_label,
        "targetUser": target_user,
        "time": event_time,
        "ruleId": rule_id,
        "alertRef": alert_ref,
        "mitreId": mitre_id,
        "mitreTactic": mitre_tactic,
        "aiSummary": ai_summary,
        "timeline": timeline,
        "rawSyslog": raw_syslog,
        "proposedAction": proposed_action,
        "status": status,
        "blockedRemainingSeconds": blocked_remaining_sec
    }


# ------------------------------------------------------------------------------
# 5. DANH SÁCH SỰ CỐ MẶC ĐỊNH CHUẨN GIAO DIỆN (UI STITCH PREVIEW INCIDENTS)
# ------------------------------------------------------------------------------
def get_default_incidents() -> List[Incident]:
    """Trả về danh sách sự cố mặc định khớp 100% bản thiết kế giao diện SOC Command Center."""
    return [
        {
            "id": "INC-2026-0042",
            "title": "SSH brute force",
            "severity": "CAO",
            "host": "Ubuntu-Server",
            "agentId": "001",
            "sourceIp": "192.168.56.102",
            "ipLabel": "RFC1918",
            "targetUser": "admin",
            "time": "10:42:18",
            "ruleId": "5712",
            "alertRef": "Wazuh alert 1730972538.081",
            "mitreId": "T1110",
            "mitreTactic": "Brute Force",
            "aiSummary": "Có 9 lần đăng nhập SSH thất bại từ cùng IP trong 2 phút. Truy vấn Wazuh archives không thấy đăng nhập thành công từ IP này trong 24 giờ gần nhất. Cần analyst xem xét trước khi chặn.",
            "timeline": [
                {
                    "time": "10:42:18",
                    "description": "Wazuh tạo alert Rule 5712, mức 10 (Critical threshold exceeded)",
                    "highlight": "Rule 5712"
                },
                {
                    "time": "10:42:19",
                    "description": "Agent nhận alert qua webhook an toàn có xác thực token",
                    "highlight": "Webhook"
                },
                {
                    "time": "10:42:20",
                    "description": "Tra cứu Wazuh archives: 9 thất bại, 0 thành công từ IP trong 24h",
                    "highlight": "Archives"
                }
            ],
            "rawSyslog": "sshd[1234]: Failed password for invalid user admin from 192.168.56.102 port 4440 ssh2",
            "proposedAction": {
                "badge": "Cần phê duyệt",
                "description": "Chặn IP nguồn trên UFW trong 15 phút. Policy đã kiểm tra whitelist và giới hạn tốc độ; cần analyst phê duyệt.",
                "checks": [
                    "IP không nằm trong whitelist quản trị",
                    "Giới hạn phản ứng: 2 / 5 lần mỗi giờ"
                ],
                "primaryBtnText": "🚫 Phê duyệt chặn 15 phút",
                "secondaryBtnText": "Đánh dấu cần xem lại"
            },
            "status": "OPEN",
            "blockedRemainingSeconds": None
        },
        {
            "id": "INC-2026-0041",
            "title": "Sudo bất thường",
            "severity": "TRUNG_BINH",
            "host": "Ubuntu-Server",
            "agentId": "001",
            "sourceIp": "192.168.56.101",
            "ipLabel": "RFC1918",
            "targetUser": "deploy",
            "time": "10:31:07",
            "ruleId": "5402",
            "alertRef": "Wazuh alert 1730971867.054",
            "mitreId": "T1548.003",
            "mitreTactic": "Sudo Abuse",
            "aiSummary": "Tài khoản deploy thực thi lệnh sudo su - không nằm trong quyền hạn sudoers cho phép. Cần kiểm tra phiên SSH.",
            "timeline": [
                {
                    "time": "10:31:00",
                    "description": "User deploy thực thi lệnh nâng quyền root",
                    "highlight": "PAM Sudo"
                },
                {
                    "time": "10:31:07",
                    "description": "Wazuh Rule 5402 phát hiện vi phạm chính sách sudoers",
                    "highlight": "Rule 5402"
                }
            ],
            "rawSyslog": "sudo[6412]: deploy : 1 incorrect password attempt ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/su -",
            "proposedAction": {
                "badge": "Cần xem xét",
                "description": "Thu hồi phiên sudo của tài khoản deploy và yêu cầu xác thực 2FA.",
                "checks": [
                    "Tài khoản deploy là tài khoản dịch vụ CI/CD",
                    "Không có yêu cầu bảo trì đã phê duyệt"
                ],
                "primaryBtnText": "Tạm khóa quyền Sudo",
                "secondaryBtnText": "Bỏ qua cảnh báo"
            },
            "status": "OPEN",
            "blockedRemainingSeconds": None
        },
        {
            "id": "INC-2026-0039",
            "title": "Tệp cấu hình thay đổi",
            "severity": "THAP",
            "host": "Ubuntu-Server",
            "agentId": "001",
            "sourceIp": "/etc/ssh/sshd_config",
            "ipLabel": "FIM File",
            "targetUser": "root",
            "time": "09:58:44",
            "ruleId": "550",
            "alertRef": "Wazuh FIM 1730969924.011",
            "mitreId": "T1565",
            "mitreTactic": "Data Manipulation",
            "aiSummary": "Wazuh FIM phát hiện file /etc/ssh/sshd_config bị sửa đổi mã băm sha256 ngoài khung giờ bảo trì.",
            "timeline": [
                {
                    "time": "09:58:40",
                    "description": "Syscheck phát hiện thay đổi mã băm sha256 của tệp cấu hình",
                    "highlight": "FIM Check"
                },
                {
                    "time": "09:58:44",
                    "description": "Wazuh Rule 550 ghi nhận sự kiện sửa đổi tập tin hệ thống",
                    "highlight": "Rule 550"
                }
            ],
            "rawSyslog": "ossec: File '/etc/ssh/sshd_config' checksum changed from old_sha256 to new_sha256",
            "proposedAction": {
                "badge": "Kiểm toán FIM",
                "description": "So sánh diff tệp sshd_config với bản sao lưu baseline và xác nhận thay đổi.",
                "checks": [
                    "Tệp thuộc danh mục giám sát tính toàn vẹn (FIM)",
                    "Không có tiến trình bất thường chạy nền"
                ],
                "primaryBtnText": "Khôi phục cấu hình",
                "secondaryBtnText": "Chấp thuận thay đổi"
            },
            "status": "OPEN",
            "blockedRemainingSeconds": None
        },
        {
            "id": "INC-2026-0038",
            "title": "Tạo tài khoản lạ ngoài Baseline",
            "severity": "CAO",
            "host": "Ubuntu-Server",
            "agentId": "001",
            "sourceIp": "192.168.56.102",
            "ipLabel": "RFC1918",
            "targetUser": "evil_backdoor",
            "time": "09:41:12",
            "ruleId": "5902",
            "alertRef": "Wazuh alert 1730968872.032",
            "mitreId": "T1136.001",
            "mitreTactic": "Persistence: Create Account",
            "aiSummary": "Tác tử AI phát hiện tài khoản 'evil_backdoor' được khởi tạo và gán vào nhóm sudo (Rule 5902). Đối chiếu file config/baseline.json phát hiện tài khoản nằm ngoài danh mục quản trị viên hợp lệ.",
            "timeline": [
                {
                    "time": "09:41:00",
                    "description": "Tiến trình useradd khởi tạo tài khoản mới: evil_backdoor",
                    "highlight": "useradd"
                },
                {
                    "time": "09:41:12",
                    "description": "Wazuh Rule 5902 phát hiện tài khoản lạ được cấp quyền sudoers",
                    "highlight": "Rule 5902"
                }
            ],
            "rawSyslog": "useradd[14205]: new user: name=evil_backdoor, UID=1003, GID=1003, home=/home/evil_backdoor",
            "proposedAction": {
                "badge": "Cần phản ứng ngay",
                "description": "Thu hồi quyền sudo và khóa tài khoản trái phép evil_backdoor khỏi máy chủ Linux.",
                "checks": [
                    "Tài khoản không có trong baseline.json được phê duyệt",
                    "Phát hiện hành vi Persistence leo thang quyền quản trị"
                ],
                "primaryBtnText": "🚫 Khóa tài khoản evil_backdoor",
                "secondaryBtnText": "Đánh dấu điều tra sâu"
            },
            "status": "OPEN",
            "blockedRemainingSeconds": None
        }
    ]


# ------------------------------------------------------------------------------
# 6. NHẬT KÝ TERMINAL MẶC ĐỊNH (DEFAULT LIVE SOC TERMINAL LOGS)
# ------------------------------------------------------------------------------
DEFAULT_TERMINAL_LOGS = (
    "[10:42:01] [INFO] [Agent-001] ossec: Wazuh Agent daemon running version 4.9.2\n"
    "[10:42:10] [WARN] [Agent-001] sshd[1220]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.102\n"
    "[10:42:15] [WARN] [Agent-001] sshd[1228]: Failed password for invalid user admin from 192.168.56.102 port 4440 ssh2\n"
    "[10:42:18] [CRIT] [Agent-001] Rule 5712 (Level 10): sshd: Multiple SSH authentication failures occurred within 2 mins from IP 192.168.56.102!\n"
    "[10:42:19] [INFO] [Active-Response] Evaluated active-response rules: Script 'firewall-drop' staged for analyst authorization\n"
    "[10:42:20] [ARCHIVE] [Wazuh-Indexer] Historical aggregate check complete: 0 prior successful sessions recorded for hash: e2a8b9..."
)


def get_default_terminal_logs() -> str:
    """Trả về chuỗi log mặc định ban đầu khớp 100% dòng nhật ký trên giao diện thiết kế."""
    return DEFAULT_TERMINAL_LOGS
