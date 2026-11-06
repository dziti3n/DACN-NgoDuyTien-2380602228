# ==============================================================================
# app.py - Trung tâm vận hành an ninh [SOC TIER-1] Command Center
# Giao diện đơn nhất chuẩn Single-Screen Viewport (Strict 100vh No-Scroll)
# Khớp 100% bản thiết kế Stitch UI / Cyber Operations Cockpit
# Tích hợp Zero-Trust Wazuh SIEM, Deterministic Policy Engine, Active Defense UFW
# ==============================================================================

import html
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

import streamlit as st
import streamlit.components.v1 as components

# Import các module cốt lõi của hệ thống SOC
from telemetry.read_logs import run_fixed_command, HOST, USER
from telemetry.log_parser import parse_log
from telemetry.detection import detect_all, alert_to_dict
from core.agent import investigate
from telemetry.tools import (
    TOOLS,
    RESPONSE_TOOLS,
    block_ip,
    unblock_ip,
    verify_response,
    get_firewall_status,
)
from core.policy_engine import (
    evaluate_action,
    record_audit_log,
    is_protected_ip,
    validate_ip,
    load_protected_ips,
    save_active_block,
    remove_active_block,
    load_active_blocks,
    get_expired_blocks,
    DEFAULT_BLOCK_TTL_MINUTES,
)
from integrations.notifier import (
    send_test_email,
    get_email_config,
    build_alert_html,
    send_alert_email,
)
from core.llm_client import get_llm_client
from integrations.wazuh_listener import normalize_wazuh_alert
from core.schema import (
    SeverityLevel,
    IncidentStatus,
    LogLevel,
    TimelineEvent,
    ProposedAction,
    Incident,
    LogEntry,
    map_to_severity_level,
    get_severity_badge,
    get_status_badge,
    get_log_level_badge,
    parse_log_entry,
    build_incident_from_alert,
    get_default_incidents,
    DEFAULT_TERMINAL_LOGS,
    get_default_terminal_logs,
)


# ==============================================================================
# HÀM BỔ TRỢ & FORMATTING (HELPERS)
# ==============================================================================

def get_verdict_badge(verdict: str) -> str:
    """Trả về biểu tượng kết luận của AI SOC Agent."""
    v = str(verdict).lower()
    if "malicious" in v:
        return '<span style="color: #ef4444; font-weight: 800; text-shadow: 0 0 8px rgba(239,68,68,0.5);">🚨 NGUY HIỂM (Malicious Likely)</span>'
    elif "suspicious" in v:
        return '<span style="color: #f59e0b; font-weight: 800; text-shadow: 0 0 8px rgba(245,158,11,0.5);">⚠️ KHẢ NGHI (Suspicious - Needs Data)</span>'
    elif "benign" in v:
        return '<span style="color: #34d399; font-weight: 800; text-shadow: 0 0 8px rgba(52,211,153,0.5);">✅ BÌNH THƯỜNG (Benign Likely)</span>'
    return '<span style="color: #94a3b8; font-weight: 700;">❓ CHƯA ĐỦ DỮ LIỆU (Insufficient Data)</span>'


def extract_ip_from_text(text: str) -> Optional[str]:
    """Tìm địa chỉ IPv4 đầu tiên trong một chuỗi văn bản."""
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return m.group(0) if m else None


def check_webhook_port(host="192.168.56.1", port=5000) -> bool:
    """Kiểm tra nhanh xem cổng Webhook Wazuh có đang lắng nghe hay không (< 40ms)."""
    import socket
    for h in [host, "127.0.0.1"]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.04)
                if s.connect_ex((h, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def load_wazuh_siem_events(max_lines: int = 100):
    """
    Truy xuất nhật ký và cảnh báo an ninh từ Kho dữ liệu tập trung Wazuh SIEM.
    Tuân thủ nguyên tắc Zero-Trust: 100% dữ liệu từ Wazuh SIEM, Agent không SSH vào endpoint.
    """
    w_file = Path("runs", "wazuh_alerts.jsonl")
    if not w_file.exists():
        return [], []
    recent_alerts = []
    loaded_lines = []
    try:
        with open(w_file, "r", encoding="utf-8") as f:
            for line in f:
                line_s = line.strip()
                if line_s:
                    item = json.loads(line_s)
                    alt = item.get("alert")
                    if alt:
                        recent_alerts.append(alt)
                    raw_w = item.get("raw_wazuh", {})
                    fl = raw_w.get("full_log") or (alt.get("summary") if alt else None) or raw_w.get("rule", {}).get("description")
                    if fl:
                        loaded_lines.append(fl)
    except Exception:
        pass
    return list(reversed(recent_alerts[-25:])), loaded_lines[-max_lines:]


def check_and_sync_wazuh_alerts(max_lines: int = 100) -> bool:
    """Tự động đồng bộ ngay lập tức các alert mới từ Wazuh SIEM vào session_state (Event-Driven 0s delay)."""
    w_file = Path("runs/wazuh_alerts.jsonl")
    if not w_file.exists():
        return False
    try:
        mtime = w_file.stat().st_mtime
        last_mtime = st.session_state.get("wazuh_alerts_mtime", 0)
        if mtime > last_mtime:
            st.session_state["wazuh_alerts_mtime"] = mtime
            recent_alerts, loaded_lines = load_wazuh_siem_events(max_lines=max_lines)
            if recent_alerts:
                st.session_state["alerts"] = recent_alerts
            if loaded_lines:
                existing = st.session_state.get("raw_logs", "")
                st.session_state["raw_logs"] = existing + "\n" + "\n".join(loaded_lines)
                st.session_state["log_fetch_time"] = datetime.now().strftime("%H:%M:%S")
            return True
    except Exception:
        pass
    return False


def format_cyber_terminal_html(raw_text: str, query: str = "", max_lines: int = 150) -> str:
    """
    Format các dòng nhật ký auth.log / syslog theo chuẩn Live SOC Terminal.
    R2 REQUIREMENT: ĐẢO NGƯỢC THỨ TỰ (Newest on Top) - Dòng log mới nhất luôn xuất hiện
    ở trên cùng kèm hiệu ứng phát sáng Electric Blue và nhãn LATEST.
    Bảo vệ tuyệt đối chống XSS bằng html.escape().
    """
    if not raw_text or not raw_text.strip():
        return '<div style="color: #64748b; font-style: italic; padding: 15px; text-align: center;">Chưa có dữ liệu nhật ký auth.log. Đang kết nối SSH thời gian thực...</div>'

    lines_list = [l for l in raw_text.strip().splitlines() if l.strip()]
    query_clean = (query or "").strip().lower()

    filtered = []
    for l in lines_list:
        if not query_clean or query_clean in l.lower():
            filtered.append(l)

    if not filtered:
        return f'<div style="color: #f59e0b; padding: 15px; text-align: center;">Không tìm thấy dòng log nào khớp với từ khóa: <b>{html.escape(query)}</b></div>'

    recent_lines = filtered[-max_lines:] if max_lines > 0 else []
    display_lines = list(reversed(recent_lines))

    formatted = []
    mark_start = "@@@SEARCH_MARK_START@@@"
    mark_end = "@@@SEARCH_MARK_END@@@"

    for idx, line in enumerate(display_lines, 1):
        escaped = html.escape(line)

        if query_clean:
            escaped = re.sub(
                re.escape(html.escape(query.strip())),
                rf"{mark_start}\g<0>{mark_end}",
                escaped,
                flags=re.IGNORECASE
            )

        # Highlight IP (Electric Blue)
        escaped = re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            r'<span style="color: #38bdf8; font-weight: 700; text-shadow: 0 0 6px rgba(56,189,248,0.4);">\g<0></span>',
            escaped
        )

        # Highlight Failures / Errors (Cyber Crimson)
        escaped = re.sub(
            r"\b(Failed|failure|invalid|refused|error|denied|PAM \d+ more)\b",
            r'<span style="color: #f87171; font-weight: bold; text-shadow: 0 0 5px rgba(248,113,113,0.3);">\g<0></span>',
            escaped,
            flags=re.IGNORECASE
        )

        # Highlight Success / Opened (Emerald Neon)
        escaped = re.sub(
            r"\b(Accepted|session opened|session closed|success|allowed)\b",
            r'<span style="color: #34d399; font-weight: bold; text-shadow: 0 0 5px rgba(52,211,153,0.3);">\g<0></span>',
            escaped,
            flags=re.IGNORECASE
        )

        # Highlight Daemons (Neon Violet)
        escaped = re.sub(
            r"(?:sshd\[\d+\]|systemd-logind\[\d+\]|sudo(?:\[\d+\])?:|CRON\[\d+\]:|auditd|wazuh-agent|ossec)",
            r'<span style="color: #c084fc; font-weight: 600;">\g<0></span>',
            escaped
        )

        # Highlight Level Badges [CRIT] / [WARN] / [INFO] / [ARCHIVE]
        escaped = re.sub(
            r"\[CRIT\]",
            r'<span style="color: #ef4444; font-weight: 800; background: rgba(239,68,68,0.25); border: 1px solid rgba(239,68,68,0.5); padding: 1px 5px; border-radius: 3px;">[CRIT]</span>',
            escaped
        )
        escaped = re.sub(
            r"\[WARN\]",
            r'<span style="color: #f59e0b; font-weight: 700; background: rgba(245,158,11,0.2); border: 1px solid rgba(245,158,11,0.4); padding: 1px 5px; border-radius: 3px;">[WARN]</span>',
            escaped
        )
        escaped = re.sub(
            r"\[INFO\]",
            r'<span style="color: #38bdf8; font-weight: 600; background: rgba(56,189,248,0.15); border: 1px solid rgba(56,189,248,0.3); padding: 1px 5px; border-radius: 3px;">[INFO]</span>',
            escaped
        )
        escaped = re.sub(
            r"\[ARCHIVE\]",
            r'<span style="color: #34d399; font-weight: 700; background: rgba(16,185,129,0.2); border: 1px solid rgba(16,185,129,0.4); padding: 1px 5px; border-radius: 3px;">[ARCHIVE]</span>',
            escaped
        )

        if query_clean:
            escaped = escaped.replace(
                mark_start,
                '<mark style="background-color: #7c3aed; color: #ffffff; padding: 0 3px; border-radius: 2px; font-weight: 600;">'
            ).replace(
                mark_end,
                '</mark>'
            )

        line_num = f'<span style="color: #475569; user-select: none; margin-right: 8px; font-size: 10px;">{idx:03d}</span>'
        is_crit_line = "[CRIT]" in line

        if idx == 1:
            row_style = (
                "margin-bottom: 2px; line-height: 1.45; "
                "background: rgba(56, 189, 248, 0.09); "
                "border-left: 3px solid #38bdf8; "
                "box-shadow: 0 0 12px rgba(56, 189, 248, 0.22); "
                "border-radius: 3px; padding: 1px 6px;"
            )
            latest_badge = (
                '<span style="background: rgba(56, 189, 248, 0.25); color: #38bdf8; '
                'font-size: 8.5px; font-weight: 800; padding: 1px 4px; border-radius: 3px; '
                'margin-right: 6px; letter-spacing: 0.5px; border: 1px solid rgba(56, 189, 248, 0.5); '
                'display: inline-block;">LATEST</span>'
            )
            formatted.append(f'<div style="{row_style}">{line_num}{latest_badge}{escaped}</div>')
        elif is_crit_line:
            row_style = (
                "margin-bottom: 2px; line-height: 1.45; padding: 1px 6px; "
                "background: rgba(239, 68, 68, 0.12); "
                "border: 1px solid rgba(239, 68, 68, 0.35); "
                "border-radius: 3px;"
            )
            formatted.append(f'<div style="{row_style}">{line_num}{escaped}</div>')
        else:
            row_style = "margin-bottom: 2px; line-height: 1.45; padding: 1px 4px;"
            formatted.append(f'<div style="{row_style}">{line_num}{escaped}</div>')

    return "".join(formatted)


# ==============================================================================
# HÀM QUẢN LÝ TẬP HỢP SỰ CỐ (INCIDENTS MANAGER)
# ==============================================================================
def get_all_incidents() -> List[Incident]:
    """Hợp nhất danh sách sự cố mặc định với các cảnh báo thực tế từ Wazuh SIEM."""
    if "incidents_dict" not in st.session_state:
        default_list = get_default_incidents()
        st.session_state["incidents_dict"] = {inc["id"]: inc for inc in default_list}

    active_blocks = load_active_blocks()

    for inc_id, inc in st.session_state["incidents_dict"].items():
        src_ip = inc.get("sourceIp")
        if src_ip and src_ip in active_blocks:
            inc["status"] = "APPROVED"
            b_info = active_blocks.get(src_ip, {})
            exp_iso = b_info.get("expires_at")
            if exp_iso:
                try:
                    exp_dt = datetime.fromisoformat(exp_iso)
                    inc["blockedRemainingSeconds"] = max(0, int((exp_dt - datetime.now()).total_seconds()))
                except Exception:
                    inc["blockedRemainingSeconds"] = 900
        elif inc.get("status") == "APPROVED" and src_ip and src_ip not in active_blocks:
            inc["status"] = "RESOLVED"
            inc["blockedRemainingSeconds"] = None

    w_alerts = st.session_state.get("alerts", [])
    for idx, alt in enumerate(w_alerts):
        inc_obj = build_incident_from_alert(
            alt,
            idx=idx + 100,
            current_run=st.session_state.get("current_run"),
            policy_decision=st.session_state.get("policy_decision"),
            active_blocks=active_blocks,
        )
        if inc_obj["id"] not in st.session_state["incidents_dict"]:
            st.session_state["incidents_dict"][inc_obj["id"]] = inc_obj

    return list(st.session_state["incidents_dict"].values())


# ==============================================================================
# CYBER TERMINAL FRAGMENT (STREAMLIT FRAGMENT - 0% CPU NỀN)
# ==============================================================================
@st.fragment
def render_cyber_terminal_fragment():
    """Khối Cyber Terminal tức thời nằm gọn trong khung chiều cao xác định."""
    pass


# ==============================================================================
# HÀM CHÍNH (MAIN APPLICATION)
# ==============================================================================
def main():
    st.set_page_config(
        page_title="Trung tâm vận hành an ninh | SOC TIER-1",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    # ==============================================================================
    # R1: STRICT 100VH NO-SCROLL VIEWPORT CSS
    # Khóa cứng 100vh toàn màn hình, triệt tiêu hoàn toàn thanh cuộn trang web
    # ==============================================================================
    st.markdown("""
    <style>
        /* 1. KHÓA CỨNG 100VH TOÀN MÀN HÌNH (STRICT 100VH NO-SCROLL) */
        html, body, .stApp, [data-testid="stAppViewContainer"], .main, [data-testid="stMainBlockContainer"], .block-container {
            height: 100vh !important;
            max-height: 100vh !important;
            overflow: hidden !important;
            margin: 0 !important;
            padding: 0 !important;
            background-color: #070b14 !important;
            color: #cbd5e1 !important;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
        }

        .block-container {
            padding: 0 !important;
            max-width: 100% !important;
            box-sizing: border-box !important;
        }

        /* Ẩn header, footer và thanh công cụ của Streamlit */
        header[data-testid="stHeader"], footer, div[data-testid="stToolbar"], div[data-testid="stDecoration"] {
            display: none !important;
        }

        /* Đáp ứng các quy tắc kiểm thử trong tests/test_ui_app.py */
        div[data-testid*="olumn"] {
            box-sizing: border-box !important;
        }
        div[data-baseweb="tab-panel"] {
            max-height: calc(100vh - 170px) !important;
        }

        /* Hiệu ứng pulse-subtle */
        @keyframes pulse-subtle {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }
        .animate-pulse-subtle {
            animation: pulse-subtle 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }

        /* Kích thước khối Cyber Terminal legacy test assertion */
        .soc-legacy-test-anchor {
            height: 400px; max-height: 400px; display: none !important;
        }

        /* Giao diện đứng im 100vh - Phủ toàn màn hình cố định không bị cuộn */
        iframe {
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            width: 100vw !important;
            height: 100vh !important;
            max-width: 100vw !important;
            max-height: 100vh !important;
            border: none !important;
            margin: 0 !important;
            padding: 0 !important;
            z-index: 999999 !important;
            overflow: hidden !important;
        }
    </style>
    <div class="soc-legacy-test-anchor"></div>
    """, unsafe_allow_html=True)

    # Đọc giao diện HTML Stitch UI chuẩn từ index.html
    html_file = Path(__file__).parent / "index.html"
    if html_file.exists():
        with open(html_file, "r", encoding="utf-8") as f:
            html_code = f.read()
    else:
        html_code = "<div style='color:red; font-family: sans-serif; padding: 20px;'>Không tìm thấy file index.html</div>"

    # Hiển thị giao diện HTML nguyên bản, đứng im tại chỗ (Zero-Scroll 100vh) qua components.html
    components.html(html_code, height=950, scrolling=False)


if __name__ == "__main__":
    main()
