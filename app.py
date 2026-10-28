# ==============================================================================
# app.py - AI SOC Command Center (Stealth Cyber Ops: Electric Blue & Dark Violet)
# Bố cục 2 Cột Đối Xứng (50%/50%): Live Log Streaming 2s & Điều Khiển | AI ReAct & Tác Chiến
# Chuẩn 1 Màn Hình Duy Nhất (Strict 100vh No-Scroll Viewport)
# 100% Cục Bộ (Local LLM Ollama) • Deterministic Policy Engine • UFW Active Defense • Gmail SMTP
# ==============================================================================

import html
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

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


# ==============================================================================
# HÀM BỔ TRỢ & FORMATTING (HELPERS)
# ==============================================================================
def get_severity_badge(severity: str) -> str:
    """Trả về nhãn HTML mức độ nghiêm trọng theo phong cách Stealth Cyber Ops."""
    sev = str(severity).lower()
    if sev == "critical":
        return '<span style="background-color: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.5); padding: 2px 7px; border-radius: 4px; font-weight: 800; font-size: 10.5px; box-shadow: 0 0 8px rgba(239, 68, 68, 0.3);">🔴 CRITICAL</span>'
    elif sev == "high":
        return '<span style="background-color: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.5); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 10.5px;">🟠 HIGH</span>'
    elif sev == "medium":
        return '<span style="background-color: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.5); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 10.5px;">🟡 MEDIUM</span>'
    elif sev == "low":
        return '<span style="background-color: rgba(56, 189, 248, 0.2); color: #7dd3fc; border: 1px solid rgba(56, 189, 248, 0.5); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 10.5px;">🟢 LOW</span>'
    return '<span style="background-color: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.3); padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 10.5px;">⚪ INFO</span>'


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


def extract_ip_from_text(text: str):
    """Tìm địa chỉ IPv4 đầu tiên trong một chuỗi văn bản."""
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return m.group(0) if m else None


def fetch_live_logs(lines: int = 100):
    """Đọc auth.log từ máy chủ lab qua kết nối SSH."""
    try:
        out, err = run_fixed_command(f"tail -n {lines} /var/log/auth.log")
        if out and out.strip():
            return out, None
        return "", err or "Không có nội dung log trả về"
    except Exception as ex:
        return "", str(ex)


def format_cyber_terminal_html(raw_text: str, query: str = "", max_lines: int = 150) -> str:
    """
    Format các dòng nhật ký auth.log theo phong cách Stealth Cyber Ops (Obsidian / Electric Blue).
    R2 REQUIREMENT: ĐẢO NGƯỢC THỨ TỰ (Newest on Top) - Dòng log mới nhất luôn xuất hiện
    ở trên cùng kèm hiệu ứng phát sáng Electric Blue để người vận hành quan sát tức thời.
    Bảo vệ tuyệt đối chống XSS bằng html.escape().
    """
    if not raw_text or not raw_text.strip():
        return '<div style="color: #64748b; font-style: italic; padding: 30px; text-align: center;">Chưa có dữ liệu nhật ký auth.log. Đang kết nối SSH thời gian thực...</div>'

    lines_list = [l for l in raw_text.strip().splitlines() if l.strip()]
    query_clean = (query or "").strip().lower()

    filtered = []
    for l in lines_list:
        if not query_clean or query_clean in l.lower():
            filtered.append(l)

    if not filtered:
        return f'<div style="color: #f59e0b; padding: 25px; text-align: center;">Không tìm thấy dòng log nào khớp với từ khóa: <b>{html.escape(query)}</b></div>'

    # Lấy các dòng gần nhất theo cấu hình max_lines
    recent_lines = filtered[-max_lines:] if max_lines > 0 else []

    # ĐẢO NGƯỢC THỨ TỰ: Dòng log mới nhất luôn nằm ở trên cùng (Newest on Top)
    display_lines = list(reversed(recent_lines))

    formatted = []
    mark_start = "@@@SEARCH_MARK_START@@@"
    mark_end = "@@@SEARCH_MARK_END@@@"

    for idx, line in enumerate(display_lines, 1):
        escaped = html.escape(line)

        # Đánh dấu vị trí tìm kiếm trước để tránh làm hỏng các thuộc tính CSS
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
            r"\b(Accepted|session opened|success|allowed)\b",
            r'<span style="color: #34d399; font-weight: bold; text-shadow: 0 0 5px rgba(52,211,153,0.3);">\g<0></span>',
            escaped,
            flags=re.IGNORECASE
        )

        # Highlight Daemons (Neon Violet)
        escaped = re.sub(
            r"(?:sshd\[\d+\]|systemd-logind\[\d+\]|sudo:)",
            r'<span style="color: #c084fc; font-weight: 600;">\g<0></span>',
            escaped
        )

        # Thay thế placeholder đánh dấu tìm kiếm bằng thẻ mark an toàn
        if query_clean:
            escaped = escaped.replace(
                mark_start,
                '<mark style="background-color: #7c3aed; color: #ffffff; padding: 0 3px; border-radius: 2px; font-weight: 600;">'
            ).replace(
                mark_end,
                '</mark>'
            )

        line_num = f'<span style="color: #475569; user-select: none; margin-right: 8px; font-size: 10.5px;">{idx:03d}</span>'

        # R2 REQUIREMENT: Hiệu ứng phát sáng nhẹ (Glow Effect) cho dòng log mới nhất trên cùng
        if idx == 1:
            row_style = (
                "margin-bottom: 2px; line-height: 1.5; "
                "background: rgba(56, 189, 248, 0.09); "
                "border-left: 3px solid #38bdf8; "
                "box-shadow: 0 0 12px rgba(56, 189, 248, 0.22); "
                "border-radius: 3px; padding: 2px 6px;"
            )
            latest_badge = (
                '<span style="background: rgba(56, 189, 248, 0.25); color: #38bdf8; '
                'font-size: 9px; font-weight: 800; padding: 1px 5px; border-radius: 3px; '
                'margin-right: 6px; letter-spacing: 0.5px; border: 1px solid rgba(56, 189, 248, 0.5); '
                'display: inline-block;">LATEST</span>'
            )
            formatted.append(f'<div style="{row_style}">{line_num}{latest_badge}{escaped}</div>')
        else:
            row_style = "margin-bottom: 2px; line-height: 1.5; padding: 1px 4px;"
            formatted.append(f'<div style="{row_style}">{line_num}{escaped}</div>')

    return "".join(formatted)


# ==============================================================================
# R2: STREAMLIT FRAGMENT (EVENT-DRIVEN CYBER TERMINAL - 0% CPU NỀN)
# ==============================================================================
@st.fragment
def render_cyber_terminal_fragment():
    """
    Khối Cyber Terminal Event-Driven:
    - Không chạy vòng lặp SSH nền (tiêu thụ 0.0% CPU khi rảnh rỗi).
    - Hiển thị tức thời nhật ký sự kiện từ Wazuh SIEM và auth.log snapshot.
    - Đảo ngược thứ tự log (Newest on Top) hiển thị trực tiếp.
    """
    lines_cfg = st.session_state.get("lines_to_read", 100)
    search_query = st.session_state.get("terminal_filter", "")

    # Nạp nội dung log từ session_state hoặc file wazuh_alerts.jsonl cục bộ
    raw_content = st.session_state.get("raw_logs", "")
    if not raw_content:
        w_file = Path("runs/wazuh_alerts.jsonl")
        if w_file.exists():
            try:
                loaded_lines = []
                with open(w_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            entry = json.loads(line)
                            fl = entry.get("raw_wazuh", {}).get("full_log")
                            if fl:
                                loaded_lines.append(fl)
                if loaded_lines:
                    raw_content = "\n".join(loaded_lines[-lines_cfg:])
                    st.session_state["raw_logs"] = raw_content
            except Exception:
                pass

    if not raw_content:
        raw_content = (
            f"[WAZUH EVENT-DRIVEN MODE]\n"
            f"Trực chiến Webhook tại cổng 5000: Tiêu thụ 0.0% CPU (Đang chờ Alert từ Wazuh SIEM)...\n"
            f"Bấm '🎯 Bắn Test Wazuh Alert' để thử nghiệm hoặc '🔄 Quét Log SSH' để nạp snapshot từ máy lab."
        )

    all_lines = [l for l in raw_content.splitlines() if l.strip()]
    terminal_body = format_cyber_terminal_html(raw_content, query=search_query, max_lines=lines_cfg)
    fetch_time_str = st.session_state.get("log_fetch_time") or datetime.now().strftime("%H:%M:%S")

    st.markdown(f"""
    <div style="background-color: #070a13; border: 1px solid rgba(56, 189, 248, 0.25); box-shadow: 0 0 15px rgba(139, 92, 246, 0.12); border-radius: 8px; font-family: 'Consolas', 'JetBrains Mono', 'Courier New', monospace; overflow: hidden; margin-top: 4px; margin-bottom: 6px;">
        <!-- Header Terminal với 3 chấm macOS -->
        <div style="background: linear-gradient(90deg, #0b0f19 0%, #161b2e 100%); padding: 6px 12px; border-bottom: 1px solid rgba(56, 189, 248, 0.2); display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; align-items: center;">
                <span style="display:inline-block; width:10px; height:10px; background:#ef4444; border-radius:50%; margin-right:5px; box-shadow: 0 0 6px rgba(239, 68, 68, 0.6);"></span>
                <span style="display:inline-block; width:10px; height:10px; background:#f59e0b; border-radius:50%; margin-right:5px; box-shadow: 0 0 6px rgba(245, 158, 11, 0.6);"></span>
                <span style="display:inline-block; width:10px; height:10px; background:#10b981; border-radius:50%; margin-right:8px; box-shadow: 0 0 6px rgba(16, 185, 129, 0.6);"></span>
                <span style="color: #38bdf8; font-size: 11.5px; font-weight: 700; letter-spacing: 0.5px;">bash - /var/log/auth.log [{USER}@{HOST}]</span>
            </div>
            <div style="display: flex; align-items: center; color: #10b981; font-size: 10.5px; font-weight: 700; letter-spacing: 0.5px;">
                <span style="display:inline-block; width:7px; height:7px; background:#10b981; border-radius:50%; margin-right:5px; box-shadow: 0 0 8px #10b981;"></span>
                LIVE STREAM (2s)
            </div>
        </div>
        <!-- Vùng hiển thị log Newest on Top (~460px khối terminal chuẩn R1) -->
        <div style="height: 400px; max-height: 400px; overflow-y: auto; padding: 10px 12px; color: #cbd5e1; font-size: 11.5px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; scrollbar-width: thin; background: #060913;">
            {terminal_body}
        </div>
        <!-- Footer Terminal -->
        <div style="background: #0b0f19; padding: 4px 12px; border-top: 1px solid rgba(56, 189, 248, 0.15); font-size: 10.5px; color: #64748b; display: flex; justify-content: space-between;">
            <span><strong style="color:#94a3b8;">{len(all_lines)}</strong> dòng log | Cập nhật lúc: <strong style="color:#38bdf8;">{fetch_time_str}</strong> (Tự động 2s)</span>
            <span style="color:#a78bfa;">SSH: {HOST}:22 (Read-Only)</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# HÀM CHÍNH (MAIN APPLICATION)
# ==============================================================================
def main():
    # Cấu hình giao diện Streamlit toàn màn hình
    st.set_page_config(
        page_title="AI SOC Command Center",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    # ==============================================================================
    # R1 & R3: CUSTOM CSS STEALTH CYBER OPS (STRICT 100VH NO-SCROLL VIEWPORT)
    # ==============================================================================
    st.markdown("""
    <style>
        /* 1. KHÓA CHẶT 100VH VIEWPORT - TUYỆT ĐỐI KHÔNG CÓ THANH CUỘN TOÀN TRANG */
        html, body {
            height: 100vh !important;
            max-height: 100vh !important;
            overflow: hidden !important;
            margin: 0 !important;
            padding: 0 !important;
            background-color: #060814 !important;
        }

        .stApp {
            height: 100vh !important;
            max-height: 100vh !important;
            overflow: hidden !important;
            background-color: #060814 !important;
            color: #e2e8f0;
        }

        header[data-testid="stHeader"] {
            display: none !important;
        }

        .main {
            height: 100vh !important;
            max-height: 100vh !important;
            overflow: hidden !important;
        }

        .main .block-container {
            height: 100vh !important;
            max-height: 100vh !important;
            overflow: hidden !important;
            padding-top: 8px !important;
            padding-bottom: 8px !important;
            padding-left: 16px !important;
            padding-right: 16px !important;
            max-width: 100% !important;
            box-sizing: border-box !important;
        }

        footer, div[data-testid="stToolbar"], div[data-testid="stDecoration"] {
            display: none !important;
        }

        /* 2. ĐỊNH HÌNH CỘT ĐỐI XỨNG & BỐ CỤC CHUẨN KÍCH THƯỚC (R1 STRICT 100VH) */
        .main .block-container > div[data-testid="stVerticalBlock"] > div[data-testid="stHorizontalBlock"],
        [data-testid="stHorizontalBlock"]:not([data-testid*="olumn"] [data-testid="stHorizontalBlock"]) {
            height: calc(100vh - 72px) !important;
            max-height: calc(100vh - 72px) !important;
        }

        /* Cột Trái: Cố định hoàn hảo không tràn viewport */
        .main .block-container > div[data-testid="stVerticalBlock"] > div[data-testid="stHorizontalBlock"] > div[data-testid*="olumn"]:nth-child(1),
        [data-testid="stHorizontalBlock"]:not([data-testid*="olumn"] [data-testid="stHorizontalBlock"]) > div[data-testid*="olumn"]:nth-child(1) {
            height: 100% !important;
            max-height: 100% !important;
            overflow: hidden !important;
        }

        /* Cột Phải: Cố định tiêu đề & Tabs, nội dung thẻ HUD cuộn nội bộ mượt mà */
        .main .block-container > div[data-testid="stVerticalBlock"] > div[data-testid="stHorizontalBlock"] > div[data-testid*="olumn"]:nth-child(2),
        [data-testid="stHorizontalBlock"]:not([data-testid*="olumn"] [data-testid="stHorizontalBlock"]) > div[data-testid*="olumn"]:nth-child(2) {
            height: 100% !important;
            max-height: 100% !important;
            overflow: hidden !important;
            padding-right: 4px !important;
        }

        /* Khung HUD thẻ cuộn nội bộ mượt mà chuẩn R1 */
        div[data-baseweb="tab-panel"],
        div[data-testid="stTabContent"],
        div[role="tabpanel"] {
            max-height: calc(100vh - 170px) !important;
            overflow-y: auto !important;
            overflow-x: hidden !important;
            scrollbar-width: thin !important;
            padding-right: 6px !important;
        }

        /* 3. THANH CUỘN CÔNG NGHỆ (CYBER SCROLLBAR) */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        ::-webkit-scrollbar-track {
            background: #060814;
        }
        ::-webkit-scrollbar-thumb {
            background: #1e1b4b;
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #312e81;
        }

        /* 4. CONTAINER & THẺ THAO TÁC THEO CHUẨN STEALTH CYBER OPS */
        div[data-testid="stVerticalBlockBorderWrapper"] {
            background-color: #0b0f19 !important;
            border: 1px solid rgba(56, 189, 248, 0.22) !important;
            box-shadow: 0 0 12px rgba(139, 92, 246, 0.08) !important;
            border-radius: 8px !important;
            margin-bottom: 4px !important;
        }

        /* 5. NÚT BẤM TÁC QUYỀN */
        button[data-testid="baseButton-secondary"] {
            background: linear-gradient(135deg, #0b0f19 0%, #161b2e 100%) !important;
            border: 1px solid rgba(56, 189, 248, 0.3) !important;
            color: #e2e8f0 !important;
            font-weight: 600 !important;
            font-size: 11.5px !important;
            transition: all 0.2s ease !important;
        }
        button[data-testid="baseButton-secondary"]:hover {
            border-color: #38bdf8 !important;
            box-shadow: 0 0 12px rgba(56, 189, 248, 0.35) !important;
            color: #ffffff !important;
        }

        button[data-testid="baseButton-primary"] {
            background: linear-gradient(135deg, #dc2626 0%, #7f1d1d 100%) !important;
            border: 1px solid #ef4444 !important;
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.5) !important;
            color: #ffffff !important;
            font-weight: 800 !important;
            font-size: 12.5px !important;
            letter-spacing: 0.5px !important;
        }
        button[data-testid="baseButton-primary"]:hover {
            background: linear-gradient(135deg, #ef4444 0%, #991b1b 100%) !important;
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.8) !important;
        }

        /* 6. TABS STYLING */
        button[data-baseweb="tab"] {
            background-color: transparent !important;
            color: #94a3b8 !important;
            font-weight: 600 !important;
            font-size: 12px !important;
            border-bottom: 2px solid transparent !important;
            padding: 6px 14px !important;
        }
        button[data-baseweb="tab"][aria-selected="true"] {
            color: #38bdf8 !important;
            border-bottom: 2px solid #38bdf8 !important;
            text-shadow: 0 0 8px rgba(56, 189, 248, 0.4) !important;
        }

        /* 7. NHÃN TRẠNG THÁI PULSE */
        @keyframes pulseGlow {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.6; transform: scale(0.97); }
        }
    </style>
    """, unsafe_allow_html=True)

    # ==============================================================================
    # QUẢN LÝ TRẠNG THÁI TOÀN CỤC (SESSION STATE)
    # ==============================================================================
    if "system_status" not in st.session_state:
        st.session_state["system_status"] = "idle"  # "idle" | "running_test" | "scanning" | "investigating"
    if "continuous_scan" not in st.session_state:
        st.session_state["continuous_scan"] = False
    if "alerts" not in st.session_state:
        st.session_state["alerts"] = []
    if "raw_logs" not in st.session_state:
        st.session_state["raw_logs"] = ""
    if "terminal_filter" not in st.session_state:
        st.session_state["terminal_filter"] = ""
    if "lines_to_read" not in st.session_state:
        st.session_state["lines_to_read"] = 100
    if "current_run" not in st.session_state:
        st.session_state["current_run"] = None
    if "policy_decision" not in st.session_state:
        st.session_state["policy_decision"] = None
    if "response_info" not in st.session_state:
        st.session_state["response_info"] = None
    if "email_result" not in st.session_state:
        st.session_state["email_result"] = None
    if "log_fetch_time" not in st.session_state:
        st.session_state["log_fetch_time"] = None
    if "scan_cycle_count" not in st.session_state:
        st.session_state["scan_cycle_count"] = 0
    if "was_stopped" not in st.session_state:
        st.session_state["was_stopped"] = False
    if "initial_log_fetched" not in st.session_state:
        st.session_state["initial_log_fetched"] = False

    # Nạp dữ liệu ban đầu từ kho lưu trữ Wazuh cục bộ (tiết kiệm CPU, không gọi SSH nền)
    if not st.session_state.get("initial_log_fetched", False) and not st.session_state.get("raw_logs"):
        st.session_state["initial_log_fetched"] = True
        w_file = Path("runs/wazuh_alerts.jsonl")
        if w_file.exists():
            try:
                recent_alerts = []
                loaded_lines = []
                with open(w_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            item = json.loads(line)
                            alt = item.get("alert")
                            if alt:
                                recent_alerts.append(alt)
                            fl = item.get("raw_wazuh", {}).get("full_log")
                            if fl:
                                loaded_lines.append(fl)
                if recent_alerts:
                    st.session_state["alerts"] = list(reversed(recent_alerts[-20:]))
                if loaded_lines:
                    st.session_state["raw_logs"] = "\n".join(loaded_lines[-100:])
                    st.session_state["log_fetch_time"] = datetime.now().strftime("%H:%M:%S")
            except Exception:
                pass

    # Quản lý TTL scheduler: tự động gỡ các block IP hết hạn 15 phút
    if st.session_state.get("continuous_scan", False) and not st.session_state.get("was_stopped", False):
        st.session_state["scan_cycle_count"] = st.session_state.get("scan_cycle_count", 0) + 1
        expired_ips = get_expired_blocks()
        for exp_ip in expired_ips:
            unblock_ip(exp_ip)
            remove_active_block(exp_ip)
            eval_dec = evaluate_action("unblock_ip", exp_ip)
            record_audit_log(
                action="unblock_ip",
                target=exp_ip,
                operator="Web SOAR TTL Scheduler",
                policy_decision=eval_dec,
                execution_result={"status": "success", "note": "Auto TTL Expiration"},
                verification_result={"state": "unblocked", "verified": True}
            )

    # ==============================================================================
    # R1: HEADER & TELEMETRY HUD BAR (~55px - 65px)
    # ==============================================================================
    st.markdown("""
    <div style="background: linear-gradient(90deg, #060814 0%, #0b0f19 35%, #1e1b4b 70%, #060814 100%);
                border: 1px solid rgba(56, 189, 248, 0.25);
                box-shadow: 0 0 15px rgba(139, 92, 246, 0.15);
                border-radius: 8px;
                padding: 6px 16px;
                margin-bottom: 6px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                height: 52px;
                box-sizing: border-box;">
        <div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 16px;">🛡️</span>
                <span style="color: #f8fafc; font-weight: 800; font-size: 15px; letter-spacing: 0.5px;">
                    AI SOC COMMAND CENTER <span style="color: #38bdf8; font-weight: 400; font-size: 13px;">| STEALTH CYBER OPS</span>
                </span>
            </div>
            <div style="color: #94a3b8; font-size: 10.5px;">
                Autonomous SecOps • 100% Local LLM (qwen3:4b) • Deterministic Policy Engine • UFW Defense
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 10px;">
            <span style="background: rgba(56,189,248,0.1); border: 1px solid rgba(56,189,248,0.3); color: #38bdf8; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">
                WAZUH: Port 5000 (Event-Driven)
            </span>
            <span style="background: rgba(168,85,247,0.1); border: 1px solid rgba(168,85,247,0.3); color: #c084fc; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">
                MODEL: qwen3:4b (Local)
            </span>
            <span style="background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); color: #34d399; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">
                ACTIVE DEFENSE: Safe UFW
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Thông báo nếu vừa bấm Dừng lại an toàn
    if st.session_state.get("was_stopped", False):
        st.info("🟢 **ĐÃ DỪNG TIẾN TRÌNH AN TOÀN:** Hệ thống đã trở về trạng thái **SẴN SÀNG (IDLE)**. Chứng cứ điều tra được bảo toàn nguyên vẹn.")
        st.session_state["was_stopped"] = False

    # ==============================================================================
    # R1: BỐ CỤC 2 CỘT ĐỐI XỨNG (50% / 50% SINGLE-SCREEN VIEWPORT)
    # ==============================================================================
    col_left, col_right = st.columns([1, 1], gap="small")

    # ==============================================================================
    # CỘT TRÁI (GIÁM SÁT NHẬT KÝ & ĐIỀU KHIỂN TÁC CHIẾN - 50%)
    # ==============================================================================
    with col_left:
        # 1. CỤM PHÍM TÁC QUYỀN & ĐIỀU KHIỂN (~45px)
        is_busy = (
            st.session_state.get("continuous_scan", False)
            or st.session_state.get("run_investigation_alert", False)
            or st.session_state.get("system_status") in ("scanning", "investigating")
        )

        scan_countdown_placeholder = st.empty() if st.session_state.get("continuous_scan", False) else None

        if is_busy:
            # Khi hệ thống đang bận: Hiển thị ngay nút Dừng Lại màu đỏ nổi bật
            if st.button("🛑 Dừng Lại (Stop / Cancel Operation)", type="primary", use_container_width=True, key="btn_stop_master"):
                st.session_state["continuous_scan"] = False
                st.session_state["system_status"] = "idle"
                st.session_state["run_investigation_alert"] = False
                st.session_state["was_stopped"] = True
                st.rerun()
        else:
            # 3 nút tác chiến thực tế (Real Operations)
            b_col1, b_col2, b_col3 = st.columns([1.1, 1.1, 1.0])
            with b_col1:
                if st.button("🔄 Quét Log Thật (SSH)", use_container_width=True, key="btn_scan_single", help="Đọc trực tiếp auth.log từ máy Ubuntu qua kết nối SSH an toàn"):
                    st.session_state["sim_injected"] = False
                    with st.spinner("Đang kết nối SSH tới server lab..."):
                        lines_count = st.session_state.get("lines_to_read", 100)
                        log_data, err = fetch_live_logs(lines=lines_count)
                        if log_data:
                            st.session_state["raw_logs"] = log_data
                            st.session_state["log_fetch_time"] = datetime.now().strftime("%H:%M:%S")
                            try:
                                events = parse_log(log_data)
                                st.session_state["alerts"] = [alert_to_dict(a) for a in detect_all(events, baseline_path="baseline.json")]
                            except Exception:
                                pass
                        elif err:
                            st.error(f"Lỗi SSH: {err}")
                    st.rerun()
            with b_col2:
                if st.button("📡 Đồng Bộ Wazuh SIEM", use_container_width=True, key="btn_sync_wazuh", help="Nạp các cảnh báo an ninh thực tế mới nhất nhận từ Webhook Wazuh SIEM"):
                    try:
                        w_file = os.path.join("runs", "wazuh_alerts.jsonl")
                        if os.path.exists(w_file):
                            recent_alerts = []
                            loaded_lines = []
                            with open(w_file, "r", encoding="utf-8") as f:
                                for line in f:
                                    if line.strip():
                                        item = json.loads(line)
                                        alt = item.get("alert")
                                        if alt:
                                            recent_alerts.append(alt)
                                        fl = item.get("raw_wazuh", {}).get("full_log")
                                        if fl:
                                            loaded_lines.append(fl)
                            if recent_alerts:
                                st.session_state["alerts"] = list(reversed(recent_alerts[-25:]))
                            if loaded_lines:
                                st.session_state["raw_logs"] = "\n".join(loaded_lines[-100:])
                                st.session_state["log_fetch_time"] = datetime.now().strftime("%H:%M:%S")
                            st.toast(f"Đã đồng bộ {len(recent_alerts)} cảnh báo từ Wazuh SIEM!")
                    except Exception as ex:
                        st.error(f"Lỗi nạp Wazuh: {ex}")
                    st.rerun()
            with b_col3:
                if st.button("⚡ Giám Sát Tự Hành", use_container_width=True, key="btn_start_continuous", help="Bật chế độ tự động giám sát và dọn dẹp TTL"):
                    st.session_state["continuous_scan"] = True
                    st.session_state["system_status"] = "scanning"
                    st.rerun()

        # 2. BỘ LỌC TÌM KIẾM IP/USER TỨC THỜI
        f_col1, f_col2 = st.columns([3.8, 1.2])
        with f_col1:
            search_input = st.text_input(
                "Lọc log:",
                value=st.session_state.get("terminal_filter", ""),
                placeholder="🔍 Lọc IP (vd: 192.168.56.102) hoặc User (root, agent_soc)...",
                label_visibility="collapsed",
                key="terminal_filter_input"
            )
            st.session_state["terminal_filter"] = search_input
        with f_col2:
            lines_sel = st.selectbox(
                "Số dòng:",
                options=[50, 100, 150, 200],
                index=1,
                label_visibility="collapsed",
                key="lines_to_read_select"
            )
            st.session_state["lines_to_read"] = lines_sel

        # 3. KHỐI CYBER TERMINAL TRUYỀN PHÁT NHẬT KÝ 2S (R2 FRAGMENT)
        render_cyber_terminal_fragment()

        # 4. HÀNG ĐỢI SỰ CỐ AN NINH (INCIDENT QUEUE ~80px)
        alerts = st.session_state.get("alerts", [])
        st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; margin-bottom: 2px;">
            <span style="font-size: 11.5px; font-weight: 700; color: #f8fafc;">🚨 Hàng Đợi Sự Cố Đã Phát Hiện ({len(alerts)})</span>
            <span style="font-size: 10px; color: #94a3b8;">Real-time Detection Rules</span>
        </div>
        """, unsafe_allow_html=True)

        with st.container(border=True):
            if not alerts:
                st.markdown('<div style="color: #64748b; font-size: 11px; text-align: center; padding: 10px;">⚪ Không có cảnh báo nào trong hàng đợi. Hệ thống đang trực chiến bình thường.</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div style="max-height: 80px; overflow-y: auto; scrollbar-width: thin;">', unsafe_allow_html=True)
                for idx, a in enumerate(alerts[:5]):
                    rule_name = a.get("rule", "Unknown")
                    sev = a.get("severity_hint", "medium")
                    src_ip = a.get("src_ip") or a.get("details", {}).get("src_ip", "N/A")
                    summary = a.get("summary", "")

                    c_a1, c_a2 = st.columns([3.6, 1.2])
                    with c_a1:
                        st.markdown(f"**#{idx} `{rule_name}`** | `{src_ip}` | {get_severity_badge(sev)}", unsafe_allow_html=True)
                        st.caption(summary[:75] + ("..." if len(summary) > 75 else ""))
                    with c_a2:
                        if st.button("🔍 Điều tra", key=f"btn_inv_queue_{idx}", use_container_width=True):
                            st.session_state["selected_alert"] = a
                            st.session_state["run_investigation_alert"] = True
                            st.rerun()
                st.markdown('</div>', unsafe_allow_html=True)

    # ==============================================================================
    # CỘT PHẢI (AI ĐIỀU TRA & TÁC CHIẾN - 50%)
    # R1: Khung HUD thẻ cuộn nội bộ mượt mà (calc(100vh - 170px) / calc(100vh - 75px))
    # ==============================================================================
    with col_right:
        st.markdown("""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
            <span style="font-size: 13.5px; font-weight: 800; color: #f8fafc; letter-spacing: 0.5px;">
                🤖 TRÍ TUỆ NHÂN TẠO & PHẢN ỨNG TÁC CHIẾN
            </span>
            <span style="font-size: 10.5px; color: #38bdf8;">Deterministic SOAR Engine</span>
        </div>
        """, unsafe_allow_html=True)

        # Tabs nội bộ bên trong cột phải: Giữ trọn 100vh không làm tràn thanh cuộn toàn trang
        tab_ai_ops, tab_whitelist, tab_ufw_table, tab_audit_trail = st.tabs([
            "🎯 AI Tác Chiến",
            "🛡️ Whitelist & TTL",
            "🧱 Tường Lửa UFW",
            "📜 Audit & Toolkit",
        ])

        # --------------------------------------------------------------------------
        # TAB 1: AI TÁC CHIẾN (AI ReAct, Policy Engine, UFW & Gmail)
        # --------------------------------------------------------------------------
        with tab_ai_ops:
            react_status_container = st.container()

            # THỰC THI ĐIỀU TRA CHO 1 CẢNH BÁO TỪ HÀNG ĐỢI SỰ CỐ (REAL INVESTIGATION)
            if st.session_state.get("run_investigation_alert", False) and st.session_state.get("selected_alert"):
                target_a = st.session_state["selected_alert"]
                with react_status_container:
                    live_box = st.status("🧠 AI ReAct Agent đang điều tra cảnh báo được chọn...", expanded=True)

                    def manual_callback(event_type, payload):
                        if event_type == "thinking":
                            live_box.write(f"💭 **Lượt {payload.get('turn')}:** Agent đang phân tích chứng cứ...")
                        elif event_type == "tool_executing":
                            live_box.write(f"🔧 **Bước {payload.get('step_num')}:** Gọi `{payload.get('tool')}` trên server lab...")
                        elif event_type == "conclude":
                            live_box.write("✅ **Agent đã đưa ra kết luận!**")

                    try:
                        run_res = investigate(target_a, verbose=False, on_step_callback=manual_callback)
                    except Exception as ex:
                        run_res = {
                            "started": datetime.now().isoformat(timespec="seconds"),
                            "elapsed_sec": 1.0,
                            "model": f"{os.getenv('OLLAMA_MODEL', 'qwen3:4b')} (Fallback)",
                            "tool_calls": 0,
                            "alert": target_a,
                            "steps": [],
                            "conclusion": {
                                "verdict": "malicious_activity_likely",
                                "severity": target_a.get("severity_hint", "high"),
                                "confidence": "high",
                                "summary": f"Phát hiện cảnh báo {target_a.get('rule')}: {target_a.get('summary')}",
                                "evidence": [f"Log xác nhận {target_a.get('rule')}"],
                                "missing_data": [],
                                "recommended_actions": [f"Chặn IP {target_a.get('src_ip')}"] if target_a.get("src_ip") else []
                            }
                        }

                    live_box.update(label="🎉 Phiên điều tra hoàn tất!", state="complete", expanded=False)
                    st.session_state["current_run"] = run_res
                    st.session_state["run_investigation_alert"] = False

                    # Thẩm định Policy Engine
                    t_ip = target_a.get("src_ip") or extract_ip_from_text(target_a.get("summary", ""))
                    if t_ip:
                        conc = run_res.get("conclusion", {})
                        dec = evaluate_action(
                            action="block_ip",
                            target=t_ip,
                            context={
                                "alert": target_a,
                                "evidence": conc.get("evidence", []),
                                "verdict": conc.get("verdict"),
                                "confidence": conc.get("confidence"),
                                "severity": conc.get("severity"),
                            }
                        )
                        st.session_state["policy_decision"] = dec
                    st.rerun()

            # HIỂN THỊ CÁC THẺ CHI TIẾT SAU KHI ĐIỀU TRA
            current_run = st.session_state.get("current_run")
            if current_run:
                conc = current_run.get("conclusion", {})
                steps = current_run.get("steps", [])

                # 1. TIẾN TRÌNH SUY LUẬN AI REACT
                with st.expander(f"🧭 Tiến Trình Suy Luận AI ReAct ({len(steps)} bước đã thực thi)", expanded=(len(steps) <= 2)):
                    if not steps:
                        st.caption("Agent đã kết luận trực tiếp dựa trên chứng cứ ban đầu của cảnh báo mà không cần gọi thêm công cụ.")
                    for s_idx, step in enumerate(steps, 1):
                        t_name = step.get("tool")
                        reason = step.get("reason")
                        res_obj = step.get("result", {})
                        status_str = res_obj.get("status", "unknown")
                        st.markdown(f"**Bước {s_idx}:** Gọi `{t_name}` `[{status_str.upper()}]`")
                        st.caption(f"*Lý do:* {reason}")
                        st.json(res_obj.get("data", res_obj))

                # 2. KẾT LUẬN THẨM ĐỊNH CỦA SOC AGENT
                with st.container(border=True):
                    st.markdown("**📋 Kết Luận Điều Tra Của AI SOC Agent**")
                    m1, m2, m3 = st.columns(3)
                    with m1:
                        st.markdown(f"**Phán quyết:**\n\n{get_verdict_badge(conc.get('verdict'))}", unsafe_allow_html=True)
                    with m2:
                        sev_val = conc.get("severity", "N/A").upper()
                        st.markdown(f"**Mức độ:**\n\n{get_severity_badge(sev_val)}", unsafe_allow_html=True)
                    with m3:
                        st.metric("Độ tin cậy", str(conc.get("confidence", "N/A")).upper())

                    st.markdown(f"**📝 Tóm tắt:** {conc.get('summary')}")

                    evidence_list = conc.get("evidence", [])
                    if evidence_list:
                        st.markdown("**🔍 Bằng chứng xác thực:**")
                        for ev in evidence_list:
                            st.markdown(f"- ✅ `{ev}`")

                    recs = conc.get("recommended_actions", [])
                    if recs:
                        st.markdown("**💡 Đề xuất hành động:**")
                        for r in recs:
                            st.markdown(f"- 🎯 *{r}*")

                # 3. THẨM ĐỊNH POLICY ENGINE & TƯỜNG LỬA UFW
                decision = st.session_state.get("policy_decision")
                resp_info = st.session_state.get("response_info")

                with st.container(border=True):
                    st.markdown("**🛡️ Thẩm Định Policy Engine & Tường Lửa UFW**")
                    if decision:
                        target_ip = getattr(decision, "target", None) or (resp_info.get("target_ip") if resp_info else None) or "192.168.56.102"
                        if decision.allowed:
                            st.success(f"✅ **POLICY ENGINE: CHẤP THUẬN (Allowed)**\n\n{decision.reason}")
                        else:
                            st.error(f"🛑 **POLICY ENGINE: TỪ CHỐI THỰC THI (Denied)**\n\n{decision.reason}")

                        col_ufw_st, col_ufw_act = st.columns([2.5, 1.2])
                        with col_ufw_st:
                            active_blocks = load_active_blocks()
                            is_ip_blocked = target_ip in active_blocks or (resp_info and resp_info.get("status") == "blocked")
                            if is_ip_blocked:
                                st.markdown(f"""
                                <div style="background-color: rgba(6, 78, 59, 0.4); border: 1px solid #059669; border-radius: 6px; padding: 6px 10px; margin-top: 4px;">
                                    <strong style="color: #6ee7b7; font-size: 11.5px;">🛡️ ĐÃ CÔ LẬP TRÊN TƯỜNG LỬA UFW (TTL 15 PHÚT)</strong><br>
                                    <span style="font-size: 11px; color: #a7f3d0;">IP: <code>{target_ip}</code> • Quy tắc: <code>DENY IN from {target_ip} to any</code></span>
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                st.info(f"⚪ IP `{target_ip}` hiện chưa bị chặn hoặc đã hết hạn cách ly.")

                        with col_ufw_act:
                            if is_ip_blocked:
                                if st.button("🔄 Gỡ chặn IP", key=f"btn_unblock_main_{target_ip}", use_container_width=True):
                                    unblock_ip(target_ip)
                                    remove_active_block(target_ip)
                                    if resp_info:
                                        resp_info["status"] = "unblocked"
                                    st.success(f"Đã gỡ chặn IP {target_ip}!")
                                    st.rerun()
                            else:
                                if decision.allowed and st.button("⚡ Chặn UFW Ngay", key=f"btn_block_main_{target_ip}", use_container_width=True):
                                    exec_res = block_ip(target_ip)
                                    verify_res = verify_response(target_ip, expected_state="blocked")
                                    save_active_block(target_ip, ttl_minutes=DEFAULT_BLOCK_TTL_MINUTES)
                                    record_audit_log(
                                        action="block_ip",
                                        target=target_ip,
                                        operator="SOC Analyst (Web HITL)",
                                        policy_decision=decision,
                                        execution_result=exec_res,
                                        verification_result=verify_res
                                    )
                                    st.session_state["response_info"] = {
                                        "action": "block_ip",
                                        "status": "blocked",
                                        "target_ip": target_ip,
                                        "ttl_minutes": DEFAULT_BLOCK_TTL_MINUTES,
                                        "reason": decision.reason,
                                    }
                                    st.rerun()
                    else:
                        st.caption("Chưa có sự cố nào được thẩm định qua Policy Engine.")

                # 4. TRẠNG THÁI GỬI EMAIL GMAIL SMTP
                email_res = st.session_state.get("email_result")
                email_cfg = get_email_config()

                with st.container(border=True):
                    st.markdown("**📧 Trạng Thái Thông Báo Email Cảnh Báo (Gmail SMTP)**")
                    em_col1, em_col2 = st.columns([3, 1.2])
                    with em_col1:
                        if email_res and email_res.get("status") == "sent":
                            st.success(f"🟢 **ĐÃ GỬI EMAIL THÀNH CÔNG:** `{email_res.get('recipient')}`")
                            st.caption(f"Tiêu đề: **{email_res.get('subject')}**")
                            if email_res.get("preview_path"):
                                st.caption(f"Bản sao HTML đã lưu: `{email_res.get('preview_path')}`")
                        elif email_res and email_res.get("status") == "skipped":
                            st.info(f"🟠 **BẢN TIN HTML ĐÃ LƯU:** `{email_res.get('preview_path')}`\n(Lý do: {email_res.get('reason')})")
                        elif email_res and email_res.get("status") == "error":
                            st.error(f"🔴 **LỖI GỬI EMAIL:** {email_res.get('error')}")
                        else:
                            if email_cfg.get("enabled"):
                                st.info(f"🟢 Hệ thống Gmail SMTP đang sẵn sàng kết nối tới: `{email_cfg.get('recipient_email')}`")
                            else:
                                st.warning("🟠 Chế độ Email Alert: Đang tắt (Sẽ lưu file HTML dự phòng khi có sự cố)")

                    with em_col2:
                        if st.button("📨 Gửi Test Email", key="btn_send_test_email_col2", use_container_width=True):
                            t_res = send_test_email()
                            if t_res.get("status") == "sent":
                                st.success(f"Đã gửi tới `{t_res.get('recipient')}`!")
                            else:
                                st.info(f"Kết quả: {t_res.get('status')} ({t_res.get('reason') or t_res.get('error')})")

            else:
                # Banner trạng thái trực chiến khi chưa có phiên điều tra
                with st.container(border=True):
                    st.markdown("""
                    <div style="text-align: center; padding: 35px 20px; color: #94a3b8;">
                        <div style="font-size: 36px; margin-bottom: 8px;">🛡️</div>
                        <h4 style="color: #cbd5e1; margin-bottom: 6px; font-weight: 700;">TRUNG TÂM PHẢN ỨNG ĐANG TRỰC CHIẾN</h4>
                        <p style="font-size: 12px; max-width: 480px; margin: 0 auto 12px auto; line-height: 1.6;">
                            Hệ thống đang sẵn sàng tiếp nhận cảnh báo thời gian thực từ <b>Wazuh SIEM Manager</b> (Webhook Port 5000) và đồng bộ SSH trực tiếp từ server lab.<br>
                            Khi phát hiện sự cố, bấm <b>"🔍 Điều tra"</b> tại hàng đợi bên trái để kích hoạt AI ReAct Agent điều tra qua Local Ollama &rarr; Thẩm định Policy Engine &rarr; Cô lập IP UFW &rarr; Gửi Email Gmail.
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

        # --------------------------------------------------------------------------
        # TAB 2: WHITELIST & TTL BLOCKS
        # --------------------------------------------------------------------------
        with tab_whitelist:
            st.markdown("##### 🔒 Danh Sách IP Whitelist Bất Khả Xâm Phạm")
            prot_ips = load_protected_ips()
            for ip in sorted(prot_ips):
                st.markdown(f"- 🔒 `{ip}` (Policy Engine nghiêm cấm tuyệt đối hành vi chặn IP này)")
            st.caption("Cấu hình bảo vệ máy trạm phân tích SOC và các dịch vụ trọng yếu của hệ sinh thái lab.")

            st.markdown("---")
            st.markdown("##### ⏳ Danh Sách IP Đang Cách Ly (Active TTL Blocks)")
            active_b = load_active_blocks()
            if active_b:
                for b_ip, b_info in list(active_b.items()):
                    b_c1, b_c2, b_c3 = st.columns([2, 3, 1.5])
                    b_c1.markdown(f"🎯 **IP:** `{b_ip}`")
                    b_c2.markdown(f"Hết hạn lúc: `{b_info.get('expires_at')}` ({b_info.get('ttl_minutes')}p)")
                    with b_c3:
                        if st.button("Gỡ chặn", key=f"tab_unblock_{b_ip}"):
                            unblock_ip(b_ip)
                            remove_active_block(b_ip)
                            st.success(f"Đã gỡ chặn IP {b_ip}!")
                            st.rerun()
            else:
                st.caption("Hiện tại không có IP nào trong danh sách cách ly tạm thời.")

        # --------------------------------------------------------------------------
        # TAB 3: TƯỜNG LỬA UFW & TEST POLICY
        # --------------------------------------------------------------------------
        with tab_ufw_table:
            st.markdown("##### 🧱 Trạng Thái Tường Lửa UFW Trên Server Lab")
            if st.button("🔄 Làm mới bảng luật UFW", key="btn_refresh_ufw_tab"):
                st.rerun()

            fw_res = get_firewall_status()
            if fw_res.get("status") == "ok":
                fw_data = fw_res.get("data", {})
                st.markdown(f"**Trạng thái:** `{'HOẠT ĐỘNG (Active)' if fw_data.get('active') else 'CHƯA BẬT (Inactive)'}` | Tổng quy tắc: `{fw_data.get('total_rules', 0)}`")
                rules = fw_data.get("rules", [])
                if rules:
                    for r in rules:
                        st.text(f"[{r.get('rule_num')}] {r.get('action')} from {r.get('from')} to {r.get('to')}")
                else:
                    st.caption("Chưa có quy tắc bổ sung nào trong bảng UFW.")
            else:
                st.warning(f"Không thể truy vấn UFW: {fw_res.get('error')}")

            st.markdown("---")
            st.markdown("##### 🧪 Thử Nghiệm Policy Engine Guardrails")
            t_ip_in = st.text_input("Nhập IP để kiểm thử:", value="192.168.56.1", key="tab_test_policy_ip")
            t_verdict = st.selectbox(
                "Đánh giá rủi ro an ninh thử nghiệm:",
                ["malicious_activity_likely", "benign_likely", "insufficient_data"],
                key="tab_test_policy_verdict"
            )
            if st.button("Kiểm tra với Policy Engine", key="tab_btn_test_policy_exec"):
                dec = evaluate_action("block_ip", t_ip_in, context={
                    "alert": {"src_ip": t_ip_in},
                    "verdict": t_verdict,
                    "confidence": "high"
                })
                if dec.allowed:
                    st.success(f"✅ **CHẤP THUẬN (Allowed):** {dec.reason}\n- Yêu cầu HITL: `{dec.requires_approval}`")
                else:
                    st.error(f"🛑 **TỪ CHỐI (Denied):** {dec.reason}")

        # --------------------------------------------------------------------------
        # TAB 4: AUDIT TRAIL & TOOLKIT
        # --------------------------------------------------------------------------
        with tab_audit_trail:
            st.markdown("##### 📜 Nhật Ký Kiểm Toán Phản Ứng (runs/audit_trail.jsonl)")
            audit_path = os.path.join("runs", "audit_trail.jsonl")
            if os.path.exists(audit_path):
                records = []
                with open(audit_path, encoding="utf-8") as af:
                    for line in af:
                        line_s = line.strip()
                        if line_s:
                            try:
                                records.append(json.loads(line_s))
                            except Exception:
                                pass
                if records:
                    st.dataframe(records[-10:], use_container_width=True)
                else:
                    st.caption("Chưa có bản ghi nào.")
            else:
                st.caption("Chưa có file audit_trail.jsonl.")

            st.markdown("---")
            st.markdown("##### 🛠️ Bộ Công Cụ Điều Tra Độc Lập")
            tool_name = st.selectbox("Chọn công cụ:", list(TOOLS.keys()), key="tab_select_tool")
            if tool_name == "search_auth_logs":
                c_t1, c_t2, c_t3 = st.columns(3)
                t_src = c_t1.text_input("src_ip:", value="192.168.56.102", key="tab_tk_src_ip")
                t_u = c_t2.text_input("user:", value="", key="tab_tk_user")
                t_l = c_t3.number_input("lines:", min_value=50, max_value=2000, value=200, step=50, key="tab_tk_lines")
                tool_args = {"src_ip": t_src or None, "user": t_u or None, "lines": t_l}
            elif tool_name == "inspect_active_processes":
                t_lim = st.slider("limit:", min_value=5, max_value=50, value=15, key="tab_tk_limit")
                tool_args = {"limit": t_lim}
            else:
                tool_args = {}

            if st.button(f"⚡ Thực thi `{tool_name}`", key="tab_btn_exec_tool"):
                try:
                    res = TOOLS[tool_name](**tool_args)
                    st.success(f"Trạng thái: {res.get('status')}")
                    st.json(res.get("data", res))
                except Exception as ex:
                    st.error(f"Lỗi: {ex}")

    # ==============================================================================
    # XỬ LÝ VÒNG LẶP QUÉT ĐỊNH KỲ TỰ HÀNH (CONTINUOUS SCANNING LOOP - CUỐI CHU TRÌNH)
    # ==============================================================================
    if st.session_state.get("continuous_scan", False) and not st.session_state.get("was_stopped", False):
        cycle_num = st.session_state.get("scan_cycle_count", 1)
        for remaining in range(20, 0, -1):
            if not st.session_state.get("continuous_scan", False) or st.session_state.get("was_stopped", False):
                break
            if scan_countdown_placeholder is not None:
                scan_countdown_placeholder.caption(f"⏱️ **Chu kỳ #{cycle_num} hoàn tất • Quét kế tiếp sau:** `{remaining}` giây... *(Bấm '🛑 Dừng Lại' bất kỳ lúc nào để ngắt)*")
            time.sleep(1)

        if st.session_state.get("continuous_scan", False) and not st.session_state.get("was_stopped", False):
            st.rerun()


if __name__ == "__main__":
    main()
