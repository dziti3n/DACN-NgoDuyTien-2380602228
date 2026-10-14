import json
import os
import sys
from datetime import datetime

import streamlit as st

# Cấu hình trang Streamlit
st.set_page_config(
    page_title="AI SOC Investigation Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Thêm logic import các module SOC
from read_logs import run_fixed_command, HOST, USER
from log_parser import parse_log
from detection import detect_all, alert_to_dict
from agent import investigate
from tools import TOOLS
from llm_client import get_llm_client


# Helper: Badge màu theo mức độ cảnh báo
def get_severity_badge(severity):
    sev = str(severity).lower()
    if sev == "critical":
        return "🔴 **CRITICAL**"
    elif sev == "high":
        return "🟠 **HIGH**"
    elif sev == "medium":
        return "🟡 **MEDIUM**"
    elif sev == "low":
        return "🟢 **LOW**"
    return "⚪ **INFO**"


def get_verdict_badge(verdict):
    v = str(verdict).lower()
    if "malicious" in v:
        return "🚨 **NGUY HIỂM (Malicious Likely)**"
    elif "suspicious" in v:
        return "⚠️ **KHẢ NGHI (Suspicious - Needs Data)**"
    elif "benign" in v:
        return "✅ **LÀNH TÍNH (Benign Likely)**"
    return "❓ **CHƯA ĐỦ DỮ LIỆU (Insufficient Data)**"


# ==========================================
# SIDEBAR: Cấu hình và Quét hệ thống
# ==========================================
st.sidebar.title("🛡️ Cấu hình SOC Agent")

st.sidebar.markdown(f"**Máy chủ Lab:** `{HOST}`")
st.sidebar.markdown(f"**Tài khoản SSH:** `{USER}`")
st.sidebar.markdown(f"**LLM Provider:** `{os.getenv('LLM_PROVIDER', 'gemini').upper()}`")
st.sidebar.markdown(f"**Mô hình chính:** `{os.getenv('LLM_MODEL', 'gemini-3.5-flash-lite')}`")

st.sidebar.markdown("---")
st.sidebar.subheader("⚙️ Quét Log Máy Chủ")
lines_to_scan = st.sidebar.select_slider(
    "Số dòng log auth.log quét:",
    options=[200, 500, 1000, 2000],
    value=1000,
)

if st.sidebar.button("🔄 Quét cảnh báo mới (Scan Now)", use_container_width=True):
    with st.sidebar.status("Đang kết nối SSH và phân tích log..."):
        try:
            out, err = run_fixed_command(f"tail -n {lines_to_scan} /var/log/auth.log")
            if not out.strip() and err:
                st.sidebar.error(f"Lỗi đọc log: {err}")
            else:
                events = parse_log(out)
                alerts = [alert_to_dict(a) for a in detect_all(events, baseline_path="baseline.json")]
                st.session_state["events_count"] = len(events)
                st.session_state["alerts"] = alerts
                st.sidebar.success(f"Quét {len(events)} sự kiện ➔ Phát hiện {len(alerts)} cảnh báo!")
        except Exception as ex:
            st.sidebar.error(f"Lỗi: {ex}")

st.sidebar.markdown("---")
# Xem baseline
with st.sidebar.expander("📋 Xem Baseline Security chuẩn"):
    if os.path.exists("baseline.json"):
        with open("baseline.json", encoding="utf-8") as f:
            st.json(json.load(f))
    else:
        st.write("Chưa có file baseline.json")


# ==========================================
# MAIN PAGE
# ==========================================
st.title("🛡️ Trung Tâm Giám Sát & Điều Tra Tự Động (AI SOC Agent)")
st.caption("Autonomous Security Operations Center Powered by ReAct Agent & Multi-Provider LLMs")

# Tạo 3 Tabs chính
tab1, tab2, tab3 = st.tabs([
    "🚨 Cảnh báo an ninh & Điều tra (Alerts & Investigation)",
    "📊 Lịch sử các ca điều tra (Run History)",
    "🛠️ Bộ công cụ điều tra (Investigation Toolkit)",
])


# ==============================================================================
# TAB 1: CẢNH BÁO AN NINH & ĐIỀU TRA
# ==============================================================================
with tab1:
    if "alerts" not in st.session_state:
        st.info("👋 Bấm nút **'🔄 Quét cảnh báo mới (Scan Now)'** ở thanh bên trái để nạp cảnh báo từ máy chủ lab.")
    else:
        alerts = st.session_state["alerts"]
        st.subheader(f"Danh sách Cảnh báo đã phát hiện ({len(alerts)} sự cố)")

        if not alerts:
            st.success("🎉 Hệ thống an toàn! Không có cảnh báo bất thường nào được phát hiện.")
        else:
            col_left, col_right = st.columns([1, 1.2])

            with col_left:
                st.markdown("#### 📌 Chọn cảnh báo để xem chi tiết:")
                for i, a in enumerate(alerts):
                    rule_name = a.get("rule", "Unknown")
                    sev = a.get("severity_hint", "medium")
                    summary = a.get("summary", "")
                    
                    with st.container(border=True):
                        st.markdown(f"**#{i} - Quy tắc:** `{rule_name}` | {get_severity_badge(sev)}")
                        st.write(summary)
                        if st.button(f"🚀 Kích hoạt Agent điều tra cảnh báo #{i}", key=f"btn_investigate_{i}", use_container_width=True):
                            st.session_state["selected_alert_idx"] = i
                            st.session_state["run_investigation"] = True

            with col_right:
                if "selected_alert_idx" in st.session_state:
                    selected_idx = st.session_state["selected_alert_idx"]
                    current_alert = alerts[selected_idx]

                    st.markdown(f"### 🔍 Chi tiết Cảnh báo #{selected_idx}")
                    st.json(current_alert)

                    if st.session_state.get("run_investigation", False):
                        st.markdown("---")
                        st.markdown("### 🤖 Quá trình Agent điều tra tự động (ReAct Loop)")
                        with st.spinner("Agent đang suy luận, gọi các tools an toàn trên máy chủ và tổng hợp chứng cứ..."):
                            run_result = investigate(current_alert, verbose=False)
                            st.session_state["current_run"] = run_result
                            st.session_state["run_investigation"] = False
                            st.success("Đã hoàn tất điều tra!")

                if "current_run" in st.session_state:
                    run = st.session_state["current_run"]
                    conc = run.get("conclusion", {})

                    st.markdown("#### 🧭 Tiến trình điều tra từng bước:")
                    steps = run.get("steps", [])
                    for s_idx, step in enumerate(steps, 1):
                        tool_name = step.get("tool")
                        reason = step.get("reason")
                        status = step.get("result", {}).get("status", "unknown")
                        
                        with st.expander(f"Bước {s_idx}: Gọi `{tool_name}` (Kết quả: {status})", expanded=True):
                            st.markdown(f"**Lý do suy luận:** *{reason}*")
                            st.markdown(f"**Đối số:** `{json.dumps(step.get('args', {}), ensure_ascii=False)}`")
                            with st.container(border=True):
                                st.json(step.get("result", {}).get("data", step.get("result")))

                    # KẾT LUẬN CUỐI CÙNG
                    st.markdown("---")
                    st.markdown("### 📋 KẾT LUẬN ĐIỀU TRA CỦA SOC AGENT")
                    
                    m_col1, m_col2, m_col3 = st.columns(3)
                    with m_col1:
                        st.metric("Kết luận (Verdict)", conc.get("verdict", "N/A"))
                    with m_col2:
                        st.metric("Mức độ nghiêm trọng", conc.get("severity", "N/A"))
                    with m_col3:
                        st.metric("Độ tin cậy", conc.get("confidence", "N/A"))

                    st.info(f"**Tóm tắt vụ việc:**\n\n{conc.get('summary')}")

                    st.markdown("**Bằng chứng đã xác thực:**")
                    for ev in conc.get("evidence", []):
                        st.markdown(f"- ✅ {ev}")

                    if conc.get("missing_data"):
                        st.markdown("**Dữ liệu còn thiếu / Khuyến nghị thu thập thêm:**")
                        for md in conc.get("missing_data", []):
                            st.markdown(f"- ❓ {md}")

                    st.markdown("**Đề xuất hành động xử lý (Remediation Proposals):**")
                    for act_idx, act in enumerate(conc.get("recommended_actions", [])):
                        c_act1, c_act2 = st.columns([4, 1])
                        with c_act1:
                            st.warning(f"👉 {act}")
                        with c_act2:
                            if st.button("Phê duyệt (HITL)", key=f"hitl_{act_idx}"):
                                st.success("Đã ghi nhận phê duyệt!")

                    st.caption(f"Phiên điều tra hoàn thành trong {run.get('elapsed_sec')}s | Model: {run.get('model')} | Lưu vết: {run.get('saved_to')}")


# ==============================================================================
# TAB 2: LỊCH SỬ CÁC CA ĐIỀU TRA
# ==============================================================================
with tab2:
    st.subheader("📊 Lịch sử các ca điều tra đã lưu vết (Run Logs)")

    runs_dir = "runs"
    if not os.path.exists(runs_dir):
        st.write("Chưa có thư mục runs/")
    else:
        run_files = sorted([f for f in os.listdir(runs_dir) if f.endswith(".json")], reverse=True)
        if not run_files:
            st.info("Chưa có phiên điều tra nào được lưu vết trong runs/")
        else:
            selected_file = st.selectbox("Chọn file log phiên điều tra để xem lại:", run_files)
            if selected_file:
                file_path = os.path.join(runs_dir, selected_file)
                try:
                    with open(file_path, encoding="utf-8") as rf:
                        r_data = json.load(rf)

                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Thời gian bắt đầu", r_data.get("started", "N/A"))
                    c2.metric("Thời gian chạy", f"{r_data.get('elapsed_sec', 'N/A')} s")
                    c3.metric("Số lượt gọi tool", r_data.get("tool_calls", "N/A"))
                    c4.metric("Model LLM", r_data.get("model", "N/A"))

                    c_info = r_data.get("conclusion", {})
                    st.markdown(f"**Kết luận:** {get_verdict_badge(c_info.get('verdict'))} | Mức độ: `{c_info.get('severity')}` | Tin cậy: `{c_info.get('confidence')}`")
                    st.write(f"**Tóm tắt:** {c_info.get('summary')}")

                    with st.expander("Xem chi tiết toàn bộ dữ liệu JSON của phiên:"):
                        st.json(r_data)
                except Exception as ex:
                    st.error(f"Lỗi đọc file: {ex}")


# ==============================================================================
# TAB 3: BỘ CÔNG CỤ ĐIỀU TRA (TEST ĐỘC LẬP)
# ==============================================================================
with tab3:
    st.subheader("🛠️ Kiểm tra độc lập 6 Công cụ Điều tra (Investigation Toolkit)")
    st.caption("Cho phép chuyên viên SOC gọi trực tiếp từng công cụ lên máy chủ lab để kiểm tra kết quả trả về.")

    tool_choice = st.selectbox("Chọn công cụ muốn thực thi:", list(TOOLS.keys()))

    if tool_choice == "search_auth_logs":
        col_t1, col_t2, col_t3 = st.columns(3)
        t_ip = col_t1.text_input("IP Nguồn (src_ip):", value="192.168.56.1")
        t_user = col_t2.text_input("Tài khoản (user):", value="")
        t_lines = col_t3.number_input("Số dòng quét:", min_value=100, max_value=2000, value=500, step=100)
        args = {"src_ip": t_ip or None, "user": t_user or None, "lines": t_lines}

    elif tool_choice == "inspect_active_processes":
        t_limit = st.slider("Giới hạn số tiến trình hàng đầu (CPU):", min_value=5, max_value=50, value=15)
        args = {"limit": t_limit}

    else:
        args = {}
        st.write("Công cụ này không cần đối số bổ sung.")

    if st.button(f"⚡ Thực thi `{tool_choice}`"):
        with st.spinner("Đang chạy lệnh an toàn qua SSH..."):
            try:
                res = TOOLS[tool_choice](**args)
                st.success(f"Trạng thái: {res.get('status')}")
                st.json(res.get("data", res))
            except Exception as ex:
                st.error(f"Lỗi thực thi: {ex}")

