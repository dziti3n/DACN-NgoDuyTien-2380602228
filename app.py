import json
import os
import re
import sys
from datetime import datetime

import streamlit as st

# Cấu hình trang Streamlit
st.set_page_config(
    page_title="AI SOC Investigation & Defense Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Thêm logic import các module SOC
from read_logs import run_fixed_command, HOST, USER
from log_parser import parse_log
from detection import detect_all, alert_to_dict
from agent import investigate
from tools import (
    TOOLS,
    RESPONSE_TOOLS,
    block_ip,
    unblock_ip,
    verify_response,
    get_firewall_status,
)
from policy_engine import (
    evaluate_action,
    record_audit_log,
    is_protected_ip,
    validate_ip,
    load_protected_ips,
)
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
        return "✅ **BÌNH THƯỜNG (Benign Likely)**"
    return "❓ **CHƯA ĐỦ DỮ LIỆU (Insufficient Data)**"


def extract_ip_from_text(text):
    """Tìm địa chỉ IPv4 đầu tiên trong một chuỗi văn bản."""
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return m.group(0) if m else None


# ==========================================
# SIDEBAR
# ==========================================
st.sidebar.title("🛡️ SOC Control Panel")
st.sidebar.markdown(f"**Target Host:** `{HOST}`")
st.sidebar.markdown(f"**SSH User:** `{USER}`")

# Trạng thái mô hình LLM Cục bộ
st.sidebar.markdown("---")
st.sidebar.markdown("### 🧠 Mô hình AI Cục bộ (Ollama)")
st.sidebar.success("⚡ **Chế độ: 100% Cục bộ (Local Air-Gapped)**")
st.sidebar.info(f"Model: `{os.getenv('OLLAMA_MODEL', 'qwen3:4b')}`\n\nEndpoint: `127.0.0.1:11434`\n\nSeed: `42` (Deterministic)")

# Whitelist IP bảo vệ
st.sidebar.markdown("---")
with st.sidebar.expander("🛡️ Danh sách IP Bảo vệ (Whitelist)"):
    prot_ips = load_protected_ips()
    for ip in sorted(prot_ips):
        st.markdown(f"- 🔒 `{ip}`")
    st.caption("Policy Engine cấm tuyệt đối hành động chặn các IP này.")

# Điều khiển quét log
st.sidebar.markdown("---")
lines_to_scan = st.sidebar.number_input("Số dòng log auth.log cần quét:", min_value=100, max_value=5000, value=1000, step=100)
if st.sidebar.button("🔄 Quét cảnh báo mới (Scan Now)", use_container_width=True):
    with st.spinner(f"Đang đọc log từ {HOST}..."):
        try:
            out, err = run_fixed_command(f"tail -n {lines_to_scan} /var/log/auth.log")
            if not out.strip() and err:
                st.sidebar.error(f"Lỗi: {err}")
            else:
                events = parse_log(out)
                alerts = [alert_to_dict(a) for a in detect_all(events, baseline_path="baseline.json")]
                st.session_state["alerts"] = alerts
                st.session_state.pop("current_run", None)
                st.sidebar.success(f"Đã phát hiện {len(alerts)} cảnh báo!")
        except Exception as ex:
            st.sidebar.error(f"Lỗi kết nối SSH: {ex}")

with st.sidebar.expander("📋 Xem Baseline Security chuẩn"):
    if os.path.exists("baseline.json"):
        with open("baseline.json", encoding="utf-8") as f:
            st.json(json.load(f))
    else:
        st.write("Chưa có file baseline.json")


# ==========================================
# MAIN PAGE
# ==========================================
st.title("🛡️ Trung Tâm Giám Sát, Điều Tra & Phản Ứng (AI SOC Agent)")
st.caption("Autonomous Security Operations Center • Local LLM • Deterministic Policy Engine • Human-in-the-Loop")

# 4 Tabs chính
tab1, tab2, tab3, tab4 = st.tabs([
    "🚨 Cảnh báo & Điều tra (Alerts & Investigation)",
    "📊 Lịch sử các ca điều tra (Run History)",
    "🛠️ Bộ công cụ điều tra (Investigation Toolkit)",
    "🛡️ Phản ứng có kiểm soát & Tường lửa (Active Defense)",
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
                        st.markdown("### 🤖 Tiến trình Agent điều tra trực tiếp (Live ReAct Loop)")
                        
                        live_status = st.status("🧠 Agent đang khởi động phiên điều tra qua Ollama cục bộ...", expanded=True)
                        
                        def ui_callback(event_type, payload):
                            if event_type == "thinking":
                                live_status.write(f"💭 **Lượt {payload.get('turn')}:** Agent đang phân tích chứng cứ bằng Ollama local...")
                            elif event_type == "tool_executing":
                                live_status.write(f"🔧 **Bước {payload.get('step_num')}:** Thực thi công cụ `{payload.get('tool')}` trên server lab qua SSH...")
                                live_status.caption(f"Mục đích: *{payload.get('reason')}*")
                            elif event_type == "tool_done":
                                live_status.write(f"📊 Đã nhận chứng cứ từ `{payload.get('tool')}` (Trạng thái: `{payload.get('status')}`)")
                            elif event_type == "conclude":
                                live_status.write("✅ **Agent đã tổng hợp xong chứng cứ và đưa ra kết luận!**")
                            elif event_type == "error":
                                live_status.error(f"Lỗi: {payload.get('error')}")

                        run_result = investigate(current_alert, verbose=False, on_step_callback=ui_callback)
                        live_status.update(label="🎉 Phiên điều tra hoàn tất!", state="complete", expanded=False)
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
                        
                        with st.expander(f"Bước {s_idx}: Gọi `{tool_name}` (Kết quả: {status})", expanded=False):
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

                    # ==========================================================
                    # LỚP PHẢN ỨNG CÓ KIỂM SOÁT & POLICY ENGINE (HITL)
                    # ==========================================================
                    st.markdown("---")
                    st.markdown("### 🛡️ Đề xuất xử lý & Thẩm định Policy Engine (HITL)")
                    st.caption("Mọi hành động phản ứng trên hệ thống mạng đều phải được Policy Engine thẩm định an toàn và được chuyên viên SOC phê duyệt.")

                    recs = conc.get("recommended_actions", [])
                    if not recs:
                        st.write("Không có đề xuất hành động cụ thể.")
                    
                    for act_idx, act in enumerate(recs):
                        with st.container(border=True):
                            st.markdown(f"**Hành động đề xuất #{act_idx + 1}:** {act}")
                            
                            # Tìm IP mục tiêu từ văn bản đề xuất hoặc từ alert
                            target_ip = extract_ip_from_text(act) or current_alert.get("src_ip")
                            is_block_proposal = any(k in act.lower() for k in ["chặn", "block", "ufw", "cấm"])
                            
                            if is_block_proposal and target_ip:
                                st.markdown(f"🎯 **Đối tượng IP mục tiêu:** `{target_ip}`")
                                
                                # Thẩm định an toàn qua Policy Engine
                                decision = evaluate_action(
                                    action="block_ip",
                                    target=target_ip,
                                    context={
                                        "verdict": conc.get("verdict"),
                                        "confidence": conc.get("confidence"),
                                        "severity": conc.get("severity"),
                                    }
                                )
                                
                                if not decision.allowed:
                                    # Trường hợp Policy Engine ngăn chặn (ví dụ: Whitelist IP máy host)
                                    st.error(f"🛑 **POLICY ENGINE TỪ CHỐI THỰC THI:**\n\n{decision.reason}")
                                    st.button(
                                        "❌ Đã bị khóa bởi Policy Engine (Cấm Chặn)",
                                        key=f"hitl_disabled_{act_idx}",
                                        disabled=True
                                    )
                                else:
                                    # Trường hợp Policy Engine chấp thuận nhưng yêu cầu HITL
                                    st.warning(f"⚠️ **POLICY ENGINE:** {decision.reason}")
                                    
                                    col_btn1, col_btn2 = st.columns([1, 1])
                                    with col_btn1:
                                        if st.button(f"✅ Phê duyệt & Chặn IP `{target_ip}` (HITL)", key=f"hitl_exec_{act_idx}"):
                                            with st.spinner(f"Đang thực thi lệnh chặn UFW và xác minh trên {HOST}..."):
                                                exec_res = block_ip(target_ip)
                                                verify_res = verify_response(target_ip, expected_state="blocked")
                                                record_audit_log(
                                                    action="block_ip",
                                                    target=target_ip,
                                                    operator="SOC Analyst (Web HITL)",
                                                    policy_decision=decision,
                                                    execution_result=exec_res,
                                                    verification_result=verify_res
                                                )
                                                if exec_res.get("status") == "ok":
                                                    st.session_state[f"blocked_status_{target_ip}"] = True
                                                    st.success(f"🎉 {verify_res.get('data', {}).get('message', 'Đã chặn IP thành công!')}")
                                                else:
                                                    st.error(f"Lỗi thực thi UFW: {exec_res.get('error')}")

                                    with col_btn2:
                                        if st.session_state.get(f"blocked_status_{target_ip}", False):
                                            if st.button(f"🔄 Hoàn tác (Gỡ chặn `{target_ip}`)", key=f"hitl_unblock_{act_idx}"):
                                                with st.spinner(f"Đang gỡ bỏ quy tắc chặn trên {HOST}..."):
                                                    unblock_res = unblock_ip(target_ip)
                                                    v_unblock = verify_response(target_ip, expected_state="unblocked")
                                                    st.session_state[f"blocked_status_{target_ip}"] = False
                                                    st.info(f"Đã gỡ chặn IP {target_ip}!")
                            else:
                                # Hành động đề xuất thông thường (không phải block IP)
                                col_a1, col_a2 = st.columns([4, 1])
                                with col_a1:
                                    st.info("Hành động xử lý mang tính chất khuyến nghị quy trình / rà soát thủ công.")
                                with col_a2:
                                    if st.button("Ghi nhận (Acknowledge)", key=f"hitl_ack_{act_idx}"):
                                        st.success("Đã ghi nhận vào báo cáo ca trực!")

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
        run_files = sorted([f for f in os.listdir(runs_dir) if f.startswith("run_") and f.endswith(".json")], reverse=True)
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


# ==============================================================================
# TAB 4: LỚP PHẢN ỨNG CÓ KIỂM SOÁT & TƯỜNG LỬA (ACTIVE DEFENSE)
# ==============================================================================
with tab4:
    st.subheader("🛡️ Lớp Phản ứng có kiểm soát & Tường lửa UFW (Active Defense)")
    st.caption("Quản lý trạng thái tường lửa máy chủ lab, kiểm thử Policy Engine và tra cứu Nhật ký Kiểm toán không thể chối bỏ.")

    col_fw_left, col_fw_right = st.columns([1.2, 1])

    with col_fw_left:
        st.markdown("#### 🧱 Trạng thái Tường lửa UFW trên Lab Server")
        if st.button("🔄 Làm mới trạng thái UFW"):
            st.rerun()

        with st.spinner("Đang truy vấn bảng luật UFW qua SSH..."):
            fw_res = get_firewall_status()

        if fw_res.get("status") == "ok":
            fw_data = fw_res.get("data", {})
            st.markdown(f"**Trạng thái dịch vụ:** `{'HOẠT ĐỘNG (Active)' if fw_data.get('active') else 'CHƯA BẬT (Inactive)'}` | Tổng số quy tắc: `{fw_data.get('total_rules', 0)}`")
            
            rules = fw_data.get("rules", [])
            if rules:
                for r in rules:
                    r_num = r.get("rule_num")
                    r_from = r.get("from")
                    r_act = r.get("action")
                    r_to = r.get("to")
                    
                    c_r1, c_r2, c_r3 = st.columns([1, 3, 1.5])
                    c_r1.markdown(f"**Rule #{r_num}**")
                    c_r2.markdown(f"`{r_act}` from `{r_from}` to `{r_to}`")
                    with c_r3:
                        if "DENY" in r_act:
                            if st.button(f"Gỡ chặn", key=f"unblock_btn_{r_num}"):
                                clean_unblock_ip = r_from.split()[0]
                                un_res = unblock_ip(clean_unblock_ip)
                                st.success(f"Đã gửi lệnh gỡ rule #{r_num}!")
                                st.rerun()
            else:
                st.info("Chưa có quy tắc nào trong bảng UFW (hoặc UFW đang ở trạng thái mặc định).")
                with st.expander("Xem raw output từ máy chủ:"):
                    st.text(fw_data.get("raw_output", ""))
        else:
            st.warning(f"Không thể truy vấn UFW: {fw_res.get('error')}")
            st.info("💡 Lưu ý: Trên máy chủ lab Linux, cần cấp quyền sudo không mật khẩu cho UFW:\n```bash\necho 'agent_soc ALL=(ALL) NOPASSWD: /usr/sbin/ufw' | sudo tee /etc/sudoers.d/soc_agent_ufw\n```")

    with col_fw_right:
        st.markdown("#### 🧪 Thử nghiệm Policy Engine Guardrails")
        st.caption("Kiểm thử xem Policy Engine có ngăn chặn đúng các tình huống nguy hiểm hay không.")
        
        test_ip_input = st.text_input("Nhập IP để kiểm tra:", value="192.168.56.1")
        test_verdict = st.selectbox(
            "Giả lập kết luận điều tra (Verdict):",
            ["malicious_activity_likely", "benign_likely", "insufficient_data"]
        )
        
        if st.button("Kiểm tra với Policy Engine"):
            dec = evaluate_action("block_ip", test_ip_input, context={"verdict": test_verdict, "confidence": "high"})
            if dec.allowed:
                st.success(f"✅ **CHẤP THUẬN (Allowed):** {dec.reason}\n- Yêu cầu HITL: `{dec.requires_approval}`\n- Mức độ rủi ro: `{dec.risk_level}`")
            else:
                st.error(f"🛑 **TỪ CHỐI (Denied):** {dec.reason}\n- Mức độ rủi ro: `{dec.risk_level}`")

    st.markdown("---")
    st.markdown("#### 📜 Nhật ký Kiểm toán Phản ứng (Audit Trail Log)")
    audit_log_path = os.path.join("runs", "audit_trail.jsonl")
    if os.path.exists(audit_log_path):
        audit_records = []
        with open(audit_log_path, encoding="utf-8") as af:
            for line in af:
                line_str = line.strip()
                if line_str:
                    try:
                        audit_records.append(json.loads(line_str))
                    except Exception:
                        pass
        if audit_records:
            st.dataframe(audit_records, use_container_width=True)
        else:
            st.info("Chưa có bản ghi nhật ký kiểm toán nào.")
    else:
        st.info("Chưa có file audit_trail.jsonl. Nhật ký sẽ được tự động tạo khi có hành động phản ứng.")
