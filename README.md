# 🛡️ AI SOC Investigation Agent

Hệ thống tác tử AI (Autonomous Security Investigation Agent) tự động điều tra cảnh báo an ninh mạng trên máy chủ Linux sử dụng kiến trúc **ReAct (Reasoning + Acting)** an toàn.

Agent đóng vai trò như một **SOC Analyst Tier 1 / Tier 2**, tự động kết nối đến máy chủ mục tiêu qua kênh SSH chỉ đọc (Read-only), thu thập chứng cứ, phân tích nhật ký, đối chiếu với cấu hình an toàn chuẩn (Baseline) và đưa ra kết luận điều tra toàn diện bằng tiếng Việt.

---

## ✨ Tính năng nổi bật

1. **Kiến trúc ReAct Agent có kiểm soát:**
   - Hoạt động theo chu trình: *Nhận cảnh báo ➔ Suy luận (Reason) ➔ Gọi công cụ (Tool Call) ➔ Nhận dữ liệu (Observation) ➔ Đưa ra kết luận (Conclude)*.
   - Giới hạn số bước tối đa (`MAX_STEPS = 6`) để tránh lặp vô tận và tối ưu chi phí token.
   - Đầu ra chuẩn JSON có xác thực chặt chẽ (Schema validation).

2. **Phòng vệ Prompt Injection chủ động:**
   - Toàn bộ kết quả từ log hệ thống và cấu hình máy chủ được bọc trong thẻ `<untrusted_tool_output>`.
   - System prompt thiết lập ranh giới bảo mật nghiêm ngặt: Agent coi dữ liệu từ log là dữ liệu thô do kẻ tấn công có thể thao túng, tuyệt đối không thực thi bất kỳ chỉ thị nào ẩn trong log.

3. **Multi-Provider LLM & Khả năng chịu lỗi cao:**
   - **Google Gemini:** Tự động **Exponential Backoff** khi gặp lỗi nghẽn tốc độ (`429 RESOURCE_EXHAUSTED`) hoặc quá tải tạm thời (`503 UNAVAILABLE`), hỗ trợ danh sách **Fallback Models** tự động luân chuyển model dự phòng khi model chính lỗi.
   - **Local LLM qua Ollama:** Hỗ trợ chạy offline 100% không cần Internet (ví dụ: `qwen2.5:7b-instruct`, `llama3.1:8b`).
   - **Groq Cloud API:** Hỗ trợ inference siêu tốc (~300+ tokens/giây) cho các mô hình mã nguồn mở.

4. **Bộ công cụ điều tra chỉ đọc (Read-Only Tools):**
   - `search_auth_logs`: Quét và lọc sự kiện xác thực SSH/sudo theo IP nguồn và tài khoản.
   - `inspect_user_changes`: Kiểm tra danh sách người dùng thường, thành viên nhóm `sudo`, đối chiếu với `baseline.json` để phát hiện user lạ hoặc leo thang quyền trái phép.
   - `check_ssh_config`: Đọc và phân tích các tham số cấu hình SSH then chốt (`PermitRootLogin`, `PasswordAuthentication`, `MaxAuthTries`).
   - `inspect_active_processes`: Liệt kê các tiến trình đang chạy theo CPU/Memory, tích hợp thuật toán heuristic tự động phát hiện reverse shell, crypto miner hoặc tiến trình độc hại.
   - `inspect_network_connections`: Phân tích các cổng đang mở lắng nghe (Listening services) và các kết nối mạng đang hoạt động (Established) để phát hiện backdoor listener hoặc kết nối C2 outbound.
   - `inspect_cron_persistence`: Kiểm tra toàn diện crontab hệ thống (`/etc/crontab`, `/etc/cron.d/*`, các script định kỳ) để phát hiện cơ chế cắm chốt duy trì quyền truy cập (persistence).

5. **Động cơ phát hiện sự cố đa lớp (Multi-Rule Detection Engine):**
   - `detect_ssh_bruteforce`: Phát hiện các đợt tấn công dò mật khẩu SSH dồn dập, tự động nhận diện các phiên đăng nhập thành công sau chuỗi thất bại.
   - `detect_sudo_abuse`: Phát hiện các hành vi lạm dụng đặc quyền sudo: tài khoản không có quyền cố tình gõ sudo (`user NOT in sudoers`), nhập sai mật khẩu sudo dồn dập, hoặc thực thi các lệnh nhạy cảm cao (spawn root shell, đọc `/etc/shadow`, xóa log).
   - `detect_baseline_account_tampering`: Tự động đối chiếu với `baseline.json` để phát hiện tạo tài khoản lạ hoặc gán nhóm đặc quyền (`sudo`, `wheel`, `root`) trái phép.
   - `detect_all`: Hợp nhất tất cả các quy tắc phát hiện trên toàn bộ dòng sự kiện log.

6. **Báo cáo kết luận chuẩn SOC:**
   - Phân loại rõ ràng:
     - **Verdict:** `malicious_activity_likely` | `suspicious_needs_more_data` | `benign_likely` | `insufficient_data`
     - **Severity:** `info` | `low` | `medium` | `high` | `critical`
     - **Confidence:** `low` | `medium` | `high`
   - Báo cáo chi tiết bằng chứng đã xác minh, dữ liệu còn thiếu và đề xuất hành động xử lý (Remediation proposals).
   - Tự động lưu vết toàn bộ phiên điều tra thành file JSON trong thư mục `runs/`.

---

## 📁 Cấu trúc dự án

```text
soc-agent/
├── agent.py            # Vòng lặp ReAct, System Prompt & quy tắc phân loại điều tra
├── tools.py            # Bộ công cụ điều tra an toàn (read-only)
├── detection.py        # Bộ quy tắc phát hiện sự cố (SSH Bruteforce detector)
├── log_parser.py       # Bộ phân tích cú pháp nhật ký /var/log/auth.log
├── read_logs.py        # Module kết nối SSH (Paramiko) để thực thi lệnh đọc log cố định
├── llm_client.py       # Lớp tương tác LLM đa nền tảng (Gemini, Ollama, Groq)
├── app.py              # Giao diện Web Dashboard (Streamlit) trực quan hóa điều tra
├── run_agent.py        # Kịch bản chạy điều tra tự động trên Terminal
├── run_detection.py    # Kịch bản quét và hiển thị toàn bộ cảnh báo
├── baseline.json       # Danh sách tài khoản và nhóm quyền được phê duyệt chuẩn
├── test_step1.py       # Bộ kiểm thử đơn vị cho LLM client và cơ chế fallback
├── test_detection_rules.py # Bộ kiểm thử các quy tắc phát hiện tấn công
├── test_tools.py       # Bộ kiểm thử 6 công cụ điều tra
├── requirements.txt    # Danh sách thư viện Python cần thiết
├── .env.example        # Mẫu cấu hình biến môi trường
└── runs/               # Thư mục lưu vết các phiên điều tra (JSON logs)
```

---

## 🚀 Hướng dẫn cài đặt & Chạy thử nghiệm

### 1. Yêu cầu hệ thống
- Python 3.10+
- Máy ảo Linux chạy SSH (Lab) để Agent kết nối thu thập log (hoặc cấu hình tương thích).

### 2. Cài đặt môi trường
```bash
# Tạo môi trường ảo
python -m venv .venv

# Kích hoạt môi trường ảo
# Trên Windows PowerShell:
.venv\Scripts\Activate.ps1
# Trên Linux/macOS:
source .venv/bin/activate

# Cài đặt thư viện
pip install -r requirements.txt
```

### 3. Cấu hình biến môi trường
Sao chép file `.env.example` thành `.env` và điền khóa API của bạn:
```bash
cp .env.example .env
```

Mở `.env` để cấu hình:
```ini
LLM_PROVIDER=gemini
LLM_API_KEY=your_gemini_api_key_here
LLM_MODEL=gemini-3.5-flash-lite
LLM_FALLBACK_MODELS=gemini-3-flash-preview,gemini-3.5-flash,gemini-3.8-flash
```

*(Nếu muốn dùng Local LLM qua Ollama, chỉ cần đổi `LLM_PROVIDER=ollama` và bật `ollama run qwen2.5:7b-instruct`)*.

### 4. Kiểm tra hoạt động của mô hình
Chạy script kiểm thử để đảm bảo kết nối LLM và cơ chế fallback hoạt động tốt:
```bash
python test_step1.py
```

### 5. Thực thi điều tra cảnh báo (Terminal CLI)
```bash
python run_agent.py
```

### 6. Khởi chạy Giao diện Web Dashboard (Streamlit UI)
```bash
streamlit run app.py
```
Trình duyệt sẽ tự động mở bảng điều khiển trực quan tại địa chỉ `http://localhost:8501`.

---

## 🔒 Nguyên tắc An toàn (Safety Principles)

- **Không bao giờ trao quyền shell tự do cho LLM:** Agent chỉ được phép gọi các hàm Python đã được định nghĩa sẵn (`search_auth_logs`, `inspect_user_changes`, `check_ssh_config`) với đối số được kiểm tra kiểu chặt chẽ.
- **Hành động phản ứng chỉ mang tính đề xuất:** Agent không tự ý chạy các lệnh thay đổi cấu hình hoặc chặn IP (`iptables`/`ufw`) trên máy chủ mà chỉ đưa ra phương án để con người (Human-in-the-Loop) phê duyệt.
- **Bảo mật tuyệt đối Secret:** Các khóa bí mật (API Key, SSH Private Key) được quản lý qua biến môi trường và luôn bị loại trừ khỏi Git theo `.gitignore`.

---

## 📜 Giấy phép
Dự án được phát hành dưới giấy phép MIT License.

