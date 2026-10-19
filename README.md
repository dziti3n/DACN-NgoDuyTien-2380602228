# 🛡️ AI SOC Investigation & Defense Agent

Hệ thống tác tử AI (Autonomous Security Investigation & Controlled Defense Agent) tự động điều tra cảnh báo an ninh mạng và thực thi phản ứng có kiểm soát trên máy chủ Linux sử dụng kiến trúc **ReAct (Reasoning + Acting)** an toàn.

Agent đóng vai trò như một **SOC Analyst Tier 1 / Tier 2**, tự động kết nối đến máy chủ mục tiêu qua kênh SSH chỉ đọc (Read-only), thu thập chứng cứ, phân tích nhật ký, đối chiếu với cấu hình an toàn chuẩn (Baseline) và đưa ra kết luận điều tra toàn diện bằng tiếng Việt. Sau khi điều tra, các đề xuất phản ứng chủ động (Active Defense) được đưa qua **Lớp Kiểm soát Chính sách (Policy Engine Guardrails)** độc lập và cơ chế **Phê duyệt Con người (Human-in-the-Loop)** trước khi áp dụng luật chặn trên tường lửa UFW.

---

## ✨ Tính năng nổi bật

1. **Kiến trúc ReAct Agent có kiểm soát:**
   - Hoạt động theo chu trình: *Nhận cảnh báo ➔ Suy luận (Reason) ➔ Gọi công cụ (Tool Call) ➔ Nhận dữ liệu (Observation) ➔ Đưa ra kết luận (Conclude)*.
   - Giới hạn số bước tối đa (`MAX_STEPS = 6`) để tránh lặp vô tận và tối ưu hiệu năng.
   - Đầu ra chuẩn JSON có xác thực cấu trúc nghiêm ngặt (Schema validation).

2. **100% Local LLM (Air-Gapped & Zero Data Leakage):**
   - Hệ thống vận hành hoàn toàn ngoại tuyến thông qua **Ollama** cục bộ (khuyên dùng `qwen3:4b` hoặc `qwen2.5:7b-instruct`).
   - Khóa chặt kết nối chỉ trong phạm vi `127.0.0.1:11434`, tuyệt đối không gửi bất kỳ dữ liệu cảnh báo hay thông tin hệ thống nào ra ngoài Internet.
   - Thiết lập `temperature=0.0` và `seed=42` cố định để đảm bảo tính **Tất định (Deterministic)** và độ tin cậy khoa học cao trong phân tích an ninh.

3. **Lớp Kiểm soát Phản ứng Độc lập (Policy Engine Guardrails):**
   - Mã nguồn Python xác định (Deterministic Rule-based), không phụ thuộc vào LLM để phòng vệ tuyệt đối chống **Prompt Injection**:
     - **Whitelist Bảo vệ (Protected IPs):** Cấm tuyệt đối hành động chặn IP máy Host Windows (`192.168.56.1`), IP máy chủ lab (`192.168.56.101`) hoặc Loopback (`127.0.0.1`), ngăn chặn nguy cơ tự khóa mình ra khỏi hệ thống.
     - **Chống Command Injection:** Kiểm tra cú pháp địa chỉ IP nghiêm ngặt bằng module `ipaddress`.
     - **Ngưỡng Bằng chứng (Evidence Threshold):** Từ chối tự động các đề xuất chặn nếu kết luận điều tra là bình thường (`benign_likely`) hoặc thiếu dữ liệu (`insufficient_data`).
     - **Human-in-the-Loop (HITL):** Mọi hành động làm thay đổi trạng thái mạng đều bắt buộc phải có sự xác nhận của chuyên viên SOC.

4. **Lớp Phản ứng Chủ động & Tường lửa (Active Response Tools):**
   - `block_ip(ip)`: Thực thi lệnh chèn luật chặn `sudo ufw insert 1 deny from <ip>` lên đầu bảng tường lửa UFW.
   - `unblock_ip(ip)`: Hoàn tác (Rollback) gỡ bỏ quy tắc chặn IP nhanh chóng khi cần.
   - `verify_response(ip, expected_state)`: Tự động truy vấn `ufw status numbered` để xác minh độc lập xem luật đã thực sự có hiệu lực trên máy chủ hay chưa.
   - `get_firewall_status()`: Trích xuất toàn bộ bảng quy tắc tường lửa đang hoạt động trên máy chủ lab.

5. **Bộ công cụ điều tra chỉ đọc (Read-Only Tools):**
   - `search_auth_logs`: Quét và lọc sự kiện xác thực SSH/sudo theo IP nguồn và tài khoản.
   - `inspect_user_changes`: Kiểm tra danh sách người dùng thường, thành viên nhóm `sudo`, đối chiếu với `baseline.json` để phát hiện user lạ hoặc leo thang quyền trái phép.
   - `check_ssh_config`: Đọc và phân tích các tham số cấu hình SSH then chốt (`PermitRootLogin`, `PasswordAuthentication`, `MaxAuthTries`).
   - `inspect_active_processes`: Liệt kê các tiến trình đang chạy theo CPU/Memory, tích hợp thuật toán heuristic tự động phát hiện reverse shell, crypto miner hoặc tiến trình độc hại.
   - `inspect_network_connections`: Phân tích các cổng đang mở lắng nghe (Listening services) và các kết nối mạng đang hoạt động (Established) để phát hiện backdoor listener hoặc kết nối C2 outbound.
   - `inspect_cron_persistence`: Kiểm tra toàn diện crontab hệ thống (`/etc/crontab`, `/etc/cron.d/*`, các script định kỳ) để phát hiện cơ chế cắm chốt duy trì quyền truy cập (persistence).

6. **Nhật ký Kiểm toán không thể chối bỏ (Audit Trail):**
   - Tự động ghi lại toàn bộ hành động phản ứng (thành công, thất bại hoặc bị Policy Engine từ chối) vào cả `runs/action_audit.log` (định dạng văn bản) và `runs/audit_trail.jsonl` (chuẩn JSON Lines cho SIEM).

---

## 📁 Cấu trúc dự án

```text
soc-agent/
├── agent.py            # Vòng lặp ReAct, System Prompt & quy tắc phân loại điều tra
├── policy_engine.py    # Lớp kiểm soát chính sách an toàn (Guardrails, Whitelist, Audit Trail)
├── tools.py            # 6 Công cụ điều tra chỉ đọc + 4 Công cụ phản ứng tường lửa UFW
├── detection.py        # Bộ quy tắc phát hiện sự cố (SSH Bruteforce, Sudo Abuse, Baseline Tampering)
├── log_parser.py       # Bộ phân tích cú pháp nhật ký /var/log/auth.log
├── read_logs.py        # Module kết nối SSH (Paramiko) để thực thi lệnh cố định
├── llm_client.py       # Lớp tương tác mô hình LLM cục bộ (Ollama Local Client - Air-Gapped)
├── app.py              # Giao diện Web Dashboard (Streamlit) với 4 Tabs giám sát & phản ứng
├── cli.py              # Công cụ dòng lệnh hợp nhất (Scan, Investigate, Firewall, Block, UI, Test)
├── baseline.json       # Danh sách tài khoản và nhóm quyền được phê duyệt chuẩn
├── security_audit.py   # Công cụ tự động quét chống rò rỉ Secret / API Key
├── tests/              # Toàn bộ bộ kiểm thử tự động
│   ├── test_policy_engine.py   # Kiểm thử Whitelist, Chống Injection & Ngưỡng bằng chứng (9 test cases)
│   ├── test_detection_rules.py # Kiểm thử 11 kịch bản phát hiện tấn công
│   ├── test_llm.py             # Kiểm thử kết nối mô hình LLM cục bộ (Ollama qwen3:4b)
│   └── test_tools.py           # Kiểm thử 6 công cụ điều tra trên server lab
├── requirements.txt    # Danh sách thư viện Python cần thiết
├── .env.example        # Mẫu cấu hình biến môi trường
└── runs/               # Lưu vết các phiên điều tra (JSON) và nhật ký kiểm toán (Audit logs)
```

---

## 🚀 Hướng dẫn cài đặt & Cấu hình

### 1. Yêu cầu hệ thống
- Python 3.10+
- Máy ảo Linux (Ubuntu/Debian) đóng vai trò máy chủ Lab kết nối qua SSH.
- [Ollama](https://ollama.com/) cài đặt sẵn trên máy host với mô hình `qwen3:4b`:
  ```bash
  ollama run qwen3:4b
  ```

### 2. Cài đặt môi trường Python
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

### 3. Cấu hình biến môi trường `.env`
Sao chép `.env.example` thành `.env`:
```ini
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
OLLAMA_MODEL=qwen3:4b
OLLAMA_SEED=42
OLLAMA_TEMPERATURE=0.0

# Kết nối SSH tới máy ảo Lab
SSH_HOST=192.168.56.101
SSH_PORT=22
SSH_USER=agent_soc
SSH_KEY_PATH=~/.ssh/soc_agent_key
```

### 4. Cấu hình phân quyền đặc quyền tối thiểu (Least Privilege) trên Máy ảo Lab
Để tài khoản `agent_soc` có thể thực thi các lệnh tường lửa UFW mà không cần gõ mật khẩu (và không được phép sudo bừa bãi), hãy chạy lệnh sau một lần duy nhất trên máy ảo Linux:

```bash
# Đăng nhập vào máy ảo Linux và cấp quyền tối thiểu cho UFW:
echo 'agent_soc ALL=(ALL) NOPASSWD: /usr/sbin/ufw' | sudo tee /etc/sudoers.d/soc_agent_ufw
sudo chmod 0440 /etc/sudoers.d/soc_agent_ufw
```

---

## 🛠️ Hướng dẫn sử dụng

### 1. Sử dụng Công cụ Dòng lệnh Hợp nhất (`cli.py`)
```bash
# 1. Quét và hiển thị toàn bộ cảnh báo an ninh trên máy chủ lab
python cli.py scan

# 2. Agent tự động điều tra cảnh báo mới nhất
python cli.py investigate

# 3. Điều tra cảnh báo cụ thể theo số thứ tự (ví dụ: cảnh báo #0)
python cli.py investigate 0

# 4. Xem bảng trạng thái tường lửa UFW trên máy chủ lab
python cli.py firewall

# 5. Chặn một IP có thẩm định an toàn qua Policy Engine
python cli.py block 198.51.100.22

# Thử nghiệm chặn IP Host Windows (Policy Engine sẽ chặn đứng ngay lập tức):
python cli.py block 192.168.56.1

# 6. Gỡ chặn một IP trên UFW
python cli.py unblock 198.51.100.22

# 7. Chạy toàn bộ các bài kiểm thử tự động
python cli.py test

# 8. Khởi chạy Giao diện Web Dashboard
python cli.py ui
```

### 2. Giao diện Web Dashboard (`app.py`)
Khởi chạy bảng điều khiển trực quan:
```bash
python cli.py ui
# hoặc
streamlit run app.py
```
Giao diện bao gồm 4 Tabs chuyên nghiệp:
- **Tab 1: Cảnh báo & Điều tra (Alerts & Investigation):** Xem danh sách cảnh báo, kích hoạt ReAct Agent, hiển thị chuỗi suy luận từng bước, kết luận và nút phê duyệt chặn IP (HITL) được bảo vệ bởi Policy Engine.
- **Tab 2: Lịch sử các ca điều tra (Run History):** Xem lại toàn bộ các phiên điều tra đã lưu vết trong thư mục `runs/`.
- **Tab 3: Bộ công cụ điều tra (Investigation Toolkit):** Cho phép chuyên viên gọi thử nghiệm từng công cụ điều tra chỉ đọc.
- **Tab 4: Phản ứng có kiểm soát & Tường lửa (Active Defense):** Quản lý trực tiếp các luật UFW trên lab server, thử nghiệm Policy Engine và theo dõi bảng Nhật ký Kiểm toán (Audit Trail Log).

---

## 🔒 Nguyên tắc An toàn Cốt lõi (Core Security Principles)

1. **Deterministic Guardrails First:** Mọi quyết định can thiệp hệ thống (chặn IP, ngắt kết nối) đều phải qua mã nguồn Python xác định (Policy Engine). Không bao giờ tin tưởng tuyệt đối vào kết quả sinh của mô hình ngôn ngữ lớn (LLM).
2. **Nguyên tắc Đặc quyền Tối thiểu (Principle of Least Privilege):** Agent chỉ được cấp quyền sudo đối với đúng binary `/usr/sbin/ufw`, không được cấp sudo toàn quyền (`ALL=(ALL)`).
3. **Auditability & Accountability:** Mọi thao tác đều được lưu vết chi tiết với định danh người phê duyệt, thời điểm và kết quả xác minh.

---

## 📜 Tác giả
Dự án được phát triển bởi **Duy Tiến**.
