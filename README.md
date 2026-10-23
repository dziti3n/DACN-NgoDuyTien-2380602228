# 🛡️ AI SOC Investigation & Autonomous Defense Platform

Hệ thống tác tử an ninh mạng tự hành (**Autonomous Security Investigation & Controlled Defense Platform**) kết hợp mô hình ngôn ngữ lớn cục bộ (**Local On-Premises LLM**) với động cơ điều tra **ReAct (Reasoning + Acting)**, lớp kiểm soát an toàn xác định (**Deterministic Policy Engine Guardrails**), và cơ chế phản ứng tự động trên tường lửa Linux (**UFW Defense**) cùng hệ thống báo động qua Gmail.

Hệ thống hoạt động tương đương một **SOC Analyst Tier 1 / Tier 2 kết hợp SOAR mini**, tự động giám sát máy chủ Linux, phát hiện tấn công, thu thập chứng cứ đa chiều, thẩm định chính sách an toàn và thực thi cô lập kẻ tấn công trong thời gian thực.

---

## 🏛️ Kiến trúc Tổng thể Hệ thống

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MÁY CHỦ LINUX LAB (UBUNTU)                           │
│  /var/log/auth.log   •   sshd_config   •   crontab   •   ss/ps   •   baseline   │
│                                                                                 │
│         ▲                                                    │ (UFW Rule)       │
│         │ SSH Read-Only (Paramiko)                           ▼                  │
│         │                                        /usr/local/sbin/soc-block-ip   │
│         │                                        /usr/local/sbin/soc-unblock-ip │
└─────────┼────────────────────────────────────────────────────▲──────────────────┘
          │                                                    │
══════════╪════════════════════════════════════════════════════╪═══════════════════
          │                                                    │
┌─────────▼────────────────────────────────────────────────────┴──────────────────┐
│                    MÁY HOST WINDOWS (AI SOC CONTROL CENTER)                     │
│                                                                                 │
│  ┌───────────────────────┐         ┌─────────────────────────────────────────┐  │
│  │   detection.py        │         │   agent.py (ReAct Investigation)        │  │
│  │   • SSH Bruteforce    │ ──────> │   • Local Ollama (qwen3:4b, seed=42)    │  │
│  │   • Sudo Abuse        │ Cảnh báo│   • MAX_STEPS = 3, Evidence Extraction  │  │
│  │   • Baseline Tampering│         │   • 6 Read-only Investigation Tools     │  │
│  └───────────────────────┘         └────────────────────┬────────────────────┘  │
│             ▲                                           │                       │
│             │ Log events                                ▼ Đề xuất phản ứng      │
│  ┌──────────┴────────────┐         ┌─────────────────────────────────────────┐  │
│  │   monitor_daemon.py   │         │   policy_engine.py (Guardrails)         │  │
│  │   • Quét ngầm định kỳ │         │   • Protected IP Whitelist (Anti-Lockout│  │
│  │   • Cooldown 15 phút  │         │   • Anti-Prompt Injection Correlation   │  │
│  │   • Quản lý TTL 15m   │         │   • Rate Limiting (Tối đa 5 lần/giờ)    │  │
│  └──────────┬────────────┘         │   • TTL 15 phút (runs/active_blocks)    │  │
│             │                      └────────────────────┬────────────────────┘  │
│             │ Cảnh báo HTML                             │                       │
│             ▼                                           ▼ Thực thi              │
│  ┌───────────────────────┐         ┌─────────────────────────────────────────┐  │
│  │   notifier.py         │         │   tools.py (Active Defense)             │  │
│  │   • Gmail SMTP 587    │         │   • block_ip(ip) via Safe Wrapper       │  │
│  │   • Báo động HTML SOC │         │   • verify_response(ip) via UFW         │  │
│  │   • Preview Offline   │         │   • Structured Audit Trail (SIEM-ready) │  │
│  └───────────────────────┘         └─────────────────────────────────────────┘  │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  app.py: AI SOC Command Center (Giao diện Streamlit Hợp nhất 50% / 50%)   │  │
│  │  • Live Cyber Terminal Log Streamer   • Bắn Test Mô Phỏng Tấn Công Nhanh   │  │
│  │  • Trực quan hóa suy luận ReAct Live  • Phê duyệt HITL & Audit Viewer     │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Tính năng Nổi bật & Cải tiến Mới nhất

### 1. Tiến trình Giám sát An ninh Tự hành (`monitor_daemon.py`)
- **Vòng lặp tự động liên tục:** Định kỳ quét nhật ký hệ thống qua SSH (`poll_interval=20s`), tự động kích hoạt chu trình:  
  $$\text{Phát hiện} \longrightarrow \text{Điều tra ReAct} \longrightarrow \text{Thẩm định Policy} \longrightarrow \text{Cô lập UFW} \longrightarrow \text{Gửi Gmail}$$
- **Cơ chế IP Cooldown (15 phút):** Ngăn chặn bão cảnh báo (Alert Fatigue), chống nghẽn hàng đợi LLM khi bị tấn công dồn dập từ cùng một IP.
- **Tự động mở khóa TTL (Time-To-Live):** Tự động gỡ bỏ luật chặn trên UFW khi thời hạn cách ly (15 phút) kết thúc, tránh tích tụ luật rác.

### 2. Trung tâm Chỉ huy Trực quan Hợp nhất (`app.py` - AI SOC Command Center)
- **Thiết kế Cyber Console chuyên nghiệp trên 1 màn hình duy nhất (Bố cục 50% / 50%):**
  - **Cột Trái (Live Detection & Control):** Trạng thái kết nối SSH thời gian thực, nút **"Bắn Test Mô Phỏng Tấn Công (Quick Kali SSH Brute Force Demo)"**, công tắc giám sát tự hành, bộ lọc Cyber Terminal log streamer và bảng danh sách cảnh báo.
  - **Cột Phải (AI Intelligence & Defense):** Hiển thị trực tiếp luồng suy luận của AI ReAct từng bước (Thinking $\rightarrow$ Tool Call $\rightarrow$ Conclude), thẻ kết luận điều tra (Verdict, Severity, Confidence, Evidence), thẻ thẩm định Policy Engine, công cụ phản ứng UFW kèm thời hạn TTL, trạng thái thông báo Gmail và nhật ký kiểm toán.

### 3. Vận hành Cục bộ 100% (Local On-Premises LLM - Zero Data Leakage)
- Sử dụng **Ollama** cục bộ trên máy host (khuyến nghị mô hình `qwen3:4b` hoặc `qwen2.5:7b-instruct`).
- Khóa chặt kết nối nội bộ `127.0.0.1:11434`, không truyền bất kỳ dữ liệu cảnh báo hay thông tin hệ thống nào ra ngoài Internet.
- Thiết lập `temperature=0.0` và `seed=42` cố định để tối đa hóa tính ổn định và tính lặp lại (Deterministic) trong phân tích an ninh.
- Tối ưu hóa chu trình suy luận `MAX_STEPS = 3` và cô đọng token đầu ra của công cụ nhằm đảm bảo phản hồi tức thì trên phần cứng nội bộ.

### 4. Lớp Kiểm soát An toàn Xác định (Deterministic Policy Engine Guardrails)
Mã nguồn Python xác định độc lập, tuyệt đối không phụ thuộc vào LLM để phòng vệ trước các nguy cơ tấn công:
- **Whitelist Bảo vệ (Protected IPs):** Cấm tuyệt đối hành vi chặn IP Host Windows (`192.168.56.1`), IP Lab Server (`192.168.56.101`), NAT Gateway (`10.0.2.2`) hoặc Loopback (`127.0.0.1`), triệt tiêu hoàn toàn nguy cơ **Self-Lockout**.
- **Chống Prompt Injection & Log Poisoning:** Chỉ cho phép chặn IP nếu IP đó xuất hiện trong cảnh báo gốc hoặc chứng cứ đã xác minh; mọi dữ liệu log đều được đóng gói trong sandbox `<untrusted_tool_output>`.
- **Chống DoS / Bão Luật (Rate Limiting):** Giới hạn tối đa 5 lần chặn/giờ để bảo vệ bảng luật tường lửa UFW không bị tràn bộ nhớ.
- **Quản lý Thời hạn Cách ly (TTL 15 phút):** Lưu vết trạng thái vào `runs/active_blocks.json` kèm mốc thời gian hết hạn cụ thể.
- **Human-in-the-Loop (HITL):** Cho phép chuyên viên SOC trực tiếp xem xét và phê duyệt trước khi can thiệp vào hệ thống mạng.

### 5. Bộ Wrapper Scripts An toàn & Đặc quyền Tối thiểu (`scripts/setup_lab_guardrails.sh`)
- Thu hẹp quyền sudoers trên máy chủ lab: Tài khoản `agent_soc` không được cấp quyền `sudo /usr/sbin/ufw` trực tiếp (tránh nguy cơ bị kẻ tấn công lợi dụng thực thi `ufw disable` hoặc `ufw reset`).
- Cấp quyền thực thi qua 2 Wrapper Scripts an toàn thuộc sở hữu của `root`:
  - `/usr/local/sbin/soc-block-ip <ip>`: Kiểm tra cú pháp IP, tự động cho phép cổng 22/tcp (SSH) trước khi chèn luật `deny from <ip>` lên đầu bảng UFW.
  - `/usr/local/sbin/soc-unblock-ip <ip>`: Thực thi gỡ bỏ luật chặn an toàn.

### 6. Hệ thống Thông báo Báo động qua Gmail (`notifier.py`)
- Kết nối Gmail SMTP qua cổng bảo mật 587 (TLS).
- Tự động sinh báo cáo HTML chuẩn SOC hiển thị mức độ nghiêm trọng, địa chỉ IP vi phạm, kết luận của AI Agent, chuỗi chứng cứ và trạng thái UFW.
- **Chế độ Kép:** Nếu chưa cấu hình mật khẩu ứng dụng Gmail, hệ thống tự động lưu bản tin HTML vào `runs/alerts/` để người dùng mở xem trên trình duyệt mà không làm gián đoạn tiến trình.

### 7. Bộ Công cụ Điều tra Chỉ đọc (6 Read-Only Tools)
- `search_auth_logs`: Quét và lọc sự kiện xác thực SSH/sudo theo IP nguồn và tài khoản.
- `inspect_user_changes`: Kiểm tra danh sách người dùng, đối chiếu với `baseline.json` để phát hiện user lạ hoặc leo thang quyền trái phép.
- `check_ssh_config`: Đọc và phân tích các tham số cấu hình SSH then chốt (`PermitRootLogin`, `PasswordAuthentication`, `MaxAuthTries`).
- `inspect_active_processes`: Liệt kê các tiến trình đang chạy theo CPU/Memory, tích hợp thuật toán heuristic phát hiện reverse shell, crypto miner hoặc payload socket.
- `inspect_network_connections`: Phân tích các cổng đang mở lắng nghe (Listening services) và kết nối `ESTABLISHED` ra ngoài.
- `inspect_cron_persistence`: Kiểm tra toàn diện crontab hệ thống và script định kỳ để phát hiện cơ chế cắm chốt duy trì quyền truy nhập.

### 8. Nhật ký Kiểm toán Có cấu trúc (Structured Audit Trail)
- Lưu vết đầy đủ vào `runs/action_audit.log` (văn bản dễ đọc) và `runs/audit_trail.jsonl` (chuẩn JSON Lines sẵn sàng tích hợp SIEM/Splunk/ELK).

---

## 📁 Cấu trúc Thư mục Dự án

```text
soc-agent/
├── agent.py                 # Vòng lặp ReAct, System Prompt & quy tắc phân loại điều tra (MAX_STEPS=3)
├── policy_engine.py         # Lớp kiểm soát chính sách an toàn (Guardrails, Whitelist, TTL, Rate Limit)
├── tools.py                 # 6 Công cụ điều tra chỉ đọc + 4 Công cụ phản ứng UFW an toàn
├── detection.py             # Bộ quy tắc phát hiện sự cố (SSH Bruteforce, Sudo Abuse, Baseline Tampering)
├── log_parser.py            # Phân tích cú pháp nhật ký xác thực /var/log/auth.log
├── read_logs.py             # Module kết nối SSH cố định qua Paramiko
├── llm_client.py            # Client tương tác mô hình LLM cục bộ (Ollama Local Client)
├── monitor_daemon.py        # Tiến trình giám sát tự hành chạy ngầm (Autonomous SOAR Daemon)
├── notifier.py              # Hệ thống gửi email cảnh báo HTML qua Gmail SMTP
├── app.py                   # AI SOC Command Center (Giao diện Streamlit hợp nhất 50/50 trên 1 màn hình)
├── cli.py                   # Giao diện dòng lệnh hợp nhất (Monitor, Test-Email, Scan, Investigate, UI...)
├── baseline.json            # Danh sách tài khoản và nhóm quyền chuẩn được phê duyệt
├── security_audit.py        # Quét kiểm tra an toàn mã nguồn, chống rò rỉ API Key / Secret
├── scripts/
│   ├── setup_lab_guardrails.sh  # Script thiết lập wrapper scripts & thu hẹp sudoers trên server lab
│   └── test_autonomous_flow.py  # Script kiểm thử luồng tự hành trọn gói
├── tests/                   # Bộ kiểm thử tự động toàn diện
│   ├── test_policy_engine.py    # Kiểm thử Whitelist, Anti-Injection, TTL, Rate Limit (10 tests)
│   ├── test_detection_rules.py  # Kiểm thử 11 kịch bản phát hiện vi phạm
│   ├── test_notifier.py         # Kiểm thử sinh HTML và xử lý ngoại lệ SMTP (3 tests)
│   ├── test_monitor_daemon.py   # Kiểm thử logic tự hành, cooldown, gỡ chặn TTL (4 tests)
│   ├── test_llm.py              # Kiểm thử kết nối mô hình LLM cục bộ Ollama
│   └── test_tools.py            # Kiểm thử công cụ điều tra trên môi trường lab
├── requirements.txt         # Danh mục thư viện Python
├── .env.example             # Mẫu cấu hình biến môi trường
└── runs/                    # Lưu vết phiên làm việc, nhật ký kiểm toán và cảnh báo
    ├── alerts/              # Bản tin cảnh báo HTML lưu trữ xem offline
    ├── active_blocks.json   # Danh sách các IP đang bị cách ly kèm thời hạn TTL
    ├── action_audit.log     # Nhật ký kiểm toán phản ứng dạng văn bản
    └── audit_trail.jsonl    # Nhật ký kiểm toán phản ứng chuẩn JSON Lines
```

---

## 🚀 Hướng dẫn Cài đặt & Vận hành

### 1. Yêu cầu Hệ thống
- **Hệ điều hành:** Windows 10/11 (Máy Host điều khiển) + Ubuntu Server 22.04/24.04 trên VirtualBox (Máy Lab).
- **Python:** 3.10+
- **Mô hình AI Cục bộ:** Cài đặt [Ollama](https://ollama.com/) và tải mô hình:
  ```bash
  ollama run qwen3:4b
  ```

### 2. Cài đặt Môi trường Python trên Máy Host
```powershell
# Tạo và kích hoạt môi trường ảo
python -m venv .venv
.venv\Scripts\Activate.ps1

# Cài đặt thư viện phụ thuộc
pip install -r requirements.txt
```

### 3. Cấu hình Biến Môi trường (`.env`)
Tạo file `.env` từ file mẫu:
```ini
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
OLLAMA_MODEL=qwen3:4b
OLLAMA_SEED=42
OLLAMA_TEMPERATURE=0.0

# Kết nối SSH tới máy chủ Lab Linux
SSH_HOST=192.168.56.101
SSH_PORT=22
SSH_USER=agent_soc
SSH_KEY_PATH=~/.ssh/soc_agent_key

# Cấu hình Email Báo Động (Tùy chọn Gmail SMTP)
ALERT_EMAIL_ENABLED=false
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your_email@gmail.com
SENDER_APP_PASSWORD=your_16_digit_app_password
RECIPIENT_EMAIL=your_email@gmail.com
```

### 4. Thiết lập Ranh giới An toàn (Guardrails) trên Máy ảo Lab
Đăng nhập vào máy ảo Linux và thực thi script thiết lập phân quyền tối thiểu một lần duy nhất:
```bash
sudo bash scripts/setup_lab_guardrails.sh
```
Script sẽ tự động khởi tạo 2 wrapper an toàn `/usr/local/sbin/soc-block-ip`, `/usr/local/sbin/soc-unblock-ip`, mở sẵn cổng SSH 22 và giới hạn quyền sudo của `agent_soc`.

---

## 🛠️ Hướng dẫn Sử dụng Hệ thống

### Cách 1: Sử dụng Giao diện Web Command Center (`app.py`)
Khởi chạy bảng điều khiển chỉ huy:
```powershell
python cli.py ui
# hoặc: streamlit run app.py
```
- Truy cập trình duyệt tại `http://localhost:8501`.
- Nhấn nút **"Bắn Test Mô Phỏng Tấn Công"** để xem AI Agent phân tích, suy luận, thẩm định Policy, ra lệnh chặn UFW và sinh báo cáo HTML trực quan ngay lập tức.

### Cách 2: Khởi chạy Tiến trình Giám sát Tự hành Chạy ngầm (`monitor_daemon.py`)
```powershell
# Chạy ở chế độ hoàn toàn tự hành (Auto-Detect, Auto-Investigate, Auto-Block, Auto-Email)
python cli.py monitor

# Chạy ở chế độ giám sát cảnh báo (không tự chặn, chờ người duyệt)
python cli.py monitor --no-auto-block
```

### Cách 3: Sử dụng Công cụ Dòng lệnh Hợp nhất (`cli.py`)
```powershell
# 1. Quét toàn bộ cảnh báo trên server lab
python cli.py scan

# 2. Agent tự động điều tra cảnh báo
python cli.py investigate

# 3. Xem bảng trạng thái tường lửa UFW
python cli.py firewall

# 4. Kiểm tra gửi Email cảnh báo (HTML Preview hoặc Live SMTP)
python cli.py test-email

# 5. Chặn 1 IP qua thẩm định Policy Engine
python cli.py block 192.168.56.102

# 6. Gỡ chặn 1 IP trên tường lửa
python cli.py unblock 192.168.56.102

# 7. Chạy kiểm thử tự động toàn dự án
python cli.py test
```

### ⚔️ Kịch bản Kiểm thử & Mô phỏng Tấn công (Testing Workflow)
Để thực hiện test thực tế các kịch bản tấn công (SSH Brute Force từ Kali, Leo quyền sudo, Tạo backdoor ngoài baseline, Reverse shell, Crontab persistence, Self-lockout...), vui lòng tham khảo sổ tay lệnh chi tiết tại:  
👉 **[WORKLOG.md - PHẦN D: BẢNG LỆNH TEST TẤN CÔNG THỰC TẾ](file:///d:/soc-agent/WORKLOG.md#-phần-d-bảng-lệnh-test-tấn-công-thực-tế-test-workflow)**

---

## 🔬 Phạm vi Ứng dụng & Hạn chế của Đề tài (Scope & Limitations)

### Phạm vi Ứng dụng
- Tập trung vào giám sát an ninh mức hệ điều hành máy chủ Linux (Host-based Security Monitoring).
- Phân tích nhật ký xác thực hệ thống (`/var/log/auth.log`), đối chiếu cấu hình chuẩn (Baseline), rà soát tiến trình, kết nối mạng và các tác vụ định kỳ (Cron persistence).
- Phản ứng nhanh thông qua tường lửa máy chủ nội bộ (UFW Host Firewall).

### Hạn chế Kỹ thuật Hiện tại
1. **Phạm vi Log:** Hệ thống tập trung vào log hệ điều hành Linux và xác thực SSH/Sudo; chưa tích hợp bộ bóc tách chuyên sâu cho log tầng ứng dụng Web (Nginx/Apache access log) hoặc cơ sở dữ liệu.
2. **Quy mô Mô hình LLM:** Dự án sử dụng mô hình SLM 4B (`qwen3:4b`) tối ưu hóa để vận hành mượt mà trên phần cứng máy tính cá nhân (GPU rời RTX 3050). Năng lực xử lý ngữ cảnh cực dài và suy luận đa tầng bị giới hạn so với các mô hình đám mây thương mại cỡ lớn, nhưng đổi lại đảm bảo tính bảo mật và quyền riêng tư dữ liệu tuyệt đối (On-Premises).
3. **Phạm vi Phản ứng Mạng:** Biện pháp cô lập dựa trên tường lửa cục bộ UFW trên máy chủ đích, chưa tích hợp API của các thiết bị mạng biên hoặc tường lửa phần cứng chuyên dụng (Palo Alto, Fortinet, pfSense).

---

## 🔒 Nguyên tắc An toàn Cốt lõi (Security Principles)

1. **Deterministic Guardrails First:** Mọi quyết định can thiệp hệ thống (chặn IP, ngắt kết nối) đều phải qua mã nguồn Python xác định (Policy Engine). Không bao giờ tin tưởng tuyệt đối vào kết quả sinh ngẫu nhiên của mô hình ngôn ngữ lớn (LLM).
2. **Nguyên tắc Đặc quyền Tối thiểu (Principle of Least Privilege):** Agent chỉ được cấp quyền sudo đối với đúng 2 wrapper scripts an toàn, không được cấp quyền chạy UFW trực tiếp hay sudo toàn quyền.
3. **Structured Auditability:** Toàn bộ thao tác đều được lưu vết chi tiết với định danh chủ thể, mốc thời gian, lý do phê duyệt và kết quả kiểm chứng độc lập.

---

## 📜 Tác giả
Dự án được nghiên cứu và phát triển bởi **Ngô Duy Tiến**.
