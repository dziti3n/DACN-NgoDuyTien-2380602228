# 🛡️ Xây dựng hệ thống Single-Agent AI tự trị hỗ trợ giám sát, truy vết và tự động điều phối phản ứng sự cố an ninh mạng



Hệ thống tác tử an ninh mạng tự trị (**Single-Agent Autonomous Cyber Security Operations**) kết hợp mô hình ngôn ngữ lớn cục bộ (**Local On-Premises LLM - Ollama**) với động cơ điều tra **ReAct (Reasoning + Acting)**, lớp kiểm soát an toàn xác định (**Deterministic Policy Engine Guardrails**), tích hợp trực tiếp với máy chủ **Wazuh SIEM All-in-One 4.9.2 (Tier 1 SOC)** nhả Alert theo thời gian thực qua **Event-Driven Webhook (Tier 2)**, thực thi phòng vệ chủ động có thời hạn trên tường lửa Linux (**UFW Active Defense với TTL 15 phút**) và tự động gửi báo động sự cố qua **Gmail SMTP**.



Hệ thống hoạt động trên môi trường triển khai thực tế 100%: Webhook được bảo vệ bằng **xác thực token (X-SOC-Token)**, mạng riêng **Host-Only (`192.168.56.0/24`)**, tiếp nhận xử lý qua **hàng đợi tuần tự (FIFO Queue)**, bóc tách và đối sánh quy tắc Wazuh, kết hợp cơ chế phân loại nhanh **Fast-Path Triage (<1ms)** cho các hành vi bảo trì hợp lệ.



---



## 🏛️ Kiến trúc Triển khai Thực tế (Real-World Architecture)



```

┌─────────────────────────────────────────────────────────────────────────────────┐

│              1. MÁY ẢO UBUNTU SERVER 24.04 (SOC LAB & WAZUH SIEM - 192.168.56.101)│

│                                                                                 │

│  • Wazuh SIEM All-in-One 4.9.2 (Manager + Indexer + Web Dashboard Port 443)    │

│  • Nguồn nhật ký: /var/log/auth.log, Syslog, Journald, Auditd                  │

│  • Wazuh Detection Rules Engine (Rule 5710, 5712, 5760, 5401, 5402, 550...)     │

│  • Custom Webhook Integration (/var/ossec/integrations/custom-ai-soc)           │

│                                      │                                          │

│                                      ▼ HTTP POST (Token Auth, Port 5000)        │

├─────────────────────────────────────────────────────────────────────────────────┤

│              2. MÁY HOST WINDOWS 11 (AI SOC COMMAND CENTER - 192.168.56.1)       │

│                                                                                 │

│  ┌─────────────────────────┐         ┌───────────────────────────────────────┐  │

│  │    wazuh_listener.py    │         │    agent.py (ReAct Investigation)     │  │

│  │    • Webhook Token Auth │         │    • Local Ollama (qwen3:4b, seed=42) │  │

│  │    • SOAR Loop Filter   │ ──────> │    • Điều tra chuỗi sự kiện thực tế   │  │

│  │    • Fast-Path (<1ms)   │ Alert   │    • Đóng gói <untrusted_tool_output> │  │

│  │    • FIFO Queue Worker  │         │    • 6 công cụ trinh sát chỉ đọc      │  │

│  └─────────────────────────┘         └───────────────────┬───────────────────┘  │

│               │                                          │                      │

│               ▼ Ghi nhận                                 ▼ Đề xuất phản ứng     │

│  ┌─────────────────────────┐         ┌───────────────────────────────────────┐  │

│  │    runs/wazuh_alerts    │         │    policy_engine.py (Guardrails)      │  │

│  │    • Alert Stream JSONL │         │    • Protected IP Whitelist           │  │

│  │    • Audit Trail        │         │    • Anti-Prompt Injection Validator  │  │

│  │    • Active Blocks & TTL│         │    • Rate Limiting (Tối đa 5 lần/giờ) │  │

│  └─────────────────────────┘         │    • Quản lý thời hạn TTL 15 phút     │  │

│                                      └───────────────────┬───────────────────┘  │

│                                                          │                      │

│               ┌──────────────────────────────────────────┴────────────────┐     │

│               ▼ Gửi báo động HTML                         ▼ Thực thi SSH  │     │

│  ┌─────────────────────────┐         ┌────────────────────────────────┐   │     │

│  │    notifier.py          │         │    tools.py (Active Defense)   │   │     │

│  │    • Gmail SMTP 587     │         │    • /usr/local/sbin/soc-block │   │     │

│  │    • HTML Alert Report  │         │    • Cô lập IP UFW có thời hạn │   │     │

│  │    • Ngưỡng lọc báo bão │         │    • Tự động mở khóa sau 15p   │   │     │

│  └─────────────────────────┘         └────────────────────────────────┘   │     │

│                                                                                 │

│  ┌───────────────────────────────────────────────────────────────────────────┐  │

│  │  app.py: Giao Diện Bàn Điều Khiển AI SOC (Streamlit Dark Console 50% / 50%)│  │

│  │  • Cyber Terminal Live Streamer    • Hàng đợi sự cố thực tế từ Wazuh      │  │

│  │  • Trực quan hóa suy luận ReAct    • Thẩm định Policy & Bảng điều khiển UFW│  │

│  └───────────────────────────────────────────────────────────────────────────┘  │

└─────────────────────────────────────────────────────────────────────────────────┘

```



---



## ✨ Tính Năng Nổi Bật Đã Hoàn Thiện



### 1. Tích Hợp Máy Chủ Wazuh SIEM 4.9.2 Thực Tế (Event-Driven SIEM Push)

- Triển khai thành công cụm **Wazuh All-in-One** (Wazuh Manager, Indexer, Dashboard) trên máy ảo Ubuntu 24.04 (`192.168.56.101`).

- Quản trị giao diện Web SIEM an toàn tại `https://192.168.56.101:443`.

- Bắn sự kiện an ninh tự động từ Wazuh sang AI SOC Agent thông qua **Custom Webhook Integration** (`/var/ossec/integrations/custom-ai-soc`) với mã xác thực Token bí mật (`X-SOC-Token`).

- Tốc độ phản hồi HTTP tiếp nhận sự kiện: **< 5ms** nhờ hàng đợi FIFO Queue xử lý bất đồng bộ.



### 2. Bộ Lọc Fast-Path Triage (Tier 1.5 - Xử lý trong < 1ms)

- Cơ chế phân loại xác định tức thì dựa trên Whitelist an toàn nghiêm ngặt (`ALLOWED_SUDO_EXACT_COMMANDS = {"/usr/bin/apt update", "/usr/sbin/ufw status"}`).

- Khi quản trị viên thực hiện lệnh bảo trì hợp lệ (`sudo apt update`), hệ thống kết luận `benign_likely` chỉ trong **0.3ms**, giải phóng hoàn toàn tài nguyên GPU/CPU, không kích hoạt LLM và không gây bão email rác.



### 3. Cơ Chế Triệt Tiêu Vòng Lặp Phản Hồi (SOAR Telemetry Loop Prevention)

- Khắc phục triệt để hiện tượng **SOAR Observer Effect**: Khi AI Agent chạy lệnh điều tra trên máy chủ Linux bằng tài khoản `agent_soc` (`sudo ufw status`), Wazuh phát hiện lệnh sudo và kích hoạt Rule 5402.

- Hệ thống tự động nhận diện và bỏ qua 100% telemetry nội bộ từ `agent_soc`, ngăn chặn hoàn toàn vòng lặp tự kích hoạt vô hạn.

- Đặt ngưỡng gửi email báo động: Chỉ gửi thư Gmail khi xác định mối đe dọa thực sự (`malicious_activity_likely`, `suspicious_needs_more_data`), khi thực thi chặn IP hoặc cấp độ cảnh báo $\ge 7$.



### 4. Điều Tra Tác Tử ReAct Cục Bộ (Local Ollama - Zero Data Leakage)

- Vận hành hoàn toàn Offline trên máy tính cá nhân qua **Local Ollama** (mô hình `qwen3:4b` hoặc `deepseek-r1:7b` / `qwen2.5:7b`).

- Dữ liệu an ninh nhạy cảm không bao giờ bị rò rỉ ra ngoài Internet.

- Động cơ ReAct thực hiện chu trình lặp: Suy luận (Thought) $\rightarrow$ Gọi công cụ trinh sát (Action) $\rightarrow$ Đọc chứng cứ (Observation) $\rightarrow$ Đưa ra kết luận có cấu trúc (Verdict, Severity, Confidence, Evidence).

- Toàn bộ dữ liệu nhật ký hệ thống đều được bọc trong thẻ an toàn `<untrusted_tool_output>` để triệt tiêu tấn công **Indirect Prompt Injection**.



### 5. Lớp Kiểm Soát Chính Sách Xác Định (Deterministic Policy Engine Guardrails)

Mã Python độc lập thẩm định mọi hành động đề xuất trước khi can thiệp vào máy chủ:

- **Protected IP Whitelist (Chống Tự Khóa):** Nghiêm cấm chặn IP máy Host Windows (`192.168.56.1`), IP Máy chủ (`192.168.56.101`), Gateway (`10.0.2.2`) hay Loopback (`127.0.0.1`).

- **Giới Hạn Tần Suất (Rate Limiting):** Tối đa 5 lần chặn/giờ nhằm chống tấn công làm cạn kiệt tài nguyên tường lửa.

- **Quản Lý Thời Hạn Cách Ly (TTL 15 Phút):** IP tấn công chỉ bị cô lập trong 15 phút. Hệ thống tự động theo dõi và gỡ bỏ luật khi hết hạn, tránh phình to bảng luật UFW.



### 6. Báo Cáo Sự Cố Trực Quan Qua Gmail SMTP

- Sinh bản tin cảnh báo chuẩn HTML chuyên nghiệp với giao diện Dark Mode, hiển thị chi tiết mã luật Wazuh, IP nguồn, tài khoản đích, bằng chứng xác thực và trạng thái cô lập UFW.

- Tự động lưu bản tin dự phòng tại thư mục `runs/alerts/` phục vụ kiểm toán offline.



---



## 📁 Cấu Trúc Thư Mục Dự Án



```text

soc-agent/

├── core/                        # Trọng tâm AI SOC Agent & Lớp an toàn xác định

│   ├── agent.py                 # Động cơ điều tra ReAct, System Prompt & trích xuất kết luận

│   ├── llm_client.py            # Client giao tiếp mô hình LLM cục bộ (Ollama)

│   └── policy_engine.py         # Lớp kiểm soát an toàn xác định (Whitelist, TTL, Rate Limit)

│

├── integrations/                # Cổng tiếp nhận SIEM, Giám sát tự hành & Báo động

│   ├── wazuh_listener.py        # Webhook Server đón nhận Alert từ Wazuh & Fast-Path Triage

│   ├── monitor_daemon.py        # Tiến trình giám sát an ninh tự hành liên tục

│   └── notifier.py              # Sinh báo cáo HTML và gửi thư cảnh báo qua Gmail SMTP

│

├── telemetry/                   # Thu thập nhật ký, bóc tách & Công cụ phản ứng an ninh

│   ├── tools.py                 # 6 Công cụ trinh sát chỉ đọc + 4 Công cụ phản ứng UFW

│   ├── log_parser.py            # Bóc tách cú pháp nhật ký xác thực Linux /var/log/auth.log

│   ├── read_logs.py             # Kết nối SSH cố định qua Paramiko

│   └── detection.py             # Bộ quy tắc phát hiện cảnh báo dự phòng cục bộ

│

├── config/                      # Danh mục dữ liệu chuẩn & Ranh giới an toàn

│   └── baseline.json            # Danh sách tài khoản người dùng và nhóm quyền hợp lệ

│

├── scripts/                     # Kịch bản triển khai & Cấu hình máy chủ

│   ├── setup_wazuh_integration.sh # Cấu hình Webhook Integration trên Wazuh Manager

│   ├── setup_lab_guardrails.sh    # Phân quyền sudoers tối thiểu & Wrapper scripts trên Ubuntu

│   ├── setup_windows_firewall.ps1 # Mở cổng tường lửa Windows 5000 cho Webhook

│   ├── benchmark_wazuh.py         # Đánh giá định lượng hiệu năng và độ chính xác

│   └── security_audit.py        # Quét kiểm tra an toàn mã nguồn, chống rò rỉ Secret / Token

│

├── app.py                       # Bàn điều khiển tác chiến AI SOC Command Center (Streamlit UI)

├── cli.py                       # Giao diện dòng lệnh hợp nhất (Unified CLI)

├── requirements.txt             # Danh mục thư viện Python

├── .env.example                 # File mẫu biến môi trường

├── .gitignore                   # Cấu hình loại trừ file rác & dữ liệu nội bộ

├── README.md                    # Tài liệu dự án

├── WORKLOG.md                   # Sổ tay tiến độ và hướng dẫn thao tác

└── BAO_CAO_TUAN_3.md            # Báo cáo tiến độ tuần 3 cho giảng viên hướng dẫn

```



---



## 🚀 Hướng Dẫn Vận Hành Hệ Thống Thực Tế



### 1. Chuẩn Bị Môi Trường

- **Máy Host (Windows 11):** Cài đặt Python 3.10+, VirtualBox và Ollama (`ollama run qwen3:4b`).

- **Máy Lab (Ubuntu 24.04 VM):** Đã cài đặt Wazuh All-in-One 4.9.2 (IP `192.168.56.101`).



### 2. Cài Đặt Thư Viện Python

```powershell

python -m venv .venv

.venv\Scripts\Activate.ps1

pip install -r requirements.txt

```



### 3. Cấu Hình File `.env`

Tạo file `.env` tại thư mục gốc với các thông số thực tế:

```ini

LLM_PROVIDER=ollama

OLLAMA_BASE_URL=http://127.0.0.1:11434/v1

OLLAMA_MODEL=qwen3:4b

OLLAMA_SEED=42

OLLAMA_TEMPERATURE=0.0



# Kết nối SSH tới máy chủ Ubuntu Lab

SSH_HOST=192.168.56.101

SSH_PORT=22

SSH_USER=agent_soc

SSH_KEY_PATH=~/.ssh/soc_agent_key



# Cấu hình Webhook Listener đón nhận Alert từ Wazuh

WEBHOOK_HOST=192.168.56.1

WEBHOOK_PORT=5000

WEBHOOK_AUTH_TOKEN=<CHÈN_AUTH_TOKEN_32_BYTES_TẠI_ĐÂY>



# Cấu hình Gửi Email Cảnh Báo Gmail SMTP

ALERT_EMAIL_ENABLED=true

SMTP_SERVER=smtp.gmail.com

SMTP_PORT=587

SENDER_EMAIL=your_email@gmail.com

SENDER_APP_PASSWORD=your_16_digit_app_password

RECIPIENT_EMAIL=your_recipient@gmail.com

```



### 4. Khởi Chạy Hệ Thống Thực Tế



#### Cách 1: Khởi Chạy Webhook Receiver Lắng Nghe Wazuh SIEM

Mở PowerShell trên máy Windows và chạy:

```powershell

.venv\Scripts\python.exe cli.py listen --host 192.168.56.1 --port 5000

```

*Hệ thống sẽ lắng nghe các cảnh báo đẩy về từ Wazuh SIEM trên Ubuntu, tự động kích hoạt điều tra ReAct, thẩm định Policy, cách ly UFW và gửi email Gmail.*



#### Cách 2: Khởi Chạy Giao Diện Bàn Điều Khiển Web (Streamlit UI)

Mở cửa sổ PowerShell khác và chạy:

```powershell

.venv\Scripts\python.exe cli.py ui

```

*Truy cập trình duyệt tại `http://localhost:8501` để theo dõi Cyber Terminal, hàng đợi sự cố thực tế từ Wazuh, luồng suy luận của AI và điều khiển tường lửa UFW.*



#### Cách 3: Kiểm Tra Gửi Email Gmail SMTP Thật

```powershell

.venv\Scripts\python.exe cli.py test-email

```



#### Cách 4: Chạy Toàn Bộ Bộ Kiểm Thử An Toàn (54 Tests)

```powershell

.venv\Scripts\python.exe cli.py test

```



---



## 🎯 Kiểm Thử Thực Nghiệm Trên Hệ Thống Thật



| STT | Kịch Bản Thử Nghiệm | Thao Tác Thực Hiện | Kết Quả Thực Tế |

| :---: | :--- | :--- | :--- |

| **1** | **Bảo trì hệ thống hợp lệ** | Trên Ubuntu gõ: `sudo apt update` | **Fast-Path Triage** xử lý trong **0.3ms**, không gọi LLM, không gửi email rác. |

| **2** | **Tấn công dò mật khẩu SSH** | Từ Windows gõ: `ssh hacker@192.168.56.101` (nhập sai pass) | Wazuh kích hoạt **Rule 5710/5712**, AI ReAct điều tra, UFW cô lập IP trong 15 phút, gửi 1 email báo động HTML. |

| **3** | **Tấn công leo quyền trái phép** | Tạo user thường trên Ubuntu và gõ `sudo ls /root` | Wazuh bắt **Rule 5405** (User not in sudoers), Agent đánh giá mức độ High và ghi nhận chứng cứ. |

| **4** | **Kiểm tra chống tự khóa (Anti-Lockout)** | Đề xuất chặn IP máy Host `192.168.56.1` hoặc máy Lab | **Policy Engine từ chối 100%**, bảo vệ hệ thống không bao giờ bị mất kết nối quản trị. |

| **5** | **Tự động mở khóa TTL** | Chờ hết 15 phút sau khi một IP bị chặn | Scheduler tự động gỡ luật trên UFW, cập nhật trạng thái `unblocked` vào audit trail. |



---



## 🔒 Nguyên Tắc An Toàn Cốt Lõi



1. **Deterministic Guardrails First:** Mọi quyết định can thiệp tường lửa phải qua mã Python xác định (Policy Engine). Tuyệt đối không giao quyền thực thi trực tiếp cho đầu ra ngẫu nhiên của LLM.

2. **Đặc Quyền Tối Thiểu (Principle of Least Privilege):** Agent chỉ được gọi wrapper scripts an toàn được cấu hình sẵn, không có quyền chạy lệnh `ufw` tùy tiện hay tắt tường lửa.

3. **Structured Auditability:** 100% quyết định và hành động đều được ghi nhật ký kiểm toán minh bạch tại `runs/action_audit.log` và `runs/audit_trail.jsonl`.

4. **Data Privacy (On-Premises):** Chạy mô hình ngôn ngữ lớn nội bộ qua Ollama, bảo vệ toàn vẹn dữ liệu an ninh mạng của tổ chức.



---



## 📜 Tác Giả & Bản Quyền

Dự án được nghiên cứu và phát triển bởi **Ngô Duy Tiến**

