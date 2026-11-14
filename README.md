# 🛡️ Xây dựng hệ thống Single-Agent AI tự trị hỗ trợ giám sát, truy vết và tự động điều phối phản ứng sự cố an ninh mạng



Hệ thống tác tử an ninh mạng tự trị (**Single-Agent Autonomous Cyber Security Operations**) kết hợp mô hình ngôn ngữ lớn cục bộ (**Local On-Premises LLM - Ollama**) với động cơ điều tra **ReAct (Reasoning + Acting)**, lớp kiểm soát an toàn xác định (**Deterministic Policy Engine Guardrails**), tích hợp trực tiếp với máy chủ **Wazuh SIEM All-in-One 4.9.2 (Tier 1 SOC)** nhả Alert theo thời gian thực qua **Event-Driven Webhook (Tier 2)**, thực thi phòng vệ chủ động có thời hạn trên tường lửa Linux (**UFW Active Defense với TTL 15 phút**) và tự động gửi báo động sự cố qua **Gmail SMTP**.



Hệ thống hoạt động trên môi trường triển khai thực tế 100%: Webhook được bảo vệ bằng **xác thực token (X-SOC-Token)**, mạng riêng **Host-Only (`192.168.56.0/24`)**, tiếp nhận xử lý qua **hàng đợi tuần tự (FIFO Queue)**, bóc tách và đối sánh quy tắc Wazuh, kết hợp cơ chế phân loại nhanh **Fast-Path Triage (<1ms)** cho các hành vi bảo trì hợp lệ.



---



## 🏛️ Kiến trúc Triển khai Thực tế & Luồng Dữ liệu (Real-World Architecture & Data Flow)

> **Nguyên tắc Kiến trúc Cốt lõi (Zero-Trust SOC):**  
> *"Agent không SSH và không đọc trực tiếp log trên endpoint. Agent nhận alert do Wazuh gửi qua webhook. Khi cần điều tra lịch sử, agent yêu cầu một công cụ truy vấn chỉ đọc trên dữ liệu alert/archive của Wazuh; kết quả truy vấn cũng đến từ Wazuh."*

```
auth.log trên endpoint
       │
       ▼
  Wazuh Agent / Logcollector (Đọc cục bộ tại endpoint)
       │
       ▼
  Wazuh Manager: giải mã (Decoders), đối chiếu ruleset, tạo alert
       ├── alert JSON ──────────► custom integration ──► listener ──► agent (Phân tích alert hiện tại)
       │                         (/var/ossec/integrations/               (Đọc full_log, rule, IP, user)
       │                          custom-ai-soc :5000)
       │
       └── archive sự kiện ────► Wazuh Indexer (Kho lưu trữ tập trung)
                                       ▲
                                       │ (Truy vấn lịch sử chỉ đọc)
                                 agent yêu cầu backend truy vấn lịch sử (query_wazuh_history)
```

### Kiến trúc Hybrid 2 Tầng (Real-Time Defense + Non-Real-Time LLM):
1. **Tầng 1 — Phản ứng thời gian thực (`< 0.5s`, KHÔNG chờ LLM):**
   - `integrations/wazuh_listener.py` nhận alert JSON từ Wazuh Webhook (`5710/5711/5712/5715/5760/5763/5401..5405/550/5902`), trả HTTP 200 trong `<5ms`.
   - `core/correlator.py` (**Stateful Kill-Chain Correlator + Anti-Lockout Guard**) nối chuỗi tấn công nhiều bước (*Dò mật khẩu ➔ Đăng nhập thành công ➔ Leo quyền Sudo/FIM*, kể cả *Low-and-Slow <8 lần*), truy ngược IP nguồn khi log `sudo`/`FIM` thiếu IP, đồng thời lọc không khóa nhầm Admin gõ sai mật khẩu.
   - `core/policy_engine.py` thẩm định Whitelist/Rate-limit và kích hoạt **UFW Block IP + Ngắt phiên SSH bị xâm nhập** ngay lập tức mà không đợi mô hình AI.
2. **Tầng 2 — Phân tích AI bất đồng bộ (`~15–20s`, Non-Real-Time Background Worker):**
   - `_ai_worker_loop` đưa tác vụ nặng của Local LLM (`qwen3:4b`) ra khỏi đường găng thời gian thực:
     - **Hậu kiểm sau chặn:** Phân tích chuỗi sự kiện qua `query_wazuh_history`, gắn mã MITRE ATT&CK và gửi Email HTML chi tiết về Gmail Admin.
     - **Thẩm định ca nhập nhằng (`DEFER_TO_LLM`):** Kiểm tra sâu các ca Admin nghi gõ nhầm mật khẩu để đảm bảo `0%` khóa nhầm quản trị viên.
3. **Xác nhận thành phần thu thập:** Trên máy ảo Ubuntu 24.04 All-in-One (`192.168.56.101`), Wazuh Manager tự thu thập `/var/log/auth.log` thông qua module nội bộ `logcollector` (định danh cục bộ `agent.id: 001` — `ubuntu-lab`), tuyệt đối **không SSH từ Agent để đọc log thô**.

```text
[Wazuh Alert Stream] ──► Webhook :5000 ──► [TẦNG 1: Real-Time Correlator & Policy (<10ms)]
                                               ├── Lành hợp lệ (Fast-Path) ──► Bỏ qua LLM (<1ms)
                                               ├── Admin gõ nhầm (Anti-Lockout) ──► KHÔNG chặn; đẩy Tầng 2 rà soát
                                               └── Brute Force / Multi-Step ──► Chặn UFW + Ngắt phiên NGAY (<0.5s)
                                                                                     │
                                                                                     ▼ (Hàng đợi nền)
                                                                     [TẦNG 2: Local LLM (qwen3:4b ~15s)]
                                                                     • Phân tích Kill-Chain & MITRE ATT&CK
                                                                     • Gửi Email báo cáo HTML qua Gmail SMTP
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
│   ├── correlator.py            # Bộ tương quan tấn công nhiều bước & Anti-Lockout Context Guard
│   ├── llm_client.py            # Client giao tiếp mô hình LLM cục bộ (Ollama)
│   ├── policy_engine.py         # Lớp kiểm soát an toàn xác định (Whitelist, TTL, Rate Limit, Session Containment)
│   └── schema.py                # Data Models & Converters cho SOC Command Center
├── integrations/                # Cổng tiếp nhận SIEM, Hàng đợi Hybrid & Báo động
│   ├── wazuh_listener.py        # Webhook Hybrid 2 tầng (Tầng 1 Real-Time + Tầng 2 AI Non-Real-Time)
│   ├── monitor_daemon.py        # Tiến trình giám sát an ninh tự hành liên tục
│   └── notifier.py              # Sinh báo cáo HTML và gửi thư cảnh báo qua Gmail SMTP
├── telemetry/                   # Thu thập nhật ký, bóc tách & Công cụ phản ứng an ninh
│   ├── tools.py                 # Công cụ truy vấn SIEM + Phản ứng UFW & Ngắt phiên xâm nhập
│   ├── log_parser.py            # Bóc tách cú pháp nhật ký xác thực Linux /var/log/auth.log
│   ├── read_logs.py             # Kết nối SSH cố định qua Paramiko cho wrapper phản ứng
│   └── detection.py             # Bộ quy tắc phát hiện & chữ ký lệnh sudo nguy hiểm
├── config/                      # Danh mục dữ liệu chuẩn & Ranh giới an toàn
│   └── baseline.json            # Danh sách tài khoản quản trị viên và quyền sudo hợp lệ
├── scripts/                     # Kịch bản triển khai & Đánh giá đối sánh định lượng
│   ├── setup_wazuh_integration.sh # Cấu hình Webhook trên Wazuh (bao gồm Rule 5715, 5902)
│   ├── setup_lab_guardrails.sh    # Wrapper scripts (/usr/local/sbin/soc-block-ip, soc-kill-session)
│   ├── setup_windows_firewall.ps1 # Mở cổng tường lửa Windows 5000 cho Webhook
│   ├── benchmark_wazuh.py         # Đánh giá định lượng hiệu năng và độ chính xác (40 kịch bản)
│   ├── compare_wazuh_vs_agent.py  # So sánh trực tiếp Wazuh mặc định vs AI SOC Agent Hybrid
│   └── security_audit.py          # Quét kiểm tra an toàn mã nguồn, chống rò rỉ Secret / Token
├── app.py                       # Bàn điều khiển tác chiến AI SOC Command Center (Streamlit UI)
├── cli.py                       # Giao diện dòng lệnh hợp nhất (Unified CLI)
├── BAO_CAO_TUAN_3.md            # Báo cáo tiến độ tuần 3
├── BAO_CAO_TUAN_4.md            # Báo cáo tiến độ tuần 4
└── BAO_CAO_TUAN_5.md            # Báo cáo tiến độ tuần 5 (Hybrid 2 tầng & Kế hoạch test VM thực tế)

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



#### Cách 4: Chạy Toàn Bộ Bộ Kiểm Thử An Toàn & So Sánh Với Wazuh Mặc Định

```powershell
# Chạy toàn bộ 65 Unit/Integration tests + 11 Detection rules + Security Audit
.venv\Scripts\python.exe cli.py test

# Chạy bảng so sánh định lượng: Wazuh Active Response mặc định vs AI SOC Agent Hybrid
.venv\Scripts\python.exe cli.py benchmark-compare
```

---

## 🎯 So Sánh Với Wazuh Active Response Mặc Định (Trên Bộ 16 Chuỗi Kịch Bản)

| Hệ thống | Thời gian quyết định / ngăn chặn | Tỷ lệ chặn nhầm Admin | Tỷ lệ chặn tấn công | Xử lý tấn công nhiều bước | Vị trí chạy LLM |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Wazuh Mặc Định** *(Active Response)* | **18.06 ms** *(nội bộ)* | **40.0%** *(2/5 ca)* | **62.5%** *(5/8)* | **0.0%** *(0/4)* | Không có AI |
| **AI Agent Cũ** *(Đồng bộ trước khi chặn)* | **15.42 s** *(đợi AI)* | **40.0%** *(2/5 ca)* | **62.5%** *(5/8)* | **0.0%** *(0/4)* | Chạy đồng bộ trước khi chặn |
| **AI Agent Mới** *(Hybrid 2 Tầng)* | **7.85 ms** *(logic Tầng 1)* | **0.0%** *(0/5 ca)* | **100.0%** *(8/8)* | **100.0%** *(4/4)* | Chạy nền Tầng 2 *(không làm trễ)* |

*(Ghi chú: Đo trên bộ kịch bản mô phỏng ở chế độ `test_mode`; khi thực thi trên Ubuntu thực tế Tầng 1 cộng thêm ~0.2–0.4s độ trễ SSH UFW.)*

## 🎯 Kiểm Thử Thực Nghiệm Trên Hệ Thống Thật

| STT | Kịch Bản Thử Nghiệm | Thao Tác Thực Hiện | Kết Quả Kỳ Vọng |
| :---: | :--- | :--- | :--- |
| **1** | **Bảo trì hệ thống hợp lệ** | Trên Ubuntu gõ: `sudo apt update` | **Fast-Path Triage** xử lý trong **<1ms**, không gọi LLM, không gửi email rác. |
| **2** | **Tấn công Brute Force SSH** | Từ Kali chạy Hydra nhắm `root@192.168.56.101` | Wazuh kích hoạt **Rule 5712**, Tầng 1 chặn IP UFW tức thì (**<1s**), Tầng 2 LLM phân tích nền & gửi Gmail. |
| **3** | **Tấn công nhiều bước (Kill-Chain)** | Dò pass 4–5 lần ➔ Login thành công (`5715`) ➔ `sudo su -` | `KillChainCorrelator` nối 3 bước (kể cả khi log sudo thiếu IP), **chặn IP + ngắt phiên SSH**. |
| **4** | **Admin gõ nhầm mật khẩu (Anti-Lockout)** | `admin_duytien` gõ sai pass 8 lần (`Rule 5763`) với nhịp tay người | **Không tự khóa nhầm Admin (`0%` FP)**, đẩy sang Tầng 2 LLM thẩm định ngữ cảnh. |
| **5** | **Chống tự khóa & Mở khóa TTL** | Thử chặn IP Host Windows `192.168.56.1` hoặc chờ hết TTL 15 phút | **Policy Engine từ chối 100%** IP quản trị; IP tấn công tự gỡ chặn sau 15 phút. |



---



## 🔒 Nguyên Tắc An Toàn Cốt Lõi



1. **Deterministic Guardrails First:** Mọi quyết định can thiệp tường lửa phải qua mã Python xác định (Policy Engine). Tuyệt đối không giao quyền thực thi trực tiếp cho đầu ra ngẫu nhiên của LLM.

2. **Đặc Quyền Tối Thiểu (Principle of Least Privilege):** Agent chỉ được gọi wrapper scripts an toàn được cấu hình sẵn, không có quyền chạy lệnh `ufw` tùy tiện hay tắt tường lửa.

3. **Structured Auditability:** 100% quyết định và hành động đều được ghi nhật ký kiểm toán minh bạch tại `runs/action_audit.log` và `runs/audit_trail.jsonl`.

4. **Data Privacy (On-Premises):** Chạy mô hình ngôn ngữ lớn nội bộ qua Ollama, bảo vệ toàn vẹn dữ liệu an ninh mạng của tổ chức.



---



## 📜 Tác Giả & Bản Quyền

Dự án được nghiên cứu và phát triển bởi **Ngô Duy Tiến**

