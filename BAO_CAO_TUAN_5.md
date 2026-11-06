# 📋 BÁO CÁO TIẾN ĐỘ THỰC HIỆN ĐỀ TÀI (TUẦN 5)
### Chuyên ngành: An toàn Thông tin / An ninh Mạng
### Đề tài: **Xây dựng hệ thống Single-Agent AI tự trị hỗ trợ giám sát, truy vết và tự động điều phối phản ứng sự cố an ninh mạng**

---

**Thông tin chung:**
- **Sinh viên thực hiện:** Ngô Duy Tiến
- **Giảng viên hướng dẫn:** [Điền tên Thầy / Cô hướng dẫn]
- **Thời gian báo cáo:** Tuần 5 (01/11/2026 – 07/11/2026)
- **Kho lưu trữ mã nguồn:** `d:\soc-agent` (Branch: `main` / `Tuan5`)

---

## 🎯 1. TỔNG QUAN TÌNH HÌNH & TRỌNG TÂM TUẦN 5

Trong giai đoạn chuyển tiếp từ Tuần 4 sang Tuần 5, trọng tâm kỹ thuật của đề tài đã được rà soát và tái cấu trúc sâu sắc dựa trên các góp ý chuyên môn từ Giảng viên hướng dẫn về **Kiến trúc An toàn Thông tin chuẩn Zero-Trust**:

1. **Khắc phục triệt để lỗi kiến trúc "Agent đọc trực tiếp log trên endpoint qua SSH":**
   - Loại bỏ 100% cơ chế cũ (Agent mở phiên SSH vào máy Ubuntu để chạy lệnh `tail /var/log/auth.log` hay `grep`).
   - Khẳng định vai trò độc tôn của **Wazuh SIEM All-in-One 4.9.2** là nguồn chân lý duy nhất (Single Source of Truth) trong việc thu thập, chuẩn hóa và lưu trữ nhật ký an ninh.
2. **Chuẩn hóa Mô hình Điều tra 2 Tầng (Two-Phase Investigation Pipeline):**
   - **Tầng 1 (Phân tích Alert hiện tại):** Webhook Listener tiếp nhận gói tin JSON do Wazuh đẩy sang; Agent đọc `full_log`, `rule.id`, `rule.level`, địa chỉ IP nguồn (`srcip`), tài khoản (`dstuser`), thời gian thực sự có trong cảnh báo kích hoạt.
   - **Tầng 2 (Tra cứu lịch sử & tương quan sự kiện):** Khi cần kiểm tra xem trước đó IP hoặc tài khoản này đã từng đăng nhập thành công hay có chuỗi thất bại kéo dài hay chưa, Agent gọi công cụ chỉ đọc `query_wazuh_history` để truy vấn kho lưu trữ tập trung (Alerts & Archives) của Wazuh SIEM, **hoàn toàn không chạm vào endpoint**.
3. **Làm sạch mã nguồn và tối ưu hóa thời gian thực (0s delay):**
   - Giao diện Streamlit (`app.py`) chuyển sang hiển thị luồng dữ liệu sự kiện tập trung từ Wazuh SIEM, loại bỏ hoàn toàn các nút thao tác SSH đọc log cục bộ.
   - Hệ thống đạt **54/54 bài kiểm thử tự động (PASS 100%)** và vượt qua kiểm toán an toàn mã nguồn.

---

## 🏛️ 2. MÔ HÌNH KIẾN TRÚC & LUỒNG DỮ LIỆU ĐÃ CHUẨN HÓA

> 📌 **Nguyên tắc Kiến trúc Cốt lõi (Zero-Trust SOC):**  
> *"Agent không SSH và không đọc trực tiếp log trên endpoint. Agent nhận alert do Wazuh gửi qua webhook. Khi cần điều tra lịch sử, agent yêu cầu một công cụ truy vấn chỉ đọc trên dữ liệu alert/archive của Wazuh; kết quả truy vấn cũng đến từ Wazuh."*

```
auth.log trên endpoint (Ubuntu Lab)
       │
       ▼
  Wazuh Logcollector (Đọc log nội bộ trên máy All-in-One 192.168.56.101)
       │
       ▼
  Wazuh Manager 4.9.2: giải mã (Decoders), đối chiếu ruleset, tạo alert
       ├── alert JSON ──────────► custom integration ──► listener ──► agent (Giai đoạn 1: Phân tích alert hiện tại)
       │                         (/var/ossec/integrations/               (Đọc full_log, rule, IP, user)
       │                          custom-ai-soc :5000)
       │
       └── archive sự kiện ────► Wazuh Indexer (Kho lưu trữ tập trung)
                                       ▲
                                       │ (Truy vấn lịch sử chỉ đọc)
                                 agent yêu cầu backend truy vấn lịch sử (query_wazuh_history)
```

### Chi tiết phân định luồng xử lý:
* **Gói Webhook đẩy sang:** Chứa thông tin cảnh báo tức thời vi phạm Rule (ví dụ: Rule 5712 - SSH brute-force). Trường `full_log` là dòng nhật ký thô trực tiếp kích hoạt vi phạm đó. Hệ thống không mặc định `full_log` chứa toàn bộ lịch sử trước đó của tài khoản.
* **Truy vấn lịch sử:** Công cụ `query_wazuh_history` (alias của `search_auth_logs` trong `telemetry/tools.py`) truy vấn kho lưu trữ tập trung của Wazuh (`runs/wazuh_alerts.jsonl` và archives), tổng hợp số lần vi phạm theo quy tắc, thống kê tỷ lệ thành công/thất bại để cung cấp cho Agent làm căn cứ kết luận.

---

## 🛠️ 3. CÁC HẠNG MỤC KỸ THUẬT ĐÃ HOÀN TẤT TRONG TUẦN 5

| Hạng mục | Tệp tin thực thi | Mô tả chi tiết kết quả đạt được |
| :--- | :--- | :--- |
| **Công cụ tra cứu lịch sử SIEM** | [`telemetry/tools.py`](file:///d:/soc-agent/telemetry/tools.py) | Viết lại `search_auth_logs` và tạo mới `query_wazuh_history`: Thay thế hoàn toàn lệnh `run_fixed_command(tail /var/log/auth.log)` bằng logic truy vấn kho sự kiện tập trung của Wazuh SIEM. Trả về metadata nguồn `"Wazuh SIEM Centralized Store"` và xác nhận `"direct_ssh": False`. |
| **Tối ưu hóa Prompt của Agent** | [`core/agent.py`](file:///d:/soc-agent/core/agent.py) | Cập nhật `SYSTEM_PROMPT` và danh mục công cụ cho phép `ALLOWED_ARGS`. Chỉ định rõ ràng: `full_log` là sự kiện tức thời; muốn tra cứu chuỗi sự kiện lịch sử bắt buộc phải gọi `query_wazuh_history`. Tuyệt đối cấm Agent chạy shell hay mở SSH đọc log. |
| **Chuẩn hóa Giao diện Command Center** | [`app.py`](file:///d:/soc-agent/app.py) | Xóa bỏ hàm `fetch_live_logs` (kết nối SSH đọc log cũ). Thay nút *"Quét Log Thật (SSH)"* bằng các nút tác chiến chuẩn SIEM: **"📡 Đồng Bộ Alert Wazuh"** và **"🔍 Tra Cứu Lịch Sử SIEM"**. Chuẩn hóa Terminal hiển thị luồng sự kiện Wazuh thời gian thực (0s delay). |
| **Làm sạch công cụ CLI** | [`cli.py`](file:///d:/soc-agent/cli.py) | Chuyển đổi lệnh `scan` và hàm `fetch_alerts` sang đọc trực tiếp từ kho cảnh báo Wazuh SIEM tập trung, loại bỏ lệnh gọi SSH `tail /var/log/auth.log`. |
| **Kiểm thử hồi quy tự động (Test Suite)** | `tests/` | Chạy bộ kiểm thử tự động toàn diện: **54/54 Unit tests PASS (100%)**, **11/11 Detection rules PASS**, kiểm toán an toàn mã nguồn đạt 0 lỗ hổng rò rỉ secret/key. |
| **Đồng bộ tài liệu học thuật** | [`README.md`](file:///d:/soc-agent/README.md), [`WORKLOG.md`](file:///d:/soc-agent/WORKLOG.md) | Cập nhật mô hình kiến trúc, luồng dữ liệu 2 tầng và nguyên tắc Zero-Trust để phục vụ báo cáo với Giảng viên hướng dẫn. |

---

## 📸 4. MINH CHỨNG KẾT QUẢ VẬN HÀNH & KIỂM THỬ

### 4.1. Kết quả kiểm thử tự động toàn diện (54/54 PASS)
Toàn bộ hệ thống vượt qua bộ bài kiểm thử tự động nghiêm ngặt trong 1.68s, bao gồm kiểm tra bảo mật Whitelist, kháng Prompt Injection, kiểm định cơ chế Fast-Path và độ chính xác của Policy Engine:

```
==========================================================
KIỂM THỬ BỘ QUY TẮC PHÁT HIỆN AN NINH (DETECTION RULES)
==========================================================
1. Kiểm tra log_parser nhận diện sự kiện:           [PASS 5/5]
2. Kiểm tra Rule detect_sudo_abuse:                 [PASS 3/3]
3. Kiểm tra Rule detect_baseline_account_tampering: [PASS 2/2]
4. Kiểm tra detect_all:                             [PASS 1/1]
KẾT QUẢ KIỂM THỬ: 11 PASS, 0 FAIL
----------------------------------------------------------
Ran 54 tests in 1.684s - OK
🎉 KẾT QUẢ: 100% AN TOÀN! Không phát hiện rò rỉ Secret hay Key.
```

### 4.2. Cấu trúc dữ liệu Alert thực tế tiếp nhận từ Wazuh Manager
Dữ liệu cảnh báo thực tế đẩy qua Webhook port 5000 (`runs/wazuh_alerts.jsonl`) phản ánh đúng cấu trúc Agent All-in-One:
* `agent.id`: `"001"` (`ubuntu-lab`, IP: `192.168.56.101`).
* `rule.id`: `"5710"` / `"5712"` (Mức độ: `Level 10 - High/Critical`).
* `mitre`: `T1110 - Brute Force` (`Credential Access`).
* `full_log`: Dòng log kích hoạt tức thời do Wazuh `logcollector` ghi nhận.

---

## 📅 5. KẾ HOẠCH HÀNH ĐỘNG TUẦN TIẾP THEO (TUẦN 6)

Để hoàn thiện phần thực nghiệm khoa học phục vụ cuốn Báo cáo Đồ án và buổi bảo vệ chính thức, các công việc trọng tâm trong tuần tới bao gồm:

1. **Thực nghiệm tấn công thực tế từ Kali Linux (End-to-End Live Attack Validation):**
   * Sử dụng máy ảo Kali Linux (`192.168.56.102`) bắn các đợt tấn công dò mật khẩu SSH bằng công cụ **Hydra** vào máy chủ Ubuntu Lab (`192.168.56.101`).
   * Đo đạc và thu thập chuỗi dữ liệu thực nghiệm:
     * Thời gian phát hiện (MTTD): Từ lúc Hydra bắt đầu gửi gói tin đến khi Wazuh SIEM kích hoạt Rule 5712 và bắn Webhook.
     * Thời gian điều tra & cô lập (MTTR): Từ lúc AI Agent nhận alert, thẩm định Policy Engine, đến khi UFW chặn đứng IP Kali Linux (lệnh Hydra trên Kali lập tức báo lỗi `Connection refused`).
     * Bản tin email cảnh báo gửi về Gmail.
2. **Khai thác dữ liệu Archive của Wazuh SIEM (Lưu trữ toàn bộ sự kiện):**
   * Bật cấu hình `<jsonout_output>yes</jsonout_output>` trong `/var/ossec/etc/ossec.conf` trên máy chủ Ubuntu để Wazuh Manager ghi nhận toàn bộ sự kiện vào `/var/ossec/logs/archives/archives.json`.
   * Cung cấp dữ liệu đầy đủ cho công cụ `query_wazuh_history` tra cứu cả những sự kiện không sinh alert (ví dụ: các lần đăng nhập thành công trước đó).
3. **Mở rộng thêm kịch bản tấn công đối kháng:**
   * Kịch bản quét cổng mạng (Nmap Port Scan / Reconnaissance).
   * Kịch bản can thiệp tệp tin nhạy cảm (FIM - Real-time File Integrity Monitoring trên `/etc/passwd` và `/etc/sudoers`).
4. **Tổng hợp số liệu & Soạn thảo chương Thực nghiệm trong Báo cáo:**
   * Vẽ biểu đồ ma trận nhầm lẫn (Confusion Matrix), đo lường độ chính xác (Accuracy, F1-Score) và thời gian phản ứng trung bình của AI Agent.

---
*Báo cáo được cập nhật ngày 07/11/2026 bởi sinh viên **Ngô Duy Tiến**.*
