# 📋 BÁO CÁO TIẾN ĐỘ TUẦN 5
### Đề tài: **Xây dựng hệ thống Single-Agent AI tự trị hỗ trợ giám sát, truy vết và tự động điều phối phản ứng sự cố an ninh mạng**
**Sinh viên:** Ngô Duy Tiến | **Thời gian:** Tuần 5 (08/11/2026 – 12/11/2026)

---

## 1. TRỌNG TÂM CẢI TIẾN THEO GÓP Ý GIẢNG VIÊN

Sau nhận xét của Giảng viên về việc **Wazuh đã có sẵn Active Response** và **Local LLM phản hồi chậm**, hệ thống được nâng cấp hoàn toàn theo hướng sau:

1. **Đặt Local LLM ở bước KHÔNG cần thời gian thực (Kiến trúc Hybrid 2 Tầng):**
   - **Tầng 1 (Thời gian thực `< 0.5s`, KHÔNG chờ AI):** Tương quan chuỗi sự kiện ➔ Kiểm tra Policy Whitelist / Chống chặn nhầm ➔ Thực thi chặn UFW ngay lập tức.
   - **Tầng 2 (Chạy nền bất đồng bộ `~15–20s`):** Local LLM (`qwen3:4b`) chạy ở hàng đợi nền để điều tra sâu, ánh xạ MITRE ATT&CK, xử lý các ca nhập nhằng và gửi Email báo cáo — **không làm trễ thời gian chặn**.
2. **Xử lý tấn công nhiều bước (vượt trội hơn Wazuh Active Response):**
   - Bổ sung bộ tương quan trạng thái `core/correlator.py` theo dõi chuỗi thời gian cho từng cặp `(IP, User)`:
     **Bước 1:** Dò mật khẩu *(bắt được cả kiểu tấn công chậm 3–5 lần né ngưỡng 8 lần của Wazuh)* ➔ **Bước 2:** Đăng nhập SSH thành công (`Rule 5715` - xác định xâm nhập) ➔ **Bước 3:** Leo quyền `sudo` (`5402/5404/5405`) hoặc sửa file hệ thống (`550`).
   - Tự động **truy ngược lại IP nguồn** kể cả khi log `sudo`/`FIM` không chứa IP, đồng thời **chặn IP + ngắt phiên SSH** của tài khoản bị xâm nhập.
3. **Chống chặn nhầm (Anti-Lockout Context Guard):**
   - Phân biệt **Admin gõ nhầm mật khẩu** *(tài khoản hợp lệ trong `baseline.json`, 1 user duy nhất, không quét user lạ, nhịp gõ tay con người)* với **công cụ Brute Force tự động** *(Hydra tốc độ cao, quét user không tồn tại, đa tài khoản)*.
   - Khi Admin gõ sai SSH 8 lần (`Rule 5763`) hoặc gõ nhầm `sudo` 3 lần (`Rule 5404`), hệ thống **không tự khóa nhầm IP** mà chuyển sang Tầng 2 kiểm tra ngữ cảnh.

---

## 2. KẾT QUẢ BƯỚC ĐẦU & SO SÁNH VỚI WAZUH MẶC ĐỊNH (MÔI TRƯỜNG MÔ PHỎNG)

> Ghi chú: Số liệu dưới đây đo bước kiểm thử cấu trúc bằng bộ 16 chuỗi kịch bản (`scripts/compare_wazuh_vs_agent.py`, bật `test_mode` mô phỏng lệnh UFW). Toàn bộ các ca thực tế sẽ được chạy kiểm chứng trực tiếp trên máy ảo vào bước kế tiếp.

| Hệ thống | Thời gian quyết định / ngăn chặn | Tỷ lệ chặn nhầm Admin | Tỷ lệ chặn tấn công | Xử lý tấn công nhiều bước | Vị trí chạy LLM |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Wazuh Mặc Định** *(Active Response)* | **18.06 ms** *(nội bộ)* | **40.0%** *(2/5 ca)* | **62.5%** *(5/8)* | **0.0%** *(0/4)* | Không có AI |
| **AI Agent Cũ** *(Đồng bộ trước khi chặn)* | **15.42 s** *(đợi AI)* | **40.0%** *(2/5 ca)* | **62.5%** *(5/8)* | **0.0%** *(0/4)* | Chạy đồng bộ trước khi chặn |
| **AI Agent Mới** *(Hybrid 2 Tầng)* | **7.85 ms** *(logic Tầng 1)* | **0.0%** *(0/5 ca)* | **100.0%** *(8/8)* | **100.0%** *(4/4)* | Chạy nền Tầng 2 *(không làm trễ)* |

- **Kiểm thử phần mềm:** Đạt **65/65 Unit/Integration tests PASS**, **11/11 Detection rules PASS**, và **0 lỗ hổng rò rỉ Secret** (`security_audit.py`).

---

## 3. KẾ HOẠCH KIỂM THỬ THỰC TẾ TRÊN MÁY ẢO (KHÔNG DÙNG SCRIPT)

Thay vì chạy bằng script giả lập, các kịch bản thực tế trên 3 máy **(Kali `192.168.56.10` ➔ Ubuntu Server/Wazuh `192.168.56.101` ➔ Windows Agent `192.168.56.1`)** sẽ được thực hiện thủ công bằng tay như sau:

### Bước chuẩn bị trên Ubuntu & Windows:
- Cập nhật tích hợp Wazuh trên Ubuntu (`scripts/setup_wazuh_integration.sh` hoặc thêm `5715,5902` vào `<rule_id>` trong `/var/ossec/etc/ossec.conf` rồi `sudo systemctl restart wazuh-manager`) để đẩy thêm sự kiện đăng nhập SSH thành công `5715` sang Webhook.
- Chạy lại `sudo bash scripts/setup_lab_guardrails.sh` trên Ubuntu để kích hoạt wrapper ngắt phiên `/usr/local/sbin/soc-kill-session`.
- Khởi động Agent trên Windows: `python cli.py listen`.

### 3 Kịch bản kiểm thử thực tế cần thực hiện & chụp ảnh minh chứng:

1. **Kịch bản 1 — Tấn công nhiều bước thật (Dò pass ➔ Đăng nhập thành công ➔ Leo quyền):**
   - Từ Kali: Gõ SSH sai mật khẩu user thật (`testuser` hoặc `ubuntu`) 4–5 lần *(cố ý dưới ngưỡng 8 lần của Wazuh)* ➔ lần tiếp theo nhập **đúng mật khẩu** để đăng nhập ➔ chạy lệnh `sudo su -` hoặc `sudo cat /etc/shadow`.
   - **Mục tiêu kiểm chứng:** Dù Wazuh Active Response không phát hiện do chưa tới 8 lần sai, SOC Agent vẫn nối được 3 bước, **chặn IP Kali trên UFW + ngắt phiên SSH** và gửi Email báo cáo đầy đủ kill-chain.

2. **Kịch bản 2 — Kịch bản lành dễ chặn nhầm thật (Admin gõ sai mật khẩu):**
   - Đảm bảo IP máy đang thao tác đã được gỡ khỏi UFW. Dùng tài khoản quản trị thật trong baseline (`admin_duytien@192.168.56.101`), **tự gõ nhầm mật khẩu bằng tay 8 lần liên tiếp** (mỗi lần cách nhau ~3s để kích hoạt Wazuh `Rule 5763 Level 10`), sau đó gõ đúng mật khẩu đăng nhập và chạy `sudo /usr/bin/apt update`.
   - **Mục tiêu kiểm chứng:** Chứng minh Agent **không khóa nhầm Admin** như Wazuh mặc định, giữ kết nối quản trị thông suốt (`0%` chặn nhầm).

3. **Kịch bản 3 — Tấn công Brute Force tốc độ cao (Đo độ trễ Tầng 1 vs Tầng 2):**
   - Từ Kali chạy thật: `hydra -l root -P /usr/share/wordlists/fasttrack.txt ssh://192.168.56.101 -t 4`.
   - **Mục tiêu kiểm chứng:** Ghi lại timestamp thực tế chứng minh Tầng 1 chặn UFW ngay lập tức (**dưới 1 giây** kể từ lúc `Rule 5712` nổ), còn Tầng 2 LLM tiếp tục chạy nền ~15–20s sau đó mới gửi Email báo cáo.
