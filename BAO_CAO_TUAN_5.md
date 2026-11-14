# 📋 BÁO CÁO TIẾN ĐỘ TUẦN 5
### Đề tài: **Xây dựng hệ thống Single-Agent AI tự trị hỗ trợ giám sát, truy vết và tự động điều phối phản ứng sự cố an ninh mạng**
**Sinh viên thực hiện:** Ngô Duy Tiến | **Thời gian:** Tuần 5 (08/11/2026 – 12/11/2026)

---

## 1. ĐANG LÀM ĐẾN ĐÂU RỒI & HỆ THỐNG VẬN HÀNH NHƯ THẾ NÀO

### 1.1. Đang làm đến đâu rồi
- **Kiến trúc Hybrid 2 Tầng:** Đã cấu trúc lại toàn bộ hệ thống, tách riêng thời gian thực và thời gian xử lý AI.
- **Bộ tương quan tấn công nhiều bước (`core/correlator.py`):** Đã hoàn thiện logic theo dõi chuỗi hành vi: *Dò mật khẩu chậm (3–5 lần) ➔ Đăng nhập SSH thành công ➔ Leo quyền sudo trái phép*. Tự động truy vết ngược ra IP tấn công ban đầu để chặn và ngắt phiên SSH.
- **Cơ chế chống chặn nhầm Admin (`ANTI-LOCKOUT GUARD`):** Đã phân biệt được giữa việc Admin gõ nhầm mật khẩu (nhịp gõ tay người, tài khoản quản trị hợp lệ) và công cụ dò quét tự động để không bao giờ tự khóa nhầm IP quản trị.
- **Kiểm thử logic & Mã nguồn:** Toàn bộ **65/65 bài kiểm thử tự động (Unit & Integration tests) đều PASS**, đạt **11/11 luật phát hiện** và an toàn tuyệt đối với rò rỉ mã bí mật.

### 1.2. Hệ thống vận hành như thế nào
Hệ thống vận hành theo quy trình phối hợp nhịp nhàng giữa 2 tầng:

1. **Tầng 1 — Ngăn chặn thời gian thực (< 0.5 giây, KHÔNG chờ AI):**
   - Khi có sự kiện an ninh từ máy chủ Ubuntu (như dò quét SSH, brute force), Wazuh gửi cảnh báo tức thì qua Webhook sang Agent.
   - Agent kiểm tra nhanh chuỗi hành vi và danh sách an toàn (Whitelist / Baseline).
   - Nếu xác định là hành vi tấn công nguy hiểm: Agent gửi lệnh chặn IP ngay lập tức bằng tường lửa UFW và ngắt phiên đăng nhập (thời gian xử lý chỉ mất **dưới 0.5 giây**).

2. **Tầng 2 — AI phân tích sâu & Báo cáo (Chạy nền bất đồng bộ ~15–20 giây):**
   - Sự kiện sau khi đã được Tầng 1 chặn xong sẽ đẩy vào hàng đợi cho mô hình AI cục bộ (`qwen3:4b`).
   - AI thực hiện nhiệm vụ điều tra: đọc nhật ký, ánh xạ kỹ thuật tấn công theo chuẩn MITRE ATT&CK, viết báo cáo phân tích sự cố và tự động gửi Gmail cảnh báo cho quản trị viên.
   - *Kết quả:* Vừa đảm bảo tốc độ phản ứng chặn đứng tấn công ngay lập tức, vừa có báo cáo thông minh từ AI mà không gây nghẽn hệ thống.



---

## 2. KẾ HOẠCH CHO TUẦN TIẾP THEO

Tuần tới sẽ tiến hành **kiểm thử trực tiếp bằng tay trên 3 máy ảo thực tế** (Kali `192.168.56.10` ➔ Ubuntu Server `192.168.56.101` ➔ Windows Agent `192.168.56.1`), không sử dụng script mô phỏng:

1. **Thử nghiệm Kịch bản 1 — Tấn công nhiều bước thực tế:**
   - Thao tác từ Kali: Gõ sai mật khẩu 4 lần (né mức cảnh báo 8 lần của Wazuh) ➔ Đăng nhập thành công ➔ Chạy `sudo su -`.
   - Đánh giá khả năng Agent xâu chuỗi sự kiện, chặn IP và ngắt phiên SSH của kẻ tấn công.
2. **Thử nghiệm Kịch bản 2 — Admin gõ nhầm mật khẩu thực tế:**
   - Thao tác từ máy quản trị: Gõ sai mật khẩu liên tiếp 8 lần bằng tay.
   - Đánh giá khả năng Agent chống chặn nhầm, đảm bảo kết nối của Admin không bị ngắt.
3. **Thử nghiệm Kịch bản 3 — Đo đạc thời gian và thu thập ảnh minh chứng:**
   - Chạy tấn công Hydra để ghi nhận thời gian thực tế: Tầng 1 kích hoạt chặn UFW (mục tiêu < 1 giây) và Tầng 2 gửi Gmail hoàn tất.
   - Chụp lại toàn bộ ảnh kết quả trực tiếp từ màn hình các máy ảo để bổ sung vào báo cáo hoàn chỉnh và slide đồ án.
