# Original User Request

## 2026-10-23T14:10:46Z

This is a single self-contained fix; keep it small and focused.

Tái thiết kế giao diện Web Dashboard của AI SOC Agent (app.py) thành Trung Tâm Chỉ Huy Hợp Nhất Trên 1 Màn Hình (Unified Single-Screen SOC Command Center). Tích hợp bộ xem trực tiếp nhật ký log (Cyber Terminal Log Viewer), nút kích hoạt bài test mô phỏng và nút quét liên tục kèm nút dừng lại, hiển thị toàn bộ tiến trình điều tra AI và phản ứng tường lửa/email trong cùng một khung nhìn trực quan.

Working directory: d:\soc-agent
Integrity mode: development

## Requirements

### R1. Màn Hình Chỉ Huy Hợp Nhất Trên Cùng Một Khung Nhìn (Single-Screen Layout)
Thiết kế lại giao diện chính của `app.py` với bố cục chia 2 cột đối xứng (50% / 50%) trên cùng một màn hình, giúp người vận hành không cần chuyển qua lại giữa nhiều tab rời rạc:
- **Cột Trái (Phía Giám Sát & Điều Khiển):** Khung xem nhật ký trực tiếp (Live Log Terminal) và Cụm phím điều khiển (Bắt đầu quét, Chạy test, Dừng lại).
- **Cột Phải (Phía AI Điều Tra & Phản Ứng):** Tiến trình suy luận AI ReAct thời gian thực, Kết luận thẩm định Policy Engine, Trạng thái cách ly tường lửa UFW và Trạng thái thông báo Email Gmail.

### R2. Cyber Terminal Live Log Viewer
Tích hợp khung xem nhật ký `/var/log/auth.log` trực tiếp từ máy chủ Linux lab qua kết nối SSH:
- Giao diện phong cách Cyber Console (nền đen `#0b0f19`, chữ monospace sáng màu, khung viền bo góc).
- Hiển thị 50 - 200 dòng log xác thực mới nhất kèm thanh cuộn mượt mà.
- Tích hợp ô lọc nhanh theo địa chỉ IP hoặc tên User và nút "🔄 Cập nhật Log".

### R3. Bộ Điều Khiển Chạy Test & Quét Trực Tiếp Trên Web (Không Dùng Terminal)
Cung cấp các nút điều khiển trực tiếp trên web:
- **Nút "🧪 Chạy Test Mô Phỏng":** Tự động khởi chạy kịch bản tấn công mẫu (SSH Bruteforce từ `192.168.56.102`), kích hoạt quy trình AI ReAct điều tra, thẩm định qua Policy Engine, và tự động gửi email cảnh báo về Gmail mà không cần gõ lệnh terminal.
- **Nút "⚡ Bắt Đầu Quét Liên Tục":** Khởi chạy vòng lặp giám sát định kỳ tự động (chu kỳ 20s) ngay trên web.
- **Chuyển đổi trạng thái trực quan:** Khi đang quét/test, giao diện chuyển sang trạng thái "🟡 ĐANG QUÉT & ĐIỀU TRA..." với hiệu ứng spinner động.

### R4. Nút "🛑 Dừng Lại" (Stop/Cancel Control)
Khi hệ thống đang ở trạng thái quét hoặc đang chạy bài test, xuất hiện nút "🛑 Dừng Lại" màu đỏ nổi bật. Khi người dùng bấm nút:
- Ngắt tiến trình quét an toàn.
- Chuyển trạng thái về "🟢 SẴN SÀNG (IDLE)".
- Giữ nguyên các kết quả điều tra và nhật ký log đã thu thập được trước đó để người dùng quan sát.

## Acceptance Criteria

### Giao diện & Trực quan (UI/UX)
- [ ] Giao diện Web hiển thị toàn bộ luồng nghiệp vụ trên cùng 1 màn hình chia 2 cột cân đối.
- [ ] Khung Live Log hiển thị các dòng log thực tế từ máy chủ `192.168.56.101` với phong cách terminal đen đẹp mắt.
- [ ] Có nút kích hoạt bài Test mô phỏng trực tiếp trên web; khi bấm, giao diện lập tức chuyển sang trạng thái "Đang quét & điều tra".
- [ ] Có nút "Dừng lại" màu đỏ để hủy hoặc dừng quét bất kỳ lúc nào.
- [ ] Quá trình AI ReAct điều tra từng bước (Live Status) hiển thị song song ngay bên cột phải.
- [ ] Sau khi test hoàn tất, thông báo trạng thái gửi email và cách ly IP hiển thị rõ ràng trên màn hình.

### Độ tin cậy & An toàn
- [ ] Không có lỗi cú pháp Python (`python -m py_compile app.py` thành công).
- [ ] Không làm gián đoạn các tính năng cũ (Whitelist, Policy Engine, Notifier).
- [ ] Dừng tiến trình không gây lỗi crash hoặc treo ứng dụng Streamlit.


## 2026-10-23T16:31:01Z

This is a single self-contained UI/UX refactoring and real-time streaming upgrade for the AI SOC Agent web interface (`app.py`); keep it small and focused.

Tái thiết kế toàn diện giao diện Web Command Center (`app.py`) theo phong cách **Stealth Cyber Ops (Electric Blue & Dark Violet)**: Đảm bảo giao diện vừa vặn hoàn hảo trong đúng **1 màn hình duy nhất (100vh, tuyệt đối không xuất hiện thanh cuộn trang chính kéo lên kéo xuống)**. Tích hợp cơ chế truyền phát nhật ký log thời gian thực tự động **chu kỳ 2 giây/lần** bằng `@st.fragment` không cần bấm nút reset/cập nhật, với thứ tự hiển thị **dòng log mới nhất luôn nằm ở trên cùng** để người vận hành quan sát tức thời.

Working directory: d:\soc-agent
Integrity mode: development

CRITICAL CONSTRAINTS:
1. TUYỆT ĐỐI KHÔNG TỰ TIỆN CHẠY GIT COMMIT HOẶC GIT PUSH (Người dùng sẽ tự push sau khi kiểm tra).
2. Duy trì 100% hoạt động cục bộ (Local Ollama qwen3:4b), không sử dụng Cloud API bên ngoài.
3. Giữ nguyên tốc độ suy luận nhanh (~9s) đã được tối ưu ở Phiên 10, không làm hỏng Policy Engine, UFW Wrapper, Gmail SMTP hay test suite.

## Requirements

### R1. Thiết Kế Chuẩn 1 Màn Hình Duy Nhất (Strict 100vh No-Scroll Viewport)
- Can thiệp CSS (`overflow: hidden; max-height: 100vh;` trên container chính của Streamlit), đảm bảo thanh cuộn trình duyệt của cả trang không bao giờ xuất hiện ("vừa đủ 1 trang k kéo lên kéo xuống").
- Phân bổ tỷ lệ chiều cao chính xác:
  - Header & Telemetry HUD bar: ~65px.
  - Cột Trái (Giám sát & Điều khiển): Cụm nút tác chiến (~45px) + Cyber Terminal Log (~460px) + Incident Badge Queue (~80px).
  - Cột Phải (AI Điều Tra & Tác Chiến): Khung HUD thẻ cuộn nội bộ mượt mà (`overflow-y: auto; max-height: calc(100vh - 170px); scrollbar-width: thin;`).

### R2. Cơ Chế Live Log Streaming Tự Động 2s & Đảo Ngược Log Mới Lên Đầu (Newest on Top)
- Sử dụng Streamlit native `@st.fragment(run_every="2s")` cho riêng khối Cyber Terminal:
  - Tự động đọc và giải mã `/var/log/auth.log` từ máy chủ lab mỗi 2 giây qua SSH.
  - Tự động làm mới log ngầm mà **người dùng không cần bấm nút reset hay refresh**.
  - **Đảo ngược thứ tự log (Newest on Top):** Các dòng log mới phát sinh luôn xuất hiện ở trên cùng của màn hình console kèm hiệu ứng phát sáng nhẹ, giúp người vận hành nắm bắt sự cố tức thì mà không cần cuộn tìm kiếm.
  - Bộ lọc tìm kiếm IP/User phản hồi tức thời và bảo vệ chống XSS bằng `html.escape()`.

### R3. Ngôn Ngữ Thiết Kế Stealth Cyber Ops (Electric Blue & Dark Violet)
- Phối màu cao cấp theo chuẩn hệ thống phòng thủ mạng hiện đại:
  - Màu nền: Deep Midnight Obsidian (`#060814` / `#0b0f19`).
  - Điểm nhấn chính: Electric Blue (`#38bdf8`, `#0284c7`) và Dark Violet/Purple (`#a855f7`, `#7c3aed`).
  - Viền phát sáng công nghệ: `border: 1px solid rgba(56, 189, 248, 0.25); box-shadow: 0 0 15px rgba(139, 92, 246, 0.15);`.
  - Giữ trọn vẹn khối Cyber Terminal với 3 chấm tròn macOS (đỏ/vàng/lục), font chữ Monospace hacker (`Consolas` / `JetBrains Mono`).

### R4. Tích Hợp Cụm Phím Tác Quyền & Quy Trình Tự Hành Siêu Tốc (~9s)
- Cụm phím tác chiến trực tiếp:
  - "🧪 Chạy Test Mô Phỏng" (kích hoạt kịch bản Kali SSH Bruteforce).
  - "⚡ Bắt Đầu Quét Liên Tục" (vòng lặp tự hành).
  - "🛑 Dừng Lại" (màu đỏ nổi bật, hiển thị lập tức khi hệ thống bận).
  - "🔄 Quét Ngay 1 Lần".
- Đảm bảo giữ nguyên các thành quả tối ưu hóa tốc độ ở Phiên 10: Quy trình AI ReAct hoàn tất trong ~9.38s, thẩm định Policy Engine, kích hoạt chặn UFW và gửi Gmail thông báo tức thời.

## Acceptance Criteria

### Giao Diện & Trải Nghiệm (UI/UX)
- [ ] Toàn bộ trang web vừa khít 100vh trên trình duyệt, không có thanh cuộn dọc ngoài cùng của trang web.
- [ ] Dòng log trong Cyber Terminal tự động nhảy thời gian thực (chu kỳ 2s) mà không cần người dùng ấn nút F5 hoặc nút cập nhật.
- [ ] Dòng log mới nhất luôn xuất hiện ở dòng đầu tiên (trên cùng) của khung Terminal.
- [ ] Khối Cyber Terminal giữ đúng giao diện console nền đen 3 chấm màu yêu thích, được nâng cấp tông màu Stealth Cyber Ops (Electric Blue & Dark Violet).
- [ ] Cột bên phải có thanh cuộn nội bộ êm ái khi các thẻ AI ReAct, Policy Engine, UFW và Email mở rộng, không làm vỡ bố cục trang.

### Kỹ Thuật & Hiệu Năng
- [ ] Biên dịch không lỗi cú pháp (`python -m py_compile app.py` thành công).
- [ ] Luồng `@st.fragment` chạy ngầm mượt mà, không gây lag hay gián đoạn khi người dùng đang bấm nút hoặc tương tác ở cột phải.
- [ ] Toàn bộ 50 unit tests của hệ thống tiếp tục PASS 100%.
