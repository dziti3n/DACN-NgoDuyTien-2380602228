| Hệ thống | Thời gian ngăn chặn | Tỷ lệ chặn nhầm Admin (FP) | Tỷ lệ chặn tấn công | Xử lý tấn công nhiều bước | Vị trí chạy LLM |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Wazuh Mặc Định (Active Response)** | 18.06ms (logic) | 40.0% (2/5) | 62.5% (5/8) | 0.0% (0/4) | Không có AI |
| **AI Agent Cũ (Tuần 5 - Sync LLM)** | 15.42s | 40.0% (2/5) | 62.5% (5/8) | 0.0% (0/4) | Chạy đồng bộ trước khi chặn (~15s) |
| **AI Agent Mới (Tuần 6 - Hybrid Async)** | 7.85ms (logic) | 0.0% (0/5) | 100.0% (8/8) | 100.0% (4/4) | Chạy bất đồng bộ Tầng 2 (Không làm trễ) |
