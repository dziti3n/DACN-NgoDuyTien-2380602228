import os
import sys
import json
from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

from llm_client import (
    parse_json,
    GeminiClient,
    OpenAICompatibleClient,
    get_llm_client,
    LLMError,
)

passed = 0
failed = 0

def report(name, success, msg=""):
    global passed, failed
    if success:
        passed += 1
        print(f"  [PASS] {name} {msg}")
    else:
        failed += 1
        print(f"  [FAIL] {name} - {msg}")

print("==================================================")
print("KIỂM THỬ TOÀN DIỆN BƯỚC 1: LLM CLIENT & ROBUSTNESS")
print("==================================================\n")

# --- TEST 1: Kiểm tra parse_json xử lý các định dạng đầu ra của LLM ---
print("1. Kiểm tra hàm parse_json:")
try:
    # 1.1 JSON chuẩn
    r1 = parse_json('{"status": "ok", "value": 123}')
    report("1.1 JSON chuẩn", r1.get("status") == "ok")

    # 1.2 JSON bọc trong markdown ```json
    r2 = parse_json('```json\n{"action": "conclude", "verdict": "benign_likely"}\n```')
    report("1.2 Markdown ```json fence", r2.get("verdict") == "benign_likely")

    # 1.3 LLM viết thêm chữ giải thích bên ngoài JSON
    r3 = parse_json('Dưới đây là kết quả của tôi:\n{"action": "call_tool", "tool": "search_auth_logs"}\nHy vọng giúp được bạn!')
    report("1.3 Văn bản phụ bao quanh JSON", r3.get("tool") == "search_auth_logs")

    # 1.4 JSON không hợp lệ phải ném lỗi
    try:
        parse_json("Đây hoàn toàn không phải JSON")
        report("1.4 Bắt lỗi JSON hỏng", False, "Không ném lỗi khi dữ liệu hỏng")
    except Exception:
        report("1.4 Bắt lỗi JSON hỏng", True)
except Exception as e:
    report("Nhóm test parse_json", False, str(e))


# --- TEST 2: Kiểm tra Factory get_llm_client() ---
print("\n2. Kiểm tra Factory get_llm_client():")
try:
    c_gemini = get_llm_client("gemini")
    report("2.1 Khởi tạo Gemini provider", isinstance(c_gemini, GeminiClient))

    c_ollama = get_llm_client("ollama")
    report("2.2 Khởi tạo Ollama provider", isinstance(c_ollama, OpenAICompatibleClient))
    report("2.2.1 Ollama Base URL", "11434" in c_ollama.base_url)
except Exception as e:
    report("Nhóm test get_llm_client", False, str(e))


# --- TEST 3: Kiểm tra Cơ chế Fallback tự động của GeminiClient ---
print("\n3. Kiểm tra cơ chế Fallback tự động khi model chính lỗi:")
try:
    # Cố tình đưa model chính là model không tồn tại để ép kích hoạt fallback
    bad_model = "gemini-model-khong-ton-tai-12345"
    client_fallback = GeminiClient(model=bad_model)
    # Gán fallback_models rõ ràng với model đã biết hoạt động tốt
    client_fallback.fallback_models = ["gemini-3.5-flash-lite"]
    
    print(f"  [*] Đang thử gọi với model chính cố tình sai: '{bad_model}'...")
    res = client_fallback.generate(
        "Chỉ trả về JSON",
        '{"test": "fallback"}'
    )
    report("3.1 Tự động fallback sang model phụ thành công", res.get("test") == "fallback")
    report("3.2 Ghi nhận last_model_used đúng model fallback", client_fallback.last_model_used == "gemini-3.5-flash-lite")
except Exception as e:
    report("3.1 Cơ chế fallback", False, str(e))


# --- TEST 4: Kiểm tra xử lý lỗi khi không kết nối được Ollama/Local Server ---
print("\n4. Kiểm tra xử lý lỗi kết nối máy chủ Local LLM (Ollama):")
try:
    # Gọi tới một port không có dịch vụ nào chạy
    dead_client = OpenAICompatibleClient(base_url="http://localhost:59999/v1", model="test")
    try:
        dead_client.generate("sys", "user")
        report("4.1 Xử lý mất kết nối local", False, "Lẽ ra phải ném LLMError")
    except LLMError as ex:
        err_msg = str(ex)
        has_guidance = "ollama" in err_msg.lower() or "kết nối" in err_msg.lower()
        report("4.1 Bắt lỗi mất kết nối và có thông báo hướng dẫn", has_guidance, err_msg[:80] + "...")
except Exception as e:
    report("Nhóm test Ollama error", False, str(e))

print("\n==================================================")
print(f"TỔNG KẾT: {passed} PASS, {failed} FAIL")
print("==================================================")

