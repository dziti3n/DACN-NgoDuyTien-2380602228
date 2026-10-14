import sys
import os

# Đảm bảo in UTF-8 không bị lỗi trên Windows PowerShell
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from llm_client import get_llm_client

client = get_llm_client()
print(f"[*] Provider: {os.getenv('LLM_PROVIDER', 'gemini')}")
print(f"[*] Model cấu hình: {getattr(client, 'model', 'default')}")
if hasattr(client, "fallback_models"):
    print(f"[*] Fallback models: {client.fallback_models}")

print("\n[*] Đang gửi request kiểm tra sinh JSON...")
result = client.generate(
    "Bạn là trợ lý SOC. Chỉ trả về JSON hợp lệ, không thêm văn bản nào khác.",
    'Trả về JSON dạng {"ok": true, "reply": "<một câu chào ngắn bằng tiếng Việt>", "provider": "<tên provider>"}',
)

print("[+] Kết quả trả về:")
print(result)
print(f"[+] Model thực tế đã xử lý: {getattr(client, 'last_model_used', 'N/A')}")