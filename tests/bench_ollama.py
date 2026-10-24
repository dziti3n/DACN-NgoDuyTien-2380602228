import time
import httpx

url = "http://127.0.0.1:11434/v1/chat/completions"

# Test 1: Có response_format json_object
print("--- TEST 1: CÓ response_format json_object ---")
t0 = time.time()
try:
    r1 = httpx.post(
        url,
        json={
            "model": "qwen3:4b",
            "messages": [{"role": "user", "content": "Trả về JSON: {\"status\": \"ok\"}"}],
            "response_format": {"type": "json_object"},
        },
        timeout=20,
    )
    print(f"Test 1 xong trong {round(time.time() - t0, 2)}s:")
    print(r1.json()["choices"][0]["message"]["content"])
except Exception as e:
    print(f"Test 1 lỗi sau {round(time.time() - t0, 2)}s: {e}")

# Test 2: KHÔNG CÓ response_format (dùng parse_json xử lý text)
print("\n--- TEST 2: KHÔNG CÓ response_format ---")
t0 = time.time()
try:
    r2 = httpx.post(
        url,
        json={
            "model": "qwen3:4b",
            "messages": [{"role": "user", "content": "Trả về JSON duy nhất: {\"status\": \"ok\"}"}],
        },
        timeout=20,
    )
    print(f"Test 2 xong trong {round(time.time() - t0, 2)}s:")
    print(r2.json()["choices"][0]["message"]["content"])
except Exception as e:
    print(f"Test 2 lỗi sau {round(time.time() - t0, 2)}s: {e}")

