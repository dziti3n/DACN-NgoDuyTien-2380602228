import time
import httpx

if __name__ == "__main__":
    url = "http://127.0.0.1:11434/api/chat"

    payload = {
        "model": "qwen3:4b",
        "messages": [
            {"role": "system", "content": "You are a SOC agent. Answer ONLY in JSON format: {\"action\": \"conclude\", \"verdict\": \"malicious\"}"},
            {"role": "user", "content": "Investigate alert: brute force from 192.168.56.1"}
        ],
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.0,
            "seed": 42,
            "num_thread": 8,
            "num_ctx": 2048,
            "num_predict": 256,
        }
    }

    print("[*] Gui request toi Ollama native /api/chat...")
    t0 = time.time()
    try:
        r = httpx.post(url, json=payload, timeout=60)
        data = r.json()
        dur = round(time.time() - t0, 2)
        print(f"[+] Thanh cong trong {dur}s!")
        print("Content:", data.get("message", {}).get("content"))
        eval_count = data.get("eval_count", 0)
        eval_dur = data.get("eval_duration", 1) / 1e9
        print(f"[+] Toc do sinh token: {round(eval_count / eval_dur, 2)} tokens/s")
        prompt_eval_dur = data.get("prompt_eval_duration", 1) / 1e9
        print(f"[+] Thoi gian doc prompt: {round(prompt_eval_dur, 2)}s")
    except Exception as e:
        print(f"[-] Loi sau {round(time.time() - t0, 2)}s: {e}")

