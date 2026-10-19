"""
llm_client.py - Lớp tương tác mô hình ngôn ngữ cục bộ (Local LLM Client) qua Ollama.
Hệ thống được thiết kế theo chuẩn bảo mật đóng (Air-Gapped / Pure Local),
đảm bảo 100% dữ liệu điều tra không bao giờ rời khỏi máy tính cục bộ.
"""

import json
import os
import re
import sys
import time
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()


class LLMError(Exception):
    """Lỗi chung khi giao tiếp với mô hình ngôn ngữ."""
    pass


def parse_json(text):
    """Trích xuất và parse JSON từ phản hồi LLM an toàn.
    Tự động bóc tách reasoning tag <think>...</think> và markdown code blocks nếu có.
    """
    text = (text or "").strip()
    # Loại bỏ reasoning tag <think>...</think> (đặc thù của dòng mô hình Qwen / DeepSeek)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    # Loại bỏ code block ```json ... ```
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.DOTALL).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Nếu LLM kèm văn bản dẫn nhập bên ngoài, trích xuất khối {...} đầu tiên
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


class OllamaLocalClient:
    """Client giao tiếp trực tiếp với dịch vụ Ollama cục bộ.
    Được khóa cứng chỉ cho phép kết nối localhost/127.0.0.1 để chống rò rỉ dữ liệu.
    """

    ALLOWED_HOSTS = {"localhost", "127.0.0.1"}

    def __init__(self, base_url=None, model=None, seed=42):
        import httpx

        raw_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1")
        self.base_url = raw_url.rstrip("/")
        
        parsed = urlparse(self.base_url)
        hostname = (parsed.hostname or "").lower()
        if hostname not in self.ALLOWED_HOSTS:
            raise LLMError(
                f"Chính sách bảo mật Local-Only: Từ chối kết nối tới '{hostname}'. "
                f"Hệ thống chỉ cho phép kết nối Ollama tại localhost hoặc 127.0.0.1."
            )

        self.model = model or os.getenv("OLLAMA_MODEL", "qwen3:4b")
        self.last_model_used = self.model
        self.seed = int(os.getenv("OLLAMA_SEED", str(seed)))
        self.temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0.0"))
        
        # Timeout 120s cho mỗi lượt gọi LLM
        self.client = httpx.Client(timeout=120.0)

    def generate(self, system, user, retries=1):
        """Gửi prompt tới Ollama qua OpenAI-compatible chat endpoint với temperature=0 và seed cố định."""
        import httpx

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer ollama",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "seed": self.seed,
        }

        url = f"{self.base_url}/chat/completions"
        last_error = None

        for attempt in range(retries + 1):
            try:
                resp = self.client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                self.last_model_used = self.model
                return parse_json(content)
            except httpx.ConnectError as ex:
                raise LLMError(
                    f"Không thể kết nối đến máy chủ Ollama tại '{self.base_url}'. "
                    f"Vui lòng đảm bảo Ollama đang chạy (gõ 'ollama serve' hoặc bật ứng dụng Ollama). Chi tiết: {ex}"
                )
            except Exception as ex:
                last_error = ex
                if attempt < retries:
                    time.sleep(1.0)

        raise LLMError(f"Gọi mô hình Local ({self.model}) thất bại sau {retries + 1} lần: {str(last_error)[:300]}")


# Alias tương thích ngược
GeminiClient = OllamaLocalClient


def get_llm_client(provider=None, model=None):
    """Factory khởi tạo client cục bộ duy nhất cho toàn bộ hệ thống."""
    return OllamaLocalClient(model=model)