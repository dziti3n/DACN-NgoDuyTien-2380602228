import json
import os
import re
import time
import sys
from dotenv import load_dotenv

load_dotenv()


class LLMError(Exception):
    """Lỗi chung khi giao tiếp với mô hình ngôn ngữ."""
    pass


def parse_json(text):
    """Trích xuất và parse JSON từ phản hồi LLM an toàn, loại bỏ markdown fence nếu có."""
    text = (text or "").strip()
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


class GeminiClient:
    """Client giao tiếp với Google Gemini qua google-genai SDK.
    Hỗ trợ tự động Exponential Backoff khi gặp 429/503 và Fallback sang model phụ.
    """

    DEFAULT_FALLBACKS = [
        "gemini-3.5-flash-lite",
        "gemini-3-flash-preview",
        "gemini-3.5-flash",
        "gemini-3.8-flash",
    ]

    def __init__(self, model=None):
        from google import genai
        key = os.getenv("LLM_API_KEY")
        if not key:
            raise LLMError("Thiếu LLM_API_KEY trong file .env")
        self.client = genai.Client(api_key=key)
        self.primary_model = model or os.getenv("LLM_MODEL", "gemini-3.5-flash-lite")
        
        env_fallbacks = os.getenv("LLM_FALLBACK_MODELS")
        if env_fallbacks:
            self.fallback_models = [m.strip() for m in env_fallbacks.split(",") if m.strip()]
        else:
            self.fallback_models = [m for m in self.DEFAULT_FALLBACKS if m != self.primary_model]

        self.model = self.primary_model
        self.last_model_used = self.primary_model

    def generate(self, system, user, retries=2):
        from google.genai import types

        # Danh sách các model sẽ lần lượt thử nếu model trước đó bị 429 / 503
        candidate_models = [self.model] + [m for m in self.fallback_models if m != self.model]
        last_error = None

        for model_name in candidate_models:
            for attempt in range(retries + 1):
                try:
                    resp = self.client.models.generate_content(
                        model=model_name,
                        contents=user,
                        config=types.GenerateContentConfig(
                            system_instruction=system,
                            response_mime_type="application/json",
                            temperature=0.2,
                        ),
                    )
                    self.last_model_used = model_name
                    self.model = model_name
                    return parse_json(resp.text)
                except Exception as ex:
                    last_error = ex
                    err_str = str(ex)
                    is_rate_limit = "429" in err_str or "RESOURCE_EXHAUSTED" in err_str
                    is_unavailable = "503" in err_str or "UNAVAILABLE" in err_str

                    if (is_rate_limit or is_unavailable) and attempt < retries:
                        # Exponential backoff: 4s, 8s, ...
                        delay = 4 * (attempt + 1)
                        status_name = "429 Rate Limit" if is_rate_limit else "503 Quá tải"
                        print(f"  [Gemini] {status_name} trên '{model_name}'. Đang chờ {delay}s trước khi thử lại (lần {attempt + 1}/{retries})...")
                        time.sleep(delay)
                    else:
                        break  # Hết lượt retry cho model này hoặc là lỗi khác, chuyển sang fallback model

            print(f"  [Gemini] Model '{model_name}' không thành công. Thử model dự phòng...")

        raise LLMError(f"Gọi Gemini thất bại qua các model {candidate_models}: {str(last_error)[:300]}")


class OpenAICompatibleClient:
    """Client giao tiếp với bất kỳ API nào chuẩn OpenAI (Ollama, Groq, DeepSeek, OpenAI)."""

    def __init__(self, base_url, api_key=None, model="default"):
        import httpx
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or "none"
        self.model = model
        self.last_model_used = model
        self.client = httpx.Client(timeout=60.0)

    def generate(self, system, user, retries=2):
        import httpx

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        url = f"{self.base_url}/chat/completions"
        last_error = None

        for attempt in range(retries + 1):
            try:
                resp = self.client.post(url, headers=headers, json=payload)
                if resp.status_code == 429:
                    delay = 4 * (attempt + 1)
                    print(f"  [OpenAI API] 429 Rate limit tại {self.base_url}. Đang chờ {delay}s...")
                    time.sleep(delay)
                    continue
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                self.last_model_used = self.model
                return parse_json(content)
            except httpx.ConnectError as ex:
                raise LLMError(
                    f"Không thể kết nối đến máy chủ LLM tại '{self.base_url}'. "
                    f"Nếu dùng Ollama, hãy đảm bảo service đã được bật ('ollama serve'). Chi tiết: {ex}"
                )
            except Exception as ex:
                last_error = ex
                if attempt < retries:
                    time.sleep(2 * (attempt + 1))

        raise LLMError(f"Gọi mô hình ({self.model}) thất bại: {str(last_error)[:300]}")


def get_llm_client(provider=None, model=None):
    """Factory khởi tạo client dựa trên cấu hình LLM_PROVIDER trong file .env.
    Hỗ trợ:
      - 'gemini' (mặc định)
      - 'ollama' (Local LLM qua http://localhost:11434/v1)
      - 'groq'   (Miễn phí, siêu nhanh qua https://api.groq.com/openai/v1)
      - 'openai' (Hoặc tương thích)
    """
    prov = (provider or os.getenv("LLM_PROVIDER", "gemini")).lower().strip()

    if prov == "ollama":
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        m = model or os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct")
        return OpenAICompatibleClient(base_url=base_url, api_key="ollama", model=m)

    if prov == "groq":
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise LLMError("Thiếu GROQ_API_KEY trong file .env khi chọn provider 'groq'.")
        m = model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        return OpenAICompatibleClient(
            base_url="https://api.groq.com/openai/v1", api_key=api_key, model=m
        )

    if prov == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise LLMError("Thiếu OPENAI_API_KEY trong file .env khi chọn provider 'openai'.")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        m = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        return OpenAICompatibleClient(base_url=base_url, api_key=api_key, model=m)

    # Mặc định là Gemini
    return GeminiClient(model=model)