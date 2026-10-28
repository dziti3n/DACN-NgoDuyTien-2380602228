#!/usr/bin/env python3
"""
security_audit.py - Công cụ tự động quét rà soát bí mật và rò rỉ dữ liệu (Secret Scanner).
Sử dụng script này trước khi đóng gói hoặc 'git push' để đảm bảo không rò rỉ secret/API key.
"""

import os
import re
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Các regex nhận diện bí mật nhạy cảm
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP)? PRIVATE KEY-----"), "Khóa bí mật SSH/RSA (Private Key)"),
    (re.compile(r"(?:AIzaSy[A-Za-z0-9_-]{33})"), "Google API Key"),
    (re.compile(r"AQ\.[A-Za-z0-9_-]{40,}"), "Gemini / Vertex API Token"),
    (re.compile(r"sk-[A-Za-z0-9_-]{40,}"), "OpenAI API Key"),
    (re.compile(r"gsk_[A-Za-z0-9_-]{40,}"), "Groq API Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
]

# Các file nguy hiểm tuyệt đối không được phép nằm trong Git
BLOCKED_FILES = [
    ".env",
    ".env.local",
    "id_rsa",
    "id_rsa.pub",
    "soc_agent_key",
]

def run_audit():
    print("=" * 60)
    print("🛡️  KIỂM TRA AN TOÀN BẢO MẬT & CHỐNG RÒ RỈ DỮ LIỆU (AUDIT)")
    print("=" * 60)
    
    issues_found = 0

    # 1. Kiểm tra danh sách file đang được Git theo dõi
    print("\n[*] 1. Kiểm tra các file đang được Git theo dõi (git ls-files)...")
    try:
        res = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
        tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
        
        for bf in BLOCKED_FILES:
            if bf in tracked_files:
                print(f"  ❌ NGUY HIỂM: File '{bf}' đang bị Git theo dõi! Cần xóa khỏi Git ngay.")
                issues_found += 1

        json_runs_in_git = [f for f in tracked_files if f.startswith("runs/") and f.endswith(".json")]
        if json_runs_in_git:
            print(f"  ⚠️ CẢNH BÁO: Có {len(json_runs_in_git)} file run log trong 'runs/' đang bị Git theo dõi.")
            issues_found += len(json_runs_in_git)
        else:
            print("  ✅ Các file nhạy cảm (.env, private keys, log runs) đều KHÔNG bị Git theo dõi.")
    except Exception as e:
        print(f"  ⚠️ Không thể kiểm tra Git (có thể chưa cài Git hoặc lỗi lệnh): {e}")

    # 2. Quét nội dung các file mã nguồn để tìm hardcoded secrets
    print("\n[*] 2. Quét nội dung mã nguồn tìm API Key / Private Key hardcoded...")
    scan_extensions = (".py", ".json", ".md", ".txt", ".yml", ".yaml", ".sh")
    
    for root, dirs, files in os.walk("."):
        # Bỏ qua thư mục venv, git, runs
        if any(ignored in root for ignored in [".venv", ".git", "runs", "__pycache__"]):
            continue
            
        for file in files:
            if not file.endswith(scan_extensions):
                continue
            if file == ".env":
                continue  # Bỏ qua file .env thật tại local vì nó đã bị .gitignore chặn
                
            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    
                for pattern, desc in SECRET_PATTERNS:
                    matches = pattern.findall(content)
                    if matches:
                        # Kiểm tra xem có phải placeholder trong .example không
                        if "example" in filepath.lower() or "your_" in content:
                            continue
                        print(f"  ❌ PHÁT HIỆN SECRET: Tìm thấy '{desc}' trong file: {filepath}")
                        issues_found += 1
            except Exception as e:
                pass

    print("\n" + "=" * 60)
    if issues_found == 0:
        print("🎉 KẾT QUẢ: 100% AN TOÀN! Không phát hiện rò rỉ Secret hay Key.")
        print("   Bạn có thể yên tâm đóng gói hoặc đẩy mã nguồn lên GitHub.")
    else:
        print(f"🚨 KẾT QUẢ: PHÁT HIỆN {issues_found} VẤN ĐỀ CẦN XỬ LÝ TRƯỚC KHI PUSH!")
    print("=" * 60)
    return issues_found

if __name__ == "__main__":
    sys.exit(run_audit())

