"""
install_ui_skills.py - Tự động tải và cài đặt các Skill thiết kế giao diện (UI/UX) hàng đầu từ GitHub
vào hệ thống Antigravity Customizations (.agents/skills và ~/.gemini/config/skills).
"""

import sys
if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
import os
import shutil
import httpx

TARGET_DIRS = [
    os.path.abspath(".agents/skills"),
    os.path.expanduser("~/.gemini/config/skills")
]

GITHUB_SKILLS = [
    {
        "name": "frontend-design",
        "files": {
            "SKILL.md": "https://raw.githubusercontent.com/sickn33/agentic-awesome-skills/main/skills/frontend-design/SKILL.md",
        }
    },
    {
        "name": "anti-ui-slop",
        "files": {
            "SKILL.md": "https://raw.githubusercontent.com/sickn33/agentic-awesome-skills/main/skills/anti-ui-slop/SKILL.md",
        }
    },
    {
        "name": "antigravity-design-expert",
        "files": {
            "SKILL.md": "https://raw.githubusercontent.com/sickn33/agentic-awesome-skills/main/skills/antigravity-design-expert/SKILL.md",
        }
    },
    {
        "name": "design-system",
        "files": {
            "SKILL.md": "https://raw.githubusercontent.com/sickn33/agentic-awesome-skills/main/skills/design-system/SKILL.md",
            "references/motion-choreography.md": "https://raw.githubusercontent.com/sickn33/agentic-awesome-skills/main/skills/design-system/references/motion-choreography.md"
        }
    },
    {
        "name": "build-ui",
        "files": {
            "SKILL.md": "https://raw.githubusercontent.com/sickn33/agentic-awesome-skills/main/skills/build-ui/SKILL.md",
        }
    }
]

STREAMLIT_SKILL_MD = """---
name: streamlit-design-architect
description: >-
  Use this skill when building, restyling, or refining Python Streamlit web user interfaces,
  cybersecurity command centers, dark-mode dashboards, custom CSS injection, real-time live terminal logs,
  responsive layouts, or interactive SOC control panels.
---

# Streamlit Design Architect & Cyber UI Engineering

This skill provides expert design rules and architectural patterns for building elite, production-grade
Streamlit dashboards and Command Centers. It prevents typical Streamlit layout traps, ensuring high-craft,
responsive, and distinctive interfaces.

## 1. Core Visual Principles
- **Aesthetic Direction:** Purposeful dark-mode cyberpunk/SOC aesthetic (#060913 background, #0b0f19 card panels, #1e293b borders, #38bdf8 cyan accents, #10b981 emerald active indicators, #ef4444 red alert states).
- **Typography:** Crisp monospace for logs and addresses (`Consolas`, `JetBrains Mono`, `Courier New`), clean sans-serif for headers (`Inter`, `Segoe UI`, system UI).
- **Layout Architecture:**
  - Prefer balanced 50/50 two-column layouts (`st.columns([1, 1], gap="medium")`) for unified single-screen views without vertical scrolling sprawl.
  - Wrap sections in `st.container(border=True)` with consistent margins.
  - Never let log boxes push critical action buttons below the fold.

## 2. Advanced CSS Injection Techniques
- Always wrap custom CSS in `st.markdown('<style>...</style>', unsafe_allow_html=True)`.
- Use scoped CSS selectors or semantic class names to style containers:
  - Custom buttons: `button[data-testid="baseButton-primary"]` for high-impact action buttons.
  - Terminal containers: Fixed height (`height: 380px; overflow-y: auto; scrollbar-width: thin;`) with smooth scrolling and high contrast.
  - Animated status badges: CSS `@keyframes pulse` for real-time scanning / busy states.

## 3. Real-Time Performance & Non-Blocking Execution
- Keep the UI responsive: Never run blocking synchronous loops longer than 1-2 seconds on the main thread.
- Use `st.session_state` as a clean state machine (`idle`, `scanning`, `investigating`, `stopped`).
- Use callback patterns (`on_step_callback`) or `st.status()` to stream live ReAct thoughts and tool results directly to the user without full-page flickering.
- Provide immediate emergency cancellation: Always render a prominent `🛑 Stop / Cancel` button during background cycles.

## 4. XSS & Security Guardrails
- When rendering user-controlled log lines or external inputs inside HTML, ALWAYS sanitize via `html.escape()` or string replacement of `<`, `>`, `&`, `"`, `'`.
- Never insert raw untrusted data into `unsafe_allow_html=True` blocks without escaping.

## 5. Review Checklist Before Delivery
- [ ] No vertical overflow or awkward horizontal scrollbars.
- [ ] Color contrast passes WCAG AA (minimum 4.5:1 ratio for text against dark panels).
- [ ] Status indicators accurately reflect the underlying state machine.
- [ ] Log and terminal streams retain smooth scrollability with line numbers.
- [ ] All interactive buttons have explicit keys (`key="..."`) to prevent Streamlit duplicate widget ID errors.
"""

def install():
    client = httpx.Client(timeout=20.0, follow_redirects=True)
    
    for base_dir in TARGET_DIRS:
        print(f"\n📁 Đang cài đặt vào thư mục: {base_dir}")
        os.makedirs(base_dir, exist_ok=True)
        
        # 1. Tải và cài đặt các Skill từ GitHub
        for skill in GITHUB_SKILLS:
            skill_dir = os.path.join(base_dir, skill["name"])
            os.makedirs(skill_dir, exist_ok=True)
            print(f"  ⬇️ Cài đặt GitHub Skill: {skill['name']}...")
            
            for rel_path, url in skill["files"].items():
                dest_file = os.path.join(skill_dir, rel_path)
                os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                resp = client.get(url)
                if resp.status_code == 200:
                    with open(dest_file, "w", encoding="utf-8") as f:
                        f.write(resp.text)
                    print(f"     ✅ Đã lưu {rel_path} ({len(resp.text)} bytes)")
                else:
                    print(f"     ❌ Lỗi tải {url}: HTTP {resp.status_code}")
                    
        # 2. Cài đặt Skill chuyên biệt Streamlit Design Architect
        st_dir = os.path.join(base_dir, "streamlit-design-architect")
        os.makedirs(st_dir, exist_ok=True)
        st_file = os.path.join(st_dir, "SKILL.md")
        with open(st_file, "w", encoding="utf-8") as f:
            f.write(STREAMLIT_SKILL_MD)
        print(f"  🎨 Cài đặt Dedicated Skill: streamlit-design-architect (Đã lưu SKILL.md)")

    print("\n🎉 HOÀN TẤT CÀI ĐẶT TẤT CẢ CÁC SKILL THIẾT KẾ GIAO DIỆN!")

if __name__ == "__main__":
    install()
