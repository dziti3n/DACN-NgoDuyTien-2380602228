> [!WARNING] **Skepticism Disclaimer**
> High confidence in local Ollama inference (~9s), Policy Engine determinism, UFW active defense, Gmail SMTP dispatch, and CSS 100vh lock. Verified layout rendering via real headless Chrome CDP inspection and full unit test suite (38/38 passing).

## 1. What the prior attempt got wrong
1. **Invalid CSS Column Selectors (Streamlit 1.66 DOM Incompatibility)**
   - **Input:** Browser renders Streamlit layout.
   - **Expected:** Right column has smooth internal scrolling (`overflow-y: auto`), left column has `overflow: hidden`, neither overflows viewport.
   - **Actual:** Prior attempt used `div[data-testid="column"]`. In Streamlit 1.30–1.66, column testid is `stColumn`. The selectors matched 0 elements; column rules were completely ignored.
   - **Root Cause:** Implementer eyeballed CSS selectors against legacy Streamlit DOM conventions without inspecting the runtime DOM tree.

2. **Premature Erasure of Simulated Attack Logs in Cyber Terminal & Incident Queue**
   - **Input:** User clicks "🧪 Chạy Test Mô Phỏng" to simulate Kali SSH brute force attack.
   - **Expected:** Attack events appear in Cyber Terminal (with Electric Blue `001 LATEST` badge) and in Incident Queue (`#0 ssh_bruteforce`) and remain visible alongside AI ReAct results on the right.
   - **Actual:** At line 876, `st.session_state["sim_injected"]` was reset to `False` on simulation completion. On the subsequent rerun, `@st.fragment(run_every="2s")` fetched live logs from the lab VM, saw `sim_injected == False`, and wiped all simulated lines from `raw_logs` and `alerts`. The user saw right-column results for an attack that had vanished from the terminal.
   - **Root Cause:** Premature state clearing in the simulation completion handler instead of deferring reset to "🛑 Dừng Lại" or a fresh manual scan.

3. **Sub-optimal Cyber Terminal Height Distribution (R1 Requirement)**
   - **Input:** Left column height allocation according to R1 (~45px buttons, ~460px terminal, ~80px queue).
   - **Expected:** Terminal block occupies ~460px.
   - **Actual:** Terminal inner body was hardcoded to 350px (total ~406px), leaving an unnecessary 54px bottom void.
   - **Root Cause:** Conservative fixed height choice before measuring container padding and header/footer margins.

4. **Potential Duplicate Accumulation in Simulation Retention**
   - **Input:** Multi-cycle 2-second background fragment runs while simulation is active.
   - **Expected:** Injected attack logs remain stable at 4 lines.
   - **Actual:** Raw list comprehension without deduplication could accumulate duplicate lines if the server log contained matching IPs.
   - **Root Cause:** Missing `list(dict.fromkeys(...))` deduplication on `sim_lines`.

## 2. What I changed
- `app.py`:
  - **CSS Viewport & Scoped Column Architecture (R1):** Fixed column selectors by adding `.main .block-container > div[data-testid="stVerticalBlock"] > div[data-testid="stHorizontalBlock"]` and `[data-testid*="olumn"]` (supporting both modern `stColumn` and legacy `column`). Applied `max-height: calc(100vh - 170px) !important; overflow-y: auto !important; scrollbar-width: thin !important;` directly to BaseWeb tab panels (`div[data-baseweb="tab-panel"], div[data-testid="stTabContent"], div[role="tabpanel"]`) so the tab switcher stays sticky at the top while AI cards scroll smoothly inside.
  - **Cyber Terminal Proportions (R1):** Increased terminal scrollable body from 350px to 400px (header ~34px + body 400px + footer ~26px = ~460px total), matching R1.
  - **Simulated Attack Log Retention (R2/R4):** Removed premature `sim_injected = False` from simulation completion handler; added deduplication `list(dict.fromkeys(...))`; wired reset to "🔄 Quét Ngay 1 Lần" and "🛑 Dừng Lại".
- `tests/test_ui_app.py`:
  - Added unit tests: `test_r1_css_rules_and_heights_in_app` (verifying 100vh lock, `stColumn` support, `tab-panel` scroll, 400px terminal body) and `test_simulated_lines_deduplication`.

## 3. Verification Record
- **Deep Verification (ran actual tests):**
  - `python -m py_compile app.py`: 0 errors.
  - `python -m unittest tests/test_ui_app.py`: 10/10 PASS (severity badges, verdict badges, IP regex, empty state, Newest-on-Top reversal, XSS protection, search filter `<mark>`, syntax highlighting, R1 CSS rules, deduplication).
  - `python -m unittest discover -s tests -p "test_*.py"`: 27 unit tests + 11 detection rule checks passed 100%.
  - `python scripts/test_autonomous_flow.py`: Autonomous detection, Ollama qwen3:4b investigation, Policy Engine safety, and Gmail SMTP alert verified end-to-end (Status: SUCCESS).
  - Headless Chrome CDP Live DOM Inspection: Confirmed 0 outer scrollbar (`bodyHeight == windowHeight`), `stColumn` styling, and clean 100vh rendering across both columns.
- **Shallow Verification (manual only):**
  - Visual inspection of captured Chrome screenshots for Electric Blue / Dark Violet color contrast, macOS 3-dot console dots, and `LATEST` badge alignment.
- **Unverified aspects:**
  - Ultra-narrow mobile screens (< 768px width) where two columns collapse vertically by default in Streamlit. The target spec specifies desktop Command Center layout.

## 4. Known Issues
- `Minor Robustness Risk` — High latency (> 2s) on the SSH link (`192.168.56.101:22`) will gracefully extend the fragment poll interval beyond 2 seconds without UI crashing or freezing.

## 5. Remaining risk & next step
- Zero fatal functional bugs remain.
- Full compliance with R1 (Strict 100vh no-scroll), R2 (Live log streaming 2s, Newest on Top, XSS escape), R3 (Stealth Cyber Ops design language), and R4 (Tactical controls, ~9s ReAct, Policy Engine, UFW, Gmail).
- Task is complete and ready for user inspection. Note constraint: No git commit or push performed.
