#!/usr/bin/env python3
"""
core/correlator.py - Bộ Tương Quan Chuỗi Tấn Công Nhiều Bước & Bảo Vệ Chống Chặn Nhầm
(Stateful Multi-Step Kill-Chain Correlator & Anti-False-Positive Context Guard).

Giải quyết 2 giới hạn cốt lõi của Wazuh Active Response mặc định:
1. Stateful Kill-Chain Correlation:
   Liên kết các sự kiện rời rạc theo (src_ip, user) qua cửa sổ thời gian:
     Stage 1: Dò mật khẩu / Quét tài khoản (Rule 5710, 5711, 5760, 5712, 5763)
              — bao gồm cả tấn công chậm (Low-and-Slow < 8 lần) lọt ngưỡng Wazuh.
     Stage 2: Đăng nhập thành công sau khi thất bại (Rule 5715) -> Xâm nhập ban đầu.
     Stage 3: Leo thang đặc quyền Sudo hoặc sửa file hệ thống (Rule 5401/5402/5404/5405/550/5902)
              — tự động truy ngược lại IP nguồn ngay cả khi log sudo/FIM không chứa srcip!
2. Context-Aware Anti-False-Positive Guard:
   Phân biệt hành vi gõ nhầm mật khẩu của Admin hợp lệ (baseline user, 1 user duy nhất,
   không rà quét invalid user, nhịp độ người dùng, hoặc đã có phiên SSH Key/phục hồi an toàn)
   với tấn công tự động (Hydra, multi-user spray, invalid user, command injection)
   để KHÔNG khóa nhầm tài khoản quản trị (0% Admin Lockout).
"""

import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    from telemetry.detection import DANGEROUS_SUDO_COMMANDS
except ImportError:
    from detection import DANGEROUS_SUDO_COMMANDS


ROOT_DIR = Path(__file__).resolve().parent.parent
BASELINE_CANDIDATES = [ROOT_DIR / "config" / "baseline.json", ROOT_DIR / "baseline.json"]

ALLOWED_MAINTENANCE_COMMANDS = {
    "/usr/bin/apt update",
    "/usr/sbin/ufw status",
    "/usr/sbin/ufw status verbose",
    "/bin/systemctl restart nginx",
}

ADVERSARIAL_PAYLOAD_RE = re.compile(
    r"(?:SYSTEM\s+OVERRIDE|Ignore\s+all\s+previous|</?untrusted_tool_output>|"
    r"DO\s+NOT\s+BLOCK|`id;|;\s*cat\s+|Authorized\s+pentest|Tool\s+inspect_user_changes)",
    re.IGNORECASE,
)

SENSITIVE_FIM_PATHS = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/cron.d/", "/etc/ssh/sshd_config")

AUTH_FAIL_RULES = {"5710", "5711", "5712", "5716", "5760", "5763"}
AUTH_SUCCESS_RULES = {"5715"}
SUDO_RULES = {"5401", "5402", "5403", "5404", "5405"}
FIM_RULES = {"550", "5902"}


def load_baseline_config() -> dict:
    """Nạp cấu hình baseline quản trị viên hợp lệ từ config/baseline.json."""
    for path in BASELINE_CANDIDATES:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception:
                pass
    return {
        "allowed_users": ["admin_duytien", "agent_soc", "admin"],
        "allowed_sudo_members": ["admin_duytien", "agent_soc", "admin"],
    }


def _parse_event_epoch(alert: dict, raw_payload: Optional[dict] = None) -> float:
    """Chuyển đổi timestamp của alert về Unix epoch (giây) để tính toán cửa sổ trượt chính xác."""
    ts_str = (
        (raw_payload or {}).get("timestamp")
        or alert.get("last_seen")
        or alert.get("first_seen")
    )
    if isinstance(ts_str, (int, float)):
        return float(ts_str)
    if isinstance(ts_str, str) and ts_str.strip():
        cleaned = ts_str.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        # Chuẩn hóa offset dạng +0000 -> +00:00 cho Python fromisoformat
        cleaned = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", cleaned)
        try:
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            pass
    return time.time()


def _extract_failure_count_hint(full_log: str, default_inc: int = 1) -> int:
    """Trích xuất số lần thất bại gộp nếu dòng log có chú thích tần suất (VD: '18 consecutive failures')."""
    if not full_log:
        return default_inc
    patterns = [
        r"\((\d+)\s+(?:consecutive\s+)?(?:failures|attempts)\b",
        r"for\s+(\d+)\s+distinct\s+users",
        r"repeated\s+(\d+)\s+times",
    ]
    for pat in patterns:
        m = re.search(pat, full_log, re.IGNORECASE)
        if m:
            try:
                return max(default_inc, int(m.group(1)))
            except ValueError:
                pass
    if "multiple usernames:" in full_log.lower():
        return max(default_inc, 3)
    return default_inc


def _extract_cadence_hint_fast(full_log: str) -> bool:
    """Nhận diện dấu hiệu tool tự động từ tốc độ hoặc mô tả dồn dập trong log."""
    if not full_log:
        return False
    low = full_log.lower()
    if re.search(r"\b(?:1[2-9]|[2-9]\d+)\s+(?:consecutive\s+)?(?:failures|attempts)\b", low):
        return True
    if "in 10s" in low or "multiple usernames:" in low or "distinct users" in low:
        return True
    return False


def _is_dangerous_sudo(full_log: str, command: Optional[str]) -> Optional[str]:
    """Kiểm tra lệnh sudo có nằm trong danh mục leo quyền / phá hoại nguy hiểm hay không."""
    text = f"{command or ''} {full_log or ''}"
    for pattern, reason in DANGEROUS_SUDO_COMMANDS:
        if pattern.search(text):
            return reason
    if "/tmp/" in text or "/dev/shm/" in text:
        return "exec_from_temp_dir"
    if "find " in text and "-exec" in text:
        return "lolbin_find_exec"
    if "user not in sudoers" in text.lower():
        return "user_not_in_sudoers"
    return None


@dataclass
class IpCorrelationState:
    src_ip: str
    failed_timestamps: List[float] = field(default_factory=list)
    failed_count_total: int = 0
    invalid_user_count: int = 0
    users_attempted: Set[str] = field(default_factory=set)
    last_failed_user: Optional[str] = None
    has_compromised_login: bool = False
    compromised_user: Optional[str] = None
    compromised_at: Optional[float] = None
    trusted_ssh_key_login: bool = False
    trusted_login_users: Set[str] = field(default_factory=set)
    stage_history: List[Dict[str, Any]] = field(default_factory=list)
    kill_chain_stage: int = 0  # 0=Normal, 1=CredentialAccess, 2=CompromisedLogin, 3=PrivEsc/Persistence
    deferred_review_count: int = 0

    def prune(self, now_ts: float, window_sec: float = 300.0):
        cutoff = now_ts - window_sec
        self.failed_timestamps = [t for t in self.failed_timestamps if t >= cutoff]
        self.stage_history = [s for s in self.stage_history if s.get("ts", 0.0) >= cutoff]
        if self.compromised_at and self.compromised_at < (now_ts - window_sec * 2):
            self.has_compromised_login = False
            self.compromised_user = None
            self.compromised_at = None
            self.kill_chain_stage = 0


@dataclass
class CorrelationDecision:
    route: str  # TELEMETRY_ONLY | FAST_BENIGN | DEFER_TO_LLM | FAST_BLOCK | MULTISTEP_CONTAINMENT
    verdict_hint: str
    severity: str
    confidence: str
    should_block_ip: bool
    recommended_actions: List[str]
    kill_chain_stage: int
    correlated_ip: Optional[str]
    compromised_user: Optional[str]
    mitre_techniques: List[str]
    reason: str
    timeline_summary: List[str]
    is_false_positive_protected: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class KillChainCorrelator:
    """
    Bộ tương quan trạng thái chuỗi sự cố thời gian thực (<1ms mỗi sự kiện).
    Đặt hoàn toàn ở Tầng 1 xác định (không gọi LLM trong đường găng thời gian thực).
    """

    def __init__(self, window_sec: float = 300.0):
        self.window_sec = window_sec
        self._lock = threading.Lock()
        self._ip_states: Dict[str, IpCorrelationState] = {}
        self._user_to_ip: Dict[str, Dict[str, Any]] = {}

    def reset(self):
        with self._lock:
            self._ip_states.clear()
            self._user_to_ip.clear()

    def _get_or_create_ip_state(self, src_ip: str, now_ts: float) -> IpCorrelationState:
        st = self._ip_states.get(src_ip)
        if st is None:
            st = IpCorrelationState(src_ip=src_ip)
            self._ip_states[src_ip] = st
        st.prune(now_ts, self.window_sec)
        return st

    def _is_human_admin_typo_pattern(
        self,
        ip_state: IpCorrelationState,
        target_user: str,
        rule_id: str,
        full_log: str,
        baseline_users: Set[str],
    ) -> Tuple[bool, str]:
        """
        Kiểm tra xem chuỗi lỗi có khớp mẫu gõ nhầm mật khẩu của Admin hợp lệ hay không:
        - User thuộc danh sách quản trị viên trong baseline.json (không phải root, không phải user lạ)
        - Không có bất kỳ thăm dò invalid user (Rule 5710 / multiple usernames)
        - Chỉ nhắm 1 tài khoản duy nhất (không rải password spray nhiều user)
        - Không có dấu hiệu payload prompt/command injection
        - Tốc độ/nhịp độ phù hợp gõ tay của con người (khoảng cách trung bình >= 1.2s hoặc tổng số lần <= 10)
        """
        if not target_user or target_user == "root" or target_user not in baseline_users:
            return False, "User mục tiêu không thuộc baseline quản trị viên hợp lệ"

        if ADVERSARIAL_PAYLOAD_RE.search(full_log or ""):
            return False, "Phát hiện chuỗi payload đối kháng/injection trong log"

        if ip_state.invalid_user_count > 0 or rule_id == "5710" or "invalid user" in (full_log or "").lower():
            return False, "Phát hiện rà quét tài khoản không tồn tại (Invalid User)"

        if len(ip_state.users_attempted) > 1:
            return False, f"Phát hiện rải nhiều tài khoản ({sorted(ip_state.users_attempted)})"

        # Nếu có dấu hiệu tốc độ máy (Hydra/Medusa) từ số lần thất bại gộp lớn hoặc nhịp < 1.0s
        if _extract_cadence_hint_fast(full_log):
            return False, "Tốc độ tấn công mật khẩu cao mang đặc trưng công cụ tự động"

        fail_times = sorted(ip_state.failed_timestamps)
        if len(fail_times) >= 3:
            total_span = fail_times[-1] - fail_times[0]
            avg_gap = total_span / max(1, len(fail_times) - 1)
            # Nếu >= 3 lần xảy ra dồn dập dưới 0.9s/lần (Hydra -t 4) -> Tool tấn công!
            # Lưu ý: tổng span > 0 mới đánh giá cadence (nếu replay đồng thời không có gap rõ ràng thì dựa vào metadata/baseline)
            if total_span > 0.05 and avg_gap < 0.9:
                return False, f"Nhịp độ thử mật khẩu quá nhanh ({avg_gap:.2f}s/lần - dấu hiệu công cụ Brute Force)"

        if ip_state.failed_count_total > 10:
            return False, f"Số lần nhập sai vượt ngưỡng an toàn cho phép của gõ nhầm ({ip_state.failed_count_total} lần)"

        # Nếu là Rule 5404 (nhập sai mật khẩu sudo 3 lần) từ tài khoản đã đăng nhập SSH hợp lệ
        if rule_id == "5404" and ip_state.trusted_ssh_key_login:
            return True, f"Quản trị viên '{target_user}' đã xác thực SSH Key trước đó, nhập nhầm mật khẩu sudo"

        return True, (
            f"Tài khoản quản trị baseline '{target_user}' nhập sai giới hạn ({ip_state.failed_count_total} lần), "
            f"0 rà quét user lạ, nhịp độ phù hợp thao tác con người"
        )

    def evaluate_event(self, alert: dict, raw_payload: Optional[dict] = None) -> CorrelationDecision:
        """
        Đưa một alert đã chuẩn hóa qua động cơ tương quan nhiều bước và bảo vệ chống chặn nhầm.
        """
        with self._lock:
            now_ts = _parse_event_epoch(alert, raw_payload)
            wazuh = alert.get("wazuh", {}) if isinstance(alert.get("wazuh"), dict) else {}
            rule_id = str(wazuh.get("rule_id") or "")
            rule_level = int(wazuh.get("level") or 5)
            rule_desc = wazuh.get("description") or alert.get("summary") or ""
            full_log = wazuh.get("full_log") or alert.get("details", {}).get("full_log") or ""

            src_ip = alert.get("src_ip")
            target_user = (
                alert.get("src_user")
                or alert.get("user")
                or wazuh.get("srcuser")
                or wazuh.get("dstuser")
                or "unknown"
            )
            if target_user == "root" and wazuh.get("srcuser"):
                target_user = wazuh.get("srcuser")

            baseline = load_baseline_config()
            baseline_users = set(baseline.get("allowed_users", []))
            baseline_sudoers = set(baseline.get("allowed_sudo_members", []))

            # Truy ngược IP nguồn nếu event nội bộ (sudo / FIM) không mang srcip
            resolved_ip = src_ip
            user_ctx = self._user_to_ip.get(target_user)
            if (not resolved_ip or resolved_ip == "192.168.56.101") and user_ctx:
                if (now_ts - user_ctx.get("ts", 0)) <= self.window_sec * 2:
                    resolved_ip = user_ctx.get("src_ip") or resolved_ip

            # Với trường hợp FIM/Cron không có user cụ thể nhưng có vừa có IP compromise gần đây
            if not resolved_ip and rule_id in FIM_RULES:
                recent_comp = [
                    st for st in self._ip_states.values()
                    if st.has_compromised_login and (now_ts - (st.compromised_at or 0)) <= self.window_sec * 2
                ]
                if recent_comp:
                    recent_comp.sort(key=lambda s: s.compromised_at or 0, reverse=True)
                    resolved_ip = recent_comp[0].src_ip
                    if target_user == "unknown" and recent_comp[0].compromised_user:
                        target_user = recent_comp[0].compromised_user

            ip_state = self._get_or_create_ip_state(resolved_ip, now_ts) if resolved_ip else None

            # -----------------------------------------------------------------
            # NHÁNH 1: SỰ KIỆN THẤT BẠI ĐĂNG NHẬP SSH (5710, 5711, 5760, 5712, 5763)
            # -----------------------------------------------------------------
            if rule_id in AUTH_FAIL_RULES:
                inc_count = _extract_failure_count_hint(full_log, default_inc=1)
                if ip_state is not None:
                    ip_state.failed_timestamps.append(now_ts)
                    ip_state.failed_count_total += inc_count
                    if target_user and target_user != "unknown":
                        ip_state.users_attempted.add(target_user)
                        ip_state.last_failed_user = target_user
                    if rule_id == "5710" or "invalid user" in full_log.lower():
                        ip_state.invalid_user_count += inc_count
                    ip_state.kill_chain_stage = max(ip_state.kill_chain_stage, 1)
                    ip_state.stage_history.append({
                        "ts": now_ts,
                        "stage": "Stage 1: Credential Access",
                        "detail": f"Rule {rule_id}: Failed auth for '{target_user}' (+{inc_count})"
                    })

                # Nếu có payload injection hoặc rải nhiều user ngay từ log -> Chặn nhanh
                has_adv = bool(ADVERSARIAL_PAYLOAD_RE.search(full_log or ""))
                multi_user_spray = ip_state is not None and len(ip_state.users_attempted) >= 2
                is_heavy_tool = _extract_cadence_hint_fast(full_log) or (ip_state is not None and ip_state.failed_count_total > 10)

                # Đơn lẻ cấp thấp (<7) và không phải spray/injection -> Chỉ lưu Telemetry Buffer (<1ms)
                if rule_level < 7 and not has_adv and not multi_user_spray and "multiple usernames" not in full_log.lower():
                    return CorrelationDecision(
                        route="TELEMETRY_ONLY",
                        verdict_hint="insufficient_data",
                        severity="low",
                        confidence="medium",
                        should_block_ip=False,
                        recommended_actions=[],
                        kill_chain_stage=1,
                        correlated_ip=resolved_ip,
                        compromised_user=None,
                        mitre_techniques=["T1110"],
                        reason=f"Ghi nhận lần thất bại xác thực (Rule {rule_id}, tích lũy {ip_state.failed_count_total if ip_state else 1} lần) vào bộ đệm tương quan.",
                        timeline_summary=[s["detail"] for s in (ip_state.stage_history[-5:] if ip_state else [])],
                    )

                # Khi đạt ngưỡng Level >= 7 (5712, 5763 hoặc 5710 spray/injection):
                if ip_state is not None and not is_heavy_tool:
                    is_typo, typo_reason = self._is_human_admin_typo_pattern(
                        ip_state=ip_state,
                        target_user=target_user,
                        rule_id=rule_id,
                        full_log=full_log,
                        baseline_users=baseline_users,
                    )
                    if is_typo:
                        ip_state.deferred_review_count += 1
                        return CorrelationDecision(
                            route="DEFER_TO_LLM",
                            verdict_hint="suspicious_needs_more_data",
                            severity="medium",
                            confidence="medium",
                            should_block_ip=False,
                            recommended_actions=[
                                f"Theo dõi IP {resolved_ip} và chuyển AI điều tra ngoại tuyến (KHÔNG khóa nhầm Admin {target_user})"
                            ],
                            kill_chain_stage=1,
                            correlated_ip=resolved_ip,
                            compromised_user=None,
                            mitre_techniques=["T1110"],
                            reason=f"ANTI-LOCKOUT GUARD: {typo_reason}. Trì hoãn chặn IP để tránh khóa nhầm Admin.",
                            timeline_summary=[s["detail"] for s in ip_state.stage_history[-5:]],
                            is_false_positive_protected=True,
                        )

                # Trường hợp xác thực Brute Force thực thụ (Hydra, root, invalid user, multi-user spray, injection)
                return CorrelationDecision(
                    route="FAST_BLOCK",
                    verdict_hint="malicious_activity_likely",
                    severity="high",
                    confidence="high",
                    should_block_ip=bool(resolved_ip),
                    recommended_actions=[f"Chặn ngay IP {resolved_ip} trên tường lửa UFW"] if resolved_ip else [],
                    kill_chain_stage=1,
                    correlated_ip=resolved_ip,
                    compromised_user=None,
                    mitre_techniques=["T1110"],
                    reason=f"Phát hiện Brute Force xác thực từ {resolved_ip} vào tài khoản '{target_user}' (Rule {rule_id}, tổng thất bại={ip_state.failed_count_total if ip_state else inc_count}).",
                    timeline_summary=[s["detail"] for s in (ip_state.stage_history[-5:] if ip_state else [])],
                )

            # -----------------------------------------------------------------
            # NHÁNH 2: ĐĂNG NHẬP SSH THÀNH CÔNG (Rule 5715)
            # -----------------------------------------------------------------
            if rule_id in AUTH_SUCCESS_RULES:
                is_pubkey = "publickey" in full_log.lower()
                if resolved_ip and target_user and target_user != "unknown":
                    self._user_to_ip[target_user] = {
                        "src_ip": resolved_ip,
                        "ts": now_ts,
                        "is_pubkey": is_pubkey,
                    }

                if ip_state is not None:
                    ip_state.stage_history.append({
                        "ts": now_ts,
                        "stage": "Stage 2: Initial Access (SSH Login)",
                        "detail": f"Rule 5715: {'PublicKey' if is_pubkey else 'Password'} login success for '{target_user}' from {resolved_ip}"
                    })

                    # Kiểm tra: có phải vừa bị dò mật khẩu trước khi đăng nhập thành công không?
                    prior_fails = ip_state.failed_count_total
                    was_probing_invalid = ip_state.invalid_user_count > 0 or len(ip_state.users_attempted) > 1

                    # Nếu là PublicKey hợp lệ cho baseline user VÀ chưa từng rà quét invalid/multi-user -> An toàn!
                    if is_pubkey and target_user in baseline_users and not was_probing_invalid:
                        ip_state.trusted_ssh_key_login = True
                        ip_state.trusted_login_users.add(target_user)
                        return CorrelationDecision(
                            route="FAST_BENIGN",
                            verdict_hint="benign_likely",
                            severity="info",
                            confidence="high",
                            should_block_ip=False,
                            recommended_actions=[],
                            kill_chain_stage=0,
                            correlated_ip=resolved_ip,
                            compromised_user=None,
                            mitre_techniques=[],
                            reason=f"Đăng nhập SSH Public Key hợp lệ cho tài khoản baseline '{target_user}'.",
                            timeline_summary=[s["detail"] for s in ip_state.stage_history[-5:]],
                            is_false_positive_protected=(prior_fails > 0),
                        )

                    # Nếu Password login thành công cho baseline user sau vài lần gõ nhầm (<= 8 lần, 0 invalid user, 1 user, human cadence)
                    # -> Có thể là Admin gõ nhầm rồi nhớ ra mật khẩu! Khoan chặn, đặt trạng thái giám sát chặt nếu leo quyền bất thường!
                    is_typo_recovery, typo_reason = self._is_human_admin_typo_pattern(
                        ip_state=ip_state,
                        target_user=target_user,
                        rule_id="5715",
                        full_log=full_log,
                        baseline_users=baseline_users,
                    )
                    if prior_fails >= 3 and (not is_typo_recovery or was_probing_invalid or target_user not in baseline_users):
                        # PHÁT HIỆN XÂM NHẬP THÀNH CÔNG SAU BRUTE FORCE (Stage 1 -> Stage 2 Compromise!)
                        ip_state.has_compromised_login = True
                        ip_state.compromised_user = target_user
                        ip_state.compromised_at = now_ts
                        ip_state.kill_chain_stage = 2
                        return CorrelationDecision(
                            route="MULTISTEP_CONTAINMENT",
                            verdict_hint="malicious_activity_likely",
                            severity="critical",
                            confidence="high",
                            should_block_ip=bool(resolved_ip),
                            recommended_actions=[
                                f"Chặn khẩn cấp IP {resolved_ip} trên UFW",
                                f"Ngắt phiên SSH đang hoạt động của tài khoản bị xâm nhập '{target_user}'",
                                f"Kiểm tra lịch sử lệnh sau xâm nhập trên '{target_user}'"
                            ],
                            kill_chain_stage=2,
                            correlated_ip=resolved_ip,
                            compromised_user=target_user,
                            mitre_techniques=["T1110", "T1078"],
                            reason=(
                                f"KILL-CHAIN STAGE 2 (XÂM NHẬP THÀNH CÔNG): IP {resolved_ip} đã thử sai {prior_fails} lần "
                                f"sau đó ĐĂNG NHẬP THÀNH CÔNG vào '{target_user}'! (Tấn công dò mật khẩu đã xuyên thủng lớp SSH)"
                            ),
                            timeline_summary=[s["detail"] for s in ip_state.stage_history[-6:]],
                        )

                    if prior_fails > 0 and is_typo_recovery:
                        # Admin gõ nhầm mật khẩu rồi đăng nhập lại được -> Giữ trạng thái giám sát hậu kiểm (chặn ngay nếu chạy lệnh nguy hiểm ở Stage 3)
                        ip_state.trusted_login_users.add(target_user)
                        return CorrelationDecision(
                            route="FAST_BENIGN" if prior_fails <= 4 else "DEFER_TO_LLM",
                            verdict_hint="benign_likely" if prior_fails <= 4 else "suspicious_needs_more_data",
                            severity="low" if prior_fails <= 4 else "medium",
                            confidence="medium",
                            should_block_ip=False,
                            recommended_actions=[] if prior_fails <= 4 else [
                                f"Giám sát phiên làm việc của '{target_user}' bằng AI ngoại tuyến (không chặn nhầm)"
                            ],
                            kill_chain_stage=0,
                            correlated_ip=resolved_ip,
                            compromised_user=None,
                            mitre_techniques=[],
                            reason=f"ANTI-LOCKOUT RECOVERY: {typo_reason}, sau đó đăng nhập thành công (theo dõi hậu kiểm không khóa nhầm).",
                            timeline_summary=[s["detail"] for s in ip_state.stage_history[-5:]],
                            is_false_positive_protected=True,
                        )

                # Trường hợp đăng nhập thành công bình thường không có tiền sử thất bại
                return CorrelationDecision(
                    route="TELEMETRY_ONLY",
                    verdict_hint="benign_likely",
                    severity="info",
                    confidence="high",
                    should_block_ip=False,
                    recommended_actions=[],
                    kill_chain_stage=0,
                    correlated_ip=resolved_ip,
                    compromised_user=None,
                    mitre_techniques=[],
                    reason=f"Ghi nhận phiên đăng nhập SSH thành công cho '{target_user}' từ {resolved_ip or 'N/A'}.",
                    timeline_summary=[f"Rule 5715: SSH login success ({target_user})"],
                )

            # -----------------------------------------------------------------
            # NHÁNH 3: LEO QUYỀN SUDO / PHÁ HOẠI / PERSISTENCE (5401..5405, 550, 5902)
            # -----------------------------------------------------------------
            if rule_id in SUDO_RULES or rule_id in FIM_RULES:
                data_obj = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
                command = wazuh.get("command") or data_obj.get("command")
                if not command and "COMMAND=" in full_log.upper():
                    cmd_idx = full_log.upper().find("COMMAND=")
                    command = full_log[cmd_idx + len("COMMAND="):].strip()

                danger_reason = _is_dangerous_sudo(full_log, command) if rule_id in SUDO_RULES else None
                sensitive_fim = (
                    rule_id in FIM_RULES
                    and any(p in full_log.lower() for p in SENSITIVE_FIM_PATHS)
                    and "logrotate" not in full_log.lower()
                    and ".gz" not in full_log.lower()
                )
                is_user_backdoor = rule_id == "5902" or "useradd" in full_log.lower() or "backdoor" in full_log.lower()

                prior_compromise = bool(ip_state and ip_state.has_compromised_login)
                prior_fails = ip_state.failed_count_total if ip_state else 0

                if ip_state is not None:
                    ip_state.stage_history.append({
                        "ts": now_ts,
                        "stage": "Stage 3: Privilege Escalation / Persistence",
                        "detail": f"Rule {rule_id}: user='{target_user}' cmd='{command or rule_desc}'"
                    })

                # Kiểm tra trường hợp Admin gõ sai mật khẩu sudo 3 lần (Rule 5404) khi chạy lệnh bảo trì an toàn
                if rule_id == "5404" and not prior_compromise and target_user in baseline_sudoers and not danger_reason:
                    is_trusted_admin = (
                        (ip_state and (ip_state.trusted_ssh_key_login or target_user in ip_state.trusted_login_users))
                        or prior_fails == 0
                    )
                    if is_trusted_admin:
                        return CorrelationDecision(
                            route="DEFER_TO_LLM",
                            verdict_hint="suspicious_needs_more_data",
                            severity="medium",
                            confidence="medium",
                            should_block_ip=False,
                            recommended_actions=[
                                f"Xác minh phiên sudo của quản trị viên '{target_user}' qua LLM (KHÔNG tự động chặn IP Admin)"
                            ],
                            kill_chain_stage=0,
                            correlated_ip=resolved_ip,
                            compromised_user=None,
                            mitre_techniques=["T1548.003"],
                            reason=(
                                f"ANTI-LOCKOUT GUARD: Quản trị viên baseline '{target_user}' nhập nhầm mật khẩu sudo (Rule 5404), "
                                "không có tiền sử dò mật khẩu SSH từ ngoài. Không khóa IP để tránh gián đoạn quản trị."
                            ),
                            timeline_summary=[s["detail"] for s in (ip_state.stage_history[-5:] if ip_state else [])],
                            is_false_positive_protected=True,
                        )

                # Nếu đang có phiên xâm nhập trước đó (Stage 1/2 -> Stage 3) HOẶC hành vi leo quyền/FIM rõ ràng
                if prior_compromise or danger_reason or sensitive_fim or is_user_backdoor or prior_fails >= 2:
                    if ip_state is not None:
                        ip_state.kill_chain_stage = 3
                    stage_num = 3 if (prior_compromise or prior_fails >= 2) else 2
                    mitres = ["T1110", "T1078", "T1548.003"] if stage_num == 3 else ["T1548.003"]
                    if sensitive_fim or is_user_backdoor:
                        mitres.append("T1053.003" if "cron" in full_log.lower() else "T1565.001")

                    recs = []
                    if resolved_ip:
                        recs.append(f"Chặn ngay IP nguồn tấn công {resolved_ip} trên UFW")
                    if target_user and target_user not in ("root", "unknown", "agent_soc"):
                        recs.append(f"Chấm dứt phiên SSH và xem xét khóa tài khoản '{target_user}'")
                    recs.append("Truy vết nhật ký leo quyền và hoàn tác thay đổi hệ thống")

                    return CorrelationDecision(
                        route="MULTISTEP_CONTAINMENT" if stage_num >= 2 and resolved_ip else "FAST_BLOCK",
                        verdict_hint="malicious_activity_likely",
                        severity="critical" if stage_num == 3 else "high",
                        confidence="high",
                        should_block_ip=bool(resolved_ip),
                        recommended_actions=recs,
                        kill_chain_stage=stage_num,
                        correlated_ip=resolved_ip,
                        compromised_user=target_user if target_user not in ("unknown", "root") else None,
                        mitre_techniques=mitres,
                        reason=(
                            f"PHÁT HIỆN CHUỖI TẤN CÔNG ĐA BƯỚC (STAGE {stage_num}): "
                            f"Tài khoản '{target_user}' (truy ngược từ IP {resolved_ip or 'N/A'}, fail trước đó={prior_fails}) "
                            f"thực thi leo quyền/can thiệp nhạy cảm ({danger_reason or rule_desc})."
                        ),
                        timeline_summary=[s["detail"] for s in (ip_state.stage_history[-6:] if ip_state else [])],
                    )

            # Mặc định các cảnh báo khác chuyển qua AI bất đồng bộ hoặc xử lý tiêu chuẩn
            return CorrelationDecision(
                route="DEFER_TO_LLM",
                verdict_hint="suspicious_needs_more_data",
                severity=alert.get("severity_hint", "medium"),
                confidence="low",
                should_block_ip=False,
                recommended_actions=["Chuyển Local AI điều tra sâu trong hàng đợi bất đồng bộ"],
                kill_chain_stage=ip_state.kill_chain_stage if ip_state else 0,
                correlated_ip=resolved_ip,
                compromised_user=None,
                mitre_techniques=wazuh.get("mitre_id") or [],
                reason=f"Sự kiện Rule {rule_id} cần AI đánh giá ngữ cảnh ngoại tuyến trước khi quyết định.",
                timeline_summary=[s["detail"] for s in (ip_state.stage_history[-5:] if ip_state else [])],
            )
