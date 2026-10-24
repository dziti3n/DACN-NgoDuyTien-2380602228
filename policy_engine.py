#!/usr/bin/env python3
"""
policy_engine.py - Lớp kiểm soát và thực thi chính sách an toàn (Guardrails & Policy Engine).
Bảo vệ hệ thống khỏi việc AI Agent bị Prompt Injection hoặc nhầm lẫn dẫn đến hành động nguy hiểm.
Chạy bằng mã nguồn Python xác định (Deterministic Rule-Based), hoàn toàn không phụ thuộc vào LLM.
"""

import ipaddress
import json
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Optional, List, Tuple, Dict, Any


# Danh sách các IP và Subnet luôn luôn được bảo vệ (Whitelist - Cấm chặn trong mọi trường hợp)
# Tránh trường hợp Agent bị lừa hoặc nhầm lẫn tự chặn máy Host Windows (192.168.56.1),
# loopback, cổng NAT VirtualBox (10.0.2.2), hoặc chính IP của máy chủ lab.
DEFAULT_PROTECTED_IPS = {
    "127.0.0.1",
    "::1",
    "192.168.56.1",    # Host Windows (VirtualBox Host-Only Adapter)
    "192.168.56.101",  # Target Lab Server Linux
    "10.0.2.2",        # VirtualBox NAT Gateway
    "192.168.56.254",  # Host-Only Subnet Gateway
}

DEFAULT_PROTECTED_NETWORKS = [
    # Có thể bổ sung dải mạng quản trị nếu cần
]

DEFAULT_BLOCK_TTL_MINUTES = 15  # Thời gian cách ly mặc định: 15 phút
MAX_BLOCKS_PER_HOUR = 5        # Giới hạn tối đa 5 lần chặn trong 1 giờ (Anti-DoS)


def load_protected_ips() -> set:
    """Nạp danh sách IP bảo vệ từ biến môi trường hoặc dùng danh sách mặc định."""
    custom = os.getenv("PROTECTED_IPS", "")
    ips = set(DEFAULT_PROTECTED_IPS)
    if custom:
        for item in custom.split(","):
            cleaned = item.strip()
            if cleaned:
                ips.add(cleaned)
    return ips


@dataclass
class PolicyDecision:
    """Kết quả thẩm định của Policy Engine trước khi cho phép thực thi hành động."""
    allowed: bool
    action: str
    target: str
    reason: str
    requires_approval: bool = True
    risk_level: str = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self):
        return asdict(self)


def validate_ip(ip_str: str) -> Tuple[bool, str]:
    """Kiểm tra cú pháp địa chỉ IP hợp lệ (chống Command Injection & sai định dạng)."""
    if not ip_str or not isinstance(ip_str, str):
        return False, "Địa chỉ IP rỗng hoặc không đúng định dạng chuỗi."
    cleaned = ip_str.strip()
    try:
        ipaddress.ip_address(cleaned)
        return True, cleaned
    except ValueError:
        return False, f"'{ip_str}' không phải là địa chỉ IPv4 hoặc IPv6 hợp lệ."


def is_protected_ip(ip_str: str) -> Tuple[bool, str]:
    """Kiểm tra xem IP có thuộc danh sách được bảo vệ (Whitelist) không được phép chặn hay không."""
    valid, cleaned = validate_ip(ip_str)
    if not valid:
        return False, cleaned

    protected_set = load_protected_ips()
    if cleaned in protected_set:
        return True, f"IP {cleaned} nằm trong danh sách ĐẶC BIỆT ĐƯỢC BẢO VỆ (Protected Whitelist: Host/Lab/Gateway)."

    ip_obj = ipaddress.ip_address(cleaned)
    if ip_obj.is_loopback:
        return True, f"IP {cleaned} là địa chỉ Loopback cục bộ (127.0.0.0/8 hoặc ::1)."

    for net in DEFAULT_PROTECTED_NETWORKS:
        if ip_obj in net:
            return True, f"IP {cleaned} thuộc dải mạng được bảo vệ ({net})."

    return False, "IP không nằm trong danh sách bảo vệ."


def check_rate_limit(max_per_hour: int = MAX_BLOCKS_PER_HOUR, log_dir: str = "runs") -> Tuple[bool, str]:
    """
    Kiểm tra tần suất thực thi chặn IP trong 1 giờ qua.
    Chống lại kịch bản kẻ tấn công kích hoạt hàng trăm cảnh báo giả để làm tràn bảng luật UFW.
    """
    audit_jsonl = os.path.join(log_dir, "audit_trail.jsonl")
    if not os.path.exists(audit_jsonl):
        return True, "Chưa có sự kiện nào."

    one_hour_ago = datetime.now() - timedelta(hours=1)
    recent_blocks = 0

    try:
        with open(audit_jsonl, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    entry = json.loads(line_str)
                    if entry.get("action") == "block_ip" and entry.get("execution", {}).get("status") in ("ok", "success"):
                        ts_str = entry.get("timestamp")
                        if ts_str:
                            ts = datetime.fromisoformat(ts_str)
                            if ts >= one_hour_ago:
                                recent_blocks += 1
                except Exception:
                    pass
    except Exception as ex:
        return True, f"Bỏ qua kiểm tra rate limit do lỗi đọc file: {ex}"

    if recent_blocks >= max_per_hour:
        return False, f"Đã thực thi {recent_blocks} lần chặn trong 1 giờ qua (Giới hạn: tối đa {max_per_hour} lần/giờ)."
    return True, f"Tần suất an toàn ({recent_blocks}/{max_per_hour} lần trong giờ qua)."


def evaluate_action(action: str, target: str, context: Optional[dict] = None, log_dir: Optional[str] = None) -> PolicyDecision:
    """
    Thẩm định một hành động phản ứng dự kiến (Block IP, Unblock IP, ...).
    
    Tham số:
    - action: Tên hành động ("block_ip", "unblock_ip")
    - target: Đối tượng tác động (ví dụ: IP cần chặn)
    - context: Ngữ cảnh điều tra (alert, verdict, severity, confidence, evidence)
    - log_dir: Thư mục chứa audit log và active blocks (mặc định "runs")
    """
    context = context or {}
    effective_log_dir = log_dir or context.get("log_dir") or os.getenv("SOC_RUNS_DIR", "runs")
    
    # 1. Thẩm định hành động BLOCK IP
    if action == "block_ip":
        # a. Kiểm tra tính hợp lệ cú pháp IP (Chống Command Injection)
        valid, msg = validate_ip(target)
        if not valid:
            return PolicyDecision(
                allowed=False,
                action=action,
                target=target,
                reason=f"Từ chối: Cú pháp IP không hợp lệ ({msg}).",
                requires_approval=True,
                risk_level="HIGH"
            )

        # b. Kiểm tra danh sách bảo vệ (QUAN TRỌNG NHẤT: Chống tự khóa mình)
        protected, prot_msg = is_protected_ip(target)
        if protected:
            return PolicyDecision(
                allowed=False,
                action=action,
                target=target,
                reason=f"TỪ CHỐI BẢO MẬT: {prot_msg} Hệ thống không cho phép chặn để ngăn ngừa nguy cơ tự cắt kết nối quản trị.",
                requires_approval=True,
                risk_level="CRITICAL"
            )

        # c. Ràng buộc IP với Cảnh báo & Bằng chứng (Chống Prompt Injection lừa chặn IP tùy ý)
        alert = context.get("alert") or {}
        evidence = context.get("evidence") or []
        alert_src = alert.get("src_ip")

        # Thu thập các IP thực sự liên quan trong phiên điều tra
        related_ips = set()
        if alert_src:
            related_ips.add(alert_src.strip())
        for ev in evidence:
            found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(ev))
            for f_ip in found_ips:
                related_ips.add(f_ip.strip())

        # Nếu có thông tin cảnh báo/bằng chứng, IP mục tiêu BẮT BUỘC phải nằm trong đó
        if related_ips and (target.strip() not in related_ips):
            return PolicyDecision(
                allowed=False,
                action=action,
                target=target,
                reason=(
                    f"TỪ CHỐI BẢO MẬT: IP '{target}' không xuất hiện trong cảnh báo gốc ({alert_src or 'N/A'}) "
                    f"hay bất kỳ chứng cứ nào đã xác minh. Hệ thống ngăn chặn nguy cơ Prompt Injection dẫn dắt chặn IP tùy ý."
                ),
                requires_approval=True,
                risk_level="CRITICAL"
            )

        # d. Kiểm tra ngưỡng bằng chứng (Evidence Threshold)
        verdict = context.get("verdict")
        confidence = context.get("confidence", "low")
        
        if verdict == "benign_likely":
            return PolicyDecision(
                allowed=False,
                action=action,
                target=target,
                reason="Từ chối: Kết luận điều tra của Agent là 'benign_likely' (bình thường), không được áp dụng biện pháp ngăn chặn.",
                requires_approval=True,
                risk_level="MEDIUM"
            )
        
        if verdict == "insufficient_data" and confidence == "low":
            return PolicyDecision(
                allowed=False,
                action=action,
                target=target,
                reason="Từ chối: Dữ liệu chưa đủ xác minh (insufficient_data) và độ tin cậy thấp, cần điều tra thêm trước khi chặn.",
                requires_approval=True,
                risk_level="MEDIUM"
            )

        # e. Kiểm tra Rate Limiting (Giới hạn tần suất)
        rate_ok, rate_msg = check_rate_limit(max_per_hour=MAX_BLOCKS_PER_HOUR, log_dir=effective_log_dir)
        if not rate_ok:
            return PolicyDecision(
                allowed=False,
                action=action,
                target=target,
                reason=f"TỪ CHỐI BẢO MẬT: {rate_msg} Vui lòng đợi hoặc gỡ chặn các IP cũ trước khi thực hiện thêm.",
                requires_approval=True,
            )

        # Mọi điều kiện an toàn đều vượt qua: Cho phép nhưng BẮT BUỘC người phê duyệt (Human-in-the-Loop)
        return PolicyDecision(
            allowed=True,
            action=action,
            target=target,
            reason=f"Hợp lệ: IP kiểm tra đạt chuẩn an toàn, nằm trong cảnh báo, không vi phạm Whitelist. Áp dụng thời hạn cách ly {DEFAULT_BLOCK_TTL_MINUTES} phút. Yêu cầu phê duyệt từ chuyên viên SOC (HITL).",
            requires_approval=True,
            risk_level="HIGH"
        )

    # 2. Thẩm định hành động UNBLOCK IP
    elif action == "unblock_ip":
        valid, msg = validate_ip(target)
        if not valid:
            return PolicyDecision(
                allowed=False,
                action=action,
                target=target,
                reason=f"Từ chối: Cú pháp IP không hợp lệ ({msg}).",
                requires_approval=True,
                risk_level="MEDIUM"
            )
        return PolicyDecision(
            allowed=True,
            action=action,
            target=target,
            reason="Hợp lệ: Cho phép gỡ bỏ luật chặn IP theo yêu cầu người vận hành (HITL).",
            requires_approval=True,
            risk_level="MEDIUM"
        )

    # Các hành động chưa được hỗ trợ hoặc không nằm trong danh mục
    return PolicyDecision(
        allowed=False,
        action=action,
        target=target,
        reason=f"Từ chối: Hành động '{action}' không nằm trong danh mục chính sách được cấp phép của SOC Agent.",
        requires_approval=True,
        risk_level="CRITICAL"
    )


# ==============================================================
# QUẢN LÝ THỜI HẠN CÁCH LY IP (TTL MANAGEMENT)
# ==============================================================

def get_active_blocks_file(log_dir: str = "runs") -> str:
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, "active_blocks.json")


def load_active_blocks(log_dir: str = "runs") -> Dict[str, Any]:
    path = get_active_blocks_file(log_dir)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_active_block(
    ip: str,
    ttl_minutes: int = DEFAULT_BLOCK_TTL_MINUTES,
    reason: str = "",
    operator: str = "SOC Analyst",
    log_dir: str = "runs"
) -> Dict[str, Any]:
    """Lưu trữ thông tin chặn IP kèm thời gian hết hạn (TTL)."""
    blocks = load_active_blocks(log_dir)
    now = datetime.now()
    expires_at = now + timedelta(minutes=ttl_minutes)

    entry = {
        "ip": ip,
        "blocked_at": now.isoformat(timespec="seconds"),
        "ttl_minutes": ttl_minutes,
        "expires_at": expires_at.isoformat(timespec="seconds"),
        "reason": reason,
        "operator": operator
    }
    blocks[ip] = entry

    path = get_active_blocks_file(log_dir)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(blocks, f, ensure_ascii=False, indent=2)

    return entry


def remove_active_block(ip: str, log_dir: str = "runs") -> bool:
    """Xóa IP khỏi danh sách theo dõi khi đã gỡ chặn."""
    blocks = load_active_blocks(log_dir)
    if ip in blocks:
        del blocks[ip]
        path = get_active_blocks_file(log_dir)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(blocks, f, ensure_ascii=False, indent=2)
        return True
    return False


def get_expired_blocks(log_dir: str = "runs") -> List[str]:
    """Tìm danh sách các IP đã hết hạn thời gian cách ly để tiến hành tự động gỡ bỏ."""
    blocks = load_active_blocks(log_dir)
    now = datetime.now()
    expired = []

    for ip, info in blocks.items():
        exp_str = info.get("expires_at")
        if exp_str:
            try:
                exp_dt = datetime.fromisoformat(exp_str)
                if now >= exp_dt:
                    expired.append(ip)
            except Exception:
                pass
    return expired


def record_audit_log(
    action: str,
    target: str,
    operator: str,
    policy_decision: Optional[PolicyDecision] = None,
    execution_result: Optional[dict] = None,
    verification_result: Optional[dict] = None,
    log_dir: str = "runs"
):
    """
    Ghi nhật ký kiểm toán có cấu trúc (Structured Audit Trail) vào cả
    file log dễ đọc (action_audit.log) và JSON Lines (audit_trail.jsonl).
    """
    os.makedirs(log_dir, exist_ok=True)
    now_str = datetime.now().isoformat(timespec="seconds")

    audit_entry = {
        "timestamp": now_str,
        "action": action,
        "target": target,
        "operator": operator,
        "policy": policy_decision.to_dict() if policy_decision else {"allowed": True, "reason": "N/A or System Automated"},
        "execution": execution_result or {},
        "verification": verification_result or {},
    }

    # 1. Ghi file JSON Lines (phục vụ SIEM / Audit Tooling)
    jsonl_path = os.path.join(log_dir, "audit_trail.jsonl")
    with open(jsonl_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")

    # 2. Ghi file Text Log truyền thống
    text_path = os.path.join(log_dir, "action_audit.log")
    with open(text_path, "a", encoding="utf-8") as f:
        status_str = "SUCCESS" if (execution_result and execution_result.get("status") in ("ok", "success")) else "FAILED"
        verified_str = "VERIFIED" if (verification_result and verification_result.get("verified")) else "UNVERIFIED"
        policy_str = "ALLOWED" if (not policy_decision or policy_decision.allowed) else "DENIED"
        reason_str = policy_decision.reason if policy_decision else "Automated System Action"
        line = (
            f"[{now_str}] OPERATOR='{operator}' ACTION='{action}' TARGET='{target}' "
            f"POLICY='{policy_str}' "
            f"RESULT='{status_str}' VERIFY='{verified_str}' REASON='{reason_str}'\n"
        )
        f.write(line)

    return audit_entry
