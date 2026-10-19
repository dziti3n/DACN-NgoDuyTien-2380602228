#!/usr/bin/env python3
"""
policy_engine.py - Lớp kiểm soát và thực thi chính sách an toàn (Guardrails & Policy Engine).
Bảo vệ hệ thống khỏi việc AI Agent bị Prompt Injection hoặc nhầm lẫn dẫn đến hành động nguy hiểm.
Chạy bằng mã nguồn Python xác định (Deterministic Rule-Based), hoàn toàn không phụ thuộc vào LLM.
"""

import ipaddress
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List, Tuple


# Danh sách các IP và Subnet luôn luôn được bảo vệ (Whitelist - Cấm chặn trong mọi trường hợp)
# Tránh trường hợp Agent bị lừa hoặc nhầm lẫn tự chặn máy Host Windows (192.168.56.1),
# loopback, hoặc chính IP của máy chủ lab.
DEFAULT_PROTECTED_IPS = {
    "127.0.0.1",
    "::1",
    "192.168.56.1",    # Host Windows (VirtualBox Host-Only Adapter)
    "192.168.56.101",  # Target Lab Server Linux
}

DEFAULT_PROTECTED_NETWORKS = [
    # Có thể thêm dải mạng nội bộ bảo vệ nếu cần:
    # ipaddress.ip_network("127.0.0.0/8"),
]


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
        return True, f"IP {cleaned} nằm trong danh sách ĐẶC BIỆT ĐƯỢC BẢO VỆ (Protected Whitelist - Host/Lab Server)."

    ip_obj = ipaddress.ip_address(cleaned)
    if ip_obj.is_loopback:
        return True, f"IP {cleaned} là địa chỉ Loopback cục bộ (127.0.0.0/8 hoặc ::1)."

    for net in DEFAULT_PROTECTED_NETWORKS:
        if ip_obj in net:
            return True, f"IP {cleaned} thuộc dải mạng được bảo vệ ({net})."

    return False, "IP không nằm trong danh sách bảo vệ."


def evaluate_action(action: str, target: str, context: Optional[dict] = None) -> PolicyDecision:
    """
    Thẩm định một hành động phản ứng dự kiến (Block IP, Unblock IP, ...).
    
    Tham số:
    - action: Tên hành động ("block_ip", "unblock_ip")
    - target: Đối tượng tác động (ví dụ: IP cần chặn)
    - context: Ngữ cảnh điều tra (verdict, severity, confidence, evidence)
    
    Trả về: PolicyDecision
    """
    context = context or {}
    
    # 1. Thẩm định hành động BLOCK IP
    if action == "block_ip":
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

        # Kiểm tra danh sách bảo vệ (QUAN TRỌNG NHẤT: Chống tự khóa mình)
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

        # Kiểm tra ngưỡng bằng chứng (Evidence Threshold)
        verdict = context.get("verdict")
        confidence = context.get("confidence", "low")
        
        # Nếu đã có kết luận điều tra:
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

        # Mọi điều kiện an toàn đều vượt qua: Cho phép nhưng BẮT BUỘC người phê duyệt (Human-in-the-Loop)
        return PolicyDecision(
            allowed=True,
            action=action,
            target=target,
            reason="Hợp lệ: IP kiểm tra đạt chuẩn an toàn, không vi phạm Whitelist. Yêu cầu phê duyệt từ chuyên viên SOC (HITL).",
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


def record_audit_log(
    action: str,
    target: str,
    operator: str,
    policy_decision: PolicyDecision,
    execution_result: dict,
    verification_result: Optional[dict] = None,
    log_dir: str = "runs"
):
    """
    Ghi nhật ký kiểm toán không thể chối bỏ (Audit Trail / Non-repudiation) vào cả
    file log dễ đọc (action_audit.log) và JSON Lines (audit_trail.jsonl).
    """
    os.makedirs(log_dir, exist_ok=True)
    now_str = datetime.now().isoformat(timespec="seconds")

    audit_entry = {
        "timestamp": now_str,
        "action": action,
        "target": target,
        "operator": operator,
        "policy": policy_decision.to_dict(),
        "execution": execution_result,
        "verification": verification_result or {},
    }

    # 1. Ghi file JSON Lines (phục vụ SIEM / Audit Tooling)
    jsonl_path = os.path.join(log_dir, "audit_trail.jsonl")
    with open(jsonl_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")

    # 2. Ghi file Text Log truyền thống
    text_path = os.path.join(log_dir, "action_audit.log")
    with open(text_path, "a", encoding="utf-8") as f:
        status_str = "SUCCESS" if execution_result.get("status") == "ok" else "FAILED"
        verified_str = "VERIFIED" if (verification_result and verification_result.get("verified")) else "UNVERIFIED"
        line = (
            f"[{now_str}] OPERATOR='{operator}' ACTION='{action}' TARGET='{target}' "
            f"POLICY='{'ALLOWED' if policy_decision.allowed else 'DENIED'}' "
            f"RESULT='{status_str}' VERIFY='{verified_str}' REASON='{policy_decision.reason}'\n"
        )
        f.write(line)

    return audit_entry

