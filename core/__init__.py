"""
core - Trọng tâm AI SOC Agent & Lớp kiểm soát an toàn xác định.
Bao gồm:
  - agent: Chu trình điều tra ReAct (Reasoning + Acting)
  - llm_client: Kết nối mô hình LLM cục bộ (Ollama)
  - policy_engine: Lớp kiểm soát chính sách (Guardrails, Whitelist, TTL, Rate Limit)
"""

from core.agent import investigate
from core.llm_client import get_llm_client
from core.policy_engine import (
    evaluate_action,
    record_audit_log,
    is_protected_ip,
    validate_ip,
    load_protected_ips,
    save_active_block,
    remove_active_block,
    load_active_blocks,
    get_expired_blocks,
    DEFAULT_BLOCK_TTL_MINUTES,
)
from core.schema import (
    SeverityLevel,
    IncidentStatus,
    LogLevel,
    TimelineEvent,
    ProposedAction,
    Incident,
    LogEntry,
    map_to_severity_level,
    get_severity_badge,
    get_status_badge,
    get_log_level_badge,
    parse_log_entry,
    build_incident_from_alert,
    get_default_incidents,
    DEFAULT_TERMINAL_LOGS,
    get_default_terminal_logs,
)

__all__ = [
    "investigate",
    "get_llm_client",
    "evaluate_action",
    "record_audit_log",
    "is_protected_ip",
    "validate_ip",
    "load_protected_ips",
    "save_active_block",
    "remove_active_block",
    "load_active_blocks",
    "get_expired_blocks",
    "DEFAULT_BLOCK_TTL_MINUTES",
    "SeverityLevel",
    "IncidentStatus",
    "LogLevel",
    "TimelineEvent",
    "ProposedAction",
    "Incident",
    "LogEntry",
    "map_to_severity_level",
    "get_severity_badge",
    "get_status_badge",
    "get_log_level_badge",
    "parse_log_entry",
    "build_incident_from_alert",
    "get_default_incidents",
    "DEFAULT_TERMINAL_LOGS",
    "get_default_terminal_logs",
]

