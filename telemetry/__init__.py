"""
telemetry - Thu thập, trinh sát dữ liệu & Công cụ phản ứng an ninh.
Bao gồm:
  - read_logs: Kết nối SSH đọc nhật ký an ninh Linux
  - log_parser: Bóc tách cú pháp /var/log/auth.log
  - detection: Bộ quy tắc phát hiện vi phạm bảo mật
  - tools: 6 công cụ trinh sát chỉ đọc + 4 công cụ phản ứng UFW
"""

from telemetry.read_logs import run_fixed_command, HOST, USER
from telemetry.log_parser import parse_log
from telemetry.detection import detect_all, alert_to_dict
from telemetry.tools import (
    TOOLS,
    RESPONSE_TOOLS,
    block_ip,
    unblock_ip,
    verify_response,
    get_firewall_status,
    search_auth_logs,
    inspect_user_changes,
    check_ssh_config,
    inspect_active_processes,
    inspect_network_connections,
    inspect_cron_persistence,
)

__all__ = [
    "run_fixed_command",
    "HOST",
    "USER",
    "parse_log",
    "detect_all",
    "alert_to_dict",
    "TOOLS",
    "RESPONSE_TOOLS",
    "block_ip",
    "unblock_ip",
    "verify_response",
    "get_firewall_status",
    "search_auth_logs",
    "inspect_user_changes",
    "check_ssh_config",
    "inspect_active_processes",
    "inspect_network_connections",
    "inspect_cron_persistence",
]
