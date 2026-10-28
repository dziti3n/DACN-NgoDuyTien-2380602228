"""
integrations - Tiếp nhận cảnh báo SIEM, Tiến trình tự hành & Báo động.
Bao gồm:
  - wazuh_listener: Webhook Server tiếp nhận alert từ Wazuh & Fast-Path Triage
  - monitor_daemon: Tiến trình giám sát an ninh tự hành liên tục
  - notifier: Báo cáo sự cố chuẩn HTML gửi qua Gmail SMTP
"""

from integrations.wazuh_listener import (
    start_wazuh_listener,
    normalize_wazuh_alert,
    fast_path_triage,
    WazuhWebhookServer,
    WazuhWebhookManager,
    extract_ip_from_payload,
    map_wazuh_level_to_severity,
    validate_wazuh_payload_schema,
    is_allowed_client_ip,
)
from integrations.monitor_daemon import SOCMonitorDaemon
from integrations.notifier import (
    send_alert_email,
    build_alert_html,
    send_test_email,
    get_email_config,
)

__all__ = [
    "start_wazuh_listener",
    "normalize_wazuh_alert",
    "fast_path_triage",
    "WazuhWebhookServer",
    "WazuhWebhookManager",
    "extract_ip_from_payload",
    "map_wazuh_level_to_severity",
    "validate_wazuh_payload_schema",
    "is_allowed_client_ip",
    "SOCMonitorDaemon",
    "send_alert_email",
    "build_alert_html",
    "send_test_email",
    "get_email_config",
]
