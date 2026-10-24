#!/usr/bin/env bash
# ==============================================================================
# scripts/setup_wazuh_integration.sh
# Kịch bản tự động cấu hình Wazuh SIEM Manager nhả Alert cho AI SOC Agent
# Hỗ trợ xác thực bảo mật Token qua <api_key> và Header X-SOC-Token
# Chạy script này trên máy chủ Wazuh Manager (Ubuntu/Debian) bằng quyền root:
#   sudo bash setup_wazuh_integration.sh <WINDOWS_HOST_IP> <PORT> <AUTH_TOKEN>
# ==============================================================================

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "[-] Vui lòng chạy kịch bản này bằng quyền root: sudo bash $0 <WINDOWS_HOST_IP> [PORT] [AUTH_TOKEN]"
    exit 1
fi

AGENT_HOST="${1:-192.168.56.1}"
AGENT_PORT="${2:-5000}"
AUTH_TOKEN="${3:-<WEBHOOK_AUTH_TOKEN>}"
HOOK_URL="http://${AGENT_HOST}:${AGENT_PORT}/api/v1/wazuh-alert"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
INTEGRATION_SCRIPT="/var/ossec/integrations/custom-ai-soc"

echo "=============================================================================="
echo "🛡️  CẤU HÌNH WAZUH SIEM MANAGER NHẢ ALERT CHO AI SOC AGENT (BẢO MẬT)"
echo "=============================================================================="
echo "[*] Địa chỉ AI SOC Agent Host: ${AGENT_HOST}:${AGENT_PORT}"
echo "[*] Webhook Endpoint:          ${HOOK_URL}"
echo "[*] Shared Secret Token:       ${AUTH_TOKEN}"
echo "[*] Tệp cấu hình Wazuh:        ${OSSEC_CONF}"
echo "------------------------------------------------------------------------------"

if [ ! -f "$OSSEC_CONF" ]; then
    echo "[-] Không tìm thấy tệp ${OSSEC_CONF}. Máy này đã cài đặt Wazuh Manager chưa?"
    exit 1
fi

# 1. Tạo script tích hợp /var/ossec/integrations/custom-ai-soc
echo "[*] 1/3. Đang tạo script chuyển tiếp Webhook an toàn tại ${INTEGRATION_SCRIPT}..."
cat << 'EOF' > "${INTEGRATION_SCRIPT}"
#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error

# Tham số do Wazuh integratord truyền vào:
# sys.argv[1]: Đường dẫn tệp alert JSON tạm
# sys.argv[2]: API key / Token (khai báo trong ossec.conf)
# sys.argv[3]: Hook URL

if len(sys.argv) < 2:
    sys.exit(0)

alert_file = sys.argv[1]
api_key = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else ""
hook_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else "http://192.168.56.1:5000/api/v1/wazuh-alert"

try:
    with open(alert_file, "r", encoding="utf-8") as f:
        alert_json = json.load(f)
except Exception:
    sys.exit(0)

try:
    data_bytes = json.dumps(alert_json).encode("utf-8")
    req = urllib.request.Request(
        hook_url,
        data=data_bytes,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-SOC-Token": api_key
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        pass
except Exception:
    pass

sys.exit(0)
EOF

chmod 750 "${INTEGRATION_SCRIPT}"
if getent group wazuh >/dev/null 2>&1; then
    chown root:wazuh "${INTEGRATION_SCRIPT}"
else
    chown root:root "${INTEGRATION_SCRIPT}"
fi
echo "[+] Đã tạo script ${INTEGRATION_SCRIPT} thành công."

# 2. Cấu hình ossec.conf
echo "[*] 2/3. Đang kiểm tra cấu hình <integration> trong ${OSSEC_CONF}..."
# Cấu hình rule_id cụ thể đối chiếu chuẩn Wazuh ruleset:
#   - 5710: sshd: Attempt to login using a non-existent user (Level 5)
#   - 5711: sshd: authentication failed (Level 5)
#   - 5712: sshd: brute force trying to get access to the system (Level 10 - non-existent user)
#   - 5760: sshd: Authentication failed with an existing user (Level 5)
#   - 5763: sshd: brute force trying to get access to the system. Authentication failed (Level 10 - existing user)
#   - 5401: sudo: Failed attempt to run sudo (Level 5)
#   - 5402: sudo: successful sudo to ROOT (Level 3)
#   - 5404: sudo: 3 failed attempts to run sudo (Level 10)
#   - 5405: sudo: user NOT in sudoers executed command (Level 5/7)
#   - 550:  ossec: Integrity checksum changed / FIM (Level 7)
# Lưu ý: Rule 5715 (Accepted publickey) không đưa vào live filter để tránh đẩy mọi phiên SSH hợp lệ vào hàng đợi SOAR.
RULE_FILTER="5710,5711,5712,5760,5763,5401,5402,5404,5405,550"

if grep -q "custom-ai-soc" "$OSSEC_CONF"; then
    echo "[!] Cấu hình custom-ai-soc đã tồn tại trong ${OSSEC_CONF}."
    echo "[*] Đang cập nhật hook_url, api_key và rule_id..."
    sed -i "s|<hook_url>.*</hook_url>|<hook_url>${HOOK_URL}</hook_url>|g" "$OSSEC_CONF"
else
    echo "[*] Đang chèn khối <integration> bảo mật vào trước </ossec_config>..."
    INTEGRATION_BLOCK="  <integration>\n    <name>custom-ai-soc</name>\n    <hook_url>${HOOK_URL}</hook_url>\n    <api_key>${AUTH_TOKEN}</api_key>\n    <rule_id>${RULE_FILTER}</rule_id>\n    <alert_format>json</alert_format>\n  </integration>\n</ossec_config>"
    sed -i "s|</ossec_config>|${INTEGRATION_BLOCK}|g" "$OSSEC_CONF"
fi
echo "[+] Đã cấu hình ${OSSEC_CONF} thành công."

# 3. Khởi động lại dịch vụ wazuh-manager
echo "[*] 3/3. Đang khởi động lại dịch vụ wazuh-manager..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart wazuh-manager
    echo "✅ Wazuh Manager đã được khởi động lại thành công!"
elif command -v service >/dev/null 2>&1; then
    service wazuh-manager restart
    echo "✅ Wazuh Manager đã được khởi động lại thành công!"
else
    /var/ossec/bin/wazuh-control restart || true
fi

echo "=============================================================================="
echo "🎉 HOÀN TẤT THIẾT LẬP WAZUH SIEM INTEGRATION!"
echo "   Alert được lọc theo danh sách Rule trọng yếu (${RULE_FILTER}):"
echo "   Endpoint:     ${HOOK_URL}"
echo "   Auth Token:   ${AUTH_TOKEN}"
echo "   Phân quyền:   chmod 750 ${INTEGRATION_SCRIPT} (root:wazuh)"
echo "   Lưu ý:        Định kỳ xoay vòng (rotate) Auth Token để đảm bảo an toàn."
echo "=============================================================================="
