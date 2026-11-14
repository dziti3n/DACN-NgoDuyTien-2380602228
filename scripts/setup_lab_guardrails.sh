#!/usr/bin/env bash
# ==============================================================================
# scripts/setup_lab_guardrails.sh
# Thiết lập các Wrapper Scripts an toàn và cấp quyền đặc quyền tối thiểu (Least Privilege)
# cho tài khoản agent_soc trên máy ảo Linux Lab (Ubuntu/Debian).
#
# Chạy với quyền root trên máy ảo Lab:
# sudo bash setup_lab_guardrails.sh
# ==============================================================================

set -euo pipefail

echo "[*] Bắt đầu thiết lập Lớp Phản Ứng Có Kiểm Soát (Guardrails) trên Lab Linux..."

# 1. Tạo script kiểm soát chặn IP: /usr/local/sbin/soc-block-ip
cat << 'EOF' > /usr/local/sbin/soc-block-ip
#!/usr/bin/env bash
set -euo pipefail

IP="${1:-}"

if [[ -z "$IP" ]]; then
    echo "ERROR: Thiếu địa chỉ IP cần chặn." >&2
    exit 1
fi

# Regex kiểm tra cú pháp IPv4 hợp lệ
if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "ERROR: Địa chỉ IP '$IP' không đúng định dạng IPv4." >&2
    exit 1
fi

# Whitelist các IP sống còn trên máy ảo Linux (CẤM CHẶN TUYỆT ĐỐI)
PROTECTED_IPS=("127.0.0.1" "192.168.56.1" "192.168.56.101" "10.0.2.2")
for prot in "${PROTECTED_IPS[@]}"; do
    if [[ "$IP" == "$prot" ]]; then
        echo "SECURITY ERROR: IP '$IP' nằm trong Whitelist bảo vệ sống còn của máy chủ. Cấm chặn!" >&2
        exit 2
    fi
done

# Đảm bảo cổng SSH (22/tcp) luôn được ALLOW trước khi chặn để không tự khóa SSH
/usr/sbin/ufw allow 22/tcp >/dev/null 2>&1 || true

# Thực thi chèn luật chặn lên đầu bảng (insert 1)
OUTPUT=$(/usr/sbin/ufw insert 1 deny from "$IP" to any 2>&1)
echo "SUCCESS: $OUTPUT"
EOF

chmod 0750 /usr/local/sbin/soc-block-ip
chown root:root /usr/local/sbin/soc-block-ip
echo "[+] Đã tạo /usr/local/sbin/soc-block-ip thành công."

# 2. Tạo script kiểm soát gỡ chặn IP: /usr/local/sbin/soc-unblock-ip
cat << 'EOF' > /usr/local/sbin/soc-unblock-ip
#!/usr/bin/env bash
set -euo pipefail

IP="${1:-}"

if [[ -z "$IP" ]]; then
    echo "ERROR: Thiếu địa chỉ IP cần gỡ chặn." >&2
    exit 1
fi

if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "ERROR: Địa chỉ IP '$IP' không đúng định dạng IPv4." >&2
    exit 1
fi

# Thử xóa cả 2 dạng cú pháp UFW
OUTPUT1=$(/usr/sbin/ufw delete deny from "$IP" to any 2>&1 || true)
OUTPUT2=$(/usr/sbin/ufw delete deny from "$IP" 2>&1 || true)

echo "SUCCESS: $OUTPUT1 | $OUTPUT2"
EOF

chmod 0750 /usr/local/sbin/soc-unblock-ip
chown root:root /usr/local/sbin/soc-unblock-ip
echo "[+] Đã tạo /usr/local/sbin/soc-unblock-ip thành công."

# 2.5. Tạo script ngắt phiên SSH tài khoản bị xâm nhập: /usr/local/sbin/soc-kill-session
cat << 'EOF' > /usr/local/sbin/soc-kill-session
#!/usr/bin/env bash
set -euo pipefail

TARGET_USER="${1:-}"
if [[ -z "$TARGET_USER" ]] || ! [[ "$TARGET_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    echo "ERROR: Tên tài khoản không hợp lệ." >&2
    exit 1
fi

for prot in "root" "agent_soc" "wazuh" "sshd" "daemon" "www-data"; do
    if [[ "$TARGET_USER" == "$prot" ]]; then
        echo "SECURITY ERROR: Cấm ngắt phiên tài khoản hệ thống '$TARGET_USER'." >&2
        exit 2
    fi
done

/usr/bin/pkill -KILL -u "$TARGET_USER" sshd 2>/dev/null || true
echo "SUCCESS: Terminated SSH sessions for user '$TARGET_USER'"
EOF

chmod 0750 /usr/local/sbin/soc-kill-session
chown root:root /usr/local/sbin/soc-kill-session
echo "[+] Đã tạo /usr/local/sbin/soc-kill-session thành công."

# 3. Cập nhật cấu hình sudoers tối thiểu: /etc/sudoers.d/soc_agent_ufw
cat << 'EOF' > /etc/sudoers.d/soc_agent_ufw
# Đặc quyền tối thiểu cho agent_soc (Least Privilege Guardrails)
agent_soc ALL=(ALL) NOPASSWD: /usr/local/sbin/soc-block-ip, /usr/local/sbin/soc-unblock-ip, /usr/local/sbin/soc-kill-session, /usr/sbin/ufw status numbered, /usr/sbin/ufw status
EOF

chmod 0440 /etc/sudoers.d/soc_agent_ufw
chown root:root /etc/sudoers.d/soc_agent_ufw
echo "[+] Đã cập nhật /etc/sudoers.d/soc_agent_ufw thành công."

echo ""
echo "=========================================================================="
echo "🎉 THIẾT LẬP HOÀN TẤT! Máy chủ Lab đã được bảo vệ bởi Defense-in-Depth."
echo "Tài khoản agent_soc KHÔNG THỂ chạy lệnh ufw disable/reset tự do."
echo "=========================================================================="

