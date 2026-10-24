# ==============================================================================
# scripts/setup_windows_firewall.ps1
# Cấu hình Windows Firewall cho phép máy ảo Wazuh gửi Webhook tới cổng 5000
# Chạy trên Windows PowerShell bằng quyền Administrator:
#   powershell -ExecutionPolicy Bypass -File scripts\setup_windows_firewall.ps1
# ==============================================================================

# Kiểm tra quyền Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[-] Vui lòng chạy PowerShell bằng quyền Administrator (Run as Administrator) để cấu hình Firewall."
    exit 1
}

$ruleName = "AI-SOC-Wazuh-Webhook"
$port = 5000
$allowedSubnet = "192.168.56.0/24"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "🛡️  CẤU HÌNH WINDOWS FIREWALL CHO AI SOC WAZUH WEBHOOK (PORT $port)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

# Kiểm tra xem rule đã tồn tại chưa
$existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

if ($existingRule) {
    Write-Host "[*] Luật '$ruleName' đã tồn tại. Đang cập nhật lại..." -ForegroundColor Yellow
    Set-NetFirewallRule -DisplayName $ruleName -Enabled True -Direction Inbound -Protocol TCP -LocalPort $port -RemoteAddress "$allowedSubnet,127.0.0.1" -Action Allow
} else {
    Write-Host "[*] Đang tạo luật mới '$ruleName' cho phép kết nối từ $allowedSubnet..." -ForegroundColor Green
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -RemoteAddress "$allowedSubnet,127.0.0.1" -Action Allow | Out-Null
}

Write-Host "✅ Đã cho phép Inbound TCP Port $port từ subnet $allowedSubnet (Host-Only Network)!" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Cyan
