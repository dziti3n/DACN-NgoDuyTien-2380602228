# ==============================================================================
# notifier.py - Hệ thống Thông báo Email Cảnh báo Tự động (SOC Email Notifier)
# Hỗ trợ gửi Email định dạng HTML chuyên nghiệp qua Gmail SMTP (TLS 587)
# Chế độ Kép: Gửi live thật hoặc lưu bản tin HTML (Preview) nếu chưa cấu hình.
# ==============================================================================

import email.utils
import json
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

ALERTS_DIR = Path("runs/alerts")


def get_email_config():
    """Đọc cấu hình email từ biến môi trường."""
    load_dotenv()
    enabled_str = os.getenv("ALERT_EMAIL_ENABLED", "false").lower()
    return {
        "enabled": enabled_str in ("true", "1", "yes"),
        "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
        "sender_email": os.getenv("SENDER_EMAIL", "").strip(),
        "sender_password": os.getenv("SENDER_APP_PASSWORD", "").strip(),
        "recipient_email": os.getenv("RECIPIENT_EMAIL", "").strip() or os.getenv("SENDER_EMAIL", "").strip(),
    }


def build_alert_html(alert: dict, run: dict = None, response_info: dict = None) -> str:
    """
    Sinh mã HTML email cảnh báo an ninh chuẩn SOC với giao diện hiện đại.
    """
    alert = alert or {}
    run = run or {}
    conclusion = run.get("conclusion", {})
    response_info = response_info or {}

    rule = alert.get("rule", "Unknown")
    sev = (conclusion.get("severity") or alert.get("severity_hint") or "medium").upper()
    summary = conclusion.get("summary") or alert.get("summary") or "Không có tóm tắt"
    verdict = conclusion.get("verdict", "chưa có kết luận")
    confidence = conclusion.get("confidence", "medium").upper()
    src_ip = alert.get("src_ip") or alert.get("details", {}).get("src_ip", "N/A")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Bảng màu theo mức độ nghiêm trọng
    sev_colors = {
        "CRITICAL": {"bg": "#7f1d1d", "border": "#dc2626", "badge": "#ef4444"},
        "HIGH": {"bg": "#7c2d12", "border": "#ea580c", "badge": "#f97316"},
        "MEDIUM": {"bg": "#78350f", "border": "#d97706", "badge": "#f59e0b"},
        "LOW": {"bg": "#1e3a8a", "border": "#2563eb", "badge": "#3b82f6"},
    }
    color = sev_colors.get(sev, sev_colors["MEDIUM"])

    # Phân loại trạng thái phản ứng
    action_type = response_info.get("action", "none")
    action_status = response_info.get("status", "none")
    action_reason = response_info.get("reason", "")
    target_ip = response_info.get("target_ip", src_ip)
    ttl_minutes = response_info.get("ttl_minutes", 15)

    if action_status == "blocked":
        action_html = f"""
        <div style="background-color: #064e3b; border-left: 4px solid #10b981; padding: 12px 16px; border-radius: 4px; margin-top: 15px;">
            <strong style="color: #6ee7b7; font-size: 14px;">🛡️ HÀNH ĐỘNG PHẢN ỨNG TỰ ĐỘNG: ĐÃ CÁCH LY IP THÀNH CÔNG</strong>
            <p style="margin: 6px 0 0 0; color: #e2e8f0; font-size: 13px;">
                Địa chỉ IP <code>{target_ip}</code> đã được tự động thêm vào tường lửa UFW với quy tắc chặn (Rule Deny #1).<br>
                Thời hạn cách ly tạm thời: <strong>{ttl_minutes} phút</strong> (Hệ thống sẽ tự động mở khóa sau khi hết thời hạn TTL).
            </p>
        </div>
        """
    elif action_status == "rejected":
        action_html = f"""
        <div style="background-color: #451a03; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 4px; margin-top: 15px;">
            <strong style="color: #fde68a; font-size: 14px;">⚠️ HÀNH ĐỘNG BỊ TỪ CHỐI BỞI POLICY ENGINE</strong>
            <p style="margin: 6px 0 0 0; color: #e2e8f0; font-size: 13px;">
                Đề xuất chặn IP <code>{target_ip}</code> đã bị từ chối bởi cơ chế an toàn Guardrails.<br>
                <strong>Lý do:</strong> {action_reason}
            </p>
        </div>
        """
    elif action_status == "pending_approval":
        action_html = f"""
        <div style="background-color: #1e293b; border-left: 4px solid #38bdf8; padding: 12px 16px; border-radius: 4px; margin-top: 15px;">
            <strong style="color: #7dd3fc; font-size: 14px;">⏳ CHỜ CHUYÊN VIÊN PHÊ DUYỆT (SEMI-AUTONOMOUS)</strong>
            <p style="margin: 6px 0 0 0; color: #e2e8f0; font-size: 13px;">
                Agent đề xuất chặn IP <code>{target_ip}</code>. Chế độ Auto-Block hiện đang tắt, vui lòng truy cập Web Dashboard để bấm duyệt thực thi.
            </p>
        </div>
        """
    else:
        action_html = f"""
        <div style="background-color: #1e293b; border-left: 4px solid #64748b; padding: 12px 16px; border-radius: 4px; margin-top: 15px;">
            <strong style="color: #cbd5e1; font-size: 14px;">ℹ️ TRẠNG THÁI PHẢN ỨNG: CHỈ GHI NHẬN & GIÁM SÁT</strong>
            <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 13px;">Không phát sinh yêu cầu cô lập tường lửa từ kết luận điều tra này.</p>
        </div>
        """

    # Danh sách bằng chứng
    evidence_items = conclusion.get("evidence", [])
    if evidence_items:
        evidence_html = "".join([f"<li style='margin-bottom: 4px;'>{ev}</li>" for ev in evidence_items])
    else:
        evidence_html = "<li>Được phát hiện trực tiếp từ luồng sự kiện phân tích log hệ thống.</li>"

    # Chi tiết alert
    details = alert.get("details", {})
    details_str = json.dumps(details, ensure_ascii=False, indent=2) if details else "{}"

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Security Alert</title>
</head>
<body style="margin: 0; padding: 20px; background-color: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0;">
    <div style="max-width: 680px; margin: 0 auto; background-color: #111827; border: 1px solid #1f2937; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
        
        <!-- Header Banner -->
        <div style="background: linear-gradient(90deg, {color['bg']}, #111827); border-bottom: 2px solid {color['border']}; padding: 20px 24px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: #94a3b8;">🛡️ AI SOC DEFENSE PLATFORM</span>
                <span style="background-color: {color['badge']}; color: #ffffff; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 800; letter-spacing: 1px;">{sev} SEVERITY</span>
            </div>
            <h1 style="margin: 10px 0 0 0; font-size: 20px; font-weight: 700; color: #ffffff; line-height: 1.3;">
                🚨 Cảnh Báo An Ninh: {rule.upper()}
            </h1>
            <p style="margin: 6px 0 0 0; font-size: 12px; color: #cbd5e1;">Thời gian phát hiện: {timestamp} (Local Time)</p>
        </div>

        <div style="padding: 24px;">
            
            <!-- Summary Box -->
            <div style="background-color: #1e293b; border-radius: 6px; padding: 16px; margin-bottom: 20px;">
                <h3 style="margin: 0 0 8px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8;">Tóm Tắt Sự Cố</h3>
                <p style="margin: 0; font-size: 14px; line-height: 1.5; color: #f8fafc;">{summary}</p>
            </div>

            <!-- Key Metrics Grid -->
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <tr>
                    <td style="padding: 10px 12px; background-color: #172033; border: 1px solid #1e293b; width: 50%;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Địa Chỉ IP Tấn Công</div>
                        <div style="font-size: 16px; font-weight: 700; color: #f43f5e; font-family: monospace; margin-top: 4px;">{src_ip}</div>
                    </td>
                    <td style="padding: 10px 12px; background-color: #172033; border: 1px solid #1e293b; width: 50%;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Kết Luận AI (Verdict)</div>
                        <div style="font-size: 14px; font-weight: 700; color: #38bdf8; margin-top: 4px;">{verdict}</div>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px 12px; background-color: #172033; border: 1px solid #1e293b;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Độ Tin Cậy (Confidence)</div>
                        <div style="font-size: 14px; font-weight: 600; color: #e2e8f0; margin-top: 4px;">{confidence}</div>
                    </td>
                    <td style="padding: 10px 12px; background-color: #172033; border: 1px solid #1e293b;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Mô Hình Điều Tra</div>
                        <div style="font-size: 14px; font-weight: 600; color: #a78bfa; margin-top: 4px;">{run.get('model', 'qwen3:4b (Local Ollama)')}</div>
                    </td>
                </tr>
            </table>

            <!-- Verified Evidence -->
            <div style="margin-bottom: 20px;">
                <h3 style="margin: 0 0 10px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8;">
                    🔍 Bằng Chứng Đã Xác Thực Qua AI ReAct:
                </h3>
                <ul style="margin: 0; padding-left: 20px; font-size: 13px; color: #cbd5e1; line-height: 1.6;">
                    {evidence_html}
                </ul>
            </div>

            <!-- Action Status Box -->
            {action_html}

            <!-- Technical Raw Details -->
            <div style="margin-top: 24px; border-top: 1px solid #1e293b; padding-top: 16px;">
                <details>
                    <summary style="font-size: 12px; color: #64748b; cursor: pointer; user-select: none;">
                        Xem thông tin kỹ thuật thô (Raw Alert Metadata)
                    </summary>
                    <pre style="background-color: #0b0f19; border: 1px solid #1e293b; border-radius: 4px; padding: 10px; font-size: 11px; color: #94a3b8; overflow-x: auto; margin-top: 8px;">{details_str}</pre>
                </details>
            </div>

        </div>

        <!-- Footer -->
        <div style="background-color: #0d131f; border-top: 1px solid #1e293b; padding: 14px 24px; font-size: 11px; color: #64748b; text-align: center;">
            Hệ thống AI SOC Agent hoạt động độc lập tại máy trạm cục bộ (Air-Gapped / Local LLM).<br>
            Bảo mật tối đa dữ liệu nhạy cảm theo tiêu chuẩn Zero Cloud Data Leakage.
        </div>

    </div>
</body>
</html>
    """
    return html.strip()


def send_alert_email(
    subject: str,
    html_content: str,
    plain_text: str = "",
    recipient: str = None,
    save_preview: bool = True
) -> dict:
    """
    Gửi email cảnh báo qua giao thức SMTP Gmail.
    Nếu cấu hình chưa đầy đủ hoặc gửi lỗi, tự động lưu file HTML vào runs/alerts/
    mà không làm gián đoạn chương trình.
    """
    config = get_email_config()
    target_recipient = recipient or config["recipient_email"]
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    preview_path = ALERTS_DIR / f"alert_{timestamp_str}.html"

    # Luôn lưu file preview HTML vào thư mục runs/alerts/ để tra cứu offline
    if save_preview:
        try:
            with open(preview_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as ex:
            print(f"[!] Không thể lưu file preview HTML: {ex}")

    # Kiểm tra xem tính năng gửi email có được bật hay không
    if not config["enabled"]:
        return {
            "status": "skipped",
            "reason": "ALERT_EMAIL_ENABLED=false trong cấu hình .env",
            "preview_path": str(preview_path),
        }

    # Kiểm tra tài khoản và mật khẩu ứng dụng
    if not config["sender_email"] or not config["sender_password"] or not target_recipient:
        return {
            "status": "skipped",
            "reason": "Thiếu SENDER_EMAIL, SENDER_APP_PASSWORD hoặc RECIPIENT_EMAIL trong .env",
            "preview_path": str(preview_path),
        }

    # Khởi tạo gói tin Email MIME Multipart
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = email.utils.formataddr(("AI SOC Agent Alert", config["sender_email"]))
    msg["To"] = target_recipient
    msg["Date"] = email.utils.formatdate(localtime=True)

    text_part = MIMEText(plain_text or "Cảnh báo an ninh từ AI SOC Agent. Vui lòng mở bằng ứng dụng hỗ trợ HTML.", "plain", "utf-8")
    html_part = MIMEText(html_content, "html", "utf-8")
    msg.attach(text_part)
    msg.attach(html_part)

    try:
        # Kết nối tới SMTP Server (smtp.gmail.com:587)
        server = smtplib.SMTP(config["smtp_server"], config["smtp_port"], timeout=15)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(config["sender_email"], config["sender_password"])
        server.sendmail(config["sender_email"], [target_recipient], msg.as_string())
        server.quit()

        return {
            "status": "sent",
            "recipient": target_recipient,
            "subject": subject,
            "preview_path": str(preview_path),
        }
    except smtplib.SMTPAuthenticationError as auth_err:
        err_msg = (
            f"Lỗi xác thực Gmail SMTP: {auth_err}. "
            "Lưu ý: Bạn phải tạo 'Mật khẩu ứng dụng' (App Password 16 ký tự) trong Google Account "
            "(Security -> 2-Step Verification -> App passwords), không dùng mật khẩu tài khoản thường."
        )
        return {
            "status": "error",
            "error": err_msg,
            "preview_path": str(preview_path),
        }
    except Exception as ex:
        return {
            "status": "error",
            "error": f"Lỗi gửi email: {str(ex)}",
            "preview_path": str(preview_path),
        }


def send_test_email(recipient: str = None) -> dict:
    """Gửi một email thử nghiệm (Test Email) để kiểm tra kết nối SMTP Gmail."""
    sample_alert = {
        "rule": "ssh_bruteforce",
        "severity_hint": "critical",
        "summary": "Thử nghiệm kết nối hệ thống cảnh báo email tự động từ AI SOC Agent.",
        "src_ip": "192.168.56.102",
        "details": {
            "src_ip": "192.168.56.102",
            "total_failures": 25,
            "users_tried": ["root", "admin", "ubuntu", "test"],
            "success_after_failures": ["ubuntu"],
        }
    }
    sample_run = {
        "model": "qwen3:4b (Ollama Local)",
        "conclusion": {
            "verdict": "malicious_activity_likely",
            "severity": "critical",
            "confidence": "high",
            "summary": "Đây là email kiểm tra kết nối SMTP tự động. Hệ thống AI SOC Agent hoạt động ổn định và sẵn sàng ứng phó sự cố.",
            "evidence": [
                "Đã kiểm tra cấu hình SMTP Server smtp.gmail.com:587 trơn tru",
                "Phát hiện mẫu thử nghiệm tấn công SSH Bruteforce từ máy trạm Kali",
                "Xác nhận cơ chế Policy Engine và cách ly UFW đã kích hoạt"
            ]
        }
    }
    sample_response = {
        "action": "block_ip",
        "status": "blocked",
        "target_ip": "192.168.56.102",
        "ttl_minutes": 15,
        "reason": "Tự động cách ly IP nguồn tấn công theo chính sách an toàn"
    }

    subject = "🧪 [SOC TEST] Kiểm tra kết nối hệ thống cảnh báo Email tự động"
    html_body = build_alert_html(sample_alert, sample_run, sample_response)
    plain_text = "Đây là email kiểm tra kết nối từ AI SOC Defense Agent."

    return send_alert_email(subject, html_body, plain_text, recipient=recipient)

