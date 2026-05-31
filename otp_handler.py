"""
OTP (One-Time Password) Handler
Supports: Email OTP, SMS OTP (via Twilio)
"""

import os
import secrets
import string
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import session


SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_PHONE = os.environ.get("TWILIO_PHONE", "").strip()

OTP_LENGTH = 6
OTP_EXPIRY = 600  # 10 minutes
MAX_ATTEMPTS = 5


class OTPHandler:
    """Handle OTP generation, sending, and verification"""
    
    @staticmethod
    def generate_otp(length=OTP_LENGTH):
        """Generate random OTP code"""
        digits = string.digits
        return "".join(secrets.choice(digits) for _ in range(length))
    
    @staticmethod
    def send_email_otp(email, phone_number=None):
        """Send OTP via email"""
        if not SMTP_EMAIL or not SMTP_PASSWORD:
            return False, "Email service not configured"
        
        otp = OTPHandler.generate_otp()
        
        try:
            # Compose email
            msg = MIMEMultipart()
            msg["From"] = SMTP_EMAIL
            msg["To"] = email
            msg["Subject"] = "โค้ด OTP ของคุณ - งานใกล้บ้าน"
            
            body = f"""
            <html>
                <body>
                    <h2>ยืนยันตัวตน</h2>
                    <p>โค้ด OTP ของคุณคือ:</p>
                    <h1 style="color: #0ea5e9; letter-spacing: 5px; font-family: monospace;">
                        {otp}
                    </h1>
                    <p>โค้ดนี้จะหมดอายุใน 10 นาที</p>
                    <hr>
                    <p style="color: #666; font-size: 12px;">
                        งานใกล้บ้าน - ระบบค้นหางานรับสมัครออนไลน์
                    </p>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(body, "html"))
            
            # Send email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_EMAIL, SMTP_PASSWORD)
                server.send_message(msg)
            
            # Store OTP in session
            OTPHandler.store_otp(email, otp, "email")
            return True, "OTP sent to your email"
            
        except Exception as e:
            print(f"Error sending OTP email: {e}")
            return False, f"Failed to send OTP: {str(e)}"
    
    @staticmethod
    def send_sms_otp(phone_number):
        """Send OTP via SMS (Twilio)"""
        if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_PHONE:
            return False, "SMS service not configured"
        
        otp = OTPHandler.generate_otp()
        
        try:
            from twilio.rest import Client
            
            client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
            message = client.messages.create(
                body=f"โค้ด OTP ของคุณ: {otp}\nหมดอายุใน 10 นาที\n(งานใกล้บ้าน)",
                from_=TWILIO_PHONE,
                to=phone_number,
            )
            
            # Store OTP in session
            OTPHandler.store_otp(phone_number, otp, "sms")
            return True, "OTP sent to your phone"
            
        except Exception as e:
            print(f"Error sending OTP SMS: {e}")
            return False, f"Failed to send OTP: {str(e)}"
    
    @staticmethod
    def store_otp(identifier, otp, method="email"):
        """Store OTP in session"""
        session[f"otp_{method}_{identifier}"] = {
            "code": otp,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(seconds=OTP_EXPIRY)).isoformat(),
            "attempts": 0,
        }
    
    @staticmethod
    def verify_otp(identifier, otp_code, method="email"):
        """Verify OTP code"""
        key = f"otp_{method}_{identifier}"
        
        if key not in session:
            return False, "No OTP found"
        
        otp_data = session[key]
        
        # Check expiry
        expires_at = datetime.fromisoformat(otp_data["expires_at"])
        if datetime.now() > expires_at:
            session.pop(key, None)
            return False, "OTP expired"
        
        # Check attempts
        if otp_data["attempts"] >= MAX_ATTEMPTS:
            session.pop(key, None)
            return False, "Too many attempts"
        
        # Verify code
        if otp_data["code"] != otp_code.strip():
            otp_data["attempts"] += 1
            return False, f"Invalid OTP (attempts: {otp_data['attempts']}/{MAX_ATTEMPTS})"
        
        # OTP verified
        session.pop(key, None)
        return True, "OTP verified"
    
    @staticmethod
    def clear_otp(identifier, method="email"):
        """Clear OTP from session"""
        key = f"otp_{method}_{identifier}"
        session.pop(key, None)


class PhoneOTPFlow:
    """Handle phone number OTP registration flow"""
    
    @staticmethod
    def initiate_phone_registration(phone_number):
        """Start phone registration with OTP"""
        # Store phone temporarily
        session[f"pending_phone_registration"] = {
            "phone": phone_number,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(minutes=30)).isoformat(),
        }
        
        # Send OTP
        success, message = OTPHandler.send_sms_otp(phone_number)
        return success, message
    
    @staticmethod
    def verify_phone_registration(otp_code):
        """Verify phone registration OTP"""
        if "pending_phone_registration" not in session:
            return False, "Registration session expired"
        
        reg_data = session["pending_phone_registration"]
        phone_number = reg_data["phone"]
        
        # Verify expiry
        expires_at = datetime.fromisoformat(reg_data["expires_at"])
        if datetime.now() > expires_at:
            session.pop("pending_phone_registration", None)
            return False, "Registration session expired"
        
        # Verify OTP
        success, message = OTPHandler.verify_otp(phone_number, otp_code, "sms")
        
        if success:
            # Store verified phone in session
            session["verified_phone"] = phone_number
            session.pop("pending_phone_registration", None)
            return True, "Phone verified"
        
        return False, message
    
    @staticmethod
    def get_verified_phone():
        """Get verified phone number from session"""
        return session.get("verified_phone")
    
    @staticmethod
    def clear_phone_registration():
        """Clear phone registration data"""
        session.pop("pending_phone_registration", None)
        session.pop("verified_phone", None)
