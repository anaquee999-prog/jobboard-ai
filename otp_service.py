import random
import time
import smtplib
import requests
from email.mime.text import MIMEText

# OTP storage (ใช้ RAM ก่อน)
otp_store = {}

OTP_EXPIRE = 300
OTP_MAX_ATTEMPT = 5


def generate_otp():
    return str(random.randint(100000, 999999))


def create_otp(user_key):

    otp = generate_otp()

    otp_store[user_key] = {
        "otp": otp,
        "expire": time.time() + OTP_EXPIRE,
        "attempt": 0
    }

    return otp


def verify_otp(user_key, input_otp):

    if user_key not in otp_store:
        return False, "OTP not found"

    data = otp_store[user_key]

    if time.time() > data["expire"]:
        del otp_store[user_key]
        return False, "OTP expired"

    if data["attempt"] >= OTP_MAX_ATTEMPT:
        del otp_store[user_key]
        return False, "Too many attempts"

    data["attempt"] += 1

    if data["otp"] == input_otp:
        del otp_store[user_key]
        return True, "OTP verified"

    return False, "Invalid OTP"


def send_email_otp(email, otp, smtp_email, smtp_password):

    msg = MIMEText(f"""
JobBoard Verification Code

Your OTP is: {otp}

This code expires in 5 minutes.
""")

    msg["Subject"] = "JobBoard OTP Verification"
    msg["From"] = smtp_email
    msg["To"] = email

    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login(smtp_email, smtp_password)
    server.send_message(msg)
    server.quit()


def send_line_otp(line_token, otp):

    url = "https://notify-api.line.me/api/notify"

    headers = {
        "Authorization": f"Bearer {line_token}"
    }

    data = {
        "message": f"\nJobBoard OTP: {otp}\nหมดอายุ 5 นาที"
    }

    requests.post(url, headers=headers, data=data)


def send_otp(user_key, email, line_token, smtp_email, smtp_password):

    otp = create_otp(user_key)

    try:
        send_email_otp(email, otp, smtp_email, smtp_password)
    except:
        pass

    try:
        send_line_otp(line_token, otp)
    except:
        pass

    return otp