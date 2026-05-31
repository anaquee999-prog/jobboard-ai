# ระบบ Login ของ JobBoard "งานใกล้บ้าน"

## 📋 ภาพรวม

ระบบ Login ใหม่ของ JobBoard รองรับ 3 วิธีการลงชื่อเข้าใช้:

1. **เบอร์โทรศัพท์ + รหัสผ่าน** (Phone)
2. **Google OAuth 2.0** (Google Account)
3. **Facebook OAuth 2.0** (Facebook Account)

พร้อมด้วยระบบ OTP (One-Time Password) สำหรับการยืนยันตัวตน

---

## 🔐 ประเภทการล็อกอิน

### 1. Phone + Password (เบอร์โทรศัพท์ + รหัสผ่าน)

**ลงทะเบียน:**
- ไปที่ `/register`
- เลือก "ลงทะเบียนด้วยเบอร์โทรศัพท์"
- กรอกเบอร์โทร (จะส่ง OTP 6 หลัก)
- ยืนยัน OTP ที่ได้รับ
- ตั้งรหัสผ่าน (อย่างน้อย 6 ตัวอักษร)

**เข้าสู่ระบบ:**
```bash
POST /login
Content-Type: application/x-www-form-urlencoded

phone_number=0812345678&password=your-password
```

### 2. Google OAuth 2.0

**ขั้นตอนการตั้งค่า:**

1. ไปที่ [Google Cloud Console](https://console.cloud.google.com)
2. สร้าง Project ใหม่
3. เปิด "OAuth 2.0 Credentials"
4. Create "OAuth 2.0 Client ID" > "Web application"
5. เพิ่ม Authorized JavaScript origins:
   ```
   https://jobboard-ai-app.onrender.com
   http://localhost:5000
   ```
6. เพิ่ม Authorized redirect URIs:
   ```
   https://jobboard-ai-app.onrender.com/auth/google/callback
   http://localhost:5000/auth/google/callback
   ```
7. Copy `Client ID` และ `Client Secret` ไปยัง `.env`

**ตั้งค่า .env:**
```env
GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxx
GOOGLE_REDIRECT_URI=https://jobboard-ai-app.onrender.com/auth/google/callback
```

**ใช้งาน:**
- ปุ่ม "Sign in with Google" ที่หน้า login
- URL: `/auth/google/initiate`

### 3. Facebook OAuth 2.0

**ขั้นตอนการตั้งค่า:**

1. ไปที่ [Facebook Developers](https://developers.facebook.com)
2. สร้าง App ใหม่ (`Consumer` type)
3. เพิ่ม Product "Facebook Login"
4. ไปที่ Settings > Basic และ เก็บ App ID และ App Secret
5. ไปที่ Settings > Advanced > Client OAuth Settings เพิ่ม:
   ```
   https://jobboard-ai-app.onrender.com
   http://localhost:5000
   ```
6. ไปที่ Products > Facebook Login > Settings เพิ่ม Valid OAuth Redirect URIs:
   ```
   https://jobboard-ai-app.onrender.com/auth/facebook/callback
   http://localhost:5000/auth/facebook/callback
   ```

**ตั้งค่า .env:**
```env
FACEBOOK_APP_ID=xxx
FACEBOOK_APP_SECRET=xxx
FACEBOOK_REDIRECT_URI=https://jobboard-ai-app.onrender.com/auth/facebook/callback
```

**ใช้งาน:**
- ปุ่ม "Sign in with Facebook" ที่หน้า login
- URL: `/auth/facebook/initiate`

---

## 📱 ระบบ OTP

### วิธีการส่ง OTP

#### Email OTP (SMTP)

ใช้สำหรับการส่ง OTP ผ่านอีเมล

**ตั้งค่า Gmail:**
1. เปิด [Google Account Security](https://myaccount.google.com/security)
2. เปิด "Less secure app access"
3. หรือใช้ "App Passwords" (ขอแนะนำ)
4. สร้าง App Password สำหรับ "Mail"

**ตั้งค่า .env:**
```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_EMAIL=your-email@gmail.com
SMTP_PASSWORD=your-app-password  # Not your Gmail password
```

#### SMS OTP (Twilio)

ใช้สำหรับการส่ง OTP ผ่าน SMS

**ขั้นตอนการตั้งค่า:**
1. สมัครสมาชิก [Twilio](https://www.twilio.com)
2. ได้ Account SID และ Auth Token
3. ซื้อเบอร์โทร Twilio (International format, เช่น +66...)

**ตั้งค่า .env:**
```env
TWILIO_ACCOUNT_SID=ACxxxxx
TWILIO_AUTH_TOKEN=your-auth-token
TWILIO_PHONE=+66812345678
```

---

## 🔄 OAuth Flow

### Google OAuth Callback Flow

```
User clicks "Sign in with Google"
↓
GET /auth/google/initiate
↓
Redirect to Google consent screen
↓
User authenticates with Google
↓
Google redirects to /auth/google/callback?code=xxx&state=xxx
↓
Exchange code for access token
↓
Get user info (id, email, name, picture)
↓
Check if user exists (google_id)
  ├─ Yes → Log in user → Redirect to /dashboard
  └─ No → Redirect to /setup-oauth-profile/{callback_key}
         → User fills phone number and role
         → Create new user
         → Log in and redirect to /dashboard
```

### Phone OTP Registration Flow

```
User enters phone number
↓
POST /auth/phone-otp
↓
Check if user exists
  ├─ Yes → Send OTP for login
  └─ No → Send OTP for registration
↓
User enters OTP
↓
POST /auth/verify-otp
↓
Verify OTP code (6 digits, expires in 10 minutes)
  ├─ Success → Redirect to /register/phone-verified
  └─ Failed → Show error
↓
User fills password and role
↓
POST /register/phone-verified
↓
Create user with phone_number, password_hash
↓
Log in and redirect to /dashboard
```

---

## 📊 Database Schema

### Users Table

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    phone_number TEXT UNIQUE,           -- For phone login
    password_hash TEXT,                 -- For phone login
    email TEXT UNIQUE,                  -- From OAuth or user input
    google_id TEXT UNIQUE,              -- Google OAuth
    google_email TEXT,
    facebook_id TEXT UNIQUE,            -- Facebook OAuth
    facebook_email TEXT,
    profile_picture TEXT,               -- From OAuth provider
    full_name TEXT,
    role TEXT DEFAULT 'JOB_SEEKER',     -- JOB_SEEKER or EMPLOYER
    auth_method TEXT DEFAULT 'phone',   -- 'phone', 'google', 'facebook'
    is_verified INTEGER DEFAULT 0,      -- Account verified
    is_phone_verified INTEGER DEFAULT 0,
    is_email_verified INTEGER DEFAULT 0,
    is_banned INTEGER DEFAULT 0,
    trust_score INTEGER DEFAULT 50,
    created_at TEXT,
    updated_at TEXT
);
```

---

## 🛣️ Routes

### Authentication Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/login` | GET, POST | Login page + form |
| `/register` | GET, POST | Register page + form |
| `/auth/google/initiate` | GET | Start Google OAuth |
| `/auth/google/callback` | GET | Google OAuth callback |
| `/auth/facebook/initiate` | GET | Start Facebook OAuth |
| `/auth/facebook/callback` | GET | Facebook OAuth callback |
| `/auth/phone-otp` | POST | Request OTP for phone |
| `/auth/verify-otp` | POST | Verify OTP code |
| `/setup-oauth-profile/{key}` | GET, POST | Setup profile after OAuth |
| `/register/phone-verified` | GET, POST | Complete registration with verified phone |
| `/logout` | GET, POST | Logout |

---

## 🧪 Testing Locally

### 1. Set up .env

```bash
cd jobboard_step10_ai_scam_center
cp .env.example .env
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run Flask app

```bash
python app.py
```

### 4. Test Phone Login

- URL: `http://localhost:5000/auth/phone-otp`
- Note: SMS won't work locally unless Twilio is configured

### 5. Test Google OAuth (Requires setup)

- Configure Google credentials in .env
- Redirect URI for localhost: `http://localhost:5000/auth/google/callback`
- Click "Sign in with Google" button

---

## 🚀 Production Deployment

### Render Deployment

1. Add environment variables to Render Dashboard:
   ```env
   GOOGLE_CLIENT_ID=xxx
   GOOGLE_CLIENT_SECRET=xxx
   FACEBOOK_APP_ID=xxx
   FACEBOOK_APP_SECRET=xxx
   TWILIO_ACCOUNT_SID=xxx
   TWILIO_AUTH_TOKEN=xxx
   TWILIO_PHONE=+66xxx
   SMTP_EMAIL=xxx
   SMTP_PASSWORD=xxx
   JOBBOARD_SESSION_COOKIE_SECURE=1
   ```

2. Update redirect URIs in Google & Facebook to production URL:
   ```
   https://jobboard-ai-app.onrender.com/auth/google/callback
   https://jobboard-ai-app.onrender.com/auth/facebook/callback
   ```

3. Deploy:
   ```bash
   git push origin main
   ```

---

## 🔒 Security Features

- **Password hashing**: BCrypt (rounds=12)
- **Session security**: HttpOnly, Secure, SameSite cookies
- **CSRF protection**: Token-based validation
- **OTP security**: 
  - 6-digit codes
  - 10-minute expiry
  - 5 attempts limit
- **OAuth state verification**: CSRF token for OAuth flow

---

## 🐛 Troubleshooting

### "Google OAuth not configured"
- Check GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env
- Verify redirect URI matches exactly

### "SMS not working"
- Check TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE
- Verify phone number is in E.164 format (+66...)

### "Email OTP not sending"
- Check SMTP_EMAIL and SMTP_PASSWORD
- Use Gmail App Password, not regular password
- Enable less secure apps if not using App Password

### "User already exists with this phone"
- Phone number must be unique
- Try different phone number or use existing account

---

## 📚 References

- [Google OAuth 2.0](https://developers.google.com/identity/protocols/oauth2)
- [Facebook Login](https://developers.facebook.com/docs/facebook-login)
- [Twilio SMS](https://www.twilio.com/docs/sms/quickstart/python)
- [BCrypt Python](https://github.com/pyca/bcrypt)
- [Flask Sessions](https://flask.palletsprojects.com/en/2.3.x/api/#sessions)
