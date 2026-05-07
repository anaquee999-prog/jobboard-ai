from dotenv import load_dotenv
load_dotenv()

import os
import hmac
import io
import sqlite3
import secrets
import re
from html import unescape
import zipfile
from functools import wraps
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urljoin

import bcrypt
import requests
from werkzeug.utils import secure_filename
from flask import (
    Flask,
    g,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    Response,
    jsonify,
    send_from_directory,
)
from security_engine import security_guard

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / os.environ.get("JOBBOARD_DATABASE_PATH", "instance/jobboard.db")

app = Flask(__name__)
app.secret_key = os.environ.get("JOBBOARD_SECRET_KEY", "").strip()
app.permanent_session_lifetime = timedelta(hours=12)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("JOBBOARD_SESSION_COOKIE_SECURE", "0") == "1"
app.config["MAX_CONTENT_LENGTH"] = 55 * 1024 * 1024

ADMIN_PHONE = os.environ.get("JOBBOARD_ADMIN_PHONE", "").strip()
ADMIN_PASSWORD = os.environ.get("JOBBOARD_ADMIN_PASSWORD", "").strip()
DISCORD_SCAM_ALERT_WEBHOOK_URL = os.environ.get("DISCORD_SCAM_ALERT_WEBHOOK_URL", "").strip()
DOE_NEWS_SOURCES = [
    {
        "key": "doe-main",
        "province": "กรมการจัดหางาน",
        "phone": "0996101000",
        "employer": "กรมการจัดหางาน / ข่าวประกาศรับสมัครงาน",
        "tax_id": "DOE-SOURCE-MAIN",
        "url": "https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label",
        "priority": 100,
    },
    {
        "key": "phichit",
        "province": "พิจิตร",
        "phone": "0996101001",
        "employer": "สำนักงานจัดหางานจังหวัดพิจิตร / ข่าวงานท้องถิ่น",
        "tax_id": "DOE-SOURCE-PHICHIT-LIVE",
        "url": "https://www.doe.go.th/prd/phichit/news/param/site/96/cat/8/sub/0/pull/category/view/list-label",
        "priority": 95,
    },
    {
        "key": "phitsanulok",
        "province": "พิษณุโลก",
        "phone": "0996101002",
        "employer": "สำนักงานจัดหางานจังหวัดพิษณุโลก / ข่าวงานท้องถิ่น",
        "tax_id": "DOE-SOURCE-PHITSANULOK-LIVE",
        "url": "https://www.doe.go.th/prd/phitsanulok/news/param/site/161/cat/8/sub/0/pull/category/view/list-label",
        "priority": 94,
    },
    {
        "key": "kamphaengphet",
        "province": "กำแพงเพชร",
        "phone": "0996101003",
        "employer": "สำนักงานจัดหางานจังหวัดกำแพงเพชร / ข่าวงานท้องถิ่น",
        "tax_id": "DOE-SOURCE-KAMPHAENGPHET-LIVE",
        "url": "https://www.doe.go.th/prd/kamphaengphet/news/param/site/139/cat/8/sub/0/pull/category/view/list-label",
        "priority": 93,
    },
    {
        "key": "nakhonsawan",
        "province": "นครสวรรค์",
        "phone": "0996101004",
        "employer": "สำนักงานจัดหางานจังหวัดนครสวรรค์ / ข่าวงานท้องถิ่น",
        "tax_id": "DOE-SOURCE-NAKHONSAWAN-LIVE",
        "url": "https://www.doe.go.th/prd/nakhonsawan/news/param/site/146/cat/8/sub/0/pull/category/view/list-label",
        "priority": 92,
    },
]
OPENCHAT_UPLOAD_DIR = BASE_DIR / "instance" / "uploads" / "openchat"
OPENCHAT_ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
OPENCHAT_ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm"}
OPENCHAT_MAX_IMAGE_UPLOAD_BYTES = 5 * 1024 * 1024
OPENCHAT_MAX_VIDEO_UPLOAD_BYTES = 50 * 1024 * 1024
JOBBOARD_CRON_TOKEN = os.environ.get("JOBBOARD_CRON_TOKEN", "").strip()

ROLES = {"JOB_SEEKER", "EMPLOYER", "ADMIN"}


def validate_runtime_config():
    missing = []
    if not app.secret_key:
        missing.append("JOBBOARD_SECRET_KEY")
    if not ADMIN_PHONE:
        missing.append("JOBBOARD_ADMIN_PHONE")
    if not ADMIN_PASSWORD:
        missing.append("JOBBOARD_ADMIN_PASSWORD")

    if missing:
        raise RuntimeError("Missing required environment variables: " + ", ".join(missing))

    if len(app.secret_key) < 32:
        raise RuntimeError("JOBBOARD_SECRET_KEY ต้องยาวอย่างน้อย 32 ตัวอักษร")

    if len(ADMIN_PASSWORD) < 12:
        raise RuntimeError("JOBBOARD_ADMIN_PASSWORD ควรยาวอย่างน้อย 12 ตัวอักษร")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_phone(value):
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def is_valid_thai_phone(phone):
    phone = normalize_phone(phone)
    return len(phone) == 10 and phone.startswith("0")


def validate_account_password(password, phone_number=""):
    password = str(password or "")
    phone_number = normalize_phone(phone_number)

    weak_passwords = {
        "password",
        "password123",
        "12345678",
        "123456789",
        "00000000",
        "11111111",
        "qwerty123",
        "admin1234",
    }

    if len(password) < 8:
        return False, "รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร"

    if len(password) > 128:
        return False, "รหัสผ่านยาวเกินไป"

    if password.lower() in weak_passwords:
        return False, "รหัสผ่านนี้เดาง่ายเกินไป กรุณาตั้งใหม่"

    if phone_number and password == phone_number:
        return False, "ห้ามใช้เบอร์โทรศัพท์เป็นรหัสผ่าน"

    if password.isdigit():
        return False, "รหัสผ่านไม่ควรเป็นตัวเลขล้วน"

    if not re.search(r"[A-Za-zก-๙]", password) or not re.search(r"\d", password):
        return False, "รหัสผ่านควรมีทั้งตัวอักษรและตัวเลข"

    return True, ""


def validate_profile_name(value, label, max_length=120):
    value = str(value or "").strip()

    if not value:
        return False, f"กรุณากรอก{label}"

    if len(value) > max_length:
        return False, f"{label}ยาวเกินไป"

    blocked_patterns = [
        r"https?://",
        r"www\.",
        r"line\s*id",
        r"telegram",
        r"whatsapp",
        r"เว็บพนัน",
        r"พนัน",
        r"เงินกู้",
    ]

    lowered = value.lower()
    for pattern in blocked_patterns:
        if re.search(pattern, lowered, re.IGNORECASE):
            return False, f"{label}มีข้อความที่ไม่เหมาะสม"

    return True, ""


def hash_password(password):
    return bcrypt.hashpw(str(password).encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password, password_hash):
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(str(password).encode("utf-8"), str(password_hash).encode("utf-8"))
    except ValueError:
        return False


def generate_mock_otp():
    return "123456"


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return token


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    try:
        return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    except Exception:
        return None


def job_slug(job):
    try:
        job_id = job["id"]
    except Exception:
        job_id = getattr(job, "id", "")
    return str(job_id or "")


def scam_risk_label(score):
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def get_page_view_stats(page_path=None):
    return {"path": page_path or "", "view_count": 0}


def get_official_doe_source_for_location(location="", title=""):
    text = f"{location or ''} {title or ''}"
    for source in DOE_NEWS_SOURCES:
        if source["province"] in text:
            return source["url"]
    return DOE_NEWS_SOURCES[0]["url"]


def is_bad_or_placeholder_source_url(source_url):
    source_url = str(source_url or "").strip().lower()
    if not source_url or source_url == "#":
        return True
    return any(bad in source_url for bad in ("example.com", "google.com", "localhost", "127.0.0.1"))


def safe_source_url(source_url="", location="", title=""):
    if is_bad_or_placeholder_source_url(source_url):
        return get_official_doe_source_for_location(location, title)
    return source_url


def mask_phone_for_display(phone_number):
    phone = normalize_phone(phone_number)
    if len(phone) < 7:
        return phone or "-"
    return f"{phone[:3]}xxx{phone[-4:]}"


def ensure_notification_schema():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT DEFAULT '',
            link_url TEXT DEFAULT '',
            category TEXT DEFAULT 'SYSTEM',
            is_read INTEGER NOT NULL DEFAULT 0,
            read_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at);
        """
    )
    ensure_column(conn, "users", "email", "TEXT DEFAULT ''")
    ensure_column(conn, "users", "wants_email_alerts", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "wants_web_alerts", "INTEGER NOT NULL DEFAULT 1")
    ensure_column(conn, "users", "browser_notifications_enabled", "INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def get_unread_notifications_count(user_id=None):
    user_id = user_id or session.get("user_id")
    if not user_id:
        return 0
    try:
        ensure_notification_schema()
        row = get_db().execute(
            "SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND is_read = 0",
            (user_id,),
        ).fetchone()
        return int(row["count"] or 0)
    except Exception:
        return 0


def get_recent_notifications(user_id=None, limit=5):
    user_id = user_id or session.get("user_id")
    if not user_id:
        return []
    try:
        ensure_notification_schema()
        return get_db().execute(
            """
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (user_id, int(limit or 5)),
        ).fetchall()
    except Exception:
        return []


def create_notification(user_id, title, message="", link_url="", category="SYSTEM"):
    if not user_id:
        return None
    try:
        ensure_notification_schema()
        cur = get_db().execute(
            """
            INSERT INTO notifications (user_id, title, message, link_url, category, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, title, message, link_url, category, now_str()),
        )
        get_db().commit()
        return cur.lastrowid
    except Exception:
        return None


def add_activity_log(actor_id, action, target_type="", target_id=None, detail=""):
    try:
        get_db().execute(
            """
            INSERT INTO activity_logs (actor_id, action, target_type, target_id, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor_id, action, target_type, target_id, str(detail or "")[:500], now_str()),
        )
    except Exception:
        pass


def analyze_job_content(title, description, salary_range="", location="", trust_score=50, report_count=0):
    try:
        from security_engine import calculate_scam_score
        score, reasons = calculate_scam_score(f"{title} {description} {salary_range} {location}")
    except Exception:
        score, reasons = 50, ["ระบบคัดกรองทำงานไม่สมบูรณ์ จึงส่งให้ผู้ดูแลตรวจ"]

    try:
        trust_score = int(trust_score or 50)
    except (TypeError, ValueError):
        trust_score = 50

    try:
        report_count = int(report_count or 0)
    except (TypeError, ValueError):
        report_count = 0

    if trust_score < 30:
        score += 20
        reasons.append("Trust score ต่ำ")
    if report_count >= 3:
        score += 20
        reasons.append("มีรายงานจากผู้ใช้หลายครั้ง")

    score = max(0, min(100, int(score or 0)))
    if score >= 70:
        return score, "REJECTED", " | ".join(reasons[:8])
    if score >= 35:
        return score, "PENDING_AI_REVIEW", " | ".join(reasons[:8])
    return score, "ACTIVE", " | ".join(reasons[:8])


def get_trust_level(score):
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "NORMAL"
    if score >= 20:
        return "LOW"
    return "RISK"


@app.context_processor
def inject_common_values():
    return {
        "csrf_token": generate_csrf_token,
        "current_year": datetime.now().year,
        "current_user": get_current_user(),
        "job_slug": job_slug,
        "scam_risk_label": scam_risk_label,
        "page_view_stats": get_page_view_stats,
        "official_source_url": get_official_doe_source_for_location,
        "is_bad_source_url": is_bad_or_placeholder_source_url,
        "safe_source_url": safe_source_url,
        "unread_notifications_count": get_unread_notifications_count,
        "recent_notifications": get_recent_notifications,
    }


@app.before_request
def csrf_protect():
    if request.method != "POST":
        return None

    session_token = session.get("_csrf_token", "")
    form_token = request.form.get("csrf_token", "")

    if not session_token or not form_token or not hmac.compare_digest(session_token, form_token):
        return "CSRF token ไม่ถูกต้องหรือหมดอายุ กรุณารีเฟรชหน้าแล้วลองใหม่อีกครั้ง", 400

    return None


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def get_db():
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_column(conn, table_name, column_name, definition):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing = {row["name"] for row in rows}
    if column_name not in existing:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def init_db():
    conn = get_db()

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'JOB_SEEKER',
            is_verified INTEGER NOT NULL DEFAULT 0,
            is_banned INTEGER NOT NULL DEFAULT 0,
            trust_score INTEGER NOT NULL DEFAULT 50,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS employer_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            company_name TEXT NOT NULL,
            tax_id TEXT UNIQUE,
            is_company_verified INTEGER NOT NULL DEFAULT 0,
            address TEXT DEFAULT '',
            website TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS job_seeker_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            headline TEXT DEFAULT '',
            resume_url TEXT DEFAULT '',
            is_public INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS job_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employer_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            salary_range TEXT DEFAULT '',
            location TEXT DEFAULT '',
            is_government_news INTEGER NOT NULL DEFAULT 0,
            source_url TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'PENDING_AI_REVIEW',
            ai_risk_score INTEGER,
            ai_risk_reason TEXT DEFAULT '',
            report_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (employer_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_seeker_id INTEGER NOT NULL,
            job_post_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            message TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(job_seeker_id, job_post_id),
            FOREIGN KEY (job_seeker_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_post_id INTEGER NOT NULL,
            reporter_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(job_post_id, reporter_id),
            FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            application_id INTEGER,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);
        CREATE INDEX IF NOT EXISTS idx_messages_application ON messages(application_id);

        CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone_number);
        CREATE INDEX IF NOT EXISTS idx_job_posts_status ON job_posts(status);
        CREATE INDEX IF NOT EXISTS idx_job_posts_created ON job_posts(created_at);
        CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT DEFAULT '',
            target_id INTEGER,
            detail TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS ai_decision_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_post_id INTEGER,
            title TEXT DEFAULT '',
            risk_score INTEGER DEFAULT 0,
            risk_reason TEXT DEFAULT '',
            final_status TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_ai_decision_logs_job ON ai_decision_logs(job_post_id);

        CREATE TABLE IF NOT EXISTS community_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            moderation_score INTEGER NOT NULL DEFAULT 0,
            moderation_reason TEXT DEFAULT '',
            report_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS community_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            reporter_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(post_id, reporter_id),
            FOREIGN KEY (post_id) REFERENCES community_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_community_posts_status ON community_posts(status);
        CREATE INDEX IF NOT EXISTS idx_community_posts_created ON community_posts(created_at);
        CREATE INDEX IF NOT EXISTS idx_community_reports_post ON community_reports(post_id);

        CREATE TABLE IF NOT EXISTS page_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_path TEXT NOT NULL UNIQUE,
            page_title TEXT DEFAULT '',
            view_count INTEGER NOT NULL DEFAULT 0,
            last_viewed_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_page_views_count ON page_views(view_count);
        CREATE INDEX IF NOT EXISTS idx_page_views_last ON page_views(last_viewed_at);


        CREATE TABLE IF NOT EXISTS openchat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            moderation_score INTEGER NOT NULL DEFAULT 0,
            moderation_reason TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_openchat_messages_status ON openchat_messages(status);
        CREATE INDEX IF NOT EXISTS idx_openchat_messages_created ON openchat_messages(created_at);
        """
    )

    conn.executescript("""

        CREATE TABLE IF NOT EXISTS post_media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL UNIQUE,
            original_name TEXT DEFAULT '',
            file_type TEXT NOT NULL,
            mime_type TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
            review_note TEXT DEFAULT '',
            reviewed_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (post_id) REFERENCES community_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_post_media_post ON post_media(post_id);
        CREATE INDEX IF NOT EXISTS idx_post_media_status ON post_media(status);

    """)

    conn.executescript("""

        CREATE TABLE IF NOT EXISTS openchat_media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL UNIQUE,
            original_name TEXT DEFAULT '',
            file_type TEXT NOT NULL,
            mime_type TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
            review_note TEXT DEFAULT '',
            reviewed_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (message_id) REFERENCES openchat_messages(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_openchat_media_message ON openchat_media(message_id);
        CREATE INDEX IF NOT EXISTS idx_openchat_media_status ON openchat_media(status);

    """)

    ensure_column(conn, "job_posts", "is_urgent", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "job_seeker_profiles", "is_urgent", "INTEGER NOT NULL DEFAULT 0")


    seed_admin(conn)
    ensure_production_job_schema(conn)
    clean_demo_and_test_data(conn)
    conn.commit()


def seed_admin(conn):
    phone = normalize_phone(ADMIN_PHONE)
    current_time = now_str()
    password_hash = hash_password(ADMIN_PASSWORD)

    row = conn.execute("SELECT id FROM users WHERE phone_number = ?", (phone,)).fetchone()

    if row:
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?,
                role = 'ADMIN',
                is_verified = 1,
                is_banned = 0,
                trust_score = 100,
                updated_at = ?
            WHERE id = ?
            """,
            (password_hash, current_time, row["id"])
        )
        return

    conn.execute(
        """
        INSERT INTO users (
            phone_number, password_hash, role, is_verified, is_banned,
            trust_score, created_at, updated_at
        )
        VALUES (?, ?, 'ADMIN', 1, 0, 100, ?, ?)
        """,
        (phone, password_hash, current_time, current_time)
    )

def seed_demo_jobs(conn):
    count = conn.execute("SELECT COUNT(*) AS count FROM job_posts").fetchone()["count"]
    if count > 0:
        return

    current_time = now_str()
    employer_phone = "0811111111"

    employer = conn.execute("SELECT id FROM users WHERE phone_number = ?", (employer_phone,)).fetchone()
    if employer:
        employer_id = employer["id"]
    else:
        conn.execute(
            """
            INSERT INTO users (
                phone_number, password_hash, role, is_verified, is_banned,
                trust_score, created_at, updated_at
            )
            VALUES (?, ?, 'EMPLOYER', 1, 0, 75, ?, ?)
            """,
            (employer_phone, hash_password("demo-password-123"), current_time, current_time)
        )
        employer_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    profile = conn.execute("SELECT id FROM employer_profiles WHERE user_id = ?", (employer_id,)).fetchone()
    if not profile:
        conn.execute(
            """
            INSERT INTO employer_profiles (
                user_id, company_name, tax_id, is_company_verified,
                address, website, created_at, updated_at
            )
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (employer_id, "Demo Company Co., Ltd.", f"DEMO-TAX-{employer_id}", "Bangkok", "https://example.com", current_time, current_time)
        )

    demo_jobs = [
        ("Marketing Officer", "วางแผนการตลาด ดูแลคอนเทนต์ และประสานงานแคมเปญออนไลน์", "18,000 - 28,000 บาท", "Bangkok", 0),
        ("Graphic Designer", "ออกแบบสื่อโฆษณา ภาพโปรโมต และงานกราฟิกสำหรับ Social Media", "20,000 - 30,000 บาท", "Chiang Mai", 0),
        ("ข่าวรับสมัครงานราชการตัวอย่าง", "ตัวอย่างข่าวราชการที่ระบบ AI จะดึงเข้ามาในอนาคต", "", "ทั่วประเทศ", 1),
    ]

    for title, desc, salary, loc, is_gov in demo_jobs:
        conn.execute(
            """
            INSERT INTO job_posts (
                employer_id, title, description, salary_range, location,
                is_government_news, source_url, status, ai_risk_score,
                ai_risk_reason, report_count, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, 'demo seed data', 0, ?, ?)
            """,
            (
                employer_id,
                title,
                desc,
                salary,
                loc,
                is_gov,
                "https://example.com/government-job" if is_gov else "",
                current_time,
                current_time,
            )
        )



# PRODUCTION_GOVERNMENT_FIX_V1
def ensure_production_job_schema(conn):
    ensure_column(conn, "job_posts", "view_count", "INTEGER NOT NULL DEFAULT 0")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_job_posts_gov_active ON job_posts(is_government_news, status, updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_job_posts_source_url ON job_posts(source_url)")


def clean_demo_and_test_data(conn):
    current_time = now_str()
    ensure_production_job_schema(conn)

    conn.execute(
        """
        DELETE FROM job_posts
        WHERE lower(COALESCE(ai_risk_reason, '')) LIKE '%demo%'
           OR lower(COALESCE(description, '')) LIKE '%demo%'
           OR title LIKE '%ตัวอย่าง%'
           OR lower(COALESCE(source_url, '')) LIKE '%example.com%'
           OR lower(COALESCE(source_url, '')) LIKE '%/demo/%'
           OR title IN ('Marketing Officer', 'Graphic Designer')
        """
    )

    for phone in ("0811111111", "0810000001", "0810000002"):
        conn.execute(
            "DELETE FROM users WHERE phone_number = ? AND role != 'ADMIN'",
            (phone,),
        )

    conn.execute(
        """
        DELETE FROM employer_profiles
        WHERE upper(COALESCE(tax_id, '')) LIKE 'DEMO-%'
           OR upper(COALESCE(tax_id, '')) LIKE 'TEST-%'
           OR company_name LIKE '%Demo%'
           OR company_name LIKE '%ทดสอบ%'
        """
    )

    conn.execute(
        """
        UPDATE job_posts
        SET source_url = CASE
                WHEN is_government_news = 1 THEN COALESCE(NULLIF(source_url, ''), 'https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label')
                ELSE source_url
            END,
            updated_at = ?
        WHERE status = 'ACTIVE'
          AND is_government_news = 1
          AND (
                source_url IS NULL
                OR source_url = ''
                OR lower(source_url) LIKE '%example.com%'
                OR lower(source_url) LIKE '%google.com%'
                OR source_url = '#'
          )
        """,
        (current_time,),
    )


def government_jobs_where_sql(prefix="job_posts"):
    return f"""
        {prefix}.status = 'ACTIVE'
        AND {prefix}.is_government_news = 1
        AND COALESCE({prefix}.source_url, '') != ''
        AND lower(COALESCE({prefix}.source_url, '')) NOT LIKE '%example.com%'
        AND lower(COALESCE({prefix}.source_url, '')) NOT LIKE '%google.com%'
        AND lower(COALESCE({prefix}.source_url, '')) NOT LIKE '%localhost%'
        AND lower(COALESCE({prefix}.source_url, '')) NOT LIKE '%127.0.0.1%'
        AND {prefix}.title NOT LIKE '%ตัวอย่าง%'
        AND lower(COALESCE({prefix}.description, '')) NOT LIKE '%demo%'
    """





# SAFE_PUBLIC_ROUTES_FINAL_V1
def _safe_html_escape(value):
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _safe_agency_name(company_name="", location="", source_url=""):
    company_name = str(company_name or "").strip()
    location = str(location or "").strip()
    source_url = str(source_url or "").lower().strip()

    bad = {"", "ระบบดึงงานอัตโนมัติ", "auto job engine", "government job news"}

    if company_name.lower() not in bad:
        return company_name

    if "phichit" in source_url or "พิจิตร" in location:
        return "สำนักงานจัดหางานจังหวัดพิจิตร"
    if "phitsanulok" in source_url or "พิษณุโลก" in location:
        return "สำนักงานจัดหางานจังหวัดพิษณุโลก"
    if "kamphaengphet" in source_url or "กำแพงเพชร" in location:
        return "สำนักงานจัดหางานจังหวัดกำแพงเพชร"
    if "nakhonsawan" in source_url or "นครสวรรค์" in location:
        return "สำนักงานจัดหางานจังหวัดนครสวรรค์"
    return "กรมการจัดหางาน / ข่าวประกาศรับสมัครงาน"


def _safe_is_real_job_title(title):
    title = str(title or "").strip()
    lowered = title.lower()

    if len(title) < 8:
        return False

    bad_terms = [
        "สำนักงานบริหารแรงงานไทยไปต่างประเทศ",
        "สำนักบริหารแรงงานต่างด้าว",
        "เว็บลิงค์หน่วยงานภายนอก",
        "เว็บลิงค์หน่วยงานภายใน",
        "รายงานงบทดลองเบิกจ่าย",
        "ข่าวประกาศ",
        "กฏหมาย",
        "กฎหมาย",
        "แผนงาน",
        "โครงการ และงบประมาณ",
        "ยุทธศาสตร์",
        "แผนปฏิบัติราชการ",
        "แผนพัฒนาดิจิทัล",
        "นโยบายกรม",
        "นโยบายกระทรวง",
        "อำนาจหน้าที่",
        "ภารกิจของหน่วยงาน",
        "โครงสร้างหน่วยงาน",
        "ข้อมูลผู้บริหาร",
        "ผู้บริหารกรม",
        "ผลการปฏิบัติงาน",
        "คู่มือตาม",
        "เกี่ยวกับบริษัทจัดหางาน",
        "บทความ/งานวิเคราะห์",
        "วารสาร",
        "mobile app",
        "ข้อมูลการไปทำงานต่างประเทศ",
        "สถานการณ์ว่างงาน",
        "ศูนย์บริหารข้อมูลตลาดแรงงาน",
        "การทำงานในประเทศ",
        "การทำงานของคนต่างด้าว",
        "การไปทำงานต่างประเทศ",
        "การเดินทางไปทำงานต่างประเทศ",
        "แรงงานต่างด้าว",
    ]

    if any(term.lower() in lowered for term in bad_terms):
        return False

    good_terms = [
        "รับสมัคร",
        "เปิดรับสมัคร",
        "ประกาศรับสมัคร",
        "ตำแหน่งงานว่าง",
        "งานว่าง",
        "นัดพบแรงงาน",
        "ตลาดงาน",
        "ลูกจ้าง",
        "พนักงาน",
        "จ้างเหมา",
        "สอบคัดเลือก",
        "สรรหา",
    ]

    return any(term in title for term in good_terms)


def _safe_fetch_government_rows(limit=100, q="", location=""):
    conn = get_db()

    try:
        ensure_production_job_schema(conn)
    except Exception:
        pass

    where = """
        job_posts.status = 'ACTIVE'
        AND job_posts.is_government_news = 1
        AND COALESCE(job_posts.source_url, '') != ''
        AND lower(COALESCE(job_posts.source_url, '')) NOT LIKE '%example.com%'
        AND lower(COALESCE(job_posts.source_url, '')) NOT LIKE '%google.com%'
        AND lower(COALESCE(job_posts.source_url, '')) NOT LIKE '%localhost%'
        AND lower(COALESCE(job_posts.source_url, '')) NOT LIKE '%127.0.0.1%'
        AND job_posts.title NOT LIKE '%ตัวอย่าง%'
        AND lower(COALESCE(job_posts.description, '')) NOT LIKE '%demo%'
    """
    params = []

    q = str(q or "").strip().lower()
    location = str(location or "").strip().lower()

    if q:
        like_q = f"%{q}%"
        where += """
            AND (
                lower(job_posts.title) LIKE ?
                OR lower(job_posts.description) LIKE ?
                OR lower(job_posts.location) LIKE ?
                OR lower(employer_profiles.company_name) LIKE ?
            )
        """
        params.extend([like_q, like_q, like_q, like_q])

    if location:
        where += " AND lower(job_posts.location) LIKE ?"
        params.append(f"%{location}%")

    try:
        rows = conn.execute(
            f"""
            SELECT
                job_posts.id,
                job_posts.title,
                job_posts.description,
                job_posts.salary_range,
                job_posts.location,
                job_posts.source_url,
                job_posts.created_at,
                job_posts.updated_at,
                COALESCE(job_posts.view_count, 0) AS view_count,
                employer_profiles.company_name,
                employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE {where}
            ORDER BY
                CASE WHEN lower(job_posts.source_url) LIKE '%doe.go.th%' THEN 0 ELSE 1 END,
                datetime(job_posts.updated_at) DESC,
                datetime(job_posts.created_at) DESC,
                job_posts.id DESC
            LIMIT ?
            """,
            tuple(params + [int(limit or 100)]),
        ).fetchall()
    except Exception:
        rows = []

    clean_rows = []
    for row in rows:
        if _safe_is_real_job_title(row["title"]):
            clean_rows.append(row)

    return clean_rows


def _safe_fetch_public_job_rows(limit=100, q="", location=""):
    conn = get_db()
    try:
        ensure_production_job_schema(conn)
    except Exception:
        pass

    where = ["job_posts.status = 'ACTIVE'"]
    params = []
    q = str(q or "").strip().lower()
    location = str(location or "").strip().lower()

    if q:
        like_q = f"%{q}%"
        where.append(
            """
            (
                lower(job_posts.title) LIKE ?
                OR lower(job_posts.description) LIKE ?
                OR lower(job_posts.location) LIKE ?
                OR lower(employer_profiles.company_name) LIKE ?
            )
            """
        )
        params.extend([like_q, like_q, like_q, like_q])

    if location:
        where.append("lower(job_posts.location) LIKE ?")
        params.append(f"%{location}%")

    rows = conn.execute(
        f"""
        SELECT
            job_posts.id,
            job_posts.title,
            job_posts.description,
            job_posts.salary_range,
            job_posts.location,
            job_posts.source_url,
            job_posts.created_at,
            job_posts.updated_at,
            job_posts.is_government_news,
            job_posts.ai_risk_score,
            job_posts.report_count,
            COALESCE(job_posts.view_count, 0) AS view_count,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE {" AND ".join(where)}
        ORDER BY
            COALESCE(job_posts.is_urgent, 0) DESC,
            CASE WHEN job_posts.is_government_news = 1 THEN 0 ELSE 1 END,
            datetime(job_posts.updated_at) DESC,
            job_posts.id DESC
        LIMIT ?
        """,
        tuple(params + [int(limit or 100)]),
    ).fetchall()

    clean_rows = []
    for row in rows:
        if row["is_government_news"] and not _safe_is_real_job_title(row["title"]):
            continue
        clean_rows.append(row)
    return clean_rows


def _safe_render_public_page(page_title, subtitle, rows, q="", location="", show_search=True):
    cards = []

    for row in rows:
        title = _safe_html_escape(row["title"])
        loc = _safe_html_escape(row["location"] or "ทั่วประเทศ")
        is_government = int(row["is_government_news"] or 0) if "is_government_news" in row.keys() else 1
        agency_name = _safe_agency_name(row["company_name"], row["location"], row["source_url"]) if is_government else (row["company_name"] or "นายจ้าง")
        agency = _safe_html_escape(agency_name)
        salary = _safe_html_escape(row["salary_range"] or "ตรวจสอบตามประกาศต้นทาง")
        updated = _safe_html_escape(row["updated_at"] or row["created_at"] or "")
        source_url = _safe_html_escape(safe_source_url(row["source_url"], row["location"], row["title"])) if is_government else ""
        views = int(row["view_count"] or 0)
        badge = "งานราชการ / DOE" if is_government else "ประกาศจากนายจ้าง"
        source_action = f'<a class="btn" href="{source_url}" target="_blank" rel="noopener">เปิดต้นทาง DOE</a>' if source_url else ""

        detail_url = f"/job/{row['id']}"

        cards.append(
            f"""
            <article class="card">
                <div class="badge">{badge}</div>
                <h2>{title}</h2>
                <p><b>หน่วยงาน:</b> {agency}</p>
                <p><b>พื้นที่:</b> {loc}</p>
                <p><b>เงินเดือน:</b> {salary}</p>
                <p><b>อัปเดต:</b> {updated} · <b>เข้าชม:</b> {views} ครั้ง</p>
                <div class="actions">
                    <a class="btn primary" href="{detail_url}">ดูรายละเอียด</a>
                    {source_action}
                </div>
            </article>
            """
        )

    if not cards:
        cards.append(
            """
            <article class="card">
                <h2>ยังไม่พบงานราชการจริงในฐานข้อมูล</h2>
                <p>ให้รัน <code>python auto_job_engine.py --live</code> เพื่อดึงข่าวล่าสุด</p>
            </article>
            """
        )

    search_html = ""
    if show_search:
        search_html = f"""
        <form class="search" method="get" action="/jobs">
            <input name="q" value="{_safe_html_escape(q)}" placeholder="ค้นหา เช่น รับสมัคร ลูกจ้าง พนักงาน">
            <input name="location" value="{_safe_html_escape(location)}" placeholder="จังหวัด เช่น พิจิตร พิษณุโลก">
            <button type="submit">ค้นหา</button>
            <a href="/jobs">ล้างคำค้น</a>
        </form>
        """

    return f"""
    <!doctype html>
    <html lang="th">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{_safe_html_escape(page_title)} | งานใกล้บ้าน</title>
        <style>
            body{{margin:0;font-family:Tahoma,Arial,sans-serif;background:#f8fafc;color:#0f172a;line-height:1.65}}
            .wrap{{max-width:1160px;margin:0 auto;padding:28px 18px 70px}}
            .hero{{background:linear-gradient(135deg,#111827,#1d4ed8);color:#fff;border-radius:26px;padding:34px;box-shadow:0 20px 50px rgba(15,23,42,.18);margin-bottom:18px}}
            .hero h1{{margin:0 0 8px;font-size:clamp(28px,5vw,44px)}}
            .hero p{{margin:0;opacity:.92;font-size:17px}}
            .nav{{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}}
            .nav a,.btn,.search button,.search a{{display:inline-block;padding:10px 14px;border-radius:999px;background:#fff;color:#1d4ed8;border:1px solid #dbeafe;text-decoration:none;font-weight:700}}
            .search{{display:grid;grid-template-columns:1fr 1fr auto auto;gap:10px;background:#fff;padding:14px;border-radius:18px;border:1px solid #e2e8f0;margin:18px 0}}
            .search input{{padding:12px 14px;border-radius:999px;border:1px solid #cbd5e1;font-size:15px}}
            .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:16px}}
            .card{{background:#fff;border:1px solid #e2e8f0;border-radius:22px;padding:20px;box-shadow:0 10px 30px rgba(15,23,42,.08)}}
            .card h2{{margin:10px 0;font-size:20px}}
            .badge{{display:inline-block;background:#dcfce7;color:#166534;border-radius:999px;padding:6px 10px;font-weight:700;font-size:13px}}
            .actions{{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}}
            .btn.primary,.search button{{background:#2563eb;color:#fff;border-color:#2563eb;cursor:pointer}}
            .count{{color:#dbeafe;margin-top:8px}}
            @media(max-width:760px){{.search{{grid-template-columns:1fr}}}}
        </style>
    </head>
    <body>
        <main class="wrap">
            <section class="hero">
                <h1>{_safe_html_escape(page_title)}</h1>
                <p>{_safe_html_escape(subtitle)}</p>
                <p class="count">พบข้อมูล {len(rows)} รายการ</p>
            </section>
            <nav class="nav">
                <a href="/">หน้าแรก</a>
                <a href="/home">Home</a>
                <a href="/jobs">งานราชการทั้งหมด</a>
                <a href="/news">ข่าวกรมแรงงาน</a>
                <a href="/urgent">งานด่วน</a>
            </nav>
            {search_html}
            <section class="grid">{''.join(cards)}</section>
        </main>
    </body>
    </html>
    """


@app.route("/")
@app.route("/home")
def home():
    rows = _safe_fetch_government_rows(limit=12)
    return _safe_render_public_page(
        "งานใกล้บ้าน",
        "รวมงานราชการ ข่าวกรมแรงงาน และตำแหน่งงานว่างจากแหล่งข้อมูลจริง",
        rows,
    )


@app.route("/jobs")
def jobs_public():
    q = request.args.get("q", "").strip()
    location = request.args.get("location", "").strip()
    rows = _safe_fetch_public_job_rows(limit=100, q=q, location=location)
    return _safe_render_public_page(
        "งานทั้งหมด",
        "ค้นหาและดูประกาศงานจากนายจ้าง พร้อมข่าวรับสมัครงานราชการ/ตำแหน่งงานว่างจาก DOE",
        rows,
        q=q,
        location=location,
    )


@app.route("/news")
def government_news():
    rows = _safe_fetch_government_rows(limit=100)
    return _safe_render_public_page(
        "ข่าวกรมแรงงาน / งานราชการ",
        "รวมข่าวประกาศรับสมัครงานและตำแหน่งงานว่างจากแหล่งข้อมูลราชการจริง",
        rows,
        show_search=False,
    )




# RESTORED_CRON_IMPORT_ROUTE_V1
def _cron_token_is_valid():
    expected = os.environ.get("JOBBOARD_CRON_TOKEN", "").strip()
    token = request.headers.get("X-Cron-Token", "").strip()
    if not token:
        token = request.args.get("token", "").strip()
    return bool(expected) and bool(token) and hmac.compare_digest(expected, token)


@app.route("/internal/cron/import-upper-central-jobs", methods=["GET", "POST"])
@app.route("/internal/cron/import-doe-news", methods=["GET", "POST"])
def cron_import_upper_central_jobs():
    if not _cron_token_is_valid():
        abort(403)

    result = {
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
        "scanned": 0,
        "errors": [],
    }

    source = "unknown"

    try:
        if "import_latest_doe_news_to_db" in globals():
            doe_result = import_latest_doe_news_to_db()
            result["inserted"] += int(doe_result.get("inserted", 0) or 0)
            result["updated"] += int(doe_result.get("updated", 0) or 0)
            result["scanned"] += int(doe_result.get("scanned", 0) or 0)
            result["errors"].extend(doe_result.get("errors", []) or [])
            source = "app.import_latest_doe_news_to_db"
        else:
            from auto_job_engine import run_live
            doe_result = run_live()
            result["inserted"] += int(doe_result.get("inserted", 0) or 0)
            result["updated"] += int(doe_result.get("updated", 0) or 0)
            result["skipped"] += int(doe_result.get("skipped", 0) or 0)
            result["scanned"] += int(doe_result.get("scanned", 0) or 0)
            result["errors"].extend(doe_result.get("errors", []) or [])
            source = "auto_job_engine.run_live"

        try:
            conn = get_db()
            if "repair_job_source_urls_to_official" in globals():
                fixed = repair_job_source_urls_to_official()
                result["fixed_sources"] = int(fixed or 0)
            if "clean_demo_and_test_data" in globals():
                clean_demo_and_test_data(conn)
            if "add_activity_log" in globals():
                add_activity_log(
                    None,
                    "CRON_IMPORT_DOE_NEWS",
                    "job_posts",
                    None,
                    f"source={source}, inserted={result['inserted']}, updated={result['updated']}, scanned={result['scanned']}, errors={len(result['errors'])}",
                )
            conn.commit()
        except Exception as log_exc:
            result["errors"].append("post_import_log: " + str(log_exc)[:200])

        try:
            if "send_discord_alert" in globals():
                send_discord_alert(
                    "✅ Cron Import DOE สำเร็จ\n"
                    f"Inserted: {result['inserted']}\n"
                    f"Updated: {result['updated']}\n"
                    f"Scanned: {result['scanned']}\n"
                    f"Errors: {len(result['errors'])}\n"
                    f"Source: {source}\n"
                    f"เวลา: {now_str()}",
                    username="JobBoard Cron Import Bot",
                )
        except Exception:
            pass

        return jsonify({
            "ok": True,
            "source": source,
            "inserted": result["inserted"],
            "updated": result["updated"],
            "skipped": result["skipped"],
            "scanned": result["scanned"],
            "errors": result["errors"],
            "checked_at": now_str(),
        })

    except Exception as exc:
        try:
            if "add_activity_log" in globals():
                add_activity_log(None, "CRON_IMPORT_DOE_NEWS_FAILED", "job_posts", None, str(exc)[:500])
                get_db().commit()
        except Exception:
            pass

        return jsonify({
            "ok": False,
            "error": str(exc),
            "checked_at": now_str(),
        }), 500



@app.cli.command("init-db")
def init_db_command():
    validate_runtime_config()
    with app.app_context():
        init_db()
    print(f"Initialized database at {DB_PATH}")


@app.before_request
def ensure_database_ready():
    if getattr(app, "_jobboard_database_ready", False):
        return None
    if request.endpoint == "static":
        return None
    validate_runtime_config()
    init_db()
    app._jobboard_database_ready = True
    return None






# AUTO_FIX_BAD_SOURCE_URLS_ONCE
_AUTO_SOURCE_REPAIR_DONE = False

@app.before_request
def auto_repair_bad_source_urls_once():
    global _AUTO_SOURCE_REPAIR_DONE

    if _AUTO_SOURCE_REPAIR_DONE:
        return None

    try:
        endpoint = request.endpoint or ""
        if endpoint.startswith("static"):
            return None

        _AUTO_SOURCE_REPAIR_DONE = True

        conn = get_db()
        bad = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM job_posts
            WHERE source_url = ''
               OR source_url IS NULL
               OR lower(source_url) LIKE '%google.com%'
               OR lower(source_url) LIKE '%example.com%'
               OR lower(source_url) LIKE '%localhost%'
               OR lower(source_url) LIKE '%127.0.0.1%'
               OR source_url = '#'
            """
        ).fetchone()["count"]

        if int(bad or 0) > 0:
            repair_job_source_urls_to_official()
    except Exception:
        return None

    return None




# SEED_TEST_ACCOUNTS_AND_REPAIR_DB
def upsert_test_user_account(phone, password, role, display_name):
    conn = get_db()
    current_time = now_str()
    password_hash = hash_password(password)

    existing = conn.execute(
        "SELECT id FROM users WHERE phone = ? LIMIT 1",
        (phone,)
    ).fetchone()

    if existing:
        user_id = existing["id"]
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, role = ?, is_phone_verified = 1, status = 'ACTIVE', updated_at = ?
            WHERE id = ?
            """,
            (password_hash, role, current_time, user_id)
        )
    else:
        cur = conn.execute(
            """
            INSERT INTO users (
                phone, password_hash, role, is_phone_verified, status, created_at, updated_at
            )
            VALUES (?, ?, ?, 1, 'ACTIVE', ?, ?)
            """,
            (phone, password_hash, role, current_time, current_time)
        )
        user_id = cur.lastrowid

    if role == "JOB_SEEKER":
        row = conn.execute(
            "SELECT id FROM job_seeker_profiles WHERE user_id = ? LIMIT 1",
            (user_id,)
        ).fetchone()

        if row:
            conn.execute(
                """
                UPDATE job_seeker_profiles
                SET full_name = ?, headline = ?, resume_url = ?, is_public = 1, is_urgent = 1, updated_at = ?
                WHERE user_id = ?
                """,
                (
                    display_name,
                    "พร้อมเริ่มงานทันที ต้องการงานใกล้บ้าน",
                    "โปรไฟล์ทดสอบสำหรับตรวจระบบผู้หางาน",
                    current_time,
                    user_id,
                )
            )
        else:
            conn.execute(
                """
                INSERT INTO job_seeker_profiles (
                    user_id, full_name, headline, resume_url, is_public, is_urgent, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 1, 1, ?, ?)
                """,
                (
                    user_id,
                    display_name,
                    "พร้อมเริ่มงานทันที ต้องการงานใกล้บ้าน",
                    "โปรไฟล์ทดสอบสำหรับตรวจระบบผู้หางาน",
                    current_time,
                    current_time,
                )
            )

    if role == "EMPLOYER":
        row = conn.execute(
            "SELECT id FROM employer_profiles WHERE user_id = ? LIMIT 1",
            (user_id,)
        ).fetchone()

        if row:
            employer_id = row["id"]
            conn.execute(
                """
                UPDATE employer_profiles
                SET company_name = ?, tax_id = ?, company_description = ?, is_company_verified = 1, updated_at = ?
                WHERE user_id = ?
                """,
                (
                    display_name,
                    "TEST-EMPLOYER-0002",
                    "บริษัททดสอบสำหรับตรวจระบบนายจ้าง งานใกล้บ้าน",
                    current_time,
                    user_id,
                )
            )
        else:
            cur = conn.execute(
                """
                INSERT INTO employer_profiles (
                    user_id, company_name, tax_id, company_description, is_company_verified, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    user_id,
                    display_name,
                    "TEST-EMPLOYER-0002",
                    "บริษัททดสอบสำหรับตรวจระบบนายจ้าง งานใกล้บ้าน",
                    current_time,
                    current_time,
                )
            )
            employer_id = cur.lastrowid

        existing_job = conn.execute(
            """
            SELECT id FROM job_posts
            WHERE employer_id = ? AND title = ?
            LIMIT 1
            """,
            (employer_id, "ด่วน รับพนักงานประสานงานใกล้บ้าน")
        ).fetchone()

        if existing_job:
            conn.execute(
                """
                UPDATE job_posts
                SET description = ?, salary_range = ?, location = ?, is_government_news = 0,
                    source_url = '', status = 'ACTIVE', ai_risk_score = 5,
                    ai_risk_reason = ?, is_urgent = 1, updated_at = ?
                WHERE id = ?
                """,
                (
                    "งานทดสอบสำหรับตรวจหน้า งานด่วน นายจ้างประกาศรับสมัครจริงในระบบ",
                    "15,000 - 18,000 บาท",
                    "พิจิตร",
                    "ประกาศทดสอบจากนายจ้างที่ยืนยันแล้ว",
                    current_time,
                    existing_job["id"],
                )
            )
        else:
            conn.execute(
                """
                INSERT INTO job_posts (
                    employer_id, title, description, salary_range, location,
                    is_government_news, source_url, status, ai_risk_score,
                    ai_risk_reason, report_count, created_at, updated_at, is_urgent
                )
                VALUES (?, ?, ?, ?, ?, 0, '', 'ACTIVE', 5, ?, 0, ?, ?, 1)
                """,
                (
                    employer_id,
                    "ด่วน รับพนักงานประสานงานใกล้บ้าน",
                    "งานทดสอบสำหรับตรวจหน้า งานด่วน นายจ้างประกาศรับสมัครจริงในระบบ",
                    "15,000 - 18,000 บาท",
                    "พิจิตร",
                    "ประกาศทดสอบจากนายจ้างที่ยืนยันแล้ว",
                    current_time,
                    current_time,
                )
            )

    conn.commit()
    return user_id


def force_repair_demo_and_bad_sources():
    conn = get_db()
    current_time = now_str()

    source_map = {
        "พิจิตร": "https://www.doe.go.th/prd/phichit/news/param/site/96/cat/8/sub/0/pull/category/view/list-label",
        "พิษณุโลก": "https://www.doe.go.th/prd/phitsanulok/news/param/site/161/cat/8/sub/0/pull/category/view/list-label",
        "กำแพงเพชร": "https://www.doe.go.th/prd/kamphaengphet/news/param/site/139/cat/8/sub/0/pull/category/view/list-label",
        "นครสวรรค์": "https://www.doe.go.th/prd/nakhonsawan/news/param/site/146/cat/8/sub/0/pull/category/view/list-label",
    }
    default_url = "https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label"

    rows = conn.execute(
        """
        SELECT id, title, location, source_url
        FROM job_posts
        WHERE source_url = ''
           OR source_url IS NULL
           OR lower(source_url) LIKE '%google.com%'
           OR lower(source_url) LIKE '%example.com%'
           OR lower(source_url) LIKE '%localhost%'
           OR lower(source_url) LIKE '%127.0.0.1%'
           OR source_url = '#'
           OR title LIKE '%ตัวอย่าง%'
           OR description LIKE '%ตัวอย่าง%'
           OR description LIKE '%Demo%'
        """
    ).fetchall()

    fixed = 0
    for row in rows:
        text = f"{row['title'] or ''} {row['location'] or ''}"
        target = default_url
        for province, url in source_map.items():
            if province in text:
                target = url
                break

        title = row["title"] or ""
        if "ตัวอย่าง" in title:
            title = "ข่าวรับสมัครงานจากกรมการจัดหางาน"
        if not title.strip():
            title = "ข่าวรับสมัครงานจากกรมการจัดหางาน"

        conn.execute(
            """
            UPDATE job_posts
            SET title = ?,
                source_url = ?,
                is_government_news = CASE
                    WHEN is_government_news = 1 THEN 1
                    WHEN title LIKE '%ราชการ%' THEN 1
                    ELSE is_government_news
                END,
                status = 'ACTIVE',
                updated_at = ?
            WHERE id = ?
            """,
            (title, target, current_time, row["id"])
        )
        fixed += 1

    conn.commit()
    return fixed


@app.route("/internal/admin/seed-test-accounts-and-repair", methods=["GET", "POST"])
def internal_seed_test_accounts_and_repair():
    abort(404)



# NOTIFICATION_AUTO_SCHEMA_V1
_NOTIFICATION_SCHEMA_READY = False

@app.before_request
def auto_ensure_notification_schema():
    global _NOTIFICATION_SCHEMA_READY

    if _NOTIFICATION_SCHEMA_READY:
        return None

    try:
        endpoint = request.endpoint or ""
        if endpoint.startswith("static"):
            return None

        ensure_notification_schema()
        _NOTIFICATION_SCHEMA_READY = True
    except Exception:
        return None

    return None



# RESTORED_AUTH_DECORATORS_V2
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login'))
            if user['role'] not in roles:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


def _fetch_template_jobs(limit=20, status="ACTIVE", urgent_only=False):
    conn = get_db()
    ensure_production_job_schema(conn)
    where = ["job_posts.status = ?"]
    params = [status]
    if urgent_only:
        where.append("COALESCE(job_posts.is_urgent, 0) = 1")
    return conn.execute(
        f"""
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE {" AND ".join(where)}
        ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
        LIMIT ?
        """,
        tuple(params + [int(limit or 20)]),
    ).fetchall()


def _admin_stats():
    conn = get_db()

    def count(sql, params=()):
        try:
            return int(conn.execute(sql, params).fetchone()["count"] or 0)
        except Exception:
            return 0

    return {
        "users": count("SELECT COUNT(*) AS count FROM users"),
        "pending_ai": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'"),
        "active": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'"),
        "rejected": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'REJECTED'"),
        "reports": count("SELECT COUNT(*) AS count FROM reports WHERE status = 'PENDING'"),
    }


def _redirect_back(default_endpoint="home"):
    return redirect(request.referrer or url_for(default_endpoint))


@app.route("/login", methods=["GET", "POST"])
def login():
    # TODO: Restore the full login flow if this fallback is replaced by the original route.
    error = ""
    if request.method == "POST":
        phone = normalize_phone(request.form.get("phone_number") or request.form.get("phone"))
        password = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE phone_number = ?", (phone,)).fetchone()
        if row and verify_password(password, row["password_hash"]) and not row["is_banned"]:
            session["user_id"] = row["id"]
            session.permanent = True
            return redirect(url_for("dashboard"))
        error = "เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง"
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        role = request.form.get("role", "JOB_SEEKER").strip().upper()
        phone = normalize_phone(request.form.get("phone_number"))
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        full_name = request.form.get("full_name", "").strip()
        company_name = request.form.get("company_name", "").strip()

        if role not in {"JOB_SEEKER", "EMPLOYER"}:
            error = "ประเภทบัญชีไม่ถูกต้อง"
        elif not request.form.get("accept_terms"):
            error = "กรุณายอมรับเงื่อนไขการใช้งาน"
        elif not is_valid_thai_phone(phone):
            error = "กรุณากรอกเบอร์โทรศัพท์ไทย 10 หลัก"
        elif email and ("@" not in email or "." not in email.split("@")[-1]):
            error = "รูปแบบอีเมลไม่ถูกต้อง"
        elif password != confirm_password:
            error = "รหัสผ่านและยืนยันรหัสผ่านไม่ตรงกัน"
        else:
            ok, message = validate_account_password(password, phone)
            if not ok:
                error = message

        if not error:
            label = "ชื่อผู้หางาน" if role == "JOB_SEEKER" else "ชื่อบริษัท"
            profile_name = full_name if role == "JOB_SEEKER" else company_name
            ok, message = validate_profile_name(profile_name, label)
            if not ok:
                error = message

        if not error:
            try:
                ensure_notification_schema()
                conn = get_db()
                current_time = now_str()
                cur = conn.execute(
                    """
                    INSERT INTO users (
                        phone_number, password_hash, role, is_verified, is_banned,
                        trust_score, email, wants_email_alerts, wants_web_alerts,
                        created_at, updated_at
                    )
                    VALUES (?, ?, ?, 1, 0, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        phone,
                        hash_password(password),
                        role,
                        55 if role == "EMPLOYER" else 50,
                        email,
                        1 if request.form.get("notify_consent") else 0,
                        current_time,
                        current_time,
                    ),
                )
                user_id = cur.lastrowid

                if role == "JOB_SEEKER":
                    conn.execute(
                        """
                        INSERT INTO job_seeker_profiles (
                            user_id, full_name, headline, resume_url, is_public,
                            created_at, updated_at
                        )
                        VALUES (?, ?, '', '', 0, ?, ?)
                        """,
                        (user_id, full_name, current_time, current_time),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO employer_profiles (
                            user_id, company_name, tax_id, is_company_verified,
                            address, website, created_at, updated_at
                        )
                        VALUES (?, ?, ?, 0, '', '', ?, ?)
                        """,
                        (user_id, company_name, f"EMP-{user_id}", current_time, current_time),
                    )

                add_activity_log(user_id, "REGISTER", "users", user_id, f"role={role}")
                conn.commit()
                session["user_id"] = user_id
                session.permanent = True
                create_notification(
                    user_id,
                    "สมัครสมาชิกเรียบร้อย",
                    "ยินดีต้อนรับเข้าสู่ระบบงานใกล้บ้าน",
                    url_for("dashboard"),
                    "ACCOUNT",
                )
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                error = "เบอร์โทรศัพท์นี้ถูกใช้สมัครแล้ว"
            except Exception:
                error = "สมัครสมาชิกไม่สำเร็จ กรุณาลองใหม่อีกครั้ง"

    return render_template("register.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    if user and user["role"] == "ADMIN":
        return redirect(url_for("admin_dashboard"))
    if user and user["role"] == "EMPLOYER":
        return redirect(url_for("employer_dashboard"))
    return redirect(url_for("job_seeker_dashboard"))


@app.route("/dashboard/job-seeker")
@login_required
def job_seeker_dashboard():
    user = get_current_user()
    conn = get_db()
    profile = conn.execute(
        "SELECT * FROM job_seeker_profiles WHERE user_id = ?",
        (user["id"],),
    ).fetchone()
    applications = conn.execute(
        """
        SELECT
            applications.*,
            job_posts.title,
            job_posts.location,
            employer_profiles.company_name
        FROM applications
        JOIN job_posts ON job_posts.id = applications.job_post_id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE applications.job_seeker_id = ?
        ORDER BY datetime(applications.created_at) DESC, applications.id DESC
        """,
        (user["id"],),
    ).fetchall()
    recommended_jobs = _fetch_template_jobs(limit=6, status="ACTIVE")
    return render_template(
        "dashboard_job_seeker.html",
        user=user,
        profile=profile,
        applications=applications,
        recommended_jobs=recommended_jobs,
    )


@app.route("/employer/dashboard")
@app.route("/dashboard/employer")
@login_required
def employer_dashboard():
    user = get_current_user()
    if user["role"] != "EMPLOYER":
        abort(403)
    conn = get_db()
    profile = conn.execute(
        "SELECT * FROM employer_profiles WHERE user_id = ?",
        (user["id"],),
    ).fetchone()
    jobs = conn.execute(
        """
        SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.employer_id = ?
        ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
        """,
        (user["id"],),
    ).fetchall()
    applications = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM applications
        JOIN job_posts ON job_posts.id = applications.job_post_id
        WHERE job_posts.employer_id = ?
        """,
        (user["id"],),
    ).fetchone()["count"]
    return render_template(
        "dashboard_employer.html",
        user=user,
        profile=profile,
        jobs=jobs,
        applications=applications,
        trust_level=get_trust_level(user["trust_score"]),
    )


@app.route("/post-job", methods=["GET", "POST"])
@app.route("/employer/jobs/new", methods=["GET", "POST"])
@login_required
def employer_create_job():
    user = get_current_user()
    if user["role"] != "EMPLOYER":
        abort(403)
    locked = int(user["trust_score"] or 0) < 20 or int(user["is_banned"] or 0)
    error = ""
    preview = None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        salary_range = request.form.get("salary_range", "").strip()
        location = request.form.get("location", "").strip()
        is_urgent = 1 if request.form.get("is_urgent") else 0
        preview = {
            "title": title,
            "description": description,
            "salary_range": salary_range,
            "location": location,
            "is_urgent": is_urgent,
        }

        if locked:
            error = "บัญชีนี้ยังไม่พร้อมโพสต์งาน"
        elif len(title) < 5:
            error = "กรุณากรอกชื่อตำแหน่งงานให้ชัดเจน"
        elif len(description) < 40:
            error = "รายละเอียดงานควรยาวอย่างน้อย 40 ตัวอักษร"
        else:
            ok, message = validate_profile_name(title, "ชื่อตำแหน่งงาน", 160)
            if not ok:
                error = message

        if not error:
            score, status, reason = analyze_job_content(
                title,
                description,
                salary_range,
                location,
                user["trust_score"],
                0,
            )
            conn = get_db()
            current_time = now_str()
            cur = conn.execute(
                """
                INSERT INTO job_posts (
                    employer_id, title, description, salary_range, location,
                    is_government_news, source_url, status, ai_risk_score,
                    ai_risk_reason, report_count, created_at, updated_at, is_urgent
                )
                VALUES (?, ?, ?, ?, ?, 0, '', ?, ?, ?, 0, ?, ?, ?)
                """,
                (
                    user["id"],
                    title,
                    description,
                    salary_range,
                    location,
                    status,
                    score,
                    reason,
                    current_time,
                    current_time,
                    is_urgent,
                ),
            )
            job_id = cur.lastrowid
            conn.execute(
                """
                INSERT INTO ai_decision_logs (job_post_id, title, risk_score, risk_reason, final_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (job_id, title, score, reason, status, current_time),
            )
            add_activity_log(user["id"], "CREATE_JOB", "job_posts", job_id, f"status={status}, risk={score}")
            conn.commit()
            return redirect(url_for("job_detail", slug=str(job_id)))

    return render_template("employer_job_form.html", job=None, error=error, locked=locked, preview=preview)


@app.route("/employer/applications")
@login_required
def employer_applications():
    user = get_current_user()
    if user["role"] != "EMPLOYER":
        abort(403)
    applications = get_db().execute(
        """
        SELECT
            applications.*,
            applications.job_seeker_id,
            job_posts.title AS job_title,
            job_posts.location AS job_location,
            users.phone_number AS applicant_phone,
            job_seeker_profiles.full_name,
            job_seeker_profiles.headline,
            job_seeker_profiles.resume_url
        FROM applications
        JOIN job_posts ON job_posts.id = applications.job_post_id
        JOIN users ON users.id = applications.job_seeker_id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = applications.job_seeker_id
        WHERE job_posts.employer_id = ?
        ORDER BY datetime(applications.created_at) DESC, applications.id DESC
        """,
        (user["id"],),
    ).fetchall()
    return render_template("employer_applications.html", applications=applications)


@app.route("/employer/applications/<int:application_id>/<action>", methods=["POST"])
@login_required
def employer_update_application(application_id, action):
    user = get_current_user()
    if user["role"] != "EMPLOYER":
        abort(403)
    status_map = {
        "review": "REVIEWING",
        "shortlist": "SHORTLISTED",
        "reject": "REJECTED",
        "accept": "ACCEPTED",
    }
    new_status = status_map.get(action)
    if not new_status:
        abort(404)

    row = get_db().execute(
        """
        SELECT applications.*, job_posts.employer_id, job_posts.title
        FROM applications
        JOIN job_posts ON job_posts.id = applications.job_post_id
        WHERE applications.id = ?
        """,
        (application_id,),
    ).fetchone()
    if not row or row["employer_id"] != user["id"]:
        abort(404)

    get_db().execute(
        "UPDATE applications SET status = ?, updated_at = ? WHERE id = ?",
        (new_status, now_str(), application_id),
    )
    create_notification(
        row["job_seeker_id"],
        "สถานะใบสมัครอัปเดต",
        f"ใบสมัครงาน {row['title']} เปลี่ยนเป็น {new_status}",
        url_for("job_seeker_dashboard"),
        "APPLICATION",
    )
    add_activity_log(user["id"], "UPDATE_APPLICATION", "applications", application_id, new_status)
    get_db().commit()
    return redirect(url_for("employer_applications"))


@app.route("/job-seeker/post", methods=["GET", "POST"])
@login_required
def job_seeker_post():
    user = get_current_user()
    if user["role"] != "JOB_SEEKER":
        abort(403)
    if request.method == "POST":
        return redirect(url_for("job_seeker_post"))
    profile = get_db().execute(
        "SELECT * FROM job_seeker_profiles WHERE user_id = ?",
        (user["id"],),
    ).fetchone()
    applications = get_db().execute(
        """
        SELECT applications.*, job_posts.title, job_posts.location, employer_profiles.company_name
        FROM applications
        JOIN job_posts ON job_posts.id = applications.job_post_id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE applications.job_seeker_id = ?
        ORDER BY datetime(applications.created_at) DESC, applications.id DESC
        """,
        (user["id"],),
    ).fetchall()
    return render_template("job_seeker_post.html", profile=profile, applications=applications)


@app.route("/applications/<int:job_id>", methods=["POST"])
@login_required
def apply_job(job_id):
    user = get_current_user()
    if user["role"] != "JOB_SEEKER":
        abort(403)

    job = get_db().execute(
        "SELECT * FROM job_posts WHERE id = ? AND status = 'ACTIVE'",
        (job_id,),
    ).fetchone()
    if not job:
        abort(404)

    message = request.form.get("message", "").strip()[:1000]
    current_time = now_str()
    try:
        get_db().execute(
            """
            INSERT INTO applications (job_seeker_id, job_post_id, status, message, created_at, updated_at)
            VALUES (?, ?, 'PENDING', ?, ?, ?)
            """,
            (user["id"], job_id, message, current_time, current_time),
        )
        create_notification(
            job["employer_id"],
            "มีผู้สมัครงานใหม่",
            f"มีผู้สมัครงาน {job['title']}",
            url_for("employer_applications"),
            "APPLICATION",
        )
        add_activity_log(user["id"], "APPLY_JOB", "job_posts", job_id, "")
        get_db().commit()
    except sqlite3.IntegrityError:
        pass
    return redirect(url_for("job_detail_old", job_id=job_id))


@app.route("/reports/<int:job_id>", methods=["POST"])
@login_required
def report_job(job_id):
    user = get_current_user()
    reason = request.form.get("reason", "").strip()
    if len(reason) < 3:
        reason = "ผู้ใช้แจ้งตรวจประกาศนี้"
    current_time = now_str()
    try:
        get_db().execute(
            """
            INSERT INTO reports (job_post_id, reporter_id, reason, status, created_at, updated_at)
            VALUES (?, ?, ?, 'PENDING', ?, ?)
            """,
            (job_id, user["id"], reason[:500], current_time, current_time),
        )
        row = get_db().execute(
            "SELECT COUNT(*) AS count FROM reports WHERE job_post_id = ?",
            (job_id,),
        ).fetchone()
        report_count = int(row["count"] or 0)
        job = get_db().execute("SELECT * FROM job_posts WHERE id = ?", (job_id,)).fetchone()
        if job:
            score, status, risk_reason = analyze_job_content(
                job["title"],
                job["description"],
                job["salary_range"],
                job["location"],
                50,
                report_count,
            )
            next_status = "PENDING_AI_REVIEW" if status == "ACTIVE" and report_count > 0 else status
            get_db().execute(
                """
                UPDATE job_posts
                SET report_count = ?, ai_risk_score = ?, ai_risk_reason = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (report_count, score, risk_reason, next_status, current_time, job_id),
            )
            create_notification(
                job["employer_id"],
                "ประกาศถูกแจ้งตรวจ",
                f"ประกาศ {job['title']} ถูกผู้ใช้แจ้งตรวจ",
                url_for("job_detail", slug=str(job_id)),
                "REPORT",
            )
        add_activity_log(user["id"], "REPORT_JOB", "job_posts", job_id, reason)
        get_db().commit()
    except sqlite3.IntegrityError:
        pass
    return redirect(url_for("job_detail_old", job_id=job_id))


@app.route("/messages", methods=["POST"])
@login_required
def send_message():
    user = get_current_user()
    receiver_id = request.form.get("receiver_id", "").strip()
    application_id = request.form.get("application_id", "").strip() or None
    message = request.form.get("message", "").strip()
    if receiver_id and message:
        try:
            get_db().execute(
                """
                INSERT INTO messages (sender_id, receiver_id, application_id, message, is_read, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (user["id"], int(receiver_id), int(application_id) if application_id else None, message[:1000], now_str()),
            )
            create_notification(
                int(receiver_id),
                "มีข้อความใหม่",
                message[:160],
                url_for("inbox"),
                "MESSAGE",
            )
            add_activity_log(user["id"], "SEND_MESSAGE", "messages", None, f"receiver={receiver_id}")
            get_db().commit()
        except Exception:
            pass
    return _redirect_back("inbox")


@app.route("/inbox")
@login_required
def inbox():
    return render_template("inbox.html", conversations=[], messages=[], selected_application=None)


@app.route("/api/messages/unread-count")
@login_required
def api_unread_messages_count():
    row = get_db().execute(
        "SELECT COUNT(*) AS count FROM messages WHERE receiver_id = ? AND is_read = 0",
        (get_current_user()["id"],),
    ).fetchone()
    return {"ok": True, "unread": int(row["count"] or 0)}


@app.route("/community")
def community_board():
    posts = get_db().execute(
        """
        SELECT
            community_posts.*,
            users.phone_number,
            job_seeker_profiles.full_name,
            employer_profiles.company_name
        FROM community_posts
        LEFT JOIN users ON users.id = community_posts.user_id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = community_posts.user_id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = community_posts.user_id
        WHERE community_posts.status = 'ACTIVE'
        ORDER BY datetime(community_posts.created_at) DESC, community_posts.id DESC
        LIMIT 100
        """
    ).fetchall()
    stats = {
        "active": len(posts),
        "pending": 0,
        "blocked": 0,
    }
    return render_template("community.html", posts=posts, stats=stats)


@app.route("/community/posts", methods=["POST"])
@login_required
def create_community_post():
    user = get_current_user()
    body = request.form.get("body", "").strip() or request.form.get("content", "").strip()
    if body:
        result = None
        try:
            from security_engine import analyze_community_post
            result = analyze_community_post(body)
        except Exception:
            result = {"score": 35, "status": "PENDING_REVIEW", "reason": "ระบบคัดกรองไม่สมบูรณ์"}

        current_time = now_str()
        get_db().execute(
            """
            INSERT INTO community_posts (
                user_id, body, status, moderation_score, moderation_reason,
                report_count, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                user["id"],
                body[:2000],
                result.get("status", "PENDING_REVIEW"),
                int(result.get("score", 0) or 0),
                result.get("reason", ""),
                current_time,
                current_time,
            ),
        )
        add_activity_log(user["id"], "CREATE_COMMUNITY_POST", "community_posts", None, "")
        get_db().commit()
    return redirect(url_for("community_board"))


@app.route("/openchat")
def openchat():
    messages = get_db().execute(
        """
        SELECT
            openchat_messages.*,
            users.phone_number,
            users.role,
            COALESCE(job_seeker_profiles.full_name, employer_profiles.company_name, '') AS author_name
        FROM openchat_messages
        LEFT JOIN users ON users.id = openchat_messages.user_id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = openchat_messages.user_id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = openchat_messages.user_id
        WHERE openchat_messages.status = 'ACTIVE'
        ORDER BY datetime(openchat_messages.created_at) DESC, openchat_messages.id DESC
        LIMIT 100
        """
    ).fetchall()
    return render_template("openchat.html", messages=messages, media_by_message={})


@app.route("/openchat/send", methods=["POST"])
@login_required
def openchat_send():
    user = get_current_user()
    message = request.form.get("message", "").strip()
    if message:
        try:
            from security_engine import analyze_openchat_message
            result = analyze_openchat_message(message)
        except Exception:
            result = {"score": 35, "status": "PENDING_REVIEW", "reason": "ระบบคัดกรองไม่สมบูรณ์"}

        current_time = now_str()
        get_db().execute(
            """
            INSERT INTO openchat_messages (
                user_id, message, status, moderation_score, moderation_reason,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                message[:1000],
                result.get("status", "PENDING_REVIEW"),
                int(result.get("score", 0) or 0),
                result.get("reason", ""),
                current_time,
                current_time,
            ),
        )
        add_activity_log(user["id"], "SEND_OPENCHAT", "openchat_messages", None, "")
        get_db().commit()
    return redirect(url_for("openchat"))


@app.route("/uploads/openchat/<path:filename>")
def uploaded_openchat_media(filename):
    return send_from_directory(OPENCHAT_UPLOAD_DIR, filename)


@app.route("/urgent")
@app.route("/urgent-jobs")
def urgent_jobs():
    employer_jobs = _fetch_template_jobs(limit=30, urgent_only=True)
    seeker_posts = []
    stats = {
        "total": len(employer_jobs) + len(seeker_posts),
        "employer_jobs": len(employer_jobs),
        "seeker_posts": len(seeker_posts),
    }
    return render_template("urgent_jobs.html", stats=stats, employer_jobs=employer_jobs, seeker_posts=seeker_posts)


@app.route("/job/<slug>")
def job_detail(slug):
    try:
        job_id = int(str(slug).split("-")[0])
    except (TypeError, ValueError):
        abort(404)

    job = get_db().execute(
        """
        SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.id = ?
        """,
        (job_id,),
    ).fetchone()
    if not job:
        abort(404)
    already_applied = False
    if get_current_user() and get_current_user()["role"] == "JOB_SEEKER":
        already_applied = bool(
            get_db().execute(
                "SELECT id FROM applications WHERE job_seeker_id = ? AND job_post_id = ?",
                (get_current_user()["id"], job_id),
            ).fetchone()
        )
    try:
        get_db().execute(
            "UPDATE job_posts SET view_count = COALESCE(view_count, 0) + 1 WHERE id = ?",
            (job_id,),
        )
        get_db().commit()
    except Exception:
        pass
    return render_template("job_detail.html", job=job, already_applied=already_applied)


@app.route("/job-id/<int:job_id>")
def job_detail_old(job_id):
    return redirect(url_for("job_detail", slug=str(job_id)))


@app.route("/privacy")
def privacy_policy():
    return render_template("privacy.html")


@app.route("/terms")
def terms_page():
    return render_template("terms.html")


@app.route("/pricing")
def pricing_page():
    return render_template("pricing.html")


@app.route("/employer")
def employer_landing():
    return redirect(url_for("pricing_page"))


@app.route("/setup-check")
@role_required("ADMIN")
def setup_check():
    # TODO: Expand this with full system checks if the admin diagnostics page is restored.
    conn = get_db()

    def count(table_name):
        try:
            row = conn.execute(f"SELECT COUNT(*) AS count FROM {table_name}").fetchone()
            return int(row["count"] or 0)
        except Exception:
            return 0

    stats = {
        "users": count("users"),
        "job_posts": count("job_posts"),
        "reports": count("reports"),
        "checked_at": now_str(),
    }
    return render_template("setup_check.html", stats=stats)


@app.route("/admin")
@role_required("ADMIN")
def admin_dashboard():
    return render_template("admin_dashboard.html", stats=_admin_stats(), review_jobs=_fetch_template_jobs(limit=8, status="PENDING_AI_REVIEW"))


@app.route("/admin/moderation")
@role_required("ADMIN")
def admin_moderation():
    q = request.args.get("q", "").strip().lower()
    status = request.args.get("status", "PENDING_AI_REVIEW").strip()
    where = []
    params = []
    if status:
        where.append("job_posts.status = ?")
        params.append(status)
    if q:
        where.append(
            "(lower(job_posts.title) LIKE ? OR lower(job_posts.description) LIKE ? OR lower(employer_profiles.company_name) LIKE ?)"
        )
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    jobs = get_db().execute(
        f"""
        SELECT
            job_posts.*,
            users.phone_number,
            users.trust_score,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN users ON users.id = job_posts.employer_id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        {where_sql}
        ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
        LIMIT 100
        """,
        tuple(params),
    ).fetchall()
    return render_template("admin_moderation.html", jobs=jobs, q=q, status=status)


@app.route("/scam-check")
@app.route("/admin/scam-center")
@role_required("ADMIN")
def admin_scam_center():
    conn = get_db()

    def count(sql, params=()):
        try:
            return int(conn.execute(sql, params).fetchone()["count"] or 0)
        except Exception:
            return 0

    stats = {
        "high": count("SELECT COUNT(*) AS count FROM job_posts WHERE COALESCE(ai_risk_score, 0) >= 70"),
        "medium": count("SELECT COUNT(*) AS count FROM job_posts WHERE COALESCE(ai_risk_score, 0) >= 35 AND COALESCE(ai_risk_score, 0) < 70"),
        "low": count("SELECT COUNT(*) AS count FROM job_posts WHERE COALESCE(ai_risk_score, 0) < 35"),
        "pending": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'"),
    }
    jobs = conn.execute(
        """
        SELECT
            job_posts.*,
            users.trust_score,
            employer_profiles.company_name
        FROM job_posts
        LEFT JOIN users ON users.id = job_posts.employer_id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.status = 'PENDING_AI_REVIEW'
           OR COALESCE(job_posts.ai_risk_score, 0) >= 35
        ORDER BY COALESCE(job_posts.ai_risk_score, 0) DESC, datetime(job_posts.updated_at) DESC
        LIMIT 100
        """
    ).fetchall()
    logs = []
    try:
        logs = conn.execute(
            """
            SELECT scam_scan_logs.*, job_posts.title
            FROM scam_scan_logs
            LEFT JOIN job_posts ON job_posts.id = scam_scan_logs.job_post_id
            ORDER BY datetime(scam_scan_logs.created_at) DESC, scam_scan_logs.id DESC
            LIMIT 50
            """
        ).fetchall()
    except Exception:
        logs = []
    return render_template("admin_scam_center.html", stats=stats, jobs=jobs, logs=logs)


@app.route("/admin/users")
@role_required("ADMIN")
def admin_users():
    users = get_db().execute("SELECT * FROM users ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/admin/logs")
@role_required("ADMIN")
def admin_logs():
    logs = get_db().execute("SELECT * FROM activity_logs ORDER BY datetime(created_at) DESC, id DESC LIMIT 100").fetchall()
    return render_template("admin_logs.html", logs=logs)


@app.route("/admin/import-runs")
@role_required("ADMIN")
def admin_import_runs():
    return render_template("admin_import_runs.html", import_runs=[])


@app.route("/admin/trust")
@role_required("ADMIN")
def admin_trust_center():
    users = get_db().execute("SELECT * FROM users ORDER BY trust_score ASC, id DESC LIMIT 100").fetchall()
    return render_template("admin_trust.html", users=users)


@app.route("/admin/system-health")
@role_required("ADMIN")
def admin_system_health():
    conn = get_db()

    def count(sql):
        try:
            return int(conn.execute(sql).fetchone()["count"] or 0)
        except Exception:
            return 0

    db_path = DB_PATH
    health = {
        "checked_at": now_str(),
        "render_git_commit": os.environ.get("RENDER_GIT_COMMIT", ""),
        "render_service_name": os.environ.get("RENDER_SERVICE_NAME", ""),
        "render_external_url": os.environ.get("RENDER_EXTERNAL_URL", ""),
        "database_exists": db_path.exists(),
        "database_size": f"{db_path.stat().st_size} bytes" if db_path.exists() else "-",
        "database_path": str(db_path),
        "stats": {
            "users": count("SELECT COUNT(*) AS count FROM users"),
            "active_jobs": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'"),
            "pending_jobs": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'"),
            "rejected_jobs": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'REJECTED'"),
            "reports": count("SELECT COUNT(*) AS count FROM reports"),
            "activity_logs": count("SELECT COUNT(*) AS count FROM activity_logs"),
        },
        "env_checks": {
            "JOBBOARD_SECRET_KEY": bool(app.secret_key),
            "JOBBOARD_ADMIN_PHONE": bool(ADMIN_PHONE),
            "JOBBOARD_ADMIN_PASSWORD": bool(ADMIN_PASSWORD),
            "JOBBOARD_CRON_TOKEN": bool(JOBBOARD_CRON_TOKEN),
        },
    }
    return render_template("admin_system_health.html", health=health)


@app.route("/admin/openchat-media")
@role_required("ADMIN")
def admin_openchat_media_review():
    stats = {"pending": 0, "approved": 0, "rejected": 0}
    return render_template("admin_openchat_media_review.html", stats=stats, media_items=[])


@app.route("/admin/backup/download")
@role_required("ADMIN")
def admin_backup_download():
    # TODO: Restore full backup ZIP generation.
    return Response("Backup route placeholder", mimetype="text/plain")


@app.route("/admin/discord-test")
@role_required("ADMIN")
def admin_discord_test():
    # TODO: Restore Discord webhook test.
    return redirect(url_for("admin_system_health"))


@app.route("/admin/import-upper-central-jobs")
@role_required("ADMIN")
def admin_import_upper_central_jobs():
    try:
        from auto_job_engine import run_live
        result = run_live()
        add_activity_log(get_current_user()["id"], "ADMIN_IMPORT_DOE_NEWS", "job_posts", None, str(result))
        get_db().commit()
    except Exception as exc:
        add_activity_log(get_current_user()["id"], "ADMIN_IMPORT_DOE_NEWS_FAILED", "job_posts", None, str(exc))
        get_db().commit()
    return redirect(url_for("admin_import_runs"))


@app.route("/admin/import-latest-doe-news")
@role_required("ADMIN")
def admin_import_latest_doe_news():
    return admin_import_upper_central_jobs()


@app.route("/admin/repair-doe-source-links")
@role_required("ADMIN")
def admin_repair_doe_source_links():
    # TODO: Restore source link repair action.
    return redirect(url_for("admin_import_runs"))


@app.route("/admin/fetch-government-news", methods=["POST"])
@role_required("ADMIN")
def admin_fetch_government_news():
    try:
        from auto_job_engine import run_live
        result = run_live()
        add_activity_log(get_current_user()["id"], "ADMIN_FETCH_GOVERNMENT_NEWS", "job_posts", None, str(result))
        get_db().commit()
    except Exception as exc:
        add_activity_log(get_current_user()["id"], "ADMIN_FETCH_GOVERNMENT_NEWS_FAILED", "job_posts", None, str(exc))
        get_db().commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/scam-center/run", methods=["POST"])
@role_required("ADMIN")
def admin_run_scam_scanner():
    try:
        from scam_engine import scan_all_jobs
        result = scan_all_jobs(apply_changes=True)
        add_activity_log(
            get_current_user()["id"],
            "RUN_SCAM_SCANNER",
            "job_posts",
            None,
            str(result),
        )
        get_db().commit()
    except Exception as exc:
        add_activity_log(get_current_user()["id"], "RUN_SCAM_SCANNER_FAILED", "job_posts", None, str(exc))
        get_db().commit()
    return redirect(url_for("admin_scam_center"))


@app.route("/admin/jobs/<int:job_id>/<action>", methods=["POST"])
@role_required("ADMIN")
def admin_update_job_status(job_id, action):
    status_map = {
        "approve": "ACTIVE",
        "review": "PENDING_AI_REVIEW",
        "reject": "REJECTED",
        "close": "CLOSED",
    }
    status = status_map.get(action)
    if not status:
        abort(404)
    get_db().execute(
        "UPDATE job_posts SET status = ?, updated_at = ? WHERE id = ?",
        (status, now_str(), job_id),
    )
    add_activity_log(get_current_user()["id"], "ADMIN_UPDATE_JOB_STATUS", "job_posts", job_id, status)
    get_db().commit()
    return _redirect_back("admin_moderation")


@app.route("/admin/jobs/<int:job_id>/delete", methods=["POST"])
@role_required("ADMIN")
def admin_delete_job(job_id):
    get_db().execute("DELETE FROM job_posts WHERE id = ?", (job_id,))
    add_activity_log(get_current_user()["id"], "ADMIN_DELETE_JOB", "job_posts", job_id, "")
    get_db().commit()
    return redirect(url_for("admin_moderation"))


@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@role_required("ADMIN")
def admin_ban_user(user_id):
    get_db().execute("UPDATE users SET is_banned = 1, updated_at = ? WHERE id = ?", (now_str(), user_id))
    add_activity_log(get_current_user()["id"], "ADMIN_BAN_USER", "users", user_id, "")
    get_db().commit()
    return _redirect_back("admin_users")


@app.route("/admin/users/<int:user_id>/unban", methods=["POST"])
@role_required("ADMIN")
def admin_unban_user(user_id):
    get_db().execute("UPDATE users SET is_banned = 0, updated_at = ? WHERE id = ?", (now_str(), user_id))
    add_activity_log(get_current_user()["id"], "ADMIN_UNBAN_USER", "users", user_id, "")
    get_db().commit()
    return _redirect_back("admin_users")


@app.route("/admin/users/<int:user_id>/verify-employer", methods=["POST"])
@role_required("ADMIN")
def admin_verify_employer(user_id):
    get_db().execute(
        "UPDATE employer_profiles SET is_company_verified = 1, updated_at = ? WHERE user_id = ?",
        (now_str(), user_id),
    )
    get_db().execute(
        "UPDATE users SET trust_score = min(100, trust_score + 15), updated_at = ? WHERE id = ?",
        (now_str(), user_id),
    )
    add_activity_log(get_current_user()["id"], "ADMIN_VERIFY_EMPLOYER", "users", user_id, "")
    get_db().commit()
    return redirect(url_for("admin_trust_center"))


@app.route("/admin/users/<int:user_id>/unverify-employer", methods=["POST"])
@role_required("ADMIN")
def admin_unverify_employer(user_id):
    get_db().execute(
        "UPDATE employer_profiles SET is_company_verified = 0, updated_at = ? WHERE user_id = ?",
        (now_str(), user_id),
    )
    add_activity_log(get_current_user()["id"], "ADMIN_UNVERIFY_EMPLOYER", "users", user_id, "")
    get_db().commit()
    return redirect(url_for("admin_trust_center"))


@app.route("/admin/users/<int:user_id>/trust/<action>", methods=["POST"])
@role_required("ADMIN")
def admin_update_trust(user_id, action):
    delta_map = {"increase": 10, "decrease": -10, "reset": None}
    if action not in delta_map:
        abort(404)
    if delta_map[action] is None:
        get_db().execute(
            "UPDATE users SET trust_score = 50, updated_at = ? WHERE id = ?",
            (now_str(), user_id),
        )
    else:
        get_db().execute(
            "UPDATE users SET trust_score = max(0, min(100, trust_score + ?)), updated_at = ? WHERE id = ?",
            (delta_map[action], now_str(), user_id),
        )
    add_activity_log(get_current_user()["id"], "ADMIN_UPDATE_TRUST", "users", user_id, action)
    get_db().commit()
    return redirect(url_for("admin_trust_center"))


@app.route("/admin/openchat-media/<int:media_id>/<action>", methods=["POST"])
@role_required("ADMIN")
def admin_update_openchat_media_review(media_id, action):
    # TODO: Restore OpenChat media moderation workflow.
    return redirect(url_for("admin_openchat_media_review"))


@app.route("/notifications")
@login_required
def notifications_page():
    user = get_current_user()
    ensure_notification_schema()
    conn = get_db()

    items = conn.execute(
        """
        SELECT *
        FROM notifications
        WHERE user_id = ?
        ORDER BY is_read ASC, datetime(created_at) DESC, id DESC
        LIMIT 50
        """,
        (user["id"],)
    ).fetchall()

    return render_template("notifications.html", notifications=items, user=user)


@app.route("/notifications/settings", methods=["GET", "POST"])
@login_required
def notification_settings():
    user = get_current_user()
    ensure_notification_schema()
    error = ""
    success = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        wants_email = 1 if request.form.get("wants_email_alerts") else 0
        wants_web = 1 if request.form.get("wants_web_alerts") else 0
        browser_enabled = 1 if request.form.get("browser_notifications_enabled") else 0

        if email and ("@" not in email or "." not in email.split("@")[-1]):
            error = "รูปแบบอีเมลไม่ถูกต้อง"
        else:
            conn = get_db()
            conn.execute(
                """
                UPDATE users
                SET email = ?,
                    wants_email_alerts = ?,
                    wants_web_alerts = ?,
                    browser_notifications_enabled = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (email, wants_email, wants_web, browser_enabled, now_str(), user["id"])
            )
            conn.commit()

            create_notification(
                user["id"],
                "ตั้งค่าการแจ้งเตือนแล้ว",
                "ระบบบันทึกการตั้งค่าการแจ้งเตือนของคุณเรียบร้อย",
                url_for("notifications_page"),
                "SETTINGS",
            )
            success = "บันทึกการตั้งค่าเรียบร้อย"
            user = get_current_user()

    return render_template("notification_settings.html", user=user, error=error, success=success)


@app.route("/api/notifications")
@login_required
def api_notifications():
    user = get_current_user()
    items = get_recent_notifications(user["id"], 10)
    unread = get_unread_notifications_count(user["id"])

    return {
        "ok": True,
        "unread": unread,
        "items": [
            {
                "id": row["id"],
                "title": row["title"],
                "message": row["message"],
                "link_url": row["link_url"],
                "category": row["category"],
                "is_read": bool(row["is_read"]),
                "created_at": row["created_at"],
            }
            for row in items
        ],
    }


@app.route("/api/notifications/mark-read", methods=["POST"])
@login_required
def api_notifications_mark_read():
    user = get_current_user()
    ensure_notification_schema()
    conn = get_db()
    current_time = now_str()

    notification_id = request.form.get("notification_id", "").strip()

    if notification_id:
        conn.execute(
            """
            UPDATE notifications
            SET is_read = 1, read_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (current_time, notification_id, user["id"])
        )
    else:
        conn.execute(
            """
            UPDATE notifications
            SET is_read = 1, read_at = ?
            WHERE user_id = ? AND is_read = 0
            """,
            (current_time, user["id"])
        )

    conn.commit()
    return {"ok": True, "unread": get_unread_notifications_count(user["id"])}


@app.route("/api/notifications/browser-enabled", methods=["POST"])
@login_required
def api_notifications_browser_enabled():
    user = get_current_user()
    ensure_notification_schema()
    conn = get_db()
    conn.execute(
        """
        UPDATE users
        SET browser_notifications_enabled = 1,
            wants_web_alerts = 1,
            updated_at = ?
        WHERE id = ?
        """,
        (now_str(), user["id"])
    )
    conn.commit()

    create_notification(
        user["id"],
        "เปิดแจ้งเตือนบนอุปกรณ์แล้ว",
        "คุณจะเห็นแจ้งเตือนในเว็บ และ Browser Notification เมื่อเปิดเว็บนี้ไว้",
        url_for("notifications_page"),
        "SETTINGS",
    )

    return {"ok": True}


if __name__ == "__main__":
    validate_runtime_config()
    with app.app_context():
        init_db()
    app.run(debug=os.environ.get("JOBBOARD_DEBUG", "0") == "1")
