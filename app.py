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
    seed_demo_jobs(conn)
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


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    row = get_db().execute(
        """
        SELECT id, phone_number, role, is_verified, is_banned, trust_score
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    return dict(row) if row else None



# NOTIFICATION_SCHEMA_V1
def ensure_notification_schema():
    conn = get_db()

    ensure_column(conn, "users", "email", "TEXT DEFAULT ''")
    ensure_column(conn, "users", "wants_email_alerts", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "wants_web_alerts", "INTEGER NOT NULL DEFAULT 1")
    ensure_column(conn, "users", "browser_notifications_enabled", "INTEGER NOT NULL DEFAULT 0")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            link_url TEXT DEFAULT '',
            category TEXT DEFAULT 'GENERAL',
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);")

    conn.commit()


def create_notification(user_id, title, message, link_url="", category="GENERAL"):
    try:
        if not user_id:
            return None

        ensure_notification_schema()
        conn = get_db()
        current_time = now_str()

        cur = conn.execute(
            """
            INSERT INTO notifications (
                user_id, title, message, link_url, category, is_read, created_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (
                user_id,
                str(title or "แจ้งเตือน")[:180],
                str(message or "")[:1000],
                str(link_url or "")[:500],
                str(category or "GENERAL")[:60],
                current_time,
            )
        )
        conn.commit()
        return cur.lastrowid
    except Exception:
        return None


def create_notifications_for_role(role, title, message, link_url="", category="GENERAL"):
    try:
        ensure_notification_schema()
        conn = get_db()
        rows = conn.execute(
            """
            SELECT id
            FROM users
            WHERE role = ?
              AND status = 'ACTIVE'
              AND COALESCE(wants_web_alerts, 1) = 1
            """,
            (role,)
        ).fetchall()

        count = 0
        for row in rows:
            if create_notification(row["id"], title, message, link_url, category):
                count += 1
        return count
    except Exception:
        return 0


def get_unread_notifications_count(user_id):
    try:
        ensure_notification_schema()
        conn = get_db()
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND is_read = 0",
            (user_id,)
        ).fetchone()
        return int(row["count"] or 0)
    except Exception:
        return 0


def get_recent_notifications(user_id, limit=8):
    try:
        ensure_notification_schema()
        conn = get_db()
        return conn.execute(
            """
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY is_read ASC, datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (user_id, int(limit or 8))
        ).fetchall()
    except Exception:
        return []

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("login"))
            if user["role"] not in roles:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator



def enforce_security(action):
    ok, message = security_guard(request, action)
    if not ok:
        add_activity_log(
            session.get("user_id"),
            "SECURITY_RATE_LIMIT",
            "request",
            None,
            f"action={action}; ip={request.remote_addr}; path={request.path}",
        )
        try:
            get_db().commit()
        except Exception:
            pass
        return message, 429
    return None

def send_discord_alert(message, username="JobBoard Alert"):
    if not DISCORD_SCAM_ALERT_WEBHOOK_URL:
        return False

    try:
        response = requests.post(
            DISCORD_SCAM_ALERT_WEBHOOK_URL,
            json={
                "username": username,
                "content": message[:1900],
            },
            timeout=5,
        )
        return 200 <= response.status_code < 300
    except Exception:
        return False


def send_job_risk_discord_alert(job_id, user, title, description, salary_range, location, status, score, reason):
    try:
        risk_score = int(score or 0)
    except (TypeError, ValueError):
        risk_score = 0

    risk_label = scam_risk_label(risk_score)
    employer_phone = user.get("phone_number", "-") if isinstance(user, dict) else "-"

    short_description = str(description or "").strip().replace("\r", " ").replace("\n", " ")
    if len(short_description) > 300:
        short_description = short_description[:300] + "..."

    safe_reason = str(reason or "-").strip()
    if len(safe_reason) > 700:
        safe_reason = safe_reason[:700] + "..."

    admin_url = url_for("admin_scam_center", _external=True)

    message = (
        "🚨 พบประกาศงานเสี่ยงจากระบบ AI Anti-Scam\n"
        f"Job ID: {job_id}\n"
        f"สถานะ: {status}\n"
        f"ระดับความเสี่ยง: {risk_label} ({risk_score}/100)\n"
        f"นายจ้าง: {employer_phone}\n"
        f"ตำแหน่ง: {title}\n"
        f"เงินเดือน: {salary_range or '-'}\n"
        f"พื้นที่: {location or '-'}\n"
        f"เหตุผล: {safe_reason}\n"
        f"รายละเอียดย่อ: {short_description or '-'}\n"
        f"ตรวจสอบในระบบ: {admin_url}"
    )

    return send_discord_alert(message, username="JobBoard Scam Alert Bot")


@app.errorhandler(400)
def handle_400(error):
    return render_template("error.html", code=400, title="คำขอไม่ถูกต้อง", message="กรุณาตรวจสอบข้อมูลแล้วลองใหม่อีกครั้ง"), 400


@app.errorhandler(403)
def handle_403(error):
    return render_template("error.html", code=403, title="ไม่มีสิทธิ์เข้าถึง", message="บัญชีของคุณไม่มีสิทธิ์ใช้งานหน้านี้"), 403


@app.errorhandler(404)
def handle_404(error):
    return render_template("error.html", code=404, title="ไม่พบหน้าที่ต้องการ", message="ลิงก์นี้อาจถูกย้าย ลบ หรือพิมพ์ผิด"), 404


@app.errorhandler(413)
def handle_413(error):
    return render_template("error.html", code=413, title="ไฟล์ใหญ่เกินไป", message="กรุณาอัปโหลดรูปภาพไม่เกิน 5 MB หรือวิดีโอไม่เกิน 50 MB"), 413


@app.errorhandler(500)
def handle_500(error):
    try:
        add_activity_log(session.get("user_id"), "SERVER_ERROR_500", "request", None, f"path={request.path}")
        get_db().commit()
    except Exception:
        pass
    return render_template("error.html", code=500, title="ระบบขัดข้องชั่วคราว", message="ระบบพบข้อผิดพลาด กรุณาลองใหม่อีกครั้ง หรือแจ้งผู้ดูแลระบบ"), 500


@app.route("/")
def home():
    conn = get_db()

    stats = {
        "active_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'").fetchone()["count"],
        "blocked_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'REJECTED'").fetchone()["count"],
        "reports": conn.execute("SELECT COUNT(*) AS count FROM reports").fetchone()["count"],
        "verified_employers": conn.execute("SELECT COUNT(*) AS count FROM employer_profiles WHERE is_company_verified = 1").fetchone()["count"],
    }

    latest_jobs = conn.execute(
        """
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.status = 'ACTIVE'
        ORDER BY datetime(job_posts.created_at) DESC, job_posts.id DESC
        LIMIT 6
        """
    ).fetchall()

    government_jobs = conn.execute(
        """
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.status = 'ACTIVE'
          AND job_posts.is_government_news = 1
        ORDER BY
            CASE WHEN job_posts.source_url LIKE '%doe.go.th%' THEN 0 ELSE 1 END,
            CASE WHEN job_posts.source_url LIKE '%google.com%' THEN 9 ELSE 0 END,
            CASE WHEN job_posts.source_url LIKE '%example.com%' THEN 9 ELSE 0 END,
            datetime(job_posts.updated_at) DESC,
            datetime(job_posts.created_at) DESC,
            job_posts.id DESC
        LIMIT 8
        """
    ).fetchall()

    recommended_jobs = conn.execute(
        """
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.status = 'ACTIVE'
          AND job_posts.ai_risk_score <= 20
        ORDER BY employer_profiles.is_company_verified DESC,
                 job_posts.report_count ASC,
                 datetime(job_posts.created_at) DESC
        LIMIT 4
        """
    ).fetchall()

    popular_employers = conn.execute(
        """
        SELECT
            employer_profiles.user_id,
            employer_profiles.company_name,
            employer_profiles.website,
            employer_profiles.is_company_verified,
            users.trust_score,
            COUNT(job_posts.id) AS job_count
        FROM employer_profiles
        JOIN users ON users.id = employer_profiles.user_id
        LEFT JOIN job_posts ON job_posts.employer_id = employer_profiles.user_id
                          AND job_posts.status = 'ACTIVE'
        GROUP BY employer_profiles.user_id
        ORDER BY employer_profiles.is_company_verified DESC,
                 users.trust_score DESC,
                 job_count DESC
        LIMIT 6
        """
    ).fetchall()

    locations = conn.execute(
        """
        SELECT location, COUNT(*) AS count
        FROM job_posts
        WHERE status = 'ACTIVE'
          AND location != ''
        GROUP BY location
        ORDER BY count DESC, location ASC
        LIMIT 8
        """
    ).fetchall()

    return render_template(
        "home.html",
        latest_jobs=latest_jobs,
        government_jobs=government_jobs,
        recommended_jobs=recommended_jobs,
        popular_employers=popular_employers,
        locations=locations,
        stats=stats,
    )



@app.route("/urgent")
def urgent_jobs():
    conn = get_db()

    employer_jobs = conn.execute(
        """
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            employer_profiles.is_company_verified,
            users.trust_score
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        LEFT JOIN users ON users.id = job_posts.employer_id
        WHERE job_posts.status = 'ACTIVE'
          AND (
                COALESCE(job_posts.is_urgent, 0) = 1
                OR job_posts.title LIKE '%ด่วน%'
                OR job_posts.description LIKE '%ด่วน%'
              )
        ORDER BY
            COALESCE(job_posts.is_urgent, 0) DESC,
            employer_profiles.is_company_verified DESC,
            datetime(job_posts.created_at) DESC,
            job_posts.id DESC
        LIMIT 80
        """
    ).fetchall()

    seeker_posts = conn.execute(
        """
        SELECT
            job_seeker_profiles.*,
            users.phone_number,
            users.trust_score,
            users.created_at AS user_created_at
        FROM job_seeker_profiles
        JOIN users ON users.id = job_seeker_profiles.user_id
        WHERE users.is_banned = 0
          AND job_seeker_profiles.is_public = 1
          AND (
                COALESCE(job_seeker_profiles.is_urgent, 0) = 1
                OR job_seeker_profiles.headline LIKE '%ด่วน%'
                OR job_seeker_profiles.resume_url LIKE '%ด่วน%'
              )
        ORDER BY
            COALESCE(job_seeker_profiles.is_urgent, 0) DESC,
            datetime(job_seeker_profiles.updated_at) DESC,
            job_seeker_profiles.id DESC
        LIMIT 80
        """
    ).fetchall()

    stats = {
        "employer_jobs": len(employer_jobs),
        "seeker_posts": len(seeker_posts),
        "total": len(employer_jobs) + len(seeker_posts),
    }

    return render_template(
        "urgent_jobs.html",
        employer_jobs=employer_jobs,
        seeker_posts=seeker_posts,
        stats=stats,
    )


@app.route("/jobs")
def jobs_public():
    q = request.args.get("q", "").strip().lower()
    location = request.args.get("location", "").strip()
    page_raw = request.args.get("page", "1").strip()

    try:
        page = max(1, int(page_raw))
    except ValueError:
        page = 1

    per_page = 10
    offset = (page - 1) * per_page

    conn = get_db()

    where_sql = "WHERE job_posts.status = 'ACTIVE'"
    params = []

    if q:
        like_q = f"%{q}%"
        where_sql += """
            AND (
                lower(job_posts.title) LIKE ?
                OR lower(job_posts.description) LIKE ?
                OR lower(job_posts.location) LIKE ?
                OR lower(job_posts.salary_range) LIKE ?
                OR lower(employer_profiles.company_name) LIKE ?
            )
        """
        params.extend([like_q, like_q, like_q, like_q, like_q])

    if location:
        where_sql += " AND lower(job_posts.location) LIKE ?"
        params.append(f"%{location.lower()}%")

    total = conn.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        {where_sql}
        """,
        tuple(params)
    ).fetchone()["count"]

    jobs = conn.execute(
        f"""
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        {where_sql}
        ORDER BY datetime(job_posts.created_at) DESC, job_posts.id DESC
        LIMIT ? OFFSET ?
        """,
        tuple(params + [per_page, offset])
    ).fetchall()

    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "jobs.html",
        jobs=jobs,
        q=q,
        location=location,
        page=page,
        total_pages=total_pages,
        total=total,
    )


@app.route("/robots.txt")
def robots_txt():
    lines = [
        "User-agent: *",
        "Allow: /",
        "Disallow: /admin",
        "Disallow: /admin/",
        "Disallow: /dashboard",
        "Disallow: /dashboard/",
        f"Sitemap: {url_for('sitemap_xml', _external=True)}",
    ]
    return Response("\n".join(lines), mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    conn = get_db()
    jobs = conn.execute(
        """
        SELECT id, title, location, updated_at, created_at
        FROM job_posts
        WHERE status = 'ACTIVE'
        ORDER BY datetime(updated_at) DESC, id DESC
        LIMIT 5000
        """
    ).fetchall()

    urls = [
        (url_for("home", _external=True), now_str()[:10], "daily", "1.0"),
        (url_for("jobs_public", _external=True), now_str()[:10], "daily", "0.9"),
    ]

    for job in jobs:
        lastmod = (job["updated_at"] or job["created_at"] or now_str())[:10]
        urls.append((url_for("job_detail", slug=job_slug(job), _external=True), lastmod, "weekly", "0.8"))

    xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    for loc, lastmod, changefreq, priority in urls:
        xml.append("  <url>")
        xml.append(f"    <loc>{loc}</loc>")
        xml.append(f"    <lastmod>{lastmod}</lastmod>")
        xml.append(f"    <changefreq>{changefreq}</changefreq>")
        xml.append(f"    <priority>{priority}</priority>")
        xml.append("  </url>")
    xml.append("</urlset>")
    return Response("\n".join(xml), mimetype="application/xml")


@app.route("/employers/<int:user_id>")
def employer_public_profile(user_id):
    conn = get_db()
    employer = conn.execute(
        """
        SELECT
            users.id,
            users.phone_number,
            users.trust_score,
            employer_profiles.company_name,
            employer_profiles.address,
            employer_profiles.website,
            employer_profiles.is_company_verified,
            employer_profiles.created_at
        FROM users
        JOIN employer_profiles ON employer_profiles.user_id = users.id
        WHERE users.id = ?
          AND users.role = 'EMPLOYER'
          AND users.is_banned = 0
        """,
        (user_id,)
    ).fetchone()

    if not employer:
        abort(404)

    jobs = conn.execute(
        """
        SELECT *
        FROM job_posts
        WHERE employer_id = ?
          AND status = 'ACTIVE'
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 50
        """,
        (user_id,)
    ).fetchall()

    return render_template("employer_profile.html", employer=employer, jobs=jobs)


@app.route("/setup-check")
def setup_check():
    abort(404)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""

    if request.method == "POST":
        blocked = enforce_security("register")
        if blocked:
            return blocked

        role = request.form.get("role", "JOB_SEEKER").strip()
        phone_number = normalize_phone(request.form.get("phone_number"))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        accept_terms = request.form.get("accept_terms", "")

        full_name = request.form.get("full_name", "").strip()
        company_name = request.form.get("company_name", "").strip()

        if role not in {"JOB_SEEKER", "EMPLOYER"}:
            error = "ประเภทบัญชีไม่ถูกต้อง"
        elif not is_valid_thai_phone(phone_number):
            error = "กรุณากรอกเบอร์โทรศัพท์ 10 หลัก เช่น 0800000000"
        elif not validate_account_password(password, phone_number)[0]:
            error = validate_account_password(password, phone_number)[1]
        elif password != confirm_password:
            error = "รหัสผ่านไม่ตรงกัน"
        elif accept_terms != "on":
            error = "กรุณายอมรับนโยบายความเป็นส่วนตัวและข้อกำหนดการใช้งาน"
        elif role == "JOB_SEEKER" and not validate_profile_name(full_name, "ชื่อผู้หางาน", 80)[0]:
            error = validate_profile_name(full_name, "ชื่อผู้หางาน", 80)[1]
        elif role == "EMPLOYER" and not validate_profile_name(company_name, "ชื่อบริษัท", 120)[0]:
            error = validate_profile_name(company_name, "ชื่อบริษัท", 120)[1]
        else:
            conn = get_db()
            exists = conn.execute("SELECT id FROM users WHERE phone_number = ?", (phone_number,)).fetchone()
            if exists:
                error = "เบอร์โทรศัพท์นี้มีบัญชีอยู่แล้ว"
            else:
                otp = generate_mock_otp()
                session["pending_register"] = {
                    "role": role,
                    "phone_number": phone_number,
                    "password_hash": hash_password(password),
                    "full_name": full_name,
                    "company_name": company_name,
                    "otp": otp,
                    "created_at": now_str(),
                }
                session["user_id"] = user_id
                return redirect(url_for("dashboard"))

    return render_template("register.html", error=error)



@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        blocked = enforce_security("login")
        if blocked:
            return blocked

        phone_number = normalize_phone(request.form.get("phone_number"))
        password = request.form.get("password", "")

        row = get_db().execute(
            "SELECT * FROM users WHERE phone_number = ? LIMIT 1",
            (phone_number,)
        ).fetchone()

        if not row or not verify_password(password, row["password_hash"]):
            error = "เบอร์โทรหรือรหัสผ่านไม่ถูกต้อง"
        elif row["is_banned"]:
            error = "บัญชีนี้ถูกระงับ กรุณาติดต่อผู้ดูแลระบบ"
        else:
            session.clear()
            session.permanent = True
            session["user_id"] = row["id"]
            session["role"] = row["role"]
            return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))



@app.route("/admin/discord-test")
@role_required("ADMIN")
def admin_discord_test():
    ok = send_discord_alert(
        "✅ ทดสอบ Discord Webhook สำเร็จ\n"
        "ระบบ JobBoard AI Anti-Scam เชื่อมต่อ Discord แล้ว",
        username="JobBoard Scam Alert Bot",
    )

    if ok:
        return "OK: Discord webhook sent"

    return "ERROR: Discord webhook failed or DISCORD_SCAM_ALERT_WEBHOOK_URL is missing", 500

@app.route("/admin/backup/download")
@app.route("/admin/backup.zip")
@role_required("ADMIN")
def admin_backup_download():
    admin = get_current_user()
    conn = get_db()

    try:
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(FULL)")
    except Exception:
        pass

    add_activity_log(
        admin["id"],
        "ADMIN_DOWNLOAD_BACKUP",
        "system",
        None,
        "download database and source backup zip",
    )
    conn.commit()

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    zip_buffer = io.BytesIO()

    def add_file(zip_file, file_path, arcname):
        file_path = Path(file_path)
        if file_path.exists() and file_path.is_file():
            zip_file.write(file_path, arcname)

    def add_directory(zip_file, dir_path, arc_prefix):
        dir_path = Path(dir_path)
        if not dir_path.exists() or not dir_path.is_dir():
            return

        blocked_names = {
            ".env",
            "__pycache__",
            ".git",
            ".venv",
            "venv",
            "node_modules",
            ".pytest_cache",
        }

        for item in dir_path.rglob("*"):
            if any(part in blocked_names for part in item.parts):
                continue
            if item.is_file():
                relative_name = item.relative_to(dir_path).as_posix()
                zip_file.write(item, f"{arc_prefix}/{relative_name}")

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        add_file(zip_file, DB_PATH, f"database/{DB_PATH.name}")
        add_file(zip_file, str(DB_PATH) + "-wal", f"database/{DB_PATH.name}-wal")
        add_file(zip_file, str(DB_PATH) + "-shm", f"database/{DB_PATH.name}-shm")

        important_files = [
            "app.py",
            "requirements.txt",
            "Procfile",
            ".gitignore",
            "security_engine.py",
            "scam_engine.py",
            "auto_job_engine.py",
            "government_scraper.py",
            "graphic_generator.py",
        ]

        for filename in important_files:
            add_file(zip_file, BASE_DIR / filename, f"source/{filename}")

        add_directory(zip_file, BASE_DIR / "templates", "source/templates")
        add_directory(zip_file, BASE_DIR / "static", "source/static")

        info = (
            "JobBoard AI Anti-Scam Backup\n"
            f"Created at: {now_str()}\n"
            "Includes: SQLite database, templates, static files, and key Python source files\n"
            "Excluded: .env, .git, virtualenv, cache folders, and secrets\n"
        )
        zip_file.writestr("README-BACKUP.txt", info)

    zip_buffer.seek(0)
    filename = f"jobboard-ai-backup-{timestamp}.zip"

    response = Response(zip_buffer.getvalue(), mimetype="application/zip")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    if user["role"] == "ADMIN":
        return redirect(url_for("admin_dashboard"))
    if user["role"] == "EMPLOYER":
        return redirect(url_for("employer_dashboard"))
    return redirect(url_for("job_seeker_dashboard"))


@app.route("/dashboard/job-seeker")
@role_required("JOB_SEEKER")
def job_seeker_dashboard():
    user = get_current_user()
    conn = get_db()
    profile = conn.execute(
        "SELECT * FROM job_seeker_profiles WHERE user_id = ?",
        (user["id"],)
    ).fetchone()
    applications = conn.execute(
        """
        SELECT applications.*, job_posts.title, job_posts.location, employer_profiles.company_name
        FROM applications
        JOIN job_posts ON job_posts.id = applications.job_post_id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE applications.job_seeker_id = ?
        ORDER BY datetime(applications.created_at) DESC
        """,
        (user["id"],)
    ).fetchall()
    return render_template("dashboard_job_seeker.html", profile=profile, applications=applications)


def add_activity_log(actor_id, action, target_type="", target_id=None, detail=""):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO activity_logs (actor_id, action, target_type, target_id, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor_id, action, target_type, target_id, detail, now_str())
    )


def add_ai_decision_log(job_post_id, title, risk_score, risk_reason, final_status):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO ai_decision_logs (
            job_post_id, title, risk_score, risk_reason, final_status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (job_post_id, title, risk_score, risk_reason, final_status, now_str())
    )


def adjust_trust_score(user_id, delta):
    conn = get_db()
    conn.execute(
        """
        UPDATE users
        SET trust_score = max(0, min(100, trust_score + ?)),
            updated_at = ?
        WHERE id = ?
        """,
        (delta, now_str(), user_id)
    )


def slugify(value):
    text = str(value or "").strip().lower()
    thai_or_word = re.findall(r"[a-z0-9ก-๙]+", text)
    slug = "-".join(thai_or_word)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug or "job"


def job_slug(job):
    return f"{slugify(job['title'])}-{job['location'].strip().lower() if job['location'] else 'online'}-{job['id']}"


def get_trust_level(score):
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 50

    if score >= 80:
        return "HIGH_TRUST"
    if score >= 50:
        return "NORMAL"
    if score >= 25:
        return "LOW_TRUST"
    return "LOCKED"


def can_post_job(user):
    if not user:
        return False, "กรุณาเข้าสู่ระบบ"

    if int(user.get("is_banned", 0)):
        return False, "บัญชีนี้ถูกระงับ"

    trust_score = int(user.get("trust_score", 50))
    if trust_score < 25:
        return False, "Trust Score ต่ำเกินไป ระบบระงับการโพสต์งานชั่วคราว กรุณาติดต่อ Admin"

    return True, ""


def get_user_by_id(user_id):
    row = get_db().execute(
        "SELECT id, phone_number, role, is_verified, is_banned, trust_score FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    return dict(row) if row else None


def run_auto_job_engine_demo():
    from auto_job_engine import run_demo
    return run_demo()


def run_government_scraper_demo():
    from government_scraper import DEMO_JOBS, save_jobs_to_db
    return save_jobs_to_db(DEMO_JOBS)


def run_scam_scanner_now():
    from scam_engine import scan_all_jobs
    return scan_all_jobs(apply_changes=True)


def scam_risk_label(score):
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        score = 0

    if score >= 75:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def analyze_job_text(title, description):
    text = f"{title} {description}".lower()
    score = 0
    reasons = []

    high_risk = {
        "โอนเงินก่อน": 45,
        "ค่าประกัน": 40,
        "ค่าสมัคร": 35,
        "ค่ามัดจำ": 35,
        "งานแพ็คของที่บ้าน": 35,
        "ลงทุนก่อน": 45,
        "ลงทุนน้อย": 30,
        "กำไรสูง": 25,
        "ไม่ต้องสัมภาษณ์": 25,
        "แอดไลน์": 20,
        "ทักไลน์": 20,
        "รายได้หลักแสน": 40,
    }

    medium_risk = {
        "งานออนไลน์": 15,
        "จ่ายรายวัน": 15,
        "ไม่ต้องมีประสบการณ์": 12,
        "รับทันที": 12,
        "รายได้ดี": 10,
        "ทำที่บ้าน": 10,
        "ไม่จำกัดวุฒิ": 8,
    }

    if len(description.strip()) < 80:
        score += 20
        reasons.append("รายละเอียดงานสั้นเกินไป")

    for term, point in high_risk.items():
        if term in text:
            score += point
            reasons.append(f"พบคำเสี่ยงสูง: {term}")

    for term, point in medium_risk.items():
        if term in text:
            score += point
            reasons.append(f"พบคำที่ควรตรวจเพิ่ม: {term}")

    score = max(0, min(score, 100))

    if not reasons:
        reasons.append("ไม่พบคำเสี่ยงเด่นจาก rule-based scanner")

    if score >= 70:
        status = "REJECTED"
    elif score >= 40:
        status = "PENDING_AI_REVIEW"
    else:
        status = "ACTIVE"

    return score, " | ".join(reasons[:8]), status



def normalize_user_text_for_safety(value, max_length=1500):
    text = str(value or "")
    text = text.replace("\x00", "")
    text = re.sub(r"[\u200b-\u200f\u202a-\u202e]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    text = text.strip()

    if len(text) > max_length:
        text = text[:max_length].strip()

    return text


def detect_sensitive_personal_data(text):
    raw = str(text or "")
    digits = re.sub(r"\D", "", raw)
    findings = []

    if re.search(r"\b\d{13}\b", digits):
        findings.append("พบเลขลักษณะคล้ายเลขบัตรประชาชน 13 หลัก")

    if re.search(r"0[689]\d{8}", digits):
        findings.append("พบเบอร์โทรศัพท์ในข้อความ")

    if re.search(r"\b\d{10,12}\b", digits):
        findings.append("พบเลขยาวลักษณะคล้ายเลขบัญชี/ข้อมูลการเงิน")

    if re.search(r"(line\s*id|ไลน์|ไอดีไลน์|telegram|เทเลแกรม|whatsapp|วอทส์แอพ)", raw, re.IGNORECASE):
        findings.append("พบช่องทางติดต่อภายนอก เช่น Line/Telegram/WhatsApp")

    return findings


def analyze_safety_text(body, context="GENERAL"):
    text = normalize_user_text_for_safety(body, 2000)
    lowered = text.lower()

    score = 0
    reasons = []

    if not text:
        return 100, "ข้อความว่างเปล่า", "BLOCKED"

    if len(text) < 2:
        score += 35
        reasons.append("ข้อความสั้นเกินไป")

    if len(text) > 1000:
        score += 15
        reasons.append("ข้อความยาวมากผิดปกติ")

    if re.search(r"(.)\1{7,}", lowered):
        score += 25
        reasons.append("มีอักขระซ้ำจำนวนมาก")

    url_count = len(re.findall(r"https?://|www\.|bit\.ly|shorturl|tinyurl|t\.me/", lowered))
    if url_count >= 2:
        score += 45
        reasons.append("มีลิงก์หลายรายการ")
    elif url_count == 1:
        score += 18
        reasons.append("มีลิงก์ในข้อความ")

    dangerous_terms = {
        "โอนเงินก่อน": 70,
        "ค่าประกัน": 60,
        "ค่าสมัคร": 55,
        "ค่ามัดจำ": 55,
        "ลงทุนก่อน": 70,
        "เว็บพนัน": 80,
        "พนัน": 65,
        "บาคาร่า": 75,
        "สล็อต": 75,
        "เงินกู้": 55,
        "ปล่อยกู้": 60,
        "รับจำนำ": 45,
        "รายได้หลักแสน": 55,
        "ไม่ต้องสัมภาษณ์": 35,
        "งานแพ็คของที่บ้าน": 60,
        "แอดไลน์": 35,
        "ทักไลน์": 35,
        "telegram": 35,
        "whatsapp": 35,
    }

    sexual_terms = {
        "18+": 70,
        "คลิปโป๊": 90,
        "รูปโป๊": 90,
        "หนังโป๊": 90,
        "รับงานเสียว": 90,
        "ไซด์ไลน์": 75,
        "นัดเย": 95,
        "เย็ด": 95,
        "ควย": 65,
        "หี": 65,
        "นม": 35,
    }

    rude_terms = {
        "เหี้ย": 60,
        "สัส": 50,
        "สัด": 50,
        "ไอ้ควาย": 55,
        "ไอ้โง่": 45,
        "มึง": 25,
        "กู": 20,
    }

    threat_terms = {
        "ฆ่า": 75,
        "ทำร้าย": 65,
        "ขู่": 45,
        "ประจาน": 45,
        "แบล็คเมล์": 70,
    }

    for term, point in dangerous_terms.items():
        if term in lowered:
            score += point
            reasons.append(f"พบคำเสี่ยงหลอกลวง/ผิดกฎ: {term}")

    for term, point in sexual_terms.items():
        if term in lowered:
            score += point
            reasons.append(f"พบคำลามก/อนาจาร: {term}")

    for term, point in rude_terms.items():
        if term in lowered:
            score += point
            reasons.append(f"พบคำไม่สุภาพ: {term}")

    for term, point in threat_terms.items():
        if term in lowered:
            score += point
            reasons.append(f"พบคำข่มขู่/คุกคาม: {term}")

    personal_findings = detect_sensitive_personal_data(text)
    if personal_findings:
        if context in {"OPENCHAT", "COMMUNITY"}:
            score += 55
        else:
            score += 25
        reasons.extend(personal_findings[:4])

    score = max(0, min(score, 100))

    if score >= 75:
        status = "BLOCKED"
    elif score >= 35:
        status = "PENDING_REVIEW"
    else:
        status = "ACTIVE"

    if not reasons:
        reasons.append("ผ่านการตรวจความปลอดภัยเบื้องต้น")

    return score, " | ".join(reasons[:10]), status



def safe_send_moderation_alert(content_type, content_id, user, body, status, score, reason):
    try:
        if "send_content_moderation_discord_alert" in globals():
            return send_content_moderation_discord_alert(
                content_type,
                content_id,
                user,
                body,
                status,
                score,
                reason,
            )

        user_phone = user.get("phone_number", "-") if isinstance(user, dict) else "-"
        message = (
            "🛡️ Safety Guard Alert\n"
            f"Type: {content_type}\n"
            f"Content ID: {content_id}\n"
            f"Status: {status}\n"
            f"Score: {score}/100\n"
            f"User: {user_phone}\n"
            f"Reason: {str(reason or '-')[:700]}\n"
            f"Text: {str(body or '-')[:900]}"
        )
        return send_discord_alert(message, username="JobBoard Safety Guard")
    except Exception:
        return False


def safe_add_activity_log(actor_id, action, target_type="", target_id=None, detail=""):
    try:
        add_activity_log(actor_id, action, target_type, target_id, detail)
        return True
    except Exception:
        return False


def reject_unsafe_text_response(score, reason):
    safe_reason = str(reason or "ข้อความไม่ผ่านระบบความปลอดภัย")
    return (
        "ข้อความนี้ไม่สามารถส่งได้ เพราะระบบตรวจพบความเสี่ยงด้านความปลอดภัยหรือความเหมาะสม<br>"
        f"คะแนนความเสี่ยง: {score}/100<br>"
        f"เหตุผล: {safe_reason}<br>"
        '<a href="javascript:history.back()">กลับไปแก้ไขข้อความ</a>'
    ), 400

def analyze_community_text(body):
    return analyze_safety_text(body, context="COMMUNITY")


@app.route("/community")
def community_board():
    user = get_current_user()
    conn = get_db()
    status_filter = request.args.get("status", "").strip().upper()

    if user and user["role"] == "ADMIN":
        where = "WHERE 1=1"
        params = []
        if status_filter in {"ACTIVE", "PENDING_REVIEW", "BLOCKED", "HIDDEN"}:
            where += " AND community_posts.status = ?"
            params.append(status_filter)
    else:
        where = "WHERE community_posts.status = 'ACTIVE'"
        params = []

    posts = conn.execute(
        f"""
        SELECT
            community_posts.*,
            users.phone_number,
            users.role,
            job_seeker_profiles.full_name,
            employer_profiles.company_name
        FROM community_posts
        JOIN users ON users.id = community_posts.user_id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = users.id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = users.id
        {where}
        ORDER BY datetime(community_posts.created_at) DESC, community_posts.id DESC
        LIMIT 100
        """,
        tuple(params)
    ).fetchall()

    stats = {
        "active": conn.execute("SELECT COUNT(*) AS count FROM community_posts WHERE status = 'ACTIVE'").fetchone()["count"],
        "pending": conn.execute("SELECT COUNT(*) AS count FROM community_posts WHERE status = 'PENDING_REVIEW'").fetchone()["count"],
        "blocked": conn.execute("SELECT COUNT(*) AS count FROM community_posts WHERE status = 'BLOCKED'").fetchone()["count"],
    }
    return render_template("community.html", posts=posts, stats=stats, status_filter=status_filter)


@app.route("/community/posts", methods=["POST"])
@login_required
def create_community_post():
    blocked = enforce_security("community")
    if blocked:
        return blocked

    user = get_current_user()
    body = normalize_user_text_for_safety(request.form.get("body", ""), 1000)

    if not body:
        return redirect(url_for("community_board"))

    score, reason, status = analyze_safety_text(body, context="COMMUNITY")

    if status == "BLOCKED":
        alert_sent = safe_send_moderation_alert(
            "COMMUNITY_BLOCKED",
            "-",
            user,
            body,
            status,
            score,
            reason,
        )
        safe_add_activity_log(
            user["id"],
            "COMMUNITY_POST_BLOCKED",
            "community_posts",
            None,
            f"score={score}, alert={alert_sent}, reason={str(reason)[:200]}",
        )
        try:
            get_db().commit()
        except Exception:
            pass
        return reject_unsafe_text_response(score, reason)

    current_time = now_str()
    conn = get_db()

    conn.execute(
        """
        INSERT INTO community_posts (
            user_id, body, status, moderation_score, moderation_reason,
            report_count, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (user["id"], body, status, score, reason, current_time, current_time)
    )

    post_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    add_activity_log(user["id"], "CREATE_COMMUNITY_POST", "community_posts", post_id, f"status={status}, score={score}")

    if status in {"PENDING_REVIEW", "BLOCKED"} or int(score or 0) >= 35:
        alert_sent = safe_send_moderation_alert(
            "COMMUNITY",
            post_id,
            user,
            body,
            status,
            score,
            reason,
        )
        add_activity_log(
            user["id"],
            "DISCORD_COMMUNITY_ALERT_SENT" if alert_sent else "DISCORD_COMMUNITY_ALERT_FAILED",
            "community_posts",
            post_id,
            f"status={status}, score={score}",
        )

    conn.commit()

    return redirect(url_for("community_board"))


@app.route("/community/posts/<int:post_id>/report", methods=["POST"])
@login_required
def report_community_post(post_id):
    user = get_current_user()
    reason = request.form.get("reason", "โพสต์ไม่เหมาะสม").strip() or "โพสต์ไม่เหมาะสม"
    conn = get_db()

    post = conn.execute("SELECT * FROM community_posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        abort(404)

    exists = conn.execute(
        "SELECT id FROM community_reports WHERE post_id = ? AND reporter_id = ?",
        (post_id, user["id"])
    ).fetchone()

    if not exists:
        current_time = now_str()
        conn.execute(
            """
            INSERT INTO community_reports (post_id, reporter_id, reason, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (post_id, user["id"], reason, current_time)
        )
        conn.execute(
            """
            UPDATE community_posts
            SET report_count = report_count + 1,
                status = CASE
                    WHEN report_count + 1 >= 3 AND status = 'ACTIVE' THEN 'PENDING_REVIEW'
                    ELSE status
                END,
                updated_at = ?
            WHERE id = ?
            """,
            (current_time, post_id)
        )
        add_activity_log(user["id"], "REPORT_COMMUNITY_POST", "community_posts", post_id, reason)
        conn.commit()

    return redirect(url_for("community_board"))


@app.route("/admin/community/posts/<int:post_id>/<action>", methods=["POST"])
@role_required("ADMIN")
def admin_update_community_post(post_id, action):
    action_map = {
        "approve": "ACTIVE",
        "review": "PENDING_REVIEW",
        "hide": "HIDDEN",
        "block": "BLOCKED",
    }

    admin = get_current_user()
    conn = get_db()

    post = conn.execute("SELECT id FROM community_posts WHERE id = ?", (post_id,)).fetchone()
    if not post:
        abort(404)

    if action == "delete":
        conn.execute("DELETE FROM community_posts WHERE id = ?", (post_id,))
        add_activity_log(admin["id"], "ADMIN_DELETE_COMMUNITY_POST", "community_posts", post_id, "deleted")
        conn.commit()
        return redirect(url_for("community_board"))

    if action not in action_map:
        abort(404)

    new_status = action_map[action]
    conn.execute(
        "UPDATE community_posts SET status = ?, updated_at = ? WHERE id = ?",
        (new_status, now_str(), post_id)
    )
    add_activity_log(admin["id"], f"ADMIN_COMMUNITY_{action.upper()}", "community_posts", post_id, f"status={new_status}")
    conn.commit()

    return redirect(url_for("community_board"))




def mask_phone_for_display(phone):
    phone = str(phone or "")
    if len(phone) >= 7:
        return phone[:3] + "****" + phone[-3:]
    return "สมาชิก"


def get_openchat_media_kind(ext):
    ext = str(ext or "").lower().strip(".")
    if ext in OPENCHAT_ALLOWED_IMAGE_EXTENSIONS:
        return "IMAGE"
    if ext in OPENCHAT_ALLOWED_VIDEO_EXTENSIONS:
        return "VIDEO"
    return ""


def validate_and_prepare_openchat_media(file_storage):
    if not file_storage or not file_storage.filename:
        return True, None

    original_name = secure_filename(file_storage.filename or "")
    ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
    file_type = get_openchat_media_kind(ext)

    if not file_type:
        return False, "รองรับเฉพาะรูปภาพ jpg, jpeg, png, webp และวิดีโอ mp4, webm เท่านั้น"

    data = file_storage.read()
    file_storage.seek(0)

    if not data:
        return False, "ไฟล์ว่างเปล่า"

    if file_type == "IMAGE" and len(data) > OPENCHAT_MAX_IMAGE_UPLOAD_BYTES:
        return False, "รูปภาพต้องไม่เกิน 5 MB"

    if file_type == "VIDEO" and len(data) > OPENCHAT_MAX_VIDEO_UPLOAD_BYTES:
        return False, "วิดีโอต้องไม่เกิน 50 MB"

    header = data[:64]

    if ext in {"jpg", "jpeg"} and not header.startswith(b"\xff\xd8\xff"):
        return False, "ไฟล์ jpg/jpeg ไม่ถูกต้อง"

    if ext == "png" and not header.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, "ไฟล์ png ไม่ถูกต้อง"

    if ext == "webp" and not (header.startswith(b"RIFF") and b"WEBP" in header[:16]):
        return False, "ไฟล์ webp ไม่ถูกต้อง"

    if ext == "mp4" and b"ftyp" not in header:
        return False, "ไฟล์ mp4 ไม่ถูกต้อง"

    if ext == "webm" and not header.startswith(b"\x1a\x45\xdf\xa3"):
        return False, "ไฟล์ webm ไม่ถูกต้อง"

    file_name = f"{secrets.token_hex(20)}.{ext}"

    return True, {
        "file_name": file_name,
        "original_name": original_name,
        "file_type": file_type,
        "mime_type": file_storage.mimetype or "",
        "data": data,
    }


def save_prepared_openchat_media(prepared_media):
    OPENCHAT_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    file_path = OPENCHAT_UPLOAD_DIR / prepared_media["file_name"]
    file_path.write_bytes(prepared_media["data"])
    return file_path


def build_openchat_media_by_message(conn, messages, current_user=None):
    media_by_message = {}
    message_ids = [message["id"] for message in messages]
    if not message_ids:
        return media_by_message

    try:
        ensure_openchat_media_tables(conn)
    except Exception:
        return media_by_message

    placeholders = ",".join(["?"] * len(message_ids))
    where_status = "" if current_user and current_user.get("role") == "ADMIN" else "AND status = 'APPROVED'"

    try:
        rows = conn.execute(
            f"""
            SELECT *
            FROM openchat_media
            WHERE message_id IN ({placeholders})
            {where_status}
            ORDER BY datetime(created_at) ASC, id ASC
            """,
            tuple(message_ids)
        ).fetchall()
    except sqlite3.OperationalError:
        return media_by_message

    for row in rows:
        media_by_message.setdefault(row["message_id"], []).append(row)

    return media_by_message


@app.route("/media/openchat/<path:filename>")
def uploaded_openchat_media(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(404)

    conn = get_db()
    media = conn.execute(
        "SELECT * FROM openchat_media WHERE file_name = ?",
        (safe_name,)
    ).fetchone()

    if not media:
        abort(404)

    current = get_current_user()

    if media["status"] != "APPROVED":
        if not current:
            abort(404)
        if current["role"] != "ADMIN" and current["id"] != media["user_id"]:
            abort(404)

    return send_from_directory(str(OPENCHAT_UPLOAD_DIR), safe_name)



def ensure_openchat_media_tables(conn):
    conn.executescript(
        """
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
        """
    )


@app.route("/openchat")
@login_required
def openchat():
    user = get_current_user()
    conn = get_db()
    try:
        ensure_openchat_media_tables(conn)
    except Exception:
        pass

    messages = conn.execute(
        """
        SELECT
            openchat_messages.id,
            openchat_messages.user_id,
            openchat_messages.message,
            openchat_messages.status,
            openchat_messages.moderation_score,
            openchat_messages.moderation_reason,
            openchat_messages.created_at,
            users.phone_number,
            COALESCE(job_seeker_profiles.full_name, employer_profiles.company_name, '') AS author_name,
            users.role
        FROM openchat_messages
        JOIN users ON users.id = openchat_messages.user_id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = users.id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = users.id
        WHERE openchat_messages.status = 'ACTIVE'
        ORDER BY datetime(openchat_messages.created_at) DESC, openchat_messages.id DESC
        LIMIT 100
        """
    ).fetchall()

    media_by_message = build_openchat_media_by_message(conn, messages, user)

    return render_template(
        "openchat.html",
        messages=messages,
        current_user=user,
        media_by_message=media_by_message,
        mask_phone_for_display=mask_phone_for_display,
    )


@app.route("/openchat/send", methods=["POST"])
@login_required
def openchat_send():
    blocked = enforce_security("openchat")
    if blocked:
        return blocked

    user = get_current_user()
    message = normalize_user_text_for_safety(request.form.get("message", ""), 500)
    media_file = request.files.get("media")
    has_media = bool(media_file and media_file.filename)

    if not message and not has_media:
        return redirect(url_for("openchat"))

    prepared_media = None
    if has_media:
        ok, result = validate_and_prepare_openchat_media(media_file)
        if not ok:
            return result, 400
        prepared_media = result

    if not message and prepared_media:
        message = "ส่งรูปภาพ/วิดีโอ"

    score, reason, status = analyze_safety_text(message, context="OPENCHAT")

    if status == "BLOCKED":
        alert_sent = safe_send_moderation_alert(
            "OPENCHAT_BLOCKED",
            "-",
            user,
            message,
            status,
            score,
            reason,
        )
        safe_add_activity_log(
            user["id"],
            "OPENCHAT_MESSAGE_BLOCKED",
            "openchat_messages",
            None,
            f"score={score}, alert={alert_sent}, reason={str(reason)[:200]}",
        )
        try:
            get_db().commit()
        except Exception:
            pass
        return reject_unsafe_text_response(score, reason)

    current_time = now_str()
    conn = get_db()
    try:
        ensure_openchat_media_tables(conn)
    except Exception:
        pass

    conn.execute(
        """
        INSERT INTO openchat_messages (
            user_id, message, status, moderation_score,
            moderation_reason, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user["id"], message, status, score, reason, current_time, current_time)
    )

    message_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    if prepared_media:
        save_prepared_openchat_media(prepared_media)

        conn.execute(
            """
            INSERT INTO openchat_media (
                message_id, user_id, file_name, original_name, file_type,
                mime_type, status, review_note, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'PENDING_REVIEW', '', ?, ?)
            """,
            (
                message_id,
                user["id"],
                prepared_media["file_name"],
                prepared_media["original_name"],
                prepared_media["file_type"],
                prepared_media["mime_type"],
                current_time,
                current_time,
            )
        )

        media_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

        add_activity_log(
            user["id"],
            "CREATE_OPENCHAT_MEDIA",
            "openchat_media",
            media_id,
            f"message_id={message_id}, type={prepared_media['file_type']}",
        )

        safe_send_moderation_alert(
            "OPENCHAT_MEDIA_PENDING_REVIEW",
            media_id,
            user,
            message,
            "PENDING_REVIEW",
            score,
            "มีรูปภาพ/วิดีโอใหม่ใน OpenChat รอ Admin ตรวจ",
        )

    add_activity_log(
        user["id"],
        "CREATE_OPENCHAT_MESSAGE",
        "openchat_messages",
        message_id,
        f"status={status}, score={score}",
    )

    if status in {"PENDING_REVIEW", "BLOCKED"} or int(score or 0) >= 35:
        alert_sent = safe_send_moderation_alert(
            "OPENCHAT",
            message_id,
            user,
            message,
            status,
            score,
            reason,
        )
        add_activity_log(
            user["id"],
            "DISCORD_OPENCHAT_ALERT_SENT" if alert_sent else "DISCORD_OPENCHAT_ALERT_FAILED",
            "openchat_messages",
            message_id,
            f"status={status}, score={score}",
        )

    conn.commit()

    return redirect(url_for("openchat"))


@app.route("/admin/openchat/messages/<int:message_id>/<action>", methods=["POST"])
@role_required("ADMIN")
def admin_update_openchat_message(message_id, action):
    action_map = {
        "approve": "ACTIVE",
        "review": "PENDING_REVIEW",
        "hide": "HIDDEN",
        "block": "BLOCKED",
    }

    admin = get_current_user()
    conn = get_db()

    message = conn.execute(
        "SELECT id FROM openchat_messages WHERE id = ?",
        (message_id,)
    ).fetchone()

    if not message:
        abort(404)

    if action == "delete":
        conn.execute("DELETE FROM openchat_messages WHERE id = ?", (message_id,))
        add_activity_log(admin["id"], "ADMIN_DELETE_OPENCHAT_MESSAGE", "openchat_messages", message_id, "deleted")
        conn.commit()
        return redirect(url_for("openchat"))

    if action not in action_map:
        abort(404)

    new_status = action_map[action]
    conn.execute(
        "UPDATE openchat_messages SET status = ?, updated_at = ? WHERE id = ?",
        (new_status, now_str(), message_id)
    )
    add_activity_log(admin["id"], f"ADMIN_OPENCHAT_{action.upper()}", "openchat_messages", message_id, f"status={new_status}")
    conn.commit()

    return redirect(url_for("openchat"))


@app.route("/job/<int:job_id>")
def job_detail_old(job_id):
    conn = get_db()
    job = conn.execute("SELECT id, title, location FROM job_posts WHERE id = ? AND status = 'ACTIVE'", (job_id,)).fetchone()
    if not job:
        abort(404)
    return redirect(url_for("job_detail", slug=job_slug(job)), code=301)


@app.route("/jobs/<slug>")
def job_detail(slug):
    job_id_match = re.search(r"-(\d+)$", slug)
    if not job_id_match:
        abort(404)
    job_id = int(job_id_match.group(1))
    conn = get_db()
    job = conn.execute(
        """
        SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.id = ?
        """,
        (job_id,)
    ).fetchone()

    if not job or job["status"] != "ACTIVE":
        abort(404)

    already_applied = False
    current = get_current_user()
    if current and current["role"] == "JOB_SEEKER":
        row = conn.execute(
            "SELECT id FROM applications WHERE job_seeker_id = ? AND job_post_id = ?",
            (current["id"], job_id)
        ).fetchone()
        already_applied = row is not None

    return render_template("job_detail.html", job=job, already_applied=already_applied)


@app.route("/job/<int:job_id>/apply", methods=["POST"])
@role_required("JOB_SEEKER")
def apply_job(job_id):
    user = get_current_user()
    message = request.form.get("message", "").strip()
    conn = get_db()

    job = conn.execute(
        "SELECT id FROM job_posts WHERE id = ? AND status = 'ACTIVE'",
        (job_id,)
    ).fetchone()

    if not job:
        abort(404)

    exists = conn.execute(
        "SELECT id FROM applications WHERE job_seeker_id = ? AND job_post_id = ?",
        (user["id"], job_id)
    ).fetchone()

    if not exists:
        current_time = now_str()
        conn.execute(
            """
            INSERT INTO applications (
                job_seeker_id, job_post_id, status, message, created_at, updated_at
            )
            VALUES (?, ?, 'PENDING', ?, ?, ?)
            """,
            (user["id"], job_id, message, current_time, current_time)
        )
        conn.commit()

    return redirect(url_for("job_detail_old", job_id=job_id))


@app.route("/job/<int:job_id>/report", methods=["POST"])
@role_required("JOB_SEEKER", "EMPLOYER")
def report_job(job_id):
    user = get_current_user()
    reason = request.form.get("reason", "").strip()
    if not reason:
        reason = "ประกาศน่าสงสัย"

    conn = get_db()
    job = conn.execute("SELECT * FROM job_posts WHERE id = ?", (job_id,)).fetchone()
    if not job:
        abort(404)

    exists = conn.execute(
        "SELECT id FROM reports WHERE job_post_id = ? AND reporter_id = ?",
        (job_id, user["id"])
    ).fetchone()

    if not exists:
        current_time = now_str()
        conn.execute(
            """
            INSERT INTO reports (
                job_post_id, reporter_id, reason, status, created_at, updated_at
            )
            VALUES (?, ?, ?, 'PENDING', ?, ?)
            """,
            (job_id, user["id"], reason, current_time, current_time)
        )
        new_report_count = int(job["report_count"] or 0) + 1
        new_status = "PENDING_AI_REVIEW" if new_report_count >= 3 else job["status"]

        conn.execute(
            """
            UPDATE job_posts
            SET report_count = ?,
                status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (new_report_count, new_status, current_time, job_id)
        )

        alert_sent = send_job_report_discord_alert(
            job,
            user,
            reason,
            new_report_count,
            new_status,
        )

        add_activity_log(user["id"], "REPORT_JOB", "job_posts", job_id, reason)
        add_activity_log(
            user["id"],
            "DISCORD_JOB_REPORT_ALERT_SENT" if alert_sent else "DISCORD_JOB_REPORT_ALERT_FAILED",
            "job_posts",
            job_id,
            f"reports={new_report_count}, status={new_status}",
        )
        conn.commit()

    return redirect(url_for("job_detail_old", job_id=job_id))


@app.route("/dashboard/employer")
@role_required("EMPLOYER")
def employer_dashboard():
    user = get_current_user()
    conn = get_db()
    profile = conn.execute(
        "SELECT * FROM employer_profiles WHERE user_id = ?",
        (user["id"],)
    ).fetchone()
    jobs = conn.execute(
        """
        SELECT *
        FROM job_posts
        WHERE employer_id = ?
        ORDER BY datetime(created_at) DESC, id DESC
        """,
        (user["id"],)
    ).fetchall()
    return render_template(
        "dashboard_employer.html",
        profile=profile,
        jobs=jobs,
        trust_level=get_trust_level(user["trust_score"]),
    )


@app.route("/dashboard/employer/jobs/new", methods=["GET", "POST"])
@role_required("EMPLOYER")
def employer_create_job():
    user = get_current_user()
    error = ""
    preview = None

    allowed, trust_error = can_post_job(user)
    if not allowed:
        return render_template("employer_job_form.html", error=trust_error, preview=None, locked=True)

    if request.method == "POST":
        blocked = enforce_security("job_post")
        if blocked:
            return blocked

        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        salary_range = request.form.get("salary_range", "").strip()
        location = request.form.get("location", "").strip()
        is_urgent = 1 if request.form.get("is_urgent") else 0

        if not title:
            error = "กรุณากรอกชื่อตำแหน่งงาน"
        elif len(description) < 40:
            error = "กรุณากรอกรายละเอียดงานอย่างน้อย 40 ตัวอักษร"
        else:
            score, reason, status = analyze_job_text(title, description)

            trust_score = int(user.get("trust_score", 50))
            if trust_score < 40 and status == "ACTIVE":
                status = "PENDING_AI_REVIEW"
                reason = reason + " | Trust Score ต่ำกว่า 40 จึงส่งให้ Admin ตรวจเพิ่ม"
            if trust_score < 25:
                status = "REJECTED"
                reason = reason + " | Trust Score ต่ำกว่า 25 ระบบไม่อนุญาตให้โพสต์งาน"

            current_time = now_str()
            conn = get_db()
            conn.execute(
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
                )
            )
            job_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            add_ai_decision_log(job_id, title, score, reason, status)
            add_activity_log(user["id"], "CREATE_JOB", "job_posts", job_id, f"status={status}, risk={score}")
            if status == "ACTIVE":
                adjust_trust_score(user["id"], 2)
            elif status == "REJECTED":
                adjust_trust_score(user["id"], -20)

            if status in {"PENDING_AI_REVIEW", "REJECTED"} or scam_risk_label(score) == "HIGH":
                alert_sent = send_job_risk_discord_alert(
                    job_id,
                    user,
                    title,
                    description,
                    salary_range,
                    location,
                    status,
                    score,
                    reason,
                )
                add_activity_log(
                    user["id"],
                    "DISCORD_JOB_RISK_ALERT_SENT" if alert_sent else "DISCORD_JOB_RISK_ALERT_FAILED",
                    "job_posts",
                    job_id,
                    f"status={status}, risk={score}",
                )

            conn.commit()
            return redirect(url_for("employer_dashboard"))

        preview = {
            "title": title,
            "description": description,
            "salary_range": salary_range,
            "location": location,
        }

    return render_template("employer_job_form.html", error=error, preview=preview)


@app.route("/admin/jobs/<int:job_id>/<action>", methods=["POST"])
@role_required("ADMIN")
def admin_update_job_status(job_id, action):
    status_map = {
        "approve": "ACTIVE",
        "reject": "REJECTED",
        "review": "PENDING_AI_REVIEW",
        "close": "CLOSED",
    }
    if action not in status_map:
        abort(404)

    admin = get_current_user()
    conn = get_db()
    job = conn.execute("SELECT * FROM job_posts WHERE id = ?", (job_id,)).fetchone()
    if not job:
        abort(404)

    new_status = status_map[action]
    conn.execute(
        "UPDATE job_posts SET status = ?, updated_at = ? WHERE id = ?",
        (new_status, now_str(), job_id)
    )

    if action == "approve":
        adjust_trust_score(job["employer_id"], 5)
    elif action == "reject":
        adjust_trust_score(job["employer_id"], -25)
    elif action == "close":
        adjust_trust_score(job["employer_id"], 1)

    add_activity_log(admin["id"], f"ADMIN_{action.upper()}_JOB", "job_posts", job_id, f"new_status={new_status}")
    conn.commit()
    return redirect(url_for("admin_moderation"))


@app.route("/admin/jobs/<int:job_id>/delete", methods=["POST"])
@role_required("ADMIN")
def admin_delete_job(job_id):
    admin = get_current_user()
    conn = get_db()
    job = conn.execute("SELECT * FROM job_posts WHERE id = ?", (job_id,)).fetchone()
    if not job:
        abort(404)

    conn.execute("DELETE FROM job_posts WHERE id = ?", (job_id,))
    adjust_trust_score(job["employer_id"], -10)
    add_activity_log(admin["id"], "ADMIN_DELETE_JOB", "job_posts", job_id, job["title"])
    conn.commit()
    return redirect(url_for("admin_moderation"))


@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@role_required("ADMIN")
def admin_ban_user(user_id):
    admin = get_current_user()
    reason = request.form.get("reason", "Admin banned user").strip()
    conn = get_db()
    conn.execute(
        "UPDATE users SET is_banned = 1, trust_score = 0, updated_at = ? WHERE id = ? AND role != 'ADMIN'",
        (now_str(), user_id)
    )
    conn.execute(
        "UPDATE job_posts SET status = 'REJECTED', updated_at = ? WHERE employer_id = ?",
        (now_str(), user_id)
    )
    add_activity_log(admin["id"], "ADMIN_BAN_USER", "users", user_id, reason)
    conn.commit()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/unban", methods=["POST"])
@role_required("ADMIN")
def admin_unban_user(user_id):
    admin = get_current_user()
    conn = get_db()
    conn.execute(
        "UPDATE users SET is_banned = 0, trust_score = 50, updated_at = ? WHERE id = ? AND role != 'ADMIN'",
        (now_str(), user_id)
    )
    add_activity_log(admin["id"], "ADMIN_UNBAN_USER", "users", user_id, "unban user")
    conn.commit()
    return redirect(url_for("admin_users"))


@app.route("/admin/moderation")
@role_required("ADMIN")
def admin_moderation():
    conn = get_db()
    q = request.args.get("q", "").strip().lower()
    status = request.args.get("status", "").strip()

    where = "WHERE 1=1"
    params = []
    if q:
        like = f"%{q}%"
        where += " AND (lower(job_posts.title) LIKE ? OR lower(job_posts.description) LIKE ? OR lower(employer_profiles.company_name) LIKE ?)"
        params.extend([like, like, like])
    if status:
        where += " AND job_posts.status = ?"
        params.append(status)

    jobs = conn.execute(
        f"""
        SELECT job_posts.*, employer_profiles.company_name, users.phone_number,
               users.trust_score, users.is_banned
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        LEFT JOIN users ON users.id = job_posts.employer_id
        {where}
        ORDER BY
            CASE job_posts.status
                WHEN 'PENDING_AI_REVIEW' THEN 1
                WHEN 'REJECTED' THEN 2
                WHEN 'ACTIVE' THEN 3
                WHEN 'CLOSED' THEN 4
                ELSE 5
            END,
            job_posts.ai_risk_score DESC,
            datetime(job_posts.created_at) DESC
        LIMIT 100
        """,
        tuple(params)
    ).fetchall()

    return render_template("admin_moderation.html", jobs=jobs, q=q, status=status)


@app.route("/admin/users")
@role_required("ADMIN")
def admin_users():
    conn = get_db()
    users = conn.execute(
        """
        SELECT users.*,
               employer_profiles.company_name,
               job_seeker_profiles.full_name,
               COUNT(job_posts.id) AS job_count
        FROM users
        LEFT JOIN employer_profiles ON employer_profiles.user_id = users.id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = users.id
        LEFT JOIN job_posts ON job_posts.employer_id = users.id
        GROUP BY users.id
        ORDER BY datetime(users.created_at) DESC, users.id DESC
        LIMIT 200
        """
    ).fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/admin/scam-center")
@role_required("ADMIN")
def admin_scam_center():
    conn = get_db()

    try:
        logs = conn.execute(
            """
            SELECT scam_scan_logs.*, job_posts.title
            FROM scam_scan_logs
            LEFT JOIN job_posts ON job_posts.id = scam_scan_logs.job_post_id
            ORDER BY datetime(scam_scan_logs.created_at) DESC, scam_scan_logs.id DESC
            LIMIT 100
            """
        ).fetchall()
    except sqlite3.OperationalError:
        logs = []

    jobs = conn.execute(
        """
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            users.trust_score
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        LEFT JOIN users ON users.id = job_posts.employer_id
        WHERE job_posts.is_government_news = 0
        ORDER BY job_posts.ai_risk_score DESC,
                 job_posts.report_count DESC,
                 datetime(job_posts.created_at) DESC
        LIMIT 100
        """
    ).fetchall()

    stats = {
        "high": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE ai_risk_score >= 75").fetchone()["count"],
        "medium": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE ai_risk_score >= 40 AND ai_risk_score < 75").fetchone()["count"],
        "low": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE ai_risk_score < 40 OR ai_risk_score IS NULL").fetchone()["count"],
        "pending": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'").fetchone()["count"],
    }

    return render_template("admin_scam_center.html", jobs=jobs, logs=logs, stats=stats)


@app.route("/admin/scam-center/run", methods=["POST"])
@role_required("ADMIN")
def admin_run_scam_scanner():
    admin = get_current_user()
    result = run_scam_scanner_now()
    add_activity_log(
        admin["id"],
        "ADMIN_RUN_SCAM_SCANNER",
        "job_posts",
        None,
        f"scanned={result['scanned']}, high={result['high']}, medium={result['medium']}, low={result['low']}, changed={result['changed']}",
    )
    get_db().commit()
    return redirect(url_for("admin_scam_center"))


@app.route("/admin/import-runs")
@role_required("ADMIN")
def admin_import_runs():
    conn = get_db()
    try:
        runs = conn.execute(
            """
            SELECT *
            FROM import_runs
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 100
            """
        ).fetchall()
    except sqlite3.OperationalError:
        runs = []
    return render_template("admin_import_runs.html", runs=runs)


@app.route("/admin/logs")
@role_required("ADMIN")
def admin_logs():
    conn = get_db()
    activity_logs = conn.execute(
        """
        SELECT activity_logs.*, users.phone_number, users.role
        FROM activity_logs
        LEFT JOIN users ON users.id = activity_logs.actor_id
        ORDER BY datetime(activity_logs.created_at) DESC, activity_logs.id DESC
        LIMIT 200
        """
    ).fetchall()

    ai_logs = conn.execute(
        """
        SELECT ai_decision_logs.*, job_posts.status
        FROM ai_decision_logs
        LEFT JOIN job_posts ON job_posts.id = ai_decision_logs.job_post_id
        ORDER BY datetime(ai_decision_logs.created_at) DESC, ai_decision_logs.id DESC
        LIMIT 200
        """
    ).fetchall()

    return render_template("admin_logs.html", activity_logs=activity_logs, ai_logs=ai_logs)


@app.route("/admin/trust")
@role_required("ADMIN")
def admin_trust_center():
    conn = get_db()
    users = conn.execute(
        """
        SELECT users.*,
               employer_profiles.company_name,
               employer_profiles.is_company_verified,
               job_seeker_profiles.full_name,
               COUNT(DISTINCT job_posts.id) AS job_count,
               COUNT(DISTINCT reports.id) AS reports_made
        FROM users
        LEFT JOIN employer_profiles ON employer_profiles.user_id = users.id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = users.id
        LEFT JOIN job_posts ON job_posts.employer_id = users.id
        LEFT JOIN reports ON reports.reporter_id = users.id
        GROUP BY users.id
        ORDER BY users.trust_score ASC, datetime(users.created_at) DESC
        LIMIT 300
        """
    ).fetchall()

    return render_template("admin_trust.html", users=users, get_trust_level=get_trust_level)


@app.route("/admin/users/<int:user_id>/trust/<action>", methods=["POST"])
@role_required("ADMIN")
def admin_update_trust(user_id, action):
    admin = get_current_user()
    deltas = {
        "increase": 10,
        "decrease": -10,
        "reset": 0,
        "verify": 20,
    }

    if action not in deltas:
        abort(404)

    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target or target["role"] == "ADMIN":
        abort(404)

    if action == "reset":
        conn.execute(
            "UPDATE users SET trust_score = 50, is_banned = 0, updated_at = ? WHERE id = ?",
            (now_str(), user_id)
        )
        add_activity_log(admin["id"], "ADMIN_RESET_TRUST", "users", user_id, "trust=50")
    else:
        adjust_trust_score(user_id, deltas[action])
        add_activity_log(admin["id"], f"ADMIN_TRUST_{action.upper()}", "users", user_id, f"delta={deltas[action]}")

    conn.commit()
    return redirect(url_for("admin_trust_center"))


@app.route("/admin/employers/<int:user_id>/verify", methods=["POST"])
@role_required("ADMIN")
def admin_verify_employer(user_id):
    admin = get_current_user()
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'EMPLOYER'", (user_id,)).fetchone()
    if not user:
        abort(404)

    conn.execute(
        "UPDATE employer_profiles SET is_company_verified = 1, updated_at = ? WHERE user_id = ?",
        (now_str(), user_id)
    )
    adjust_trust_score(user_id, 20)
    add_activity_log(admin["id"], "ADMIN_VERIFY_EMPLOYER", "users", user_id, "verified employer +20 trust")
    conn.commit()
    return redirect(url_for("admin_trust_center"))


@app.route("/admin/employers/<int:user_id>/unverify", methods=["POST"])
@role_required("ADMIN")
def admin_unverify_employer(user_id):
    admin = get_current_user()
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ? AND role = 'EMPLOYER'", (user_id,)).fetchone()
    if not user:
        abort(404)

    conn.execute(
        "UPDATE employer_profiles SET is_company_verified = 0, updated_at = ? WHERE user_id = ?",
        (now_str(), user_id)
    )
    adjust_trust_score(user_id, -20)
    add_activity_log(admin["id"], "ADMIN_UNVERIFY_EMPLOYER", "users", user_id, "unverified employer -20 trust")
    conn.commit()
    return redirect(url_for("admin_trust_center"))



def ensure_local_source_employer(conn, phone, company_name, tax_id, province):
    current_time = now_str()

    user = conn.execute(
        "SELECT id FROM users WHERE phone_number = ?",
        (phone,)
    ).fetchone()

    if user:
        employer_id = user["id"]
        conn.execute(
            """
            UPDATE users
            SET role = 'EMPLOYER',
                is_verified = 1,
                is_banned = 0,
                trust_score = 90,
                updated_at = ?
            WHERE id = ?
            """,
            (current_time, employer_id)
        )
    else:
        conn.execute(
            """
            INSERT INTO users (
                phone_number, password_hash, role, is_verified, is_banned,
                trust_score, created_at, updated_at
            )
            VALUES (?, ?, 'EMPLOYER', 1, 0, 90, ?, ?)
            """,
            (
                phone,
                hash_password(f"source-import-{province}-disabled-login"),
                current_time,
                current_time,
            )
        )
        employer_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    profile = conn.execute(
        "SELECT id FROM employer_profiles WHERE user_id = ?",
        (employer_id,)
    ).fetchone()

    if profile:
        conn.execute(
            """
            UPDATE employer_profiles
            SET company_name = ?,
                tax_id = ?,
                is_company_verified = 1,
                address = ?,
                website = '',
                updated_at = ?
            WHERE user_id = ?
            """,
            (company_name, tax_id, province, current_time, employer_id)
        )
    else:
        conn.execute(
            """
            INSERT INTO employer_profiles (
                user_id, company_name, tax_id, is_company_verified,
                address, website, created_at, updated_at
            )
            VALUES (?, ?, ?, 1, ?, '', ?, ?)
            """,
            (employer_id, company_name, tax_id, province, current_time, current_time)
        )

    return employer_id


def get_upper_central_job_import_data():
    return [
        {
            "province": "พิจิตร",
            "phone": "0996600001",
            "employer": "สำนักงานจัดหางานจังหวัดพิจิตร / แหล่งงานท้องถิ่น",
            "tax_id": "LOCAL-SOURCE-PHICHIT",
            "source_url": "https://www.doe.go.th/prd/phichit/news/param/site/96/cat/8/sub/0/pull/category/view/list-label",
            "jobs": [
                {
                    "title": "เจ้าหน้าที่บัญชี วิทยาลัยชุมชนพิจิตร",
                    "description": "ข้อมูลนำเข้าจากประกาศรับสมัครงานจังหวัดพิจิตร ตำแหน่งเจ้าหน้าที่บัญชี จำนวน 1 อัตรา ผู้สมัครควรตรวจสอบรายละเอียด วันรับสมัคร คุณสมบัติ และเอกสารที่ต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "พิจิตร",
                    "is_gov": 1,
                },
                {
                    "title": "พนักงานบัญชี จังหวัดพิจิตร",
                    "description": "ตำแหน่งงานว่างในพื้นที่จังหวัดพิจิตรจากข้อมูลสำนักงานจัดหางาน เหมาะสำหรับผู้มีพื้นฐานบัญชี เอกสาร และงานสำนักงาน กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "พิจิตร",
                    "is_gov": 0,
                },
                {
                    "title": "บาริสต้า จังหวัดพิจิตร",
                    "description": "ตำแหน่งงานบริการในพื้นที่จังหวัดพิจิตรจากข้อมูลตำแหน่งงานว่าง เหมาะสำหรับผู้สนใจงานร้านกาแฟ งานบริการลูกค้า และงานหน้าร้าน กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "พิจิตร",
                    "is_gov": 0,
                },
                {
                    "title": "พนักงานทั่วไป จังหวัดพิจิตร",
                    "description": "ตำแหน่งงานทั่วไปในพื้นที่จังหวัดพิจิตรจากข้อมูลสำนักงานจัดหางาน เหมาะสำหรับผู้ต้องการงานใกล้บ้านและพร้อมเริ่มงานตามเงื่อนไขนายจ้าง กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "พิจิตร",
                    "is_gov": 0,
                },
                {
                    "title": "ฝ่ายผลิต จังหวัดพิจิตร",
                    "description": "ตำแหน่งงานฝ่ายผลิตในพื้นที่จังหวัดพิจิตรจากข้อมูลตำแหน่งงานว่าง เหมาะสำหรับผู้สนใจงานโรงงาน งานผลิต และงานประจำพื้นที่ กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "พิจิตร",
                    "is_gov": 0,
                },
                {
                    "title": "พนักงานปฏิบัติการพิเศษ จังหวัดพิจิตร",
                    "description": "ตำแหน่งงานในพื้นที่จังหวัดพิจิตรจากข้อมูลสำนักงานจัดหางาน เหมาะสำหรับผู้ที่ต้องการงานประจำในพื้นที่และสามารถปฏิบัติงานตามเงื่อนไขนายจ้าง กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "พิจิตร",
                    "is_gov": 0,
                },
            ],
        },
        {
            "province": "พิษณุโลก",
            "phone": "0996500002",
            "employer": "สำนักงานจัดหางานจังหวัดพิษณุโลก / แหล่งงานท้องถิ่น",
            "tax_id": "LOCAL-SOURCE-PHITSANULOK",
            "source_url": "https://www.doe.go.th/prd/phitsanulok/news/param/site/161/cat/8/sub/0/pull/category/view/list-label",
            "jobs": [
                {
                    "title": "พนักงานทั่วไป โรงพยาบาลมหาวิทยาลัยนเรศวร",
                    "description": "ข้อมูลนำเข้าจากข่าวประชาสัมพันธ์ตำแหน่งงานในจังหวัดพิษณุโลก ตำแหน่งพนักงานทั่วไป ผู้สมัครควรตรวจสอบคุณสมบัติ วันรับสมัคร และเอกสารที่ต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "พิษณุโลก",
                    "is_gov": 1,
                },
                {
                    "title": "ลูกจ้างชั่วคราว โรงพยาบาลพุทธชินราช พิษณุโลก",
                    "description": "ประกาศตำแหน่งลูกจ้างชั่วคราวในพื้นที่จังหวัดพิษณุโลกจากแหล่งข้อมูลสำนักงานจัดหางาน ผู้สมัครควรตรวจสอบตำแหน่งย่อย คุณสมบัติ และกำหนดการที่ต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "พิษณุโลก",
                    "is_gov": 1,
                },
                {
                    "title": "พนักงานรักษาความปลอดภัย วิทยาลัยอาชีวศึกษาพิษณุโลก",
                    "description": "ข้อมูลประกาศรับสมัครพนักงานรักษาความปลอดภัยในพื้นที่จังหวัดพิษณุโลก เหมาะสำหรับผู้สนใจงานดูแลความปลอดภัยในหน่วยงาน กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "พิษณุโลก",
                    "is_gov": 1,
                },
                {
                    "title": "นักวิชาการสรรพสามิต สำนักงานสรรพสามิตภาคที่ 6",
                    "description": "ข้อมูลประกาศรับสมัครงานหน่วยงานในพื้นที่พิษณุโลก ตำแหน่งนักวิชาการสรรพสามิต ผู้สมัครควรตรวจสอบคุณสมบัติ เอกสาร และวันรับสมัครที่ต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "พิษณุโลก",
                    "is_gov": 1,
                },
                {
                    "title": "พนักงานทำความสะอาด สทบ.สาขาเขต 3",
                    "description": "ข้อมูลประกาศรับสมัครพนักงานทำความสะอาดในพื้นที่จังหวัดพิษณุโลกจากสำนักงานจัดหางาน เหมาะสำหรับผู้ต้องการงานบริการทั่วไป กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "พิษณุโลก",
                    "is_gov": 1,
                },
                {
                    "title": "ตำแหน่งงานว่างจังหวัดพิษณุโลก ประจำเดือนล่าสุด",
                    "description": "รวมตำแหน่งงานว่างจากสำนักงานจัดหางานจังหวัดพิษณุโลก ผู้สมัครสามารถตรวจสอบรายการตำแหน่งล่าสุด รายละเอียดนายจ้าง และเงื่อนไขการสมัครจากต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "พิษณุโลก",
                    "is_gov": 0,
                },
            ],
        },
        {
            "province": "กำแพงเพชร",
            "phone": "0996200003",
            "employer": "สำนักงานจัดหางานจังหวัดกำแพงเพชร / แหล่งงานท้องถิ่น",
            "tax_id": "LOCAL-SOURCE-KAMPHAENGPHET",
            "source_url": "https://www.doe.go.th/prd/kamphaengphet/news/param/site/139/cat/8/sub/0/pull/category/view/list-label",
            "jobs": [
                {
                    "title": "นักวิชาการแรงงาน สำนักงานจัดหางานจังหวัดกำแพงเพชร",
                    "description": "ข้อมูลประกาศตำแหน่งนักวิชาการแรงงาน สังกัดสำนักงานจัดหางานจังหวัดกำแพงเพชร ผู้สมัครควรตรวจสอบคุณสมบัติ กำหนดการ และรายละเอียดที่ต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "กำแพงเพชร",
                    "is_gov": 1,
                },
                {
                    "title": "นักวิชาการแรงงาน จิตวิทยาการแนะแนว จังหวัดกำแพงเพชร",
                    "description": "ข้อมูลประกาศรับสมัครตำแหน่งนักวิชาการแรงงานด้านจิตวิทยาการแนะแนวในจังหวัดกำแพงเพชร ผู้สมัครควรตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "กำแพงเพชร",
                    "is_gov": 1,
                },
                {
                    "title": "ตำแหน่งงานว่างจังหวัดกำแพงเพชร ประจำเดือนมกราคม 2569",
                    "description": "ข้อมูลตำแหน่งงานว่างประจำเดือนจากสำนักงานจัดหางานจังหวัดกำแพงเพชร ผู้สมัครควรตรวจสอบรายการตำแหน่ง นายจ้าง และเงื่อนไขการสมัครที่ต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "กำแพงเพชร",
                    "is_gov": 0,
                },
                {
                    "title": "ตำแหน่งงานว่างจังหวัดกำแพงเพชร ประจำเดือนธันวาคม 2568",
                    "description": "ข้อมูลตำแหน่งงานว่างประจำเดือนจากสำนักงานจัดหางานจังหวัดกำแพงเพชร เหมาะสำหรับผู้ต้องการหางานใกล้บ้านในพื้นที่ กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "กำแพงเพชร",
                    "is_gov": 0,
                },
                {
                    "title": "ตำแหน่งงานนัดพบแรงงาน @ ชากังราว",
                    "description": "ข้อมูลกิจกรรมตำแหน่งงานนัดพบแรงงานในจังหวัดกำแพงเพชร ผู้สมัครสามารถติดตามรายละเอียดนายจ้าง วันเวลา และตำแหน่งที่เปิดรับจากต้นทางก่อนเข้าร่วม",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "กำแพงเพชร",
                    "is_gov": 0,
                },
                {
                    "title": "ตำแหน่งงานว่างจังหวัดกำแพงเพชร ประจำเดือนพฤศจิกายน 2568",
                    "description": "ข้อมูลตำแหน่งงานว่างจากสำนักงานจัดหางานจังหวัดกำแพงเพชร ผู้สมัครควรตรวจสอบรายการตำแหน่งล่าสุดและรายละเอียดการสมัครจากต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "กำแพงเพชร",
                    "is_gov": 0,
                },
            ],
        },
        {
            "province": "นครสวรรค์",
            "phone": "0996000004",
            "employer": "สำนักงานจัดหางานจังหวัดนครสวรรค์ / แหล่งงานท้องถิ่น",
            "tax_id": "LOCAL-SOURCE-NAKHONSAWAN",
            "source_url": "https://www.doe.go.th/prd/nakhonsawan/news/param/site/146/cat/8/sub/0/pull/category/view/list-label",
            "jobs": [
                {
                    "title": "พนักงานวิเคราะห์นโยบายและแผน สำนักงานจังหวัดนครสวรรค์",
                    "description": "ข้อมูลประกาศรับสมัครพนักงานวิเคราะห์นโยบายและแผนในจังหวัดนครสวรรค์ ผู้สมัครควรตรวจสอบคุณสมบัติ กำหนดวันรับสมัคร และเอกสารที่ต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "นครสวรรค์",
                    "is_gov": 1,
                },
                {
                    "title": "เจ้าหน้าที่วิเคราะห์นโยบายและแผน สำนักงานทรัพยากรน้ำแห่งชาติ",
                    "description": "ข้อมูลประกาศรับสมัครพนักงานจ้างเหมาบริการ ตำแหน่งเจ้าหน้าที่วิเคราะห์นโยบายและแผน ค่าจ้างตามประกาศ ผู้สมัครควรตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "15,000 บาท",
                    "location": "นครสวรรค์",
                    "is_gov": 1,
                },
                {
                    "title": "งานดูแลรักษาความปลอดภัย อุทยานแห่งชาติแม่วงก์",
                    "description": "ข้อมูลประกาศรับสมัครพนักงานจ้างเอกชนดำเนินงาน ตำแหน่งงานดูแลรักษาความปลอดภัย ในพื้นที่นครสวรรค์ ผู้สมัครควรตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "9,000 บาท",
                    "location": "นครสวรรค์",
                    "is_gov": 1,
                },
                {
                    "title": "ตำแหน่งงานโรงพยาบาลสวรรค์ประชารักษ์",
                    "description": "ข้อมูลประกาศรับสมัครงานโรงพยาบาลสวรรค์ประชารักษ์หลายตำแหน่ง เช่น นักโภชนาการ นักกายภาพบำบัด นักเทคนิคการแพทย์ เภสัชกร และแพทย์แผนไทย กรุณาตรวจสอบรายละเอียดต้นทางก่อนสมัคร",
                    "salary": "ตรวจสอบตามประกาศ",
                    "location": "นครสวรรค์",
                    "is_gov": 1,
                },
                {
                    "title": "ตำแหน่งงานว่างจังหวัดนครสวรรค์ ประจำวันที่ 27 เมษายน 2569",
                    "description": "ข้อมูลตำแหน่งงานว่างรายวันจากสำนักงานจัดหางานจังหวัดนครสวรรค์ ผู้สมัครควรตรวจสอบรายการตำแหน่ง นายจ้าง และวิธีสมัครจากต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "นครสวรรค์",
                    "is_gov": 0,
                },
                {
                    "title": "ตำแหน่งงานว่างจังหวัดนครสวรรค์ ประจำเดือนกุมภาพันธ์ 2569",
                    "description": "ข้อมูลวารสาร/ตำแหน่งงานว่างประจำเดือนจากสำนักงานจัดหางานจังหวัดนครสวรรค์ ผู้สมัครควรตรวจสอบรายละเอียดรายการตำแหน่งจากต้นทางก่อนสมัคร",
                    "salary": "ตามโครงสร้างนายจ้าง",
                    "location": "นครสวรรค์",
                    "is_gov": 0,
                },
            ],
        },
    ]




def get_official_doe_source_for_location(location):
    location = str(location or "").strip()

    mapping = {
        "พิจิตร": "https://www.doe.go.th/prd/phichit/news/param/site/96/cat/8/sub/0/pull/category/view/list-label",
        "พิษณุโลก": "https://www.doe.go.th/prd/phitsanulok/news/param/site/161/cat/8/sub/0/pull/category/view/list-label",
        "กำแพงเพชร": "https://www.doe.go.th/prd/kamphaengphet/news/param/site/139/cat/8/sub/0/pull/category/view/list-label",
        "นครสวรรค์": "https://www.doe.go.th/prd/nakhonsawan/news/param/site/146/cat/8/sub/0/pull/category/view/list-label",
    }

    for province, url in mapping.items():
        if province in location:
            return url

    return "https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label"


def is_bad_or_placeholder_source_url(source_url):
    source_url = str(source_url or "").strip().lower()

    if not source_url:
        return True

    bad_patterns = [
        "google.com",
        "example.com",
        "facebook.com",
        "localhost",
        "127.0.0.1",
        "#",
    ]

    return any(pattern in source_url for pattern in bad_patterns)



# SAFE_SOURCE_URL_HELPER
def safe_source_url(source_url="", location="", title=""):
    raw = str(source_url or "").strip()

    if raw and not is_bad_or_placeholder_source_url(raw):
        return raw

    lookup_text = " ".join([
        str(location or "").strip(),
        str(title or "").strip(),
    ]).strip()

    try:
        return get_official_doe_source_for_location(lookup_text)
    except Exception:
        return "https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label"

def repair_job_source_urls_to_official():
    conn = get_db()
    current_time = now_str()

    rows = conn.execute(
        """
        SELECT id, title, location, source_url, is_government_news
        FROM job_posts
        WHERE source_url = ''
           OR lower(source_url) LIKE '%google.com%'
           OR lower(source_url) LIKE '%example.com%'
           OR lower(source_url) LIKE '%localhost%'
           OR lower(source_url) LIKE '%127.0.0.1%'
           OR source_url = '#'
        ORDER BY id ASC
        """
    ).fetchall()

    fixed = 0

    for row in rows:
        title = str(row["title"] or "")
        location = str(row["location"] or "")
        is_gov = int(row["is_government_news"] or 0)

        should_repair = False

        if is_gov == 1:
            should_repair = True

        if any(word in title for word in ["กรม", "แรงงาน", "จัดหางาน", "รับสมัคร", "ตำแหน่งงานว่าง", "ราชการ", "ลูกจ้าง"]):
            should_repair = True

        if any(province in location for province in ["พิจิตร", "พิษณุโลก", "กำแพงเพชร", "นครสวรรค์"]):
            should_repair = True

        if not should_repair:
            continue

        official_url = get_official_doe_source_for_location(location)

        conn.execute(
            """
            UPDATE job_posts
            SET source_url = ?,
                is_government_news = CASE
                    WHEN title LIKE '%ราชการ%'
                      OR title LIKE '%กรม%'
                      OR title LIKE '%แรงงาน%'
                      OR title LIKE '%จัดหางาน%'
                      OR title LIKE '%รับสมัคร%'
                      OR title LIKE '%ลูกจ้าง%'
                    THEN 1
                    ELSE is_government_news
                END,
                ai_risk_score = COALESCE(ai_risk_score, 0),
                ai_risk_reason = CASE
                    WHEN ai_risk_reason = '' OR ai_risk_reason IS NULL THEN 'official DOE source repaired'
                    ELSE ai_risk_reason || ' | official DOE source repaired'
                END,
                updated_at = ?
            WHERE id = ?
            """,
            (official_url, current_time, row["id"])
        )
        fixed += 1

    return fixed


def clean_doe_title(value):
    value = unescape(str(value or ""))
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)
    value = value.strip(" \n\t-–—•|")
    return value


def is_useful_doe_job_title(title):
    title = clean_doe_title(title)
    lowered = title.lower()

    if len(title) < 10:
        return False

    bad_terms = [
        "เข้าสู่ระบบ",
        "ค้นหา",
        "หน้าหลัก",
        "ศูนย์ข่าว",
        "ดาวน์โหลด",
        "ติดต่อ",
        "previous",
        "next",
        "first",
        "last",
        "rss",
        "read more",
        "ข่าวประชาสัมพันธ์ทั่วไป",
        "การจัดซื้อจัดจ้าง",
    ]

    if any(term in lowered for term in bad_terms):
        return False

    good_terms = [
        "ตำแหน่งงานว่าง",
        "รับสมัคร",
        "เปิดรับสมัคร",
        "ประกาศ",
        "พนักงาน",
        "ลูกจ้าง",
        "จ้างเหมา",
        "ราชการ",
        "งาน",
        "คนหางาน",
        "นัดพบแรงงาน",
    ]

    return any(term in title for term in good_terms)


def extract_doe_listing_items(source, limit=12):
    url = source["url"]
    headers = {
        "User-Agent": "JobBoardAI/1.0 (+https://jobboard-ai-app.onrender.com)",
        "Accept": "text/html,application/xhtml+xml",
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        html = response.text
    except Exception as exc:
        return [], str(exc)

    pairs = re.findall(
        r'<a[^>]+href=["\\\']([^"\\\']+)["\\\'][^>]*>(.*?)</a>',
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    items = []
    seen = set()

    for href, label_html in pairs:
        title = clean_doe_title(label_html)
        if not is_useful_doe_job_title(title):
            continue

        href = unescape(str(href or "")).strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            continue

        source_url = urljoin(url, href)

        key = (title, source_url)
        if key in seen:
            continue

        seen.add(key)
        items.append({
            "title": title[:180],
            "source_url": source_url,
            "province": source["province"],
            "employer": source["employer"],
            "priority": source.get("priority", 50),
        })

        if len(items) >= limit:
            break

    return items, ""


def ensure_doe_source_employer(conn, source):
    current_time = now_str()
    phone = normalize_phone(source["phone"])

    user = conn.execute(
        "SELECT id FROM users WHERE phone_number = ?",
        (phone,)
    ).fetchone()

    if user:
        employer_id = user["id"]
        conn.execute(
            """
            UPDATE users
            SET role = 'EMPLOYER',
                is_verified = 1,
                is_banned = 0,
                trust_score = 95,
                updated_at = ?
            WHERE id = ?
            """,
            (current_time, employer_id)
        )
    else:
        conn.execute(
            """
            INSERT INTO users (
                phone_number, password_hash, role, is_verified, is_banned,
                trust_score, created_at, updated_at
            )
            VALUES (?, ?, 'EMPLOYER', 1, 0, 95, ?, ?)
            """,
            (
                phone,
                hash_password(f"doe-source-{source['key']}-disabled-login"),
                current_time,
                current_time,
            )
        )
        employer_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    profile = conn.execute(
        "SELECT id FROM employer_profiles WHERE user_id = ?",
        (employer_id,)
    ).fetchone()

    if profile:
        conn.execute(
            """
            UPDATE employer_profiles
            SET company_name = ?,
                tax_id = ?,
                is_company_verified = 1,
                address = ?,
                website = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                source["employer"],
                source["tax_id"],
                source["province"],
                source["url"],
                current_time,
                employer_id,
            )
        )
    else:
        conn.execute(
            """
            INSERT INTO employer_profiles (
                user_id, company_name, tax_id, is_company_verified,
                address, website, created_at, updated_at
            )
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (
                employer_id,
                source["employer"],
                source["tax_id"],
                source["province"],
                source["url"],
                current_time,
                current_time,
            )
        )

    return employer_id


def import_latest_doe_news_to_db():
    conn = get_db()
    current_time = now_str()

    inserted = 0
    updated = 0
    scanned = 0
    errors = []

    for source in DOE_NEWS_SOURCES:
        employer_id = ensure_doe_source_employer(conn, source)
        items, error = extract_doe_listing_items(source, limit=12)

        if error:
            errors.append(f"{source['province']}: {error[:120]}")
            continue

        for item in items:
            scanned += 1
            title = item["title"]
            province = item["province"]
            source_url = item["source_url"]

            description = (
                f"ข่าวประกาศรับสมัครงาน/ตำแหน่งงานว่างจาก {source['employer']}\\n\\n"
                f"หัวข้อ: {title}\\n"
                f"พื้นที่: {province}\\n\\n"
                "ผู้หางานควรกดลิงก์ต้นทางเพื่อตรวจสอบรายละเอียดล่าสุด คุณสมบัติ วิธีสมัคร วันรับสมัคร และเอกสารที่ต้องใช้ก่อนสมัครทุกครั้ง"
            )

            exists = conn.execute(
                """
                SELECT id
                FROM job_posts
                WHERE source_url = ?
                LIMIT 1
                """,
                (source_url,)
            ).fetchone()

            if exists:
                conn.execute(
                    """
                    UPDATE job_posts
                    SET employer_id = ?,
                        title = ?,
                        description = ?,
                        salary_range = ?,
                        location = ?,
                        is_government_news = 1,
                        status = 'ACTIVE',
                        ai_risk_score = 0,
                        ai_risk_reason = 'DOE official live import',
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        employer_id,
                        title,
                        description,
                        "ตรวจสอบตามประกาศต้นทาง",
                        province,
                        current_time,
                        exists["id"],
                    )
                )
                updated += 1
            else:
                conn.execute(
                    """
                    INSERT INTO job_posts (
                        employer_id, title, description, salary_range, location,
                        is_government_news, source_url, status, ai_risk_score,
                        ai_risk_reason, report_count, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, 1, ?, 'ACTIVE', 0, 'DOE official live import', 0, ?, ?)
                    """,
                    (
                        employer_id,
                        title,
                        description,
                        "ตรวจสอบตามประกาศต้นทาง",
                        province,
                        source_url,
                        current_time,
                        current_time,
                    )
                )
                inserted += 1

    return {
        "inserted": inserted,
        "updated": updated,
        "scanned": scanned,
        "errors": errors,
    }


def import_upper_central_jobs_to_db():
    conn = get_db()
    current_time = now_str()

    inserted = 0
    updated = 0

    for group in get_upper_central_job_import_data():
        employer_id = ensure_local_source_employer(
            conn,
            group["phone"],
            group["employer"],
            group["tax_id"],
            group["province"],
        )

        for job in group["jobs"]:
            title = job["title"].strip()
            location = job["location"].strip()
            source_url = group["source_url"].strip()
            description = (
                job["description"].strip()
                + "\n\nที่มา: "
                + group["employer"]
                + "\nหมายเหตุ: โปรดตรวจสอบรายละเอียดล่าสุดจากแหล่งข้อมูลต้นทางก่อนสมัครทุกครั้ง"
            )

            exists = conn.execute(
                """
                SELECT id
                FROM job_posts
                WHERE title = ?
                  AND location = ?
                  AND source_url = ?
                LIMIT 1
                """,
                (title, location, source_url)
            ).fetchone()

            if exists:
                conn.execute(
                    """
                    UPDATE job_posts
                    SET employer_id = ?,
                        description = ?,
                        salary_range = ?,
                        is_government_news = ?,
                        status = 'ACTIVE',
                        ai_risk_score = 0,
                        ai_risk_reason = 'official/local source import',
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        employer_id,
                        description,
                        job["salary"],
                        int(job["is_gov"]),
                        current_time,
                        exists["id"],
                    )
                )
                updated += 1
            else:
                conn.execute(
                    """
                    INSERT INTO job_posts (
                        employer_id, title, description, salary_range, location,
                        is_government_news, source_url, status, ai_risk_score,
                        ai_risk_reason, report_count, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, 'official/local source import', 0, ?, ?)
                    """,
                    (
                        employer_id,
                        title,
                        description,
                        job["salary"],
                        location,
                        int(job["is_gov"]),
                        source_url,
                        current_time,
                        current_time,
                    )
                )
                inserted += 1

    return inserted, updated



def is_valid_cron_request():
    token = request.headers.get("X-Cron-Token", "").strip()
    if not token:
        token = request.args.get("token", "").strip()

    return bool(JOBBOARD_CRON_TOKEN) and bool(token) and hmac.compare_digest(token, JOBBOARD_CRON_TOKEN)


@app.route("/internal/cron/import-upper-central-jobs", methods=["GET", "POST"])
def cron_import_upper_central_jobs():
    if not is_valid_cron_request():
        abort(403)

    static_inserted, static_updated = import_upper_central_jobs_to_db()
    doe_result = import_latest_doe_news_to_db()
    source_fixed = repair_job_source_urls_to_official()

    inserted = int(static_inserted or 0) + int(doe_result.get("inserted", 0))
    updated = int(static_updated or 0) + int(doe_result.get("updated", 0))

    add_activity_log(
        None,
        "CRON_IMPORT_UPPER_CENTRAL_AND_DOE_NEWS",
        "job_posts",
        None,
        f"inserted={inserted}, updated={updated}, doe_scanned={doe_result.get('scanned', 0)}, source_fixed={source_fixed}, errors={len(doe_result.get('errors', []))}",
    )
    get_db().commit()

    send_discord_alert(
        "✅ Auto Import งาน/ข่าวกรมแรงงานสำเร็จ\n"
        f"Inserted: {inserted}\n"
        f"Updated: {updated}\n"
        f"DOE Scanned: {doe_result.get('scanned', 0)}\n"
        f"Source Links Fixed: {source_fixed}\n"
        "พื้นที่: พิจิตร / พิษณุโลก / กำแพงเพชร / นครสวรรค์ / กรมการจัดหางาน\n"
        f"เวลา: {now_str()}",
        username="JobBoard Auto Import Bot",
    )

    return jsonify({
        "ok": True,
        "inserted": inserted,
        "updated": updated,
        "doe_scanned": doe_result.get("scanned", 0),
        "doe_errors": doe_result.get("errors", []),
        "provinces": ["พิจิตร", "พิษณุโลก", "กำแพงเพชร", "นครสวรรค์"],
        "checked_at": now_str(),
    })




@app.route("/admin/doe-news/repair-sources")
@role_required("ADMIN")
def admin_repair_doe_source_links():
    admin = get_current_user()
    fixed = repair_job_source_urls_to_official()

    add_activity_log(
        admin["id"],
        "ADMIN_REPAIR_DOE_SOURCE_LINKS",
        "job_posts",
        None,
        f"fixed_sources={fixed}",
    )
    get_db().commit()

    send_discord_alert(
        "✅ ซ่อมลิงก์ต้นทางข่าวกรมแรงงานสำเร็จ\n"
        f"Fixed Sources: {fixed}\n"
        f"เวลา: {now_str()}",
        username="JobBoard DOE Import Bot",
    )

    return (
        "OK: repaired DOE source links<br>"
        f"Fixed Sources: {fixed}<br>"
        '<a href="/admin">Back to Admin</a> | '
        '<a href="/">Home</a> | '
        '<a href="/jobs">Jobs</a>'
    )


@app.route("/admin/doe-news/import-latest")
@role_required("ADMIN")
def admin_import_latest_doe_news():
    admin = get_current_user()
    result = import_latest_doe_news_to_db()
    fixed_sources = repair_job_source_urls_to_official()

    add_activity_log(
        admin["id"],
        "ADMIN_IMPORT_LATEST_DOE_NEWS",
        "job_posts",
        None,
        f"inserted={result['inserted']}, updated={result['updated']}, scanned={result['scanned']}, fixed_sources={fixed_sources}, errors={len(result['errors'])}",
    )
    get_db().commit()

    send_discord_alert(
        "✅ ดึงข่าวกรมแรงงาน/กรมการจัดหางานล่าสุดสำเร็จ\\n"
        f"Inserted: {result['inserted']}\\n"
        f"Updated: {result['updated']}\\n"
        f"Scanned: {result['scanned']}\\n"
        f"Fixed Sources: {fixed_sources}\n"
        f"Errors: {len(result['errors'])}",
        username="JobBoard DOE Import Bot",
    )

    return (
        "OK: imported latest DOE news<br>"
        f"Inserted: {result['inserted']}<br>"
        f"Updated: {result['updated']}<br>"
        f"Scanned: {result['scanned']}<br>"
        f"Fixed Sources: {fixed_sources}<br>"
        f"Errors: {len(result['errors'])}<br>"
        '<a href="/admin">Back to Admin</a> | '
        '<a href="/jobs">View Jobs</a> | '
        '<a href="/">Home</a>'
    )


@app.route("/admin/local-jobs/import-upper-central")
@role_required("ADMIN")
def admin_import_upper_central_jobs():
    admin = get_current_user()
    inserted, updated = import_upper_central_jobs_to_db()

    add_activity_log(
        admin["id"],
        "ADMIN_IMPORT_UPPER_CENTRAL_JOBS",
        "job_posts",
        None,
        f"inserted={inserted}, updated={updated}, provinces=phichit,phitsanulok,kamphaengphet,nakhonsawan",
    )
    get_db().commit()

    return (
        "OK: imported upper central local jobs<br>"
        f"Inserted: {inserted}<br>"
        f"Updated: {updated}<br>"
        '<a href="/admin">Back to Admin</a> | '
        '<a href="/jobs">View Jobs</a>'
    )


@app.route("/admin/government-news/fetch", methods=["POST"])
@role_required("ADMIN")
def admin_fetch_government_news():
    admin = get_current_user()
    result = run_auto_job_engine_demo()
    add_activity_log(
        admin["id"],
        "ADMIN_RUN_AUTO_JOB_ENGINE",
        "job_posts",
        None,
        f"inserted={result['inserted']}, updated={result['updated']}, skipped={result['skipped']}",
    )
    get_db().commit()
    return redirect(url_for("admin_dashboard"))



def format_file_size(num_bytes):
    try:
        num_bytes = int(num_bytes or 0)
    except (TypeError, ValueError):
        num_bytes = 0

    units = ["B", "KB", "MB", "GB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size = size / 1024

    return f"{num_bytes} B"


@app.route("/admin/system-health")
@role_required("ADMIN")
def admin_system_health():
    conn = get_db()

    db_exists = DB_PATH.exists()
    db_size = DB_PATH.stat().st_size if db_exists else 0

    env_checks = {
        "JOBBOARD_SECRET_KEY": bool(app.secret_key),
        "JOBBOARD_ADMIN_PHONE": bool(ADMIN_PHONE),
        "JOBBOARD_ADMIN_PASSWORD": bool(ADMIN_PASSWORD),
        "JOBBOARD_DATABASE_PATH": bool(os.environ.get("JOBBOARD_DATABASE_PATH", "").strip()),
        "JOBBOARD_SESSION_COOKIE_SECURE": app.config.get("SESSION_COOKIE_SECURE") is True,
        "DISCORD_SCAM_ALERT_WEBHOOK_URL": bool(DISCORD_SCAM_ALERT_WEBHOOK_URL),
        "JOBBOARD_CRON_TOKEN": bool(JOBBOARD_CRON_TOKEN),
    }

    stats = {
        "users": conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"],
        "active_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'").fetchone()["count"],
        "pending_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'").fetchone()["count"],
        "rejected_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'REJECTED'").fetchone()["count"],
        "reports": conn.execute("SELECT COUNT(*) AS count FROM reports").fetchone()["count"],
        "activity_logs": conn.execute("SELECT COUNT(*) AS count FROM activity_logs").fetchone()["count"],
    }

    health = {
        "checked_at": now_str(),
        "render_git_commit": os.environ.get("RENDER_GIT_COMMIT", "").strip(),
        "render_service_name": os.environ.get("RENDER_SERVICE_NAME", "").strip(),
        "render_external_url": os.environ.get("RENDER_EXTERNAL_URL", "").strip(),
        "database_path": str(DB_PATH),
        "database_exists": db_exists,
        "database_size": format_file_size(db_size),
        "env_checks": env_checks,
        "stats": stats,
    }

    return render_template("admin_system_health.html", health=health)



@app.route("/admin/openchat-media-review")
@role_required("ADMIN")
def admin_openchat_media_review():
    conn = get_db()
    try:
        ensure_openchat_media_tables(conn)
    except Exception:
        pass

    status_filter = request.args.get("status", "PENDING_REVIEW").strip().upper()

    where = "WHERE 1=1"
    params = []

    if status_filter in {"PENDING_REVIEW", "APPROVED", "REJECTED"}:
        where += " AND openchat_media.status = ?"
        params.append(status_filter)

    media_items = conn.execute(
        f"""
        SELECT
            openchat_media.*,
            openchat_messages.message,
            openchat_messages.status AS message_status,
            openchat_messages.moderation_score,
            openchat_messages.moderation_reason,
            users.phone_number,
            users.role,
            COALESCE(job_seeker_profiles.full_name, employer_profiles.company_name, '') AS author_name
        FROM openchat_media
        JOIN openchat_messages ON openchat_messages.id = openchat_media.message_id
        JOIN users ON users.id = openchat_media.user_id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = users.id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = users.id
        {where}
        ORDER BY datetime(openchat_media.created_at) DESC, openchat_media.id DESC
        LIMIT 200
        """,
        tuple(params)
    ).fetchall()

    stats = {
        "pending": conn.execute("SELECT COUNT(*) AS count FROM openchat_media WHERE status = 'PENDING_REVIEW'").fetchone()["count"],
        "approved": conn.execute("SELECT COUNT(*) AS count FROM openchat_media WHERE status = 'APPROVED'").fetchone()["count"],
        "rejected": conn.execute("SELECT COUNT(*) AS count FROM openchat_media WHERE status = 'REJECTED'").fetchone()["count"],
    }

    return render_template(
        "admin_openchat_media_review.html",
        media_items=media_items,
        stats=stats,
        status_filter=status_filter,
        mask_phone_for_display=mask_phone_for_display,
    )


@app.route("/admin/openchat-media-review/<int:media_id>/<action>", methods=["POST"])
@role_required("ADMIN")
def admin_update_openchat_media_review(media_id, action):
    admin = get_current_user()
    conn = get_db()

    media = conn.execute("SELECT * FROM openchat_media WHERE id = ?", (media_id,)).fetchone()
    if not media:
        abort(404)

    current_time = now_str()

    if action == "approve":
        conn.execute(
            """
            UPDATE openchat_media
            SET status = 'APPROVED',
                reviewed_by = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (admin["id"], current_time, media_id)
        )
        add_activity_log(admin["id"], "ADMIN_APPROVE_OPENCHAT_MEDIA", "openchat_media", media_id, f"message_id={media['message_id']}")

    elif action == "reject":
        conn.execute(
            """
            UPDATE openchat_media
            SET status = 'REJECTED',
                reviewed_by = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (admin["id"], current_time, media_id)
        )
        add_activity_log(admin["id"], "ADMIN_REJECT_OPENCHAT_MEDIA", "openchat_media", media_id, f"message_id={media['message_id']}")

    elif action == "delete":
        file_path = OPENCHAT_UPLOAD_DIR / media["file_name"]
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception:
            pass

        conn.execute("DELETE FROM openchat_media WHERE id = ?", (media_id,))
        add_activity_log(admin["id"], "ADMIN_DELETE_OPENCHAT_MEDIA", "openchat_media", media_id, f"message_id={media['message_id']}")

    else:
        abort(404)

    conn.commit()
    return redirect(url_for("admin_openchat_media_review"))


@app.route("/admin")
@role_required("ADMIN")
def admin_dashboard():
    conn = get_db()
    stats = {
        "pending_ai": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'").fetchone()["count"],
        "active": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'").fetchone()["count"],
        "rejected": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'REJECTED'").fetchone()["count"],
        "reports": conn.execute("SELECT COUNT(*) AS count FROM reports WHERE status = 'PENDING'").fetchone()["count"],
        "users": conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"],
    }
    latest_users = conn.execute(
        """
        SELECT id, phone_number, role, is_verified, trust_score, created_at
        FROM users
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 10
        """
    ).fetchall()

    review_jobs = conn.execute(
        """
        SELECT job_posts.*, employer_profiles.company_name
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.status IN ('PENDING_AI_REVIEW', 'REJECTED')
        ORDER BY job_posts.ai_risk_score DESC, datetime(job_posts.created_at) DESC
        LIMIT 20
        """
    ).fetchall()

    reports = conn.execute(
        """
        SELECT reports.*, job_posts.title
        FROM reports
        JOIN job_posts ON job_posts.id = reports.job_post_id
        WHERE reports.status = 'PENDING'
        ORDER BY datetime(reports.created_at) DESC
        LIMIT 20
        """
    ).fetchall()

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        latest_users=latest_users,
        review_jobs=review_jobs,
        reports=reports,
    )



@app.route("/job/<int:job_id>/generate-image")
def generate_image(job_id):
    from graphic_generator import generate_job_graphic

    conn = get_db()

    job = conn.execute(
        """
        SELECT
            job_posts.*,
            employer_profiles.company_name
        FROM job_posts
        LEFT JOIN employer_profiles
            ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.id = ?
        """,
        (job_id,)
    ).fetchone()

    if not job:
        return "Job not found", 404

    image_url = generate_job_graphic(job)
    return redirect(image_url)


@app.route("/jobs/location/<province>")
def jobs_by_province(province):
    conn = get_db()

    jobs = conn.execute(
        """
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles
            ON employer_profiles.user_id = job_posts.employer_id
        WHERE job_posts.status = 'ACTIVE'
          AND job_posts.location LIKE ?
        ORDER BY datetime(job_posts.created_at) DESC, job_posts.id DESC
        """,
        (f"%{province}%",)
    ).fetchall()

    return render_template(
        "jobs_by_province.html",
        jobs=jobs,
        province=province,
        total=len(jobs),
    )


@app.route("/job-seeker/post", methods=["GET", "POST"])
@role_required("JOB_SEEKER")
def job_seeker_post():
    user = get_current_user()
    conn = get_db()

    profile = conn.execute(
        "SELECT * FROM job_seeker_profiles WHERE user_id = ?",
        (user["id"],)
    ).fetchone()

    error = ""

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        headline = request.form.get("headline", "").strip()
        preferred_location = request.form.get("preferred_location", "").strip()
        bio = request.form.get("bio", "").strip()
        is_public = 1 if request.form.get("is_public") else 0
        is_urgent = 1 if request.form.get("is_urgent") else 0

        if not full_name:
            error = "กรุณากรอกชื่อ-นามสกุล"
        else:
            current_time = now_str()
            combined_bio = bio
            if preferred_location:
                combined_bio = f"พื้นที่ที่ต้องการทำงาน: {preferred_location}\n\n{bio}".strip()

            if profile:
                conn.execute(
                    """
                    UPDATE job_seeker_profiles
                    SET full_name = ?, headline = ?, resume_url = ?, is_public = ?, is_urgent = ?, updated_at = ?
                    WHERE user_id = ?
                    """,
                    (full_name, headline, combined_bio, is_public, is_urgent, current_time, user["id"])
                )
            else:
                conn.execute(
                    """
                    INSERT INTO job_seeker_profiles (
                        user_id, full_name, headline, resume_url, is_public, is_urgent, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (user["id"], full_name, headline, combined_bio, is_public, is_urgent, current_time, current_time)
                )

            conn.commit()
            return redirect(url_for("job_seeker_dashboard"))

    return render_template(
        "job_seeker_post.html",
        profile=profile,
        error=error
    )


@app.route("/messages")
@login_required
def inbox():
    user = get_current_user()
    conn = get_db()

    messages = conn.execute(
        """
        SELECT
            messages.*,
            sender.phone_number AS sender_phone,
            receiver.phone_number AS receiver_phone,
            applications.status AS application_status,
            job_posts.title AS job_title,
            job_seeker_profiles.full_name AS sender_full_name,
            employer_profiles.company_name AS sender_company_name
        FROM messages
        JOIN users AS sender ON sender.id = messages.sender_id
        JOIN users AS receiver ON receiver.id = messages.receiver_id
        LEFT JOIN applications ON applications.id = messages.application_id
        LEFT JOIN job_posts ON job_posts.id = applications.job_post_id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = sender.id
        LEFT JOIN employer_profiles ON employer_profiles.user_id = sender.id
        WHERE messages.receiver_id = ?
        ORDER BY datetime(messages.created_at) DESC, messages.id DESC
        """,
        (user["id"],)
    ).fetchall()

    conn.execute(
        "UPDATE messages SET is_read = 1 WHERE receiver_id = ?",
        (user["id"],)
    )
    conn.commit()

    return render_template("inbox.html", messages=messages)




@app.route("/api/messages/unread-count")
@login_required
def api_unread_messages_count():
    user = get_current_user()
    conn = get_db()
    count = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM messages
        WHERE receiver_id = ?
          AND is_read = 0
        """,
        (user["id"],)
    ).fetchone()["count"]

    return jsonify({"unread": int(count)})


@app.route("/messages/send", methods=["POST"])
@login_required
def send_message():
    blocked = enforce_security("message")
    if blocked:
        return blocked

    user = get_current_user()
    receiver_id = request.form.get("receiver_id", "").strip()
    application_id = request.form.get("application_id", "").strip()
    message = normalize_user_text_for_safety(request.form.get("message", ""), 1000)

    if not receiver_id or not message:
        return "กรุณากรอกข้อความให้ครบ", 400

    safety_score, safety_reason, safety_status = analyze_safety_text(message, context="PRIVATE_MESSAGE")
    if safety_status == "BLOCKED":
        alert_sent = safe_send_moderation_alert(
            "PRIVATE_MESSAGE_BLOCKED",
            "-",
            user,
            message,
            safety_status,
            safety_score,
            safety_reason,
        )
        safe_add_activity_log(
            user["id"],
            "PRIVATE_MESSAGE_BLOCKED",
            "messages",
            None,
            f"score={safety_score}, alert={alert_sent}, reason={str(safety_reason)[:200]}",
        )
        try:
            get_db().commit()
        except Exception:
            pass
        return reject_unsafe_text_response(safety_score, safety_reason)

    try:
        receiver_id_int = int(receiver_id)
    except ValueError:
        return "receiver_id ไม่ถูกต้อง", 400

    application_id_int = None
    if application_id:
        try:
            application_id_int = int(application_id)
        except ValueError:
            application_id_int = None

    conn = get_db()

    receiver = conn.execute(
        "SELECT id FROM users WHERE id = ? AND is_banned = 0",
        (receiver_id_int,)
    ).fetchone()
    if not receiver:
        return "ไม่พบผู้รับข้อความ", 404

    if application_id_int:
        application = conn.execute(
            """
            SELECT applications.*, job_posts.employer_id
            FROM applications
            JOIN job_posts ON job_posts.id = applications.job_post_id
            WHERE applications.id = ?
            """,
            (application_id_int,)
        ).fetchone()

        if not application:
            return "ไม่พบใบสมัคร", 404

        allowed_sender_ids = {application["job_seeker_id"], application["employer_id"]}
        if user["id"] not in allowed_sender_ids or receiver_id_int not in allowed_sender_ids:
            abort(403)

    conn.execute(
        """
        INSERT INTO messages (sender_id, receiver_id, application_id, message, is_read, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
        """,
        (user["id"], receiver_id_int, application_id_int, message, now_str())
    )
    conn.commit()

    return redirect(request.referrer or url_for("inbox"))


@app.route("/dashboard/employer/applications")
@role_required("EMPLOYER")
def employer_applications():
    user = get_current_user()
    conn = get_db()

    applications = conn.execute(
        """
        SELECT
            applications.*,
            users.phone_number AS applicant_phone,
            job_posts.title AS job_title,
            job_posts.location AS job_location,
            job_seeker_profiles.full_name,
            job_seeker_profiles.headline,
            job_seeker_profiles.resume_url
        FROM applications
        JOIN users ON users.id = applications.job_seeker_id
        JOIN job_posts ON job_posts.id = applications.job_post_id
        LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = applications.job_seeker_id
        WHERE job_posts.employer_id = ?
        ORDER BY datetime(applications.created_at) DESC, applications.id DESC
        """,
        (user["id"],)
    ).fetchall()

    return render_template("employer_applications.html", applications=applications)


@app.route("/dashboard/employer/applications/<int:application_id>/<action>", methods=["POST"])
@role_required("EMPLOYER")
def employer_update_application(application_id, action):
    status_map = {
        "review": "REVIEWING",
        "shortlist": "SHORTLISTED",
        "reject": "REJECTED",
        "hire": "HIRED",
    }

    if action not in status_map:
        abort(404)

    user = get_current_user()
    conn = get_db()

    application = conn.execute(
        """
        SELECT applications.*, job_posts.employer_id
        FROM applications
        JOIN job_posts ON job_posts.id = applications.job_post_id
        WHERE applications.id = ?
        """,
        (application_id,)
    ).fetchone()

    if not application or application["employer_id"] != user["id"]:
        abort(404)

    new_status = status_map[action]
    conn.execute(
        """
        UPDATE applications
        SET status = ?, updated_at = ?
        WHERE id = ?
        """,
        (new_status, now_str(), application_id)
    )
    conn.commit()

    return redirect(url_for("employer_applications"))


def normalize_page_path_for_stats(path):
    path = str(path or "/").split("?")[0].strip()
    if not path:
        path = "/"

    if path != "/" and path.endswith("/"):
        path = path[:-1]

    return path[:240]


def should_track_page_view():
    if request.method != "GET":
        return False

    if request.endpoint == "static":
        return False

    path = request.path or "/"

    ignored_prefixes = (
        "/static/",
        "/api/",
        "/media/",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/internal/",
    )

    return not path.startswith(ignored_prefixes)


def get_page_title_for_stats(path):
    path = normalize_page_path_for_stats(path)

    titles = {
        "/": "หน้าแรก",
        "/jobs": "งานใกล้ฉัน",
        "/urgent": "งานด่วน",
        "/openchat": "OpenChat",
        "/login": "เข้าสู่ระบบ",
        "/register": "สมัครใช้งาน",
        "/admin": "Admin Dashboard",
    }

    if path.startswith("/jobs/"):
        return "รายละเอียดงาน"
    if path.startswith("/admin"):
        return "Admin"
    if path.startswith("/dashboard"):
        return "Dashboard"
    if path.startswith("/messages"):
        return "ข้อความ"

    return titles.get(path, path)


def get_page_view_stats(path=None):
    try:
        conn = get_db()
        page_path = normalize_page_path_for_stats(path or request.path)

        row = conn.execute(
            "SELECT view_count FROM page_views WHERE page_path = ?",
            (page_path,)
        ).fetchone()

        total = conn.execute(
            "SELECT COALESCE(SUM(view_count), 0) AS total FROM page_views"
        ).fetchone()["total"]

        return {
            "path": page_path,
            "current": int(row["view_count"]) if row else 0,
            "total": int(total or 0),
        }
    except Exception:
        return {"path": path or "/", "current": 0, "total": 0}


@app.after_request
def track_page_view_response(response):
    try:
        if response.status_code == 200 and should_track_page_view():
            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type:
                conn = get_db()
                page_path = normalize_page_path_for_stats(request.path)
                page_title = get_page_title_for_stats(page_path)
                current_time = now_str()

                conn.execute(
                    """
                    INSERT INTO page_views (page_path, page_title, view_count, last_viewed_at, created_at)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(page_path) DO UPDATE SET
                        page_title = excluded.page_title,
                        view_count = page_views.view_count + 1,
                        last_viewed_at = excluded.last_viewed_at
                    """,
                    (page_path, page_title, current_time, current_time)
                )
                conn.commit()
    except Exception:
        pass

    return response


@app.cli.command("init-db")
def init_db_command():
    validate_runtime_config()
    with app.app_context():
        init_db()
    print(f"Initialized database at {DB_PATH}")


@app.before_request
def ensure_database_ready():
    if request.endpoint == "static":
        return None
    validate_runtime_config()
    init_db()
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
    token = request.args.get("token", "") or request.form.get("token", "")
    expected = os.getenv("JOBBOARD_CRON_TOKEN", "")

    if not expected or token != expected:
        abort(403)

    seeker_id = upsert_test_user_account(
        "0810000001",
        "JobSeeker@2026",
        "JOB_SEEKER",
        "ผู้หางาน ทดสอบ"
    )

    employer_id = upsert_test_user_account(
        "0810000002",
        "Employer@2026",
        "EMPLOYER",
        "บริษัท ทดสอบ งานใกล้บ้าน จำกัด"
    )

    fixed_sources = force_repair_demo_and_bad_sources()

    return {
        "ok": True,
        "job_seeker": {
            "phone": "0810000001",
            "password": "JobSeeker@2026",
            "otp": "123456",
            "user_id": seeker_id,
        },
        "employer": {
            "phone": "0810000002",
            "password": "Employer@2026",
            "otp": "123456",
            "user_id": employer_id,
        },
        "fixed_sources": fixed_sources,
    }



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



# NOTIFICATION_ROUTES_V1
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
