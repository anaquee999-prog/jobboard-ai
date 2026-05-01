from dotenv import load_dotenv
load_dotenv()

import os
import hmac
import io
import sqlite3
import secrets
import re
import zipfile
from functools import wraps
from datetime import datetime, timedelta
from pathlib import Path

import bcrypt
import requests
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

ADMIN_PHONE = os.environ.get("JOBBOARD_ADMIN_PHONE", "").strip()
ADMIN_PASSWORD = os.environ.get("JOBBOARD_ADMIN_PASSWORD", "").strip()
DISCORD_SCAM_ALERT_WEBHOOK_URL = os.environ.get("DISCORD_SCAM_ALERT_WEBHOOK_URL", "").strip()
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
            VALUES (?, ?, ?, 0, ?, ?, ?, ?)
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
        ORDER BY datetime(job_posts.created_at) DESC, job_posts.id DESC
        LIMIT 4
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
        elif len(password) < 8:
            error = "รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร"
        elif password != confirm_password:
            error = "รหัสผ่านไม่ตรงกัน"
        elif accept_terms != "on":
            error = "กรุณายอมรับนโยบายความเป็นส่วนตัวและข้อกำหนดการใช้งาน"
        elif role == "JOB_SEEKER" and not full_name:
            error = "กรุณากรอกชื่อผู้หางาน"
        elif role == "EMPLOYER" and not company_name:
            error = "กรุณากรอกชื่อบริษัท"
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
                return redirect(url_for("verify_otp"))

    return render_template("register.html", error=error)


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending = session.get("pending_register")
    if not pending:
        return redirect(url_for("register"))

    error = ""
    if request.method == "POST":
        blocked = enforce_security("otp")
        if blocked:
            return blocked

        otp = request.form.get("otp", "").strip()
        if otp != pending.get("otp"):
            error = "OTP ไม่ถูกต้อง สำหรับระบบทดสอบให้ใช้ 123456"
        else:
            conn = get_db()
            current_time = now_str()

            conn.execute(
                """
                INSERT INTO users (
                    phone_number, password_hash, role, is_verified, is_banned,
                    trust_score, created_at, updated_at
                )
                VALUES (?, ?, ?, 1, 0, 50, ?, ?)
                """,
                (
                    pending["phone_number"],
                    pending["password_hash"],
                    pending["role"],
                    current_time,
                    current_time,
                )
            )
            user_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

            if pending["role"] == "JOB_SEEKER":
                conn.execute(
                    """
                    INSERT INTO job_seeker_profiles (
                        user_id, full_name, headline, resume_url, is_public, created_at, updated_at
                    )
                    VALUES (?, ?, '', '', 0, ?, ?)
                    """,
                    (user_id, pending["full_name"], current_time, current_time)
                )
            elif pending["role"] == "EMPLOYER":
                conn.execute(
                    """
                    INSERT INTO employer_profiles (
                        user_id, company_name, tax_id, is_company_verified,
                        address, website, created_at, updated_at
                    )
                    VALUES (?, ?, ?, 0, '', '', ?, ?)
                    """,
                    (
                        user_id,
                        pending["company_name"],
                        f"EMP-{user_id}-{pending['phone_number']}",
                        current_time,
                        current_time,
                    )
                )

            conn.commit()
            session.pop("pending_register", None)
            session.clear()
            session.permanent = True
            session["user_id"] = user_id
            session["role"] = pending["role"]
            return redirect(url_for("dashboard"))

    return render_template("verify_otp.html", error=error, pending=pending)


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



@app.route("/openchat")
@login_required
def openchat():
    user = get_current_user()
    conn = get_db()

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

    return render_template(
        "openchat.html",
        messages=messages,
        current_user=user,
    )


@app.route("/openchat/send", methods=["POST"])
@login_required
def openchat_send():
    blocked = enforce_security("openchat")
    if blocked:
        return blocked

    user = get_current_user()
    message = normalize_user_text_for_safety(request.form.get("message", ""), 500)

    if not message:
        return redirect(url_for("openchat"))

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
    add_activity_log(user["id"], "CREATE_OPENCHAT_MESSAGE", "openchat_messages", message_id, f"status={status}, score={score}")

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
                    ai_risk_reason, report_count, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 0, '', ?, ?, ?, 0, ?, ?)
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

    inserted, updated = import_upper_central_jobs_to_db()

    add_activity_log(
        None,
        "CRON_IMPORT_UPPER_CENTRAL_JOBS",
        "job_posts",
        None,
        f"inserted={inserted}, updated={updated}, provinces=phichit,phitsanulok,kamphaengphet,nakhonsawan",
    )
    get_db().commit()

    send_discord_alert(
        "? Auto Import ??? 4 ??????? ??????\n"
        f"Inserted: {inserted}\n"
        f"Updated: {updated}\n"
        "???????: ?????? / ???????? / ????????? / ?????????\n"
        f"????: {now_str()}",
        username="JobBoard Auto Import Bot",
    )

    return jsonify({
        "ok": True,
        "inserted": inserted,
        "updated": updated,
        "provinces": ["??????", "????????", "?????????", "?????????"],
        "checked_at": now_str(),
    })


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
                    SET full_name = ?, headline = ?, resume_url = ?, is_public = ?, updated_at = ?
                    WHERE user_id = ?
                    """,
                    (full_name, headline, combined_bio, is_public, current_time, user["id"])
                )
            else:
                conn.execute(
                    """
                    INSERT INTO job_seeker_profiles (
                        user_id, full_name, headline, resume_url, is_public, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (user["id"], full_name, headline, combined_bio, is_public, current_time, current_time)
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


if __name__ == "__main__":
    validate_runtime_config()
    with app.app_context():
        init_db()
    app.run(debug=os.environ.get("JOBBOARD_DEBUG", "0") == "1")
