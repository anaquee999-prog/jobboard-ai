from dotenv import load_dotenv
load_dotenv()

import argparse
import hashlib
import os
import sqlite3
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / os.environ.get("JOBBOARD_DATABASE_PATH", "instance/jobboard.db")

DEMO_JOBS = [
    {
        "title": "รับสมัครพนักงานราชการทั่วไป",
        "agency": "สำนักงาน ก.พ.",
        "location": "ทั่วประเทศ",
        "closing_date": "",
        "description": "ข่าวรับสมัครงานราชการตัวอย่างจากระบบ Government Job Scraper ใช้สำหรับทดสอบการบันทึกข่าวราชการลง JobBoard",
        "source_url": "https://job.ocsc.go.th/demo/government-job-001",
    },
    {
        "title": "รับสมัครเจ้าหน้าที่บริหารงานทั่วไป",
        "agency": "หน่วยงานราชการตัวอย่าง",
        "location": "กรุงเทพมหานคร",
        "closing_date": "",
        "description": "ประกาศรับสมัครเจ้าหน้าที่บริหารงานทั่วไป รายละเอียดเป็นข้อมูลทดสอบเพื่อยืนยันระบบ deduplication และการแสดงผลหน้า jobs",
        "source_url": "https://job.ocsc.go.th/demo/government-job-002",
    },
    {
        "title": "รับสมัครนักวิชาการคอมพิวเตอร์",
        "agency": "กรมตัวอย่าง",
        "location": "นนทบุรี",
        "closing_date": "",
        "description": "ตำแหน่งนักวิชาการคอมพิวเตอร์ สำหรับทดสอบการนำเข้าข่าวราชการอัตโนมัติและการสร้าง SEO URL",
        "source_url": "https://job.ocsc.go.th/demo/government-job-003",
    },
]


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_text(value):
    return " ".join(str(value or "").split()).strip()


def source_key(job):
    source_url = normalize_text(job.get("source_url"))
    if source_url:
        return source_url

    raw = "|".join([
        normalize_text(job.get("title")),
        normalize_text(job.get("agency")),
        normalize_text(job.get("closing_date")),
    ])
    return "generated:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_government_employer(conn):
    phone = "0000000000"
    current_time = now_str()

    user = conn.execute("SELECT id FROM users WHERE phone_number = ?", (phone,)).fetchone()
    if user:
        user_id = user["id"]
    else:
        conn.execute(
            """
            INSERT INTO users (
                phone_number, password_hash, role, is_verified, is_banned,
                trust_score, created_at, updated_at
            )
            VALUES (?, ?, 'EMPLOYER', 1, 0, 100, ?, ?)
            """,
            (phone, "SYSTEM_ACCOUNT_NO_LOGIN", current_time, current_time),
        )
        user_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    profile = conn.execute("SELECT id FROM employer_profiles WHERE user_id = ?", (user_id,)).fetchone()
    if not profile:
        conn.execute(
            """
            INSERT INTO employer_profiles (
                user_id, company_name, tax_id, is_company_verified,
                address, website, created_at, updated_at
            )
            VALUES (?, 'Government Job News', '', 1, 'Thailand', 'https://job.ocsc.go.th', ?, ?)
            """,
            (current_time, current_time),
        )

    return user_id


def save_jobs_to_db(jobs):
    conn = get_db()
    employer_id = ensure_government_employer(conn)

    inserted = 0
    updated = 0
    skipped = 0
    current_time = now_str()

    for job in jobs:
        title = normalize_text(job.get("title"))
        description = normalize_text(job.get("description"))
        agency = normalize_text(job.get("agency"))
        location = normalize_text(job.get("location")) or "ทั่วประเทศ"
        source_url = source_key(job)

        if not title or not description:
            skipped += 1
            continue

        full_description = description
        if agency:
            full_description = f"หน่วยงาน: {agency}\n\n{description}"

        exists = conn.execute(
            "SELECT id FROM job_posts WHERE source_url = ? LIMIT 1",
            (source_url,),
        ).fetchone()

        if exists:
            conn.execute(
                """
                UPDATE job_posts
                SET title = ?,
                    description = ?,
                    location = ?,
                    is_government_news = 1,
                    status = 'ACTIVE',
                    ai_risk_score = 0,
                    ai_risk_reason = 'government source',
                    updated_at = ?
                WHERE id = ?
                """,
                (title, full_description, location, current_time, exists["id"]),
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
                VALUES (?, ?, ?, '', ?, 1, ?, 'ACTIVE', 0, 'government source', 0, ?, ?)
                """,
                (employer_id, title, full_description, location, source_url, current_time, current_time),
            )
            inserted += 1

    conn.commit()
    conn.close()
    return {"inserted": inserted, "updated": updated, "skipped": skipped}


def scrape_ocsc_basic():
    use_live = os.environ.get("GOV_SCRAPER_LIVE", "0") == "1"

    if not use_live:
        return DEMO_JOBS

    if requests is None:
        raise RuntimeError("requests is not installed. Run: pip install requests")

    url = "https://job.ocsc.go.th"
    response = requests.get(url, timeout=20, headers={"User-Agent": "JobBoardBot/1.0"})
    response.raise_for_status()

    return [
        {
            "title": "ข่าวรับสมัครงานราชการจาก job.ocsc.go.th",
            "agency": "สำนักงาน ก.พ.",
            "location": "ทั่วประเทศ",
            "closing_date": "",
            "description": "ระบบเชื่อมต่อ job.ocsc.go.th ได้สำเร็จ โปรดปรับ selector/live extractor ใน production",
            "source_url": url,
        }
    ]


def main():
    parser = argparse.ArgumentParser(description="Government Job Scraper for JobBoard")
    parser.add_argument("--demo", action="store_true", help="Use demo government jobs")
    parser.add_argument("--live", action="store_true", help="Try live lightweight fetch")
    args = parser.parse_args()

    if args.live:
        os.environ["GOV_SCRAPER_LIVE"] = "1"

    print("Starting Government Job Scraper...")
    print(f"Database: {DB_PATH}")

    jobs = DEMO_JOBS if args.demo else scrape_ocsc_basic()
    result = save_jobs_to_db(jobs)

    print("Finished.")
    print(f"Inserted: {result['inserted']}")
    print(f"Updated: {result['updated']}")
    print(f"Skipped: {result['skipped']}")


if __name__ == "__main__":
    main()
