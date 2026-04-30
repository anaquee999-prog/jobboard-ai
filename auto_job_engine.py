from dotenv import load_dotenv
load_dotenv()

import argparse
import hashlib
import json
import os
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    requests = None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / os.environ.get("JOBBOARD_DATABASE_PATH", "instance/jobboard.db")

USER_AGENT = "NganKlaibaanBot/1.0 (+local-development)"
REQUEST_TIMEOUT = 20

SOURCES = [
    {
        "name": "OCSC",
        "url": "https://job.ocsc.go.th",
        "type": "smoke",
        "agency": "สำนักงาน ก.พ.",
    },
    {
        "name": "Sorbratchakarn",
        "url": "https://www.sorbratchakarn.com",
        "type": "smoke",
        "agency": "สอบราชการ",
    },
]

DEMO_JOBS = [
    {
        "title": "กรมตัวอย่าง รับสมัครพนักงานราชการทั่วไป",
        "agency": "กรมตัวอย่าง",
        "location": "ทั่วประเทศ",
        "salary_range": "",
        "description": "ประกาศรับสมัครพนักงานราชการทั่วไปจากระบบ Auto Job Engine ใช้สำหรับทดสอบการนำเข้าข่าวงานราชการแบบอัตโนมัติ",
        "source_url": "https://job.ocsc.go.th/demo/auto-job-001",
    },
    {
        "title": "สำนักงานตัวอย่าง รับสมัครเจ้าหน้าที่บริหารงานทั่วไป",
        "agency": "สำนักงานตัวอย่าง",
        "location": "กรุงเทพมหานคร",
        "salary_range": "",
        "description": "รับสมัครเจ้าหน้าที่บริหารงานทั่วไป ทำหน้าที่ประสานงานเอกสาร งานธุรการ และงานบริการประชาชน",
        "source_url": "https://job.ocsc.go.th/demo/auto-job-002",
    },
    {
        "title": "โรงพยาบาลรัฐตัวอย่าง รับสมัครนักวิชาการคอมพิวเตอร์",
        "agency": "โรงพยาบาลรัฐตัวอย่าง",
        "location": "นนทบุรี",
        "salary_range": "",
        "description": "รับสมัครนักวิชาการคอมพิวเตอร์เพื่อดูแลระบบสารสนเทศ ฐานข้อมูล และสนับสนุนงานเทคโนโลยีของหน่วยงาน",
        "source_url": "https://job.ocsc.go.th/demo/auto-job-003",
    },
    {
        "title": "เทศบาลตัวอย่าง รับสมัครเจ้าพนักงานธุรการ",
        "agency": "เทศบาลตัวอย่าง",
        "location": "เชียงใหม่",
        "salary_range": "",
        "description": "เปิดรับสมัครเจ้าพนักงานธุรการ ปฏิบัติงานเอกสาร ประสานงานราชการ และให้บริการประชาชนในพื้นที่",
        "source_url": "https://job.ocsc.go.th/demo/auto-job-004",
    },
]


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_text(value):
    return " ".join(str(value or "").split()).strip()


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_tables(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS import_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL,
            status TEXT NOT NULL,
            inserted_count INTEGER NOT NULL DEFAULT 0,
            updated_count INTEGER NOT NULL DEFAULT 0,
            skipped_count INTEGER NOT NULL DEFAULT 0,
            error_message TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_import_runs_created ON import_runs(created_at);
        """
    )
    conn.execute("UPDATE employer_profiles SET tax_id = NULL WHERE tax_id = ''")
    conn.commit()


def source_key(job):
    source_url = normalize_text(job.get("source_url"))
    if source_url:
        return source_url

    raw = "|".join([
        normalize_text(job.get("title")),
        normalize_text(job.get("agency")),
        normalize_text(job.get("location")),
    ])
    return "generated:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def ensure_government_employer(conn):
    phone = "0000000000"
    current_time = now_str()

    user = conn.execute(
        "SELECT id FROM users WHERE phone_number = ?",
        (phone,),
    ).fetchone()

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

    profile = conn.execute(
        "SELECT id FROM employer_profiles WHERE user_id = ?",
        (user_id,),
    ).fetchone()

    if not profile:
        conn.execute(
            """
            INSERT INTO employer_profiles (
                user_id, company_name, tax_id, is_company_verified,
                address, website, created_at, updated_at
            )
            VALUES (?, 'Government Job News', NULL, 1, 'Thailand', 'https://job.ocsc.go.th', ?, ?)
            """,
            (user_id, current_time, current_time),
        )

    return user_id


def safe_extract_jobs_from_html(html, base_url, agency):
    """
    Lightweight extractor สำหรับ MVP:
    - ดึง title จาก tag <title> และ heading บางส่วน
    - ใช้เป็น smoke/live แบบปลอดภัย ไม่ถี่
    - Production จริงควรเปลี่ยนเป็น Playwright + AI extraction
    """
    text = re.sub(r"<script.*?</script>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)

    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.S | re.I)
    page_title = normalize_text(re.sub(r"<.*?>", " ", title_match.group(1))) if title_match else "ข่าวรับสมัครงานราชการ"

    heading_matches = re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>", text, flags=re.S | re.I)
    titles = []
    for item in heading_matches[:8]:
        clean = normalize_text(re.sub(r"<.*?>", " ", item))
        if clean and len(clean) >= 8:
            titles.append(clean)

    if not titles:
        titles = [page_title]

    jobs = []
    for index, title in enumerate(titles[:5], start=1):
        jobs.append(
            {
                "title": title[:160],
                "agency": agency,
                "location": "ทั่วประเทศ",
                "salary_range": "",
                "description": f"ข่าวงานราชการจาก {agency} นำเข้าด้วย Auto Job Engine โปรดกดลิงก์ต้นทางเพื่อตรวจสอบรายละเอียดล่าสุด",
                "source_url": f"{base_url}#auto-{index}",
            }
        )

    return jobs


def fetch_source(source):
    if requests is None:
        raise RuntimeError("requests is not installed. Run: python -m pip install requests")

    response = requests.get(
        source["url"],
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    return safe_extract_jobs_from_html(response.text, source["url"], source["agency"])


def save_jobs_to_db(jobs, source_name="manual"):
    conn = get_db()
    ensure_tables(conn)
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
        salary_range = normalize_text(job.get("salary_range"))
        source_url = source_key(job)

        if not title or not description:
            skipped += 1
            continue

        full_description = description
        if agency:
            full_description = f"หน่วยงาน: {agency}\n\n{description}"
        if source_url:
            full_description = f"{full_description}\n\nลิงก์ต้นทาง: {source_url}"

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
                    salary_range = ?,
                    location = ?,
                    is_government_news = 1,
                    status = 'ACTIVE',
                    ai_risk_score = 0,
                    ai_risk_reason = 'government auto import',
                    updated_at = ?
                WHERE id = ?
                """,
                (title, full_description, salary_range, location, current_time, exists["id"]),
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
                VALUES (?, ?, ?, ?, ?, 1, ?, 'ACTIVE', 0, 'government auto import', 0, ?, ?)
                """,
                (
                    employer_id,
                    title,
                    full_description,
                    salary_range,
                    location,
                    source_url,
                    current_time,
                    current_time,
                ),
            )
            inserted += 1

    conn.execute(
        """
        INSERT INTO import_runs (
            source_name, status, inserted_count, updated_count, skipped_count,
            error_message, created_at
        )
        VALUES (?, 'SUCCESS', ?, ?, ?, '', ?)
        """,
        (source_name, inserted, updated, skipped, current_time),
    )

    conn.commit()
    conn.close()

    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
    }


def run_demo():
    return save_jobs_to_db(DEMO_JOBS, source_name="DEMO")


def run_live():
    all_jobs = []
    errors = []

    for source in SOURCES:
        try:
            print(f"Fetching {source['name']}...")
            jobs = fetch_source(source)
            print(f"  Found {len(jobs)} candidate jobs")
            all_jobs.extend(jobs)
            time.sleep(2)
        except Exception as exc:
            message = f"{source['name']}: {exc}"
            print(f"  ERROR {message}")
            errors.append(message)

    if not all_jobs:
        print("No live jobs found. Falling back to demo jobs.")
        all_jobs = DEMO_JOBS

    result = save_jobs_to_db(all_jobs, source_name="LIVE_WITH_FALLBACK" if errors else "LIVE")
    if errors:
        print("Live warnings:")
        for err in errors:
            print(f"- {err}")
    return result


def main():
    parser = argparse.ArgumentParser(description="Auto Job Engine for Government JobBoard")
    parser.add_argument("--demo", action="store_true", help="Import demo government jobs")
    parser.add_argument("--live", action="store_true", help="Try safe live import from public government/job sources")
    args = parser.parse_args()

    print("Starting Auto Job Engine...")
    print(f"Database: {DB_PATH}")

    if args.live:
        result = run_live()
    else:
        result = run_demo()

    print("Finished.")
    print(f"Inserted: {result['inserted']}")
    print(f"Updated: {result['updated']}")
    print(f"Skipped: {result['skipped']}")


if __name__ == "__main__":
    main()
