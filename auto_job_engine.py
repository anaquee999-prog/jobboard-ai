from dotenv import load_dotenv
load_dotenv()

import argparse
import os
import re
import sqlite3
from datetime import datetime
from html import unescape
from pathlib import Path
from urllib.parse import urljoin

import requests

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / os.environ.get("JOBBOARD_DATABASE_PATH", "instance/jobboard.db")
USER_AGENT = "JobBoardAI/1.0 (+https://jobboard-ai-app.onrender.com)"
REQUEST_TIMEOUT = 20

DOE_NEWS_SOURCES = [
    {"key": "doe-main", "province": "กรมการจัดหางาน", "phone": "0996101000", "employer": "กรมการจัดหางาน / ข่าวประกาศรับสมัครงาน", "tax_id": "DOE-SOURCE-MAIN", "url": "https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label"},
    {"key": "phichit", "province": "พิจิตร", "phone": "0996101001", "employer": "สำนักงานจัดหางานจังหวัดพิจิตร / ข่าวงานท้องถิ่น", "tax_id": "DOE-SOURCE-PHICHIT-LIVE", "url": "https://www.doe.go.th/prd/phichit/news/param/site/96/cat/8/sub/0/pull/category/view/list-label"},
    {"key": "phitsanulok", "province": "พิษณุโลก", "phone": "0996101002", "employer": "สำนักงานจัดหางานจังหวัดพิษณุโลก / ข่าวงานท้องถิ่น", "tax_id": "DOE-SOURCE-PHITSANULOK-LIVE", "url": "https://www.doe.go.th/prd/phitsanulok/news/param/site/161/cat/8/sub/0/pull/category/view/list-label"},
    {"key": "kamphaengphet", "province": "กำแพงเพชร", "phone": "0996101003", "employer": "สำนักงานจัดหางานจังหวัดกำแพงเพชร / ข่าวงานท้องถิ่น", "tax_id": "DOE-SOURCE-KAMPHAENGPHET-LIVE", "url": "https://www.doe.go.th/prd/kamphaengphet/news/param/site/139/cat/8/sub/0/pull/category/view/list-label"},
    {"key": "nakhonsawan", "province": "นครสวรรค์", "phone": "0996101004", "employer": "สำนักงานจัดหางานจังหวัดนครสวรรค์ / ข่าวงานท้องถิ่น", "tax_id": "DOE-SOURCE-NAKHONSAWAN-LIVE", "url": "https://www.doe.go.th/prd/nakhonsawan/news/param/site/146/cat/8/sub/0/pull/category/view/list-label"},
]


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_phone(value):
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_column(conn, table_name, column_name, definition):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing = {row["name"] for row in rows}
    if column_name not in existing:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def ensure_tables(conn):
    conn.executescript("""
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
    """)
    ensure_column(conn, "job_posts", "view_count", "INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def clean_title(value):
    value = unescape(str(value or ""))
    value = re.sub(r"<script.*?</script>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<style.*?</style>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value).strip(" \n\t-–—•|")
    return value


def is_useful_title(title):
    title = clean_title(title)
    lowered = title.lower()

    if len(title) < 8:
        return False

    bad_terms = ['สำนักงานบริหารแรงงานไทยไปต่างประเทศ', 'สำนักบริหารแรงงานต่างด้าว', 'เว็บลิงค์หน่วยงานภายนอก', 'เว็บลิงค์หน่วยงานภายใน', 'รายงานงบทดลองเบิกจ่าย', 'ข่าวประกาศ', 'กฏหมาย', 'กฎหมาย', 'แผนงาน', 'โครงการ และงบประมาณ', 'ยุทธศาสตร์', 'แผนปฏิบัติราชการ', 'แผนพัฒนาดิจิทัล', 'นโยบายกรม', 'นโยบายกระทรวง', 'อำนาจหน้าที่', 'ภารกิจของหน่วยงาน', 'โครงสร้างหน่วยงาน', 'ข้อมูลผู้บริหาร', 'ผู้บริหารกรม', 'ผลการปฏิบัติงาน', 'คู่มือตาม', 'เกี่ยวกับบริษัทจัดหางาน', 'บทความ/งานวิเคราะห์', 'วารสาร', 'Mobile App', 'ข้อมูลการไปทำงานต่างประเทศ', 'สถานการณ์ว่างงาน', 'ศูนย์บริหารข้อมูลตลาดแรงงาน', 'การทำงานในประเทศ', 'การทำงานของคนต่างด้าว', 'การไปทำงานต่างประเทศ', 'การเดินทางไปทำงานต่างประเทศ', 'แรงงานต่างด้าว']

    if any(term.lower() in lowered for term in bad_terms):
        return False

    good_terms = ['รับสมัคร', 'เปิดรับสมัคร', 'ประกาศรับสมัคร', 'ตำแหน่งงานว่าง', 'งานว่าง', 'นัดพบแรงงาน', 'ตลาดงาน', 'ลูกจ้าง', 'พนักงาน', 'จ้างเหมา', 'สอบคัดเลือก', 'สรรหา']

    return any(term in title for term in good_terms)

def extract_listing_items(source, limit=15):
    response = requests.get(source["url"], headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    html = response.text
    pairs = re.findall(r'<a[^>]+href=["\\\']([^"\\\']+)["\\\'][^>]*>(.*?)</a>', html, flags=re.I | re.S)
    items, seen = [], set()
    for href, label_html in pairs:
        title = clean_title(label_html)
        if not is_useful_title(title):
            continue
        href = unescape(str(href or "")).strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        source_url = urljoin(source["url"], href)
        key = (title, source_url)
        if key in seen:
            continue
        seen.add(key)
        items.append({"title": title[:180], "source_url": source_url, "province": source["province"], "employer": source["employer"]})
        if len(items) >= limit:
            break
    return items


def ensure_doe_employer(conn, source):
    current_time = now_str()
    phone = normalize_phone(source["phone"])
    user = conn.execute("SELECT id FROM users WHERE phone_number = ?", (phone,)).fetchone()
    if user:
        employer_id = user["id"]
        conn.execute("""
            UPDATE users
            SET role = 'EMPLOYER', is_verified = 1, is_banned = 0, trust_score = 95, updated_at = ?
            WHERE id = ?
        """, (current_time, employer_id))
    else:
        conn.execute("""
            INSERT INTO users (phone_number, password_hash, role, is_verified, is_banned, trust_score, created_at, updated_at)
            VALUES (?, 'DOE_SOURCE_DISABLED_LOGIN', 'EMPLOYER', 1, 0, 95, ?, ?)
        """, (phone, current_time, current_time))
        employer_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    profile = conn.execute("SELECT id FROM employer_profiles WHERE user_id = ?", (employer_id,)).fetchone()
    if profile:
        conn.execute("""
            UPDATE employer_profiles
            SET company_name = ?, tax_id = ?, is_company_verified = 1, address = ?, website = ?, updated_at = ?
            WHERE user_id = ?
        """, (source["employer"], source["tax_id"], source["province"], source["url"], current_time, employer_id))
    else:
        conn.execute("""
            INSERT INTO employer_profiles (user_id, company_name, tax_id, is_company_verified, address, website, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
        """, (employer_id, source["employer"], source["tax_id"], source["province"], source["url"], current_time, current_time))
    return employer_id


def save_items(conn, source, items):
    current_time = now_str()
    employer_id = ensure_doe_employer(conn, source)
    inserted = updated = skipped = 0
    for item in items:
        title = clean_title(item["title"])
        source_url = str(item["source_url"] or "").strip()
        if not title or not source_url or "example.com" in source_url.lower():
            skipped += 1
            continue
        description = (
            f"ข่าวประกาศรับสมัครงาน/ตำแหน่งงานว่างจาก {source['employer']}\n\n"
            f"หัวข้อ: {title}\nพื้นที่: {source['province']}\n\n"
            "ผู้หางานควรกดลิงก์ต้นทางเพื่อตรวจสอบรายละเอียดล่าสุด คุณสมบัติ วิธีสมัคร วันรับสมัคร และเอกสารที่ต้องใช้ก่อนสมัครทุกครั้ง"
        )
        exists = conn.execute("SELECT id FROM job_posts WHERE source_url = ? LIMIT 1", (source_url,)).fetchone()
        if exists:
            conn.execute("""
                UPDATE job_posts
                SET employer_id = ?, title = ?, description = ?, salary_range = 'ตรวจสอบตามประกาศต้นทาง', location = ?,
                    is_government_news = 1, status = 'ACTIVE', ai_risk_score = 0,
                    ai_risk_reason = 'DOE official live import', updated_at = ?
                WHERE id = ?
            """, (employer_id, title, description, source["province"], current_time, exists["id"]))
            updated += 1
        else:
            conn.execute("""
                INSERT INTO job_posts (
                    employer_id, title, description, salary_range, location, is_government_news, source_url,
                    status, ai_risk_score, ai_risk_reason, report_count, created_at, updated_at, view_count
                )
                VALUES (?, ?, ?, 'ตรวจสอบตามประกาศต้นทาง', ?, 1, ?, 'ACTIVE', 0, 'DOE official live import', 0, ?, ?, 0)
            """, (employer_id, title, description, source["province"], source_url, current_time, current_time))
            inserted += 1
    return inserted, updated, skipped


def remove_demo_jobs(conn):
    conn.execute("""
        DELETE FROM job_posts
        WHERE lower(COALESCE(ai_risk_reason, '')) LIKE '%demo%'
           OR lower(COALESCE(description, '')) LIKE '%demo%'
           OR title LIKE '%ตัวอย่าง%'
           OR lower(COALESCE(source_url, '')) LIKE '%example.com%'
           OR lower(COALESCE(source_url, '')) LIKE '%/demo/%'
           OR title IN ('Marketing Officer', 'Graphic Designer')
    """)
    for phone in ("0811111111", "0810000001", "0810000002"):
        conn.execute("DELETE FROM users WHERE phone_number = ? AND role != 'ADMIN'", (phone,))


def run_live():
    conn = get_db()
    ensure_tables(conn)
    remove_demo_jobs(conn)
    total_inserted = total_updated = total_skipped = scanned = 0
    errors = []
    for source in DOE_NEWS_SOURCES:
        try:
            print(f"Fetching {source['province']}...")
            items = extract_listing_items(source, limit=15)
            scanned += len(items)
            inserted, updated, skipped = save_items(conn, source, items)
            total_inserted += inserted
            total_updated += updated
            total_skipped += skipped
            print(f"  items={len(items)} inserted={inserted} updated={updated} skipped={skipped}")
        except Exception as exc:
            message = f"{source['province']}: {exc}"
            errors.append(message)
            print(f"  ERROR {message}")
    status = "SUCCESS" if not errors else "PARTIAL_SUCCESS"
    conn.execute("""
        INSERT INTO import_runs (source_name, status, inserted_count, updated_count, skipped_count, error_message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, ("DOE_LIVE_NO_DEMO", status, total_inserted, total_updated, total_skipped, "\n".join(errors)[:1000], now_str()))
    conn.commit()
    conn.close()
    return {"inserted": total_inserted, "updated": total_updated, "skipped": total_skipped, "scanned": scanned, "errors": errors}


def run_demo():
    return run_live()


def main():
    parser = argparse.ArgumentParser(description="Live DOE Auto Import for JobBoard")
    parser.add_argument("--live", action="store_true", help="Import live DOE jobs/news")
    parser.add_argument("--demo", action="store_true", help="Disabled; will run live import")
    args = parser.parse_args()
    print("Starting DOE live import. Demo fallback is disabled.")
    print(f"Database: {DB_PATH}")
    result = run_live()
    print("Finished.")
    print(f"Inserted: {result['inserted']}")
    print(f"Updated: {result['updated']}")
    print(f"Skipped: {result['skipped']}")
    print(f"Scanned: {result['scanned']}")
    print(f"Errors: {len(result['errors'])}")


if __name__ == "__main__":
    main()
