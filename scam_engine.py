from dotenv import load_dotenv
load_dotenv()

import argparse
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / os.environ.get("JOBBOARD_DATABASE_PATH", "instance/jobboard.db")


HIGH_RISK_RULES = {
    "โอนเงินก่อน": 45,
    "ค่าประกัน": 40,
    "ค่าประกันอุปกรณ์": 50,
    "ค่าสมัคร": 35,
    "ค่ามัดจำ": 35,
    "ลงทุนก่อน": 45,
    "งานแพ็คของที่บ้าน": 35,
    "รายได้หลักแสน": 40,
    "ไม่ต้องสัมภาษณ์": 25,
    "แอดไลน์": 20,
    "ทักไลน์": 20,
    "ไลน์เท่านั้น": 25,
    "กำไรสูง": 25,
}

MEDIUM_RISK_RULES = {
    "งานออนไลน์": 15,
    "จ่ายรายวัน": 15,
    "ไม่ต้องมีประสบการณ์": 12,
    "รับทันที": 12,
    "รายได้ดี": 10,
    "ทำที่บ้าน": 10,
    "ไม่จำกัดวุฒิ": 8,
    "พาร์ทไทม์ออนไลน์": 14,
}

CONTACT_RISK_PATTERNS = [
    (r"line\s*id", 15, "พบช่องทาง LINE ID"),
    (r"ไลน์\s*id", 15, "พบช่องทาง LINE ID"),
    (r"@[a-zA-Z0-9_.-]{3,}", 12, "พบรูปแบบบัญชี @"),
    (r"0\d{8,9}", 8, "พบเบอร์โทรในรายละเอียด"),
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
        CREATE TABLE IF NOT EXISTS scam_scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_post_id INTEGER,
            old_status TEXT DEFAULT '',
            new_status TEXT DEFAULT '',
            risk_score INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'LOW',
            reasons TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_scam_scan_logs_job ON scam_scan_logs(job_post_id);
        CREATE INDEX IF NOT EXISTS idx_scam_scan_logs_created ON scam_scan_logs(created_at);
        """
    )
    conn.commit()


def analyze_scam_risk(title, description, salary_range="", location="", trust_score=50, report_count=0):
    text = f"{title} {description} {salary_range} {location}".lower()
    score = 0
    reasons = []

    if len(normalize_text(description)) < 80:
        score += 18
        reasons.append("รายละเอียดงานสั้นเกินไป")

    for term, points in HIGH_RISK_RULES.items():
        if term in text:
            score += points
            reasons.append(f"คำเสี่ยงสูง: {term}")

    for term, points in MEDIUM_RISK_RULES.items():
        if term in text:
            score += points
            reasons.append(f"คำควรตรวจเพิ่ม: {term}")

    for pattern, points, reason in CONTACT_RISK_PATTERNS:
        if re.search(pattern, text, flags=re.I):
            score += points
            reasons.append(reason)

    try:
        trust_score = int(trust_score)
    except (TypeError, ValueError):
        trust_score = 50

    try:
        report_count = int(report_count)
    except (TypeError, ValueError):
        report_count = 0

    if trust_score < 25:
        score += 35
        reasons.append("Trust Score ต่ำกว่า 25")
    elif trust_score < 40:
        score += 18
        reasons.append("Trust Score ต่ำกว่า 40")

    if report_count >= 5:
        score += 35
        reasons.append("มีรายงานจากผู้ใช้ตั้งแต่ 5 ครั้ง")
    elif report_count >= 3:
        score += 20
        reasons.append("มีรายงานจากผู้ใช้ตั้งแต่ 3 ครั้ง")
    elif report_count >= 1:
        score += 8
        reasons.append("มีรายงานจากผู้ใช้")

    score = max(0, min(100, score))

    if score >= 75:
        risk_level = "HIGH"
        status = "REJECTED"
    elif score >= 40:
        risk_level = "MEDIUM"
        status = "PENDING_AI_REVIEW"
    else:
        risk_level = "LOW"
        status = "ACTIVE"

    if not reasons:
        reasons.append("ไม่พบสัญญาณเสี่ยงเด่น")

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "status": status,
        "reasons": " | ".join(reasons[:10]),
    }


def scan_all_jobs(apply_changes=True):
    conn = get_db()
    ensure_tables(conn)

    jobs = conn.execute(
        """
        SELECT
            job_posts.*,
            users.trust_score
        FROM job_posts
        LEFT JOIN users ON users.id = job_posts.employer_id
        WHERE job_posts.is_government_news = 0
        ORDER BY datetime(job_posts.created_at) DESC, job_posts.id DESC
        """
    ).fetchall()

    scanned = 0
    high = 0
    medium = 0
    low = 0
    changed = 0
    current_time = now_str()

    for job in jobs:
        result = analyze_scam_risk(
            title=job["title"],
            description=job["description"],
            salary_range=job["salary_range"],
            location=job["location"],
            trust_score=job["trust_score"],
            report_count=job["report_count"],
        )

        old_status = job["status"]
        new_status = result["status"]

        if result["risk_level"] == "HIGH":
            high += 1
        elif result["risk_level"] == "MEDIUM":
            medium += 1
        else:
            low += 1

        if apply_changes:
            conn.execute(
                """
                UPDATE job_posts
                SET ai_risk_score = ?,
                    ai_risk_reason = ?,
                    status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    result["risk_score"],
                    result["reasons"],
                    new_status,
                    current_time,
                    job["id"],
                ),
            )

        if old_status != new_status:
            changed += 1

        conn.execute(
            """
            INSERT INTO scam_scan_logs (
                job_post_id, old_status, new_status, risk_score, risk_level,
                reasons, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job["id"],
                old_status,
                new_status,
                result["risk_score"],
                result["risk_level"],
                result["reasons"],
                current_time,
            ),
        )

        scanned += 1

    conn.commit()
    conn.close()

    return {
        "scanned": scanned,
        "high": high,
        "medium": medium,
        "low": low,
        "changed": changed,
    }


def main():
    parser = argparse.ArgumentParser(description="AI Anti-Scam Scanner")
    parser.add_argument("--dry-run", action="store_true", help="Scan only, do not apply status changes")
    args = parser.parse_args()

    print("Starting AI Anti-Scam Scanner...")
    print(f"Database: {DB_PATH}")

    result = scan_all_jobs(apply_changes=not args.dry_run)

    print("Finished.")
    print(f"Scanned: {result['scanned']}")
    print(f"High Risk: {result['high']}")
    print(f"Medium Risk: {result['medium']}")
    print(f"Low Risk: {result['low']}")
    print(f"Status Changed: {result['changed']}")


if __name__ == "__main__":
    main()
