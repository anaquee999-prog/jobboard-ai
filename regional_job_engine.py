import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "instance" / "jobboard.db"

PROVINCES = ["พิจิตร", "พิษณุโลก", "นครสวรรค์"]


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connect_db():
    return sqlite3.connect(DB_PATH)


def ensure_system_employer(cursor):
    current_time = now_str()
    system_phone = "0899999999"
    system_tax_id = "AUTO_JOB_ENGINE_001"

    cursor.execute(
        "SELECT id FROM users WHERE phone_number = ?",
        (system_phone,)
    )
    user = cursor.fetchone()

    if user:
        employer_id = user[0]

        cursor.execute(
            "SELECT id FROM employer_profiles WHERE user_id = ?",
            (employer_id,)
        )
        profile = cursor.fetchone()

        if not profile:
            cursor.execute(
                """
                INSERT INTO employer_profiles (
                    user_id, company_name, tax_id, is_company_verified,
                    address, website, created_at, updated_at
                )
                VALUES (?, ?, ?, 1, ?, '', ?, ?)
                """,
                (
                    employer_id,
                    "ระบบดึงงานอัตโนมัติ",
                    system_tax_id,
                    "Thailand",
                    current_time,
                    current_time,
                )
            )

        return employer_id

    cursor.execute(
        """
        INSERT INTO users (
            phone_number, password_hash, role, is_verified, is_banned,
            trust_score, created_at, updated_at
        )
        VALUES (?, ?, 'EMPLOYER', 1, 0, 80, ?, ?)
        """,
        (
            system_phone,
            "auto-job-engine-demo-password",
            current_time,
            current_time,
        )
    )

    employer_id = cursor.lastrowid

    cursor.execute(
        """
        INSERT INTO employer_profiles (
            user_id, company_name, tax_id, is_company_verified,
            address, website, created_at, updated_at
        )
        VALUES (?, ?, ?, 1, ?, '', ?, ?)
        """,
        (
            employer_id,
            "ระบบดึงงานอัตโนมัติ",
            system_tax_id,
            "Thailand",
            current_time,
            current_time,
        )
    )

    return employer_id


def job_exists(cursor, title, location):
    cursor.execute(
        """
        SELECT id FROM job_posts
        WHERE title = ?
          AND location = ?
        LIMIT 1
        """,
        (title, location)
    )
    return cursor.fetchone() is not None


def insert_job(cursor, employer_id, job):
    current_time = now_str()

    cursor.execute(
        """
        INSERT INTO job_posts (
            employer_id,
            title,
            description,
            salary_range,
            location,
            is_government_news,
            source_url,
            status,
            ai_risk_score,
            ai_risk_reason,
            report_count,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (
            employer_id,
            job["title"],
            job["description"],
            job["salary_range"],
            job["location"],
            1,
            job["source_url"],
            "ACTIVE",
            5,
            "นำเข้าจาก Regional Job Engine / ความเสี่ยงต่ำ",
            current_time,
            current_time,
        )
    )


def demo_jobs():
    jobs = []

    for province in PROVINCES:
        jobs.extend([
            {
                "title": f"ข่าวรับสมัครงานราชการ จังหวัด{province}",
                "description": f"รวมข่าวรับสมัครงานราชการ งานลูกจ้าง และงานหน่วยงานภาครัฐในจังหวัด{province} ผู้สมัครควรตรวจสอบรายละเอียดจากหน่วยงานต้นทางก่อนสมัคร",
                "salary_range": "",
                "location": province,
                "source_url": f"https://www.google.com/search?q=รับสมัครงานราชการ+{province}",
            },
            {
                "title": f"รับสมัครลูกจ้างชั่วคราว จังหวัด{province}",
                "description": f"ประกาศรับสมัครลูกจ้างชั่วคราวในพื้นที่จังหวัด{province} เหมาะสำหรับผู้ที่ต้องการหางานใกล้บ้าน งานราชการ งานโรงพยาบาล งานเทศบาล และงานอบต.",
                "salary_range": "",
                "location": province,
                "source_url": f"https://www.google.com/search?q=ลูกจ้างชั่วคราว+{province}",
            },
            {
                "title": f"หางานบริษัทเอกชน จังหวัด{province}",
                "description": f"รวมตำแหน่งงานเอกชนในจังหวัด{province} เช่น งานธุรการ งานขาย งานคลังสินค้า งานบริการ และงานทั่วไปในพื้นที่",
                "salary_range": "ตามตกลง",
                "location": province,
                "source_url": f"https://www.google.com/search?q=หางาน+{province}",
            },
        ])

    return jobs


def run_engine():
    conn = connect_db()
    cursor = conn.cursor()

    employer_id = ensure_system_employer(cursor)

    total_new = 0
    total_skip = 0

    for job in demo_jobs():
        if job_exists(cursor, job["title"], job["location"]):
            total_skip += 1
            continue

        insert_job(cursor, employer_id, job)
        total_new += 1

    conn.commit()
    conn.close()

    print(f"✅ Import เสร็จ: {total_new} งานใหม่")
    print(f"⏭️ ข้ามงานซ้ำ: {total_skip} งาน")
    print("📍 จังหวัด: พิจิตร / พิษณุโลก / นครสวรรค์")


if __name__ == "__main__":
    run_engine()