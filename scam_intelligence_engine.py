import sqlite3
import re


SCAM_PATTERNS = [
    r"โอนเงินก่อน",
    r"ค่าประกัน",
    r"ลงทุนก่อน",
    r"รายได้สูง.*ง่าย",
    r"ไม่ต้องสัมภาษณ์",
    r"แอดไลน์",
    r"ทักไลน์",
    r"telegram",
    r"whatsapp"
]


def get_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def calculate_text_risk(text):

    text = text.lower()

    score = 0

    for pattern in SCAM_PATTERNS:
        if re.search(pattern, text):
            score += 20

    if "เงินด่วน" in text:
        score += 15

    if "ทำงานที่บ้าน" in text:
        score += 10

    return score


def calculate_employer_risk(trust_score):

    if trust_score < 20:
        return 40

    if trust_score < 50:
        return 20

    return 0


def calculate_report_risk(report_count):

    if report_count >= 5:
        return 40

    if report_count >= 3:
        return 20

    return 0


def risk_level(score):

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def analyze_job(db_path, job_title, job_description, employer_id):

    conn = get_db(db_path)
    c = conn.cursor()

    text_score = calculate_text_risk(job_title + " " + job_description)

    c.execute("""
    SELECT score FROM trust_scores
    WHERE user_id=?
    """, (employer_id,))

    row = c.fetchone()

    trust_score = row["score"] if row else 50

    employer_score = calculate_employer_risk(trust_score)

    c.execute("""
    SELECT COUNT(*) as reports
    FROM job_reports
    WHERE employer_id=?
    """, (employer_id,))

    report_row = c.fetchone()

    report_score = calculate_report_risk(report_row["reports"])

    total = text_score + employer_score + report_score

    level = risk_level(total)

    conn.close()

    return total, level
