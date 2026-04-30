import sqlite3
import re
from datetime import datetime

BAD_WORDS = [
    "เหี้ย","ควาย","สัส","fuck","shit"
]

SCAM_WORDS = [
    "โอนเงินก่อน",
    "ค่าประกัน",
    "ลงทุนก่อน",
    "รายได้สูง",
    "แอดไลน์",
    "ทักไลน์",
    "งานออนไลน์รายได้ดี"
]


def get_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_community(db_path):

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS community_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def contains_bad_word(text):

    text = text.lower()

    for word in BAD_WORDS:
        if word in text:
            return True

    return False


def scam_score(text):

    text = text.lower()

    score = 0

    for word in SCAM_WORDS:
        if word in text:
            score += 30

    if "line" in text:
        score += 10

    if "telegram" in text:
        score += 10

    return score


def analyze_post(content):

    if contains_bad_word(content):
        return "BLOCKED"

    score = scam_score(content)

    if score >= 60:
        return "BLOCKED"

    if score >= 30:
        return "PENDING"

    return "ACTIVE"


def create_post(db_path, user_id, content):

    status = analyze_post(content)

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    INSERT INTO community_posts (user_id, content, status, created_at)
    VALUES (?, ?, ?, ?)
    """, (
        user_id,
        content,
        status,
        datetime.utcnow()
    ))

    conn.commit()
    conn.close()

    return status


def get_posts(db_path):

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    SELECT
        p.id,
        p.content,
        p.status,
        p.created_at,
        u.phone as phone_number,
        u.name as author_name
    FROM community_posts p
    LEFT JOIN users u ON p.user_id = u.id
    WHERE p.status != 'BLOCKED'
    ORDER BY p.id DESC
    LIMIT 100
    """)

    posts = c.fetchall()

    conn.close()

    return posts