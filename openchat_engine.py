import sqlite3
from datetime import datetime


BAD_WORDS = [
    "เหี้ย", "ควาย", "สัส", "ไอ้สัส", "fuck", "shit"
]

SCAM_WORDS = [
    "โอนเงินก่อน",
    "ค่าประกัน",
    "ลงทุนก่อน",
    "รายได้สูง",
    "รายได้ดีมาก",
    "ไม่ต้องสัมภาษณ์",
    "แอดไลน์",
    "ทักไลน์",
    "telegram",
    "whatsapp"
]


def get_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_openchat(db_path):
    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS openchat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        risk_level TEXT DEFAULT 'LOW',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def analyze_message(message):
    text = (message or "").lower().strip()

    if not text:
        return "BLOCKED", "HIGH"

    for word in BAD_WORDS:
        if word in text:
            return "BLOCKED", "HIGH"

    score = 0

    for word in SCAM_WORDS:
        if word in text:
            score += 25

    if "line" in text:
        score += 10

    if len(text) > 500:
        score += 30

    if score >= 60:
        return "PENDING", "HIGH"

    if score >= 30:
        return "PENDING", "MEDIUM"

    return "ACTIVE", "LOW"


def create_message(db_path, user_id, message):
    status, risk_level = analyze_message(message)

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    INSERT INTO openchat_messages (
        user_id,
        message,
        status,
        risk_level,
        created_at
    )
    VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        message.strip(),
        status,
        risk_level,
        datetime.utcnow()
    ))

    conn.commit()
    conn.close()

    return status, risk_level


def get_messages(db_path, limit=80):
    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    SELECT
        m.id,
        m.user_id,
        m.message,
        m.status,
        m.risk_level,
        m.created_at,
        u.phone as phone_number,
        u.name as author_name
    FROM openchat_messages m
    LEFT JOIN users u ON m.user_id = u.id
    WHERE m.status = 'ACTIVE'
    ORDER BY m.id DESC
    LIMIT ?
    """, (limit,))

    messages = c.fetchall()

    conn.close()

    return messages