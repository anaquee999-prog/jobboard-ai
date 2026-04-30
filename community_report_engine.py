import sqlite3
from datetime import datetime


def get_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_report_tables(db_path):

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS community_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        reporter_id INTEGER,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def report_post(db_path, post_id, reporter_id, reason):

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    INSERT INTO community_reports (post_id, reporter_id, reason, created_at)
    VALUES (?, ?, ?, ?)
    """, (
        post_id,
        reporter_id,
        reason,
        datetime.utcnow()
    ))

    conn.commit()
    conn.close()


def get_reports(db_path):

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    SELECT
        r.id,
        r.reason,
        r.created_at,
        p.content,
        u.phone as reporter_phone
    FROM community_reports r
    LEFT JOIN community_posts p ON r.post_id = p.id
    LEFT JOIN users u ON r.reporter_id = u.id
    ORDER BY r.id DESC
    """)

    reports = c.fetchall()

    conn.close()

    return reports