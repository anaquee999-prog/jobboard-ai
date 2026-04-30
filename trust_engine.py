import sqlite3


def get_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_trust_tables(db_path):

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS trust_scores (
        user_id INTEGER PRIMARY KEY,
        score INTEGER DEFAULT 50,
        level TEXT DEFAULT 'NORMAL'
    )
    """)

    conn.commit()
    conn.close()


def calculate_level(score):

    if score >= 80:
        return "HIGH_TRUST"

    if score >= 50:
        return "NORMAL"

    if score >= 20:
        return "LOW_TRUST"

    return "LOCKED"


def get_trust_score(db_path, user_id):

    conn = get_db(db_path)
    c = conn.cursor()

    c.execute("""
    SELECT score FROM trust_scores
    WHERE user_id=?
    """, (user_id,))

    row = c.fetchone()

    if not row:
        c.execute("""
        INSERT INTO trust_scores (user_id,score,level)
        VALUES (?,?,?)
        """, (user_id,50,"NORMAL"))

        conn.commit()
        conn.close()

        return 50

    conn.close()

    return row["score"]


def update_trust(db_path, user_id, delta):

    conn = get_db(db_path)
    c = conn.cursor()

    score = get_trust_score(db_path, user_id)

    new_score = score + delta

    if new_score > 100:
        new_score = 100

    if new_score < 0:
        new_score = 0

    level = calculate_level(new_score)

    c.execute("""
    INSERT OR REPLACE INTO trust_scores (user_id,score,level)
    VALUES (?,?,?)
    """, (user_id,new_score,level))

    conn.commit()
    conn.close()

    return new_score, level