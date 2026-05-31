import json
import secrets


def build_discord_services(deps):
    token_provider = deps["DISCORD_BOT_API_TOKEN"]
    jsonify = deps["jsonify"]
    request = deps["request"]
    get_db = deps["get_db"]
    now_str = deps["now_str"]
    ensure_discord_schema = deps["ensure_discord_schema"]
    hash_password = deps["hash_password"]
    _profile_job_match = deps["_profile_job_match"]
    _row_value = deps["_row_value"]
    _canonical_job_position = deps["_canonical_job_position"]
    scam_risk_label = deps["scam_risk_label"]
    SITE_URL = deps["SITE_URL"]
    url_for = deps["url_for"]
    job_slug = deps["job_slug"]

    def _require_discord_bot_token():
        token_value = token_provider() if callable(token_provider) else token_provider
        if not token_value:
            return jsonify({"ok": False, "message": "DISCORD_BOT_API_TOKEN is not configured."}), 503
        token = request.headers.get("X-Discord-Bot-Token", "").strip()
        auth = request.headers.get("Authorization", "").strip()
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if not secrets.compare_digest(token, token_value):
            return jsonify({"ok": False, "message": "Invalid Discord bot token."}), 401
        return None

    def _json_payload():
        return request.get_json(silent=True) or {}

    def _bounded_int(value, default, minimum, maximum):
        try:
            number = int(value if value not in (None, "") else default)
        except (TypeError, ValueError):
            return None
        return max(minimum, min(maximum, number))

    def _discord_text(value, max_length=500):
        return str(value or "").strip()[:max_length]

    def _discord_list_text(value, max_length=300):
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item).strip() for item in value if str(item).strip())
        return _discord_text(value, max_length)

    def _get_or_create_discord_user(discord_user_id, discord_username="", role="JOB_SEEKER"):
        ensure_discord_schema()
        discord_user_id = _discord_text(discord_user_id, 80)
        discord_username = _discord_text(discord_username, 120)
        role = "EMPLOYER" if str(role or "").upper() == "EMPLOYER" else "JOB_SEEKER"
        if not discord_user_id:
            raise ValueError("discord_user_id is required")

        conn = get_db()
        account = conn.execute(
            """
            SELECT discord_accounts.*, users.role AS user_role
            FROM discord_accounts
            JOIN users ON users.id = discord_accounts.user_id
            WHERE discord_accounts.discord_user_id = ?
            """,
            (discord_user_id,),
        ).fetchone()
        current_time = now_str()
        if account:
            user_id = int(account["user_id"])
            conn.execute(
                """
                UPDATE discord_accounts
                SET discord_username = ?, role = ?, updated_at = ?
                WHERE discord_user_id = ?
                """,
                (discord_username, role, current_time, discord_user_id),
            )
            conn.execute("UPDATE users SET role = ?, updated_at = ? WHERE id = ?", (role, current_time, user_id))
            conn.commit()
            return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

        phone_number = f"discord:{discord_user_id}"
        cur = conn.execute(
            """
            INSERT INTO users (
                phone_number, password_hash, role, is_verified, is_banned,
                trust_score, created_at, updated_at
            )
            VALUES (?, ?, ?, 1, 0, 60, ?, ?)
            """,
            (phone_number, hash_password(secrets.token_urlsafe(24)), role, current_time, current_time),
        )
        user_id = cur.lastrowid
        conn.execute(
            """
            INSERT INTO discord_accounts (
                user_id, discord_user_id, discord_username, role, dm_enabled, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (user_id, discord_user_id, discord_username, role, current_time, current_time),
        )
        conn.commit()
        return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def _discord_account_for_user(user_id):
        ensure_discord_schema()
        return get_db().execute("SELECT * FROM discord_accounts WHERE user_id = ?", (user_id,)).fetchone()

    def _discord_account_from_request(data=None, role=None):
        ensure_discord_schema()
        data = data or {}
        discord_user_id = _discord_text(
            data.get("discord_user_id")
            or request.args.get("discord_user_id")
            or request.args.get("discord_id"),
            80,
        )
        if discord_user_id:
            if role:
                user = _get_or_create_discord_user(discord_user_id, data.get("discord_username"), role)
                return get_db().execute(
                    "SELECT * FROM discord_accounts WHERE user_id = ?",
                    (user["id"],),
                ).fetchone()
            return get_db().execute(
                "SELECT * FROM discord_accounts WHERE discord_user_id = ?",
                (discord_user_id,),
            ).fetchone()
        user_id = data.get("user_id") or request.args.get("user_id")
        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            return None
        return get_db().execute("SELECT * FROM discord_accounts WHERE user_id = ?", (user_id,)).fetchone()

    def _queue_discord_notification(user_id, event_type, payload):
        ensure_discord_schema()
        account = _discord_account_for_user(user_id)
        if not account or not int(account["dm_enabled"] or 0):
            return None
        current_time = now_str()
        cur = get_db().execute(
            """
            INSERT INTO discord_notifications (
                user_id, discord_user_id, event_type, payload, status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 'PENDING', ?, ?)
            """,
            (
                user_id,
                account["discord_user_id"],
                event_type,
                json.dumps(payload, ensure_ascii=False),
                current_time,
                current_time,
            ),
        )
        get_db().commit()
        return cur.lastrowid

    def _job_match_score(row, keyword="", location="", job_type="", profile=None):
        if profile:
            score, _, _ = _profile_job_match(row, profile)
            keyword = str(keyword or "").strip().lower()
            if keyword and keyword in " ".join([str(row["title"] or ""), str(row["description"] or "")]).lower():
                score = min(100, score + 5)
            return score

        text = " ".join(
            [
                str(row["title"] or ""),
                str(row["description"] or ""),
                str(row["location"] or ""),
                str(row["company_name"] or ""),
            ]
        ).lower()
        score = 0
        keyword = str(keyword or "").strip().lower()
        location = str(location or "").strip().lower()
        job_type = str(job_type or "").strip().lower()
        if keyword and keyword in text:
            score += 35
        if location and location in str(row["location"] or "").lower():
            score += 25
        if job_type and job_type in text:
            score += 10
        canonical = _canonical_job_position(keyword)
        if canonical and canonical == (_row_value(row, "canonical_position") or _canonical_job_position(row["title"], row["description"])):
            score += 25
        if int(row["is_company_verified"] or 0):
            score += 10
        risk = int(row["ai_risk_score"] or 0)
        if risk >= 70:
            score -= 30
        elif risk >= 35:
            score -= 10
        return max(0, min(100, score))

    def _discord_job_payload(row, match_score=0):
        return {
            "id": row["id"],
            "title": row["title"],
            "company_name": row["company_name"] or "Verified employer",
            "location": row["location"] or "",
            "salary_range": row["salary_range"] or "",
            "risk_score": int(row["ai_risk_score"] or 0),
            "risk_level": scam_risk_label(row["ai_risk_score"]),
            "match_score": int(match_score or 0),
            "is_urgent": bool(row["is_urgent"] or 0) if "is_urgent" in row.keys() else False,
            "url": f"{SITE_URL}{url_for('job_detail', slug=job_slug(row))}",
            "created_at": row["created_at"],
        }

    def _discord_profile_payload(account, profile=None, employer_profile=None):
        role = str(account["role"] or "").upper()
        payload = {
            "user_id": account["user_id"],
            "discord_user_id": account["discord_user_id"],
            "discord_username": account["discord_username"] or "",
            "role": role,
            "dm_enabled": bool(account["dm_enabled"] or 0),
            "updated_at": account["updated_at"],
        }
        if role == "EMPLOYER":
            employer_profile = employer_profile or get_db().execute(
                "SELECT * FROM employer_profiles WHERE user_id = ?",
                (account["user_id"],),
            ).fetchone()
            payload["employer_profile"] = {
                "company_name": employer_profile["company_name"] if employer_profile else "",
                "is_company_verified": bool(employer_profile["is_company_verified"] or 0) if employer_profile else False,
                "address": employer_profile["address"] if employer_profile else "",
                "website": employer_profile["website"] if employer_profile else "",
            }
            return payload

        profile = profile or get_db().execute(
            "SELECT * FROM job_seeker_profiles WHERE user_id = ?",
            (account["user_id"],),
        ).fetchone()
        payload["profile"] = {
            "full_name": profile["full_name"] if profile else "",
            "headline": profile["headline"] if profile else "",
            "desired_position": profile["desired_position"] if profile else "",
            "skills": profile["skills"] if profile else "",
            "preferred_location": profile["preferred_location"] if profile else "",
            "job_type": profile["job_type"] if profile else "",
            "expected_salary": profile["expected_salary"] if profile else "",
            "resume_url": profile["resume_url"] if profile else "",
            "cv_url": profile["resume_url"] if profile else "",
            "is_public": bool(profile["is_public"] or 0) if profile else False,
        }
        return payload

    def _notify_followers_for_job(job_id, company_name, location, title):
        ensure_discord_schema()
        company_name_lc = str(company_name or "").strip().lower()
        location_lc = str(location or "").strip().lower()
        rows = get_db().execute(
            """
            SELECT DISTINCT discord_accounts.user_id
            FROM discord_accounts
            LEFT JOIN company_follows ON company_follows.user_id = discord_accounts.user_id
            LEFT JOIN job_alert_preferences ON job_alert_preferences.user_id = discord_accounts.user_id
            WHERE discord_accounts.role = 'JOB_SEEKER'
              AND discord_accounts.dm_enabled = 1
            """
        ).fetchall()
        queued = 0
        for row in rows:
            user_id = int(row["user_id"])
            follows = get_db().execute("SELECT company_name FROM company_follows WHERE user_id = ?", (user_id,)).fetchall()
            prefs = get_db().execute("SELECT * FROM job_alert_preferences WHERE user_id = ?", (user_id,)).fetchone()
            follow_match = any(company_name_lc and company_name_lc == str(f["company_name"] or "").lower() for f in follows)
            pref_match = False
            if prefs:
                keywords = str(prefs["keywords"] or "").lower()
                locations = str(prefs["locations"] or "").lower()
                pref_match = (keywords and keywords in str(title or "").lower()) or (location_lc and location_lc in locations)
            if follow_match or pref_match:
                _queue_discord_notification(
                    user_id,
                    "job_match",
                    {
                        "job_id": job_id,
                        "title": title,
                        "company_name": company_name,
                        "location": location,
                        "url": f"{SITE_URL}{url_for('job_detail', slug=str(job_id))}",
                    },
                )
                queued += 1
        return queued

    def _record_match_event(job_row, profile_row, match_score, match_reason, canonical_position):
        if match_score < 70:
            return False
        job_id = int(_row_value(job_row, "id"))
        job_seeker_id = int(_row_value(profile_row, "user_id"))
        employer_id = int(_row_value(job_row, "employer_id"))
        current_time = now_str()
        conn = get_db()
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO match_events (
                job_id, job_seeker_id, employer_id, match_score, match_reason,
                canonical_position, status, notified_job_seeker, notified_employer,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'NEW', 0, 0, ?, ?)
            """,
            (
                job_id,
                job_seeker_id,
                employer_id,
                int(match_score),
                match_reason,
                canonical_position or "",
                current_time,
                current_time,
            ),
        )
        inserted = cur.rowcount > 0
        if not inserted:
            conn.execute(
                """
                UPDATE match_events
                SET match_score = max(match_score, ?),
                    match_reason = CASE WHEN ? > match_score THEN ? ELSE match_reason END,
                    canonical_position = CASE WHEN ? != '' THEN ? ELSE canonical_position END,
                    updated_at = ?
                WHERE job_id = ? AND job_seeker_id = ?
                """,
                (
                    int(match_score),
                    int(match_score),
                    match_reason,
                    canonical_position or "",
                    canonical_position or "",
                    current_time,
                    job_id,
                    job_seeker_id,
                ),
            )
            conn.commit()
            return False

        job_payload = {
            "job_id": job_id,
            "job_title": _row_value(job_row, "title"),
            "company_name": _row_value(job_row, "company_name") or "Verified employer",
            "location": _row_value(job_row, "location"),
            "salary_range": _row_value(job_row, "salary_range"),
            "match_score": int(match_score),
            "match_reason": match_reason,
            "url": f"{SITE_URL}{url_for('job_detail', slug=str(job_id))}",
        }
        seeker_payload = {
            "job_id": job_id,
            "job_title": _row_value(job_row, "title"),
            "applicant_user_id": job_seeker_id,
            "applicant_name": _row_value(profile_row, "full_name") or f"Applicant {job_seeker_id}",
            "headline": _row_value(profile_row, "headline"),
            "skills": _row_value(profile_row, "skills"),
            "match_score": int(match_score),
            "match_reason": match_reason,
            "url": f"{SITE_URL}{url_for('employer_applications')}",
        }
        seeker_notice = _queue_discord_notification(job_seeker_id, "job_match", job_payload)
        employer_notice = _queue_discord_notification(employer_id, "candidate_match", seeker_payload)
        conn.execute(
            """
            UPDATE match_events
            SET notified_job_seeker = ?, notified_employer = ?, status = 'NOTIFIED', updated_at = ?
            WHERE job_id = ? AND job_seeker_id = ?
            """,
            (1 if seeker_notice else 0, 1 if employer_notice else 0, now_str(), job_id, job_seeker_id),
        )
        conn.commit()
        return True

    def _run_matching_for_job(job_id, limit=20):
        ensure_discord_schema()
        job = get_db().execute(
            """
            SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE job_posts.id = ? AND job_posts.status = 'ACTIVE' AND COALESCE(job_posts.ai_risk_score, 0) < 70
            """,
            (job_id,),
        ).fetchone()
        if not job:
            return 0
        profiles = get_db().execute(
            """
            SELECT job_seeker_profiles.*
            FROM job_seeker_profiles
            JOIN discord_accounts ON discord_accounts.user_id = job_seeker_profiles.user_id
            WHERE discord_accounts.role = 'JOB_SEEKER'
              AND discord_accounts.dm_enabled = 1
            ORDER BY datetime(job_seeker_profiles.updated_at) DESC, job_seeker_profiles.id DESC
            LIMIT 200
            """
        ).fetchall()
        created = 0
        ranked = []
        for profile in profiles:
            score, reason, canonical = _profile_job_match(job, profile)
            ranked.append((score, reason, canonical, profile))
        for score, reason, canonical, profile in sorted(ranked, key=lambda item: item[0], reverse=True)[:limit]:
            if _record_match_event(job, profile, score, reason, canonical):
                created += 1
        return created

    def _run_matching_for_profile(user_id, limit=20):
        ensure_discord_schema()
        profile = get_db().execute("SELECT * FROM job_seeker_profiles WHERE user_id = ?", (user_id,)).fetchone()
        if not profile:
            return 0
        jobs = get_db().execute(
            """
            SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE job_posts.status = 'ACTIVE'
              AND COALESCE(job_posts.ai_risk_score, 0) < 70
            ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
            LIMIT 300
            """
        ).fetchall()
        created = 0
        ranked = []
        for job in jobs:
            score, reason, canonical = _profile_job_match(job, profile)
            ranked.append((score, reason, canonical, job))
        for score, reason, canonical, job in sorted(ranked, key=lambda item: item[0], reverse=True)[:limit]:
            if _record_match_event(job, profile, score, reason, canonical):
                created += 1
        return created

    return {
        "_require_discord_bot_token": _require_discord_bot_token,
        "_json_payload": _json_payload,
        "_bounded_int": _bounded_int,
        "_discord_text": _discord_text,
        "_discord_list_text": _discord_list_text,
        "_get_or_create_discord_user": _get_or_create_discord_user,
        "_discord_account_for_user": _discord_account_for_user,
        "_discord_account_from_request": _discord_account_from_request,
        "_queue_discord_notification": _queue_discord_notification,
        "_job_match_score": _job_match_score,
        "_discord_job_payload": _discord_job_payload,
        "_discord_profile_payload": _discord_profile_payload,
        "_notify_followers_for_job": _notify_followers_for_job,
        "_record_match_event": _record_match_event,
        "_run_matching_for_job": _run_matching_for_job,
        "_run_matching_for_profile": _run_matching_for_profile,
    }
