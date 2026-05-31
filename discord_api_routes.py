import json
import sqlite3


def register_discord_api_routes(app, deps):
    jsonify = deps["jsonify"]
    request = deps["request"]
    url_for = deps["url_for"]
    get_db = deps["get_db"]
    now_str = deps["now_str"]
    SITE_URL = deps["SITE_URL"]
    _require_discord_bot_token = deps["_require_discord_bot_token"]
    _discord_account_from_request = deps["_discord_account_from_request"]
    _discord_profile_payload = deps["_discord_profile_payload"]
    _json_payload = deps["_json_payload"]
    _get_or_create_discord_user = deps["_get_or_create_discord_user"]
    _discord_text = deps["_discord_text"]
    _discord_list_text = deps["_discord_list_text"]
    _canonical_job_position = deps["_canonical_job_position"]
    _queue_discord_notification = deps["_queue_discord_notification"]
    _notify_followers_for_job = deps["_notify_followers_for_job"]
    _bounded_int = deps["_bounded_int"]
    _discord_job_payload = deps["_discord_job_payload"]
    _run_matching_for_profile = deps["_run_matching_for_profile"]
    _run_matching_for_job = deps["_run_matching_for_job"]
    _profile_job_match = deps["_profile_job_match"]
    _record_match_event = deps["_record_match_event"]
    _job_match_score = deps["_job_match_score"]
    _extract_skill_tags = deps["_extract_skill_tags"]
    analyze_job_content = deps["analyze_job_content"]
    add_activity_log = deps["add_activity_log"]

    @app.route("/api/discord/commands")
    def api_discord_commands():
        return jsonify({
            "ok": True,
            "commands": [
                {"name": "/profile view", "description": "View your CV, skills, and experience profile"},
                {"name": "/profile edit", "description": "Create or update your profile, skills, and CV"},
                {"name": "/search job", "description": "Search active jobs by keyword, location, and type"},
                {"name": "/apply", "description": "Apply to a job from Discord"},
                {"name": "/alert job", "description": "Set job alerts by keyword, location, type, and salary"},
                {"name": "/applications", "description": "View application status"},
                {"name": "/follow company", "description": "Follow a company for new job alerts"},
                {"name": "/post job", "description": "Employer posts a new job"},
                {"name": "/list jobs", "description": "List active posted jobs"},
                {"name": "/view applicants", "description": "Employer views applicants for a job"},
                {"name": "/message applicant", "description": "Send a Discord DM to an applicant"},
                {"name": "/notify applicants", "description": "Send an announcement to applicants for a job"},
                {"name": "/match jobs", "description": "AI recommends jobs for a job seeker"},
                {"name": "/match applicants", "description": "AI recommends applicants for a job"},
                {"name": "/stats users", "description": "View user and application statistics"},
                {"name": "/stats jobs", "description": "View job posting and popularity statistics"},
            ],
        })


    @app.route("/api/discord/profile", methods=["GET"])
    def api_discord_profile_view():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        account = _discord_account_from_request()
        if not account:
            return jsonify({"ok": False, "message": "Discord profile not found."}), 404
        return jsonify({"ok": True, "profile": _discord_profile_payload(account)})


    @app.route("/api/discord/profile", methods=["POST"])
    def api_discord_profile():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        data = _json_payload()
        try:
            user = _get_or_create_discord_user(
                data.get("discord_user_id"),
                data.get("discord_username"),
                data.get("role") or "JOB_SEEKER",
            )
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

        conn = get_db()
        current_time = now_str()
        role = str(user["role"] or "JOB_SEEKER").upper()
        if role == "EMPLOYER":
            company_name = _discord_text(data.get("company_name") or data.get("full_name") or data.get("discord_username"), 160)
            conn.execute(
                """
                INSERT INTO employer_profiles (user_id, company_name, tax_id, is_company_verified, address, website, created_at, updated_at)
                VALUES (?, ?, ?, 0, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    company_name = excluded.company_name,
                    address = excluded.address,
                    website = excluded.website,
                    updated_at = excluded.updated_at
                """,
                (
                    user["id"],
                    company_name or f"Discord Employer {user['id']}",
                    f"DISCORD-{user['id']}",
                    _discord_text(data.get("address"), 240),
                    _discord_text(data.get("website"), 240),
                    current_time,
                    current_time,
                ),
            )
        else:
            full_name = _discord_text(data.get("full_name") or data.get("discord_username"), 160)
            desired_position = _discord_text(data.get("desired_position") or data.get("position") or data.get("headline"), 160)
            skills = _discord_list_text(data.get("skills"), 500)
            preferred_location = _discord_text(data.get("preferred_location") or data.get("location"), 160)
            job_type = _discord_text(data.get("job_type") or data.get("type"), 80)
            expected_salary = _discord_text(data.get("expected_salary") or data.get("salary"), 80)
            canonical_position = _canonical_job_position(desired_position, skills, data.get("headline"))
            conn.execute(
                """
                INSERT INTO job_seeker_profiles (
                    user_id, full_name, headline, resume_url, is_public,
                    desired_position, canonical_position, skills, preferred_location,
                    job_type, expected_salary, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    full_name = excluded.full_name,
                    headline = excluded.headline,
                    resume_url = excluded.resume_url,
                    is_public = excluded.is_public,
                    desired_position = excluded.desired_position,
                    canonical_position = excluded.canonical_position,
                    skills = excluded.skills,
                    preferred_location = excluded.preferred_location,
                    job_type = excluded.job_type,
                    expected_salary = excluded.expected_salary,
                    updated_at = excluded.updated_at
                """,
                    (
                        user["id"],
                        full_name or f"Discord User {user['id']}",
                        _discord_text(data.get("headline") or skills, 300),
                        _discord_text(data.get("resume_url") or data.get("cv_url"), 500),
                    1 if data.get("is_public", True) else 0,
                    desired_position,
                    canonical_position,
                    skills,
                    preferred_location,
                    job_type,
                    expected_salary,
                    current_time,
                    current_time,
                ),
            )
            conn.execute(
                """
                INSERT INTO job_alert_preferences (
                    user_id, keywords, locations, job_types, min_salary, alert_frequency, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    keywords = excluded.keywords,
                    locations = excluded.locations,
                    job_types = excluded.job_types,
                    min_salary = excluded.min_salary,
                    alert_frequency = excluded.alert_frequency,
                    updated_at = excluded.updated_at
                """,
                (
                    user["id"],
                    _discord_list_text(data.get("keywords") or data.get("skills")),
                    _discord_list_text(data.get("locations") or data.get("location")),
                    _discord_list_text(data.get("job_types") or data.get("type")),
                    _discord_text(data.get("min_salary"), 80),
                    _discord_text(data.get("alert_frequency") or "instant", 40),
                    current_time,
                    current_time,
                ),
            )
        if "dm_enabled" in data:
            conn.execute(
                "UPDATE discord_accounts SET dm_enabled = ?, updated_at = ? WHERE user_id = ?",
                (1 if data.get("dm_enabled") else 0, current_time, user["id"]),
            )
        conn.commit()
        new_matches = _run_matching_for_profile(user["id"]) if role == "JOB_SEEKER" else 0
        return jsonify({"ok": True, "user_id": user["id"], "role": role, "new_matches": new_matches})


    @app.route("/api/discord/search", methods=["POST"])
    def api_discord_search():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        data = _json_payload()
        keyword = _discord_text(data.get("keyword") or data.get("q"), 120)
        location = _discord_text(data.get("location"), 120)
        job_type = _discord_text(data.get("type") or data.get("job_type"), 80)
        limit = _bounded_int(data.get("limit"), 5, 1, 10)
        if limit is None:
            return jsonify({"ok": False, "message": "limit must be a number."}), 400
        profile = None
        if data.get("discord_user_id"):
            account = get_db().execute(
                "SELECT user_id FROM discord_accounts WHERE discord_user_id = ?",
                (_discord_text(data.get("discord_user_id"), 80),),
            ).fetchone()
            if account:
                profile = get_db().execute("SELECT * FROM job_seeker_profiles WHERE user_id = ?", (account["user_id"],)).fetchone()

        where = ["job_posts.status = 'ACTIVE'"]
        params = []
        if keyword:
            like = f"%{keyword.lower()}%"
            where.append("(lower(job_posts.title) LIKE ? OR lower(job_posts.description) LIKE ? OR lower(employer_profiles.company_name) LIKE ?)")
            params.extend([like, like, like])
        if location:
            where.append("lower(job_posts.location) LIKE ?")
            params.append(f"%{location.lower()}%")

        rows = get_db().execute(
            f"""
            SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE {" AND ".join(where)}
            ORDER BY COALESCE(job_posts.is_urgent, 0) DESC, datetime(job_posts.updated_at) DESC, job_posts.id DESC
            LIMIT 50
            """,
            params,
        ).fetchall()
        ranked = sorted(
            [(_job_match_score(row, keyword, location, job_type, profile), row) for row in rows],
            key=lambda item: item[0],
            reverse=True,
        )[:limit]
        return jsonify({"ok": True, "count": len(ranked), "jobs": [_discord_job_payload(row, score) for score, row in ranked]})


    @app.route("/api/discord/follow", methods=["POST"])
    def api_discord_follow():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        data = _json_payload()
        user = _get_or_create_discord_user(data.get("discord_user_id"), data.get("discord_username"), "JOB_SEEKER")
        follow_type = _discord_text(data.get("type") or "company", 40).lower()
        value = _discord_text(data.get("value") or data.get("company_name") or data.get("keyword"), 160)
        if not value:
            return jsonify({"ok": False, "message": "follow value is required."}), 400
        current_time = now_str()
        if follow_type == "company":
            employer = get_db().execute(
                "SELECT user_id FROM employer_profiles WHERE lower(company_name) = ? LIMIT 1",
                (value.lower(),),
            ).fetchone()
            get_db().execute(
                """
                INSERT OR IGNORE INTO company_follows (user_id, employer_id, company_name, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (user["id"], employer["user_id"] if employer else None, value, current_time),
            )
        else:
            prefs = get_db().execute("SELECT * FROM job_alert_preferences WHERE user_id = ?", (user["id"],)).fetchone()
            keywords = prefs["keywords"] if prefs else ""
            locations = prefs["locations"] if prefs else ""
            job_types = prefs["job_types"] if prefs else ""
            if follow_type == "location":
                locations = ", ".join(filter(None, [locations, value]))
            elif follow_type in {"category", "type", "job_type"}:
                job_types = ", ".join(filter(None, [job_types, value]))
            else:
                keywords = ", ".join(filter(None, [keywords, value]))
            get_db().execute(
                """
                INSERT INTO job_alert_preferences (user_id, keywords, locations, job_types, min_salary, alert_frequency, created_at, updated_at)
                VALUES (?, ?, ?, ?, '', 'instant', ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    keywords = excluded.keywords,
                    locations = excluded.locations,
                    job_types = excluded.job_types,
                    updated_at = excluded.updated_at
                """,
                (user["id"], keywords, locations, job_types, current_time, current_time),
            )
        get_db().commit()
        return jsonify({"ok": True, "follow_type": follow_type, "value": value})


    @app.route("/api/discord/alert-job", methods=["POST"])
    def api_discord_alert_job():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        data = _json_payload()
        user = _get_or_create_discord_user(data.get("discord_user_id"), data.get("discord_username"), "JOB_SEEKER")
        criteria = data.get("criteria") or {}
        if isinstance(criteria, str):
            criteria = {"keywords": criteria}
        current_time = now_str()
        keywords = _discord_list_text(criteria.get("keywords") or data.get("keywords") or data.get("keyword"), 500)
        locations = _discord_list_text(criteria.get("locations") or data.get("locations") or data.get("location"), 500)
        job_types = _discord_list_text(criteria.get("job_types") or data.get("job_types") or data.get("type"), 300)
        min_salary = _discord_text(criteria.get("min_salary") or data.get("min_salary") or data.get("salary"), 80)
        frequency = _discord_text(criteria.get("alert_frequency") or data.get("alert_frequency") or "instant", 40)
        get_db().execute(
            """
            INSERT INTO job_alert_preferences (user_id, keywords, locations, job_types, min_salary, alert_frequency, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                keywords = excluded.keywords,
                locations = excluded.locations,
                job_types = excluded.job_types,
                min_salary = excluded.min_salary,
                alert_frequency = excluded.alert_frequency,
                updated_at = excluded.updated_at
            """,
            (user["id"], keywords, locations, job_types, min_salary, frequency, current_time, current_time),
        )
        get_db().commit()
        return jsonify({
            "ok": True,
            "criteria": {
                "keywords": keywords,
                "locations": locations,
                "job_types": job_types,
                "min_salary": min_salary,
                "alert_frequency": frequency,
            },
        })


    @app.route("/api/discord/apply", methods=["POST"])
    def api_discord_apply():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        data = _json_payload()
        user = _get_or_create_discord_user(data.get("discord_user_id"), data.get("discord_username"), "JOB_SEEKER")
        try:
            job_id = int(data.get("job_id"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "message": "job_id is required."}), 400
        job = get_db().execute("SELECT * FROM job_posts WHERE id = ? AND status = 'ACTIVE'", (job_id,)).fetchone()
        if not job:
            return jsonify({"ok": False, "message": "Active job not found."}), 404
        current_time = now_str()
        try:
            cur = get_db().execute(
                """
                INSERT INTO applications (job_seeker_id, job_post_id, status, message, created_at, updated_at)
                VALUES (?, ?, 'PENDING', ?, ?, ?)
                """,
                (user["id"], job_id, _discord_text(data.get("message"), 500), current_time, current_time),
            )
            application_id = cur.lastrowid
        except sqlite3.IntegrityError:
            existing = get_db().execute(
                "SELECT id FROM applications WHERE job_seeker_id = ? AND job_post_id = ?",
                (user["id"], job_id),
            ).fetchone()
            application_id = existing["id"]
        get_db().commit()
        _queue_discord_notification(
            job["employer_id"],
            "new_application",
            {
                "application_id": application_id,
                "job_id": job_id,
                "job_title": job["title"],
                "applicant_user_id": user["id"],
                "url": f"{SITE_URL}{url_for('employer_applications')}",
            },
        )
        return jsonify({"ok": True, "application_id": application_id, "status": "PENDING"})


    @app.route("/api/discord/applications")
    def api_discord_applications():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        discord_user_id = _discord_text(request.args.get("discord_user_id"), 80)
        account = get_db().execute("SELECT user_id FROM discord_accounts WHERE discord_user_id = ?", (discord_user_id,)).fetchone()
        if not account:
            return jsonify({"ok": True, "applications": []})
        rows = get_db().execute(
            """
            SELECT applications.*, job_posts.title, job_posts.location, employer_profiles.company_name
            FROM applications
            JOIN job_posts ON job_posts.id = applications.job_post_id
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE applications.job_seeker_id = ?
            ORDER BY datetime(applications.created_at) DESC, applications.id DESC
            LIMIT 20
            """,
            (account["user_id"],),
        ).fetchall()
        return jsonify({
            "ok": True,
            "applications": [
                {
                    "id": row["id"],
                    "job_id": row["job_post_id"],
                    "job_title": row["title"],
                    "company_name": row["company_name"] or "",
                    "location": row["location"] or "",
                    "status": row["status"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ],
        })


    @app.route("/api/discord/post-job", methods=["POST"])
    def api_discord_post_job():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        data = _json_payload()
        user = _get_or_create_discord_user(data.get("discord_user_id"), data.get("discord_username"), "EMPLOYER")
        title = _discord_text(data.get("title"), 160)
        description = _discord_text(data.get("description"), 4000)
        salary_range = _discord_text(data.get("salary_range") or data.get("salary"), 120)
        location = _discord_text(data.get("location"), 120)
        company_name = _discord_text(data.get("company_name") or data.get("discord_username"), 160)
        required_skills = _discord_list_text(data.get("required_skills") or data.get("skills") or _extract_skill_tags(title, description), 500)
        job_type = _discord_text(data.get("job_type") or data.get("type"), 80)
        canonical_position = _canonical_job_position(title, description, required_skills)
        if len(title) < 5:
            return jsonify({"ok": False, "message": "title must be at least 5 characters."}), 400
        if len(description) < 40:
            return jsonify({"ok": False, "message": "description must be at least 40 characters."}), 400

        current_time = now_str()
        get_db().execute(
            """
            INSERT INTO employer_profiles (user_id, company_name, tax_id, is_company_verified, address, website, created_at, updated_at)
            VALUES (?, ?, ?, 0, '', '', ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET company_name = excluded.company_name, updated_at = excluded.updated_at
            """,
            (user["id"], company_name or f"Discord Employer {user['id']}", f"DISCORD-{user['id']}", current_time, current_time),
        )
        score, status, reason = analyze_job_content(title, description, salary_range, location, user["trust_score"], 0)
        cur = get_db().execute(
            """
            INSERT INTO job_posts (
                employer_id, title, description, salary_range, location,
                is_government_news, source_url, status, ai_risk_score,
                ai_risk_reason, report_count, created_at, updated_at, is_urgent,
                canonical_position, required_skills, job_type
            )
            VALUES (?, ?, ?, ?, ?, 0, '', ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                title,
                description,
                salary_range,
                location,
                status,
                score,
                reason,
                current_time,
                current_time,
                1 if data.get("is_urgent") else 0,
                canonical_position,
                required_skills,
                job_type,
            ),
        )
        job_id = cur.lastrowid
        get_db().execute(
            """
            INSERT INTO ai_decision_logs (job_post_id, title, risk_score, risk_reason, final_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (job_id, title, score, reason, status, current_time),
        )
        add_activity_log(user["id"], "DISCORD_CREATE_JOB", "job_posts", job_id, f"status={status}, risk={score}")
        get_db().commit()
        follower_notifications = _notify_followers_for_job(job_id, company_name, location, title) if status == "ACTIVE" else 0
        match_notifications = _run_matching_for_job(job_id) if status == "ACTIVE" else 0
        return jsonify({
            "ok": True,
            "job_id": job_id,
            "status": status,
            "risk_score": score,
            "risk_reason": reason,
            "queued_notifications": follower_notifications + match_notifications,
            "follower_notifications": follower_notifications,
            "match_notifications": match_notifications,
            "canonical_position": canonical_position,
            "url": f"{SITE_URL}{url_for('job_detail', slug=str(job_id))}",
        })


    @app.route("/api/discord/jobs")
    def api_discord_list_jobs():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        keyword = _discord_text(request.args.get("keyword") or request.args.get("q"), 120)
        location = _discord_text(request.args.get("location"), 120)
        job_type = _discord_text(request.args.get("type") or request.args.get("job_type"), 80)
        limit = _bounded_int(request.args.get("limit"), 20, 1, 50)
        if limit is None:
            return jsonify({"ok": False, "message": "limit must be a number."}), 400
        where = ["job_posts.status = 'ACTIVE'"]
        params = []
        if keyword:
            like = f"%{keyword.lower()}%"
            where.append("(lower(job_posts.title) LIKE ? OR lower(job_posts.description) LIKE ? OR lower(employer_profiles.company_name) LIKE ?)")
            params.extend([like, like, like])
        if location:
            where.append("lower(job_posts.location) LIKE ?")
            params.append(f"%{location.lower()}%")
        if job_type:
            where.append("lower(COALESCE(job_posts.job_type, '')) LIKE ?")
            params.append(f"%{job_type.lower()}%")
        rows = get_db().execute(
            f"""
            SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE {" AND ".join(where)}
            ORDER BY COALESCE(job_posts.is_urgent, 0) DESC, datetime(job_posts.updated_at) DESC, job_posts.id DESC
            LIMIT ?
            """,
            params + [limit],
        ).fetchall()
        return jsonify({"ok": True, "count": len(rows), "jobs": [_discord_job_payload(row) for row in rows]})


    @app.route("/api/discord/applicants")
    @app.route("/api/discord/employer/applicants")
    def api_discord_employer_applicants():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        discord_user_id = _discord_text(request.args.get("discord_user_id"), 80)
        account = get_db().execute("SELECT user_id FROM discord_accounts WHERE discord_user_id = ?", (discord_user_id,)).fetchone()
        if not account:
            return jsonify({"ok": True, "applications": []})
        params = [account["user_id"]]
        where = ["job_posts.employer_id = ?"]
        if request.args.get("job_id"):
            job_id = _bounded_int(request.args.get("job_id"), None, 1, 10**12)
            if job_id is None:
                return jsonify({"ok": False, "message": "job_id must be a number."}), 400
            where.append("job_posts.id = ?")
            params.append(job_id)
        rows = get_db().execute(
            f"""
            SELECT applications.*, job_posts.title AS job_title, job_posts.location AS job_location,
                   job_seeker_profiles.full_name, job_seeker_profiles.headline, job_seeker_profiles.resume_url,
                   job_seeker_profiles.skills, discord_accounts.discord_user_id
            FROM applications
            JOIN job_posts ON job_posts.id = applications.job_post_id
            LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = applications.job_seeker_id
            LEFT JOIN discord_accounts ON discord_accounts.user_id = applications.job_seeker_id
            WHERE {" AND ".join(where)}
            ORDER BY datetime(applications.created_at) DESC, applications.id DESC
            LIMIT 30
            """,
            params,
        ).fetchall()
        return jsonify({
            "ok": True,
            "applications": [
                {
                    "id": row["id"],
                    "job_id": row["job_post_id"],
                    "job_title": row["job_title"],
                    "job_location": row["job_location"],
                    "applicant_user_id": row["job_seeker_id"],
                    "applicant_discord_user_id": row["discord_user_id"] or "",
                    "applicant_name": row["full_name"] or f"Applicant {row['job_seeker_id']}",
                    "headline": row["headline"] or "",
                    "skills": row["skills"] or "",
                    "resume_url": row["resume_url"] or "",
                    "status": row["status"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ],
        })


    @app.route("/api/discord/message-applicant", methods=["POST"])
    def api_discord_message_applicant():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        data = _json_payload()
        sender = _get_or_create_discord_user(data.get("discord_user_id"), data.get("discord_username"), "EMPLOYER")
        try:
            applicant_user_id = int(data.get("user_id") or data.get("applicant_user_id"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "message": "applicant user_id is required."}), 400
        message = _discord_text(data.get("message"), 1200)
        if not message:
            return jsonify({"ok": False, "message": "message is required."}), 400

        application_id = data.get("application_id")
        try:
            application_id = int(application_id) if application_id not in (None, "") else None
        except (TypeError, ValueError):
            application_id = None
        if application_id:
            application = get_db().execute(
                """
                SELECT applications.id
                FROM applications
                JOIN job_posts ON job_posts.id = applications.job_post_id
                WHERE applications.id = ? AND applications.job_seeker_id = ? AND job_posts.employer_id = ?
                """,
                (application_id, applicant_user_id, sender["id"]),
            ).fetchone()
            if not application:
                return jsonify({"ok": False, "message": "Application not found for this employer."}), 404
        else:
            application = get_db().execute(
                """
                SELECT applications.id
                FROM applications
                JOIN job_posts ON job_posts.id = applications.job_post_id
                WHERE applications.job_seeker_id = ? AND job_posts.employer_id = ?
                ORDER BY datetime(applications.created_at) DESC, applications.id DESC
                LIMIT 1
                """,
                (applicant_user_id, sender["id"]),
            ).fetchone()
            application_id = application["id"] if application else None

        cur = get_db().execute(
            """
            INSERT INTO messages (sender_id, receiver_id, application_id, message, is_read, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            (sender["id"], applicant_user_id, application_id, message, now_str()),
        )
        get_db().commit()
        notification_id = _queue_discord_notification(
            applicant_user_id,
            "employer_message",
            {
                "message_id": cur.lastrowid,
                "application_id": application_id,
                "from_user_id": sender["id"],
                "message": message,
            },
        )
        return jsonify({"ok": True, "message_id": cur.lastrowid, "queued_notification_id": notification_id})


    @app.route("/api/discord/notify-applicants", methods=["POST"])
    def api_discord_notify_applicants():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        data = _json_payload()
        sender = _get_or_create_discord_user(data.get("discord_user_id"), data.get("discord_username"), "EMPLOYER")
        try:
            job_id = int(data.get("job_id"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "message": "job_id is required."}), 400
        message = _discord_text(data.get("message"), 1200)
        if not message:
            return jsonify({"ok": False, "message": "message is required."}), 400
        job = get_db().execute(
            "SELECT * FROM job_posts WHERE id = ? AND employer_id = ?",
            (job_id, sender["id"]),
        ).fetchone()
        if not job:
            return jsonify({"ok": False, "message": "Job not found for this employer."}), 404
        rows = get_db().execute(
            """
            SELECT applications.id, applications.job_seeker_id
            FROM applications
            WHERE applications.job_post_id = ?
            ORDER BY datetime(applications.created_at) DESC, applications.id DESC
            LIMIT 100
            """,
            (job_id,),
        ).fetchall()
        queued = 0
        for row in rows:
            get_db().execute(
                """
                INSERT INTO messages (sender_id, receiver_id, application_id, message, is_read, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (sender["id"], row["job_seeker_id"], row["id"], message, now_str()),
            )
            if _queue_discord_notification(
                row["job_seeker_id"],
                "applicant_announcement",
                {"job_id": job_id, "job_title": job["title"], "application_id": row["id"], "message": message},
            ):
                queued += 1
        get_db().commit()
        return jsonify({"ok": True, "job_id": job_id, "applicants": len(rows), "queued_notifications": queued})


    @app.route("/api/discord/match-jobs")
    def api_discord_match_jobs():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        account = _discord_account_from_request()
        if not account:
            return jsonify({"ok": False, "message": "Discord job seeker profile not found."}), 404
        _run_matching_for_profile(account["user_id"])
        profile = get_db().execute("SELECT * FROM job_seeker_profiles WHERE user_id = ?", (account["user_id"],)).fetchone()
        if not profile:
            return jsonify({"ok": False, "message": "Job seeker profile not found."}), 404
        limit = _bounded_int(request.args.get("limit"), 10, 1, 20)
        if limit is None:
            return jsonify({"ok": False, "message": "limit must be a number."}), 400
        jobs = get_db().execute(
            """
            SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE job_posts.status = 'ACTIVE' AND COALESCE(job_posts.ai_risk_score, 0) < 70
            ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
            LIMIT 300
            """
        ).fetchall()
        ranked = []
        for job in jobs:
            score, reason, canonical = _profile_job_match(job, profile)
            ranked.append((score, reason, canonical, job))
        matches = [
            {
                **_discord_job_payload(job, score),
                "match_reason": reason,
                "canonical_position": canonical,
            }
            for score, reason, canonical, job in sorted(ranked, key=lambda item: item[0], reverse=True)[:limit]
        ]
        return jsonify({"ok": True, "user_id": account["user_id"], "matches": matches})


    @app.route("/api/discord/match-applicants")
    def api_discord_match_applicants():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        try:
            job_id = int(request.args.get("job_id"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "message": "job_id is required."}), 400
        job = get_db().execute(
            """
            SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE job_posts.id = ?
            """,
            (job_id,),
        ).fetchone()
        if not job:
            return jsonify({"ok": False, "message": "Job not found."}), 404
        discord_user_id = _discord_text(request.args.get("discord_user_id"), 80)
        if discord_user_id:
            account = get_db().execute(
                "SELECT user_id FROM discord_accounts WHERE discord_user_id = ?",
                (discord_user_id,),
            ).fetchone()
            if not account or int(account["user_id"]) != int(job["employer_id"]):
                return jsonify({"ok": False, "message": "You can only match applicants for your own jobs."}), 403
        limit = _bounded_int(request.args.get("limit"), 10, 1, 20)
        if limit is None:
            return jsonify({"ok": False, "message": "limit must be a number."}), 400
        profiles = get_db().execute(
            """
            SELECT job_seeker_profiles.*, discord_accounts.discord_user_id, discord_accounts.discord_username
            FROM job_seeker_profiles
            JOIN discord_accounts ON discord_accounts.user_id = job_seeker_profiles.user_id
            WHERE discord_accounts.role = 'JOB_SEEKER'
            ORDER BY datetime(job_seeker_profiles.updated_at) DESC, job_seeker_profiles.id DESC
            LIMIT 300
            """
        ).fetchall()
        ranked = []
        for profile in profiles:
            score, reason, canonical = _profile_job_match(job, profile)
            ranked.append((score, reason, canonical, profile))
            _record_match_event(job, profile, score, reason, canonical)
        matches = [
            {
                "applicant_user_id": profile["user_id"],
                "applicant_discord_user_id": profile["discord_user_id"],
                "discord_username": profile["discord_username"] or "",
                "applicant_name": profile["full_name"],
                "headline": profile["headline"] or "",
                "skills": profile["skills"] or "",
                "resume_url": profile["resume_url"] or "",
                "match_score": int(score or 0),
                "match_reason": reason,
                "canonical_position": canonical,
            }
            for score, reason, canonical, profile in sorted(ranked, key=lambda item: item[0], reverse=True)[:limit]
        ]
        return jsonify({"ok": True, "job_id": job_id, "matches": matches})


    @app.route("/api/discord/matches")
    def api_discord_matches():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        discord_user_id = _discord_text(request.args.get("discord_user_id"), 80)
        account = get_db().execute(
            "SELECT user_id, role FROM discord_accounts WHERE discord_user_id = ?",
            (discord_user_id,),
        ).fetchone()
        if not account:
            return jsonify({"ok": True, "matches": []})

        if str(account["role"] or "").upper() == "EMPLOYER":
            rows = get_db().execute(
                """
                SELECT match_events.*, job_posts.title AS job_title, job_posts.location AS job_location,
                       job_seeker_profiles.full_name, job_seeker_profiles.headline, job_seeker_profiles.skills
                FROM match_events
                JOIN job_posts ON job_posts.id = match_events.job_id
                JOIN job_seeker_profiles ON job_seeker_profiles.user_id = match_events.job_seeker_id
                WHERE match_events.employer_id = ?
                ORDER BY match_events.match_score DESC, datetime(match_events.created_at) DESC
                LIMIT 20
                """,
                (account["user_id"],),
            ).fetchall()
            matches = [
                {
                    "id": row["id"],
                    "job_id": row["job_id"],
                    "job_title": row["job_title"],
                    "applicant_user_id": row["job_seeker_id"],
                    "applicant_name": row["full_name"],
                    "headline": row["headline"] or "",
                    "skills": row["skills"] or "",
                    "match_score": row["match_score"],
                    "match_reason": row["match_reason"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        else:
            rows = get_db().execute(
                """
                SELECT match_events.*, job_posts.title AS job_title, job_posts.location AS job_location,
                       job_posts.salary_range, employer_profiles.company_name
                FROM match_events
                JOIN job_posts ON job_posts.id = match_events.job_id
                LEFT JOIN employer_profiles ON employer_profiles.user_id = match_events.employer_id
                WHERE match_events.job_seeker_id = ?
                ORDER BY match_events.match_score DESC, datetime(match_events.created_at) DESC
                LIMIT 20
                """,
                (account["user_id"],),
            ).fetchall()
            matches = [
                {
                    "id": row["id"],
                    "job_id": row["job_id"],
                    "job_title": row["job_title"],
                    "company_name": row["company_name"] or "",
                    "location": row["job_location"] or "",
                    "salary_range": row["salary_range"] or "",
                    "match_score": row["match_score"],
                    "match_reason": row["match_reason"],
                    "url": f"{SITE_URL}{url_for('job_detail', slug=str(row['job_id']))}",
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        return jsonify({"ok": True, "matches": matches})


    @app.route("/api/discord/analytics")
    def api_discord_analytics():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        conn = get_db()
        return jsonify({
            "ok": True,
            "summary": {
                "discord_users": conn.execute("SELECT COUNT(*) AS count FROM discord_accounts").fetchone()["count"],
                "discord_pending_notifications": conn.execute("SELECT COUNT(*) AS count FROM discord_notifications WHERE status = 'PENDING'").fetchone()["count"],
                "jobs_posted": conn.execute("SELECT COUNT(*) AS count FROM job_posts").fetchone()["count"],
                "active_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'").fetchone()["count"],
                "applications": conn.execute("SELECT COUNT(*) AS count FROM applications").fetchone()["count"],
                "matches": conn.execute("SELECT COUNT(*) AS count FROM match_events").fetchone()["count"],
                "high_matches": conn.execute("SELECT COUNT(*) AS count FROM match_events WHERE match_score >= 85").fetchone()["count"],
            },
            "dashboard_url": f"{SITE_URL}/admin",
        })


    @app.route("/api/discord/stats/users")
    def api_discord_stats_users():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        conn = get_db()
        return jsonify({
            "ok": True,
            "stats": {
                "total_users": conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"],
                "discord_users": conn.execute("SELECT COUNT(*) AS count FROM discord_accounts").fetchone()["count"],
                "job_seekers": conn.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'JOB_SEEKER'").fetchone()["count"],
                "employers": conn.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'EMPLOYER'").fetchone()["count"],
                "applications": conn.execute("SELECT COUNT(*) AS count FROM applications").fetchone()["count"],
                "company_follows": conn.execute("SELECT COUNT(*) AS count FROM company_follows").fetchone()["count"],
                "job_alerts": conn.execute("SELECT COUNT(*) AS count FROM job_alert_preferences").fetchone()["count"],
                "pending_notifications": conn.execute("SELECT COUNT(*) AS count FROM discord_notifications WHERE status = 'PENDING'").fetchone()["count"],
            },
        })


    @app.route("/api/discord/stats/jobs")
    def api_discord_stats_jobs():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        conn = get_db()
        top_jobs = conn.execute(
            """
            SELECT job_posts.id AS job_id, job_posts.title AS job_title, COUNT(applications.id) AS applications
            FROM job_posts
            LEFT JOIN applications ON applications.job_post_id = job_posts.id
            GROUP BY job_posts.id, job_posts.title
            ORDER BY applications DESC, datetime(job_posts.created_at) DESC
            LIMIT 10
            """
        ).fetchall()
        return jsonify({
            "ok": True,
            "stats": {
                "total_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts").fetchone()["count"],
                "active_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'").fetchone()["count"],
                "pending_review_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'").fetchone()["count"],
                "rejected_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'REJECTED'").fetchone()["count"],
                "urgent_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE COALESCE(is_urgent, 0) = 1").fetchone()["count"],
                "high_risk_jobs": conn.execute("SELECT COUNT(*) AS count FROM job_posts WHERE COALESCE(ai_risk_score, 0) >= 70").fetchone()["count"],
                "matches": conn.execute("SELECT COUNT(*) AS count FROM match_events").fetchone()["count"],
            },
            "top_jobs": [
                {"job_id": row["job_id"], "job_title": row["job_title"], "applications": int(row["applications"] or 0)}
                for row in top_jobs
            ],
        })


    @app.route("/api/discord/notifications/pending")
    def api_discord_pending_notifications():
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        limit = _bounded_int(request.args.get("limit"), 20, 1, 50)
        if limit is None:
            return jsonify({"ok": False, "message": "limit must be a number."}), 400
        rows = get_db().execute(
            """
            SELECT *
            FROM discord_notifications
            WHERE status = 'PENDING'
            ORDER BY datetime(created_at) ASC, id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return jsonify({
            "ok": True,
            "notifications": [
                {
                    "id": row["id"],
                    "discord_user_id": row["discord_user_id"],
                    "event_type": row["event_type"],
                    "payload": json.loads(row["payload"] or "{}"),
                    "created_at": row["created_at"],
                }
                for row in rows
            ],
        })


    @app.route("/api/discord/notifications/<int:notification_id>/sent", methods=["POST"])
    def api_discord_mark_notification_sent(notification_id):
        auth_error = _require_discord_bot_token()
        if auth_error:
            return auth_error
        status = _discord_text((_json_payload().get("status") or "SENT"), 40).upper()
        if status not in {"SENT", "FAILED"}:
            status = "SENT"
        get_db().execute(
            """
            UPDATE discord_notifications
            SET status = ?, sent_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, now_str(), now_str(), notification_id),
        )
        get_db().commit()
        return jsonify({"ok": True, "status": status})



