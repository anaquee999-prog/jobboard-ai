import re
import sqlite3


def register_community_routes(app, deps):
    login_required = deps["login_required"]
    abort = deps["abort"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    url_for = deps["url_for"]
    send_from_directory = deps["send_from_directory"]
    get_current_user = deps["get_current_user"]
    get_db = deps["get_db"]
    now_str = deps["now_str"]
    analyze_job_content = deps["analyze_job_content"]
    create_notification = deps["create_notification"]
    add_activity_log = deps["add_activity_log"]
    redirect_back = deps["_redirect_back"]
    security_guard = deps["security_guard"]
    OPENCHAT_UPLOAD_DIR = deps["OPENCHAT_UPLOAD_DIR"]

    COMMUNITY_CATEGORY_LABELS = {
        "GENERAL": "General",
        "SCAM_ALERT": "Scam alert",
        "QUESTION": "Question",
        "EXPERIENCE": "Experience",
        "LOCAL_NEWS": "Local news",
    }
    COMMUNITY_CATEGORIES = set(COMMUNITY_CATEGORY_LABELS)

    def community_status_counts():
        rows = get_db().execute(
            """
            SELECT status, COUNT(*) AS count
            FROM community_posts
            GROUP BY status
            """
        ).fetchall()
        counts = {row["status"]: int(row["count"] or 0) for row in rows}
        return {
            "active": counts.get("ACTIVE", 0),
            "pending": counts.get("PENDING_REVIEW", 0),
            "blocked": counts.get("BLOCKED", 0),
        }

    def normalize_community_category(value):
        category = str(value or "GENERAL").strip().upper()
        return category if category in COMMUNITY_CATEGORIES else "GENERAL"

    @app.route("/reports/<int:job_id>", methods=["POST"])
    @login_required
    def report_job(job_id):
        user = get_current_user()
        reason = request.form.get("reason", "").strip()
        if len(reason) < 3:
            reason = "User reported this job"
        current_time = now_str()
        try:
            get_db().execute(
                """
                INSERT INTO reports (job_post_id, reporter_id, reason, status, created_at, updated_at)
                VALUES (?, ?, ?, 'PENDING', ?, ?)
                """,
                (job_id, user["id"], reason[:500], current_time, current_time),
            )
            row = get_db().execute(
                "SELECT COUNT(*) AS count FROM reports WHERE job_post_id = ?",
                (job_id,),
            ).fetchone()
            report_count = int(row["count"] or 0)
            job = get_db().execute("SELECT * FROM job_posts WHERE id = ?", (job_id,)).fetchone()
            if job:
                score, status, risk_reason = analyze_job_content(
                    job["title"],
                    job["description"],
                    job["salary_range"],
                    job["location"],
                    50,
                    report_count,
                )
                next_status = "PENDING_AI_REVIEW" if status == "ACTIVE" and report_count > 0 else status
                get_db().execute(
                    """
                    UPDATE job_posts
                    SET report_count = ?, ai_risk_score = ?, ai_risk_reason = ?, status = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (report_count, score, risk_reason, next_status, current_time, job_id),
                )
                create_notification(
                    job["employer_id"],
                    "Job reported",
                    f"{job['title']} was reported by a user.",
                    url_for("job_detail", slug=str(job_id)),
                    "REPORT",
                )
            add_activity_log(user["id"], "REPORT_JOB", "job_posts", job_id, reason)
            get_db().commit()
        except sqlite3.IntegrityError:
            pass
        return redirect(url_for("job_detail_old", job_id=job_id))

    @app.route("/messages", methods=["POST"])
    @login_required
    def send_message():
        user = get_current_user()
        receiver_id = request.form.get("receiver_id", "").strip()
        application_id = request.form.get("application_id", "").strip() or None
        message = request.form.get("message", "").strip()
        if receiver_id and message:
            try:
                get_db().execute(
                    """
                    INSERT INTO messages (sender_id, receiver_id, application_id, message, is_read, created_at)
                    VALUES (?, ?, ?, ?, 0, ?)
                    """,
                    (user["id"], int(receiver_id), int(application_id) if application_id else None, message[:1000], now_str()),
                )
                create_notification(
                    int(receiver_id),
                    "New message",
                    message[:160],
                    url_for("inbox"),
                    "MESSAGE",
                )
                add_activity_log(user["id"], "SEND_MESSAGE", "messages", None, f"receiver={receiver_id}")
                get_db().commit()
            except Exception:
                pass
        return redirect_back("inbox")

    @app.route("/inbox")
    @login_required
    def inbox():
        return render_template("inbox.html", conversations=[], messages=[], selected_application=None)

    @app.route("/api/messages/unread-count")
    @login_required
    def api_unread_messages_count():
        row = get_db().execute(
            "SELECT COUNT(*) AS count FROM messages WHERE receiver_id = ? AND is_read = 0",
            (get_current_user()["id"],),
        ).fetchone()
        return {"ok": True, "unread": int(row["count"] or 0)}

    @app.route("/community")
    def community_board():
        user = get_current_user()
        selected_category = request.args.get("category", "ALL").strip().upper()
        if selected_category != "ALL":
            selected_category = normalize_community_category(selected_category)
        q = request.args.get("q", "").strip()[:80]

        where_clauses = ["community_posts.status = 'ACTIVE'"]
        params = []
        if user:
            where_clauses = [
                "(community_posts.status = 'ACTIVE' OR (community_posts.user_id = ? AND community_posts.status != 'BLOCKED'))"
            ]
            params.append(user["id"])
        if selected_category != "ALL":
            where_clauses.append("community_posts.category = ?")
            params.append(selected_category)
        if q:
            where_clauses.append("community_posts.body LIKE ?")
            params.append(f"%{q}%")

        posts = get_db().execute(
            f"""
            SELECT
                community_posts.*,
                users.phone_number,
                job_seeker_profiles.full_name,
                employer_profiles.company_name
            FROM community_posts
            LEFT JOIN users ON users.id = community_posts.user_id
            LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = community_posts.user_id
            LEFT JOIN employer_profiles ON employer_profiles.user_id = community_posts.user_id
            WHERE {" AND ".join(where_clauses)}
            ORDER BY datetime(community_posts.created_at) DESC, community_posts.id DESC
            LIMIT 100
            """,
            params,
        ).fetchall()
        stats = community_status_counts()
        return render_template(
            "community.html",
            posts=posts,
            stats=stats,
            categories=COMMUNITY_CATEGORY_LABELS,
            selected_category=selected_category,
            q=q,
            posted=request.args.get("posted", ""),
            reported=request.args.get("reported", ""),
        )

    @app.route("/community/posts", methods=["POST"])
    @login_required
    def create_community_post():
        user = get_current_user()
        if int(user["is_banned"] or 0):
            abort(403)

        ok, message = security_guard(request, "community")
        if not ok:
            add_activity_log(user["id"], "COMMUNITY_RATE_LIMITED", "community_posts", None, message)
            get_db().commit()
            return redirect(url_for("community_board", posted="rate_limited"))

        body = request.form.get("body", "").strip() or request.form.get("content", "").strip()
        category = normalize_community_category(request.form.get("category"))
        if body:
            body = re.sub(r"\s+", " ", body).strip()
            if len(body) < 10 or len(body) > 1000:
                return redirect(url_for("community_board", posted="invalid"))

            duplicate = get_db().execute(
                """
                SELECT id
                FROM community_posts
                WHERE user_id = ? AND lower(body) = lower(?)
                  AND datetime(created_at) >= datetime('now', '-30 minutes')
                LIMIT 1
                """,
                (user["id"], body[:1000]),
            ).fetchone()
            if duplicate:
                return redirect(url_for("community_board", posted="duplicate"))

            try:
                from security_engine import analyze_community_post

                result = analyze_community_post(body)
            except Exception:
                result = {"score": 35, "status": "PENDING_REVIEW", "reason": "Community moderation unavailable"}

            current_time = now_str()
            get_db().execute(
                """
                INSERT INTO community_posts (
                    user_id, body, category, status, moderation_score, moderation_reason,
                    report_count, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    user["id"],
                    body[:1000],
                    category,
                    result.get("status", "PENDING_REVIEW"),
                    int(result.get("score", 0) or 0),
                    result.get("reason", ""),
                    current_time,
                    current_time,
                ),
            )
            add_activity_log(user["id"], "CREATE_COMMUNITY_POST", "community_posts", None, "")
            get_db().commit()
            return redirect(url_for("community_board", posted=result.get("status", "PENDING_REVIEW").lower()))
        return redirect(url_for("community_board", posted="invalid"))

    @app.route("/community/posts/<int:post_id>/report", methods=["POST"])
    @login_required
    def report_community_post(post_id):
        user = get_current_user()
        ok, message = security_guard(request, "community")
        if not ok:
            add_activity_log(user["id"], "COMMUNITY_REPORT_RATE_LIMITED", "community_posts", post_id, message)
            get_db().commit()
            return redirect(url_for("community_board", reported="rate_limited"))

        reason = request.form.get("reason", "").strip()[:500]
        if len(reason) < 3:
            reason = "User reported this post"
        current_time = now_str()
        post = get_db().execute("SELECT * FROM community_posts WHERE id = ?", (post_id,)).fetchone()
        if not post:
            abort(404)
        try:
            get_db().execute(
                """
                INSERT INTO community_reports (post_id, reporter_id, reason, status, created_at, updated_at)
                VALUES (?, ?, ?, 'PENDING', ?, ?)
                """,
                (post_id, user["id"], reason, current_time, current_time),
            )
        except sqlite3.IntegrityError:
            return redirect(url_for("community_board", reported="duplicate"))

        row = get_db().execute("SELECT COUNT(*) AS count FROM community_reports WHERE post_id = ?", (post_id,)).fetchone()
        report_count = int(row["count"] or 0)
        next_status = "PENDING_REVIEW" if report_count >= 1 and post["status"] == "ACTIVE" else post["status"]
        if report_count >= 3:
            next_status = "BLOCKED"
        get_db().execute(
            """
            UPDATE community_posts
            SET report_count = ?, status = ?, updated_at = ?
            WHERE id = ?
            """,
            (report_count, next_status, current_time, post_id),
        )
        add_activity_log(user["id"], "REPORT_COMMUNITY_POST", "community_posts", post_id, reason)
        get_db().commit()
        return redirect(url_for("community_board", reported="ok"))

    @app.route("/openchat")
    def openchat():
        messages = get_db().execute(
            """
            SELECT
                openchat_messages.*,
                users.phone_number,
                users.role,
                COALESCE(job_seeker_profiles.full_name, employer_profiles.company_name, '') AS author_name
            FROM openchat_messages
            LEFT JOIN users ON users.id = openchat_messages.user_id
            LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = openchat_messages.user_id
            LEFT JOIN employer_profiles ON employer_profiles.user_id = openchat_messages.user_id
            WHERE openchat_messages.status = 'ACTIVE'
            ORDER BY datetime(openchat_messages.created_at) DESC, openchat_messages.id DESC
            LIMIT 100
            """
        ).fetchall()
        return render_template("openchat.html", messages=messages, media_by_message={})

    @app.route("/openchat/send", methods=["POST"])
    @login_required
    def openchat_send():
        user = get_current_user()
        message = request.form.get("message", "").strip()
        if message:
            try:
                from security_engine import analyze_openchat_message

                result = analyze_openchat_message(message)
            except Exception:
                result = {"score": 35, "status": "PENDING_REVIEW", "reason": "OpenChat moderation unavailable"}

            current_time = now_str()
            get_db().execute(
                """
                INSERT INTO openchat_messages (
                    user_id, message, status, moderation_score, moderation_reason,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    message[:1000],
                    result.get("status", "PENDING_REVIEW"),
                    int(result.get("score", 0) or 0),
                    result.get("reason", ""),
                    current_time,
                    current_time,
                ),
            )
            add_activity_log(user["id"], "SEND_OPENCHAT", "openchat_messages", None, "")
            get_db().commit()
        return redirect(url_for("openchat"))

    @app.route("/uploads/openchat/<path:filename>")
    def uploaded_openchat_media(filename):
        return send_from_directory(OPENCHAT_UPLOAD_DIR, filename)
