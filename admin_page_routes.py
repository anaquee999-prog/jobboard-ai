import os


def register_admin_page_routes(app, deps):
    role_required = deps["role_required"]
    render_template = deps["render_template"]
    request = deps["request"]
    sqlite3 = deps["sqlite3"]
    app_get_db = deps["get_db"]
    get_current_user = deps["get_current_user"]
    normalize_phone = deps["normalize_phone"]
    blacklist_phone = deps["blacklist_phone"]
    admin_stats = deps["_admin_stats"]
    fetch_import_status = deps["_fetch_import_status"]
    fetch_template_jobs = deps["_fetch_template_jobs"]
    ensure_import_run_schema = deps["ensure_import_run_schema"]
    now_str = deps["now_str"]
    DB_PATH = deps["DB_PATH"]
    app_secret_key = deps["app_secret_key"]
    ADMIN_PHONE = deps["ADMIN_PHONE"]
    ADMIN_PASSWORD = deps["ADMIN_PASSWORD"]
    JOBBOARD_CRON_TOKEN = deps["JOBBOARD_CRON_TOKEN"]
    JOBBOARD_API_BASE_URL = deps["JOBBOARD_API_BASE_URL"]
    DISCORD_SCAM_ALERT_WEBHOOK_URL = deps["DISCORD_SCAM_ALERT_WEBHOOK_URL"]

    @app.route("/admin")
    @role_required("ADMIN")
    def admin_dashboard():
        stats = admin_stats()
        stats["import_status"] = fetch_import_status()
        return render_template(
            "admin_dashboard.html",
            stats=stats,
            review_jobs=fetch_template_jobs(limit=8, status="PENDING_AI_REVIEW"),
        )

    @app.route("/admin/blacklist", methods=["GET", "POST"])
    @role_required("ADMIN")
    def admin_blacklist():
        message = None
        message_type = None

        if request.method == "POST":
            phone = normalize_phone(request.form.get("phone", ""))
            reason = request.form.get("reason", "").strip()
            user = get_current_user()
            success, message = blacklist_phone(phone, reason, user["id"] if user else None)
            message_type = "success" if success else "error"
            if not success:
                message_type = "error"

        blacklist = app_get_db().execute(
            """
            SELECT phone_blacklist.*, users.full_name as banned_by_name, users.phone_number as banned_by_phone
            FROM phone_blacklist
            LEFT JOIN users ON users.id = phone_blacklist.banned_by_user_id
            ORDER BY datetime(phone_blacklist.created_at) DESC
            LIMIT 100
            """
        ).fetchall()

        return render_template(
            "admin_blacklist.html",
            blacklist=blacklist,
            message=message,
            message_type=message_type,
        )

    @app.route("/admin/moderation")
    @role_required("ADMIN")
    def admin_moderation():
        q = request.args.get("q", "").strip().lower()
        status = request.args.get("status", "PENDING_AI_REVIEW").strip()
        where = []
        params = []
        if status:
            where.append("job_posts.status = ?")
            params.append(status)
        if q:
            where.append(
                "(lower(job_posts.title) LIKE ? OR lower(job_posts.description) LIKE ? OR lower(employer_profiles.company_name) LIKE ?)"
            )
            params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
        where_sql = "WHERE " + " AND ".join(where) if where else ""
        jobs = app_get_db().execute(
            f"""
            SELECT
                job_posts.*,
                users.phone_number,
                users.trust_score,
                employer_profiles.company_name,
                employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN users ON users.id = job_posts.employer_id
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            {where_sql}
            ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
            LIMIT 100
            """,
            tuple(params),
        ).fetchall()
        community_posts = app_get_db().execute(
            """
            SELECT
                community_posts.*,
                users.phone_number,
                COALESCE(job_seeker_profiles.full_name, employer_profiles.company_name, '') AS author_name
            FROM community_posts
            LEFT JOIN users ON users.id = community_posts.user_id
            LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = community_posts.user_id
            LEFT JOIN employer_profiles ON employer_profiles.user_id = community_posts.user_id
            WHERE community_posts.status != 'ACTIVE' OR community_posts.report_count > 0
            ORDER BY
                CASE community_posts.status WHEN 'PENDING_REVIEW' THEN 0 WHEN 'BLOCKED' THEN 1 ELSE 2 END,
                community_posts.report_count DESC,
                datetime(community_posts.updated_at) DESC,
                community_posts.id DESC
            LIMIT 50
            """
        ).fetchall()
        return render_template("admin_moderation.html", jobs=jobs, community_posts=community_posts, q=q, status=status)

    @app.route("/scam-check")
    @app.route("/admin/scam-center")
    @role_required("ADMIN")
    def admin_scam_center():
        conn = app_get_db()

        def count(sql, params=()):
            try:
                return int(conn.execute(sql, params).fetchone()["count"] or 0)
            except Exception:
                return 0

        stats = {
            "high": count("SELECT COUNT(*) AS count FROM job_posts WHERE COALESCE(ai_risk_score, 0) >= 70"),
            "medium": count("SELECT COUNT(*) AS count FROM job_posts WHERE COALESCE(ai_risk_score, 0) >= 35 AND COALESCE(ai_risk_score, 0) < 70"),
            "low": count("SELECT COUNT(*) AS count FROM job_posts WHERE COALESCE(ai_risk_score, 0) < 35"),
            "pending": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'"),
        }
        jobs = conn.execute(
            """
            SELECT
                job_posts.*,
                users.trust_score,
                employer_profiles.company_name
            FROM job_posts
            LEFT JOIN users ON users.id = job_posts.employer_id
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE job_posts.status = 'PENDING_AI_REVIEW'
               OR COALESCE(job_posts.ai_risk_score, 0) >= 35
            ORDER BY COALESCE(job_posts.ai_risk_score, 0) DESC, datetime(job_posts.updated_at) DESC
            LIMIT 100
            """
        ).fetchall()
        try:
            logs = conn.execute(
                """
                SELECT scam_scan_logs.*, job_posts.title
                FROM scam_scan_logs
                LEFT JOIN job_posts ON job_posts.id = scam_scan_logs.job_post_id
                ORDER BY datetime(scam_scan_logs.created_at) DESC, scam_scan_logs.id DESC
                LIMIT 50
                """
            ).fetchall()
        except Exception:
            logs = []
        return render_template("admin_scam_center.html", stats=stats, jobs=jobs, logs=logs)

    @app.route("/admin/users")
    @role_required("ADMIN")
    def admin_users():
        users = app_get_db().execute(
            """
            SELECT
                users.*,
                employer_profiles.company_name,
                employer_profiles.is_company_verified,
                job_seeker_profiles.full_name AS seeker_full_name,
                COALESCE(job_counts.job_count, 0) AS job_count
            FROM users
            LEFT JOIN employer_profiles ON employer_profiles.user_id = users.id
            LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = users.id
            LEFT JOIN (
                SELECT employer_id, COUNT(*) AS job_count
                FROM job_posts
                GROUP BY employer_id
            ) AS job_counts ON job_counts.employer_id = users.id
            ORDER BY users.id DESC
            LIMIT 100
            """
        ).fetchall()
        return render_template("admin_users.html", users=users)

    @app.route("/admin/logs")
    @role_required("ADMIN")
    def admin_logs():
        conn = app_get_db()
        activity_logs = conn.execute(
            "SELECT * FROM activity_logs ORDER BY datetime(created_at) DESC, id DESC LIMIT 100"
        ).fetchall()
        ai_logs = conn.execute(
            "SELECT * FROM ai_decision_logs ORDER BY datetime(created_at) DESC, id DESC LIMIT 100"
        ).fetchall()
        return render_template("admin_logs.html", activity_logs=activity_logs, ai_logs=ai_logs)

    @app.route("/admin/import-runs")
    @role_required("ADMIN")
    def admin_import_runs():
        conn = app_get_db()
        ensure_import_run_schema(conn)

        status = request.args.get("status", "").strip().upper()
        source_filter = request.args.get("source", "").strip()

        where_clauses = []
        params = []
        if status:
            where_clauses.append("status = ?")
            params.append(status)
        if source_filter:
            where_clauses.append("lower(source_name) LIKE ?")
            params.append(f"%{source_filter.lower()}%")

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        runs = conn.execute(
            f"SELECT * FROM import_runs {where_sql} ORDER BY datetime(created_at) DESC, id DESC LIMIT 200",
            params,
        ).fetchall()
        return render_template(
            "admin_import_runs.html",
            runs=runs,
            selected_status=status,
            source_filter=source_filter,
            import_status=fetch_import_status(conn),
        )

    @app.route("/admin/trust")
    @role_required("ADMIN")
    def admin_trust_center():
        users = app_get_db().execute(
            """
            SELECT
                users.*,
                employer_profiles.company_name,
                employer_profiles.is_company_verified,
                job_seeker_profiles.full_name AS seeker_full_name,
                COALESCE(job_counts.job_count, 0) AS job_count,
                COALESCE(report_counts.reports_made, 0) AS reports_made
            FROM users
            LEFT JOIN employer_profiles ON employer_profiles.user_id = users.id
            LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = users.id
            LEFT JOIN (
                SELECT employer_id, COUNT(*) AS job_count
                FROM job_posts
                GROUP BY employer_id
            ) AS job_counts ON job_counts.employer_id = users.id
            LEFT JOIN (
                SELECT reporter_id, COUNT(*) AS reports_made
                FROM reports
                GROUP BY reporter_id
            ) AS report_counts ON report_counts.reporter_id = users.id
            ORDER BY users.trust_score ASC, users.id DESC
            LIMIT 100
            """
        ).fetchall()
        return render_template("admin_trust.html", users=users)

    @app.route("/admin/system-health")
    @role_required("ADMIN")
    def admin_system_health():
        conn = app_get_db()

        def count(sql):
            try:
                return int(conn.execute(sql).fetchone()["count"] or 0)
            except Exception:
                return 0

        db_path = DB_PATH
        import_status = {
            "last_run_at": None,
            "last_status": None,
            "total_imports": 0,
            "failed_imports": 0,
        }
        try:
            import_status = conn.execute(
                "SELECT source_name, status, created_at FROM import_runs ORDER BY datetime(created_at) DESC, id DESC LIMIT 1"
            ).fetchone() or import_status
            import_status = {
                "last_run_at": import_status["created_at"] if isinstance(import_status, sqlite3.Row) else None,
                "last_status": import_status["status"] if isinstance(import_status, sqlite3.Row) else None,
                "last_source": import_status["source_name"] if isinstance(import_status, sqlite3.Row) else None,
                "total_imports": count("SELECT COUNT(*) AS count FROM import_runs"),
                "failed_imports": count("SELECT COUNT(*) AS count FROM import_runs WHERE status != 'SUCCESS'"),
            }
        except Exception:
            import_status = {
                "last_run_at": None,
                "last_status": None,
                "last_source": None,
                "total_imports": 0,
                "failed_imports": 0,
            }
        try:
            import_status = fetch_import_status(conn)
        except Exception:
            pass

        health = {
            "checked_at": now_str(),
            "render_git_commit": os.environ.get("RENDER_GIT_COMMIT", ""),
            "render_service_name": os.environ.get("RENDER_SERVICE_NAME", ""),
            "render_external_url": os.environ.get("RENDER_EXTERNAL_URL", ""),
            "database_exists": db_path.exists(),
            "database_size": f"{db_path.stat().st_size} bytes" if db_path.exists() else "-",
            "database_path": str(db_path),
            "stats": {
                "users": count("SELECT COUNT(*) AS count FROM users"),
                "active_jobs": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'"),
                "pending_jobs": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'"),
                "rejected_jobs": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'REJECTED'"),
                "reports": count("SELECT COUNT(*) AS count FROM reports"),
                "activity_logs": count("SELECT COUNT(*) AS count FROM activity_logs"),
            },
            "env_checks": {
                "JOBBOARD_SECRET_KEY": bool(app_secret_key),
                "JOBBOARD_ADMIN_PHONE": bool(ADMIN_PHONE),
                "JOBBOARD_ADMIN_PASSWORD": bool(ADMIN_PASSWORD),
                "JOBBOARD_CRON_TOKEN": bool(JOBBOARD_CRON_TOKEN),
                "JOBBOARD_API_BASE_URL": bool(JOBBOARD_API_BASE_URL),
                "DISCORD_SCAM_ALERT_WEBHOOK_URL": bool(DISCORD_SCAM_ALERT_WEBHOOK_URL),
            },
            "jobboard_api_base_url": JOBBOARD_API_BASE_URL,
            "import_status": import_status,
        }
        return render_template("admin_system_health.html", health=health)

    @app.route("/admin/openchat-media")
    @role_required("ADMIN")
    def admin_openchat_media_review():
        requested_status = request.args.get("status", "PENDING_REVIEW").strip().upper()
        allowed_statuses = {"PENDING_REVIEW", "APPROVED", "REJECTED"}
        if requested_status not in allowed_statuses:
            requested_status = "PENDING_REVIEW"

        conn = app_get_db()
        stats = {"pending": 0, "approved": 0, "rejected": 0}
        try:
            rows = conn.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM openchat_media
                GROUP BY status
                """
            ).fetchall()
            for row in rows:
                key = str(row["status"] or "").lower().replace("_review", "")
                if key in stats:
                    stats[key] = int(row["count"] or 0)
        except Exception:
            pass

        try:
            media_items = conn.execute(
                """
                SELECT
                    openchat_media.*,
                    openchat_messages.message,
                    users.phone_number,
                    COALESCE(job_seeker_profiles.full_name, employer_profiles.company_name, '') AS author_name
                FROM openchat_media
                LEFT JOIN openchat_messages ON openchat_messages.id = openchat_media.message_id
                LEFT JOIN users ON users.id = openchat_media.user_id
                LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = openchat_media.user_id
                LEFT JOIN employer_profiles ON employer_profiles.user_id = openchat_media.user_id
                WHERE openchat_media.status = ?
                ORDER BY datetime(openchat_media.created_at) DESC, openchat_media.id DESC
                LIMIT 200
                """,
                (requested_status,),
            ).fetchall()
        except Exception:
            media_items = []

        return render_template("admin_openchat_media_review.html", stats=stats, media_items=media_items)
