import sqlite3


def register_dashboard_routes(app, deps):
    login_required = deps["login_required"]
    abort = deps["abort"]
    redirect = deps["redirect"]
    render_template = deps["render_template"]
    request = deps["request"]
    url_for = deps["url_for"]
    datetime = deps["datetime"]
    timedelta = deps["timedelta"]
    get_current_user = deps["get_current_user"]
    get_db = deps["get_db"]
    now_str = deps["now_str"]
    fetch_template_jobs = deps["_fetch_template_jobs"]
    get_trust_level = deps["get_trust_level"]
    validate_profile_name = deps["validate_profile_name"]
    analyze_job_content = deps["analyze_job_content"]
    canonical_job_position = deps["_canonical_job_position"]
    extract_skill_tags = deps["_extract_skill_tags"]
    add_activity_log = deps["add_activity_log"]
    run_matching_for_job = deps["_run_matching_for_job"]
    create_notification = deps["create_notification"]

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = get_current_user()
        if user and user["role"] == "ADMIN":
            return redirect(url_for("admin_dashboard"))
        if user and user["role"] == "EMPLOYER":
            return redirect(url_for("employer_dashboard"))
        return redirect(url_for("job_seeker_dashboard"))

    @app.route("/dashboard/job-seeker")
    @login_required
    def job_seeker_dashboard():
        user = get_current_user()
        conn = get_db()
        profile = conn.execute(
            "SELECT * FROM job_seeker_profiles WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
        applications = conn.execute(
            """
            SELECT
                applications.*,
                job_posts.title,
                job_posts.location,
                employer_profiles.company_name
            FROM applications
            JOIN job_posts ON job_posts.id = applications.job_post_id
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE applications.job_seeker_id = ?
            ORDER BY datetime(applications.created_at) DESC, applications.id DESC
            """,
            (user["id"],),
        ).fetchall()
        recommended_jobs = fetch_template_jobs(limit=6, status="ACTIVE")
        return render_template(
            "dashboard_job_seeker.html",
            user=user,
            profile=profile,
            applications=applications,
            recommended_jobs=recommended_jobs,
        )

    @app.route("/employer/dashboard")
    @app.route("/dashboard/employer")
    @login_required
    def employer_dashboard():
        user = get_current_user()
        if user["role"] != "EMPLOYER":
            abort(403)
        conn = get_db()
        profile = conn.execute(
            "SELECT * FROM employer_profiles WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
        jobs = conn.execute(
            """
            SELECT job_posts.*, employer_profiles.company_name, employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE job_posts.employer_id = ?
            ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
            """,
            (user["id"],),
        ).fetchall()
        applications = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM applications
            JOIN job_posts ON job_posts.id = applications.job_post_id
            WHERE job_posts.employer_id = ?
            """,
            (user["id"],),
        ).fetchone()["count"]

        live_viewers = {}
        application_counts = {}
        job_ids = [job["id"] for job in jobs if job["id"] is not None]
        if job_ids:
            placeholders = ",".join("?" for _ in job_ids)
            cutoff = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            rows = conn.execute(
                f"SELECT job_id, COUNT(*) AS count FROM job_views WHERE job_id IN ({placeholders}) AND viewed_at >= ? GROUP BY job_id",
                tuple(job_ids + [cutoff]),
            ).fetchall()
            live_viewers = {row["job_id"]: int(row["count"] or 0) for row in rows}

            rows = conn.execute(
                f"SELECT job_post_id, COUNT(*) AS count FROM applications WHERE job_post_id IN ({placeholders}) GROUP BY job_post_id",
                tuple(job_ids),
            ).fetchall()
            application_counts = {row["job_post_id"]: int(row["count"] or 0) for row in rows}

        return render_template(
            "dashboard_employer.html",
            user=user,
            profile=profile,
            jobs=jobs,
            applications=applications,
            trust_level=get_trust_level(user["trust_score"]),
            live_viewers=live_viewers,
            application_counts=application_counts,
        )

    @app.route("/post-job", methods=["GET", "POST"])
    @app.route("/employer/jobs/new", methods=["GET", "POST"])
    @login_required
    def employer_create_job():
        user = get_current_user()
        if user["role"] != "EMPLOYER":
            abort(403)
        locked = int(user["trust_score"] or 0) < 20 or int(user["is_banned"] or 0)
        error = ""
        preview = None
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            salary_range = request.form.get("salary_range", "").strip()
            location = request.form.get("location", "").strip()
            is_urgent = 1 if request.form.get("is_urgent") else 0
            preview = {
                "title": title,
                "description": description,
                "salary_range": salary_range,
                "location": location,
                "is_urgent": is_urgent,
            }

            if locked:
                error = "Account is not ready to post jobs"
            elif len(title) < 5:
                error = "Please enter a longer job title"
            elif len(description) < 40:
                error = "Job description should be at least 40 characters"
            else:
                ok, message = validate_profile_name(title, "Job title", 160)
                if not ok:
                    error = message

            if not error:
                score, status, reason = analyze_job_content(
                    title,
                    description,
                    salary_range,
                    location,
                    user["trust_score"],
                    0,
                )
                conn = get_db()
                current_time = now_str()
                canonical_position = canonical_job_position(title, description)
                required_skills = extract_skill_tags(title, description)
                cur = conn.execute(
                    """
                    INSERT INTO job_posts (
                        employer_id, title, description, salary_range, location,
                        is_government_news, source_url, status, ai_risk_score,
                        ai_risk_reason, report_count, created_at, updated_at, is_urgent,
                        canonical_position, required_skills, job_type
                    )
                    VALUES (?, ?, ?, ?, ?, 0, '', ?, ?, ?, 0, ?, ?, ?, ?, ?, '')
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
                        is_urgent,
                        canonical_position,
                        required_skills,
                    ),
                )
                job_id = cur.lastrowid
                conn.execute(
                    """
                    INSERT INTO ai_decision_logs (job_post_id, title, risk_score, risk_reason, final_status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (job_id, title, score, reason, status, current_time),
                )
                add_activity_log(user["id"], "CREATE_JOB", "job_posts", job_id, f"status={status}, risk={score}")
                conn.commit()
                if status == "ACTIVE":
                    run_matching_for_job(job_id)
                return redirect(url_for("job_detail", slug=str(job_id)))

        return render_template("employer_job_form.html", job=None, error=error, locked=locked, preview=preview)

    @app.route("/employer/applications")
    @login_required
    def employer_applications():
        user = get_current_user()
        if user["role"] != "EMPLOYER":
            abort(403)
        applications = get_db().execute(
            """
            SELECT
                applications.*,
                applications.job_seeker_id,
                job_posts.title AS job_title,
                job_posts.location AS job_location,
                users.phone_number AS applicant_phone,
                job_seeker_profiles.full_name,
                job_seeker_profiles.headline,
                job_seeker_profiles.resume_url
            FROM applications
            JOIN job_posts ON job_posts.id = applications.job_post_id
            JOIN users ON users.id = applications.job_seeker_id
            LEFT JOIN job_seeker_profiles ON job_seeker_profiles.user_id = applications.job_seeker_id
            WHERE job_posts.employer_id = ?
            ORDER BY datetime(applications.created_at) DESC, applications.id DESC
            """,
            (user["id"],),
        ).fetchall()
        return render_template("employer_applications.html", applications=applications)

    @app.route("/employer/applications/<int:application_id>/<action>", methods=["POST"])
    @login_required
    def employer_update_application(application_id, action):
        user = get_current_user()
        if user["role"] != "EMPLOYER":
            abort(403)
        status_map = {
            "review": "REVIEWING",
            "shortlist": "SHORTLISTED",
            "reject": "REJECTED",
            "accept": "ACCEPTED",
        }
        new_status = status_map.get(action)
        if not new_status:
            abort(404)

        row = get_db().execute(
            """
            SELECT applications.*, job_posts.employer_id, job_posts.title
            FROM applications
            JOIN job_posts ON job_posts.id = applications.job_post_id
            WHERE applications.id = ?
            """,
            (application_id,),
        ).fetchone()
        if not row or row["employer_id"] != user["id"]:
            abort(404)

        get_db().execute(
            "UPDATE applications SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, now_str(), application_id),
        )
        create_notification(
            row["job_seeker_id"],
            "Application status updated",
            f"Your application for {row['title']} is now {new_status}",
            url_for("job_seeker_dashboard"),
            "APPLICATION",
        )
        add_activity_log(user["id"], "UPDATE_APPLICATION", "applications", application_id, new_status)
        get_db().commit()
        return redirect(url_for("employer_applications"))

    @app.route("/job-seeker/post", methods=["GET", "POST"])
    @login_required
    def job_seeker_post():
        user = get_current_user()
        if user["role"] != "JOB_SEEKER":
            abort(403)
        if request.method == "POST":
            return redirect(url_for("job_seeker_post"))
        profile = get_db().execute(
            "SELECT * FROM job_seeker_profiles WHERE user_id = ?",
            (user["id"],),
        ).fetchone()
        applications = get_db().execute(
            """
            SELECT applications.*, job_posts.title, job_posts.location, employer_profiles.company_name
            FROM applications
            JOIN job_posts ON job_posts.id = applications.job_post_id
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE applications.job_seeker_id = ?
            ORDER BY datetime(applications.created_at) DESC, applications.id DESC
            """,
            (user["id"],),
        ).fetchall()
        return render_template("job_seeker_post.html", profile=profile, applications=applications)

    @app.route("/applications/<int:job_id>", methods=["POST"])
    @login_required
    def apply_job(job_id):
        user = get_current_user()
        if user["role"] != "JOB_SEEKER":
            abort(403)

        job = get_db().execute(
            "SELECT * FROM job_posts WHERE id = ? AND status = 'ACTIVE'",
            (job_id,),
        ).fetchone()
        if not job:
            abort(404)

        message = request.form.get("message", "").strip()[:1000]
        current_time = now_str()
        try:
            get_db().execute(
                """
                INSERT INTO applications (job_seeker_id, job_post_id, status, message, created_at, updated_at)
                VALUES (?, ?, 'PENDING', ?, ?, ?)
                """,
                (user["id"], job_id, message, current_time, current_time),
            )
            create_notification(
                job["employer_id"],
                "New application received",
                f"You have a new application for {job['title']}",
                url_for("employer_applications"),
                "APPLICATION",
            )
            add_activity_log(user["id"], "APPLY_JOB", "job_posts", job_id, "")
            get_db().commit()
        except sqlite3.IntegrityError:
            pass
        return redirect(url_for("job_detail_old", job_id=job_id))
