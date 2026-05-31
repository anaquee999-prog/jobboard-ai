import os


def register_admin_action_routes(app, deps):
    role_required = deps["role_required"]
    Response = deps["Response"]
    abort = deps["abort"]
    jsonify = deps["jsonify"]
    redirect = deps["redirect"]
    request = deps["request"]
    url_for = deps["url_for"]
    requests = deps["requests"]
    io = deps["io"]
    zipfile = deps["zipfile"]
    secure_filename = deps["secure_filename"]
    BASE_DIR = deps["BASE_DIR"]
    OPENCHAT_UPLOAD_DIR = deps["OPENCHAT_UPLOAD_DIR"]
    get_discord_webhook_url = deps["get_discord_webhook_url"]
    app_get_current_user = deps["get_current_user"]
    app_get_db = deps["get_db"]
    add_activity_log = deps["add_activity_log"]
    now_str = deps["now_str"]
    send_discord_alert = deps["send_discord_alert"]
    record_import_run = deps["_record_import_run"]
    repair_job_source_urls_to_official = deps["repair_job_source_urls_to_official"]
    cron_token_is_valid = deps["_cron_token_is_valid"]
    redirect_back = deps["_redirect_back"]

    json = deps["json"]
    datetime = deps["datetime"]
    timezone = deps["timezone"]

    def build_backup_zip():
        backup_buffer = io.BytesIO()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"jobboard-backup-{timestamp}.zip"
        include_files = [
            "app.py",
            "auth_module.py",
            "otp_handler.py",
            "requirements.txt",
            "render.yaml",
            "Procfile",
            ".env.example",
            "cloudflare_automation.py",
            "run_cloudflare_automation.ps1",
        ]
        include_dirs = ["templates", "static"]
        database_path = BASE_DIR / os.environ.get("JOBBOARD_DATABASE_PATH", "instance/jobboard.db")

        with zipfile.ZipFile(backup_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            manifest = {
                "created_at_utc": timestamp,
                "site_url": deps["SITE_URL"],
                "database_path": str(database_path.relative_to(BASE_DIR)) if database_path.exists() else "",
                "notes": "Runtime secrets from .env are intentionally excluded.",
            }
            archive.writestr("backup_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))

            if database_path.exists():
                archive.write(database_path, database_path.relative_to(BASE_DIR).as_posix())

            for relative_name in include_files:
                file_path = BASE_DIR / relative_name
                if file_path.exists() and file_path.is_file():
                    archive.write(file_path, relative_name)

            for relative_dir in include_dirs:
                dir_path = BASE_DIR / relative_dir
                if not dir_path.exists():
                    continue
                for file_path in dir_path.rglob("*"):
                    if file_path.is_file():
                        archive.write(file_path, file_path.relative_to(BASE_DIR).as_posix())

        backup_buffer.seek(0)
        return filename, backup_buffer.getvalue()

    @app.route("/admin/backup/download")
    @role_required("ADMIN")
    def admin_backup_download():
        filename, backup_bytes = build_backup_zip()
        return Response(
            backup_bytes,
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.route("/internal/cron/backup", methods=["GET", "POST"])
    def cron_backup_database():
        if not cron_token_is_valid():
            abort(403)

        filename, backup_bytes = build_backup_zip()
        backup_dir = BASE_DIR / os.environ.get("JOBBOARD_BACKUP_DIR", "instance/backups")
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / filename
        backup_path.write_bytes(backup_bytes)

        return jsonify(
            {
                "ok": True,
                "filename": filename,
                "path": str(backup_path.relative_to(BASE_DIR)),
                "size_bytes": len(backup_bytes),
                "created_at": now_str(),
            }
        )

    @app.route("/admin/discord-test", methods=["GET", "POST"])
    def admin_discord_test():
        automation_allowed = os.environ.get("JOBBOARD_ALLOW_UNAUTH_DISCORD_TEST", "0") == "1"
        wants_json = request.method == "POST" or "application/json" in request.headers.get("Accept", "")

        if not automation_allowed:
            user = app_get_current_user()
            if not user:
                if wants_json:
                    return jsonify({"ok": False, "message": "Admin login required."}), 401
                return redirect(url_for("login"))
            if user["role"] != "ADMIN":
                abort(403)

        discord_webhook_url = get_discord_webhook_url()
        if not discord_webhook_url:
            message = "DISCORD_SCAM_ALERT_WEBHOOK_URL is not configured; webhook send was skipped."
            if wants_json:
                return jsonify({"ok": True, "sent": False, "message": message})
            return redirect(url_for("admin_system_health"))

        payload = {
            "content": "JobBoard AI Anti-Scam Discord webhook test: admin alert pipeline is working."
        }

        try:
            response = requests.post(discord_webhook_url, json=payload, timeout=10)
            response.raise_for_status()
        except Exception as exc:
            if wants_json:
                return jsonify({"ok": False, "sent": False, "message": f"Discord webhook failed: {exc}"}), 502
            return redirect(url_for("admin_system_health"))

        if wants_json:
            return jsonify({"ok": True, "sent": True, "message": "Discord webhook test sent successfully."})
        return redirect(url_for("admin_system_health"))

    @app.route("/admin/import-upper-central-jobs", methods=["POST"])
    @role_required("ADMIN")
    def admin_import_upper_central_jobs():
        try:
            from auto_job_engine import run_live

            result = run_live()
            add_activity_log(app_get_current_user()["id"], "ADMIN_IMPORT_DOE_NEWS", "job_posts", None, str(result))
            app_get_db().commit()
        except Exception as exc:
            record_import_run("ADMIN_IMPORT_DOE_NEWS", "ERROR", error_message=str(exc))
            add_activity_log(app_get_current_user()["id"], "ADMIN_IMPORT_DOE_NEWS_FAILED", "job_posts", None, str(exc))
            send_discord_alert(
                "Admin DOE import failed\n"
                f"Error: {str(exc)[:500]}\n"
                f"Time: {now_str()}",
                username="JobBoard Admin Import Bot",
            )
            app_get_db().commit()
        return redirect(url_for("admin_import_runs"))

    @app.route("/admin/import-latest-doe-news", methods=["POST"])
    @role_required("ADMIN")
    def admin_import_latest_doe_news():
        return admin_import_upper_central_jobs()

    @app.route("/admin/repair-doe-source-links", methods=["POST"])
    @role_required("ADMIN")
    def admin_repair_doe_source_links():
        fixed = repair_job_source_urls_to_official()
        add_activity_log(
            app_get_current_user()["id"],
            "ADMIN_REPAIR_DOE_SOURCE_LINKS",
            "job_posts",
            None,
            f"fixed={fixed}",
        )
        app_get_db().commit()
        return redirect(url_for("admin_import_runs"))

    @app.route("/admin/fetch-government-news", methods=["POST"])
    @role_required("ADMIN")
    def admin_fetch_government_news():
        try:
            from auto_job_engine import run_live

            result = run_live()
            add_activity_log(
                app_get_current_user()["id"],
                "ADMIN_FETCH_GOVERNMENT_NEWS",
                "job_posts",
                None,
                str(result),
            )
            app_get_db().commit()
        except Exception as exc:
            record_import_run("ADMIN_FETCH_GOVERNMENT_NEWS", "ERROR", error_message=str(exc))
            add_activity_log(
                app_get_current_user()["id"],
                "ADMIN_FETCH_GOVERNMENT_NEWS_FAILED",
                "job_posts",
                None,
                str(exc),
            )
            send_discord_alert(
                "Admin government news import failed\n"
                f"Error: {str(exc)[:500]}\n"
                f"Time: {now_str()}",
                username="JobBoard Admin Import Bot",
            )
            app_get_db().commit()
        return redirect(url_for("admin_dashboard"))

    @app.route("/admin/scam-center/run", methods=["POST"])
    @role_required("ADMIN")
    def admin_run_scam_scanner():
        try:
            from scam_engine import scan_all_jobs

            result = scan_all_jobs(apply_changes=True)
            add_activity_log(
                app_get_current_user()["id"],
                "RUN_SCAM_SCANNER",
                "job_posts",
                None,
                str(result),
            )
            app_get_db().commit()
        except Exception as exc:
            add_activity_log(app_get_current_user()["id"], "RUN_SCAM_SCANNER_FAILED", "job_posts", None, str(exc))
            app_get_db().commit()
        return redirect(url_for("admin_scam_center"))

    @app.route("/admin/jobs/<int:job_id>/<action>", methods=["POST"])
    @role_required("ADMIN")
    def admin_update_job_status(job_id, action):
        status_map = {
            "approve": "ACTIVE",
            "review": "PENDING_AI_REVIEW",
            "reject": "REJECTED",
            "close": "CLOSED",
        }
        status = status_map.get(action)
        if not status:
            abort(404)
        app_get_db().execute(
            "UPDATE job_posts SET status = ?, updated_at = ? WHERE id = ?",
            (status, now_str(), job_id),
        )
        add_activity_log(app_get_current_user()["id"], "ADMIN_UPDATE_JOB_STATUS", "job_posts", job_id, status)
        app_get_db().commit()
        return redirect_back("admin_moderation")

    @app.route("/admin/jobs/<int:job_id>/delete", methods=["POST"])
    @role_required("ADMIN")
    def admin_delete_job(job_id):
        app_get_db().execute("DELETE FROM job_posts WHERE id = ?", (job_id,))
        add_activity_log(app_get_current_user()["id"], "ADMIN_DELETE_JOB", "job_posts", job_id, "")
        app_get_db().commit()
        return redirect(url_for("admin_moderation"))

    @app.route("/admin/community-posts/<int:post_id>/<action>", methods=["POST"])
    @role_required("ADMIN")
    def admin_update_community_post(post_id, action):
        status_map = {
            "approve": "ACTIVE",
            "review": "PENDING_REVIEW",
            "block": "BLOCKED",
        }
        if action == "delete":
            app_get_db().execute("DELETE FROM community_posts WHERE id = ?", (post_id,))
            add_activity_log(app_get_current_user()["id"], "ADMIN_DELETE_COMMUNITY_POST", "community_posts", post_id, "")
            app_get_db().commit()
            return redirect(url_for("admin_moderation"))

        status = status_map.get(action)
        if not status:
            abort(404)
        app_get_db().execute(
            "UPDATE community_posts SET status = ?, updated_at = ? WHERE id = ?",
            (status, now_str(), post_id),
        )
        add_activity_log(app_get_current_user()["id"], "ADMIN_UPDATE_COMMUNITY_POST", "community_posts", post_id, status)
        app_get_db().commit()
        return redirect(url_for("admin_moderation"))

    @app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
    @role_required("ADMIN")
    def admin_ban_user(user_id):
        app_get_db().execute("UPDATE users SET is_banned = 1, updated_at = ? WHERE id = ?", (now_str(), user_id))
        add_activity_log(app_get_current_user()["id"], "ADMIN_BAN_USER", "users", user_id, "")
        app_get_db().commit()
        return redirect_back("admin_users")

    @app.route("/admin/users/<int:user_id>/unban", methods=["POST"])
    @role_required("ADMIN")
    def admin_unban_user(user_id):
        app_get_db().execute("UPDATE users SET is_banned = 0, updated_at = ? WHERE id = ?", (now_str(), user_id))
        add_activity_log(app_get_current_user()["id"], "ADMIN_UNBAN_USER", "users", user_id, "")
        app_get_db().commit()
        return redirect_back("admin_users")

    @app.route("/admin/users/<int:user_id>/verify-employer", methods=["POST"])
    @role_required("ADMIN")
    def admin_verify_employer(user_id):
        app_get_db().execute(
            "UPDATE employer_profiles SET is_company_verified = 1, updated_at = ? WHERE user_id = ?",
            (now_str(), user_id),
        )
        app_get_db().execute(
            "UPDATE users SET trust_score = min(100, trust_score + 15), updated_at = ? WHERE id = ?",
            (now_str(), user_id),
        )
        add_activity_log(app_get_current_user()["id"], "ADMIN_VERIFY_EMPLOYER", "users", user_id, "")
        app_get_db().commit()
        return redirect(url_for("admin_trust_center"))

    @app.route("/admin/users/<int:user_id>/unverify-employer", methods=["POST"])
    @role_required("ADMIN")
    def admin_unverify_employer(user_id):
        app_get_db().execute(
            "UPDATE employer_profiles SET is_company_verified = 0, updated_at = ? WHERE user_id = ?",
            (now_str(), user_id),
        )
        add_activity_log(app_get_current_user()["id"], "ADMIN_UNVERIFY_EMPLOYER", "users", user_id, "")
        app_get_db().commit()
        return redirect(url_for("admin_trust_center"))

    @app.route("/admin/users/<int:user_id>/trust/<action>", methods=["POST"])
    @role_required("ADMIN")
    def admin_update_trust(user_id, action):
        delta_map = {"increase": 10, "decrease": -10, "reset": None}
        if action not in delta_map:
            abort(404)
        if delta_map[action] is None:
            app_get_db().execute(
                "UPDATE users SET trust_score = 50, updated_at = ? WHERE id = ?",
                (now_str(), user_id),
            )
        else:
            app_get_db().execute(
                "UPDATE users SET trust_score = max(0, min(100, trust_score + ?)), updated_at = ? WHERE id = ?",
                (delta_map[action], now_str(), user_id),
            )
        add_activity_log(app_get_current_user()["id"], "ADMIN_UPDATE_TRUST", "users", user_id, action)
        app_get_db().commit()
        return redirect(url_for("admin_trust_center"))

    @app.route("/admin/openchat-media/<int:media_id>/<action>", methods=["POST"])
    @role_required("ADMIN")
    def admin_update_openchat_media_review(media_id, action):
        action_map = {"approve": "APPROVED", "reject": "REJECTED"}
        conn = app_get_db()
        item = conn.execute("SELECT * FROM openchat_media WHERE id = ?", (media_id,)).fetchone()
        if not item:
            abort(404)

        user = app_get_current_user()
        current_time = now_str()
        if action in action_map:
            conn.execute(
                """
                UPDATE openchat_media
                SET status = ?, reviewed_by = ?, review_note = ?, updated_at = ?
                WHERE id = ?
                """,
                (action_map[action], user["id"], action, current_time, media_id),
            )
            add_activity_log(user["id"], "ADMIN_REVIEW_OPENCHAT_MEDIA", "openchat_media", media_id, action)
        elif action == "delete":
            file_path = OPENCHAT_UPLOAD_DIR / secure_filename(item["file_name"])
            conn.execute("DELETE FROM openchat_media WHERE id = ?", (media_id,))
            if file_path.exists() and file_path.is_file() and file_path.parent == OPENCHAT_UPLOAD_DIR:
                try:
                    file_path.unlink()
                except OSError:
                    pass
            add_activity_log(user["id"], "ADMIN_DELETE_OPENCHAT_MEDIA", "openchat_media", media_id, item["file_name"])
        else:
            abort(404)

        conn.commit()
        return redirect(url_for("admin_openchat_media_review"))
