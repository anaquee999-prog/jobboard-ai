def register_notification_routes(app, deps):
    login_required = deps["login_required"]
    render_template = deps["render_template"]
    request = deps["request"]
    jsonify = deps["jsonify"]
    url_for = deps["url_for"]
    get_current_user = deps["get_current_user"]
    get_db = deps["get_db"]
    ensure_notification_schema = deps["ensure_notification_schema"]
    now_str = deps["now_str"]
    create_notification = deps["create_notification"]
    get_recent_notifications = deps["get_recent_notifications"]
    get_unread_notifications_count = deps["get_unread_notifications_count"]

    @app.route("/notifications")
    @login_required
    def notifications_page():
        user = get_current_user()
        ensure_notification_schema()
        conn = get_db()

        items = conn.execute(
            """
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY is_read ASC, datetime(created_at) DESC, id DESC
            LIMIT 50
            """,
            (user["id"],),
        ).fetchall()

        return render_template("notifications.html", notifications=items, user=user)

    @app.route("/notifications/settings", methods=["GET", "POST"])
    @login_required
    def notification_settings():
        user = get_current_user()
        ensure_notification_schema()
        error = ""
        success = ""

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            wants_email = 1 if request.form.get("wants_email_alerts") else 0
            wants_web = 1 if request.form.get("wants_web_alerts") else 0
            browser_enabled = 1 if request.form.get("browser_notifications_enabled") else 0

            if email and ("@" not in email or "." not in email.split("@")[-1]):
                error = "Invalid email format"
            else:
                conn = get_db()
                conn.execute(
                    """
                    UPDATE users
                    SET email = ?,
                        wants_email_alerts = ?,
                        wants_web_alerts = ?,
                        browser_notifications_enabled = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (email, wants_email, wants_web, browser_enabled, now_str(), user["id"]),
                )
                conn.commit()

                create_notification(
                    user["id"],
                    "Notification settings updated",
                    "Your notification preferences have been saved.",
                    url_for("notifications_page"),
                    "SETTINGS",
                )
                success = "Notification settings saved"
                user = get_current_user()

        return render_template("notification_settings.html", user=user, error=error, success=success)

    @app.route("/api/notifications")
    def api_notifications():
        ensure_notification_schema()
        user = get_current_user()
        unread = 0

        if user:
            items = get_recent_notifications(user["id"], 10)
            unread = get_unread_notifications_count(user["id"])
        else:
            items = get_db().execute(
                """
                SELECT
                    id,
                    action AS title,
                    detail AS message,
                    '' AS link_url,
                    target_type AS category,
                    1 AS is_read,
                    created_at
                FROM activity_logs
                ORDER BY datetime(created_at) DESC, id DESC
                LIMIT 10
                """
            ).fetchall()

        return jsonify(
            {
                "ok": True,
                "unread": unread,
                "items": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "message": row["message"],
                        "link_url": row["link_url"],
                        "category": row["category"],
                        "is_read": bool(row["is_read"]),
                        "created_at": row["created_at"],
                    }
                    for row in items
                ],
            }
        )

    @app.route("/api/notifications/mark-read", methods=["POST"])
    @login_required
    def api_notifications_mark_read():
        user = get_current_user()
        ensure_notification_schema()
        conn = get_db()
        current_time = now_str()

        notification_id = request.form.get("notification_id", "").strip()

        if notification_id:
            conn.execute(
                """
                UPDATE notifications
                SET is_read = 1, read_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (current_time, notification_id, user["id"]),
            )
        else:
            conn.execute(
                """
                UPDATE notifications
                SET is_read = 1, read_at = ?
                WHERE user_id = ? AND is_read = 0
                """,
                (current_time, user["id"]),
            )

        conn.commit()
        return {"ok": True, "unread": get_unread_notifications_count(user["id"])}

    @app.route("/api/notifications/browser-enabled", methods=["POST"])
    @login_required
    def api_notifications_browser_enabled():
        user = get_current_user()
        ensure_notification_schema()
        conn = get_db()
        conn.execute(
            """
            UPDATE users
            SET browser_notifications_enabled = 1,
                wants_web_alerts = 1,
                updated_at = ?
            WHERE id = ?
            """,
            (now_str(), user["id"]),
        )
        conn.commit()

        create_notification(
            user["id"],
            "Browser notifications enabled",
            "We'll send browser alerts when important updates are available.",
            url_for("notifications_page"),
            "SETTINGS",
        )

        return {"ok": True}
