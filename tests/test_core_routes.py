import os
import unittest

import app as app_module
from app import app, get_db, init_db


class CoreRoutesTestCase(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        with app.app_context():
            init_db()

    def test_public_routes(self):
        for path in ["/", "/jobs", "/news", "/urgent", "/community", "/openchat", "/guides", "/faq", "/sources", "/privacy", "/terms", "/robots.txt", "/llms.txt", "/sitemap.xml", "/login", "/register"]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)

    def test_api_jobs_returns_items(self):
        response = self.client.get("/api/jobs")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertIn("items", payload)

    def test_province_landing_route(self):
        response = self.client.get("/jobs/province/Nakhon%20Sawan")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Jobs in", response.data)

    def test_guide_detail_route(self):
        response = self.client.get("/guides/avoid-job-scams")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"How to avoid job scams", response.data)

    def test_admin_backup_download_returns_zip(self):
        with app.app_context():
            admin = get_db().execute("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1").fetchone()
            self.assertIsNotNone(admin)

        with self.client.session_transaction() as session:
            session["user_id"] = admin["id"]

        response = self.client.get("/admin/backup/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "application/zip")
        self.assertEqual(response.data[:2], b"PK")

    def test_admin_pages_render_for_admin(self):
        with app.app_context():
            admin = get_db().execute("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1").fetchone()
            self.assertIsNotNone(admin)

        with self.client.session_transaction() as session:
            session["user_id"] = admin["id"]

        for path in [
            "/admin",
            "/admin/blacklist",
            "/admin/moderation",
            "/admin/scam-center",
            "/admin/users",
            "/admin/logs",
            "/admin/import-runs",
            "/admin/trust",
            "/admin/system-health",
            "/admin/openchat-media",
        ]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)

    def test_cron_backup_requires_token(self):
        response = self.client.get("/internal/cron/backup")
        self.assertEqual(response.status_code, 403)

    def test_cron_backup_with_token(self):
        os.environ["JOBBOARD_CRON_TOKEN"] = "test-token"
        response = self.client.get("/internal/cron/backup", headers={"X-Cron-Token": "test-token"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["filename"].endswith(".zip"))

    def test_phone_otp_form_without_phone_returns_json_400(self):
        self.client.get("/login")
        with self.client.session_transaction() as session:
            csrf_token = session["_csrf_token"]

        response = self.client.post("/auth/phone-otp", data={"csrf_token": csrf_token})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Phone number required")

    def test_discord_jobs_rejects_invalid_limit(self):
        original_token = app_module.DISCORD_BOT_API_TOKEN
        app_module.DISCORD_BOT_API_TOKEN = "test-token"
        try:
            response = self.client.get(
                "/api/discord/jobs?limit=abc",
                headers={"X-Discord-Bot-Token": "test-token"},
            )
        finally:
            app_module.DISCORD_BOT_API_TOKEN = original_token

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["message"], "limit must be a number.")

    def test_admin_discord_json_post_does_not_require_form_csrf(self):
        original_webhook = app_module.DISCORD_SCAM_ALERT_WEBHOOK_URL
        app_module.DISCORD_SCAM_ALERT_WEBHOOK_URL = ""
        try:
            with app.app_context():
                admin = get_db().execute("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1").fetchone()
                self.assertIsNotNone(admin)

            with self.client.session_transaction() as session:
                session["user_id"] = admin["id"]

            response = self.client.post("/admin/discord-test", json={})
        finally:
            app_module.DISCORD_SCAM_ALERT_WEBHOOK_URL = original_webhook

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["sent"])

    def test_admin_openchat_media_review_lists_and_updates_items(self):
        with app.app_context():
            conn = get_db()
            admin = conn.execute("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1").fetchone()
            user = conn.execute("SELECT id FROM users WHERE role != 'ADMIN' LIMIT 1").fetchone()
            if user is None:
                conn.execute(
                    """
                    INSERT INTO users (phone_number, password_hash, role, full_name, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    ("0812345678", "x", "JOB_SEEKER", "Media Tester", "2026-01-01", "2026-01-01"),
                )
                user = conn.execute("SELECT id FROM users WHERE phone_number = ?", ("0812345678",)).fetchone()
            conn.execute(
                """
                INSERT INTO openchat_messages (
                    user_id, message, status, moderation_score, moderation_reason, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user["id"], "media test", "ACTIVE", 0, "", "2026-01-01", "2026-01-01"),
            )
            message_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            file_name = f"review-test-{message_id}.jpg"
            conn.execute(
                """
                INSERT INTO openchat_media (
                    message_id, user_id, file_name, original_name, file_type, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (message_id, user["id"], file_name, file_name, "IMAGE", "PENDING_REVIEW", "2026-01-01", "2026-01-01"),
            )
            media_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            conn.commit()

        with self.client.session_transaction() as session:
            session["user_id"] = admin["id"]
            session["_csrf_token"] = "test-csrf"

        response = self.client.get("/admin/openchat-media")
        self.assertEqual(response.status_code, 200)
        self.assertIn(file_name.encode(), response.data)

        response = self.client.post(
            f"/admin/openchat-media/{media_id}/approve",
            data={"csrf_token": "test-csrf"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        with app.app_context():
            status = get_db().execute("SELECT status FROM openchat_media WHERE id = ?", (media_id,)).fetchone()["status"]
        self.assertEqual(status, "APPROVED")

    def test_notifications_api_and_mark_read(self):
        with app.app_context():
            conn = get_db()
            user = conn.execute("SELECT id FROM users WHERE role != 'ADMIN' LIMIT 1").fetchone()
            if user is None:
                conn.execute(
                    """
                    INSERT INTO users (phone_number, password_hash, role, full_name, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    ("0899999999", "x", "JOB_SEEKER", "Notify Tester", "2026-01-01", "2026-01-01"),
                )
                user = conn.execute("SELECT id FROM users WHERE phone_number = ?", ("0899999999",)).fetchone()
            conn.execute(
                """
                INSERT INTO notifications (user_id, title, message, link_url, category, is_read, created_at)
                VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                (user["id"], "Test notice", "Body", "/dashboard", "SYSTEM", "2026-01-01"),
            )
            notification_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            conn.commit()

        with self.client.session_transaction() as session:
            session["user_id"] = user["id"]
            session["_csrf_token"] = "notify-csrf"

        response = self.client.get("/api/notifications")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(payload["unread"], 1)

        response = self.client.post(
            "/api/notifications/mark-read",
            data={"csrf_token": "notify-csrf", "notification_id": str(notification_id)},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])

        with app.app_context():
            row = get_db().execute("SELECT is_read FROM notifications WHERE id = ?", (notification_id,)).fetchone()
        self.assertEqual(row["is_read"], 1)

    def test_dashboard_redirects_by_role(self):
        with app.app_context():
            conn = get_db()
            admin = conn.execute("SELECT id FROM users WHERE role = 'ADMIN' LIMIT 1").fetchone()
            seeker = conn.execute("SELECT id FROM users WHERE role = 'JOB_SEEKER' LIMIT 1").fetchone()
            employer = conn.execute("SELECT id FROM users WHERE role = 'EMPLOYER' LIMIT 1").fetchone()
            if employer is None:
                conn.execute(
                    """
                    INSERT INTO users (phone_number, password_hash, role, full_name, trust_score, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("0822222222", "x", "EMPLOYER", "Employer Tester", 80, "2026-01-01", "2026-01-01"),
                )
                employer = conn.execute("SELECT id FROM users WHERE phone_number = ?", ("0822222222",)).fetchone()
                conn.execute(
                    """
                    INSERT INTO employer_profiles (user_id, company_name, tax_id, is_company_verified, address, website, created_at, updated_at)
                    VALUES (?, ?, ?, 0, '', '', ?, ?)
                    """,
                    (employer["id"], "Employer Tester Co", f"EMP-{employer['id']}", "2026-01-01", "2026-01-01"),
                )
                conn.commit()

        for user_id, expected_path in [
            (admin["id"], "/admin"),
            (seeker["id"], "/dashboard/job-seeker"),
            (employer["id"], "/dashboard/employer"),
        ]:
            with self.subTest(expected_path=expected_path):
                with self.client.session_transaction() as session:
                    session["user_id"] = user_id
                response = self.client.get("/dashboard", follow_redirects=False)
                self.assertEqual(response.status_code, 302)
                self.assertIn(expected_path, response.headers["Location"])

    def test_unread_messages_api(self):
        with app.app_context():
            conn = get_db()
            receiver = conn.execute("SELECT id FROM users WHERE role != 'ADMIN' LIMIT 1").fetchone()
            sender = conn.execute("SELECT id FROM users WHERE id != ? LIMIT 1", (receiver["id"],)).fetchone()
            conn.execute(
                """
                INSERT INTO messages (sender_id, receiver_id, application_id, message, is_read, created_at)
                VALUES (?, ?, NULL, ?, 0, ?)
                """,
                (sender["id"], receiver["id"], "hello", "2026-01-01"),
            )
            conn.commit()

        with self.client.session_transaction() as session:
            session["user_id"] = receiver["id"]

        response = self.client.get("/api/messages/unread-count")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(payload["unread"], 1)


if __name__ == "__main__":
    unittest.main()
