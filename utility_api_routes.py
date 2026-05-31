def register_utility_api_routes(app, deps):
    jsonify = deps["jsonify"]
    render_template = deps["render_template"]
    request = deps["request"]
    requests = deps["requests"]
    url_for = deps["url_for"]
    get_db = deps["get_db"]
    get_job_view_count = deps["get_job_view_count"]
    get_live_viewers = deps["get_live_viewers"]
    ensure_analytics_schema = deps["ensure_analytics_schema"]
    now_str = deps["now_str"]
    init_db = deps["init_db"]
    api_job_rows = deps["_api_job_rows"]
    with_job_seo_fields = deps["_with_job_seo_fields"]
    trust_distribution = deps["_trust_distribution"]
    FAQ_ITEMS = deps["FAQ_ITEMS"]
    CONTENT_GUIDES = deps["CONTENT_GUIDES"]
    SITE_URL = deps["SITE_URL"]
    AI_SEARCH_API_ENDPOINT = deps["AI_SEARCH_API_ENDPOINT"]
    SEO_SITE_NAME = deps["SEO_SITE_NAME"]
    SEO_CITY = deps["SEO_CITY"]
    SEO_REGION = deps["SEO_REGION"]
    SEO_COUNTRY = deps["SEO_COUNTRY"]
    job_slug = deps["job_slug"]

    def local_ai_search(query, limit=8):
        query = str(query or "").strip()
        if not query:
            return []

        normalized_limit = max(1, min(int(limit or 8), 12))
        like = f"%{query}%"
        results = []

        for item in FAQ_ITEMS:
            haystack = f"{item['question']} {item['answer']}".lower()
            if query.lower() in haystack:
                results.append(
                    {
                        "type": "faq",
                        "title": item["question"],
                        "answer": item["answer"],
                        "url": f"{SITE_URL}/faq",
                    }
                )

        for guide in CONTENT_GUIDES:
            haystack = " ".join([guide["title"], guide["description"], *guide.get("sections", [])]).lower()
            if query.lower() in haystack:
                results.append(
                    {
                        "type": "guide",
                        "title": guide["title"],
                        "answer": guide["description"],
                        "url": f"{SITE_URL}{url_for('content_guide_detail', slug=guide['slug'])}",
                    }
                )

        try:
            rows = get_db().execute(
                """
                SELECT
                    job_posts.id,
                    job_posts.title,
                    job_posts.description,
                    job_posts.location,
                    employer_profiles.company_name
                FROM job_posts
                LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
                WHERE job_posts.status = 'ACTIVE'
                  AND (
                    job_posts.title LIKE ?
                    OR job_posts.description LIKE ?
                    OR job_posts.location LIKE ?
                    OR employer_profiles.company_name LIKE ?
                  )
                ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
                LIMIT ?
                """,
                (like, like, like, like, normalized_limit),
            ).fetchall()
            for row in rows:
                results.append(
                    {
                        "type": "job",
                        "title": row["title"],
                        "answer": str(row["description"] or "")[:220],
                        "location": row["location"] or "",
                        "url": f"{SITE_URL}{url_for('job_detail', slug=job_slug(row))}",
                    }
                )
        except Exception:
            pass

        return results[:normalized_limit]

    @app.route("/api/jobs")
    def api_jobs():
        items = [with_job_seo_fields(item) for item in api_job_rows(limit=100)]
        stats = {
            "total_jobs": len(items),
            "high_risk_jobs": sum(1 for item in items if item["risk_level"] == "HIGH"),
            "scam_jobs": sum(1 for item in items if item["risk_level"] == "HIGH"),
            "urgent_jobs": sum(1 for item in items if item["is_urgent"]),
            "safe_jobs": sum(1 for item in items if item["risk_level"] == "LOW"),
        }
        return jsonify({"ok": True, "stats": stats, "items": items, "jobs": items})

    @app.route("/api/jobs/<int:job_id>")
    def api_job_detail(job_id):
        items = [with_job_seo_fields(item) for item in api_job_rows(limit=500)]
        job = next((item for item in items if int(item["id"]) == int(job_id)), None)
        if not job:
            return jsonify({"ok": False, "message": "Job not found."}), 404
        return jsonify({"ok": True, "job": job})

    @app.route("/api/job-views/<int:job_id>")
    def api_job_views(job_id):
        job = get_db().execute("SELECT id FROM job_posts WHERE id = ?", (job_id,)).fetchone()
        if not job:
            return jsonify({"ok": False, "message": "Job not found."}), 404
        return jsonify(
            {
                "ok": True,
                "job_id": job_id,
                "total_views": get_job_view_count(job_id),
                "live_viewers": get_live_viewers(job_id, minutes=5),
            }
        )

    @app.route("/api/scam-stats")
    def api_scam_stats():
        items = api_job_rows(limit=500)
        stats = {
            "total_jobs": len(items),
            "scam_jobs": sum(1 for item in items if item["risk_level"] == "HIGH"),
            "medium_risk_jobs": sum(1 for item in items if item["risk_level"] == "MEDIUM"),
            "safe_jobs": sum(1 for item in items if item["risk_level"] == "LOW"),
            "urgent_jobs": sum(1 for item in items if item["is_urgent"]),
            "community_reports": sum(int(item["report_count"] or 0) for item in items),
        }
        return jsonify({"ok": True, "stats": stats})

    @app.route("/api/urgent-jobs")
    def api_urgent_jobs():
        items = [with_job_seo_fields(item) for item in api_job_rows(limit=100, urgent_only=True)]
        return jsonify({"ok": True, "items": items, "jobs": items, "count": len(items)})

    @app.route("/api/trust-distribution")
    def api_trust_distribution():
        return jsonify({"ok": True, "distribution": trust_distribution(api_job_rows(limit=500))})

    @app.route("/api/community-reports")
    def api_community_reports():
        init_db()
        rows = get_db().execute(
            """
            SELECT
                community_reports.id,
                community_reports.reason,
                community_reports.created_at,
                community_posts.body,
                community_posts.status
            FROM community_reports
            LEFT JOIN community_posts ON community_posts.id = community_reports.post_id
            ORDER BY datetime(community_reports.created_at) DESC, community_reports.id DESC
            LIMIT 100
            """
        ).fetchall()
        items = [
            {
                "id": row["id"],
                "title": "Community safety report",
                "reason": row["reason"],
                "description": row["body"] or row["reason"],
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        return jsonify({"ok": True, "items": items, "reports": items, "count": len(items)})

    @app.route("/api/analytics", methods=["GET", "POST"])
    def api_analytics():
        ensure_analytics_schema()
        conn = get_db()
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            event_name = str(data.get("event") or data.get("event_name") or "").strip()
            allowed_events = {
                "page_view",
                "job_card_click",
                "job_detail_view",
                "job_filter",
                "signup_click",
                "search_navigation",
                "apply_click",
                "report_click",
                "form_submit",
                "cta_click",
                "outbound_link_click",
                "ai_search",
            }
            if event_name not in allowed_events:
                return jsonify({"ok": False, "message": "Unsupported analytics event."}), 400
            job_id = data.get("job_id")
            try:
                job_id = int(job_id) if job_id not in (None, "") else None
            except (TypeError, ValueError):
                job_id = None
            conn.execute(
                """
                INSERT INTO analytics_events (event_name, job_id, job_title, location, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_name,
                    job_id,
                    str(data.get("job_title") or "")[:200],
                    str(data.get("location") or "")[:120],
                    str(data.get("metadata") or data.get("path") or "")[:500],
                    now_str(),
                ),
            )
            conn.commit()
            return jsonify({"ok": True})

        totals = conn.execute(
            """
            SELECT event_name, COUNT(*) AS count
            FROM analytics_events
            GROUP BY event_name
            """
        ).fetchall()
        top_locations = conn.execute(
            """
            SELECT location, COUNT(*) AS count
            FROM analytics_events
            WHERE location != ''
            GROUP BY location
            ORDER BY count DESC, location ASC
            LIMIT 10
            """
        ).fetchall()
        top_jobs = conn.execute(
            """
            SELECT job_id, job_title, COUNT(*) AS count
            FROM analytics_events
            WHERE job_id IS NOT NULL
            GROUP BY job_id, job_title
            ORDER BY count DESC, job_title ASC
            LIMIT 10
            """
        ).fetchall()
        summary = {row["event_name"]: int(row["count"] or 0) for row in totals}
        return jsonify(
            {
                "ok": True,
                "summary": {
                    "page_views": summary.get("page_view", 0),
                    "job_card_clicks": summary.get("job_card_click", 0),
                    "job_detail_views": summary.get("job_detail_view", 0),
                    "job_filters": summary.get("job_filter", 0),
                    "signup_clicks": summary.get("signup_click", 0),
                    "search_navigation": summary.get("search_navigation", 0),
                    "form_submits": summary.get("form_submit", 0),
                    "cta_clicks": summary.get("cta_click", 0),
                    "outbound_link_clicks": summary.get("outbound_link_click", 0),
                    "ai_searches": summary.get("ai_search", 0),
                },
                "top_locations": [{"location": row["location"], "count": int(row["count"] or 0)} for row in top_locations],
                "top_jobs": [{"job_id": row["job_id"], "job_title": row["job_title"], "count": int(row["count"] or 0)} for row in top_jobs],
            }
        )

    @app.route("/ai-search")
    def ai_search_landing():
        return render_template(
            "ai_search_landing.html",
            GA4_ID=deps["GOOGLE_ANALYTICS_ID"],
            SITE_NAME=SEO_SITE_NAME,
            CITY=SEO_CITY,
            REGION=SEO_REGION,
            COUNTRY=SEO_COUNTRY,
        )

    @app.route("/api/ai-search", methods=["GET", "POST"])
    def api_ai_search():
        data = request.get_json(silent=True) or {}
        query = str(
            request.args.get("q")
            or request.args.get("query")
            or data.get("q")
            or data.get("query")
            or ""
        ).strip()
        if len(query) < 2:
            return jsonify({"ok": False, "message": "Please enter at least 2 characters.", "items": []}), 400

        if AI_SEARCH_API_ENDPOINT:
            try:
                if request.method == "GET":
                    response = requests.get(
                        AI_SEARCH_API_ENDPOINT,
                        params={"q": query, "query": query, "site_url": SITE_URL, "locale": "th-TH"},
                        timeout=12,
                    )
                else:
                    response = requests.post(
                        AI_SEARCH_API_ENDPOINT,
                        json={"query": query, "q": query, "site_url": SITE_URL, "locale": "th-TH"},
                        timeout=12,
                    )
                response.raise_for_status()
                payload = response.json()
                if isinstance(payload, dict):
                    payload.setdefault("ok", True)
                    payload.setdefault("items", payload.get("results") or [])
                    payload.setdefault("results", payload.get("items") or [])
                    return jsonify(payload)
                items = payload if isinstance(payload, list) else []
                return jsonify({"ok": True, "items": items, "results": items})
            except Exception as exc:
                items = local_ai_search(query)
                return jsonify(
                    {
                        "ok": True,
                        "source": "local-fallback",
                        "message": "External AI search is unavailable, so local site results are shown.",
                        "error": str(exc)[:160],
                        "items": items,
                        "results": items,
                    }
                )

        items = local_ai_search(query)
        return jsonify({"ok": True, "source": "local", "items": items, "results": items})
