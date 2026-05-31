import sqlite3


def register_auth_routes(app, deps):
    OAUTH_PROVIDERS = deps["OAUTH_PROVIDERS"]
    OTPHandler = deps["OTPHandler"]
    PhoneOTPFlow = deps["PhoneOTPFlow"]
    request = deps["request"]
    render_template = deps["render_template"]
    jsonify = deps["jsonify"]
    redirect = deps["redirect"]
    url_for = deps["url_for"]
    session = deps["session"]
    get_db = deps["get_db"]
    now_str = deps["now_str"]
    normalize_phone = deps["normalize_phone"]
    verify_oauth_state = deps["verify_oauth_state"]
    generate_oauth_state = deps["generate_oauth_state"]
    store_oauth_state = deps["store_oauth_state"]
    store_oauth_callback = deps["store_oauth_callback"]
    get_oauth_callback = deps["get_oauth_callback"]
    hash_password = deps["hash_password"]
    verify_password = deps["verify_password"]
    is_phone_blacklisted = deps["is_phone_blacklisted"]
    is_valid_thai_phone = deps["is_valid_thai_phone"]
    validate_account_password = deps["validate_account_password"]
    validate_profile_name = deps["validate_profile_name"]
    ensure_notification_schema = deps["ensure_notification_schema"]
    create_notification = deps["create_notification"]
    add_activity_log = deps["add_activity_log"]

    @app.route("/auth/google/initiate", methods=["GET"])
    def google_login():
        if "google" not in OAUTH_PROVIDERS:
            return jsonify({"error": "Google OAuth not configured"}), 400

        state = generate_oauth_state()
        store_oauth_state(state)
        auth_url = OAUTH_PROVIDERS["google"].get_auth_url(state)
        return redirect(auth_url)

    @app.route("/auth/google/callback", methods=["GET"])
    def google_callback():
        if "google" not in OAUTH_PROVIDERS:
            return jsonify({"error": "Google OAuth not configured"}), 400

        code = request.args.get("code")
        state = request.args.get("state")
        error = request.args.get("error")

        if error:
            return redirect(url_for("login") + "?error=Google+login+cancelled")

        if not code or not state or not verify_oauth_state(state):
            return redirect(url_for("login") + "?error=Invalid+OAuth+state")

        token_data = OAUTH_PROVIDERS["google"].exchange_code(code)
        if not token_data or "access_token" not in token_data:
            return redirect(url_for("login") + "?error=Failed+to+get+access+token")

        user_info = OAUTH_PROVIDERS["google"].get_user_info(token_data["access_token"])
        if not user_info:
            return redirect(url_for("login") + "?error=Failed+to+get+user+info")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE google_id = ?", (user_info["id"],)).fetchone()

        if user:
            if user["is_banned"]:
                return redirect(url_for("login") + "?error=User+is+banned")
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("dashboard"))

        callback_key = store_oauth_callback(user_info, "google")
        return redirect(url_for("setup_oauth_profile", callback_key=callback_key))

    @app.route("/auth/facebook/initiate", methods=["GET"])
    def facebook_login():
        if "facebook" not in OAUTH_PROVIDERS:
            return jsonify({"error": "Facebook OAuth not configured"}), 400

        state = generate_oauth_state()
        store_oauth_state(state)
        auth_url = OAUTH_PROVIDERS["facebook"].get_auth_url(state)
        return redirect(auth_url)

    @app.route("/auth/facebook/callback", methods=["GET"])
    def facebook_callback():
        if "facebook" not in OAUTH_PROVIDERS:
            return jsonify({"error": "Facebook OAuth not configured"}), 400

        code = request.args.get("code")
        state = request.args.get("state")
        error = request.args.get("error")

        if error:
            return redirect(url_for("login") + "?error=Facebook+login+cancelled")

        if not code or not state or not verify_oauth_state(state):
            return redirect(url_for("login") + "?error=Invalid+OAuth+state")

        token_data = OAUTH_PROVIDERS["facebook"].exchange_code(code)
        if not token_data or "access_token" not in token_data:
            return redirect(url_for("login") + "?error=Failed+to+get+access+token")

        user_info = OAUTH_PROVIDERS["facebook"].get_user_info(token_data["access_token"])
        if not user_info:
            return redirect(url_for("login") + "?error=Failed+to+get+user+info")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE facebook_id = ?", (user_info["id"],)).fetchone()

        if user:
            if user["is_banned"]:
                return redirect(url_for("login") + "?error=User+is+banned")
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("dashboard"))

        callback_key = store_oauth_callback(user_info, "facebook")
        return redirect(url_for("setup_oauth_profile", callback_key=callback_key))

    @app.route("/auth/phone-otp", methods=["POST"])
    def phone_otp():
        data = request.get_json(silent=True) or {}
        phone = normalize_phone(request.form.get("phone") or data.get("phone", ""))

        if not phone:
            return jsonify({"error": "Phone number required"}), 400

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE phone_number = ?", (phone,)).fetchone()

        if user:
            success, msg = OTPHandler.send_sms_otp(phone)
            return jsonify({"success": success, "message": msg, "mode": "login"}), 200 if success else 400

        PhoneOTPFlow.initiate_phone_registration(phone)
        return jsonify({"success": True, "message": "OTP sent to your phone", "mode": "register"}), 200

    @app.route("/auth/verify-otp", methods=["POST"])
    def verify_otp():
        data = request.get_json() or request.form
        phone = normalize_phone(data.get("phone", ""))
        otp_code = data.get("otp_code", "").strip()
        mode = data.get("mode", "login")

        if not phone or not otp_code:
            return jsonify({"error": "Phone and OTP required"}), 400

        if mode == "register":
            success, message = PhoneOTPFlow.verify_phone_registration(otp_code)
            if success:
                return jsonify(
                    {
                        "success": True,
                        "message": message,
                        "redirect": url_for("register_phone_verified"),
                    }
                ), 200
            return jsonify({"error": message}), 400

        success, message = OTPHandler.verify_otp(phone, otp_code, "sms")
        if success:
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE phone_number = ?", (phone,)).fetchone()

            if user and not user["is_banned"]:
                session.clear()
                session["user_id"] = user["id"]
                session.permanent = True
                return jsonify(
                    {
                        "success": True,
                        "message": "Logged in successfully",
                        "redirect": url_for("dashboard"),
                    }
                ), 200
            return jsonify({"error": "User not found or banned"}), 401

        return jsonify({"error": message}), 400

    @app.route("/setup-oauth-profile/<callback_key>", methods=["GET", "POST"])
    def setup_oauth_profile(callback_key):
        callback_data = get_oauth_callback(callback_key)

        if not callback_data:
            return redirect(url_for("login") + "?error=Session+expired")

        user_info = callback_data["user_data"]
        auth_method = callback_data["auth_method"]

        if request.method == "POST":
            phone = normalize_phone(request.form.get("phone", ""))
            full_name = request.form.get("full_name", user_info.get("name", "")).strip()
            role = request.form.get("role", "JOB_SEEKER").strip().upper()

            if not phone:
                return render_template(
                    "oauth_setup.html",
                    user_info=user_info,
                    auth_method=auth_method,
                    error="Phone number required",
                )

            conn = get_db()
            current_time = now_str()

            try:
                if auth_method == "google":
                    conn.execute(
                        """
                        INSERT INTO users (
                            google_id, google_email, email, phone_number,
                            full_name, profile_picture, role, auth_method,
                            is_email_verified, is_verified, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user_info["id"],
                            user_info["email"],
                            user_info["email"],
                            phone,
                            full_name,
                            user_info.get("picture", ""),
                            role,
                            "google",
                            1,
                            0,
                            current_time,
                            current_time,
                        ),
                    )
                elif auth_method == "facebook":
                    conn.execute(
                        """
                        INSERT INTO users (
                            facebook_id, facebook_email, email, phone_number,
                            full_name, profile_picture, role, auth_method,
                            is_email_verified, is_verified, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user_info["id"],
                            user_info.get("email", ""),
                            user_info.get("email", ""),
                            phone,
                            full_name,
                            user_info.get("picture", ""),
                            role,
                            "facebook",
                            1,
                            0,
                            current_time,
                            current_time,
                        ),
                    )

                conn.commit()
                user_id = conn.execute(
                    "SELECT id FROM users WHERE google_id = ? OR facebook_id = ?",
                    (user_info["id"], user_info["id"]),
                ).fetchone()["id"]

                session.clear()
                session["user_id"] = user_id
                session.permanent = True
                return redirect(url_for("dashboard"))

            except Exception as exc:
                return render_template(
                    "oauth_setup.html",
                    user_info=user_info,
                    auth_method=auth_method,
                    error=f"Failed to create account: {str(exc)}",
                )

        return render_template("oauth_setup.html", user_info=user_info, auth_method=auth_method)

    @app.route("/register/phone-verified", methods=["GET", "POST"])
    def register_phone_verified():
        phone = PhoneOTPFlow.get_verified_phone()

        if not phone:
            return redirect(url_for("login") + "?error=Please+verify+phone+first")

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            role = request.form.get("role", "JOB_SEEKER").strip().upper()

            if is_phone_blacklisted(phone):
                return render_template(
                    "register_phone_verified.html",
                    phone=phone,
                    error="Phone number is blocked from registration.",
                )

            if not full_name or not password or not confirm_password:
                return render_template("register_phone_verified.html", phone=phone, error="All fields required")

            if password != confirm_password:
                return render_template("register_phone_verified.html", phone=phone, error="Passwords do not match")

            if len(password) < 6:
                return render_template(
                    "register_phone_verified.html",
                    phone=phone,
                    error="Password must be at least 6 characters",
                )

            conn = get_db()
            current_time = now_str()
            password_hash = hash_password(password)

            try:
                conn.execute(
                    """
                    INSERT INTO users (
                        phone_number, password_hash, full_name, role,
                        auth_method, is_phone_verified, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (phone, password_hash, full_name, role, "phone", 1, current_time, current_time),
                )
                conn.commit()

                user = conn.execute("SELECT id FROM users WHERE phone_number = ?", (phone,)).fetchone()

                session.clear()
                session["user_id"] = user["id"]
                session.permanent = True

                PhoneOTPFlow.clear_phone_registration()
                return redirect(url_for("dashboard"))

            except Exception as exc:
                return render_template(
                    "register_phone_verified.html",
                    phone=phone,
                    error=f"Registration failed: {str(exc)}",
                )

        return render_template("register_phone_verified.html", phone=phone)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if request.method == "POST":
            phone = normalize_phone(request.form.get("phone_number") or request.form.get("phone"))
            password = request.form.get("password", "")
            row = get_db().execute("SELECT * FROM users WHERE phone_number = ?", (phone,)).fetchone()
            if row and verify_password(password, row["password_hash"]) and not row["is_banned"]:
                session.clear()
                session["user_id"] = row["id"]
                session.permanent = True
                return redirect(url_for("dashboard"))
            error = "Invalid phone number or password"
        return render_template("login.html", error=error)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        error = ""
        if request.method == "POST":
            role = request.form.get("role", "JOB_SEEKER").strip().upper()
            phone = normalize_phone(request.form.get("phone_number"))
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            full_name = request.form.get("full_name", "").strip()
            company_name = request.form.get("company_name", "").strip()

            if role not in {"JOB_SEEKER", "EMPLOYER"}:
                error = "Invalid account type"
            elif not request.form.get("accept_terms"):
                error = "Please accept the terms"
            elif not is_valid_thai_phone(phone):
                error = "Please enter a valid 10-digit Thai phone number"
            elif is_phone_blacklisted(phone):
                error = "Phone number is blocked from registration."
            elif email and ("@" not in email or "." not in email.split("@")[-1]):
                error = "Invalid email format"
            elif password != confirm_password:
                error = "Passwords do not match"
            else:
                ok, message = validate_account_password(password, phone)
                if not ok:
                    error = message

            if not error:
                label = "Full name" if role == "JOB_SEEKER" else "Company name"
                profile_name = full_name if role == "JOB_SEEKER" else company_name
                ok, message = validate_profile_name(profile_name, label)
                if not ok:
                    error = message

            if not error:
                try:
                    ensure_notification_schema()
                    conn = get_db()
                    current_time = now_str()
                    cur = conn.execute(
                        """
                        INSERT INTO users (
                            phone_number, password_hash, role, is_verified, is_banned,
                            trust_score, email, wants_email_alerts, wants_web_alerts,
                            created_at, updated_at
                        )
                        VALUES (?, ?, ?, 1, 0, ?, ?, ?, 1, ?, ?)
                        """,
                        (
                            phone,
                            hash_password(password),
                            role,
                            55 if role == "EMPLOYER" else 50,
                            email,
                            1 if request.form.get("notify_consent") else 0,
                            current_time,
                            current_time,
                        ),
                    )
                    user_id = cur.lastrowid

                    if role == "JOB_SEEKER":
                        conn.execute(
                            """
                            INSERT INTO job_seeker_profiles (
                                user_id, full_name, headline, resume_url, is_public,
                                created_at, updated_at
                            )
                            VALUES (?, ?, '', '', 0, ?, ?)
                            """,
                            (user_id, full_name, current_time, current_time),
                        )
                    else:
                        conn.execute(
                            """
                            INSERT INTO employer_profiles (
                                user_id, company_name, tax_id, is_company_verified,
                                address, website, created_at, updated_at
                            )
                            VALUES (?, ?, ?, 0, '', '', ?, ?)
                            """,
                            (user_id, company_name, f"EMP-{user_id}", current_time, current_time),
                        )

                    add_activity_log(user_id, "REGISTER", "users", user_id, f"role={role}")
                    conn.commit()
                    session.clear()
                    session["user_id"] = user_id
                    session.permanent = True
                    create_notification(
                        user_id,
                        "Registration complete",
                        "Welcome to JobBoard AI.",
                        url_for("dashboard"),
                        "ACCOUNT",
                    )
                    return redirect(url_for("dashboard"))
                except sqlite3.IntegrityError:
                    error = "Phone number is already registered"
                except Exception:
                    error = "Registration failed. Please try again."

        return render_template("register.html", error=error)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("home"))
