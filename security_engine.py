import time
import hashlib
import re
from collections import defaultdict

# =========================
# In-memory security store
# =========================

rate_store = defaultdict(list)
device_store = defaultdict(list)

# =========================
# Rate limit config
# =========================

LIMITS = {
    "register": {"limit": 5, "window": 3600},
    "login": {"limit": 10, "window": 900},
    "otp": {"limit": 5, "window": 900},
    "openchat": {"limit": 20, "window": 300},
    "community": {"limit": 10, "window": 600},
    "job_post": {"limit": 10, "window": 900},
}

DEVICE_LIMIT = 30
DEVICE_WINDOW = 3600

# =========================
# Scam keywords
# =========================

SCAM_KEYWORDS = {
    "โอนเงินก่อน": 35,
    "ค่าประกัน": 35,
    "ค่าสมัคร": 30,
    "ค่ามัดจำ": 30,
    "ลงทุนก่อน": 40,
    "ลงทุนน้อย": 25,
    "กำไรสูง": 25,
    "รายได้สูงมาก": 30,
    "รายได้หลักแสน": 40,
    "ไม่ต้องสัมภาษณ์": 25,
    "งานง่าย": 15,
    "ทำงานง่าย": 15,
    "เงินดีมาก": 20,
    "รับรายได้ทันที": 25,
    "คลิกสมัคร": 15,
    "แอดไลน์": 25,
    "ทักไลน์": 25,
    "telegram": 25,
    "whatsapp": 20,
    "line id": 20,
    "งานแพ็คของที่บ้าน": 35,
    "ไม่ต้องมีประสบการณ์": 10,
    "รับทันที": 12,
    "จ่ายรายวัน": 12,
}

BAD_WORDS = [
    "เหี้ย",
    "ควย",
    "สัส",
    "สัด",
    "ไอ้ควาย",
    "ไอ้โง่",
    "fuck",
    "shit",
]

# =========================
# Helpers
# =========================

def now_ts():
    return int(time.time())


def get_client_ip(request):
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP", "")
    if real_ip:
        return real_ip.strip()

    return request.remote_addr or "unknown"


def normalize_text(text):
    text = str(text or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text


def clean_input(text, max_length=1000):
    text = normalize_text(text)
    text = text.replace("\x00", "")
    text = text[:max_length]
    return text


def generate_device_fingerprint(request):
    raw = "|".join([
        request.headers.get("User-Agent", ""),
        request.headers.get("Accept-Language", ""),
        request.headers.get("Accept-Encoding", ""),
        get_client_ip(request),
    ])

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _cleanup(bucket, window):
    current = now_ts()
    return [t for t in bucket if current - t < window]


def check_rate_limit(key, action):
    config = LIMITS.get(action)

    if not config:
        config = {"limit": 10, "window": 300}

    limit = config["limit"]
    window = config["window"]

    store_key = f"{action}:{key}"
    rate_store[store_key] = _cleanup(rate_store[store_key], window)

    if len(rate_store[store_key]) >= limit:
        return False

    rate_store[store_key].append(now_ts())
    return True


def check_device_limit(fingerprint):
    device_store[fingerprint] = _cleanup(device_store[fingerprint], DEVICE_WINDOW)

    if len(device_store[fingerprint]) >= DEVICE_LIMIT:
        return False

    device_store[fingerprint].append(now_ts())
    return True


# =========================
# Compatibility functions
# =========================

def check_ip_rate_limit(ip):
    return check_rate_limit(ip, "register")


def check_device_spam(fingerprint):
    return check_device_limit(fingerprint)


# =========================
# Scam detection
# =========================

def contains_bad_word(text):
    text = normalize_text(text).lower()

    for word in BAD_WORDS:
        if word in text:
            return True

    return False


def calculate_scam_score(text):
    text = normalize_text(text).lower()

    score = 0
    reasons = []

    if not text:
        return 100, ["ข้อความว่าง"]

    if len(text) < 5:
        score += 20
        reasons.append("ข้อความสั้นผิดปกติ")

    if re.search(r"(.)\1{6,}", text):
        score += 20
        reasons.append("มีตัวอักษรซ้ำผิดปกติ")

    url_count = len(re.findall(r"https?://|www\.", text))
    if url_count >= 2:
        score += 30
        reasons.append("มีลิงก์หลายรายการ")
    elif url_count == 1:
        score += 10
        reasons.append("มีลิงก์ในข้อความ")

    for word, point in SCAM_KEYWORDS.items():
        if word in text:
            score += point
            reasons.append(f"พบคำเสี่ยง: {word}")

    if contains_bad_word(text):
        score += 40
        reasons.append("พบคำไม่สุภาพ")

    score = max(0, min(score, 100))

    if not reasons:
        reasons.append("ไม่พบความเสี่ยงเด่น")

    return score, reasons[:8]


def scam_score(text):
    score, _ = calculate_scam_score(text)

    if score >= 70:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


def analyze_text_status(text):
    score, reasons = calculate_scam_score(text)

    if score >= 70:
        return {
            "score": score,
            "risk": "HIGH",
            "status": "BLOCKED",
            "reason": " | ".join(reasons),
        }

    if score >= 35:
        return {
            "score": score,
            "risk": "MEDIUM",
            "status": "PENDING_REVIEW",
            "reason": " | ".join(reasons),
        }

    return {
        "score": score,
        "risk": "LOW",
        "status": "ACTIVE",
        "reason": " | ".join(reasons),
    }


def analyze_job_post(title, description):
    combined = f"{title} {description}"
    result = analyze_text_status(combined)

    if result["risk"] == "HIGH":
        return "REJECTED"

    if result["risk"] == "MEDIUM":
        return "PENDING_AI_REVIEW"

    return "ACTIVE"


def analyze_openchat_message(message):
    message = clean_input(message, 500)
    return analyze_text_status(message)


def analyze_community_post(content):
    content = clean_input(content, 1000)
    return analyze_text_status(content)


# =========================
# Main guard
# =========================

def security_guard(request, action):
    ip = get_client_ip(request)
    fingerprint = generate_device_fingerprint(request)

    if not check_rate_limit(ip, action):
        return False, "ทำรายการถี่เกินไป กรุณารอสักครู่"

    if not check_device_limit(fingerprint):
        return False, "อุปกรณ์นี้มีพฤติกรรมผิดปกติ กรุณาลองใหม่ภายหลัง"

    return True, ""
