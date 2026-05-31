import re


POSITION_SYNONYMS = {
    "software_developer": [
        "developer",
        "web developer",
        "software engineer",
        "programmer",
        "coder",
        "python",
        "flask",
        "frontend",
        "backend",
    ],
    "sales": ["sales", "telesales", "sale admin"],
    "admin_officer": ["admin", "office admin", "coordinator"],
    "accounting": ["accounting", "accountant", "finance"],
    "customer_service": ["call center", "customer service", "support"],
    "driver": ["driver", "delivery"],
    "warehouse": ["warehouse", "stock", "inventory"],
    "marketing": ["marketing", "digital marketing", "content", "seo"],
    "hr": ["hr", "recruiter"],
    "technician": ["technician", "maintenance"],
}

SKILL_KEYWORDS = [
    "python",
    "flask",
    "django",
    "javascript",
    "react",
    "vue",
    "sql",
    "excel",
    "sales",
    "seo",
    "marketing",
    "admin",
    "customer service",
    "call center",
]


def row_value(row, key, default=""):
    try:
        if key in row.keys():
            return row[key]
    except Exception:
        pass
    try:
        return row.get(key, default)
    except Exception:
        return getattr(row, key, default)


def canonical_job_position(*values):
    text = " ".join(str(value or "") for value in values).lower()
    text = re.sub(r"\s+", " ", text)
    best_key = ""
    best_hits = 0
    for key, synonyms in POSITION_SYNONYMS.items():
        hits = sum(1 for synonym in synonyms if synonym.lower() in text)
        if hits > best_hits:
            best_key = key
            best_hits = hits
    return best_key


def extract_skill_tags(*values):
    text = " ".join(str(value or "") for value in values).lower()
    found = []
    for skill in SKILL_KEYWORDS:
        if skill.lower() in text and skill not in found:
            found.append(skill)
    return ", ".join(found)


def split_match_terms(value):
    return [part.strip().lower() for part in re.split(r"[,/| ]+", str(value or "")) if part.strip()]


def salary_numbers(value):
    numbers = re.findall(r"\d+(?:,\d{3})*|\d+k", str(value or "").lower())
    result = []
    for number in numbers:
        if number.endswith("k"):
            result.append(int(float(number[:-1] or 0) * 1000))
        else:
            result.append(int(number.replace(",", "")))
    return result


def salary_overlap(job_salary, expected_salary):
    job_numbers = salary_numbers(job_salary)
    expected_numbers = salary_numbers(expected_salary)
    if not job_numbers or not expected_numbers:
        return False
    job_min, job_max = min(job_numbers), max(job_numbers)
    expected = min(expected_numbers)
    return job_min <= expected <= job_max or expected <= job_max


def profile_job_match(job_row, profile_row):
    job_position = row_value(job_row, "canonical_position") or canonical_job_position(
        row_value(job_row, "title"),
        row_value(job_row, "description"),
    )
    seeker_position = row_value(profile_row, "canonical_position") or canonical_job_position(
        row_value(profile_row, "desired_position"),
        row_value(profile_row, "headline"),
        row_value(profile_row, "skills"),
    )
    job_text = " ".join(
        [
            str(row_value(job_row, "title")),
            str(row_value(job_row, "description")),
            str(row_value(job_row, "required_skills")),
            str(row_value(job_row, "location")),
        ]
    ).lower()
    seeker_skills = split_match_terms(row_value(profile_row, "skills") or row_value(profile_row, "headline"))
    matched_skills = [skill for skill in seeker_skills if len(skill) > 1 and skill in job_text]

    score = 0
    reasons = []
    if job_position and seeker_position and job_position == seeker_position:
        score += 40
        reasons.append(f"position:{job_position}")
    elif seeker_position and seeker_position in job_text:
        score += 20
        reasons.append(f"related_position:{seeker_position}")

    if matched_skills:
        score += min(25, 10 + len(matched_skills) * 5)
        reasons.append("skills:" + ", ".join(matched_skills[:5]))

    seeker_location = str(row_value(profile_row, "preferred_location") or "").lower()
    job_location = str(row_value(job_row, "location") or "").lower()
    if seeker_location and (seeker_location in job_location or job_location in seeker_location):
        score += 20
        reasons.append("location")

    seeker_job_type = str(row_value(profile_row, "job_type") or "").lower()
    job_type = str(row_value(job_row, "job_type") or "").lower()
    if seeker_job_type and job_type and seeker_job_type == job_type:
        score += 5
        reasons.append("job_type")

    if salary_overlap(row_value(job_row, "salary_range"), row_value(profile_row, "expected_salary")):
        score += 10
        reasons.append("salary")

    if int(row_value(job_row, "is_company_verified", 0) or 0):
        score += 5
        reasons.append("verified_company")

    risk = int(row_value(job_row, "ai_risk_score", 0) or 0)
    if risk >= 70:
        score -= 30
        reasons.append("high_risk_penalty")
    elif risk >= 35:
        score -= 10
        reasons.append("medium_risk_penalty")

    canonical = job_position or seeker_position
    return max(0, min(100, score)), " | ".join(reasons[:8]), canonical
