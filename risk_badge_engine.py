def get_risk_badge(risk_level, trust_level=None, is_verified=False):
    """
    Return badge data for job/employer display.
    ใช้แสดง badge บนหน้า jobs / job_detail
    """

    badges = []

    if is_verified:
        badges.append({
            "label": "Verified Employer",
            "class": "badge-verified",
            "icon": "✅"
        })

    if trust_level == "HIGH_TRUST":
        badges.append({
            "label": "นายจ้างน่าเชื่อถือสูง",
            "class": "badge-trust-high",
            "icon": "🟢"
        })

    elif trust_level == "LOW_TRUST":
        badges.append({
            "label": "นายจ้างความน่าเชื่อถือต่ำ",
            "class": "badge-trust-low",
            "icon": "🔴"
        })

    elif trust_level == "LOCKED":
        badges.append({
            "label": "บัญชีถูกจำกัด",
            "class": "badge-locked",
            "icon": "⛔"
        })

    if risk_level == "LOW":
        badges.append({
            "label": "Low Risk Job",
            "class": "badge-risk-low",
            "icon": "🟢"
        })

    elif risk_level == "MEDIUM":
        badges.append({
            "label": "รอตรวจสอบโดย AI",
            "class": "badge-risk-medium",
            "icon": "🟡"
        })

    elif risk_level == "HIGH":
        badges.append({
            "label": "เสี่ยงสูง",
            "class": "badge-risk-high",
            "icon": "🔴"
        })

    return badges


def get_job_status_from_risk(risk_level):
    """
    Map AI risk level to job status.
    """

    if risk_level == "HIGH":
        return "REJECTED"

    if risk_level == "MEDIUM":
        return "PENDING_AI_REVIEW"

    return "ACTIVE"


def get_badge_css():
    """
    CSS สำหรับเอาไปใส่ใน style.css หรือ template
    """

    return """
.badge-wrap {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 10px 0;
}

.risk-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 7px 12px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 900;
    border: 1px solid rgba(255,255,255,.14);
}

.badge-verified {
    background: rgba(14,165,233,.16);
    color: #7dd3fc;
}

.badge-trust-high,
.badge-risk-low {
    background: rgba(34,197,94,.14);
    color: #86efac;
}

.badge-risk-medium {
    background: rgba(234,179,8,.14);
    color: #fde68a;
}

.badge-trust-low,
.badge-risk-high {
    background: rgba(239,68,68,.14);
    color: #fca5a5;
}

.badge-locked {
    background: rgba(127,29,29,.3);
    color: #fecaca;
}
"""