from dotenv import load_dotenv
load_dotenv()

import os
import hmac
import io
import sqlite3
import secrets
import re
import json
from html import unescape
import zipfile
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin

import bcrypt
import requests
from werkzeug.utils import secure_filename
from flask import (
    Flask,
    g,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    Response,
    jsonify,
    send_from_directory,
)
from security_engine import security_guard
from auth_module import init_oauth_providers, generate_oauth_state, store_oauth_state, verify_oauth_state, store_oauth_callback, get_oauth_callback
from otp_handler import OTPHandler, PhoneOTPFlow
from admin_action_routes import register_admin_action_routes
from admin_page_routes import register_admin_page_routes
from auth_routes import register_auth_routes
from community_routes import register_community_routes
from dashboard_routes import register_dashboard_routes
from job_data_sources import JOB_DATA_SOURCES
from matching_services import (
    canonical_job_position as _canonical_job_position,
    extract_skill_tags as _extract_skill_tags,
    profile_job_match as _profile_job_match,
    row_value as _row_value,
)
from notifications_routes import register_notification_routes
from public_routes import register_public_routes
from utility_api_routes import register_utility_api_routes
from discord_api_routes import register_discord_api_routes
from discord_services import build_discord_services

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / os.environ.get("JOBBOARD_DATABASE_PATH", "instance/jobboard.db")
SITE_URL = os.environ.get("JOBBOARD_SITE_URL", "https://jobboard-ai-app.onrender.com").rstrip("/")
JOBBOARD_API_BASE_URL = os.environ.get("JOBBOARD_API_BASE_URL", SITE_URL).rstrip("/")
SEO_SITE_NAME = os.environ.get("JOBBOARD_SEO_SITE_NAME", "JobBoard").strip() or "JobBoard"
SEO_CITY = os.environ.get("JOBBOARD_SEO_CITY", "Bangkok").strip() or "Bangkok"
SEO_REGION = os.environ.get("JOBBOARD_SEO_REGION", "Bangkok").strip() or "Bangkok"
SEO_COUNTRY = os.environ.get("JOBBOARD_SEO_COUNTRY", "TH").strip() or "TH"
SEO_KEYWORDS = os.environ.get(
    "JOBBOARD_SEO_KEYWORDS",
    "local jobs, job search, urgent jobs, government jobs, apply jobs, trusted jobs, job scam detection, Thailand jobs",
).strip()
AI_SEARCH_API_ENDPOINT = os.environ.get("AI_SEARCH_API_ENDPOINT", "").strip()

app = Flask(__name__)
app.secret_key = os.environ.get("JOBBOARD_SECRET_KEY", "").strip()
app.permanent_session_lifetime = timedelta(hours=12)
DASHBOARD_DIST_DIR = BASE_DIR / "dashboard_frontend" / "dist"
DEFAULT_PROVINCE_LANDING_PAGES = [
    "Bangkok",
    "Nakhon Sawan",
    "Phichit",
    "Phitsanulok",
    "Kamphaeng Phet",
    "Chiang Mai",
    "Chonburi",
    "Khon Kaen",
    "Nakhon Ratchasima",
    "Songkhla",
]
CONTENT_GUIDES = [
    {
        "slug": "avoid-job-scams",
        "title": "How to avoid job scams before applying",
        "description": "A practical checklist for spotting suspicious job ads, upfront payment tricks, and unsafe contact patterns.",
        "sections": [
            "Never transfer money before starting work or signing a clear agreement.",
            "Verify the employer through official websites, phone numbers, and public business records.",
            "Be careful with jobs that promise unusually high pay for unclear work.",
            "Use report buttons when a listing asks for deposits, document fees, or personal data too early.",
        ],
    },
    {
        "slug": "government-job-source-checklist",
        "title": "Government job source checklist",
        "description": "How to verify DOE and government job announcements before sharing documents.",
        "sections": [
            "Open the official source link whenever it is available.",
            "Check the application dates, required documents, and agency contact details.",
            "Avoid reposted announcements that remove source links or ask for fees.",
            "Keep copies of official pages and receipts when applying.",
        ],
    },
    {
        "slug": "safe-local-job-search",
        "title": "Safe local job search guide",
        "description": "Steps for finding local jobs while protecting phone numbers, documents, and personal information.",
        "sections": [
            "Search by province and job title, then compare multiple listings.",
            "Prefer employers with clear company names, locations, and contact channels.",
            "Ask questions in writing before sharing sensitive documents.",
            "Report suspicious patterns to help the community stay safer.",
        ],
    },
]
FAQ_ITEMS = [
    {
        "question": "How does JobBoard detect suspicious jobs?",
        "answer": "The system checks listing text, employer trust signals, report counts, risky keywords, and scam patterns before assigning a risk score.",
    },
    {
        "question": "Can users report suspicious job posts?",
        "answer": "Yes. Logged-in users can report jobs and community posts so admins can review and moderate them.",
    },
    {
        "question": "Are government job posts linked to official sources?",
        "answer": "Government and DOE posts should include official source links when available, and users should verify details on the source page before applying.",
    },
    {
        "question": "Do I need to pay money before applying for jobs?",
        "answer": "No. Be cautious of any job that asks for upfront fees, deposits, or document processing payments before work begins.",
    },
]


def build_seo_title(page_title=""):
    page_title = str(page_title or "").strip()
    if not page_title:
        return f"{SEO_SITE_NAME} | Safe Local Jobs in {SEO_REGION}"
    if SEO_SITE_NAME.lower() in page_title.lower():
        return page_title
    return f"{page_title} | {SEO_SITE_NAME}"


def build_meta_description(page_description=""):
    description = str(page_description or "").strip()
    if description:
        return description[:300]
    return (
        f"Find local jobs in {SEO_CITY}, {SEO_REGION} with trusted employer signals, "
        "official job sources, and safety FAQ answers."
    )


def build_local_business_schema():
    return {
        "@context": "https://schema.org",
        "@type": "LocalBusiness",
        "name": SEO_SITE_NAME,
        "url": SITE_URL,
        "description": build_meta_description(),
        "areaServed": {
            "@type": "AdministrativeArea",
            "name": SEO_REGION,
            "address": {
                "@type": "PostalAddress",
                "addressLocality": SEO_CITY,
                "addressRegion": SEO_REGION,
                "addressCountry": SEO_COUNTRY,
            },
        },
        "address": {
            "@type": "PostalAddress",
            "addressLocality": SEO_CITY,
            "addressRegion": SEO_REGION,
            "addressCountry": SEO_COUNTRY,
        },
    }


def _schema_row_value(row, key, default=""):
    try:
        value = row[key]
    except Exception:
        value = getattr(row, key, default)
    return default if value is None else value


def generate_jobposting_jsonld(job):
    title = _schema_row_value(job, "title", "Job opening")
    description = _schema_row_value(job, "description", "")
    location = _schema_row_value(job, "location", SEO_CITY)
    company_name = _schema_row_value(job, "company_name", SEO_SITE_NAME) or SEO_SITE_NAME
    created_at = str(_schema_row_value(job, "created_at", "") or "")
    posted_date = created_at[:10] if created_at else datetime.now(timezone.utc).date().isoformat()

    return {
        "@context": "https://schema.org",
        "@type": "JobPosting",
        "title": title,
        "description": description,
        "datePosted": posted_date,
        "employmentType": _schema_row_value(job, "job_type", "") or "FULL_TIME",
        "hiringOrganization": {
            "@type": "Organization",
            "name": company_name,
            "sameAs": SITE_URL,
        },
        "jobLocation": {
            "@type": "Place",
            "address": {
                "@type": "PostalAddress",
                "addressLocality": location or SEO_CITY,
                "addressRegion": SEO_REGION,
                "addressCountry": SEO_COUNTRY,
            },
        },
    }

# Initialize OAuth Providers
OAUTH_PROVIDERS = init_oauth_providers()

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("JOBBOARD_SESSION_COOKIE_SECURE", "0") == "1"
app.config["MAX_CONTENT_LENGTH"] = 55 * 1024 * 1024

ADMIN_PHONE = os.environ.get("JOBBOARD_ADMIN_PHONE", "").strip()
ADMIN_PASSWORD = os.environ.get("JOBBOARD_ADMIN_PASSWORD", "").strip()
DISCORD_SCAM_ALERT_WEBHOOK_URL = os.environ.get("DISCORD_SCAM_ALERT_WEBHOOK_URL", "").strip()
DISCORD_BOT_API_TOKEN = os.environ.get("DISCORD_BOT_API_TOKEN", "").strip()
DOE_NEWS_SOURCES = [
    {
        "key": "doe-main",
        "province": "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "phone": "0996101000",
        "employer": "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ / ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "tax_id": "DOE-SOURCE-MAIN",
        "url": "https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label",
        "priority": 100,
    },
    {
        "key": "phichit",
        "province": "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£",
        "phone": "0996101001",
        "employer": "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ / ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "tax_id": "DOE-SOURCE-PHICHIT-LIVE",
        "url": "https://www.doe.go.th/prd/phichit/news/param/site/96/cat/8/sub/0/pull/category/view/list-label",
        "priority": 95,
    },
    {
        "key": "phitsanulok",
        "province": "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â",
        "phone": "0996101002",
        "employer": "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â / ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "tax_id": "DOE-SOURCE-PHITSANULOK-LIVE",
        "url": "https://www.doe.go.th/prd/phitsanulok/news/param/site/161/cat/8/sub/0/pull/category/view/list-label",
        "priority": 94,
    },
    {
        "key": "kamphaengphet",
        "province": "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚Â£",
        "phone": "0996101003",
        "employer": "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚Â£ / ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "tax_id": "DOE-SOURCE-KAMPHAENGPHET-LIVE",
        "url": "https://www.doe.go.th/prd/kamphaengphet/news/param/site/139/cat/8/sub/0/pull/category/view/list-label",
        "priority": 93,
    },
    {
        "key": "nakhonsawan",
        "province": "ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¹Ã…â€™",
        "phone": "0996101004",
        "employer": "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¹Ã…â€™ / ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "tax_id": "DOE-SOURCE-NAKHONSAWAN-LIVE",
        "url": "https://www.doe.go.th/prd/nakhonsawan/news/param/site/146/cat/8/sub/0/pull/category/view/list-label",
        "priority": 92,
    },
]
OPENCHAT_UPLOAD_DIR = BASE_DIR / "instance" / "uploads" / "openchat"
OPENCHAT_ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
OPENCHAT_ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm"}
OPENCHAT_MAX_IMAGE_UPLOAD_BYTES = 5 * 1024 * 1024
OPENCHAT_MAX_VIDEO_UPLOAD_BYTES = 50 * 1024 * 1024
JOBBOARD_CRON_TOKEN = os.environ.get("JOBBOARD_CRON_TOKEN", "").strip()

ROLES = {"JOB_SEEKER", "EMPLOYER", "ADMIN"}


def validate_runtime_config():
    missing = []
    if not app.secret_key:
        missing.append("JOBBOARD_SECRET_KEY")
    if not ADMIN_PHONE:
        missing.append("JOBBOARD_ADMIN_PHONE")
    if not ADMIN_PASSWORD:
        missing.append("JOBBOARD_ADMIN_PASSWORD")

    if missing:
        raise RuntimeError("Missing required environment variables: " + ", ".join(missing))

    if len(app.secret_key) < 32:
        raise RuntimeError("JOBBOARD_SECRET_KEY must be at least 32 characters long.")

    if len(ADMIN_PASSWORD) < 12:
        raise RuntimeError("JOBBOARD_ADMIN_PASSWORD must be at least 12 characters long.")


def send_discord_alert(message, username="JobBoard Alert"):
    """Send a message to the configured Discord webhook."""
    if not DISCORD_SCAM_ALERT_WEBHOOK_URL:
        return False
    try:
        payload = {
            "username": username,
            "content": message,
        }
        response = requests.post(DISCORD_SCAM_ALERT_WEBHOOK_URL, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except Exception:
        return False


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_phone(value):
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def is_phone_blacklisted(phone):
    """ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â ban ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡"""
    phone = normalize_phone(phone)
    if not phone:
        return False
    try:
        row = get_db().execute(
            "SELECT id FROM phone_blacklist WHERE phone_number = ?",
            (phone,),
        ).fetchone()
        return row is not None
    except Exception:
        return False


def blacklist_phone(phone, reason="", banned_by_user_id=None):
    """Ban ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¹Ã…â€™"""
    phone = normalize_phone(phone)
    if not is_valid_thai_phone(phone):
        return False, "ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡"

    if is_phone_blacklisted(phone):
        return False, "ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â ban ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â§"

    try:
        get_db().execute(
            """
            INSERT INTO phone_blacklist (phone_number, reason, banned_by_user_id, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (phone, reason, banned_by_user_id, now_str()),
        )
        get_db().commit()
        return True, "Ban ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‹â€ "
    except Exception as e:
        return False, f"ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â: {str(e)}"


def track_job_view(job_id, user_id=None, ip_address=None, user_agent=None):
    """ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¶ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"""
    try:
        get_db().execute(
            """
            INSERT INTO job_views (job_id, user_id, ip_address, user_agent, viewed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (job_id, user_id, ip_address, user_agent, now_str()),
        )
        get_db().commit()
        return True
    except Exception:
        return False


def get_job_view_count(job_id):
    """ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"""
    try:
        row = get_db().execute(
            "SELECT COUNT(*) as count FROM job_views WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return int(row["count"] or 0) if row else 0
    except Exception:
        return 0


def get_live_viewers(job_id, minutes=5):
    """ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã¢â‚¬Â° (ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ 5 ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¸Ã¢â‚¬Â)"""
    try:
        cutoff = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        row = get_db().execute(
            """
            SELECT COUNT(DISTINCT COALESCE(user_id, ip_address)) as count
            FROM job_views
            WHERE job_id = ? AND viewed_at >= ?
            """,
            (job_id, cutoff),
        ).fetchone()
        return int(row["count"] or 0) if row else 0
    except Exception:
        return 0


def is_valid_thai_phone(phone):
    phone = normalize_phone(phone)
    return len(phone) == 10 and phone.startswith("0")


def validate_account_password(password, phone_number=""):
    password = str(password or "")
    phone_number = normalize_phone(phone_number)

    weak_passwords = {
        "password",
        "password123",
        "12345678",
        "123456789",
        "00000000",
        "11111111",
        "qwerty123",
        "admin1234",
    }

    if len(password) < 8:
        return False, "ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ 8 ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã‚Â£"

    if len(password) > 128:
        return False, "ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Âº"

    if password.lower() in weak_passwords:
        return False, "ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Âº ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ "

    if phone_number and password == phone_number:
        return False, "ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¹Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"

    if password.isdigit():
        return False, "ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¹Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"

    if not re.search(r"[A-Za-zÃƒÂ Ã‚Â¸Ã‚Â-ÃƒÂ Ã‚Â¹Ã¢â€žÂ¢]", password) or not re.search(r"\d", password):
        return False, "ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡"

    return True, ""


def validate_profile_name(value, label, max_length=120):
    value = str(value or "").strip()

    if not value:
        return False, f"ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â{label}"

    if len(value) > max_length:
        return False, f"{label}ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Âº"

    blocked_patterns = [
        r"https?://",
        r"www\.",
        r"line\s*id",
        r"telegram",
        r"whatsapp",
        r"ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        r"ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        r"ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°",
    ]

    lowered = value.lower()
    for pattern in blocked_patterns:
        if re.search(pattern, lowered, re.IGNORECASE):
            return False, f"{label}ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡"

    return True, ""


def hash_password(password):
    return bcrypt.hashpw(str(password).encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password, password_hash):
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(str(password).encode("utf-8"), str(password_hash).encode("utf-8"))
    except ValueError:
        return False


def generate_mock_otp():
    return "123456"


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["_csrf_token"] = token
    return token


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    try:
        return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    except Exception:
        return None


def job_slug(job):
    try:
        job_id = job["id"]
    except Exception:
        job_id = getattr(job, "id", "")
    return str(job_id or "")


def scam_risk_label(score):
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def get_page_view_stats(page_path=None):
    path = page_path or (request.path if request else "")
    try:
        init_db()
        row = get_db().execute(
            "SELECT page_path, page_title, view_count, last_viewed_at FROM page_views WHERE page_path = ?",
            (path,),
        ).fetchone()
        if not row:
            return {"path": path, "current": 0, "total": 0, "view_count": 0}
        total = get_db().execute("SELECT SUM(view_count) AS count FROM page_views").fetchone()
        total_count = int((total and total["count"]) or 0)
        view_count = int(row["view_count"] or 0)
        return {"path": path, "current": view_count, "total": total_count, "view_count": view_count}
    except Exception:
        return {"path": path, "current": 0, "total": 0, "view_count": 0}


def _record_page_view(response):
    if request.method != "GET":
        return response
    if request.path.startswith(("/api/", "/admin/", "/internal/", "/static/", "/uploads/")):
        return response
    if response.status_code >= 400:
        return response
    if "text/html" not in response.content_type:
        return response

    try:
        init_db()
        title = ""
        text = response.get_data(as_text=True)
        match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if match:
            title = re.sub(r"\s+", " ", match.group(1)).strip()[:200]
        get_db().execute(
            """
            INSERT INTO page_views (page_path, page_title, view_count, last_viewed_at, created_at)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(page_path) DO UPDATE SET
                page_title = excluded.page_title,
                view_count = page_views.view_count + 1,
                last_viewed_at = excluded.last_viewed_at
            """,
            (request.path, title, now_str(), now_str()),
        )
        get_db().commit()
    except Exception:
        pass
    return response


def get_official_doe_source_for_location(location="", title=""):
    text = f"{location or ''} {title or ''}"
    for source in DOE_NEWS_SOURCES:
        if source["province"] in text:
            return source["url"]
    return DOE_NEWS_SOURCES[0]["url"]


def is_bad_or_placeholder_source_url(source_url):
    source_url = str(source_url or "").strip().lower()
    if not source_url or source_url == "#":
        return True
    return any(bad in source_url for bad in ("example.com", "google.com", "localhost", "127.0.0.1"))


def safe_source_url(source_url="", location="", title=""):
    if is_bad_or_placeholder_source_url(source_url):
        return get_official_doe_source_for_location(location, title)
    return source_url


def mask_phone_for_display(phone_number):
    phone = normalize_phone(phone_number)
    if len(phone) < 7:
        return phone or "-"
    return f"{phone[:3]}xxx{phone[-4:]}"


def ensure_notification_schema():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT DEFAULT '',
            link_url TEXT DEFAULT '',
            category TEXT DEFAULT 'SYSTEM',
            is_read INTEGER NOT NULL DEFAULT 0,
            read_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at);
        """
    )
    ensure_column(conn, "users", "email", "TEXT DEFAULT ''")
    ensure_column(conn, "users", "wants_email_alerts", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "wants_web_alerts", "INTEGER NOT NULL DEFAULT 1")
    ensure_column(conn, "users", "browser_notifications_enabled", "INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def ensure_analytics_schema():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS analytics_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_name TEXT NOT NULL,
            job_id INTEGER,
            job_title TEXT DEFAULT '',
            location TEXT DEFAULT '',
            metadata TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (job_id) REFERENCES job_posts(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_analytics_events_name ON analytics_events(event_name);
        CREATE INDEX IF NOT EXISTS idx_analytics_events_job ON analytics_events(job_id);
        CREATE INDEX IF NOT EXISTS idx_analytics_events_created ON analytics_events(created_at);
        """
    )
    conn.commit()


def get_unread_notifications_count(user_id=None):
    user_id = user_id or session.get("user_id")
    if not user_id:
        return 0
    try:
        ensure_notification_schema()
        row = get_db().execute(
            "SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND is_read = 0",
            (user_id,),
        ).fetchone()
        return int(row["count"] or 0)
    except Exception:
        return 0


def get_recent_notifications(user_id=None, limit=5):
    user_id = user_id or session.get("user_id")
    if not user_id:
        return []
    try:
        ensure_notification_schema()
        return get_db().execute(
            """
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (user_id, int(limit or 5)),
        ).fetchall()
    except Exception:
        return []


def create_notification(user_id, title, message="", link_url="", category="SYSTEM"):
    if not user_id:
        return None
    try:
        ensure_notification_schema()
        cur = get_db().execute(
            """
            INSERT INTO notifications (user_id, title, message, link_url, category, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, title, message, link_url, category, now_str()),
        )
        get_db().commit()
        return cur.lastrowid
    except Exception:
        return None


def add_activity_log(actor_id, action, target_type="", target_id=None, detail=""):
    try:
        get_db().execute(
            """
            INSERT INTO activity_logs (actor_id, action, target_type, target_id, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor_id, action, target_type, target_id, str(detail or "")[:500], now_str()),
        )
    except Exception:
        pass


def analyze_job_content(title, description, salary_range="", location="", trust_score=50, report_count=0):
    try:
        from security_engine import calculate_scam_score
        score, reasons = calculate_scam_score(f"{title} {description} {salary_range} {location}")
    except Exception:
        score, reasons = 50, ["ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¹Ã…â€™ ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¶ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‹â€ "]

    try:
        trust_score = int(trust_score or 50)
    except (TypeError, ValueError):
        trust_score = 50

    try:
        report_count = int(report_count or 0)
    except (TypeError, ValueError):
        report_count = 0

    if trust_score < 30:
        score += 20
        reasons.append("Trust score ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â³")
    if report_count >= 3:
        score += 20
        reasons.append("ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡")

    score = max(0, min(100, int(score or 0)))
    if score >= 70:
        return score, "REJECTED", " | ".join(reasons[:8])
    if score >= 35:
        return score, "PENDING_AI_REVIEW", " | ".join(reasons[:8])
    return score, "ACTIVE", " | ".join(reasons[:8])


def get_trust_level(score):
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "NORMAL"
    if score >= 20:
        return "LOW"
    return "RISK"


@app.context_processor
def inject_common_values():
    canonical_path = request.path if request else "/"
    canonical_url = f"{SITE_URL}{canonical_path}"
    return {
        "csrf_token": generate_csrf_token,
        "current_year": datetime.now().year,
        "current_user": get_current_user(),
        "site_url": SITE_URL,
        "site_name": SEO_SITE_NAME,
        "canonical_url": canonical_url,
        "seo_keywords": SEO_KEYWORDS,
        "seo_city": SEO_CITY,
        "seo_region": SEO_REGION,
        "seo_country": SEO_COUNTRY,
        "default_meta_description": build_meta_description(),
        "local_business_schema": build_local_business_schema(),
        "job_slug": job_slug,
        "scam_risk_label": scam_risk_label,
        "get_trust_level": get_trust_level,
        "page_view_stats": get_page_view_stats,
        "official_source_url": get_official_doe_source_for_location,
        "is_bad_source_url": is_bad_or_placeholder_source_url,
        "safe_source_url": safe_source_url,
        "unread_notifications_count": get_unread_notifications_count,
        "recent_notifications": get_recent_notifications,
        "google_analytics_id": os.environ.get("GOOGLE_ANALYTICS_ID", "").strip(),
        "microsoft_clarity_id": os.environ.get("MICROSOFT_CLARITY_ID", "").strip(),
        "google_adsense_client": os.environ.get("GOOGLE_ADSENSE_CLIENT", "").strip(),
        "ai_search_endpoint": url_for("api_ai_search"),
    }


@app.before_request
def csrf_protect():
    if request.method != "POST":
        return None
    if request.path == "/admin/discord-test" and (
        request.is_json or os.environ.get("JOBBOARD_ALLOW_UNAUTH_DISCORD_TEST", "0") == "1"
    ):
        return None
    if request.path == "/api/analytics":
        return None
    if request.path == "/api/ai-search":
        return None
    if request.path.startswith("/api/discord/"):
        return None
    if request.path.startswith("/internal/cron/"):
        return None

    session_token = session.get("_csrf_token", "")
    form_token = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")

    if not session_token or not form_token or not hmac.compare_digest(session_token, form_token):
        return "CSRF token ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â·ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â¸ ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¸ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡", 400

    return None


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return _record_page_view(response)


def get_db():
    if "db" not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_column(conn, table_name, column_name, definition):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing = {row["name"] for row in rows}
    if column_name not in existing:
        # SQLite cannot add a column with UNIQUE directly via ALTER TABLE.
        # Add the column first, then enforce uniqueness with an index.
        normalized = definition.strip()
        if "UNIQUE" in normalized.upper():
            column_definition = " ".join(
                part for part in normalized.split() if part.upper() != "UNIQUE"
            ).strip()
            conn.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
            )
            conn.execute(
                f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table_name}_{column_name}_unique "
                f"ON {table_name}({column_name})"
            )
        else:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def ensure_discord_schema(conn=None):
    conn = conn or get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS discord_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            discord_user_id TEXT NOT NULL UNIQUE,
            discord_username TEXT DEFAULT '',
            role TEXT NOT NULL DEFAULT 'JOB_SEEKER',
            dm_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS job_alert_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            keywords TEXT DEFAULT '',
            locations TEXT DEFAULT '',
            job_types TEXT DEFAULT '',
            min_salary TEXT DEFAULT '',
            alert_frequency TEXT NOT NULL DEFAULT 'instant',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS company_follows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            employer_id INTEGER,
            company_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, company_name),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (employer_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS discord_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            discord_user_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            sent_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS match_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL,
            job_seeker_id INTEGER NOT NULL,
            employer_id INTEGER NOT NULL,
            match_score INTEGER NOT NULL DEFAULT 0,
            match_reason TEXT DEFAULT '',
            canonical_position TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'NEW',
            notified_job_seeker INTEGER NOT NULL DEFAULT 0,
            notified_employer INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(job_id, job_seeker_id),
            FOREIGN KEY (job_id) REFERENCES job_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (job_seeker_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (employer_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_discord_accounts_user ON discord_accounts(user_id);
        CREATE INDEX IF NOT EXISTS idx_discord_accounts_discord ON discord_accounts(discord_user_id);
        CREATE INDEX IF NOT EXISTS idx_job_alert_preferences_user ON job_alert_preferences(user_id);
        CREATE INDEX IF NOT EXISTS idx_company_follows_company ON company_follows(company_name);
        CREATE INDEX IF NOT EXISTS idx_discord_notifications_status ON discord_notifications(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_match_events_seeker ON match_events(job_seeker_id, match_score);
        CREATE INDEX IF NOT EXISTS idx_match_events_employer ON match_events(employer_id, match_score);
        CREATE INDEX IF NOT EXISTS idx_match_events_job ON match_events(job_id, match_score);
        """
    )


def init_db():
    conn = get_db()

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT UNIQUE,
            password_hash TEXT,
            email TEXT UNIQUE,
            google_id TEXT UNIQUE,
            google_email TEXT,
            facebook_id TEXT UNIQUE,
            facebook_email TEXT,
            profile_picture TEXT DEFAULT '',
            full_name TEXT DEFAULT '',
            role TEXT NOT NULL DEFAULT 'JOB_SEEKER',
            auth_method TEXT DEFAULT 'phone',
            is_verified INTEGER NOT NULL DEFAULT 0,
            is_phone_verified INTEGER NOT NULL DEFAULT 0,
            is_email_verified INTEGER NOT NULL DEFAULT 0,
            is_banned INTEGER NOT NULL DEFAULT 0,
            trust_score INTEGER NOT NULL DEFAULT 50,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS employer_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            company_name TEXT NOT NULL,
            tax_id TEXT UNIQUE,
            is_company_verified INTEGER NOT NULL DEFAULT 0,
            address TEXT DEFAULT '',
            website TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS job_seeker_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            headline TEXT DEFAULT '',
            resume_url TEXT DEFAULT '',
            is_public INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS job_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employer_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            salary_range TEXT DEFAULT '',
            location TEXT DEFAULT '',
            is_government_news INTEGER NOT NULL DEFAULT 0,
            source_url TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'PENDING_AI_REVIEW',
            ai_risk_score INTEGER,
            ai_risk_reason TEXT DEFAULT '',
            report_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (employer_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS phone_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT UNIQUE NOT NULL,
            reason TEXT,
            banned_by_user_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (banned_by_user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS job_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL,
            user_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            viewed_at TEXT NOT NULL,
            FOREIGN KEY (job_id) REFERENCES job_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_job_views_job_id ON job_views(job_id);
        CREATE INDEX IF NOT EXISTS idx_job_views_viewed_at ON job_views(viewed_at);

        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_seeker_id INTEGER NOT NULL,
            job_post_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            message TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(job_seeker_id, job_post_id),
            FOREIGN KEY (job_seeker_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_post_id INTEGER NOT NULL,
            reporter_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(job_post_id, reporter_id),
            FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            application_id INTEGER,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);
        CREATE INDEX IF NOT EXISTS idx_messages_application ON messages(application_id);

        CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone_number);
        CREATE INDEX IF NOT EXISTS idx_job_posts_status ON job_posts(status);
        CREATE INDEX IF NOT EXISTS idx_job_posts_created ON job_posts(created_at);
        CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT DEFAULT '',
            target_id INTEGER,
            detail TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS ai_decision_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_post_id INTEGER,
            title TEXT DEFAULT '',
            risk_score INTEGER DEFAULT 0,
            risk_reason TEXT DEFAULT '',
            final_status TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (job_post_id) REFERENCES job_posts(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_ai_decision_logs_job ON ai_decision_logs(job_post_id);

        CREATE TABLE IF NOT EXISTS community_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            moderation_score INTEGER NOT NULL DEFAULT 0,
            moderation_reason TEXT DEFAULT '',
            report_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS community_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            reporter_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(post_id, reporter_id),
            FOREIGN KEY (post_id) REFERENCES community_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_community_posts_status ON community_posts(status);
        CREATE INDEX IF NOT EXISTS idx_community_posts_created ON community_posts(created_at);
        CREATE INDEX IF NOT EXISTS idx_community_reports_post ON community_reports(post_id);

        CREATE TABLE IF NOT EXISTS page_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_path TEXT NOT NULL UNIQUE,
            page_title TEXT DEFAULT '',
            view_count INTEGER NOT NULL DEFAULT 0,
            last_viewed_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_page_views_count ON page_views(view_count);
        CREATE INDEX IF NOT EXISTS idx_page_views_last ON page_views(last_viewed_at);


        CREATE TABLE IF NOT EXISTS openchat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            moderation_score INTEGER NOT NULL DEFAULT 0,
            moderation_reason TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_openchat_messages_status ON openchat_messages(status);
        CREATE INDEX IF NOT EXISTS idx_openchat_messages_created ON openchat_messages(created_at);
        """
    )

    conn.executescript("""

        CREATE TABLE IF NOT EXISTS post_media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL UNIQUE,
            original_name TEXT DEFAULT '',
            file_type TEXT NOT NULL,
            mime_type TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
            review_note TEXT DEFAULT '',
            reviewed_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (post_id) REFERENCES community_posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_post_media_post ON post_media(post_id);
        CREATE INDEX IF NOT EXISTS idx_post_media_status ON post_media(status);

    """)

    conn.executescript("""

        CREATE TABLE IF NOT EXISTS openchat_media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL UNIQUE,
            original_name TEXT DEFAULT '',
            file_type TEXT NOT NULL,
            mime_type TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
            review_note TEXT DEFAULT '',
            reviewed_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (message_id) REFERENCES openchat_messages(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_openchat_media_message ON openchat_media(message_id);
        CREATE INDEX IF NOT EXISTS idx_openchat_media_status ON openchat_media(status);

    """)

    ensure_column(conn, "job_posts", "is_urgent", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "job_posts", "canonical_position", "TEXT DEFAULT ''")
    ensure_column(conn, "job_posts", "required_skills", "TEXT DEFAULT ''")
    ensure_column(conn, "job_posts", "job_type", "TEXT DEFAULT ''")
    ensure_column(conn, "job_seeker_profiles", "is_urgent", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "job_seeker_profiles", "desired_position", "TEXT DEFAULT ''")
    ensure_column(conn, "job_seeker_profiles", "canonical_position", "TEXT DEFAULT ''")
    ensure_column(conn, "job_seeker_profiles", "skills", "TEXT DEFAULT ''")
    ensure_column(conn, "job_seeker_profiles", "preferred_location", "TEXT DEFAULT ''")
    ensure_column(conn, "job_seeker_profiles", "job_type", "TEXT DEFAULT ''")
    ensure_column(conn, "job_seeker_profiles", "expected_salary", "TEXT DEFAULT ''")
    ensure_column(conn, "community_posts", "category", "TEXT DEFAULT 'GENERAL'")
    ensure_column(conn, "community_reports", "status", "TEXT NOT NULL DEFAULT 'PENDING'")
    ensure_column(conn, "community_reports", "updated_at", "TEXT")
    ensure_discord_schema(conn)
    
    # Migrate users table for OAuth support
    ensure_column(conn, "users", "email", "TEXT UNIQUE")
    ensure_column(conn, "users", "google_id", "TEXT UNIQUE")
    ensure_column(conn, "users", "google_email", "TEXT")
    ensure_column(conn, "users", "facebook_id", "TEXT UNIQUE")
    ensure_column(conn, "users", "facebook_email", "TEXT")
    ensure_column(conn, "users", "profile_picture", "TEXT DEFAULT ''")
    ensure_column(conn, "users", "full_name", "TEXT DEFAULT ''")
    ensure_column(conn, "users", "auth_method", "TEXT DEFAULT 'phone'")
    ensure_column(conn, "users", "is_phone_verified", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "is_email_verified", "INTEGER NOT NULL DEFAULT 0")


    seed_admin(conn)
    ensure_production_job_schema(conn)
    clean_demo_and_test_data(conn)
    conn.commit()


def seed_admin(conn):
    phone = normalize_phone(ADMIN_PHONE)
    current_time = now_str()
    password_hash = hash_password(ADMIN_PASSWORD)

    row = conn.execute("SELECT id FROM users WHERE phone_number = ?", (phone,)).fetchone()

    if row:
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?,
                role = 'ADMIN',
                is_verified = 1,
                is_banned = 0,
                trust_score = 100,
                updated_at = ?
            WHERE id = ?
            """,
            (password_hash, current_time, row["id"])
        )
        return

    conn.execute(
        """
        INSERT INTO users (
            phone_number, password_hash, role, is_verified, is_banned,
            trust_score, created_at, updated_at
        )
        VALUES (?, ?, 'ADMIN', 1, 0, 100, ?, ?)
        """,
        (phone, password_hash, current_time, current_time)
    )

def seed_demo_jobs(conn):
    count = conn.execute("SELECT COUNT(*) AS count FROM job_posts").fetchone()["count"]
    if count > 0:
        return

    current_time = now_str()
    employer_phone = "0811111111"

    employer = conn.execute("SELECT id FROM users WHERE phone_number = ?", (employer_phone,)).fetchone()
    if employer:
        employer_id = employer["id"]
    else:
        conn.execute(
            """
            INSERT INTO users (
                phone_number, password_hash, role, is_verified, is_banned,
                trust_score, created_at, updated_at
            )
            VALUES (?, ?, 'EMPLOYER', 1, 0, 75, ?, ?)
            """,
            (employer_phone, hash_password("demo-password-123"), current_time, current_time)
        )
        employer_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

    profile = conn.execute("SELECT id FROM employer_profiles WHERE user_id = ?", (employer_id,)).fetchone()
    if not profile:
        conn.execute(
            """
            INSERT INTO employer_profiles (
                user_id, company_name, tax_id, is_company_verified,
                address, website, created_at, updated_at
            )
            VALUES (?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (employer_id, "Demo Company Co., Ltd.", f"DEMO-TAX-{employer_id}", "Bangkok", "https://example.com", current_time, current_time)
        )

    demo_jobs = [
        ("Marketing Officer", "ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã…â€™ ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã…â€™", "18,000 - 28,000 ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬â€", "Bangkok", 0),
        ("Graphic Designer", "ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â·ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â² ÃƒÂ Ã‚Â¸Ã‚Â ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã…Â¸ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ Social Media", "20,000 - 30,000 ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬â€", "Chiang Mai", 0),
        ("ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡", "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ AI ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â¶ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢", "", "ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¨", 1),
    ]

    for title, desc, salary, loc, is_gov in demo_jobs:
        conn.execute(
            """
            INSERT INTO job_posts (
                employer_id, title, description, salary_range, location,
                is_government_news, source_url, status, ai_risk_score,
                ai_risk_reason, report_count, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, 'demo seed data', 0, ?, ?)
            """,
            (
                employer_id,
                title,
                desc,
                salary,
                loc,
                is_gov,
                "https://example.com/government-job" if is_gov else "",
                current_time,
                current_time,
            )
        )



# PRODUCTION_GOVERNMENT_FIX_V1
def ensure_production_job_schema(conn):
    ensure_column(conn, "job_posts", "view_count", "INTEGER NOT NULL DEFAULT 0")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_job_posts_gov_active ON job_posts(is_government_news, status, updated_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_job_posts_source_url ON job_posts(source_url)")


def clean_demo_and_test_data(conn):
    current_time = now_str()
    ensure_production_job_schema(conn)

    conn.execute(
        """
        DELETE FROM job_posts
        WHERE lower(COALESCE(ai_risk_reason, '')) LIKE '%demo%'
           OR lower(COALESCE(description, '')) LIKE '%demo%'
           OR title LIKE '%ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡%'
           OR lower(COALESCE(source_url, '')) LIKE '%example.com%'
           OR lower(COALESCE(source_url, '')) LIKE '%/demo/%'
           OR title IN ('Marketing Officer', 'Graphic Designer')
        """
    )

    for phone in ("0811111111", "0810000001", "0810000002"):
        conn.execute(
            "DELETE FROM users WHERE phone_number = ? AND role != 'ADMIN'",
            (phone,),
        )

    conn.execute(
        """
        DELETE FROM employer_profiles
        WHERE upper(COALESCE(tax_id, '')) LIKE 'DEMO-%'
           OR upper(COALESCE(tax_id, '')) LIKE 'TEST-%'
           OR company_name LIKE '%Demo%'
           OR company_name LIKE '%ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡%'
        """
    )

    conn.execute(
        """
        UPDATE job_posts
        SET source_url = CASE
                WHEN is_government_news = 1 THEN COALESCE(NULLIF(source_url, ''), 'https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label')
                ELSE source_url
            END,
            updated_at = ?
        WHERE status = 'ACTIVE'
          AND is_government_news = 1
          AND (
                source_url IS NULL
                OR source_url = ''
                OR lower(source_url) LIKE '%example.com%'
                OR lower(source_url) LIKE '%google.com%'
                OR source_url = '#'
          )
        """,
        (current_time,),
    )


def government_jobs_where_sql(prefix="job_posts"):
    return f"""
        {prefix}.status = 'ACTIVE'
        AND {prefix}.is_government_news = 1
        AND COALESCE({prefix}.source_url, '') != ''
        AND lower(COALESCE({prefix}.source_url, '')) NOT LIKE '%example.com%'
        AND lower(COALESCE({prefix}.source_url, '')) NOT LIKE '%google.com%'
        AND lower(COALESCE({prefix}.source_url, '')) NOT LIKE '%localhost%'
        AND lower(COALESCE({prefix}.source_url, '')) NOT LIKE '%127.0.0.1%'
        AND {prefix}.title NOT LIKE '%ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡%'
        AND lower(COALESCE({prefix}.description, '')) NOT LIKE '%demo%'
    """





# SAFE_PUBLIC_ROUTES_FINAL_V1
def _safe_html_escape(value):
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _safe_agency_name(company_name="", location="", source_url=""):
    company_name = str(company_name or "").strip()
    location = str(location or "").strip()
    source_url = str(source_url or "").lower().strip()

    bad = {"", "ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â¶ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â´", "auto job engine", "government job news"}

    if company_name.lower() not in bad:
        return company_name

    if "phichit" in source_url or "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£" in location:
        return "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£"
    if "phitsanulok" in source_url or "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â" in location:
        return "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â"
    if "kamphaengphet" in source_url or "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚Â£" in location:
        return "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚Â£"
    if "nakhonsawan" in source_url or "ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¹Ã…â€™" in location:
        return "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¹Ã…â€™"
    return "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ / ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"


def _safe_is_real_job_title(title):
    title = str(title or "").strip()
    lowered = title.lower()

    if len(title) < 8:
        return False

    bad_terms = [
        "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¨",
        "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§",
        "ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â",
        "ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢",
        "ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨",
        "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢",
        "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã…Â½ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢",
        "ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“",
        "ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‹Å“ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã…â€™",
        "ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£",
        "ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬â„¢ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â¥",
        "ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¡",
        "ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡",
        "ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã‹â€ ",
        "ÃƒÂ Ã‚Â¸Ã‚Â ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£",
        "ÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¡",
        "ÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â·ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¡",
        "ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¡/ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¹Ã…â€™",
        "ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£",
        "mobile app",
        "ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¨",
        "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã¢â‚¬â€œÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¨",
        "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§",
        "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¨",
        "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¨",
        "ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§",
    ]

    if any(term.lower() in lowered for term in bad_terms):
        return False

    good_terms = [
        "ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£",
        "ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£",
        "ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£",
        "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡",
        "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡",
        "ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡",
        "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
        "ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â²",
        "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â·ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â",
        "ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²",
    ]

    return any(term in title for term in good_terms)


def _safe_fetch_government_rows(limit=100, q="", location=""):
    conn = get_db()

    try:
        ensure_production_job_schema(conn)
    except Exception:
        pass

    where = """
        job_posts.status = 'ACTIVE'
        AND job_posts.is_government_news = 1
        AND COALESCE(job_posts.source_url, '') != ''
        AND lower(COALESCE(job_posts.source_url, '')) NOT LIKE '%example.com%'
        AND lower(COALESCE(job_posts.source_url, '')) NOT LIKE '%google.com%'
        AND lower(COALESCE(job_posts.source_url, '')) NOT LIKE '%localhost%'
        AND lower(COALESCE(job_posts.source_url, '')) NOT LIKE '%127.0.0.1%'
        AND job_posts.title NOT LIKE '%ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡%'
        AND lower(COALESCE(job_posts.description, '')) NOT LIKE '%demo%'
    """
    params = []

    q = str(q or "").strip().lower()
    location = str(location or "").strip().lower()

    if q:
        like_q = f"%{q}%"
        where += """
            AND (
                lower(job_posts.title) LIKE ?
                OR lower(job_posts.description) LIKE ?
                OR lower(job_posts.location) LIKE ?
                OR lower(employer_profiles.company_name) LIKE ?
            )
        """
        params.extend([like_q, like_q, like_q, like_q])

    if location:
        where += " AND lower(job_posts.location) LIKE ?"
        params.append(f"%{location}%")

    try:
        rows = conn.execute(
            f"""
            SELECT
                job_posts.id,
                job_posts.title,
                job_posts.description,
                job_posts.salary_range,
                job_posts.location,
                job_posts.source_url,
                job_posts.created_at,
                job_posts.updated_at,
                COALESCE(job_posts.view_count, 0) AS view_count,
                employer_profiles.company_name,
                employer_profiles.is_company_verified
            FROM job_posts
            LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
            WHERE {where}
            ORDER BY
                CASE WHEN lower(job_posts.source_url) LIKE '%doe.go.th%' THEN 0 ELSE 1 END,
                datetime(job_posts.updated_at) DESC,
                datetime(job_posts.created_at) DESC,
                job_posts.id DESC
            LIMIT ?
            """,
            tuple(params + [int(limit or 100)]),
        ).fetchall()
    except Exception:
        rows = []

    clean_rows = []
    for row in rows:
        if _safe_is_real_job_title(row["title"]):
            clean_rows.append(row)

    return clean_rows


def _safe_fetch_public_job_rows(limit=100, q="", location="", job_type=""):
    conn = get_db()
    try:
        ensure_production_job_schema(conn)
    except Exception:
        pass

    where = ["job_posts.status = 'ACTIVE'"]
    params = []
    q = str(q or "").strip().lower()
    location = str(location or "").strip().lower()
    job_type = str(job_type or "").strip().lower()

    if q:
        like_q = f"%{q}%"
        where.append(
            """
            (
                lower(job_posts.title) LIKE ?
                OR lower(job_posts.description) LIKE ?
                OR lower(job_posts.location) LIKE ?
                OR lower(employer_profiles.company_name) LIKE ?
            )
            """
        )
        params.extend([like_q, like_q, like_q, like_q])

    if location:
        where.append("lower(job_posts.location) LIKE ?")
        params.append(f"%{location}%")

    if job_type == "government":
        where.append("job_posts.is_government_news = 1")
    elif job_type == "private":
        where.append("job_posts.is_government_news = 0")

    rows = conn.execute(
        f"""
        SELECT
            job_posts.id,
            job_posts.title,
            job_posts.description,
            job_posts.salary_range,
            job_posts.location,
            job_posts.source_url,
            job_posts.created_at,
            job_posts.updated_at,
            job_posts.is_government_news,
            job_posts.ai_risk_score,
            job_posts.report_count,
            COALESCE(job_posts.view_count, 0) AS view_count,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE {" AND ".join(where)}
        ORDER BY
            COALESCE(job_posts.is_urgent, 0) DESC,
            CASE WHEN job_posts.is_government_news = 1 THEN 0 ELSE 1 END,
            datetime(job_posts.updated_at) DESC,
            job_posts.id DESC
        LIMIT ?
        """,
        tuple(params + [int(limit or 100)]),
    ).fetchall()

    clean_rows = []
    for row in rows:
        if row["is_government_news"] and not _safe_is_real_job_title(row["title"]):
            continue
        clean_rows.append(row)
    return clean_rows


@app.route("/")
@app.route("/home")
def home():
    return redesigned_home()


@app.route("/jobboard-ai/")
@app.route("/jobboard-ai/<path:path>")
def jobboard_ai_dashboard(path="index.html"):
    if path.startswith("assets/"):
        return send_from_directory(DASHBOARD_DIST_DIR, path)
    return send_from_directory(DASHBOARD_DIST_DIR, "index.html")


@app.route("/jobs")
def jobs_public():
    return redesigned_jobs_public()


@app.route("/news")
def government_news():
    return redesigned_government_news()




def _public_row_value(row, key, default=""):
    try:
        if isinstance(row, dict):
            return row.get(key, default)
        if hasattr(row, "keys") and key in row.keys():
            return row[key]
        return getattr(row, key, default)
    except Exception:
        return default


def _public_row_int(row, key, default=0):
    try:
        value = _public_row_value(row, key, default)
        if value is None or value == "":
            value = default
        return int(value)
    except (TypeError, ValueError):
        return default


def _public_listing_items(rows):
    items = []
    for row in rows:
        title = str(_public_row_value(row, "title", "") or "").strip()
        location = str(_public_row_value(row, "location", "") or "").strip() or "ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â¨"
        salary = str(_public_row_value(row, "salary_range", "") or "").strip() or "ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â·ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"
        updated = str(
            _public_row_value(row, "updated_at", "")
            or _public_row_value(row, "created_at", "")
            or "ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¸Ã¢â‚¬Â"
        ).strip()
        source_url_raw = str(_public_row_value(row, "source_url", "") or "").strip()
        company_name = str(_public_row_value(row, "company_name", "") or "").strip()
        is_government = bool(_public_row_int(row, "is_government_news", 1))
        agency = (
            _safe_agency_name(company_name, location, source_url_raw)
            if is_government
            else (company_name or "ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡")
        )
        description = re.sub(r"\s+", " ", str(_public_row_value(row, "description", "") or "")).strip()
        if len(description) > 180:
            description = f"{description[:177].rstrip()}..."

        risk_score = _public_row_int(row, "ai_risk_score", 0)
        if risk_score >= 70:
            risk_class = "red"
        elif risk_score >= 35:
            risk_class = "amber"
        else:
            risk_class = "green"

        try:
            detail_url = url_for("job_detail", slug=job_slug(row))
        except Exception:
            detail_url = f"/job/{_public_row_value(row, 'id', '')}"

        source_url = ""
        if is_government:
            source_url = safe_source_url(source_url_raw, location, title)

        items.append({
            "title": title or "ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
            "description": description,
            "agency": agency,
            "location": location,
            "salary": salary,
            "updated": updated,
            "detail_url": detail_url,
            "source_url": source_url,
            "views": _public_row_int(row, "view_count", 0),
            "report_count": _public_row_int(row, "report_count", 0),
            "risk_score": risk_score,
            "risk_class": risk_class,
            "badge": "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ / DOE" if is_government else "ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡",
            "badge_class": "green" if is_government else "blue",
        })
    return items


def _public_filter_links(q="", location="", job_type=""):
    filter_args = {}
    if q:
        filter_args["q"] = q
    if location:
        filter_args["location"] = location
    return [
        {
            "label": "ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â",
            "url": url_for("jobs_public", **filter_args),
            "active": not job_type,
        },
        {
            "label": "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£",
            "url": url_for("jobs_public", type="government", **filter_args),
            "active": job_type == "government",
        },
        {
            "label": "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡",
            "url": url_for("jobs_public", type="private", **filter_args),
            "active": job_type == "private",
        },
    ]


def _render_redesigned_public_page(page_title, subtitle, rows, q="", location="", show_search=True, job_type="", search_action="/jobs"):
    items = _public_listing_items(rows)
    canonical_url = f"{SITE_URL}{request.path}"
    meta_description = build_meta_description(subtitle)
    website_schema = json.dumps({
        "@context": "https://schema.org",
        "@type": "WebSite",
        "name": SEO_SITE_NAME,
        "url": SITE_URL,
        "potentialAction": {
            "@type": "SearchAction",
            "target": f"{SITE_URL}/jobs?q={{search_term_string}}",
            "query-input": "required name=search_term_string",
        },
    }, ensure_ascii=False)
    item_list_schema = json.dumps({
        "@context": "https://schema.org",
        "@type": "ItemList",
        "name": page_title,
        "numberOfItems": len(items),
        "itemListElement": [
            {
                "@type": "ListItem",
                "position": index + 1,
                "url": f"{SITE_URL}{item['detail_url']}",
                "name": item["title"],
            }
            for index, item in enumerate(items[:20])
        ],
    }, ensure_ascii=False)

    if search_action == "/news":
        reset_url = url_for("government_news")
        filter_links = []
    else:
        reset_url = url_for("jobs_public")
        filter_links = _public_filter_links(q, location, job_type)

    return render_template(
        "public_listing.html",
        page_title=page_title,
        subtitle=subtitle,
        meta_description=meta_description,
        canonical_url=canonical_url,
        website_schema=website_schema,
        item_list_schema=item_list_schema,
        local_business_schema_json=json.dumps(build_local_business_schema(), ensure_ascii=False),
        items=items,
        rows_count=len(items),
        q=q,
        location=location,
        show_search=show_search,
        job_type=job_type,
        search_action=search_action,
        reset_url=reset_url,
        filter_links=filter_links,
    )

def redesigned_home():
    rows = _safe_fetch_government_rows(limit=12)
    return _render_redesigned_public_page(
        "งานใกล้บ้าน",
        "รวมงานใกล้บ้าน งานราชการ ข่าวกรมแรงงาน และประกาศจากนายจ้าง พร้อมระบบช่วยคัดกรองประกาศเสี่ยง",
        rows,
    )


def redesigned_jobs_public():
    q = request.args.get("q", "").strip()
    location = request.args.get("location", "").strip()
    job_type = request.args.get("type", "").strip().lower()
    rows = _safe_fetch_public_job_rows(limit=100, q=q, location=location, job_type=job_type)
    return _render_redesigned_public_page(
        "ค้นหางานทั้งหมด",
        "ค้นหางานตามตำแหน่ง จังหวัด หรือแหล่งงาน พร้อมข้อมูลความปลอดภัยก่อนสมัคร",
        rows,
        q=q,
        location=location,
        job_type=job_type,
    )


def redesigned_government_news():
    q = request.args.get("q", "").strip()
    location = request.args.get("location", "").strip()
    rows = _safe_fetch_government_rows(limit=100, q=q, location=location)
    return _render_redesigned_public_page(
        "ข่าวกรมแรงงาน / งานราชการ",
        "รวมข่าวประกาศรับสมัครงานและตำแหน่งงานว่างจากแหล่งข้อมูลราชการ",
        rows,
        q=q,
        location=location,
        show_search=True,
        search_action="/news",
    )


# RESTORED_CRON_IMPORT_ROUTE_V1
def _cron_token_is_valid():
    expected = os.environ.get("JOBBOARD_CRON_TOKEN", "").strip()
    token = request.headers.get("X-Cron-Token", "").strip()
    if not token:
        token = request.args.get("token", "").strip()
    return bool(expected) and bool(token) and hmac.compare_digest(expected, token)


@app.route("/internal/cron/import-upper-central-jobs", methods=["GET", "POST"])
@app.route("/internal/cron/import-doe-news", methods=["GET", "POST"])
def cron_import_upper_central_jobs():
    if not _cron_token_is_valid():
        abort(403)

    result = {
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
        "scanned": 0,
        "errors": [],
    }

    source = "unknown"

    try:
        if "import_latest_doe_news_to_db" in globals():
            doe_result = import_latest_doe_news_to_db()
            result["inserted"] += int(doe_result.get("inserted", 0) or 0)
            result["updated"] += int(doe_result.get("updated", 0) or 0)
            result["scanned"] += int(doe_result.get("scanned", 0) or 0)
            result["errors"].extend(doe_result.get("errors", []) or [])
            source = "app.import_latest_doe_news_to_db"
        else:
            from auto_job_engine import run_live
            doe_result = run_live()
            result["inserted"] += int(doe_result.get("inserted", 0) or 0)
            result["updated"] += int(doe_result.get("updated", 0) or 0)
            result["skipped"] += int(doe_result.get("skipped", 0) or 0)
            result["scanned"] += int(doe_result.get("scanned", 0) or 0)
            result["errors"].extend(doe_result.get("errors", []) or [])
            source = "auto_job_engine.run_live"

        try:
            conn = get_db()
            if "repair_job_source_urls_to_official" in globals():
                fixed = repair_job_source_urls_to_official()
                result["fixed_sources"] = int(fixed or 0)
            if "clean_demo_and_test_data" in globals():
                clean_demo_and_test_data(conn)
            if "add_activity_log" in globals():
                add_activity_log(
                    None,
                    "CRON_IMPORT_DOE_NEWS",
                    "job_posts",
                    None,
                    f"source={source}, inserted={result['inserted']}, updated={result['updated']}, scanned={result['scanned']}, errors={len(result['errors'])}",
                )
            conn.commit()
        except Exception as log_exc:
            result["errors"].append("post_import_log: " + str(log_exc)[:200])

        try:
            if "send_discord_alert" in globals():
                status_text = "ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ Cron Import DOE ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‹â€ "
                if result["errors"]:
                    status_text = "ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â Cron Import DOE ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"
                send_discord_alert(
                    f"{status_text}\n"
                    f"Inserted: {result['inserted']}\n"
                    f"Updated: {result['updated']}\n"
                    f"Scanned: {result['scanned']}\n"
                    f"Errors: {len(result['errors'])}\n"
                    f"Source: {source}\n"
                    f"ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â²: {now_str()}",
                    username="JobBoard Cron Import Bot",
                )
        except Exception:
            pass

        return jsonify({
            "ok": True,
            "source": source,
            "inserted": result["inserted"],
            "updated": result["updated"],
            "skipped": result["skipped"],
            "scanned": result["scanned"],
            "errors": result["errors"],
            "checked_at": now_str(),
        })

    except Exception as exc:
        try:
            _record_import_run("CRON_IMPORT_DOE_NEWS", "ERROR", error_message=str(exc))
        except Exception:
            pass
        try:
            if "add_activity_log" in globals():
                add_activity_log(None, "CRON_IMPORT_DOE_NEWS_FAILED", "job_posts", None, str(exc)[:500])
                get_db().commit()
        except Exception:
            pass

        try:
            if "send_discord_alert" in globals():
                send_discord_alert(
                    "ÃƒÂ¢Ã‚ÂÃ…â€™ Cron Import DOE ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â§\n"
                    f"Error: {str(exc)[:500]}\n"
                    f"Source: {source}\n"
                    f"ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â²: {now_str()}",
                    username="JobBoard Cron Import Bot",
                )
        except Exception:
            pass

        return jsonify({
            "ok": False,
            "error": str(exc),
            "checked_at": now_str(),
        }), 500


@app.route("/internal/cron/import-status", methods=["GET"])
def cron_import_status():
    if not _cron_token_is_valid():
        abort(403)
    return jsonify({
        "ok": True,
        "checked_at": now_str(),
        "import_status": _fetch_import_status(),
        "env": {
            "JOBBOARD_CRON_TOKEN": bool(JOBBOARD_CRON_TOKEN),
            "JOBBOARD_API_BASE_URL": bool(JOBBOARD_API_BASE_URL),
            "DISCORD_SCAM_ALERT_WEBHOOK_URL": bool(DISCORD_SCAM_ALERT_WEBHOOK_URL),
        },
    })



@app.cli.command("init-db")
def init_db_command():
    validate_runtime_config()
    with app.app_context():
        init_db()
    print(f"Initialized database at {DB_PATH}")


@app.before_request
def ensure_database_ready():
    if getattr(app, "_jobboard_database_ready", False):
        return None
    if request.endpoint == "static":
        return None
    validate_runtime_config()
    init_db()
    app._jobboard_database_ready = True
    return None






# AUTO_FIX_BAD_SOURCE_URLS_ONCE
_AUTO_SOURCE_REPAIR_DONE = False

@app.before_request
def auto_repair_bad_source_urls_once():
    global _AUTO_SOURCE_REPAIR_DONE

    if _AUTO_SOURCE_REPAIR_DONE:
        return None

    try:
        endpoint = request.endpoint or ""
        if endpoint.startswith("static"):
            return None

        _AUTO_SOURCE_REPAIR_DONE = True

        conn = get_db()
        bad = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM job_posts
            WHERE source_url = ''
               OR source_url IS NULL
               OR lower(source_url) LIKE '%google.com%'
               OR lower(source_url) LIKE '%example.com%'
               OR lower(source_url) LIKE '%localhost%'
               OR lower(source_url) LIKE '%127.0.0.1%'
               OR source_url = '#'
            """
        ).fetchone()["count"]

        if int(bad or 0) > 0:
            repair_job_source_urls_to_official()
    except Exception:
        return None

    return None




# SEED_TEST_ACCOUNTS_AND_REPAIR_DB
def upsert_test_user_account(phone, password, role, display_name):
    conn = get_db()
    current_time = now_str()
    password_hash = hash_password(password)

    existing = conn.execute(
        "SELECT id FROM users WHERE phone = ? LIMIT 1",
        (phone,)
    ).fetchone()

    if existing:
        user_id = existing["id"]
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, role = ?, is_phone_verified = 1, status = 'ACTIVE', updated_at = ?
            WHERE id = ?
            """,
            (password_hash, role, current_time, user_id)
        )
    else:
        cur = conn.execute(
            """
            INSERT INTO users (
                phone, password_hash, role, is_phone_verified, status, created_at, updated_at
            )
            VALUES (?, ?, ?, 1, 'ACTIVE', ?, ?)
            """,
            (phone, password_hash, role, current_time, current_time)
        )
        user_id = cur.lastrowid

    if role == "JOB_SEEKER":
        row = conn.execute(
            "SELECT id FROM job_seeker_profiles WHERE user_id = ? LIMIT 1",
            (user_id,)
        ).fetchone()

        if row:
            conn.execute(
                """
                UPDATE job_seeker_profiles
                SET full_name = ?, headline = ?, resume_url = ?, is_public = 1, is_urgent = 1, updated_at = ?
                WHERE user_id = ?
                """,
                (
                    display_name,
                    "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Âµ ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
                    "ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã…Â¸ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
                    current_time,
                    user_id,
                )
            )
        else:
            conn.execute(
                """
                INSERT INTO job_seeker_profiles (
                    user_id, full_name, headline, resume_url, is_public, is_urgent, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 1, 1, ?, ?)
                """,
                (
                    user_id,
                    display_name,
                    "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚Âµ ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
                    "ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã…Â¸ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã…â€™ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…â€œÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
                    current_time,
                    current_time,
                )
            )

    if role == "EMPLOYER":
        row = conn.execute(
            "SELECT id FROM employer_profiles WHERE user_id = ? LIMIT 1",
            (user_id,)
        ).fetchone()

        if row:
            employer_id = row["id"]
            conn.execute(
                """
                UPDATE employer_profiles
                SET company_name = ?, tax_id = ?, company_description = ?, is_company_verified = 1, updated_at = ?
                WHERE user_id = ?
                """,
                (
                    display_name,
                    "TEST-EMPLOYER-0002",
                    "ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
                    current_time,
                    user_id,
                )
            )
        else:
            cur = conn.execute(
                """
                INSERT INTO employer_profiles (
                    user_id, company_name, tax_id, company_description, is_company_verified, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    user_id,
                    display_name,
                    "TEST-EMPLOYER-0002",
                    "ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
                    current_time,
                    current_time,
                )
            )
            employer_id = cur.lastrowid

        existing_job = conn.execute(
            """
            SELECT id FROM job_posts
            WHERE employer_id = ? AND title = ?
            LIMIT 1
            """,
            (employer_id, "ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢")
        ).fetchone()

        if existing_job:
            conn.execute(
                """
                UPDATE job_posts
                SET description = ?, salary_range = ?, location = ?, is_government_news = 0,
                    source_url = '', status = 'ACTIVE', ai_risk_score = 5,
                    ai_risk_reason = ?, is_urgent = 1, updated_at = ?
                WHERE id = ?
                """,
                (
                    "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â² ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡",
                    "15,000 - 18,000 ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬â€",
                    "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£",
                    "ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â·ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â§",
                    current_time,
                    existing_job["id"],
                )
            )
        else:
            conn.execute(
                """
                INSERT INTO job_posts (
                    employer_id, title, description, salary_range, location,
                    is_government_news, source_url, status, ai_risk_score,
                    ai_risk_reason, report_count, created_at, updated_at, is_urgent
                )
                VALUES (?, ?, ?, ?, ?, 0, '', 'ACTIVE', 5, ?, 0, ?, ?, 1)
                """,
                (
                    employer_id,
                    "ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢",
                    "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â² ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã†â€™ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã…Â¡",
                    "15,000 - 18,000 ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬â€",
                    "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£",
                    "ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂºÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â°ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¨ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã¢â‚¬â€ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â·ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â§",
                    current_time,
                    current_time,
                )
            )

    conn.commit()
    return user_id


def force_repair_demo_and_bad_sources():
    conn = get_db()
    current_time = now_str()

    source_map = {
        "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â£": "https://www.doe.go.th/prd/phichit/news/param/site/96/cat/8/sub/0/pull/category/view/list-label",
        "ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã‚Â´ÃƒÂ Ã‚Â¸Ã‚Â©ÃƒÂ Ã‚Â¸Ã¢â‚¬Å“ÃƒÂ Ã‚Â¸Ã‚Â¸ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¸Ã‚Â¥ÃƒÂ Ã‚Â¸Ã‚Â": "https://www.doe.go.th/prd/phitsanulok/news/param/site/161/cat/8/sub/0/pull/category/view/list-label",
        "ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â³ÃƒÂ Ã‚Â¹Ã‚ÂÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¹Ã¢â€šÂ¬ÃƒÂ Ã‚Â¸Ã…Â¾ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚Â£": "https://www.doe.go.th/prd/kamphaengphet/news/param/site/139/cat/8/sub/0/pull/category/view/list-label",
        "ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¹Ã…â€™": "https://www.doe.go.th/prd/nakhonsawan/news/param/site/146/cat/8/sub/0/pull/category/view/list-label",
    }
    default_url = "https://www.doe.go.th/prd/main/news/param/site/1/cat/8/sub/0/pull/category/view/list-label"

    rows = conn.execute(
        """
        SELECT id, title, location, source_url
        FROM job_posts
        WHERE source_url = ''
           OR source_url IS NULL
           OR lower(source_url) LIKE '%google.com%'
           OR lower(source_url) LIKE '%example.com%'
           OR lower(source_url) LIKE '%localhost%'
           OR lower(source_url) LIKE '%127.0.0.1%'
           OR source_url = '#'
           OR title LIKE '%ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡%'
           OR description LIKE '%ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡%'
           OR description LIKE '%Demo%'
        """
    ).fetchall()

    fixed = 0
    for row in rows:
        text = f"{row['title'] or ''} {row['location'] or ''}"
        target = default_url
        for province, url in source_map.items():
            if province in text:
                target = url
                break

        title = row["title"] or ""
        if "ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¢ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¢ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡" in title:
            title = "ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"
        if not title.strip():
            title = "ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â§ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã…Â¡ÃƒÂ Ã‚Â¸Ã‚ÂªÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â±ÃƒÂ Ã‚Â¸Ã¢â‚¬ÂÃƒÂ Ã‚Â¸Ã‚Â«ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â‚¬Â¡ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã¢â€žÂ¢"

        conn.execute(
            """
            UPDATE job_posts
            SET title = ?,
                source_url = ?,
                is_government_news = CASE
                    WHEN is_government_news = 1 THEN 1
                    WHEN title LIKE '%ÃƒÂ Ã‚Â¸Ã‚Â£ÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã…Â ÃƒÂ Ã‚Â¸Ã‚ÂÃƒÂ Ã‚Â¸Ã‚Â²ÃƒÂ Ã‚Â¸Ã‚Â£%' THEN 1
                    ELSE is_government_news
                END,
                status = 'ACTIVE',
                updated_at = ?
            WHERE id = ?
            """,
            (title, target, current_time, row["id"])
        )
        fixed += 1

    conn.commit()
    return fixed


def repair_job_source_urls_to_official():
    return force_repair_demo_and_bad_sources()


@app.route("/internal/admin/seed-test-accounts-and-repair", methods=["GET", "POST"])
def internal_seed_test_accounts_and_repair():
    abort(404)



# NOTIFICATION_AUTO_SCHEMA_V1
_NOTIFICATION_SCHEMA_READY = False

@app.before_request
def auto_ensure_notification_schema():
    global _NOTIFICATION_SCHEMA_READY

    if _NOTIFICATION_SCHEMA_READY:
        return None

    try:
        endpoint = request.endpoint or ""
        if endpoint.startswith("static"):
            return None

        ensure_notification_schema()
        _NOTIFICATION_SCHEMA_READY = True
    except Exception:
        return None

    return None



# RESTORED_AUTH_DECORATORS_V2
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for('login'))
            if user['role'] not in roles:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


def _fetch_template_jobs(limit=20, status="ACTIVE", urgent_only=False):
    conn = get_db()
    ensure_production_job_schema(conn)
    where = ["job_posts.status = ?"]
    params = [status]
    if urgent_only:
        where.append("COALESCE(job_posts.is_urgent, 0) = 1")
    return conn.execute(
        f"""
        SELECT
            job_posts.*,
            employer_profiles.company_name,
            employer_profiles.is_company_verified
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE {" AND ".join(where)}
        ORDER BY datetime(job_posts.updated_at) DESC, job_posts.id DESC
        LIMIT ?
        """,
        tuple(params + [int(limit or 20)]),
    ).fetchall()


def _admin_stats():
    conn = get_db()
    ensure_import_run_schema(conn)

    def count(sql, params=()):
        try:
            return int(conn.execute(sql, params).fetchone()["count"] or 0)
        except Exception:
            return 0

    last_import = None
    try:
        last_import = conn.execute(
            "SELECT * FROM import_runs ORDER BY datetime(created_at) DESC, id DESC LIMIT 1"
        ).fetchone()
    except Exception:
        last_import = None

    return {
        "users": count("SELECT COUNT(*) AS count FROM users"),
        "pending_ai": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'PENDING_AI_REVIEW'"),
        "active": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'ACTIVE'"),
        "rejected": count("SELECT COUNT(*) AS count FROM job_posts WHERE status = 'REJECTED'"),
        "reports": count("SELECT COUNT(*) AS count FROM reports WHERE status = 'PENDING'"),
        "import_status": {
            "last_run_at": last_import["created_at"] if last_import else None,
            "last_status": last_import["status"] if last_import else "N/A",
            "last_source": last_import["source_name"] if last_import else "ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â¥",
            "total_imports": count("SELECT COUNT(*) AS count FROM import_runs"),
            "failed_imports": count("SELECT COUNT(*) AS count FROM import_runs WHERE status != 'SUCCESS'"),
        },
    }


def ensure_import_run_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS import_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL,
            status TEXT NOT NULL,
            inserted_count INTEGER NOT NULL DEFAULT 0,
            updated_count INTEGER NOT NULL DEFAULT 0,
            skipped_count INTEGER NOT NULL DEFAULT 0,
            error_message TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_import_runs_created ON import_runs(created_at)")
    conn.commit()


def _record_import_run(source_name, status, inserted=0, updated=0, skipped=0, error_message=""):
    conn = get_db()
    ensure_import_run_schema(conn)
    conn.execute(
        """
        INSERT INTO import_runs (
            source_name, status, inserted_count, updated_count,
            skipped_count, error_message, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(source_name or "UNKNOWN")[:120],
            str(status or "ERROR")[:40],
            int(inserted or 0),
            int(updated or 0),
            int(skipped or 0),
            str(error_message or "")[:1000],
            now_str(),
        ),
    )
    conn.commit()


def _fetch_import_status(conn=None):
    conn = conn or get_db()
    ensure_import_run_schema(conn)

    def count(sql, params=()):
        try:
            return int(conn.execute(sql, params).fetchone()["count"] or 0)
        except Exception:
            return 0

    last_import = conn.execute(
        "SELECT * FROM import_runs ORDER BY datetime(created_at) DESC, id DESC LIMIT 1"
    ).fetchone()

    status = {
        "last_run_at": last_import["created_at"] if last_import else None,
        "last_status": last_import["status"] if last_import else "N/A",
        "last_source": last_import["source_name"] if last_import else "ÃƒÂ Ã‚Â¹Ã¢â‚¬Å¾ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¹Ã‹â€ ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚ÂµÃƒÂ Ã‚Â¸Ã¢â‚¬Å¡ÃƒÂ Ã‚Â¹Ã¢â‚¬Â°ÃƒÂ Ã‚Â¸Ã‚Â­ÃƒÂ Ã‚Â¸Ã‚Â¡ÃƒÂ Ã‚Â¸Ã‚Â¹ÃƒÂ Ã‚Â¸Ã‚Â¥",
        "last_inserted": last_import["inserted_count"] if last_import else 0,
        "last_updated": last_import["updated_count"] if last_import else 0,
        "last_skipped": last_import["skipped_count"] if last_import else 0,
        "last_error": last_import["error_message"] if last_import else "",
        "total_imports": count("SELECT COUNT(*) AS count FROM import_runs"),
        "successful_imports": count("SELECT COUNT(*) AS count FROM import_runs WHERE status = 'SUCCESS'"),
        "failed_imports": count("SELECT COUNT(*) AS count FROM import_runs WHERE status NOT IN ('SUCCESS', 'PARTIAL_SUCCESS')"),
        "partial_imports": count("SELECT COUNT(*) AS count FROM import_runs WHERE status = 'PARTIAL_SUCCESS'"),
        "government_jobs": count("SELECT COUNT(*) AS count FROM job_posts WHERE is_government_news = 1 AND status = 'ACTIVE'"),
    }
    status["is_error"] = status["last_status"] not in ("SUCCESS", "PARTIAL_SUCCESS", "N/A")
    status["is_partial"] = status["last_status"] == "PARTIAL_SUCCESS"
    status["is_ok"] = status["last_status"] == "SUCCESS"
    return status


def _redirect_back(default_endpoint="home"):
    return redirect(request.referrer or url_for(default_endpoint))


register_admin_action_routes(
    app,
    {
        "role_required": role_required,
        "Response": Response,
        "abort": abort,
        "json": json,
        "jsonify": jsonify,
        "redirect": redirect,
        "request": request,
        "url_for": url_for,
        "requests": requests,
        "io": io,
        "zipfile": zipfile,
        "datetime": datetime,
        "timezone": timezone,
        "secure_filename": secure_filename,
        "BASE_DIR": BASE_DIR,
        "SITE_URL": SITE_URL,
        "OPENCHAT_UPLOAD_DIR": OPENCHAT_UPLOAD_DIR,
        "get_discord_webhook_url": lambda: DISCORD_SCAM_ALERT_WEBHOOK_URL,
        "get_current_user": get_current_user,
        "get_db": get_db,
        "add_activity_log": add_activity_log,
        "now_str": now_str,
        "send_discord_alert": send_discord_alert,
        "_record_import_run": _record_import_run,
        "repair_job_source_urls_to_official": repair_job_source_urls_to_official,
        "_cron_token_is_valid": _cron_token_is_valid,
        "_redirect_back": _redirect_back,
    },
)

register_admin_page_routes(
    app,
    {
        "role_required": role_required,
        "render_template": render_template,
        "request": request,
        "sqlite3": sqlite3,
        "get_db": get_db,
        "get_current_user": get_current_user,
        "normalize_phone": normalize_phone,
        "blacklist_phone": blacklist_phone,
        "_admin_stats": _admin_stats,
        "_fetch_import_status": _fetch_import_status,
        "_fetch_template_jobs": _fetch_template_jobs,
        "ensure_import_run_schema": ensure_import_run_schema,
        "now_str": now_str,
        "DB_PATH": DB_PATH,
        "app_secret_key": app.secret_key,
        "ADMIN_PHONE": ADMIN_PHONE,
        "ADMIN_PASSWORD": ADMIN_PASSWORD,
        "JOBBOARD_CRON_TOKEN": JOBBOARD_CRON_TOKEN,
        "JOBBOARD_API_BASE_URL": JOBBOARD_API_BASE_URL,
        "DISCORD_SCAM_ALERT_WEBHOOK_URL": DISCORD_SCAM_ALERT_WEBHOOK_URL,
    },
)

register_auth_routes(
    app,
    {
        "OAUTH_PROVIDERS": OAUTH_PROVIDERS,
        "OTPHandler": OTPHandler,
        "PhoneOTPFlow": PhoneOTPFlow,
        "request": request,
        "render_template": render_template,
        "jsonify": jsonify,
        "redirect": redirect,
        "url_for": url_for,
        "session": session,
        "get_db": get_db,
        "now_str": now_str,
        "normalize_phone": normalize_phone,
        "verify_oauth_state": verify_oauth_state,
        "generate_oauth_state": generate_oauth_state,
        "store_oauth_state": store_oauth_state,
        "store_oauth_callback": store_oauth_callback,
        "get_oauth_callback": get_oauth_callback,
        "hash_password": hash_password,
        "verify_password": verify_password,
        "is_phone_blacklisted": is_phone_blacklisted,
        "is_valid_thai_phone": is_valid_thai_phone,
        "validate_account_password": validate_account_password,
        "validate_profile_name": validate_profile_name,
        "ensure_notification_schema": ensure_notification_schema,
        "create_notification": create_notification,
        "add_activity_log": add_activity_log,
    },
)

register_notification_routes(
    app,
    {
        "login_required": login_required,
        "render_template": render_template,
        "request": request,
        "jsonify": jsonify,
        "url_for": url_for,
        "get_current_user": get_current_user,
        "get_db": get_db,
        "ensure_notification_schema": ensure_notification_schema,
        "now_str": now_str,
        "create_notification": create_notification,
        "get_recent_notifications": get_recent_notifications,
        "get_unread_notifications_count": get_unread_notifications_count,
    },
)

register_dashboard_routes(
    app,
    {
        "login_required": login_required,
        "abort": abort,
        "redirect": redirect,
        "render_template": render_template,
        "request": request,
        "url_for": url_for,
        "datetime": datetime,
        "timedelta": timedelta,
        "get_current_user": get_current_user,
        "get_db": get_db,
        "now_str": now_str,
        "_fetch_template_jobs": _fetch_template_jobs,
        "get_trust_level": get_trust_level,
        "validate_profile_name": validate_profile_name,
        "analyze_job_content": analyze_job_content,
        "_canonical_job_position": lambda *values: _canonical_job_position(*values),
        "_extract_skill_tags": lambda *values: _extract_skill_tags(*values),
        "add_activity_log": add_activity_log,
        "_run_matching_for_job": lambda job_id: _run_matching_for_job(job_id),
        "create_notification": create_notification,
    },
)

register_community_routes(
    app,
    {
        "login_required": login_required,
        "abort": abort,
        "redirect": redirect,
        "render_template": render_template,
        "request": request,
        "url_for": url_for,
        "send_from_directory": send_from_directory,
        "get_current_user": get_current_user,
        "get_db": get_db,
        "now_str": now_str,
        "analyze_job_content": analyze_job_content,
        "create_notification": create_notification,
        "add_activity_log": add_activity_log,
        "_redirect_back": _redirect_back,
        "security_guard": security_guard,
        "OPENCHAT_UPLOAD_DIR": OPENCHAT_UPLOAD_DIR,
    },
)

register_public_routes(
    app,
    {
        "abort": abort,
        "redirect": redirect,
        "render_template": render_template,
        "request": request,
        "url_for": url_for,
        "Response": Response,
        "datetime": datetime,
        "timezone": timezone,
        "get_db": get_db,
        "get_current_user": get_current_user,
        "_fetch_template_jobs": _fetch_template_jobs,
        "track_job_view": track_job_view,
        "get_job_view_count": get_job_view_count,
        "get_live_viewers": get_live_viewers,
        "generate_jobposting_jsonld": generate_jobposting_jsonld,
        "_safe_fetch_public_job_rows": _safe_fetch_public_job_rows,
        "SITE_URL": SITE_URL,
        "CONTENT_GUIDES": CONTENT_GUIDES,
        "FAQ_ITEMS": FAQ_ITEMS,
        "JOB_DATA_SOURCES": JOB_DATA_SOURCES,
        "DEFAULT_PROVINCE_LANDING_PAGES": DEFAULT_PROVINCE_LANDING_PAGES,
        "init_db": init_db,
        "job_slug": job_slug,
    },
)

def _dashboard_risk_level(score, status=""):
    status = str(status or "").upper()
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        score = 0

    if status == "REJECTED" or score >= 70:
        return "HIGH"
    if status == "PENDING_AI_REVIEW" or score >= 35:
        return "MEDIUM"
    return "LOW"


def _api_job_rows(limit=100, urgent_only=False):
    init_db()
    conn = get_db()
    where = ["1 = 1"]
    params = []
    if urgent_only:
        where.append("COALESCE(job_posts.is_urgent, 0) = 1")

    rows = conn.execute(
        f"""
        SELECT
            job_posts.id,
            job_posts.title,
            job_posts.description,
            job_posts.salary_range,
            job_posts.location,
            job_posts.status,
            job_posts.ai_risk_score,
            job_posts.ai_risk_reason,
            job_posts.report_count,
            job_posts.is_urgent,
            job_posts.created_at,
            employer_profiles.company_name
        FROM job_posts
        LEFT JOIN employer_profiles ON employer_profiles.user_id = job_posts.employer_id
        WHERE {" AND ".join(where)}
        ORDER BY datetime(job_posts.created_at) DESC, job_posts.id DESC
        LIMIT ?
        """,
        (*params, int(limit or 100)),
    ).fetchall()

    items = []
    for row in rows:
        risk_level = _dashboard_risk_level(row["ai_risk_score"], row["status"])
        risk_score = int(row["ai_risk_score"] or 0)
        trust_score = max(0, min(100, 100 - risk_score))
        items.append(
            {
                "id": row["id"],
                "title": row["title"],
                "description": row["description"],
                "company": row["company_name"] or "Verified employer",
                "company_name": row["company_name"] or "Verified employer",
                "salary": row["salary_range"],
                "salary_range": row["salary_range"],
                "location": row["location"],
                "status": row["status"],
                "risk_score": risk_score,
                "trust_score": trust_score,
                "risk_level": risk_level,
                "risk_reason": row["ai_risk_reason"],
                "report_count": int(row["report_count"] or 0),
                "is_urgent": bool(row["is_urgent"]),
                "date": row["created_at"],
                "created_at": row["created_at"],
            }
        )

    return items


def _trust_distribution(items):
    buckets = {"0-39": 0, "40-59": 0, "60-79": 0, "80-100": 0}
    for item in items:
        score = int(item.get("trust_score") or 0)
        if score < 40:
            buckets["0-39"] += 1
        elif score < 60:
            buckets["40-59"] += 1
        elif score < 80:
            buckets["60-79"] += 1
        else:
            buckets["80-100"] += 1
    return buckets


def _job_slug_text(job):
    raw = f"{job.get('title') or 'job'}-{job.get('id') or ''}".lower()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return slug or str(job.get("id") or "job")


def _with_job_seo_fields(item):
    location = item.get("location") or "Thailand"
    title = item.get("title") or "Job opening"
    item["slug"] = _job_slug_text(item)
    item["url"] = f"/jobs/{item['id']}/{item['slug']}"
    item["seo_title"] = f"{title} | {location} | JobBoard Anti-Scam"
    item["seo_description"] = (
        f"Apply for {title} in {location}. This listing includes AI trust score "
        f"{item.get('trust_score', 0)} and anti-scam screening."
    )
    item["seo_keywords"] = f"{title}, {location}, trusted jobs, scam safe jobs, jobboard"
    item["geo"] = {
        "region": "TH",
        "placename": location,
        "position": "13.7563;100.5018",
        "icbm": "13.7563, 100.5018",
    }
    return item


register_utility_api_routes(
    app,
    {
        "jsonify": jsonify,
        "render_template": render_template,
        "request": request,
        "requests": requests,
        "url_for": url_for,
        "get_db": get_db,
        "get_job_view_count": get_job_view_count,
        "get_live_viewers": get_live_viewers,
        "ensure_analytics_schema": ensure_analytics_schema,
        "now_str": now_str,
        "init_db": init_db,
        "_api_job_rows": _api_job_rows,
        "_with_job_seo_fields": _with_job_seo_fields,
        "_trust_distribution": _trust_distribution,
        "FAQ_ITEMS": FAQ_ITEMS,
        "CONTENT_GUIDES": CONTENT_GUIDES,
        "SITE_URL": SITE_URL,
        "AI_SEARCH_API_ENDPOINT": AI_SEARCH_API_ENDPOINT,
        "SEO_SITE_NAME": SEO_SITE_NAME,
        "SEO_CITY": SEO_CITY,
        "SEO_REGION": SEO_REGION,
        "SEO_COUNTRY": SEO_COUNTRY,
        "job_slug": job_slug,
        "GOOGLE_ANALYTICS_ID": os.environ.get("GOOGLE_ANALYTICS_ID", "").strip(),
    },
)


discord_services = build_discord_services(
    {
        "DISCORD_BOT_API_TOKEN": lambda: DISCORD_BOT_API_TOKEN,
        "jsonify": jsonify,
        "request": request,
        "get_db": get_db,
        "now_str": now_str,
        "ensure_discord_schema": ensure_discord_schema,
        "hash_password": hash_password,
        "_profile_job_match": _profile_job_match,
        "_row_value": _row_value,
        "_canonical_job_position": _canonical_job_position,
        "scam_risk_label": scam_risk_label,
        "SITE_URL": SITE_URL,
        "url_for": url_for,
        "job_slug": job_slug,
    },
)

_require_discord_bot_token = discord_services["_require_discord_bot_token"]
_json_payload = discord_services["_json_payload"]
_bounded_int = discord_services["_bounded_int"]
_discord_text = discord_services["_discord_text"]
_discord_list_text = discord_services["_discord_list_text"]
_get_or_create_discord_user = discord_services["_get_or_create_discord_user"]
_discord_account_for_user = discord_services["_discord_account_for_user"]
_discord_account_from_request = discord_services["_discord_account_from_request"]
_queue_discord_notification = discord_services["_queue_discord_notification"]
_job_match_score = discord_services["_job_match_score"]
_discord_job_payload = discord_services["_discord_job_payload"]
_discord_profile_payload = discord_services["_discord_profile_payload"]
_notify_followers_for_job = discord_services["_notify_followers_for_job"]
_record_match_event = discord_services["_record_match_event"]
_run_matching_for_job = discord_services["_run_matching_for_job"]
_run_matching_for_profile = discord_services["_run_matching_for_profile"]

register_discord_api_routes(
    app,
    {
        "jsonify": jsonify,
        "request": request,
        "url_for": url_for,
        "get_db": get_db,
        "now_str": now_str,
        "SITE_URL": SITE_URL,
        "_require_discord_bot_token": _require_discord_bot_token,
        "_discord_account_from_request": _discord_account_from_request,
        "_discord_profile_payload": _discord_profile_payload,
        "_json_payload": _json_payload,
        "_get_or_create_discord_user": _get_or_create_discord_user,
        "_discord_text": _discord_text,
        "_discord_list_text": _discord_list_text,
        "_canonical_job_position": _canonical_job_position,
        "_queue_discord_notification": _queue_discord_notification,
        "_notify_followers_for_job": _notify_followers_for_job,
        "_bounded_int": _bounded_int,
        "_discord_job_payload": _discord_job_payload,
        "_run_matching_for_profile": _run_matching_for_profile,
        "_run_matching_for_job": _run_matching_for_job,
        "_profile_job_match": _profile_job_match,
        "_record_match_event": _record_match_event,
        "_job_match_score": _job_match_score,
        "_extract_skill_tags": _extract_skill_tags,
        "analyze_job_content": analyze_job_content,
        "add_activity_log": add_activity_log,
    },
)


if __name__ == "__main__":
    validate_runtime_config()
    with app.app_context():
        init_db()
    app.run(
        host=os.environ.get("JOBBOARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("JOBBOARD_PORT", "5000")),
        debug=os.environ.get("JOBBOARD_DEBUG", "0") == "1",
    )







