# Production Runbook

## Required Environment Variables

Core:

- `JOBBOARD_SECRET_KEY`
- `JOBBOARD_ADMIN_PHONE`
- `JOBBOARD_ADMIN_PASSWORD`
- `JOBBOARD_DATABASE_PATH`
- `JOBBOARD_BACKUP_DIR`
- `JOBBOARD_SESSION_COOKIE_SECURE`
- `JOBBOARD_CRON_TOKEN`
- `JOBBOARD_API_BASE_URL`

OAuth:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`
- `FACEBOOK_APP_ID`
- `FACEBOOK_APP_SECRET`
- `FACEBOOK_REDIRECT_URI`

Messaging:

- `SMTP_SERVER`
- `SMTP_PORT`
- `SMTP_EMAIL`
- `SMTP_PASSWORD`
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_PHONE`
- `DISCORD_SCAM_ALERT_WEBHOOK_URL`
- `DISCORD_BOT_TOKEN`
- `DISCORD_BOT_API_TOKEN`
- `DISCORD_GUILD_ID`
- `DISCORD_ADMIN_USER_IDS`

Cloudflare:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ZONE_ID`
- `CLOUDFLARE_WWW_IP`
- `CLOUDFLARE_DNS_NAME`

Analytics and ads:

- `GOOGLE_ANALYTICS_ID`
- `MICROSOFT_CLARITY_ID`
- `GOOGLE_ADSENSE_CLIENT`

## Local Verification

```powershell
.\.venv\Scripts\python.exe -m py_compile app.py cloudflare_automation.py cloudflare_setup.py
.\.venv\Scripts\python.exe -m unittest discover -s tests
Set-Location dashboard_frontend
npm.cmd run build
Set-Location ..
```

## Start Locally

```powershell
.\.venv\Scripts\python.exe app.py
```

Open:

- `http://127.0.0.1:5000/`
- `http://127.0.0.1:5000/jobboard-ai/`
- `http://127.0.0.1:5000/jobs`
- `http://127.0.0.1:5000/faq`
- `http://127.0.0.1:5000/guides`

## Cloudflare Dry Run

```powershell
.\run_cloudflare_automation.ps1
```

The PowerShell runner starts with dry-run mode. It only applies real changes after typing `YES`.

## Backup

Manual admin download:

- `/admin/backup/download`

Cron endpoint:

- `/internal/cron/backup`

The cron endpoint requires the `X-Cron-Token` header to match `JOBBOARD_CRON_TOKEN`.

## Load Test

```powershell
.\.venv\Scripts\python.exe load_test.py --base-url http://127.0.0.1:5000 --requests 100 --concurrency 10
```

Use a small concurrency first, then increase gradually.

## Rollback Notes

- Keep a backup ZIP before every production deploy.
- Save Render env vars before large config changes.
- If frontend dashboard fails, rebuild `dashboard_frontend` and confirm Flask serves `/jobboard-ai/`.
- If a cron import fails, check `/admin/import-runs` and `/admin/system-health`.
