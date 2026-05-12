# JobBoard AI Anti-Scam Platform - Final Handover

Last updated: 2026-05-10

## Production

- Production URL: https://jobboard-ai-app.onrender.com
- GitHub Repo: https://github.com/anaquee999-prog/jobboard-ai
- Render Service: `jobboard-ai-app`
- Main app: Flask backend served by Gunicorn

## Current Status

Production is online and usable.

- Public home page is live
- Login, register, and OTP flows are available
- Admin dashboard is available
- System health page is available
- Backup ZIP download is available for admins
- Discord webhook test route is available
- Discord alerts are configured for scam and moderation events
- Discord Bot API foundation is available for profile, search, follow, apply, post job, applicants, two-way matching, analytics, and queued DM notifications
- Discord Bot worker scaffold is available in `discord_bot.py` with slash commands, modals, embeds, apply buttons, and pending DM polling
- Community safety has rate limiting, duplicate-post checks, AI moderation, user reports, and admin review actions
- Scam Center and Trust Center are available
- GitHub, Render, and the local repository are aligned

## Important URLs

Admin login is required for admin routes.

- Home: https://jobboard-ai-app.onrender.com
- Admin Dashboard: https://jobboard-ai-app.onrender.com/admin
- System Health: https://jobboard-ai-app.onrender.com/admin/system-health
- Backup ZIP: https://jobboard-ai-app.onrender.com/admin/backup/download
- Discord Test: https://jobboard-ai-app.onrender.com/admin/discord-test
- Discord Bot API Docs: `DISCORD_BOT_API.md`
- Scam Center: https://jobboard-ai-app.onrender.com/admin/scam-center
- Moderation: https://jobboard-ai-app.onrender.com/admin/moderation
- Logs: https://jobboard-ai-app.onrender.com/admin/logs
- Trust Center: https://jobboard-ai-app.onrender.com/admin/trust

## Scheduled Jobs

GitHub Actions runs the daily import workflow:

- Workflow file: `.github/workflows/auto-import-upper-central-jobs.yml`
- Cron URL: `https://jobboard-ai-app.onrender.com/internal/cron/import-upper-central-jobs`
- Required secret: `JOBBOARD_CRON_TOKEN`

The workflow calls the cron endpoint with the `X-Cron-Token` header.

## Required Render Environment Variables

Do not commit real secret values. Configure these in Render:

- `JOBBOARD_SECRET_KEY`
- `JOBBOARD_ADMIN_PHONE`
- `JOBBOARD_ADMIN_PASSWORD`
- `JOBBOARD_DATABASE_PATH`
- `JOBBOARD_SESSION_COOKIE_SECURE`
- `JOBBOARD_CRON_TOKEN`
- `DISCORD_SCAM_ALERT_WEBHOOK_URL`
- `DISCORD_BOT_API_TOKEN`
- `DISCORD_BOT_TOKEN`
- `JOBBOARD_API_BASE_URL`
- `DISCORD_GUILD_ID` optional for fast guild command sync
- `DISCORD_ADMIN_USER_IDS` optional comma-separated admin Discord user IDs
- `DISCORD_NOTIFICATION_POLL_SECONDS` optional, defaults to 30

Current local/example database setting:

```text
JOBBOARD_DATABASE_PATH=instance/jobboard.db
```

## Deployment Notes

- Render uses `Procfile` with `web: gunicorn app:app`
- The Discord bot can run as a separate Render worker with `worker: python discord_bot.py`
- `render.yaml` is available as a Render Blueprint for the web service and Discord worker
- `.python-version` pins Render to Python 3.12 because `discord.py==2.4.0` is not compatible with Python 3.14
- Render does not offer the free instance type for background workers; review the worker plan before deploying the Blueprint
- Python dependencies are listed in `requirements.txt`
- Runtime database files and local secrets must stay out of git
- Rotate `DISCORD_SCAM_ALERT_WEBHOOK_URL` in Discord and Render if the webhook URL was shared anywhere
- SQLite storage on Render Free can be lost after restart or redeploy, so use the admin Backup ZIP regularly

## Final Verification

Latest local checks:

- Production homepage responded successfully
- Local git remote points to `anaquee999-prog/jobboard-ai`
- Local git status was clean before this handover cleanup
- Core Python files compiled successfully with the project virtual environment

## Handover Result

The production app is live, the repository is connected to GitHub, and the main operational routes are documented above.
