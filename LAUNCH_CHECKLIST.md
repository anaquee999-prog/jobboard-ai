# JobBoard AI Launch Checklist

## Local Readiness

- [ ] Run `.\.venv\Scripts\python.exe -m unittest discover -s tests`
- [ ] Run `npm.cmd run build` inside `dashboard_frontend`
- [ ] Open `http://127.0.0.1:5000/`
- [ ] Open `http://127.0.0.1:5000/jobboard-ai/`
- [ ] Open `http://127.0.0.1:5000/jobs`
- [ ] Open `http://127.0.0.1:5000/faq`
- [ ] Open `http://127.0.0.1:5000/guides`
- [ ] Run a small load test: `.\.venv\Scripts\python.exe load_test.py --requests 50 --concurrency 10`

## Render

- [ ] Create or connect the Render service from `render.yaml`
- [ ] Set production environment variables in Render
- [ ] Confirm web service deploys with `gunicorn app:app`
- [ ] Confirm cron service calls `/internal/cron/import-doe-news`
- [ ] Confirm backup cron calls `/internal/cron/backup`

## Cloudflare / Domain

- [ ] Set `CLOUDFLARE_API_TOKEN`
- [ ] Set `CLOUDFLARE_ZONE_ID`
- [ ] Set `CLOUDFLARE_WWW_IP`
- [ ] Set `CLOUDFLARE_DNS_NAME`
- [ ] Run `.\run_cloudflare_automation.ps1`
- [ ] Confirm DNS A record points to production
- [ ] Confirm SSL mode is Full
- [ ] Confirm HTTPS opens the site

## SEO / Analytics

- [ ] Set `GOOGLE_ANALYTICS_ID`
- [ ] Set `MICROSOFT_CLARITY_ID`
- [ ] Add and verify the domain in Google Search Console
- [ ] Submit `/sitemap.xml`
- [ ] Confirm `/robots.txt`
- [ ] Confirm `/llms.txt`
- [ ] Confirm `/faq` renders FAQ schema
- [ ] Confirm `/guides` and `/guides/avoid-job-scams`
- [ ] Confirm province landing pages such as `/jobs/province/Nakhon%20Sawan`

## Safety / Moderation

- [ ] Login as admin
- [ ] Review `/admin/moderation`
- [ ] Review `/admin/scam-center`
- [ ] Test blacklist flow at `/admin/blacklist`
- [ ] Test backup download at `/admin/backup/download`
- [ ] Test Discord alert from `/admin/discord-test`

## Marketing

- [ ] Prepare 10 launch posts for Facebook job groups
- [ ] Prepare Pantip launch post
- [ ] Prepare Reddit Thai launch post
- [ ] Prepare first employer outreach message
- [ ] Prepare first job seeker email campaign
- [ ] Add LINE OA once account is ready

## Revenue

- [ ] Wait until there is enough traffic and content for AdSense review
- [ ] Set `GOOGLE_ADSENSE_CLIENT`
- [ ] Add ad placements after approval
