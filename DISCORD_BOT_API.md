# Discord Bot API

This file documents the JobBoard AI Discord integration foundation.

## Security

Set this environment variable on Render and in any bot worker:

```text
DISCORD_BOT_API_TOKEN=replace-with-a-long-random-token
```

Every protected Discord API request must include one of:

```text
X-Discord-Bot-Token: <token>
Authorization: Bearer <token>
```

## Discord Bot Worker

The repository now includes `discord_bot.py`, a Discord slash-command worker using `discord.py`.

Required bot worker environment variables:

```text
DISCORD_BOT_TOKEN=Discord bot token
DISCORD_BOT_API_TOKEN=same value as the Flask backend
JOBBOARD_API_BASE_URL=https://jobboard-ai-app.onrender.com
```

Optional variables:

```text
DISCORD_GUILD_ID=server id for fast guild command sync
DISCORD_ADMIN_USER_IDS=comma-separated Discord user ids allowed to run /stats users
DISCORD_NOTIFICATION_POLL_SECONDS=30
```

For the free worker deployment path, use Koyeb and follow:

```text
KOYEB_DISCORD_WORKER.md
```

Koyeb service settings:

```text
Service type: Worker
Builder: Buildpack
Run command: python discord_bot.py
```

Render can run it as a separate worker from the `Procfile`:

```text
worker: python discord_bot.py
```

The repository also includes `render.yaml` as a Render Blueprint for a web service
plus a separate Discord worker. All secret values in that file use `sync: false`,
so set the real values in the Render dashboard after creating or updating services.
Render does not support the free instance type for background workers, so review
the worker plan before deploying the Blueprint.
The repo pins Python with `.python-version` to avoid the current Render default
Python 3.14, which is not compatible with `discord.py==2.4.0`.

## Public Command Metadata

```http
GET /api/discord/commands
```

Returns command names and descriptions for the Discord bot UI.

## Smoke Check

Run a protected Discord API smoke check without printing secret values:

```bash
python check_discord_integration.py
```

Use `--local` when the Flask app is running on `http://127.0.0.1:5000`.

## Slash Command Endpoint Map

- `/profile view` -> `GET /api/discord/profile?discord_user_id=123`
- `/profile edit` -> `POST /api/discord/profile`
- `/search job [keyword] [location] [type]` -> `POST /api/discord/search`
- `/follow company [company_name]` -> `POST /api/discord/follow`
- `/applications` -> `GET /api/discord/applications?discord_user_id=123`
- `/alert job [criteria]` -> `POST /api/discord/alert-job`
- `/post job [title] [salary] [location] [type]` -> `POST /api/discord/post-job`
- `/list jobs` -> `GET /api/discord/jobs`
- `/view applicants [job_id]` -> `GET /api/discord/applicants?discord_user_id=999&job_id=84`
- `/message applicant [user_id] [message]` -> `POST /api/discord/message-applicant`
- `/notify applicants [job_id] [message]` -> `POST /api/discord/notify-applicants`
- `/match jobs [user_id]` -> `GET /api/discord/match-jobs?user_id=123`
- `/match applicants [job_id]` -> `GET /api/discord/match-applicants?job_id=84`
- `/stats users` -> `GET /api/discord/stats/users`
- `/stats jobs` -> `GET /api/discord/stats/jobs`

## Job Seeker

```http
GET /api/discord/profile?discord_user_id=123
```

Returns the Discord-linked job seeker or employer profile.

```http
POST /api/discord/profile
```

Creates or updates a Discord-linked job seeker profile.

```json
{
  "discord_user_id": "123",
  "discord_username": "ana",
  "role": "JOB_SEEKER",
  "full_name": "Ana",
  "desired_position": "โปรแกรมเมอร์",
  "skills": ["Python", "SQL"],
  "preferred_location": "Bangkok",
  "job_type": "fulltime",
  "expected_salary": "35000",
  "resume_url": "https://cdn.example.com/cv.pdf"
}
```

When the profile is saved, the system normalizes the desired position into a canonical job family and creates two-way match notifications when active jobs score at least 70.

```http
POST /api/discord/search
```

Searches active jobs and returns ranked job matches.

```json
{
  "discord_user_id": "123",
  "keyword": "IT",
  "location": "Bangkok",
  "type": "fulltime",
  "limit": 5
}
```

```http
POST /api/discord/apply
```

Applies to an active job and queues a Discord notification for the employer.

```json
{
  "discord_user_id": "123",
  "job_id": 84,
  "message": "สนใจตำแหน่งนี้"
}
```

```http
GET /api/discord/applications?discord_user_id=123
```

Returns the user's latest application statuses.

```http
POST /api/discord/follow
```

Follows a company, location, category, or keyword.

```json
{
  "discord_user_id": "123",
  "type": "company",
  "value": "ABC Co"
}
```

```http
POST /api/discord/alert-job
```

Creates or updates job alert criteria.

```json
{
  "discord_user_id": "123",
  "criteria": {
    "keywords": "Python, SQL",
    "locations": "Bangkok",
    "job_types": "fulltime",
    "min_salary": "35000"
  }
}
```

## Employer

```http
POST /api/discord/post-job
```

Creates an employer profile if needed, scans the job with AI Anti-Scam, creates the job post, and queues matching notifications.

```json
{
  "discord_user_id": "999",
  "discord_username": "employer",
  "company_name": "ABC Co",
  "title": "โปรแกรมเมอร์",
  "description": "รายละเอียดงานอย่างน้อย 40 ตัวอักษร...",
  "required_skills": ["Python", "SQL"],
  "salary": "35000-50000",
  "location": "Bangkok",
  "job_type": "fulltime",
  "is_urgent": true
}
```

When an active job is created, the system matches it against Discord-linked job seeker profiles. Matching jobs queue `job_match` DMs for seekers and `candidate_match` DMs for employers.

```http
GET /api/discord/jobs?keyword=IT&location=Bangkok&type=fulltime
```

Returns active posted jobs. This powers `/list jobs`.

```http
GET /api/discord/applicants?discord_user_id=999&job_id=84
GET /api/discord/employer/applicants?discord_user_id=999
GET /api/discord/employer/applicants?discord_user_id=999&job_id=84
```

Returns recent applicants for that employer.

```http
POST /api/discord/message-applicant
```

Queues a Discord DM and stores an internal message for an applicant.

```json
{
  "discord_user_id": "999",
  "applicant_user_id": 123,
  "message": "We would like to schedule an interview."
}
```

```http
POST /api/discord/notify-applicants
```

Queues a Discord announcement for all applicants on a job.

```json
{
  "discord_user_id": "999",
  "job_id": 84,
  "message": "Interview shortlist will be updated tomorrow."
}
```

## Two-Way Matching

```http
GET /api/discord/matches?discord_user_id=123
```

```http
GET /api/discord/match-jobs?discord_user_id=123
GET /api/discord/match-jobs?user_id=123
GET /api/discord/match-applicants?job_id=84
```

Returns the latest matches for a job seeker or employer. The matching engine scores:

- Canonical position match
- Skill overlap
- Location match
- Job type match
- Salary overlap
- Verified employer boost
- AI risk penalty

Matches with score 70 or higher are stored in `match_events` and queued for both sides.

## Analytics And Notifications

```http
GET /api/discord/analytics
GET /api/discord/stats/users
GET /api/discord/stats/jobs
```

Returns a short dashboard summary for bot responses.

```http
GET /api/discord/notifications/pending?limit=20
```

Returns pending Discord DM notifications. A bot worker should poll this endpoint, send DMs, then mark each item.

```http
POST /api/discord/notifications/<notification_id>/sent
```

```json
{
  "status": "SENT"
}
```

Use `FAILED` when the Discord DM could not be delivered.
