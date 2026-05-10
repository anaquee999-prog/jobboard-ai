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

## Public Command Metadata

```http
GET /api/discord/commands
```

Returns command names and descriptions for the Discord bot UI.

## Job Seeker

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
  "skills": ["Python", "SQL"],
  "location": "Bangkok",
  "resume_url": "https://cdn.example.com/cv.pdf"
}
```

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
  "salary": "35000-50000",
  "location": "Bangkok",
  "is_urgent": true
}
```

```http
GET /api/discord/employer/applicants?discord_user_id=999
GET /api/discord/employer/applicants?discord_user_id=999&job_id=84
```

Returns recent applicants for that employer.

## Analytics And Notifications

```http
GET /api/discord/analytics
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
