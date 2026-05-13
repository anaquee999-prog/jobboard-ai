# Deploy Discord Bot Worker on Koyeb

This service runs the Discord slash-command bot from `discord_bot.py`.
The Flask web app stays on Render at:

```text
https://jobboard-ai-app.onrender.com
```

## Service Settings

Create a new Koyeb service from the GitHub repository:

```text
anaquee999-prog/jobboard-ai
```

Use these settings:

```text
Service type: Worker
Builder: Buildpack
Branch: main
Run command: python discord_bot.py
```

If Koyeb asks for the working directory, leave it as the repository root.

## Required Environment Variables

Set these in the Koyeb service environment:

```text
DISCORD_BOT_TOKEN=your-new-discord-bot-token
DISCORD_BOT_API_TOKEN=same-value-used-on-render-web-service
JOBBOARD_API_BASE_URL=https://jobboard-ai-app.onrender.com
DISCORD_GUILD_ID=your-discord-server-id
DISCORD_ADMIN_USER_IDS=comma-separated-admin-discord-user-ids
DISCORD_NOTIFICATION_POLL_SECONDS=30
```

`DISCORD_GUILD_ID` is strongly recommended because it syncs slash commands to
the JobBoard Community server faster than global command sync.

## Koyeb CLI Alternative

After installing and logging in to the Koyeb CLI, create a worker service with:

```bash
koyeb app init jobboard-ai-discord-worker \
  --git github.com/anaquee999-prog/jobboard-ai \
  --git-branch main \
  --git-builder buildpack \
  --git-buildpack-run-command "python discord_bot.py" \
  --type WORKER \
  --env JOBBOARD_API_BASE_URL=https://jobboard-ai-app.onrender.com \
  --env DISCORD_NOTIFICATION_POLL_SECONDS=30
```

Then add these secrets in the Koyeb dashboard before deploying:

```text
DISCORD_BOT_TOKEN
DISCORD_BOT_API_TOKEN
DISCORD_GUILD_ID
DISCORD_ADMIN_USER_IDS
```

## Verify

After the Koyeb deployment is running:

1. Check the Koyeb runtime logs for a successful Discord login and command sync.
2. In Discord, test:

```text
/stats jobs
/search job
/profile view
```

3. Confirm that webhook alerts still arrive in `#scam-alert`.
4. Confirm that the protected backend API is still OK from Render.

## Troubleshooting

- `Missing required environment variables`: check `DISCORD_BOT_TOKEN` and
  `DISCORD_BOT_API_TOKEN` in Koyeb.
- Slash commands do not appear: confirm `DISCORD_GUILD_ID` is the JobBoard
  Community server ID, then redeploy the worker.
- API requests fail: confirm `DISCORD_BOT_API_TOKEN` matches the Render web
  service value exactly.
- Bot starts but cannot DM users: make sure users have DMs enabled and have
  linked their Discord account through the bot flow.
