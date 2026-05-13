import asyncio
import json
import os
from typing import Any

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv


load_dotenv()

DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "").strip()
DISCORD_ADMIN_USER_IDS = {
    item.strip()
    for item in os.environ.get("DISCORD_ADMIN_USER_IDS", "").split(",")
    if item.strip()
}
JOBBOARD_API_BASE_URL = os.environ.get("JOBBOARD_API_BASE_URL", "https://jobboard-ai-app.onrender.com").rstrip("/")
DISCORD_BOT_API_TOKEN = os.environ.get("DISCORD_BOT_API_TOKEN", "").strip()
NOTIFICATION_POLL_SECONDS = max(15, int(os.environ.get("DISCORD_NOTIFICATION_POLL_SECONDS", "30") or 30))

JOB_TYPE_CHOICES = [
    app_commands.Choice(name="ประจำ", value="fulltime"),
    app_commands.Choice(name="พาร์ทไทม์", value="parttime"),
    app_commands.Choice(name="ฟรีแลนซ์", value="freelance"),
    app_commands.Choice(name="สัญญาจ้าง", value="contract"),
]


def _text(value: Any, default: str = "-") -> str:
    value = str(value or "").strip()
    return value if value else default


def _short(value: Any, limit: int = 900) -> str:
    value = _text(value, "")
    return value[: limit - 1] + "…" if len(value) > limit else value


def _discord_user_payload(interaction: discord.Interaction) -> dict[str, str]:
    user = interaction.user
    return {
        "discord_user_id": str(user.id),
        "discord_username": getattr(user, "global_name", None) or user.name,
    }


def _is_admin(interaction: discord.Interaction) -> bool:
    if not DISCORD_ADMIN_USER_IDS:
        return False
    return str(interaction.user.id) in DISCORD_ADMIN_USER_IDS


class JobBoardApi:
    def __init__(self) -> None:
        self.session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "X-Discord-Bot-Token": DISCORD_BOT_API_TOKEN,
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=20),
            )

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()

    async def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        await self.start()
        assert self.session is not None
        url = f"{JOBBOARD_API_BASE_URL}{path}"
        try:
            async with self.session.request(method, url, **kwargs) as response:
                text = await response.text()
                try:
                    data = json.loads(text or "{}")
                except json.JSONDecodeError:
                    data = {"ok": False, "message": text[:500]}
                if response.status >= 400:
                    data.setdefault("ok", False)
                    data.setdefault("message", f"API error {response.status}")
                return data
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"ok": False, "message": f"Cannot reach JobBoard API: {exc}"}

    async def get(self, path: str, **params: Any) -> dict[str, Any]:
        clean = {key: value for key, value in params.items() if value not in (None, "")}
        return await self.request("GET", path, params=clean)

    async def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.request("POST", path, json=payload)


api = JobBoardApi()


def job_embed(job: dict[str, Any], title_prefix: str = "งานที่พบ") -> discord.Embed:
    risk_level = _text(job.get("risk_level"), "UNKNOWN")
    risk_score = int(job.get("risk_score") or 0)
    color = discord.Color.green()
    if risk_score >= 70:
        color = discord.Color.red()
    elif risk_score >= 35:
        color = discord.Color.orange()

    embed = discord.Embed(
        title=f"{title_prefix}: {_short(job.get('title'), 180)}",
        url=job.get("url") or None,
        color=color,
    )
    embed.add_field(name="บริษัท", value=_short(job.get("company_name"), 220), inline=True)
    embed.add_field(name="สถานที่", value=_short(job.get("location"), 120), inline=True)
    embed.add_field(name="เงินเดือน", value=_short(job.get("salary_range"), 120), inline=True)
    embed.add_field(name="Match", value=f"{int(job.get('match_score') or 0)}%", inline=True)
    embed.add_field(name="ความเสี่ยง", value=f"{risk_level} ({risk_score})", inline=True)
    if job.get("match_reason"):
        embed.add_field(name="เหตุผลที่แนะนำ", value=_short(job.get("match_reason"), 400), inline=False)
    embed.set_footer(text=f"Job ID: {job.get('id') or job.get('job_id')} | JobBoard AI Anti-Scam")
    return embed


def application_embed(applications: list[dict[str, Any]]) -> discord.Embed:
    embed = discord.Embed(title="สถานะสมัครงาน", color=discord.Color.blurple())
    if not applications:
        embed.description = "ยังไม่มีรายการสมัครงาน"
        return embed
    for item in applications[:10]:
        embed.add_field(
            name=f"#{item.get('job_id')} {_short(item.get('job_title'), 120)}",
            value=f"{_text(item.get('company_name'))} | {_text(item.get('location'))} | `{_text(item.get('status'))}`",
            inline=False,
        )
    return embed


def profile_embed(profile: dict[str, Any]) -> discord.Embed:
    role = _text(profile.get("role"), "JOB_SEEKER")
    embed = discord.Embed(title="โปรไฟล์ของคุณ", color=discord.Color.teal())
    embed.add_field(name="Discord", value=_text(profile.get("discord_username")), inline=True)
    embed.add_field(name="Role", value=role, inline=True)
    if role == "EMPLOYER":
        employer = profile.get("employer_profile") or {}
        embed.add_field(name="บริษัท", value=_text(employer.get("company_name")), inline=False)
        embed.add_field(name="Verified", value="ใช่" if employer.get("is_company_verified") else "ยังไม่ยืนยัน", inline=True)
        embed.add_field(name="Website", value=_text(employer.get("website")), inline=True)
        return embed

    seeker = profile.get("profile") or {}
    embed.add_field(name="ชื่อ", value=_text(seeker.get("full_name")), inline=True)
    embed.add_field(name="ตำแหน่งที่สนใจ", value=_text(seeker.get("desired_position")), inline=True)
    embed.add_field(name="ประเภทงาน", value=_text(seeker.get("job_type")), inline=True)
    embed.add_field(name="ทักษะ", value=_short(seeker.get("skills"), 700), inline=False)
    embed.add_field(name="พื้นที่", value=_text(seeker.get("preferred_location")), inline=True)
    embed.add_field(name="เงินเดือนคาดหวัง", value=_text(seeker.get("expected_salary")), inline=True)
    embed.add_field(name="CV", value=_text(seeker.get("cv_url") or seeker.get("resume_url")), inline=False)
    return embed


class ApplyButton(discord.ui.Button):
    def __init__(self, job_id: int) -> None:
        super().__init__(label="Apply", style=discord.ButtonStyle.success)
        self.job_id = job_id

    async def callback(self, interaction: discord.Interaction) -> None:
        payload = {
            **_discord_user_payload(interaction),
            "job_id": self.job_id,
            "message": "Applied from Discord",
        }
        data = await api.post("/api/discord/apply", payload)
        if data.get("ok"):
            await interaction.response.send_message(
                f"สมัครงาน #{self.job_id} แล้ว สถานะ: `{data.get('status', 'PENDING')}`",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(_text(data.get("message"), "สมัครงานไม่สำเร็จ"), ephemeral=True)


def job_view(job: dict[str, Any]) -> discord.ui.View:
    view = discord.ui.View(timeout=180)
    job_id = int(job.get("id") or job.get("job_id") or 0)
    if job_id:
        view.add_item(ApplyButton(job_id))
    if job.get("url"):
        view.add_item(discord.ui.Button(label="View", url=job["url"]))
    return view


class ProfileEditModal(discord.ui.Modal, title="แก้ไขโปรไฟล์ผู้หางาน"):
    full_name = discord.ui.TextInput(label="ชื่อ", max_length=120)
    desired_position = discord.ui.TextInput(label="ตำแหน่งที่สนใจ", max_length=120)
    skills = discord.ui.TextInput(label="ทักษะ", style=discord.TextStyle.paragraph, max_length=500)
    preferred_location = discord.ui.TextInput(label="พื้นที่/จังหวัด", max_length=120, required=False)
    cv_url = discord.ui.TextInput(label="CV URL", max_length=500, required=False)

    async def on_submit(self, interaction: discord.Interaction) -> None:
        payload = {
            **_discord_user_payload(interaction),
            "role": "JOB_SEEKER",
            "full_name": self.full_name.value,
            "desired_position": self.desired_position.value,
            "skills": self.skills.value,
            "preferred_location": self.preferred_location.value,
            "resume_url": self.cv_url.value,
            "is_public": True,
        }
        data = await api.post("/api/discord/profile", payload)
        if data.get("ok"):
            await interaction.response.send_message(
                f"บันทึกโปรไฟล์แล้ว และพบ match ใหม่ {int(data.get('new_matches') or 0)} รายการ",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(_text(data.get("message"), "บันทึกโปรไฟล์ไม่สำเร็จ"), ephemeral=True)


class PostJobModal(discord.ui.Modal, title="โพสต์งานใหม่"):
    title_input = discord.ui.TextInput(label="ชื่อตำแหน่ง", max_length=120)
    description = discord.ui.TextInput(label="รายละเอียดงาน", style=discord.TextStyle.paragraph, max_length=1800)
    salary = discord.ui.TextInput(label="เงินเดือน", max_length=120, required=False)
    location = discord.ui.TextInput(label="พื้นที่/จังหวัด", max_length=120)
    required_skills = discord.ui.TextInput(label="ทักษะที่ต้องการ", max_length=400, required=False)

    def __init__(self, job_type: str, company_name: str = "") -> None:
        super().__init__()
        self.job_type = job_type
        self.company_name = company_name

    async def on_submit(self, interaction: discord.Interaction) -> None:
        payload = {
            **_discord_user_payload(interaction),
            "role": "EMPLOYER",
            "company_name": self.company_name or interaction.user.name,
            "title": self.title_input.value,
            "description": self.description.value,
            "salary": self.salary.value,
            "location": self.location.value,
            "required_skills": self.required_skills.value,
            "job_type": self.job_type,
        }
        data = await api.post("/api/discord/post-job", payload)
        if data.get("ok"):
            embed = discord.Embed(
                title="โพสต์งานเรียบร้อย",
                description=f"Job ID: `{data.get('job_id')}` | Status: `{data.get('status')}`",
                url=data.get("url") or None,
                color=discord.Color.green() if data.get("status") == "ACTIVE" else discord.Color.orange(),
            )
            embed.add_field(name="AI Risk", value=f"{data.get('risk_score')} | {_short(data.get('risk_reason'), 500)}", inline=False)
            embed.add_field(name="Queued Notifications", value=str(data.get("queued_notifications") or 0), inline=True)
            await interaction.response.send_message(embed=embed, ephemeral=True)
        else:
            await interaction.response.send_message(_text(data.get("message"), "โพสต์งานไม่สำเร็จ"), ephemeral=True)


class JobBoardBot(commands.Bot):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self) -> None:
        await api.start()
        for group in COMMAND_GROUPS:
            self.tree.add_command(group)
        if DISCORD_GUILD_ID:
            guild = discord.Object(id=int(DISCORD_GUILD_ID))
            self.tree.copy_global_to(guild=guild)
            synced = await self.tree.sync(guild=guild)
            print(f"Synced {len(synced)} Discord slash command groups to guild {DISCORD_GUILD_ID}", flush=True)
        else:
            synced = await self.tree.sync()
            print(f"Synced {len(synced)} global Discord slash command groups", flush=True)
        notification_poller.change_interval(seconds=NOTIFICATION_POLL_SECONDS)
        notification_poller.start()

    async def close(self) -> None:
        notification_poller.cancel()
        await api.close()
        await super().close()


bot = JobBoardBot()


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
    print(f"Discord command error: {error!r}", flush=True)
    message = "คำสั่งทำงานไม่สำเร็จ กรุณาลองใหม่อีกครั้ง"
    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except Exception as exc:
        print(f"Failed to send command error response: {exc!r}", flush=True)

profile_group = app_commands.Group(name="profile", description="โปรไฟล์ผู้หางาน")
search_group = app_commands.Group(name="search", description="ค้นหา")
follow_group = app_commands.Group(name="follow", description="ติดตาม")
alert_group = app_commands.Group(name="alert", description="แจ้งเตือน")
post_group = app_commands.Group(name="post", description="โพสต์")
list_group = app_commands.Group(name="list", description="รายการ")
view_group = app_commands.Group(name="view", description="ดูข้อมูล")
message_group = app_commands.Group(name="message", description="ส่งข้อความ")
notify_group = app_commands.Group(name="notify", description="แจ้งผู้ใช้")
match_group = app_commands.Group(name="match", description="AI matching")
stats_group = app_commands.Group(name="stats", description="สถิติ")


@profile_group.command(name="view", description="ดูโปรไฟล์ตัวเอง")
async def profile_view(interaction: discord.Interaction) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.get("/api/discord/profile", discord_user_id=str(interaction.user.id))
    if data.get("ok"):
        await interaction.followup.send(embed=profile_embed(data.get("profile") or {}), ephemeral=True)
    else:
        await interaction.followup.send(_text(data.get("message"), "ยังไม่พบโปรไฟล์ ใช้ /profile edit ก่อน"), ephemeral=True)


@profile_group.command(name="edit", description="แก้ไขโปรไฟล์ผู้หางาน")
async def profile_edit(interaction: discord.Interaction) -> None:
    await interaction.response.send_modal(ProfileEditModal())


@search_group.command(name="job", description="ค้นหางานด้วย keyword, location, type")
@app_commands.choices(type=JOB_TYPE_CHOICES)
async def search_job(
    interaction: discord.Interaction,
    keyword: str = "",
    location: str = "",
    type: app_commands.Choice[str] | None = None,
) -> None:
    await interaction.response.defer(ephemeral=True)
    payload = {
        **_discord_user_payload(interaction),
        "keyword": keyword,
        "location": location,
        "type": type.value if type else "",
        "limit": 5,
    }
    data = await api.post("/api/discord/search", payload)
    jobs = data.get("jobs") or []
    if not jobs:
        await interaction.followup.send(_text(data.get("message"), "ไม่พบงานที่ตรงเงื่อนไข"), ephemeral=True)
        return
    await interaction.followup.send(f"พบงาน {len(jobs)} รายการ", ephemeral=True)
    for job in jobs[:5]:
        await interaction.followup.send(embed=job_embed(job), view=job_view(job), ephemeral=True)


@follow_group.command(name="company", description="ติดตามบริษัท")
async def follow_company(interaction: discord.Interaction, company_name: str) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.post(
        "/api/discord/follow",
        {**_discord_user_payload(interaction), "type": "company", "value": company_name},
    )
    await interaction.followup.send(
        "ติดตามบริษัทแล้ว" if data.get("ok") else _text(data.get("message"), "ติดตามไม่สำเร็จ"),
        ephemeral=True,
    )


@alert_group.command(name="job", description="ตั้งแจ้งเตือนงาน")
@app_commands.choices(type=JOB_TYPE_CHOICES)
async def alert_job(
    interaction: discord.Interaction,
    keyword: str = "",
    location: str = "",
    type: app_commands.Choice[str] | None = None,
    min_salary: str = "",
) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.post(
        "/api/discord/alert-job",
        {
            **_discord_user_payload(interaction),
            "criteria": {
                "keywords": keyword,
                "locations": location,
                "job_types": type.value if type else "",
                "min_salary": min_salary,
            },
        },
    )
    await interaction.followup.send(
        "ตั้งแจ้งเตือนงานแล้ว" if data.get("ok") else _text(data.get("message"), "ตั้งแจ้งเตือนไม่สำเร็จ"),
        ephemeral=True,
    )


@bot.tree.command(name="applications", description="ดูสถานะสมัครงาน")
async def applications(interaction: discord.Interaction) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.get("/api/discord/applications", discord_user_id=str(interaction.user.id))
    await interaction.followup.send(embed=application_embed(data.get("applications") or []), ephemeral=True)


@post_group.command(name="job", description="โพสต์งานใหม่")
@app_commands.choices(type=JOB_TYPE_CHOICES)
async def post_job(
    interaction: discord.Interaction,
    type: app_commands.Choice[str],
    company_name: str = "",
) -> None:
    await interaction.response.send_modal(PostJobModal(type.value, company_name))


@list_group.command(name="jobs", description="ดูงานที่เปิดรับอยู่")
@app_commands.choices(type=JOB_TYPE_CHOICES)
async def list_jobs(
    interaction: discord.Interaction,
    keyword: str = "",
    location: str = "",
    type: app_commands.Choice[str] | None = None,
) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.get(
        "/api/discord/jobs",
        keyword=keyword,
        location=location,
        type=type.value if type else "",
        limit=10,
    )
    jobs = data.get("jobs") or []
    if not jobs:
        await interaction.followup.send("ยังไม่พบงานที่เปิดรับ", ephemeral=True)
        return
    await interaction.followup.send(f"งานที่เปิดรับ {len(jobs)} รายการ", ephemeral=True)
    for job in jobs[:5]:
        await interaction.followup.send(embed=job_embed(job, "เปิดรับ"), view=job_view(job), ephemeral=True)


@view_group.command(name="applicants", description="ดูผู้สมัครของงาน")
async def view_applicants(interaction: discord.Interaction, job_id: int) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.get("/api/discord/applicants", discord_user_id=str(interaction.user.id), job_id=job_id)
    applicants = data.get("applications") or []
    embed = discord.Embed(title=f"ผู้สมัครงาน #{job_id}", color=discord.Color.blurple())
    if not applicants:
        embed.description = "ยังไม่มีผู้สมัคร หรือคุณไม่มีสิทธิ์ดูงานนี้"
    for item in applicants[:10]:
        embed.add_field(
            name=f"{_text(item.get('applicant_name'))} | User {item.get('applicant_user_id')}",
            value=f"{_short(item.get('headline'), 180)}\nSkills: {_short(item.get('skills'), 220)}\nStatus: `{_text(item.get('status'))}`",
            inline=False,
        )
    await interaction.followup.send(embed=embed, ephemeral=True)


@message_group.command(name="applicant", description="DM ผู้สมัคร")
async def message_applicant(interaction: discord.Interaction, user_id: int, message: str) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.post(
        "/api/discord/message-applicant",
        {**_discord_user_payload(interaction), "applicant_user_id": user_id, "message": message},
    )
    await interaction.followup.send(
        "ส่งข้อความเข้าคิว DM แล้ว" if data.get("ok") else _text(data.get("message"), "ส่งข้อความไม่สำเร็จ"),
        ephemeral=True,
    )


@notify_group.command(name="applicants", description="แจ้งผู้สมัครในงาน")
async def notify_applicants(interaction: discord.Interaction, job_id: int, message: str) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.post(
        "/api/discord/notify-applicants",
        {**_discord_user_payload(interaction), "job_id": job_id, "message": message},
    )
    await interaction.followup.send(
        f"แจ้งผู้สมัคร {data.get('applicants', 0)} คนแล้ว"
        if data.get("ok")
        else _text(data.get("message"), "แจ้งผู้สมัครไม่สำเร็จ"),
        ephemeral=True,
    )


@match_group.command(name="jobs", description="AI แนะนำงานที่ตรงโปรไฟล์")
async def match_jobs(interaction: discord.Interaction, user_id: int | None = None) -> None:
    await interaction.response.defer(ephemeral=True)
    params = {"limit": 5}
    if user_id and _is_admin(interaction):
        params["user_id"] = user_id
    else:
        params["discord_user_id"] = str(interaction.user.id)
    data = await api.get("/api/discord/match-jobs", **params)
    matches = data.get("matches") or []
    if not matches:
        await interaction.followup.send(_text(data.get("message"), "ยังไม่มีงานที่ match"), ephemeral=True)
        return
    await interaction.followup.send(f"AI แนะนำงาน {len(matches)} รายการ", ephemeral=True)
    for job in matches[:5]:
        await interaction.followup.send(embed=job_embed(job, "AI Match"), view=job_view(job), ephemeral=True)


@match_group.command(name="applicants", description="AI แนะนำผู้สมัครที่ตรงงาน")
async def match_applicants(interaction: discord.Interaction, job_id: int) -> None:
    await interaction.response.defer(ephemeral=True)
    params = {"job_id": job_id, "limit": 10}
    if not _is_admin(interaction):
        params["discord_user_id"] = str(interaction.user.id)
    data = await api.get("/api/discord/match-applicants", **params)
    matches = data.get("matches") or []
    embed = discord.Embed(title=f"AI แนะนำผู้สมัครสำหรับงาน #{job_id}", color=discord.Color.purple())
    if not matches:
        embed.description = _text(data.get("message"), "ยังไม่มีผู้สมัครที่ match")
    for item in matches[:10]:
        embed.add_field(
            name=f"{_text(item.get('applicant_name'))} | {int(item.get('match_score') or 0)}%",
            value=f"{_short(item.get('headline'), 180)}\nSkills: {_short(item.get('skills'), 220)}\nReason: {_short(item.get('match_reason'), 220)}",
            inline=False,
        )
    await interaction.followup.send(embed=embed, ephemeral=True)


@stats_group.command(name="users", description="สถิติผู้ใช้")
async def stats_users(interaction: discord.Interaction) -> None:
    await interaction.response.defer(ephemeral=True)
    if not _is_admin(interaction):
        await interaction.followup.send("คำสั่งนี้จำกัดเฉพาะ admin", ephemeral=True)
        return
    data = await api.get("/api/discord/stats/users")
    stats = data.get("stats") or {}
    embed = discord.Embed(title="สถิติผู้ใช้", color=discord.Color.gold())
    for key, value in stats.items():
        embed.add_field(name=key, value=str(value), inline=True)
    await interaction.followup.send(embed=embed, ephemeral=True)


@stats_group.command(name="jobs", description="สถิติงาน")
async def stats_jobs(interaction: discord.Interaction) -> None:
    await interaction.response.defer(ephemeral=True)
    data = await api.get("/api/discord/stats/jobs")
    stats = data.get("stats") or {}
    embed = discord.Embed(title="สถิติงาน", color=discord.Color.gold())
    for key, value in stats.items():
        embed.add_field(name=key, value=str(value), inline=True)
    top_jobs = data.get("top_jobs") or []
    if top_jobs:
        embed.add_field(
            name="งานยอดนิยม",
            value="\n".join(
                f"#{item.get('job_id')} {_short(item.get('job_title'), 80)} ({item.get('applications')} applications)"
                for item in top_jobs[:5]
            ),
            inline=False,
        )
    await interaction.followup.send(embed=embed, ephemeral=True)


COMMAND_GROUPS = [
    profile_group,
    search_group,
    follow_group,
    alert_group,
    post_group,
    list_group,
    view_group,
    message_group,
    notify_group,
    match_group,
    stats_group,
]


@tasks.loop(seconds=NOTIFICATION_POLL_SECONDS)
async def notification_poller() -> None:
    await bot.wait_until_ready()
    data = await api.get("/api/discord/notifications/pending", limit=20)
    for item in data.get("notifications") or []:
        status = "SENT"
        try:
            user = await bot.fetch_user(int(item["discord_user_id"]))
            payload = item.get("payload") or {}
            embed = discord.Embed(
                title=_text(payload.get("title") or item.get("event_type"), "JobBoard notification"),
                description=_short(payload.get("message") or payload.get("job_title") or payload.get("applicant_name"), 1800),
                color=discord.Color.blurple(),
            )
            if payload.get("url"):
                embed.url = payload["url"]
            for key in ("job_id", "job_title", "company_name", "location", "match_score", "status"):
                if payload.get(key) not in (None, ""):
                    embed.add_field(name=key, value=_short(payload.get(key), 220), inline=True)
            await user.send(embed=embed)
        except Exception:
            status = "FAILED"
        await api.post(f"/api/discord/notifications/{item['id']}/sent", {"status": status})
        await asyncio.sleep(0.5)


def main() -> None:
    missing = []
    if not DISCORD_BOT_TOKEN:
        missing.append("DISCORD_BOT_TOKEN")
    if not DISCORD_BOT_API_TOKEN:
        missing.append("DISCORD_BOT_API_TOKEN")
    if missing:
        raise RuntimeError("Missing required environment variables: " + ", ".join(missing))
    bot.run(DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    main()
