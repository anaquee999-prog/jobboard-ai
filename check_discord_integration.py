import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from dotenv import load_dotenv


DEFAULT_PRODUCTION_URL = "https://jobboard-ai-app.onrender.com"
DEFAULT_LOCAL_URL = "http://127.0.0.1:5000"


def load_environment() -> None:
    load_dotenv(".env")


def request_json(base_url: str, token: str, method: str, path: str, payload=None) -> tuple[int, dict]:
    body = None
    headers = {
        "User-Agent": "JobBoard Discord Smoke Check",
        "X-Discord-Bot-Token": token,
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
        data=body,
        headers=headers,
        method=method,
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        if not raw:
            return response.status, {}
        return response.status, json.loads(raw.decode("utf-8"))


def summarize(label: str, status: int, data: dict) -> None:
    details = [f"status={status}"]
    if "ok" in data:
        details.append(f"ok={data.get('ok')}")
    if "count" in data:
        details.append(f"count={data.get('count')}")
    if "commands" in data:
        details.append(f"commands={len(data.get('commands') or [])}")
    if "notifications" in data:
        details.append(f"notifications={len(data.get('notifications') or [])}")
    if "stats" in data and isinstance(data["stats"], dict):
        stats = data["stats"]
        for key in ("discord_users", "pending_notifications", "active_jobs", "total_jobs"):
            if key in stats:
                details.append(f"{key}={stats[key]}")
    print(f"[PASS] {label} - " + ", ".join(details))


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test the protected Discord bot API.")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("JOBBOARD_API_BASE_URL") or DEFAULT_PRODUCTION_URL,
        help="Backend base URL. Defaults to JOBBOARD_API_BASE_URL or production.",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help=f"Use {DEFAULT_LOCAL_URL} instead of production.",
    )
    args = parser.parse_args()

    load_environment()
    token = os.environ.get("DISCORD_BOT_API_TOKEN", "").strip()
    if not token:
        print("[FAIL] DISCORD_BOT_API_TOKEN is not configured.", file=sys.stderr)
        return 1

    base_url = DEFAULT_LOCAL_URL if args.local else args.base_url
    checks = [
        ("commands", "GET", "/api/discord/commands", None),
        ("jobs", "GET", "/api/discord/jobs?keyword=IT&location=Bangkok", None),
        ("stats-users", "GET", "/api/discord/stats/users", None),
        ("stats-jobs", "GET", "/api/discord/stats/jobs", None),
        ("pending-notifications", "GET", "/api/discord/notifications/pending?limit=3", None),
    ]

    print(f"Discord smoke check target: {base_url}")
    failed = False
    for label, method, path, payload in checks:
        try:
            status, data = request_json(base_url, token, method, path, payload)
            if status < 200 or status >= 300 or data.get("ok") is False:
                failed = True
                print(f"[FAIL] {label} - status={status}, response={data}")
            else:
                summarize(label, status, data)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            failed = True
            print(f"[FAIL] {label} - {type(exc).__name__}: {exc}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
