#!/usr/bin/env python3
"""
Idempotent deployment helper for JobBoard Flask app.

What it does:
1) Ensures deployment environment variables exist (and writes/updates .env safely).
2) Installs Python dependencies from requirements.txt.
3) Starts Gunicorn locally for health verification.
4) Verifies key endpoints:
   - /
   - /job/<id or slug> (best-effort discovery, then fallback candidates)
   - /api/ai-search?q=...
5) Runs Cloudflare automation in dry-run mode, then prompts for confirmation
   before running real mode.
6) Prints an optional GA4 verification note.

This script does not modify application source code.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import requests


REPO_DIR = Path(__file__).resolve().parent
ENV_PATH = REPO_DIR / ".env"
REQUIREMENTS_PATH = REPO_DIR / "requirements.txt"
APP_MODULE = "app:app"
GUNICORN_BIND = "127.0.0.1:8000"
BASE_URL = f"http://{GUNICORN_BIND}"


DEFAULT_ENV: Dict[str, str] = {
    "GOOGLE_ANALYTICS_ID": "G-XXXXXXXXXX",
    "JOBBOARD_SEO_SITE_NAME": "JobBoard AI",
    "JOBBOARD_SEO_CITY": "Bangkok",
    "JOBBOARD_SEO_REGION": "Bangkok",
    "JOBBOARD_SEO_COUNTRY": "TH",
    "AI_SEARCH_API_ENDPOINT": "",
    # Must be >= 32 chars for app validation in validate_runtime_config()
    "JOBBOARD_SECRET_KEY": "replace-with-a-long-random-secret-at-least-32-chars",
    # Required by validate_runtime_config() during startup.
    "JOBBOARD_ADMIN_PHONE": "0999999999",
    "JOBBOARD_ADMIN_PASSWORD": "replace-with-a-strong-admin-password",
}


class StepError(RuntimeError):
    pass


def print_step(name: str) -> None:
    print(f"\n==> {name}")


def print_ok(msg: str) -> None:
    print(f"[OK] {msg}")


def print_warn(msg: str) -> None:
    print(f"[WARN] {msg}")


def print_fail(msg: str) -> None:
    print(f"[FAIL] {msg}")


def run_cmd(
    cmd: List[str],
    *,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        cwd=str(cwd or REPO_DIR),
        env=env,
        text=True,
        capture_output=True,
    )
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    if check and result.returncode != 0:
        raise StepError(f"Command failed ({result.returncode}): {' '.join(cmd)}")
    return result


def read_env_file(path: Path) -> Dict[str, str]:
    data: Dict[str, str] = {}
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.strip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def upsert_env_file(path: Path, values: Dict[str, str]) -> None:
    existing_lines: List[str] = []
    if path.exists():
        existing_lines = path.read_text(encoding="utf-8").splitlines()

    key_pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
    present_keys = set()
    new_lines: List[str] = []

    for line in existing_lines:
        match = key_pattern.match(line)
        if not match:
            new_lines.append(line)
            continue
        key = match.group(1)
        if key in values:
            new_lines.append(f"{key}={values[key]}")
            present_keys.add(key)
        else:
            new_lines.append(line)

    for key, value in values.items():
        if key not in present_keys:
            new_lines.append(f"{key}={value}")

    path.write_text("\n".join(new_lines).rstrip() + "\n", encoding="utf-8")


def ensure_env_vars(non_interactive: bool = False) -> Dict[str, str]:
    print_step("Setting environment variables")
    file_values = read_env_file(ENV_PATH)
    final_values: Dict[str, str] = {}

    for key, default in DEFAULT_ENV.items():
        current = os.environ.get(key, "").strip() or file_values.get(key, "").strip()

        if current:
            final_values[key] = current
            continue

        if non_interactive:
            final_values[key] = default
        else:
            entered = input(f"{key} [{default}]: ").strip()
            final_values[key] = entered if entered else default

        os.environ[key] = final_values[key]

    # Keep process env aligned even if loaded from file.
    for key, value in final_values.items():
        os.environ[key] = value

    upsert_env_file(ENV_PATH, final_values)
    print_ok(f"Updated {ENV_PATH.name} idempotently")

    if len(final_values.get("JOBBOARD_SECRET_KEY", "")) < 32:
        print_warn("JOBBOARD_SECRET_KEY is shorter than 32 chars; app validation may fail.")

    return final_values


def install_dependencies() -> None:
    print_step("Installing dependencies")
    if not REQUIREMENTS_PATH.exists():
        raise StepError("requirements.txt not found")
    run_cmd([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_PATH)])
    print_ok("Dependencies installed")


def start_gunicorn(env: Dict[str, str]) -> subprocess.Popen:
    print_step("Starting Gunicorn")
    cmd = [
        sys.executable,
        "-m",
        "gunicorn",
        "--bind",
        GUNICORN_BIND,
        "--workers",
        "2",
        "--timeout",
        "120",
        APP_MODULE,
    ]
    print(f"$ {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        cwd=str(REPO_DIR),
        env={**os.environ, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return process


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
            time.sleep(1)
        else:
            process.terminate()
        process.wait(timeout=10)
    except Exception:
        process.kill()


def wait_for_server(process: Optional[subprocess.Popen] = None, timeout_sec: int = 45) -> None:
    start = time.time()
    while time.time() - start < timeout_sec:
        if process is not None and process.poll() is not None:
            output = ""
            if process.stdout is not None:
                try:
                    output = process.stdout.read().strip()
                except Exception:
                    output = ""
            if output:
                print(output)
            raise StepError("Gunicorn exited before the server became ready")
        try:
            resp = requests.get(f"{BASE_URL}/", timeout=3)
            if resp.status_code == 200:
                print_ok("Gunicorn is ready")
                return
        except Exception:
            pass
        time.sleep(1)
    raise StepError("Gunicorn did not become ready in time")


def find_job_url() -> Optional[str]:
    # 1) Try sitemap for /job/...
    try:
        res = requests.get(f"{BASE_URL}/sitemap.xml", timeout=5)
        if res.ok:
            match = re.search(r"<loc>(https?://[^<]+/job/[^<]+)</loc>", res.text)
            if match:
                return match.group(1).replace(BASE_URL, "")
    except Exception:
        pass

    # 2) Try /jobs page links
    try:
        res = requests.get(f"{BASE_URL}/jobs", timeout=5)
        if res.ok:
            match = re.search(r'href="(/job/[^"]+)"', res.text)
            if match:
                return match.group(1)
    except Exception:
        pass

    return None


def check_endpoint(path: str, expected_statuses: Iterable[int] = (200,)) -> Tuple[bool, int]:
    url = f"{BASE_URL}{path}"
    try:
        res = requests.get(url, timeout=8)
        ok = res.status_code in expected_statuses
        return ok, res.status_code
    except Exception:
        return False, 0


def verify_endpoints() -> None:
    print_step("Verifying production endpoints")

    checks: List[Tuple[str, Tuple[int, ...]]] = [
        ("/", (200,)),
        ("/api/ai-search?q=test", (200, 400)),
    ]

    job_path = find_job_url()
    if job_path:
        checks.append((job_path, (200,)))
    else:
        # Fallback candidates for /job/<id> requirement.
        checks.append(("/job/1", (200,)))

    failed: List[str] = []
    for path, statuses in checks:
        ok, code = check_endpoint(path, statuses)
        if ok:
            print_ok(f"{path} -> {code}")
        else:
            print_fail(f"{path} -> {code or 'no response'}")
            failed.append(path)

    if failed:
        raise StepError("Endpoint verification failed: " + ", ".join(failed))


def run_cloudflare_automation(skip: bool = False, auto_yes: bool = False) -> None:
    if skip:
        print_warn("Skipping Cloudflare automation (--skip-cloudflare)")
        return

    script_path = REPO_DIR / "cloudflare_automation.py"
    powershell_path = REPO_DIR / "run_cloudflare_automation.ps1"
    if not script_path.exists() and not powershell_path.exists():
        print_warn("Cloudflare automation files not found; skipping Cloudflare step")
        return

    print_step("Cloudflare automation: dry-run")
    env = os.environ.copy()
    if powershell_path.exists():
        run_cmd(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(powershell_path),
            ],
            env={**env, "DRY_RUN": "1"},
        )
    else:
        run_cmd([sys.executable, str(script_path)], env={**env, "DRY_RUN": "1"})
    print_ok("Cloudflare dry-run completed")

    proceed = auto_yes
    if not auto_yes:
        answer = input("Type YES to run Cloudflare real mode: ").strip()
        proceed = answer == "YES"

    if not proceed:
        print_warn("Cloudflare real mode cancelled by user")
        return

    print_step("Cloudflare automation: real mode")
    if powershell_path.exists():
        run_cmd(
            [
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(powershell_path),
            ],
            env={**env, "DRY_RUN": "0"},
        )
    else:
        run_cmd([sys.executable, str(script_path)], env={**env, "DRY_RUN": "0"})
    print_ok("Cloudflare real mode completed")


def print_ga4_note(env_values: Dict[str, str]) -> None:
    print_step("Optional GA4 check")
    ga4_id = env_values.get("GOOGLE_ANALYTICS_ID", "").strip()
    if not ga4_id or ga4_id == "G-XXXXXXXXXX":
        print_warn("GA4 ID looks unset or placeholder. Skipping GA4 verification hint.")
        return
    print_ok(
        "GA4 check: open browser DevTools on '/', filter network for 'collect' or 'gtag/js', "
        f"and confirm events are sent for {ga4_id}."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy helper for JobBoard Flask app")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Use defaults for missing env vars instead of prompting.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Auto-confirm Cloudflare real mode.",
    )
    parser.add_argument(
        "--skip-cloudflare",
        action="store_true",
        help="Skip Cloudflare dry-run/real-run steps.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gunicorn_process: Optional[subprocess.Popen] = None

    try:
        env_values = ensure_env_vars(non_interactive=args.non_interactive)
        install_dependencies()

        gunicorn_process = start_gunicorn(env_values)
        wait_for_server(gunicorn_process)
        verify_endpoints()

        run_cloudflare_automation(
            skip=args.skip_cloudflare,
            auto_yes=args.yes,
        )
        print_ga4_note(env_values)

        print("\nDeployment script completed successfully.")
        return 0
    except StepError as exc:
        print_fail(str(exc))
        return 1
    except KeyboardInterrupt:
        print_fail("Interrupted by user")
        return 130
    finally:
        if gunicorn_process:
            stop_process(gunicorn_process)


if __name__ == "__main__":
    raise SystemExit(main())
