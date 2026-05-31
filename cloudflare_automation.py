import json
import os
import sys
from typing import Any

import requests


BASE_URL = "https://api.cloudflare.com/client/v4"


def configure_output() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def is_dry_run() -> bool:
    return os.getenv("DRY_RUN", "1").strip().lower() not in {"0", "false", "no", "off"}


def load_config() -> dict[str, str]:
    return {
        "api_token": os.getenv("CLOUDFLARE_API_TOKEN", "").strip(),
        "zone_id": os.getenv("CLOUDFLARE_ZONE_ID", "").strip(),
        "www_ip": os.getenv("CLOUDFLARE_WWW_IP", "").strip(),
        "dns_name": os.getenv("CLOUDFLARE_DNS_NAME", "www").strip(),
    }


def validate_config(config: dict[str, str]) -> list[str]:
    missing = []
    if not config["api_token"]:
        missing.append("CLOUDFLARE_API_TOKEN")
    if not config["zone_id"]:
        missing.append("CLOUDFLARE_ZONE_ID")
    if not config["www_ip"]:
        missing.append("CLOUDFLARE_WWW_IP")
    if not config["dns_name"]:
        missing.append("CLOUDFLARE_DNS_NAME")
    return missing


def print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def print_plan(config: dict[str, str]) -> None:
    print("Cloudflare automation dry-run. No API changes will be made.")
    print(f"Zone ID configured: {'yes' if config['zone_id'] else 'no'}")
    print(f"DNS record: {config['dns_name']} A -> {config['www_ip']}")
    print("Planned changes:")
    print("1. Create or update proxied DNS A record")
    print("2. Set SSL/TLS encryption mode to full")
    print("3. Create or update a custom firewall ruleset")
    print("4. Purge Cloudflare cache")


def log_response(step_name: str, response: requests.Response) -> dict[str, Any] | None:
    print(f"\n===== {step_name} =====")
    print(f"HTTP Status: {response.status_code}")

    try:
        data = response.json()
    except ValueError:
        print("ERROR: Response is not valid JSON")
        print(response.text[:1000])
        return None

    if not response.ok or not data.get("success", False):
        print(f"ERROR: {step_name} failed")
        if data.get("errors"):
            print("Errors:")
            print_json(data["errors"])
    else:
        print(f"SUCCESS: {step_name}")

    return data


def cloudflare_request(
    config: dict[str, str],
    step_name: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    url = f"{BASE_URL}{path}"
    headers = {
        "Authorization": f"Bearer {config['api_token']}",
        "Content-Type": "application/json",
    }

    if payload is not None:
        print(f"\nPayload for {step_name}:")
        print_json(payload)

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            json=payload,
            timeout=30,
        )
    except requests.RequestException as exc:
        print(f"\n===== {step_name} =====")
        print(f"ERROR: Request failed: {exc}")
        return None

    return log_response(step_name, response)


def find_dns_record(config: dict[str, str]) -> dict[str, Any] | None:
    path = (
        f"/zones/{config['zone_id']}/dns_records"
        f"?type=A&name={config['dns_name']}"
    )
    data = cloudflare_request(config, "Find DNS A Record", "GET", path)
    if data and data.get("success") and data.get("result"):
        return data["result"][0]
    return None


def upsert_dns_record(config: dict[str, str]) -> None:
    payload = {
        "type": "A",
        "name": config["dns_name"],
        "content": config["www_ip"],
        "ttl": 1,
        "proxied": True,
    }
    existing = find_dns_record(config)
    if existing and existing.get("id"):
        cloudflare_request(
            config,
            "Update DNS A Record",
            "PUT",
            f"/zones/{config['zone_id']}/dns_records/{existing['id']}",
            payload,
        )
        return

    cloudflare_request(
        config,
        "Create DNS A Record",
        "POST",
        f"/zones/{config['zone_id']}/dns_records",
        payload,
    )


def enable_ssl_full_mode(config: dict[str, str]) -> None:
    cloudflare_request(
        config,
        "Enable SSL/TLS Full Mode",
        "PATCH",
        f"/zones/{config['zone_id']}/settings/ssl",
        {"value": "full"},
    )


def list_firewall_rulesets(config: dict[str, str]) -> list[dict[str, Any]]:
    data = cloudflare_request(
        config,
        "List Firewall Rulesets",
        "GET",
        f"/zones/{config['zone_id']}/rulesets",
    )
    if data and data.get("success") and isinstance(data.get("result"), list):
        return data["result"]
    return []


def create_or_update_firewall_ruleset(config: dict[str, str]) -> str | None:
    ruleset_name = "JobBoard AI Anti-Scam Firewall"
    rules = [
        {
            "action": "block",
            "expression": '(http.user_agent contains "BadBot")',
            "description": "Block obvious bad bot user agents",
            "enabled": True,
        },
        {
            "action": "managed_challenge",
            "expression": "(cf.threat_score gt 30)",
            "description": "Challenge high-threat requests",
            "enabled": True,
        },
    ]
    payload = {
        "name": ruleset_name,
        "kind": "zone",
        "description": "Created by cloudflare_automation.py",
        "phase": "http_request_firewall_custom",
        "rules": rules,
    }

    for ruleset in list_firewall_rulesets(config):
        if ruleset.get("name") == ruleset_name and ruleset.get("id"):
            data = cloudflare_request(
                config,
                "Update Firewall Ruleset",
                "PUT",
                f"/zones/{config['zone_id']}/rulesets/{ruleset['id']}",
                payload,
            )
            if data and data.get("success"):
                return ruleset["id"]
            return None

    data = cloudflare_request(
        config,
        "Create Firewall Ruleset",
        "POST",
        f"/zones/{config['zone_id']}/rulesets",
        payload,
    )
    if data and data.get("success"):
        return data.get("result", {}).get("id")
    return None


def purge_cache(config: dict[str, str]) -> None:
    cloudflare_request(
        config,
        "Purge Entire Cache",
        "POST",
        f"/zones/{config['zone_id']}/purge_cache",
        {"purge_everything": True},
    )


def run_real_mode(config: dict[str, str]) -> None:
    print("Starting Cloudflare automation in real mode.")
    upsert_dns_record(config)
    enable_ssl_full_mode(config)
    ruleset_id = create_or_update_firewall_ruleset(config)
    if ruleset_id:
        print(f"Firewall ruleset ready: {ruleset_id}")
    else:
        print("WARNING: Firewall ruleset was not created or updated.")
    purge_cache(config)
    print("\nCloudflare automation completed.")


def main() -> int:
    configure_output()
    config = load_config()
    missing = validate_config(config)
    if missing:
        print("Missing required configuration: " + ", ".join(missing), file=sys.stderr)
        return 1

    if is_dry_run():
        print_plan(config)
        return 0

    run_real_mode(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
