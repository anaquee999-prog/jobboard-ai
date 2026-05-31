import sys
import os

import requests

API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN", "")
ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID", "")
WWW_IP = os.getenv("CLOUDFLARE_WWW_IP", "")
DNS_NAME = os.getenv("CLOUDFLARE_DNS_NAME", "www")
BASE_URL = "https://api.cloudflare.com/client/v4"


def configure_output() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def load_config() -> dict:
    return {
        "api_token": API_TOKEN.strip(),
        "zone_id": ZONE_ID.strip(),
        "www_ip": WWW_IP.strip(),
        "dns_name": DNS_NAME,
    }


def validate_config(config: dict) -> list[str]:
    missing = []
    if not config["api_token"]:
        missing.append("CLOUDFLARE_API_TOKEN")
    if not config["zone_id"]:
        missing.append("CLOUDFLARE_ZONE_ID")
    if not config["www_ip"]:
        missing.append("CLOUDFLARE_WWW_IP")
    return missing


def log_response(step_name, response):
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
            print("Errors:", data["errors"])
    else:
        print(f"SUCCESS: {step_name}")

    return data


def cloudflare_request(config, step_name, method, path, payload=None):
    url = f"{BASE_URL}{path}"
    headers = {
        "Authorization": f"Bearer {config['api_token']}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            json=payload,
            timeout=30,
        )
        return log_response(step_name, response)
    except requests.RequestException as exc:
        print(f"\n===== {step_name} =====")
        print(f"ERROR: Request failed: {exc}")
        return None


def print_plan(config):
    print("Cloudflare setup dry run. No API changes will be made.")
    print(f"Zone ID configured: {'yes' if config['zone_id'] else 'no'}")
    print(f"DNS record: {config['dns_name']} A -> {config['www_ip'] or '(missing)'}")
    print("Planned changes:")
    print("- Create or update proxied A record")
    print("- Set SSL/TLS mode to full")
    print("- Create and deploy custom firewall ruleset")
    print("- Purge entire cache")
    print("Run with --apply after setting CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID, and CLOUDFLARE_WWW_IP.")


def find_dns_record(config):
    path = (
        f"/zones/{config['zone_id']}/dns_records"
        f"?type=A&name={config['dns_name']}"
    )
    data = cloudflare_request(config, "Find DNS A Record", "GET", path)
    if data and data.get("success") and data.get("result"):
        return data["result"][0]
    return None


def upsert_dns_record(config):
    payload = {
        "type": "A",
        "name": config["dns_name"],
        "content": config["www_ip"],
        "ttl": 3600,
        "proxied": True,
    }
    existing = find_dns_record(config)
    if existing and existing.get("id"):
        return cloudflare_request(
            config,
            "Update DNS A Record",
            "PUT",
            f"/zones/{config['zone_id']}/dns_records/{existing['id']}",
            payload,
        )

    return cloudflare_request(
        config,
        "Add DNS A Record",
        "POST",
        f"/zones/{config['zone_id']}/dns_records",
        payload,
    )


def enable_ssl_full_mode(config):
    return cloudflare_request(
        config,
        "Enable SSL/TLS Full Mode",
        "PATCH",
        f"/zones/{config['zone_id']}/settings/ssl",
        {"value": "full"},
    )


def create_firewall_ruleset(config):
    payload = {
        "name": "Block Bad Bots Ruleset",
        "kind": "custom",
        "description": "Custom firewall ruleset created via Cloudflare Rulesets API",
        "phase": "http_request_firewall_custom",
        "rules": [
            {
                "action": "block",
                "expression": '(http.user_agent contains "BadBot")',
                "description": "Block user agents containing BadBot",
                "enabled": True,
            }
        ],
    }

    data = cloudflare_request(
        config,
        "Create Firewall Custom Ruleset",
        "POST",
        f"/zones/{config['zone_id']}/rulesets",
        payload,
    )
    if data and data.get("success") and data.get("result", {}).get("id"):
        return data["result"]["id"]
    return None


def deploy_firewall_ruleset(config, ruleset_id):
    payload = {
        "action": "execute",
        "expression": "true",
        "description": "Deploy Block Bad Bots Ruleset",
        "enabled": True,
        "action_parameters": {"id": ruleset_id},
    }

    return cloudflare_request(
        config,
        "Deploy Firewall Ruleset",
        "POST",
        f"/zones/{config['zone_id']}/rulesets/phases/http_request_firewall_custom/entrypoint/rules",
        payload,
    )


def purge_cache(config):
    return cloudflare_request(
        config,
        "Purge Entire Cache",
        "POST",
        f"/zones/{config['zone_id']}/purge_cache",
        {"purge_everything": True},
    )


def main() -> int:
    configure_output()
    config = load_config()
    missing = validate_config(config)
    if missing:
        print("Missing required configuration: " + ", ".join(missing), file=sys.stderr)
        return 1

    print("Starting Cloudflare automation...")
    upsert_dns_record(config)
    enable_ssl_full_mode(config)

    ruleset_id = create_firewall_ruleset(config)
    if ruleset_id:
        deploy_firewall_ruleset(config, ruleset_id)
    else:
        print("\n===== Deploy Firewall Ruleset =====")
        print("ERROR: Skipped because ruleset creation failed")

    purge_cache(config)
    print("\nCloudflare automation completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
