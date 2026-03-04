#!/usr/bin/env python3
"""
TEST 05: Network Traffic Interception
=======================================
mitmproxy addon that intercepts and logs Fishing Planet API traffic.
Tests for certificate pinning, unsigned requests, and modifiable responses.

Usage:
  1. Install: pip install mitmproxy
  2. Run proxy: mitmproxy -s mitm_setup.py -p 8080
  3. Configure game to use proxy (set HTTP_PROXY/HTTPS_PROXY env vars)
  4. Launch game and observe traffic

Severity: HIGH
"""
import json
import sys
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).parent
LOG_FILE = RESULTS_DIR / "traffic_log.json"

# Known game API domains
GAME_DOMAINS = [
    "fishingplanet",
    "epicgames.dev",
    "firebaseio.com",
    "googleapis.com",
    "photonengine.com",
    "playfab.com",
    "unity3d.com",
    "appspot.com",
    "sentry.io",
]

# Response fields to look for modification opportunities
ECONOMY_FIELDS = [
    "money", "cash", "gold", "silver", "currency", "balance",
    "experience", "xp", "level", "premium", "isPremium",
    "hasPremium", "coins", "credits", "reward",
]

traffic_log: list[dict] = []


def is_game_traffic(host: str) -> bool:
    """Check if the request is to a game-related domain."""
    return any(domain in host.lower() for domain in GAME_DOMAINS)


def check_economy_fields(data: dict, path: str = "") -> list[str]:
    """Recursively search response data for economy-related fields."""
    findings: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            if any(field in key.lower() for field in ECONOMY_FIELDS):
                findings.append(f"{current_path} = {value}")
            if isinstance(value, (dict, list)):
                findings.extend(check_economy_fields(value, current_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, (dict, list)):
                findings.extend(check_economy_fields(item, f"{path}[{i}]"))
    return findings


# mitmproxy addon class
try:
    from mitmproxy import http, ctx

    class FishingPlanetInterceptor:
        """mitmproxy addon for intercepting Fishing Planet traffic."""

        def request(self, flow: http.HTTPFlow) -> None:
            """Log and analyze outgoing requests."""
            if not is_game_traffic(flow.request.host):
                return

            entry = {
                "timestamp": datetime.now().isoformat(),
                "direction": "request",
                "method": flow.request.method,
                "url": flow.request.url,
                "host": flow.request.host,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "content_length": len(flow.request.content) if flow.request.content else 0,
            }

            # Check for authentication headers
            auth_header = flow.request.headers.get("Authorization", "")
            if auth_header:
                entry["auth_type"] = auth_header.split(" ")[0] if " " in auth_header else "unknown"
                entry["has_auth"] = True
            else:
                entry["has_auth"] = False
                ctx.log.warn(f"[!] UNAUTHENTICATED request to {flow.request.host}{flow.request.path}")

            # Try to parse request body
            if flow.request.content:
                try:
                    body = json.loads(flow.request.content)
                    economy_fields = check_economy_fields(body)
                    if economy_fields:
                        entry["economy_fields_in_request"] = economy_fields
                        ctx.log.alert(f"[!!] Economy data in REQUEST: {economy_fields}")
                except (json.JSONDecodeError, ValueError):
                    pass

            traffic_log.append(entry)
            ctx.log.info(f"[REQ] {flow.request.method} {flow.request.host}{flow.request.path}")

        def response(self, flow: http.HTTPFlow) -> None:
            """Log and analyze incoming responses. Flag modifiable economy data."""
            if not is_game_traffic(flow.request.host):
                return

            entry = {
                "timestamp": datetime.now().isoformat(),
                "direction": "response",
                "status": flow.response.status_code,
                "url": flow.request.url,
                "host": flow.request.host,
                "path": flow.request.path,
                "content_type": flow.response.headers.get("Content-Type", ""),
                "content_length": len(flow.response.content) if flow.response.content else 0,
            }

            # Check for signed/integrity-verified responses
            integrity_headers = ["x-signature", "x-hmac", "x-digest", "x-integrity"]
            has_integrity = any(
                h in flow.response.headers for h in integrity_headers
            )
            entry["has_integrity_check"] = has_integrity
            if not has_integrity:
                ctx.log.warn(f"[!] Response has NO integrity verification: {flow.request.path}")

            # Parse response body for economy data
            if flow.response.content:
                try:
                    body = json.loads(flow.response.content)
                    economy_fields = check_economy_fields(body)
                    if economy_fields:
                        entry["economy_fields_in_response"] = economy_fields
                        entry["modifiable"] = not has_integrity
                        ctx.log.alert(f"[!!] Economy data in RESPONSE: {economy_fields}")
                        if not has_integrity:
                            ctx.log.alert(f"[!!!] MODIFIABLE economy response: {flow.request.path}")
                except (json.JSONDecodeError, ValueError):
                    pass

            traffic_log.append(entry)
            ctx.log.info(
                f"[RSP] {flow.response.status_code} {flow.request.host}{flow.request.path} "
                f"({entry['content_length']} bytes)"
            )

        def done(self) -> None:
            """Save traffic log on shutdown."""
            LOG_FILE.write_text(json.dumps(traffic_log, indent=2))
            ctx.log.info(f"[*] Traffic log saved to {LOG_FILE} ({len(traffic_log)} entries)")

    addons = [FishingPlanetInterceptor()]

except ImportError:
    pass


def main() -> None:
    """Standalone mode - print setup instructions and analyze existing logs."""
    print("=" * 60)
    print("TEST 05: Network Traffic Interception")
    print("=" * 60)

    print("\n[*] Setup Instructions:")
    print("  1. Install mitmproxy: pip install mitmproxy")
    print("  2. Start proxy:")
    print("     mitmproxy -s mitm_setup.py -p 8080")
    print("  3. Launch game with proxy:")
    print("     HTTP_PROXY=http://127.0.0.1:8080 \\")
    print("     HTTPS_PROXY=http://127.0.0.1:8080 \\")
    print('     "$GAME_DIR/FishingPlanet.X86_64"')
    print("\n  The script will automatically log all game API traffic")
    print("  and flag modifiable economy data in responses.")

    print("\n[*] What this test checks:")
    print("  - Certificate pinning (will proxy connection fail?)")
    print("  - Unauthenticated API requests")
    print("  - Economy data in request/response bodies")
    print("  - Response integrity verification (signatures/HMAC)")
    print("  - Modifiable currency/XP/premium values in responses")

    print("\n[*] Known game API domains monitored:")
    for domain in GAME_DOMAINS:
        print(f"    - *{domain}*")

    # Check if previous log exists
    if LOG_FILE.exists():
        log_data = json.loads(LOG_FILE.read_text())
        print(f"\n[*] Previous traffic log found: {len(log_data)} entries")
        economy_entries = [e for e in log_data if "economy_fields_in_response" in e]
        if economy_entries:
            print(f"  [VULNERABLE] {len(economy_entries)} responses contain economy data")
            for entry in economy_entries[:5]:
                print(f"    {entry['path']}: {entry['economy_fields_in_response']}")


if __name__ == "__main__":
    main()
