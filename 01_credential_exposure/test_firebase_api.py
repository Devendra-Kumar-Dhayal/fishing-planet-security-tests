#!/usr/bin/env python3
"""
TEST 01b: Firebase API Key Exposure
====================================
Tests if the exposed Firebase API key allows unauthorized access
to Firebase services (Auth, Firestore, Realtime DB, Storage).

Severity: CRITICAL
"""
import json
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import FIREBASE_API_KEY, FIREBASE_CONFIG, FIREBASE_PROJECT_ID

RESULTS: list[dict] = []


def test_firebase_config_readable() -> bool:
    """Check what Firebase config data is exposed."""
    print("\n[TEST] Checking Firebase config exposure...")

    config = json.loads(FIREBASE_CONFIG.read_text())
    project_info = config.get("project_info", {})
    clients = config.get("client", [])

    print(f"  [EXPOSED] Project ID: {project_info.get('project_id')}")
    print(f"  [EXPOSED] Project Number: {project_info.get('project_number')}")
    print(f"  [EXPOSED] Storage Bucket: {project_info.get('storage_bucket')}")

    for client in clients:
        client_info = client.get("client_info", {})
        print(f"  [EXPOSED] App ID: {client_info.get('mobilesdk_app_id')}")
        print(f"  [EXPOSED] Package: {client_info.get('android_client_info', {}).get('package_name')}")

        for oauth in client.get("oauth_client", []):
            print(f"  [EXPOSED] OAuth Client: {oauth.get('client_id', '')[:40]}...")

        for key in client.get("api_key", []):
            print(f"  [EXPOSED] API Key: {key.get('current_key')}")

    RESULTS.append({"test": "firebase_config_exposure", "status": "VULNERABLE"})
    return True


def test_firebase_auth_signup() -> bool:
    """Test if Firebase Auth allows anonymous or email signup via exposed key."""
    print("\n[TEST] Testing Firebase Auth - anonymous sign-in...")

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
    data = {"returnSecureToken": True}

    try:
        resp = requests.post(url, json=data, timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            print(f"  [VULNERABLE] Anonymous auth succeeded!")
            print(f"  [VULNERABLE] Got ID token: {result.get('idToken', '')[:40]}...")
            print(f"  [VULNERABLE] Local ID: {result.get('localId', '')}")
            RESULTS.append({"test": "firebase_anon_auth", "status": "VULNERABLE"})
            return True
        else:
            error = resp.json().get("error", {})
            print(f"  [INFO] Auth returned {resp.status_code}: {error.get('message', '')}")
            RESULTS.append({
                "test": "firebase_anon_auth",
                "status": "BLOCKED",
                "error": error.get("message", ""),
            })
            return False
    except requests.RequestException as e:
        print(f"  [ERROR] {e}")
        RESULTS.append({"test": "firebase_anon_auth", "status": "ERROR"})
        return False


def test_firebase_rtdb_read() -> bool:
    """Test if Realtime Database allows unauthenticated reads."""
    print("\n[TEST] Testing Firebase Realtime Database read access...")

    url = f"https://{FIREBASE_PROJECT_ID}-default-rtdb.firebaseio.com/.json"

    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            print(f"  [VULNERABLE] RTDB read succeeded! Data type: {type(data).__name__}")
            if isinstance(data, dict):
                print(f"  [VULNERABLE] Top-level keys: {list(data.keys())[:10]}")
            RESULTS.append({"test": "firebase_rtdb_read", "status": "VULNERABLE"})
            return True
        elif resp.status_code == 401:
            print(f"  [OK] RTDB requires authentication (401)")
            RESULTS.append({"test": "firebase_rtdb_read", "status": "SECURE"})
            return False
        else:
            print(f"  [INFO] RTDB returned {resp.status_code}")
            RESULTS.append({"test": "firebase_rtdb_read", "status": "BLOCKED"})
            return False
    except requests.RequestException as e:
        print(f"  [ERROR] {e}")
        RESULTS.append({"test": "firebase_rtdb_read", "status": "ERROR"})
        return False


def test_firestore_read() -> bool:
    """Test if Firestore allows unauthenticated reads."""
    print("\n[TEST] Testing Firestore read access...")

    url = (
        f"https://firestore.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}"
        f"/databases/(default)/documents"
    )

    try:
        resp = requests.get(url, params={"key": FIREBASE_API_KEY}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            docs = data.get("documents", [])
            print(f"  [VULNERABLE] Firestore read succeeded! {len(docs)} documents found")
            RESULTS.append({"test": "firestore_read", "status": "VULNERABLE"})
            return True
        elif resp.status_code in (403, 401):
            print(f"  [OK] Firestore requires proper auth ({resp.status_code})")
            RESULTS.append({"test": "firestore_read", "status": "SECURE"})
            return False
        else:
            print(f"  [INFO] Firestore returned {resp.status_code}: {resp.text[:200]}")
            RESULTS.append({"test": "firestore_read", "status": "BLOCKED"})
            return False
    except requests.RequestException as e:
        print(f"  [ERROR] {e}")
        RESULTS.append({"test": "firestore_read", "status": "ERROR"})
        return False


def test_storage_bucket_read() -> bool:
    """Test if Cloud Storage bucket allows unauthenticated reads."""
    print("\n[TEST] Testing Cloud Storage bucket access...")

    bucket = f"{FIREBASE_PROJECT_ID}.appspot.com"
    url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"

    try:
        resp = requests.get(url, params={"key": FIREBASE_API_KEY}, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            print(f"  [VULNERABLE] Storage bucket listing succeeded! {len(items)} objects")
            for item in items[:5]:
                print(f"    - {item.get('name', 'unknown')}")
            RESULTS.append({"test": "storage_read", "status": "VULNERABLE"})
            return True
        elif resp.status_code in (403, 401):
            print(f"  [OK] Storage requires auth ({resp.status_code})")
            RESULTS.append({"test": "storage_read", "status": "SECURE"})
            return False
        else:
            print(f"  [INFO] Storage returned {resp.status_code}")
            RESULTS.append({"test": "storage_read", "status": "BLOCKED"})
            return False
    except requests.RequestException as e:
        print(f"  [ERROR] {e}")
        RESULTS.append({"test": "storage_read", "status": "ERROR"})
        return False


def main() -> None:
    print("=" * 60)
    print("TEST 01b: Firebase API Key Exposure")
    print("=" * 60)

    test_firebase_config_readable()
    test_firebase_auth_signup()
    test_firebase_rtdb_read()
    test_firestore_read()
    test_storage_bucket_read()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    vuln_count = sum(1 for r in RESULTS if r["status"] == "VULNERABLE")
    total = len(RESULTS)
    print(f"  Vulnerabilities found: {vuln_count}/{total} tests")

    if vuln_count > 0:
        print("  [FAIL] Firebase services are accessible with exposed credentials")
        print("  [FIX]  Restrict API key usage in Firebase Console")
        print("  [FIX]  Enable proper Firebase Security Rules")
        print("  [FIX]  Disable anonymous authentication if not needed")

    results_file = Path(__file__).parent / "results_firebase.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
