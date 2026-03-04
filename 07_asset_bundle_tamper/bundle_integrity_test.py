#!/usr/bin/env python3
"""
TEST 07: Asset Bundle Tamper Test
===================================
Tests whether Unity Addressable asset bundles have integrity verification.
Attempts to modify a bundle and checks if the game rejects it.

Severity: MEDIUM
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import ADDRESSABLES_DIR, STREAMING_ASSETS

RESULTS: list[dict] = []
BACKUP_DIR = Path(__file__).parent / "backups"


def analyze_catalog_hash() -> None:
    """Analyze the catalog hash file for integrity mechanism."""
    print("\n[TEST] Analyzing catalog hash...")

    hash_file = STREAMING_ASSETS / "aa" / "catalog.hash"
    if not hash_file.exists():
        print("  [INFO] No catalog.hash file found")
        return

    hash_content = hash_file.read_text().strip()
    print(f"  Catalog hash: {hash_content}")
    print(f"  Hash length: {len(hash_content)} chars")

    # Determine hash type by length
    hash_type = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}.get(len(hash_content), "UNKNOWN")
    print(f"  Probable hash type: {hash_type}")

    RESULTS.append({
        "test": "catalog_hash",
        "hash": hash_content,
        "type": hash_type,
        "status": "FOUND",
    })


def analyze_bundle_structure() -> None:
    """Analyze the structure of asset bundles."""
    print("\n[TEST] Analyzing bundle file structure...")

    bundles = list(ADDRESSABLES_DIR.glob("*.bundle"))
    print(f"  Total bundles: {len(bundles)}")

    if not bundles:
        print("  [ERROR] No bundles found!")
        return

    # Analyze a few bundles
    sizes = [b.stat().st_size for b in bundles]
    print(f"  Size range: {min(sizes)} - {max(sizes)} bytes")
    print(f"  Total size: {sum(sizes) / (1024**3):.2f} GB")

    # Check magic bytes of first few bundles
    print("\n  Bundle format analysis:")
    for bundle in bundles[:3]:
        with open(bundle, "rb") as f:
            magic = f.read(16)

        # Unity asset bundle magic: "UnityFS" or "UnityWeb" or "UnityRaw"
        magic_str = magic[:8].decode("ascii", errors="replace")
        is_unity_bundle = magic_str.startswith("UnityFS") or magic_str.startswith("UnityWeb")

        print(f"    {bundle.name[:40]}... magic={magic_str!r} unity={is_unity_bundle}")
        RESULTS.append({
            "test": "bundle_format",
            "name": bundle.name,
            "magic": magic_str,
            "is_unity": is_unity_bundle,
            "size": bundle.stat().st_size,
        })


def test_bundle_modification() -> None:
    """Test if modifying a bundle is detected by computing hash changes."""
    print("\n[TEST] Testing bundle modification detection (non-destructive)...")

    bundles = sorted(ADDRESSABLES_DIR.glob("*.bundle"), key=lambda b: b.stat().st_size)
    if not bundles:
        print("  [ERROR] No bundles found!")
        return

    # Pick the smallest bundle for testing
    target = bundles[0]
    target_size = target.stat().st_size
    print(f"  Target bundle: {target.name} ({target_size} bytes)")

    # Create backup
    BACKUP_DIR.mkdir(exist_ok=True)
    backup_path = BACKUP_DIR / target.name
    if not backup_path.exists():
        shutil.copy2(target, backup_path)
        print(f"  Backup created: {backup_path}")

    # Calculate original hashes
    original_data = target.read_bytes()
    original_md5 = hashlib.md5(original_data).hexdigest()
    original_sha256 = hashlib.sha256(original_data).hexdigest()

    print(f"  Original MD5:    {original_md5}")
    print(f"  Original SHA256: {original_sha256}")

    RESULTS.append({
        "test": "bundle_modification",
        "bundle": target.name,
        "original_md5": original_md5,
        "original_sha256": original_sha256,
        "original_size": target_size,
    })

    # Check if catalog.bin references this bundle with a hash
    catalog_bin = STREAMING_ASSETS / "aa" / "catalog.bin"
    if catalog_bin.exists():
        catalog_data = catalog_bin.read_bytes()
        # Search for the bundle name in catalog
        bundle_name_bytes = target.name.encode("utf-8")
        if bundle_name_bytes in catalog_data:
            offset = catalog_data.index(bundle_name_bytes)
            # Check surrounding data for hash references
            context = catalog_data[max(0, offset - 100):offset + len(bundle_name_bytes) + 200]
            # Look for hash-like patterns (32 or 64 hex chars)
            import re
            hashes_found = re.findall(rb'[0-9a-f]{32,64}', context)
            if hashes_found:
                print(f"\n  [INFO] Found {len(hashes_found)} hash-like values near bundle reference in catalog:")
                for h in hashes_found[:5]:
                    print(f"    {h.decode()}")
                RESULTS.append({
                    "test": "catalog_bundle_hash",
                    "bundle": target.name,
                    "hashes_in_catalog": [h.decode() for h in hashes_found[:5]],
                    "status": "HASHES_FOUND",
                })
            else:
                print(f"\n  [VULNERABLE] No hash verification found for bundle in catalog!")
                RESULTS.append({
                    "test": "catalog_bundle_hash",
                    "bundle": target.name,
                    "status": "NO_HASH",
                })
        else:
            print(f"\n  [INFO] Bundle name not found in catalog.bin (may use hashed paths)")

    print("\n  NOTE: Actual runtime tamper test requires launching the game.")
    print("  To test: modify a bundle byte, launch game, check Player.log for errors.")


def check_crc_verification() -> None:
    """Check if the Addressables system uses CRC verification."""
    print("\n[TEST] Checking for CRC/hash verification in Addressables config...")

    settings_file = STREAMING_ASSETS / "aa" / "settings.json"
    if settings_file.exists():
        settings = json.loads(settings_file.read_text())
        print(f"  Addressables version: {settings.get('m_AddressablesVersion', 'unknown')}")

        # Check for CRC-related settings
        has_crc = "crc" in json.dumps(settings).lower()
        print(f"  CRC settings found: {has_crc}")

        RESULTS.append({
            "test": "crc_check",
            "has_crc_settings": has_crc,
            "addressables_version": settings.get("m_AddressablesVersion"),
            "status": "VULNERABLE" if not has_crc else "HAS_CRC",
        })


def main() -> None:
    print("=" * 60)
    print("TEST 07: Asset Bundle Tamper Test")
    print("=" * 60)

    analyze_catalog_hash()
    analyze_bundle_structure()
    test_bundle_modification()
    check_crc_verification()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total findings: {len(RESULTS)}")
    print("  [INFO] Full runtime test requires launching the game")
    print("  [FIX]  Enable CRC checking for all asset bundles")
    print("  [FIX]  Implement server-side validation for critical game data")
    print("  [FIX]  Sign bundles and verify signatures at load time")

    results_file = Path(__file__).parent / "results.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
