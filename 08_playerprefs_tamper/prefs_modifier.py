#!/usr/bin/env python3
"""
TEST 08: PlayerPrefs Tamper Test
==================================
Tests modification of Unity PlayerPrefs XML file.
Checks for debug flags, version spoofing, and other tamperable values.

Severity: MEDIUM
"""
import base64
import json
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import PLAYER_PREFS

RESULTS: list[dict] = []
BACKUP_DIR = Path(__file__).parent / "backups"


def backup_prefs() -> Path:
    """Create a backup of the current prefs file."""
    BACKUP_DIR.mkdir(exist_ok=True)
    backup_path = BACKUP_DIR / "prefs.backup"
    if PLAYER_PREFS.exists():
        shutil.copy2(PLAYER_PREFS, backup_path)
        print(f"  [*] Backup created: {backup_path}")
    return backup_path


def restore_prefs() -> None:
    """Restore prefs from backup."""
    backup_path = BACKUP_DIR / "prefs.backup"
    if backup_path.exists():
        shutil.copy2(backup_path, PLAYER_PREFS)
        print(f"  [*] Prefs restored from backup")


def analyze_current_prefs() -> dict[str, dict]:
    """Parse and analyze all current PlayerPrefs values."""
    print("\n[TEST] Analyzing current PlayerPrefs...")

    if not PLAYER_PREFS.exists():
        print("  [ERROR] Prefs file not found!")
        return {}

    tree = ET.parse(PLAYER_PREFS)
    root = tree.getroot()

    prefs: dict[str, dict] = {}
    for pref in root.findall("pref"):
        name = pref.get("name", "")
        ptype = pref.get("type", "")
        value = pref.text or ""
        prefs[name] = {"type": ptype, "value": value}

    print(f"  Total prefs: {len(prefs)}")

    # Decode base64 string values
    print("\n  Base64-encoded values:")
    for name, info in prefs.items():
        if info["type"] == "string" and info["value"]:
            try:
                decoded = base64.b64decode(info["value"]).decode("utf-8", errors="replace")
                print(f"    {name} = {decoded}")
                prefs[name]["decoded"] = decoded
            except Exception:
                pass

    return prefs


def test_debug_flag(prefs: dict) -> None:
    """Test if DebugInfo flag can enable debug features."""
    print("\n[TEST] Analyzing DebugInfo flag...")

    debug_info = prefs.get("DebugInfo", {})
    current_value = debug_info.get("value", "N/A")
    print(f"  Current DebugInfo value: {current_value}")

    if current_value == "0":
        print("  [VULNERABLE] DebugInfo is 0 (disabled) - can be set to 1")
        print("  [INFO] Setting to 1 may enable debug overlay/console in-game")
        RESULTS.append({
            "test": "debug_flag",
            "current": 0,
            "tamper_value": 1,
            "status": "VULNERABLE",
        })
    elif current_value == "1":
        print("  [INFO] DebugInfo already enabled")
        RESULTS.append({
            "test": "debug_flag",
            "current": 1,
            "status": "ALREADY_ENABLED",
        })


def test_version_spoofing(prefs: dict) -> None:
    """Test if version string can be modified."""
    print("\n[TEST] Analyzing Version string...")

    version = prefs.get("Version", {})
    decoded = version.get("decoded", "unknown")
    print(f"  Current version: {decoded}")

    # Test encoding a fake version
    fake_version = "99.0.0 (revision 99999)"
    fake_encoded = base64.b64encode(fake_version.encode()).decode()
    print(f"  Fake version would be: {fake_version}")
    print(f"  Fake encoded: {fake_encoded}")
    print("  [INFO] Version mismatch may trigger different server behavior")

    RESULTS.append({
        "test": "version_spoof",
        "current": decoded,
        "fake": fake_version,
        "status": "TAMPERABLE",
    })


def test_session_id_manipulation(prefs: dict) -> None:
    """Check if session/user IDs can be manipulated."""
    print("\n[TEST] Analyzing session identifiers...")

    id_fields = [
        "unity.cloud_userid", "unity.player_sessionid",
        "unity.player_session_count", "unity_connect.session_id",
        "unity_connect.installation_id", "unity_connect.mega_session_id",
    ]

    for field in id_fields:
        if field in prefs:
            info = prefs[field]
            decoded = info.get("decoded", info.get("value", "N/A"))
            print(f"  [EXPOSED] {field} = {decoded}")
            RESULTS.append({
                "test": "session_id",
                "field": field,
                "value": str(decoded)[:50],
                "status": "EXPOSED",
            })


def test_graphics_exploit(prefs: dict) -> None:
    """Check for graphical settings that could provide unfair advantages."""
    print("\n[TEST] Analyzing graphics settings for exploit potential...")

    exploit_settings = {
        "RenderQuality": "Lower quality = less visual clutter = easier to spot fish",
        "OceanWaterValue": "Lower water quality = see through water more easily",
        "DynWaterValue": "Dynamic water = affects fish visibility",
        "IsPostFx": "Post-processing = affects visibility",
        "SSAO": "Ambient occlusion = affects underwater visibility",
        "AntialiasingValue": "AA settings = edge visibility",
    }

    for setting, desc in exploit_settings.items():
        if setting in prefs:
            value = prefs[setting]["value"]
            print(f"  {setting} = {value} ({desc})")
            RESULTS.append({
                "test": "graphics_exploit",
                "setting": setting,
                "value": value,
                "description": desc,
                "status": "TAMPERABLE",
            })


def list_all_tamperable_prefs(prefs: dict) -> None:
    """List all prefs that could be tampered with."""
    print("\n[TEST] Complete list of tamperable preferences:")
    print("-" * 60)

    for name, info in sorted(prefs.items()):
        decoded = info.get("decoded", "")
        value_display = decoded if decoded else info["value"]
        if len(str(value_display)) > 60:
            value_display = str(value_display)[:60] + "..."
        print(f"  [{info['type']:6s}] {name:45s} = {value_display}")


def generate_tampered_prefs(prefs: dict) -> None:
    """Generate a tampered prefs file for testing (does NOT overwrite original)."""
    print("\n[*] Generating tampered prefs file (for manual testing)...")

    tamper_file = Path(__file__).parent / "tampered_prefs.xml"

    tree = ET.parse(PLAYER_PREFS)
    root = tree.getroot()

    modifications = {
        "DebugInfo": ("int", "1"),
    }

    for pref in root.findall("pref"):
        name = pref.get("name", "")
        if name in modifications:
            new_type, new_value = modifications[name]
            pref.set("type", new_type)
            pref.text = new_value
            print(f"  Modified: {name} -> {new_value}")

    tree.write(tamper_file, xml_declaration=False)
    print(f"\n  Tampered file saved to: {tamper_file}")
    print("  To test: stop game, replace prefs file, restart game")
    print("  To restore: use the backup in ./backups/prefs.backup")


def main() -> None:
    print("=" * 60)
    print("TEST 08: PlayerPrefs Tamper Test")
    print("=" * 60)

    backup_prefs()
    prefs = analyze_current_prefs()

    if not prefs:
        print("\n  [ERROR] Could not parse prefs. Exiting.")
        return

    test_debug_flag(prefs)
    test_version_spoofing(prefs)
    test_session_id_manipulation(prefs)
    test_graphics_exploit(prefs)
    list_all_tamperable_prefs(prefs)
    generate_tampered_prefs(prefs)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    vuln_count = sum(1 for r in RESULTS if r["status"] in ("VULNERABLE", "TAMPERABLE", "EXPOSED"))
    print(f"  Tamperable items: {vuln_count}")
    print("  [FAIL] PlayerPrefs stored as plaintext XML")
    print("  [FAIL] Debug flag, version, and session IDs are modifiable")
    print("  [FIX]  Use ObscuredPrefs (ACTk) for sensitive values")
    print("  [FIX]  Validate critical prefs server-side on login")
    print("  [FIX]  Hash/sign the prefs file to detect tampering")

    results_file = Path(__file__).parent / "results.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
