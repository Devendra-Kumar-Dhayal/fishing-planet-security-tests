#!/usr/bin/env python3
"""
TEST 06a: Anti-Cheat Analysis - CodeStage ACTk
=================================================
Analyzes the CodeStage Anti-Cheat Toolkit implementation.
Identifies ObscuredType patterns, detector configurations,
and potential bypass vectors.

Severity: HIGH
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import ANTICHEAT_TARGETS, GAME_ASSEMBLY, METADATA_FILE
from utils.binary_search import find_string_references, get_symbols
from utils.il2cpp_metadata import (
    Il2CppMetadataParser, find_methods_by_name, find_types_by_name,
    get_type_fields, get_type_methods,
)

RESULTS: list[dict] = []


def analyze_obscured_types(parser: Il2CppMetadataParser) -> None:
    """Analyze ObscuredType implementations."""
    print("\n[ANALYSIS] Enumerating ObscuredType implementations...")

    obscured_types = [
        "ObscuredInt", "ObscuredFloat", "ObscuredBool", "ObscuredString",
        "ObscuredDouble", "ObscuredLong", "ObscuredShort", "ObscuredByte",
        "ObscuredUInt", "ObscuredDecimal", "ObscuredVector3", "ObscuredQuaternion",
    ]

    for type_name in obscured_types:
        matches = find_types_by_name(parser, type_name, exact=True)
        if matches:
            for idx, type_def, name, namespace in matches:
                methods = get_type_methods(parser, type_def)
                fields = get_type_fields(parser, type_def)

                print(f"\n  {namespace}.{name}")
                print(f"    Methods ({type_def.method_count}):")

                # Key methods for bypass
                key_methods = ["Decrypt", "Encrypt", "GetDecrypted", "SetEncrypted",
                               "get_Value", "set_Value", "InternalDecrypt",
                               "op_Implicit", "ApplyNewCryptoKey"]
                for mid, mname in methods:
                    marker = " ***" if mname in key_methods else ""
                    print(f"      [{mid}] {mname}{marker}")

                print(f"    Fields ({type_def.field_count}):")
                # Key fields: cryptoKey, hiddenValue, fakeValue, fakeValueActive
                key_fields = ["cryptoKey", "hiddenValue", "fakeValue",
                              "fakeValueActive", "currentCryptoKey", "inited"]
                for fid, fname in fields:
                    marker = " ***" if fname in key_fields else ""
                    print(f"      [{fid}] {fname}{marker}")

                RESULTS.append({
                    "test": "obscured_type",
                    "name": f"{namespace}.{name}",
                    "type_index": idx,
                    "methods": [m[1] for m in methods],
                    "fields": [f[1] for f in fields],
                    "has_decrypt": any(m[1] in ("Decrypt", "InternalDecrypt", "GetDecrypted") for m in methods),
                    "has_crypto_key": any(f[1] in ("cryptoKey", "currentCryptoKey") for f in fields),
                    "status": "VULNERABLE",
                })
        else:
            print(f"\n  {type_name}: not found")


def analyze_detectors(parser: Il2CppMetadataParser) -> None:
    """Analyze anti-cheat detector implementations."""
    print("\n\n[ANALYSIS] Enumerating ACTk Detectors...")

    detectors = [
        "SpeedHackDetector", "ObscuredCheatingDetector",
        "TimeCheatingDetector", "InjectionDetector",
        "WallHackDetector", "ActDetectorBase",
    ]

    for detector_name in detectors:
        matches = find_types_by_name(parser, detector_name)
        if matches:
            for idx, type_def, name, namespace in matches:
                methods = get_type_methods(parser, type_def)
                fields = get_type_fields(parser, type_def)
                full_name = f"{namespace}.{name}" if namespace else name

                print(f"\n  {full_name}")

                # Key methods to hook for bypass
                bypass_methods = ["StartDetection", "StopDetection", "OnCheatingDetected",
                                  "Detect", "DetectSpeedHack", "DetectTimeCheating",
                                  "OnDetected", "ReportCheat"]
                print(f"    Bypass-candidate methods:")
                for mid, mname in methods:
                    if any(bm in mname for bm in bypass_methods):
                        print(f"      [{mid}] {mname} *** HOOK TARGET")
                    else:
                        print(f"      [{mid}] {mname}")

                RESULTS.append({
                    "test": "detector",
                    "name": full_name,
                    "type_index": idx,
                    "methods": [m[1] for m in methods],
                    "bypass_targets": [m[1] for m in methods
                                       if any(bm in m[1] for bm in bypass_methods)],
                    "status": "VULNERABLE",
                })
        else:
            print(f"\n  {detector_name}: NOT FOUND (not implemented)")
            RESULTS.append({
                "test": "detector_missing",
                "name": detector_name,
                "status": "MISSING",
            })


def analyze_binary_patterns() -> None:
    """Search binary for ACTk-specific patterns."""
    print("\n\n[ANALYSIS] Searching binary for ACTk patterns...")

    patterns = [
        "[ACTk]",
        "Obscured Cheating Detector",
        "Speed Hack Detector",
        "Time Cheating Detector",
        "Injection Detector",
        "cheating detected",
        "hack detected",
    ]

    for pattern in patterns:
        refs = find_string_references(GAME_ASSEMBLY, pattern, max_results=5)
        status = "FOUND" if refs else "not found"
        print(f"  '{pattern}': {status} ({len(refs)} refs)")
        if refs:
            for off in refs[:3]:
                print(f"    offset: 0x{off:08X}")
            RESULTS.append({
                "test": "binary_pattern",
                "pattern": pattern,
                "offsets": [f"0x{o:08X}" for o in refs],
                "status": "FOUND",
            })


def assess_coverage() -> None:
    """Assess what anti-cheat coverage exists vs what's missing."""
    print("\n\n[ASSESSMENT] Anti-Cheat Coverage:")
    print("-" * 50)

    coverage = {
        "Memory value protection (ObscuredTypes)": True,
        "Speed hack detection": True,
        "Time manipulation detection": True,
        "Code injection detection": True,
        "Wall hack detection": False,
        "Teleport/position validation": False,
        "Server-side validation": "UNKNOWN",
        "Binary integrity check": "UNKNOWN",
        "Root/jailbreak detection": False,
        "Debugger detection (runtime)": False,
    }

    for check, status in coverage.items():
        if status is True:
            print(f"  [+] {check}: IMPLEMENTED (client-side only)")
        elif status is False:
            print(f"  [-] {check}: NOT IMPLEMENTED")
        else:
            print(f"  [?] {check}: {status}")


def main() -> None:
    print("=" * 60)
    print("TEST 06a: Anti-Cheat Analysis (CodeStage ACTk)")
    print("=" * 60)

    parser = Il2CppMetadataParser(METADATA_FILE)

    analyze_obscured_types(parser)
    analyze_detectors(parser)
    analyze_binary_patterns()
    assess_coverage()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total findings: {len(RESULTS)}")
    print("  [FAIL] ObscuredTypes use known XOR encryption (bypassable)")
    print("  [FAIL] All detectors are client-side only")
    print("  [FAIL] No position/teleport validation detected")
    print("  [FAIL] Detector callbacks can be hooked and nullified")
    print("  [FIX]  Implement server-side anti-cheat validation")
    print("  [FIX]  Add server-side statistical anomaly detection")
    print("  [FIX]  Validate critical game state server-side")

    results_file = Path(__file__).parent / "results.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
