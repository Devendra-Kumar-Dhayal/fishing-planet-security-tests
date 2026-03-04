#!/usr/bin/env python3
"""
TEST 02a: Premium Bypass - Static Analysis
============================================
Finds HasPremium/IsPremium field and method offsets in IL2CPP metadata
and maps them to potential memory addresses in GameAssembly.so.

Severity: CRITICAL
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import GAME_ASSEMBLY, METADATA_FILE, PREMIUM_TARGETS
from utils.il2cpp_metadata import (
    Il2CppMetadataParser, find_methods_by_name, find_types_by_name,
    get_type_fields, get_type_methods,
)
from utils.binary_search import find_string_references, get_symbols

RESULTS: list[dict] = []


def analyze_premium_types(parser: Il2CppMetadataParser) -> None:
    """Find all types related to premium functionality."""
    print("\n[ANALYSIS] Searching for premium-related types...")

    premium_types = find_types_by_name(parser, "premium")
    print(f"  Found {len(premium_types)} types containing 'premium':\n")

    for idx, type_def, name, namespace in premium_types:
        full_name = f"{namespace}.{name}" if namespace else name
        print(f"  [{idx:5d}] {full_name}")
        print(f"          methods: {type_def.method_count}, fields: {type_def.field_count}")

        methods = get_type_methods(parser, type_def)
        for mid, mname in methods:
            print(f"          -> method [{mid}]: {mname}")

        fields = get_type_fields(parser, type_def)
        for fid, fname in fields:
            if "premium" in fname.lower() or "free" in fname.lower():
                print(f"          -> field  [{fid}]: {fname} ***")
            else:
                print(f"          -> field  [{fid}]: {fname}")

        RESULTS.append({
            "test": "premium_type",
            "type_index": idx,
            "name": full_name,
            "method_count": type_def.method_count,
            "field_count": type_def.field_count,
            "methods": [m[1] for m in methods],
            "fields": [f[1] for f in fields],
        })
        print()


def analyze_premium_methods(parser: Il2CppMetadataParser) -> None:
    """Find specific premium-related methods."""
    print("\n[ANALYSIS] Searching for premium getter/setter methods...")

    for target in PREMIUM_TARGETS:
        matches = find_methods_by_name(parser, target)
        if matches:
            print(f"\n  '{target}' - {len(matches)} matches:")
            for idx, method_def, name in matches:
                types = parser.get_type_definitions()
                parent_type = ""
                if method_def.declaring_type < len(types):
                    t = types[method_def.declaring_type]
                    ns = parser.get_string(t.namespace_index)
                    tn = parser.get_string(t.name_index)
                    parent_type = f"{ns}.{tn}" if ns else tn

                print(f"    [{idx:6d}] {parent_type}::{name}()")
                print(f"             token=0x{method_def.token:08X}, params={method_def.parameter_count}")

                RESULTS.append({
                    "test": "premium_method",
                    "method_index": idx,
                    "name": name,
                    "parent_type": parent_type,
                    "token": f"0x{method_def.token:08X}",
                    "parameter_count": method_def.parameter_count,
                })
        else:
            print(f"\n  '{target}' - not found in methods")


def analyze_premium_backing_fields(parser: Il2CppMetadataParser) -> None:
    """Find backing fields for premium auto-properties."""
    print("\n[ANALYSIS] Searching for premium backing fields...")

    fields = parser.get_field_definitions()
    types = parser.get_type_definitions()

    premium_fields: list[tuple[int, str, str]] = []
    for i, field in enumerate(fields):
        try:
            name = parser.get_string(field.name_index)
            if "premium" in name.lower() or "HasPremium" in name or "IsPremium" in name:
                premium_fields.append((i, name, f"token=0x{field.token:08X}"))
        except (IndexError, UnicodeDecodeError):
            continue

    print(f"  Found {len(premium_fields)} premium-related fields:\n")
    for idx, name, token_str in premium_fields:
        print(f"    [{idx:6d}] {name} ({token_str})")
        RESULTS.append({
            "test": "premium_backing_field",
            "field_index": idx,
            "name": name,
            "info": token_str,
        })


def analyze_binary_references() -> None:
    """Search for premium-related strings directly in the binary."""
    print("\n[ANALYSIS] Searching GameAssembly.so for premium string references...")

    for target in ["HasPremium", "IsPremium", "FreeForPremium", "PremiumAccount"]:
        offsets = find_string_references(GAME_ASSEMBLY, target, max_results=10)
        if offsets:
            print(f"\n  '{target}' found at {len(offsets)} locations:")
            for off in offsets[:5]:
                print(f"    offset 0x{off:08X}")
            RESULTS.append({
                "test": "binary_string_ref",
                "target": target,
                "offsets": [f"0x{o:08X}" for o in offsets[:10]],
                "status": "VULNERABLE",
            })
        else:
            print(f"\n  '{target}' - not found in binary")


def main() -> None:
    print("=" * 60)
    print("TEST 02a: Premium Bypass - Static Analysis")
    print("=" * 60)

    print(f"\n[*] Loading metadata from: {METADATA_FILE}")
    parser = Il2CppMetadataParser(METADATA_FILE)
    summary = parser.dump_summary()
    print(f"  Metadata version: {summary['version']}")
    print(f"  String literals: {summary['string_literals_count']}")
    print(f"  TypeDef struct size: {summary['typedef_struct_size']}")
    print(f"  Method struct size: {summary['method_struct_size']}")

    analyze_premium_types(parser)
    analyze_premium_methods(parser)
    analyze_premium_backing_fields(parser)
    analyze_binary_references()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total findings: {len(RESULTS)}")
    print("  [FAIL] Premium system internals fully exposed via metadata")
    print("  [FAIL] Method tokens and field indices available for Frida hooking")
    print("  [FIX]  All premium checks must be server-authoritative")
    print("  [FIX]  Obfuscate IL2CPP metadata (e.g., BeeByte obfuscator)")

    results_file = Path(__file__).parent / "results.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
