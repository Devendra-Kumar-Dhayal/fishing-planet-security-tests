#!/usr/bin/env python3
"""
TEST 03b: Economy Class Dump
==============================
Focused extraction of all economy, currency, and monetization classes
from IL2CPP metadata. Shows exactly what an attacker would target.

Severity: HIGH
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import ECONOMY_TARGETS, METADATA_FILE, PREMIUM_TARGETS
from utils.il2cpp_metadata import (
    Il2CppMetadataParser, find_methods_by_name, find_types_by_name,
    get_type_fields, get_type_methods,
)

RESULTS: list[dict] = []


def dump_economy_types(parser: Il2CppMetadataParser) -> None:
    """Find and dump all economy-related types with full detail."""
    economy_keywords = [
        "money", "currency", "gold", "silver", "cash", "credit",
        "balance", "wallet", "reward", "payment", "purchase",
        "converter", "price", "cost", "discount", "shop",
    ]

    types = parser.get_type_definitions()
    found_types: list[dict] = []

    print("\n[*] Economy-Related Types:")
    print("-" * 60)

    for i, t in enumerate(types):
        try:
            name = parser.get_string(t.name_index)
            namespace = parser.get_string(t.namespace_index)
            full = f"{namespace}.{name}".lower()

            if any(kw in full for kw in economy_keywords):
                methods = get_type_methods(parser, t)
                fields = get_type_fields(parser, t)
                full_name = f"{namespace}.{name}" if namespace else name

                print(f"\n  [{i}] {full_name}")
                for mid, mname in methods:
                    print(f"    method: {mname}()")
                for fid, fname in fields:
                    print(f"    field:  {fname}")

                found_types.append({
                    "type_index": i,
                    "name": full_name,
                    "token": f"0x{t.token:08X}",
                    "methods": [{"index": m[0], "name": m[1]} for m in methods],
                    "fields": [{"index": f[0], "name": f[1]} for f in fields],
                })
        except (IndexError, UnicodeDecodeError):
            continue

    RESULTS.extend(found_types)
    print(f"\n  Total economy types found: {len(found_types)}")


def dump_target_methods(parser: Il2CppMetadataParser) -> None:
    """Find specific high-value target methods."""
    all_targets = ECONOMY_TARGETS + PREMIUM_TARGETS
    types = parser.get_type_definitions()

    print("\n\n[*] High-Value Target Methods:")
    print("-" * 60)

    for target in all_targets:
        matches = find_methods_by_name(parser, target)
        if matches:
            for idx, method_def, name in matches:
                parent = ""
                if method_def.declaring_type < len(types):
                    t = types[method_def.declaring_type]
                    ns = parser.get_string(t.namespace_index)
                    tn = parser.get_string(t.name_index)
                    parent = f"{ns}.{tn}" if ns else tn

                print(f"  {parent}::{name}() [method #{idx}, token=0x{method_def.token:08X}]")

                RESULTS.append({
                    "type": "target_method",
                    "method_index": idx,
                    "name": name,
                    "parent": parent,
                    "token": f"0x{method_def.token:08X}",
                    "params": method_def.parameter_count,
                })


def dump_string_literals(parser: Il2CppMetadataParser) -> None:
    """Search string literals for economy-related values."""
    print("\n\n[*] Economy-Related String Literals:")
    print("-" * 60)

    search_terms = [
        "currency", "money", "gold", "silver", "premium",
        "purchase", "buy", "price", "balance", "reward",
        "xp", "experience", "level",
    ]

    for term in search_terms:
        results = parser.search_string_literals(term, case_sensitive=False)
        if results:
            print(f"\n  '{term}' ({len(results)} matches):")
            for idx, value in results[:5]:
                display = value[:80] + "..." if len(value) > 80 else value
                print(f"    [{idx}] {display}")


def main() -> None:
    print("=" * 60)
    print("TEST 03b: Economy Class Dump")
    print("=" * 60)

    parser = Il2CppMetadataParser(METADATA_FILE)

    dump_economy_types(parser)
    dump_target_methods(parser)
    dump_string_literals(parser)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total findings: {len(RESULTS)}")
    print("  [FAIL] Full economy system architecture exposed")
    print("  [FAIL] Method tokens available for direct hooking")
    print("  [FIX]  Server-validate ALL currency operations")
    print("  [FIX]  Never trust client-reported balances")

    results_file = Path(__file__).parent / "economy_dump.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
