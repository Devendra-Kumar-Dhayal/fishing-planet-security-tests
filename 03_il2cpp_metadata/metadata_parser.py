#!/usr/bin/env python3
"""
TEST 03a: IL2CPP Metadata Dump
================================
Full dump of types, methods, and fields from global-metadata.dat.
Demonstrates how easily the entire game codebase structure is exposed.

Severity: HIGH
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import METADATA_FILE
from utils.il2cpp_metadata import (
    Il2CppMetadataParser, get_type_fields, get_type_methods,
)

RESULTS: dict = {}


def dump_full_metadata(parser: Il2CppMetadataParser) -> None:
    """Dump complete type hierarchy from metadata."""
    print("\n[*] Parsing all type definitions...")

    types = parser.get_type_definitions()
    methods = parser.get_method_definitions()
    images = parser.get_image_definitions()

    print(f"  Types:   {len(types)}")
    print(f"  Methods: {len(methods)}")
    print(f"  Images:  {len(images)}")

    RESULTS["summary"] = {
        "total_types": len(types),
        "total_methods": len(methods),
        "total_images": len(images),
        "metadata_version": parser.version,
    }

    # Dump assembly/image info
    print("\n[*] Assemblies/Images:")
    image_data: list[dict] = []
    for i, img in enumerate(images):
        try:
            name = parser.get_string(img.name_index)
            print(f"  [{i:3d}] {name} (types: {img.type_count}, start: {img.type_start})")
            image_data.append({
                "index": i,
                "name": name,
                "type_start": img.type_start,
                "type_count": img.type_count,
            })
        except (IndexError, UnicodeDecodeError):
            continue
    RESULTS["images"] = image_data

    # Dump all types with their methods and fields
    print(f"\n[*] Dumping all {len(types)} types (this may take a moment)...")
    type_dump: list[dict] = []

    for i, t in enumerate(types):
        try:
            name = parser.get_string(t.name_index)
            namespace = parser.get_string(t.namespace_index)
            full_name = f"{namespace}.{name}" if namespace else name

            type_info: dict = {
                "index": i,
                "name": full_name,
                "flags": f"0x{t.flags:08X}",
                "token": f"0x{t.token:08X}",
                "methods": [],
                "fields": [],
            }

            for mid, mname in get_type_methods(parser, t):
                type_info["methods"].append({"index": mid, "name": mname})

            for fid, fname in get_type_fields(parser, t):
                type_info["fields"].append({"index": fid, "name": fname})

            type_dump.append(type_info)
        except (IndexError, UnicodeDecodeError):
            continue

    RESULTS["types"] = type_dump
    print(f"  Successfully dumped {len(type_dump)} types")


def print_interesting_types(parser: Il2CppMetadataParser) -> None:
    """Print types that are particularly interesting for exploitation."""
    categories = {
        "Economy/Currency": ["money", "currency", "gold", "silver", "cash", "coin", "credit", "wallet", "balance"],
        "Premium/Shop": ["premium", "shop", "store", "purchase", "buy", "payment"],
        "Experience/Level": ["experience", "xp", "level", "rank", "progression"],
        "Anti-Cheat": ["obscured", "anticheat", "cheat", "detect", "hack"],
        "Inventory": ["inventory", "item", "equipment", "tackle", "rod", "reel", "bait"],
        "Fish/Catch": ["fish", "catch", "keepnet", "fishcage", "bite"],
        "Tournament": ["tournament", "competition", "leaderboard"],
    }

    types = parser.get_type_definitions()

    for category, keywords in categories.items():
        print(f"\n{'=' * 50}")
        print(f"  {category}")
        print(f"{'=' * 50}")

        found = 0
        for i, t in enumerate(types):
            try:
                name = parser.get_string(t.name_index)
                namespace = parser.get_string(t.namespace_index)
                full = f"{namespace}.{name}".lower()

                if any(kw in full for kw in keywords):
                    print(f"  {namespace}.{name}" if namespace else f"  {name}")
                    print(f"    methods={t.method_count} fields={t.field_count}")
                    found += 1
            except (IndexError, UnicodeDecodeError):
                continue

        print(f"  [{found} types found]")


def main() -> None:
    print("=" * 60)
    print("TEST 03a: IL2CPP Metadata Full Dump")
    print("=" * 60)

    parser = Il2CppMetadataParser(METADATA_FILE)
    summary = parser.dump_summary()
    print(f"\n  Metadata version: {summary['version']}")

    print_interesting_types(parser)
    dump_full_metadata(parser)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    total_types = RESULTS.get("summary", {}).get("total_types", 0)
    total_methods = RESULTS.get("summary", {}).get("total_methods", 0)
    print(f"  Exposed: {total_types} types, {total_methods} methods")
    print("  [FAIL] Complete game code structure is recoverable from metadata")
    print("  [FIX]  Use IL2CPP metadata obfuscation/encryption")
    print("  [FIX]  Strip method names from release builds")

    results_file = Path(__file__).parent / "metadata_dump.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Full dump saved to: {results_file}")
    print(f"  (File may be large: {len(json.dumps(RESULTS))} bytes)")


if __name__ == "__main__":
    main()
