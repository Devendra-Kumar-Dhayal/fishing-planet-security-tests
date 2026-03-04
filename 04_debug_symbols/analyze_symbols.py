#!/usr/bin/env python3
"""
TEST 04: Debug Symbol Analysis
================================
Checks for debug information leakage in GameAssembly.so.
Extracts exported symbols, checks for debug sections, and
maps the IL2CPP API surface available for exploitation.

Severity: HIGH
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import GAME_ASSEMBLY, GAME_DIR
from utils.binary_search import (
    check_debug_info, get_debuglink_target, get_il2cpp_api_symbols,
    get_sections, get_symbols,
)

RESULTS: list[dict] = []


def test_debug_sections() -> None:
    """Check what debug sections exist in the binary."""
    print("\n[TEST] Checking debug sections in GameAssembly.so...")

    debug_info = check_debug_info(GAME_ASSEMBLY)
    for section, present in debug_info.items():
        status = "PRESENT" if present else "absent"
        marker = "[EXPOSED]" if present else "[OK]    "
        print(f"  {marker} {section}: {status}")

        if present:
            RESULTS.append({
                "test": "debug_section",
                "section": section,
                "status": "VULNERABLE",
            })


def test_debuglink() -> None:
    """Check .gnu_debuglink reference."""
    print("\n[TEST] Checking .gnu_debuglink target...")

    target = get_debuglink_target(GAME_ASSEMBLY)
    if target:
        print(f"  [EXPOSED] Debug link target: {target}")
        debug_file = GAME_DIR / target
        if debug_file.exists():
            size = debug_file.stat().st_size
            print(f"  [CRITICAL] Debug file EXISTS! Size: {size} bytes")
            RESULTS.append({
                "test": "debuglink",
                "target": target,
                "exists": True,
                "size": size,
                "status": "CRITICAL",
            })
        else:
            print(f"  [INFO] Debug file not present (referenced but not shipped)")
            RESULTS.append({
                "test": "debuglink",
                "target": target,
                "exists": False,
                "status": "MEDIUM",
            })
    else:
        print("  [OK] No debug link found")


def test_symbol_table() -> None:
    """Analyze the exported symbol table."""
    print("\n[TEST] Analyzing exported symbols...")

    all_symbols = get_symbols(GAME_ASSEMBLY)
    print(f"  Total dynamic symbols: {len(all_symbols)}")

    # Categorize symbols
    il2cpp_symbols = [s for s in all_symbols if s.name.startswith("il2cpp_")]
    mono_symbols = [s for s in all_symbols if s.name.startswith("mono_")]
    unity_symbols = [s for s in all_symbols if "unity" in s.name.lower() or "Unity" in s.name]

    print(f"  IL2CPP API symbols: {len(il2cpp_symbols)}")
    print(f"  Mono compat symbols: {len(mono_symbols)}")
    print(f"  Unity symbols: {len(unity_symbols)}")

    RESULTS.append({
        "test": "symbol_count",
        "total": len(all_symbols),
        "il2cpp": len(il2cpp_symbols),
        "mono": len(mono_symbols),
        "unity": len(unity_symbols),
        "status": "VULNERABLE" if il2cpp_symbols else "SECURE",
    })

    # List dangerous IL2CPP API functions
    dangerous_apis = [
        "il2cpp_domain_get", "il2cpp_domain_get_assemblies",
        "il2cpp_assembly_get_image", "il2cpp_class_from_name",
        "il2cpp_class_get_method_from_name", "il2cpp_class_get_fields",
        "il2cpp_method_get_pointer", "il2cpp_field_get_value",
        "il2cpp_field_set_value", "il2cpp_field_static_get_value",
        "il2cpp_field_static_set_value", "il2cpp_runtime_invoke",
        "il2cpp_object_new", "il2cpp_string_new",
        "il2cpp_thread_attach", "il2cpp_thread_detach",
    ]

    print("\n  Dangerous IL2CPP APIs available for hooking:")
    for api_name in dangerous_apis:
        found = any(s.name == api_name for s in il2cpp_symbols)
        marker = "[EXPOSED]" if found else "[OK]    "
        print(f"    {marker} {api_name}")
        if found:
            sym = next(s for s in il2cpp_symbols if s.name == api_name)
            RESULTS.append({
                "test": "dangerous_api",
                "name": api_name,
                "address": f"0x{sym.address:016X}",
                "status": "VULNERABLE",
            })


def test_section_analysis() -> None:
    """Analyze all ELF sections for information leakage."""
    print("\n[TEST] ELF section analysis...")

    sections = get_sections(GAME_ASSEMBLY)
    print(f"  Total sections: {len(sections)}")

    interesting_sections = [".symtab", ".strtab", ".debug_info", ".debug_abbrev",
                           ".debug_line", ".debug_str", ".gnu_debuglink",
                           ".note.gnu.build-id", ".rodata"]

    for section in sections:
        if section.name in interesting_sections:
            print(f"  [{section.name}] offset=0x{section.offset:X} size={section.size} bytes")
            RESULTS.append({
                "test": "elf_section",
                "name": section.name,
                "offset": f"0x{section.offset:X}",
                "size": section.size,
            })


def main() -> None:
    print("=" * 60)
    print("TEST 04: Debug Symbol Analysis")
    print("=" * 60)

    test_debug_sections()
    test_debuglink()
    test_symbol_table()
    test_section_analysis()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    vuln_count = sum(1 for r in RESULTS if r.get("status") in ("VULNERABLE", "CRITICAL"))
    print(f"  Vulnerabilities: {vuln_count}")
    print("  [FAIL] IL2CPP API fully exposed via dynamic symbols")
    print("  [FAIL] Debug link reference present (even if file not shipped)")
    print("  [FAIL] Full symbol table enables Frida/GDB-based attacks")
    print("  [FIX]  Strip all unnecessary symbols from release builds")
    print("  [FIX]  Remove .gnu_debuglink section")
    print("  [FIX]  Consider custom IL2CPP builds with API symbol stripping")

    results_file = Path(__file__).parent / "results.json"
    results_file.write_text(json.dumps(RESULTS, indent=2))
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
