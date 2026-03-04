"""
Binary search utilities for ELF analysis of GameAssembly.so.

Provides symbol extraction, pattern matching, and section analysis
using readelf/nm/objdump subprocess calls and direct binary parsing.
"""
import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ElfSymbol:
    address: int
    size: int
    symbol_type: str
    binding: str
    name: str


@dataclass
class ElfSection:
    name: str
    section_type: str
    address: int
    offset: int
    size: int
    flags: str


def get_symbols(binary_path: Path, pattern: Optional[str] = None) -> list[ElfSymbol]:
    """Extract symbols from an ELF binary using nm."""
    result = subprocess.run(
        ["nm", "-D", "--defined-only", "-S", str(binary_path)],
        capture_output=True, timeout=60,
    )
    result.stdout = result.stdout.decode("utf-8", errors="replace")
    symbols: list[ElfSymbol] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4:
            try:
                addr = int(parts[0], 16)
                size = int(parts[1], 16) if len(parts) > 3 else 0
                sym_type = parts[2] if len(parts) > 3 else parts[1]
                name = parts[-1]
                if pattern and pattern.lower() not in name.lower():
                    continue
                symbols.append(ElfSymbol(addr, size, sym_type, "GLOBAL", name))
            except ValueError:
                continue
    return symbols


def get_sections(binary_path: Path) -> list[ElfSection]:
    """Extract section information from an ELF binary using readelf."""
    result = subprocess.run(
        ["readelf", "-S", str(binary_path)],
        capture_output=True, timeout=60,
    )
    result.stdout = result.stdout.decode("utf-8", errors="replace")
    sections: list[ElfSection] = []
    section_re = re.compile(
        r'\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)',
        re.IGNORECASE,
    )
    for line in result.stdout.splitlines():
        m = section_re.search(line)
        if m:
            sections.append(ElfSection(
                name=m.group(1),
                section_type=m.group(2),
                address=int(m.group(3), 16),
                offset=int(m.group(4), 16),
                size=int(m.group(5), 16),
                flags="",
            ))
    return sections


def check_debug_info(binary_path: Path) -> dict[str, bool]:
    """Check what debug information is present in the binary."""
    sections = get_sections(binary_path)
    section_names = {s.name for s in sections}

    return {
        "has_debuglink": ".gnu_debuglink" in section_names,
        "has_debug_info": ".debug_info" in section_names,
        "has_debug_abbrev": ".debug_abbrev" in section_names,
        "has_debug_line": ".debug_line" in section_names,
        "has_debug_str": ".debug_str" in section_names,
        "has_symtab": ".symtab" in section_names,
        "has_dynsym": ".dynsym" in section_names,
        "has_strtab": ".strtab" in section_names,
        "has_note_gnu_build_id": ".note.gnu.build-id" in section_names,
    }


def get_debuglink_target(binary_path: Path) -> Optional[str]:
    """Extract the debug link target filename."""
    result = subprocess.run(
        ["readelf", "--string-dump=.gnu_debuglink", str(binary_path)],
        capture_output=True, timeout=30,
    )
    try:
        stdout = result.stdout.decode("utf-8", errors="replace")
    except AttributeError:
        stdout = str(result.stdout)
    for line in stdout.splitlines():
        if "]" in line:
            parts = line.split("]", 1)
            if len(parts) > 1:
                cleaned = parts[1].strip()
                if cleaned:
                    return cleaned
    return None


def find_pattern_in_binary(binary_path: Path, pattern: bytes,
                           max_results: int = 100) -> list[int]:
    """Find byte pattern occurrences in a binary file."""
    data = binary_path.read_bytes()
    results: list[int] = []
    start = 0
    while len(results) < max_results:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        results.append(idx)
        start = idx + 1
    return results


def find_string_references(binary_path: Path, target: str,
                           max_results: int = 50) -> list[int]:
    """Find references to a string in the binary."""
    return find_pattern_in_binary(binary_path, target.encode("utf-8"), max_results)


def get_il2cpp_api_symbols(binary_path: Path) -> list[ElfSymbol]:
    """Extract all IL2CPP API function symbols."""
    return get_symbols(binary_path, "il2cpp_")


def get_function_at_address(binary_path: Path, address: int, num_bytes: int = 64) -> bytes:
    """Read bytes at a given address (file offset) from the binary."""
    with open(binary_path, "rb") as f:
        f.seek(address)
        return f.read(num_bytes)


def disassemble_at_offset(binary_path: Path, offset: int,
                          num_instructions: int = 20) -> str:
    """Disassemble instructions at a given offset using objdump."""
    result = subprocess.run(
        ["objdump", "-d", f"--start-address=0x{offset:x}",
         f"--stop-address=0x{offset + num_instructions * 15:x}",
         str(binary_path)],
        capture_output=True, timeout=30,
    )
    return result.stdout.decode("utf-8", errors="replace")
