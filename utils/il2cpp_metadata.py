"""
IL2CPP global-metadata.dat parser.

Parses the binary metadata format used by IL2CPP to extract:
- String literals
- Type definitions (classes, structs, enums)
- Method definitions
- Field definitions
- Image/assembly info

Reference: https://github.com/pgarba/il2cppdumper (format docs)
"""
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# IL2CPP metadata magic number
IL2CPP_METADATA_MAGIC = 0xFAB11BAF

# Header field count varies by version. We support v24+ (Unity 2018.3+) through v31
HEADER_FIELDS_V24 = [
    "sanity", "version",
    "stringLiteralOffset", "stringLiteralSize",
    "stringLiteralDataOffset", "stringLiteralDataSize",
    "stringOffset", "stringSize",
    "eventsOffset", "eventsSize",
    "propertiesOffset", "propertiesSize",
    "methodsOffset", "methodsSize",
    "parameterDefaultValuesOffset", "parameterDefaultValuesSize",
    "fieldDefaultValuesOffset", "fieldDefaultValuesSize",
    "fieldAndParameterDefaultValueDataOffset", "fieldAndParameterDefaultValueDataSize",
    "fieldMarshaledSizesOffset", "fieldMarshaledSizesSize",
    "parametersOffset", "parametersSize",
    "fieldsOffset", "fieldsSize",
    "genericParametersOffset", "genericParametersSize",
    "genericParameterConstraintsOffset", "genericParameterConstraintsSize",
    "genericContainersOffset", "genericContainersSize",
    "nestedTypesOffset", "nestedTypesSize",
    "interfacesOffset", "interfacesSize",
    "vtableMethodsOffset", "vtableMethodsSize",
    "interfaceOffsetsOffset", "interfaceOffsetsSize",
    "typeDefinitionsOffset", "typeDefinitionsSize",
    "imagesOffset", "imagesSize",
    "assembliesOffset", "assembliesSize",
    "fieldRefsOffset", "fieldRefsSize",
    "referencedAssembliesOffset", "referencedAssembliesSize",
    "attributeDataOffset", "attributeDataSize",
    "attributeDataRangeOffset", "attributeDataRangeSize",
]


@dataclass
class Il2CppStringLiteral:
    length: int
    data_index: int


@dataclass
class Il2CppTypeDefinition:
    name_index: int
    namespace_index: int
    byval_type_index: int
    declaringtype_index: int
    parent_index: int
    element_type_index: int
    generic_container_index: int
    flags: int
    field_start: int
    method_start: int
    event_start: int
    property_start: int
    nested_types_start: int
    interfaces_start: int
    vtable_start: int
    interface_offsets_start: int
    method_count: int
    property_count: int
    field_count: int
    event_count: int
    nested_type_count: int
    vtable_count: int
    interfaces_count: int
    interface_offsets_count: int
    bitfield: int
    token: int


@dataclass
class Il2CppMethodDefinition:
    name_index: int
    declaring_type: int
    return_type: int
    parameter_start: int
    generic_container_index: int
    token: int
    flags: int
    iflags: int
    slot: int
    parameter_count: int


@dataclass
class Il2CppFieldDefinition:
    name_index: int
    type_index: int
    token: int


@dataclass
class Il2CppImageDefinition:
    name_index: int
    assembly_index: int
    type_start: int
    type_count: int
    exported_type_start: int
    exported_type_count: int
    entry_point_index: int
    token: int
    custom_attribute_start: int
    custom_attribute_count: int


class Il2CppMetadataParser:
    """Parses IL2CPP global-metadata.dat files."""

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.data = filepath.read_bytes()
        self.header: dict[str, int] = {}
        self.version: int = 0
        self._parse_header()

    def _parse_header(self) -> None:
        magic, version = struct.unpack_from("<II", self.data, 0)
        if magic != IL2CPP_METADATA_MAGIC:
            raise ValueError(f"Invalid metadata magic: 0x{magic:08X} (expected 0x{IL2CPP_METADATA_MAGIC:08X})")

        self.version = version
        self.header["sanity"] = magic
        self.header["version"] = version

        # Parse remaining header fields (all uint32 pairs of offset+size)
        offset = 8
        for i in range(2, len(HEADER_FIELDS_V24), 2):
            if offset + 8 > len(self.data):
                break
            field_offset, field_size = struct.unpack_from("<II", self.data, offset)
            self.header[HEADER_FIELDS_V24[i]] = field_offset
            self.header[HEADER_FIELDS_V24[i + 1]] = field_size
            offset += 8

    def get_string(self, index: int) -> str:
        """Get a string from the string table by index."""
        str_offset = self.header["stringOffset"]
        str_size = self.header["stringSize"]
        start = str_offset + index
        if start >= str_offset + str_size or start >= len(self.data):
            return ""
        end = self.data.find(b'\x00', start, str_offset + str_size)
        if end == -1:
            end = min(start + 256, str_offset + str_size)
        return self.data[start:end].decode("utf-8", errors="replace")

    def get_string_literal(self, index: int) -> str:
        """Get a string literal by its index in the string literal table."""
        lit_offset = self.header["stringLiteralOffset"]
        entry_offset = lit_offset + index * 8
        length, data_idx = struct.unpack_from("<II", self.data, entry_offset)

        data_offset = self.header["stringLiteralDataOffset"] + data_idx
        return self.data[data_offset:data_offset + length].decode("utf-8", errors="replace")

    def get_type_definitions(self) -> list[Il2CppTypeDefinition]:
        """Parse all type definitions."""
        offset = self.header["typeDefinitionsOffset"]
        size = self.header["typeDefinitionsSize"]
        type_def_size = self._detect_typedef_size()
        count = size // type_def_size

        types: list[Il2CppTypeDefinition] = []
        for i in range(count):
            pos = offset + i * type_def_size

            if self.version >= 29 and type_def_size == 88:
                # v29+/v31: 88 bytes total
                # 16 int32 (64 bytes) + 8 uint16 (16 bytes) + 2 int32 (8 bytes)
                int32s = struct.unpack_from("<16I", self.data, pos)
                uint16s = struct.unpack_from("<8H", self.data, pos + 64)
                tail = struct.unpack_from("<2I", self.data, pos + 80)

                td = Il2CppTypeDefinition(
                    name_index=int32s[0], namespace_index=int32s[1],
                    byval_type_index=int32s[2], declaringtype_index=int32s[3],
                    parent_index=int32s[4], element_type_index=int32s[5],
                    generic_container_index=int32s[6], flags=int32s[7],
                    field_start=int32s[8], method_start=int32s[9],
                    event_start=int32s[10], property_start=int32s[11],
                    nested_types_start=int32s[12], interfaces_start=int32s[13],
                    vtable_start=int32s[14], interface_offsets_start=int32s[15],
                    method_count=uint16s[0], property_count=uint16s[1],
                    field_count=uint16s[2], event_count=uint16s[3],
                    nested_type_count=uint16s[4], vtable_count=uint16s[5],
                    interfaces_count=uint16s[6], interface_offsets_count=uint16s[7],
                    bitfield=tail[0], token=tail[1],
                )
            else:
                # v24-v27: all uint32
                fields = struct.unpack_from(f"<{'I' * (type_def_size // 4)}", self.data, pos)
                td = Il2CppTypeDefinition(
                    name_index=fields[0], namespace_index=fields[1],
                    byval_type_index=fields[2], declaringtype_index=fields[3],
                    parent_index=fields[4], element_type_index=fields[5],
                    generic_container_index=fields[6], flags=fields[7],
                    field_start=fields[8], method_start=fields[9],
                    event_start=fields[10], property_start=fields[11],
                    nested_types_start=fields[12], interfaces_start=fields[13],
                    vtable_start=fields[14], interface_offsets_start=fields[15],
                    method_count=fields[16], property_count=fields[17],
                    field_count=fields[18], event_count=fields[19],
                    nested_type_count=fields[20], vtable_count=fields[21],
                    interfaces_count=fields[22], interface_offsets_count=fields[23],
                    bitfield=fields[24], token=fields[25] if len(fields) > 25 else 0,
                )
            types.append(td)
        return types

    def get_method_definitions(self) -> list[Il2CppMethodDefinition]:
        """Parse all method definitions."""
        offset = self.header["methodsOffset"]
        size = self.header["methodsSize"]
        method_size = self._detect_method_size()
        count = size // method_size

        methods: list[Il2CppMethodDefinition] = []
        for i in range(count):
            pos = offset + i * method_size
            if method_size == 24 and self.version >= 29:
                # v29+/v31: nameIndex(4), declaringType(2), returnType(2),
                #   parameterStart(2), genericContainerIndex(2),
                #   token(4), flags(2), iflags(2), slot(2), parameterCount(2)
                name_idx, = struct.unpack_from("<I", self.data, pos)
                declaring, ret_type, param_start, generic = struct.unpack_from("<4H", self.data, pos + 4)
                token, = struct.unpack_from("<I", self.data, pos + 12)
                flags, iflags, slot, param_count = struct.unpack_from("<4H", self.data, pos + 16)
                md = Il2CppMethodDefinition(
                    name_index=name_idx, declaring_type=declaring, return_type=ret_type,
                    parameter_start=param_start, generic_container_index=generic,
                    token=token, flags=flags, iflags=iflags,
                    slot=slot, parameter_count=param_count,
                )
            elif method_size == 28:
                base = struct.unpack_from("<6I", self.data, pos)
                extras = struct.unpack_from("<4H", self.data, pos + 24)
                md = Il2CppMethodDefinition(
                    name_index=base[0], declaring_type=base[1], return_type=base[2],
                    parameter_start=base[3], generic_container_index=base[4],
                    token=base[5], flags=extras[0], iflags=extras[1],
                    slot=extras[2], parameter_count=extras[3],
                )
            else:
                # v24-v26: 32 bytes
                fields = struct.unpack_from("<6I4H", self.data, pos)
                md = Il2CppMethodDefinition(
                    name_index=fields[0], declaring_type=fields[1], return_type=fields[2],
                    parameter_start=fields[3], generic_container_index=fields[4],
                    token=fields[5], flags=fields[6], iflags=fields[7],
                    slot=fields[8], parameter_count=fields[9],
                )
            methods.append(md)
        return methods

    def get_field_definitions(self) -> list[Il2CppFieldDefinition]:
        """Parse all field definitions."""
        offset = self.header["fieldsOffset"]
        size = self.header["fieldsSize"]
        field_size = 12  # nameIndex(4) + typeIndex(4) + token(4)
        count = size // field_size

        fields: list[Il2CppFieldDefinition] = []
        for i in range(count):
            pos = offset + i * field_size
            name_idx, type_idx, token = struct.unpack_from("<III", self.data, pos)
            fields.append(Il2CppFieldDefinition(name_idx, type_idx, token))
        return fields

    def get_image_definitions(self) -> list[Il2CppImageDefinition]:
        """Parse all image/assembly definitions."""
        offset = self.header["imagesOffset"]
        size = self.header["imagesSize"]
        img_size = 40  # 10 * 4 bytes
        count = size // img_size

        images: list[Il2CppImageDefinition] = []
        for i in range(count):
            pos = offset + i * img_size
            fields = struct.unpack_from("<10I", self.data, pos)
            images.append(Il2CppImageDefinition(*fields))
        return images

    def get_string_literals_count(self) -> int:
        """Get total number of string literals."""
        return self.header["stringLiteralSize"] // 8

    def search_strings(self, pattern: str, case_sensitive: bool = True) -> list[tuple[int, str]]:
        """Search the string table for entries matching a pattern."""
        str_offset = self.header["stringOffset"]
        str_size = self.header["stringSize"]
        raw = self.data[str_offset:str_offset + str_size]

        results: list[tuple[int, str]] = []
        search = pattern if case_sensitive else pattern.lower()
        pos = 0
        while pos < len(raw):
            end = raw.index(b'\x00', pos) if b'\x00' in raw[pos:] else len(raw)
            s = raw[pos:end].decode("utf-8", errors="replace")
            compare = s if case_sensitive else s.lower()
            if search in compare:
                results.append((pos, s))
            pos = end + 1
        return results

    def search_string_literals(self, pattern: str, case_sensitive: bool = True) -> list[tuple[int, str]]:
        """Search string literals for entries matching a pattern."""
        count = self.get_string_literals_count()
        search = pattern if case_sensitive else pattern.lower()
        results: list[tuple[int, str]] = []

        for i in range(count):
            try:
                s = self.get_string_literal(i)
                compare = s if case_sensitive else s.lower()
                if search in compare:
                    results.append((i, s))
            except (IndexError, UnicodeDecodeError):
                continue
        return results

    def _detect_typedef_size(self) -> int:
        """Detect TypeDefinition struct size based on version."""
        size = self.header["typeDefinitionsSize"]
        # v31 uses 88 bytes, v29: 104, v27: 104, v24: 100
        if self.version >= 31:
            candidates = [88, 108, 104, 100]
        elif self.version >= 27:
            candidates = [104, 108, 100, 88]
        else:
            candidates = [100, 104, 96]
        for candidate in candidates:
            if size % candidate == 0:
                return candidate
        return 104  # default

    def _detect_method_size(self) -> int:
        """Detect MethodDefinition struct size."""
        size = self.header["methodsSize"]
        # v31 uses 24 bytes, v29 uses 28, v24 uses 32
        if self.version >= 31:
            candidates = [24, 28, 32]
        else:
            candidates = [32, 28, 24]
        for candidate in candidates:
            if size % candidate == 0:
                return candidate
        return 28

    def dump_summary(self) -> dict[str, int]:
        """Return a summary of metadata contents."""
        return {
            "version": self.version,
            "string_table_size": self.header.get("stringSize", 0),
            "string_literals_count": self.get_string_literals_count(),
            "type_definitions_size": self.header.get("typeDefinitionsSize", 0),
            "methods_size": self.header.get("methodsSize", 0),
            "fields_size": self.header.get("fieldsSize", 0),
            "images_size": self.header.get("imagesSize", 0),
            "typedef_struct_size": self._detect_typedef_size(),
            "method_struct_size": self._detect_method_size(),
        }


def find_methods_by_name(parser: Il2CppMetadataParser, name: str,
                         exact: bool = False) -> list[tuple[int, Il2CppMethodDefinition, str]]:
    """Find method definitions by name. Returns (index, method_def, resolved_name)."""
    methods = parser.get_method_definitions()
    results: list[tuple[int, Il2CppMethodDefinition, str]] = []
    search = name.lower()

    for i, m in enumerate(methods):
        try:
            method_name = parser.get_string(m.name_index)
            compare = method_name if exact else method_name.lower()
            target = name if exact else search
            if (exact and compare == target) or (not exact and target in compare):
                results.append((i, m, method_name))
        except (IndexError, UnicodeDecodeError):
            continue
    return results


def find_types_by_name(parser: Il2CppMetadataParser, name: str,
                       exact: bool = False) -> list[tuple[int, Il2CppTypeDefinition, str, str]]:
    """Find type definitions by name. Returns (index, type_def, name, namespace)."""
    types = parser.get_type_definitions()
    results: list[tuple[int, Il2CppTypeDefinition, str, str]] = []
    search = name.lower()

    for i, t in enumerate(types):
        try:
            type_name = parser.get_string(t.name_index)
            namespace = parser.get_string(t.namespace_index)
            compare = type_name if exact else type_name.lower()
            target = name if exact else search
            if (exact and compare == target) or (not exact and target in compare):
                results.append((i, t, type_name, namespace))
        except (IndexError, UnicodeDecodeError):
            continue
    return results


def get_type_methods(parser: Il2CppMetadataParser,
                     type_def: Il2CppTypeDefinition) -> list[tuple[int, str]]:
    """Get all methods for a type definition. Returns (method_index, method_name)."""
    methods = parser.get_method_definitions()
    results: list[tuple[int, str]] = []
    for i in range(type_def.method_start, type_def.method_start + type_def.method_count):
        if i < len(methods):
            try:
                name = parser.get_string(methods[i].name_index)
                results.append((i, name))
            except (IndexError, UnicodeDecodeError):
                continue
    return results


def get_type_fields(parser: Il2CppMetadataParser,
                    type_def: Il2CppTypeDefinition) -> list[tuple[int, str]]:
    """Get all fields for a type definition. Returns (field_index, field_name)."""
    fields = parser.get_field_definitions()
    results: list[tuple[int, str]] = []
    for i in range(type_def.field_start, type_def.field_start + type_def.field_count):
        if i < len(fields):
            try:
                name = parser.get_string(fields[i].name_index)
                results.append((i, name))
            except (IndexError, UnicodeDecodeError):
                continue
    return results
