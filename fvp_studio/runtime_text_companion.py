"""Read-only UIF text companion candidates for ANSI ``DrawTextA`` targets.

This module deliberately has no game-specific paths or names.  It validates a
user-supplied UniversalInjectorFramework package, parses just enough PE data
to prove the target/proxy contract, and creates an in-memory candidate.  The
three DLL payloads are copied byte-for-byte; only the JSON configuration is
generated.  No function in this module writes a file.

The source HCB encoding is kept as an explicit input because ``shift_jis`` and
``cp932`` are not identical Python codecs.  Carrier bytes are always checked
against CP932 and, before selection, against the declared source codec as an
exact two-byte round trip.  This means a candidate can be fed back to a strict
Shift-JIS HCB writer without silently changing a carrier byte, while a caller
that declares ``cp932`` can use the CP932 private-use/IBM-extension priority
tiers as intended.
"""

from __future__ import annotations

import codecs
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat as stat_module
import struct
from typing import Any, Iterable, Iterator, Mapping, Sequence
import unicodedata


RUNTIME_TEXT_COMPANION_SCHEMA = "fvp-studio-v2.runtime-text-companion.v1"
PACKAGE_SNAPSHOT_SCHEMA = "fvp-studio-v2.runtime-text-companion-package.v1"
PE_INSPECTION_SCHEMA = "fvp-studio-v2.runtime-text-companion-pe.v1"
REQUIRED_PACKAGE_FILES = (
    "winmm.dll",
    "LoaderDll.dll",
    "LocaleEmulator.dll",
    "uif_config.json",
)
_WINMM_NAME = "winmm.dll"
_CP932_ENCODING = "cp932"
_UIF_DIALOGUE_APIS = ["DrawTextA"]
_UIF_CONVERSION_CODEPAGE = 932
_MAX_PE_SECTIONS = 96
_MAX_IMPORT_DESCRIPTORS = 4096
_MAX_IMPORT_THUNKS = 65536
_MAX_EXPORTS = 1_000_000


class RuntimeTextCompanionError(ValueError):
    """Base error for fail-closed companion validation."""


class CompanionPackageError(RuntimeTextCompanionError):
    """Raised when a package file is missing, unsafe, malformed, or drifting."""


class PEFormatError(RuntimeTextCompanionError):
    """Raised when a PE import/export table cannot be proven from bytes."""


class TextMappingError(RuntimeTextCompanionError):
    """Raised when a deterministic CP932 text mapping cannot be made."""


@dataclass(frozen=True)
class FileIdentity:
    """Content identity returned for one stable ordinary file."""

    name: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class PEImport:
    """One normal PE import thunk."""

    dll: str
    name: str | None
    ordinal: int | None
    thunk_index: int

    @property
    def is_ordinal(self) -> bool:
        return self.ordinal is not None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "dll": self.dll,
            "thunk_index": self.thunk_index,
        }
        if self.name is not None:
            value["name"] = self.name
        if self.ordinal is not None:
            value["ordinal"] = self.ordinal
        return value


@dataclass(frozen=True)
class PEExports:
    """The named and ordinal-only exports proven from one PE image."""

    named: tuple[str, ...]
    ordinal_base: int
    ordinal_only: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "named": list(self.named),
            "named_count": len(self.named),
            "ordinal_base": self.ordinal_base,
            "ordinal_only": list(self.ordinal_only),
            "ordinal_only_count": len(self.ordinal_only),
        }


@dataclass(frozen=True)
class _Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)


class _PEImage:
    """Small bounds-checked PE32/PE32+ view used by the public parsers."""

    def __init__(
        self,
        payload: bytes,
        *,
        sections: tuple[_Section, ...],
        directories: Mapping[int, tuple[int, int]],
        size_of_headers: int,
        thunk_size: int,
    ) -> None:
        self.payload = payload
        self.sections = sections
        self.directories = dict(directories)
        self.size_of_headers = size_of_headers
        self.thunk_size = thunk_size

    @classmethod
    def parse(cls, payload: bytes) -> "_PEImage":
        if not isinstance(payload, bytes):
            raise PEFormatError("PE payload 必须是 bytes")
        if len(payload) < 64 or payload[:2] != b"MZ":
            raise PEFormatError("文件不是有效 PE：缺少 MZ")
        try:
            pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        except struct.error as exc:
            raise PEFormatError("PE DOS 头已截断") from exc
        if pe_offset < 0x40 or pe_offset + 4 + 20 > len(payload):
            raise PEFormatError("PE 头偏移超出文件")
        if payload[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise PEFormatError("缺少 PE 签名")

        coff_offset = pe_offset + 4
        try:
            (
                _machine,
                section_count,
                _timestamp,
                _symbol_table,
                _symbol_count,
                optional_size,
                _characteristics,
            ) = struct.unpack_from("<HHIIIHH", payload, coff_offset)
        except struct.error as exc:
            raise PEFormatError("PE COFF 头已截断") from exc
        if not 1 <= section_count <= _MAX_PE_SECTIONS:
            raise PEFormatError("PE section 数量无效")
        optional_offset = coff_offset + 20
        optional_end = optional_offset + optional_size
        if optional_size < 2 or optional_end > len(payload):
            raise PEFormatError("PE optional header 已截断")
        magic = struct.unpack_from("<H", payload, optional_offset)[0]
        if magic == 0x10B:
            directory_count_relative = 92
            directory_start_relative = 96
            thunk_size = 4
        elif magic == 0x20B:
            directory_count_relative = 108
            directory_start_relative = 112
            thunk_size = 8
        else:
            raise PEFormatError("PE optional header 类型不受支持")
        if optional_size < directory_start_relative:
            raise PEFormatError("PE optional header 缺少 data directories")
        try:
            size_of_headers = struct.unpack_from(
                "<I", payload, optional_offset + 60
            )[0]
        except struct.error as exc:
            raise PEFormatError("PE optional header 缺少 SizeOfHeaders") from exc
        if size_of_headers <= 0 or size_of_headers > len(payload):
            raise PEFormatError("PE SizeOfHeaders 无效")

        directories: dict[int, tuple[int, int]] = {}
        if optional_size >= directory_count_relative + 4:
            directory_count = struct.unpack_from(
                "<I", payload, optional_offset + directory_count_relative
            )[0]
        else:
            directory_count = 0
        available_directories = min(
            directory_count,
            16,
            max(0, (optional_size - directory_start_relative) // 8),
        )
        for index in range(available_directories):
            directory_offset = (
                optional_offset + directory_start_relative + index * 8
            )
            directories[index] = struct.unpack_from(
                "<II", payload, directory_offset
            )

        section_offset = optional_end
        section_end = section_offset + section_count * 40
        if section_end > len(payload):
            raise PEFormatError("PE section table 已截断")
        sections: list[_Section] = []
        for index in range(section_count):
            offset = section_offset + index * 40
            try:
                virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                    "<IIII", payload, offset + 8
                )
            except struct.error as exc:
                raise PEFormatError("PE section header 已截断") from exc
            if raw_size and (
                raw_offset > len(payload)
                or raw_size > len(payload) - raw_offset
            ):
                raise PEFormatError("PE section raw data 超出文件")
            sections.append(
                _Section(
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                )
            )
        return cls(
            payload,
            sections=tuple(sections),
            directories=directories,
            size_of_headers=size_of_headers,
            thunk_size=thunk_size,
        )

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories.get(index, (0, 0))

    def rva_span(self, rva: int) -> tuple[int, int]:
        if rva < 0 or rva > 0xFFFFFFFF:
            raise PEFormatError("PE RVA 超出范围")
        if rva < self.size_of_headers:
            if rva >= len(self.payload):
                raise PEFormatError("PE header RVA 超出文件")
            return rva, min(self.size_of_headers - rva, len(self.payload) - rva)

        matches: list[tuple[int, int]] = []
        for section in self.sections:
            if not section.mapped_size:
                continue
            if section.virtual_address <= rva < section.virtual_address + section.mapped_size:
                relative = rva - section.virtual_address
                if relative >= section.raw_size:
                    raise PEFormatError("PE RVA 位于 section 的未映射尾部")
                offset = section.raw_offset + relative
                matches.append((offset, section.raw_size - relative))
        if len(matches) != 1:
            raise PEFormatError("PE RVA 不能唯一映射到文件")
        offset, span = matches[0]
        if offset < 0 or offset > len(self.payload):
            raise PEFormatError("PE RVA 映射偏移超出文件")
        return offset, min(span, len(self.payload) - offset)

    def read_rva(self, rva: int, size: int) -> bytes:
        if size < 0:
            raise PEFormatError("PE 读取长度无效")
        offset, span = self.rva_span(rva)
        if size > span or size > len(self.payload) - offset:
            raise PEFormatError("PE RVA 数据已截断")
        return self.payload[offset : offset + size]

    def c_string_rva(self, rva: int, *, label: str) -> bytes:
        offset, span = self.rva_span(rva)
        end = self.payload.find(b"\0", offset, offset + span)
        if end < 0:
            raise PEFormatError(f"{label} 未终止")
        return self.payload[offset:end]


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise RuntimeTextCompanionError("无法生成确定性 JSON 身份") from exc


def _json_no_constant(value: str) -> Any:
    raise ValueError(f"JSON 常量不允许: {value}")


def _json_no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON 键重复: {key}")
        result[key] = value
    return result


def _parse_utf8_json(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload:
        raise CompanionPackageError("uif_config.json 必须是非空 bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CompanionPackageError("uif_config.json 不是有效 UTF-8") from exc
    if text.startswith("\ufeff"):
        raise CompanionPackageError("uif_config.json 不允许 UTF-8 BOM")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_json_no_duplicate_pairs,
            parse_constant=_json_no_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CompanionPackageError("uif_config.json 不是有效 UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CompanionPackageError("uif_config.json 根节点必须是对象")
    return value


def _path_lstat(path: Path, *, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise CompanionPackageError(f"{label}缺失: {path}") from exc
    except OSError as exc:
        raise CompanionPackageError(f"无法读取{label}状态: {path}") from exc
    if stat_module.S_ISLNK(info.st_mode):
        raise CompanionPackageError(f"{label}不能是符号链接: {path}")
    return info


def _stable_stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        # Path.lstat() and an open file descriptor expose different permission
        # bits on Windows.  The type bits are enough here because symlinks are
        # rejected separately by _path_lstat().
        int(stat_module.S_IFMT(info.st_mode)),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _ordinary_file_stamp(path: Path, *, label: str) -> tuple[int, ...]:
    info = _path_lstat(path, label=label)
    if not stat_module.S_ISREG(info.st_mode):
        raise CompanionPackageError(f"{label}必须是根目录直属普通文件: {path}")
    return _stable_stamp(info)


def _read_stable_file(path: Path, *, label: str) -> tuple[bytes, tuple[int, ...]]:
    """Read twice and reject replacement/content/metadata drift."""

    first_payload: bytes | None = None
    first_stamp: tuple[int, ...] | None = None
    for _attempt in range(2):
        before = _ordinary_file_stamp(path, label=label)
        try:
            with path.open("rb") as handle:
                fd_before = _stable_stamp(os.fstat(handle.fileno()))
                if fd_before != before:
                    raise CompanionPackageError(f"{label}读取前已漂移: {path}")
                payload = handle.read()
                fd_after = _stable_stamp(os.fstat(handle.fileno()))
        except CompanionPackageError:
            raise
        except OSError as exc:
            raise CompanionPackageError(f"无法读取{label}: {path}") from exc
        after = _ordinary_file_stamp(path, label=label)
        if (
            before != after
            or fd_before != fd_after
            or len(payload) != before[3]
        ):
            raise CompanionPackageError(f"{label}读取期间发生漂移: {path}")
        if first_payload is not None and (
            payload != first_payload or after != first_stamp
        ):
            raise CompanionPackageError(f"{label}重复读取不一致: {path}")
        first_payload = payload
        first_stamp = after
    assert first_payload is not None and first_stamp is not None
    return first_payload, first_stamp


def _resolve_directory(value: str | Path, *, label: str) -> Path:
    try:
        raw = Path(value).expanduser()
    except (TypeError, ValueError, OSError) as exc:
        raise CompanionPackageError(f"{label}路径无效") from exc
    try:
        info = raw.lstat()
    except FileNotFoundError as exc:
        raise CompanionPackageError(f"{label}不存在: {raw}") from exc
    except OSError as exc:
        raise CompanionPackageError(f"无法读取{label}: {raw}") from exc
    if stat_module.S_ISLNK(info.st_mode):
        raise CompanionPackageError(f"{label}不能是符号链接: {raw}")
    if not stat_module.S_ISDIR(info.st_mode):
        raise CompanionPackageError(f"{label}必须是目录: {raw}")
    try:
        return raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CompanionPackageError(f"无法解析{label}: {raw}") from exc


def _resolve_file(value: str | Path, *, label: str) -> Path:
    try:
        raw = Path(value).expanduser()
    except (TypeError, ValueError, OSError) as exc:
        raise CompanionPackageError(f"{label}路径无效") from exc
    _ordinary_file_stamp(raw, label=label)
    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CompanionPackageError(f"无法解析{label}: {raw}") from exc
    _ordinary_file_stamp(resolved, label=label)
    return resolved


@dataclass(frozen=True)
class CompanionPackageSnapshot:
    """A stable, in-memory package snapshot."""

    root: Path
    payloads: Mapping[str, bytes]
    files: Mapping[str, FileIdentity]
    config: Mapping[str, Any]
    config_bytes: bytes
    package_identity: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": PACKAGE_SNAPSHOT_SCHEMA,
            "package_root": str(self.root),
            "package_identity": copy.deepcopy(dict(self.package_identity)),
            "files": {
                name: identity.as_dict()
                for name, identity in self.files.items()
            },
            "config": copy.deepcopy(dict(self.config)),
        }

    def verify_current(self) -> None:
        """Re-read the four direct children and reject any package drift."""

        current = read_companion_package(self.root)
        if current.package_identity != self.package_identity:
            raise CompanionPackageError("伴随组件 package identity 已漂移")
        for name in REQUIRED_PACKAGE_FILES:
            if current.payloads[name] != self.payloads[name]:
                raise CompanionPackageError(
                    f"伴随组件负载已漂移: {name}"
                )


def _package_identity(files: Mapping[str, FileIdentity]) -> dict[str, Any]:
    records = [files[name].as_dict() for name in REQUIRED_PACKAGE_FILES]
    digest = _sha256_bytes(_canonical_json_bytes(records))
    return {
        "schema": PACKAGE_SNAPSHOT_SCHEMA,
        "files": copy.deepcopy(records),
        "sha256": digest,
    }


def read_companion_package(package_root: str | Path) -> CompanionPackageSnapshot:
    """Read exactly the four required direct ordinary files from ``package_root``."""

    root = _resolve_directory(package_root, label="package_root")
    payloads: dict[str, bytes] = {}
    files: dict[str, FileIdentity] = {}
    for name in REQUIRED_PACKAGE_FILES:
        path = root / name
        payload, _stamp = _read_stable_file(
            path,
            label=f"package_root/{name}",
        )
        payloads[name] = payload
        files[name] = FileIdentity(
            name=name,
            size=len(payload),
            sha256=_sha256_bytes(payload),
        )

    # A file read first must still be the same after the other three have been
    # read.  This closes the ordinary "package changes while snapshotting"
    # race without relying on timestamps alone.
    for name in REQUIRED_PACKAGE_FILES:
        reread, _stamp = _read_stable_file(
            root / name,
            label=f"package_root/{name}",
        )
        if reread != payloads[name]:
            raise CompanionPackageError(f"package_root/{name}读取后已漂移")

    config = _parse_utf8_json(payloads["uif_config.json"])
    return CompanionPackageSnapshot(
        root=root,
        payloads=payloads,
        files=files,
        config=config,
        config_bytes=payloads["uif_config.json"],
        package_identity=_package_identity(files),
    )


def _read_u32(data: bytes, offset: int, *, label: str) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as exc:
        raise PEFormatError(f"{label}已截断") from exc


def _read_thunk(image: _PEImage, offset: int) -> int:
    try:
        if image.thunk_size == 4:
            return struct.unpack_from("<I", image.payload, offset)[0]
        return struct.unpack_from("<Q", image.payload, offset)[0]
    except struct.error as exc:
        raise PEFormatError("PE import thunk 已截断") from exc


def parse_pe_imports(payload: bytes) -> tuple[PEImport, ...]:
    """Parse normal PE imports, retaining named and ordinal-only thunks."""

    image = _PEImage.parse(payload)
    import_rva, import_size = image.directory(1)
    if not import_rva or not import_size:
        return ()
    descriptor_offset, descriptor_span = image.rva_span(import_rva)
    if import_size > descriptor_span:
        raise PEFormatError("PE import directory 超出 section raw data")
    descriptor_end = descriptor_offset + import_size
    result: list[PEImport] = []
    for descriptor_index in range(_MAX_IMPORT_DESCRIPTORS):
        descriptor = descriptor_offset + descriptor_index * 20
        if descriptor + 20 > descriptor_end:
            raise PEFormatError("PE import descriptor 已截断")
        try:
            original_thunk, _time, _forwarder, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", image.payload, descriptor
            )
        except struct.error as exc:
            raise PEFormatError("PE import descriptor 已截断") from exc
        if original_thunk == 0 and name_rva == 0 and first_thunk == 0:
            return tuple(result)
        if not name_rva or not (original_thunk or first_thunk):
            raise PEFormatError("PE import descriptor 字段无效")
        raw_dll = image.c_string_rva(name_rva, label="PE import DLL 名称")
        try:
            dll = raw_dll.decode("ascii")
        except UnicodeDecodeError as exc:
            raise PEFormatError("PE import DLL 名称不是 ASCII") from exc
        if not dll:
            raise PEFormatError("PE import DLL 名称为空")
        thunk_rva = original_thunk or first_thunk
        thunk_offset, _thunk_span = image.rva_span(thunk_rva)
        ordinal_mask = 0x80000000 if image.thunk_size == 4 else 0x8000000000000000
        for thunk_index in range(_MAX_IMPORT_THUNKS):
            thunk_offset_current = thunk_offset + thunk_index * image.thunk_size
            value = _read_thunk(image, thunk_offset_current)
            if value == 0:
                break
            if value & ordinal_mask:
                result.append(
                    PEImport(
                        dll=dll,
                        name=None,
                        ordinal=value & 0xFFFF,
                        thunk_index=thunk_index,
                    )
                )
                continue
            name_offset, _name_span = image.rva_span(value)
            if name_offset + 2 > len(image.payload):
                raise PEFormatError("PE import hint/name 已截断")
            raw_name = image.c_string_rva(value + 2, label="PE import 名称")
            try:
                name = raw_name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise PEFormatError("PE import 名称不是 ASCII") from exc
            if not name:
                raise PEFormatError("PE import 名称为空")
            result.append(
                PEImport(
                    dll=dll,
                    name=name,
                    ordinal=None,
                    thunk_index=thunk_index,
                )
            )
        else:
            raise PEFormatError("PE import thunk 数量异常")
    raise PEFormatError("PE import descriptor 数量异常")


def parse_pe_exports(payload: bytes) -> PEExports:
    """Parse a PE export directory and distinguish named/ordinal-only exports."""

    image = _PEImage.parse(payload)
    export_rva, export_size = image.directory(0)
    if not export_rva or not export_size:
        return PEExports(named=(), ordinal_base=0, ordinal_only=())
    export_offset, export_span = image.rva_span(export_rva)
    if export_size > export_span:
        raise PEFormatError("PE export directory 超出 section raw data")
    if export_size < 40:
        raise PEFormatError("PE export directory 已截断")
    try:
        (
            _characteristics,
            _timestamp,
            _major,
            _minor,
            _name_rva,
            ordinal_base,
            function_count,
            name_count,
            functions_rva,
            names_rva,
            name_ordinals_rva,
        ) = struct.unpack_from("<IIHHIIIIIII", image.payload, export_offset)
    except struct.error as exc:
        raise PEFormatError("PE export directory 已截断") from exc
    if function_count > _MAX_EXPORTS or name_count > _MAX_EXPORTS:
        raise PEFormatError("PE export 数量异常")
    if name_count > function_count:
        raise PEFormatError("PE export name 数量超过 function 数量")

    functions: list[int] = []
    if function_count:
        function_offset, function_span = image.rva_span(functions_rva)
        byte_count = function_count * 4
        if byte_count > function_span:
            raise PEFormatError("PE export address table 已截断")
        for index in range(function_count):
            functions.append(_read_u32(image.payload, function_offset + index * 4, label="PE export address"))

    names: list[str] = []
    named_function_indices: set[int] = set()
    if name_count:
        names_offset, names_span = image.rva_span(names_rva)
        ordinals_offset, ordinals_span = image.rva_span(name_ordinals_rva)
        if name_count * 4 > names_span or name_count * 2 > ordinals_span:
            raise PEFormatError("PE export name table 已截断")
        for index in range(name_count):
            name_rva = _read_u32(
                image.payload,
                names_offset + index * 4,
                label="PE export name RVA",
            )
            raw_name = image.c_string_rva(name_rva, label="PE export 名称")
            try:
                name = raw_name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise PEFormatError("PE export 名称不是 ASCII") from exc
            if not name or name in names:
                raise PEFormatError("PE export 名称为空或重复")
            try:
                function_index = struct.unpack_from(
                    "<H", image.payload, ordinals_offset + index * 2
                )[0]
            except struct.error as exc:
                raise PEFormatError("PE export ordinal table 已截断") from exc
            if function_index >= function_count:
                raise PEFormatError("PE export ordinal 指向范围外")
            named_function_indices.add(function_index)
            names.append(name)

    ordinal_only = tuple(
        ordinal_base + index
        for index, address in enumerate(functions)
        if address and index not in named_function_indices
    )
    return PEExports(
        named=tuple(sorted(names)),
        ordinal_base=ordinal_base,
        ordinal_only=ordinal_only,
    )


def inspect_pe_imports(payload: bytes) -> dict[str, Any]:
    imports = parse_pe_imports(payload)
    named_by_dll: dict[str, list[str]] = {}
    for item in imports:
        if item.name is not None:
            named_by_dll.setdefault(item.dll, []).append(item.name)
    return {
        "schema": PE_INSPECTION_SCHEMA,
        "imports": [item.as_dict() for item in imports],
        "named_by_dll": {
            dll: sorted(names)
            for dll, names in sorted(named_by_dll.items(), key=lambda pair: pair[0].casefold())
        },
        "ordinal_only_imports": [
            item.as_dict() for item in imports if item.is_ordinal
        ],
    }


def inspect_pe_exports(payload: bytes) -> dict[str, Any]:
    exports = parse_pe_exports(payload)
    return {
        "schema": PE_INSPECTION_SCHEMA,
        "exports": exports.as_dict(),
    }


def validate_target_proxy_imports(
    target_payload: bytes,
    proxy_winmm_payload: bytes,
) -> dict[str, Any]:
    """Prove the target's named WINMM imports are exported by the proxy."""

    imports = parse_pe_imports(target_payload)
    exports = parse_pe_exports(proxy_winmm_payload)
    winmm_imports = [
        item for item in imports if item.dll.casefold() == _WINMM_NAME
    ]
    if not winmm_imports:
        raise PEFormatError("目标 PE 没有导入 WINMM.dll")
    ordinal_only = [item for item in winmm_imports if item.is_ordinal]
    if ordinal_only:
        raise PEFormatError(
            "目标从 WINMM.dll 使用 ordinal-only 导入，无法建立命名覆盖证明"
        )
    named_winmm = sorted({item.name for item in winmm_imports if item.name is not None})
    missing = sorted(set(named_winmm) - set(exports.named))
    if missing:
        raise PEFormatError(
            "proxy winmm.dll 缺少目标 WINMM 导出: " + ", ".join(missing)
        )
    drawtext_imports = [
        item
        for item in imports
        if item.name == "DrawTextA"
    ]
    if not drawtext_imports:
        raise PEFormatError("目标 PE 没有导入 DrawTextA")
    return {
        "schema": PE_INSPECTION_SCHEMA,
        "all_named_winmm_imports_covered": True,
        "drawtexta_imported": True,
        "winmm_imports": [item.as_dict() for item in winmm_imports],
        "named_winmm_imports": named_winmm,
        "proxy_named_exports": list(exports.named),
        "missing_exports": [],
        "ordinal_only_winmm_imports": [],
        "drawtexta_imports": [item.as_dict() for item in drawtext_imports],
        "proxy_ordinal_only_exports": list(exports.ordinal_only),
    }


def _codec_name(encoding: str) -> str:
    if not isinstance(encoding, str) or not encoding.strip():
        raise TextMappingError("source_encoding 必须是非空编码名")
    try:
        return codecs.lookup(encoding).name
    except LookupError as exc:
        raise TextMappingError(f"不支持的 source_encoding: {encoding}") from exc


def _exact_encode(character: str, encoding: str) -> bytes | None:
    try:
        encoded = character.encode(encoding, errors="strict")
        if encoded.decode(encoding, errors="strict") != character:
            return None
    except (UnicodeEncodeError, UnicodeDecodeError, LookupError):
        return None
    return encoded


def _carrier_class(encoded: bytes, character: str) -> tuple[int, str]:
    category = unicodedata.category(character)
    if category == "Co":
        return 0, "private_use"
    if encoded[0] in range(0xFA, 0xFD):
        return 1, "ibm_extension"
    if encoded[0] in (0x87, 0xED, 0xEE):
        return 2, "vendor_extension"
    return 3, "standard_double_byte"


def _allowed_carrier(character: str) -> bool:
    if len(character) != 1:
        return False
    codepoint = ord(character)
    category = unicodedata.category(character)
    if codepoint <= 0x7F or category in {"Cc", "Cf", "Cs", "Cn"}:
        return False
    if category.startswith("M") or 0xFF61 <= codepoint <= 0xFF9F:
        return False
    if unicodedata.east_asian_width(character) == "H":
        return False
    if character.isspace():
        return False
    # Private-use characters are intentionally allowed: they are not printable
    # according to str.isprintable(), but CP932 maps the selected PUA ranges to
    # stable two-byte values and they are the least likely to occur in HCB text.
    if category != "Co" and not character.isprintable():
        return False
    return True


@dataclass(frozen=True)
class Cp932Carrier:
    character: str
    cp932_bytes: bytes
    priority: int
    kind: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "carrier": self.character,
            "bytes": self.cp932_bytes.hex(" "),
            "priority": self.priority,
            "kind": self.kind,
        }


def _iter_all_cp932_carriers() -> Iterator[Cp932Carrier]:
    lead_bytes = tuple(range(0x81, 0xA0)) + tuple(range(0xE0, 0xFD))
    trail_bytes = tuple(range(0x40, 0x7F)) + tuple(range(0x80, 0xFD))
    for lead in lead_bytes:
        for trail in trail_bytes:
            encoded = bytes((lead, trail))
            try:
                character = encoded.decode(_CP932_ENCODING, errors="strict")
            except UnicodeDecodeError:
                continue
            if len(character) != 1 or _exact_encode(character, _CP932_ENCODING) != encoded:
                continue
            if not _allowed_carrier(character):
                continue
            priority, kind = _carrier_class(encoded, character)
            yield Cp932Carrier(
                character=character,
                cp932_bytes=encoded,
                priority=priority,
                kind=kind,
            )


def enumerate_cp932_double_byte_carriers() -> tuple[Cp932Carrier, ...]:
    """Enumerate every valid, printable/stable CP932 two-byte candidate."""

    candidates = list(_iter_all_cp932_carriers())
    candidates.sort(key=lambda item: (item.priority, item.cp932_bytes))
    return tuple(candidates)


def iter_cp932_double_byte_carriers() -> Iterator[Cp932Carrier]:
    """Yield the deterministic CP932 carrier enumeration."""

    yield from enumerate_cp932_double_byte_carriers()


def _mapping_table_hash(entries: Sequence[Mapping[str, Any]]) -> str:
    projection = [
        {
            "display": str(entry["display"]),
            "carrier": str(entry["carrier"]),
            "bytes": str(entry["bytes"]),
        }
        for entry in entries
    ]
    return _sha256_bytes(_canonical_json_bytes(projection))


def _text_mapping(
    display_texts: Sequence[str],
    source_hcb: bytes,
    source_encoding: str,
) -> dict[str, Any]:
    if not isinstance(source_hcb, bytes):
        raise TextMappingError("source_hcb 必须是 bytes")
    if isinstance(display_texts, (str, bytes)):
        raise TextMappingError("display_texts 必须是字符串序列，而不是单个字符串")
    try:
        texts = tuple(display_texts)
    except TypeError as exc:
        raise TextMappingError("display_texts 必须是可迭代序列") from exc
    if any(not isinstance(text, str) for text in texts):
        raise TextMappingError("display_texts 中每项必须是 str")
    codec = _codec_name(source_encoding)
    direct_characters = set("".join(texts))
    targets: list[str] = []
    for text in texts:
        for character in text:
            if character in targets:
                continue
            if _exact_encode(character, codec) is None:
                targets.append(character)

    all_candidates = enumerate_cp932_double_byte_carriers()
    usable_by_character: dict[str, Cp932Carrier] = {}
    for candidate in all_candidates:
        if candidate.character in direct_characters:
            continue
        # Keep carrierized HCB bytes exact under the declared source codec.  A
        # CP932 extension is therefore available when source_encoding=cp932,
        # while strict shift_jis correctly falls back to other stable DBCS.
        source_bytes = _exact_encode(candidate.character, codec)
        if source_bytes != candidate.cp932_bytes:
            continue
        if source_hcb.count(candidate.cp932_bytes) != 0:
            continue
        usable_by_character.setdefault(candidate.character, candidate)

    selected: list[Cp932Carrier] = []
    for _target in targets:
        if not usable_by_character:
            raise TextMappingError(
                "没有足够的无碰撞 CP932 双字节载体"
            )
        candidate = min(
            usable_by_character.values(),
            key=lambda item: (item.priority, item.cp932_bytes),
        )
        selected.append(candidate)
        del usable_by_character[candidate.character]

    source_chars = "".join(item.character for item in selected)
    target_chars = "".join(targets)
    target_to_carrier = dict(zip(target_chars, source_chars, strict=True))
    carrier_to_target = dict(zip(source_chars, target_chars, strict=True))
    carrierized_texts = [
        "".join(target_to_carrier.get(character, character) for character in text)
        for text in texts
    ]
    round_tripped_texts = [
        "".join(carrier_to_target.get(character, character) for character in text)
        for text in carrierized_texts
    ]
    if round_tripped_texts != list(texts):
        raise TextMappingError("载体到目标字符往返校验失败")

    mapping_entries = [
        {
            "display": target,
            "carrier": carrier.character,
            "bytes": carrier.cp932_bytes.hex(" "),
            "raw_hcb_occurrences": source_hcb.count(carrier.cp932_bytes),
            "direct_display_occurrences": sum(text.count(carrier.character) for text in texts),
        }
        for target, carrier in zip(targets, selected, strict=True)
    ]
    table_hash = _mapping_table_hash(mapping_entries)
    carrierized_bytes: list[bytes] = []
    for text in carrierized_texts:
        encoded = text.encode(codec, errors="strict")
        if encoded.decode(codec, errors="strict") != text:
            raise TextMappingError("载体化文本不能在 source_encoding 下往返")
        carrierized_bytes.append(encoded)
    return {
        "source_encoding": source_encoding,
        "source_codec": codec,
        "carrier_encoding": _CP932_ENCODING,
        "display_texts": list(texts),
        "carrierized_texts": carrierized_texts,
        "carrierized_text_bytes": carrierized_bytes,
        "round_tripped_texts": round_tripped_texts,
        "source_chars": source_chars,
        "target_chars": target_chars,
        "mapping": mapping_entries,
        "mapping_table_hash": table_hash,
        "mapping_table_sha256": table_hash,
        "candidate_space_count": len(all_candidates),
        "usable_candidate_count": len(usable_by_character) + len(selected),
        "source_hcb_size": len(source_hcb),
        "source_hcb_sha256": _sha256_bytes(source_hcb),
        "runtime_roundtrip": True,
    }


def build_text_mapping_candidate(
    display_texts: Sequence[str],
    source_hcb: bytes,
    *,
    source_encoding: str = "shift_jis",
) -> dict[str, Any]:
    """Return the minimal deterministic carrier mapping and audit data."""

    return _text_mapping(display_texts, source_hcb, source_encoding)


def build_uif_config_bytes(
    template_bytes: bytes,
    *,
    source_chars: str,
    target_chars: str,
) -> bytes:
    """Build a strict UTF-8 UIF config scoped to the dialogue renderer.

    UIF hooks every supported ANSI API when ``enabled_apis`` is omitted.  Old
    FVP titles can update their menu labels through ``SetMenuItemInfoA`` using
    flag combinations that are unsafe to pass through UIF's A-to-W wrapper.
    The companion only needs ``DrawTextA`` for carrier substitution, so keep
    unrelated menu/window APIs outside this generated bridge.
    """

    config = _parse_utf8_json(template_bytes)
    if not isinstance(source_chars, str) or not isinstance(target_chars, str):
        raise TextMappingError("UIF source_chars/target_chars 必须是字符串")
    if len(source_chars) != len(target_chars):
        raise TextMappingError("UIF source_chars/target_chars 长度不一致")
    if len(set(source_chars)) != len(source_chars):
        raise TextMappingError("UIF source_chars 载体不唯一")
    if len(set(target_chars)) != len(target_chars):
        raise TextMappingError("UIF target_chars 目标不唯一")
    processor = config.get("text_processor")
    if not isinstance(processor, dict):
        raise CompanionPackageError("UIF 配置缺少 text_processor 对象")
    if processor.get("enable") is not True:
        raise CompanionPackageError("UIF text_processor 未启用")
    if "rules" in processor and not isinstance(processor["rules"], list):
        raise CompanionPackageError("UIF text_processor.rules 不是列表")

    candidate = copy.deepcopy(config)
    candidate_processor = candidate["text_processor"]
    candidate_processor["enabled_apis"] = list(_UIF_DIALOGUE_APIS)
    candidate_processor["conversion_codepage"] = _UIF_CONVERSION_CODEPAGE
    candidate_processor["rules"] = [
        {
            "type": "replace_chars",
            "source_chars": source_chars,
            "target_chars": target_chars,
            "apis": ["DrawTextA"],
        }
    ]
    try:
        encoded = (
            json.dumps(
                candidate,
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise CompanionPackageError("无法生成 UTF-8 UIF 配置") from exc
    # Parse the generated bytes again so a future serializer change cannot
    # silently emit a config that the strict reader would refuse.
    reparsed = _parse_utf8_json(encoded)
    generated_processor = reparsed["text_processor"]
    generated_rules = generated_processor["rules"]
    if len(generated_rules) != 1:
        raise CompanionPackageError("生成的 UIF 规则不是唯一一条")
    rule = generated_rules[0]
    if (
        rule.get("type") != "replace_chars"
        or rule.get("source_chars") != source_chars
        or rule.get("target_chars") != target_chars
        or rule.get("apis") != ["DrawTextA"]
        or generated_processor.get("enabled_apis") != _UIF_DIALOGUE_APIS
        or generated_processor.get("conversion_codepage")
        != _UIF_CONVERSION_CODEPAGE
    ):
        raise CompanionPackageError("生成的 UIF DrawTextA 独占作用域校验失败")
    return encoded


def build_runtime_text_companion_candidate(
    package_root: str | Path,
    target_exe: str | Path,
    display_texts: Sequence[str],
    source_hcb: bytes,
    *,
    source_encoding: str = "shift_jis",
) -> dict[str, Any]:
    """Build a complete pure-memory candidate and its audit report."""

    package = read_companion_package(package_root)
    target_path = _resolve_file(target_exe, label="target_exe")
    target_payload, _target_stamp = _read_stable_file(
        target_path,
        label="target_exe",
    )
    target_identity = {
        "name": target_path.name,
        "size": len(target_payload),
        "sha256": _sha256_bytes(target_payload),
    }
    coverage = validate_target_proxy_imports(
        target_payload,
        package.payloads["winmm.dll"],
    )
    mapping = _text_mapping(display_texts, source_hcb, source_encoding)
    config_bytes = build_uif_config_bytes(
        package.config_bytes,
        source_chars=mapping["source_chars"],
        target_chars=mapping["target_chars"],
    )
    config = _parse_utf8_json(config_bytes)

    candidate_files: dict[str, bytes] = {
        "winmm.dll": package.payloads["winmm.dll"],
        "LoaderDll.dll": package.payloads["LoaderDll.dll"],
        "LocaleEmulator.dll": package.payloads["LocaleEmulator.dll"],
        "uif_config.json": config_bytes,
    }
    candidate_file_map: dict[str, dict[str, Any]] = {}
    for name in REQUIRED_PACKAGE_FILES:
        candidate_payload = candidate_files[name]
        source_identity = package.files[name]
        candidate_file_map[name] = {
            "source": "package",
            "source_name": name,
            "source_size": source_identity.size,
            "source_sha256": source_identity.sha256,
            "size": len(candidate_payload),
            "sha256": _sha256_bytes(candidate_payload),
            "preserved_byte_for_byte": name != "uif_config.json",
        }
    candidate_file_map["uif_config.json"].update(
        {
            "source": "generated_from_package_template",
            "preserved_byte_for_byte": False,
        }
    )
    report: dict[str, Any] = {
        "schema": RUNTIME_TEXT_COMPANION_SCHEMA,
        "read_only_candidate": True,
        "written": False,
        "package_identity": copy.deepcopy(dict(package.package_identity)),
        "target_exe_identity": target_identity,
        "winmm_import_coverage": coverage,
        "mapping_table_hash": mapping["mapping_table_hash"],
        "mapping_table_sha256": mapping["mapping_table_sha256"],
        "source_hcb": {
            "size": mapping["source_hcb_size"],
            "sha256": mapping["source_hcb_sha256"],
        },
        "source_encoding": mapping["source_encoding"],
        "carrier_encoding": mapping["carrier_encoding"],
        "mapping": copy.deepcopy(mapping["mapping"]),
        "display_texts": list(mapping["display_texts"]),
        "carrierized_texts": list(mapping["carrierized_texts"]),
        "round_tripped_texts": list(mapping["round_tripped_texts"]),
        "source_chars": mapping["source_chars"],
        "target_chars": mapping["target_chars"],
        "runtime_roundtrip": mapping["runtime_roundtrip"],
        "config": {
            "name": "uif_config.json",
            "template_sha256": package.files["uif_config.json"].sha256,
            "size": len(config_bytes),
            "sha256": _sha256_bytes(config_bytes),
            "unique_drawtexta_replace_chars_rule": True,
            "enabled_apis": list(_UIF_DIALOGUE_APIS),
            "conversion_codepage": _UIF_CONVERSION_CODEPAGE,
            "non_dialogue_ansi_apis_excluded": True,
        },
        "candidate_files": copy.deepcopy(candidate_file_map),
    }
    return {
        "schema": RUNTIME_TEXT_COMPANION_SCHEMA,
        "package_root": str(package.root),
        "package_identity": copy.deepcopy(dict(package.package_identity)),
        "target_exe_identity": target_identity,
        "candidate_files": candidate_files,
        "candidate_file_map": candidate_file_map,
        "config": config,
        "config_bytes": config_bytes,
        "display_texts": mapping["display_texts"],
        "carrierized_texts": mapping["carrierized_texts"],
        "carrierized_text_bytes": mapping["carrierized_text_bytes"],
        "source_chars": mapping["source_chars"],
        "target_chars": mapping["target_chars"],
        "mapping": mapping["mapping"],
        "report": report,
    }


# Small aliases keep the public vocabulary convenient for callers without
# introducing a second implementation or a game-specific wrapper.
load_companion_package = read_companion_package
build_runtime_text_companion = build_runtime_text_companion_candidate
generate_runtime_text_companion_candidate = build_runtime_text_companion_candidate
validate_pe_import_coverage = validate_target_proxy_imports


__all__ = [
    "CompanionPackageError",
    "CompanionPackageSnapshot",
    "Cp932Carrier",
    "FileIdentity",
    "PEExports",
    "PEFormatError",
    "PEImport",
    "PACKAGE_SNAPSHOT_SCHEMA",
    "REQUIRED_PACKAGE_FILES",
    "RUNTIME_TEXT_COMPANION_SCHEMA",
    "RuntimeTextCompanionError",
    "TextMappingError",
    "build_runtime_text_companion",
    "build_runtime_text_companion_candidate",
    "build_text_mapping_candidate",
    "build_uif_config_bytes",
    "enumerate_cp932_double_byte_carriers",
    "generate_runtime_text_companion_candidate",
    "inspect_pe_exports",
    "inspect_pe_imports",
    "iter_cp932_double_byte_carriers",
    "load_companion_package",
    "parse_pe_exports",
    "parse_pe_imports",
    "read_companion_package",
    "validate_pe_import_coverage",
    "validate_target_proxy_imports",
]
