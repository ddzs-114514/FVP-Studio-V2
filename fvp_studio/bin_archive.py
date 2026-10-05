"""Deterministic reader and additive builder for FVP ``*.bin`` archives.

The V2 portrait/CG pipeline never replaces an existing graph entry.  It
validates every offset, rebuilds only the directory in the Japanese collation
order used by the Windows FVP runtime, preserves the original data tail, and
appends new HZC/NVSG payloads at EOF.  Existing payload bytes are copied
verbatim without materialising a second parsed copy of a multi-gigabyte CG
archive.

This module deliberately works on ``bytes``.  Deciding where a candidate file
may be written belongs to :mod:`hoshimemo_portrait_transaction`.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import functools
import hashlib
import os
from pathlib import Path
import struct
from typing import BinaryIO, Iterable, Mapping
import zlib


JAPANESE_LCID = 0x0411


class BinArchiveError(ValueError):
    """Raised when an archive or HZC payload cannot be rebuilt safely."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _encode_name(name: str) -> bytes:
    if not isinstance(name, str) or not name:
        raise BinArchiveError("BIN 资源名不能为空")
    if "\0" in name:
        raise BinArchiveError(f"BIN 资源名含 NUL: {name!r}")
    try:
        return name.encode("cp932")
    except UnicodeEncodeError as exc:
        raise BinArchiveError(
            f"BIN 资源名不能编码为 Windows 日文 CP932: {name!r}"
        ) from exc


def _windows_japanese_compare(left: bytes, right: bytes) -> int:
    kernel32 = ctypes.windll.kernel32
    result = kernel32.CompareStringA(
        JAPANESE_LCID,
        0,
        left,
        len(left),
        right,
        len(right),
    )
    if result == 0:
        raise ctypes.WinError()
    return int(result) - 2


def japanese_compare(left: bytes, right: bytes) -> int:
    """Compare CP932 names using the runtime's Japanese Windows order.

    Windows is the verified Hoshimemo/FVP target.  A deterministic byte-order
    fallback keeps read-only tooling usable elsewhere, but callers can inspect
    :func:`collation_id` and refuse installable output on an unverified host.
    """

    if os.name == "nt":
        return _windows_japanese_compare(left, right)
    return (left > right) - (left < right)


def collation_id() -> str:
    return "windows-ja-JP-CompareStringA" if os.name == "nt" else "cp932-byte-fallback"


@dataclass(frozen=True)
class BinEntry:
    index: int
    name: str
    name_bytes: bytes
    name_offset: int
    file_offset: int
    file_size: int
    payload: bytes

    @property
    def sha256(self) -> str:
        return _sha256(self.payload)


@dataclass(frozen=True)
class BinArchive:
    entries: tuple[BinEntry, ...]
    names_size: int
    metadata_end: int
    original_bytes: bytes

    def by_name(self) -> dict[str, BinEntry]:
        return {item.name: item for item in self.entries}

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.entries)


@dataclass(frozen=True)
class _BinEntryIndex:
    """Validated BIN directory row without copying its payload."""

    index: int
    name: str
    name_bytes: bytes
    name_offset: int
    file_offset: int
    file_size: int


@dataclass(frozen=True)
class _BinArchiveIndex:
    entries: tuple[_BinEntryIndex, ...]
    names_size: int
    metadata_end: int

    def by_name(self) -> dict[str, _BinEntryIndex]:
        return {item.name: item for item in self.entries}


@dataclass(frozen=True)
class HzcMetadata:
    kind: int
    width: int
    height: int
    offset_x: int
    offset_y: int
    frame_count: int
    raw_length: int
    compressed_length: int

    def to_dict(self) -> dict[str, int]:
        return {
            "kind": self.kind,
            "width": self.width,
            "height": self.height,
            "offset_x": self.offset_x,
            "offset_y": self.offset_y,
            "frame_count": self.frame_count,
            "raw_length": self.raw_length,
            "compressed_length": self.compressed_length,
        }


@dataclass(frozen=True)
class HzcAlphaStorageProbe:
    """Observed BGRA alpha-storage invariants for one 32-bit HZC payload.

    FVP titles do not all store the RGB channels of transparent pixels the
    same way.  A premultiplied payload must satisfy ``B,G,R <= A`` for every
    pixel and must have black RGB when alpha is zero.  Violating either rule
    proves that a byte-for-byte cross-game copy is unsafe for a target which
    expects premultiplied pixels.
    """

    kind: int
    pixel_count: int
    opaque_pixels: int
    partial_alpha_pixels: int
    transparent_pixels: int
    rgb_exceeds_alpha_pixels: int
    transparent_nonzero_rgb_pixels: int
    storage: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "pixel_count": self.pixel_count,
            "opaque_pixels": self.opaque_pixels,
            "partial_alpha_pixels": self.partial_alpha_pixels,
            "transparent_pixels": self.transparent_pixels,
            "rgb_exceeds_alpha_pixels": self.rgb_exceeds_alpha_pixels,
            "transparent_nonzero_rgb_pixels": self.transparent_nonzero_rgb_pixels,
            "storage": self.storage,
            "premultiplied_invariants_hold": (
                self.rgb_exceeds_alpha_pixels == 0
                and self.transparent_nonzero_rgb_pixels == 0
            ),
        }


@dataclass(frozen=True)
class ArchiveAppendResult:
    data: bytes
    added: tuple[Mapping[str, object], ...]
    original_entry_count: int
    final_entry_count: int
    source_was_sorted: bool
    collation: str

    def validation_dict(self) -> dict[str, object]:
        return {
            "original_entry_count": self.original_entry_count,
            "final_entry_count": self.final_entry_count,
            "source_was_sorted": self.source_was_sorted,
            "collation": self.collation,
            "added": [dict(item) for item in self.added],
            "sha256": _sha256(self.data),
        }


@dataclass(frozen=True)
class FileArchiveAppendResult:
    """Audit record for a streamed additive BIN candidate.

    Large FVP audio archives are hundreds of MiB, so the complete candidate
    must never be represented as one ``bytes`` object.  This result keeps only
    the candidate path and streaming fingerprints.
    """

    path: Path
    added: tuple[Mapping[str, object], ...]
    original_entry_count: int
    final_entry_count: int
    source_was_sorted: bool
    collation: str
    source_sha256: str
    output_sha256: str
    source_size: int
    output_size: int
    metadata_delta: int

    def validation_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "original_entry_count": self.original_entry_count,
            "final_entry_count": self.final_entry_count,
            "source_was_sorted": self.source_was_sorted,
            "collation": self.collation,
            "source_sha256": self.source_sha256,
            "output_sha256": self.output_sha256,
            "source_size": self.source_size,
            "output_size": self.output_size,
            "metadata_delta": self.metadata_delta,
            "added": [dict(item) for item in self.added],
        }


def _parse_archive_index(data: bytes) -> _BinArchiveIndex:
    if not isinstance(data, bytes) or len(data) < 8:
        raise BinArchiveError("BIN 文件头被截断")
    count, names_size = struct.unpack_from("<II", data, 0)
    table_start = 8
    table_end = table_start + count * 12
    names_end = table_end + names_size
    if table_end < table_start or names_end < table_end or names_end > len(data):
        raise BinArchiveError("BIN 表或名称区越界")
    names_blob = data[table_end:names_end]
    entries: list[_BinEntryIndex] = []
    seen_names: set[bytes] = set()
    occupied: list[tuple[int, int, int]] = []
    for index in range(count):
        name_offset, file_offset, file_size = struct.unpack_from(
            "<III", data, table_start + index * 12
        )
        if name_offset >= names_size:
            raise BinArchiveError(f"BIN 第 {index} 项名称偏移越界")
        name_end = names_blob.find(b"\0", name_offset)
        if name_end < 0:
            raise BinArchiveError(f"BIN 第 {index} 项名称未终止")
        name_bytes = names_blob[name_offset:name_end]
        if not name_bytes:
            raise BinArchiveError(f"BIN 第 {index} 项名称为空")
        if name_bytes in seen_names:
            raise BinArchiveError(f"BIN 含重复资源名: {name_bytes!r}")
        seen_names.add(name_bytes)
        try:
            name = name_bytes.decode("cp932")
        except UnicodeDecodeError as exc:
            raise BinArchiveError(
                f"BIN 第 {index} 项名称不是 Windows 日文 CP932"
            ) from exc
        file_end = file_offset + file_size
        if file_offset < names_end or file_end < file_offset or file_end > len(data):
            raise BinArchiveError(f"BIN 资源 {name} 的数据范围越界")
        for other_start, other_end, other_index in occupied:
            if file_offset < other_end and other_start < file_end:
                raise BinArchiveError(
                    f"BIN 资源数据重叠: 第 {other_index} 项与第 {index} 项"
                )
        occupied.append((file_offset, file_end, index))
        entries.append(
            _BinEntryIndex(
                index=index,
                name=name,
                name_bytes=name_bytes,
                name_offset=name_offset,
                file_offset=file_offset,
                file_size=file_size,
            )
        )
    return _BinArchiveIndex(tuple(entries), names_size, names_end)


def _read_exact(handle: BinaryIO, size: int, label: str) -> bytes:
    value = handle.read(size)
    if len(value) != size:
        raise BinArchiveError(f"{label}被截断")
    return value


def _parse_archive_file_index(
    path: str | Path,
) -> tuple[_BinArchiveIndex, int, bytes, os.stat_result]:
    """Read and validate only one BIN's directory region from disk."""

    archive_path = Path(path).expanduser().resolve()
    if archive_path.is_symlink() or not archive_path.is_file():
        raise BinArchiveError(f"BIN 文件不存在或不是普通文件: {archive_path}")
    try:
        before = archive_path.stat()
        total_size = int(before.st_size)
        with archive_path.open("rb") as handle:
            header = _read_exact(handle, 8, "BIN 文件头")
            count, names_size = struct.unpack("<II", header)
            table_size = count * 12
            metadata_end = 8 + table_size + names_size
            if metadata_end < 8 or metadata_end > total_size:
                raise BinArchiveError("BIN 表或名称区越界")
            table = _read_exact(handle, table_size, "BIN 目录表")
            names_blob = _read_exact(handle, names_size, "BIN 名称区")
    except BinArchiveError:
        raise
    except OSError as exc:
        raise BinArchiveError(f"无法读取 BIN 目录: {archive_path}") from exc

    entries: list[_BinEntryIndex] = []
    seen_names: set[bytes] = set()
    ranges: list[tuple[int, int, int, str]] = []
    for index in range(count):
        name_offset, file_offset, file_size = struct.unpack_from(
            "<III", table, index * 12
        )
        if name_offset >= names_size:
            raise BinArchiveError(f"BIN 第 {index} 项名称偏移越界")
        name_end = names_blob.find(b"\0", name_offset)
        if name_end < 0:
            raise BinArchiveError(f"BIN 第 {index} 项名称未终止")
        name_bytes = names_blob[name_offset:name_end]
        if not name_bytes:
            raise BinArchiveError(f"BIN 第 {index} 项名称为空")
        if name_bytes in seen_names:
            raise BinArchiveError(f"BIN 含重复资源名: {name_bytes!r}")
        seen_names.add(name_bytes)
        try:
            name = name_bytes.decode("cp932")
        except UnicodeDecodeError as exc:
            raise BinArchiveError(
                f"BIN 第 {index} 项名称不是 Windows 日文 CP932"
            ) from exc
        file_end = file_offset + file_size
        if (
            file_offset < metadata_end
            or file_end < file_offset
            or file_end > total_size
        ):
            raise BinArchiveError(f"BIN 资源 {name} 的数据范围越界")
        ranges.append((file_offset, file_end, index, name))
        entries.append(
            _BinEntryIndex(
                index=index,
                name=name,
                name_bytes=name_bytes,
                name_offset=name_offset,
                file_offset=file_offset,
                file_size=file_size,
            )
        )
    ranges.sort(key=lambda item: (item[0], item[1]))
    for left, right in zip(ranges, ranges[1:]):
        if right[0] < left[1]:
            raise BinArchiveError(
                f"BIN 资源数据重叠: 第 {left[2]} 项 {left[3]} 与"
                f"第 {right[2]} 项 {right[3]}"
            )
    return (
        _BinArchiveIndex(tuple(entries), names_size, metadata_end),
        total_size,
        header + table + names_blob,
        before,
    )


def archive_entry_names_file(path: str | Path) -> tuple[str, ...]:
    """Return a validated on-disk BIN listing without loading its payloads."""

    index, _size, _metadata, _stat = _parse_archive_file_index(path)
    return tuple(item.name for item in index.entries)


def archive_entry_table_file(
    path: str | Path,
) -> tuple[tuple[int, int, str], ...]:
    """Return ``(offset, size, name)`` rows in directory-table order.

    FVP archives address every payload through its explicit directory offset.
    A valid archive therefore does not need payloads to be physically packed in
    the same order as the sorted directory names.  Keeping that distinction is
    important for streamed additive builds, which preserve original payload
    bytes in place and append new payloads at EOF.
    """

    index, _size, _metadata, _stat = _parse_archive_file_index(path)
    return tuple(
        (item.file_offset, item.file_size, item.name)
        for item in index.entries
    )


def archive_directory_identity_file(
    path: str | Path,
) -> tuple[tuple[str, ...], str]:
    """Return validated entry names and the exact BIN directory SHA-256.

    The digest covers the header, offset/size table and encoded name area, but
    does not read or hash multi-gigabyte payloads.
    """

    index, _size, metadata, _stat = _parse_archive_file_index(path)
    return (
        tuple(item.name for item in index.entries),
        hashlib.sha256(metadata).hexdigest(),
    )


def parse_archive(data: bytes) -> BinArchive:
    index = _parse_archive_index(data)
    entries = tuple(
        BinEntry(
            index=item.index,
            name=item.name,
            name_bytes=item.name_bytes,
            name_offset=item.name_offset,
            file_offset=item.file_offset,
            file_size=item.file_size,
            payload=data[item.file_offset : item.file_offset + item.file_size],
        )
        for item in index.entries
    )
    return BinArchive(entries, index.names_size, index.metadata_end, data)


def archive_entry_names(data: bytes) -> tuple[str, ...]:
    """Return a validated directory listing without copying archive payloads."""

    return tuple(item.name for item in _parse_archive_index(data).entries)


def _sorted_entries(entries: Iterable[tuple[str, bytes]]) -> list[tuple[str, bytes, bytes]]:
    encoded = [(name, _encode_name(name), payload) for name, payload in entries]
    encoded.sort(
        key=functools.cmp_to_key(lambda left, right: japanese_compare(left[1], right[1]))
    )
    return encoded


def _is_sorted(entries: Iterable[BinEntry | _BinEntryIndex]) -> bool:
    names = [item.name_bytes for item in entries]
    return all(japanese_compare(left, right) <= 0 for left, right in zip(names, names[1:]))


def build_archive(entries: Iterable[tuple[str, bytes]]) -> bytes:
    ordered = _sorted_entries(entries)
    if not ordered:
        raise BinArchiveError("BIN 至少需要一个资源")
    names = bytearray()
    name_offsets: list[int] = []
    for name, encoded_name, payload in ordered:
        if not isinstance(payload, bytes) or not payload:
            raise BinArchiveError(f"BIN 资源 {name} 必须是非空 bytes")
        name_offsets.append(len(names))
        names.extend(encoded_name)
        names.append(0)
    count = len(ordered)
    header_size = 8 + count * 12 + len(names)
    table = bytearray()
    payloads = bytearray()
    for name_offset, (name, _encoded_name, payload) in zip(name_offsets, ordered):
        file_offset = header_size + len(payloads)
        if file_offset > 0xFFFFFFFF or len(payload) > 0xFFFFFFFF:
            raise BinArchiveError(f"BIN 资源过大: {name}")
        table.extend(struct.pack("<III", name_offset, file_offset, len(payload)))
        payloads.extend(payload)
    return (
        struct.pack("<II", count, len(names))
        + bytes(table)
        + bytes(names)
        + bytes(payloads)
    )


def hzc_metadata(data: bytes, *, validate_pixels: bool = True) -> HzcMetadata:
    if len(data) < 44 or data[:4] != b"hzc1" or data[12:16] != b"NVSG":
        raise BinArchiveError("立绘负载不是 HZC1/NVSG")
    raw_length = struct.unpack_from("<I", data, 4)[0]
    kind = struct.unpack_from("<H", data, 18)[0]
    depths = {
        0: 3,  # single24
        1: 4,  # single32
        2: 4,  # multi32
        3: 1,  # single8 alpha mask
        4: 1,  # single1 alpha mask (one stored byte per pixel in FVP)
    }
    if kind not in depths:
        raise BinArchiveError(f"不支持的 HZC 图层类型: {kind}")
    width, height = struct.unpack_from("<HH", data, 20)
    offset_x, offset_y = struct.unpack_from("<hh", data, 24)
    frame_count = struct.unpack_from("<I", data, 32)[0] if kind == 2 else 1
    if width <= 0 or height <= 0 or frame_count <= 0:
        raise BinArchiveError("HZC 尺寸或帧数无效")
    expected = width * height * depths[kind] * frame_count
    if raw_length != expected:
        raise BinArchiveError(
            f"HZC 原始长度不匹配: 头部 {raw_length}, 按尺寸计算 {expected}"
        )
    if validate_pixels:
        try:
            raw = zlib.decompress(data[44:])
        except zlib.error as exc:
            raise BinArchiveError(f"HZC zlib 数据损坏: {exc}") from exc
        if len(raw) != expected:
            raise BinArchiveError(
                f"HZC 解压长度不匹配: 预期 {expected}, 实际 {len(raw)}"
            )
    return HzcMetadata(
        kind=kind,
        width=width,
        height=height,
        offset_x=offset_x,
        offset_y=offset_y,
        frame_count=frame_count,
        raw_length=raw_length,
        compressed_length=len(data) - 44,
    )


def _hzc_32bit_raw(data: bytes) -> tuple[HzcMetadata, bytes]:
    metadata = hzc_metadata(data, validate_pixels=False)
    if metadata.kind not in {1, 2}:
        raise BinArchiveError(
            f"HZC alpha storage 仅支持 32-bit kind=1/2，实际 kind={metadata.kind}"
        )
    try:
        raw = zlib.decompress(data[44:])
    except zlib.error as exc:
        raise BinArchiveError(f"HZC zlib 数据损坏: {exc}") from exc
    if len(raw) != metadata.raw_length:
        raise BinArchiveError(
            f"HZC 解压长度不匹配: 预期 {metadata.raw_length}, 实际 {len(raw)}"
        )
    return metadata, raw


def _hzc_alpha_probe_from_raw(
    raw: bytes | bytearray,
    *,
    kind: int,
) -> HzcAlphaStorageProbe:
    if len(raw) % 4:
        raise BinArchiveError("32-bit HZC 像素长度不是 4 的倍数")
    opaque = 0
    partial = 0
    transparent = 0
    rgb_exceeds_alpha = 0
    transparent_nonzero_rgb = 0
    view = memoryview(raw)
    for offset in range(0, len(view), 4):
        blue = int(view[offset])
        green = int(view[offset + 1])
        red = int(view[offset + 2])
        alpha = int(view[offset + 3])
        if alpha == 0:
            transparent += 1
            if blue or green or red:
                transparent_nonzero_rgb += 1
        elif alpha == 255:
            opaque += 1
        else:
            partial += 1
        if blue > alpha or green > alpha or red > alpha:
            rgb_exceeds_alpha += 1
    compatible = rgb_exceeds_alpha == 0 and transparent_nonzero_rgb == 0
    return HzcAlphaStorageProbe(
        kind=kind,
        pixel_count=len(view) // 4,
        opaque_pixels=opaque,
        partial_alpha_pixels=partial,
        transparent_pixels=transparent,
        rgb_exceeds_alpha_pixels=rgb_exceeds_alpha,
        transparent_nonzero_rgb_pixels=transparent_nonzero_rgb,
        storage=(
            "premultiplied_compatible"
            if compatible
            else "straight_or_unassociated"
        ),
    )


def probe_hzc_alpha_storage(data: bytes) -> HzcAlphaStorageProbe:
    """Return evidence about one kind=1/2 HZC without changing its bytes."""

    metadata, raw = _hzc_32bit_raw(data)
    return _hzc_alpha_probe_from_raw(raw, kind=metadata.kind)


def convert_hzc_to_premultiplied_alpha(
    data: bytes,
) -> tuple[bytes, Mapping[str, object]]:
    """Return a deterministic premultiplied BGRA HZC and an audit report.

    The 44-byte HZC/NVSG header and geometry are preserved exactly.  RGB is
    multiplied by alpha with integer round-to-nearest; alpha itself is never
    changed.  Already-compatible payloads are returned byte-for-byte so this
    operation is idempotent and does not create needless archive churn.
    """

    metadata, raw = _hzc_32bit_raw(data)
    before = _hzc_alpha_probe_from_raw(raw, kind=metadata.kind)
    if before.storage == "premultiplied_compatible":
        return data, {
            "mode": "already_premultiplied_compatible",
            "changed": False,
            "header_preserved": True,
            "source_sha256": _sha256(data),
            "output_sha256": _sha256(data),
            "source_size": len(data),
            "output_size": len(data),
            "changed_pixels": 0,
            "before": before.to_dict(),
            "after": before.to_dict(),
        }

    converted = bytearray(raw)
    changed_pixels = 0
    for offset in range(0, len(converted), 4):
        alpha = converted[offset + 3]
        changed = False
        for channel in range(3):
            old = converted[offset + channel]
            new = (old * alpha + 127) // 255
            if new != old:
                converted[offset + channel] = new
                changed = True
        if changed:
            changed_pixels += 1
    after = _hzc_alpha_probe_from_raw(converted, kind=metadata.kind)
    if after.storage != "premultiplied_compatible":
        raise BinArchiveError("HZC 预乘透明转换后仍违反 RGB <= A 不变量")
    output = data[:44] + zlib.compress(bytes(converted), level=9)
    output_metadata = hzc_metadata(output)
    if (
        output[:44] != data[:44]
        or output_metadata.kind != metadata.kind
        or output_metadata.width != metadata.width
        or output_metadata.height != metadata.height
        or output_metadata.offset_x != metadata.offset_x
        or output_metadata.offset_y != metadata.offset_y
        or output_metadata.frame_count != metadata.frame_count
        or output_metadata.raw_length != metadata.raw_length
    ):
        raise BinArchiveError("HZC 预乘透明转换改变了头部或几何元数据")
    return output, {
        "mode": "straight_to_premultiplied_bgra",
        "changed": True,
        "header_preserved": True,
        "source_sha256": _sha256(data),
        "output_sha256": _sha256(output),
        "source_size": len(data),
        "output_size": len(output),
        "changed_pixels": changed_pixels,
        "before": before.to_dict(),
        "after": after.to_dict(),
    }


def infer_archive_hzc_alpha_storage(
    source: bytes,
    *,
    max_samples: int = 12,
    exclude_name_prefixes: tuple[str, ...] = ("CHR_FVPV2_",),
) -> Mapping[str, object]:
    """Infer a target archive's 32-bit alpha convention from native entries.

    Only bounded, deterministic samples are inflated.  V2-added names are
    excluded so an earlier cross-game experiment cannot teach the next build
    the wrong target convention.  A premultiplied result requires at least two
    native samples, meaningful transparent/partial-alpha evidence, and zero
    invariant violations; all other cases preserve source bytes.
    """

    if not isinstance(max_samples, int) or max_samples < 1:
        raise BinArchiveError("HZC alpha sample 数量必须是正整数")
    archive = _parse_archive_index(source)
    lowered_prefixes = tuple(value.casefold() for value in exclude_name_prefixes)
    candidates: list[_BinEntryIndex] = []
    for entry in archive.entries:
        if any(entry.name.casefold().startswith(prefix) for prefix in lowered_prefixes):
            continue
        if entry.file_size <= 44:
            continue
        header = source[entry.file_offset : entry.file_offset + 44]
        if len(header) != 44 or header[:4] != b"hzc1" or header[12:16] != b"NVSG":
            continue
        try:
            raw_length = struct.unpack_from("<I", header, 4)[0]
            kind = struct.unpack_from("<H", header, 18)[0]
        except struct.error:
            continue
        if kind not in {1, 2} or raw_length <= 0 or raw_length > 64 * 1024 * 1024:
            continue
        candidates.append(entry)

    if len(candidates) <= max_samples:
        selected = candidates
    elif max_samples == 1:
        selected = [candidates[len(candidates) // 2]]
    else:
        selected_indices = {
            round(index * (len(candidates) - 1) / (max_samples - 1))
            for index in range(max_samples)
        }
        selected = [candidates[index] for index in sorted(selected_indices)]

    samples: list[dict[str, object]] = []
    total_evidence_pixels = 0
    total_rgb_exceeds_alpha = 0
    total_transparent_nonzero = 0
    for entry in selected:
        payload = source[
            entry.file_offset : entry.file_offset + entry.file_size
        ]
        try:
            probe = probe_hzc_alpha_storage(payload)
        except BinArchiveError:
            continue
        total_evidence_pixels += (
            probe.partial_alpha_pixels + probe.transparent_pixels
        )
        total_rgb_exceeds_alpha += probe.rgb_exceeds_alpha_pixels
        total_transparent_nonzero += probe.transparent_nonzero_rgb_pixels
        samples.append(
            {
                "entry_index": entry.index,
                "name": entry.name,
                "size": entry.file_size,
                "sha256": _sha256(payload),
                **probe.to_dict(),
            }
        )

    premultiplied = (
        len(samples) >= 2
        and total_evidence_pixels >= 256
        and total_rgb_exceeds_alpha == 0
        and total_transparent_nonzero == 0
    )
    storage = "premultiplied" if premultiplied else (
        "straight_or_mixed"
        if total_rgb_exceeds_alpha or total_transparent_nonzero
        else "unknown"
    )
    return {
        "schema": "fvp-studio-v2.hzc-alpha-storage.v1",
        "storage": storage,
        "sample_count": len(samples),
        "candidate_count": len(candidates),
        "max_samples": max_samples,
        "evidence_alpha_pixels": total_evidence_pixels,
        "rgb_exceeds_alpha_pixels": total_rgb_exceeds_alpha,
        "transparent_nonzero_rgb_pixels": total_transparent_nonzero,
        "excluded_name_prefixes": list(exclude_name_prefixes),
        "samples": samples,
        "conversion_policy": (
            "normalize_imported_kind1_kind2_to_premultiplied"
            if premultiplied
            else "preserve_source_payload"
        ),
    }


def append_hzc_entries(
    source: bytes,
    additions: Mapping[str, bytes],
    *,
    require_source_sorted: bool = True,
) -> ArchiveAppendResult:
    """Append new HZC entries without replacing any existing resource."""

    archive = _parse_archive_index(source)
    source_sorted = _is_sorted(archive.entries)
    if require_source_sorted and not source_sorted:
        raise BinArchiveError("源 BIN 不是已确认的日文排序，拒绝生成安装候选")
    if not additions:
        raise BinArchiveError("没有待追加的 HZC 资源")
    existing = archive.by_name()
    details: list[Mapping[str, object]] = []
    addition_payloads: dict[str, bytes] = {}
    for name in sorted(additions, key=lambda value: _encode_name(value)):
        payload = additions[name]
        if name in existing:
            raise BinArchiveError(f"禁止覆盖已有 BIN 资源: {name}")
        metadata = hzc_metadata(payload)
        addition_payloads[name] = payload
        details.append(
            {
                "name": name,
                "sha256": _sha256(payload),
                "size": len(payload),
                "hzc": metadata.to_dict(),
            }
        )

    # Real graph_vis archives can be close to 2 GiB.  Rebuilding them through
    # ``parse_archive`` + ``build_archive`` copied every old payload several
    # times.  The directory is the only part that must be rebuilt: retain the
    # complete old data tail byte-for-byte, shift its offsets by the metadata
    # delta, and append only the new payloads at EOF.
    ordered: list[tuple[str, bytes, _BinEntryIndex | None, bytes | None]] = [
        (item.name, item.name_bytes, item, None) for item in archive.entries
    ]
    ordered.extend(
        (name, _encode_name(name), None, payload)
        for name, payload in addition_payloads.items()
    )
    ordered.sort(
        key=functools.cmp_to_key(
            lambda left, right: japanese_compare(left[1], right[1])
        )
    )
    names = bytearray()
    name_offsets: list[int] = []
    for _name, encoded_name, _source_item, _payload in ordered:
        name_offsets.append(len(names))
        names.extend(encoded_name)
        names.append(0)
    count = len(ordered)
    metadata_end = 8 + count * 12 + len(names)
    metadata_delta = metadata_end - archive.metadata_end
    if metadata_delta <= 0:
        raise BinArchiveError("BIN 追加后的目录没有增长")
    source_tail_size = len(source) - archive.metadata_end
    additions_size = sum(len(payload) for payload in addition_payloads.values())
    output_size = metadata_end + source_tail_size + additions_size
    if output_size > 0xFFFFFFFF:
        raise BinArchiveError("BIN 追加后超过 32-bit 归档上限")

    output_buffer = bytearray(output_size)
    struct.pack_into("<II", output_buffer, 0, count, len(names))
    output_buffer[8 + count * 12 : metadata_end] = names
    source_view = memoryview(source)
    output_view = memoryview(output_buffer)
    shifted_tail_end = metadata_end + source_tail_size
    output_view[metadata_end:shifted_tail_end] = source_view[archive.metadata_end:]
    next_added_offset = shifted_tail_end
    added_offsets: dict[str, tuple[int, int]] = {}
    for table_index, (name, _encoded_name, source_item, payload) in enumerate(ordered):
        if source_item is not None:
            file_offset = source_item.file_offset + metadata_delta
            file_size = source_item.file_size
        else:
            assert payload is not None
            file_offset = next_added_offset
            file_size = len(payload)
            file_end = file_offset + file_size
            output_view[file_offset:file_end] = memoryview(payload)
            added_offsets[name] = (file_offset, file_size)
            next_added_offset = file_end
        struct.pack_into(
            "<III",
            output_buffer,
            8 + table_index * 12,
            name_offsets[table_index],
            file_offset,
            file_size,
        )
    if next_added_offset != output_size:
        raise BinArchiveError("BIN 追加后的负载长度不一致")
    del output_view, source_view
    output = bytes(output_buffer)
    del output_buffer

    reparsed = _parse_archive_index(output)
    if not _is_sorted(reparsed.entries):
        raise BinArchiveError("重建后的 BIN 未保持日文排序")
    reparsed_by_name = reparsed.by_name()
    source_view = memoryview(source)
    output_view = memoryview(output)
    for item in archive.entries:
        after = reparsed_by_name.get(item.name)
        if (
            after is None
            or after.file_size != item.file_size
            or output_view[after.file_offset : after.file_offset + after.file_size]
            != source_view[item.file_offset : item.file_offset + item.file_size]
        ):
            raise BinArchiveError(f"重建改变了原资源负载: {item.name}")
    for name, payload in addition_payloads.items():
        after = reparsed_by_name.get(name)
        expected_offset, expected_size = added_offsets[name]
        if (
            after is None
            or after.file_offset != expected_offset
            or after.file_size != expected_size
            or output_view[after.file_offset : after.file_offset + after.file_size]
            != memoryview(payload)
        ):
            raise BinArchiveError(f"新增资源负载不一致: {name}")
    del output_view, source_view
    return ArchiveAppendResult(
        data=output,
        added=tuple(details),
        original_entry_count=len(archive.entries),
        final_entry_count=len(reparsed.entries),
        source_was_sorted=source_sorted,
        collation=collation_id(),
    )


def _sha256_file_region(path: Path, offset: int, size: int, chunk_size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    try:
        with path.open("rb") as handle:
            handle.seek(offset)
            while remaining:
                block = handle.read(min(chunk_size, remaining))
                if not block:
                    raise BinArchiveError(
                        f"BIN 候选负载读取不完整: {path.name} @ {offset}"
                    )
                digest.update(block)
                remaining -= len(block)
    except BinArchiveError:
        raise
    except OSError as exc:
        raise BinArchiveError(f"无法复检 BIN 候选负载: {path}") from exc
    return digest.hexdigest()


def append_entries_file(
    source_path: str | Path,
    output_path: str | Path,
    additions: Mapping[
        str,
        bytes | bytearray | memoryview | str | Path,
    ],
    *,
    require_source_sorted: bool = True,
    chunk_size: int = 1024 * 1024,
) -> FileArchiveAppendResult:
    """Stream an additive BIN candidate to a new file.

    The source directory is rebuilt, every existing payload is copied exactly
    once, and new payloads are appended at EOF.  Existing names are never
    replaced.  ``output_path`` must not exist, which keeps candidate creation
    separate from the transactional installer.
    """

    if not isinstance(additions, Mapping) or not additions:
        raise BinArchiveError("没有待追加的 BIN 资源")
    try:
        chunk_size = int(chunk_size)
    except (TypeError, ValueError) as exc:
        raise BinArchiveError("BIN 流式复制块大小必须是整数") from exc
    if chunk_size < 64 * 1024 or chunk_size > 16 * 1024 * 1024:
        raise BinArchiveError("BIN 流式复制块大小必须在 64 KiB 到 16 MiB 之间")

    raw_source = Path(source_path).expanduser()
    if raw_source.is_symlink():
        raise BinArchiveError(f"源 BIN 是符号链接，拒绝生成候选: {raw_source}")
    source = raw_source.resolve()
    raw_output = Path(output_path).expanduser()
    output = raw_output.resolve()
    if output == source:
        raise BinArchiveError("BIN 候选输出不能覆盖源归档")
    if raw_output.exists() or raw_output.is_symlink():
        raise BinArchiveError(f"BIN 候选输出已存在: {raw_output}")
    if not output.parent.is_dir():
        raise BinArchiveError(f"BIN 候选输出目录不存在: {output.parent}")

    archive, source_size, source_metadata, source_stat = _parse_archive_file_index(
        source
    )
    source_sorted = _is_sorted(archive.entries)
    if require_source_sorted and not source_sorted:
        raise BinArchiveError("源 BIN 不是已确认的日文排序，拒绝生成安装候选")
    existing = archive.by_name()

    prepared: list[
        tuple[str, bytes, bytes | None, Path | None, int]
    ] = []
    for raw_name, raw_payload in additions.items():
        name = str(raw_name)
        encoded_name = _encode_name(name)
        if name in existing:
            raise BinArchiveError(f"禁止覆盖已有 BIN 资源: {name}")
        if isinstance(raw_payload, bytes):
            payload_bytes: bytes | None = raw_payload
            payload_path: Path | None = None
            payload_size = len(raw_payload)
        elif isinstance(raw_payload, (bytearray, memoryview)):
            payload_bytes = bytes(raw_payload)
            payload_path = None
            payload_size = len(payload_bytes)
        elif isinstance(raw_payload, (str, Path)):
            raw_path = Path(raw_payload).expanduser()
            if raw_path.is_symlink():
                raise BinArchiveError(
                    f"新增 BIN 资源 {name} 的负载是符号链接"
                )
            payload_path = raw_path.resolve()
            if not payload_path.is_file():
                raise BinArchiveError(
                    f"新增 BIN 资源 {name} 的负载文件不存在: {payload_path}"
                )
            if payload_path in {source, output}:
                raise BinArchiveError(
                    f"新增 BIN 资源 {name} 的负载路径与归档冲突"
                )
            payload_bytes = None
            try:
                payload_size = int(payload_path.stat().st_size)
            except OSError as exc:
                raise BinArchiveError(
                    f"无法读取新增 BIN 资源 {name} 的负载大小"
                ) from exc
        else:
            raise BinArchiveError(
                f"新增 BIN 资源 {name} 必须是 bytes 或普通文件路径"
            )
        if payload_size <= 0:
            raise BinArchiveError(f"新增 BIN 资源 {name} 不能为空")
        if payload_size > 0xFFFFFFFF:
            raise BinArchiveError(f"新增 BIN 资源过大: {name}")
        prepared.append(
            (name, encoded_name, payload_bytes, payload_path, payload_size)
        )

    ordered: list[
        tuple[
            str,
            bytes,
            _BinEntryIndex | None,
            tuple[str, bytes, bytes | None, Path | None, int] | None,
        ]
    ] = [
        (item.name, item.name_bytes, item, None) for item in archive.entries
    ]
    ordered.extend((item[0], item[1], None, item) for item in prepared)
    ordered.sort(
        key=functools.cmp_to_key(
            lambda left, right: japanese_compare(left[1], right[1])
        )
    )

    names = bytearray()
    name_offsets: list[int] = []
    for _name, encoded_name, _source_item, _addition in ordered:
        name_offsets.append(len(names))
        names.extend(encoded_name)
        names.append(0)
    count = len(ordered)
    metadata_end = 8 + count * 12 + len(names)
    metadata_delta = metadata_end - archive.metadata_end
    if metadata_delta <= 0:
        raise BinArchiveError("BIN 追加后的目录没有增长")
    source_tail_size = source_size - archive.metadata_end
    additions_size = sum(item[4] for item in prepared)
    output_size = metadata_end + source_tail_size + additions_size
    if output_size > 0xFFFFFFFF:
        raise BinArchiveError("BIN 追加后超过 32-bit 归档上限")

    metadata = bytearray(metadata_end)
    struct.pack_into("<II", metadata, 0, count, len(names))
    metadata[8 + count * 12 : metadata_end] = names
    next_added_offset = metadata_end + source_tail_size
    added_offsets: dict[str, tuple[int, int]] = {}
    for table_index, (name, _encoded_name, source_item, addition) in enumerate(
        ordered
    ):
        if source_item is not None:
            file_offset = source_item.file_offset + metadata_delta
            file_size = source_item.file_size
        else:
            assert addition is not None
            file_offset = next_added_offset
            file_size = addition[4]
            added_offsets[name] = (file_offset, file_size)
            next_added_offset += file_size
        struct.pack_into(
            "<III",
            metadata,
            8 + table_index * 12,
            name_offsets[table_index],
            file_offset,
            file_size,
        )
    if next_added_offset != output_size:
        raise BinArchiveError("BIN 追加后的负载长度不一致")

    source_digest = hashlib.sha256(source_metadata)
    output_digest = hashlib.sha256(metadata)
    detail_by_name: dict[str, dict[str, object]] = {}
    try:
        with source.open("rb") as source_handle, output.open("xb") as output_handle:
            output_handle.write(metadata)
            source_handle.seek(archive.metadata_end)
            remaining = source_tail_size
            while remaining:
                block = source_handle.read(min(chunk_size, remaining))
                if not block:
                    raise BinArchiveError("源 BIN 数据尾读取不完整")
                source_digest.update(block)
                output_handle.write(block)
                output_digest.update(block)
                remaining -= len(block)

            for name, _encoded_name, payload_bytes, payload_path, payload_size in prepared:
                payload_digest = hashlib.sha256()
                if payload_bytes is not None:
                    view = memoryview(payload_bytes)
                    cursor = 0
                    while cursor < payload_size:
                        block = view[cursor : cursor + chunk_size]
                        output_handle.write(block)
                        output_digest.update(block)
                        payload_digest.update(block)
                        cursor += len(block)
                else:
                    assert payload_path is not None
                    with payload_path.open("rb") as payload_handle:
                        remaining = payload_size
                        while remaining:
                            block = payload_handle.read(min(chunk_size, remaining))
                            if not block:
                                raise BinArchiveError(
                                    f"新增 BIN 资源 {name} 的负载读取不完整"
                                )
                            output_handle.write(block)
                            output_digest.update(block)
                            payload_digest.update(block)
                            remaining -= len(block)
                detail_by_name[name] = {
                    "name": name,
                    "sha256": payload_digest.hexdigest(),
                    "size": payload_size,
                    "file_offset": added_offsets[name][0],
                    "source": str(payload_path) if payload_path is not None else "memory",
                }
            output_handle.flush()
            os.fsync(output_handle.fileno())
    except Exception:
        try:
            output.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    try:
        after_source = source.stat()
    except OSError as exc:
        raise BinArchiveError("源 BIN 在候选生成后无法复检") from exc
    if (
        int(after_source.st_size) != int(source_stat.st_size)
        or int(after_source.st_mtime_ns) != int(source_stat.st_mtime_ns)
        or int(after_source.st_ctime_ns) != int(source_stat.st_ctime_ns)
    ):
        raise BinArchiveError("源 BIN 在候选生成期间发生变化")
    if int(output.stat().st_size) != output_size:
        raise BinArchiveError("流式 BIN 候选最终大小不一致")

    reparsed, reparsed_size, _reparsed_metadata, _reparsed_stat = (
        _parse_archive_file_index(output)
    )
    if reparsed_size != output_size or not _is_sorted(reparsed.entries):
        raise BinArchiveError("流式 BIN 候选目录或日文排序复检失败")
    reparsed_by_name = reparsed.by_name()
    for item in archive.entries:
        after = reparsed_by_name.get(item.name)
        if (
            after is None
            or after.file_offset != item.file_offset + metadata_delta
            or after.file_size != item.file_size
        ):
            raise BinArchiveError(f"流式重建改变了原资源目录记录: {item.name}")
    for name, expected in added_offsets.items():
        after = reparsed_by_name.get(name)
        if (
            after is None
            or (after.file_offset, after.file_size) != expected
            or _sha256_file_region(
                output,
                after.file_offset,
                after.file_size,
                chunk_size,
            )
            != detail_by_name[name]["sha256"]
        ):
            raise BinArchiveError(f"新增资源负载复检失败: {name}")

    details = tuple(detail_by_name[item[0]] for item in prepared)
    return FileArchiveAppendResult(
        path=output,
        added=details,
        original_entry_count=len(archive.entries),
        final_entry_count=len(reparsed.entries),
        source_was_sorted=source_sorted,
        collation=collation_id(),
        source_sha256=source_digest.hexdigest(),
        output_sha256=output_digest.hexdigest(),
        source_size=source_size,
        output_size=output_size,
        metadata_delta=metadata_delta,
    )
