"""Safe visual/audio BIN patch builder for FVP Studio.

This adapter reuses the workspace's proven HZC1/NVSG codec and stream BIN
rebuilder.  Originals are read-only; every build writes a new archive under a
chosen output directory.  A PNG replacement is resized to the template's
dimensions and encoded with the template's pixel/container metadata.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
from functools import lru_cache
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import struct
from datetime import datetime
from typing import Any
import zlib

from PIL import Image, ImageOps

from .profile import adapter_root_dir


class ResourceBuildError(ValueError):
    pass


# A small profile-backed compatibility table is used only when the original
# expression container is intentionally all-transparent and therefore carries
# no pixels from which its draw rectangle can be inferred.  Other portraits
# are discovered from their actual frame-zero/body pixels.  The UI also exposes
# manual offsets as a safe fallback for future games.
_KNOWN_FACE_OFFSETS: dict[str, tuple[int, int]] = {
    "CHR_夢_幼少L_表情": (900, 194),
}


# Hoshimemo's backlog avatar is independent from graph_bs.  ``bl_char`` is a
# fixed 10x5 atlas whose cells contain dim/selected pairs.  Unknown mappings
# are deliberately ignored instead of guessing coordinates in another game.
_HOSHIMEMO_LOG_AVATAR_MAPPINGS: tuple[dict[str, Any], ...] = (
    {
        "mapping_id": "hoshimemo.yume_adult_to_child",
        "archive": "graph.bin",
        "entry_index": 216,
        "resource_name": "bl_char",
        "atlas_size": (1900, 950),
        "cell_size": (190, 190),
        "source_cells": ((380, 190), (570, 190)),
        "target_cells": ((1140, 760), (1330, 760)),
    },
)


def _plan_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise ResourceBuildError("sync_log_avatar 必须是布尔值")


def _resolve_log_avatar_mapping(specification: dict[str, Any]) -> dict[str, Any] | None:
    if not _plan_bool(specification.get("sync_log_avatar"), True):
        return None
    source_name = str(specification.get("source_body_name", ""))
    target_name = str(specification.get("target_body_name", ""))
    if (
        source_name.startswith("CHR_夢_")
        and "幼少" not in source_name
        and target_name.startswith("CHR_夢_幼少")
    ):
        return dict(_HOSHIMEMO_LOG_AVATAR_MAPPINGS[0])
    return None


def _safe_child(root: Path, relative_name: str, label: str) -> Path:
    """Resolve a plan archive while keeping it inside the project directory."""

    root = root.expanduser().resolve()
    candidate = (root / relative_name).resolve()
    if candidate != root and not candidate.is_relative_to(root):
        raise ResourceBuildError(f"{label} 不能跳出项目目录: {relative_name}")
    return candidate


def _audio_info(data: bytes, archive: Path, entry_index: int) -> dict[str, Any]:
    """Return a browser-friendly description for a raw audio BIN entry."""

    if data.startswith(b"OggS"):
        mime = "audio/ogg"
        format_name = "ogg"
    elif data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WAVE":
        mime = "audio/wav"
        format_name = "wav"
    elif data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0):
        mime = "audio/mpeg"
        format_name = "mp3"
    elif data.startswith(b"fLaC"):
        mime = "audio/flac"
        format_name = "flac"
    else:
        raise ResourceBuildError(
            f"归档条目不是可识别的 OGG/WAV/MP3/FLAC 音频: {archive.name}#{entry_index}"
        )
    return {
        "archive": str(archive),
        "entry_index": int(entry_index),
        "size": len(data),
        "mime": mime,
        "format": format_name,
    }


def preview_audio_entry(archive: Path, entry_index: int) -> tuple[bytes, dict[str, Any]]:
    """Read one raw audio entry for the local UI without modifying the archive."""

    archive = archive.expanduser().resolve()
    if not archive.is_file():
        raise ResourceBuildError(f"原始 BIN 不存在: {archive}")
    stat = archive.stat()
    entries = _cached_bin_entry_table(
        str(archive),
        int(stat.st_size),
        int(stat.st_mtime_ns),
    )
    index = int(entry_index)
    if not 0 <= index < len(entries):
        raise ResourceBuildError(f"entry_index 超出范围: {index}")
    offset, size, _source_name = entries[index]
    # Avoid accidentally turning the local preview endpoint into a large-file
    # copier for a non-audio archive entry.
    if size > 128 * 1024 * 1024:
        raise ResourceBuildError(f"音频条目过大，拒绝预览: {size} bytes")
    with archive.open("rb") as source:
        source.seek(offset)
        data = source.read(size)
    return data, _audio_info(data, archive, index)


def _unpremul(value: int, alpha: int) -> int:
    return 0 if alpha == 0 else min(255, (value * 255 + alpha // 2) // alpha)


def inspect_bin_entry(archive: Path, entry_index: int) -> dict[str, Any]:
    """Read authoritative HZC metadata from the active BIN archive."""

    archive = archive.expanduser().resolve()
    if not archive.is_file():
        raise ResourceBuildError(f"原始 BIN 不存在: {archive}")
    stat = archive.stat()
    entries = _cached_bin_entry_table(
        str(archive),
        int(stat.st_size),
        int(stat.st_mtime_ns),
    )
    index = int(entry_index)
    if not 0 <= index < len(entries):
        raise ResourceBuildError(f"entry_index 超出范围: {index}")
    offset, size, _source_name = entries[index]
    with archive.open("rb") as source:
        source.seek(offset)
        header = source.read(min(size, 44))
    codec = _adapter_module("hzc_template_codec")
    info = codec.metadata(header)
    return {
        # Keep the logical archive name owned by the UI intact.  Returning an
        # ``archive`` field here would overwrite ``graph_bs.bin`` with an
        # absolute path when metadata is merged into the selected asset, and
        # the preview endpoint deliberately rejects such paths.
        "archive_path": str(archive),
        "entry_index": index,
        "entry_size": size,
        **{key: info[key] for key in ("kind", "type", "width", "height", "frame_count")},
    }


def _scan_hzc_archive_uncached(archive: Path) -> dict[str, Any]:
    codec = _adapter_module("hzc_template_codec")
    stat = archive.stat()
    entries = _cached_bin_entry_table(
        str(archive),
        int(stat.st_size),
        int(stat.st_mtime_ns),
    )
    visuals: list[dict[str, Any]] = []
    skipped = 0
    with archive.open("rb") as source:
        if entries:
            source.seek(entries[0][0])
        for index, (entry_offset, entry_size, source_name) in enumerate(entries):
            try:
                entry_offset = int(entry_offset)
                entry_size = int(entry_size)
                if entry_size < 0:
                    raise ValueError("entry size must be non-negative")
                # Directory names are sorted, but additive archives may keep
                # original payloads in their old physical order and append new
                # data at EOF.  Follow each validated explicit offset while
                # still reusing one file handle for nearby entries.
                if source.tell() != entry_offset:
                    source.seek(entry_offset)
                header = source.read(min(entry_size, 44))
                remaining = entry_size - len(header)
                if remaining <= 16:
                    remainder = source.read(remaining)
                    tail = (header + remainder)[-16:]
                else:
                    source.seek(remaining - 16, os.SEEK_CUR)
                    tail = source.read(16)
                if source.tell() != entry_offset + entry_size:
                    raise ValueError("entry probe did not end at payload boundary")
                info = codec.metadata(header)
                frame_count = int(info["frame_count"])
                if frame_count < 1:
                    raise ValueError("frame_count must be positive")
                visuals.append(
                    {
                        "entry_index": index,
                        "entry_size": entry_size,
                        "payload_probe_sha256": _hzc_payload_probe_from_parts(
                            entry_size,
                            header,
                            tail,
                        ),
                        "kind": int(info["kind"]),
                        # The proven codec reports names such as ``single32``
                        # and ``multi32`` for real game archives.  Preserve
                        # that semantic value instead of coercing it to int.
                        "type": str(info["type"]),
                        "width": int(info["width"]),
                        "height": int(info["height"]),
                        "frame_count": frame_count,
                        "role": "expression" if frame_count > 1 else "body",
                        "source_name": source_name,
                        "label": source_name or f"entry #{index}",
                    }
                )
            except (KeyError, TypeError, ValueError, OSError, zlib.error):
                skipped += 1
    return {
        "archive_path": str(archive),
        "archive_name": archive.name,
        "entry_count": len(entries),
        "visual_count": len(visuals),
        "skipped_count": skipped,
        "entries": visuals,
    }


@lru_cache(maxsize=8)
def _cached_hzc_archive_scan(
    archive_path: str,
    file_size: int,
    modified_ns: int,
    created_ns: int,
) -> dict[str, Any]:
    """Cache metadata-only scans by path and a lightweight file fingerprint."""

    del file_size, modified_ns, created_ns
    return _scan_hzc_archive_uncached(Path(archive_path))


def scan_hzc_archive(archive: Path) -> dict[str, Any]:
    """Scan an FVP visual BIN without decoding every frame.

    Cross-game portrait import intentionally treats the source game as
    read-only.  Reading only each entry's 44-byte HZC header gives the UI
    authoritative dimensions and frame counts.  Results are reused when a
    user switches away from a source game and back; callers receive a deep
    copy so the browser/session cannot mutate the cached scan.
    """

    archive = archive.expanduser().resolve()
    if not archive.is_file():
        raise ResourceBuildError(f"原始 BIN 不存在: {archive}")
    file_stat = archive.stat()
    result = _cached_hzc_archive_scan(
        str(archive),
        int(file_stat.st_size),
        int(file_stat.st_mtime_ns),
        int(file_stat.st_ctime_ns),
    )
    return copy.deepcopy(result)


def preview_bin_entry(
    archive: Path,
    entry_index: int,
    frame: int = 0,
    max_dimension: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Decode one BIN/HZC visual entry into a PNG preview in memory.

    ``max_dimension`` is used by the asset browser's lazy thumbnails.  The
    archive entry is still decoded exactly as before; only the returned PNG is
    reduced, so selecting an item in the inspector remains full resolution.
    """

    archive = archive.expanduser().resolve()
    if not archive.is_file():
        raise ResourceBuildError(f"原始 BIN 不存在: {archive}")
    index = int(entry_index)
    archive_stat = archive.stat()
    rgba, frozen_info = _cached_hzc_frame_rgba(
        str(archive),
        int(archive_stat.st_size),
        int(archive_stat.st_mtime_ns),
        index,
        int(frame),
    )
    info = _thaw_hzc_info(frozen_info)
    frame_count = int(info["frame_count"])
    frame_index = int(frame)
    if not 0 <= frame_index < frame_count:
        raise ResourceBuildError(f"frame 超出范围: {frame_index}")
    width = int(info["width"])
    height = int(info["height"])
    image = Image.frombytes("RGBA", (width, height), rgba)
    original_width, original_height = width, height
    preview_width, preview_height = width, height
    if max_dimension is not None and int(max_dimension) > 0:
        limit = int(max_dimension)
        image.thumbnail((limit, limit), Image.Resampling.LANCZOS)
        preview_width, preview_height = image.size
    output = BytesIO()
    image.save(output, "PNG")
    return output.getvalue(), {
        "archive": str(archive),
        "entry_index": index,
        "frame": frame_index,
        **{key: info[key] for key in ("type", "width", "height", "frame_count")},
        "preview_width": preview_width,
        "preview_height": preview_height,
        "original_width": original_width,
        "original_height": original_height,
    }


def preview_bin_entry_crop(
    archive: Path,
    entry_index: int,
    *,
    left: int,
    top: int,
    width: int,
    height: int,
    frame: int = 0,
) -> tuple[bytes, dict[str, Any]]:
    """Return one exact PNG crop without re-decoding the cached HZC frame.

    Story-stage B.LOG preview uses a single 190x190 avatar from a much larger
    atlas.  Returning only that cell avoids sending and painting the 1900x950
    source every time the user moves to the previous or next line.
    """

    archive = archive.expanduser().resolve()
    if not archive.is_file():
        raise ResourceBuildError(f"原始 BIN 不存在: {archive}")
    index = int(entry_index)
    frame_index = int(frame)
    crop_left = int(left)
    crop_top = int(top)
    crop_width = int(width)
    crop_height = int(height)
    if crop_left < 0 or crop_top < 0 or crop_width <= 0 or crop_height <= 0:
        raise ResourceBuildError("预览裁剪范围无效")

    archive_stat = archive.stat()
    rgba, frozen_info = _cached_hzc_frame_rgba(
        str(archive),
        int(archive_stat.st_size),
        int(archive_stat.st_mtime_ns),
        index,
        frame_index,
    )
    info = _thaw_hzc_info(frozen_info)
    frame_count = int(info["frame_count"])
    if not 0 <= frame_index < frame_count:
        raise ResourceBuildError(f"frame 超出范围: {frame_index}")
    source_width = int(info["width"])
    source_height = int(info["height"])
    right = crop_left + crop_width
    bottom = crop_top + crop_height
    if right > source_width or bottom > source_height:
        raise ResourceBuildError(
            f"预览裁剪超出图像范围: ({crop_left}, {crop_top}, {right}, {bottom}) / "
            f"{source_width}x{source_height}"
        )
    image = Image.frombytes("RGBA", (source_width, source_height), rgba)
    output = BytesIO()
    image.crop((crop_left, crop_top, right, bottom)).save(output, "PNG")
    return output.getvalue(), {
        "archive": str(archive),
        "entry_index": index,
        "frame": frame_index,
        **{key: info[key] for key in ("type", "width", "height", "frame_count")},
        "original_width": source_width,
        "original_height": source_height,
        "crop": {
            "left": crop_left,
            "top": crop_top,
            "width": crop_width,
            "height": crop_height,
        },
    }


_HZC_INFO_KEYS = ("type", "width", "height", "frame_count", "kind")


def _freeze_hzc_info(info: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(info[key] for key in _HZC_INFO_KEYS)


def _thaw_hzc_info(info: tuple[Any, ...]) -> dict[str, Any]:
    return dict(zip(_HZC_INFO_KEYS, info, strict=True))


@lru_cache(maxsize=8)
def _cached_bin_entry_table(
    archive_path: str,
    archive_size: int,
    archive_mtime_ns: int,
) -> tuple[tuple[int, int, str], ...]:
    """Parse one immutable BIN directory table once per file version."""

    del archive_size, archive_mtime_ns  # cache identity only
    archive = Path(archive_path)
    # Import locally to keep the resource adapter independent from the archive
    # writer during module initialisation.
    from .bin_archive import BinArchiveError, archive_entry_table_file

    try:
        return archive_entry_table_file(archive)
    except BinArchiveError as exc:
        raise ResourceBuildError(str(exc)) from exc


def _hzc_payload_probe_from_parts(entry_size: int, header: bytes, tail: bytes) -> str:
    """Cheap scan-time identity for detecting same-stat entry drift.

    The selected entry still receives a full SHA-256 when staged.  Scanning
    every compressed CG in full would defeat the ten-second source-switch
    target, so the list records the authoritative HZC header plus the zlib
    tail/checksum and exact entry size instead.
    """

    return hashlib.sha256(
        struct.pack("<Q", int(entry_size)) + bytes(header[:44]) + bytes(tail[-16:])
    ).hexdigest()


def hzc_payload_probe(data: bytes) -> str:
    if not isinstance(data, bytes) or not data:
        raise ResourceBuildError("HZC probe 需要非空 bytes")
    return _hzc_payload_probe_from_parts(len(data), data[:44], data[-16:])


def read_bin_entry_payload(
    archive: str | Path,
    entry_index: int,
) -> tuple[bytes, dict[str, Any]]:
    """Read one compressed HZC entry without materialising the whole BIN.

    Candidate generation needs the original compressed body/face payload so
    it can append that exact resource to another ``graph_bs.bin``.  Preview
    helpers inflate pixels and the generic archive parser accepts an entire
    file as ``bytes``; either route would waste hundreds of megabytes for a
    normal FVP archive.  This function reuses the cached directory table and
    performs one bounded seek/read instead.
    """

    path = Path(archive).expanduser().resolve()
    if not path.is_file():
        raise ResourceBuildError(f"原始 BIN 不存在: {path}")
    stat = path.stat()
    entries = _cached_bin_entry_table(
        str(path),
        int(stat.st_size),
        int(stat.st_mtime_ns),
    )
    index = int(entry_index)
    if not 0 <= index < len(entries):
        raise ResourceBuildError(f"entry_index 超出范围: {index}")
    offset, size, source_name = entries[index]
    with path.open("rb") as source:
        source.seek(offset)
        payload = source.read(size)
    if len(payload) != size:
        raise ResourceBuildError(
            f"BIN entry 读取不完整: 需要 {size} 字节，实际 {len(payload)} 字节"
        )
    codec = _adapter_module("hzc_template_codec")
    info = codec.metadata(payload)
    return payload, {
        "archive": str(path),
        "entry_index": index,
        "offset": offset,
        "compressed_size": size,
        "source_name": source_name,
        "payload_probe_sha256": hzc_payload_probe(payload),
        **{key: info[key] for key in _HZC_INFO_KEYS},
    }


@lru_cache(maxsize=8)
def _cached_hzc_entry_payload(
    archive_path: str,
    archive_size: int,
    archive_mtime_ns: int,
    entry_index: int,
) -> tuple[bytes, tuple[Any, ...]]:
    """Read and inflate one immutable HZC entry once per BIN file version.

    Expression containers keep every face frame in one compressed entry.  The
    old preview path reopened and inflated that same entry for every click.
    The size/mtime values are deliberately part of the key so replacing a BIN
    invalidates its cached payload without any manual reset.  Eight entries are
    enough for the usual four-character stage while keeping memory bounded.
    """

    archive = Path(archive_path)
    entries = _cached_bin_entry_table(
        archive_path,
        archive_size,
        archive_mtime_ns,
    )
    index = int(entry_index)
    if not 0 <= index < len(entries):
        raise ResourceBuildError(f"entry_index 超出范围: {index}")
    offset, size, _source_name = entries[index]
    with archive.open("rb") as source:
        source.seek(offset)
        data = source.read(size)
    codec = _adapter_module("hzc_template_codec")
    info = codec.metadata(data)
    return zlib.decompress(data[44:]), _freeze_hzc_info(info)


def _decode_hzc_frame(
    raw: bytes,
    info: dict[str, Any],
    frame: int,
) -> Image.Image:
    """Decode one already-inflated HZC frame with Pillow's native raw codec."""

    width = int(info["width"])
    height = int(info["height"])
    frame_count = int(info["frame_count"])
    frame_index = int(frame)
    if not 0 <= frame_index < frame_count:
        raise ResourceBuildError(f"frame 超出范围: {frame_index}")
    kind = int(info["kind"])
    try:
        depth = {0: 3, 1: 4, 2: 4, 3: 1, 4: 1}[kind]
    except KeyError as exc:
        raise ResourceBuildError(f"不支持的 HZC 像素类型: {kind}") from exc
    frame_size = width * height * depth
    start = frame_index * frame_size
    pixels_raw = raw[start:start + frame_size]
    if len(pixels_raw) != frame_size:
        raise ResourceBuildError("解压后的 HZC 帧数据不完整")
    if kind == 0:
        return Image.frombytes("RGB", (width, height), pixels_raw, "raw", "BGR").convert("RGBA")
    if kind in (1, 2):
        # FVP stores BGRA with premultiplied colour channels.  Pillow's BGRa
        # raw decoder performs the inverse conversion in native code instead
        # of allocating millions of Python tuples for a full-body portrait.
        return Image.frombytes("RGBA", (width, height), pixels_raw, "raw", "BGRa")
    alpha = Image.frombytes("L", (width, height), pixels_raw)
    if kind == 4:
        alpha = alpha.point(lambda value: 255 if value else 0)
    image = Image.new("RGBA", (width, height), (255, 255, 255, 255))
    image.putalpha(alpha)
    return image


@lru_cache(maxsize=16)
def _cached_hzc_frame_rgba(
    archive_path: str,
    archive_size: int,
    archive_mtime_ns: int,
    entry_index: int,
    frame: int,
) -> tuple[bytes, tuple[Any, ...]]:
    """Cache the native RGBA conversion used by thumbnails and composites."""

    raw, frozen_info = _cached_hzc_entry_payload(
        archive_path,
        archive_size,
        archive_mtime_ns,
        entry_index,
    )
    info = _thaw_hzc_info(frozen_info)
    image = _decode_hzc_frame(raw, info, frame)
    return image.tobytes(), frozen_info


def _adapter_module(name: str):
    try:
        from .adapters import load
        return load(name)
    except ImportError as exc:
        raise ResourceBuildError(f"无法加载资源工具 {name}: {exc}") from exc


def _decoded_entry_image(archive: Path, entry_index: int, frame: int = 0) -> tuple[Image.Image, dict[str, Any]]:
    archive = archive.expanduser().resolve()
    if not archive.is_file():
        raise ResourceBuildError(f"原始 BIN 不存在: {archive}")
    archive_stat = archive.stat()
    rgba, frozen_info = _cached_hzc_frame_rgba(
        str(archive),
        int(archive_stat.st_size),
        int(archive_stat.st_mtime_ns),
        int(entry_index),
        int(frame),
    )
    info = _thaw_hzc_info(frozen_info)
    image = Image.frombytes(
        "RGBA",
        (int(info["width"]), int(info["height"])),
        rgba,
    )
    return image, {
        "archive": str(archive),
        "entry_index": int(entry_index),
        "frame": int(frame),
        **{key: info[key] for key in ("type", "width", "height", "frame_count")},
        "preview_width": int(info["width"]),
        "preview_height": int(info["height"]),
        "original_width": int(info["width"]),
        "original_height": int(info["height"]),
    }


def _find_exact_rgba_subimage(body: Image.Image, face: Image.Image) -> tuple[int, int]:
    """Locate a face/parts frame inside its matching frame-zero body image.

    FVP portrait bodies contain expression frame zero at the exact rectangle
    where the separate multi-frame overlay is drawn.  Searching one distinctive
    scanline first avoids a quadratic per-pixel walk while retaining an exact
    byte-for-byte verification of every candidate.
    """

    body = body.convert("RGBA")
    face = face.convert("RGBA")
    if face.getchannel("A").getbbox() is None:
        raise ResourceBuildError("表情帧全透明，不能用像素自动定位")
    if face.width > body.width or face.height > body.height:
        raise ResourceBuildError("表情图尺寸大于身体图，无法自动定位脸部坐标")
    body_data = body.tobytes()
    face_data = face.tobytes()
    body_stride = body.width * 4
    face_stride = face.width * 4
    # Transparent top/bottom rows are common.  Use the row with the largest
    # non-zero byte count as the search anchor, then verify the whole rectangle.
    anchor_row = max(
        range(face.height),
        key=lambda row: sum(1 for value in face_data[row * face_stride:(row + 1) * face_stride] if value),
    )
    needle = face_data[anchor_row * face_stride:(anchor_row + 1) * face_stride]
    for body_row in range(anchor_row, body.height - face.height + anchor_row + 1):
        row_start = body_row * body_stride
        row = body_data[row_start:row_start + body_stride]
        search_from = 0
        while True:
            byte_x = row.find(needle, search_from)
            if byte_x < 0:
                break
            search_from = byte_x + 1
            if byte_x % 4:
                continue
            x = byte_x // 4
            y = body_row - anchor_row
            if x + face.width > body.width or y < 0 or y + face.height > body.height:
                continue
            if all(
                body_data[(y + row_index) * body_stride + x * 4:(y + row_index) * body_stride + x * 4 + face_stride]
                == face_data[row_index * face_stride:(row_index + 1) * face_stride]
                for row_index in range(face.height)
            ):
                return x, y
    raise ResourceBuildError("身体图中找不到表情第 0 帧；无法安全推断脸部坐标")


def _validated_face_offset(
    raw: Any,
    body: Image.Image,
    face: Image.Image,
    label: str,
) -> tuple[int, int] | None:
    if raw in (None, ""):
        return None
    if not isinstance(raw, (list, tuple)) or len(raw) != 2:
        raise ResourceBuildError(f"{label}必须是 [x, y]")
    try:
        left, top = (int(raw[0]), int(raw[1]))
    except (TypeError, ValueError) as exc:
        raise ResourceBuildError(f"{label}必须是两个整数") from exc
    if left < 0 or top < 0 or left + face.width > body.width or top + face.height > body.height:
        raise ResourceBuildError(f"{label}超出身体画布")
    return left, top


def _resolve_face_offset(
    archive: Path,
    body: Image.Image,
    expression_index: int,
    expression_info: dict[str, Any],
    explicit: Any,
    resource_name: str,
    label: str,
) -> tuple[tuple[int, int], int | None, str]:
    first_face, _ = _decoded_entry_image(archive, expression_index, 0)
    manual = _validated_face_offset(explicit, body, first_face, label)
    if manual is not None:
        return manual, None, "manual"
    for frame in range(int(expression_info["frame_count"])):
        face, _ = _decoded_entry_image(archive, expression_index, frame)
        if face.getchannel("A").getbbox() is None:
            continue
        try:
            return _find_exact_rgba_subimage(body, face), frame, "pixel_match"
        except ResourceBuildError:
            continue
    known = _KNOWN_FACE_OFFSETS.get(resource_name)
    if known is not None:
        checked = _validated_face_offset(known, body, first_face, label)
        if checked is not None:
            return checked, None, "profile"
    raise ResourceBuildError(
        f"{label}无法自动定位；请在整套立绘高级设置中填写 X/Y"
    )


def decoded_bin_entry_image(
    archive: Path,
    entry_index: int,
    frame: int = 0,
) -> tuple[Image.Image, dict[str, Any]]:
    """Public read-only decoder used by the layered-portrait importer.

    Keeping this as a narrow wrapper lets new editor subsystems reuse the
    already-tested BIN/HZC decoder without depending on a private helper.
    """

    return _decoded_entry_image(archive, entry_index, frame)


def find_exact_portrait_face_offset(
    body: Image.Image,
    face: Image.Image,
) -> tuple[int, int]:
    """Public exact-pixel body/face pairing helper."""

    return _find_exact_rgba_subimage(body, face)


def resolve_portrait_face_offset(
    archive: Path,
    body: Image.Image,
    expression_index: int,
    expression_info: dict[str, Any],
    explicit: Any,
    resource_name: str,
    label: str = "脸部坐标",
) -> tuple[tuple[int, int], int | None, str]:
    """Resolve an FVP expression layer's location without modifying files."""

    return _resolve_face_offset(
        archive,
        body,
        expression_index,
        expression_info,
        explicit,
        resource_name,
        label,
    )


def _composite_clipped(canvas: Image.Image, source: Image.Image, left: int, top: int) -> None:
    source_left = max(0, -left)
    source_top = max(0, -top)
    target_left = max(0, left)
    target_top = max(0, top)
    width = min(source.width - source_left, canvas.width - target_left)
    height = min(source.height - source_top, canvas.height - target_top)
    if width <= 0 or height <= 0:
        raise ResourceBuildError("自动适配后的立绘完全落在目标画布之外")
    clipped = source.crop((source_left, source_top, source_left + width, source_top + height))
    canvas.alpha_composite(clipped, (target_left, target_top))


def inspect_portrait_set(
    source_archive: Path,
    target_archive: Path,
    specification: dict[str, Any],
) -> dict[str, Any]:
    """Validate and describe one body + multi-frame expression mapping."""

    source_archive = source_archive.expanduser().resolve()
    target_archive = target_archive.expanduser().resolve()
    try:
        source_body_index = int(specification["source_body_index"])
        source_expression_index = int(specification["source_expression_index"])
        target_body_index = int(specification["target_body_index"])
        target_expression_index = int(specification["target_expression_index"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ResourceBuildError("整套立绘计划缺少四个有效的 archive index") from exc
    if str(specification.get("frame_mode", "same_index")) != "same_index":
        raise ResourceBuildError("目前整套立绘仅支持按相同表情编号映射")

    source_body, source_body_info = _decoded_entry_image(source_archive, source_body_index)
    source_face, source_expression_info = _decoded_entry_image(source_archive, source_expression_index)
    target_body, target_body_info = _decoded_entry_image(target_archive, target_body_index)
    target_face, target_expression_info = _decoded_entry_image(target_archive, target_expression_index)
    if int(source_body_info["frame_count"]) != 1 or int(target_body_info["frame_count"]) != 1:
        raise ResourceBuildError("身体资源必须是单帧 HZC")
    source_frames = int(source_expression_info["frame_count"])
    target_frames = int(target_expression_info["frame_count"])
    if source_frames <= 1 or target_frames <= 1:
        raise ResourceBuildError("表情资源必须是多帧 HZC")
    if source_frames < target_frames:
        raise ResourceBuildError(
            f"来源表情只有 {source_frames} 帧，少于目标的 {target_frames} 帧"
        )
    source_face_offset, source_reference_frame, source_offset_mode = _resolve_face_offset(
        source_archive,
        source_body,
        source_expression_index,
        source_expression_info,
        specification.get("source_face_offset"),
        str(specification.get("source_expression_name", "")),
        "来源脸部坐标",
    )
    target_face_offset, target_reference_frame, target_offset_mode = _resolve_face_offset(
        target_archive,
        target_body,
        target_expression_index,
        target_expression_info,
        specification.get("target_face_offset"),
        str(specification.get("target_expression_name", "")),
        "目标脸部坐标",
    )
    log_avatar_mapping = _resolve_log_avatar_mapping(specification)
    return {
        "source_archive": str(source_archive),
        "target_archive": str(target_archive),
        "source_body_index": source_body_index,
        "source_expression_index": source_expression_index,
        "target_body_index": target_body_index,
        "target_expression_index": target_expression_index,
        "source_body": source_body_info,
        "source_expression": source_expression_info,
        "target_body": target_body_info,
        "target_expression": target_expression_info,
        "source_face_offset": list(source_face_offset),
        "target_face_offset": list(target_face_offset),
        "source_reference_frame": source_reference_frame,
        "target_reference_frame": target_reference_frame,
        "source_offset_mode": source_offset_mode,
        "target_offset_mode": target_offset_mode,
        "mapped_frames": target_frames,
        "unused_source_frames": source_frames - target_frames,
        "frame_mode": "same_index",
        "sync_log_avatar": _plan_bool(specification.get("sync_log_avatar"), True),
        "log_avatar_sync": log_avatar_mapping,
    }


def prepare_portrait_set_replacements(
    source_archive: Path,
    target_archive: Path,
    specification: dict[str, Any],
    work_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Generate ordinary PNG replacement items for one logical portrait set."""

    report = inspect_portrait_set(source_archive, target_archive, specification)
    work_dir.mkdir(parents=True, exist_ok=True)
    source_body, _ = _decoded_entry_image(source_archive, report["source_body_index"])
    source_face_zero, _ = _decoded_entry_image(source_archive, report["source_expression_index"])
    target_body_size = (
        int(report["target_body"]["width"]),
        int(report["target_body"]["height"]),
    )
    target_face_size = (
        int(report["target_expression"]["width"]),
        int(report["target_expression"]["height"]),
    )
    source_face_offset = tuple(int(value) for value in report["source_face_offset"])
    target_face_offset = tuple(int(value) for value in report["target_face_offset"])
    scale_x = target_face_size[0] / source_face_zero.width
    scale_y = target_face_size[1] / source_face_zero.height
    resized_size = (
        round(source_body.width * scale_x),
        round(source_body.height * scale_y),
    )
    resized_body = source_body.resize(resized_size, Image.Resampling.LANCZOS)
    body_left = target_face_offset[0] - round(source_face_offset[0] * scale_x)
    body_top = target_face_offset[1] - round(source_face_offset[1] * scale_y)
    body = Image.new("RGBA", target_body_size, (0, 0, 0, 0))
    _composite_clipped(body, resized_body, body_left, body_top)
    frame_zero = source_face_zero.resize(target_face_size, Image.Resampling.LANCZOS)
    body.alpha_composite(frame_zero, target_face_offset)
    body_path = work_dir / "body.png"
    body.save(body_path, "PNG")

    replacements: list[dict[str, Any]] = [
        {
            "entry_index": report["target_body_index"],
            "replacement_path": str(body_path),
            "fit": "stretch",
        }
    ]
    expression_paths: list[str] = []
    for frame in range(int(report["mapped_frames"])):
        source_expression, _ = _decoded_entry_image(
            source_archive, report["source_expression_index"], frame
        )
        expression = source_expression.resize(target_face_size, Image.Resampling.LANCZOS)
        expression_path = work_dir / f"expression_{frame:03d}.png"
        expression.save(expression_path, "PNG")
        expression_paths.append(str(expression_path))
        replacements.append(
            {
                "entry_index": report["target_expression_index"],
                "replacement_path": str(expression_path),
                "fit": "stretch",
                "frame": frame,
            }
        )
    report.update(
        {
            "scale": [scale_x, scale_y],
            "body_offset": [body_left, body_top],
            "resized_body_size": list(resized_size),
            "prepared_body": str(body_path),
            "prepared_expressions": expression_paths,
        }
    )
    return replacements, report


def prepare_log_avatar_replacements(
    project_dir: Path,
    mappings: list[dict[str, Any]],
    work_dir: Path,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    """Compose known LOG-avatar cell mappings into visual replacements."""

    grouped: dict[tuple[str, int], list[dict[str, Any]]] = {}
    unique_ids: set[str] = set()
    for mapping in mappings:
        mapping_id = str(mapping["mapping_id"])
        if mapping_id in unique_ids:
            continue
        unique_ids.add(mapping_id)
        key = (str(mapping["archive"]), int(mapping["entry_index"]))
        grouped.setdefault(key, []).append(mapping)

    replacements: dict[str, list[dict[str, Any]]] = {}
    reports: list[dict[str, Any]] = []
    occupied_targets: dict[tuple[str, int, int, int], str] = {}
    for (archive_name, entry_index), atlas_mappings in grouped.items():
        archive = _safe_child(project_dir, archive_name, "LOG 头像归档路径")
        bin_builder = _adapter_module("build_bin_patch")
        entries, _ = bin_builder.read_archive(archive)
        if not 0 <= entry_index < len(entries):
            raise ResourceBuildError(f"LOG 头像 entry_index 超出范围: {entry_index}")
        entry = entries[entry_index]
        with archive.open("rb") as source:
            source.seek(entry.offset)
            template_data = source.read(entry.size)
        codec = _adapter_module("hzc_template_codec")
        info = codec.metadata(template_data)
        if int(info["frame_count"]) != 1:
            raise ResourceBuildError(f"LOG 头像图集必须是单帧: {archive_name}#{entry_index}")
        expected_size = tuple(int(value) for value in atlas_mappings[0]["atlas_size"])
        actual_size = (int(info["width"]), int(info["height"]))
        if actual_size != expected_size:
            raise ResourceBuildError(
                f"LOG 头像图集尺寸不匹配: 预期 {expected_size[0]}x{expected_size[1]}，"
                f"实际 {actual_size[0]}x{actual_size[1]}"
            )
        kind = int(info["kind"])
        if kind not in (1, 2):
            raise ResourceBuildError(
                f"LOG 头像图集必须是 32 位 HZC: {archive_name}#{entry_index}"
            )
        depth = int(codec.DEPTHS[kind])
        original_raw = zlib.decompress(template_data[44:])
        row_stride = actual_size[0] * depth
        expected_raw_size = row_stride * actual_size[1]
        if len(original_raw) != expected_raw_size:
            raise ResourceBuildError(
                f"LOG 头像图集解压尺寸不匹配: 预期 {expected_raw_size}，实际 {len(original_raw)}"
            )
        composed_raw = bytearray(original_raw)
        applied_ids: list[str] = []
        for mapping in atlas_mappings:
            cell_width, cell_height = (int(value) for value in mapping["cell_size"])
            source_cells = tuple(
                tuple(int(value) for value in cell) for cell in mapping["source_cells"]
            )
            target_cells = tuple(
                tuple(int(value) for value in cell) for cell in mapping["target_cells"]
            )
            if len(source_cells) != len(target_cells):
                raise ResourceBuildError(f"LOG 头像映射格子数量不一致: {mapping['mapping_id']}")
            for source_cell, target_cell in zip(source_cells, target_cells, strict=True):
                source_left, source_top = source_cell
                target_left, target_top = target_cell
                if (
                    source_left < 0
                    or source_top < 0
                    or source_left + cell_width > actual_size[0]
                    or source_top + cell_height > actual_size[1]
                    or target_left < 0
                    or target_top < 0
                    or target_left + cell_width > actual_size[0]
                    or target_top + cell_height > actual_size[1]
                ):
                    raise ResourceBuildError(f"LOG 头像映射超出图集: {mapping['mapping_id']}")
                target_key = (archive_name, entry_index, target_left, target_top)
                previous = occupied_targets.get(target_key)
                if previous is not None and previous != mapping["mapping_id"]:
                    raise ResourceBuildError(
                        f"LOG 头像目标格冲突: {previous} / {mapping['mapping_id']}"
                    )
                occupied_targets[target_key] = str(mapping["mapping_id"])
                cell_row_size = cell_width * depth
                for row in range(cell_height):
                    source_start = (source_top + row) * row_stride + source_left * depth
                    target_start = (target_top + row) * row_stride + target_left * depth
                    composed_raw[target_start:target_start + cell_row_size] = original_raw[
                        source_start:source_start + cell_row_size
                    ]
            applied_ids.append(str(mapping["mapping_id"]))
        work_dir.mkdir(parents=True, exist_ok=True)
        output = work_dir / f"{Path(archive_name).stem}_{entry_index}_bl_char.hzc"
        header = bytearray(template_data[:44])
        header[4:8] = len(composed_raw).to_bytes(4, "little")
        output.write_bytes(bytes(header) + zlib.compress(bytes(composed_raw), 9))
        replacements.setdefault(archive_name, []).append(
            {
                "entry_index": entry_index,
                "replacement_path": str(output),
            }
        )
        reports.append(
            {
                "archive": archive_name,
                "entry_index": entry_index,
                "resource_name": str(atlas_mappings[0].get("resource_name", "")),
                "atlas_size": list(expected_size),
                "mapping_ids": applied_ids,
                "prepared_hzc": str(output),
            }
        )
    return replacements, reports


def _fit_image(source: Path, width: int, height: int, mode: str, output: Path) -> Path:
    with Image.open(source) as image:
        image = image.convert("RGBA")
        if mode == "stretch":
            prepared = image.resize((width, height), Image.Resampling.LANCZOS)
        elif mode == "cover":
            prepared = ImageOps.fit(image, (width, height), method=Image.Resampling.LANCZOS, centering=(0.5, 0.5))
        elif mode == "cover_top":
            # Portrait L resources are enlarged upper-body crops. Preserve the
            # head/hair at the top edge and crop only the lower body when a
            # full-body source is converted into that layout.
            prepared = ImageOps.fit(
                image,
                (width, height),
                method=Image.Resampling.LANCZOS,
                centering=(0.5, 0.0),
            )
        elif mode == "contain_bottom":
            # Standalone, already-composited character art must keep its
            # original aspect ratio.  FVP anchors standing portraits at the
            # bottom of their resource canvas, so leave any spare transparent
            # space above the sprite instead of vertically centering it.
            prepared = Image.new("RGBA", (width, height), (0, 0, 0, 0))
            contained = ImageOps.contain(image, (width, height), method=Image.Resampling.LANCZOS)
            prepared.alpha_composite(contained, ((width - contained.width) // 2, height - contained.height))
        else:  # contain: preserve the whole replacement with transparent margins
            prepared = Image.new("RGBA", (width, height), (0, 0, 0, 0))
            contained = ImageOps.contain(image, (width, height), method=Image.Resampling.LANCZOS)
            prepared.alpha_composite(contained, ((width - contained.width) // 2, (height - contained.height) // 2))
    output.parent.mkdir(parents=True, exist_ok=True)
    prepared.save(output, "PNG")
    return output


def _entry_template(archive: Path, entry_index: int, directory: Path) -> Path:
    extractor = _adapter_module("extract_bin_entry")
    source_root = archive.resolve(strict=True).parent
    destination_root = directory.absolute().resolve()
    if destination_root == source_root or source_root in destination_root.parents:
        raise ResourceBuildError("素材工作目录不能位于原作目录内")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"template_{archive.stem}_{entry_index}.hzc"
    if target.exists() or target.is_symlink():
        from .performance_install import _safe
        from .local_binding import stat_identity
        target = _safe(target.absolute(), file=True)
        rows = _cached_bin_entry_table(str(archive.resolve()), archive.stat().st_size, archive.stat().st_mtime_ns)
        if not 0 <= int(entry_index) < len(rows) or rows[int(entry_index)][1] > 256 * 1024 * 1024:
            raise ResourceBuildError("缓存模板来源索引/大小不合法")
        expected, _ = read_bin_entry_payload(archive, int(entry_index))
        before = target.stat()
        if target.read_bytes() != expected or stat_identity(target.stat()) != stat_identity(before):
            raise ResourceBuildError("同名模板缓存与来源不一致；拒绝覆盖")
        return target
    extractor.extract(archive, int(entry_index), target)
    return target


def _entry_magic(archive: Path, entry_index: int) -> bytes:
    """Read the first four bytes of a validated archive entry."""

    bin_builder = _adapter_module("build_bin_patch")
    entries, _ = bin_builder.read_archive(archive)
    index = int(entry_index)
    if not 0 <= index < len(entries):
        raise ResourceBuildError(f"entry_index 超出范围: {index}")
    entry = entries[index]
    with archive.open("rb") as source:
        source.seek(entry.offset)
        return source.read(4)


def _transcode_to_ogg(source: Path, output: Path) -> Path:
    """Convert a supported audio input to Vorbis-in-Ogg for an OggS slot."""

    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise ResourceBuildError("WAV→OGG 替换需要 ffmpeg，但当前 PATH 中未找到")
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-i",
        str(source),
        "-vn",
        "-c:a",
        "libvorbis",
        "-q:a",
        "5",
        str(output),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
        detail = (completed.stderr or completed.stdout or "unknown ffmpeg failure").strip()
        raise ResourceBuildError(f"WAV→OGG 转码失败: {detail}")
    if output.read_bytes()[:4] != b"OggS":
        raise ResourceBuildError("WAV→OGG 转码结果不是有效 OggS 数据")
    return output


def _prepare_replacement(
    archive: Path,
    entry_index: int,
    replacement: Path,
    work_dir: Path,
    fit: str,
    frame: int | None = None,
    template_override: Path | None = None,
    output_tag: str = "0",
) -> tuple[Path, dict[str, Any]]:
    if not replacement.is_file():
        raise ResourceBuildError(f"替换文件不存在: {replacement}")
    suffix = replacement.suffix.casefold()
    audio_suffixes = {".ogg", ".oga", ".wav", ".wave", ".mp3", ".flac"}
    if suffix in audio_suffixes:
        original_magic = _entry_magic(archive, entry_index)
        replacement_magic = replacement.read_bytes()[:4]
        if original_magic == b"OggS" and replacement_magic != b"OggS":
            output = work_dir / f"replacement_{entry_index}.ogg"
            _transcode_to_ogg(replacement, output)
            return output, {
                "source": str(replacement),
                "prepared": str(output),
                "mode": "audio_to_ogg",
            }
        return replacement, {"source": str(replacement), "mode": "raw"}
    if suffix in {".hzc", ".bin"}:
        return replacement, {"source": str(replacement), "mode": "raw"}
    if suffix not in {".png", ".webp", ".jpg", ".jpeg"}:
        raise ResourceBuildError(f"暂不支持的视觉替换格式: {replacement.suffix}")
    codec = _adapter_module("hzc_template_codec")
    template = template_override or _entry_template(archive, entry_index, work_dir / "templates")
    info = codec.metadata(template.read_bytes())
    frame_count = int(info["frame_count"])
    if frame is None:
        if frame_count > 1:
            raise ResourceBuildError(
                f"多帧资源 {archive.name}#{entry_index} 有 {frame_count} 帧，必须指定 frame"
            )
        frame_index = 0
    else:
        try:
            frame_index = int(frame)
        except (TypeError, ValueError) as exc:
            raise ResourceBuildError(f"frame 不是整数: {frame}") from exc
        if not 0 <= frame_index < frame_count:
            raise ResourceBuildError(
                f"frame 超出范围: {frame_index}（资源共有 {frame_count} 帧）"
            )

    prepared = _fit_image(
        replacement,
        int(info["width"]),
        int(info["height"]),
        fit,
        work_dir / f"prepared_{entry_index}_{frame_index}_{output_tag}.png",
    )
    output = work_dir / f"replacement_{entry_index}_{output_tag}.hzc"
    template_data = template.read_bytes()
    raw = bytearray(zlib.decompress(template_data[44:]))
    width = int(info["width"])
    height = int(info["height"])
    kind = int(info["kind"])
    depth = int(codec.DEPTHS[kind])
    frame_size = width * height * depth
    expected = frame_size * frame_count
    if len(raw) != expected:
        raise ResourceBuildError(
            f"HZC 解压尺寸不匹配: 预期 {expected}，实际 {len(raw)}"
        )
    encoded_frame = bytearray()
    with Image.open(prepared) as source:
        image = source.convert("RGBA")
        pixels = image.get_flattened_data() if hasattr(image, "get_flattened_data") else image.getdata()
        for red, green, blue, alpha in pixels:
            if kind == 0:
                encoded_frame.extend((blue, green, red))
            elif kind in (1, 2):
                encoded_frame.extend((
                    codec.premul(blue, alpha),
                    codec.premul(green, alpha),
                    codec.premul(red, alpha),
                    alpha,
                ))
            elif kind == 3:
                encoded_frame.append(alpha)
            else:
                encoded_frame.append(1 if alpha >= 128 else 0)
    if len(encoded_frame) != frame_size:
        raise ResourceBuildError(
            f"替换帧编码尺寸不匹配: 预期 {frame_size}，实际 {len(encoded_frame)}"
        )
    frame_start = frame_index * frame_size
    raw[frame_start:frame_start + frame_size] = encoded_frame
    header = bytearray(template_data[:44])
    header[4:8] = len(raw).to_bytes(4, "little")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(bytes(header) + zlib.compress(bytes(raw), 9))
    return output, {
        "source": str(replacement),
        "template": str(template),
        "prepared": str(prepared),
        "mode": "png_frame_to_hzc",
        "width": info["width"],
        "height": info["height"],
        "frame_count": frame_count,
        "frame": frame_index,
        "preserved_frame_count": frame_count - 1,
        "fit": fit,
    }


def build_archive_patch(
    archive: Path,
    replacements: list[dict[str, Any]],
    output: Path,
    work_dir: Path | None = None,
) -> dict[str, Any]:
    """Build one new BIN archive from visual/audio replacement entries."""

    archive = archive.expanduser().resolve()
    output = output.expanduser().resolve()
    if not archive.is_file():
        raise ResourceBuildError(f"原始 BIN 不存在: {archive}")
    if not replacements:
        raise ResourceBuildError("至少需要一个资源替换")
    bin_builder = _adapter_module("build_bin_patch")
    entries, _ = bin_builder.read_archive(archive)
    work = work_dir or output.parent / ".fvpstudio_resource_work"
    work.mkdir(parents=True, exist_ok=True)
    prepared: dict[int, Path] = {}
    details: list[dict[str, Any]] = []
    try:
        for sequence, item in enumerate(replacements):
            try:
                index = int(item["entry_index"])
                source = Path(str(item["replacement_path"])).expanduser().resolve()
            except (KeyError, TypeError, ValueError) as exc:
                raise ResourceBuildError(f"替换项缺少 entry_index/replacement_path: {item}") from exc
            if not 0 <= index < len(entries):
                raise ResourceBuildError(f"entry_index 超出范围: {index}")
            replacement, detail = _prepare_replacement(
                archive,
                index,
                source,
                work,
                str(item.get("fit", "contain")),
                item.get("frame"),
                prepared.get(index),
                str(sequence),
            )
            prepared[index] = replacement
            details.append({"entry_index": index, **detail})
        report = bin_builder.build(archive, prepared, output)
        report["prepared_replacements"] = details
        return report
    finally:
        # Keep the generated replacement HZCs/PNGs in the workspace for audit;
        # callers can remove the work directory after reviewing the report.
        pass


def build_plan(plan: dict[str, Any], project_dir: Path, output_dir: Path) -> dict[str, Any]:
    """Build visual/audio archive patches described by a saved plan."""

    project_dir = project_dir.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in plan.get("visual_replacements", []):
        archive = str(item.get("archive", "")).strip()
        if not archive:
            raise ResourceBuildError("视觉计划缺少 archive")
        groups.setdefault(archive, []).append({
            "entry_index": item.get("archive_index"),
            "replacement_path": item.get("replacement_path"),
            "fit": item.get("fit", "contain"),
            "frame": item.get("frame"),
        })
    portrait_specs: list[tuple[Path, Path, dict[str, Any], int]] = []
    for set_index, item in enumerate(plan.get("portrait_sets", [])):
        source_name = str(item.get("source_archive", item.get("archive", ""))).strip()
        target_name = str(item.get("target_archive", item.get("archive", ""))).strip()
        if not source_name or not target_name:
            raise ResourceBuildError("整套立绘计划缺少来源或目标 archive")
        source_archive = _safe_child(project_dir, source_name, "来源立绘归档路径")
        target_archive = _safe_child(project_dir, target_name, "目标立绘归档路径")
        groups.setdefault(target_name, [])
        portrait_specs.append((source_archive, target_archive, item, set_index))
    # Audio entries need a profile-resolved archive index and are intentionally
    # accepted only when the plan has already recorded one.
    for item in plan.get("audio_replacements", []):
        archive = str(item.get("archive", "voice.bin")).strip()
        if item.get("archive_index") is None:
            raise ResourceBuildError("语音计划需要 archive_index（由项目索引解析后写入）")
        groups.setdefault(archive, []).append({
            "entry_index": item["archive_index"],
            "replacement_path": item.get("replacement_path"),
        })
    portrait_reports: list[dict[str, Any]] = []
    log_avatar_mappings: list[dict[str, Any]] = []
    for source_archive, target_archive, specification, set_index in portrait_specs:
        generated, portrait_report = prepare_portrait_set_replacements(
            source_archive,
            target_archive,
            specification,
            output_dir / ".fvpstudio_portrait_sets" / f"set_{set_index:03d}",
        )
        target_name = str(specification.get("target_archive", specification.get("archive", ""))).strip()
        groups[target_name].extend(generated)
        portrait_reports.append(portrait_report)
        if portrait_report.get("log_avatar_sync") is not None:
            log_avatar_mappings.append(dict(portrait_report["log_avatar_sync"]))
    log_replacements, log_avatar_reports = prepare_log_avatar_replacements(
        project_dir,
        log_avatar_mappings,
        output_dir / ".fvpstudio_log_avatars",
    )
    for archive_name, replacements in log_replacements.items():
        groups.setdefault(archive_name, []).extend(replacements)
    for archive_name, replacements in groups.items():
        occupied: set[tuple[int, int]] = set()
        for replacement in replacements:
            try:
                key = (
                    int(replacement["entry_index"]),
                    int(replacement.get("frame") or 0),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ResourceBuildError(f"资源替换目标无效: {replacement}") from exc
            if key in occupied:
                raise ResourceBuildError(
                    f"{archive_name}#{key[0]} frame {key[1]} 被多个计划重复替换"
                )
            occupied.add(key)
    targets: list[tuple[Path, Path, list[dict[str, Any]]]] = []
    seen_outputs: set[Path] = set()
    for archive_name, replacements in groups.items():
        archive = _safe_child(project_dir, archive_name, "归档路径")
        output = output_dir / f"{archive.stem}.fvpstudio.bin"
        if output in seen_outputs:
            raise ResourceBuildError(f"多个归档会生成同名输出，拒绝构建: {output.name}")
        seen_outputs.add(output)
        if output.exists():
            raise ResourceBuildError(f"输出已存在，拒绝覆盖: {output}")
        targets.append((archive, output, replacements))
    reports = []
    for archive, output, replacements in targets:
        reports.append(build_archive_patch(archive, replacements, output))
    return {
        "schema": plan.get("schema", "fvp-studio-replacement-plan.v1"),
        "reports": reports,
        "portrait_sets": portrait_reports,
        "log_avatars": log_avatar_reports,
    }


def install_patch_set(patch_dir: Path, target_dir: Path, backup_root: Path | None = None) -> dict[str, Any]:
    """Install generated ``*.fvpstudio.bin`` patches into a game copy.

    The caller is responsible for refusing known original directories.  This
    function still requires the target to exist and backs up every destination
    before copying, producing a manifest suitable for a later rollback.
    """

    patch_dir = patch_dir.expanduser().resolve()
    target_dir = target_dir.expanduser().resolve()
    if not patch_dir.is_dir():
        raise ResourceBuildError(f"补丁目录不存在: {patch_dir}")
    if not target_dir.is_dir():
        raise ResourceBuildError(f"目标游戏目录不存在: {target_dir}")
    patches = sorted(patch_dir.glob("*.fvpstudio.bin"))
    if not patches:
        raise ResourceBuildError(f"补丁目录没有 *.fvpstudio.bin: {patch_dir}")
    destinations: list[tuple[Path, Path]] = []
    for patch in patches:
        original_name = patch.name.removesuffix(".fvpstudio.bin") + ".bin"
        destination = target_dir / original_name
        if not destination.is_file():
            raise ResourceBuildError(f"目标目录缺少原始归档，拒绝安装: {destination}")
        destinations.append((patch, destination))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = (backup_root.expanduser().resolve() if backup_root else target_dir / ".fvpstudio-backups" / stamp)
    backup_dir.mkdir(parents=True, exist_ok=True)
    installed: list[dict[str, Any]] = []
    for patch, destination in destinations:
        original_name = destination.name
        backup = backup_dir / original_name
        shutil.copy2(destination, backup)
        shutil.copy2(patch, destination)
        installed.append({
            "archive": original_name,
            "source_patch": str(patch),
            "destination": str(destination),
            "backup": str(backup),
            "backup_sha256": _sha256(backup),
            "installed_sha256": _sha256(destination),
        })
    manifest = {
        "schema": "fvp-studio-install-manifest.v1",
        "target_dir": str(target_dir),
        "patch_dir": str(patch_dir),
        "backup_dir": str(backup_dir),
        "installed": installed,
    }
    manifest_path = backup_dir / "manifest.json"
    manifest_path.write_text(__import__("json").dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {**manifest, "manifest": str(manifest_path)}


def inspect_copy_install(manifest_path: Path) -> dict[str, Any]:
    """Inspect one copy-install manifest without changing the game copy.

    The same path and hash rules used by :func:`restore_copy_install` are
    applied here.  Returning an explicit state for every HCB/BIN lets the UI
    prove whether the copy is still installed, already restored, missing, or
    has drifted since installation.
    """

    manifest_path = manifest_path.expanduser().resolve()
    if manifest_path.name != "install-manifest.json" or not manifest_path.is_file():
        raise ResourceBuildError("恢复需要有效的 install-manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResourceBuildError(f"无法读取安装清单: {exc}") from exc
    if manifest.get("schema") != "fvp-studio-copy-install.v1":
        raise ResourceBuildError("安装清单格式不受支持")

    target_dir = Path(str(manifest.get("target_dir", ""))).expanduser().resolve()
    backup_root = Path(str(manifest.get("backup_root", ""))).expanduser().resolve()
    if not target_dir.is_dir():
        raise ResourceBuildError(f"测试副本目录不存在: {target_dir}")
    expected_backup_parent = (target_dir / ".fvpstudio-backups").resolve()
    if backup_root.parent != expected_backup_parent or manifest_path != backup_root / "install-manifest.json":
        raise ResourceBuildError("安装清单与测试副本的备份目录不匹配")

    candidates: list[dict[str, Any]] = []

    hcb = manifest.get("hcb")
    if isinstance(hcb, dict):
        destination = Path(str(hcb.get("destination", ""))).expanduser().resolve()
        backup_value = hcb.get("backup")
        backup = Path(str(backup_value)).expanduser().resolve() if backup_value else None
        candidates.append({
            "kind": "hcb",
            "destination": destination,
            "backup": backup,
            "backup_sha256": hcb.get("backup_sha256"),
            "installed_sha256": hcb.get("installed_sha256"),
        })

    archives = manifest.get("archives")
    if isinstance(archives, dict):
        archive_backup_dir = Path(str(archives.get("backup_dir", ""))).expanduser().resolve()
        if archive_backup_dir != backup_root / "archives":
            raise ResourceBuildError("资源备份目录与安装清单不匹配")
        for item in archives.get("installed", []):
            if not isinstance(item, dict):
                raise ResourceBuildError("资源安装记录格式错误")
            candidates.append({
                "kind": "archive",
                "destination": Path(str(item.get("destination", ""))).expanduser().resolve(),
                "backup": Path(str(item.get("backup", ""))).expanduser().resolve(),
                "backup_sha256": item.get("backup_sha256"),
                "installed_sha256": item.get("installed_sha256"),
            })
    if not candidates:
        raise ResourceBuildError("安装清单中没有可恢复文件")

    files: list[dict[str, Any]] = []
    for item in candidates:
        destination: Path = item["destination"]
        backup: Path | None = item["backup"]
        if destination.parent != target_dir:
            raise ResourceBuildError(f"恢复目标不在测试副本根目录: {destination}")
        if not destination.is_file():
            if backup is None:
                files.append({**item, "state": "already_restored", "current_sha256": None})
                continue
            files.append({**item, "state": "missing", "current_sha256": None})
            continue
        current_sha256 = _sha256(destination)
        installed_sha256 = str(item.get("installed_sha256") or "")
        if backup is None:
            if not installed_sha256:
                raise ResourceBuildError(f"清单缺少安装哈希，拒绝移除: {destination.name}")
            state = "installed_new" if current_sha256 == installed_sha256 else "drifted"
            files.append({**item, "state": state, "current_sha256": current_sha256})
            continue
        if not backup.is_file() or not backup.is_relative_to(backup_root):
            raise ResourceBuildError(f"备份文件不存在或路径不安全: {destination.name}")
        backup_sha256 = _sha256(backup)
        expected_backup_sha256 = str(item.get("backup_sha256") or "")
        if not expected_backup_sha256 or backup_sha256 != expected_backup_sha256:
            raise ResourceBuildError(f"备份哈希不匹配，拒绝恢复: {destination.name}")
        if current_sha256 == backup_sha256:
            state = "already_restored"
        elif installed_sha256 and current_sha256 == installed_sha256:
            state = "installed"
        else:
            state = "drifted"
        files.append({**item, "state": state, "current_sha256": current_sha256})

    public_files = [
        {
            "kind": item["kind"],
            "destination": str(item["destination"]),
            "backup": str(item["backup"]) if item["backup"] is not None else None,
            "state": item["state"],
            "current_sha256": item.get("current_sha256"),
            "installed_sha256": item.get("installed_sha256"),
            "backup_sha256": item.get("backup_sha256"),
        }
        for item in files
    ]
    unsafe = {"missing", "drifted"}
    return {
        "schema": manifest["schema"],
        "manifest": str(manifest_path),
        "target_dir": str(target_dir),
        "ready_to_restore": bool(files) and not any(item["state"] in unsafe for item in files),
        "all_restored": bool(files) and all(item["state"] == "already_restored" for item in files),
        "files": public_files,
    }


def restore_copy_install(manifest_path: Path) -> dict[str, Any]:
    """Restore files recorded by a ``copy-install`` manifest.

    Every destination is hash-checked before any file is changed so rollback
    cannot silently overwrite later user edits.  Repeating a completed
    rollback is a safe no-op.
    """

    inspection = inspect_copy_install(manifest_path)
    manifest_path = Path(inspection["manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    target_dir = Path(inspection["target_dir"])
    backup_root = Path(str(manifest["backup_root"])).expanduser().resolve()
    states = {item["state"] for item in inspection["files"]}
    if "missing" in states:
        missing = next(item for item in inspection["files"] if item["state"] == "missing")
        raise ResourceBuildError(f"待恢复文件不存在: {missing['destination']}")
    if "drifted" in states:
        drifted = next(item for item in inspection["files"] if item["state"] == "drifted")
        raise ResourceBuildError(f"安装后文件已被修改，拒绝恢复: {Path(drifted['destination']).name}")

    actions: list[dict[str, Any]] = []
    for item in inspection["files"]:
        actions.append({
            "kind": item["kind"],
            "destination": Path(item["destination"]),
            "backup": Path(item["backup"]) if item["backup"] else None,
            "backup_sha256": item.get("backup_sha256"),
            "installed_sha256": item.get("installed_sha256"),
            "current_sha256": item.get("current_sha256"),
            "state": {
                "installed": "restore",
                "installed_new": "remove_new",
                "already_restored": "already_restored",
            }[item["state"]],
        })

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    restored: list[dict[str, Any]] = []
    for item in actions:
        destination = item["destination"]
        backup = item["backup"]
        state = item["state"]
        if state == "restore":
            temporary = destination.with_name(f".{destination.name}.fvpstudio-restore-{stamp}.tmp")
            if temporary.exists():
                raise ResourceBuildError(f"临时恢复文件已存在: {temporary}")
            try:
                shutil.copy2(backup, temporary)
                if _sha256(temporary) != item["backup_sha256"]:
                    raise ResourceBuildError(f"恢复临时文件校验失败: {destination.name}")
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
        elif state == "remove_new":
            preserved_dir = backup_root / "removed-on-rollback"
            preserved_dir.mkdir(parents=True, exist_ok=True)
            preserved = preserved_dir / destination.name
            if preserved.exists():
                raise ResourceBuildError(f"回滚保留文件已存在: {preserved}")
            shutil.move(str(destination), str(preserved))
        restored.append({
            "kind": item["kind"],
            "destination": str(destination),
            "state": state,
            "restored_sha256": _sha256(destination) if destination.is_file() else None,
        })

    manifest["rollback_performed_at"] = datetime.now().isoformat(timespec="seconds")
    manifest["rollback_files"] = restored
    manifest_temp = manifest_path.with_name(".install-manifest.restore.tmp")
    manifest_temp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(manifest_temp, manifest_path)
    return {
        "schema": manifest["schema"],
        "manifest": str(manifest_path),
        "target_dir": str(target_dir),
        "restored": restored,
    }


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
