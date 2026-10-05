"""Compile one frozen external FVP background into a Hoshimemo graph candidate.

The compiler is deliberately an in-memory boundary.  Source HZC payloads are
obtained through :func:`resource_builder.read_bin_entry_payload`, target
resources are appended with :func:`bin_archive.append_hzc_entries`, and no
source or target file is opened for writing.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any, Mapping
import zlib

from PIL import Image, ImageOps

from .bin_archive import (
    BinArchiveError,
    HzcMetadata,
    append_hzc_entries,
    hzc_metadata,
    parse_archive,
)
from .hoshimemo_stage_geometry import (
    HoshimemoStageGeometryError,
    NativeBackgroundCanvasGeometry,
    background_canvas_geometry,
)
from .resource_builder import ResourceBuildError, read_bin_entry_payload


BACKGROUND_ARCHIVE_NAMES = frozenset({"graph.bin", "graph_bg.bin"})
_SOURCE_HASH_FIELDS = ("payload_sha256", "source_payload_sha256", "entry_sha256", "sha256")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_DIRECTORY_NAME_BYTES = 16 * 1024 * 1024


class VisualSceneBackgroundCompileError(ValueError):
    """Raised when a frozen background cannot be proven safe to append."""


@dataclass(frozen=True)
class VisualSceneBackgroundBuild:
    """Immutable result of a pure-memory background compilation."""

    graph: bytes
    graph_source_sha256: str
    target_resource_name: str
    runtime_blur_resource_name: str
    resource_payloads: Mapping[str, bytes]
    report: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.graph, bytes):
            raise TypeError("graph 必须是 bytes")
        if not isinstance(self.graph_source_sha256, str):
            raise TypeError("graph_source_sha256 必须是字符串")
        if not isinstance(self.resource_payloads, Mapping):
            raise TypeError("resource_payloads 必须是 Mapping")
        if not isinstance(self.report, Mapping):
            raise TypeError("report 必须是 Mapping")
        # Keep the returned report JSON-safe without embedding source paths or
        # raw payload bytes in it.
        json.dumps(self.report, ensure_ascii=False, sort_keys=True)

    @property
    def graph_bytes(self) -> bytes:
        """Alias that makes the candidate's byte payload explicit."""

        return self.graph

    @property
    def candidate_graph(self) -> bytes:
        return self.graph

    @property
    def source_graph_sha256(self) -> str:
        return self.graph_source_sha256

    @property
    def resource_payload_mapping(self) -> Mapping[str, bytes]:
        return self.resource_payloads


@dataclass(frozen=True)
class _ReadSource:
    path: Path
    archive_name: str
    entry_index: int
    resource_name: str
    payload: bytes
    metadata: HzcMetadata
    report: Mapping[str, Any]


@dataclass(frozen=True)
class _TargetBackgroundTemplate:
    resource_name: str
    payload: bytes
    metadata: HzcMetadata
    geometry: NativeBackgroundCanvasGeometry
    profile_count: int
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_name": self.resource_name,
            "hzc": self.metadata.to_dict(),
            "geometry": self.geometry.to_dict(),
            "profile_count": self.profile_count,
            "header_sha256": hashlib.sha256(self.payload[:44]).hexdigest(),
            "fingerprint": self.fingerprint,
        }


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VisualSceneBackgroundCompileError(f"{label}缺失或不是对象")
    return value


def _required_text(reference: Mapping[str, Any], key: str, label: str) -> str:
    value = reference.get(key)
    if value is None:
        raise VisualSceneBackgroundCompileError(f"{label}缺少 {key}")
    text = str(value).strip()
    if not text:
        raise VisualSceneBackgroundCompileError(f"{label}缺少 {key}")
    return text


def _required_int(reference: Mapping[str, Any], key: str, label: str, *, minimum: int) -> int:
    value = reference.get(key)
    if isinstance(value, bool):
        raise VisualSceneBackgroundCompileError(f"{label}的 {key} 不是整数")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise VisualSceneBackgroundCompileError(f"{label}的 {key} 不是整数") from exc
    if isinstance(value, float) and value != result:
        raise VisualSceneBackgroundCompileError(f"{label}的 {key} 不是整数")
    if result < minimum:
        raise VisualSceneBackgroundCompileError(f"{label}的 {key} 小于 {minimum}")
    return result


def _read_info_int(info: Mapping[str, Any], key: str, default: int, label: str) -> int:
    value = info.get(key, default)
    if isinstance(value, bool):
        raise VisualSceneBackgroundCompileError(f"{label} bounded 读取返回的 {key} 无效")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise VisualSceneBackgroundCompileError(f"{label} bounded 读取返回的 {key} 无效") from exc
    if isinstance(value, float) and value != result:
        raise VisualSceneBackgroundCompileError(f"{label} bounded 读取返回的 {key} 无效")
    return result


def _source_archive(reference: Mapping[str, Any], label: str) -> tuple[Path, str]:
    raw_path = reference.get("archive_path")
    if raw_path is None or not str(raw_path).strip():
        raise VisualSceneBackgroundCompileError(f"{label}冻结引用缺少 archive_path")
    try:
        path = Path(raw_path).expanduser().resolve()
    except (OSError, RuntimeError, TypeError) as exc:
        raise VisualSceneBackgroundCompileError(f"{label}冻结引用的归档无效") from exc

    archive_name = path.name
    declared_name = str(reference.get("archive_name") or "").strip()
    if declared_name and declared_name.casefold() != archive_name.casefold():
        raise VisualSceneBackgroundCompileError(
            f"{label}冻结归档名与实际类型不一致: {declared_name}"
        )
    if archive_name.casefold() not in BACKGROUND_ARCHIVE_NAMES:
        raise VisualSceneBackgroundCompileError(
            f"{label}来源归档只允许 graph.bin 或 graph_bg.bin"
        )
    return path, archive_name


def _read_directory_name(path: Path, entry_index: int) -> tuple[str, int]:
    """Read only the selected BIN directory record and its bounded name tail."""

    try:
        archive_size = path.stat().st_size
        with path.open("rb") as source:
            header = source.read(8)
            if len(header) != 8:
                raise ValueError("BIN 文件头被截断")
            count, names_size = struct.unpack("<II", header)
            table_start = 8
            table_end = table_start + count * 12
            names_end = table_end + names_size
            if table_end < table_start or names_end < table_end or names_end > archive_size:
                raise ValueError("BIN 表或名称区越界")
            if entry_index < 0 or entry_index >= count:
                raise ValueError("entry_index 超出范围")
            source.seek(table_start + entry_index * 12)
            record = source.read(12)
            if len(record) != 12:
                raise ValueError("BIN 条目表被截断")
            name_offset, file_offset, file_size = struct.unpack("<III", record)
            if name_offset >= names_size:
                raise ValueError("名称偏移越界")
            file_end = file_offset + file_size
            if file_offset < names_end or file_end < file_offset or file_end > archive_size:
                raise ValueError("数据范围越界")
            remaining = names_size - name_offset
            if remaining > _MAX_DIRECTORY_NAME_BYTES:
                raise ValueError("名称区过大")
            source.seek(table_end + name_offset)
            name_tail = source.read(remaining)
    except (OSError, struct.error, ValueError) as exc:
        raise VisualSceneBackgroundCompileError("无法验证来源 BIN 的冻结 resource_name") from exc

    raw_name = name_tail.split(b"\0", 1)[0]
    if not raw_name:
        raise VisualSceneBackgroundCompileError("无法验证来源 BIN 的冻结 resource_name")
    try:
        name = raw_name.decode("cp932")
    except UnicodeDecodeError as exc:
        raise VisualSceneBackgroundCompileError(
            "来源 BIN 的 resource_name 不是合法 Windows 日文 CP932"
        ) from exc
    return name, file_size


def _current_resource_name(
    path: Path,
    entry_index: int,
    read_info: Mapping[str, Any],
    label: str,
    payload_size: int,
) -> str:
    for key in ("resource_name", "source_name", "name"):
        value = read_info.get(key)
        if value is not None and str(value).strip():
            name = str(value).strip()
            directory_size = read_info.get("directory_entry_size")
            if directory_size is not None and int(directory_size) != payload_size:
                raise VisualSceneBackgroundCompileError(
                    f"{label} 来源条目漂移: entry_size 与 bounded 读取不一致"
                )
            return name

    name, directory_size = _read_directory_name(path, entry_index)
    if directory_size != payload_size:
        raise VisualSceneBackgroundCompileError(
            f"{label} 来源条目漂移: entry_size 与当前目录不一致"
        )
    return name


def _check_optional_payload_hash(
    reference: Mapping[str, Any],
    payload_hash: str,
    label: str,
) -> None:
    expected: Any = None
    expected_key = ""
    for key in _SOURCE_HASH_FIELDS:
        if reference.get(key) is not None:
            expected = reference.get(key)
            expected_key = key
            break
    if expected is None:
        raise VisualSceneBackgroundCompileError(
            f"{label}冻结引用缺少 payload_sha256，请重新选择背景"
        )
    expected_text = str(expected).strip()
    if not _SHA256.fullmatch(expected_text):
        raise VisualSceneBackgroundCompileError(f"{label}冻结的 {expected_key} 不是 SHA-256")
    if expected_text.casefold() != payload_hash:
        raise VisualSceneBackgroundCompileError(
            f"{label} 来源条目漂移: 冻结的 {expected_key} 与当前 payload 不一致"
        )


def _read_source(reference: Mapping[str, Any], label: str) -> _ReadSource:
    path, archive_name = _source_archive(reference, label)
    frozen_archive_size = _required_int(
        reference,
        "archive_size",
        label,
        minimum=1,
    )
    frozen_archive_mtime_ns = _required_int(
        reference,
        "archive_mtime_ns",
        label,
        minimum=0,
    )
    try:
        archive_stat = path.stat()
    except OSError as exc:
        raise VisualSceneBackgroundCompileError(
            f"{label} 无法复检来源归档身份"
        ) from exc
    if (
        int(archive_stat.st_size) != frozen_archive_size
        or int(archive_stat.st_mtime_ns) != frozen_archive_mtime_ns
    ):
        raise VisualSceneBackgroundCompileError(
            f"{label} 来源归档漂移: 大小或修改时间与扫描冻结值不一致"
        )
    entry_index = _required_int(reference, "entry_index", label, minimum=0)
    frozen_entry_size = _required_int(reference, "entry_size", label, minimum=1)
    frozen_resource_name = _required_text(reference, "resource_name", label)
    frozen_dimensions = {
        key: _required_int(reference, key, label, minimum=1)
        for key in ("width", "height", "frame_count")
    }

    try:
        raw_payload, raw_info = read_bin_entry_payload(path, entry_index)
    except (OSError, ResourceBuildError, TypeError, ValueError) as exc:
        raise VisualSceneBackgroundCompileError(
            f"{label} 无法通过 read_bin_entry_payload 完成 bounded 读取"
        ) from exc
    if not isinstance(raw_payload, (bytes, bytearray, memoryview)):
        raise VisualSceneBackgroundCompileError(f"{label} bounded 读取没有返回 bytes payload")
    payload = bytes(raw_payload)
    if not isinstance(raw_info, Mapping):
        raise VisualSceneBackgroundCompileError(f"{label} bounded 读取没有返回元数据")

    actual_entry_size = _read_info_int(
        raw_info,
        "compressed_size" if "compressed_size" in raw_info else "entry_size",
        len(payload),
        label,
    )
    if actual_entry_size != len(payload) or frozen_entry_size != len(payload):
        raise VisualSceneBackgroundCompileError(
            f"{label} 来源条目漂移: 冻结 entry_size 与当前 bounded 读取不一致"
        )
    reported_index = _read_info_int(raw_info, "entry_index", entry_index, label)
    if reported_index != entry_index:
        raise VisualSceneBackgroundCompileError(
            f"{label} 来源条目漂移: 冻结 entry_index 与当前 bounded 读取不一致"
        )

    try:
        metadata = hzc_metadata(payload)
    except BinArchiveError as exc:
        raise VisualSceneBackgroundCompileError(
            f"{label} HZC 元数据验证失败: {exc}"
        ) from exc

    for key in ("width", "height", "frame_count"):
        actual_value = getattr(metadata, key)
        reported_value = _read_info_int(raw_info, key, actual_value, label)
        if reported_value != actual_value or frozen_dimensions[key] != actual_value:
            raise VisualSceneBackgroundCompileError(
                f"{label} 来源条目漂移: 冻结 {key} 与当前 HZC 不一致"
            )

    current_resource_name = _current_resource_name(
        path,
        entry_index,
        raw_info,
        label,
        len(payload),
    )
    if current_resource_name != frozen_resource_name:
        raise VisualSceneBackgroundCompileError(
            f"{label} 来源条目漂移: 冻结 resource_name 与当前 bounded 读取不一致"
        )

    payload_hash = hashlib.sha256(payload).hexdigest()
    _check_optional_payload_hash(reference, payload_hash, label)
    source_report = {
        "role": label,
        "read_method": "resource_builder.read_bin_entry_payload",
        "archive_name": archive_name,
        "archive_size": frozen_archive_size,
        "archive_mtime_ns": frozen_archive_mtime_ns,
        "entry_index": entry_index,
        "entry_size": len(payload),
        "resource_name": current_resource_name,
        "payload_bytes": len(payload),
        "payload_sha256": payload_hash,
        "sha256": payload_hash,
        "width": metadata.width,
        "height": metadata.height,
        "frame_count": metadata.frame_count,
        "hzc": metadata.to_dict(),
    }
    return _ReadSource(
        path=path,
        archive_name=archive_name,
        entry_index=entry_index,
        resource_name=current_resource_name,
        payload=payload,
        metadata=metadata,
        report=source_report,
    )


def _target_name(payload: bytes) -> str:
    return f"BG_FVPV2_{hashlib.sha256(payload).hexdigest()[:16].upper()}"


def _source_identity(source: _ReadSource) -> tuple[str, int]:
    return (str(source.path).casefold(), source.entry_index)


def _target_graph_archive(graph: bytes):
    try:
        return parse_archive(graph)
    except BinArchiveError as exc:
        raise VisualSceneBackgroundCompileError(f"目标 graph.bin 无效: {exc}") from exc


def _target_background_template(target_graph: bytes) -> _TargetBackgroundTemplate:
    """Infer the target game's native background canvas without a fixed name."""

    archive = _target_graph_archive(target_graph)
    candidates: list[tuple[Any, HzcMetadata]] = []
    for entry in archive.entries:
        folded_name = entry.name.casefold()
        if not folded_name.startswith("bg") or folded_name.startswith("bg_fvpv2_"):
            continue
        try:
            metadata = hzc_metadata(entry.payload, validate_pixels=False)
        except BinArchiveError:
            continue
        if metadata.kind not in {0, 1} or metadata.frame_count != 1:
            continue
        candidates.append((entry, metadata))
    if not candidates:
        raise VisualSceneBackgroundCompileError(
            "目标 graph.bin 没有可识别的原生单帧背景模板"
        )

    def profile_key(metadata: HzcMetadata) -> tuple[int, int, int, int, int, int]:
        return (
            int(metadata.kind),
            int(metadata.width),
            int(metadata.height),
            int(metadata.offset_x),
            int(metadata.offset_y),
            int(metadata.frame_count),
        )

    counts = Counter(profile_key(metadata) for _entry, metadata in candidates)
    selected_profile = max(
        counts,
        key=lambda key: (
            counts[key],
            key[1] * key[2],
            key[1],
            key[2],
            -key[0],
            -abs(key[3]),
            -abs(key[4]),
        ),
    )
    selected_entry, _metadata = next(
        (entry, metadata)
        for entry, metadata in candidates
        if profile_key(metadata) == selected_profile
    )
    try:
        metadata = hzc_metadata(selected_entry.payload)
        geometry = background_canvas_geometry(metadata)
    except (BinArchiveError, HoshimemoStageGeometryError) as exc:
        raise VisualSceneBackgroundCompileError(
            f"目标背景模板 {selected_entry.name} 无法建立原生可视窗口: {exc}"
        ) from exc
    fingerprint_value = {
        "schema": "fvp-studio-v2.target-background-canvas.v1",
        "hzc_header_sha256": hashlib.sha256(selected_entry.payload[:44]).hexdigest(),
        "hzc": metadata.to_dict(),
        "geometry": geometry.to_dict(),
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return _TargetBackgroundTemplate(
        resource_name=selected_entry.name,
        payload=selected_entry.payload,
        metadata=metadata,
        geometry=geometry,
        profile_count=counts[selected_profile],
        fingerprint=fingerprint,
    )


def background_target_canvas_fingerprint(target_graph: bytes) -> str:
    """Return a stable cache identity that ignores prior V2 additions."""

    if not isinstance(target_graph, bytes):
        raise VisualSceneBackgroundCompileError("目标 graph.bin 必须是 bytes")
    return _target_background_template(target_graph).fingerprint


def _decode_background(payload: bytes, metadata: HzcMetadata) -> Image.Image:
    if metadata.kind not in {0, 1} or metadata.frame_count != 1:
        raise VisualSceneBackgroundCompileError(
            "跨游戏背景只支持 single24/single32 单帧 HZC"
        )
    try:
        raw = zlib.decompress(payload[44:])
    except zlib.error as exc:
        raise VisualSceneBackgroundCompileError(f"来源背景 HZC 解压失败: {exc}") from exc
    size = (int(metadata.width), int(metadata.height))
    try:
        if metadata.kind == 0:
            return Image.frombytes("RGB", size, raw, "raw", "BGR").convert("RGBA")
        return Image.frombytes("RGBA", size, raw, "raw", "BGRa")
    except (TypeError, ValueError) as exc:
        raise VisualSceneBackgroundCompileError(
            "来源背景 HZC 像素无法解码"
        ) from exc


def _fit_background_to_target_canvas(
    source: _ReadSource,
    template: _TargetBackgroundTemplate,
    fit: str,
) -> tuple[bytes, Mapping[str, Any]]:
    image = _decode_background(source.payload, source.metadata)
    geometry = template.geometry
    viewport_size = (geometry.viewport_width, geometry.viewport_height)
    resampling = Image.Resampling.LANCZOS
    if fit == "stretch":
        fitted = image.resize(viewport_size, resampling)
    elif fit == "cover":
        fitted = ImageOps.fit(
            image,
            viewport_size,
            method=resampling,
            centering=(0.5, 0.5),
        )
    elif fit == "contain":
        contained = ImageOps.contain(image, viewport_size, method=resampling)
        fitted = Image.new("RGBA", viewport_size, (0, 0, 0, 255))
        fitted.alpha_composite(
            contained,
            (
                (viewport_size[0] - contained.width) // 2,
                (viewport_size[1] - contained.height) // 2,
            ),
        )
    else:
        raise VisualSceneBackgroundCompileError(
            "冻结背景 fit 必须是 cover、contain 或 stretch"
        )

    canvas = Image.new(
        "RGBA",
        (geometry.canvas_width, geometry.canvas_height),
        (0, 0, 0, 255),
    )
    canvas.alpha_composite(
        fitted,
        (geometry.viewport_left, geometry.viewport_top),
    )
    if template.metadata.kind == 0:
        raw = canvas.convert("RGB").tobytes("raw", "BGR")
    elif template.metadata.kind == 1:
        raw = canvas.tobytes("raw", "BGRa")
    else:  # Kept explicit even though template selection already rejects it.
        raise VisualSceneBackgroundCompileError(
            f"目标背景模板 kind={template.metadata.kind} 不可编码"
        )
    header = bytearray(template.payload[:44])
    struct.pack_into("<I", header, 4, len(raw))
    normalized = bytes(header) + zlib.compress(raw, level=9)
    try:
        output_metadata = hzc_metadata(normalized)
    except BinArchiveError as exc:
        raise VisualSceneBackgroundCompileError(
            f"归一化背景 HZC 自检失败: {exc}"
        ) from exc
    layout_fields = (
        "kind",
        "width",
        "height",
        "offset_x",
        "offset_y",
        "frame_count",
        "raw_length",
    )
    if any(
        getattr(output_metadata, field) != getattr(template.metadata, field)
        for field in layout_fields
    ):
        raise VisualSceneBackgroundCompileError(
            "归一化背景没有保留目标游戏的 HZC 画布模板"
        )
    source_hash = hashlib.sha256(source.payload).hexdigest()
    output_hash = hashlib.sha256(normalized).hexdigest()
    return normalized, {
        "source_resource_name": source.resource_name,
        "source_hzc": source.metadata.to_dict(),
        "source_payload_bytes": len(source.payload),
        "source_payload_sha256": source_hash,
        "target_hzc": output_metadata.to_dict(),
        "target_payload_bytes": len(normalized),
        "target_payload_sha256": output_hash,
        "fit": fit,
        "target_canvas": geometry.to_dict(),
        "source_payload_preserved_exactly": normalized == source.payload,
    }


def compile_visual_scene_background(
    background: Mapping[str, Any],
    target_graph: bytes,
) -> VisualSceneBackgroundBuild:
    """Compile a frozen external background into an additive graph candidate.

    ``background`` is the frozen mapping produced by the V2 stage.  A primary
    reference is always read once.  A valid nested ``blur`` reference is read
    once more; otherwise the HCB runtime name intentionally aliases the main
    resource instead of creating a second copy of the same HZC payload.
    """

    if not isinstance(background, Mapping):
        raise VisualSceneBackgroundCompileError("冻结背景必须是 Mapping")
    if background.get("build_mode") != "copy_hzc":
        raise VisualSceneBackgroundCompileError("冻结背景 build_mode 必须是 copy_hzc")
    if not isinstance(target_graph, bytes):
        raise VisualSceneBackgroundCompileError("目标 graph.bin 必须是 bytes")

    variant = str(background.get("variant") or "primary").strip().casefold()
    if variant not in {"primary", "blur"}:
        raise VisualSceneBackgroundCompileError("冻结背景 variant 必须是 primary 或 blur")
    fit = str(background.get("fit") or "cover").strip().casefold()
    if fit not in {"cover", "contain", "stretch"}:
        raise VisualSceneBackgroundCompileError(
            "冻结背景 fit 必须是 cover、contain 或 stretch"
        )

    primary = _read_source(background, "主图")
    blur_value = background.get("blur")
    blur: _ReadSource | None = None
    if blur_value is not None:
        blur_reference = _required_mapping(blur_value, "冻结背景 blur 配对")
        blur = _read_source(blur_reference, "模糊图")
        if _source_identity(primary) == _source_identity(blur):
            raise VisualSceneBackgroundCompileError(
                "冻结背景 blur 配对必须是独立的来源条目"
            )

    target_template = _target_background_template(target_graph)
    primary_payload, primary_normalization = _fit_background_to_target_canvas(
        primary,
        target_template,
        fit,
    )
    blur_payload: bytes | None = None
    blur_normalization: Mapping[str, Any] | None = None
    if blur is not None:
        blur_payload, blur_normalization = _fit_background_to_target_canvas(
            blur,
            target_template,
            fit,
        )

    target_name = _target_name(primary_payload)
    runtime_blur_name = f"{target_name}b" if blur is not None else target_name
    additions: dict[str, bytes] = {target_name: primary_payload}
    if blur_payload is not None:
        additions[runtime_blur_name] = blur_payload

    target_archive = _target_graph_archive(target_graph)
    existing_names = set(target_archive.names)
    conflicting_names = sorted(existing_names.intersection(additions))
    if conflicting_names:
        raise VisualSceneBackgroundCompileError(
            "目标资源名冲突，拒绝覆盖已有资源: " + ", ".join(conflicting_names)
        )

    try:
        appended = append_hzc_entries(target_graph, additions)
    except BinArchiveError as exc:
        raise VisualSceneBackgroundCompileError(f"目标 graph.bin 只追加失败: {exc}") from exc

    candidate = appended.data
    candidate_archive = _target_graph_archive(candidate)
    candidate_by_name = candidate_archive.by_name()
    target_payloads_preserved_exactly = all(
        candidate_by_name.get(name) is not None
        and candidate_by_name[name].payload == entry.payload
        for name, entry in target_archive.by_name().items()
    )
    added_payloads_preserved_exactly = all(
        candidate_by_name.get(name) is not None
        and candidate_by_name[name].payload == payload
        for name, payload in additions.items()
    )
    source_payloads_preserved_exactly = (
        primary_payload == primary.payload
        and (blur is None or blur_payload == blur.payload)
    )
    no_existing_resource_replaced = (
        existing_names.issubset(set(candidate_archive.names))
        and not existing_names.intersection(additions)
    )
    if not target_payloads_preserved_exactly:
        raise VisualSceneBackgroundCompileError(
            "目标 graph.bin candidate 未逐字节保留原有资源"
        )
    if not added_payloads_preserved_exactly:
        raise VisualSceneBackgroundCompileError(
            "归一化后的外部背景 payload 未逐字节追加到目标 candidate"
        )
    if not no_existing_resource_replaced:
        raise VisualSceneBackgroundCompileError(
            "目标 graph.bin candidate 发生已有资源替换"
        )

    payload_bytes = sum(len(payload) for payload in additions.values())
    graph_added_bytes = len(candidate) - len(target_graph)
    archive_metadata_bytes = graph_added_bytes - payload_bytes
    if archive_metadata_bytes < 0:
        raise VisualSceneBackgroundCompileError(
            "目标 graph.bin candidate 的实际归档增量小于 payload 增量"
        )

    graph_source_sha256 = hashlib.sha256(target_graph).hexdigest()
    graph_after_sha256 = hashlib.sha256(candidate).hexdigest()
    source_references = [dict(primary.report)]
    if blur is not None:
        source_references.append(dict(blur.report))
    payload_report = {
        name: {
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        for name, payload in additions.items()
    }
    report: dict[str, Any] = {
        "schema": "fvp-studio-v2.visual-scene-background-build.v2",
        "build_mode": "copy_hzc",
        "stage_variant": variant,
        "stage_fit": fit,
        "target_resource_name": target_name,
        "runtime_blur_resource_name": runtime_blur_name,
        "target_background_template": target_template.to_dict(),
        "target_canvas_profile_fingerprint": target_template.fingerprint,
        "fit_compiled_to_target_canvas": True,
        "source_payloads_normalized_for_target_canvas": True,
        "normalization": {
            "primary": dict(primary_normalization),
            "blur": dict(blur_normalization) if blur_normalization is not None else None,
        },
        "bounded_source_references": source_references,
        "source_references": source_references,
        "bounded_source_read_count": len(source_references),
        "payload_bytes": payload_bytes,
        "archive_metadata_bytes": archive_metadata_bytes,
        "graph_added_bytes": graph_added_bytes,
        "graph_source_sha256": graph_source_sha256,
        "graph_before": {
            "size": len(target_graph),
            "sha256": graph_source_sha256,
        },
        "graph_after": {
            "size": len(candidate),
            "sha256": graph_after_sha256,
        },
        "graph_before_size": len(target_graph),
        "graph_before_sha256": graph_source_sha256,
        "graph_after_size": len(candidate),
        "graph_after_sha256": graph_after_sha256,
        "resource_payloads": payload_report,
        "one_payload_reused_for_two_layers": blur is None,
        "source_payloads_preserved_exactly": source_payloads_preserved_exactly,
        "added_payloads_preserved_exactly": added_payloads_preserved_exactly,
        "target_payloads_preserved_exactly": target_payloads_preserved_exactly,
        "no_existing_resource_replaced": no_existing_resource_replaced,
        "added_resource_names": list(additions),
        "archive_append": appended.validation_dict(),
    }
    return VisualSceneBackgroundBuild(
        graph=candidate,
        graph_source_sha256=graph_source_sha256,
        target_resource_name=target_name,
        runtime_blur_resource_name=runtime_blur_name,
        resource_payloads=dict(additions),
        report=report,
    )


# Descriptive aliases keep the boundary discoverable to callers that name the
# operation after the external FVP/HZC source rather than the visual-scene UI.
compile_external_fvp_background = compile_visual_scene_background
compile_visual_scene_background_hzc = compile_visual_scene_background


__all__ = [
    "BACKGROUND_ARCHIVE_NAMES",
    "VisualSceneBackgroundBuild",
    "VisualSceneBackgroundCompileError",
    "background_target_canvas_fingerprint",
    "compile_external_fvp_background",
    "compile_visual_scene_background",
    "compile_visual_scene_background_hzc",
]
