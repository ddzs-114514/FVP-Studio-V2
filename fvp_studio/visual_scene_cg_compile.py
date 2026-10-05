"""Append one frozen external FVP event CG to its matching graph_vis archive.

Only the selected source entry is read.  The target candidate is built in
memory, retains every existing payload byte-for-byte, and receives a
content-addressed resource name so no original entry is replaced.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any, Mapping

from .bin_archive import (
    BinArchiveError,
    append_hzc_entries,
    archive_entry_names,
    hzc_metadata,
)
from .cg_workspace import CG_ARCHIVE_SELECTORS
from .resource_builder import ResourceBuildError, read_bin_entry_payload


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_DIRECTORY_NAME_BYTES = 16 * 1024 * 1024


class VisualSceneCgCompileError(ValueError):
    """Raised when a frozen CG cannot be proven safe to append."""


@dataclass(frozen=True)
class VisualSceneCgBuild:
    archive: bytes
    archive_source_sha256: str
    target_archive_name: str
    target_resource_name: str
    archive_selector: int
    resource_payloads: Mapping[str, bytes]
    report: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.archive, bytes):
            raise TypeError("archive 必须是 bytes")
        json.dumps(self.report, ensure_ascii=False, sort_keys=True)


def _required_int(reference: Mapping[str, Any], key: str, *, minimum: int) -> int:
    value = reference.get(key)
    if isinstance(value, bool):
        raise VisualSceneCgCompileError(f"冻结 CG 的 {key} 不是整数")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise VisualSceneCgCompileError(f"冻结 CG 缺少有效 {key}") from exc
    if isinstance(value, float) and value != result:
        raise VisualSceneCgCompileError(f"冻结 CG 的 {key} 不是整数")
    if result < minimum:
        raise VisualSceneCgCompileError(f"冻结 CG 的 {key} 小于 {minimum}")
    return result


def _read_directory_name(path: Path, entry_index: int) -> tuple[str, int]:
    try:
        archive_size = path.stat().st_size
        with path.open("rb") as source:
            header = source.read(8)
            if len(header) != 8:
                raise ValueError("BIN 文件头被截断")
            count, names_size = struct.unpack("<II", header)
            table_end = 8 + count * 12
            names_end = table_end + names_size
            if names_end < table_end or names_end > archive_size:
                raise ValueError("BIN 表或名称区越界")
            if entry_index < 0 or entry_index >= count:
                raise ValueError("entry_index 超出范围")
            source.seek(8 + entry_index * 12)
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
            raw_name = source.read(remaining).split(b"\0", 1)[0]
    except (OSError, struct.error, ValueError) as exc:
        raise VisualSceneCgCompileError("无法验证来源 CG 的冻结 resource_name") from exc
    if not raw_name:
        raise VisualSceneCgCompileError("来源 CG 的 resource_name 为空")
    try:
        return raw_name.decode("cp932"), file_size
    except UnicodeDecodeError as exc:
        raise VisualSceneCgCompileError("来源 CG 的 resource_name 不是合法 CP932") from exc


def _read_frozen_source(event_visual: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    raw_path = str(event_visual.get("archive_path") or "").strip()
    if not raw_path:
        raise VisualSceneCgCompileError("冻结 CG 缺少 archive_path")
    archive = Path(raw_path).expanduser().resolve()
    archive_name = archive.name.casefold()
    declared_name = str(event_visual.get("archive_name") or "").strip().casefold()
    if declared_name != archive_name or archive_name not in CG_ARCHIVE_SELECTORS:
        raise VisualSceneCgCompileError("冻结 CG 的 archive_name 与 graph_vis 类型不一致")
    try:
        stat = archive.stat()
    except OSError as exc:
        raise VisualSceneCgCompileError("无法复检来源 CG 归档身份") from exc
    frozen_size = _required_int(event_visual, "archive_size", minimum=1)
    frozen_mtime = _required_int(event_visual, "archive_mtime_ns", minimum=0)
    if int(stat.st_size) != frozen_size or int(stat.st_mtime_ns) != frozen_mtime:
        raise VisualSceneCgCompileError("来源 CG 归档漂移: 大小或修改时间已变化")

    entry_index = _required_int(event_visual, "entry_index", minimum=0)
    entry_size = _required_int(event_visual, "entry_size", minimum=1)
    resource_name = str(event_visual.get("resource_name") or "").strip()
    if not resource_name:
        raise VisualSceneCgCompileError("冻结 CG 缺少 resource_name")
    try:
        payload, info = read_bin_entry_payload(archive, entry_index)
    except (OSError, ResourceBuildError, TypeError, ValueError) as exc:
        raise VisualSceneCgCompileError("来源 CG bounded payload 读取失败") from exc
    payload = bytes(payload)
    if len(payload) != entry_size:
        raise VisualSceneCgCompileError("来源 CG entry_size 与 bounded payload 不一致")
    directory_name, directory_size = _read_directory_name(archive, entry_index)
    if directory_name != resource_name or directory_size != len(payload):
        raise VisualSceneCgCompileError("来源 CG 条目漂移: resource_name 或大小已变化")
    payload_hash = hashlib.sha256(payload).hexdigest()
    expected_hash = str(event_visual.get("payload_sha256") or "").strip()
    if not _SHA256.fullmatch(expected_hash):
        raise VisualSceneCgCompileError("冻结 CG 缺少有效 payload_sha256，请重新选择")
    if expected_hash.casefold() != payload_hash:
        raise VisualSceneCgCompileError("来源 CG payload 与冻结 SHA-256 不一致")
    try:
        metadata = hzc_metadata(payload)
    except BinArchiveError as exc:
        raise VisualSceneCgCompileError(f"来源 CG HZC 元数据无效: {exc}") from exc
    for key in ("width", "height", "frame_count"):
        frozen = _required_int(event_visual, key, minimum=1)
        actual = int(getattr(metadata, key))
        reported = int(info.get(key, actual))
        if frozen != actual or reported != actual:
            raise VisualSceneCgCompileError(f"来源 CG 的 {key} 已漂移")
    selector = _required_int(event_visual, "archive_selector", minimum=0)
    if selector != CG_ARCHIVE_SELECTORS[archive_name]:
        raise VisualSceneCgCompileError("冻结 CG 的 archive_selector 与归档不一致")
    return payload, {
        "read_method": "resource_builder.read_bin_entry_payload",
        "archive_name": archive.name,
        "archive_size": frozen_size,
        "archive_mtime_ns": frozen_mtime,
        "archive_selector": selector,
        "entry_index": entry_index,
        "entry_size": len(payload),
        "resource_name": resource_name,
        "payload_sha256": payload_hash,
        "width": metadata.width,
        "height": metadata.height,
        "frame_count": metadata.frame_count,
        "hzc": metadata.to_dict(),
    }


def compile_visual_scene_cg(
    event_visual: Mapping[str, Any],
    target_archive: bytes,
) -> VisualSceneCgBuild:
    """Compile one cross-game CG as an additive graph_vis* candidate."""

    if not isinstance(event_visual, Mapping):
        raise VisualSceneCgCompileError("冻结 CG 必须是 Mapping")
    if str(event_visual.get("build_mode") or "").casefold() != "copy_hzc":
        raise VisualSceneCgCompileError("冻结 CG build_mode 必须是 copy_hzc")
    if not isinstance(target_archive, bytes):
        raise VisualSceneCgCompileError("目标 graph_vis 归档必须是 bytes")
    archive_name = str(event_visual.get("archive_name") or "").strip().casefold()
    if archive_name not in CG_ARCHIVE_SELECTORS:
        raise VisualSceneCgCompileError("冻结 CG 目标归档类型无效")
    payload, source_report = _read_frozen_source(event_visual)
    target_name = "CG_FVPV2_" + hashlib.sha256(payload).hexdigest()[:16].upper()
    try:
        target_names = archive_entry_names(target_archive)
    except BinArchiveError as exc:
        raise VisualSceneCgCompileError(f"目标 {archive_name} 无效: {exc}") from exc
    if target_name in set(target_names):
        raise VisualSceneCgCompileError(f"目标资源名冲突，拒绝覆盖已有资源: {target_name}")
    try:
        appended = append_hzc_entries(target_archive, {target_name: payload})
    except BinArchiveError as exc:
        raise VisualSceneCgCompileError(f"目标 {archive_name} 只追加失败: {exc}") from exc
    # append_hzc_entries returns only after comparing every original payload
    # and the selected addition against the rebuilt candidate byte-for-byte.
    target_payloads_preserved = True
    source_payload_preserved = True
    added_bytes = len(appended.data) - len(target_archive)
    metadata_bytes = added_bytes - len(payload)
    if metadata_bytes < 0:
        raise VisualSceneCgCompileError("目标 CG 归档增量小于 payload 增量")
    source_sha = hashlib.sha256(target_archive).hexdigest()
    after_sha = hashlib.sha256(appended.data).hexdigest()
    report: dict[str, Any] = {
        "schema": "fvp-studio-v2.visual-scene-cg-build.v1",
        "build_mode": "copy_hzc",
        "target_archive_name": archive_name,
        "target_resource_name": target_name,
        "archive_selector": CG_ARCHIVE_SELECTORS[archive_name],
        "bounded_source_read_count": 1,
        "bounded_source_reference": source_report,
        "payload_bytes": len(payload),
        "archive_metadata_bytes": metadata_bytes,
        "archive_added_bytes": added_bytes,
        "archive_before": {"size": len(target_archive), "sha256": source_sha},
        "archive_after": {"size": len(appended.data), "sha256": after_sha},
        "resource_payloads": {
            target_name: {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        },
        "source_payload_preserved_exactly": source_payload_preserved,
        "target_payloads_preserved_exactly": target_payloads_preserved,
        "no_existing_resource_replaced": True,
        "added_resource_names": [target_name],
        "archive_append": appended.validation_dict(),
    }
    return VisualSceneCgBuild(
        archive=appended.data,
        archive_source_sha256=source_sha,
        target_archive_name=archive_name,
        target_resource_name=target_name,
        archive_selector=CG_ARCHIVE_SELECTORS[archive_name],
        resource_payloads={target_name: payload},
        report=report,
    )


compile_external_fvp_cg = compile_visual_scene_cg


__all__ = [
    "VisualSceneCgBuild",
    "VisualSceneCgCompileError",
    "compile_external_fvp_cg",
    "compile_visual_scene_cg",
]
