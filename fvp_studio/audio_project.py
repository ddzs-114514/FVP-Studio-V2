"""Portable, game-independent project audio assets.

This module is deliberately separate from :mod:`audio_workspace`.  It stores
audio owned by an FVP Studio project, rather than discovering or referencing a
game archive.  ``relative_path`` is relative to ``library_root/assets`` and is
the only path kept in an asset reference; the library root is never serialized.
"""

from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import tempfile
from typing import Any, BinaryIO, Mapping


PROJECT_AUDIO_SCHEMA = "v1"
PROJECT_AUDIO_SOURCE_KIND = "project_asset"
PROJECT_AUDIO_BUILD_MODE = "additive_resource"
PROJECT_AUDIO_MAX_BYTES = 128 * 1024 * 1024
PROJECT_AUDIO_ASSETS_DIR = "assets"
PROJECT_AUDIO_RECORDS_DIR = "records"

_AUDIO_FORMATS = {
    "ogg": "audio/ogg",
    "wav": "audio/wav",
    "mp3": "audio/mpeg",
    "flac": "audio/flac",
}
_TRACKS = frozenset({"bgm", "se"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE_KEYS = frozenset(
    {
        "schema",
        "source_kind",
        "build_mode",
        "compile_ready",
        "preview_only",
        "portable",
        "relative_path",
        "payload_sha256",
        "size",
        "format",
        "mime",
        "track",
        "label",
        "asset_id",
    }
)


class ProjectAudioError(ValueError):
    """Raised when a project audio asset is invalid or has drifted."""


# The longer name is useful to callers that prefer an asset-specific error.
ProjectAudioAssetError = ProjectAudioError


@dataclass(frozen=True)
class _PayloadInfo:
    size: int
    payload_sha256: str
    format: str
    mime: str


def _path_value(value: str | os.PathLike[str], *, field: str) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise ProjectAudioError(f"{field} 必须是路径") from exc
    if isinstance(raw, bytes):
        raise ProjectAudioError(f"{field} 不支持 bytes 路径")
    raw = str(raw)
    if not raw or "\x00" in raw:
        raise ProjectAudioError(f"{field} 无效")
    return raw


def _absolute_lexical_path(value: str | os.PathLike[str], *, field: str) -> Path:
    """Make an absolute path without resolving symlinks."""

    raw = _path_value(value, field=field)
    try:
        return Path(os.path.abspath(os.path.expanduser(raw)))
    except (OSError, RuntimeError) as exc:
        raise ProjectAudioError(f"{field} 无法解析") from exc


def _reject_symlink_components(path: Path, *, field: str) -> None:
    """Reject symlinks in an existing path component, including the leaf."""

    current = Path(os.path.abspath(str(path)))
    while True:
        try:
            if current.is_symlink():
                raise ProjectAudioError(f"{field} 不得包含符号链接: {path}")
        except OSError as exc:
            raise ProjectAudioError(f"{field} 无法检查: {path}") from exc
        parent = current.parent
        if parent == current:
            return
        current = parent


def _library_path(library_root: str | os.PathLike[str]) -> Path:
    root = _absolute_lexical_path(library_root, field="library_root")
    _reject_symlink_components(root, field="library_root")
    if root.exists() and not root.is_dir():
        raise ProjectAudioError("library_root 必须是目录")
    return root


def _safe_relative_path(value: str | os.PathLike[str]) -> str:
    """Normalize one safe, portable path relative to ``assets``."""

    raw = _path_value(value, field="relative_path")
    portable = raw.replace("\\", "/")
    if (
        portable.startswith("/")
        or portable.startswith("//")
        or ntpath.splitdrive(portable)[0]
        or PurePosixPath(portable).is_absolute()
        or PureWindowsPath(raw).is_absolute()
    ):
        raise ProjectAudioError("relative_path 必须是相对路径")

    parts = portable.split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise ProjectAudioError("relative_path 不能包含空段、. 或 ..")
    # A colon in a component can become a Windows drive/ADS path after a move.
    if any(":" in part for part in parts):
        raise ProjectAudioError("relative_path 含有非法路径段")
    return "/".join(parts)


def _ensure_directory(path: Path, *, field: str) -> None:
    _reject_symlink_components(path, field=field)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ProjectAudioError(f"无法创建 {field}: {path}") from exc
    _reject_symlink_components(path, field=field)
    if not path.is_dir():
        raise ProjectAudioError(f"{field} 不是目录: {path}")


def _ensure_layout(root: Path) -> tuple[Path, Path]:
    _ensure_directory(root, field="library_root")
    assets = root / PROJECT_AUDIO_ASSETS_DIR
    records = root / PROJECT_AUDIO_RECORDS_DIR
    _ensure_directory(assets, field="assets")
    _ensure_directory(records, field="records")
    return assets, records


def _asset_path(root: Path, relative_path: str) -> Path:
    assets = root / PROJECT_AUDIO_ASSETS_DIR
    _reject_symlink_components(assets, field="assets")
    target = assets.joinpath(*relative_path.split("/"))
    _reject_symlink_components(target, field="asset path")
    return target


def _audio_type(probe: bytes) -> tuple[str, str] | None:
    if probe.startswith(b"OggS"):
        return "ogg", _AUDIO_FORMATS["ogg"]
    if probe.startswith(b"RIFF") and len(probe) >= 12 and probe[8:12] == b"WAVE":
        return "wav", _AUDIO_FORMATS["wav"]
    if probe.startswith(b"fLaC"):
        return "flac", _AUDIO_FORMATS["flac"]
    if probe.startswith(b"ID3") or (
        len(probe) >= 2 and probe[0] == 0xFF and probe[1] & 0xE0 == 0xE0
    ):
        return "mp3", _AUDIO_FORMATS["mp3"]
    return None


def _info_from_stream(stream: BinaryIO, *, expected_size: int | None = None) -> _PayloadInfo:
    digest = hashlib.sha256()
    probe = bytearray()
    total = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        if not probe:
            probe.extend(chunk[:12])
        elif len(probe) < 12:
            probe.extend(chunk[: 12 - len(probe)])
        total += len(chunk)
        if total > PROJECT_AUDIO_MAX_BYTES:
            raise ProjectAudioError("单个项目音频文件不能超过 128 MiB")
        digest.update(chunk)

    if expected_size is not None and total != expected_size:
        raise ProjectAudioError("音频文件大小在读取期间发生变化")
    if total <= 0:
        raise ProjectAudioError("项目音频文件不能为空")
    audio_type = _audio_type(bytes(probe))
    if audio_type is None:
        raise ProjectAudioError("不支持的项目音频格式，仅支持 OGG/WAV/MP3/FLAC")
    format_name, mime = audio_type
    return _PayloadInfo(total, digest.hexdigest(), format_name, mime)


def _info_from_bytes(payload: bytes | bytearray | memoryview) -> _PayloadInfo:
    try:
        data = bytes(payload)
    except (TypeError, ValueError) as exc:
        raise ProjectAudioError("payload 必须是 bytes") from exc
    if not data:
        raise ProjectAudioError("项目音频文件不能为空")
    if len(data) > PROJECT_AUDIO_MAX_BYTES:
        raise ProjectAudioError("单个项目音频文件不能超过 128 MiB")
    audio_type = _audio_type(data[:12])
    if audio_type is None:
        raise ProjectAudioError("不支持的项目音频格式，仅支持 OGG/WAV/MP3/FLAC")
    format_name, mime = audio_type
    return _PayloadInfo(len(data), hashlib.sha256(data).hexdigest(), format_name, mime)


def _source_fingerprint(path: Path) -> tuple[int, int, int, int]:
    _reject_symlink_components(path, field="source file")
    try:
        info = path.stat()
    except OSError as exc:
        raise ProjectAudioError(f"无法读取 source file: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ProjectAudioError("source file 必须是普通文件")
    return (
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", 0)),
        int(getattr(info, "st_dev", 0)),
        int(getattr(info, "st_ino", 0)),
    )


def _info_from_file(path: Path) -> tuple[_PayloadInfo, tuple[int, int, int, int]]:
    fingerprint = _source_fingerprint(path)
    if fingerprint[0] <= 0:
        raise ProjectAudioError("项目音频文件不能为空")
    if fingerprint[0] > PROJECT_AUDIO_MAX_BYTES:
        raise ProjectAudioError("单个项目音频文件不能超过 128 MiB")
    try:
        with path.open("rb") as source:
            info = _info_from_stream(source, expected_size=fingerprint[0])
    except ProjectAudioError:
        raise
    except OSError as exc:
        raise ProjectAudioError(f"无法读取 source file: {path}") from exc
    if _source_fingerprint(path) != fingerprint:
        raise ProjectAudioError("source file 在读取期间发生变化")
    return info, fingerprint


def _info_from_stored_file(path: Path) -> _PayloadInfo:
    _reject_symlink_components(path, field="asset path")
    try:
        if not path.is_file():
            raise ProjectAudioError(f"资产文件不存在或不是普通文件: {path}")
        with path.open("rb") as stored:
            return _info_from_stream(stored, expected_size=int(path.stat().st_size))
    except ProjectAudioError:
        raise
    except OSError as exc:
        raise ProjectAudioError(f"无法读取资产文件: {path}") from exc


def _same_payload_info(left: _PayloadInfo, right: _PayloadInfo) -> bool:
    return left == right


def _normalise_track(track: Any, kind: Any = None) -> str:
    if track is None:
        track = kind
    elif kind is not None and str(track).strip().casefold() != str(kind).strip().casefold():
        raise ProjectAudioError("track 与 kind 不一致")
    if not isinstance(track, str):
        raise ProjectAudioError("track 必须是 bgm 或 se")
    value = track.strip().casefold()
    if value not in _TRACKS:
        raise ProjectAudioError("track 只支持 bgm 或 se")
    return value


def _make_asset_id(payload_sha256: str, track: str) -> str:
    identity = "\0".join(
        (PROJECT_AUDIO_SCHEMA, PROJECT_AUDIO_SOURCE_KIND, PROJECT_AUDIO_BUILD_MODE, track, payload_sha256)
    ).encode("utf-8")
    return "project-audio-" + hashlib.sha256(identity).hexdigest()[:32]


def _label_value(label: Any, relative_path: str, track: str) -> str:
    if label is None:
        value = Path(relative_path).stem or f"{track} audio"
    elif isinstance(label, str):
        value = label.strip()
    else:
        raise ProjectAudioError("label 必须是字符串")
    if not value:
        raise ProjectAudioError("label 不能为空")
    if "\x00" in value:
        raise ProjectAudioError("label 无效")
    return value


def _make_reference(
    info: _PayloadInfo,
    *,
    relative_path: str,
    track: str,
    label: str,
) -> dict[str, Any]:
    return {
        "schema": PROJECT_AUDIO_SCHEMA,
        "source_kind": PROJECT_AUDIO_SOURCE_KIND,
        "build_mode": PROJECT_AUDIO_BUILD_MODE,
        "compile_ready": True,
        "preview_only": False,
        "portable": True,
        "relative_path": relative_path,
        "payload_sha256": info.payload_sha256,
        "size": info.size,
        "format": info.format,
        "mime": info.mime,
        "track": track,
        "kind": track,
        "label": label,
        "asset_id": _make_asset_id(info.payload_sha256, track),
    }


def _validate_reference_fields(asset_ref: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(asset_ref, Mapping):
        raise ProjectAudioError("asset_ref 必须是 Mapping")
    raw = dict(asset_ref)
    extra = set(raw) - _REFERENCE_KEYS
    if extra:
        raise ProjectAudioError(f"asset_ref 含有不允许的字段: {', '.join(sorted(extra))}")
    missing = _REFERENCE_KEYS - set(raw)
    if missing:
        raise ProjectAudioError(f"asset_ref 缺少字段: {', '.join(sorted(missing))}")
    if raw["schema"] != PROJECT_AUDIO_SCHEMA:
        raise ProjectAudioError("asset_ref schema 必须是 v1")
    if raw["source_kind"] != PROJECT_AUDIO_SOURCE_KIND:
        raise ProjectAudioError("asset_ref source_kind 必须是 project_asset")
    if raw["build_mode"] != PROJECT_AUDIO_BUILD_MODE:
        raise ProjectAudioError("asset_ref build_mode 必须是 additive_resource")
    for field, expected in (("compile_ready", True), ("preview_only", False), ("portable", True)):
        if type(raw[field]) is not bool or raw[field] is not expected:
            raise ProjectAudioError(f"asset_ref {field} 值不符合 v1")

    track = _normalise_track(raw["track"])
    if raw["track"] != track:
        raise ProjectAudioError("asset_ref track 必须是规范值")
    relative_path = _safe_relative_path(raw["relative_path"])
    if raw["relative_path"] != relative_path:
        raise ProjectAudioError("asset_ref relative_path 必须使用规范相对路径")

    digest = raw["payload_sha256"]
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise ProjectAudioError("asset_ref payload_sha256 必须是小写 SHA-256")
    size = raw["size"]
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= PROJECT_AUDIO_MAX_BYTES:
        raise ProjectAudioError("asset_ref size 超出范围")
    format_name = raw["format"]
    mime = raw["mime"]
    if not isinstance(format_name, str) or format_name not in _AUDIO_FORMATS:
        raise ProjectAudioError("asset_ref format/mime 不匹配")
    if not isinstance(mime, str) or mime != _AUDIO_FORMATS[format_name]:
        raise ProjectAudioError("asset_ref format/mime 不匹配")
    if not isinstance(raw["label"], str) or not raw["label"].strip() or "\x00" in raw["label"]:
        raise ProjectAudioError("asset_ref label 无效")
    asset_id = raw["asset_id"]
    if not isinstance(asset_id, str) or asset_id != _make_asset_id(digest, track):
        raise ProjectAudioError("asset_ref asset_id 不稳定或与 payload/track 不匹配")
    return raw


def _unwrap_asset_ref(value: Mapping[str, Any]) -> Mapping[str, Any]:
    nested = value.get("asset_ref") if isinstance(value, Mapping) else None
    if isinstance(nested, Mapping):
        return nested
    # ``list_project_audio_assets`` adds the UI-only kind alias.  It is not
    # written to records, but accepting the entry here keeps validation useful
    # at the same UI boundary.
    if isinstance(value, Mapping) and "kind" in value:
        candidate = dict(value)
        candidate.pop("kind", None)
        return candidate
    return value


def _load_json_record(path: Path) -> dict[str, Any]:
    _reject_symlink_components(path, field="record path")
    try:
        with path.open("r", encoding="utf-8") as source:
            raw = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectAudioError(f"无法读取项目音频记录: {path.name}") from exc
    if not isinstance(raw, dict):
        raise ProjectAudioError(f"项目音频记录不是对象: {path.name}")
    return raw


def _validate_existing_reference(root: Path, raw: Mapping[str, Any]) -> dict[str, Any]:
    reference = _validate_reference_fields(_unwrap_asset_ref(raw))
    target = _asset_path(root, reference["relative_path"])
    if not target.exists() or target.is_symlink():
        raise ProjectAudioError("项目音频记录引用的 payload 不存在")
    actual = _info_from_stored_file(target)
    expected = _PayloadInfo(
        reference["size"],
        reference["payload_sha256"],
        reference["format"],
        reference["mime"],
    )
    if not _same_payload_info(actual, expected):
        raise ProjectAudioError("项目音频 payload 的 hash、size 或格式已漂移")
    return reference


def _validate_existing_reference_metadata(
    root: Path,
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a listing row without hashing the complete audio payload.

    The browser may refresh the library frequently while a 300+ MiB game BIN
    scan is also running.  Full content identity remains mandatory at import,
    preview, staging, and target build boundaries; the list view only needs a
    safe record, exact size, and the 12-byte format signature.
    """

    reference = _validate_reference_fields(_unwrap_asset_ref(raw))
    target = _asset_path(root, reference["relative_path"])
    try:
        if target.is_symlink() or not target.is_file():
            raise ProjectAudioError("项目音频记录引用的 payload 不存在")
        if int(target.stat().st_size) != int(reference["size"]):
            raise ProjectAudioError("项目音频 payload 大小已漂移")
        with target.open("rb") as stored:
            detected = _audio_type(stored.read(12))
    except ProjectAudioError:
        raise
    except OSError as exc:
        raise ProjectAudioError(f"无法读取项目音频资产: {target}") from exc
    if detected != (reference["format"], reference["mime"]):
        raise ProjectAudioError("项目音频 payload 格式已漂移")
    return reference


def _find_existing_reference(
    root: Path,
    records: Path,
    *,
    asset_id: str,
    payload_sha256: str,
    track: str,
) -> dict[str, Any] | None:
    desired_record = records / f"{asset_id}.json"
    if desired_record.exists() or desired_record.is_symlink():
        if desired_record.is_symlink():
            raise ProjectAudioError("项目音频记录不得是符号链接")
        reference = _validate_existing_reference(root, _load_json_record(desired_record))
        if reference["asset_id"] != asset_id:
            raise ProjectAudioError("项目音频记录文件名与 asset_id 不一致")
        return reference

    try:
        candidates = sorted(records.iterdir(), key=lambda item: item.name.casefold())
    except OSError as exc:
        raise ProjectAudioError("无法读取项目音频 records") from exc
    for candidate in candidates:
        if candidate.suffix.casefold() != ".json":
            continue
        if candidate.is_symlink():
            raise ProjectAudioError("项目音频记录不得是符号链接")
        raw = _load_json_record(candidate)
        reference = _validate_reference_fields(_unwrap_asset_ref(raw))
        if reference["payload_sha256"] == payload_sha256 and reference["track"] == track:
            if reference["asset_id"] != asset_id:
                raise ProjectAudioError("项目音频记录的稳定 asset_id 已漂移")
            return _validate_existing_reference(root, reference)
    return None


def _existing_target_info(target: Path, expected: _PayloadInfo) -> bool:
    if not target.exists() and not target.is_symlink():
        return False
    if target.is_symlink():
        raise ProjectAudioError("资产目标不得是符号链接")
    if not target.is_file():
        raise ProjectAudioError("资产目标不是普通文件")
    actual = _info_from_stored_file(target)
    if not _same_payload_info(actual, expected):
        raise ProjectAudioError("不能用不同内容覆盖已有项目音频资产")
    return True


def _atomic_write_payload(
    target: Path,
    expected: _PayloadInfo,
    *,
    payload: bytes | None = None,
    source_path: Path | None = None,
    source_fingerprint: tuple[int, int, int, int] | None = None,
) -> None:
    parent = target.parent
    _ensure_directory(parent, field="asset directory")
    temp_name: str | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=str(parent)
        )
        with os.fdopen(fd, "wb") as destination:
            digest = hashlib.sha256()
            total = 0
            if payload is not None:
                destination.write(payload)
                digest.update(payload)
                total = len(payload)
            elif source_path is not None:
                _reject_symlink_components(source_path, field="source file")
                with source_path.open("rb") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        destination.write(chunk)
                        digest.update(chunk)
                        total += len(chunk)
                        if total > PROJECT_AUDIO_MAX_BYTES:
                            raise ProjectAudioError("单个项目音频文件不能超过 128 MiB")
            else:
                raise ProjectAudioError("缺少 payload")
            destination.flush()
            os.fsync(destination.fileno())
        if total != expected.size or digest.hexdigest() != expected.payload_sha256:
            raise ProjectAudioError("写入临时项目音频时 payload 身份不一致")
        if source_path is not None and source_fingerprint is not None:
            if _source_fingerprint(source_path) != source_fingerprint:
                raise ProjectAudioError("source file 在写入期间发生变化")
        # Recheck before replace so an independently created different file is
        # never intentionally replaced.
        if target.exists() or target.is_symlink():
            if not _existing_target_info(target, expected):
                raise ProjectAudioError("资产目标在写入期间发生变化")
            return
        os.replace(temp_name, target)
        temp_name = None
        final = _info_from_stored_file(target)
        if not _same_payload_info(final, expected):
            raise ProjectAudioError("最终项目音频 payload SHA-256 校验失败")
    except ProjectAudioError:
        raise
    except OSError as exc:
        raise ProjectAudioError(f"无法原子写入项目音频资产: {target}") from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _atomic_write_record(path: Path, reference: Mapping[str, Any]) -> None:
    _ensure_directory(path.parent, field="records")
    expected = dict(reference)
    if path.exists() or path.is_symlink():
        if path.is_symlink():
            raise ProjectAudioError("项目音频记录不得是符号链接")
        current = _load_json_record(path)
        if current != expected:
            raise ProjectAudioError("不能用不同元数据覆盖已有项目音频记录")
        return

    temp_name: str | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as destination:
            json.dump(expected, destination, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        if path.exists() or path.is_symlink():
            if path.is_symlink() or _load_json_record(path) != expected:
                raise ProjectAudioError("项目音频记录在写入期间发生变化")
            return
        os.replace(temp_name, path)
        temp_name = None
        if _load_json_record(path) != expected:
            raise ProjectAudioError("最终项目音频记录校验失败")
    except ProjectAudioError:
        raise
    except OSError as exc:
        raise ProjectAudioError(f"无法原子写入项目音频记录: {path.name}") from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _import_info(
    root: Path,
    info: _PayloadInfo,
    *,
    track: str,
    label: Any,
    relative_path: str | os.PathLike[str] | None,
    payload: bytes | None = None,
    source_path: Path | None = None,
    source_fingerprint: tuple[int, int, int, int] | None = None,
) -> dict[str, Any]:
    normal_path = (
        _safe_relative_path(relative_path)
        if relative_path is not None
        else f"{info.payload_sha256}.{info.format}"
    )
    label_value = _label_value(label, normal_path, track)
    assets, records = _ensure_layout(root)
    reference = _make_reference(
        info,
        relative_path=normal_path,
        track=track,
        label=label_value,
    )
    existing = _find_existing_reference(
        root,
        records,
        asset_id=reference["asset_id"],
        payload_sha256=info.payload_sha256,
        track=track,
    )
    if existing is not None:
        if source_path is not None:
            current_info, current_fingerprint = _info_from_file(source_path)
            if current_info != info or current_fingerprint != source_fingerprint:
                raise ProjectAudioError("source file 在导入期间发生变化")
        return copy.deepcopy(existing)

    target = assets.joinpath(*normal_path.split("/"))
    _reject_symlink_components(target, field="asset path")
    if not _existing_target_info(target, info):
        _atomic_write_payload(
            target,
            info,
            payload=payload,
            source_path=source_path,
            source_fingerprint=source_fingerprint,
        )
    _atomic_write_record(records / f"{reference['asset_id']}.json", reference)
    # Read back the exact on-disk pair so a successful return is also a local
    # acceptance check, not merely a check of the input bytes.
    return copy.deepcopy(_validate_existing_reference(root, reference))


def import_project_audio_bytes(
    library_root: str | os.PathLike[str],
    payload: bytes | bytearray | memoryview,
    track: str | None = None,
    label: str | None = None,
    relative_path: str | os.PathLike[str] | None = None,
    *,
    kind: str | None = None,
) -> dict[str, Any]:
    """Import bytes into a portable project audio library.

    ``relative_path`` is relative to ``library_root/assets``.  When omitted,
    the content-addressed ``<sha256>.<format>`` path is used.
    """

    # Accept the occasional natural ``(payload, library_root, ...)`` call while
    # keeping the documented, explicit library_root-first form unambiguous.
    if isinstance(library_root, (bytes, bytearray, memoryview)) and not isinstance(
        payload, (bytes, bytearray, memoryview)
    ):
        library_root, payload = payload, library_root
    root = _library_path(library_root)
    track_value = _normalise_track(track, kind)
    info = _info_from_bytes(payload)
    return _import_info(
        root,
        info,
        track=track_value,
        label=label,
        relative_path=relative_path,
        payload=bytes(payload),
    )


def import_project_audio_file(
    library_root: str | os.PathLike[str],
    source_file: str | os.PathLike[str] | None = None,
    track: str | None = None,
    label: str | None = None,
    relative_path: str | os.PathLike[str] | None = None,
    *,
    kind: str | None = None,
    source_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Import one local audio file without storing its absolute source path."""

    if source_path is not None:
        if source_file is not None and str(source_file) != str(source_path):
            raise ProjectAudioError("source_file 与 source_path 不一致")
        source_file = source_path
    if source_file is None:
        raise ProjectAudioError("必须指定 source_file")
    # Also tolerate source-first positional use when the two existing paths
    # make the intent unambiguous; the persisted reference remains unchanged.
    first = _absolute_lexical_path(library_root, field="library_root")
    second = _absolute_lexical_path(source_file, field="source_file")
    if first.is_file() and not second.is_file():
        first, second = second, first
    root = _library_path(first)
    source = second
    track_value = _normalise_track(track, kind)
    info, fingerprint = _info_from_file(source)
    return _import_info(
        root,
        info,
        track=track_value,
        label=label,
        relative_path=relative_path,
        source_path=source,
        source_fingerprint=fingerprint,
    )


def validate_project_audio_asset(
    asset_ref: Mapping[str, Any] | str | os.PathLike[str],
    library_root: str | os.PathLike[str] | Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one reference and its stored payload, raising on any drift."""

    if not isinstance(asset_ref, Mapping) and isinstance(library_root, Mapping):
        asset_ref, library_root = library_root, asset_ref
    if not isinstance(asset_ref, Mapping):
        raise ProjectAudioError("asset_ref 必须是 Mapping")
    root = _library_path(library_root)  # type: ignore[arg-type]
    reference = _validate_existing_reference(root, _unwrap_asset_ref(asset_ref))
    result = copy.deepcopy(reference)
    entry = copy.deepcopy(reference)
    entry["kind"] = entry["track"]
    result.update(
        {
            "valid": True,
            "ok": True,
            "asset_ref": copy.deepcopy(reference),
            "entry": entry,
            "kind": reference["track"],
        }
    )
    return result


def list_project_audio_assets(
    library_root: str | os.PathLike[str],
    *,
    verify_payloads: bool = True,
) -> dict[str, Any]:
    """Return a source object whose entries can be merged into the audio UI.

    ``verify_payloads=False`` is the latency-bounded browser-listing mode.  It
    still rejects unsafe paths, symlinks, size drift, and format drift, while
    deferring the full SHA-256 pass to the selected-asset boundary.
    """

    root = _library_path(library_root)
    records = root / PROJECT_AUDIO_RECORDS_DIR
    if records.is_symlink():
        raise ProjectAudioError("records 不得是符号链接")
    if not records.exists():
        return {
            "schema": PROJECT_AUDIO_SCHEMA,
            "source_kind": PROJECT_AUDIO_SOURCE_KIND,
            "build_mode": PROJECT_AUDIO_BUILD_MODE,
            "compile_ready": True,
            "preview_only": False,
            "portable": True,
            "read_only": True,
            "audio_count": 0,
            "bgm_count": 0,
            "se_count": 0,
            "entries": [],
        }
    if records.is_symlink() or not records.is_dir():
        raise ProjectAudioError("records 必须是普通目录")
    _reject_symlink_components(records, field="records")
    try:
        candidates = sorted(records.iterdir(), key=lambda item: item.name.casefold())
    except OSError as exc:
        raise ProjectAudioError("无法读取项目音频 records") from exc

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for candidate in candidates:
        if candidate.suffix.casefold() != ".json":
            continue
        if candidate.is_symlink():
            raise ProjectAudioError("项目音频记录不得是符号链接")
        raw = _load_json_record(candidate)
        reference = (
            _validate_existing_reference(root, raw)
            if verify_payloads
            else _validate_existing_reference_metadata(root, raw)
        )
        if candidate.stem != reference["asset_id"]:
            raise ProjectAudioError("项目音频记录文件名与 asset_id 不一致")
        if reference["asset_id"] in seen_ids:
            raise ProjectAudioError("项目音频记录存在重复 asset_id")
        seen_ids.add(reference["asset_id"])
        entry = copy.deepcopy(reference)
        entry["kind"] = entry["track"]
        entries.append(entry)
    entries.sort(key=lambda item: (item["track"], item["label"].casefold(), item["asset_id"]))
    return {
        "schema": PROJECT_AUDIO_SCHEMA,
        "source_kind": PROJECT_AUDIO_SOURCE_KIND,
        "build_mode": PROJECT_AUDIO_BUILD_MODE,
        "compile_ready": True,
        "preview_only": False,
        "portable": True,
        "read_only": True,
        "audio_count": len(entries),
        "bgm_count": sum(item["track"] == "bgm" for item in entries),
        "se_count": sum(item["track"] == "se" for item in entries),
        "entries": entries,
    }


def list_project_audio_asset_entries(
    library_root: str | os.PathLike[str],
) -> list[dict[str, Any]]:
    """Return only the UI-ready project audio entries."""

    return list_project_audio_assets(library_root)["entries"]


__all__ = [
    "PROJECT_AUDIO_ASSETS_DIR",
    "PROJECT_AUDIO_BUILD_MODE",
    "PROJECT_AUDIO_MAX_BYTES",
    "PROJECT_AUDIO_RECORDS_DIR",
    "PROJECT_AUDIO_SCHEMA",
    "PROJECT_AUDIO_SOURCE_KIND",
    "ProjectAudioAssetError",
    "ProjectAudioError",
    "import_project_audio_bytes",
    "import_project_audio_file",
    "list_project_audio_asset_entries",
    "list_project_audio_assets",
    "validate_project_audio_asset",
]
