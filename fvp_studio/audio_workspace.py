"""Read-only audio discovery and frozen V2 stage references.

The audio workspace deliberately stops at the boundary before a compiler or
installer.  A source scan reads the BIN directory through the existing
``build_bin_patch.read_archive`` adapter and probes at most twelve bytes from
each entry.  Selecting one entry is the explicit freeze point: only then is
that entry streamed once for a bounded SHA-256 identity.  No function ABI,
HCB call target, or archive rebuild is inferred here.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
from functools import lru_cache
from pathlib import Path
import re
import sys
import time
from typing import Any, Mapping

from .profile import adapter_root_dir


AUDIO_ARCHIVES = ("bgm.bin", "bgm2.bin", "se.bin")
AUDIO_ARCHIVE_KINDS = {
    "bgm.bin": "bgm",
    "bgm2.bin": "bgm2",
    "se.bin": "se",
}
AUDIO_STAGE_SCHEMA = "fvp-studio-v2.audio-stage.v1"
AUDIO_TRACK_SCHEMA = "fvp-studio-v2.audio-track.v1"
AUDIO_MAX_ENTRY_BYTES = 128 * 1024 * 1024
AUDIO_MAGIC_BYTES = 12
AUDIO_SCAN_CHUNK_BYTES = 1024 * 1024
_NUMERIC_RESOURCE_NAME = re.compile(r"^[0-9]+$")


class AudioWorkspaceError(ValueError):
    """Raised when an audio source or staged track is unsafe to use."""


def _load_build_bin_patch() -> Any:
    """Load the existing stream adapter without copying its implementation."""

    try:
        from .adapters import load
        return load("build_bin_patch")
    except ImportError as exc:
        raise AudioWorkspaceError(f"无法加载资源工具 build_bin_patch: {exc}") from exc


# Keep the dependency visible for tests and for the audit trail.  A portable
# V2 checkout without the optional adapter can still import this module; the
# first real scan then reports the Chinese error from _build_bin_patch().
try:
    build_bin_patch: Any = _load_build_bin_patch()
except AudioWorkspaceError:
    build_bin_patch = None


def _build_bin_patch() -> Any:
    global build_bin_patch
    if build_bin_patch is None:
        build_bin_patch = _load_build_bin_patch()
    return build_bin_patch


def _same_directory(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve() == right.resolve()


def _resolve_current_root(
    current_game_dir: str | Path | None,
    current_game_root: str | Path | None,
) -> Path | None:
    if current_game_dir is not None and current_game_root is not None:
        left = Path(current_game_dir).expanduser().resolve()
        right = Path(current_game_root).expanduser().resolve()
        if not _same_directory(left, right):
            raise AudioWorkspaceError("当前游戏目录与当前游戏根不一致")
        return right
    raw = current_game_root if current_game_root is not None else current_game_dir
    return Path(raw).expanduser().resolve() if raw is not None else None


def _archive_paths(requested: Path) -> tuple[Path, list[Path]]:
    allowed = {name.casefold(): name for name in AUDIO_ARCHIVES}
    if requested.is_file():
        if requested.name.casefold() not in allowed:
            raise AudioWorkspaceError(
                "音频来源文件必须是 bgm.bin、bgm2.bin 或 se.bin，也可以填写游戏目录"
            )
        return requested.parent, [requested]
    if not requested.is_dir():
        raise AudioWorkspaceError(f"音频来源路径不存在: {requested}")
    try:
        direct_children = {
            item.name.casefold(): item
            for item in requested.iterdir()
            if item.is_file()
        }
    except OSError as exc:
        raise AudioWorkspaceError(f"无法读取音频来源目录: {requested}") from exc
    archives = [
        direct_children[canonical]
        for canonical in (name.casefold() for name in AUDIO_ARCHIVES)
        if canonical in direct_children
    ]
    if not archives:
        raise AudioWorkspaceError(
            "游戏目录中找不到 bgm.bin / bgm2.bin / se.bin: " f"{requested}"
        )
    return requested, archives


def _decode_entry_name(names: Any, name_offset: Any) -> str:
    if not isinstance(names, (bytes, bytearray, memoryview)):
        return ""
    try:
        offset = int(name_offset)
    except (TypeError, ValueError):
        return ""
    raw_names = bytes(names)
    if not 0 <= offset < len(raw_names):
        return ""
    raw = raw_names[offset:].split(b"\0", 1)[0]
    return raw.decode("cp932", errors="replace").strip()


def _entry_field(entry: Any, field: str, default: Any = None) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(field, default)
    return getattr(entry, field, default)


def _audio_type(magic: bytes) -> tuple[str, str] | None:
    """Return ``(format, mime)`` from no more than the supplied probe bytes."""

    if magic.startswith(b"OggS"):
        return "ogg", "audio/ogg"
    if magic.startswith(b"RIFF") and len(magic) >= 12 and magic[8:12] == b"WAVE":
        return "wav", "audio/wav"
    if magic.startswith(b"ID3") or (
        len(magic) >= 2 and magic[0] == 0xFF and magic[1] & 0xE0 == 0xE0
    ):
        return "mp3", "audio/mpeg"
    if magic.startswith(b"fLaC"):
        return "flac", "audio/flac"
    return None


def _native_id(kind: str, resource_name: str) -> int | None:
    if not _NUMERIC_RESOURCE_NAME.fullmatch(resource_name):
        return None
    value = int(resource_name)
    return value + 1000 if kind == "bgm2" else value


def _audio_label(kind: str, resource_name: str, entry_index: int) -> str:
    prefix = {"bgm": "BGM", "bgm2": "BGM2", "se": "SE"}[kind]
    return f"{prefix} {resource_name}" if resource_name else f"{prefix} entry #{entry_index}"


def _read_entry_magic(archive: Path, offset: int, size: int) -> bytes:
    """Read only the bounded magic probe for one directory entry."""

    count = min(AUDIO_MAGIC_BYTES, max(0, int(size)))
    with archive.open("rb") as source:
        source.seek(int(offset))
        magic = source.read(count)
    if len(magic) != count:
        raise AudioWorkspaceError(
            f"音频归档条目 magic 读取不完整: {archive.name} @ {offset}"
        )
    return magic


def _archive_scan_revision(
    archive_name: str,
    archive_size: int,
    archive_mtime_ns: int,
    entries: list[dict[str, Any]],
) -> str:
    material = [f"{archive_name}:{archive_size}:{archive_mtime_ns}"]
    material.extend(
        "{index}:{name}:{size}:{magic}:{format}".format(
            index=item["entry_index"],
            name=item["resource_name"],
            size=item["entry_size"],
            magic=item["magic_hex"],
            format=item["format"],
        )
        for item in entries
    )
    return hashlib.sha256("|".join(material).encode("utf-8")).hexdigest()[:16]


def _scan_archive_uncached(
    archive_path: str,
    archive_size: int,
    archive_mtime_ns: int,
    archive_ctime_ns: int,
) -> dict[str, Any]:
    del archive_ctime_ns
    archive = Path(archive_path)
    try:
        entries, names = _build_bin_patch().read_archive(archive)
    except (OSError, TypeError, ValueError) as exc:
        raise AudioWorkspaceError(f"无法读取音频归档目录: {archive}") from exc

    scanned: list[dict[str, Any]] = []
    skipped = 0
    for entry_index, entry in enumerate(entries):
        try:
            offset = int(_entry_field(entry, "offset"))
            entry_size = int(_entry_field(entry, "size"))
            if (
                offset < 0
                or entry_size <= 0
                or offset + entry_size > int(archive_size)
            ):
                raise ValueError("条目范围越过归档")
            magic = _read_entry_magic(archive, offset, entry_size)
            audio_type = _audio_type(magic)
            if audio_type is None:
                skipped += 1
                continue
            resource_name = _decode_entry_name(
                names, _entry_field(entry, "name_offset")
            )
            format_name, mime = audio_type
            archive_kind = AUDIO_ARCHIVE_KINDS[archive.name.casefold()]
            scanned.append(
                {
                    "entry_index": int(entry_index),
                    "entry_size": entry_size,
                    "resource_name": resource_name,
                    "native_id": _native_id(archive_kind, resource_name),
                    "label": _audio_label(archive_kind, resource_name, entry_index),
                    "kind": archive_kind,
                    "mime": mime,
                    "format": format_name,
                    "magic": magic[:4].decode("latin1", errors="replace"),
                    "magic_hex": magic.hex(),
                }
            )
        except AudioWorkspaceError:
            raise
        except (OSError, TypeError, ValueError):
            skipped += 1

    try:
        after = archive.stat()
    except OSError as exc:
        raise AudioWorkspaceError(f"无法复检音频归档: {archive}") from exc
    if (
        int(after.st_size) != int(archive_size)
        or int(after.st_mtime_ns) != int(archive_mtime_ns)
    ):
        raise AudioWorkspaceError("音频来源归档在扫描期间已变化，请重新扫描")
    return {
        "archive_name": archive.name,
        "archive_path": str(archive),
        "entry_count": len(entries),
        "audio_count": len(scanned),
        "skipped_count": skipped,
        "revision": _archive_scan_revision(
            archive.name,
            int(archive_size),
            int(archive_mtime_ns),
            scanned,
        ),
        "entries": scanned,
    }


@lru_cache(maxsize=32)
def _cached_archive_scan(
    archive_path: str,
    archive_size: int,
    archive_mtime_ns: int,
    archive_ctime_ns: int,
) -> dict[str, Any]:
    """Cache only directory/magic metadata, keyed by a lightweight stat."""

    return _scan_archive_uncached(
        archive_path,
        archive_size,
        archive_mtime_ns,
        archive_ctime_ns,
    )


def clear_audio_scan_cache() -> None:
    """Clear the process-local metadata cache (mainly useful for tests)."""

    _cached_archive_scan.cache_clear()


def _asset_id(
    root: Path,
    archive: Path,
    archive_size: int,
    archive_mtime_ns: int,
    raw: Mapping[str, Any],
) -> str:
    identity = "\0".join(
        (
            str(root).casefold(),
            archive.name.casefold(),
            str(int(archive_size)),
            str(int(archive_mtime_ns)),
            str(int(raw["entry_index"])),
            str(raw.get("resource_name") or ""),
            str(int(raw.get("entry_size") or 0)),
            str(raw.get("magic_hex") or ""),
        )
    )
    return "audio-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def scan_audio_source(
    path: str | Path,
    current_game_dir: str | Path | None = None,
    *,
    current_game_root: str | Path | None = None,
) -> dict[str, Any]:
    """Scan exact audio archives without reading complete payloads."""

    started = time.perf_counter()
    requested = Path(path).expanduser().resolve()
    root, archives = _archive_paths(requested)
    current_root = _resolve_current_root(current_game_dir, current_game_root)
    is_current_game = current_root is not None and _same_directory(root, current_root)
    source_mode = "current_game" if is_current_game else "external_game"
    result_source_kind = "current_game" if is_current_game else "other_fvp_game"
    result_build_mode = "direct_reference" if is_current_game else "preview_only"
    source_game = root.name or str(root)

    assets: list[dict[str, Any]] = []
    archive_summaries: list[dict[str, Any]] = []
    cache_hits = 0
    skipped_count = 0
    revision_parts: list[str] = []

    for archive in archives:
        try:
            stat = archive.stat()
        except OSError as exc:
            raise AudioWorkspaceError(f"无法读取音频归档 stat: {archive}") from exc
        before_hits = _cached_archive_scan.cache_info().hits
        try:
            archive_scan = copy.deepcopy(
                _cached_archive_scan(
                    str(archive),
                    int(stat.st_size),
                    int(stat.st_mtime_ns),
                    int(stat.st_ctime_ns),
                )
            )
        except AudioWorkspaceError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise AudioWorkspaceError(f"无法扫描音频归档: {archive}") from exc
        if _cached_archive_scan.cache_info().hits > before_hits:
            cache_hits += 1

        archive_name = archive.name
        archive_kind = AUDIO_ARCHIVE_KINDS[archive_name.casefold()]
        skipped_count += int(archive_scan.get("skipped_count") or 0)
        archive_revision = str(archive_scan.get("revision") or "")
        revision_parts.append(
            f"{archive_name}:{int(stat.st_size)}:{int(stat.st_mtime_ns)}:{archive_revision}"
        )
        archive_summaries.append(
            {
                "archive": archive_name,
                "archive_name": archive_name,
                "path": str(archive),
                "archive_path": str(archive),
                "size": int(stat.st_size),
                "mtime": int(stat.st_mtime_ns),
                "archive_size": int(stat.st_size),
                "archive_mtime_ns": int(stat.st_mtime_ns),
                "entry_count": int(archive_scan.get("entry_count") or 0),
                "audio_count": int(archive_scan.get("audio_count") or 0),
                "skipped_count": int(archive_scan.get("skipped_count") or 0),
                "revision": archive_revision,
            }
        )
        for raw in archive_scan.get("entries", []):
            if not isinstance(raw, Mapping):
                continue
            native_id = raw.get("native_id")
            # The verified native wrappers use positive resource IDs; zero is
            # a control/no-selection sentinel in the original call paths.
            compile_ready = bool(
                is_current_game and native_id is not None and native_id > 0
            )
            asset_build_mode = "direct_reference" if compile_ready else "preview_only"
            asset = {
                "asset_id": _asset_id(
                    root,
                    archive,
                    int(stat.st_size),
                    int(stat.st_mtime_ns),
                    raw,
                ),
                "source_kind": "native" if is_current_game else "fvp_external",
                "source_mode": source_mode,
                "build_mode": asset_build_mode,
                "compile_ready": compile_ready,
                "preview_only": not compile_ready,
                "source_game": source_game,
                "project_dir": str(root),
                "archive": archive_name,
                "archive_name": archive_name,
                "path": str(archive),
                "archive_path": str(archive),
                "size": int(raw.get("entry_size") or 0),
                "mtime": int(stat.st_mtime_ns),
                "archive_size": int(stat.st_size),
                "archive_mtime_ns": int(stat.st_mtime_ns),
                "entry_index": int(raw["entry_index"]),
                "entry_size": int(raw.get("entry_size") or 0),
                "payload_size": int(raw.get("entry_size") or 0),
                "resource_name": str(raw.get("resource_name") or ""),
                "label": str(raw.get("label") or ""),
                "native_id": native_id,
                "kind": str(raw.get("kind") or archive_kind),
                "track": "se" if archive_kind == "se" else "bgm",
                "mime": str(raw.get("mime") or ""),
                "format": str(raw.get("format") or ""),
                "magic": str(raw.get("magic") or ""),
                "magic_hex": str(raw.get("magic_hex") or ""),
                "revision": "",
                "scan_seconds": 0.0,
            }
            if native_id is None:
                asset["compile_blocked_reason"] = "resource_name 不是纯数字，无法映射 native_id"
            elif native_id <= 0:
                asset["compile_blocked_reason"] = "native_id 必须大于 0"
            assets.append(asset)

    revision = hashlib.sha256("|".join(revision_parts).encode("utf-8")).hexdigest()[:16]
    scan_seconds = round(time.perf_counter() - started, 3)
    for asset in assets:
        asset["revision"] = revision
        asset["scan_seconds"] = scan_seconds

    compile_ready_count = sum(bool(item.get("compile_ready")) for item in assets)
    return {
        "schema": "fvp-studio-v2.audio-source.v1",
        "project_dir": str(root),
        "source_game": source_game,
        "source_kind": result_source_kind,
        "source_mode": source_mode,
        "build_mode": result_build_mode,
        "is_current_game": is_current_game,
        "read_only": True,
        "archives": archive_summaries,
        "audio_count": len(assets),
        "compile_ready_count": compile_ready_count,
        "preview_only_count": len(assets) - compile_ready_count,
        "skipped_count": skipped_count,
        "cache_hit": bool(archives) and cache_hits == len(archives),
        "cache_hits": cache_hits,
        "scan_seconds": scan_seconds,
        "revision": revision,
        "entries": assets,
    }


# The plural spelling is convenient for callers and keeps compatibility with
# the task wording; the singular spelling follows the existing CG/background
# workspace modules.
scan_audio_sources = scan_audio_source
scan_audio_workspace = scan_audio_source


def _normalise_track_kind(value: Any) -> str:
    normalized = str(value or "").strip().casefold()
    if normalized in {"bgm", "bgm2"}:
        return "bgm"
    if normalized == "se":
        return "se"
    raise AudioWorkspaceError("音频 track 必须是 bgm 或 se")


def _normalise_action(track: str, value: Any, *, default: str) -> str:
    action = str(default if value is None else value).strip().casefold()
    allowed = {"keep", "play", "stop"} if track == "bgm" else {"none", "play", "stop_all"}
    if action not in allowed:
        if track == "bgm":
            raise AudioWorkspaceError("BGM action 必须是 keep、play 或 stop")
        raise AudioWorkspaceError("SE action 必须是 none、play 或 stop_all")
    return action


def _bounded_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise AudioWorkspaceError(f"{label}必须是整数")
    if isinstance(value, float) and not value.is_integer():
        raise AudioWorkspaceError(f"{label}必须是整数")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise AudioWorkspaceError(f"{label}必须是整数") from exc
    if not minimum <= number <= maximum:
        raise AudioWorkspaceError(f"{label}必须在 {minimum} 到 {maximum} 之间")
    return number


def _volume(value: Any) -> int:
    return _bounded_integer(value, "音量", 0, 100)


def _transition_ms(value: Any) -> int:
    return _bounded_integer(value, "transition_ms", 0, 60000)


def _loop(value: Any) -> bool:
    if not isinstance(value, bool):
        raise AudioWorkspaceError("loop 必须是布尔值")
    return value


def _settings_mapping(settings: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if settings is None:
        return {}
    if not isinstance(settings, Mapping):
        raise AudioWorkspaceError("音频 settings 必须是对象")
    return settings


def _setting(
    settings: Mapping[str, Any],
    key: str,
    explicit: Any,
    current: Any,
    default: Any,
) -> Any:
    if explicit is not None:
        return explicit
    if key in settings:
        return settings[key]
    return current if current is not None else default


def _normalise_build_mode(asset: Mapping[str, Any]) -> str:
    raw = str(asset.get("build_mode") or "").strip().casefold()
    if raw in {"direct_reference", "native", "current_game"}:
        return "direct_reference"
    if raw in {"preview_only", "preview", "copy_hzc", "external_game"}:
        return "preview_only"
    if raw in {"additive_resource", "project_asset", "portable_project"}:
        return "additive_resource"
    if not raw:
        return (
            "direct_reference"
            if bool(asset.get("compile_ready"))
            else "preview_only"
        )
    raise AudioWorkspaceError(
        "音频 build_mode 必须是 direct_reference、additive_resource 或 preview_only"
    )


def _compile_ready(asset: Mapping[str, Any], build_mode: str) -> bool:
    raw = asset.get("compile_ready")
    if raw is not None and not isinstance(raw, bool):
        raise AudioWorkspaceError("音频 compile_ready 必须是布尔值")
    return bool(
        build_mode in {"direct_reference", "additive_resource"}
        and (raw is None or raw)
    )


def _archive_name_from_asset(asset: Mapping[str, Any]) -> str:
    raw = str(asset.get("archive_name") or asset.get("archive") or "").strip()
    if not raw:
        raise AudioWorkspaceError("音频缺少精确来源归档名")
    return Path(raw).name


def _archive_path_from_asset(asset: Mapping[str, Any]) -> Path:
    raw = str(asset.get("archive_path") or asset.get("path") or "").strip()
    if not raw:
        raise AudioWorkspaceError("音频缺少精确来源归档路径")
    return Path(raw).expanduser().resolve()


def _validate_asset_identity(asset: Mapping[str, Any]) -> tuple[str, str, Path, int]:
    asset_id = str(asset.get("asset_id") or "").strip()
    if not asset_id:
        raise AudioWorkspaceError("音频资源缺少稳定 asset_id")
    kind = str(asset.get("kind") or "").strip().casefold()
    if kind not in {"bgm", "bgm2", "se"}:
        raise AudioWorkspaceError("音频 kind 必须是 bgm、bgm2 或 se")
    archive_name = _archive_name_from_asset(asset)
    archive_key = archive_name.casefold()
    if archive_key not in AUDIO_ARCHIVE_KINDS:
        raise AudioWorkspaceError("音频来源归档类型不受支持")
    if AUDIO_ARCHIVE_KINDS[archive_key] != kind:
        raise AudioWorkspaceError("音频 kind 与来源归档不一致")
    archive = _archive_path_from_asset(asset)
    if archive.name.casefold() != archive_key or not archive.is_file():
        raise AudioWorkspaceError(f"音频来源归档不存在或名称不一致: {archive}")
    resource_name = str(asset.get("resource_name") or "").strip()
    native_id = _native_id(kind, resource_name)
    if native_id is None:
        raise AudioWorkspaceError("音频 resource_name 必须是纯数字，才能映射 native_id")
    if asset.get("native_id") is not None:
        try:
            reported_native_id = int(asset["native_id"])
        except (TypeError, ValueError) as exc:
            raise AudioWorkspaceError("音频 native_id 无效") from exc
        if reported_native_id != native_id:
            raise AudioWorkspaceError("音频 native_id 与 resource_name 映射不一致")
    try:
        entry_index = int(asset["entry_index"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AudioWorkspaceError("音频缺少有效 entry_index") from exc
    if entry_index < 0:
        raise AudioWorkspaceError("音频 entry_index 不能为负数")
    return kind, archive_name, archive, native_id


def _merged_reference(track: Mapping[str, Any]) -> dict[str, Any]:
    nested = track.get("asset")
    result: dict[str, Any] = {}
    if isinstance(nested, Mapping):
        result.update(dict(nested))
    result.update(dict(track))
    return result


def _expected_magic_hex(reference: Mapping[str, Any]) -> str:
    value = reference.get("magic_hex")
    if value is not None and str(value).strip():
        return str(value).strip().casefold()
    legacy = reference.get("magic")
    if isinstance(legacy, (bytes, bytearray)):
        return bytes(legacy).hex()
    if legacy is not None and str(legacy).strip():
        text = str(legacy)
        if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0:
            return text.casefold()
        return text.encode("latin1", errors="replace").hex()
    return ""


def _freeze_payload_identity(
    reference: Mapping[str, Any],
    archive: Path,
    *,
    context: str,
) -> dict[str, Any]:
    """Re-read one directory row and stream only that bounded entry."""

    try:
        expected_archive_size = int(reference["archive_size"])
        expected_archive_mtime_ns = int(reference["archive_mtime_ns"])
        entry_index = int(reference["entry_index"])
        raw_entry_size = reference.get("entry_size")
        if raw_entry_size is None:
            raw_entry_size = reference.get("payload_size", reference.get("size"))
        expected_entry_size = int(raw_entry_size)
    except (KeyError, TypeError, ValueError) as exc:
        raise AudioWorkspaceError(f"{context}缺少可冻结的归档或条目身份") from exc

    if expected_entry_size <= 0:
        raise AudioWorkspaceError(f"{context}条目大小必须为正数")
    if expected_entry_size > AUDIO_MAX_ENTRY_BYTES:
        raise AudioWorkspaceError(
            f"{context}条目超过 128 MiB，无法完成 bounded payload 冻结"
        )
    try:
        stat = archive.stat()
    except OSError as exc:
        raise AudioWorkspaceError(f"{context}来源归档不存在，请重新扫描") from exc
    if (
        int(stat.st_size) != expected_archive_size
        or int(stat.st_mtime_ns) != expected_archive_mtime_ns
    ):
        raise AudioWorkspaceError(f"{context}来源归档在扫描后已变化，请重新扫描")

    try:
        entries, names = _build_bin_patch().read_archive(archive)
    except (OSError, TypeError, ValueError) as exc:
        raise AudioWorkspaceError(f"{context}无法读取来源归档目录") from exc
    if not 0 <= entry_index < len(entries):
        raise AudioWorkspaceError(f"{context} entry_index 在扫描后已失效，请重新扫描")
    entry = entries[entry_index]
    try:
        actual_offset = int(_entry_field(entry, "offset"))
        actual_entry_size = int(_entry_field(entry, "size"))
    except (TypeError, ValueError) as exc:
        raise AudioWorkspaceError(f"{context}条目目录记录无效") from exc
    actual_name = _decode_entry_name(names, _entry_field(entry, "name_offset"))
    expected_name = str(reference.get("resource_name") or "").strip()
    if not expected_name or actual_name != expected_name:
        raise AudioWorkspaceError(f"{context}条目名称在冻结后已变化，请重新扫描")
    if actual_entry_size != expected_entry_size:
        raise AudioWorkspaceError(f"{context}条目大小在冻结后已变化，请重新扫描")
    if (
        actual_offset < 0
        or actual_entry_size <= 0
        or actual_offset + actual_entry_size > int(stat.st_size)
    ):
        raise AudioWorkspaceError(f"{context}条目范围无效，请重新扫描")

    digest = hashlib.sha256()
    remaining = actual_entry_size
    first_probe = bytearray()
    try:
        with archive.open("rb") as source:
            source.seek(actual_offset)
            while remaining:
                block = source.read(min(AUDIO_SCAN_CHUNK_BYTES, remaining))
                if not block:
                    raise AudioWorkspaceError(f"{context} payload 读取不完整")
                if len(first_probe) < AUDIO_MAGIC_BYTES:
                    first_probe.extend(
                        block[: AUDIO_MAGIC_BYTES - len(first_probe)]
                    )
                digest.update(block)
                remaining -= len(block)
    except AudioWorkspaceError:
        raise
    except OSError as exc:
        raise AudioWorkspaceError(f"{context}无法完成 bounded payload 冻结") from exc

    first_block = bytes(first_probe)
    actual_magic_hex = first_block.hex()
    expected_magic_hex = _expected_magic_hex(reference)
    if expected_magic_hex and expected_magic_hex != actual_magic_hex:
        raise AudioWorkspaceError(f"{context}条目 magic 在冻结后已变化，请重新扫描")
    audio_type = _audio_type(first_block)
    if audio_type is None:
        raise AudioWorkspaceError(f"{context}条目不是可识别的音频")
    actual_format, actual_mime = audio_type
    expected_format = str(reference.get("format") or "").strip().casefold()
    if expected_format and expected_format != actual_format:
        raise AudioWorkspaceError(f"{context}条目 format 在冻结后已变化，请重新扫描")

    try:
        after = archive.stat()
    except OSError as exc:
        raise AudioWorkspaceError(f"{context}无法复检来源归档") from exc
    if (
        int(after.st_size) != expected_archive_size
        or int(after.st_mtime_ns) != expected_archive_mtime_ns
    ):
        raise AudioWorkspaceError(f"{context}来源归档在读取期间已变化，请重新扫描")

    payload_sha256 = digest.hexdigest()
    expected_payload_sha256 = str(reference.get("payload_sha256") or "").strip().casefold()
    if expected_payload_sha256 and expected_payload_sha256 != payload_sha256:
        raise AudioWorkspaceError(f"{context}payload 在冻结后已变化，请重新选择")
    return {
        "archive_size": expected_archive_size,
        "archive_mtime_ns": expected_archive_mtime_ns,
        "entry_index": entry_index,
        "entry_size": actual_entry_size,
        "resource_name": actual_name,
        "magic": first_block[:4].decode("latin1", errors="replace"),
        "magic_hex": actual_magic_hex,
        "format": actual_format,
        "mime": actual_mime,
        "payload_sha256": payload_sha256,
    }


def _empty_track(track: str, action: str) -> dict[str, Any]:
    loop_default = track == "bgm"
    return {
        "schema": AUDIO_TRACK_SCHEMA,
        "track": track,
        "kind": track,
        "action": action,
        "volume": 100,
        "transition_ms": 0,
        "loop": loop_default,
        "asset": None,
        "asset_id": None,
        "label": "",
        "archive": None,
        "archive_name": None,
        "path": None,
        "archive_path": None,
        "size": None,
        "mtime": None,
        "archive_size": None,
        "archive_mtime_ns": None,
        "entry_index": None,
        "entry_size": None,
        "resource_name": "",
        "native_id": None,
        "mime": None,
        "format": None,
        "magic": None,
        "magic_hex": None,
        "payload_sha256": None,
        "source_kind": "none",
        "source_mode": "none",
        "build_mode": "none",
        "compile_ready": True,
        "preview_only": False,
        "frozen": False,
    }


def stage_audio_defaults() -> dict[str, Any]:
    """Return the explicit no-op audio state for a new stage."""

    return {
        "schema": AUDIO_STAGE_SCHEMA,
        "revision": 0,
        "read_only": True,
        "bgm": _empty_track("bgm", "keep"),
        "se": _empty_track("se", "none"),
    }


def _apply_track_settings(
    track_value: Mapping[str, Any],
    track_kind: str,
    *,
    action: Any = None,
    settings: Mapping[str, Any] | None = None,
    volume: Any = None,
    transition_ms: Any = None,
    loop: Any = None,
) -> dict[str, Any]:
    settings_value = _settings_mapping(settings)
    result = copy.deepcopy(dict(track_value))
    result["schema"] = AUDIO_TRACK_SCHEMA
    result["track"] = track_kind
    action_value = _setting(
        settings_value,
        "action",
        action,
        result.get("action"),
        "keep" if track_kind == "bgm" else "none",
    )
    result["action"] = _normalise_action(
        track_kind,
        action_value,
        default="keep" if track_kind == "bgm" else "none",
    )
    result["volume"] = _volume(
        _setting(settings_value, "volume", volume, result.get("volume"), 100)
    )
    result["transition_ms"] = _transition_ms(
        _setting(
            settings_value,
            "transition_ms",
            transition_ms,
            result.get("transition_ms"),
            0,
        )
    )
    result["loop"] = _loop(
        _setting(
            settings_value,
            "loop",
            loop,
            result.get("loop"),
            track_kind == "bgm",
        )
    )
    if result["action"] == "play" and not str(result.get("asset_id") or "").strip():
        raise AudioWorkspaceError(
            f"{'BGM' if track_kind == 'bgm' else 'SE'} play 必须绑定已冻结音频资源"
        )
    return result


def _clear_track_source(track_value: Mapping[str, Any], track_kind: str) -> dict[str, Any]:
    result = _empty_track(
        track_kind,
        "keep" if track_kind == "bgm" else "none",
    )
    # A stop/no-op deliberately drops the source identity, but it must retain
    # the action and the user-facing settings that were just validated.
    for key in ("action", "volume", "transition_ms", "loop"):
        if key in track_value:
            result[key] = copy.deepcopy(track_value[key])
    for key, value in track_value.items():
        if key not in result:
            result[key] = copy.deepcopy(value)
    result["schema"] = AUDIO_TRACK_SCHEMA
    result["track"] = track_kind
    return result


def _stage_project_audio_track(
    asset: Mapping[str, Any],
    *,
    project_library_root: str | Path | None,
    action: str | None,
    settings: Mapping[str, Any] | None,
    volume: Any,
    transition_ms: Any,
    loop: Any,
) -> dict[str, Any]:
    if project_library_root is None:
        raise AudioWorkspaceError("项目音频缺少 V2 项目资产库根目录")
    try:
        from .audio_project import ProjectAudioError, validate_project_audio_asset

        validation = validate_project_audio_asset(asset, project_library_root)
    except (ProjectAudioError, OSError, TypeError, ValueError) as exc:
        raise AudioWorkspaceError(f"项目音频资产复检失败: {exc}") from exc
    reference = copy.deepcopy(dict(validation["asset_ref"]))
    track_kind = _normalise_track_kind(reference.get("track"))
    settings_value = _settings_mapping(settings)
    action_value = _normalise_action(
        track_kind,
        _setting(settings_value, "action", action, None, "play"),
        default="play",
    )
    frozen_settings = _apply_track_settings(
        {
            "asset_id": reference["asset_id"],
            "action": action_value,
            "volume": 100,
            "transition_ms": 0,
            "loop": track_kind == "bgm",
        },
        track_kind,
        action=action_value,
        settings=settings_value,
        volume=volume,
        transition_ms=transition_ms,
        loop=loop,
    )
    frozen_asset = {**reference, "kind": track_kind}
    return {
        "schema": AUDIO_TRACK_SCHEMA,
        "track": track_kind,
        "kind": track_kind,
        "action": frozen_settings["action"],
        "volume": frozen_settings["volume"],
        "transition_ms": frozen_settings["transition_ms"],
        "loop": frozen_settings["loop"],
        "asset": frozen_asset,
        "asset_id": reference["asset_id"],
        "label": reference["label"],
        "archive": None,
        "archive_name": None,
        "path": None,
        "archive_path": None,
        "size": reference["size"],
        "mtime": None,
        "archive_size": None,
        "archive_mtime_ns": None,
        "entry_index": None,
        "entry_size": reference["size"],
        "resource_name": "",
        "native_id": None,
        "mime": reference["mime"],
        "format": reference["format"],
        "magic": None,
        "magic_hex": None,
        "payload_sha256": reference["payload_sha256"],
        "source_kind": "project_asset",
        "source_mode": "project_library",
        "build_mode": "additive_resource",
        "compile_ready": True,
        "preview_only": False,
        "portable": True,
        "frozen": True,
    }


def stage_audio_track_from_asset(
    asset: Mapping[str, Any],
    action: str | None = None,
    settings: Mapping[str, Any] | None = None,
    *,
    volume: Any = None,
    transition_ms: Any = None,
    loop: Any = None,
    project_library_root: str | Path | None = None,
) -> dict[str, Any]:
    """Freeze one scanned BGM/BGM2/SE asset for preview or later validation."""

    if not isinstance(asset, Mapping):
        raise AudioWorkspaceError("音频资源必须是 Mapping")
    build_mode = _normalise_build_mode(asset)
    if build_mode == "additive_resource":
        return _stage_project_audio_track(
            asset,
            project_library_root=project_library_root,
            action=action,
            settings=settings,
            volume=volume,
            transition_ms=transition_ms,
            loop=loop,
        )
    kind, archive_name, archive, native_id = _validate_asset_identity(asset)
    track_kind = "se" if kind == "se" else "bgm"
    settings_value = _settings_mapping(settings)
    action_value = _setting(
        settings_value,
        "action",
        action,
        None,
        "play",
    )
    action_value = _normalise_action(track_kind, action_value, default="play")
    frozen_settings = _apply_track_settings(
        {
            "asset_id": str(asset["asset_id"]),
            "action": action_value,
            "volume": 100,
            "transition_ms": 0,
            "loop": track_kind == "bgm",
        },
        track_kind,
        action=action_value,
        settings=settings_value,
        volume=volume,
        transition_ms=transition_ms,
        loop=loop,
    )
    try:
        frozen_identity = _freeze_payload_identity(
            asset,
            archive,
            context=f"音频 {asset['asset_id']} ",
        )
    except AudioWorkspaceError:
        raise

    compile_ready = _compile_ready(asset, build_mode)
    source_mode = str(
        asset.get("source_mode") or ("current_game" if compile_ready else "external_game")
    )
    source_kind = str(
        asset.get("source_kind") or ("native" if compile_ready else "fvp_external")
    )
    frozen_asset = copy.deepcopy(dict(asset))
    frozen_asset.update(frozen_identity)
    frozen_asset.update(
        {
            "archive": archive_name,
            "archive_name": archive_name,
            "path": str(archive),
            "archive_path": str(archive),
            "entry_size": frozen_identity["entry_size"],
            "size": frozen_identity["entry_size"],
            "native_id": native_id,
        }
    )
    result = {
        "schema": AUDIO_TRACK_SCHEMA,
        "track": track_kind,
        "kind": kind,
        "action": frozen_settings["action"],
        "volume": frozen_settings["volume"],
        "transition_ms": frozen_settings["transition_ms"],
        "loop": frozen_settings["loop"],
        "asset": frozen_asset,
        "asset_id": str(asset["asset_id"]),
        "label": str(asset.get("label") or asset.get("resource_name") or ""),
        "archive": archive_name,
        "archive_name": archive_name,
        "path": str(archive),
        "archive_path": str(archive),
        "size": frozen_identity["entry_size"],
        "mtime": frozen_identity["archive_mtime_ns"],
        "archive_size": frozen_identity["archive_size"],
        "archive_mtime_ns": frozen_identity["archive_mtime_ns"],
        "entry_index": frozen_identity["entry_index"],
        "entry_size": frozen_identity["entry_size"],
        "resource_name": frozen_identity["resource_name"],
        "native_id": native_id,
        "mime": frozen_identity["mime"],
        "format": frozen_identity["format"],
        "magic": frozen_identity["magic"],
        "magic_hex": frozen_identity["magic_hex"],
        "payload_sha256": frozen_identity["payload_sha256"],
        "revision": str(asset.get("revision") or ""),
        "scan_seconds": float(asset.get("scan_seconds") or 0.0),
        "source_kind": source_kind,
        "source_mode": source_mode,
        "build_mode": build_mode,
        "compile_ready": compile_ready,
        "preview_only": not compile_ready,
        "source_game": str(asset.get("source_game") or archive.parent.name),
        "project_dir": str(asset.get("project_dir") or archive.parent),
        "frozen": True,
    }
    return result


def _normalise_stage(stage: Mapping[str, Any] | None) -> dict[str, Any]:
    if stage is None:
        return stage_audio_defaults()
    if not isinstance(stage, Mapping):
        raise AudioWorkspaceError("音频舞台必须是 Mapping")
    result = copy.deepcopy(dict(stage))
    result["schema"] = AUDIO_STAGE_SCHEMA
    for track_kind, default_action in (("bgm", "keep"), ("se", "none")):
        current = result.get(track_kind)
        if current is None:
            result[track_kind] = _empty_track(track_kind, default_action)
            continue
        if not isinstance(current, Mapping):
            raise AudioWorkspaceError(f"音频舞台 {track_kind} 状态无效")
        result[track_kind] = _apply_track_settings(
            current,
            track_kind,
        )
    try:
        result["revision"] = int(result.get("revision") or 0)
    except (TypeError, ValueError) as exc:
        raise AudioWorkspaceError("音频舞台 revision 必须是整数") from exc
    if result["revision"] < 0:
        raise AudioWorkspaceError("音频舞台 revision 不能为负数")
    result["read_only"] = True
    return result


def _track_from_update_value(
    value: Mapping[str, Any],
    track_kind: str,
    *,
    action: str | None,
    settings: Mapping[str, Any] | None,
    volume: Any,
    transition_ms: Any,
    loop: Any,
    project_library_root: str | Path | None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AudioWorkspaceError(f"音频舞台 {track_kind} 更新值无效")
    value_build_mode = str(value.get("build_mode") or "").strip().casefold()
    looks_staged = str(value.get("schema") or "") == AUDIO_TRACK_SCHEMA or (
        "asset_id" in value
        and "payload_sha256" in value
        and value_build_mode != "additive_resource"
    )
    if looks_staged:
        candidate = _apply_track_settings(
            value,
            track_kind,
            action=action,
            settings=settings,
            volume=volume,
            transition_ms=transition_ms,
            loop=loop,
        )
        return candidate
    return stage_audio_track_from_asset(
        value,
        action=action,
        settings=settings,
        volume=volume,
        transition_ms=transition_ms,
        loop=loop,
        project_library_root=project_library_root,
    )


def update_stage_audio(
    stage: Mapping[str, Any] | None = None,
    track: str | Mapping[str, Any] | None = None,
    *,
    asset: Mapping[str, Any] | None = None,
    action: str | None = None,
    settings: Mapping[str, Any] | None = None,
    volume: Any = None,
    transition_ms: Any = None,
    loop: Any = None,
    bgm: Mapping[str, Any] | None = None,
    se: Mapping[str, Any] | None = None,
    project_library_root: str | Path | None = None,
) -> dict[str, Any]:
    """Return a copied stage with one explicit BGM or SE state changed."""

    result = _normalise_stage(stage)
    replacements: list[tuple[str, Mapping[str, Any]]] = []
    if bgm is not None:
        replacements.append(("bgm", bgm))
    if se is not None:
        replacements.append(("se", se))
    if replacements and (track is not None or asset is not None or action is not None):
        raise AudioWorkspaceError("音频舞台更新参数不能同时指定 track 与 bgm/se")
    if len(replacements) > 1:
        for track_kind, value in replacements:
            result[track_kind] = _track_from_update_value(
                value,
                track_kind,
                action=None,
                settings=None,
                volume=None,
                transition_ms=None,
                loop=None,
                project_library_root=project_library_root,
            )
        result["revision"] += 1
        return result

    if replacements:
        target, value = replacements[0]
        result[target] = _track_from_update_value(
            value,
            target,
            action=None,
            settings=None,
            volume=None,
            transition_ms=None,
            loop=None,
            project_library_root=project_library_root,
        )
        result["revision"] += 1
        return result

    target: str | None = None
    track_value: Mapping[str, Any] | None = None
    if isinstance(track, str):
        target = _normalise_track_kind(track)
    elif isinstance(track, Mapping):
        target = _normalise_track_kind(track.get("track") or track.get("kind"))
        track_value = track
    elif track is not None:
        raise AudioWorkspaceError("音频 track 必须是 bgm、se 或 Mapping")
    if target is None and asset is not None:
        target = _normalise_track_kind(asset.get("track") or asset.get("kind"))
    if target is None:
        raise AudioWorkspaceError("更新音频舞台时必须指定 bgm 或 se")
    if track_value is not None and asset is not None:
        raise AudioWorkspaceError("音频舞台更新不能同时指定 track Mapping 与 asset")

    if asset is not None:
        candidate = stage_audio_track_from_asset(
            asset,
            action=action,
            settings=settings,
            volume=volume,
            transition_ms=transition_ms,
            loop=loop,
            project_library_root=project_library_root,
        )
    elif track_value is not None:
        candidate = _track_from_update_value(
            track_value,
            target,
            action=action,
            settings=settings,
            volume=volume,
            transition_ms=transition_ms,
            loop=loop,
            project_library_root=project_library_root,
        )
    else:
        candidate = _apply_track_settings(
            result[target],
            target,
            action=action,
            settings=settings,
            volume=volume,
            transition_ms=transition_ms,
            loop=loop,
        )

    if candidate["action"] in ({"keep", "stop"} if target == "bgm" else {"none", "stop_all"}):
        candidate = _clear_track_source(candidate, target)
        candidate["action"] = _normalise_action(target, candidate["action"], default=candidate["action"])
        candidate["volume"] = _volume(candidate.get("volume", 100))
        candidate["transition_ms"] = _transition_ms(candidate.get("transition_ms", 0))
        candidate["loop"] = _loop(candidate.get("loop", target == "bgm"))
    result[target] = candidate
    result["revision"] += 1
    return result


def _validate_one_staged_track(
    staged: Mapping[str, Any],
    *,
    current_root: Path | None,
    for_compile: bool,
    project_library_root: str | Path | None,
) -> dict[str, Any]:
    if not isinstance(staged, Mapping):
        raise AudioWorkspaceError("冻结音频必须是 Mapping")
    track_kind = _normalise_track_kind(staged.get("track") or staged.get("kind"))
    action = _normalise_action(
        track_kind,
        staged.get("action"),
        default="keep" if track_kind == "bgm" else "none",
    )
    _volume(staged.get("volume", 100))
    _transition_ms(staged.get("transition_ms", 0))
    _loop(staged.get("loop", track_kind == "bgm"))
    reference = _merged_reference(staged)
    asset_id = str(reference.get("asset_id") or "").strip()
    if not asset_id:
        if action == "play":
            raise AudioWorkspaceError(
                f"{'BGM' if track_kind == 'bgm' else 'SE'} play 缺少冻结音频资源"
            )
        return {
            "valid": True,
            "ok": True,
            "track": track_kind,
            "action": action,
            "asset_id": None,
            "source_present": False,
            "compile_ready": True,
            "preview_only": False,
            "build_mode": "none",
            "current_game_bound": True,
        }

    build_mode = _normalise_build_mode(reference)
    if build_mode == "additive_resource":
        if project_library_root is None:
            raise AudioWorkspaceError("项目音频复检缺少 V2 项目资产库根目录")
        nested = staged.get("asset")
        portable = nested if isinstance(nested, Mapping) else staged
        try:
            from .audio_project import ProjectAudioError, validate_project_audio_asset

            validation = validate_project_audio_asset(portable, project_library_root)
        except (ProjectAudioError, OSError, TypeError, ValueError) as exc:
            raise AudioWorkspaceError(f"项目音频资产复检失败: {exc}") from exc
        frozen = dict(validation["asset_ref"])
        if str(frozen.get("track") or "") != track_kind:
            raise AudioWorkspaceError("项目音频 track 与舞台轨道不一致")
        for key in ("asset_id", "payload_sha256", "size", "format", "mime"):
            top_value = staged.get(key)
            if top_value not in (None, "") and top_value != frozen.get(key):
                raise AudioWorkspaceError(f"项目音频嵌套身份与顶层 {key} 冲突")
        return {
            "valid": True,
            "ok": True,
            "track": track_kind,
            "action": action,
            "asset_id": frozen["asset_id"],
            "source_present": True,
            "source_kind": "project_asset",
            "source_mode": "project_library",
            "build_mode": "additive_resource",
            "compile_ready": True,
            "preview_only": False,
            "current_game_bound": False,
            "target_binding_required": True,
            "portable": True,
            "payload_sha256": frozen["payload_sha256"],
            "entry_size": frozen["size"],
            "format": frozen["format"],
            "mime": frozen["mime"],
            "asset_ref": frozen,
        }

    kind, archive_name, archive, native_id = _validate_asset_identity(reference)
    del kind, archive_name, native_id
    compile_ready = _compile_ready(reference, build_mode)
    preview_only = not compile_ready
    if for_compile and (build_mode != "direct_reference" or not compile_ready or preview_only):
        raise AudioWorkspaceError("外部音频资源仅可预览，不能进入编译")
    if build_mode == "direct_reference":
        if current_root is None:
            raise AudioWorkspaceError("本作直引音频缺少当前目标游戏根")
        frozen_root = Path(
            str(reference.get("project_dir") or archive.parent)
        ).expanduser().resolve()
        if not _same_directory(frozen_root, current_root) or not _same_directory(
            archive.parent,
            current_root,
        ):
            raise AudioWorkspaceError("本作直引音频不属于当前目标游戏，请重新扫描")
    frozen = _freeze_payload_identity(
        reference,
        archive,
        context="冻结音频 ",
    )
    return {
        "valid": True,
        "ok": True,
        "track": track_kind,
        "action": action,
        "asset_id": asset_id,
        "source_present": True,
        "source_kind": str(reference.get("source_kind") or ""),
        "source_mode": str(reference.get("source_mode") or ""),
        "build_mode": build_mode,
        "compile_ready": compile_ready,
        "preview_only": preview_only,
        "current_game_bound": build_mode == "direct_reference",
        "archive": archive.name,
        "archive_path": str(archive),
        "entry_index": frozen["entry_index"],
        "entry_size": frozen["entry_size"],
        "resource_name": frozen["resource_name"],
        "payload_sha256": frozen["payload_sha256"],
        "magic_hex": frozen["magic_hex"],
        "format": frozen["format"],
        "mime": frozen["mime"],
    }


def validate_staged_audio_source(
    staged: Mapping[str, Any],
    current_game_dir: str | Path | None = None,
    *,
    current_game_root: str | Path | None = None,
    for_compile: bool = True,
    compile: bool | None = None,
    for_preview: bool | None = None,
    track: str | None = None,
    project_library_root: str | Path | None = None,
) -> dict[str, Any]:
    """Revalidate a frozen track, or every track in a frozen audio stage."""

    if compile is not None:
        for_compile = bool(compile)
    if for_preview is not None:
        for_compile = not bool(for_preview)
    current_root = _resolve_current_root(current_game_dir, current_game_root)

    if not isinstance(staged, Mapping):
        raise AudioWorkspaceError("冻结音频必须是 Mapping")
    is_stage = "bgm" in staged or "se" in staged
    if not is_stage:
        return _validate_one_staged_track(
            staged,
            current_root=current_root,
            for_compile=for_compile,
            project_library_root=project_library_root,
        )

    if track is not None:
        selected_track = _normalise_track_kind(track)
        raw_track = staged.get(selected_track)
        if not isinstance(raw_track, Mapping):
            raise AudioWorkspaceError(f"音频舞台缺少 {selected_track} 状态")
        return _validate_one_staged_track(
            raw_track,
            current_root=current_root,
            for_compile=for_compile,
            project_library_root=project_library_root,
        )

    reports: dict[str, dict[str, Any]] = {}
    for track_kind in ("bgm", "se"):
        raw_track = staged.get(track_kind)
        if not isinstance(raw_track, Mapping):
            raise AudioWorkspaceError(f"音频舞台缺少 {track_kind} 状态")
        reports[track_kind] = _validate_one_staged_track(
            raw_track,
            current_root=current_root,
            for_compile=for_compile,
            project_library_root=project_library_root,
        )
    return {
        "valid": True,
        "ok": True,
        "tracks": reports,
        "compile_ready": all(report["compile_ready"] for report in reports.values()),
        "preview_only": any(report["preview_only"] for report in reports.values()),
        "current_game_bound": all(
            report["current_game_bound"] for report in reports.values()
        ),
    }


__all__ = [
    "AUDIO_ARCHIVES",
    "AUDIO_MAX_ENTRY_BYTES",
    "AUDIO_STAGE_SCHEMA",
    "AUDIO_TRACK_SCHEMA",
    "AudioWorkspaceError",
    "clear_audio_scan_cache",
    "scan_audio_source",
    "scan_audio_sources",
    "scan_audio_workspace",
    "stage_audio_defaults",
    "stage_audio_track_from_asset",
    "update_stage_audio",
    "validate_staged_audio_source",
]
