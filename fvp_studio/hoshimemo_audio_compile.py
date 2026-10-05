"""Hoshimemo target binding for portable project BGM/SE assets.

Project assets have no archive, entry index, or native ID.  This module is the
target-specific boundary that validates those portable references, chooses a
compatible native payload, allocates deterministic numeric resource names,
and produces streamed additive BIN candidates outside the game directory.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
from typing import Any, Mapping, Sequence
from uuid import uuid4

from .audio_project import (
    PROJECT_AUDIO_ASSETS_DIR,
    PROJECT_AUDIO_BUILD_MODE,
    ProjectAudioError,
    validate_project_audio_asset,
)
from .bin_archive import (
    BinArchiveError,
    FileArchiveAppendResult,
    append_entries_file,
    archive_entry_names_file,
)


HOSHIMEMO_AUDIO_TARGET_PROFILE_ID = "hoshimemo-hd-native-audio-additive-v1"
HOSHIMEMO_SCENE_PROFILE_ID = "hoshimemo-hd-native-scene-hook-v1"
HOSHIMEMO_AUDIO_BUILD_SCHEMA = "fvp-studio-v2.hoshimemo-audio-build.v1"
HOSHIMEMO_AUDIO_BINDING_SCHEMA = "fvp-studio-v2.hoshimemo-audio-binding.v1"
_NUMERIC_NAME_RE = re.compile(r"^[0-9]+$")
_MAX_NATIVE_ID = 0x7FFFFFFF
_MAX_BGM_BIN_ID = 999
_COPY_CHUNK_BYTES = 1024 * 1024


class HoshimemoAudioCompileError(ValueError):
    """Raised when a portable asset cannot be bound to the native target."""


@dataclass(frozen=True)
class HoshimemoAudioBuild:
    bindings: Mapping[str, Mapping[str, Any]]
    resource_archive_files: Mapping[str, Path]
    resource_archive_source_sha256: Mapping[str, str]
    report: Mapping[str, Any]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(_COPY_CHUNK_BYTES), b""):
                digest.update(block)
    except OSError as exc:
        raise HoshimemoAudioCompileError(f"无法读取音频文件: {path}") from exc
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _validated_root(value: str | Path, label: str, *, create: bool = False) -> Path:
    raw = Path(value).expanduser()
    if raw.is_symlink():
        raise HoshimemoAudioCompileError(f"{label}不能是符号链接: {raw}")
    if create:
        raw.mkdir(parents=True, exist_ok=True)
    resolved = raw.resolve()
    if not resolved.is_dir():
        raise HoshimemoAudioCompileError(f"{label}不存在: {resolved}")
    return resolved


def _portable_reference(track: Mapping[str, Any]) -> Mapping[str, Any]:
    nested = track.get("asset")
    reference = nested if isinstance(nested, Mapping) else track
    if not isinstance(reference, Mapping):
        raise HoshimemoAudioCompileError("自定义音频播放状态缺少 asset_ref")
    return reference


def collect_project_audio_references(
    scenes: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Collect and deduplicate portable play references from buildable scenes."""

    collected: dict[str, dict[str, Any]] = {}
    for scene in scenes:
        cue = scene.get("cue") if isinstance(scene.get("cue"), Mapping) else {}
        audio = cue.get("audio") if isinstance(cue.get("audio"), Mapping) else {}
        for track_name in ("bgm", "se"):
            track = (
                audio.get(track_name)
                if isinstance(audio.get(track_name), Mapping)
                else {}
            )
            if str(track.get("action") or ("keep" if track_name == "bgm" else "none")).casefold() != "play":
                continue
            reference = _portable_reference(track)
            build_mode = str(reference.get("build_mode") or track.get("build_mode") or "").strip().casefold()
            if build_mode != PROJECT_AUDIO_BUILD_MODE:
                continue
            asset_id = str(reference.get("asset_id") or "").strip()
            if not asset_id:
                raise HoshimemoAudioCompileError("自定义音频 asset_ref 缺少 asset_id")
            item = dict(reference)
            item_track = str(item.get("track") or item.get("kind") or "").strip().casefold()
            if item_track != track_name:
                raise HoshimemoAudioCompileError(
                    f"自定义音频 {asset_id} 的 track 与舞台轨道不一致"
                )
            prior = collected.get(asset_id)
            if prior is not None and prior != item:
                raise HoshimemoAudioCompileError(
                    f"同一自定义音频 asset_id 出现冲突引用: {asset_id}"
                )
            collected[asset_id] = item
    return tuple(
        collected[key]
        for key in sorted(
            collected,
            key=lambda value: (
                str(collected[value].get("track") or ""),
                value,
            ),
        )
    )


def _project_asset_path(library_root: Path, reference: Mapping[str, Any]) -> Path:
    relative = PurePosixPath(str(reference.get("relative_path") or ""))
    if relative.is_absolute() or not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise HoshimemoAudioCompileError("自定义音频 relative_path 无效")
    assets_root = (library_root / PROJECT_AUDIO_ASSETS_DIR).resolve()
    path = assets_root.joinpath(*relative.parts)
    if path.is_symlink():
        raise HoshimemoAudioCompileError("自定义音频负载不能是符号链接")
    resolved = path.resolve()
    if not resolved.is_relative_to(assets_root) or not resolved.is_file():
        raise HoshimemoAudioCompileError("自定义音频负载不在项目 assets 目录")
    return resolved


def _is_vorbis_ogg(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            probe = handle.read(64 * 1024)
    except OSError:
        return False
    return probe.startswith(b"OggS") and b"\x01vorbis" in probe


def _pcm_wav_profile(path: Path) -> dict[str, int] | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(256 * 1024)
    except OSError:
        return None
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    cursor = 12
    fmt: tuple[int, int, int, int] | None = None
    has_data = False
    while cursor + 8 <= len(data):
        chunk_id = data[cursor : cursor + 4]
        chunk_size = struct.unpack_from("<I", data, cursor + 4)[0]
        body = cursor + 8
        end = body + chunk_size
        if chunk_id == b"fmt " and chunk_size >= 16 and body + 16 <= len(data):
            audio_format, channels, sample_rate = struct.unpack_from(
                "<HHI", data, body
            )
            bits = struct.unpack_from("<H", data, body + 14)[0]
            fmt = (audio_format, channels, sample_rate, bits)
        elif chunk_id == b"data":
            has_data = chunk_size > 0
            break
        if end > len(data):
            break
        cursor = end + (chunk_size & 1)
    if fmt is None or not has_data:
        return None
    audio_format, channels, sample_rate, bits = fmt
    if (
        audio_format != 1
        or channels not in {1, 2}
        or sample_rate not in {22050, 44100}
        or bits != 16
    ):
        return None
    return {
        "audio_format": audio_format,
        "channels": channels,
        "sample_rate": sample_rate,
        "bits_per_sample": bits,
    }


def _transcode(
    source: Path,
    output: Path,
    *,
    track: str,
) -> dict[str, Any]:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise HoshimemoAudioCompileError(
            "自定义音频需要转码，但 PATH 中找不到 ffmpeg"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{uuid4().hex}.tmp{output.suffix}")
    if temporary.exists():
        raise HoshimemoAudioCompileError(f"转码临时文件已存在: {temporary}")
    common = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-nostdin",
        "-y",
        "-i",
        str(source),
        "-map_metadata",
        "-1",
        "-vn",
    ]
    if track == "bgm":
        command = [*common, "-c:a", "libvorbis", "-q:a", "5", "-f", "ogg", str(temporary)]
        mode = "transcode-vorbis-q5"
    else:
        command = [
            *common,
            "-ac",
            "2",
            "-ar",
            "22050",
            "-c:a",
            "pcm_s16le",
            "-f",
            "wav",
            str(temporary),
        ]
        mode = "transcode-pcm-s16le-stereo-22050"
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "ffmpeg failed").strip()
            raise HoshimemoAudioCompileError(f"自定义音频转码失败: {detail}")
        if not temporary.is_file() or temporary.stat().st_size <= 0:
            raise HoshimemoAudioCompileError("自定义音频转码没有生成有效文件")
        if track == "bgm" and not _is_vorbis_ogg(temporary):
            raise HoshimemoAudioCompileError("BGM 转码结果不是 Vorbis-in-Ogg")
        if track == "se" and _pcm_wav_profile(temporary) is None:
            raise HoshimemoAudioCompileError("SE 转码结果不是受支持的 PCM WAV")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {"mode": mode, "ffmpeg": str(ffmpeg)}


def _prepare_payload(
    reference: Mapping[str, Any],
    source: Path,
    library_root: Path,
) -> tuple[Path, dict[str, Any]]:
    track = str(reference["track"])
    if track == "bgm" and _is_vorbis_ogg(source):
        return source, {"mode": "native-vorbis-copy", "source_format": reference["format"]}
    wav_profile = _pcm_wav_profile(source) if track == "se" else None
    if track == "se" and wav_profile is not None:
        return source, {
            "mode": "native-pcm-wav-copy",
            "source_format": reference["format"],
            "wav": wav_profile,
        }

    suffix = ".ogg" if track == "bgm" else ".wav"
    settings_id = "vorbis-q5" if track == "bgm" else "pcm-s16le-stereo-22050"
    rendition_root = library_root / "renditions" / HOSHIMEMO_AUDIO_TARGET_PROFILE_ID
    if rendition_root.is_symlink():
        raise HoshimemoAudioCompileError("项目音频 renditions 不能是符号链接")
    rendition_root.mkdir(parents=True, exist_ok=True)
    output = rendition_root / f"{reference['payload_sha256']}-{settings_id}{suffix}"
    if output.exists():
        if output.is_symlink() or not output.is_file():
            raise HoshimemoAudioCompileError("项目音频转码缓存不是普通文件")
        valid = _is_vorbis_ogg(output) if track == "bgm" else _pcm_wav_profile(output) is not None
        if not valid:
            raise HoshimemoAudioCompileError("项目音频转码缓存已损坏")
        return output.resolve(), {
            "mode": "cached-rendition",
            "settings": settings_id,
        }
    report = _transcode(source, output, track=track)
    report["settings"] = settings_id
    return output.resolve(), report


def _numeric_names(path: Path) -> tuple[set[int], int]:
    try:
        names = archive_entry_names_file(path)
    except BinArchiveError as exc:
        raise HoshimemoAudioCompileError(str(exc)) from exc
    values = {
        int(name)
        for name in names
        if _NUMERIC_NAME_RE.fullmatch(name)
    }
    return values, max(values, default=0)


def _allocate_names(
    archive_name: str,
    existing: set[int],
    current_max: int,
    count: int,
) -> list[tuple[str, int]]:
    if count <= 0:
        return []
    next_value = current_max + 1
    result: list[tuple[str, int]] = []
    while len(result) < count:
        if archive_name == "bgm.bin" and next_value > _MAX_BGM_BIN_ID:
            raise HoshimemoAudioCompileError("bgm.bin 的原生 ID 空间不足")
        native_id = next_value + (1000 if archive_name == "bgm2.bin" else 0)
        if native_id > _MAX_NATIVE_ID:
            raise HoshimemoAudioCompileError(f"{archive_name} 的原生 ID 空间不足")
        if next_value not in existing:
            result.append((str(next_value), native_id))
            existing.add(next_value)
        next_value += 1
    return result


def _select_bgm_archive(game_root: Path, count: int) -> tuple[Path, set[int], int]:
    candidates: list[tuple[Path, set[int], int]] = []
    for name in ("bgm.bin", "bgm2.bin"):
        path = game_root / name
        if not path.is_file() or path.is_symlink():
            continue
        values, maximum = _numeric_names(path)
        if name == "bgm.bin" and maximum + count > _MAX_BGM_BIN_ID:
            continue
        candidates.append((path.resolve(), values, maximum))
    if not candidates:
        raise HoshimemoAudioCompileError(
            "目标游戏没有可追加且 ID 空间足够的 bgm.bin / bgm2.bin"
        )
    # Prefer bgm.bin: its native namespace is direct and the verified target
    # archive is materially smaller than bgm2.bin in Hoshimemo HD.
    return candidates[0]


def build_hoshimemo_audio_resources(
    scenes: Sequence[Mapping[str, Any]],
    *,
    target_game_dir: str | Path,
    library_root: str | Path,
    build_root: str | Path,
    scene_profile_id: str,
) -> HoshimemoAudioBuild | None:
    """Build streamed additive audio archives for every project scene."""

    references = collect_project_audio_references(scenes)
    if not references:
        return None
    if str(scene_profile_id) != HOSHIMEMO_SCENE_PROFILE_ID:
        raise HoshimemoAudioCompileError(
            "当前游戏没有已登记的原生新增音频 target profile"
        )
    game_root = _validated_root(target_game_dir, "目标游戏目录")
    library = _validated_root(library_root, "项目音频库")
    build = _validated_root(build_root, "音频候选目录", create=True)
    if _paths_overlap(game_root, library) or _paths_overlap(game_root, build):
        raise HoshimemoAudioCompileError(
            "项目音频库和候选目录不得与游戏目录重叠"
        )
    if any(build.iterdir()):
        raise HoshimemoAudioCompileError("音频候选目录必须为空")

    validated: list[tuple[dict[str, Any], Path, Path, dict[str, Any]]] = []
    for reference in references:
        try:
            validation = validate_project_audio_asset(reference, library)
        except ProjectAudioError as exc:
            raise HoshimemoAudioCompileError(
                f"项目音频 {reference.get('asset_id')} 复检失败: {exc}"
            ) from exc
        frozen = dict(validation["asset_ref"])
        source = _project_asset_path(library, frozen)
        prepared, conversion = _prepare_payload(frozen, source, library)
        validated.append((frozen, source, prepared, conversion))

    bgm_assets = [item for item in validated if item[0]["track"] == "bgm"]
    se_assets = [item for item in validated if item[0]["track"] == "se"]
    archive_groups: dict[str, tuple[Path, list[tuple[dict[str, Any], Path, Path, dict[str, Any]]], list[tuple[str, int]]]] = {}
    if bgm_assets:
        archive_path, existing, maximum = _select_bgm_archive(game_root, len(bgm_assets))
        archive_groups[archive_path.name.casefold()] = (
            archive_path,
            bgm_assets,
            _allocate_names(archive_path.name.casefold(), existing, maximum, len(bgm_assets)),
        )
    if se_assets:
        se_path = game_root / "se.bin"
        if se_path.is_symlink() or not se_path.is_file():
            raise HoshimemoAudioCompileError("目标游戏缺少普通文件 se.bin")
        existing, maximum = _numeric_names(se_path)
        archive_groups["se.bin"] = (
            se_path.resolve(),
            se_assets,
            _allocate_names("se.bin", existing, maximum, len(se_assets)),
        )

    bindings: dict[str, dict[str, Any]] = {}
    archive_files: dict[str, Path] = {}
    archive_sources: dict[str, str] = {}
    archive_reports: dict[str, dict[str, Any]] = {}
    for archive_name in sorted(archive_groups):
        source_archive, assets, allocated = archive_groups[archive_name]
        additions: dict[str, Path] = {}
        pending_bindings: list[tuple[dict[str, Any], str, int, Path, dict[str, Any]]] = []
        for (reference, _source, prepared, conversion), (resource_name, native_id) in zip(assets, allocated):
            additions[resource_name] = prepared
            pending_bindings.append(
                (reference, resource_name, native_id, prepared, conversion)
            )
        try:
            append_result: FileArchiveAppendResult = append_entries_file(
                source_archive,
                build / archive_name,
                additions,
            )
        except BinArchiveError as exc:
            raise HoshimemoAudioCompileError(
                f"无法生成 {archive_name} 新增资源候选: {exc}"
            ) from exc
        archive_files[archive_name] = append_result.path
        archive_sources[archive_name] = append_result.source_sha256
        archive_reports[archive_name] = append_result.validation_dict()
        added_by_name = {
            str(item["name"]): dict(item) for item in append_result.added
        }
        for reference, resource_name, native_id, prepared, conversion in pending_bindings:
            added = added_by_name[resource_name]
            binding = {
                "schema": HOSHIMEMO_AUDIO_BINDING_SCHEMA,
                "target_profile_id": HOSHIMEMO_AUDIO_TARGET_PROFILE_ID,
                "scene_profile_id": scene_profile_id,
                "asset_id": reference["asset_id"],
                "track": reference["track"],
                "source_payload_sha256": reference["payload_sha256"],
                "archive_name": archive_name,
                "resource_name": resource_name,
                "native_id": native_id,
                "target_payload_sha256": added["sha256"],
                "target_payload_size": added["size"],
                "conversion": dict(conversion),
                "prepared_payload": str(prepared),
            }
            bindings[str(reference["asset_id"])] = binding

    identity = {
        "target_profile_id": HOSHIMEMO_AUDIO_TARGET_PROFILE_ID,
        "scene_profile_id": scene_profile_id,
        "bindings": {
            key: {
                item_key: item_value
                for item_key, item_value in value.items()
                if item_key != "prepared_payload"
            }
            for key, value in sorted(bindings.items())
        },
        "archives": {
            name: {
                "source_sha256": archive_sources[name],
                "output_sha256": archive_reports[name]["output_sha256"],
            }
            for name in sorted(archive_reports)
        },
    }
    report = {
        "schema": HOSHIMEMO_AUDIO_BUILD_SCHEMA,
        "passed": True,
        "install_ready": True,
        "target_profile_id": HOSHIMEMO_AUDIO_TARGET_PROFILE_ID,
        "scene_profile_id": scene_profile_id,
        "plan_sha256": _canonical_sha256(identity),
        "asset_count": len(bindings),
        "bindings": {key: dict(value) for key, value in sorted(bindings.items())},
        "archives": archive_reports,
        "safety": {
            "native_loader_only": True,
            "existing_entry_replacement": False,
            "new_payloads_at_eof": True,
            "candidate_outside_game": True,
            "unknown_profile_fail_closed": True,
        },
    }
    return HoshimemoAudioBuild(
        bindings=bindings,
        resource_archive_files=archive_files,
        resource_archive_source_sha256=archive_sources,
        report=report,
    )


__all__ = [
    "HOSHIMEMO_AUDIO_BINDING_SCHEMA",
    "HOSHIMEMO_AUDIO_BUILD_SCHEMA",
    "HOSHIMEMO_AUDIO_TARGET_PROFILE_ID",
    "HOSHIMEMO_SCENE_PROFILE_ID",
    "HoshimemoAudioBuild",
    "HoshimemoAudioCompileError",
    "build_hoshimemo_audio_resources",
    "collect_project_audio_references",
]
