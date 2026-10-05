"""Read-only event-CG discovery and frozen V2 stage references.

FVP keeps event visuals in ``graph_vis.bin`` and its numbered siblings.  The
workspace scans only BIN directory records and HZC headers.  Selecting a CG
from another game freezes one bounded payload identity; no source archive is
ever opened for writing here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import time
from typing import Any, Mapping

from .resource_builder import (
    ResourceBuildError,
    hzc_payload_probe,
    read_bin_entry_payload,
    scan_hzc_archive,
)


CG_ARCHIVE_SELECTORS: Mapping[str, int] = {
    "graph_vis.bin": 0,
    "graph_vis1.bin": 1,
    "graph_vis2.bin": 2,
}
CG_ARCHIVES = tuple(CG_ARCHIVE_SELECTORS)
CG_STAGE_WIDTH = 1920
CG_STAGE_HEIGHT = 1080
CG_SCALE_MIN = 1
CG_SCALE_MAX = 4000
CG_DISPLAY_PRESETS: Mapping[str, Mapping[str, int]] = {
    # ``scale`` uses the engine's native PrimSetRS unit: 1000 == 100%.
    # Standard is replaced with an asset-specific fit scale during freezing.
    "standard": {"x": 0, "y": 0, "depth": 2000, "rotation": 0, "scale": 1000},
    # Exact close-up tuple used by the original YUME_e02 scene.
    "closeup": {"x": 140, "y": 120, "depth": 1600, "rotation": 0, "scale": 1000},
}
_AUXILIARY_NAME = re.compile(r"(?:^|[_-])(?:parts?|mask|thumb)(?:$|[_-])", re.IGNORECASE)


class CgWorkspaceError(ValueError):
    """Raised when an event-CG source or stage reference is invalid."""


def fit_cg_scale(width: int, height: int) -> int:
    """Contain a CG at native Z=2000, camera Z=0 (1000 focal distance).

    PrimSetRS is applied *before* perspective. The native 3840x2160 CG
    wrappers use RS=1000, not 500: perspective already halves the image.
    This is a native primitive scale, not a CSS/image-pixel fit factor.
    """

    try:
        source_width = int(width)
        source_height = int(height)
    except (TypeError, ValueError):
        return 1000
    if source_width <= 0 or source_height <= 0:
        return 1000
    scale = round(
        min(
            CG_STAGE_WIDTH * 2000 / source_width,
            CG_STAGE_HEIGHT * 2000 / source_height,
        )
    )
    return max(CG_SCALE_MIN, min(CG_SCALE_MAX, int(scale)))


def _same_directory(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve() == right.resolve()


def _archive_paths(requested: Path) -> tuple[Path, list[Path]]:
    allowed = set(CG_ARCHIVE_SELECTORS)
    if requested.is_file():
        if requested.name.casefold() not in allowed:
            raise CgWorkspaceError(
                "CG 来源文件必须是 graph_vis.bin、graph_vis1.bin 或 graph_vis2.bin"
            )
        return requested.parent, [requested]
    if not requested.is_dir():
        raise CgWorkspaceError(f"CG 来源路径不存在: {requested}")
    archives = [requested / name for name in CG_ARCHIVES if (requested / name).is_file()]
    if not archives:
        raise CgWorkspaceError(
            "游戏目录中找不到 graph_vis.bin / graph_vis1.bin / graph_vis2.bin: "
            f"{requested}"
        )
    return requested, archives


def _asset_id(root: Path, archive: Path, entry: Mapping[str, Any]) -> str:
    stat = archive.stat()
    identity = "\0".join(
        (
            str(root).casefold(),
            archive.name.casefold(),
            str(stat.st_size),
            str(stat.st_mtime_ns),
            str(int(entry["entry_index"])),
            str(entry.get("source_name") or ""),
        )
    )
    return "cg-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def _confidence(entry: Mapping[str, Any]) -> str:
    name = str(entry.get("source_name") or "").strip()
    width = max(0, int(entry.get("width") or 0))
    height = max(0, int(entry.get("height") or 0))
    if _AUXILIARY_NAME.search(name):
        return "auxiliary"
    if width >= 640 and height >= 360:
        return "event_visual"
    return "possible"


def scan_cg_source(
    path: str | Path,
    *,
    current_game_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Scan one FVP game's event-visual archives without decoding frames."""

    started = time.perf_counter()
    requested = Path(path).expanduser().resolve()
    root, archives = _archive_paths(requested)
    current_root = (
        Path(current_game_dir).expanduser().resolve() if current_game_dir is not None else None
    )
    is_current_game = _same_directory(root, current_root)
    entries: list[dict[str, Any]] = []
    archive_summaries: list[dict[str, Any]] = []
    skipped = 0

    for archive in archives:
        stat = archive.stat()
        try:
            scan = scan_hzc_archive(archive)
        except (OSError, ResourceBuildError) as exc:
            raise CgWorkspaceError(str(exc)) from exc
        skipped += int(scan.get("skipped_count") or 0)
        archive_summaries.append(
            {
                "archive_name": archive.name,
                "archive_path": str(archive),
                "archive_selector": CG_ARCHIVE_SELECTORS[archive.name.casefold()],
                "entry_count": int(scan.get("entry_count") or 0),
                "visual_count": int(scan.get("visual_count") or 0),
                "skipped_count": int(scan.get("skipped_count") or 0),
            }
        )
        for raw in scan.get("entries", []):
            if not isinstance(raw, Mapping):
                continue
            resource_name = str(raw.get("source_name") or "").strip()
            entry_index = int(raw["entry_index"])
            entries.append(
                {
                    "asset_id": _asset_id(root, archive, raw),
                    "source_kind": "native" if is_current_game else "fvp_external",
                    "build_mode": "direct_reference" if is_current_game else "copy_hzc",
                    "source_game": root.name,
                    "project_dir": str(root),
                    "archive_name": archive.name,
                    "archive_path": str(archive),
                    "archive_selector": CG_ARCHIVE_SELECTORS[archive.name.casefold()],
                    "archive_size": int(stat.st_size),
                    "archive_mtime_ns": int(stat.st_mtime_ns),
                    "entry_index": entry_index,
                    "entry_size": int(raw.get("entry_size") or 0),
                    "payload_probe_sha256": str(
                        raw.get("payload_probe_sha256") or ""
                    ),
                    "resource_name": resource_name,
                    "label": resource_name or f"{archive.stem} entry #{entry_index}",
                    "virtual_path": f"{archive.stem}/{resource_name}" if resource_name else "",
                    "width": int(raw.get("width") or 0),
                    "height": int(raw.get("height") or 0),
                    "frame_count": max(1, int(raw.get("frame_count") or 1)),
                    "type": str(raw.get("type") or "HZC"),
                    "confidence": _confidence(raw),
                }
            )

    revision_material = "|".join(
        f"{archive.name}:{archive.stat().st_size}:{archive.stat().st_mtime_ns}"
        for archive in archives
    )
    return {
        "schema": "fvp-studio-v2.cg-source.v1",
        "project_dir": str(root),
        "source_game": root.name,
        "source_kind": "current_game" if is_current_game else "other_fvp_game",
        "build_mode": "direct_reference" if is_current_game else "copy_hzc",
        "is_current_game": is_current_game,
        "read_only": True,
        "archives": archive_summaries,
        "cg_count": len(entries),
        "skipped_count": skipped,
        "scan_seconds": round(time.perf_counter() - started, 3),
        "revision": hashlib.sha256(revision_material.encode("utf-8")).hexdigest()[:16],
        "entries": entries,
    }


def _normalise_transform(
    value: Mapping[str, Any] | None,
    *,
    display_mode: str,
    width: int = 0,
    height: int = 0,
) -> dict[str, int]:
    if display_mode not in {*CG_DISPLAY_PRESETS, "custom"}:
        raise CgWorkspaceError("CG 显示方式必须是 standard、closeup 或 custom")
    base = dict(CG_DISPLAY_PRESETS.get(display_mode, CG_DISPLAY_PRESETS["standard"]))
    if display_mode != "closeup":
        base["scale"] = fit_cg_scale(width, height)
    if isinstance(value, Mapping):
        for key in ("x", "y", "depth", "rotation", "scale"):
            if key in value:
                try:
                    base[key] = int(value[key])
                except (TypeError, ValueError) as exc:
                    raise CgWorkspaceError(f"CG {key} 必须是整数") from exc
    if not -4096 <= base["x"] <= 4096 or not -4096 <= base["y"] <= 4096:
        raise CgWorkspaceError("CG X/Y 必须在 -4096 到 4096 之间")
    if not 1 <= base["depth"] <= 4000:
        raise CgWorkspaceError("CG depth 必须在 1 到 4000 之间")
    if not -3600 <= base["rotation"] <= 3600:
        raise CgWorkspaceError("CG rotation 必须在 -3600 到 3600 之间")
    if not CG_SCALE_MIN <= base["scale"] <= CG_SCALE_MAX:
        raise CgWorkspaceError(
            f"CG scale 必须在 {CG_SCALE_MIN} 到 {CG_SCALE_MAX} 之间"
        )
    return base


def _freeze_payload(asset: Mapping[str, Any], archive: Path) -> str:
    try:
        expected_size = int(asset["archive_size"])
        expected_mtime = int(asset["archive_mtime_ns"])
        entry_index = int(asset["entry_index"])
        entry_size = int(asset["entry_size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CgWorkspaceError("CG 缺少可冻结的归档或条目身份") from exc
    stat = archive.stat()
    if int(stat.st_size) != expected_size or int(stat.st_mtime_ns) != expected_mtime:
        raise CgWorkspaceError("CG 来源归档在扫描后已变化，请重新扫描")
    try:
        payload, info = read_bin_entry_payload(archive, entry_index)
    except (OSError, ResourceBuildError, TypeError, ValueError) as exc:
        raise CgWorkspaceError("CG 无法完成 bounded payload 冻结") from exc
    if entry_size <= 0 or len(payload) != entry_size:
        raise CgWorkspaceError("CG 条目大小在扫描后已变化，请重新扫描")
    expected_name = str(asset.get("resource_name") or "").strip()
    if not expected_name or str(info.get("source_name") or "") != expected_name:
        raise CgWorkspaceError("CG 条目名称在扫描后已变化，请重新扫描")
    for key in ("width", "height", "frame_count"):
        if int(asset.get(key) or 0) != int(info.get(key) or 0):
            raise CgWorkspaceError(f"CG 的 {key} 在扫描后已变化，请重新扫描")
    expected_probe = str(asset.get("payload_probe_sha256") or "").strip().casefold()
    actual_probe = hzc_payload_probe(payload)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_probe):
        raise CgWorkspaceError("CG 扫描结果缺少 payload probe，请重新扫描")
    if expected_probe != actual_probe:
        raise CgWorkspaceError("CG payload 在扫描后已变化，请重新扫描")
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    expected_sha256 = str(asset.get("payload_sha256") or "").strip().casefold()
    if expected_sha256 and expected_sha256 != payload_sha256:
        raise CgWorkspaceError("CG payload 与冻结 SHA-256 不一致，请重新选择")
    return payload_sha256


def stage_cg_from_asset(
    asset: Mapping[str, Any],
    *,
    display_mode: str = "standard",
    transform: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Freeze one trusted CG reference into scene state."""

    if not isinstance(asset, Mapping) or not str(asset.get("asset_id") or "").startswith("cg-"):
        raise CgWorkspaceError("CG 资源缺少稳定 asset_id")
    archive = Path(str(asset.get("archive_path") or "")).expanduser().resolve()
    archive_name = str(asset.get("archive_name") or "").casefold()
    if not archive.is_file() or archive.name.casefold() != archive_name:
        raise CgWorkspaceError(f"CG 来源归档不存在或名称不一致: {archive}")
    if archive_name not in CG_ARCHIVE_SELECTORS:
        raise CgWorkspaceError("CG 来源归档类型不受支持")
    selector = int(asset.get("archive_selector", CG_ARCHIVE_SELECTORS[archive_name]))
    if selector != CG_ARCHIVE_SELECTORS[archive_name]:
        raise CgWorkspaceError("CG 归档选择器与 archive_name 不一致")
    resource_name = str(asset.get("resource_name") or "").strip()
    if not resource_name:
        raise CgWorkspaceError("CG 缺少精确 resource_name，不能交给原作加载器")
    build_mode = str(asset.get("build_mode") or "").strip().casefold()
    if build_mode not in {"direct_reference", "copy_hzc"}:
        raise CgWorkspaceError("CG build_mode 必须是 direct_reference 或 copy_hzc")
    display = str(display_mode or "standard").strip().casefold()
    frozen_transform = _normalise_transform(
        transform,
        display_mode=display,
        width=int(asset.get("width") or 0),
        height=int(asset.get("height") or 0),
    )
    # Selection is the formal freeze point for both modes.  Reading and
    # hashing one selected payload keeps metadata-only source scans fast while
    # ensuring a native direct reference cannot silently drift afterwards.
    payload_sha256 = _freeze_payload(asset, archive)
    return {
        "asset_id": str(asset["asset_id"]),
        "label": str(asset.get("label") or resource_name),
        "source_kind": str(asset.get("source_kind") or "fvp_external"),
        "build_mode": build_mode,
        "source_game": str(asset.get("source_game") or archive.parent.name),
        "project_dir": str(asset.get("project_dir") or archive.parent),
        "archive_name": archive.name,
        "archive_path": str(archive),
        "archive_selector": selector,
        "archive_size": int(asset.get("archive_size") or archive.stat().st_size),
        "archive_mtime_ns": int(asset.get("archive_mtime_ns") or archive.stat().st_mtime_ns),
        "entry_index": int(asset["entry_index"]),
        "entry_size": int(asset.get("entry_size") or 0),
        "payload_sha256": payload_sha256,
        "payload_probe_sha256": str(asset.get("payload_probe_sha256") or ""),
        "resource_name": resource_name,
        "virtual_path": str(asset.get("virtual_path") or ""),
        "width": int(asset.get("width") or 0),
        "height": int(asset.get("height") or 0),
        "frame_count": max(1, int(asset.get("frame_count") or 1)),
        "display_mode": display,
        "transform": frozen_transform,
    }


def validate_staged_cg_source(
    event_visual: Mapping[str, Any],
    *,
    current_game_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Revalidate one staged CG before emitting an install-ready candidate."""

    if not isinstance(event_visual, Mapping):
        raise CgWorkspaceError("冻结 CG 必须是 Mapping")
    archive = Path(str(event_visual.get("archive_path") or "")).expanduser().resolve()
    archive_name = str(event_visual.get("archive_name") or "").strip().casefold()
    if not archive.is_file() or archive.name.casefold() != archive_name:
        raise CgWorkspaceError("冻结 CG 的 graph_vis 来源不存在或名称不一致")
    build_mode = str(event_visual.get("build_mode") or "").strip().casefold()
    if build_mode not in {"direct_reference", "copy_hzc"}:
        raise CgWorkspaceError("冻结 CG build_mode 无效")
    if build_mode == "direct_reference":
        if current_game_dir is None:
            raise CgWorkspaceError("本作直引 CG 缺少当前目标游戏目录")
        current_root = Path(current_game_dir).expanduser().resolve()
        frozen_root = Path(
            str(event_visual.get("project_dir") or archive.parent)
        ).expanduser().resolve()
        if not _same_directory(frozen_root, current_root) or not _same_directory(
            archive.parent,
            current_root,
        ):
            raise CgWorkspaceError("本作直引 CG 不属于当前目标游戏，请重新扫描")
    payload_sha256 = _freeze_payload(event_visual, archive)
    return {
        "archive_path": str(archive),
        "archive_name": archive.name,
        "resource_name": str(event_visual.get("resource_name") or ""),
        "entry_index": int(event_visual.get("entry_index") or 0),
        "payload_sha256": payload_sha256,
        "build_mode": build_mode,
        "current_game_bound": build_mode != "direct_reference" or current_game_dir is not None,
    }


def update_stage_cg_display(
    event_visual: Mapping[str, Any],
    *,
    display_mode: str | None = None,
    transform: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a copy with display parameters changed but source identity intact."""

    if not isinstance(event_visual, Mapping):
        raise CgWorkspaceError("舞台尚未设置 CG")
    result = dict(event_visual)
    mode = str(display_mode or result.get("display_mode") or "standard").strip().casefold()
    result["display_mode"] = mode
    result["transform"] = _normalise_transform(
        transform if transform is not None else result.get("transform"),
        display_mode=mode,
        width=int(result.get("width") or 0),
        height=int(result.get("height") or 0),
    )
    return result


__all__ = [
    "CG_ARCHIVES",
    "CG_ARCHIVE_SELECTORS",
    "CG_DISPLAY_PRESETS",
    "CG_SCALE_MAX",
    "CG_SCALE_MIN",
    "CG_STAGE_HEIGHT",
    "CG_STAGE_WIDTH",
    "CgWorkspaceError",
    "fit_cg_scale",
    "scan_cg_source",
    "stage_cg_from_asset",
    "update_stage_cg_display",
    "validate_staged_cg_source",
]
