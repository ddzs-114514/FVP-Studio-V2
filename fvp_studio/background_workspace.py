"""Read-only background discovery for the V2 visual stage.

The editor deliberately keeps source discovery separate from installation.
Backgrounds owned by the active game can be referenced by their existing FVP
virtual path, while a background selected from another game is only marked as
an HZC migration candidate.  Neither operation writes a BIN or HCB.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import time
from typing import Any

from .resource_builder import (
    ResourceBuildError,
    read_bin_entry_payload,
    scan_hzc_archive,
)


BACKGROUND_ARCHIVES = ("graph.bin", "graph_bg.bin")
BACKGROUND_FITS = {"cover", "contain", "stretch"}
BACKGROUND_VARIANTS = {"primary", "blur"}
_BACKGROUND_NAME = re.compile(r"^(?:bg|back|background)[_\-0-9a-z]*", re.IGNORECASE)
_NON_BACKGROUND_NAME = re.compile(r"^(?:chr|char|face|diss|mask|ef|effect|window|sys)", re.IGNORECASE)


class BackgroundWorkspaceError(ValueError):
    """Raised when a background source or stage reference is invalid."""


def _same_directory(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    try:
        return left.samefile(right)
    except OSError:
        return left.resolve() == right.resolve()


def _background_confidence(archive_name: str, entry: dict[str, Any]) -> str:
    """Return a conservative UI confidence label without decoding the frame."""

    name = str(entry.get("source_name") or entry.get("label") or "").strip()
    width = max(0, int(entry.get("width") or 0))
    height = max(0, int(entry.get("height") or 0))
    if _BACKGROUND_NAME.match(name):
        return "named"
    if archive_name.casefold() == "graph_bg.bin":
        return "background_archive"
    if _NON_BACKGROUND_NAME.match(name):
        return "possible"
    if width >= 960 and height >= 540 and width >= height:
        return "landscape"
    return "possible"


def _asset_id(root: Path, archive: Path, entry: dict[str, Any]) -> str:
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
    return "bg-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def _archive_paths(requested: Path) -> tuple[Path, list[Path]]:
    if requested.is_file():
        if requested.name.casefold() not in {name.casefold() for name in BACKGROUND_ARCHIVES}:
            raise BackgroundWorkspaceError(
                "背景来源文件必须是 graph.bin 或 graph_bg.bin，也可以填写游戏目录"
            )
        return requested.parent, [requested]
    if not requested.is_dir():
        raise BackgroundWorkspaceError(f"背景来源路径不存在: {requested}")
    archives = [requested / name for name in BACKGROUND_ARCHIVES if (requested / name).is_file()]
    if not archives:
        expected = " / ".join(BACKGROUND_ARCHIVES)
        raise BackgroundWorkspaceError(f"游戏目录中找不到 {expected}: {requested}")
    return requested, archives


def _paired_reference(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "asset_id": item["asset_id"],
        "label": item["label"],
        "archive_name": item["archive_name"],
        "archive_path": item["archive_path"],
        "archive_size": item.get("archive_size"),
        "archive_mtime_ns": item.get("archive_mtime_ns"),
        "entry_index": item["entry_index"],
        "entry_size": item["entry_size"],
        "resource_name": item["resource_name"],
        "virtual_path": item["virtual_path"],
        "width": item["width"],
        "height": item["height"],
        "frame_count": item["frame_count"],
        "type": item["type"],
        "confidence": item["confidence"],
    }


def _collapse_blur_variants(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Hide obvious blur duplicates while retaining their exact source ref."""

    by_archive_name = {
        (str(item["archive_name"]).casefold(), str(item["resource_name"]).casefold()): item
        for item in items
        if item.get("resource_name")
    }
    primary_by_name = {
        str(item["resource_name"]).casefold(): item
        for item in items
        if item.get("resource_name") and str(item["archive_name"]).casefold() == "graph.bin"
    }
    hidden: set[str] = set()
    for item in items:
        name = str(item.get("resource_name") or "")
        if not name:
            continue
        archive_key = str(item["archive_name"]).casefold()
        name_key = name.casefold()
        primary: dict[str, Any] | None = None
        if archive_key == "graph_bg.bin":
            primary = primary_by_name.get(name_key)
            if primary is None and name_key.endswith("b"):
                primary = primary_by_name.get(name_key[:-1])
        elif name_key.endswith("b"):
            primary = by_archive_name.get((archive_key, name_key[:-1]))
        if primary is not None and primary["asset_id"] != item["asset_id"]:
            if not primary.get("blur"):
                primary["blur"] = _paired_reference(item)
            hidden.add(item["asset_id"])

    # A clear graph entry may have an adjacent blur entry in either archive.
    for item in items:
        if item.get("blur") or not item.get("resource_name"):
            continue
        name_key = str(item["resource_name"]).casefold()
        candidates = (
            by_archive_name.get(("graph_bg.bin", name_key)),
            by_archive_name.get(("graph_bg.bin", name_key + "b")),
            by_archive_name.get((str(item["archive_name"]).casefold(), name_key + "b")),
        )
        blur = next(
            (candidate for candidate in candidates if candidate and candidate["asset_id"] != item["asset_id"]),
            None,
        )
        if blur is not None:
            item["blur"] = _paired_reference(blur)
            hidden.add(blur["asset_id"])
    return [item for item in items if item["asset_id"] not in hidden]


def scan_background_source(
    path: str | Path,
    *,
    current_game_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Scan one FVP game for background candidates without decoding images."""

    started = time.perf_counter()
    requested = Path(path).expanduser().resolve()
    root, archives = _archive_paths(requested)
    current_root = (
        Path(current_game_dir).expanduser().resolve() if current_game_dir is not None else None
    )
    is_current_game = _same_directory(root, current_root)
    source_game = root.name
    assets: list[dict[str, Any]] = []
    archive_summaries: list[dict[str, Any]] = []
    total_visuals = 0
    total_skipped = 0

    for archive in archives:
        archive_stat = archive.stat()
        try:
            scan = scan_hzc_archive(archive)
        except (ResourceBuildError, OSError) as exc:
            raise BackgroundWorkspaceError(str(exc)) from exc
        total_visuals += int(scan.get("visual_count") or 0)
        total_skipped += int(scan.get("skipped_count") or 0)
        archive_summaries.append(
            {
                "archive_name": archive.name,
                "archive_path": str(archive),
                "entry_count": int(scan.get("entry_count") or 0),
                "visual_count": int(scan.get("visual_count") or 0),
                "skipped_count": int(scan.get("skipped_count") or 0),
            }
        )
        for entry in scan.get("entries", []):
            if not isinstance(entry, dict):
                continue
            resource_name = str(entry.get("source_name") or "").strip()
            entry_index = int(entry["entry_index"])
            confidence = _background_confidence(archive.name, entry)
            asset = {
                "asset_id": _asset_id(root, archive, entry),
                "source_kind": "native" if is_current_game else "fvp_external",
                "build_mode": "direct_reference" if is_current_game else "copy_hzc",
                "source_game": source_game,
                "project_dir": str(root),
                "archive_name": archive.name,
                "archive_path": str(archive),
                "archive_size": int(archive_stat.st_size),
                "archive_mtime_ns": int(archive_stat.st_mtime_ns),
                "entry_index": entry_index,
                "entry_size": int(entry.get("entry_size") or 0),
                "resource_name": resource_name,
                "label": resource_name or f"{archive.stem} entry #{entry_index}",
                "virtual_path": f"{archive.stem}/{resource_name}" if resource_name else "",
                "width": int(entry.get("width") or 0),
                "height": int(entry.get("height") or 0),
                "frame_count": max(1, int(entry.get("frame_count") or 1)),
                "type": str(entry.get("type") or "HZC"),
                "confidence": confidence,
                "blur": None,
            }
            assets.append(asset)

    entries = _collapse_blur_variants(assets)
    revision_material = "|".join(
        f"{path.name}:{path.stat().st_size}:{path.stat().st_mtime_ns}" for path in archives
    )
    return {
        "schema": "fvp-studio-v2.background-source.v1",
        "project_dir": str(root),
        "source_game": source_game,
        "source_kind": "current_game" if is_current_game else "other_fvp_game",
        "build_mode": "direct_reference" if is_current_game else "copy_hzc",
        "is_current_game": is_current_game,
        "read_only": True,
        "archives": archive_summaries,
        "visual_count": total_visuals,
        "background_count": len(entries),
        "skipped_count": total_skipped,
        "scan_seconds": round(time.perf_counter() - started, 3),
        "revision": hashlib.sha256(revision_material.encode("utf-8")).hexdigest()[:16],
        "entries": entries,
    }


def _stage_archive(reference: dict[str, Any], *, variant: str) -> Path:
    archive_name = str(reference.get("archive_name") or "").strip()
    archive = Path(str(reference.get("archive_path") or "")).expanduser().resolve()
    if (
        not archive_name
        or archive_name.casefold() != archive.name.casefold()
        or not archive.is_file()
        or archive.name.casefold() not in {name.casefold() for name in BACKGROUND_ARCHIVES}
    ):
        raise BackgroundWorkspaceError(
            f"背景 {variant} 归档不存在、名称不一致或类型不受支持: {archive}"
        )
    return archive


def _freeze_payload_identity(
    reference: dict[str, Any],
    archive: Path,
    *,
    variant: str,
) -> dict[str, Any]:
    """Hash one selected HZC with a bounded read, never the whole archive."""

    stat = archive.stat()
    try:
        expected_archive_size = int(reference["archive_size"])
        expected_archive_mtime_ns = int(reference["archive_mtime_ns"])
        entry_index = int(reference["entry_index"])
        expected_entry_size = int(reference["entry_size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BackgroundWorkspaceError(
            f"背景 {variant} 缺少可冻结的归档或条目身份"
        ) from exc
    if (
        expected_archive_size != int(stat.st_size)
        or expected_archive_mtime_ns != int(stat.st_mtime_ns)
    ):
        raise BackgroundWorkspaceError(
            f"背景 {variant} 来源归档在扫描后已变化，请重新扫描"
        )
    try:
        payload, info = read_bin_entry_payload(archive, entry_index)
    except (OSError, ResourceBuildError, TypeError, ValueError) as exc:
        raise BackgroundWorkspaceError(
            f"背景 {variant} 无法完成 bounded payload 冻结"
        ) from exc
    if expected_entry_size <= 0 or len(payload) != expected_entry_size:
        raise BackgroundWorkspaceError(
            f"背景 {variant} 条目大小在扫描后已变化，请重新扫描"
        )
    for key in ("width", "height", "frame_count"):
        if int(reference.get(key) or 0) != int(info.get(key) or 0):
            raise BackgroundWorkspaceError(
                f"背景 {variant} 的 {key} 在扫描后已变化，请重新扫描"
            )
    frozen = dict(reference)
    frozen["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    return frozen


def stage_background_from_asset(
    asset: dict[str, Any],
    fit: str = "cover",
    *,
    variant: str = "primary",
) -> dict[str, Any]:
    """Freeze a trusted primary or paired-blur source reference into scene state."""

    if not isinstance(asset, dict) or not str(asset.get("asset_id") or "").startswith("bg-"):
        raise BackgroundWorkspaceError("背景资源缺少稳定 asset_id")
    base_asset_id = str(asset["asset_id"])
    variant_value = str(variant).strip().casefold()
    if variant_value not in BACKGROUND_VARIANTS:
        raise BackgroundWorkspaceError("背景 variant 必须是 primary 或 blur")
    fit_value = str(fit or "cover").strip().casefold()
    if fit_value not in BACKGROUND_FITS:
        raise BackgroundWorkspaceError("背景显示方式必须是 cover、contain 或 stretch")

    blur = asset.get("blur") if isinstance(asset.get("blur"), dict) else None
    selected = asset
    if variant_value == "blur":
        if blur is None:
            raise BackgroundWorkspaceError("所选背景没有已扫描的模糊层")
        selected = blur
        selected_asset_id = str(selected.get("asset_id") or "")
        if not selected_asset_id.startswith("bg-") or selected_asset_id == base_asset_id:
            raise BackgroundWorkspaceError("背景模糊层缺少独立稳定 asset_id")
        if not str(selected.get("resource_name") or "").strip():
            raise BackgroundWorkspaceError("背景模糊层缺少精确 resource_name")
    else:
        selected_asset_id = base_asset_id

    archive = _stage_archive(selected, variant=variant_value)
    build_mode = str(asset.get("build_mode") or "copy_hzc")
    selected_frozen = dict(selected)
    frozen_blur = dict(blur) if variant_value == "primary" and blur is not None else None
    if build_mode == "copy_hzc":
        selected_frozen = _freeze_payload_identity(
            selected,
            archive,
            variant=variant_value,
        )
        if frozen_blur is not None:
            blur_archive = _stage_archive(frozen_blur, variant="blur")
            frozen_blur = _freeze_payload_identity(
                frozen_blur,
                blur_archive,
                variant="blur",
            )
    try:
        entry_index = int(selected["entry_index"])
        width = int(selected.get("width") or 0)
        height = int(selected.get("height") or 0)
        frame_count = max(1, int(selected.get("frame_count") or 1))
    except (KeyError, TypeError, ValueError) as exc:
        raise BackgroundWorkspaceError(
            f"背景 {variant_value} 扫描引用缺少有效条目或尺寸元数据"
        ) from exc
    if entry_index < 0 or width < 0 or height < 0:
        raise BackgroundWorkspaceError(f"背景 {variant_value} 扫描引用包含非法数值")

    resource_name = str(selected.get("resource_name") or "")
    return {
        "asset_id": selected_asset_id,
        "base_asset_id": base_asset_id,
        "variant": variant_value,
        "label": str(selected.get("label") or resource_name or "未命名背景"),
        "source_kind": str(asset.get("source_kind") or "fvp_external"),
        "build_mode": build_mode,
        "source_game": str(asset.get("source_game") or archive.parent.name),
        "project_dir": str(asset.get("project_dir") or archive.parent),
        "archive_name": archive.name,
        "archive_path": str(archive),
        "archive_size": int(selected.get("archive_size") or archive.stat().st_size),
        "archive_mtime_ns": int(
            selected.get("archive_mtime_ns") or archive.stat().st_mtime_ns
        ),
        "entry_index": entry_index,
        "entry_size": int(selected.get("entry_size") or 0),
        "payload_sha256": selected_frozen.get("payload_sha256"),
        "resource_name": resource_name,
        "virtual_path": str(selected.get("virtual_path") or ""),
        "width": width,
        "height": height,
        "frame_count": frame_count,
        "blur": frozen_blur,
        "fit": fit_value,
    }
