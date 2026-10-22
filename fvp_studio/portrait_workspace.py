"""Read-only workspace helpers for the FVP Studio V2 portrait panel.

The browser sends one explicit body entry and one explicit expression entry.
This module turns that request into a deterministic, serialisable draft.  It
does not append to the target graph_bs, patch an HCB, or guess a story insertion point.
Those destructive steps deliberately live behind the later candidate/build
workflow.
"""

from __future__ import annotations

from io import BytesIO
import hashlib
from pathlib import Path
from typing import Any, Mapping

from .portrait_import import (
    FvpLayeredImportRequest,
    StageReference,
    inspect_fvp_layered_pair,
)
from .portrait_project import PortraitProjectError
from .resource_builder import (
    ResourceBuildError,
    decoded_bin_entry_image,
    read_bin_entry_payload,
    scan_hzc_archive,
)


PORTRAIT_DRAFT_SCHEMA = "fvp-studio-v2.layered-portrait-draft.v1"
DEDICATED_PORTRAIT_ARCHIVE = "graph_bs.bin"
PREFERRED_MIXED_PORTRAIT_ARCHIVES = ("graph.bin", "graph2.bin")
FORM_IDS: dict[int, str] = {
    -1: "U",
    0: "L",
    1: "base",
    2: "S",
}


def _portrait_source_candidates(requested_path: Path) -> tuple[Path, list[Path]]:
    """Resolve a game directory or one explicit visual BIN without writing it."""

    requested = Path(requested_path).expanduser().resolve()
    if requested.is_file():
        if requested.suffix.casefold() != ".bin":
            raise PortraitProjectError("立绘来源文件必须是 FVP 的 .bin 视觉归档")
        return requested.parent, [requested]
    if not requested.is_dir():
        raise PortraitProjectError(f"立绘来源目录或 BIN 不存在: {requested}")

    archives = {
        item.name.casefold(): item
        for item in requested.iterdir()
        if item.is_file() and item.suffix.casefold() == ".bin"
    }
    dedicated = archives.get(DEDICATED_PORTRAIT_ARCHIVE)
    if dedicated is not None:
        return requested, [dedicated]

    candidates: list[Path] = []
    for name in PREFERRED_MIXED_PORTRAIT_ARCHIVES:
        archive = archives.get(name)
        if archive is not None:
            candidates.append(archive)
    candidates.extend(
        archive
        for name, archive in sorted(archives.items())
        if name.startswith("graph") and archive not in candidates
    )
    if not candidates:
        raise PortraitProjectError(
            f"来源目录没有可扫描的 FVP 视觉归档（graph*.bin）: {requested}"
        )
    return requested, candidates


def _mixed_archive_portrait_entries(scan: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Keep only strongly paired body/expression entries from a mixed graph BIN.

    Older FVP games commonly store every visual class in ``graph.bin``.  A
    single-frame 32-bit body and a smaller multi-frame 32-bit entry whose name
    extends the body name form a strong, game-agnostic layered-portrait
    relation.  Adjacency is preferred but not required because some engines
    place speech-bubble variants between a body and its normal face atlas.
    Requiring the remaining signals avoids showing backgrounds, CGs and UI
    animations as portrait candidates.
    """

    entries = [dict(item) for item in scan.get("entries", []) if isinstance(item, Mapping)]
    by_index: dict[int, dict[str, Any]] = {}
    bodies: list[dict[str, Any]] = []
    for item in entries:
        try:
            by_index[int(item["entry_index"])] = item
        except (KeyError, TypeError, ValueError):
            continue
        try:
            if (
                int(item.get("frame_count", 0)) == 1
                and str(item.get("type", "")).casefold() == "single32"
                and str(item.get("source_name") or "").strip()
            ):
                bodies.append(item)
        except (TypeError, ValueError):
            continue

    paired: dict[int, dict[str, Any]] = {}
    for expression in entries:
        try:
            expression_index = int(expression["entry_index"])
            expression_frames = int(expression.get("frame_count", 0))
        except (KeyError, TypeError, ValueError):
            continue
        if expression_frames <= 1:
            continue
        if str(expression.get("type", "")).casefold() != "multi32":
            continue

        expression_name = str(expression.get("source_name") or "").strip()
        if not expression_name:
            continue

        def matches_name(candidate: Mapping[str, Any]) -> bool:
            body_name = str(candidate.get("source_name") or "").strip()
            if not body_name or not expression_name.startswith(body_name):
                return False
            suffix = expression_name[len(body_name) :]
            return bool(suffix) and (not suffix[0].isalnum() or suffix[0] == "表")

        body = by_index.get(expression_index - 1)
        if body is None or not matches_name(body):
            matching_bodies = [candidate for candidate in bodies if matches_name(candidate)]
            body = max(
                matching_bodies,
                key=lambda candidate: len(str(candidate.get("source_name") or "")),
                default=None,
            )
        if body is None:
            continue
        try:
            if int(expression.get("width", 0)) > int(body.get("width", 0)):
                continue
            if int(expression.get("height", 0)) > int(body.get("height", 0)):
                continue
        except (TypeError, ValueError):
            continue

        body_copy = dict(body)
        expression_copy = dict(expression)
        body_copy.update(role="body", pair_entry_index=expression_index)
        expression_copy.update(
            role="expression", pair_entry_index=int(body_copy["entry_index"])
        )
        paired[int(body_copy["entry_index"])] = body_copy
        paired[expression_index] = expression_copy

    return [paired[index] for index in sorted(paired)]


def scan_portrait_source(requested_path: Path) -> dict[str, Any]:
    """Discover a dedicated or mixed FVP portrait archive read-only."""

    root, candidates = _portrait_source_candidates(requested_path)
    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    for archive in candidates:
        try:
            scan = scan_hzc_archive(archive)
        except (ResourceBuildError, OSError) as exc:
            errors.append(f"{archive.name}: {exc}")
            continue
        if archive.name.casefold() == DEDICATED_PORTRAIT_ARCHIVE:
            entries = [dict(item) for item in scan.get("entries", [])]
            source_layout = "dedicated_portrait_archive"
            pair_count = min(
                sum(int(item.get("frame_count", 0)) == 1 for item in entries),
                sum(int(item.get("frame_count", 0)) > 1 for item in entries),
            )
        else:
            entries = _mixed_archive_portrait_entries(scan)
            source_layout = "mixed_visual_archive"
            pair_count = sum(item.get("role") == "expression" for item in entries)
        reports.append(
            {
                **scan,
                "archive_path": str(archive.resolve()),
                "archive_name": archive.name,
                "entries": entries,
                "visual_count": len(entries),
                "filtered_count": max(0, int(scan.get("visual_count", 0)) - len(entries)),
                "portrait_pair_count": pair_count,
                "source_layout": source_layout,
            }
        )

    if not reports:
        detail = "；".join(errors) if errors else "没有候选归档"
        raise PortraitProjectError(f"无法扫描立绘来源: {detail}")
    best = max(reports, key=lambda item: (int(item["portrait_pair_count"]), int(item["visual_count"])))
    if int(best["portrait_pair_count"]) < 1:
        scanned = "、".join(item["archive_name"] for item in reports)
        raise PortraitProjectError(
            f"已扫描 {scanned}，但没有识别到可靠的单帧身体 + 多帧表情配对"
        )
    return {
        **best,
        "project_dir": str(root),
        "source_game": root.name,
        "read_only": True,
        "candidate_archives": [item["archive_name"] for item in reports],
    }


def _text(payload: Mapping[str, Any], key: str, label: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise PortraitProjectError(f"{label}不能为空")
    return value


def _integer(
    payload: Mapping[str, Any],
    key: str,
    label: str,
    *,
    minimum: int | None = None,
    default: int | None = None,
) -> int:
    raw = payload.get(key, default)
    if raw is None or str(raw).strip() == "":
        raise PortraitProjectError(f"{label}不能为空")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise PortraitProjectError(f"{label}必须是整数") from exc
    if minimum is not None and value < minimum:
        raise PortraitProjectError(f"{label}不能小于 {minimum}")
    return value


def _number(
    payload: Mapping[str, Any],
    key: str,
    label: str,
    *,
    default: float,
) -> float:
    raw = payload.get(key, default)
    try:
        return float(raw)
    except (TypeError, ValueError) as exc:
        raise PortraitProjectError(f"{label}必须是数字") from exc


def _boolean(payload: Mapping[str, Any], key: str, *, default: bool = False) -> bool:
    raw = payload.get(key, default)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)) and raw in {0, 1}:
        return bool(raw)
    value = str(raw).strip().casefold()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off", ""}:
        return False
    raise PortraitProjectError(f"{key} 必须是布尔值")


def _optional_pair(
    payload: Mapping[str, Any], x_key: str, y_key: str, label: str
) -> tuple[int, int] | None:
    x_raw = payload.get(x_key)
    y_raw = payload.get(y_key)
    x_empty = x_raw is None or str(x_raw).strip() == ""
    y_empty = y_raw is None or str(y_raw).strip() == ""
    if x_empty and y_empty:
        return None
    if x_empty or y_empty:
        raise PortraitProjectError(f"{label} X/Y 必须同时填写")
    x = _integer(payload, x_key, f"{label} X", minimum=0)
    y = _integer(payload, y_key, f"{label} Y", minimum=0)
    return x, y


def form_id_for_code(raw: Any) -> tuple[int, str]:
    """Normalize the Hoshimemo/Sakura form selector used by the UI.

    The mapping is target-profile knowledge, not a universal FVP ABI:
    ``0 -> L``, ``-1 -> U``, ``1 -> base`` and ``2 -> S``.
    """

    try:
        code = int(raw)
    except (TypeError, ValueError) as exc:
        raise PortraitProjectError("立绘尺寸类型必须是 -1、0、1 或 2") from exc
    try:
        return code, FORM_IDS[code]
    except KeyError as exc:
        raise PortraitProjectError("立绘尺寸类型必须是 -1、0、1 或 2") from exc


def _read_frozen_payload(
    archive: Path,
    entry_index: int,
    label: str,
) -> tuple[bytes, int]:
    """Read one exact compressed entry for the draft's source identity."""

    try:
        raw_payload, raw_info = read_bin_entry_payload(archive, entry_index)
    except (OSError, ResourceBuildError, TypeError, ValueError) as exc:
        raise PortraitProjectError(
            f"{label}无法完成 bounded payload 冻结"
        ) from exc
    if not isinstance(raw_payload, (bytes, bytearray, memoryview)):
        raise PortraitProjectError(f"{label} bounded 读取没有返回 bytes payload")
    if not isinstance(raw_info, Mapping):
        raise PortraitProjectError(f"{label} bounded 读取没有返回元数据")

    payload = bytes(raw_payload)
    reported_size = raw_info.get("compressed_size", raw_info.get("entry_size", len(payload)))
    try:
        entry_size = int(reported_size)
    except (TypeError, ValueError) as exc:
        raise PortraitProjectError(f"{label} bounded 读取返回的 entry_size 无效") from exc
    if entry_size != len(payload):
        raise PortraitProjectError(f"{label} bounded 读取返回的 entry_size 与 payload 不一致")
    return payload, entry_size


def build_layered_portrait_draft(
    payload: Mapping[str, Any], archive_path: Path
) -> dict[str, Any]:
    """Analyse one strongly-bound FVP body/face pair without writing files."""

    if not isinstance(payload, Mapping):
        raise PortraitProjectError("分层立绘请求必须是对象")
    archive = Path(archive_path).expanduser().resolve()
    if not archive.is_file():
        raise PortraitProjectError(f"找不到来源视觉 BIN: {archive}")
    try:
        archive_stat = archive.stat()
    except OSError as exc:
        raise PortraitProjectError(f"无法读取来源视觉 BIN 身份: {archive}") from exc

    form_code, form_id = form_id_for_code(payload.get("form_code", 0))
    body_entry = _integer(payload, "body_entry", "身体层 entry", minimum=0)
    face_entry = _integer(payload, "face_entry", "表情层 entry", minimum=0)
    if body_entry == face_entry:
        raise PortraitProjectError("身体层与表情层不能指向同一个 BIN entry")

    manual_face_offset = _optional_pair(
        payload, "manual_face_x", "manual_face_y", "手动脸部坐标"
    )
    request = FvpLayeredImportRequest(
        character_id=_text(payload, "character_id", "角色 ID"),
        display_name=_text(payload, "display_name", "角色显示名"),
        variant_id=_text(payload, "variant_id", "变体 ID"),
        pose_id=_text(payload, "pose_id", "动作 ID"),
        form_id=form_id,
        archive=archive,
        body_entry=body_entry,
        body_resource_name=_text(payload, "body_resource_name", "身体层资源名"),
        face_entry=face_entry,
        face_resource_name=_text(payload, "face_resource_name", "表情层资源名"),
        source_game=str(payload.get("source_game", "")).strip(),
        default_expression=str(payload.get("default_expression", "000")).strip() or "000",
        manual_face_offset=manual_face_offset,
        allow_name_mismatch=_boolean(payload, "allow_name_mismatch"),
    )
    reference = StageReference(
        target_visible_height=_integer(
            payload, "target_visible_height", "目标可见高度", minimum=1
        ),
        baseline_y=_integer(payload, "baseline_y", "舞台基线 Y"),
        default_z=_integer(payload, "default_z", "默认 Z", default=1500),
        minimum_ratio=_number(
            payload, "minimum_ratio", "缩放最小比例", default=0.60
        ),
        maximum_ratio=_number(
            payload, "maximum_ratio", "缩放最大比例", default=1.80
        ),
        hard_minimum=_integer(
            payload, "hard_minimum", "缩放最小硬边界", minimum=1, default=100
        ),
        hard_maximum=_integer(
            payload, "hard_maximum", "缩放最大硬边界", minimum=1, default=4000
        ),
        wheel_step=_integer(
            payload, "wheel_step", "滚轮缩放步长", minimum=1, default=25
        ),
    )
    result = inspect_fvp_layered_pair(request, reference)
    body_payload, body_entry_size = _read_frozen_payload(
        archive, body_entry, "身体层"
    )
    face_payload, face_entry_size = _read_frozen_payload(
        archive, face_entry, "表情层"
    )
    try:
        current_archive_stat = archive.stat()
    except OSError as exc:
        raise PortraitProjectError("无法复检分析期间的来源视觉 BIN 身份") from exc
    if (
        int(current_archive_stat.st_size) != int(archive_stat.st_size)
        or int(current_archive_stat.st_mtime_ns) != int(archive_stat.st_mtime_ns)
    ):
        raise PortraitProjectError("来源视觉 BIN 在分析期间已变化，请重新分析")
    transform = result.suggested_transform.to_dict()
    policy = result.variant.scale_policy.to_dict()
    draft = {
        "schema": PORTRAIT_DRAFT_SCHEMA,
        "candidate_status": "analysis_complete",
        "install_ready": False,
        "character": {
            "character_id": request.character_id,
            "display_name": request.display_name,
        },
        "source_game": request.source_game,
        "form_code": form_code,
        "form_id": form_id,
        "variant": result.variant.to_dict(),
        "locked_pair": {
            "archive": archive.name,
            "body_entry": body_entry,
            "face_entry": face_entry,
            "body_resource_name": request.body_resource_name,
            "face_resource_name": request.face_resource_name,
            "archive_size": int(archive_stat.st_size),
            "archive_mtime_ns": int(archive_stat.st_mtime_ns),
            "body_entry_size": body_entry_size,
            "face_entry_size": face_entry_size,
            "body_payload_sha256": hashlib.sha256(body_payload).hexdigest(),
            "face_payload_sha256": hashlib.sha256(face_payload).hexdigest(),
        },
        "transform": transform,
        "scale_policy": policy,
        "stage_reference": {
            "target_visible_height": reference.target_visible_height,
            "baseline_y": reference.baseline_y,
            "default_z": reference.default_z,
        },
        "report": result.report,
        "next_step": (
            "只读分析已完成。确认动作/表情/尺寸与变换后，才能进入新增 graph_bs "
            "条目和私有 HCB 包装函数的候选构建；本草稿不会猜测剧情插入点。"
        ),
    }
    return draft


def render_layered_portrait_preview(
    draft: Mapping[str, Any],
    archive_path: str | Path,
    *,
    expression_frame: int = 0,
) -> tuple[bytes, dict[str, Any]]:
    """Render a locked body/expression pair entirely in memory.

    This is deliberately a preview-only operation: it decodes two existing
    HZC entries and alpha-composites the selected face frame onto a copy of the
    body frame.  No HCB or BIN data is rebuilt or written.
    """

    if not isinstance(draft, Mapping) or draft.get("schema") != PORTRAIT_DRAFT_SCHEMA:
        raise PortraitProjectError("当前没有可预览的 V2 分层立绘草稿")

    archive = Path(archive_path).expanduser().resolve()
    if not archive.is_file():
        raise PortraitProjectError(f"找不到来源视觉 BIN: {archive}")

    locked = draft.get("locked_pair")
    variant = draft.get("variant")
    if not isinstance(locked, Mapping) or not isinstance(variant, Mapping):
        raise PortraitProjectError("分层立绘草稿缺少锁定资源信息")
    expected_archive = str(locked.get("archive", "")).strip()
    if expected_archive and archive.name.casefold() != expected_archive.casefold():
        raise PortraitProjectError("当前来源视觉 BIN 与草稿锁定归档不一致")

    try:
        body_entry = int(locked["body_entry"])
        face_entry = int(locked["face_entry"])
        frame = int(expression_frame)
    except (KeyError, TypeError, ValueError) as exc:
        raise PortraitProjectError("分层立绘草稿中的 entry 或表情帧无效") from exc
    if body_entry < 0 or face_entry < 0 or frame < 0:
        raise PortraitProjectError("entry 与表情帧不能为负数")

    face_ref = variant.get("face")
    frame_count = 0
    if isinstance(face_ref, Mapping):
        try:
            frame_count = int(face_ref.get("frame_count", 0))
        except (TypeError, ValueError):
            frame_count = 0
    if frame_count > 0 and frame >= frame_count:
        raise PortraitProjectError(
            f"表情帧 {frame} 超出范围（当前表情层共 {frame_count} 帧）"
        )

    offset = variant.get("face_offset")
    if not isinstance(offset, (list, tuple)) or len(offset) != 2:
        raise PortraitProjectError("分层立绘草稿缺少脸部合成坐标")
    try:
        face_x, face_y = int(offset[0]), int(offset[1])
    except (TypeError, ValueError) as exc:
        raise PortraitProjectError("脸部合成坐标必须是整数") from exc

    body_image, body_meta = decoded_bin_entry_image(archive, body_entry, 0)
    face_image, face_meta = decoded_bin_entry_image(archive, face_entry, frame)
    body = body_image.convert("RGBA")
    face = face_image.convert("RGBA")

    left = max(0, face_x)
    top = max(0, face_y)
    right = min(body.width, face_x + face.width)
    bottom = min(body.height, face_y + face.height)
    if right <= left or bottom <= top:
        raise PortraitProjectError("脸部坐标完全落在身体画布之外，无法合成预览")
    face_crop = face.crop(
        (left - face_x, top - face_y, right - face_x, bottom - face_y)
    )
    body.alpha_composite(face_crop, (left, top))

    output = BytesIO()
    body.save(output, format="PNG")
    actual_frame_count = frame_count
    if actual_frame_count <= 0:
        try:
            actual_frame_count = int(face_meta.get("frame_count", 0))
        except (AttributeError, TypeError, ValueError):
            actual_frame_count = 0
    metadata = {
        "body_entry": body_entry,
        "face_entry": face_entry,
        "expression_frame": frame,
        "frame_count": actual_frame_count,
        "face_offset": [face_x, face_y],
        "width": body.width,
        "height": body.height,
        "body_metadata": body_meta,
        "face_metadata": face_meta,
    }
    return output.getvalue(), metadata
