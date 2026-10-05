"""Target-neutral portrait lifecycle plans for discovered FVP games.

This module deliberately stops before HCB bytecode emission.  A structurally
discovered 13-argument dispatcher and clear/apply pair do not by themselves
prove per-resource selector values, private primitive ownership, layer order,
or the next safe cleanup boundary.  The planner therefore freezes the exact
target-owned body/face references and produces deterministic show/replace/
update/hide/order operations while keeping ``hcb_emission_ready`` false.

No function in this module opens a path or mutates a caller-owned object.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from .hcb import HcbError
from .visual_scene_project import VisualSceneProjectError, buildable_story_scenes


NATIVE_PORTRAIT_PLAN_SCHEMA = "fvp-studio-v2.native-portrait-scene-plan.v1"
NATIVE_PORTRAIT_OPERATION_SCHEMA = (
    "fvp-studio-v2.native-portrait-lifecycle-operation.v1"
)
TARGET_PORTRAIT_ARCHIVE = "graph_bs.bin"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class NativePortraitCompileError(HcbError):
    """Raised when a target-neutral portrait plan would lose identity."""


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NativePortraitCompileError(f"{label}缺失或不是对象")
    return value


def _required_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise NativePortraitCompileError(f"{label}不能为空")
    return text


def _required_int(value: Any, label: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool):
        raise NativePortraitCompileError(f"{label}必须是整数")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise NativePortraitCompileError(f"{label}必须是整数") from exc
    if isinstance(value, float) and result != value:
        raise NativePortraitCompileError(f"{label}必须是整数")
    if minimum is not None and result < minimum:
        raise NativePortraitCompileError(f"{label}不能小于 {minimum}")
    return result


def _required_sha256(value: Any, label: str) -> str:
    digest = str(value).strip().casefold()
    if not _SHA256.fullmatch(digest):
        raise NativePortraitCompileError(f"{label}不是 SHA-256")
    return digest


def _normalise_resources(
    available_resources: Mapping[str, Sequence[str]],
) -> dict[str, frozenset[str]]:
    if not isinstance(available_resources, Mapping):
        raise NativePortraitCompileError("立绘只读资源目录必须是 Mapping")
    result: dict[str, frozenset[str]] = {}
    for archive, names in available_resources.items():
        token = str(archive or "").strip().casefold()
        if not token or isinstance(names, (str, bytes, bytearray)):
            raise NativePortraitCompileError("立绘只读资源目录条目无效")
        try:
            result[token] = frozenset(str(item) for item in names)
        except TypeError as exc:
            raise NativePortraitCompileError("立绘只读资源名称列表无效") from exc
    return result


def _transform(value: Any, actor_id: str) -> dict[str, int]:
    source = _required_mapping(value, f"角色 {actor_id} 变换")
    result = {
        "x": _required_int(source.get("x", 0), f"角色 {actor_id} X"),
        "y": _required_int(source.get("y", 0), f"角色 {actor_id} Y"),
        "z": _required_int(source.get("z", 1500), f"角色 {actor_id} Z"),
        "scale": _required_int(
            source.get("scale", 1000), f"角色 {actor_id} 缩放", minimum=1
        ),
        "rotation": _required_int(
            source.get("rotation", 0), f"角色 {actor_id} 旋转"
        ),
        "opacity": _required_int(
            source.get("opacity", 255), f"角色 {actor_id} 透明度", minimum=0
        ),
    }
    if result["opacity"] > 255:
        raise NativePortraitCompileError(f"角色 {actor_id} 透明度不能大于 255")
    return result


def _actor_reference(
    actor: Mapping[str, Any],
    resources: Mapping[str, frozenset[str]],
) -> dict[str, Any]:
    actor_id = _required_text(actor.get("actor_id"), "舞台角色稳定 actor_id")
    locked = _required_mapping(
        actor.get("locked_pair"), f"角色 {actor_id} 冻结身体/表情配对"
    )
    archive = _required_text(
        locked.get("archive"), f"角色 {actor_id} 冻结来源归档"
    ).casefold()
    if archive != TARGET_PORTRAIT_ARCHIVE:
        raise NativePortraitCompileError(
            f"角色 {actor_id} 不是目标本作 {TARGET_PORTRAIT_ARCHIVE} 直引；"
            "通用跨游戏 additive_resource 尚未开放"
        )
    names = resources.get(archive)
    if names is None:
        raise NativePortraitCompileError(
            f"通用立绘计划缺少 {archive} 的只读资源目录"
        )
    body_name = _required_text(
        locked.get("body_resource_name"), f"角色 {actor_id} 身体资源名"
    )
    face_name = _required_text(
        locked.get("face_resource_name"), f"角色 {actor_id} 表情资源名"
    )
    for name, label in ((body_name, "身体"), (face_name, "表情")):
        if name not in names:
            raise NativePortraitCompileError(
                f"目标本作 {archive} 找不到角色 {actor_id} 的{label}资源 {name}"
            )
    body_entry = _required_int(
        locked.get("body_entry"), f"角色 {actor_id} 身体 entry", minimum=0
    )
    face_entry = _required_int(
        locked.get("face_entry"), f"角色 {actor_id} 表情 entry", minimum=0
    )
    if body_entry == face_entry:
        raise NativePortraitCompileError(f"角色 {actor_id} 身体与表情 entry 不能相同")
    identity = actor.get("identity") if isinstance(actor.get("identity"), Mapping) else {}
    reference = {
        "actor_id": actor_id,
        "identity": {
            "character_id": str(identity.get("character_id") or ""),
            "display_name": str(identity.get("display_name") or ""),
            "label": str(identity.get("label") or identity.get("display_name") or actor_id),
        },
        "archive_name": archive,
        "body_entry": body_entry,
        "face_entry": face_entry,
        "body_resource_name": body_name,
        "face_resource_name": face_name,
        "archive_size": _required_int(
            locked.get("archive_size"),
            f"角色 {actor_id} 冻结归档大小",
            minimum=1,
        ),
        "archive_mtime_ns": _required_int(
            locked.get("archive_mtime_ns"),
            f"角色 {actor_id} 冻结归档时间",
            minimum=0,
        ),
        "body_entry_size": _required_int(
            locked.get("body_entry_size"),
            f"角色 {actor_id} 身体 entry 大小",
            minimum=1,
        ),
        "face_entry_size": _required_int(
            locked.get("face_entry_size"),
            f"角色 {actor_id} 表情 entry 大小",
            minimum=1,
        ),
        "body_payload_sha256": _required_sha256(
            locked.get("body_payload_sha256"),
            f"角色 {actor_id} 身体 payload",
        ),
        "face_payload_sha256": _required_sha256(
            locked.get("face_payload_sha256"),
            f"角色 {actor_id} 表情 payload",
        ),
        "expression_frame": _required_int(
            actor.get("expression_frame", 0),
            f"角色 {actor_id} 表情帧",
            minimum=0,
        ),
        "form_code": _required_int(
            actor.get("form_code", 0), f"角色 {actor_id} form_code"
        ),
        "form_id": str(actor.get("form_id") or ""),
        "transform": _transform(actor.get("transform"), actor_id),
        "visible": bool(actor.get("visible", True)),
        "source_mode": "target_direct_reference",
    }
    reference["resource_identity_sha256"] = _canonical_sha256(
        {
            key: reference[key]
            for key in (
                "archive_name",
                "body_entry",
                "face_entry",
                "body_resource_name",
                "face_resource_name",
                "archive_size",
                "archive_mtime_ns",
                "body_entry_size",
                "face_entry_size",
                "body_payload_sha256",
                "face_payload_sha256",
                "form_code",
                "form_id",
            )
        }
    )
    reference["state_sha256"] = _canonical_sha256(
        {
            "resource": reference["resource_identity_sha256"],
            "expression_frame": reference["expression_frame"],
            "transform": reference["transform"],
            "visible": reference["visible"],
        }
    )
    return reference


def _operation(kind: str, **payload: Any) -> dict[str, Any]:
    return {
        "schema": NATIVE_PORTRAIT_OPERATION_SCHEMA,
        "kind": kind,
        **copy.deepcopy(payload),
        "hcb_emission_ready": False,
    }


def _binding_identity(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        "address": value.get("address"),
        "argument_count": value.get("argument_count"),
        "structure_sha256": value.get("structure_sha256"),
    }


def build_native_portrait_story_plan(
    story: Mapping[str, Any],
    available_resources: Mapping[str, Sequence[str]],
    *,
    lifecycle_bindings: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build deterministic lifecycle IR for target-owned frozen portraits.

    ``None`` means no captured actor exists in any buildable scene.  A returned
    plan is an audit artifact, not executable HCB; callers must preserve that
    distinction in their candidate and UI reports.
    """

    resources = _normalise_resources(available_resources)
    try:
        scenes = buildable_story_scenes(story)
    except VisualSceneProjectError as exc:
        raise NativePortraitCompileError(str(exc)) from exc
    if not any(
        isinstance(scene.get("cue"), Mapping)
        and isinstance(scene["cue"].get("actors"), list)
        and bool(scene["cue"]["actors"])
        for scene in scenes
    ):
        return None

    lifecycle = lifecycle_bindings if isinstance(lifecycle_bindings, Mapping) else {}
    previous_visible: dict[str, dict[str, Any]] = {}
    scene_reports: list[dict[str, Any]] = []
    all_actor_ids: set[str] = set()
    total_visible = 0
    total_hidden = 0

    for scene in scenes:
        cue = _required_mapping(scene.get("cue"), "剧情场景舞台快照")
        raw_actors = cue.get("actors")
        if not isinstance(raw_actors, list) or any(
            not isinstance(actor, Mapping) for actor in raw_actors
        ):
            raise NativePortraitCompileError("剧情场景立绘快照必须是对象数组")
        references = [
            _actor_reference(actor, resources)
            for actor in raw_actors
            if isinstance(actor, Mapping)
        ]
        actor_ids = [str(item["actor_id"]) for item in references]
        if len(actor_ids) != len(set(actor_ids)):
            raise NativePortraitCompileError(
                f"剧情场景 {scene.get('title') or scene.get('scene_id')} 含重复 actor_id"
            )
        all_actor_ids.update(actor_ids)
        visible = [item for item in references if item["visible"]]
        hidden = [item for item in references if not item["visible"]]
        total_visible += len(visible)
        total_hidden += len(hidden)
        operations: list[dict[str, Any]] = []
        event_visual = cue.get("event_visual")
        if isinstance(event_visual, Mapping):
            operations.append(
                _operation(
                    "event_visual_suppresses_portraits",
                    captured_actor_ids=actor_ids,
                    reason="全屏事件 CG cue 不发射下方立绘",
                )
            )
            previous_visible = {}
        else:
            current_visible = {str(item["actor_id"]): item for item in visible}
            for actor_id in previous_visible:
                if actor_id not in current_visible:
                    operations.append(_operation("hide", actor_id=actor_id))
            for item in hidden:
                operations.append(_operation("hide", actor_id=item["actor_id"]))
            for layer_index, item in enumerate(visible):
                actor_id = str(item["actor_id"])
                previous = previous_visible.get(actor_id)
                if previous is None:
                    kind = "show"
                elif (
                    previous["resource_identity_sha256"]
                    != item["resource_identity_sha256"]
                ):
                    kind = "replace"
                elif previous["state_sha256"] != item["state_sha256"]:
                    kind = "update"
                else:
                    kind = "keep"
                operations.append(
                    _operation(
                        kind,
                        actor_id=actor_id,
                        layer_index_back_to_front=layer_index,
                        reference=item,
                    )
                )
            operations.append(
                _operation(
                    "set_layer_order",
                    actor_ids_back_to_front=[item["actor_id"] for item in visible],
                    rule="editor_left_back_to_right_front",
                )
            )
            operations.append(
                _operation(
                    "schedule_cleanup",
                    actor_ids=[item["actor_id"] for item in visible],
                    clear_binding=_binding_identity(lifecycle.get("portrait_clear")),
                    apply_binding=_binding_identity(lifecycle.get("portrait_apply")),
                    boundary_status="not_reviewed",
                )
            )
            previous_visible = current_visible
        scene_reports.append(
            {
                "scene_id": str(scene.get("scene_id") or ""),
                "title": str(scene.get("title") or ""),
                "anchor_id": str((scene.get("anchor") or {}).get("anchor_id") or ""),
                "actor_order_back_to_front": [item["actor_id"] for item in visible],
                "visible_actor_count": len(visible),
                "hidden_actor_count": len(hidden),
                "suppressed_by_event_visual": isinstance(event_visual, Mapping),
                "operations": operations,
            }
        )

    blockers = [
        "portrait_resource_selector_mapping_not_reviewed",
        "portrait_private_primitive_ownership_not_reviewed",
        "portrait_layer_order_abi_not_reviewed",
        "portrait_lifecycle_cleanup_not_reviewed",
    ]
    core = {
        "schema": NATIVE_PORTRAIT_PLAN_SCHEMA,
        "mode": "target_direct_reference_audit",
        "writes_performed": False,
        "hcb_emission_ready": False,
        "archive_name": TARGET_PORTRAIT_ARCHIVE,
        "actor_ids": sorted(all_actor_ids),
        "scene_count": len(scene_reports),
        "visible_actor_snapshot_count": total_visible,
        "hidden_actor_snapshot_count": total_hidden,
        "scenes": scene_reports,
        "lifecycle_bindings": {
            "portrait_clear": _binding_identity(lifecycle.get("portrait_clear")),
            "portrait_apply": _binding_identity(lifecycle.get("portrait_apply")),
        },
        "blockers": blockers,
        "rules": {
            "target_owned_graph_bs_only": True,
            "cross_game_additive_resource_allowed": False,
            "original_archive_replacement_allowed": False,
            "stable_actor_id_controls_identity": True,
            "editor_order_is_back_to_front": True,
        },
    }
    core["plan_sha256"] = _canonical_sha256(core)
    return core


__all__ = [
    "NATIVE_PORTRAIT_OPERATION_SCHEMA",
    "NATIVE_PORTRAIT_PLAN_SCHEMA",
    "NativePortraitCompileError",
    "TARGET_PORTRAIT_ARCHIVE",
    "build_native_portrait_story_plan",
]
