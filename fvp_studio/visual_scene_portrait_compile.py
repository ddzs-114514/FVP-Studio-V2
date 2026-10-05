"""Compile frozen visual-scene actors into the reviewed Hoshimemo backend.

This module is the explicit bridge between the UI's immutable story cue and
the generic portrait IR/backend.  It never writes a path: source ``graph_bs``
entries are read with bounded seeks, target names are deterministic ASCII,
and the caller receives an in-memory patch plan plus exact HZC payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping

from .bin_archive import (
    BinArchiveError,
    convert_hzc_to_premultiplied_alpha,
    hzc_metadata,
    parse_archive,
    probe_hzc_alpha_storage,
)
from .hoshimemo_native_portrait_profile import (
    build_hoshimemo_native_portrait_backend_profile,
    build_hoshimemo_native_portrait_profile,
)
from .hoshimemo_portrait_backend import (
    HoshimemoPortraitBackendError,
    HoshimemoPortraitPatchPlan,
    HoshimemoVariantInstall,
    allocate_private_slots,
    build_patch_plan,
)
from .hoshimemo_stage_geometry import (
    HoshimemoStageGeometryError,
    NativePortraitGeometry,
    editor_portrait_to_native,
)
from .portrait_compile import (
    HoshimemoVariantBinding,
    PortraitIROperation,
    PortraitIRProgram,
    compile_stage_snapshot,
)
from .portrait_project import (
    CharacterPortraitSet,
    LayeredPortraitVariant,
    PortraitProject,
    PortraitProjectError,
    StageActor,
    StageTransform,
)
from .resource_builder import ResourceBuildError, read_bin_entry_payload


FORM_SUFFIXES = {-1: "U", 0: "L", 1: "", 2: "S"}
# These outfit branches are the exact branches used by the accepted private
# selector probes.  A new target profile must supply its own mapping.
PRIVATE_SLOT_OUTFIT_CODES = {
    "selector16": 6,
    "selector19": 6,
    "selector21": 9,
}
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


class VisualScenePortraitCompileError(PortraitProjectError):
    """Raised when a frozen actor cannot be proven safe to emit."""


@dataclass(frozen=True)
class VisualScenePortraitTarget:
    """Exact target-side contract used by one portrait compilation.

    Hoshimemo remains the reviewed production default.  Other FVP targets may
    supply the same byte-oriented backend contract only after their dispatcher,
    primitive pair, resource-name branch and geometry have been extracted from
    the current target bytes.  Keeping this object data-driven avoids selecting
    behaviour from a game name or filesystem path.
    """

    target_profile: Any
    backend_profile: Any
    outfit_codes: Mapping[str, int]
    geometry_converter: Callable[..., NativePortraitGeometry]
    form_suffixes: Mapping[int, str]
    action_suffix: str = "_基"
    hzc_alpha_storage: str = "preserve"
    evidence: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.action_suffix:
            raise VisualScenePortraitCompileError("目标立绘动作后缀不能为空")
        if not callable(self.geometry_converter):
            raise VisualScenePortraitCompileError("目标立绘几何换算器不可调用")
        if not self.outfit_codes:
            raise VisualScenePortraitCompileError("目标立绘没有可用衣装分支")
        if not self.form_suffixes:
            raise VisualScenePortraitCompileError("目标立绘没有尺寸后缀规则")
        if self.hzc_alpha_storage not in {"preserve", "premultiplied"}:
            raise VisualScenePortraitCompileError(
                "目标立绘 HZC alpha storage 只能是 preserve 或 premultiplied"
            )


def _hoshimemo_portrait_target() -> VisualScenePortraitTarget:
    return VisualScenePortraitTarget(
        target_profile=build_hoshimemo_native_portrait_profile(),
        backend_profile=build_hoshimemo_native_portrait_backend_profile(),
        outfit_codes=PRIVATE_SLOT_OUTFIT_CODES,
        geometry_converter=editor_portrait_to_native,
        form_suffixes=FORM_SUFFIXES,
        action_suffix="_基",
        evidence={"mode": "reviewed_hoshimemo_profile"},
    )


@dataclass(frozen=True)
class VisualScenePortraitBuild:
    plan: HoshimemoPortraitPatchPlan
    resource_payloads: Mapping[str, bytes]
    report: Mapping[str, Any]

    def __post_init__(self) -> None:
        json.dumps(self.report, ensure_ascii=False, sort_keys=True)


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VisualScenePortraitCompileError(f"{label}缺失或不是对象")
    return value


def _required_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise VisualScenePortraitCompileError(f"{label}不能为空")
    return text


def _expression_id_for_frame(
    variant: LayeredPortraitVariant,
    frame: int,
) -> str:
    for expression in variant.expressions:
        if expression.frame == frame:
            return expression.expression_id
    raise VisualScenePortraitCompileError(
        f"变体 {variant.variant_id} 不包含表情帧 {frame}"
    )


def _required_locked_int(
    locked: Mapping[str, Any],
    key: str,
    label: str,
    *,
    minimum: int,
) -> int:
    value = locked.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise VisualScenePortraitCompileError(
            f"{label}冻结配对缺少 {key}，请重新分析"
        )
    if isinstance(value, bool):
        raise VisualScenePortraitCompileError(
            f"{label}冻结配对的 {key} 不是整数，请重新分析"
        )
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise VisualScenePortraitCompileError(
            f"{label}冻结配对的 {key} 不是整数，请重新分析"
        ) from exc
    if isinstance(value, float) and value != result:
        raise VisualScenePortraitCompileError(
            f"{label}冻结配对的 {key} 不是整数，请重新分析"
        )
    if result < minimum:
        raise VisualScenePortraitCompileError(
            f"{label}冻结配对的 {key} 小于 {minimum}，请重新分析"
        )
    return result


def _required_locked_sha256(
    locked: Mapping[str, Any],
    key: str,
    label: str,
) -> str:
    value = locked.get(key)
    if value is None or not str(value).strip():
        raise VisualScenePortraitCompileError(
            f"{label}冻结配对缺少 {key}，请重新分析"
        )
    digest = str(value).strip().casefold()
    if not _SHA256.fullmatch(digest):
        raise VisualScenePortraitCompileError(
            f"{label}冻结配对的 {key} 不是 SHA-256，请重新分析"
        )
    return digest


def _read_locked_payload(
    archive: Path,
    entry_index: int,
    label: str,
) -> tuple[bytes, Mapping[str, Any]]:
    try:
        raw_payload, raw_info = read_bin_entry_payload(archive, entry_index)
    except (OSError, ResourceBuildError, TypeError, ValueError) as exc:
        raise VisualScenePortraitCompileError(
            f"{label}无法通过 read_bin_entry_payload 完成 bounded 读取，请重新分析"
        ) from exc
    if not isinstance(raw_payload, (bytes, bytearray, memoryview)):
        raise VisualScenePortraitCompileError(
            f"{label} bounded 读取没有返回 bytes payload，请重新分析"
        )
    if not isinstance(raw_info, Mapping):
        raise VisualScenePortraitCompileError(
            f"{label} bounded 读取没有返回元数据，请重新分析"
        )
    payload = bytes(raw_payload)
    reported_size = raw_info.get(
        "compressed_size", raw_info.get("entry_size", len(payload))
    )
    try:
        actual_size = int(reported_size)
    except (TypeError, ValueError) as exc:
        raise VisualScenePortraitCompileError(
            f"{label} bounded 读取返回的 entry_size 无效，请重新分析"
        ) from exc
    if actual_size != len(payload):
        raise VisualScenePortraitCompileError(
            f"{label} 来源条目漂移: bounded 读取的 entry_size 与 payload 不一致，请重新分析"
        )
    return payload, raw_info


def _verify_locked_pair(
    actor: Mapping[str, Any],
    variant: LayeredPortraitVariant,
    archive: Path,
) -> tuple[int, int, Mapping[str, Any]]:
    actor_id = str(actor.get("actor_id") or "").strip() or "<unknown>"
    label = f"角色 {actor_id} "
    locked = _required_mapping(actor.get("locked_pair"), "冻结身体/表情配对")
    expected_archive = _required_text(locked.get("archive"), "冻结来源归档名")
    if archive.name.casefold() != expected_archive.casefold():
        raise VisualScenePortraitCompileError(
            f"冻结来源归档已漂移: 需要 {expected_archive}，实际 {archive.name}"
        )
    try:
        body_entry = int(locked["body_entry"])
        face_entry = int(locked["face_entry"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VisualScenePortraitCompileError("冻结身体/表情 entry 无效") from exc
    if body_entry != variant.body.entry_index or face_entry != variant.face.entry_index:
        raise VisualScenePortraitCompileError("冻结 entry 与变体资源身份不一致")
    if str(locked.get("body_resource_name") or "") != variant.body.resource_name:
        raise VisualScenePortraitCompileError("冻结身体资源名与变体身份不一致")
    if str(locked.get("face_resource_name") or "") != variant.face.resource_name:
        raise VisualScenePortraitCompileError("冻结表情资源名与变体身份不一致")
    expected_archive_size = _required_locked_int(
        locked, "archive_size", label, minimum=1
    )
    expected_archive_mtime_ns = _required_locked_int(
        locked, "archive_mtime_ns", label, minimum=0
    )
    _required_locked_int(locked, "body_entry_size", label, minimum=1)
    _required_locked_int(locked, "face_entry_size", label, minimum=1)
    _required_locked_sha256(locked, "body_payload_sha256", label)
    _required_locked_sha256(locked, "face_payload_sha256", label)
    try:
        archive_stat = archive.stat()
    except OSError as exc:
        raise VisualScenePortraitCompileError(
            f"{label}无法复检来源归档身份，请重新分析"
        ) from exc
    if (
        int(archive_stat.st_size) != expected_archive_size
        or int(archive_stat.st_mtime_ns) != expected_archive_mtime_ns
    ):
        raise VisualScenePortraitCompileError(
            f"{label}来源归档漂移: 大小或修改时间与分析冻结值不一致，请重新分析"
        )
    return body_entry, face_entry, locked


def _target_resource_names(
    body_payload: bytes,
    face_payload: bytes,
    form_code: int,
    *,
    form_suffixes: Mapping[int, str],
    action_suffix: str,
    resource_namespace: str,
) -> tuple[str, str, str, str]:
    try:
        suffix = str(form_suffixes[form_code])
    except KeyError as exc:
        raise VisualScenePortraitCompileError(
            f"目标 profile 不支持立绘尺寸类型: {form_code}"
        ) from exc
    digest = hashlib.sha256(body_payload + face_payload).hexdigest()[:16].upper()
    resource_stem = f"CHR_FVPV2_{digest}"
    outfit_suffix = "_V2"
    body_name = f"{resource_stem}{action_suffix}{outfit_suffix}{suffix}"
    namespace = str(resource_namespace).strip().casefold()
    if not re.fullmatch(r"graph(?:_[a-z0-9]+)?/", namespace):
        raise VisualScenePortraitCompileError(
            f"目标 profile 的立绘资源命名空间无效: {namespace or '<empty>'}"
        )
    return (
        body_name,
        f"{body_name}_表情",
        f"{namespace}{resource_stem}",
        outfit_suffix,
    )


def _apply_native_geometry_to_program(
    program: PortraitIRProgram,
    geometry_by_actor: Mapping[str, NativePortraitGeometry],
) -> PortraitIRProgram:
    """Replace only final XY/Z/scale calls after editor-side validation.

    ``PortraitProject`` deliberately validates the convenient 1280x720 editor
    values against each variant's UI scale policy.  Hoshimemo's primitive
    wrappers use a different coordinate system and can legitimately need a
    scale above that UI policy, so the conversion belongs at this IR boundary
    rather than in the shared project model.
    """

    rewritten: list[PortraitIROperation] = []
    converted_actor_ids: set[str] = set()
    for operation in program.operations:
        if operation.kind != "apply_final_transform":
            rewritten.append(operation)
            continue
        payload = dict(operation.payload)
        actor_id = str(payload.get("actor_id") or "")
        geometry = geometry_by_actor.get(actor_id)
        if geometry is None:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id or '<unknown>'} 缺少舞台到原生几何换算"
            )
        transform = dict(payload.get("transform", {}))
        transform.update(
            {
                key: int(getattr(geometry.transform, key))
                for key in ("x", "y", "z", "scale")
            }
        )
        payload["transform"] = transform
        rewritten.append(PortraitIROperation(operation.kind, payload))
        converted_actor_ids.add(actor_id)
    expected_actor_ids = set(geometry_by_actor)
    if converted_actor_ids != expected_actor_ids:
        missing = sorted(expected_actor_ids - converted_actor_ids)
        raise VisualScenePortraitCompileError(
            "原生立绘几何没有完整进入最终变换调用: " + ", ".join(missing)
        )
    return PortraitIRProgram(
        target_profile=program.target_profile,
        operations=tuple(rewritten),
        warnings=program.warnings,
    )


def compile_visual_scene_portraits(
    cue: Mapping[str, Any],
    target_graph_bs: bytes,
    *,
    target: VisualScenePortraitTarget | None = None,
) -> VisualScenePortraitBuild:
    """Compile every visible frozen actor; never silently drops one."""

    if not isinstance(cue, Mapping):
        raise VisualScenePortraitCompileError("剧情舞台快照必须是对象")
    actor_values = cue.get("actors")
    if not isinstance(actor_values, list):
        raise VisualScenePortraitCompileError("剧情舞台角色快照必须是数组")
    if any(not isinstance(actor, Mapping) for actor in actor_values):
        raise VisualScenePortraitCompileError("舞台角色快照含无效对象")
    stage_visible = [
        actor
        for actor in actor_values
        if isinstance(actor, Mapping) and bool(actor.get("visible", True))
    ]
    if not stage_visible:
        raise VisualScenePortraitCompileError("舞台快照没有可编译的可见角色")

    # The editor stores actors back-to-front because that is the natural order
    # for the draggable layer strip.  Hoshimemo's reviewed private portrait
    # chain resolves overlap in the opposite direction: the front-most actor
    # must enter the actor -> private slot -> wrapper -> registration stream
    # first.  Reversing at this single compiler boundary keeps stable actor
    # identities and source bindings untouched while converting the complete
    # native chain together.  Real-engine A/B acceptance also proved that
    # swapping transform.z alone does not change inter-actor overlap.
    visible = list(reversed(stage_visible))

    compile_target = target or _hoshimemo_portrait_target()
    target_profile = compile_target.target_profile
    backend_profile = compile_target.backend_profile
    actor_ids = [_required_text(actor.get("actor_id"), "舞台角色 ID") for actor in visible]
    if len(actor_ids) != len(set(actor_ids)):
        raise VisualScenePortraitCompileError("舞台快照含重复 actor_id")
    try:
        slot_by_actor = allocate_private_slots(actor_ids, target_profile)
    except HoshimemoPortraitBackendError as exc:
        raise VisualScenePortraitCompileError(str(exc)) from exc

    project = PortraitProject()
    bindings: list[HoshimemoVariantBinding] = []
    installs: list[HoshimemoVariantInstall] = []
    payloads: dict[str, bytes] = {}
    actor_report: list[dict[str, Any]] = []
    native_geometry_by_actor: dict[str, NativePortraitGeometry] = {}

    for index, actor in enumerate(visible):
        actor_id = actor_ids[index]
        variant_value = _required_mapping(actor.get("variant"), f"角色 {actor_id} 变体")
        try:
            variant = LayeredPortraitVariant.from_dict(variant_value)
            editor_transform = StageTransform.from_dict(
                _required_mapping(actor.get("transform"), f"角色 {actor_id} 变换")
            )
        except (KeyError, TypeError, ValueError, PortraitProjectError) as exc:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 的冻结立绘状态无效: {exc}"
            ) from exc
        archive = Path(
            _required_text(actor.get("source_archive_path"), f"角色 {actor_id} 来源归档")
        ).expanduser().resolve()
        if not archive.is_file() or archive.suffix.casefold() != ".bin":
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 来源视觉 BIN 不存在: {archive}"
            )
        body_entry, face_entry, locked = _verify_locked_pair(actor, variant, archive)
        label = f"角色 {actor_id} "
        expected_archive_size = _required_locked_int(
            locked, "archive_size", label, minimum=1
        )
        expected_archive_mtime_ns = _required_locked_int(
            locked, "archive_mtime_ns", label, minimum=0
        )
        expected_body_entry_size = _required_locked_int(
            locked, "body_entry_size", label, minimum=1
        )
        expected_face_entry_size = _required_locked_int(
            locked, "face_entry_size", label, minimum=1
        )
        expected_body_hash = _required_locked_sha256(
            locked, "body_payload_sha256", label
        )
        expected_face_hash = _required_locked_sha256(
            locked, "face_payload_sha256", label
        )
        body_payload, body_info = _read_locked_payload(
            archive, body_entry, f"角色 {actor_id} 身体层"
        )
        face_payload, face_info = _read_locked_payload(
            archive, face_entry, f"角色 {actor_id} 表情层"
        )
        try:
            current_archive_stat = archive.stat()
        except OSError as exc:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 无法复检读取期间的来源归档身份，请重新分析"
            ) from exc
        if (
            int(current_archive_stat.st_size) != expected_archive_size
            or int(current_archive_stat.st_mtime_ns) != expected_archive_mtime_ns
        ):
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 来源归档在读取期间漂移，请重新分析"
            )
        body_entry_size = len(body_payload)
        face_entry_size = len(face_payload)
        if body_entry_size != expected_body_entry_size:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 来源条目漂移: 冻结 body_entry_size 与当前 bounded 读取不一致，请重新分析"
            )
        if face_entry_size != expected_face_entry_size:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 来源条目漂移: 冻结 face_entry_size 与当前 bounded 读取不一致，请重新分析"
            )
        body_hash = hashlib.sha256(body_payload).hexdigest()
        face_hash = hashlib.sha256(face_payload).hexdigest()
        if body_hash != expected_body_hash:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 来源条目漂移: 冻结的 body_payload_sha256 与当前 payload 不一致，请重新分析"
            )
        if face_hash != expected_face_hash:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 来源条目漂移: 冻结的 face_payload_sha256 与当前 payload 不一致，请重新分析"
            )
        try:
            body_meta = hzc_metadata(body_payload)
            face_meta = hzc_metadata(face_payload)
        except ValueError as exc:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 冻结资源 HZC 元数据验证失败，请重新分析"
            ) from exc
        if body_meta.kind != 1 or face_meta.kind != 2:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 冻结资源不是身体 kind=1 + 表情 kind=2"
            )
        if body_meta.frame_count != 1 or face_meta.frame_count != variant.face.frame_count:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 冻结资源帧数与变体元数据不一致"
            )
        try:
            if compile_target.hzc_alpha_storage == "premultiplied":
                installed_body_payload, body_alpha_report = (
                    convert_hzc_to_premultiplied_alpha(body_payload)
                )
                installed_face_payload, face_alpha_report = (
                    convert_hzc_to_premultiplied_alpha(face_payload)
                )
            else:
                body_probe = probe_hzc_alpha_storage(body_payload)
                face_probe = probe_hzc_alpha_storage(face_payload)
                installed_body_payload = body_payload
                installed_face_payload = face_payload
                body_alpha_report = {
                    "mode": "preserve_source_payload",
                    "changed": False,
                    "header_preserved": True,
                    "source_sha256": body_hash,
                    "output_sha256": body_hash,
                    "source_size": len(body_payload),
                    "output_size": len(body_payload),
                    "changed_pixels": 0,
                    "before": body_probe.to_dict(),
                    "after": body_probe.to_dict(),
                }
                face_alpha_report = {
                    "mode": "preserve_source_payload",
                    "changed": False,
                    "header_preserved": True,
                    "source_sha256": face_hash,
                    "output_sha256": face_hash,
                    "source_size": len(face_payload),
                    "output_size": len(face_payload),
                    "changed_pixels": 0,
                    "before": face_probe.to_dict(),
                    "after": face_probe.to_dict(),
                }
        except BinArchiveError as exc:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} HZC alpha storage 处理失败: {exc}"
            ) from exc
        try:
            form_code = int(actor.get("form_code"))
        except (TypeError, ValueError) as exc:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 尺寸类型无效"
            ) from exc
        body_name, face_name, resource_base, outfit_suffix = _target_resource_names(
            installed_body_payload,
            installed_face_payload,
            form_code,
            form_suffixes=compile_target.form_suffixes,
            action_suffix=compile_target.action_suffix,
            resource_namespace=target_profile.portrait_resource_namespace,
        )
        for name, payload in (
            (body_name, installed_body_payload),
            (face_name, installed_face_payload),
        ):
            previous = payloads.get(name)
            if previous is not None and previous != payload:
                raise VisualScenePortraitCompileError(f"目标资源名发生哈希冲突: {name}")
            payloads[name] = payload

        slot_id = slot_by_actor[actor_id]
        slot = target_profile.slot(slot_id)
        try:
            native_geometry = compile_target.geometry_converter(
                editor_transform,
                body_meta,
                form_code=form_code,
                selector=slot.selector,
            )
        except HoshimemoStageGeometryError as exc:
            raise VisualScenePortraitCompileError(
                f"角色 {actor_id} 无法从可视化舞台换算为原生几何: {exc}"
            ) from exc
        native_geometry_by_actor[actor_id] = native_geometry
        try:
            outfit_code = int(compile_target.outfit_codes[slot_id])
        except KeyError as exc:
            raise VisualScenePortraitCompileError(
                f"立绘槽 {slot_id} 没有经过验证的衣装分支"
            ) from exc
        expression_frame = int(actor.get("expression_frame", 0))
        expression_id = _expression_id_for_frame(variant, expression_frame)
        compile_character_id = f"scene::{actor_id}"
        project.add_character(
            CharacterPortraitSet(
                character_id=compile_character_id,
                display_name=str(
                    _required_mapping(actor.get("identity"), f"角色 {actor_id} 身份").get(
                        "display_name"
                    )
                    or actor_id
                ),
                variants={variant.variant_id: variant},
                default_variant=variant.variant_id,
            )
        )
        project.add_actor(
            StageActor(
                actor_id=actor_id,
                character_id=compile_character_id,
                variant_id=variant.variant_id,
                expression_id=expression_id,
                transform=editor_transform,
                state_slot=(index % 2) + 1,
                position_preset=0,
                transition=None,
                hidden=False,
                slot_id=slot_id,
            )
        )
        bindings.append(
            HoshimemoVariantBinding(
                variant_id=variant.variant_id,
                dispatcher_symbol=slot.dispatcher_symbol,
                selector=slot.selector,
                action_code=1,
                outfit_code=outfit_code,
                form_code=form_code,
                expression_codes={
                    item.expression_id: item.frame for item in variant.expressions
                },
                slot_id=slot_id,
            )
        )
        installs.append(
            HoshimemoVariantInstall(
                variant_id=variant.variant_id,
                slot_id=slot_id,
                target_body_name=body_name,
                target_face_name=face_name,
                resource_values={
                    "resource_base": resource_base,
                    "outfit_suffix": outfit_suffix,
                },
            )
        )
        actor_report.append(
            {
                "actor_id": actor_id,
                "slot_id": slot_id,
                "selector": slot.selector,
                "primitive_ids": list(slot.primitive_ids),
                "source_archive": str(archive),
                "source_archive_size": expected_archive_size,
                "source_archive_mtime_ns": expected_archive_mtime_ns,
                "source_body_entry": body_entry,
                "source_face_entry": face_entry,
                "source_body_entry_size": body_entry_size,
                "source_face_entry_size": face_entry_size,
                "source_body_sha256": body_hash,
                "source_face_sha256": face_hash,
                "installed_body_sha256": hashlib.sha256(
                    installed_body_payload
                ).hexdigest(),
                "installed_face_sha256": hashlib.sha256(
                    installed_face_payload
                ).hexdigest(),
                "target_body_name": body_name,
                "target_face_name": face_name,
                "resource_base": resource_base,
                "outfit_suffix": outfit_suffix,
                "form_code": form_code,
                "expression_frame": expression_frame,
                # Keep the legacy field editor-facing for report consumers,
                # while making the emitted native geometry independently
                # auditable.
                "transform": editor_transform.to_dict(),
                "editor_transform": editor_transform.to_dict(),
                "native_transform": native_geometry.transform.to_dict(),
                "geometry_conversion": dict(native_geometry.report),
                "compressed_payload_bytes": (
                    len(installed_body_payload) + len(installed_face_payload)
                ),
                "body_metadata": body_meta.to_dict(),
                "face_metadata": face_meta.to_dict(),
                "alpha_storage": {
                    "target": compile_target.hzc_alpha_storage,
                    "body": dict(body_alpha_report),
                    "face": dict(face_alpha_report),
                },
                "bounded_source_reads": [body_info, face_info],
            }
        )

    try:
        program = compile_stage_snapshot(
            project,
            backend_profile,
            bindings,
            apply_duration=0,
        )
        program = _apply_native_geometry_to_program(
            program,
            native_geometry_by_actor,
        )
        existing_names = parse_archive(target_graph_bs).names
        plan = build_patch_plan(
            program,
            target_profile,
            installs,
            existing_resource_names=existing_names,
        )
    except (HoshimemoPortraitBackendError, PortraitProjectError, ValueError) as exc:
        raise VisualScenePortraitCompileError(str(exc)) from exc

    report = {
        "profile_id": target_profile.profile_id,
        "actor_count": len(visible),
        "stage_actor_order_back_to_front": [
            _required_text(actor.get("actor_id"), "舞台角色 ID")
            for actor in stage_visible
        ],
        "native_actor_order_front_to_back": list(actor_ids),
        "actors": actor_report,
        "slot_assignment": dict(slot_by_actor),
        "resource_names": sorted(payloads),
        "resource_archive_name": target_profile.portrait_archive_name,
        "resource_namespace": target_profile.portrait_resource_namespace,
        "target_hzc_alpha_storage": compile_target.hzc_alpha_storage,
        "resource_payload_bytes": sum(len(item) for item in payloads.values()),
        "plan": plan.to_dict(),
        "target_evidence": dict(compile_target.evidence or {}),
        "rules": {
            "all_visible_actors_compiled": True,
            "source_entries_read_with_bounded_seeks": True,
            "target_names_are_deterministic_ascii": True,
            "body_and_face_installed_atomically": True,
            "no_existing_target_resource_replaced": True,
            "native_layer_order_compiled_front_to_back": True,
            "transform_z_is_not_actor_identity": True,
            "editor_identity_and_native_geometry_are_separate": True,
            "editor_stage_geometry_converted_to_native_v3d": True,
            "hzc_alpha_storage_is_target_driven": True,
            "source_hzc_payloads_never_modified": True,
        },
    }
    return VisualScenePortraitBuild(
        plan=plan,
        resource_payloads=dict(sorted(payloads.items())),
        report=report,
    )


__all__ = [
    "PRIVATE_SLOT_OUTFIT_CODES",
    "VisualScenePortraitBuild",
    "VisualScenePortraitCompileError",
    "VisualScenePortraitTarget",
    "compile_visual_scene_portraits",
]
