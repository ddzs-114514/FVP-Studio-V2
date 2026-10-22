"""Read-only import analysis for native FVP layered portraits.

An import is explicit: the caller selects one body entry and its matching face
entry.  The importer validates the pair, discovers the face offset, records all
expression frames and calculates only a *starting* scale/height estimate.  It
does not append data to a BIN and does not patch an HCB.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from PIL import Image

from .portrait_project import (
    CharacterPortraitSet,
    ExpressionFrame,
    FvpResourceRef,
    LayeredPortraitVariant,
    PixelBounds,
    PortraitProjectError,
    ScalePolicy,
    StageTransform,
)
from .resource_builder import (
    ResourceBuildError,
    decoded_bin_entry_image,
    find_exact_portrait_face_offset,
    inspect_bin_entry,
    resolve_portrait_face_offset,
)


@dataclass(frozen=True)
class StageReference:
    """Target-stage reference used to calculate a non-authoritative baseline.

    ``target_visible_height`` should come from a visually approved native
    portrait of the same form (for example L or U) in the target game.  The
    resulting scale is a useful first value, not a promise that foreign games
    share the same anchors.
    """

    target_visible_height: int
    baseline_y: int
    default_z: int = 1500
    minimum_ratio: float = 0.60
    maximum_ratio: float = 1.80
    hard_minimum: int = 100
    hard_maximum: int = 4000
    wheel_step: int = 25

    def __post_init__(self) -> None:
        if self.target_visible_height <= 0:
            raise PortraitProjectError("目标可见高度必须大于零")
        if self.minimum_ratio <= 0 or self.maximum_ratio < self.minimum_ratio:
            raise PortraitProjectError("缩放范围比例无效")
        if self.hard_minimum <= 0 or self.hard_maximum < self.hard_minimum:
            raise PortraitProjectError("缩放硬边界无效")
        if self.wheel_step <= 0:
            raise PortraitProjectError("滚轮缩放步长必须大于零")

    def estimate(self, visible_bounds: PixelBounds) -> tuple[ScalePolicy, StageTransform]:
        raw = round(self.target_visible_height * 1000 / visible_bounds.height)
        estimated = max(self.hard_minimum, min(self.hard_maximum, raw))
        minimum = max(self.hard_minimum, round(estimated * self.minimum_ratio))
        maximum = min(self.hard_maximum, round(estimated * self.maximum_ratio))
        minimum = min(minimum, estimated)
        maximum = max(maximum, estimated)
        policy = ScalePolicy(
            estimated=estimated,
            minimum=minimum,
            maximum=maximum,
            wheel_step=self.wheel_step,
        )
        # This aligns the decoded alpha bottom to the chosen reference baseline.
        # A per-game HCB backend may later translate this preview-space origin.
        suggested_y = self.baseline_y - round(visible_bounds.bottom * estimated / 1000)
        return policy, StageTransform(
            x=0,
            y=suggested_y,
            z=self.default_z,
            scale=estimated,
            rotation=0,
        )


@dataclass(frozen=True)
class FvpLayeredImportRequest:
    character_id: str
    display_name: str
    variant_id: str
    pose_id: str
    form_id: str
    archive: Path
    body_entry: int
    body_resource_name: str
    face_entry: int
    face_resource_name: str
    source_game: str = ""
    default_expression: str = "000"
    expression_ids: Mapping[int, str] | None = None
    manual_face_offset: tuple[int, int] | None = None
    allow_name_mismatch: bool = False


@dataclass(frozen=True)
class FvpLayeredImportResult:
    variant: LayeredPortraitVariant
    suggested_transform: StageTransform
    report: dict[str, Any]


@dataclass(frozen=True)
class FvpCharacterImportResult:
    """One character assembled from several strongly-bound action/form pairs."""

    character: CharacterPortraitSet
    suggested_transforms: Mapping[str, StageTransform]
    reports: Mapping[str, Mapping[str, Any]]


def _alpha_bounds(image: Image.Image) -> PixelBounds:
    bounds = image.convert("RGBA").getchannel("A").getbbox()
    if bounds is None:
        raise PortraitProjectError("身体层全透明，无法估算尺寸与基线")
    return PixelBounds(*bounds)


def expected_face_resource_name(body_resource_name: str) -> str:
    """Return the conventional FVP expression-layer name for a body layer."""

    body = str(body_resource_name).split("#", 1)[0]
    return f"{body}_表情"


def validate_layer_names(
    body_resource_name: str,
    face_resource_name: str,
    *,
    allow_mismatch: bool = False,
) -> tuple[str, ...]:
    expected = expected_face_resource_name(body_resource_name)
    actual = str(face_resource_name).split("#", 1)[0]
    if actual == expected:
        return ()
    message = f"表情层名称 {actual} 与身体层预期名称 {expected} 不一致"
    if not allow_mismatch:
        raise PortraitProjectError(message)
    return (message,)


def resolve_face_offset_from_images(
    body: Image.Image,
    face_frames: Sequence[Image.Image],
    manual_face_offset: tuple[int, int] | None = None,
) -> tuple[tuple[int, int], int | None, str]:
    """Resolve one shared face anchor for an explicitly selected layer pair."""

    body = body.convert("RGBA")
    if not face_frames:
        raise PortraitProjectError("表情层没有可用帧")
    normalized = [frame.convert("RGBA") for frame in face_frames]
    first = normalized[0]
    if manual_face_offset is not None:
        if len(manual_face_offset) != 2:
            raise PortraitProjectError("手动脸部坐标必须是 (x, y)")
        left, top = (int(value) for value in manual_face_offset)
        if left < 0 or top < 0 or left + first.width > body.width or top + first.height > body.height:
            raise PortraitProjectError("手动脸部坐标超出身体层画布")
        return (left, top), None, "manual"
    for index, face in enumerate(normalized):
        if face.getchannel("A").getbbox() is None:
            continue
        try:
            return find_exact_portrait_face_offset(body, face), index, "pixel_match"
        except ResourceBuildError:
            continue
    raise PortraitProjectError(
        "身体层中找不到任何表情帧；请确认动作/尺寸配对，或手动填写脸部坐标"
    )


def _expression_frames(
    frame_count: int,
    explicit_ids: Mapping[int, str] | None,
) -> tuple[ExpressionFrame, ...]:
    if explicit_ids is None:
        return tuple(
            ExpressionFrame(expression_id=f"{frame:03d}", frame=frame)
            for frame in range(frame_count)
        )
    normalized = {int(frame): str(expression_id) for frame, expression_id in explicit_ids.items()}
    if set(normalized) != set(range(frame_count)):
        missing = sorted(set(range(frame_count)) - set(normalized))
        extra = sorted(set(normalized) - set(range(frame_count)))
        raise PortraitProjectError(
            f"表情语义映射必须覆盖全部帧；缺少={missing}，越界={extra}"
        )
    return tuple(
        ExpressionFrame(expression_id=normalized[frame], frame=frame)
        for frame in range(frame_count)
    )


def build_layered_variant_from_images(
    *,
    request: FvpLayeredImportRequest,
    body_ref: FvpResourceRef,
    face_ref: FvpResourceRef,
    body_image: Image.Image,
    face_frames: Sequence[Image.Image],
    stage_reference: StageReference,
    resolved_face_offset: tuple[tuple[int, int], int | None, str] | None = None,
) -> FvpLayeredImportResult:
    """Build a strongly-bound variant from already decoded FVP layers."""

    warnings = list(
        validate_layer_names(
            request.body_resource_name,
            request.face_resource_name,
            allow_mismatch=request.allow_name_mismatch,
        )
    )
    if body_ref.frame_count != 1:
        raise PortraitProjectError("所选身体资源不是单帧 FVP 立绘层")
    if face_ref.frame_count != len(face_frames):
        raise PortraitProjectError("已解码表情帧数与 BIN 元数据不一致")
    if any(frame.size != (face_ref.width, face_ref.height) for frame in face_frames):
        raise PortraitProjectError("表情帧尺寸与 BIN 元数据不一致")
    if body_image.size != (body_ref.width, body_ref.height):
        raise PortraitProjectError("身体图尺寸与 BIN 元数据不一致")
    if resolved_face_offset is None:
        face_offset, reference_frame, offset_mode = resolve_face_offset_from_images(
            body_image,
            face_frames,
            request.manual_face_offset,
        )
    else:
        face_offset, reference_frame, offset_mode = resolved_face_offset
    visible_bounds = _alpha_bounds(body_image)
    scale_policy, suggested_transform = stage_reference.estimate(visible_bounds)
    expressions = _expression_frames(face_ref.frame_count, request.expression_ids)
    variant = LayeredPortraitVariant(
        variant_id=request.variant_id,
        pose_id=request.pose_id,
        form_id=request.form_id,
        body=body_ref,
        face=face_ref,
        expressions=expressions,
        default_expression=request.default_expression,
        face_offset=face_offset,
        visible_bounds=visible_bounds,
        scale_policy=scale_policy,
        source_game=request.source_game,
        warnings=tuple(warnings),
    )
    report = {
        "source_kind": "fvp_layered",
        "archive": str(request.archive),
        "body": body_ref.to_dict(),
        "face": face_ref.to_dict(),
        "face_offset": list(face_offset),
        "face_offset_mode": offset_mode,
        "face_reference_frame": reference_frame,
        "visible_bounds": visible_bounds.to_dict(),
        "scale_policy": scale_policy.to_dict(),
        "suggested_transform": suggested_transform.to_dict(),
        "warnings": warnings,
        "authoritative": {
            "resource_pair": True,
            "expression_frames": True,
            # ``profile`` means a target-game coordinate that was measured and
            # recorded by the compatibility adapter.  It is just as suitable
            # for deterministic generation as an exact pixel match.  A manual
            # value remains an explicit user override rather than an analysed
            # fact.
            "face_offset": offset_mode in {"pixel_match", "profile"},
            "stage_scale_and_position": False,
        },
    }
    return FvpLayeredImportResult(variant, suggested_transform, report)


def inspect_fvp_layered_pair(
    request: FvpLayeredImportRequest,
    stage_reference: StageReference,
) -> FvpLayeredImportResult:
    """Decode and validate one explicit body/expression pair from graph_bs."""

    archive = Path(request.archive).expanduser().resolve()
    body_info = inspect_bin_entry(archive, request.body_entry)
    face_info = inspect_bin_entry(archive, request.face_entry)
    body_ref = FvpResourceRef(
        archive=archive.name,
        entry_index=request.body_entry,
        resource_name=request.body_resource_name,
        width=int(body_info["width"]),
        height=int(body_info["height"]),
        frame_count=int(body_info["frame_count"]),
        texture_type=str(body_info["type"]),
    )
    face_ref = FvpResourceRef(
        archive=archive.name,
        entry_index=request.face_entry,
        resource_name=request.face_resource_name,
        width=int(face_info["width"]),
        height=int(face_info["height"]),
        frame_count=int(face_info["frame_count"]),
        texture_type=str(face_info["type"]),
    )
    body_image, _ = decoded_bin_entry_image(archive, request.body_entry, 0)
    face_frames = [
        decoded_bin_entry_image(archive, request.face_entry, frame)[0]
        for frame in range(face_ref.frame_count)
    ]
    # Native FVP portraits are not guaranteed to contain expression frame 0
    # inside the body image.  Hoshimemo's layered bodies, for example, contain
    # a transparent face window and draw the multi-frame expression resource
    # separately.  Reuse the established resolver here: explicit coordinates
    # win, then exact pixels, then a verified per-game compatibility anchor.
    resolved_face_offset = resolve_portrait_face_offset(
        archive,
        body_image,
        request.face_entry,
        face_info,
        request.manual_face_offset,
        request.face_resource_name,
        "脸部坐标",
    )
    return build_layered_variant_from_images(
        request=request,
        body_ref=body_ref,
        face_ref=face_ref,
        body_image=body_image,
        face_frames=face_frames,
        stage_reference=stage_reference,
        resolved_face_offset=resolved_face_offset,
    )


def assemble_fvp_character(
    *,
    character_id: str,
    display_name: str,
    imports: Sequence[FvpLayeredImportResult],
    default_variant: str | None = None,
    pose_defaults: Mapping[str, str] | None = None,
) -> FvpCharacterImportResult:
    """Group imported pairs without ever detaching a face set from its body.

    This is the boundary the future UI should use after importing all desired
    actions/forms.  A variant remains the atomic unit; body resources and face
    resources are never stored in two independently selectable global lists.
    """

    if not imports:
        raise PortraitProjectError("角色导入至少需要一个身体层 + 表情层组合")
    variants: dict[str, LayeredPortraitVariant] = {}
    transforms: dict[str, StageTransform] = {}
    reports: dict[str, Mapping[str, Any]] = {}
    for item in imports:
        variant_id = item.variant.variant_id
        if variant_id in variants:
            raise PortraitProjectError(f"重复导入立绘变体: {variant_id}")
        variants[variant_id] = item.variant
        transforms[variant_id] = item.suggested_transform
        reports[variant_id] = dict(item.report)
    chosen_default = default_variant or imports[0].variant.variant_id
    character = CharacterPortraitSet(
        character_id=character_id,
        display_name=display_name,
        variants=variants,
        default_variant=chosen_default,
        pose_defaults=dict(pose_defaults or {}),
    )
    return FvpCharacterImportResult(character, transforms, reports)
