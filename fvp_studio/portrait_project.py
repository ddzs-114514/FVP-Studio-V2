"""Domain model for additive, layered FVP portrait projects.

The module deliberately contains no HCB bytecode writer and no UI code.  It
defines the stable contract shared by the future importer, stage editor and
per-game compiler backends.

Version 1 supports FVP's body + expression-layer layout only.  Flat images
from non-FVP games are intentionally not modelled yet: accepting them here
would hide the decisions still needed around cropping, anchors and expression
authoring.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping


PORTRAIT_PROJECT_SCHEMA = "fvp-studio.portrait-project.v1"


class PortraitProjectError(ValueError):
    """Raised when a portrait project violates a structural invariant."""


def _required_id(value: str, label: str) -> str:
    value = str(value).strip()
    if not value:
        raise PortraitProjectError(f"{label}不能为空")
    return value


@dataclass(frozen=True)
class PixelBounds:
    """A right/bottom-exclusive rectangle in decoded resource pixels."""

    left: int
    top: int
    right: int
    bottom: int

    def __post_init__(self) -> None:
        values = (self.left, self.top, self.right, self.bottom)
        if any(int(value) != value for value in values):
            raise PortraitProjectError("像素边界必须是整数")
        if self.left < 0 or self.top < 0:
            raise PortraitProjectError("像素边界不能为负数")
        if self.right <= self.left or self.bottom <= self.top:
            raise PortraitProjectError("像素边界必须具有正宽高")

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top

    def to_dict(self) -> dict[str, int]:
        return {
            "left": self.left,
            "top": self.top,
            "right": self.right,
            "bottom": self.bottom,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PixelBounds":
        return cls(*(int(raw[key]) for key in ("left", "top", "right", "bottom")))


@dataclass(frozen=True)
class FvpResourceRef:
    """One authoritative entry in an FVP BIN archive."""

    archive: str
    entry_index: int
    resource_name: str
    width: int
    height: int
    frame_count: int
    texture_type: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "archive", _required_id(self.archive, "BIN 归档名"))
        object.__setattr__(self, "resource_name", _required_id(self.resource_name, "资源名"))
        if self.entry_index < 0:
            raise PortraitProjectError("BIN entry_index 不能为负数")
        if self.width <= 0 or self.height <= 0:
            raise PortraitProjectError("资源宽高必须大于零")
        if self.frame_count <= 0:
            raise PortraitProjectError("资源帧数必须大于零")

    def to_dict(self) -> dict[str, Any]:
        return {
            "archive": self.archive,
            "entry_index": self.entry_index,
            "resource_name": self.resource_name,
            "width": self.width,
            "height": self.height,
            "frame_count": self.frame_count,
            "texture_type": self.texture_type,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "FvpResourceRef":
        return cls(
            archive=str(raw["archive"]),
            entry_index=int(raw["entry_index"]),
            resource_name=str(raw["resource_name"]),
            width=int(raw["width"]),
            height=int(raw["height"]),
            frame_count=int(raw["frame_count"]),
            texture_type=str(raw.get("texture_type", "")),
        )


@dataclass(frozen=True)
class ExpressionFrame:
    """A semantic expression id bound to one frame in one face resource."""

    expression_id: str
    frame: int
    label: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "expression_id", _required_id(self.expression_id, "表情 ID")
        )
        if self.frame < 0:
            raise PortraitProjectError("表情帧号不能为负数")

    def to_dict(self) -> dict[str, Any]:
        return {
            "expression_id": self.expression_id,
            "frame": self.frame,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ExpressionFrame":
        return cls(
            expression_id=str(raw["expression_id"]),
            frame=int(raw["frame"]),
            label=str(raw.get("label", "")),
        )


@dataclass(frozen=True)
class ScalePolicy:
    """Estimated starting scale and the manual wheel-editing envelope.

    Values use FVP's per-mille convention: 1000 means 100 percent.
    """

    estimated: int
    minimum: int
    maximum: int
    wheel_step: int = 25

    def __post_init__(self) -> None:
        if self.minimum <= 0:
            raise PortraitProjectError("最小缩放必须大于零")
        if self.maximum < self.minimum:
            raise PortraitProjectError("最大缩放不能小于最小缩放")
        if not self.minimum <= self.estimated <= self.maximum:
            raise PortraitProjectError("估算缩放必须位于最小值与最大值之间")
        if self.wheel_step <= 0:
            raise PortraitProjectError("滚轮缩放步长必须大于零")

    def clamp(self, value: int) -> int:
        return max(self.minimum, min(self.maximum, int(value)))

    def adjust(self, current: int, wheel_steps: int) -> int:
        return self.clamp(int(current) + int(wheel_steps) * self.wheel_step)

    def to_dict(self) -> dict[str, int]:
        return {
            "estimated": self.estimated,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "wheel_step": self.wheel_step,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ScalePolicy":
        return cls(
            estimated=int(raw["estimated"]),
            minimum=int(raw["minimum"]),
            maximum=int(raw["maximum"]),
            wheel_step=int(raw.get("wheel_step", 25)),
        )


@dataclass(frozen=True)
class LayeredPortraitVariant:
    """One exact action/form and its inseparable body + face resource pair."""

    variant_id: str
    pose_id: str
    form_id: str
    body: FvpResourceRef
    face: FvpResourceRef
    expressions: tuple[ExpressionFrame, ...]
    default_expression: str
    face_offset: tuple[int, int]
    visible_bounds: PixelBounds
    scale_policy: ScalePolicy
    source_game: str = ""
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "variant_id", _required_id(self.variant_id, "变体 ID"))
        object.__setattr__(self, "pose_id", _required_id(self.pose_id, "动作 ID"))
        object.__setattr__(self, "form_id", _required_id(self.form_id, "尺寸类型"))
        object.__setattr__(
            self,
            "default_expression",
            _required_id(self.default_expression, "默认表情 ID"),
        )
        object.__setattr__(self, "expressions", tuple(self.expressions))
        object.__setattr__(self, "warnings", tuple(str(item) for item in self.warnings))
        if self.body.frame_count != 1:
            raise PortraitProjectError("身体层必须是单帧资源")
        if self.body.archive != self.face.archive:
            raise PortraitProjectError("身体层与表情层必须来自同一个 BIN 归档")
        if self.visible_bounds.right > self.body.width or self.visible_bounds.bottom > self.body.height:
            raise PortraitProjectError("可见区域超出身体层画布")
        if len(self.face_offset) != 2:
            raise PortraitProjectError("脸部坐标必须是 (x, y)")
        face_x, face_y = (int(value) for value in self.face_offset)
        if face_x < 0 or face_y < 0:
            raise PortraitProjectError("脸部坐标不能为负数")
        if face_x + self.face.width > self.body.width or face_y + self.face.height > self.body.height:
            raise PortraitProjectError("表情层超出身体层画布")
        object.__setattr__(self, "face_offset", (face_x, face_y))
        if not self.expressions:
            raise PortraitProjectError("分层立绘至少需要一个表情帧")
        ids: set[str] = set()
        frames: set[int] = set()
        for expression in self.expressions:
            if expression.expression_id in ids:
                raise PortraitProjectError(f"重复表情 ID: {expression.expression_id}")
            if expression.frame in frames:
                raise PortraitProjectError(f"重复绑定表情帧: {expression.frame}")
            if expression.frame >= self.face.frame_count:
                raise PortraitProjectError(
                    f"表情 {expression.expression_id} 的帧号超出资源范围"
                )
            ids.add(expression.expression_id)
            frames.add(expression.frame)
        if self.default_expression not in ids:
            raise PortraitProjectError("默认表情不属于当前动作/尺寸的表情组")

    @property
    def expression_map(self) -> dict[str, ExpressionFrame]:
        return {item.expression_id: item for item in self.expressions}

    def expression(self, expression_id: str) -> ExpressionFrame:
        try:
            return self.expression_map[expression_id]
        except KeyError as exc:
            raise PortraitProjectError(
                f"变体 {self.variant_id} 不包含表情 {expression_id}"
            ) from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "pose_id": self.pose_id,
            "form_id": self.form_id,
            "body": self.body.to_dict(),
            "face": self.face.to_dict(),
            "expressions": [item.to_dict() for item in self.expressions],
            "default_expression": self.default_expression,
            "face_offset": list(self.face_offset),
            "visible_bounds": self.visible_bounds.to_dict(),
            "scale_policy": self.scale_policy.to_dict(),
            "source_game": self.source_game,
            "warnings": list(self.warnings),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "LayeredPortraitVariant":
        return cls(
            variant_id=str(raw["variant_id"]),
            pose_id=str(raw["pose_id"]),
            form_id=str(raw["form_id"]),
            body=FvpResourceRef.from_dict(raw["body"]),
            face=FvpResourceRef.from_dict(raw["face"]),
            expressions=tuple(
                ExpressionFrame.from_dict(item) for item in raw["expressions"]
            ),
            default_expression=str(raw["default_expression"]),
            face_offset=tuple(int(value) for value in raw["face_offset"]),
            visible_bounds=PixelBounds.from_dict(raw["visible_bounds"]),
            scale_policy=ScalePolicy.from_dict(raw["scale_policy"]),
            source_game=str(raw.get("source_game", "")),
            warnings=tuple(str(item) for item in raw.get("warnings", ())),
        )


@dataclass
class CharacterPortraitSet:
    """All imported actions/forms for one logical character."""

    character_id: str
    display_name: str
    variants: dict[str, LayeredPortraitVariant]
    default_variant: str
    pose_defaults: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.character_id = _required_id(self.character_id, "角色 ID")
        self.display_name = _required_id(self.display_name, "角色显示名")
        self.variants = dict(self.variants)
        self.pose_defaults = dict(self.pose_defaults)
        if not self.variants:
            raise PortraitProjectError("角色至少需要一个立绘变体")
        for key, variant in self.variants.items():
            if key != variant.variant_id:
                raise PortraitProjectError(f"变体键与 ID 不一致: {key}")
        if self.default_variant not in self.variants:
            raise PortraitProjectError("角色默认变体不存在")
        poses = {variant.pose_id for variant in self.variants.values()}
        for pose_id in poses:
            candidates = [
                variant.variant_id
                for variant in self.variants.values()
                if variant.pose_id == pose_id
            ]
            self.pose_defaults.setdefault(pose_id, candidates[0])
        for pose_id, variant_id in self.pose_defaults.items():
            if variant_id not in self.variants:
                raise PortraitProjectError(f"动作 {pose_id} 的默认变体不存在")
            if self.variants[variant_id].pose_id != pose_id:
                raise PortraitProjectError(f"动作 {pose_id} 的默认变体属于其他动作")

    def variant(self, variant_id: str) -> LayeredPortraitVariant:
        try:
            return self.variants[variant_id]
        except KeyError as exc:
            raise PortraitProjectError(
                f"角色 {self.character_id} 不包含变体 {variant_id}"
            ) from exc

    def choose_variant(
        self, pose_id: str, preferred_form: str | None = None
    ) -> LayeredPortraitVariant:
        candidates = [
            variant for variant in self.variants.values() if variant.pose_id == pose_id
        ]
        if not candidates:
            raise PortraitProjectError(
                f"角色 {self.character_id} 不包含动作 {pose_id}"
            )
        if preferred_form is not None:
            for candidate in candidates:
                if candidate.form_id == preferred_form:
                    return candidate
        return self.variant(self.pose_defaults[pose_id])

    def to_dict(self) -> dict[str, Any]:
        return {
            "character_id": self.character_id,
            "display_name": self.display_name,
            "default_variant": self.default_variant,
            "pose_defaults": dict(sorted(self.pose_defaults.items())),
            "variants": [
                self.variants[key].to_dict() for key in sorted(self.variants)
            ],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CharacterPortraitSet":
        variants = [LayeredPortraitVariant.from_dict(item) for item in raw["variants"]]
        return cls(
            character_id=str(raw["character_id"]),
            display_name=str(raw["display_name"]),
            variants={item.variant_id: item for item in variants},
            default_variant=str(raw["default_variant"]),
            pose_defaults={
                str(key): str(value)
                for key, value in dict(raw.get("pose_defaults", {})).items()
            },
        )


@dataclass(frozen=True)
class StageTransform:
    """User-editable final transform/effects applied after native layout."""

    x: int = 0
    y: int = 0
    z: int = 1500
    scale: int = 1000
    rotation: int = 0
    opacity: int = 255

    def __post_init__(self) -> None:
        if not 0 <= self.opacity <= 255:
            raise PortraitProjectError("立绘透明度必须在 0 到 255 之间")
        # MotionMoveR stores tenths of a degree in a signed 16-bit field.
        if not -3276 <= self.rotation <= 3276:
            raise PortraitProjectError("立绘旋转角度必须在 -3276 到 3276 度之间")

    def to_dict(self) -> dict[str, int]:
        return {
            "x": self.x,
            "y": self.y,
            "z": self.z,
            "scale": self.scale,
            "rotation": self.rotation,
            "opacity": self.opacity,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "StageTransform":
        return cls(
            x=int(raw.get("x", 0)),
            y=int(raw.get("y", 0)),
            z=int(raw.get("z", 1500)),
            scale=int(raw.get("scale", 1000)),
            rotation=int(raw.get("rotation", 0)),
            opacity=int(raw.get("opacity", 255)),
        )


@dataclass
class StageActor:
    """One independent character instance on the stage.

    ``slot_id`` is the logical identity of the target-backend portrait slot.
    It must be unique inside a stage.  ``state_slot`` is deliberately kept as
    a separate field: in Hoshimemo's verified 4+9 call shape it is the eighth
    runtime argument, and multiple independent private dispatchers may legally
    use the same value.  Treating that runtime value as the slot identity was
    an earlier modelling mistake.
    """

    actor_id: str
    character_id: str
    variant_id: str
    expression_id: str
    transform: StageTransform
    state_slot: int
    position_preset: int = 0
    transition: int | None = None
    hidden: bool = False
    slot_id: str = ""

    def __post_init__(self) -> None:
        self.actor_id = _required_id(self.actor_id, "舞台角色 ID")
        self.character_id = _required_id(self.character_id, "角色 ID")
        self.variant_id = _required_id(self.variant_id, "变体 ID")
        self.expression_id = _required_id(self.expression_id, "表情 ID")
        self.slot_id = _required_id(
            self.slot_id or self.actor_id,
            "目标立绘槽 ID",
        )
        if self.state_slot < 0:
            raise PortraitProjectError("运行状态参数不能为负数")

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "character_id": self.character_id,
            "variant_id": self.variant_id,
            "expression_id": self.expression_id,
            "transform": self.transform.to_dict(),
            "state_slot": self.state_slot,
            "position_preset": self.position_preset,
            "transition": self.transition,
            "hidden": self.hidden,
            "slot_id": self.slot_id,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "StageActor":
        return cls(
            actor_id=str(raw["actor_id"]),
            character_id=str(raw["character_id"]),
            variant_id=str(raw["variant_id"]),
            expression_id=str(raw["expression_id"]),
            transform=StageTransform.from_dict(raw.get("transform", {})),
            state_slot=int(raw["state_slot"]),
            position_preset=int(raw.get("position_preset", 0)),
            transition=(
                None if raw.get("transition") is None else int(raw["transition"])
            ),
            hidden=bool(raw.get("hidden", False)),
            slot_id=str(raw.get("slot_id", raw["actor_id"])),
        )


@dataclass
class PortraitProject:
    """Mutable project state used by a future stage editor."""

    characters: dict[str, CharacterPortraitSet] = field(default_factory=dict)
    actors: dict[str, StageActor] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.characters = dict(self.characters)
        self.actors = dict(self.actors)
        self.validate()

    def validate(self) -> None:
        for key, character in self.characters.items():
            if key != character.character_id:
                raise PortraitProjectError(f"角色键与 ID 不一致: {key}")
        occupied_slots: dict[str, str] = {}
        for key, actor in self.actors.items():
            if key != actor.actor_id:
                raise PortraitProjectError(f"舞台角色键与 ID 不一致: {key}")
            character = self.character(actor.character_id)
            variant = character.variant(actor.variant_id)
            variant.expression(actor.expression_id)
            if not variant.scale_policy.minimum <= actor.transform.scale <= variant.scale_policy.maximum:
                raise PortraitProjectError(
                    f"角色 {actor.actor_id} 的缩放超出当前变体范围"
                )
            if actor.slot_id in occupied_slots:
                raise PortraitProjectError(
                    f"目标立绘槽 {actor.slot_id} 被 {occupied_slots[actor.slot_id]} "
                    f"和 {actor.actor_id} 重复占用"
                )
            occupied_slots[actor.slot_id] = actor.actor_id

    def character(self, character_id: str) -> CharacterPortraitSet:
        try:
            return self.characters[character_id]
        except KeyError as exc:
            raise PortraitProjectError(f"未知角色: {character_id}") from exc

    def actor(self, actor_id: str) -> StageActor:
        try:
            return self.actors[actor_id]
        except KeyError as exc:
            raise PortraitProjectError(f"未知舞台角色: {actor_id}") from exc

    def add_character(self, character: CharacterPortraitSet) -> None:
        if character.character_id in self.characters:
            raise PortraitProjectError(f"角色已存在: {character.character_id}")
        self.characters[character.character_id] = character

    def add_actor(self, actor: StageActor) -> None:
        if actor.actor_id in self.actors:
            raise PortraitProjectError(f"舞台角色已存在: {actor.actor_id}")
        if any(item.slot_id == actor.slot_id for item in self.actors.values()):
            raise PortraitProjectError(f"目标立绘槽已被占用: {actor.slot_id}")
        character = self.character(actor.character_id)
        variant = character.variant(actor.variant_id)
        variant.expression(actor.expression_id)
        if not variant.scale_policy.minimum <= actor.transform.scale <= variant.scale_policy.maximum:
            raise PortraitProjectError("初始缩放超出变体允许范围")
        self.actors[actor.actor_id] = actor

    def set_expression(self, actor_id: str, expression_id: str) -> None:
        """Switch only the face frame; body and transform stay untouched."""

        actor = self.actor(actor_id)
        variant = self.character(actor.character_id).variant(actor.variant_id)
        variant.expression(expression_id)
        actor.expression_id = expression_id

    def switch_variant(
        self,
        actor_id: str,
        variant_id: str,
        *,
        reset_scale: bool = False,
    ) -> None:
        """Switch body and its attached face set as one atomic operation.

        A semantic expression id is retained when the destination variant owns
        the same id.  Otherwise the destination's default is selected.  The
        final stage transform is retained; scale is clamped to the destination
        envelope, or reset to its estimate when explicitly requested.
        """

        actor = self.actor(actor_id)
        character = self.character(actor.character_id)
        target = character.variant(variant_id)
        expression_id = (
            actor.expression_id
            if actor.expression_id in target.expression_map
            else target.default_expression
        )
        scale = (
            target.scale_policy.estimated
            if reset_scale
            else target.scale_policy.clamp(actor.transform.scale)
        )
        actor.variant_id = target.variant_id
        actor.expression_id = expression_id
        actor.transform = replace(actor.transform, scale=scale)

    def switch_pose(
        self,
        actor_id: str,
        pose_id: str,
        *,
        preferred_form: str | None = None,
        reset_scale: bool = False,
    ) -> None:
        actor = self.actor(actor_id)
        character = self.character(actor.character_id)
        current = character.variant(actor.variant_id)
        target = character.choose_variant(
            pose_id,
            preferred_form=current.form_id if preferred_form is None else preferred_form,
        )
        self.switch_variant(actor_id, target.variant_id, reset_scale=reset_scale)

    def switch_form(
        self,
        actor_id: str,
        form_id: str,
        *,
        reset_scale: bool = False,
    ) -> None:
        actor = self.actor(actor_id)
        character = self.character(actor.character_id)
        current = character.variant(actor.variant_id)
        target = character.choose_variant(current.pose_id, preferred_form=form_id)
        if target.form_id != form_id:
            raise PortraitProjectError(
                f"动作 {current.pose_id} 不包含尺寸类型 {form_id}"
            )
        self.switch_variant(actor_id, target.variant_id, reset_scale=reset_scale)

    def adjust_scale(self, actor_id: str, wheel_steps: int) -> int:
        actor = self.actor(actor_id)
        variant = self.character(actor.character_id).variant(actor.variant_id)
        value = variant.scale_policy.adjust(actor.transform.scale, wheel_steps)
        actor.transform = replace(actor.transform, scale=value)
        return value

    def move_actor(self, actor_id: str, *, x: int | None = None, y: int | None = None) -> None:
        actor = self.actor(actor_id)
        actor.transform = replace(
            actor.transform,
            x=actor.transform.x if x is None else int(x),
            y=actor.transform.y if y is None else int(y),
        )

    def resolve_actor(self, actor_id: str) -> dict[str, Any]:
        """Return the exact body, face frame and transform for a backend."""

        actor = self.actor(actor_id)
        character = self.character(actor.character_id)
        variant = character.variant(actor.variant_id)
        expression = variant.expression(actor.expression_id)
        return {
            "actor_id": actor.actor_id,
            "character_id": character.character_id,
            "variant_id": variant.variant_id,
            "pose_id": variant.pose_id,
            "form_id": variant.form_id,
            "body": variant.body.to_dict(),
            "face": variant.face.to_dict(),
            "face_frame": expression.frame,
            "expression_id": expression.expression_id,
            "face_offset": list(variant.face_offset),
            "transform": actor.transform.to_dict(),
            "state_slot": actor.state_slot,
            "slot_id": actor.slot_id,
            "position_preset": actor.position_preset,
            "transition": actor.transition,
            "hidden": actor.hidden,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PORTRAIT_PROJECT_SCHEMA,
            "source_kind": "fvp_layered",
            "characters": [
                self.characters[key].to_dict() for key in sorted(self.characters)
            ],
            "actors": [self.actors[key].to_dict() for key in sorted(self.actors)],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PortraitProject":
        if raw.get("schema") != PORTRAIT_PROJECT_SCHEMA:
            raise PortraitProjectError("不支持的立绘工程格式")
        if raw.get("source_kind") != "fvp_layered":
            raise PortraitProjectError("v1 只支持 FVP 身体层 + 表情层导入")
        characters = [
            CharacterPortraitSet.from_dict(item) for item in raw.get("characters", ())
        ]
        actors = [StageActor.from_dict(item) for item in raw.get("actors", ())]
        return cls(
            characters={item.character_id: item for item in characters},
            actors={item.actor_id: item for item in actors},
        )

    @classmethod
    def from_iterables(
        cls,
        characters: Iterable[CharacterPortraitSet],
        actors: Iterable[StageActor] = (),
    ) -> "PortraitProject":
        character_list = list(characters)
        actor_list = list(actors)
        return cls(
            characters={item.character_id: item for item in character_list},
            actors={item.actor_id: item for item in actor_list},
        )
