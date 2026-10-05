"""Auditable Hoshimemo HD lowering for additive layered portraits.

This module is intentionally a *planner*, not a disk writer.  It turns the
target-neutral portrait IR into a deterministic install plan containing:

* exact target fingerprints that must pass before any write;
* atomic graph_bs body/face additions;
* profiled native or private-clone portrait slots;
* 4 resource + 9 runtime argument registration wrappers;
* ordered script calls (register all, native layout once, final transforms).

The later byte emitter may only consume a plan after ``preflight_target`` has
passed.  Keeping this boundary explicit prevents an address or carrier slot
from one HCB build from being silently reused against another build.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from .portrait_compile import (
    HoshimemoPortraitBackendProfile,
    PortraitCompileError,
    PortraitIRProgram,
)


HOSHIMEMO_PATCH_PLAN_SCHEMA = "fvp-studio.hoshimemo-portrait-patch-plan.v1"
HOSHIMEMO_TARGET_PROFILE_SCHEMA = "fvp-studio.hoshimemo-portrait-target.v1"
# Stable identity shared by the reviewed production profile and the compile
# profile.  The exact bytes are declared by the factory module below; keeping
# the identifier here also lets callers compare an IR target without importing
# the factory (and avoids a circular import).
HOSHIMEMO_NATIVE_PORTRAIT_PROFILE_ID = "hoshimemo-hd-cn-native-portrait-v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class HoshimemoPortraitBackendError(PortraitCompileError):
    """Raised before any file write when a target-specific invariant fails."""


def _required(value: str, label: str) -> str:
    value = str(value).strip()
    if not value:
        raise HoshimemoPortraitBackendError(f"{label}不能为空")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalise_sha256(value: str, label: str) -> str:
    value = str(value).strip().lower()
    if not _SHA256_RE.fullmatch(value):
        raise HoshimemoPortraitBackendError(f"{label}不是有效 SHA-256")
    return value


@dataclass(frozen=True)
class BinaryFingerprint:
    """Exact identity of one target file before installation."""

    sha256: str
    size: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "sha256",
            _normalise_sha256(self.sha256, "文件指纹"),
        )
        if self.size < 0:
            raise HoshimemoPortraitBackendError("文件大小不能为负数")

    @classmethod
    def from_bytes(cls, data: bytes) -> "BinaryFingerprint":
        return cls(_sha256(data), len(data))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BinaryFingerprint":
        return cls(str(value["sha256"]), int(value["size"]))

    def verify(self, data: bytes, label: str) -> None:
        if len(data) != self.size:
            raise HoshimemoPortraitBackendError(
                f"{label}大小不匹配: 预期 {self.size}, 实际 {len(data)}"
            )
        actual = _sha256(data)
        if actual != self.sha256:
            raise HoshimemoPortraitBackendError(
                f"{label} SHA-256 不匹配: 预期 {self.sha256}, 实际 {actual}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class CodeRegionFingerprint:
    """Fingerprint and ABI guard for the original portrait dispatcher."""

    start: int
    end: int
    sha256: str
    args: int = 13
    locals: int = 16

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise HoshimemoPortraitBackendError("函数指纹范围无效")
        object.__setattr__(
            self,
            "sha256",
            _normalise_sha256(self.sha256, "函数指纹"),
        )
        if self.args not in {12, 13}:
            raise HoshimemoPortraitBackendError(
                "当前后端只接受已确认的 12 / 13 入参立绘 dispatcher ABI"
            )
        if self.locals < 0:
            raise HoshimemoPortraitBackendError("局部变量数量不能为负数")

    @classmethod
    def from_bytes(
        cls,
        hcb: bytes,
        start: int,
        end: int,
        *,
        args: int = 13,
        locals: int = 16,
    ) -> "CodeRegionFingerprint":
        if start < 0 or end <= start or end > len(hcb):
            raise HoshimemoPortraitBackendError("无法从 HCB 取得函数指纹范围")
        return cls(start, end, _sha256(hcb[start:end]), args, locals)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CodeRegionFingerprint":
        return cls(
            int(value["start"]),
            int(value["end"]),
            str(value["sha256"]),
            int(value.get("args", 13)),
            int(value.get("locals", 16)),
        )

    def verify(self, hcb: bytes, label: str = "function_4477_") -> None:
        if self.end > len(hcb):
            raise HoshimemoPortraitBackendError(f"{label}超出目标 HCB")
        actual = _sha256(hcb[self.start : self.end])
        if actual != self.sha256:
            raise HoshimemoPortraitBackendError(
                f"{label}函数体指纹不匹配: 预期 {self.sha256}, 实际 {actual}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "sha256": self.sha256,
            "args": self.args,
            "locals": self.locals,
        }


@dataclass(frozen=True)
class LiteralPatchTemplate:
    """One profiled string literal rewrite inside a private dispatcher clone.

    ``value_key`` is resolved from ``HoshimemoVariantInstall.resource_values``.
    Keeping the source offset and expected text in the plan makes accidental
    matches impossible; a byte emitter must verify both before replacement.
    """

    source_offset: int
    expected: str
    value_key: str

    def __post_init__(self) -> None:
        if self.source_offset < 0:
            raise HoshimemoPortraitBackendError("字符串模板偏移不能为负数")
        object.__setattr__(self, "expected", _required(self.expected, "预期字符串"))
        object.__setattr__(self, "value_key", _required(self.value_key, "资源值键"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_offset": self.source_offset,
            "expected": self.expected,
            "value_key": self.value_key,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LiteralPatchTemplate":
        return cls(
            int(value["source_offset"]),
            str(value["expected"]),
            str(value["value_key"]),
        )


@dataclass(frozen=True)
class PrivateDispatcherRecipe:
    """Profiled recipe for cloning, never overwriting, function_4477_."""

    recipe_id: str
    output_symbol: str
    source_symbol: str
    carrier_selector: int
    literal_patches: tuple[LiteralPatchTemplate, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "recipe_id", _required(self.recipe_id, "克隆方案 ID"))
        object.__setattr__(
            self, "output_symbol", _required(self.output_symbol, "私有函数符号")
        )
        object.__setattr__(
            self, "source_symbol", _required(self.source_symbol, "源函数符号")
        )
        if self.carrier_selector < 0:
            raise HoshimemoPortraitBackendError("载体 selector 不能为负数")
        offsets = [item.source_offset for item in self.literal_patches]
        if len(offsets) != len(set(offsets)):
            raise HoshimemoPortraitBackendError(
                f"克隆方案 {self.recipe_id} 含重复字符串偏移"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "recipe_id": self.recipe_id,
            "output_symbol": self.output_symbol,
            "source_symbol": self.source_symbol,
            "carrier_selector": self.carrier_selector,
            "literal_patches": [item.to_dict() for item in self.literal_patches],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PrivateDispatcherRecipe":
        return cls(
            str(value["recipe_id"]),
            str(value["output_symbol"]),
            str(value["source_symbol"]),
            int(value["carrier_selector"]),
            tuple(
                LiteralPatchTemplate.from_dict(item)
                for item in value.get("literal_patches", ())
            ),
        )


@dataclass(frozen=True)
class HoshimemoPortraitSlot:
    """One independent target portrait channel.

    The identity is the dispatcher/selector/double-buffer primitive pair.
    The two primitives are alternating complete portrait composites, not the
    imported body and face resource layers.  ``state_slot`` from the runtime
    ABI is *not* part of this identity and may repeat.
    """

    slot_id: str
    selector: int
    primitive_ids: tuple[int, int]
    dispatcher_symbol: str
    kind: str = "private_clone"
    clone_recipe_id: str | None = None
    allocation_rank: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "slot_id", _required(self.slot_id, "立绘槽 ID"))
        object.__setattr__(
            self,
            "dispatcher_symbol",
            _required(self.dispatcher_symbol, "立绘槽分派函数"),
        )
        if self.selector < 0:
            raise HoshimemoPortraitBackendError("selector 不能为负数")
        if len(self.primitive_ids) != 2:
            raise HoshimemoPortraitBackendError("立绘槽必须有两个双缓冲 primitive")
        if any(value < 0 for value in self.primitive_ids):
            raise HoshimemoPortraitBackendError("primitive ID 不能为负数")
        if self.primitive_ids[0] == self.primitive_ids[1]:
            raise HoshimemoPortraitBackendError("双缓冲 primitive 不能相同")
        if self.kind not in {"native", "private_clone"}:
            raise HoshimemoPortraitBackendError(f"未知立绘槽类型: {self.kind}")
        if self.kind == "private_clone" and not self.clone_recipe_id:
            raise HoshimemoPortraitBackendError(
                f"私有立绘槽 {self.slot_id} 缺少克隆方案"
            )
        if self.kind == "native" and self.clone_recipe_id is not None:
            raise HoshimemoPortraitBackendError("原生立绘槽不能绑定克隆方案")

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "selector": self.selector,
            "primitive_ids": list(self.primitive_ids),
            "dispatcher_symbol": self.dispatcher_symbol,
            "kind": self.kind,
            "clone_recipe_id": self.clone_recipe_id,
            "allocation_rank": self.allocation_rank,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "HoshimemoPortraitSlot":
        primitive_ids = tuple(int(item) for item in value["primitive_ids"])
        if len(primitive_ids) != 2:
            raise HoshimemoPortraitBackendError(
                "目标配置中的立绘槽必须有两个 primitive ID"
            )
        return cls(
            slot_id=str(value["slot_id"]),
            selector=int(value["selector"]),
            primitive_ids=(primitive_ids[0], primitive_ids[1]),
            dispatcher_symbol=str(value["dispatcher_symbol"]),
            kind=str(value.get("kind", "private_clone")),
            clone_recipe_id=(
                None
                if value.get("clone_recipe_id") is None
                else str(value["clone_recipe_id"])
            ),
            allocation_rank=int(value.get("allocation_rank", 0)),
        )


@dataclass(frozen=True)
class HoshimemoTargetProfile:
    """One exact Hoshimemo HD backend target, guarded by fingerprints."""

    profile_id: str
    hcb: BinaryFingerprint
    graph_bs: BinaryFingerprint
    portrait_dispatcher: CodeRegionFingerprint
    symbols: Mapping[str, int]
    slots: tuple[HoshimemoPortraitSlot, ...]
    clone_recipes: tuple[PrivateDispatcherRecipe, ...] = ()
    # Layout calls are executable policy, not merely names present in the
    # symbol table.  The legacy Hoshimemo profile admits function_4480_; a
    # target-extracted acceptance profile must name its own exact apply helper.
    native_layout_symbols: tuple[str, ...] = ("function_4480_",)
    # Legacy FVP targets keep character resources in ``graph.bin`` while
    # newer targets commonly route them through ``graph_bs.bin``.  The exact
    # archive/namespace pair is target evidence, not a game-name switch.
    portrait_archive_name: str = "graph_bs.bin"
    portrait_resource_namespace: str = "graph_bs/"
    # Newer targets expose a reviewed 3/2 coordinate helper.  Older targets
    # use the native PrimSetXY syscall directly for the same static state.
    static_xy_mode: str = "function_4286"

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile_id", _required(self.profile_id, "目标配置 ID"))
        symbols = {str(key): int(value) for key, value in self.symbols.items()}
        if any(value < 0 for value in symbols.values()):
            raise HoshimemoPortraitBackendError("函数符号地址不能为负数")
        object.__setattr__(self, "symbols", symbols)
        # A profile is a declarative set, not an execution sequence.  Keep its
        # in-memory form canonical so JSON roundtrips, reviews and hashes do
        # not depend on the order in which a UI happened to add entries.
        object.__setattr__(
            self,
            "slots",
            tuple(sorted(self.slots, key=lambda item: item.slot_id)),
        )
        object.__setattr__(
            self,
            "clone_recipes",
            tuple(sorted(self.clone_recipes, key=lambda item: item.recipe_id)),
        )
        layout_symbols = tuple(
            sorted(
                {
                    _required(str(symbol), "原生布局函数符号")
                    for symbol in self.native_layout_symbols
                }
            )
        )
        if not layout_symbols:
            raise HoshimemoPortraitBackendError("目标配置必须声明原生布局函数")
        unresolved_layouts = [
            symbol for symbol in layout_symbols if symbol not in symbols
        ]
        if unresolved_layouts:
            raise HoshimemoPortraitBackendError(
                "原生布局函数未解析: " + ", ".join(unresolved_layouts)
            )
        object.__setattr__(self, "native_layout_symbols", layout_symbols)

        archive_name = _required(
            self.portrait_archive_name, "目标立绘资源归档"
        ).casefold()
        if (
            Path(archive_name).name != archive_name
            or not re.fullmatch(r"graph(?:_[a-z0-9]+)?\.bin", archive_name)
        ):
            raise HoshimemoPortraitBackendError(
                f"目标立绘资源归档不是受支持的 FVP graph BIN: {archive_name}"
            )
        namespace = _required(
            self.portrait_resource_namespace, "目标立绘资源命名空间"
        ).casefold()
        expected_namespace = f"{Path(archive_name).stem}/"
        if namespace != expected_namespace:
            raise HoshimemoPortraitBackendError(
                "立绘资源命名空间与目标归档不一致: "
                f"{namespace} != {expected_namespace}"
            )
        static_xy_mode = _required(
            self.static_xy_mode, "原生静态 XY 模式"
        ).casefold()
        if static_xy_mode not in {"function_4286", "primsetxy_syscall"}:
            raise HoshimemoPortraitBackendError(
                f"不支持的原生静态 XY 模式: {static_xy_mode}"
            )
        object.__setattr__(self, "portrait_archive_name", archive_name)
        object.__setattr__(self, "portrait_resource_namespace", namespace)
        object.__setattr__(self, "static_xy_mode", static_xy_mode)

        slot_ids: set[str] = set()
        selectors: set[int] = set()
        primitives: dict[int, str] = {}
        recipe_ids = {item.recipe_id for item in self.clone_recipes}
        if len(recipe_ids) != len(self.clone_recipes):
            raise HoshimemoPortraitBackendError("目标配置含重复克隆方案 ID")
        output_symbols = {item.output_symbol for item in self.clone_recipes}
        if len(output_symbols) != len(self.clone_recipes):
            raise HoshimemoPortraitBackendError("目标配置含重复私有函数符号")
        for slot in self.slots:
            if slot.slot_id in slot_ids:
                raise HoshimemoPortraitBackendError(f"重复立绘槽: {slot.slot_id}")
            if slot.selector in selectors:
                raise HoshimemoPortraitBackendError(
                    f"selector {slot.selector} 被多个立绘槽占用"
                )
            slot_ids.add(slot.slot_id)
            selectors.add(slot.selector)
            for primitive in slot.primitive_ids:
                if primitive in primitives:
                    raise HoshimemoPortraitBackendError(
                        f"primitive {primitive} 被 {primitives[primitive]} "
                        f"和 {slot.slot_id} 重复占用"
                    )
                primitives[primitive] = slot.slot_id
            if slot.kind == "private_clone":
                if slot.clone_recipe_id not in recipe_ids:
                    raise HoshimemoPortraitBackendError(
                        f"立绘槽 {slot.slot_id} 引用了未知克隆方案"
                    )
                recipe = next(
                    item
                    for item in self.clone_recipes
                    if item.recipe_id == slot.clone_recipe_id
                )
                if recipe.output_symbol != slot.dispatcher_symbol:
                    raise HoshimemoPortraitBackendError(
                        f"立绘槽 {slot.slot_id} 的 dispatcher 与克隆输出不一致"
                    )
            elif slot.dispatcher_symbol not in symbols:
                raise HoshimemoPortraitBackendError(
                    f"原生立绘槽 {slot.slot_id} 的 dispatcher 未解析"
                )
        for recipe in self.clone_recipes:
            if recipe.source_symbol not in symbols:
                raise HoshimemoPortraitBackendError(
                    f"克隆方案 {recipe.recipe_id} 的源函数符号未解析"
                )

    def slot(self, slot_id: str) -> HoshimemoPortraitSlot:
        for item in self.slots:
            if item.slot_id == slot_id:
                return item
        raise HoshimemoPortraitBackendError(f"目标配置不存在立绘槽: {slot_id}")

    def clone_recipe(self, recipe_id: str) -> PrivateDispatcherRecipe:
        for item in self.clone_recipes:
            if item.recipe_id == recipe_id:
                return item
        raise HoshimemoPortraitBackendError(f"未知克隆方案: {recipe_id}")

    def resolves_symbol(self, symbol: str) -> bool:
        return symbol in self.symbols or any(
            item.output_symbol == symbol for item in self.clone_recipes
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": HOSHIMEMO_TARGET_PROFILE_SCHEMA,
            "profile_id": self.profile_id,
            "hcb": self.hcb.to_dict(),
            "graph_bs": self.graph_bs.to_dict(),
            "portrait_dispatcher": self.portrait_dispatcher.to_dict(),
            "symbols": dict(sorted(self.symbols.items())),
            "slots": [item.to_dict() for item in sorted(self.slots, key=lambda x: x.slot_id)],
            "clone_recipes": [
                item.to_dict()
                for item in sorted(self.clone_recipes, key=lambda x: x.recipe_id)
            ],
            "native_layout_symbols": list(self.native_layout_symbols),
            "portrait_archive_name": self.portrait_archive_name,
            "portrait_resource_namespace": self.portrait_resource_namespace,
            "static_xy_mode": self.static_xy_mode,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "HoshimemoTargetProfile":
        schema = str(value.get("schema", ""))
        if schema != HOSHIMEMO_TARGET_PROFILE_SCHEMA:
            raise HoshimemoPortraitBackendError(
                f"不支持的目标配置 schema: {schema or '<缺失>'}"
            )
        return cls(
            profile_id=str(value["profile_id"]),
            hcb=BinaryFingerprint.from_dict(value["hcb"]),
            graph_bs=BinaryFingerprint.from_dict(value["graph_bs"]),
            portrait_dispatcher=CodeRegionFingerprint.from_dict(
                value["portrait_dispatcher"]
            ),
            symbols={
                str(key): int(address)
                for key, address in value.get("symbols", {}).items()
            },
            slots=tuple(
                HoshimemoPortraitSlot.from_dict(item)
                for item in value.get("slots", ())
            ),
            clone_recipes=tuple(
                PrivateDispatcherRecipe.from_dict(item)
                for item in value.get("clone_recipes", ())
            ),
            native_layout_symbols=tuple(
                str(item)
                for item in value.get(
                    "native_layout_symbols", ("function_4480_",)
                )
            ),
            portrait_archive_name=str(
                value.get("portrait_archive_name", "graph_bs.bin")
            ),
            portrait_resource_namespace=str(
                value.get("portrait_resource_namespace", "graph_bs/")
            ),
            static_xy_mode=str(value.get("static_xy_mode", "function_4286")),
        )


@dataclass(frozen=True)
class TargetPreflightReport:
    profile_id: str
    hcb_sha256: str
    graph_bs_sha256: str
    portrait_function_sha256: str
    passed: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "passed": self.passed,
            "hcb_sha256": self.hcb_sha256,
            "graph_bs_sha256": self.graph_bs_sha256,
            "portrait_function_sha256": self.portrait_function_sha256,
        }


def preflight_target(
    profile: HoshimemoTargetProfile,
    hcb: bytes,
    graph_bs: bytes,
) -> TargetPreflightReport:
    """Verify the exact files and source dispatcher before any mutation."""

    profile.hcb.verify(hcb, "HCB")
    profile.graph_bs.verify(graph_bs, profile.portrait_archive_name)
    profile.portrait_dispatcher.verify(hcb)
    return TargetPreflightReport(
        profile.profile_id,
        _sha256(hcb),
        _sha256(graph_bs),
        _sha256(hcb[profile.portrait_dispatcher.start : profile.portrait_dispatcher.end]),
    )


def allocate_private_slots(
    actor_ids: Iterable[str],
    profile: HoshimemoTargetProfile,
    *,
    occupied_slot_ids: Iterable[str] = (),
) -> dict[str, str]:
    """Deterministically assign only pre-profiled private slots.

    No selector or primitive ID is guessed.  If the profile has too few safe
    slots the operation fails instead of borrowing an original character slot.
    """

    actors = [_required(item, "舞台角色 ID") for item in actor_ids]
    if len(actors) != len(set(actors)):
        raise HoshimemoPortraitBackendError("待分配舞台角色 ID 重复")
    occupied = {str(item) for item in occupied_slot_ids}
    candidates = sorted(
        (
            item
            for item in profile.slots
            if item.kind == "private_clone" and item.slot_id not in occupied
        ),
        key=lambda item: (item.allocation_rank, item.selector, item.slot_id),
    )
    if len(candidates) < len(actors):
        raise HoshimemoPortraitBackendError(
            f"安全私有立绘槽不足: 需要 {len(actors)}, 可用 {len(candidates)}"
        )
    return {actor: candidates[index].slot_id for index, actor in enumerate(actors)}


@dataclass(frozen=True)
class HoshimemoVariantInstall:
    """Target resource names and clone values for one layered variant."""

    variant_id: str
    slot_id: str
    target_body_name: str
    target_face_name: str
    resource_values: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "variant_id", _required(self.variant_id, "变体 ID"))
        object.__setattr__(self, "slot_id", _required(self.slot_id, "立绘槽 ID"))
        object.__setattr__(
            self,
            "target_body_name",
            _required(self.target_body_name, "目标身体资源名"),
        )
        object.__setattr__(
            self,
            "target_face_name",
            _required(self.target_face_name, "目标表情资源名"),
        )
        if self.target_face_name != f"{self.target_body_name}_表情":
            raise HoshimemoPortraitBackendError(
                f"变体 {self.variant_id} 的表情资源必须与身体强绑定为 <身体>_表情"
            )
        object.__setattr__(
            self,
            "resource_values",
            {str(key): str(value) for key, value in self.resource_values.items()},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "slot_id": self.slot_id,
            "target_body_name": self.target_body_name,
            "target_face_name": self.target_face_name,
            "resource_values": dict(sorted(self.resource_values.items())),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "HoshimemoVariantInstall":
        return cls(
            variant_id=str(value["variant_id"]),
            slot_id=str(value["slot_id"]),
            target_body_name=str(value["target_body_name"]),
            target_face_name=str(value["target_face_name"]),
            resource_values={
                str(key): str(item)
                for key, item in value.get("resource_values", {}).items()
            },
        )


def load_target_profile(path: str | Path) -> HoshimemoTargetProfile:
    """Load one reviewed target profile shared by UI, CLI and installer."""

    profile_path = Path(path)
    try:
        value = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HoshimemoPortraitBackendError(
            f"无法读取目标配置 {profile_path}: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise HoshimemoPortraitBackendError("目标配置根节点必须是 JSON object")
    return HoshimemoTargetProfile.from_dict(value)


def save_target_profile(
    profile: HoshimemoTargetProfile,
    path: str | Path,
) -> None:
    """Write a deterministic UTF-8 profile; never touches game files."""

    profile_path = Path(path)
    try:
        profile_path.write_text(
            json.dumps(
                profile.to_dict(),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise HoshimemoPortraitBackendError(
            f"无法写入目标配置 {profile_path}: {exc}"
        ) from exc


@dataclass(frozen=True)
class LayeredResourceAppendPlan:
    variant_id: str
    atomic_group: str
    target_archive: str
    target_body_name: str
    target_face_name: str
    source_body: Mapping[str, Any]
    source_face: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "atomic_group": self.atomic_group,
            "target_archive": self.target_archive,
            "target_body_name": self.target_body_name,
            "target_face_name": self.target_face_name,
            "source_body": dict(self.source_body),
            "source_face": dict(self.source_face),
            "rules": {
                "install_body_and_face_together": True,
                "preserve_existing_payloads_byte_for_byte": True,
                "sort_names_with_profiled_japanese_collation": True,
            },
        }


@dataclass(frozen=True)
class DispatcherClonePlan:
    slot_id: str
    output_symbol: str
    source_symbol: str
    carrier_selector: int
    primitive_ids: tuple[int, int]
    resolved_literal_patches: tuple[Mapping[str, Any], ...]
    expected_args: int = 13
    expected_locals: int = 16

    def __post_init__(self) -> None:
        if self.expected_args not in {12, 13} or self.expected_locals < 0:
            raise HoshimemoPortraitBackendError("私有分派器克隆 ABI 无效")

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "output_symbol": self.output_symbol,
            "source_symbol": self.source_symbol,
            "carrier_selector": self.carrier_selector,
            "primitive_ids": list(self.primitive_ids),
            "resolved_literal_patches": [dict(item) for item in self.resolved_literal_patches],
            "rules": {
                "append_clone_at_hcb_eof": True,
                "relocate_internal_branches": True,
                "leave_original_dispatcher_unchanged": True,
                "verify_init_stack": {
                    "args": self.expected_args,
                    "locals": self.expected_locals,
                },
            },
        }


@dataclass(frozen=True)
class RegistrationWrapperPlan:
    symbol: str
    actor_id: str
    variant_id: str
    slot_id: str
    dispatcher_symbol: str
    resource_args: tuple[Any, ...]
    runtime_args: tuple[Any, ...]
    expected_argument_count: int = 13

    def __post_init__(self) -> None:
        if self.expected_argument_count not in {12, 13}:
            raise HoshimemoPortraitBackendError("立绘包装函数 dispatcher 参数数无效")
        if (
            len(self.resource_args) != 4
            or len(self.runtime_args) not in {8, 9}
            or len(self.resource_args) + len(self.runtime_args)
            != self.expected_argument_count
        ):
            raise HoshimemoPortraitBackendError(
                "立绘包装函数必须严格匹配 4+8 / 4+9 dispatcher ABI"
            )

    def to_dict(self) -> dict[str, Any]:
        pushes = list(self.resource_args + self.runtime_args)
        return {
            "symbol": self.symbol,
            "actor_id": self.actor_id,
            "variant_id": self.variant_id,
            "slot_id": self.slot_id,
            "dispatcher_symbol": self.dispatcher_symbol,
            "resource_args": list(self.resource_args),
            "runtime_args": list(self.runtime_args),
            "expected_argument_count": self.expected_argument_count,
            "bytecode_blueprint": [
                {"op": "init_stack", "args": 0, "locals": 0},
                *({"op": "push", "value": value} for value in pushes),
                {"op": "call", "symbol": self.dispatcher_symbol},
                {"op": "ret"},
            ],
        }


@dataclass(frozen=True)
class HoshimemoPortraitPatchPlan:
    profile: HoshimemoTargetProfile
    resources: tuple[LayeredResourceAppendPlan, ...]
    dispatcher_clones: tuple[DispatcherClonePlan, ...]
    wrappers: tuple[RegistrationWrapperPlan, ...]
    script_operations: tuple[Mapping[str, Any], ...]
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": HOSHIMEMO_PATCH_PLAN_SCHEMA,
            "target_profile": self.profile.to_dict(),
            "resources": [item.to_dict() for item in self.resources],
            "dispatcher_clones": [item.to_dict() for item in self.dispatcher_clones],
            "wrappers": [item.to_dict() for item in self.wrappers],
            "script_operations": [dict(item) for item in self.script_operations],
            "warnings": list(self.warnings),
            "write_policy": {
                "requires_successful_preflight": True,
                "write_to_isolated_copy": True,
                "transactional_hcb_and_graph_bs": True,
                "no_original_resource_replacement": True,
            },
        }


def _install_index(
    installs: Iterable[HoshimemoVariantInstall],
) -> dict[tuple[str, str], HoshimemoVariantInstall]:
    result: dict[tuple[str, str], HoshimemoVariantInstall] = {}
    for item in installs:
        key = (item.variant_id, item.slot_id)
        if key in result:
            raise HoshimemoPortraitBackendError(
                f"重复变体安装绑定: {item.variant_id}/{item.slot_id}"
            )
        result[key] = item
    return result


def _resolve_clone_patches(
    recipe: PrivateDispatcherRecipe,
    install: HoshimemoVariantInstall,
) -> tuple[Mapping[str, Any], ...]:
    """Resolve one slot's profiled clone constants without touching bytes.

    A private dispatcher is emitted once per logical portrait slot, not once
    per action.  Therefore every variant installed into the same slot must
    resolve the clone template to the exact same constant set.  Different
    body/action resources are still selected by the 4 resource arguments;
    clone literals are reserved for constants shared by the whole slot.
    """

    resolved: list[Mapping[str, Any]] = []
    for template in recipe.literal_patches:
        try:
            replacement = install.resource_values[template.value_key]
        except KeyError as exc:
            raise HoshimemoPortraitBackendError(
                f"变体 {install.variant_id} 缺少克隆资源值 {template.value_key}"
            ) from exc
        resolved.append(
            {
                "source_offset": template.source_offset,
                "expected": template.expected,
                "replacement": replacement,
                "value_key": template.value_key,
            }
        )
    return tuple(resolved)


def _validate_operation_order(operations: Sequence[Any]) -> None:
    finish_kinds = ("apply_final_transform",)

    def validate_finish_blocks(items: Sequence[Any]) -> list[str]:
        if len(items) % len(finish_kinds):
            raise HoshimemoPortraitBackendError("每个立绘必须完整应用几何、透明度和旋转")
        actor_ids: list[str] = []
        for start in range(0, len(items), len(finish_kinds)):
            block = items[start : start + len(finish_kinds)]
            if tuple(item.kind for item in block) != finish_kinds:
                raise HoshimemoPortraitBackendError(
                    "立绘最终效果必须是完整的静态 primitive 状态"
                )
            payloads = [dict(item.payload) for item in block]
            actor_id = str(payloads[0].get("actor_id", ""))
            slot_id = str(payloads[0].get("slot_id", ""))
            if not actor_id or not slot_id or any(
                str(payload.get("actor_id", "")) != actor_id
                or str(payload.get("slot_id", "")) != slot_id
                for payload in payloads[1:]
            ):
                raise HoshimemoPortraitBackendError("立绘最终状态不能跨角色或跨槽")
            actor_ids.append(actor_id)
        return actor_ids

    kinds = [item.kind for item in operations]
    if not kinds:
        return
    if "apply_native_layout" in kinds:
        if kinds.count("apply_native_layout") != 1:
            raise HoshimemoPortraitBackendError("原作布局函数必须且只能调用一次")
        boundary = kinds.index("apply_native_layout")
        if any(kind != "register_actor" for kind in kinds[:boundary]):
            raise HoshimemoPortraitBackendError("布局前只能注册立绘")
        if boundary == 0:
            raise HoshimemoPortraitBackendError("调用布局前至少要注册一个立绘")
        finished = validate_finish_blocks(operations[boundary + 1 :])
        registered = [str(item.payload.get("actor_id", "")) for item in operations[:boundary]]
        if finished != registered:
            raise HoshimemoPortraitBackendError("布局后的最终效果必须逐一对应已注册立绘")
        return
    if kinds[0] == "update_expression":
        finished = validate_finish_blocks(operations[1:])
        actor_id = str(operations[0].payload.get("actor_id", ""))
        if finished != [actor_id]:
            raise HoshimemoPortraitBackendError("表情更新后必须重应用同角色全部最终效果")
        return
    raise HoshimemoPortraitBackendError(f"不支持的立绘 IR 顺序: {kinds}")


def build_patch_plan(
    program: PortraitIRProgram,
    profile: HoshimemoTargetProfile,
    installs: Iterable[HoshimemoVariantInstall],
    *,
    existing_resource_names: Iterable[str] = (),
) -> HoshimemoPortraitPatchPlan:
    """Lower portrait IR into a deterministic, non-writing patch plan."""

    if program.target_profile.profile_id != profile.profile_id:
        raise HoshimemoPortraitBackendError(
            "IR 目标配置与 Hoshimemo 后端目标指纹不一致"
        )
    runtime_count_by_abi = {
        "resource4_runtime8": 8,
        "resource4_runtime9": 9,
    }
    try:
        expected_runtime_count = runtime_count_by_abi[
            program.target_profile.portrait_abi
        ]
    except KeyError as exc:
        raise HoshimemoPortraitBackendError(
            f"不支持的立绘 IR ABI: {program.target_profile.portrait_abi}"
        ) from exc
    expected_dispatcher_args = 4 + expected_runtime_count
    if profile.portrait_dispatcher.args != expected_dispatcher_args:
        raise HoshimemoPortraitBackendError(
            "立绘 IR ABI 与目标 dispatcher 参数数不一致"
        )
    _validate_operation_order(program.operations)
    install_map = _install_index(installs)
    existing = {str(item) for item in existing_resource_names}
    planned_names: dict[str, tuple[str, str]] = {}
    resources: dict[tuple[str, str], LayeredResourceAppendPlan] = {}
    clones: dict[str, DispatcherClonePlan] = {}
    wrappers: list[RegistrationWrapperPlan] = []
    script_operations: list[Mapping[str, Any]] = []

    for index, operation in enumerate(program.operations):
        payload = dict(operation.payload)
        if operation.kind == "register_actor":
            actor_id = _required(str(payload.get("actor_id", "")), "舞台角色 ID")
            variant_id = _required(str(payload.get("variant_id", "")), "变体 ID")
            slot_id = _required(str(payload.get("slot_id", "")), "立绘槽 ID")
            slot = profile.slot(slot_id)
            try:
                install = install_map[(variant_id, slot_id)]
            except KeyError as exc:
                raise HoshimemoPortraitBackendError(
                    f"变体 {variant_id} 在立绘槽 {slot_id} 没有安装绑定"
                ) from exc
            if int(payload["resource_args"][0]) != slot.selector:
                raise HoshimemoPortraitBackendError(
                    f"角色 {actor_id} 的 selector 与立绘槽 {slot_id} 不一致"
                )
            if payload.get("dispatcher_symbol") != slot.dispatcher_symbol:
                raise HoshimemoPortraitBackendError(
                    f"角色 {actor_id} 的 dispatcher 与立绘槽 {slot_id} 不一致"
                )
            if not profile.resolves_symbol(slot.dispatcher_symbol):
                raise HoshimemoPortraitBackendError(
                    f"立绘槽 {slot_id} 的 dispatcher 尚未解析"
                )
            resource_args = tuple(payload.get("resource_args", ()))
            runtime_args = tuple(payload.get("runtime_args", ()))
            if (
                len(resource_args) != 4
                or len(runtime_args) != expected_runtime_count
            ):
                raise HoshimemoPortraitBackendError(
                    f"角色 {actor_id} 的立绘调用不是严格 "
                    f"4+{expected_runtime_count} 入参"
                )

            pair_key = (install.target_body_name, install.target_face_name)
            body = dict(payload["body"])
            face = dict(payload["face"])
            for name, source_kind in (
                (install.target_body_name, "body"),
                (install.target_face_name, "face"),
            ):
                if name in existing:
                    raise HoshimemoPortraitBackendError(
                        f"目标 {profile.portrait_archive_name} 已存在资源 {name}; "
                        "新增流程禁止覆盖"
                    )
                owner = planned_names.get(name)
                if owner is not None and owner != pair_key:
                    raise HoshimemoPortraitBackendError(
                        f"目标资源名 {name} 被多个变体复用"
                    )
                planned_names[name] = pair_key
                if source_kind == "face" and int(face.get("frame_count", 0)) <= 0:
                    raise HoshimemoPortraitBackendError("表情资源没有可用帧")
            if pair_key not in resources:
                resources[pair_key] = LayeredResourceAppendPlan(
                    variant_id=variant_id,
                    atomic_group=f"portrait::{slot_id}::{variant_id}",
                    target_archive=profile.portrait_archive_name,
                    target_body_name=install.target_body_name,
                    target_face_name=install.target_face_name,
                    source_body=body,
                    source_face=face,
                )
            else:
                previous = resources[pair_key]
                if dict(previous.source_body) != body or dict(previous.source_face) != face:
                    raise HoshimemoPortraitBackendError(
                        f"资源对 {pair_key[0]} 的来源不一致"
                    )

            if slot.kind == "private_clone":
                recipe = profile.clone_recipe(str(slot.clone_recipe_id))
                resolved_patches = _resolve_clone_patches(recipe, install)
                candidate_clone = DispatcherClonePlan(
                    slot_id=slot.slot_id,
                    output_symbol=recipe.output_symbol,
                    source_symbol=recipe.source_symbol,
                    carrier_selector=recipe.carrier_selector,
                    primitive_ids=slot.primitive_ids,
                    resolved_literal_patches=resolved_patches,
                    expected_args=profile.portrait_dispatcher.args,
                    expected_locals=profile.portrait_dispatcher.locals,
                )
                previous_clone = clones.get(slot.slot_id)
                if previous_clone is None:
                    clones[slot.slot_id] = candidate_clone
                elif previous_clone != candidate_clone:
                    raise HoshimemoPortraitBackendError(
                        f"立绘槽 {slot.slot_id} 的多个动作解析出了不同的私有 "
                        "dispatcher 常量; 该槽不能安全共用同一克隆函数"
                    )

            wrapper_symbol = f"portrait_wrapper::{actor_id}::{variant_id}"
            wrapper = RegistrationWrapperPlan(
                wrapper_symbol,
                actor_id,
                variant_id,
                slot_id,
                slot.dispatcher_symbol,
                resource_args,
                runtime_args,
                expected_dispatcher_args,
            )
            wrappers.append(wrapper)
            script_operations.append(
                {
                    "kind": "call_registration_wrapper",
                    "symbol": wrapper_symbol,
                    "actor_id": actor_id,
                    "slot_id": slot_id,
                }
            )
        elif operation.kind == "apply_native_layout":
            symbol = _required(str(payload.get("symbol", "")), "布局函数符号")
            if symbol not in profile.symbols:
                raise HoshimemoPortraitBackendError(f"布局函数符号未解析: {symbol}")
            script_operations.append(
                {
                    "kind": "call_native_layout",
                    "symbol": symbol,
                    "address": profile.symbols[symbol],
                    "duration": payload.get("duration"),
                    "actor_ids": list(payload.get("actor_ids", ())),
                }
            )
        elif operation.kind == "apply_final_transform":
            actor_id = _required(str(payload.get("actor_id", "")), "舞台角色 ID")
            slot_id = _required(str(payload.get("slot_id", "")), "立绘槽 ID")
            slot = profile.slot(slot_id)
            if payload.get("mode") != "direct_static_state":
                raise HoshimemoPortraitBackendError(
                    "立绘最终状态必须使用 direct_static_state，不能用运动通道模拟"
                )
            setter_symbol = _required(
                str(payload.get("setter_symbol", "")), "静态 primitive setter 符号"
            )
            if setter_symbol != program.target_profile.final_transform_symbol:
                raise HoshimemoPortraitBackendError(
                    "静态 primitive setter 与编译目标配置不一致"
                )
            transform_value = payload.get("transform")
            if not isinstance(transform_value, Mapping):
                raise HoshimemoPortraitBackendError(
                    f"角色 {actor_id} 的最终状态缺少 transform"
                )
            try:
                x = int(transform_value["x"])
                y = int(transform_value["y"])
                z = int(transform_value["z"])
                scale = int(transform_value["scale"])
                rotation_degrees = int(transform_value["rotation"])
                opacity = int(transform_value["opacity"])
                rotation_tenths = int(payload["rotation_tenths"])
            except (KeyError, TypeError, ValueError) as exc:
                raise HoshimemoPortraitBackendError(
                    f"角色 {actor_id} 的最终状态必须包含整数 "
                    "x/y/z/scale/rotation/opacity"
                ) from exc
            if rotation_tenths != rotation_degrees * 10 or not (
                -32768 <= rotation_tenths <= 32767
            ):
                raise HoshimemoPortraitBackendError(
                    "立绘旋转角度无法编码为十分之一度"
                )
            if not 0 <= opacity <= 255:
                raise HoshimemoPortraitBackendError(
                    "立绘透明度必须在 0 到 255 之间"
                )
            transform = {
                "x": x,
                "y": y,
                "z": z,
                "scale": scale,
                "rotation": rotation_degrees,
                "opacity": opacity,
            }
            calls = [
                {
                    "symbol": setter_symbol,
                    "primitive_id": primitive_id,
                    # native_primitive_state(id, x, y, z,
                    #                        rotation_tenths, scale, opacity)
                    "args": [
                        primitive_id,
                        x,
                        y,
                        z,
                        rotation_tenths,
                        scale,
                        opacity,
                    ],
                }
                for primitive_id in slot.primitive_ids
            ]
            script_operations.append(
                {
                    "kind": "call_final_transform",
                    "actor_id": actor_id,
                    "slot_id": slot_id,
                    "state_slot": payload.get("state_slot"),
                    "setter_symbol": setter_symbol,
                    "transform": transform,
                    "rotation_tenths": rotation_tenths,
                    "mode": "direct_static_state",
                    "primitive_ids": list(slot.primitive_ids),
                    "calls": calls,
                    "rules": {
                        "native_chain": [
                            "function_4286_",
                            "PrimSetAlpha",
                            "PrimSetZ",
                            "PrimSetRS",
                        ],
                        "apply_to_both_double_buffers": True,
                        "uses_motion_channel": False,
                    },
                }
            )
        elif operation.kind == "apply_portrait_opacity":
            symbol = _required(str(payload.get("symbol", "")), "立绘透明度函数符号")
            if symbol not in profile.symbols:
                raise HoshimemoPortraitBackendError(
                    f"立绘透明度函数符号未解析: {symbol}"
                )
            slot_id = _required(str(payload.get("slot_id", "")), "立绘槽 ID")
            slot = profile.slot(slot_id)
            opacity = int(payload.get("opacity", -1))
            duration = int(payload.get("duration", 1))
            if not 0 <= opacity <= 255:
                raise HoshimemoPortraitBackendError("立绘透明度必须在 0 到 255 之间")
            if duration <= 0:
                raise HoshimemoPortraitBackendError("立绘透明度调用时长必须大于 0")
            script_operations.append(
                {
                    "kind": "call_portrait_opacity",
                    "symbol": symbol,
                    "address": profile.symbols[symbol],
                    "actor_id": payload["actor_id"],
                    "slot_id": slot_id,
                    "opacity": opacity,
                    "duration": duration,
                    "primitive_ids": list(slot.primitive_ids),
                    "calls": [
                        {
                            "primitive_id": primitive_id,
                            # function_4405_(id, src, dst, duration,
                            #                  wait, type, reverse, special)
                            "args": [
                                primitive_id,
                                opacity,
                                opacity,
                                duration,
                                None,
                                None,
                                None,
                                None,
                            ],
                        }
                        for primitive_id in slot.primitive_ids
                    ],
                    "rules": {
                        "apply_to_both_double_buffers": True,
                        "source_equals_target_for_immediate_state": True,
                    },
                }
            )
        elif operation.kind == "apply_portrait_rotation":
            symbol = _required(str(payload.get("symbol", "")), "立绘旋转函数符号")
            if symbol not in profile.symbols:
                raise HoshimemoPortraitBackendError(
                    f"立绘旋转函数符号未解析: {symbol}"
                )
            slot_id = _required(str(payload.get("slot_id", "")), "立绘槽 ID")
            slot = profile.slot(slot_id)
            degrees = int(payload.get("rotation_degrees", 0))
            tenths = int(payload.get("rotation_tenths", degrees * 10))
            duration = int(payload.get("duration", 1))
            if tenths != degrees * 10 or not -32768 <= tenths <= 32767:
                raise HoshimemoPortraitBackendError("立绘旋转角度无法编码为十分之一度")
            if duration <= 0:
                raise HoshimemoPortraitBackendError("立绘旋转调用时长必须大于 0")
            script_operations.append(
                {
                    "kind": "call_portrait_rotation",
                    "symbol": symbol,
                    "address": profile.symbols[symbol],
                    "actor_id": payload["actor_id"],
                    "slot_id": slot_id,
                    "rotation_degrees": degrees,
                    "rotation_tenths": tenths,
                    "duration": duration,
                    "primitive_ids": list(slot.primitive_ids),
                    "calls": [
                        {
                            "primitive_id": primitive_id,
                            # function_4409_(id, src, dst, duration,
                            #                  type, reverse, wait, special)
                            "args": [
                                primitive_id,
                                tenths,
                                tenths,
                                duration,
                                None,
                                None,
                                None,
                                None,
                            ],
                        }
                        for primitive_id in slot.primitive_ids
                    ],
                    "rules": {
                        "unit": "one_tenth_degree",
                        "apply_to_both_double_buffers": True,
                        "source_equals_target_for_immediate_state": True,
                    },
                }
            )
        elif operation.kind == "update_expression":
            symbol = _required(str(payload.get("symbol", "")), "表情函数符号")
            if symbol not in profile.symbols:
                raise HoshimemoPortraitBackendError(f"表情函数符号未解析: {symbol}")
            slot_id = _required(str(payload.get("slot_id", "")), "立绘槽 ID")
            profile.slot(slot_id)
            variant_id = _required(str(payload.get("variant_id", "")), "变体 ID")
            try:
                install = install_map[(variant_id, slot_id)]
            except KeyError as exc:
                raise HoshimemoPortraitBackendError(
                    f"变体 {variant_id} 在立绘槽 {slot_id} 没有安装绑定"
                ) from exc
            if payload.get("body_must_remain") is None or not payload.get(
                "preserve_transform"
            ):
                raise HoshimemoPortraitBackendError("表情更新缺少身体/变换保持保护")
            body_source = dict(payload["body_must_remain"])
            face_source = dict(payload["face"])
            expected_source_face = f"{body_source.get('resource_name', '')}_表情"
            if face_source.get("resource_name") != expected_source_face:
                raise HoshimemoPortraitBackendError(
                    f"变体 {variant_id} 的来源表情层没有与当前身体强绑定"
                )
            script_operations.append(
                {
                    "kind": "call_expression_update",
                    "symbol": symbol,
                    "address": profile.symbols[symbol],
                    "actor_id": payload["actor_id"],
                    "slot_id": slot_id,
                    "variant_id": variant_id,
                    "expression_code": payload["expression_code"],
                    "face_frame": payload["face_frame"],
                    "source_face": face_source,
                    "source_body_must_remain": body_source,
                    "target_face_name": install.target_face_name,
                    "target_body_must_remain": install.target_body_name,
                    "rules": {
                        "keep_body_primitive": True,
                        "keep_stage_transform": True,
                        "face_must_belong_to_target_body": True,
                    },
                }
            )
        else:
            raise HoshimemoPortraitBackendError(
                f"不支持的立绘 IR 操作 #{index}: {operation.kind}"
            )

    return HoshimemoPortraitPatchPlan(
        profile=profile,
        resources=tuple(
            resources[key] for key in sorted(resources, key=lambda item: item)
        ),
        dispatcher_clones=tuple(
            clones[key] for key in sorted(clones)
        ),
        wrappers=tuple(wrappers),
        script_operations=tuple(script_operations),
        warnings=tuple(program.warnings),
    )


def build_hoshimemo_native_portrait_profile() -> HoshimemoTargetProfile:
    """Lazy public entry point for the reviewed production profile factory."""

    from .hoshimemo_native_portrait_profile import (
        build_hoshimemo_native_portrait_profile as factory,
    )

    return factory()


def build_hoshimemo_native_portrait_backend_profile() -> HoshimemoPortraitBackendProfile:
    """Lazy public entry point for the matching compile-IR profile factory."""

    from .hoshimemo_native_portrait_profile import (
        build_hoshimemo_native_portrait_backend_profile as factory,
    )

    return factory()


def make_hoshimemo_native_portrait_profile() -> HoshimemoTargetProfile:
    """Compatibility alias for the reviewed production profile factory."""

    return build_hoshimemo_native_portrait_profile()


def make_hoshimemo_native_portrait_backend_profile() -> HoshimemoPortraitBackendProfile:
    """Compatibility alias for the matching compile-IR profile factory."""

    return build_hoshimemo_native_portrait_backend_profile()
