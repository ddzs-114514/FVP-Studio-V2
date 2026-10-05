"""Deterministic Hoshimemo layered-portrait candidate emitter.

This module is intentionally narrower than a general HCB compiler.  It turns
an already validated :class:`HoshimemoPortraitPatchPlan` into two complete
candidate byte streams while preserving the original files:

* new body/face HZC entries are appended to ``graph_bs.bin``;
* profiled private dispatcher clones and strict 4+8 / 4+9 wrappers are appended at
  the physical HCB EOF;
* an optional, explicitly fingerprinted scene hook can jump into a small
  trampoline that calls those wrappers.

The emitter never guesses a story offset.  Without a :class:`SceneHookSpec`
the output is useful for byte review, but is deliberately marked
``install_ready=False`` and cannot cross the transaction boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import struct
from typing import Any, Iterable, Mapping, Sequence

from .bin_archive import append_hzc_entries, hzc_metadata
from .hcb import Instruction, parse_bytes
from .hoshimemo_portrait_backend import (
    DispatcherClonePlan,
    HoshimemoPortraitBackendError,
    HoshimemoPortraitPatchPlan,
    RegistrationWrapperPlan,
    preflight_target,
)


PORTRAIT_EMITTER_ID = "fvp-studio-v2.hoshimemo-layered-portrait-emitter/1"
NATIVE_PRIMITIVE_STATE_SYMBOL = "native_primitive_state"


class PortraitEmitterError(HoshimemoPortraitBackendError):
    """Raised when a patch plan cannot be lowered without guessing."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u32(value: int, label: str) -> bytes:
    value = int(value)
    if value < 0 or value > 0xFFFFFFFF:
        raise PortraitEmitterError(f"{label}超出 u32 范围: {value}")
    return struct.pack("<I", value)


def _encode_init(args: int, locals_: int) -> bytes:
    if not 0 <= int(args) <= 0xFF or not 0 <= int(locals_) <= 0xFF:
        raise PortraitEmitterError("init_stack 参数超出 u8 范围")
    return bytes((0x01, int(args), int(locals_)))


def _encode_call(address: int) -> bytes:
    return b"\x02" + _u32(address, "call 地址")


def _encode_syscall(syscall_id: int) -> bytes:
    value = int(syscall_id)
    if not 0 <= value <= 0xFFFF:
        raise PortraitEmitterError(f"syscall ID 超出 u16 范围: {value}")
    return b"\x03" + struct.pack("<H", value)


def _encode_push_stack(index: int) -> bytes:
    value = int(index)
    if not -0x80 <= value <= 0x7F:
        raise PortraitEmitterError(f"push_stack 索引超出 i8 范围: {value}")
    return b"\x10" + struct.pack("<b", value)


def _encode_jmp(address: int) -> bytes:
    return b"\x06" + _u32(address, "jmp 地址")


def _encode_jz(address: int) -> bytes:
    return b"\x07" + _u32(address, "jz 地址")


def _encode_string(value: str, encoding: str) -> bytes:
    try:
        payload = str(value).encode(encoding) + b"\0"
    except UnicodeEncodeError as exc:
        raise PortraitEmitterError(
            f"字符串不能编码为 {encoding}: {value!r}"
        ) from exc
    if len(payload) > 0xFF:
        raise PortraitEmitterError(
            f"push_string 超过 255 字节: {value!r} ({len(payload)})"
        )
    return bytes((0x0E, len(payload))) + payload


def _encode_push(value: Any, encoding: str) -> bytes:
    if value is None:
        return b"\x08"
    if value is True:
        return b"\x09"
    if value is False:
        value = 0
    if isinstance(value, int):
        if -0x80 <= value <= 0x7F:
            return b"\x0C" + struct.pack("<b", value)
        if -0x8000 <= value <= 0x7FFF:
            return b"\x0B" + struct.pack("<h", value)
        if -0x80000000 <= value <= 0x7FFFFFFF:
            return b"\x0A" + struct.pack("<i", value)
        raise PortraitEmitterError(f"整数超出 HCB i32 范围: {value}")
    if isinstance(value, float):
        return b"\x0D" + struct.pack("<f", value)
    if isinstance(value, str):
        return _encode_string(value, encoding)
    raise PortraitEmitterError(f"不支持的 HCB 入参类型: {type(value).__name__}")


@dataclass(frozen=True)
class SceneHookSpec:
    """One exact five-byte story patch and its explicit trampoline program.

    Supported operations are intentionally small and reviewable:

    ``call_symbol``
        Call a generated wrapper/private clone or a profiled native symbol.
    ``call_address``
        Call an explicit absolute address.
    ``push``
        Push one literal value using the regular HCB value encoding.
    ``jmp``
        Jump to an explicit absolute continuation address.
    ``ret``
        Return from the current function.

    A trampoline normally ends in an explicit ``jmp`` back to the first
    untouched instruction.  Nothing is inferred from the patch plan's logical
    ``script_operations`` because those operations do not identify a story
    byte offset.
    """

    patch_offset: int
    expected: bytes
    operations: tuple[Mapping[str, Any], ...]
    label: str = "scene-hook"

    def __post_init__(self) -> None:
        if int(self.patch_offset) < 4:
            raise PortraitEmitterError("场景挂接偏移必须位于 HCB 代码区")
        if not isinstance(self.expected, bytes) or len(self.expected) != 5:
            raise PortraitEmitterError("场景挂接 expected 必须恰好为 5 字节")
        if not self.operations:
            raise PortraitEmitterError("场景挂接 trampoline 不能为空")


_HOOK_OPERATION_KINDS = frozenset(
    {"call_symbol", "call_address", "push", "jmp", "ret"}
)
_LOGICAL_METADATA_PREFIX = "_portrait_"


def _logical_operation_kind(
    operation: Mapping[str, Any], index: int
) -> str:
    if not isinstance(operation, Mapping):
        raise PortraitEmitterError(
            f"立绘逻辑操作 #{index} 必须是 object"
        )
    raw = operation.get("kind", operation.get("op", ""))
    kind = str(raw).strip()
    if not kind:
        raise PortraitEmitterError(f"立绘逻辑操作 #{index} 缺少类型")
    return kind


def _hook_operation_kind(
    operation: Mapping[str, Any], index: int
) -> str:
    if not isinstance(operation, Mapping):
        raise PortraitEmitterError(f"挂接操作 #{index} 必须是 object")
    kind = str(operation.get("op", "")).strip()
    if kind not in _HOOK_OPERATION_KINDS:
        raise PortraitEmitterError(
            f"挂接操作 {index} 类型不受支持: {kind or '<缺失>'}"
        )
    return kind


def _require_nonempty_text(value: Any, label: str) -> str:
    text = str(value).strip()
    if not text:
        raise PortraitEmitterError(f"{label}不能为空")
    return text


def _validate_hook_operation(
    operation: Mapping[str, Any], index: int
) -> str:
    kind = _hook_operation_kind(operation, index)
    if kind == "call_symbol":
        _require_nonempty_text(operation.get("symbol", ""), "挂接函数符号")
    elif kind in {"call_address", "jmp"}:
        try:
            _u32(int(operation["address"]), f"挂接 {kind} 地址")
        except (KeyError, TypeError, ValueError) as exc:
            raise PortraitEmitterError(
                f"挂接操作 {index} 缺少有效 address"
            ) from exc
    elif kind == "push":
        if "value" not in operation:
            raise PortraitEmitterError(f"挂接操作 {index} 缺少 push value")
        value = operation.get("value")
        if not (
            value is None
            or isinstance(value, (bool, int, float, str))
        ):
            raise PortraitEmitterError(
                f"挂接操作 {index} 的 push 值类型不受支持: "
                f"{type(value).__name__}"
            )
    return kind


def _normalise_explicit_operations(
    operations: Iterable[Mapping[str, Any]],
    *,
    label: str,
    allow_terminal: bool = False,
) -> tuple[Mapping[str, Any], ...]:
    result: list[Mapping[str, Any]] = []
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            raise PortraitEmitterError(f"{label} #{index} 必须是 object")
        kind = _validate_hook_operation(operation, index)
        if not allow_terminal and kind in {"jmp", "ret"}:
            raise PortraitEmitterError(
                f"{label} #{index} 不能提前结束 trampoline"
            )
        result.append(dict(operation))
    return tuple(result)


def _profile_symbol(
    plan: HoshimemoPortraitPatchPlan,
    operation: Mapping[str, Any],
    symbol: Any,
    *,
    label: str,
) -> str:
    name = _require_nonempty_text(symbol, label)
    if name not in plan.profile.symbols:
        raise PortraitEmitterError(f"{label}未解析: {name}")
    expected_address = int(plan.profile.symbols[name])
    if operation.get("address") is not None:
        try:
            actual_address = int(operation["address"])
        except (TypeError, ValueError) as exc:
            raise PortraitEmitterError(f"{label} address 无效: {name}") from exc
        if actual_address != expected_address:
            raise PortraitEmitterError(
                f"{label} address 与 profile 不一致: {name}"
            )
    return name


def _sequence_value(
    value: Any,
    *,
    label: str,
) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(
        value, Sequence
    ):
        raise PortraitEmitterError(f"{label} 必须是有序数组")
    return tuple(value)


def _push_call_operations(
    args: Sequence[Any],
    symbol: str,
) -> list[Mapping[str, Any]]:
    return [
        *({"op": "push", "value": value} for value in args),
        {"op": "call_symbol", "symbol": symbol},
    ]


def _lower_static_state_operation(
    plan: HoshimemoPortraitPatchPlan,
    operation: Mapping[str, Any],
    index: int,
) -> list[Mapping[str, Any]]:
    slot_id = _require_nonempty_text(operation.get("slot_id", ""), "立绘槽 ID")
    slot = plan.profile.slot(slot_id)
    if operation.get("mode") != "direct_static_state":
        raise PortraitEmitterError(
            f"逻辑操作 #{index} 必须使用 direct_static_state"
        )
    setter_symbol = _require_nonempty_text(
        operation.get("setter_symbol", ""), "静态 primitive setter 符号"
    )
    if setter_symbol != NATIVE_PRIMITIVE_STATE_SYMBOL:
        raise PortraitEmitterError(
            f"静态 primitive setter 未经核验: {setter_symbol}"
        )
    transform = operation.get("transform")
    if not isinstance(transform, Mapping):
        raise PortraitEmitterError(f"逻辑操作 #{index} 的最终状态缺少 transform")
    try:
        x = int(transform["x"])
        y = int(transform["y"])
        z = int(transform["z"])
        scale = int(transform["scale"])
        rotation_degrees = int(transform["rotation"])
        opacity = int(transform["opacity"])
        rotation_tenths = int(operation["rotation_tenths"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PortraitEmitterError(
            f"逻辑操作 #{index} 的最终状态必须包含整数 "
            "x/y/z/scale/rotation/opacity"
        ) from exc
    if rotation_tenths != rotation_degrees * 10 or not (
        -32768 <= rotation_tenths <= 32767
    ):
        raise PortraitEmitterError("立绘旋转角度无法编码为十分之一度")
    if not 0 <= opacity <= 255:
        raise PortraitEmitterError("立绘透明度必须在 0 到 255 之间")

    calls = _sequence_value(operation.get("calls"), label=f"逻辑操作 #{index} calls")
    expected_calls = [
        (
            primitive_id,
            [
                primitive_id,
                x,
                y,
                z,
                rotation_tenths,
                scale,
                opacity,
            ],
        )
        for primitive_id in slot.primitive_ids
    ]
    if len(calls) != len(expected_calls):
        raise PortraitEmitterError(
            f"逻辑操作 #{index} 的最终状态必须覆盖两个 double buffer"
        )
    lowered: list[Mapping[str, Any]] = []
    for call_index, (call, expected) in enumerate(zip(calls, expected_calls)):
        if not isinstance(call, Mapping):
            raise PortraitEmitterError(
                f"逻辑操作 #{index} static call #{call_index} 必须是 object"
            )
        primitive_id, expected_args = expected
        actual_primitive = call.get("primitive_id")
        try:
            actual_primitive = int(actual_primitive)
        except (TypeError, ValueError) as exc:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} static call #{call_index} primitive 无效"
            ) from exc
        actual_symbol = _require_nonempty_text(
            call.get("symbol", ""), "静态 primitive setter 符号"
        )
        if actual_primitive != primitive_id or actual_symbol != setter_symbol:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} static call #{call_index} 顺序或 setter 不匹配"
            )
        actual_args = call.get("args")
        if not isinstance(actual_args, (list, tuple)) or list(actual_args) != expected_args:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} static call #{call_index} 参数不匹配"
            )
        lowered.extend(_push_call_operations(expected_args, actual_symbol))
    return lowered


def _lower_effect_operation(
    plan: HoshimemoPortraitPatchPlan,
    operation: Mapping[str, Any],
    index: int,
    *,
    effect: str,
) -> list[Mapping[str, Any]]:
    symbol = _profile_symbol(
        plan,
        operation,
        operation.get("symbol", ""),
        label=f"立绘{effect}函数符号",
    )
    slot_id = _require_nonempty_text(operation.get("slot_id", ""), "立绘槽 ID")
    slot = plan.profile.slot(slot_id)
    try:
        duration = int(operation["duration"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PortraitEmitterError(
            f"逻辑操作 #{index} 的立绘{effect}缺少 duration"
        ) from exc
    if duration <= 0:
        raise PortraitEmitterError(f"逻辑操作 #{index} 的立绘{effect}时长必须大于 0")
    if effect == "透明度":
        try:
            effect_value = int(operation["opacity"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} 的透明度无效"
            ) from exc
        if not 0 <= effect_value <= 255:
            raise PortraitEmitterError("立绘透明度必须在 0 到 255 之间")
    else:
        try:
            effect_value = int(operation["rotation_tenths"])
            degrees = int(operation["rotation_degrees"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} 的旋转角度无效"
            ) from exc
        if effect_value != degrees * 10 or not -32768 <= effect_value <= 32767:
            raise PortraitEmitterError("立绘旋转角度无法编码为十分之一度")

    calls = _sequence_value(operation.get("calls"), label=f"逻辑操作 #{index} calls")
    declared_primitive_ids = operation.get("primitive_ids")
    if declared_primitive_ids is not None:
        try:
            declared = tuple(int(item) for item in declared_primitive_ids)
        except (TypeError, ValueError) as exc:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} 的立绘{effect} primitive 声明无效"
            ) from exc
        if declared != slot.primitive_ids:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} 的立绘{effect} primitive 声明不匹配"
            )
    if len(calls) != len(slot.primitive_ids):
        raise PortraitEmitterError(
            f"逻辑操作 #{index} 的立绘{effect}必须覆盖两个 double buffer"
        )
    lowered: list[Mapping[str, Any]] = []
    for call_index, (call, primitive_id) in enumerate(
        zip(calls, slot.primitive_ids)
    ):
        if not isinstance(call, Mapping):
            raise PortraitEmitterError(
                f"逻辑操作 #{index} effect call #{call_index} 必须是 object"
            )
        try:
            actual_primitive = int(call["primitive_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} effect call #{call_index} primitive 无效"
            ) from exc
        if actual_primitive != primitive_id:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} 的立绘{effect} primitive 顺序不匹配"
            )
        if call.get("symbol") is not None and str(call["symbol"]) != symbol:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} 的立绘{effect}函数符号不匹配"
            )
        if effect == "透明度":
            expected_args = [
                primitive_id,
                effect_value,
                effect_value,
                duration,
                None,
                None,
                None,
                None,
            ]
        else:
            expected_args = [
                primitive_id,
                effect_value,
                effect_value,
                duration,
                None,
                None,
                None,
                None,
            ]
        actual_args = call.get("args")
        if not isinstance(actual_args, (list, tuple)) or list(actual_args) != expected_args:
            raise PortraitEmitterError(
                f"逻辑操作 #{index} 的立绘{effect}参数不匹配"
            )
        lowered.extend(_push_call_operations(expected_args, symbol))
    return lowered


def _lower_one_logical_operation(
    plan: HoshimemoPortraitPatchPlan,
    operation: Mapping[str, Any],
    index: int,
) -> tuple[str, list[Mapping[str, Any]]]:
    kind = _logical_operation_kind(operation, index)
    if kind == "call_registration_wrapper":
        symbol = _require_nonempty_text(operation.get("symbol", ""), "包装函数符号")
        if symbol not in {item.symbol for item in plan.wrappers}:
            raise PortraitEmitterError(f"包装函数符号未在计划中定义: {symbol}")
        return kind, [{"op": "call_symbol", "symbol": symbol}]
    if kind == "call_native_layout":
        symbol = _profile_symbol(
            plan,
            operation,
            operation.get("symbol", ""),
            label="布局函数符号",
        )
        if symbol not in plan.profile.native_layout_symbols:
            raise PortraitEmitterError(
                "原生布局 lowering 只允许当前指纹 profile 显式核验的函数"
            )
        duration = operation.get("duration")
        if duration is not None and (
            not isinstance(duration, int) or isinstance(duration, bool)
        ):
            raise PortraitEmitterError("原生布局 duration 必须是整数或 Nil")
        return kind, [
            {"op": "push", "value": duration},
            {"op": "push", "value": None},
            {"op": "push", "value": None},
            {"op": "call_symbol", "symbol": symbol},
        ]
    if kind == "call_final_transform":
        return kind, _lower_static_state_operation(plan, operation, index)
    if kind == "call_portrait_geometry":
        raise PortraitEmitterError(
            "旧版 MotionMove 静态几何计划已停用；请重新编译舞台快照"
        )
    if kind == "call_portrait_opacity":
        return kind, _lower_effect_operation(
            plan, operation, index, effect="透明度"
        )
    if kind == "call_portrait_rotation":
        return kind, _lower_effect_operation(
            plan, operation, index, effect="旋转"
        )
    if kind == "call_expression_update":
        explicit = operation.get("lowering_operations")
        if explicit is None:
            raise PortraitEmitterError(
                "表情更新的 function_4487_ ABI 尚未得到足够实机证据，拒绝静默生成"
            )
        explicit_ops = _normalise_explicit_operations(
            _sequence_value(explicit, label=f"逻辑操作 #{index} lowering_operations"),
            label=f"表情更新逻辑操作 #{index}",
            allow_terminal=False,
        )
        if not explicit_ops:
            raise PortraitEmitterError("表情更新 lowering_operations 不能为空")
        return kind, list(explicit_ops)
    raise PortraitEmitterError(f"不支持的立绘逻辑操作 #{index}: {kind}")


def _terminal_operation(
    *,
    continuation: int | None,
    return_address: int | None,
    return_operation: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    supplied = sum(
        value is not None
        for value in (continuation, return_address, return_operation)
    )
    if supplied != 1:
        raise PortraitEmitterError(
            "必须明确提供一个 return/continuation：continuation、return_address "
            "或 return_operation"
        )
    if continuation is not None and return_address is not None:
        raise PortraitEmitterError("continuation 与 return_address 不能同时提供")
    if continuation is not None:
        try:
            value = int(continuation)
        except (TypeError, ValueError) as exc:
            raise PortraitEmitterError("trampoline continuation 必须是整数") from exc
        _u32(value, "trampoline continuation")
        return {"op": "jmp", "address": value}
    if return_address is not None:
        try:
            value = int(return_address)
        except (TypeError, ValueError) as exc:
            raise PortraitEmitterError("trampoline return address 必须是整数") from exc
        _u32(value, "trampoline return address")
        return {"op": "jmp", "address": value}
    assert return_operation is not None
    operation = dict(return_operation)
    kind = _validate_hook_operation(operation, 0)
    if kind not in {"jmp", "ret"}:
        raise PortraitEmitterError("return_operation 必须是明确的 jmp 或 ret")
    return operation


def _lower_portrait_script_operations_with_metadata(
    plan: HoshimemoPortraitPatchPlan,
    *,
    prefix_operations: Iterable[Mapping[str, Any]] = (),
    suffix_operations: Iterable[Mapping[str, Any]] = (),
    continuation: int | None = None,
    return_address: int | None = None,
    return_operation: Mapping[str, Any] | None = None,
) -> tuple[Mapping[str, Any], ...]:
    """Lower every logical plan operation to executable HCB hook operations.

    This private form adds per-logical-operation metadata for attestation.
    """

    prefix = _normalise_explicit_operations(
        prefix_operations, label="trampoline 前缀", allow_terminal=False
    )
    suffix = _normalise_explicit_operations(
        suffix_operations, label="trampoline 后缀", allow_terminal=False
    )
    lowered: list[Mapping[str, Any]] = list(prefix)
    for index, operation in enumerate(plan.script_operations):
        kind, operations = _lower_one_logical_operation(plan, operation, index)
        for order, item in enumerate(operations):
            if not isinstance(item, Mapping):
                raise PortraitEmitterError(
                    f"逻辑操作 #{index} 的 lowering 结果必须是 object"
                )
            _validate_hook_operation(item, order)
            tagged = dict(item)
            tagged[f"{_LOGICAL_METADATA_PREFIX}logical_index"] = index
            tagged[f"{_LOGICAL_METADATA_PREFIX}logical_kind"] = kind
            tagged[f"{_LOGICAL_METADATA_PREFIX}logical_order"] = order
            lowered.append(tagged)
    lowered.extend(suffix)
    if any(
        value is not None
        for value in (continuation, return_address, return_operation)
    ):
        lowered.append(
            _terminal_operation(
                continuation=continuation,
                return_address=return_address,
                return_operation=return_operation,
            )
        )
    return tuple(lowered)


def lower_portrait_script_operations(
    plan: HoshimemoPortraitPatchPlan,
    *,
    prefix_operations: Iterable[Mapping[str, Any]] = (),
    suffix_operations: Iterable[Mapping[str, Any]] = (),
    continuation: int | None = None,
    return_address: int | None = None,
    return_operation: Mapping[str, Any] | None = None,
) -> tuple[Mapping[str, Any], ...]:
    """Return clean executable ``SceneHookSpec`` operations for every plan op.

    No story offset or continuation is inferred.  Supplying one of the
    explicit termination arguments appends it; otherwise the caller receives
    the non-terminating lowered stream for inspection or for composition with
    an explicitly terminated hook.
    """

    tagged = _lower_portrait_script_operations_with_metadata(
        plan,
        prefix_operations=prefix_operations,
        suffix_operations=suffix_operations,
        continuation=continuation,
        return_address=return_address,
        return_operation=return_operation,
    )
    return tuple(_without_lowering_metadata(item) for item in tagged)


def build_portrait_scene_hook(
    plan: HoshimemoPortraitPatchPlan,
    *,
    patch_offset: int,
    expected: bytes,
    continuation: int | None = None,
    return_address: int | None = None,
    return_operation: Mapping[str, Any] | None = None,
    prefix_operations: Iterable[Mapping[str, Any]] = (),
    suffix_operations: Iterable[Mapping[str, Any]] = (),
    label: str = "portrait-scene-hook",
) -> SceneHookSpec:
    """Build an installable hook only from explicit patch and return data."""

    operations = lower_portrait_script_operations(
        plan,
        prefix_operations=prefix_operations,
        suffix_operations=suffix_operations,
    )
    operations = (
        *operations,
        _terminal_operation(
            continuation=continuation,
            return_address=return_address,
            return_operation=return_operation,
        ),
    )
    return SceneHookSpec(
        patch_offset=patch_offset,
        expected=expected,
        operations=tuple(operations),
        label=label,
    )


# Descriptive aliases for callers that name this boundary "lowering to a
# hook" rather than "building a hook".  They intentionally share one strict
# implementation and therefore cannot drift in their safety checks.
lower_portrait_plan_to_scene_hook = build_portrait_scene_hook
lower_portrait_plan_to_hook = build_portrait_scene_hook
make_portrait_scene_hook = build_portrait_scene_hook


@dataclass(frozen=True)
class PortraitScriptProgram:
    """One non-terminating portrait program ready for trampoline composition."""

    data: bytes
    validation: Mapping[str, Any]


@dataclass(frozen=True)
class CandidateBuildResult:
    hcb: bytes
    graph_bs: bytes
    symbols: Mapping[str, int]
    validation: Mapping[str, Any]
    install_ready: bool

    def to_validated_outputs(
        self, plan: HoshimemoPortraitPatchPlan
    ) -> "ValidatedPortraitOutputs":
        """Cross the install boundary only for an explicitly hooked build."""

        if not self.install_ready:
            raise PortraitEmitterError(
                "候选仅含资源/函数库，尚未提供经过校验的场景挂接点，禁止安装"
            )
        from .hoshimemo_portrait_transaction import (  # avoid import cycle
            ValidatedPortraitOutputs,
            patch_plan_sha256,
        )

        return ValidatedPortraitOutputs(
            hcb=self.hcb,
            graph_bs=self.graph_bs,
            plan_sha256=patch_plan_sha256(plan),
            emitter_id=PORTRAIT_EMITTER_ID,
            validation=self.validation,
        )


def _instructions_in_region(
    instructions: Iterable[Instruction], start: int, end: int
) -> tuple[Instruction, ...]:
    selected = tuple(item for item in instructions if start <= item.offset < end)
    if not selected or selected[0].offset != start:
        raise PortraitEmitterError("私有分派器起点不是可解析指令边界")
    cursor = start
    for item in selected:
        if item.offset != cursor:
            raise PortraitEmitterError(
                f"私有分派器在 0x{cursor:X} 到 0x{item.offset:X} 间存在解析缺口"
            )
        if not item.known or item.warning:
            raise PortraitEmitterError(
                f"私有分派器含未知/警告指令: 0x{item.offset:X}"
            )
        cursor += item.size
    if cursor != end:
        raise PortraitEmitterError(
            f"私有分派器结尾不是指令边界: 0x{cursor:X} != 0x{end:X}"
        )
    return selected


def _literal_payload(raw: bytes) -> bytes:
    if len(raw) < 3 or raw[0] != 0x0E or raw[1] != len(raw) - 2:
        raise PortraitEmitterError("目标指令不是有效 push_string")
    return raw[2:]


def _clone_dispatcher(
    source_hcb: bytes,
    instructions: tuple[Instruction, ...],
    source_start: int,
    source_end: int,
    clone_start: int,
    plan: DispatcherClonePlan,
    *,
    resource_encoding: str,
    expected_args: int,
    expected_locals: int,
) -> tuple[bytes, Mapping[str, Any]]:
    if instructions[0].opcode != 0x01:
        raise PortraitEmitterError("私有分派器第一条指令不是 init_stack")
    if instructions[0].operands != {
        "args": expected_args,
        "locals": expected_locals,
    }:
        raise PortraitEmitterError(
            "私有分派器 init_stack ABI 不匹配: "
            f"{instructions[0].operands!r}"
        )
    if instructions[-1].opcode != 0x04:
        raise PortraitEmitterError("私有分派器最后一条指令不是 ret")

    patches: dict[int, Mapping[str, Any]] = {}
    for patch in plan.resolved_literal_patches:
        offset = int(patch["source_offset"])
        if offset in patches:
            raise PortraitEmitterError(f"重复字符串补丁偏移: 0x{offset:X}")
        patches[offset] = patch

    first_pass: list[bytes] = []
    mapping: dict[int, int] = {}
    cursor = clone_start
    for item in instructions:
        mapping[item.offset] = cursor
        replacement = patches.get(item.offset)
        if replacement is None:
            encoded = item.raw
        else:
            if item.opcode != 0x0E:
                raise PortraitEmitterError(
                    f"字符串补丁 0x{item.offset:X} 未指向 push_string"
                )
            try:
                expected = str(replacement["expected"]).encode(resource_encoding) + b"\0"
            except UnicodeEncodeError as exc:
                raise PortraitEmitterError(
                    f"预期资源字面量不能编码为 {resource_encoding}"
                ) from exc
            actual = _literal_payload(item.raw)
            if actual != expected:
                raise PortraitEmitterError(
                    f"字符串补丁 0x{item.offset:X} 原值不匹配: "
                    f"预期 {expected!r}, 实际 {actual!r}"
                )
            encoded = _encode_string(str(replacement["replacement"]), resource_encoding)
        first_pass.append(encoded)
        cursor += len(encoded)

    unused = sorted(set(patches) - {item.offset for item in instructions})
    if unused:
        raise PortraitEmitterError(
            "字符串补丁未命中源函数: " + ", ".join(f"0x{x:X}" for x in unused)
        )

    output = bytearray()
    branch_count = 0
    for item, encoded in zip(instructions, first_pass):
        if item.opcode in (0x06, 0x07):
            target = int(item.operands["target"])
            if not source_start <= target < source_end or target not in mapping:
                raise PortraitEmitterError(
                    f"私有分派器跳转离开克隆范围: 0x{item.offset:X} -> 0x{target:X}"
                )
            output.extend(
                _encode_jmp(mapping[target])
                if item.opcode == 0x06
                else _encode_jz(mapping[target])
            )
            branch_count += 1
        elif item.opcode == 0x02:
            target = int(item.operands["target"])
            if source_start <= target < source_end:
                raise PortraitEmitterError(
                    f"私有分派器含内部 CALL，不能安全克隆: 0x{item.offset:X}"
                )
            output.extend(encoded)
        else:
            output.extend(encoded)

    return bytes(output), {
        "slot_id": plan.slot_id,
        "symbol": plan.output_symbol,
        "source_range": [source_start, source_end],
        "output_range": [clone_start, clone_start + len(output)],
        "sha256": _sha256(bytes(output)),
        "relocated_branch_count": branch_count,
        "literal_patch_count": len(patches),
    }


def _emit_wrapper(
    wrapper: RegistrationWrapperPlan,
    symbols: Mapping[str, int],
    *,
    resource_encoding: str,
) -> bytes:
    try:
        dispatcher = int(symbols[wrapper.dispatcher_symbol])
    except KeyError as exc:
        raise PortraitEmitterError(
            f"包装函数 {wrapper.symbol} 引用了未解析符号 {wrapper.dispatcher_symbol}"
        ) from exc
    values = wrapper.resource_args + wrapper.runtime_args
    if len(values) != wrapper.expected_argument_count:
        raise PortraitEmitterError(
            f"包装函数 {wrapper.symbol} 参数数与目标 dispatcher 不一致"
        )
    return (
        _encode_init(0, 0)
        + b"".join(_encode_push(value, resource_encoding) for value in values)
        + _encode_call(dispatcher)
        + b"\x04"
    )


def _require_named_syscall(
    document: Any,
    name: str,
    args: int,
) -> int:
    matches = [
        (index, item)
        for index, item in enumerate(document.header.syscalls)
        if item.name == name
    ]
    if len(matches) != 1:
        raise PortraitEmitterError(
            f"目标 HCB 的 syscall {name} 不是唯一匹配: {len(matches)}"
        )
    syscall_id, syscall = matches[0]
    if int(syscall.args) != int(args):
        raise PortraitEmitterError(
            f"目标 HCB 的 syscall {name} 参数数不匹配: "
            f"预期 {args}, 实际 {syscall.args}"
        )
    return int(syscall_id)


def _emit_native_primitive_state_helper(
    plan: HoshimemoPortraitPatchPlan,
    document: Any,
) -> tuple[bytes, Mapping[str, Any]]:
    """Emit the audited direct static-state path used by function_4477_.

    ABI: ``(primitive, x, y, z, rotation_tenths, scale, opacity)``.
    The helper deliberately contains no MotionMove* syscall.  A target profile
    either proves an original coordinate converter (modern FVP) or proves that
    static coordinates are accepted directly by ``PrimSetXY`` (legacy FVP).
    Both paths then use the same direct primitive setters as registration.
    """

    xy_mode = plan.profile.static_xy_mode
    xy_setter: int | None = None
    prim_set_xy: int | None = None
    if xy_mode == "function_4286":
        try:
            xy_setter = int(plan.profile.symbols["function_4286_"])
        except KeyError as exc:
            raise PortraitEmitterError(
                "目标 profile 缺少已核验的 function_4286_ 直接 XY setter"
            ) from exc
        instruction_by_offset = {
            int(item.offset): item for item in document.instructions
        }
        entry = instruction_by_offset.get(xy_setter)
        if (
            entry is None
            or entry.opcode != 0x01
            or dict(entry.operands) != {"args": 3, "locals": 2}
        ):
            raise PortraitEmitterError(
                "function_4286_ 地址不是已核验的 init_stack 3/2 函数入口"
            )
    elif xy_mode == "primsetxy_syscall":
        prim_set_xy = _require_named_syscall(document, "PrimSetXY", 3)
    else:  # profile validation should make this unreachable
        raise PortraitEmitterError(f"不支持的静态 XY 模式: {xy_mode}")

    prim_set_alpha = _require_named_syscall(document, "PrimSetAlpha", 2)
    prim_set_z = _require_named_syscall(document, "PrimSetZ", 2)
    prim_set_rs = _require_named_syscall(document, "PrimSetRS", 3)

    # init_stack args=7 => argument indexes -8 .. -2.
    encoded = bytearray(_encode_init(7, 0))
    encoded.extend(_encode_push_stack(-8))  # primitive
    encoded.extend(_encode_push_stack(-7))  # x
    encoded.extend(_encode_push_stack(-6))  # y
    if xy_setter is not None:
        encoded.extend(_encode_call(xy_setter))
    else:
        assert prim_set_xy is not None
        encoded.extend(_encode_syscall(prim_set_xy))
    encoded.extend(_encode_push_stack(-8))  # primitive
    encoded.extend(_encode_push_stack(-2))  # opacity
    encoded.extend(_encode_syscall(prim_set_alpha))
    encoded.extend(_encode_push_stack(-8))  # primitive
    encoded.extend(_encode_push_stack(-5))  # z
    encoded.extend(_encode_syscall(prim_set_z))
    encoded.extend(_encode_push_stack(-8))  # primitive
    encoded.extend(_encode_push_stack(-4))  # rotation_tenths
    encoded.extend(_encode_push_stack(-3))  # scale
    encoded.extend(_encode_syscall(prim_set_rs))
    encoded.append(0x04)
    data = bytes(encoded)
    syscall_report = {
        "PrimSetAlpha": prim_set_alpha,
        "PrimSetZ": prim_set_z,
        "PrimSetRS": prim_set_rs,
    }
    if prim_set_xy is not None:
        syscall_report["PrimSetXY"] = prim_set_xy
    return data, {
        "symbol": NATIVE_PRIMITIVE_STATE_SYMBOL,
        "argument_count": 7,
        "xy_mode": xy_mode,
        "function_4286_address": xy_setter,
        "syscalls": syscall_report,
        "uses_motion_channel": False,
        "sha256": _sha256(data),
    }


def _encode_hook_operation(
    operation: Mapping[str, Any],
    symbols: Mapping[str, int],
    *,
    resource_encoding: str,
    index: int,
) -> bytes:
    kind = _validate_hook_operation(operation, index)
    if kind == "call_symbol":
        symbol = str(operation["symbol"]).strip()
        if symbol not in symbols:
            raise PortraitEmitterError(
                f"挂接操作 {index} 引用了未解析符号 {symbol!r}"
            )
        return _encode_call(symbols[symbol])
    if kind == "call_address":
        return _encode_call(int(operation["address"]))
    if kind == "push":
        return _encode_push(operation.get("value"), resource_encoding)
    if kind == "jmp":
        return _encode_jmp(int(operation["address"]))
    return b"\x04"


def _without_lowering_metadata(
    operation: Mapping[str, Any],
) -> Mapping[str, Any]:
    return {
        str(key): value
        for key, value in operation.items()
        if not str(key).startswith(_LOGICAL_METADATA_PREFIX)
    }


def _hook_operation_semantics(operation: Mapping[str, Any]) -> str:
    return json.dumps(
        _without_lowering_metadata(operation),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _emit_operations_with_reports(
    operations: Sequence[Mapping[str, Any]],
    symbols: Mapping[str, int],
    *,
    resource_encoding: str,
) -> tuple[bytes, tuple[Mapping[str, Any], ...]]:
    output = bytearray()
    reports: list[Mapping[str, Any]] = []
    for index, operation in enumerate(operations):
        start = len(output)
        encoded = _encode_hook_operation(
            operation,
            symbols,
            resource_encoding=resource_encoding,
            index=index,
        )
        output.extend(encoded)
        report: dict[str, Any] = {
            "index": index,
            "op": _hook_operation_kind(operation, index),
            "byte_range": [start, len(output)],
            "sha256": _sha256(encoded),
        }
        for key in (
            f"{_LOGICAL_METADATA_PREFIX}logical_index",
            f"{_LOGICAL_METADATA_PREFIX}logical_kind",
            f"{_LOGICAL_METADATA_PREFIX}logical_order",
        ):
            if key in operation:
                report[key.removeprefix(_LOGICAL_METADATA_PREFIX)] = operation[key]
        reports.append(report)
    return bytes(output), tuple(reports)


def _emit_hook_program_with_reports(
    hook: SceneHookSpec,
    symbols: Mapping[str, int],
    *,
    resource_encoding: str,
) -> tuple[bytes, tuple[Mapping[str, Any], ...]]:
    operations = tuple(hook.operations)
    if not operations:
        raise PortraitEmitterError("挂接 trampoline 不能为空")
    for index, operation in enumerate(operations):
        _validate_hook_operation(operation, index)
        if index < len(operations) - 1 and _hook_operation_kind(operation, index) in {
            "jmp",
            "ret",
        }:
            raise PortraitEmitterError(
                f"挂接操作 {index} 提前结束 trampoline"
            )
    if _hook_operation_kind(operations[-1], len(operations) - 1) not in {
        "jmp",
        "ret",
    }:
        raise PortraitEmitterError("挂接 trampoline 必须以 jmp 或 ret 明确结束")
    return _emit_operations_with_reports(
        operations,
        symbols,
        resource_encoding=resource_encoding,
    )


def _emit_hook_program(
    hook: SceneHookSpec,
    symbols: Mapping[str, int],
    *,
    resource_encoding: str,
) -> bytes:
    """Compatibility wrapper for callers that only need trampoline bytes."""

    encoded, _reports = _emit_hook_program_with_reports(
        hook,
        symbols,
        resource_encoding=resource_encoding,
    )
    return encoded


def _validate_resource_payloads(
    plan: HoshimemoPortraitPatchPlan,
    payloads: Mapping[str, bytes],
) -> Mapping[str, bytes]:
    expected: dict[str, int] = {}
    for resource in plan.resources:
        if (
            resource.target_archive.casefold()
            != plan.profile.portrait_archive_name.casefold()
        ):
            raise PortraitEmitterError(
                "资源计划归档与目标 profile 不一致: "
                f"{resource.target_archive} != "
                f"{plan.profile.portrait_archive_name}"
            )
        for name, kind in (
            (resource.target_body_name, 1),
            (resource.target_face_name, 2),
        ):
            if name in expected:
                raise PortraitEmitterError(f"补丁计划重复定义资源: {name}")
            expected[name] = kind
    actual_names = set(payloads)
    if actual_names != set(expected):
        missing = sorted(set(expected) - actual_names)
        extra = sorted(actual_names - set(expected))
        raise PortraitEmitterError(
            f"资源负载与计划不一致; 缺少={missing}, 多余={extra}"
        )
    result: dict[str, bytes] = {}
    for name in sorted(expected):
        payload = payloads[name]
        if not isinstance(payload, bytes) or not payload:
            raise PortraitEmitterError(f"资源 {name} 必须是非空 bytes")
        metadata = hzc_metadata(payload)
        if metadata.kind != expected[name]:
            layer = "身体" if expected[name] == 1 else "表情"
            raise PortraitEmitterError(
                f"资源 {name} 不是预期的{layer} HZC(kind={expected[name]})"
            )
        result[name] = payload
    return result


def _zero_addition_graph_validation(
    base_graph_bs: bytes,
) -> Mapping[str, Any]:
    """Describe a graph candidate that intentionally received no entries."""

    return {
        "zero_addition": True,
        "data_unchanged": True,
        "added": [],
        "added_bytes": 0,
        "sha256": _sha256(base_graph_bs),
    }


def _validate_base_hcb_prefix(
    base_hcb: bytes,
    candidate_hcb: bytes,
    hook: SceneHookSpec | None,
) -> Mapping[str, Any]:
    """Prove that appending did not rewrite the supplied HCB base prefix."""

    prefix = candidate_hcb[: len(base_hcb)]
    if len(prefix) != len(base_hcb):
        raise PortraitEmitterError("生成结果短于 base HCB，无法验证前缀保真")

    if hook is None:
        if prefix != base_hcb:
            raise PortraitEmitterError("生成器意外改变了整个 base HCB 前缀")
        return {
            "byte_count": len(base_hcb),
            "base_sha256": _sha256(base_hcb),
            "candidate_sha256": _sha256(prefix),
            "unchanged": True,
            "unchanged_outside_registered_window": True,
            "registered_window": None,
        }

    start = int(hook.patch_offset)
    end = start + len(hook.expected)
    if start < 0 or end > len(base_hcb):
        raise PortraitEmitterError("场景挂接必须完整位于 base HCB 前缀内")
    if prefix[:start] != base_hcb[:start] or prefix[end:] != base_hcb[end:]:
        raise PortraitEmitterError(
            "生成器意外改变了登记挂接窗口之外的 base HCB 字节"
        )
    return {
        "byte_count": len(base_hcb),
        "base_sha256": _sha256(base_hcb),
        "candidate_sha256": _sha256(prefix),
        "unchanged": prefix == base_hcb,
        "unchanged_outside_registered_window": True,
        "registered_window": {
            "start": start,
            "end": end,
            "base_sha256": _sha256(base_hcb[start:end]),
            "candidate_sha256": _sha256(prefix[start:end]),
        },
    }


def _find_contiguous_operation_match(
    expected: Sequence[Mapping[str, Any]],
    actual: Sequence[Mapping[str, Any]],
) -> int | None:
    if not expected:
        return 0
    if len(expected) > len(actual):
        return None
    expected_semantics = tuple(
        _hook_operation_semantics(item) for item in expected
    )
    for start in range(len(actual) - len(expected) + 1):
        actual_semantics = tuple(
            _hook_operation_semantics(actual[start + index])
            for index in range(len(expected))
        )
        if actual_semantics == expected_semantics:
            return start
    return None


def _logical_script_validation(
    lowered: Sequence[Mapping[str, Any]],
    lowered_bytes: bytes,
    lowered_reports: Sequence[Mapping[str, Any]],
    *,
    installed_in_scene_hook: bool,
    byte_base: str,
) -> Mapping[str, Any]:
    groups: dict[int, list[int]] = {}
    kinds: dict[int, str] = {}
    for index, operation in enumerate(lowered):
        logical_index = operation.get(f"{_LOGICAL_METADATA_PREFIX}logical_index")
        if logical_index is None:
            continue
        logical_index = int(logical_index)
        groups.setdefault(logical_index, []).append(index)
        kinds[logical_index] = str(
            operation.get(f"{_LOGICAL_METADATA_PREFIX}logical_kind", "")
        )
    logical_operations: list[Mapping[str, Any]] = []
    for logical_index in sorted(groups):
        operation_indices = groups[logical_index]
        reports = [lowered_reports[index] for index in operation_indices]
        start = int(reports[0]["byte_range"][0])
        end = int(reports[-1]["byte_range"][1])
        logical_operations.append(
            {
                "index": logical_index,
                "kind": kinds[logical_index],
                "lowered_operation_count": len(reports),
                "lowered_operation_types": [
                    str(report["op"]) for report in reports
                ],
                "byte_range": [start, end],
                "sha256": _sha256(lowered_bytes[start:end]),
                "operation_ranges": [
                    {
                        "op": report["op"],
                        "byte_range": list(report["byte_range"]),
                        "sha256": report["sha256"],
                    }
                    for report in reports
                ],
            }
        )
    logical_operations.sort(key=lambda item: int(item["index"]))
    return {
        "passed": True,
        "installed_in_scene_hook": installed_in_scene_hook,
        "byte_base": byte_base,
        "count": len(logical_operations),
        "lowered_operation_count": len(lowered),
        "lowered_operation_types": [
            str(report["op"]) for report in lowered_reports
        ],
        "byte_range": [0, len(lowered_bytes)],
        "sha256": _sha256(lowered_bytes),
        "operations": logical_operations,
    }


def emit_portrait_script_program(
    plan: HoshimemoPortraitPatchPlan,
    symbols: Mapping[str, int],
    *,
    resource_encoding: str = "shift_jis",
    byte_base: str = "unified_scene_trampoline",
) -> PortraitScriptProgram:
    """Encode the complete portrait stream without adding ``ret`` or ``jmp``.

    Generated dispatcher clones and wrappers are regular HCB functions, but a
    story trampoline is not.  Unified scene builders therefore compose these
    bytes inline and own the single final continuation themselves.
    """

    lowered = _lower_portrait_script_operations_with_metadata(plan)
    if not lowered:
        raise PortraitEmitterError("立绘计划没有可组合的脚本操作")
    for index, operation in enumerate(lowered):
        if _hook_operation_kind(operation, index) in {"jmp", "ret"}:
            raise PortraitEmitterError("可组合立绘程序不能自行结束控制流")
    data, reports = _emit_operations_with_reports(
        lowered,
        symbols,
        resource_encoding=resource_encoding,
    )
    validation = _logical_script_validation(
        lowered,
        data,
        reports,
        installed_in_scene_hook=True,
        byte_base=byte_base,
    )
    return PortraitScriptProgram(data=data, validation=validation)


def emit_portrait_candidates(
    plan: HoshimemoPortraitPatchPlan,
    source_hcb: bytes,
    source_graph_bs: bytes,
    resource_payloads: Mapping[str, bytes],
    *,
    hcb_encoding: str = "gbk",
    resource_encoding: str = "shift_jis",
    hook: SceneHookSpec | None = None,
    base_hcb: bytes | None = None,
    base_graph_bs: bytes | None = None,
) -> CandidateBuildResult:
    """Emit deterministic candidate bytes without writing any filesystem path.

    ``source_hcb`` and ``source_graph_bs`` remain the profiled preflight
    baseline.  Optional bases are only the byte streams receiving this call's
    append-only output, which lets multiple emitters compose without
    re-validating an already-appended candidate as the original target.
    """

    base_hcb = source_hcb if base_hcb is None else base_hcb
    base_graph_bs = (
        source_graph_bs if base_graph_bs is None else base_graph_bs
    )
    preflight = preflight_target(plan.profile, source_hcb, source_graph_bs)
    if not isinstance(base_hcb, bytes):
        raise PortraitEmitterError("base_hcb 必须是 bytes")
    if not isinstance(base_graph_bs, bytes):
        raise PortraitEmitterError("base_graph_bs 必须是 bytes")
    additions = _validate_resource_payloads(plan, resource_payloads)
    if additions:
        graph_result = append_hzc_entries(base_graph_bs, additions)
        graph_data = graph_result.data
        graph_validation = graph_result.validation_dict()
    else:
        graph_data = base_graph_bs
        graph_validation = _zero_addition_graph_validation(base_graph_bs)

    document = parse_bytes(source_hcb, hcb_encoding)
    region = plan.profile.portrait_dispatcher
    source_symbol = None
    for clone in plan.dispatcher_clones:
        address = plan.profile.symbols.get(clone.source_symbol)
        if address != region.start:
            raise PortraitEmitterError(
                f"克隆源符号 {clone.source_symbol} 未精确指向函数指纹起点"
            )
        source_symbol = clone.source_symbol
    source_instructions = _instructions_in_region(
        document.instructions, region.start, region.end
    )

    output = bytearray(base_hcb)
    symbols: dict[str, int] = dict(plan.profile.symbols)
    emitted_symbols: set[str] = set()
    clone_reports: list[Mapping[str, Any]] = []
    for clone in plan.dispatcher_clones:
        if clone.output_symbol in symbols or clone.output_symbol in emitted_symbols:
            raise PortraitEmitterError(f"重复/覆盖函数符号: {clone.output_symbol}")
        start = len(output)
        encoded, report = _clone_dispatcher(
            source_hcb,
            source_instructions,
            region.start,
            region.end,
            start,
            clone,
            resource_encoding=resource_encoding,
            expected_args=region.args,
            expected_locals=region.locals,
        )
        output.extend(encoded)
        symbols[clone.output_symbol] = start
        emitted_symbols.add(clone.output_symbol)
        clone_reports.append(report)

    static_state_helper_report: Mapping[str, Any] | None = None
    needs_static_state_helper = any(
        _logical_operation_kind(operation, index) == "call_final_transform"
        for index, operation in enumerate(plan.script_operations)
    )
    if needs_static_state_helper:
        if (
            NATIVE_PRIMITIVE_STATE_SYMBOL in symbols
            or NATIVE_PRIMITIVE_STATE_SYMBOL in emitted_symbols
        ):
            raise PortraitEmitterError(
                f"重复/覆盖函数符号: {NATIVE_PRIMITIVE_STATE_SYMBOL}"
            )
        start = len(output)
        encoded, helper_report = _emit_native_primitive_state_helper(
            plan, document
        )
        output.extend(encoded)
        symbols[NATIVE_PRIMITIVE_STATE_SYMBOL] = start
        emitted_symbols.add(NATIVE_PRIMITIVE_STATE_SYMBOL)
        static_state_helper_report = {
            **dict(helper_report),
            "range": [start, start + len(encoded)],
        }

    wrapper_reports: list[Mapping[str, Any]] = []
    for wrapper in plan.wrappers:
        if wrapper.symbol in symbols or wrapper.symbol in emitted_symbols:
            raise PortraitEmitterError(f"重复/覆盖函数符号: {wrapper.symbol}")
        start = len(output)
        encoded = _emit_wrapper(
            wrapper, symbols, resource_encoding=resource_encoding
        )
        output.extend(encoded)
        symbols[wrapper.symbol] = start
        emitted_symbols.add(wrapper.symbol)
        wrapper_reports.append(
            {
                "symbol": wrapper.symbol,
                "dispatcher_symbol": wrapper.dispatcher_symbol,
                "range": [start, start + len(encoded)],
                "argument_count": wrapper.expected_argument_count,
                "sha256": _sha256(encoded),
            }
        )

    # Lower the complete logical stream after generated clone/wrapper symbols
    # exist.  This virtual emission is also performed for an unhooked library,
    # so an audit can prove the plan is executable without pretending that a
    # story offset was guessed or installed.
    lowered_script = _lower_portrait_script_operations_with_metadata(plan)
    lowered_script_bytes, lowered_script_reports = _emit_operations_with_reports(
        lowered_script,
        symbols,
        resource_encoding=resource_encoding,
    )
    script_lowering = _logical_script_validation(
        lowered_script,
        lowered_script_bytes,
        lowered_script_reports,
        installed_in_scene_hook=hook is not None,
        byte_base="logical_lowering",
    )

    hook_report: Mapping[str, Any] | None = None
    logical_script_validation: Mapping[str, Any] = script_lowering
    if hook is not None:
        if hook.patch_offset < 4:
            raise PortraitEmitterError("场景挂接不能覆盖 HCB 文件头")
        end = hook.patch_offset + len(hook.expected)
        if end > document.header.sysdesc_offset:
            raise PortraitEmitterError(
                "场景挂接必须完整位于 HCB 代码区内"
            )
        if hook.patch_offset < region.end and end > region.start:
            raise PortraitEmitterError("场景挂接不能覆盖私有分派器源函数")
        if end > len(base_hcb):
            raise PortraitEmitterError("场景挂接必须完整位于 base HCB 前缀内")
        actual = base_hcb[hook.patch_offset:end]
        if actual != hook.expected:
            raise PortraitEmitterError(
                f"场景挂接原字节不匹配 @0x{hook.patch_offset:X}: "
                f"预期 {hook.expected.hex(' ')}, 实际 {actual.hex(' ')}"
            )
        trampoline_start = len(output)
        trampoline, trampoline_operation_reports = _emit_hook_program_with_reports(
            hook, symbols, resource_encoding=resource_encoding
        )
        match_start = _find_contiguous_operation_match(
            lowered_script,
            hook.operations,
        )
        if match_start is None:
            raise PortraitEmitterError(
                "场景 trampoline 未按原顺序包含全部立绘逻辑操作"
            )
        match_end = match_start + len(lowered_script)
        matched_lowered: list[Mapping[str, Any]] = []
        for expected_operation, actual_operation in zip(
            lowered_script,
            hook.operations[match_start:match_end],
        ):
            tagged = dict(actual_operation)
            for key in (
                f"{_LOGICAL_METADATA_PREFIX}logical_index",
                f"{_LOGICAL_METADATA_PREFIX}logical_kind",
                f"{_LOGICAL_METADATA_PREFIX}logical_order",
            ):
                if key in expected_operation:
                    tagged[key] = expected_operation[key]
            matched_lowered.append(tagged)
        matched_reports = trampoline_operation_reports[match_start:match_end]
        logical_script_validation = _logical_script_validation(
            matched_lowered,
            trampoline,
            matched_reports,
            installed_in_scene_hook=True,
            byte_base="scene_hook_trampoline",
        )
        output.extend(trampoline)
        output[hook.patch_offset:end] = _encode_jmp(trampoline_start)
        hook_report = {
            "label": hook.label,
            "patch_offset": hook.patch_offset,
            "expected_hex": hook.expected.hex(" "),
            "patched_hex": bytes(output[hook.patch_offset:end]).hex(" "),
            "trampoline_range": [
                trampoline_start,
                trampoline_start + len(trampoline),
            ],
            "sha256": _sha256(trampoline),
            "operation_count": len(hook.operations),
            "logical_operation_start": match_start,
            "logical_operation_end": match_end,
            "logical_operations": list(
                logical_script_validation["operations"]
            ),
        }

    candidate_hcb = bytes(output)
    base_prefix_validation = _validate_base_hcb_prefix(
        base_hcb, candidate_hcb, hook
    )

    install_ready = hook is not None
    validation = {
        "passed": True,
        "install_ready": install_ready,
        "emitter_id": PORTRAIT_EMITTER_ID,
        "preflight": preflight.to_dict(),
        "source": {
            "hcb_sha256": _sha256(source_hcb),
            "graph_bs_sha256": _sha256(source_graph_bs),
        },
        "base": {
            "hcb_sha256": _sha256(base_hcb),
            "graph_bs_sha256": _sha256(base_graph_bs),
        },
        "output": {
            "hcb_sha256": _sha256(candidate_hcb),
            "graph_bs_sha256": _sha256(graph_data),
            "hcb_appended_bytes": len(candidate_hcb) - len(base_hcb),
        },
        "graph_bs": graph_validation,
        "base_hcb_prefix": base_prefix_validation,
        "dispatcher_source_symbol": source_symbol,
        "dispatcher_clones": clone_reports,
        "static_state_helper": static_state_helper_report,
        "wrappers": wrapper_reports,
        "scene_hook": hook_report,
        "script_lowering": script_lowering,
        "logical_script_operations": logical_script_validation,
    }
    # Ensure the attestation itself is deterministic and JSON-safe before it
    # reaches the transaction module.
    json.dumps(validation, ensure_ascii=False, sort_keys=True)
    return CandidateBuildResult(
        hcb=candidate_hcb,
        graph_bs=graph_data,
        symbols=dict(sorted(symbols.items())),
        validation=validation,
        install_ready=install_ready,
    )
