"""Exact-byte portrait profile extraction for one isolated FVP acceptance.

This module is intentionally narrower than the long-term trusted target
registry.  It derives one active native portrait selector from the selected
story anchor, proves its 4+8 / 4+9 wrapper, resource-name branch, primitive pair,
coordinate converter, V3D camera, resolution table and clear/apply lifecycle,
then returns an in-memory compile target.  No game name or filesystem path
selects an ABI and no function here writes a file.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import math
from typing import Any, Iterable, Mapping, Sequence

from .bin_archive import (
    BinArchiveError,
    HzcMetadata,
    infer_archive_hzc_alpha_storage,
)
from .hcb import HcbDocument, HcbError, Instruction
from .hoshimemo_portrait_backend import (
    BinaryFingerprint,
    CodeRegionFingerprint,
    HoshimemoPortraitSlot,
    HoshimemoTargetProfile,
    LiteralPatchTemplate,
    PrivateDispatcherRecipe,
)
from .hoshimemo_stage_geometry import NativePortraitGeometry
from .portrait_compile import HoshimemoPortraitBackendProfile
from .portrait_project import StageTransform
from .visual_scene_portrait_compile import VisualScenePortraitTarget


NATIVE_PORTRAIT_ACCEPTANCE_SCHEMA = (
    "fvp-studio-v2.native-portrait-acceptance-profile.v1"
)
EDITOR_WIDTH = 1280
EDITOR_HEIGHT = 720


class NativePortraitAcceptanceError(HcbError):
    """Raised when a target-side portrait fact is not uniquely proven."""


@dataclass(frozen=True)
class _FunctionSpan:
    start: int
    end: int
    args: int
    locals: int
    instructions: tuple[Instruction, ...]
    syscalls: tuple[str, ...]
    calls: tuple[int, ...]


@dataclass(frozen=True)
class _DispatcherStackLayout:
    """Stable resource/runtime argument slots for reviewed dispatcher ABIs."""

    argument_count: int
    runtime_count: int
    selector: int
    action: int
    outfit: int
    expression: int
    form: int


def _dispatcher_stack_layout(argument_count: int) -> _DispatcherStackLayout:
    if int(argument_count) not in {12, 13}:
        raise NativePortraitAcceptanceError(
            "目标立绘 dispatcher 参数数不在已审核的 12 / 13 范围"
        )
    count = int(argument_count)
    return _DispatcherStackLayout(
        argument_count=count,
        runtime_count=count - 4,
        selector=-(count + 1),
        action=-count,
        outfit=-(count - 1),
        expression=-(count - 2),
        form=-(count - 3),
    )


@dataclass(frozen=True)
class NativePortraitAcceptanceProfile:
    compile_target: VisualScenePortraitTarget
    clear_target: int
    apply_target: int
    apply_argument_count: int
    registration_argument_count: int
    registration_targets: tuple[int, ...]
    registration_argument_counts: Mapping[int, int]
    selector: int
    primitive_ids: tuple[int, int]
    report: Mapping[str, Any]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _required_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NativePortraitAcceptanceError(f"{label}缺失或不是对象")
    return value


def _integer_value(item: Instruction) -> int | None:
    if item.mnemonic not in {"push_i8", "push_i16", "push_i32"}:
        return None
    try:
        return int(item.operands["value"])
    except (KeyError, TypeError, ValueError):
        return None


def _function_spans(document: HcbDocument) -> tuple[_FunctionSpan, ...]:
    instructions = document.instructions
    starts = [
        index
        for index, item in enumerate(instructions)
        if item.mnemonic == "init_stack"
    ]
    syscall_names = document.syscall_names
    result: list[_FunctionSpan] = []
    for position, start_index in enumerate(starts):
        end_index = starts[position + 1] if position + 1 < len(starts) else len(instructions)
        body = tuple(instructions[start_index:end_index])
        if not body:
            continue
        entry = body[0]
        end = (
            int(instructions[end_index].offset)
            if end_index < len(instructions)
            else int(document.header.sysdesc_offset)
        )
        result.append(
            _FunctionSpan(
                start=int(entry.offset),
                end=end,
                args=int(entry.operands.get("args", 0)),
                locals=int(entry.operands.get("locals", 0)),
                instructions=body,
                syscalls=tuple(
                    syscall_names.get(int(item.operands.get("id", -1)), "<unknown>")
                    for item in body
                    if item.mnemonic == "syscall"
                ),
                calls=tuple(
                    int(item.operands["target"])
                    for item in body
                    if item.mnemonic == "call" and "target" in item.operands
                ),
            )
        )
    return tuple(result)


def _region_from_discovery(
    discovery: Mapping[str, Any],
    name: str,
) -> Mapping[str, Any]:
    seed = _required_mapping(discovery.get("profile_seed"), "目标发现 profile_seed")
    symbols = _required_mapping(seed.get("native_symbols"), "目标发现 native_symbols")
    return _required_mapping(symbols.get(name), f"目标发现 {name}")


def _lifecycle_call_records(
    discovery: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    lifecycle = _region_from_discovery(discovery, "portrait_lifecycle_family")
    clear = _required_mapping(lifecycle.get("clear"), "目标立绘 clear")
    apply = _required_mapping(lifecycle.get("apply"), "目标立绘 apply")
    if str(lifecycle.get("engine_variant") or "").strip() == "legacy_fvp":
        delegates = _required_mapping(
            lifecycle.get("delegates"),
            "目标旧式立绘生命周期 delegates",
        )
        clear = _required_mapping(
            delegates.get("clear"),
            "目标旧式立绘 clear delegate",
        )
        apply = _required_mapping(
            delegates.get("apply"),
            "目标旧式立绘 apply delegate",
        )
    return clear, apply


def _lifecycle_targets(discovery: Mapping[str, Any]) -> tuple[int, int]:
    clear, apply = _lifecycle_call_records(discovery)
    try:
        clear_target = int(clear["start"])
        apply_target = int(apply["start"])
    except (KeyError, TypeError, ValueError) as exc:
        raise NativePortraitAcceptanceError("目标立绘 clear/apply 地址无效") from exc
    if int(clear.get("args", -1)) != 2 or int(apply.get("args", -1)) not in {2, 3}:
        raise NativePortraitAcceptanceError("目标立绘 clear/apply 不是已审核的 2/2 或 2/3 参数 ABI")
    return clear_target, apply_target


def _lifecycle_apply_argument_count(discovery: Mapping[str, Any]) -> int:
    _, apply = _lifecycle_call_records(discovery)
    try:
        count = int(apply.get("args", -1))
    except (TypeError, ValueError) as exc:
        raise NativePortraitAcceptanceError("目标立绘 apply 参数数无效") from exc
    if count not in {2, 3}:
        raise NativePortraitAcceptanceError("目标立绘 apply 参数数不在已审核的 2/3 范围")
    return count


def _instructions_in_range(
    document: HcbDocument,
    start: int,
    end: int,
) -> tuple[Instruction, ...]:
    values = tuple(
        item for item in document.instructions if start <= int(item.offset) < end
    )
    if not values or int(values[0].offset) != start:
        raise NativePortraitAcceptanceError(
            f"目标函数 0x{start:X}-0x{end:X} 不是已解析指令边界"
        )
    return values


def _validate_function_entry(
    document: HcbDocument,
    source_document: HcbDocument,
    start: int,
    *,
    args: int,
    locals_: int,
    label: str,
) -> None:
    try:
        analysis_entry = document.find(start)
        source_entry = source_document.find(start)
    except HcbError as exc:
        raise NativePortraitAcceptanceError(f"{label}不是函数入口") from exc
    expected = {"args": args, "locals": locals_}
    if (
        analysis_entry.mnemonic != "init_stack"
        or dict(analysis_entry.operands) != expected
        or source_entry.raw != analysis_entry.raw
    ):
        raise NativePortraitAcceptanceError(f"{label}入口或参数已漂移")


def _wrapper_constants(
    region: _FunctionSpan,
    dispatcher_start: int,
    dispatcher_argument_count: int = 13,
) -> tuple[int, int, int, int] | None:
    layout = _dispatcher_stack_layout(dispatcher_argument_count)
    if (
        region.args != layout.runtime_count
        or region.locals != 0
        or region.calls != (dispatcher_start,)
    ):
        return None
    body = region.instructions
    call_index = next(
        (
            index
            for index, item in enumerate(body)
            if item.mnemonic == "call"
            and int(item.operands.get("target", -1)) == dispatcher_start
        ),
        -1,
    )
    expected_call_index = 5 + layout.runtime_count
    if call_index != expected_call_index or len(body) <= call_index + 1:
        return None
    constants = tuple(_integer_value(item) for item in body[1:5])
    if any(value is None for value in constants):
        return None
    expected_stacks = tuple(range(-(layout.runtime_count + 1), -1))
    actual_stacks = tuple(
        int(item.operands.get("value", 0)) for item in body[5:call_index]
    )
    if (
        any(item.mnemonic != "push_stack" for item in body[5:call_index])
        or actual_stacks != expected_stacks
        or body[call_index + 1].mnemonic != "ret"
    ):
        return None
    return tuple(int(value) for value in constants if value is not None)  # type: ignore[return-value]


def _wrapper_constants_for_dispatcher(
    region: _FunctionSpan,
    dispatcher_start: int,
    dispatcher_argument_count: int,
) -> tuple[int, int, int, int] | None:
    # Keep the long-standing 13-argument helper call shape stable for tests and
    # downstream read-only analyzers; only the legacy ABI needs the new value.
    if int(dispatcher_argument_count) == 13:
        return _wrapper_constants(region, dispatcher_start)
    return _wrapper_constants(
        region,
        dispatcher_start,
        dispatcher_argument_count,
    )


def _forward_direct_dispatcher_pair(
    analysis_document: HcbDocument,
    source_document: HcbDocument,
    dispatcher_start: int,
    apply_target: int,
    hook_return_offset: int | None,
    *,
    dispatcher_argument_count: int,
    apply_argument_count: int,
) -> tuple[int, tuple[int, int, int, int], int, int] | None:
    """Prove a linear direct dispatcher/apply pair after a dialogue hook.

    Early FVP scripts sometimes call the portrait dispatcher directly from the
    story stream instead of going through a 4+N wrapper.  The direct form is
    accepted only when the hook returns at the first dispatcher argument, all
    dispatcher arguments are literal pushes, and the call is followed solely
    by the exact apply argument vector and apply CALL.  This keeps the evidence
    structural while avoiding any game-name or address special case.
    """

    if hook_return_offset is None:
        return None
    if dispatcher_argument_count not in {12, 13} or apply_argument_count not in {2, 3}:
        return None
    instructions = analysis_document.instructions
    start_index = next(
        (
            index
            for index, item in enumerate(instructions)
            if int(item.offset) == int(hook_return_offset)
        ),
        -1,
    )
    if start_index < 0:
        raise NativePortraitAcceptanceError(
            "剧情挂接返回地址不是目标 HCB 的指令边界"
        )
    dispatcher_call_index = start_index + dispatcher_argument_count
    apply_call_index = dispatcher_call_index + 1 + apply_argument_count
    if apply_call_index >= len(instructions):
        return None
    dispatcher_arguments = tuple(instructions[start_index:dispatcher_call_index])
    dispatcher_call = instructions[dispatcher_call_index]
    apply_arguments = tuple(
        instructions[dispatcher_call_index + 1 : apply_call_index]
    )
    apply_call = instructions[apply_call_index]
    literal_pushes = {
        "push_nil",
        "push_true",
        "push_false",
        "push_i8",
        "push_i16",
        "push_i32",
        "push_f32",
        "push_string",
    }
    if (
        len(dispatcher_arguments) != dispatcher_argument_count
        or any(item.mnemonic not in literal_pushes for item in dispatcher_arguments)
        or dispatcher_call.mnemonic != "call"
        or int(dispatcher_call.operands.get("target", -1)) != dispatcher_start
        or len(apply_arguments) != apply_argument_count
        or any(item.mnemonic not in literal_pushes for item in apply_arguments)
        or apply_call.mnemonic != "call"
        or int(apply_call.operands.get("target", -1)) != apply_target
    ):
        return None
    constants = tuple(_integer_value(item) for item in dispatcher_arguments[:4])
    if any(value is None for value in constants):
        return None
    for item in (
        *dispatcher_arguments,
        dispatcher_call,
        *apply_arguments,
        apply_call,
    ):
        source_raw = source_document.original_bytes[
            int(item.offset) : int(item.offset) + int(item.size)
        ]
        if source_raw != item.raw:
            raise NativePortraitAcceptanceError(
                f"挂接返回后的原生立绘调用在 0x{item.offset:X} 已漂移"
            )
    return (
        dispatcher_start,
        tuple(int(value) for value in constants if value is not None),
        int(dispatcher_call.offset),
        int(apply_call.offset),
    )


def _active_wrapper(
    analysis_document: HcbDocument,
    source_document: HcbDocument,
    spans: Sequence[_FunctionSpan],
    dispatcher_start: int,
    clear_target: int,
    apply_target: int,
    anchor_offset: int,
    *,
    dispatcher_argument_count: int = 13,
    apply_argument_count: int = 3,
    hook_return_offset: int | None = None,
    dispatcher_instructions: Sequence[Instruction] | None = None,
    resource_namespace: str = "graph_bs/",
) -> tuple[int, tuple[int, int, int, int], int, int]:
    wrappers = {
        region.start: constants
        for region in spans
        if (
            constants := _wrapper_constants_for_dispatcher(
                region,
                dispatcher_start,
                dispatcher_argument_count,
            )
        )
        is not None
    }
    if not wrappers:
        raise NativePortraitAcceptanceError(
            "目标 HCB 没有匹配 dispatcher 的严格 4+8 / 4+9 立绘包装函数"
        )
    direct_pair = _forward_direct_dispatcher_pair(
        analysis_document,
        source_document,
        dispatcher_start,
        apply_target,
        hook_return_offset,
        dispatcher_argument_count=dispatcher_argument_count,
        apply_argument_count=apply_argument_count,
    )
    if direct_pair is not None:
        direct_selector = int(direct_pair[1][0])

        def require_usable_carrier(selector: int) -> None:
            _selector_pre_scene_clear_evidence(
                analysis_document,
                source_document,
                selector=selector,
                clear_target=clear_target,
                apply_target=apply_target,
                apply_argument_count=apply_argument_count,
            )
            if dispatcher_instructions is not None:
                _selector_branch(
                    dispatcher_instructions,
                    selector,
                    resource_namespace=resource_namespace,
                    layout=_dispatcher_stack_layout(dispatcher_argument_count),
                )

        try:
            require_usable_carrier(direct_selector)
        except NativePortraitAcceptanceError:
            # The original direct registration after the hook is still the
            # exact lifecycle handoff, but its selector need not be a suitable
            # temporary V2 carrier.  Choose the nearest structurally valid
            # wrapper used earlier in the same HCB whose selector has the
            # target game's own clear/apply evidence.  The carrier need not be
            # in the current story function: state isolation snapshots and
            # restores the complete selector-owned global set before the direct
            # registration is replayed.
            tried_selectors: set[int] = {direct_selector}
            fallback_calls = [
                item
                for item in analysis_document.instructions
                if item.mnemonic == "call"
                and int(item.offset) < int(anchor_offset)
                and int(item.operands.get("target", -1)) in wrappers
            ]
            for item in reversed(fallback_calls):
                target = int(item.operands["target"])
                constants = wrappers[target]
                selector = int(constants[0])
                if selector in tried_selectors:
                    continue
                tried_selectors.add(selector)
                try:
                    require_usable_carrier(selector)
                except NativePortraitAcceptanceError:
                    continue
                source_raw = source_document.original_bytes[
                    int(item.offset) : int(item.offset) + int(item.size)
                ]
                if source_raw != item.raw:
                    raise NativePortraitAcceptanceError(
                        f"挂点前原生立绘调用在 0x{item.offset:X} 已漂移"
                    )
                return (
                    target,
                    constants,
                    int(item.offset),
                    int(direct_pair[3]),
                )
            raise NativePortraitAcceptanceError(
                "挂点附近没有同时具备原作清场证据的临时立绘 selector"
            )
        return direct_pair
    calls = [
        item
        for item in analysis_document.instructions
        if item.mnemonic == "call" and int(item.offset) < anchor_offset
    ]
    apply_calls = [
        item for item in calls if int(item.operands.get("target", -1)) == apply_target
    ]
    if not apply_calls:
        raise NativePortraitAcceptanceError("挂点前没有原生立绘 apply 调用")
    apply_call = apply_calls[-1]
    clear_calls = [
        item
        for item in calls
        if int(item.offset) < int(apply_call.offset)
        and int(item.operands.get("target", -1)) == clear_target
    ]
    if not clear_calls:
        raise NativePortraitAcceptanceError("挂点前没有原生立绘 clear 调用")
    wrapper_calls = [
        item
        for item in calls
        if int(clear_calls[-1].offset) < int(item.offset) < int(apply_call.offset)
        and int(item.operands.get("target", -1)) in wrappers
    ]
    if not wrapper_calls:
        raise NativePortraitAcceptanceError(
            "最近 clear/apply 区间没有匹配 dispatcher 的立绘调用"
        )
    # A source scene can contain several mutually exclusive branch bodies
    # between one clear and the apply nearest to the selected dialogue.  A
    # linear byte scan therefore cannot require the whole interval to contain
    # just one wrapper.  Bind the carrier to the last wrapper whose return is
    # followed directly by the apply arguments: no control transfer or other
    # call may occur between the two calls.  This proves an executable native
    # wrapper/apply pair without pretending every earlier branch was taken.
    wrapper_call = wrapper_calls[-1]
    bridge = tuple(
        item
        for item in analysis_document.instructions
        if int(wrapper_call.offset) + int(wrapper_call.size)
        <= int(item.offset)
        < int(apply_call.offset)
    )
    allowed = {
        "push_nil",
        "push_i8",
        "push_i16",
        "push_i32",
        "push_f32",
        "push_string",
        "neg",
    }
    if not bridge or any(item.mnemonic not in allowed for item in bridge):
        raise NativePortraitAcceptanceError(
            "挂点前最近立绘 wrapper 与 apply 之间不是线性参数桥"
        )
    target = int(wrapper_call.operands["target"])
    for item in (wrapper_call, apply_call):
        source_raw = source_document.original_bytes[
            int(item.offset) : int(item.offset) + int(item.size)
        ]
        if source_raw != item.raw:
            raise NativePortraitAcceptanceError(
                f"挂点前原生立绘调用在 0x{item.offset:X} 已漂移"
            )
    return target, wrappers[target], int(wrapper_call.offset), int(apply_call.offset)


def _direct_branch_literal(
    instructions: Sequence[Instruction],
    *,
    stack_offset: int,
    value: int,
    label: str,
) -> Instruction:
    matches: list[Instruction] = []
    for index in range(max(0, len(instructions) - 4)):
        first, second, third, fourth = instructions[index : index + 4]
        if (
            first.mnemonic != "push_stack"
            or int(first.operands.get("value", 0)) != stack_offset
            or _integer_value(second) != value
            or third.mnemonic != "set_e"
            or fourth.mnemonic != "jz"
        ):
            continue
        false_target = int(fourth.operands.get("target", -1))
        strings = [
            item
            for item in instructions[index + 4 :]
            if int(item.offset) < false_target and item.mnemonic == "push_string"
        ]
        if len(strings) == 1:
            matches.append(strings[0])
    if len(matches) != 1 or not str(matches[0].text or "").startswith("_"):
        raise NativePortraitAcceptanceError(f"{label}资源后缀不是唯一直接分支")
    return matches[0]


def _branch_primitive_pair(
    branch: Sequence[Instruction],
    *,
    selector: int,
) -> tuple[int, int]:
    """Derive the selector's two primitive IDs without assuming a local slot.

    Reviewed FVP families store the pair in one dispatcher local, but early
    builds use local 2 while later builds use local 3.  The branch itself must
    uniquely expose one non-negative local receiving exactly two integer IDs.
    """

    values_by_local: dict[int, set[int]] = {}
    for pos in range(max(0, len(branch) - 1)):
        value = _integer_value(branch[pos])
        following = branch[pos + 1]
        if (
            value is None
            or int(value) < 0
            or following.mnemonic != "pop_stack"
        ):
            continue
        local = int(following.operands.get("value", -1))
        if local < 0:
            continue
        values_by_local.setdefault(local, set()).add(int(value))
    candidates = [
        tuple(sorted(values))
        for values in values_by_local.values()
        if len(values) == 2
    ]
    if len(candidates) != 1:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 的 primitive 局部槽不是唯一双值来源"
        )
    return int(candidates[0][0]), int(candidates[0][1])


def _selector_branch(
    dispatcher: Sequence[Instruction],
    selector: int,
    *,
    resource_namespace: str = "graph_bs/",
    layout: _DispatcherStackLayout | None = None,
) -> tuple[Instruction, Instruction, tuple[int, int], str, int, str]:
    layout = layout or _dispatcher_stack_layout(13)
    matches: list[tuple[Instruction, Instruction, tuple[int, int], str, int, str]] = []
    for index in range(max(0, len(dispatcher) - 4)):
        first, second, third, fourth = dispatcher[index : index + 4]
        if (
            first.mnemonic != "push_stack"
            or int(first.operands.get("value", 0)) != layout.selector
            or _integer_value(second) != selector
            or third.mnemonic != "set_e"
            or fourth.mnemonic != "jz"
        ):
            continue
        false_target = int(fourth.operands.get("target", -1))
        branch = tuple(
            item
            for item in dispatcher[index + 4 :]
            if int(item.offset) < false_target
        )
        roots = [
            item
            for item in branch
            if item.mnemonic == "push_string"
            and str(item.text or "").startswith(
                f"{resource_namespace}CHR_"
            )
        ]
        if len(roots) != 1:
            continue
        try:
            primitive_pair = _branch_primitive_pair(branch, selector=selector)
        except NativePortraitAcceptanceError:
            continue
        action = _direct_branch_literal(
            branch,
            stack_offset=layout.action,
            value=1,
            label=f"selector {selector} 动作 1",
        )
        outfit_candidates: list[tuple[int, Instruction]] = []
        for outfit_code in range(1, 10):
            try:
                literal = _direct_branch_literal(
                    branch,
                    stack_offset=layout.outfit,
                    value=outfit_code,
                    label=f"selector {selector} 衣装 {outfit_code}",
                )
            except NativePortraitAcceptanceError:
                continue
            if "吹出" not in str(literal.text or ""):
                outfit_candidates.append((outfit_code, literal))
        if not outfit_candidates:
            continue
        outfit_code, outfit = outfit_candidates[0]
        matches.append(
            (
                roots[0],
                outfit,
                primitive_pair,
                str(action.text),
                outfit_code,
                str(outfit.text),
            )
        )
    if len(matches) != 1:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 的资源根/primitive/衣装分支不是唯一匹配"
        )
    return matches[0]


def _normal_form_suffixes(
    dispatcher: Sequence[Instruction],
    *,
    layout: _DispatcherStackLayout | None = None,
) -> tuple[Mapping[int, str], Mapping[str, Any]]:
    """Extract the target dispatcher's normal portrait form suffix table.

    The dispatcher builds the body name in stack local 0, then copies it to
    local 1 and appends ``_表情`` for the face resource.  Immediately before
    that copy, FVP targets compare the target-owned form argument
    and conditionally append the target-owned size suffix.  Deriving that
    chain from the selected target keeps cross-game acceptance independent of
    game names and of Studio's reviewed Hoshimemo suffix table.

    Bubble branches can suppress the normal suffix through local 12.  The
    acceptance carrier deliberately selects a non-bubble outfit branch, so
    the literal in each true branch is the applicable normal suffix.
    """

    layout = layout or _dispatcher_stack_layout(13)
    face_markers: list[int] = []
    for index in range(max(0, len(dispatcher) - 5)):
        first, second, third, fourth, fifth, sixth = dispatcher[index : index + 6]
        if (
            first.mnemonic == "push_stack"
            and int(first.operands.get("value", 0)) == 0
            and second.mnemonic == "pop_stack"
            and int(second.operands.get("value", 0)) == 1
            and third.mnemonic == "push_stack"
            and int(third.operands.get("value", 0)) == 1
            and fourth.mnemonic == "push_string"
            and str(fourth.text or "") == "_表情"
            and fifth.mnemonic == "add"
            and sixth.mnemonic == "pop_stack"
            and int(sixth.operands.get("value", 0)) == 1
        ):
            face_markers.append(index)
    if len(face_markers) != 1:
        raise NativePortraitAcceptanceError(
            "目标立绘身体名到表情名的派生边界不是唯一匹配"
        )

    face_index = face_markers[0]
    face_offset = int(dispatcher[face_index].offset)
    comparisons: dict[int, tuple[int, int, int]] = {}
    for index in range(face_index):
        first = dispatcher[index]
        if (
            first.mnemonic != "push_stack"
            or int(first.operands.get("value", 0)) != layout.form
            or index + 3 >= face_index
        ):
            continue
        raw_value = _integer_value(dispatcher[index + 1])
        if raw_value is None:
            continue
        cursor = index + 2
        form_code = int(raw_value)
        if dispatcher[cursor].mnemonic == "neg":
            form_code = -form_code
            cursor += 1
        if (
            cursor + 1 >= face_index
            or dispatcher[cursor].mnemonic != "set_e"
            or dispatcher[cursor + 1].mnemonic != "jz"
        ):
            continue
        false_target = int(dispatcher[cursor + 1].operands.get("target", -1))
        if int(first.offset) < false_target <= face_offset:
            comparisons[int(first.offset)] = (index, cursor + 2, form_code)

    terminal = [
        (offset, value)
        for offset, value in comparisons.items()
        if int(dispatcher[value[1] - 1].operands.get("target", -1)) == face_offset
    ]
    if len(terminal) != 1:
        raise NativePortraitAcceptanceError(
            "目标立绘尺寸后缀链没有唯一的表情名汇合边界"
        )

    chain: list[tuple[int, int, int, int]] = []
    current_offset, current = terminal[0]
    while True:
        index, branch_start, form_code = current
        false_target = int(dispatcher[branch_start - 1].operands["target"])
        chain.append((current_offset, branch_start, false_target, form_code))
        predecessors = [
            (offset, value)
            for offset, value in comparisons.items()
            if int(dispatcher[value[1] - 1].operands.get("target", -1))
            == current_offset
        ]
        if not predecessors:
            break
        if len(predecessors) != 1:
            raise NativePortraitAcceptanceError(
                "目标立绘尺寸后缀链存在歧义分支"
            )
        current_offset, current = predecessors[0]
    chain.reverse()

    suffixes: dict[int, str] = {}
    evidence: list[Mapping[str, Any]] = []
    offset_to_index = {
        int(item.offset): index for index, item in enumerate(dispatcher[: face_index + 1])
    }
    for comparison_offset, branch_start, false_target, form_code in chain:
        try:
            branch_end = offset_to_index[false_target]
        except KeyError as exc:
            raise NativePortraitAcceptanceError(
                "目标立绘尺寸后缀分支未落在已解析指令边界"
            ) from exc
        literals: list[Instruction] = []
        for index in range(branch_start, max(branch_start, branch_end - 3)):
            first, second, third, fourth = dispatcher[index : index + 4]
            if (
                first.mnemonic == "push_stack"
                and int(first.operands.get("value", 0)) == 0
                and second.mnemonic == "push_string"
                and third.mnemonic == "add"
                and fourth.mnemonic == "pop_stack"
                and int(fourth.operands.get("value", 0)) == 0
            ):
                literals.append(second)
        if len(literals) > 1:
            raise NativePortraitAcceptanceError(
                f"目标立绘尺寸类型 {form_code} 有多个资源后缀"
            )
        suffix = str(literals[0].text or "") if literals else ""
        if any(value in suffix for value in ("\x00", "/", "\\")):
            raise NativePortraitAcceptanceError(
                f"目标立绘尺寸类型 {form_code} 的资源后缀无效"
            )
        if form_code in suffixes:
            raise NativePortraitAcceptanceError(
                f"目标立绘尺寸类型 {form_code} 被重复定义"
            )
        suffixes[form_code] = suffix
        evidence.append(
            {
                "form_code": form_code,
                "suffix": suffix,
                "comparison_offset": comparison_offset,
                "false_target": false_target,
                "literal_offset": (
                    int(literals[0].offset) if literals else None
                ),
            }
        )
    if not suffixes:
        raise NativePortraitAcceptanceError("目标立绘没有可证明的尺寸后缀规则")
    return dict(sorted(suffixes.items())), {
        "schema": "fvp-studio-v2.native-portrait-form-suffixes.v1",
        "argument_stack": layout.form,
        "dispatcher_argument_count": layout.argument_count,
        "body_local": 0,
        "face_local": 1,
        "face_suffix": "_表情",
        "face_copy_offset": face_offset,
        "mappings": evidence,
    }


def _selector_cache_guard(
    dispatcher: Sequence[Instruction],
    *,
    selector: int,
    resource_root_offset: int,
    layout: _DispatcherStackLayout | None = None,
) -> Mapping[str, Any]:
    """Prove one selector-local form cache key that can be invalidated safely.

    FVP portrait dispatchers commonly avoid reloading a body when action,
    outfit and form match selector-specific globals.  A private clone changes
    the resource literal but deliberately keeps the same selector ABI, so it
    must not inherit that source dispatcher's cache hit.  Bind the guard to an
    exact read/write pair for the action argument and to the JZ that
    enters the selected resource-root block.  No game name or global-number
    table is used.
    """

    layout = layout or _dispatcher_stack_layout(13)
    selector_branches: list[tuple[Instruction, ...]] = []
    for index in range(max(0, len(dispatcher) - 4)):
        first, second, third, fourth = dispatcher[index : index + 4]
        if (
            first.mnemonic != "push_stack"
            or int(first.operands.get("value", 0)) != layout.selector
            or _integer_value(second) != int(selector)
            or third.mnemonic != "set_e"
            or fourth.mnemonic != "jz"
        ):
            continue
        false_target = int(fourth.operands.get("target", -1))
        branch = tuple(
            item
            for item in dispatcher[index + 4 :]
            if int(item.offset) < false_target
        )
        if any(int(item.offset) == int(resource_root_offset) for item in branch):
            selector_branches.append(branch)
    if len(selector_branches) != 1:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 的资源缓存分支不是唯一匹配"
        )
    branch = selector_branches[0]
    gates = [
        item
        for item in branch
        if item.mnemonic == "jz"
        and int(item.operands.get("target", -1)) == int(resource_root_offset)
        and int(item.offset) < int(resource_root_offset)
    ]
    if len(gates) != 1:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 的资源缓存门不是唯一 JZ"
        )
    gate = gates[0]
    reads: list[tuple[int, int]] = []
    for index in range(max(0, len(branch) - 2)):
        first, second, third = branch[index : index + 3]
        if (
            int(first.offset) < int(gate.offset)
            and first.mnemonic == "push_stack"
            and int(first.operands.get("value", 0)) == layout.action
            and second.mnemonic == "push_global"
            and third.mnemonic == "set_e"
        ):
            reads.append((int(second.operands.get("value", -1)), int(second.offset)))
    if len(reads) != 1 or not 0 <= reads[0][0] <= 0xFFFF:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 的 action 缓存读取不是唯一配对"
        )
    global_id, read_offset = reads[0]
    writes: list[int] = []
    for index in range(max(0, len(branch) - 1)):
        first, second = branch[index : index + 2]
        if (
            int(first.offset) > int(resource_root_offset)
            and first.mnemonic == "push_stack"
            and int(first.operands.get("value", 0)) == layout.action
            and second.mnemonic == "pop_global"
            and int(second.operands.get("value", -1)) == global_id
        ):
            writes.append(int(second.offset))
    if len(writes) != 1:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 的 action 缓存写回不是唯一配对"
        )
    return {
        "schema": "fvp-studio-v2.native-portrait-cache-guard.v1",
        "selector": int(selector),
        "argument_stack": layout.action,
        "dispatcher_argument_count": layout.argument_count,
        "argument_role": "action_code",
        "global_id": global_id,
        "read_offset": read_offset,
        "write_offset": writes[0],
        "gate_offset": int(gate.offset),
        "gate_target": int(resource_root_offset),
        "strategy": "set_nil_before_custom_portrait_program",
    }


def _selector_state_isolation(
    dispatcher: Sequence[Instruction],
    *,
    selector: int,
    resource_root_offset: int,
    cache_global_id: int,
    layout: _DispatcherStackLayout | None = None,
) -> Mapping[str, Any]:
    """Derive every selector-global written by the active dispatcher branch.

    A cloned dispatcher deliberately reuses the target game's native selector
    and primitive pair.  Its resource cache, coordinates, scale and related
    state therefore live in the same globals as the original character.  The
    scene hook must snapshot those globals before running the clone and restore
    them before replaying the next native registration.  Keep the list bound to
    the exact selected source branch instead of maintaining a game-specific
    global-number table.
    """

    layout = layout or _dispatcher_stack_layout(13)
    matches: list[tuple[int, int, tuple[Instruction, ...]]] = []
    for index in range(max(0, len(dispatcher) - 4)):
        first, second, third, fourth = dispatcher[index : index + 4]
        if (
            first.mnemonic != "push_stack"
            or int(first.operands.get("value", 0)) != layout.selector
            or _integer_value(second) != int(selector)
            or third.mnemonic != "set_e"
            or fourth.mnemonic != "jz"
        ):
            continue
        false_target = int(fourth.operands.get("target", -1))
        branch = tuple(
            item
            for item in dispatcher[index + 4 :]
            if int(item.offset) < false_target
        )
        if any(int(item.offset) == int(resource_root_offset) for item in branch):
            matches.append((int(first.offset), false_target, branch))
    if len(matches) != 1:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 的状态写入分支不是唯一匹配"
        )

    selector_test_offset, branch_end, branch = matches[0]
    writes: dict[int, list[int]] = {}
    reads: dict[int, list[int]] = {}
    for item in branch:
        if item.mnemonic not in {"push_global", "pop_global"}:
            continue
        global_id = int(item.operands.get("value", -1))
        if not 0 <= global_id <= 0xFFFF:
            raise NativePortraitAcceptanceError(
                f"selector {selector} 的 global ID 无效"
            )
        target = reads if item.mnemonic == "push_global" else writes
        target.setdefault(global_id, []).append(int(item.offset))

    global_ids = tuple(sorted(writes))
    if not global_ids:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 没有可快照的状态 global"
        )
    if int(cache_global_id) not in writes:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 的缓存 global 不在状态写回集合中"
        )
    branch_start = int(branch[0].offset) if branch else selector_test_offset
    return {
        "schema": "fvp-studio-v2.native-portrait-state-isolation.v1",
        "selector": int(selector),
        "global_ids": list(global_ids),
        "cache_global_id": int(cache_global_id),
        "selector_test_offset": selector_test_offset,
        "source_branch_range": [branch_start, branch_end],
        "resource_root_offset": int(resource_root_offset),
        "global_write_offsets": {
            str(global_id): offsets for global_id, offsets in sorted(writes.items())
        },
        "global_read_offsets": {
            str(global_id): offsets for global_id, offsets in sorted(reads.items())
        },
        # The translated runtime HCB must retain the exact system-description
        # counts of its paired analysis HCB.  Keep the snapshot on the VM
        # operand stack instead of borrowing a declared global or expanding
        # the header.
        "scratch_allocation": "vm_operand_stack",
        "strategy": "snapshot_on_operand_stack_restore_before_original_replay",
        "cache_rearm": "set_nil_at_cleanup_before_native_replay",
    }


def _selector_pre_scene_clear_evidence(
    analysis_document: HcbDocument,
    source_document: HcbDocument,
    *,
    selector: int,
    clear_target: int,
    apply_target: int,
    apply_argument_count: int = 3,
) -> Mapping[str, Any]:
    """Prove the target game's own immediate selector-clear sequence.

    Entering an authored scene must remove the already-rendered native
    portrait before the background transition starts.  Do not infer the
    apply arguments from another FVP title: require an exact, repeated source
    sequence for this selector and verify the translated/runtime HCB keeps the
    same opcode bytes at every accepted site.
    """

    if int(apply_argument_count) not in {2, 3}:
        raise NativePortraitAcceptanceError("原生清场证据的 apply 参数数不受支持")
    apply_nil_count = int(apply_argument_count)
    instructions = analysis_document.instructions
    matches: list[tuple[int, int]] = []
    sequence_length = 4 + apply_nil_count
    for index in range(max(0, len(instructions) - sequence_length + 1)):
        sequence = instructions[index : index + sequence_length]
        if len(sequence) != sequence_length:
            continue
        selector_value, clear_tail, clear_call = sequence[:3]
        apply_arguments = sequence[3:-1]
        apply_call = sequence[-1]
        if (
            _integer_value(selector_value) != int(selector)
            or clear_tail.mnemonic != "push_nil"
            or clear_call.mnemonic != "call"
            or int(clear_call.operands.get("target", -1)) != int(clear_target)
            or any(item.mnemonic != "push_nil" for item in apply_arguments)
            or apply_call.mnemonic != "call"
            or int(apply_call.operands.get("target", -1)) != int(apply_target)
        ):
            continue
        start = int(selector_value.offset)
        end = int(apply_call.offset) + int(apply_call.size)
        analysis_bytes = analysis_document.original_bytes[start:end]
        source_bytes = source_document.original_bytes[start:end]
        expected = b"".join(item.raw for item in sequence)
        if analysis_bytes != expected or source_bytes != expected:
            raise NativePortraitAcceptanceError(
                f"selector {selector} 的原生清场序列在活动/分析 HCB 间漂移"
            )
        matches.append((start, int(apply_call.offset)))
    if not matches:
        raise NativePortraitAcceptanceError(
            f"selector {selector} 没有原作 clear + Nil apply 清场证据"
        )
    source_offsets = [start for start, _ in matches]
    return {
        "schema": "fvp-studio-v2.native-portrait-pre-scene-clear.v1",
        "selector": int(selector),
        "clear_target": int(clear_target),
        "clear_arguments": [int(selector), None],
        "apply_target": int(apply_target),
        "apply_argument_count": apply_nil_count,
        "apply_arguments": [None] * apply_nil_count,
        "source_sequence_count": len(matches),
        "source_sequence_offsets": source_offsets,
        "source_apply_offsets": [offset for _, offset in matches],
        "source_sequence_offsets_sha256": hashlib.sha256(
            ",".join(str(value) for value in source_offsets).encode("ascii")
        ).hexdigest(),
        "strategy": "clear_then_nil_apply_before_visual",
    }


def _extract_direct_xy_scales(
    region: Sequence[Instruction],
    syscall_names: Mapping[int, str],
) -> tuple[float, float]:
    values: dict[int, list[float]] = {-3: [], -2: []}
    for index in range(max(0, len(region) - 2)):
        first, second, third = region[index : index + 3]
        if first.mnemonic != "push_stack" or second.mnemonic != "push_f32" or third.mnemonic != "mul":
            continue
        stack = int(first.operands.get("value", 0))
        if stack in values:
            values[stack].append(float(second.operands.get("value")))
    syscalls = tuple(
        syscall_names.get(int(item.operands.get("id", -1)), "<unknown>")
        for item in region
        if item.mnemonic == "syscall"
    )
    if syscalls != ("FloatToInt", "FloatToInt", "PrimSetXY"):
        raise NativePortraitAcceptanceError("目标直接 XY 函数系统调用序列已漂移")
    if any(len(values[key]) != 1 or values[key][0] <= 0 for key in (-3, -2)):
        raise NativePortraitAcceptanceError("目标直接 XY 倍率不是唯一正数")
    return values[-3][0], values[-2][0]


_UNKNOWN = object()


def _form_comparison(
    instructions: Sequence[Instruction],
    index: int,
    *,
    layout: _DispatcherStackLayout | None = None,
) -> tuple[int, int, int] | None:
    """Decode ``form argument == constant; jz`` at one instruction index."""

    layout = layout or _dispatcher_stack_layout(13)
    if (
        index + 3 >= len(instructions)
        or instructions[index].mnemonic != "push_stack"
        or int(instructions[index].operands.get("value", 0)) != layout.form
    ):
        return None
    raw_value = _integer_value(instructions[index + 1])
    if raw_value is None:
        return None
    cursor = index + 2
    form_code = int(raw_value)
    if instructions[cursor].mnemonic == "neg":
        form_code = -form_code
        cursor += 1
    if (
        cursor + 1 >= len(instructions)
        or instructions[cursor].mnemonic != "set_e"
        or instructions[cursor + 1].mnemonic != "jz"
    ):
        return None
    return form_code, cursor + 2, int(
        instructions[cursor + 1].operands.get("target", -1)
    )


def _known_binary(mnemonic: str, left: Any, right: Any) -> Any:
    if left is _UNKNOWN or right is _UNKNOWN:
        return _UNKNOWN
    if mnemonic == "set_e":
        return left == right
    if mnemonic == "set_ne":
        return left != right
    if mnemonic == "set_g":
        return left > right
    if mnemonic == "set_ge":
        return left >= right
    if mnemonic == "set_l":
        return left < right
    if mnemonic == "set_le":
        return left <= right
    if mnemonic == "and":
        return bool(left) and bool(right)
    if mnemonic == "or":
        return bool(left) or bool(right)
    if mnemonic == "add":
        return left + right
    if mnemonic == "sub":
        return left - right
    if mnemonic == "mul":
        return left * right
    if mnemonic == "div":
        return left / right
    raise NativePortraitAcceptanceError(
        f"原生立绘枢轴分支含不支持的二元指令 {mnemonic}"
    )


def _evaluate_pivot_branch(
    dispatcher: Sequence[Instruction],
    *,
    branch_start: int,
    branch_end: int,
    primsetop_target: int | None = None,
    primsetop_syscall_id: int | None = None,
    known_arguments: Mapping[int, Any],
) -> tuple[int, int, int] | None:
    """Evaluate one target-owned form branch until its indirect PrimSetOP call.

    Only constants, local assignments and argument-owned conditions are
    accepted.  If the OP depends on a global or another unproved runtime value,
    extraction fails closed instead of inventing a pivot.
    """

    offset_to_index = {int(item.offset): index for index, item in enumerate(dispatcher)}
    if branch_start not in offset_to_index or branch_end not in offset_to_index:
        raise NativePortraitAcceptanceError(
            "目标立绘枢轴分支没有落在已解析指令边界"
        )
    pc = offset_to_index[branch_start]
    values: list[Any] = []
    locals_: dict[int, Any] = {}
    visited: set[int] = set()
    binary_ops = {
        "set_e",
        "set_ne",
        "set_g",
        "set_ge",
        "set_l",
        "set_le",
        "and",
        "or",
        "add",
        "sub",
        "mul",
        "div",
    }
    while 0 <= pc < len(dispatcher):
        item = dispatcher[pc]
        offset = int(item.offset)
        if offset >= branch_end:
            return None
        if offset in visited:
            raise NativePortraitAcceptanceError("目标立绘枢轴分支出现循环")
        visited.add(offset)
        mnemonic = item.mnemonic
        if mnemonic in {"push_i8", "push_i16", "push_i32"}:
            values.append(int(item.operands["value"]))
        elif mnemonic == "push_f32":
            values.append(float(item.operands["value"]))
        elif mnemonic == "push_true":
            values.append(True)
        elif mnemonic == "push_nil":
            values.append(None)
        elif mnemonic == "push_stack":
            slot = int(item.operands.get("value", 0))
            values.append(
                known_arguments.get(slot, locals_.get(slot, _UNKNOWN))
            )
        elif mnemonic == "pop_stack":
            if not values:
                raise NativePortraitAcceptanceError("目标立绘枢轴分支栈下溢")
            locals_[int(item.operands.get("value", 0))] = values.pop()
        elif mnemonic == "neg":
            if not values:
                raise NativePortraitAcceptanceError("目标立绘枢轴分支栈下溢")
            value = values.pop()
            values.append(_UNKNOWN if value is _UNKNOWN else -value)
        elif mnemonic in binary_ops:
            if len(values) < 2:
                raise NativePortraitAcceptanceError("目标立绘枢轴分支栈下溢")
            right = values.pop()
            left = values.pop()
            values.append(_known_binary(mnemonic, left, right))
        elif mnemonic == "jz":
            if not values:
                raise NativePortraitAcceptanceError("目标立绘枢轴分支栈下溢")
            condition = values.pop()
            if condition is _UNKNOWN:
                raise NativePortraitAcceptanceError(
                    "目标立绘枢轴取决于未证明的运行时状态"
                )
            if not bool(condition):
                target = int(item.operands.get("target", -1))
                if target >= branch_end:
                    return None
                try:
                    pc = offset_to_index[target]
                except KeyError as exc:
                    raise NativePortraitAcceptanceError(
                        "目标立绘枢轴条件跳转未落在指令边界"
                    ) from exc
                continue
        elif mnemonic == "jmp":
            target = int(item.operands.get("target", -1))
            if target >= branch_end:
                return None
            try:
                pc = offset_to_index[target]
            except KeyError as exc:
                raise NativePortraitAcceptanceError(
                    "目标立绘枢轴跳转未落在指令边界"
                ) from exc
            continue
        elif mnemonic == "call":
            target = int(item.operands.get("target", -1))
            if primsetop_target is None or target != primsetop_target:
                raise NativePortraitAcceptanceError(
                    "目标立绘枢轴分支在 PrimSetOP 前调用了未证明函数"
                )
            if len(values) < 4:
                raise NativePortraitAcceptanceError("目标 PrimSetOP 包装调用参数不足")
            arguments = values[-4:]
            pivot_x, pivot_y = arguments[1], arguments[2]
            if (
                isinstance(pivot_x, bool)
                or isinstance(pivot_y, bool)
                or not isinstance(pivot_x, int)
                or not isinstance(pivot_y, int)
            ):
                raise NativePortraitAcceptanceError(
                    "目标 PrimSetOP 枢轴不是可证明整数"
                )
            return int(pivot_x), int(pivot_y), offset
        elif mnemonic == "syscall":
            syscall_id = int(item.operands.get("id", -1))
            if primsetop_syscall_id is None or syscall_id != primsetop_syscall_id:
                raise NativePortraitAcceptanceError(
                    "目标立绘枢轴分支在 PrimSetOP 前调用了未证明系统调用"
                )
            if len(values) < 3:
                raise NativePortraitAcceptanceError("目标 PrimSetOP 系统调用参数不足")
            arguments = values[-3:]
            pivot_x, pivot_y = arguments[1], arguments[2]
            if (
                isinstance(pivot_x, bool)
                or isinstance(pivot_y, bool)
                or not isinstance(pivot_x, int)
                or not isinstance(pivot_y, int)
            ):
                raise NativePortraitAcceptanceError(
                    "目标 PrimSetOP 枢轴不是可证明整数"
                )
            return int(pivot_x), int(pivot_y), offset
        elif mnemonic not in {"nop"}:
            raise NativePortraitAcceptanceError(
                f"目标立绘枢轴分支含不支持的指令 {mnemonic}"
            )
        pc += 1
    return None


def _embedded_native_form_pivots(
    dispatcher: Sequence[Instruction],
    syscall_names: Mapping[int, str],
    *,
    selector: int,
    action_code: int,
    outfit_code: int,
    expression_code: int,
    form_codes: Iterable[int],
    layout: _DispatcherStackLayout | None = None,
) -> tuple[Mapping[int, tuple[int, int]], Mapping[str, Any]]:
    """Extract old-FVP form pivots from its in-dispatcher PrimSetOP calls."""

    layout = layout or _dispatcher_stack_layout(13)
    primsetop_ids = {
        int(syscall_id)
        for syscall_id, name in syscall_names.items()
        if str(name) == "PrimSetOP"
    }
    if len(primsetop_ids) != 1:
        raise NativePortraitAcceptanceError(
            "目标旧版 dispatcher 的 PrimSetOP 系统调用 ID 不是唯一匹配"
        )
    primsetop_id = next(iter(primsetop_ids))
    normalized_forms = tuple(sorted({int(value) for value in form_codes}))
    known_arguments = {
        layout.selector: int(selector),
        layout.action: int(action_code),
        layout.outfit: int(outfit_code),
        layout.expression: int(expression_code),
    }
    matches: dict[int, list[tuple[int, int, int, int]]] = {
        value: [] for value in normalized_forms
    }
    for index in range(len(dispatcher)):
        decoded = _form_comparison(dispatcher, index, layout=layout)
        if decoded is None:
            continue
        form_code, branch_index, branch_end = decoded
        if form_code not in matches or branch_end <= int(dispatcher[branch_index].offset):
            continue
        linear_branch = tuple(
            item
            for item in dispatcher[branch_index:]
            if int(item.offset) < branch_end
        )
        if not any(
            item.mnemonic == "syscall"
            and int(item.operands.get("id", -1)) == primsetop_id
            for item in linear_branch
        ):
            continue
        resolved = _evaluate_pivot_branch(
            dispatcher,
            branch_start=int(dispatcher[branch_index].offset),
            branch_end=branch_end,
            primsetop_syscall_id=primsetop_id,
            known_arguments=known_arguments,
        )
        if resolved is not None:
            pivot_x, pivot_y, call_offset = resolved
            matches[form_code].append(
                (
                    pivot_x,
                    pivot_y,
                    int(dispatcher[index].offset),
                    call_offset,
                )
            )

    native_pivots: dict[int, tuple[int, int]] = {}
    evidence: list[Mapping[str, Any]] = []
    for form_code in normalized_forms:
        values = matches[form_code]
        unique = {(item[0], item[1]) for item in values}
        if len(unique) != 1:
            raise NativePortraitAcceptanceError(
                f"目标旧版立绘尺寸类型 {form_code} 的 PrimSetOP 枢轴不是唯一匹配"
            )
        pivot_x, pivot_y = next(iter(unique))
        native_pivots[form_code] = (pivot_x, pivot_y)
        evidence.append(
            {
                "form_code": form_code,
                "native_pivot": [pivot_x, pivot_y],
                "comparison_offsets": [item[2] for item in values],
                "syscall_offsets": [item[3] for item in values],
                "source": "embedded_primsetop_syscall",
            }
        )
    return native_pivots, {
        "strategy": "embedded_primsetop_syscall",
        "primsetop_syscall_id": primsetop_id,
        "forms": evidence,
    }


def _native_form_pivots(
    dispatcher: Sequence[Instruction],
    spans: Sequence[_FunctionSpan],
    *,
    selector: int,
    action_code: int,
    outfit_code: int,
    expression_code: int,
    form_codes: Iterable[int],
    logical_x_scale: float,
    logical_y_scale: float,
    layout: _DispatcherStackLayout | None = None,
) -> tuple[Mapping[int, tuple[int, int]], Mapping[str, Any]]:
    """Discover target-owned form pivots through an indirect PrimSetOP helper."""

    layout = layout or _dispatcher_stack_layout(13)
    dispatcher_calls = {
        int(item.operands["target"])
        for item in dispatcher
        if item.mnemonic == "call" and "target" in item.operands
    }
    helpers = [
        region
        for region in spans
        if region.start in dispatcher_calls
        and region.args == 4
        and region.syscalls.count("PrimSetOP") == 1
    ]
    if len(helpers) != 1:
        raise NativePortraitAcceptanceError(
            "目标 dispatcher 的间接 PrimSetOP 包装函数不是唯一匹配"
        )
    helper = helpers[0]
    for stack_slot, expected in ((-4, logical_x_scale), (-3, logical_y_scale)):
        scales = [
            float(second.operands.get("value"))
            for first, second, third in zip(
                helper.instructions,
                helper.instructions[1:],
                helper.instructions[2:],
            )
            if first.mnemonic == "push_stack"
            and int(first.operands.get("value", 0)) == stack_slot
            and second.mnemonic == "push_f32"
            and third.mnemonic == "mul"
        ]
        if not scales or any(not math.isclose(value, expected) for value in scales):
            raise NativePortraitAcceptanceError(
                "目标 PrimSetOP 包装函数与直接 XY 倍率不一致"
            )

    normalized_forms = tuple(sorted({int(value) for value in form_codes}))
    known_arguments = {
        layout.selector: int(selector),
        layout.action: int(action_code),
        layout.outfit: int(outfit_code),
        layout.expression: int(expression_code),
    }
    matches: dict[int, list[tuple[int, int, int, int]]] = {
        value: [] for value in normalized_forms
    }
    for index in range(len(dispatcher)):
        decoded = _form_comparison(dispatcher, index, layout=layout)
        if decoded is None:
            continue
        form_code, branch_index, branch_end = decoded
        if form_code not in matches or branch_end <= int(dispatcher[branch_index].offset):
            continue
        linear_branch = tuple(
            item
            for item in dispatcher[branch_index:]
            if int(item.offset) < branch_end
        )
        if not any(
            item.mnemonic == "call"
            and int(item.operands.get("target", -1)) == helper.start
            for item in linear_branch
        ):
            continue
        resolved = _evaluate_pivot_branch(
            dispatcher,
            branch_start=int(dispatcher[branch_index].offset),
            branch_end=branch_end,
            primsetop_target=helper.start,
            known_arguments=known_arguments,
        )
        if resolved is not None:
            logical_x, logical_y, call_offset = resolved
            matches[form_code].append(
                (
                    logical_x,
                    logical_y,
                    int(dispatcher[index].offset),
                    call_offset,
                )
            )

    native_pivots: dict[int, tuple[int, int]] = {}
    evidence: list[Mapping[str, Any]] = []
    for form_code in normalized_forms:
        values = matches[form_code]
        unique = {(item[0], item[1]) for item in values}
        if len(unique) > 1:
            raise NativePortraitAcceptanceError(
                f"目标立绘尺寸类型 {form_code} 有多个 PrimSetOP 枢轴"
            )
        if unique:
            logical_x, logical_y = next(iter(unique))
            native = (
                math.trunc(float(logical_x) * logical_x_scale),
                math.trunc(float(logical_y) * logical_y_scale),
            )
            native_pivots[form_code] = native
            evidence.append(
                {
                    "form_code": form_code,
                    "logical_pivot": [logical_x, logical_y],
                    "native_pivot": list(native),
                    "comparison_offsets": [item[2] for item in values],
                    "call_offsets": [item[3] for item in values],
                    "source": "indirect_primsetop",
                }
            )
        else:
            native_pivots[form_code] = (0, 0)
            evidence.append(
                {
                    "form_code": form_code,
                    "logical_pivot": [0, 0],
                    "native_pivot": [0, 0],
                    "comparison_offsets": [],
                    "call_offsets": [],
                    "source": "no_primsetop_form_branch",
                }
            )
    return dict(sorted(native_pivots.items())), {
        "schema": "fvp-studio-v2.native-portrait-form-pivots.v1",
        "helper_range": [helper.start, helper.end],
        "helper_sha256": _sha256(b"".join(item.raw for item in helper.instructions)),
        "logical_xy_scale": [logical_x_scale, logical_y_scale],
        "selector": int(selector),
        "action_code": int(action_code),
        "outfit_code": int(outfit_code),
        "expression_code": int(expression_code),
        "mappings": evidence,
    }


def _mode_table_value(region: _FunctionSpan, game_mode: int) -> tuple[int, int] | None:
    body = region.instructions
    cases: list[tuple[int, int]] = []
    for index in range(max(0, len(body) - 6)):
        first, second, third, fourth, fifth, sixth = body[index : index + 6]
        if (
            _integer_value(first) != game_mode
            or _integer_value(second) is None
            or third.mnemonic != "set_e"
            or fourth.mnemonic != "jz"
            or _integer_value(fifth) is None
            or sixth.mnemonic != "retv"
        ):
            continue
        cases.append((int(_integer_value(second)), int(_integer_value(fifth))))
    matches = [value for mode, value in cases if mode == game_mode]
    if len(cases) < 8 or len(matches) != 1:
        return None
    return len(cases), matches[0]


def _native_resolution(
    spans: Sequence[_FunctionSpan],
    game_mode: int,
) -> tuple[int, int, tuple[int, int]]:
    candidates = [
        (region, value)
        for region in spans
        if region.args == 0
        and region.locals == 0
        and (value := _mode_table_value(region, game_mode)) is not None
    ]
    adjacent: list[tuple[_FunctionSpan, _FunctionSpan, int, int]] = []
    for left, left_value in candidates:
        for right, right_value in candidates:
            if left.end != right.start:
                continue
            width = int(left_value[1])
            height = int(right_value[1])
            if width >= 640 and height >= 480 and 1.2 <= width / float(height) <= 2.0:
                adjacent.append((left, right, width, height))
    if len(adjacent) != 1:
        raise NativePortraitAcceptanceError("目标原生宽高模式表不是唯一相邻函数对")
    width_region, height_region, width, height = adjacent[0]
    return width, height, (width_region.start, height_region.start)


def _profile_background_resolution(
    assets: Sequence[Mapping[str, Any]],
    *,
    archive_name: str,
) -> tuple[int, int, Mapping[str, Any]]:
    """Prove an old-FVP viewport from the target profile's background mode.

    Some old FVP executables embed primitive geometry but do not expose the
    modern adjacent width/height mode-table functions.  Their own normal
    single-frame backgrounds still provide target-owned evidence: the native
    viewport is the unique dominant exact image size.  Panoramas remain in
    the competing-mode report, while CG/portrait rows and other archives are
    excluded by construction.
    """

    archive_key = str(archive_name or "").strip().casefold()
    if (
        not archive_key
        or archive_key != str(archive_name).strip()
        .replace("\\", "/")
        .rsplit("/", 1)[-1]
        .casefold()
        or "/" in str(archive_name).replace("\\", "/")
    ):
        raise NativePortraitAcceptanceError("目标背景尺寸证据的归档名无效")
    if isinstance(assets, (str, bytes, bytearray)):
        raise NativePortraitAcceptanceError("目标背景尺寸证据不是资源列表")

    modes: Counter[tuple[int, int]] = Counter()
    matching_background_count = 0
    rejected = Counter()
    for asset in assets:
        if not isinstance(asset, Mapping):
            rejected["non_mapping"] += 1
            continue
        category = str(asset.get("category") or "").strip().casefold()
        if category != "background":
            rejected["non_background"] += 1
            continue
        asset_archive = str(
            asset.get("archive") or asset.get("archive_name") or ""
        ).strip().casefold()
        if asset_archive != archive_key:
            rejected["other_archive"] += 1
            continue
        matching_background_count += 1
        try:
            width = int(asset.get("width"))
            height = int(asset.get("height"))
            frame_count = int(asset.get("frame_count"))
        except (TypeError, ValueError):
            rejected["invalid_metadata"] += 1
            continue
        if frame_count != 1:
            rejected["not_single_frame"] += 1
            continue
        if width < 640 or height < 480:
            rejected["too_small"] += 1
            continue
        aspect = width / float(height)
        if not 1.2 <= aspect <= 2.0:
            rejected["implausible_aspect"] += 1
            continue
        modes[(width, height)] += 1

    ranked = sorted(
        modes.items(),
        key=lambda item: (-int(item[1]), int(item[0][0]), int(item[0][1])),
    )
    eligible_count = sum(modes.values())
    if eligible_count < 8 or not ranked:
        raise NativePortraitAcceptanceError(
            "目标旧版背景尺寸证据不足（至少需要 8 个同归档单帧背景）"
        )
    (width, height), selected_count = ranked[0]
    runner_up_count = int(ranked[1][1]) if len(ranked) > 1 else 0
    selected_share = float(selected_count) / float(eligible_count)
    if (
        int(selected_count) < 8
        or int(selected_count) <= runner_up_count
        or selected_share < 0.60
    ):
        raise NativePortraitAcceptanceError(
            "目标旧版背景尺寸没有达到唯一且占比至少 60% 的主模式"
        )
    evidence = {
        "schema": "fvp-studio-v2.target-background-resolution.v1",
        "source": "target_profile_background_mode",
        "archive_name": archive_key,
        "matching_background_asset_count": int(matching_background_count),
        "eligible_asset_count": int(eligible_count),
        "selected_size": [int(width), int(height)],
        "selected_count": int(selected_count),
        "selected_share": selected_share,
        "runner_up_count": runner_up_count,
        "minimum_selected_count": 8,
        "minimum_selected_share": 0.60,
        "modes": [
            {"width": int(size[0]), "height": int(size[1]), "count": int(count)}
            for size, count in ranked
        ],
        "rejected": {
            str(reason): int(count) for reason, count in sorted(rejected.items())
        },
        "game_name_switch_used": False,
    }
    return int(width), int(height), evidence


def _negative_default(body: Sequence[Instruction], stack_slot: int) -> int | None:
    matches: list[int] = []
    for index in range(max(0, len(body) - 7)):
        first, second, third, fourth = body[index : index + 4]
        if (
            first.mnemonic != "push_stack"
            or int(first.operands.get("value", 0)) != stack_slot
            or second.mnemonic != "push_nil"
            or third.mnemonic != "set_e"
            or fourth.mnemonic != "jz"
        ):
            continue
        false_target = int(fourth.operands.get("target", -1))
        true_body = [
            item for item in body[index + 4 :] if int(item.offset) < false_target
        ]
        for position in range(max(0, len(true_body) - 2)):
            value = _integer_value(true_body[position])
            if (
                value is not None
                and true_body[position + 1].mnemonic == "neg"
                and true_body[position + 2].mnemonic == "pop_stack"
                and int(true_body[position + 2].operands.get("value", 0)) == stack_slot
            ):
                matches.append(-int(value))
    unique = sorted(set(matches))
    return unique[0] if len(unique) == 1 else None


def _camera_z(
    spans: Sequence[_FunctionSpan],
    syscall_names: Mapping[int, str],
    x_scale: float,
    y_scale: float,
) -> tuple[int, int]:
    setters = [
        region
        for region in spans
        if region.args == 3
        and region.locals == 0
        and region.syscalls == ("FloatToInt", "FloatToInt", "V3DSet")
    ]
    verified: list[_FunctionSpan] = []
    for region in setters:
        scales = [
            float(item.operands.get("value"))
            for item in region.instructions
            if item.mnemonic == "push_f32"
        ]
        if len(scales) == 2 and math.isclose(scales[0], x_scale) and math.isclose(scales[1], y_scale):
            verified.append(region)
    if len(verified) != 1:
        raise NativePortraitAcceptanceError("目标 V3DSet 坐标包装函数不是唯一匹配")
    setter = verified[0]
    defaults: list[int] = []
    for region in spans:
        if setter.start not in region.calls:
            continue
        for index, item in enumerate(region.instructions):
            if item.mnemonic != "call" or int(item.operands.get("target", -1)) != setter.start:
                continue
            if index < 3 or any(
                part.mnemonic != "push_stack"
                for part in region.instructions[index - 3 : index]
            ):
                continue
            z_slot = int(region.instructions[index - 1].operands.get("value", 0))
            default = _negative_default(region.instructions, z_slot)
            if default is not None:
                defaults.append(default)
    unique = sorted(set(defaults))
    if len(unique) != 1 or unique[0] >= 0:
        raise NativePortraitAcceptanceError("目标默认 V3D 相机 Z 不是唯一负值")
    return unique[0], setter.start


def _embedded_v3d_camera(
    spans: Sequence[_FunctionSpan],
    syscall_names: Mapping[int, str],
    *,
    anchor_offset: int,
) -> tuple[tuple[int, int, int], Mapping[str, Any]]:
    """Prove the last target-owned V3D camera reset before an old-FVP hook."""

    syscall_ids = {
        int(syscall_id)
        for syscall_id, name in syscall_names.items()
        if str(name) == "V3DSet"
    }
    if len(syscall_ids) != 1:
        raise NativePortraitAcceptanceError("目标旧版 V3DSet syscall ID 不是唯一匹配")
    syscall_id = next(iter(syscall_ids))
    by_start = {int(span.start): span for span in spans}
    owners = [
        span for span in spans if int(span.start) <= anchor_offset < int(span.end)
    ]
    if len(owners) != 1:
        raise NativePortraitAcceptanceError("目标旧版挂点不属于唯一脚本函数")
    anchor_owner = owners[0]

    # Each marker is either one literal camera tuple or ``None`` for a dynamic
    # V3DSet call.  Propagating markers through the reverse call graph lets the
    # anchor function prove which direct call can change the camera without
    # assigning semantics from a function name or game path.
    markers_by_function: dict[int, set[tuple[int, int, int] | None]] = {}
    ordered_markers_by_function: dict[
        int, list[tuple[int, tuple[int, int, int] | None]]
    ] = {}
    literal_sites: list[dict[str, Any]] = []
    dynamic_sites: list[dict[str, Any]] = []
    for span in spans:
        for index, item in enumerate(span.instructions):
            if (
                item.mnemonic != "syscall"
                or int(item.operands.get("id", -1)) != syscall_id
            ):
                continue
            arguments = (
                tuple(_integer_value(part) for part in span.instructions[index - 3 : index])
                if index >= 3
                else ()
            )
            if len(arguments) == 3 and all(value is not None for value in arguments):
                camera = tuple(int(value) for value in arguments)
                markers_by_function.setdefault(int(span.start), set()).add(camera)
                ordered_markers_by_function.setdefault(int(span.start), []).append(
                    (int(item.offset), camera)
                )
                literal_sites.append(
                    {
                        "function_start": int(span.start),
                        "syscall_offset": int(item.offset),
                        "literal_offsets": [
                            int(part.offset) for part in span.instructions[index - 3 : index]
                        ],
                        "camera": list(camera),
                    }
                )
            else:
                markers_by_function.setdefault(int(span.start), set()).add(None)
                ordered_markers_by_function.setdefault(int(span.start), []).append(
                    (int(item.offset), None)
                )
                dynamic_sites.append(
                    {
                        "function_start": int(span.start),
                        "syscall_offset": int(item.offset),
                    }
                )
    if not literal_sites:
        raise NativePortraitAcceptanceError("目标旧版没有直接整数 V3DSet 相机基线")
    reverse_calls: dict[int, set[int]] = {}
    for span in spans:
        for target in span.calls:
            if int(target) in by_start:
                reverse_calls.setdefault(int(target), set()).add(int(span.start))
    reachable_markers: dict[int, set[tuple[int, int, int] | None]] = {
        start: set(markers) for start, markers in markers_by_function.items()
    }
    for source_start, source_markers in markers_by_function.items():
        pending = list(reverse_calls.get(source_start, ()))
        visited: set[int] = set()
        while pending:
            caller = pending.pop()
            if caller in visited:
                continue
            visited.add(caller)
            reachable_markers.setdefault(caller, set()).update(source_markers)
            pending.extend(reverse_calls.get(caller, ()))

    events: list[dict[str, Any]] = []
    for index, item in enumerate(anchor_owner.instructions):
        if int(item.offset) >= anchor_offset:
            break
        if item.mnemonic == "call":
            target = int(item.operands.get("target", -1))
            markers = reachable_markers.get(target, set())
            if markers:
                events.append(
                    {
                        "offset": int(item.offset),
                        "kind": "call",
                        "target": target,
                        "markers": set(markers),
                    }
                )
        elif (
            item.mnemonic == "syscall"
            and int(item.operands.get("id", -1)) == syscall_id
        ):
            arguments = (
                tuple(
                    _integer_value(part)
                    for part in anchor_owner.instructions[index - 3 : index]
                )
                if index >= 3
                else ()
            )
            markers: set[tuple[int, int, int] | None] = {
                tuple(int(value) for value in arguments)
                if len(arguments) == 3 and all(value is not None for value in arguments)
                else None
            }
            events.append(
                {
                    "offset": int(item.offset),
                    "kind": "syscall",
                    "target": None,
                    "markers": markers,
                }
            )
    if events:
        latest = max(events, key=lambda item: int(item["offset"]))
        latest_markers = set(latest["markers"])
        if len(latest_markers) != 1 or None in latest_markers:
            raise NativePortraitAcceptanceError("目标旧版挂点前最后一次 V3D 相机设置不是唯一常量")
        camera = next(iter(latest_markers))
        if camera is None:  # Kept explicit for static type narrowing.
            raise NativePortraitAcceptanceError("目标旧版挂点前最后一次 V3D 相机设置不是唯一常量")
        evidence_source = "last_reachable_v3dset_before_story_anchor"
        selected_event = {
            "offset": int(latest["offset"]),
            "kind": str(latest["kind"]),
            "target": latest["target"],
        }
        terminal_sites: list[dict[str, Any]] = []
    else:
        # Some early FVP scripts do not repeat a camera reset in every story
        # function.  Accept their inherited baseline only when every function
        # that can mutate V3D terminates with the same literal tuple.  This is
        # stronger than choosing the most frequent tuple and still permits a
        # transient effect camera that is restored before its function exits.
        terminal_sites = [
            {
                "function_start": int(function_start),
                "syscall_offset": int(ordered[-1][0]),
                "camera": (
                    None
                    if ordered[-1][1] is None
                    else list(ordered[-1][1])
                ),
            }
            for function_start, ordered in sorted(ordered_markers_by_function.items())
            if ordered
        ]
        terminal_markers = {
            ordered[-1][1]
            for ordered in ordered_markers_by_function.values()
            if ordered
        }
        if len(terminal_sites) < 2 or len(terminal_markers) != 1 or None in terminal_markers:
            raise NativePortraitAcceptanceError(
                "目标旧版挂点前没有调用相机，且全局 V3D 复位基线不是唯一常量"
            )
        camera = next(iter(terminal_markers))
        if camera is None:  # Kept explicit for static type narrowing.
            raise NativePortraitAcceptanceError(
                "目标旧版挂点前没有调用相机，且全局 V3D 复位基线不是唯一常量"
            )
        evidence_source = "all_v3d_mutators_restore_same_literal_baseline"
        selected_event = {
            "offset": None,
            "kind": "target_reset_invariant",
            "target": None,
        }

    evidence: Mapping[str, Any] = {
        "schema": "fvp-studio-v2.embedded-v3d-camera.v1",
        "source": evidence_source,
        "camera": list(camera),
        "syscall_id": syscall_id,
        "anchor_offset": int(anchor_offset),
        "anchor_function": int(anchor_owner.start),
        "selected_event": selected_event,
        "literal_sites": literal_sites,
        "dynamic_sites": dynamic_sites,
        "terminal_sites": terminal_sites,
        "event_count_before_anchor": len(events),
        "game_name_switch_used": False,
    }
    return camera, evidence


def _round_nearest(value: float) -> int:
    return int(math.floor(value + 0.5)) if value >= 0 else int(math.ceil(value - 0.5))


def _geometry_converter(
    *,
    logical_x_scale: float,
    logical_y_scale: float,
    native_width: int,
    native_height: int,
    camera_z: int,
    native_pivots: Mapping[int, tuple[int, int]],
):
    def convert(
        editor: StageTransform,
        body: HzcMetadata,
        *,
        form_code: int,
        selector: int,
    ) -> NativePortraitGeometry:
        if editor.scale <= 0:
            raise NativePortraitAcceptanceError("舞台立绘缩放必须大于 0")
        depth = int(editor.z) - int(camera_z)
        if depth <= 0:
            raise NativePortraitAcceptanceError("舞台立绘位于目标 V3D 相机后方")
        try:
            pivot_x, pivot_y = native_pivots[int(form_code)]
        except (KeyError, TypeError, ValueError) as exc:
            raise NativePortraitAcceptanceError(
                f"目标立绘尺寸类型 {form_code} 没有已证明的原生枢轴"
            ) from exc
        angle = math.radians(-int(editor.rotation))
        cosine = math.cos(angle)
        sine = math.sin(angle)
        # HZC body offsets describe the layer's position on its source canvas;
        # PrimSetOP installs a target-owned origin in that same native pixel
        # space.  Both terms are required.  Dropping either one turns a full
        # portrait into the upper-left fragment seen when an FVP title's
        # indirect OP wrapper was missed.
        local_center_x = (
            float(body.offset_x) + float(body.width) / 2.0 - float(pivot_x)
        )
        local_center_y = (
            float(body.offset_y) + float(body.height) / 2.0 - float(pivot_y)
        )
        rotated_center_x = cosine * local_center_x - sine * local_center_y
        rotated_center_y = sine * local_center_x + cosine * local_center_y
        desired_local_x = 1000.0 * float(editor.x) / float(editor.scale)
        desired_local_y = (
            1000.0 * (float(editor.y) - EDITOR_HEIGHT / 2.0) / float(editor.scale)
            + float(body.height) / 2.0
        )
        native_x = _round_nearest(
            (desired_local_x - rotated_center_x) / logical_x_scale
        )
        native_y = _round_nearest(
            (desired_local_y - rotated_center_y) / logical_y_scale
        )
        native_scale = _round_nearest(
            depth * (native_width / float(EDITOR_WIDTH)) * float(editor.scale) / 1000.0
        )
        if native_scale <= 0:
            raise NativePortraitAcceptanceError("换算后的目标原生立绘缩放无效")
        native = StageTransform(
            x=native_x,
            y=native_y,
            z=int(editor.z),
            scale=native_scale,
            rotation=int(editor.rotation),
            opacity=int(editor.opacity),
        )
        projected_scale = float(native_scale) / float(depth)
        projected_center_x = native_width / 2.0 + projected_scale * (
            logical_x_scale * native_x + rotated_center_x
        )
        projected_center_y = native_height / 2.0 + projected_scale * (
            logical_y_scale * native_y + rotated_center_y
        )
        desired_center_x = (EDITOR_WIDTH / 2.0 + float(editor.x)) * (
            native_width / float(EDITOR_WIDTH)
        )
        desired_center_y = (
            float(editor.y) + float(body.height) * float(editor.scale) / 2000.0
        ) * (native_height / float(EDITOR_HEIGHT))
        return NativePortraitGeometry(
            transform=native,
            report={
                "schema": "fvp-studio-v2.native-fvp-stage-geometry.v1",
                "editor_transform": editor.to_dict(),
                "native_transform": native.to_dict(),
                "body_hzc": body.to_dict(),
                "form_code": int(form_code),
                "selector": int(selector),
                "native_pivot": [int(pivot_x), int(pivot_y)],
                "hzc_composition_offset": [int(body.offset_x), int(body.offset_y)],
                "hzc_composition_offset_applied_to_primitive_xy": True,
                "v3d_camera": [0, 0, int(camera_z)],
                "logical_xy_scale": [logical_x_scale, logical_y_scale],
                "editor_size": [EDITOR_WIDTH, EDITOR_HEIGHT],
                "native_size": [native_width, native_height],
                "projected_center_error_pixels": [
                    projected_center_x - desired_center_x,
                    projected_center_y - desired_center_y,
                ],
                "native_evidence": (
                    "exact direct-XY multipliers + transitive PrimSetOP form "
                    "pivot + HZC composition offset + mode-table resolution + "
                    "default V3D camera"
                ),
            },
        )

    return convert


def _embedded_xy_geometry_converter(
    *,
    native_width: int,
    native_height: int,
    camera: tuple[int, int, int],
    native_pivots: Mapping[int, tuple[int, int]],
):
    """Convert the V2 stage into an old-FVP V3D-projected primitive space."""

    if native_width <= 0 or native_height <= 0:
        raise NativePortraitAcceptanceError("目标旧版原生分辨率无效")
    if len(camera) != 3:
        raise NativePortraitAcceptanceError("目标旧版 V3D 相机参数无效")
    camera_x, camera_y, camera_z = (int(value) for value in camera)
    width_ratio = float(native_width) / float(EDITOR_WIDTH)
    height_ratio = float(native_height) / float(EDITOR_HEIGHT)

    def convert(
        editor: StageTransform,
        body: HzcMetadata,
        *,
        form_code: int,
        selector: int,
    ) -> NativePortraitGeometry:
        if editor.scale <= 0:
            raise NativePortraitAcceptanceError("舞台立绘缩放必须大于 0")
        depth = int(editor.z) - camera_z
        if depth <= 0:
            raise NativePortraitAcceptanceError("舞台立绘位于目标旧版 V3D 相机后方")
        try:
            pivot_x, pivot_y = native_pivots[int(form_code)]
        except (KeyError, TypeError, ValueError) as exc:
            raise NativePortraitAcceptanceError(
                f"目标旧版立绘尺寸类型 {form_code} 没有已证明的原生枢轴"
            ) from exc
        # PrimSetZ enables V3D projection in old FVP.  PrimSetXY therefore lives
        # before the scale/depth projection and cannot be treated as a screen
        # pixel translation.  Preserve vertical character framing when moving
        # the V2 16:9 stage to a target such as 4:3.
        desired_projected_scale = (
            float(editor.scale) * height_ratio / 1000.0
        )
        native_scale = _round_nearest(float(depth) * desired_projected_scale)
        if native_scale <= 0:
            raise NativePortraitAcceptanceError("换算后的目标旧版立绘缩放无效")
        angle = math.radians(-int(editor.rotation))
        cosine = math.cos(angle)
        sine = math.sin(angle)
        local_center_x = (
            float(body.offset_x) + float(body.width) / 2.0 - float(pivot_x)
        )
        local_center_y = (
            float(body.offset_y) + float(body.height) / 2.0 - float(pivot_y)
        )
        rotated_center_x = cosine * local_center_x - sine * local_center_y
        rotated_center_y = sine * local_center_x + cosine * local_center_y
        projected_scale = float(native_scale) / float(depth)
        camera_shift_x = 1000.0 * float(camera_x) / float(native_scale)
        camera_shift_y = 1000.0 * float(camera_y) / float(native_scale)
        desired_center_x = float(editor.x) * width_ratio
        desired_center_y = (
            float(editor.y)
            + float(body.height) * float(editor.scale) / 2000.0
            - EDITOR_HEIGHT / 2.0
        ) * height_ratio
        native_x = _round_nearest(
            desired_center_x / projected_scale
            + camera_shift_x
            - rotated_center_x
        )
        native_y = _round_nearest(
            desired_center_y / projected_scale
            + camera_shift_y
            - rotated_center_y
        )
        native = StageTransform(
            x=native_x,
            y=native_y,
            z=int(editor.z),
            scale=native_scale,
            rotation=int(editor.rotation),
            opacity=int(editor.opacity),
        )
        projected_center_x = (
            native_width / 2.0
            + projected_scale
            * (float(native_x) - camera_shift_x + rotated_center_x)
        )
        projected_center_y = (
            native_height / 2.0
            + projected_scale
            * (float(native_y) - camera_shift_y + rotated_center_y)
        )
        absolute_desired_center_x = native_width / 2.0 + desired_center_x
        absolute_desired_center_y = native_height / 2.0 + desired_center_y
        return NativePortraitGeometry(
            transform=native,
            report={
                "schema": "fvp-studio-v2.native-fvp-embedded-xy-geometry.v2",
                "editor_transform": editor.to_dict(),
                "native_transform": native.to_dict(),
                "body_hzc": body.to_dict(),
                "form_code": int(form_code),
                "selector": int(selector),
                "native_pivot": [int(pivot_x), int(pivot_y)],
                "hzc_composition_offset": [
                    int(body.offset_x),
                    int(body.offset_y),
                ],
                "hzc_composition_offset_applied_to_primitive_xy": True,
                "v3d_camera": [camera_x, camera_y, camera_z],
                "v3d_depth": depth,
                "projected_scale": projected_scale,
                "logical_xy_scale": [1.0, 1.0],
                "editor_size": [EDITOR_WIDTH, EDITOR_HEIGHT],
                "native_size": [native_width, native_height],
                "editor_to_native_position_ratio": [
                    width_ratio,
                    height_ratio,
                ],
                "editor_to_native_portrait_scale_ratio": (
                    float(depth) * height_ratio / 1000.0
                ),
                "mapping_mode": "v3d_projected_xy_with_vertical_uniform_scale",
                "projected_center_error_pixels": [
                    projected_center_x - absolute_desired_center_x,
                    projected_center_y - absolute_desired_center_y,
                ],
                "native_evidence": (
                    "embedded PrimSetXY + PrimSetZ V3D projection + literal "
                    "dispatcher V3DSet camera + embedded PrimSetOP form pivot + "
                    "direct PrimSetRS scale + target-proven native resolution"
                ),
            },
        )

    return convert


def build_native_portrait_acceptance_profile(
    source_document: HcbDocument,
    analysis_document: HcbDocument,
    discovery: Mapping[str, Any],
    target_graph_bs: bytes,
    *,
    anchor_offset: int,
    hook_return_offset: int | None = None,
    target_visual_assets: Sequence[Mapping[str, Any]] | None = None,
) -> NativePortraitAcceptanceProfile:
    """Extract one exact active-selector compile target without path writes."""

    if not isinstance(source_document, HcbDocument) or not isinstance(analysis_document, HcbDocument):
        raise NativePortraitAcceptanceError("原生立绘验收缺少配对 HCB 文档")
    if not isinstance(target_graph_bs, bytes) or not target_graph_bs:
        raise NativePortraitAcceptanceError("原生立绘验收缺少目标角色资源归档 bytes")
    dispatcher_record = _region_from_discovery(discovery, "portrait_dispatcher")
    engine_variant = str(dispatcher_record.get("engine_variant") or "").strip()
    geometry_mode = str(dispatcher_record.get("geometry_mode") or "").strip()
    resource_namespace = str(
        dispatcher_record.get("resource_namespace") or ""
    ).strip()
    resource_archive_name = str(
        dispatcher_record.get("resource_archive_name") or ""
    ).strip()
    expected_target_shape = {
        "modern_fvp": ("direct_xy_wrapper", "graph_bs/", "graph_bs.bin"),
        "old_fvp": ("embedded_xy", "graph/", "graph.bin"),
        "legacy_fvp": ("embedded_xy", "graph/", "graph.bin"),
    }.get(engine_variant)
    if expected_target_shape is None or (
        geometry_mode,
        resource_namespace,
        resource_archive_name,
    ) != expected_target_shape:
        raise NativePortraitAcceptanceError("目标立绘发现报告的引擎/资源形态不一致")
    try:
        hzc_alpha_evidence = dict(
            infer_archive_hzc_alpha_storage(target_graph_bs, max_samples=8)
        )
    except BinArchiveError as exc:
        hzc_alpha_evidence = {
            "schema": "fvp-studio-v2.hzc-alpha-storage.v1",
            "storage": "unknown",
            "sample_count": 0,
            "conversion_policy": "preserve_source_payload",
            "reason": str(exc),
        }
    target_hzc_alpha_storage = (
        "premultiplied"
        if hzc_alpha_evidence.get("storage") == "premultiplied"
        else "preserve"
    )
    direct_record = (
        _region_from_discovery(discovery, "direct_xy")
        if geometry_mode == "direct_xy_wrapper"
        else None
    )
    try:
        dispatcher_start = int(dispatcher_record["start"])
        dispatcher_end = int(dispatcher_record["end"])
        dispatcher_args = int(dispatcher_record["args"])
        dispatcher_locals = int(dispatcher_record["locals"])
        direct_start = (
            int(direct_record["start"]) if direct_record is not None else None
        )
        direct_end = int(direct_record["end"]) if direct_record is not None else None
    except (KeyError, TypeError, ValueError) as exc:
        raise NativePortraitAcceptanceError("目标发现报告中的立绘函数范围无效") from exc
    layout = _dispatcher_stack_layout(dispatcher_args)
    if dispatcher_locals < 0:
        raise NativePortraitAcceptanceError("目标立绘 dispatcher 局部变量数量无效")
    _validate_function_entry(
        analysis_document,
        source_document,
        dispatcher_start,
        args=dispatcher_args,
        locals_=dispatcher_locals,
        label="目标立绘 dispatcher",
    )
    if direct_start is not None and direct_end is not None:
        _validate_function_entry(
            analysis_document,
            source_document,
            direct_start,
            args=3,
            locals_=2,
            label="目标直接 XY 函数",
        )
    if source_document.original_bytes[dispatcher_start:dispatcher_end] != analysis_document.original_bytes[dispatcher_start:dispatcher_end]:
        raise NativePortraitAcceptanceError("活动/分析 HCB 的立绘 dispatcher 字节不一致")
    if (
        direct_start is not None
        and direct_end is not None
        and source_document.original_bytes[direct_start:direct_end]
        != analysis_document.original_bytes[direct_start:direct_end]
    ):
        raise NativePortraitAcceptanceError("活动/分析 HCB 的直接 XY 字节不一致")

    spans = _function_spans(analysis_document)
    clear_target, apply_target = _lifecycle_targets(discovery)
    apply_argument_count = _lifecycle_apply_argument_count(discovery)
    clear_record, apply_record = _lifecycle_call_records(discovery)
    try:
        clear_locals = int(clear_record.get("locals", -1))
        apply_locals = int(apply_record.get("locals", -1))
    except (TypeError, ValueError) as exc:
        raise NativePortraitAcceptanceError(
            "目标立绘 clear/apply 局部变量数量无效"
        ) from exc
    if clear_locals < 0 or apply_locals < 0:
        raise NativePortraitAcceptanceError(
            "目标立绘 clear/apply 局部变量数量无效"
        )
    _validate_function_entry(
        analysis_document,
        source_document,
        clear_target,
        args=2,
        locals_=clear_locals,
        label="目标立绘 clear",
    )
    _validate_function_entry(
        analysis_document,
        source_document,
        apply_target,
        args=apply_argument_count,
        locals_=apply_locals,
        label="目标立绘 apply",
    )
    dispatcher = _instructions_in_range(
        analysis_document, dispatcher_start, dispatcher_end
    )
    wrapper_start, wrapper_constants, wrapper_call, apply_call = _active_wrapper(
        analysis_document,
        source_document,
        spans,
        dispatcher_start,
        clear_target,
        apply_target,
        int(anchor_offset),
        dispatcher_argument_count=dispatcher_args,
        apply_argument_count=apply_argument_count,
        hook_return_offset=hook_return_offset,
        dispatcher_instructions=dispatcher,
        resource_namespace=resource_namespace,
    )
    selector, original_action, original_outfit, original_expression = wrapper_constants
    root_literal, outfit_literal, primitive_ids, action_suffix, outfit_code, outfit_expected = _selector_branch(
        dispatcher,
        selector,
        resource_namespace=resource_namespace,
        layout=layout,
    )
    registration_targets = tuple(
        sorted(
            region.start
            for region in spans
            if (
                (
                    constants := _wrapper_constants_for_dispatcher(
                        region,
                        dispatcher_start,
                        dispatcher_args,
                    )
                )
                is not None
                and int(constants[0]) == selector
            )
        )
    )
    if not registration_targets or (
        wrapper_start != dispatcher_start and wrapper_start not in registration_targets
    ):
        raise NativePortraitAcceptanceError(
            "目标活动 selector 没有完整的原生角色注册函数集合"
        )
    registration_argument_counts = {
        int(target): int(layout.runtime_count) for target in registration_targets
    }
    registration_argument_counts[int(dispatcher_start)] = int(dispatcher_args)
    form_suffixes, form_suffix_evidence = _normal_form_suffixes(
        dispatcher,
        layout=layout,
    )
    cache_guard = _selector_cache_guard(
        dispatcher,
        selector=selector,
        resource_root_offset=int(root_literal.offset),
        layout=layout,
    )
    state_isolation = _selector_state_isolation(
        dispatcher,
        selector=selector,
        resource_root_offset=int(root_literal.offset),
        cache_global_id=int(cache_guard["global_id"]),
        layout=layout,
    )
    pre_scene_clear = _selector_pre_scene_clear_evidence(
        analysis_document,
        source_document,
        selector=selector,
        clear_target=clear_target,
        apply_target=apply_target,
        apply_argument_count=apply_argument_count,
    )

    try:
        native_width, native_height, resolution_functions = _native_resolution(
            spans, int(analysis_document.header.game_mode)
        )
        resolution_evidence: Mapping[str, Any] = {
            "schema": "fvp-studio-v2.target-mode-table-resolution.v1",
            "source": "adjacent_native_mode_table_functions",
            "game_mode": int(analysis_document.header.game_mode),
            "selected_size": [int(native_width), int(native_height)],
            "resolution_functions": list(resolution_functions),
            "game_name_switch_used": False,
        }
    except NativePortraitAcceptanceError as mode_table_error:
        if engine_variant not in {"old_fvp", "legacy_fvp"}:
            raise
        try:
            native_width, native_height, resolution_evidence = (
                _profile_background_resolution(
                    target_visual_assets or (),
                    archive_name=resource_archive_name,
                )
            )
        except NativePortraitAcceptanceError as profile_error:
            raise NativePortraitAcceptanceError(
                "目标旧版既没有唯一原生宽高模式表，也没有充分的目标背景尺寸证据："
                f"{profile_error}"
            ) from mode_table_error
        resolution_functions = ()
    if geometry_mode == "direct_xy_wrapper":
        assert direct_start is not None and direct_end is not None
        direct_region = _instructions_in_range(
            analysis_document, direct_start, direct_end
        )
        x_scale, y_scale = _extract_direct_xy_scales(
            direct_region, analysis_document.syscall_names
        )
        native_pivots, pivot_evidence = _native_form_pivots(
            dispatcher,
            spans,
            selector=selector,
            action_code=1,
            outfit_code=outfit_code,
            expression_code=original_expression,
            form_codes=form_suffixes,
            logical_x_scale=x_scale,
            logical_y_scale=y_scale,
            layout=layout,
        )
        camera_z, v3d_setter = _camera_z(
            spans,
            analysis_document.syscall_names,
            x_scale,
            y_scale,
        )
        camera = (0, 0, int(camera_z))
        camera_evidence: Mapping[str, Any] = {
            "schema": "fvp-studio-v2.wrapped-v3d-camera.v1",
            "source": "verified_v3dset_coordinate_wrapper_default",
            "camera": list(camera),
            "setter_function": v3d_setter,
            "game_name_switch_used": False,
        }
        geometry_converter = _geometry_converter(
            logical_x_scale=x_scale,
            logical_y_scale=y_scale,
            native_width=native_width,
            native_height=native_height,
            camera_z=camera_z,
            native_pivots=native_pivots,
        )
    else:
        x_scale, y_scale = 1.0, 1.0
        native_pivots, pivot_evidence = _embedded_native_form_pivots(
            dispatcher,
            analysis_document.syscall_names,
            selector=selector,
            action_code=1,
            outfit_code=outfit_code,
            expression_code=original_expression,
            form_codes=form_suffixes,
            layout=layout,
        )
        camera, camera_evidence = _embedded_v3d_camera(
            spans,
            analysis_document.syscall_names,
            anchor_offset=int(anchor_offset),
        )
        camera_z = int(camera[2])
        v3d_setter = None
        geometry_converter = _embedded_xy_geometry_converter(
            native_width=native_width,
            native_height=native_height,
            camera=camera,
            native_pivots=native_pivots,
        )
    target_id = str(discovery.get("target_id") or "").strip()
    if not target_id:
        raise NativePortraitAcceptanceError("目标发现报告缺少 target_id")
    identity = hashlib.sha256(
        (
            target_id
            + source_document.source_sha256
            + _sha256(target_graph_bs)
            + str(selector)
        ).encode("ascii")
    ).hexdigest()[:16]
    profile_id = f"fvp-native-portrait-acceptance-{identity}"
    slot_id = f"selector{selector}"
    source_symbol = "native_portrait_dispatcher"
    output_symbol = f"native_portrait_dispatcher_{slot_id}"
    apply_symbol = "native_portrait_apply"
    recipe = PrivateDispatcherRecipe(
        recipe_id=f"{profile_id}-{slot_id}-clone",
        output_symbol=output_symbol,
        source_symbol=source_symbol,
        carrier_selector=selector,
        literal_patches=(
            LiteralPatchTemplate(
                int(root_literal.offset),
                str(root_literal.text),
                "resource_base",
            ),
            LiteralPatchTemplate(
                int(outfit_literal.offset),
                outfit_expected,
                "outfit_suffix",
            ),
        ),
    )
    target_symbols = {
        source_symbol: dispatcher_start,
        apply_symbol: apply_target,
    }
    if direct_start is not None:
        target_symbols["function_4286_"] = direct_start
    target_profile = HoshimemoTargetProfile(
        profile_id=profile_id,
        hcb=BinaryFingerprint.from_bytes(source_document.original_bytes),
        graph_bs=BinaryFingerprint.from_bytes(target_graph_bs),
        portrait_dispatcher=CodeRegionFingerprint.from_bytes(
            source_document.original_bytes,
            dispatcher_start,
            dispatcher_end,
            args=dispatcher_args,
            locals=dispatcher_locals,
        ),
        symbols=target_symbols,
        slots=(
            HoshimemoPortraitSlot(
                slot_id=slot_id,
                selector=selector,
                primitive_ids=primitive_ids,
                dispatcher_symbol=output_symbol,
                kind="private_clone",
                clone_recipe_id=recipe.recipe_id,
                allocation_rank=10,
            ),
        ),
        clone_recipes=(recipe,),
        native_layout_symbols=(apply_symbol,),
        portrait_archive_name=resource_archive_name,
        portrait_resource_namespace=resource_namespace,
        static_xy_mode=(
            "function_4286"
            if geometry_mode == "direct_xy_wrapper"
            else "primsetxy_syscall"
        ),
    )
    backend_profile = HoshimemoPortraitBackendProfile(
        profile_id=profile_id,
        portrait_abi=(
            "resource4_runtime8"
            if dispatcher_args == 12
            else "resource4_runtime9"
        ),
        apply_layout_symbol=apply_symbol,
        final_transform_symbol="native_primitive_state",
        opacity_symbol="native_primitive_state",
        rotation_symbol="native_primitive_state",
        expression_update_symbol="native_portrait_expression_unavailable",
        geometry_xy_symbol=(
            "function_4286_"
            if geometry_mode == "direct_xy_wrapper"
            else "native_primitive_state"
        ),
        geometry_z_symbol="native_primitive_state",
        geometry_scale_symbol="native_primitive_state",
    )
    report = {
        "schema": NATIVE_PORTRAIT_ACCEPTANCE_SCHEMA,
        "target_id": target_id,
        "profile_id": profile_id,
        "source_hcb_sha256": source_document.source_sha256,
        "analysis_hcb_sha256": analysis_document.source_sha256,
        "resource_archive_name": resource_archive_name,
        "resource_archive_sha256": _sha256(target_graph_bs),
        "graph_bs_sha256": _sha256(target_graph_bs),
        "hzc_alpha_storage": {
            **hzc_alpha_evidence,
            "compile_target": target_hzc_alpha_storage,
            "game_name_switch_used": False,
        },
        "dispatcher": {
            "range": [dispatcher_start, dispatcher_end],
            "sha256": _sha256(
                source_document.original_bytes[dispatcher_start:dispatcher_end]
            ),
            "args": dispatcher_args,
            "locals": dispatcher_locals,
            "portrait_abi": (
                "resource4_runtime8"
                if dispatcher_args == 12
                else "resource4_runtime9"
            ),
        },
        "active_native_call": {
            "anchor_offset": int(anchor_offset),
            "hook_return_offset": (
                None if hook_return_offset is None else int(hook_return_offset)
            ),
            "call_kind": (
                "direct_dispatcher"
                if wrapper_start == dispatcher_start
                else "registration_wrapper"
            ),
            "wrapper_start": wrapper_start,
            "wrapper_call": wrapper_call,
            "apply_call": apply_call,
            "resource_args": list(wrapper_constants),
        },
        "carrier": {
            "selector": selector,
            "primitive_ids": list(primitive_ids),
            "resource_root_offset": int(root_literal.offset),
            "resource_root_expected": str(root_literal.text),
            "action_code": 1,
            "action_suffix": action_suffix,
            "outfit_code": outfit_code,
            "outfit_expected": outfit_expected,
            "original_action": original_action,
            "original_outfit": original_outfit,
            "original_expression": original_expression,
            "form_suffixes": dict(form_suffixes),
            "form_suffix_evidence": dict(form_suffix_evidence),
        },
        "geometry": {
            "mode": geometry_mode,
            "direct_xy_range": (
                [direct_start, direct_end]
                if direct_start is not None and direct_end is not None
                else None
            ),
            "logical_xy_scale": [x_scale, y_scale],
            "native_size": [native_width, native_height],
            "resolution_functions": list(resolution_functions),
            "resolution_evidence": dict(resolution_evidence),
            "v3d_setter": v3d_setter,
            "camera_z": camera_z,
            "v3d_camera": list(camera),
            "camera_evidence": dict(camera_evidence),
            "pivots": {
                str(form_code): list(pivot)
                for form_code, pivot in sorted(native_pivots.items())
            },
            "pivot_evidence": dict(pivot_evidence),
        },
        "lifecycle": {
            "clear_target": clear_target,
            "apply_target": apply_target,
            "apply_argument_count": apply_argument_count,
            "pre_scene_clear": dict(pre_scene_clear),
            "registration_argument_count": layout.runtime_count,
            "direct_registration_argument_count": dispatcher_args,
            "direct_registration_target": dispatcher_start,
            "registration_target_count": len(registration_targets),
            "registration_targets_sha256": hashlib.sha256(
                ",".join(str(value) for value in registration_targets).encode("ascii")
            ).hexdigest(),
            "active_wrapper_target": wrapper_start,
        },
        "cache_guard": dict(cache_guard),
        "state_isolation": dict(state_isolation),
        "rules": {
            "engine_variant": engine_variant,
            "resource_namespace": resource_namespace,
            "resource_archive_name": resource_archive_name,
            "game_name_switch_used": False,
            "source_dispatcher_cloned_at_eof": True,
            "original_resources_replaced": False,
            "single_active_selector_acceptance": True,
            "exact_source_fingerprints_required": True,
        },
    }
    compile_target = VisualScenePortraitTarget(
        target_profile=target_profile,
        backend_profile=backend_profile,
        outfit_codes={slot_id: outfit_code},
        geometry_converter=geometry_converter,
        form_suffixes=form_suffixes,
        action_suffix=action_suffix,
        hzc_alpha_storage=target_hzc_alpha_storage,
        evidence=report,
    )
    return NativePortraitAcceptanceProfile(
        compile_target=compile_target,
        clear_target=clear_target,
        apply_target=apply_target,
        apply_argument_count=apply_argument_count,
        registration_argument_count=layout.runtime_count,
        registration_targets=registration_targets,
        registration_argument_counts=registration_argument_counts,
        selector=selector,
        primitive_ids=primitive_ids,
        report=report,
    )


__all__ = [
    "NATIVE_PORTRAIT_ACCEPTANCE_SCHEMA",
    "NativePortraitAcceptanceError",
    "NativePortraitAcceptanceProfile",
    "build_native_portrait_acceptance_profile",
]
