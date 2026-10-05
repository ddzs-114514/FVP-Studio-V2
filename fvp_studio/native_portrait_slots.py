"""Native multi-actor ownership discovery, without borrowing Hoshi slot IDs.

A distinct resource name is NOT proof of a distinct Parts/Graph handle. This
module extracts selector/primitive/global ownership and emits exact native
clear/snapshot bytes. Rendering remains gated until the Parts loading chain is
also bound; this is not permission to lift the GUI portrait-output restriction.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from itertools import combinations
from typing import Mapping

from .hcb import HcbDocument
from .hoshimemo_scene_hook import _arguments, _pop_global, _push_global
from .native_call_flow import NativeFunctionFlow
from .native_portrait_carriers import carrier_layout, plain_carrier_constants, carrier_lifecycle_targets
from .native_portrait_handles import extract_dispatcher_handles, handles_conflict
from .native_script_state import NativeScriptStateClosure
from .native_target_discovery import (
    _function_regions, _native_clear_apply_sequences, _native_clear_apply_batches,
)
from .native_portrait_acceptance import (
    NativePortraitAcceptanceError, _function_spans,
    _instructions_in_range,
    _integer_value,
    _region_from_discovery, _selector_branch, _selector_cache_guard,
    _selector_pre_scene_clear_evidence, _selector_state_isolation,
)


SCHEMA = "fvp-native-portrait-slot-ownership/1"


def _registration_constants(span, dispatcher, argc):
    """Recognise a plain carrier or an exact native on/off guarded carrier.

    Older wrappers surround the otherwise identical four-constant forwarder
    with a literal global flag. Keep that flag as an explicit dependency; do
    not pretend the source wrapper was plain, or compile its side effects here.
    """
    constants = plain_carrier_constants(span, dispatcher, argc)
    if constants is not None:
        return constants, None
    body = span.instructions
    if (len(body) < 9 or _integer_value(body[1]) != 1
            or body[2].mnemonic != "pop_global"):
        return None, None
    tail = len(body)
    while tail > 0 and body[tail - 1].mnemonic == "ret":
        tail -= 1
    if (tail < 4 or _integer_value(body[tail - 2]) != 0
            or body[tail - 1].mnemonic != "pop_global"
            or body[tail - 1].operands != body[2].operands):
        return None, None
    # Only the two exact flag writes are removed from this analysis view. The
    # actual registration function remains byte-bound in full, including them.
    inner = replace(span, instructions=(body[0], *body[3:tail - 2], *body[tail:]))
    constants = plain_carrier_constants(inner, dispatcher, argc)
    if constants is None:
        return None, None
    return constants, dict(global_id=int(body[2].operands["value"]),
                           entry_value=1, exit_value=0,
                           entry_write_offset=body[2].offset,
                           exit_write_offset=body[tail - 1].offset,
                           side_effects_compiled=False)


@dataclass(frozen=True)
class NativePortraitSlot:
    selector: int
    primitive_ids: tuple[int, int]
    global_ids: tuple[int, ...]
    read_global_ids: tuple[int, ...]
    cache_global_id: int
    evidence: Mapping

    def __post_init__(self):
        if type(self.selector) is not int or self.selector < 0:
            raise NativePortraitAcceptanceError("原生角色 selector 无效。")
        if (len(self.primitive_ids) != 2 or len(set(self.primitive_ids)) != 2
                or any(type(x) is not int or x < 0 for x in self.primitive_ids)):
            raise NativePortraitAcceptanceError("原生角色须有两个独立图元。")
        for values in (self.global_ids, self.read_global_ids):
            if values != tuple(sorted(set(values))) or any(type(x) is not int or not 0 <= x <= 65535 for x in values):
                raise NativePortraitAcceptanceError("原生角色状态变量列表无效。")
        if not self.global_ids or self.cache_global_id not in self.global_ids:
            raise NativePortraitAcceptanceError("原生角色缓存不在状态变量集合中。")


def slots_conflict(left, right):
    """Check handles AND cross-selector write/read interference."""
    left_handles = left.evidence.get("dispatcher_handles")
    right_handles = right.evidence.get("dispatcher_handles")
    resource_conflict = bool(left_handles and right_handles and handles_conflict(left_handles, right_handles))
    return (left.selector == right.selector
        or resource_conflict
        or bool(set(left.primitive_ids) & set(right.primitive_ids))
        or bool(set(left.global_ids) & (set(right.global_ids) | set(right.read_global_ids)))
        or bool(set(right.global_ids) & set(left.read_global_ids)))


def _native_cleanup_plan(selected):
    """Exact-cover cleanup: no foreign actor or repeated overlapping batch."""
    selectors = {x.selector for x in selected}
    options = []
    seen = set()
    for slot in selected:
        if slot.evidence.get("native_clear_hex"):
            options.append(dict(selectors=[slot.selector], native_clear_hex=slot.evidence["native_clear_hex"]))
        for batch in slot.evidence.get("native_clear_batches", ()):
            key = (batch["start"], batch["end"])
            if key not in seen and set(batch["selectors"]).issubset(selectors):
                seen.add(key)
                options.append(batch)

    def cover(remaining):
        if not remaining:
            return []
        first = min(remaining)
        for option in sorted(options, key=lambda x: (len(x["selectors"]), x.get("start", -1))):
            members = set(option["selectors"])
            if first in members and members.issubset(remaining):
                rest = cover(remaining - members)
                if rest is not None:
                    return [option, *rest]
        return None

    return cover(selectors)


def allocate_native_slots(slots, actor_ids):
    actors = tuple(actor_ids)
    if not 1 <= len(actors) <= 4 or any(not isinstance(x, str) or not x for x in actors):
        raise NativePortraitAcceptanceError("舞台角色数量须为 1～4，且必须有稳定身份。")
    if len(set(actors)) != len(actors):
        raise NativePortraitAcceptanceError("舞台角色身份重复。")
    ordered = tuple(sorted(slots, key=lambda x: x.selector))
    # A greedy first-slot choice can unnecessarily exclude a valid four-way
    # allocation. The selector set is small; exhaust combinations up to four.
    for selected in combinations(ordered, len(actors)):
        if (not any(slots_conflict(a, b) for a, b in combinations(selected, 2))
                and _native_cleanup_plan(selected) is not None):
            return dict(zip(actors, selected))
    raise NativePortraitAcceptanceError("没有足够的独立原生角色槽；不会复用槽位覆盖其他角色。")


class NativePortraitSlots:
    def __init__(self, source: HcbDocument, analysis: HcbDocument, discovery, *,
                 with_handle_flow=False, runtime_context=None):
        if not isinstance(source, HcbDocument) or not isinstance(analysis, HcbDocument):
            raise NativePortraitAcceptanceError("角色槽提取缺少目标 HCB。")
        from .native_script_state import validate_native_script_pair
        self._runtime_binding_report = validate_native_script_pair(
            source, analysis, runtime_context=runtime_context)
        self._runtime_context = runtime_context
        if [(s.name, s.args) for s in source.header.syscalls] != [(s.name, s.args) for s in analysis.header.syscalls]:
            raise NativePortraitAcceptanceError("运行/分析 HCB 的原生系统调用表不一致。")
        if (source.header.non_volatile_globals, source.header.volatile_globals) != (analysis.header.non_volatile_globals, analysis.header.volatile_globals):
            raise NativePortraitAcceptanceError("运行/分析 HCB 的状态变量声明不一致。")
        record = _region_from_discovery(discovery, "portrait_dispatcher")
        start, end, argc = (int(record[x]) for x in ("start", "end", "args"))
        layout = carrier_layout(argc)
        spans = _function_spans(analysis)
        by_start = {x.start: x for x in spans}
        clear, apply, apply_count = carrier_lifecycle_targets(discovery)
        self._dependencies = {}
        for address in (start, clear, apply):
            span = by_start.get(address)
            expected_argc = argc if address == start else (2 if address == clear else apply_count)
            if span is None or span.args != expected_argc or (address == start and span.end != end):
                raise NativePortraitAcceptanceError("角色槽生命周期不是原生函数入口。")
            raw = analysis.original_bytes[span.start:span.end]
            if source.original_bytes[span.start:span.end] != raw:
                raise NativePortraitAcceptanceError("运行/分析 HCB 的立绘生命周期函数已漂移。")
            self._dependencies[address] = (span.end, raw)
        lifecycle = _region_from_discovery(discovery, "portrait_lifecycle_family")
        for delegate in lifecycle.get("delegates", {}).values():
            if not delegate:
                continue
            address = int(delegate["start"])
            span = by_start.get(address)
            if span is None or span.end != int(delegate["end"]) or span.args != int(delegate["args"]):
                raise NativePortraitAcceptanceError("原生清场依赖不是已识别的函数。")
            raw = analysis.original_bytes[span.start:span.end]
            if source.original_bytes[span.start:span.end] != raw:
                raise NativePortraitAcceptanceError("运行／分析 HCB 的清场依赖已漂移。")
            self._dependencies[address] = (span.end, raw)
        dispatcher = _instructions_in_range(analysis, start, end)
        handle_flow = NativeFunctionFlow(analysis) if with_handle_flow else None
        regions = _function_regions(analysis) if apply_count == 4 else ()
        four_argument_clears = (_native_clear_apply_sequences(analysis, regions,
            clear_target=clear, apply_target=apply, apply_argument_count=4) if apply_count == 4 else [])
        native_batches = (_native_clear_apply_batches(analysis, regions,
            clear_target=clear, apply_target=apply, apply_argument_count=4) if apply_count == 4 else [])
        for batch in native_batches:
            raw = analysis.original_bytes[batch["start"]:batch["end"]]
            if source.original_bytes[batch["start"]:batch["end"]] != raw:
                raise NativePortraitAcceptanceError("原生批量清场序列在运行／分析 HCB 间漂移。")
            batch["native_clear_hex"] = raw.hex()
        if source.original_bytes[start:end] != analysis.original_bytes[start:end]:
            raise NativePortraitAcceptanceError("原生立绘 dispatcher 已漂移。")
        wrappers = {}
        guards = {}
        for span in spans:
            constants, guard = _registration_constants(span, start, argc)
            if constants is not None:
                wrappers.setdefault(constants[0], []).append(span)
                if guard is not None:
                    guards.setdefault(constants[0], []).append(dict(function=span.start, **guard))
        self.slots, self.rejected = [], []
        total_globals = source.header.non_volatile_globals + source.header.volatile_globals
        for selector, registrations in sorted(wrappers.items()):
            try:
                for span in registrations:
                    raw = analysis.original_bytes[span.start:span.end]
                    if source.original_bytes[span.start:span.end] != raw:
                        raise NativePortraitAcceptanceError("原生角色注册函数已漂移。")
                root, _outfit, pair, _action, _outfit_code, _outfit_text = _selector_branch(
                    dispatcher, selector, resource_namespace=record["resource_namespace"], layout=layout)
                cache = _selector_cache_guard(dispatcher, selector=selector,
                    resource_root_offset=root.offset, layout=layout)
                state = _selector_state_isolation(dispatcher, selector=selector,
                    resource_root_offset=root.offset, cache_global_id=cache["global_id"], layout=layout)
                batches = [x for x in native_batches if selector in x["selectors"]]
                native_clear = b""
                if apply_count == 4:
                    sites = [x for x in four_argument_clears if x["selector"] == selector]
                    if not sites and not batches:
                        raise NativePortraitAcceptanceError("角色没有原生四参数即时清场序列。")
                    if any(source.original_bytes[x["start"]:x["end"]] != analysis.original_bytes[x["start"]:x["end"]] for x in sites):
                        raise NativePortraitAcceptanceError("原生四参数清场序列在运行／分析 HCB 间漂移。")
                    pre_clear = dict(selector=selector, clear_target=clear, apply_target=apply,
                        apply_argument_count=4, clear_arguments=[selector, None], apply_arguments=[None] * 4,
                        source_sequence_offsets=[x["start"] for x in sites],
                        source_apply_offsets=[x["apply_call_offset"] for x in sites],
                        source_sequence_count=len(sites), strategy="exact_four_argument_native_clear_apply")
                    if not sites:
                        pre_clear = dict(selector=selector, clear_target=clear, apply_target=apply,
                            apply_argument_count=4, source_sequence_count=0,
                            strategy="whole_batch_only_no_individual_clear_evidence")
                else:
                    pre_clear = _selector_pre_scene_clear_evidence(analysis, source, selector=selector,
                        clear_target=clear, apply_target=apply, apply_argument_count=apply_count)
                if pre_clear.get("source_sequence_count"):
                    clear_start = pre_clear["source_sequence_offsets"][0]
                    clear_call = analysis.find(pre_clear["source_apply_offsets"][0])
                    native_clear = source.original_bytes[clear_start:clear_call.offset + clear_call.size]
                binding = None
                if with_handle_flow:
                    binding, dependencies = extract_dispatcher_handles(source, analysis, record,
                        selector=selector, primitive_ids=pair, action_code=1,
                        outfit_code=_outfit_code, flow=handle_flow)
                    self._dependencies.update(dependencies)
                binding_globals = set(binding["binding_global_ids"]) if binding else set()
                globals_ = tuple(sorted(set(state["global_ids"]) | binding_globals))
                reads = tuple(sorted({int(x) for x in state["global_read_offsets"]} | binding_globals))
                if any(x < 0 or x >= total_globals for x in (*globals_, *reads)):
                    raise NativePortraitAcceptanceError("角色状态变量越过 HCB 声明范围。")
                evidence = dict(resource_root=str(root.text), cache_guard=dict(cache),
                    state_isolation=dict(state), pre_scene_clear=dict(pre_clear),
                    native_clear_hex=native_clear.hex(),
                    registration_functions=[x.start for x in registrations])
                if batches:
                    evidence["native_clear_batches"] = batches
                    evidence["individual_clear_supported"] = bool(native_clear)
                if selector in guards:
                    if any(not 0 <= g["global_id"] < total_globals for g in guards[selector]):
                        raise NativePortraitAcceptanceError("原生注册函数的全局开关越过声明范围。")
                    evidence["registration_guards"] = guards[selector]
                if binding:
                    evidence["dispatcher_handles"] = binding
                self.slots.append(NativePortraitSlot(selector, pair, globals_, reads, cache["global_id"], evidence))
                for span in registrations:
                    self._dependencies[span.start] = (span.end, analysis.original_bytes[span.start:span.end])
            except NativePortraitAcceptanceError as exc:
                self.rejected.append(dict(selector=selector, reason=str(exc)))
        self.source_sha256 = source.source_sha256
        self.analysis_sha256 = analysis.source_sha256
        self._source_bytes = source.original_bytes
        self.clear_target, self.apply_target, self.apply_count = clear, apply, apply_count
        self.with_handle_flow = bool(with_handle_flow)
        self._state_closure = (NativeScriptStateClosure(source, analysis, [start, clear, apply],
                               runtime_context=runtime_context)
                               if with_handle_flow else None)
        if self._state_closure:
            self._dependencies.update(self._state_closure.dependencies)

    def describe(self):
        capacity = 0
        for count in range(1, min(4, len(self.slots)) + 1):
            try:
                allocate_native_slots(self.slots, ["actor" + str(i) for i in range(count)])
                capacity = count
            except NativePortraitAcceptanceError:
                continue  # A batch-only family can have two slots but no single-slot cleanup.
        return dict(schema=SCHEMA, source_sha256=self.source_sha256,
            analysis_sha256=self.analysis_sha256,
            runtime_binding=getattr(self, "_runtime_binding_report", None),
            independent_selector_capacity=capacity,
            slot_candidates=[dict(selector=s.selector, primitive_ids=list(s.primitive_ids),
                global_ids=list(s.global_ids), read_global_ids=list(s.read_global_ids),
                cache_global_id=s.cache_global_id, evidence=dict(s.evidence)) for s in self.slots],
            rejected=list(self.rejected), game_name_switch_used=False,
            dispatcher_handle_flow_requested=self.with_handle_flow,
            dispatcher_resource_handle_capacity=capacity if self.with_handle_flow else None,
            extracted_capacity_is_not_engine_limit=True,
            script_state_closure=self._state_closure.describe() if self._state_closure else None,
            parts_ownership_verified=False, hcb_rendering_ready=False,
            runtime_verified=False, writes_performed=False,
            remaining=("资源槽参数已提取，尚需接生命周期副作用、加载编译与实机显示。"
                       if self.with_handle_flow else "尚需证明每个 selector 的 Graph/Parts 句柄绑定并接入身体/表情加载。"))

    def compile_lifecycle(self, document, actor_ids):
        assignments = allocate_native_slots(self.slots, actor_ids)
        return self.compile_bound_lifecycle(document, assignments)

    def compile_bound_lifecycle(self, document, assignments):
        """Clear an allocated actor subset without reallocating its carriers.

        Batch-only clear sequences remain indivisible: callers must explicitly
        include every member, never an implicit extra actor. Shared snapshots
        describe scene scope, not independent engine-image restoration.
        """
        return self._compile_lifecycle(document, assignments)

    def compile_known_entry_lifecycle(self, document):
        """Clear ALL catalogued inherited selectors, not an actor allocation.

        A source can have more native selectors than the editor's four actors,
        and alias selectors must also be cleared before the new scene loads.
        This whole-scene transaction makes no disjoint-actor ownership claim.
        The ordinary bound-actor cleanup remains restricted and unchanged.
        """
        if not 1 <= len(self.slots) <= 64:
            raise NativePortraitAcceptanceError("原生开场清场的角色槽数量未限定。")
        return self._compile_lifecycle(document,
            {"entry_selector_" + str(s.selector): s for s in self.slots}, entry_all=True)

    def _compile_lifecycle(self, document, assignments, *, entry_all=False):
        if document.source_sha256 != self.source_sha256 or document.original_bytes != self._source_bytes:
            raise NativePortraitAcceptanceError("角色槽属于另一份目标 HCB。")
        if (not isinstance(assignments, Mapping) or not 1 <= len(assignments) <= (64 if entry_all else 4)
                or any(not isinstance(a, str) or not a for a in assignments)
                or any(not any(slot is original for original in self.slots)
                       for slot in assignments.values())):
            raise NativePortraitAcceptanceError("退场需要当前目录中已经分配的稳定角色槽。")
        assignments = dict(assignments)
        selected = list(assignments.values())
        conflicting = any(slots_conflict(a, b) for a, b in combinations(selected, 2))
        if conflicting and not entry_all:
            raise NativePortraitAcceptanceError("退场角色的原生槽位互相冲突。")
        cleanup_plan = _native_cleanup_plan(selected)
        if cleanup_plan is None:
            raise NativePortraitAcceptanceError("该角色只有成组原生清场；请显式选择同组角色，不会连带清除其他角色。")
        closure = getattr(self, "_state_closure", None)
        selector_globals = {x for slot in selected for x in slot.global_ids}
        guard_globals = {g["global_id"] for slot in selected
                         for g in slot.evidence.get("registration_guards", ())}
        # Callees may write globals outside the selected dispatcher branch.
        # Keep these at scene scope, not in an actor's independence claim.
        globals_ = sorted(selector_globals | guard_globals | (set(closure.global_ids) if closure else set()))
        snapshot = b"".join(_push_global(x) for x in globals_)
        restore = b"".join(_pop_global(x) for x in reversed(globals_))
        # Batch-only slots may be cleaned only together with every member of
        # that exact original transaction. Never split it or replace its modes.
        cleanup_codes, batches_used = [], []
        for cleanup in cleanup_plan:
            raw = bytes.fromhex(cleanup["native_clear_hex"])
            if len(cleanup["selectors"]) > 1:
                if (raw != document.original_bytes[cleanup["start"]:cleanup["end"]]
                        or hashlib.sha256(raw).hexdigest() != cleanup["byte_sha256"]):
                    raise NativePortraitAcceptanceError("原生批量清场证据已漂移。")
                batches_used.append(dict(selectors=cleanup["selectors"], start=cleanup["start"],
                    byte_sha256=cleanup["byte_sha256"], clears=cleanup["clears"]))
            cleanup_codes.append(raw)
        clear = b"".join(cleanup_codes)
        rearm = b"".join(_arguments([None]) + _pop_global(slot.cache_global_id) for slot in selected)
        report = dict(schema=SCHEMA, assignments={a: s.selector for a, s in assignments.items()},
            existing_assignments_preserved=True, subset_reallocated=False,
            whole_known_entry_cleanup=entry_all, editor_actor_limit_changed=False,
            all_catalogued_selectors_included=entry_all,
            global_ids=globals_, operand_stack_value_count=len(globals_),
            script_callee_writes_included=closure is not None,
            shared_scene_global_ids=sorted(set(globals_) - selector_globals - guard_globals),
            global_snapshot_scope="conservative_script_closure" if closure else "selected_dispatcher_fields_only",
            engine_resource_restoration_proven=False,
            header_unchanged=True, exact_native_clear_sequences_repeated=True,
            whole_native_batches_preserved=batches_used,
            unselected_selectors_explicitly_cleared=False,
            callee_effects_on_unselected_selectors_verified=False,
            individual_clear_selectors=[slot.selector for slot in selected if slot.evidence.get("native_clear_hex")],
            primitives_and_global_accesses_disjoint=not conflicting, parts_ownership_verified=False,
            dispatcher_resource_handles_disjoint=all(slot.evidence.get("dispatcher_handles", {}).get(
                "dispatcher_handles_verified", False) for slot in selected),
            registration_guard_side_effects_compiled=False,
            registration_guard_global_ids=sorted(guard_globals),
            registration_guard_values_snapshotted=True,
            hcb_rendering_ready=False, runtime_verified=False,
            code_sha256={name: hashlib.sha256(code).hexdigest() for name, code in
                         (("snapshot", snapshot), ("restore", restore), ("clear", clear), ("rearm", rearm))})
        return dict(snapshot=snapshot, restore=restore, clear=clear, rearm=rearm, report=report)
