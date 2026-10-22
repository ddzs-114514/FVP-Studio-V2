"""Conditional old-resource retention across a complete native carrier.

The two buffer orientations are derived from this target's own branch and
Graph/Parts/Sprite argument flow. The emitted predicate MUST be checked before
the carrier's cache/registration writes. It is not enough to check the pair
after loading, when an incorrectly selected old resource could be overwritten.

This proves the carrier call chain does not replace the old Graph, Parts or
sprite binding under that predicate. A separate conditional proof inventories
R/S2 setters, motion starts and stops on the old primitive. It does not own
concurrent engine threads or already-running motions, promise unchanged
group/visual state, or enable public scene body fades.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .hoshimemo_scene_hook import _arguments, _call, _push_global
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import NativePortraitAcceptanceError, _integer_value, _selector_branch
from .native_portrait_handles import _integer_values
from .native_script_state import NativeScriptStateClosure


SCHEMA = "fvp-native-portrait-carrier-retention/1"
RESOURCE_CALLS = {"GraphLoad": 2, "PartsLoad": 2, "PartsAssign": 2,
                  "PrimSetSprt": 4, "PrimSetNull": 1}
ROTATION_SCALE_CALLS = {"PrimSetRS": 3, "PrimSetRS2": 4, "MotionMoveR": 6,
                      "MotionMoveS2": 8, "MotionMoveRStop": 1, "MotionMoveS2Stop": 1}
# These cannot load/free Graph/Parts or replace a sprite binding. Their visual
# and scheduling effects are deliberately NOT claimed to be harmless: the
# scene/thread ownership gate remains separate. Unknown syscalls fail closed.
NON_RESOURCE_CALLS = {
    "FloatToInt": (1,), "PartsSelect": (2,), "PartsMotion": (3,), "PartsMotionTest": (1,),
    "PrimSetOP": (3,), "PrimSetXY": (3,), "PrimSetZ": (2,), "PrimSetRS": (3,),
    "PrimSetRS2": (4,), "PrimSetAlpha": (2,), "PrimSetDraw": (2,),
    "PrimGroupIn": (2,), "PrimGroupOut": (1,), "GraphRGB": (4,), "PartsRGB": (4,),
    "MotionAlpha": (5, 6), "MotionAlphaTest": (1,), "MotionAlphaStop": (1,),
    "MotionMove": (8,), "MotionMoveTest": (1,), "MotionMoveStop": (1,),
    "MotionMoveZ": (6,), "MotionMoveZTest": (1,), "MotionMoveZStop": (1,),
    "MotionMoveR": (6,), "MotionMoveRTest": (1,), "MotionMoveRStop": (1,),
    "MotionMoveR": (6,), "MotionMoveRTest": (1,), "MotionMoveRStop": (1,),
    "MotionMoveS2": (8,), "MotionMoveS2Test": (1,), "MotionMoveS2Stop": (1,),
    "ThreadNext": (0,), "ThreadWait": (1,),
}


@dataclass(frozen=True)
class NativePortraitCarrierRetentionPlan:
    precondition_code: bytes
    _report: dict
    _owner: object
    _stamp: tuple

    def report(self):
        return deepcopy(self._report)


def _buffer_flags(body, primitives):
    """Find actual conditional literal buffer assignments, not fixed offsets."""
    by_offset = {i.offset: n for n, i in enumerate(body)}
    result = set()
    for n, item in enumerate(body):
        if item.mnemonic != "jz" or n + 2 >= len(body):
            continue
        other = by_offset.get(item.operands["target"])
        if other is None or other + 1 >= len(body):
            continue
        left, right = body[n+1:n+3], body[other:other+2]
        if (left[1].mnemonic != "pop_stack" or right[1].mnemonic != "pop_stack"
                or left[1].operands != right[1].operands
                or {_integer_value(left[0]), _integer_value(right[0])} != set(primitives)):
            continue
        # Only the two observed source shapes are candidate generators. The
        # complete function flow below, not this local shape, proves each arm.
        condition = None
        integers = {"push_i8", "push_i16", "push_i32"}
        if (n >= 3 and body[n-3].mnemonic == "push_global"
                and body[n-2].mnemonic in integers and body[n-1].mnemonic == "set_e"):
            condition = body[n-3:n]
        elif (n >= 7 and [x.mnemonic for x in body[n-7:n-3]] == [
                "push_global", "push_nil", "set_e", "push_global"]
                and body[n-3].mnemonic in integers
                and [x.mnemonic for x in body[n-2:n]] == ["set_e", "or"]):
            condition = body[n-7:n]
        if condition is not None:
            globals_ = {x.operands["value"] for x in condition if x.mnemonic == "push_global"}
            literals = [x.operands["value"] for x in condition if x.mnemonic in integers]
            if len(globals_) == 1 and literals and all(type(v) is int and v in (0, 1) for v in literals):
                result.update(globals_)
    return sorted(result)


def _literal_arguments(arguments):
    """Specialize exact scalar operands only; never guess call/global results."""
    result = {}
    for n, value in enumerate(arguments):
        if value.get("kind") == "literal" and (value.get("value") is None
                or type(value.get("value")) in (int, bool, str)):
            result[n] = value["value"]
        else:
            try:
                values = _integer_values(value)
            except NativePortraitAcceptanceError:
                continue
            if len(values) == 1:
                result[n] = next(iter(values))
    return result


class NativePortraitCarrierRetention:
    def __init__(self, loader, actor_id, *, catalogue_only=False):
        from .native_portrait_loading import NativePortraitLoading
        if (type(catalogue_only) is not bool or not isinstance(loader, NativePortraitLoading)
                or actor_id not in loader.assignments
                or not catalogue_only and actor_id not in loader._active):
            raise NativePortraitAcceptanceError("换装资源保护需要已在场的角色。")
        self.loader, self.actor_id = loader, actor_id
        self.slot = loader.assignments[actor_id] if catalogue_only else loader._active[actor_id]["slot"]
        proof = self.slot.evidence["dispatcher_handles"]
        if (not proof.get("dispatcher_handles_verified") or len(proof["binding_global_ids"]) != 1
                or len(proof["buffers"]) != 2):
            raise NativePortraitAcceptanceError("换装资源保护缺少目标自己的双缓冲绑定。")
        self.binding_global = proof["binding_global_ids"][0]
        self.buffers = deepcopy(proof["buffers"])
        self.root = int(loader._record["start"])
        self.closure = NativeScriptStateClosure(loader._source, loader._analysis, [self.root],
            runtime_context=getattr(loader.catalog, "_runtime_context", None))
        self.flow = NativeFunctionFlow(loader._analysis)
        self.functions, self.signatures = {}, {}
        self.resource_functions = set()
        self.rotation_scale_functions = set()
        self.yield_sites = []
        table = loader._analysis.header.syscalls
        for address in self.closure.dependencies:
            first, end = self.flow.entries[address]
            body = loader._analysis.instructions[first:end]
            self.functions[address] = body
            for i in body:
                self.signatures[i.offset] = (i.mnemonic, deepcopy(i.operands), i.raw, i.address_role)
                if i.address_role == "thread_start_function_pointer":
                    raise NativePortraitAcceptanceError("换装加载含有尚未隔离的原生线程入口。")
                if i.mnemonic == "syscall":
                    desc = table[i.operands["id"]]
                    if desc.name in ROTATION_SCALE_CALLS:
                        self.rotation_scale_functions.add(address)
                    if desc.name in RESOURCE_CALLS:
                        if desc.args != RESOURCE_CALLS[desc.name]:
                            raise NativePortraitAcceptanceError("换装资源调用参数布局未接通：" + desc.name)
                        self.resource_functions.add(address)
                    elif desc.args not in NON_RESOURCE_CALLS.get(desc.name, ()):
                        # The shared dispatcher contains other selectors and
                        # optional layers. An unknown call may only be excluded
                        # by the complete specialized flow, not by its name or
                        # by assuming the selected source branch is isolated.
                        self.resource_functions.add(address)
                    if desc.name in {"ThreadNext", "ThreadWait"}:
                        self.yield_sites.append(i.offset)
        # Functions with a resource-mutating descendant need argument flow as
        # well. Resource-neutral wait loops may be inventoried without widening
        # the forward-flow solver or pretending to execute their effects.
        edges = self.closure.describe()["call_edges"]
        for functions in (self.resource_functions, self.rotation_scale_functions):
            while True:
                expanded = functions | {int(a) for a, children in edges.items()
                    if any(c in functions for c in children)}
                if expanded == functions:
                    break
                functions.update(expanded)

    def _check(self, document, staged):
        from .native_portrait_loading import NativeStagedPortraitLoad
        self.loader._check(document)
        if (not isinstance(staged, NativeStagedPortraitLoad) or staged._owner is not self.loader
                or staged._stamp != self.loader._stage_stamp() or staged._slot is not self.slot
                or self.loader._active.get(self.actor_id, {}).get("slot") is not self.slot
                or self.loader.assignments.get(self.actor_id) is not self.slot
                or staged._load["actor_id"] != self.actor_id):
            raise NativePortraitAcceptanceError("换装资源准备已过期或属于其他角色。")
        for address, (end, raw) in self.closure.dependencies.items():
            if (document.original_bytes[address:end] != raw or any(
                    i.dirty or i.warning or not i.known
                    or (i.mnemonic, i.operands, i.raw, i.address_role) != self.signatures[i.offset]
                    for i in self.functions[address])):
                raise NativePortraitAcceptanceError("换装加载链的原生证据已改变。")
        if self.loader._syscalls != {d.name: (n, d.args) for n, d in enumerate(document.header.syscalls)}:
            raise NativePortraitAcceptanceError("换装加载链的原生调用表已改变。")

    def _trace(self, address, arguments, globals_):
        trace = self.flow.trace(address, literal_arguments=_literal_arguments(arguments),
            literal_globals=globals_, track_global_literals=True,
            max_instructions=16384, max_joined_values=64)
        if trace["status"] != "proven_static_argument_flow":
            raise NativePortraitAcceptanceError("换装资源路径未确定：" + ", ".join(trace["blockers"]))
        return trace

    def _resource_calls(self, address, arguments, globals_, *, ancestors=()):
        if address in ancestors or len(ancestors) >= 32:
            raise NativePortraitAcceptanceError("换装资源路径存在递归或过深的调用。")
        if address not in self.resource_functions:
            return []
        trace = self._trace(address, arguments, globals_)
        calls = []
        for call in trace["calls"]:
            if call["kind"] == "call":
                calls.extend(self._resource_calls(call["address"], call["arguments"],
                    call["literal_globals_before_call"], ancestors=(*ancestors, address)))
            elif call["name"] in RESOURCE_CALLS:
                calls.append(dict(function=address, offset=call["offset"], name=call["name"],
                                  arguments=deepcopy(call["arguments"])))
            elif call["argument_count"] not in NON_RESOURCE_CALLS.get(call["name"], ()):
                raise NativePortraitAcceptanceError("换装加载包含未审核的调用：" + call["name"])
        return calls

    def _rotation_scale_calls(self, address, arguments, globals_, *, ancestors=()):
        # Inventory all R/S2 descendants, including resource-neutral helpers,
        # but specialize only calls reached by this carrier's actual arguments.
        # A pure wait loop needs no forward trace. Failures belong solely to
        # the additional proof, never to resource retention or its predicate.
        if address not in self.rotation_scale_functions:
            return [], []
        if address in ancestors or len(ancestors) >= 32:
            return [], [f"R/S2 调用路径递归或过深：0x{address:x}"]
        try:
            trace = self._trace(address, arguments, globals_)
        except NativePortraitAcceptanceError as exc:
            return [], [f"R/S2 调用路径未确定：0x{address:x}：{exc}"]
        calls, blockers = [], []
        for call in trace["calls"]:
            if call["kind"] == "call":
                nested, reasons = self._rotation_scale_calls(call["address"], call["arguments"],
                    call["literal_globals_before_call"], ancestors=(*ancestors, address))
                calls.extend(nested)
                blockers.extend(reasons)
            elif call["name"] in ROTATION_SCALE_CALLS:
                calls.append(dict(function=address, offset=call["offset"], name=call["name"],
                                  arguments=deepcopy(call["arguments"])))
                if call["argument_count"] != ROTATION_SCALE_CALLS[call["name"]]:
                    blockers.append("R/S2 调用参数布局未接通：" + call["name"])
        return calls, blockers

    def prepare(self, document, staged):
        self._check(document, staged)
        _, _, _, _, outfit_code, _ = _selector_branch(self.loader._body, self.slot.selector,
            resource_namespace=self.loader._record["resource_namespace"], layout=self.loader._layout)
        args = [self.slot.selector, 1, outfit_code, staged._expression, *staged._load["runtime_arguments"]]
        if staged.carrier_code != _arguments(args) + _call(staged._clone["address"]):
            raise NativePortraitAcceptanceError("换装资源路径与准备好的载体调用不一致。")
        return self._prove(document, args, staged._stamp)

    def probe(self, document, *, runtime_arguments, expression=0):
        """Read only native branch/resource flow without inventing a live actor."""
        self.loader._check(document)
        if self.loader.assignments.get(self.actor_id) is not self.slot:
            raise NativePortraitAcceptanceError("换装资源槽已经变化。")
        _, _, _, _, outfit_code, _ = _selector_branch(self.loader._body, self.slot.selector,
            resource_namespace=self.loader._record["resource_namespace"], layout=self.loader._layout)
        args = [self.slot.selector, 1, outfit_code, expression, *runtime_arguments]
        return self._prove(document, args, self.loader._stage_stamp())

    def _prove(self, document, args, stamp):
        arguments = [dict(kind="literal", type=type(a).__name__, value=a) for a in args]
        flags = _buffer_flags(self.functions[self.root], self.slot.primitive_ids)
        candidates, blockers = [], []
        for flag in flags:
            if flag in {self.binding_global, self.slot.cache_global_id}:
                continue
            orientations = []
            try:
                for value in (0, 1):
                    globals_ = {flag: value, self.slot.cache_global_id: None}
                    for guard in self.slot.evidence.get("registration_guards", ()):
                        globals_[guard["global_id"]] = guard["entry_value"]
                    trace = self._trace(self.root, arguments, globals_)
                    loads = [c for c in trace["calls"] if c.get("name") == "GraphLoad"]
                    if len(loads) != 1:
                        raise NativePortraitAcceptanceError("换装身体没有唯一的加载目标。")
                    graph = _integer_values(loads[0]["arguments"][0])
                    chosen = [b for b in self.buffers if graph == frozenset([b["graph"]])]
                    if len(chosen) != 1:
                        raise NativePortraitAcceptanceError("换装身体未确定加载到另一个原生槽。")
                    new = chosen[0]
                    old = next(b for b in self.buffers if b != new)
                    globals_[self.binding_global] = old["parts"]
                    calls = self._resource_calls(self.root, arguments, globals_)
                    counts = {}
                    for call in calls:
                        name, values = call["name"], call["arguments"]
                        expected = {"GraphLoad": [new["graph"]], "PartsLoad": [new["parts"]],
                            "PartsAssign": [new["parts"], new["graph"]],
                            "PrimSetSprt": [new["primitive"], new["graph"]],
                            "PrimSetNull": [new["primitive"]]}[name]
                        if any(_integer_values(actual) != frozenset([wanted])
                               for actual, wanted in zip(values, expected)):
                            raise NativePortraitAcceptanceError("换装加载链会改动旧图或未确认的资源槽。")
                        counts[name] = counts.get(name, 0) + 1
                    if any(counts.get(n) != 1 for n in ("GraphLoad", "PartsLoad", "PartsAssign", "PrimSetSprt")):
                        raise NativePortraitAcceptanceError("换装身体、表情及 sprite 的完整加载链未唯一闭合。")
                    orientations.append(dict(flag_value=value, old_buffer=old, new_buffer=new,
                                             resource_calls=calls))
                if orientations[0]["new_buffer"] == orientations[1]["new_buffer"]:
                    raise NativePortraitAcceptanceError("原生标记没有切换两个独立资源槽。")
                candidates.append((flag, orientations))
            except NativePortraitAcceptanceError as exc:
                blockers.append(str(exc))
                continue
        if len(candidates) != 1:
            detail = "；".join(dict.fromkeys(blockers))
            raise NativePortraitAcceptanceError("换装加载前的双缓冲资源保护尚未确定。" + detail)
        flag, orientations = candidates[0]
        for row in orientations:
            globals_ = {flag: row["flag_value"], self.slot.cache_global_id: None}
            for guard in self.slot.evidence.get("registration_guards", ()):
                globals_[guard["global_id"]] = guard["entry_value"]
            globals_[self.binding_global] = row["old_buffer"]["parts"]
            calls, reasons = self._rotation_scale_calls(self.root, arguments, globals_)
            for call in calls:
                site = f"{call['name']}@0x{call['offset']:x}"
                try:
                    handles = _integer_values(call["arguments"][0])
                except (NativePortraitAcceptanceError, IndexError):
                    reasons.append("R/S2 primitive 句柄未确定：" + site)
                    continue
                if row["old_buffer"]["primitive"] in handles:
                    reasons.append("载体会更新旧 primitive 的 R/S2：" + site)
                elif not handles:
                    reasons.append("R/S2 primitive 句柄未确定：" + site)
                # A completely resolved, different primitive does not write
                # this old primitive's local R/S2 fields. Preserve that native
                # call (e.g. the target's message layer), rather than treating
                # every non-portrait operation as an unknown old buffer.
            row.update(rotation_scale_calls=calls, rotation_scale_blockers=list(dict.fromkeys(reasons)),
                       old_rotation_scale_unchanged_proven=not reasons)
        predicate = bytearray()
        for row in orientations:
            predicate.extend(_push_global(flag) + _arguments([row["flag_value"]]) + b"\x22"
                + _push_global(self.binding_global) + _arguments([row["old_buffer"]["parts"]]) + b"\x22\x20")
        predicate.extend(b"\x21")
        report = dict(schema=SCHEMA, source_sha256=document.source_sha256,
            selector=self.slot.selector, carrier_address=self.root,
            carrier_arguments=args, flag_global_id=flag, binding_global_id=self.binding_global,
            orientations=orientations, source_call_closure=self.closure.describe(),
            carrier_resource_retention_proven_under_precondition=True,
            old_rotation_scale_unchanged_proven=all(
                row["old_rotation_scale_unchanged_proven"] for row in orientations),
            rotation_scale_proof_scope="owned_primitive_fields_not_parent_group_state",
            precondition_must_run_before_any_carrier_write=True,
            cache_nil_and_registration_entry_values_required=True,
            old_graph_parts_and_sprite_binding_replaced_by_carrier=False,
            resource_neutral_helper_yield_sites=sorted(self.yield_sites),
            old_visual_group_state_unchanged_proven=False, concurrent_engine_threads_owned=False,
            old_buffer_lifetime_proven=False, shared_apply_serialization_proven=False,
            scene_export_connected=False, runtime_verified=False, resources_published=False,
            code_emitted=False, source_size_rule_changed=False)
        return NativePortraitCarrierRetentionPlan(bytes(predicate), report, self.loader, stamp)
