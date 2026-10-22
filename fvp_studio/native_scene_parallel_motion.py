"""A guarded current-buffer callback for loaded, non-swapping scene actors.

Only an in-memory zero-argument helper is prepared. The batch caller owns its
launch boundary and resets the private kicked flag for each frame. No native
apply, geometry setter, stop, alpha, parts, camera or new thread is emitted.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
from itertools import combinations
import math
import struct
from typing import Literal, TypedDict

from .hcb import HcbDocument
from .hoshimemo_scene_hook import _pop_global
from .native_cg_snapshot_storage import NativeCGSnapshotStorage
from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans
from .native_portrait_buffer_geometry import NativePortraitBufferGeometry, validated_geometry
from .native_portrait_loading import NativePortraitLoading
from .native_portrait_motion import NativePortraitMotion, ROLES
from .native_portrait_parallel_motion import _signature
from .native_portrait_slots import NativePortraitSlot, slots_conflict
from .native_scene_candidate import _header_signature
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .portrait_emitter import _encode_push, _encode_push_stack


SCHEMA = "fvp-native-scene-parallel-motion/1"
Channel = Literal["xy", "z", "r", "s2"]
MotionValue = int | float | bool | None


class NativeSceneParallelMotionChannel(TypedDict):
    channel: Channel
    values: list[MotionValue] | tuple[MotionValue, ...]


class NativeSceneParallelMotionRow(TypedDict):
    actor_id: str
    fields: dict
    channels: list[NativeSceneParallelMotionChannel]


@dataclass(frozen=True)
class _Channel:
    channel: Channel
    values: tuple[MotionValue, ...]


@dataclass(frozen=True)
class _Row:
    actor_id: str
    fields: dict
    channels: tuple[_Channel, ...]
    slot: NativePortraitSlot = field(repr=False, compare=False)


@dataclass(frozen=True)
class NativeSceneParallelMotionPlan:
    entry_address: int
    code: bytes
    _report: dict = field(repr=False)
    _owner: NativeSceneParallelMotion = field(repr=False, compare=False)
    _seal: tuple = field(repr=False, compare=False)

    def check(self, loader: NativePortraitLoading, document: HcbDocument) -> None:
        self._owner.check(loader, document)
        if _signature((self.entry_address, self.code, self._report, self._owner)) != self._seal:
            raise NativePortraitAcceptanceError("已准备的普通角色同拍运动计划发生变化。")

    def report(self) -> dict:
        self.check(self._owner.loader, self._owner._source)
        return deepcopy(self._report)


def _converted_start(value: int | float, factor: float) -> int:
    """Follow the source helper's f32 wire values, multiply and FloatToInt."""
    try:
        wire = struct.unpack("<f", struct.pack("<f", value))[0] if type(value) is float else value
        # Match native_cg_motion's midpoint resolver: round the HCB operand,
        # then multiply by the bound source factor and truncate toward zero.
        product = wire * factor
    except (OverflowError, struct.error) as exc:
        raise NativePortraitAcceptanceError("本目标原生 XY 起点换算超出数值范围。") from exc
    if not math.isfinite(product) or not -2**31 <= product < 2**31:
        raise NativePortraitAcceptanceError("本目标原生 XY 起点换算超出整数范围。")
    return int(product)


class NativeSceneParallelMotion:
    def __init__(self, loader: NativePortraitLoading, motion: NativePortraitMotion,
                 rows: list[NativeSceneParallelMotionRow], storage: NativeCGSnapshotStorage):
        if (not isinstance(loader, NativePortraitLoading) or not isinstance(motion, NativePortraitMotion)
                or not isinstance(storage, NativeCGSnapshotStorage)
                or not isinstance(rows, list) or not 1 <= len(rows) <= 128):
            # Each captured current primitive occupies a signed i8 local.
            raise NativePortraitAcceptanceError("普通角色同拍运动需要真实原生加载器、运动、状态存储及非空角色列表；图元局部索引须可编码。")
        self.loader, self.motion, self.storage = loader, motion, storage
        self._source, self._analysis = loader._source, loader._analysis
        self._catalog, self._handoff = loader.catalog, storage.handoff
        self._context = getattr(loader.catalog, "_runtime_context", None)
        self._owners = (loader, motion, storage)
        self._check_pair()
        prepared, seen = [], set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"actor_id", "fields", "channels"}:
                raise NativePortraitAcceptanceError("普通角色同拍运动须完整提供 actor_id、fields 和 channels。")
            actor = row["actor_id"]
            if (type(actor) is not str or not actor or actor in seen or actor not in loader.assignments
                    or actor not in loader._active or loader._active[actor].get("slot") is not loader.assignments[actor]):
                raise NativePortraitAcceptanceError("普通角色同拍运动的角色重复、未加载或当前原生槽不一致。")
            slot = loader.assignments[actor]
            if (not isinstance(slot, NativePortraitSlot) or not any(slot is s for s in self._catalog.slots)
                    or any(p <= 0 for p in slot.primitive_ids)):
                raise NativePortraitAcceptanceError("普通角色同拍运动必须使用当前目录的角色槽，不能使用全局图元 0。")
            channels = row["channels"]
            if not isinstance(channels, list) or not channels:
                raise NativePortraitAcceptanceError("普通角色同拍运动需要明确的原生通道。")
            values, used = [], set()
            for channel in channels:
                if not isinstance(channel, dict) or set(channel) != {"channel", "values"}:
                    raise NativePortraitAcceptanceError("普通角色同拍通道须明确提供 channel 和 values。")
                name, parameters = channel["channel"], channel["values"]
                if (type(name) is not str or name not in ROLES or name in used
                        or not isinstance(parameters, (tuple, list))):
                    raise NativePortraitAcceptanceError("普通角色同拍运动只接受不重复的 xy/z/r/s2 通道及完整参数。")
                values.append(_Channel(name, tuple(parameters)))
                used.add(name)
            prepared.append(_Row(actor, validated_geometry(row["fields"]), tuple(values), slot))
            seen.add(actor)
        self.rows = tuple(prepared)
        if any(slots_conflict(a.slot, b.slot) for a, b in combinations(self.rows, 2)):
            raise NativePortraitAcceptanceError("普通角色同拍运动的原生句柄或状态变量互相冲突。")
        self.primitive_ids = tuple(sorted(p for row in self.rows for p in row.slot.primitive_ids))
        self._geometries = tuple(NativePortraitBufferGeometry(self._source, r.slot) for r in self.rows)
        self._current = tuple(g.capture_operand(self._source) for g in self._geometries)
        if self._current != tuple(loader._active_primitive(r.slot) for r in self.rows):
            raise NativePortraitAcceptanceError("普通角色的当前图元操作数与本目标原生缓冲证据不一致。")
        # Validate every numeric/curve/flag row through the actual compiler
        # before comparing starts or reserving a persistent scene cell.
        self._motion_code = self._compile_rows()
        self._geometry_binding = self._check_starts()
        roots = [motion._bindings[c][0] for c in sorted(motion._bindings)]
        self._closure = NativeScriptStateClosure(self._source, self._analysis, roots,
            runtime_context=self._context, max_functions=128, max_instructions=32768)
        proof = motion.report()
        if (_signature(proof.get("native_dependency_closure")) != _signature(self._closure.describe())
                or _signature(motion.global_ids) != _signature(self._closure.global_ids)
                or set(proof.get("roles", {})) != set(motion._bindings)):
            raise NativePortraitAcceptanceError("普通角色同拍运动的完整原生调用链或缓存证据不一致。")
        self._closure_state = _signature((self._closure.dependencies, self._closure.global_ids, self._closure.describe()))
        for name, (address, count, tail) in motion._bindings.items():
            role = proof["roles"][name]
            if (name not in ROLES or count != ROLES[name][1] or address != role["helper"]
                    or count + len(tail) != role["helper_args"] or not tail
                    or _signature(tail[0]) != _signature(role["nonblocking_arguments"][count])
                    or role.get("nonblocking_path_proven") is not True):
                raise NativePortraitAcceptanceError("普通角色同拍运动的非等待原生入口与参数证据不一致。")
        self._bytes = (self._source.original_bytes, self._analysis.original_bytes)
        self._headers = (_header_signature(self._source), _header_signature(self._analysis))
        self._table = dict(loader._syscalls)
        self._slots = _signature(tuple(vars(r.slot) for r in self.rows))
        self._motion_state = self._motion_signature()
        offsets = {i.offset for s in _function_spans(self._analysis)
                   if s.start in self._closure.dependencies for i in s.instructions}
        self._instruction_count = len(self._analysis.instructions)
        self._instruction_indexes = tuple(n for n, i in enumerate(self._analysis.instructions) if i.offset in offsets)
        self._instructions = self._instruction_signature()
        scopes, number = {g["scope"] for g in storage.groups}, 0
        while f"scene_parallel_motion:{number}" in scopes:
            number += 1
        self.scope = f"scene_parallel_motion:{number}"
        reserved = storage.reserve_private(1, self.scope)
        self.kicked_global = reserved["private_global_ids"][0]
        self.reset_code = b"\x08" + _pop_global(self.kicked_global)
        self._flag_group = storage.groups[-1]
        self._configuration = self._configuration_signature()

    def _check_pair(self) -> None:
        context = self._context
        if (context is None or self._handoff.context is not context
                or self._handoff.source is not self._source or self._handoff.analysis is not self._analysis
                or context.document is not self._source or context.analysis_document is not self._analysis
                or self.motion.analysis is not self._analysis):
            raise NativePortraitAcceptanceError("普通角色同拍运动的来源、分析及场景状态存储与加载器不一致。")
        self.loader._check(self._source)
        pair = validate_native_script_pair(self._source, self._analysis, runtime_context=context)
        try:
            self.storage.validate(self._handoff)
        except ValueError as exc:
            raise NativePortraitAcceptanceError("普通角色同拍运动的场景状态存储绑定已变化：" + str(exc)) from exc
        proof = self.motion.report()
        source_table = {d.name: (i, d.args) for i, d in enumerate(self._source.header.syscalls)}
        analysis_table = {d.name: (i, d.args) for i, d in enumerate(self._analysis.header.syscalls)}
        if (proof.get("source_sha256") != self._source.source_sha256
                or proof.get("analysis_sha256") != self._analysis.source_sha256
                or _signature(proof.get("runtime_binding")) != _signature(pair)
                or len(source_table) != len(self._source.header.syscalls)
                or len(analysis_table) != len(self._analysis.header.syscalls)
                or _signature(source_table) != _signature(self.loader._syscalls)
                or _signature(source_table) != _signature(analysis_table)):
            raise NativePortraitAcceptanceError("普通角色同拍运动的来源／分析或原生调用表绑定不一致。")

    def _compile_rows(self) -> bytes:
        return b"".join(self.motion.compile(c.channel, _encode_push_stack(i), c.values,
            allow_nil_flag=c.values[-1:] == (None,)) for i, r in enumerate(self.rows) for c in r.channels)

    def _check_starts(self) -> dict:
        binding = {}
        for row in self.rows:
            starts = {}
            for c in row.channels:
                if c.channel == "xy":
                    actual = tuple(c.values[:2])
                    if self.motion.xy_converted:
                        actual = tuple(_converted_start(v, self.motion.xy_factors[a])
                                       for a, v in zip(("x", "y"), actual))
                    expected = (row.fields["x"], row.fields["y"])
                elif c.channel == "s2":
                    actual = (c.values[0], c.values[2])
                    expected = (row.fields.get("scale_x", row.fields["scale"]),
                                row.fields.get("scale_y", row.fields["scale"]))
                else:
                    actual = (c.values[0],)
                    expected = (row.fields["rotation" if c.channel == "r" else "z"],)
                if _signature(actual) != _signature(expected):
                    raise NativePortraitAcceptanceError("普通角色原生运动起点与当前几何不一致：" + c.channel)
                starts[c.channel] = list(actual)
            binding[row.actor_id] = starts
        return binding

    def _motion_signature(self):
        nil_channels = {c.channel for r in self.rows for c in r.channels if c.values[-1:] == (None,)}
        return _signature((self.motion.report(), self.motion._bindings, self.motion.global_ids,
            self.motion.xy_converted, dict(self.motion.xy_factors),
            {c: self.motion._nil_flag_proofs.get(c) for c in nil_channels}))

    def _instruction_signature(self):
        if len(self._analysis.instructions) != self._instruction_count:
            raise NativePortraitAcceptanceError("普通角色同拍运动的分析指令边界发生变化。")
        return _signature(tuple((i.offset, i.opcode, i.mnemonic, i.operands, i.raw,
            i.address_role, i.dirty, i.warning, i.known)
            for i in (self._analysis.instructions[n] for n in self._instruction_indexes)))

    def _configuration_signature(self):
        return _signature((tuple((r.actor_id, r.fields, tuple((c.channel, c.values) for c in r.channels),
            r.slot) for r in self.rows), self.primitive_ids, self._current, self._motion_code,
            self._geometry_binding, self.scope, self.kicked_global, self.reset_code, self._flag_group))

    def check(self, loader: NativePortraitLoading, doc: HcbDocument) -> None:
        if (loader is not self._owners[0] or self.loader is not loader or self.motion is not self._owners[1]
                or self.storage is not self._owners[2] or doc is not self._source
                or loader._source is not self._source or loader._analysis is not self._analysis
                or loader.catalog is not self._catalog or self.storage.handoff is not self._handoff
                or getattr(loader.catalog, "_runtime_context", None) is not self._context
                or any(loader.assignments.get(r.actor_id) is not r.slot
                    or loader._active.get(r.actor_id, {}).get("slot") is not r.slot
                    or not any(r.slot is s for s in self._catalog.slots) for r in self.rows)):
            raise NativePortraitAcceptanceError("普通角色同拍运动的角色、加载器、运动或状态存储绑定发生变化。")
        self._check_pair()
        if ((self._source.original_bytes, self._analysis.original_bytes) != self._bytes
                or (_header_signature(self._source), _header_signature(self._analysis)) != self._headers
                or loader._syscalls != self._table
                or _signature(tuple(vars(r.slot) for r in self.rows)) != self._slots
                or self._motion_signature() != self._motion_state
                or _signature((self._closure.dependencies, self._closure.global_ids, self._closure.describe())) != self._closure_state
                or self._instruction_signature() != self._instructions
                or self._configuration_signature() != self._configuration
                or not any(g is self._flag_group for g in self.storage.groups)
                or self._compile_rows() != self._motion_code
                or self._check_starts() != self._geometry_binding
                or tuple(loader._active_primitive(r.slot) for r in self.rows) != self._current):
            raise NativePortraitAcceptanceError("普通角色同拍运动的原生证据、私有标志或已准备计划发生变化。")
        self._closure.compile_snapshot(doc)

    def runtime_guard_code(self) -> bytes:
        self.check(self.loader, self._source)
        return b"".join(operand + _encode_push(row.slot.primitive_ids[0], "shift_jis") + b"\x22"
            + operand + _encode_push(row.slot.primitive_ids[1], "shift_jis") + b"\x22\x21"
            + (b"\x20" if i else b"") for i, (row, operand) in enumerate(zip(self.rows, self._current)))

    def assert_excludes(self, slots) -> None:
        self.check(self.loader, self._source)
        try:
            excluded = tuple(slots.values() if isinstance(slots, Mapping) else slots)
        except TypeError as exc:
            raise NativePortraitAcceptanceError("同拍换装排除列表必须提供本目标的真实原生角色槽。") from exc
        if any(not isinstance(s, NativePortraitSlot) or not any(s is original for original in self._catalog.slots)
               for s in excluded):
            raise NativePortraitAcceptanceError("同拍换装排除列表包含其他目标或未绑定的角色槽。")
        if any(slots_conflict(r.slot, s) for r in self.rows for s in excluded):
            raise NativePortraitAcceptanceError("普通角色同拍运动与换装角色的原生图元、资源或状态槽冲突。")

    def prepare(self, doc: HcbDocument, helper_address: int) -> NativeSceneParallelMotionPlan:
        self.check(self.loader, doc)
        if type(helper_address) is not int or not len(doc.original_bytes) <= helper_address < 2**31:
            raise NativePortraitAcceptanceError("普通角色同拍运动入口须位于当前来源脚本的附加区。")
        snapshot = self._closure.compile_snapshot(doc)
        guard = self.runtime_guard_code()
        capture = b"".join(operand + b"\x16" + struct.pack("<b", i) for i, operand in enumerate(self._current))
        success = (snapshot["snapshot"] + capture + self._motion_code + snapshot["restore"]
                   + b"\x09" + _pop_global(self.kicked_global) + b"\x09\x05")
        rejected = helper_address + 3 + len(guard) + 5 + len(success)
        code = (bytes((1, 0, len(self.rows))) + guard + b"\x07" + struct.pack("<I", rejected)
                + success + b"\x08\x05")
        if helper_address + len(code) >= 2**31:
            raise NativePortraitAcceptanceError("普通角色同拍运动代码超过目标有符号地址范围。")
        report = self.report()
        report.update(entry_address=helper_address, helper_size=len(code), code_sha256=hashlib.sha256(code).hexdigest(),
            arguments=0, locals=len(self.rows), saved_operand_values=len(self._closure.global_ids),
            operand_stack_delta=0, current_primitives_captured_before_first_motion=True,
            current_primitives_kept_in_locals_across_native_cache_writes=True,
            native_globals_restored_before_kicked_and_return=True, snapshot=snapshot["report"],
            return_opcode="RETV", return_value="typed_true_or_nil", bad_guard_returns_nil_without_mutation=True)
        seal = _signature((helper_address, code, report, self))
        return NativeSceneParallelMotionPlan(helper_address, code, report, self, seal)

    def report(self) -> dict:
        self.check(self.loader, self._source)
        return dict(schema=SCHEMA, source_sha256=self._source.source_sha256,
            analysis_sha256=self._analysis.source_sha256, primitive_ids=self.primitive_ids,
            participants=[dict(actor_id=r.actor_id, selector=r.slot.selector, primitive_ids=r.slot.primitive_ids,
                fields=deepcopy(r.fields), channels=[dict(channel=c.channel, values=list(c.values)) for c in r.channels])
                for r in self.rows], geometry_start_binding=deepcopy(self._geometry_binding),
            current_dynamic_primitive_ownership_guard=True, primitive_global_zero_forbidden=True,
            kicked_global=self.kicked_global, kicked_values="typed_true_or_nil", nil_and_int_zero_distinct=True,
            private_scope=self.scope, private_volatile_cells=1, flags_managed_by_caller=True,
            caller_must_reset_each_frame=True, native_global_header_installation_required=True,
            exclusive_authored_scene_owner_required=True, concurrent_or_reentrant_ownership_proven=False,
            global_ids=list(self._closure.global_ids), native_dependency_closure=self._closure.describe(),
            native_motion=self.motion.report(), nonblocking=True, current_buffer_only=True,
            old_new_dual_launch=False, source_globals_saved_and_restored=True, caller_must_check_result=True,
            caller_owns_batch_alpha_launch_boundary=True, source_wait_or_geometry_suppression_connected=False,
            new_threads_created=False, stop_emitted=False, alpha_emitted=False, parts_emitted=False,
            camera_emitted=False, geometry_setters_emitted=False, resources_changed=False,
            resources_published=False, code_emitted=False, scene_export_connected=False, runtime_verified=False)
