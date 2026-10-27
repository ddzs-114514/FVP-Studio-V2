"""One intact native apply for an explicitly owned, same-beat buffer batch.

Only bytecode plans are returned. Carrier retention, scene serialization and
publication remain the caller's responsibility. A source yield between the
first and last owned alpha starts is forwarded, but makes the batch fail.
Optional actor motion starts once after every batch alpha, before any source
apply yield. Later native alpha maintenance must not reset those trajectories.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
from itertools import combinations
import struct
from typing import TypedDict

from .hcb import HcbDocument
from .hoshimemo_scene_hook import _arguments, _call, _pop_global, _push_global
from .native_cg_snapshot_storage import NativeCGSnapshotStorage
from .native_portrait_acceptance import NativePortraitAcceptanceError
from .native_portrait_buffer_geometry import geometry_code, validated_geometry
from .native_portrait_loading import NativePortraitLoading
from .native_portrait_parallel_motion import NativePortraitParallelMotion, _signature
from .native_cg_dialogue_guard import _return_inventory, _return_unused
from .native_portrait_slots import slots_conflict
from .native_portrait_swap_apply import NativePortraitSwapApply
from .native_portrait_swap_pose import NativePortraitSwapPose
from .native_scene_candidate import _header_signature
from .native_script_state import validate_native_script_pair
from .portrait_emitter import _encode_push, _encode_push_stack


SCHEMA = "fvp-native-portrait-batch-apply/1"


class _RequiredParticipant(TypedDict):
    actor_id: str
    old_fields: dict
    new_fields: dict
    duration_ms: int


class NativePortraitBatchApplyParticipant(_RequiredParticipant, total=False):
    pose: NativePortraitSwapPose | None
    parallel: NativePortraitParallelMotion | None


@dataclass(frozen=True)
class _Participant:
    actor_id: str
    old_fields: dict
    new_fields: dict
    duration_ms: int
    pose: NativePortraitSwapPose | None
    held_rotation: tuple[bool, bool]
    parallel: NativePortraitParallelMotion | None


@dataclass(frozen=True)
class NativePortraitBatchApplyPlan:
    helper_address: int
    helper_code: bytes
    reset_code: bytes
    _report: dict = field(repr=False)
    _owner: NativePortraitBatchApply = field(repr=False, compare=False)
    _stamp: tuple = field(repr=False, compare=False)
    _seal: tuple = field(repr=False, compare=False)

    def check(self, loader: NativePortraitLoading, document: HcbDocument) -> None:
        self._owner.check(loader, document)
        if (loader._stage_stamp() != self._stamp
                or _signature((self.helper_address, self.helper_code, self.reset_code, self._report)) != self._seal):
            raise NativePortraitAcceptanceError("已准备的同拍换装计划发生变化。")

    def report(self) -> dict:
        self.check(self._owner.loader, self._owner._source)
        return deepcopy(self._report)


def _flags_predicate(flags: tuple[int, ...], operation: bytes) -> bytes:
    # Exact VM True comparisons also reject Int(1), not just falsey values.
    return b"".join(_push_global(g) + b"\x09\x22" + (operation if i else b"")
                    for i, g in enumerate(flags))


class NativePortraitBatchApply:
    def __init__(self, loader: NativePortraitLoading,
                 participants: list[NativePortraitBatchApplyParticipant], storage: NativeCGSnapshotStorage,
                 *, extra_motion=None):
        if (not isinstance(loader, NativePortraitLoading)
                or not isinstance(storage, NativeCGSnapshotStorage)
                or not isinstance(participants, list) or not (1 if extra_motion is not None else 2) <= len(participants) <= 4):
            raise NativePortraitAcceptanceError("同拍换装需要真实原生加载器和状态存储；单人换装批次还须有其他已入场角色的运动。")
        self.loader, self.storage = loader, storage
        self._source, self._analysis = loader._source, loader._analysis
        self._catalog, self._handoff = loader.catalog, storage.handoff
        self._context = getattr(loader.catalog, "_runtime_context", None)
        self._check_pair()
        rows, bindings, seen = [], [], set()
        required = {"actor_id", "old_fields", "new_fields", "duration_ms"}
        for row in participants:
            if not isinstance(row, dict) or not required <= set(row) <= required | {"pose", "parallel"}:
                raise NativePortraitAcceptanceError("同拍换装须完整提供角色、旧新几何及各自时长。")
            actor, duration, pose = row["actor_id"], row["duration_ms"], row.get("pose")
            if (type(actor) is not str or not actor or actor in seen
                    or actor not in loader.assignments or actor not in loader._active
                    or loader._active[actor].get("slot") is not loader.assignments[actor]):
                raise NativePortraitAcceptanceError("同拍换装的角色重复、未加载或原生槽分配不一致。")
            if type(duration) is not int or not 1 <= duration <= 6000:
                raise NativePortraitAcceptanceError("每名同拍换装角色的时长须为 1～6000ms 的整数。")
            old, new = validated_geometry(row["old_fields"]), validated_geometry(row["new_fields"])
            if pose is not None:
                if not isinstance(pose, NativePortraitSwapPose):
                    raise NativePortraitAcceptanceError("倾斜同拍换装需要本目标真实绑定的原生姿态。")
                pose.check(loader, self._source)
            elif old["rotation"] or new["rotation"]:
                raise NativePortraitAcceptanceError("倾斜同拍换装需要本目标真实绑定的原生姿态。")
            held = (bool(pose and pose.avoids_setter(old)), bool(pose and pose.avoids_setter(new)))
            binding = NativePortraitSwapApply(loader, actor)
            binding._check(self._source)
            # Reuse the single-actor admission and complete closure, never its
            # prepare() or two separate apply invocations.
            if bindings and (binding.root != bindings[0].root or binding.root_count != bindings[0].root_count
                    or self._binding_signature(binding) != self._binding_signature(bindings[0])):
                raise NativePortraitAcceptanceError("同拍角色没有共享同一来源的完整原生提交调用链。")
            if any(slots_conflict(binding.slot, previous.slot) for previous in bindings):
                raise NativePortraitAcceptanceError("同拍换装的原生角色、资源句柄或状态变量互相冲突。")
            for fields in (old, new):
                geometry_code(loader._syscall, _encode_push_stack(-2), fields)
            participant = _Participant(actor, old, new, duration, pose, held, row.get("parallel"))
            self._check_parallel(participant, binding.slot)
            rows.append(participant)
            bindings.append(binding)
            seen.add(actor)
        self.participants, self._bindings = tuple(rows), tuple(bindings)
        self._binding_owners = self._bindings
        self.extra_motion = extra_motion
        self._check_extra()
        self._parallel = tuple((i, r.parallel) for i, r in enumerate(rows) if r.parallel is not None)
        self._has_motion = bool(self._parallel or extra_motion is not None)
        self._launch_flag = self._parallel[0][1].flags[2] if self._parallel else (
            extra_motion.kicked_global if extra_motion is not None else None)
        self.context_count = 2 * len(rows)
        self.root, self.root_count = bindings[0].root, bindings[0].root_count
        self.closure, self.spans = bindings[0].closure, bindings[0].spans
        self.sites = dict(bindings[0].sites) | dict(bindings[0].yield_sites)
        if extra_motion is not None:
            # Stop calls may otherwise retire the newly authored OTHER actor's
            # XY mid-apply. Only add an owned-handle wrapper when its original
            # return is actually unused; no source return gets fabricated.
            inventory = _return_inventory(self.spans,set(self.closure.dependencies),set())
            extra_names = {'MotionMoveStop'}
            if getattr(extra_motion,'alpha_ids',()):
                extra_names.update({'MotionAlpha','MotionAlphaStop'})
            if getattr(extra_motion,'parts_ids',()):
                extra_names.add('PartsMotion')
            for original in self.closure.dependencies:
                span = self.spans[original]
                for position,item in enumerate(span.instructions):
                    if item.mnemonic=='syscall' and self._analysis.header.syscalls[item.operands['id']].name in extra_names:
                        _return_unused(self.spans,span,position,inventory)
                        self.sites[item.offset]=self._analysis.header.syscalls[item.operands['id']].name
        for address in self.closure.dependencies:
            span = self.spans[address]
            if (span.args + self.context_count > 127
                    or any(i.mnemonic in {"push_stack", "pop_stack"}
                        and i.operands["value"] <= -2
                        and i.operands["value"] - self.context_count < -128 for i in span.instructions)):
                raise NativePortraitAcceptanceError("同拍提交的附加参数超过原生有符号栈索引范围。")
        self._owners = (loader, storage)
        self._bytes = (self._source.original_bytes, self._analysis.original_bytes)
        self._headers = (_header_signature(self._source), _header_signature(self._analysis))
        self._slots = _signature(tuple(vars(b.slot) for b in bindings))
        self._closure_state = tuple(self._binding_signature(b) for b in bindings)
        addresses = set(self.closure.dependencies) | set(bindings[0].alpha_closure.dependencies)
        for row in rows:
            if row.pose is not None:
                addresses.update(row.pose.closure.dependencies)
        offsets = {i.offset for a in addresses for i in self.spans[a].instructions}
        self._instruction_count = len(self._analysis.instructions)
        self._instruction_indexes = tuple(n for n, i in enumerate(self._analysis.instructions) if i.offset in offsets)
        self._instructions = self._instruction_signature()
        scopes = {g["scope"] for g in storage.groups}
        scope_index = 0
        while f"portrait_batch_apply:{scope_index}" in scopes:
            scope_index += 1
        self.scope = f"portrait_batch_apply:{scope_index}"
        reserved = storage.reserve_private(self.context_count + 1, self.scope)
        self.flags = tuple(reserved["private_global_ids"][:-1])
        self.frontier_global = reserved["private_global_ids"][-1]
        self.reset_code = b"".join(b"\x08" + _pop_global(g) for g in (*self.flags, self.frontier_global))
        self.reset_code += b"".join(p.reset_code for _, p in self._parallel)
        if extra_motion is not None:
            self.reset_code += extra_motion.reset_code
        self._flag_group = storage.groups[-1]
        self._configuration = self._configuration_signature()

    def _check_pair(self) -> None:
        context = self._context
        if (context is None or self._handoff.context is not context
                or self._handoff.source is not self._source or self._handoff.analysis is not self._analysis
                or context.document is not self._source or context.analysis_document is not self._analysis):
            raise NativePortraitAcceptanceError("同拍换装的状态存储、来源及分析脚本与加载器不一致。")
        validate_native_script_pair(self._source, self._analysis, runtime_context=context)
        self.storage.validate(self._handoff)
        source_table = {d.name: (i, d.args) for i, d in enumerate(self._source.header.syscalls)}
        analysis_table = {d.name: (i, d.args) for i, d in enumerate(self._analysis.header.syscalls)}
        if (len(source_table) != len(self._source.header.syscalls)
                or len(analysis_table) != len(self._analysis.header.syscalls)
                or _signature(source_table) != _signature(self.loader._syscalls)
                or _signature(source_table) != _signature(analysis_table)):
            raise NativePortraitAcceptanceError("同拍换装的来源／分析原生调用表不一致。")

    @staticmethod
    def _binding_signature(binding):
        return _signature((binding.root, binding.root_count, binding.closure.dependencies,
            binding.closure.describe(), binding.alpha_closure.dependencies, binding.alpha.report(),
            binding.sites, binding.yield_sites, binding._table))

    def _instruction_signature(self):
        if len(self._analysis.instructions) != self._instruction_count:
            raise NativePortraitAcceptanceError("同拍换装的原生分析指令边界发生变化。")
        return _signature(tuple((i.offset, i.opcode, i.mnemonic, i.operands, i.raw,
            i.address_role, i.dirty, i.warning, i.known)
            for i in (self._analysis.instructions[n] for n in self._instruction_indexes)))

    def _configuration_signature(self):
        return _signature((tuple((r.actor_id, r.old_fields, r.new_fields, r.duration_ms, r.pose,
            r.held_rotation, None if r.pose is None else r.pose.report(), r.parallel,
            None if r.parallel is None else r.parallel.report()) for r in self.participants),
            self.scope, self.flags, self.frontier_global, self.reset_code, self._flag_group,
            self.context_count, self.root, self.root_count, self.sites, self._parallel, self._launch_flag,
            self.extra_motion, self._has_motion,
            None if self.extra_motion is None else self.extra_motion.report(),
            tuple((b.loader, b.actor_id, b.slot, b.geometry.buffers) for b in self._bindings)))

    def _check_extra(self):
        if self.extra_motion is not None:
            from .native_scene_parallel_motion import NativeSceneParallelMotion
            from .native_scene_parallel_effects import NativeSceneParallelEffects
            if not isinstance(self.extra_motion,(NativeSceneParallelMotion, NativeSceneParallelEffects)) or self.extra_motion.storage is not self.storage:
                raise NativePortraitAcceptanceError('其他角色的同拍运动须绑定本场景真实的原生接口。')
            self.extra_motion.check(self.loader,self._source)
            self.extra_motion.assert_excludes([b.slot for b in self._bindings])
            if isinstance(self.extra_motion,NativeSceneParallelEffects) and any(
                    e['kind']=='CameraShot' for e in self.extra_motion.events):
                binding = self._bindings[0]
                calls = {self._analysis.header.syscalls[i.operands['id']].name
                    for a in binding.closure.dependencies for i in binding.spans[a].instructions
                    if i.mnemonic=='syscall'}
                if calls.intersection({'V3DSet','V3DMotion','V3DMotionStop'}):
                    raise NativePortraitAcceptanceError('此目标换装提交还会改写镜头，暂不能与镜头同拍。')

    def _check_parallel(self, row: _Participant, slot) -> dict:
        parallel = row.parallel
        if parallel is None:
            return {}
        if not isinstance(parallel, NativePortraitParallelMotion):
            raise NativePortraitAcceptanceError("同拍换装运动需要当前角色真实绑定的原生运动。")
        parallel.check(self.loader, self._source)
        if parallel.actor_id != row.actor_id or parallel.storage is not self.storage or parallel._slot is not slot:
            raise NativePortraitAcceptanceError("同拍换装运动的角色、原生几何槽或状态存储不一致。")
        starts = {}
        for channel in parallel.channels:
            actual, expected = [], []
            for values, fields in ((channel.old_values, row.old_fields), (channel.new_values, row.new_fields)):
                if channel.channel == "xy":
                    origin = tuple(values[:2])
                    if parallel.motion.xy_converted:
                        # Match the bound helper's encoded f32 inputs and
                        # proven axis conversion into raw setter coordinates.
                        origin = tuple(int((struct.unpack("<f", struct.pack("<f", value))[0]
                            if type(value) is float else value) * parallel.motion.xy_factors[axis])
                            for axis, value in zip(("x", "y"), origin))
                    target = (fields["x"], fields["y"])
                elif channel.channel == "s2":
                    origin = (values[0], values[2])
                    target = (fields.get("scale_x", fields["scale"]), fields.get("scale_y", fields["scale"]))
                else:
                    origin = (values[0],)
                    target = (fields["rotation" if channel.channel == "r" else "z"],)
                actual.append(origin)
                expected.append(target)
            if _signature(actual) != _signature(expected):
                raise NativePortraitAcceptanceError("同拍原生运动起点与角色旧、新缓冲几何不一致：" + channel.channel)
            starts[channel.channel] = dict(old_start=list(actual[0]), new_start=list(actual[1]))
        return starts

    def check(self, loader: NativePortraitLoading, document: HcbDocument) -> None:
        if (loader is not self._owners[0] or self.loader is not loader or self.storage is not self._owners[1]
                or document is not self._source or loader._source is not self._source
                or loader._analysis is not self._analysis or loader.catalog is not self._catalog
                or getattr(loader.catalog, "_runtime_context", None) is not self._context
                or self.storage.handoff is not self._handoff or self._bindings != self._binding_owners
                or self.closure is not self._bindings[0].closure or self.spans is not self._bindings[0].spans):
            raise NativePortraitAcceptanceError("同拍换装的加载器、状态存储或目标来源绑定发生变化。")
        self._check_pair()
        self._check_extra()
        for row, binding in zip(self.participants, self._bindings):
            binding._check(document)
            self._check_parallel(row, binding.slot)
            if row.pose is not None:
                row.pose.check(loader, document)
                if row.held_rotation != (bool(row.pose.avoids_setter(row.old_fields)),
                                        bool(row.pose.avoids_setter(row.new_fields))):
                    raise NativePortraitAcceptanceError("同拍换装的原生半周旋转保护发生变化。")
        if ((self._source.original_bytes, self._analysis.original_bytes) != self._bytes
                or (_header_signature(self._source), _header_signature(self._analysis)) != self._headers
                or _signature(tuple(vars(b.slot) for b in self._bindings)) != self._slots
                or tuple(self._binding_signature(b) for b in self._bindings) != self._closure_state
                or self._instruction_signature() != self._instructions
                or self._configuration_signature() != self._configuration
                or not any(g is self._flag_group for g in self.storage.groups)):
            raise NativePortraitAcceptanceError("同拍换装的角色证据、私有标志或原生计划发生变化。")

    def _context_operands(self) -> tuple[bytes, ...]:
        return tuple(_encode_push_stack(i - self.context_count - 1) for i in range(self.context_count))

    def _wrappers(self, address: int) -> tuple[bytes, dict[str, int], list[int]]:
        code, entries, launch_calls = bytearray(), {}, []
        context = self._context_operands()
        all_started = _flags_predicate(self.flags, b"\x20")
        any_started = _flags_predicate(self.flags, b"\x21")
        for name in sorted(set(self.sites.values())):
            ident, count = self.loader._syscalls[name]
            entries[name] = address + len(code)
            code.extend(bytes((1, count + self.context_count, 2 if name == "MotionAlpha" else 0)))
            native_args = tuple(_encode_push_stack(i - count - self.context_count - 1) for i in range(count))
            if name in {"ThreadNext", "ThreadWait"}:
                # Motion batches cannot launch after even a pre-alpha yield.
                # Pure fade batches keep their original partial-start rule.
                predicate = (all_started + b"\x09\x23" if self._has_motion else
                             any_started + all_started + b"\x09\x23\x20")
                code.extend(predicate + b"\x07\0\0\0\0")
                boundary = len(code) - 4
                code.extend(b"\x09" + _pop_global(self.frontier_global))
                struct.pack_into("<I", code, boundary, address + len(code))
            else:
                for index, row in enumerate(self.participants):
                    for role, fields in enumerate((row.old_fields, row.new_fields)):
                        code.extend(native_args[0] + context[2 * index + role] + b"\x22\x07\0\0\0\0")
                        unowned = len(code) - 4
                        if name == "MotionAlpha":
                            if self._has_motion:
                                code.extend(_push_global(self._launch_flag) + b"\x09\x22\x07\0\0\0\0")
                                before_launch = len(code) - 4
                                code.extend(b"".join(native_args) + b"\x03" + struct.pack("<H", ident) + b"\x14\x05")
                                struct.pack_into("<I", code, before_launch, address + len(code))
                            # The existing target-native Int(1) override keeps
                            # fast-forward cleanup from outliving its motion.
                            code.extend(native_args[3] + _arguments([1]) + b"\x22\x07\0\0\0\0")
                            native_time = len(code) - 4
                            code.extend(_arguments([1]) + b"\x16\0\x06\0\0\0\0")
                            authored_time = len(code) - 4
                            struct.pack_into("<I", code, native_time, address + len(code))
                            code.extend(_arguments([row.duration_ms]) + b"\x16\0")
                            struct.pack_into("<I", code, authored_time, address + len(code))
                            preparation = dict(fields, alpha=fields["alpha"] if role == 0 else 0)
                            geometry, _ = geometry_code(self.loader._syscall, native_args[0], preparation,
                                include_rotation=not row.held_rotation[role])
                            code.extend(geometry + native_args[0]
                                + _arguments([fields["alpha"] if role == 0 else 0,
                                              0 if role == 0 else fields["alpha"]])
                                + _encode_push_stack(0) + b"".join(native_args[4:])
                                + b"\x03" + struct.pack("<H", ident) + b"\x14\x16\x01"
                                + b"\x09" + _pop_global(self.flags[2 * index + role]))
                            if row.parallel is not None:
                                code.extend(b"\x09" + _pop_global(row.parallel.flags[role]))
                            if self._has_motion:
                                # All author helpers return Nil; keep this SYS
                                # result in the wrapper's original local 1.
                                code.extend(b"".join(context) + b"\x02\0\0\0\0")
                                launch_calls.append(len(code) - 4)
                            code.extend(_encode_push_stack(1) + b"\x05")
                        elif name=='MotionAlphaStop':
                            # This wrapper protects only another actor's
                            # authored fade. Keep the swapped pair's original
                            # alpha retirement exactly as the source performs it.
                            code.extend(b''.join(native_args)+b'\x03'+struct.pack('<H',ident)+b'\x14\x05')
                        elif name=='MotionMoveStop':
                            if role==1 and row.parallel is not None and any(c.channel=='xy' for c in row.parallel.channels):
                                code.extend(_push_global(row.parallel.flags[2])+b'\x09\x22\x07\0\0\0\0')
                                before_launch = len(code)-4
                                code.extend(b'\x04')
                                struct.pack_into('<I',code,before_launch,address+len(code))
                            code.extend(b''.join(native_args)+b'\x03'+struct.pack('<H',ident)+b'\x14\x05')
                        else:
                            # Admission by NativePortraitSwapApply proves
                            # selected entry/exit XY/Z return values unused.
                            code.extend(b"\x04")
                        struct.pack_into("<I", code, unowned, address + len(code))
            protected = ()
            if self.extra_motion is not None:
                if hasattr(self.extra_motion,'protected_primitives'):
                    protected = self.extra_motion.protected_primitives(name)
                elif name in {'MotionMove','MotionMoveZ','MotionMoveStop'}:
                    protected = self.extra_motion.primitive_ids
            if protected and name in {'MotionMove','MotionMoveZ','MotionMoveStop','MotionAlpha','MotionAlphaStop','PartsMotion'}:
                owned = b''.join(native_args[0]+_arguments([p])+b'\x22'+(b'\x21' if i else b'')
                    for i,p in enumerate(protected))
                code.extend(_push_global(self.extra_motion.kicked_global)+b'\x09\x22'+owned+b'\x20\x07\0\0\0\0')
                unowned_extra = len(code)-4
                code.extend(b'\x04')
                struct.pack_into('<I',code,unowned_extra,address+len(code))
            code.extend(b"".join(native_args) + b"\x03" + struct.pack("<H", ident) + b"\x14\x05")
        return bytes(code), entries, launch_calls

    def _launch(self, document: HcbDocument, address: int) -> tuple[bytes, dict]:
        if not self._has_motion:
            return b"", {}
        context = self._context_operands()
        predicate = (_flags_predicate(self.flags, b"\x20")
            + _push_global(self.frontier_global) + b"\x08\x22\x20")
        for _, parallel in self._parallel:
            predicate += _push_global(parallel.flags[2]) + b"\x08\x22\x20"
        if self.extra_motion is not None:
            predicate += (_push_global(self.extra_motion.kicked_global)+b'\x08\x22\x20'
                + self.extra_motion.runtime_guard_code()+b'\x20')
        code = bytearray(bytes((1, self.context_count, 0)) + predicate + b"\x07\0\0\0\0")
        reject = len(code) - 4
        for _, parallel in self._parallel:
            code.extend(b"\x09" + _pop_global(parallel.flags[2]))
        calls = []
        for index, _ in self._parallel:
            code.extend(context[2*index] + context[2*index+1] + b"\x02\0\0\0\0")
            calls.append(len(code) - 4)
        extra_call = None
        if self.extra_motion is not None:
            code.extend(b'\x02\0\0\0\0')
            extra_call = len(code)-4
            code.extend(b'\x14\x09\x22\x07\0\0\0\0')
            extra_rejected = len(code)-4
        struct.pack_into("<I", code, reject, address + len(code))
        code.extend(b"\x04")
        if extra_call is not None:
            struct.pack_into('<I',code,extra_rejected,address+len(code))
            code.extend(b'\x09'+_pop_global(self.frontier_global)+b'\x04')
        helpers, reports = bytearray(), {}
        for position, (_, parallel) in zip(calls, self._parallel):
            author = parallel.prepare(document, address + len(code) + len(helpers))
            struct.pack_into("<I", code, position, author.entry_address)
            helpers.extend(author.code)
            reports[parallel.actor_id] = author.report()
        if extra_call is not None:
            extra = self.extra_motion.prepare(document,address+len(code)+len(helpers))
            struct.pack_into('<I',code,extra_call,extra.entry_address)
            helpers.extend(extra.code)
            reports['other_actors']=extra.report()
        return bytes(code + helpers), reports

    def _cleanup_old(self, document: HcbDocument, address: int) -> bytes:
        code = bytearray()
        context = self._context_operands()
        for index, parallel in self._parallel:
            # A rejected frontier never owns an author start to retire.
            code.extend(_push_global(parallel.flags[2]) + b"\x09\x22\x07\0\0\0\0")
            skip = len(code) - 4
            code.extend(parallel.cleanup_old(document, context[2*index]))
            struct.pack_into("<I", code, skip, address + len(code))
        return bytes(code)

    def prepare(self, document: HcbDocument, helper_address: int) -> NativePortraitBatchApplyPlan:
        self.check(self.loader, document)
        if type(helper_address) is not int or not len(document.original_bytes) <= helper_address < 2**31:
            raise NativePortraitAcceptanceError("同拍换装入口须位于当前来源脚本的附加区。")
        context = self._context_operands()
        predicate = bytearray()
        for index, binding in enumerate(self._bindings):
            old, new = context[2 * index:2 * index + 2]
            first, second = (b["primitive"] for b in binding.geometry.buffers)
            pair = bytearray()
            for previous, current in ((first, second), (second, first)):
                pair.extend(old + _encode_push(previous, "shift_jis") + b"\x22"
                    + new + _encode_push(current, "shift_jis") + b"\x22\x20")
            predicate.extend(pair + b"\x21" + (b"\x20" if index else b""))
        for left, right in combinations(context, 2):
            predicate.extend(left + right + b"\x23\x20")
        if self.extra_motion is not None:
            predicate.extend(self.extra_motion.runtime_guard_code()+b'\x20')
        prefix = bytearray(bytes((1, self.context_count, 0)) + self.reset_code + predicate + b"\x07\0\0\0\0")
        pair_branch = len(prefix) - 4
        for index, row in enumerate(self.participants):
            old, new = context[2 * index:2 * index + 2]
            old_code, _ = geometry_code(self.loader._syscall, old, row.old_fields,
                include_rotation=not row.held_rotation[0])
            new_code, _ = geometry_code(self.loader._syscall, new, dict(row.new_fields,
                alpha=0, rotation=0 if row.held_rotation[1] else row.new_fields["rotation"]))
            prefix.extend(old_code + new_code)
            if row.held_rotation[1]:
                prefix.extend(row.pose.initialize_hidden(new, row.new_fields, helper_address + len(prefix)))
        invocation = _arguments([None] * self.root_count) + b"".join(context)
        old_cleanup = self._cleanup_old(document, helper_address + len(prefix) + len(invocation) + 5)
        predicate = _flags_predicate(self.flags, b"\x20") + _push_global(self.frontier_global) + b"\x08\x22\x20"
        if self._parallel:
            predicate += _flags_predicate(tuple(p.flags[2] for _, p in self._parallel), b"\x20") + b"\x20"
        if self.extra_motion is not None:
            predicate += _push_global(self.extra_motion.kicked_global)+b'\x09\x22\x20'
        success = bytearray(predicate + b"\x07\0\0\0\0\x09\x05")
        reject_address = helper_address + len(prefix) + len(invocation) + 5 + len(old_cleanup) + len(success)
        struct.pack_into("<I", prefix, pair_branch, reject_address)
        struct.pack_into("<I", success, len(success) - 6, reject_address)
        wrapper_address = reject_address + 2
        wrappers, entries, launch_calls = self._wrappers(wrapper_address)
        launch_address = wrapper_address + len(wrappers)
        launch, launch_reports = self._launch(document, launch_address)
        if launch_calls:
            wrappers = bytearray(wrappers)
            for position in launch_calls:
                struct.pack_into("<I", wrappers, position, launch_address)
        address = launch_address + len(launch)
        mapping, offsets = {}, {}
        growth = len(b"".join(context)) + 5
        for original in sorted(self.closure.dependencies):
            mapping[original], offsets[original] = address, {}
            for item in self.spans[original].instructions:
                offsets[original][item.offset] = address
                address += growth if item.mnemonic == "call" or item.offset in self.sites else item.size
        if address >= 2**31:
            raise NativePortraitAcceptanceError("同拍原生提交副本超过目标有符号地址范围。")
        code = prefix + invocation + _call(mapping[self.root]) + old_cleanup + success + b"\x08\x05" + wrappers + launch
        for original in sorted(mapping):
            span = self.spans[original]
            for item in span.instructions:
                raw = bytearray(item.raw)
                if item.mnemonic == "init_stack":
                    raw[1] = span.args + self.context_count
                elif item.mnemonic in {"push_stack", "pop_stack"} and item.operands["value"] <= -2:
                    struct.pack_into("<b", raw, 1, item.operands["value"] - self.context_count)
                elif item.mnemonic in {"jmp", "jz"}:
                    struct.pack_into("<I", raw, 1, offsets[original][item.operands["target"]])
                elif item.mnemonic == "call":
                    raw = bytearray(b"".join(context) + _call(mapping[item.operands["target"]]))
                elif item.offset in self.sites:
                    raw = bytearray(b"".join(context) + _call(entries[self.sites[item.offset]]))
                code.extend(raw)
        if helper_address + len(code) != address:
            raise NativePortraitAcceptanceError("同拍原生提交副本的地址计算不一致。")
        report = dict(schema=SCHEMA, source_sha256=document.source_sha256,
            analysis_sha256=self._analysis.source_sha256, helper_address=helper_address,
            helper_size=len(code), helper_sha256=hashlib.sha256(code).hexdigest(),
            participants=[dict(actor_id=r.actor_id, selector=b.slot.selector, buffers=deepcopy(b.geometry.buffers),
                old_geometry=deepcopy(r.old_fields), new_geometry=deepcopy(r.new_fields), duration_ms=r.duration_ms,
                alpha_started_globals=list(self.flags[2*i:2*i+2]), signed_rotation_connected=r.pose is not None,
                author_motion_parallelism_connected=r.parallel is not None,
                author_motion_geometry_binding=self._check_parallel(r, b.slot),
                rotation_preservation=None if r.pose is None else r.pose.report(),
                old_rotation_scale_setter_omitted=r.held_rotation[0],
                new_signed_rotation_initialized_before_alpha=r.held_rotation[1])
                for i, (r, b) in enumerate(zip(self.participants, self._bindings))],
            participant_count=len(self.participants), owned_buffer_context_arguments=self.context_count,
            native_apply_root=self.root, native_apply_argument_count=self.root_count, native_apply_invocations=1,
            original_intact_apply_once=True, native_apply_frame_split=False,
            native_dependency_closure=self.closure.describe(), apply_mapping={str(a): b for a, b in mapping.items()},
            motion_wrapper_entries=entries, native_local_indices_unchanged=True,
            native_argument_indices_rebased=True, native_apply_default_arguments_preserved=True,
            native_pending_cache_write_instructions_preserved=True,
            native_wait_and_cleanup_call_graph_preserved=True,
            native_alpha_argument_flow=self._bindings[0].alpha.report(), header_arity_only=False,
            native_one_ms_fast_override_preserved=True, participant_specific_durations=True,
            other_buffer_motion_arguments_and_returns_preserved=self.extra_motion is None,
            non_authored_buffer_motion_arguments_and_returns_preserved=True,
            selected_buffer_entry_exit_xy_z_suppressed=True,
            runtime_distinct_owned_pair_guard=True, runtime_all_participant_handles_distinct_guard=True,
            source_yield_boundary_guard=True, original_source_yields_always_forwarded=True,
            source_yield_sites={str(a): n for a, n in self._bindings[0].yield_sites.items()},
            alpha_started_globals=list(self.flags), source_yield_boundary_failure_global=self.frontier_global,
            return_requires_all_alphas_started_and_failure_nil=True,
            flag_values="typed_true_or_nil", nil_and_int_zero_distinct=True,
            return_value="typed_true_or_nil", caller_must_check_result=True,
            private_scope=self.scope, private_volatile_cells=self.context_count+1,
            native_global_header_installation_required=True, exclusive_authored_scene_owner_required=True,
            old_buffer_lifetime_proven=False, shared_apply_serialization_proven=False,
            author_motion_parallelism_connected=self._has_motion, author_motion_launch=launch_reports,
            other_actor_motion_connected=self.extra_motion is not None,
            other_actor_motion=None if self.extra_motion is None else self.extra_motion.report(),
            owned_other_actor_xy_z_stops_suppressed_after_launch=self.extra_motion is not None,
            author_motion_launch_entry=launch_address if self._has_motion else None,
            author_motion_launch_once_per_actor=self._has_motion,
            author_motion_launch_after_all_owned_alphas=self._has_motion,
            author_motion_started_before_intact_apply_wait=self._has_motion,
            author_motion_launch_checked_on_apply_return=self._has_motion,
            author_motion_flags_managed_by_batch=self._has_motion,
            author_motion_private_volatile_cells=3*len(self._parallel)+(self.extra_motion is not None),
            later_native_alpha_maintenance_kept_after_author_launch=self._has_motion,
            old_author_channels_stopped_after_native_apply=bool(self._parallel),
            old_author_channel_cleanup={p.actor_id: deepcopy(p._stops) for _, p in self._parallel},
            author_motion_pre_alpha_source_yield_rejected=self._has_motion, new_threads_created=False,
            resources_published=False, code_emitted=False, scene_export_connected=False, runtime_verified=False)
        seal = _signature((helper_address, bytes(code), self.reset_code, report))
        return NativePortraitBatchApplyPlan(helper_address, bytes(code), self.reset_code, report,
            self, self.loader._stage_stamp(), seal)
