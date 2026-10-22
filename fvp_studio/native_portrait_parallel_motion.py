"""Prepare two-buffer author motion without splitting the native apply.

The caller supplies complete target-native parameters and owns the distinct
old/new primitive pair. It resets the private flags, records the first old
and new alpha starts, and calls this helper once before the intact apply's
wait. Flag guards, cleanup insertion and publication belong to that caller.
All returned bytecode stays in memory; no thread or resource is created here.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import struct
from typing import Literal, TypedDict

from .hcb import HcbDocument, parse_bytes
from .hoshimemo_scene_hook import _pop_global
from .native_cg_snapshot_storage import NativeCGSnapshotStorage
from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans
from .native_portrait_loading import NativePortraitLoading
from .native_portrait_motion import NativePortraitMotion, ROLES
from .native_scene_candidate import _header_signature
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .portrait_emitter import _encode_push_stack


SCHEMA = "fvp-native-portrait-parallel-motion/1"
Channel = Literal["xy", "z", "r", "s2"]
MotionValue = int | float | bool | None


class NativePortraitParallelMotionRow(TypedDict):
    channel: Channel
    old_values: Sequence[MotionValue]
    new_values: Sequence[MotionValue]


@dataclass(frozen=True)
class NativePortraitParallelMotionChannel:
    channel: Channel
    old_values: tuple[MotionValue, ...]
    new_values: tuple[MotionValue, ...]


def _signature(value):
    """Keep Nil, bool, int and float distinct in stale-plan checks."""
    if isinstance(value, Mapping):
        return (type(value), frozenset((_signature(k), _signature(v)) for k, v in value.items()))
    if isinstance(value, (tuple, list)):
        return (type(value), tuple(_signature(v) for v in value))
    return (type(value), value)


def _rows(channels) -> tuple[NativePortraitParallelMotionChannel, ...]:
    if not isinstance(channels, (tuple, list)) or not channels:
        raise NativePortraitAcceptanceError("同拍运动需要明确的原生通道。")
    result, seen = [], set()
    for row in channels:
        if isinstance(row, NativePortraitParallelMotionChannel):
            channel, old, new = row.channel, row.old_values, row.new_values
        elif isinstance(row, Mapping) and set(row) == {"channel", "old_values", "new_values"}:
            channel, old, new = row["channel"], row["old_values"], row["new_values"]
        else:
            raise NativePortraitAcceptanceError("同拍运动须明确提供 channel、old_values 和 new_values。")
        if type(channel) is not str or channel not in ROLES or channel in seen:
            raise NativePortraitAcceptanceError("同拍运动只接受不重复的 xy/z/r/s2 通道。")
        if not isinstance(old, (tuple, list)) or not isinstance(new, (tuple, list)):
            raise NativePortraitAcceptanceError("同拍运动的旧、新值需要完整的原生参数。")
        result.append(NativePortraitParallelMotionChannel(channel, tuple(old), tuple(new)))
        seen.add(channel)
    return tuple(result)


@dataclass(frozen=True)
class NativePortraitParallelMotionPlan:
    entry_address: int
    code: bytes
    _report: dict = field(repr=False)
    _owner: NativePortraitParallelMotion = field(repr=False, compare=False)
    _seal: tuple = field(repr=False, compare=False)

    def check(self, loader: NativePortraitLoading, document: HcbDocument) -> None:
        self._owner.check(loader, document)
        if _signature((self.entry_address, self.code, self._report)) != self._seal:
            raise NativePortraitAcceptanceError("已准备的同拍运动计划发生变化。")

    def report(self) -> dict:
        self.check(self._owner.loader, self._owner._source)
        return deepcopy(self._report)


class NativePortraitParallelMotion:
    def __init__(self, loader: NativePortraitLoading, actor_id: str,
                 motion: NativePortraitMotion,
                 channels: Sequence[NativePortraitParallelMotionRow | NativePortraitParallelMotionChannel],
                 storage: NativeCGSnapshotStorage):
        if (not isinstance(loader, NativePortraitLoading) or type(actor_id) is not str
                or actor_id not in loader.assignments
                or not isinstance(motion, NativePortraitMotion)
                or not isinstance(storage, NativeCGSnapshotStorage)):
            raise NativePortraitAcceptanceError("同拍运动需要当前目标真实绑定的角色、加载器、运动及状态存储。")
        self.loader, self.actor_id, self.motion, self.storage = loader, actor_id, motion, storage
        self.channels = _rows(channels)
        self._source, self._analysis = loader._source, loader._analysis
        self._catalog, self._handoff = loader.catalog, storage.handoff
        self._context = getattr(loader.catalog, "_runtime_context", None)
        self._slot = loader.assignments[actor_id]
        self._owners = (loader, actor_id, motion, storage)
        self._check_pair()
        proof = motion.report()
        roots = [motion._bindings[c][0] for c in sorted(motion._bindings)]
        self._closure = NativeScriptStateClosure(self._source, self._analysis, roots,
            runtime_context=self._context, max_functions=128, max_instructions=32768)
        if (_signature(proof.get("native_dependency_closure")) != _signature(self._closure.describe())
                or _signature(motion.global_ids) != _signature(self._closure.global_ids)
                or set(proof.get("roles", {})) != set(motion._bindings)):
            raise NativePortraitAcceptanceError("同拍运动的完整原生依赖与状态证据不一致。")
        for channel, (address, count, tail) in motion._bindings.items():
            role = proof["roles"][channel]
            if (channel not in ROLES or count != ROLES[channel][1]
                    or address != role["helper"] or count + len(tail) != role["helper_args"]
                    or not tail or _signature(tail[0]) != _signature(role["nonblocking_arguments"][count])):
                raise NativePortraitAcceptanceError("同拍运动的非等待原生入口与证据不一致。")
        self._table = dict(loader._syscalls)
        self._stops = {}
        for row in self.channels:
            name = ROLES[row.channel][0] + "Stop"
            bound = self._table.get(name)
            if bound is None or bound[1] != 1 or type(bound[0]) is not int or not 0 <= bound[0] <= 0x7fff:
                raise NativePortraitAcceptanceError("旧缓冲的单参数原生停止入口尚未接通：" + name)
            self._stops[row.channel] = dict(stop_syscall=name, stop_syscall_id=bound[0], stop_arity=1)
        # Reuse compile for every numeric/curve/flag rule before reserving cells.
        self._old_code, self._new_code = self._compile_rows()
        self._source_bytes, self._analysis_bytes = self._source.original_bytes, self._analysis.original_bytes
        self._headers = (_header_signature(self._source), _header_signature(self._analysis))
        self._motion_state = self._motion_signature()
        self._slot_state = _signature(vars(self._slot))
        offsets = {i.offset for span in _function_spans(self._analysis)
                   if span.start in self._closure.dependencies for i in span.instructions}
        self._instruction_count = len(self._analysis.instructions)
        self._instruction_indexes = tuple(n for n, i in enumerate(self._analysis.instructions) if i.offset in offsets)
        self._instructions = self._instruction_signature()
        scope_index = 0
        scopes = {g["scope"] for g in storage.groups}
        while f"portrait_parallel_motion:{actor_id}:{scope_index}" in scopes:
            scope_index += 1
        self.scope = f"portrait_parallel_motion:{actor_id}:{scope_index}"
        reserved = storage.reserve_private(3, self.scope)
        old_flag, new_flag, done_flag = reserved["private_global_ids"]
        self.flags: tuple[int, int, int] = (old_flag, new_flag, done_flag)
        self.reset_code: bytes = b"".join(b"\x08" + _pop_global(g) for g in self.flags)
        self._flag_group = storage.groups[-1]
        self._configuration = self._configuration_signature()

    def _check_pair(self) -> None:
        source, analysis, context = self._source, self._analysis, self._context
        if (context is None or self._handoff.context is not context
                or self._handoff.source is not source or self._handoff.analysis is not analysis
                or context.document is not source or context.analysis_document is not analysis
                or self.motion.analysis is not analysis):
            raise NativePortraitAcceptanceError("同拍运动的目标、运行脚本及分析脚本与加载器不一致。")
        self.loader._check(source)
        pair = validate_native_script_pair(source, analysis, runtime_context=context)
        self.storage.validate(self._handoff)
        proof = self.motion.report()
        table = {d.name: (i, d.args) for i, d in enumerate(source.header.syscalls)}
        if (proof.get("source_sha256") != source.source_sha256
                or proof.get("analysis_sha256") != analysis.source_sha256
                or _signature(proof.get("runtime_binding")) != _signature(pair)
                or len(table) != len(source.header.syscalls)
                or _signature(table) != _signature(self.loader._syscalls)
                or _signature(table) != _signature({d.name: (i, d.args)
                    for i, d in enumerate(analysis.header.syscalls)})):
            raise NativePortraitAcceptanceError("同拍运动的运行／分析脚本配对或原生调用表不一致。")

    def _compile_rows(self) -> tuple[bytes, bytes]:
        chunks = []
        for name, index in (("old_values", -3), ("new_values", -2)):
            chunks.append(b"".join(self.motion.compile(row.channel, _encode_push_stack(index),
                getattr(row, name), allow_nil_flag=getattr(row, name)[-1:] == (None,))
                for row in self.channels))
        return chunks[0], chunks[1]

    def _motion_signature(self):
        nil_channels = {r.channel for r in self.channels
                        if r.old_values[-1:] == (None,) or r.new_values[-1:] == (None,)}
        return _signature((self.motion.report(), self.motion._bindings, self.motion.global_ids,
            self.motion.xy_converted, dict(self.motion.xy_factors),
            {c: self.motion._nil_flag_proofs.get(c) for c in nil_channels}))

    def _instruction_signature(self):
        if len(self._analysis.instructions) != self._instruction_count:
            raise NativePortraitAcceptanceError("同拍运动的分析指令边界发生变化。")
        return _signature(tuple((i.offset, i.opcode, i.mnemonic, i.operands, i.raw,
            i.address_role, i.dirty, i.warning, i.known)
            for i in (self._analysis.instructions[n] for n in self._instruction_indexes)))

    def _configuration_signature(self):
        return _signature((tuple((r.channel, r.old_values, r.new_values) for r in self.channels),
            self.scope, self.flags, self.reset_code, self._old_code, self._new_code, self._stops,
            self._flag_group))

    def check(self, loader: NativePortraitLoading, document: HcbDocument) -> None:
        old_loader, actor, motion, storage = self._owners
        if (loader is not old_loader or self.loader is not old_loader or self.actor_id != actor
                or self.motion is not motion or self.storage is not storage
                or document is not self._source or loader._source is not self._source
                or loader._analysis is not self._analysis or loader.catalog is not self._catalog
                or getattr(loader.catalog, "_runtime_context", None) is not self._context
                or storage.handoff is not self._handoff
                or loader.assignments.get(actor) is not self._slot
                or loader._active.get(actor, {}).get("slot", self._slot) is not self._slot):
            raise NativePortraitAcceptanceError("同拍运动的角色、加载器、原生运动或来源绑定发生变化。")
        self._check_pair()
        if (self._source.original_bytes != self._source_bytes or self._analysis.original_bytes != self._analysis_bytes
                or (_header_signature(self._source), _header_signature(self._analysis)) != self._headers
                or loader._syscalls != self._table or _signature(vars(self._slot)) != self._slot_state
                or self._motion_signature() != self._motion_state
                or self._instruction_signature() != self._instructions
                or self._configuration_signature() != self._configuration
                or not any(g is self._flag_group for g in storage.groups)
                or self._compile_rows() != (self._old_code, self._new_code)):
            raise NativePortraitAcceptanceError("同拍运动的原生证据或已准备的计划发生变化。")
        self._closure.compile_snapshot(document)

    def prepare(self, document: HcbDocument, helper_address: int) -> NativePortraitParallelMotionPlan:
        self.check(self.loader, document)
        if type(helper_address) is not int or not len(document.original_bytes) <= helper_address < 2**31:
            raise NativePortraitAcceptanceError("同拍运动入口须位于当前来源脚本的附加区。")
        snapshot = self._closure.compile_snapshot(document)
        code = (b"\x01\x02\0" + snapshot["snapshot"] + self._old_code + self._new_code
                + snapshot["restore"] + b"\x04")
        if helper_address + len(code) >= 2**31:
            raise NativePortraitAcceptanceError("同拍运动附加代码超出原生有符号地址范围。")
        report = self.report()
        report.update(entry_address=helper_address, helper_size=len(code),
            code_sha256=hashlib.sha256(code).hexdigest(), arguments=2, locals=0,
            old_primitive_argument_index=-3, new_primitive_argument_index=-2,
            return_opcode="RET", return_value="typed_nil", operand_stack_delta=0,
            saved_operand_values=len(self._closure.global_ids),
            globals_restored_before_return=True, snapshot=snapshot["report"])
        seal = _signature((helper_address, code, report))
        return NativePortraitParallelMotionPlan(helper_address, code, report, self, seal)

    def cleanup_old(self, document: HcbDocument, old_primitive_operand: bytes) -> bytes:
        """Stop just these author channels; a dynamic operand needs the caller's owned-pair guard."""
        self.check(self.loader, document)
        self._check_old_operand(old_primitive_operand)
        return b"".join(self.loader._syscall(self._stops[row.channel]["stop_syscall"],
            [old_primitive_operand]) for row in self.channels)

    def _check_old_operand(self, operand: bytes) -> None:
        if type(operand) is not bytes or not operand:
            raise NativePortraitAcceptanceError("停止旧缓冲需要一个已绑定的原生图元操作数。")
        body = b"\x01\0\0" + operand + b"\x04"
        header = bytearray(self._source_bytes[self._source.header.sysdesc_offset:])
        struct.pack_into("<I", header, 0, 4)
        parsed = parse_bytes(struct.pack("<I", 4 + len(body)) + body + header, self._source.encoding)
        stack = []
        allowed_globals = set(self._slot.global_ids) | set(self._slot.read_global_ids)
        for item in parsed.instructions[1:-1]:
            name, value = item.mnemonic, item.operands.get("value")
            if item.warning or item.dirty or not item.known:
                break
            if name in {"push_i8", "push_i16", "push_i32"}:
                stack.append(value)
            elif (name == "push_stack" and -128 <= value <= -2
                    or name == "push_global" and value in allowed_globals):
                stack.append(None)
            elif name in {"add", "sub"} and len(stack) >= 2:
                right, left = stack.pop(), stack.pop()
                stack.append(None if left is None or right is None else
                    left + right if name == "add" else left - right)
            else:
                break
        else:
            if (not parsed.warnings and parsed.instructions[-1].mnemonic == "ret"
                    and len(stack) == 1 and (stack[0] is None
                    or type(stack[0]) is int and stack[0] > 0 and stack[0] in self._slot.primitive_ids)):
                return
        raise NativePortraitAcceptanceError("旧缓冲操作数只能是已绑定图元的单值表达式，不能全部停止。")

    def report(self) -> dict:
        self.check(self.loader, self._source)
        return dict(schema=SCHEMA, source_sha256=self._source.source_sha256,
            analysis_sha256=self._analysis.source_sha256, actor_id=self.actor_id,
            channels=[r.channel for r in self.channels],
            native_parameters=[dict(channel=r.channel, old_values=list(r.old_values),
                new_values=list(r.new_values)) for r in self.channels],
            flags=self.flags, flag_roles=("old_alpha_started", "new_alpha_started", "kicked"),
            private_scope=self.scope, private_volatile_cells=3, flags_managed_by_caller=True,
            native_global_header_installation_required=True,
            global_ids=list(self._closure.global_ids), globals_saved_and_restored=True,
            motion_source_binding="sha256_and_exact_dependency_bytes", motion_analysis_identity_bound=True,
            runtime_context_source_analysis_identity_bound=True,
            native_motion=self.motion.report(), native_dependency_closure=self._closure.describe(),
            old_new_independent_starts=True, nonblocking=True, new_threads_created=False,
            cleanup_channels=deepcopy(self._stops), cleanup_only_old_author_channels=True,
            dynamic_cleanup_operand_requires_owned_pair_guard=True,
            native_stop_handler_bytes_verified=False, all_primitive_stop_emitted=False,
            caller_must_launch_once_after_first_two_owned_alphas_before_native_wait=True,
            original_apply_wait_cleanup_changed=False, shared_apply_serialization_proven=False,
            resources_changed=False, resources_published=False, code_emitted=False,
            source_size_rule_changed=False, calibration_used=False, game_name_switch_used=False,
            runtime_verified=False, public_connected=False, scene_export_connected=False)
