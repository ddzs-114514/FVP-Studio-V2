"""Private intact-apply preparation for an owned portrait buffer handoff.

This is NOT a public scene-body-fade capability. The caller must still prove
that the carrier retained the old resource, check the returned owned-pair
guard, serialize the original shared apply transaction and publish atomically.
All original cache writes, waits and cleanup remain in their original frames.
Only the two explicitly supplied actor buffers get the authored geometry and
alpha duration; other handles forward their original arguments and result.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _arguments, _call, _push_global, _pop_global
from .native_cg_dialogue_guard import _return_inventory, _return_unused
from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans
from .native_portrait_alpha import NativePortraitAlpha
from .native_portrait_buffer_geometry import NativePortraitBufferGeometry, geometry_code, validated_geometry
from .native_script_state import NativeScriptStateClosure
from .portrait_emitter import _encode_push, _encode_push_stack


SCHEMA = "fvp-native-portrait-swap-apply/1"
HOOKS = {"MotionAlpha": (5, 6), "MotionMove": (8,), "MotionMoveZ": (6,)}
# This deliberately narrow family contains no primitive re-creation or hidden
# thread launch. A new target must match its own full source closure, not its
# title, carrier argc or the layout of a previously inspected game.
UNCHANGED = {"GraphRGB": (4,), "PartsRGB": (4,), "GraphLoad": (2,),
    "PartsLoad": (2,), "PartsMotion": (3,), "PrimSetNull": (1,),
    "MotionAlphaTest": (1,), "MotionAlphaStop": (1,), "MotionMoveStop": (1,),
    "FloatToInt": (1,), "ThreadNext": (0,), "ThreadWait": (1,)}


@dataclass(frozen=True)
class NativePortraitSwapApplyPlan:
    helper_address: int
    helper_code: bytes
    capture_code: bytes
    finish_code: bytes
    _report: dict
    _owner: object
    _stamp: tuple

    def report(self):
        return deepcopy(self._report)


class NativePortraitSwapApply:
    def __init__(self, loader, actor_id, *, catalogue_only=False):
        from .native_portrait_loading import NativePortraitLoading
        if (type(catalogue_only) is not bool or not isinstance(loader, NativePortraitLoading)
                or actor_id not in loader.assignments
                or not catalogue_only and actor_id not in loader._active):
            raise NativePortraitAcceptanceError("换装渐变需要当前已加载的角色。")
        self.loader, self.actor_id = loader, actor_id
        self.root, self.root_count = loader.catalog.apply_target, loader.catalog.apply_count
        self._table = dict(loader._syscalls)
        self.slot = loader.assignments[actor_id] if catalogue_only else loader._active[actor_id]["slot"]
        self.geometry = NativePortraitBufferGeometry(loader._source, self.slot)
        runtime_context = getattr(loader.catalog, "_runtime_context", None)
        # Bind p/from/to/time to this target's own complete alpha-helper flow;
        # a same-named syscall and argc alone do not establish those roles.
        self.alpha = NativePortraitAlpha(loader._source, loader._analysis,
            runtime_context=runtime_context)
        self.alpha_closure = NativeScriptStateClosure(loader._source, loader._analysis,
            [self.alpha.address], runtime_context=runtime_context)
        self.closure = NativeScriptStateClosure(loader._source, loader._analysis,
            [loader.catalog.apply_target],
            runtime_context=runtime_context)
        self.spans = {s.start: s for s in _function_spans(loader._analysis)}
        if self.spans[loader.catalog.apply_target].args != loader.catalog.apply_count:
            raise NativePortraitAcceptanceError("换装渐变缺少当前目标的完整原生提交入口。")
        reachable = set(self.closure.dependencies)
        inventory = _return_inventory(self.spans, reachable, set())
        if inventory[1][loader.catalog.apply_target]:
            raise NativePortraitAcceptanceError("换装提交会读取调用前的返回寄存器，不能插入几何准备。")
        self.sites = {}
        self.yield_sites = {}
        self._instructions = {}
        table = loader._syscalls
        if table.get("MotionAlpha", (None, None))[1] != self.alpha.report()["native_syscall_args"]:
            raise NativePortraitAcceptanceError("换装透明度布局与本目标的原生动作参数流不一致。")
        self._alpha_instructions = {i.offset: (i.mnemonic, deepcopy(i.operands), i.raw)
            for a in self.alpha_closure.dependencies for i in self.spans[a].instructions}
        for address in sorted(reachable):
            span = self.spans[address]
            if not 0 <= span.args <= 125:
                raise NativePortraitAcceptanceError("换装调用参数超过原生栈范围。")
            for position, item in enumerate(span.instructions):
                if item.dirty or item.warning or not item.known:
                    raise NativePortraitAcceptanceError("换装原生提交指令已改变。")
                self._instructions[item.offset] = (item.mnemonic, deepcopy(item.operands), item.address_role)
                if item.mnemonic in {"push_stack", "pop_stack"}:
                    index = item.operands["value"]
                    if index == -1 or index < -126:
                        raise NativePortraitAcceptanceError("换装提交含有不能安全平移的原生栈索引。")
                if item.address_role == "thread_start_function_pointer":
                    raise NativePortraitAcceptanceError("换装提交包含未隔离的原生线程。")
                if item.mnemonic != "syscall":
                    continue
                desc = loader._analysis.header.syscalls[item.operands["id"]]
                if desc.name not in HOOKS and desc.name not in UNCHANGED:
                    raise NativePortraitAcceptanceError("此目标换装提交还含有未接入的原生调用：" + desc.name)
                expected = HOOKS.get(desc.name, UNCHANGED.get(desc.name))
                if desc.args not in expected or table.get(desc.name) != (item.operands["id"], desc.args):
                    raise NativePortraitAcceptanceError("换装渐变的原生参数布局不一致。")
                if desc.name in HOOKS:
                    if desc.name != "MotionAlpha":
                        try:
                            _return_unused(self.spans, span, position, inventory)
                        except ValueError as exc:
                            raise NativePortraitAcceptanceError(
                                "换装位置保护不能丢弃被读取的原生动作返回值。") from exc
                    self.sites[item.offset] = desc.name
                elif desc.name in {'ThreadNext', 'ThreadWait'}:
                    self.yield_sites[item.offset] = desc.name
        if "MotionAlpha" not in self.sites.values():
            raise NativePortraitAcceptanceError("原生换装提交没有已绑定的透明度渐变。")

    def _check(self, document):
        self.loader._check(document)
        if self.loader._active.get(self.actor_id, {}).get("slot") is not self.slot:
            raise NativePortraitAcceptanceError("换装角色已退场或重新分配。")
        if (self.loader.assignments.get(self.actor_id) is not self.slot
                or (self.loader.catalog.apply_target, self.loader.catalog.apply_count)
                != (self.root, self.root_count)):
            raise NativePortraitAcceptanceError("换装角色槽或原生提交入口已改变。")
        self.closure.compile_snapshot(document)
        self.alpha_closure.compile_snapshot(document)
        for address in self.alpha_closure.dependencies:
            if any(i.dirty or i.warning or not i.known
                    or (i.mnemonic, i.operands, i.raw) != self._alpha_instructions[i.offset]
                    for i in self.spans[address].instructions):
                raise NativePortraitAcceptanceError("换装透明度参数的原生证据已改变。")
        for address, (end, raw) in self.closure.dependencies.items():
            span = self.spans[address]
            if (document.original_bytes[address:end] != raw
                    or any(i.dirty or i.warning or not i.known
                           or (i.mnemonic, i.operands, i.address_role) != self._instructions[i.offset]
                           or i.raw != raw[i.offset-address:i.offset-address+i.size]
                           for i in span.instructions)):
                raise NativePortraitAcceptanceError("换装原生提交依赖已漂移。")
        if (self.loader._syscalls != self._table or self._table != {d.name: (i, d.args)
                for i, d in enumerate(document.header.syscalls)}):
            raise NativePortraitAcceptanceError("换装原生系统调用表已改变。")

    def _wrappers(self, address, old, new, duration, *, held_rotation=(False, False), parallel=None,
                  frontier_global=None, sites=None):
        code, entries, launch_calls = bytearray(), {}, []
        for name in sorted(set((self.sites if sites is None else sites).values())):
            ident, count = self.loader._syscalls[name]
            entries[name] = address + len(code)
            code.extend(bytes((1, count + 2, (2 if parallel is not None else 1) if name == "MotionAlpha" else 0)))
            if parallel is not None and name in {'ThreadNext', 'ThreadWait'}:
                # A target that yields BETWEEN the two owned alpha starts
                # must not quietly turn the author motion into a late one.
                # Preserve that source yield, but make the parallel plan fail
                # closed at its existing scene-abort/result handoff.
                predicate = (_push_global(parallel.flags[0]) + _push_global(parallel.flags[1]) + b'\x23'
                    + _push_global(parallel.flags[2]) + b'\x08\x22\x20')
                code.extend(predicate + b'\x07\0\0\0\0')
                branch = len(code)-4
                code.extend(b'\x09' + _pop_global(frontier_global))
                struct.pack_into('<I', code, branch, address+len(code))
                for index in range(count):
                    code.extend(_encode_push_stack(index-count-3))
                code.extend(b'\x03'+struct.pack('<H', ident)+b'\x14\x05')
                continue
            handle = _encode_push_stack(-count - 3)
            for role, fields, argument in (("old", old, -3), ("new", new, -2)):
                code.extend(handle + _encode_push_stack(argument) + b"\x22\x07\0\0\0\0")
                branch = len(code) - 4
                if name == "MotionAlpha":
                    after_start = None
                    if parallel is not None:
                        # Later source maintenance remains native. Reasserting
                        # the entry geometry here would reset a running author
                        # trajectory back to its starting pose.
                        code.extend(_push_global(parallel.flags[2]) + b'\x07\0\0\0\0')
                        after_start = len(code)-4
                        for index in range(count):
                            code.extend(_encode_push_stack(index-count-3))
                        code.extend(b'\x03'+struct.pack('<H', ident)+b'\x14\x05')
                        struct.pack_into('<I', code, after_start, address+len(code))
                    # The intact original apply may skip its wait in native
                    # fast-forward mode. Preserve its exact 1ms override;
                    # forcing a 200ms engine motion here could outlive cleanup.
                    code.extend(_encode_push_stack(-count) + _arguments([1])
                        + b"\x22\x07\0\0\0\0")
                    native_time_branch = len(code) - 4
                    code.extend(_arguments([1]) + b"\x16\0\x06\0\0\0\0")
                    authored_time_branch = len(code) - 4
                    struct.pack_into("<I", code, native_time_branch, address + len(code))
                    code.extend(_arguments([duration]) + b"\x16\0")
                    struct.pack_into("<I", code, authored_time_branch, address + len(code))
                    preparation = dict(fields, alpha=fields["alpha"] if role == "old" else 0)
                    geometry, _ = geometry_code(self.loader._syscall, handle, preparation,
                        include_rotation=not held_rotation[0 if role == "old" else 1])
                    code.extend(geometry)
                    code.extend(handle + _arguments([
                        old["alpha"] if role == "old" else 0,
                        0 if role == "old" else new["alpha"]]) + b"\x10\0")
                    for index in range(4, count):
                        code.extend(_encode_push_stack(index - count - 3))
                    code.extend(b"\x03" + struct.pack("<H", ident) + b"\x14")
                    if parallel is not None:
                        # Preserve the native return while recording only this
                        # private actor-pair launch. The second alpha call can
                        # launch author motion before the intact apply waits.
                        code.extend(b"\x16\x01\x09" + _pop_global(parallel.flags[0 if role == 'old' else 1]))
                        code.extend(b"\x10\xfd\x10\xfe\x02\0\0\0\0")
                        launch_calls.append(len(code)-4)
                        code.extend(b"\x10\x01")
                    code.extend(b"\x05")
                else:
                    # These apply-only entry/exit moves must not pull the
                    # imported portrait back to the native default XY/Z.
                    # The independently reviewed original return is unused.
                    code.extend(b"\x04")
                struct.pack_into("<I", code, branch, address + len(code))
            for index in range(count):
                code.extend(_encode_push_stack(index - count - 3))
            code.extend(b"\x03" + struct.pack("<H", ident) + b"\x14\x05")
        return bytes(code), entries, launch_calls

    def prepare(self, document, *, helper_address, old_fields, new_fields, duration_ms=200, pose=None,
                parallel=None):
        self._check(document)
        if (type(helper_address) is not int
                or not len(document.original_bytes) <= helper_address < 2**31
                or type(duration_ms) is not int or not 1 <= duration_ms <= 6000):
            raise NativePortraitAcceptanceError("换装渐变需要附加区地址及 1～6000ms 的整数时长。")
        old, new = validated_geometry(old_fields), validated_geometry(new_fields)
        frontier_global = None
        sites = dict(self.sites)
        if parallel is not None:
            from .native_portrait_parallel_motion import NativePortraitParallelMotion
            if not isinstance(parallel, NativePortraitParallelMotion):
                raise NativePortraitAcceptanceError("同拍换装运动需要当前角色的原生参数绑定。")
            parallel.check(self.loader, document)
            if parallel.actor_id != self.actor_id:
                raise NativePortraitAcceptanceError("同拍换装运动属于另一个角色。")
            frontier_global = parallel.storage.reserve_private(1,
                f'parallel_source_yield_boundary_{parallel.flags[2]}_{helper_address}')['private_global_ids'][0]
            sites.update(self.yield_sites)
        if pose is not None:
            from .native_portrait_swap_pose import NativePortraitSwapPose
            if not isinstance(pose, NativePortraitSwapPose):
                raise NativePortraitAcceptanceError("倾斜换装需要本目标已绑定的原生姿态初始化。")
            pose.check(self.loader, document)
        elif old["rotation"] or new["rotation"]:
            raise NativePortraitAcceptanceError("倾斜换装需要本目标已绑定的原生姿态初始化。")
        held_rotation = (bool(pose and pose.avoids_setter(old)), bool(pose and pose.avoids_setter(new)))
        stamp = self.loader._stage_stamp()
        # The existing runtime guard checks both orientations of this actor's
        # exact buffer pair before making any geometry/native apply call.
        previous, current = _encode_push_stack(-3), _encode_push_stack(-2)
        first, second = (b["primitive"] for b in self.geometry.buffers)
        predicate = bytearray()
        for old_id, new_id in ((first, second), (second, first)):
            predicate.extend(previous + _encode_push(old_id, "shift_jis") + b"\x22"
                + current + _encode_push(new_id, "shift_jis") + b"\x22\x20")
        predicate.extend(b"\x21")
        old_code, _ = geometry_code(self.loader._syscall, previous, old,
            include_rotation=not held_rotation[0])
        new_code, _ = geometry_code(self.loader._syscall, current,
            dict(new, alpha=0, rotation=0 if held_rotation[1] else new["rotation"]))
        reset = b'\x08' + _pop_global(frontier_global) if parallel is not None else b''
        prefix = bytearray(b"\x01\x02\0" + reset + predicate + b"\x07\0\0\0\0" + old_code + new_code)
        predicate_branch = 3 + len(reset) + len(predicate)
        if held_rotation[1]:
            prefix.extend(pose.initialize_hidden(current, new, helper_address + len(prefix)))
        root_count = self.loader.catalog.apply_count
        old_cleanup = parallel.cleanup_old(document, _encode_push_stack(-3)) if parallel is not None else b''
        invocation_size = len(_arguments([None] * root_count)) + 4 + 5 + len(old_cleanup)
        success = bytearray(b'\x09\x05')
        if parallel is not None:
            success = bytearray(_push_global(parallel.flags[2]) + b'\x07\0\0\0\0\x09\x05')
        reject_address = helper_address + len(prefix) + invocation_size + len(success)
        if parallel is not None:
            struct.pack_into('<I', success, 4, reject_address)
        wrapper_base = reject_address + 2
        wrappers, entries, launch_calls = self._wrappers(wrapper_base, old, new, duration_ms,
            held_rotation=held_rotation, parallel=parallel, frontier_global=frontier_global, sites=sites)
        launch, parallel_report = b'', None
        if parallel is not None:
            launch_address = wrapper_base + len(wrappers)
            predicate = (_push_global(parallel.flags[0]) + _push_global(parallel.flags[1]) + b'\x20'
                + _push_global(parallel.flags[2]) + b'\x08\x22\x20'
                + _push_global(frontier_global) + b'\x08\x22\x20')
            launch_code = bytearray(b'\x01\x02\0' + predicate + b'\x07\0\0\0\0'
                + b'\x09' + _pop_global(parallel.flags[2]) + b'\x10\xfd\x10\xfe\x02\0\0\0\0\x04')
            struct.pack_into('<I', launch_code, 3+len(predicate)+1, launch_address+len(launch_code)-1)
            author = parallel.prepare(document, helper_address=launch_address+len(launch_code))
            struct.pack_into('<I', launch_code, len(launch_code)-5, author.entry_address)
            wrappers = bytearray(wrappers)
            for position in launch_calls:
                struct.pack_into('<I', wrappers, position, launch_address)
            wrappers = bytes(wrappers)
            launch = bytes(launch_code) + author.code
            parallel_report = author.report()
        address = wrapper_base + len(wrappers) + len(launch)
        mapping, offsets = {}, {}
        for original in sorted(self.closure.dependencies):
            mapping[original] = address
            offsets[original] = {}
            for item in self.spans[original].instructions:
                offsets[original][item.offset] = address
                address += 9 if item.mnemonic == "call" or item.offset in sites else item.size
        if address >= 2**31:
            raise NativePortraitAcceptanceError("换装原生提交副本超过目标地址范围。")
        # A rejected pair returns before any setter, native apply/cache write
        # or motion starts. No shared globals hold this handoff's two handles.
        struct.pack_into("<I", prefix, predicate_branch+1,
            reject_address)
        code = prefix + _arguments([None] * root_count) + b"\x10\xfd\x10\xfe"
        code += _call(mapping[self.loader.catalog.apply_target]) + old_cleanup + success + b"\x08\x05" + wrappers + launch
        for original in sorted(mapping):
            span = self.spans[original]
            for item in span.instructions:
                raw = bytearray(item.raw)
                if item.mnemonic == "init_stack":
                    raw[1] = span.args + 2
                elif item.mnemonic in {"push_stack", "pop_stack"} and item.operands["value"] <= -2:
                    struct.pack_into("<b", raw, 1, item.operands["value"] - 2)
                elif item.mnemonic in {"jmp", "jz"}:
                    struct.pack_into("<I", raw, 1, offsets[original][item.operands["target"]])
                elif item.mnemonic == "call":
                    raw = bytearray(b"\x10\xfd\x10\xfe" + _call(mapping[item.operands["target"]]))
                elif item.offset in sites:
                    raw = bytearray(b"\x10\xfd\x10\xfe" + _call(entries[sites[item.offset]]))
                code.extend(raw)
        if helper_address + len(code) != address:
            raise NativePortraitAcceptanceError("换装原生提交副本的地址计算不一致。")
        report = dict(schema=SCHEMA, source_sha256=document.source_sha256,
            selector=self.slot.selector, buffers=deepcopy(self.geometry.buffers),
            duration_ms=duration_ms, old_geometry=old, new_geometry=new,
            helper_address=helper_address, helper_size=len(code),
            helper_sha256=hashlib.sha256(code).hexdigest(),
            apply_mapping={str(a): b for a, b in mapping.items()},
            motion_wrapper_entries=entries, owned_buffer_context_arguments=2,
            native_argument_indices_rebased=True, native_local_indices_unchanged=True,
            native_apply_frame_split=False, native_pending_cache_write_instructions_preserved=True,
            native_cache_fields_mapped_to_authored_geometry=False,
            native_wait_and_cleanup_call_graph_preserved=True,
            native_apply_default_arguments_preserved=True,
            native_alpha_argument_flow=self.alpha.report(), header_arity_only=False,
            native_one_ms_fast_override_preserved=True,
            native_alpha_helper_only_used_for_semantic_binding=True,
            other_buffer_motion_arguments_and_returns_preserved=True,
            selected_buffer_entry_exit_xy_z_suppressed=True,
            author_motion_parallelism_connected=parallel is not None,
            author_motion_launch=parallel_report,
            author_motion_launch_after_both_owned_alphas=parallel is not None,
            author_motion_started_before_intact_apply_wait=parallel is not None,
            author_motion_launch_checked_on_apply_return=parallel is not None,
            author_motion_source_yield_boundary_guard=parallel is not None,
            author_motion_boundary_failure_global=frontier_global,
            later_native_alpha_maintenance_kept_after_author_launch=parallel is not None,
            old_author_channels_stopped_after_native_apply=parallel is not None,
            signed_rotation_connected=pose is not None,
            rotation_preservation=None if pose is None else pose.report(),
            old_rotation_scale_setter_omitted=held_rotation[0],
            new_signed_rotation_initialized_before_alpha=held_rotation[1],
            runtime_distinct_owned_pair_guard=True, caller_must_check_result=True,
            old_buffer_lifetime_proven=False, shared_apply_serialization_proven=False,
            resources_published=False, code_emitted=False, scene_export_connected=False,
            source_size_rule_changed=False, image_resampled=False, face_alignment_used=False,
            runtime_verified=False)
        operand = self.geometry.capture_operand(document)
        return NativePortraitSwapApplyPlan(helper_address, bytes(code), operand,
            operand + _call(helper_address), report, self.loader, stamp)
