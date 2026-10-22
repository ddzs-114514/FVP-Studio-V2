"""Source-owned CG-handle guards for private native text/menu copies.

The source may use the same generic helper for a CG and a UI control. Do not
drop that helper wholesale. At each reviewed mutating syscall the private
wrapper ignores ONLY this target's owned CG handles and forwards every other
handle/argument to the original syscall. Queries, input, text and waits remain.
Opt-in source-bound CG parent protection also rejects attaching a foreign
child into those groups; parent numbers never become Graph identities.
An optional private-camera guard also isolates V3D mutations. Its caller must
first own/quiesce the camera and separately protect its script cache state.
This does not acquire existing engine motions/threads or parent groups.
"""
from copy import deepcopy
import struct

from .native_script_state import validate_native_script_pair
from .portrait_emitter import _encode_push


# Exact supported layouts, not IDs or title-specific addresses. Variants retain
# their full source arguments; no optional value or return value is invented.
PRIMITIVE_MUTATORS = {"PrimSetNull":(1,), "PrimSetSprt":(4,), "PrimSetText":(4,), "PrimSetOP":(3,),
    "PrimSetXY":(3,), "PrimSetWH":(3,), "PrimSetUV":(3,), "PrimSetZ":(2,), "PrimSetRS":(3,), "PrimSetRS2":(4,),
    "PrimSetAlpha":(2,), "PrimSetDraw":(2,), "PrimGroupIn":(2,), "PrimGroupOut":(1,),
    "MotionAlpha":(5,6), "MotionMove":(8,), "MotionMoveZ":(6,), "MotionMoveR":(6,),
    "MotionMoveS2":(8,), "MotionAnim":(4,), "MotionPause":(2,), "MotionAnimStop":(1,), "MotionAlphaStop":(1,),
    "MotionMoveStop":(1,), "MotionMoveZStop":(1,), "MotionMoveRStop":(1,), "MotionMoveS2Stop":(1,)}
GRAPH_MUTATORS = {"GraphLoad":(2,), "GraphRGB":(4,)}
READ_ONLY = {"PrimHit", "MotionAlphaTest", "MotionMoveTest", "MotionMoveZTest",
             "MotionMoveRTest", "MotionMoveS2Test", "MotionAnimTest"}
CAMERA_MUTATORS = {"V3DSet": (3,), "V3DMotion": (6,), "V3DMotionStop": (0,),
                   "V3DMotionPause": (1,)}
CAMERA_QUERIES = {"V3DMotionTest": (0,)}


def _direct_argument(span, position, count):
    """Only a full uninterrupted push window proves an argument's type."""
    if position < count:
        return None
    window = span.instructions[position-count:position]
    pushes = {"push_nil","push_true","push_i8","push_i16","push_i32","push_f32",
              "push_string","push_stack","push_global","push_return"}
    if any(i.mnemonic not in pushes for i in window):
        return None
    interior = {i.offset for i in [*window[1:],span.instructions[position]]}
    if any(i.mnemonic in {"jmp","jz"} and i.operands["target"] in interior for i in span.instructions):
        return None
    return window[0]


def _direct_handle(span, position, count, argument=0):
    first = _direct_argument(span, position, count)
    item = span.instructions[position-count+argument] if first is not None else None
    return (item.operands["value"] if item is not None
            and item.mnemonic in {"push_i8","push_i16","push_i32"} else None)


def _return_inventory(spans, reachable, suppressed, *, scope="CG"):
    """Incoming-register reads before a callee defines its own result.

    HCB 0x04 RET is a void/Nil return; only 0x05 RETV returns a stack value.
    CALL itself does not erase an incoming register before callee execution,
    so a callee that reads it on entry still needs to be rejected.
    """
    maps = {a:{i.offset:n for n,i in enumerate(spans[a].instructions)} for a in reachable}
    reads = {a:False for a in reachable}

    def inspect(address):
        if address in suppressed:
            return False
        span = spans[address]
        pending, visited = [1], set()
        while pending:
            index = pending.pop()
            if index in visited:
                continue
            if not 0 < index < len(span.instructions):
                raise ValueError(f"{scope} 返回值调用链越过原生函数。")
            visited.add(index)
            item = span.instructions[index]
            if item.mnemonic == "push_return":
                return True
            if item.mnemonic in {"ret","retv","syscall"}:
                continue
            if item.mnemonic == "call":
                child = item.operands["target"]
                if reads.get(child, True):
                    return True
                continue
            if item.mnemonic in {"jmp","jz"}:
                if item.operands["target"] not in maps[address]:
                    raise ValueError(f"{scope} 返回值调用链含有跨函数分支。")
                pending.append(maps[address][item.operands["target"]])
                if item.mnemonic == "jmp":
                    continue
            pending.append(index+1)
        return False

    for _ in range(len(reachable)+1):
        updated = {a:inspect(a) for a in reachable}
        if updated == reads:
            break
        reads.update(updated)
    else:
        raise ValueError(f"{scope} 返回值调用链没有在限定范围内收敛。")
    return maps, reads


def _return_unused(spans, span, position, inventory, *, scope="CG"):
    """Conservative CFG/caller check, including loops and unknown edges.

    A skipped mutation has no proven return value. Reject any use of its return
    register before the next call, including a backward edge or a callee's
    incoming-register read. RET clears it to Nil; it must not be mistakenly
    carried into a caller. Authored root results are checked on rewrite.
    """
    maps, reads = inventory
    pending, visited = [(span.start, position+1)], set()
    while pending:
        address, index = pending.pop()
        if (address,index) in visited:
            continue
        instructions, offsets = spans[address].instructions, maps[address]
        if not 0 <= index < len(instructions):
            raise ValueError(f"{scope} 交接的返回值检查越过原生函数。")
        visited.add((address,index))
        item = instructions[index]
        if item.mnemonic == "push_return":
            error = ValueError(f"{scope} 旧刷新使用了画面修改的返回值，不能静默跳过。")
            error.native_details = dict(mutation_function=span.start,
                mutation_site=span.instructions[position].offset,
                return_function=address, return_read_site=item.offset)
            raise error
        if item.mnemonic == "call":
            child = item.operands["target"]
            if reads.get(child, True):
                raise ValueError(f"{scope} 旧刷新的下层函数使用了画面修改的返回值。")
            continue
        if item.mnemonic in {"syscall", "ret", "retv"}:
            continue
        if item.mnemonic in {"jmp", "jz"}:
            if item.operands["target"] not in offsets:
                raise ValueError(f"{scope} 交接分支越过原生函数。")
            pending.append((address,offsets[item.operands["target"]]))
            if item.mnemonic == "jmp":
                continue
        pending.append((address,index+1))


def _entry_results_unused(document, mapping, summaries, *, scope="CG"):
    instructions = document.instructions
    offsets = {i.offset:n for n,i in enumerate(instructions)}
    pending = [n+1 for n,i in enumerate(instructions)
        if i.mnemonic == "call" and i.operands["target"] in mapping]
    visited = set()
    while pending:
        index = pending.pop()
        if index in visited or index == len(instructions):
            continue
        if not 0 <= index < len(instructions):
            raise ValueError(f"{scope} 交接入口的返回值检查越过场景片段。")
        visited.add(index)
        item = instructions[index]
        if item.mnemonic == "push_return":
            raise ValueError(f"场景使用了 {scope} 交接入口的返回值，不能静默跳过画面修改。")
        if item.mnemonic == "call":
            preserve, read = summaries.get(item.operands["target"], (True,True))
            if read:
                raise ValueError(f"{scope} 交接入口之后的函数可能使用旧返回值。")
            if not preserve:
                continue
        if item.mnemonic in {"syscall", "ret", "retv"}:
            continue
        if item.mnemonic in {"jmp", "jz"}:
            if item.operands["target"] not in offsets:
                raise ValueError(f"{scope} 交接入口的返回值分支越过场景片段。")
            pending.append(offsets[item.operands["target"]])
            if item.mnemonic == "jmp":
                continue
        pending.append(index+1)


class _NativeDialogueGuard:
    """Private source/handle guard mechanics shared by concrete bindings."""
    _scope = "CG"

    def bind_rotation_loops(self, rows):
        self.bind_motion_loops({'r': rows})

    def bind_motion_loops(self, by_channel):
        """Only the active captured carrier/channel bypasses line waits.

        Preserve the real query (and its typed return) for every other handle.
        The caller reserves these cells in this scene's private state bank.
        R and XY have separate active flags, even for one actor using them in
        successive beats. A Y loop must not disable that actor's R query.
        """
        self._validate_ownership()
        if self._loop_cells():
            raise ValueError('台词摇摆查询保护已绑定，不能中途改写。')
        if not isinstance(by_channel, dict) or not by_channel or set(by_channel) - {'r', 'xy'}:
            raise ValueError('持续运动查询只支持已绑定的 R／XY 通道。')
        normalized = {c: tuple(tuple(row) for row in rows) for c, rows in by_channel.items()}
        cells = tuple(row for rows in normalized.values() for row in rows)
        if (any(not rows or len(rows) > 4 for rows in normalized.values())
                or any(len(r) != 2 for r in cells)
                or any(type(g) is not int or not 0 <= g < 32768 for r in cells for g in r)
                or len({g for r in cells for g in r}) != 2 * len(cells)):
            raise ValueError('台词摇摆查询保护缺少本目标的独立状态单元。')
        for channel in normalized:
            name = 'MotionMoveRTest' if channel == 'r' else 'MotionMoveTest'
            if self.table.get(name, (None, None))[1] != 1:
                raise ValueError('持续运动尚未绑定本目标查询：' + name)
        self.rotation_loop_cells = normalized.get('r', ())
        self.translation_loop_cells = normalized.get('xy', ())

    def _loop_cells(self):
        return (getattr(self, 'rotation_loop_cells', ())
                + getattr(self, 'translation_loop_cells', ()))

    def _loop_query_cells(self, name):
        if name == 'MotionMoveRTest':
            return getattr(self, 'rotation_loop_cells', ())
        if name == 'MotionMoveTest':
            return getattr(self, 'translation_loop_cells', ())
        return ()

    def _validate_ownership(self):
        pass

    def _validate_visibility(self):
        pass

    def sites(self, spans, reachable, suppressed, *, roots=None):
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        self._validate_ownership()
        thread_sites = {}
        if self.thread_slots is not None:
            if not roots:
                raise ValueError(f"{self._scope} 自制线程交接需要明确的台词／选项入口。")
            review = self.thread_slots.review(roots, suppressed)
            thread_sites = {r["offset"]:r for r in review["native_control_sites"]}
            if any(r["function"] not in reachable - suppressed for r in thread_sites.values()):
                raise ValueError(f"{self._scope} 自制线程范围与本次复制的原生调用链不一致。")
        self._validate_visibility()
        # Inventory all unreviewed layouts at once. Do not gradually widen a
        # prefix-based allowlist or silently treat every Prim/Graph API as a
        # first-handle setter merely because its name looks familiar.
        used = {self.source.header.syscalls[i.operands["id"]].name
            for a in reachable - suppressed for i in spans[a].instructions if i.mnemonic == "syscall"}
        unsupported = sorted(name for name in used if name.startswith(("Prim","Graph","Motion"))
            and name not in PRIMITIVE_MUTATORS and name not in GRAPH_MUTATORS and name not in READ_ONLY)
        if unsupported:
            raise ValueError(f"{self._scope} 旧刷新含有未分类的原生画面调用："+"、".join(
                name+f"（{self.table[name][1]} 参数）" for name in unsupported))
        if self.isolate_camera:
            for name in sorted(used):
                if not name.startswith("V3D"):
                    continue
                layouts = CAMERA_MUTATORS if name in CAMERA_MUTATORS else CAMERA_QUERIES
                if name not in layouts or self.table[name][1] not in layouts[name]:
                    raise ValueError(f"{self._scope} 旧刷新含有未分类的原生镜头调用："+name)
        inventory = _return_inventory(spans, reachable, suppressed, scope=self._scope)
        for a in reachable:
            before = self.return_summaries.get(a, (False,False))
            self.return_summaries[a] = (False, before[1] or inventory[1][a])
        sites, records, other_handle_sites = {}, [], []
        for address in sorted(reachable - suppressed):
            span = spans[address]
            for position, item in enumerate(span.instructions):
                if item.mnemonic != "syscall":
                    continue
                desc = self.source.header.syscalls[item.operands["id"]]
                name, count = desc.name, desc.args
                if self._loop_query_cells(name):
                    if count != 1:
                        raise ValueError('本目标持续运动查询参数不匹配。')
                    # Unlike void mutators, this wrapper MUST retain a return.
                    sites[item.offset] = name
                    records.append(dict(function=address, offset=item.offset, name=name, args=count,
                        namespace='active_owned_rotation_wait' if name == 'MotionMoveRTest'
                                  else 'active_owned_translation_wait', other_handles_query_preserved=True))
                    continue
                if item.offset in thread_sites:
                    _return_unused(spans, span, position, inventory, scope=self._scope)
                    sites[item.offset] = name
                    record = thread_sites[item.offset]
                    records.append(dict(function=address, offset=item.offset, name=name, args=count,
                        namespace="owned_scene_threads", original_slot=record["slot"],
                        native_owned_slot=self.thread_slots.mapping.get(record["slot"]),
                        nil_current_callback_exit=record["nil"]))
                    continue
                if self.isolate_camera and name in CAMERA_MUTATORS:
                    if name == "V3DMotionPause":
                        argument = _direct_argument(span, position, count)
                        if argument is not None and argument.mnemonic == "push_nil":
                            # Nil is the target's pause-state QUERY, not a
                            # resume command. Its native return remains usable.
                            other_handle_sites.append(dict(function=address, offset=item.offset,
                                name=name, native_query_kept=True, original_syscall_kept=True))
                            continue
                    # Camera APIs have no first-handle identity. They must not
                    # pass through the primitive wrapper's handle predicate.
                    _return_unused(spans, span, position, inventory, scope=self._scope)
                    sites[item.offset] = name
                    records.append(dict(function=address, offset=item.offset,
                        name=name, args=count, namespace="owned_scene_camera"))
                    continue
                layouts = GRAPH_MUTATORS if name in GRAPH_MUTATORS else PRIMITIVE_MUTATORS
                if name in layouts:
                    if count not in layouts[name]:
                        raise ValueError(f"{self._scope} 旧刷新含有未接通的原生画面修改参数。")
                    owned = self.graphs if name in GRAPH_MUTATORS else self.primitives
                    direct = _direct_handle(span, position, count)
                    parent = (_direct_handle(span, position, count, 1)
                              if name == "PrimGroupIn" and self.parent_groups else None)
                    group_in_safe = (name != "PrimGroupIn" or not self.parent_groups
                                     or parent is not None and parent not in self.parent_groups)
                    loop_mutator = bool(name in PRIMITIVE_MUTATORS and self._loop_cells())
                    if direct is not None and direct not in owned and group_in_safe and not loop_mutator:
                        other_handle_sites.append(dict(function=address, offset=item.offset, name=name,
                            native_handle=direct, original_syscall_kept=True))
                        continue
                    _return_unused(spans, span, position, inventory, scope=self._scope)
                    sites[item.offset] = name
                    records.append(dict(function=address, offset=item.offset, name=name, args=count))
                elif name.startswith(("Prim", "Graph", "Motion")) and name not in READ_ONLY:
                    raise ValueError(f"{self._scope} 旧刷新含有未分类的原生画面调用："+name+f"（{count} 参数）")
        self.other_handle_sites = other_handle_sites
        return sites, records

    def compile_wrappers(self, names, base):
        self._validate_ownership()
        code, addresses = bytearray(), {}
        thread_names = set(names) & {"ThreadStart", "ThreadExit"}
        if thread_names:
            if self.thread_slots is None:
                raise ValueError(f"{self._scope} 自制线程控制没有绑定独立位置。")
            thread_code, thread_addresses = self.thread_slots.wrappers(thread_names, base)
            code.extend(thread_code)
            addresses.update(thread_addresses)
        for name in sorted(set(names) - thread_names):
            ident, count = self.table[name]
            if self._loop_query_cells(name):
                from .hoshimemo_scene_hook import _push_global
                addresses[name] = base + len(code)
                code.extend(b'\x01\x01\0')
                for flag, primitive in self._loop_query_cells(name):
                    code.extend(_push_global(flag) + b'\x09\x22\x07\0\0\0\0')
                    flag_jump = len(code) - 4
                    code.extend(b'\x10\xfe' + _push_global(primitive) + b'\x22\x07\0\0\0\0')
                    handle_jump = len(code) - 4
                    code.extend(b'\x08\x05')
                    for pos in (flag_jump, handle_jump):
                        struct.pack_into('<I', code, pos, base + len(code))
                code.extend(b'\x10\xfe\x03' + struct.pack('<H', ident) + b'\x14\x05')
                continue
            if self.isolate_camera and name in CAMERA_MUTATORS:
                if count not in CAMERA_MUTATORS[name]:
                    raise ValueError(f"{self._scope} 镜头隔离参数不匹配。")
                addresses[name] = base+len(code)
                if name == "V3DMotionPause":
                    # Dynamic Nil must still reach the original query. Only
                    # non-Nil mutation paths may use the reviewed void return.
                    code.extend(bytes((1, count, 0))+b"\x10\xfe\x08\x22\x07\0\0\0\0")
                    branch = len(code)-4
                    code.extend(b"\x10\xfe\x03"+struct.pack("<H", ident)+b"\x14\x05")
                    struct.pack_into("<I", code, branch, base+len(code))
                    code.extend(b"\x04")
                    continue
                # All arguments are consumed by the original native frame.
                # The return convention is void/Nil, never a guessed value.
                code.extend(bytes((1, count, 0, 4)))
                continue
            owned = self.graphs if name in GRAPH_MUTATORS else self.primitives
            addresses[name] = base+len(code)
            start = len(code)
            code.extend(bytes((1,count,0)))
            # The CG guard's ordinary ownership domain can differ from the
            # retained portrait domain. Protect the captured active-loop
            # carrier too, otherwise a native line refresh can cancel/reset
            # its running rotation or translation.
            if name in PRIMITIVE_MUTATORS and self._loop_cells():
                from .hoshimemo_scene_hook import _push_global
                for flag, primitive in self._loop_cells():
                    code.extend(_push_global(flag) + b'\x09\x22\x07\0\0\0\0')
                    flag_jump = len(code)-4
                    code.extend(b'\x10' + struct.pack('<b', -count-1)
                        + _push_global(primitive) + b'\x22\x07\0\0\0\0')
                    handle_jump = len(code)-4
                    code.extend(b'\x08\x05')
                    for pos in (flag_jump, handle_jump):
                        struct.pack_into('<I', code, pos, base+len(code))
            predicates = [(0,owned)]
            if name == "PrimGroupIn" and self.parent_groups:
                predicates.append((1,self.parent_groups))
            for argument, handles in predicates:
                for handle in sorted(handles):
                    code.extend(b"\x10"+struct.pack("<b", argument-count-1)
                        +_encode_push(handle, self.source.encoding)+b"\x22\x07\0\0\0\0")
                    branch = len(code)-4
                    code.extend(b"\x08\x05")  # Owned mutation: no guessed native return.
                    struct.pack_into("<I", code, branch, base+len(code))
            for i in range(count):
                code.extend(b"\x10"+struct.pack("<b", i-count-1))
            code.extend(b"\x03"+struct.pack("<H", ident)+b"\x14\x05")
            if len(code)-start > 8192:
                raise ValueError(f"{self._scope} 台词交接保护函数超出限定范围。")
        if base+len(code) >= 2**31:
            raise ValueError(f"{self._scope} 台词交接函数超出原生有符号地址范围。")
        return bytes(code), addresses

    def check_entry_results(self, document, mapping):
        _entry_results_unused(document, mapping, self.return_summaries, scope=self._scope)


class NativeCGDialogueGuard(_NativeDialogueGuard):
    def __init__(self, context, presentation, *, isolate_camera=False, camera=None,
                 protect_cg_parents=False, group_ancestry=None, thread_slots=None):
        from .native_cg_presentation import NativeCGPresentation
        if not isinstance(presentation, NativeCGPresentation) or presentation.context is not context:
            raise ValueError("CG 台词交接必须使用当前目标已绑定的显示流程。")
        self.context, self.presentation = context, presentation
        self.thread_slots = thread_slots
        if thread_slots is not None:
            from .native_cg_thread_slots import NativeCGThreadSlots
            if not isinstance(thread_slots, NativeCGThreadSlots) or thread_slots.context is not context:
                raise ValueError("CG 自制台词／选项线程必须绑定当前目标自己的原生容量。")
            thread_slots.validate()
        if type(isolate_camera) is not bool or type(protect_cg_parents) is not bool:
            raise ValueError("CG 镜头隔离必须由本机场景编译器明确选择。")
        self.isolate_camera = isolate_camera
        self.protect_cg_parents = protect_cg_parents
        self.group_ancestry = group_ancestry
        if group_ancestry is not None:
            from .native_cg_group_ancestry import NativeCGGroupAncestry
            if not protect_cg_parents or not isinstance(group_ancestry, NativeCGGroupAncestry):
                raise ValueError("CG 上层分组保护需要本目标已绑定的原生调用链。")
            group_ancestry.validate(presentation.stage)
        self.backend = presentation.backend
        validate_native_script_pair(self.backend.source, self.backend.analysis, runtime_context=context)
        self.camera_cache_slots = ()
        if camera is not None:
            from .native_scene_camera import NativeSceneCamera
            if (not isolate_camera or not isinstance(camera, NativeSceneCamera)
                    or camera.source is not self.backend.source or camera.analysis is not self.backend.analysis):
                raise ValueError("CG 镜头缓存保护必须绑定本目标自己的镜头调用链。")
            slots = tuple(camera.cache_slots)
            total = self.backend.source.header.non_volatile_globals + self.backend.source.header.volatile_globals
            if len(slots) != 3 or len(set(slots)) != 3 or any(type(g) is not int or not 0 <= g < total for g in slots):
                raise ValueError("CG 镜头缓存不是本目标已绑定的三个坐标变量。")
            self.camera_cache_slots = tuple(sorted(slots))
        companions = set().union(*(set(rows) for rows in presentation.companions.values()))
        self.primitives = frozenset(self.backend.planes) | companions
        self.graphs = frozenset(r["graph"] for r in self.backend.resource_graphs) | companions
        self.parent_groups, self.parent_evidence = frozenset(), []
        self.direct_parent_groups = frozenset()
        if protect_cg_parents:
            parents, self.parent_evidence = self._parent_binding()
            if not parents or parents & self.primitives:
                raise ValueError("CG 图层与父分组的身份冲突。")
            self.direct_parent_groups = frozenset(parents)
            if group_ancestry is not None and self.direct_parent_groups != group_ancestry.direct_parents:
                raise ValueError("CG 上层分组与本目标的直接父分组不一致。")
            self.parent_groups = group_ancestry.ancestors if group_ancestry is not None else self.direct_parent_groups
            self.primitives |= self.parent_groups
        if (not self.primitives or not self.graphs or any(type(p) is not int or p <= 0
                for p in self.primitives | self.graphs)):
            raise ValueError("CG 交接缺少目标自己的图元／图像身份。")
        self.table = {d.name:(i,d.args) for i,d in enumerate(self.backend.source.header.syscalls)}
        if len(self.table) != len(self.backend.source.header.syscalls):
            raise ValueError("CG 交接的原生系统调用名重复。")
        self.return_summaries = {}

    @property
    def source(self):
        return self.backend.source

    @property
    def analysis(self):
        return self.backend.analysis

    def _parent_binding(self):
        from .native_background_backend import _literal
        parents, evidence = set(), []
        for plan in self.presentation.stage.plans:
            plan["closure"].compile_snapshot(self.backend.source)
            effects, _, _, _ = self.presentation.stage._creator(plan["creator"],
                tuple(_literal(v) for v in plan["creator_arguments"]),
                plan["creator_globals"], plan["graph"])
            groups = [c for c in effects if c["name"] in {"PrimGroup", "PrimGroupIn"}]
            if len(groups) != 1 or groups[0] != plan["source_group_call"]:
                raise ValueError("CG 父分组与当前原生创建参数不一致。")
            group, values = groups[0], groups[0].get("arguments", ())
            if (len(values) != 2
                    or any(v.get("kind") != "literal" or type(v.get("value")) is not int for v in values)
                    or values[0]["value"] != plan["primitive"]
                    or not 0 < values[1]["value"] < 2**31):
                raise ValueError("CG 父分组必须来自本目标完整的原生创建参数。")
            parents.add(values[1]["value"])
            evidence.append(deepcopy(group))
        return frozenset(parents), evidence

    def _validate_parents(self):
        if self.protect_cg_parents:
            parents, evidence = self._parent_binding()
            if parents != self.direct_parent_groups or evidence != self.parent_evidence:
                raise ValueError("CG 父分组的原生证据已经变化。")
            if self.group_ancestry is not None:
                self.group_ancestry.validate(self.presentation.stage)

    def _validate_ownership(self):
        self._validate_parents()

    def _validate_visibility(self):
        for archive in self.backend.routes:
            self.presentation.visibility.policy(archive)

    def report(self):
        return deepcopy(dict(schema="fvp-native-cg-dialogue-guard/1",
            source_sha256=self.backend.source.source_sha256,
            owned_primitives=sorted(self.primitives), owned_graphs=sorted(self.graphs),
            private_cg_parent_protection=self.protect_cg_parents,
            cg_parent_groups=sorted(self.parent_groups), cg_parent_source_calls=self.parent_evidence,
            cg_direct_parent_groups=sorted(self.direct_parent_groups),
            source_group_ancestry=self.group_ancestry.report() if self.group_ancestry is not None else None,
            authored_thread_slots=self.thread_slots.report() if self.thread_slots is not None else None,
            private_authored_thread_controls_remapped=self.thread_slots is not None,
            private_ancestor_mutation_protection=self.group_ancestry is not None,
            parent_groups_not_added_to_graph_namespace=True,
            foreign_child_insertion_into_cg_parent_guarded=bool(self.parent_groups),
            parent_and_ancestor_ownership_granted=False,
            handle_namespaces_kept_separate=True, other_handles_forwarded=not bool(self.parent_groups),
            non_owned_handles_and_parent_targets_forwarded=True,
            foreign_children_into_owned_groups_forwarded=False if self.parent_groups else None,
            guard_result_use_checked_locally=True, caller_result_use_reviewed=True,
            entry_root_results_checked_on_rewrite=True,
            return_convention="hcb_04_ret_nil_05_retv_stack_value",
            native_ret_handler_byte_verified=False,
            input_text_queries_waits_preserved=True, camera_ownership_granted=False,
            active_owned_rotation_wait_bypassed=bool(getattr(self, 'rotation_loop_cells', ())),
            rotation_wait_scope='only_active_captured_primitive_R',
            active_owned_translation_wait_bypassed=bool(getattr(self, 'translation_loop_cells', ())),
            translation_wait_scope='only_active_captured_primitive_XY',
            private_camera_mutations_isolated=self.isolate_camera,
            native_camera_queries_preserved=True,
            native_camera_pause_nil_query_forwarded=True,
            native_camera_cache_writes_preserved=True,
            camera_cache_global_ids=list(self.camera_cache_slots),
            camera_cache_entry_snapshot_available=bool(self.camera_cache_slots),
            camera_cache_snapshot_required=self.isolate_camera and not self.camera_cache_slots,
            camera_join_or_stop_required_before_use=self.isolate_camera,
            source_non_owned_motion_pause_preserved=True,
            fixed_non_cg_sites_kept_original=getattr(self, "other_handle_sites", []),
            preexisting_engine_thread_ownership_proven=False,
            preexisting_engine_motion_ownership_proven=False,
            original_functions_patched=False, scene_export_connected=False, runtime_verified=False))
