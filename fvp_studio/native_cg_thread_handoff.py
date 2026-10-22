"""Prepare source-local cooperative parking of inherited native callbacks.

Only in-memory libraries, patch plans or private images are returned. ThreadStart sites
must point at these copies BEFORE the engine starts the original story. The
scene's own dialogue/menu threads must use a separately owned, ungated graph.
Their slots must also be disjoint from the parked original slots.
Engine motion, group/resource ownership, global-header installation and real
scheduler acceptance are separate requirements; this does not open export.
"""
from .engine_patterns import engine_pattern

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import re
import struct

from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _function, _relocated
from .native_portrait_acceptance import _function_spans
from .native_portrait_dialogue import _terminated_padded_literal, _translated_literal_stub
from .native_rotation_degrees import _registration
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair


SCHEMA = "fvp-native-cg-thread-handoff/1"
GATE_BYTES = 19


def _instruction_signature(item):
    return (item.offset, item.opcode, item.mnemonic, deepcopy(item.operands), item.raw, item.address_role)


def _header_signature(document):
    h = document.header
    return (h.sysdesc_offset, h.entry_point, h.non_volatile_globals, h.volatile_globals,
            tuple((s.name,s.args) for s in h.syscalls))


def _next_registration(raw, image, sections):
    patterns = [re.compile(p, re.DOTALL) for p in (
        engine_pattern('native_cg_thread_handoff:41:8'),
        engine_pattern('native_cg_thread_handoff:43:8'))]
    founds = []
    for _, rva, length, pointer, flags in sections:
        if not flags & 0x20000000:
            continue
        for pattern in patterns:
            for m in pattern.finditer(raw[pointer:pointer+length]):
                label, address = (struct.unpack("<I", m[k])[0] for k in ("label", "handler"))
                try:
                    at = _relocated(raw, image, sections, label, executable=False, length=11)
                    if raw[at:at+11] != engine_pattern('native_cg_thread_handoff:54:40'):
                        continue
                    offset = _relocated(raw, image, sections, address, executable=True)
                    registrar = image+rva+m.end()+struct.unpack("<i", m["register"])[0]
                    _relocated(raw, image, sections, registrar, executable=True)
                except ValueError:
                    continue
                founds.append(dict(address=address, offset=offset, registrar=registrar,
                    registration_offset=pointer+m.start()))
    if len(founds) != 1:
        raise ValueError("CG 线程交接没有唯一的本机 ThreadNext 注册。")
    return founds[0]


def _next_binding(raw):
    image, sections = _pe_sections(raw)
    binding = _next_registration(raw, image, sections)
    _, code = _function(raw, image, sections, binding["address"])
    # Complete handler: read CURRENT slot, address that slot, set only its
    # yield byte. No argument reads, calls, stack/result writes or exits.
    match = re.fullmatch(engine_pattern('native_cg_thread_handoff:74:25'), code, re.DOTALL)
    if match is None:
        raise ValueError("CG 线程交接尚未证明原生让出执行不会覆盖栈或返回值。")
    fields = {k:struct.unpack("<I", match[k])[0] for k in ("current", "stride", "yield")}
    wait = _registration(raw, image, sections, "ThreadWait", 1)
    _, wait_code = _function(raw, image, sections, wait["address"])
    # Check the same current slot and per-thread address against the target's
    # registered wait function, not a field/address copied from another game.
    current = b"\x8b\x81"+struct.pack("<I", fields["current"])
    stride = b"\x69\xc0"+struct.pack("<I", fields["stride"])
    if fields["yield"] < 0x810:
        raise ValueError("CG 原生当前线程字段无效。")
    base = b"\x8d\x84\x08"+struct.pack("<I", fields["yield"]-0x810)
    if (wait["registrar"] != binding["registrar"]
            or not 0x811 <= fields["stride"] <= 0x100000
            or current+stride not in wait_code or base not in wait_code
            or not wait_code.endswith(engine_pattern('native_cg_thread_handoff:91:38'))):
        raise ValueError("CG 线程让出与等待没有绑定同一份原生当前线程字段。")
    return dict(**binding, exe_sha256=hashlib.sha256(raw).hexdigest(),
        code_sha256=hashlib.sha256(code).hexdigest(), current_thread_fields=fields,
        wait_address=wait["address"], wait_code_sha256=hashlib.sha256(wait_code).hexdigest(),
        argument_stack_untouched=True, return_value_untouched=True, other_threads_not_exited=True,
        return_preservation_scope="ThreadNext_handler_only_not_SYS_dispatch",
        syscall_dispatch_return_preservation_required=True)


@dataclass(frozen=True)
class PreparedCGThreadHandoff:
    code: bytes
    acquire: bytes
    release: bytes
    patches: tuple
    report: dict
    instruction_entries: dict


class NativeCGThreadHandoff:
    def __init__(self, context, executable):
        self.context = context
        self.source, self.analysis = context.document, context.analysis_document
        self.pair = validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        self.source_bytes = self.source.original_bytes
        self.executable = bytes(executable)
        self.spans = {s.start:s for s in _function_spans(self.analysis)}
        self.table = {s.name:(i,s.args) for i,s in enumerate(self.source.header.syscalls)}
        self.header_signature = _header_signature(self.source)
        if len(self.table) != len(self.source.header.syscalls):
            raise ValueError("CG 线程交接的原生系统调用名重复。")
        self.starts = []
        if "ThreadStart" in self.table:
            if self.table["ThreadStart"][1] != 2:
                raise ValueError("CG 线程启动参数未绑定。")
            for span in self.spans.values():
                for n, ins in enumerate(span.instructions):
                    if ins.mnemonic != "syscall" or ins.operands["id"] != self.table["ThreadStart"][0]:
                        continue
                    pointer = span.instructions[n-1] if n else None
                    if (pointer is None or pointer.mnemonic != "push_i32"
                            or pointer.address_role != "thread_start_function_pointer"
                            or pointer.operands["value"] not in self.spans
                            or self.spans[pointer.operands["value"]].args != 0):
                        raise ValueError("CG 线程交接遇到未绑定的动态回调入口，不按线程编号强停。")
                    for item in (pointer, ins):
                        if (item.warning or item.dirty or not item.known
                                or self.source_bytes[item.offset:item.offset+item.size] != item.raw):
                            raise ValueError("CG 原生线程启动指令已经变化。")
                    self.starts.append(dict(function=span.start, offset=pointer.offset,
                        callback=pointer.operands["value"], expected=pointer.raw))
        self.roots = frozenset(s["callback"] for s in self.starts)
        self.next_binding = _next_binding(self.executable) if self.roots else None
        if self.roots and self.table.get("ThreadNext", (None,None))[1] != 0:
            raise ValueError("CG 原生线程让出入口不是零参数。")
        if self.roots and not 0 <= self.table["ThreadNext"][0] <= 0x7fff:
            raise ValueError("CG 线程让出编号超出原生有符号调用表的范围。")
        self.total_globals = self.source.header.non_volatile_globals+self.source.header.volatile_globals
        if self.roots and (self.total_globals >= 65535 or self.source.header.volatile_globals >= 65535):
            raise ValueError("CG 线程交接没有可声明的独立临时变量。")
        self.flag_slot = self.total_globals if self.roots else None
        pending, reachable = list(self.roots), set()
        while pending:
            address = pending.pop()
            if address in reachable:
                continue
            if address not in self.spans or len(reachable) >= 1024:
                raise ValueError("CG 回调调用链缺少原生入口或超出限定范围。")
            reachable.add(address)
            span = self.spans[address]
            children = set(span.calls)
            children.update(i.operands["value"] for i in span.instructions
                            if i.address_role == "thread_start_function_pointer")
            pending.extend(children-reachable)
        self.reachable = frozenset(reachable)
        self.closure = (NativeScriptStateClosure(self.analysis, self.analysis, sorted(reachable),
            max_functions=1024, max_instructions=1048576) if reachable else None)
        self.literals = {}
        for address in sorted(reachable):
            for ins in self.spans[address].instructions:
                actual = self.source_bytes[ins.offset:ins.offset+ins.size]
                if actual == ins.raw:
                    self.literals[ins.offset] = actual
                elif ins.mnemonic == "push_string" and len(actual) == ins.size:
                    if actual[0] == 6:
                        self.literals[ins.offset] = _translated_literal_stub(
                            self.source, self.analysis, ins, actual)["literal"]
                    elif (actual[:2] == ins.raw[:2] and _terminated_padded_literal(actual)
                            and _terminated_padded_literal(ins.raw)):
                        self.literals[ins.offset] = actual
                    else:
                        raise ValueError("CG 线程交接遇到未绑定的翻译文字槽。")
                else:
                    raise ValueError("CG 线程回调的原生控制指令已经变化。")
        self.instruction_signatures = {i.offset:_instruction_signature(i)
            for a in reachable for i in self.spans[a].instructions}

    def validate(self):
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        if self.source.original_bytes != self.source_bytes:
            raise ValueError("CG 线程交接的来源脚本已经变化。")
        if (self.header_signature != _header_signature(self.source)
                or self.table != {s.name:(i,s.args) for i,s in enumerate(self.source.header.syscalls)}
                or self.flag_slot != (self.total_globals if self.roots else None)):
            raise ValueError("CG 线程交接的原生变量或调用表已经变化。")
        if self.closure:
            self.closure.compile_snapshot(self.analysis)
        for address in self.reachable:
            for item in self.spans[address].instructions:
                if (item.dirty or item.warning or not item.known
                        or _instruction_signature(item) != self.instruction_signatures[item.offset]):
                    raise ValueError("CG 原生线程回调的指令证据已经变化。")
        for row in self.starts:
            ins = next((i for i in self.spans[row["function"]].instructions if i.offset == row["offset"]), None)
            if (ins is None or ins.dirty or ins.warning or ins.raw != row["expected"]
                    or ins.operands["value"] != row["callback"]):
                raise ValueError("CG 线程回调入口已经变化。")

    def _gate(self, address, yield_entry):
        # Native SYS releases/nils the return register BEFORE ThreadNext.
        # PUSH_RETURN moves that value into an owned argument; the private
        # one-argument frame yields, then RETV restores it on resumption.
        return (_push_global(self.flag_slot)+b"\x07"+struct.pack("<I", address+GATE_BYTES)
            +b"\x14\x02"+struct.pack("<I",yield_entry)
            +b"\x06"+struct.pack("<I", address))

    def prepare(self, base, *, graph_load_recorder=None):
        self.validate()
        if type(base) is not int or not len(self.source_bytes) <= base < 2**31:
            raise ValueError("CG 回调副本必须追加在当前脚本之后。")
        recorder_routes = {}
        if graph_load_recorder is not None:
            if (not isinstance(graph_load_recorder,dict)
                    or graph_load_recorder.get('source_sha256') != self.source.source_sha256
                    or type(graph_load_recorder.get('recorder_entry')) is not int
                    or not len(self.source_bytes) <= graph_load_recorder['recorder_entry'] < base
                    or self.table.get('GraphLoad',(None,None))[1] != 2):
                raise ValueError("CG 回调的原剧情图像记录入口不属于当前脚本。")
            recorder_routes[self.table['GraphLoad'][0]] = graph_load_recorder['recorder_entry']
            for name,row in graph_load_recorder.get('syscall_recorders',{}).items():
                if (not isinstance(row,dict) or self.table.get(name) != (row.get('id'),row.get('args'))
                        or type(row.get('entry')) is not int
                        or not len(self.source_bytes) <= row['entry'] < base):
                    raise ValueError("CG 回调的画面记录入口不属于当前脚本。")
                recorder_routes[row['id']] = row['entry']
        def raw_for(ins):
            if ins.mnemonic=='syscall' and ins.operands['id'] in recorder_routes:
                return b'\x02'+struct.pack('<I',recorder_routes[ins.operands['id']])
            return self.literals[ins.offset]
        entries, offsets, address = {}, {}, base
        for root in sorted(self.reachable):
            entries[root] = address
            for ins in self.spans[root].instructions:
                offsets[ins.offset] = address
                address += len(raw_for(ins))+(0 if ins.mnemonic == "init_stack" else GATE_BYTES)
        yield_entry = address if self.roots else None
        if address+int(bool(self.roots))*9 >= 2**31:
            raise ValueError("CG 回调副本超出原生有符号地址范围。")
        code = bytearray()
        try:
            for root in sorted(self.reachable):
                for ins in self.spans[root].instructions:
                    if ins.mnemonic != "init_stack":
                        code.extend(self._gate(base+len(code),yield_entry))
                    raw = raw_for(ins)
                    if ins.mnemonic == "call":
                        raw = b"\x02"+struct.pack("<I", entries[ins.operands["target"]])
                    elif ins.mnemonic in {"jmp", "jz"}:
                        raw = bytes((ins.opcode,))+struct.pack("<I", offsets[ins.operands["target"]])
                    elif ins.address_role == "thread_start_function_pointer":
                        raw = b"\x0a"+struct.pack("<i", entries[ins.operands["value"]])
                    code.extend(raw)
        except KeyError as exc:
            raise ValueError("CG 回调副本存在未绑定的调用或分支边界。") from exc
        if self.roots:
            if base+len(code) != yield_entry:
                raise ValueError("CG 返回值保护函数的独立入口已经变化。")
            code.extend(b"\x01\x01\0\x03"+struct.pack("<H",self.table["ThreadNext"][0])
                        +b"\x10\xfe\x05")
        patches = tuple(dict(offset=s["offset"], expected=s["expected"],
            replacement=b"\x0a"+struct.pack("<i", entries[s["callback"]])) for s in self.starts)
        acquire = (b"\x09"+_pop_global(self.flag_slot)+b"\x14\x02"
            +struct.pack("<I",yield_entry)) if self.roots else b""
        release = b"\x08"+_pop_global(self.flag_slot) if self.roots else b""
        report = self.report()
        report.update(append_offset=base, code_bytes=len(code), code_sha256=hashlib.sha256(code).hexdigest(),
            callback_entries=entries, guarded_instruction_count=sum(len(self.spans[a].instructions)-1
                for a in self.reachable), original_start_patch_count=len(patches),
            prepared_in_memory=True, candidate_header_installed=False,
            new_volatile_global_required=bool(self.roots), private_flag_slot=self.flag_slot,
            additional_volatile_globals=int(bool(self.roots)),
            original_callbacks_must_be_retargeted_before_start=True,
            owned_dialogue_menu_thread_graph_must_remain_ungated=True,
            owned_dialogue_menu_thread_slots_must_not_replace_inherited_slots=True,
            native_thread_slot_capacity_and_remapping_required=True,
            gate_bytes=GATE_BYTES,yield_return_preserver_entry=yield_entry,
            gates_preserve_existing_call_frames_and_expression_values=True,
            yield_uses_private_one_argument_frame=bool(self.roots),
            yield_return_saved_before_SYS_and_RETV_restored=bool(self.roots),
            native_vm_frame_semantics_binding_required=bool(self.roots),
            yield_stack_capacity_runtime_verified=False,
            original_graph_load_recorder_supplied=graph_load_recorder is not None,
            original_visual_command_recorder_count=len(recorder_routes),
            scheduler_quiescence_runtime_verified=False, engine_motion_stop_still_required=True)
        return PreparedCGThreadHandoff(bytes(code), acquire, release, patches, deepcopy(report), dict(offsets))

    def report(self):
        self.validate()
        return deepcopy(dict(schema=SCHEMA, source_sha256=self.source.source_sha256,
            analysis_sha256=self.analysis.source_sha256, runtime_binding=self.pair,
            native_yield_binding=self.next_binding, native_callback_count=len(self.roots),
            native_start_count=len(self.starts), native_callback_dependencies=sorted(self.reachable),
            original_thread_ids_not_used_as_ownership=True, new_ThreadExit_for_handoff_emitted=False,
            original_callback_ThreadExit_syscall_count=sum(
                1 for a in self.reachable for i in self.spans[a].instructions
                if i.mnemonic == "syscall"
                and self.source.header.syscalls[i.operands["id"]].name == "ThreadExit"),
            original_callback_ThreadExit_calls_preserved=True,
            native_thread_slot_isolation_proven=False,
            original_thread_pc_and_stack_not_recreated=True, inherited_callbacks_actually_retargeted=False,
            preexisting_engine_thread_ownership_proven=False, engine_groups_or_resources_owned=False,
            scene_export_connected=False, runtime_verified=False))

    def prepare_image(self):
        """Build a private memory image, never an installable game artifact.

        This is the standalone layout recipe. Scene assembly must place this
        library after its OWN appended program, then reserve/apply the same
        entry/global/start changes and keep owned UI callbacks ungated.
        """
        packet = self.prepare(len(self.source_bytes))
        if not self.roots:
            return self.source_bytes, dict(packet.report, standalone_memory_image=True,
                original_header_changed=False, original_start_patches_applied_in_memory=False)
        entry = self.analysis.header.entry_point
        span = self.spans.get(entry)
        if span is None or span.args != 0:
            raise ValueError("CG 临时变量初始化缺少本目标原生零参数启动入口。")
        first = span.instructions[0]
        if (first.mnemonic != "init_stack" or first.dirty or first.warning
                or self.source_bytes[entry:entry+first.size] != first.raw):
            raise ValueError("CG 原生启动栈帧已经变化。")
        bootstrap_entry = len(self.source_bytes)+len(packet.code)
        bootstrap = first.raw+packet.release+b"\x06"+struct.pack("<I",entry+first.size)
        image = bytearray(self.source_bytes+packet.code+bootstrap)
        for patch in packet.patches:
            start = patch["offset"]
            if image[start:start+len(patch["expected"])] != patch["expected"]:
                raise ValueError("CG 原生回调入口在装配前已经变化。")
            image[start:start+len(patch["expected"])] = patch["replacement"]
        header = self.source.header.sysdesc_offset
        struct.pack_into("<H",image,header+6,self.source.header.volatile_globals+1)
        struct.pack_into("<I",image,header,bootstrap_entry)
        # Exact rollback audit: only native ThreadStart pointer literals and
        # the two declared header fields change. No thread id, callback body
        # operation, local, string or source entry frame is rewritten.
        restored = bytearray(image[:len(self.source_bytes)])
        for patch in packet.patches:
            start = patch["offset"]
            restored[start:start+len(patch["expected"])] = patch["expected"]
        restored[header:header+4] = self.source_bytes[header:header+4]
        restored[header+6:header+8] = self.source_bytes[header+6:header+8]
        if bytes(restored) != self.source_bytes:
            raise ValueError("CG 线程交接改动超出了已确认的启动位置。")
        self.validate()
        return bytes(image), dict(packet.report, standalone_memory_image=True,
            original_header_changed=True, candidate_header_installed=True,
            runtime_image_installed=False, old_global_ids_unchanged=True,
            original_start_patches_applied_in_memory=True, private_flag_initialized_at_native_start=True,
            original_entry_frame_used_once=True, bootstrap_entry=bootstrap_entry,
            bootstrap_hex=bootstrap.hex(), bootstrap_continuation=entry+first.size,
            image_sha256=hashlib.sha256(image).hexdigest(), native_global_allocation_runtime_verified=False,
            restored_prefix_byte_identical=True,
            original_callback_instructions_unchanged_except_thread_start_pointers=True,
            scene_program_not_inserted=True, public_installer_must_reject=True)
