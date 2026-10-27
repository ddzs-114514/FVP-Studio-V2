"""Private full-scene VM handoff image, NOT a game-ready ownership grant.

The authored scene is a zero-argument function. Entry trampolines retain the
original caller frame and pending arguments, pause inherited callback copies,
call that scene, release only after its teardown, and replay the native hook.
The original and copied callback origins have distinct native continuations.
No file is written and public export must continue to reject this image.
"""
from copy import deepcopy
from dataclasses import replace
from bisect import bisect_right
import hashlib
import struct

from .hcb import parse_bytes
from .hoshimemo_scene_hook import _call
from .native_cg_thread_handoff import NativeCGThreadHandoff,GATE_BYTES,_next_binding
from .native_cg_original_graph_journal import NativeCGOriginalGraphJournal
from .native_cg_thread_slots import NativeCGThreadSlots,_capacity
from .native_cg_global_storage import bind_native_cg_global_storage
from .native_cg_vm_dispatch import bind_native_cg_vm_dispatch
from .native_cg_vm_frames import bind_native_cg_vm_frames
from .native_cg_vm_primitives import bind_native_cg_vm_primitives
from .native_cg_vm_syscall_stack import bind_native_cg_vm_syscall_stack
from .native_cg_vm_syscall_header import bind_native_cg_vm_syscall_header
from .native_cg_vm_syscall_catalogue import bind_native_cg_vm_syscall_catalogue
from .native_cg_vm_save_tree_children import bind_native_cg_vm_save_tree_children
from .native_cg_thread_entry import bind_native_cg_thread_entry
from .native_cg_stack_usage import bind_cg_stack_usage
from .native_cg_snapshot_storage import NativeCGSnapshotStorage
from .native_portrait_dialogue import _translated_literal_stub,_terminated_padded_literal


SCHEMA = "fvp-native-cg-scene-thread-image/1"


def _jmp(address):
    return b"\x06"+struct.pack("<I",address)


def _relocate_truncated_literal_tail(handoff, base):
    """Complete only an EOF-truncated literal return in the NEW image.

    The untranslated instruction supplies the exact continuation. Both the
    surviving jump prefix and every omitted (zero) high byte must agree. The
    old tail stays untouched; its source slot jumps to a complete new copy.
    """
    raw = handoff.source_bytes
    code, patches, repairs = bytearray(), [], []
    for item in handoff.analysis.instructions:
        if item.mnemonic != 'push_string' or item.size < 5:
            continue
        actual = raw[item.offset:item.offset+item.size]
        if (actual[:1] != b'\x06' or len(actual) != item.size
                or actual[5:] != item.raw[5:]):
            continue
        target = struct.unpack_from('<I',actual,1)[0]
        if not len(handoff.analysis.original_bytes) <= target < len(raw)-2 or raw[target] != 14:
            continue
        end = target+2+raw[target+1]
        remaining = len(raw)-end
        if not 2 <= remaining < 5 or not _terminated_padded_literal(raw[target:end]):
            continue
        continuation = _jmp(item.offset+item.size)
        if raw[end:] != continuation[:remaining] or any(continuation[remaining:]):
            continue
        relocated = base+len(code)
        code.extend(raw[target:end]+continuation)
        patches.append(dict(offset=item.offset,expected=actual[:5],replacement=_jmp(relocated)))
        repairs.append(dict(source_offset=item.offset,old_tail=target,new_tail=relocated,
            return_offset=item.offset+item.size,missing_zero_bytes=5-remaining,
            source_tail_unchanged=True))
    return bytes(code), patches, repairs


def _decode(handoff,code,base,additional_globals=0):
    table = bytearray(handoff.analysis.original_bytes[handoff.analysis.header.sysdesc_offset:])
    struct.pack_into("<H",table,6,handoff.source.header.volatile_globals+additional_globals)
    fragment = parse_bytes(struct.pack("<I",4+len(code))+code+table,handoff.source.encoding)
    if fragment.warnings:
        raise ValueError("CG 整场景交接含有未解析的追加指令。")
    return [replace(i,offset=base+i.offset-4) for i in fragment.instructions]


def _preserved_source_calls(h, packet, graph_library, resolve):
    """Identify actual CALL sites still representing their exact source edge.

    New adapters, recorders and yield helpers have no source entry and cannot
    use this route. Replaced or newly introduced calls are likewise excluded.
    """
    origins = {entry:entry for entry in h.spans}
    origins.update({new:old for old,new in packet.report['callback_entries'].items()})
    if graph_library is not None:
        origins.update({new:old for old,new in graph_library.report['function_entries'].items()})
    calls = {}
    for entry,span in h.spans.items():
        for item in span.instructions:
            if item.mnemonic != 'call':
                continue
            locations = [item.offset]
            copied = packet.instruction_entries.get(item.offset)
            if copied is not None:
                locations.append(copied+GATE_BYTES)
            if graph_library is not None:
                copied = graph_library.report['instruction_entries'].get(item.offset)
                if copied is not None:
                    locations.append(copied)
            for pc in locations:
                actual = resolve(pc)
                if (actual is not None and actual.mnemonic == 'call'
                        and origins.get(actual.operands['target']) == item.operands['target']):
                    calls[pc] = (entry,item.operands['target'])
    return origins,calls


def _root_flow(items,base,end):
    """Inline libraries may be skipped, but the authored root may only RET."""
    instructions = {i.offset:i for i in items}
    pending,visited = [base+3],set()
    while pending:
        pc = pending.pop()
        if pc in visited:
            continue
        if pc not in instructions or not base <= pc < end:
            raise ValueError("CG 自制场景越过独立调用帧，不能提前接回原剧情。")
        visited.add(pc)
        i = instructions[pc]
        if i.mnemonic in {"ret","retv"}:
            if pc != end-1 or i.mnemonic != "ret":
                raise ValueError("CG 自制场景没有走到统一的清理返回节点。")
            continue
        if i.mnemonic == "init_stack":
            raise ValueError("CG 自制场景意外进入了内联辅助函数的栈帧。")
        if i.mnemonic in {"jmp","jz"}:
            pending.append(i.operands["target"])
            if i.mnemonic == "jmp":
                continue
        pending.append(pc+i.size)
    if end-1 not in visited:
        raise ValueError("CG 自制场景无法到达清理后的独立返回。")
    return visited


def _requires_cleanup(items,base,end,required):
    instructions = {i.offset:i for i in items}
    pending,seen = [base+3],set()
    while pending:
        pc = pending.pop()
        if pc == required or pc in seen:
            continue
        if pc == end-1:
            raise ValueError("CG 自制场景有绕过线程清理的返回路线。")
        seen.add(pc)
        i = instructions[pc]
        if i.mnemonic in {"jmp","jz"}:
            pending.append(i.operands["target"])
            if i.mnemonic == "jmp":
                continue
        pending.append(pc+i.size)


def _candidate_stack_graph(h,image,patches,added):
    """Actual patched prefix plus verified translation tails, not stale HCB.

    Parsing the whole translated prefix can decode leftover string bytes as
    opcodes. Use the original boundaries, but replace every changed slot with
    its actual declared patch or independently closed literal hop instead.
    """
    by_offset = {p["offset"]:p for p in patches}
    if len(by_offset) != len(patches):
        raise ValueError("CG 栈分析的来源修改位置重复。")
    starts = sorted(by_offset)
    items,overlays = {},[]
    def include(instructions):
        for item in instructions:
            if item.offset in resolved and resolved[item.offset] != item:
                raise ValueError("CG 栈分析的真实指令边界冲突。")
            resolved[item.offset] = item
    resolved = {}
    used = set()
    for item in h.analysis.instructions:
        at = item.offset
        p = by_offset.get(at)
        if p is not None:
            include(_decode(h,p["replacement"],at,int(bool(h.roots))))
            items[at] = resolved[at]
            used.add(at)
            continue
        previous = bisect_right(starts,at)-1
        if previous >= 0:
            p = by_offset[starts[previous]]
            if at < p["offset"]+len(p["replacement"]):
                continue
        items[at] = item
    if used != set(starts):
        raise ValueError("CG 栈分析的来源修改不是原生指令边界。")
    include(added)
    for item in added:
        items[item.offset] = item
    def resolve(at):
        if at in resolved:
            return resolved[at]
        item = items.get(at)
        if item is None:
            return None
        actual = bytes(image[at:at+item.size])
        if actual == item.raw:
            include([item])
        elif item.mnemonic == "push_string" and actual[:1] == b"\x06":
            try:
                proof = _translated_literal_stub(h.source,h.analysis,item,actual)
            except ValueError as error:
                raise ValueError("CG 已到达的汉化文字跳转尚未闭合，位置 "+str(at)+"："+str(error)) from error
            include(_decode(h,actual[:5],at,int(bool(h.roots))))
            include(_decode(h,bytes(image[proof["source_target"]:proof["source_end"]]),
                            proof["source_target"],int(bool(h.roots))))
            overlays.append(dict(offset=at,source_target=proof["source_target"],
                                 source_end=proof["source_end"]))
        elif (item.mnemonic == "push_string" and actual[:2] == item.raw[:2]
                and _terminated_padded_literal(actual) and _terminated_padded_literal(item.raw)):
            include(_decode(h,actual,at,int(bool(h.roots))))
        else:
            raise ValueError("CG 栈分析遇到未声明或未绑定的来源指令修改。")
        return resolved[at]
    return list(items.values()),resolve,overlays


class NativeCGSceneThreadImage:
    def __init__(self,handoff,slots,*,snapshot_storage=None,original_graph_journal=None):
        if (not isinstance(handoff,NativeCGThreadHandoff)
                or not isinstance(slots,NativeCGThreadSlots) or slots.handoff is not handoff):
            raise ValueError("CG 整场景交接必须共用本目标的回调和独立线程绑定。")
        self.handoff,self.slots = handoff,slots
        if snapshot_storage is not None:
            if not isinstance(snapshot_storage,NativeCGSnapshotStorage):
                raise ValueError("CG 状态暂存必须使用本目标的原生快照分配器。")
            snapshot_storage.validate(handoff)
        self.snapshot_storage = snapshot_storage
        if original_graph_journal is not None:
            if (not isinstance(original_graph_journal,NativeCGOriginalGraphJournal)
                    or original_graph_journal.handoff is not handoff
                    or original_graph_journal.storage is not snapshot_storage):
                raise ValueError("原剧情图像记录不属于当前 CG 场景。")
            original_graph_journal.validate()
        self.original_graph_journal = original_graph_journal

    def _replay(self,patch,packet,*,copied,source_graph_patches=(),graph_library=None):
        h = self.handoff
        offset,size = patch["replay_offset"],patch["replay_size"]
        raw = bytes.fromhex(patch["replay_hex"])
        if not copied:
            # Original replay can contain an original ThreadStart pointer too.
            # Do not reintroduce an ungated callback from stale replay bytes.
            out = bytearray(raw)
            for p in (*packet.patches,*source_graph_patches):
                if offset <= p["offset"] and p["offset"]+len(p["expected"]) <= offset+size:
                    at = p["offset"]-offset
                    if out[at:at+len(p["expected"])] != p["expected"]:
                        raise ValueError("CG 原剧情重放的回调字面量已经变化。")
                    out[at:at+len(p["expected"])] = p["replacement"]
            return bytes(out)+(b"" if patch.get("replay_terminal") else _jmp(patch["return_offset"]))
        item = next((i for i in h.analysis.instructions if i.offset == offset),None)
        literal_bank = self.original_graph_journal.literals if copied=='graph' else h.literals
        instruction_entries = (graph_library.report['instruction_entries'] if copied=='graph' else packet.instruction_entries)
        function_entries = (graph_library.report['function_entries'] if copied=='graph' else packet.report['callback_entries'])
        if item is None or offset not in literal_bank:
            raise ValueError("CG 回调接入点的原生重放没有确定的复制边界。")
        literal = bytearray(literal_bank[offset])
        if item.mnemonic == "call":
            target = function_entries.get(item.operands["target"],item.operands['target'] if copied=='graph' else None)
            if target is None:
                raise ValueError("CG 回调重放会逃出原剧情的停驻调用链。")
            struct.pack_into("<I",literal,1,target)
        elif item.mnemonic in {"jmp","jz"}:
            target = instruction_entries.get(item.operands["target"],item.operands['target'] if copied=='graph' else None)
            if target is None:
                raise ValueError("CG 回调重放缺少复制后的分支边界。")
            struct.pack_into("<I",literal,1,target)
        elif item.address_role == "thread_start_function_pointer":
            struct.pack_into("<i",literal,1,packet.report["callback_entries"][item.operands["value"]])
        # A verified translated string overlay is already normalized in the
        # handoff literal. Never jump from a copied callback to the OLD stub's
        # original return PC. Resume its COPY instead, even for terminal replay.
        if item.mnemonic in {"ret","retv","jmp"} and patch.get("replay_terminal"):
            return bytes(literal)
        target = instruction_entries.get(patch["return_offset"])
        if target is None:
            raise ValueError("CG 回调重放无法接回它自己的原生指令位置。")
        return bytes(literal)+_jmp(target)

    def assemble(self,payload,anchor,*,cleanup_sites=(),_defer_preserved_source_cycles=False,
                 voice_replay=None):
        if type(_defer_preserved_source_cycles) is not bool:
            raise ValueError('原作循环续作只能由本机隔离副本明确选择。')
        h,slots = self.handoff,self.slots
        h.validate(); slots.validate()
        if self.snapshot_storage is not None:
            self.snapshot_storage.validate(h)
        additional_globals = (self.snapshot_storage.additional_volatile if self.snapshot_storage is not None
                              else int(bool(h.roots)))
        next_binding = h.next_binding or _next_binding(h.executable)
        storage = bind_native_cg_global_storage(h.executable,h.source.header,next_binding,
                                               additional_volatile=additional_globals)
        if h.roots and storage["private_global_index"] != h.flag_slot:
            raise ValueError("CG 临时变量位置与本引擎分配的变量范围不一致。")
        vm_binding = bind_native_cg_vm_dispatch(h.executable,storage,next_binding,
                        slots.binding or _capacity(h.executable,next_binding))
        storage["global_opcode_index_semantics_bound"] = vm_binding["global_read_write_and_flag_tags_static_bound"]
        frames = bind_native_cg_vm_frames(h.executable,vm_binding)
        syscall_stack = bind_native_cg_vm_syscall_stack(h.executable,vm_binding,frames)
        syscall_header = bind_native_cg_vm_syscall_header(h.executable,h.source.header,vm_binding,frames)
        thread_entry = bind_native_cg_thread_entry(h.executable,vm_binding,frames)
        catalogue = bind_native_cg_vm_syscall_catalogue(h.executable,h.source.header,vm_binding,frames)
        vm_save_tree_children = bind_native_cg_vm_save_tree_children(h.executable,h.source.header,vm_binding,frames)
        vm_save_tree_encoding = vm_save_tree_children['native_vm_save_tree_encoding']
        vm_save_algorithm_children = vm_save_tree_encoding['native_vm_save_algorithm_children']
        vm_save_algorithms = vm_save_algorithm_children['native_vm_save_algorithms']
        vm_save_trees = vm_save_algorithms['native_vm_save_trees']
        vm_save_deflate = vm_save_trees['native_vm_save_deflate']
        vm_state_pack_children = vm_save_deflate['native_vm_state_pack_children']
        vm_state_pack = vm_state_pack_children['native_vm_state_pack']
        vm_controller = vm_state_pack['native_vm_controller']
        vm_lifecycle = vm_controller['native_vm_lifecycle']
        vm_heap_reallocate = vm_lifecycle['native_vm_heap_reallocate']
        vm_heap_exit = vm_heap_reallocate['native_vm_heap_exit']
        vm_heap_errors = vm_heap_exit['native_vm_heap_errors']
        vm_heap_context = vm_heap_errors['native_vm_heap_context']
        vm_heap_allocations = vm_heap_context['native_vm_heap_allocations']
        vm_restore_symbols = vm_heap_allocations['native_vm_restore_symbols']
        vm_restore_huffman = vm_restore_symbols['native_vm_restore_huffman']
        vm_restore_blocks = vm_restore_huffman['native_vm_restore_blocks']
        vm_restore_inflate = vm_restore_blocks['native_vm_restore_inflate']
        vm_restore_children = vm_restore_inflate['native_vm_restore_children']
        vm_restore = vm_restore_children['native_vm_restore']
        vm_thread_startup = vm_restore['native_vm_thread_startup']
        vm_loader = vm_thread_startup['native_vm_loader']
        vm_heap_children = vm_loader['native_vm_heap_children']
        vm_heap_paths = vm_heap_children["native_vm_heap_paths"]
        vm_member_copy = vm_heap_paths["native_vm_member_copy"]
        vm_member_children = vm_member_copy["native_vm_member_children"]
        vm_members = vm_member_children["native_vm_members"]
        vm_teardown = vm_members["native_vm_teardown"]
        vm_cleanup = vm_teardown["native_vm_cleanup"]
        application = vm_cleanup["native_vm_application"]
        instance = application["native_vm_instance"]
        startup = instance["native_vm_startup"]
        primitives = bind_native_cg_vm_primitives(h.executable,vm_binding)
        original = h.source_bytes
        base = len(original)
        if not isinstance(payload,bytes) or not base+4 <= len(payload) < 2**31:
            raise ValueError("CG 整场景交接需要本目标完整的私有场景字节。")
        patch = deepcopy(anchor.get("patch") or {})
        for k in ("patch_offset","replay_offset","replay_size","return_offset"):
            if type(patch.get(k)) is not int:
                raise ValueError("CG 整场景交接缺少本目标的原生接续位置。")
        hook,replay_at,replay_size = patch["patch_offset"],patch["replay_offset"],patch["replay_size"]
        expected,replay = bytes.fromhex(patch.get("expected_hex","")),bytes.fromhex(patch.get("replay_hex",""))
        if (not anchor.get("safe") or patch.get("replay_order") != "custom_then_original"
                or len(expected) != 5 or not 4 <= hook <= h.analysis.code_end-5
                or not 4 <= replay_at < base or replay_size != len(replay) or replay_size <= 0
                or original[hook:hook+5] != expected or original[replay_at:replay_at+replay_size] != replay
                or payload[hook:hook+5] != _jmp(base)):
            raise ValueError("CG 整场景交接的原生接入／重放字节不一致。")
        restored = bytearray(payload[:base]); restored[hook:hook+5] = expected
        if bytes(restored) != original or payload[base:base+3] != b"\x01\0\0" or payload[-1:] != b"\x04":
            raise ValueError("CG 场景不是保持原始前缀的零参数独立函数。")
        source_replay_blocks = []
        source_replay_items = []
        replay_item = next((i for i in h.analysis.instructions if i.offset == replay_at),None)
        if replay_item is not None and replay_item.mnemonic == "push_string" and replay[:1] == b"\x06":
            proof = _translated_literal_stub(h.source,h.analysis,replay_item,
                original[replay_at:replay_at+replay_item.size])
            source_replay_blocks.append(proof)
            source_replay_items = _decode(h,original[proof["source_target"]:proof["source_end"]],proof["source_target"])
        own = _decode(h,payload[base:],base,additional_globals)
        root = _root_flow(own,base,len(payload))
        ends = [r for r in cleanup_sites if r.get("reason") == "before_scene_end_restore"]
        cleanup = slots.cleanup()
        if cleanup:
            if len(ends) != 1:
                raise ValueError("CG 自制线程在接回原剧情前没有唯一清理节点。")
            start,end = ends[0]["byte_range"]
            if (type(start) is not int or type(end) is not int or not 3 <= start < end <= len(payload)-base
                    or payload[base+start:base+end] != cleanup or base+start not in root):
                raise ValueError("CG 自制线程清理字节与场景返回节点不一致。")
            _requires_cleanup(own,base,len(payload),base+start)
        for n,i in enumerate(own):
            if i.mnemonic != "syscall":
                continue
            name = h.source.header.syscalls[i.operands["id"]].name
            count = 2 if name == "ThreadStart" else 1
            if name not in {"ThreadStart","ThreadExit"}:
                continue
            argument = own[n-count] if n >= count else None
            value = argument.operands.get("value") if argument is not None else None
            if not (argument is not None and argument.mnemonic in {"push_i8","push_i16","push_i32"}
                    and type(value) is int and value in slots.owned_slots
                    or name == "ThreadExit" and argument is not None and argument.mnemonic == "push_nil"):
                raise ValueError("CG 自制调用图仍会启动／清理原剧情或未知线程。")
        journal = self.original_graph_journal
        graph_library = journal.prepare(len(payload),hook_offset=hook) if journal is not None else None
        packet = h.prepare(len(payload)+(len(graph_library.code) if graph_library is not None else 0),
            **(dict(graph_load_recorder=graph_library.report) if graph_library is not None else {}))
        if graph_library is not None:
            previous_size = len(graph_library.code)
            graph_library = journal.prepare(len(payload),callback_routes=packet.report['callback_entries'],hook_offset=hook)
            if len(graph_library.code) != previous_size:
                raise ValueError("原剧情图像记录的线程重定向改变了库的大小。")
        graph_patches = graph_library.patches if graph_library is not None else ()
        code = bytearray((graph_library.code if graph_library is not None else b'')+packet.code)
        adapter = len(payload)+len(code)
        # Give the native renderer its next frame after restoring resources
        # and geometry, while original script callbacks are still parked.
        # This is a real native yield, not a fabricated dissolve or delay.
        restore_frame = (b'\x03'+struct.pack('<H',h.table['ThreadNext'][0])
            if graph_library is not None and h.table.get('ThreadNext',(None,None))[1] == 0 else b'')
        # Keep the incoming native return value in this frame while the
        # zero-argument authored scene runs; its RET and SYS calls may nil R.
        code.extend(b"\x01\x01\0"+packet.acquire+(journal.pause if journal is not None else b'')
                    +b"\x02"+struct.pack("<I",base)
                    +(_call(graph_library.report['restore_entry'])+restore_frame+journal.resume
                        if graph_library is not None else b'')
                    +packet.release+b"\x10\xfe\x05")
        trampolines = []
        original_trampoline = len(payload)+len(code)
        def append_trampoline(copied):
            at = len(payload)+len(code)
            body = b"\x14\x02"+struct.pack("<I",adapter)+self._replay(
                patch,packet,copied=copied,source_graph_patches=graph_patches,graph_library=graph_library)
            code.extend(body)
            trampolines.append(dict(entry=at,copied_origin=copied,bytes=len(body),
                original_frame_and_pending_arguments_preserved=True))
            return at
        append_trampoline(False)
        if hook in packet.instruction_entries:
            gate = packet.instruction_entries[hook]
            at = gate-len(payload)
            if bytes(code[at:at+GATE_BYTES]) != h._gate(gate,packet.report["yield_return_preserver_entry"]):
                raise ValueError("CG 回调接入点没有原生停驻边界。")
            copied_trampoline = append_trampoline(True)
            # Redirect only the gate's NIL branch. Even a tiny translated
            # literal remains intact and the active-pause yield loop survives.
            struct.pack_into("<I",code,at+4,copied_trampoline)
        if graph_library is not None and graph_library.report['source_hook_marker'] is not None:
            marker = graph_library.report['source_hook_marker']
            at = marker-len(payload)
            if bytes(code[at:at+5]) != _jmp(marker+5):
                raise ValueError("原剧情图像函数的场景接入标记已经变化。")
            graph_trampoline = append_trampoline('graph')
            code[at:at+5] = _jmp(graph_trampoline)
        tail_code, tail_patches, tail_repairs = _relocate_truncated_literal_tail(h,len(payload)+len(code))
        code.extend(tail_code)
        header_changes = []
        image = bytearray(payload+code)
        source_patches = [dict(offset=hook,expected=expected,replacement=_jmp(original_trampoline))]
        source_patches.extend(packet.patches)
        source_patches.extend(graph_patches)
        source_patches.extend(tail_patches)
        for p in source_patches:
            start = p["offset"]
            if p is not source_patches[0] and (start < hook+5 and start+len(p["expected"]) > hook):
                raise ValueError("CG 剧情接入点与原线程指针重叠。")
            current = _jmp(base) if p is source_patches[0] else p["expected"]
            if image[start:start+len(current)] != current:
                raise ValueError("CG 整场景装配前的来源字节已经变化。")
            image[start:start+len(current)] = p["replacement"]
        bootstrap = None
        if additional_globals:
            entry = h.analysis.header.entry_point
            span = h.spans.get(entry)
            first = span.instructions[0] if span is not None else None
            if (span is None or span.args != 0 or first.mnemonic != "init_stack"
                    or first.warning or first.dirty or original[entry:entry+first.size] != first.raw
                    or entry <= hook < entry+first.size):
                raise ValueError("CG 整场景交接缺少未修改的原生启动栈帧。")
            bootstrap = len(image)
            continuation = (graph_library.report['instruction_entries'].get(entry+first.size,entry+first.size)
                            if graph_library is not None else entry+first.size)
            image.extend(first.raw+packet.release+(journal.startup if journal is not None else b'')+_jmp(continuation))
            hdr = h.source.header.sysdesc_offset
            for at,value,size in ((hdr,bootstrap,4),(hdr+6,h.source.header.volatile_globals+additional_globals,2)):
                raw = struct.pack("<I" if size == 4 else "<H",value)
                header_changes.append(dict(offset=at,expected=original[at:at+size],replacement=raw))
                image[at:at+size] = raw
        if len(image) >= 2**31:
            raise ValueError("CG 整场景交接超出原生有符号地址范围。")
        voice_patches = []
        if voice_replay is not None:
            from .native_voice_backlog import NativeVoiceBacklogProgram
            if not isinstance(voice_replay, NativeVoiceBacklogProgram) or voice_replay.source is not h.source:
                raise ValueError('回看配音程序不属于当前场景脚本。')
            voice_patches = voice_replay.patch_image(image, function_maps=(
                packet.report['callback_entries'],
                graph_library.report['function_entries'] if graph_library is not None else {}))
            source_patches.extend(p for p in voice_patches if p['offset'] < base)
        all_added = _decode(h,bytes(image[base:]),base,additional_globals)
        boundaries = ({i.offset for i in h.analysis.instructions}|{i.offset for i in h.source.instructions}
                      |{i.offset for i in all_added}|{i.offset for i in source_replay_items})
        if any(i.mnemonic in {"call","jmp","jz"} and i.operands["target"] not in boundaries for i in all_added):
            raise ValueError("CG 整场景交接含有未绑定的调用或接续边界。")
        rollback = bytearray(image[:base])
        for p in [*source_patches,*header_changes]:
            rollback[p["offset"]:p["offset"]+len(p["expected"])] = p["expected"]
        if bytes(rollback) != original:
            raise ValueError("CG 整场景交接修改了已声明位置之外的原始字节。")
        stack_items,resolve_instruction,stack_overlays = _candidate_stack_graph(h,image,source_patches,all_added)
        stack_roots = {bootstrap if bootstrap is not None else h.analysis.header.entry_point,base}
        # callback_entries maps the ENTIRE copied CALL closure. Its ordinary
        # parameterized helpers are not external scheduler roots. Root only
        # the actual source ThreadStart callbacks; discover owned UI workers
        # from reached SYS arguments, including pointers forwarded by wrappers.
        initial_callbacks = {packet.report["callback_entries"][a] for a in h.roots}
        stack_roots.update(initial_callbacks)
        source_origins,source_calls = (_preserved_source_calls(h,packet,graph_library,resolve_instruction)
            if _defer_preserved_source_cycles else (None,None))
        stack_usage = bind_cg_stack_usage(stack_items,h.source.header.syscalls,stack_roots,
            frames["stack_capacity_cells"],instruction_resolver=resolve_instruction,
            native_integer_conditions_bound=primitives["integer_equality_static_bound"],
            native_primitive_equality_results=primitives["primitive_equality_results"],
            native_table_scalar_access_bound=bool(primitives.get('native_table_scalar_access')),
            source_function_origins=source_origins,deferred_source_calls=source_calls,
            thread_start_syscall_id=h.table.get("ThreadStart",(None,None))[0])
        native_started = initial_callbacks|set(stack_usage["discovered_thread_callback_entries"])
        for requirement in stack_usage["root_requirements"]:
            bound = requirement["entry"] in native_started
            requirement["native_ThreadStart_SP_static_bound"] = bound
            if bound:
                if requirement["args"] != 0 or requirement["external_entry_SP_assumed"] != 0:
                    raise ValueError("CG 已确认的原生 ThreadStart 入口不是零参数栈。")
                requirement["native_ThreadStart_initial_SP"] = 0
        # The bootstrap/main creator and a separately profiled scene CALL root
        # are NOT established by the ThreadStart helper. Keep global entry and
        # complete-native-stack grants closed until their own chain is bound.
        stack_usage["native_ThreadStart_zero_SP_entries"] = sorted(native_started)
        stack_usage["external_entry_SP_basis"] = "ThreadStart_callbacks_only;other_roots_relative"
        # Complete literal registrations match this source's HCB names/argc,
        # Full normal ctor/startup paths now bind local count zero and local
        # builder-before-loader. Same-instance construction, once-only use,
        # clear/reload and opaque child effects still do NOT reach this load.
        # Do NOT feed this conditional match as native_syscall_arities_bound.
        stack_usage["source_header_literals_match_own_complete_catalogue_builder"] = True
        stack_usage["own_normal_constructor_and_startup_paths_static_bound"] = True
        # Parent paths agree on an embedded offset, not on a live instance or
        # a once-only/clear-before-reload lifetime. Arity/root grants stay off.
        stack_usage["own_parent_normal_paths_static_bound"] = True
        stack_usage["own_application_and_parent_cleanup_normal_paths_static_bound"] = True
        stack_usage["own_controller_vector_cleanup_normal_paths_static_bound"] = True
        stack_usage["own_pre_vector_member_teardown_normal_path_static_bound"] = True
        stack_usage["own_pre_vector_member_setter_normal_paths_static_bound"] = True
        stack_usage["normal_zero_argument_setter_returns_consume_four_bytes_static_bound"] = True
        stack_usage["own_member_allocator_bridges_static_bound"] = True
        stack_usage["own_member_construct_and_callback_normal_paths_static_bound"] = True
        stack_usage["own_complete_member_copy_instruction_paths_static_bound"] = True
        stack_usage["own_allocation_release_failure_dispatch_paths_static_bound"] = True
        stack_usage["own_heap_child_dispatch_instruction_paths_static_bound"] = True
        stack_usage["own_loader_entry_header_normal_return_and_error_dispatch_static_bound"] = True
        stack_usage["own_complete_dispatch_thread_and_main_initialization_paths_static_bound"] = True
        stack_usage["own_complete_post_main_explicit_normal_paths_static_bound"] = True
        stack_usage["normal_CRT_free_frame_argument_return_mapping_static_bound_conditional"] = (
            vm_teardown["normal_CRT_free_frame_argument_return_mapping_static_bound_conditional"])
        stack_usage["actual_candidate_control_flow_checked"] = True
        stack_usage["verified_translation_tail_count"] = len(stack_overlays)
        stack_usage["declared_source_patch_count"] = len(source_patches)
        h.validate(); slots.validate()
        report = dict(schema=SCHEMA,memory_only=True,scene_program_inserted=True,
            scene_entry=base,scene_zero_argument_call_frame=True,scene_root_control_flow_checked=True,
            native_thread_handoff=deepcopy(packet.report),authored_thread_slots=slots.report(),
            original_graph_journal=(deepcopy(graph_library.report) if graph_library is not None else None),
            original_graph_requests_replayed_before_thread_release=graph_library is not None,
            original_stage_commands_replayed_before_thread_release=bool(graph_library and
                graph_library.report.get('original_stage_command_restore_emitted')),
            resource_restore_native_frame_handoff_emitted=bool(restore_frame),
            original_callbacks_released_after_native_frame=bool(restore_frame),
            instruction_boundaries_checked=True,new_instruction_count=len(all_added),
            native_voice_backlog=voice_replay.report() if voice_replay else None,
            original_global_ids_unchanged=True,private_flag_initialized_at_native_start=bool(h.roots),
            native_startup_frame_used_once=True,original_replay_kept=True,trampolines=trampolines,
            scene_return_preserver_entry=adapter,scene_return_preserved_in_one_argument_frame=True,
            verified_source_replay_overlays=deepcopy(source_replay_blocks),
            repaired_truncated_translation_tails=tail_repairs,
            original_start_patches_applied_in_memory=bool(packet.patches),
            candidate_header_installed_in_memory=bool(header_changes),
            additional_volatile_globals=additional_globals,
            snapshot_storage=(self.snapshot_storage.report() if self.snapshot_storage is not None else None),
            copied_hook_nil_branch_retargeted=hook in packet.instruction_entries,
            source_patch_ranges=[dict(offset=p["offset"],bytes=len(p["expected"]),
                expected_hex=p["expected"].hex(),replacement_hex=p["replacement"].hex())
                for p in [*source_patches,*header_changes]],restored_prefix_byte_identical=True,
            original_source_sha256=h.source.source_sha256,image_sha256=hashlib.sha256(image).hexdigest(),
            native_global_storage=deepcopy(storage),native_global_header_count_range_bound=bool(storage),
            native_vm_dispatch=deepcopy(vm_binding),native_vm_opcode_table_bound=bool(vm_binding),
            native_vm_frames=deepcopy(frames),native_call_frame_static_bound=True,
            native_vm_syscall_stack=deepcopy(syscall_stack),native_SYS_argument_cleanup_static_bound=True,
            native_vm_syscall_header=deepcopy(syscall_header),native_SYS_header_lookup_append_static_bound=True,
            native_vm_syscall_catalogue=deepcopy(catalogue),native_catalogue_literal_registration_static_bound=True,
            native_vm_startup=deepcopy(startup),native_normal_constructor_startup_static_bound=True,
            native_vm_instance=deepcopy(instance),native_parent_normal_paths_static_bound=True,
            native_vm_application=deepcopy(application),native_application_normal_paths_static_bound=True,
            native_vm_cleanup=deepcopy(vm_cleanup),native_controller_vector_cleanup_normal_paths_static_bound=True,
            native_vm_teardown=deepcopy(vm_teardown),native_pre_vector_member_teardown_normal_path_static_bound=True,
            native_vm_members=deepcopy(vm_members),native_pre_vector_member_setter_normal_paths_static_bound=True,
            native_vm_member_children=deepcopy(vm_member_children),native_member_allocator_bridges_static_bound=True,
            native_member_construct_and_callback_normal_paths_static_bound=True,
            native_vm_member_copy=deepcopy(vm_member_copy),native_member_copy_instruction_paths_static_bound=True,
            native_vm_heap_paths=deepcopy(vm_heap_paths),native_heap_dispatch_instruction_paths_static_bound=True,
            native_vm_heap_children=deepcopy(vm_heap_children),native_heap_child_dispatch_instruction_paths_static_bound=True,
            native_vm_loader=deepcopy(vm_loader),native_HCB_loader_dispatch_instruction_paths_static_bound=True,
            native_vm_thread_startup=deepcopy(vm_thread_startup),native_thread_startup_instruction_paths_static_bound=True,
            native_vm_restore=deepcopy(vm_restore),native_restore_instruction_paths_static_bound=True,
            native_vm_restore_children=deepcopy(vm_restore_children),native_restore_child_instruction_paths_static_bound=True,
            native_vm_restore_inflate=deepcopy(vm_restore_inflate),native_restore_inflate_control_binding_static_bound=True,
            native_vm_restore_blocks=deepcopy(vm_restore_blocks),native_restore_block_controller_binding_static_bound=True,
            native_vm_restore_huffman=deepcopy(vm_restore_huffman),native_restore_huffman_builder_binding_static_bound=True,
            native_vm_restore_symbols=deepcopy(vm_restore_symbols),native_restore_symbol_decoder_binding_static_bound=True,
            native_vm_heap_allocations=deepcopy(vm_heap_allocations),native_heap_allocation_descendants_binding_static_bound=True,
            native_vm_heap_context=deepcopy(vm_heap_context),native_heap_context_descendants_binding_static_bound=True,
            native_vm_heap_errors=deepcopy(vm_heap_errors),native_heap_error_descendants_binding_static_bound=True,
            native_vm_heap_exit=deepcopy(vm_heap_exit),native_heap_exit_descendants_binding_static_bound=True,
            native_vm_heap_reallocate=deepcopy(vm_heap_reallocate),native_heap_reallocation_descendants_binding_static_bound=True,
            native_vm_lifecycle=deepcopy(vm_lifecycle),native_application_lifecycle_binding_static_bound=True,
            native_vm_controller=deepcopy(vm_controller),native_controller_tick_and_thread_gate_binding_static_bound=True,
            native_vm_state_pack=deepcopy(vm_state_pack),native_exit_state_pack_binding_static_bound=True,
            native_vm_state_pack_children=deepcopy(vm_state_pack_children),native_save_IO_children_binding_static_bound=True,
            native_vm_save_deflate=deepcopy(vm_save_deflate),native_save_deflate_control_binding_static_bound=True,
            native_vm_save_trees=deepcopy(vm_save_trees),native_save_tree_paths_binding_static_bound=True,
            native_vm_save_algorithms=deepcopy(vm_save_algorithms),native_save_algorithm_bodies_binding_static_bound=True,
            native_vm_save_algorithm_children=deepcopy(vm_save_algorithm_children),native_save_algorithm_children_binding_static_bound=True,
            native_vm_save_tree_encoding=deepcopy(vm_save_tree_encoding),native_save_tree_encoding_binding_static_bound=True,
            native_vm_save_tree_children=deepcopy(vm_save_tree_children),native_save_tree_children_binding_static_bound=True,
            native_thread_start_entry=deepcopy(thread_entry),native_ThreadStart_entry_static_bound=True,
            native_vm_integer_facts=deepcopy(primitives),
            native_stack_usage=stack_usage,
            relative_candidate_stack_capacity_checked=stack_usage['relative_frame_and_operand_heights_bound'],
            native_call_frame_and_retained_object_lifetime_proven=False,
            runtime_image_installed=False,native_global_allocation_runtime_verified=False,
            preexisting_engine_thread_ownership_proven=False,hidden_native_thread_creation_review_required=True,
            engine_motion_and_group_ownership_proven=False,scene_export_connected=False,
            runtime_verified=False,public_installer_must_reject=True)
        return bytes(image),report
