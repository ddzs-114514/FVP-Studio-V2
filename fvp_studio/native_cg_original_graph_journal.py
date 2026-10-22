"""Record own original GraphLoad requests and replay them before thread release.

This is a private source-call instrumentation plan, not a pixel snapshot.
Requests (including Nil/unload) are distinct from successful native loads.
Unknown original slots are not treated as empty. Primitive properties, parent
groups, RGB, animated parts and pending caches require separate restoration.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_cg_snapshot_storage import NativeCGSnapshotStorage
from .native_cg_thread_handoff import NativeCGThreadHandoff, _instruction_signature
from .native_portrait_dialogue import _translated_literal_stub, _terminated_padded_literal
from .portrait_emitter import _encode_push

SCHEMA = "fvp-native-cg-original-graph-journal/1"


@dataclass(frozen=True)
class OriginalGraphJournalLibrary:
    code: bytes
    patches: tuple
    report: dict


class NativeCGOriginalGraphJournal:
    def __init__(self,handoff,storage,graphs,*,observed_syscalls=()):
        if (not isinstance(handoff,NativeCGThreadHandoff)
                or not isinstance(storage,NativeCGSnapshotStorage) or storage.handoff is not handoff):
            raise ValueError("原剧情图像记录需要同一场景的原生变量和线程绑定。")
        graphs = tuple(graphs)
        if (not graphs or len(graphs) > 64 or len(set(graphs)) != len(graphs)
                or any(type(g) is not int or not 0 <= g < 2**31 for g in graphs)
                or handoff.table.get("GraphLoad",(None,None))[1] != 2):
            raise ValueError("原剧情图像记录需要明确的本目标 Graph 槽和两参数加载入口。")
        observed_syscalls = tuple(observed_syscalls)
        if (len(set(observed_syscalls)) != len(observed_syscalls)
                or any(not isinstance(name,str) or name not in handoff.table
                       for name in observed_syscalls)):
            raise ValueError("原剧情画面记录入口不属于本目标的系统调用表。")
        self.handoff,self.storage = handoff,storage
        self.observed_syscalls = frozenset(('GraphLoad',*observed_syscalls))
        self.graphs = tuple(sorted(graphs))
        self._graphs = self.graphs
        self.functions,self.literals,self.signatures = {},{},{}
        self.overlays = []
        observed_ids = {handoff.table[name][0] for name in self.observed_syscalls}
        for address,span in handoff.spans.items():
            if not any(i.mnemonic == "syscall" and i.operands["id"] in observed_ids for i in span.instructions):
                continue
            boundaries = {i.offset for i in handoff.analysis.instructions}
            if any(i.mnemonic in {"jmp","jz"} and i.operands["target"] not in boundaries
                   for i in span.instructions):
                raise ValueError("原剧情图像加载函数跳转到未解析的原生指令。")
            for item in span.instructions:
                if item.warning or item.dirty or not item.known:
                    raise ValueError("原剧情图像加载函数的指令不完整。")
                raw = handoff.source_bytes[item.offset:item.offset+item.size]
                if raw == item.raw:
                    self.literals[item.offset] = item.raw
                elif (item.mnemonic=='push_string' and raw[:2]==item.raw[:2]
                      and _terminated_padded_literal(raw) and _terminated_padded_literal(item.raw)):
                    self.literals[item.offset] = raw
                else:
                    overlay = _translated_literal_stub(handoff.source,handoff.analysis,item,raw)
                    self.literals[item.offset] = overlay['literal']
                    self.overlays.append({k:v for k,v in overlay.items() if k!='literal'}
                                         | dict(literal_hex=overlay['literal'].hex()))
                self.signatures[item.offset] = _instruction_signature(item)
            self.functions[address] = span
        if not self.functions:
            raise ValueError("原剧情没有可确认的图像加载函数。")
        self.calls = []
        for item in handoff.analysis.instructions:
            if item.mnemonic == "call" and item.operands['target'] in self.functions:
                if handoff.source_bytes[item.offset:item.offset+item.size] != item.raw:
                    raise ValueError("原剧情图像加载的调用位置已经变化。")
                self.calls.append(dict(offset=item.offset,target=item.operands['target'],expected=item.raw))
        self._calls = tuple((r['offset'],r['target'],r['expected']) for r in self.calls)
        cells = storage.reserve_private(1+2*len(self.graphs),'original_graph_load_journal')
        self.private_ids = cells['private_global_ids']
        self.pause_slot = self.private_ids[0]
        self.slots = {g:dict(resource=self.private_ids[1+2*n],known=self.private_ids[2+2*n])
                      for n,g in enumerate(self.graphs)}

    @property
    def pause(self):
        return b'\x09'+_pop_global(self.pause_slot)

    @property
    def resume(self):
        return b'\x08'+_pop_global(self.pause_slot)

    @property
    def startup(self):
        return self.resume

    def validate(self):
        self.storage.validate(self.handoff)
        self.handoff.validate()
        for span in self.functions.values():
            for item in span.instructions:
                if (item.warning or item.dirty or _instruction_signature(item) != self.signatures[item.offset]):
                    raise ValueError("原剧情图像记录的指令证据已经变化。")
        for row in self.calls:
            if self.handoff.source_bytes[row['offset']:row['offset']+5] != row['expected']:
                raise ValueError("原剧情图像记录的来源调用已经变化。")
        group = next((g for g in self.storage.groups if g['scope']=='original_graph_load_journal'),None)
        if group is None or group['private_global_ids'] != self.private_ids:
            raise ValueError("原剧情图像记录变量不属于当前场景。")
        expected_slots = {g:dict(resource=self.private_ids[1+2*n],known=self.private_ids[2+2*n])
                          for n,g in enumerate(self._graphs)}
        if (self.graphs != self._graphs or self.pause_slot != self.private_ids[0]
                or self.slots != expected_slots
                or tuple((r['offset'],r['target'],r['expected']) for r in self.calls) != self._calls):
            raise ValueError("原剧情图像记录的变量或原始调用映射已经变化。")

    def _prepare_recorders(self,base):
        """Append native-call wrappers; subclasses may add visual recorders."""
        h = self.handoff
        graph_id = h.table['GraphLoad'][0]
        code = bytearray(b'\x01\x02\0\x10\xfd\x10\xfe\x03'+struct.pack('<H',graph_id)+b'\x14')
        recorder = base
        def jump(opcode):
            at = len(code)
            code.extend(bytes((opcode,))+b'\0'*4)
            return at
        def to(at,target):
            struct.pack_into('<I',code,at+1,base+target)
        code.extend(_push_global(self.pause_slot))
        record_branch = jump(7)
        skip_record = jump(6)
        to(record_branch,len(code))
        finishes = []
        for graph,row in self.slots.items():
            code.extend(b'\x10\xfd'+_encode_push(graph,h.source.encoding)+b'\x22')
            next_graph = jump(7)
            code.extend(b'\x10\xfe'+_pop_global(row['resource'])+b'\x09'+_pop_global(row['known']))
            finishes.append(jump(6))
            to(next_graph,len(code))
        to(skip_record,len(code))
        for at in finishes:
            to(at,len(code))
        code.extend(b'\x05')  # Native SYS result retained beneath bookkeeping.
        restore = base+len(code)
        code.extend(b'\x01\0\0')
        for graph,row in self.slots.items():
            code.extend(_push_global(row['known']))
            unknown = jump(7)
            code.extend(_encode_push(graph,h.source.encoding)+_push_global(row['resource'])
                        +b'\x03'+struct.pack('<H',graph_id))
            to(unknown,len(code))
        code.extend(b'\x04')
        return code,dict(recorder_entry=recorder,restore_entry=restore,
            syscall_recorders={'GraphLoad':dict(id=graph_id,args=2,entry=recorder)})

    def prepare(self,base,*,callback_routes=None,hook_offset=None):
        self.validate()
        h = self.handoff
        if type(base) is not int or not len(h.source_bytes) <= base < 2**31:
            raise ValueError("原剧情图像记录库必须追加在本目标脚本之后。")
        if hook_offset is not None and (type(hook_offset) is not int or not 4 <= hook_offset < len(h.source_bytes)):
            raise ValueError("原剧情图像记录的场景接入位置无效。")
        callback_routes = dict(callback_routes or {})
        if any(type(a) is not int or a not in h.reachable or type(v) is not int
               or not base <= v < 2**31 for a,v in callback_routes.items()):
            raise ValueError("原剧情图像记录的线程指针没有对应停驻副本。")
        code,recorder_report = self._prepare_recorders(base)
        recorder_routes = {row['id']:row['entry'] for row in recorder_report['syscall_recorders'].values()}
        entries,offsets,cursor = {},{},base+len(code)
        for address,span in self.functions.items():
            entries[address] = cursor
            for item in span.instructions:
                offsets[item.offset] = cursor
                cursor += (5 if item.offset==hook_offset else 0)
                cursor += 5 if item.mnemonic=='syscall' and item.operands['id'] in recorder_routes else len(self.literals[item.offset])
        if cursor >= 2**31:
            raise ValueError("原剧情图像记录库超出原生有符号地址范围。")
        for address,span in self.functions.items():
            for item in span.instructions:
                if item.offset==hook_offset:
                    code.extend(b'\x06'+struct.pack('<I',offsets[item.offset]+5))
                raw = self.literals[item.offset]
                if item.mnemonic=='syscall' and item.operands['id'] in recorder_routes:
                    raw = _call(recorder_routes[item.operands['id']])
                elif item.mnemonic in {'jmp','jz'}:
                    target = item.operands['target']
                    raw = bytes((item.opcode,))+struct.pack('<I',offsets.get(target,target))
                elif item.mnemonic=='call' and item.operands['target'] in entries:
                    raw = _call(entries[item.operands['target']])
                elif item.address_role=='thread_start_function_pointer' and callback_routes:
                    target = callback_routes.get(item.operands['value'])
                    if target is None:
                        raise ValueError("原剧情图像函数会启动未停驻的线程。")
                    raw = b'\x0a'+struct.pack('<i',target)
                code.extend(raw)
        patches = tuple(dict(offset=row['offset'],expected=row['expected'],replacement=_call(entries[row['target']]))
                        for row in self.calls)
        report = self.report()
        report.update(append_offset=base,code_bytes=len(code),code_sha256=hashlib.sha256(code).hexdigest(),
            **recorder_report,function_entries=entries,instruction_entries=offsets,
            source_hook_marker=(offsets[hook_offset] if hook_offset in offsets else None),
            source_call_patch_count=len(patches),callback_pointer_remapping_supplied=bool(callback_routes),
            native_SYS_result_forwarded_by_RETV=True,bookkeeping_uses_no_additional_syscalls=True,
            source_functions_copied_in_memory=True,source_calls_retargeted_in_memory=True,
            journal_recording_paused_during_authored_scene=True)
        return OriginalGraphJournalLibrary(bytes(code),patches,report)

    def report(self):
        self.validate()
        return dict(schema=SCHEMA,source_sha256=self.handoff.source.source_sha256,
            analysis_sha256=self.handoff.analysis.source_sha256,graphs=list(self.graphs),
            private_global_ids=list(self.private_ids),pause_slot=self.pause_slot,slots=deepcopy(self.slots),
            native_function_count=len(self.functions),verified_translation_overlays=deepcopy(self.overlays),
            native_argument_forwarding=True,known_Nil_unload_distinct_from_unobserved=True,
            unknown_slots_skipped_not_assumed_empty=True,requests_recorded_after_native_return=True,
            observed_requests_are_not_successful_load_proof=True,
            overlay_tail_GraphLoad_coverage_proven=False,engine_load_commit_semantics_bound=False,
            primitive_properties_and_parent_groups_restored=False,animated_parts_restored=False,
            concurrent_or_reentrant_ownership_proven=False,original_images_restored=False,
            scene_export_connected=False,runtime_verified=False,original_game_files_modified=False)
