"""Source/native-capacity-bound slots for private authored UI callbacks.

This allocates only slots absent from the target's declared script threads.
The inherited callback gate, extra global, hidden native thread creation,
resources and real scheduling still need ownership before public export.
"""
from .engine_patterns import engine_pattern

from copy import deepcopy
import hashlib
import re
import struct

from .native_cg_dialogue_guard import _direct_argument
from .native_cg_thread_handoff import NativeCGThreadHandoff, _instruction_signature, _next_binding
from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _function, _relocated
from .native_rotation_degrees import _registration
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-cg-thread-slots/1"


def _branches(match, pairs):
    for displacement, label in pairs:
        if match.end(displacement)+int.from_bytes(match[displacement], "little", signed=True) != match.start(label):
            raise ValueError("原生线程容量处理器的分支没有回到已确认的入口。")


def _capacity(executable, next_binding):
    image, sections = _pe_sections(executable)
    start = _registration(executable, image, sections, "ThreadStart", 2)
    stop = _registration(executable, image, sections, "ThreadExit", 1)
    _, start_code = _function(executable, image, sections, start["address"])
    _, stop_code = _function(executable, image, sections, stop["address"])
    modern_start = re.fullmatch(
        engine_pattern('native_cg_thread_slots:36:8'), start_code, re.DOTALL)
    legacy_start = re.fullmatch(
        engine_pattern('native_cg_thread_slots:44:8'), start_code, re.DOTALL)
    if modern_start is not None:
        m = modern_start
        count = m["last"][0]+1
        if count != m["count"][0]:
            raise ValueError("原生线程上界与清理数量不一致。")
        _branches(m, (("bad1","done"),("bad2","done"),("range","done_b"),
            ("skip","create"),("repeat","loop")))
        recipe = "unsigned-slot-range"
    elif legacy_start is not None:
        m = legacy_start
        count = m["count"][0]
        if count != struct.unpack("<I",m["loop_count"])[0]:
            raise ValueError("原生线程上界与清理数量不一致。")
        _branches(m, (("bad1","done"),("bad2","done"),("lower","done_i"),
            ("upper","done_i"),("skip","create"),("repeat","loop")))
        recipe = "signed-slot-range"
    else:
        raise ValueError("原生线程容量尚未从完整启动处理器中确定。")
    # LEA disp8 and CMP imm8 are signed here. 0x80 is not +128;
    # accepting it as a clearing-loop count would change the native domain.
    if not 2 <= count <= 127:
        raise ValueError("原生线程数量超出已识别的字面量范围。")
    base, stride = (struct.unpack("<I",m[k])[0] for k in ("base","stride"))
    if (start["registrar"] != stop["registrar"] or start["registrar"] != next_binding["registrar"]
            or stride != next_binding["current_thread_fields"]["stride"]
            or base+0x810 != next_binding["current_thread_fields"]["yield"]):
        raise ValueError("启动、等待与退出没有绑定同一份本机线程数组。")
    for key in ("reset","spawn"):
        helper = start["address"]+m.end(key)+struct.unpack("<i",m[key])[0]
        _relocated(executable,image,sections,helper,executable=True)
    prefix = (engine_pattern('native_cg_thread_slots:81:14'))
    suffix = (engine_pattern('native_cg_thread_slots:84:14'))
    modern_stop = re.fullmatch(prefix+engine_pattern('native_cg_thread_slots:85:38')+suffix+
        engine_pattern('native_cg_thread_slots:87:8'),
        stop_code,re.DOTALL)
    legacy_stop = re.fullmatch(prefix+engine_pattern('native_cg_thread_slots:90:38')+suffix+
        engine_pattern('native_cg_thread_slots:92:8'),
        stop_code,re.DOTALL)
    exit_match = modern_stop if modern_start is not None else legacy_stop
    if exit_match is None:
        raise ValueError("原生线程退出的零／单线程边界尚未完整确定。")
    e = exit_match
    exit_count = e["count"][0] if modern_start is not None else struct.unpack("<I",e["count"])[0]
    if (exit_count != count or e["upper"][0] != (count-2 if modern_start is not None else count)
            or struct.unpack("<I",e["base"])[0] != base or struct.unpack("<I",e["stride"])[0] != stride
            or struct.unpack("<I",e["current"])[0] != next_binding["current_thread_fields"]["current"]):
        raise ValueError("原生启动与退出的线程范围不一致。")
    pairs = [("int","int_label"),("join","join_label"),("bad_type","done"),
             ("nonzero","nonzero_label"),("repeat","loop"),("bad_range","done")]
    if legacy_start is not None:
        pairs.append(("bad_lower","done"))
    _branches(e,pairs)
    for key in ("reset","exit"):
        _relocated(executable,image,sections,stop["address"]+e.end(key)+struct.unpack("<i",e[key])[0],executable=True)
    _relocated(executable,image,sections,struct.unpack("<I",e["controller"])[0],executable=False,length=4)
    return dict(capacity=count, valid_positive_slots=list(range(1,count)), recipe=recipe,
        native_base=base,native_stride=stride, ThreadStart=start, ThreadExit=stop,
        exe_sha256=hashlib.sha256(executable).hexdigest(),
        start_code_sha256=hashlib.sha256(start_code).hexdigest(),exit_code_sha256=hashlib.sha256(stop_code).hexdigest(),
        zero_start_clears_all_threads=True, zero_exit_exits_all_threads=True,
        nil_exit_targets_current_thread=True, positive_exit_is_slot_local=True)


class NativeCGThreadSlots:
    def __init__(self, context, handoff):
        if not isinstance(handoff,NativeCGThreadHandoff) or handoff.context is not context:
            raise ValueError("自制线程必须绑定本目标的原剧情交接。")
        self.context, self.handoff = context, handoff
        self.spans, self.table = handoff.spans, dict(handoff.table)
        self.source = handoff.source
        self.controls, self.used, self.signatures = [], {0}, {}
        for span in self.spans.values():
            for n,ins in enumerate(span.instructions):
                if ins.mnemonic != "syscall":
                    continue
                desc = self.source.header.syscalls[ins.operands["id"]]
                if desc.name not in {"ThreadStart","ThreadExit"}:
                    continue
                count = 2 if desc.name == "ThreadStart" else 1
                if desc.args != count:
                    raise ValueError("自制线程控制的原生参数未绑定。")
                argument = _direct_argument(span,n,count)
                slot = (argument.operands["value"] if argument is not None
                    and argument.mnemonic in {"push_i8","push_i16","push_i32"} else None)
                if desc.name == "ThreadStart" and (type(slot) is not int or slot <= 0):
                    raise ValueError("原剧情有未确定或全局重启的线程编号，不能猜测独立位置。")
                if type(slot) is int and slot > 0:
                    self.used.add(slot)
                self.controls.append(dict(function=span.start,offset=ins.offset,name=desc.name,slot=slot,
                    nil=bool(argument is not None and argument.mnemonic == "push_nil"),position=n))
                for item in (ins,argument):
                    if item is not None:
                        if (item.warning or item.dirty or not item.known
                                or handoff.source_bytes[item.offset:item.offset+item.size] != item.raw):
                            raise ValueError("原生线程控制位置已经变化。")
                        self.signatures[item.offset] = _instruction_signature(item)
        if self.controls and self.table.get("ThreadExit", (None,None))[1] != 1:
            raise ValueError("自制线程清理缺少本目标的单参数原生退出入口。")
        next_binding = (handoff.next_binding or _next_binding(handoff.executable)) if self.controls else None
        self.binding = _capacity(handoff.executable,next_binding) if self.controls else None
        self.capacity = self.binding["capacity"] if self.binding else 0
        if any(s >= self.capacity for s in self.used-{0}):
            raise ValueError("原剧情线程编号越过当前目标的本机容量。")
        highest = max(self.used)
        self.available = tuple([s for s in range(highest+1,self.capacity) if s not in self.used]
            +[s for s in range(1,highest+1) if s not in self.used])
        self.mapping, self.reviews, self.global_exit_domain_frozen = {}, [], False
        self._reserved_mapping = {}
        self.private_mapping, self._reserved_private = {}, {}

    @property
    def owned_slots(self):
        return set(self.mapping.values()) | set(self.private_mapping.values())

    def reserve_private(self, name):
        """Reserve an authored worker, separate from copied dialogue callbacks."""
        self.validate()
        if not isinstance(name, str) or not name or len(name) > 160:
            raise ValueError('自制工作线程名称不合法。')
        if name not in self.private_mapping:
            free = [s for s in self.available if s not in self.owned_slots]
            if not free:
                raise ValueError('当前引擎没有剩余独立线程位置供摇摆使用。')
            self.private_mapping[name] = free[0]
            self._reserved_private = dict(self.private_mapping)
        return self.private_mapping[name]

    def validate(self):
        self.handoff.validate()
        if (self.table != self.handoff.table or self.mapping != self._reserved_mapping
                or self.private_mapping != self._reserved_private
                or any(s in self.used for s in self.owned_slots)):
            raise ValueError("自制线程的编号映射已经变化。")
        if (len(self.owned_slots) != len(self.mapping) + len(self.private_mapping)
                or any(s not in self.available for s in self.owned_slots)):
            raise ValueError("自制线程覆盖了另一个线程位置。")
        for span in self.spans.values():
            for ins in span.instructions:
                if ins.offset in self.signatures and (ins.dirty or ins.warning
                        or _instruction_signature(ins) != self.signatures[ins.offset]):
                    raise ValueError("原生线程编号的指令证据已经变化。")

    def review(self, roots, suppressed=()):
        self.validate()
        roots, suppressed = set(roots), set(suppressed)
        def reach(seeds, callbacks=False):
            pending, result = list(seeds),set()
            while pending:
                a = pending.pop()
                if a in result:
                    continue
                if a not in self.spans or len(result) >= 1024:
                    raise ValueError("自制线程控制调用链缺少确定入口。")
                result.add(a)
                if a not in suppressed:
                    pending.extend(set(self.spans[a].calls)-result)
                    if callbacks:
                        pending.extend(i.operands["value"] for i in self.spans[a].instructions
                                       if i.address_role == "thread_start_function_pointer")
            return result
        main, full = reach(roots),reach(roots,True)
        callback_roots = {i.operands["value"] for a in full-suppressed for i in self.spans[a].instructions
                          if i.address_role == "thread_start_function_pointer"}
        callbacks = reach(callback_roots,True) if callback_roots else set()
        rows = [row for row in self.controls if row["function"] in full-suppressed]
        requested = set()
        for row in rows:
            slot, nil, address = row["slot"],row["nil"],row["function"]
            if row["name"] == "ThreadExit" and nil:
                if address in main or address not in callbacks:
                    raise ValueError("自制台词／选项可能退出主线程，不能借用原作退出入口。")
            elif row["name"] == "ThreadExit" and slot == 0:
                if address in callbacks:
                    raise ValueError("回调中的全局线程退出需要独立当前线程证明。")
            elif type(slot) is int and 0 < slot < self.capacity:
                requested.add(slot)
            else:
                raise ValueError("自制线程控制使用了未确定的线程编号。")
        missing = sorted(requested-self.mapping.keys())
        if missing and self.global_exit_domain_frozen:
            raise ValueError("全局自制线程清理已编译；请先登记全部台词／选项入口再装配。")
        free = [s for s in self.available if s not in self.owned_slots]
        if len(missing) > len(free):
            raise ValueError("当前原生引擎没有足够独立线程位置，不会覆盖原剧情。")
        self.mapping.update(zip(missing,free))
        self._reserved_mapping = dict(self.mapping)
        result = dict(roots=sorted(roots),main_functions=sorted(main),callback_functions=sorted(callbacks),
            requested_original_slots=sorted(requested),native_control_sites=deepcopy(rows),
            global_exit_main_only=all(r["function"] in main for r in rows if r["slot"] == 0),
            current_thread_exit_callback_only=True)
        self.reviews.append(deepcopy(result))
        return result

    def wrappers(self, names, base):
        self.validate()
        if type(base) is not int or not len(self.handoff.source_bytes) <= base < 2**31:
            raise ValueError("自制线程控制副本必须追加在当前脚本之后。")
        if "ThreadExit" in names and any(r["slot"] == 0
                for review in self.reviews for r in review["native_control_sites"]):
            self.global_exit_domain_frozen = True
        code, entries = bytearray(),{}
        for name in sorted(names):
            if name not in {"ThreadStart","ThreadExit"} or name not in self.table:
                raise ValueError("自制线程包装入口不属于已绑定的原生控制。")
            ident,count = self.table[name]
            entries[name] = base+len(code)
            code.extend(bytes((1,count,0)))
            # Every private site was checked for a literal domain above.
            # Branches retain typed Nil and forward the complete native args.
            for original,owned in sorted(self.mapping.items()):
                code.extend(b"\x10"+struct.pack("<b",-count-1)+_encode_push(original,self.source.encoding)+b"\x22\x07\0\0\0\0")
                branch = len(code)-4
                code.extend(_encode_push(owned,self.source.encoding))
                if count == 2:
                    code.extend(b"\x10\xfe")
                code.extend(b"\x03"+struct.pack("<H",ident)+b"\x14\x05")
                struct.pack_into("<I",code,branch,base+len(code))
            if name == "ThreadExit":
                code.extend(b"\x10\xfe\x08\x22\x07\0\0\0\0")
                branch = len(code)-4
                code.extend(b"\x08\x03"+struct.pack("<H",ident)+b"\x14\x05")
                struct.pack_into("<I",code,branch,base+len(code))
                code.extend(b"\x10\xfe"+_encode_push(0,self.source.encoding)+b"\x22\x07\0\0\0\0")
                branch = len(code)-4
                # Native line refresh ends UI callbacks, not authored loops.
                code.extend(self.cleanup(include_private=False)+b"\x08\x05")
                struct.pack_into("<I",code,branch,base+len(code))
            code.extend(b"\x08\x05")  # unreachable outside the reviewed static domains
        if base+len(code) >= 2**31:
            raise ValueError("自制线程控制副本超出原生地址范围。")
        return bytes(code),entries

    def cleanup(self, *, include_private=True):
        self.validate()
        owned = self.owned_slots if include_private else set(self.mapping.values())
        if not owned:
            return b""
        ident,count = self.table["ThreadExit"]
        if count != 1:
            raise ValueError("自制线程退出参数已变化。")
        return b"".join(_encode_push(s,self.source.encoding)+b"\x03"+struct.pack("<H",ident)
                        for s in sorted(owned))

    def report(self):
        self.validate()
        return deepcopy(dict(schema=SCHEMA,native_capacity_binding=self.binding,
            source_declared_or_explicitly_targeted_slots=sorted(self.used),available_declared_slots=list(self.available),
            owned_mapping=self.mapping,private_worker_mapping=self.private_mapping,source_scope_reviews=self.reviews,
            declared_source_slot_disjointness_proven=True,zero_thread_id_never_emitted_by_owned_control=True,
            native_thread_slot_isolation_prepared=True,runtime_slot_ownership_proven=False,
            global_exit_cleanup_domain_frozen=self.global_exit_domain_frozen,
            inherited_threads_must_already_be_parked=True,owned_threads_must_stop_before_global_restore=True,
            hidden_native_thread_creation_review_required=True,scene_export_connected=False,runtime_verified=False))
