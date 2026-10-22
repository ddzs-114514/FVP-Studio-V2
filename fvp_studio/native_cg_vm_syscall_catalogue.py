"""Own literal registration builder and descriptor/sorted-insert chain.

This binds complete linear builder bytes, not scattered registration prefixes.
It does NOT establish the table's initial state, the builder/loader call order,
allocation/shift/exception side effects or later descriptor immutability.
Normal helper returns respecting the native ABI remain an explicit assumption.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _function, _relocated
from .native_cg_thread_handoff import _next_binding
from .native_cg_vm_syscall_header import bind_native_cg_vm_syscall_header
from .native_rotation_degrees import _imports

SCHEMA = "fvp-native-cg-vm-syscall-catalogue/1"
_UNKNOWN = object()


def _target(address, match, key):
    return address+match.end(key)+struct.unpack("<i", match[key])[0]


def _code_record(address, offset, code):
    return dict(address=address, offset=offset, code_bytes=len(code), code_sha256=hashlib.sha256(code).hexdigest())


def _registrar(raw, image, sections, address, older):
    offset, code = _function(raw, image, sections, address)
    start = (engine_pattern('native_cg_vm_syscall_catalogue:32:13'))
    fields = (
        engine_pattern('native_cg_vm_syscall_catalogue:34:8')
        if older else
        engine_pattern('native_cg_vm_syscall_catalogue:37:8'))
    failure = (
        engine_pattern('native_cg_vm_syscall_catalogue:40:8'))
    failure += (engine_pattern('native_cg_vm_syscall_catalogue:43:16') if older else
                engine_pattern('native_cg_vm_syscall_catalogue:44:16'))
    failure += engine_pattern('native_cg_vm_syscall_catalogue:45:15')
    match = re.fullmatch(start+fields+failure, code, re.DOTALL)
    if match is None:
        raise ValueError("CG 原生注册器没有完整绑定自己的名称、参数数和函数描述符。")
    for branch, label in (("success", "done"), ("no_error_object", "empty"), ("error_join", "error")):
        if match.end(branch)+struct.unpack("<b", match[branch])[0] != match.start(label):
            raise ValueError("CG 原生注册器的成功／重复名分支已经变化。")
    targets = {key:_target(address, match, key) for key in ("allocate", "allocate_error", "insert", "free", "error_construct", "throw")}
    if targets["allocate"] != targets["allocate_error"]:
        raise ValueError("CG 原生描述符没有使用自己一致的分配入口。")
    for target in targets.values():
        _relocated(raw, image, sections, target, executable=True)
    for key in ("error_text", "error_type"):
        _relocated(raw, image, sections, struct.unpack("<I", match[key])[0], executable=False)
    return dict(**_code_record(address, offset, code), descriptor_bytes=24, descriptor_name_field=0,
        descriptor_argc_field=4, descriptor_handler_field=8, descriptor_this_adjustment_field=12,
        descriptor_remaining_fields=[16,20], argument_bytes_consumed=24,
        helper_addresses=targets, success_keeps_new_descriptor_pointer=True,
        failure_releases_new_descriptor_before_error_construction=True,
        native_allocation_and_failure_side_effects_complete=False)


def _indexed_insert(raw, image, sections, address, older, link):
    offset, window = _function(raw, image, sections, address)
    prefix = (
        engine_pattern('native_cg_vm_syscall_catalogue:70:8'))
    middle = (engine_pattern('native_cg_vm_syscall_catalogue:74:14') if older else engine_pattern('native_cg_vm_syscall_catalogue:74:45'))
    middle += engine_pattern('native_cg_vm_syscall_catalogue:75:14')
    middle += engine_pattern('native_cg_vm_syscall_catalogue:76:14') if older else engine_pattern('native_cg_vm_syscall_catalogue:76:56')
    tail = (engine_pattern('native_cg_vm_syscall_catalogue:77:12')
            if older else engine_pattern('native_cg_vm_syscall_catalogue:78:26'))
    # A modern indexed insert has no padding before the next lookup function.
    # This closed body has two checked return paths; the window is not a body.
    match = re.match(prefix+middle+tail, window, re.DOTALL)
    if match is None:
        raise ValueError("CG 原生调用表的按位置插入没有完整绑定。")
    if (_target(address, match, "append") != link["native_append"]["address"]
            or _target(address, match, "grow") != link["native_append"]["native_grow_address"]):
        raise ValueError("CG 调用表排序没有沿用自己的追加／扩容入口。")
    if older:
        shift = struct.unpack("<I", match["shift"])[0]
        _relocated(raw, image, sections, shift, executable=False, length=4)
        if _imports(raw, image).get(shift) != ("msvcr71.dll", "memmove"):
            raise ValueError("CG 旧版调用表的搬移没有接到已命名的本机导入。")
    else:
        shift = _target(address, match, "shift")
        _relocated(raw, image, sections, shift, executable=True)
    return dict(**_code_record(address, offset, match[0]), count_field=4, buffer_field=8,
        native_shift_address=shift, shift_is_named_memmove_import=older,
        shift_source_is_insertion_slot=True, shift_destination_is_next_pointer_slot=True,
        shift_bytes_are_remaining_count_times_4=True, new_descriptor_stored_at_requested_index=True,
        native_shift_and_grow_side_effects_complete=False)


def _sorted_insert(raw, image, sections, address, older, link):
    offset, code = _function(raw, image, sections, address)
    first = engine_pattern('native_cg_vm_syscall_catalogue:104:12')+(engine_pattern('native_cg_vm_syscall_catalogue:104:30') if older else engine_pattern('native_cg_vm_syscall_catalogue:104:69'))
    pattern = (first+engine_pattern('native_cg_vm_syscall_catalogue:105:21'))
    match = re.fullmatch(pattern, code, re.DOTALL)
    if match is None:
        raise ValueError("CG 原生调用表的查重／排序插入没有完整绑定。")
    if (_target(address, match, "append") != link["native_append"]["address"]
            or _target(address, match, "lookup") != link["native_lookup"]["address"]):
        raise ValueError("CG 原生注册和 HCB 读名没有使用同一套查名／追加函数。")
    indexed = _indexed_insert(raw, image, sections, _target(address, match, "indexed"), older, link)
    return dict(**_code_record(address, offset, code), native_indexed_insert=indexed,
        empty_table_appends_same_descriptor=True, duplicate_returns_existing_descriptor=True,
        absent_name_uses_lookup_insertion_index=True, success_returns_zero=True,
        complete_sorting_storage_side_effects_proven=False)


def _literal_builder(raw, image, sections, start, address, catalogue, older):
    """Decode ONLY the complete branchless native registration grammar.

    Keep register/stack facts across records. Argument zero may be PUSH EDX,
    not PUSH imm8; a handler literal may precede SUB ESP,16. Never walk backwards
    across unknown instructions or turn a partial prefix into a registration.
    """
    section = next(s for s in sections if s[3] <= start < s[3]+s[2])
    window = raw[start:min(start+0x20000, section[3]+section[2])]
    saved = [3,6,7] if older else [3,5,6,7]
    prologue = bytes(0x50+r for r in saved)
    if not window.startswith(prologue):
        raise ValueError("CG 原生注册总入口缺少完整保存现场的序言。")
    original = {r:("input",r) for r in range(8)}
    regs, memory, sp = dict(original), {}, 0
    for reg in saved:
        sp -= 4; memory[sp] = regs[reg]
    saved_sp = sp
    cursor, frame, catalogue_seen, entries = len(prologue), False, False, []
    value = lambda reg: ("stack",sp) if reg == 4 else regs[reg]
    while cursor < len(window):
        begin, opcode = cursor, window[cursor]
        def need(count):
            if cursor+count > len(window):
                raise ValueError("CG 原生注册总入口的机器指令被截断。")
        if opcode == 0x83:
            need(3)
            if window[cursor:cursor+3] != b"\x83\xec\x10" or frame or sp != saved_sp:
                raise ValueError("CG 原生注册没有独立的 16-byte 函数参数区。")
            sp -= 16; frame = True; cursor += 3
        elif 0xb8 <= opcode <= 0xbf:
            need(5); reg = opcode-0xb8
            if reg == 4: raise ValueError("CG 原生注册覆盖了本机 ESP。")
            regs[reg] = struct.unpack_from("<I",window,cursor+1)[0]; cursor += 5
        elif opcode == 0x33:
            need(2); modrm = window[cursor+1]; reg, rm = (modrm>>3)&7, modrm&7
            if modrm>>6 != 3 or reg != rm or reg == 4:
                raise ValueError("CG 原生注册遇到未绑定的寄存器计算。")
            regs[reg] = 0; cursor += 2
        elif opcode in (0x89,0x8b):
            need(2); modrm = window[cursor+1]; mod, reg, rm = modrm>>6,(modrm>>3)&7,modrm&7
            if mod == 3:
                dst, src = (rm,reg) if opcode == 0x89 else (reg,rm)
                if dst == 4: raise ValueError("CG 原生注册覆盖了本机 ESP。")
                regs[dst] = value(src); cursor += 2
            elif opcode == 0x89 and mod in (0,1) and rm not in (4,5):
                need(3 if mod == 1 else 2)
                displacement = struct.unpack_from("<b",window,cursor+2)[0] if mod == 1 else 0
                base = value(rm)
                if not frame or not isinstance(base,tuple) or base[0] != "stack":
                    raise ValueError("CG 原生注册写到了已确认参数区以外的内存。")
                dest = base[1]+displacement
                if dest%4 or not sp <= dest < saved_sp:
                    raise ValueError("CG 原生注册的参数写入越过自己的栈区。")
                memory[dest] = value(reg); cursor += 3 if mod == 1 else 2
            else:
                raise ValueError("CG 原生注册含有未绑定的内存读取／写入。")
        elif opcode == 0x8d:
            need(6)
            if (window[cursor:cursor+2] != b"\x8d\xb1" or catalogue_seen or entries
                    or regs[1] != original[1] or struct.unpack_from("<I",window,cursor+2)[0] != catalogue):
                raise ValueError("CG 原生注册总入口没有选择当前来源自己的 catalogue。")
            regs[6] = ("catalogue",catalogue); catalogue_seen = True; cursor += 6
        elif opcode in (0x68,0x6a) or 0x50 <= opcode <= 0x57:
            if not frame: raise ValueError("CG 原生注册参数出现在分配区以外。")
            size = 5 if opcode == 0x68 else 2 if opcode == 0x6a else 1
            need(size)
            v = struct.unpack_from("<I",window,cursor+1)[0] if opcode == 0x68 else (
                struct.unpack_from("<b",window,cursor+1)[0] if opcode == 0x6a else value(opcode-0x50))
            sp -= 4; memory[sp] = v; cursor += size
        elif opcode == 0xe8:
            need(5)
            target = address+cursor+5+struct.unpack_from("<i",window,cursor+1)[0]
            if (not frame or sp != saved_sp-24 or not catalogue_seen
                    or regs[1] != ("catalogue",catalogue)):
                raise ValueError("CG 原生注册调用的 catalogue 或完整参数区没有闭合。")
            args = [memory.get(sp+i*4,_UNKNOWN) for i in range(6)]
            if any(type(v) is not int for v in args) or not 0 <= args[1] <= 127:
                raise ValueError("CG 原生注册的名称／参数数／函数结构不是确定字面量。")
            label = _relocated(raw,image,sections,args[0],executable=False)
            data_end = next(s[3]+s[2] for s in sections if s[3] <= label < s[3]+s[2])
            end = raw.find(b"\0",label,min(data_end,label+256))
            if end <= label:
                raise ValueError("CG 原生注册名称没有在自己的数据区完整终止。")
            try: name = raw[label:end].decode("ascii")
            except UnicodeDecodeError as error: raise ValueError("CG 原生注册名称不是已绑定的 ASCII 记录。") from error
            _relocated(raw,image,sections,args[2],executable=True)
            entries.append(dict(name=name,argc=args[1],handler=args[2],this_adjustment=args[3],
                remaining_fields=args[4:],call_address=address+cursor,registrar_address=target))
            for at in range(sp,saved_sp,4): memory.pop(at,None)
            sp = saved_sp; frame = False
            # The complete registrar returns through RET 24. Native helper
            # ABI normal returns are conditional; volatile values are UNKNOWN.
            for reg in (0,1,2): regs[reg] = _UNKNOWN
            cursor += 5
        elif 0x58 <= opcode <= 0x5f:
            reg = opcode-0x58
            if frame or reg == 4 or sp >= 0 or sp not in memory:
                raise ValueError("CG 原生注册总入口没有恢复完整的调用现场。")
            regs[reg] = memory.pop(sp); sp += 4; cursor += 1
        elif opcode == 0xc3:
            if frame or sp != 0 or not entries or any(regs[r] != original[r] for r in saved):
                raise ValueError("CG 原生注册总入口没有走到完整恢复后的返回。")
            return dict(**_code_record(address,start,window[:cursor+1]), entries=entries,
                native_catalogue_field=catalogue, complete_linear_builder_control_flow_bound=True,
                normal_helper_return_ABI_is_an_assumption=True)
        else:
            raise ValueError("CG 原生注册总入口含有未绑定指令或分支，位置 "+str(address+begin)+"。")
    raise ValueError("CG 原生注册总入口未完整返回。")


def bind_native_cg_vm_syscall_catalogue(executable, header, vm, frames):
    raw = bytes(executable)
    link = bind_native_cg_vm_syscall_header(raw,header,vm,frames)
    image, sections = _pe_sections(raw)
    next_binding = _next_binding(raw)
    older = link["layout"] == "signed-word-legacy"
    registrar = _registrar(raw,image,sections,next_binding["registrar"],older)
    insertion = _sorted_insert(raw,image,sections,registrar["helper_addresses"]["insert"],older,link)
    catalogue = link["native_catalogue_field"]
    marker = b"\x8d\xb1"+struct.pack("<I",catalogue)
    prologue = b"\x53\x56\x57" if older else b"\x53\x55\x56\x57\x83\xec\x10"
    candidates = []
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000: continue
        code = raw[pointer:pointer+length]
        for match in re.finditer(re.escape(prologue),code):
            if marker not in code[match.start():match.start()+64]: continue
            try:
                builder = _literal_builder(raw,image,sections,pointer+match.start(),image+rva+match.start(),catalogue,older)
            except ValueError:
                continue
            if all(e["registrar_address"] == next_binding["registrar"] for e in builder["entries"]):
                candidates.append(builder)
    if len(candidates) != 1:
        raise ValueError("CG 原生注册总入口没有完整且唯一地连到自己的 catalogue／注册器。")
    builder = candidates[0]
    # Conservatively reject even byte-level matching registrar calls outside
    # this complete builder. A hidden native writer cannot inherit its facts.
    call_sites = set()
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000: continue
        for match in re.finditer(engine_pattern('native_cg_vm_syscall_catalogue:263:33'),raw[pointer:pointer+length],re.DOTALL):
            address = image+rva+match.start()
            if address+5+struct.unpack("<i",match["relative"])[0] == next_binding["registrar"]:
                call_sites.add(address)
    if call_sites != {entry["call_address"] for entry in builder["entries"]}:
        raise ValueError("CG 原生注册器还有未纳入完整 catalogue 入口的调用位置。")
    by_name = {}
    for entry in builder["entries"]:
        if entry["name"] in by_name:
            raise ValueError("CG 原生注册总入口重复定义了同一名称。")
        by_name[entry["name"]] = entry
    if by_name.get("ThreadNext",{}).get("handler") != next_binding["address"]:
        raise ValueError("CG 完整 catalogue 和本机已绑定的 ThreadNext 不是同一个函数。")
    records = []
    for row in link["source_header_records"]:
        entry = by_name.get(row["name"])
        if entry is None or entry["argc"] != row["header_argc"]:
            raise ValueError("CG 源 HCB 的调用名称／参数数和本机完整注册入口不一致："+row["name"])
        records.append(dict(**row,native_literal_argc=entry["argc"],native_handler=entry["handler"],
            native_registration_call_address=entry["call_address"]))
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=link["layout"],
        native_registrar=registrar,native_sorted_insert=insertion,native_registration_builder=builder,
        source_header_syscalls_sha256=link["source_header_syscalls_sha256"],source_header_literal_bindings=records,
        complete_literal_registration_builder_static_bound=True,
        all_executable_matching_direct_registrar_calls_within_builder=True,
        indirect_registrar_callers_proven_absent=False,
        complete_native_registration_descriptor_static_bound=True,
        complete_sorted_insertion_control_flow_static_bound=True,
        source_header_names_and_argc_match_own_complete_builder=True,
        catalogue_builder_called_before_loader_proven=False,initial_catalogue_is_empty_proven=False,
        initial_syscall_vector_count_zero_proven=False,native_catalogue_construction_and_sorting_complete=False,
        native_descriptor_argc_immutability_proven=False,source_header_arity_to_native_descriptor_bound=False,
        native_allocation_shift_and_failure_side_effects_complete=False,
        runtime_verified=False,scene_export_connected=False)
