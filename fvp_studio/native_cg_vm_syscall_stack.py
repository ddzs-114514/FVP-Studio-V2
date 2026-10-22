"""Own-EXE complete SYS argument release loop, not syscall-index/runtime proof.

The SYS descriptor's native argc drives both the incoming argument pointer
and its exact post-call pop/release loop. Binding this code does not establish
the HCB name/index -> native descriptor map, handler side effects, zero-count
destruction, or a scheduler's initial SP. Those remain separate requirements.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _function,_relocated
from .native_cg_thread_handoff import _next_binding
from .native_cg_vm_frames import bind_native_cg_vm_frames

SCHEMA = "fvp-native-cg-vm-syscall-stack/1"


def bind_native_cg_vm_syscall_stack(executable,vm,frames):
    raw = bytes(executable)
    digest = hashlib.sha256(raw).hexdigest()
    if vm["exe_sha256"] != digest or frames != bind_native_cg_vm_frames(raw,vm):
        raise ValueError("CG 系统调用与完整调用帧不是同一份原生引擎。")
    image,sections = _pe_sections(raw)
    next_binding = _next_binding(raw)
    table_at = vm["initializer_offset"]
    if (vm["opcode_count"] != 40 or vm["initializer_bytes"] != 400
            or hashlib.sha256(raw[table_at:table_at+400]).hexdigest() != vm["initializer_sha256"]):
        raise ValueError("CG 系统调用缺少完整的本机指令表。")
    addresses = []
    for opcode in range(40):
        at = table_at+opcode*10
        if raw[at:at+2] != b"\xc7\x05" or struct.unpack_from("<I",raw,at+2)[0] != vm["opcode_table"]+opcode*4:
            raise ValueError("CG 系统调用的指令表位置已经变化。")
        address = struct.unpack_from("<I",raw,at+6)[0]
        _relocated(raw,image,sections,address,executable=True)
        addresses.append(address)
    address = addresses[3]
    offset,body = _function(raw,image,sections,address)
    following = [a for a in addresses if address < a < address+len(body)]
    if following: body = body[:min(following)-address]
    body = body.rstrip(b"\xcc")
    record = vm["handlers"].get(3,vm["handlers"].get("3"))
    if (record is None or record["address"] != address
            or record["code_sha256"] != hashlib.sha256(body).hexdigest()):
        raise ValueError("CG 系统调用处理器不属于当前绑定的原生指令表。")
    fields = vm["thread_frame_fields"]
    sp,pc,fp,rv = (fields[k] for k in ("sp","pc","fp","return_value"))
    word = lambda value:re.escape(struct.pack("<I",value))
    SP,PC,RV,ONE,TWO = map(word,(sp,pc,rv,fp+4,fp+4+0x100))
    prefix = (engine_pattern('native_cg_vm_syscall_stack:52:14')+RV+engine_pattern('native_cg_vm_syscall_stack:52:54')+PC+engine_pattern('native_cg_vm_syscall_stack:53:24')+PC+
        engine_pattern('native_cg_vm_syscall_stack:54:8')+SP+
        engine_pattern('native_cg_vm_syscall_stack:55:8'))
    layouts = {
        "register-call/in-place-SP":(
            engine_pattern('native_cg_vm_syscall_stack:58:12'),
            engine_pattern('native_cg_vm_syscall_stack:60:12')+SP+engine_pattern('native_cg_vm_syscall_stack:60:28')+SP,
            engine_pattern('native_cg_vm_syscall_stack:61:12')+ONE+engine_pattern('native_cg_vm_syscall_stack:61:53')+ONE+
            engine_pattern('native_cg_vm_syscall_stack:62:12'),
            engine_pattern('native_cg_vm_syscall_stack:63:12')+TWO+engine_pattern('native_cg_vm_syscall_stack:63:53')+TWO+
            engine_pattern('native_cg_vm_syscall_stack:64:12'),engine_pattern('native_cg_vm_syscall_stack:64:46')),
        "memory-call/load-decrement-store-SP":(
            engine_pattern('native_cg_vm_syscall_stack:66:12'),
            engine_pattern('native_cg_vm_syscall_stack:67:12')+SP+engine_pattern('native_cg_vm_syscall_stack:67:28')+SP,
            engine_pattern('native_cg_vm_syscall_stack:68:12')+ONE+engine_pattern('native_cg_vm_syscall_stack:68:53')+ONE+
            engine_pattern('native_cg_vm_syscall_stack:69:12'),
            engine_pattern('native_cg_vm_syscall_stack:70:12')+TWO+engine_pattern('native_cg_vm_syscall_stack:70:53')+TWO+
            engine_pattern('native_cg_vm_syscall_stack:71:12'),engine_pattern('native_cg_vm_syscall_stack:71:54'))}
    found = []
    for layout,(call,step,one,two,counter) in layouts.items():
        pattern = (prefix+call+rb"(?P<loop>)"+step+engine_pattern('native_cg_vm_syscall_stack:74:51')+one+engine_pattern('native_cg_vm_syscall_stack:75:45')+two+engine_pattern('native_cg_vm_syscall_stack:76:38')+counter+engine_pattern('native_cg_vm_syscall_stack:77:46'))
        match = re.fullmatch(pattern,body,re.DOTALL)
        if match is not None: found.append((layout,match))
    if len(found) != 1:
        raise ValueError("CG 原生 SYS 有参数路径的完整回收循环尚未绑定。")
    layout,match = found[0]
    jumps = [("zero","done"),("primitive","primitive_label"),("other","other_label"),
             ("join","join_label"),("again","loop")]
    if "first" in match.re.groupindex: jumps.append(("first","loop"))
    for jump,label in jumps:
        if match.end(jump)+struct.unpack("<b",match[jump])[0] != match.start(label):
            raise ValueError("CG 原生 SYS 回收分支没有接回本机完整循环。")
    relative = lambda name:address+match.end(name)+struct.unpack("<i",match[name])[0]
    if relative("release") != vm["release_value_address"]:
        raise ValueError("CG 原生 SYS 返回值释放没有沿用本机调用帧入口。")
    helpers = {}
    for name,k in (("one",1),("two",2)):
        destination = relative(name)
        row = frames["retained_reference_mutators"].get(k,frames["retained_reference_mutators"].get(str(k)))
        if row is None or row["address"] != destination:
            raise ValueError("CG 原生 SYS 参数释放和调用帧没有共用本机对象回收入口。")
        helpers[name] = destination
    table_field = struct.unpack("<I",match["table"])[0]
    if table_field != next_binding["current_thread_fields"]["current"]+32:
        raise ValueError("CG 原生 SYS 不属于本目标的线程控制器。")
    return dict(schema=SCHEMA,exe_sha256=digest,address=address,offset=offset,
        code_sha256=hashlib.sha256(body).hexdigest(),code_bytes=len(body),layout=layout,
        thread_SP_field=sp,syscall_descriptor_table_field=table_field,descriptor_argc_field=4,
        descriptor_handler_field=8,descriptor_this_adjustment_field=12,
        signed_syscall_index_bits=16,native_argc_drives_pointer_and_cleanup=True,
        argument_value_bytes=8,argument_value_base=8,reverse_argument_release_loop_static_bound=True,
        one_argument_value_popped_per_completed_loop_iteration=True,
        post_handler_loop_rechecks_current_descriptor_argc=True,
        zero_or_negative_native_argc_bypasses_loop=True,primitive_arguments_do_not_call_object_releases=True,
        object_arguments_decrease_and_nil_their_slots=True,object_release_helpers=helpers,
        SYS_clears_R_before_handler=True,SYS_argument_cleanup_does_not_directly_overwrite_R=True,
        source_header_arity_to_native_descriptor_bound=False,native_handler_SP_side_effects_audited=False,
        native_descriptor_argc_immutability_proven=False,native_release_helper_side_effects_complete=False,
        zero_count_destructor_audit_complete=False,live_initializer_executed_verified=False,
        runtime_verified=False,scene_export_connected=False)
