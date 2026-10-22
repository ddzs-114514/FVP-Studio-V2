"""Private native opcode-table/VM-field binding, never engine acceptance.

The initializer, actual opcode-byte dispatch loop and requested handlers must
agree in this EXE. In particular SYS clears R and PUSH_RETURN moves/nils R;
checking the ThreadNext handler alone cannot prove return preservation.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated,_function
from .native_cg_thread_handoff import _next_binding
from .native_cg_thread_slots import _capacity

SCHEMA = "fvp-native-cg-vm-dispatch/1"


def _u(value):
    return struct.pack("<I",value)


def _pattern(code):
    return re.compile(code,re.DOTALL)


def _mapped_table(raw,image,sections,address,length):
    pe = struct.unpack_from("<I",raw,0x3c)[0]
    image_size = struct.unpack_from("<I",raw,pe+24+56)[0]
    if not 0 <= address-image < address-image+length <= image_size:
        raise ValueError("原生指令表超出本机 EXE 的映射范围。")
    rows = [s for s in sections if not s[4]&0x20000000 and s[4]&0x80000000
            and s[1] <= address-image and address-image+length <= s[1]+max(s[0],s[2])]
    if len(rows) != 1:
        raise ValueError("原生指令表不是本机 EXE 唯一的可写数据区。")


def bind_native_cg_vm_dispatch(executable,storage,next_binding,capacity):
    raw = bytes(executable)
    digest = hashlib.sha256(raw).hexdigest()
    if (storage["exe_sha256"] != digest or capacity["exe_sha256"] != digest
            or _next_binding(raw) != next_binding or _capacity(raw,next_binding) != capacity):
        raise ValueError("CG 指令分派、变量分配和线程不是同一份原生引擎。")
    image,sections = _pe_sections(raw)
    if (storage["vm_fields"]["nonvolatile"]+8 != next_binding["current_thread_fields"]["current"]
            or storage["vm_fields"]["buffer"] != storage["vm_fields"]["parser"]+16
            or type(storage["private_global_index"]) is not int
            or not 0 <= storage["private_global_index"] <= 0x7fff):
        raise ValueError("CG 临时变量不在本游戏已确认的原生变量范围。")
    buffer = re.escape(_u(storage["vm_fields"]["buffer"]))
    reader = _pattern(engine_pattern('native_cg_vm_dispatch:51:22')+buffer+
        engine_pattern('native_cg_vm_dispatch:54:8'))
    found = []
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000:
            continue
        for match in reader.finditer(raw[pointer:pointer+length]):
            address = image+rva+match.start()
            end = address+len(match[0])+struct.unpack("<b",match["primitive"])[0]
            at = _relocated(raw,image,sections,end,executable=True)
            if raw[at:at+1] != b"\xc3":
                continue
            found.append((address,struct.unpack("<I",match["sp"])[0],struct.unpack("<I",match["pc"])[0],match[0]))
    if len(found) != 1:
        raise ValueError("原生变量读取没有唯一的有符号编号和完整标记复制路径。")
    get_address,sp,pc,get_bytes = found[0]
    fp,rv,yield_field = sp+4,pc-8,pc-12
    if (sp != pc+4 or capacity["native_base"]+yield_field != next_binding["current_thread_fields"]["yield"]
            or capacity["native_stride"] <= fp+4):
        raise ValueError("原生变量指令与线程分派的栈字段不一致。")
    initializers = []
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000:
            continue
        for m in _pattern(engine_pattern('native_cg_vm_dispatch:78:26')+re.escape(_u(get_address))).finditer(raw[pointer:pointer+length]):
            at = pointer+m.start()
            table = struct.unpack("<I",m[1])[0]-15*4
            start = at-15*10
            if start < pointer:
                continue
            addresses = []
            try:
                for n in range(40):
                    pos = start+n*10
                    if raw[pos:pos+2] != b"\xc7\x05" or struct.unpack_from("<I",raw,pos+2)[0] != table+n*4:
                        raise ValueError("不完整指令表")
                    target = struct.unpack_from("<I",raw,pos+6)[0]
                    _relocated(raw,image,sections,target,executable=True)
                    addresses.append(target)
                _mapped_table(raw,image,sections,table,40*4)
            except ValueError:
                continue
            initializers.append((table,start,addresses))
    if len(initializers) != 1:
        raise ValueError("原生变量处理器与完整指令表初始化不一致。")
    table,start,addresses = initializers[0]
    SP,PC,RV,FP,Y = (re.escape(_u(n)) for n in (sp,pc,rv,fp,yield_field))
    common = engine_pattern('native_cg_vm_dispatch:101:13')+PC+engine_pattern('native_cg_vm_dispatch:101:29')
    loops = []
    for layout,tail in (("register-call",engine_pattern('native_cg_vm_dispatch:103:41')+PC+engine_pattern('native_cg_vm_dispatch:103:57')+re.escape(_u(table))+
                        engine_pattern('native_cg_vm_dispatch:104:24')+Y+engine_pattern('native_cg_vm_dispatch:104:55')),
                       ("memory-call",engine_pattern('native_cg_vm_dispatch:105:38')+PC+engine_pattern('native_cg_vm_dispatch:105:62')+re.escape(_u(table))+
                        engine_pattern('native_cg_vm_dispatch:106:24')+Y+engine_pattern('native_cg_vm_dispatch:106:39'))):
        for _,rva,length,pointer,flags in sections:
            if not flags&0x20000000:
                continue
            for m in _pattern(common+tail).finditer(raw[pointer:pointer+length]):
                if len(m[0])+struct.unpack("<b",m["again"])[0] != 0:
                    continue
                loops.append(dict(layout=layout,offset=pointer+m.start(),address=image+rva+m.start(),
                                  bytes_sha256=hashlib.sha256(m[0]).hexdigest()))
    if len(loops) != 1:
        raise ValueError("原生指令表没有绑定真正的读指令和让出执行循环。")
    bodies = {}
    def body(opcode):
        at,code = _function(raw,image,sections,addresses[opcode])
        following = [a for a in addresses if addresses[opcode] < a < addresses[opcode]+len(code)]
        if following:
            code = code[:min(following)-addresses[opcode]]
        return code.rstrip(b"\xcc")
    def match(opcode,pattern,*,prefix=False):
        code = body(opcode)
        m = re.match(pattern,code,re.DOTALL) if prefix else re.fullmatch(pattern,code,re.DOTALL)
        if m is None:
            raise ValueError("CG 所需的原生指令语义尚未完整绑定："+str(opcode))
        bodies[opcode] = dict(address=addresses[opcode],code_sha256=hashlib.sha256(code).hexdigest())
        return m
    release = None
    for opcode,tag in ((8,0),(9,1)):
        match(opcode,engine_pattern('native_cg_vm_dispatch:133:21')+SP+engine_pattern('native_cg_vm_dispatch:133:37')+SP+
              engine_pattern('native_cg_vm_dispatch:134:14')+bytes((tag,))+rb"\xc3")
    match(20,engine_pattern('native_cg_vm_dispatch:135:13')+RV+engine_pattern('native_cg_vm_dispatch:135:29')+SP+engine_pattern('native_cg_vm_dispatch:135:45')+
          re.escape(_u(rv+4))+engine_pattern('native_cg_vm_dispatch:136:30')+SP+engine_pattern('native_cg_vm_dispatch:136:62')+RV+rb"\0\xc3")
    jz_prefix = (engine_pattern('native_cg_vm_dispatch:137:17')+SP+engine_pattern('native_cg_vm_dispatch:137:36')+SP+engine_pattern('native_cg_vm_dispatch:137:52')+SP+
        engine_pattern('native_cg_vm_dispatch:138:8')+SP+engine_pattern('native_cg_vm_dispatch:138:28'))
    m = match(7,jz_prefix+engine_pattern('native_cg_vm_dispatch:139:26')+PC+
        engine_pattern('native_cg_vm_dispatch:140:8')+PC+
        engine_pattern('native_cg_vm_dispatch:141:8')+PC+engine_pattern('native_cg_vm_dispatch:141:42'))
    release = addresses[7]+m.end("release")+struct.unpack("<i",m["release"])[0]
    _relocated(raw,image,sections,release,executable=True)
    pop_start = engine_pattern('native_cg_vm_dispatch:144:16')+PC+engine_pattern('native_cg_vm_dispatch:144:48')
    pop_modern = (engine_pattern('native_cg_vm_dispatch:145:18')+PC+engine_pattern('native_cg_vm_dispatch:145:54')+buffer+
        engine_pattern('native_cg_vm_dispatch:146:8')+SP+engine_pattern('native_cg_vm_dispatch:146:24')+SP+engine_pattern('native_cg_vm_dispatch:146:40'))
    pop_legacy = (engine_pattern('native_cg_vm_dispatch:147:18')+PC+engine_pattern('native_cg_vm_dispatch:147:54')+buffer+
        engine_pattern('native_cg_vm_dispatch:148:8')+SP+engine_pattern('native_cg_vm_dispatch:148:40')+SP+engine_pattern('native_cg_vm_dispatch:148:60'))
    m = match(21,pop_start+rb"(?:"+pop_modern+rb"|"+pop_legacy+engine_pattern('native_cg_vm_dispatch:149:63'))
    if addresses[21]+m.end("release")+struct.unpack("<i",m["release"])[0] != release:
        raise ValueError("原生变量写入与条件跳转的值释放不是同一个入口。")
    sys_prefix = (engine_pattern('native_cg_vm_dispatch:153:18')+RV+engine_pattern('native_cg_vm_dispatch:153:58')+PC+engine_pattern('native_cg_vm_dispatch:154:24')+PC+engine_pattern('native_cg_vm_dispatch:155:36')+SP+engine_pattern('native_cg_vm_dispatch:156:24'))
    sys_call = (engine_pattern('native_cg_vm_dispatch:157:16'))
    m = match(3,sys_prefix+sys_call,prefix=True)
    if addresses[3]+m.end("release")+struct.unpack("<i",m["release"])[0] != release:
        raise ValueError("SYS 清空返回值的原生释放入口不一致。")
    sys_body = body(3)
    zero_at = m.end()+struct.unpack("<b",m["zero"])[0]
    if (struct.unpack("<I",m["table"])[0] != storage["vm_fields"]["nonvolatile"]+40
            or sys_body[zero_at:] != bytes.fromhex("5f5e5d5bc3")):
        raise ValueError("SYS 没有本机的零参数原生处理器返回路径。")
    # These source-native frames are recorded/bound, but a complete capacity
    # and retained-object lifecycle audit remains necessary before publishing.
    for opcode in (1,2,4,5,16):
        code = body(opcode)
        bodies[opcode] = dict(address=addresses[opcode],code_sha256=hashlib.sha256(code).hexdigest())
    bodies[15] = dict(address=get_address,primitive_path_sha256=hashlib.sha256(get_bytes).hexdigest())
    return dict(schema=SCHEMA,exe_sha256=digest,opcode_table=table,opcode_count=40,
        initializer_offset=start,initializer_bytes=400,
        initializer_sha256=hashlib.sha256(raw[start:start+400]).hexdigest(),
        initializer_fragment_only_bound=True,native_initializer_remainder_audit_complete=False,
        interpreter_loop=loops[0],handlers=bodies,
        thread_frame_fields=dict(pc=pc,sp=sp,fp=fp,return_value=rv,yield_byte=yield_field),
        global_index_signed_bits=16,global_read_write_and_flag_tags_static_bound=True,
        SYS_clears_return_before_handler=True,PUSH_RETURN_moves_and_nils_register=True,
        SYS_zero_argument_native_handler_dispatch_bound=True,
        native_yield_dispatch_loop_static_bound=True,release_value_address=release,
        native_call_frame_and_retained_object_audit_complete=False,
        live_initializer_executed_verified=False,frame_capacity_runtime_verified=False,
        runtime_verified=False,scene_export_connected=False)
