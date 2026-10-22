"""Own-EXE HCB frame/return-transfer binding; never native runtime acceptance.

Bind every branch of the frame initializer/returner and the paired reference
mutators. The latter's positive-count return path is sufficient for the extra
retain/release pair of a valid saved R; zero-count destruction still needs its
own ownership/lifecycle audit before generic CG can be published.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _function, _relocated

SCHEMA = "fvp-native-cg-vm-frames/1"


def _u(value):
    return struct.pack("<I", value)


def bind_native_cg_vm_frames(executable, vm):
    raw = bytes(executable)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != vm["exe_sha256"]:
        raise ValueError("CG 调用帧与指令分派不是同一份原生引擎。")
    image, sections = _pe_sections(raw)
    table_at = vm["initializer_offset"]
    if (vm["opcode_count"] != 40 or vm["initializer_bytes"] != 400
            or hashlib.sha256(raw[table_at:table_at+400]).hexdigest() != vm["initializer_sha256"]):
        raise ValueError("CG 调用帧的原生指令表已经变化。")
    addresses = []
    for n in range(40):
        at = table_at+n*10
        if raw[at:at+2] != b"\xc7\x05" or struct.unpack_from("<I",raw,at+2)[0] != vm["opcode_table"]+n*4:
            raise ValueError("CG 调用帧没有完整的本机指令表。")
        address = struct.unpack_from("<I",raw,at+6)[0]
        _relocated(raw,image,sections,address,executable=True)
        addresses.append(address)
    fields = vm["thread_frame_fields"]
    sp, pc, fp, rv, yield_byte = (fields[n] for n in ("sp","pc","fp","return_value","yield_byte"))
    SP, PC, FP, RV, PAY, Y = (re.escape(_u(n)) for n in (sp,pc,fp,rv,rv+4,yield_byte))
    if not (fp == sp+4 and sp == pc+4 and rv == pc-8 and yield_byte == pc-12):
        raise ValueError("原生调用帧、返回值和让出执行字段不一致。")
    checked = {}
    def read(address):
        at, code = _function(raw,image,sections,address)
        following = [a for a in addresses if address < a < address+len(code)]
        if following:
            code = code[:min(following)-address]
        return at, code.rstrip(b"\xcc")
    def check(address, pattern, label, *, prefix=False):
        at, code = read(address)
        m = re.match(pattern,code,re.DOTALL) if prefix else re.fullmatch(pattern,code,re.DOTALL)
        if m is None:
            raise ValueError("尚未完整绑定本游戏的原生调用帧："+label)
        checked[label] = dict(address=address,offset=at,code_sha256=hashlib.sha256(code).hexdigest())
        return m, code
    def relative(address, m, name):
        destination = address+m.end(name)+struct.unpack("<i",m[name])[0]
        _relocated(raw,image,sections,destination,executable=True)
        return destination
    def branches(m, pairs):
        for jump, label in pairs:
            width = len(m[jump])
            distance = struct.unpack("<b" if width == 1 else "<i",m[jump])[0]
            if m.end(jump)+distance != m.start(label):
                raise ValueError("原生调用帧的控制分支没有接回自己的边界："+list(checked)[-1]+"/"+jump+
                    " ("+str(m.end(jump)+distance)+" != "+str(m.start(label))+")")
    for opcode in (1,2,4,5,16):
        record = vm["handlers"].get(opcode, vm["handlers"].get(str(opcode)))
        if (record is None or record["address"] != addresses[opcode]
                or record["code_sha256"] != hashlib.sha256(read(addresses[opcode])[1]).hexdigest()):
            raise ValueError("原生调用帧处理器不属于已绑定的指令表。")

    m,_ = check(addresses[1],engine_pattern('native_cg_vm_frames:76:29')+PC+engine_pattern('native_cg_vm_frames:76:45')+PC+
        engine_pattern('native_cg_vm_frames:77:8')+PC+engine_pattern('native_cg_vm_frames:77:52'),"INIT")
    init_address = relative(addresses[1],m,"init")
    initial = (engine_pattern('native_cg_vm_frames:79:15')+SP+engine_pattern('native_cg_vm_frames:79:31')+SP+
        engine_pattern('native_cg_vm_frames:80:8')+SP+engine_pattern('native_cg_vm_frames:80:80'))
    modern_init = (engine_pattern('native_cg_vm_frames:81:19')+FP+engine_pattern('native_cg_vm_frames:81:35')+SP+
        engine_pattern('native_cg_vm_frames:83:8'))
    legacy_init = (engine_pattern('native_cg_vm_frames:84:19')+FP+engine_pattern('native_cg_vm_frames:84:43')+SP+
        engine_pattern('native_cg_vm_frames:85:8')+SP+engine_pattern('native_cg_vm_frames:85:44'))
    try:
        m,_ = check(init_address,initial+modern_init,"frame_initialise")
        init_layout = "increment-by-one-register"
        branches(m,[("zero","done"),("first","loop"),("again","loop")])
    except ValueError:
        m,_ = check(init_address,initial+legacy_init,"frame_initialise")
        init_layout = "increment-and-store"
        branches(m,[("zero","done"),("again","loop")])

    call_prefix = engine_pattern('native_cg_vm_frames:95:18')+SP+engine_pattern('native_cg_vm_frames:95:38')+FP
    modern_call = (engine_pattern('native_cg_vm_frames:96:19')+PC+engine_pattern('native_cg_vm_frames:96:55')+SP+engine_pattern('native_cg_vm_frames:97:24')+PC+engine_pattern('native_cg_vm_frames:97:58')+PC+
        engine_pattern('native_cg_vm_frames:98:8'))
    legacy_call = (engine_pattern('native_cg_vm_frames:99:19')+PC+engine_pattern('native_cg_vm_frames:99:67')+PC+engine_pattern('native_cg_vm_frames:100:24')+PC+
        engine_pattern('native_cg_vm_frames:101:8')+SP+engine_pattern('native_cg_vm_frames:101:24'))
    try:
        m,code = check(addresses[2],call_prefix+modern_call,"CALL",prefix=True)
        call_layout = "compare-before-PC-read"
    except ValueError:
        m,code = check(addresses[2],call_prefix+legacy_call,"CALL",prefix=True)
        call_layout = "compare-after-PC-write"
    capacity = struct.unpack("<I",m["capacity"])[0]
    success_at = m.end()+struct.unpack("<b",m["success"])[0]
    if code[success_at:] != b"\x59\xc3" or capacity < 1 or 8+8*capacity != pc-20:
        raise ValueError("本游戏的栈容量没有与实际表达式存储区对上。")

    release = vm["release_value_address"]
    m,_ = check(addresses[4],engine_pattern('native_cg_vm_frames:114:29')+RV+
        engine_pattern('native_cg_vm_frames:115:8'),"RET")
    if relative(addresses[4],m,"release") != release:
        raise ValueError("RET 释放返回值的入口与原生 SYS 不一致。")
    return_address = relative(addresses[4],m,"return")
    retv_pop = (engine_pattern('native_cg_vm_frames:119:16')+SP+engine_pattern('native_cg_vm_frames:119:35')+SP+engine_pattern('native_cg_vm_frames:119:51')+SP+engine_pattern('native_cg_vm_frames:119:68')+SP+rb")")
    m,_ = check(addresses[5],engine_pattern('native_cg_vm_frames:120:29')+RV+engine_pattern('native_cg_vm_frames:120:61')+retv_pop+
        engine_pattern('native_cg_vm_frames:121:8'),"RETV")
    if relative(addresses[5],m,"release") != release or relative(addresses[5],m,"return") != return_address:
        raise ValueError("RET 和 RETV 不是同一条本机帧返回链。")
    ref_one, ref_two = fp+4, fp+4+0x100
    ONE, TWO = re.escape(_u(ref_one)), re.escape(_u(ref_two))
    release_pattern = (engine_pattern('native_cg_vm_frames:126:23')+ONE+engine_pattern('native_cg_vm_frames:127:33')+ONE+engine_pattern('native_cg_vm_frames:127:66')+TWO+
        engine_pattern('native_cg_vm_frames:129:8')+TWO+engine_pattern('native_cg_vm_frames:129:41'))
    m,_ = check(release,release_pattern,"release_value")
    branches(m,[("primitive","done"),("other","other_label")])
    decrease = {1:relative(release,m,"one"),2:relative(release,m,"two")}
    stack_push = (engine_pattern('native_cg_vm_frames:133:18')+SP+engine_pattern('native_cg_vm_frames:133:34')+SP+engine_pattern('native_cg_vm_frames:133:78')+PC+
        engine_pattern('native_cg_vm_frames:134:8')+PC+engine_pattern('native_cg_vm_frames:134:44')+FP+
        engine_pattern('native_cg_vm_frames:135:8')+ONE+engine_pattern('native_cg_vm_frames:137:33')+ONE+engine_pattern('native_cg_vm_frames:137:60')+TWO+engine_pattern('native_cg_vm_frames:138:50')+TWO+engine_pattern('native_cg_vm_frames:138:77'))
    m,_ = check(addresses[16],stack_push,"PUSH_STACK")
    branches(m,[("primitive","done"),("other","other_label")])
    if any(relative(addresses[16],m,n) != decrease[k] for n,k in (("one",1),("two",2))):
        raise ValueError("参数复制与帧释放没有配对到同一个原生引用计数入口。")

    # Different register allocation, identical physical frame operations.
    local_drop = (engine_pattern('native_cg_vm_frames:145:18')+ONE+engine_pattern('native_cg_vm_frames:145:55')+ONE+
        engine_pattern('native_cg_vm_frames:146:8'))
    local_else = (engine_pattern('native_cg_vm_frames:147:18')+TWO+engine_pattern('native_cg_vm_frames:147:55')+TWO+
        engine_pattern('native_cg_vm_frames:148:8'))
    argument_drop = (engine_pattern('native_cg_vm_frames:149:21')+ONE+engine_pattern('native_cg_vm_frames:149:58')+ONE+
        engine_pattern('native_cg_vm_frames:150:8'))
    argument_else = (engine_pattern('native_cg_vm_frames:151:21')+TWO+engine_pattern('native_cg_vm_frames:151:58')+TWO+
        engine_pattern('native_cg_vm_frames:152:8'))
    def drop_loop(name, first, other):
        return (rb"(?P<"+name.encode()+engine_pattern('native_cg_vm_frames:154:39')+name.encode()+engine_pattern('native_cg_vm_frames:154:105')+name.encode()+rb"_other>.)"+first+
            rb"(?P<"+name.encode()+rb"_other_label>)"+other+rb"(?P<"+name.encode()+engine_pattern('native_cg_vm_frames:156:83')+name.encode()+engine_pattern('native_cg_vm_frames:157:35')+
            (engine_pattern('native_cg_vm_frames:158:13') if name == "local" else engine_pattern('native_cg_vm_frames:158:66'))+
            engine_pattern('native_cg_vm_frames:159:12')+name.encode()+rb"_again>.)")
    modern_return = (engine_pattern('native_cg_vm_frames:160:21')+FP+engine_pattern('native_cg_vm_frames:160:57')+FP+
        engine_pattern('native_cg_vm_frames:161:8')+SP+engine_pattern('native_cg_vm_frames:161:24'))
    legacy_return = (engine_pattern('native_cg_vm_frames:162:21')+FP+engine_pattern('native_cg_vm_frames:162:57')+SP+
        engine_pattern('native_cg_vm_frames:163:8')+FP+engine_pattern('native_cg_vm_frames:163:40'))
    local_end_modern = engine_pattern('native_cg_vm_frames:165:23')
    local_end_legacy = engine_pattern('native_cg_vm_frames:166:23')
    restore = (engine_pattern('native_cg_vm_frames:167:15')+FP+engine_pattern('native_cg_vm_frames:167:70')+SP+engine_pattern('native_cg_vm_frames:168:54')+FP+
        engine_pattern('native_cg_vm_frames:169:8')+PC+engine_pattern('native_cg_vm_frames:169:40')+RV+engine_pattern('native_cg_vm_frames:170:24')+PAY+engine_pattern('native_cg_vm_frames:171:25')+ONE+engine_pattern('native_cg_vm_frames:171:50')+PAY+engine_pattern('native_cg_vm_frames:171:67')+ONE+
        engine_pattern('native_cg_vm_frames:172:8')+PAY+engine_pattern('native_cg_vm_frames:173:47')+TWO+engine_pattern('native_cg_vm_frames:173:72')+TWO+
        engine_pattern('native_cg_vm_frames:174:8')+PAY+engine_pattern('native_cg_vm_frames:174:25')+RV+engine_pattern('native_cg_vm_frames:174:88')+Y+engine_pattern('native_cg_vm_frames:175:49')+re.escape(_u(yield_byte-8))+
        engine_pattern('native_cg_vm_frames:176:8'))
    loops = drop_loop("local",local_drop,local_else)
    arguments = drop_loop("arg",argument_drop,argument_else)
    try:
        m,_ = check(return_address,modern_return+loops+local_end_modern+arguments+restore,"frame_return")
        return_layout = "decrement-FP-in-place"
    except ValueError:
        m,_ = check(return_address,legacy_return+loops+local_end_legacy+arguments+restore,"frame_return")
        return_layout = "decrement-FP-and-store"
    jumps = [("local_end","local_end_label"),("arg_end","arg_end_label"),("nested","nested_label"),
        ("root_primitive","root_primitive_label"),("root_other","root_other_label"),("root_join","root_join_label")]
    for name in ("local","arg"):
        jumps.extend((name+"_"+jump,name+"_"+label) for jump,label in
            (("primitive","primitive_label"),("other","other_label"),("join","join_label"),("again","loop")))
    branches(m,jumps)
    if bool(m["test_before"]) != (return_layout == "decrement-FP-and-store"):
        raise ValueError("原生嵌套返回没有按恢复后的 SP 判断根帧。")
    for name,k in (("local_one",1),("local_two",2),("arg_one",1),("arg_two",2),("root_one",1),("root_two",2)):
        if relative(return_address,m,name) != decrease[k]:
            raise ValueError("帧清理、根返回和参数复制没有共用本机引用计数入口。")

    mutators = {}
    for k,address in decrease.items():
        prefix = (engine_pattern('native_cg_vm_frames:199:18')+
            (engine_pattern('native_cg_vm_frames:200:13') if k == 1 else
             engine_pattern('native_cg_vm_frames:201:13'))+rb"(?P<counter>.{4})")
        index = rb"\x7e" if k == 1 else rb"\x6e"
        load = engine_pattern('native_cg_vm_frames:203:15')+index+engine_pattern('native_cg_vm_frames:203:41')+index+rb")(?P=counter)"
        positive = (engine_pattern('native_cg_vm_frames:204:20') if k == 1 else
                    engine_pattern('native_cg_vm_frames:205:20'))
        m,code = check(address,prefix+load+positive,"reference_mutator_"+str(k),prefix=True)
        distance = struct.unpack("<b" if k == 1 else "<i",m["positive"])[0]
        done = m.end()+distance
        epilogue = b"\x5f\x5e\xc2\x08\0" if k == 1 else b"\x5e\x5d\xc2\x08\0"
        if code[done:done+len(epilogue)] != epilogue:
            raise ValueError("原生引用计数的存活对象没有独立的返回路径。")
        counter = struct.unpack("<I",m["counter"])[0]
        if not 0 < counter < 2**31:
            raise ValueError("原生引用计数不在本机对象的有效字段范围。")
        mutators[k] = dict(address=address,counter_field=counter,positive_return_offset=done,
            signed_word_delta=True,zero_count_destructor_audit_complete=False)
    return dict(schema=SCHEMA,exe_sha256=digest,source_windows=checked,
        init_layout=init_layout,call_layout=call_layout,return_layout=return_layout,
        stack_value_bytes=8,stack_value_base=8,stack_capacity_cells=capacity,
        frame_metadata_cells=1,argc_and_locals_signed_bits=8,saved_FP_signed_bits=16,
        one_argument_offset_from_FP=-2,yield_preserver_extra_peak_cells=3,
        frame_initialisation_static_bound=True,CALL_metadata_and_success_path_static_bound=True,
        frame_local_argument_release_and_restore_static_bound=True,
        RETV_moves_value_and_nested_return_preserves_R=True,
        PUSH_STACK_copy_and_reference_pair_static_bound=True,
        retained_reference_mutators=mutators,positive_retained_return_path_static_bound=True,
        zero_count_destructor_audit_complete=False,native_object_ownership_runtime_verified=False,
        maximum_source_stack_height_verified=False,runtime_verified=False,scene_export_connected=False)
