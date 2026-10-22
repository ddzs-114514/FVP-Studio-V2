"""Own enclosing constructors/startup, with explicit lifetime limitations.

Complete functions select the same embedded controller offset. That is NOT
proof that the application's callers use the same live object, call once, or
clear before a reload. Opaque child effects and normal child ABI remain
conditions. No instructions execute; this module grants no public output.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_rotation_degrees import _imports
from .native_cg_vm_startup import bind_native_cg_vm_startup, _record, _relative

SCHEMA = "fvp-native-cg-vm-parent-instance/1"
_UNKNOWN = object()


def _w(name):
    return rb"(?P<"+name.encode()+rb">.{4})"


def _branch(match, key, label):
    size = len(match[key])
    displacement = struct.unpack("<b" if size == 1 else "<i", match[key])[0]
    if match.end(key)+displacement != match.start(label):
        raise ValueError("CG 上层初始化的分支没有闭合到自己的循环／返回路径。")


def _mapped(raw, image, sections, match, keys, executable=False):
    for key in keys:
        _relocated(raw,image,sections,struct.unpack("<I",match[key])[0],executable=executable)


def _api(raw, image, sections, imports, match, key, expected):
    address = struct.unpack("<I",match[key])[0]
    _relocated(raw,image,sections,address,executable=False,length=4)
    if imports.get(address) != expected:
        raise ValueError("CG 上层初始化没有使用本来源的 "+expected[1]+" 导入。")


def _parent_startup_pattern(older):
    w = _w
    if older:
        p = engine_pattern('native_cg_vm_instance:47:12')+w("name0")+engine_pattern('native_cg_vm_instance:47:60')+w("string_field")+engine_pattern('native_cg_vm_instance:47:91')
    else:
        p = engine_pattern('native_cg_vm_instance:49:12')+w("seh")+engine_pattern('native_cg_vm_instance:49:38')+w("cookie")
        p += engine_pattern('native_cg_vm_instance:50:13')
        p += engine_pattern('native_cg_vm_instance:51:13')
        p += engine_pattern('native_cg_vm_instance:52:13')+w("version_api")
        p += engine_pattern('native_cg_vm_instance:53:13')
        p += engine_pattern('native_cg_vm_instance:54:13')+w("name0")+engine_pattern('native_cg_vm_instance:54:67')+w("string_field")
    p += rb"\xe8"+w("string_call")+engine_pattern('native_cg_vm_instance:55:35')+w("setup_call")
    p += rb"\x68"+w("mutex_name")+engine_pattern('native_cg_vm_instance:56:34')+w("mutex_api")
    p += (engine_pattern('native_cg_vm_instance:57:10') if older else engine_pattern('native_cg_vm_instance:57:72'))
    p += engine_pattern('native_cg_vm_instance:58:9')+w("error_api")+engine_pattern('native_cg_vm_instance:58:37')
    if older:
        p += engine_pattern('native_cg_vm_instance:60:13')
    else:
        p += engine_pattern('native_cg_vm_instance:62:13')+w("existing_branch")+rb"(?P<mutex_join>)"
    p += engine_pattern('native_cg_vm_instance:63:9')+w("config_field")+(rb"\x57" if older else b"")+engine_pattern('native_cg_vm_instance:63:69')+w("config_call")
    p += engine_pattern('native_cg_vm_instance:64:9')+w("message_api")+engine_pattern('native_cg_vm_instance:64:70')+w("message_text")
    p += engine_pattern('native_cg_vm_instance:65:9')+w("cancel_branch")
    p += engine_pattern('native_cg_vm_instance:66:9')+w("retry_call")+engine_pattern('native_cg_vm_instance:66:42')
    p += engine_pattern('native_cg_vm_instance:67:9')+w("flag0")+engine_pattern('native_cg_vm_instance:67:33')+w("flag1")+engine_pattern('native_cg_vm_instance:67:61')+w("com_api")+engine_pattern('native_cg_vm_instance:67:89')+w("tick_api")+rb"\x50"
    if older:
        p += engine_pattern('native_cg_vm_instance:69:13')+w("seed_api")+engine_pattern('native_cg_vm_instance:69:40')+w("prepare_call")
        p += engine_pattern('native_cg_vm_instance:70:13')+w("controller_field")+rb"\xe8"+w("controller_call")
        p += engine_pattern('native_cg_vm_instance:71:13')+w("graphics_field")
        p += engine_pattern('native_cg_vm_instance:72:13')+w("zero0")+engine_pattern('native_cg_vm_instance:72:37')+w("zero1")+engine_pattern('native_cg_vm_instance:72:69')+w("graphics_call")
        p += engine_pattern('native_cg_vm_instance:73:13')+w("post_call")+engine_pattern('native_cg_vm_instance:73:45')+w("member_field")+rb"\xe8"+w("member_call")
        p += engine_pattern('native_cg_vm_instance:74:13')
    else:
        p += rb"\xe8"+w("seed_call")+engine_pattern('native_cg_vm_instance:76:37')+w("allocate0_call")+engine_pattern('native_cg_vm_instance:76:82')
        p += engine_pattern('native_cg_vm_instance:77:13')+w("construct0_call")
        p += engine_pattern('native_cg_vm_instance:78:13')+w("object0_field")
        p += rb"\xe8"+w("allocate1_call")+engine_pattern('native_cg_vm_instance:79:42')
        p += engine_pattern('native_cg_vm_instance:80:13')+w("vtable1")+rb"\xe8"+w("member1_call")
        p += rb"\x68"+w("construct1_parameter")+engine_pattern('native_cg_vm_instance:81:48')+w("construct1_call")+engine_pattern('native_cg_vm_instance:81:86')
        p += engine_pattern('native_cg_vm_instance:82:13')+w("object1_field")+engine_pattern('native_cg_vm_instance:82:45')+w("array_field")
        p += engine_pattern('native_cg_vm_instance:83:13')+w("allocate2_call")
        p += engine_pattern('native_cg_vm_instance:84:13')
        p += engine_pattern('native_cg_vm_instance:85:13')+w("construct2_call")+engine_pattern('native_cg_vm_instance:85:51')
        p += engine_pattern('native_cg_vm_instance:86:13')+w("controller_field")+engine_pattern('native_cg_vm_instance:86:103')+w("controller_call")
        p += engine_pattern('native_cg_vm_instance:87:13')+w("allocate3_call")+engine_pattern('native_cg_vm_instance:87:58')
        p += engine_pattern('native_cg_vm_instance:88:13')
        p += engine_pattern('native_cg_vm_instance:89:13')+w("vtable3")+engine_pattern('native_cg_vm_instance:89:67')+w("construct3_call")
        p += engine_pattern('native_cg_vm_instance:90:13')+w("graphics_field")
        p += rb"\xe8"+w("post_call")+engine_pattern('native_cg_vm_instance:91:37')+w("allocate4_call")+engine_pattern('native_cg_vm_instance:91:82')
        p += engine_pattern('native_cg_vm_instance:92:13')+w("construct4_call")
        p += engine_pattern('native_cg_vm_instance:93:13')+w("object4_field")
        p += engine_pattern('native_cg_vm_instance:94:13')+w("graphics0_call")
        p += engine_pattern('native_cg_vm_instance:95:13')+w("read0_field")+engine_pattern('native_cg_vm_instance:95:43')+w("read1_field")+engine_pattern('native_cg_vm_instance:95:73')+w("graphics1_call")
        p += engine_pattern('native_cg_vm_instance:96:13')+w("placement_api")
        p += engine_pattern('native_cg_vm_instance:97:13')+w("graphics2_call")
        p += engine_pattern('native_cg_vm_instance:98:13')+w("show_api")+engine_pattern('native_cg_vm_instance:98:64')+w("controller_post_call")
        p += engine_pattern('native_cg_vm_instance:99:13')
        p += engine_pattern('native_cg_vm_instance:100:13')+w("cookie_call")
        p += engine_pattern('native_cg_vm_instance:101:13')
    return p


def _parent_startup(raw, image, sections, at, address, older, startup, table_field):
    section = next(s for s in sections if s[3] <= at < s[3]+s[2])
    m = re.match(_parent_startup_pattern(older),raw[at:min(at+2048,section[3]+section[2])],re.DOTALL)
    if m is None:
        raise ValueError("CG 上层初始化没有完整覆盖成功、取消和失败返回。")
    pairs = [("mutex_branch","mutex_join"),("ready_branch","ready"),("retry_branch","retry"),("cancel_branch","failure")]
    if older: pairs.append(("not_existing","mutex_join"))
    else:
        pairs += [("os_branch0","os_join"),("os_branch1","os_join"),("existing_branch","failure"),
                  ("array_first_branch","array_loop"),("array_back","array_loop"),("return_branch","return")]
        pairs += [(f"{kind}{i}_branch",f"{kind}{i}") for i in range(5) for kind in ("nil","join")]
    for key,label in pairs: _branch(m,key,label)
    imports = _imports(raw,image)
    apis = {"mutex_api":("kernel32.dll","CreateMutexA"),"error_api":("kernel32.dll","GetLastError"),
            "message_api":("user32.dll","MessageBoxA"),"com_api":("ole32.dll","CoInitializeEx"),"tick_api":("kernel32.dll","GetTickCount")}
    if older: apis["seed_api"]=("msvcr71.dll","srand")
    else: apis.update(version_api=("kernel32.dll","GetVersionExA"),placement_api=("user32.dll","SetWindowPlacement"),show_api=("user32.dll","ShowWindow"))
    for key,expected in apis.items(): _api(raw,image,sections,imports,m,key,expected)
    _mapped(raw,image,sections,m,["name0","mutex_name","message_text"]+([] if older else ["cookie","vtable1","vtable3"]))
    if not older: _mapped(raw,image,sections,m,["seh"],True)
    calls={key:_relative(address,m,key) for key in m.groupdict() if key.endswith("_call")}
    for target in calls.values(): _relocated(raw,image,sections,target,executable=True)
    if calls["controller_call"] != startup["native_startup"]["address"] or calls["config_call"] != calls["retry_call"]:
        raise ValueError("CG 上层初始化的控制器／重试入口不是自己的完整入口。")
    if not older and len({calls[f"allocate{i}_call"] for i in range(5)}) != 1:
        raise ValueError("CG 上层初始化的分配路径没有使用同一来源的入口。")
    embedded = struct.unpack("<I",m["controller_field"])[0]
    if not 0 < embedded < 2**31-table_field-64:
        raise ValueError("CG 上层对象的控制器偏移无效。")
    # Complete grammar supplies ALL direct parent-object writes. Heap-object
    # writes and opaque children are deliberately NOT parent-table facts.
    writes=[(0,4 if older else 1),(4,4),(8,4)] if not older else [(0,4),(4,4)]
    fields=["flag0","flag1","zero0","zero1"] if older else ["flag0","flag1","object0_field","object1_field","graphics_field","object4_field"]
    for key in fields:
        writes.append((struct.unpack("<I",m[key])[0],1 if key.startswith("flag") else 4))
    if not older: writes += [(struct.unpack("<I",m["array_field"])[0],32*4),(0x34,4)]
    start,end = embedded+table_field,embedded+table_field+64
    if any(field<0 or field+size>=2**31 or max(field,start)<min(field+size,end) for field,size in writes):
        raise ValueError("CG 上层初始化直接覆盖了嵌入控制器的调用表。")
    return dict(**_record(address,at,m[0]),embedded_controller_field=embedded,
        helper_addresses=calls,direct_parent_writes=[dict(field=f,bytes=n) for f,n in writes],
        controller_call_address=address+m.start("controller_call")-1,
        complete_normal_success_and_failure_paths_static_bound=True,
        direct_controller_startup_calls_per_normal_parent_invocation_maximum=1,
        explicit_loops_all_precede_controller_startup=True,
        failure_paths_before_controller_startup_do_not_load=True,
        opaque_children_may_mutate_or_reenter=True,complete_exception_and_child_effects_bound=False)


def _parent_constructor(raw,image,sections,at,address,older,startup,embedded,table_field):
    section = next(s for s in sections if s[3] <= at < s[3]+s[2])
    code=raw[at:min(at+4096,section[3]+section[2])]
    w=_w
    p=engine_pattern('native_cg_vm_instance:158:6')+w("seh")+engine_pattern('native_cg_vm_instance:158:32')
    if older:
        p+=engine_pattern('native_cg_vm_instance:160:11')
    else:
        p+=engine_pattern('native_cg_vm_instance:162:11')+w("cookie")+engine_pattern('native_cg_vm_instance:162:48')
    p+=engine_pattern('native_cg_vm_instance:163:7')+w("member_field")+engine_pattern('native_cg_vm_instance:163:38')+w("mutex_api")+engine_pattern('native_cg_vm_instance:163:66')+w("member_call")
    p+=engine_pattern('native_cg_vm_instance:164:7')+w("controller_field")+engine_pattern('native_cg_vm_instance:164:42')+w("controller_call")
    m=re.match(p,code,re.DOTALL)
    if m is None or struct.unpack("<I",m["controller_field"])[0]!=embedded or _relative(address,m,"controller_call")!=startup["native_controller_constructor"]["address"]:
        raise ValueError("CG 上层构造没有在相同偏移调用自己的完整控制器构造。")
    _mapped(raw,image,sections,m,["seh"],True)
    if not older: _mapped(raw,image,sections,m,["cookie"])
    _api(raw,image,sections,_imports(raw,image),m,"mutex_api",("kernel32.dll","CreateMutexA"))
    member_call=_relative(address,m,"member_call");_relocated(raw,image,sections,member_call,executable=True)
    regs=[_UNKNOWN]*8;regs[3]=0;regs[6]=("this",0);regs[7]=("this",struct.unpack("<I",m["member_field"])[0])
    cursor,pending=m.end(),0
    calls=[dict(address=address+m.start("member_call")-1,target=member_call,opaque=True),
           dict(address=address+m.start("controller_call")-1,target=startup["native_controller_constructor"]["address"],opaque=False,this_field=embedded)]
    writes=[]
    def store(base,displacement,size):
        if base==4:
            if displacement-pending!=28 or size not in (1,4):
                raise ValueError("CG 上层构造的局部异常状态栈地址已经变化。")
            return
        value=regs[base]
        if not isinstance(value,tuple) or value[0]!="this":
            raise ValueError("CG 上层构造遇到未知写入对象。")
        field=value[1]+displacement
        first,last=embedded+table_field,embedded+table_field+64
        if field<0 or field+size>=2**31 or max(field,first)<min(field+size,last):
            raise ValueError("CG 上层构造直接覆盖了已构造的调用表。")
        writes.append(dict(field=field,bytes=size))
    # The prefix's mutex store belongs to the member, not the controller.
    store(7,0x300,4)
    while cursor<len(code):
        rest=code[cursor:]
        tail=(engine_pattern('native_cg_vm_instance:194:14')+w("zero0")+
              engine_pattern('native_cg_vm_instance:195:14')+w("zero1")+engine_pattern('native_cg_vm_instance:195:38') if older else
              engine_pattern('native_cg_vm_instance:196:14'))
        t=re.match(tail,rest,re.DOTALL)
        if t:
            if pending:raise ValueError("CG 上层构造返回前留有未清理参数。")
            if older:
                for field in (0,4,8,16,struct.unpack("<I",t["zero0"])[0],struct.unpack("<I",t["zero1"])[0]):store(6,field,4)
            return dict(**_record(address,at,code[:cursor+t.end()]),embedded_controller_field=embedded,
                controller_constructor_call_address=address+m.start("controller_call")-1,child_calls=calls,
                direct_parent_writes=writes,complete_normal_constructor_path_static_bound=True,
                controller_constructor_called_once_on_normal_path=True,
                post_controller_children_may_mutate_or_reenter=True,normal_child_ABI_return_is_an_assumption=True,
                complete_exception_and_child_effects_bound=False)
        if rest.startswith(b"\xe8") and len(rest)>=5:
            target=address+cursor+5+struct.unpack_from("<i",rest,1)[0];_relocated(raw,image,sections,target,executable=True)
            if target in (startup["native_controller_constructor"]["address"],startup["native_startup"]["address"]):
                raise ValueError("CG 上层构造再次调用了控制器构造／启动。")
            calls.append(dict(address=address+cursor,target=target,opaque=True,normal_argument_bytes_assumed_cleaned=pending))
            for reg in (0,1,2):regs[reg]=_UNKNOWN
            pending=0;cursor+=5;continue
        wide=rest.startswith(b"\x66");prefix=1 if wide else 0
        if len(rest)<=prefix:break
        op=rest[prefix];n=0
        if not wide and 0xb8<=op<=0xbf and len(rest)>=5:
            reg=op-0xb8
            if reg in (3,4,6):raise ValueError("CG 上层构造覆盖了保留寄存器。")
            regs[reg]=struct.unpack_from("<I",rest,1)[0];n=5
        elif not wide and op in (0x8b,0x33) and len(rest)>=2 and rest[1]>>6==3:
            dst,src=(rest[1]>>3)&7,rest[1]&7
            if dst in (3,4,6) or (op==0x33 and dst!=src):raise ValueError("CG 上层构造遇到未知寄存器计算。")
            regs[dst]=0 if op==0x33 else regs[src];n=2
        elif not wide and op==0x8d and len(rest)>=3:
            modrm=rest[1];mod,dst,base=modrm>>6,(modrm>>3)&7,modrm&7
            if mod not in (1,2) or base!=6 or dst in (3,4,6):raise ValueError("CG 上层构造遇到未知成员寻址。")
            n=3 if mod==1 else 6
            if len(rest)<n:break
            displacement=struct.unpack_from("<b" if mod==1 else "<i",rest,2)[0]
            if displacement<0:raise ValueError("CG 上层构造成员偏移无效。")
            regs[dst]=("this",displacement)
        elif not wide and (0x50<=op<=0x57 or op in (0x68,0x6a)):
            n=5 if op==0x68 else 2 if op==0x6a else 1;pending+=4
        elif op in (0x88,0x89,0xc6,0xc7) and len(rest)>=prefix+2:
            modrm=rest[prefix+1];mod,reg,base=modrm>>6,(modrm>>3)&7,modrm&7
            size=1 if op in (0x88,0xc6) else 2 if wide else 4
            immediate=op in (0xc6,0xc7)
            if mod not in (0,1,2) or (immediate and reg!=0):raise ValueError("CG 上层构造遇到未知内存写入。")
            pos=prefix+2
            if base==4:
                if wide or mod!=1 or len(rest)<pos+2 or rest[pos]!=0x24:raise ValueError("CG 上层构造遇到未知栈写入。")
                pos+=1
            elif base not in (6,7):raise ValueError("CG 上层构造写入基址没有绑定。")
            amount=0 if mod==0 else 1 if mod==1 else 4
            n=pos+amount+(size if immediate else 0)
            if len(rest)<n:break
            displacement=0 if mod==0 else struct.unpack_from("<b" if mod==1 else "<i",rest,pos)[0]
            store(base,displacement,size)
        else:raise ValueError("CG 上层完整构造路径含未知指令，位置 "+str(address+cursor)+"。")
        if len(rest)<n:break
        cursor+=n
    raise ValueError("CG 上层构造没有完整正常返回。")


def bind_native_cg_vm_instance(executable,header,vm,frames):
    raw=bytes(executable);image,sections=_pe_sections(raw)
    startup=bind_native_cg_vm_startup(raw,header,vm,frames)
    older=startup["layout"]=="signed-word-legacy"
    field=startup["native_controller_constructor"]["table_constructor_fields"][0]
    initializers=[]
    marker=engine_pattern('native_cg_vm_instance:263:11') if older else b"\x6a\xff\x68"
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000:continue
        code=raw[pointer:pointer+length]
        for m in re.finditer(re.escape(marker),code):
            try:report=_parent_startup(raw,image,sections,pointer+m.start(),image+rva+m.start(),older,startup,field)
            except ValueError:continue
            initializers.append(report)
    if len(initializers)!=1:raise ValueError("CG 本来源上层完整初始化路径还未唯一绑定。")
    parent=initializers[0];constructors=[]
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000:continue
        code=raw[pointer:pointer+length]
        for m in re.finditer(engine_pattern('native_cg_vm_instance:276:29'),code,re.DOTALL):
            try:report=_parent_constructor(raw,image,sections,pointer+m.start(),image+rva+m.start(),older,startup,parent["embedded_controller_field"],field)
            except ValueError:continue
            constructors.append(report)
    if len(constructors)!=1:raise ValueError("CG 本来源上层完整构造路径还未唯一绑定。")
    # Conservative raw direct-call audit; no claim about hidden indirect calls.
    targets={startup["native_startup"]["address"],startup["native_controller_constructor"]["address"]};sites=set()
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000:continue
        for m in re.finditer(engine_pattern('native_cg_vm_instance:285:29'),raw[pointer:pointer+length],re.DOTALL):
            address=image+rva+m.start()
            if address+5+struct.unpack("<i",m["rel"])[0] in targets:sites.add(address)
    ctor=constructors[0]
    if sites!={parent["controller_call_address"],ctor["controller_constructor_call_address"]}:
        raise ValueError("CG 控制器还有未纳入完整上层路径的直接调用。")
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=startup["layout"],
        native_parent_constructor=ctor,native_parent_startup=parent,native_vm_startup=startup,
        complete_parent_normal_constructor_static_bound=True,complete_parent_normal_startup_paths_static_bound=True,
        same_embedded_controller_offset_static_bound=True,
        direct_controller_startup_once_per_normal_parent_invocation_static_bound=True,
        all_matching_direct_controller_calls_in_bound_parents=True,
        same_live_parent_instance_constructor_before_startup_proven=False,startup_at_most_once_per_instance_proven=False,
        reload_clear_before_header_append_proven=False,initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False,complete_allocation_exception_and_reentry_effects_bound=False,
        indirect_callers_proven_absent=False,normal_child_ABI_return_is_an_assumption=True,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False)
