"""Own complete normal constructor/startup paths, not instance-lifetime proof.

The constructor and startup are DIFFERENT native functions. Constructor-local
count zero and startup-local builder-before-loader do not establish that those
facts reach any particular load/reload. Child calls may throw, allocate, reenter
or mutate other storage; their normal ABI returns are an explicit condition.
No native instructions execute here, and no public output grant is made.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_syscall_catalogue import bind_native_cg_vm_syscall_catalogue
from .native_cg_vm_syscall_header import bind_native_cg_vm_syscall_header
from .native_rotation_degrees import _imports

SCHEMA = "fvp-native-cg-vm-startup/1"
_UNKNOWN = object()


def _record(address, offset, code):
    return dict(address=address, offset=offset, code_bytes=len(code), code_sha256=hashlib.sha256(code).hexdigest())


def _relative(address, match, key):
    return address+match.end(key)+struct.unpack("<i", match[key])[0]


def _branch(match, key, label):
    if match.end(key)+struct.unpack("<b", match[key])[0] != match.start(label):
        raise ValueError("CG 原生初始化的循环／返回分支没有完整闭合。")


def _vector_ctor(raw, image, sections, address):
    offset = _relocated(raw, image, sections, address, executable=True, length=23)
    code = raw[offset:offset+23]
    match = re.fullmatch(engine_pattern('native_cg_vm_startup:39:25'), code, re.DOTALL)
    if match is None or not 0 < struct.unpack("<I", match["growth"])[0] <= 0x10000:
        raise ValueError("CG 原生调用表的构造函数没有完整清零容量和数量。")
    return dict(**_record(address, offset, code), capacity_field=0, count_field=4,
        buffer_field=8, growth_field=12, growth_increment=struct.unpack("<I", match["growth"])[0],
        constructor_local_capacity_zero=True, constructor_local_count_zero=True,
        buffer_initialized_by_this_constructor=False)


def _loader_entry(raw, image, sections, link, older):
    """Bind all bytes BEFORE the already-bound header reader, not a guessed VA."""
    first = (engine_pattern('native_cg_vm_startup:50:13')
        if older else engine_pattern('native_cg_vm_startup:51:22'))
    first += (engine_pattern('native_cg_vm_startup:54:14'))
    first += engine_pattern('native_cg_vm_startup:58:13') if older else engine_pattern('native_cg_vm_startup:58:56')
    first += engine_pattern('native_cg_vm_startup:59:13')+(engine_pattern('native_cg_vm_startup:59:48') if older else b"")
    first += engine_pattern('native_cg_vm_startup:60:13')+(rb"\x44" if older else rb"\x48")
    # This is a closed prefix ending EXACTLY at the independently bound reader.
    matches = []
    for _, rva, length, pointer, flags in sections:
        if not flags & 0x20000000: continue
        for m in re.finditer(first, raw[pointer:pointer+length], re.DOTALL):
            if pointer+m.end() != link["reader_offset"]: continue
            for key, label in (("found","load"),("empty","nil"),("join","throw_block")):
                _branch(m, key, label)
            address = image+rva+m.start()
            helpers = {k:_relative(address-m.start(),m,k) for k in ("allocate","construct_error","throw")}
            for at in helpers.values(): _relocated(raw,image,sections,at,executable=True)
            _relocated(raw,image,sections,struct.unpack("<I",m["seh"])[0],executable=True)
            for k in ("filename","error_text","error_type")+(tuple() if older else ("cookie",)):
                _relocated(raw,image,sections,struct.unpack("<I",m[k])[0],executable=False)
            imports = _imports(raw,image)
            for k, name in (("find","FindFirstFileA"),("close","FindClose")):
                iat = struct.unpack("<I",m[k])[0]
                _relocated(raw,image,sections,iat,executable=False,length=4)
                if imports.get(iat) != ("kernel32.dll",name):
                    raise ValueError("CG 原生脚本加载入口没有使用自己的文件查找／关闭导入。")
            matches.append(dict(**_record(address,pointer+m.start(),m[0]), helper_addresses=helpers,
                connected_reader_address=link["reader_address"], complete_entry_to_reader_prefix_static_bound=True,
                file_missing_exception_effects_complete=False, complete_loader_success_and_failure_paths_bound=False))
    if len(matches) != 1:
        raise ValueError("CG 原生脚本加载入口没有完整且唯一地连到自己的脚本头读取器。")
    return matches[0]


def _startup_pattern(older):
    w = lambda n: rb"(?P<"+n.encode()+rb">.{4})"
    if older:
        first = engine_pattern('native_cg_vm_startup:92:16')+w("flag0")
        first += b"".join(engine_pattern('native_cg_vm_startup:93:26')+w(n) for n in ("zero0","zero1","zero2"))
        first += engine_pattern('native_cg_vm_startup:94:17')+w("flag1")+engine_pattern('native_cg_vm_startup:94:45')+w("zero3")+engine_pattern('native_cg_vm_startup:94:69')+w("zero4")
        first += engine_pattern('native_cg_vm_startup:95:17')+w("index0")+engine_pattern('native_cg_vm_startup:95:50')
    else:
        first = engine_pattern('native_cg_vm_startup:97:16')
        first += b"".join(engine_pattern('native_cg_vm_startup:98:26')+w(n) for n in ("flag0","flag1","flag2"))
        first += engine_pattern('native_cg_vm_startup:99:17')+w("zero0")
        first += engine_pattern('native_cg_vm_startup:100:17')
        first += b"".join(engine_pattern('native_cg_vm_startup:101:26')+w(n) for n in ("flag3","flag4","flag5","flag6"))
        first += engine_pattern('native_cg_vm_startup:102:17')+w("size0")+engine_pattern('native_cg_vm_startup:102:41')+w("size1")+engine_pattern('native_cg_vm_startup:102:75')
        first += engine_pattern('native_cg_vm_startup:103:17')+w("zero1")+engine_pattern('native_cg_vm_startup:103:41')+w("index0")
    first += engine_pattern('native_cg_vm_startup:104:13')
    first += engine_pattern('native_cg_vm_startup:105:13')+w("zero5")+engine_pattern('native_cg_vm_startup:105:37')+w("index1")+(engine_pattern('native_cg_vm_startup:105:71') if older else rb"\x90")
    first += engine_pattern('native_cg_vm_startup:106:13')
    first += (engine_pattern('native_cg_vm_startup:107:14')+w("clear0")+engine_pattern('native_cg_vm_startup:107:47') if older else
              engine_pattern('native_cg_vm_startup:108:14')+w("clear0")+engine_pattern('native_cg_vm_startup:108:53'))
    first += engine_pattern('native_cg_vm_startup:109:13')+w("clear1")
    first += (engine_pattern('native_cg_vm_startup:110:14') if older else engine_pattern('native_cg_vm_startup:110:47'))+engine_pattern('native_cg_vm_startup:110:67')
    if not older: first += engine_pattern('native_cg_vm_startup:111:27')+w("native_error")+engine_pattern('native_cg_vm_startup:111:58')
    first += engine_pattern('native_cg_vm_startup:112:13')+(engine_pattern('native_cg_vm_startup:112:39') if older else b"")
    first += engine_pattern('native_cg_vm_startup:113:13')+(rb"\xbe" if older else rb"\xae")+w("threads")
    first += (engine_pattern('native_cg_vm_startup:114:14') if older else engine_pattern('native_cg_vm_startup:114:47'))
    first += engine_pattern('native_cg_vm_startup:115:13')
    first += (rb"\x4d" if older else engine_pattern('native_cg_vm_startup:116:37'))+engine_pattern('native_cg_vm_startup:116:55')
    first += engine_pattern('native_cg_vm_startup:117:13')+w("entry")+rb"\x50"+(engine_pattern('native_cg_vm_startup:117:47') if older else engine_pattern('native_cg_vm_startup:117:86'))
    first += engine_pattern('native_cg_vm_startup:118:13')
    if older:
        first += b"".join(engine_pattern('native_cg_vm_startup:120:26')+w(n) for n in ("post_zero0","post_zero1"))
        first += engine_pattern('native_cg_vm_startup:121:17')+w("post_tag0")+engine_pattern('native_cg_vm_startup:121:45')+w("renderer")+engine_pattern('native_cg_vm_startup:121:76')+w("post_view0")
        first += engine_pattern('native_cg_vm_startup:122:17')+w("post_zero2")
        first += b"".join(engine_pattern('native_cg_vm_startup:123:26')+w(n) for n in ("post_zero3","post_zero4"))
        first += engine_pattern('native_cg_vm_startup:124:17')+w("post_view1")+engine_pattern('native_cg_vm_startup:124:50')+w("post_one")+engine_pattern('native_cg_vm_startup:124:77')+w("post_tag1")+rb"\x02"
        first += engine_pattern('native_cg_vm_startup:125:17')+w("post_view2")
        first += engine_pattern('native_cg_vm_startup:126:17')
        first += b"".join(engine_pattern('native_cg_vm_startup:127:26')+w(n) for n in ("post_flag0","post_flag1","post_flag2"))
        first += engine_pattern('native_cg_vm_startup:128:17')+w("post_zero5")+engine_pattern('native_cg_vm_startup:128:46')+w("post_view3")+engine_pattern('native_cg_vm_startup:128:79')+w("post_minus1")+engine_pattern('native_cg_vm_startup:128:109')
    else:
        first += engine_pattern('native_cg_vm_startup:130:17')+w("error_name")
        first += rb"\x68"+w("default_name")+engine_pattern('native_cg_vm_startup:131:44')+w("renderer")
        first += engine_pattern('native_cg_vm_startup:132:17')
        first += engine_pattern('native_cg_vm_startup:133:17')
        first += engine_pattern('native_cg_vm_startup:134:17')
    return first


def _startup(raw, image, sections, at, address, older, catalogue, link, loader):
    section = next(s for s in sections if s[3] <= at < s[3]+s[2])
    m = re.match(_startup_pattern(older), raw[at:min(at+2048,section[3]+section[2])], re.DOTALL)
    if m is None: raise ValueError("CG 原生初始化函数没有完整覆盖自己的循环和全部正常返回。")
    for k, label in (("index_back0","index_loop0"),("index_back1","index_loop1"),("thread_back","thread_loop")):
        _branch(m,k,label)
    if not older:
        _branch(m,"initial_back","initial_loop"); _branch(m,"other_return","alternate")
    relatives = ["builder","loader","global_helper","thread_init","main_entry","post_main"]
    relatives += ["after_loader"] if older else ["initial_helper","clear_helper","name_helper","resolve0","resolve1"]
    helpers = {k:_relative(address,m,k) for k in relatives}
    for helper in helpers.values(): _relocated(raw,image,sections,helper,executable=True)
    if helpers["builder"] != catalogue["native_registration_builder"]["address"] or helpers["loader"] != loader["address"]:
        raise ValueError("CG 原生初始化调用的注册／加载入口不属于同一来源。")
    if not older and helpers["resolve0"] != helpers["resolve1"]:
        raise ValueError("CG 原生初始化两条返回路径没有使用同一解析入口。")
    get = lambda k: struct.unpack("<I",m[k])[0]
    _relocated(raw,image,sections,get("renderer"),executable=False,length=4)
    if not older: _relocated(raw,image,sections,get("default_name"),executable=False)
    if get("entry") != link["native_catalogue_field"]-4:
        raise ValueError("CG 初始化读取的主线程入口不是自己的 HCB 入口字段。")
    table_start, table_end = link["native_catalogue_field"], link["native_catalogue_field"]+64
    writes = []
    for k in m.groupdict():
        if k in helpers: continue  # A relative CALL operand is not an object field.
        if not k.startswith(("flag","zero","size","index","clear","post_","native_error")): continue
        if k.endswith(("loop0","loop1","back0","back1")) or k in {"post_main"}: continue
        if m[k] is None or len(m[k]) != 4: continue
        size = (256 if k == "index0" else 512 if k == "index1" else
                256 if k == "clear0" else (0x80000 if older else 0x100000) if k == "clear1" else
                1 if k.startswith(("flag","post_flag","post_tag","post_minus")) else
                2 if k.startswith(("post_view","post_zero0","post_zero1","post_zero3","post_zero4")) else 4)
        field = get(k)
        if field >= 2**31 or max(field,table_start) < min(field+size,table_end):
            raise ValueError("CG 原生初始化直接覆盖了调用表；不能继承构造时的数量。")
        writes.append(dict(role=k,field=field,bytes=size))
    return dict(**_record(address,at,m[0]), helper_addresses=helpers, direct_object_writes=writes,
        builder_call_address=address+m.start("builder")-1, loader_call_address=address+m.start("loader")-1,
        thread_initialization_iterations=8 if older else 32, complete_normal_paths_static_bound=True,
        own_builder_precedes_own_loader_on_normal_path=True, direct_table_clear_in_this_startup=False,
        opaque_child_calls_may_mutate_or_reenter=True, complete_child_and_exception_effects_bound=False)


def _controller_ctor(raw, image, sections, at, address, older, catalogue_field):
    section = next(s for s in sections if s[3] <= at < s[3]+s[2])
    code = raw[at:min(at+4096,section[3]+section[2])]
    prologue = (engine_pattern('native_cg_vm_startup:184:16')
        if older else engine_pattern('native_cg_vm_startup:185:22'))
    m = re.match(prologue,code,re.DOTALL)
    if m is None: raise ValueError("CG 原生控制器构造函数缺少完整正常入口。")
    _relocated(raw,image,sections,struct.unpack("<I",m["seh"])[0],executable=True)
    if not older: _relocated(raw,image,sections,struct.unpack("<I",m["cookie"])[0],executable=False,length=4)
    # All instructions are decoded, including stores before/after the table
    # calls. Unknown child effects are NOT facts about instance lifetime.
    regs = [_UNKNOWN]*8; regs[6]=("this",0); regs[3]=0
    cursor, calls, writes, tables, pending = m.end(), [], [], [], 0
    table_ctor = None
    def store(base, displacement, size, value):
        v = regs[base]
        if base == 4:
            state_offset = 24 if older else 36
            if displacement-pending != state_offset or size not in (1,4):
                raise ValueError("CG 控制器构造的栈写入没有保持自己的局部异常状态区。")
            return
        if not isinstance(v,tuple) or v[0] != "this":
            raise ValueError("CG 控制器构造写入了未绑定的对象地址。")
        field=v[1]+displacement
        if not 0 <= field < 2**31 or max(field,catalogue_field) < min(field+size,catalogue_field+64):
            raise ValueError("CG 控制器构造在完整调用表构造之外写入了表字段。")
        writes.append(dict(field=field,bytes=size,value=value if type(value) is int else None))
    while cursor < len(code):
        rest = code[cursor:]
        epilogue = (engine_pattern('native_cg_vm_startup:211:20')
            if older else engine_pattern('native_cg_vm_startup:212:26'))
        tail = re.match(epilogue,rest,re.DOTALL)
        if tail:
            if pending: raise ValueError("CG 控制器构造返回前还留有未清理的子调用参数。")
            store(6,struct.unpack("<I",tail["final"])[0],4,0)
            if tables != [catalogue_field+i*16 for i in range(4)] or table_ctor is None:
                raise ValueError("CG 控制器没有依次构造自己的 catalogue、SYS 和相邻调用表。")
            return dict(**_record(address,at,code[:cursor+tail.end()]),
                native_pointer_vector_constructor=table_ctor, table_constructor_fields=tables,
                child_calls=calls,direct_object_writes=writes,complete_normal_constructor_path_static_bound=True,
                table_counts_zero_at_normal_constructor_return_conditional=True,
                normal_child_ABI_return_is_an_assumption=True, complete_exception_and_child_effects_bound=False)
        # The modern two-object member loop is bounded and its whole back edge
        # is checked; an arbitrary constructor branch cannot borrow this rule.
        loop = re.match(engine_pattern('native_cg_vm_startup:226:24'),rest,re.DOTALL)
        if loop:
            if older or tables or pending: raise ValueError("CG 控制器构造中的成员循环位置已经变化。")
            _branch(loop,"back","body")
            target=_relative(address+cursor,loop,"call"); _relocated(raw,image,sections,target,executable=True)
            base,stride=(struct.unpack("<I",loop[k])[0] for k in ("base","stride"))
            if base >= 2**31 or not 0 < stride < 2**31 or base+stride >= 2**31:
                raise ValueError("CG 控制器成员循环范围无效。")
            calls.append(dict(address=address+cursor+loop.start("call")-1,target=target,opaque=True,iterations=2))
            regs[5]=("this",base+2*stride)
            for r in (0,1,2): regs[r]=_UNKNOWN
            cursor+=loop.end(); continue
        if rest.startswith(b"\xe8") and len(rest)>=5:
            target=address+cursor+5+struct.unpack_from("<i",rest,1)[0]
            _relocated(raw,image,sections,target,executable=True)
            this=regs[1]
            if isinstance(this,tuple) and this[0]=="this" and catalogue_field <= this[1] < catalogue_field+64:
                if pending: raise ValueError("CG 完整调用表构造不接收额外栈参数。")
                if this[1] != catalogue_field+16*len(tables) or len(tables)>=4:
                    raise ValueError("CG 控制器的原生调用表构造顺序已经变化。")
                own=_vector_ctor(raw,image,sections,target)
                if table_ctor is not None and own != table_ctor:
                    raise ValueError("CG 控制器没有使用同一个完整调用表构造函数。")
                table_ctor=own; tables.append(this[1])
            elif tables:
                raise ValueError("CG 调用表构造后还有未绑定的子调用，不能继承其数量。")
            calls.append(dict(address=address+cursor,target=target,opaque=not bool(tables),
                normal_argument_bytes_assumed_cleaned=pending,
                this_field=this[1] if isinstance(this,tuple) and this[0]=="this" else None))
            pending=0
            for r in (0,1,2): regs[r]=_UNKNOWN
            cursor+=5; continue
        # Complete allowed instruction grammar; no byte skipping or branch
        # heuristics. ESI (this) and EBX (zero) remain callee-saved conditions.
        n,wide=0,rest.startswith(b"\x66")
        prefix=1 if wide else 0; size=2 if wide else 4
        if len(rest)<=prefix: break
        op=rest[prefix]
        if not wide and (0xb8<=op<=0xbf) and len(rest)>=5:
            reg=op-0xb8
            if reg in (3,4,6): raise ValueError("CG 控制器构造覆盖了对象／零值寄存器。")
            regs[reg]=struct.unpack_from("<I",rest,1)[0]; n=5
        elif not wide and op==0xb0 and len(rest)>=2:
            regs[0]=_UNKNOWN; n=2  # Only AL known; never claim all EAX is known.
        elif not wide and op in (0x33,0x8b) and len(rest)>=2 and rest[1]>>6==3:
            dst,src=(rest[1]>>3)&7,rest[1]&7
            if dst in (3,4,6): raise ValueError("CG 控制器构造覆盖了保留寄存器。")
            if op==0x33:
                if dst!=src: raise ValueError("CG 控制器构造遇到未知寄存器计算。")
                regs[dst]=0
            else: regs[dst]=regs[src]
            n=2
        elif not wide and op==0x83 and len(rest)>=3 and rest[1] in (0xc8,0xc9) and rest[2]==0xff:
            regs[rest[1]&7]=0xffffffff; n=3
        elif not wide and op==0x8d and len(rest)>=3:
            modrm=rest[1]; mod,dst,base=modrm>>6,(modrm>>3)&7,modrm&7
            if mod not in (1,2) or base!=6 or dst in (3,4,6):
                raise ValueError("CG 控制器构造遇到未绑定的地址计算。")
            n=3 if mod==1 else 6
            if len(rest)<n: break
            disp=struct.unpack_from("<b" if mod==1 else "<i",rest,2)[0]
            if disp<0: raise ValueError("CG 控制器成员地址越过对象起点。")
            regs[dst]=("this",disp)
        elif not wide and rest.startswith(b"\xf3\xab"):
            if not (isinstance(regs[7],tuple) and regs[7][0]=="this" and type(regs[1]) is int and 0<=regs[1]<=0x10000 and type(regs[0]) is int):
                raise ValueError("CG 控制器构造的整段初始化范围不是确定值。")
            count=regs[1]; store(7,0,count*4,regs[0]); regs[7]=("this",regs[7][1]+count*4); regs[1]=0; n=2
        elif not wide and (0x50<=op<=0x57 or op in (0x68,0x6a)):
            n=5 if op==0x68 else 2 if op==0x6a else 1
            if len(rest)<n: break
            pending+=4
        elif op in (0x88,0x89,0xc6,0xc7) and len(rest)>=prefix+2:
            modrm=rest[prefix+1]; mod,reg,base=modrm>>6,(modrm>>3)&7,modrm&7
            store_size=1 if op in (0x88,0xc6) else size
            immediate=op in (0xc6,0xc7)
            if mod not in (0,1,2) or (immediate and reg!=0):
                raise ValueError("CG 控制器构造含有未绑定的内存写入。")
            pos=prefix+2
            if base==4:
                if wide or mod!=1 or len(rest)<pos+2 or rest[pos]!=0x24:
                    raise ValueError("CG 控制器构造含有未知栈寻址。")
                pos+=1
            elif base not in (6,7):
                raise ValueError("CG 控制器构造内存基址不是自己的对象。")
            disp_size=0 if mod==0 else 1 if mod==1 else 4
            if len(rest)<pos+disp_size+(store_size if immediate else 0): break
            disp=0 if mod==0 else struct.unpack_from("<b" if mod==1 else "<i",rest,pos)[0]
            pos+=disp_size
            v=int.from_bytes(rest[pos:pos+store_size],"little") if immediate else regs[reg]
            store(base,disp,store_size,v); n=pos+(store_size if immediate else 0)
        else:
            raise ValueError("CG 控制器完整构造路径含未知指令，位置 "+str(address+cursor)+"。")
        if len(rest)<n: break
        cursor+=n
    raise ValueError("CG 控制器构造没有走到完整正常返回。")


def bind_native_cg_vm_startup(executable, header, vm, frames):
    raw=bytes(executable); image,sections=_pe_sections(raw)
    catalogue=bind_native_cg_vm_syscall_catalogue(raw,header,vm,frames)
    link=bind_native_cg_vm_syscall_header(raw,header,vm,frames)
    older=link["layout"]=="signed-word-legacy"
    loader=_loader_entry(raw,image,sections,link,older)
    starts,constructors=[],[]
    start_marker=b"\x53\x33\xdb\x55\x56\x8b\xf1" if older else engine_pattern('native_cg_vm_startup:331:63')
    ctor_marker=engine_pattern('native_cg_vm_startup:332:16')
    own_field=b"\x8d\x8e"+struct.pack("<I",link["native_catalogue_field"])
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000: continue
        code=raw[pointer:pointer+length]
        for m in re.finditer(re.escape(start_marker),code):
            try: report=_startup(raw,image,sections,pointer+m.start(),image+rva+m.start(),older,catalogue,link,loader)
            except ValueError: continue
            starts.append(report)
        for m in re.finditer(ctor_marker,code,re.DOTALL):
            if own_field not in code[m.start():m.start()+4096]: continue
            try: report=_controller_ctor(raw,image,sections,pointer+m.start(),image+rva+m.start(),older,link["native_catalogue_field"])
            except ValueError: continue
            constructors.append(report)
    if len(starts)!=1 or len(constructors)!=1:
        raise ValueError("CG 当前来源的完整正常初始化／控制器构造路径还未唯一绑定。")
    startup,ctor=starts[0],constructors[0]
    # Reject matching direct callers outside this COMPLETE startup body. This
    # conservative raw scan does not claim hidden indirect callers are absent.
    targets={catalogue["native_registration_builder"]["address"],loader["address"]}
    sites=set()
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000: continue
        for m in re.finditer(engine_pattern('native_cg_vm_startup:355:29'),raw[pointer:pointer+length],re.DOTALL):
            a=image+rva+m.start()
            if a+5+struct.unpack("<i",m["rel"])[0] in targets: sites.add(a)
    if sites!={startup["builder_call_address"],startup["loader_call_address"]}:
        raise ValueError("CG 注册／加载入口还有未纳入完整正常初始化的直接调用位置。")
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=link["layout"],
        native_HCB_loader_entry_bridge=loader,native_startup=startup,native_controller_constructor=ctor,
        complete_controller_constructor_normal_path_static_bound=True,complete_startup_normal_paths_static_bound=True,
        builder_precedes_loader_within_bound_startup=True,constructor_local_table_counts_zero_static_bound=True,
        all_matching_direct_builder_and_loader_calls_in_bound_startup=True,indirect_callers_proven_absent=False,
        same_instance_constructor_before_startup_proven=False,startup_at_most_once_per_instance_proven=False,
        reload_clear_before_header_append_proven=False,initial_catalogue_is_empty_proven=False,
        initial_syscall_vector_count_zero_proven=False,source_header_arity_to_native_descriptor_bound=False,
        native_catalogue_construction_and_sorting_complete=False,native_descriptor_argc_immutability_proven=False,
        complete_allocation_exception_and_reentry_effects_bound=False,normal_child_ABI_return_is_an_assumption=True,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False)
