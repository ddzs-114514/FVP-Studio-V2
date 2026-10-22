"""Static own-EXE NIL/TRUE/INT equality table construction and handlers.

The complete constructor fragment is followed in order: a 7x7 default fill,
then all explicit replacements up to RET. No Python truth/equality coercion
is substituted for the table. Live initializer execution remains unproven.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_legacy_size_discovery import _function
from .native_cg_vm_dispatch import _mapped_table


def bind_primitive_equality_table(raw,image,sections,table,release_address,integer_compare_address):
    pattern = re.compile(engine_pattern('native_cg_vm_primitive_table:16:25'),re.DOTALL)
    matches = []
    for _,rva,length,pointer,flags in sections:
        if not flags & 0x20000000: continue
        for m in pattern.finditer(raw[pointer:pointer+length]):
            stores = [struct.unpack_from("<I",m["stores"],n*6+2)[0] for n in range(21)]
            if stores[0] != table: continue
            if m.end()-m.start()+struct.unpack("<i",m["again"])[0] != 16:
                raise ValueError("CG 原生类型表初始化循环没有回到完整一行。")
            bases = stores[:3]
            if len(set(bases)) != 3 or any(stores[n*3+g] != bases[g]+n*4 for n in range(7) for g in range(3)):
                raise ValueError("CG 原生类型表默认写入没有覆盖完整的 7×7 类型对。")
            if any(abs(a-b) < 49*4 for a in bases for b in bases if a != b):
                raise ValueError("CG 原生类型比较表的范围相互重叠。")
            for base in bases: _mapped_table(raw,image,sections,base,49*4)
            at = pointer+m.start()
            pos = pointer+m.end()
            if raw[pos:pos+1] != b"\xb8":
                raise ValueError("CG 原生类型表缺少默认填充后的完整替换段。")
            true_target = struct.unpack_from("<I",raw,pos+1)[0]
            pos += 5
            targets = {table+n*4:struct.unpack("<I",m["default"])[0] for n in range(49)}
            replacements = []
            while pos < pointer+length and pos-at < 512:
                if raw[pos:pos+1] == b"\xc3":
                    pos += 1
                    break
                if raw[pos:pos+1] == b"\xa3":
                    address,target,size = struct.unpack_from("<I",raw,pos+1)[0],true_target,5
                elif raw[pos:pos+2] == b"\xc7\x05":
                    address,target = struct.unpack_from("<II",raw,pos+2); size = 10
                else:
                    raise ValueError("CG 原生类型表替换段包含未绑定指令。")
                if not any(base <= address < base+49*4 and (address-base)%4 == 0 for base in bases):
                    raise ValueError("CG 原生类型表写入超出了本构造器的已确认范围。")
                replacements.append(dict(offset=pos,address=address,target=target))
                if address in targets: targets[address] = target
                pos += size
            else:
                raise ValueError("CG 原生类型表构造器没有闭合返回。")
            matches.append((at,pos,targets,replacements))
    if len(matches) != 1:
        raise ValueError("CG 原生类型比较表没有唯一闭合的完整构造器。")
    start,end,targets,replacements = matches[0]
    facts,windows = {},{}
    scalar_prefix = (engine_pattern('native_cg_vm_primitive_table:62:21'))
    for left in range(3):
        for right in range(3):
            slot = table+(left*7+right)*4
            # Another explicit initializer for the same scalar slot cannot
            # silently override the analyzed constructor.
            writes = []
            store = re.compile(engine_pattern('native_cg_vm_primitive_table:70:31')+re.escape(struct.pack("<I",slot)),re.DOTALL)
            for _,_,length,pointer,flags in sections:
                if flags & 0x20000000:
                    writes.extend(pointer+m.start() for m in store.finditer(raw[pointer:pointer+length]))
            if any(not start <= at < end for at in writes):
                raise ValueError("CG 原生基础类型表项还有未闭合的其他写入。")
            address = targets[slot]
            offset,code = _function(raw,image,sections,address)
            if address == integer_compare_address:
                if (left,right) != (2,2):
                    raise ValueError("CG 整数值比较器被用于其他基础类型。")
                kind = "integer_value"
                # Already fully validated against this dispatch by the caller.
                checked = code.rstrip(b"\xcc")
                if checked not in (engine_pattern('native_cg_vm_primitive_table:84:35'),
                        engine_pattern('native_cg_vm_primitive_table:85:24')):
                    raise ValueError("CG 基础类型表的整数值比较器已改变。")
            else:
                m = re.match(scalar_prefix+engine_pattern('native_cg_vm_primitive_table:88:43'),code,re.DOTALL)
                if m is None:
                    raise ValueError("CG 原生基础类型比较结果和参数释放没有完整绑定。")
                for name in ("right","left"):
                    if address+m.end(name)+struct.unpack("<i",m[name])[0] != release_address:
                        raise ValueError("CG 原生基础类型比较没有使用本机的值释放入口。")
                kind = "never_equal" if m["result"] == b"\x33\xc0" else "always_equal"
                checked = code[:m.end()]
            windows[address] = dict(address=address,offset=offset,code_sha256=hashlib.sha256(checked).hexdigest())
            facts[str(left)+","+str(right)] = kind
    return dict(primitive_equality_results=facts,scalar_compare_windows=windows,
        comparison_constructor_offset=start,comparison_constructor_bytes=end-start,
        comparison_constructor_sha256=hashlib.sha256(raw[start:end]).hexdigest(),
        full_static_7_by_7_fill_and_replacements_bound=True,
        live_comparison_table_initialized_verified=False)
