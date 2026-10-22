"""Own-EXE integer literals/equality facts for private stack specialization.

Signed integer literals, frame-slot moves, primitive copies and the actual
NIL/TRUE/INT equality table are bound. Arithmetic, globals, syscall results
and mutable objects remain unknown. No Python bool/int coercion is used.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _function, _relocated
from .native_cg_vm_dispatch import _mapped_table
from .native_cg_vm_primitive_table import bind_primitive_equality_table
from .native_cg_table_values import bind_native_table_scalar_access

SCHEMA = "fvp-native-cg-vm-primitive-facts/2"


def bind_native_cg_vm_primitives(executable, dispatch):
    raw = bytes(executable)
    if dispatch.get("exe_sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("CG 参数条件不是同一份原生 EXE。")
    image, sections = _pe_sections(raw)
    start, table = dispatch["initializer_offset"], dispatch["opcode_table"]
    if hashlib.sha256(raw[start:start+400]).hexdigest() != dispatch["initializer_sha256"]:
        raise ValueError("CG 参数条件的原生指令表已经变化。")
    addresses = []
    for op in range(40):
        pos = start+op*10
        if raw[pos:pos+2] != b"\xc7\x05" or struct.unpack_from("<I", raw, pos+2)[0] != table+op*4:
            raise ValueError("CG 参数条件缺少完整的本机指令表。")
        addresses.append(struct.unpack_from("<I", raw, pos+6)[0])
    fields = dispatch["thread_frame_fields"]
    SP, PC, FP = (re.escape(struct.pack("<I", fields[k])) for k in ("sp", "pc", "fp"))
    windows = {}
    def body(op):
        offset, code = _function(raw, image, sections, addresses[op])
        next_handlers = [a for a in addresses if addresses[op] < a < addresses[op]+len(code)]
        if next_handlers:
            code = code[:min(next_handlers)-addresses[op]]
        code = code.rstrip(b"\xcc")
        windows[op] = dict(address=addresses[op], offset=offset,
                           code_sha256=hashlib.sha256(code).hexdigest())
        return code
    literal_prefix = (engine_pattern('native_cg_vm_primitives:46:22')+SP+engine_pattern('native_cg_vm_primitives:46:38')+SP+
                      engine_pattern('native_cg_vm_primitives:47:22')+PC+engine_pattern('native_cg_vm_primitives:47:58'))
    for op, read in ((10, engine_pattern('native_cg_vm_primitives:48:26')),
                     (11, engine_pattern('native_cg_vm_primitives:49:26')),
                     (12, engine_pattern('native_cg_vm_primitives:50:26'))):
        if re.fullmatch(literal_prefix+read+engine_pattern('native_cg_vm_primitives:51:44')+PC+engine_pattern('native_cg_vm_primitives:51:60'), body(op), re.DOTALL) is None:
            raise ValueError("CG 整数常量的类型／有符号读取尚未绑定。")
    copy = re.match(engine_pattern('native_cg_vm_primitives:53:20')+SP+engine_pattern('native_cg_vm_primitives:53:36')+SP+
        engine_pattern('native_cg_vm_primitives:54:8'),body(19),re.DOTALL)
    if copy is None or body(19)[copy.end()+struct.unpack("<b",copy["primitive"])[0]:][:1] != b"\xc3":
        raise ValueError("CG 顶部基础值复制没有完整的原生路径。")
    move_prefix = engine_pattern('native_cg_vm_primitives:58:18')+PC+engine_pattern('native_cg_vm_primitives:58:50')+FP
    move_new = (engine_pattern('native_cg_vm_primitives:59:16')+SP+engine_pattern('native_cg_vm_primitives:59:32')+SP+engine_pattern('native_cg_vm_primitives:59:48'))
    move_old = (engine_pattern('native_cg_vm_primitives:60:16')+SP+engine_pattern('native_cg_vm_primitives:60:40')+SP+
                engine_pattern('native_cg_vm_primitives:61:16'))
    move = re.fullmatch(move_prefix+rb"(?:"+move_new+rb"|"+move_old+engine_pattern('native_cg_vm_primitives:62:68')+PC+
        engine_pattern('native_cg_vm_primitives:63:8'),body(22),re.DOTALL)
    if move is None or addresses[22]+move.end("release")+struct.unpack("<i",move["release"])[0] != dispatch["release_value_address"]:
        raise ValueError("CG 局部／参数赋值没有绑定到本机有符号索引和值释放。")
    comparison_tables = []
    for op in (34, 35):
        modern = (engine_pattern('native_cg_vm_primitives:68:18')+SP+engine_pattern('native_cg_vm_primitives:68:34')+SP+engine_pattern('native_cg_vm_primitives:68:50')+
                  (engine_pattern('native_cg_vm_primitives:71:19') if op == 34 else engine_pattern('native_cg_vm_primitives:71:53'))+engine_pattern('native_cg_vm_primitives:71:71'))
        older = (engine_pattern('native_cg_vm_primitives:72:17')+SP+engine_pattern('native_cg_vm_primitives:72:33')+SP+
                 engine_pattern('native_cg_vm_primitives:73:17')+
                 (engine_pattern('native_cg_vm_primitives:75:18') if op == 34 else engine_pattern('native_cg_vm_primitives:75:60'))+
                 engine_pattern('native_cg_vm_primitives:76:17'))
        code = body(op)
        match = re.fullmatch(modern, code, re.DOTALL) or re.fullmatch(older, code, re.DOTALL)
        if match is None:
            raise ValueError("CG 整数比较没有完整的类型分派和 NIL／TRUE 结果路径。")
        comparison_tables.append(struct.unpack("<I", match["table"])[0])
    if comparison_tables[0] != comparison_tables[1]:
        raise ValueError("CG 等于／不等于不是同一份原生类型比较表。")
    compare_table = comparison_tables[0]
    _mapped_table(raw, image, sections, compare_table, 49*4)
    # INT tag 2; the actual dispatch index is left_tag*7+right_tag.
    slot = compare_table+(2*7+2)*4
    assignments = []
    pattern = re.compile(engine_pattern('native_cg_vm_primitives:89:25')+re.escape(struct.pack("<I", slot))+rb"(.{4})", re.DOTALL)
    for _, rva, length, pointer, flags in sections:
        if flags & 0x20000000:
            for match in pattern.finditer(raw[pointer:pointer+length]):
                assignments.append((pointer+match.start(), struct.unpack("<I", match[1])[0]))
    if len(assignments) != 1:
        raise ValueError("CG INT／INT 比较没有唯一的本机表项初始化。")
    init_offset, compare_address = assignments[0]
    offset, code = _function(raw, image, sections, compare_address)
    code = code.rstrip(b"\xcc")
    allowed = (engine_pattern('native_cg_vm_primitives:99:15'),
               engine_pattern('native_cg_vm_primitives:100:15'))
    if code not in allowed:
        raise ValueError("CG INT／INT 比较的实际值读取和相等结果尚未绑定。")
    scalar_table = bind_primitive_equality_table(raw,image,sections,compare_table,
        dispatch["release_value_address"],compare_address)
    table_access = bind_native_table_scalar_access(raw,image,sections,addresses,fields,
        dispatch["release_value_address"])
    return dict(schema=SCHEMA, exe_sha256=dispatch["exe_sha256"],
        source_windows=windows, comparison_table=compare_table, integer_tag=2,
        integer_comparison_slot=slot, comparison_assignment_offset=init_offset,
        comparison_assignment_sha256=hashlib.sha256(raw[init_offset:init_offset+10]).hexdigest(),
        integer_compare=dict(address=compare_address, offset=offset, code_sha256=hashlib.sha256(code).hexdigest()),
        signed_integer_literals_static_bound=True, integer_equality_static_bound=True,
        primitive_equality_static_bound=True,POP_STACK_signed_slot_move_static_bound=True,
        PUSH_TOP_primitive_copy_static_bound=True,**scalar_table,
        predicate_false_is_nil_tag=True, predicate_true_is_true_tag=True,
        global_and_syscall_value_facts_used=False, other_operators_static_bound=False,
        native_table_scalar_access=table_access,
        runtime_verified=False, scene_export_connected=False)
