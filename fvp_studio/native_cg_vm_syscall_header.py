"""Own-loader SYS name/argc lookup and ordered append, not runtime acceptance.

Connect the already bound HCB header reader to its complete SYS record loop,
native name lookup, and the vector consumed by SYS. This is deliberately not
an unconditional arity grant: initial vector state, catalogue construction,
failure-path effects and later descriptor mutation remain separate audits.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _function, _relocated
from .native_cg_thread_handoff import _next_binding
from .native_cg_global_storage import bind_native_cg_global_storage, _release_pattern_value__HEADER as _HEADER, _release_pattern_value__MODERN as _MODERN, _release_pattern_value__LEGACY as _LEGACY
from .native_cg_vm_syscall_stack import bind_native_cg_vm_syscall_stack
from .native_rotation_degrees import _imports

SCHEMA = "fvp-native-cg-vm-syscall-header/1"


def _word(value):
    return re.escape(struct.pack("<I", value))


def _interlude(older):
    if older:
        return (
            engine_pattern('native_cg_vm_syscall_header:29:12'))
    return (
        engine_pattern('native_cg_vm_syscall_header:38:8'))


def _loop(older, catalogue, vector):
    begin = engine_pattern('native_cg_vm_syscall_header:51:12')
    begin += (engine_pattern('native_cg_vm_syscall_header:52:14') if older else
              engine_pattern('native_cg_vm_syscall_header:53:14'))
    body = (engine_pattern('native_cg_vm_syscall_header:54:12')
            + (rb"\x4d" if older else rb"")
            + engine_pattern('native_cg_vm_syscall_header:56:14') + _word(catalogue)
            + (engine_pattern('native_cg_vm_syscall_header:58:15') if older else engine_pattern('native_cg_vm_syscall_header:58:50'))
            + engine_pattern('native_cg_vm_syscall_header:59:14')
            + (engine_pattern('native_cg_vm_syscall_header:60:15') if older else engine_pattern('native_cg_vm_syscall_header:60:50'))
            + engine_pattern('native_cg_vm_syscall_header:61:14') + _word(vector)
            + engine_pattern('native_cg_vm_syscall_header:62:14'))
    return begin + body


def _lookup(raw, image, sections, address, imports):
    offset, code = _function(raw, image, sections, address)
    # Complete binary search, including unsuccessful and optional-index exits.
    pattern = (
        engine_pattern('native_cg_vm_syscall_header:70:8'))
    match = re.fullmatch(pattern, code, re.DOTALL)
    if match is None:
        raise ValueError("CG 调用表的原生查名函数还没有完整绑定。")
    iat = struct.unpack("<I", match["compare"])[0]
    _relocated(raw, image, sections, iat, executable=False, length=4)
    if imports.get(iat) != ("kernel32.dll", "lstrcmpA"):
        raise ValueError("CG 调用表查名没有接到本机已确认的命名比较入口。")
    return dict(address=address, offset=offset, code_sha256=hashlib.sha256(code).hexdigest(),
                code_bytes=len(code), comparator_iat=iat, comparator_dll="kernel32.dll",
                comparator_name="lstrcmpA", descriptor_name_field=0)


def _append(raw, image, sections, address):
    offset, code = _function(raw, image, sections, address)
    pattern = (
        engine_pattern('native_cg_vm_syscall_header:92:8'))
    match = re.fullmatch(pattern, code, re.DOTALL)
    if match is None:
        raise ValueError("CG 调用表不是已确认的原生顺序追加函数。")
    callee = lambda key: address + match.end(key) + struct.unpack("<i", match[key])[0]
    grow = callee("grow_zero")
    if grow != callee("grow_full"):
        raise ValueError("CG 调用表首次分配和扩容没有共用本机存储入口。")
    _relocated(raw, image, sections, grow, executable=True)
    return dict(address=address, offset=offset, code_sha256=hashlib.sha256(code).hexdigest(),
                code_bytes=len(code), native_grow_address=grow, count_field=4, buffer_field=8,
                pointer_bytes=4, appended_descriptor_is_input_pointer=True,
                native_grow_side_effects_complete=False, allocation_success_runtime_verified=False)


def bind_native_cg_vm_syscall_header(executable, header, vm, frames):
    raw = bytes(executable)
    syscall_stack = bind_native_cg_vm_syscall_stack(raw, vm, frames)
    storage = bind_native_cg_global_storage(raw, header, _next_binding(raw), additional_volatile=0)
    image, sections = _pe_sections(raw)
    field = syscall_stack["syscall_descriptor_table_field"]
    vector, catalogue = field-8, field-24
    older = storage["layout"] == "signed-word-legacy"
    start = storage["loader_reader_offset"]
    header_pattern = _HEADER() + (_LEGACY() if older else _MODERN())
    header_match = re.match(header_pattern, raw[start:], re.DOTALL)
    if header_match is None or hashlib.sha256(header_match[0]).hexdigest() != storage["loader_reader_sha256"]:
        raise ValueError("CG 调用表不属于当前目标已绑定的脚本头读取器。")
    pattern = header_pattern + _interlude(older) + _loop(older, catalogue, vector)
    match = re.match(pattern, raw[start:], re.DOTALL)
    if match is None:
        raise ValueError("CG 调用表读名／核对参数／顺序追加还没有连到本机完整脚本头读取链。")
    section = next(s for s in sections if s[3] <= start < s[3]+s[2])
    address = image+section[1]+start-section[3]
    _relocated(raw, image, sections, address, executable=True, length=match.end())
    for jump, label in (("zero", "done"), ("again", "loop")):
        if match.end(jump)+struct.unpack("<b", match[jump])[0] != match.start(label):
            raise ValueError("CG 调用表没有正确遍历脚本中的原生调用记录。")
    relative = lambda key: address+match.end(key)+struct.unpack("<i", match[key])[0]
    # Failure branches must leave the record loop for two distinct native
    # error-construction blocks. Their throw/exception semantics are not granted.
    errors = {}
    for key in ("missing", "argc_error"):
        target = relative(key)
        at = _relocated(raw, image, sections, target, executable=True, length=17)
        if target < address+match.end() or not re.match(
                engine_pattern('native_cg_vm_syscall_header:143:16'), raw[at:at+17], re.DOTALL):
            raise ValueError("CG 调用名或参数不匹配时没有分开走本机错误路径。")
        errors[key] = target
    if len(set(errors.values())) != 2:
        raise ValueError("CG 调用名与参数错误的原生分支已经合并或变化。")
    imports = _imports(raw, image)
    lookup = _lookup(raw, image, sections, relative("lookup"), imports)
    append = _append(raw, image, sections, relative("append"))
    for key in ("renderer", "empty_name"):
        _relocated(raw, image, sections, struct.unpack("<I", match[key])[0], executable=False)
    _relocated(raw, image, sections, relative("configure_name"), executable=True)
    if older:
        if match["hfield"][0] != match["wfield"][0]+4:
            raise ValueError("CG 原生脚本头中的相邻尺寸字段已经变化。")
    else:
        x, y = (struct.unpack("<I", match[k])[0] for k in ("modes", "modes_y"))
        if y != x+2:
            raise ValueError("CG 原生脚本头中的模式表字段已经变化。")
        _relocated(raw, image, sections, x, executable=False, length=64)
    if len(header.syscalls) > 0x7fff:
        raise ValueError("CG 调用表超出本机有符号调用数量的范围。")
    encoded = bytearray(struct.pack("<h", len(header.syscalls)))
    records, names = [], set()
    for index, item in enumerate(header.syscalls):
        if type(item.name) is not str or not item.name or "\0" in item.name or item.name in names:
            raise ValueError("CG 原生调用名缺失、重复或包含终止符。")
        try:
            name = item.name.encode("ascii")+b"\0"
        except UnicodeEncodeError as error:
            raise ValueError("CG 原生调用名不是当前已确认的 ASCII 名称。") from error
        if (type(item.args) is not int or not 0 <= item.args <= 0x7f
                or len(name) > 255 or getattr(item, "raw_name", name) != name):
            raise ValueError("CG 调用记录不符合本机有符号参数数／终止名称的编码。")
        names.add(item.name)
        encoded.extend(bytes((item.args, len(name)))+name)
        records.append(dict(index=index, name=item.name, header_argc=item.args))
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(),
        layout=storage["layout"], reader_offset=start, reader_address=address,
        reader_code_sha256=hashlib.sha256(match[0]).hexdigest(), reader_code_bytes=match.end(),
        source_header_syscalls_sha256=hashlib.sha256(encoded).hexdigest(), source_header_records=records,
        native_syscall_vector_field=vector, native_syscall_buffer_field=field,
        native_catalogue_field=catalogue, native_lookup=lookup, native_append=append,
        native_failure_branches=errors, native_argc_field=4, syscall_count_signed_bits=16,
        header_argc_signed_bits=8, header_name_length_unsigned_bits=8,
        loader_name_lookup_argc_check_and_ordered_append_static_bound=True,
        native_append_retains_lookup_descriptor_pointer=True,
        same_descriptor_buffer_as_SYS_dispatch=True,
        source_header_record_order_preserved_by_each_append=True,
        accepted_record_native_argc_equality_guard_static_bound=True,
        initial_syscall_vector_count_zero_proven=False,
        native_catalogue_construction_and_sorting_complete=False,
        native_loader_failure_path_effects_complete=False,
        native_descriptor_argc_immutability_proven=False,
        source_header_arity_to_native_descriptor_bound=False,
        native_loader_success_runtime_verified=False, native_code_executed=False,
        runtime_verified=False, scene_export_connected=False)
