"""Target-owned HCB global-count reader and storage request, never runtime proof.

The source EXE must read both header counts as signed words, add them, request
eight bytes per value, initialise each value's NIL tag, and store the array in
the SAME VM object used by the independently bound ThreadNext handler. Unknown
loaders do not inherit these rules. Allocation success and global-opcode index
semantics remain separate requirements before this private image can ship.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_thread_handoff import _next_binding


SCHEMA = "fvp-native-cg-global-storage/1"

def _release_pattern_value__U32():
    return engine_pattern('native_cg_global_storage:20:8')
def _release_pattern_value__I16():
    return engine_pattern('native_cg_global_storage:21:8')
def _release_pattern_value__HEADER():
    return engine_pattern('native_cg_global_storage:22:11') + _release_pattern_value__U32() + engine_pattern('native_cg_global_storage:23:13') + _release_pattern_value__U32() + engine_pattern('native_cg_global_storage:24:6') + _release_pattern_value__I16() + engine_pattern('native_cg_global_storage:25:6') + _release_pattern_value__I16()
def _release_pattern_value__MODERN():
    return engine_pattern('native_cg_global_storage:26:11')
def _release_pattern_value__LEGACY():
    return engine_pattern('native_cg_global_storage:33:11')
def _release_pattern_value__ARRAY_MODERN():
    return engine_pattern('native_cg_global_storage:39:16')
def _release_pattern_value__ARRAY_LEGACY():
    return engine_pattern('native_cg_global_storage:42:16')


def bind_native_cg_global_storage(executable, header, next_binding, *, additional_volatile=1):
    """Return static source-byte evidence or reject; no mutation/installation."""
    if type(additional_volatile) is not int or not 0 <= additional_volatile <= 0x7fff:
        raise ValueError("CG 临时变量数量超出本机已确认的 signed-word 范围。")
    raw = bytes(executable)
    native_next = _next_binding(raw)
    if next_binding != native_next:
        raise ValueError("CG 临时变量与线程交接不是同一份原生引擎。")
    image, sections = _pe_sections(raw)
    candidates = []
    for layout, body, array_code in (("signed-word-modern", _release_pattern_value__MODERN(), _release_pattern_value__ARRAY_MODERN()),
                                     ("signed-word-legacy", _release_pattern_value__LEGACY(), _release_pattern_value__ARRAY_LEGACY())):
        pattern = re.compile(_release_pattern_value__HEADER()+body, re.DOTALL)
        for _, rva, length, pointer, flags in sections:
            if not flags & 0x20000000:
                continue
            for match in pattern.finditer(raw[pointer:pointer+length]):
                fields = {name:struct.unpack("<I",match[name])[0] for name in
                          ("parser","cursor","entry","nonvolatile","volatile","buffer")}
                if (fields["cursor"] != fields["parser"]+8
                        or fields["buffer"] != fields["parser"]+16
                        or fields["volatile"] != fields["nonvolatile"]+4
                        or fields["entry"] != fields["nonvolatile"]+12
                        or native_next["current_thread_fields"]["current"] != fields["nonvolatile"]+8
                        or any(n >= 2**31 for n in fields.values())):
                    continue
                offset = pointer+match.start()
                address = image+rva+match.start()
                addresses = {name:address+(match.start(name)-match.start())+4
                             +struct.unpack("<i",match[name])[0]
                             for name in ("stream","allocator","array")}
                addresses["constructor"] = struct.unpack("<I",match["constructor"])[0]
                try:
                    helper_offsets = {name:_relocated(raw,image,sections,at,executable=True)
                                      for name,at in addresses.items()}
                    ctor_at, array_at = helper_offsets["constructor"],helper_offsets["array"]
                    _relocated(raw,image,sections,addresses["constructor"],executable=True,length=6)
                    _relocated(raw,image,sections,addresses["array"],executable=True,length=len(array_code))
                    if raw[ctor_at:ctor_at+6] != b"\x8b\xc1\xc6\0\0\xc3":
                        continue
                    if raw[array_at:array_at+len(array_code)] != array_code:
                        continue
                    # Both recognised new[] forwarders preserve the cdecl size
                    # argument. Bind their jump target locally; don't claim
                    # that allocation will succeed merely because it is called.
                    alloc_at = helper_offsets["allocator"]
                    prefix = b"\x8b\xff\x55\x8b\xec\x5d" if layout.endswith("modern") else b""
                    size = len(prefix)+5
                    _relocated(raw,image,sections,addresses["allocator"],executable=True,length=size)
                    forwarder = raw[alloc_at:alloc_at+size]
                    if forwarder[:len(prefix)+1] != prefix+b"\xe9":
                        continue
                    destination = addresses["allocator"]+size+struct.unpack_from("<i",forwarder,size-4)[0]
                    _relocated(raw,image,sections,destination,executable=True)
                except ValueError:
                    continue
                candidates.append(dict(schema=SCHEMA,layout=layout,loader_reader_offset=offset,
                    loader_reader_sha256=hashlib.sha256(match[0]).hexdigest(),vm_fields=fields,
                    native_helpers=addresses,allocator_forward_target=destination,
                    allocator_forwarder_sha256=hashlib.sha256(forwarder).hexdigest(),
                    array_constructor_sha256=hashlib.sha256(array_code).hexdigest(),
                    exe_sha256=hashlib.sha256(raw).hexdigest(),header_counts_signed_bits=16,
                    value_bytes=8,value_nil_tag_initialized=True,array_constructor_loop_bound=True,
                    same_native_thread_controller=True,storage_size_request_static_bound=True,
                    allocation_success_runtime_verified=False,global_opcode_index_semantics_bound=False,
                    runtime_verified=False,public_cg_export_enabled=False))
    if len(candidates) != 1:
        raise ValueError("尚未确定本游戏如何读取和分配 CG 交接的临时变量。")
    counts = (header.non_volatile_globals,header.volatile_globals)
    if any(type(n) is not int or not 0 <= n <= 0x7fff for n in counts):
        raise ValueError("游戏的变量数量超出本引擎已确认的范围。")
    if header.volatile_globals+additional_volatile > 0x7fff or sum(counts)+additional_volatile > 0xffff:
        raise ValueError("本游戏已没有可安全声明的 CG 临时变量。")
    # The target array-use windows include signed-word index readers too.
    # Their 0x0F/0x15 dispatch binding is not complete yet: never emit an
    # ambiguous negative private index just because both COUNTS are positive.
    if sum(counts) > 0x7fff or sum(counts)+additional_volatile > 0x8000:
        raise ValueError("尚未接上本游戏高编号的 CG 临时变量，不能生成可能错误的编号。")
    result = candidates[0]
    result.update(original_counts=list(counts),candidate_counts=[counts[0],counts[1]+additional_volatile],
        private_global_index=sum(counts),candidate_storage_bytes=(sum(counts)+additional_volatile)*8,
        additional_volatile_globals=additional_volatile,
        original_global_ids_unchanged=True)
    return result


_RELEASE_PATTERN_FACTORIES = {'_U32': _release_pattern_value__U32, '_I16': _release_pattern_value__I16, '_HEADER': _release_pattern_value__HEADER, '_MODERN': _release_pattern_value__MODERN, '_LEGACY': _release_pattern_value__LEGACY, '_ARRAY_MODERN': _release_pattern_value__ARRAY_MODERN, '_ARRAY_LEGACY': _release_pattern_value__ARRAY_LEGACY}
def __getattr__(name):
    factory = _RELEASE_PATTERN_FACTORIES.get(name)
    if factory is None:
        raise AttributeError(name)
    return factory()
