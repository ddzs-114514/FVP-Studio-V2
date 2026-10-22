"""Keep CG scratch globals out of the original system-save byte layout.

Only generated test EXE bytes are changed. The VM still allocates the full
candidate global count. The paired native startup reader and exit writer copy
the original volatile prefix, not the appended CG journal/snapshot workspace.
This does not establish compatibility of ordinary in-story save slots.
"""
import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_cg_vm_restore import _legacy_grammar, _modern_grammar
from .native_cg_vm_state_pack import _pack_grammar


def _find(raw, sections, grammar):
    matches = []
    pattern = re.compile(b''.join(grammar.parts), re.DOTALL)
    for _, _, size, offset, flags in sections:
        if not flags & 0x20000000:
            continue
        for candidate in pattern.finditer(raw[offset:offset + size]):
            at = offset + candidate.start()
            # Recheck the full body's branch destinations, not just opcodes.
            match = grammar.match(raw[at:at + len(candidate[0])])
            matches.append((at, match))
    return matches


def preserve_system_save_layout(executable, original_volatile_globals):
    if type(original_volatile_globals) is not int or not 0 <= original_volatile_globals <= 0x7fff:
        raise ValueError('系统保存兼容需要原脚本的实际变量数量。')
    raw = bytes(executable)
    _, sections = _pe_sections(raw)
    pairs = []
    for older in (False, True):
        restore = _find(raw, sections, _legacy_grammar() if older else _modern_grammar())
        pack = _find(raw, sections, _pack_grammar(older))
        if len(restore) == len(pack) == 1:
            read, write = restore[0], pack[0]
            if all(read[1][k] == write[1][k] for k in ('owner', 'filename', 'volatile', 'nonvolatile', 'buffer')):
                pairs.append((older, read, write))
    if len(pairs) != 1:
        raise ValueError('尚未配对本目标的系统保存读取和写回，不能只修一端。')
    older, read, write = pairs[0]
    result = bytearray(raw)
    patches = []
    for role, (start, match), prefix, register in (
        ('startup_read', read, b'\x8b\x8b' if older else b'\x8b\x83', 1 if older else 0),
        ('exit_write', write, b'\x8b\x96' if older else b'\x8b\xb5', 2 if older else 6),
    ):
        at = start + match.start('volatile') - 2
        expected = prefix + match['volatile']
        if raw[at:at + 6] != expected:
            raise ValueError('系统保存变量数量读取不是已配对的完整指令。')
        # MOV reg,imm32 / NOP keeps length, branch PCs, flags and all other
        # registers unchanged. Do not alter the VM count or allocation itself.
        replacement = bytes((0xb8 + register,)) + struct.pack('<I', original_volatile_globals) + b'\x90'
        result[at:at + 6] = replacement
        patches.append(dict(role=role, offset=at, expected_hex=expected.hex(), replacement_hex=replacement.hex()))
    return bytes(result), dict(
        schema='fvp-native-cg-system-save-compat/1',
        original_volatile_globals=original_volatile_globals,
        paired_startup_read_and_exit_write=True, cg_scratch_globals_persisted=False,
        candidate_vm_allocation_unchanged=True, original_save_files_modified=False,
        ordinary_save_slots_verified=False, runtime_verified=False,
        patches=patches, source_executable_sha256=hashlib.sha256(raw).hexdigest(),
        output_executable_sha256=hashlib.sha256(result).hexdigest())
