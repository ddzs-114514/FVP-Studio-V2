"""Own complete copy dispatch, bounded table domains and aligned children.

No native code runs. Normal memory/ABI facts require DF=0, nonwrapping valid
buffers not aliasing saved stack/code, immutable tables and, on the optimized path, usable
SSE2. Heap ownership, invalid accesses, exceptions and reload remain unproven.
"""
import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_cg_vm_cleanup import _code
from .native_cg_vm_application import _writable_image_range
from .native_cg_vm_startup import _record, _relative
from .native_cg_vm_instance import _w, _branch
from .native_cg_vm_member_children import bind_native_cg_vm_member_children

SCHEMA = 'fvp-native-cg-vm-member-copy/1'
MASK = 2**32 - 1


class _Grammar:
    def __init__(self):
        self.parts, self.branches = [], []

    def code(self, hex_bytes):
        self.parts.append(re.escape(bytes.fromhex(hex_bytes)))

    def mark(self, name):
        self.parts.append(b'(?P<' + name.encode() + b'>)')

    def word(self, name):
        self.parts.append(_w(name))

    def branch(self, opcode, target, wide=False):
        key = 'branch_' + str(len(self.branches))
        self.code(opcode)
        self.parts.append(_w(key) if wide else b'(?P<' + key.encode() + b'>.)')
        self.branches.append((key, target))

    def jump(self, register, key):
        self.code({'eax': 'ff2485', 'ecx': 'ff248d', 'edx': 'ff2495'}[register])
        self.word(key)

    def match(self, code):
        match = re.match(b''.join(self.parts), code, re.DOTALL)
        if match is None:
            raise ValueError('CG 成员复制没有完整覆盖自己的全部分支、搬移、表项和正常返回。')
        for key, target in self.branches:
            _branch(match, key, target)
        return match


def _native_signed_remainder16(bits):
    if type(bits) is not int or not 0 <= bits <= MASK:
        raise ValueError('CG 复制地址必须是实际32位位模式。')
    value = bits if bits < 0x80000000 else bits - 2**32
    return (abs(value) & 15) * (-1 if value < 0 else 1)


def _optimized_path_plan(destination, source, count):
    """Arithmetic witness only; no buffers are read, written or allocated."""
    for value in (destination, source, count):
        if type(value) is not int or not 0 <= value <= MASK:
            raise ValueError('CG 复制参数必须是实际32位位模式。')
    if count < 256 or (destination & 15) != (source & 15):
        raise ValueError('CG 优化复制调用条件未满足。')
    source_remainder = _native_signed_remainder16(source)
    destination_remainder = _native_signed_remainder16(destination)
    if source_remainder != destination_remainder:
        return dict(path='forward-REP', prefix_bytes=0, recursive_calls=0,
                    chunk_iterations=0, remainder_bytes=count)
    prefix = 0 if source_remainder == 0 else 16 - source_remainder
    remaining = count - prefix
    assert 0 <= prefix <= 31 and remaining >= 225
    return dict(path='aligned-SSE2', prefix_bytes=prefix, recursive_calls=int(prefix != 0),
                chunk_iterations=remaining // 128, remainder_bytes=remaining & 127)


def _aligned_chunk(raw, image, sections, address):
    at, code = _code(raw, image, sections, address, 512)
    g = _Grammar()
    g.code('558bec83ec08897dfc8975f88b750c8b7d088b4d10c1e907')
    g.branch('eb', 'loop')
    g.code('8d9b00000000')
    g.mark('loop')
    # Eight 16-byte moves, in two load-before-store groups of four registers.
    for group in (range(4), range(4, 8)):
        for opcode, base in (('660f6f', 0x46), ('660f7f', 0x47)):
            for register in group:
                if register == 0:
                    g.code(opcode + ('06' if base == 0x46 else '07'))
                else:
                    g.code(opcode + bytes((base + register * 8, register * 16)).hex())
    g.code('8db6800000008dbf8000000049')
    g.branch('75', 'loop')
    g.code('8b75f88b7dfc8be55dc3')
    m = g.match(code)
    return dict(**_record(address, at, m[0]), kind='own-complete-aligned-128-byte-copy-loop',
                entry_SP_argument_displacements=dict(destination=4, source=8, count=12),
                callee_argument_cleanup_bytes=0, bytes_per_iteration=128,
                native_iteration_expression='do/while on (unsigned count >> 7), decrement modulo 2**32',
                zero_block_count_would_iterate_2_to_32=True,
                normal_child_context_proves_positive_block_count=True,
                input_source_and_destination_alignment_bytes=16,
                nonvolatile_registers_preserved_static_bound=True,
                XMM0_to_XMM7_are_clobbered=True, usable_SSE2_required=True,
                memory_and_pointer_wrap_bounds_proven=False, native_code_executed=False)


def _optimized_tail(raw, image, sections, address):
    at, code = _code(raw, image, sections, address, 512)
    g = _Grammar()
    g.code('558bec83ec1c897df48975f8895dfc8b5d0c8bc3998bc88b450833ca2bca83e10f33ca2bca'
           '998bf833fa2bfa83e70f33fa2bfa8bd10bd7')
    g.branch('75', 'unaligned')
    g.code('8b75108bce83e17f894de83bf1')
    g.branch('74', 'remainder')
    g.code('2bf1565350e8')
    g.word('chunk_call')
    g.code('83c40c8b45088b4de8')
    g.mark('remainder')
    g.code('85c9')
    g.branch('74', 'return')
    g.code('8b5d108b550c03d32bd18955ec03d82bd9895df08b75ec8b7df08b4de8f3a48b4508')
    g.branch('eb', 'return')
    g.mark('unaligned')
    g.code('3bcf')
    g.branch('75', 'ordinary')
    g.code('f7d983c110894de48b750c8b7d088b4de4f3a48b4d08034de48b550c0355e48b45102b45e4505251e8')
    g.word('recursive_call')
    g.code('83c40c8b4508')
    g.branch('eb', 'return')
    g.mark('ordinary')
    g.code('8b750c8b7d088b4d108bd1c1e902f3a58bca83e103f3a48b4508')
    g.mark('return')
    g.code('8b5dfc8b75f88b7df48be55dc3')
    m = g.match(code)
    if _relative(address, m, 'recursive_call') != address:
        raise ValueError('CG 优化复制没有递归到自己的完整入口。')
    chunk_address = _relative(address, m, 'chunk_call')
    chunk = _aligned_chunk(raw, image, sections, chunk_address)
    if max(address, chunk_address) < min(address + m.end(), chunk_address + chunk['code_bytes']):
        raise ValueError('CG 优化复制入口与对齐循环重叠。')
    return dict(**_record(address, at, m[0]), kind='own-complete-forward-optimized-copy',
                native_aligned_chunk=chunk, entry_SP_argument_displacements=dict(destination=4, source=8, count=12),
                callee_argument_cleanup_bytes=0, return_value_is_original_destination_static_bound=True,
                nonvolatile_registers_preserved_static_bound=True,
                alignment_uses_signed_native_address_remainder=True,
                same_unsigned_alignment_does_not_imply_same_signed_remainder=True,
                conditional_prefix_byte_range=[0, 31], recursive_depth_under_parent_conditions_at_most=1,
                recursive_remaining_count_under_parent_conditions_at_least=225,
                chunk_call_count_is_positive_multiple_of_128=True,
                normal_all_explicit_paths_static_bound=True, DF_zero_at_entry_required=True,
                valid_nonwrapping_buffers_not_aliasing_saved_stack_or_code_required=True,
                parent_forward_overlap_conditions_and_usable_SSE2_required=True,
                complete_memory_exception_effects_bound=False, native_code_executed=False)


def _copy_helper(raw, image, sections, address):
    at, code = _code(raw, image, sections, address, 2048)
    g = _Grammar()
    g.code('558bec57568b750c8b4d108b7d088bc18bd103c63bfe')
    g.branch('76', 'forward')
    g.code('3bf8')
    g.branch('0f82', 'backward', wide=True)
    g.mark('forward')
    g.code('81f900010000')
    g.branch('72', 'ordinary')
    g.code('833d')
    g.word('feature_flag')
    g.code('00')
    g.branch('74', 'ordinary')
    g.code('575683e70f83e60f3bfe5e5f')
    g.branch('75', 'ordinary')
    g.code('5e5f5de9')
    g.word('optimized_tail')
    g.mark('ordinary')
    g.code('f7c703000000')
    g.branch('75', 'forward_alignment')
    g.code('c1e90283e20383f908')
    g.branch('72', 'forward_small_dispatch')
    g.code('f3a5')
    g.jump('edx', 'forward_remainder_base0')
    g.code('90')
    g.mark('forward_alignment')
    g.code('8bc7ba0300000083e904')
    g.branch('72', 'forward_short_dispatch')
    g.code('83e00303c8')
    g.jump('eax', 'forward_alignment_base')
    g.mark('forward_short_dispatch')
    g.jump('ecx', 'forward_short_base')
    g.code('90')
    g.mark('forward_small_dispatch')
    g.jump('ecx', 'forward_small_base')
    g.code('90')
    g.mark('forward_alignment_entries')
    for i in (1, 2, 3):
        g.word('forward_alignment_entry' + str(i))
    forward_prefixes = (
        '23d18a0688078a46018847018a4602c1e90288470283c60383c70383f908',
        '23d18a0688078a4601c1e90288470183c60283c70283f908',
        '23d18a06880783c601c1e90283c70183f908')
    for i, prefix in enumerate(forward_prefixes, 1):
        g.mark('forward_prefix' + str(i))
        g.code(prefix)
        g.branch('72', 'forward_small_dispatch')
        g.code('f3a5')
        g.jump('edx', 'forward_remainder_base' + str(i))
        g.code('90' if i == 2 else '8d4900')
    g.mark('forward_small_entries')
    for i in range(8):
        g.word('forward_small_entry' + str(i))
    for i in range(7, 0, -1):
        g.mark('forward_small' + str(i))
        displacement = bytes(((-i * 4) & 255,)).hex()
        g.code('8b448e' + displacement + '89448f' + displacement)
    g.mark('forward_small0')
    g.code('8d048d0000000003f003f8')
    g.mark('forward_small_remainder_dispatch')
    g.jump('edx', 'forward_remainder_base4')
    g.code('8bff')
    g.mark('forward_remainder_entries')
    for i in range(4):
        g.word('forward_remainder_entry' + str(i))
    for i in range(4):
        g.mark('forward_remainder' + str(i))
        g.code(('8a068807' if i else '') + ('8a4601884701' if i >= 2 else '') + ('8a4602884702' if i == 3 else ''))
        g.code('8b45085e5fc9c3')
        g.code('8d4900' if i == 2 else '90')
    g.mark('backward')
    g.code('8d7431fc8d7c39fcf7c703000000')
    g.branch('75', 'backward_alignment')
    g.code('c1e90283e20383f908')
    g.branch('72', 'backward_small_dispatch')
    g.code('fdf3a5fc')
    g.jump('edx', 'backward_remainder_base0')
    g.code('8bff')
    g.mark('backward_small_dispatch')
    g.code('f7d9')
    g.jump('ecx', 'backward_small_base')
    g.code('8d4900')
    g.mark('backward_alignment')
    g.code('8bc7ba0300000083f904')
    g.branch('72', 'backward_short_dispatch')
    g.code('83e0032bc8')
    g.jump('eax', 'backward_alignment_base')
    g.mark('backward_short_dispatch')
    g.jump('ecx', 'backward_short_base')
    g.code('90')
    g.mark('backward_alignment_entries')
    for i in (1, 2, 3):
        g.word('backward_alignment_entry' + str(i))
    backward_prefixes = (
        '8a460323d188470383ee01c1e90283ef0183f908',
        '8a460323d18847038a4602c1e90288470283ee0283ef0283f908',
        '8a460323d18847038a46028847028a4601c1e90288470183ee0383ef0383f908')
    for i, prefix in enumerate(backward_prefixes, 1):
        g.mark('backward_prefix' + str(i))
        g.code(prefix)
        g.branch('0f82' if i == 3 else '72', 'backward_small_dispatch', wide=i == 3)
        g.code('fdf3a5fc')
        g.jump('edx', 'backward_remainder_base' + str(i))
        g.code('90' if i == 2 else '8d4900')
    g.mark('backward_small_entries')
    for i in range(7, -1, -1):
        g.word('backward_small_entry' + str(i))
    for i in range(7, 0, -1):
        g.mark('backward_small' + str(i))
        displacement = bytes((i * 4,)).hex()
        g.code('8b448e' + displacement + '89448f' + displacement)
    g.mark('backward_small0')
    g.code('8d048d0000000003f003f8')
    g.mark('backward_small_remainder_dispatch')
    g.jump('edx', 'backward_remainder_base4')
    g.code('8bff')
    g.mark('backward_remainder_entries')
    for i in range(4):
        g.word('backward_remainder_entry' + str(i))
    for i in range(4):
        g.mark('backward_remainder' + str(i))
        g.code(('8a4603884703' if i else '') + ('8a4602884702' if i >= 2 else '') + ('8a4601884701' if i == 3 else ''))
        g.code('8b45085e5fc9c3')
        if i != 3:
            g.code('8d4900' if i == 1 else '90')
    m = g.match(code)
    words = lambda name: struct.unpack('<I', m[name])[0]
    sites = []
    def table_reference(key, label, delta, index_bits, expression):
        expected = address + m.start(label) + delta
        if words(key) != expected:
            raise ValueError('CG 复制的跳转表没有使用自己由分支限制的表域。')
        sites.append(dict(operand_address=address + m.start(key), table_base_address=expected,
                          reachable_index_bits=index_bits, index_domain_expression=expression,
                          complete_index_domain_static_bound=True))
    for i in range(5):
        table_reference('forward_remainder_base' + str(i), 'forward_remainder_entries', 0, list(range(4)), 'EDX masked by 3')
        table_reference('backward_remainder_base' + str(i), 'backward_remainder_entries', 0, list(range(4)), 'EDX masked by 3')
    table_reference('forward_alignment_base', 'forward_alignment_entries', -4, [1, 2, 3], 'nonzero EDI & 3')
    table_reference('backward_alignment_base', 'backward_alignment_entries', -4, [1, 2, 3], 'nonzero (EDI + count - 4) & 3')
    table_reference('forward_short_base', 'forward_remainder_entries', 16, [MASK - 3, MASK - 2, MASK - 1, MASK],
                    '(count - 4) mod 2**32 after unsigned subtraction borrow')
    table_reference('forward_small_base', 'forward_small_entries', 0, list(range(8)), 'unsigned dword count below 8')
    table_reference('backward_small_base', 'backward_small_entries', 28, [0] + list(range(MASK - 6, MASK + 1)),
                    'negated unsigned dword count 0..7 modulo 2**32')
    table_reference('backward_short_base', 'backward_remainder_entries', 0, list(range(4)), 'unsigned byte count below 4')
    table_ranges = []
    for direction in ('forward', 'backward'):
        for kind, indices, destination in (('alignment', (1, 2, 3), 'prefix'), ('small', range(8), 'small'),
                                             ('remainder', range(4), 'remainder')):
            for i in indices:
                target = direction + '_small_remainder_dispatch' if kind == 'small' and i == 0 else direction + '_' + destination + str(i)
                if words(direction + '_' + kind + '_entry' + str(i)) != address + m.start(target):
                    raise ValueError('CG 复制表项没有指向自己的完整搬移／返回块：' + direction + '_' + kind + '_' + str(i))
            label = direction + '_' + kind + '_entries'
            table_ranges.append(dict(address=address + m.start(label), bytes=4 * len(indices), entries=len(indices)))
    feature = _writable_image_range(raw, image, sections, words('feature_flag'), 4)
    tail_address = _relative(address, m, 'optimized_tail')
    tail = _optimized_tail(raw, image, sections, tail_address)
    for child in (tail, tail['native_aligned_chunk']):
        if max(address, child['address']) < min(address + m.end(), child['address'] + child['code_bytes']):
            raise ValueError('CG 复制函数与自己的优化子函数重叠。')
    return dict(**_record(address, at, m[0]), kind='own-complete-overlap-directed-copy',
                native_optimized_tail=tail, own_feature_flag_range=feature,
                feature_flag_contents_and_CPU_OS_support_at_call_proven=False,
                indexed_dispatch_sites=sites, embedded_table_ranges=table_ranges,
                unreachable_alignment_index_zero_not_decoded_as_code=True,
                all_reachable_table_indices_and_own_targets_static_bound=True,
                jump_table_words_are_data_not_linear_instructions=True,
                direction_condition='backward iff destination > source and destination < (source + count) modulo 2**32',
                unsigned_source_end_no_wrap_required_for_overlap_semantics=True,
                entry_SP_argument_displacements=dict(destination=4, source=8, count=12), callee_argument_cleanup_bytes=0,
                return_value_is_original_destination_static_bound=True,
                saved_EBP_ESI_EDI_and_nonvolatile_EBX_preserved_static_bound=True,
                normal_all_explicit_paths_and_child_ABI_static_bound=True,
                forward_REP_requires_DF_zero_at_entry=True, backward_REP_has_STD_and_CLD=True,
                normal_DF_zero_on_return_under_entry_condition=True,
                valid_nonwrapping_buffers_not_aliasing_saved_stack_or_code_required=True,
                code_and_table_contents_at_call_immutable_required=True,
                source_and_destination_may_overlap_under_valid_bounds=True,
                complete_heap_memory_exception_and_concurrency_effects_bound=False, native_code_executed=False)


def bind_native_cg_vm_member_copy(executable, header, vm, frames):
    raw = bytes(executable)
    image, sections = _pe_sections(raw)
    children = bind_native_cg_vm_member_children(raw, header, vm, frames)
    members = children['native_vm_members']
    copies = {}
    older = members['layout'] == 'signed-word-legacy'
    for role in ('string', 'container'):
        own = members['native_' + role + '_member']
        if older:
            if not own['native_copy_direction_flag_zero_required'] or 'copy_call' in own['helper_addresses']:
                raise ValueError('CG 旧版成员复制没有保留自己的完整内联 REP 调用链。')
            copies[role] = dict(kind='own-complete-member-inline-forward-REP-instructions',
                                owning_function_address=own['address'], owning_function_code_sha256=own['code_sha256'],
                                DF_zero_at_entry_required=True, writable_buffer_bounds_and_source_aliases_proven=False,
                                normal_instruction_paths_static_bound=True, native_code_executed=False)
        else:
            copies[role] = _copy_helper(raw, image, sections, own['helper_addresses']['copy_call'])
    if not older and copies['string'] != copies['container']:
        raise ValueError('CG 字符串和容器没有共用自己的完整复制实现。')
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=members['layout'],
                native_vm_member_children=children, native_member_copy_paths=copies,
                own_complete_member_copy_instruction_paths_static_bound=True,
                own_copy_helper_normal_control_flow_and_ABI_static_bound=not older,
                own_copy_helper_table_domains_and_children_static_bound=not older,
                own_legacy_inline_REP_instruction_paths_static_bound=older,
                member_copy_helper_effects_complete=False, legacy_inline_copy_DF_and_bounds_complete=False,
                complete_member_child_and_heap_effects_bound=False, native_allocator_and_free_heap_effects_complete=False,
                same_live_instance_lifetime_proven=False, initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False, source_header_arity_to_native_descriptor_bound=False,
                complete_allocation_exception_and_reentry_effects_bound=False, native_code_executed=False,
                runtime_verified=False, scene_export_connected=False)
