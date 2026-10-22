"""Own legacy window/match/block paths and fixed trees, not a live save grant."""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_cg_vm_application import _import_slots
from .native_cg_vm_restore_children import _ChildGrammar, _bind
from .native_cg_vm_lifecycle import _parent
from .native_cg_vm_save_algorithms import bind_native_cg_vm_save_algorithms

SCHEMA = 'fvp-native-cg-vm-save-algorithm-children/1'

_FILL = '''83ec088b432455568944240c578d4900|@loop
8b4b648b53348b736c2bd12bd6|75 nonzero|85c9|75 slide_check|85f6|75 slide_check
8bd0|e9 input|@nonzero|83faff|75 slide_check|bafeffffff|e9 input
@slide_check|8b73248db430fafeffff3bce|72 input
8b7b308bc88be9c1e9028d3407f3a58bcd83e103f3a48b7b688b73648b4b542bf82bf02bc8
897b688b7b44894b548b4b3c8973648d3479|@heads|0fb74efe83ee023bc8|72 head_zero
2bc8|eb head_store|@head_zero|33c9|@head_store|4f66890e|75 heads
8b4b388bf88d3441|@previous|0fb74efe83ee023bc8|72 previous_zero
2bc8|eb previous_store|@previous_zero|33c9|@previous_store|4f66890e|75 previous
03d0|@input|8b2b8b4d0485c9|0f84 return
8b73648b7b6c8b4b3003fe03f98b4d048bf13bf28974240c|76 count_ready
8954240c8bf2|@count_ready|85f6|75 read|33c9|eb lookahead|@read
8b551c2bce894d048b4a1885c9|75 copy|8b45008b4d30565051|call checksum
8945308b44241c83c40c|@copy
8bce8b75008bd1c1e902f3a58bca83e103f3a48b4c240c8b75008b550803f103d1897500895508
@lookahead|8b536c03d18bfa83ff0389536c|72 continue
8b4b648b53308d34110fb6168b4b50895340d3e20fb64e0133d123534c895340
@continue|81ff06010000|73 return|8b138b4a0485c9|0f85 loop
@return|5f5e5d83c408c3'''

_MATCH = '''83ec148b4e748b566453558b6e70578bbe88000000894c24108b4e30897c24148b7e24
8d9ffafeffff03ca3bd3|76 limit_zero|2bd781c20601000089542418|eb limit_ready
@limit_zero|c744241800000000|@limit_ready
8a5429ff8854240e8a14298854240f3bae840000008db902010000|72 chain_ready
c16c241002|@chain_ready|8b566c395424148954241c|76 nice_ready
89542414|eb nice_ready|8d9b00000000|@nice_ready
@candidate|8b56308a5c240f03d0381c2a|0f85 next
8a5c240e385c2aff|0f85 next|8a1a3a19|0f85 next|8a5a01423a5901|0f85 next
83c10242|eb compare|8d4900|@compare
8a590141423a1a|75 compared|8a590141423a1a|75 compared
8a590141423a1a|75 compared|8a590141423a1a|75 compared
8a590141423a1a|75 compared|8a590141423a1a|75 compared
8a590141423a1a|75 compared|8a590141423a1a|75 compared|3bcf|72 compare
@compared|8bd12bd781c2020100003bd58d8ffefeffff|7e next
3b5424148946688bea|7d finished|8a5c0aff8a140a885c240e8854240f
@next|8b562c23d08b46380fb704503b442418|76 finished|ff4c2410|0f85 candidate
@finished|8b44241c3be8|77 capped|8bc5|@capped|5f5d5b83c414c3'''

_BLOCK = '''53558b6c2414568b7424108b4e7c33c085c957|7e stored_level
807e1c02|75 trees|8bce|call data_type|@trees|8d86100b000050|call build_tree
8d8e1c0b000051|call build_tree|83c4088bc6|call build_bit_length_tree
8b96a01600008b8ea416000083c20a83c10ac1ea03c1e9033bca|77 sizes_ready
eb choose_static|@stored_level|8d4d05|@choose_static|8bd1|@sizes_ready
8d7d043bfa|77 compressed|8b5c241885db|74 compressed
8b7c242057555356|call stored_block|83c410|e9 block_done|@compressed
8b7c24203bca8b8eb4160000|0f85 dynamic|83f90d8d4702|7e static_room
8bd0d3e28b4e08660996b01600008b56148a9eb0160000881c118b56148a9eb1160000
428956148bca8b5608881c118b4e148b96b416000041894e14b1102aca66d3e883c2f3
8996b4160000668986b0160000|eb static_header_done|@static_room
d3e0660986b016000083c103898eb4160000|@static_header_done
abs 68 static_distance|abs 68 static_literal|8bc6|call compress_block
83c408|e9 block_done|@dynamic|83f90d8d5704|7e dynamic_room
8bdad3e38b4e088944242066099eb01600008b5e148a86b01600008804198b4e148a86b1160000
8b5e0841894e148804198b9eb41600008b4614b1102acb66d3ea4083c3f38946148b442420
668996b0160000899eb4160000|eb dynamic_header_done|@dynamic_room
d3e2660996b016000083c103898eb4160000|@dynamic_header_done
8b8e140b000040508b86200b0000405041518bc6|call send_all_trees
8d9680090000528d868c000000508bc6|call compress_block|83c414|@block_done
8bd6|call init_block|85ff5f|74 return|8bc65e5d5b|tail bit_windup
@return|5e5d5bc3'''


def _path(raw, image, sections, imports, address, tape, data=()):
    grammar = _ChildGrammar()
    branches = {'72', '73', '74', '75', '76', '77', '7d', '7e', 'eb', 'e9', '0f84', '0f85'}
    counts = {}
    for token in tape.replace('\n', '|').split('|'):
        words = token.split()
        if not words:
            continue
        kind, *args = words
        if kind.startswith('@'):
            grammar.mark(kind[1:])
        elif kind in branches:
            grammar.branch(kind, args[0], wide=kind.startswith('0f') or kind == 'e9')
        elif kind in ('call', 'tail'):
            role = args[0]
            index = counts.get(role, 0)
            counts[role] = index + 1
            grammar.operand('e8' if kind == 'call' else 'e9', role + str(index) + '_call')
        elif kind == 'abs':
            grammar.operand(args[0], args[1])
        else:
            grammar.code(kind)
    _, row = _bind(raw, image, sections, imports, address, grammar, data=data)
    return row


def _fill_window(raw, image, sections, imports, address):
    row = _path(raw, image, sections, imports, address, _FILL)
    return dict(**row, entry_state_register='EBX', callee_argument_cleanup_bytes=0,
        window_slide_rebases_head_and_previous_unsigned_words_with_zero_floor=True,
        window_free_space_arithmetic_and_position_rebase_wrap_32_bits=True,
        zero_and_UINT32_MAX_free_space_special_paths_bound=True,
        input_count_is_unsigned_min_available_and_free_space=True,
        checksum_only_when_no_header_state_is_zero=True,
        input_pointer_and_total_advanced_by_selected_count=True,
        hash_seed_updated_when_lookahead_at_least_three=True,
        loop_while_lookahead_below262_and_input_available=True, DF_zero_required=True,
        heap_bounds_aliasing_input_counts_and_loop_termination_proven=False)


def _longest_match(raw, image, sections, imports, address):
    row = _path(raw, image, sections, imports, address, _MATCH)
    return dict(**row, entry_state_register='ESI', entry_candidate_register='EAX',
        callee_argument_cleanup_bytes=0, maximum_match_bytes=258,
        good_match_reduces_chain_limit_by_unsigned_shift_two=True,
        eight_byte_comparison_unroll_and_all_exit_branches_bound=True,
        improvement_comparison_is_signed_and_return_cap_is_unsigned=True,
        previous_links_are_unsigned_16_bit_masked_by_window_mask=True,
        chain_decrement_has_no_initial_zero_guard=True,
        actual_heap_bounds_chain_acyclicity_and_loop_termination_proven=False)


def _flush_block(raw, image, sections, imports, address):
    row = _path(raw, image, sections, imports, address, _BLOCK,
        data=(('static_literal', 288 * 4), ('static_distance', 30 * 4)))
    return dict(**row, entry_SP_arguments=dict(state=4, source=8, count=12, eof=16),
        callee_argument_cleanup_bytes=0,
        own_stored_static_dynamic_block_selection_and_bit_header_paths_bound=True,
        compressed_block_sizes_use_unsigned_shift_three_after_add10=True,
        stored_choice_requires_nonnull_source_and_count_plus4_at_most_best_bytes=True,
        equal_compressed_byte_counts_choose_static_tree=True,
        own_init_block_runs_after_all_three_paths=True,
        nonzero_eof_tail_restores_entry_stack_before_own_bit_windup=True,
        native_eof_domain_tree_state_and_pending_capacity_proven=False)


def _reverse_bits(code, length):
    result = 0
    for _ in range(length):
        result = (result << 1) | (code & 1)
        code >>= 1
    return result


def _static_trees(block, descriptors):
    lengths = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
    counts = {n: lengths.count(n) for n in range(1, 10)}
    next_codes, code = {}, 0
    for n in range(1, 10):
        code = (code + counts.get(n - 1, 0)) << 1
        next_codes[n] = code
    literal = []
    for length in lengths:
        literal.append((_reverse_bits(next_codes[length], length), length))
        next_codes[length] += 1
    expected = dict(literal=literal, distance=[(_reverse_bits(n, 5), 5) for n in range(30)])
    tables = {}
    for role, words in expected.items():
        ref = block['data_references']['static_' + role]
        body = bytes.fromhex(ref['bytes'])
        values = list(struct.iter_unpack('<HH', body))
        if ref['address'] != descriptors[role]['words'][0] or values != words:
            raise ValueError('CG 保存压缩的固定树字节没有对应自己的树描述和编码。')
        tables[role] = dict(**ref, symbol_count=len(words), record_bytes=4,
            own_full_reversed_code_and_bit_length_words_static_bound=True)
    if max(tables['literal']['address'], tables['distance']['address']) < min(
        tables['literal']['address'] + 288 * 4, tables['distance']['address'] + 30 * 4):
        raise ValueError('CG 保存压缩的两套固定树不能共用重叠存储。')
    return dict(tables=tables, own_complete_static_tree_contents_bound=True,
        runtime_dynamic_tree_contents_and_native_compressed_bytes_proven=False)


def _one_helper(path, role):
    values = {v for k, v in path['helper_addresses'].items() if k.startswith(role)}
    if len(values) != 1:
        raise ValueError('CG 保存压缩的数据块没有保持自身重复子调用的同一入口。')
    return values.pop()


def bind_native_cg_vm_save_algorithm_children(executable, header, vm, frames):
    raw = bytes(executable)
    parent = bind_native_cg_vm_save_algorithms(raw, header, vm, frames)
    image, sections = _pe_sections(raw)
    imports = _import_slots(raw, image)
    older = parent['layout'] == 'signed-word-legacy'
    children = None
    if older:
        algorithms = parent['native_save_algorithms']
        entries = algorithms['remaining_child_addresses']
        paths = dict(fill_window=_fill_window(raw, image, sections, imports, entries['fill_window']),
            longest_match=_longest_match(raw, image, sections, imports, entries['longest_match']),
            flush_block=_flush_block(raw, image, sections, imports, entries['flush_block']))
        trees = parent['native_vm_save_trees']['native_save_trees']
        own_checksum = _parent(parent, 'fvp-native-cg-vm-restore-inflate/1')['native_restore_inflate']['paths']['checksum']
        if _one_helper(paths['fill_window'], 'checksum') != own_checksum['address']:
            raise ValueError('CG 保存压缩读入没有使用自己的完整原生校验入口。')
        block = paths['flush_block']
        for role in ('stored_block', 'init_block', 'bit_windup'):
            if _one_helper(block, role) != trees['paths'][role]['address']:
                raise ValueError('CG 保存压缩的数据块没有使用自身已接入的写出或清理入口。')
        remaining = {role: _one_helper(block, role) for role in
            ('data_type', 'build_tree', 'build_bit_length_tree', 'compress_block', 'send_all_trees')}
        static = _static_trees(block, trees['descriptors'])
        control = parent['native_vm_save_trees']['native_vm_save_deflate']['native_save_deflate']
        rows = list(paths.values()) + list(algorithms['paths'].values()) + list(trees['paths'].values()) + list(control['paths'].values()) + [own_checksum]
        for i, first in enumerate(rows):
            for second in rows[i + 1:]:
                if max(first['address'], second['address']) < min(first['address'] + first['code_bytes'], second['address'] + second['code_bytes']):
                    raise ValueError('CG 保存压缩读入、匹配与写出范围不能重叠自身其他完整函数。')
        children = dict(paths=paths, static_trees=static, own_checksum=own_checksum,
            own_complete_window_match_and_block_paths_static_bound=True,
            existing_checksum_tree_and_bit_windup_identities_static_bound=True,
            remaining_child_addresses=remaining,
            complete_compression_children_bounds_and_termination_proven=False,
            actual_native_compressed_bytes_file_and_round_trip_proven=False, native_code_executed=False)
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=parent['layout'],
        native_vm_save_algorithms=parent, native_save_algorithm_children=children,
        own_legacy_save_window_match_and_block_paths_static_bound=older,
        same_live_instance_lifetime_proven=False, complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False, initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False, complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
