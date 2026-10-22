"""Own complete legacy tree leaves; no native execution or live-save grant.

These five leaves contain no absolute relocations, imports or direct calls.
Their full instruction bodies, including branches after early returns, are
matched at the entries actually linked by the own tree-encoding parent.
Input/state domains and lifetime remain separate, unproven obligations.
"""
from .engine_patterns import engine_pattern

import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record
from .native_cg_vm_save_tree_encoding import bind_native_cg_vm_save_tree_encoding

SCHEMA = 'fvp-native-cg-vm-save-tree-children/1'

def _release_pattern_value__CODE():
    return {'pqdownheap': engine_pattern('native_cg_vm_save_tree_children:19:17'), 'gen_bitlen': engine_pattern('native_cg_vm_save_tree_children:25:17'), 'gen_codes': engine_pattern('native_cg_vm_save_tree_children:37:16'), 'scan_tree': engine_pattern('native_cg_vm_save_tree_children:41:16'), 'send_tree': engine_pattern('native_cg_vm_save_tree_children:47:16')}

_BRANCHES = {
    'pqdownheap':((29,6),(36,2),(63,2),(65,2),(81,2),(106,2),(108,2),(124,2),(151,2)),
    'gen_bitlen':((129,6),(163,2),(195,2),(212,2),(230,2),(260,2),(310,6),(322,6),
        (372,2),(382,2),(409,2),(417,6),(427,2),(441,2),(473,2),(486,2),(533,2),(553,2)),
    'gen_codes':((41,2),(47,2),(57,2),(94,2),(105,2)),
    'scan_tree':((28,2),(49,6),(76,2),(80,2),(88,2),(98,2),(102,2),(106,2),
        (123,2),(128,2),(137,2),(152,2),(164,2),(168,2),(180,2),(204,6)),
    'send_tree':((40,2),(54,6),(72,2),(102,2),(106,6),(114,6),(120,2),(151,2),(243,2),
        (276,6),(282,5),(289,6),(297,6),(326,2),(418,2),(473,2),(564,2),(597,2),(682,5),
        (699,5),(718,6),(735,2),(826,2),(859,2),(944,5),(961,5),(977,2),(1068,2),
        (1101,2),(1186,2),(1216,2),(1228,2),(1232,2),(1244,2),(1276,6)),
}


def _leaf(raw,image,sections,address,role):
    body = _release_pattern_value__CODE()[role]
    # send_tree alone needs a bigger bounded window. pqdownheap's two later
    # returns are also mandatory; no first-RET prefix acceptance is used.
    window = 1408 if role == 'send_tree' else 1024
    at,code = _code(raw,image,sections,address,window)
    if code[:len(body)] != body:
        raise ValueError('CG 保存编码的自身树子函数没有完整对应原生指令路径：'+role)
    branches = []
    for site,size in _BRANCHES[role]:
        displacement = struct.unpack_from('<b' if size == 2 else '<i',body,site+size-(1 if size == 2 else 4))[0]
        target = site+size+displacement
        if not 0 <= target < len(body):
            raise ValueError('CG 保存编码树子函数的完整分支必须留在自身函数范围。')
        branches.append(dict(offset=site,instruction_bytes=size,target_offset=target))
    returns = [168,184,195] if role == 'pqdownheap' else [len(body)-1]
    return dict(**_record(address,at,body),bounded_code_window_bytes=window,
        own_complete_explicit_instruction_paths_static_bound=True,
        all_internal_branches=branches,return_offsets=returns,
        first_RET_does_not_end_complete_function=role == 'pqdownheap',
        helper_addresses={},import_calls={},data_references={},
        external_child_effects_and_memory_bounds_proven=False,native_code_executed=False)


def _semantics(role):
    common = dict(callee_argument_cleanup_bytes=0,dynamic_indices_bounds_aliases_and_termination_proven=False)
    if role == 'pqdownheap':
        return dict(**common,entry_state_register='EAX',entry_tree_register='EDI',entry_heap_index_SP_argument=4,
            heap_length_field=0x1448,heap_entries_field=0xb54,depth_entries_field=0x1450,
            frequency_comparison_unsigned_16_bits=True,depth_tiebreak_unsigned_8_bits=True,
            child_equal_frequency_prefers_right_when_right_depth_at_most_left_depth=True,
            parent_equal_frequency_stops_when_parent_depth_at_most_child_depth=True,
            heap_index_and_length_branches_use_signed_comparisons=True,
            all_three_return_paths_store_saved_heap_node=True)
    if role == 'gen_bitlen':
        return dict(**common,entry_state_register='EAX',entry_descriptor_register='ECX',
            bit_length_counts_field=0xb34,bit_length_count_words=16,
            heap_max_field=0x144c,native_heap_limit=573,
            root_length_zero_then_parent_length_plus_one=True,
            descriptor_max_length_clamps_depth_and_counts_overflow=True,
            frequency_length_and_extra_bits_update_own_optimal_and_static_costs=True,
            length_counts_wrap_16_bits_and_costs_wrap_32_bits=True,
            overflow_redistribution_moves_two_codes_and_subtracts_two_overflow=True,
            overflow_repair_then_heap_order_reassignment_and_optimal_cost_adjustment=True,
            extra_bits_and_static_tree_read_from_own_descriptor=True)
    if role == 'gen_codes':
        return dict(**common,entry_tree_register='EDI',entry_max_code_register='EBX',entry_length_counts_register='EDX',
            canonical_next_code_lengths=list(range(1,16)),
            next_code_recurrence_previous_plus_count_then_left_shift=True,
            next_code_storage_and_updates_wrap_16_bits=True,
            zero_length_symbols_skipped=True,negative_max_code_skips_symbols=True,
            symbols_iterated_inclusive_through_max_code=True,
            code_bits_reversed_by_own_complete_inline_loop=True)
    groups = dict(nonzero_first=dict(maximum=7,minimum=4),zero=dict(maximum=138,minimum=3),
        same_nonzero=dict(maximum=6,minimum=3))
    repeat = dict(previous_length=dict(symbol=16,minimum=3,maximum=6,extra_bits=2),
        zero_short=dict(symbol=17,minimum=3,maximum=10,extra_bits=3),
        zero_long=dict(symbol=18,minimum=11,maximum=138,extra_bits=7))
    if role == 'scan_tree':
        return dict(**common,entry_tree_register='EAX',entry_max_code_register='ECX',entry_state_SP_argument=4,
            writes_word_ffff_at_max_code_plus_one_length=True,
            sentinel_write_occurs_before_negative_max_code_exit=True,
            bit_length_tree_field=0xa74,group_thresholds=groups,repeat_codes=repeat,
            all_symbol_frequencies_wrap_16_bits=True)
    return dict(**common,entry_state_register='EAX',entry_tree_register='ECX',entry_max_code_SP_argument=4,
        negative_max_code_skips_symbol_output=True,requires_existing_next_length_sentinel=True,
        writes_sentinel_itself=False,bit_length_tree_field=0xa74,group_thresholds=groups,repeat_codes=repeat,
        bit_buffer_field=0x16b0,valid_bits_field=0x16b4,pending_buffer_field=8,pending_count_field=0x14,
        overflow_emits_two_little_endian_bytes_and_preserves_remaining_bits=True,
        final_partial_bits_remain_in_buffer=True,pending_capacity_and_actual_output_bytes_proven=False)


def bind_native_cg_vm_save_tree_children(executable,header,vm,frames):
    raw = bytes(executable)
    parent = bind_native_cg_vm_save_tree_encoding(raw,header,vm,frames)
    image,sections = _pe_sections(raw)
    older = parent['layout'] == 'signed-word-legacy'
    own = None
    if older:
        encoding = parent['native_save_tree_encoding']
        entries = encoding['remaining_child_addresses']
        if set(entries) != set(_release_pattern_value__CODE()):
            raise ValueError('CG 保存编码的完整自身树子调用集合不一致。')
        paths = {role:dict(**_leaf(raw,image,sections,address,role),**_semantics(role))
            for role,address in entries.items()}
        algorithm_children = parent['native_vm_save_algorithm_children']['native_save_algorithm_children']
        algorithms = parent['native_vm_save_algorithm_children']['native_vm_save_algorithms']
        tree_parent = algorithms['native_vm_save_trees']
        control = tree_parent['native_vm_save_deflate']['native_save_deflate']
        rows = list(paths.values())+list(encoding['paths'].values())+list(algorithm_children['paths'].values())
        rows += list(algorithms['native_save_algorithms']['paths'].values())+list(tree_parent['native_save_trees']['paths'].values())
        rows += list(control['paths'].values())+[algorithm_children['own_checksum']]
        for i,first in enumerate(rows):
            for second in rows[i+1:]:
                if max(first['address'],second['address']) < min(first['address']+first['code_bytes'],second['address']+second['code_bytes']):
                    raise ValueError('CG 保存树子调用完整函数范围不能重叠自身其他保存路径。')
        own = dict(paths=paths,own_complete_heap_bitlength_code_scan_and_send_instruction_paths_static_bound=True,
            own_linked_tree_leaf_entries_bound=True,no_further_direct_tree_leaf_calls=True,
            remaining_child_addresses={},complete_compression_effects_bounds_and_termination_proven=False,
            actual_native_compressed_bytes_file_and_round_trip_proven=False,native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
        native_vm_save_tree_encoding=parent,native_save_tree_children=own,
        own_legacy_complete_save_tree_leaf_instruction_paths_static_bound=older,
        same_live_instance_lifetime_proven=False,complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False,initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False,complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)


_RELEASE_PATTERN_FACTORIES = {'_CODE': _release_pattern_value__CODE}
def __getattr__(name):
    factory = _RELEASE_PATTERN_FACTORIES.get(name)
    if factory is None:
        raise AttributeError(name)
    return factory()
