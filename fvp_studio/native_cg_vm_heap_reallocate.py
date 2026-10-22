"""Own allocation-size, retry and small/ordinary heap reallocation paths.

Complete explicit bodies and their own bound children are followed. Mutable
allocator metadata, heap/API/SEH ownership and reentry are not established by
this static binding. It neither executes native code nor enables public CG.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots
from .native_cg_vm_heap_paths import _word
from .native_cg_vm_heap_children import _data, _same
from .native_cg_vm_heap_allocations import _AllocationGrammar, _bind
from .native_cg_vm_heap_exit import bind_native_cg_vm_heap_exit

SCHEMA = 'fvp-native-cg-vm-heap-reallocate/1'


def _scope(raw, image, sections, address, unwind):
    at = _relocated(raw, image, sections, address, executable=False, length=28)
    words = list(struct.unpack_from('<7I', raw, at))
    if words != [0xfffffffe, 0, 0xffffffd0, 0, 0xfffffffe, 0, unwind]:
        raise ValueError('CG 重分配的异常表没有对应自身完整的锁释放落点。')
    return dict(**_data(raw, image, sections, address, 28), words=words,
                own_unwind_landing_identity_static_bound=True, actual_OS_SEH_dispatch_and_lock_ownership_proven=False)


def _size(raw, image, sections, imports, address):
    g = _AllocationGrammar(); g.code('6a1068'); g.word('seh'); g.code('e8'); g.word('frame_call')
    g.code('33c08b5d0833ff3bdf0f95c03bc7'); g.branch('75', 'valid'); g.code('e8'); g.word('error_call')
    g.code('c700160000005757575757e8'); g.word('invalid_call'); g.code('83c41483c8ff'); g.branch('eb', 'return')
    g.mark('valid'); g.code('833d'); g.word('mode'); g.code('03'); g.branch('75', 'ordinary')
    g.code('6a04e8'); g.word('lock_call'); g.code('59897dfc53e8'); g.word('lookup_call')
    g.code('598945e03bc7'); g.branch('74', 'missing'); g.code('8b73fc83ee098975e4'); g.branch('eb', 'finish_lock')
    g.mark('missing'); g.code('8b75e4'); g.mark('finish_lock'); g.code('c745fcfeffffffe8'); g.word('finally_call')
    g.code('397de0'); g.branch('75', 'result'); g.mark('ordinary'); g.code('5357ff35'); g.word('heap')
    g.code('ff15'); g.word('size_api'); g.code('8bf0'); g.mark('result'); g.code('8bc6')
    g.mark('return'); g.code('e8'); g.word('unframe_call'); g.code('c3')
    g.mark('unwind'); g.code('33ff8b5d088b75e4'); g.mark('finally'); g.code('6a04e8'); g.word('unlock_call'); g.code('59c3')
    m, row = _bind(raw, image, sections, imports, address, g, ranges=('mode', 'heap'), apis=(('size_api', 'HeapSize'),))
    if row['helper_addresses']['finally_call'] != address + m.start('finally'):
        raise ValueError('CG 分配尺寸没有使用自身的锁释放收尾。')
    return dict(**row, own_SEH_scope=_scope(raw, image, sections, _word(m, 'seh'), address + m.start('unwind')),
                entry_SP_argument_displacements=dict(pointer=4),
                null_pointer_sets_errno_22_calls_invalid_handler_and_returns_minus_one=True,
                mode3_found_small_block_size_is_header_minus_nine_modulo_32_bits=True,
                missing_small_header_reads_unspecified_local_before_overwriting_with_HeapSize=True,
                ordinary_heap_size_flags=0,
                HeapSize_failure_minus_one_is_not_locally_translated=True,
                actual_block_header_heap_size_and_exception_lifetime_proven=False)


def _retry(raw, image, sections, imports, address):
    g = _AllocationGrammar(); g.code('8bff558bec565733f6'); g.mark('retry')
    g.code('ff750cff7508e8'); g.word('core_call'); g.code('8bf8595985ff'); g.branch('75', 'return')
    g.code('39450c'); g.branch('74', 'return'); g.code('3905'); g.word('timeout'); g.branch('76', 'return')
    g.code('56ff15'); g.word('sleep_api'); g.code('8d86e80300003b05'); g.word('timeout')
    g.branch('76', 'advance'); g.code('83c8ff'); g.mark('advance'); g.code('8bf083f8ff')
    g.branch('75', 'retry'); g.mark('return'); g.code('8bc75f5e5dc3')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('timeout',), apis=(('sleep_api', 'Sleep'),))
    return dict(**row, entry_SP_argument_displacements=dict(pointer=4, size=8),
                failed_zero_size_request_returns_without_retry=True,
                timeout_zero_returns_after_first_failure=True, first_allowed_sleep_argument=0,
                retry_step=1000, timeout_reread_after_each_failure_and_sleep=True,
                retry_arithmetic_wraps_32_bits_and_stops_on_minus_one=True,
                actual_elapsed_time_callback_mutation_and_retry_termination_proven=False)


def _core(raw, image, sections, imports, address):
    g = _AllocationGrammar(); g.code('6a1068'); g.word('seh'); g.code('e8'); g.word('frame_call')
    g.code('8b5d0885db'); g.branch('75', 'pointer'); g.code('ff750ce8'); g.word('allocate_call')
    g.code('59'); g.branch('e9', 'return', True); g.mark('pointer'); g.code('8b750c85f6')
    g.branch('75', 'mode_check'); g.code('53e8'); g.word('free_call'); g.code('59'); g.branch('e9', 'zero', True)
    g.mark('mode_check'); g.code('833d'); g.word('mode'); g.code('03'); g.branch('0f85', 'range', True)
    g.mark('retry_small'); g.code('33ff897de483fee0'); g.branch('0f87', 'oversize', True)
    g.code('6a04e8'); g.word('lock_call'); g.code('59897dfc53e8'); g.word('lookup_call0')
    g.code('598945e03bc7'); g.branch('0f84', 'finish_lock', True)
    g.code('3b35'); g.word('threshold'); g.branch('77', 'small_fallback'); g.code('565350e8')
    g.word('resize_call'); g.code('83c40c85c0'); g.branch('74', 'new_small'); g.code('895de4')
    g.branch('eb', 'small_fallback'); g.mark('new_small'); g.code('56e8'); g.word('small_call')
    g.code('598945e43bc7'); g.branch('74', 'small_fallback'); g.code('8b43fc483bc6')
    g.branch('72', 'copy_small'); g.code('8bc6'); g.mark('copy_small'); g.code('5053ff75e4e8')
    g.word('copy_call0'); g.code('53e8'); g.word('lookup_call1'); g.code('8945e05350e8')
    g.word('small_free_call0'); g.code('83c418'); g.mark('small_fallback'); g.code('397de4')
    g.branch('75', 'finish_lock'); g.code('3bf7'); g.branch('75', 'align_small')
    g.code('33f64689750c'); g.mark('align_small'); g.code('83c60f83e6f089750c5657ff35')
    g.word('heap'); g.code('ff15'); g.word('alloc_api'); g.code('8945e43bc7')
    g.branch('74', 'finish_lock'); g.code('8b43fc483bc6'); g.branch('72', 'copy_ordinary')
    g.code('8bc6'); g.mark('copy_ordinary'); g.code('5053ff75e4e8'); g.word('copy_call1')
    g.code('53ff75e0e8'); g.word('small_free_call1'); g.code('83c414'); g.mark('finish_lock')
    g.code('c745fcfeffffffe8'); g.word('finally_call'); g.code('837de000')
    g.branch('75', 'small_result'); g.code('85f6'); g.branch('75', 'align_ordinary'); g.code('46')
    g.mark('align_ordinary'); g.code('83c60f83e6f089750c56536a00ff35'); g.word('heap')
    g.code('ff15'); g.word('realloc_api'); g.code('8bf8'); g.branch('eb', 'test')
    g.mark('unwind'); g.code('8b750c8b5d08'); g.mark('finally'); g.code('6a04e8'); g.word('unlock_call'); g.code('59c3')
    g.mark('small_result'); g.code('8b7de4'); g.mark('test'); g.code('85ff')
    g.branch('0f85', 'success', True); g.code('393d'); g.word('new_mode'); g.branch('74', 'disabled_small')
    g.code('56e8'); g.word('handler_call0'); g.code('5985c0'); g.branch('0f85', 'retry_small', True)
    g.code('e8'); g.word('error_call0'); g.code('397de0'); g.branch('75', 'errno_twelve')
    g.mark('translate'); g.code('8bf0ff15'); g.word('last_error_api'); g.code('50e8')
    g.word('map_call0'); g.code('598906'); g.branch('eb', 'zero'); g.mark('disabled_small')
    g.code('85ff'); g.branch('0f85', 'success', True); g.code('e8'); g.word('error_call1')
    g.code('397de0'); g.branch('74', 'translate_disabled'); g.code('c7000c000000')
    g.branch('eb', 'success'); g.mark('normal_retry'); g.code('85f6'); g.branch('75', 'normal_request')
    g.code('46'); g.mark('normal_request'); g.code('56536a00ff35'); g.word('heap')
    g.code('ff15'); g.word('realloc_api'); g.code('8bf885ff'); g.branch('75', 'success')
    g.code('3905'); g.word('new_mode'); g.branch('74', 'disabled_ordinary'); g.code('56e8')
    g.word('handler_call1'); g.code('5985c0'); g.branch('74', 'failed_handler')
    g.mark('range'); g.code('83fee0'); g.branch('76', 'normal_retry'); g.mark('oversize')
    g.code('56e8'); g.word('handler_call2'); g.code('59e8'); g.word('error_call2')
    g.mark('errno_twelve'); g.code('c7000c000000'); g.mark('zero'); g.code('33c0')
    g.mark('return'); g.code('e8'); g.word('unframe_call'); g.code('c3')
    g.mark('failed_handler'); g.code('e8'); g.word('error_call3'); g.branch('e9', 'translate', True)
    g.mark('disabled_ordinary'); g.code('85ff'); g.branch('75', 'success'); g.code('e8')
    g.word('error_call4'); g.mark('translate_disabled'); g.code('8bf0ff15'); g.word('last_error_api')
    g.code('50e8'); g.word('map_call1'); g.code('890659'); g.mark('success'); g.code('8bc7')
    g.branch('eb', 'return')
    m, row = _bind(raw, image, sections, imports, address, g, ranges=('mode', 'threshold', 'heap', 'new_mode'),
                  apis=(('alloc_api', 'HeapAlloc'), ('realloc_api', 'HeapReAlloc'), ('last_error_api', 'GetLastError')))
    if row['helper_addresses']['finally_call'] != address + m.start('finally'):
        raise ValueError('CG 重分配没有调用自身的锁释放收尾。')
    return dict(**row, own_SEH_scope=_scope(raw, image, sections, _word(m, 'seh'), address + m.start('unwind')),
                entry_SP_argument_displacements=dict(pointer=4, size=8),
                null_pointer_delegates_to_own_allocator=True, nonnull_pointer_zero_size_frees_then_returns_zero=True,
                nonzero_request_unsigned_limit=0xffffffe0,
                mode3_lookup_and_small_resize_or_move_share_own_lock=True,
                mode3_ordinary_requests_align_sixteen_and_update_caller_size_cell=True,
                copied_count_is_unsigned_min_header_minus_one_and_current_request=True,
                ordinary_mode_zero_request_becomes_one_without_sixteen_alignment=True,
                ordinary_heap_flags=0, oversize_calls_own_handler_even_when_new_mode_disabled=True,
                enabled_handler_retry_rereads_own_mutable_state=True,
                failed_small_pointer_errno=12, failed_ordinary_pointer_uses_own_OS_error_translation=True,
                failed_reallocation_does_not_explicitly_free_old_pointer=True,
                actual_copy_bounds_old_pointer_ownership_heap_callbacks_SEH_and_reentry_proven=False)


def _small_resize(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec83ec0c8b4d088b411053568b7510578b7d0c8bd72b510c83c617c1ea0f8bca69c9040200008d8c0144010000894df48b4ffc83e6f0493bf18d7c39fc8b1f894d10895dfc')
    g.branch('0f8e', 'shrink', True); g.code('f6c301'); g.branch('0f85', 'failure', True)
    g.code('03d93bf3'); g.branch('0f8f', 'failure', True)
    g.code('8b4dfcc1f90449894df883f93f'); g.branch('76', 'grow_bucket'); g.code('6a3f59894df8')
    g.mark('grow_bucket'); g.code('8b5f043b5f08'); g.branch('75', 'grow_unlink')
    g.code('bb0000008083f920'); g.branch('73', 'grow_high')
    g.code('d3eb8b4df88d4c0104f7d3215c9044fe09'); g.branch('75', 'grow_unlink')
    g.code('8b4d082119'); g.branch('eb', 'grow_unlink'); g.mark('grow_high')
    g.code('83c1e0d3eb8b4df88d4c0104f7d3219c90c4000000fe09'); g.branch('75', 'grow_unlink')
    g.code('8b4d08215904'); g.mark('grow_unlink')
    g.code('8b4f088b5f048959048b4f048b7f088979088b4d102bce014dfc837dfc00')
    g.branch('0f8e', 'grow_no_tail', True)
    g.code('8b7dfc8b4d0cc1ff044f8d4c31fc83ff3f'); g.branch('76', 'tail_bucket'); g.code('6a3f5f')
    g.mark('tail_bucket'); g.code('8b5df48d1cfb895d108b5b048959048b5d10895908894b048b5904894b088b59043b5908')
    g.branch('75', 'write_tail'); g.code('8a4c0704884d13fec1884c070483ff20'); g.branch('73', 'tail_high')
    g.code('807d1300'); g.branch('75', 'tail_low_mask'); g.code('8bcfbb00000080d3eb8b4d080919')
    g.mark('tail_low_mask'); g.code('8d4490448bcf'); g.branch('eb', 'tail_mask')
    g.mark('tail_high'); g.code('807d1300'); g.branch('75', 'tail_high_mask')
    g.code('8d4fe0bb00000080d3eb8b4d08095904'); g.mark('tail_high_mask')
    g.code('8d8490c40000008d4fe0'); g.mark('tail_mask'); g.code('ba00000080d3ea0910')
    g.mark('write_tail'); g.code('8b550c8b4dfc8d4432fc8908894c01fc'); g.branch('eb', 'write_grown')
    g.mark('grow_no_tail'); g.code('8b550c'); g.mark('write_grown'); g.code('8d46018942fc894432f8')
    g.branch('e9', 'success', True); g.mark('failure'); g.code('33c0'); g.branch('e9', 'return', True)
    g.mark('shrink'); g.branch('0f8d', 'success', True)
    g.code('8b5d0c2975108d4e01894bfc8d5c33fc8b7510c1fe044e895d0c894bfc83fe3f')
    g.branch('76', 'shrink_bucket'); g.code('6a3f5e'); g.mark('shrink_bucket'); g.code('f645fc01')
    g.branch('0f85', 'shrink_insert', True)
    g.code('8b75fcc1fe044e83fe3f'); g.branch('76', 'neighbor_bucket'); g.code('6a3f5e')
    g.mark('neighbor_bucket'); g.code('8b4f043b4f08'); g.branch('75', 'shrink_unlink')
    g.code('bb0000008083fe20'); g.branch('73', 'shrink_high')
    g.code('8bced3eb8d740604f7d3215c9044fe0e'); g.branch('75', 'shrink_recover')
    g.code('8b4d082119'); g.branch('eb', 'shrink_recover'); g.mark('shrink_high')
    g.code('8d4ee0d3eb8d4c0604f7d3219c90c4000000fe09'); g.branch('75', 'shrink_recover')
    g.code('8b4d08215904'); g.mark('shrink_recover'); g.code('8b5d0c')
    g.mark('shrink_unlink'); g.code('8b4f088b77048971048b77088b4f048971088b75100375fc897510c1fe044e83fe3f')
    g.branch('76', 'shrink_insert'); g.code('6a3f5e'); g.mark('shrink_insert')
    g.code('8b4df48d0cf18b7904894b08897b048959048b4b048959088b4b043b4b08')
    g.branch('75', 'write_shrunk'); g.code('8a4c0604884d0ffec1884c060483fe20')
    g.branch('73', 'insert_high'); g.code('807d0f00'); g.branch('75', 'insert_low_mask')
    g.code('8bcebf00000080d3ef8b4d080939'); g.mark('insert_low_mask'); g.code('8d4490448bce')
    g.branch('eb', 'insert_mask'); g.mark('insert_high'); g.code('807d0f00')
    g.branch('75', 'insert_high_mask'); g.code('8d4ee0bf00000080d3ef8b4d08097904')
    g.mark('insert_high_mask'); g.code('8d8490c40000008d4ee0'); g.mark('insert_mask')
    g.code('ba00000080d3ea0910'); g.mark('write_shrunk'); g.code('8b45108903894418fc')
    g.mark('success'); g.code('33c040'); g.mark('return'); g.code('5f5e5bc9c3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, entry_SP_argument_displacements=dict(header=4, pointer=8, size=12),
                requested_block_bytes_are_size_plus_23_aligned_sixteen_modulo_32_bits=True,
                region_index_unsigned_shift=15, region_metadata_stride=516, free_list_base_offset=0x144,
                signed_size_comparisons_and_signed_bucket_shift_preserved=True, maximum_bucket_index=63,
                growing_requires_free_neighbor_with_enough_combined_block_bytes=True,
                shrinking_coalesces_free_neighbor_and_publishes_tail=True,
                free_list_counts_are_bytes_and_can_wrap=True, shifts_use_x86_low_five_count_bits=True,
                header_and_footer_size_tags_published_on_success=True,
                equal_aligned_size_returns_one_without_block_rewrite=True,
                failure_returns_zero_without_general_allocator_fallback_in_this_body=True,
                caller_pointer_and_size_stack_cells_are_modified=True,
                caller_header_stack_cell_not_written_by_body=True,
                actual_metadata_bounds_aliases_concurrency_and_heap_invariants_proven=False)


def _own_reallocate_paths(raw, image, sections, imports, parent, heap, allocations, context):
    remaining = parent['native_heap_exit_descendants']['remaining_exit_children']
    p = heap['native_vm_heap_paths']['native_heap_instruction_paths']; c = heap['native_heap_child_dispatch_paths']
    free = heap['native_vm_heap_paths']['native_vm_member_copy']['native_vm_member_children']['native_vm_members'][
        'native_vm_teardown']['native_vm_cleanup']['native_release_bridge']['native_free_paths']
    paths = dict(allocation_size=_size(raw, image, sections, imports, remaining['allocation_size']),
                 reallocate_retry=_retry(raw, image, sections, imports, remaining['reallocate']))
    paths['reallocate_core'] = _core(raw, image, sections, imports, paths['reallocate_retry']['helper_addresses']['core_call'])
    paths['small_resize'] = _small_resize(raw, image, sections, imports, paths['reallocate_core']['helper_addresses']['resize_call'])
    common = dict(frame_call=free['helper_addresses']['frame_call'], unframe_call=free['helper_addresses']['unframe_call'],
                  lock_call=p['lock_dispatch']['lock']['address'], unlock_call=p['lock_dispatch']['unlock']['address'])
    _same(paths['allocation_size']['helper_addresses'], dict(**common, error_call=p['error_slot']['address'],
                                                           invalid_call=context['invalid_dispatch']['address'], lookup_call=p['lookup']['address']))
    _same(paths['reallocate_core']['helper_addresses'], dict(**common, allocate_call=p['allocation']['address'], free_call=free['address'],
          lookup_call0=p['lookup']['address'], lookup_call1=p['lookup']['address'], small_call=allocations['small_core']['address'],
          copy_call0=heap['native_vm_heap_paths']['native_vm_member_copy']['native_member_copy_paths']['string']['address'],
          copy_call1=heap['native_vm_heap_paths']['native_vm_member_copy']['native_member_copy_paths']['string']['address'],
          small_free_call0=p['small_release']['address'], small_free_call1=p['small_release']['address'],
          **{'handler_call' + str(i):p['handler']['address'] for i in range(3)},
          **{'error_call' + str(i):p['error_slot']['address'] for i in range(5)},
          map_call0=p['error_map']['address'], map_call1=p['error_map']['address']))
    a = p['allocation']['static_heap_ranges']
    if paths['allocation_size']['static_ranges'] != dict(mode=a['heap_mode'], heap=a['heap_global']):
        raise ValueError('CG 分配尺寸没有使用自身同一模式和普通堆。')
    if paths['reallocate_core']['static_ranges'] != allocations['calloc_core']['static_ranges']:
        raise ValueError('CG 重分配没有使用自身同一堆、阈值与处理设置。')
    if paths['reallocate_retry']['static_ranges'] != allocations['malloc_retry']['static_ranges']:
        raise ValueError('CG 重分配重试没有使用自身同一分配超时设置。')
    rows = list(paths.values()) + list(parent['native_heap_exit_descendants']['paths'].values()) + list(context.values()) + list(allocations.values()) + list(c.values()) + [p['allocation'], p['small_release'], free]
    for index, first in enumerate(rows):
        if any(max(first['address'], second['address']) < min(first['address'] + first['code_bytes'], second['address'] + second['code_bytes']) for second in rows[index + 1:]):
            raise ValueError('CG 重分配与自身已绑定的函数字节重叠。')
    return paths


def bind_native_cg_vm_heap_reallocate(executable, header, vm, frames):
    raw = bytes(executable); parent = bind_native_cg_vm_heap_exit(raw, header, vm, frames)
    legacy = parent['layout'] == 'signed-word-legacy'; descendants = None
    if not legacy:
        context_parent = parent['native_vm_heap_errors']['native_vm_heap_context']
        allocations_parent = context_parent['native_vm_heap_allocations']; p = allocations_parent['native_vm_restore_symbols']
        heap = p['native_vm_restore_huffman']['native_vm_restore_blocks']['native_vm_restore_inflate'][
            'native_vm_restore_children']['native_vm_restore']['native_vm_thread_startup']['native_vm_loader']['native_vm_heap_children']
        image, sections = _pe_sections(raw)
        paths = _own_reallocate_paths(raw, image, sections, _import_slots(raw, image), parent, heap,
                                    allocations_parent['native_heap_allocation_descendants']['paths'], context_parent['native_heap_context_descendants']['paths'])
        descendants = dict(paths=paths, own_complete_reallocation_and_size_paths_static_bound=True,
                           remaining_reallocation_children={}, all_direct_reallocation_children_have_own_static_bodies=True,
                           actual_heap_objects_metadata_aliases_callbacks_SEH_and_reentry_proven=False, native_code_executed=False)
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=parent['layout'],
                native_vm_heap_exit=parent, native_heap_reallocation_descendants=descendants,
                own_modern_heap_reallocation_paths_static_bound=not legacy, legacy_external_heap_reallocation_not_substituted=legacy,
                actual_heap_reallocation_copy_and_old_pointer_ownership_proven=False,
                complete_heap_and_aliasing_effects_proven=False, complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False, same_live_instance_lifetime_proven=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                initial_syscall_vector_count_zero_proven=False, reload_clear_before_header_append_proven=False,
                source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
