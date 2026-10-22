"""Own locale-reference and error-string/fallback paths, not runtime effects.

Executable call sites, full explicit bodies, imports and shared identities are
bound. Locale/aliasing, indirect callbacks, exception handlers and termination
remain conditional; native code does not execute and public CG stays closed.
"""
import hashlib

from .native_import_size_discovery import _pe_sections
from .native_cg_vm_application import _import_slots
from .native_cg_vm_heap_paths import _word
from .native_cg_vm_heap_children import _data, _same
from .native_cg_vm_heap_allocations import _AllocationGrammar, _bind
from .native_cg_vm_heap_context import bind_native_cg_vm_heap_context

SCHEMA = 'fvp-native-cg-vm-heap-errors/1'


def _locale_reference(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec53568b35'); g.word('increment_api'); g.code('578b7d0857ffd6')
    for index, field in enumerate((0xb0, 0xb8, 0xb4, 0xc0)):
        g.code('8b87' + field.to_bytes(4, 'little').hex() + '85c0')
        g.branch('74', 'next' + str(index)); g.code('50ffd6'); g.mark('next' + str(index))
    g.code('8d5f50c7450806000000'); g.mark('loop'); g.code('817bf8'); g.word('initial_string')
    g.branch('74', 'wide'); g.code('8b0385c0'); g.branch('74', 'wide'); g.code('50ffd6')
    g.mark('wide'); g.code('837bfc00'); g.branch('74', 'next_category'); g.code('8b430485c0')
    g.branch('74', 'next_category'); g.code('50ffd6'); g.mark('next_category')
    g.code('83c310ff4d08'); g.branch('75', 'loop'); g.code('8b87d400000005b400000050ffd65f5e5b5dc3')
    m, row = _bind(raw, image, sections, imports, address, g, apis=(('increment_api', 'InterlockedIncrement'),))
    return dict(**row, own_initial_category_string_pointer=_data(raw, image, sections, _word(m, 'initial_string'), 1),
                entry_SP_argument_displacements=dict(locale=4), caller_locale_not_locally_null_checked=True,
                locale_reference_incremented_before_children=True,
                optional_reference_field_offsets=[0xb0, 0xb8, 0xb4, 0xc0], category_count=6,
                category_first_record_offset=0x48, category_record_stride=16,
                original_argument_stack_cell_replaced_by_loop_count=True,
                initial_narrow_string_skips_only_its_narrow_reference=True,
                wide_reference_requires_nonzero_category_length_and_reference=True,
                final_owner_pointer_field_offset=0xd4, final_nested_reference_offset=0xb4,
                final_owner_pointer_not_locally_null_checked=True,
                actual_locale_extents_reference_lifetime_overflow_aliases_and_lock_ownership_proven=False)


def _invalid_fallback(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec81ec28030000a1'); g.word('cookie'); g.code('33c58945fc83a5d8fcffff00536a4c8d85dcfcffff6a0050e8')
    g.word('fill_call'); g.code('8d85d8fcffff898528fdffff8d8530fdffff83c40c89852cfdffff')
    g.code('8985e0fdffff898ddcfdffff8995d8fdffff899dd4fdffff89b5d0fdffff89bdccfdffff')
    g.code('668c95f8fdffff668c8decfdffff668c9dc8fdffff668c85c4fdffff668ca5c0fdffff668cadbcfdffff')
    g.code('9c8f85f0fdffff8b45048d4d04c78530fdffff010001008985e8fdffff898df4fdffff8b49fc898de4fdffff')
    g.code('c785d8fcffff170400c0c785dcfcffff010000008985e4fcffffff15'); g.word('debugger_api')
    g.code('6a008bd8ff15'); g.word('set_filter_api'); g.code('8d8528fdffff50ff15'); g.word('filter_api')
    g.code('85c0'); g.branch('75', 'terminate'); g.code('85db'); g.branch('75', 'terminate')
    g.code('6a02e8'); g.word('mode_call'); g.code('59'); g.mark('terminate')
    g.code('68170400c0ff15'); g.word('process_api'); g.code('50ff15'); g.word('terminate_api')
    g.code('8b4dfc33cd5be8'); g.word('cookie_call'); g.code('c9c3')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('cookie',),
                  apis=(('debugger_api', 'IsDebuggerPresent'), ('set_filter_api', 'SetUnhandledExceptionFilter'),
                        ('filter_api', 'UnhandledExceptionFilter'), ('process_api', 'GetCurrentProcess'),
                        ('terminate_api', 'TerminateProcess')))
    return dict(**row, entry_SP_argument_displacements={}, stack_local_bytes=0x328,
                exception_code_and_termination_status=0xc0000417, exception_flags=1,
                own_zero_fill_request_bytes=0x4c, context_flags=0x10001,
                captured_general_registers_are_after_zero_fill_child=True,
                caller_return_address_and_stack_pointer_recorded=True,
                previous_unhandled_filter_not_restored_by_explicit_path=True,
                mode_two_called_only_if_filter_returns_zero_and_no_debugger=True,
                external_termination_result_not_checked=True,
                explicit_return_after_termination_API_returns_and_cookie_child_returns=True,
                actual_exception_context_OS_filters_termination_and_reentry_proven=False)


def _cookie_check(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('3b0d'); g.word('cookie'); g.branch('75', 'failure'); g.code('f3c3')
    g.mark('failure'); g.code('e9'); g.word('failure_call')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('cookie',))
    return dict(**row, cookie_argument_register='ECX', entry_SP_argument_displacements={},
                equality_returns_without_changing_ECX=True,
                mismatch_tails_to_own_failure_without_local_stack_adjustment=True,
                actual_cookie_identity_validity_and_failure_nonreturn_effects_proven=False)


def _concat(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec8b45085333db56573bc3'); g.branch('74', 'invalid')
    g.code('8b7d0c3bfb'); g.branch('77', 'source'); g.mark('invalid'); g.code('e8'); g.word('error_call0')
    g.code('6a165e8930'); g.mark('notify'); g.code('5353535353e8'); g.word('invalid_call')
    g.code('83c4148bc6'); g.branch('eb', 'return'); g.mark('source'); g.code('8b75103bf3')
    g.branch('75', 'scan_begin'); g.mark('clear_invalid'); g.code('8818'); g.branch('eb', 'invalid')
    g.mark('scan_begin'); g.code('8bd0'); g.mark('scan'); g.code('381a'); g.branch('74', 'scanned')
    g.code('424f'); g.branch('75', 'scan'); g.mark('scanned'); g.code('3bfb'); g.branch('74', 'clear_invalid')
    g.mark('copy'); g.code('8a0e880a42463acb'); g.branch('74', 'test'); g.code('4f'); g.branch('75', 'copy')
    g.mark('test'); g.code('3bfb'); g.branch('75', 'success'); g.code('8818e8'); g.word('error_call1')
    g.code('6a225989088bf1'); g.branch('eb', 'notify'); g.mark('success'); g.code('33c0')
    g.mark('return'); g.code('5f5e5b5dc3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, entry_SP_argument_displacements=dict(destination=4, capacity=8, source=12),
                invalid_arguments_errno=22, insufficient_space_errno=34,
                missing_destination_terminator_is_invalid_argument_not_range_error=True,
                valid_destination_reset_first_byte_on_invalid_source_or_failure=True,
                success_copies_source_terminator=True,
                actual_string_bounds_overlap_immutability_and_invalid_handler_effects_proven=False)


def _bounded_copy(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec53568b750833db57395d14'); g.branch('75', 'destination')
    g.code('3bf3'); g.branch('75', 'capacity'); g.code('395d0c'); g.branch('75', 'invalid')
    g.mark('success'); g.code('33c0'); g.mark('return'); g.code('5f5e5b5dc3')
    g.mark('destination'); g.code('3bf3'); g.branch('74', 'invalid'); g.mark('capacity')
    g.code('8b7d0c3bfb'); g.branch('77', 'count'); g.mark('invalid'); g.code('e8'); g.word('error_call0')
    g.code('6a165e8930'); g.mark('notify'); g.code('5353535353e8'); g.word('invalid_call')
    g.code('83c4148bc6'); g.branch('eb', 'return'); g.mark('count'); g.code('395d14')
    g.branch('75', 'source'); g.code('881e'); g.branch('eb', 'success'); g.mark('source')
    g.code('8b55103bd3'); g.branch('75', 'choose'); g.code('881e'); g.branch('eb', 'invalid')
    g.mark('choose'); g.code('837d14ff8bc6'); g.branch('75', 'bounded')
    g.mark('truncate'); g.code('8a0a880840423acb'); g.branch('74', 'test'); g.code('4f')
    g.branch('75', 'truncate'); g.branch('eb', 'test'); g.mark('bounded')
    g.code('8a0a880840423acb'); g.branch('74', 'count_end'); g.code('4f'); g.branch('74', 'count_end')
    g.code('ff4d14'); g.branch('75', 'bounded'); g.mark('count_end'); g.code('395d14')
    g.branch('75', 'test'); g.code('8818'); g.mark('test'); g.code('3bfb'); g.branch('75', 'success')
    g.code('837d14ff'); g.branch('75', 'range_error'); g.code('8b450c6a50885c06ff58')
    g.branch('e9', 'return', True); g.mark('range_error'); g.code('881ee8'); g.word('error_call1')
    g.code('6a225989088bf1'); g.branch('eb', 'notify')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, entry_SP_argument_displacements=dict(destination=4, capacity=8, source=12, count=16),
                null_destination_zero_capacity_zero_count_returns_zero_without_write=True,
                valid_destination_zero_count_resets_first_byte_and_does_not_read_source=True,
                invalid_arguments_errno=22, insufficient_space_errno=34,
                truncate_count_bit_pattern=0xffffffff, truncation_result=80,
                truncate_capacity_exhaustion_terminates_last_destination_byte=True,
                nontruncate_insufficient_capacity_resets_first_byte_and_notifies_handler=True,
                explicit_count_argument_stack_cell_decremented=True,
                actual_string_bounds_overlap_immutability_and_invalid_handler_effects_proven=False)


def _error_mode(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec8b4d085633f63bce'); g.branch('7c', 'invalid'); g.code('83f902')
    g.branch('7e', 'set'); g.code('83f903'); g.branch('75', 'invalid'); g.code('a1'); g.word('mode')
    g.branch('eb', 'return'); g.mark('set'); g.code('a1'); g.word('mode'); g.code('890d'); g.word('mode')
    g.branch('eb', 'return'); g.mark('invalid'); g.code('e8'); g.word('error_call')
    g.code('5656565656c70016000000e8'); g.word('invalid_call'); g.code('83c41483c8ff')
    g.mark('return'); g.code('5e5dc3')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('mode',))
    return dict(**row, entry_SP_argument_displacements=dict(mode=4),
                signed_zero_through_two_set_mode_and_return_previous_value=True,
                mode_three_queries_without_setting=True, invalid_mode_errno=22, invalid_mode_return=0xffffffff,
                mutable_mode_concurrency_and_invalid_handler_effects_proven=False)


def _own_error_paths(raw, image, sections, imports, heap, allocations, context):
    c = heap['native_heap_child_dispatch_paths']
    p = heap['native_vm_heap_paths']['native_heap_instruction_paths']
    error = c['error_output']['helper_addresses']
    paths = dict(locale_reference=_locale_reference(raw, image, sections, imports, context['thread_initialize']['helper_addresses']['locale_reference_call']),
                 invalid_fallback=_invalid_fallback(raw, image, sections, imports, context['invalid_dispatch']['helper_addresses']['fallback_call']),
                 concat=_concat(raw, image, sections, imports, error['concat_call0']),
                 bounded_copy=_bounded_copy(raw, image, sections, imports, error['bounded_copy_call']),
                 error_mode=_error_mode(raw, image, sections, imports, error['mode_call0']))
    paths['cookie_check'] = _cookie_check(raw, image, sections, imports, paths['invalid_fallback']['helper_addresses']['cookie_call'])
    _same(paths['invalid_fallback']['helper_addresses'], dict(fill_call=allocations['zero_fill']['address'], mode_call=context['invalid_mode']['address']))
    for name in ('concat', 'bounded_copy'):
        _same(paths[name]['helper_addresses'], dict(error_call0=p['error_slot']['address'], error_call1=p['error_slot']['address'],
                                                  invalid_call=context['invalid_dispatch']['address']))
    _same(paths['error_mode']['helper_addresses'], dict(error_call=p['error_slot']['address'], invalid_call=context['invalid_dispatch']['address']))
    if error['concat_call1'] != paths['concat']['address'] or error['mode_call1'] != paths['error_mode']['address']:
        raise ValueError('CG 错误输出没有复用自己同一字符串和模式入口。')
    if paths['invalid_fallback']['static_ranges']['cookie'] != paths['cookie_check']['static_ranges']['cookie']:
        raise ValueError('CG 异常参数出口和cookie检查没有使用同一来源的cookie。')
    # The error-output shortcut is not necessarily the setting read/written
    # by its called error-mode function. Preserve the two observed references.
    paths['error_mode']['own_error_output_shortcut_state_range'] = c['error_output']['mode_global_range']
    paths['error_mode']['mode_and_error_output_shortcut_use_distinct_storage'] = (
        paths['error_mode']['static_ranges']['mode']['address'] != c['error_output']['mode_global_range']['address'])
    if paths['locale_reference']['imported_identities']['increment_api'] != context['thread_initialize']['imported_identities']['increment_api']:
        raise ValueError('CG 语言环境引用没有沿用自身线程初始化的原生原子增加导入。')
    rows = list(paths.values()) + list(context.values()) + list(allocations.values()) + list(c.values())
    for index, first in enumerate(rows):
        if any(max(first['address'], second['address']) < min(first['address'] + first['code_bytes'], second['address'] + second['code_bytes']) for second in rows[index + 1:]):
            raise ValueError('CG 错误孩子与已经绑定的自身函数字节重叠。')
    return paths


def bind_native_cg_vm_heap_errors(executable, header, vm, frames):
    raw = bytes(executable)
    parent = bind_native_cg_vm_heap_context(raw, header, vm, frames)
    legacy = parent['layout'] == 'signed-word-legacy'
    errors = None
    if not legacy:
        p = parent['native_vm_heap_allocations']['native_vm_restore_symbols']
        heap = p['native_vm_restore_huffman']['native_vm_restore_blocks']['native_vm_restore_inflate'][
            'native_vm_restore_children']['native_vm_restore']['native_vm_thread_startup']['native_vm_loader']['native_vm_heap_children']
        context = parent['native_heap_context_descendants']['paths']
        allocations = parent['native_vm_heap_allocations']['native_heap_allocation_descendants']['paths']
        image, sections = _pe_sections(raw)
        paths = _own_error_paths(raw, image, sections, _import_slots(raw, image), heap, allocations, context)
        c = heap['native_heap_child_dispatch_paths']
        errors = dict(paths=paths, own_complete_error_descendant_paths_static_bound=True,
                      remaining_error_children=dict(cookie_failure=paths['cookie_check']['helper_addresses']['failure_call'],
                                                    error_show=c['error_output']['helper_addresses']['show_call'],
                                                    preexit=c['external_exit_dispatch']['helper_addresses']['preexit_call'],
                                                    exit_register=c['exit_register']['helper_addresses']['register_call']),
                      actual_locale_aliasing_callbacks_OS_exceptions_and_termination_proven=False, native_code_executed=False)
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=parent['layout'],
                native_vm_heap_context=parent, native_heap_error_descendants=errors,
                own_modern_error_descendant_paths_static_bound=not legacy,
                legacy_external_error_implementation_not_substituted=legacy,
                actual_locale_aliasing_callbacks_OS_exceptions_and_termination_proven=False,
                complete_heap_and_aliasing_effects_proven=False, complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False, same_live_instance_lifetime_proven=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                initial_syscall_vector_count_zero_proven=False, reload_clear_before_header_append_proven=False,
                source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
