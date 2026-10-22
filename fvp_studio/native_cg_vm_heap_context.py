"""Own lock, TLS initialization and invalid-parameter dispatch descendants.

This follows the executable's call sites, imports, shared storage and full
explicit bodies, including its local exception landing pads. Mutable TLS,
locale/callback effects and OS exception dispatch remain unproven. Neither
native code execution nor public CG output is authorized by this binding.
"""
from .engine_patterns import engine_pattern

import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots
from .native_cg_vm_heap_paths import _word, _literal
from .native_cg_vm_heap_children import _data, _same
from .native_cg_vm_heap_allocations import (
    bind_native_cg_vm_heap_allocations, _AllocationGrammar, _bind)

SCHEMA = 'fvp-native-cg-vm-heap-context/1'


def _seh(raw, image, sections, pointer, expected):
    size = 4 * len(expected)
    at = _relocated(raw, image, sections, pointer, executable=False, length=size)
    if list(struct.unpack_from('<' + 'I' * len(expected), raw, at)) != expected:
        raise ValueError('CG 线程上下文没有使用自身完整异常表和自身落点。')
    return dict(**_data(raw, image, sections, pointer, size), words=expected,
                own_table_and_landing_identity_static_bound=True,
                runtime_cookie_OS_dispatch_and_unwind_effects_proven=False)


def _critical_initialize(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('6a1068'); g.word('seh'); g.code('e8'); g.word('frame_call')
    g.code('8365fc00ff750cff7508ff15'); g.word('initialize_api')
    g.code('8945e4'); g.branch('eb', 'finish'); g.mark('filter')
    g.code('8b45ec8b008b008945e033c93d170000c00f94c18bc1c3')
    g.mark('landing'); g.code('8b65e8817de0170000c0'); g.branch('75', 'zero')
    g.code('6a08ff15'); g.word('set_error_api'); g.mark('zero'); g.code('8365e400')
    g.mark('finish'); g.code('c745fcfeffffff8b45e4e8'); g.word('unframe_call'); g.code('c3')
    m, row = _bind(raw, image, sections, imports, address, g,
                  apis=(('initialize_api', 'InitializeCriticalSectionAndSpinCount'),
                        ('set_error_api', 'SetLastError')))
    table = _seh(raw, image, sections, _word(m, 'seh'),
                 [0xfffffffe, 0, 0xffffffd0, 0, 0xfffffffe,
                  address + m.start('filter'), address + m.start('landing')])
    return dict(**row, own_SEH_table=table,
                entry_SP_argument_displacements=dict(critical_section=4, spin_count=8),
                initialize_API_result_returned_on_explicit_normal_path=True,
                filter_matches_only_status_no_memory=0xc0000017,
                matching_exception_landing_sets_last_error=8,
                explicit_exception_landing_result_zero=True,
                actual_lock_initialization_ownership_and_exception_effects_proven=False)


def _tls_resolver(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff56ff35'); g.word('tls_index'); g.code('ff15'); g.word('get_api')
    g.code('8bf085f6'); g.branch('75', 'return'); g.code('ff35'); g.word('encoded_getter')
    g.code('e8'); g.word('decode_call'); g.code('598bf056ff35'); g.word('tls_index')
    g.code('ff15'); g.word('set_api'); g.mark('return'); g.code('8bc65ec3')
    _, row = _bind(raw, image, sections, imports, address, g,
                  ranges=('tls_index', 'encoded_getter'),
                  apis=(('get_api', 'TlsGetValue'), ('set_api', 'TlsSetValue')))
    return dict(**row, entry_SP_argument_displacements={},
                nonzero_cached_TLS_getter_returned_without_decoding=True,
                cache_miss_decodes_own_encoded_getter_and_attempts_TLS_set=True,
                TLS_set_result_not_checked_and_decoded_result_returned=True,
                decoded_getter_can_be_zero=True,
                last_error_not_locally_saved_or_restored=True,
                actual_TLS_contents_getter_identity_ABI_and_reentry_proven=False)


def _thread_initialize(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('6a0c68'); g.word('seh'); g.code('e8'); g.word('frame_call')
    g.code('be'); g.word('module_name'); g.code('56ff15'); g.word('module_api')
    g.code('85c0'); g.branch('75', 'module_ready'); g.code('56e8'); g.word('module_load_call')
    g.code('59'); g.mark('module_ready'); g.code('8945e48b7508c7465c'); g.word('exception_table')
    g.code('33ff47897e1485c0'); g.branch('74', 'defaults'); g.code('68'); g.word('encode_name')
    g.code('508b1d'); g.word('procedure_api'); g.code('ffd38986f801000068'); g.word('decode_name')
    g.code('ff75e4ffd38986fc010000'); g.mark('defaults')
    g.code('897e70c686c800000043c6864b01000043c74668'); g.word('initial_multibyte')
    g.code('6a0de8'); g.word('lock_call0'); g.code('598365fc00ff7668ff15'); g.word('increment_api')
    g.code('c745fcfeffffffe8'); g.word('finally_call0'); g.code('6a0ce8'); g.word('lock_call1')
    g.code('59897dfc8b450c89466c85c0'); g.branch('75', 'locale_ready')
    g.code('a1'); g.word('current_locale'); g.code('89466c'); g.mark('locale_ready')
    g.code('ff766ce8'); g.word('locale_reference_call'); g.code('59c745fcfeffffffe8'); g.word('finally_call1')
    g.code('e8'); g.word('unframe_call'); g.code('c3'); g.mark('unwind0'); g.code('33ff478b7508')
    g.mark('finally0'); g.code('6a0de8'); g.word('unlock_call0'); g.code('59c3')
    g.mark('finally1'); g.code('6a0ce8'); g.word('unlock_call1'); g.code('59c3')
    m, row = _bind(raw, image, sections, imports, address, g,
                  ranges=('initial_multibyte', 'current_locale'),
                  apis=(('module_api', 'GetModuleHandleW'), ('procedure_api', 'GetProcAddress'),
                        ('increment_api', 'InterlockedIncrement')))
    _same(row['helper_addresses'], dict(finally_call0=address + m.start('finally0'),
                                      finally_call1=address + m.start('finally1')))
    table = _seh(raw, image, sections, _word(m, 'seh'),
                 [0xfffffffe, 0, 0xffffffd4, 0, 0xfffffffe, 0,
                  address + m.start('unwind0'), 0xfffffffe, 0, address + m.start('finally1')])
    literals = dict(module=_literal(raw, image, sections, _word(m, 'module_name'), 'KERNEL32.DLL\0'.encode('utf-16-le')),
                    encode=_literal(raw, image, sections, _word(m, 'encode_name'), engine_pattern('native_cg_vm_heap_context:102:83')),
                    decode=_literal(raw, image, sections, _word(m, 'decode_name'), engine_pattern('native_cg_vm_heap_context:103:83')))
    return dict(**row, own_SEH_table=table, own_dynamic_literals=literals,
                own_exception_table_pointer=_data(raw, image, sections, _word(m, 'exception_table'), 1),
                entry_SP_argument_displacements=dict(thread_object=4, inherited_locale=8),
                explicit_pointer_field_offsets=dict(exception_table=0x5c, multibyte=0x68, locale=0x6c,
                                                   encode=0x1f8, decode=0x1fc),
                explicit_one_field_offsets=[0x14, 0x70], explicit_C_byte_offsets=[0xc8, 0x14b],
                dynamic_module_failure_skips_procedure_lookup=True,
                zero_procedure_results_written_without_local_fallback=True,
                multibyte_reference_increment_under_lock_index=13,
                inherited_or_current_locale_reference_under_lock_index=12,
                first_unwind_landing_restores_ESI_and_EDI=True,
                actual_thread_extent_locale_reference_ownership_SEH_and_reentry_proven=False)


def _invalid_dispatch(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558becff35'); g.word('encoded_handler'); g.code('e8'); g.word('decode_call')
    g.code('5985c0'); g.branch('74', 'fallback'); g.code('5dffe0'); g.mark('fallback')
    g.code('6a02e8'); g.word('mode_call'); g.code('595de9'); g.word('fallback_call')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('encoded_handler',))
    return dict(**row, entry_SP_argument_displacements=dict(expression=4, function=8, file=12, line=16, reserved=20),
                decoded_nonzero_handler_tail_preserves_original_five_arguments=True,
                no_handler_calls_mode_with_two_then_tails_to_own_fallback=True,
                dynamic_handler_may_return_mutate_or_reenter=True,
                decoded_handler_identity_ABI_nonreturn_and_fallback_effects_proven=False)


def _invalid_mode(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8325'); g.word('mode'); g.code('00c3')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('mode',))
    return dict(**row, entry_SP_argument_displacements={},
                caller_argument_two_not_read_by_own_body=True,
                own_global_explicitly_cleared_and_EAX_not_locally_assigned=True)


def _own_context_paths(raw, image, sections, imports, heap, allocations):
    c = heap['native_heap_child_dispatch_paths']
    p = heap['native_vm_heap_paths']['native_heap_instruction_paths']
    free = heap['native_vm_heap_paths']['native_vm_member_copy']['native_vm_member_children']['native_vm_members'][
        'native_vm_teardown']['native_vm_cleanup']['native_release_bridge']['native_free_paths']
    decode = p['handler']['native_handler_decode']
    paths = dict(critical_initialize=_critical_initialize(raw, image, sections, imports, c['lock_initialize']['helper_addresses']['critical_initialize_call']),
                 tls_resolver=_tls_resolver(raw, image, sections, imports, c['thread_data']['helper_addresses']['get_resolver_call']),
                 thread_initialize=_thread_initialize(raw, image, sections, imports, c['thread_data']['helper_addresses']['initialize_call']),
                 invalid_dispatch=_invalid_dispatch(raw, image, sections, imports, c['string_copy']['helper_addresses']['invalid_call']))
    paths['invalid_mode'] = _invalid_mode(raw, image, sections, imports, paths['invalid_dispatch']['helper_addresses']['mode_call'])
    for name in ('critical_initialize', 'thread_initialize'):
        _same(paths[name]['helper_addresses'], dict(frame_call=free['helper_addresses']['frame_call'], unframe_call=free['helper_addresses']['unframe_call']))
    for name in ('tls_resolver', 'invalid_dispatch'):
        _same(paths[name]['helper_addresses'], dict(decode_call=decode['address']))
    init = paths['thread_initialize']
    _same(init['helper_addresses'], dict(module_load_call=c['module_wait']['address'],
          lock_call0=p['lock_dispatch']['lock']['address'], lock_call1=p['lock_dispatch']['lock']['address'],
          unlock_call0=p['lock_dispatch']['unlock']['address'], unlock_call1=p['lock_dispatch']['unlock']['address']))
    _same(paths['invalid_dispatch']['helper_addresses'], dict(fallback_call=c['error_output']['helper_addresses']['invalid_call0']))
    if any(c['error_output']['helper_addresses']['invalid_call' + str(i)] != paths['invalid_dispatch']['helper_addresses']['fallback_call'] for i in range(5)):
        raise ValueError('CG 无处理函数的异常出口不是本来源错误输出调用的同一入口。')
    if allocations['calloc_core']['helper_addresses']['invalid_call'] != paths['invalid_dispatch']['address']:
        raise ValueError('CG 清零分配没有使用自身同一异常参数派发入口。')
    if paths['tls_resolver']['static_ranges']['tls_index'] != decode['static_tls_ranges']['tls_index']:
        raise ValueError('CG TLS 函数缓存没有沿用自身解码入口的同一索引。')
    if init['own_dynamic_literals']['module'] != decode['own_dynamic_module_literal'] or init['own_dynamic_literals']['decode'] != decode['own_dynamic_procedure_literal']:
        raise ValueError('CG 线程初始化没有使用自身处理函数解码的同一模块和入口文字。')
    rows = list(paths.values()) + list(c.values()) + list(allocations.values()) + [decode]
    for index, first in enumerate(rows):
        if any(max(first['address'], second['address']) < min(first['address'] + first['code_bytes'], second['address'] + second['code_bytes']) for second in rows[index + 1:]):
            raise ValueError('CG 上下文函数与已绑定自身函数字节重叠。')
    return paths


def bind_native_cg_vm_heap_context(executable, header, vm, frames):
    raw = bytes(executable)
    parent = bind_native_cg_vm_heap_allocations(raw, header, vm, frames)
    legacy = parent['layout'] == 'signed-word-legacy'
    context = None
    if not legacy:
        p = parent['native_vm_restore_symbols']
        heap = p['native_vm_restore_huffman']['native_vm_restore_blocks']['native_vm_restore_inflate'][
            'native_vm_restore_children']['native_vm_restore']['native_vm_thread_startup']['native_vm_loader']['native_vm_heap_children']
        image, sections = _pe_sections(raw)
        paths = _own_context_paths(raw, image, sections, _import_slots(raw, image), heap, parent['native_heap_allocation_descendants']['paths'])
        context = dict(paths=paths, own_complete_context_descendant_paths_static_bound=True,
                       remaining_context_children=dict(locale_reference=paths['thread_initialize']['helper_addresses']['locale_reference_call'],
                                                       invalid_parameter_fallback=paths['invalid_dispatch']['helper_addresses']['fallback_call']),
                       actual_TLS_lock_locale_callback_and_exception_effects_proven=False, native_code_executed=False)
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=parent['layout'],
                native_vm_heap_allocations=parent, native_heap_context_descendants=context,
                own_modern_context_descendant_paths_static_bound=not legacy,
                legacy_external_context_implementation_not_substituted=legacy,
                actual_TLS_lock_locale_callback_and_exception_effects_proven=False,
                actual_heap_allocation_release_and_zeroed_extents_proven=False,
                complete_heap_and_aliasing_effects_proven=False, complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False, initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False, source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
