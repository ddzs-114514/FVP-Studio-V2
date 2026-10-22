"""Own error-display, encoded callback registration and exit descendants.

This follows executable call sites and binds complete explicit bodies, imports,
literals and shared storage. It does not run native code or establish mutable
heap/TLS state, dynamic callback identity, OS exception effects or termination.
"""
from .engine_patterns import engine_pattern

import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots, _writable_image_range
from .native_cg_vm_heap_paths import _word, _literal
from .native_cg_vm_heap_children import _data, _same
from .native_cg_vm_heap_allocations import _AllocationGrammar, _bind
from .native_cg_vm_heap_errors import bind_native_cg_vm_heap_errors

SCHEMA = 'fvp-native-cg-vm-heap-exit/1'


def _encode(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec56ff35'); g.word('tls_index'); g.code('8b35'); g.word('tls_api'); g.code('ffd685c0')
    g.branch('74', 'fallback'); g.code('a1'); g.word('tls_function_index'); g.code('83f8ff')
    g.branch('74', 'fallback'); g.code('50ff35'); g.word('tls_index'); g.code('ffd6ffd085c0')
    g.branch('74', 'fallback'); g.code('8b80f8010000'); g.branch('eb', 'join')
    g.mark('fallback'); g.code('be'); g.word('module_name'); g.code('56ff15'); g.word('module_api')
    g.code('85c0'); g.branch('75', 'module_ready'); g.code('56e8'); g.word('module_load_call')
    g.code('5985c0'); g.branch('74', 'return'); g.mark('module_ready'); g.code('68')
    g.word('procedure_name'); g.code('50ff15'); g.word('procedure_api'); g.mark('join')
    g.code('85c0'); g.branch('74', 'return'); g.code('ff7508ffd0894508')
    g.mark('return'); g.code('8b45085e5dc3')
    m, row = _bind(raw, image, sections, imports, address, g,
                  ranges=('tls_index', 'tls_function_index'),
                  apis=(('tls_api', 'TlsGetValue'), ('module_api', 'GetModuleHandleW'), ('procedure_api', 'GetProcAddress')))
    return dict(**row, own_dynamic_module_literal=_literal(raw, image, sections, _word(m, 'module_name'), 'KERNEL32.DLL\0'.encode('utf-16-le')),
                own_dynamic_procedure_literal=_literal(raw, image, sections, _word(m, 'procedure_name'), engine_pattern('native_cg_vm_heap_exit:37:105')),
                entry_SP_argument_displacements=dict(pointer=4), TLS_object_function_field=0x1f8,
                zero_dynamic_function_returns_original_argument=True,
                encoder_result_written_into_caller_argument_cell=True,
                actual_TLS_object_extent_dynamic_function_identity_ABI_and_reentry_proven=False)


def _encoded_zero(raw, image, sections, imports, address):
    g = _AllocationGrammar(); g.code('6a00e8'); g.word('encode_call'); g.code('59c3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, entry_SP_argument_displacements={}, own_encoder_argument=0,
                actual_encoded_zero_value_and_stability_across_reentry_proven=False)


def _show(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec83ec14535657e8'); g.word('zero_call'); g.code('8365fc00833d'); g.word('message')
    g.code('008bd8'); g.branch('0f85', 'ready', wide=True); g.code('68'); g.word('module_name'); g.code('ff15')
    g.word('load_api'); g.code('8bf885ff'); g.branch('0f84', 'zero', wide=True); g.code('8b35'); g.word('procedure_api')
    g.code('68'); g.word('message_name'); g.code('57ffd685c0'); g.branch('0f84', 'zero', wide=True)
    g.code('50e8'); g.word('encode_call0'); g.code('c70424'); g.word('active_name'); g.code('57a3')
    g.word('message'); g.code('ffd650e8'); g.word('encode_call1'); g.code('c70424'); g.word('popup_name')
    g.code('57a3'); g.word('active'); g.code('ffd650e8'); g.word('encode_call2'); g.code('c70424')
    g.word('object_name'); g.code('57a3'); g.word('popup'); g.code('ffd650e8'); g.word('encode_call3')
    g.code('59a3'); g.word('object_info'); g.code('85c0'); g.branch('74', 'ready'); g.code('68')
    g.word('station_name'); g.code('57ffd650e8'); g.word('encode_call4'); g.code('59a3'); g.word('station')
    g.mark('ready'); g.code('a1'); g.word('station'); g.code('3bc3'); g.branch('74', 'active_path')
    g.code('391d'); g.word('object_info'); g.branch('74', 'active_path'); g.code('50e8')
    g.word('decode_call0'); g.code('ff35'); g.word('object_info'); g.code('8bf0e8'); g.word('decode_call1')
    g.code('59598bf885f6'); g.branch('74', 'active_path'); g.code('85ff'); g.branch('74', 'active_path')
    g.code('ffd685c0'); g.branch('74', 'notification'); g.code('8d4df8516a0c8d4dec516a0150ffd785c0')
    g.branch('74', 'notification'); g.code('f645f401'); g.branch('75', 'active_path')
    g.mark('notification'); g.code('814d1000002000'); g.branch('eb', 'call_message')
    g.mark('active_path'); g.code('a1'); g.word('active'); g.code('3bc3'); g.branch('74', 'call_message')
    g.code('50e8'); g.word('decode_call2'); g.code('5985c0'); g.branch('74', 'call_message')
    g.code('ffd08945fc85c0'); g.branch('74', 'call_message'); g.code('a1'); g.word('popup')
    g.code('3bc3'); g.branch('74', 'call_message'); g.code('50e8'); g.word('decode_call3')
    g.code('5985c0'); g.branch('74', 'call_message'); g.code('ff75fcffd08945fc')
    g.mark('call_message'); g.code('ff35'); g.word('message'); g.code('e8'); g.word('decode_call4')
    g.code('5985c0'); g.branch('74', 'zero'); g.code('ff7510ff750cff7508ff75fcffd0')
    g.branch('eb', 'return'); g.mark('zero'); g.code('33c0'); g.mark('return'); g.code('5f5e5bc9c3')
    m, row = _bind(raw, image, sections, imports, address, g,
                  ranges=('message', 'active', 'popup', 'object_info', 'station'),
                  apis=(('load_api', 'LoadLibraryA'), ('procedure_api', 'GetProcAddress')))
    literals = {n:_literal(raw, image, sections, _word(m, n), value) for n, value in (
        ('module_name', engine_pattern('native_cg_vm_heap_exit:82:24')), ('message_name', engine_pattern('native_cg_vm_heap_exit:82:59')),
        ('active_name', engine_pattern('native_cg_vm_heap_exit:83:24')), ('popup_name', engine_pattern('native_cg_vm_heap_exit:83:62')),
        ('object_name', engine_pattern('native_cg_vm_heap_exit:84:24')), ('station_name', engine_pattern('native_cg_vm_heap_exit:84:74')))}
    return dict(**row, own_dynamic_literals=literals,
                entry_SP_argument_displacements=dict(text=4, caption=8, flags=12), stack_local_bytes=20,
                raw_message_cache_zero_check_is_distinct_from_encoded_zero_sentinel=True,
                dynamic_function_cache_can_remain_partially_initialized_after_failure=True,
                station_flags_request=dict(index=1, buffer_bytes=12, tested_flag_bit=1),
                notification_flag_or_into_original_caller_argument=0x200000,
                missing_module_message_or_decoded_message_returns_zero=True,
                optional_active_and_popup_functions_select_owner_window=True,
                loaded_module_not_released_by_explicit_path=True,
                actual_encoded_cache_window_objects_dynamic_ABI_and_callback_effects_proven=False)


def _preexit(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec68'); g.word('module_name'); g.code('ff15'); g.word('module_api'); g.code('85c0')
    g.branch('74', 'return'); g.code('68'); g.word('procedure_name'); g.code('50ff15'); g.word('procedure_api')
    g.code('85c0'); g.branch('74', 'return'); g.code('ff7508ffd0'); g.mark('return'); g.code('5dc3')
    m, row = _bind(raw, image, sections, imports, address, g,
                  apis=(('module_api', 'GetModuleHandleW'), ('procedure_api', 'GetProcAddress')))
    return dict(**row, own_dynamic_module_literal=_literal(raw, image, sections, _word(m, 'module_name'), 'mscoree.dll\0'.encode('utf-16-le')),
                own_dynamic_procedure_literal=_literal(raw, image, sections, _word(m, 'procedure_name'), engine_pattern('native_cg_vm_heap_exit:105:105')),
                entry_SP_argument_displacements=dict(status=4), module_not_loaded_by_this_body=True,
                missing_module_or_procedure_returns_without_callback=True,
                actual_dynamic_exit_identity_ABI_reentry_and_nonreturn_proven=False)


def _exit_register(raw, image, sections, imports, address):
    g = _AllocationGrammar()
    g.code('8bff558bec51535657ff35'); g.word('begin'); g.code('e8'); g.word('decode_call0')
    g.code('ff35'); g.word('end'); g.code('8bf8897dfce8'); g.word('decode_call1')
    g.code('8bf059593bf7'); g.branch('0f82', 'failure', wide=True); g.code('8bde2bdf8d430483f804')
    g.branch('72', 'failure'); g.code('57e8'); g.word('size_call'); g.code('8bf88d4304593bf8')
    g.branch('73', 'append'); g.code('b8000800003bf8'); g.branch('73', 'cap_ready'); g.code('8bc7')
    g.mark('cap_ready'); g.code('03c73bc7'); g.branch('72', 'fallback'); g.code('50ff75fce8')
    g.word('realloc_call0'); g.code('595985c0'); g.branch('75', 'grown'); g.mark('fallback')
    g.code('8d47103bc7'); g.branch('72', 'failure'); g.code('50ff75fce8'); g.word('realloc_call1')
    g.code('595985c0'); g.branch('74', 'failure'); g.mark('grown'); g.code('c1fb02508d3498e8')
    g.word('encode_call0'); g.code('59a3'); g.word('begin'); g.mark('append'); g.code('ff7508e8')
    g.word('encode_call1'); g.code('890683c60456e8'); g.word('encode_call2'); g.code('59a3')
    g.word('end'); g.code('8b450859'); g.branch('eb', 'return'); g.mark('failure'); g.code('33c0')
    g.mark('return'); g.code('5f5e5bc9c3')
    _, row = _bind(raw, image, sections, imports, address, g, ranges=('begin', 'end'))
    return dict(**row, entry_SP_argument_displacements=dict(callback=4),
                unsigned_end_before_begin_rejected=True, wrapped_used_plus_four_rejected=True,
                first_growth_is_capacity_plus_min_capacity_2048=True,
                fallback_growth_is_capacity_plus_16=True, both_growth_requests_have_unsigned_wrap_guards=True,
                reallocated_end_rebuilt_using_signed_used_bytes_shift_right=2,
                callback_encoded_before_array_write_and_end_publication=True,
                success_returns_original_callback_failure_returns_zero=True,
                actual_heap_extent_pointer_alignment_encoding_aliases_and_publication_proven=False)


def _cookie_failure(raw, image, sections, imports, address):
    g = _AllocationGrammar(); g.code('8bff558bec81ec28030000')
    for opcode, name in (('a3', 'eax'), ('890d', 'ecx'), ('8915', 'edx'), ('891d', 'ebx'), ('8935', 'esi'), ('893d', 'edi'),
                         ('668c15', 'ss'), ('668c0d', 'cs'), ('668c1d', 'ds'), ('668c05', 'es'), ('668c25', 'fs'), ('668c2d', 'gs'),
                         ('9c8f05', 'eflags'), ('8b4500a3', 'ebp'), ('8b4504a3', 'eip'), ('8d4508a3', 'esp')):
        g.code(opcode); g.word(name)
    g.code('8b85e0fcffffc705'); g.word('context'); g.code('01000100a1'); g.word('eip')
    g.code('a3'); g.word('exception_address'); g.code('c705'); g.word('exception_code'); g.code('090400c0c705')
    g.word('exception_flags'); g.code('01000000a1'); g.word('cookie'); g.code('8985d8fcffffa1')
    g.word('cookie_complement'); g.code('8985dcfcffffff15'); g.word('debugger_api'); g.code('a3')
    g.word('debugger_flag'); g.code('6a01e8'); g.word('mode_call0'); g.code('596a00ff15')
    g.word('set_filter_api'); g.code('68'); g.word('exception_pointers'); g.code('ff15'); g.word('filter_api')
    g.code('833d'); g.word('debugger_flag'); g.code('00'); g.branch('75', 'terminate')
    g.code('6a01e8'); g.word('mode_call1'); g.code('59'); g.mark('terminate')
    g.code('68090400c0ff15'); g.word('process_api'); g.code('50ff15'); g.word('terminate_api'); g.code('c9c3')
    m, row = _bind(raw, image, sections, imports, address, g,
                  ranges=('cookie', 'cookie_complement', 'debugger_flag'),
                  apis=(('debugger_api', 'IsDebuggerPresent'), ('set_filter_api', 'SetUnhandledExceptionFilter'),
                        ('filter_api', 'UnhandledExceptionFilter'), ('process_api', 'GetCurrentProcess'), ('terminate_api', 'TerminateProcess')))
    base = _word(m, 'context')
    offsets = dict(gs=0x8c, fs=0x90, es=0x94, ds=0x98, edi=0x9c, esi=0xa0, ebx=0xa4, edx=0xa8,
                   ecx=0xac, eax=0xb0, ebp=0xb4, eip=0xb8, cs=0xbc, eflags=0xc0, esp=0xc4, ss=0xc8)
    if any(_word(m, name) != base + offset for name, offset in offsets.items()):
        raise ValueError('CG cookie失败记录没有引用自身同一上下文的寄存器位置。')
    record = _word(m, 'exception_code')
    if _word(m, 'exception_flags') != record + 4 or _word(m, 'exception_address') != record + 12:
        raise ValueError('CG cookie失败记录没有使用自身同一异常记录。')
    pointer = _word(m, 'exception_pointers')
    at = _relocated(raw, image, sections, pointer, executable=False, length=8)
    if list(struct.unpack_from('<II', raw, at)) != [record, base]:
        raise ValueError('CG cookie失败入口没有沿用自身异常和上下文指针。')
    fields = {n:_writable_image_range(raw, image, sections, _word(m, n), 2 if n in ('gs', 'fs', 'es', 'ds', 'cs', 'ss') else 4)
              for n in tuple(offsets) + ('context', 'exception_code', 'exception_flags', 'exception_address')}
    return dict(**row, own_record_fields=fields, own_exception_pointers=dict(**_data(raw, image, sections, pointer, 8), words=[record, base]),
                own_captured_context_field_offsets=offsets, entry_SP_argument_displacements={}, stack_local_bytes=0x328,
                exception_code_and_termination_status=0xc0000409, exception_flags=1, context_flags=0x10001,
                general_register_capture_precedes_API_and_callback_calls=True,
                caller_frame_return_address_and_stack_pointer_recorded=True,
                unspecified_stack_local_read_before_EAX_overwrite=True,
                cookie_and_complement_copied_to_stack_not_exception_parameters=True,
                shared_debugger_flag_reread_after_exception_filter=True,
                previous_unhandled_filter_not_restored_and_filter_result_ignored=True,
                termination_result_not_checked_and_explicit_return_retained=True,
                actual_context_initialization_concurrency_filters_and_termination_proven=False)


def _own_exit_paths(raw, image, sections, imports, parent, heap, allocations, context):
    remaining = parent['native_heap_error_descendants']['remaining_error_children']
    c = heap['native_heap_child_dispatch_paths']
    decode = heap['native_vm_heap_paths']['native_heap_instruction_paths']['handler']['native_handler_decode']
    paths = dict(show=_show(raw, image, sections, imports, remaining['error_show']),
                 preexit=_preexit(raw, image, sections, imports, remaining['preexit']),
                 exit_register=_exit_register(raw, image, sections, imports, remaining['exit_register']),
                 cookie_failure=_cookie_failure(raw, image, sections, imports, remaining['cookie_failure']))
    paths['encoded_zero'] = _encoded_zero(raw, image, sections, imports, paths['show']['helper_addresses']['zero_call'])
    paths['encode'] = _encode(raw, image, sections, imports, paths['encoded_zero']['helper_addresses']['encode_call'])
    encode = paths['encode']
    _same(encode['helper_addresses'], dict(module_load_call=c['module_wait']['address']))
    _same(paths['show']['helper_addresses'], {**{'encode_call' + str(i):encode['address'] for i in range(5)},
                                            **{'decode_call' + str(i):decode['address'] for i in range(5)}})
    _same(paths['exit_register']['helper_addresses'], {**{'encode_call' + str(i):encode['address'] for i in range(3)},
                                                     **{'decode_call' + str(i):decode['address'] for i in range(2)}})
    helpers = paths['exit_register']['helper_addresses']
    if helpers['realloc_call0'] != helpers['realloc_call1']:
        raise ValueError('CG 退出注册没有复用自身同一重新分配入口。')
    _same(paths['cookie_failure']['helper_addresses'], dict(mode_call0=context['invalid_mode']['address'], mode_call1=context['invalid_mode']['address']))
    if paths['cookie_failure']['static_ranges']['cookie'] != parent['native_heap_error_descendants']['paths']['cookie_check']['static_ranges']['cookie']:
        raise ValueError('CG cookie失败没有使用自身检查的同一cookie。')
    if encode['static_ranges'] != decode['static_tls_ranges']:
        raise ValueError('CG 指针编码与解码没有使用自身同一TLS存储。')
    literals = context['thread_initialize']['own_dynamic_literals']
    if encode['own_dynamic_module_literal'] != literals['module'] or encode['own_dynamic_procedure_literal'] != literals['encode']:
        raise ValueError('CG 指针编码没有沿用自身线程初始化的动态入口名称。')
    for key in ('debugger_api', 'set_filter_api', 'filter_api', 'process_api', 'terminate_api'):
        if paths['cookie_failure']['imported_identities'][key] != parent['native_heap_error_descendants']['paths']['invalid_fallback']['imported_identities'][key]:
            raise ValueError('CG cookie失败没有沿用自身异常参数出口的OS导入。')
    rows = list(paths.values()) + list(parent['native_heap_error_descendants']['paths'].values()) + list(context.values()) + list(allocations.values()) + list(c.values())
    for index, first in enumerate(rows):
        if any(max(first['address'], second['address']) < min(first['address'] + first['code_bytes'], second['address'] + second['code_bytes']) for second in rows[index + 1:]):
            raise ValueError('CG 显示和退出孩子与自身已绑定函数字节重叠。')
    return paths


def bind_native_cg_vm_heap_exit(executable, header, vm, frames):
    raw = bytes(executable); parent = bind_native_cg_vm_heap_errors(raw, header, vm, frames)
    legacy = parent['layout'] == 'signed-word-legacy'; descendants = None
    if not legacy:
        context_parent = parent['native_vm_heap_context']
        allocations_parent = context_parent['native_vm_heap_allocations']
        p = allocations_parent['native_vm_restore_symbols']
        heap = p['native_vm_restore_huffman']['native_vm_restore_blocks']['native_vm_restore_inflate'][
            'native_vm_restore_children']['native_vm_restore']['native_vm_thread_startup']['native_vm_loader']['native_vm_heap_children']
        image, sections = _pe_sections(raw)
        paths = _own_exit_paths(raw, image, sections, _import_slots(raw, image), parent, heap,
                                allocations_parent['native_heap_allocation_descendants']['paths'],
                                context_parent['native_heap_context_descendants']['paths'])
        helpers = paths['exit_register']['helper_addresses']
        descendants = dict(paths=paths, own_complete_display_encoding_cookie_failure_and_exit_paths_static_bound=True,
                           remaining_exit_children=dict(allocation_size=helpers['size_call'], reallocate=helpers['realloc_call0']),
                           dynamic_windows_TLS_callbacks_registration_and_exit_effects_proven=False, native_code_executed=False)
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=parent['layout'],
                native_vm_heap_errors=parent, native_heap_exit_descendants=descendants,
                own_modern_heap_exit_descendant_paths_static_bound=not legacy,
                legacy_external_error_and_exit_implementation_not_substituted=legacy,
                dynamic_windows_TLS_callbacks_registration_and_exit_effects_proven=False,
                complete_heap_and_aliasing_effects_proven=False, complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False, same_live_instance_lifetime_proven=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                initial_syscall_vector_count_zero_proven=False, reload_clear_before_header_append_proven=False,
                source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
