"""Own heap/TLS/lock/string dispatch children, not live allocator acceptance.

All normal instruction paths are conditional on valid memory and child ABI.
Dynamic handlers, locks, TLS/current heap, exception dispatch and reentry are
not inferred from function names. External-exit return/trap continuations are
explicitly unproven. No native code executes and no public output is granted.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_application import _writable_image_range, _import_slots
from .native_cg_vm_startup import _record
from .native_cg_vm_heap_paths import bind_native_cg_vm_heap_paths, _Grammar, _word, _callee, _import
from .native_cg_vm_member_copy import _copy_helper

SCHEMA = 'fvp-native-cg-vm-heap-children/1'


def _helpers(raw,image,sections,address,m):
    return {n:_callee(raw,image,sections,address,m,n) for n in m.groupdict()
            if '_call' in n and not n.startswith('branch_')}


def _same(helpers,relations):
    if any(helpers[name]!=target for name,target in relations.items()):
        raise ValueError('CG 堆子调用没有沿用本来源同一套分配、锁、错误和复制入口。')


def _data(raw,image,sections,address,size):
    offset=_relocated(raw,image,sections,address,executable=False,length=size)
    value=raw[offset:offset+size]
    return dict(address=address,bytes=size,sha256=hashlib.sha256(value).hexdigest())


def _strlen(raw,image,sections,address):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('8b4c2404f7c103000000');g.branch('74','aligned');g.mark('prefix')
    g.code('8a0183c10184c0');g.branch('74','last');g.code('f7c103000000');g.branch('75','prefix')
    g.code('05000000008da424000000008da42400000000');g.mark('aligned')
    g.code('8b01bafffefe7e03d083f0ff33c283c104a900010181');g.branch('74','aligned')
    g.code('8b41fc84c0');g.branch('74','first');g.code('84e4');g.branch('74','second')
    g.code('a90000ff00');g.branch('74','third');g.code('a9000000ff');g.branch('74','last');g.branch('eb','aligned')
    for label,byte in (('last','ff'),('third','fe'),('second','fd'),('first','fc')):
        g.mark(label);g.code('8d41'+byte+'8b4c24042bc1c3')
    m=g.match(code)
    return dict(**_record(address,at,m[0]),entry_SP_argument_displacements=dict(string=4),callee_argument_cleanup_bytes=0,
                all_four_zero_byte_returns_and_alignment_loop_static_bound=True,
                native_result_is_terminator_minus_original_pointer_modulo_32_bits=True,
                aligned_dword_read_can_extend_three_bytes_past_terminator=True,
                valid_read_bounds_termination_nonwrapping_and_immutability_proven=False,
                complete_explicit_normal_strlen_paths_static_bound=True,native_code_executed=False)


def _string_copy(raw,image,sections,address,slot):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('8bff558bec8b4d085333db56573bcb');g.branch('74','invalid');g.code('8b7d0c3bfb');g.branch('77','source')
    g.mark('invalid');g.code('e8');g.word('error_call0');g.code('6a165e8930');g.mark('notify')
    g.code('5353535353e8');g.word('invalid_call');g.code('83c4148bc6');g.branch('eb','return')
    g.mark('source');g.code('8b75103bf3');g.branch('75','copy');g.code('8819');g.branch('eb','invalid')
    g.mark('copy');g.code('8bd1');g.mark('loop');g.code('8a06880242463ac3');g.branch('74','test')
    g.code('4f');g.branch('75','loop');g.mark('test');g.code('3bfb');g.branch('75','success')
    g.code('8819e8');g.word('error_call1');g.code('6a225989088bf1');g.branch('eb','notify')
    g.mark('success');g.code('33c0');g.mark('return');g.code('5f5e5b5dc3');m=g.match(code)
    helpers=_helpers(raw,image,sections,address,m)
    _same(helpers,dict(error_call0=slot['address'],error_call1=slot['address']))
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,entry_SP_argument_displacements=dict(destination=4,capacity=8,source=12),
                callee_argument_cleanup_bytes=0,invalid_arguments_errno=22,capacity_exhausted_errno=34,
                invalid_source_or_exhaustion_resets_destination_first_byte=True,
                destination_null_or_zero_capacity_not_written_by_explicit_paths=True,
                invalid_parameter_handler_runs_after_error_storage=True,successful_copy_includes_zero_terminator=True,
                allocation_bounds_aliases_and_invalid_handler_effects_complete=False,
                complete_explicit_normal_string_copy_paths_static_bound=True,native_code_executed=False)


def _module_wait(raw,image,sections,imports,address):
    at,code=_code(raw,image,sections,address,128);g=_Grammar()
    g.code('8bff558bec57bfe8030000');g.mark('loop');g.code('57ff15');g.word('sleep_api')
    g.code('ff7508ff15');g.word('module_api');g.code('81c7e803000081ff60ea0000');g.branch('77','return')
    g.code('85c0');g.branch('74','loop');g.mark('return');g.code('5f5dc3');m=g.match(code)
    for key,api in (('sleep_api','Sleep'),('module_api','GetModuleHandleW')):_import(raw,image,sections,imports,m,key,api)
    return dict(**_record(address,at,m[0]),callee_argument_cleanup_bytes=0,
                normal_attempts_maximum=60,requested_wait_milliseconds=list(range(1000,60001,1000)),
                maximum_requested_total_wait_milliseconds=1830000,
                final_attempt_return_occurs_before_result_test=True,
                external_wait_and_module_results_or_elapsed_time_proven=False,
                complete_explicit_normal_module_wait_paths_static_bound=True,native_code_executed=False)


def _error_report(raw,image,sections,imports,address,strlen,copy):
    at,code=_code(raw,image,sections,address,1024);g=_Grammar()
    g.code('8bff558bec5151538b5d08565733f633ff897dfc');g.mark('scan');g.code('3b1cfd');g.word('keys')
    g.branch('74','found');g.code('47897dfc83ff17');g.branch('72','scan');g.mark('found')
    g.code('83ff17');g.branch('0f83','return',True);g.code('6a03e8');g.word('mode_call0')
    g.code('5983f801');g.branch('0f84','console',True);g.code('6a03e8');g.word('mode_call1');g.code('5985c0')
    g.branch('75','message');g.code('833d');g.word('mode_global');g.code('01');g.branch('0f84','console',True)
    g.mark('message');g.code('81fbfc000000');g.branch('0f84','return',True)
    g.code('68');g.word('prefix_text');g.code('bb1403000053bf');g.word('buffer');g.code('57e8');g.word('copy_call0')
    g.code('83c40c85c0');g.branch('74','path');g.code('5656565656e8');g.word('invalid_call0');g.code('83c414')
    g.mark('path');g.code('6804010000be');g.word('path_buffer');g.code('566a00c605');g.word('path_end');g.code('00ff15');g.word('module_filename_api')
    g.code('85c0');g.branch('75','path_ready');g.code('68');g.word('fallback_text');g.code('68fb02000056e8');g.word('copy_call1')
    g.code('83c40c85c0');g.branch('74','path_ready');g.code('33c05050505050e8');g.word('invalid_call1');g.code('83c414')
    g.mark('path_ready');g.code('56e8');g.word('strlen_call0');g.code('405983f83c');g.branch('76','zero')
    g.code('56e8');g.word('strlen_call1');g.code('83ee3b03c66a03b9');g.word('buffer_end');g.code('68');g.word('ellipsis')
    g.code('2bc85150e8');g.word('bounded_copy_call');g.code('83c41485c0');g.branch('74','zero')
    g.code('33f65656565656e8');g.word('invalid_call2');g.code('83c414');g.branch('eb','build')
    g.mark('zero');g.code('33f6');g.mark('build');g.code('68');g.word('separator');g.code('5357e8');g.word('concat_call0')
    g.code('83c40c85c0');g.branch('74','error_text');g.code('5656565656e8');g.word('invalid_call3');g.code('83c414')
    g.mark('error_text');g.code('8b45fcff34c5');g.word('values0');g.code('5357e8');g.word('concat_call1')
    g.code('83c40c85c0');g.branch('74','show');g.code('5656565656e8');g.word('invalid_call4');g.code('83c414')
    g.mark('show');g.code('681020010068');g.word('caption');g.code('57e8');g.word('show_call');g.code('83c40c');g.branch('eb','return')
    g.mark('console');g.code('6af4ff15');g.word('std_handle_api');g.code('8bd83bde');g.branch('74','return')
    g.code('83fbff');g.branch('74','return');g.code('6a008d45f8508d34fd');g.word('values1')
    g.code('ff36e8');g.word('strlen_call2');g.code('5950ff3653ff15');g.word('write_api')
    g.mark('return');g.code('5f5e5bc9c3');m=g.match(code);helpers=_helpers(raw,image,sections,address,m)
    _same(helpers,{**{'strlen_call'+str(i):strlen['address'] for i in range(3)},
                   **{'copy_call'+str(i):copy['address'] for i in range(2)},
                   **{'mode_call1':helpers['mode_call0'],'concat_call1':helpers['concat_call0']},
                   **{'invalid_call'+str(i):helpers['invalid_call0'] for i in range(1,5)}})
    if _word(m,'values0')!=_word(m,'keys')+4 or _word(m,'values1')!=_word(m,'values0'):
        raise ValueError('CG 堆错误输出没有使用自己同一张成对信息表。')
    buffer=_word(m,'buffer');path=_word(m,'path_buffer')
    if path!=buffer+25 or _word(m,'path_end')!=path+260 or _word(m,'buffer_end')!=buffer+0x314:
        raise ValueError('CG 堆错误输出的原生缓冲区关系不完整。')
    for key,api in (('module_filename_api','GetModuleFileNameA'),('std_handle_api','GetStdHandle'),('write_api','WriteFile')):
        _import(raw,image,sections,imports,m,key,api)
    table=_data(raw,image,sections,_word(m,'keys'),23*8)
    offset=_relocated(raw,image,sections,table['address'],executable=False,length=184)
    pairs=[list(struct.unpack_from('<II',raw,offset+8*i)) for i in range(23)]
    literals={n:_data(raw,image,sections,_word(m,n),1) for n in ('prefix_text','fallback_text','ellipsis','separator','caption')}
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,own_error_information_table=table,
                ordered_error_message_pointer_entries=pairs,own_text_pointer_ranges=literals,
                own_message_buffer_range=_writable_image_range(raw,image,sections,buffer,0x314),
                mode_global_range=_writable_image_range(raw,image,sections,_word(m,'mode_global'),4),
                first_matching_error_code_or_no_output=True,console_standard_handle_argument=-12,
                console_invalid_handle_zero_or_minus_one_skips_write=True,
                text_buffer_bounds_at_call_and_child_mutation_reentry_effects_complete=False,
                callee_argument_cleanup_bytes=0,complete_explicit_normal_error_output_paths_static_bound=True,native_code_executed=False)


def _error_preamble(raw,image,sections,address,report):
    at,code=_code(raw,image,sections,address,128);g=_Grammar()
    g.code('6a03e8');g.word('mode_call0');g.code('5983f801');g.branch('74','emit')
    g.code('6a03e8');g.word('mode_call1');g.code('5985c0');g.branch('75','return')
    g.code('833d');g.word('mode_global');g.code('01');g.branch('75','return');g.mark('emit')
    g.code('68fc000000e8');g.word('report_call0');g.code('68ff000000e8');g.word('report_call1')
    g.code('5959');g.mark('return');g.code('c3');m=g.match(code);helpers=_helpers(raw,image,sections,address,m)
    _same(helpers,dict(mode_call0=report['helper_addresses']['mode_call0'],mode_call1=report['helper_addresses']['mode_call0'],
                      report_call0=report['address'],report_call1=report['address']))
    if _word(m,'mode_global')!=report['mode_global_range']['address']:
        raise ValueError('CG 堆错误引言和输出没有使用同一来源模式。')
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,own_mode_global_range=report['mode_global_range'],
                callee_argument_cleanup_bytes=0,complete_explicit_normal_error_preamble_paths_static_bound=True,native_code_executed=False)


def _external_exit(raw,image,sections,imports,address):
    at,code=_code(raw,image,sections,address,64);g=_Grammar()
    g.code('8bff558becff7508e8');g.word('preexit_call');g.code('59ff7508ff15');g.word('exit_api');g.code('cc');m=g.match(code)
    _import(raw,image,sections,imports,m,'exit_api','ExitProcess')
    return dict(**_record(address,at,m[0]),helper_addresses=_helpers(raw,image,sections,address,m),
                imported_exit_identity=imports[_word(m,'exit_api')],INT3_after_external_exit_return=True,
                own_external_exit_and_trap_dispatch_static_bound=True,
                external_exit_nonreturning_and_post_return_trap_continuation_proven=False,native_code_executed=False)


def _lock_error(raw,image,sections,address,preamble,report,decode):
    at,code=_code(raw,image,sections,address,128);g=_Grammar()
    g.code('8bff558bece8');g.word('preamble_call');g.code('ff7508e8');g.word('report_call')
    g.code('ff35');g.word('exit_handler');g.code('e8');g.word('decode_call');g.code('68ff000000ffd083c40c5dc3');m=g.match(code)
    helpers=_helpers(raw,image,sections,address,m)
    _same(helpers,dict(preamble_call=preamble['address'],report_call=report['address'],decode_call=decode['address']))
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,
                encoded_exit_handler_range=_writable_image_range(raw,image,sections,_word(m,'exit_handler'),4),
                cdecl_dynamic_handler_argument=255,callee_argument_cleanup_bytes=0,
                dynamic_handler_can_return_or_mutate_or_reenter=True,
                decoded_handler_identity_and_exception_nonreturn_effects_proven=False,
                complete_explicit_normal_lock_failure_paths_static_bound=True,native_code_executed=False)


def _small_allocate(raw,image,sections,address,p,free):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('6a0c68');g.word('seh');g.code('e8');g.word('frame_call');g.code('8365e4008b75083b35');g.word('threshold')
    g.branch('77','result');g.code('6a04e8');g.word('lock_call');g.code('598365fc0056e8');g.word('small_call')
    g.code('598945e4c745fcfeffffffe8');g.word('finally_call');g.mark('result')
    g.code('8b45e4e8');g.word('unframe_call');g.code('c3');g.mark('finally');g.code('6a04e8');g.word('unlock_call');g.code('59c3');m=g.match(code)
    helpers=_helpers(raw,image,sections,address,m)
    _same(helpers,dict(frame_call=free['helper_addresses']['frame_call'],unframe_call=free['helper_addresses']['unframe_call'],
                      lock_call=p['lock_dispatch']['lock']['address'],unlock_call=p['lock_dispatch']['unlock']['address'],
                      finally_call=address+m.start('finally')))
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,own_SEH_data_range=_data(raw,image,sections,_word(m,'seh'),1),
                own_small_request_threshold_range=_writable_image_range(raw,image,sections,_word(m,'threshold'),4),
                local_result_initial_zero=True,large_request_returns_zero=True,heap_lock_index=4,
                callee_argument_cleanup_bytes=0,complete_explicit_normal_small_allocate_wrapper_paths_static_bound=True,
                small_allocator_bounds_SEH_concurrency_and_effects_complete=False,native_code_executed=False)


def _thread_data(raw,image,sections,imports,address,p,free):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('8bff5657ff15');g.word('last_error_api');g.code('ff35');g.word('tls_index0');g.code('8bf8e8');g.word('get_resolver_call')
    g.code('ffd08bf085f6');g.branch('75','return');g.code('68140200006a01e8');g.word('calloc_call')
    g.code('8bf0595985f6');g.branch('74','return');g.code('56ff35');g.word('tls_index1');g.code('ff35');g.word('tls_setter')
    g.code('e8');g.word('decode_call');g.code('59ffd085c0');g.branch('74','release');g.code('6a0056e8');g.word('initialize_call')
    g.code('5959ff15');g.word('thread_id_api');g.code('834e04ff8906');g.branch('eb','return')
    g.mark('release');g.code('56e8');g.word('free_call');g.code('5933f6');g.mark('return')
    g.code('57ff15');g.word('set_error_api');g.code('5f8bc65ec3');m=g.match(code);helpers=_helpers(raw,image,sections,address,m)
    decode=p['handler']['native_handler_decode']
    _same(helpers,dict(decode_call=decode['address'],free_call=free['address']))
    if _word(m,'tls_index0')!=_word(m,'tls_index1') or _word(m,'tls_index0')!=decode['static_tls_ranges']['tls_function_index']['address']:
        raise ValueError('CG 错误线程数据没有使用本来源同一 TLS 索引。')
    for key,api in (('last_error_api','GetLastError'),('thread_id_api','GetCurrentThreadId'),('set_error_api','SetLastError')):
        _import(raw,image,sections,imports,m,key,api)
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,
                own_tls_setter_range=_writable_image_range(raw,image,sections,_word(m,'tls_setter'),4),
                own_TLS_index_range=decode['static_tls_ranges']['tls_function_index'],calloc_request=dict(count=1,size=0x214),
                reuses_nonnull_TLS_object_without_allocating=True,setter_failure_frees_new_object_and_returns_zero=True,
                last_error_saved_and_restored_on_explicit_normal_paths=True,
                initialized_thread_id_and_minus_one_fields=[0,4],callee_argument_cleanup_bytes=0,
                actual_TLS_identity_allocation_extent_and_indirect_ABI_or_reentry_proven=False,
                complete_explicit_normal_thread_data_paths_static_bound=True,native_code_executed=False)


def _lock_initialize(raw,image,sections,address,p,free,preamble,report,exit_):
    at,code=_code(raw,image,sections,address,512);g=_Grammar()
    g.code('6a0c68');g.word('seh');g.code('e8');g.word('frame_call');g.code('33ff47897de433db391d');g.word('heap_global')
    g.branch('75','ready');g.code('e8');g.word('preamble_call');g.code('6a1ee8');g.word('report_call')
    g.code('68ff000000e8');g.word('exit_call');g.code('5959');g.mark('ready')
    g.code('8b75088d34f5');g.word('table');g.code('391e');g.branch('74','allocate');g.code('8bc7');g.branch('eb','return')
    g.mark('allocate');g.code('6a18e8');g.word('allocate_call');g.code('598bf83bfb');g.branch('75','lock')
    g.code('e8');g.word('error_call0');g.code('c7000c00000033c0');g.branch('eb','return')
    g.mark('lock');g.code('6a0ae8');g.word('lock_call');g.code('59895dfc391e');g.branch('75','already_published')
    g.code('68a00f000057e8');g.word('critical_initialize_call');g.code('595985c0');g.branch('75','publish')
    g.code('57e8');g.word('free_call0');g.code('59e8');g.word('error_call1');g.code('c7000c000000895de4');g.branch('eb','unlock')
    g.mark('publish');g.code('893e');g.branch('eb','unlock');g.mark('already_published')
    g.code('57e8');g.word('free_call1');g.code('59');g.mark('unlock');g.code('c745fcfeffffffe8');g.word('finally_call')
    g.code('8b45e4');g.mark('return');g.code('e8');g.word('unframe_call');g.code('c3');g.mark('finally')
    g.code('6a0ae8');g.word('unlock_call');g.code('59c3');m=g.match(code);helpers=_helpers(raw,image,sections,address,m)
    _same(helpers,dict(frame_call=free['helper_addresses']['frame_call'],unframe_call=free['helper_addresses']['unframe_call'],
                      preamble_call=preamble['address'],report_call=report['address'],exit_call=exit_['address'],
                      error_call0=p['error_slot']['address'],error_call1=p['error_slot']['address'],
                      free_call0=free['address'],free_call1=free['address'],lock_call=p['lock_dispatch']['lock']['address'],
                      unlock_call=p['lock_dispatch']['unlock']['address'],finally_call=address+m.start('finally')))
    if _word(m,'heap_global')!=free['static_heap_ranges']['heap_global']['address'] or _word(m,'table')+32!=p['lock_dispatch']['own_heap_lock_pointer_storage']['address']:
        raise ValueError('CG 锁初始化没有沿用自己的普通堆和同一锁表。')
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,own_SEH_data_range=_data(raw,image,sections,_word(m,'seh'),1),
                management_lock_pointer_range=_writable_image_range(raw,image,sections,_word(m,'table')+10*8,4),
                allocation_request_bytes=24,critical_section_spin_parameter=4000,management_lock_index=10,
                nonnull_existing_lock_skips_allocate=True,publication_race_frees_unpublished_new_lock=True,
                initialize_failure_frees_new_lock_stores_12_and_returns_zero=True,
                callee_argument_cleanup_bytes=0,complete_explicit_normal_lock_initialize_paths_static_bound=True,
                allocator_critical_section_bounds_recursive_initialization_and_SEH_effects_complete=False,native_code_executed=False)


def _lock_wrapper(raw,image,sections,address,target):
    at,code=_code(raw,image,sections,address,32);g=_Grammar();g.code('6a08e8');g.word('lock_call');g.code('59c3');m=g.match(code)
    _same(_helpers(raw,image,sections,address,m),dict(lock_call=target))
    return dict(**_record(address,at,m[0]),lock_target=target,lock_index=8,callee_argument_cleanup_bytes=0)


def _exit_register(raw,image,sections,address,p,free):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('6a0c68');g.word('seh');g.code('e8');g.word('frame_call');g.code('e8');g.word('enter_call')
    g.code('8365fc00ff7508e8');g.word('register_call');g.code('598945e4c745fcfeffffffe8');g.word('finally_call')
    g.code('8b45e4e8');g.word('unframe_call');g.code('c3');g.mark('finally');g.code('e8');g.word('leave_call');g.code('c3');m=g.match(code)
    helpers=_helpers(raw,image,sections,address,m)
    _same(helpers,dict(frame_call=free['helper_addresses']['frame_call'],unframe_call=free['helper_addresses']['unframe_call'],
                      finally_call=address+m.start('finally')))
    enter=_lock_wrapper(raw,image,sections,helpers['enter_call'],p['lock_dispatch']['lock']['address'])
    leave=_lock_wrapper(raw,image,sections,helpers['leave_call'],p['lock_dispatch']['unlock']['address'])
    table=p['lock_dispatch']['own_heap_lock_pointer_storage']['address']-32
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,native_enter_wrapper=enter,native_leave_wrapper=leave,
                own_SEH_data_range=_data(raw,image,sections,_word(m,'seh'),1),
                exit_lock_pointer_range=_writable_image_range(raw,image,sections,table+8*8,4),
                callee_argument_cleanup_bytes=0,callback_registration_result_preserved=True,
                callback_array_mutation_SEH_lifetime_and_execution_effects_complete=False,
                complete_explicit_normal_exit_register_paths_static_bound=True,native_code_executed=False)


def bind_native_cg_vm_heap_children(executable,header,vm,frames):
    raw=bytes(executable);image,sections=_pe_sections(raw);imports=_import_slots(raw,image)
    heap=bind_native_cg_vm_heap_paths(raw,header,vm,frames);p=heap['native_heap_instruction_paths']
    older=heap['layout']=='signed-word-legacy';children={}
    if not older:
        cleanup=heap['native_vm_member_copy']['native_vm_member_children']['native_vm_members']['native_vm_teardown']['native_vm_cleanup']
        free=cleanup['native_release_bridge']['native_free_paths'];a=p['allocation']['helper_addresses']
        strlen=_strlen(raw,image,sections,p['error_copy']['native_base_copy']['helper_addresses']['strlen_call'])
        copy=_string_copy(raw,image,sections,p['error_copy']['native_base_copy']['helper_addresses']['string_copy_call'],p['error_slot'])
        report=_error_report(raw,image,sections,imports,a['uninitialized_call1'],strlen,copy)
        preamble=_error_preamble(raw,image,sections,a['uninitialized_call0'],report)
        exit_=_external_exit(raw,image,sections,imports,a['uninitialized_call2'])
        children=dict(strlen=strlen,string_copy=copy,error_output=report,error_preamble=preamble,external_exit_dispatch=exit_,
                      small_allocate=_small_allocate(raw,image,sections,a['small_allocate_call'],p,free),
                      thread_data=_thread_data(raw,image,sections,imports,p['error_slot']['helper_addresses']['thread_data_call'],p,free),
                      lock_initialize=_lock_initialize(raw,image,sections,p['lock_dispatch']['lock']['helper_addresses']['initialize_call'],p,free,preamble,report,exit_),
                      lock_failure=_lock_error(raw,image,sections,p['lock_dispatch']['lock']['helper_addresses']['failure_call'],preamble,report,p['handler']['native_handler_decode']),
                      header_move=_copy_helper(raw,image,sections,p['small_release']['helper_addresses']['move_call']),
                      module_wait=_module_wait(raw,image,sections,imports,p['handler']['native_handler_decode']['helper_addresses']['module_load_call']),
                      exit_register=_exit_register(raw,image,sections,p['exit_registration']['helper_addresses']['register_call'],p,free))
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=heap['layout'],native_vm_heap_paths=heap,
                native_heap_child_dispatch_paths=children,own_heap_child_dispatch_instruction_paths_static_bound=True,
                own_modern_heap_child_normal_instruction_paths_static_bound=not older,
                legacy_external_runtime_implementation_not_substituted=older,
                native_heap_buffer_TLS_and_lock_bounds_proven=False,complete_member_child_and_heap_effects_bound=False,
                native_allocator_and_free_heap_effects_complete=False,same_live_instance_lifetime_proven=False,
                initial_syscall_vector_count_zero_proven=False,reload_clear_before_header_append_proven=False,
                source_header_arity_to_native_descriptor_bound=False,complete_allocation_exception_and_reentry_effects_bound=False,
                native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
