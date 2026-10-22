"""Own complete allocation/release dispatch paths, not live heap ownership.

Native code is not executed. Metadata bounds, lock initialization, external
APIs, callback/reentry, exceptions and the heap at this invocation remain
conditions. Explicit normal paths do not grant reload or public CG output.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_application import _writable_image_range, _import_slots
from .native_cg_vm_startup import _record, _relative
from .native_cg_vm_instance import _w, _branch, _api
from .native_cg_vm_member_copy import bind_native_cg_vm_member_copy, _Grammar as _MemberGrammar

SCHEMA = 'fvp-native-cg-vm-heap-paths/1'
MASK = 2**32 - 1


class _Grammar(_MemberGrammar):
    def match(self, code):
        try:
            return super().match(code)
        except ValueError as error:
            raise ValueError('CG 堆调用链没有完整覆盖自己的分支、子调用和正常返回。') from error


def _word(m, name):
    return struct.unpack('<I', m[name])[0]


def _callee(raw, image, sections, address, m, name):
    target = _relative(address, m, name)
    _relocated(raw, image, sections, target, executable=True)
    return target


def _import(raw, image, sections, imports, m, key, name, dll='kernel32.dll'):
    _api(raw, image, sections, {k:(v['dll'],v['name']) for k,v in imports.items() if v['ordinal'] is None},
         m, key, (dll, name))


def _native_heap_request(size, mode):
    """Matched request arithmetic, not an allocation or success guarantee."""
    if type(size) is not int or not 0 <= size <= MASK or type(mode) is not int or not 0 <= mode <= MASK:
        raise ValueError('CG 堆参数必须是实际32位位模式。')
    if size > 0xffffffe0:
        return None
    return max(size, 1) if mode == 1 else (max(size, 1) + 15) & 0xfffffff0


def _native_error_result(error, entries):
    if type(error) is not int or not 0 <= error <= MASK:
        raise ValueError('CG 原生错误号必须是实际32位位模式。')
    for original, result in entries:
        if original == error:
            return result
    if ((error - 19) & MASK) <= 17:
        return 13
    return 8 if ((error - 188) & MASK) <= 14 else 22


def _legacy_import(raw, image, sections, imports, address, name):
    at, code = _code(raw, image, sections, address, 16)
    m = re.match(engine_pattern('native_cg_vm_heap_paths:68:17')+_w('api'), code, re.DOTALL)
    if m is None:
        raise ValueError('CG 旧版堆入口缺少完整的本来源导入跳转。')
    _import(raw,image,sections,imports,m,'api',name,'msvcr71.dll')
    return dict(**_record(address,at,m[0]), kind='own-external-runtime-import',
                import_identity=imports[_word(m,'api')], entry_SP_argument_displacements=dict(argument=4),
                tail_preserves_original_stack_and_argument_static_bound=True,
                external_implementation_and_heap_effects_bound=False, native_code_executed=False)


def _handler(raw,image,sections,imports,address):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('8bff558becff35');g.word('handler_global');g.code('e8');g.word('decode_call')
    g.code('5985c0');g.branch('74','zero');g.code('ff7508ffd05985c0');g.branch('74','zero')
    g.code('33c0405dc3');g.mark('zero');g.code('33c05dc3');m=g.match(code)
    decode = _callee(raw,image,sections,address,m,'decode_call')
    return dict(**_record(address,at,m[0]), handler_pointer_storage=_writable_image_range(raw,image,sections,_word(m,'handler_global'),4),
                helper_addresses=dict(decode_call=decode), native_handler_decode=_handler_decode(raw,image,sections,imports,decode),
                entry_SP_argument_displacements=dict(size=4), callee_argument_cleanup_bytes=0,
                conditional_boolean_result='one iff decoded handler nonzero and its cdecl(size) result nonzero; otherwise zero',
                dynamic_handler_cdecl_argument_cleanup_bytes=0,
                decoded_target_identity_and_effects_proven=False, callback_may_mutate_or_reenter_heap=True,
                complete_explicit_normal_handler_paths_static_bound=True, native_code_executed=False)


def _error_slot(raw,image,sections,address):
    at,code=_code(raw,image,sections,address,128);g=_Grammar()
    g.code('e8');g.word('thread_data_call');g.code('85c0');g.branch('75','thread')
    g.code('b8');g.word('fallback');g.code('c3');g.mark('thread');g.code('83c008c3');m=g.match(code)
    return dict(**_record(address,at,m[0]),helper_addresses=dict(thread_data_call=_callee(raw,image,sections,address,m,'thread_data_call')),
                static_fallback_range=_writable_image_range(raw,image,sections,_word(m,'fallback'),4),
                thread_field_offset=8, callee_argument_cleanup_bytes=0,
                thread_allocation_extent_and_current_identity_proven=False,
                complete_explicit_normal_error_slot_paths_static_bound=True,native_code_executed=False)


def _error_map(raw,image,sections,address):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('8bff558bec8b450833c9');g.mark('scan');g.code('3b04cd');g.word('keys')
    g.branch('74','matched');g.code('4183f92d');g.branch('72','scan')
    g.code('8d48ed83f911');g.branch('77','fallback');g.code('6a0d585dc3')
    g.mark('matched');g.code('8b04cd');g.word('values');g.code('5dc3');g.mark('fallback')
    g.code('0544ffffff6a0e593bc81bc023c183c0085dc3');m=g.match(code)
    address_table=_word(m,'keys')
    if _word(m,'values')!=address_table+4:
        raise ValueError('CG 错误映射没有使用自己的成对表。')
    offset=_relocated(raw,image,sections,address_table,executable=False,length=45*8)
    table=raw[offset:offset+360];entries=[list(struct.unpack_from('<II',table,i*8)) for i in range(45)]
    return dict(**_record(address,at,m[0]),ordered_error_mapping_entries=entries,
                own_table_range=dict(address=address_table,bytes=360,sha256=hashlib.sha256(table).hexdigest()),
                lookup_is_first_matching_entry=True,unmatched_unsigned_ranges=[[19,36,13],[188,202,8]],unmatched_other_result=22,
                callee_argument_cleanup_bytes=0,table_contents_at_this_call_immutable_proven=False,
                complete_explicit_normal_error_mapping_paths_static_bound=True,native_code_executed=False)


def _malloc(raw,image,sections,imports,address,handler,slot,release):
    at,code=_code(raw,image,sections,address,512);g=_Grammar()
    g.code('8bff558bec568b750883fee0');g.branch('0f87','oversize',True)
    g.code('53578b3d');g.word('heap_alloc_api');g.mark('retry');g.code('833d');g.word('heap_global');g.code('00')
    g.branch('75','ready');g.code('e8');g.word('uninitialized_call0');g.code('6a1ee8');g.word('uninitialized_call1')
    g.code('68ff000000e8');g.word('uninitialized_call2');g.code('5959');g.mark('ready')
    g.code('a1');g.word('heap_mode');g.code('83f801');g.branch('75','small_mode');g.code('85f6');g.branch('74','one')
    g.code('8bc6');g.branch('eb','push_size');g.mark('one');g.code('33c040');g.mark('push_size');g.code('50');g.branch('eb','heap')
    g.mark('small_mode');g.code('83f803');g.branch('75','aligned');g.code('56e8');g.word('small_allocate_call')
    g.code('5985c0');g.branch('75','result');g.mark('aligned');g.code('85f6');g.branch('75','align');g.code('46')
    g.mark('align');g.code('83c60f83e6f056');g.mark('heap');g.code('6a00ff35');g.word('heap_global_again');g.code('ffd7')
    g.mark('result');g.code('8bd885db');g.branch('75','done');g.code('6a0c5e3905');g.word('new_mode');g.branch('74','set_error')
    g.code('ff7508e8');g.word('handler_call0');g.code('5985c0');g.branch('74','last_error')
    g.code('8b7508');g.branch('e9','retry',True);g.mark('set_error');g.code('e8');g.word('error_call0');g.code('8930')
    g.mark('last_error');g.code('e8');g.word('error_call1');g.code('8930');g.mark('done');g.code('5f8bc35b');g.branch('eb','return')
    g.mark('oversize');g.code('56e8');g.word('handler_call1');g.code('59e8');g.word('error_call2')
    g.code('c7000c00000033c0');g.mark('return');g.code('5e5dc3');m=g.match(code)
    _import(raw,image,sections,imports,m,'heap_alloc_api','HeapAlloc')
    helpers={n:_callee(raw,image,sections,address,m,n) for n in m.groupdict() if n.endswith('_call') or n.startswith(('error_call','handler_call','uninitialized_call'))}
    if any(helpers['handler_call'+str(i)]!=handler['address'] for i in range(2)) or any(helpers['error_call'+str(i)]!=slot['address'] for i in range(3)):
        raise ValueError('CG 堆分配没有复用自己的原生处理函数和错误存储。')
    if _word(m,'heap_global_again')!=_word(m,'heap_global') or _word(m,'heap_global')!=release['static_heap_ranges']['heap_global']['address']:
        raise ValueError('CG 堆分配和释放没有使用同一来源的堆。')
    if _word(m,'heap_mode')!=release['static_heap_ranges']['heap_mode']['address']:
        raise ValueError('CG 堆分配和释放没有使用同一来源的模式。')
    ranges={n:_writable_image_range(raw,image,sections,_word(m,n),4) for n in ('heap_global','heap_mode','new_mode')}
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,static_heap_ranges=ranges,
                heap_alloc_import_identity=imports[_word(m,'heap_alloc_api')],entry_SP_argument_displacements=dict(size=4),
                callee_argument_cleanup_bytes=0,unsigned_maximum_request_size=0xffffffe0,
                mode1_normal_request='max(size,1)',other_normal_heap_request='align_up(max(size,1),16)',
                mode3_small_allocator_runs_before_normal_heap_fallback=True,
                allocation_can_return_null=True,oversize_calls_handler_then_stores_12_and_returns_zero=True,
                failed_allocation_errno_is_12=True,callback_result_may_request_retry=True,
                termination_for_all_handlers_and_heap_states_proven=False,uninitialized_heap_children_effects_complete=False,
                small_allocator_and_external_heap_effects_complete=False,
                complete_explicit_normal_allocation_paths_static_bound=True,native_code_executed=False)


def _lookup(raw,image,sections,address):
    at,code=_code(raw,image,sections,address,128);g=_Grammar()
    g.code('8bff558bec8b0d');g.word('count');g.code('a1');g.word('buffer');g.code('6bc91403c8');g.branch('eb','test')
    g.mark('loop');g.code('8b55082b500c81fa00001000');g.branch('72','return');g.code('83c014')
    g.mark('test');g.code('3bc1');g.branch('72','loop');g.code('33c0');g.mark('return');g.code('5dc3');m=g.match(code)
    return dict(**_record(address,at,m[0]),header_count_storage=_writable_image_range(raw,image,sections,_word(m,'count'),4),
                header_buffer_pointer_storage=_writable_image_range(raw,image,sections,_word(m,'buffer'),4),
                header_stride_bytes=20,region_base_field=12,region_range_bytes=0x100000,
                native_region_test='(pointer - header.region_base) mod 2**32 < 0x100000',
                buffer_end_uses_count_times_20_modulo_32_bit=True,
                actual_header_array_allocation_bounds_and_count_proven=False,
                header_count_buffer_and_regions_immutable_under_correct_lock_required=True,
                callee_argument_cleanup_bytes=0,complete_explicit_normal_heap_lookup_paths_static_bound=True,native_code_executed=False)


def _lock_pair(raw,image,sections,imports,lock_address,unlock_address):
    at,code=_code(raw,image,sections,lock_address,128);g=_Grammar()
    g.code('8bff558bec8b4508568d34c5');g.word('table');g.code('833e00');g.branch('75','enter')
    g.code('50e8');g.word('initialize_call');g.code('5985c0');g.branch('75','enter')
    g.code('6a11e8');g.word('failure_call');g.code('59');g.mark('enter');g.code('ff36ff15');g.word('api');g.code('5e5dc3');m=g.match(code)
    _import(raw,image,sections,imports,m,'api','EnterCriticalSection')
    uat,ucode=_code(raw,image,sections,unlock_address,64)
    um=re.match(engine_pattern('native_cg_vm_heap_paths:183:16')+_w('table')+engine_pattern('native_cg_vm_heap_paths:183:77')+_w('api')+engine_pattern('native_cg_vm_heap_paths:183:100'),ucode,re.DOTALL)
    if um is None or _word(um,'table')!=_word(m,'table'):
        raise ValueError('CG 堆锁的进入和退出没有使用自己的同一张锁表。')
    _import(raw,image,sections,imports,um,'api','LeaveCriticalSection')
    # The caller passes index4. No claim that arbitrary caller indices fit.
    storage=_writable_image_range(raw,image,sections,_word(m,'table')+4*8,4)
    return dict(lock=dict(**_record(lock_address,at,m[0]),helper_addresses={n:_callee(raw,image,sections,lock_address,m,n) for n in ('initialize_call','failure_call')}),
                unlock=_record(unlock_address,uat,um[0]),own_heap_lock_pointer_storage=storage,
                heap_caller_index=4,table_slot_stride_bytes=8,
                imported_enter_and_leave_identities_static_bound=True,
                critical_section_initialization_ownership_and_reentry_proven=False,
                callee_argument_cleanup_bytes=0,complete_explicit_normal_lock_dispatch_paths_static_bound=True,native_code_executed=False)


def _small_release(raw,image,sections,imports,address,release,lookup):
    at,code=_code(raw,image,sections,address,1536);g=_Grammar()
    g.code('8bff558bec83ec108b4d088b4110568b750c578bfe2b790c83c6fcc1ef0f8bcf69c9040200008d8c0144010000894df08b0e49894dfcf6c101')
    g.branch('0f85','return',True);g.code('538d1c318b138955f48b56fc8955f88b55f4895d0cf6c201');g.branch('75','right_done')
    g.code('c1fa044a83fa3f');g.branch('76','right_size');g.code('6a3f5a');g.mark('right_size')
    g.code('8b4b043b4b08');g.branch('75','right_unlink');g.code('bb0000008083fa20');g.branch('73','right_high')
    g.code('8bcad3eb8d4c0204f7d3215cb844fe09');g.branch('75','right_finish');g.code('8b4d082119');g.branch('eb','right_finish')
    g.mark('right_high');g.code('8d4ae0d3eb8d4c0204f7d3219cb8c4000000fe09');g.branch('75','right_finish');g.code('8b4d08215904')
    g.mark('right_finish');g.code('8b5d0c');g.mark('right_unlink');g.code('8b53088b5b048b4dfc034df4895a048b550c8b5a048b5208895308894dfc')
    g.mark('right_done');g.code('8bd1c1fa044a83fa3f');g.branch('76','left_size');g.code('6a3f5a');g.mark('left_size')
    g.code('8b5df883e301895df4');g.branch('0f85','left_used',True)
    g.code('2b75f88b5df8c1fb046a3f89750c4b5e3bde');g.branch('76','left_bucket');g.code('8bde');g.mark('left_bucket')
    g.code('034df88bd1c1fa044a894dfc3bd6');g.branch('76','left_merged_bucket');g.code('8bd6');g.mark('left_merged_bucket')
    g.code('3bda');g.branch('74','left_finish');g.code('8b4d0c8b71043b7108');g.branch('75','left_unlink')
    g.code('be0000008083fb20');g.branch('73','left_high');g.code('8bcbd3eef7d62174b844fe4c0304');g.branch('75','left_unlink')
    g.code('8b4d082131');g.branch('eb','left_unlink');g.mark('left_high');g.code('8d4be0d3eef7d621b4b8c4000000fe4c0304')
    g.branch('75','left_unlink');g.code('8b4d08217104');g.mark('left_unlink')
    g.code('8b4d0c8b71088b4904894e048b4d0c8b71048b4908894e08');g.mark('left_finish');g.code('8b750c');g.branch('eb','insert_test')
    g.mark('left_used');g.code('8b5d08');g.mark('insert_test');g.code('837df400');g.branch('75','insert');g.code('3bda');g.branch('0f84','write_block',True)
    g.mark('insert');g.code('8b4df08d0cd18b5904894e08895e048971048b4e048971088b4e043b4e08');g.branch('75','write_block')
    g.code('8a4c0204884d0ffec1884c020483fa20');g.branch('73','insert_high');g.code('807d0f00');g.branch('75','insert_low_bitmap')
    g.code('8bcabb00000080d3eb8b4d080919');g.mark('insert_low_bitmap');g.code('bb000000808bcad3eb8d44b8440918');g.branch('eb','write_block')
    g.mark('insert_high');g.code('807d0f00');g.branch('75','insert_high_bitmap');g.code('8d4ae0bb00000080d3eb8b4d08095904')
    g.mark('insert_high_bitmap');g.code('8d4ae0ba00000080d3ea8d84b8c40000000910');g.mark('write_block')
    g.code('8b45fc8906894430fc8b45f0ff08');g.branch('0f85','pop_ebx',True)
    g.code('a1');g.word('cached_header0');g.code('85c0');g.branch('0f84','cache_current',True)
    g.code('8b0d');g.word('cached_region0');g.code('8b35');g.word('virtual_free_api');g.code('6800400000c1e10f03480cbb008000005351ffd6')
    g.code('8b0d');g.word('cached_region1');g.code('a1');g.word('cached_header1');g.code('ba00000080d3ea095008a1');g.word('cached_header2')
    g.code('8b40108b0d');g.word('cached_region2');g.code('83a488c400000000a1');g.word('cached_header3');g.code('8b4010fe4843a1');g.word('cached_header4')
    g.code('8b481080794300');g.branch('75','release_region');g.code('836004fea1');g.word('cached_header5');g.mark('release_region')
    g.code('837808ff');g.branch('75','cache_current');g.code('536a00ff700cffd6a1');g.word('cached_header6')
    g.code('ff70106a00ff35');g.word('heap_global');g.code('ff15');g.word('heap_free_api')
    g.code('8b0d');g.word('count0');g.code('a1');g.word('cached_header7');g.code('6bc9148b15');g.word('buffer0')
    g.code('2bc88d4c11ec518d48145150e8');g.word('move_call');g.code('8b450883c40cff0d');g.word('count1')
    g.code('3b05');g.word('cached_header8');g.branch('76','set_scan');g.code('836d0814');g.mark('set_scan')
    g.code('a1');g.word('buffer1');g.code('a3');g.word('scan_pointer');g.mark('cache_current')
    g.code('8b4508a3');g.word('cached_header9');g.code('893d');g.word('cached_region3')
    g.mark('pop_ebx');g.code('5b');g.mark('return');g.code('5f5ec9c3');m=g.match(code)
    for stem,count in (('cached_header',10),('cached_region',4),('count',2),('buffer',2)):
        if len({_word(m,stem+str(i)) for i in range(count)})!=1:
            raise ValueError('CG 小块释放没有保持自己的同一组堆状态。')
    if _word(m,'heap_global')!=release['static_heap_ranges']['heap_global']['address']:
        raise ValueError('CG 小块释放没有使用自己的同一普通堆。')
    if _word(m,'count0')!=lookup['header_count_storage']['address'] or _word(m,'buffer0')!=lookup['header_buffer_pointer_storage']['address']:
        raise ValueError('CG 小块释放和查找没有使用同一来源的区域表。')
    for key,api in (('virtual_free_api','VirtualFree'),('heap_free_api','HeapFree')):_import(raw,image,sections,imports,m,key,api)
    storage={n:_writable_image_range(raw,image,sections,_word(m,n),4) for n in ('cached_header0','cached_region0','count0','buffer0','scan_pointer')}
    return dict(**_record(address,at,m[0]),helper_addresses=dict(move_call=_callee(raw,image,sections,address,m,'move_call')),
                static_heap_ranges=storage,header_stride_bytes=20,header_region_base_field=12,header_metadata_field=16,
                region_shift_bits=15,region_metadata_stride_bytes=516,size_bucket_maximum=63,
                explicit_left_and_right_coalescing_paths_static_bound=True,
                normal_saved_EBX_ESI_EDI_EBP_and_RET0_static_bound=True,
                direct_caller_argument_cells_may_be_modified=[dict(argument=1,bytes=4),dict(argument=2,bytes=4)],
                virtual_free_result_is_not_checked_before_metadata_updates=True,
                heap_free_result_is_not_checked_before_header_compaction=True,
                header_count_may_decrease_and_caller_header_pointer_may_shift=True,
                metadata_and_buffer_bounds_lock_ownership_and_children_effects_complete=False,
                complete_explicit_normal_small_release_paths_static_bound=True,native_code_executed=False)


def _literal(raw,image,sections,address,value):
    offset = _relocated(raw,image,sections,address,executable=False,length=len(value))
    if raw[offset:offset+len(value)] != value:
        raise ValueError('CG 动态堆处理没有请求自己实际的模块和函数名。')
    return dict(address=address,bytes=len(value),sha256=hashlib.sha256(value).hexdigest())


def _handler_decode(raw,image,sections,imports,address):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('8bff558bec56ff35');g.word('tls_index');g.code('8b35');g.word('tls_api');g.code('ffd685c0')
    g.branch('74','fallback');g.code('a1');g.word('tls_function_index');g.code('83f8ff');g.branch('74','fallback')
    g.code('50ff35');g.word('tls_index_again');g.code('ffd6ffd085c0');g.branch('74','fallback')
    g.code('8b80fc010000');g.branch('eb','join');g.mark('fallback');g.code('be');g.word('module_name')
    g.code('56ff15');g.word('module_api');g.code('85c0');g.branch('75','module_ready')
    g.code('56e8');g.word('module_load_call');g.code('5985c0');g.branch('74','return')
    g.mark('module_ready');g.code('68');g.word('procedure_name');g.code('50ff15');g.word('procedure_api')
    g.mark('join');g.code('85c0');g.branch('74','return');g.code('ff7508ffd0894508')
    g.mark('return');g.code('8b45085e5dc3');m=g.match(code)
    if _word(m,'tls_index')!=_word(m,'tls_index_again'):
        raise ValueError('CG 处理函数解码没有使用自己的同一 TLS 索引。')
    for key,api in (('tls_api','TlsGetValue'),('module_api','GetModuleHandleW'),('procedure_api','GetProcAddress')):
        _import(raw,image,sections,imports,m,key,api)
    return dict(**_record(address,at,m[0]),helper_addresses=dict(module_load_call=_callee(raw,image,sections,address,m,'module_load_call')),
                static_tls_ranges={k:_writable_image_range(raw,image,sections,_word(m,k),4) for k in ('tls_index','tls_function_index')},
                own_dynamic_module_literal=_literal(raw,image,sections,_word(m,'module_name'),'KERNEL32.DLL\0'.encode('utf-16-le')),
                own_dynamic_procedure_literal=_literal(raw,image,sections,_word(m,'procedure_name'),engine_pattern('native_cg_vm_heap_paths:282:100')),
                TLS_object_function_field=0x1fc,zero_dynamic_function_returns_original_argument=True,
                decoder_result_written_into_caller_argument_cell=True,callee_argument_cleanup_bytes=0,
                complete_explicit_normal_decode_paths_static_bound=True,
                TLS_object_extent_dynamic_function_identity_and_ABI_proven=False,
                module_loader_and_dynamic_function_effects_complete=False,native_code_executed=False)


def _error_base_constructor(raw,image,sections,address):
    at,code=_code(raw,image,sections,address,64);g=_Grammar()
    g.code('8bff558bec8bc18b4d08c700');g.word('vtable');g.code('8b09836008008948045dc20800');m=g.match(code)
    _relocated(raw,image,sections,_word(m,'vtable'),executable=False,length=4)
    return dict(**_record(address,at,m[0]),vtable_address=_word(m,'vtable'),direct_this_write_fields=[0,4,8],
                object_extent_required=12,string_field_is_dereferenced_first_argument=True,
                ownership_field_written_zero=True,callee_argument_cleanup_bytes=8,return_value_is_this=True,
                this_and_argument_pointer_bounds_proven=False,complete_explicit_normal_constructor_path_static_bound=True)


def _error_constructor(raw,image,sections,address):
    at,code=_code(raw,image,sections,address,128);g=_Grammar()
    g.code('8bff566a0168');g.word('text_cell');g.code('8bf1e8');g.word('base_call')
    g.code('c706');g.word('vtable');g.code('8bc65ec3');m=g.match(code)
    base=_error_base_constructor(raw,image,sections,_callee(raw,image,sections,address,m,'base_call'))
    cell=_word(m,'text_cell');offset=_relocated(raw,image,sections,cell,executable=False,length=4)
    text=struct.unpack_from('<I',raw,offset)[0]
    _relocated(raw,image,sections,text,executable=False)
    _relocated(raw,image,sections,_word(m,'vtable'),executable=False,length=4)
    return dict(**_record(address,at,m[0]),native_base_constructor=base,vtable_address=_word(m,'vtable'),
                own_text_pointer_cell=dict(address=cell,PE_value=text),
                first_argument_is_pointer_cell_not_direct_text=True,callee_argument_cleanup_bytes=0,
                normal_saved_ESI_and_return_this_static_bound=True,object_extent_required=12,
                text_cell_value_and_string_bounds_at_call_proven=False,
                complete_explicit_normal_error_constructor_path_static_bound=True,native_code_executed=False)


def _error_base_copy(raw,image,sections,address,malloc,base_constructor):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('8bff558bec538b5d08568bf1c706');g.word('vtable');g.code('8b430889460885c08b430457')
    g.branch('74','direct');g.code('85c0');g.branch('74','nil');g.code('50e8');g.word('strlen_call')
    g.code('8bf84757e8');g.word('allocate_call');g.code('595989460485c0');g.branch('74','return')
    g.code('ff73045750e8');g.word('string_copy_call');g.code('83c40c');g.branch('eb','return')
    g.mark('nil');g.code('83660400');g.branch('eb','return');g.mark('direct');g.code('894604')
    g.mark('return');g.code('5f8bc65e5b5dc20400');m=g.match(code)
    helpers={k:_callee(raw,image,sections,address,m,k) for k in ('strlen_call','allocate_call','string_copy_call')}
    if _word(m,'vtable')!=base_constructor['vtable_address'] or helpers['allocate_call']!=malloc['address']:
        raise ValueError('CG 异常对象复制没有使用自己的基类和同一堆分配。')
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,vtable_address=_word(m,'vtable'),
                ownership_field_copied_from_source=True,zero_ownership_shares_text_pointer=True,
                nonzero_ownership_may_allocate_and_copy_text=True,
                allocation_size_is_strlen_plus_one_modulo_32_bits=True,
                null_allocation_return_retained_without_assuming_throw=True,
                destination_string_field_written_before_allocation_test=True,
                callee_argument_cleanup_bytes=4,normal_saved_EBX_ESI_EDI_EBP_and_return_this_static_bound=True,
                object_bounds_string_children_and_exception_effects_complete=False,
                complete_explicit_normal_error_copy_paths_static_bound=True,native_code_executed=False)


def _error_copy(raw,image,sections,address,malloc,constructor):
    at,code=_code(raw,image,sections,address,128);g=_Grammar()
    g.code('8b44240456508bf1e8');g.word('base_call');g.code('c706');g.word('vtable');g.code('8bc65ec20400');m=g.match(code)
    if _word(m,'vtable')!=constructor['vtable_address']:
        raise ValueError('CG 分配失败的构造与复制没有使用自己同一派生类型。')
    base=_error_base_copy(raw,image,sections,_callee(raw,image,sections,address,m,'base_call'),malloc,constructor['native_base_constructor'])
    return dict(**_record(address,at,m[0]),native_base_copy=base,vtable_address=_word(m,'vtable'),
                object_extent_required=12,callee_argument_cleanup_bytes=4,return_value_is_this=True,
                complete_explicit_normal_error_copy_wrapper_static_bound=True,native_code_executed=False)


def _raise_exception(raw,image,sections,imports,address):
    at,code=_code(raw,image,sections,address,256);g=_Grammar()
    g.code('8bff558bec83ec208b450856576a0859be');g.word('template')
    g.code('8d7de0f3a58945f88b450c5f8945fc5e85c0');g.branch('74','raise')
    g.code('f60008');g.branch('74','raise');g.code('c745f400409901');g.mark('raise')
    g.code('8d45f450ff75f0ff75e4ff75e0ff15');g.word('api');g.code('c9c20800');m=g.match(code)
    _import(raw,image,sections,imports,m,'api','RaiseException')
    template_address=_word(m,'template');offset=_relocated(raw,image,sections,template_address,executable=False,length=32)
    data=raw[offset:offset+32];words=list(struct.unpack('<8I',data))
    return dict(**_record(address,at,m[0]),own_PE_exception_template=dict(address=template_address,bytes=32,
                sha256=hashlib.sha256(data).hexdigest(),words=words),
                copied_template_bytes=32,DF_zero_at_entry_required=True,
                object_and_type_overwrite_local_template_fields=[24,28],
                type_flag8_overrides_magic_with=0x1994000,
                raise_arguments_from_template_fields=[0,4,16],exception_parameters_local_offset=20,
                callee_argument_cleanup_bytes=8,normal_external_call_return_path_static_bound=True,
                imported_raise_exception_identity=imports[_word(m,'api')],
                immutable_template_and_type_bounds_at_call_proven=False,
                imported_raise_nonreturning_and_exception_dispatch_proven=False,
                complete_explicit_raise_wrapper_paths_static_bound=True,native_code_executed=False)


def _atexit(raw,image,sections,address):
    at,code=_code(raw,image,sections,address,64);g=_Grammar()
    g.code('8bff558becff7508e8');g.word('register_call');g.code('f7d81bc0f7d859485dc3');m=g.match(code)
    return dict(**_record(address,at,m[0]),helper_addresses=dict(register_call=_callee(raw,image,sections,address,m,'register_call')),
                nonzero_child_result_maps_to_zero_zero_maps_to_minus_one=True,callee_argument_cleanup_bytes=0,
                callback_registration_lifetime_and_execution_proven=False,
                complete_explicit_normal_exit_registration_wrapper_static_bound=True,native_code_executed=False)


def bind_native_cg_vm_heap_paths(executable,header,vm,frames):
    raw=bytes(executable);image,sections=_pe_sections(raw);imports=_import_slots(raw,image)
    copy=bind_native_cg_vm_member_copy(raw,header,vm,frames)
    cleanup=copy['native_vm_member_children']['native_vm_members']['native_vm_teardown']['native_vm_cleanup']
    allocator=cleanup['native_vm_application']['native_application_allocator'];a=allocator['helper_addresses']
    bridge=cleanup['native_release_bridge'];older=copy['layout']=='signed-word-legacy'
    if older:
        allocation=_legacy_import(raw,image,sections,imports,a['allocate_call'],'malloc')
        handler=_legacy_import(raw,image,sections,imports,a['handler_call'],'_callnewh')
        native=dict(allocation=allocation,handler=handler,release=bridge,
                    external_malloc_handler_delete_and_nomemory_effects_complete=False)
    else:
        release=bridge['native_free_paths'];f=release['helper_addresses']
        slot=_error_slot(raw,image,sections,f['error_slot_call'])
        mapping=_error_map(raw,image,sections,f['error_map_call'])
        handler=_handler(raw,image,sections,imports,a['handler_call'])
        allocation=_malloc(raw,image,sections,imports,a['allocate_call'],handler,slot,release)
        lookup=_lookup(raw,image,sections,f['lookup_call'])
        lock=_lock_pair(raw,image,sections,imports,f['lock_call'],f['unlock_call'])
        small=_small_release(raw,image,sections,imports,f['small_release_call'],release,lookup)
        constructor=_error_constructor(raw,image,sections,a['error_ctor_call'])
        error_copy=_error_copy(raw,image,sections,a['copy_error_call'],allocation,constructor)
        native=dict(allocation=allocation,handler=handler,error_slot=slot,error_map=mapping,
                    lookup=lookup,lock_dispatch=lock,small_release=small,error_constructor=constructor,error_copy=error_copy,
                    raise_wrapper=_raise_exception(raw,image,sections,imports,a['throw_call']),
                    exit_registration=_atexit(raw,image,sections,a['atexit_call']),
                    error_object_full_static_PE_range=_writable_image_range(raw,image,sections,
                    allocator['failure_state_PE_ranges']['error_object']['address'],12))
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=copy['layout'],
                native_vm_member_copy=copy,native_heap_instruction_paths=native,
                own_allocation_release_and_failure_dispatch_paths_static_bound=True,
                own_modern_heap_children_explicit_normal_paths_static_bound=not older,
                own_legacy_external_heap_import_identities_static_bound=older,
                normal_helper_ABI_nonvolatile_registers_and_valid_memory_required=True,
                complete_member_child_and_heap_effects_bound=False,native_allocator_and_free_heap_effects_complete=False,
                same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
                complete_allocation_exception_and_reentry_effects_bound=False,native_code_executed=False,
                runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
