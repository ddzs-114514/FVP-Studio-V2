"""Own complete loader instruction dispatch, not live reload/heap acceptance.

The normal function-record tail and both errors belong to the already-bound
entry/header reader. Names are borrowed from the input buffer; allocation,
append, formatter, throw/SEH and post-INT3 continuation effects are not granted.
No native code executes and no public CG output is enabled.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record
from .native_cg_vm_member_copy import _Grammar as _CopyGrammar, _copy_helper
from .native_cg_vm_heap_paths import _word, _callee, _import
from .native_cg_vm_heap_children import bind_native_cg_vm_heap_children
from .native_cg_vm_syscall_header import bind_native_cg_vm_syscall_header
from .native_cg_vm_application import _import_slots

SCHEMA = 'fvp-native-cg-vm-loader/1'


class _Grammar(_CopyGrammar):
    def match(self, code):
        try:
            return super().match(code)
        except ValueError as error:
            raise ValueError('CG 脚本加载的函数表、返回或错误分支没有完整连接。') from error


def _literal(raw, image, sections, address):
    offset = _relocated(raw, image, sections, address, executable=False, length=1)
    section = next(s for s in sections if s[3] <= offset < s[3] + s[2])
    end = raw.find(b'\0', offset, section[3] + section[2])
    if end < 0:
        raise ValueError('CG 加载错误文本在自己的文件映射中没有终止符。')
    value = raw[offset:end + 1]
    return dict(address=address, bytes=len(value), sha256=hashlib.sha256(value).hexdigest(),
                disk_zero_terminated=True, immutable_at_call_proven=False)


def _function_records(header):
    """Decode the exact extra records the native tail reads; keep raw bytes."""
    count = getattr(header, 'custom_syscall_count', None)
    data = getattr(header, 'trailing', None)
    if type(count) is not int or not 0 <= count <= 0x7fff or not isinstance(data, (bytes, bytearray)):
        raise ValueError('CG 自定义函数表不符合原生有符号数量或字节范围。')
    data = bytes(data)
    cursor, records = 0, []
    for index in range(count):
        if len(data) - cursor < 6:
            raise ValueError('CG 自定义函数记录的地址、参数或名称长度不完整。')
        offset, argc, length = struct.unpack_from('<IBB', data, cursor)
        record_start = cursor
        cursor += 6
        if len(data) - cursor < length:
            raise ValueError('CG 自定义函数名称超过自己声明的数据范围。')
        name = data[cursor:cursor + length]
        records.append(dict(index=index, trailing_record_offset=record_start, code_offset=offset,
                            raw_argc_byte=argc, native_signed_argc=argc if argc < 128 else argc - 256,
                            declared_name_length=length, raw_name_hex=name.hex(),
                            zero_terminator_within_declared_name=b'\0' in name,
                            source_instruction_target_and_lifetime_proven=False))
        cursor += length
    encoded = struct.pack('<h', count) + data[:cursor]
    return dict(count=count, records=records, consumed_trailing_bytes=cursor,
                ignored_trailing_bytes=len(data) - cursor, encoded_records_sha256=hashlib.sha256(encoded).hexdigest(),
                declared_record_order_preserved=True, negative_argc_values_retained=True,
                borrowed_name_read_bounds_at_call_proven=False, output_code_offsets_relocated=False)


def _sorted_insert(raw, image, sections, address, link, heap):
    at, code = _code(raw, image, sections, address, 256)
    older = link['layout'] == 'signed-word-legacy'
    g = _Grammar()
    g.code('568bf18b4604578b7c240c3bf8'); g.branch('75', 'insert')
    g.code('8b44241050e8'); g.word('append_call'); g.code('5f5ec20800')
    g.mark('insert'); g.code('8b0e3bc8'); g.branch('75', 'move')
    g.code('8b560c03d1528bcee8'); g.word('grow_call')
    g.mark('move'); g.code('8b4e048b46082bcf'); g.code('c1e102' if older else '03c903c9')
    g.code('8d04b8515083c00450')
    if older:
        g.code('ff15'); g.word('move_api')
        g.code('8b56088b44241c8904ba8b460483c40c405f8946045ec20800')
    else:
        g.code('e8'); g.word('move_call'); g.code('8b56088b44241c83c40c8904baff46045f5ec20800')
    m = g.match(code)
    helpers = {n: _callee(raw, image, sections, address, m, n) for n in ('append_call', 'grow_call')}
    if helpers['append_call'] != link['native_append']['address'] or helpers['grow_call'] != link['native_append']['native_grow_address']:
        raise ValueError('CG 函数插入没有使用本来源同一套追加和增长入口。')
    if older:
        imports = _import_slots(raw, image)
        _import(raw, image, sections, imports, m, 'move_api', 'memmove', dll='msvcr71.dll')
        move = dict(import_identity=imports[_word(m, 'move_api')], external_implementation_effects_complete=False)
    else:
        helpers['move_call'] = _callee(raw, image, sections, address, m, 'move_call')
        # Derive and bind this callee in the same PE. A different complete
        # local memmove is legal; do not require an unrelated header mover VA.
        move = _copy_helper(raw, image, sections, helpers['move_call'])
    return dict(**_record(address, at, m[0]), helper_addresses=helpers, native_move=move,
                callee_argument_cleanup_bytes=8, capacity_field=0, count_field=4, buffer_field=8, growth_field=12,
                entry_SP_arguments=dict(index=4, descriptor_pointer=8), pointer_stride_bytes=4,
                move_byte_count_is_count_minus_index_times_four_modulo_uint32=True,
                index_bounds_not_explicitly_checked=True, buffer_and_count_reread_after_children=True,
                own_complete_sorted_insert_dispatch_paths_static_bound=True,
                growth_move_actual_bounds_ownership_mutation_and_reentry_effects_complete=False)


def _function_append(raw, image, sections, address, link, heap):
    at, code = _code(raw, image, sections, address, 256)
    older = link['layout'] == 'signed-word-legacy'
    g = _Grammar()
    g.code('568bf1'); g.code('8b460485c0' if older else '837e0400'); g.branch('75', 'lookup')
    g.code('8b44240850e8'); g.word('empty_append_call'); g.code('33c05ec20400')
    g.mark('lookup'); g.code('578b7c240c8b178d4c240c51528bcee8'); g.word('lookup_call')
    g.code('85c0'); g.branch('75', 'return')
    g.code('8b44240c57508bcee8'); g.word('insert_call'); g.code('33c0')
    g.mark('return'); g.code('5f5ec20400'); m = g.match(code)
    helpers = {n: _callee(raw, image, sections, address, m, n) for n in
               ('empty_append_call', 'lookup_call', 'insert_call')}
    if helpers['empty_append_call'] != link['native_append']['address'] or helpers['lookup_call'] != link['native_lookup']['address']:
        raise ValueError('CG 函数查重没有复用自己同一套查找和初次追加入口。')
    insert = _sorted_insert(raw, image, sections, helpers['insert_call'], link, heap)
    return dict(**_record(address, at, m[0]), helper_addresses=helpers, native_sorted_insert=insert,
                callee_argument_cleanup_bytes=4, entry_SP_descriptor_argument=4,
                empty_count_uses_ordinary_append=True, nonempty_count_checks_borrowed_name_for_duplicate=True,
                lookup_output_index_overwrites_callers_descriptor_argument_cell=True,
                found_duplicate_returns_existing_descriptor_and_skips_insert=True,
                newly_allocated_duplicate_descriptor_not_explicitly_freed_by_dispatch=True,
                own_complete_function_lookup_and_insert_dispatch_paths_static_bound=True,
                key_read_actual_sorted_order_heap_lifetime_and_reentry_effects_complete=False)


def _loader_tail(raw, image, sections, prefix, link, startup, allocator, heap):
    address = link['reader_address'] + link['reader_code_bytes']
    at, code = _code(raw, image, sections, address, 1024)
    older = link['layout'] == 'signed-word-legacy'
    g = _Grammar()
    g.code('8b46088b16')
    if older:
        g.code('0fbf0c1083c00285c9894608'); g.branch('74', 'return')
        g.code('81c7'); g.word('function_table'); g.code('897c2414894c2410')
    else:
        g.code('0fbf2c0283c00289460885ed'); g.branch('74', 'return')
        g.code('81c7'); g.word('function_table'); g.code('897c2418')
    g.mark('loop'); g.code('8b46088b0e8b1c0883c0048946088bd1')
    if older:
        g.code('0fbe2c10408946088b0e0fb60c08408946088b3e03f803c16a0c894608')
    else:
        g.code('0fbe0c1040894608894c24140fb60c02408bfa89460803f803c16a0c4d894608')
    g.code('e8'); g.word('record_allocate_call')
    if older:
        g.code('8b4c241883c404508938896804895808')
    else:
        # The first ESP+18 read is while the 12-byte request is still pushed;
        # it reads argc. After ADD ESP,4, ESP+18 reads the saved table pointer.
        g.code('8b4c241883c4048948048b4c2418508938895808')
    g.code('e8'); g.word('append_call')
    g.code('ff4c2410' if older else '85ed'); g.branch('75', 'loop')
    g.mark('return')
    if older:
        g.code('8b8c24580100005e5d5b5f64890d0000000081c454010000c3')
    else:
        g.code('8b8c246001000064890d00000000595f5e5d5b8b8c244801000033cce8')
        g.word('cookie_check_call'); g.code('81c458010000c3')
    g.mark('missing')
    g.code('6880000000e8'); g.word('error_allocate_call0'); g.code('83c40485c0'); g.branch('74', 'nil0')
    g.code('5368'); g.word('missing_format'); g.code('50e8'); g.word('error_construct_call0')
    g.code('83c40c'); g.branch('eb', 'throw0'); g.mark('nil0'); g.code('33c0'); g.mark('throw0')
    g.code('894424' + ('10' if older else '14') + '68'); g.word('error_type0')
    g.code('8d4424' + ('14' if older else '18') + '50e8'); g.word('throw_call0')
    g.mark('argc_error')
    g.code('6880000000e8'); g.word('error_allocate_call1'); g.code('83c40485c0'); g.branch('74', 'nil1')
    g.code('5368'); g.word('argc_format'); g.code('50e8'); g.word('error_construct_call1')
    g.code('83c40c'); g.branch('eb', 'throw1'); g.mark('nil1'); g.code('33c0'); g.mark('throw1')
    g.code('68'); g.word('error_type1'); g.code('8d4c24' + ('18' if older else '1c') + '51')
    g.code('894424' + ('1c' if older else '20') + 'e8'); g.word('throw_call1'); g.mark('post_throw_trap'); g.code('cc')
    m = g.match(code)
    helpers = {n: _callee(raw, image, sections, address, m, n) for n in m.groupdict()
               if n.endswith('_call') or n.startswith(('error_allocate_call', 'error_construct_call', 'throw_call'))}
    allocation = prefix['helper_addresses']['allocate']
    if allocation != allocator['address'] or any(helpers[n] != allocation for n in
             ('record_allocate_call', 'error_allocate_call0', 'error_allocate_call1')):
        raise ValueError('CG 加载函数和错误对象没有使用自己的同一完整分配入口。')
    append = _function_append(raw, image, sections, helpers['append_call'], link, heap)
    if (helpers['throw_call0'] != helpers['throw_call1'] or helpers['throw_call0'] != prefix['helper_addresses']['throw']
            or helpers['error_construct_call0'] != helpers['error_construct_call1']
            or _word(m, 'error_type0') != _word(m, 'error_type1')):
        raise ValueError('CG 两条加载错误没有沿用自己同一类型、构造和异常入口。')
    fields = startup['native_controller_constructor']['table_constructor_fields']
    if (_word(m, 'function_table') != fields[2] or link['native_syscall_vector_field'] != fields[1]
            or link['native_catalogue_field'] != fields[0]):
        raise ValueError('CG 加载函数表不属于自己构造的同一组原生容器。')
    if link['native_failure_branches'] != {n: address + m.start(n) for n in ('missing', 'argc_error')}:
        raise ValueError('CG 原生读名和参数不匹配没有进入完整的两条加载错误块。')
    type_address = _word(m, 'error_type0')
    _relocated(raw, image, sections, type_address, executable=False, length=1)
    formats = {n: _literal(raw, image, sections, _word(m, n)) for n in ('missing_format', 'argc_format')}
    return dict(**_record(address, at, m[0]), helper_addresses=helpers, native_function_append=append,
                normal_return_address=address + m.start('missing') - 1,
                normal_tail_bytes=m.start('missing'), error_dispatch_bytes=len(m[0]) - m.start('missing'),
                failure_block_addresses={n: address + m.start(n) for n in ('missing', 'argc_error')},
                post_throw_trap_address=address + m.start('post_throw_trap'),
                function_table_field=_word(m, 'function_table'), function_descriptor_bytes=12,
                descriptor_fields=dict(borrowed_name_pointer=0, signed_argc=4, source_code_offset=8),
                name_length_unsigned_bits=8, function_count_signed_bits=16, function_argc_signed_bits=8,
                zero_function_count_skips_allocation_and_append=True,
                signed_count_decrement_uses_32_bit_cell=True, negative_count_not_checked_by_native_tail=True,
                record_allocation_null_not_checked_before_writes=True,
                modern_argc_and_table_slots_distinguished_across_request_push=not older,
                callee_argument_cleanup_bytes=0, error_allocation_request_bytes=128,
                exception_type_address=type_address, own_error_format_ranges=formats,
                first_throw_return_continues_into_second_error_block=True,
                second_throw_return_continues_into_INT3=True,
                own_complete_loader_tail_normal_and_error_dispatch_paths_static_bound=True,
                formatter_append_throw_SEH_cookie_and_post_trap_effects_complete=False,
                native_code_executed=False)


def bind_native_cg_vm_loader(executable, header, vm, frames):
    raw = bytes(executable)
    image, sections = _pe_sections(raw)
    heap = bind_native_cg_vm_heap_children(raw, header, vm, frames)
    cleanup = heap['native_vm_heap_paths']['native_vm_member_copy']['native_vm_member_children']['native_vm_members']['native_vm_teardown']['native_vm_cleanup']
    application = cleanup['native_vm_application']
    startup = application['native_vm_instance']['native_vm_startup']
    prefix = startup['native_HCB_loader_entry_bridge']
    link = bind_native_cg_vm_syscall_header(raw, header, vm, frames)
    if prefix['address'] + prefix['code_bytes'] != link['reader_address'] or prefix['offset'] + prefix['code_bytes'] != link['reader_offset']:
        raise ValueError('CG 加载入口没有连续连接自己的完整脚本头读取链。')
    tail = _loader_tail(raw, image, sections, prefix, link, startup, application['native_application_allocator'], heap)
    length = prefix['code_bytes'] + link['reader_code_bytes'] + tail['code_bytes']
    offset = _relocated(raw, image, sections, prefix['address'], executable=True, length=length)
    records = _function_records(header)
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=heap['layout'],
                native_vm_heap_children=heap, native_syscall_header=link,
                native_HCB_loader_paths=dict(**_record(prefix['address'], offset, raw[offset:offset + length]),
                                             native_entry_prefix=prefix, native_header_reader=link, native_function_tail=tail),
                source_custom_function_records=records,
                own_loader_entry_header_normal_return_and_error_dispatch_static_bound=True,
                source_custom_function_records_static_decoded=True,
                whole_loader_child_allocation_error_and_reentry_effects_complete=False,
                complete_member_child_and_heap_effects_bound=False, native_allocator_and_free_heap_effects_complete=False,
                same_live_instance_lifetime_proven=False, initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False, source_header_arity_to_native_descriptor_bound=False,
                complete_allocation_exception_and_reentry_effects_bound=False,
                source_custom_function_offsets_relocated_by_output=False,
                native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
