"""Own complete restore I/O/reader/buffer instruction paths, not live I/O.

All explicit branches and terminal bytes of the bound functions are required.
API failures, untrusted file contents, heap/SEH/reentry and compression children
remain conditions. No original code is executed and public output stays shut.
"""
import hashlib

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record
from .native_cg_vm_heap_paths import _word, _callee
from .native_cg_vm_application import _import_slots, _writable_image_range
from .native_cg_vm_restore import bind_native_cg_vm_restore, _RestoreGrammar, _modern_grammar

SCHEMA = 'fvp-native-cg-vm-restore-children/1'


class _ChildGrammar(_RestoreGrammar):
    def match(self, code):
        try:
            return super().match(code)
        except ValueError as error:
            raise ValueError('CG 启动恢复的读取或清理子调用没有完整覆盖自身分支和返回。') from error


def _bind(raw, image, sections, imports, address, grammar, apis=(), data=()):
    at, code = _code(raw, image, sections, address, 1024)
    m = grammar.match(code)
    calls = {name[:-5]: _callee(raw, image, sections, address, m, name)
             for name in m.groupdict() if name.endswith('_call')}
    identities = {}
    for key, dll, name in apis:
        slot = _word(m, key)
        identity = imports.get(slot)
        if identity != dict(dll=dll, ordinal=None, name=name):
            raise ValueError('CG 恢复子调用没有使用自身确认的原生导入。')
        identities[key] = dict(address=slot, **identity)
    references = {}
    for key, length in data:
        value = _word(m, key)
        offset = _relocated(raw, image, sections, value, executable=False, length=length)
        references[key] = dict(address=value, bytes=raw[offset:offset + length].hex())
    return m, dict(**_record(address, at, m[0]), helper_addresses=calls,
                   import_calls=identities, data_references=references,
                   own_complete_explicit_instruction_paths_static_bound=True,
                   external_child_effects_and_memory_bounds_proven=False, native_code_executed=False)


def _exists(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o = g.code, g.operand
    e('8b4424046a0068000000086a036a006a01680000008050'); o('ff15', 'open_api')
    e('83f8ff'); g.branch('75', 'opened'); e('32c0c3'); g.mark('opened')
    e('50'); o('ff15', 'close_api'); e('b001c3')
    _, row = _bind(raw, image, sections, imports, address, g,
                   (('open_api', 'kernel32.dll', 'CreateFileA'), ('close_api', 'kernel32.dll', 'CloseHandle')))
    return dict(**row, callee_argument_cleanup_bytes=0, result_is_boolean_AL_only=True,
                result_means_open_succeeded_not_unconditional_file_existence=True,
                close_result_not_checked=True, path_argument_entry_SP_displacement=4)


def _resize(raw, image, sections, imports, address, older):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('56578b7c240c'); e('85ff8bf18b06' if older else '8bf18b0685ff')
    g.branch('7f', 'positive'); e('85c0'); g.branch('74', 'commit')
    e('506a00'); o('ff15', 'heap_api'); e('50'); o('ff15', 'free_api'); e('c70600000000')
    g.mark('commit'); e('897e045f5ec20400'); g.mark('positive')
    e('85c057' if older else '5785c0'); g.branch('75', 'reallocate')
    e('50'); o('ff15', 'heap_api'); e('50'); o('ff15', 'allocate_api'); g.branch('eb', 'allocated')
    g.mark('reallocate'); e('506a00'); o('ff15', 'heap_api'); e('50'); o('ff15', 'reallocate_api')
    g.mark('allocated'); e('85c08906' if older else '890685c0'); g.branch('75', 'commit')
    e('6880000000'); c('error_allocate'); e('83c4048bf085f6'); g.branch('74', 'no_message')
    o('68', 'error_format'); e('56'); o('ff15', 'format_api'); e('83c408'); g.branch('eb', 'raise')
    g.mark('no_message'); e('33f6'); g.mark('raise'); o('68', 'error_type')
    e('8d4424105089742414'); c('throw'); e('cc')
    _, row = _bind(raw, image, sections, imports, address, g,
                   (('heap_api', 'kernel32.dll', 'GetProcessHeap'), ('free_api', 'kernel32.dll', 'HeapFree'),
                    ('allocate_api', 'kernel32.dll', 'HeapAlloc'), ('reallocate_api', 'kernel32.dll', 'HeapReAlloc'),
                    ('format_api', 'user32.dll', 'wsprintfA')), (('error_format', 1), ('error_type', 1)))
    return dict(**row, kind='own-signed-size-buffer-resize-or-release', callee_argument_cleanup_bytes=4,
                direct_object_fields=dict(pointer=0, signed_size=4), nonpositive_request_frees_pointer=True,
                native_stored_size_is_original_signed_request_not_clamped=True,
                failed_HeapReAlloc_overwrites_old_pointer_before_error=True,
                HeapFree_result_not_checked=True, exception_child_return_falls_into_INT3=True,
                allocator_failure_and_exception_continuations_proven=False)


def _file(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('51538b5c240c56576a0068000000086a036a006a016800000080538bf1'); o('ff15', 'open_api')
    e('8bf883ffff'); g.branch('75', 'opened'); e('6880000000'); c('error_allocate')
    e('83c40485c0'); g.branch('74', 'no_message'); e('53'); o('68', 'error_format'); e('50')
    c('format'); e('83c40c'); g.branch('eb', 'raise'); g.mark('no_message'); e('33c0')
    g.mark('raise'); e('89442414'); o('68', 'error_type'); e('8d44241850'); c('throw')
    g.mark('opened'); e('8b0685c0'); g.branch('74', 'sized'); e('506a00')
    o('ff15', 'heap_api'); e('50'); o('ff15', 'free_api'); e('c70600000000')
    g.mark('sized'); e('6a0057c7460400000000'); o('ff15', 'size_api'); e('508bce'); c('resize')
    e('8b56048b066a008d4c241051525057'); o('ff15', 'read_api'); e('57'); o('ff15', 'close_api')
    e('5f5e5b59c20400')
    _, row = _bind(raw, image, sections, imports, address, g,
                   tuple((key, 'kernel32.dll', name) for key, name in (
                       ('open_api', 'CreateFileA'), ('heap_api', 'GetProcessHeap'), ('free_api', 'HeapFree'),
                       ('size_api', 'GetFileSize'), ('read_api', 'ReadFile'), ('close_api', 'CloseHandle'))),
                   (('error_format', 1), ('error_type', 1)))
    return dict(**row, callee_argument_cleanup_bytes=4, direct_object_fields=dict(pointer=0, size=4),
                file_length_high_word_not_requested=True, GetFileSize_failure_not_checked=True,
                ReadFile_result_and_actual_bytes_read_not_checked=True,
                stored_size_is_requested_size_not_confirmed_bytes_read=True, CloseHandle_result_not_checked=True,
                error_throw_return_would_fall_through_with_invalid_handle=True,
                native_read_success_and_file_contents_proven=False)


def _legacy_convert(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('83ec3c5556578b7c244c837f040c8be9'); g.branch('0f8c', 'move', wide=True)
    e('8b07803868'); g.branch('0f85', 'move', wide=True)
    for body in ('8078017a', '80780263', '80780331'):
        e(body); g.branch('0f85', 'move', wide=True)
    e('8b7004538b58088d0433508bcd89742414'); c('resize')
    e('33c03bd8'); g.branch('74', 'compressed')
    e('8b378b7d008bcb8bd183c60cc1e902f3a58bca83e103f3a48b7c24508b742410')
    g.mark('compressed'); e('8b550089442434894424388944243c8b078d4c180c6a388d44241803d3')
    o('68', 'compression_version'); e('50894c2420897424248954242c89742430'); c('compression_init')
    e('8d4c24206a0451'); c('compression_step'); e('83c41483f8015b'); g.branch('74', 'finished')
    g.mark('continue'); e('85c0'); g.branch('75', 'error'); e('8d5424106a0452'); c('compression_step_repeat')
    e('83c40883f801'); g.branch('75', 'continue'); g.mark('finished'); e('8d44241050'); c('compression_end')
    e('83c4045f5e5d83c43cc20400'); g.mark('error'); e('6880000000'); c('error_allocate')
    e('83c40485c0'); g.branch('74', 'no_message'); o('68', 'error_format'); e('50'); c('format')
    e('83c408'); g.branch('eb', 'raise'); g.mark('no_message'); e('33c0'); g.mark('raise')
    o('68', 'error_type'); e('8d4c24505189442454'); c('throw'); g.mark('move')
    e('8b450033f63bc6'); g.branch('74', 'transfer'); e('5056'); o('ff15', 'heap_api')
    e('50'); o('ff15', 'free_api'); e('897500'); g.mark('transfer')
    e('8975048b178955008b470489450489378977045f5e5d83c43cc20400')
    _, row = _bind(raw, image, sections, imports, address, g,
                   (('heap_api', 'kernel32.dll', 'GetProcessHeap'), ('free_api', 'kernel32.dll', 'HeapFree')),
                   (('compression_version', 1), ('error_format', 1), ('error_type', 1)))
    if row['helper_addresses']['compression_step'] != row['helper_addresses']['compression_step_repeat']:
        raise ValueError('CG 旧版恢复的解包循环没有调用自身同一步进函数。')
    return dict(**row, kind='own-legacy-hzc1-or-pointer-transfer', callee_argument_cleanup_bytes=4,
                native_compression_header_magic_hex='687a6331', native_header_minimum_signed_size=12,
                header_fields=dict(output_bytes=4, prefix_bytes=8), destination_size_sum_wraps_32_bits=True,
                plain_path_transfers_pointer_and_size_and_zeros_source=True,
                compressed_path_preserves_source_until_outer_cleanup=True,
                native_compression_loop_repeats_on_zero_until_one_or_error=True,
                complete_compression_child_effects_and_termination_proven=False,
                compressed_source_bounds_and_output_counts_proven=False, DF_zero_required=True)


def _legacy_load(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('6aff'); o('68', 'seh'); e('64a100000000506489250000000083ec08568bf1'
                              'c744240400000000c7442408000000008b44241c508d4c2408c744241800000000')
    c('file'); e('8d4c2404518bce'); c('convert'); e('8b44240485c05e'); g.branch('74', 'return')
    e('506a00'); o('ff15', 'heap_api'); e('50'); o('ff15', 'free_api'); g.mark('return')
    e('8b4c240864890d0000000083c414c20400')
    m, row = _bind(raw, image, sections, imports, address, g,
                   (('heap_api', 'kernel32.dll', 'GetProcessHeap'), ('free_api', 'kernel32.dll', 'HeapFree')))
    _relocated(raw, image, sections, _word(m, 'seh'), executable=True)
    return dict(**row, callee_argument_cleanup_bytes=4, local_file_pointer_and_size_initialized_zero=True,
                temporary_file_pointer_is_freed_iff_nonzero_after_convert=True, SEH_cleanup_dispatch_proven=False)


def _legacy_stream(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, c = g.code, g.call
    e('568b7424088b460457508bf9'); c('resize'); e('8b4f0485c9'); g.branch('74', 'return')
    e('8b368b3f8bd1c1e902f3a58bca83e103f3a4'); g.mark('return'); e('5f5ec20400')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=4, source_size_passed_to_own_resize=True,
                copy_bytes_is_destination_stored_size_as_unsigned_32_bit=True,
                signed_negative_size_would_not_skip_copy=True, DF_zero_required=True,
                parent_prefix_pointer_and_size_are_destination_fields=True)


def _reader(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('8b4424048b10568bf18b4808570fbf3c0a83c1028948086685ff'); g.branch('75', 'nonempty')
    e('8b06'); o('3d', 'empty'); g.branch('74', 'return'); e('50'); c('release'); e('83c4045f')
    o('c706', 'empty'); e('5ec20400'); g.mark('nonempty'); e('0fbfff03d103f9528bce897808')
    c('assign'); g.mark('return'); e('5f5ec20400')
    m, row = _bind(raw, image, sections, imports, address, g, data=(('empty', 1),))
    if row['data_references']['empty']['bytes'] != '00':
        raise ValueError('CG 恢复字符串没有使用自身的空字符串字节。')
    return dict(**row, callee_argument_cleanup_bytes=4, empty_string_address=_word(m, 'empty'),
                read_count_is_signed_16_bit=True, input_cursor_field=8, initial_cursor_advance_bytes=2,
                nonzero_cursor_advance_uses_signed_count_modulo_32_bits=True,
                string_copy_still_scans_NUL_instead_of_bounding_by_signed_count=True,
                complete_string_read_bounds_proven=False)


def _string_assign(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('53578bf98b07'); o('3d', 'empty'); g.branch('74', 'source')
    e('50'); c('release'); e('83c404'); o('c707', 'empty'); g.mark('source')
    e('8b5c240c85db'); g.branch('74', 'return'); e('8bc38d50018da42400000000')
    g.mark('scan'); e('8a084084c9'); g.branch('75', 'scan')
    e('2bc2568d700156'); c('allocate'); e('5653508907'); c('copy')
    e('83c4105e'); g.mark('return'); e('5f5bc20400')
    m, row = _bind(raw, image, sections, imports, address, g, data=(('empty', 1),))
    return dict(**row, empty_string_address=_word(m, 'empty'), callee_argument_cleanup_bytes=4,
                native_source_NUL_scan_is_unbounded=True, destination_allocation_return_not_null_checked=True,
                destination_pointer_published_before_copy=True, source_destination_aliasing_not_proven_absent=True)


def _mode(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o = g.code, g.operand
    e('538b5c2408568bf183fb03'); g.branch('77', 'return')
    e('80be8500000000'); g.branch('74', 'store'); e('8b4610578b7c9e1c576af450')
    o('ff15', 'class_api'); e('80be8400000000'); g.branch('74', 'pop'); e('57'); o('ff15', 'cursor_api')
    g.mark('pop'); e('5f'); g.mark('store'); e('899e88000000'); g.mark('return'); e('5e5bc20400')
    _, row = _bind(raw, image, sections, imports, address, g,
                   (('class_api', 'user32.dll', 'SetClassLongA'), ('cursor_api', 'user32.dll', 'SetCursor')))
    return dict(**row, callee_argument_cleanup_bytes=4, accepted_mode_unsigned_maximum=3,
                direct_parent_write_range=dict(field=0x88, bytes=4), mode_greater_than_three_does_not_write=True,
                external_window_and_cursor_effects_proven=False)


def _cookie(raw, image, sections, imports, address, expected):
    g = _ChildGrammar(); e, o = g.code, g.operand
    o('3b0d', 'cookie'); g.branch('75', 'failure'); e('f3c3'); g.mark('failure'); o('e9', 'failure_call')
    m, row = _bind(raw, image, sections, imports, address, g)
    if _word(m, 'cookie') != expected:
        raise ValueError('CG 恢复的保护检查没有使用自身保存的同一 cookie。')
    return dict(**row, cookie_storage=_writable_image_range(raw, image, sections, expected, 4),
                callee_argument_cleanup_bytes=0, matching_cookie_has_complete_normal_return=True,
                mismatching_cookie_tail_preserves_entry_stack=True, failure_child_effects_proven=False)


def bind_native_cg_vm_restore_children(executable, header, vm, frames):
    raw = bytes(executable)
    restore = bind_native_cg_vm_restore(raw, header, vm, frames)
    image, sections = _pe_sections(raw); imports = _import_slots(raw, image)
    own = restore['native_post_main_restore']; addresses = own['helper_addresses']
    older = restore['layout'] == 'signed-word-legacy'
    heap = restore['native_vm_thread_startup']['native_vm_loader']['native_vm_heap_children']['native_vm_heap_paths']
    members = heap['native_vm_member_copy']['native_vm_member_children']
    cleanup = members['native_vm_members']['native_vm_teardown']['native_vm_cleanup']
    application = cleanup['native_vm_application']; allocator = application['native_application_allocator']
    children = dict(exists=_exists(raw, image, sections, imports, addresses['exists']),
                    resize=_resize(raw, image, sections, imports, addresses['destroy'], older))
    if older:
        children['load'] = _legacy_load(raw, image, sections, imports, addresses['load'])
        children['file'] = _file(raw, image, sections, imports, children['load']['helper_addresses']['file'])
        children['convert'] = _legacy_convert(raw, image, sections, imports, children['load']['helper_addresses']['convert'])
        children['stream'] = _legacy_stream(raw, image, sections, imports, addresses['stream'])
        if children['convert']['helper_addresses']['format'] != children['file']['helper_addresses']['format']:
            raise ValueError('CG 旧版恢复没有沿自身一致的错误格式化入口。')
        parent_ranges = [dict(field=0, bytes=8)]
    else:
        children['file'] = _file(raw, image, sections, imports, addresses['load'])
        children['reader'] = _reader(raw, image, sections, imports, addresses['reader'])
        children['string_assign'] = _string_assign(raw, image, sections, imports, children['reader']['helper_addresses']['assign'])
        reader, assign = children['reader'], children['string_assign']
        if (reader['empty_string_address'] != assign['empty_string_address']
                or reader['helper_addresses']['release'] != assign['helper_addresses']['release']
                or assign['helper_addresses']['release'] != cleanup['native_release_bridge']['address']
                or assign['helper_addresses']['allocate'] != members['native_member_allocation_bridges']['string']['address']
                or assign['helper_addresses']['copy'] != own['native_restore_copy_path']['address']):
            raise ValueError('CG 恢复字符串没有复用同来源已完整绑定的空值、分配、释放和复制链。')
        children['mode'] = _mode(raw, image, sections, imports, addresses['mode'])
        _, code = _code(raw, image, sections, own['address'], own['code_bytes'])
        match = _modern_grammar().match(code)
        children['cookie'] = _cookie(raw, image, sections, imports, addresses['cookie'], _word(match, 'cookie'))
        parent_ranges = [children['mode']['direct_parent_write_range'],
                         dict(field=_word(match, 'reader_field'), bytes=4)]
    capacity = restore['native_vm_thread_startup']['native_scheduler_capacity']
    end = capacity['native_base'] + capacity['native_stride'] * capacity['capacity']
    for field in parent_ranges:
        if (field['field'] + field['bytes'] > application['native_application']['allocation_bytes']
                or max(field['field'], capacity['native_base']) < min(field['field'] + field['bytes'], end)):
            raise ValueError('CG 恢复子调用的父对象写入越界或覆盖自身调度线程。')
    functions = list(children.values())
    for index, first in enumerate(functions):
        for second in functions[index + 1:]:
            if max(first['address'], second['address']) < min(first['address'] + first['code_bytes'],
                                                            second['address'] + second['code_bytes']):
                raise ValueError('CG 恢复子调用的完整函数字节发生重叠。')
    resize = children['resize']
    for key in ('file', 'convert', 'stream'):
        if key in children and children[key]['helper_addresses']['resize'] != resize['address']:
            raise ValueError('CG 恢复的文件、解包或复制没有调用自身同一尺寸／清理入口。')
    for key in ('file', 'resize', 'convert'):
        if key in children:
            calls = children[key]['helper_addresses']
            if calls['error_allocate'] != allocator['address'] or calls['throw'] != resize['helper_addresses']['throw']:
                raise ValueError('CG 恢复的错误路径没有沿自身同一分配和异常入口。')
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=restore['layout'],
                native_vm_restore=restore, native_restore_children=children,
                fixed_parent_child_write_ranges=parent_ranges,
                fixed_parent_child_writes_do_not_overlap_own_thread_array_static_bound=True,
                own_complete_restore_IO_reader_buffer_explicit_instruction_paths_static_bound=True,
                own_restore_shared_allocator_release_copy_identity_static_bound=True,
                actual_file_bytes_and_type_read_bounds_proven=False,
                complete_compression_child_effects_proven=False, complete_heap_and_aliasing_effects_proven=False,
                complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False, initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False, source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
