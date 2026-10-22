"""Own full save-I/O paths and local unwind, not successful native saving.

The legacy compressor and the modern C++ exception engine are distinct
descendants. Their dynamic effects, file results, owner lifetime and actual
state round-trip remain unproven. This module never executes original code.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots
from .native_cg_vm_cleanup import _code
from .native_cg_vm_heap_paths import _word, _callee
from .native_cg_vm_heap_children import _data
from .native_cg_vm_startup import _record
from .native_cg_vm_restore_children import _ChildGrammar, _bind
from .native_cg_vm_lifecycle import _parent
from .native_cg_vm_state_pack import bind_native_cg_vm_state_pack

SCHEMA = 'fvp-native-cg-vm-state-pack-children/1'


def _file_write(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('5153'); o('8b1d', 'open_api'); e('5556578b7c24186a0068000000086a016a006a0068000000c0578be9ffd38bf083feff')
    g.branch('75', 'opened')
    e('6a0068000000086a056a006a0068000000c057ffd38bf083feff'); g.branch('75', 'opened')
    e('6880000000'); c('error_allocate'); e('83c40485c0'); g.branch('74', 'no_message')
    e('57'); o('68', 'error_format'); e('50'); c('format'); e('83c40c'); g.branch('eb', 'raise')
    g.mark('no_message'); e('33c0'); g.mark('raise'); e('89442418'); o('68', 'error_type')
    e('8d44241c50'); c('throw'); g.mark('opened')
    e('8b55048b45006a008d4c241451525056'); o('ff15', 'write_api'); e('56'); o('ff15', 'close_api')
    e('5f5e5d5b59c20400')
    _, row = _bind(raw, image, sections, imports, address, g,
        tuple((key, 'kernel32.dll', name) for key, name in (
            ('open_api', 'CreateFileA'), ('write_api', 'WriteFile'), ('close_api', 'CloseHandle'))),
        (('error_format', 1), ('error_type', 1)))
    return dict(**row, callee_argument_cleanup_bytes=4, direct_object_fields=dict(pointer=0, size=4),
        first_creation_disposition=1, fallback_creation_disposition=5, requested_access=0xc0000000,
        sharing_mode=0, file_flags=0x08000000, fallback_truncates_existing_file=True,
        WriteFile_result_and_actual_bytes_written_not_checked=True, CloseHandle_result_not_checked=True,
        error_throw_return_would_fall_through_with_invalid_handle=True, actual_file_success_proven=False)


def _append(raw, image, sections, imports, address, older):
    g = _ChildGrammar(); e, c = g.code, g.call
    if older:
        e('538bd98b4b088b4304558b6c240c03cd3bc85657'); g.branch('7e', 'ready')
        e('8b4b0c8d14018d442aff99f7f90fafc1508bcb'); c('resize'); g.mark('ready')
        e('8b43088b3b8b74241803f88bcd8bc1c1e902f3a58bc883e103f3a4'
          '8b43085f5e03c55d8943085bc20800')
    else:
        e('568bf18b4e088b4604578b7c240c03cf3bc8'); g.branch('7e', 'ready')
        e('8b4e0c8d14018d443aff99f7f90fafc1508bce'); c('resize'); g.mark('ready')
        e('8b0e8b442410034e08575051'); c('copy'); e('017e0883c40c5f5ec20800')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=8,
        direct_object_fields=dict(pointer=0, signed_capacity=4, cursor=8, rounding_quantum=12),
        growth_uses_signed_compare_IDIV_and_32bit_wrap=True, cursor_advance_is_requested_count=True,
        inline_forward_REP_copy=older, DF_zero_required=older,
        source_destination_aliasing_and_requested_count_bounds_proven=False)


def _serialize(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('538bd98b0356'); o('3d', 'empty'); g.branch('75', 'nonempty')
    e('8b74240c8b4e088b460483c1023bc8'); g.branch('7e', 'empty_ready')
    e('8b4e0c8d44010199f7f90fafc1508bce'); c('resize0'); g.mark('empty_ready')
    e('8b56088b0633c966890c02834608025e5bc20400'); g.mark('nonempty')
    e('8d50018d9b00000000'); g.mark('scan'); e('8a084084c9'); g.branch('75', 'scan')
    e('8b74240c2bc28b560840570fb7f88b460483c2023bd0'); g.branch('7e', 'nonempty_ready')
    e('8b4e0c8d44010199f7f90fafc1508bce'); c('resize1'); g.mark('nonempty_ready')
    e('8b46088b0e66893c08834608028b130fbfc752508bce'); c('append'); e('5f5e5bc20400')
    m, row = _bind(raw, image, sections, imports, address, g, data=(('empty', 1),))
    if row['data_references']['empty']['bytes'] != '00':
        raise ValueError('CG 状态字符串保存没有使用自身空字符串。')
    return dict(**row, empty_string_address=_word(m, 'empty'), callee_argument_cleanup_bytes=4,
        explicit_nonempty_path_after_first_return_bound=True, count_prefix_bytes=2,
        empty_sentinel_writes_zero_count=True, nonempty_count_is_strlen_plus_NUL_modulo_16bit=True,
        append_count_is_sign_extended_from_16bit=True, native_NUL_scan_is_unbounded=True,
        native_string_count_and_read_write_round_trip_proven=False)


def _legacy_write(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('6aff'); o('68', 'seh'); e('64a100000000506489250000000083ec405355565733ff8bd9'
        '897c2410897c24148b6c24688d850c000100508d4c2414897c245c'); c('resize0')
    e('3bef8b442410c60068c640017ac6400263c64003318b4b04894804896808')
    g.branch('74', 'prefix_done'); e('8b7424648bcd8bd1c1e9028d780cf3a58bca83e103f3a433ff')
    g.mark('prefix_done'); e('8b0b8b53046a38'); o('68', 'compression_version')
    e('894c24208d4c24208d44280c6a09bb0000010051897c2448897c244c897c24508954242c89442434895c2438')
    c('compression_init'); e('8d5424286a0452'); c('compression_step')
    e('8b74242c83c41883f801'); g.branch('74', 'finished'); e('8bff'); g.mark('continue')
    e('3bc7'); g.branch('0f85', 'error', wide=True); e('397c2428'); g.branch('75', 'step_again')
    e('81c600000100568d4c2414'); c('resize1')
    e('8b7424148b4424108d8c060000ffff894c2424895c2428'); g.mark('step_again')
    e('8d5424186a0452'); c('compression_step_repeat'); e('83c40883f801'); g.branch('75', 'continue')
    g.mark('finished'); e('2b742428568d4c2414'); c('resize2'); e('8d44241850'); c('compression_end')
    e('8b4c246483c404518d4c2414'); c('file_write'); e('8b4424103bc7'); g.branch('74', 'cleanup_done')
    e('5057'); o('ff15', 'heap_api'); e('50'); o('ff15', 'free_api'); g.mark('cleanup_done')
    e('8b4c24505f5e5d5b64890d0000000083c44cc20c00'); g.mark('error')
    e('6880000000'); c('error_allocate'); e('83c4043bc7'); g.branch('74', 'no_message')
    o('68', 'error_format'); e('50'); c('format'); e('83c408'); g.branch('eb', 'raise')
    g.mark('no_message'); e('33c0'); g.mark('raise'); o('68', 'error_type')
    e('8d54246c5289442470'); c('throw'); e('cc')
    m, row = _bind(raw, image, sections, imports, address, g,
        (('heap_api', 'kernel32.dll', 'GetProcessHeap'), ('free_api', 'kernel32.dll', 'HeapFree')),
        (('compression_version', 1), ('error_format', 1), ('error_type', 1)))
    return dict(**row, local_seh_address=_word(m, 'seh'), callee_argument_cleanup_bytes=12,
        native_compression_header_magic_hex='687a6331', header_fields=dict(output_bytes=4, prefix_bytes=8),
        raw_prefix_starts_at=12, compression_level=9, compression_stream_structure_bytes=0x38,
        grow_chunk_bytes=0x10000, compressed_loop_repeats_on_zero_until_one_or_error=True,
        full_error_path_after_normal_return_bound=True, exception_child_return_falls_into_INT3=True,
        native_growth_and_prefix_lengths_wrap_32bit=True, DF_zero_required=True,
        complete_compression_child_effects_and_termination_proven=False, actual_compressed_file_round_trip_proven=False)


def _destructor(raw, image, sections, imports, address):
    g = _ChildGrammar(); g.code('6a00'); g.call('resize'); g.code('c3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, native_buffer_resize_request=0, actual_zero_count_release_and_owner_lifetime_proven=False)


def _common_seh(raw, image, sections, imports, address, older):
    g = _ChildGrammar()
    if older:
        g.operand('ff25', 'handler_api')
        _, row = _bind(raw, image, sections, imports, address, g,
            (('handler_api', 'msvcr71.dll', '__CxxFrameHandler'),))
        return dict(**row, terminal_import_tail_without_return=True,
            complete_external_CxxFrameHandler_effects_proven=False)
    g.code('558bec83ec08535657fc8945fc33c0505050ff75fcff7514ff7510ff750cff7508')
    g.call('engine'); g.code('83c4208945f85f5e5b8b45f88be55dc3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, clears_direction_flag=True, passes_FuncInfo_in_EAX_to_engine=True,
        extra_zero_arguments=3, original_exception_arguments=4, engine_result_returned_in_EAX=True,
        complete_CxxFrameHandler_engine_effects_proven=False)


def _writer_seh(raw, image, sections, address, common, dispose):
    at, code = _code(raw, image, sections, address, 64); g = _ChildGrammar()
    g.operand('b8', 'info'); g.operand('e9', 'common_call'); m = g.match(code)
    if _callee(raw, image, sections, address, m, 'common_call') != common:
        raise ValueError('CG 旧版压缩写入没有沿自身公共异常入口。')
    info = _word(m, 'info'); info_at = _relocated(raw, image, sections, info, executable=False, length=28)
    words = list(struct.unpack_from('<7I', raw, info_at))
    if words[0:2] != [0x19930520, 1] or any(words[3:]):
        raise ValueError('CG 旧版压缩写入的异常记录不是自身单对象清理。')
    map_at = _relocated(raw, image, sections, words[2], executable=False, length=8)
    state, unwind = struct.unpack_from('<2I', raw, map_at)
    if state != 0xffffffff:
        raise ValueError('CG 旧版压缩写入的异常清理状态不一致。')
    u_at, u_code = _code(raw, image, sections, unwind, 64); ug = _ChildGrammar()
    ug.code('8d4db4'); ug.operand('e9', 'dispose_call'); u = ug.match(u_code)
    if _callee(raw, image, sections, unwind, u, 'dispose_call') != dispose:
        raise ValueError('CG 旧版压缩写入没有使用自身同一缓冲区析构。')
    return dict(**_record(address, at, m[0]), func_info=_data(raw, image, sections, info, 28),
        func_info_words=words, unwind_map=_data(raw, image, sections, words[2], 8), unwind_to_state=-1,
        local_unwind_thunk=_record(unwind, u_at, u[0]), local_buffer_EBP_displacement=-0x4c,
        own_explicit_local_SEH_and_unwind_static_bound=True, actual_exception_dispatch_and_cleanup_proven=False)


def bind_native_cg_vm_state_pack_children(executable, header, vm, frames):
    raw = bytes(executable); parent = bind_native_cg_vm_state_pack(raw, header, vm, frames)
    image, sections = _pe_sections(raw); imports = _import_slots(raw, image)
    older = parent['layout'] == 'signed-word-legacy'; pack = parent['native_exit_state_pack']
    restore = _parent(parent, 'fvp-native-cg-vm-restore-children/1')['native_restore_children']
    seh = pack['own_local_SEH']; helpers = pack['helper_addresses']
    dispose = seh['local_unwind_thunk']['destructor_address']; common = seh['common_exception_handler_address']
    children = dict(unwind_destructor=_destructor(raw, image, sections, imports, dispose),
        common_exception_handler=_common_seh(raw, image, sections, imports, common, older))
    if older:
        children['append'] = _append(raw, image, sections, imports, helpers['append0'], True)
        children['compressed_write'] = _legacy_write(raw, image, sections, imports, helpers['write'])
        writer = children['compressed_write']; w_calls = writer['helper_addresses']
        children['file_write'] = _file_write(raw, image, sections, imports, w_calls['file_write'])
        children['writer_seh'] = _writer_seh(raw, image, sections, writer['local_seh_address'], common, dispose)
        if (w_calls['compression_step'] != w_calls['compression_step_repeat'] or
            writer['data_references']['compression_version'] != restore['convert']['data_references']['compression_version']):
            raise ValueError('CG 旧版保存压缩的重复步进或版本不是自身同一链路。')
        residual = {k:v for k,v in w_calls.items() if k.startswith('compression_') or k in ('format', 'throw')}
    else:
        children['serialize'] = _serialize(raw, image, sections, imports, helpers['serialize'])
        children['append'] = _append(raw, image, sections, imports, children['serialize']['helper_addresses']['append'], False)
        children['file_write'] = _file_write(raw, image, sections, imports, helpers['write'])
        serializer = children['serialize']; reader = restore['reader']
        copy = _parent(parent, 'fvp-native-cg-vm-member-copy/1')['native_member_copy_paths']['string']['address']
        if (serializer['empty_string_address'] != reader['empty_string_address'] or
            children['append']['helper_addresses']['copy'] != copy):
            raise ValueError('CG 状态字符串保存没有使用自身恢复空值和完整复制链。')
        residual = dict(children['common_exception_handler']['helper_addresses'])
    resize = restore['resize']['address']
    for row in children.values():
        if any(v != resize for k,v in row.get('helper_addresses', {}).items() if k.startswith('resize')):
            raise ValueError('CG 保存与异常清理没有使用自身同一完整缓冲区入口。')
    for key in ('file_write', 'compressed_write'):
        if key in children:
            calls = children[key]['helper_addresses']; read_calls = restore['file']['helper_addresses']
            if any(calls[k] != read_calls[k] for k in ('error_allocate', 'format', 'throw')):
                raise ValueError('CG 保存错误路径没有沿自身恢复的分配、格式化和抛出入口。')
    file_write = children['file_write']
    residual.update({'file_'+k:v for k,v in file_write['helper_addresses'].items() if k in ('format', 'throw')})
    functions = [r for r in children.values() if 'code_bytes' in r]
    functions += [children['writer_seh']['local_unwind_thunk']] if older else []
    for i, first in enumerate(functions):
        for second in functions[i+1:]:
            if max(first['address'], second['address']) < min(first['address']+first['code_bytes'], second['address']+second['code_bytes']):
                raise ValueError('CG 保存子调用的完整原生函数发生重叠。')
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=parent['layout'],
        native_vm_state_pack=parent, native_state_pack_children=children, remaining_child_addresses=residual,
        own_complete_save_IO_append_and_local_unwind_paths_static_bound=True,
        own_modern_string_writer_and_reader_identity_static_bound=not older,
        own_legacy_compressed_writer_envelope_and_local_SEH_static_bound=older,
        actual_file_bytes_and_native_state_round_trip_proven=False, complete_compression_child_effects_proven=False,
        same_live_instance_lifetime_proven=False, complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False, initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False, complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
