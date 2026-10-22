"""Own legacy restore inflate control/state lifecycle; not a decoder grant.

Complete explicit top-level instruction paths, state table, callbacks and
checksum are bound. The block decoder and external heap/callback/exception,
aliasing, input and output bounds remain separate. No native code executes.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_heap_paths import _word
from .native_cg_vm_application import _import_slots
from .native_cg_vm_restore_children import bind_native_cg_vm_restore_children, _ChildGrammar, _bind

SCHEMA = 'fvp-native-cg-vm-restore-inflate/1'
MASK = 2**32 - 1


def _native_adler32_witness(data, initial=1):
    """Immutable-buffer arithmetic witness; not original machine execution."""
    if type(initial) is not int or not 0 <= initial <= MASK:
        raise ValueError('CG 解包校验初值必须是原生32位位模式。')
    if data is None:
        return 1
    data = bytes(data)
    if len(data) > MASK:
        raise ValueError('CG 解包校验数据长度超过原生32位。')
    low, high = initial & 0xffff, initial >> 16
    for offset in range(0, len(data), 5552):
        for value in data[offset:offset + 5552]:
            low = (low + value) & MASK
            high = (high + low) & MASK
        low %= 65521; high %= 65521
    return ((high << 16) | low) & MASK


def _init(raw, image, sections, imports, address):
    g = _ChildGrammar(); g.code('8b44240c8b4c24088b54240450516a0f52'); g.call('init2')
    g.code('83c410c3'); _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=0, native_window_bits=15,
                entry_SP_arguments=dict(stream=4, version=8, stream_bytes=12), own_argument_forwarding_static_bound=True)


def _init2(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('8b44240c5733ff3bc7'); g.branch('0f84','version_error',wide=True)
    e('803831'); g.branch('0f85','version_error',wide=True); e('837c241438')
    g.branch('0f85','version_error',wide=True); e('568b74240c3bf7'); g.branch('0f84','stream_error',wide=True)
    e('397e20897e18'); g.branch('75','release_field'); o('c74620','allocate'); e('897e28')
    g.mark('release_field'); e('397e24'); g.branch('75','state'); o('c74624','release')
    g.mark('state'); e('8b46286a186a0150ff562083c40c3bc789461c'); g.branch('74','allocation_error')
    e('8978148b4e1c89790c8b4c24103bcf'); g.branch('7d','window')
    e('8b561cf7d9c7420c01000000'); g.mark('window'); e('83f908'); g.branch('7c','bad_window')
    e('83f90f'); g.branch('7f','bad_window'); e('8b461c8948108b461cba01000000d3e233c95239780c0f95c149')
    o('81e1','checksum'); e('5156'); c('block_new'); e('8b561c8942148b461c8b481483c40c3bcf56')
    g.branch('75','reset'); c('end0'); e('83c404'); g.mark('allocation_error'); e('5eb8fcffffff5fc3')
    g.mark('reset'); c('reset'); e('83c4045e33c05fc3'); g.mark('bad_window'); e('56'); c('end1')
    e('83c404'); g.mark('stream_error'); e('5eb8feffffff5fc3'); g.mark('version_error'); e('b8faffffff5fc3')
    m, row = _bind(raw, image, sections, imports, address, g)
    for key in ('allocate','release','checksum'): _relocated(raw, image, sections, _word(m,key), executable=True)
    if row['helper_addresses']['end0'] != row['helper_addresses']['end1']:
        raise ValueError('CG 解包初始化的错误清理没有调用自身同一退出入口。')
    return dict(**row, native_default_allocate_address=_word(m,'allocate'), native_default_release_address=_word(m,'release'),
                native_checksum_address=_word(m,'checksum'), callee_argument_cleanup_bytes=0,
                native_version_check_is_only_major_ASCII_1=True, native_required_stream_bytes=56,
                native_state_allocation=dict(items=1, item_bytes=24),
                callbacks_only_defaulted_if_null=True, existing_callback_identity_not_assumed=True,
                successful_window_bits_inclusive=[8,15], negative_window_bits_select_raw_mode=True,
                raw_mode_sets_checksum_callback_zero=True, native_default_opaque_zero_written_only_with_default_allocator=True,
                stream_fields=dict(state=28,allocate=32,release=36,opaque=40,message=24),
                native_returns=dict(version_error=-6,stream_error=-2,allocation_error=-4,success=0),
                allocation_and_dynamic_callback_target_stability_proven=False)


def _reset(raw, image, sections, imports, address):
    g = _ChildGrammar(); e = g.code
    e('8b44240433d23bc2'); g.branch('74','error'); e('8b481c3bca'); g.branch('74','error')
    e('568950148950088950188b710cf7de1bf65283e6078931508b401c8b481451'); g.call('block_reset')
    e('83c40c33c05ec3'); g.mark('error'); e('b8feffffffc3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=0, stream_fields_cleared=[8,20,24],
                native_mode_after_reset='7 iff state.raw_mode is nonzero, otherwise 0',
                other_stream_fields_not_assumed_cleared=True)


def _end(raw, image, sections, imports, address):
    g = _ChildGrammar(); e = g.code
    e('568b74240885f6'); g.branch('74','error'); e('8b461c85c0'); g.branch('74','error')
    e('8b4e2485c9'); g.branch('74','error'); e('8b401485c0'); g.branch('74','release')
    e('5650'); g.call('block_end'); e('83c408'); g.mark('release')
    e('8b461c8b4e285051ff562483c408c7461c0000000033c05ec3')
    g.mark('error'); e('b8feffffff5ec3'); _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=0, clears_stream_state_pointer_after_release=True,
                release_argument_fields=dict(callback=36,opaque=40,state=28),
                other_stream_fields_not_assumed_cleared=True, callbacks_and_external_release_effects_proven=False)


def _block_new(raw, image, sections, imports, address):
    g = _ChildGrammar(); e = g.code
    e('56578b7c240c8b47286a406a0150ff57208bf083c40c85f6'); g.branch('74','failure')
    e('8b4f2868a00500006a0851ff572083c40c85c0894624'); g.branch('75','window')
    e('8b57285652ff572483c408'); g.mark('failure'); e('5f33c05ec3'); g.mark('window')
    e('8b4728538b5c2418536a0150ff572083c40c85c0894628'); g.branch('75','initialize')
    e('8b4e248b57285152ff57248b47285650ff572483c4105b5f33c05ec3')
    g.mark('initialize'); e('8b4c24146a0003c3575689462c894e38c70600000000'); g.call('block_reset')
    e('83c40c5b5f8bc65ec3'); _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=0,
                native_allocation_requests=[dict(items=1,item_bytes=64),dict(items=8,item_bytes=1440),
                                            dict(items=1,item_bytes='caller window bytes')],
                complete_all_explicit_partial_allocation_cleanup_paths_static_bound=True,
                native_buffer_fields=dict(tables=36,window=40,window_end=44,read=48,write=52,checksum_callback=56,checksum=60),
                pointer_addition_wrap_and_heap_nonaliasing_proven=False)


def _block_reset(raw, image, sections, imports, address):
    g = _ChildGrammar(); e = g.code
    e('8b44240c85c0568b74240857'); g.branch('74','mode'); e('8b4e3c8908'); g.mark('mode')
    e('8b0683f8048b7c2410'); g.branch('74','release'); e('83f805'); g.branch('75','codes')
    g.mark('release'); e('8b560c8b47285250ff572483c408'); g.mark('codes'); e('833e06')
    g.branch('75','clear'); e('8b4e045751'); g.call('codes_end'); e('83c408'); g.mark('clear')
    e('8b46288946348946308b463885c0c70600000000c7461c00000000c7462000000000')
    g.branch('74','return'); e('6a006a006a00ffd089463c83c40c894730'); g.mark('return'); e('5f5ec3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=0, releases_dynamic_lengths_only_in_modes=[4,5],
                releases_code_object_only_in_mode=6, optional_old_checksum_destination_entry_SP_displacement=12,
                checksum_callback_called_with_three_zero_arguments=True,
                checksum_callback_return_written_to_fields=dict(block=60,stream=48),
                mode_bit_count_bit_buffer_zeroed=True, read_and_write_reset_to_window_start=True,
                dynamic_callback_effects_and_targets_at_each_call_proven=False)


def _block_end(raw, image, sections, imports, address):
    g = _ChildGrammar(); e = g.code
    e('568b7424088b0683f804578b7c2410'); g.branch('74','release'); e('83f805'); g.branch('75','codes')
    g.mark('release'); e('8b460c8b4f285051ff572483c408'); g.mark('codes'); e('833e06')
    g.branch('75','clear'); e('8b56045752'); g.call('codes_end'); e('83c408'); g.mark('clear')
    e('8b462833c98946348946308b46383bc1890e894e1c894e20'); g.branch('74','free')
    e('515151ffd089463c83c40c894730'); g.mark('free')
    e('8b46288b4f285051ff57248b56248b47285250ff57248b4f285651ff572483c4185f33c05ec3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=0, optional_mode_dependent_release_order_static_bound=True,
                unconditional_final_release_order=['window','tables','block_state'],
                checksum_callback_called_with_three_zero_arguments=True, caller_state_pointer_reset_not_done_here=True,
                dynamic_callback_effects_and_targets_at_each_call_proven=False)


def _codes_end(raw, image, sections, imports, address):
    g = _ChildGrammar(); g.code('8b442404508b44240c8b482851ff502483c408c3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=0, caller_object_and_opaque_forwarded_to_dynamic_release=True)


def _default_allocate(raw, image, sections, imports, address):
    g = _ChildGrammar(); g.code('8b44240c8b4c24085051'); g.operand('ff15','calloc_api'); g.code('83c408c3')
    _, row = _bind(raw, image, sections, imports, address, g, (('calloc_api','msvcr71.dll','calloc'),))
    return dict(**row, callee_argument_cleanup_bytes=0, ignores_opaque_entry_SP_argument=True,
                forwards_items_and_item_bytes_to_own_calloc=True, external_calloc_heap_effects_proven=False)


def _default_release(raw, image, sections, imports, address):
    g = _ChildGrammar(); g.code('8b44240850'); g.operand('ff15','free_api'); g.code('59c3')
    _, row = _bind(raw, image, sections, imports, address, g, (('free_api','msvcr71.dll','free'),))
    return dict(**row, callee_argument_cleanup_bytes=0, ignores_opaque_entry_SP_argument=True,
                forwards_pointer_to_own_free=True, external_free_heap_effects_proven=False)


def _checksum(raw, image, sections, imports, address):
    g = _ChildGrammar(); e = g.code
    e('568b74240c578b7c240c8bcf81e1ffff0000c1ef1085f6'); g.branch('75','buffer')
    e('5fb8010000005ec3'); g.mark('buffer'); e('538b5c241885db'); g.branch('0f86','return',wide=True)
    e('5590'); g.mark('chunk'); e('81fbb01500008bc3'); g.branch('72','selected'); e('b8b0150000')
    g.mark('selected'); e('2bd883f810'); g.branch('0f8c','remainder',wide=True)
    e('8bd0c1ea048beaf7ddc1e50403c5'); g.branch('eb','unrolled'); e('8d9b00000000'); g.mark('unrolled')
    e('0fb62e03cd')
    for n in range(1,16): e('0fb66e' + bytes((n,)).hex() + '03f903cd')
    e('03f983c6104a'); g.branch('0f85','unrolled',wide=True); g.mark('remainder'); e('85c0')
    g.branch('74','reduce'); e('8d4900'); g.mark('byte'); e('0fb61603ca4603f948'); g.branch('75','byte')
    g.mark('reduce'); e('8bc133d2b9f1ff0000f7f18bc7bff1ff00008bca33d2f7f785db8bfa')
    g.branch('0f87','chunk',wide=True); e('5d'); g.mark('return'); e('8bc75bc1e0105f0bc15ec3')
    _, row = _bind(raw, image, sections, imports, address, g)
    return dict(**row, callee_argument_cleanup_bytes=0, native_algorithm='Adler-32', native_modulus=65521,
                native_chunk_maximum=5552, native_unrolled_bytes=16, native_arithmetic_wraps_32_bits=True,
                null_buffer_returns_one_independent_of_initial_and_length=True,
                zero_length_nonnull_buffer_returns_initial_unchanged=True,
                immutable_valid_nonaliasing_input_required=True, native_machine_code_executed=False)


def _step(raw, image, sections, imports, address):
    g = _ChildGrammar(); e, o, c = g.code, g.operand, g.call
    e('568b74240885f6'); g.branch('0f84','pre_error',wide=True); e('8b461c85c0')
    g.branch('0f84','pre_error',wide=True); e('833e00'); g.branch('0f84','pre_error',wide=True)
    e('8b00538b5c241033c983fb040f95c15557bffbffffff4983e1fb83f80d8be9')
    g.branch('0f87','error',wide=True); e('bb05000000'); g.branch('eb','dispatch'); e('8d4900')
    g.mark('dispatch'); g.jump('eax','table'); g.mark('state0'); e('8b460485c0')
    g.branch('0f84','progress',wide=True)
    e('8b56088b4e1c48428956088b168946040fb6028941048b461c8b50048b0e80e20f4180fa088bfd890e')
    g.branch('74','method'); e('c7000d0000008b461c'); o('c74618','message0'); e('895804')
    g.branch('e9','redispatch',wide=True); g.mark('method'); e('8b48048b5010c1e90483c1083bca')
    g.branch('76','header'); e('c7000d000000'); o('c74618','message1'); g.branch('e9','error_marker',wide=True)
    g.mark('header'); e('c70001000000'); g.mark('state1'); e('8b460485c0'); g.branch('0f84','progress',wide=True)
    e('8b4e1c48894604ff46088b060fb6104089068b4104c1e00803c28954241433d2bb1f000000f7f38bfdbb0500000085d2')
    g.branch('74','flags'); e('c7010d0000008b461c'); o('c74618','message2'); e('895804')
    g.branch('e9','redispatch',wide=True); g.mark('flags'); e('f644241420'); g.branch('0f85','dictionary',wide=True)
    e('c70107000000'); g.branch('e9','redispatch',wide=True); g.mark('state7'); e('8b4e1c8b5114575652')
    c('block_step'); e('8bf883c40c83fffd'); g.branch('75','block_status'); e('8b461cc7000d0000008b4e1cc7410400000000')
    g.branch('e9','redispatch',wide=True); g.mark('block_status'); e('85ff'); g.branch('75','completion'); e('8bfd')
    g.mark('completion'); e('83ff01'); g.branch('0f85','progress',wide=True); e('8b461c8d50048b40145256508bfd')
    c('block_reset'); e('8b461c8b480c83c40c85c9'); g.branch('74','trailer'); e('c7000c000000')
    g.branch('e9','redispatch',wide=True); g.mark('trailer'); e('c70008000000'); g.mark('state8')
    e('8b460485c0'); g.branch('0f84','progress',wide=True)
    e('8b56088b0e488946048b461c428956080fb611c1e2188950088b068b4e1c4089068bfdc70109000000')
    g.mark('state9'); e('8b460485c0'); g.branch('0f84','progress',wide=True)
    e('8b1648894604ff46080fb60a8b461c8b5008c1e11003d18950088b068b561c4089068bfdc7020a000000')
    g.mark('state10'); e('8b460485c0'); g.branch('0f84','progress',wide=True)
    e('8b56088b0e488946048b461c428956080fb6118b4808c1e20803ca894808ff068b461c8bfdc7000b000000')
    g.mark('state11'); e('8b460485c0'); g.branch('74','progress')
    e('8b56088b0e488946048b461c428956080fb611015008ff068b461c8b48043b48088bfd')
    g.branch('0f84','finished',wide=True); e('c7000d000000'); o('c74618','message3')
    g.mark('error_marker'); e('8b561c895a04'); g.mark('redispatch'); e('8b461c8b0083f80d')
    g.branch('0f86','dispatch',wide=True); e('5f5d5bb8feffffff5ec3'); g.mark('progress'); e('8bc75f5d5b5ec3')
    g.mark('dictionary'); e('8b4e1cc70102000000'); g.mark('state2'); e('8b460485c0'); g.branch('74','progress')
    e('8b56088b4e1c48428956088b168946040fb602c1e0188941088b068b561c4089068bfdc70203000000')
    g.mark('state3'); e('8b460485c0'); g.branch('74','progress')
    e('8b56088b0e488946048b461c428956080fb6118b4808c1e21003ca894808ff068b461c8bfdc70004000000')
    g.mark('state4'); e('8b460485c0'); g.branch('74','progress')
    e('8b0e48894604ff46080fb6118b461c8b4808c1e20803ca894808ff068b461c8bfd8918')
    g.mark('state5'); e('8b460485c0'); g.branch('0f84','progress',wide=True)
    e('8b56088b0e488946048b461c428956080fb611015008ff068b461c8b48085f5d894e305bc70006000000b8020000005ec3')
    g.mark('state6'); e('8b561cc7020d0000008b461c'); o('c74618','message4'); e('c7400400000000')
    g.mark('error'); e('5f5d5bb8feffffff5ec3'); g.mark('finished'); e('8b4e1cc7010c000000')
    g.mark('state12'); e('5f5d5bb8010000005ec3'); g.mark('state13'); e('5f5d5bb8fdffffff5ec3')
    g.mark('pre_error'); e('b8feffffff5ec3')
    m, row = _bind(raw, image, sections, imports, address, g,
                   data=tuple(('message' + str(n),1) for n in range(5)))
    table = _word(m,'table'); offset = _relocated(raw, image, sections, table, executable=True, length=56)
    expected = [address + m.start('state' + str(n)) for n in range(14)]
    actual = list(struct.unpack_from('<14I',raw,offset))
    if table != address + m.end() + 2 or raw[row['offset'] + m.end():row['offset'] + m.end() + 2] != b'\x8b\xff' or actual != expected:
        raise ValueError('CG 解包状态分发表没有完整对应自身14条路径和受限索引。')
    return dict(**row, callee_argument_cleanup_bytes=0,
                state_dispatch=dict(address=table,bytes=56,native_unsigned_maximum=13,targets=actual),
                native_state_count=14, complete_own_state_dispatch_table_static_bound=True,
                input_consumption_updates_pointer_available_and_total_fields=True,
                native_returns=dict(stream_error=-2,data_error=-3,buffer_error=-5,progress=0,done=1,dictionary=2),
                initial_progress_return_is_minus5_for_flush4_otherwise_zero=True,
                complete_block_decoder_and_buffer_boundary_effects_proven=False,
                state_and_data_immutability_and_termination_proven=False)


def bind_native_cg_vm_restore_inflate(executable, header, vm, frames):
    raw = bytes(executable)
    children = bind_native_cg_vm_restore_children(raw, header, vm, frames)
    older = children['layout'] == 'signed-word-legacy'
    image, sections = _pe_sections(raw); imports = _import_slots(raw,image)
    inflate = None
    if older:
        calls = children['native_restore_children']['convert']['helper_addresses']
        paths = dict(init=_init(raw,image,sections,imports,calls['compression_init']),
                     end=_end(raw,image,sections,imports,calls['compression_end']),
                     step=_step(raw,image,sections,imports,calls['compression_step']))
        paths['init2'] = _init2(raw,image,sections,imports,paths['init']['helper_addresses']['init2'])
        entry = paths['init2']
        paths['reset'] = _reset(raw,image,sections,imports,entry['helper_addresses']['reset'])
        paths['block_new'] = _block_new(raw,image,sections,imports,entry['helper_addresses']['block_new'])
        paths['block_reset'] = _block_reset(raw,image,sections,imports,paths['reset']['helper_addresses']['block_reset'])
        paths['block_end'] = _block_end(raw,image,sections,imports,paths['end']['helper_addresses']['block_end'])
        paths['codes_end'] = _codes_end(raw,image,sections,imports,paths['block_reset']['helper_addresses']['codes_end'])
        paths['default_allocate'] = _default_allocate(raw,image,sections,imports,entry['native_default_allocate_address'])
        paths['default_release'] = _default_release(raw,image,sections,imports,entry['native_default_release_address'])
        paths['checksum'] = _checksum(raw,image,sections,imports,entry['native_checksum_address'])
        if (entry['helper_addresses']['end0'] != paths['end']['address']
                or paths['step']['helper_addresses']['block_reset'] != paths['block_reset']['address']
                or paths['block_new']['helper_addresses']['block_reset'] != paths['block_reset']['address']
                or paths['block_end']['helper_addresses']['codes_end'] != paths['codes_end']['address']):
            raise ValueError('CG 解包状态和清理没有沿同一来源一致的自身调用链。')
        rows = list(paths.values())
        for index, first in enumerate(rows):
            for second in rows[index + 1:]:
                if max(first['address'],second['address']) < min(first['address'] + first['code_bytes'],second['address'] + second['code_bytes']):
                    raise ValueError('CG 解包的完整函数字节互相重叠。')
        version = children['native_restore_children']['convert']['data_references']['compression_version']
        if version['bytes'] != '31':
            raise ValueError('CG 恢复解包调用没有传入自身可接受的原生版本首字节。')
        inflate = dict(paths=paths, remaining_block_decoder_address=paths['step']['helper_addresses']['block_step'],
                       own_complete_explicit_top_level_state_and_lifecycle_instruction_paths_static_bound=True,
                       own_caller_callback_cells_initialized_zero_static_bound=True,
                       subsequent_dynamic_callback_identities_unconditionally_stable=False,
                       all_block_decoder_compression_effects_and_termination_proven=False,
                       external_heap_callback_SEH_and_aliasing_effects_proven=False,
                       native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=children['layout'],
                native_vm_restore_children=children,native_restore_inflate=inflate,
                own_legacy_inflate_control_state_lifecycle_paths_static_bound=older,
                modern_restore_has_no_legacy_compressed_convert_path=not older,
                complete_compression_child_effects_proven=False, actual_file_bytes_and_type_read_bounds_proven=False,
                complete_heap_and_aliasing_effects_proven=False,complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
