"""Own legacy save-compressor control and buffers, not a live encoder grant."""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots
from .native_cg_vm_heap_paths import _word
from .native_cg_vm_restore_children import _ChildGrammar, _bind
from .native_cg_vm_restore_inflate import _default_allocate, _default_release
from .native_cg_vm_lifecycle import _parent
from .native_cg_vm_state_pack_children import bind_native_cg_vm_state_pack_children

SCHEMA = 'fvp-native-cg-vm-save-deflate/1'


def _init(raw,image,sections,imports,address):
    g = _ChildGrammar(); g.code('8b4424108b4c240c8b542408508b442408516a006a086a0f6a085250')
    g.call('init2'); g.code('83c420c3')
    _,row = _bind(raw,image,sections,imports,address,g)
    return dict(**row, method=8,window_bits=15,memory_level=8,strategy=0,
        entry_SP_arguments=dict(stream=4,level=8,version=12,stream_bytes=16))


def _init2(raw,image,sections,imports,address):
    g = _ChildGrammar(); e,o,c = g.code,g.operand,g.call
    e('8b44241c535533d233ed3bc2'); g.branch('0f84','version_error',True)
    o('8b0d','version_slot'); e('8a003a01'); g.branch('0f85','version_error',True)
    e('837c242838'); g.branch('0f85','version_error',True)
    e('578b7c24103bfa'); g.branch('75','stream'); g.mark('argument_error'); e('5f5db8feffffff5bc3')
    g.mark('stream'); e('395720895718'); g.branch('75','allocate_ready')
    o('c74720','allocate'); e('895728'); g.mark('allocate_ready'); e('395724')
    g.branch('75','release_ready'); o('c74724','release'); g.mark('release_ready')
    e('8b4c241483f9ff'); g.branch('75','level_ready'); e('c7442414060000008b4c2414')
    g.mark('level_ready'); e('8b5c241c3bda'); g.branch('7d','window_ready'); e('bd01000000f7db')
    g.mark('window_ready'); e('8b44242083f801'); g.branch('7c','argument_error')
    e('83f809'); g.branch('7f','argument_error'); e('837c241808'); g.branch('75','argument_error')
    e('83fb09'); g.branch('7c','argument_error'); e('83fb0f'); g.branch('7f','argument_error')
    e('3bca'); g.branch('7c','argument_error'); e('83f909'); g.branch('7f','argument_error')
    e('8b4424243bc2'); g.branch('7c','argument_error'); e('83f802'); g.branch('7f','argument_error')
    e('8b57285668b81600006a0152ff57208bf083c40c85f6'); g.branch('0f84','memory_error',True)
    e('89771c896e188bcbbd01000000d3e5895e288b5c24248d4b078d45ff89462cb801000000'
      'd3e0894e4883c1026a028946444889464cb8abaaaaaaf7e1d1ea893e896e24895650'
      '8b4f285551ff57208b56246a028946308b47285250ff57208b4e446a028946388b57285152ff5720'
      '89463c8d4b06b801000000d3e06a04508986941600008b472850ff5720'
      '8b8e941600008d148d0000000089560c8b563083c43085d2894608')
    g.branch('74','failed_buffers'); e('8b563885d2'); g.branch('74','failed_buffers')
    e('8b563c85d2'); g.branch('74','failed_buffers'); e('85c0'); g.branch('74','failed_buffers')
    e('8bd1d1ea8d14508d044803c18b4c241889969c1600008b54242857898690160000894e7c'
      '899680000000c6461d08'); c('reset'); e('83c4045e5f5d5bc3')
    g.mark('failed_buffers'); o('a1','memory_message_slot'); e('57894718'); c('end'); e('83c404')
    g.mark('memory_error'); e('5e5f5db8fcffffff5bc3')
    g.mark('version_error'); e('5db8faffffff5bc3')
    m,row = _bind(raw,image,sections,imports,address,g,
        data=(('version_slot',4),('memory_message_slot',4)))
    return dict(**row, default_allocate_address=_word(m,'allocate'),default_release_address=_word(m,'release'),
        native_state_allocation_bytes=0x16b8, native_stream_bytes=0x38,
        native_level_range=[0,9],native_default_level=6,method=8,window_bits_range=[9,15],
        memory_level_range=[1,9],strategy_range=[0,2],dynamic_callbacks_preserved_if_nonzero=True,
        state_pointer_published_before_subbuffer_allocation=True,
        allocation_failures_call_own_end_before_minus4=True, version_check_is_first_byte_only=True,
        actual_heap_callback_aliasing_and_allocation_success_proven=False)


def _reset(raw,image,sections,imports,address):
    g = _ChildGrammar(); e,c = g.code,g.call
    e('8b44240433c93bc156'); g.branch('74','error'); e('8b701c3bf1'); g.branch('74','error')
    e('394820'); g.branch('74','error'); e('394824'); g.branch('74','error')
    e('894814894808894818c7402c020000008b5608895610394e18894e14'); g.branch('7d','raw_ready')
    e('894e18'); g.mark('raw_ready'); e('8b5618f7da1bd283e24783c22a895604c740300100000056894e20')
    c('tree_init'); e('83c4048bd6'); c('match_init'); e('33c05ec3'); g.mark('error'); e('b8feffffff5ec3')
    _,row = _bind(raw,image,sections,imports,address,g)
    return dict(**row, stream_totals_and_message_zeroed=True, checksum_initial_value=1,
        state_status_header_or_raw=[0x2a,0x71],negative_no_header_normalized_zero=True,
        pending_count_and_last_flush_zeroed=True,actual_tree_and_match_state_initialization_proven=False)


def _put_short(raw,image,sections,imports,address):
    g = _ChildGrammar(); g.code('568b70088bd1578b7814c1ea0888143e8b50148b700842895014'
        '880c328b4814415f8948145ec3')
    _,row = _bind(raw,image,sections,imports,address,g)
    return dict(**row, native_bytes_written=2, high_byte_before_low_byte=True,
        pending_count_advanced_twice=True,actual_pending_buffer_capacity_proven=False)


def _flush_pending(raw,image,sections,imports,address):
    g = _ChildGrammar(); e = g.code
    e('8b4810568b701c8b56143bd1'); g.branch('76','selected'); e('8bd1'); g.mark('selected')
    e('85d2'); g.branch('74','return'); e('8b761053578b780c8bca8bd9c1e902f3a58bcb83e103f3a4'
        '8b780c8b481c03fa89780c0151108b58148b78108b481c03da8958142bfa897810295114'
        '8b401c8b481485c95f5b'); g.branch('75','return'); e('8b4808894810')
    g.mark('return'); e('5ec3')
    _,row = _bind(raw,image,sections,imports,address,g)
    return dict(**row, copied_bytes_is_unsigned_min_pending_and_available_output=True,
        output_pointer_total_and_available_updated=True,pending_pointer_and_count_updated=True,
        empty_pending_pointer_resets_to_buffer_base=True,DF_zero_required=True,
        actual_buffer_bounds_and_aliasing_proven=False)


def _end(raw,image,sections,imports,address):
    g = _ChildGrammar(); e = g.code
    e('568b74240885f6'); g.branch('0f84','error',True); e('8b461c85c0'); g.branch('0f84','error',True)
    e('578b780483ff2a'); g.branch('74','accepted'); e('83ff71'); g.branch('74','accepted')
    e('81ff9a020000'); g.branch('74','accepted'); e('5fb8feffffff5ec3'); g.mark('accepted')
    e('8b400885c0'); g.branch('74','freed0'); e('508b462850ff562483c408'); g.mark('freed0')
    e('8b4e1c8b413c85c0'); g.branch('74','freed1'); e('8b56285052ff562483c408'); g.mark('freed1')
    e('8b461c8b403885c0'); g.branch('74','freed2'); e('8b4e285051ff562483c408'); g.mark('freed2')
    e('8b561c8b423085c0'); g.branch('74','freed3'); e('508b462850ff562483c408'); g.mark('freed3')
    e('8b4e1c8b56285152ff562483c40833c083ff71'
      '0f95c05fc7461c000000005e4883e0fdc3'); g.mark('error'); e('b8feffffff5ec3')
    _,row = _bind(raw,image,sections,imports,address,g)
    return dict(**row, accepted_state_statuses=[0x2a,0x71,0x29a], subbuffer_free_order=[8,0x3c,0x38,0x30],
        state_freed_last_and_stream_state_cleared=True, native_result_minus3_if_status71_otherwise_zero=True,
        dynamic_release_callback_identity_and_reentry_proven=False)


def _step(raw,image,sections,imports,address):
    g = _ChildGrammar(); e,o,c = g.code,g.operand,g.call
    e('538b5c240885db5556'); g.branch('0f84','error',True); e('8b731c85f6'); g.branch('0f84','error',True)
    e('8b6c241483fd04'); g.branch('0f8f','error',True); e('85ed'); g.branch('0f8c','error',True)
    e('8b430c85c0'); g.branch('0f84','stream_error',True); e('833b00'); g.branch('75','input_ready')
    e('8b430485c0'); g.branch('0f85','stream_error',True); g.mark('input_ready')
    e('8b46043d9a020000'); g.branch('75','status_ready'); e('83fd04'); g.branch('0f85','stream_error',True)
    g.mark('status_ready'); e('8b4b1085c9'); g.branch('75','output_ready'); o('a1','buffer_message_slot')
    e('5e8943185db8fbffffff5bc3'); g.mark('output_ready')
    e('83f82a8b4e2057891e894c2414896e20'); g.branch('75','header_done')
    e('8b4e288b467c83e908c1e10c81c10008000048d1f883f803'); g.branch('76','level_flags')
    e('b803000000'); g.mark('level_flags'); e('c1e0060bc88b466485c0'); g.branch('74','dictionary_flags')
    e('83c920'); g.mark('dictionary_flags'); e('8bc133d2bf1f000000f7f78bc6c74604710000002bca03cf')
    c('put_short0'); e('8b466485c0'); g.branch('74','dictionary_done')
    e('0fb74b328bc6'); c('put_short1'); e('8b4b3081e1ffff0000'); c('put_short2')
    g.mark('dictionary_done'); e('c7433001000000'); g.mark('header_done'); e('8b461485c0')
    g.branch('74','no_pending'); e('8bc3'); c('flush0'); e('8b431085c0'); g.branch('75','input_check')
    g.mark('output_empty'); e('c74620ffffffff'); g.mark('progress_return'); e('5f5e5d33c05bc3')
    g.mark('no_pending'); e('8b430485c0'); g.branch('75','input_check'); e('3b6c2414')
    g.branch('7f','input_check'); e('83fd04'); g.branch('74','input_check'); o('8b15','buffer_message_slot')
    e('5f5e5d895318b8fbffffff5bc3'); g.mark('input_check'); e('8b46043d9a0200008b4b04')
    g.branch('75','not_finished'); e('85c9'); g.branch('74','compress_check'); o('a1','buffer_message_slot')
    e('5f5e8943185db8fbffffff5bc3'); g.mark('not_finished'); e('85c9'); g.branch('75','dispatch')
    g.mark('compress_check'); e('8b4e6c85c9'); g.branch('75','dispatch'); e('85ed')
    g.branch('0f84','finish_check',True); e('3d9a020000'); g.branch('0f84','finish_check',True)
    g.mark('dispatch'); e('8b467c558d0c4056'); o('ff148d','algorithm_table')
    e('83c40883f802'); g.branch('74','mark_finished'); e('83f803'); g.branch('75','state_ready')
    g.mark('mark_finished'); e('c746049a020000'); g.mark('state_ready'); e('85c0')
    g.branch('0f84','pending_return',True); e('83f802'); g.branch('0f84','pending_return',True)
    e('83f801'); g.branch('75','finish_check'); e('3be8'); g.branch('75','block_flush')
    e('56'); c('align'); e('83c404'); g.branch('eb','flush_after_block'); g.mark('block_flush')
    e('6a006a006a0056'); c('stored_block'); e('83c41083fd03'); g.branch('75','flush_after_block')
    e('8b56448b463c66c74450fe00008b4e448b7e3c8d4c09fe8bd1c1e90233c0f3ab8bca23cdf3aa')
    g.mark('flush_after_block'); e('8bc3'); c('flush1'); e('8b431085c0'); g.branch('0f84','output_empty',True)
    g.mark('finish_check'); e('83fd04'); g.branch('0f85','progress_return',True)
    e('8b461885c0'); g.branch('74','trailer'); e('5f5e5db8010000005bc3'); g.mark('trailer')
    e('0fb74b328bc6'); c('put_short3'); e('8b4b3081e1ffff0000'); c('put_short4')
    e('8bc3'); c('flush2'); e('8b4e145fc74618ffffffff5e33c085c95d0f94c05bc3')
    g.mark('pending_return'); e('8b431085c0'); g.branch('0f85','progress_return',True)
    e('5fc74620ffffffff5e5d33c05bc3'); g.mark('stream_error'); o('a1','stream_message_slot')
    e('894318'); g.mark('error'); e('5e5db8feffffff5bc3')
    m,row = _bind(raw,image,sections,imports,address,g,
        data=(('buffer_message_slot',4),('stream_message_slot',4)))
    return dict(**row,algorithm_table_address=_word(m,'algorithm_table'),flush_range=[0,4],
        state_status_header_busy_finish=[0x2a,0x71,0x29a], native_returns=[-2,-5,0,1],
        header_and_Adler_trailer_emitted_high_byte_first=True, raw_stream_skips_trailer=True,
        native_algorithm_calls_index_level_times_three=True,
        dynamic_compressor_state_immutability_and_termination_proven=False)


def bind_native_cg_vm_save_deflate(executable,header,vm,frames):
    raw = bytes(executable); parent = bind_native_cg_vm_state_pack_children(raw,header,vm,frames)
    older = parent['layout'] == 'signed-word-legacy'; image,sections = _pe_sections(raw)
    imports = _import_slots(raw,image); deflate = None
    if older:
        writer = parent['native_state_pack_children']['compressed_write']; calls = writer['helper_addresses']
        paths = dict(init=_init(raw,image,sections,imports,calls['compression_init']),
            step=_step(raw,image,sections,imports,calls['compression_step']),
            end=_end(raw,image,sections,imports,calls['compression_end']))
        paths['init2'] = _init2(raw,image,sections,imports,paths['init']['helper_addresses']['init2'])
        core = paths['init2']; paths['reset'] = _reset(raw,image,sections,imports,core['helper_addresses']['reset'])
        step_calls = paths['step']['helper_addresses']
        if len({v for k,v in step_calls.items() if k.startswith('put_short')}) != 1 or len({v for k,v in step_calls.items() if k.startswith('flush')}) != 1:
            raise ValueError('CG 保存压缩的字节输出或缓冲区刷新不是自身同一入口。')
        paths['put_short'] = _put_short(raw,image,sections,imports,step_calls['put_short0'])
        paths['flush_pending'] = _flush_pending(raw,image,sections,imports,step_calls['flush0'])
        paths['default_allocate'] = _default_allocate(raw,image,sections,imports,core['default_allocate_address'])
        paths['default_release'] = _default_release(raw,image,sections,imports,core['default_release_address'])
        own_inflate = _parent(parent,'fvp-native-cg-vm-restore-inflate/1')['native_restore_inflate']['paths']
        if (core['helper_addresses']['end'] != paths['end']['address'] or
            any(paths[k] != own_inflate[k] for k in ('default_allocate','default_release'))):
            raise ValueError('CG 保存压缩没有使用自身恢复链的相同内存回调和自己的失败清理。')
        version = writer['data_references']['compression_version']['address']
        version_slot = core['data_references']['version_slot']['address']
        at = _relocated(raw,image,sections,version_slot,executable=False,length=4)
        if struct.unpack_from('<I',raw,at)[0] != version or writer['data_references']['compression_version']['bytes'] != '31':
            raise ValueError('CG 保存压缩的原生版本间接单元不对应自己的写入版本。')
        table = paths['step']['algorithm_table_address']-8
        table_at = _relocated(raw,image,sections,table,executable=False,length=120)
        records = [list(struct.unpack_from('<4HI',raw,table_at+12*n)) for n in range(10)]
        parameters = [[0,0,0,0],[4,4,8,4],[4,5,16,8],[4,6,32,32],[4,4,16,16],
            [8,16,32,32],[8,16,128,128],[8,32,128,256],[32,128,258,1024],[32,258,258,4096]]
        algorithms = [r[4] for r in records]
        if ([r[:4] for r in records] != parameters or len(set(algorithms)) != 3 or
            len(set(algorithms[1:4])) != 1 or len(set(algorithms[4:])) != 1):
            raise ValueError('CG 保存压缩的十等级原生参数表不完整或算法分组不一致。')
        for address in set(algorithms): _relocated(raw,image,sections,address,executable=True,length=1)
        values = list(paths.values())
        for i, first in enumerate(values):
            for second in values[i+1:]:
                if max(first['address'],second['address']) < min(first['address']+first['code_bytes'],second['address']+second['code_bytes']):
                    raise ValueError('CG 保存压缩的完整函数范围互相重叠。')
        remaining = dict(paths['reset']['helper_addresses'])
        remaining.update({k:v for k,v in step_calls.items() if k in ('align','stored_block')})
        remaining.update({'algorithm_'+str(i):address for i,address in enumerate(dict.fromkeys(algorithms))})
        deflate = dict(paths=paths,level_configuration=dict(address=table,records=records,
            bytes=120,version_slot=version_slot,level_range=[0,9],writer_level=9),
            remaining_child_addresses=remaining,own_complete_explicit_control_and_buffer_paths_static_bound=True,
            own_init_level_domain_and_10_record_dispatch_static_bound=True,
            default_memory_callbacks_match_own_restore_static_bound=True,
            dynamic_level_and_callback_identities_unconditionally_stable=False,
            complete_algorithm_child_bodies_and_compression_effects_proven=False,
            actual_compressed_bytes_native_file_and_round_trip_proven=False,native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
        native_vm_state_pack_children=parent,native_save_deflate=deflate,
        own_legacy_save_compressor_control_and_buffers_static_bound=older,
        same_live_instance_lifetime_proven=False,complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False,initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False,complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
