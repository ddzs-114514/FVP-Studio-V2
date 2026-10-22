"""Own legacy compressor tree setup and full bit-buffer paths, not live output."""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots
from .native_cg_vm_restore_children import _ChildGrammar, _bind
from .native_cg_vm_save_deflate import bind_native_cg_vm_save_deflate

SCHEMA = 'fvp-native-cg-vm-save-trees/1'


def _tree_init(raw,image,sections,imports,address):
    g=_ChildGrammar(); e,o=g.code,g.operand
    e('8b5424048d828c0000008982100b00008d82740a00008982280b000033c08d8a80090000')
    o('c782180b0000','literal_descriptor'); e('898a1c0b0000')
    o('c782240b0000','distance_descriptor'); o('c782300b0000','bit_length_descriptor')
    e('668982b01600008982b4160000c782ac16000008000000')
    o('e9','init_block_call')
    _,row=_bind(raw,image,sections,imports,address,g,data=tuple((k+'_descriptor',20) for k in ('literal','distance','bit_length')))
    return dict(**row,descriptor_destinations=dict(literal=0xb18,distance=0xb24,bit_length=0xb30),
        dynamic_tree_state_offsets=dict(literal=0x8c,distance=0x980,bit_length=0xa74),
        bit_buffer_zeroed=True,valid_bits_zeroed=True,last_end_block_length=8,
        terminal_is_own_init_block_tail_not_RET=True,actual_static_tree_and_heap_state_initialized_proven=False)


def _init_block(raw,image,sections,imports,address):
    g=_ChildGrammar(); e=g.code
    e('568d828c000000b91e01000033f68bff'); g.mark('literal')
    e('66893083c00449'); g.branch('75','literal')
    e('8d8280090000b91e000000'); g.mark('distance')
    e('66893083c00449'); g.branch('75','distance')
    e('8d82740a0000b913000000'); g.mark('bit_length')
    e('66893083c00449'); g.branch('75','bit_length')
    e('89b2a416000089b2a016000089b2a816000089b29816000066c7828c04000001005ec3')
    _,row=_bind(raw,image,sections,imports,address,g)
    return dict(**row,frequency_word_zero_counts=dict(literal=286,distance=30,bit_length=19),
        frequency_stride=4,end_block_symbol=256,end_block_frequency=1,
        counters_zeroed=[0x1698,0x16a0,0x16a4,0x16a8],actual_buffer_ownership_and_bounds_proven=False)


def _match_init(raw,image,sections,imports,address):
    g=_ChildGrammar(); e,o=g.code,g.operand
    e('8b42248b4a44d1e08942348b423c535633f666897448fe8b4a448d4c09fe8bd957'
      '8b7a3cc1e90233c0f3ab8bcb83e103f3aa8b427c8d0440c1e002')
    o('0fb788','lazy_parameter'); e('894a78')
    o('0fb788','good_parameter'); e('898a84000000')
    o('0fb788','nice_parameter'); e('898a88000000')
    o('0fb780','chain_parameter')
    e('5f89427489726489725489726cb8020000008972608972405e8942708942585bc3')
    _,row=_bind(raw,image,sections,imports,address,g,data=tuple((k+'_parameter',2) for k in ('lazy','good','nice','chain')))
    return dict(**row,window_size_is_twice_state_w_size=True,hash_head_words_cleared=True,
        configuration_row_stride=12,configuration_parameter_offsets=dict(good=0,lazy=2,nice=4,chain=6),
        match_lengths_initialized_to_two=True,DF_zero_required=True,
        dynamic_level_range_hash_allocation_bounds_and_aliasing_proven=False)


def _bit_flush(raw,image,sections,imports,address):
    g=_ChildGrammar(); e=g.code
    e('8b88b416000083f91053'); g.branch('75','not16')
    e('8b50148a98b01600008b4808881c118b50148a98b1160000428950148bca8b5008881c11'
      'ff401433c9668988b01600008988b41600005bc3')
    g.mark('not16'); e('83f908'); g.branch('7c','return')
    e('8b48088b50148a98b0160000881c11660fb688b11600008b5014668988b0160000'
      '8b88b41600004283c1f88950148988b4160000')
    g.mark('return'); e('5bc3')
    _,row=_bind(raw,image,sections,imports,address,g)
    return dict(**row,native_count16_writes_two_bytes_and_clears=True,
        native_signed_count_at_least8_writes_low_byte_and_retains_high_byte=True,
        native_signed_count_below8_writes_nothing=True,actual_pending_capacity_and_valid_bit_domain_proven=False)


def _bit_windup(raw,image,sections,imports,address):
    g=_ChildGrammar(); e=g.code
    e('8b90b416000083fa0853'); g.branch('7e','at_most8')
    e('8b50148a98b01600008b4808881c118b50148a98b1160000428950148bca8b5008881c11'
      'ff401433c9668988b01600008988b41600005bc3')
    g.mark('at_most8'); e('33c93bd1'); g.branch('7e','clear')
    e('8b50088a98b0160000568b7014881c32ff40145e')
    g.mark('clear'); e('668988b01600008988b41600005bc3')
    _,row=_bind(raw,image,sections,imports,address,g)
    return dict(**row,native_signed_count_above8_writes_two_bytes=True,
        native_signed_positive_count_at_most8_writes_one_byte=True,
        native_nonpositive_count_writes_nothing=True,all_paths_clear_bit_buffer_and_count=True,
        actual_pending_capacity_and_valid_bit_domain_proven=False)


def _copy_block(raw,image,sections,imports,address):
    g=_ChildGrammar(); e,c=g.code,g.call
    e('5356578bd98bfa'); c('bit_windup')
    e('8b4c241085c9c780ac16000008000000'); g.branch('74','bytes')
    e('8b48148b5008881c118b48148b500841894814883c118b70148b5008468970148acbf6d1'
      '880c168b70148b5008468bcbf7d1897014882c16ff4014')
    g.mark('bytes'); e('85db'); g.branch('74','return'); e('8d4900'); g.mark('loop')
    e('8b48148b5008895c24108a1f881c118b70148b5c241046474b897014'); g.branch('75','loop')
    g.mark('return'); e('5f5e5bc3')
    _,row=_bind(raw,image,sections,imports,address,g)
    return dict(**row,optional_header_is_low16_length_then_low16_complement_little_endian=True,
        source_bytes_copied_one_at_a_time_by_full_EBX_count=True,last_end_block_length=8,
        header_flag_is_entry_SP_argument4=True,actual_buffer_bounds_and_aliasing_proven=False)


def _stored_block(raw,image,sections,imports,address):
    g=_ChildGrammar(); e,c=g.code,g.call
    e('8b4424048b88b416000083f90d'); g.branch('7e','room')
    e('53568b7424188bd6d3e28b4808660990b01600008b50148a98b0160000881c118b4814'
      '8a98b11600008b500841894814881c118b90b41600008b5814b1102aca66d3ee8b4c2414'
      '4383c2f36689b0b01600005e8958148990b41600008b54240c5b6a01')
    c('copy_block0'); e('59c3')
    g.mark('room')
    e('8b542410d3e283c1038988b41600008b4c240c660990b01600008b5424086a01')
    c('copy_block1'); e('59c3')
    _,row=_bind(raw,image,sections,imports,address,g)
    return dict(**row,stored_header_appends_three_bits_from_native_eof_argument=True,
        native_valid_bits_above13_flushes_low_two_bytes=True,copy_block_header_flag_is_one=True,
        entry_SP_arguments=dict(state=4,source=8,count=12,eof=16),
        both_normal_returns_bound=True,actual_pending_capacity_and_eof_domain_proven=False)


def _align(raw,image,sections,imports,address):
    g=_ChildGrammar(); e,c=g.code,g.call
    e('8b4424048b88b4160000ba02000000d3e25356660990b016000083f90d')
    g.branch('7e','first_room')
    e('8b50148a98b01600008b4808881c118b48148a98b11600008b500841894814881c11'
      '8b90b41600008b5814b1102acabe0200000066d3ee4383c2f38958146689b0b01600008990b4160000')
    g.branch('eb','first_end'); g.mark('first_room'); e('83c1038988b4160000')
    g.mark('first_end'); e('8b88b416000033d2d3e2660990b016000083f909')
    g.branch('7e','second_room')
    e('8b50148a98b01600008b4808881c118b48148a98b11600008b500841894814881c11'
      '8b90b41600008b5814b1102aca33f666d3ee4383c2f78958146689b0b01600008990b4160000')
    g.branch('eb','second_end'); g.mark('second_room'); e('83c1078988b4160000')
    g.mark('second_end'); c('bit_flush0')
    e('8b88b41600008b90ac1600002bd183c20b83fa09'); g.branch('0f8d','return',True)
    e('ba02000000d3e2660990b016000083f90d'); g.branch('7e','third_room')
    e('8b50148a98b01600008b4808881c118b48148a98b11600008b500841894814881c11'
      '8b90b41600008b5814b1102acabe0200000066d3ee4383c2f38958146689b0b01600008990b4160000')
    g.branch('eb','third_end'); g.mark('third_room'); e('83c1038988b4160000')
    g.mark('third_end'); e('8b88b416000033d2d3e2660990b016000083f909')
    g.branch('7e','fourth_room')
    e('8b50148a98b01600008b4808881c118b48148a98b11600008b500841894814881c11'
      '8b90b41600008b5814b1102aca33f666d3ee4383c2f78958146689b0b01600008990b4160000')
    c('bit_flush1'); e('5ec780ac160000070000005bc3')
    g.mark('fourth_room'); e('83c1078988b4160000'); c('bit_flush2')
    g.mark('return'); e('5ec780ac160000070000005bc3')
    _,row=_bind(raw,image,sections,imports,address,g)
    return dict(**row,empty_static_end_block_bits_appended=True,
        second_empty_block_condition_is_signed_last_end_length_minus_remaining_bits_plus11_below9=True,
        last_end_block_length=7,all_three_own_bit_flush_calls_and_late_RET_bound=True,
        actual_buffer_bounds_bit_domain_and_aliasing_proven=False)


def bind_native_cg_vm_save_trees(executable,header,vm,frames):
    raw=bytes(executable); parent=bind_native_cg_vm_save_deflate(raw,header,vm,frames)
    image,sections=_pe_sections(raw); imports=_import_slots(raw,image); older=parent['layout']=='signed-word-legacy'
    trees=None
    if older:
        own=parent['native_save_deflate']; entries=own['remaining_child_addresses']
        paths=dict(tree_init=_tree_init(raw,image,sections,imports,entries['tree_init']),
            match_init=_match_init(raw,image,sections,imports,entries['match_init']),
            stored_block=_stored_block(raw,image,sections,imports,entries['stored_block']),
            align=_align(raw,image,sections,imports,entries['align']))
        paths['init_block']=_init_block(raw,image,sections,imports,paths['tree_init']['helper_addresses']['init_block'])
        copies=paths['stored_block']['helper_addresses']
        flushes=paths['align']['helper_addresses']
        if len(set(copies.values()))!=1 or len(set(flushes.values()))!=1:
            raise ValueError('CG 保存压缩的数据块复制和位刷新没有使用自身同一入口。')
        paths['copy_block']=_copy_block(raw,image,sections,imports,copies['copy_block0'])
        paths['bit_flush']=_bit_flush(raw,image,sections,imports,flushes['bit_flush0'])
        paths['bit_windup']=_bit_windup(raw,image,sections,imports,paths['copy_block']['helper_addresses']['bit_windup'])
        table=own['level_configuration']['address']
        for role,offset in paths['match_init']['configuration_parameter_offsets'].items():
            if paths['match_init']['data_references'][role+'_parameter']['address']!=table+offset:
                raise ValueError('CG 保存压缩的匹配初始化没有使用自己的十等级配置表。')
        descriptors={}
        shapes=dict(literal=[257,286,15],distance=[0,30,15],bit_length=[0,19,7])
        references=paths['tree_init']['data_references']
        if len({r['address'] for r in references.values()})!=3:
            raise ValueError('CG 保存压缩的三类树描述不能相互冒用。')
        for role,shape in shapes.items():
            ref=references[role+'_descriptor']; words=list(struct.unpack('<5I',bytes.fromhex(ref['bytes'])))
            if words[2:]!=shape or (words[0]==0)!=(role=='bit_length') or words[1]==0:
                raise ValueError('CG 保存压缩的原生树描述形状不一致。')
            for value in words[:2]:
                if value: _relocated(raw,image,sections,value,executable=False,length=1)
            descriptors[role]=dict(**ref,words=words,own_shape_static_bound=True,
                complete_table_contents_and_runtime_tree_initialization_proven=False)
        rows=list(paths.values())+list(own['paths'].values())
        for i,first in enumerate(rows):
            for second in rows[i+1:]:
                if max(first['address'],second['address'])<min(first['address']+first['code_bytes'],second['address']+second['code_bytes']):
                    raise ValueError('CG 保存压缩的树和缓冲函数范围与自身已有函数重叠。')
        remaining={k:v for k,v in entries.items() if k.startswith('algorithm_')}
        trees=dict(paths=paths,descriptors=descriptors,own_complete_explicit_tree_and_bit_buffer_paths_static_bound=True,
            match_initialization_uses_own_level_configuration_static_bound=True,
            remaining_algorithm_addresses=remaining,complete_algorithm_and_compressed_bytes_proven=False,
            actual_state_bounds_callbacks_reentry_and_runtime_tree_contents_proven=False,
            actual_native_file_and_round_trip_proven=False,native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
        native_vm_save_deflate=parent,native_save_trees=trees,
        own_legacy_save_tree_and_bit_buffers_static_bound=older,
        same_live_instance_lifetime_proven=False,complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False,initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False,complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
