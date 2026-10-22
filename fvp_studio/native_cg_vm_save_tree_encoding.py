"""Own complete legacy tree/encoding paths and tables, not live save execution."""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots
from .native_cg_vm_restore_children import _ChildGrammar
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record
from .native_cg_vm_heap_paths import _word, _callee
from .native_cg_vm_save_algorithm_children import bind_native_cg_vm_save_algorithm_children, _one_helper

SCHEMA = 'fvp-native-cg-vm-save-tree-encoding/1'

_TYPE = '''0fb791a00000000fb781a400000003c20fb7919c00000003c20fb7919800000003c2
0fb7919400000003c20fb7919000000003c20fb7918c000000535633f65703c2
8d91a8000000bf790000008d4900|@text|0fb71a03f383c2044f|75 text
8d918c020000bf80000000|@binary|0fb71a03c383c2044f|75 binary
c1ee023bf05f1ac0fec05e88411c5bc3'''

_TREE = '''83ec088b44240c5355578b388b40088b480c8b1833d283cdff33c03bca894c2410896c240c
899648140000c7864c1400003d020000|7e minimum|@symbol|66391487|74 zero
8b8e4814000041898e4814000089848e540b00008944240c889430501400008be8|eb next_symbol
@zero|6689548702|@next_symbol|8b4c2410403bc1|7c symbol|@minimum
83be4814000002|7d heapify|@pad|83fd02|7d symbol_zero|458bc5|eb pad_symbol
@symbol_zero|33c0|@pad_symbol
8b8e4814000041898e4814000089848e540b000066c70487010088940650140000
8b8ea0160000493bda898ea0160000|74 padding_cost_done
0fb74483022986a4160000|@padding_cost_done|83be4814000002|7c pad|896c240c
@heapify|8b4c24188969048b8648140000992bc28bd8d1fb83fb01|7c heapified
@heap_loop|538bc6|call pqdownheap|83c4044b83fb01|7d heap_loop|@heapified
8b6c2410|eb combine|8d4900|@combine
8b86481400008b9486540b00008b9e580b0000488986481400006a018bc68996580b0000
call pqdownheap
8b964c1400008b86580b000083c4044a89964c1400008bca899c8e540b00008b8e4c140000
49898e4c14000089848e540b0000668b0c8766030c9f66890caf8a8c06501400008a941e501400003ad1
72 first_depth|0fb6ca|eb depth_ready|@first_depth|0fb6c9|@depth_ready
fec1888c2e5014000066896c870266896c9f0289ae580b00006a018bc645|call pqdownheap
8b864814000083c40483f802|0f8d combine
8b864c1400008b96580b00008b4c24184889864c140000899486540b00008bc6|call gen_bitlen
8b5c240c8d96340b0000|call gen_codes|5f5d5b83c408c3'''

_BIT_TREE = '''568bf08b8e140b00008d868c00000056|call scan_tree
8b8e200b00008d868009000056|call scan_tree
8d86280b000050|call build_tree|83c40cb812000000|eb order|8d4900|@order
abs 0fb688 bit_order|6683bc8e760a000000|75 selected|4883f803|7d order
@selected|8b8ea01600008d54401103ca898ea01600005ec3'''

_ALL_TREES = '''8b88b416000083f90b538b5c240c558b6c24145657|7e literal_room
8b74241481c6fffeffff8bd6d3e28b4814895c241c660990b01600008a98b01600008b5008
881c118b50148a98b1160000428950148bca8b5008881c118b48148b90b41600008b5c241c
41894814b1102aca66d3ee83c2f58990b41600006689b0b0160000|eb literal_done|@literal_room
8b54241481c2fffeffffd3e2660990b016000083c1058988b4160000|@literal_done
8b88b416000083f90b|7e distance_room
8d73ff8bd6d3e28b4814895c241c660990b01600008a98b01600008b5008881c118b50148a98b1160000
428950148bca8b5008881c118b48148b90b41600008b5c241c41894814b1102aca66d3ee83c2f5
8990b41600006689b0b0160000|eb distance_done|@distance_room
8d53ffd3e2660990b016000083c1058988b4160000|@distance_done
8b88b416000083f90c|7e bit_room
8d75fc8bd6d3e28b4814895c241c660990b01600008a98b01600008b5008881c118b50148a98b1160000
428950148bca8b5008881c118b48148b90b41600008b5c241c41894814b1102aca66d3ee83c2f4
8990b41600006689b0b0160000|eb bit_done|@bit_room
8d55fcd3e2660990b016000083c1048988b4160000|@bit_done|33ff85ed|0f8e send
eb order|8da424000000008d4900|@order|8b88b416000083f90d|abs 0fb697 bit_order
7e order_room
0fb7b490760a00008bd6d3e28b4814660990b01600008a98b01600008b5008881c118b50148a98b1160000
428950148bca8b5008881c118b48148b90b416000041894814b1102aca66d3ee83c2f3
8990b41600006689b0b0160000|eb order_done|@order_room
668b9490760a000066d3e2660990b016000083c1038988b4160000|@order_done
473bfd|0f8c order|8b5c2418|@send
8b4c241449518d888c000000|call send_tree|4b538d8880090000|call send_tree
83c4085f5e5d5bc3'''

_COMPRESS = '''8b909816000083ec0c538b5c2414555633c985d257|0f84 end_block
eb symbol|8d4900|@symbol
8b909c1600000fb72c4a8b90901600000fb634114185ed894c24188b88b4160000|0f85 match
0fb77cb302ba100000002bd73bca|7e literal_room
0fb734b38bd6d3e28b4808895c2410660990b01600008b50148a98b0160000881c118b50148a98b1160000
428950148bca8b5008881c118b48148b90b41600008b5c241041894814b1102aca66d3ee8d4c3af0
6689b0b0160000|e9 next_symbol|@literal_room
668b14b366d3e2660990b016000003cf|e9 next_symbol|@match
abs 0fb696 length|0fb7bc9306040000bb100000002bdf3bcb897c24108b7c242089542414|7e length_room
0fb7bc97040400008bd7d3e28b4808660990b01600008b50148a98b0160000881c118b50148a98b1160000
428950148bca8b5008881c118b48148b90b416000041894814b1102aca66d3ef8b4c24108d540af0
8990b41600008b5424146689b8b0160000|eb length_done|@length_room
668bbc970404000066d3e76609b8b01600008b7c241003cf8988b4160000|@length_done
abs 8b3c95 extra_literal|85ff8b5c2420|0f84 distance|abs 2b3495 base_length
8b88b4160000ba100000002bd73bca|7e length_extra_room
8bd6d3e28b4808660990b01600008b50148a98b0160000881c118b50148a98b116000042895014
8bca8b5008881c118b48148b90b41600008b5c242041894814b1102aca66d3ee8d4c3af0
6689b0b0160000|eb length_extra_done|@length_extra_room
d3e66609b0b016000003cf|@length_extra_done|8988b4160000|@distance
4d81fd00010000|73 high_distance|abs 0fb6bd distance_low|eb distance_ready|@high_distance
8bd5c1ea07|abs 0fb6ba distance_high|@distance_ready
8b4c24240fb754b9028b88b4160000be100000002bf23bce89542414|7e distance_room
8b5424240fb734ba8bd6d3e28b4808660990b01600008b50148a98b0160000881c118b50148a98b1160000
428950148bca8b5008881c118b48148b90b41600008b5c242041894814b1102aca66d3ee8b4c2414
8d540af08990b41600006689b0b0160000|eb distance_done|@distance_room
8b742424668b34be66d3e66609b0b016000003ca8988b4160000|@distance_done
abs 8b34bd extra_distance|85f6|0f84 symbol_done|abs 2b2cbd base_distance
8b88b4160000ba100000002bd63bca|7e distance_extra_room
8bd5d3e28b4808895c2414660990b01600008b50148a98b0160000881c118b50148a98b1160000
428950148bca8b5008881c118b48148b90b41600008b5c241441894814b1102aca66d3ed8d4c32f0
6689a8b0160000|eb next_symbol|@distance_extra_room
d3e56609a8b016000003ce|@next_symbol|8988b4160000|@symbol_done
8b4c24183b8898160000|0f82 symbol|@end_block
0fb7bb020400008b88b4160000ba100000002bd73bca|7e end_room
0fb7b3000400008bd6d3e28b4808895c2420660990b01600008b50148a98b0160000881c118b5014
8b48088b5c2420428950148bea8a90b11600008814298b48148b90b416000041894814b1102aca
66d3ee8d4c3af05f8988b41600006689b0b01600000fb793020400005e5d8990ac1600005b83c40cc3
@end_room|668b930004000066d3e2660990b016000003cf5f8988b4160000
0fb78b020400005e5d8988ac1600005b83c40cc3'''


def _path(raw, image, sections, imports, address, tape, data=(), window=1024):
    grammar = _ChildGrammar()
    branches = {'72','73','74','75','7c','7d','7e','eb','e9','0f82','0f84','0f85','0f8c','0f8d','0f8e'}
    counts = {}
    for token in tape.replace('\n','|').split('|'):
        words = token.split()
        if not words:
            continue
        kind, *args = words
        if kind.startswith('@'):
            grammar.mark(kind[1:])
        elif kind in branches:
            grammar.branch(kind,args[0],wide=kind.startswith('0f') or kind=='e9')
        elif kind == 'call':
            role = args[0]
            index = counts.get(role,0)
            counts[role] = index+1
            grammar.call(role+str(index))
        elif kind == 'abs':
            grammar.operand(args[0],args[1])
        else:
            grammar.code(kind)
    at, code = _code(raw,image,sections,address,window)
    match = grammar.match(code)
    calls = {name[:-5]:_callee(raw,image,sections,address,match,name)
        for name in match.groupdict() if name.endswith('_call')}
    references = {}
    for key, length in data:
        value = _word(match,key)
        offset = _relocated(raw,image,sections,value,executable=False,length=length)
        references[key] = dict(address=value,bytes=raw[offset:offset+length].hex())
    return dict(**_record(address,at,match[0]),helper_addresses=calls,import_calls={},data_references=references,
        own_complete_explicit_instruction_paths_static_bound=True,bounded_code_window_bytes=window,
        external_child_effects_and_memory_bounds_proven=False,native_code_executed=False)


def _data_type(raw,image,sections,imports,address):
    row = _path(raw,image,sections,imports,address,_TYPE)
    return dict(**row,entry_state_register='ECX',callee_argument_cleanup_bytes=0,
        word_frequency_stride=4,binary_symbols=list(range(7))+list(range(128,256)),
        text_symbols=list(range(7,128)),native_classification_field=0x1c,
        native_classification=dict(binary=0,text=1),text_when_binary_count_at_most_text_count_unsigned_shift2=True,
        frequency_sum_arithmetic_wraps_32_bits=True,actual_frequency_heap_bounds_proven=False)


def _build_tree(raw,image,sections,imports,address):
    row = _path(raw,image,sections,imports,address,_TREE)
    return dict(**row,entry_state_register='ESI',entry_descriptor_SP_argument=4,callee_argument_cleanup_bytes=0,
        native_heap_initial_max=573,nonzero_frequency_words_build_heap=True,
        native_minimum_two_symbols_padding_and_both_cost_adjustments_bound=True,
        combined_frequencies_wrap_16_bits_and_depth_wraps_8_bits=True,
        all_three_heap_repair_calls_and_bitlength_code_children_bound=True,
        actual_heap_bounds_descriptor_domains_child_effects_and_termination_proven=False)


def _build_bit_length_tree(raw,image,sections,imports,address):
    row = _path(raw,image,sections,imports,address,_BIT_TREE,data=(('bit_order',19),))
    return dict(**row,entry_state_register='EAX',callee_argument_cleanup_bytes=0,
        scans_own_literal_and_distance_trees_before_building_bit_length_tree=True,
        native_order_scan_starts18_and_checks_down_through3=True,
        native_return_is_selected_order_index_not_count=True,
        native_optimal_bit_cost_adds_index_times3_plus17=True,
        actual_tree_state_counts_and_child_effects_proven=False)


def _send_all_trees(raw,image,sections,imports,address):
    row = _path(raw,image,sections,imports,address,_ALL_TREES,data=(('bit_order',19),))
    return dict(**row,entry_state_register='EAX',entry_SP_arguments=dict(literal_count=4,distance_count=8,bit_length_count=12),
        callee_argument_cleanup_bytes=0,header_fields_bits=dict(literal=5,distance=5,bit_length=4),
        header_subtractions=dict(literal=257,distance=1,bit_length=4),
        native_bit_order_lengths_each_use_three_bits=True,
        signed_nonpositive_bit_length_count_skips_order_loop=True,
        sends_literal_and_distance_using_count_minus_one=True,
        actual_count_domains_bitbuffer_bounds_tree_children_and_termination_proven=False)


def _compress_block(raw,image,sections,imports,address):
    # Only this own function needs the explicit larger window; all 1055 bytes,
    # including the path beyond its first RET at byte 1008, remain mandatory.
    row = _path(raw,image,sections,imports,address,_COMPRESS,window=1152,
        data=(('length',256),('extra_literal',116),('base_length',116),
            ('distance_low',256),('distance_high',256),('extra_distance',120),('base_distance',120)))
    return dict(**row,entry_state_register='EAX',entry_SP_arguments=dict(literal_tree=4,distance_tree=8),
        callee_argument_cleanup_bytes=0,first_RET_does_not_end_complete_function=True,
        literal_match_extra_bits_and_end_block_all_paths_bound=True,
        distance_is_decremented_before_own_low_or_high_code_lookup=True,
        native_end_block_symbol=256,native_end_block_length_field=0x16ac,
        both_final_returns_store_end_block_length=True,
        dynamic_tree_and_index_domains_pending_capacity_and_loop_termination_proven=False)


def _tables(paths,parent):
    symbols = parent['native_vm_save_algorithms']['native_save_algorithms']['symbol_tables']
    refs = paths['compress_block']['data_references']
    for role, expected in symbols['code_tables'].items():
        if refs[role] != expected:
            raise ValueError('CG 保存编码没有使用自己已经完整绑定的length/distance码表。')
    for role in ('literal','distance'):
        expected = symbols['extra_bits'][role]
        if refs['extra_'+role] != {key:expected[key] for key in ('address','bytes')}:
            raise ValueError('CG 保存编码没有使用自己的extra-bit表。')
    bases = {}
    for role, count in (('literal',28),('distance',30)):
        values, start = [], 0
        for extra in symbols['extra_bits'][role]['values'][:count]:
            values.append(start)
            start += 1 << extra
        # Native zlib table's last no-extra length entry stays zero and is not
        # subtracted on the code28 path; do not invent a generated 255 there.
        if role == 'literal':
            values.append(0)
        key = 'base_length' if role == 'literal' else 'base_distance'
        body = bytes.fromhex(refs[key]['bytes'])
        actual = list(struct.unpack('<'+'I'*len(values),body))
        if actual != values:
            raise ValueError('CG 保存编码的完整基值表没有对应自身extra-bit域。')
        bases[key] = dict(**refs[key],values=values)
    order = paths['build_bit_length_tree']['data_references']['bit_order']
    if order != paths['send_all_trees']['data_references']['bit_order'] or bytes.fromhex(order['bytes']) != bytes((16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15)):
        raise ValueError('CG 保存编码的构造和输出没有使用自己的完整位长顺序表。')
    data = list(refs.values())+[order]
    for i, first in enumerate(data):
        for second in data[i+1:]:
            if max(first['address'],second['address']) < min(first['address']+len(bytes.fromhex(first['bytes'])),second['address']+len(bytes.fromhex(second['bytes']))):
                raise ValueError('CG 保存编码的各类完整编码数据不能互相重叠。')
    return dict(base_tables=bases,bit_length_order=order,own_existing_extra_and_code_table_identities_bound=True,
        own_complete_base_and_bit_order_tables_static_bound=True,
        actual_dynamic_tree_indices_bitbuffer_and_compressed_output_proven=False)


def bind_native_cg_vm_save_tree_encoding(executable,header,vm,frames):
    raw = bytes(executable)
    parent = bind_native_cg_vm_save_algorithm_children(raw,header,vm,frames)
    image, sections = _pe_sections(raw)
    imports = _import_slots(raw,image)
    older = parent['layout'] == 'signed-word-legacy'
    encoding = None
    if older:
        children = parent['native_save_algorithm_children']
        entries = children['remaining_child_addresses']
        paths = dict(data_type=_data_type(raw,image,sections,imports,entries['data_type']),
            build_tree=_build_tree(raw,image,sections,imports,entries['build_tree']),
            build_bit_length_tree=_build_bit_length_tree(raw,image,sections,imports,entries['build_bit_length_tree']),
            compress_block=_compress_block(raw,image,sections,imports,entries['compress_block']),
            send_all_trees=_send_all_trees(raw,image,sections,imports,entries['send_all_trees']))
        if _one_helper(paths['build_bit_length_tree'],'build_tree') != paths['build_tree']['address']:
            raise ValueError('CG 保存位长树没有使用自身已接入的树构造入口。')
        remaining = dict(pqdownheap=_one_helper(paths['build_tree'],'pqdownheap'),
            gen_bitlen=_one_helper(paths['build_tree'],'gen_bitlen'),gen_codes=_one_helper(paths['build_tree'],'gen_codes'),
            scan_tree=_one_helper(paths['build_bit_length_tree'],'scan_tree'),send_tree=_one_helper(paths['send_all_trees'],'send_tree'))
        if len(set(remaining.values())) != len(remaining):
            raise ValueError('CG 保存编码的不同树子调用不能互相冒用。')
        tables = _tables(paths,parent)
        algorithms = parent['native_vm_save_algorithms']['native_save_algorithms']
        tree_parent = parent['native_vm_save_algorithms']['native_vm_save_trees']
        trees = tree_parent['native_save_trees']
        control = tree_parent['native_vm_save_deflate']['native_save_deflate']
        rows = list(paths.values())+list(children['paths'].values())+list(algorithms['paths'].values())+list(trees['paths'].values())+list(control['paths'].values())+[children['own_checksum']]
        for i, first in enumerate(rows):
            for second in rows[i+1:]:
                if max(first['address'],second['address']) < min(first['address']+first['code_bytes'],second['address']+second['code_bytes']):
                    raise ValueError('CG 保存树构造与编码完整函数范围不能重叠自己的其他路径。')
        encoding = dict(paths=paths,symbol_tables=tables,
            own_complete_tree_build_and_symbol_output_paths_static_bound=True,
            existing_build_tree_and_repeated_tree_child_identities_static_bound=True,
            remaining_child_addresses=remaining,complete_compression_child_effects_bounds_and_termination_proven=False,
            actual_native_compressed_bytes_file_and_round_trip_proven=False,native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
        native_vm_save_algorithm_children=parent,native_save_tree_encoding=encoding,
        own_legacy_save_tree_build_and_symbol_output_paths_static_bound=older,
        same_live_instance_lifetime_proven=False,complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False,initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False,complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
