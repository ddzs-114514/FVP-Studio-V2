"""Own Huffman builders and fixed tables, not a complete/live decoder grant.

Full explicit builder/wrapper paths and their own tables are required. Pure
arithmetic witnesses require valid immutable inputs; unchecked native array
indices, table padding, callback aliases and symbol/distance decoding are not
promoted to unconditional memory, lifetime or original-engine execution proof.
"""
from functools import lru_cache
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record
from .native_cg_vm_restore_children import _ChildGrammar,_bind
from .native_cg_vm_restore_blocks import bind_native_cg_vm_restore_blocks,_uint32
from .native_cg_vm_heap_paths import _word

SCHEMA = 'fvp-native-cg-vm-restore-huffman/1'
LENGTH_BASES = (3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258,0,0)
LENGTH_EXTRA = (0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,112,112)
DISTANCE_BASES = (1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577)
DISTANCE_EXTRA = (0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13)


def _huffman_shape_witness(lengths,root_bits):
    """Conditional count/Kraft/clamp arithmetic, not table heap execution."""
    lengths = tuple(lengths); _uint32(root_bits)
    if not 1 <= len(lengths) <= 288 or any(type(n) is not int or not 0 <= n <= 15 for n in lengths):
        raise ValueError('CG 编码表见证需要1..288个有效的0..15位长度；原生调用不替此处保护输入。')
    counts = [lengths.count(n) for n in range(16)]
    if counts[0] == len(lengths):
        return dict(status=0,root_bits=0,minimum_bits=0,maximum_bits=0,unused_terminal_codes=0,tree_is_null=True)
    minimum = next(n for n in range(1,16) if counts[n])
    maximum = max(n for n in range(1,16) if counts[n])
    root = min(max(root_bits,minimum),maximum); remaining = 1 << minimum
    for width in range(minimum,maximum):
        remaining -= counts[width]
        if remaining < 0:
            return dict(status=-3,root_bits=root,minimum_bits=minimum,maximum_bits=maximum,
                        unused_terminal_codes=None,tree_is_null=False)
        remaining <<= 1
    remaining -= counts[maximum]
    return dict(status=-3 if remaining < 0 else -5 if remaining and maximum != 1 else 0,
                root_bits=root,minimum_bits=minimum,maximum_bits=maximum,
                unused_terminal_codes=remaining if remaining >= 0 else None,tree_is_null=False)


def _huft_capacity_guard_witness(used,width):
    """Exact unsigned32 guard including wrap; not overflow protection."""
    used,width = _uint32(used),_uint32(width)
    requested = 1 << (width & 31)
    following = (used + requested) & 0xffffffff
    return dict(requested=requested,next_counter=following,native_guard_accepts=following <= 1440,
                overflow_protection_proven=False)


@lru_cache(maxsize=1)
def _fixed_tables_witness():
    """Complete static fixed-table arithmetic; these tables have zero padding."""
    def table(lengths,width,distance):
        counts = [lengths.count(n) for n in range(width + 1)]
        next_code = [0] * (width + 1); code = 0
        for n in range(1,width + 1):
            code = (code + counts[n - 1]) << 1; next_code[n] = code
        entries = [None] * (1 << width)
        for symbol,length in enumerate(lengths):
            code = next_code[length]; next_code[length] += 1
            reversed_code = sum(((code >> n) & 1) << (length - 1 - n) for n in range(length))
            if distance:
                # The native static invalid slots retain the final distance
                # base. They are not zero-filled entries; decoding the invalid
                # operation remains outside this builder/table binding.
                operation,value = (80 + DISTANCE_EXTRA[symbol],DISTANCE_BASES[symbol]) if symbol < 30 else (192,DISTANCE_BASES[-1])
            elif symbol < 256: operation,value = 0,symbol
            elif symbol == 256: operation,value = 96,256
            else: operation,value = (80 + LENGTH_EXTRA[symbol - 257]) & 255,LENGTH_BASES[symbol - 257]
            entry = struct.pack('<BBHI',operation,length,0,value)
            for index in range(reversed_code,len(entries),1 << length):
                if entries[index] is not None: raise AssertionError('Overlapping fixed Huffman arithmetic')
                entries[index] = entry
        assert all(entry is not None for entry in entries)
        return b''.join(entries)
    return table([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8,9,False),table([5] * 32,5,True)


def _trees_fixed(raw,image,sections,address):
    g = _ChildGrammar(); e,o = g.code,g.operand
    e('8b442404'); o('8b0d','literal_bits'); e('8b5424088908'); o('a1','distance_bits')
    e('8b4c240c89028b542410'); o('c701','literal_table'); o('c702','distance_table'); e('33c0c3')
    m,row = _bind(raw,image,sections,{},address,g)
    data = {}
    for key,expected in (('literal_bits',9),('distance_bits',5)):
        target = _word(m,key); at = _relocated(raw,image,sections,target,executable=False,length=4)
        if struct.unpack_from('<I',raw,at)[0] != expected:
            raise ValueError('CG 固定编码表位宽不是自身完整原生入口的9/5位。')
        data[key] = dict(address=target,bytes=raw[at:at + 4].hex())
    for key,expected in zip(('literal_table','distance_table'),_fixed_tables_witness()):
        target = _word(m,key); at = _relocated(raw,image,sections,target,executable=False,length=len(expected))
        if raw[at:at + len(expected)] != expected:
            raise ValueError('CG 固定编码表没有完整对应自身全部512/32项的原生运算结果。')
        data[key] = dict(address=target,bytes=len(expected),sha256=hashlib.sha256(expected).hexdigest())
    ranges = [(r['address'],r['address'] + (r['bytes'] if type(r['bytes']) is int else len(bytes.fromhex(r['bytes']))))
              for r in data.values()]
    if any(max(first[0],second[0]) < min(first[1],second[1])
           for index,first in enumerate(ranges) for second in ranges[index + 1:]):
        raise ValueError('CG 固定编码表数据区互相重叠。')
    row['data_references'] = data
    return dict(**row,callee_argument_cleanup_bytes=0,native_table_entry_bytes=8,literal_table_entries=512,
                distance_table_entries=32,all_fixed_entry_fields_and_padding_static_bound=True,
                literal_end_length_distance_and_invalid_entries_arithmetic_bound=True,
                global_table_immutability_during_live_engine_execution_proven=False)


def _trees_bits(raw,image,sections,address):
    g = _ChildGrammar(); e,o = g.code,g.operand
    e('5153578b7c24208b47286a046a1350c744241400000000ff57208bd883c40c85db')
    g.branch('75','build'); e('5fb8fcffffff5b59c3'); g.mark('build')
    e('8b54241c8b442418558b6c241856538d4c2414518b4c242052506a006a006a136a138bc5'); g.call('build')
    e('8bf083c42083fefd'); g.branch('75','incomplete'); e('8b4f285351'); o('c74718','message_oversubscribed')
    e('ff572483c4088bc65e5d5f5b59c3'); g.mark('incomplete'); e('83fefb'); g.branch('74','error')
    e('837d0000'); g.branch('75','release'); g.mark('error'); o('c74718','message_incomplete'); e('befdffffff')
    g.mark('release'); e('8b4f285351ff572483c4088bc65e5d5f5b59c3')
    _,row = _bind(raw,image,sections,{},address,g,data=(('message_oversubscribed',1),('message_incomplete',1)))
    return dict(**row,callee_argument_cleanup_bytes=0,native_scratch_allocation=dict(items=19,item_bytes=4),
                native_table_counter_initialized_zero=True,build_length_count=19,build_simple_count=19,
                all_explicit_scratch_release_paths_static_bound=True,
                build_minus5_or_zero_root_bits_changes_to_minus3=True,dynamic_callback_effects_proven=False)


def _trees_dynamic(raw,image,sections,address):
    g = _ChildGrammar(); e,o,c = g.code,g.operand,g.call
    e('51538b5c242c8b4328576a04682001000050c744241400000000ff53208bf883c40c85ff')
    g.branch('75','literal'); e('5fb8fcffffff5b59c3'); g.mark('literal')
    e('8b54242c8b442424558b6c241456578d4c2414518b4c242852508b442434')
    o('68','length_extra'); o('68','length_bases'); e('680101000055'); c('build0')
    e('8bf083c42085f6'); g.branch('0f85','literal_error',wide=True); e('8b4c2424833900')
    g.branch('0f84','literal_incomplete',wide=True)
    e('8b4424348b4c2430578d542414528b542424508b44242c51')
    o('68','distance_extra'); o('68','distance_bases'); e('568d0ca88b44244452'); c('build1')
    e('8bf083c42085f6'); g.branch('75','distance_error'); e('8b4c2428833900')
    g.branch('75','success'); e('81fd01010000'); g.branch('77','empty_distance')
    g.mark('success'); e('8b53285752ff532483c4085e5d5f33c05b59c3')
    g.mark('distance_error'); e('83fefd'); g.branch('75','distance_incomplete')
    e('8b43285750'); o('c74318','message_distance_oversubscribed'); e('ff532483c4088bc65e5d5f5b59c3')
    g.mark('distance_incomplete'); e('83fefb'); g.branch('75','distance_memory'); e('8b43285750')
    o('c74318','message_distance_incomplete'); e('befdffffffff532483c4088bc65e5d5f5b59c3')
    g.mark('distance_memory'); e('83fefc'); g.branch('74','distance_release'); g.mark('empty_distance')
    o('c74318','message_empty_distance'); e('befdffffff'); g.mark('distance_release')
    e('8b43285750ff532483c4088bc65e5d5f5b59c3')
    g.mark('literal_error'); e('83fefd'); g.branch('75','literal_memory'); e('8b4b285751')
    o('c74318','message_literal_oversubscribed'); e('ff532483c4088bc65e5d5f5b59c3')
    g.mark('literal_memory'); e('83fefc'); g.branch('74','literal_release'); g.mark('literal_incomplete')
    o('c74318','message_literal_incomplete'); e('befdffffff'); g.mark('literal_release')
    e('8b4b285751ff532483c4088bc65e5d5f5b59c3')
    m,row = _bind(raw,image,sections,{},address,g,
                  data=tuple(('message_' + name,1) for name in ('distance_oversubscribed','distance_incomplete',
                                                              'empty_distance','literal_oversubscribed','literal_incomplete')))
    if row['helper_addresses']['build0'] != row['helper_addresses']['build1']:
        raise ValueError('CG 字面值与距离表没有调用自身同一个构表入口。')
    references = row['data_references']
    for key,values in (('length_bases',LENGTH_BASES),('length_extra',LENGTH_EXTRA),
                       ('distance_bases',DISTANCE_BASES),('distance_extra',DISTANCE_EXTRA)):
        target = _word(m,key); size = 4 * len(values)
        at = _relocated(raw,image,sections,target,executable=False,length=size)
        if struct.unpack_from('<' + str(len(values)) + 'I',raw,at) != values:
            raise ValueError('CG 长度／距离表的完整原生基础值和附加位不是同来源数据。')
        references[key] = dict(address=target,bytes=raw[at:at + size].hex())
    return dict(**row,callee_argument_cleanup_bytes=0,native_scratch_allocation=dict(items=288,item_bytes=4),
                native_shared_table_counter_initialized_zero_and_appended=True,literal_simple_count=257,distance_simple_count=0,
                zero_distance_root_allowed_only_when_literal_count_at_most_257=True,
                all_explicit_scratch_release_paths_static_bound=True,
                counter_aliases_and_callback_mutation_effects_proven=False)


def _huft_grammar():
    g = _ChildGrammar(); e = g.code
    e('81ecfc000000535533ed568bb4240c010000578bd98bf8')
    for offset in range(0x50,0x80,4): e('896c24' + bytes((offset,)).hex())
    for offset in range(0x80,0x90,4): e('89ac24' + struct.pack('<I',offset).hex())
    spec = '''
e 8bc38bd6
b eb L070
e 8da42400000000
L070:
e 8b08ff448c508d4c8c5083c0044a
b 75 L070
e 39742450
b 75 L09e
e 8b8424200100008928892f
L091:
e 5f5e5d33c05b81c4fc000000c3
L09e:
e 8b0789442410b9010000008da42400000000
L0b0:
e 396c8c50
b 75 L0e8
e 396c8c54
b 75 L0d8
e 396c8c58
b 75 L0db
e 396c8c5c
b 75 L0e0
e 396c8c60
b 75 L0e5
e 83c10583f90f
b 76 L0b0
b eb L0e8
L0d8:
e 41
b eb L0e8
L0db:
e 83c102
b eb L0e8
L0e0:
e 83c103
b eb L0e8
L0e5:
e 83c104
L0e8:
e 3bc1894c2414
b 73 L0f6
e 894c24108bc1
L0f6:
e be0f000000
b eb L100
e 8d4900
L100:
e 396cb450
b 75 L109
e 4e
b 75 L100
L109:
e 3bc689742428
b 76 L117
e 897424108bc6
L117:
e ba01000000d3e23bce8907
b 73 L135
L124:
e 2b548c50
B 0f88 L4d8
e 41d1e23bce
b 72 L124
L135:
e 8d0cb5000000008d7c0c50894c24308b0f2bd18954244c
B 0f88 L4d8
e 03ca890f33c94e89ac2494000000
b 74 L175
e 33ff
L164:
e 034c3c5483c7044e898c3c94000000
b 75 L164
L175:
e 8bf333ff8da42400000000
L180:
e 8b0e83c6043bcd89742420
b 74 L1ac
e 8bb48c900000008b9c242c0100008d8c8c90000000893cb34689318b742420
L1ac:
e 8b8c2410010000473bf9
b 72 L180
e 8b4c24308b8c0c900000008b742428898c24100100008b8c242c010000894c24208b4c24148bd833fff7db3bce896c242c89ac2490000000c7442418ffffffff89bc24d0000000897c2430
B 0f8f L4b5
e 8b7424388d51ff895424408d548c50895424248d642400
L220:
e 8b5424248b1285d28954241c
B 0f84 L494
L232:
e 8b4c241c8b54241449894c241c8d0c033bd1
B 0f8e L36d
e 894c243c8bcb2bc8
b eb L260
L254:
e 8b4424108b4c24448d642400
L260:
e 8b6c24188b54242845896c24188b6c243c03d803c803e82bd33bd0894c2444896c243c
b 76 L287
e 8bd0
L287:
e 8b4c24148b6c241c2bcbb801000000d3e08d7d013bc7
b 76 L2c6
e 83cfff2bfd8b6c242403c73bca
b 73 L2c6
e 413bca
b 73 L2c6
L2b3:
e 8b7d0483c504d1e03bc7
b 76 L2c6
e 2bc7413bca
b 72 L2b3
L2c6:
e 8b8424280100008b00bf01000000d3e78d143881faa0050000
B 0f87 L4d8
e 8bac24240100008d6cc5008b4424188d8484d00000008944244889288b84242801000089108b44241885c0896c2430
b 74 L352
e 8b74242c8a54241089b48490000000884c24348b4c24448bc6d3e88b4c24488b49fc8bf52bf1885424358b542434c1fe032bf08914c18974c104
b eb L35b
L352:
e 8b8424200100008928
L35b:
e 8b4c243c394c2414
B 0f8f L254
e 8b6c242c
L36d:
e 8b5424148b8c242c0100008ac22ac3884424358b8424100100008d0c818b4424203bc1
b 72 L399
e c6442434c0
b eb L3e1
L399:
e 8b308b8c24140100003bf1
b 73 L3ba
e 81fe000100000f92c1fec983e160884c2434
b eb L3da
L3ba:
e 2bf18b8c241c010000c1e6028a0c0e80c150884c24348b8c24180100008b340e
L3da:
e 83c00489442420
L3e1:
e 8bca2bcbba01000000d3e28bc58bcbd3e83bc7
b 73 L41c
e 8b4c24308d0cc18d4900
L400:
e 8b6c243489298d2cd50000000089710403c203cd3bc7
b 72 L400
e 8b6c242c
L41c:
e 8b4c2440b801000000d3e085c5
b 74 L438
b eb L430
e 8d4900
L430:
e 33e8d1e885c5
b 75 L430
L438:
e 8bcbba01000000d3e233e88b4424188b8c84900000004a23d53bd1896c242c
b 74 L480
e 8da42400000000
L460:
e 2b5c24108bcbba01000000d3e28b8c848c000000484a23d53bd1
b 75 L460
e 89442418
L480:
e 8b44241c85c08b442410
B 0f85 L232
e 8b4c2414
L494:
e 83442424048b5424404142895424403b4c2428894c2414
B 0f8e L220
e 8b54244c
L4b5:
e 85d2
B 0f84 L091
e 837c242801
B 0f84 L091
e 5f5e5db8fbffffff5b81c4fc000000c3
L4d8:
e 5f5e5db8fdffffff5b81c4fc000000c3
'''
    for line in spec.splitlines():
        words = line.split()
        if not words: continue
        command,*args = words
        if command.endswith(':'): g.mark(command[:-1])
        elif command == 'e': e(args[0])
        elif command in ('b','B'): g.branch(*args,wide=(command == 'B'))
        else: raise AssertionError('Unknown explicit Huffman grammar command')
    return g


def _huft_build(raw,image,sections,address):
    at,code = _code(raw,image,sections,address,1536)
    m = _huft_grammar().match(code)
    return dict(**_record(address,at,m[0]),helper_addresses={},import_calls={},
                own_complete_explicit_instruction_paths_static_bound=True,callee_argument_cleanup_bytes=0,
                register_arguments=dict(lengths='ECX',root_bits_pointer='EAX'),
                stack_argument_displacements=dict(count=4,simple_count=8,bases=12,extra=16,
                                                  root_pointer=20,entry_buffer=24,entry_counter=28,sorted_scratch=32),
                native_stack_scratch_bytes=252,native_length_count_bins=16,native_maximum_bit_length=15,
                input_zero_count_not_guarded=True,input_length_array_indices_not_guarded=True,
                zero_lengths_write_null_tree_and_zero_root_bits=True,
                root_bit_width_clamped_to_actual_minimum_and_maximum=True,
                oversubscribed_code_space_returns_minus3=True,incomplete_tree_returns_minus5_except_maximum_one=True,
                unsigned32_entry_counter_plus_shift_guard_maximum=1440,table_entry_bytes=8,
                unsigned_counter_addition_wrap_not_prevented=True,link_offset_uses_signed_SAR3=True,
                dynamically_constructed_entry_padding_bytes_not_initialized=True,
                invalid_padding_entry_base_not_assumed_defined=True,
                caller_data_counter_ranges_aliasing_and_full_memory_effects_proven=False,native_code_executed=False)


def bind_native_cg_vm_restore_huffman(executable,header,vm,frames):
    raw = bytes(executable); parent = bind_native_cg_vm_restore_blocks(raw,header,vm,frames)
    legacy = parent['layout'] == 'signed-word-legacy'; huffman = None
    if legacy:
        image,sections = _pe_sections(raw)
        calls = parent['native_restore_blocks']['remaining_decoder_children']
        paths = dict(trees_fixed=_trees_fixed(raw,image,sections,calls['trees_fixed']),
                     trees_bits=_trees_bits(raw,image,sections,calls['trees_bits']),
                     trees_dynamic=_trees_dynamic(raw,image,sections,calls['trees_dynamic']))
        target = paths['trees_bits']['helper_addresses']['build']
        if target != paths['trees_dynamic']['helper_addresses']['build0']:
            raise ValueError('CG 长度编码表与字面值／距离表没有共用自身同一个构表入口。')
        paths['huft_build'] = _huft_build(raw,image,sections,target)
        lower = list(parent['native_restore_blocks']['paths'].values())
        lower += list(parent['native_vm_restore_inflate']['native_restore_inflate']['paths'].values())
        rows = list(paths.values()) + lower
        for index,first in enumerate(rows):
            if any(max(first['address'],second['address']) < min(first['address'] + first['code_bytes'],second['address'] + second['code_bytes'])
                   for second in rows[index + 1:]):
                raise ValueError('CG 编码表与自身分块、分配、输出或已有解包函数重叠。')
        block = parent['native_restore_blocks']['paths']['block_step']
        table_start = block['address'] + block['code_bytes']; table_end = block['dispatch_tables']['type_table']['address'] + 16
        if any(max(row['address'],table_start) < min(row['address'] + row['code_bytes'],table_end) for row in paths.values()):
            raise ValueError('CG 编码表函数覆盖自身分块分发表。')
        huffman = dict(paths=paths,remaining_symbol_decoder_address=calls['codes_step'],
                       own_complete_Huffman_builder_and_wrapper_paths_static_bound=True,
                       own_complete_fixed_tables_and_dynamic_base_extra_data_static_bound=True,
                       complete_symbol_distance_decode_effects_proven=False,
                       complete_heap_callback_SEH_aliasing_reentry_and_input_bounds_proven=False,native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
                native_vm_restore_blocks=parent,native_restore_huffman=huffman,
                own_legacy_Huffman_builder_and_wrapper_paths_static_bound=legacy,
                modern_restore_has_no_legacy_compressed_convert_path=not legacy,
                complete_compression_child_effects_proven=False,actual_file_bytes_and_type_read_bounds_proven=False,
                complete_heap_and_aliasing_effects_proven=False,complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
