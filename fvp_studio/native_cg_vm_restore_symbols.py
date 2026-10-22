"""Own full symbol/fast-decoder paths; not unconditional/live decoding proof.

Code, state table, masks and same-source links are explicit. Actual file bytes,
Huffman indices, history availability, buffers, callbacks and live restoration
remain conditions, not grants inferred from a mapped RET or diagnostic window.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record
from .native_cg_vm_restore_children import _ChildGrammar, _bind
from .native_cg_vm_heap_paths import _word, _callee
from .native_cg_vm_restore_blocks import _uint32
from .native_cg_vm_restore_huffman import bind_native_cg_vm_restore_huffman

SCHEMA = 'fvp-native-cg-vm-restore-symbols/1'


def _fast_entry_witness(contiguous_output_bytes,input_bytes):
    output,input_bytes = _uint32(contiguous_output_bytes),_uint32(input_bytes)
    return dict(native_fast_guard_accepts=output >= 258 and input_bytes >= 10,
                buffer_table_history_and_callback_effects_proven=False)


def _fast_unread_witness(consumed_input_bytes,held_bits):
    consumed,bits = _uint32(consumed_input_bytes),_uint32(held_bits)
    unread = min(consumed,bits >> 3)
    return dict(unread_bytes=unread,consumed_after_unread=consumed - unread,
                held_bits_after_unread=bits - (unread << 3),actual_input_pointer_bounds_proven=False)


def _finish_unget_witness(input_pointer,input_available,held_bits):
    pointer,available,bits = _uint32(input_pointer),_uint32(input_available),_uint32(held_bits)
    returned = int(bits > 7)
    return dict(unread_bytes=returned,input_pointer=(pointer - returned) & 0xffffffff,
                input_available=(available + returned) & 0xffffffff,held_bits=bits - 8 * returned,
                loop_or_overflow_protection_proven=False)


def _history_copy_witness(window,write,distance,length):
    """Conditional sequential read-after-write/ring arithmetic, not live flush."""
    if not isinstance(window,(bytes,bytearray)) or not 1 <= len(window) <= 32768:
        raise ValueError('CG 历史复制见证需要有效、独立的1..32768字节窗口。')
    if any(type(n) is not int for n in (write,distance,length)) or not (
            0 <= write < len(window) and 1 <= distance <= len(window) and 3 <= length <= 258):
        raise ValueError('CG 历史复制见证需要有效位置、正距离和原生3..258字节长度。')
    data,emitted = bytearray(window),bytearray()
    source = (write - distance) % len(data)
    for n in range(length):
        value = data[source]; source = (source + 1) % len(data)
        data[(write + n) % len(data)] = value; emitted.append(value)
    return dict(window_after=bytes(data),emitted=bytes(emitted),next_write=(write + length) % len(data),
                sequential_overlap_reads_newly_written_bytes=True,
                actual_flush_aliasing_and_unread_window_overwrite_safety_proven=False,native_code_executed=False)


def _explicit_grammar(spec):
    g = _ChildGrammar()
    branches = {'73','72','74','75','76','eb','e9','0f84','0f85','0f86','0f87','0f82','0f83'}
    for line in spec.splitlines():
        for token in line.split('|'):
            words = token.split()
            if not words: continue
            name,*args = words
            if name.startswith('@'): g.mark(name[1:])
            elif name in branches: g.branch(name,args[0],wide=name.startswith('0f') or name == 'e9')
            elif name == 'call': g.call(args[0])
            elif name == 'word': g.operand(*args)
            else: g.code(name)
    return g


def _symbol_grammar():
    return _explicit_grammar('''
83ec145355568b7424248b56208b4e048b5e1c578b7c242c8b47048b2f8944242c8b4630895424288b56343bd0894c2410
73 L038|2bc248|eb L03d|@L038|8b462c2bc2|@L03d|8b0983f90989442414|0f87 L5a3|8d642400
@L050|word ff248d state_table
@L057|3d02010000|0f82 L0ff|837c242c0a|0f82 L0ff
8b4424288b4c242c894620895e1c8b1f894f048b4f088bc52bc303c88b442410894f08892f578956348b48188b501456510fb64811520fb650105152
call fast_decode
8b4f048b56208b2f8b5e1c894c24448b4e30895424408b563483c4183bd189442430
73 L0d7|2bca49|eb L0dc|@L0d7|8b4e2c2bca|@L0dc|85c0894c2414|74 L0ff
33c983f8018b4424100f95c18d4c090789088b442414|e9 L594
@L0ff|8b4424100fb6481089480c8b4814894808c70001000000
@L116|8b4424108b400c3bd889442418|73 L167|eb L130|8da424000000008bff
@L130|8b44242c85c0|0f84 L601|488944242c0fb645008bcbd3e08b4c242883c308c7442430000000000bc88b442418453bd8894c2428|72 L130
@L167|word 8b0c85 masks
234c24288b4424108b40088d04c80fb64801894424188b442428d3e88b4c2418894424280fb641012bd80fb60185c0|75 L1b8
8b4424108b4904894808c700060000008b442414|e9 L594
@L1b8|a810|74 L1df|8b4c241083e00f8941088b4424188b40048941048b442414c70102000000|e9 L594
@L1df|a840|0f84 L324|a8208b442410|0f84 L5db|c700070000008b442414|e9 L594
@L202|8b4c24108b41083bd889442418|73 L248
@L211|8b44242c85c0|0f84 L601|488944242c0fb645008bcbd3e08b4c242883c308c7442430000000000bc88b442418453bd8894c2428|72 L211
@L248|word 8b0c85 masks
234c24288b4424100148048b4c2418d36c24288bc12bd88b4424100fb6481189480c8b4818894808c70003000000|eb L283
@L27f|8b442410|@L283|8b400c3bd889442418|73 L2c7|8bff
@L290|8b44242c85c0|0f84 L601|488944242c0fb645008bcbd3e08b4c242883c308c7442430000000000bc88b442418453bd8894c2428|72 L290
@L2c7|word 8b0c85 masks
234c24288b4424108b40088d04c80fb6480189442418d36c24288b4424180fb648010fb6002bd9a810|74 L31c
8b4c241083e00f8941088b4424188b400489410c8b442414c70104000000|e9 L594
@L31c|a840|0f85 L5ec
@L324|8b4c241089410c8b4424188b48048d04c88b4c24108941088b442414|e9 L594
@L345|8b4424108b40083bd889442418|73 L38b
@L354|8b44242c85c0|0f84 L601|488944242c0fb645008bcbd3e08b4c242883c308c7442430000000000bc88b442418453bd8894c2428|72 L354
@L38b|word 8b0c85 masks
234c24288b44241001480c8b4c2418d36c24288bc12bd88b442410c70005000000
@L3b3|8b4c24108bc22b410c8b4e283bc18944241c|73 L3eb
8b462c2bc18b4c241c89442420|eb L3e0|@L3d6|8b4424208d9b00000000
@L3e0|03c83b4e28|72 L3d6|894c241c
@L3eb|8b4c24108b410485c08b442414|0f84 L58e|8bff
@L400|85c0|0f85 L499|8b462c3bd089442418|75 L432|8b46308b4e283bc1|74 L432
8bd13bd0|73 L428|2bc248|eb L42e|@L428|8b4424182bc2|@L42e|85c0|75 L499
@L432|8956348b542430525756|call flush0
8b56348944243c8b463083c40c3bd089442420|73 L45b|2bc248|eb L460|@L45b|8b462c2bc2
@L460|8b4e2c3bd189442414894c2418|75 L491|8b4e288b4424203bc1|74 L48d|8bd13bd0|73 L485
2bc248|eb L491|@L485|8b4424182bc2|eb L491|@L48d|8b442414|@L491|85c0|0f84 L63c
@L499|8b4c241c8a09880a8b4c241c4241483b4e2cc744243000000000894c241c89442414|75 L4c4
8b4e28894c241c|@L4c4|8b4c2410ff490483790400|0f85 L400|e9 L58e
@L4da|85c0|0f85 L573|8b462c3bd089442418|75 L50c|8b46308b4e283bc1|74 L50c|8bd13bd0
73 L502|2bc248|eb L508|@L502|8b4424182bc2|@L508|85c0|75 L573
@L50c|8956348b542430525756|call flush1
8b56348944243c8b463083c40c3bd089442420|73 L535|2bc248|eb L53a|@L535|8b462c2bc2
@L53a|8b4e2c3bd189442414894c2418|75 L56b|8b4e288b4424203bc1|74 L567|8bd13bd0|73 L55f
2bc248|eb L56b|@L55f|8b4424182bc2|eb L56b|@L567|8b442414|@L56b|85c0|0f84 L63c
@L573|8b4c24108a4908880a8b4c24104248c74424300000000089442414
@L58e|c70100000000
@L594|8b4c24108b0983f909|0f86 L050
@L5a3|6afe|@L5a5|8b4c242c8b442430894e20895e1c8b1f8947048b47088bcd2bcb03c1894708
@L5c4|57892f56895634|call flush2|83c40c5f5e5d5b83c414c3
@L5db|c70009000000|word c74718 message_literal|6afd|eb L5a5
@L5ec|8b442410c70009000000|word c74718 message_distance|6afd|eb L5a5
@L601|8b442428894620895e1c8b1f8b47088bcd2bcb03c1c7470400000000894708892f8956348b542430525756
call flush3|83c40c5f5e5d5b83c414c3
@L63c|8b4424288b4c242c894620895e1c8b1f894f048b4f088bc52bc303c8894f088b4c243051|e9 L5c4
@L665|83fb07|76 L677|8b4c242c83eb0841894c242c4d
@L677|8956348b542430525756|call flush4|8b56348b4e3083c40c3bca|74 L6b3
8b4c2428894e208b4c242c895e1c8b1f894f048bcd2bcb014f0850|e9 L5c4
@L6b3|8b442410c70008000000
@L6bd|6a01|e9 L5a5
@L6c4|8b4424288b4c242c894620895e1c8b1f894f048b4f088bc52bc303c8894f086afd|e9 L5c4
''')


def _fast_grammar():
    return _explicit_grammar('''
83ec148b4c24288b44242c8b512053558b288b4004568b7130578b79343bfe894424108b411c896c2418
73 F035|2bf74e89742414|eb F03e|@F035|8b492c2bcf894c2414|@F03e|8b4c2428|word 8b0c8d masks
894c241c8b4c242c|word 8b0c8d masks|894c242c8d642400
@F060|83f814|73 F081|@F065|8b4c24100fb6750049894c24108bc8d3e683c0080bd64583f814|72 F065
896c2418|@F081|8b4c241c8b74243023ca0fb61cce8d34ce0fb64e01d3ea85db|0f84 F24f
0fb64e012bc1f6c310|75 F0e7|90
@F0b0|f6c340|0f85 F2d9|word 8b0c9d masks
8b5e0423ca03cb0fb61cce8d34ce0fb64e01d3ea85db|0f84 F24f|0fb64e012bc1f6c310|74 F0b0
@F0e7|83e30f|word 8b0c9d masks|23ca034e042bc3894c24288bcbd3ea83f80f|73 F121
@F105|8b4c24100fb6750049894c24108bc8d3e683c0080bd64583f80f|72 F105|896c2418
@F121|8b4c242c8b74243423ca0fb61cce8d34ce0fb64e01d3ea0fb64e012bc1f6c310|75 F176
@F147|f6c340|0f85 F2c8|word 8b0c9d masks
8b5e0423ca03cb0fb61cce8d34ce0fb64e01d3ea2bc1f6c310894c2420|74 F147
@F176|83e30f3bc3|73 F1a3|8d4900
@F180|8b4c24100fb66d0049894c24108bc8d3e583c0080bd58b6c2418453bc3896c2418|72 F180
@F1a3|8b4e04|word 8b2c9d masks
8b74241423ea03e98bcbd3ea8b4c24282bf1897424148bf72bf58b6c24382bc38b5d283bf3|73 F230
8b6d2c896c24282beb8d4900|@F1e0|03f53bf3|72 F1e0|8b6c24282bee3bcd|76 F211|2bcd
@F1f2|8a1e881f47464d|75 F1f2|8b7424388b7628
@F202|8a1e881f474649|75 F202|8b6c2418|eb F260
@F211|8a1e881f8a5e014746881f474683e902
@F221|8a1e881f474649|75 F221|8b6c2418|eb F260
@F230|8a1e881f8a5e014746881f474683e902
@F240|8a1e881f474649|75 F240|8b6c2418|eb F260
@F24f|2bc18a4e04880f8b4c24144749894c2414
@F260|817c241402010000|72 F275|837c24100a|0f83 F060
@F275|8b74243c8b5c24108b4e042bcb8bd8c1eb033bd9|73 F28d|8bcb
@F28d|8b5c24388953208d14cd000000002bc289431c8b4424108b162be903c88b4608894e048bcd2bca03c1894608892e897b345f5e5d33c05b83c414c3
@F2c8|8b4c243c8b5c2410|word c74118 message_distance|eb F33f
@F2d9|f6c3208b5c2410|74 F334|8b74243c8b4e042bcb8bd8c1eb033bd9|73 F2f6|8bcb
@F2f6|8b5c24388953208d14cd000000002bc289431c8b4424108b162be903c88b4608894e048bcd2bca03c1894608892e897b345f5e5db8010000005b83c414c3
@F334|8b4c243c|word c74118 message_literal
@F33f|8b71042bf3897424288b5c24288bf0c1ee033bf3|72 F357|8bf3
@F357|8b5c24388953208d14f5000000002bc289431c8b4424102bee03f08b41088971048b318bd52bd603c28929894108897b345f5e5db8fdffffff5b83c414c3
''')


def _mask_reference(raw,image,sections,m):
    target = _word(m,'masks'); at = _relocated(raw,image,sections,target,executable=False,length=68)
    if struct.unpack_from('<17I',raw,at) != tuple((1 << n) - 1 for n in range(17)):
        raise ValueError('CG 字面值／距离解码没有使用自身完整17项位掩码表。')
    return dict(address=target,bytes=raw[at:at + 68].hex())


def _codes_step(raw,image,sections,address):
    at,code = _code(raw,image,sections,address,4096); m = _symbol_grammar().match(code)
    calls = {n[:-5]:_callee(raw,image,sections,address,m,n) for n in m.groupdict() if n.endswith('_call')}
    if len({calls['flush' + str(n)] for n in range(5)}) != 1:
        raise ValueError('CG 字面值／距离解码的重复输出不是自身同一入口。')
    labels = ('L057','L116','L202','L27f','L345','L3b3','L4da','L665','L6bd','L6c4')
    table = _word(m,'state_table'); table_at = _relocated(raw,image,sections,table,executable=True,length=40)
    targets = list(struct.unpack_from('<10I',raw,table_at))
    if table != address + m.end() + 2 or targets != [address + m.start(n) for n in labels]:
        raise ValueError('CG 字面值／距离解码的10状态表没有完整对应自身内部入口。')
    if raw[at + m.end():at + m.end() + 2] != b'\x8b\xff':
        raise ValueError('CG 字面值／距离解码的函数与状态表边界不符。')
    data = dict(masks=_mask_reference(raw,image,sections,m))
    for name in ('message_literal','message_distance'):
        target = _word(m,name); offset = _relocated(raw,image,sections,target,executable=False,length=1)
        data[name] = dict(address=target,bytes=raw[offset:offset + 1].hex())
    return dict(**_record(address,at,m[0]),helper_addresses=calls,data_references=data,
                dispatch_tables=dict(state_table=dict(address=table,bytes=40,targets=targets)),
                own_complete_explicit_instruction_paths_static_bound=True,callee_argument_cleanup_bytes=0,
                native_state_count=10,unsigned_state_guard_inclusive=[0,9],
                fast_requires_contiguous_output_at_least=258,fast_requires_available_input_at_least=10,
                all_partial_input_output_full_literal_length_distance_error_and_finish_paths_static_bound=True,
                literal_and_history_copy_use_forward_byte_order=True,
                source_wrap_adds_window_size_repeatedly_without_zero_window_guard=True,
                history_availability_and_distance_bounds_not_checked=True,
                finish_ungets_at_most_one_input_byte_when_held_bits_above_seven=True,
                actual_tables_buffers_flush_aliases_and_input_read_effects_proven=False,native_code_executed=False)


def _fast_decode(raw,image,sections,address):
    m,row = _bind(raw,image,sections,{},address,_fast_grammar(),
                  data=(('message_literal',1),('message_distance',1)))
    row['data_references']['masks'] = _mask_reference(raw,image,sections,m)
    return dict(**row,callee_argument_cleanup_bytes=0,native_stack_scratch_bytes=20,
                input_guard_is_in_own_caller_not_before_each_fast_read=True,
                initial_literal_read_requires_twenty_held_bits=True,
                initial_distance_read_requires_fifteen_held_bits=True,
                history_copy_is_sequential_not_memmove=True,forward_copy_first_two_bytes_before_remaining_loop=True,
                no_local_minimum_length_or_available_history_guard=True,
                loop_requires_contiguous_output_at_least=258,loop_requires_available_input_at_least=10,
                all_normal_end_invalid_literal_invalid_distance_returns_static_bound=True,
                whole_input_bytes_unread_is_minimum_of_consumed_bytes_and_held_bits_divided_by_eight=True,
                success_end_and_error_statuses=[0,1,-3],actual_input_buffer_aliasing_and_history_effects_proven=False)


def bind_native_cg_vm_restore_symbols(executable,header,vm,frames):
    raw = bytes(executable); parent = bind_native_cg_vm_restore_huffman(raw,header,vm,frames)
    legacy = parent['layout'] == 'signed-word-legacy'; symbols = None
    if legacy:
        image,sections = _pe_sections(raw); huffman = parent['native_restore_huffman']
        ordinary = _codes_step(raw,image,sections,huffman['remaining_symbol_decoder_address'])
        fast = _fast_decode(raw,image,sections,ordinary['helper_addresses']['fast_decode'])
        blocks = parent['native_vm_restore_blocks']['native_restore_blocks']
        if ordinary['helper_addresses']['flush0'] != blocks['paths']['flush']['address']:
            raise ValueError('CG 字面值／距离解码没有沿自身已绑定的输出入口。')
        if ordinary['data_references']['masks'] != fast['data_references']['masks'] or ordinary['data_references']['masks'] != blocks['paths']['block_step']['data_references']['masks']:
            raise ValueError('CG 分块、字面值／距离与快速解码没有共用自身同一位掩码数据。')
        if any(ordinary['data_references'][name] != fast['data_references'][name] for name in ('message_literal','message_distance')):
            raise ValueError('CG 普通与快速解码没有使用自身相同的错误信息入口。')
        paths = dict(codes_step=ordinary,fast_decode=fast)
        rows = list(paths.values()) + list(huffman['paths'].values()) + list(blocks['paths'].values())
        rows += list(parent['native_vm_restore_blocks']['native_vm_restore_inflate']['native_restore_inflate']['paths'].values())
        for index,first in enumerate(rows):
            if any(max(first['address'],second['address']) < min(first['address'] + first['code_bytes'],second['address'] + second['code_bytes'])
                   for second in rows[index + 1:]):
                raise ValueError('CG 字面值／距离解码与自身构表、分块、输出或释放函数重叠。')
        ranges = [(ordinary['address'] + ordinary['code_bytes'],ordinary['dispatch_tables']['state_table']['address'] + 40)]
        block = blocks['paths']['block_step']
        ranges.append((block['address'] + block['code_bytes'],block['dispatch_tables']['type_table']['address'] + 16))
        if any(max(row['address'],start) < min(row['address'] + row['code_bytes'],end)
               for row in rows for start,end in ranges):
            raise ValueError('CG 解码函数覆盖自身状态或类型表。')
        symbols = dict(paths=paths,remaining_compressed_decoder_children={},
                       own_complete_symbol_and_fast_decoder_instruction_paths_static_bound=True,
                       complete_input_Huffman_indices_history_heap_callback_aliasing_and_reentry_effects_proven=False,
                       native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
                native_vm_restore_huffman=parent,native_restore_symbols=symbols,
                own_legacy_symbol_and_fast_decoder_paths_static_bound=legacy,
                modern_restore_has_no_legacy_compressed_convert_path=not legacy,
                complete_compression_child_effects_proven=False,actual_file_bytes_and_type_read_bounds_proven=False,
                complete_heap_and_aliasing_effects_proven=False,complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
