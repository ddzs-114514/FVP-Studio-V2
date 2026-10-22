"""Own legacy block dispatch, stored data and output ring; not live decoding.

The complete block controller and its flush/allocation paths are required.
Huffman builders and symbol/distance decoding remain separate descendants.
Arithmetic witnesses are conditional on valid, nonaliasing memory and do not
execute native code or grant public output or unchecked file input safety.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record
from .native_cg_vm_heap_paths import _word, _callee
from .native_cg_vm_restore_children import _ChildGrammar, _bind
from .native_cg_vm_restore_inflate import bind_native_cg_vm_restore_inflate, MASK

SCHEMA = 'fvp-native-cg-vm-restore-blocks/1'


def _uint32(value):
    if type(value) is not int or not 0 <= value <= MASK:
        raise ValueError('CG 解包参数必须是实际32位位模式。')
    return value


def _stored_length_witness(header):
    header = _uint32(header)
    length = header & 0xffff
    if ((~header & MASK) >> 16) != length:
        raise ValueError('CG 不压缩块的长度与反码不一致。')
    return length


def _dynamic_counts_witness(header):
    header = _uint32(header) & 0x3fff
    literals,distances = header & 31,(header >> 5) & 31
    if literals > 29 or distances > 29:
        raise ValueError('CG 动态解码块的原生数量字段超出范围。')
    return dict(literal_codes=literals + 257,distance_codes=distances + 1,
                length_codes=(header >> 10) + 4,length_allocation_items=literals + distances + 258,
                length_allocation_item_bytes=4)


def _flush_spans_witness(window_start,window_end,read,write,available,status=-5):
    """At most two arithmetic copy spans, conditional on a valid native ring."""
    for value in (window_start,window_end,read,write,available): _uint32(value)
    if (not window_start < window_end or not window_start <= read <= window_end
            or not window_start <= write <= window_end or type(status) is not int
            or not -(2**31) <= status < 2**31):
        raise ValueError('CG 输出缓冲区见证没有满足有效、不回绕的原生窗口条件。')
    spans = []
    stop = write if read <= write else window_end
    count = min(stop - read,available)
    spans.append(dict(source=read,bytes=count)); available -= count; read += count
    if count and status == -5: status = 0
    if read == window_end:
        read = window_start
        if write == window_end: write = window_start
        count = min(write - read,available)
        spans.append(dict(source=read,bytes=count)); available -= count; read += count
        if count and status == -5: status = 0
    return dict(spans=spans,read=read,write=write,available=available,status=status,
                copied_bytes=sum(s['bytes'] for s in spans),
                checksum_call_count_if_callback_nonnull=len(spans),native_code_executed=False)


def _block_grammar():
    # Labels name relative locations, never game-specific absolute addresses.
    # All instruction runs, internal branches, call operands and both tables
    # are explicit. Nothing is accepted merely because it falls in a window.
    spec = '''
e 83ec34538b5c243c8b4b20558b6b1c568b7424488b46048944240c8b4334894c24448b4b303bc1578b3e897c241c89442414
b 73 L039
e 2bc849
b eb L03e
L039:
e 8b4b2c2bc8
L03e:
e 8b1383fa09894c2418
b 76 L089
L049:
e 6afe
L04b:
e 8b4c244c8b542414894b20896b1c8956048b168bc72bc2
L062:
e 8b4e0803c8
L067:
e 894e088b4c241856893e53894b34
c flush0
e 83c40c5f5e5d5b83c434c3
L085:
e 8b4c2418
L089:
e 8b442448
j edx state_table
L094:
e 83fd03
b 73 L0d5
e 8da42400000000
L0a0:
e 8b4c241085c9
B 0f84 L7b6
e 8bd14a895424100fb6178bcdd3e283c508c7442450000000000bc24783fd0389442448897c241c
b 72 L0a0
L0d5:
e 8bc883e1078bd183e201d1e983f903895318
B 0f87 L79e
j ecx type_table
L0f4:
e 83ed038bcd83e107c1e803d3e82be9c7030100000089442448
B e9 L79e
L112:
e 568d442428508d4c2430518d542438528d44244050
c trees_fixed
e 8b4c24388b54243c8b44244056518b4c244c525051
c codes_new0
e 83c42885c0894304
B 0f84 La4f
e c16c24480383ed03c70306000000
B e9 L79e
L167:
e c1e8038944244883ed03c70303000000
B e9 L79e
L17c:
e 83fd20
b 73 L1b6
L181:
e 8b4c241085c9
B 0f84 L962
e 8bd14a895424100fb6178bcdd3e283c508c7442450000000000bc24783fd2089442448897c241c
b 72 L181
L1b6:
e 8bc8f7d081e1ffff0000c1e8103bc1
B 0f85 L844
e 33ed8bc13bc5894b04896c2448
B 0f84 L30c
e b8020000008903
B e9 L79e
L1ea:
e 8b44241085c0
B 0f84 L941
e 85c9
B 0f85 L2a3
e 8b532c39542414
b 75 L22a
e 8b43308b4b283bc8
b 74 L22a
e 894c2414
b 73 L21e
e 2bc1488bc8
b eb L222
L21e:
e 2bd18bca
L222:
e 85c9894c2418
b 75 L2a3
L22a:
e 8b4c24508b442414515653894334
c flush1
e 8b4b308944245c8b433483c40c3bc189442414894c2420
b 73 L25b
e 2bc849
b eb L260
L25b:
e 8b4b2c2bc8
L260:
e 8b532c3bc2894c241889542434
b 75 L29b
e 8b43288b5424203bc2
b 74 L297
e 89442414
b 73 L28b
e 2bd04a8bca894c2418
b eb L29b
L28b:
e 8b4c24342bc8894c2418
b eb L29b
L297:
e 8b442414
L29b:
e 85c9
B 0f84 L858
L2a3:
e 8b43048b5424103bc2c744245000000000
b 76 L2b8
e 8bc2
L2b8:
e 3bc1
b 76 L2be
e 8bc1
L2be:
e 8b74241c8b7c24148bc88bd1c1e902f3a58bca8b54241883e103f3a48b4c241c8b7c24108b74241403c8894c241c8b4b042bf803f02bd02bc8897c24108974241489542418894b04
B 0f85 L79e
L30c:
e 8b4318f7d81bc083e0078903
B e9 L79e
L31d:
e 83fd0e
b 73 L353
L322:
e 8b4c241085c9
B 0f84 L962
e 8bd14a895424100fb6178bcdd3e283c508c7442450000000000bc24783fd0e89442448
b 72 L322
L353:
e 25ff3f00008bc883e11f83f91d894304
B 0f87 L89a
e c1e80583e01f83f81d
B 0f87 L89a
e 8d8408020100008b4e286a045051ff562083c40c85c089430c
B 0f84 L893
e 8b4c2448c1e90e894c244883ed0ec7430800000000c703040000008bc1
L3b4:
e 8b53048b4b08c1ea0a83c2043bca
b 73 L439
L3c4:
e 83fd03
b 73 L401
e 8da42400000000
L3d0:
e 8b4c241085c9
B 0f84 L962
e 8bd14a895424100fb6178bcdd3e283c508c7442450000000000bc24783fd0389442448
b 72 L3d0
L401:
e 8b4b08
w 8b148d border
e 8b4b0c83e0078904918b53088b442448428953088b53048b4b08c1ea0ac1e80383c20483ed033bca89442448
b 72 L3c4
L439:
e 8b4b08b8130000003bc8
b 73 L471
b eb L450
e 8da424000000008bff
L450:
e 8b4b08
w 8b148d border
e 8b4b0cc70491000000008b5308428bca3bc8895308
b 72 L450
L471:
e 8b532456528b530c8d4b148d4310515052c70007000000
c trees_bits
e 83c41485c089442418
B 0f85 L8e3
e 8943088b442448c70305000000
L4a9:
e 8b4b048bd1c1ea0583e21f83e11f8d8c0a02010000394b08
B 0f83 L667
b eb L4d0
L4c9:
e 8b4424488d4900
L4d0:
e 8b4b103be9
b 73 L513
b eb L4e0
e 8da42400000000
L4e0:
e 8b4c241085c9
B 0f84 L941
e 8bd14a895424100fb6178bcdd3e28b4b1083c508c7442450000000000bc2473be989442448
b 72 L4e0
L513:
w 8b0c8d masks
e 8b531423c88d14ca0fb64a018b520483fa10894c241889542438
b 73 L54f
e d3e82be98b4b0c894424488b4308891481ff4308
B e9 L649
L54f:
e 83fa12
b 75 L55e
e c744242007000000
b eb L565
L55e:
e 8d4af2894c2420
L565:
e 33c983fa128b5424200f94c18d0ccd03000000894c241c8b4c241803ca3be9894c2434
b 73 L5c4
e 8d9b00000000
L590:
e 8b4c241085c9
B 0f84 L962
e 8bd14a895424100fb6178bcdd3e28b4c243483c508c7442450000000000bc2473be989442448
b 72 L590
L5c4:
e 8b4c2418d3e88b4c2420
w 8b148d masks
e 8b4c241c23d003ca894c241c8b4c2420d3e8894424488b44241803c88b43048bd0c1ea0583e21f83e01f8d8402020100008b54241c2be98b4b0803d13bd0
B 0f87 L9a1
e 837c243810
b 75 L632
e 83f901
B 0f82 L9a1
e 8b430c8b4488fc
b eb L634
L632:
e 33c0
L634:
e 8b530c89048a8b54241c414a8954241c
b 75 L634
e 894b08
L649:
e 8b43048bc8c1e90583e01f83e11f8d940102010000395308
B 0f82 L4c9
L667:
e 8b4b248b430456518d542444528d4c244c518d542430528b530c8d4c2430518bc8c1e90583e11f524183e01f51050101000050c7431400000000c744244009000000c744244406000000
c trees_dynamic
e 83c42485c089442418
B 0f85 L9f5
e 8b54243c8b4424408b4c242056528b542424505152
c codes_new1
e 83c41485c0
B 0f84 La4f
e 8943048b430c8b4e285051ff562483c408c70306000000
L701:
e 8b5424488b442410895320896b1c8b2e8b56088946048b4424508bcf2bcd03d1508956088b54241856893e53895334
c codes_step
e 83c40c83f801
B 0f85 L98e
e 8b4b045651c744245800000000
c codes_end
e 8b43208b4b348b3e8b56048b6b1c894424508b433083c4083bc8897c241c89542410894c2414
b 73 L782
e 8bd12bc248
b eb L789
L782:
e 8b432c2b442414
L789:
e 894424188b431885c0
B 0f85 La8b
e c70300000000
L79e:
e 8b1383fa098b7c241c8b74244c
B 0f86 L085
B e9 L049
L7b6:
e 8b4c2448894b20896b1c8b0e8b46088bd72bd18b4c245003c2518946088b44241856c7460400000000893e53894334
c flush2
e 83c40c5f5e5d5b83c434c3
L7f5:
e 8b442448c70309000000c1e803
w c74618 message_type
e 8943208b44241083c5fd896b1c8b168946048b46088bcf2bca8b5424146afd03c156894608893e53895334
c flush3
e 83c40c5f5e5d5b83c434c3
L844:
e c70309000000
w c74618 message_stored
e 6afd
B e9 L04b
L858:
e 8b4c24488b542410894b20896b1c8b2e8956048b56088bcf2bcd03d18956088b5424505256893e53894334
c flush4
e 83c40c5f5e5d5b83c434c3
L893:
e 6afc
B e9 L04b
L89a:
e 8b5424488b442410c70309000000
w c74618 message_counts
e 895320896b1c8b168946048b46088bcf2bca8b5424146afd03c156894608893e53895334
c flush5
e 83c40c5f5e5d5b83c434c3
L8e3:
e 837c2418fd
B 0f85 La10
e 8b4b0c8b56285152ff56248b4424508b4c2418894320c70309000000896b1c8b4608894e048b0e8bd72bd18b4c242083c40803c2518946088b44241856893e53894334
c flush6
e 83c40c5f5e5d5b83c434c3
L941:
e 8b542448895320896b1c8b168bc72bc28b542450c746040000000052
B e9 L062
L962:
e 8b442448894320896b1c8b168b46088bcf2bca8b54241403c18946088b442450c7460400000000893e895334
L98e:
e 505653
c flush7
e 83c40c5f5e5d5b83c434c3
L9a1:
e 8b4b0c8b56285152ff56248b4424508b4c2418c70309000000
w c74618 message_repeat
e 894320896b1c8b4608894e048b0e8bd72bd103c26afd8946088b44242056893e53894334
c flush8
e 83c4145f5e5d5b83c434c3
L9f5:
e 837c2418fd
b 75 La10
e 8b4b0c8b56285152ff562483c408c70309000000
La10:
e 8b4424488b4c2410894320896b1c8b4608894e048b0e8bd72bd18b4c241803c2518946088b44241856893e53894334
c flush9
e 83c40c5f5e5d5b83c434c3
La4f:
e 8b5424488b442410895320896b1c8b168946048b46088bcf2bca8b5424146afc03c156894608893e53895334
c flush10
e 83c40c5f5e5d5b83c434c3
La8b:
e c70307000000
La91:
e 8b4c24508b442414515653894334
c flush11
e 8b4b348b533083c40c3bd1894c2414
b 74 Lad7
e 8b5424488b4c2410895320896b1c8b2e894e048b4e088bd72bd503ca50
B e9 L067
Lad7:
e c70308000000
Ladd:
e 8b5424488b442410895320896b1c8b168946048b46088bcf2bca8b5424146a0103c156894608893e53895334
c flush12
e 83c40c5f5e5d5b83c434c3
Lb19:
e 8b4424488b4c2410894320896b1c8b4608894e048b0e8bd72bd103c26afd8946088b44241856893e53894334
c flush13
e 83c40c5f5e5d5b83c434c3
'''
    g = _ChildGrammar()
    for line in spec.splitlines():
        fields = line.split()
        if not fields: continue
        command,*args = fields
        if command.endswith(':'): g.mark(command[:-1])
        elif command == 'e': g.code(args[0])
        elif command in ('b','B'): g.branch(*args,wide=(command == 'B'))
        elif command == 'w': g.operand(*args)
        elif command == 'c': g.call(args[0])
        elif command == 'j': g.jump(*args)
        else: raise AssertionError('Unknown explicit block grammar command')
    return g


def _block_step(raw,image,sections,address):
    at,code = _code(raw,image,sections,address,4096)
    m = _block_grammar().match(code)
    calls = {name[:-5]:_callee(raw,image,sections,address,m,name)
             for name in m.groupdict() if name.endswith('_call')}
    if len({calls['flush' + str(n)] for n in range(14)}) != 1 or calls['codes_new0'] != calls['codes_new1']:
        raise ValueError('CG 分块解码的重复子调用不是自身同一输出或代码分配入口。')
    tables = {}
    state_labels = ('L094','L17c','L1ea','L31d','L3b4','L4a9','L701','La91','Ladd','Lb19')
    type_labels = ('L0f4','L112','L167','L7f5')
    for key,labels,displacement in (('state_table',state_labels,3),('type_table',type_labels,43)):
        table = _word(m,key); size = 4 * len(labels)
        offset = _relocated(raw,image,sections,table,executable=True,length=size)
        values = list(struct.unpack_from('<' + str(len(labels)) + 'I',raw,offset))
        if table != address + m.end() + displacement or values != [address + m.start(n) for n in labels]:
            raise ValueError('CG 分块解码表没有完整对应自身受限状态和类型分支。')
        tables[key] = dict(address=table,bytes=size,targets=values)
    if raw[at + m.end():at + m.end() + 3] != b'\x8d\x49\x00':
        raise ValueError('CG 分块解码末尾和状态表之间不是自身确认的填充。')
    references = {}
    expected_data = dict(border=(16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15),
                         masks=tuple((1 << n) - 1 for n in range(17)))
    for key,values in expected_data.items():
        target = _word(m,key); size = 4 * len(values)
        offset = _relocated(raw,image,sections,target,executable=False,length=size)
        if struct.unpack_from('<' + str(len(values)) + 'I',raw,offset) != values:
            raise ValueError('CG 分块解码顺序或位掩码表不是自身完整原生数据。')
        references[key] = dict(address=target,bytes=raw[offset:offset + size].hex())
    for name in ('type','stored','counts','repeat'):
        target = _word(m,'message_' + name)
        offset = _relocated(raw,image,sections,target,executable=False,length=1)
        references['message_' + name] = dict(address=target,bytes=raw[offset:offset + 1].hex())
    return dict(**_record(address,at,m[0]),helper_addresses=calls,data_references=references,dispatch_tables=tables,
                native_state_count=10,native_block_type_count=4,callee_argument_cleanup_bytes=0,
                own_complete_explicit_instruction_paths_static_bound=True,
                all_unsigned_dispatch_index_guards_static_bound=True,
                stored_length_complement_check_static_bound=True,
                stored_data_forward_REP_copy_and_ring_wrap_paths_static_bound=True,
                dynamic_count_limits_inclusive=[0,29],dynamic_length_allocation_item_bytes=4,
                repeat_previous_length_requires_nonzero_index=True,repeat_count_must_fit_total_lengths=True,
                all_explicit_partial_input_output_full_error_and_finish_paths_static_bound=True,
                symbol_distance_decoder_and_Huffman_child_effects_proven=False,
                actual_buffers_aliasing_heap_callback_and_termination_proven=False,native_code_executed=False)


def _codes_new(raw,image,sections,imports,address):
    g = _ChildGrammar(); e = g.code
    e('8b4424148b48286a1c6a0151ff502083c40c85c0'); g.branch('74','return')
    e('8a5424048a4c24088850108b54240c8848118b4c2410c70000000000895014894818')
    g.mark('return'); e('c3'); _,row = _bind(raw,image,sections,imports,address,g)
    return dict(**row,callee_argument_cleanup_bytes=0,native_allocation=dict(items=1,item_bytes=28),
                input_table_bit_widths_truncated_to_one_byte=True,mode_field_initialized_zero=True,
                initialized_table_fields=[16,17,20,24],other_allocated_fields_not_assumed_initialized=True,
                dynamic_allocate_effects_and_target_stability_proven=False)


def _flush(raw,image,sections,imports,address):
    g = _ChildGrammar(); e = g.code
    e('51538b5c240c558b6b34568b7424188b460c578b7b303bfd89442410897c2418')
    g.branch('76','first'); e('8b6b2c'); g.mark('first'); e('8b46102bef3be8')
    g.branch('76','first_count'); e('8be8'); g.mark('first_count'); e('85ed'); g.branch('74','first_status')
    e('837c2420fb'); g.branch('75','first_status'); e('c744242000000000'); g.mark('first_status')
    e('8b56142bc503d58946108956148b433885c0'); g.branch('74','first_copy')
    e('8b4b3c555751ffd089433c83c40c894630'); g.mark('first_copy')
    e('8b4424188bf78b7c24108bcd8bd1c1e902f3a58bca83e103f3a48b7c24108b4b2c03fd03c53bc1897c2410')
    g.branch('75','return'); e('394b348b732889742418'); g.branch('75','second'); e('897334')
    g.mark('second'); e('8b6b348b7c241c8b47102bee3be8'); g.branch('76','second_count'); e('8be8')
    g.mark('second_count'); e('85ed'); g.branch('74','second_status'); e('837c2420fb')
    g.branch('75','second_status'); e('c744242000000000'); g.mark('second_status')
    e('8b57142bc503d58947108957148b433885c0'); g.branch('74','second_copy')
    e('8b4b3c555651ffd089433c83c40c894730'); g.mark('second_copy')
    e('8b4424108bcd8bd1c1e9028bf8f3a503c5894424108b4424188bca83e10303c5f3a489442418')
    g.mark('return'); e('8b4c241c8b5424105f5e89510c8943308b4424185d5b59c3')
    _,row = _bind(raw,image,sections,imports,address,g)
    return dict(**row,callee_argument_cleanup_bytes=0,maximum_contiguous_copy_spans=2,
                complete_forward_REP_copy_and_ring_wrap_paths_static_bound=True,
                nonzero_output_changes_buffer_error_minus5_to_progress_zero=True,
                optional_checksum_callback_called_even_when_span_length_zero=True,
                checksum_callback_argument_order=['old_checksum','source','length'],
                updates_output_pointer_available_total_and_ring_read=True,
                callback_and_copy_aliasing_reentry_effects_proven=False)


def bind_native_cg_vm_restore_blocks(executable,header,vm,frames):
    raw = bytes(executable); parent = bind_native_cg_vm_restore_inflate(raw,header,vm,frames)
    legacy = parent['layout'] == 'signed-word-legacy'
    blocks = None
    if legacy:
        image,sections = _pe_sections(raw)
        paths = parent['native_restore_inflate']['paths']
        block = _block_step(raw,image,sections,parent['native_restore_inflate']['remaining_block_decoder_address'])
        calls = block['helper_addresses']
        flush = _flush(raw,image,sections,{},calls['flush0'])
        codes_new = _codes_new(raw,image,sections,{},calls['codes_new0'])
        if calls['codes_end'] != paths['codes_end']['address']:
            raise ValueError('CG 分块解码释放没有调用自身已绑定的代码清理入口。')
        own = dict(block_step=block,flush=flush,codes_new=codes_new)
        ranges = [(row['address'],row['address'] + row['code_bytes']) for row in (*own.values(),*paths.values())]
        for index,first in enumerate(ranges):
            if any(max(first[0],second[0]) < min(first[1],second[1]) for second in ranges[index + 1:]):
                raise ValueError('CG 分块、输出、分配与已有解包函数字节重叠。')
        # Both adjacent dispatch tables belong to this block controller too.
        tail_end = block['dispatch_tables']['type_table']['address'] + 16
        if any(max(block['address'] + block['code_bytes'],row['address']) < min(tail_end,row['address'] + row['code_bytes'])
               for row in (*paths.values(),flush,codes_new)):
            raise ValueError('CG 分块状态表覆盖了自己的其他解包函数。')
        remaining = {name:calls[name] for name in ('trees_fixed','trees_bits','trees_dynamic','codes_step')}
        blocks = dict(paths=own,remaining_decoder_children=remaining,own_complete_block_controller_and_output_paths_static_bound=True,
                      complete_Huffman_and_symbol_distance_decoder_effects_proven=False,
                      complete_heap_callback_SEH_aliasing_and_reentry_effects_proven=False,native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
                native_vm_restore_inflate=parent,native_restore_blocks=blocks,
                own_legacy_block_controller_and_output_paths_static_bound=legacy,
                modern_restore_has_no_legacy_compressed_convert_path=not legacy,
                complete_compression_child_effects_proven=False,actual_file_bytes_and_type_read_bounds_proven=False,
                complete_heap_and_aliasing_effects_proven=False,complete_exception_and_reentry_effects_proven=False,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
                native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
