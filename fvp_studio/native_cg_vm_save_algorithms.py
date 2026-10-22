"""Own complete legacy compressor bodies and tables; not a native save grant."""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots
from .native_cg_vm_restore_children import _ChildGrammar,_bind
from .native_cg_vm_save_trees import bind_native_cg_vm_save_trees

SCHEMA='fvp-native-cg-vm-save-algorithms/1'

_STORED = '''51538b5c240c8b430c5583c0fb3dffff00005657c7442410ffff0000|73 loop
89442410|@loop|8b436c83f801|77 consume|call fill_window|8b436c85c0|0f84 finish
@consume|8b4b6403c88b442410894b648b4b548b5364c7436c000000008d0401|74 split
3bd0|0f82 after_flush|@split|2bd085c989536c894364|7c source0
8b533003d1|eb source0_ready|@source0|33d2|@source0_ready|6a002bc1505253
call flush_block|8b4b648b03894b548b701c8b56148b481083c4103bd1|76 size0|8bd1
@size0|85d2|74 drained0
8b76108b780c8bca8be9c1e902f3a58bcd83e103f3a48b780c8b481c03fa89780c015110
8b68148b78108b481c03ea8968142bfa8978102951148b401c8b481485c9|75 drained0
8b5008895010|@drained0|8b038b481085c9|0f84 need_more|@after_flush
8b53548b4b648b43242bca2d060100003bc8|0f82 loop|85d2|7c source1
8b433003c2|eb source1_ready|@source1|33c0|@source1_ready|6a00515053
call flush_block|8b4b648b03894b548b701c8b56148b481083c4103bd1|76 size1|8bd1
@size1|85d2|74 drained1
8b76108b780c8bca8be9c1e902f3a58bcd83e103f3a48b780c8b481c03fa89780c015110
8b68148b78108b481c03ea8968142bfa8978102951148b401c8b481485c9|75 drained1
8b5008895010|@drained1|8b038b481085c9|0f85 loop|@need_more|5f5e5d33c05b59c3
@finish|8b7c241c85ff|74 need_more|8b735485f6|7c source2
8b433003c6|eb source2_ready|@source2|33c0|@source2_ready
8b536433c983ff040f94c12bd651525053|call flush_block
8b43648943548b0383c410|call flush_pending|8b0b8b411085c0|75 output_available
33c083ff040f95c05f5e5d5b4883e00259c3|@output_available
33c083ff040f94c05f5e5d5b8d44000159c3'''

_FAST = '''51538b5c240c55565733ff897c2410|@outer|8b6c241c|@loop
8b436c3d06010000|73 ready|call fill_window|8b436c3d06010000|73 filled
85ed|0f84 need_more|@filled|85c0|0f84 finish|@ready|83f803|72 searched
8b43408b4b508b53648b734cd3e08b4b300fb64c110233c18b4b3c23c6894340
0fb73c418b432c8b4b3823c266893c418b53408b433c668b4b64897c241066890c50
@searched|85ff|74 match_ready|8b53648b43242bd72d060100003bd0|77 match_ready
83bb8000000002|74 match_ready|8bc78bf3|call longest_match|894358
@match_ready|8b435883f803|0f82 literal
8b93981600008bb39c1600008ac8668b4364662b436880e903668904568b9390160000
8bb398160000880c328b9398160000420fb6c9899398160000|abs 0fb691 length
05ffff000066ff849390040000663d00018d8c9390040000|73 high_distance
0fb7c0|abs 0fb680 distance_low|eb distance_ready|@high_distance|0fb7c8c1e907
abs 0fb681 distance_high|@distance_ready
66ff8483800900008b93941600008bb3981600008b4b6c33c04a3bf28b53780f94c08bf0
8b43582bc83bc2894b6c|77 jump_match|83f903|72 jump_match|48894358|eb insert
8d9b00000000|@insert
8b53648b4b308b7b40428953640fb6440a028b4b50d3e78b4b3c33c723434c894340
0fb73c418b4b2c8b433823d166893c50668b43648b4b408b533c6689044a8b435848
897c2410894358|75 insert|e9 advance|@jump_match
8b4b648b533003c803d1894b648b4b50c7435800000000
0fb602894340d3e00fb64a0133c123434c894340|eb tally_ready|@literal
8b53648b43308a04028b8b981600008b939c16000066c7044a00008b9398160000
8b8b901600008804118b9398160000420fb6c089939816000066ff84838c000000
8b8b941600008bb3981600008d84838c0000004933d23bf18b4b6c0f94c249894b6c8bf2
@advance|ff4364|@tally_ready|85f6|0f84 loop|8b4b5485c9|7c source0
8b433003c1|eb source0_ready|@source0|33c0|@source0_ready
8b53646a002bd1525053|call flush_block
8b43648943548b038b701c8b56148b481083c4103bd1|76 size|8bd1|@size
85d2|74 drained
8b76108b780c8bca8be9c1e902f3a58bcd83e103f3a48b780c8b481c03fa89780c015110
8b68148b78108b481c2bfa8978108b7c241003ea8968142951148b401c8b481485c9|75 drained
8b4808894810|@drained|8b138b421085c0|0f85 outer|@need_more|5f5e5d33c05b59c3
@finish|8b735485f6|7c source1|8b433003c6|eb source1_ready|@source1|33c0
@source1_ready|8b536433c983fd040f94c12bd651525053|call flush_block
8b43648943548b0383c410|call flush_pending|8b0b8b411085c0|75 output_available
33c083fd040f95c05f5e5d5b4883e00259c3|@output_available
33c083fd040f94c05f5e5d5b8d44000159c3'''

_SLOW = '''5355568b7424105733ed8d9b00000000|@loop|8b466c3d06010000|73 ready
8bde|call fill_window|8b466c3d060100008b7c2418|73 filled|85ff|0f84 need_more
@filled|85c0|0f84 finish|@ready|83f803|72 searched
8b46408b4e508b56648b7e4cd3e08b4e300fb64c110233c18b4e3c23c7894640
0fb72c418b462c8b4e3823c266892c418b56408b463c668b4e6466890c50
@searched|85ed8b56588b4668bf0200000089567089465c897e58|74 match_ready
8b46788bca3bc8|73 match_ready|8b56648b46242bd52d060100003bd0|77 match_ready
39be80000000|74 searched_match|8bc5|call longest_match|894658|@searched_match
8b465883f805|77 match_ready|83be8000000001|74 discard_short|83f803|75 match_ready
8b4e642b4e6881f900100000|76 match_ready|@discard_short|897e58|@match_ready
8b467083f803|0f82 literal_or_wait|394658|0f87 literal_or_wait
8b56648b466c8a4e708b9e9c1600008d7c02fd33c0668bc2662b465c8b9698160000
80e90348668904538b96901600008b9e98160000880c1a8b9698160000420fb6c9899698160000
abs 0fb691 length|05ffff000066ff849690040000663d00018d8c9690040000|73 high_distance
0fb7c0|abs 0fb680 distance_low|eb distance_ready|@high_distance|0fb7c8c1e907
abs 0fb681 distance_high|@distance_ready
66ff8486800900008b96941600008b86981600004a33db3bc28b46708b566c0f94c3
b9010000002bc803d183c0fe89566c8946708da42400000000|@insert
8b4e64418bd13bd7894e64|77 inserted|8b46408b4e508b6e4cd3e08b4e30
0fb64c110233c18b4e3c23c58946400fb72c418b462c8b4e3823c266892c41
8b56408b463c668b4e6466890c50|@inserted|ff4e70|75 insert
8b4e644185dbc7466000000000c7465802000000894e64|0f84 loop
8b565485d2|7c source0|8b463003c2|eb source0_ready|@source0|33c0|@source0_ready
6a002bca515056|call flush_block|8b56648b0683c410895654|call flush_pending
8b068b481085c9|@output_check|0f85 loop|@need_more|5f5e5d33c05bc3|@literal_or_wait
8b466085c0|0f84 wait
8b4e648b56308a4411ff8b8e981600008b969c16000066c7044a00008b8e90160000
8b96981600008804118b9e981600000fb6c0438d84868c000000899e9816000066ff00
8b8e941600008b8698160000493bc1|75 literal_advance
8b4e5485c9|7c source1|8b463003c1|eb source1_ready|@source1|33c0|@source1_ready
8b56646a002bd1525056|call flush_block
8b46648946548b0683c410|call flush_pending|@literal_advance
8b56648b4e6c4249894e6c8b0e8956648b411085c0|e9 output_check|@wait
8b4e648b466c4148c7466001000000894e6489466c|e9 loop|@finish
8b466085c0|74 final_block
8b56648b46308a4402ff8b8e981600008b969c16000066c7044a00008b9698160000
8b8e901600008804118b96981600000fb6c0428d84868c00000089969816000066ff00c7466000000000
@final_block|8b4e5485c9|7c source2|8b463003c1|eb source2_ready|@source2|33c0
@source2_ready|33d283ff040f94c2528b56642bd1525056|call flush_block
8b46648946548b0683c410|call flush_pending|8b0e8b411085c0|75 output_available
33c083ff040f95c05f5e5d5b4883e002c3|@output_available
33c083ff040f94c05f5e5d5b8d440001c3'''


def _algorithm(raw,image,sections,imports,address,tape,mode):
    g=_ChildGrammar(); counts={}
    branch_ops={'73','77','74','75','76','72','7c','eb','e9','0f82','0f84','0f85','0f87'}
    for token in tape.replace('\n','|').split('|'):
        words=token.split()
        if not words: continue
        kind,*args=words
        if kind.startswith('@'): g.mark(kind[1:])
        elif kind in branch_ops: g.branch(kind,args[0],wide=kind.startswith('0f') or kind=='e9')
        elif kind=='call':
            role=args[0]; index=counts.get(role,0); counts[role]=index+1; g.call(role+str(index))
        elif kind=='abs': g.operand(args[0],args[1])
        else: g.code(kind)
    data=() if mode==0 else tuple((k,256) for k in ('length','distance_low','distance_high'))
    _,row=_bind(raw,image,sections,imports,address,g,data=data)
    return dict(**row,native_mode=mode,entry_SP_arguments=dict(state=4,flush=8),
        native_block_state_returns=[0,1,2,3],complete_loop_branches_and_all_late_returns_static_bound=True,
        native_null_source_when_signed_block_start_negative=True,
        inline_or_own_pending_flush_uses_unsigned_min=True,DF_zero_required=True,
        longest_match_strategy2_is_skipped=mode!=0,lazy_previous_match_comparison=mode==2,
        dynamic_heap_bounds_callback_reentry_and_loop_termination_proven=False)


def _stored(raw,image,sections,imports,address):
    row=_algorithm(raw,image,sections,imports,address,_STORED,0)
    return dict(**row,block_limit_is_unsigned_min_pending_size_minus5_and65535=True,
        pending_size_minus5_wraps_32_bits=True)


def _fast(raw,image,sections,imports,address):
    return _algorithm(raw,image,sections,imports,address,_FAST,1)


def _slow(raw,image,sections,imports,address):
    return _algorithm(raw,image,sections,imports,address,_SLOW,2)


def _symbol_tables(raw,image,sections,paths,trees):
    if paths['algorithm_1']['data_references']!=paths['algorithm_2']['data_references']:
        raise ValueError('CG 保存压缩的两种匹配算法没有使用自己的相同编码表。')
    expected_extra=dict(literal=[0]*8+[1]*4+[2]*4+[3]*4+[4]*4+[5]*4+[0],
        distance=[0]*4+[n for n in range(1,14) for _ in range(2)],bit_length=[0]*16+[2,3,7])
    extras={}
    for role,expected in expected_extra.items():
        address=trees['descriptors'][role]['words'][1]; count=len(expected)
        at=_relocated(raw,image,sections,address,executable=False,length=count*4)
        body=raw[at:at+count*4]; values=list(struct.unpack('<'+'I'*count,body))
        if values!=expected:
            raise ValueError('CG 保存压缩的extra-bit表没有对应自身的原生树描述。')
        extras[role]=dict(address=address,bytes=body.hex(),values=values)
    length=[code for code,extra in enumerate(extras['literal']['values'][:28]) for _ in range(1<<extra)]
    length[-1]=28
    low=[code for code,extra in enumerate(extras['distance']['values'][:16]) for _ in range(1<<extra)]
    high=[0,0]+[code for code in range(16,30) for _ in range(1<<(extras['distance']['values'][code]-7))]
    refs=paths['algorithm_1']['data_references']
    expected=dict(length=length,distance_low=low,distance_high=high)
    if any(len(values)!=256 or refs[role]['bytes']!=bytes(values).hex() for role,values in expected.items()):
        raise ValueError('CG 保存压缩的完整length/distance编码表与自己的extra-bit域不一致。')
    if len({row['address'] for row in refs.values()})!=3:
        raise ValueError('CG 保存压缩的编码表不能互相冒用。')
    return dict(extra_bits=extras,code_tables=refs,own_complete_extra_bits_and_code_tables_static_bound=True,
        actual_runtime_symbol_indices_state_and_static_tree_contents_proven=False)


def bind_native_cg_vm_save_algorithms(executable,header,vm,frames):
    raw=bytes(executable); parent=bind_native_cg_vm_save_trees(raw,header,vm,frames)
    image,sections=_pe_sections(raw); imports=_import_slots(raw,image); older=parent['layout']=='signed-word-legacy'
    algorithms=None
    if older:
        trees=parent['native_save_trees']; entries=trees['remaining_algorithm_addresses']
        paths=dict(algorithm_0=_stored(raw,image,sections,imports,entries['algorithm_0']),
            algorithm_1=_fast(raw,image,sections,imports,entries['algorithm_1']),
            algorithm_2=_slow(raw,image,sections,imports,entries['algorithm_2']))
        helpers={}
        for role in ('fill_window','longest_match','flush_block','flush_pending'):
            addresses={address for path in paths.values() for key,address in path['helper_addresses'].items() if key.startswith(role)}
            if len(addresses)!=1:
                raise ValueError('CG 保存压缩算法没有保持自己的一致子调用身份。')
            helpers[role]=addresses.pop()
        control=parent['native_vm_save_deflate']['native_save_deflate']
        if helpers['flush_pending']!=control['paths']['flush_pending']['address']:
            raise ValueError('CG 保存压缩算法没有使用自身已接入的pending缓冲刷新入口。')
        tables=_symbol_tables(raw,image,sections,paths,trees)
        rows=list(paths.values())+list(trees['paths'].values())+list(control['paths'].values())
        for i,first in enumerate(rows):
            for second in rows[i+1:]:
                if max(first['address'],second['address'])<min(first['address']+first['code_bytes'],second['address']+second['code_bytes']):
                    raise ValueError('CG 保存压缩算法的完整函数范围与自身已有函数重叠。')
        algorithms=dict(paths=paths,symbol_tables=tables,
            own_three_complete_explicit_compressor_bodies_static_bound=True,
            own_repeated_child_identities_and_known_pending_flush_static_bound=True,
            remaining_child_addresses={k:v for k,v in helpers.items() if k!='flush_pending'},
            complete_compression_child_effects_and_termination_proven=False,
            actual_native_compressed_bytes_file_and_round_trip_proven=False,native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
        native_vm_save_trees=parent,native_save_algorithms=algorithms,
        own_legacy_save_compressor_algorithm_bodies_static_bound=older,
        same_live_instance_lifetime_proven=False,complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False,initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False,complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
