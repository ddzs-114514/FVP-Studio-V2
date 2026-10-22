"""Own full exit state packing and local SEH records, not live round-trip proof.

The exit and pending-preserve entry is not a table clear. Its own state fields,
buffer helpers, startup restore layout, exception thunk and one unwind record
must agree. File, dynamic owner, serializer and C++ exception-child effects
remain separate requirements; public CG output stays closed.
"""
import hashlib
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots
from .native_cg_vm_cleanup import _code
from .native_cg_vm_heap_paths import _word, _callee, _import
from .native_cg_vm_heap_allocations import _AllocationGrammar
from .native_cg_vm_heap_children import _data
from .native_cg_vm_startup import _record
from .native_cg_vm_restore import _legacy_grammar, _modern_grammar
from .native_cg_vm_controller import bind_native_cg_vm_controller, _tick_grammar
from .native_cg_vm_lifecycle import _parent, _extent

SCHEMA = 'fvp-native-cg-vm-state-pack/1'


def _pack_grammar(older):
    g = _AllocationGrammar(); resize_index = 0
    def o(op, name):
        g.code(op); g.word(name)
    def c(name):
        o('e8', name + '_call')
    def resize():
        nonlocal resize_index
        c('resize' + str(resize_index)); resize_index += 1
    g.code('6aff'); o('68', 'seh'); g.code('64a10000000050')
    if older:
        g.code('6489250000000081ec0c01000053555633c0578bf18944241089442414')
        o('8bbe', 'saved_word'); g.code('898424240100008946088b460483f804'); g.branch('7d', 'word_ready')
        g.code('8b4e0c8d44010399f7f90fafc1508bce'); resize(); g.mark('word_ready')
        g.code('8b4e088b06893c088b4608'); o('8b96', 'nonvolatile'); g.code('83c004894608')
        o('8b86', 'buffer'); g.code('8d0cd0'); o('8b96', 'volatile'); g.code('51c1e203528bce'); c('append0')
        o('a1', 'owner'); o('8a88', 'config_flag'); g.code('8b460484c98b4e08'); g.branch('74', 'flag_zero')
        for value, label in ((1, 'flag_one_ready'), (0, 'flag_zero_ready')):
            if value == 0:
                g.mark('flag_zero')
            g.code('413bc8'); g.branch('7e', label); g.code('8b4e0c03c199f7f90fafc1508bce'); resize()
            g.mark(label); g.code('8b068b5608c60410' + bytes((value,)).hex())
            if value:
                g.branch('eb', 'flag_done')
        g.mark('flag_done'); g.code('ff4608'); o('8d86', 'large_data'); g.code('5068000008008bce'); c('append1')
        o('8d8e', 'small_data'); g.code('5168000100008bce'); c('append2')
        o('8b3d', 'owner'); o('81c7', 'settings'); g.code('bd200000008d4900'); g.mark('settings_loop')
        g.code('8b56088b46040fb65f03423bd0'); g.branch('7e', 'setting0'); g.code('8b4e0c03c199f7f90fafc1508bce'); resize()
        g.mark('setting0'); g.code('8b4e088b06881c088b5e088b4604438bcb413bc8895e080fb65f02')
        g.branch('7e', 'setting1'); g.code('8b4e0c03c199f7f90fafc1508bce'); resize()
        g.mark('setting1'); g.code('8b068b5608881c108b5e088b4604438bcb413bc8895e080fb65f01')
        g.branch('7e', 'setting2'); g.code('8b4e0c03c199f7f90fafc1508bce'); resize()
        g.mark('setting2'); g.code('8b4e088b06881c088b5e088b4604438bcb413bc8895e080fb61f')
        g.branch('7e', 'setting3'); g.code('8b4e0c03c199f7f90fafc1508bce'); resize()
        g.mark('setting3'); g.code('8b068b5608881c108b5e084383c7044d895e088bc3')
        g.branch('0f85', 'settings_loop', True); g.code('508bce'); resize()
        o('a1', 'owner'); o('8b80', 'filename'); g.code('508d4c241c51'); o('ff15', 'copy_api')
        o('68', 'suffix'); g.code('8d54241c52'); o('ff15', 'append_api')
        g.code('568d4c2414'); c('convert'); g.code('6a006a008d442420508d4c241c'); c('write')
        g.code('6a008d4c2414c7842428010000ffffffff'); resize()
        g.code('8b8c241c0100005f5e5d5b64890d0000000081c418010000c3')
        return g
    g.code('81ec18010000'); o('a1', 'cookie'); g.code('33c48984241401000053555657'); o('a1', 'cookie')
    g.code('33c4508d84242c01000064a30000000033db8be9895c2414895c2418895c241cc744242000000100')
    o('8bb5', 'volatile'); o('8b85', 'nonvolatile'); o('8b8d', 'buffer')
    g.code('03f603f603f63bf3899c24340100008d3cc1'); g.branch('7e', 'globals_ready')
    g.code('8d86ffff00009981e2ffff000003c2c1f810c1e010508d4c2418'); resize(); g.mark('globals_ready')
    g.code('8b5424148b44241c5603d05752'); c('copy0')
    g.code('8b442428'); o('8b0d', 'owner'); g.code('03c689442428'); o('8b91', 'service')
    g.code('83c40c399afc0100008b5424188d4801'); g.branch('74', 'service_flag_zero')
    g.code('3bca'); g.branch('7e', 'service_one_ready')
    g.code('8b4c24208d041199f7f90fafc1508d4c2418'); resize(); g.code('8b44241c')
    g.mark('service_one_ready'); g.code('8b542414bf01000000c6040201017c241c'); g.branch('eb', 'service_flag_done')
    g.mark('service_flag_zero'); g.code('3bca'); g.branch('7e', 'service_zero_ready')
    g.code('8b4c24208d041199f7f90fafc1508d4c2418'); resize(); g.code('8b44241c')
    g.mark('service_zero_ready'); g.code('8b542414c6040200ff44241cbf01000000'); g.mark('service_flag_done')
    o('a1', 'owner'); g.code('8b4c241c41'); o('80b8', 'flag0'); g.code('008b442418'); g.branch('74', 'flag0_zero')
    g.code('3bc8'); g.branch('7e', 'flag0_one_ready'); g.code('8b4c242003c199f7f90fafc1508d4c2418'); resize()
    g.mark('flag0_one_ready'); g.code('8b5424148b44241cc6040201'); g.branch('eb', 'flag0_done')
    g.mark('flag0_zero'); g.code('3bc8'); g.branch('7e', 'flag0_zero_ready')
    g.code('8b4c242003c199f7f90fafc1508d4c2418'); resize()
    g.mark('flag0_zero_ready'); g.code('8b5424148b44241cc6040200'); g.mark('flag0_done'); g.code('017c241c')
    g.code('8b54241c8b442418'); o('8b0d', 'owner'); g.code('8b714883c2043bd0'); g.branch('7e', 'view0_ready')
    g.code('8b4c24208d44010399f7f90fafc1508d4c2418'); resize(); g.mark('view0_ready')
    g.code('8b4c241c8b4424148934088b44241c'); o('8b15', 'owner'); g.code('83c0048944241c8b724c8d48048b4424183bc8')
    g.branch('7e', 'view1_ready'); g.code('8b4c24208d44010399f7f90fafc1508d4c2418'); resize(); g.mark('view1_ready')
    g.code('8b44241c8b5424148934028b44241c'); o('8b0d', 'owner'); g.code('83c0048944241c')
    o('8b99', 'mode'); g.code('8d50018b4424183bd0'); g.branch('7e', 'mode_ready')
    g.code('8b4c242003c199f7f90fafc1508d4c2418'); resize(); g.mark('mode_ready')
    g.code('8b4c241c8b442414881c088b44241c'); o('8b15', 'owner'); g.code('03c78944241c')
    o('80ba', 'flag1'); g.code('008b5424188d4801'); g.branch('74', 'flag1_zero')
    g.code('3bca'); g.branch('7e', 'flag1_one_ready'); g.code('8b4c24208d041199f7f90fafc1508d4c2418'); resize(); g.code('8b44241c')
    g.mark('flag1_one_ready'); g.code('8b542414c6040201'); g.branch('eb', 'flag1_done')
    g.mark('flag1_zero'); g.code('3bca'); g.branch('7e', 'flag1_zero_ready')
    g.code('8b4c24208d041199f7f90fafc1508d4c2418'); resize(); g.code('8b44241c')
    g.mark('flag1_zero_ready'); g.code('8b542414c6040200'); g.mark('flag1_done'); g.code('017c241c')
    g.code('8b44241c'); o('8bb5', 'saved_word'); g.code('8d48048b4424183bc8'); g.branch('7e', 'word0_ready')
    g.code('8b4c24208d44010399f7f90fafc1508d4c2418'); resize(); g.mark('word0_ready')
    g.code('8b44241c8b5424148934028b44241c'); o('8bb5', 'saved_word1')
    g.code('83c0048d48048944241c8b4424183bc8'); g.branch('7e', 'word1_ready')
    g.code('8b4c24208d44010399f7f90fafc1508d4c2418'); resize(); g.mark('word1_ready')
    g.code('8b44241c8b5424148934028b44241c83c0048d88000010008944241c8b4424183bc8')
    g.branch('7e', 'large_ready'); g.code('8b4c24208d8401ffff0f0099f7f90fafc1508d4c2418'); resize(); g.mark('large_ready')
    g.code('8b4424148b4c241c6800001000'); o('8d95', 'large_data'); g.code('5203c150'); c('copy1')
    g.code('8b44242805000010008d9000010000894424288b44242483c40c3bd0'); g.branch('7e', 'small_ready')
    g.code('8b4c24208d8401ff00000099f7f90fafc1508d4c2418'); resize(); g.mark('small_ready')
    g.code('8b4c24148b54241c6800010000'); o('8d85', 'small_data'); g.code('5003ca51'); c('copy2')
    g.code('8b442428'); o('8bb5', 'reader_size'); g.code('05000100008d4804894424288b44242483c40c3bc8')
    g.branch('7e', 'reader_ready'); g.code('8b4c24208d44010399f7f90fafc1508d4c2418'); resize(); g.mark('reader_ready')
    g.code('8b44241c8b5424148d4c2414518934028344242004'); o('8d8d', 'reader_field'); c('serialize')
    g.code('8b54241c528d4c2418'); resize(); o('a1', 'owner'); o('8b88', 'filename')
    g.code('8d542424'); g.mark('filename_copy'); g.code('8a01880203cf03d784c0'); g.branch('75', 'filename_copy')
    g.code('8d44242448'); g.mark('suffix_seek'); g.code('8a48014084c9'); g.branch('75', 'suffix_seek')
    o('8b0d', 'suffix'); o('8b15', 'suffix_word1'); g.code('8908'); o('8b0d', 'suffix_word2'); g.code('895004')
    o('668b15', 'suffix_word3'); g.code('894808'); o('8a0d', 'suffix_tail')
    g.code('6689500c8d54242488480e528d4c2418'); c('write')
    g.code('6a008d4c2418c7842438010000ffffffff'); resize()
    g.code('8b8c242c01000064890d00000000595f5e5d5b8b8c241401000033cc'); c('cookie')
    g.code('81c424010000c3')
    return g


def _local_seh(raw, image, sections, address, older, cookie):
    at, code = _code(raw, image, sections, address, 128); g = _AllocationGrammar()
    if not older:
        g.code('8b5424088d82d8feffff8b8ad4feffff33c8e8'); g.word('cookie0_call')
        g.code('83c0108b4afc33c8e8'); g.word('cookie1_call')
    g.code('b8'); g.word('info'); g.code('e9'); g.word('common_call'); m = g.match(code)
    if not older and any(_callee(raw,image,sections,address,m,k+'_call') != cookie for k in ('cookie0','cookie1')):
        raise ValueError('CG 状态打包的异常入口没有使用自身同一 cookie 检查。')
    info = _word(m, 'info'); length = 28 if older else 36
    info_at = _relocated(raw,image,sections,info,executable=False,length=length)
    words = list(struct.unpack_from('<' + 'I'*(length//4),raw,info_at))
    if (words[0] != (0x19930520 if older else 0x19930522) or words[1] != 1 or any(words[3:7])
            or (not older and words[7:] != [0,1])):
        raise ValueError('CG 状态打包没有使用自身单对象无 catch 的异常信息。')
    map_at = _relocated(raw,image,sections,words[2],executable=False,length=8)
    state, unwind = struct.unpack_from('<2I',raw,map_at)
    if state != 0xffffffff or not unwind:
        raise ValueError('CG 状态打包的唯一异常清理状态不一致。')
    u_at, u_code = _code(raw,image,sections,unwind,64); ug = _AllocationGrammar()
    ug.code('8d8de8feffff' if older else '8d8ddcfeffff'); ug.code('e9'); ug.word('dispose_call'); u = ug.match(u_code)
    return dict(**_record(address,at,m[0]), func_info=_data(raw,image,sections,info,length), func_info_words=words,
        unwind_map=_data(raw,image,sections,words[2],8), unwind_to_state=-1,
        local_unwind_thunk=dict(**_record(unwind,u_at,u[0]), destructor_address=_callee(raw,image,sections,unwind,u,'dispose_call')),
        common_exception_handler_address=_callee(raw,image,sections,address,m,'common_call'),
        own_local_cookie_thunk_and_unwind_record_static_bound=True,
        common_CxxFrameHandler_and_destructor_effects_bound=False, native_code_executed=False)


def bind_native_cg_vm_state_pack(executable, header, vm, frames):
    raw = bytes(executable); parent = bind_native_cg_vm_controller(raw,header,vm,frames)
    older = parent['layout'] == 'signed-word-legacy'; image, sections = _pe_sections(raw)
    lifecycle = parent['native_vm_lifecycle']; application = _parent(parent,'fvp-native-cg-vm-application/1')
    thread = _parent(parent,'fvp-native-cg-vm-thread-startup/1')
    restore = _parent(parent,'fvp-native-cg-vm-restore/1')['native_post_main_restore']
    children = _parent(parent,'fvp-native-cg-vm-restore-children/1')['native_restore_children']
    capacity = thread['native_scheduler_capacity']
    table = application['native_vm_instance']['native_vm_startup']['native_controller_constructor']['table_constructor_fields'][0]
    member = _extent(application,capacity,table)
    address = lifecycle['native_application_run']['helper_addresses']['termination']
    at, code = _code(raw,image,sections,address,2048); m = _pack_grammar(older).match(code)
    r = (_legacy_grammar() if older else _modern_grammar()).match(raw[restore['offset']:restore['offset']+restore['code_bytes']])
    expected = dict(restore['parent_fields'], owner=application['native_application']['owner_global'],
                    filename=_word(r,'filename'))
    if older:
        expected.update(config_flag=_word(r,'flag'), settings=_word(r,'settings'))
    else:
        tick = parent['native_controller_tick']
        t = _tick_grammar(False).match(raw[tick['offset']:tick['offset']+tick['code_bytes']])
        expected.update(reader_size=_word(r,'reader_size'),reader_field=_word(r,'reader_field'), flag0=0x80,
                        flag1=_word(r,'flag'),mode=0x88,service=_word(t,'service'))
    if any(_word(m,k) != v for k,v in expected.items()):
        raise ValueError('CG 状态打包与同来源恢复布局的字段、owner 或文件名不一致。')
    helpers = {k[:-5]:_callee(raw,image,sections,address,m,k) for k in m.groupdict() if k.endswith('_call')}
    if any(v != children['resize']['address'] for k,v in helpers.items() if k.startswith('resize')):
        raise ValueError('CG 状态打包没有使用自身已完整绑定的缓冲区分配入口。')
    if older:
        if len({helpers[k] for k in ('append0','append1','append2')}) != 1 or helpers['convert'] != children['convert']['address']:
            raise ValueError('CG 状态打包的追加或转换入口不属于自己同一链路。')
        imports = _import_slots(raw,image)
        _import(raw,image,sections,imports,m,'copy_api','lstrcpyA','kernel32.dll')
        _import(raw,image,sections,imports,m,'append_api','lstrcatA','kernel32.dll')
        if _word(m,'suffix') != _word(r,'suffix'):
            raise ValueError('CG 状态保存和恢复没有使用自身同一原生后缀。')
        member(_word(m,'config_flag'),1); member(_word(m,'settings'),128)
        cookie = None
    else:
        copy = _parent(parent,'fvp-native-cg-vm-member-copy/1')['native_member_copy_paths']['string']['address']
        if any(helpers[k] != copy for k in ('copy0','copy1','copy2')):
            raise ValueError('CG 状态打包没有使用自身已完整绑定的内存复制。')
        cookie = children['cookie']['address']
        if helpers['cookie'] != cookie or _word(m,'cookie') != _word(r,'cookie'):
            raise ValueError('CG 状态打包和恢复没有引用自身相同 cookie。')
        if any(_word(m,k) != _word(r,rk) for k,rk in (('suffix','suffix1'),('suffix_word1','suffix1_word1'),
            ('suffix_word2','suffix1_word2'),('suffix_word3','suffix1_word3'),('suffix_tail','suffix1_tail'))):
            raise ValueError('CG 状态打包的路径后缀与自己的恢复字节区不一致。')
        member(_word(m,'reader_field'),16,True)
        for k in ('flag0','flag1'):
            member(_word(m,k),1)
        member(_word(m,'service'),4); member(_word(m,'mode'),4); member(0x48,8)
    for k in ('nonvolatile','volatile','buffer','saved_word') + (() if older else ('saved_word1',)):
        member(_word(m,k),4,True)
    member(_word(m,'large_data'),0x80000 if older else 0x100000,True)
    member(_word(m,'small_data'),256,True); member(_word(m,'filename'),4)
    seh = _local_seh(raw,image,sections,_word(m,'seh'),older,cookie)
    unresolved = {k:v for k,v in helpers.items() if not k.startswith('resize') and k not in ('copy0','copy1','copy2','cookie','convert')}
    unresolved.update(CxxFrameHandler=seh['common_exception_handler_address'],
                      unwind_destructor=seh['local_unwind_thunk']['destructor_address'])
    pack = dict(**_record(address,at,m[0]), helper_addresses=helpers, own_local_SEH=seh,
        fields={k:_word(m,k) for k in expected}, own_startup_restore_address=restore['address'],
        own_complete_explicit_exit_state_pack_paths_static_bound=True,
        own_run_exit_calls_this_state_pack_static_bound=True,
        modern_pending_preserve_uses_same_exit_entry_static_bound=not older and address==parent['native_controller_tick']['helper_addresses']['preserve'],
        fixed_state_and_layout_correspond_to_own_restore_static_bound=True,
        packs_volatile_slice_after_nonvolatile_offset=True, large_data_bytes=0x80000 if older else 0x100000,
        small_data_bytes=256, legacy_settings_bytes=128 if older else None,
        modern_reader_and_extra_parent_flags_serialized=not older,
        older_uses_controller_prefix_as_buffer=older, native_table_clear_not_established_by_exit=True,
        filename_copy_and_pack_growth_are_unbounded=True, signed_count_rounding_and_32bit_wrap_not_memory_safety=True,
        remaining_child_addresses=unresolved, actual_live_owner_state_file_and_round_trip_proven=False,
        complete_exception_callback_and_reentry_effects_proven=False, native_code_executed=False)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=parent['layout'],
        native_vm_controller=parent,native_exit_state_pack=pack,
        own_exit_state_pack_and_restore_layout_static_bound=True,
        same_live_instance_lifetime_proven=False, complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False, initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False, complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False,public_cg_export_enabled=False)
