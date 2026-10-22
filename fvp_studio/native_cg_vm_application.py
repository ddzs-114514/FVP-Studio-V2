"""Own application allocation/first-start/cleanup paths, not full lifetime proof.

The non-null, normal-ABI path passes the constructor's returned this directly
to startup. Calls after publication can still mutate/reenter the shared owner.
Embedded exception-continuation bytes do not prove the SEH dispatch mechanism.
Allocator explicit RET paths are guarded non-null; throwing/heap/ABI effects
are not inferred from helper names. This module enables no public output.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_startup import _record, _relative
from .native_cg_vm_instance import bind_native_cg_vm_instance, _w, _branch, _mapped, _api
from .native_rotation_degrees import _imports
from .runtime_text_companion import _PEImage

SCHEMA="fvp-native-cg-vm-application/1"
_UNKNOWN=object()


def _writable_image_range(raw,image,sections,address,size):
    """Validate PE virtual storage without pretending BSS has file bytes."""
    pe=struct.unpack_from('<I',raw,0x3c)[0]
    image_size=struct.unpack_from('<I',raw,pe+24+56)[0]
    rva=address-image
    if type(size) is not int or not 0<size<=0x10000 or rva<0 or rva+size>image_size or image+image_size>2**32:
        raise ValueError("CG 程序静态状态范围越过自己的 PE 图像。")
    rows=[s for s in sections if max(rva,s[1])<min(rva+size,s[1]+max(s[0],s[2]))]
    if len(rows)!=1:raise ValueError("CG 程序虚拟状态没有唯一的本来源分节。")
    row=rows[0]
    if row[4]&0x20000000 or not row[4]&0x80000000 or not row[1]<=rva or rva+size>row[1]+max(row[0],row[2]):
        raise ValueError("CG 程序静态状态不在完整可写数据区。")
    backed=min(size,max(0,row[2]-(rva-row[1])))
    return dict(address=address,bytes=size,file_backed_bytes=backed,zero_fill_extent_bytes=size-backed,
        current_PE_virtual_data_range_bound=True,contents_at_this_call_proven=False)


def _import_slots(raw,image):
    """Record ordinal identities, never manufacture cross-version API names."""
    pe=_PEImage.parse(raw)
    if pe.thunk_size!=4:raise ValueError("CG 程序入口只接受本来源的 x86 导入。")
    rva,length=pe.directory(1);slots={}
    for index in range(min(length//20,4096)):
        original,time,forward,name,first=struct.unpack('<IIIII',pe.read_rva(rva+20*index,20))
        if not any((original,time,forward,name,first)):return slots
        dll=pe.c_string_rva(name,label='CG 程序 DLL').decode('ascii').casefold()
        for n in range(65536):
            value=struct.unpack('<I',pe.read_rva((original or first)+4*n,4))[0]
            if not value:break
            address=image+first+4*n
            if address in slots:raise ValueError("CG 程序导入的 IAT 有重叠。")
            if value&0x80000000:
                if value&0x7fff0000:raise ValueError("CG 程序导入序号有非零保留位。")
                slots[address]=dict(dll=dll,ordinal=value&0xffff,name=None)
            else:slots[address]=dict(dll=dll,ordinal=None,name=pe.c_string_rva(value+2,label='CG 程序 API').decode('ascii'))
        else:raise ValueError("CG 程序导入槽没有结束标记。")
    raise ValueError("CG 程序导入描述符没有结束标记。")


def _application_pattern(older):
    w=_w
    p=engine_pattern('native_cg_vm_application:65:6')+w('seh')+engine_pattern('native_cg_vm_application:65:44')
    if older:
        p+=engine_pattern('native_cg_vm_application:67:11')+w('command_text')
        p+=engine_pattern('native_cg_vm_application:68:11')
    else:
        p+=engine_pattern('native_cg_vm_application:70:11')+w('cookie')+engine_pattern('native_cg_vm_application:70:56')+w('command_text')+rb"\x50"
    p+=engine_pattern('native_cg_vm_application:71:7')+w('compare_api')+engine_pattern('native_cg_vm_application:71:37')+(rb"\x53" if older else rb"\x50")
    p+=rb"\x68"+w('window_text')+engine_pattern('native_cg_vm_application:72:33')+w('find_api')+(engine_pattern('native_cg_vm_application:72:61') if older else engine_pattern('native_cg_vm_application:72:88'))+engine_pattern('native_cg_vm_application:72:102')+w('no_window_branch')
    p+=(engine_pattern('native_cg_vm_application:73:8') if older else engine_pattern('native_cg_vm_application:73:35'))+engine_pattern('native_cg_vm_application:73:53')+w('post_api')+rb"\xe9"+w('posted_branch')
    p+=engine_pattern('native_cg_vm_application:74:7')+w('early_api')
    if older:
        p+=engine_pattern('native_cg_vm_application:76:11')+w('com_api')+engine_pattern('native_cg_vm_application:76:41')+w('prepare_call')
    else:p+=engine_pattern('native_cg_vm_application:77:12')+w('com_api')
    p+=rb"\x68"+w('allocation_bytes')+engine_pattern('native_cg_vm_application:78:38')+w('allocate_call')+engine_pattern('native_cg_vm_application:78:78')
    p+=(engine_pattern('native_cg_vm_application:79:8') if older else engine_pattern('native_cg_vm_application:79:63'))
    p+=engine_pattern('native_cg_vm_application:80:7')+w('constructor_call')+engine_pattern('native_cg_vm_application:80:59')
    p+=(engine_pattern('native_cg_vm_application:81:8') if older else engine_pattern('native_cg_vm_application:81:43'))+engine_pattern('native_cg_vm_application:81:65')+w('owner_global')+rb"\xe8"+w('startup_call')
    p+=engine_pattern('native_cg_vm_application:82:7')+w('run_call')
    if older:
        p+=engine_pattern('native_cg_vm_application:84:11')+w('error_text_field')+engine_pattern('native_cg_vm_application:84:112')
        p+=engine_pattern('native_cg_vm_application:85:11')+w('message_api')+engine_pattern('native_cg_vm_application:85:71')+w('error_free_call')+engine_pattern('native_cg_vm_application:85:105')+w('exception_resume')+engine_pattern('native_cg_vm_application:85:148')
        p+=engine_pattern('native_cg_vm_application:86:11')+w('destructor_call')
        p+=engine_pattern('native_cg_vm_application:87:11')+w('free_call')+engine_pattern('native_cg_vm_application:87:39')+w('finish_call')+engine_pattern('native_cg_vm_application:87:107')+w('uncom_api')
        p+=engine_pattern('native_cg_vm_application:88:11')
    else:
        p+=engine_pattern('native_cg_vm_application:90:11')+w('destructor_call')
        p+=engine_pattern('native_cg_vm_application:91:11')+w('free_call')+engine_pattern('native_cg_vm_application:91:39')+w('uncom_api')
        p+=engine_pattern('native_cg_vm_application:92:11')
        p+=engine_pattern('native_cg_vm_application:93:11')+w('error_text_field')+engine_pattern('native_cg_vm_application:93:87')+w('message_api')
        p+=engine_pattern('native_cg_vm_application:94:11')+w('error_free_call')+engine_pattern('native_cg_vm_application:94:45')+w('exception_resume')+rb"\xc3"
    return p


def _application(raw,image,sections,at,address,older,instance):
    section=next(s for s in sections if s[3]<=at<s[3]+s[2])
    m=re.match(_application_pattern(older),raw[at:min(at+2048,section[3]+section[2])],re.DOTALL)
    if m is None:raise ValueError("CG 程序入口没有完整覆盖创建、启动、退出和异常接续字节。")
    for key,label in (('ordinary_branch','ordinary'),('no_window_branch','return'),('posted_branch','return'),
        ('nil_branch','nil'),('constructed_branch','constructed'),('not_started_branch','cleanup'),('no_owner_branch','no_owner')):_branch(m,key,label)
    if older:_branch(m,'ran_branch','cleanup')
    get=lambda k:struct.unpack('<I',m[k])[0]
    if get('exception_resume')!=address+m.start('resume'):
        raise ValueError("CG 程序异常接续没有回到自己的清理位置。")
    apis={'compare_api':('kernel32.dll','lstrcmpA'),'find_api':('user32.dll','FindWindowA'),
        'post_api':('user32.dll','PostMessageA'),'message_api':('user32.dll','MessageBoxA'),
        'com_api':('ole32.dll','CoInitialize' if older else 'CoInitializeEx'),'uncom_api':('ole32.dll','CoUninitialize')}
    imports=_imports(raw,image)
    for key,expected in apis.items():_api(raw,image,sections,imports,m,key,expected)
    slots=_import_slots(raw,image);early=get('early_api')
    if early not in slots:raise ValueError("CG 程序入口的早期导入调用不是自己的 IAT。")
    _mapped(raw,image,sections,m,['seh'],True)
    _mapped(raw,image,sections,m,['command_text','window_text','owner_global']+([] if older else ['cookie']))
    _relocated(raw,image,sections,get('owner_global'),executable=False,length=4)
    calls={key:_relative(address,m,key) for key in m.groupdict() if key.endswith('_call')}
    for target in calls.values():_relocated(raw,image,sections,target,executable=True)
    if calls['constructor_call']!=instance['native_parent_constructor']['address'] or calls['startup_call']!=instance['native_parent_startup']['address']:
        raise ValueError("CG 程序入口没有调用同一来源的完整上层构造／启动。")
    if calls['error_free_call']!=calls['free_call']:
        raise ValueError("CG 程序正常／异常释放没有使用同一入口。")
    if not older and calls['allocate_call']!=instance['native_parent_startup']['helper_addresses']['allocate0_call']:
        raise ValueError("CG 程序入口和上层对象没有使用同一分配入口。")
    capacity=get('allocation_bytes');embedded=instance['native_parent_startup']['embedded_controller_field']
    required=[]
    for key in ('native_parent_constructor','native_parent_startup'):
        required += [r['field']+r['bytes'] for r in instance[key]['direct_parent_writes']]
    for key in ('native_controller_constructor','native_startup'):
        required += [embedded+r['field']+r['bytes'] for r in instance['native_vm_startup'][key]['direct_object_writes']]
    table=instance['native_vm_startup']['native_controller_constructor']['table_constructor_fields'][0]
    required += [embedded+table+64,get('error_text_field')+4]
    if not max(required)<=capacity<2**31:
        raise ValueError("CG 程序分配大小不足以容纳自己的对象／调用表写入范围。")
    return dict(**_record(address,at,m[0]),helper_addresses=calls,owner_global=get('owner_global'),
        allocation_bytes=capacity,minimum_direct_object_extent=max(required),
        early_import_identity=slots[early],early_import_effects_proven=False,
        constructor_call_address=address+m.start('constructor_call')-1,startup_call_address=address+m.start('startup_call')-1,
        complete_explicit_normal_application_paths_static_bound=True,
        constructor_return_passed_directly_to_startup_conditional=True,
        no_intervening_call_between_constructor_normal_return_and_startup=True,
        explicit_parent_startup_calls_per_application_invocation_maximum=1,
        application_clears_parent_global_after_free=not older,
        embedded_exception_continuation_bytes_bound=True,SEH_dispatch_to_embedded_handler_proven=False,
        null_allocation_branch_retained=True,normal_child_ABI_return_is_an_assumption=True,
        published_owner_may_be_modified_by_run_or_children=True,complete_allocation_exception_and_reentry_effects_bound=False)


def _allocator(raw,image,sections,address,older):
    at=_relocated(raw,image,sections,address,executable=True);section=next(s for s in sections if s[3]<=at<s[3]+s[2])
    w=_w
    if older:
        p=engine_pattern('native_cg_vm_application:154:10')+w('handler_call')
        p+=engine_pattern('native_cg_vm_application:155:11')+w('no_memory_api')+engine_pattern('native_cg_vm_application:155:81')+w('allocate_call')
        p+=engine_pattern('native_cg_vm_application:156:11')
    else:
        p=engine_pattern('native_cg_vm_application:158:10')+w('handler_call')
        p+=engine_pattern('native_cg_vm_application:159:11')+w('allocate_call')+engine_pattern('native_cg_vm_application:159:100')
        p+=engine_pattern('native_cg_vm_application:160:11')+w('error_flag')+engine_pattern('native_cg_vm_application:160:51')+w('error_object')+engine_pattern('native_cg_vm_application:160:82')+w('error_ctor_call')
        p+=rb"\x68"+w('exit_callback')+rb"\xe8"+w('atexit_call')+engine_pattern('native_cg_vm_application:161:65')+w('copy_error_call')+rb"\x68"+w('error_type')+engine_pattern('native_cg_vm_application:161:157')+w('throw_call')
    m=re.match(p,raw[at:min(at+1024,section[3]+section[2])],re.DOTALL)
    if m is None:raise ValueError("CG 程序自己的分配重试／返回路径还未完整绑定。")
    for key,label in [('first_branch','allocate'),('retry_branch','retry')]+([('continue_branch','allocate')] if older else [('error_branch','error'),('constructed_branch','constructed')]):_branch(m,key,label)
    calls={key:_relative(address,m,key) for key in m.groupdict() if key.endswith('_call')}
    for target in calls.values():_relocated(raw,image,sections,target,executable=True)
    if older:_api(raw,image,sections,_imports(raw,image),m,'no_memory_api',('msvcp71.dll','?_Nomemory@std@@YAXXZ'))
    else:
        _mapped(raw,image,sections,m,['error_type']);_mapped(raw,image,sections,m,['exit_callback'],True)
        storage={key:_writable_image_range(raw,image,sections,struct.unpack('<I',m[key])[0],4) for key in ('error_flag','error_object')}
    return dict(**_record(address,at,m[0]),helper_addresses=calls,
        complete_explicit_nonnull_return_and_retry_paths_static_bound=True,
        every_explicit_RET_requires_nonzero_allocation_result=True,
        failure_state_PE_ranges=storage if not older else {},
        complete_failure_throw_and_heap_effects_bound=False,exception_child_nonreturning_proven=False,
        normal_child_ABI_return_is_an_assumption=True,native_code_executed=False)


def _parent_destructor(raw,image,sections,address,older,instance):
    at=_relocated(raw,image,sections,address,executable=True);section=next(s for s in sections if s[3]<=at<s[3]+s[2])
    code=raw[at:min(at+4096,section[3]+section[2])];w=_w
    p=engine_pattern('native_cg_vm_application:182:6')+w('seh')+engine_pattern('native_cg_vm_application:182:32')
    if older:p+=engine_pattern('native_cg_vm_application:183:16')+w('initial_state')
    else:p+=engine_pattern('native_cg_vm_application:184:12')+w('cookie')+engine_pattern('native_cg_vm_application:184:41')+w('initial_state')
    m=re.match(p,code,re.DOTALL)
    if m is None:raise ValueError("CG 上层退出清理缺少自己的完整正常入口。")
    _mapped(raw,image,sections,m,['seh'],True)
    if not older:_mapped(raw,image,sections,m,['cookie'])
    embedded=instance['native_parent_startup']['embedded_controller_field']
    table=instance['native_vm_startup']['native_controller_constructor']['table_constructor_fields'][0]
    forbidden={instance['native_parent_constructor']['address'],instance['native_parent_startup']['address'],
        instance['native_vm_startup']['native_controller_constructor']['address'],instance['native_vm_startup']['native_startup']['address']}
    regs=[_UNKNOWN]*8;regs[1]=('this',0);regs[6]=('this',0)
    cursor,pending,calls,writes=m.end(),[],[],[]
    def store(base,disp,size):
        if base==4:
            if disp-4*len(pending)!=(16 if older else 20) or size not in (1,4):
                raise ValueError("CG 上层退出清理的局部异常状态栈地址已变化。")
            return
        value=regs[base]
        if not isinstance(value,tuple) or value[0]!='this':raise ValueError("CG 上层退出清理遇到未知写入对象。")
        field=value[1]+disp
        if field<0 or field+size>=2**31 or max(field,embedded+table)<min(field+size,embedded+table+64):
            raise ValueError("CG 上层退出清理直接覆盖了嵌入控制器调用表。")
        writes.append(dict(field=field,bytes=size))
    while cursor<len(code):
        rest=code[cursor:]
        tail=engine_pattern('native_cg_vm_application:208:13')+w('handle_field')+engine_pattern('native_cg_vm_application:208:44')+w('close_api')
        tail+=(engine_pattern('native_cg_vm_application:209:15') if older else
            engine_pattern('native_cg_vm_application:210:12'))
        t=re.match(tail,rest,re.DOTALL)
        if t:
            if pending:raise ValueError("CG 上层退出清理返回前留有未清理参数。")
            _api(raw,image,sections,_imports(raw,image),t,'close_api',('kernel32.dll','CloseHandle'))
            if struct.unpack('<I',t['handle_field'])[0]!=instance['native_parent_constructor']['direct_parent_writes'][0]['field']:
                raise ValueError("CG 上层退出关闭的不是自己构造时保存的句柄字段。")
            controller=[c for c in calls if c['this_field']==embedded]
            if len(controller)!=1 or not calls or calls[-1]!=controller[0] or controller[0]['argument_bytes']:
                raise ValueError("CG 上层退出清理没有最后一次无参数清理同一嵌入控制器。")
            return dict(**_record(address,at,code[:cursor+t.end()]),child_calls=calls,direct_parent_writes=writes,
                embedded_controller_field=embedded,controller_destructor_address=controller[0]['target'],
                complete_normal_parent_cleanup_path_static_bound=True,close_own_constructed_handle_field=True,
                controller_destructor_effects_complete=False,opaque_cleanup_children_may_mutate_or_reenter=True,
                normal_child_ABI_return_is_an_assumption=True,complete_exception_and_child_effects_bound=False)
        if rest.startswith(b'\xe8') and len(rest)>=5:
            target=address+cursor+5+struct.unpack_from('<i',rest,1)[0];_relocated(raw,image,sections,target,executable=True)
            if target in forbidden:raise ValueError("CG 上层退出清理再次调用构造／启动。")
            value=regs[1];member=value[1] if isinstance(value,tuple) and value[0]=='this' else None
            values=[dict(this_field=v[1]) if isinstance(v,tuple) else v if type(v) is int else None for v in pending]
            calls.append(dict(address=address+cursor,target=target,this_field=member,argument_bytes=4*len(pending),
                pushed_arguments_in_order=values,opaque=True))
            pending=[]
            for r in (0,1,2):regs[r]=_UNKNOWN
            cursor+=5;continue
        wide=rest.startswith(b'\x66');prefix=1 if wide else 0
        if len(rest)<=prefix:break
        op=rest[prefix];n=0
        if not wide and 0xb8<=op<=0xbf and len(rest)>=5:
            reg=op-0xb8
            if reg in (4,6):raise ValueError("CG 上层退出清理覆盖了保留寄存器。")
            regs[reg]=struct.unpack_from('<I',rest,1)[0];n=5
        elif not wide and op==0x8b and len(rest)>=2 and rest[1]>>6==3:
            dst,src=(rest[1]>>3)&7,rest[1]&7
            if dst in (4,6):raise ValueError("CG 上层退出清理覆盖了对象寄存器。")
            regs[dst]=regs[src];n=2
        elif not wide and op==0x8d and len(rest)>=3:
            modrm=rest[1];mod,dst,base=modrm>>6,(modrm>>3)&7,modrm&7
            if mod not in (1,2) or base!=6 or dst in (4,6):raise ValueError("CG 上层退出清理遇到未知成员寻址。")
            n=3 if mod==1 else 6
            if len(rest)<n:break
            disp=struct.unpack_from('<b' if mod==1 else '<i',rest,2)[0]
            if disp<0:raise ValueError("CG 上层退出清理成员偏移无效。")
            regs[dst]=('this',disp)
        elif not wide and (0x50<=op<=0x57 or op in (0x68,0x6a)):
            n=5 if op==0x68 else 2 if op==0x6a else 1
            if len(rest)<n:break
            pending.append(struct.unpack_from('<I',rest,1)[0] if op==0x68 else struct.unpack_from('<b',rest,1)[0] if op==0x6a else regs[op-0x50])
        elif op in (0x88,0x89,0xc6,0xc7) and len(rest)>=prefix+2:
            modrm=rest[prefix+1];mod,reg,base=modrm>>6,(modrm>>3)&7,modrm&7
            size=1 if op in (0x88,0xc6) else 2 if wide else 4;immediate=op in (0xc6,0xc7)
            if mod not in (0,1,2) or (immediate and reg!=0):raise ValueError("CG 上层退出清理遇到未知内存写入。")
            pos=prefix+2
            if base==4:
                if wide or mod!=1 or len(rest)<pos+2 or rest[pos]!=0x24:raise ValueError("CG 上层退出清理遇到未知栈写入。")
                pos+=1
            elif base!=6:raise ValueError("CG 上层退出清理内存基址不是自己的对象。")
            amount=0 if mod==0 else 1 if mod==1 else 4;n=pos+amount+(size if immediate else 0)
            if len(rest)<n:break
            disp=0 if mod==0 else struct.unpack_from('<b' if mod==1 else '<i',rest,pos)[0]
            store(base,disp,size)
        else:raise ValueError("CG 上层完整退出清理含未知指令，位置 "+str(address+cursor)+"。")
        if len(rest)<n:break
        cursor+=n
    raise ValueError("CG 上层退出清理没有完整正常返回。")


def bind_native_cg_vm_application(executable,header,vm,frames):
    raw=bytes(executable);image,sections=_pe_sections(raw)
    instance=bind_native_cg_vm_instance(raw,header,vm,frames);older=instance['layout']=='signed-word-legacy'
    applications=[]
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000:continue
        for m in re.finditer(engine_pattern('native_cg_vm_application:283:29'),raw[pointer:pointer+length]):
            try:report=_application(raw,image,sections,pointer+m.start(),image+rva+m.start(),older,instance)
            except ValueError:continue
            applications.append(report)
    if len(applications)!=1:raise ValueError("CG 本来源完整程序创建／首次启动路径还未唯一绑定。")
    application=applications[0];calls=application['helper_addresses']
    allocator=_allocator(raw,image,sections,calls['allocate_call'],older)
    cleanup=_parent_destructor(raw,image,sections,calls['destructor_call'],older,instance)
    if any(r['field']+r['bytes']>application['allocation_bytes'] for r in cleanup['direct_parent_writes']):
        raise ValueError("CG 退出清理写入范围越过自己的程序对象分配。")
    targets={instance['native_parent_constructor']['address'],instance['native_parent_startup']['address']};sites=set()
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000:continue
        for m in re.finditer(engine_pattern('native_cg_vm_application:296:29'),raw[pointer:pointer+length],re.DOTALL):
            address=image+rva+m.start()
            if address+5+struct.unpack('<i',m['rel'])[0] in targets:sites.add(address)
    if sites!={application['constructor_call_address'],application['startup_call_address']}:
        raise ValueError("CG 上层对象还有未纳入完整程序路径的直接创建／启动调用。")
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=instance['layout'],
        native_vm_instance=instance,native_application=application,native_application_allocator=allocator,native_parent_cleanup=cleanup,
        complete_explicit_normal_application_paths_static_bound=True,complete_normal_parent_cleanup_path_static_bound=True,
        nonnull_constructor_to_first_startup_same_pointer_static_bound_conditional=True,
        normal_allocator_explicit_RET_is_nonnull_static_bound=True,all_matching_direct_parent_calls_in_bound_application=True,
        same_live_instance_constructor_before_startup_unconditionally_proven=False,startup_at_most_once_per_live_instance_proven=False,
        native_controller_and_vector_destructor_effects_complete=False,native_allocator_and_free_heap_effects_complete=False,
        initial_syscall_vector_count_zero_proven=False,reload_clear_before_header_append_proven=False,
        source_header_arity_to_native_descriptor_bound=False,complete_allocation_exception_and_reentry_effects_bound=False,
        SEH_dispatch_to_embedded_handler_proven=False,CRT_or_external_entry_invocation_count_proven=False,
        indirect_callers_proven_absent=False,normal_child_ABI_return_is_an_assumption=True,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False)
