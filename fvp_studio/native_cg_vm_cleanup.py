"""Own controller/vector normal cleanup paths, not heap/lifetime acceptance.

Destroying a vector does NOT reset capacity/count/buffer in these layouts.
The entry-release loop re-reads count: a mutating/reentrant release can change
its bound. Opaque children, CRT frame/heap helpers and external delete remain
unproven. Whole explicit paths and import identities are not their effects.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import bind_native_cg_vm_application, _writable_image_range, _import_slots
from .native_cg_vm_startup import _record, _relative
from .native_cg_vm_instance import _w, _branch, _mapped, _api
from .native_rotation_degrees import _imports

SCHEMA = "fvp-native-cg-vm-cleanup/1"
_UNKNOWN = object()


def _code(raw, image, sections, address, limit=4096):
    at = _relocated(raw, image, sections, address, executable=True)
    section = next(s for s in sections if s[3] <= at < s[3]+s[2])
    return at, raw[at:min(at+limit, section[3]+section[2])]


def _release_bridge(raw, image, sections, address, older):
    at, code = _code(raw, image, sections, address)
    if older:
        m = re.match(engine_pattern('native_cg_vm_cleanup:32:21')+_w('delete_api'), code, re.DOTALL)
        if m is None:
            raise ValueError("CG 旧版释放入口没有完整绑定自己的导入跳转。")
        identity = _import_slots(raw, image).get(struct.unpack('<I', m['delete_api'])[0])
        if identity != dict(dll='msvcr71.dll', ordinal=None, name='??3@YAXPAX@Z'):
            raise ValueError("CG 旧版释放入口不是自己命名的 operator delete 导入。")
        _relocated(raw,image,sections,struct.unpack('<I',m['delete_api'])[0],executable=False,length=4)
        return dict(**_record(address,at,m[0]),kind='own-external-delete-import',import_identity=identity,
            complete_explicit_release_bridge_static_bound=True,external_delete_implementation_bound=False,
            native_heap_release_effects_complete=False,native_code_executed=False)
    m = re.match(engine_pattern('native_cg_vm_cleanup:42:17')+_w('free_jump'),code,re.DOTALL)
    if m is None:
        raise ValueError("CG 现代释放入口没有完整绑定自己的栈不变尾跳。")
    target = _relative(address,m,'free_jump'); inner_at, inner = _code(raw,image,sections,target)
    w = _w
    p = engine_pattern('native_cg_vm_cleanup:47:8')+w('seh_data')+rb"\xe8"+w('frame_call')+engine_pattern('native_cg_vm_cleanup:47:64')
    p += engine_pattern('native_cg_vm_cleanup:48:9')+w('heap_mode')+engine_pattern('native_cg_vm_cleanup:48:37')+w('lock_call')+engine_pattern('native_cg_vm_cleanup:48:99')+w('lookup_call')
    p += engine_pattern('native_cg_vm_cleanup:49:9')+w('small_release_call')+engine_pattern('native_cg_vm_cleanup:49:101')+w('finally_call')
    p += engine_pattern('native_cg_vm_cleanup:50:9')+w('unlock_call')+engine_pattern('native_cg_vm_cleanup:50:132')
    p += engine_pattern('native_cg_vm_cleanup:51:9')+w('heap_global')+engine_pattern('native_cg_vm_cleanup:51:73')+w('heap_free_api')+engine_pattern('native_cg_vm_cleanup:51:105')
    p += rb"\xe8"+w('error_slot_call')+engine_pattern('native_cg_vm_cleanup:52:39')+w('last_error_api')+engine_pattern('native_cg_vm_cleanup:52:80')+w('error_map_call')+engine_pattern('native_cg_vm_cleanup:52:113')+w('unframe_call')+rb"\xc3"
    f = re.match(p,inner,re.DOTALL)
    if f is None:
        raise ValueError("CG 现代堆释放函数没有完整覆盖 NULL、小块、普通堆及失败返回。")
    for key,label in (('nil_branch','return'),('ordinary_branch','ordinary'),('unlocated_branch','unlock'),
                      ('small_done_branch','return'),('heap_branch','heap'),('freed_branch','return')):
        _branch(f,key,label)
    children = {key:_relative(target,f,key) for key in f.groupdict() if key.endswith('_call')}
    for child in children.values():
        _relocated(raw,image,sections,child,executable=True)
    if children['finally_call'] != target+f.start('finally'):
        raise ValueError("CG 现代堆释放没有调用自己的内嵌解锁接续。")
    _mapped(raw,image,sections,f,['seh_data'])
    storage = {key:_writable_image_range(raw,image,sections,struct.unpack('<I',f[key])[0],4)
               for key in ('heap_mode','heap_global')}
    imports = _imports(raw,image)
    for key,api in (('heap_free_api','HeapFree'),('last_error_api','GetLastError')):
        _api(raw,image,sections,imports,f,key,('kernel32.dll',api))
    return dict(**_record(address,at,m[0]),kind='own-modern-free-tail',target=target,
        native_free_paths=dict(**_record(target,inner_at,f[0]),helper_addresses=children,
            static_heap_ranges=storage,complete_explicit_normal_free_paths_static_bound=True,
            CRT_frame_helpers_effects_complete=False,small_heap_lock_lookup_release_effects_complete=False,
            error_storage_child_effects_complete=False,SEH_dispatch_effects_complete=False),
        complete_explicit_release_bridge_static_bound=True,native_heap_release_effects_complete=False,
        native_code_executed=False)


def _buffer_destructor(raw,image,sections,address,free):
    at,code = _code(raw,image,sections,address,64)
    p = engine_pattern('native_cg_vm_cleanup:81:8')+_w('free_call')+engine_pattern('native_cg_vm_cleanup:81:82')
    m = re.match(p,code,re.DOTALL)
    if m is None:
        raise ValueError("CG 调用表缓冲区的完整析构路径尚未绑定。")
    _branch(m,'empty_branch','return')
    if _relative(address,m,'free_call') != free:
        raise ValueError("CG 调用表缓冲区没有使用自己程序的释放入口。")
    return dict(**_record(address,at,m[0]),kind='capacity-guarded-buffer-only',capacity_field=0,
        count_field=4,buffer_field=8,free_address=free,capacity_zero_skips_buffer_read=True,
        capacity_nonzero_releases_buffer=True,releases_entries=False,
        explicit_vector_field_writes=[],resets_vector_fields=False,
        complete_explicit_normal_vector_destructor_paths_static_bound=True,
        native_heap_release_effects_complete=False,normal_child_ABI_return_is_an_assumption=True)


def _vector_destructor(raw,image,sections,address,free,older):
    at,code = _code(raw,image,sections,address,128)
    if code.startswith(b'\x83\x39\0'):
        return _buffer_destructor(raw,image,sections,address,free)
    p = engine_pattern('native_cg_vm_cleanup:100:8')
    if older:
        p += engine_pattern('native_cg_vm_cleanup:102:13')
    else:
        p += engine_pattern('native_cg_vm_cleanup:104:13')
    p += engine_pattern('native_cg_vm_cleanup:105:9')+_w('free_call')
    p += engine_pattern('native_cg_vm_cleanup:106:9') if older else engine_pattern('native_cg_vm_cleanup:106:64')
    p += engine_pattern('native_cg_vm_cleanup:107:9')+_w('buffer_jump')
    m = re.match(p,code,re.DOTALL)
    if m is None:
        raise ValueError("CG 逐项释放调用表的完整循环／尾跳尚未绑定。")
    for key,label in [('empty_branch','tail'),('back_branch','loop')]+([] if older else [('first_branch','loop')]):
        _branch(m,key,label)
    if _relative(address,m,'free_call') != free:
        raise ValueError("CG 调用表项目没有使用同一程序释放入口。")
    buffer = _buffer_destructor(raw,image,sections,_relative(address,m,'buffer_jump'),free)
    return dict(**_record(address,at,m[0]),kind='signed-count-entry-loop-then-buffer',capacity_field=0,
        count_field=4,buffer_field=8,free_address=free,native_buffer_destructor=buffer,
        count_nonpositive_skips_entry_read=True,loop_index_initial=0,loop_index_increment=1,
        entry_pointer_stride_bytes=4,count_reread_after_each_release=True,releases_entries=True,
        frozen_entry_count_at_invocation_not_assumed=True,termination_under_child_mutation_proven=False,
        explicit_vector_field_writes=[],resets_vector_fields=False,
        complete_explicit_normal_vector_destructor_paths_static_bound=True,
        native_heap_release_effects_complete=False,normal_child_ABI_return_is_an_assumption=True)


def _controller_destructor(raw,image,sections,address,application,older):
    at,code = _code(raw,image,sections,address);w = _w
    instance = application['native_vm_instance'];ctor = instance['native_vm_startup']['native_controller_constructor']
    fields = ctor['table_constructor_fields'];first = fields[0]
    embedded = instance['native_parent_startup']['embedded_controller_field']
    extent = application['native_application']['allocation_bytes']-embedded
    free = application['native_application']['helper_addresses']['free_call']
    forbidden = {instance['native_parent_constructor']['address'],instance['native_parent_startup']['address'],
        ctor['address'],instance['native_vm_startup']['native_startup']['address'],
        ctor['native_pointer_vector_constructor']['address'],address}
    p = engine_pattern('native_cg_vm_cleanup:136:8')+w('seh')+engine_pattern('native_cg_vm_cleanup:136:34')
    if older:
        p += engine_pattern('native_cg_vm_cleanup:138:13')+w('state')
    else:
        p += engine_pattern('native_cg_vm_cleanup:140:13')+w('cookie')+engine_pattern('native_cg_vm_cleanup:140:46')+w('state')
    m = re.match(p,code,re.DOTALL)
    if m is None:
        raise ValueError("CG 控制器析构缺少自己的完整正常入口。")
    _mapped(raw,image,sections,m,['seh'],True)
    if not older:_mapped(raw,image,sections,m,['cookie'])
    regs = [_UNKNOWN]*8;regs[1]=regs[6]=('this',0)
    cursor=m.end();pending=[];calls=[];writes=[];vectors=[];member_releases=[]
    def field_range(field,size):
        if field < 0 or size <= 0 or field+size > extent or max(field,first)<min(field+size,first+64):
            raise ValueError("CG 控制器析构越过自己的对象或直接触碰调用表字段。")
    def store(base,disp,size,value):
        if base == 4:
            if disp-4*len(pending) != (20 if older else 24) or size not in (1,4):
                raise ValueError("CG 控制器析构的异常状态栈地址发生变化。")
            return
        owner=regs[base]
        if not isinstance(owner,tuple) or owner[0]!='this':
            raise ValueError("CG 控制器析构含未知内存写入对象。")
        field=owner[1]+disp;field_range(field,size)
        writes.append(dict(field=field,bytes=size,value=value if type(value) is int else None))
    def child(target):
        _relocated(raw,image,sections,target,executable=True)
        if target in forbidden:raise ValueError("CG 控制器退出时重新调用了构造／启动或自身析构。")
    while cursor < len(code):
        rest=code[cursor:]
        tail=(engine_pattern('native_cg_vm_cleanup:166:14') if older else
              engine_pattern('native_cg_vm_cleanup:167:14'))
        t=re.match(tail,rest,re.DOTALL)
        if t:
            if pending or [r['controller_field'] for r in vectors] != list(reversed(fields)):
                raise ValueError("CG 控制器没有完整反序清理同一四张表或返回前仍有参数。")
            return dict(**_record(address,at,code[:cursor+t.end()]),child_calls=calls,
                direct_controller_writes=writes,table_destructors=vectors,guarded_member_releases=member_releases,
                complete_explicit_normal_controller_cleanup_path_static_bound=True,
                own_constructed_tables_destroyed_once_in_reverse_order_on_explicit_normal_path=True,
                table_fields_reset_by_these_destructors=False,opaque_children_may_mutate_or_reenter=True,
                complete_exception_and_child_effects_bound=False,normal_child_ABI_return_is_an_assumption=True)
        # The whole conditional allocation-header cleanup is bound as one
        # block; never ignore its branch or pretend the heap count is known.
        array = re.match(engine_pattern('native_cg_vm_cleanup:180:25')+w('field')+engine_pattern('native_cg_vm_cleanup:180:49')+w('callback')+engine_pattern('native_cg_vm_cleanup:181:59')+w('array_call')
            +engine_pattern('native_cg_vm_cleanup:182:13')+w('delete_call')+engine_pattern('native_cg_vm_cleanup:182:43'),rest,re.DOTALL)
        if array:
            if older or pending:raise ValueError("CG 控制器动态数组清理的栈／布局不匹配。")
            _branch(array,'empty_branch','end');field=struct.unpack('<I',array['field'])[0];field_range(field,4)
            _mapped(raw,image,sections,array,['callback'],True)
            targets={k:_relative(address+cursor,array,k) for k in ('array_call','delete_call')}
            for target in targets.values():child(target)
            member_releases.append(dict(address=address+cursor,field=field,kind='nullable-allocation-header-array',
                helper_addresses=targets,heap_header_count_bound=False,heap_allocation_extent_proven=False))
            for reg in (0,1,2,7):regs[reg]=_UNKNOWN
            cursor+=array.end();continue
        pointer=re.match(engine_pattern('native_cg_vm_cleanup:193:25')+w('field')+engine_pattern('native_cg_vm_cleanup:193:49')+w('free_call')
            +engine_pattern('native_cg_vm_cleanup:194:13'),rest,re.DOTALL)
        if pointer:
            if not older or pending or regs[3]!=0:raise ValueError("CG 控制器指针释放没有确定的零值／空栈。")
            _branch(pointer,'empty_branch','end');field=struct.unpack('<I',pointer['field'])[0];field_range(field,4)
            if _relative(address+cursor,pointer,'free_call')!=free:
                raise ValueError("CG 控制器指针释放没有调用自己的程序释放入口。")
            member_releases.append(dict(address=address+cursor,field=field,kind='nullable-member-pointer',free_address=free))
            for reg in (0,1,2):regs[reg]=_UNKNOWN
            cursor+=pointer.end();continue
        if rest.startswith(b'\xe8') and len(rest)>=5:
            target=address+cursor+5+struct.unpack_from('<i',rest,1)[0];child(target)
            value=regs[1];member=value[1] if isinstance(value,tuple) and value[0]=='this' else None
            if member is not None and first<=member<first+64:
                if pending or len(vectors)>=4 or member!=fields[3-len(vectors)]:
                    raise ValueError("CG 调用表析构的对象、反序或参数不匹配。")
                vector=_vector_destructor(raw,image,sections,target,free,older)
                vectors.append(dict(controller_field=member,call_address=address+cursor,destructor=vector))
            # Callback-array ranges must stay inside this owner and away from
            # the four vectors, even though callbacks themselves are opaque.
            if len(pending)==4 and isinstance(pending[-1],tuple) and pending[-1][0]=='this':
                callback,count,stride,owner=pending
                if type(callback) is not int or type(count) is not int or type(stride) is not int or not 0<count<2**31 or not 0<stride<2**31:
                    raise ValueError("CG 控制器成员数组析构的回调／数量／步长不确定。")
                _relocated(raw,image,sections,callback,executable=True);field_range(owner[1],count*stride)
            args=[dict(this_field=v[1]) if isinstance(v,tuple) else v if type(v) is int else None for v in pending]
            calls.append(dict(address=address+cursor,target=target,this_field=member,argument_bytes=4*len(pending),
                pushed_arguments_in_order=args,opaque=not (member is not None and first<=member<first+64)))
            pending=[]
            for reg in (0,1,2):regs[reg]=_UNKNOWN
            cursor+=5;continue
        wide=rest.startswith(b'\x66');prefix=1 if wide else 0
        if len(rest)<=prefix:break
        op=rest[prefix];n=0
        if not wide and 0xb8<=op<=0xbf and len(rest)>=5:
            reg=op-0xb8
            if reg in (3,4,6):raise ValueError("CG 控制器析构覆盖了保留对象／零值寄存器。")
            regs[reg]=struct.unpack_from('<I',rest,1)[0];n=5
        elif not wide and rest.startswith(b'\x33\xdb'):
            if not older:raise ValueError("CG 控制器析构的零值寄存器布局不匹配。")
            regs[3]=0;n=2
        elif not wide and op==0x8b and len(rest)>=2 and rest[1]>>6==3:
            dst,src=(rest[1]>>3)&7,rest[1]&7
            if dst in (3,4,6):raise ValueError("CG 控制器析构覆盖了保留对象寄存器。")
            regs[dst]=regs[src];n=2
        elif not wide and op==0x8d and len(rest)>=3:
            modrm=rest[1];mod,dst,base=modrm>>6,(modrm>>3)&7,modrm&7
            if mod not in (1,2) or base!=6 or dst in (3,4,6):raise ValueError("CG 控制器析构含未知成员寻址。")
            n=3 if mod==1 else 6
            if len(rest)<n:break
            disp=struct.unpack_from('<b' if mod==1 else '<i',rest,2)[0]
            if not 0<=disp<extent:raise ValueError("CG 控制器析构成员寻址超出自身对象。")
            regs[dst]=('this',disp)
        elif not wide and (0x50<=op<=0x57 or op in (0x68,0x6a)):
            n=5 if op==0x68 else 2 if op==0x6a else 1
            if len(rest)<n:break
            pending.append(struct.unpack_from('<I',rest,1)[0] if op==0x68 else struct.unpack_from('<b',rest,1)[0] if op==0x6a else regs[op-0x50])
        elif op in (0x88,0x89,0xc6,0xc7) and len(rest)>=prefix+2:
            modrm=rest[prefix+1];mod,reg,base=modrm>>6,(modrm>>3)&7,modrm&7
            size=1 if op in (0x88,0xc6) else 2 if wide else 4;immediate=op in (0xc6,0xc7)
            if mod not in (0,1,2) or (immediate and reg!=0):raise ValueError("CG 控制器析构含未知内存写入。")
            pos=prefix+2
            if base==4:
                if wide or mod!=1 or len(rest)<pos+2 or rest[pos]!=0x24:raise ValueError("CG 控制器析构含未知栈写入。")
                pos+=1
            elif base!=6:raise ValueError("CG 控制器析构写入基址不是自己的对象。")
            amount=0 if mod==0 else 1 if mod==1 else 4;n=pos+amount+(size if immediate else 0)
            if len(rest)<n:break
            disp=0 if mod==0 else struct.unpack_from('<b' if mod==1 else '<i',rest,pos)[0];pos+=amount
            value=int.from_bytes(rest[pos:pos+size],'little') if immediate else regs[reg]
            store(base,disp,size,value)
        else:raise ValueError("CG 控制器完整正常析构含未知指令，位置 "+str(address+cursor)+"。")
        if len(rest)<n:break
        cursor+=n
    raise ValueError("CG 控制器析构没有完整正常返回。")


def bind_native_cg_vm_cleanup(executable,header,vm,frames):
    raw=bytes(executable);image,sections=_pe_sections(raw)
    application=bind_native_cg_vm_application(raw,header,vm,frames)
    older=application['layout']=='signed-word-legacy'
    free=application['native_application']['helper_addresses']['free_call']
    release=_release_bridge(raw,image,sections,free,older)
    controller=_controller_destructor(raw,image,sections,
        application['native_parent_cleanup']['controller_destructor_address'],application,older)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=application['layout'],
        native_vm_application=application,native_controller_cleanup=controller,native_release_bridge=release,
        complete_explicit_normal_controller_and_vector_cleanup_paths_static_bound=True,
        complete_explicit_release_bridge_static_bound=True,own_constructed_table_cleanup_order_static_bound=True,
        native_controller_and_vector_destructor_effects_complete=False,native_allocator_and_free_heap_effects_complete=False,
        zero_count_object_destructor_effects_complete=False,same_live_instance_lifetime_proven=False,
        initial_syscall_vector_count_zero_proven=False,reload_clear_before_header_append_proven=False,
        source_header_arity_to_native_descriptor_bound=False,complete_allocation_exception_and_reentry_effects_bound=False,
        indirect_callers_proven_absent=False,native_code_executed=False,runtime_verified=False,scene_export_connected=False)
