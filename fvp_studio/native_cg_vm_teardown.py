"""Own pre-vector teardown and normal CRT frame effects, not full lifetime.

The frame transition is symbolically interpreted from the actual bound bytes;
no native code is executed. Entry/exit mapping assumes the intervening free
body/children preserve its saved slots and normal ABI. Member loops retain
opaque children, and external legacy delete has no fabricated local frame.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import bind_native_cg_vm_cleanup, _code
from .native_cg_vm_startup import _record, _relative
from .native_cg_vm_instance import _w, _branch, _mapped

SCHEMA = "fvp-native-cg-vm-teardown/1"


def _pre_vector_teardown(raw,image,sections,cleanup,older):
    controller=cleanup['native_controller_cleanup'];calls=controller['child_calls']
    if not calls or calls[0]['this_field']!=0 or calls[0]['argument_bytes'] or not calls[0]['opaque']:
        raise ValueError("CG 退出前的成员清理没有接收同一控制器对象。")
    address=calls[0]['target'];at,code=_code(raw,image,sections,address,512);w=_w
    p=engine_pattern('native_cg_vm_teardown:26:6')+w('payload_field')
    p+=engine_pattern('native_cg_vm_teardown:27:7') if older else engine_pattern('native_cg_vm_teardown:27:42')
    p+=engine_pattern('native_cg_vm_teardown:28:7')+w('free_call')+engine_pattern('native_cg_vm_teardown:28:58')
    p+=engine_pattern('native_cg_vm_teardown:29:7')+w('base0')+rb"\xbf"+w('count0')+engine_pattern('native_cg_vm_teardown:29:64')
    p+=engine_pattern('native_cg_vm_teardown:30:7')+w('clear0_call')+engine_pattern('native_cg_vm_teardown:30:58')
    p+=rb"\x4f" if older else engine_pattern('native_cg_vm_teardown:31:30')
    p+=engine_pattern('native_cg_vm_teardown:32:7')+w('base1')+rb"\xbf"+w('count1')
    p+=engine_pattern('native_cg_vm_teardown:33:7') if older else engine_pattern('native_cg_vm_teardown:33:42')
    p+=engine_pattern('native_cg_vm_teardown:34:7')+w('clear1_call')+engine_pattern('native_cg_vm_teardown:34:58')
    p+=rb"\x4f" if older else engine_pattern('native_cg_vm_teardown:35:30')
    p+=engine_pattern('native_cg_vm_teardown:36:7')
    m=re.match(p,code,re.DOTALL)
    if m is None:raise ValueError("CG 退出前的成员清理没有完整覆盖释放、两个循环和正常返回。")
    for key,label in (('empty_branch','arrays'),('back0','loop0'),('back1','loop1')):_branch(m,key,label)
    application=cleanup['native_vm_application'];instance=application['native_vm_instance']
    ctor=instance['native_vm_startup']['native_controller_constructor']
    embedded=instance['native_parent_startup']['embedded_controller_field']
    extent=application['native_application']['allocation_bytes']-embedded;table=ctor['table_constructor_fields'][0]
    def member(field,size):
        if field<0 or size<=0 or field+size>extent or max(field,table)<min(field+size,table+64):
            raise ValueError("CG 退出前的成员清理超出自己的对象或碰到调用表。")
    payload=struct.unpack('<I',m['payload_field'])[0];member(payload,4)
    helpers={key:_relative(address,m,key) for key in ('free_call','clear0_call','clear1_call')}
    if helpers['free_call']!=application['native_application']['helper_addresses']['free_call']:
        raise ValueError("CG 成员清理没有使用自己程序的释放入口。")
    forbidden={address,controller['address'],ctor['address'],instance['native_vm_startup']['native_startup']['address'],
               instance['native_parent_constructor']['address'],instance['native_parent_startup']['address']}
    for child in helpers.values():
        _relocated(raw,image,sections,child,executable=True)
        if child in forbidden:raise ValueError("CG 成员清理又调用了自身、构造或启动。")
    loops=[]
    for index in range(2):
        base,count=(struct.unpack('<I',m[k+str(index)])[0] for k in ('base','count'))
        stride=struct.unpack('<b',m['stride'+str(index)])[0]
        if not 0<count<=0x10000 or not 0<stride<=0x7f:
            raise ValueError("CG 成员清理循环没有有界的正数量／步长。")
        member(base,count*stride)
        if max(base,payload)<min(base+count*stride,payload+4):
            raise ValueError("CG 成员清理数组与被释放的指针字段重叠。")
        loops.append(dict(base_field=base,iterations=count,stride_bytes=stride,
            child_address=helpers['clear'+str(index)+'_call'],argument=0,
            explicit_iteration_bound_static_under_normal_child_ABI=True,child_effects_complete=False))
    if max(loops[0]['base_field'],loops[1]['base_field'])<min(
            loops[0]['base_field']+loops[0]['iterations']*loops[0]['stride_bytes'],
            loops[1]['base_field']+loops[1]['iterations']*loops[1]['stride_bytes']):
        raise ValueError("CG 退出前的两个成员清理数组范围重叠。")
    return dict(**_record(address,at,m[0]),helper_addresses=helpers,payload_field=payload,
        payload_null_skips_free=True,payload_zero_after_own_release_block_conditional=True,
        payload_still_zero_after_opaque_loops_not_assumed=True,member_loops=loops,
        complete_explicit_normal_pre_vector_teardown_static_bound=True,
        direct_call_table_field_writes=[],call_table_counts_cleared_by_this_function=False,
        normal_child_ABI_and_callee_saved_registers_required=True,
        complete_child_exception_and_reentry_effects_bound=False,native_code_executed=False)


class _FrameSymbols:
    """Bounded x86 stack effects; symbolic addresses are not host addresses."""
    def __init__(self,local_bytes,seh_data):
        self.regs=[('entry-reg',i) for i in range(8)]
        self.sp=0;self.fs=('entry-FS0',);self.memory={0:('free-return',),4:('argument-pointer',)}
        self.original={reg:self.regs[reg] for reg in (3,5,6,7)}
        self.push(local_bytes);self.push(seh_data);self.push(('frame-return',))
        self.trace=[]
    def push(self,value):
        self.sp-=4
        if not -0x2000<=self.sp<=8:raise ValueError("CG 原生释放栈的符号范围越界。")
        self.memory[self.sp]=value
    def load(self,offset):
        if offset not in self.memory:raise ValueError("CG 原生释放栈读取了没有来源的保存槽。")
        return self.memory[offset]
    def pop(self):
        value=self.load(self.sp);self.sp+=4;return value
    def base(self,reg):
        value=self.regs[reg]
        if not isinstance(value,tuple) or len(value)!=2 or value[0]!='stack-address':
            raise ValueError("CG 原生释放栈使用了未绑定的栈基址。")
        return value[1]
    def run(self,code,expected_return):
        cursor=0
        while cursor<len(code):
            rest=code[cursor:];op=rest[0];n=0
            if op==0x68 and len(rest)>=5:self.push(struct.unpack_from('<I',rest,1)[0]);n=5
            elif rest.startswith(bytes.fromhex('64ff3500000000')):self.push(self.fs);n=7
            elif 0x50<=op<=0x57:
                reg=op-0x50;self.push(('stack-address',self.sp) if reg==4 else self.regs[reg]);n=1
            elif 0x58<=op<=0x5f:
                reg=op-0x58
                if reg==4:raise ValueError("CG 原生释放栈出现未知 POP ESP。")
                self.regs[reg]=self.pop();n=1
            elif rest.startswith(bytes.fromhex('8b442410')):self.regs[0]=self.load(self.sp+16);n=4
            elif rest.startswith(bytes.fromhex('896c2410')):self.memory[self.sp+16]=self.regs[5];n=4
            elif rest.startswith(bytes.fromhex('8d6c2410')):self.regs[5]=('stack-address',self.sp+16);n=4
            elif rest.startswith(bytes.fromhex('2be0')):
                value=self.regs[0]
                if type(value) is not int or not 12<=value<=0x1000 or value%4:
                    raise ValueError("CG 原生释放栈的局部空间不是合法确定值。")
                self.sp-=value;n=2
            elif op==0xa1 and len(rest)>=5:
                self.regs[0]=('own-cookie',struct.unpack_from('<I',rest,1)[0]);n=5
            elif rest.startswith(bytes.fromhex('3145fc')):
                at=self.base(5)-4;self.memory[at]=('xor',self.load(at),self.regs[0]);n=3
            elif rest.startswith(bytes.fromhex('33c5')):self.regs[0]=('xor',self.regs[0],self.regs[5]);n=2
            elif rest.startswith(bytes.fromhex('8965e8')):self.memory[self.base(5)-24]=('stack-address',self.sp);n=3
            elif rest.startswith(bytes.fromhex('ff75f8')):self.push(self.load(self.base(5)-8));n=3
            elif rest.startswith(bytes.fromhex('8b45fc')):self.regs[0]=self.load(self.base(5)-4);n=3
            elif rest.startswith(bytes.fromhex('c745fcfeffffff')):self.memory[self.base(5)-4]=0xfffffffe;n=7
            elif rest.startswith(bytes.fromhex('8945f8')):self.memory[self.base(5)-8]=self.regs[0];n=3
            elif rest.startswith(bytes.fromhex('8d45f0')):self.regs[0]=('stack-address',self.base(5)-16);n=3
            elif rest.startswith(bytes.fromhex('64a300000000')):self.fs=self.regs[0];n=6
            elif rest.startswith(bytes.fromhex('8b4df0')):self.regs[1]=self.load(self.base(5)-16);n=3
            elif rest.startswith(bytes.fromhex('64890d00000000')):self.fs=self.regs[1];n=7
            elif rest.startswith(bytes.fromhex('8be5')):self.sp=self.base(5);n=2
            elif op==0xc3:
                if cursor+1!=len(code) or self.pop()!=expected_return:
                    raise ValueError("CG 原生释放栈返回到了错误位置或没有覆盖完整函数。")
                n=1
            else:raise ValueError("CG 原生释放栈框架含未知符号指令。")
            cursor+=n;self.trace.append(dict(instruction_offset=cursor-n,SP_relative_to_free_entry=self.sp))
        return self


def _crt_frame_pair(raw,image,sections,cleanup):
    release=cleanup['native_release_bridge']
    if release['kind']=='own-external-delete-import':return None
    own=release['native_free_paths'];helpers=own['helper_addresses']
    at=own['offset'];body=raw[at:at+own['code_bytes']]
    caller=re.match(engine_pattern('native_cg_vm_teardown:152:20')+_w('seh_data')+rb"\xe8"+_w('frame_call'),body,re.DOTALL)
    if caller is None or _relative(own['address'],caller,'frame_call')!=helpers['frame_call']:
        raise ValueError("CG 原生释放栈框架没有连到自己完整释放函数的入口。")
    local=struct.unpack('<b',caller['local'])[0];seh=struct.unpack('<I',caller['seh_data'])[0]
    if not body.endswith(b'\xc3'):raise ValueError("CG 原生释放函数没有自己的无参数清理 RET。")
    frame_at,frame_code=_code(raw,image,sections,helpers['frame_call'],256)
    p=rb"\x68"+_w('handler')+engine_pattern('native_cg_vm_teardown:158:29')+_w('cookie')
    p+=engine_pattern('native_cg_vm_teardown:159:7')
    frame=re.match(p,frame_code,re.DOTALL)
    if frame is None:raise ValueError("CG 原生释放栈框架没有完整覆盖建立、保存与接续。")
    _mapped(raw,image,sections,frame,['handler'],True);_mapped(raw,image,sections,frame,['cookie'])
    return_at,return_code=_code(raw,image,sections,helpers['unframe_call'],128)
    unframe=re.match(engine_pattern('native_cg_vm_teardown:164:21'),return_code)
    if unframe is None:raise ValueError("CG 原生释放栈框架没有完整恢复保存寄存器、SEH和原返回栈。")
    if max(helpers['frame_call'],helpers['unframe_call'])<min(helpers['frame_call']+frame.end(),helpers['unframe_call']+unframe.end()):
        raise ValueError("CG 原生释放栈入口和出口函数发生重叠。")
    symbols=_FrameSymbols(local,seh);symbols.run(frame[0],('frame-return',))
    frame_sp=symbols.sp;frame_bp=symbols.base(5)
    if frame_bp!=-4 or frame_sp!=-(local+36) or symbols.load(frame_bp+8)!=('argument-pointer',):
        raise ValueError("CG 原生释放函数的参数槽没有映射到原指针。")
    if symbols.fs!=('stack-address',-20) or symbols.load(0)!=('free-return',):
        raise ValueError("CG 原生释放栈框架覆盖了原返回位置或SEH来源。")
    # Model the matched explicit body-local stores, not opaque error-slot or
    # allocator effects. Normal child ABI and saved-slot preservation remain
    # conditions; this transition is NOT a heap/exception/reentry proof.
    symbols.memory[frame_bp-4]=0xfffffffe
    symbols.memory[frame_bp-28]=('small-heap-lookup-result',)
    symbols.push(('unframe-return',));symbols.run(unframe[0],('unframe-return',))
    if symbols.sp!=0 or symbols.fs!=('entry-FS0',) or any(symbols.regs[r]!=v for r,v in symbols.original.items()):
        raise ValueError("CG 原生释放栈出口没有恢复自己的保存寄存器与调用者栈。")
    if symbols.load(4)!=('argument-pointer',) or symbols.pop()!=('free-return',) or symbols.sp!=4:
        raise ValueError("CG 原生释放的最终RET没有保留调用者参数清理。")
    return dict(native_frame_entry=_record(helpers['frame_call'],frame_at,frame[0]),
        native_frame_exit=_record(helpers['unframe_call'],return_at,unframe[0]),
        caller_local_bytes=local,frame_SP_relative_to_free_entry=frame_sp,frame_EBP_relative_to_free_entry=frame_bp,
        free_argument_EBP_displacement=8,original_argument_entry_SP_displacement=4,
        free_RET_SP_relative_to_free_entry=4,caller_argument_cleanup_bytes=4,
        original_EBP_EBX_ESI_EDI_and_FS0_restored_symbolically=True,
        normal_entry_exit_argument_return_mapping_static_bound_conditional=True,
        free_body_saved_slots_and_normal_child_ABI_are_required=True,
        opaque_body_error_pointer_aliases_and_reentry_effects_complete=False,
        heap_and_exception_effects_complete=False,SEH_dispatch_effects_complete=False,
        symbolic_instruction_trace=symbols.trace,symbolic_only=True,native_code_executed=False)


def bind_native_cg_vm_teardown(executable,header,vm,frames):
    raw=bytes(executable);image,sections=_pe_sections(raw)
    cleanup=bind_native_cg_vm_cleanup(raw,header,vm,frames);older=cleanup['layout']=='signed-word-legacy'
    members=_pre_vector_teardown(raw,image,sections,cleanup,older)
    crt=_crt_frame_pair(raw,image,sections,cleanup)
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=cleanup['layout'],
        native_vm_cleanup=cleanup,native_pre_vector_teardown=members,native_CRT_free_frame=crt,
        complete_explicit_normal_pre_vector_teardown_static_bound=True,own_pre_vector_member_ranges_static_bound=True,
        normal_CRT_free_frame_argument_return_mapping_static_bound_conditional=crt is not None,
        legacy_external_delete_frame_not_fabricated=crt is None,
        complete_member_child_and_heap_effects_bound=False,native_controller_and_vector_destructor_effects_complete=False,
        native_allocator_and_free_heap_effects_complete=False,zero_count_object_destructor_effects_complete=False,
        same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
        reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
        complete_allocation_exception_and_reentry_effects_bound=False,indirect_callers_proven_absent=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False)
