"""Own allocator bridges and complete element-construction normal paths.

The original child code is not executed. Count arithmetic is 32-bit, not a
host signed comparison; INT_MIN bits can produce 2**31 callbacks. Constructor
and callback bytes/ABI are bound, but writable element bounds, non-aliasing,
heap/exception effects and concurrent mutation still require separate proof.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record,_relative
from .native_cg_vm_instance import _w,_branch
from .native_cg_vm_members import bind_native_cg_vm_members

SCHEMA='fvp-native-cg-vm-member-children/1'
MASK=2**32-1


def _construction_iterations(raw_count):
    """Matched DEC/SUB then JS; no native callback or huge loop is executed."""
    if type(raw_count) is not int or not 0<=raw_count<=MASK:
        raise ValueError('CG 构造数量必须是实际的32位位模式。')
    decremented=(raw_count-1)&MASK
    return 0 if decremented&0x80000000 else decremented+1


def _allocator_bridge(raw,image,sections,address,root,older,direct=False):
    if direct:
        if address!=root['address']:
            raise ValueError('CG 字符串分配没有使用本来源已绑定的完整分配入口。')
        return dict(kind='own-complete-application-allocator-entry',address=address,
            native_application_allocator=root,normal_cdecl_argument_and_return_ABI_forwarded_static_bound=True,
            heap_exception_and_reentry_effects_complete=False,native_code_executed=False)
    at,code=_code(raw,image,sections,address,64)
    p=(b'' if older else engine_pattern('native_cg_vm_member_children:39:25'))+rb'\xe9'+_w('tail_call')
    m=re.match(p,code,re.DOTALL)
    if m is None:
        raise ValueError('CG 成员分配桥没有完整保持原参数、栈和尾跳。')
    target=_relative(address,m,'tail_call')
    _relocated(raw,image,sections,target,executable=True)
    if target!=root['address']:
        raise ValueError('CG 成员分配桥没有跳到本来源已绑定的完整分配入口。')
    if max(address,target)<min(address+m.end(),target+root['code_bytes']):
        raise ValueError('CG 成员分配桥与分配函数重叠。')
    return dict(**_record(address,at,m[0]),kind='own-balanced-tail-to-application-allocator',
        target_allocator_address=target,native_application_allocator=root,
        tail_preserves_entry_SP_argument_and_saved_EBP_static_bound=True,
        normal_cdecl_argument_and_return_ABI_forwarded_static_bound=True,
        heap_exception_and_reentry_effects_complete=False,native_code_executed=False)


def _construct_helper(raw,image,sections,address,older,callback):
    at,code=_code(raw,image,sections,address,256)
    if older:
        p=engine_pattern('native_cg_vm_member_children:59:10')
        p+=engine_pattern('native_cg_vm_member_children:60:11')
        p+=engine_pattern('native_cg_vm_member_children:61:11')
    else:
        p=engine_pattern('native_cg_vm_member_children:63:10')
        p+=engine_pattern('native_cg_vm_member_children:64:11')
        p+=engine_pattern('native_cg_vm_member_children:65:11')
    m=re.match(p,code,re.DOTALL)
    if m is None:
        raise ValueError('CG 成员构造循环没有完整覆盖参数、计数分支、回调、保存恢复和RET16。')
    _branch(m,'empty_branch','return');_branch(m,'back_branch','loop')
    callback_at,callback_code=_code(raw,image,sections,callback,64)
    c=re.match(engine_pattern('native_cg_vm_member_children:71:15'),callback_code)
    if c is None:
        raise ValueError('CG 成员构造回调没有完整覆盖自己的单字节初始化和正常返回。')
    if max(address,callback)<min(address+m.end(),callback+c.end()):
        raise ValueError('CG 成员构造循环与回调函数重叠。')
    # The complete byte grammar fixes all stack argument loads and register
    # saves. Both compiler forms map to the same entry-SP argument cells.
    slots=dict(buffer=4,stride=8,count=12,callback=16)
    count_cases={str(n):_construction_iterations(n) for n in (0,1,2,0x7fffffff,0x80000000,0x80000001,0xffffffff)}
    return dict(**_record(address,at,m[0]),kind='own-complete-element-construction-loop',
        entry_SP_argument_displacements=slots,callee_argument_cleanup_bytes=16,
        native_callback=_record(callback,callback_at,c[0]),callback_callee_argument_cleanup_bytes=0,
        callback_this_is_current_element_static_bound=True,
        callback_direct_element_writes=[dict(field=0,bytes=1,value=0)],
        entire_element_initialized=False,remaining_element_bytes_not_assumed_zero=True,
        callback_has_no_explicit_calls_or_branches=True,
        normal_saved_EBP_EBX_ESI_EDI_restored_static_bound=True,
        native_initial_count_test='JS on (count - 1) modulo 2**32; not signed count <= 0',
        native_backedge='JNE on decremented count' if older else 'JNS on decremented count-minus-one',
        conditional_iteration_expression='0 when bit31(count-1) is set, otherwise ((count-1) mod 2**32)+1',
        conditional_iteration_boundary_cases=count_cases,
        element_pointer_advance_is_modulo_32_bit=True,
        buffer_bounds_and_pointer_wrap_proven=False,
        writable_elements_must_not_alias_saved_stack_or_executable_code=True,
        concurrent_mutation_absence_and_normal_memory_access_required=True,
        termination_under_bound_callback_and_valid_nonaliasing_memory_static_bound_conditional=True,
        complete_explicit_normal_construct_and_callback_paths_static_bound=True,
        complete_heap_exception_and_reentry_effects_bound=False,native_code_executed=False)


def bind_native_cg_vm_member_children(executable,header,vm,frames):
    raw=bytes(executable);image,sections=_pe_sections(raw)
    members=bind_native_cg_vm_members(raw,header,vm,frames);older=members['layout']=='signed-word-legacy'
    application=members['native_vm_teardown']['native_vm_cleanup']['native_vm_application']
    root=application['native_application_allocator']
    string,container=members['native_string_member'],members['native_container_member']
    bridges={
        'string':_allocator_bridge(raw,image,sections,string['helper_addresses']['allocate_call'],root,older,direct=older),
        'container':_allocator_bridge(raw,image,sections,container['helper_addresses']['allocate_call'],root,older)}
    if not older and bridges['string']!=bridges['container']:
        raise ValueError('CG 本来源的字符串和容器没有共用同一完整分配桥。')
    construct=_construct_helper(raw,image,sections,container['helper_addresses']['construct_call'],older,
                                container['element_constructor_address'])
    if container['element_stride_bytes']<=max(w['field']+w['bytes']-1 for w in construct['callback_direct_element_writes']):
        raise ValueError('CG 成员构造回调写入超过了自己的元素步长。')
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=members['layout'],
        native_vm_members=members,native_member_allocation_bridges=bridges,native_member_construction=construct,
        own_member_allocator_bridges_static_bound=True,
        own_complete_member_construction_and_callback_normal_paths_static_bound=True,
        normal_member_construct_RET16_and_callback_RET0_static_bound=True,
        member_copy_helper_effects_complete=False,legacy_inline_copy_DF_and_bounds_complete=False,
        complete_member_child_and_heap_effects_bound=False,native_controller_and_vector_destructor_effects_complete=False,
        native_allocator_and_free_heap_effects_complete=False,zero_count_object_destructor_effects_complete=False,
        same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
        reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
        complete_allocation_exception_and_reentry_effects_bound=False,indirect_callers_proven_absent=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False)
