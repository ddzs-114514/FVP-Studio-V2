"""Own full string/member-container setter paths, not heap/lifetime grants.

Every explicit normal branch is matched, including nonzero allocation/copy
paths. Child heap, construct/copy, exception/reentry and runtime ownership
effects remain conditions. Legacy inline REP copies retain the required DF
and memory bounds; external imports are identities, not implementation proofs.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_teardown import bind_native_cg_vm_teardown
from .native_cg_vm_startup import _record, _relative
from .native_cg_vm_instance import _w, _branch, _mapped
from .native_cg_vm_application import _import_slots

SCHEMA = 'fvp-native-cg-vm-members/1'


def _helpers(raw,image,sections,address,m,own_free,forbidden):
    calls = {k:_relative(address,m,k) for k in m.groupdict() if k.endswith('_call')}
    for key,target in calls.items():
        _relocated(raw,image,sections,target,executable=True)
        if target in forbidden:
            raise ValueError('CG 成员处理重新进入了清理、构造或启动函数。')
        if key.startswith('free') and target != own_free:
            raise ValueError('CG 成员处理没有使用自己程序的释放入口。')
    return calls


def _string_member(raw,image,sections,address,older,own_free,forbidden):
    at,code = _code(raw,image,sections,address,512)
    w = _w
    if older:
        p = engine_pattern('native_cg_vm_members:38:12')+w('empty')+engine_pattern('native_cg_vm_members:38:54')+w('free_call')
        p += engine_pattern('native_cg_vm_members:39:13')
        p += engine_pattern('native_cg_vm_members:40:13')+w('length_api')+engine_pattern('native_cg_vm_members:40:54')+w('allocate_call')
        p += engine_pattern('native_cg_vm_members:41:13')
        p += engine_pattern('native_cg_vm_members:42:13')
    else:
        p = engine_pattern('native_cg_vm_members:44:12')+w('empty')+engine_pattern('native_cg_vm_members:44:56')+w('free_call')
        p += engine_pattern('native_cg_vm_members:45:13')
        p += engine_pattern('native_cg_vm_members:46:13')
        p += engine_pattern('native_cg_vm_members:47:13')+w('allocate_call')
        p += engine_pattern('native_cg_vm_members:48:13')+w('copy_call')+engine_pattern('native_cg_vm_members:48:57')
    m = re.match(p,code,re.DOTALL)
    if m is None:
        raise ValueError('CG 字符串成员处理没有完整覆盖空值、长度、分配、复制和返回。')
    _branch(m,'empty_branch','input'); _branch(m,'nil_branch','return')
    if not older: _branch(m,'scan_branch','scan')
    calls = _helpers(raw,image,sections,address,m,own_free,forbidden)
    empty = struct.unpack('<I',m['empty'])[0]
    empty_at = _relocated(raw,image,sections,empty,executable=False,length=1)
    if raw[empty_at:empty_at+1] != b'\0':
        raise ValueError('CG 字符串空值指针没有连到自己映像里的空字节。')
    length_import = None
    if older:
        slot = struct.unpack('<I',m['length_api'])[0]
        _relocated(raw,image,sections,slot,executable=False,length=4)
        length_import = _import_slots(raw,image).get(slot)
        if length_import != dict(dll='kernel32.dll',ordinal=None,name='lstrlenA'):
            raise ValueError('CG 字符串长度调用没有绑定自己的 lstrlenA 导入。')
    return dict(**_record(address,at,m[0]),kind='own-string-member-setter',pointer_field=0,
        empty_sentinel_address=empty,empty_sentinel_on_disk_first_byte_zero=True,
        empty_sentinel_contents_at_this_call_proven=False,helper_addresses=calls,length_import_identity=length_import,
        argument_entry_SP_displacement=4,callee_argument_cleanup_bytes=4,
        own_previous_non_sentinel_pointer_released_before_input_test=True,
        normal_null_input_pointer_equals_empty_sentinel_conditional=True,
        concurrent_mutation_absence_required_for_return_pointer_fact=True,
        previous_pointer_can_alias_input_string_not_assumed_safe=True,
        allocation_size_expression='32-bit string length plus one',
        length_and_allocation_overflow_and_memory_bounds_proven=False,
        native_copy_kind='inline-REP-dword-and-byte' if older else 'opaque-own-three-argument-copy-helper',
        native_copy_direction_flag_zero_required=older,
        normal_child_ABI_required=dict(free_callee_cleanup_bytes=0,allocate_callee_cleanup_bytes=0,
            length_import_callee_cleanup_bytes=4 if older else None,copy_callee_cleanup_bytes=None if older else 0),
        complete_explicit_normal_setter_paths_static_bound=True,
        heap_copy_exception_and_reentry_effects_complete=False,native_code_executed=False)


def _container_pattern(older):
    w = _w
    if older:
        p = engine_pattern('native_cg_vm_members:87:12')+w('seh')+engine_pattern('native_cg_vm_members:87:54')
        p += engine_pattern('native_cg_vm_members:88:13')+w('empty_count_branch')
        p += engine_pattern('native_cg_vm_members:89:13')+w('free0_call')+engine_pattern('native_cg_vm_members:89:101')
        p += engine_pattern('native_cg_vm_members:90:13')
        p += engine_pattern('native_cg_vm_members:91:13')+w('allocate_call')
        p += engine_pattern('native_cg_vm_members:92:13')
        p += rb'\x68'+w('element_constructor')+engine_pattern('native_cg_vm_members:93:47')+w('construct_call')
        p += engine_pattern('native_cg_vm_members:94:13')
        p += engine_pattern('native_cg_vm_members:95:13')
        p += engine_pattern('native_cg_vm_members:96:13')
        p += engine_pattern('native_cg_vm_members:97:13')+w('free1_call')+engine_pattern('native_cg_vm_members:97:67')
        p += engine_pattern('native_cg_vm_members:98:13')
        p += engine_pattern('native_cg_vm_members:99:13')
    else:
        p = engine_pattern('native_cg_vm_members:101:12')+w('seh')+engine_pattern('native_cg_vm_members:101:38')+w('cookie')
        p += engine_pattern('native_cg_vm_members:102:13')
        p += engine_pattern('native_cg_vm_members:103:13')+w('empty_count_branch')
        p += engine_pattern('native_cg_vm_members:104:13')+w('free0_call')+engine_pattern('native_cg_vm_members:104:101')
        p += engine_pattern('native_cg_vm_members:105:13')
        p += engine_pattern('native_cg_vm_members:106:13')
        p += engine_pattern('native_cg_vm_members:107:13')+w('allocate_call')
        p += engine_pattern('native_cg_vm_members:108:13')
        p += rb'\x68'+w('element_constructor')+engine_pattern('native_cg_vm_members:109:47')+w('construct_call')+engine_pattern('native_cg_vm_members:109:92')
        p += engine_pattern('native_cg_vm_members:110:13')
        p += engine_pattern('native_cg_vm_members:111:13')+w('copy_call')
        p += engine_pattern('native_cg_vm_members:112:13')+w('free1_call')+engine_pattern('native_cg_vm_members:112:67')
        p += engine_pattern('native_cg_vm_members:113:13')
        p += engine_pattern('native_cg_vm_members:114:13')
    return p


def _container_member(raw,image,sections,address,older,own_free,forbidden,member_stride):
    at,code = _code(raw,image,sections,address,1024)
    m = re.match(_container_pattern(older),code,re.DOTALL)
    if m is None:
        raise ValueError('CG 容器成员处理没有完整覆盖零值、容量、分配、搬移和正常返回。')
    for key,label in (('nonzero_branch','nonzero'),('empty_count_branch','return'),
                      ('capacity_branch','return'),('nil_branch','nil'),
                      ('allocated_branch','allocated'),('no_copy_branch','no_copy')):
        _branch(m,key,label)
    if not older: _branch(m,'grow_branch','grow')
    _mapped(raw,image,sections,m,['seh','element_constructor'],True)
    if not older:
        cookie = struct.unpack('<I',m['cookie'])[0]
        _relocated(raw,image,sections,cookie,executable=False,length=4)
    calls = _helpers(raw,image,sections,address,m,own_free,forbidden)
    fields = {'capacity':0,'count':struct.unpack('<b',m['count_field'])[0],
              'buffer':struct.unpack('<b',m['buffer_field'])[0]}
    if not older: fields['growth'] = struct.unpack('<b',m['growth_field'])[0]
    if any(f<0 or f+4>member_stride for f in fields.values()):
        raise ValueError('CG 容器成员字段超出自己的清理循环步长。')
    values = list(fields.values())
    if any(max(a,b)<min(a+4,b+4) for i,a in enumerate(values) for b in values[i+1:]):
        raise ValueError('CG 容器成员的容量、数量、指针或增长字段重叠。')
    constructor = struct.unpack('<I',m['element_constructor'])[0]
    if constructor in forbidden:
        raise ValueError('CG 成员构造回调重新进入了自身控制器路径。')
    return dict(**_record(address,at,m[0]),kind='own-member-container-resize',member_fields=fields,
        member_extent_bytes=max(fields.values())+4,element_stride_bytes=12,helper_addresses=calls,
        element_constructor_address=constructor,argument_entry_SP_displacement=4,callee_argument_cleanup_bytes=4,
        zero_argument_with_zero_old_count=dict(releases_buffer=False,direct_member_writes=[]),
        zero_argument_with_nonzero_old_count=dict(own_buffer_released=True,
            direct_member_writes=[dict(field=fields['count'],value=0),dict(field=0,value=0)],buffer_pointer_cleared=False),
        normal_zero_argument_count_zero_on_return_conditional=True,
        opaque_child_preservation_of_member_fields_required_for_return_facts=True,
        concurrent_mutation_absence_required_for_return_count_fact=True,
        capacity_guard_is_signed=True,zero_count_must_not_be_treated_as_empty_buffer=True,
        nonzero_requested_capacity_guard_skips_all_member_writes=True,
        native_nonzero_capacity_policy='requested-direct' if older else 'signed-add-growth-until-enough',
        growth_loop_termination_for_all_member_states_proven=False,
        native_allocation_size_expression='requested times 12 modulo 2**32' if older else 'unsigned capacity times 12; multiply overflow encodes 0xffffffff',
        native_copy_byte_count_expression='count re-read after allocation/construct times 12 modulo 2**32',
        count_reread_after_allocation_and_construction=True,entry_count_snapshot_not_assumed=True,
        native_copy_kind='inline-REP-dword-and-byte' if older else 'opaque-own-three-argument-copy-helper',
        native_copy_direction_flag_zero_required=older,
        allocation_and_copy_bounds_and_source_aliases_proven=False,
        normal_child_ABI_required=dict(free_callee_cleanup_bytes=0,allocate_callee_cleanup_bytes=0,
            construct_callee_cleanup_bytes=16,copy_callee_cleanup_bytes=None if older else 0),
        complete_explicit_normal_setter_paths_static_bound=True,
        complete_SEH_dispatch_allocation_copy_exception_and_reentry_effects_bound=False,native_code_executed=False)


def bind_native_cg_vm_members(executable,header,vm,frames):
    raw = bytes(executable)
    image,sections = _pe_sections(raw)
    teardown = bind_native_cg_vm_teardown(raw,header,vm,frames)
    older = teardown['layout'] == 'signed-word-legacy'
    cleanup = teardown['native_vm_cleanup']; application = cleanup['native_vm_application']
    instance = application['native_vm_instance']; startup = instance['native_vm_startup']
    loops = teardown['native_pre_vector_teardown']['member_loops']
    if len(loops)!=2 or any(r['argument']!=0 for r in loops):
        raise ValueError('CG 成员清理没有自己的两个零参数调用。')
    forbidden = {r['child_address'] for r in loops} | {
        teardown['native_pre_vector_teardown']['address'],cleanup['native_controller_cleanup']['address'],
        application['native_application']['address'],instance['native_parent_constructor']['address'],
        instance['native_parent_startup']['address'],startup['native_controller_constructor']['address'],
        startup['native_startup']['address']}
    own_free = application['native_application']['helper_addresses']['free_call']
    string = _string_member(raw,image,sections,loops[0]['child_address'],older,own_free,forbidden)
    if loops[0]['stride_bytes']<4:
        raise ValueError('CG 字符串成员指针超过自己的清理循环步长。')
    container = _container_member(raw,image,sections,loops[1]['child_address'],older,own_free,forbidden,loops[1]['stride_bytes'])
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),layout=teardown['layout'],
        native_vm_teardown=teardown,native_string_member=string,native_container_member=container,
        complete_explicit_normal_pre_vector_member_setter_paths_static_bound=True,
        normal_zero_argument_setter_returns_consume_four_bytes_static_bound=True,
        own_member_direct_field_ranges_static_bound=True,normal_child_ABI_and_heap_effects_remain_conditions=True,
        complete_member_child_and_heap_effects_bound=False,native_controller_and_vector_destructor_effects_complete=False,
        native_allocator_and_free_heap_effects_complete=False,zero_count_object_destructor_effects_complete=False,
        same_live_instance_lifetime_proven=False,initial_syscall_vector_count_zero_proven=False,
        reload_clear_before_header_append_proven=False,source_header_arity_to_native_descriptor_bound=False,
        complete_allocation_exception_and_reentry_effects_bound=False,indirect_callers_proven_absent=False,
        native_code_executed=False,runtime_verified=False,scene_export_connected=False)
