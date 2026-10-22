"""Own application pump and post-start initialization, not live lifetime proof.

All explicit branches/returns, own imports and embedded-controller call
arguments are checked. Windows callbacks and child effects may change or
replace the published owner. These paths do not establish reload-before-clear
or permit public CG output; no native code is executed.
"""
import hashlib

from .native_import_size_discovery import _pe_sections
from .native_cg_vm_application import _import_slots, _writable_image_range
from .native_cg_vm_cleanup import _code
from .native_cg_vm_heap_paths import _word, _callee, _import
from .native_cg_vm_heap_allocations import _AllocationGrammar
from .native_cg_vm_heap_reallocate import bind_native_cg_vm_heap_reallocate
from .native_cg_vm_startup import _record

SCHEMA = 'fvp-native-cg-vm-lifecycle/1'


def _parent(report, schema):
    while report.get('schema') != schema:
        parents = [v for k, v in report.items() if k.startswith('native_vm_')
                   and isinstance(v, dict) and 'schema' in v]
        if len(parents) != 1:
            raise ValueError('CG 生命周期缺少唯一的同来源上层调用记录。')
        report = parents[0]
    return report


def _extent(application, capacity, table):
    instance = application['native_vm_instance']
    embedded = instance['native_parent_startup']['embedded_controller_field']
    size = application['native_application']['allocation_bytes']
    forbidden = [(embedded + table, 64),
                 (embedded + capacity['native_base'], capacity['native_stride'] * capacity['capacity'])]
    def member(field, length, controller=False):
        absolute = field + (embedded if controller else 0)
        if field < 0 or length <= 0 or absolute + length > size or any(
                max(absolute, base) < min(absolute + length, base + count) for base, count in forbidden):
            raise ValueError('CG 生命周期直接访问越过自己的对象或覆盖调用表／调度线程。')
        return dict(field=field, bytes=length, parent_field=absolute,
                    base='controller_argument' if controller else 'parent_argument')
    return member


def _run_grammar(older):
    g = _AllocationGrammar(); g.code('83ec1c')
    if older:
        g.code('55568bf133c08a86'); g.word('prepare_flag'); g.code('5750e8'); g.word('prepare_call')
        g.code('8b4e086a0551ff15'); g.word('show_api')
        g.code('8b3d'); g.word('peek_api'); g.code('8b2d'); g.word('accelerator_api')
    else:
        g.code('538b1d'); g.word('iconic_api'); g.code('558b2d'); g.word('accelerator_api')
        g.code('568bf1578b3d'); g.word('peek_api')
    g.code('c786'); g.word('run_count'); g.code('00000000c686'); g.word('run_active'); g.code('01c686')
    g.word('completed'); g.code('00'); g.mark('pump'); g.code('6a016a006a006a00')
    g.code('8d54241c52ffd785c0' if older else '8d44242050ffd785c0'); g.branch('74', 'idle')
    g.code('837c241012' if older else '837c241412'); g.branch('74', 'exit')
    g.code('8b4e108b56088d44240c505152ffd585c0' if older else '8b56148b460c8d4c2410515250ffd585c0')
    g.branch('75', 'dispatch'); g.code('8d44240c50ff15' if older else '8d4c241051ff15'); g.word('translate_api')
    g.mark('dispatch'); g.code('8d4c240c51ff15' if older else '8d54241052ff15'); g.word('dispatch_api')
    g.branch('eb', 'pump'); g.mark('idle')
    g.code('8a86' if older else '80be'); g.word('tick_enabled'); g.code('84c0' if older else '00')
    g.branch('74', 'sleep'); g.code('8d8e'); g.word('tick_controller'); g.code('e8'); g.word('tick_call')
    g.code('8a86' if older else '80be'); g.word('completed'); g.code('84c0' if older else '00')
    if older:
        g.branch('74', 'pump')
    else:
        g.branch('75', 'termination'); g.code('8b460c50ffd3'); g.branch('eb', 'pump')
        g.mark('sleep'); g.code('6a0aff15'); g.word('sleep_api'); g.branch('eb', 'pump')
        g.mark('termination'); g.code('837e7800'); g.branch('75', 'exit')
        g.code('8b4e0c8d462c5051c7002c000000ff15'); g.word('placement_api')
    g.mark('exit')
    if not older:
        g.code('8b96'); g.word('finalize_member'); g.code('8b8a'); g.word('finalize_child_field')
        g.code('e8'); g.word('finalize_call')
    g.code('8d8e'); g.word('exit_controller'); g.code('c7460800000000' if older else 'c7460c00000000')
    g.code('e8'); g.word('termination_call'); g.code('5f5e5d83c41cc3' if older else '5f5e5d5b83c41cc3')
    if older:
        # A real backward branch reaches this block AFTER the normal RET.
        g.mark('sleep'); g.code('6a0aff15'); g.word('sleep_api'); g.branch('e9', 'pump', True)
    return g


def _run(raw, image, sections, imports, application, member, older):
    address = application['native_application']['helper_addresses']['run_call']
    at, code = _code(raw, image, sections, address, 512)
    m = _run_grammar(older).match(code)
    embedded = application['native_vm_instance']['native_parent_startup']['embedded_controller_field']
    if _word(m, 'tick_controller') != embedded or _word(m, 'exit_controller') != embedded:
        raise ValueError('CG 运行循环没有更新和退出同一个内嵌控制器。')
    identities = dict(peek_api=('user32.dll', 'PeekMessageA'), accelerator_api=('user32.dll', 'TranslateAcceleratorA'),
        translate_api=('user32.dll', 'TranslateMessage'), dispatch_api=('user32.dll', 'DispatchMessageA'),
        sleep_api=('kernel32.dll', 'Sleep'))
    identities.update(dict(show_api=('user32.dll', 'ShowWindow')) if older else dict(
        iconic_api=('user32.dll', 'IsIconic'), placement_api=('user32.dll', 'GetWindowPlacement')))
    for key, (dll, name) in identities.items():
        _import(raw, image, sections, imports, m, key, name, dll)
    children = {key[:-5]: _callee(raw, image, sections, address, m, key)
                for key in m.groupdict() if key.endswith('_call')}
    ranges = [member(_word(m, key), size) for key, size in (
        ('run_count', 4), ('run_active', 1), ('completed', 1), ('tick_enabled', 1))]
    ranges.extend((member(8 if older else 12, 4), member(16 if older else 20, 4)))
    if older:
        ranges.append(member(_word(m, 'prepare_flag'), 1))
    else:
        ranges.extend((member(0x78, 4), member(0x2c, 44), member(_word(m, 'finalize_member'), 4)))
    return dict(**_record(address, at, m[0]), helper_addresses=children,
        import_calls={k:dict(address=_word(m, k), **imports[_word(m, k)]) for k in identities},
        fixed_parent_access_ranges=ranges, embedded_controller_field=embedded,
        tick_and_termination_receive_same_embedded_controller_static=True,
        empty_message_queue_only_calls_tick_when_enabled=True,
        quit_message_value=0x12, peek_removes_message=True, idle_sleep_ms=10,
        translated_accelerator_still_reaches_DispatchMessage=True,
        clear_parent_window_before_termination_child=True,
        legacy_sleep_branch_after_RET_is_bound=older,
        complete_explicit_run_loop_paths_static_bound=True,
        loop_finiteness_and_Windows_callback_effects_proven=False,
        termination_child_is_not_assumed_to_clear_call_table=True,
        remaining_child_addresses=children, child_effects_and_live_owner_aliasing_proven=False,
        native_code_executed=False)


def _post_grammar():
    g = _AllocationGrammar(); g.code('53568bf1680004000033db8d86'); g.word('buffer')
    g.code('5350e8'); g.word('fill_call'); g.code('83c40c6a01538bcec786'); g.word('buffer_word0')
    g.code('000000ffc786'); g.word('buffer_word1'); g.code('ffffffffe8'); g.word('reset_call')
    g.code('83c9ff66898e'); g.word('minus_one'); g.code('a1'); g.word('owner'); g.code('05'); g.word('parent_loop')
    g.code('b900100000'); g.mark('loop'); g.code('83caff66891083c03483e901'); g.branch('75', 'loop')
    for name in ('zero0', 'zero1', 'zero2'):
        g.code('899e'); g.word(name)
    g.code('66898e'); g.word('view_zero0'); g.code('33d2668996'); g.word('view_zero1')
    g.code('b0028886'); g.word('view_tag0'); g.code('8b0d'); g.word('owner')
    g.code('0fb75160668996'); g.word('view_width0'); g.code('8b0d'); g.word('owner')
    g.code('0fb751648886'); g.word('view_tag1'); g.code('899e'); g.word('view_zero2')
    g.code('668996'); g.word('view_height0'); g.code('c786'); g.word('view_one'); g.code('01000000')
    g.code('33c0668986'); g.word('view_zero3'); g.code('33c966898e'); g.word('view_zero4')
    g.code('8b15'); g.word('owner'); g.code('668b4260668986'); g.word('view_width1')
    g.code('8b0d'); g.word('owner'); g.code('0fb75164')
    for name in ('view_flag0', 'view_flag1', 'view_flag2'):
        g.code('889e'); g.word(name)
    g.code('899e'); g.word('view_zero5'); g.code('668996'); g.word('view_height1')
    g.code('c686'); g.word('view_minus_one'); g.code('ff5e5bc3')
    return g


def _post(raw, image, sections, application, capacity, member, fill):
    instance = application['native_vm_instance']
    address = instance['native_parent_startup']['helper_addresses']['controller_post_call']
    at, code = _code(raw, image, sections, address, 512); m = _post_grammar().match(code)
    if _word(m, 'owner') != application['native_application']['owner_global']:
        raise ValueError('CG 启动后的初始化没有读取自己程序公布的所有者。')
    owner = _writable_image_range(raw, image, sections, _word(m, 'owner'), 4)
    if (_word(m, 'buffer') != capacity['native_base'] + capacity['capacity'] * capacity['native_stride']
            or _word(m, 'buffer_word0') != _word(m, 'buffer') + 4
            or _word(m, 'buffer_word1') != _word(m, 'buffer') + 8):
        raise ValueError('CG 启动后缓存没有接在自己调度线程数组末尾。')
    children = {key[:-5]: _callee(raw, image, sections, address, m, key)
                for key in m.groupdict() if key.endswith('_call')}
    if (children['fill'] != instance['native_vm_startup']['native_startup']['helper_addresses']['clear_helper']
            or children['fill'] != fill['address']):
        raise ValueError('CG 启动后填充与自身初始化没有使用同一完整入口。')
    fixed = [member(_word(m, 'buffer'), 1024, True)]
    for key in m.groupdict():
        if key.startswith('zero') or key in ('view_zero2', 'view_zero5', 'view_one'):
            fixed.append(member(_word(m, key), 4, True))
        elif key in ('minus_one', 'view_zero0', 'view_zero1', 'view_zero3', 'view_zero4') or key.startswith(('view_width', 'view_height')):
            fixed.append(member(_word(m, key), 2, True))
        elif key.startswith(('view_tag', 'view_flag')) or key == 'view_minus_one':
            fixed.append(member(_word(m, key), 1, True))
    # This loop writes via the PUBLISHED PARENT, not via ECX/ESI. Do not
    # silently treat its owner pointer as the embedded controller argument.
    loop_base = _word(m, 'parent_loop'); member(loop_base, (4096 - 1) * 52 + 2)
    member(0x60, 2); member(0x64, 2)
    return dict(**_record(address, at, m[0]), helper_addresses=children,
        native_zero_fill=fill, fill_uses_own_complete_memory_fill_static=True,
        fixed_controller_write_ranges=fixed, published_owner_range=owner,
        published_parent_loop=dict(base_field=loop_base, iterations=4096, stride_bytes=52, write_bytes=2,
            value=0xffff, bounded_under_valid_immutable_owner_and_normal_child_ABI=True),
        published_parent_dimension_fields=[0x60, 0x64],
        direct_writes_do_not_overlap_table_or_scheduler_static=True,
        complete_explicit_post_start_initialization_paths_static_bound=True,
        published_owner_equals_parent_of_controller_unconditionally_proven=False,
        remaining_child_addresses=dict(reset=children['reset']), native_code_executed=False)


def bind_native_cg_vm_lifecycle(executable, header, vm, frames):
    raw = bytes(executable)
    parent = bind_native_cg_vm_heap_reallocate(raw, header, vm, frames)
    application = _parent(parent, 'fvp-native-cg-vm-application/1')
    thread = _parent(parent, 'fvp-native-cg-vm-thread-startup/1')
    capacity = thread['native_scheduler_capacity']
    ctor = application['native_vm_instance']['native_vm_startup']['native_controller_constructor']
    member = _extent(application, capacity, ctor['table_constructor_fields'][0])
    older = parent['layout'] == 'signed-word-legacy'
    image, sections = _pe_sections(raw); imports = _import_slots(raw, image)
    run = _run(raw, image, sections, imports, application, member, older)
    post = None
    if not older:
        allocation = _parent(parent, 'fvp-native-cg-vm-heap-allocations/1')
        post = _post(raw, image, sections, application, capacity, member,
                     allocation['native_heap_allocation_descendants']['paths']['zero_fill'])
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=parent['layout'],
        native_vm_heap_reallocate=parent, native_application_run=run,
        native_post_start_initialization=post,
        own_complete_explicit_application_run_paths_static_bound=True,
        own_modern_post_start_initialization_static_bound=not older,
        legacy_post_start_not_substituted=older,
        same_live_instance_lifetime_proven=False,
        startup_at_most_once_per_live_instance_proven=False,
        complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        initial_syscall_vector_count_zero_proven=False,
        reload_clear_before_header_append_proven=False,
        source_header_arity_to_native_descriptor_bound=False,
        complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False, runtime_verified=False,
        scene_export_connected=False, public_cg_export_enabled=False)
