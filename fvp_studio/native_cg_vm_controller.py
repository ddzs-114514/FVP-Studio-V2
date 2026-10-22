"""Own complete tick/thread-step paths, not callback or reload acceptance.

The tick must use its own scheduler, published owner, timer and complete
thread gate leading into the already-bound interpreter loop. Mutable slot
indices, opaque children, file effects and opcode handlers may still reenter
or replace state. No native code runs and public CG remains closed.
"""
import hashlib

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_application import _import_slots, _writable_image_range
from .native_cg_vm_cleanup import _code
from .native_cg_vm_heap_paths import _word, _callee, _import
from .native_cg_vm_heap_allocations import _AllocationGrammar
from .native_cg_vm_lifecycle import bind_native_cg_vm_lifecycle, _parent, _extent, _run_grammar
from .native_cg_vm_startup import _record

SCHEMA = 'fvp-native-cg-vm-controller/1'
MASK = 2**32 - 1


def _signed(bits):
    return bits if bits < 2**31 else bits - 2**32


def _thread_gate_witness(state, delay, elapsed, wait_count):
    """Immutable-input arithmetic witness only; no memory or native execution."""
    if any(type(v) is not int or not 0 <= v <= MASK for v in (state, delay, elapsed, wait_count)):
        raise ValueError('CG 线程门控参数必须是实际32位位模式。')
    delay_used = bool(state & 2)
    if delay_used:
        delay = (delay - elapsed) & MASK
        if _signed(delay) <= 0:
            state &= MASK ^ 2
    wait_used = bool(state & 16)
    if wait_used and _signed(wait_count) <= 1:
        state &= MASK ^ 16
    return dict(state=state, delay=delay, delay_read=delay_used, wait_count_read=wait_used,
                executes_interpreter=state == 1, input_memory_immutable_required=True, native_code_executed=False)


def _step_grammar(older):
    g = _AllocationGrammar(); g.code('568bf18b86'); g.word('state'); g.code('a802'); g.branch('74', 'L_wait')
    g.code('8b0d'); g.word('owner'); g.code('8b91'); g.word('elapsed')
    if older:
        g.code('8b8e'); g.word('delay'); g.code('2bca85c9898e'); g.word('delay')
    else:
        g.code('2996'); g.word('delay'); g.code('83be'); g.word('delay'); g.code('00')
    g.branch('7f', 'L_wait'); g.code('83e0fd8986'); g.word('state'); g.mark('L_wait')
    g.code('8b86'); g.word('state'); g.code('a810b901000000' if older else 'b901000000a810')
    g.branch('74', 'L_test'); g.code('8b15'); g.word('owner'); g.code('398a'); g.word('wait_count')
    g.branch('7f', 'L_test'); g.code('83e0ef8986'); g.word('state'); g.mark('L_test')
    g.code('398e'); g.word('state'); g.branch('75', 'L_return'); g.code('c686'); g.word('yield_byte'); g.code('00')
    if older:
        g.code('8da42400000000')
    else:
        g.branch('eb', 'L_loop'); g.code('8da4240000000090')
    g.mark('L_loop'); g.code('8b86'); g.word('pc'); g.code('8b4e040fb60c010fb6d140')
    if older:
        g.code('8bce8986'); g.word('pc'); g.code('ff1495'); g.word('table')
        g.code('8a86'); g.word('yield_byte'); g.code('84c0')
    else:
        g.code('8986'); g.word('pc'); g.code('8b0495'); g.word('table')
        g.code('8bceffd080be'); g.word('yield_byte'); g.code('00')
    g.branch('74', 'L_loop'); g.mark('L_return'); g.code('5ec3')
    return g


def _tick_grammar(older):
    g = _AllocationGrammar()
    def word(op, name):
        g.code(op); g.word(name)
    def call(name):
        word('e8', name + '_call')
    if older:
        g.code('5153568bf1'); word('8b86', 'pending0'); g.code('33db3bc3'); g.branch('74', 'L_pending1')
        call('pending0'); word('a1', 'owner'); word('8998', 'elapsed'); g.mark('L_pending1')
        word('399e', 'pending1'); g.branch('74', 'L_begin'); g.code('8bce'); call('pending1')
        word('8b0d', 'owner'); word('8999', 'elapsed'); g.mark('L_begin')
        g.code('57'); word('ff15', 'clock_api'); word('8b0d', 'owner'); word('81c1', 'clock_member')
        g.code('8944240c'); call('clock_prepare'); word('a1', 'owner'); word('8b90', 'elapsed')
        g.code('52'); word('8d88', 'clock_sink'); call('clock_sink'); word('899e', 'current_slot')
        g.code('bf080000008d9b00000000'); g.mark('L_threads'); word('8b86', 'current_slot')
        g.code('69c0280b00008d8c30'); g.word('threads'); call('step')
        word('8b8e', 'current_slot'); g.code('418bc13bc7898e'); g.word('current_slot'); g.branch('7c', 'L_threads')
        word('8b0d', 'owner'); word('8bb9', 'elapsed'); g.code('55'); word('8d86', 'timers')
        g.code('bd10000000'); g.mark('L_timers'); g.code('3818'); g.branch('74', 'L_timer_next')
        g.code('8b480403cf8bd18948048b48083bd1'); g.branch('7e', 'L_timer_next')
        g.code('8948048818'); g.mark('L_timer_next'); g.code('83c00c4d'); g.branch('75', 'L_timers')
        word('8b15', 'owner'); word('f682', 'reverse_parent'); g.code('025d'); g.branch('75', 'L_reverse')
        word('389e', 'reverse_controller'); g.branch('74', 'L_updates'); g.mark('L_reverse')
        g.code('f7df'); word('889e', 'reverse_controller'); g.mark('L_updates')
        for index in range(8):
            g.code('57'); word('8d8e', 'actor' + str(index)); call('actor' + str(index))
        g.code('53578bce'); call('commit'); word('a1', 'owner'); word('3898', 'active'); g.code('5f')
        g.branch('74', 'L_no_clock'); word('ff15', 'clock_api'); g.code('2b442408')
        word('8b0d', 'owner'); word('8981', 'elapsed'); word('8b15', 'owner'); g.code('5e')
        word('899a', 'parent_zero'); g.code('5b59c3'); g.mark('L_no_clock')
        word('c680', 'active'); g.code('01'); word('a1', 'owner'); g.code('5e')
        word('8998', 'parent_zero'); g.code('5b59c3')
        return g
    g.code('81ec0c010000'); word('a1', 'cookie'); g.code('33c489842408010000'); word('a1', 'owner')
    g.code('568bf1'); word('8b88', 'service'); call('ready'); g.code('84c0'); g.branch('0f84', 'L_done', True)
    word('a1', 'owner'); word('8b88', 'elapsed'); g.code('5351'); word('8b88', 'clock_sink'); call('clock_sink')
    word('a1', 'owner'); word('8b88', 'service'); g.code('33db389900020000'); g.branch('74', 'L_service')
    call('service_reset0'); g.code('8bce'); call('pre_commit'); word('8b15', 'owner'); word('8b8a', 'service')
    g.code('6a01'); call('service_enable'); word('a1', 'owner'); word('8b88', 'service'); call('service_end0')
    word('a1', 'owner'); g.mark('L_service'); word('8b88', 'service'); g.code('5557389900020000')
    g.branch('0f85', 'L_stack_clock', True); word('389e', 'interrupted'); g.branch('74', 'L_clock')
    g.code('8b6c2410'); word('889e', 'interrupted'); g.branch('eb', 'L_thread_gate'); g.mark('L_clock')
    word('8d88', 'clock_member'); call('clock_prepare'); word('ff15', 'clock_api'); g.code('8be8')
    word('899e', 'current_slot'); g.mark('L_thread_gate'); word('389e', 'interrupted'); g.branch('0f85', 'L_after', True)
    g.code('bf01000000'); g.mark('L_threads'); word('8b86', 'current_slot'); g.code('83f820'); g.branch('7d', 'L_threads_end')
    word('389e', 'exclusive'); g.branch('74', 'L_step'); word('3986', 'exclusive_slot'); g.branch('75', 'L_next')
    g.mark('L_step'); g.code('69c0280b00008d8c30'); g.word('threads'); call('step')
    g.mark('L_next'); word('01be', 'current_slot'); word('389e', 'interrupted'); g.branch('74', 'L_threads')
    g.mark('L_threads_end'); word('389e', 'interrupted'); g.branch('0f85', 'L_after', True)
    g.code('bf980000008bff'); g.mark('L_parent_array'); word('8b15', 'owner'); g.code('8b0c17')
    call('parent_array'); g.code('83c70481ff18010000'); g.branch('7c', 'L_parent_array')
    word('a1', 'owner'); word('8bb8', 'elapsed'); g.code('57'); word('8d8e', 'clock_filter'); call('clock_filter')
    word('8b0d', 'owner'); word('f681', 'reverse_parent'); g.code('02'); g.branch('75', 'L_reverse')
    word('389e', 'reverse_controller'); g.branch('74', 'L_updates'); g.mark('L_reverse')
    g.code('f7df'); word('889e', 'reverse_controller'); g.mark('L_updates')
    word('8b15', 'owner'); word('389a', 'skip_actor0'); g.branch('75', 'L_actor1')
    g.code('57'); word('8d8e', 'actor0'); call('actor0'); g.mark('L_actor1')
    for index in range(1, 11):
        g.code('57'); word('8d8e', 'actor' + str(index)); call('actor' + str(index))
    word('a1', 'owner'); word('8b88', 'service'); call('service_reset1'); g.code('53578bce'); call('commit')
    word('8b0d', 'owner'); word('8b89', 'service'); call('service_end1')
    word('8b15', 'owner'); word('899a', 'parent_zero0'); word('a1', 'owner'); word('8998', 'parent_zero1')
    word('389e', 'pending0'); g.branch('74', 'L_pending1'); g.code('8bce'); word('889e', 'pending0'); call('pending0')
    word('c686', 'pending_ready'); g.code('01'); g.mark('L_pending1'); word('389e', 'pending1')
    g.branch('74', 'L_after'); word('389e', 'pending_ready'); g.branch('74', 'L_after')
    word('8b8e', 'pending_argument'); word('889e', 'pending1'); word('8b15', 'owner'); word('8b82', 'filename')
    g.code('51508d4c241c'); word('68', 'format'); g.code('51'); call('format'); g.code('83c4108d542414528bce')
    call('pending_name'); word('8b86', 'pending_argument'); g.code('508d4e14'); call('pending_value')
    g.code('8bce'); call('preserve'); word('ff15', 'clock_api'); g.code('8be8'); g.mark('L_after')
    word('a1', 'owner'); g.branch('eb', 'L_clock_finish'); g.mark('L_stack_clock'); g.code('8b6c2410')
    g.mark('L_clock_finish'); word('3898', 'active'); g.branch('74', 'L_clock_reset')
    word('ff15', 'clock_api'); word('8b0d', 'owner'); g.code('2bc5'); word('8981', 'elapsed')
    g.branch('eb', 'L_resume'); g.mark('L_clock_reset'); word('c680', 'active'); g.code('01')
    g.mark('L_resume'); g.code('5f5d'); word('389e', 'pending2'); g.branch('74', 'L_service_finish')
    g.code('8bce')
    word('889e', 'pending2'); call('pending2'); word('8b15', 'owner'); word('899a', 'elapsed')
    word('c686', 'interrupted'); g.code('01'); g.mark('L_service_finish')
    word('a1', 'owner'); word('8b88', 'service'); g.code('53'); call('service_disable'); g.code('5b')
    g.mark('L_done'); g.code('8b8c240c0100005e33cce8'); g.word('cookie_call'); g.code('81c40c010000c3')
    return g


def _step(raw, image, sections, address, older, vm, owner, elapsed, member):
    at, code = _code(raw, image, sections, address, 256); m = _step_grammar(older).match(code)
    fields = vm['thread_frame_fields']
    expected = dict(state=fields['pc'] - 20, delay=fields['pc'] - 16, pc=fields['pc'],
                    yield_byte=fields['yield_byte'], table=vm['opcode_table'], owner=owner, elapsed=elapsed)
    if any(_word(m, k) != v for k, v in expected.items()):
        raise ValueError('CG 线程门控与自己的状态字段、返回调度对象或指令表不一致。')
    if address + m.start('L_loop') != vm['interpreter_loop']['address']:
        raise ValueError('CG 线程门控没有连续进入本来源已绑定的真实解释循环。')
    member(_word(m, 'wait_count'), 4)
    return dict(**_record(address, at, m[0]), thread_state_fields={k:_word(m, k) for k in ('state', 'delay', 'pc', 'yield_byte')},
        published_owner=owner, parent_elapsed_field=elapsed, parent_wait_count_field=_word(m, 'wait_count'),
        native_interpreter_loop=vm['interpreter_loop'], interpreter_table=vm['opcode_table'],
        own_complete_thread_gate_and_interpreter_loop_static_bound=True,
        elapsed_subtraction_wraps_32_bits=True, delay_and_wait_comparisons_are_signed=True,
        interpreter_requires_state_exactly_one=True, yield_zeroed_before_first_opcode=True,
        delay_wait_flags_cleared_without_resetting_PC_SP_or_FP=True,
        opcode_value_not_range_checked_against_40_before_dispatch=True,
        actual_input_state_owner_aliasing_and_handler_reentry_proven=False, native_code_executed=False)


def bind_native_cg_vm_controller(executable, header, vm, frames):
    raw = bytes(executable); parent = bind_native_cg_vm_lifecycle(raw, header, vm, frames)
    application = _parent(parent, 'fvp-native-cg-vm-application/1')
    thread = _parent(parent, 'fvp-native-cg-vm-thread-startup/1')
    capacity = thread['native_scheduler_capacity']; instance = application['native_vm_instance']
    table = instance['native_vm_startup']['native_controller_constructor']['table_constructor_fields'][0]
    member = _extent(application, capacity, table)
    older = parent['layout'] == 'signed-word-legacy'; image, sections = _pe_sections(raw)
    address = parent['native_application_run']['helper_addresses']['tick']
    at, code = _code(raw, image, sections, address, 1024); m = _tick_grammar(older).match(code)
    run = parent['native_application_run']; r = _run_grammar(older).match(raw[run['offset']:run['offset'] + run['code_bytes']])
    owner = application['native_application']['owner_global']; elapsed = _word(r, 'run_count')
    if (_word(m, 'owner') != owner or _word(m, 'elapsed') != elapsed or _word(m, 'active') != _word(r, 'run_active')
            or _word(m, 'threads') != capacity['native_base'] or capacity['native_stride'] != 0xb28
            or capacity['capacity'] != (8 if older else 32)
            or _word(m, 'current_slot') != thread['native_vm_loader']['native_syscall_header']['native_syscall_buffer_field'] - 32):
        raise ValueError('CG 控制器更新没有使用自己的调度数组、当前槽位和公布对象。')
    imports = _import_slots(raw, image)
    _import(raw, image, sections, imports, m, 'clock_api', 'GetTickCount' if older else 'timeGetTime',
            'kernel32.dll' if older else 'winmm.dll')
    children = {k[:-5]:_callee(raw, image, sections, address, m, k) for k in m.groupdict() if k.endswith('_call')}
    step = _step(raw, image, sections, children['step'], older, vm, owner, elapsed, member)
    _writable_image_range(raw, image, sections, owner, 4)
    member(elapsed, 4); member(_word(m, 'active'), 1); member(_word(m, 'current_slot'), 4, True)
    for key in ('clock_sink', 'reverse_parent', 'clock_member'):
        member(_word(m, key), 4)
    for index in range(8 if older else 11):
        member(_word(m, 'actor' + str(index)), 4, True)
    member(_word(m, 'reverse_controller'), 1, True)
    remaining = {k:v for k,v in children.items() if k != 'step'}
    cookie = None
    if older:
        member(_word(m, 'timers'), 16 * 12, True); member(_word(m, 'parent_zero'), 4)
        for key in ('pending0', 'pending1'):
            member(_word(m, key), 4, True)
    else:
        if (children['service_reset0'] != children['service_reset1'] or children['service_end0'] != children['service_end1']
                or children['actor9'] != children['actor10'] or children['preserve'] != run['helper_addresses']['termination']):
            raise ValueError('CG 更新中的重复入口或退出保存调用没有对应本来源同一子函数。')
        error = _parent(parent, 'fvp-native-cg-vm-heap-errors/1')
        cookie = error['native_heap_error_descendants']['paths']['cookie_check']
        if children['cookie'] != cookie['address'] or _word(m, 'cookie') != cookie['static_ranges']['cookie']['address']:
            raise ValueError('CG 控制器更新的 cookie 没有使用自己已绑定的同一检查入口。')
        remaining.pop('cookie')
        for key in ('interrupted', 'exclusive', 'pending0', 'pending1', 'pending_ready', 'pending2'):
            member(_word(m, key), 1, True)
        for key in ('exclusive_slot', 'pending_argument', 'clock_filter'):
            member(_word(m, key), 4, True)
        for key in ('service', 'skip_actor0', 'filename', 'parent_zero0', 'parent_zero1'):
            member(_word(m, key), 4)
        member(0x98, 32 * 4)
        format_at = _relocated(raw, image, sections, _word(m, 'format'), executable=False, length=64)
        literal = raw[format_at:format_at + 64].split(b'\0', 1)[0]
        if len(literal) == 64:
            raise ValueError('CG 控制器更新的格式串没有自己的有界终止字节。')
    tick = dict(**_record(address, at, m[0]), helper_addresses=children, native_thread_step=step,
        published_owner=owner, parent_elapsed_field=elapsed, parent_active_field=_word(m, 'active'),
        current_slot_field=_word(m, 'current_slot'), scheduler_array=capacity,
        timer_import=dict(address=_word(m, 'clock_api'), **imports[_word(m, 'clock_api')]),
        native_cookie_check=cookie, complete_explicit_tick_paths_static_bound=True,
        thread_slot_counter_is_reread_after_opaque_child=True,
        negative_or_mutated_thread_slot_not_rejected_before_pointer_arithmetic=True,
        finite_scheduler_visit_bound_requires_immutable_index_and_normal_child_ABI=True,
        modern_interrupted_flag_short_circuits_remaining_updates=not older,
        modern_skip_branch_reads_stack_value_not_initialized_by_this_function=not older,
        legacy_timer_count=16 if older else None, actor_update_calls=8 if older else 11,
        modern_format_buffer_bytes=256 if not older else None,
        modern_filename_format_is_unbounded=not older,
        own_native_format_bytes=literal.hex() if not older else None,
        remaining_child_addresses=remaining, memory_aliasing_callback_and_file_effects_proven=False,
        native_code_executed=False)
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=parent['layout'],
        native_vm_lifecycle=parent, native_controller_tick=tick,
        own_complete_controller_tick_and_thread_gate_static_bound=True,
        same_live_instance_lifetime_proven=False,
        complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
        reload_clear_before_header_append_proven=False, initial_syscall_vector_count_zero_proven=False,
        source_header_arity_to_native_descriptor_bound=False,
        complete_exception_callback_and_reentry_effects_proven=False,
        native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
