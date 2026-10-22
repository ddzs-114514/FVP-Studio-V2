"""Own complete dispatch initializer and thread/main startup instruction paths.

This binds explicit native code, not a live empty-root grant. Only state and
reference counters are initialized, not every stack value/FP/PC. The later
startup restoration call may replace this state and remains a separate audit.
Native code is never executed and public CG output stays closed.
"""
import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record, _startup_pattern
from .native_cg_vm_member_copy import _Grammar as _CopyGrammar
from .native_cg_vm_heap_paths import _word, _callee
from .native_cg_vm_application import _writable_image_range
from .native_cg_vm_loader import bind_native_cg_vm_loader
from .native_cg_vm_frames import bind_native_cg_vm_frames
from .native_cg_global_storage import bind_native_cg_global_storage
from .native_cg_thread_handoff import _next_binding
from .native_cg_thread_slots import _capacity

SCHEMA = 'fvp-native-cg-vm-thread-startup/1'


class _Grammar(_CopyGrammar):
    def match(self, code):
        try:
            return super().match(code)
        except ValueError as error:
            raise ValueError('CG 线程初态的完整初始化、清理或主入口路径尚未连接。') from error


def _root_argument_iterations(raw_byte):
    """Matched signed-byte load, zero guard and 32-bit decrement, no loop run."""
    if type(raw_byte) is not int or not 0 <= raw_byte <= 255:
        raise ValueError('CG 主入口参数必须是实际的8位字节。')
    signed = raw_byte if raw_byte < 128 else raw_byte - 256
    return signed & 0xffffffff


def _initializer(raw, image, sections, address, vm):
    at, code = _code(raw, image, sections, address, 2048)
    if at != vm['initializer_offset'] or hashlib.sha256(code[:400]).hexdigest() != vm['initializer_sha256']:
        raise ValueError('CG 线程初态没有调用自己同一份原生指令表初始化器。')
    g = _Grammar()
    for index in range(40):
        g.code('c705'); g.word('slot_' + str(index)); g.word('handler_' + str(index))
    g.code('33c0b9'); g.word('default_handler'); g.branch('eb', 'loop')
    g.code('8da42400000000'); g.mark('loop')
    for index in range(21):
        g.code('8988'); g.word('type_slot_' + str(index))
    g.code('83c01c3dc4000000'); g.branch('0f8c', 'loop', wide=True)
    g.code('b8'); g.word('override_handler')
    match = g.match(code)
    opcode_rows = []
    for index in range(40):
        slot, handler = (_word(match, k + str(index)) for k in ('slot_', 'handler_'))
        if slot != vm['opcode_table'] + index * 4:
            raise ValueError('CG 原生指令表的连续写入位置发生变化。')
        _relocated(raw, image, sections, handler, executable=True)
        opcode_rows.append(dict(index=index, slot=slot, handler=handler))
    opcode_range = _writable_image_range(raw, image, sections, vm['opcode_table'], 160)
    bases = [_word(match, 'type_slot_' + str(index)) for index in range(3)]
    if len(set(bases)) != 3 or any(_word(match, 'type_slot_' + str(index)) != bases[index % 3] + 4 * (index // 3)
                                  for index in range(21)):
        raise ValueError('CG 原生类型分派没有完整初始化自己三组连续表。')
    ranges = [(base, base + 196) for base in bases] + [(vm['opcode_table'], vm['opcode_table'] + 160)]
    if any(max(a, c) < min(b, d) for index, (a, b) in enumerate(ranges) for c, d in ranges[index + 1:]):
        raise ValueError('CG 原生指令表与类型表写入区间重叠。')
    type_ranges = [_writable_image_range(raw, image, sections, base, 196) for base in bases]
    for role in ('default_handler', 'override_handler'):
        _relocated(raw, image, sections, _word(match, role), executable=True)
    cursor, overrides = match.end(), []
    # The remainder contains only ordered own-table assignments and RET. No
    # arbitrary instruction, child call or branch is ignored as padding.
    while cursor < len(code) and code[cursor] != 0xc3:
        if code[cursor:cursor + 1] == b'\xa3' and cursor + 5 <= len(code):
            slot = struct.unpack_from('<I', code, cursor + 1)[0]
            handler, size = _word(match, 'override_handler'), 5
        elif code[cursor:cursor + 2] == b'\xc7\x05' and cursor + 10 <= len(code):
            slot, handler = struct.unpack_from('<II', code, cursor + 2)
            size = 10
        else:
            raise ValueError('CG 原生类型表覆盖的完整尾部尚未绑定。')
        owners = [n for n, base in enumerate(bases) if base <= slot and slot + 4 <= base + 196 and (slot - base) % 4 == 0]
        if len(owners) != 1:
            raise ValueError('CG 原生类型表覆盖写入越过自己的有效表项。')
        _relocated(raw, image, sections, handler, executable=True)
        overrides.append(dict(table_index=owners[0], index=(slot - bases[owners[0]]) // 4, slot=slot, handler=handler))
        cursor += size
    if cursor == len(code) or not overrides:
        raise ValueError('CG 原生类型表初始化缺少完整覆盖和正常返回。')
    return dict(**_record(address, at, code[:cursor + 1]), opcode_rows=opcode_rows, opcode_range=opcode_range,
                type_table_ranges=type_ranges, type_table_bases=bases, default_handler=_word(match, 'default_handler'),
                type_table_entries_each=49, fill_iterations=7, fill_stride_bytes=28, ordered_overrides=overrides,
                full_explicit_normal_initializer_path_static_bound=True, has_no_explicit_child_calls=True,
                handler_implementation_and_concurrent_table_mutation_effects_complete=False,
                native_code_executed=False)


def _thread_init(raw, image, sections, address, older, fields, code_field):
    at, code = _code(raw, image, sections, address, 256)
    g = _Grammar(); g.code('8b4424048bd189028b80'); g.word('code_field')
    if older:
        g.code('5789420433c08982'); g.word('state'); g.code('8882'); g.word('return_value')
        g.code('8dba'); g.word('counter_one'); g.code('b940000000f3ab8dba'); g.word('counter_two')
        g.code('b980000000f3ab5fc20400')
    else:
        g.code('89420433c0568982'); g.word('state'); g.code('8882'); g.word('return_value')
        g.code('0fb7f08d4840578bc6c1e6100bc68dba'); g.word('counter_one')
        g.code('f3ab33c08dba'); g.word('counter_two'); g.code('0fb7d08bc2c1e210b9800000000bc2f3ab5f5ec20400')
    m = g.match(code)
    expected = dict(code_field=code_field, state=fields['pc'] - 20, return_value=fields['return_value'],
                    counter_one=fields['pc'] + 12, counter_two=fields['pc'] + 268)
    if any(_word(m, k) != v for k, v in expected.items()):
        raise ValueError('CG 线程初始化的脚本指针、状态和引用计数没有对应本来源调用帧。')
    return dict(**_record(address, at, m[0]), parent_pointer_field=0, code_pointer_field=4,
                parent_code_pointer_field=code_field, state_field=expected['state'], state_value=0,
                return_value_tag_field=fields['return_value'], return_value_tag=0,
                counter_ranges=[dict(field=expected['counter_one'], bytes=256, value=0),
                                dict(field=expected['counter_two'], bytes=512, value=0)],
                callee_argument_cleanup_bytes=4, has_no_explicit_calls_or_branches=True,
                direction_flag_zero_at_entry_required=True, valid_nonaliasing_thread_and_parent_memory_required=True,
                stack_values_PC_SP_FP_and_return_payload_initialized=False,
                full_explicit_normal_thread_initializer_path_static_bound=True, native_code_executed=False)


def _reset(raw, image, sections, address, older, fields, frames):
    at, code = _code(raw, image, sections, address, 256)
    g = _Grammar(); g.code('538bd9')
    if older:
        g.code('8b83'); g.word('state'); g.code('85c0')
    else:
        g.code('83bb'); g.word('state'); g.code('00')
    g.branch('74', 'return'); g.code('5657c783'); g.word('clear_state'); g.code('00000000c683')
    g.word('yield_byte'); g.code('0133ff8db3' if older else '0133f68dbb'); g.word('counter_one')
    g.mark('one_loop'); g.code('668b066685c0' if older else '0fb7076685c0'); g.branch('74', 'one_next')
    g.code('8b0b0fbfc0f7d85057e8' if older else '8b0b98f7d85056e8'); g.word('release_one_call')
    g.code('66c7060000' if older else '33c966890f'); g.mark('one_next')
    g.code('4783c60281ff80000000' if older else '4683c70281fe80000000'); g.branch('7c', 'one_loop')
    g.code('33ff8db3' if older else '33f68dbb'); g.word('counter_two')
    g.mark('two_loop'); g.code('668b066685c0' if older else '0fb7076685c0'); g.branch('74', 'two_next')
    g.code('0fbfc8f7d9518b0b57e8' if older else '8b0b0fbfd0f7da5256e8'); g.word('release_two_call')
    g.code('66c7060000' if older else '33c0668907'); g.mark('two_next')
    g.code('4783c60281ff00010000' if older else '4683c70281fe00010000'); g.branch('7c', 'two_loop')
    g.code('5f5e'); g.mark('return'); g.code('5bc3'); m = g.match(code)
    expected = dict(state=fields['pc'] - 20, clear_state=fields['pc'] - 20, yield_byte=fields['yield_byte'],
                    counter_one=fields['pc'] + 12, counter_two=fields['pc'] + 268)
    if any(_word(m, k) != v for k, v in expected.items()):
        raise ValueError('CG 主入口清理没有使用同一线程状态和引用计数区。')
    children = {n: _callee(raw, image, sections, address, m, 'release_' + n + '_call') for n in ('one', 'two')}
    if any(children[n] != frames['retained_reference_mutators'][i]['address'] for n, i in (('one', 1), ('two', 2))):
        raise ValueError('CG 主入口清理没有使用自己调用帧的同一引用计数入口。')
    return dict(**_record(address, at, m[0]), helper_addresses=children,
                state_zero_skips_all_counter_reads_and_child_calls=True, state_nonzero_clears_state_then_sets_yield=True,
                counter_iterations=[128, 256], counter_word_signed_delta_is_negated=True,
                counter_zeroed_after_normal_child_return=True, callee_argument_cleanup_bytes=0,
                children_can_mutate_or_reenter=True, complete_child_zero_count_destruction_effects_bound=False,
                full_explicit_normal_main_reset_paths_static_bound=True, native_code_executed=False)


def _main_entry(raw, image, sections, address, older, fields, frames):
    at, code = _code(raw, image, sections, address, 256)
    g = _Grammar(); g.code('568bf1e8' if older else '56578bf1e8'); g.word('reset_call')
    g.code('8b4424088b560433c9c786' if older else '8b44240c8b7e0433c9ba010000008996')
    g.word('state'); g.code('01000000' if older else '')
    g.code('8986'); g.word('pc'); g.code('898e'); g.word('sp')
    g.code('0fbe4402013bc1' if older else '0fbe4407013bc1'); g.branch('74', 'return')
    g.mark('loop')
    if older:
        g.code('8b96'); g.word('sp_read0'); g.code('884cd6088b96'); g.word('sp_read1')
        g.code('42488996'); g.word('sp_write'); g.branch('75', 'loop')
    else:
        g.code('8bbe'); g.word('sp_read0'); g.code('2bc2884cfe080196'); g.word('sp_write')
        g.code('3bc1'); g.branch('75', 'loop')
    g.mark('return'); g.code('5ec20400' if older else '5f5ec20400'); m = g.match(code)
    expected = dict(state=fields['pc'] - 20, pc=fields['pc'], sp=fields['sp'],
                    sp_read0=fields['sp'], sp_write=fields['sp'])
    if older: expected['sp_read1'] = fields['sp']
    if any(_word(m, k) != v for k, v in expected.items()):
        raise ValueError('CG 主入口初始栈写入没有使用自己同一PC/SP字段。')
    child = _callee(raw, image, sections, address, m, 'reset_call')
    reset = _reset(raw, image, sections, child, older, fields, frames)
    return dict(**_record(address, at, m[0]), native_thread_reset=reset,
                entry_SP_code_offset_argument=4, callee_argument_cleanup_bytes=4,
                PC_is_input_argument_not_advanced=True, state_set_to_one_after_reset=True,
                SP_zero_then_increments_for_each_initial_nil_argument=True,
                initial_argument_count_read_as_signed_byte_at_code_offset_plus_one=True,
                negative_argument_count_not_checked_before_32_bit_decrement_loop=True,
                initial_argument_cell_write_is_tag_only=True, initial_FP_and_stack_payload_not_written=True,
                complete_child_and_memory_bounds_effects_bound=False,
                full_explicit_normal_main_entry_paths_static_bound=True, native_code_executed=False)


def bind_native_cg_vm_thread_startup(executable, header, vm, frames):
    raw = bytes(executable)
    if frames != bind_native_cg_vm_frames(raw, vm):
        raise ValueError('CG 线程初态与自己的完整调用帧记录不一致。')
    loader = bind_native_cg_vm_loader(raw, header, vm, frames)
    application = loader['native_vm_heap_children']['native_vm_heap_paths']['native_vm_member_copy']['native_vm_member_children']['native_vm_members']['native_vm_teardown']['native_vm_cleanup']['native_vm_application']
    startup = application['native_vm_instance']['native_vm_startup']['native_startup']
    older = loader['layout'] == 'signed-word-legacy'
    image, sections = _pe_sections(raw)
    source = raw[startup['offset']:startup['offset'] + startup['code_bytes']]
    match = re.fullmatch(_startup_pattern(older), source, re.DOTALL)
    if match is None:
        raise ValueError('CG 线程初态没有完整的同来源启动调用序列。')
    storage = bind_native_cg_global_storage(raw, header, _next_binding(raw), additional_volatile=0)
    capacity = _capacity(raw, _next_binding(raw))
    if (struct.unpack('<I', match['threads'])[0] != capacity['native_base'] or capacity['native_stride'] != 0xb28
            or startup['thread_initialization_iterations'] != capacity['capacity']
            or frames['stack_capacity_cells'] != 256 or frames['stack_value_base'] != 8 or frames['stack_value_bytes'] != 8
            or vm['thread_frame_fields']['pc'] + 780 != capacity['native_stride']):
        raise ValueError('CG 线程初始化与本来源调度的数组位置、步长或数量不一致。')
    fields = vm['thread_frame_fields']
    helpers = startup['helper_addresses']
    initializer = _initializer(raw, image, sections, helpers['global_helper'], vm)
    thread = _thread_init(raw, image, sections, helpers['thread_init'], older, fields, storage['vm_fields']['parser'])
    main = _main_entry(raw, image, sections, helpers['main_entry'], older, fields, frames)
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=loader['layout'],
                native_vm_loader=loader, native_dispatch_initializer=initializer, native_thread_initializer=thread,
                native_main_entry=main, native_scheduler_capacity=capacity,
                initializers_and_main_use_own_scheduler_thread_array_static_bound=True,
                own_complete_dispatch_thread_and_main_initialization_paths_static_bound=True,
                first_main_reset_skips_reference_calls_conditional_on_valid_immutable_initialized_thread=True,
                startup_post_main_restoration_address=helpers['post_main'],
                post_main_restoration_can_replace_initial_thread_state_not_ruled_out=True,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False, initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False, source_header_arity_to_native_descriptor_bound=False,
                complete_allocation_exception_and_reentry_effects_bound=False,
                native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
