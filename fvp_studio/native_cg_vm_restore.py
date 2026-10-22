"""Own complete post-main normal restore body; not a live empty-root grant.

Source bytes, every explicit branch, imports and parent-field destinations
are bound. File contents, child effects, exceptions, aliasing and reentry are
separate requirements. No native code runs and no public output is enabled.
"""
import hashlib

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated
from .native_cg_vm_cleanup import _code
from .native_cg_vm_startup import _record
from .native_cg_vm_thread_startup import bind_native_cg_vm_thread_startup
from .native_cg_vm_member_copy import _Grammar, _copy_helper
from .native_cg_vm_heap_paths import _callee, _word
from .native_cg_vm_application import _import_slots, _writable_image_range
from .native_cg_global_storage import bind_native_cg_global_storage
from .native_cg_thread_handoff import _next_binding

SCHEMA = 'fvp-native-cg-vm-restore/1'


class _RestoreGrammar(_Grammar):
    def __init__(self):
        super().__init__()
        self.operands = set()

    def operand(self, opcode, name):
        self.code(opcode)
        if name in self.operands:
            self.parts.append(b'(?P=' + name.encode() + b')')
        else:
            self.word(name)
            self.operands.add(name)

    def call(self, name):
        self.operand('e8', name + '_call')

    def match(self, code):
        try:
            return super().match(code)
        except ValueError as error:
            raise ValueError('CG 启动后的原生恢复没有完整覆盖自身的正常路径和返回。') from error


def _legacy_grammar():
    g = _RestoreGrammar(); o, e, c = g.operand, g.code, g.call
    e('6aff'); o('68', 'seh'); e('64a100000000506489250000000081ec0c010000535533ed8bd9896c2408896c240c')
    o('a1', 'owner'); o('8b80', 'filename'); e('508d4c24145189ac2424010000'); o('ff15', 'copy_api')
    o('68', 'suffix'); e('8d54241452'); o('ff15', 'append_api'); e('8d44241050'); c('exists')
    e('83c40484c0'); g.branch('0f84', 'cleanup', wide=True)
    e('56578d4c2418518d4c2414'); c('load'); e('8d542410528bcb'); c('stream')
    e('8b03'); o('8b93', 'nonvolatile'); e('896b088b08'); o('898b', 'saved_word')
    o('8b8b', 'volatile'); e('c1e1038d70048d4104894308'); o('8b83', 'buffer')
    e('8d3cd08bd1c1e902f3a58bca83e103f3a48b43088b0b0fbe0c08408943083bcd')
    o('8b0d', 'owner'); e('0f95c0'); o('8881', 'flag')
    e('8b43088b0b8d34080500000800894308b900000200'); o('8dbb', 'large_data'); e('f3a5')
    e('8b43088b0b8d34080500010000894308'); o('8dbb', 'small_data'); e('b940000000f3a5')
    o('a1', 'owner'); o('05', 'settings'); e('ba08000000'); g.branch('eb', 'record'); e('8d4900'); g.mark('record')
    for index, destination in enumerate((3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12)):
        e('8b73088b0b0fb60c0e46897308' if index < 12 else
          '8b73088b3b0fb60c3e46897308' if index != 13 else '8b3b8b73080fb60c3e46897308')
        e('8808' if destination == 0 else '8848' + bytes((destination,)).hex())
    e('83c0104a'); g.branch('0f85', 'record', wide=True); e('5f5e'); g.mark('cleanup')
    e('558d4c240cc7842420010000ffffffff'); c('destroy')
    e('8b8c24140100005d5b64890d0000000081c418010000c3')
    return g


def _modern_grammar():
    g = _RestoreGrammar(); o, e, c = g.operand, g.code, g.call
    e('6aff'); o('68', 'seh'); e('64a1000000005081ec24030000'); o('a1', 'cookie')
    e('33c48984242003000053555657'); o('a1', 'cookie')
    e('33c4508d84243803000064a300000000'); o('a1', 'owner'); e('8bd9'); o('8b88', 'filename')
    e('8d5424288d642400'); g.mark('filename_copy'); e('8a018802414284c0'); g.branch('75', 'filename_copy')
    e('8d44242883ceff03c6'); g.mark('suffix_seek'); e('8a48014084c9'); g.branch('75', 'suffix_seek')
    o('8b0d', 'suffix0'); o('668b15', 'suffix0_tail'); e('680401000089088d8c24300100005166895004568d5424345233ed5533c0556689842444010000')
    o('ff15', 'wide_api'); e('8d84242c0100006639ac242c010000'); g.branch('74', 'converted')
    g.mark('slash'); e('6683382f'); g.branch('75', 'next_character'); e('b95c000000668908')
    g.mark('next_character'); e('83c002663928'); g.branch('75', 'slash'); g.mark('converted')
    e('8d94242c0100005255'); o('ff15', 'directory_api'); o('a1', 'owner'); o('c680', 'loaded'); e('00')
    o('8b0d', 'owner'); o('8b89', 'filename'); e('8d542428'); g.mark('second_copy')
    e('8a018802414284c0'); g.branch('75', 'second_copy'); e('8d44242803c6'); g.mark('second_seek')
    e('8a48014084c9'); g.branch('75', 'second_seek'); o('8b15', 'suffix1'); o('8b0d', 'suffix1_word1')
    e('8910'); o('8b15', 'suffix1_word2'); e('894804'); o('668b0d', 'suffix1_word3')
    e('895008'); o('8a15', 'suffix1_tail'); e('6689480c88500e8d44242850'); c('exists')
    e('83c40484c0'); g.branch('0f84', 'missing', wide=True)
    e('896c2414896c2418896c241cc7442420000001008d4c2428518d4c241889ac2444030000'); c('load')
    o('8b83', 'volatile'); e('8b4c241c8b54241403c003c003c003d103c850'); o('8b83', 'nonvolatile')
    e('894c2420'); o('8b8b', 'buffer'); e('528d14c152'); c('copy0')
    e('8b4424288b4c24200fbe0c0833d24089442428'); o('a1', 'owner')
    e('83c40c3bcd0f95c2'); o('8b3d', 'metric_api'); e('6a0789507c8b4c24208b5424180fbe0411')
    o('8b15', 'owner'); e('41894c24203bc50f95c1888a80000000')
    o('8b0d', 'owner'); e('c7412c2c000000'); o('8b15', 'owner'); e('896a30')
    o('8b0d', 'owner'); e('894134'); o('8b15', 'owner'); e('897238'); o('a1', 'owner'); e('89703c')
    o('8b0d', 'owner'); e('897140'); o('8b15', 'owner'); e('897244')
    for offset in ('48', '4c'):
        e('8b4424208b4c24188b0c08'); o('8b15', 'owner'); e('83c00489442420894a' + offset)
    e('ffd7'); o('8b0d', 'owner'); e('8b51608d0442894424246a08ffd78bf06a0403f6ffd7')
    o('8b0d', 'owner'); e('8b51480341640354242403c6895150'); o('8b0d', 'owner'); e('8b514c03d0895154')
    e('8b44241c8b4c24140fbe0c084051'); o('8b0d', 'owner'); e('89442420'); c('mode')
    e('8b44241c8b5424140fbe0c10408944241c3bcd'); o('8b0d', 'owner'); e('0f95c0'); o('8881', 'flag')
    e('8b6c241c8b7424148b042e83c504896c241c'); o('8983', 'saved_word')
    e('8b042e83c504'); o('8983', 'saved_word1'); e('8d042e680000100050'); o('8d93', 'large_data')
    e('81c50000100052896c2428'); c('copy1'); e('8b44242003f581c500010000896c2428')
    o('8dbb', 'small_data'); e('b940000000f3a58b042883c40c8d4c24145183c504')
    o('8d8b', 'reader_field'); e('896c2420'); o('8983', 'reader_size'); c('reader')
    o('8b15', 'owner'); e('6a008d4c2418'); o('c682', 'loaded')
    e('01c7842444030000ffffffff'); c('destroy'); g.branch('eb', 'return'); g.mark('missing')
    o('a1', 'owner'); e('89687c'); o('8b0d', 'owner'); e('c6818000000001'); g.mark('return')
    e('8b8c243803000064890d00000000595f5e5d5b8b8c242003000033cc'); c('cookie')
    e('81c430030000c3')
    return g


def _post_main(raw, image, sections, address, older, application, startup, storage, capacity):
    at, code = _code(raw, image, sections, address, 2048)
    grammar = _legacy_grammar() if older else _modern_grammar()
    match = grammar.match(code)
    get = lambda key: _word(match, key)
    if get('owner') != application['owner_global']:
        raise ValueError('CG 启动恢复使用的共享对象不是自己的程序入口所有者。')
    owner_range = _writable_image_range(raw, image, sections, get('owner'), 4)
    _relocated(raw, image, sections, get('seh'), executable=True)
    expected = dict(nonvolatile=storage['vm_fields']['nonvolatile'], volatile=storage['vm_fields']['volatile'],
                    buffer=storage['vm_fields']['buffer'])
    writes = {r['role']: r for r in startup['direct_object_writes']}
    expected.update(saved_word=writes['size0' if not older else 'zero3']['field'],
                    large_data=writes['clear1']['field'], small_data=writes['clear0']['field'])
    if not older:
        expected.update(saved_word1=writes['size1']['field'])
    if any(get(key) != value for key, value in expected.items()):
        raise ValueError('CG 启动恢复的变量和数据区没有对应同来源加载／初始化字段。')
    allocation = application['allocation_bytes']
    parent_ranges = [(get('saved_word'), 4), (get('large_data'), 0x80000 if older else 0x100000), (get('small_data'), 256)]
    parent_ranges.append((get('flag'), 1))
    if older:
        parent_ranges.extend(((8, 4), (get('settings'), 128)))
    else:
        parent_ranges.extend(((get('saved_word1'), 4), (get('reader_size'), 4), (get('loaded'), 1),
                              (0x7c, 4), (0x80, 1), (0x2c, 44)))
        if get('reader_size') != get('reader_field') + 4 or get('reader_field') + 16 > allocation:
            raise ValueError('CG 启动恢复没有使用自身完整的原生读取器字段。')
    thread_first = capacity['native_base']; thread_last = thread_first + capacity['native_stride'] * capacity['capacity']
    if any(field < 0 or field + size > allocation or max(field, thread_first) < min(field + size, thread_last)
           for field, size in parent_ranges):
        raise ValueError('CG 启动恢复的固定对象写入越界或覆盖自身调度线程。')
    if get('filename') + 4 > allocation or get('flag') + 1 > allocation:
        raise ValueError('CG 启动恢复的文件名或配置字段越过原生对象。')
    imports = _import_slots(raw, image)
    identities = dict(copy_api=('kernel32.dll', 'lstrcpyA'), append_api=('kernel32.dll', 'lstrcatA')) if older else dict(
        wide_api=('kernel32.dll', 'MultiByteToWideChar'), metric_api=('user32.dll', 'GetSystemMetrics'))
    api_rows = {}
    for key, (dll, name) in identities.items():
        value = imports.get(get(key))
        if value != dict(dll=dll, ordinal=None, name=name):
            raise ValueError('CG 启动恢复没有调用自己确认的原生导入。')
        api_rows[key] = dict(address=get(key), **value)
    if not older:
        identity = imports.get(get('directory_api'))
        if identity != dict(dll='shell32.dll', ordinal=165, name=None):
            raise ValueError('CG 启动恢复的目录调用不属于自己同一序号导入。')
        api_rows['directory_api'] = dict(address=get('directory_api'), **identity)
        _relocated(raw, image, sections, get('cookie'), executable=False, length=4)
        if any(get(key) != get('suffix1') + displacement for key, displacement in (
                ('suffix1_word1', 4), ('suffix1_word2', 8), ('suffix1_word3', 12), ('suffix1_tail', 14))):
            raise ValueError('CG 启动恢复追加的原生文件名不是同一完整字节区。')
        if get('suffix0_tail') != get('suffix0') + 4:
            raise ValueError('CG 启动恢复的原生路径后缀不是同一完整字节区。')
    data_rows = {}
    for key, length in (('suffix', 1),) if older else (('suffix0', 6), ('suffix1', 15)):
        offset = _relocated(raw, image, sections, get(key), executable=False, length=length)
        data_rows[key] = dict(address=get(key), bytes=raw[offset:offset + length].hex())
    children = {key[:-5]: _callee(raw, image, sections, address, match, key)
                for key in match.groupdict() if key.endswith('_call')}
    if not older and children['copy0'] != children['copy1']:
        raise ValueError('CG 启动恢复两次数据复制没有使用自身同一入口。')
    return dict(**_record(address, at, match[0]), import_calls=api_rows, data_references=data_rows,
                helper_addresses=children, owner_global_range=owner_range,
                parent_fields={key: get(key) for key in expected},
                fixed_parent_write_ranges=[dict(field=field, bytes=size) for field, size in parent_ranges],
                own_complete_post_main_explicit_normal_paths_static_bound=True,
                fixed_parent_writes_do_not_overlap_own_thread_array_static_bound=True,
                restore_reader_uses_parent_prefix_not_HCB_loader_parser=older,
                own_HCB_loader_parser_field=storage['vm_fields']['parser'],
                child_effects_and_dynamic_pointer_copy_aliasing_bound=False,
                source_file_contents_and_read_bounds_proven=False, native_filename_copy_is_unbounded=True,
                same_live_parent_as_shared_owner_unconditionally_proven=False,
                SEH_and_cookie_failure_effects_bound=False, complete_final_initial_thread_state_proven=False,
                native_code_executed=False)


def bind_native_cg_vm_restore(executable, header, vm, frames):
    raw = bytes(executable)
    thread = bind_native_cg_vm_thread_startup(raw, header, vm, frames)
    application = thread['native_vm_loader']['native_vm_heap_children']['native_vm_heap_paths']['native_vm_member_copy'][
        'native_vm_member_children']['native_vm_members']['native_vm_teardown']['native_vm_cleanup']['native_vm_application']
    startup = application['native_vm_instance']['native_vm_startup']['native_startup']
    image, sections = _pe_sections(raw)
    storage = bind_native_cg_global_storage(raw, header, _next_binding(raw), additional_volatile=0)
    restore = _post_main(raw, image, sections, thread['startup_post_main_restoration_address'],
                         thread['layout'] == 'signed-word-legacy', application['native_application'], startup,
                         storage, thread['native_scheduler_capacity'])
    older = thread['layout'] == 'signed-word-legacy'
    restore['native_restore_copy_path'] = (
        dict(kind='own-complete-inline-forward-REP-instructions', owning_function_address=restore['address'],
             DF_zero_at_entry_required=True, valid_nonwrapping_memory_and_nonaliasing_stack_required=True,
             full_explicit_copy_instruction_paths_static_bound=True, complete_heap_memory_effects_bound=False)
        if older else _copy_helper(raw, image, sections, restore['helper_addresses']['copy0']))
    restore['own_complete_restore_copy_instruction_paths_static_bound'] = True
    return dict(schema=SCHEMA, exe_sha256=hashlib.sha256(raw).hexdigest(), layout=thread['layout'],
                native_vm_thread_startup=thread, native_post_main_restore=restore,
                own_complete_post_main_explicit_normal_paths_static_bound=True,
                post_main_restoration_paths_and_children_bound=False,
                complete_thread_and_root_initial_state_at_first_dispatch_proven=False,
                same_live_instance_lifetime_proven=False, initial_syscall_vector_count_zero_proven=False,
                reload_clear_before_header_append_proven=False, source_header_arity_to_native_descriptor_bound=False,
                complete_allocation_exception_and_reentry_effects_bound=False,
                native_code_executed=False, runtime_verified=False, scene_export_connected=False, public_cg_export_enabled=False)
