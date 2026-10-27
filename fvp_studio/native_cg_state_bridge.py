"""Native CG state interface for a NEW test executable only.

No source executable is changed by this module. The generated x86 handlers
use the target's existing native registration ABI and its own inline primitive
and motion layouts. A position-independent PE section keeps a private state
buffer; no DLL injection, global environment change or foreign address is used.
Resource objects are NOT memcpy'd: their owning loaders rebuild them before
native geometry/motion state is restored.
"""
from .engine_patterns import engine_pattern

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import re
import struct
from .hcb import parse_bytes, Syscall
from .native_import_size_discovery import _pe_sections
from .native_rotation_degrees import _code
SCHEMA = 'fvp-native-cg-state-bridge/1'
HOLD_NAME = 'FvpStudioCGStateHold1'
RESTORE_NAME = 'FvpStudioCGStateRestore1'
AUDIO_HOLD_NAME = 'FvpStudioAudioHold1'
AUDIO_RESTORE_NAME = 'FvpStudioAudioRestore1'

def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment

class _X86:

    def __init__(self, rva):
        (self.rva, self.code, self.labels, self.fixups) = (rva, bytearray(), {}, [])

    @property
    def pc(self):
        return self.rva + len(self.code)

    def put(self, data):
        self.code.extend(data)

    def u32(self, value):
        self.put(struct.pack('<I', value & 4294967295))

    def label(self, name):
        self.labels[name] = self.pc

    def rel(self, opcode, target):
        self.put(opcode)
        at = len(self.code)
        self.u32(0)
        self.fixups.append((at, target))

    def finish(self):
        for (at, target) in self.fixups:
            dest = self.labels[target] if isinstance(target, str) else target
            struct.pack_into('<i', self.code, at, dest - (self.rva + at + 4))
        return bytes(self.code)

    def module_base(self):
        self.put(engine_pattern('native_cg_state_bridge:54:17'))
        self.u32(self.pc - 3)

@dataclass(frozen=True)
class NativeCGStateBridgeImage:
    executable: bytes
    report: dict

def _parts_camera_layout(raw, entries, adjustment):
    """Read these layouts from this EXE's registered handlers, not its title.

    Parts objects own allocated pixel/string buffers. Only their scalar fields
    and the inline animation clock manager are saved. The native PartsSelect
    method rebuilds the actual expression pixels after resource reconstruction.
    """
    (image, sections) = _pe_sections(raw)

    def body(name, arity, size):
        row = entries[name]
        if row['argc'] != arity or row['remaining_fields'] != [0, 0]:
            raise ValueError('状态接口没有接入本目标的 ' + name + ' 原生参数。')
        return (row, _code(raw, image, sections, row['handler'], size)[1])
    (parts, select) = body('PartsSelect', 2, 82)
    m = re.fullmatch(engine_pattern('native_cg_state_bridge:79:8'), select, re.DOTALL)
    if m is None or not 0 < m['maximum'][0] < 128 or m['stride'][0] != 52:
        raise ValueError('尚未接入这个 FVP 版本的表情对象和动画布局。')
    u32 = lambda data: struct.unpack('<I', data)[0]
    relative = lambda key: parts['this_adjustment'] - adjustment + u32(m[key])
    target = lambda key: parts['handler'] + m.end(key) + struct.unpack('<i', m[key])[0]
    (select_address, stop_address) = (target('select'), target('stop'))
    (_, select_body) = _code(raw, image, sections, select_address, 600)
    if not re.search(engine_pattern('native_cg_state_bridge:93:22'), select_body) or not (select_body.startswith(engine_pattern('native_cg_state_bridge:94:43')) or select_body.startswith(engine_pattern('native_cg_state_bridge:95:46'))):
        raise ValueError('本目标的表情选择尚未配对到原生像素重建方法。')
    (stop, stop_body) = body('PartsMotionStop', 1, 40)
    expected = engine_pattern('native_cg_state_bridge:98:14') + m['maximum'] + engine_pattern('native_cg_state_bridge:99:14') + m['motion']
    if not stop_body.startswith(expected) or stop_body[-3:] != b'\xc2\x04\x00' or stop['this_adjustment'] != parts['this_adjustment'] or (stop['handler'] + 37 + struct.unpack_from('<i', stop_body, 33)[0] != stop_address):
        raise ValueError('本目标的表情停止入口与表情对象没有使用同一动画通道。')
    (_, leaf) = _code(raw, image, sections, stop_address, 80)
    legacy = engine_pattern('native_cg_state_bridge:107:11')
    modern = engine_pattern('native_cg_state_bridge:108:11')
    if leaf.startswith(legacy):
        (width, stride, free, count, extent) = (1, 12, 96, 104, 105)
    elif leaf == modern:
        (width, stride, free, count, extent) = (2, 16, 128, 144, 146)
    else:
        raise ValueError('尚未接入本目标的完整表情动画时钟记录。')
    channel = dict(name='parts', offset=relative('motion'), layout=dict(record_base_offset=0, record_stride=stride, record_capacity=8, active_offset=0, free_list_offset=free, counter_offset=count, counter_width=width, channel_extent=extent))
    parts_layout = dict(offset=relative('array'), stride=m['stride'][0], count=m['maximum'][0] + 1, selection_field=2, select_method_rva=select_address - image, resource_pointer_fields_excluded=True)
    regions = [dict(role='parts_selection', offset=parts_layout['offset'], bytes=4, count=parts_layout['count'], stride=parts_layout['stride']), dict(role='parts_animation', offset=channel['offset'], bytes=extent)]
    (rgb, rgb_handler) = body('PartsRGB', 4, 160)
    rgb_call = re.search(engine_pattern('native_cg_state_bridge:126:23'), rgb_handler, re.DOTALL)
    if rgb_call is None or u32(rgb_call['array']) != u32(m['array']):
        raise ValueError('本目标的表情颜色方法未配对到同一个对象。')
    (_, rgb_body) = _code(raw, image, sections, rgb['handler'] + rgb_call.end('call') + struct.unpack('<i', rgb_call['call'])[0], 400)
    if not all((re.search(engine_pattern('native_cg_state_bridge:131:25') + bytes((field,)), rgb_body) for field in (48, 49, 50))):
        raise ValueError('尚未接入本目标的表情 RGB 标量字段。')
    scalar_bytes = 3
    if 'PartsMotionPause' in entries:
        (pause, pause_body) = body('PartsMotionPause', 2, 57)
        field = re.search(engine_pattern('native_cg_state_bridge:136:24'), pause_body, re.DOTALL)
        if field is None or pause['this_adjustment'] != parts['this_adjustment'] or u32(field[1]) != u32(m['array']) + 51:
            raise ValueError('尚未接入本目标的表情动画暂停字段。')
        scalar_bytes = 4
    regions.append(dict(role='parts_rgb_pause', offset=parts_layout['offset'] + 48, bytes=scalar_bytes, count=parts_layout['count'], stride=parts_layout['stride']))
    (camera, set_body) = body('V3DSet', 3, 80)
    fields = re.findall(engine_pattern('native_cg_state_bridge:145:22'), set_body.split(b'\xc2\x04\x00', 1)[0], re.DOTALL)
    slots = [u32(field) for field in fields]
    if len(slots) != 3 or slots != list(range(slots[0], slots[0] + 12, 4)):
        raise ValueError('尚未接入本目标的原生镜头坐标。')
    (camera_stop, camera_stop_body) = body('V3DMotionStop', 0, 14)
    cm = re.fullmatch(engine_pattern('native_cg_state_bridge:150:20'), camera_stop_body, re.DOTALL)
    if cm is None:
        raise ValueError('尚未接入本目标的原生镜头动画通道。')
    (camera_motion, motion_body) = body('V3DMotion', 6, 160)
    tail = re.search(engine_pattern('native_cg_state_bridge:154:19'), motion_body, re.DOTALL)
    if tail is None or tail['offset'] != cm['offset'] or camera_motion['this_adjustment'] != camera_stop['this_adjustment']:
        raise ValueError('本目标的镜头开始和停止没有配对到同一原生动画。')
    (_, camera_start) = _code(raw, image, sections, camera_motion['handler'] + tail.end('call') + struct.unpack('<i', tail['call'])[0], 180)
    if not re.search(engine_pattern('native_cg_state_bridge:159:21'), camera_start):
        raise ValueError('尚未接入本目标的原生镜头相对时钟。')
    camera_offset = camera['this_adjustment'] - adjustment + slots[0]
    camera_motion_offset = camera_stop['this_adjustment'] - adjustment + u32(cm['offset'])
    regions.extend((dict(role='camera_xyz', offset=camera_offset, bytes=12), dict(role='camera_animation', offset=camera_motion_offset, bytes=24)))
    return (regions, channel, parts_layout, camera_motion_offset)

def build_audio_state_bridge(executable, audio_resume, *, original_volatile_globals, checkpoint_runtime=False, checkpoint_test_hooks=False):
    """The same audio retention core, without taking ownership of graphics."""
    return build_state_bridge(executable, None, None, audio_resume.catalogue, original_volatile_globals=original_volatile_globals, audio_resume=audio_resume, audio_only=True, checkpoint_runtime=checkpoint_runtime, checkpoint_test_hooks=checkpoint_test_hooks)

def build_state_bridge(executable, primitive_groups, motion_binding, catalogue, *, original_volatile_globals, audio_resume=None, audio_only=False, checkpoint_runtime=False, checkpoint_test_hooks=False):
    if checkpoint_runtime or checkpoint_test_hooks:
        raise ValueError('音频存读档实验未发布，拒绝启用。')
    'Build bytes; callers may write them only into a fresh test copy.'
    raw = bytes(executable)
    digest = hashlib.sha256(raw).hexdigest()
    if catalogue['exe_sha256'] != digest or (not audio_only and (primitive_groups['executable_sha256'] != digest or motion_binding['executable_sha256'] != digest)):
        raise ValueError('状态接口必须使用目标自身的图层、动画和注册入口。')
    if audio_only and audio_resume is None:
        raise ValueError('音频状态接口缺少目标原生续播绑定。')
    (hold_name, restore_name) = (AUDIO_HOLD_NAME, AUDIO_RESTORE_NAME) if audio_only else (HOLD_NAME, RESTORE_NAME)
    if any((name.encode() in raw for name in (HOLD_NAME, RESTORE_NAME, AUDIO_HOLD_NAME, AUDIO_RESTORE_NAME))):
        raise ValueError('这个启动程序已经带有 CG 状态接口，不重复追加。')
    nt = struct.unpack_from('<I', raw, 60)[0]
    coff = nt + 4
    (machine, number) = struct.unpack_from('<HH', raw, coff)
    optional_size = struct.unpack_from('<H', raw, coff + 16)[0]
    optional = coff + 20
    if raw[nt:nt + 4] != b'PE\x00\x00' or machine != 332 or struct.unpack_from('<H', raw, optional)[0] != 267:
        raise ValueError('CG 原生状态接口目前只接已解析的 x86 FVP。')
    image_base = struct.unpack_from('<I', raw, optional + 28)[0]
    (section_alignment, file_alignment) = struct.unpack_from('<II', raw, optional + 32)
    headers_size = struct.unpack_from('<I', raw, optional + 60)[0]
    section_table = optional + optional_size
    if not 0 < number < 96 or section_table + (number + 1) * 40 > headers_size:
        raise ValueError('启动程序没有可安全追加接口的 PE section 表空间。')
    sections = []
    for n in range(number):
        at = section_table + 40 * n
        (size, rva, raw_size, pointer) = struct.unpack_from('<IIII', raw, at + 8)
        sections.append((size, rva, raw_size, pointer))
    first_raw = min((p for (_, _, s, p) in sections if s and p))
    if section_table + (number + 1) * 40 > first_raw:
        raise ValueError('CG 接口不能覆盖原启动程序的 section 数据。')
    section_rva = _align(max((r + max(s, rs) for (s, r, rs, _) in sections)), section_alignment)
    pointer = _align(len(raw), file_alignment)
    builder = catalogue['native_registration_builder']
    entries = {row['name']: row for row in builder['entries']}
    reference = entries['AudioLoad' if audio_only else 'PrimGroupIn']
    if reference['remaining_fields'] != [0, 0]:
        raise ValueError('状态接口暂未接入此版本的特殊原生成员调用。')
    adjustment = reference['this_adjustment']
    (regions, channels, parts_layout) = ([], [], None)
    if not audio_only:
        primitive_count = primitive_groups['parent_range'][1] + 1
        stride = primitive_groups['primitive_stride']
        primitive_offset = primitive_groups['primitive_array_offset']
        regions.append(dict(role='primitive_table', offset=primitive_offset, bytes=primitive_count * stride))
        for (name, row) in motion_binding['roles'].items():
            entry = entries[row['stop']]
            relative = entry['this_adjustment'] - adjustment + row['channel_context_offset']
            layout = deepcopy(row['layout'])
            regions.append(dict(role='motion_' + name, offset=relative, bytes=layout['channel_extent']))
            channels.append(dict(name=name, offset=relative, layout=layout))
        (extra, parts_channel, parts_layout, camera_motion_offset) = _parts_camera_layout(raw, entries, adjustment)
        regions.extend(extra)
        channels.append(parts_channel)
    if any((r['offset'] < 0 or r['offset'] + r['bytes'] >= 2147483648 for r in regions)):
        raise ValueError('状态接口的本目标成员范围无效。')
    code_capacity = 16384 if audio_resume is not None else 4096
    data_rva = section_rva + code_capacity
    (owner_rva, valid_rva) = (data_rva, data_rva + 4)
    cursor = data_rva + 8
    for region in regions:
        region['buffer_rva'] = cursor
        cursor = _align(cursor + region['bytes'] * region.get('count', 1), 4)
    audio_code = None
    if audio_resume is not None:
        from .native_audio_resume import NativeAudioResumeBinding, NativeAudioResumeCode
        if not isinstance(audio_resume, NativeAudioResumeBinding):
            raise ValueError('音频续播必须使用同一目标的原生 ABI 绑定。')
        audio_resume.validate_catalogue(catalogue)
        (audio_owner_rva, audio_valid_rva) = (cursor, cursor + 4)
        cursor += 8
        audio_code = NativeAudioResumeCode(audio_resume, cursor, audio_valid_rva, owner_rva=audio_owner_rva)
        cursor = audio_code.end_rva
    persistence_code = None
    a = _X86(section_rva)
    handlers = {}
    for (operation, label) in (('hold', hold_name), ('restore', restore_name)):
        handlers[label] = a.pc
        a.label(operation)
        a.put(b'SVWU\x8b\xd9')
        a.module_base()
        if operation == 'hold':
            a.put(b'\x89\x9d')
            a.u32(owner_rva)
            a.put(b'\xc6\x85')
            a.u32(valid_rva)
            a.put(b'\x01')
            if audio_code is not None:
                audio_code.emit_hold_ownership(a)
        else:
            if audio_code is not None:
                audio_code.emit_restore_ownership(a)
            a.put(b'9\x9d')
            a.u32(owner_rva)
            a.rel(b'\x0f\x85', 'restore_done')
            a.put(b'\x80\xbd')
            a.u32(valid_rva)
            a.put(b'\x01')
            a.rel(b'\x0f\x85', 'restore_done')
        for region in regions:
            if operation == 'hold':
                a.put(b'\x8d\xb3')
                a.u32(region['offset'])
                a.put(b'\x8d\xbd')
                a.u32(region['buffer_rva'])
            else:
                a.put(b'\x8d\xb5')
                a.u32(region['buffer_rva'])
                a.put(b'\x8d\xbb')
                a.u32(region['offset'])
            if region.get('count', 1) > 1:
                a.put(b'\xba')
                a.u32(region['count'])
                a.label(operation + '_' + region['role'])
            a.put(b'\xb9')
            a.u32(region['bytes'])
            a.put(b'\xfc\xf3\xa4')
            if region.get('count', 1) > 1:
                a.put(b'\x81\xc6' if operation == 'hold' else b'\x81\xc7')
                a.u32(region['stride'] - region['bytes'])
                a.put(b'J')
                a.rel(b'\x0f\x85', operation + '_' + region['role'])
        if operation == 'hold':
            for channel in channels:
                layout = channel['layout']
                offset = channel['offset']
                a.put(b'\x8d\xb3')
                a.u32(offset + layout['record_base_offset'])
                a.put(b'\xb9')
                a.u32(layout['record_capacity'])
                a.label('clear_' + channel['name'])
                a.put(b'\xc6\x86')
                a.u32(layout['active_offset'])
                a.put(b'\x00')
                a.put(b'\x81\xc6')
                a.u32(layout['record_stride'])
                a.put(b'I')
                a.rel(b'\x0f\x85', 'clear_' + channel['name'])
                width = layout['counter_width']
                a.put(b'f\xc7\x83' if width == 2 else b'\xc6\x83')
                a.u32(offset + layout['counter_offset'])
                a.put(b'\x00\x00' if width == 2 else b'\x00')
                a.put(b'\x8d\xbb')
                a.u32(offset + layout['free_list_offset'])
                a.put(b'3\xc0\xb9')
                a.u32(layout['record_capacity'])
                a.label('free_' + channel['name'])
                a.put(b'f\xab' if width == 2 else b'\xaa')
                a.put(b'@I')
                a.rel(b'\x0f\x85', 'free_' + channel['name'])
            if not audio_only:
                a.put(b'\xc6\x83')
                a.u32(camera_motion_offset)
                a.put(b'\x00')
        elif not audio_only:
            a.put(b'\x8d\xb3')
            a.u32(parts_layout['offset'])
            a.put(b'\xbf')
            a.u32(parts_layout['count'])
            a.label('parts_pixels')
            a.put(b'\x0f\xbfF' + bytes((parts_layout['selection_field'],)) + b'\x85\xc0')
            a.rel(b'\x0f\x88', 'parts_next')
            a.put(b'=')
            a.u32(255)
            a.rel(b'\x0f\x8f', 'parts_next')
            a.put(b'P\x8b\xce')
            a.rel(b'\xe8', parts_layout['select_method_rva'])
            a.label('parts_next')
            a.put(b'\x81\xc6')
            a.u32(parts_layout['stride'])
            a.put(b'O')
            a.rel(b'\x0f\x85', 'parts_pixels')
            a.put(b'\x8d\xb3')
            a.u32(primitive_offset)
            a.put(b'\xb9')
            a.u32(primitive_count)
            a.label('dirty')
            a.put(b'\x80N' + bytes((primitive_groups['flags_field'],)) + b'@')
            a.put(b'\x83\xc6' + bytes((stride,)) + b'I')
            a.rel(b'\x0f\x85', 'dirty')
        if operation == 'restore':
            a.put(b'\xc6\x85')
            a.u32(valid_rva)
            a.put(b'\x00')
        a.label(operation + '_done')
        a.put(b']_^[\xc2\x04\x00')
    labels = {}
    for name in (hold_name, restore_name):
        labels[name] = a.pc
        a.put(name.encode('ascii') + b'\x00')
    wrapper = a.pc
    a.put(b'`')
    a.module_base()
    a.put(b'\x8b\xd9')
    for name in (hold_name, restore_name):
        a.put(b'\x83\xec\x10\x8b\xf4\x8d\x85')
        a.u32(handlers[name])
        a.put(b'\x89\x06\xc7F\x04')
        a.u32(adjustment)
        a.put(engine_pattern('native_cg_state_bridge:312:14'))
        a.put(b'j\x00\x8d\x85')
        a.u32(labels[name])
        a.put(b'P\x8d\x8b')
        a.u32(builder['native_catalogue_field'])
        a.rel(b'\xe8', reference['registrar_address'] - image_base)
    a.put(b'a')
    older = catalogue['layout'] == 'signed-word-legacy'
    head_size = 9 if older else 7
    original_head = raw[builder['offset']:builder['offset'] + head_size]
    if older and original_head[:5] != b'SVW\x8d\xb1' or (not older and original_head != b'SUVW\x83\xec\x10'):
        raise ValueError('CG 接口没有接入已解析的完整注册入口序言。')
    a.put(original_head)
    a.rel(b'\xe9', builder['address'] - image_base + head_size)
    if audio_code is not None:
        audio_code.emit(a)
    content = a.finish()
    if len(content) > code_capacity:
        raise ValueError('CG 接口代码超过保留代码页。')
    raw_size = _align(len(content), file_alignment)
    result = bytearray(raw + b'\x00' * (pointer - len(raw)) + content + b'\x00' * (raw_size - len(content)))
    at = section_table + 40 * number
    result[at:at + 40] = struct.pack('<8sIIIIIIHHI', engine_pattern('native_cg_state_bridge:332:48'), cursor - section_rva, section_rva, raw_size, pointer, 0, 0, 0, 0, 3758096416)
    struct.pack_into('<H', result, coff + 2, number + 1)
    struct.pack_into('<I', result, optional + 56, _align(cursor, section_alignment))
    struct.pack_into('<I', result, optional + 64, 0)
    struct.pack_into('<II', result, optional + 96 + 8 * 4, 0, 0)
    struct.pack_into('<I', result, optional + 4, struct.unpack_from('<I', raw, optional + 4)[0] + raw_size)
    relative = wrapper - (builder['address'] - image_base + 5)
    result[builder['offset']:builder['offset'] + head_size] = b'\xe9' + struct.pack('<i', relative) + b'\x90' * (head_size - 5)
    if audio_code is not None:
        result = bytearray(audio_code.patch_registrations(result))
    from .native_cg_system_save_compat import preserve_system_save_layout
    (result, save_compat) = preserve_system_save_layout(result, original_volatile_globals)
    report = dict(schema='fvp-native-audio-state-bridge/1' if audio_only else SCHEMA, audio_only=audio_only, source_executable_sha256=digest, output_executable_sha256=hashlib.sha256(result).hexdigest(), new_test_copy_only=True, native_interface_names=[hold_name, restore_name], native_interface_arity=0, section_rva=section_rva, section_file_offset=pointer, code_bytes=len(content), reserved_code_bytes=code_capacity, snapshot_bytes=cursor - data_rva, regions=deepcopy(regions), handlers_rva=handlers, registration_wrapper_rva=wrapper, original_registration_head_hex=original_head.hex(), original_registration_offset=builder['offset'], position_independent=True, native_motion_channels_isolated=not audio_only, original_resource_objects_copied=False, animated_parts_clock_snapshot=not audio_only, camera_native_state_snapshot=not audio_only, parts_layout=parts_layout, parts_pixel_restore_uses_original_native_select=not audio_only, original_camera_motion_isolated=not audio_only, relative_animation_elapsed_time_restored=not audio_only, primitive_runtime_values_snapshot=not audio_only, motion_runtime_records_snapshot=not audio_only, original_executable_modified=False, system_save_compatibility=save_compat, runtime_verified=False)
    if audio_code is not None:
        report['native_audio_resume'] = audio_code.report()
    return NativeCGStateBridgeImage(bytes(result), report)

def link_state_bridge(payload, thread_image, bridge, *, encoding):
    """Wire native hold/restore around the existing full-scene handoff.

The original syscall IDs stay in place. The replacement descriptor header
adds only our two names; the executable's registration extension supplies
their native handlers. Neither registration nor a native name is faked in an
unmodified original executable.
"""
    if not isinstance(bridge, NativeCGStateBridgeImage):
        raise ValueError('CG 状态接口必须同时提供测试副本的原生启动程序。')
    image = bytearray(payload)
    original_end = thread_image['scene_entry']
    header_at = struct.unpack_from('<I', image, 0)[0]
    if not 4 <= header_at < original_end <= len(image):
        raise ValueError('CG 状态接口没有对应完整场景和原生脚本头。')
    original_header = bytes(image[header_at:original_end])
    header_document = parse_bytes(struct.pack('<I', 4) + original_header, encoding)
    original_entry = header_document.header.entry_point
    names = {s.name for s in header_document.header.syscalls}
    if HOLD_NAME in names or RESTORE_NAME in names:
        raise ValueError('此场景已带有状态接口，不重复接入。')
    first = len(header_document.header.syscalls)
    if first + 1 > 32767:
        raise ValueError('CG 状态接口超出原生系统调用编号范围。')
    scene = thread_image['scene_entry']
    restore = thread_image['original_graph_journal']['restore_entry']
    adapter = thread_image['scene_return_preserver_entry']
    adapter_end = min((t['entry'] for t in thread_image['trampolines']))
    call = lambda address: b'\x02' + struct.pack('<I', address)
    sys = lambda ident: b'\x03' + struct.pack('<H', ident)
    hold_wrapper = len(image)
    image.extend(b'\x01\x00\x00' + sys(first) + call(scene) + b'\x04')
    restore_wrapper = len(image)
    image.extend(b'\x01\x00\x00' + call(restore) + sys(first + 1) + b'\x04')
    patches = []
    for (old, new) in ((scene, hold_wrapper), (restore, restore_wrapper)):
        locations = []
        start = adapter
        while True:
            at = image.find(call(old), start, adapter_end)
            if at < 0:
                break
            locations.append(at)
            start = at + 1
        if len(locations) != 1:
            raise ValueError('CG 状态接口没有唯一的场景进入／资源恢复调用。')
        at = locations[0]
        image[at:at + 5] = call(new)
        patches.append(dict(offset=at, original_target=old, new_target=new))
    for name in (HOLD_NAME, RESTORE_NAME):
        header_document.header.syscalls.append(Syscall(0, name, name.encode('ascii') + b'\x00'))
    new_header_at = len(image)
    image.extend(header_document._build_sysdesc(new_header_at, original_entry))
    struct.pack_into('<I', image, 0, new_header_at)
    report = deepcopy(bridge.report)
    report.update(script_linked=True, source_script_sha256=hashlib.sha256(payload).hexdigest(), output_script_sha256=hashlib.sha256(image).hexdigest(), native_interface_syscall_ids=[first, first + 1], hold_wrapper=hold_wrapper, restore_wrapper=restore_wrapper, adapter_patches=patches, original_syscall_ids_unchanged=True, original_script_entry_unchanged=True, original_callbacks_parked_during_native_state_handoff=True, resource_commands_replayed_before_native_state_restore=True, native_state_restored_before_renderer_frame_and_callback_release=True, requires_matching_new_test_executable=True)
    return (bytes(image), report)
