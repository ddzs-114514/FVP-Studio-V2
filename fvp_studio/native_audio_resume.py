"""Source-bound, lazy audio ownership for paired NEW test executables.

Retain original slot/decoder/DirectSound objects, not a filename/time estimate.
The native Play method is deliberately NOT a resume API (it seeks to zero).
Only the secondary buffer is resumed. The Ogg worker is cooperatively joined
and restarted without reopening/rewinding its decoder or refilling its ring.
No module here executes native code or writes a game file.
"""
from .engine_patterns import engine_pattern

from copy import deepcopy
import hashlib
import re
import struct
from .native_import_size_discovery import _pe_sections
from .native_rotation_degrees import _code, _imports
from .runtime_text_companion import _PEImage
from .native_cg_vm_syscall_catalogue import _literal_builder
SCHEMA = 'fvp-native-audio-resume/1'
MUTATORS = {prefix + suffix: argc for prefix in ('Audio', 'Sound') for (suffix, argc) in (('Load', 2), ('Play', 2 if prefix == 'Audio' else 3), ('Stop', 2), ('Type', 2), ('Vol', 3), ('SilentOn', 1))}

def _u32(raw):
    return struct.unpack('<I', raw)[0]

def _one(values, message):
    if len(values) != 1:
        raise ValueError('精确音频续播未匹配：' + message)
    return values[0]

class NativeAudioResumeBinding:
    """Conservative modern x86 ABI grammar; unmatched versions stay disabled."""

    def __init__(self, executable):
        raw = bytes(executable)
        self.sha256 = hashlib.sha256(raw).hexdigest()
        (image, sections) = _pe_sections(raw)
        self.image = image
        self.raw = raw
        self.evidence = []
        builders = []
        for (_, rva, length, pointer, flags) in sections:
            if not flags & 536870912:
                continue
            body = raw[pointer:pointer + length]
            for found in re.finditer(engine_pattern('native_audio_resume:43:37'), body):
                start = found.start()
                marker = re.search(engine_pattern('native_audio_resume:45:35'), body[start:start + 64], re.DOTALL)
                if marker is None:
                    continue
                try:
                    builder = _literal_builder(raw, image, sections, pointer + start, image + rva + start, _u32(marker[1]), False)
                except ValueError:
                    continue
                if set(MUTATORS) <= {e['name'] for e in builder['entries']}:
                    builders.append(builder)
        builder = _one(builders, '完整音频注册入口')
        self.catalogue = dict(exe_sha256=self.sha256, layout='signed-word-modern', native_registration_builder=deepcopy(builder))
        entries = {e['name']: e for e in builder['entries']}
        self.entries = {n: entries[n] for n in MUTATORS}
        for (name, argc) in MUTATORS.items():
            row = entries[name]
            if row['argc'] != argc or row['this_adjustment'] != 0 or row['remaining_fields'] != [0, 0]:
                raise ValueError('精确音频续播未匹配：' + name + ' 调用约定')
        self.literal_patches = []
        start = builder['offset']
        end = start + builder['code_bytes']
        for (name, row) in self.entries.items():
            literal = re.escape(struct.pack('<I', row['handler']))
            sites = [start + m.start() + 1 for m in re.finditer(engine_pattern('native_audio_resume:67:64') + literal, raw[start:end])]
            at = _one(sites, name + ' 唯一函数指针')
            self.literal_patches.append(dict(name=name, offset=at, original=row['handler']))
        pe = _PEImage.parse(raw)
        (reloc_rva, reloc_size) = pe.directory(5)
        relocated = set()
        cursor = 0
        while cursor < reloc_size:
            (page, size) = struct.unpack('<II', pe.read_rva(reloc_rva + cursor, 8))
            if size < 8 or size % 2 or cursor + size > reloc_size:
                raise ValueError('音频续播的 PE 重定位表无效。')
            for offset in range(8, size, 2):
                item = struct.unpack('<H', pe.read_rva(reloc_rva + cursor + offset, 2))[0]
                if item >> 12 == 3:
                    relocated.add(page + (item & 4095))
            cursor += size
        nt = _u32(raw[60:64])
        dynamic = bool(struct.unpack_from('<H', raw, nt + 24 + 70)[0] & 64)
        for row in self.literal_patches:
            section = next((s for s in sections if s[3] <= row['offset'] < s[3] + s[2]))
            if (dynamic or reloc_size) and section[1] + row['offset'] - section[3] not in relocated:
                raise ValueError('音频函数指针缺少原始 HIGHLOW 重定位，不能安全替换。')

        def code(address, count):
            (at, value) = _code(raw, image, sections, address, count)
            if len(value) != count:
                raise ValueError('精确音频续播代码被截断。')
            self.evidence.append(dict(address=address, bytes=count, sha256=hashlib.sha256(value).hexdigest()))
            return value

        def match(address, count, pattern):
            value = code(address, count)
            result = re.fullmatch(pattern, value, re.DOTALL)
            if result is None:
                raise ValueError('精确音频续播未匹配：本目标声音对象／解码器布局')
            return result

        def call(address, found, group):
            return address + found.end(group) + struct.unpack('<i', found[group])[0]
        suffix = engine_pattern('native_audio_resume:106:17')
        loads = []
        for (name, size) in (('AudioLoad', 87), ('SoundLoad', 87)):
            address = entries[name]['handler']
            body = code(address, size)
            found = _one(list(re.finditer(suffix, body, re.DOTALL)), name + ' 槽池')
            loads.append((found, call(address, found, 'load')))
        (a, s) = loads
        if a[0]['singleton'] != s[0]['singleton'] or a[0]['pool'] != s[0]['pool'] or a[1] != s[1]:
            raise ValueError('Audio 与 Sound 不是同一声音池，不能套用别名。')
        if s[0]['slot'] != b'\x8bL\xb2\x04' or a[0]['slot'][:3] != b'\x8b\x8c\xb2':
            raise ValueError('声音槽索引布局未匹配。')
        self.audio_alias = (_u32(a[0]['slot'][3:]) - 4) // 4
        if self.audio_alias != 36:
            raise ValueError('音频别名布局尚未接入。')
        sound = code(entries['SoundLoad']['handler'], 87)
        if b'\x81\xfe\xff\x00\x00\x00' not in sound or b'\x83\xfe\x03' not in code(entries['AudioLoad']['handler'], 87):
            raise ValueError('声音槽范围尚未接入。')
        self.count = 256
        self.singleton_rva = _u32(a[0]['singleton']) - image
        self.pool_offset = _u32(a[0]['pool'])
        self.slot_load = a[1] - image
        loader = match(a[1], 86, engine_pattern('native_audio_resume:128:33'))
        stop_address = call(a[1], loader, 'stop')
        stop = match(stop_address, 133, engine_pattern('native_audio_resume:130:40'))
        self.stop_backend = stop_address - image
        pattern = engine_pattern('native_audio_resume:132:18')
        loops = []
        for (_, rva, length, pointer, flags) in sections:
            if flags & 536870912:
                loops.extend(((image + rva, m) for m in re.finditer(pattern, raw[pointer:pointer + length], re.DOTALL)))
        (addr, loop) = _one(loops, '声音槽构造循环')
        self.allocate = call(addr, loop, 'allocate') - image
        ctor = call(addr, loop, 'ctor')
        self.slot_ctor = ctor - image
        ctor_call_rva = addr - image + loop.end('ctor') - 5
        ctor_section = next((s for s in sections if s[1] <= ctor_call_rva < s[1] + s[2]))
        ctor_call_offset = ctor_section[3] + ctor_call_rva - ctor_section[1]
        self.pool_ctor_call = dict(rva=ctor_call_rva, offset=ctor_call_offset, callee_rva=self.slot_ctor, original_hex=raw[ctor_call_offset:ctor_call_offset + 5].hex())
        body = code(ctor, 112)
        constructor = _one(list(re.finditer(engine_pattern('native_audio_resume:146:44'), body, re.DOTALL)), '声音槽构造字段')
        available = call(ctor, constructor, 'available')
        match(available, 11, engine_pattern('native_audio_resume:148:29'))
        allocator = call(ctor, constructor, 'allocate')
        allocate_code = code(allocator, 96)
        allocation = _one(list(re.finditer(engine_pattern('native_audio_resume:151:43'), allocate_code, re.DOTALL)), '解码器分配')
        backend_ctor = call(allocator, allocation, 'ctor')
        ctor_code = code(backend_ctor, 160)
        if engine_pattern('native_audio_resume:154:11') not in ctor_code:
            raise ValueError('声音解码器 manager/buffer/type 字段未匹配。')
        event = _one(list(re.finditer(engine_pattern('native_audio_resume:156:38'), ctor_code, re.DOTALL)), '自动复位流结束事件')
        start_pattern = engine_pattern('native_audio_resume:157:24')
        starts = []
        for (_, rva, length, pointer, flags) in sections:
            if flags & 536870912:
                starts.extend(((image + rva, m) for m in re.finditer(start_pattern, raw[pointer:pointer + length], re.DOTALL)))
        (_, stream) = _one(starts, '原生流线程入口')
        self.worker = _u32(stream['worker']) - image
        entry = match(image + self.worker, 24, engine_pattern('native_audio_resume:164:47'))
        worker = call(image + self.worker, entry, 'run')
        worker_body = match(worker, 98, engine_pattern('native_audio_resume:166:40'))
        if worker_body['wait'] != stop['wait']:
            raise ValueError('音频线程等待 API 不一致。')
        self.worker_ring = call(worker, worker_body, 'ring') - image
        self.imports = {}
        imports = _imports(raw, image)
        for (name, value) in (('SetEvent', stop['signal']), ('WaitForSingleObject', stop['wait']), ('CloseHandle', stop['close']), ('CreateThread', stream['create']), ('ExitThread', worker_body['exit']), ('CreateEventA', event['event'])):
            address = _u32(value)
            if imports.get(address) != ('kernel32.dll', name):
                raise ValueError('精确续播的线程 API 未绑定到本目标：' + name)
            self.imports[name] = address - image
        ticks = []
        tick_pattern = engine_pattern('native_audio_resume:178:23')
        for (_, rva, length, pointer, flags) in sections:
            if flags & 536870912:
                ticks.extend(((image + rva, m) for m in re.finditer(tick_pattern, raw[pointer:pointer + length], re.DOTALL)))
        (tick_base, tick_loop) = _one(ticks, '声音池时钟遍历')
        tick_address = tick_base + tick_loop.start()
        signed = call(tick_base, tick_loop, 'tick')
        signed_body = match(signed, 68, engine_pattern('native_audio_resume:185:40'))
        if call(signed, signed_body, 'stop') != stop_address:
            raise ValueError('声音淡出终止与本目标停止函数不一致。')
        self.apply_volume = call(signed, signed_body, 'volume') - image
        positive = call(signed, signed_body, 'tick')
        elapsed = code(positive, 39)
        if not re.fullmatch(engine_pattern('native_audio_resume:191:28'), elapsed, re.DOTALL):
            raise ValueError('声音淡入淡出不是相对时钟，不能原样冻结。')
        redraws = []
        redraw_pattern = b'\\xa1' + re.escape(a[0]['singleton']) + engine_pattern('native_audio_resume:194:67') + re.escape(a[0]['pool']) + engine_pattern('native_audio_resume:194:128')
        for (_, rva, length, pointer, flags) in sections:
            if flags & 536870912:
                redraws.extend(((image + rva, m) for m in re.finditer(redraw_pattern, raw[pointer:pointer + length], re.DOTALL)))
        if not any((call(address, m, 'call') == tick_address for (address, m) in redraws)):
            raise ValueError('声音池时钟没有连到本目标逐帧更新入口。')

    def validate_catalogue(self, catalogue):
        if catalogue['exe_sha256'] != self.sha256:
            raise ValueError('音频续播接口与目标 EXE 不一致。')
        entries = {e['name']: e for e in catalogue['native_registration_builder']['entries']}
        if any((entries.get(n) != e for (n, e) in self.entries.items())):
            raise ValueError('音频续播接口与完整原生注册表不一致。')

    def report(self):
        return dict(schema=SCHEMA, executable_sha256=self.sha256, physical_slots=self.count, audio_alias_first_sound_slot=self.audio_alias, lazy_first_mutation=True, unexecuted_audio_branches_untouched=True, original_objects_retained=True, original_decoder_reopened=False, original_cursor_reset=False, native_play_used_for_resume=False, relative_fade_clock_retained=True, stream_worker_cooperative_join=True, force_terminate_original_worker=False, registered_mutators=sorted(self.entries), evidence=deepcopy(self.evidence), paired_test_executable_required=True, save_load_verified=False, runtime_verified=False, persistent_checkpoint_schema='fvp-native-audio-checkpoint/1', native_save_hooks_installed=False, cross_process_restore_connected=False)

    def bind_save_pipeline(self):
        raise ValueError('跨进程音频存读档实验未包含在此发布版中。')

    def bind_checkpoint_runtime(self):
        raise ValueError('跨进程音频存读档实验未包含在此发布版中。')

class NativeAudioResumeCode:
    """Emit PI x86 helpers into the existing paired native-state section.

    Each record owns pointers, never a memcpy of an owning C++/COM object.
    Original slot objects remain in their manager's native ownership list.
    Spare slots are heap-allocated once, so normal exit while inside a test
    does not ask the native destructor to delete a static/BSS address.
    """
    RECORD_BYTES = 32

    def __init__(self, binding, base_rva, valid_rva, *, owner_rva=None):
        self.binding = binding
        self.pool_rva = base_rva
        self.error_rva = base_rva + 4
        self.records_rva = base_rva + 8
        self.end_rva = self.records_rva + self.RECORD_BYTES * binding.count
        self.valid_rva = valid_rva
        self.owner_rva = owner_rva
        self.pool_epoch_rva = None
        self.bank_epoch_rva = None
        self.wrappers = {}

    def emit_hold_ownership(self, a):
        """EBX=current native owner; EBP=module. Visual validity is separate."""
        if self.owner_rva is None:
            raise ValueError('音频所有权缺少独立的原生持有者。')
        a.put(b'\x89\x9d')
        a.u32(self.owner_rva)
        a.put(b'\xc6\x85')
        a.u32(self.valid_rva)
        a.put(b'\x01')

    def emit_restore_ownership(self, a):
        if self.owner_rva is None:
            raise ValueError('音频所有权缺少独立的原生持有者。')
        a.put(b'9\x9d')
        a.u32(self.owner_rva)
        a.rel(b'\x0f\x85', 'audio_ownership_restore_skip')
        a.put(b'\x80\xbd')
        a.u32(self.valid_rva)
        a.put(b'\x01')
        a.rel(b'\x0f\x85', 'audio_ownership_restore_skip')
        a.put(b'\xc6\x85')
        a.u32(self.valid_rva)
        a.put(b'\x00')
        a.rel(b'\xe8', 'audio_restore')
        a.label('audio_ownership_restore_skip')

    def emit(self, a):
        b = self.binding

        def iat(name):
            a.put(b'\xff\x95')
            a.u32(b.imports[name])

        def error():
            a.put(b'\xff\x85')
            a.u32(self.error_rva)

        def jump(op, label):
            a.rel(op, 'audio_' + label)

        def label(name):
            a.label('audio_' + name)

        def buffer_call(offset):
            a.put(b'\x8b\x08P\xffQ' + bytes((offset,)))
        for (name, row) in b.entries.items():
            self.wrappers[name] = a.pc
            a.put(b'`')
            a.module_base()
            a.put(b'\x80\xbd')
            a.u32(self.valid_rva)
            a.put(b'\x01')
            jump(b'\x0f\x85', name + '_pass')
            a.put(b'\x8bT$$\x80:\x02')
            jump(b'\x0f\x85', name + '_pass')
            a.put(b'\x8bB\x04=')
            a.u32(3 if name.startswith('Audio') else b.count - 1)
            jump(b'\x0f\x87', name + '_pass')
            if name.startswith('Audio'):
                a.put(b'\x83\xc0' + bytes((b.audio_alias,)))
            jump(b'\xe8', 'claim')
            a.put(b'\x85\xc0')
            jump(b'\x0f\x85', name + '_pass')
            a.put(b'a\xc2\x04\x00')
            label(name + '_pass')
            a.put(b'a')
            a.rel(b'\xe9', row['handler'] - b.image)
        label('join')
        a.put(b'\x83~\x1c\x02')
        jump(b'\x0f\x85', 'join_ok')
        a.put(b'\x83\xbeL\x03\x00\x00\x00')
        jump(b'\x0f\x84', 'join_ok')
        a.put(b'\xff\xb6P\x03\x00\x00')
        iat('SetEvent')
        a.put(b'\x85\xc0')
        jump(b'\x0f\x84', 'join_fail')
        a.put(b'h\x88\x13\x00\x00\xff\xb6L\x03\x00\x00')
        iat('WaitForSingleObject')
        a.put(b'\x85\xc0')
        jump(b'\x0f\x85', 'join_fail')
        a.put(b'\xff\xb6L\x03\x00\x00')
        iat('CloseHandle')
        a.put(b'\xc7\x86L\x03\x00\x00\x00\x00\x00\x00')
        label('join_ok')
        a.put(b'\xb8\x01\x00\x00\x00\xc3')
        label('join_fail')
        error()
        a.put(b'3\xc0\xc3')
        label('claim')
        a.put(b'SVW\x8b\xd8\xc1\xe0\x05\x8d\xbc\x05')
        a.u32(self.records_rva)
        a.put(b'\x8b\x85')
        a.u32(b.singleton_rva)
        a.put(b'\x85\xc0')
        jump(b'\x0f\x84', 'claim_fail')
        a.put(b'\x8b\x80')
        a.u32(b.pool_offset)
        a.put(b'\x85\xc0')
        jump(b'\x0f\x84', 'claim_fail')
        a.put(b'\x83\xbd')
        a.u32(self.pool_rva)
        a.put(b'\x00')
        jump(b'\x0f\x85', 'pool_known')
        a.put(b'\x89\x85')
        a.u32(self.pool_rva)
        if self.pool_epoch_rva is not None:
            a.put(b'\x8b\x95')
            a.u32(self.pool_epoch_rva)
            a.put(b'\x89\x95')
            a.u32(self.bank_epoch_rva)
        label('pool_known')
        a.put(b'9\x85')
        a.u32(self.pool_rva)
        jump(b'\x0f\x85', 'claim_fail')
        if self.pool_epoch_rva is not None:
            a.put(b'\x8b\x95')
            a.u32(self.pool_epoch_rva)
            a.put(b';\x95')
            a.u32(self.bank_epoch_rva)
            jump(b'\x0f\x85', 'claim_fail')
        a.put(b'\x8dt\x98\x04\x89w\x14\x83?\x00')
        jump(b'\x0f\x85', 'claimed')
        a.put(b'\x8b6\x85\xf6')
        jump(b'\x0f\x84', 'claim_fail')
        a.put(b'\x83\x7f\x04\x00')
        jump(b'\x0f\x85', 'spare_ready')
        a.put(b'j\x18')
        a.rel(b'\xe8', b.allocate)
        a.put(b'\x83\xc4\x04\x85\xc0')
        jump(b'\x0f\x84', 'claim_fail')
        a.put(b'3\xd2')
        for at in range(0, 24, 4):
            a.put(b'\x89P' + bytes((at,)))
        a.put(b'\xff6\x8b\xc8')
        a.rel(b'\xe8', b.slot_ctor)
        a.put(b'\x89G\x04')
        label('spare_ready')
        a.put(b'\x897\xc7G\x08\x00\x00\x00\x00\xc7G\x0c\x00\x00\x00\x00')
        a.put(b'\x8bG\x04f\x8bV\x12f\x89P\x12')
        a.put(b'\x8bN\x04\x8bP\x04\x8bA\x10\x89B\x10\x8bA\x14\x89B\x14')
        a.put(b'\x8b\xf1\x83~\x1c\x00')
        jump(b'\x0f\x84', 'swap')
        a.put(b'\x83~\x1c\x02')
        jump(b'\x0f\x87', 'claim_fail')
        a.put(b'\x8bF\x0c\x85\xc0')
        jump(b'\x0f\x84', 'claim_fail')
        a.put(b'\x8dW\x08R')
        buffer_call(36)
        a.put(b'\x85\xc0')
        jump(b'\x0f\x88', 'claim_fail')
        a.put(b'\xf6G\x08\x02')
        jump(b'\x0f\x85', 'claim_fail')
        a.put(b'\x8bF\x0c')
        buffer_call(72)
        a.put(b'\x85\xc0')
        jump(b'\x0f\x88', 'claim_fail')
        jump(b'\xe8', 'join')
        a.put(b'\x85\xc0')
        jump(b'\x0f\x84', 'claim_fail')
        label('swap')
        a.put(b'\x8bG\x04\x8bW\x14\x89\x02\xc7G\x0c\x01\x00\x00\x00')
        label('claimed')
        a.put(b'\x83\x7f\x0c\x01')
        jump(b'\x0f\x85', 'claim_fail')
        a.put(b'\x8bG\x04\x8bW\x149\x02')
        jump(b'\x0f\x85', 'claim_fail')
        a.put(b'\xb8\x01\x00\x00\x00_^[\xc3')
        label('claim_fail')
        error()
        a.put(b'3\xc0_^[\xc3')
        self.restore_rva = a.pc
        label('restore')
        a.put(b'SVW')
        a.put(b'\x8b\x85')
        a.u32(b.singleton_rva)
        a.put(b'\x85\xc0')
        jump(b'\x0f\x84', 'restore_done')
        a.put(b'\x8b\x80')
        a.u32(b.pool_offset)
        a.put(b'9\x85')
        a.u32(self.pool_rva)
        jump(b'\x0f\x85', 'restore_done')
        if self.pool_epoch_rva is not None:
            a.put(b'\x8b\x95')
            a.u32(self.pool_epoch_rva)
            a.put(b';\x95')
            a.u32(self.bank_epoch_rva)
            jump(b'\x0f\x85', 'restore_done')
        a.put(b'\x8d\xbd')
        a.u32(self.records_rva)
        a.put(b'\xbb')
        a.u32(b.count)
        label('restore_loop')
        a.put(b'\x83?\x00')
        jump(b'\x0f\x84', 'restore_next')
        a.put(b'\x8bO\x04j\x00')
        a.rel(b'\xe8', b.slot_load)
        a.put(b'\x8bG\x04\x8b@\x04\xc7@ \x00\x00\x00\x00')
        a.put(b'\x8b7\x8bW\x14\x892\x8bv\x04')
        jump(b'\xe8', 'join')
        a.put(b'\x85\xc0')
        jump(b'\x0f\x84', 'restore_clear')
        a.put(b'\xf6G\x08\x01')
        jump(b'\x0f\x84', 'restore_clear')
        a.put(b'\x83~\x1c\x02')
        jump(b'\x0f\x85', 'resume_buffer')
        a.put(b'j\x00j\x00V\x8d\x85')
        a.u32(b.worker)
        a.put(b'Pj\x00j\x00')
        iat('CreateThread')
        a.put(b'\x89\x86L\x03\x00\x00\x85\xc0')
        jump(b'\x0f\x84', 'resume_fail')
        label('resume_buffer')
        a.put(b'\x8bG\x08\xc1\xe8\x02\x83\xe0\x01Pj\x00j\x00\x8bF\x0c')
        buffer_call(48)
        a.put(b'\x85\xc0')
        jump(b'\x0f\x89', 'restore_clear')
        label('resume_fail')
        error()
        label('restore_clear')
        a.put(b'\xc7\x07\x00\x00\x00\x00\xc7G\x0c\x00\x00\x00\x00')
        label('restore_next')
        a.put(b'\x83\xc7 K')
        jump(b'\x0f\x85', 'restore_loop')
        label('restore_done')
        a.put(b'_^[\xc3')

    def patch_registrations(self, executable):
        result = bytearray(executable)
        for row in self.binding.literal_patches:
            at = row['offset']
            if _u32(result[at:at + 4]) != row['original']:
                raise ValueError('音频原生注册字面量在生成过程中发生变化。')
            struct.pack_into('<I', result, at, self.binding.image + self.wrappers[row['name']])
        return bytes(result)

    def report(self):
        return dict(self.binding.report(), native_registration_wrappers=deepcopy(self.wrappers), native_registration_patch_count=len(self.wrappers), error_counter_rva=self.error_rva, ownership_valid_rva=self.valid_rva, ownership_owner_rva=self.owner_rva, ownership_independent_of_visual_snapshot=self.owner_rva is not None, bank_bytes=self.end_rva - self.pool_rva, original_playback_restore_connected=True, resume_method='retained_secondary_buffer_and_decoder', native_error_fallback='deny_mutation_no_restart')
