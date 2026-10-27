"""Target-bound blocking OP playback; no game-name or fixed-address ABI.

Clone the target's fullscreen wrapper, including native display, readiness/end
waits and MovieStop. Replace paths/optional input skip and isolate the cleanup
from unrelated ordinary Graph slots. Background/legacy ABIs fail closed.
"""
from copy import deepcopy
from pathlib import PurePosixPath
import struct

from .hoshimemo_scene_hook import _arguments, _call, _push_string
from .native_portrait_acceptance import _function_spans
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .native_story_hooks import reachable_native_instructions

SCHEMA = 'fvp-native-movie/1'


def _integer(ins, value=None):
    return (ins.mnemonic in ('push_i8', 'push_i16', 'push_i32')
            and (value is None or ins.operands['value'] == value))


class NativeMovieBinding:
    def __init__(self, context):
        self.context = context
        self.source, self.analysis = context.document, context.analysis_document
        self.pair = validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        table = {}
        for n, row in enumerate(self.analysis.header.syscalls):
            if row.name in table:
                raise ValueError('影片系统调用名重复。')
            table[row.name] = (n, row.args)
        for name, count in (('Movie', 2), ('MovieState', 1), ('MovieStop', 0), ('InputGetState', 0)):
            if table.get(name, (None, None))[1] != count:
                raise ValueError('此目标尚未匹配阻塞式 Movie/MovieState/MovieStop 影片接口。')
        self.table = table
        spans = {s.start: s for s in _function_spans(self.analysis)}
        candidates = []
        for span in spans.values():
            if (span.args != 2 or span.locals != 1 or span.syscalls.count('Movie') != 2
                    or span.syscalls.count('MovieStop') != 2
                    or span.syscalls.count('InputGetState') != 2):
                continue
            try:
                paths, skip, loop, ready, display = self._shape(span, spans)
            except ValueError:
                continue
            # Retain the original story invocation, not menu/default arguments.
            callers = [i.offset for s in spans.values() for n, i in enumerate(s.instructions)
                       if i.mnemonic == 'call' and i.operands['target'] == span.start and n >= 2
                       and _integer(s.instructions[n-2], 1) and _integer(s.instructions[n-1], 1)]
            if callers:
                candidates.append((span, paths, skip, loop, ready, display, callers))
        if len(candidates) != 1:
            raise ValueError('未唯一匹配原作全屏影片、结束等待与点击跳过调用链。')
        self.span, self.paths, self.skip, self.loop, self.ready, self.display, self.callers = candidates[0]
        self.spans = spans
        self.cleanup, self.cleanup_calls = self._cleanup(spans)
        self.closure = NativeScriptStateClosure(self.source, self.analysis, [self.span.start], runtime_context=context)
        reachable, reachability = reachable_native_instructions(self.analysis, self.source)
        own = {i.offset for i in self.span.instructions}
        for ins in self.analysis.instructions:
            if ins.offset in reachable and ins.mnemonic == 'syscall':
                name = self.analysis.header.syscalls[ins.operands['id']].name
                if name in ('Movie', 'MoviePlay') and ins.offset not in own:
                    raise ValueError('此目标还存在可达的非阻塞／背景影片，暂不能安全接回原剧情影片状态。')
        if not any(at in reachable for at in self.callers):
            raise ValueError('影片故事调用未从原作入口可达。')
        self.reachability = reachability
        self.suffixes = sorted({i.text.lower() for i in self.span.instructions
                                if i.mnemonic == 'push_string' and i.text.lower() in ('.wmv', '.mpg', '.mpeg', '.avi')})
        if not self.suffixes:
            raise ValueError('未确认本目标影片使用的原生文件类型。')
        self.validate()

    def _shape(self, span, spans):
        ins = span.instructions
        names = lambda i: self.analysis.header.syscalls[i.operands['id']].name if i.mnemonic == 'syscall' else None
        paths, waits = [], {}
        for n, i in enumerate(ins):
            if names(i) == 'Movie':
                if (n < 2 or ins[n-2].mnemonic != 'push_stack' or ins[n-2].operands['value'] != 0
                        or ins[n-1].mnemonic != 'push_nil'):
                    raise ValueError('影片路径和播放模式未分离。')
                paths.append(ins[n-2].offset)
            if names(i) == 'MovieState':
                tail = ins[n+1:n+8]
                if (n < 1 or not _integer(ins[n-1]) or len(tail) < 7
                        or [x.mnemonic for x in tail[:4]] != ['push_return', 'push_true', 'set_ne', 'jz']
                        or tail[4].mnemonic != 'call'):
                    raise ValueError('影片等待不是已确认的原作状态循环。')
                helper = spans.get(tail[4].operands['target'])
                if (helper is None or helper.args or helper.locals or helper.syscalls != ('ThreadNext',)
                        or helper.calls or any(x.mnemonic not in ('init_stack', 'syscall', 'ret') for x in helper.instructions)):
                    raise ValueError('影片等待没有单独让出原生帧。')
                waits.setdefault(ins[n-1].operands['value'], []).append((n, tail))
        if len(waits.get(0, ())) != 1 or len(waits.get(1, ())) != 2:
            raise ValueError('影片就绪与结束状态选择器不匹配。')
        ready_n, ready = waits[0][0]
        if ready[5].mnemonic != 'jmp' or ready[5].operands['target'] != ins[ready_n-1].offset:
            raise ValueError('影片就绪等待没有回到状态查询。')
        setup = ins[ready_n-13:ready_n-1]
        if (len(setup) != 12 or not _integer(setup[0]) or setup[1].mnemonic != 'push_nil'
                or not _integer(setup[2], 2) or setup[3].mnemonic != 'neg'
                or any(setup[i].mnemonic != 'call' for i in (4,8,11))
                or not all(_integer(setup[i]) for i in (5,6,7,9)) or not _integer(setup[10], 0)
                or len({setup[i].operands['value'] for i in (0,5,9)}) != 1
                or setup[0].operands['value'] <= 0):
            raise ValueError('影片全屏图元／画幅／根组设置未匹配。')
        create, size, group = (spans[setup[i].operands['target']] for i in (4,8,11))
        if (create.args != 3 or size.args != 3 or size.syscalls.count('PrimSetWH') != 1
                or group.args != 2 or group.syscalls.count('PrimGroupIn') != 1):
            raise ValueError('影片全屏图元辅助函数未匹配。')
        skips = []
        for n, i in enumerate(ins):
            if names(i) != 'InputGetState':
                continue
            block = ins[n:n+12]
            if ([x.mnemonic for x in block] != ['syscall','push_return','push_i8','bit_test',
                    'syscall','push_return','push_i8','bit_test','or','jz','jmp','jmp']
                    or names(block[4]) != 'InputGetState'):
                continue
            if (block[9].operands['target'] != block[11].offset
                    or not any(block[11].operands['target'] == ins[k-1].offset
                               and tail[4].offset < block[0].offset
                               and tail[3].operands['target'] == block[10].operands['target']
                               for k, tail in waits[1])):
                continue
            skips.append((block[0].offset, block[11].offset))
        if len(skips) != 1:
            raise ValueError('影片跳过边没有与原作结束清理汇合。')
        return paths, skips[0][0], skips[0][1], ins[ready_n-1].offset, setup[0].operands['value']

    def validate(self):
        self.closure.compile_snapshot(self.source)
        if self.source.original_bytes[self.span.start:self.span.end] != self.analysis.original_bytes[self.span.start:self.span.end]:
            raise ValueError('影片原生函数证据已改变。')

    def _cleanup(self, spans):
        # Movie uses the engine's special video texture, not Graph[primitive].
        # The shared original deletion helper also unloads that ordinary Graph
        # slot. Do not destroy it: the paired bridge restores primitive state,
        # while that untouched graph may belong to the inherited story/UI.
        sites, helpers, slots = [], set(), set()
        ins = self.span.instructions
        for n, item in enumerate(ins):
            if item.mnemonic != 'call' or n < 1 or not _integer(ins[n-1]):
                continue
            helper = spans[item.operands['target']]
            if helper.args != 1 or helper.locals or helper.calls or helper.syscalls != ('GraphLoad','PrimGroupOut','PrimSetNull'):
                continue
            h = helper.instructions
            if ([i.mnemonic for i in h] not in (
                    ['init_stack','push_stack','push_nil','syscall','push_stack','syscall','push_stack','syscall','ret'],
                    ['init_stack','push_stack','push_nil','syscall','push_stack','syscall','push_stack','syscall','ret','ret'])
                    or any(h[k].operands['value'] != -2 for k in (1,4,6))):
                continue
            sites.append(item.offset); helpers.add(helper.start); slots.add(ins[n-1].operands['value'])
        if len(sites) != 2 or len(helpers) != 1 or slots != {self.display}:
            raise ValueError('影片停止后的图元清理不能与普通图像资源卸载分离。')
        return spans[helpers.pop()], sites

    def assert_audio(self, native):
        """The preserved wrapper must stop the same two owned BGM channels."""
        from .native_call_flow import NativeFunctionFlow
        if native.context is not self.context or 'bgm' not in native.bindings:
            raise ValueError('影片音频与目标原生 BGM 通道未配对。')
        expected = {native.bindings['bgm']['current'], native.bindings['bgm']['previous']}
        candidates = []
        for n, ins in enumerate(self.span.instructions):
            if ins.mnemonic != 'call':
                continue
            child = self.spans[ins.operands['target']]
            if child.args != 1 or child.calls or child.syscalls != ('AudioStop', 'AudioStop'):
                continue
            if n < 1 or self.span.instructions[n-1].mnemonic != 'push_nil':
                continue
            flow = NativeFunctionFlow(self.analysis).trace(child.start, literal_arguments={0: None})
            calls = flow.get('calls', [])
            if (flow['status'] != 'proven_static_argument_flow' or len(calls) != 2
                    or any(c.get('name') != 'AudioStop' or c['arguments'][0].get('kind') != 'global_read'
                           or c['arguments'][1].get('kind') != 'literal'
                           or type(c['arguments'][1].get('value')) is not int
                           or not 0 <= c['arguments'][1]['value'] <= 6000 for c in calls)
                    or {c['arguments'][0]['slot'] for c in calls} != expected):
                continue
            candidates.append(child.start)
        if len(candidates) != 1:
            raise ValueError('影片原作音乐停止不能与已绑定的 BGM 通道唯一对应。')
        return dict(target=candidates[0], bgm_channel_globals=sorted(expected))

    def screen_sites(self, screen):
        """Match blocking wrappers through this target's proven fade roots."""
        if screen.source is not self.source:
            raise ValueError('影片与转场脚本不匹配。')
        result = {}
        for name, root in (('reveal',screen.reveal), ('colour',screen.colour)):
            helpers = []
            for span in self.spans.values():
                calls = [n for n,i in enumerate(span.instructions)
                         if i.mnemonic == 'call' and i.operands['target'] == root.start]
                if len(calls) != 1 or span.syscalls.count('DissolveWait') != 1:
                    continue
                n = calls[0]
                args = span.instructions[n-root.args:n]
                if len(args) != root.args or span.args not in (root.args,root.args-1):
                    continue
                count = span.args
                if (any(i.mnemonic != 'push_stack' or i.operands['value'] != k-count-1
                        for k,i in enumerate(args[:count]))
                        or any(i.mnemonic != 'push_nil' for i in args[count:])):
                    continue
                sites = [i.offset for i in self.span.instructions
                         if i.mnemonic == 'call' and i.operands['target'] == span.start]
                if sites:
                    helpers.append((span,sites))
            if len(helpers) != 1:
                raise ValueError('影片淡入淡出未唯一匹配当前目标的安全转场助手。')
            span, sites = helpers[0]
            result.update({name+'_args':span.args,name+'_calls':sites,name+'_original':span.start})
        return result

    def prepare(self, output, resource, skippable, *, call_overrides=None):
        self.validate()
        if (type(skippable) is not bool or not isinstance(resource, str) or not resource
                or '\\' in resource or ':' in resource or '\0' in resource
                or resource != PurePosixPath(resource).as_posix()
                or PurePosixPath(resource).is_absolute() or '..' in PurePosixPath(resource).parts
                or PurePosixPath(resource).suffix.lower() not in self.suffixes):
            raise ValueError('影片须为本目标已确认类型的相对资源路径。')
        try:
            path = _push_string(resource, self.source.encoding)
        except ValueError as exc:
            raise ValueError('影片资源路径无法写入目标脚本编码；本轮不转码。') from exc
        replacements = {at: path for at in self.paths}
        overrides = call_overrides or {}
        call_sites = {i.offset for i in self.span.instructions if i.mnemonic == 'call'}
        if (set(overrides)-call_sites or any(type(v) is not int or not 0 < v < 2**32 for v in overrides.values())):
            raise ValueError('影片转场回调不是本函数内的原生调用。')
        replacements.update({at:_call(address) for at,address in overrides.items()})
        if not skippable:
            replacements[self.skip] = b'\x06' + bytes(4)
        base = len(self.source.original_bytes)
        start = len(output)
        cleanup_code = self.cleanup.instructions[0].raw + b''.join(i.raw for i in self.cleanup.instructions[4:])
        cleanup_address = base + start + 5
        replacements.update({at:_call(cleanup_address) for at in self.cleanup_calls})
        address = cleanup_address + len(cleanup_code)
        mapping, cursor = {}, address
        for ins in self.span.instructions:
            mapping[ins.offset] = cursor
            cursor += len(replacements.get(ins.offset, ins.raw))
        if cursor >= 2**32:
            raise ValueError('影片副本超出 VM 地址范围。')
        body = bytearray()
        for ins in self.span.instructions:
            raw = replacements.get(ins.offset, ins.raw)
            if ins.offset == self.skip and not skippable:
                raw = b'\x06' + struct.pack('<I', mapping[self.loop])
            elif ins.mnemonic in ('jmp', 'jz'):
                if ins.operands['target'] not in mapping:
                    raise ValueError('影片包含跨函数跳转，不能安全复制。')
                raw = bytes((ins.opcode,)) + struct.pack('<I', mapping[ins.operands['target']])
            body.extend(raw)
        # Publish only after the complete clone has validated.
        output.extend(b'\x06' + struct.pack('<I', cursor) + cleanup_code + body)
        return address, dict(address=address, source_function=self.span.start,
            resource=resource, skippable=skippable, path_sites=list(self.paths),
            natural_end_wait_preserved=True, readiness_wait_preserved=True,
            native_failure_exit_preserved=True, native_movie_stop_preserved=True,
            cleanup_copy=cleanup_address, ordinary_graph_unload_omitted=True,
            screen_callback_sites=sorted(overrides),
            native_primitive_cleanup_preserved=True,
            timeline_duration_used_as_timeout=False, original_functions_patched=False,
            input_skip_removed=not skippable, jumps_relocated=True, runtime_verified=False)

    def report(self):
        return dict(schema=SCHEMA, source_sha256=self.source.source_sha256,
            analysis_sha256=self.analysis.source_sha256, source_function=self.span.start,
            native_video_primitive=self.display, ordinary_graph_unload_omitted=True,
            native_story_callers=self.callers, native_call_arguments=[1, 1],
            extensions=self.suffixes, runtime_binding=self.pair,
            state_dependency=self.closure.describe(), native_entry_reachability=self.reachability,
            game_name_switch_used=False, native_display_setup_preserved=True,
            bgm_policy='native_movie_wrapper', browser_playability_is_not_native_proof=True,
            same_target_original_files_only=False, registered_source_import=True,
            external_transcoding=False, decoder_compatibility_verified=False,
            requires_paired_visual_and_audio_restore=True, runtime_verified=False)

    @staticmethod
    def call(address):
        return _arguments([1, 1]) + _call(address)


class NativeMovieProgram:
    def __init__(self, target, owner, events, output, bindings, native_audio):
        if (owner is None or owner.target is not target or bindings.target is not target
                or owner.snapshot_storage.handoff.source is not target.context.document):
            raise ValueError('影片须配对同一目标的场景保存／恢复接口。')
        self.binding, self.bindings, self.output = bindings.native, bindings, output
        self.owner, self.events, self.handoff = owner, events, None
        self.audio_proof = self.binding.assert_audio(native_audio)
        capture = getattr(owner, 'audio_resume_capture', None)
        if not capture or capture['binding'] is None:
            raise ValueError('影片会使用原作音乐停止接口；此目标尚未匹配原剧情音频恢复，暂不输出。')
        snapshot = self.binding.closure.compile_snapshot(self.binding.source)
        self.snapshot = owner.snapshot_storage.reserve(snapshot, 'original_movie_script_state')
        output.extend(self.snapshot['snapshot'])
        self.helpers, self.operations = {}, []
    def prepare_helpers(self, screen, chapter, movie_scenes):
        from .native_movie_chapter import NativeMovieChapter
        self.handoff = NativeMovieChapter(self.binding,self.owner,screen,chapter,movie_scenes)
        scene_id = None
        sequences = {}
        resources = {}
        for index, event in enumerate(self.events):
            if event['kind'] == 'Scene':
                scene_id = event['scene_id']
            if event['kind'] != 'GuiMovie':
                continue
            if scene_id not in movie_scenes:
                raise ValueError('影片节拍缺少已确认的独立 OP 场景。')
            resources[index] = self.bindings.resolve(event)['target_resource']
            sequences.setdefault(scene_id, []).append(index)
        prepared = {}
        for scene_id, indexes in sequences.items():
            count = len(indexes)
            for position, index in enumerate(indexes, 1):
                event = self.events[index]
                first, last = position == 1, position == count
                # The same file may occur at either end or in the middle.
                # Its callbacks, not just its resource/skip flag, identify
                # the clone: a shared exit would fade out every clip.
                resource = resources[index]
                identity = (scene_id, resource, event['skippable'], first, last)
                if identity not in prepared:
                    prepared[identity] = self.binding.prepare(self.output, resource, event['skippable'],
                        call_overrides=self.handoff.overrides(scene_id, first=first, last=last))
                self.helpers[index] = (scene_id, position, count, prepared[identity])

    def emit(self, event, audio, *, event_index):
        self.bindings.resolve(event)
        scene_id, position, count, (address, report) = self.helpers[event_index]
        audio.claim_native_movie_bgm()
        self.output.extend(self.binding.call(address))
        self.handoff.after_movie(scene_id, last=position == count)
        self.operations.append(dict(report, duration_estimate_ms=event['duration_ms'],
                                    scene_id=scene_id, sequence_position=position, sequence_length=count,
                                    scene_entry_transition=position == 1, scene_exit_transition=position == count,
                                    estimate_controls_native_end=False))

    def finish(self):
        self.handoff.finish()
        self.output.extend(self.snapshot['restore'])

    def report(self):
        return dict(binding=self.bindings.report(), operations=deepcopy(self.operations),
            chapter_handoff=self.handoff.report(),
            audio_ownership=self.audio_proof, snapshot=deepcopy(self.snapshot['report']),
            scene_export_connected=True, original_files_modified=False, runtime_verified=False)
