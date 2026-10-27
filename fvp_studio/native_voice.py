"""Caller-bound dialogue voice, with native mute/skip and input waiting.

Only a proven dialogue loader is eligible, never a system-voice/SE helper
selected merely by a filename. Native history replay is independently bound
on demand; inherited decoder playback-position restoration is not implied.
"""
from copy import deepcopy
import hashlib
import struct

from .hoshimemo_scene_hook import _arguments, _call, _push_global, _push_string
from .native_background_backend import _literal
from .native_script_state import NativeScriptStateClosure

SCHEMA = 'fvp-native-dialogue-voice/1'


def _stack(n):
    return b'\x10' + struct.pack('<b', n)


def _pop(n):
    return b'\x16' + struct.pack('<b', n)


class NativeVoiceBackend:
    def __init__(self, audio):
        from .native_audio import _normal
        self.audio = audio
        context, spans = audio.context, audio.spans
        abi = getattr(context, 'abi', None)
        if (abi is None
                or type(getattr(abi, 'print_target', None)) is not int
                or type(getattr(abi, 'wait_target', None)) is not int):
            raise ValueError('此目标的人声需要已绑定的原生打印和等待入口。')
        self.print_split = None
        if getattr(abi, 'print_includes_wait', True):
            # Reuse the byte-proven producer/wait split, never guess where a
            # five-argument printer finishes text and begins its click wait.
            from .native_dialogue_backend import choice_prompt_abi
            abi, self.print_split = choice_prompt_abi(context)
        self.dialogue_abi = abi
        printer = spans.get(abi.print_target)
        seen = set()
        # Follow only byte-proven argument forwarding, not every callee of a
        # UI/configuration routine that happens to load voice files.
        while printer is not None and printer.start not in seen:
            seen.add(printer.start)
            body = printer.instructions
            argc = printer.args
            expected = ['init_stack'] + ['push_stack']*argc + ['call']
            if ([i.mnemonic for i in body[:argc+2]] != expected
                    or any(i.mnemonic != 'ret' for i in body[argc+2:])
                    or [i.operands['value'] for i in body[1:argc+1]] != list(range(-argc-1, -1))):
                break
            following = spans.get(body[argc+1].operands['target'])
            if following is None or following.args != argc:
                raise ValueError('台词转发参数不一致。')
            printer = following
        if printer is None or printer.args not in (3,4):
            raise ValueError('未匹配原生台词正文入口。')
        candidates = []
        for address in printer.calls:
            span = spans[address]
            if (span.args not in (2,3) or span.locals > 125
                    or 'AudioLoad' not in span.syscalls):
                continue
            try:
                row = self._bind(span, _normal)
                candidates.append(row)
            except ValueError:
                continue
        if len(candidates) != 1:
            raise ValueError('台词直接调用的人声加载器未唯一匹配；不退化成音效。')
        self.binding = row = candidates[0]
        reached, pending, sites = set(), [abi.wait_target], []
        while pending:
            address = pending.pop()
            if address in reached:
                continue
            if address not in spans or len(reached) >= 512:
                raise ValueError('人声的原生等待调用链未闭合。')
            reached.add(address)
            span = spans[address]
            pending.extend(span.calls)
            for a,b in zip(span.instructions, span.instructions[1:]):
                if (a.mnemonic == 'push_global' and a.operands['value'] == row['channel_global']
                        and b.mnemonic == 'syscall'
                        and audio.analysis.header.syscalls[b.operands['id']].name == 'AudioState'):
                    if audio.source.original_bytes[a.offset:b.offset+b.size] != a.raw+b.raw:
                        raise ValueError('人声等待指令已改变。')
                    sites.append(b.offset)
        if not sites:
            raise ValueError('原生台词等待未查询同一人声槽，不能承诺自动播放连续性。')
        row['closure'] = NativeScriptStateClosure(audio.source, audio.analysis,
            [row['span'].start], runtime_context=context)
        self.printer, self.wait_sites = printer.start, sorted(sites)
        self._backlog = None
        self._backlog_checked = False
        self._backlog_blocker = None

    def bind_backlog(self):
        if not self._backlog_checked:
            from .native_voice_backlog import NativeVoiceBacklog
            try:
                self._backlog = NativeVoiceBacklog(self)
            except ValueError as exc:
                self._backlog_blocker = str(exc)
            self._backlog_checked = True
        if self._backlog is None:
            raise ValueError(self._backlog_blocker)
        return self._backlog

    def _bind(self, span, normal):
        audio = self.audio
        if set(span.syscalls)-{'IntToText','AudioStop','AudioLoad','AudioVol','AudioPlay'}:
            raise ValueError('人声加载器还含有未接入的额外副作用。')
        if any(i.mnemonic == 'retv' for i in span.instructions):
            raise ValueError('人声加载器不是原生空返回。')
        from .native_cg_dialogue_guard import _return_inventory
        reachable, pending = set(), [span.start]
        while pending:
            at = pending.pop()
            if at in reachable:
                continue
            if at not in audio.spans or len(reachable) >= 128:
                raise ValueError('人声加载器的辅助调用未闭合。')
            reachable.add(at)
            pending.extend(audio.spans[at].calls)
        _, incoming = _return_inventory(audio.spans,reachable,set(),scope='人声')
        if incoming[span.start]:
            raise ValueError('人声加载器会读取前一个台词函数的返回值。')
        for name, argc in [('IntToText',2),('AudioStop',2),('AudioLoad',2),('AudioVol',3),('AudioPlay',2),('AudioState',1)]:
            if audio.table.get(name, (None,None))[1] != argc:
                raise ValueError('人声系统调用参数不匹配。')
        trace = audio.flow.trace(span.start,
            literal_arguments={i:None for i in range(1,span.args)},
            non_nil_arguments={0}, max_joined_values=128)
        if trace['status'] != 'proven_static_argument_flow':
            raise ValueError('人声参数流未闭合。')
        calls = [dict(c, arguments=normal(c['arguments'])) for c in trace['calls']
                 if c.get('name','').startswith('Audio')]
        loads = [c for c in calls if c['name'] == 'AudioLoad']
        plays = [c for c in calls if c['name'] == 'AudioPlay']
        vols = [c for c in calls if c['name'] == 'AudioVol']
        if (len(loads) != 1 or len(plays) != 1 or not 1 <= len(vols) <= 2
                or len(vols) == 2 and vols[0]['arguments'][1:] != [_literal(0),_literal(None)]):
            raise ValueError('人声加载、音量、播放没有唯一对应。')
        channel = loads[0]['arguments'][0]
        if channel.get('kind') != 'global_read' or any(c['arguments'][0] != channel for c in calls):
            raise ValueError('人声没有使用同一个目标原生槽。')
        path = loads[0]['arguments'][1]
        if path.get('kind') != 'add' or len(path.get('operands', ())) != 2:
            raise ValueError('人声原生路径不是已知的编号路径。')
        prefix, suffix = path['operands']
        if (prefix.get('kind') != 'literal' or prefix.get('value','').lower() not in ('voice/','voice2/')
                or suffix.get('kind') != 'call_return' or suffix.get('call_kind') != 'syscall'
                or suffix.get('target') != 'IntToText' or len(suffix.get('arguments', ())) != 2
                or not self._number_from_voice_argument(suffix['arguments'][0])
                or suffix['arguments'][1].get('type') != 'int'
                or not 1 <= suffix['arguments'][1]['value'] <= 10
                or plays[0]['arguments'][1] != _literal(None)):
            raise ValueError('人声路径或非循环参数未证明。')
        return dict(span=span, slots=[], channel_global=channel['slot'], category=None,
            routes={prefix['value'].rstrip('/').lower()+'.bin':prefix['value']},
            load_offset=loads[0]['offset'], volume_offset=vols[-1]['offset'],
            numbering_width=suffix['arguments'][1]['value'])

    @staticmethod
    def _number_from_voice_argument(value):
        # Character-dependent variant lookup may add a value to the selected
        # voice ID. Retain that source logic; replace only the final filepath.
        if value == dict(kind='argument',index=0):
            return True
        if value.get('kind') == 'choice':
            parts = value.get('operands', [])
            return bool(parts) and all(NativeVoiceBackend._number_from_voice_argument(v) for v in parts)
        if value.get('kind') == 'add':
            parts = value.get('operands', [])
            return len(parts) == 2 and parts[0] == dict(kind='argument',index=0) and parts[1].get('kind') == 'call_return'
        return False

    def prepare(self, output):
        row = self.binding
        row['closure'].compile_snapshot(self.audio.source)
        span = row['span']
        address = len(self.audio.source.original_bytes) + len(output) + 5
        argc = span.args + 2
        code = bytearray(bytes((1,argc,span.locals+2)))
        mapping = {span.start:address}
        jumps = []
        for ins in span.instructions[1:]:
            mapping[ins.offset] = address + len(code)
            if ins.offset == row['load_offset']:
                code.extend(_pop(span.locals) + _stack(-argc-1))
            if ins.offset == row['volume_offset']:
                code.extend(_pop(span.locals+1)+_pop(span.locals)+_stack(-argc)+_stack(span.locals+1))
            if ins.mnemonic in ('jmp','jz'):
                jumps.append((len(code)+1,ins.operands['target']))
            code.extend(ins.raw)
        for at,target in jumps:
            if target not in mapping:
                raise ValueError('人声加载器分支越过边界。')
            struct.pack_into('<I',code,at,mapping[target])
        output.extend(b'\x06'+struct.pack('<I',address+len(code))+code)
        return dict(kind='voice', address=address, argument_count=argc,
            source_function=span.start, source_sha256=self.audio.source.source_sha256,
            incoming_return_read=False, native_return='Nil',
            helper_sha256=hashlib.sha256(code).hexdigest())

    def bind_wait_guard(self, guard, helper):
        # The only helper inserted between native print and wait is our
        # byte-proven clone. Its additions only replace stack arguments; the
        # original CFG was independently checked for incoming result reads.
        if (guard.context is not self.audio.context or helper.get('source_function') != self.binding['span'].start
                or helper.get('incoming_return_read') is not False or helper.get('native_return') != 'Nil'):
            raise ValueError('人声辅助函数与台词保护的返回值证明不一致。')
        guard.return_summaries[helper['address']] = (False, False)

    def play(self, helper, binding, volume):
        from .native_audio import AudioCode
        row = self.binding
        if (helper.get('kind') != 'voice' or helper.get('argument_count') != row['span'].args+2
                or helper.get('source_sha256') != self.audio.source.source_sha256
                or helper.get('source_function') != row['span'].start
                or binding.get('kind') != 'voice' or binding.get('target_archive') not in row['routes']
                or type(volume) is not int or not 0 <= volume <= 100
                or type(binding.get('native_id')) is not int or not 1 <= binding['native_id'] <= 0x7fffffff):
            raise ValueError('人声素材、音量或目标函数不一致。')
        name = binding.get('target_resource')
        if (not isinstance(name,str) or not 0 < len(name) <= 128 or not name.isascii()
                or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in name)):
            raise ValueError('人声资源名无效。')
        path = row['routes'][binding['target_archive']] + name
        code = (_push_string(path,self.audio.source.encoding)
            +_arguments([volume,binding['native_id']]+[None]*(row['span'].args-1))+_call(helper['address']))
        return AudioCode(code,dict(kind='voice',target_path=path,volume=volume,
            native_mute_skip_guards=True,native_loop_value='Nil',runtime_verified=False))

    def stop(self):
        from .native_audio import AudioCode
        code = _push_global(self.binding['channel_global'])+_arguments([0])+b'\x03'+struct.pack('<H',self.audio.table['AudioStop'][0])
        return AudioCode(code,dict(kind='voice',duration_ms=0,only_target_dialogue_slot=True,runtime_verified=False))

    def report(self):
        return dict(schema=SCHEMA,printer=self.printer,loader=self.binding['span'].start,
            loader_argument_count=self.binding['span'].args,print_wait_split=deepcopy(self.print_split),
            channel_global=self.binding['channel_global'],wait_audio_state_sites=deepcopy(self.wait_sites),
            native_mute_skip_guards=True,explicit_target_path=True,game_name_switch_used=False,
            native_click_auto_wait_preserved=True,backlog_replay=self._backlog is not None,
            backlog_binding_checked=self._backlog_checked,backlog_blocker=self._backlog_blocker,
            original_playback_restored=False,runtime_verified=False)
