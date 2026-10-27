"""Target-bound BGM/SE/voice bytecode, not a title-specific audio ABI.

This layer binds native slots and category volume. The scene program owns
line/route lifetime; inherited playback restoration is not yet connected.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _arguments, _call, _push_global, _pop_global, _push_string
from .native_background_backend import _dependencies, _literal
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import _function_spans
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair

SCHEMA = 'fvp-native-audio/1'


def _normal(value):
    if isinstance(value, dict):
        return {k: _normal(v) for k, v in value.items() if k not in {'offset', 'semantics_reviewed'}}
    if isinstance(value, (tuple, list)):
        return [_normal(v) for v in value]
    return value


def _stack(index):
    return b'\x10' + struct.pack('<b', index)


def _pop(index):
    return b'\x16' + struct.pack('<b', index)


def _integers(value):
    if value.get('kind') == 'literal' and type(value.get('value')) is int:
        return {value['value']}
    if value.get('kind') == 'choice':
        return set().union(*(_integers(v) for v in value['operands']))
    raise ValueError('音效的原生槽范围尚未确定。')


def _path(value):
    if value.get('kind') != 'add' or len(value.get('operands', ())) != 2:
        raise ValueError('原生音效路径结构未匹配。')
    prefix, suffix = value['operands']
    if (prefix != _literal('se/') or suffix.get('kind') != 'call_return'
            or suffix.get('call_kind') != 'syscall' or suffix.get('target') != 'IntToText'
            or suffix.get('arguments') != [dict(kind='argument', index=0), _literal(3)]):
        raise ValueError('原生音效路径参数未匹配。')
    return prefix['value']


@dataclass(frozen=True)
class AudioCode:
    code: bytes
    report: dict


class NativeAudioBackend:
    def __init__(self, context):
        self.context, self.source, self.analysis = context, context.document, context.analysis_document
        self.pair = validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        self.spans = {s.start: s for s in _function_spans(self.analysis)}
        self.flow = NativeFunctionFlow(self.analysis)
        self.table = {}
        for index, entry in enumerate(self.source.header.syscalls):
            if entry.name in self.table:
                raise ValueError('目标音频系统调用名重复。')
            self.table[entry.name] = (index, entry.args)
        self.bindings, self.blockers = {}, {}
        for kind, bind in (('se', self._bind_se), ('bgm', self._bind_bgm)):
            candidates = []
            for span in self.spans.values():
                if ('SoundLoad' if kind == 'se' else 'AudioLoad') not in span.syscalls:
                    continue
                try:
                    row = bind(span)
                    closure = NativeScriptStateClosure(self.source, self.analysis, [span.start], runtime_context=context)
                    row['closure'] = closure
                    candidates.append(row)
                except (ValueError, KeyError):
                    continue
            if len(candidates) == 1:
                self.bindings[kind] = candidates[0]
            else:
                self.blockers[kind] = '目标的原生音乐/音效调用未唯一匹配。'
        self.voice = None
        try:
            from .native_voice import NativeVoiceBackend
            self.voice = NativeVoiceBackend(self)
            self.bindings['voice'] = self.voice.binding
        except (ValueError, KeyError) as exc:
            self.blockers['voice'] = str(exc)
        if not self.bindings:
            raise ValueError('此目标暂未匹配通用声音调用。')

    def syscall(self, name, values):
        if self.table.get(name, (None, None))[1] != len(values):
            raise ValueError('目标音频调用参数不匹配：' + name)
        return _arguments(values) + b'\x03' + struct.pack('<H', self.table[name][0])

    def _bind_se(self, span):
        if any(self.table.get(name,(None,None))[1] != count for name,count in (
                ('IntToText',2),('SoundStop',2),('SoundType',2),('SoundLoad',2),('SoundVol',3),('SoundPlay',3))):
            raise ValueError('目标普通音效系统调用签名未匹配。')
        if span.args != 4 or not 0 <= span.locals < 127 or span.calls:
            raise ValueError('普通音效入口未匹配。')
        trace = self.flow.trace(span.start, literal_arguments={1: None, 2: 1},
            non_nil_arguments={0, 3}, max_joined_values=128)
        calls = trace['calls']
        expected = ['IntToText', 'SoundStop', 'SoundType', 'SoundLoad', 'SoundVol', 'SoundPlay']
        if trace['status'] != 'proven_static_argument_flow' or [c.get('name') for c in calls] != expected:
            raise ValueError('普通音效播放链未匹配。')
        stop, category, load, volume, play = calls[1:]
        slots = sorted(_integers(load['arguments'][0]))
        if not slots or len(slots) > 16 or any(not 0 <= s <= 255 for s in slots):
            raise ValueError('普通音效原生槽范围不支持。')
        for call in calls[1:]:
            if _normal(call['arguments'][0]) != _normal(load['arguments'][0]):
                raise ValueError('普通音效槽身份不一致。')
        prefix = _path(load['arguments'][1])
        if (stop['arguments'][1] != _literal(0)
                or category['arguments'][1].get('type') != 'int'
                or not 0 <= category['arguments'][1]['value'] <= 9
                or volume['arguments'][1:] != [dict(kind='argument', index=3), _literal(None)]
                or play['arguments'][1:] != [_literal(None), _literal(None)]):
            raise ValueError('普通音效的音量或一次播放语义未匹配。')
        for slot in slots:
            stop_trace = self.flow.trace(span.start, literal_arguments={0: slot, 2: -1},
                non_nil_arguments={1}, max_joined_values=128)
            stopped = stop_trace['calls']
            if (stopped and stopped[0].get('name') == 'IntToText'
                    and stopped[0]['arguments'] == [_literal(slot),_literal(3)]):
                # Some targets construct an unused path before branching into
                # slot-stop mode. This pure formatting call is not playback.
                stopped = stopped[1:]
            if (stop_trace['status'] != 'proven_static_argument_flow'
                    or len(stopped) != 1 or stopped[0].get('name') != 'SoundStop'
                    or stopped[0]['arguments'] != [_literal(slot), dict(kind='argument', index=1)]):
                raise ValueError('普通音效停止与原生缓存清理未匹配。')
        return dict(span=span, slots=slots, category=category['arguments'][1]['value'],
            routes={'se.bin': prefix}, load_offset=load['offset'], play_offset=play['offset'],
            trace=trace)

    def _bind_bgm(self, span):
        if any(self.table.get(name,(None,None))[1] != count for name,count in (
                ('AudioStop',2),('AudioType',2),('AudioLoad',2),('AudioVol',3),('AudioPlay',2))):
            raise ValueError('目标音乐系统调用签名未匹配。')
        if span.args != 5 or not 1 <= span.locals < 127:
            raise ValueError('音乐入口未匹配。')
        body = span.instructions
        load_at = [n for n, i in enumerate(body) if i.mnemonic == 'syscall'
                   and self.analysis.header.syscalls[i.operands['id']].name == 'AudioLoad']
        if len(load_at) != 1:
            raise ValueError('音乐加载入口不唯一。')
        pos = load_at[0]
        if [i.mnemonic for i in body[pos-2:pos]] != ['push_global', 'push_stack']:
            raise ValueError('音乐加载槽与路径不是明确变量。')
        current, path_local = (body[pos-2].operands['value'], body[pos-1].operands['value'])
        if not 0 <= path_local < span.locals:
            raise ValueError('音乐路径局部变量无效。')
        matches = []
        for n in range(1, pos-12):
            q = body[n:n+13]
            if [i.mnemonic for i in q] != ['push_global', q[1].mnemonic, 'set_e', 'jz',
                    q[4].mnemonic, 'pop_global', q[6].mnemonic, 'pop_global', 'jmp',
                    q[9].mnemonic, 'pop_global', q[11].mnemonic, 'pop_global']:
                continue
            if any(q[i].mnemonic not in {'push_i8', 'push_i16', 'push_i32'} for i in (1,4,6,9,11)):
                continue
            a, b, previous = q[1].operands['value'], q[4].operands['value'], q[7].operands['value']
            if (a == b or not 0 <= a <= 3 or not 0 <= b <= 3 or previous == current
                    or any(q[i].operands['value'] != current for i in (0,5,10))
                    or q[12].operands['value'] != previous
                    or [q[i].operands['value'] for i in (6,9,11)] != [a,a,b]
                    or q[3].operands['target'] != q[9].offset
                    or q[8].operands['target'] != body[n+13].offset):
                continue
            matches.append((n, previous, [a,b]))
        if len(matches) != 1:
            raise ValueError('音乐双槽切换未唯一匹配。')
        start, previous, slots = matches[0]
        plays = [n for n, i in enumerate(body) if i.mnemonic == 'syscall'
                 and self.analysis.header.syscalls[i.operands['id']].name == 'AudioPlay']
        if len(plays) != 2 or plays[-1] + 1 >= len(body):
            raise ValueError('音乐循环分支未匹配。')
        finish = plays[-1] + 1
        loop_global = None
        # Some native loaders remember the typed loop value immediately
        # after each AudioPlay. Include both stores and their common join;
        # stopping at the second syscall cuts a valid branch in half.
        if plays[-1] + 3 < len(body):
            yes, no = body[plays[0]+1:plays[0]+3], body[plays[-1]+1:plays[-1]+3]
            if ([i.mnemonic for i in yes] == ['push_true','pop_global']
                    and [i.mnemonic for i in no] == ['push_nil','pop_global']
                    and yes[1].operands == no[1].operands):
                loop_global = yes[1].operands['value']
                finish += 2
        fragment = body[start:finish]
        limit = body[finish].offset
        boundaries = {i.offset for i in fragment} | {limit}
        if (any(i.mnemonic in {'call', 'retv', 'ret', 'init_stack'} for i in fragment)
                or any(i.mnemonic in {'jmp','jz'} and i.operands['target'] not in boundaries for i in fragment)
                or any(i.mnemonic == 'push_stack' and i.operands['value'] not in {path_local,-4,-3} for i in fragment)
                or any(i.mnemonic == 'pop_stack' for i in fragment)):
            raise ValueError('音乐双槽片段包含未接入依赖。')
        syscalls = [self.analysis.header.syscalls[i.operands['id']].name for i in fragment
                    if i.mnemonic == 'syscall']
        calls_with_stop = ['AudioStop','AudioType','AudioLoad','AudioVol','AudioPlay','AudioPlay']
        if syscalls not in (calls_with_stop, calls_with_stop[1:]):
            raise ValueError('音乐片段包含额外的系统调用。')
        # A symbolic flow proves the argument roles of the target's actual
        # calls. Literal loop branches are checked independently, preserving
        # typed Nil/Int rather than converting Python bool to native Int.
        flow = self.flow.trace(span.start, literal_arguments={1: 800, 2: 1, 3: 63, 4: 1},
            non_nil_arguments={0}, max_joined_values=128)
        if flow['status'] != 'proven_static_argument_flow':
            raise ValueError('音乐参数流未匹配。')
        audio = [c for c in flow['calls'] if c.get('name', '').startswith('Audio')]
        expected = ['AudioType','AudioLoad','AudioVol','AudioPlay']
        stops_new_slot = syscalls[0] == 'AudioStop'
        if [c['name'] for c in audio] != (['AudioStop'] if stops_new_slot else []) + expected:
            raise ValueError('音乐起播链未匹配。')
        if (any(c['arguments'][0].get('kind') != 'global_read'
                or c['arguments'][0].get('slot') != current for c in audio)
                or stops_new_slot and audio[0]['arguments'][1] != _literal(0)):
            raise ValueError('音乐目标槽或原生加载前停止参数未匹配。')
        category,load,volume,play = audio[-4:]
        if (category['arguments'][1].get('type') != 'int'
                or not 0 <= category['arguments'][1]['value'] <= 9
                or volume['arguments'][1:] != [_literal(63), _literal(None)]
                or play['arguments'][1] != _literal(True)):
            raise ValueError('音乐音量或循环参数未匹配。')
        once = self.flow.trace(span.start, literal_arguments={1:800,2:0,3:63,4:1},
            non_nil_arguments={0}, max_joined_values=128)
        once_plays = [c for c in once['calls'] if c.get('name') == 'AudioPlay']
        if (once['status'] != 'proven_static_argument_flow' or len(once_plays) != 1
                or once_plays[0]['arguments'][1] != _literal(None)):
            raise ValueError('音乐一次播放参数未匹配。')
        if loop_global is not None and (loop_global in (current,previous)
                or [w['value'] for w in flow['global_writes'] if w['slot']==loop_global] != [_literal(True)]
                or [w['value'] for w in once['global_writes'] if w['slot']==loop_global] != [_literal(None)]):
            raise ValueError('音乐循环缓存未与各自播放分支一致。')
        id_globals = {w['slot'] for w in flow['global_writes'] if _dependencies(w['value']) == {0}}
        if len(id_globals) != 1 or current in id_globals or previous in id_globals:
            raise ValueError('音乐资源编号缓存未唯一匹配。')
        prefixes = {i.text for i in body if i.mnemonic == 'push_string'
                    and i.text and i.text.lower() in {'bgm/', 'bgm2/'}}
        if not prefixes or len({p.lower() for p in prefixes}) != len(prefixes):
            raise ValueError('音乐归档路径未唯一匹配。')
        return dict(span=span, slots=slots, current=current, previous=previous,
            id_global=next(iter(id_globals)), category=category['arguments'][1]['value'],
            loop_global=loop_global, native_stops_new_slot=stops_new_slot,
            routes={p.rstrip('/').lower()+'.bin':p for p in prefixes},
            volume_globals=sorted({fragment[n+1].operands['value'] for n, ins in enumerate(fragment[:-1])
                if ins.mnemonic == 'push_stack' and ins.operands['value'] == -3
                and fragment[n+1].mnemonic == 'pop_global'}),
            path_local=path_local, fragment=fragment, fragment_end=limit, trace=flow)

    def validate(self):
        for binding in self.bindings.values():
            binding['closure'].compile_snapshot(self.source)

    def prepare(self, kind, output, *, fade_in=False):
        """Append a skipped private helper; all original source bytes stay intact."""
        self.validate()
        if (kind not in self.bindings or not isinstance(output, bytearray)
                or type(fade_in) is not bool or kind != 'bgm' and fade_in):
            raise ValueError('此目标尚未绑定这类声音。')
        if kind == 'voice':
            return self.voice.prepare(output)
        row = self.bindings[kind]
        span = row['span']
        skip = len(self.source.original_bytes) + len(output)
        address = skip + 5
        code, mapping, jumps = bytearray(), {}, []
        if kind == 'se':
            # Prefix typed loop, path and fade duration, keeping original
            # argument indices intact. One scratch local drops only the old
            # computed path/fade argument; slot allocation/caches are untouched.
            body = span.instructions[1:]
            code.extend(bytes((1,7,span.locals+1)))
        else:
            body = row['fragment']
            code.extend(bytes((1,7 if fade_in else 6,span.locals)))
            code.extend(_stack(-8 if fade_in else -7) + _pop(row['path_local']))
            code.extend(_stack(-6) + _pop_global(row['id_global']))
        for ins in body:
            mapping[ins.offset] = address + len(code)
            if kind == 'se' and ins.offset == row['load_offset']:
                code.extend(_pop(span.locals) + _stack(-7))
            if kind == 'se' and ins.offset == row['play_offset']:
                # Replace both original Nil arguments. False must become Nil,
                # never native Int0 (which would also enable looping).
                code.extend(_pop(span.locals)*2 + _stack(-8) + _stack(-6))
            is_play = (kind == 'bgm' and fade_in and ins.mnemonic == 'syscall'
                       and self.analysis.header.syscalls[ins.operands['id']].name == 'AudioPlay')
            if is_play:
                # Load has already cleared this new slot. Keep the original
                # target-volume cache but start actual playback at zero.
                code.extend(_push_global(row['current']) + _arguments([0,0])
                            + b'\x03' + struct.pack('<H',self.table['AudioVol'][0]))
            if ins.mnemonic in {'jmp','jz'}:
                jumps.append((len(code)+1, ins.operands['target']))
            code.extend(ins.raw)
            if is_play:
                code.extend(_push_global(row['current']) + _stack(-3) + _stack(-7)
                            + b'\x03' + struct.pack('<H',self.table['AudioVol'][0]))
        if kind == 'bgm':
            mapping[row['fragment_end']] = address + len(code)
            # Use the proven target old slot with the author's exact duration,
            # not the original helper's title-specific +1000/default offset.
            code.extend(_push_global(row['previous']) + _stack(-5)
                        + b'\x03' + struct.pack('<H', self.table['AudioStop'][0]) + b'\x04')
        for at, target in jumps:
            if target not in mapping:
                raise ValueError('声音副本的跳转越过已匹配片段。')
            struct.pack_into('<I', code, at, mapping[target])
        output.extend(b'\x06' + struct.pack('<I', address+len(code)) + code)
        return dict(kind=kind, address=address, argument_count=7 if kind == 'se' or fade_in else 6,
            fade_in=fade_in,
            source_function=span.start, helper_sha256=hashlib.sha256(code).hexdigest(),
            source_sha256=self.source.source_sha256)

    def play(self, helper, binding, *, volume=100, loop=False, duration_ms=0, fade_in_ms=0):
        self.validate()
        kind = helper.get('kind')
        if kind == 'voice':
            if self.voice is None or loop is not False or duration_ms != 0 or fade_in_ms != 0:
                raise ValueError('台词人声不能循环或附加音乐渐变。')
            return self.voice.play(helper, binding, volume)
        row = self.bindings.get(kind)
        if (row is None or helper.get('source_sha256') != self.source.source_sha256
                or helper.get('source_function') != row['span'].start
                or binding.get('kind') != kind
                or binding.get('target_archive') not in row['routes']
                or type(volume) is not int or not 0 <= volume <= 100
                or type(duration_ms) is not int or not 0 <= duration_ms <= 6000
                or type(loop) is not bool or type(fade_in_ms) is not int or not 0 <= fade_in_ms <= 6000
                or kind != 'bgm' and fade_in_ms != 0
                or bool(fade_in_ms) != helper.get('fade_in',False)
                or helper.get('argument_count') != (7 if kind == 'se' or fade_in_ms else 6)
                or type(binding.get('native_id')) is not int or not 1 <= binding['native_id'] <= 0x7fffffff):
            raise ValueError('声音绑定、音量、循环或时长不正确。')
        name = binding.get('target_resource')
        if (not isinstance(name,str) or not 0 < len(name) <= 128 or not name.isascii()
                or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in name)):
            raise ValueError('目标声音资源名不正确。')
        path = row['routes'][binding['target_archive']] + name
        if kind == 'se':
            code = (_arguments([True if loop else None]) + _push_string(path,self.source.encoding)
                    + _arguments([duration_ms,binding['native_id'],None,1,volume]))
        else:
            values = ([fade_in_ms] if fade_in_ms else []) + [binding['native_id'],duration_ms,1 if loop else 0,volume,1]
            code = _push_string(path,self.source.encoding) + _arguments(values)
        return AudioCode(code + _call(helper['address']), dict(kind=kind,
            target_path=path, native_id=binding['native_id'], volume=volume, loop=loop,
            duration_ms=duration_ms, duration_role='fade_in' if kind == 'se' else 'previous_bgm_fade_out',
            fade_in_ms=fade_in_ms, true_crossfade=kind=='bgm' and fade_in_ms>0 and duration_ms>0,
            native_category=row['category'], runtime_verified=False))

    def volume(self, volume, duration_ms=0):
        """Only call for an owned active BGM; never reverse a pending Stop."""
        self.validate()
        if ('bgm' not in self.bindings or type(volume) is not int or not 0 <= volume <= 100
                or type(duration_ms) is not int or not 0 <= duration_ms <= 6000):
            raise ValueError('音乐音量或时长无效。')
        row = self.bindings['bgm']
        code = (_push_global(row['current']) + _arguments([volume,duration_ms])
                + b'\x03' + struct.pack('<H',self.table['AudioVol'][0]))
        for cell in row['volume_globals']:
            code += _arguments([volume]) + _pop_global(cell)
        return AudioCode(code,dict(kind='bgm',volume=volume,duration_ms=duration_ms,
            native_envelope_semantics=True,cancels_pending_stop=False,runtime_verified=False))

    def stop(self, kind, duration_ms=0):
        self.validate()
        if kind not in self.bindings or type(duration_ms) is not int or not 0 <= duration_ms <= 6000:
            raise ValueError('声音停止类型或时间无效。')
        if kind == 'voice':
            if duration_ms:
                raise ValueError('台词切换停止人声不使用淡出时间。')
            return self.voice.stop()
        row = self.bindings[kind]
        if kind == 'se':
            code = b''.join(_arguments([slot,duration_ms,-1,None])+_call(row['span'].start)
                            for slot in row['slots'])
        else:
            # Slot expressions come from the target, never from a fixed title ABI.
            code = b''.join(_push_global(g)+_arguments([duration_ms])+b'\x03'
                           +struct.pack('<H',self.table['AudioStop'][0]) for g in (row['current'],row['previous']))
            code += _arguments([None]) + _pop_global(row['id_global'])
        return AudioCode(code, dict(kind=kind, duration_ms=duration_ms, native_cache_cleanup=True,
                                    original_playback_position_restored=False, runtime_verified=False))

    def report(self):
        from .gui_audio_program import playback_contract
        voice = self.voice.report() if self.voice else None
        return dict(schema=SCHEMA, target_id=getattr(self.context,'target_id',None),
            playback=playback_contract(self.bindings, voice_backlog_replay=bool(voice and voice['backlog_replay'])),
            game_name_switch_used=False, source_sha256=self.source.source_sha256,
            kinds={kind: dict(native_calls_bound=True, function=row['span'].start,
                native_slots=row['slots'], native_category=row['category'], routes=deepcopy(row['routes']),
                native_slot_allocator=kind=='se', runtime_verified=False)
                for kind,row in self.bindings.items()}, blockers=deepcopy(self.blockers),
            voice_bound=self.voice is not None, voice=voice,
            scene_export_connected=False, chapter_export_connected=False,
            original_audio_restore_connected=False, runtime_verified=False)
