"""Target-bound native history voice routing, never a title/address switch.

The history field, row tables, replay caller and separate audio slot must form
one chain. Unmatched targets retain ordinary line playback without claiming
backlog support. Compiled routes live in the new script, not temporary globals.
"""
from copy import deepcopy
from dataclasses import replace
import struct

from .hcb import parse_bytes
from .hoshimemo_scene_hook import _arguments, _call, _pop_global, _push_string
from .native_voice import _stack, _pop

SCHEMA = 'fvp-native-voice-backlog/1'


def _integer(item):
    return item.operands['value'] if item.mnemonic in ('push_i8', 'push_i16', 'push_i32') else None


def _voice_global(value):
    if value.get('kind') == 'global_read':
        return value['slot']
    if value.get('kind') == 'add':
        parts = value.get('operands', ())
        if len(parts) == 2 and parts[1].get('kind') == 'call_return':
            return _voice_global(parts[0])
    if value.get('kind') == 'choice':
        slots = {_voice_global(v) for v in value.get('operands', ())}
        if len(slots) == 1:
            return slots.pop()
    return None


class NativeVoiceBacklog:
    def __init__(self, voice):
        from .native_audio import _normal
        self.voice, self.audio = voice, voice.audio
        audio = self.audio
        if any(audio.table.get(n, (None, None))[1] != 2 for n in ('HistorySet', 'HistoryGet')):
            raise ValueError('原生回看记录接口未匹配。')
        trace = audio.flow.trace(voice.printer)
        calls = [c for c in trace.get('calls', ()) if c.get('address') == voice.binding['span'].start]
        slots = {_voice_global(_normal(c['arguments'][0])) for c in calls}
        if trace['status'] != 'proven_static_argument_flow' or len(slots) != 1 or None in slots:
            raise ValueError('台词语音编号与回看记录的来源未唯一匹配。')
        self.voice_global = slots.pop()
        # The explicit-path loader runs AFTER print initialization. It must
        # not replace the history token with its unrelated numeric asset ID.
        pending, checked = [voice.binding['span'].start], set()
        while pending:
            at = pending.pop()
            if at in checked:
                continue
            if at not in audio.spans or len(checked) >= 128:
                raise ValueError('正文配音的编号副作用未闭合。')
            checked.add(at)
            span = audio.spans[at]
            if any(i.mnemonic in ('pop_global', 'pop_global_table') and i.operands['value'] == self.voice_global
                   for i in span.instructions):
                raise ValueError('正文加载器会覆盖回看语音编号，暂不接入此目标。')
            pending.extend(span.calls)
        reached, pending = set(), [voice.dialogue_abi.print_target, voice.dialogue_abi.wait_target]
        while pending:
            at = pending.pop()
            if at in reached:
                continue
            if at not in audio.spans or len(reached) >= 512:
                raise ValueError('回看记录的台词调用链不完整。')
            reached.add(at)
            span = audio.spans[at]
            pending.extend(span.calls)
            pending.extend(i.operands['value'] for i in span.instructions
                           if i.address_role == 'thread_start_function_pointer')
        records = []
        for at in reached:
            rows = audio.spans[at].instructions
            for a, b, c in zip(rows, rows[1:], rows[2:]):
                if (_integer(a) is not None and b.mnemonic == 'push_global'
                        and b.operands['value'] == self.voice_global and self._sys(c, 'HistorySet')):
                    self._exact((a, b, c))
                    records.append(dict(function=at, offset=c.offset, field=_integer(a)))
        fields = {r['field'] for r in records}
        if len(fields) != 1:
            raise ValueError('没有唯一的原生配音回看记录字段。')
        self.field = fields.pop()
        # HistoryGet(field, row) -> local -> native UI row table. Preserve the
        # original row/name indexing; only dispatch that row's selected sound.
        rows_bound = []
        for span in audio.spans.values():
            rows, tables = span.instructions, {}
            for i in range(2, len(rows)-2):
                if (not self._sys(rows[i], 'HistoryGet') or _integer(rows[i-2]) is None
                        or rows[i-1].mnemonic != 'push_stack'
                        or rows[i+1].mnemonic != 'push_return' or rows[i+2].mnemonic != 'pop_stack'):
                    continue
                local = rows[i+2].operands['value']
                for a, b, c in zip(rows[i+3:], rows[i+4:], rows[i+5:]):
                    if (a.mnemonic == 'push_stack' and a.operands['value'] < -1
                            and b.mnemonic == 'push_stack' and b.operands['value'] == local
                            and c.mnemonic == 'pop_global_table'):
                        self._exact((*rows[i-2:i+3], a, b, c))
                        tables.setdefault(_integer(rows[i-2]), set()).add(c.operands['value'])
            if len(tables.get(self.field, ())) == 1:
                rows_bound.append((next(iter(tables[self.field])),
                    set().union(*(v for k, v in tables.items() if k != self.field)), span.start))
        candidates = []
        for span in audio.spans.values():
            if (span.args != 2 or span.locals > 125 or span.start == voice.binding['span'].start
                    or 'AudioLoad' not in span.syscalls):
                continue
            try:
                replay = voice._bind(span, _normal)
                self._exact(span.instructions)
            except ValueError:
                continue
            if (replay['channel_global'] == voice.binding['channel_global']
                    or replay['routes'] != voice.binding['routes']
                    or replay['numbering_width'] != voice.binding['numbering_width']):
                continue
            links = []
            for caller in audio.spans.values():
                for i, ins in enumerate(caller.instructions):
                    if ins.mnemonic != 'call' or ins.operands['target'] != span.start or i < 8:
                        continue
                    items = caller.instructions[i-8:i]
                    if [x.mnemonic for x in items] != ['push_global_table', 'pop_stack', 'push_stack',
                            'push_global', 'push_i8', 'sub', 'push_global_table', 'push_global_table']:
                        continue
                    if items[1].operands['value'] != items[2].operands['value'] or _integer(items[4]) != 1:
                        continue
                    for voice_table, names, reader in rows_bound:
                        if items[0].operands['value'] == voice_table and items[-1].operands['value'] in names:
                            self._exact((*items, ins))
                            links.append(dict(caller=caller.start, offset=ins.offset, row_reader=reader,
                                voice_table=voice_table, name_table=items[-1].operands['value']))
            if links:
                candidates.append((replay, links))
        if len(candidates) != 1:
            raise ValueError('原生回看选句、人声槽与回放函数未唯一匹配。')
        self.binding, self.links = candidates[0]
        self.records = records
        self.current = None
        self.current_blocker = None
        from .native_voice_current import NativeVoiceCurrentReplay
        try:
            self.current = NativeVoiceCurrentReplay(self)
        except ValueError as exc:
            self.current_blocker = str(exc)

    def _sys(self, item, name):
        return item.mnemonic == 'syscall' and item.operands['id'] == self.audio.table[name][0]

    def _exact(self, items):
        for item in items:
            if self.audio.source.original_bytes[item.offset:item.offset+item.size] != item.raw:
                raise ValueError('原生回看调用字节与已分析版本不一致。')

    def report(self):
        return dict(schema=SCHEMA, voice_global=self.voice_global, history_field=self.field,
            record_sites=deepcopy(self.records), replay_function=self.binding['span'].start,
            replay_channel_global=self.binding['channel_global'], row_links=deepcopy(self.links),
            original_story_fallback=True, game_name_switch_used=False,
            scope='native_history_row_replay', current_line_replay_hotkey=self.current is not None,
            current_line_replay=self.current.report() if self.current else None,
            current_line_replay_blocker=self.current_blocker,
            scene_export_connected=False, runtime_verified=False)


class NativeVoiceBacklogProgram:
    def __init__(self, contract, output, bindings, events, *, absolute_output=False,
                 append_start=None, append_encoding=None):
        self.contract, self.output = contract, output
        self.source, self.analysis = contract.audio.source, contract.audio.analysis
        if type(absolute_output) is not bool or not isinstance(output, bytearray):
            raise ValueError('人声重播输出地址模式不正确。')
        if absolute_output:
            if type(append_start) is not int or not len(self.source.original_bytes) <= append_start <= len(output):
                raise ValueError('绝对地址人声输出缺少完整原始脚本边界。')
        elif append_start is not None or append_encoding is not None:
            raise ValueError('相对地址人声输出不能覆盖原始脚本边界。')
        self.base = 0 if absolute_output else len(self.source.original_bytes)
        self.append_start = append_start if absolute_output else self.base
        self.append_encoding = append_encoding or self.source.encoding
        self.bindings = bindings
        self.entries, self.routes, self.aliases = [], {}, {contract.binding['span'].start}
        unique = self.routes
        for event in events:
            if event['kind'] != 'GuiVoiceLine':
                continue
            asset = bindings.audio(event)
            key = (asset['target_archive'], asset['target_resource'], event['volume'])
            if key not in unique:
                unique[key] = dict(token=bindings.reserve_voice_replay_token(), volume=event['volume'],
                    path=contract.binding['routes'][key[0]]+key[1])
                self.entries.append(unique[key])
        self.helper = self._clone_replay()
        self.dispatcher = self.base + len(output) + 5
        code = bytearray(b'\x01\x02\0')
        for entry in self.entries:
            code.extend(_stack(-3)+_arguments([entry['token']])+b'\x22\x07')
            jump = len(code); code.extend(bytes(4))
            code.extend(_push_string(entry['path'], self.source.encoding)
                +_arguments([entry['volume']])+_stack(-3)+_stack(-2)+_call(self.helper)+b'\x04')
            struct.pack_into('<I', code, jump, self.dispatcher+len(code))
        code.extend(_stack(-3)+_stack(-2))
        self.fallback_call = self.dispatcher+len(code)
        code.extend(_call(contract.binding['span'].start)+b'\x04')
        output.extend(b'\x06'+struct.pack('<I', self.dispatcher+len(code))+code)
        self.patches = []
        self.current = None
        if contract.current is not None:
            from .native_voice_current import NativeVoiceCurrentReplayProgram
            self.current = NativeVoiceCurrentReplayProgram(contract.current, self)

    def _clone_replay(self, row=None):
        row = row if row is not None else self.contract.binding
        span = row['span']
        address = self.base+len(self.output)+5
        code = bytearray(bytes((1, span.args+2, span.locals+2)))
        mapping, jumps = {span.start: address}, []
        for ins in span.instructions[1:]:
            mapping[ins.offset] = address+len(code)
            if ins.offset == row['load_offset']:
                code.extend(_pop(span.locals)+_stack(-span.args-3))
            if ins.offset == row['volume_offset']:
                # Keep native per-speaker mute/volume preferences. Authored
                # volume is a multiplier, not a way to bypass a native zero.
                code.extend(_pop(span.locals+1)+_pop(span.locals)+_stack(span.locals)
                    +_stack(-span.args-2)+b'\x1c'+_arguments([100])+b'\x1d'+_stack(span.locals+1))
            if ins.mnemonic in ('jmp', 'jz'):
                jumps.append((len(code)+1, ins.operands['target']))
            code.extend(ins.raw)
        for at, target in jumps:
            if target not in mapping:
                raise ValueError('回看配音分支越过原生函数边界。')
            struct.pack_into('<I', code, at, mapping[target])
        self.output.extend(b'\x06'+struct.pack('<I', address+len(code))+code)
        return address

    def before_print(self, event):
        asset = self.bindings.audio(event)
        key = (asset['target_archive'], asset['target_resource'], event['volume'])
        return _arguments([self.routes[key]['token']])+_pop_global(self.contract.voice_global)

    def clear_line(self):
        return b'\x08'+_pop_global(self.contract.voice_global)

    def add_aliases(self, mapping):
        for old, new in mapping.items():
            if int(old) in self.aliases:
                self.aliases.add(new)
        if self.current is not None:
            self.current.add_aliases(mapping)

    def patch_image(self, image, *, function_maps=()):
        """Patch decoded CALL operands before the scene assembler checks stacks.

        No game file is written. Return exact old/new bytes for the assembler's
        prefix rollback proof; also route its copies of native UI callbacks.
        """
        for mapping in function_maps:
            self.add_aliases(mapping)
        table = self.analysis.original_bytes[self.analysis.header.sysdesc_offset:]
        start = self.append_start
        if not start <= len(image):
            raise ValueError('人声重播的新增程序边界超出输出。')
        added = parse_bytes(struct.pack('<I', 4+len(image)-start)+bytes(image[start:])+table,
                            self.append_encoding)
        if added.warnings:
            raise ValueError('回看配音接入时新增程序不能完整解码。')
        items = list(self.analysis.instructions)+[
            replace(i, offset=i.offset+start-4) for i in added.instructions]
        patches, current_patches, history_patches = [], [], []
        for item in items:
            if item.mnemonic != 'call':
                continue
            target = item.operands['target']
            if target in self.aliases and item.offset != self.fallback_call:
                destination, group = self.dispatcher, history_patches
            elif (self.current is not None and target in self.current.aliases
                    and item.offset != self.current.fallback_call):
                destination, group = self.current.dispatcher, current_patches
            else:
                continue
            actual = bytes(image[item.offset:item.offset+5])
            if actual != item.raw:
                raise ValueError('回看调用位置与场景接入补丁发生冲突。')
            replacement = _call(destination)
            patch = dict(offset=item.offset, expected=actual, replacement=replacement)
            patches.append(patch)
            group.append(patch)
        if not history_patches:
            raise ValueError('生成的场景没有可接入的原生回看调用。')
        if self.current is not None and not current_patches:
            raise ValueError('当前句配音重播缺少配套调用点，不能输出半接入脚本。')
        for patch in patches:
            at = patch['offset']; image[at:at+5] = patch['replacement']
        self.patches = [dict(offset=p['offset'], expected_hex=p['expected'].hex(),
            replacement_hex=p['replacement'].hex()) for p in patches]
        if self.current is not None:
            self.current.patches = [dict(offset=p['offset'], expected_hex=p['expected'].hex(),
                replacement_hex=p['replacement'].hex()) for p in current_patches]
        return patches

    def report(self):
        return dict(self.contract.report(), routes=deepcopy(self.entries), dispatcher=self.dispatcher,
            helper=self.helper, call_patches=deepcopy(self.patches),
            current_line_replay_hotkey=bool(self.current and self.current.patches),
            current_line_replay=self.current.report() if self.current else None,
            mapping_lifetime='compiled_script_not_temporary_globals',
            volume_policy='native_speaker_preference_times_authored_volume',
            scene_export_connected=bool(self.patches), save_load_verified=False,
            original_files_modified=False)
