"""Bind the target's current-line voice replay, without inventing hotkeys."""
from copy import deepcopy
import hashlib
import struct

from .hoshimemo_scene_hook import _arguments, _call, _push_global, _push_string
from .native_voice import _stack


def _preserved_callee_literals(history, span):
    """Keep translated name lookups in place; never accept changed VM logic."""
    from .native_portrait_dialogue import _terminated_padded_literal, _translated_literal_stub
    audio, changes = history.audio, []
    for item in span.instructions:
        actual = audio.source.original_bytes[item.offset:item.offset+item.size]
        if actual == item.raw:
            continue
        if item.mnemonic != 'push_string' or len(actual) != item.size:
            raise ValueError('当前句重播的原生辅助调用指令已改变。')
        record = dict(function=span.start, offset=item.offset)
        if actual[0] == 6:
            stub = _translated_literal_stub(audio.source, audio.analysis, item, actual)
            record.update(source_target=stub['source_target'], return_offset=stub['return_offset'])
            actual = stub['literal']
        elif (actual[:2] != item.raw[:2] or not _terminated_padded_literal(actual)
                or not _terminated_padded_literal(item.raw)):
            raise ValueError('当前句重播的汉化文字改变了原生指令边界。')
        record['runtime_literal_sha256'] = hashlib.sha256(actual).hexdigest()
        changes.append(record)
    return changes


class NativeVoiceCurrentReplay:
    def __init__(self, history):
        from .native_audio import _normal
        audio, voice = history.audio, history.voice
        row = voice.binding
        # Both the normal printer and the replay must use the SAME native
        # current voice and speaker fields. An unrelated numeric loader is
        # not enough evidence to route a UI/system sound as dialogue.
        trace = audio.flow.trace(voice.printer)
        printer_calls = [c for c in trace.get('calls', ()) if c.get('address') == row['span'].start]
        names = {_normal(c['arguments'][1]).get('slot') for c in printer_calls
                 if _normal(c['arguments'][1]).get('kind') == 'global_read'}
        if (trace['status'] != 'proven_static_argument_flow' or len(names) != 1
                or len(printer_calls) != sum(_normal(c['arguments'][1]).get('kind') == 'global_read'
                                            for c in printer_calls)):
            raise ValueError('当前句重播的原生说话人字段未唯一匹配。')
        name = names.pop()
        candidates = []
        argc = row['span'].args
        for span in audio.spans.values():
            if span.args or span.start == voice.printer or span.locals > 125:
                continue
            if any(i.mnemonic == 'retv' or i.address_role == 'thread_start_function_pointer'
                   for i in span.instructions):
                continue
            if any(i.mnemonic in ('push_stack', 'pop_stack') and i.operands['value'] < 0
                   for i in span.instructions):
                continue
            sites = []
            for index, ins in enumerate(span.instructions):
                if ins.mnemonic != 'call' or ins.operands['target'] != row['span'].start or index < argc:
                    continue
                args = span.instructions[index-argc:index]
                interior = {i.offset for i in args[1:]} | {ins.offset}
                if any(i.mnemonic in ('jmp', 'jz') and i.operands['target'] in interior
                       for i in span.instructions):
                    continue
                if (args[0].mnemonic == args[1].mnemonic == 'push_global'
                        and args[0].operands['value'] == history.voice_global
                        and args[1].operands['value'] == name
                        and all(i.mnemonic in ('push_global', 'push_stack', 'push_nil',
                                               'push_true', 'push_i8', 'push_i16', 'push_i32') for i in args)):
                    sites.append(dict(offset=ins.offset, argument_start=args[0].offset))
            if len(sites) != 1:
                continue
            flow = audio.flow.trace(span.start)
            calls = [c for c in flow.get('calls', ()) if c.get('address') == row['span'].start]
            if (flow['status'] != 'proven_static_argument_flow' or len(calls) != 1
                    or _normal(calls[0]['arguments'][:2]) != [
                        dict(kind='global_read', slot=history.voice_global), dict(kind='global_read', slot=name)]):
                continue
            # The selector remains valid throughout the wrapper, including
            # any small native text/name lookup callees before the load.
            pending, seen, literal_changes = [span.start], set(), []
            safe = True
            while pending:
                at = pending.pop()
                if at in seen:
                    continue
                if at not in audio.spans or len(seen) >= 128:
                    safe = False
                    break
                seen.add(at)
                callee = audio.spans[at]
                if any((i.mnemonic in ('pop_global', 'pop_global_table')
                        and i.operands['value'] in (history.voice_global, name))
                       or i.address_role == 'thread_start_function_pointer' for i in callee.instructions):
                    safe = False
                    break
                if set(callee.syscalls) & {'ThreadStart', 'ThreadExit', 'ThreadNext', 'ThreadWait', 'ThreadSleep'}:
                    safe = False
                    break
                if at in (span.start, row['span'].start):
                    # These two bodies are cloned below; keep their bytes exact.
                    history._exact(callee.instructions)
                else:
                    # Native name/text lookups stay at their ORIGINAL address.
                    # Reuse the existing pure-text overlay proof, not Japanese
                    # replacement strings or an unchecked control-flow bypass.
                    literal_changes.extend(_preserved_callee_literals(history, callee))
                pending.extend(callee.calls)
            if not safe:
                continue
            callers = [dict(caller=s.start, offset=i.offset) for s in audio.spans.values()
                       for i in s.instructions if i.mnemonic == 'call' and i.operands['target'] == span.start]
            if callers:
                candidates.append(dict(span=span, sites=sites, callers=callers,
                                       literal_changes=literal_changes))
        if len(candidates) != 1:
            raise ValueError('当前句重播入口与正文语音字段未唯一匹配。')
        self.binding = candidates[0]
        self.voice_global, self.name_global = history.voice_global, name
        self.channel_global = row['channel_global']

    def report(self):
        return dict(schema='fvp-native-current-voice-replay/1',
            function=self.binding['span'].start, voice_global=self.voice_global,
            speaker_global=self.name_global, channel_global=self.channel_global,
            callers=deepcopy(self.binding['callers']), load_sites=deepcopy(self.binding['sites']),
            preserved_native_text_literals=deepcopy(self.binding['literal_changes']),
            native_current_line_wrapper_preserved=True, original_story_fallback=True,
            hotkey_assignment_changed=False, game_name_switch_used=False,
            runtime_verified=False, save_load_verified=False)


class NativeVoiceCurrentReplayProgram:
    def __init__(self, contract, history_program):
        self.contract, self.owner = contract, history_program
        self.aliases = {contract.binding['span'].start}
        self.patches = []
        # Same explicit-path helper and immutable token table as backlog,
        # but the source binding here owns the normal dialogue channel.
        self.helper = history_program._clone_replay(history_program.contract.voice.binding)
        self.wrapper = self._clone_wrapper()
        self.dispatcher = history_program.base + len(history_program.output) + 5
        code = bytearray(b'\x01\0\0')
        for entry in history_program.entries:
            code.extend(_push_global(contract.voice_global)+_arguments([entry['token']])+b'\x22\x07')
            jump = len(code)
            code.extend(bytes(4))
            code.extend(_push_string(entry['path'], history_program.source.encoding)
                        +_arguments([entry['volume']])+_call(self.wrapper)+b'\x04')
            struct.pack_into('<I', code, jump, self.dispatcher+len(code))
        self.fallback_call = self.dispatcher+len(code)
        code.extend(_call(contract.binding['span'].start)+b'\x04')
        history_program.output.extend(b'\x06'+struct.pack('<I', self.dispatcher+len(code))+code)

    def _clone_wrapper(self):
        owner, binding = self.owner, self.contract.binding
        span, site = binding['span'], binding['sites'][0]
        address = owner.base+len(owner.output)+5
        code = bytearray(bytes((1, 2, span.locals)))
        mapping, jumps = {span.start: address}, []
        for ins in span.instructions[1:]:
            mapping[ins.offset] = address+len(code)
            if ins.offset == site['argument_start']:
                code.extend(_stack(-3)+_stack(-2))  # path, authored volume, then native arguments
            if ins.mnemonic in ('jmp', 'jz'):
                jumps.append((len(code)+1, ins.operands['target']))
            code.extend(_call(self.helper) if ins.offset == site['offset'] else ins.raw)
        for at, target in jumps:
            if target not in mapping:
                raise ValueError('当前句配音重播的分支越过函数边界。')
            struct.pack_into('<I', code, at, mapping[target])
        owner.output.extend(b'\x06'+struct.pack('<I', address+len(code))+code)
        return address

    def add_aliases(self, mapping):
        for old, new in mapping.items():
            if int(old) in self.aliases:
                self.aliases.add(new)

    def report(self):
        return dict(self.contract.report(), helper=self.helper, wrapper=self.wrapper,
            dispatcher=self.dispatcher, call_patches=deepcopy(self.patches),
            scene_export_connected=bool(self.patches),
            mapping_lifetime='same_compiled_token_table_as_backlog',
            volume_policy='native_speaker_preference_times_authored_volume')
