"""Use the shared native voice replayers without moving the legacy entry.

The old adapter retains its audited text/voice loader and independent-stage
entry. Only immutable replay routes and byte-bound UI CALL operands are added
to the candidate image. No source game or user project is written here.
"""
from .gui_legacy_audio import legacy_backend
from .gui_story_program import StoryVariableBank
from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_voice_backlog import NativeVoiceBacklogProgram


class LegacyVoiceReplay:
    def __init__(self, emitter, events, resources):
        self.emitter = emitter
        native = legacy_backend(emitter.source, emitter.clean)
        if native.voice is None:
            raise ValueError('原生人声调用未匹配，不能接入回看重播。')
        contract = native.voice.bind_backlog()
        # legacy_backend checks the exact, already audited source/clean pair.
        # Every function cloned by the shared replayers must ALSO be equal;
        # translated name lookups stay in the original image, never recopied.
        rows = [contract.binding, contract.voice.binding]
        if contract.current is not None:
            rows.append(contract.current.binding)
        for row in rows:
            span = row['span']
            if emitter.source[span.start:span.end] != emitter.clean[span.start:span.end]:
                raise ValueError('原生人声重播函数与已审核指令不一致。')
        bank = getattr(emitter, 'story_bank', None)
        if bank is None:
            bank = emitter.story_bank = StoryVariableBank(emitter, {})
            bank.initialize()
        self.saved = bank.reserve_private(1, 'legacy_voice_history_original')['private_global_ids'][0]
        emitter.output.extend(_push_global(contract.voice_global)+_pop_global(self.saved))
        # Both FrozenResources (preflight) and ExportResources use this same
        # archive-aware plan. No guessed high number or reusable asset ID.
        owner = resources if callable(getattr(resources, 'audio_binding_plan', None)) else getattr(resources, 'frozen', None)
        if not callable(getattr(owner, 'audio_binding_plan', None)):
            raise ValueError('人声重播需要当前目标的声音绑定计划，不能使用猜测的回看编号。')
        bindings = owner.audio_binding_plan()
        self.program = NativeVoiceBacklogProgram(contract, emitter.output, bindings, events,
            absolute_output=True, append_start=len(emitter.source), append_encoding='gbk')
        self.patches = []

    def restore(self):
        self.emitter.output.extend(_push_global(self.saved)
            +_pop_global(self.program.contract.voice_global)+b'\x08'+_pop_global(self.saved))

    def finalize(self, payload):
        image = bytearray(payload)
        self.patches = self.program.patch_image(image)
        return bytes(image)

    def validate_patches(self, payload, prefix):
        if not self.patches:
            raise ValueError('人声重播尚未连接到候选脚本，不能当作完整输出。')
        for patch in self.patches:
            at, old, new = patch['offset'], patch['expected'], patch['replacement']
            if payload[at:at+len(new)] != new:
                raise ValueError('人声重播调用在输出过程中发生变化。')
            if at < len(prefix):
                if self.emitter.source[at:at+len(old)] != old:
                    raise ValueError('人声重播补丁不属于当前原始脚本。')
                prefix[at:at+len(old)] = old

    def report(self):
        current = self.program.current
        return dict(schema='fvp-legacy-shared-voice-replay/1',
            shared_generic_replay=True, independent_entry_unchanged=True,
            voice_backlog_replay=bool(self.program.patches),
            voice_current_line_replay=bool(current and current.patches),
            voice_backlog=self.program.report(),
            voice_current_line=current.report() if current else None,
            voice_current_line_blocker=self.program.contract.current_blocker,
            original_history_global=self.program.contract.voice_global,
            private_saved_global=self.saved, original_history_restored=True,
            call_patches=[dict(offset=p['offset'], expected_hex=p['expected'].hex(),
                replacement_hex=p['replacement'].hex()) for p in self.patches],
            runtime_verified=False, save_load_verified=False)
