"""Reuse target-bound BGM/SE semantics in the fingerprinted legacy exporter.

Only candidate-owned tail globals are added. Original game files and the
legacy voice/text bridge are retained; native audio retention is shared with
generic exports whenever the emitter supplies a matched executable.
"""
from functools import lru_cache
from types import SimpleNamespace

from .gui_audio_program import event_values
from .gui_story_program import StoryVariableBank
from .hoshimemo_scene_hook import HOSHIMEMO_SCENE_HOOK_ABI
from .native_audio import NativeAudioBackend
from .native_audio_program import NativeAudioProgram
from .performance_compile import CLEAN_SHA, SOURCE_SHA, _baseline_document, sha


@lru_cache(maxsize=1)
def legacy_backend(source, clean):
    # The generic binder works from parsed original functions. The legacy
    # overlay is accepted ONLY as the existing whole-file fingerprinted pair,
    # not by hiding parser warnings or inventing a generic runtime context.
    if sha(source) != SOURCE_SHA or sha(clean) != CLEAN_SHA:
        raise ValueError('旧输出的声音调用与已审核脚本版本不一致。')
    document = _baseline_document(clean)
    native = NativeAudioBackend(SimpleNamespace(document=document,
        analysis_document=document, abi=HOSHIMEMO_SCENE_HOOK_ABI,
        target_id='legacy-audio-fingerprinted-pair'))
    for row in native.bindings.values():
        for start, (end, raw) in row['closure'].dependencies.items():
            if source[start:end] != raw:
                raise ValueError('旧输出的声音依赖与原版指令不一致。')
    return native


class LegacyAudioProgram(NativeAudioProgram):
    """Same runtime ownership/cache logic as generic export, absolute output."""
    def __init__(self, emitter, events, resources):
        selected = [e for e in events if e['kind'] in {'GuiBGM', 'GuiSE'}]
        if not selected:
            raise ValueError('声音程序没有音乐或音效。')
        for event in selected:
            event_values(event['kind'], {k: v for k, v in event.items() if k != 'kind'})
        self.native = legacy_backend(emitter.source, emitter.clean)
        kinds = sorted({'bgm' if e['kind'] == 'GuiBGM' else 'se' for e in selected})
        if any(kind not in self.native.bindings for kind in kinds):
            raise ValueError('旧输出目标未绑定所需声音类型。')
        self.output, self.bindings, self.base = emitter.output, resources, 0
        self.operations = []
        # The adapter owns no alternate audio-resume implementation. It uses
        # the same target-bound session as the generic paired export.
        self.backlog=self.voice_dialogue=self.voice_metadata_saved=None
        self.backlog_blocker=None
        session=getattr(emitter,'audio_resume_session',None)
        self.resume=session.binding if session else None
        self.resume_snapshot=session.snapshot if session else None
        self.resume_blocker=None if session else '此编译调用未提供配套原生音频状态接口。'
        self.resume_linked=False
        bank = getattr(emitter, 'story_bank', None)
        if bank is None:
            bank = emitter.story_bank = StoryVariableBank(emitter, {})
            bank.initialize()
        cells = bank.reserve_private(len(kinds) + int('bgm' in kinds),
            'legacy_audio_active')['private_global_ids']
        self.flags = dict(zip(kinds, cells))
        self.bgm_asset = cells[-1] if 'bgm' in kinds else None
        self.helpers = {kind: self.prepare_helper(kind) for kind in kinds}
        if any(e.get('fade_in_ms', 0) for e in selected):
            self.helpers['bgm_fade'] = self.prepare_helper('bgm', fade_in=True)

    def prepare_helper(self, kind, *, fade_in=False):
        # Native helpers normally follow their source HCB. The old exporter
        # has already appended private text helpers to a translated overlay.
        # Reserve that address gap in memory, then append ONLY the new bytes.
        gap = len(self.output) - len(self.native.source.original_bytes)
        if gap < 0:
            raise ValueError('旧输出的声音辅助函数地址不完整。')
        tail = bytearray(gap)
        helper = self.native.prepare(kind, tail, fade_in=fade_in)
        self.output.extend(tail[gap:])
        return helper

    def report(self):
        result = super().report()
        result.update(schema='fvp-legacy-target-bound-audio-program/1',
            legacy_fingerprint_required=True, shared_generic_playback=True)
        return result
