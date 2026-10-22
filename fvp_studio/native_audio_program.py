"""BGM/SE/voice lifetime within a paired generic scene.

An unselected branch must not stop original audio merely because it contained
a sound event. Private runtime flags track the categories actually used.
Voice uses its own native line slot/wait, never an SE downgrade. Backlog replay
and original playback restoration remain explicitly separate capabilities.
"""
from copy import deepcopy
import struct

from .gui_audio_program import event_values, playback_contract
from .hoshimemo_scene_hook import _arguments, _push_global, _pop_global

KINDS = {'GuiBGM','GuiSE','GuiVoiceLine'}
SCHEMA = 'fvp-native-audio-program/1'


class NativeAudioProgram:
    def __init__(self, target, owner, events, output, bindings):
        if (owner is None or owner.target is not target or owner.snapshot_storage is None
                or owner.snapshot_storage.handoff.source is not target.context.document
                or bindings.native.context is not target.context or bindings.root != target.root
                or not isinstance(output,bytearray)):
            raise ValueError('通用声音需要同一目标的场景状态及素材绑定。')
        selected=[e for e in events if e['kind'] in KINDS]
        if not selected:
            raise ValueError('声音程序缺少音乐、音效或配音台词。')
        if any(e['kind']=='GuiVoiceLine' for e in selected) and 'voice' not in bindings.native.bindings:
            raise ValueError('此目标台词语音尚未匹配，不能按音效降级播放。')
        for e in selected:
            if e['kind'] == 'GuiVoiceLine':
                from .gui_voice_program import event_values as voice_values
                voice_values({k:v for k,v in e.items() if k!='kind'}, encoding=None)
            else:
                event_values(e['kind'],{k:v for k,v in e.items() if k!='kind'})
        self.target,self.owner,self.output,self.bindings=target,owner,output,bindings
        self.native=bindings.native
        self.base=len(target.context.document.original_bytes)
        self.operations=[]
        kinds=sorted({{'GuiBGM':'bgm','GuiSE':'se','GuiVoiceLine':'voice'}[e['kind']] for e in selected})
        if any(k not in self.native.bindings for k in kinds):
            raise ValueError('目标未绑定本场景使用的声音类型。')
        cells=owner.snapshot_storage.reserve_private(len(kinds)+int('bgm' in kinds),
            'scene_audio_active')['private_global_ids']
        self.flags=dict(zip(kinds,cells))
        self.bgm_asset=cells[-1] if 'bgm' in kinds else None
        for cell in cells:
            output.extend(b'\x08'+_pop_global(cell))
        self.helpers={kind:self.native.prepare(kind,output) for kind in kinds}
        if 'voice' in kinds and getattr(owner, 'guard', None) is not None:
            self.native.voice.bind_wait_guard(owner.guard, self.helpers['voice'])
        if any(e.get('fade_in_ms',0) for e in selected):
            self.helpers['bgm_fade']=self.native.prepare('bgm',output,fade_in=True)

    def unless_equal(self, cell, value, body):
        """Runtime branch, so skipped routes never mutate audio ownership."""
        self.output.extend(_push_global(cell)+_arguments([value])+b'\x22\x07')
        enter=len(self.output);self.output.extend(bytes(4)+b'\x06')
        done=len(self.output);self.output.extend(bytes(4))
        struct.pack_into('<I',self.output,enter,self.base+len(self.output))
        self.output.extend(body)
        struct.pack_into('<I',self.output,done,self.base+len(self.output))

    def emit(self,event):
        if event.get('kind') not in {'GuiBGM','GuiSE'}:
            raise ValueError('这类声音事件尚未接入。')
        kind='bgm' if event['kind']=='GuiBGM' else 'se'
        fields=event_values(event['kind'],{k:v for k,v in event.items() if k!='kind'})
        if kind not in self.flags:
            raise ValueError('声音事件不属于此场景的分配。')
        if fields['op']=='keep':
            self.operations.append(dict(event_kind=event['kind'],op='keep',emits_audio_calls=False))
            return
        if fields['op']=='volume':
            action=self.native.volume(fields['volume'],fields['duration_ms'])
            self.unless_equal(self.bgm_asset,None,action.code)
            self.operations.append(dict(event_kind=event['kind'],op='volume',owned_active_bgm_only=True,**action.report))
            return
        if fields['op'] in ('play','restart'):
            binding=self.bindings.audio(event)
            fade=fields.get('fade_in_ms',0)
            helper=self.helpers['bgm_fade' if fade else kind]
            action=self.native.play(helper,binding,volume=fields['volume'],loop=fields['loop'],
                duration_ms=fields['duration_ms'],fade_in_ms=fade)
            body=b'\x09'+_pop_global(self.flags[kind])+action.code
            if kind=='bgm':
                body+=_arguments([binding['native_id']])+_pop_global(self.bgm_asset)
            if kind=='bgm' and fields['op']=='play':
                # Private identity, NOT the original story's numeric cache:
                # an unrelated original resource can have the same number.
                self.unless_equal(self.bgm_asset,binding['native_id'],body)
            else:
                self.output.extend(body)
        else:
            action=self.native.stop(kind,fields['duration_ms'])
            self.output.extend(b'\x09'+_pop_global(self.flags[kind])+action.code)
            if kind=='bgm':
                self.output.extend(b'\x08'+_pop_global(self.bgm_asset))
        self.operations.append(dict(event_kind=event['kind'],op=fields['op'],**action.report))

    def voice_start(self, event):
        from .gui_voice_program import event_values as voice_values
        if event.get('kind') != 'GuiVoiceLine' or 'voice' not in self.flags:
            raise ValueError('此目标没有接入当前配音台词。')
        fields = voice_values({k:v for k,v in event.items() if k != 'kind'}, encoding=None)
        action = self.native.play(self.helpers['voice'], self.bindings.audio(event), volume=fields['volume'])
        self.operations.append(dict(event_kind='GuiVoiceLine', line_id=fields['line_id'],
            op='line', native_wait=True, backlog_replay=False, **action.report))
        # This runs after the native print initialization but before native
        # wait. Do not forge an original voice-ID/backlog record for our path.
        return b'\x09'+_pop_global(self.flags['voice'])+action.code

    def voice_end(self):
        return self.native.stop('voice',0).code+b'\x08'+_pop_global(self.flags['voice'])

    def finish(self):
        for kind,cell in self.flags.items():
            self.output.extend(_push_global(cell)+b'\x09\x22\x07')
            patch=len(self.output);self.output.extend(bytes(4))
            self.output.extend(self.native.stop(kind,0).code)
            self.output.extend(b'\x08'+_pop_global(cell))
            struct.pack_into('<I',self.output,patch,self.base+len(self.output))
        self.native.validate()
        if self.bgm_asset is not None:
            self.output.extend(b'\x08'+_pop_global(self.bgm_asset))

    def report(self):
        return dict(schema=SCHEMA,native=self.native.report(),operations=deepcopy(self.operations),
            playback=playback_contract(self.flags),private_bgm_asset=self.bgm_asset,
            private_active_flags=deepcopy(self.flags),cleanup_only_executed_categories=True,
            scene_boundary_restarts_music=False,voice_connected='voice' in self.flags,
            voice_backlog_replay=False,voice_stop_on_line_advance=True,
            original_playback_restored=False,save_load_verified=False,
            scene_export_connected=False,runtime_verified=False)
