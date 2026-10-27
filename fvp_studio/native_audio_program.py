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


def audio_script_snapshot(native, reserve_private, *, extra_globals=()):
    """Shared cache snapshot for both relative and absolute script emitters."""
    ids=sorted(set(extra_globals).union(*(set(row['closure'].global_ids)
                                        for row in native.bindings.values())))
    header=native.source.header
    total=header.non_volatile_globals+header.volatile_globals
    if any(type(g) is not int or not 0 <= g < min(total,0x8000) for g in ids):
        raise ValueError('原剧情音频快照超出本目标变量范围。')
    private=(reserve_private(len(ids),'original_audio_script_state')['private_global_ids']
             if ids else [])
    if len(private)!=len(ids) or any(not total <= p <= 0x7fff for p in private):
        raise ValueError('原剧情音频快照没有独立的私有变量。')
    pairs=list(zip(ids,private))
    return dict(snapshot=b''.join(_push_global(g)+_pop_global(p) for g,p in pairs),
        restore=b''.join(_push_global(p)+_pop_global(g)+b'\x08'+_pop_global(p)
                         for g,p in reversed(pairs)),
        report=dict(global_ids=ids,private_global_ids=private,
                    maximum_transient_operand_values=int(bool(ids)),
                    private_cells_cleared_after_restore=True))


class NativeAudioProgram:
    @staticmethod
    def capture_original_audio(target,owner,native,output):
        """Capture before any authored stage initializer can call native code."""
        previous=getattr(owner,'audio_resume_capture',None)
        if previous is not None:
            if previous['output'] is not output or previous['native'] is not native:
                raise ValueError('音频原剧情快照不能跨编译复用。')
            return previous
        result=dict(output=output,native=native,binding=None,snapshot=None,blocker=None)
        if getattr(target,'executable',None):
            from .native_audio_resume import NativeAudioResumeBinding
            try:
                result['binding']=NativeAudioResumeBinding((target.root/target.executable).read_bytes())
            except (ValueError,OSError,KeyError) as exc:
                result['blocker']=str(exc)
            else:
                result['snapshot']=audio_script_snapshot(native,owner.snapshot_storage.reserve_private)
                output.extend(result['snapshot']['snapshot'])
                owner.native_audio_resume=result['binding']
        owner.audio_resume_capture=result
        return result

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
        captured=self.capture_original_audio(target,owner,self.native,output)
        self.resume,self.resume_snapshot=captured['binding'],captured['snapshot']
        self.resume_blocker=captured['blocker']
        self.resume_linked=False
        self.backlog = self.voice_dialogue = self.voice_metadata_saved = None
        self.backlog_blocker = None
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
        if 'voice' in kinds:
            from .native_voice_backlog import NativeVoiceBacklogProgram
            try:
                contract = self.native.voice.bind_backlog()
            except ValueError as exc:
                self.backlog_blocker = str(exc)
            else:
                # Never leave a half-emitted clone behind on a binding failure.
                # Only unsupported CONTRACTS fall back to line-only playback.
                self.voice_metadata_saved = owner.snapshot_storage.reserve_private(
                    1, 'scene_voice_history_original')['private_global_ids'][0]
                output.extend(_push_global(contract.voice_global)+_pop_global(self.voice_metadata_saved))
                self.voice_dialogue = owner.dialogue.for_voice(self.native.voice, output)
                self.backlog = NativeVoiceBacklogProgram(contract, output, bindings, selected)
                for dialogue in (owner.dialogue, self.voice_dialogue):
                    self.backlog.add_aliases(dialogue.mapping)

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
            op='line', native_wait=True, backlog_replay=self.backlog is not None, **action.report))
        # The scene-local printer skips the native numeric-file loader. The
        # actual imported path starts after initialization and before waiting.
        return b'\x09'+_pop_global(self.flags['voice'])+action.code

    def claim_native_movie_bgm(self):
        # Movie's byte-bound original wrapper performs AudioStop itself. Mark
        # that category as used only on the executed route, without stopping
        # it twice or leaving the "same authored BGM" cache stale afterwards.
        if 'bgm' not in self.flags or self.resume is None or self.bgm_asset is None:
            raise ValueError('影片没有配套的音乐通道所有权／原剧情续播接口。')
        self.output.extend(b'\x09'+_pop_global(self.flags['bgm'])+b'\x08'+_pop_global(self.bgm_asset))
        self.operations.append(dict(event_kind='GuiMovie', op='native_movie_bgm_stop',
                                    executed_route_only=True, duplicate_audio_stop_emitted=False))

    def voice_before_print(self, event):
        return self.backlog.before_print(event) if self.backlog else b''

    def voice_end(self):
        return (self.native.stop('voice',0).code+b'\x08'+_pop_global(self.flags['voice'])
                +(self.backlog.clear_line() if self.backlog else b''))

    def finish(self, *, restore_original=True):
        for kind,cell in self.flags.items():
            self.output.extend(_push_global(cell)+b'\x09\x22\x07')
            patch=len(self.output);self.output.extend(bytes(4))
            self.output.extend(self.native.stop(kind,0).code)
            self.output.extend(b'\x08'+_pop_global(cell))
            struct.pack_into('<I',self.output,patch,self.base+len(self.output))
        self.native.validate()
        if self.bgm_asset is not None:
            self.output.extend(b'\x08'+_pop_global(self.bgm_asset))
        if self.backlog is not None:
            self.output.extend(_push_global(self.voice_metadata_saved)
                +_pop_global(self.backlog.contract.voice_global)
                +b'\x08'+_pop_global(self.voice_metadata_saved))
        if self.resume_snapshot is not None and restore_original:
            # Pair with restoration of the retained native slot objects.
            # Clearing these IDs instead would break the native same-track
            # cache and the current/previous BGM channel selection on return.
            self.output.extend(self.resume_snapshot['restore'])

    def link_resume(self,bridge_report):
        if self.resume is None:
            return
        bound=bridge_report.get('native_audio_resume',{})
        if (bound.get('executable_sha256')!=self.resume.sha256
                or not bound.get('original_playback_restore_connected')
                or bound.get('native_registration_patch_count')!=len(self.resume.entries)):
            raise ValueError('音频脚本快照缺少同一目标的原生声音恢复接口。')
        self.resume_linked=True

    def report(self):
        native=self.native.report()
        native['original_audio_restore_connected']=self.resume_linked
        current = self.backlog.current if self.backlog else None
        return dict(schema=SCHEMA,native=native,operations=deepcopy(self.operations),
            playback=playback_contract(self.flags, voice_backlog_replay=bool(self.backlog and self.backlog.patches),
                voice_current_line_replay=bool(current and current.patches)),
            private_bgm_asset=self.bgm_asset,
            private_active_flags=deepcopy(self.flags),cleanup_only_executed_categories=True,
            scene_boundary_restarts_music=False,voice_connected='voice' in self.flags,
            voice_backlog_replay=bool(self.backlog and self.backlog.patches),
            voice_backlog=self.backlog.report() if self.backlog else None,
            voice_backlog_blocker=self.backlog_blocker,
            voice_current_line_replay=bool(current and current.patches),
            voice_current_line=current.report() if current else None,
            voice_current_line_blocker=self.backlog.contract.current_blocker if self.backlog else self.backlog_blocker,
            voice_history_original_restored=self.voice_metadata_saved is not None,
            voice_stop_on_line_advance=True,
            original_playback_restored=False,
            original_playback_restore_connected=self.resume_linked,
            original_audio_resume=self.resume.report() if self.resume else None,
            original_audio_resume_blocker=self.resume_blocker,
            original_audio_globals=self.resume_snapshot['report']['global_ids'] if self.resume_snapshot else [],
            save_load_verified=False,
            scene_export_connected=False,runtime_verified=False)
