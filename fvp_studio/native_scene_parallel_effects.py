"""Target-bound camera/blur launches at the portrait apply's alpha frontier.

Resource preparation happens before the carrier transaction. Only proven
nonblocking helpers run at the frontier; their script caches are isolated from
the intact native apply, then the authored caches are committed after it.
"""
from copy import deepcopy
from dataclasses import dataclass
import struct

from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_portrait_acceptance import NativePortraitAcceptanceError
from .native_portrait_slots import slots_conflict
from .native_portrait_parallel_motion import _signature
from .portrait_emitter import _encode_push


@dataclass(frozen=True)
class _Plan:
    entry_address: int
    code: bytes
    _report: dict

    def report(self):
        return deepcopy(self._report)


class NativeSceneParallelEffects:
    def __init__(self, scene, events, *, blur=None, motion=None):
        from .native_portrait_scene import NativePortraitScene
        from .native_scene_camera import NativeSceneCamera
        from .native_scene_background_blur import NativeSceneBackgroundBlur
        if not isinstance(scene, NativePortraitScene) or scene.snapshot_storage is None:
            raise ValueError('同拍舞台效果需要本目标配套的角色状态接口。')
        if not events or any(e['kind'] not in {'CameraShot', 'GuiBackgroundBlur', 'Action', 'GuiActorSlide'}
                or e['kind']=='Action' and e.get('channels')!='alpha' for e in events):
            raise ValueError('同拍舞台提交只接受镜头、原作模糊和其他角色的淡入淡出或滑入滑出。')
        if len({(e['kind'],e.get('actor')) for e in events}) != len(events):
            raise ValueError('同拍舞台通道不能重复提交。')
        slides = {e['actor'] for e in events if e['kind']=='GuiActorSlide'}
        if (slides.intersection(e['actor'] for e in events if e['kind']=='Action')
                or motion is not None and any(scene.actors[a]==r.actor_id for a in slides for r in motion.rows)):
            raise ValueError('同拍滑入滑出已包含移动和透明度，滑动角色的其他动作请分拍。')
        self.loader, self.storage, self._source = scene.loader, scene.snapshot_storage, scene.source
        self.scene, self.camera, self.blur, self.motion = scene, scene.scene_camera, blur, motion
        self.alpha_slots = tuple(scene.loader.assignments[scene.actors[e['actor']]]
            for e in events if e['kind'] in {'Action','GuiActorSlide'})
        self.alpha_ids = tuple(sorted({p for slot in self.alpha_slots for p in slot.primitive_ids}))
        self.slide_ids = tuple(sorted({p for a in slides
            for p in scene.loader.assignments[scene.actors[a]].primitive_ids}))
        self.primitive_ids = tuple(sorted(set(motion.primitive_ids if motion else ()) | set(self.alpha_ids)))
        self._context = scene.target.context
        chunks, globals_, post = [], set(), []
        # Prepare the blur image BEFORE any launch, even if the GUI lists the
        # camera first. Its alpha helper is deferred, not its resource load.
        for event in sorted(events, key=lambda e: e['kind'] != 'GuiBackgroundBlur'):
            if event['kind'] == 'GuiBackgroundBlur':
                if not isinstance(blur, NativeSceneBackgroundBlur) or blur.target is not scene.target:
                    raise ValueError('同拍模糊没有绑定当前目标。')
                chunks.append(blur.prepare_event(event))
                globals_.update(blur.binding.closure.global_ids)
                post.append(blur.binding.cache_code(blur.current['alpha']))
            elif event['kind']=='CameraShot':
                camera = self.camera
                if not isinstance(camera, NativeSceneCamera) or camera.source is not self._source or camera.pending:
                    raise ValueError('同拍镜头须先结束上一拍的运动，并绑定当前目标。')
                start = len(scene.output)
                camera.emit(event, scene.states.values())
                chunks.append(bytes(scene.output[start:]))
                del scene.output[start:]
                globals_.update(camera.global_ids)
                post.extend(_encode_push(v, self._source.encoding) + _pop_global(g)
                    for g, v in zip(camera.cache_slots, camera.logical_coordinates(camera.current)))
            elif event['kind']=='GuiActorSlide':
                actor = event['actor']
                if (actor not in scene.states or scene.alpha is None or scene.motion is None
                        or any(a==actor for a,_ in scene.pending)
                        or event.get('phase') not in {'enter','exit'}
                        or event.get('direction') not in {'left','right'}):
                    raise ValueError('同拍滑入滑出需要本目标原生移动/透明度和无残留运动的已准备角色。')
                if event['phase']=='enter' and scene.states[actor]['alpha']!=0:
                    raise ValueError('同拍滑入须先以透明状态准备角色，不能让在场角色突然跳到画外。')
                # Compile the ordinary target-native slide once, but defer ALL
                # of it (including an entrant's off-screen XY placement) to
                # the swap alpha frontier. No pending track means emit adds
                # no join/wait here; size, depth and pivot stay untouched.
                start = len(scene.output)
                scene.emit(event)
                chunks.append(bytes(scene.output[start:]))
                del scene.output[start:]
                globals_.update(scene.alpha.global_ids)
                globals_.update(scene.motion.global_ids)
            else:
                actor = event['actor']
                state = scene.states.get(actor)
                if state is None or scene.alpha is None or (actor,'alpha') in scene.pending:
                    raise ValueError('同拍淡入淡出需要已准备、无上一拍残留运动的角色。')
                chunks.append(scene.alpha.compile(scene.prim(actor),state['alpha'],event['alpha'],event['duration_ms']))
                globals_.update(scene.alpha.global_ids)
                state['alpha'] = event['alpha']
                scene.pending[actor,'alpha'] = True
        self.launch_code = b''.join(chunks)
        self.cache_commit = b''.join(post)
        self.global_ids = tuple(sorted(globals_))
        self.events = deepcopy(events)
        self.kicked_global = self.storage.reserve_private(1,
            'scene_parallel_effects:'+str(len(self.storage.groups)))['private_global_ids'][0]
        self.reset_code = b'\x08' + _pop_global(self.kicked_global)
        if motion is not None:
            self.reset_code += motion.reset_code
        self._seal = self._signature()
        self.check(self.loader, self._source)

    def _signature(self):
        return _signature((self.launch_code, self.cache_commit, self.global_ids,
            self.events, self.kicked_global, self.reset_code, self.primitive_ids,
            self.alpha_ids,self.slide_ids,self.motion))

    def check(self, loader, document):
        if (loader is not self.loader or document is not self._source
                or self.storage.handoff.context is not self._context
                or self._context.document is not document or self._signature() != self._seal):
            raise NativePortraitAcceptanceError('同拍舞台提交的来源或计划发生变化。')
        loader._check(document)
        self.storage.validate(self.storage.handoff)
        if self.motion is not None:
            self.motion.check(loader, document)

    def runtime_guard_code(self):
        self.check(self.loader, self._source)
        guards = [self.motion.runtime_guard_code()] if self.motion is not None else []
        for slot in self.alpha_slots:
            primitive = self.loader._active_primitive(slot)
            guards.append(primitive+_encode_push(slot.primitive_ids[0],'shift_jis')+b'\x22'
                +primitive+_encode_push(slot.primitive_ids[1],'shift_jis')+b'\x22\x21')
        return b''.join(g+(b'\x20' if i else b'') for i,g in enumerate(guards)) if guards else b'\x09'

    def protected_primitives(self,name):
        if name in {'MotionAlpha','MotionAlphaStop'}:
            return self.alpha_ids
        return tuple(sorted(set(self.motion.primitive_ids if self.motion is not None else ())
            | set(self.slide_ids)))

    def assert_excludes(self, slots):
        self.check(self.loader, self._source)
        if self.motion is not None:
            self.motion.assert_excludes(slots)
        if any(slots_conflict(a,b) for a in self.alpha_slots for b in slots):
            raise ValueError('换装的两张缓冲图不能同时使用另一条透明度轨道；请分拍。')
        if self.blur is not None:
            self.blur.binding.assert_portrait_ownership(slots)

    def prepare(self, document, helper_address):
        self.check(self.loader, document)
        if type(helper_address) is not int or not len(document.original_bytes) <= helper_address < 2**31:
            raise ValueError('同拍效果入口不在本脚本附加区。')
        guard = self.runtime_guard_code()
        code = bytearray(b'\x01\0\0' + guard + b'\x07\0\0\0\0')
        failure = len(code)-4
        motion_call = motion_failure = None
        if self.motion is not None:
            code.extend(b'\x02\0\0\0\0\x14\x09\x22\x07\0\0\0\0')
            motion_call, motion_failure = len(code)-12, len(code)-4
        code.extend(b''.join(_push_global(g) for g in self.global_ids))
        code.extend(self.launch_code)
        code.extend(b''.join(_pop_global(g) for g in reversed(self.global_ids)))
        code.extend(b'\x09' + _pop_global(self.kicked_global) + b'\x09\x05')
        rejected = helper_address + len(code)
        struct.pack_into('<I', code, failure, rejected)
        if motion_failure is not None:
            struct.pack_into('<I', code, motion_failure, rejected)
        code.extend(b'\x08\x05')
        if motion_call is not None:
            plan = self.motion.prepare(document, helper_address+len(code))
            struct.pack_into('<I', code, motion_call, plan.entry_address)
            code.extend(plan.code)
        return _Plan(helper_address, bytes(code), self.report())

    def commit_caches(self, output):
        self.check(self.loader, self._source)
        output.extend(self.cache_commit)

    def report(self):
        self.check(self.loader, self._source)
        return dict(schema='fvp-native-scene-parallel-effects/1',
            events=deepcopy(self.events), source_sha256=self._source.source_sha256,
            kicked_global=self.kicked_global, primitive_ids=self.primitive_ids,
            native_apply_frontier=True, nonblocking=True, original_apply_preserved=True,
            native_caches_isolated_during_apply=True, runtime_verified=False,
            other_motion=self.motion.report() if self.motion is not None else None)
