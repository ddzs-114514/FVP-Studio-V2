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
    def __init__(self, scene, events, *, blur=None, motion=None, screen=None, background_launch=None):
        from .native_portrait_scene import NativePortraitScene
        from .native_scene_camera import NativeSceneCamera
        from .native_scene_background_blur import NativeSceneBackgroundBlur
        if not isinstance(scene, NativePortraitScene) or scene.snapshot_storage is None:
            raise ValueError('同拍舞台效果需要本目标配套的角色状态接口。')
        if (not events and background_launch is None) or any(e['kind'] not in {'CameraShot', 'GuiBackgroundBlur', 'Action', 'GuiActorSlide', 'Transition'}
                or e['kind']=='Action' and e.get('channels') not in {'alpha', 'parts'} for e in events):
            raise ValueError('同拍舞台提交只接受镜头、原作模糊、转场和其他角色的透明度、表情、滑动。')
        if len({(e['kind'],e.get('actor'),e.get('channels')) for e in events}) != len(events):
            raise ValueError('同拍舞台通道不能重复提交。')
        slides = {e['actor'] for e in events if e['kind']=='GuiActorSlide'}
        if (slides.intersection(e['actor'] for e in events if e['kind']=='Action' and e['channels']=='alpha')
                or motion is not None and any(scene.actors[a]==r.actor_id for a in slides for r in motion.rows)):
            raise ValueError('同拍滑入滑出已包含移动和透明度，滑动角色的其他动作请分拍。')
        self.loader, self.storage, self._source = scene.loader, scene.snapshot_storage, scene.source
        self.scene, self.camera, self.blur, self.motion = scene, scene.scene_camera, blur, motion
        self.alpha_slots = tuple(scene.loader.assignments[scene.actors[e['actor']]]
            for e in events if e['kind']=='GuiActorSlide' or e['kind']=='Action' and e['channels']=='alpha')
        self.parts_slots = tuple(scene.loader.assignments[scene.actors[e['actor']]]
            for e in events if e['kind']=='Action' and e['channels']=='parts')
        self.parts_ids = tuple(sorted({b['graph'] for slot in self.parts_slots
            for b in slot.evidence['dispatcher_handles']['buffers']}))
        self.alpha_ids = tuple(sorted({p for slot in self.alpha_slots for p in slot.primitive_ids}))
        self.slide_ids = tuple(sorted({p for a in slides
            for p in scene.loader.assignments[scene.actors[a]].primitive_ids}))
        self.primitive_ids = tuple(sorted(set(motion.primitive_ids if motion else ()) | set(self.alpha_ids)))
        self._context = scene.target.context
        chunks, globals_, post = [], set(), []
        self.parts_updates = []
        # Prepare the blur image BEFORE any launch, even if the GUI lists the
        # camera first. Its alpha helper is deferred, not its resource load.
        for event in sorted(events, key=lambda e: e['kind'] != 'GuiBackgroundBlur'):
            if event['kind'] == 'Transition':
                from .native_screen_transition import NativeSceneScreenTransition
                if not isinstance(screen, NativeSceneScreenTransition) or screen.target is not scene.target:
                    raise ValueError('换装同拍转场没有绑定当前目标。')
                chunks.append(screen.prepare_parallel(event))
                globals_.update(screen.binding.global_ids)
            elif event['kind'] == 'GuiBackgroundBlur':
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
            elif event.get('channels') == 'parts':
                actor = event['actor']
                if actor not in scene.states or (actor, 'parts') in scene.pending:
                    raise ValueError('同拍表情需要已准备、没有上一拍残留表情运动的角色。')
                actor_id = scene.actors[actor]
                active = scene.loader._active.get(actor_id)
                frame, duration = event['expression'], event['duration_ms']
                if (active is None or type(frame) is not int or not 0 <= frame < active['frames']
                        or type(duration) is not int or not 0 <= duration <= 6000):
                    raise ValueError('同拍表情帧或时长越界。')
                slot = scene.loader.assignments[actor_id]
                binding = scene.loader.expression_bindings[slot.selector]
                frame_globals = [binding[k] for k in ('pending_frame_global_id', 'committed_frame_global_id')]
                name = 'PartsMotion' if duration else 'PartsSelect'
                operands = [scene.loader._active_parts(slot), _encode_push(frame, self._source.encoding)]
                if duration:
                    operands.append(_encode_push(duration, self._source.encoding))
                chunks.append(scene.loader._syscall(name, operands))
                globals_.update(frame_globals)
                post.extend(_encode_push(frame, self._source.encoding) + _pop_global(g) for g in frame_globals)
                self.parts_updates.append(dict(actor_id=actor_id, frame=frame, duration_ms=duration,
                    native_call=name, body_reloaded=False, native_geometry_changed=False,
                    native_expression_state_updated=True, native_binding=dict(binding)))
                scene.states[actor]['expression'] = frame
                if duration:
                    scene.pending[actor, 'parts'] = True
            else:
                actor = event['actor']
                state = scene.states.get(actor)
                if state is None or scene.alpha is None or (actor,'alpha') in scene.pending:
                    raise ValueError('同拍淡入淡出需要已准备、无上一拍残留运动的角色。')
                chunks.append(scene.alpha.compile(scene.prim(actor),state['alpha'],event['alpha'],event['duration_ms']))
                globals_.update(scene.alpha.global_ids)
                state['alpha'] = event['alpha']
                scene.pending[actor,'alpha'] = True
        if background_launch is not None:
            from .native_screen_transition import NativeSceneScreenTransition
            if (not isinstance(screen, NativeSceneScreenTransition) or screen.target is not scene.target
                    or not isinstance(background_launch, bytes) or not background_launch
                    or screen.parallel_event is None or screen.parallel_event['kind'] != 'BackgroundReveal'
                    or any(e['kind'] == 'Transition' for e in events)):
                raise ValueError('同拍背景渐变没有绑定当前目标的唯一转场。')
            chunks.append(background_launch)
            globals_.update(screen.binding.global_ids)
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
            self.alpha_ids,self.parts_ids,self.parts_updates,self.slide_ids,self.motion))

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
        for slot in (*self.alpha_slots, *self.parts_slots):
            primitive = self.loader._active_primitive(slot)
            guards.append(primitive+_encode_push(slot.primitive_ids[0],'shift_jis')+b'\x22'
                +primitive+_encode_push(slot.primitive_ids[1],'shift_jis')+b'\x22\x21')
        return b''.join(g+(b'\x20' if i else b'') for i,g in enumerate(guards)) if guards else b'\x09'

    def protected_primitives(self,name):
        if name == 'PartsMotion':
            return self.parts_ids
        if name in {'MotionAlpha','MotionAlphaStop'}:
            return self.alpha_ids
        return tuple(sorted(set(self.motion.primitive_ids if self.motion is not None else ())
            | set(self.slide_ids)))

    def assert_excludes(self, slots):
        self.check(self.loader, self._source)
        if self.motion is not None:
            self.motion.assert_excludes(slots)
        if any(slots_conflict(a,b) for a in (*self.alpha_slots, *self.parts_slots) for b in slots):
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
        # Do not mutate loader revisions while its prepared swap rows are in
        # flight. Commit independent expression caches after that transaction.
        for row in self.parts_updates:
            self.loader._active[row['actor_id']]['expression'] = row['frame']
            self.loader.expressions.append(deepcopy(row))
            self.loader._state_revision += 1

    def report(self):
        self.check(self.loader, self._source)
        return dict(schema='fvp-native-scene-parallel-effects/1',
            events=deepcopy(self.events), source_sha256=self._source.source_sha256,
            kicked_global=self.kicked_global, primitive_ids=self.primitive_ids,
            native_apply_frontier=True, nonblocking=True, original_apply_preserved=True,
            native_caches_isolated_during_apply=True, runtime_verified=False,
            other_motion=self.motion.report() if self.motion is not None else None)
