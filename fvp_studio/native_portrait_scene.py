"""Bind native portraits to an interleaved, target-owned GUI scene stream.

Keeps the existing source-size bridge unchanged. All carrier clone addresses
are placed after the CURRENT output cursor, including intervening dialogue.
Native state snapshots are not a claim to restore the previous story's images.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import math
from pathlib import Path
import struct

from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_portrait_alpha import NativePortraitAlpha
from .native_portrait_acceptance import (
    NativePortraitAcceptanceError, _function_spans, _camera_z,
    _embedded_v3d_camera, _extract_direct_xy_scales, _instructions_in_range, _negative_default,
)
from .native_portrait_geometry import NativePortraitGeometry, _round
from .native_portrait_loading import NativePortraitLoading
from .native_portrait_swap_apply import NativePortraitSwapApply
from .native_portrait_carrier_retention import NativePortraitCarrierRetention
from .native_portrait_motion import NativePortraitMotion, _converted_coordinate
from .native_stage_baseline import native_default_camera, NativeStageBaselineUnavailable
from .camera_zoom_limits import camera_near_z
from .native_script_state import NativeScriptStateClosure
from .native_portrait_dialogue import NativePortraitDialogue
from .performance_compile import resource_reference
from .portrait_emitter import _encode_push
from .gui_cg_stage_handoff import POSE_KIND, pose_values
from .gui_actor_sway import KINDS as SWAY_KINDS


KINDS = {"Portrait", "GuiActorSwap", "Hide", "Action", "GuiActorMove", "GuiActorSlide", POSE_KIND} | SWAY_KINDS
TESTS = {"alpha": "MotionAlphaTest", "xy": "MotionMoveTest", "z": "MotionMoveZTest",
         "s2": "MotionMoveS2Test", "r": "MotionMoveRTest", "parts": "PartsMotionTest"}


def _with_native_snapshot(lifecycle, binding, kind):
    """Include the bound helper's native cache writes before any scene call."""
    lifecycle = deepcopy(lifecycle)
    report = lifecycle["report"]
    existing = list(report.get("global_ids", ()))
    extra = sorted(set(binding.global_ids) - set(existing))
    lifecycle["snapshot"] += b"".join(_push_global(g) for g in extra)
    lifecycle["restore"] = b"".join(_pop_global(g) for g in reversed(extra)) + lifecycle["restore"]
    report.update(global_ids=existing + extra, operand_stack_value_count=len(existing) + len(extra))
    report["native_" + kind + "_global_writes_included"] = True
    report["additional_" + kind + "_global_ids"] = extra
    report.setdefault("code_sha256", {}).update({
        name: hashlib.sha256(lifecycle[name]).hexdigest() for name in ("snapshot", "restore")})
    return lifecycle


def _with_alpha_snapshot(lifecycle, alpha):
    return _with_native_snapshot(lifecycle, alpha, "alpha")


def _with_private_snapshot(lifecycle, storage, source):
    """Keep long-lived portrait state off the finite VM operand stack.

    The whole-scene assembler alone owns the added volatile cells/header.
    Ordinary portrait-only output keeps its existing bytecode unchanged.
    """
    if storage.handoff.source is not source:
        raise ValueError("角色状态暂存必须属于同一份原生场景。")
    result = deepcopy(lifecycle)
    # Alpha/motion closures can append lower-numbered globals. Reorder before
    # emission, not after values have been pushed; each global is independent.
    ids = sorted(set(result['report']['global_ids']))
    result['report']['global_ids'] = ids
    result['snapshot'] = b''.join(_push_global(g) for g in ids)
    result['restore'] = b''.join(_pop_global(g) for g in reversed(ids))
    result.update(storage.reserve(result, 'scene_portraits'))
    return result


class NativePortraitScene:
    def __init__(self, target, events, anchor, imports, output, *, motion_contract=None, scene_camera=None,
                 rotation_contract=None, cg_guard=None, snapshot_storage=None, slot_catalog=None):
        self.target, self.source, self.analysis = target, target.context.document, target.context.analysis_document
        self.blend_abort_positions = []
        self.motion_groups = []
        self.blend_abort_target = None
        self.snapshot_storage = snapshot_storage
        self.rotation_contract = rotation_contract
        if rotation_contract is not None:
            rotation_contract.assert_target(target)
        self.imports, self.output = imports, output
        actor_numbers = sorted({e["portrait"]["actor"] if e["kind"] == "GuiActorSwap" else e["actor"]
                                for e in events if e["kind"] in KINDS})
        if not actor_numbers or any(type(a) is not int or not 1 <= a <= 4 for a in actor_numbers):
            raise ValueError("场景立绘需要稳定的角色槽编号。")
        self.actors = {a: "scene_actor_" + str(a) for a in actor_numbers}
        self.loader = NativePortraitLoading(self.source, self.analysis, target.discovery,
            tuple(self.actors.values()), runtime_context=target.context,
            **(dict(catalog=slot_catalog) if slot_catalog is not None else {}))
        namespace = self.loader._record["resource_namespace"].rstrip("/\\").casefold() + ".bin"
        if not imports or namespace not in imports.routes.get("portrait", {}):
            raise ValueError("场景立绘没有绑定目标载体自己的资源包。")
        # Clear every discovered independent carrier at scene entry, not just
        # the selected actor. Unresolved engine resources remain an explicit
        # limitation; they are never described as a restored original scene.
        self.lifecycle = self.loader.catalog.compile_known_entry_lifecycle(self.source)
        self.alpha = None
        if any(e["kind"] == "GuiActorSlide" or e["kind"] == "Action"
               and "alpha" in e["channels"].split("+") for e in events):
            self.alpha = NativePortraitAlpha(self.source, self.analysis, runtime_context=target.context)
            self.lifecycle = _with_alpha_snapshot(self.lifecycle, self.alpha)
        motion_channels = set()
        for event in events:
            if event['kind'] in SWAY_KINDS:
                if event['kind'] == 'GuiActorSwayStart':
                    motion_channels.add('xy' if event.get('axis', 'r') == 'y' else 'r')
            elif event["kind"] in {"GuiActorMove", "GuiActorSlide"}:
                motion_channels.add("xy")
            elif event["kind"] == "Action":
                motion_channels.update(set(event["channels"].split("+")) - {"parts", "alpha"})
            elif event["kind"] == POSE_KIND and rotation_contract is not None:
                # A target's RS setter can wrap negative R. Retain the same
                # signed-angle correction used by native body loading.
                motion_channels.add("r")
        self.motion = (NativePortraitMotion(self.source, self.analysis, motion_channels,
                                            runtime_context=target.context) if motion_channels else None)
        if self.motion:
            self.lifecycle = _with_native_snapshot(self.lifecycle, self.motion, "motion")
        spans = _function_spans(self.analysis)
        mode = self.loader._record.get("geometry_mode")
        if mode == "direct_xy_wrapper":
            direct = target.discovery["profile_seed"]["native_symbols"]["direct_xy"]
            xy = _instructions_in_range(self.analysis, int(direct["start"]), int(direct["end"]))
            factors = _extract_direct_xy_scales(xy, self.analysis.syscall_names)
            camera_z, _setter = _camera_z(spans, self.analysis.syscall_names, *factors)
            defaults = []
            for span in spans:
                for i, item in enumerate(span.instructions):
                    operands = span.instructions[i - 3:i] if i >= 3 else ()
                    if (item.mnemonic == "call" and item.operands["target"] == _setter
                            and len(operands) == 3 and all(x.mnemonic == "push_stack" for x in operands)
                            and _negative_default(span.instructions, operands[-1].operands["value"]) is not None):
                        defaults.append(span.start)
            _proof = dict(strategy="target_wrapped_camera_default", setter=_setter,
                source_dependencies=NativeScriptStateClosure(self.source, self.analysis,
                    sorted(set([_setter, *defaults])), runtime_context=target.context).describe())
            camera = (0, 0, camera_z)
        elif mode == "embedded_xy":
            try:
                camera, _proof = native_default_camera(self.source, self.analysis,
                                                       runtime_context=target.context)
            except NativeStageBaselineUnavailable:
                camera, _proof = _embedded_v3d_camera(spans, self.analysis.syscall_names,
                                                      anchor_offset=anchor["patch"]["patch_offset"])
                # The older invariant is derived from native function markers.
                # Match those complete mutators with the actual runtime image,
                # including reachable callees, even for a translated overlay.
                roots = {int(s["function_start"]) for s in (*_proof["literal_sites"], *_proof["dynamic_sites"])}
                _proof = dict(_proof, source_dependencies=NativeScriptStateClosure(
                    self.source, self.analysis, sorted(roots), runtime_context=target.context).describe())
        else:
            raise ValueError("目标立绘坐标结构尚未识别。")
        self.geometry = NativePortraitGeometry.from_executable(
            (target.root / target.executable).read_bytes(), self.analysis.header.game_mode, camera=camera)
        if scene_camera is not None and (self.geometry.camera != scene_camera.baseline
                                         or self.geometry.viewport != scene_camera.viewport):
            raise ValueError("镜头与立绘没有使用同一份目标舞台基准。")
        self.scene_camera = scene_camera
        self.camera_evidence = _proof
        self.cursor, self.states, self.pending, self.references, self.geometry_reports = 0, {}, {}, [], []
        if snapshot_storage is not None:
            self.lifecycle = _with_private_snapshot(self.lifecycle, snapshot_storage, self.source)
        self.output.extend(self.lifecycle["snapshot"] + self.lifecycle["clear"])
        self.reset_camera()
        self.dialogue = NativePortraitDialogue(target.context,
            target.discovery["profile_seed"]["native_symbols"]["portrait_lifecycle_family"], self.output,
            cg_guard=cg_guard)

    def syscall(self, name, operands):
        return self.loader._syscall(name, operands)

    def reset_camera(self):
        scene_camera = getattr(self, "scene_camera", None)
        if scene_camera is not None:
            scene_camera.restore_current()
        else:
            self.output.extend(self.syscall("V3DSet", [self.push(v) for v in self.geometry.camera]))

    @staticmethod
    def push(value):
        return _encode_push(value, "shift_jis")

    def prim(self, actor):
        return self.loader._active_primitive(self.loader.assignments[self.actors[actor]])

    def parts(self, actor):
        return self.loader._active_parts(self.loader.assignments[self.actors[actor]])

    def sync_loader(self):
        self.output.extend(self.loader.code[self.cursor:])
        self.cursor = len(self.loader.code)

    def rebase_loader(self):
        self.loader.base = len(self.source.original_bytes) + len(self.output) - len(self.loader.code)

    def runtime_arguments(self):
        runtime = [min(self.loader.form_suffixes), *([None] * (self.loader._layout.runtime_count - 1))]
        if len(runtime) == 10:
            runtime[-1] = 0
        return runtime

    def body_swap_capability(self):
        """Bind the target's own apply and carrier, without loading any image."""
        proofs = []
        for actor_id in self.loader.assignments:
            apply = NativePortraitSwapApply(self.loader, actor_id, catalogue_only=True)
            retention = NativePortraitCarrierRetention(self.loader, actor_id, catalogue_only=True)
            proof = retention.probe(self.source, runtime_arguments=self.runtime_arguments())
            proofs.append(dict(selector=apply.slot.selector, native_apply=apply.root,
                native_alpha=apply.alpha.address, retention=proof.report()))
        return dict(supported=bool(proofs), default_ms=200, minimum_ms=1, maximum_ms=6000,
            preserves_nonuniform_scale=self.loader._syscalls.get('PrimSetRS2',(None,None))[1]==4,
            native_binding=dict(slots=proofs), runtime_verified=False)

    def load(self, event, *, swapping=False, duration_ms=0, native_rotation=0,
             preserve_transform=None, preserve_scale_axes=None, parallel_events=None,
             parallel_base_scale=None, _batch_prepare=False):
        actor = event["actor"]
        if type(duration_ms) is not int or not 0 <= duration_ms <= 6000:
            raise ValueError("换装时长应为 0～6000ms 的整数。")
        if not swapping and actor in self.states:
            raise ValueError("已在场角色不能再次加载。")
        self.join(actor)
        body, body_ref = resource_reference(event["archive"], event["body"])
        face, face_ref = resource_reference(event["archive"], event["body"] + "_表情")
        fields, report = self.geometry.portrait(event, body)
        # KEEP within one source archive retains the original PrimSetOP / XY /
        # RS. The new bitmap's crop offset then positions it in the same source
        # space, without aligning heads or forcing unlike crop bottoms equal.
        if preserve_transform is not None:
            fields.update(pivot=list(preserve_transform['pivot']),
                          x=preserve_transform['x'], y=preserve_transform['y'],
                          scale=preserve_transform['sy'])
        if preserve_scale_axes is not None:
            sx, sy = preserve_scale_axes
            if any(type(v) is not int or not self.geometry.scale_range[0] <= v <= self.geometry.scale_range[1]
                   for v in (sx, sy)):
                raise ValueError("保留的两轴缩放超出目标原生范围；不会夹紧或改成等比。")
            fields["scale"] = sy
            if sx != sy:
                fields.update(scale_x=sx, scale_y=sy)
            if preserve_transform is None:
                # Cross-source KEEP uses the new bitmap's own origin, while
                # retaining both raw scale axes and the authored anchor.
                fields["x"], fields["y"] = self.geometry.native_xy(
                    dict(fields, sx=sx, sy=sy), event["stage_x"], event["bottom_y"])
        report['source_origin_preserved'] = preserve_transform is not None
        # The native emitter consumes raw R, not degrees.
        if type(native_rotation) is not int or not -1000 <= native_rotation <= 1000:
            raise ValueError("原生旋转必须是 -1000～1000 的整数单位；不是角度。")
        fields["rotation"] = native_rotation
        if self.scene_camera is not None and fields["z"] - camera_near_z(self.scene_camera) < 64:
            raise ValueError("新立绘的景深不能位于当前镜头后方。")
        runtime = self.runtime_arguments()
        self.rebase_loader()
        recover_rotation = bool(self.rotation_contract and self.rotation_contract.setter_changes_angle(native_rotation))
        parallel, parallel_state, parallel_channels = None, {}, []
        if swapping and duration_ms:
            old = self.states[actor]
            old_fields = {key:deepcopy(old[key]) for key in ("pivot", "x", "y", "z", "scale", "rotation", "alpha")}
            old_fields["scale"] = old["sy"]
            if old["sx"] != old["sy"]:
                old_fields.update(scale_x=old["sx"], scale_y=old["sy"])
            pose = None
            if old_fields["rotation"] or fields["rotation"]:
                from .native_portrait_swap_pose import NativePortraitSwapPose
                self.bind_motion()
                pose = NativePortraitSwapPose(self.loader, self.target, self.rotation_contract, self.motion)
            if parallel_events:
                parallel, parallel_state, parallel_channels = self.prepare_parallel_motion(
                    actor, fields, parallel_events, base_scale=parallel_base_scale)
            if _batch_prepare:
                return dict(actor_id=self.actors[actor],body_payload=body,face_payload=face,
                    runtime_arguments=runtime,expression=event['expression'],old_fields=old_fields,
                    new_fields=fields,duration_ms=duration_ms,pose=pose,parallel=parallel,
                    _event=event,_body_ref=body_ref,_geometry_report=report,
                    _parallel_state=parallel_state,_parallel_channels=parallel_channels)
            self.loader.blended_swap(self.source, self.actors[actor], body, face,
                runtime_arguments=runtime, expression=event["expression"], old_fields=old_fields,
                new_fields=fields, duration_ms=duration_ms, pose=pose, parallel=parallel)
        else:
            method = self.loader.swap if swapping else self.loader.load
            method(self.source, self.actors[actor], body, face, runtime_arguments=runtime,
                   expression=event["expression"])
            self.loader.geometry(self.source, self.actors[actor],
                                 {**fields,"rotation":0} if recover_rotation else fields)
        self.sync_loader()
        if swapping and duration_ms:
            self.output.extend(b"\x14\x07\0\0\0\0")
            self.blend_abort_positions.append(len(self.output)-4)
        if recover_rotation and not (swapping and duration_ms):
            # Keep the new buffer hidden across the native 1ms assignment.
            # RS still owns size/position; only signed R bypasses its proven
            # half-turn modulo. Never display a wrapped/second angle first.
            self.bind_motion()
            self.output.extend(self.syscall("PrimSetDraw",[self.prim(actor),self.push(False)]))
            self.start(actor,"r",self.motion.compile("r",self.prim(actor),(0,native_rotation,1,1,True)))
            self.join(actor,"r")
            self.output.extend(self.syscall("PrimSetDraw",[self.prim(actor),self.push(True)]))
        self.record_loaded_actor(event,fields,body,face,body_ref,report)
        if parallel is not None:
            self.states[actor].update(parallel_state)
            for channel in parallel_channels:
                self.pending[actor, channel] = True

    def record_loaded_actor(self,event,fields,body,face,body_ref,report):
        actor = event['actor']
        reference = self.imports.bind_portrait_loading(event["archive"], event["body"], self.loader)
        reference["scene_export_connected"] = True
        self.references.append(reference)
        self.geometry_reports.append(dict(actor=actor, **report))
        self.states[actor] = dict(fields, base_scale=fields["scale"],
            sx=fields.get("scale_x", fields["scale"]), sy=fields.get("scale_y", fields["scale"]),
            stage_x=event["stage_x"], bottom_y=event["bottom_y"], height=event["height"],
            body_height=body_ref["height"], expression=event["expression"],
            body_meta=deepcopy(body_ref), archive=str(Path(event['archive']).resolve()),
            resource_identity=(hashlib.sha256(body).hexdigest(), hashlib.sha256(face).hexdigest()))

    def swap_parameters(self,event):
        portrait = dict(event['portrait'])
        old = self.states.get(portrait['actor'])
        if old is None:
            raise ValueError('换身体角色尚未入场。')
        same_origin = (event['policy']=='keep' and old.get('archive') is not None
            and Path(old['archive']).resolve()==Path(portrait['archive']).resolve())
        x,y = self.geometry.editor_position(old) if same_origin else self.body_bottom_position(old)
        portrait.update(stage_x=x,bottom_y=y,depth=old['z'],alpha=event.get('target_alpha',old['alpha']))
        if event['policy']=='keep':
            _,new_body = resource_reference(portrait['archive'],portrait['body'])
            portrait['height'] = (new_body['height'] * old['sy']
                / (old['z']-self.geometry.camera[2]) * 720 / self.geometry.viewport[1])
        return portrait,old,same_origin

    def swap_batch(self,events,*,parallel_events=None,stage_events=None,blur=None):
        if self.snapshot_storage is None or not isinstance(events,(tuple,list)) or not 1 <= len(events) <= 4:
            raise ValueError('同拍换装需要已配对的原生状态接口和真实已加载的角色。')
        actors = [e['portrait']['actor'] for e in events]
        if len(set(actors))!=len(actors):
            raise ValueError('同一批换装不能重复同一个演员。')
        extra_events = [e for e in parallel_events or [] if e.get('actor') not in actors]
        extra_actors = sorted({e.get('actor') for e in extra_events})
        for actor in extra_actors:
            if actor not in self.states:
                raise ValueError('同拍运动的其他角色尚未入场。')
            self.join(actor)
        rows, previous = [], []
        for event in events:
            if event['kind']!='GuiActorSwap' or not 1 <= event.get('duration_ms',0) <= 6000:
                raise ValueError('多角色同拍换装只接明确的原生渐变，不把直接切换排队。')
            portrait,old,same_origin = self.swap_parameters(event)
            previous.append((portrait['actor'],event['policy'],old['base_scale']))
            rows.append(self.load(portrait,swapping=True,duration_ms=event['duration_ms'],
                native_rotation=old.get('rotation',0),preserve_transform=old if same_origin else None,
                preserve_scale_axes=(old['sx'],old['sy']) if event['policy']=='keep' else None,
                parallel_events=[e for e in parallel_events or [] if e.get('actor')==portrait['actor']],
                parallel_base_scale=old['base_scale'] if event['policy']=='keep' else None,
                _batch_prepare=True))
        extra_motion, extra_updates = self.prepare_extra_motion(extra_events) if extra_events else (None,{})
        stage_effects = None
        if stage_events:
            from .native_scene_parallel_effects import NativeSceneParallelEffects
            stage_effects = NativeSceneParallelEffects(self,stage_events,blur=blur,motion=extra_motion)
            extra_motion = stage_effects
            if self.scene_camera is not None and (any(
                    min(row['old_fields']['z'], row['new_fields']['z'],
                        row['_parallel_state'].get('z', row['new_fields']['z'])) - camera_near_z(self.scene_camera) < 64
                    for row in rows) or any(
                    updates.get('z', self.states[actor]['z']) - camera_near_z(self.scene_camera) < 64
                    for actor,(updates,_) in extra_updates.items())):
                raise ValueError('同拍镜头会越过换装角色的运动景深。')
        self.rebase_loader()
        self.loader.blended_batch(self.source,rows,storage=self.snapshot_storage,extra_motion=extra_motion)
        self.sync_loader()
        self.output.extend(b'\x14\x07\0\0\0\0')
        self.blend_abort_positions.append(len(self.output)-4)
        if stage_effects is not None:
            stage_effects.commit_caches(self.output)
        for row in rows:
            self.record_loaded_actor(row['_event'],row['new_fields'],row['body_payload'],row['face_payload'],
                row['_body_ref'],row['_geometry_report'])
            actor = row['_event']['actor']
            self.states[actor].update(row['_parallel_state'])
            for channel in row['_parallel_channels']:
                self.pending[actor,channel]=True
        for actor,policy,base in previous:
            if policy=='keep':
                self.states[actor]['base_scale']=base
        for actor,(updates,channels) in extra_updates.items():
            self.states[actor].update(updates)
            for channel in channels:
                self.pending[actor,channel]=True

    def prepare_extra_motion(self,events):
        from .native_scene_parallel_motion import NativeSceneParallelMotion
        self.bind_motion()
        rows,updates = [],{}
        for actor in sorted({e['actor'] for e in events}):
            state = self.states[actor]
            fields = {k:deepcopy(state[k]) for k in ('pivot','x','y','z','scale','rotation','alpha')}
            fields['scale']=state['sy']
            if state['sx']!=state['sy']:
                fields.update(scale_x=state['sx'],scale_y=state['sy'])
            # Reuse the same real native mapping, without manufacturing a
            # second body or submitting it twice on the current primitive.
            motion,end,channels = self.prepare_parallel_motion(actor,fields,
                [e for e in events if e['actor']==actor],base_scale=state['base_scale'],_resolve_only=True)
            rows.append(dict(actor_id=self.actors[actor],fields=fields,channels=[
                dict(channel=r['channel'],values=r['new_values']) for r in motion]))
            updates[actor]=(end,channels)
        return NativeSceneParallelMotion(self.loader,self.motion,rows,self.snapshot_storage),updates

    def motion_batch(self, events):
        """Launch current-buffer trajectories once, before any new wait."""
        from .hoshimemo_scene_hook import _call
        from .native_portrait_motion_group import bind_motion_groups
        bind_motion_groups(events, [dict(beat_id='current', action_indexes=list(range(len(events))))])
        actors = sorted({event['actor'] for event in events})
        if self.snapshot_storage is None or any(actor not in self.states for actor in actors):
            raise ValueError('普通同拍运动需要本目标配对状态接口和已经入场的角色。')
        # Join prior tracks only. None of the new group's channels have been
        # launched yet; never wait for XY before starting its S2/Z companion.
        for actor in actors:
            self.join(actor)
        motion, updates = self.prepare_extra_motion(events)
        start = len(self.source.original_bytes) + len(self.output)
        plan = motion.prepare(self.source, start + 5)
        self.output.extend(b'\x06' + struct.pack('<I', start + 5 + len(plan.code)))
        self.output.extend(plan.code + motion.reset_code + _call(plan.entry_address))
        self.output.extend(b'\x14\x07\0\0\0\0')
        self.blend_abort_positions.append(len(self.output) - 4)
        if not hasattr(self, 'motion_groups'):
            self.motion_groups = []
        self.motion_groups.append(dict(native_launch=plan.report(),
            launch_boundary='all_current_buffers_before_first_new_wait',
            source_size_rule_changed=False, scene_export_connected=True, runtime_verified=False))
        for actor, (end, channels) in updates.items():
            self.states[actor].update(end)
            for channel in channels:
                self.pending[actor, channel] = True

    def prepare_parallel_motion(self, actor, fields, events, *, base_scale=None, _resolve_only=False):
        """Target-native two-buffer trajectories; never move a new body twice."""
        from .native_portrait_parallel_motion import NativePortraitParallelMotion
        if self.snapshot_storage is None:
            raise ValueError("同拍换装运动需要目标已接通的配套状态接口；不会改成先换装后运动。")
        self.bind_motion()
        old = self.states[actor]
        current = dict(fields, sx=fields.get('scale_x', fields['scale']),
            sy=fields.get('scale_y', fields['scale']),
            base_scale=base_scale if base_scale is not None else fields['scale'])
        rows, updates, used, deferred_xy = [], {}, set(), []
        old_final = dict(old)
        for event in events:
            if event.get('actor') != actor:
                raise ValueError("多角色同拍换装的提交并行仍需接入；不会依动作顺序串行输出。")
            channels = ['xy'] if event['kind']=='GuiActorMove' else event.get('channels', '').split('+')
            if event['kind'] not in {'Action', 'GuiActorMove'} or not channels or set(channels)-{'xy','z','r','s2'}:
                raise ValueError("同拍换装暂只接原生移动、倾斜、缩放和景深；不会省略其他动作。")
            for channel in channels:
                if channel in used:
                    raise ValueError("同拍换装的同一运动通道不能重复提交。")
                used.add(channel)
                tail = (event['duration_ms'], event['curve'], True)
                if channel == 'xy':
                    # S2/Z endpoints must be known before inverting an
                    # absolute screen endpoint. Never let array order choose
                    # the wrong scale/depth for the target native XY.
                    deferred_xy.append((len(rows),event,tail))
                    rows.append(None)
                    continue
                elif channel == 's2':
                    sx, sy = (_round(current['base_scale'] * event[key] / 100) for key in ('scale_x','scale_y'))
                    ox, oy = _round(old['sx']*sx/current['sx']), _round(old['sy']*sy/current['sy'])
                    if any(not self.geometry.scale_range[0] <= v <= self.geometry.scale_range[1]
                           for v in (sx,sy,ox,oy)):
                        raise ValueError("同拍换装的两套运动尺寸超出本目标原生范围；不会夹紧。")
                    old_values, new_values = (old['sx'],ox,old['sy'],oy), (current['sx'],sx,current['sy'],sy)
                    updates.update(sx=sx,sy=sy)
                    old_final.update(sx=ox,sy=oy)
                elif channel == 'z':
                    z = event['depth']
                    camera_z = camera_near_z(self.scene_camera) if self.scene_camera else self.geometry.camera[2]
                    if min(old['z'],current['z'],z)-camera_z < 64:
                        raise ValueError("同拍换装运动的景深不能移到镜头后方。")
                    old_values, new_values = (old['z'],z), (current['z'],z)
                    updates['z'] = z
                    updates['_depth_start'] = min(old['z'], current['z'])
                    old_final['z'] = z
                else:
                    r = event['rotation']
                    if type(r) is not int or not -1000 <= r <= 1000:
                        raise ValueError("同拍换装的旋转须是本目标原生单位的整数，不是角度。")
                    old_values, new_values = (old.get('rotation',0),r), (current.get('rotation',0),r)
                    updates['rotation'] = r
                rows.append(dict(channel=channel, old_values=old_values+tail, new_values=new_values+tail))
        coupled = bool(used & {'s2','z'})
        for index,event,tail in deferred_xy:
            # GuiActorMove is persisted/lowered with x/y, not the Portrait
            # loader's stage_x/bottom_y names.
            stage_x, bottom_y = event['x'], event['y']
            final = dict(current,**updates)
            nx,ny = self.geometry.native_xy(final,stage_x,bottom_y)
            if coupled:
                ox,oy = self.geometry.editor_position(old)
                cx,cy = self.geometry.editor_position(current)
                tx,ty = self.geometry.native_xy(old_final,
                    ox+stage_x-cx,oy+bottom_y-cy)
            else:
                tx,ty = old['x']+nx-current['x'],old['y']+ny-current['y']
            old_values = (old['x'],old['y'],tx,ty)
            new_values = (current['x'],current['y'],nx,ny)
            if self.motion.xy_converted:
                fx,fy = self.motion.xy_factors['x'],self.motion.xy_factors['y']
                old_values = tuple(_converted_coordinate(v,fx if n%2==0 else fy)
                    for n,v in enumerate(old_values))
                new_values = tuple(_converted_coordinate(v,fx if n%2==0 else fy)
                    for n,v in enumerate(new_values))
            rows[index] = dict(channel='xy',old_values=old_values+tail,new_values=new_values+tail)
            updates.update(x=nx,y=ny,stage_x=stage_x,bottom_y=bottom_y)
        if deferred_xy and coupled:
            rows.sort(key=lambda row: ('xy','z','s2','r').index(row['channel']))
        if _resolve_only:
            return rows,updates,sorted(used)
        return NativePortraitParallelMotion(self.loader,self.actors[actor],self.motion,rows,self.snapshot_storage), updates, sorted(used)

    def body_bottom_position(self, state):
        """Actual crop bottom for SOURCE / cross-source swaps after a KEEP."""
        meta, pivot = state.get('body_meta'), state.get('pivot')
        if meta is None or pivot is None:
            return self.geometry.editor_position(state)
        qx = meta['offset_x'] + meta['width'] / 2 - pivot[0]
        qy = meta['offset_y'] + meta['height'] - pivot[1]
        rotation = state.get('rotation', 0)
        angle = 0
        if rotation and (qx or qy):
            if self.rotation_contract is None:
                raise ValueError('此目标尚不能换算倾斜后立绘的下缘位置。')
            angle = math.radians(rotation / self.rotation_contract.report()['units_per_degree'])
        c, s = math.cos(angle), math.sin(angle)
        return self.geometry.editor_position({**state,
            'x': state['x'] + c * qx - s * qy,
            'y': state['y'] + s * qx + c * qy})

    def bind_abort_cleanup(self, address):
        for position in getattr(self, "blend_abort_positions", ()):
            struct.pack_into("<I", self.output, position, address)
        self.blend_abort_target = address

    def bind_motion(self):
        if self.motion is None:
            raise ValueError("场景动作没有预先绑定目标原生参数。")

    def move(self, actor, x, y, duration_ms, curve):
        state = self.states.get(actor)
        if state is None:
            raise ValueError("移动角色尚未入场。")
        self.bind_motion()
        fx, fy = self.motion.xy_factors["x"], self.motion.xy_factors["y"]
        nx, ny = self.geometry.native_xy(state, x, y)
        positions = ((state["x"] / fx, state["y"] / fy, nx / fx, ny / fy)
                     if self.motion.xy_converted else (state["x"], state["y"], nx, ny))
        values = (*positions, duration_ms, curve, True)
        self.start(actor, "xy", self.motion.compile("xy", self.prim(actor), values))
        state.update(x=nx, y=ny, stage_x=x, bottom_y=y)

    def start(self, actor, channel, code):
        if (actor, channel) in self.pending:
            self.join(actor, channel)
        self.output.extend(code)
        self.pending[actor, channel] = True

    def join(self, actor=None, channel=None):
        for a, c in list(self.pending):
            if actor is not None and a != actor or channel is not None and c != channel:
                continue
            operand = self.parts(a) if c == "parts" else self.prim(a)
            start = len(self.source.original_bytes) + len(self.output)
            test = self.syscall(TESTS[c], [operand]) + b"\x14"
            wait = self.syscall("ThreadWait", [self.push(1)])
            finish = start + len(test) + 5 + len(wait) + 5
            self.output.extend(test + b"\x07" + struct.pack("<I", finish)
                               + wait + b"\x06" + struct.pack("<I", start))
            del self.pending[a, c]
            if c == 'z' and a in self.states:
                self.states[a].pop('_depth_start', None)

    def set_pose(self, event):
        """Commit an already-covered pose with the target's raw setters.

        The scene compiler owns the cover guard. Pixel scale, image origin,
        body/face allocation and authored scale baseline are not replaced.
        """
        fields = pose_values({k: v for k, v in event.items() if k != "kind"})
        actor = fields["actor"]
        if actor not in self.states:
            raise ValueError("设置姿态的角色尚未入场。")
        state = deepcopy(self.states[actor])
        if "scale_x" in fields:
            state["sx"], state["sy"] = (
                _round(state["base_scale"] * fields[key] / 100) for key in ("scale_x", "scale_y"))
            if any(not self.geometry.scale_range[0] <= state[k] <= self.geometry.scale_range[1]
                   for k in ("sx", "sy")):
                raise ValueError("设置尺寸超出目标原生范围；不会夹紧大小。")
        if "depth" in fields:
            state["z"] = fields["depth"]
        camera_z = camera_near_z(self.scene_camera) if self.scene_camera else self.geometry.camera[2]
        if state["z"] - camera_z < 64:
            raise ValueError("设置的立绘景深不能移到镜头后方。")
        if "rotation" in fields:
            state["rotation"] = fields["rotation"]
        if "x" in fields:
            # Either this event includes S2/Z, or canonical stage ordering has
            # already installed them. Absolute XY always uses the FINAL pose.
            state["x"], state["y"] = self.geometry.native_xy(state, fields["x"], fields["y"])
            state.update(stage_x=fields["x"], bottom_y=fields["y"])
        raw = {k: deepcopy(state[k]) for k in ("pivot", "x", "y", "z", "rotation", "alpha")}
        raw["scale"] = state["sy"]
        if state["sx"] != state["sy"]:
            raw.update(scale_x=state["sx"], scale_y=state["sy"])
        recover_rotation = bool(self.rotation_contract
            and self.rotation_contract.setter_changes_angle(state["rotation"]))
        if recover_rotation:
            self.bind_motion()
        self.join(actor)
        self.loader.geometry(self.source, self.actors[actor],
            dict(raw, rotation=0) if recover_rotation else raw)
        self.sync_loader()
        if recover_rotation:
            # Still under the caller's colour cover. A 1ms native assignment
            # bypasses RS's signed-angle modulo; never send Motion(0).
            self.start(actor, "r", self.motion.compile("r", self.prim(actor),
                (0, state["rotation"], 1, 1, True)))
            self.join(actor, "r")
        self.states[actor] = state
        self.geometry_reports.append(dict(actor=actor, instantaneous_pose_set=True,
            native_geometry=raw, current_native_buffer_only=True,
            signed_rotation_assignment_ms=1 if recover_rotation else 0, motion_zero_used=False,
            image_resampled=False, face_alignment_used=False, source_size_rule_changed=False,
            runtime_verified=False))

    def emit(self, event, *, parallel_events=None):
        kind = event["kind"]
        if kind == POSE_KIND:
            self.set_pose(event)
        elif kind == "Portrait":
            self.load(event)
        elif kind == "GuiActorSwap":
            portrait,old,same_origin = self.swap_parameters(event)
            self.load(portrait, swapping=True, duration_ms=event.get("duration_ms", 0),
                      native_rotation=old.get("rotation", 0),
                      preserve_transform=old if same_origin else None,
                      preserve_scale_axes=(old["sx"], old["sy"]) if event["policy"] == "keep" else None,
                      parallel_events=parallel_events,
                      parallel_base_scale=old['base_scale'] if event['policy']=='keep' else None)
            if event["policy"] == "keep":
                # Later authored scale actions are relative to the original
                # base, not to an already-scaled pose at the swap boundary.
                self.states[portrait["actor"]]["base_scale"] = old["base_scale"]
        elif kind == "Hide":
            self.join(event["actor"])
            self.loader.clear_actors(self.source, [self.actors[event["actor"]]])
            self.sync_loader()
            self.states.pop(event["actor"], None)
        elif kind == "Action":
            actor, channels = event["actor"], event["channels"].split("+")
            state = self.states.get(actor)
            if state is None:
                raise ValueError("动作角色尚未入场。")
            if any(c not in {"alpha", "parts", "s2", "z", "r"} for c in channels):
                raise ValueError("此目标的该动作通道尚未接通；不会使用星空的坐标单位。")
            for channel in channels:
                if channel == "parts":
                    self.join(actor, channel)
                    self.loader.expression(self.source, self.actors[actor], event["expression"],
                                           duration_ms=event["duration_ms"])
                    self.sync_loader()
                    state["expression"] = event["expression"]
                    if event["duration_ms"]:
                        self.pending[actor, channel] = True
                elif channel == "alpha":
                    if self.alpha is None:
                        raise ValueError("场景透明度没有预先绑定目标原生参数。")
                    self.start(actor, channel, self.alpha.compile(self.prim(actor),
                        state["alpha"], event["alpha"], event["duration_ms"]))
                    state["alpha"] = event["alpha"]
                elif channel == "s2":
                    self.bind_motion()
                    sx, sy = (_round(state["base_scale"] * event[key] / 100)
                              for key in ("scale_x", "scale_y"))
                    if any(not self.geometry.scale_range[0] <= v <= self.geometry.scale_range[1]
                           for v in (sx, sy)):
                        raise ValueError("动作尺寸超出目标原生范围；不会夹紧大小。")
                    values = (state["sx"], sx, state["sy"], sy, event["duration_ms"], event["curve"], True)
                    self.start(actor, channel, self.motion.compile(channel, self.prim(actor), values))
                    state.update(sx=sx, sy=sy)
                elif channel == "z":
                    self.bind_motion()
                    z = event["depth"]
                    camera_z = (camera_near_z(self.scene_camera) if getattr(self, "scene_camera", None)
                                is not None else self.geometry.camera[2])
                    if min(state["z"], z) - camera_z < 64:
                        raise ValueError("立绘景深不能移到镜头后方。")
                    values = (state["z"], z, event["duration_ms"], event["curve"], True)
                    self.start(actor, channel, self.motion.compile(channel, self.prim(actor), values))
                    state['_depth_start'] = state['z']
                    state["z"] = z
                elif channel == "r":
                    self.bind_motion()
                    rotation = event["rotation"]
                    if type(rotation) is not int or not -1000 <= rotation <= 1000:
                        raise ValueError("原生旋转必须是 -1000～1000 的整数单位；不是角度。")
                    values = (state.get("rotation", 0), rotation,
                              event["duration_ms"], event["curve"], True)
                    self.start(actor, channel, self.motion.compile(channel, self.prim(actor), values))
                    state["rotation"] = rotation
        elif kind in {"GuiActorMove", "GuiActorSlide"}:
            actor, x, y = event["actor"], event["x"], event["y"]
            state = self.states.get(actor)
            if state is None:
                raise ValueError("移动角色尚未入场。")
            if kind == "GuiActorSlide":
                off = -event["height"] * .3 if event["direction"] == "left" else 1280 + event["height"] * .3
                if not -640 <= off <= 1920:
                    raise ValueError("滑动起止位置超出场景范围。")
                if event["phase"] == "enter":
                    self.join(actor, "xy")
                    nx, ny = self.geometry.native_xy(state, off, y)
                    self.output.extend(self.syscall("PrimSetXY", [self.prim(actor), self.push(nx), self.push(ny)]))
                    state.update(x=nx, y=ny)
                else:
                    x = off
            self.move(actor, x, y, event["duration_ms"], event["curve"])
            if kind == "GuiActorSlide":
                alpha = 255 if event["phase"] == "enter" else 0
                if self.alpha is None:
                    raise ValueError("场景透明度没有预先绑定目标原生参数。")
                self.start(actor, "alpha", self.alpha.compile(self.prim(actor),
                    state["alpha"], alpha, event["duration_ms"]))
                state["alpha"] = alpha
        else:
            raise ValueError("尚未接通此角色事件。")

    def finish(self):
        if getattr(self, "blend_abort_target", None) is None:
            self.bind_abort_cleanup(len(self.source.original_bytes)+len(self.output))
        self.join()
        self.loader.cleanup(self.source)
        self.sync_loader()
        self.output.extend(self.lifecycle["restore"])
        self.states.clear()

    def report(self):
        loading = self.loader.report()
        loading.update(scene_export_connected=True, entry_cleanup_reviewed=True)
        return dict(schema="fvp-native-portrait-scene/1", loading=loading,
            geometry=self.geometry.describe(), camera_evidence=deepcopy(self.camera_evidence),
            geometry_operations=deepcopy(self.geometry_reports),
            parallel_motion_groups=deepcopy(getattr(self, 'motion_groups', [])),
            native_motion=self.motion.report() if self.motion else None,
            native_alpha=self.alpha.report() if self.alpha else None,
            native_dialogue=self.dialogue.report(),
            entry_lifecycle=self.lifecycle["report"], source_size_rule_changed=False,
            body_swap_blend=any(row.get("blended_swap") for row in self.loader.loads),
            body_swap_duration_control=any(row.get("blended_swap") for row in self.loader.loads),
            body_swap_default_ms=200,
            failed_blend_precondition_returns_to_scene_cleanup=True,
            raw_rotation_supported=bool(self.motion and "r" in self.motion._bindings),
            rotation_units="target_native_raw_R_not_degrees",
            rotation_degrees_supported=self.rotation_contract is not None,
            rotation_degree_conversion=self.rotation_contract.report() if self.rotation_contract else None,
            native_apply_default_duration_preserved=not any(row.get("blended_swap") for row in self.loader.loads),
            native_apply_wait_and_cleanup_preserved=True, instant_body_swap_proven=False,
            current_buffer_used=True, scene_export_connected=True,
            known_inherited_selectors_cleared=True, script_state_snapshot_restored=True,
            engine_resource_restoration_proven=False, runtime_verified=False)
