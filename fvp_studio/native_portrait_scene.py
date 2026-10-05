"""Bind native portraits to an interleaved, target-owned GUI scene stream.

Keeps the existing source-size bridge unchanged. All carrier clone addresses
are placed after the CURRENT output cursor, including intervening dialogue.
Native state snapshots are not a claim to restore the previous story's images.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import struct

from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_portrait_alpha import NativePortraitAlpha
from .native_portrait_acceptance import (
    NativePortraitAcceptanceError, _function_spans, _camera_z,
    _embedded_v3d_camera, _extract_direct_xy_scales, _instructions_in_range, _negative_default,
)
from .native_portrait_geometry import NativePortraitGeometry, _round
from .native_portrait_loading import NativePortraitLoading
from .native_portrait_motion import NativePortraitMotion
from .native_stage_baseline import native_default_camera, NativeStageBaselineUnavailable
from .native_script_state import NativeScriptStateClosure
from .native_portrait_dialogue import NativePortraitDialogue
from .performance_compile import resource_reference
from .portrait_emitter import _encode_push


KINDS = {"Portrait", "GuiActorSwap", "Hide", "Action", "GuiActorMove", "GuiActorSlide"}
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


class NativePortraitScene:
    def __init__(self, target, events, anchor, imports, output, *, motion_contract=None):
        self.target, self.source, self.analysis = target, target.context.document, target.context.analysis_document
        self.imports, self.output = imports, output
        actor_numbers = sorted({e["portrait"]["actor"] if e["kind"] == "GuiActorSwap" else e["actor"]
                                for e in events if e["kind"] in KINDS})
        if not actor_numbers or any(type(a) is not int or not 1 <= a <= 4 for a in actor_numbers):
            raise ValueError("场景立绘需要稳定的角色槽编号。")
        self.actors = {a: "scene_actor_" + str(a) for a in actor_numbers}
        self.loader = NativePortraitLoading(self.source, self.analysis, target.discovery,
            tuple(self.actors.values()), runtime_context=target.context)
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
            if event["kind"] in {"GuiActorMove", "GuiActorSlide"}:
                motion_channels.add("xy")
            elif event["kind"] == "Action":
                motion_channels.update(set(event["channels"].split("+")) - {"parts", "alpha"})
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
        self.camera_evidence = _proof
        self.cursor, self.states, self.pending, self.references, self.geometry_reports = 0, {}, {}, [], []
        self.output.extend(self.lifecycle["snapshot"] + self.lifecycle["clear"])
        self.reset_camera()
        self.dialogue = NativePortraitDialogue(target.context,
            target.discovery["profile_seed"]["native_symbols"]["portrait_lifecycle_family"], self.output)

    def syscall(self, name, operands):
        return self.loader._syscall(name, operands)

    def reset_camera(self):
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

    def load(self, event, *, swapping=False, duration_ms=0):
        actor = event["actor"]
        if swapping and duration_ms:
            raise ValueError("此目标的身体渐变尚未接通，不会把渐变改成直接换图。")
        if not swapping and actor in self.states:
            raise ValueError("已在场角色不能再次加载。")
        self.join(actor)
        body, body_ref = resource_reference(event["archive"], event["body"])
        face, face_ref = resource_reference(event["archive"], event["body"] + "_表情")
        fields, report = self.geometry.portrait(event, body)
        runtime = [min(self.loader.form_suffixes), *([None] * (self.loader._layout.runtime_count - 1))]
        if len(runtime) == 10:
            runtime[-1] = 0
        self.rebase_loader()
        method = self.loader.swap if swapping else self.loader.load
        method(self.source, self.actors[actor], body, face, runtime_arguments=runtime,
               expression=event["expression"])
        self.loader.geometry(self.source, self.actors[actor], fields)
        self.sync_loader()
        reference = self.imports.bind_portrait_loading(event["archive"], event["body"], self.loader)
        reference["scene_export_connected"] = True
        self.references.append(reference)
        self.geometry_reports.append(dict(actor=actor, **report))
        self.states[actor] = dict(fields, base_scale=fields["scale"], sx=fields["scale"], sy=fields["scale"],
            stage_x=event["stage_x"], bottom_y=event["bottom_y"], height=event["height"],
            body_height=body_ref["height"], expression=event["expression"])

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

    def emit(self, event):
        kind = event["kind"]
        if kind == "Portrait":
            self.load(event)
        elif kind == "GuiActorSwap":
            portrait = dict(event["portrait"])
            old = self.states.get(portrait["actor"])
            if old is None:
                raise ValueError("换身体角色尚未入场。")
            if old["sx"] != old["sy"]:
                raise ValueError("经过非等比变换的通用换装尚未接通。")
            x, y = self.geometry.editor_position(old)
            portrait.update(stage_x=x, bottom_y=y,
                            depth=old["z"], alpha=old["alpha"])
            if event["policy"] == "keep":
                portrait["height"] = (old["body_height"] * old["sy"]
                    / (old["z"] - self.geometry.camera[2]) * 720 / self.geometry.viewport[1])
            self.load(portrait, swapping=True, duration_ms=event.get("duration_ms", 0))
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
            if any(c not in {"alpha", "parts", "s2", "z"} for c in channels):
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
                    if min(state["z"], z) - self.geometry.camera[2] < 64:
                        raise ValueError("立绘景深不能移到镜头后方。")
                    values = (state["z"], z, event["duration_ms"], event["curve"], True)
                    self.start(actor, channel, self.motion.compile(channel, self.prim(actor), values))
                    state["z"] = z
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
            native_motion=self.motion.report() if self.motion else None,
            native_alpha=self.alpha.report() if self.alpha else None,
            native_dialogue=self.dialogue.report(),
            entry_lifecycle=self.lifecycle["report"], source_size_rule_changed=False,
            body_swap_blend=False, body_swap_duration_control=False,
            native_apply_default_duration_preserved=True, instant_body_swap_proven=False,
            current_buffer_used=True, scene_export_connected=True,
            known_inherited_selectors_cleared=True, script_state_snapshot_restored=True,
            engine_resource_restoration_proven=False, runtime_verified=False)
