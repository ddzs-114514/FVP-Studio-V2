"""Typed, memory-only GUI CG extension of the audited Hoshi emitter.

Never used by the production candidate builder. GUI/CSS and native trajectories
are not interchangeable: non-origin scale/translation combinations fail closed.
The source functions are copied by the existing bounded relocation audit.
"""
from __future__ import annotations

from copy import deepcopy
import math
import struct
from functools import lru_cache

from .cg_workspace import fit_cg_scale
from .performance_cg import SPECS, relocate, hidden_gate
from .performance_compile import Emitter, args, call, jump, rounded, validate_program
from .performance_compile import CLEAN_SHA, CALLS, _baseline_document
from .native_stage_motion import NativeStageMotion, motion_contract
from .native_stage_helpers import NativeStageHelpers, stage_helper_contract
from .performance_workflow import SCHEMA as BASE_SCHEMA
from .gui_actor_program import KINDS as ACTOR_KINDS, event_values as actor_values, emit_actor
from .gui_background_program import KINDS as BG_KINDS, event_values as bg_values, emit_background
from .gui_background_blur import (KINDS as BLUR_KINDS, event_values as blur_values,
                                  emit_blur, clear as clear_blur)
from .gui_choice_tracks import (SCHEMA as TRACK_SCHEMA, KINDS as TRACK_KINDS,
    BRANCH_EVENTS, GuiTrackChoiceEmitter, base_event, validate_track_structure)

SCHEMA = "fvp-gui-preflight-program/2"
CONTRACT = "fvp-gui-cg-preflight/1"
KINDS = {"GuiCGLoad", "GuiCGTransform", "GuiCGExit"}


@lru_cache(maxsize=1)
def _gui_stage_motion(source, clean):
    document = _baseline_document(clean)
    if document.source_sha256 != CLEAN_SHA:
        raise ValueError("动作参数参考不是已确认的原版脚本。")
    return NativeStageMotion(document, source, motion_contract(document))


@lru_cache(maxsize=1)
def _gui_stage_helpers(source, clean):
    document = _baseline_document(clean)
    if document.source_sha256 != CLEAN_SHA:
        raise ValueError("立绘调用参考不是已确认的原版脚本。")
    contract = stage_helper_contract(document,
        {role: CALLS[role][0] for role in ("sprite", "xy_set", "group")})
    return NativeStageHelpers(document, source, contract)


def number(value, low, high, *, integral=False):
    if (type(value) not in (int, float) or not math.isfinite(value)
            or not low <= value <= high or integral and int(value) != value):
        raise ValueError("CG 参数不是安全范围内的有限数值")
    return int(value) if integral else value


def event_values(kind, fields):
    """Closed, independent types; no production node/schema is added."""
    if kind == "GuiCGLoad":
        allowed = {"source_game", "archive", "resource", "fit", "duration_ms"}
        if set(fields) != allowed or fields["fit"] != "contain":
            raise ValueError("CG 原生预检仅支持完整单帧 contain 登记")
        for key in ("source_game", "archive", "resource"):
            if not isinstance(fields[key], str) or not fields[key] or len(fields[key]) > 1024 or "\0" in fields[key]:
                raise ValueError("CG 来源/资源引用不合法")
        number(fields["duration_ms"], 100, 3000, integral=True)
    elif kind == "GuiCGTransform":
        if set(fields) != {"x", "y", "s", "duration_ms", "curve"}:
            raise ValueError("CG 构图字段不完整或包含未知字段")
        number(fields["x"], -1280, 1280)
        number(fields["y"], -720, 720)
        number(fields["s"], 10, 400)
        number(fields["duration_ms"], 200, 6000, integral=True)
        if type(fields["curve"]) is not int or fields["curve"] not in (2, 3):
            raise ValueError("CG 构图曲线须为 2 或 3")
    elif kind == "GuiCGExit":
        if set(fields) != {"colour", "duration_ms"} or fields["colour"] not in ("white", "black"):
            raise ValueError("CG 退场字段不完整或包含未知字段")
        number(fields["duration_ms"], 600, 3000, integral=True)
    else:
        raise ValueError("未知 CG 扩展事件")
    return deepcopy(fields)


def validate_gui_program(program):
    from .gui_audio_program import KINDS as AUDIO_KINDS, event_values as audio_values
    if program.get("schema") == BASE_SCHEMA:
        return validate_program(program)
    if program.get("schema") not in (SCHEMA, TRACK_SCHEMA):
        raise ValueError("不支持的原生预检程序格式")
    # The normal validator still checks scene/text/choice/End and every ordinary
    # event. Extended events are independently typed, not handed to production.
    normal = deepcopy(program)
    normal["schema"] = BASE_SCHEMA
    extended = 0
    tracks = program["schema"] == TRACK_SCHEMA
    if tracks:
        validate_track_structure(program.get("events", []))
        if not any(e.get("kind") in TRACK_KINDS for e in program.get("events", [])):
            raise ValueError("分支专用程序缺少分支轨道事件")
    for i, event in enumerate(normal.get("events", [])):
        if event.get("kind") in ACTOR_KINDS:
            actor_values(event["kind"], {k:v for k,v in event.items() if k != "kind"})
            normal["events"][i] = {"kind": "Wait"}
            extended += 1
        elif event.get("kind") in AUDIO_KINDS:
            audio_values(event["kind"], {k:v for k,v in event.items() if k != "kind"})
            normal["events"][i] = {"kind": "Wait"}
            extended += 1
        elif event.get("kind") in BG_KINDS:
            bg_values(event["kind"], {k:v for k,v in event.items() if k != "kind"})
            normal["events"][i] = {"kind": "Wait"}
            extended += 1
        elif event.get("kind") in BLUR_KINDS:
            blur_values(event["kind"], {k:v for k,v in event.items() if k != "kind"})
            normal["events"][i] = {"kind": "Wait"}
            extended += 1
        elif event.get("kind") in KINDS:
            event_values(event["kind"], {k:v for k,v in event.items() if k != "kind"})
            normal["events"][i] = {"kind": "Wait"}
            extended += 1
        elif tracks and event.get("kind") in TRACK_KINDS:
            normal["events"][i] = base_event(event)
            extended += 1
    if not extended:
        raise ValueError("GUI 专用程序缺少扩展事件")
    return validate_program(normal, choice_branch_kinds=BRANCH_EVENTS if tracks else None)


def cg_scale(width, height, percentage=100):
    # Reject instead of silently using fit_cg_scale's safety clamp.
    exact = min(1920 * 2000 / width, 1080 * 2000 / height)
    baseline = round(exact)
    if not 1 <= baseline <= 4000 or baseline != fit_cg_scale(width, height):
        raise ValueError("CG 画布需要超出已审核范围的原生 RS，不能静默夹紧")
    result = rounded(baseline * percentage / 100)
    if not 1 <= result <= 4000:
        raise ValueError("CG 局部倍率换算超出已审核的原生 RS 范围")
    return baseline, result


def local_xy(x, y, scale):
    # performance_geometry.projection_matrix's audited inverse at CG Z=2000,
    # camera baseline 0. Camera changes remain a separate, shared V3D motion.
    return x * 1.5 * 2000 / scale / 2.4, y * 1.5 * 2000 / scale / 1.8


class GuiCgEmitter(Emitter):
    choice_validation_branch_kinds = BRANCH_EVENTS | BG_KINDS

    def __init__(self, source, clean):
        self.cg_dissolve_pending = False
        self.bg_dissolve_pending = False
        self.gui_background = None
        self.gui_background_blur = None
        self.gui_tracks_finished = False
        super().__init__(source, clean)
        self.stage_motion = _gui_stage_motion(source, clean)
        self.call_table.update(self.stage_motion.bindings)
        self.stage_helpers = _gui_stage_helpers(source, clean)
        self.call_table.update(self.stage_helpers.bindings)
        self.track_choices = GuiTrackChoiceEmitter(self)
        from .gui_actor_swap_blend import NativeActorSwapBlend
        self.actor_swap_blend = NativeActorSwapBlend(self)
        from .gui_speaker_identity import NativeSpeakerBridge
        self.native_speakers = NativeSpeakerBridge(self)

    def set_speech_identity(self, name=None, history_key=None, *, narration=True):
        if not hasattr(self, "native_speakers"):
            return super().set_speech_identity(name, history_key, narration=narration)
        return self.native_speakers.set_identity(name, history_key, narration=narration)

    def start_motion(self, channel, ident, code):
        super().start_motion(channel, ident, code)
        if hasattr(self, "actor_swap_blend"):
            self.actor_swap_blend.mirror_motion(channel, ident)

    def clear_actor(self, actor):
        if hasattr(self, "actor_swap_blend"):
            self.actor_swap_blend.finish_actor(actor)
        super().clear_actor(actor)

    def native(self, name, v=()):
        if hasattr(self, "stage_helpers") and name in self.stage_helpers.bindings:
            code = self.stage_helpers.call(name, v)
            self.calls.append(dict(function=name, address=self.stage_helpers.bindings[name][0],
                                   arguments=list(v)))
            return code
        if hasattr(self, "stage_motion") and name in self.stage_motion.bindings:
            code = self.stage_motion.call(name, v)
            self.calls.append(dict(function=name, address=self.stage_motion.bindings[name][0],
                                   arguments=list(v)))
            return code
        return super().native(name, v)

    def compile(self, program, resources, *, finalize_jumps=True):
        if program.get("schema") == TRACK_SCHEMA:
            validate_gui_program(program)
        super().compile(program, resources, finalize_jumps=finalize_jumps)
        if finalize_jumps:
            self.native_speakers.finish()
        return bytes(self.output)

    def join(self):
        if self.cg_dissolve_pending or self.bg_dissolve_pending:
            self.output.extend(self.syscall("DissolveWait", (True,)))
            self.cg_dissolve_pending = False
            self.bg_dissolve_pending = False
        super().join()
        if hasattr(self, "actor_swap_blend"):
            self.actor_swap_blend.finish_all()

    def generic_loader(self):
        key = ("gui_cg_loader", CONTRACT)
        if key in self.helpers:
            return self.helpers[key]["loader"]
        skip = len(self.output)
        self.output.extend(jump(0))
        stubs = {}
        # These are the same two camera protection sites audited in the existing
        # CG variant adapter. The shim commits the correct reference separately.
        for target, arity in ((0x5465A, 4), (0x4B47E, 3)):
            instruction = self.by_offset.get(target)
            if not instruction or instruction.operands.get("args") != arity:
                raise ValueError("CG 镜头保护调用 ABI 漂移")
            stubs[target] = len(self.output)
            self.output.extend(bytes((1, arity, 0, 4)))
        routes, cursor = dict(stubs), len(self.output)
        for number_, start, end, arity in SPECS:
            routes[start] = cursor
            cursor += end - start + (len(hidden_gate(self)) if number_ == 4173 else 0)
        copies = []
        for spec in SPECS:
            block, report = relocate(self, spec, routes[spec[1]], routes)
            self.output.extend(block)
            copies.append(report)
        struct.pack_into("<I", self.output, skip + 1, len(self.output))
        self.helpers[key] = dict(loader=routes[0x5368B], copies=copies,
            skipped_camera_calls={str(k):v for k,v in stubs.items()},
            transition_owner="audited_4466_explicit_nonblocking", runtime_verified=False)
        return routes[0x5368B]

    def load_gui_cg(self, event, resources):
        self.join()
        self.clear_background_blur()
        if self.actors:
            raise ValueError("CG 入场前须明确退场并清除普通立绘，不能省略旧角色")
        if self.covered:
            raise ValueError("CG 入场时仍有整幕遮盖；不能隐式 reveal")
        binding = resources.cg(event)
        metadata = binding["metadata"]
        gx, gy, gs = ((self.cg[k] for k in ("gx", "gy", "gscale"))
                      if self.cg else (0, 0, 100))
        if self.cg is None and self.camera != [0, 0, -200]:
            raise ValueError("首次 CG 入场前镜头须为基准状态，当前镜头重定基尚未接通")
        base, scale = cg_scale(metadata["width"], metadata["height"], gs)
        x, y = local_xy(gx, gy, scale)
        loader = self.generic_loader()
        self.output.extend(self.native("cg_prepare"))
        if self.cg is None:
            self.output.extend(self.syscall("V3DSet", (0, 0, 0)))
            self.camera = [0, 0, 0]
        self.output.extend(args([binding["name"], 0, 1, None, None, None, 2000, 0, None, 0]) + call(loader))
        pivot = (metadata["offset_x"] + metadata["width"] // 2,
                 metadata["offset_y"] + metadata["height"] // 2)
        self.output.extend(self.syscall("PrimSetOP", (191, *pivot)))
        self.output.extend(self.native("xy_set", (191, x, y)))
        self.output.extend(self.syscall("PrimSetZ", (191, 2000)))
        self.output.extend(self.syscall("PrimSetRS", (191, 0, scale)))
        for glob, value in ((157,2000),(158,2000),(159,0),(160,0),(161,x),(162,y)):
            self.output.extend(args([value]) + b"\x15" + struct.pack("<H", glob))
        for name, parameters in (("MotionAlphaStop",(190,)),("MotionAlphaStop",(191,)),
                ("PrimSetDraw",(190,0)),("PrimSetAlpha",(190,0)),
                ("PrimSetAlpha",(191,0)),("PrimSetDraw",(191,1))):
            self.output.extend(self.syscall(name, parameters))
        # Hoshi 4466 @57F42: fourth argument -1 skips both alpha waits (@580A3)
        # and its end wait/sleep tail (@587F8 ->5885A). Ninth alone is NOT enough.
        # Explicit mode 0 bypasses 859's settings/default selection. No original
        # byte is patched. The following private text runs before the join.
        self.output.extend(self.native("dissolve", (0, event["duration_ms"], None, -1, None, None, None, 0, 0)))
        self.output.extend(args([None]) + b"\x15" + struct.pack("<H", 15))
        self.cg_dissolve_pending = True
        self.cg = dict(x=x,y=y,z=2000,r=0,sx=scale,sy=scale,scale=scale,
            base_scale=base,gx=gx,gy=gy,gscale=gs,resource=binding["name"],
            body_meta=metadata,pivot=pivot)
        self.camera_reference = (2000, 0)
        self.background_loaded, self.covered = False, False
        self.gui_background = None

    def transform_gui_cg(self, event):
        if self.cg is None:
            raise ValueError("没有正在显示的 CG，不能调整构图")
        state = self.cg
        changed_scale = event["s"] != state["gscale"]
        if changed_scale and any(v != 0 for v in (state["gx"],state["gy"],event["x"],event["y"])):
            raise ValueError("非零位移上的 CG 拡缩需要补偿原点轨道；不会以近似动画冒充")
        _base, scale = cg_scale(state["body_meta"]["width"], state["body_meta"]["height"], event["s"])
        x, y = local_xy(event["x"], event["y"], scale)
        duration, curve = event["duration_ms"], event["curve"]
        if changed_scale:
            self.start_motion("s2", 191, self.native("s2", (191,state["sx"],scale,state["sy"],scale,duration,curve,True,0,-1)))
            state.update(sx=scale,sy=scale,scale=scale)
        if x != state["x"] or y != state["y"]:
            self.start_motion("xy", 191, self.native("xy", (191,state["x"],state["y"],x,y,duration,curve,True,0,-1)))
            state.update(x=x,y=y)
        state.update(gx=event["x"],gy=event["y"],gscale=event["s"])
        for glob, value in ((161,x),(162,y)):
            self.output.extend(args([value]) + b"\x15" + struct.pack("<H", glob))

    def emit_extension(self, event, resources):
        kind = event["kind"]
        if kind == "Speech":
            return self.native_speakers.speech(event, resources)
        if emit_background(self, event, resources):
            return True
        if emit_blur(self, event, resources):
            return True
        if emit_actor(self, event, resources):
            return True
        if kind in TRACK_KINDS:
            self.track_choices.emit(event)
            return True
        if kind == "End" and self.gui_tracks_finished:
            # Every alternative already has its own native end tail.
            return True
        if kind == "Background":
            self.join()
            self.clear_background_blur()
            self.gui_background = (event["archive"], event["resource"], event["fit"])
        if kind not in KINDS:
            return False
        event_values(kind, {k:v for k,v in event.items() if k != "kind"})
        if kind == "GuiCGLoad":
            self.load_gui_cg(event, resources)
        elif kind == "GuiCGTransform":
            self.transform_gui_cg(event)
        else:
            if self.cg is None:
                raise ValueError("没有已加载 CG 可退场")
            self.join()
            self.output.extend(self.native("bg_" + event["colour"]))
            self.output.extend(self.native("dissolve", (0,event["duration_ms"],None,None,None,None,None,None,1)))
            self.output.extend(self.syscall("DissolveWait", (True,)))
            self.cleanup()
            self.background_loaded, self.covered = False, True
            self.gui_background = None
        return True

    def clear_background_blur(self):
        clear_blur(self)

    def cleanup(self):
        super().cleanup()
        self.clear_background_blur()
