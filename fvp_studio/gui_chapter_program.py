"""GUI chapter control flow on the existing audited Hoshi stage.

Scene IDs, not array adjacency, own the native jumps. The generic chapter
graph and the target-specific bytecode adapter remain separate contracts.
No production/Comfy node, import scale rule, or original script is changed.
"""
from copy import deepcopy
import struct

from .gui_chapter import BOUNDARY_MS, MAX_EVENTS, MAX_SCENES, PROGRAM_SCHEMA
from .gui_native_preflight import SCENE_RE, ident
from .gui_audio_program import GuiAudioEmitter, KINDS as AUDIO_KINDS, event_values as audio_values
from .gui_native_cg import KINDS as CG_KINDS, event_values as cg_values
from .gui_actor_program import KINDS as ACTOR_KINDS, event_values as actor_values
from .gui_background_program import KINDS as BG_KINDS, event_values as bg_values
from .gui_background_blur import KINDS as BLUR_KINDS, event_values as blur_values
from .gui_choice_tracks import (KINDS as TRACK_KINDS, BRANCH_EVENTS, GuiTrackChoiceEmitter,
                                base_event, event_values as track_values, validate_track_structure)
from .performance_choices import choice_options, validate_choices
from .performance_compile import Emitter, ENTRY, args, call, jump
from .performance_workflow import values
from .portrait_emitter import _encode_push
from .gui_story_logic import (KINDS as LOGIC_KINDS, effects, predicate, route_targets,
                              event_values as logic_values, variables)
from .gui_story_program import StoryVariableBank

NORMAL_KINDS = {"Background", "Portrait", "PortraitNative", "PortraitFraming", "PortraitSwap",
                "Action", "Camera", "CameraShot", "CameraNative", "Dialogue", "Text", "Speech",
                "Wait", "Hide", "Transition", "Choice", "ChoiceCase", "ChoiceEnd"}


def exit_values(event, definitions=None):
    definitions = definitions or {}
    common = {"kind", "scene_id", "mode", "target", "prompt", "options"}
    if set(event) != common | ({"test", "then", "else"} if event.get("mode") == "condition" else set()):
        raise ValueError("场景出口字段不完整。")
    mode = event["mode"]
    if mode not in ("next", "jump", "choice", "condition", "end") or not SCENE_RE.fullmatch(event["scene_id"]):
        raise ValueError("场景出口类型不正确。")
    if mode in ("next", "jump"):
        if (not isinstance(event["target"], str) or not SCENE_RE.fullmatch(event["target"])
                or event["prompt"] != "" or event["options"] != []):
            raise ValueError("场景跳转缺少明确目标。")
    elif mode == "end":
        if event["target"] is not None or event["prompt"] != "" or event["options"] != []:
            raise ValueError("章节结束不能同时跳到其他场景。")
    elif mode == "condition":
        if event["target"] is not None or event["prompt"] != "" or event["options"] != []:
            raise ValueError("条件出口不能同时设置选项或直接跳转。")
        predicate(event["test"], definitions)
        if any(not isinstance(event[k], str) or not SCENE_RE.fullmatch(event[k]) for k in ("then", "else")):
            raise ValueError("条件的两条路线都需要明确目标。")
    else:
        options = event["options"]
        if event["target"] is not None or not isinstance(options, list) or not 2 <= len(options) <= 4:
            raise ValueError("场景选项需要 2～4 条路线。")
        for option in options:
            if (not isinstance(option, dict) or set(option) not in ({"label", "target"}, {"label", "target", "effects"})
                    or not isinstance(option["label"], str)
                    or not isinstance(option["target"], str) or not SCENE_RE.fullmatch(option["target"])):
                raise ValueError("选项缺少文字或目标场景。")
            if "effects" in option:
                effects(option["effects"], definitions)
        choice_options(dict(prompt=event["prompt"], **{
            f"option_{i}": options[i-1]["label"] if i <= len(options) else "" for i in range(1, 5)}))
    return deepcopy(event)


def validate_chapter_program(program):
    required = {"schema", "source_root", "title", "chapter_id", "entry_scene_id", "boundary_ms", "events"}
    if (not isinstance(program, dict) or set(program) not in (required, required | {"variables"}) or program["schema"] != PROGRAM_SCHEMA
            or not isinstance(program["source_root"], str) or not program["source_root"]
            or type(program["boundary_ms"]) is not int or program["boundary_ms"] != BOUNDARY_MS):
        raise ValueError("章节程序格式不正确。")
    ident(program["chapter_id"], "章节 ID")
    definitions = variables(program.get("variables", {}))
    if not isinstance(program["title"], str) or not program["title"].strip() or len(program["title"]) > 512:
        raise ValueError("章节标题不正确。")
    events = program["events"]
    if not isinstance(events, list) or not 3 <= len(events) <= MAX_EVENTS:
        raise ValueError("这章太大，请拆成较小章节。")
    blocks, current, scene_ids = [], None, set()
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("章节含有不正确的指令。")
        kind = event.get("kind")
        fields = {k: v for k, v in event.items() if k != "kind"}
        if kind == "GuiChapterScene":
            if current is not None:
                raise ValueError("上一场景缺少出口。")
            parsed = values("Scene", fields)
            sid = parsed["scene_id"]
            if not SCENE_RE.fullmatch(sid) or sid in scene_ids:
                raise ValueError("章节场景 ID 不正确或重复。")
            scene_ids.add(sid)
            current = [{"kind": kind, **parsed}]
        elif current is None:
            raise ValueError("场景内容必须从场景入口开始。")
        elif kind == "GuiChapterExit":
            current.append(exit_values(event, definitions))
            if event["scene_id"] != current[0]["scene_id"] or len(current) > 512:
                raise ValueError("场景出口不属于当前场景，或场景过大。")
            normalized = deepcopy(current)
            normalized[0]["kind"] = "Scene"
            normalized[-1] = {"kind": "End"}
            validate_track_structure(normalized)
            normal_choices = [base_event(e) if e["kind"] in TRACK_KINDS else
                              {"kind": "Wait"} if e["kind"] in CG_KINDS | AUDIO_KINDS | LOGIC_KINDS | ACTOR_KINDS | BG_KINDS | BLUR_KINDS else e
                              for e in normalized]
            validate_choices(normal_choices, branch_kinds=BRANCH_EVENTS)
            if event["mode"] == "choice" and any(e.get("completion") == "end" for e in current):
                raise ValueError("本场景的分支已结束并清场；请把场景级选项放到下一场景，或让分支先汇合。")
            blocks.append(current)
            current = None
        else:
            parser = (lambda k, f: logic_values(k, f, definitions)) if kind in LOGIC_KINDS else (
                      blur_values if kind in BLUR_KINDS else bg_values if kind in BG_KINDS else actor_values if kind in ACTOR_KINDS else cg_values if kind in CG_KINDS else audio_values if kind in AUDIO_KINDS else
                      track_values if kind in TRACK_KINDS else values if kind in NORMAL_KINDS else None)
            if parser is None:
                raise ValueError("章节包含尚未支持的指令，不会跳过它继续生成。")
            parsed = parser(kind, fields)
            if kind in ("Dialogue", "Text", "Speech"):
                if not parsed["text"].strip():
                    raise ValueError("台词不能为空。")
                _encode_push((parsed["case_id"] + " " if kind == "Dialogue" else "") + parsed["text"], "gbk")
            current.append({"kind": kind, **parsed})
    if current is not None or not 1 <= len(blocks) <= MAX_SCENES:
        raise ValueError("章节缺少场景出口，或场景数量过多。")
    if blocks[0][0]["scene_id"] != program["entry_scene_id"]:
        raise ValueError("章节入口不一致。")
    for block in blocks:
        route = block[-1]
        destinations = route_targets(route)
        if any(target not in scene_ids for target in destinations):
            raise ValueError("场景连线指向了本次没有输出的场景。")
    return blocks


class GuiChapterEmitter(GuiAudioEmitter):
    choice_validation_branch_kinds = BRANCH_EVENTS | LOGIC_KINDS

    def __init__(self, source, clean):
        super().__init__(source, clean)
        self.chapter_scene_entry = None
        self.chapter_finishing = False
        self.local_exit_jumps = []
        self.route_reports = []
        self.story_bank = None

    def reset_scene_state(self):
        # Compile-time state only. Each route already joins and clears its
        # actual native stage, and the destination emits its own full setup.
        self.pending, self.actors = {}, {}
        self.depth_envelopes, self.camera_envelope = {}, []
        self.cg, self.speech, self.gui_background = None, None, None
        self.camera, self.camera_reference = [0, 0, -200], (1900, -200)
        self.background_loaded, self.covered = False, True
        self.cg_dissolve_pending, self.gui_tracks_finished = False, False
        self.bg_dissolve_pending = False
        self.gui_background_blur = None
        self.track_choices = GuiTrackChoiceEmitter(self)
        self.local_exit_jumps = []

    def resume_original(self):
        if self.chapter_finishing:
            return super().resume_original()
        # A scene-local branch ending now reaches this scene's exit, not the
        # original game's opening. These jumps are patched after all branches.
        self.local_exit_jumps.append(len(self.output))
        self.output.extend(jump(0))

    def transfer(self, target):
        # Always emit for EVERY option, including when the previous compiled
        # alternative ended covered. Compile order is not native run order.
        self.transition(dict(method="black_out", duration_ms=BOUNDARY_MS))
        self.cleanup()
        self.background_loaded = False
        at = len(self.output)
        self.jumps.append((at, target))
        self.output.extend(jump(0))
        return at

    def scene_choice(self, route):
        self.join()
        if self.covered:
            raise ValueError("选项前需要恢复画面；请接一个淡入恢复节拍。")
        start = len(self.output)
        self.set_speech_identity()
        self.speech = dict(name="", text=route["prompt"])
        self.output.extend(args([route["prompt"], None, None, None]) + call(self.text_target))
        for option in route["options"]:
            self.output.extend(self.native("choice_add", (option["label"], None, None)))
        self.output.extend(self.native("choice_show"))
        names = GuiTrackChoiceEmitter.STATE
        baseline = {name: deepcopy(getattr(self, name)) for name in names}
        skipped = None
        choices = []
        for number, option in enumerate(route["options"], 1):
            if skipped is not None:
                struct.pack_into("<I", self.output, skipped + 1, len(self.output))
            for name, state in baseline.items():
                setattr(self, name, deepcopy(state))
            self.output.extend(b"\x0f\x62\x00" + _encode_push(number, "gbk") + b"\x22")
            skipped = len(self.output)
            self.output.extend(b"\x07\0\0\0\0")
            for item in option.get("effects", []):
                self.story_bank.emit_effect(item)
            choices.append(dict(index=number, target=option["target"], jump_offset=self.transfer(option["target"])))
        struct.pack_into("<I", self.output, skipped + 1, start)
        self.speech = None
        return dict(menu_offset=start, native_result_global=98, options=choices,
                    unexpected_result="retry_menu")

    def scene_condition(self, route):
        self.join()
        start = len(self.output)
        self.output.extend(self.story_bank.compare(route["test"]))
        skipped = len(self.output)
        self.output.extend(b"\x07\0\0\0\0")
        names = GuiTrackChoiceEmitter.STATE
        baseline = {name: deepcopy(getattr(self, name)) for name in names}
        yes = self.transfer(route["then"])
        struct.pack_into("<I", self.output, skipped + 1, len(self.output))
        for name, state in baseline.items():
            setattr(self, name, deepcopy(state))
        no = self.transfer(route["else"])
        return dict(condition_offset=start, test=deepcopy(route["test"]),
            variable_slot=self.story_bank.slots[route["test"]["variable"]],
            options=[dict(result=True, target=route["then"], jump_offset=yes),
                     dict(result=False, target=route["else"], jump_offset=no)])

    def emit_extension(self, event, resources):
        kind = event["kind"]
        if kind in LOGIC_KINDS:
            self.story_bank.emit_effect({k:v for k,v in event.items() if k != "kind"})
            return True
        if kind == "GuiChapterScene":
            self.current_scene = event["scene_id"]
            self.scene_labels[self.current_scene] = self.chapter_scene_entry
            return True
        if kind != "GuiChapterExit":
            return super().emit_extension(event, resources)
        exit_at = len(self.output)
        for at in self.local_exit_jumps:
            struct.pack_into("<I", self.output, at + 1, exit_at)
        report = dict(scene_id=self.current_scene, mode=event["mode"], exit_offset=exit_at,
                      local_branch_exit_jumps=list(self.local_exit_jumps))
        if event["mode"] in ("next", "jump"):
            report.update(target=event["target"], jump_offset=self.transfer(event["target"]))
        elif event["mode"] == "choice":
            report.update(self.scene_choice(event))
        elif event["mode"] == "condition":
            report.update(self.scene_condition(event))
        else:
            self.transition(dict(method="black_out", duration_ms=BOUNDARY_MS))
            self.cleanup()
            self.chapter_finishing = True
            try:
                self.resume_original()
            finally:
                self.chapter_finishing = False
            report["returns_to_original"] = True
        self.route_reports.append(report)
        return True

    def compile(self, program, resources, *, finalize_jumps=True):
        if not finalize_jumps:
            raise ValueError("章节必须一次生成完整的连线。")
        blocks = validate_chapter_program(program)
        if program.get("variables"):
            self.story_bank = StoryVariableBank(self, program["variables"])
            self.story_bank.initialize()
        # An end scene can appear before a music-using branch in storage order.
        # All chapter ends therefore make the same stop decision, never a
        # decision derived from whichever alternative was compiled first.
        self.gui_audio_used = any(e["kind"] in AUDIO_KINDS for block in blocks for e in block)
        self.gui_voice_used = any(e["kind"] == "GuiVoiceLine" for block in blocks for e in block)
        self.transition(dict(method="black_out", duration_ms=BOUNDARY_MS))
        for block in blocks:
            self.reset_scene_state()
            self.chapter_scene_entry = len(self.output)
            # The base prelude is included in the label; it is not skipped when
            # revisiting a scene or entering from a backward/cross-order edge.
            super().compile({**program, "events": block}, resources, finalize_jumps=False)
        for at, target in self.jumps:
            struct.pack_into("<I", self.output, at + 1, self.scene_labels[target])
        self.output[ENTRY:ENTRY + 5] = jump(self.entry)
        self.native_speakers.finish()
        return bytes(self.output)
