"""GUI-only complete-beat choice tracks on the audited Hoshi native menu.

Track IDs and an explicit merge/scene-end intent survive project round trips.
They are not action lanes: native dispatch executes exactly one alternative.
The old production choice node contract is intentionally not widened.
"""
from copy import deepcopy
import re
import struct

from .performance_choices import BRANCH_KINDS, ChoiceEmitter, choice_options
from .performance_workflow import values
from .gui_background_program import KINDS as BG_KINDS
from .gui_background_blur import KINDS as BLUR_KINDS

SCHEMA = "fvp-gui-branch-program/1"
CONTRACT = "fvp-gui-choice-tracks/1"
KINDS = {"GuiChoice", "GuiChoiceCase", "GuiChoiceEnd"}
BASE_KINDS = {"GuiChoice": "Choice", "GuiChoiceCase": "ChoiceCase", "GuiChoiceEnd": "ChoiceEnd"}
BRANCH_EVENTS = BRANCH_KINDS | {"Portrait", "Hide", "Background", "Transition"} | BG_KINDS | BLUR_KINDS


def event_values(kind, fields):
    base = BASE_KINDS.get(kind)
    if base is None:
        raise ValueError("未知分支轨道事件")
    extras = ({"completion", "merge_beat_id"} if kind == "GuiChoice"
              else {"track_id"} if kind == "GuiChoiceCase" else set())
    if not extras <= set(fields):
        raise ValueError("分支轨道缺少出口或轨道 ID")
    result = values(base, {k: v for k, v in fields.items() if k not in extras})
    if kind == "GuiChoice":
        choice_options(result)
        mode, target = fields["completion"], fields["merge_beat_id"]
        if mode not in ("merge", "end"):
            raise ValueError("分支出口须明确汇合或结束场景")
        if mode == "end" and target is not None:
            raise ValueError("结束分支不能同时指定汇合节拍")
        if mode == "merge" and (not isinstance(target, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", target)):
            raise ValueError("分支缺少明确的汇合节拍 ID")
        result.update(completion=mode, merge_beat_id=target)
    elif kind == "GuiChoiceCase":
        track = fields["track_id"]
        if not isinstance(track, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", track):
            raise ValueError("分支轨道 ID 不合法")
        result["track_id"] = track
    return result


def base_event(event):
    """Closed type check, then drop only GUI control-flow metadata."""
    kind = event["kind"]
    parsed = event_values(kind, {k: v for k, v in event.items() if k != "kind"})
    extras = {"completion", "merge_beat_id", "track_id"}
    return {"kind": BASE_KINDS[kind], **{k: v for k, v in parsed.items() if k not in extras}}


def validate_track_structure(events):
    """Also guard raw typed programs, not just SceneBuilder output."""
    active, track_ids = None, set()
    for index, event in enumerate(events):
        kind = event["kind"]
        if kind in KINDS:
            event_values(kind, {k: v for k, v in event.items() if k != "kind"})
        if kind == "GuiChoice":
            if active is not None:
                raise ValueError("本轮不支持分支内再嵌套选项")
            active = event
        elif kind in ("GuiChoiceCase", "GuiChoiceEnd"):
            if active is None or event["choice_id"] != active["choice_id"]:
                raise ValueError("轨道入口或汇合不属于当前选项")
            if kind == "GuiChoiceCase":
                if event["track_id"] in track_ids:
                    raise ValueError("分支轨道 ID 重复")
                track_ids.add(event["track_id"])
            else:
                if active["completion"] == "end" and (
                        index != len(events)-2 or events[-1]["kind"] != "End"):
                    raise ValueError("结束场景的分支之后不能再放公共节拍")
                active = None
    if active is not None:
        raise ValueError("分支轨道缺少明确出口")


class GuiTrackChoiceEmitter(ChoiceEmitter):
    # Background identity matters at a merge; a mere loaded=True is not enough.
    STATE = ChoiceEmitter.STATE + ("gui_background", "gui_background_blur", "cg_dissolve_pending", "bg_dissolve_pending")

    @staticmethod
    def execution_state(state):
        comparable = deepcopy(state)
        for actor in comparable["actors"].values():
            # Load-time bookkeeping can differ after an explicit fade-out /
            # reload / fade-in even when the actual final native pose agrees.
            # Neither field drives a subsequent native Action/Camera motion.
            actor.pop("source_event", None)
            actor.pop("stage", None)
        return comparable

    def branch_end(self):
        block = self.active
        if not block["case"]:
            return
        if block["completion"] == "end":
            # Each alternative finishes with its own actual actor/CG state.
            # No fabricated common state, longest-route padding or implicit
            # move/resize/expression reset. The native tail cannot fall through.
            self.e.transition({"method": "black_out", "duration_ms": 800})
            self.e.cleanup()
            self.e.resume_original()
            return
        self.e.join()
        state = self.state()
        if block["end_state"] is not None and self.execution_state(state) != self.execution_state(block["end_state"]):
            raise ValueError(f"轨道 {block['track_id']} 无法接入公共节拍：立绘、CG、背景或镜头状态不一致；请明确恢复一致状态，不会自动改坐标或大小")
        block["end_state"] = state
        block["ends"].append(len(self.e.output))
        self.e.output.extend(b"\x06\0\0\0\0")

    def emit(self, event):
        kind, e = event["kind"], self.e
        parsed = base_event(event)
        if kind == "GuiChoice":
            super().emit(parsed)
            self.active.update(completion=event["completion"], track_id=None)
        elif kind == "GuiChoiceCase":
            super().emit(parsed)
            self.active["track_id"] = event["track_id"]
        else:
            block = self.active
            if block["completion"] == "merge":
                super().emit(parsed)
            else:
                self.branch_end()
                e.speech = None
                # An unexpected native choice result returns to the menu.
                struct.pack_into("<I", e.output, block["skip"] + 1, block["start"])
                self.active = None
                e.gui_tracks_finished = True
