"""Structured, non-nested choices on the hash-bound Hoshimemo owned stage.

Native ABI: original 4501(text, Nil, optional icon) / 4502(), result G98,
1-based. See function_validation/build_choice_registration_result_probe_v40.py
and hidden UI init v61. No arbitrary addresses or scratch globals are exposed.
Native menu styling, keyboard behavior and save/backlog remain in-game QA.
"""
import copy
import re
import struct

from .portrait_emitter import _encode_push

CHOICE_KINDS = {"Choice", "ChoiceCase", "ChoiceEnd"}
BRANCH_KINDS = {"Text", "Speech", "Dialogue", "Wait", "Action", "Camera", "CameraShot", "CameraNative", "CGAction"}


def choice_options(event):
    options = [event[f"option_{i}"] for i in range(1, 5)]
    while options and not options[-1].strip():
        options.pop()
    if len(options) < 2 or any(not text.strip() for text in options):
        raise ValueError("选项需要连续的 2～4 个非空标题；第三项为空时不能填写第四项")
    if len(set(options)) != len(options):
        raise ValueError("选项标题不能完全相同")
    for text in [event["prompt"], *options]:
        if not text.strip():
            raise ValueError("选项提示不能留空")
        _encode_push(text, "gbk")
    return options


def validate_choices(events, *, partial=False, branch_kinds=None):
    # Only a separately typed GUI bridge may supply its broader beat set.
    # Ordinary Comfy/production programs keep the original restricted contract.
    allowed = BRANCH_KINDS if branch_kinds is None else branch_kinds
    active, used, count = None, set(), 0
    for event in events:
        kind = event["kind"]
        if kind == "Choice":
            ident = event["choice_id"]
            if active or ident in used or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", ident):
                raise ValueError("选项 ID 必须唯一；首版不支持嵌套选项")
            used.add(ident)
            active, count = (ident, len(choice_options(event))), 0
        elif kind in ("ChoiceCase", "ChoiceEnd"):
            if not active or event["choice_id"] != active[0]:
                raise ValueError("分支 / 汇合节点的选项 ID 与当前选项不一致")
            if kind == "ChoiceCase":
                if event["option_index"] != count + 1 or count >= active[1]:
                    raise ValueError("选项分支须按 1～N 排列，每项恰好一个分支")
                count += 1
            else:
                if count != active[1]:
                    raise ValueError("选项缺少分支，请为每个选项添加分支入口")
                active = None
        elif active and not count:
            raise ValueError("选项节点后必须先连接“分支入口”；请从舞台的“＋选项与分支”生成完整结构，或先选择选项前的节点加入素材")
        elif active and kind not in allowed:
            raise ValueError("当前位置在选项分支内，暂不能新增立绘、BG、CG 或换场；请选中“分支汇合”节点后再加入素材")
    if active and not partial:
        raise ValueError("选项缺少汇合节点")


class ChoiceEmitter:
    STATE = ("actors", "cg", "camera", "camera_reference", "background_loaded", "covered")

    def __init__(self, emitter):
        self.e = emitter
        self.active = None

    def state(self):
        return {name: copy.deepcopy(getattr(self.e, name)) for name in self.STATE}

    def branch_end(self):
        block = self.active
        if not block["case"]:
            return
        self.e.join()
        state = self.state()
        if block["end_state"] is not None and state != block["end_state"]:
            raise ValueError("分支汇合时立绘 / CG / 镜头状态不一致；请在各分支末尾恢复一致位置、表情、大小及透明度")
        block["end_state"] = state
        block["ends"].append(len(self.e.output))
        self.e.output.extend(b"\x06\0\0\0\0")

    def emit(self, event):
        kind, e = event["kind"], self.e
        if kind == "Choice":
            e.join()
            if e.covered:
                raise ValueError("选项出现前请先恢复黑 / 白场")
            start = len(e.output)
            # A choice prompt is narration, not the preceding speaker's line.
            e.set_speech_identity()
            e.speech = dict(name='', text=event['prompt'])
            # Non-empty private print initialises native message/choice UI,
            # without re-submitting the original portrait dispatcher or waiting
            # for a separate dialogue click. Same owned-stage print as Text.
            for value in (event["prompt"], None, None, None):
                e.output.extend(_encode_push(value, "gbk"))
            e.output.extend(b"\x02" + struct.pack("<I", e.text_target))
            for text in choice_options(event):
                e.output.extend(e.native("choice_add", (text, None, None)))
            e.output.extend(e.native("choice_show"))
            self.active = dict(start=start, baseline=self.state(), case=0,
                               skip=None, ends=[], end_state=None)
        elif kind == "ChoiceCase":
            self.branch_end()
            e.speech = None  # Never preview the preceding branch's final line.
            block = self.active
            if block["skip"] is not None:
                struct.pack_into("<I", e.output, block["skip"] + 1, len(e.output))
            for name, value in block["baseline"].items():
                setattr(e, name, copy.deepcopy(value))
            block["case"] = event["option_index"]
            e.output.extend(b"\x0f\x62\x00" + _encode_push(block["case"], "gbk") + b"\x22")
            block["skip"] = len(e.output)
            e.output.extend(b"\x07\0\0\0\0")
        elif kind == "ChoiceEnd":
            self.branch_end()
            e.speech = None  # The selected branch is unknown in a static preview.
            block = self.active
            # An unexpected native result retries the menu instead of executing
            # an arbitrary branch. No re-use of a result across nested choices.
            struct.pack_into("<I", e.output, block["skip"] + 1, block["start"])
            for at in block["ends"]:
                struct.pack_into("<I", e.output, at + 1, len(e.output))
            self.active = None
