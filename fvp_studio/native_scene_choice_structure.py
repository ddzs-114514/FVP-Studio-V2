"""Bounded native scene choice grammar, independent of the Hoshi emitter.

Every nested menu stays within its selected parent route and has a complete,
explicit merge. This does not grant arbitrary jumps or nested scene exits.
"""
import re

from .gui_choice_tracks import KINDS as GUI_KINDS, base_event
from .performance_choices import CHOICE_KINDS, choice_options
from .performance_workflow import values

MAX_NESTING = 8


def validate_scene_choices(events, branch_kinds, *, scene_end_indexes=()):
    stack, choice_ids, track_ids = [], set(), set()
    for position, event in enumerate(events):
        kind = event["kind"]
        parsed = (base_event(event, encoding=None) if kind in GUI_KINDS else
                  dict(kind=kind, **values(kind, {k: v for k, v in event.items() if k != "kind"}))
                  if kind in CHOICE_KINDS else event)
        base_kind = parsed["kind"]
        if base_kind == "Choice":
            ident = parsed["choice_id"]
            if (not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", ident)
                    or ident in choice_ids):
                raise ValueError("选项 ID 须合法且唯一，包括嵌套选项。")
            if stack and not stack[-1]["case"]:
                raise ValueError("选项后须先连接分支入口，不能直接开始嵌套选项。")
            if len(stack) >= MAX_NESTING:
                raise ValueError("嵌套选项超过允许的 8 层。")
            mode = event.get("completion", "merge")
            if stack and mode != "merge":
                raise ValueError("嵌套选项须接回所在分支的下一节拍；嵌套结束场景尚未接入。")
            choice_ids.add(ident)
            stack.append(dict(ident=ident, options=len(choice_options(parsed, encoding=None)),
                              case=0, mode=mode, gui=kind in GUI_KINDS))
        elif base_kind in {"ChoiceCase", "ChoiceEnd"}:
            if (not stack or parsed["choice_id"] != stack[-1]["ident"]
                    or (kind in GUI_KINDS) != stack[-1]["gui"]):
                raise ValueError("分支入口或汇合与当前选项不一致。")
            block = stack[-1]
            if base_kind == "ChoiceCase":
                index = parsed["option_index"]
                if type(index) is not int or index != block["case"]+1 or index > block["options"]:
                    raise ValueError("每个选项须按 1～N 顺序具有唯一分支入口。")
                if kind in GUI_KINDS:
                    if event["track_id"] in track_ids:
                        raise ValueError("分支轨道 ID 重复，包括嵌套选项。")
                    track_ids.add(event["track_id"])
                block["case"] = index
            else:
                if block["case"] != block["options"]:
                    raise ValueError("选项缺少分支入口。")
                if (block["mode"] == "end" and position+1 not in scene_end_indexes
                        and (position != len(events)-2 or events[-1]["kind"] != "End")):
                    raise ValueError("结束场景的分支之后不能再放公共节拍。")
                stack.pop()
        elif stack:
            if not stack[-1]["case"]:
                raise ValueError("选项后须先连接分支入口。")
            if kind not in branch_kinds:
                raise ValueError("此内容尚不能放在当前目标的选项分支中："+kind)
    if stack:
        raise ValueError("选项缺少明确汇合节点。")
