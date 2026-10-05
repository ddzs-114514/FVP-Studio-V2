"""Target-independent story values and explicit conditional scene routes.

No original-game global numbers, Python expressions, paths or UI state enter
this contract. Values belong to the authored project, not a preview selection.
"""
from copy import deepcopy
import re

CONTRACT = "fvp-gui-story-logic/1"
MAX_VARIABLES = 64
MAX_EFFECTS = 32
INT_LIMIT = 1000000
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
COMPARE = {"eq": 0x22, "ne": 0x23, "gt": 0x24, "ge": 0x25, "lt": 0x26, "le": 0x27}
KINDS = {"GuiStoryEffect"}


def scalar(value, kind):
    if kind == "bool":
        if type(value) is not bool:
            raise ValueError("开关值只能是 true / false。")
    elif type(value) is not int or not -INT_LIMIT <= value <= INT_LIMIT:
        raise ValueError("剧情数值须为 -1000000～1000000 的整数。")
    return value


def variables(value):
    if not isinstance(value, dict) or len(value) > MAX_VARIABLES:
        raise ValueError("剧情变量须为最多 64 项的表。")
    result = {}
    for key, definition in value.items():
        if not isinstance(key, str) or not ID.fullmatch(key):
            raise ValueError("剧情变量 ID 不正确。")
        if not isinstance(definition, dict) or set(definition) != {"name", "type", "initial"}:
            raise ValueError("剧情变量需要名称、类型和初始值。")
        name, kind = definition["name"], definition["type"]
        if not isinstance(name, str) or not name.strip() or len(name) > 128 or "\0" in name:
            raise ValueError("剧情变量名称不能为空。")
        if kind not in ("int", "bool"):
            raise ValueError("剧情变量只支持整数或开关。")
        scalar(definition["initial"], kind)
        result[key] = deepcopy(definition)
    return result


def effect(value, definitions):
    if not isinstance(value, dict) or set(value) != {"variable", "op", "value"}:
        raise ValueError("剧情赋值需要变量、操作和值。")
    key, op = value["variable"], value["op"]
    if not isinstance(key, str) or key not in definitions:
        raise ValueError("引用的剧情变量不存在，请重新选择。")
    kind = definitions[key]["type"]
    if op not in ("set", "add") or op == "add" and kind != "int":
        raise ValueError("开关只能设置；整数可以设置或增减。")
    scalar(value["value"], kind)
    return deepcopy(value)


def effects(value, definitions):
    if not isinstance(value, list) or len(value) > MAX_EFFECTS:
        raise ValueError("同一处最多设置 32 项剧情赋值。")
    # Order is meaningful: set followed by add is deliberately not deduplicated.
    return [effect(item, definitions) for item in value]


def predicate(value, definitions):
    if not isinstance(value, dict) or set(value) != {"variable", "op", "value"}:
        raise ValueError("条件需要变量、比较方式和值。")
    key, op = value["variable"], value["op"]
    if not isinstance(key, str) or key not in definitions:
        raise ValueError("条件引用的剧情变量不存在。")
    kind = definitions[key]["type"]
    if op not in COMPARE or kind == "bool" and op not in ("eq", "ne"):
        raise ValueError("开关只能比较相同或不同；整数还可比较大小。")
    scalar(value["value"], kind)
    return deepcopy(value)


def event_values(kind, fields, definitions):
    if kind != "GuiStoryEffect":
        raise ValueError("未知剧情变量指令。")
    return effect(fields, definitions)


def route_targets(route):
    if route["mode"] == "condition":
        return [route["then"], route["else"]]
    return [route["target"]] if route["target"] else [o["target"] for o in route["options"]]


def initial_state(definitions):
    return {key: value["initial"] for key, value in definitions.items()}


def apply_effects(state, items, definitions):
    """Small reference runner for backend/GUI agreement, not native acceptance."""
    if set(state) != set(definitions):
        raise ValueError("剧情状态与变量表不一致。")
    result = {key: scalar(state[key], definition["type"]) for key, definition in definitions.items()}
    for item in effects(items, definitions):
        key, op, value = item["variable"], item["op"], item["value"]
        result[key] = value if op == "set" else max(-INT_LIMIT, min(INT_LIMIT, result[key] + value))
    return result


def evaluate(state, test, definitions):
    test = predicate(test, definitions)
    key, op, right = test["variable"], test["op"], test["value"]
    left = scalar(state[key], definitions[key]["type"])
    return {"eq": lambda: left == right, "ne": lambda: left != right,
            "gt": lambda: left > right, "ge": lambda: left >= right,
            "lt": lambda: left < right, "le": lambda: left <= right}[op]()
