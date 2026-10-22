"""Lower a CG colour exit and instantaneous stage setup under its cover.

This is not a parallel CG/portrait animation or visible overlay. The exit
owns the only fade; setup is committed while covered, before an authored
reveal. Native helpers and their units remain target-bound downstream.
"""

from copy import deepcopy

from .gui_actor_program import number


POSE_KIND = "GuiActorPoseSet"
POSE_ACTIONS = {"move", "scale", "depth", "tilt"}
SETUP_ORDER = {name: i for i, name in enumerate((
    "bg", "exit", "enter", "swap", "expr", "depth", "scale", "tilt", "move", "camera", "bgblur"))}


def pose_values(fields):
    """Internal covered-stage event, deliberately not a zero-time motion."""
    allowed = {"actor", "x", "y", "scale_x", "scale_y", "depth", "rotation"}
    if (not isinstance(fields, dict) or not {"actor"} < set(fields)
            or set(fields) - allowed
            or ("x" in fields) != ("y" in fields)
            or ("scale_x" in fields) != ("scale_y" in fields)):
        raise ValueError("遮盖内的角色姿态参数不完整。")
    bounds = {"actor": (1, 4), "x": (-640, 1920), "y": (-720, 1800),
        "scale_x": (50, 150), "scale_y": (50, 150), "depth": (500, 2400),
        "rotation": (-1000, 1000)}
    for key, value in fields.items():
        number(value, *bounds[key], "角色姿态 " + key, integer=key not in {"x", "y"})
    return deepcopy(fields)


def pose_capability(document, *, rotation_degrees_supported=False):
    """Bind direct setters independently of a target's motion wrappers."""
    from .native_portrait_buffer_geometry import SETTERS
    rows = getattr(getattr(document, "header", None), "syscalls", ())
    calls = {row.name: row.args for row in rows}
    supported = len(calls) == len(rows) and all(calls.get(n) == argc for n, argc in SETTERS)
    actions = ["move", "scale", "depth"] if supported else []
    if supported and rotation_degrees_supported is True:
        actions.append("tilt")
    return dict(supported=supported, actions=actions,
        nonuniform_scale=supported and calls.get("PrimSetRS2") == 4,
        current_native_buffer_only=True, motion_zero_used=False, runtime_verified=False)


def ordered_exit_setup(actions):
    visual = [a for a in actions if a["type"] not in {"bgm", "se"}]
    exits = [a for a in visual if a["type"] == "cgexit"]
    if len(exits) != 1:
        raise ValueError("CG 遮盖交接需要一个明确的黑／白退场。")
    setup = [a for a in visual if a is not exits[0]]
    for action in setup:
        if action["type"] not in SETUP_ORDER or action["dur"] != 0:
            raise ValueError("CG 退场同拍只接零时长的背景、角色和镜头设置；带时长的运动请放到后续节拍。")
        if action["type"] in {"enter", "exit"} and action["p"].get("preset") != "cut":
            raise ValueError("CG 遮盖内的角色入退场请选直接切换；淡入淡出或滑动放到后续节拍。")
        if action["type"] == "exit" and any(a is not action and a["target"] == action["target"] for a in setup):
            raise ValueError("同拍直接退场的角色不能再换装或设置姿态，请分拍。")
    # Body/expression fusion and native entry geometry are handled by
    # SceneBuilder. All setup is hidden, not animated in this imposed order.
    return sorted(actions, key=lambda a: (
        -2 if a["type"] in {"bgm", "se"} else -1 if a["type"] == "cgexit"
        else SETUP_ORDER[a["type"]], a["target"], a["id"]))


def contract():
    return dict(supported=True, beat_kind="wait", colours=["black", "white"],
        stage_actions=list(SETUP_ORDER), stage_duration_ms=0,
        actor_entry_exit="cut", ordering="exit_wait_then_covered_setup",
        pose_event=POSE_KIND, pose_binding="target_raw_current_buffer_setters",
        position_uses_final_scale_and_depth=True,
        source_size_rule_changed=False, explicit_reveal_required=True,
        input_array_order_independent=True, visible_cg_portrait_overlay=False,
        target_support_required=True, runtime_verified=False)
