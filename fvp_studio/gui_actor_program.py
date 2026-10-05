"""GUI actor operations on the existing native stage; import sizes stay intact."""
from copy import deepcopy
import math

from .performance_compile import PRIMS, rounded
from .performance_workflow import values

CONTRACT = "fvp-gui-actor-actions/1"
KINDS = {"GuiActorSlide", "GuiActorMove", "GuiActorSwap"}


def number(value, low, high, label, *, integer=False):
    if (type(value) not in (int, float) or not math.isfinite(value)
            or not low <= value <= high or integer and int(value) != value):
        raise ValueError(f"{label}超出范围。")
    return int(value) if integer else value


def event_values(kind, fields):
    if kind == "GuiActorSwap":
        if (not {"portrait", "policy"} <= set(fields)
                or set(fields) - {"portrait", "policy", "duration_ms"}
                or fields["policy"] not in ("keep", "source")):
            raise ValueError("换身体需要明确的新素材和大小策略。")
        number(fields.get("duration_ms", 0), 0, 6000, "换装时长", integer=True)
        portrait = fields["portrait"]
        if not isinstance(portrait, dict):
            raise ValueError("换身体参数不正确。")
        # No per-game guesses: the caller has checked the new body's native size.
        if set(portrait) != set(values("Portrait", portrait)):
            raise ValueError("换身体包含未知参数。")
        values("Portrait", portrait)
    elif kind in ("GuiActorSlide", "GuiActorMove"):
        required = {"actor", "x", "y", "duration_ms", "curve"}
        if kind == "GuiActorSlide":
            required |= {"phase", "direction", "height"}
        if set(fields) != required:
            raise ValueError("立绘移动参数不完整。")
        number(fields["actor"], 1, 4, "角色槽", integer=True)
        number(fields["x"], -640, 1920, "目标横坐标")
        number(fields["y"], -720, 1800, "目标纵坐标")
        number(fields["duration_ms"], 100, 6000, "移动时长", integer=True)
        if type(fields["curve"]) is not int or fields["curve"] not in (2, 3):
            raise ValueError("动作曲线不正确。")
        if kind == "GuiActorSlide":
            if fields["phase"] not in ("enter", "exit") or fields["direction"] not in ("left", "right"):
                raise ValueError("滑入滑出方向不正确。")
            number(fields["height"], 1, 10000, "立绘高度")
    else:
        raise ValueError("未知立绘动作。")
    return deepcopy(fields)


def native_xy(state, x, y):
    """Inverse of projected_anchor at the stage baseline, not face alignment.

    Use the ACTUAL current native scales/depth, including earlier scale/swap
    operations. Shared story-camera movement remains a separate operation.
    """
    distance = state["z"] + 200
    return (rounded((x - 640) * 1.5 * distance / state["sx"] / 2.4),
            rounded((y - 360) * 1.5 * distance / state["sy"] / 1.8))


def emit_actor(emitter, event, resources):
    kind = event["kind"]
    if kind not in KINDS:
        return False
    event_values(kind, {k: v for k, v in event.items() if k != "kind"})
    if kind == "GuiActorSwap":
        portrait = dict(event["portrait"], kind="Portrait")
        if emitter.cg is not None or not emitter.background_loaded:
            raise ValueError("请在立绘舞台中换身体。")
        previous = emitter.actors.get(portrait["actor"])
        if previous is None:
            raise ValueError("换身体的角色尚未入场。")
        portrait["alpha"] = previous["alpha"]
        if event.get("duration_ms", 0) > 0:
            emitter.actor_swap_blend.start(portrait, resources, event["policy"], event["duration_ms"])
        else:
            emitter.portrait(portrait, resources, replacing=True,
                             keep=event["policy"] == "keep", keep_position=True)
        return True
    actor = event["actor"]
    if actor not in emitter.actors or emitter.cg is not None:
        raise ValueError("动作角色尚未入场或已经退场。")
    state, prim = emitter.actors[actor], PRIMS[actor]
    x, y = event["x"], event["y"]
    if kind == "GuiActorSlide":
        off = -event["height"] * .3 if event["direction"] == "left" else 1280 + event["height"] * .3
        if event["phase"] == "enter":
            start_x, start_y = native_xy(state, off, y)
            emitter.output.extend(emitter.native("xy_set", (prim, start_x, start_y)))
            state.update(x=start_x, y=start_y)
        else:
            x = off
    nx, ny = native_xy(state, x, y)
    emitter.start_motion("xy", prim, emitter.native("xy", (
        prim, state["x"], state["y"], nx, ny, event["duration_ms"], event["curve"], True, 0, -1)))
    state.update(x=nx, y=ny)
    if kind == "GuiActorSlide":
        alpha = 255 if event["phase"] == "enter" else 0
        # Use the established nonblocking native fade for the whole slide.
        # The legacy HTML's 40%-duration approximation is not a native timing
        # claim; this policy is exposed in the health/GUI handoff contract.
        emitter.start_motion("alpha", prim, emitter.native("alpha", (
            prim, state["alpha"], alpha, event["duration_ms"], 0, None, True, 0)))
        state["alpha"] = alpha
    return True
