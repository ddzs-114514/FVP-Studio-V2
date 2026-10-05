"""Whole-body swaps on the source-locked independent GUI portrait stage.

The second primitive is extracted from the original dispatcher, not guessed
from a title or a character's artwork. Both layers use the existing native
sprite/group/alpha helpers. This does not enable another game's renderer.
"""
from copy import deepcopy
from functools import lru_cache
import hashlib
import struct

from .native_portrait_acceptance import _selector_branch
from .performance_compile import (PRIMS, SOURCE_SHA, CLEAN_SHA, STOPS, call,
                                  rounded, _baseline_document)
from .portrait_emitter import _encode_push

# Selectors in this exact original dispatcher; slots may share selectors in
# other profiles. These are not global FVP slot IDs.
SELECTORS = {1: 12, 2: 13, 3: 21, 4: 14}
CONTRACT = "fvp-gui-actor-swap-blend/1"
DEFAULT_DURATION_MS = 200


@lru_cache(maxsize=1)
def original_buffers(clean):
    # Cache the immutable original bytes, not the mutable/unhashable document.
    document = _baseline_document(clean)
    if document.source_sha256 != CLEAN_SHA:
        raise ValueError("换装渐变的目标调用链尚未核对。")
    entries = [i for i in document.instructions if i.opcode == 1]
    start, end = entries[4477].offset, entries[4478].offset
    if start != 0x5BA7A or entries[4477].operands["args"] != 13:
        raise ValueError("换装双缓冲 dispatcher 已漂移。")
    instructions = tuple(i for i in document.instructions if start <= i.offset < end)
    buffers = {}
    for actor, selector in SELECTORS.items():
        pair = _selector_branch(instructions, selector)[2]
        if pair[0] != PRIMS[actor] or len(set(pair)) != 2:
            raise ValueError("换装双缓冲 primitive 不匹配。")
        buffers[actor] = pair[1]
    if len(set(buffers.values()) | set(PRIMS.values())) != 8:
        raise ValueError("换装缓冲与其他角色冲突。")
    return buffers


class NativeActorSwapBlend:
    def __init__(self, emitter):
        self.e = emitter
        self.active = {}

    def report(self):
        return dict(schema=CONTRACT, target="hoshi", clean_hcb_sha256=CLEAN_SHA,
                    dispatcher=0x5BA7A, primitive_pairs={str(a): [PRIMS[a], p]
                        for a,p in original_buffers(self.e.clean).items()},
                    whole_body_and_expression=True, native_import_size_unchanged=True,
                    keeps_authored_position=True, default_duration_ms=DEFAULT_DURATION_MS,
                    legacy_duration_ms=0, same_actor_alpha_overlap=False,
                    runtime_verified=False)

    def clear_shadow(self, actor):
        state = self.active.pop(actor, None)
        if not state:
            return
        e, prim = self.e, state["primitive"]
        for channel, stop in STOPS.items():
            e.output.extend(e.syscall(stop, (prim - 99 if channel == "parts" else prim,)))
        e.output.extend(e.syscall("PrimSetNull", (prim,)))

    def finish_actor(self, actor):
        state = self.active.get(actor)
        if not state:
            return
        e, main, ghost = self.e, PRIMS[actor], state["primitive"]
        owned = {main, main - 99, ghost, ghost - 99}
        for key in list(e.pending):
            if key[0] != "camera" and key[1] in owned:
                e.output.extend(call(e.wait_helper(*key)))
                e.pending.pop(key)
        self.clear_shadow(actor)

    def finish_all(self):
        # Called only AFTER the stage's normal join has finished both fades.
        for actor in tuple(self.active):
            self.clear_shadow(actor)

    def _load_shadow(self, actor, previous, prim):
        e, part = self.e, prim - 99
        for channel, stop in STOPS.items():
            e.output.extend(e.syscall(stop, (part if channel == "parts" else prim,)))
        e.output.extend(e.syscall("PrimSetNull", (prim,)))
        for name, arguments in (
                ("GraphLoad", (part, "graph_bs/" + previous["resource"])),
                ("PartsLoad", (part, "graph_bs/" + previous["resource"] + "_表情"))):
            ident, arity = e.syscalls[name]
            if arity != 2:
                raise ValueError("换装资源 ABI 漂移。")
            e.output.extend(b"".join(_encode_push(v, "shift_jis") for v in arguments)
                            + b"\x03" + struct.pack("<H", ident))
        e.output.extend(e.native("sprite", (prim, part, None, None)))
        e.output.extend(e.syscall("PartsAssign", (part, part)))
        e.output.extend(e.syscall("PartsSelect", (part, previous["expression"])))
        e.output.extend(e.native("group", (prim, 7 + actor)))
        e.output.extend(e.syscall("PrimSetOP", (prim, *previous["pivot"])))
        e.output.extend(e.native("xy_set", (prim, previous["x"], previous["y"])))
        e.output.extend(e.syscall("PrimSetZ", (prim, previous["z"])))
        e.output.extend(e.syscall("PrimSetRS", (prim, previous["r"], previous["sx"])))
        if previous["sx"] != previous["sy"]:
            e.output.extend(e.syscall("PrimSetRS2",
                                     (prim, previous["r"], previous["sx"], previous["sy"])))
        e.output.extend(e.syscall("PrimSetAlpha", (prim, previous["alpha"])))
        # No yield between handing the old visible image to the back buffer
        # and hiding the old main primitive before its new resource is loaded.
        e.output.extend(e.syscall("PrimSetDraw", (prim, True)))
        e.output.extend(e.syscall("PrimSetDraw", (PRIMS[actor], False)))

    def start(self, portrait, resources, policy, duration):
        e, actor = self.e, portrait["actor"]
        if hashlib.sha256(e.source).hexdigest() != SOURCE_SHA:
            raise ValueError("当前目标的换装双缓冲尚未接入，不能套用其他游戏的图元。")
        ghost = original_buffers(e.clean)[actor]
        self.finish_actor(actor)
        # Settle just this actor before copying its old complete body/face.
        # Shared camera and other actors continue running.
        owned = {PRIMS[actor], PRIMS[actor] - 99}
        for key in list(e.pending):
            if key[0] != "camera" and key[1] in owned:
                e.output.extend(call(e.wait_helper(*key)))
                e.pending.pop(key)
        previous = deepcopy(e.actors[actor])
        # Resource checks precede the visible-buffer handoff.
        resources.portrait(portrait)
        self._load_shadow(actor, previous, ghost)
        e.portrait(portrait, resources, replacing=True,
                   keep=policy == "keep", keep_position=True)
        main = PRIMS[actor]
        e.output.extend(e.syscall("PrimSetAlpha", (main, 0)))
        self.active[actor] = dict(primitive=ghost, pose=previous)
        # The old source image has its original size; new geometry is exactly
        # the existing KEEP/SOURCE resolver's result.
        e.start_motion("alpha", main, e.native("alpha",
            (main, 0, previous["alpha"], duration, 0, None, True, 0)))
        e.start_motion("alpha", ghost, e.native("alpha",
            (ghost, previous["alpha"], 0, duration, 0, None, True, 0)))

    def mirror_motion(self, channel, ident):
        # Same-beat body geometry applies to both layers. Expression is new
        # body's Parts only. Author alpha + crossfade needs two alpha channels
        # per layer, so that combination is rejected by the GUI bridge.
        if channel not in ("xy", "z", "r", "s2"):
            return
        actor = next((a for a in self.active if PRIMS[a] == ident), None)
        if actor is None:
            return
        e, shadow = self.e, self.active[actor]
        recorded = e.calls[-1] if e.calls else {}
        if recorded.get("function") != channel:
            raise ValueError("换装期间的图元运动缺少原生调用记录。")
        arguments = list(recorded["arguments"])
        pose, current, ghost = shadow["pose"], e.actors[actor], shadow["primitive"]
        arguments[0] = ghost
        if channel == "xy":
            dx = (arguments[3] - arguments[1]) * current["sx"] / pose["sx"]
            dy = (arguments[4] - arguments[2]) * current["sy"] / pose["sy"]
            arguments[1:5] = [pose["x"], pose["y"],
                             rounded(pose["x"] + dx), rounded(pose["y"] + dy)]
            pose.update(x=arguments[3], y=arguments[4])
        elif channel == "s2":
            sx = rounded(pose["sx"] * arguments[2] / arguments[1])
            sy = rounded(pose["sy"] * arguments[4] / arguments[3])
            arguments[1:5] = [pose["sx"], sx, pose["sy"], sy]
            pose.update(sx=sx, sy=sy)
        else:
            arguments[1:3] = [pose[channel], pose[channel] + arguments[2] - arguments[1]]
            pose[channel] = arguments[2]
        e.start_motion(channel, ghost, e.native(channel, tuple(arguments)))
