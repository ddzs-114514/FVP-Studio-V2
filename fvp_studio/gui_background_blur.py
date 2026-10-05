"""Native pre-blurred BG layer control, not a Gaussian/CSS blur.

Hoshi's source chain: BG pair wrapper -> 4384/primitive 187 ->
4413 -> 4405 (MotionAlpha). 4413 maps camera Z with a threshold, so manual
continuous strength uses its same alpha child, never fabricated camera Z.
Only the private copy of 4384 bypasses the global preference guard.
"""
from copy import deepcopy
import math
import struct

from .gui_background_program import _copy_wrapper
from .performance_compile import args, call, jump, rounded
from .performance_workflow import values

CONTRACT = "fvp-gui-background-blur/1"
KINDS = {"GuiBackgroundBlur"}


def event_values(kind, fields):
    if kind not in KINDS or set(fields) != {"source_game", "archive", "resource", "fit",
            "sharp_archive", "sharp_resource", "amount", "duration_ms"}:
        raise ValueError("背景模糊参数不完整。")
    amount, duration = fields["amount"], fields["duration_ms"]
    if type(amount) not in (int, float) or not math.isfinite(amount) or not 0 <= amount <= 100:
        raise ValueError("背景模糊强度为 0～100%。")
    if type(duration) is not int or duration != 0 and not 100 <= duration <= 6000:
        raise ValueError("直接切换设为 0；渐变时长为 100～6000 毫秒。")
    for archive, resource in (("archive", "resource"), ("sharp_archive", "sharp_resource")):
        values("Background", dict(source_game=fields["source_game"], fit=fields["fit"],
            archive=fields[archive], resource=fields[resource]))
    return deepcopy(fields)


def loader(emitter):
    key = ("gui_background_blur_loader", CONTRACT)
    if key not in emitter.helpers:
        skip = len(emitter.output)
        emitter.output.extend(jump(0))
        address = len(emitter.output)
        block, copied = _copy_wrapper(emitter, "bg_blur", 0x52CCF, 0x52DD0,
            address, 0, explicit_blur=True)
        emitter.output.extend(block)
        struct.pack_into("<I", emitter.output, skip+1, len(emitter.output))
        emitter.helpers[key] = dict(address=address, copy=copied,
            primitive=187, original_configuration_unchanged=True)
    return emitter.helpers[key]["address"]


def clear(emitter):
    if emitter.gui_background_blur is not None:
        # Do not leave an old texture available for a later native blur link.
        for name, parameters in (("MotionAlphaStop", (187,)),
                ("PrimSetAlpha", (187, 0)), ("GraphLoad", (187, None))):
            emitter.output.extend(emitter.syscall(name, parameters))
        emitter.output.extend(args([0]) + b"\x15\x46\x00")
        emitter.gui_background_blur = None


def emit_blur(emitter, event, resources):
    if event["kind"] not in KINDS:
        return False
    event_values(event["kind"], {k:v for k,v in event.items() if k != "kind"})
    expected = (event["sharp_archive"], event["sharp_resource"], event["fit"])
    if emitter.cg is not None or not emitter.background_loaded or emitter.gui_background != expected:
        raise ValueError("背景模糊需要当前清晰背景的原作配对；CG 不使用这个动作。")
    if event["duration_ms"] and emitter.covered:
        raise ValueError("黑白场下请直接设置模糊，再用淡入恢复画面。")
    identity = (event["archive"], event["resource"], event["fit"])
    state = emitter.gui_background_blur
    if state is None or state["identity"] != identity:
        # SceneBuilder emits resource preparation before any same-beat motion.
        emitter.join()
        clear(emitter)
        address = loader(emitter)
        parameters = [resources.bg(event), None, 50, None, None, None, None, None, 1]
        emitter.output.extend(args(parameters) + call(address))
        emitter.calls.append(dict(function="gui_background_blur_load", address=address,
                                  arguments=parameters))
        state = dict(identity=identity, alpha=0)
    target = rounded(event["amount"] * 255 / 100)
    duration = event["duration_ms"]
    if duration:
        # Same eight arguments as 4413 -> 4405, with its no-wait path.
        # MotionAlpha has no GUI 2/3 easing parameter; do not reinterpret it.
        parameters = (187, state["alpha"], target, duration, None, None, True, None)
        emitter.start_motion("alpha", 187, emitter.native("alpha", parameters))
    else:
        if ("alpha", 187) in emitter.pending:
            raise ValueError("请等待上一段背景模糊渐变结束后再直接切换。")
        emitter.output.extend(emitter.syscall("MotionAlphaStop", (187,)))
        emitter.output.extend(emitter.syscall("PrimSetAlpha", (187, target)))
    # Source 4413 uses G70 as the target cache, not a current-frame sample.
    emitter.output.extend(args([target]) + b"\x15\x46\x00")
    emitter.gui_background_blur = dict(identity=identity, alpha=target)
    return True


def report(emitter):
    return dict(schema=CONTRACT, target="hoshi", primitive=187,
        source_chain=[4384, 4413, 4405], native_preblurred_image=True,
        continuous_strength="native_alpha_child_of_4413", uses_generated_blur=False,
        uses_web_filter=False, changes_camera=False, native_curve=False,
        portrait_geometry_unchanged=True, original_configuration_unchanged=True,
        adapters=deepcopy([v for k,v in emitter.helpers.items()
            if isinstance(k,tuple) and k[0] == "gui_background_blur_loader"]),
        runtime_verified=False)
