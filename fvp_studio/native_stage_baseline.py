"""Prove a target's explicit stage baseline without selecting a story camera.

Embedded-coordinate generations may have a four-argument V3D reset with Nil
defaults instead of the modern FloatToInt wrapper. The source function bytes
and its specialised CFG are checked; a majority/frequent camera is never used.
This remains script evidence, not a claim of native-engine runtime acceptance.
"""
from __future__ import annotations

from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans
from .native_script_state import NativeScriptStateClosure


class NativeStageBaselineUnavailable(NativePortraitAcceptanceError):
    """No matching default wrapper; a separately proven older reset may apply."""


def native_default_camera(source, analysis, *, runtime_context=None):
    flow = NativeFunctionFlow(analysis)
    candidates = []
    for span in _function_spans(analysis):
        if (span.args not in (3, 4) or span.locals != 0
                or span.syscalls.count("V3DSet") != 1
                or set(span.syscalls) - {"V3DSet", "V3DMotionStop"}
                or len(span.instructions) > 256):
            continue
        # Nil selects the target's own x/y/z defaults. The optional fourth
        # argument disables unrelated story-side effects while deriving them.
        arguments = {i: None for i in range(span.args)}
        if span.args == 4:
            arguments[3] = 0
        trace = flow.trace(span.start, literal_arguments=arguments)
        if trace["status"] != "proven_static_argument_flow":
            continue
        calls = trace["calls"]
        if any(c["kind"] != "syscall" or c["name"] not in {"V3DSet", "V3DMotionStop"}
               for c in calls):
            continue
        resets = [c for c in calls if c["name"] == "V3DSet"]
        if len(resets) != 1 or len(resets[0]["arguments"]) != 3:
            continue
        operands = resets[0]["arguments"]
        if any(v.get("kind") != "literal" or type(v.get("value")) is not int for v in operands):
            continue
        camera = tuple(v["value"] for v in operands)
        if camera[2] > 0 or any(not -(2**31) <= v < 2**31 for v in camera):
            continue
        closure = NativeScriptStateClosure(source, analysis, [span.start], runtime_context=runtime_context)
        candidates.append((camera, dict(function_start=span.start, arguments=arguments,
            syscall_offset=resets[0]["offset"], specialised_native_default=True,
            source_function_bytes_checked=True, runtime_verified=False,
            script_dependencies=closure.describe())))
    if not candidates:
        raise NativeStageBaselineUnavailable("未识别到原生默认相机包装函数。")
    if len(candidates) != 1:
        raise NativePortraitAcceptanceError("原生相机复位默认值没有唯一的参数调用链。")
    return candidates[0]
