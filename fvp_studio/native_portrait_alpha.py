"""Target-owned nonblocking alpha calls for different native FVP generations.

Derive operands from the ORIGINAL helper's complete argument flow, including
its native cache writes and skip policy. Do not assume that an alpha helper
has eight arguments or require unrelated XY/rotation helpers to match Hoshi.
The proven nonblocking call must reach exactly one MotionAlpha syscall and no
wait/callee. The full original dependency closure still stays byte-bound.
This grants neither primitive ownership nor runtime/rendering acceptance.
"""
from __future__ import annotations

from copy import deepcopy

from .hoshimemo_scene_hook import _call
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-portrait-alpha/1"
LAYOUTS = {
    5: dict(syscall_args=5, tail=(None,), nonblocking={4: None}),
    6: dict(syscall_args=5, tail=(0, None), nonblocking={4: 0}),
    7: dict(syscall_args=6, tail=(0, None, True), nonblocking={4: 0}),
    8: dict(syscall_args=6, tail=(0, None, True, 0), nonblocking={4: 0, 7: 0}),
}


def _argument(index):
    return dict(kind="argument", index=index)


def _duration(value):
    # Preserve the source helper's existing fast-forward/skip override. Only
    # the requested duration or its exact native 1-ms override is admitted.
    if value == _argument(3):
        return True
    if value.get("kind") != "choice":
        return False
    members = value.get("operands", ())
    return (len(members) == 2 and _argument(3) in members
            and dict(kind="literal", type="int", value=1) in members)


class NativePortraitAlpha:
    def __init__(self, source, analysis, *, runtime_context=None):
        pair = validate_native_script_pair(source, analysis, runtime_context=runtime_context)
        flow = NativeFunctionFlow(analysis)
        candidates = []
        for span in _function_spans(analysis):
            layout = LAYOUTS.get(span.args)
            if (layout is None or span.locals != 0 or len(span.instructions) > 2048
                    or span.syscalls != ("MotionAlpha", "MotionAlphaTest")):
                continue
            trace = flow.trace(span.start, literal_arguments=layout["nonblocking"],
                               max_instructions=2048, max_joined_values=128)
            calls = trace.get("calls", ())
            if (trace["status"] != "proven_static_argument_flow" or len(calls) != 1
                    or calls[0].get("kind") != "syscall" or calls[0].get("name") != "MotionAlpha"
                    or calls[0].get("argument_count") != layout["syscall_args"]):
                continue
            arguments = calls[0]["arguments"]
            expected_tail = ([_argument(5), _argument(6)] if span.args in (7, 8)
                             else [_argument(5)] if span.args == 6
                             else [dict(kind="literal", type="NoneType", value=None)])
            if (arguments[:3] != [_argument(i) for i in range(3)]
                    or not _duration(arguments[3]) or arguments[4:] != expected_tail):
                continue
            candidates.append((span, layout, trace, calls[0]))
        if len(candidates) != 1:
            raise NativePortraitAcceptanceError("目标的原生淡入淡出参数尚不能唯一确定。")
        span, layout, trace, call = candidates[0]
        closure = NativeScriptStateClosure(source, analysis, [span.start],
            runtime_context=runtime_context, max_functions=128, max_instructions=32768)
        self.address, self.argument_count = span.start, span.args
        self.global_ids = closure.global_ids
        self._tail = layout["tail"]
        self._report = dict(schema=SCHEMA, source_sha256=source.source_sha256,
            analysis_sha256=analysis.source_sha256, helper=span.start, helper_args=span.args,
            native_syscall_args=layout["syscall_args"], native_syscall_offset=call["offset"],
            nonblocking_arguments=dict(layout["nonblocking"]),
            native_argument_flow=deepcopy(call),
            native_cache_writes=deepcopy(trace["global_writes"]),
            native_dependency_closure=closure.describe(), runtime_binding=pair,
            native_helper_side_effects_preserved=True, nonblocking_path_proven=True,
            primitive_ownership_granted=False, game_name_switch_used=False, runtime_verified=False)

    def compile(self, primitive_operand, start, end, duration_ms):
        if type(primitive_operand) is not bytes or not primitive_operand:
            raise NativePortraitAcceptanceError("淡入淡出缺少已分配的图元表达式。")
        if (any(type(v) is not int or not 0 <= v <= 255 for v in (start, end))
                or type(duration_ms) is not int or not 0 <= duration_ms <= 6000):
            raise NativePortraitAcceptanceError("原生淡入淡出数值无效。")
        values = (start, end, duration_ms, *self._tail)
        return primitive_operand + b"".join(_encode_push(v, "shift_jis") for v in values) + _call(self.address)

    def call(self, primitive, start, end, duration_ms):
        if type(primitive) is not int or not 0 <= primitive < 2**31:
            raise NativePortraitAcceptanceError("淡入淡出的图元编号无效。")
        return self.compile(_encode_push(primitive, "shift_jis"), start, end, duration_ms)

    def report(self):
        return deepcopy(self._report)
