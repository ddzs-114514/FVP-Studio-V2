"""Bind each target's nonblocking native motion by complete parameter flow.

Different wrapper generations and raw/scaled XY helpers are independent.
Every supplied primitive/from/to/time/curve/option position must reach the
native syscall unchanged, except the original fast-forward 1-ms override.
An XY conversion is accepted only through the exact, pure four-axis
FloatToInt helper. Native caches and the complete dependency bytes stay owned
by this target. This is not engine rendering or a degree-unit conversion.
"""
from __future__ import annotations

from copy import deepcopy
import math
from types import MappingProxyType

from .hoshimemo_scene_hook import _call
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .native_stage_motion import _SemanticImage
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-portrait-motion-flow/1"
ROLES = {"xy": ("MotionMove", 8, 5), "z": ("MotionMoveZ", 6, 3),
         "s2": ("MotionMoveS2", 8, 5), "r": ("MotionMoveR", 6, 3)}


def _argument(index):
    return dict(kind="argument", index=index)


def _duration(value, index):
    if value == _argument(index):
        return True
    members = value.get("operands", ())
    return (value.get("kind") == "choice" and len(members) == 2
            and _argument(index) in members
            and dict(kind="literal", type="int", value=1) in members)


def _direct_arguments(arguments, count, duration):
    return (len(arguments) == count and _duration(arguments[duration], duration)
            and all(v == _argument(i) for i, v in enumerate(arguments) if i != duration))


def _converted_xy(flow, span):
    """Prove the delegate, not just the presence of four float constants."""
    if span.args != 8 or span.locals != 4 or span.calls:
        return None
    if span.syscalls != ("FloatToInt",) * 4 + ("MotionMove",):
        return None
    # Reuse only the bounded exact axis instruction matcher, not a reference
    # game's semantic family or global names. All other operands are checked
    # below against this target's actual syscall argument flow.
    image = _SemanticImage.__new__(_SemanticImage)
    image.document, image.xy_factors = flow.document, {}
    offsets = image._xy_parameters(span, span.instructions)
    if not offsets:
        return None
    factors = image.xy_factors.get(span.start)
    traced = flow.trace(span.start, max_joined_values=128, non_nil_arguments=range(8))
    calls = traced.get("calls", ())
    if (traced["status"] != "proven_static_argument_flow" or traced["global_writes"]
            or len(calls) != 5 or any(c["kind"] != "syscall" for c in calls)
            or calls[-1].get("name") != "MotionMove" or calls[-1]["argument_count"] != 8):
        return None
    expected = [_argument(0)]
    for index, conversion in enumerate(calls[:4], 1):
        factor = factors["x" if index in (1, 3) else "y"]
        argument = dict(kind="mul", operands=[_argument(index),
            dict(kind="literal", type="float", value=factor)])
        if (conversion.get("name") != "FloatToInt" or conversion["argument_count"] != 1
                or conversion["arguments"] != [argument]):
            return None
        expected.append(dict(kind="call_return", call_kind="syscall", target="FloatToInt",
            offset=conversion["offset"], arguments=[argument], semantics_reviewed=False))
    expected += [_argument(i) for i in (5, 6, 7)]
    if calls[-1]["arguments"] != expected:
        return None
    return dict(factors=factors, delegate=span.start, native_argument_flow=deepcopy(calls[-1]),
                conversion_argument_flows=deepcopy(calls[:4]))


class NativePortraitMotion:
    def __init__(self, source, analysis, channels, *, runtime_context=None):
        pair = validate_native_script_pair(source, analysis, runtime_context=runtime_context)
        if type(channels) not in (tuple, list, set, frozenset) or any(type(c) is not str for c in channels):
            raise NativePortraitAcceptanceError("场景动作需要明确的目标原生通道。")
        channels = tuple(sorted(set(channels)))
        if not channels or set(channels) - ROLES.keys():
            raise NativePortraitAcceptanceError("场景动作需要明确的目标原生通道。")
        spans = _function_spans(analysis)
        by_start = {span.start: span for span in spans}
        flow = NativeFunctionFlow(analysis)
        bindings, proofs, roots = {}, {}, []
        for channel in channels:
            name, count, duration = ROLES[channel]
            candidates = []
            for span in spans:
                if (span.locals != 0 or span.args not in (count + 1, count + 2)
                        or len(span.instructions) > 2048):
                    continue
                delegated = channel == "xy" and span.syscalls == (name + "Test",)
                if not delegated and span.syscalls != (name, name + "Test"):
                    continue
                # Older wait parameters are typed Nil, not integer zero.
                wait = None if span.args == count + 1 else 0
                traced = flow.trace(span.start, literal_arguments={count: wait},
                                    max_instructions=2048, max_joined_values=128,
                                    non_nil_arguments=range(count))
                calls = traced.get("calls", ())
                if traced["status"] != "proven_static_argument_flow" or len(calls) != 1:
                    continue
                call = calls[0]
                if (call["argument_count"] != count
                        or not _direct_arguments(call["arguments"], count, duration)):
                    continue
                conversion = None
                if delegated:
                    child = by_start.get(call.get("address")) if call["kind"] == "call" else None
                    if child is None:
                        continue
                    conversion = _converted_xy(flow, child)
                    if conversion is None:
                        continue
                elif call["kind"] != "syscall" or call.get("name") != name:
                    continue
                tail = (wait,) if span.args == count + 1 else (wait, -1)
                candidates.append((span, tail, traced, call, conversion))
            if len(candidates) != 1:
                raise NativePortraitAcceptanceError("目标的原生动作参数尚不能唯一确定：" + channel)
            span, tail, traced, call, conversion = candidates[0]
            bindings[channel] = (span.start, count, tail)
            roots.append(span.start)
            proofs[channel] = dict(helper=span.start, helper_args=span.args,
                nonblocking_arguments={count: tail[0]}, native_argument_flow=deepcopy(call),
                non_nil_argument_indexes=list(range(count)),
                native_cache_writes=deepcopy(traced["global_writes"]),
                xy_conversion=conversion, nonblocking_path_proven=True,
                coordinate_space="target_native_helper", angle_units="target_native_raw")
        closure = NativeScriptStateClosure(source, analysis, roots, runtime_context=runtime_context,
                                          max_functions=128, max_instructions=32768)
        self.global_ids = closure.global_ids
        self._bindings = bindings
        conversion = proofs.get("xy", {}).get("xy_conversion")
        self.xy_converted = conversion is not None
        self.xy_factors = MappingProxyType(deepcopy(conversion["factors"] if conversion else dict(x=1, y=1)))
        self._report = dict(schema=SCHEMA, source_sha256=source.source_sha256,
            analysis_sha256=analysis.source_sha256, roles=proofs,
            native_xy_factors=dict(self.xy_factors), native_dependency_closure=closure.describe(),
            runtime_binding=pair, target_native_helper_side_effects_preserved=True,
            cross_game_reference_required=False, primitive_ownership_granted=False,
            rotation_degrees_conversion_proven=False, game_name_switch_used=False, runtime_verified=False)

    def compile(self, channel, primitive_operand, values):
        if channel not in self._bindings or type(primitive_operand) is not bytes or not primitive_operand:
            raise NativePortraitAcceptanceError("动作缺少已经绑定的通道或图元。")
        address, count, tail = self._bindings[channel]
        if not isinstance(values, (tuple, list)) or len(values) != count - 1:
            raise NativePortraitAcceptanceError("原生动作参数数量错误。")
        duration = ROLES[channel][2] - 1
        if type(values[duration]) is not int or not 0 <= values[duration] <= 6000:
            raise NativePortraitAcceptanceError("原生动作时长无效。")
        if type(values[duration + 1]) is not int:
            raise NativePortraitAcceptanceError("动作曲线必须保留其原生整数类型。")
        for index, value in enumerate(values):
            if index == count - 2:
                if type(value) is not bool:
                    raise NativePortraitAcceptanceError("动作原生选项必须保留其布尔类型。")
            elif (type(value) not in (int, float) or not math.isfinite(value)
                  or type(value) is int and not -2**31 <= value < 2**31
                  or type(value) is float and abs(value) > 3.402823466e38):
                raise NativePortraitAcceptanceError("原生动作数值无效。")
            elif index < duration and (channel != "xy" or not self.xy_converted) and type(value) is not int:
                raise NativePortraitAcceptanceError("直通原生动作的坐标／尺寸必须是整数；不隐式取整。")
        return primitive_operand + b"".join(_encode_push(v, "shift_jis") for v in (*values, *tail)) + _call(address)

    def report(self):
        return deepcopy(self._report)
