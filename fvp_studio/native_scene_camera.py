"""Target-owned V3D camera calls; no borrowed addresses, viewport or XY units.

Bind the converted-coordinate 11-argument or direct-coordinate 12-argument
scene wrapper by complete argument flow, including the native fast path.
Native skip policies and cache writes stay inside the original wrapper. A
missing legacy recipe is a refusal, not a raw V3DMotion fallback. Import-size
conversion is deliberately left unchanged.
"""
from __future__ import annotations

from copy import deepcopy
import math
import struct

from .hoshimemo_scene_hook import _call
from .native_background_backend import _substitute
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import _function_spans
from .native_portrait_geometry import _round
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .portrait_emitter import _encode_push
from .camera_zoom_limits import ZOOM_MIN, ZOOM_SCHEMA_MAX, zoom_range, check_camera_path


SCHEMA = "fvp-native-scene-camera/1"


def argument(index):
    return dict(kind="argument", index=index)


def literal(value):
    return dict(kind="literal", type=type(value).__name__, value=value)


def dependencies(value):
    if value.get("kind") == "argument":
        return {value["index"]}
    if value.get("kind") in {"global_read", "call_return"}:
        return {-1}
    return set().union(*(dependencies(v) for v in value.get("operands", ())))


def camera_cache(trace):
    slots = [w["slot"] for i in range(3) for w in trace.get("global_writes", ())
             if w["value"] == argument(i)]
    return tuple(slots) if len(slots) == 3 and len(set(slots)) == 3 else None


def coordinate_delegate(flow, span, name="V3DMotion", count=6):
    if span.args != count or span.locals or span.calls or len(span.instructions) > 64:
        return None
    traced = flow.trace(span.start, non_nil_arguments=range(count))
    calls = traced.get("calls", ())
    if traced["status"] != "proven_static_argument_flow" or traced["global_writes"]:
        return None
    if span.syscalls == (name,):
        return ((1., 1.), calls[-1]) if len(calls) == 1 and calls[0]["arguments"] == [argument(i) for i in range(count)] else None
    if span.syscalls != ("FloatToInt", "FloatToInt", name) or len(calls) != 3:
        return None
    expected, factors = [], []
    for index, conversion in enumerate(calls[:2]):
        values = conversion.get("arguments", ())
        if len(values) != 1 or values[0].get("kind") != "mul":
            return None
        operands = values[0].get("operands", ())
        if (len(operands) != 2 or operands[0] != argument(index)
                or operands[1].get("kind") != "literal" or operands[1].get("type") != "float"
                or not math.isfinite(operands[1]["value"]) or not 0 < operands[1]["value"] <= 32):
            return None
        factors.append(operands[1]["value"])
        expected.append(dict(kind="call_return", call_kind="syscall", target="FloatToInt",
            offset=conversion["offset"], arguments=values, semantics_reviewed=False))
    expected += [argument(i) for i in range(2, count)]
    if calls[-1].get("name") != name or calls[-1]["arguments"] != expected:
        return None
    return tuple(factors), calls[-1]


def background_plane(flow, backend):
    """Specialise the actual background defaults all the way to PrimSetZ."""
    recipe = backend.compile_load(backend._source, resource_name="BG_FVP_CAMERA_REFERENCE",
        archive_name=next(iter(backend.archive_selectors)), duration_ms=0)
    primary = recipe.report["calls"][0]
    roots, depths = set(), set()
    budget = [128]
    def visit(address, values, ancestors=()):
        budget[0] -= 1
        if budget[0] < 0 or address in ancestors or len(ancestors) > 8:
            raise ValueError("原生背景景深调用链超出范围。")
        roots.add(address)
        trace = flow.trace(address, literal_arguments={i: v["value"] for i, v in enumerate(values)
                          if v.get("kind") == "literal"}, max_joined_values=128)
        if trace["status"] != "proven_static_argument_flow":
            raise ValueError("原生背景参考平面的参数尚未确定。")
        for call in trace["calls"]:
            args = [_substitute(v, tuple(values)) for v in call["arguments"]]
            if call["kind"] == "call":
                visit(call["address"], args, (*ancestors, address))
            elif call.get("name") == "PrimSetZ":
                if len(args) != 2 or args[1].get("kind") != "literal" or type(args[1].get("value")) is not int:
                    raise ValueError("原生背景景深不是明确的默认值。")
                depths.add(args[1]["value"])
    visit(primary["address"], [literal(v) for v in primary["arguments"]])
    if len(depths) != 1 or next(iter(depths)) <= 0:
        raise ValueError("原生背景参考平面没有唯一的景深。")
    return next(iter(depths)), roots


class NativeSceneCamera:
    def __init__(self, target, output):
        context = target.context
        self.source, self.analysis, self.output = context.document, context.analysis_document, output
        pair = validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        spans = _function_spans(self.analysis)
        flow = NativeFunctionFlow(self.analysis)
        delegates = {s.start: (s, recipe) for s in spans
                     if (recipe := coordinate_delegate(flow, s)) is not None}
        entries = {s.start: s for s in spans}
        candidates = []
        for span in spans:
            if span.args not in (11, 12) or span.locals or len(span.instructions) > 256 or "V3DMotionTest" not in span.syscalls:
                continue
            proofs, child, fast_path, factors, caches, signature = {}, None, None, None, None, None
            for curve in (2, 3):
                parameters = {4: curve, 6: 0, 7: -1, 8: 0, 9: 1, 10: None}
                if span.args == 12:
                    parameters[11] = -1
                trace = flow.trace(span.start, literal_arguments=parameters,
                    non_nil_arguments=(0, 1, 2, 3, 5), max_joined_values=128, max_instructions=2048)
                calls = trace.get("calls", ())
                if trace["status"] != "proven_static_argument_flow":
                    break
                if span.args == 11:
                    moves = [c for c in calls if c["kind"] == "call"]
                    if (len(moves) != 1 or moves[0]["address"] not in delegates
                            or any(c["kind"] == "syscall" and (c.get("name") != "ControlPulse" or c["arguments"]) for c in calls)):
                        break
                    child = moves[0]["address"]
                    factors = delegates[child][1][0]
                else:
                    fast_path = None
                    moves = [c for c in calls if c["kind"] == "syscall" and c.get("name") == "V3DMotion"]
                    instant = [c for c in calls if c["kind"] == "call"]
                    if (len(moves) != 1 or len(instant) > 1 or any(c["kind"] == "syscall"
                            and c.get("name") != "V3DMotion" and (c.get("name") != "ControlPulse" or c["arguments"]) for c in calls)):
                        break
                    if instant:
                        call, quick = instant[0], entries[instant[0]["address"]]
                        if (quick.args != 4 or quick.locals or len(quick.instructions) > 128
                                or call["arguments"] != [argument(i) for i in range(3)] + [literal(0)]):
                            break
                        fast = flow.trace(quick.start, literal_arguments={3: 0}, non_nil_arguments=(0, 1, 2))
                        if (fast["status"] != "proven_static_argument_flow" or len(fast["calls"]) != 1
                                or fast["calls"][0].get("name") != "V3DMotion"
                                or fast["calls"][0]["arguments"] != [argument(i) for i in range(3)]
                                    + [literal(1), literal(1), literal(None)]
                                or camera_cache(fast) != camera_cache(trace)):
                            break
                        fast_path = quick.start
                    factors = (1., 1.)
                values = moves[0]["arguments"]
                if (len(values) != 6 or values[:3] != [argument(i) for i in range(3)]
                        or dependencies(values[3]) != {3}
                        or values[4:] != [literal(curve), argument(5)]):
                    break
                cache = camera_cache(trace)
                if cache is None or (caches is not None and caches != cache):
                    break
                binding = (child, fast_path, factors, cache)
                if signature is not None and signature != binding:
                    break
                signature = binding
                caches = cache
                proofs[curve] = trace
            if len(proofs) == 2:
                candidates.append((span, child, fast_path, factors, caches, proofs))
        if len(candidates) != 1:
            raise ValueError("此版本的原生镜头运动调用链尚未接通；不会借用其他游戏的镜头参数。")
        span, child, fast_path, factors, caches, proofs = candidates[0]
        self.address, self.factors, self.cache_slots, self.native_arity = span.start, factors, caches, span.args
        setters = {s.start for s in spans if (recipe := coordinate_delegate(flow, s, "V3DSet", 3))
                   is not None and recipe[0] == self.factors}
        resets = []
        for reset in spans:
            if (reset.args != 4 or reset.locals or len(reset.instructions) > 128
                    or reset.syscalls not in (("V3DMotionStop",), ("V3DMotionStop", "V3DSet"))):
                continue
            defaults = flow.trace(reset.start, literal_arguments={0: None, 1: None, 2: None, 3: 0})
            forwards = flow.trace(reset.start, literal_arguments={3: 0}, non_nil_arguments=(0, 1, 2))
            def setter_call(call):
                return (call["kind"] == "call" and call["address"] in setters
                        or self.factors == (1., 1.) and call.get("name") == "V3DSet")
            dcalls = [c for c in defaults.get("calls", ()) if setter_call(c)]
            fcalls = [c for c in forwards.get("calls", ()) if setter_call(c)]
            if (defaults["status"] != "proven_static_argument_flow" or forwards["status"] != "proven_static_argument_flow"
                    or len(dcalls) != 1 or len(fcalls) != 1 or dcalls[0].get("address") != fcalls[0].get("address")
                    or dcalls[0]["kind"] != fcalls[0]["kind"]
                    or any(not setter_call(c) and not (c.get("name") == "V3DMotionStop" and not c["arguments"])
                           for c in [*defaults.get("calls", ()), *forwards.get("calls", ())])
                    or fcalls[0]["arguments"] != [argument(i) for i in range(3)]
                    or len(dcalls[0]["arguments"]) != 3 or any(v.get("kind") != "literal"
                        or type(v.get("value")) is not int for v in dcalls[0]["arguments"])):
                continue
            baseline = [v["value"] for v in dcalls[0]["arguments"]]
            resets.append((reset, dcalls[0].get("address"), baseline, defaults, forwards))
        if len(resets) != 1:
            raise ValueError("目标原生镜头复位和默认取景尚不能唯一确定。")
        reset, setter, baseline, default_proof, reset_proof = resets[0]
        self.reset_address = reset.start
        self.baseline = (int(baseline[0]*self.factors[0]), int(baseline[1]*self.factors[1]), baseline[2])
        if self.baseline[2] >= 0:
            raise ValueError("此镜头包装布局尚未确认原生基准景深。")
        self.current = self.baseline
        backend = context.abi.native_background_backend
        self.plane, bg_roots = background_plane(flow, backend)
        self.closure = NativeScriptStateClosure(self.source, self.analysis,
            sorted({span.start, reset.start, *({setter} if setter is not None else set()), *bg_roots}), runtime_context=context,
            max_functions=256, max_instructions=131072)
        self.snapshot = self.closure.compile_snapshot(self.source)
        self.global_ids = self.closure.global_ids
        from .native_import_size_discovery import extract_exe_viewport
        self.viewport = tuple(extract_exe_viewport((target.root / target.executable).read_bytes(),
                                                  self.analysis.header.game_mode)["viewport"])
        self.pending = False
        self._motion_start = self.current
        self.zoom_range = zoom_range(self.plane, self.baseline, self.viewport)
        if len({s.name for s in self.source.header.syscalls}) != len(self.source.header.syscalls):
            raise ValueError("原生镜头系统调用名重复，不能确定当前目标。")
        self._syscalls = {s.name: (i, s.args) for i, s in enumerate(self.source.header.syscalls)}
        for name, count in (("V3DMotionTest", 0), ("ThreadWait", 1), ("V3DMotionStop", 0), ("V3DSet", 3)):
            if self._syscalls.get(name, (None, None))[1] != count:
                raise ValueError("原生镜头等待调用不匹配：" + name)
        self.operations = []
        self._report = dict(schema=SCHEMA, native_helper=span.start, native_argument_count=span.args,
            coordinate_delegate=child, native_fast_path=fast_path, camera_cache_slots=list(caches),
            native_reset_helper=reset.start, default_camera_flow=default_proof, reset_camera_flow=reset_proof,
            xy_factors=list(self.factors), baseline=list(self.baseline), reference_plane_z=self.plane,
            viewport=list(self.viewport), original_cache_writes_preserved=True,
            zoom_range=self.zoom_range,
            xy_quantization="original_float32_and_FloatToInt" if child is not None else "native_integer_coordinates",
            native_duration_and_skip_policy_preserved=True, nonblocking_flow=proofs,
            source_dependencies=self.closure.describe(), runtime_binding=pair,
            game_name_switch_used=False, source_size_rule_changed=False, runtime_verified=False)

    def syscall(self, name, values=()):
        index, count = self._syscalls[name]
        if count != len(values):
            raise ValueError("原生镜头系统调用参数不匹配。")
        return b"".join(_encode_push(v, "shift_jis") for v in values) + b"\x03" + struct.pack("<H", index)

    def restore_current(self):
        args = (*self.logical_coordinates(self.current), 0)
        self.output.extend(b"".join(_encode_push(v, "shift_jis") for v in args) + _call(self.reset_address))
        # A background helper may reset its cached XYZ independently of V3D.
        # Keep the exact cache fields/units proven by the target motion wrapper.
        for slot, value in zip(self.cache_slots, args[:3]):
            self.output.extend(_encode_push(value, "shift_jis") + b"\x15" + struct.pack("<H", slot))

    def logical_coordinates(self, camera):
        return tuple(camera[i] if self.factors[i] == 1. else camera[i]/self.factors[i]
                     for i in (0, 1)) + (camera[2],)

    def join(self):
        if not self.pending:
            return
        start = len(self.source.original_bytes) + len(self.output)
        test = self.syscall("V3DMotionTest") + b"\x14"
        wait = self.syscall("ThreadWait", (1,))
        finish = start + len(test) + 5 + len(wait) + 5
        self.output.extend(test + b"\x07" + struct.pack("<I", finish)
                           + wait + b"\x06" + struct.pack("<I", start))
        self.pending = False

    def emit(self, event, states=()):
        cx, cy, zoom, duration, curve = (event[k] for k in ("center_x", "center_y", "zoom", "duration_ms", "curve"))
        if (any(type(v) is not int for v in (cx, cy, zoom, duration, curve))
                or not 0 <= cx <= 1280 or not 0 <= cy <= 720 or not ZOOM_MIN <= zoom <= ZOOM_SCHEMA_MAX
                or not (duration == 0 or 200 <= duration <= 6000) or curve not in (2, 3)):
            raise ValueError("镜头取景或时间超出支持范围。")
        distance = self.plane - self.baseline[2]
        camera = (_round(self.baseline[0] + (cx-640) * self.viewport[0]/1280 * distance/1000),
                  _round(self.baseline[1] + (cy-360) * self.viewport[1]/720 * distance/1000),
                  _round(self.plane-distance*100/zoom))
        depths = [min(s["z"], s.get("_depth_start", s["z"])) for s in states]
        bounds = zoom_range(self.plane, self.baseline, self.viewport, depths=depths)
        if zoom > bounds["max_percent"]:
            raise ValueError(f"镜头取景会越过在场图层；此处最高可用 {bounds['max_percent']}%，请调整倍率或景深。")
        check_camera_path(self.current, camera, [self.plane, *depths])
        logical = self.logical_coordinates(camera)
        self.join()
        self._motion_start = self.current
        if duration == 0:
            self.current = camera
            self.restore_current()
            self.operations.append(dict(authored_center=[cx, cy], zoom=zoom,
                target_camera=list(camera), target_camera_is_nominal=bool(self.factors != (1., 1.)),
                arguments=[*logical, 0], original_helper=self.reset_address,
                instantaneous_set=True, motion_zero_duration_used=False))
            return
        args = (*logical, duration, curve, True, 0, -1, 0, 1, None)
        if self.native_arity == 12:
            args += (-1,)
        self.output.extend(b"".join(_encode_push(v, "shift_jis") for v in args) + _call(self.address))
        self.current, self.pending = camera, True
        self.operations.append(dict(authored_center=[cx, cy], zoom=zoom, target_camera=list(camera),
            target_camera_is_nominal=bool(self.factors != (1., 1.)),
            arguments=list(args), original_helper=self.address))

    def finish(self):
        self.join()
        self.current = self.baseline
        self.restore_current()

    def report(self):
        return dict(deepcopy(self._report), operations=deepcopy(self.operations))
