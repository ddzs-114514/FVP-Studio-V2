"""CG-owned XY/Z motion using this target's native nonblocking wrappers.

Zoom follows the already used native Z channel. No shared V3D or RS/S2
animation is substituted. Only the selected CG resource planes participate.
"""
from copy import deepcopy
import math
import struct

from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_portrait_motion import NativePortraitMotion
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-cg-motion/1"
TESTS = {"xy":"MotionMoveTest", "z":"MotionMoveZTest"}


def _converted_coordinate(value, factor):
    # The native delegate truncates after multiplying. Use the middle of
    # that integer's interval: simply dividing can become 19.999999 after
    # the HCB float32 operand is encoded, causing a jump when CG is reloaded.
    logical = (value+math.copysign(.5, value))/factor if value else 0.0
    encoded = struct.unpack("<f", struct.pack("<f", logical))[0]
    if int(encoded*factor) != value:
        raise ValueError("CG 坐标超出目标原生浮点换算范围。")
    return encoded


class NativeCGMotion:
    def __init__(self, context, stage, output):
        if stage.context is not context:
            raise ValueError("CG 运动与图像准备必须属于同一目标。")
        self.context, self.stage, self.output = context, stage, output
        self.source = context.document
        self.binding = NativePortraitMotion(self.source, context.analysis_document,
            {"xy", "z"}, runtime_context=context)
        for channel in TESTS:
            self.binding.prove_nil_flag(channel)
        self.table = {s.name:(i,s.args) for i,s in enumerate(self.source.header.syscalls)}
        if any(self.table.get(name, (None,None))[1] != 1 for name in (*TESTS.values(), "ThreadWait")):
            raise ValueError("目标的 CG 运动等待入口尚未确定。")
        self.pending, self.operations = set(), []
        self.snapshot = None

    def snapshot_state(self, storage=None):
        ids = sorted(set(self.binding.global_ids))
        snapshot = dict(snapshot=b"".join(_push_global(g) for g in ids),
            restore=b"".join(_pop_global(g) for g in reversed(ids)), report=dict(global_ids=ids))
        self.snapshot = storage.reserve(snapshot, "cg_motion") if storage is not None else snapshot
        self.output.extend(self.snapshot["snapshot"])

    def frames(self, archive, metadata, view):
        route = self.stage.backend.routes[archive][0]
        plans = [p for p in self.stage.plans if p["prefix"] == route["prefix"]]
        return {p["primitive"]:self.stage.geometry.frame(p["primitive"], metadata[p["suffix"]],
            x=view["x"], y=view["y"], percentage=view["s"], depth_zoom=True)[0] for p in plans}

    def emit(self, archive, metadata, start, end, duration, curve):
        # A saved screen offset is not a fixed native XY coordinate: with
        # constant RS, projection is XY * RS / Z. Resolve BOTH endpoints at
        # their own depth, then launch XY and Z together through the bound
        # nonblocking wrappers. In particular, stationary off-centre zoom
        # still needs XY motion so the CG does not drift toward/away from 0.
        before, after = self.frames(archive, metadata, start), self.frames(archive, metadata, end)
        chunks, operations, geometry = [], [], []
        for primitive, old in before.items():
            new = after[primitive]
            geometry.append(dict(primitive=primitive, start=deepcopy(old), end=deepcopy(new)))
            operand = _encode_push(primitive, self.source.encoding)
            if (old["x"], old["y"]) != (new["x"], new["y"]):
                positions = (old["x"], old["y"], new["x"], new["y"])
                if self.binding.xy_converted:
                    fx, fy = self.binding.xy_factors["x"], self.binding.xy_factors["y"]
                    positions = tuple(_converted_coordinate(v, f) for v, f in
                        zip(positions, (fx, fy, fx, fy)))
                values = (*positions, duration, curve, None)
                chunks.append(self.binding.compile("xy", operand, values, allow_nil_flag=True))
                operations.append(dict(primitive=primitive, channel="xy", native_arguments=list(values)))
            if old["z"] != new["z"]:
                values = (old["z"], new["z"], duration, curve, None)
                chunks.append(self.binding.compile("z", operand, values, allow_nil_flag=True))
                operations.append(dict(primitive=primitive, channel="z", native_arguments=list(values)))
        self.join()
        self.output.extend(b"".join(chunks))
        self.pending.update((row["primitive"], row["channel"]) for row in operations)
        self.operations.append(dict(start=deepcopy(start), end=deepcopy(end),
            duration_ms=duration, curve=curve, planes=operations, endpoint_geometry=geometry))

    def syscall(self, name, values):
        index, count = self.table[name]
        if len(values) != count:
            raise ValueError("CG 运动等待参数数量不一致。")
        return b"".join(_encode_push(v, self.source.encoding) for v in values)+b"\x03"+struct.pack("<H", index)

    def join(self):
        for primitive, channel in sorted(self.pending):
            start = len(self.source.original_bytes)+len(self.output)
            test = self.syscall(TESTS[channel], [primitive])+b"\x14"
            wait = self.syscall("ThreadWait", [1])
            finish = start+len(test)+5+len(wait)+5
            self.output.extend(test+b"\x07"+struct.pack("<I", finish)
                +wait+b"\x06"+struct.pack("<I", start))
        self.pending.clear()

    def finish(self):
        self.join()
        if self.snapshot is not None:
            self.output.extend(self.snapshot["restore"])

    def report(self):
        return dict(schema=SCHEMA, binding=self.binding.report(), operations=deepcopy(self.operations),
            zoom_channel="z", move_channel="xy", native_flag=None,
            off_center_zoom_supported=True, xy_endpoints_at_own_depth=True,
            xy_and_z_start_without_intermediate_join=True,
            shared_camera_changed=False, image_resampled=False, source_size_rule_changed=False,
            snapshot=self.snapshot["report"] if self.snapshot is not None else None,
            joins_before_reload_and_exit=True, runtime_verified=False)
