"""Stop target-owned CG primitive motions before reusing or releasing slots.

Only source-bound CG planes and reveal companions qualify. A primitive stop
does not stop a VM thread, acquire a parent group, restore an inherited image,
or prove native rendering. No wildcard/all-primitive stop is emitted.
"""
from copy import deepcopy
import struct

from .native_cg_backend import NativeCGBackend
from .native_cg_motion_stop_binding import NativeCGMotionStopBinding
from .native_script_state import validate_native_script_pair
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-cg-motion-quiescence/1"
CHANNELS = {
    "alpha": ("MotionAlpha", (5, 6), "MotionAlphaStop"),
    "xy": ("MotionMove", (8,), "MotionMoveStop"),
    "z": ("MotionMoveZ", (6,), "MotionMoveZStop"),
    "rotation": ("MotionMoveR", (6,), "MotionMoveRStop"),
    "scale": ("MotionMoveS2", (8,), "MotionMoveS2Stop"),
    "animation": ("MotionAnim", (4,), "MotionAnimStop"),
}


class NativeCGMotionQuiescence:
    def __init__(self, context, backend, *, presentation=None, executable=None):
        if not isinstance(backend, NativeCGBackend) or backend.context is not context:
            raise ValueError("CG 动画停止必须使用当前目标自己的图层绑定。")
        self.context, self.backend = context, backend
        self.presentation = presentation
        validate_native_script_pair(backend.source, backend.analysis, runtime_context=context)
        primitives = set(backend.planes)
        if presentation is not None:
            from .native_cg_presentation import NativeCGPresentation
            if (not isinstance(presentation, NativeCGPresentation)
                    or presentation.context is not context or presentation.backend is not backend):
                raise ValueError("CG 附属图层不属于当前目标的显示流程。")
            for rows in presentation.companions.values():
                primitives.update(rows)
        if not primitives or any(type(p) is not int or not 0 < p < 2**31 for p in primitives):
            raise ValueError("CG 动画停止只能使用已绑定的正整数图层，不能全部停止。")
        self.primitives = tuple(sorted(primitives))
        self.table = {s.name:(i,s.args) for i,s in enumerate(backend.source.header.syscalls)}
        if len(self.table) != len(backend.source.header.syscalls):
            raise ValueError("CG 动画停止的原生调用名重复。")
        reviewed = {name for start, _, stop in CHANNELS.values() for name in (start, stop, start+"Test")}
        reviewed.add("MotionPause")
        unknown = sorted(name for name in self.table if name.startswith("Motion") and name not in reviewed)
        if unknown:
            raise ValueError("CG 含有尚未配对停止入口的原生动画："+"、".join(unknown))
        self.channels = {}
        for channel, (start, layouts, stop) in CHANNELS.items():
            if start not in self.table:
                continue  # A missing generation's channel is not invented.
            if self.table[start][1] not in layouts or self.table.get(stop, (None,None))[1] != 1:
                raise ValueError("CG 原生动画与停止调用未配对："+start)
            self.channels[channel] = dict(start=start, start_arity=self.table[start][1],
                stop=stop, stop_arity=1, stop_syscall_id=self.table[stop][0])
        self.native_binding = (NativeCGMotionStopBinding(executable, self.channels)
            if executable is not None and self.channels else None)
        if self.native_binding is not None:
            self.native_binding.validate(self.channels, self.primitives)

    def _validate(self):
        validate_native_script_pair(self.backend.source, self.backend.analysis, runtime_context=self.context)
        if self.presentation is not None:
            for archive in self.backend.routes:
                self.presentation.visibility.policy(archive)
        for address in self.backend.closure.dependencies:
            span = self.backend.spans[address]
            if (self.backend.source.original_bytes[span.start:span.end]
                    != self.backend.analysis.original_bytes[span.start:span.end]
                    or any(i.dirty or i.warning or not i.known for i in span.instructions)):
                raise ValueError("CG 动画停止的原生图层证据已经变化。")
        actual = {s.name:(i,s.args) for i,s in enumerate(self.backend.source.header.syscalls)}
        if actual != self.table:
            raise ValueError("CG 动画停止的原生调用表已经变化。")
        if self.native_binding is not None:
            self.native_binding.validate(self.channels, self.primitives)

    def code(self):
        self._validate()
        return b"".join(_encode_push(p, self.backend.source.encoding)+b"\x03"
            +struct.pack("<H", row["stop_syscall_id"])
            for p in self.primitives for row in self.channels.values())

    def report(self):
        self._validate()
        return dict(schema=SCHEMA, source_sha256=self.backend.source.source_sha256,
            primitives=list(self.primitives), channels=deepcopy(self.channels),
            stop_call_count=len(self.primitives)*len(self.channels),
            all_primitive_wildcard_used=False, vm_threads_stopped=False,
            parent_groups_acquired=False, inherited_images_restored=False,
            registered_source_layouts_checked=True,
            native_stop_handler_bytes_verified=self.native_binding is not None,
            native_stop_binding=self.native_binding.report() if self.native_binding is not None else None,
            all_matching_records_removed=False, motion_start_uniqueness_proven=False,
            runtime_verified=False)
