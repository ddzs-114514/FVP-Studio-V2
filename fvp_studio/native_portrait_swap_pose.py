"""Preserve a target-owned portrait angle across its complete body fade.

Some native RS setters wrap signed R at a half-turn. Keep that old buffer's
RS fields untouched; initialize the alpha-zero new buffer through its own
MotionMoveR helper and wait before starting the original native apply.
"""
from __future__ import annotations

from copy import deepcopy
import struct

from .native_portrait_acceptance import NativePortraitAcceptanceError
from .native_portrait_motion import NativePortraitMotion
from .native_rotation_degrees import NativeRotationDegrees
from .native_script_state import NativeScriptStateClosure
from .portrait_emitter import _encode_push


class NativePortraitSwapPose:
    def __init__(self, loader, target, rotation, motion):
        if not isinstance(rotation, NativeRotationDegrees) or not isinstance(motion, NativePortraitMotion):
            raise NativePortraitAcceptanceError("倾斜换装缺少本目标已绑定的角度与原生动作。")
        rotation.assert_target(target)
        context = target.context
        if context.document is not loader._source or context.analysis_document is not loader._analysis:
            raise NativePortraitAcceptanceError("换装姿态不属于当前原生加载器。")
        rp, mp = rotation.report(), motion.report()
        r = mp.get("roles", {}).get("r", {})
        if (rp.get("hcb_sha256") != loader._source.source_sha256
                or mp.get("source_sha256") != loader._source.source_sha256
                or mp.get("analysis_sha256") != loader._analysis.source_sha256
                or r.get("helper") != rp.get("native_helper")):
            raise NativePortraitAcceptanceError("换装姿态没有共享目标自己的旋转字段与动作入口。")
        self.loader, self.target, self.rotation, self.motion = loader, target, rotation, motion
        self.closure = NativeScriptStateClosure(loader._source, loader._analysis,
            [r["helper"]], runtime_context=getattr(loader.catalog, "_runtime_context", None))
        self.proof = dict(rotation=rp, native_motion=r, runtime_verified=False)

    def check(self, loader, document):
        if loader is not self.loader:
            raise NativePortraitAcceptanceError("换装姿态属于另一个加载器。")
        loader._check(document)
        self.rotation.assert_target(self.target)
        self.closure.compile_snapshot(document)

    def avoids_setter(self, fields):
        return self.rotation.setter_changes_angle(fields["rotation"])

    def initialize_hidden(self, primitive_operand, fields, start_address):
        """Caller has already applied geometry with R=0 and alpha=0."""
        if not self.avoids_setter(fields):
            return b""
        code = bytearray(self.motion.compile("r", primitive_operand,
            (0, fields["rotation"], 1, 1, True)))
        loop = start_address + len(code)
        test = self.loader._syscall("MotionMoveRTest", [primitive_operand]) + b"\x14"
        wait = self.loader._syscall("ThreadWait", [_encode_push(1, "shift_jis")])
        finish = loop + len(test) + 5 + len(wait) + 5
        code.extend(test + b"\x07" + struct.pack("<I", finish)
            + wait + b"\x06" + struct.pack("<I", loop))
        return bytes(code)

    def report(self):
        return deepcopy(self.proof)
