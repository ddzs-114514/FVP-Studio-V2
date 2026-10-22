"""Prepare explicit geometry on target-owned portrait buffers in memory.

This is the geometry stage of a body transition, not a replacement for native
apply. The caller must resolve which physical buffer is old/new from the
native handoff. This module neither guesses that role nor commits native
pending caches, starts a fade, waits, or frees either buffer.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _call, _push_global
from .native_portrait_acceptance import NativePortraitAcceptanceError
from .portrait_emitter import _encode_push, _encode_push_stack


SCHEMA = "fvp-native-portrait-buffer-geometry/1"
SETTERS = (("PrimSetOP", 3), ("PrimSetXY", 3), ("PrimSetZ", 2),
           ("PrimSetRS", 3), ("PrimSetAlpha", 2))
FIELDS = frozenset({"pivot", "x", "y", "z", "scale", "rotation", "alpha"})
SCALE_AXES = frozenset({"scale_x", "scale_y"})


def validated_geometry(fields):
    """Copy raw units with optional paired scale axes; never infer size."""
    if not isinstance(fields, dict) or set(fields) not in (FIELDS, FIELDS | SCALE_AXES):
        raise NativePortraitAcceptanceError("目标原生几何参数不完整。")
    pivot = fields["pivot"]
    if (not isinstance(pivot, (list, tuple)) or len(pivot) != 2
            or any(type(v) is not int or not -2**31 <= v < 2**31 for v in pivot)
            or any(type(fields[k]) is not int or not -2**31 <= fields[k] < 2**31
                   for k in FIELDS - {"pivot"})
            or any(type(fields[k]) is not int or not 0 < fields[k] < 2**31
                   for k in SCALE_AXES if k in fields)
            or fields["z"] <= 0 or fields["scale"] <= 0
            or not 0 <= fields["alpha"] <= 255):
        raise NativePortraitAcceptanceError("目标原生几何数值无效。")
    return dict(fields, pivot=list(pivot))


def geometry_code(syscall, primitive_operand, fields, *, include_rotation=True):
    """Assemble all setters before returning any bytes to the caller."""
    geometry = validated_geometry(fields)
    if type(primitive_operand) is not bytes or not primitive_operand:
        raise NativePortraitAcceptanceError("立绘几何缺少已绑定的图元。")
    if type(include_rotation) is not bool:
        raise NativePortraitAcceptanceError("立绘旋转设置方式无效。")
    rotation_setter = (
        ("PrimSetRS2", (geometry["rotation"], geometry["scale_x"], geometry["scale_y"]))
        if "scale_x" in geometry else
        ("PrimSetRS", (geometry["rotation"], geometry["scale"])))
    result = bytearray()
    setters = (
            ("PrimSetOP", geometry["pivot"]),
            ("PrimSetXY", (geometry["x"], geometry["y"])),
            ("PrimSetZ", (geometry["z"],)))
    if include_rotation:
        setters += (rotation_setter,)
    setters += (("PrimSetAlpha", (geometry["alpha"],)),)
    for name, values in setters:
        result.extend(syscall(name, [primitive_operand,
            *(_encode_push(v, "shift_jis") for v in values)]))
    return bytes(result), geometry


@dataclass(frozen=True)
class NativeBufferGeometryPreparation:
    code: bytes
    _report: dict

    def report(self):
        return deepcopy(self._report)


@dataclass(frozen=True)
class NativeBufferGeometryHandoff:
    helper_address: int
    helper_code: bytes
    capture_code: bytes
    finish_code: bytes
    _report: dict

    def report(self):
        return deepcopy(self._report)


class NativePortraitBufferGeometry:
    """Use a loader's proven two-buffer allocation, never guessed slot IDs."""
    def __init__(self, source, slot):
        proof = slot.evidence.get("dispatcher_handles", {})
        if (proof.get("schema") != "fvp-native-portrait-dispatcher-handles/1"
                or proof.get("dispatcher_handles_verified") is not True
                or proof.get("source_sha256") != source.source_sha256
                or proof.get("selector") != slot.selector):
            raise NativePortraitAcceptanceError("换装几何缺少当前目标的原生双缓冲证据。")
        buffers = proof.get("buffers", ())
        if (not isinstance(buffers, (list, tuple)) or len(buffers) != 2
                or any(not isinstance(b, dict) or set(b) != {"primitive", "graph", "parts"}
                       or any(type(v) is not int or not 0 <= v < 2**31 for v in b.values())
                       or b["graph"] != b["parts"] for b in buffers)
                or {b["primitive"] for b in buffers} != set(slot.primitive_ids)
                or len({b["graph"] for b in buffers}) != 2):
            raise NativePortraitAcceptanceError("换装几何的身体、表情和图元缓冲不配对。")
        delta = {b["primitive"] - b["graph"] for b in buffers}
        globals_ = proof.get("binding_global_ids", ())
        total = source.header.non_volatile_globals + source.header.volatile_globals
        if (len(delta) != 1 or len(globals_) != 1
                or type(globals_[0]) is not int or not 0 <= globals_[0] < min(total, 65536)
                or globals_[0] not in slot.global_ids):
            raise NativePortraitAcceptanceError("换装几何的当前原生资源槽未唯一绑定。")
        calls = {}
        for index, desc in enumerate(source.header.syscalls):
            if desc.name in calls:
                raise NativePortraitAcceptanceError("目标系统调用名称重复。")
            calls[desc.name] = (index, desc.args)
        if any(calls.get(name, (None, None))[1] != argc for name, argc in SETTERS):
            raise NativePortraitAcceptanceError("目标的立绘几何系统调用尚未完整绑定。")
        self.source_sha256, self._source_bytes = source.source_sha256, source.original_bytes
        self.selector, self.buffers = slot.selector, deepcopy(list(buffers))
        self._global, self._delta, self._calls = globals_[0], next(iter(delta)), calls

    def _check(self, document):
        if (document.source_sha256 != self.source_sha256
                or document.original_bytes != self._source_bytes):
            raise NativePortraitAcceptanceError("换装几何属于另一份目标脚本。")

    def _syscall(self, name, operands):
        bound = self._calls.get(name)
        if bound is None or bound[1] != len(operands):
            raise NativePortraitAcceptanceError("目标原生几何调用未接通：" + name)
        return b"".join(operands) + b"\x03" + struct.pack("<H", bound[0])

    def current(self, document, fields):
        """Keep the established current-buffer geometry operation unchanged."""
        self._check(document)
        primitive = (_push_global(self._global)
            + _encode_push(self._delta, "shift_jis") + b"\x1a")
        return geometry_code(self._syscall, primitive, fields)

    def capture_operand(self, document):
        """Read the actual current primitive; caller stack preserves it."""
        self._check(document)
        return _push_global(self._global) + _encode_push(self._delta, "shift_jis") + b"\x1a"

    def handoff(self, document, *, helper_address, old_fields, new_fields):
        """Capture before/after native loading without inferring buffer roles.

        Place helper_code at helper_address, capture_code before the complete
        carrier call, and finish_code after it. The two-argument helper writes
        geometry only for a distinct, owned pair and returns VM True on that
        path, Nil otherwise. The caller must check the result before starting
        apply; native cache commits/lifetimes still require separate binding.
        No wrapper function is inserted inside the native apply stack frame.
        """
        self._check(document)
        if (type(helper_address) is not int
                or not len(self._source_bytes) <= helper_address < 2**32):
            raise NativePortraitAcceptanceError("换装几何辅助函数须位于目标脚本附加区。")
        old, new = validated_geometry(old_fields), validated_geometry(new_fields)
        previous, current = _encode_push_stack(-3), _encode_push_stack(-2)
        first, second = (b["primitive"] for b in self.buffers)
        compare = bytearray()
        for old_id, new_id in ((first, second), (second, first)):
            compare.extend(previous + _encode_push(old_id, "shift_jis") + b"\x22"
                + current + _encode_push(new_id, "shift_jis") + b"\x22\x20")
        compare.extend(b"\x21")
        old_code, _ = geometry_code(self._syscall, previous, old)
        new_code, _ = geometry_code(self._syscall, current, dict(new, alpha=0))
        success = old_code + new_code + b"\x09\x05"
        rejected = helper_address + 3 + len(compare) + 5 + len(success)
        if rejected + 2 >= 2**32:
            raise NativePortraitAcceptanceError("换装几何辅助函数超出 HCB 地址范围。")
        helper = (b"\x01\x02\0" + bytes(compare) + b"\x07" + struct.pack("<I", rejected)
                  + success + b"\x08\x05")
        operand = self.capture_operand(document)
        report = dict(schema=SCHEMA, source_sha256=self.source_sha256,
            selector=self.selector, buffers=deepcopy(self.buffers),
            old_geometry=old, new_geometry=new, prepared_new_alpha=0,
            helper_address=helper_address, helper_args=2, helper_locals=0,
            helper_sha256=hashlib.sha256(helper).hexdigest(),
            old_primitive_capture="before_native_carrier",
            new_primitive_capture="after_native_carrier",
            capture_binding_global_id=self._global, primitive_graph_delta=self._delta,
            runtime_distinct_owned_pair_guard=True, rejected_guard_writes_geometry=False,
            success_return="VM True", rejected_return="VM Nil",
            buffer_role_guessing_used=False, caller_must_check_result=True,
            raw_syscall_units=True, source_size_rule_changed=False,
            image_resampled=False, face_alignment_used=False,
            native_pending_cache_commit_proven=False, old_buffer_lifetime_proven=False,
            native_apply_replaced=False, motion_started=False, wait_added=False,
            buffer_released=False, scene_export_connected=False, runtime_verified=False)
        return NativeBufferGeometryHandoff(helper_address, helper, operand,
                                           operand + _call(helper_address), report)

    def prepare(self, document, *, old_primitive, new_primitive, old_fields, new_fields):
        """Prepare both explicitly resolved buffers, with the new one hidden.

        The IDs describe roles supplied by the native handoff caller. Owning
        two buffers is not proof of which one is old; do not infer that role
        from sorted IDs or the most recently imported resource name.
        """
        self._check(document)
        if (type(old_primitive) is not int or type(new_primitive) is not int
                or old_primitive == new_primitive
                or {old_primitive, new_primitive} != {b["primitive"] for b in self.buffers}):
            raise NativePortraitAcceptanceError("换装须明确使用该角色自己的两个不同缓冲。")
        old = validated_geometry(old_fields)
        new = validated_geometry(new_fields)
        hidden = dict(new, alpha=0)
        old_code, _ = geometry_code(self._syscall, _encode_push(old_primitive, "shift_jis"), old)
        new_code, _ = geometry_code(self._syscall, _encode_push(new_primitive, "shift_jis"), hidden)
        code = old_code + new_code
        report = dict(schema=SCHEMA, source_sha256=self.source_sha256,
            selector=self.selector, buffers=deepcopy(self.buffers),
            old_primitive=old_primitive, new_primitive=new_primitive,
            old_geometry=old, new_geometry=new, prepared_new_alpha=0,
            code_sha256=hashlib.sha256(code).hexdigest(), code_size=len(code),
            buffer_roles_supplied_by_caller=True, buffer_role_resolution_proven=False,
            raw_syscall_units=True, source_size_rule_changed=False,
            image_resampled=False, face_alignment_used=False,
            native_pending_cache_commit_proven=False, native_apply_replaced=False,
            motion_started=False, wait_added=False, buffer_released=False,
            scene_export_connected=False, runtime_verified=False)
        return NativeBufferGeometryPreparation(code, report)
