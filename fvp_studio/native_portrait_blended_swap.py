"""Private executable carrier + intact-apply swap transaction preparation.

Precondition failure returns Nil before any carrier cache/resource mutation.
The old primitive lives in the caller's local frame across the complete native
carrier. Registration closure/restoration and apply wait/cleanup remain intact.
This prepares bytes/payloads, never publishes them or opens scene capabilities.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _call
from .native_portrait_acceptance import NativePortraitAcceptanceError
from .native_portrait_carrier_retention import NativePortraitCarrierRetention
from .native_portrait_swap_apply import NativePortraitSwapApply
from .portrait_emitter import _encode_push_stack


SCHEMA = "fvp-native-portrait-blended-swap-preparation/1"


@dataclass(frozen=True)
class NativePreparedBlendedSwap:
    start_address: int
    entry_address: int
    code: bytes
    _payloads: tuple
    _report: dict
    _owner: object
    _stamp: tuple
    _staged: object

    @property
    def payloads(self):
        return dict(self._payloads)

    def report(self):
        return deepcopy(self._report)


def prepare_blended_swap(loader, document, actor_id, body_payload, face_payload, *,
                         runtime_arguments, old_fields, new_fields, expression=0, duration_ms=200, pose=None,
                         parallel=None):
    from .native_portrait_loading import NativePortraitLoading
    if not isinstance(loader, NativePortraitLoading):
        raise NativePortraitAcceptanceError("换装准备缺少当前目标的原生加载器。")
    loader._check(document)
    stamp = loader._stage_stamp()
    initial = loader.prepare_swap(document, actor_id, body_payload, face_payload,
        runtime_arguments=runtime_arguments, expression=expression)
    retention = NativePortraitCarrierRetention(loader, actor_id)
    guard = retention.prepare(document, initial)
    if (old_fields.get("rotation") or new_fields.get("rotation")) and guard.report().get(
            "old_rotation_scale_unchanged_proven") is not True:
        raise NativePortraitAcceptanceError("此目标换装加载尚不能保留旧立绘的倾斜与缩放。")
    apply = NativePortraitSwapApply(loader, actor_id)
    start = loader.base + len(loader.code)
    entry = start + 5
    if parallel is not None:
        parallel.check(loader, document)
    prefix = bytearray(b"\x01\0\x02" + (parallel.reset_code if parallel is not None else b'')
        + guard.precondition_code + b"\x07\0\0\0\0")
    rejection_patch = len(prefix)-4
    prefix.extend(apply.geometry.capture_operand(document) + b"\x16\0")
    # Bind the clone's absolute addresses to its actual location inside the
    # wrapper. A relocated stage cannot be published by the default loader.
    staged = loader.prepare_swap(document, actor_id, body_payload, face_payload,
        runtime_arguments=runtime_arguments, expression=expression,
        _start_address=entry+len(prefix))
    final_guard = retention.prepare(document, staged)
    if guard.precondition_code != final_guard.precondition_code:
        raise NativePortraitAcceptanceError("换装加载前后的资源保护不一致。")
    carrier = staged.before_carrier_code + staged.carrier_code + staged.after_carrier_code
    operands = _encode_push_stack(0) + loader._active_primitive(staged._slot)
    # Store the apply result locally before restoring a registration gate; do
    # not rely on a future restoration fragment leaving the return register.
    tail = bytearray(operands + b"\x02\0\0\0\0\x14\x16\x01"
        + staged.after_apply_code + _encode_push_stack(1) + b"\x05")
    reject = entry + len(prefix) + len(carrier) + len(tail)
    struct.pack_into("<I", prefix, rejection_patch, reject)
    helper_address = reject + 2
    native = apply.prepare(document, helper_address=helper_address,
        old_fields=old_fields, new_fields=new_fields, duration_ms=duration_ms, pose=pose, parallel=parallel)
    struct.pack_into("<I", tail, len(operands)+1, helper_address)
    main = bytes(prefix) + carrier + bytes(tail) + b"\x08\x05"
    callsite = helper_address + len(native.helper_code)
    code = b"\x06" + struct.pack("<I", callsite) + main + native.helper_code + _call(entry)
    if start + len(code) >= 2**31:
        raise NativePortraitAcceptanceError("换装准备超过当前目标的代码地址范围。")
    if loader._stage_stamp() != stamp:
        raise NativePortraitAcceptanceError("换装准备期间加载器状态已变化。")
    report = dict(schema=SCHEMA, source_sha256=document.source_sha256,
        actor_id=actor_id, selector=staged._slot.selector,
        start_address=start, entry_address=entry, helper_address=helper_address,
        code_size=len(code), code_sha256=hashlib.sha256(code).hexdigest(),
        load=staged.report(), retention=final_guard.report(), native_apply=native.report(),
        precondition_checked_before_first_carrier_write=True,
        old_primitive_kept_in_local_across_carrier=True,
        complete_carrier_and_apply_compiled=True, original_apply_frame_split=False,
        registration_gate_restoration_needed=bool(staged.report()["registration_guard_global_id"] is not None),
        registration_gate_restored_after_apply=staged.report()["registration_guard_restored_after_apply"],
        caller_must_check_result=True, failed_precondition_returns_nil_without_writes=True,
        prepared_only=True, resources_published=False, code_emitted=False,
        native_cache_fields_mapped_to_authored_geometry=False,
        shared_apply_serialization_proven=False, concurrent_engine_threads_owned=False,
        author_motion_parallelism_connected=parallel is not None,
        old_authored_motion_retired_after_native_apply=parallel is not None,
        signed_rotation_connected=pose is not None,
        old_buffer_lifetime_proven=False, scene_export_connected=False,
        runtime_verified=False, source_size_rule_changed=False, image_resampled=False,
        face_alignment_used=False)
    return NativePreparedBlendedSwap(start, entry, code, staged._payloads, report, loader, stamp, staged)
