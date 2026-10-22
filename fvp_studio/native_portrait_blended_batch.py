"""Prepare all native carriers, then ONE intact multi-actor apply.

Old operands are captured before any carrier. Each actor's original guard is
rechecked immediately before that carrier, and registration gates are kept in
local cells rather than held across an unknown partial transaction on stack.
All bytes/resources are prepared without publishing loader state.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _call
from .native_portrait_acceptance import NativePortraitAcceptanceError
from .native_portrait_carrier_retention import NativePortraitCarrierRetention
from .native_portrait_swap_apply import NativePortraitSwapApply
from .portrait_emitter import _encode_push_stack


@dataclass(frozen=True)
class NativePreparedBlendedBatch:
    start_address: int
    entry_address: int
    code: bytes
    _payloads: tuple
    _report: dict
    _owner: object
    _stamp: tuple
    _staged: tuple
    _fields: tuple

    @property
    def payloads(self):
        return dict(self._payloads)

    def report(self):
        return deepcopy(self._report)


def prepare_blended_batch(loader, document, rows, *, storage, extra_motion=None):
    from .native_portrait_loading import NativePortraitLoading
    from .native_portrait_batch_apply import NativePortraitBatchApply
    if not isinstance(loader, NativePortraitLoading) or not isinstance(rows,(list,tuple)) or not (1 if extra_motion is not None else 2) <= len(rows) <= 4:
        raise NativePortraitAcceptanceError('同拍换装需要当前加载器及真实已入场角色；单人批次还须有其他角色运动。')
    loader._check(document)
    actors = [r.get('actor_id') for r in rows if isinstance(r,dict)]
    if len(actors)!=len(rows) or len(set(actors))!=len(actors) or any(a not in loader._active for a in actors):
        raise NativePortraitAcceptanceError('同拍换装的角色必须已加载且身份唯一。')
    stamp, count = loader._stage_stamp(), len(rows)
    prepared, guards, applies = [], [], []
    for row in rows:
        stage = loader.prepare_swap(document,row['actor_id'],row['body_payload'],row['face_payload'],
            runtime_arguments=row['runtime_arguments'],expression=row['expression'])
        retention = NativePortraitCarrierRetention(loader,row['actor_id'])
        proof = retention.prepare(document,stage)
        if (row['old_fields'].get('rotation') or row['new_fields'].get('rotation')) and not proof.report()['old_rotation_scale_unchanged_proven']:
            raise NativePortraitAcceptanceError('同拍换装的载体尚不能保留旧立绘倾斜和缩放。')
        prepared.append(stage)
        guards.append((retention,proof))
        applies.append(NativePortraitSwapApply(loader,row['actor_id']))
    # Resource retention already restricts every carrier's complete resource
    # calls to its own new buffer. These namespaces must also be disjoint.
    occupied = {'primitive':set(),'graph':set(),'parts':set()}
    for apply in applies:
        for name in occupied:
            values = {b[name] for b in apply.geometry.buffers}
            if values & occupied[name]:
                raise NativePortraitAcceptanceError('同拍换装角色的图元、身体或表情缓冲存在冲突。')
            occupied[name].update(values)
    participants = [dict(actor_id=r['actor_id'],old_fields=r['old_fields'],new_fields=r['new_fields'],
        duration_ms=r['duration_ms'],pose=r.get('pose'),
        **(dict(parallel=r['parallel']) if r.get('parallel') is not None else {})) for r in rows]
    batch = NativePortraitBatchApply(loader,participants,storage,extra_motion=extra_motion)
    start, entry = loader.base+len(loader.code), loader.base+len(loader.code)+5
    main = bytearray(bytes((1,0,2*count+1)))
    failures = []
    if extra_motion is not None:
        main.extend(extra_motion.runtime_guard_code()+b'\x07\0\0\0\0')
        failures.append((len(main)-4,0))
    # Check every participant before the first source cache/resource write.
    for number,(apply,(_,guard)) in enumerate(zip(applies,guards)):
        main.extend(guard.precondition_code+b'\x07\0\0\0\0')
        failures.append((len(main)-4,0))
        main.extend(apply.geometry.capture_operand(document)+b'\x16'+bytes((number,)))
    final_stages = []
    for number,(row,(retention,proof)) in enumerate(zip(rows,guards)):
        main.extend(proof.precondition_code+b'\x07\0\0\0\0')
        failures.append((len(main)-4,number))
        stage = loader.prepare_swap(document,row['actor_id'],row['body_payload'],row['face_payload'],
            runtime_arguments=row['runtime_arguments'],expression=row['expression'],_start_address=entry+len(main))
        final = retention.prepare(document,stage)
        if final.precondition_code != proof.precondition_code:
            raise NativePortraitAcceptanceError('同拍换装准备期间的载体保护发生变化。')
        main.extend(stage.before_carrier_code+stage.carrier_code+stage.after_carrier_code)
        if stage.report()['registration_guard_global_id'] is not None:
            main.extend(b'\x16'+bytes((count+number,)))
        final_stages.append(stage)
    for number,stage in enumerate(final_stages):
        main.extend(_encode_push_stack(number)+loader._active_primitive(stage._slot))
    main.extend(b'\x02\0\0\0\0')
    apply_call = len(main)-4
    main.extend(b'\x14\x16'+bytes((2*count,)))
    def restore(completed):
        result = bytearray()
        for number in reversed(range(completed)):
            stage = final_stages[number]
            if stage.report()['registration_guard_global_id'] is not None:
                result.extend(_encode_push_stack(count+number)+stage.after_apply_code)
        return result
    main.extend(restore(count)+_encode_push_stack(2*count)+b'\x05')
    rejection_entries = {}
    for completed in sorted({n for _,n in failures}):
        rejection_entries[completed] = entry+len(main)
        main.extend(restore(completed)+b'\x08\x05')
    for position,completed in failures:
        struct.pack_into('<I',main,position,rejection_entries[completed])
    native = batch.prepare(document,helper_address=entry+len(main))
    struct.pack_into('<I',main,apply_call,native.helper_address)
    callsite = native.helper_address+len(native.helper_code)
    code = b'\x06'+struct.pack('<I',callsite)+bytes(main)+native.helper_code+_call(entry)
    payloads = {}
    for stage in final_stages:
        for name, data in stage.payloads.items():
            if name in payloads and payloads[name]!=data:
                raise NativePortraitAcceptanceError('同拍换装素材标识冲突。')
            payloads[name]=data
    if loader._stage_stamp()!=stamp or start+len(code)>=2**31:
        raise NativePortraitAcceptanceError('同拍换装准备已过期或超出原生地址范围。')
    report = dict(schema='fvp-native-portrait-blended-batch/1',source_sha256=document.source_sha256,
        actors=actors,start_address=start,entry_address=entry,code_size=len(code),
        code_sha256=hashlib.sha256(code).hexdigest(),native_apply=native.report(),
        loads=[s.report() for s in final_stages],retention=[g.report() for _,g in guards],
        all_old_primitives_captured_before_carriers=True,all_preconditions_before_first_write=True,
        each_precondition_rechecked_before_own_carrier=True,
        registration_gates_kept_in_local_cells=True,registration_gates_restored_reverse_order=True,
        partial_carrier_failure_requires_scene_abort=True,complete_apply_call_count=1,
        author_motion_parallelism_connected=extra_motion is not None or any(r.get('parallel') is not None for r in rows),
        other_actor_motion_connected=extra_motion is not None,
        original_apply_frame_split=False,prepared_only=True,resources_published=False,
        code_emitted=False,runtime_verified=False,scene_export_connected=False,
        source_size_rule_changed=False,image_resampled=False,face_alignment_used=False)
    return NativePreparedBlendedBatch(start,entry,code,tuple(payloads.items()),report,loader,stamp,
        tuple(final_stages),tuple(deepcopy(r['new_fields']) for r in rows))
