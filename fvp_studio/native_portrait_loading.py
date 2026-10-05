"""Compile target-native portrait loads and expression changes in memory.

The complete original carrier is cloned with two proven resource literals
changed. Its argument count, buffer selection, downstream calls and globals
stay native. This supports the separate 12/13/14 carrier views without relaxing
the older production acceptance compiler. Resources are supplied as bytes;
this module never opens a path, writes a game, aligns faces, or estimates size.

This is a bytecode component, not yet the GUI scene-export/entry contract.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import struct

from .bin_archive import hzc_metadata
from .hoshimemo_scene_hook import _arguments, _call, _push_global, _pop_global
from .native_portrait_acceptance import (
    NativePortraitAcceptanceError, _instructions_in_range, _selector_branch,
    _normal_form_suffixes,
)
from .native_portrait_carriers import carrier_layout
from .native_portrait_expression import bind_native_expressions
from .native_portrait_slots import NativePortraitSlots, allocate_native_slots
from .portrait_emitter import _clone_dispatcher, _encode_push


SCHEMA = "fvp-native-portrait-loading/1"


@dataclass(frozen=True)
class NativeCarrierClone:
    slot_id: str
    output_symbol: str
    resolved_literal_patches: tuple


class NativePortraitLoading:
    def __init__(self, source, analysis, discovery, actor_ids, *, append_offset=None,
                 catalog=None, runtime_context=None):
        if catalog is not None and (not isinstance(catalog, NativePortraitSlots)
                or not catalog.with_handle_flow or catalog.source_sha256 != source.source_sha256
                or catalog.analysis_sha256 != analysis.source_sha256
                or catalog._source_bytes != source.original_bytes):
            raise NativePortraitAcceptanceError("已有角色槽目录不属于当前目标的原生加载链。")
        self.catalog = catalog if catalog is not None else NativePortraitSlots(
            source, analysis, discovery, with_handle_flow=True, runtime_context=runtime_context)
        self.assignments = allocate_native_slots(self.catalog.slots, actor_ids)
        self._source, self._analysis = source, analysis
        self._source_bytes = source.original_bytes
        self.source_sha256 = source.source_sha256
        record = discovery["profile_seed"]["native_symbols"]["portrait_dispatcher"]
        self._record = dict(record)
        self._layout = carrier_layout(int(record["args"]))
        self._body = _instructions_in_range(analysis, int(record["start"]), int(record["end"]))
        self.form_suffixes, self._form_evidence = _normal_form_suffixes(self._body, layout=self._layout)
        self.expression_bindings = bind_native_expressions(source, analysis, self.catalog, record, self._layout)
        self.base = len(self._source_bytes) if append_offset is None else append_offset
        if type(self.base) is not int or not len(self._source_bytes) <= self.base < 2**32:
            raise NativePortraitAcceptanceError("立绘附加代码必须在当前目标脚本末尾之后。")
        self.code = bytearray()
        self.payloads, self.loads, self.expressions, self.clears = {}, [], [], []
        self.geometries = []
        self._clones, self._active = {}, {}
        self._syscalls = {}
        for index, desc in enumerate(source.header.syscalls):
            if desc.name in self._syscalls:
                raise NativePortraitAcceptanceError("目标系统调用名称重复。")
            self._syscalls[desc.name] = index, desc.args

    def _check(self, document):
        if document.source_sha256 != self.source_sha256 or document.original_bytes != self._source_bytes:
            raise NativePortraitAcceptanceError("立绘加载器属于另一份目标脚本。")

    def _syscall(self, name, operands):
        bound = self._syscalls.get(name)
        if bound is None or bound[1] != len(operands):
            raise NativePortraitAcceptanceError("目标原生立绘调用未接通：" + name)
        return b"".join(operands) + b"\x03" + struct.pack("<H", bound[0])

    def _active_parts(self, slot):
        proof = slot.evidence["dispatcher_handles"]
        globals_ = proof["binding_global_ids"]
        if len(globals_) != 1 or not proof.get("dispatcher_handles_verified"):
            raise NativePortraitAcceptanceError("表情操作缺少唯一的当前原生资源槽变量。")
        return _push_global(globals_[0])

    def _active_primitive(self, slot):
        proof = slot.evidence["dispatcher_handles"]
        deltas = {x["primitive"] - x["graph"] for x in proof["buffers"]}
        if len(deltas) != 1:
            raise NativePortraitAcceptanceError("当前图元与资源槽的原生对应关系不一致。")
        return self._active_parts(slot) + _encode_push(next(iter(deltas)), "shift_jis") + b"\x1a"

    def load(self, document, actor_id, body_payload, face_payload, *, runtime_arguments,
             expression=0, native_scale=None, native_rotation=0):
        """Use explicit target-native arguments; no size inference is allowed.

        The caller must derive geometry from the locked import-size and current
        target geometry contract. A final RS override is optional and consumes
        an explicitly supplied native scale, never a face or bounding-box fit.
        """
        self._check(document)
        slot = self.assignments.get(actor_id)
        if slot is None:
            raise NativePortraitAcceptanceError("立绘角色未分配目标自己的槽位。")
        if (not isinstance(runtime_arguments, (list, tuple))
                or len(runtime_arguments) != self._layout.runtime_count
                or any(x is not None and type(x) not in (int, float, bool) for x in runtime_arguments)):
            raise NativePortraitAcceptanceError("原生立绘运行参数数量或类型错误。")
        if any(type(x) is float and (not math.isfinite(x) or abs(x) > 3.402823466e38)
               for x in runtime_arguments):
            raise NativePortraitAcceptanceError("原生立绘浮点参数必须是可编码的有限值。")
        if len(runtime_arguments) == 10 and (type(runtime_arguments[-1]) is not int or runtime_arguments[-1] != 0):
            raise NativePortraitAcceptanceError("附加图层加载尚未接通；普通立绘须明确关闭该层。")
        form = runtime_arguments[0]
        if type(form) is not int or form not in self.form_suffixes:
            raise NativePortraitAcceptanceError("目标立绘没有该原生形态后缀。")
        body_meta, face_meta = hzc_metadata(body_payload), hzc_metadata(face_payload)
        if body_meta.kind != 1 or body_meta.frame_count != 1 or face_meta.kind != 2:
            raise NativePortraitAcceptanceError("加载需要一张身体与配对表情图层。")
        if type(expression) is not int or not 0 <= expression < face_meta.frame_count:
            raise NativePortraitAcceptanceError("表情帧越界。")
        if (native_scale is not None and (type(native_scale) is not int or not 1 <= native_scale <= 4000)
                or type(native_rotation) is not int or not -2147483648 <= native_rotation <= 2147483647):
            raise NativePortraitAcceptanceError("显式原生缩放或旋转无效。")
        root, outfit, pair, action, outfit_code, _text = _selector_branch(
            self._body, slot.selector, resource_namespace=self._record["resource_namespace"], layout=self._layout)
        digest = hashlib.sha256(body_payload + face_payload).hexdigest().upper()
        stem = "CHR_FVP_" + digest
        suffix = "_FVP"
        body_name = stem + action + suffix + self.form_suffixes[form]
        face_name = body_name + "_表情"
        clone_key = actor_id, digest
        additions = {body_name: body_payload, face_name: face_payload}
        if any(name in self.payloads and self.payloads[name] != payload for name, payload in additions.items()):
            raise NativePortraitAcceptanceError("立绘配对内容标识冲突。")
        # Assemble the whole operation before publishing any bytes/resources.
        section = bytearray()
        clone = self._clones.get(clone_key)
        if clone is None:
            destination = self.base + len(self.code) + 5
            plan = NativeCarrierClone(str(slot.selector), "native_actor_" + actor_id, (
                dict(source_offset=root.offset, expected=root.text,
                     replacement=self._record["resource_namespace"] + stem),
                dict(source_offset=outfit.offset, expected=outfit.text, replacement=suffix)))
            raw, clone_report = _clone_dispatcher(self._source_bytes, self._body,
                int(self._record["start"]), int(self._record["end"]), destination, plan,
                resource_encoding=analysis_encoding(self._analysis),
                expected_args=int(self._record["args"]), expected_locals=int(self._record["locals"]))
            after = destination + len(raw)
            if after >= 2**32:
                raise NativePortraitAcceptanceError("附加立绘函数超出 HCB 地址范围。")
            section.extend(b"\x06" + struct.pack("<I", after) + raw)
            clone = dict(address=destination, report=clone_report)
        guards = slot.evidence.get("registration_guards", ())
        guard_values = {(g["global_id"], g["entry_value"], g["exit_value"]) for g in guards}
        if len(guard_values) > 1:
            raise NativePortraitAcceptanceError("目标角色注册开关不唯一。")
        guard = next(iter(guard_values)) if guard_values else None
        if guard:
            section.extend(_push_global(guard[0]) + _arguments([guard[1]]) + _pop_global(guard[0]))
        section.extend(_arguments([None]) + _pop_global(slot.cache_global_id))
        arguments = [slot.selector, 1, outfit_code, expression, *runtime_arguments]
        section.extend(b"".join(_encode_push(v, "shift_jis") for v in arguments) + _call(clone["address"]))
        if guard:
            section.extend(_arguments([guard[2]]) + _pop_global(guard[0]))
        section.extend(_arguments([None] * self.catalog.apply_count) + _call(self.catalog.apply_target))
        if native_scale is not None:
            section.extend(self._syscall("PrimSetRS", [self._active_primitive(slot),
                _encode_push(native_rotation, "shift_jis"), _encode_push(native_scale, "shift_jis")]))
        if guard:
            # The native registration wrapper closes its gate BEFORE the
            # separate apply transaction. Restoring a previously true gate
            # earlier would change that native downstream call's behaviour.
            section.extend(_pop_global(guard[0]))
        self.code.extend(section)
        self.payloads.update(additions)
        self._clones[clone_key] = clone
        self._active[actor_id] = dict(slot=slot, expression=expression, frames=face_meta.frame_count)
        self.loads.append(dict(actor_id=actor_id, selector=slot.selector, primitive_ids=list(pair),
            clone_address=clone["address"], dispatcher_argument_count=len(arguments),
            runtime_arguments=list(runtime_arguments), body_resource=body_name, face_resource=face_name,
            body_payload_sha256=hashlib.sha256(body_payload).hexdigest(),
            face_payload_sha256=hashlib.sha256(face_payload).hexdigest(),
            body_metadata=body_meta.to_dict(), face_metadata=face_meta.to_dict(),
            native_scale_override=native_scale, native_rotation=native_rotation,
            registration_guard_preserved=bool(guard), registration_guard_restored=bool(guard),
            original_loading_chain_preserved=True, image_resampled=False, face_alignment_used=False))
        return self.loads[-1]

    def swap(self, document, actor_id, body_payload, face_payload, **parameters):
        """Replace a live actor through its own carrier, preserving allocation.

        Geometry is still explicit: do not estimate size from face alignment.
        """
        self._check(document)
        if actor_id not in self._active:
            raise NativePortraitAcceptanceError("换装角色尚未加载或已经退场。")
        load = self.load(document, actor_id, body_payload, face_payload, **parameters)
        load["replacing_existing_actor"] = True
        load["actor_assignment_preserved"] = True
        return load

    def geometry(self, document, actor_id, fields):
        """Install caller-resolved raw primitive values on the CURRENT buffer.

        Native carrier/resource/face composition remains unchanged. These are
        direct syscall units, not another title's logical XY helper units.
        Assemble everything first so a rejected ABI changes no compiler state.
        """
        self._check(document)
        state = self._active.get(actor_id)
        if state is None:
            raise NativePortraitAcceptanceError("设置位置的角色尚未加载。")
        required = {"pivot", "x", "y", "z", "scale", "rotation", "alpha"}
        if not isinstance(fields, dict) or set(fields) != required:
            raise NativePortraitAcceptanceError("目标原生几何参数不完整。")
        pivot = fields["pivot"]
        if (not isinstance(pivot, (list, tuple)) or len(pivot) != 2
                or any(type(v) is not int or not -2147483648 <= v <= 2147483647 for v in pivot)
                or any(type(fields[k]) is not int or not -2147483648 <= fields[k] <= 2147483647
                       for k in required - {"pivot"})
                or fields["z"] <= 0 or fields["scale"] <= 0 or not 0 <= fields["alpha"] <= 255):
            raise NativePortraitAcceptanceError("目标原生几何数值无效。")
        prim = self._active_primitive(state["slot"])
        section = bytearray()
        for name, values in (
                ("PrimSetOP", pivot), ("PrimSetXY", (fields["x"], fields["y"])),
                ("PrimSetZ", (fields["z"],)),
                ("PrimSetRS", (fields["rotation"], fields["scale"])),
                ("PrimSetAlpha", (fields["alpha"],))):
            section.extend(self._syscall(name, [prim, *(_encode_push(v, "shift_jis") for v in values)]))
        self.code.extend(section)
        state["geometry"] = dict(fields, pivot=list(pivot))
        self.geometries.append(dict(actor_id=actor_id, selector=state["slot"].selector,
            current_native_buffer_used=True, raw_syscall_units=True,
            native_geometry=dict(fields, pivot=list(pivot)), image_resampled=False,
            face_alignment_used=False))

    def expression(self, document, actor_id, frame, *, duration_ms=200):
        self._check(document)
        state = self._active.get(actor_id)
        if state is None:
            raise NativePortraitAcceptanceError("表情切换角色尚未加载。")
        if type(frame) is not int or not 0 <= frame < state["frames"]:
            raise NativePortraitAcceptanceError("表情帧越界。")
        if type(duration_ms) is not int or not 0 <= duration_ms <= 6000:
            raise NativePortraitAcceptanceError("表情渐变时间无效。")
        name = "PartsMotion" if duration_ms else "PartsSelect"
        operands = [self._active_parts(state["slot"]), _encode_push(frame, "shift_jis")]
        if duration_ms:
            operands.append(_encode_push(duration_ms, "shift_jis"))
        binding = self.expression_bindings[state["slot"].selector]
        # Update the native pending/committed frame caches as the original
        # apply transaction does. Otherwise a later native apply could see
        # stale script state while the Parts engine is showing the new frame.
        section = b"".join(_arguments([frame]) + _pop_global(binding[key])
            for key in ("pending_frame_global_id", "committed_frame_global_id"))
        section += self._syscall(name, operands)
        self.code.extend(section)
        state["expression"] = frame
        self.expressions.append(dict(actor_id=actor_id, frame=frame, duration_ms=duration_ms,
            native_call=name, body_reloaded=False, native_geometry_changed=False,
            native_expression_state_updated=True, native_binding=dict(binding)))

    def clear_actors(self, document, actor_ids):
        """Clear only selected live actors with their exact native transaction."""
        self._check(document)
        if (not isinstance(actor_ids, (list, tuple)) or not actor_ids
                or any(not isinstance(actor, str) or actor not in self._active for actor in actor_ids)
                or len(set(actor_ids)) != len(actor_ids)):
            raise NativePortraitAcceptanceError("退场角色须已加载、身份不重复，不能包含其他角色。")
        selected = {actor: self.assignments[actor] for actor in actor_ids}
        compiled = self.catalog.compile_bound_lifecycle(document, selected)
        # A rejected partial native batch changes neither code nor live state.
        self.code.extend(compiled["clear"])
        for actor in actor_ids:
            del self._active[actor]
        self.clears.append(dict(actor_ids=list(actor_ids), scope="explicit_actor_subset",
                               native_lifecycle=compiled["report"]))
        return compiled

    def cleanup(self, document):
        self._check(document)
        compiled = self.catalog.compile_bound_lifecycle(document, self.assignments)
        self.code.extend(compiled["clear"])
        self._active.clear()
        self.clears.append(dict(actor_ids=list(self.assignments), scope="whole_allocated_scene",
                               native_lifecycle=compiled["report"]))
        return compiled

    def report(self):
        from copy import deepcopy
        return dict(schema=SCHEMA, source_sha256=self.source_sha256, append_offset=self.base,
            code_sha256=hashlib.sha256(self.code).hexdigest(), code_size=len(self.code),
            assignments={a: s.selector for a, s in self.assignments.items()},
            loads=deepcopy(self.loads), expressions=deepcopy(self.expressions),
            clears=deepcopy(self.clears), geometries=deepcopy(self.geometries),
            active_actor_ids=list(self._active),
            expression_bindings=deepcopy(self.expression_bindings),
            clones=[deepcopy(x["report"]) for x in self._clones.values()],
            source_resources_preserved=True, game_name_switch_used=False,
            native_loading_bytecode_generated=bool(self.loads),
            scene_export_connected=False, entry_cleanup_reviewed=False,
            runtime_verified=False, original_game_written=False)


def analysis_encoding(document):
    # Resource strings are read from the analysis/native carrier, even when the
    # translated runtime script uses a different encoding for dialogue.
    return document.encoding

