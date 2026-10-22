"""Keep target-native dialogue without reapplying inherited portrait state.

Only a scene-local copy of the print/wait call graph is changed. Exact native
portrait clear/apply entry points become argument-consuming no-ops there;
loading and exit cleanup still call the ORIGINAL target functions. Text,
speaker names, backlog, native input waits and all other functions remain.
This is byte-bound compilation, not engine-thread/runtime acceptance.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import struct

from .hcb import parse_bytes
from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair


def _terminated_padded_literal(raw):
    """Allow shorter translated C strings within an unchanged opcode slot.

    The encoded byte count, not the first NUL, bounds the next instruction.
    Some native translated scripts use trailing zero padding. Keep it intact;
    do not accept a changed slot length or non-padding bytes after the NUL.
    """
    payload = raw[2:]
    end = payload.find(b"\0")
    return end >= 0 and not any(payload[end:])


def _translated_literal_stub(source, analysis, item, actual):
    """Recognise only a pure translated string -> exact next-slot return.

    It must live beyond the complete analysis image and keep the unused source
    slot bytes intact. No arbitrary redirected calls or instructions qualify.
    Keep the raw payload without guessing the translator's text encoding.
    """
    if (item.size < 5 or actual[0] != 6 or actual[5:] != item.raw[5:]):
        raise NativePortraitAcceptanceError("汉化文字跳转不是完整的原生文本替换。")
    raw = source.original_bytes
    target = struct.unpack_from("<I", actual, 1)[0]
    if (target < len(analysis.original_bytes) or target + 2 > len(raw)
            or raw[target] != 14):
        raise NativePortraitAcceptanceError("汉化文字跳转没有指向已绑定的文本尾桩。")
    end = target + 2 + raw[target + 1]
    if (end + 5 > len(raw) or raw[end] != 6
            or struct.unpack_from("<I", raw, end + 1)[0] != item.offset + item.size
            or not _terminated_padded_literal(raw[target:end])):
        raise NativePortraitAcceptanceError("汉化文字尾桩没有准确返回下一条指令。")
    return dict(source_target=target, source_end=end + 5,
                return_offset=item.offset + item.size, literal=raw[target:end])


class NativePortraitDialogue:
    def __init__(self, context, lifecycle, output, *, roots=None,
                 suppress_scope="owned_scene_dialogue_only", cg_guard=None):
        source, analysis = context.document, context.analysis_document
        pair_binding = validate_native_script_pair(source, analysis, runtime_context=context)
        guard_prefix = "cg"
        if cg_guard is not None:
            from .native_cg_dialogue_guard import NativeCGDialogueGuard
            from .native_scene_dialogue_guard import NativeSceneDialogueGuard
            # Retain the existing keyword and clone/entry-wrapper contract.
            if not isinstance(cg_guard, (NativeCGDialogueGuard, NativeSceneDialogueGuard)) or cg_guard.context is not context:
                raise NativePortraitAcceptanceError("CG 交接保护不属于当前场景脚本。")
            if isinstance(cg_guard, NativeSceneDialogueGuard):
                guard_prefix = "scene"
        spans = {s.start: s for s in _function_spans(analysis)}
        roots = ({context.abi.print_target, context.abi.wait_target}
                 if roots is None else set(roots))
        if not roots or suppress_scope not in {
                "owned_scene_dialogue_only", "owned_scene_menu_only"}:
            raise NativePortraitAcceptanceError("场景交接缺少限定的原生调用入口。")
        # Speaker/name/backlog-avatar selection remains the target's existing
        # independently validated call. Do not clone every unused speaker or
        # turn this portrait fix into a target-wide speaker ABI relaxation.
        records = [lifecycle.get("clear"), lifecycle.get("apply")]
        records.extend(lifecycle.get("delegates", {}).values())
        suppressed = {int(s["start"]) for s in records if s}
        if (not suppressed and cg_guard is None) or any(s not in spans for s in suppressed | roots):
            raise NativePortraitAcceptanceError("台词舞台交接缺少原生函数身份。")
        # Include explicitly marked native ThreadStart function pointers. They
        # are not inferred from arbitrary integer operands or a game name.
        edges = {}
        pending, reachable = list(roots), set()
        while pending:
            address = pending.pop()
            if address in reachable:
                continue
            if address not in spans or len(reachable) >= 512:
                raise NativePortraitAcceptanceError("原生台词调用链超过限定范围。")
            reachable.add(address)
            span = spans[address]
            children = set(span.calls)
            children.update(i.operands["value"] for i in span.instructions
                            if i.address_role == "thread_start_function_pointer")
            edges[address] = children
            pending.extend(children - reachable)
        # UI punctuation/macros can be translated IN PLACE. This adapter copies
        # the actual runtime text bytes, not the clean Japanese literals. Every
        # other instruction (including calls, globals, constants and branches)
        # must match exactly. Native portrait/resource functions remain strict.
        # This allowance is LOCAL to dialogue cloning, not the slot/motion ABI.
        literal_changes, translated_stubs = [], {}
        for address in sorted(reachable):
            span = spans[address]
            for item in span.instructions:
                actual = source.original_bytes[item.offset:item.offset + item.size]
                if actual == item.raw:
                    continue
                if address in suppressed or item.mnemonic != "push_string" or len(actual) != item.size:
                    raise NativePortraitAcceptanceError("汉化脚本的台词控制指令已改变，不能交接立绘。")
                if actual[0] == 6:
                    stub = _translated_literal_stub(source, analysis, item, actual)
                    translated_stubs[item.offset] = dict(function=address, **stub)
                    actual = stub["literal"]
                elif (actual[:2] != item.raw[:2] or not _terminated_padded_literal(actual)
                        or not _terminated_padded_literal(item.raw)):
                    raise NativePortraitAcceptanceError("汉化脚本的台词控制指令已改变，不能交接立绘。")
                literal_changes.append(dict(offset=item.offset, function=address,
                    runtime_payload_sha256=hashlib.sha256(actual).hexdigest()))
        # The instruction CFG is identical after the checks above; the reference
        # inventory remains explicitly an ANALYSIS inventory, not a falsely
        # warning-free view of the entire translated runtime image.
        closure = NativeScriptStateClosure(analysis, analysis, sorted(reachable),
            max_functions=512, max_instructions=524288)
        selected = suppressed & reachable
        cg_reachable = set()
        if cg_guard is not None:
            pending = list(roots)
            while pending:
                address = pending.pop()
                if address in cg_reachable:
                    continue
                cg_reachable.add(address)
                if address not in selected:
                    pending.extend(edges[address]-cg_reachable)
        guarded_sites, guarded_records = (cg_guard.sites(spans, cg_reachable, selected & cg_reachable, roots=roots)
            if cg_guard is not None else ({}, []))
        changed = set(selected) | {r["function"] for r in guarded_records}
        protected_globals = cg_guard.camera_cache_slots if cg_guard is not None else ()
        if protected_globals:
            changed.update(roots)
        while True:
            parents = {a for a, children in edges.items() if children & changed}
            if parents <= changed:
                break
            changed.update(parents)
        self.source, self.analysis = source, analysis
        self.cg_guard = cg_guard
        self.mapping, section = {}, bytearray()
        self.entry_mapping = {}
        cloned_stubs, guard_entries, instruction_maps = {}, {}, {}
        if changed:
            address = len(source.original_bytes) + len(output) + 5
            if guarded_sites:
                guard_code, guard_entries = cg_guard.compile_wrappers(set(guarded_sites.values()), address)
                section.extend(guard_code)
                address += len(guard_code)
            for original in sorted(changed):
                span = spans[original]
                self.mapping[original] = address
                if original in selected:
                    address += 4
                    continue
                offsets = {}
                for item in span.instructions:
                    offsets[item.offset] = address
                    address += 5 if item.offset in guarded_sites else item.size
                instruction_maps[original] = offsets
            for offset, stub in sorted(translated_stubs.items()):
                if stub["function"] in changed:
                    cloned_stubs[offset] = address
                    address += len(stub["literal"]) + 5
            if address >= 2**31:
                raise NativePortraitAcceptanceError("台词函数指针超出目标有符号地址范围。")
            for original in sorted(changed):
                span = spans[original]
                if original in selected:
                    # Native function frames consume their exact argument count
                    # on return; dropping a call opcode would leak its arguments.
                    section.extend(bytes((1, span.args, 0, 4)))
                    continue
                offsets = instruction_maps[original]
                for item in span.instructions:
                    if item.offset in cloned_stubs:
                        section.extend(
                            b"\x06" + struct.pack("<I", cloned_stubs[item.offset]) + bytes(item.size - 5))
                        continue
                    if item.offset in guarded_sites:
                        section.extend(b"\x02"+struct.pack("<I", guard_entries[guarded_sites[item.offset]]))
                        continue
                    raw = bytearray(source.original_bytes[item.offset:item.offset+item.size])
                    target = None
                    if item.mnemonic in {"jmp", "jz"}:
                        original_target = item.operands["target"]
                        if original_target not in offsets:
                            raise NativePortraitAcceptanceError("台词分支越过被复制的原生函数。")
                        target = offsets[original_target]
                    elif item.mnemonic == "call":
                        target = self.mapping.get(item.operands["target"])
                    elif item.address_role == "thread_start_function_pointer":
                        target = self.mapping.get(item.operands["value"])
                    if target is not None:
                        struct.pack_into("<I", raw, 1, target)
                    section.extend(raw)
            # Rehome each verified text-only trampoline too. Keeping its old
            # return pointer would escape into the ORIGINAL portrait refresh.
            for offset in sorted(cloned_stubs):
                stub = translated_stubs[offset]
                original = stub["function"]
                return_at = instruction_maps[original][stub["return_offset"]]
                section.extend(stub["literal"] + b"\x06" + struct.pack("<I", return_at))
            self.entry_mapping.update(self.mapping)
            if protected_globals:
                # Cache restoration surrounds only authored print/menu entry
                # calls. Internal calls keep the native clone graph. Values
                # live on this call's stack, not shared scratch globals, so
                # nested entries do not overwrite each other's snapshots.
                for original in sorted(roots):
                    argc = spans[original].args
                    if not 0 <= argc <= 127:
                        raise NativePortraitAcceptanceError("镜头缓存保护入口的参数超过原生栈范围。")
                    self.entry_mapping[original] = address
                    wrapper = bytearray(bytes((1, argc, 1)))
                    for g in protected_globals:
                        wrapper.extend(_push_global(g))
                    for index in range(argc):
                        wrapper.extend(b"\x10"+struct.pack("<b", index-argc-1))
                    wrapper.extend(_call(self.mapping[original])+b"\x14\x16\0")
                    for g in reversed(protected_globals):
                        wrapper.extend(_pop_global(g))
                    wrapper.extend(b"\x10\0\x05")  # Preserve the original root's result.
                    section.extend(wrapper)
                    address += len(wrapper)
                if address >= 2**31:
                    raise NativePortraitAcceptanceError("镜头缓存保护入口超出目标有符号地址范围。")
            output.extend(b"\x06" + struct.pack("<I", address) + section)
        self._report = dict(schema="fvp-native-portrait-dialogue/1",
            original_source_functions_patched=False, native_click_wait_preserved=True,
            original_speaker_calls_preserved=True,
            motion_join_inserted_before_text=False, suppress_scope=suppress_scope,
            native_entry_roots=sorted(roots),
            native_portrait_targets=sorted(selected),
            **{f"{guard_prefix}_handle_guard": cg_guard.report() if cg_guard is not None else None,
               f"{guard_prefix}_guarded_syscall_sites": guarded_records,
               f"{guard_prefix}_guard_entries": deepcopy(guard_entries),
               f"{guard_prefix}_effective_reachable_functions": sorted(cg_reachable)},
            variable_width_instruction_relocation=bool(guarded_sites),
            function_map={str(k): v for k, v in self.entry_mapping.items()},
            internal_clone_map={str(k): v for k, v in self.mapping.items()},
            camera_cache_entry_global_ids=list(protected_globals),
            camera_cache_entry_snapshot_restored=bool(protected_globals),
            camera_cache_snapshot_scope="each_authored_entry_stack_frame" if protected_globals else None,
            clone_count=len(changed), clone_sha256=hashlib.sha256(section).hexdigest(),
            runtime_binding=pair_binding, runtime_text_literals_preserved=literal_changes,
            runtime_text_trampolines=[dict(offset=offset, function=stub["function"],
                source_target=stub["source_target"], source_end=stub["source_end"],
                original_return=stub["return_offset"], cloned_target=cloned_stubs.get(offset))
                for offset, stub in sorted(translated_stubs.items())],
            non_string_instructions_byte_identical=True,
            native_dependency_analysis_inventory=closure.describe(),
            preexisting_engine_thread_ownership_proven=False, runtime_verified=False)

    def rewrite(self, payload):
        table = self.analysis.original_bytes[self.analysis.header.sysdesc_offset:]
        doc = parse_bytes(struct.pack("<I", 4 + len(payload)) + payload + table, self.source.encoding)
        if doc.warnings:
            raise NativePortraitAcceptanceError("台词程序有未解析指令，不能交接舞台。")
        if self.cg_guard is not None:
            self.cg_guard.check_entry_results(doc, self.mapping)
        output = bytearray(payload)
        for item in doc.instructions:
            if item.mnemonic == "call" and item.operands["target"] in self.mapping:
                struct.pack_into("<I", output, item.offset - 4 + 1, self.entry_mapping[item.operands["target"]])
        return bytes(output)

    def report(self):
        return deepcopy(self._report)
