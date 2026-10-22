"""Bind the menu that the current target's own story actually calls.

Option registration, blocking input and cleanup stay in the original script.
No Hoshi address, result global, UI image or game-title switch is reused.
An arity or a registered syscall name alone never grants menu support.
"""
from copy import deepcopy

from .hoshimemo_scene_hook import _call, _pop_global
from .native_call_flow import NativeFunctionFlow
from .native_menu_tables import compile_table_snapshot, install_snapshot_helpers
from .native_portrait_acceptance import _function_spans
from .native_portrait_dialogue import (
    NativePortraitDialogue, _terminated_padded_literal, _translated_literal_stub,
)
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-scene-menu/1"


def discover_menus(document):
    entries = {s.start: s for s in _function_spans(document)}
    body, groups, consumed = document.instructions, {}, set()
    for index in range(len(body)-8):
        if index in consumed:
            continue
        # Older wrappers take (text, icon), newer ones (text, sound, icon).
        # Recognise the literal call sequence and verify the actual entry
        # arity below, rather than selecting a layout by game title.
        arity = next((n for n in (2, 3) if index+n < len(body)
            and [i.mnemonic for i in body[index:index+n+1]] ==
                ["push_string", *(["push_nil"]*(n-1)), "call"]), None)
        if arity is None:
            continue
        width = arity+1
        cursor, labels, add = index, [], None
        while cursor+width <= len(body) and [i.mnemonic for i in body[cursor:cursor+width]] == [
                "push_string", *(["push_nil"]*(arity-1)), "call"]:
            called = body[cursor+arity].operands["target"]
            if add is not None and called != add:
                break
            add = called
            labels.append(body[cursor].text)
            cursor += width
        if not 2 <= len(labels) <= 8 or cursor+5 >= len(body) or body[cursor].mnemonic != "call":
            continue
        show = body[cursor].operands["target"]
        if add not in entries or show not in entries or entries[add].args != arity or entries[show].args != 0:
            continue
        # The original caller dispatches the native result to numbered routes.
        # Ignore unrelated scalar setup, never infer a result slot from its ID.
        comparisons = {}
        for pos in range(cursor+1, min(cursor+80, len(body)-3)):
            window = body[pos:pos+4]
            if (window[0].mnemonic == "push_global" and window[1].mnemonic in {"push_i8", "push_i16", "push_i32"}
                    and window[2].mnemonic == "set_e" and window[3].mnemonic == "jz"
                    and 1 <= window[1].operands["value"] <= len(labels)):
                comparisons.setdefault(window[0].operands["value"], set()).add(window[1].operands["value"])
        results = [slot for slot, cases in comparisons.items() if {1, 2} <= cases]
        if len(results) != 1:
            continue
        consumed.update(range(index+1, cursor))
        groups.setdefault((add, show, results[0]), []).append(dict(
            offset=body[index].offset, show_offset=body[cursor].offset, option_count=len(labels)))
    return entries, groups


class NativeSceneMenu:
    def __init__(self, context):
        self.context, self.source, self.analysis = context, context.document, context.analysis_document
        pair = validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        entries, groups = discover_menus(self.analysis)
        flow, matches = NativeFunctionFlow(self.analysis), []
        for (add, show, result), sites in groups.items():
            registration, menu = entries[add], entries[show]
            if (registration.locals or len(registration.instructions) > 2048 or len(menu.instructions) > 16384
                    or not {"InputGetDown", "InputGetState", "PrimHit"} <= set(menu.syscalls)
                    or not any(i.mnemonic == "jmp" and i.operands["target"] < i.offset for i in menu.instructions)
                    or not any(i.mnemonic == "pop_global" and i.operands["value"] == result for i in menu.instructions)):
                continue
            trace = flow.trace(add, literal_arguments={i: None for i in range(1, registration.args)}, non_nil_arguments=(0,),
                               max_joined_values=128, max_instructions=8192)
            if trace["status"] != "proven_static_argument_flow":
                continue
            writes = trace["global_writes"]
            strings = {w["slot"] for w in writes if w["value"] == {"kind": "argument", "index": 0}}
            printed = [c for c in trace["calls"] if c.get("name") == "TextPrint"]
            if (not 2 <= len(printed) <= 8 or len(strings) != len(printed)
                    or any(len(c["arguments"]) != 2 or c["arguments"][0] != dict(kind="literal", type="int", value=i)
                        or c["arguments"][1].get("kind") != "global_read"
                        or c["arguments"][1]["slot"] not in strings for i, c in enumerate(printed, 1))):
                continue
            counters = []
            for w in writes:
                value, slot = w["value"], w["slot"]
                operands = value.get("operands", ())
                if (value.get("kind") == "add" and len(operands) == 2
                        and operands[0].get("kind") == "global_read" and operands[0]["slot"] == slot
                        and operands[1] == dict(kind="literal", type="int", value=1)
                        and any(v["slot"] == slot and v["value"] == dict(kind="literal", type="int", value=0) for v in writes)):
                    counters.append(slot)
            if len(counters) != 1:
                continue
            counter = counters[0]
            # The counter's -1 guard resets the target-native menu, not ours.
            guards = [b["condition"] for b in trace["branches"]]
            if not any(g.get("kind") == "set_e" and len(g.get("operands", ())) == 2
                    and g["operands"][0].get("kind") == "global_read" and g["operands"][0]["slot"] == counter
                    and g["operands"][1] == dict(kind="literal", type="int", value=-1) for g in guards):
                continue
            matches.append((add, show, result, counter, len(printed), sites, trace))
        if len(matches) != 1:
            raise ValueError("此版本的原生选项登记、等待输入和分支结果尚不能唯一绑定。")
        self.add, self.show, self.result, self.counter, self.capacity, sites, trace = matches[0]
        self.registration_arity = entries[self.add].args
        roots = {self.add, self.show}
        # Include native ThreadStart callbacks; a direct-call closure alone is
        # insufficient for menus with animated controls and input workers.
        while True:
            # UI macros may have translated strings or pure string tail stubs.
            # Inventory the clean CFG, then byte-check EVERY runtime dependency
            # below. This exception is local to text, never calls/globals/input.
            closure = NativeScriptStateClosure(self.analysis, self.analysis, sorted(roots),
                max_functions=1024, max_instructions=1048576)
            threads = {i.operands["value"] for address in closure.dependencies for i in entries[address].instructions
                       if i.address_role == "thread_start_function_pointer"}
            if threads <= roots:
                break
            roots.update(threads)
        text_changes = []
        for address in sorted(closure.dependencies):
            for item in entries[address].instructions:
                actual = self.source.original_bytes[item.offset:item.offset+item.size]
                if actual == item.raw:
                    continue
                if item.mnemonic != "push_string" or len(actual) != item.size:
                    raise ValueError("运行脚本的原生选项控制指令已改变，不能借用分析脚本的入口。")
                record = dict(offset=item.offset, function=address)
                if actual[0] == 6:
                    stub = _translated_literal_stub(self.source, self.analysis, item, actual)
                    record.update(runtime_text_stub=stub["source_target"], return_offset=stub["return_offset"])
                elif (actual[:2] != item.raw[:2] or not _terminated_padded_literal(actual)
                        or not _terminated_padded_literal(item.raw)):
                    raise ValueError("选项文字替换改变了原生指令边界。")
                text_changes.append(record)
        self.closure = closure
        self.portrait_bridge = None
        self.snapshot = compile_table_snapshot(self.analysis, entries, closure, roots)
        syscalls = closure.describe()["syscall_sites"]
        if not {"ThreadNext", "InputGetDown", "InputGetState"} <= set(syscalls):
            raise ValueError("原生选项的输入等待调用链不完整。")
        self._report = dict(schema=SCHEMA, registration_helper=self.add, input_helper=self.show,
            registration_argument_count=self.registration_arity,
            result_global=self.result, counter_global=self.counter, option_capacity=self.capacity,
            original_story_call_sites=sites, registration_argument_flow=trace,
            native_input_polling_preserved=True, native_menu_images_used=True,
            runtime_binding=pair, source_dependencies=closure.describe(),
            runtime_source_sha256=self.source.source_sha256,
            runtime_text_literals_preserved=text_changes,
            native_table_snapshot=deepcopy(self.snapshot["table_report"]),
            state_snapshot=deepcopy(self.snapshot["report"]),
            non_string_instructions_byte_identical=True,
            game_name_switch_used=False, runtime_verified=False)

    def compile(self, options):
        if (not isinstance(options, (list, tuple)) or not 2 <= len(options) <= min(4, self.capacity)
                or any(not isinstance(t, str) or not t.strip() for t in options) or len(set(options)) != len(options)):
            raise ValueError("选项需要 2～4 个不同的非空标题，且不能超过原作容量。")
        encoding = self.source.encoding
        section = bytearray(_encode_push(-1, encoding) + _pop_global(self.counter))
        for text in options:
            section.extend(_encode_push(text, encoding) + b"\x08"*(self.registration_arity-1) + _call(self.add))
        section.extend(_call(self.show))
        return (self.portrait_bridge.rewrite(bytes(section))
                if self.portrait_bridge is not None else bytes(section))

    def protect_scene_portraits(self, lifecycle, output):
        """Rehome only the native menu's inherited-portrait refresh calls.

        The original menu, its input workers and UI resources stay intact.
        In the scene-local copy only proven clear/apply/delegate entry points
        become exact-arity no-ops, as they already do for scene dialogue.
        No actor pose is reset before or after the author's selected route.
        """
        self.protect_scene_graphics(lifecycle, output)

    def protect_scene_graphics(self, lifecycle, output, *, cg_guard=None):
        """One private menu copy for portrait refresh AND owned CG guards.

        Composing two independent root rewrites would let the first copied
        root bypass the second. Build one graph when the scene owns both.
        Existing portrait-only callers retain their original behaviour.
        """
        if self.portrait_bridge is not None:
            raise ValueError("当前选项已绑定场景立绘，不能重复复制调用链。")
        records = [lifecycle.get("clear"), lifecycle.get("apply"),
                   *lifecycle.get("delegates", {}).values()]
        mutators = {int(record["start"]) for record in records if record}
        if cg_guard is None and not mutators & set(self.closure.dependencies):
            return
        self.portrait_bridge = NativePortraitDialogue(self.context, lifecycle, output,
            roots={self.add, self.show}, suppress_scope="owned_scene_menu_only", cg_guard=cg_guard)
        if mutators:
            self._report["owned_portrait_handoff"] = self.portrait_bridge.report()
        if cg_guard is not None:
            self._report["owned_cg_handoff"] = self.portrait_bridge.report()
        self._report["original_menu_functions_patched"] = False

    def report(self):
        return deepcopy(self._report)

    def prepare(self, output):
        install_snapshot_helpers(self.snapshot, self.source, output)
        self._report["state_snapshot"] = deepcopy(self.snapshot["report"])
