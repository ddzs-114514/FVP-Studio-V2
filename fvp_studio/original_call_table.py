"""Read-only, source-order dialogue/call tables for original FVP HCB scripts.

This is deliberately not an execution trace or a Studio project exporter.
Arguments are decoded within basic blocks; facts are discarded at joins and
unknown operations. Function ordinals belong only to the SHA-bound input.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from .hcb import HcbDocument, HcbError, load, normalize_encoding
from .native_target_discovery import (
    _discover_speaker_wrapper_family,
    _discover_story_dialogue_family,
    _function_regions,
)
from .original_import import OriginalImportError, read_active_string


SCHEMA = "fvp-original-dialogue-call-table/1"
SCOPE = "static-source-order-not-runtime-trace"


@dataclass(frozen=True)
class _Value:
    value: Any
    string_offset: int | None = None


def _unknown(reason: str) -> _Value:
    return _Value({"unknown": reason})


def _symbol(kind: str, **data: Any) -> _Value:
    return _Value({"kind": kind, **data})


def _format(value: Any) -> str:
    if value is None:
        return "Nil"
    if value is True:
        return "True"
    if value is False:
        return "False"
    if isinstance(value, dict):
        if "unknown" in value:
            return "?[" + value["unknown"] + "]"
        if value.get("kind") == "argument":
            return f"arg[{value['index']}]"
        if value.get("kind") in {"global", "local"}:
            return f"{value['kind']}[{value['slot']}]"
        if value.get("kind") == "return":
            return f"return@0x{value['call_offset']:X}"
        if value.get("kind") == "operator":
            return value["operator"] + "(" + ", ".join(map(_format, value["operands"])) + ")"
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


class OriginalCallTable:
    def __init__(self, document: HcbDocument, *, print_target: int | None = None,
                 wait_target: int | None = None, print_includes_wait: bool = False):
        if document.warnings:
            raise HcbError("HCB 解析存在警告；请先确认编码/版本，不能把不完整解析当成完整调用表。")
        self.document = document
        self.sha256 = document.source_sha256
        self.regions = _function_regions(document)
        self.regions_by_start = {r.start: r for r in self.regions}
        self.ordinals = {r.start: n for n, r in enumerate(self.regions)}
        if print_target is None:
            discovery = _discover_story_dialogue_family(document, self.regions)
            selected = discovery.get("selected")
            if not selected:
                raise HcbError("无法唯一定位本 HCB 的台词函数；可显式传入 --print-target / --wait-target。")
            print_target = selected["print"]["start"]
            wait_target = selected["wait"]["start"]
            print_includes_wait = bool(selected.get("print_includes_wait", False))
            self.dialogue_discovery = {
                "status": discovery["status"], "mode": selected.get("discovery_mode"),
                "evidence": selected.get("evidence", []),
            }
        else:
            self.dialogue_discovery = {"status": "explicit_caller_supplied_addresses"}
        if print_target not in self.regions_by_start:
            raise HcbError("台词函数地址不是此 HCB 的函数入口。")
        if self.regions_by_start[print_target].args < 1:
            raise HcbError("台词函数必须至少有文本参数。")
        if not print_includes_wait and wait_target not in self.regions_by_start:
            raise HcbError("需要此 HCB 的等待函数，或显式 --print-includes-wait。")
        self.print_target, self.wait_target = print_target, wait_target
        self.print_includes_wait = print_includes_wait
        speakers = _discover_speaker_wrapper_family(document, self.regions)
        self.speakers = {x["start"]: x for x in speakers.get("entries", [])}
        self.speaker_discovery_status = speakers.get("status")

    def label(self, address: int) -> str:
        n = self.ordinals.get(address)
        return f"function_{n}_" if n is not None else f"sub_0x{address:X}"

    def role(self, address: int) -> str:
        if address == self.print_target:
            return "台词提交（内部含等待）" if self.print_includes_wait else "台词提交"
        if address == self.wait_target:
            return "显示/输入等待"
        if address in self.speakers:
            return "说话人包装函数"
        return ""

    def _scan(self, region) -> tuple[list[dict], list[dict]]:
        """Recover exact local stack values, never carry them across CFG joins."""
        body = self.document.instructions[region.instruction_start_index:region.instruction_end_index]
        targets = {x.operands["target"] for x in body if x.mnemonic in {"jmp", "jz"}}
        stack: list[_Value] = []
        slots: dict[int, _Value] = {}
        returned = _unknown("return_not_known_in_block")
        calls, control = [], []
        reset = True
        block = region.start

        def consume(count: int) -> list[_Value]:
            if count == 0:
                return []
            present = min(count, len(stack))
            values = stack[-present:] if present else []
            if present:
                del stack[-present:]
            return [_unknown("value_from_outside_basic_block")] * (count - present) + values

        for item in body:
            name = item.mnemonic
            if reset or item.offset in targets:
                stack.clear()
                slots.clear()
                returned = _unknown("return_not_known_in_block")
                block, reset = item.offset, False
            if name == "init_stack":
                continue
            if name == "push_string":
                stack.append(_Value(item.text, item.offset))
            elif name in {"push_i8", "push_i16", "push_i32", "push_f32"}:
                stack.append(_Value(item.operands["value"]))
            elif name == "push_nil":
                stack.append(_Value(None))
            elif name == "push_true":
                stack.append(_Value(True))
            elif name == "push_top":
                stack.append(stack[-1] if stack else _unknown("empty_stack_top"))
            elif name == "push_stack":
                slot = item.operands["value"]
                if slot in slots:
                    stack.append(slots[slot])
                elif -(region.args + 1) <= slot <= -2:
                    # An argument may have been reassigned before this block.
                    stack.append(_symbol("argument", index=slot + region.args + 1)
                                 if block == region.start else _symbol("local", slot=slot))
                else:
                    stack.append(_symbol("local", slot=slot))
            elif name == "push_global":
                stack.append(_symbol("global", slot=item.operands["value"]))
            elif name == "pop_stack":
                slots[item.operands["value"]] = consume(1)[0]
            elif name == "pop_global":
                consume(1)
            elif name == "push_return":
                stack.append(returned)
            elif name == "neg":
                value = consume(1)[0].value
                stack.append(_Value(-value) if type(value) in {int, float}
                             else _symbol("operator", operator="neg", operands=[value]))
            elif name in {"add", "sub", "mul", "div", "and", "or",
                          "set_e", "set_ne", "set_g", "set_ge", "set_l", "set_le"}:
                operands = [x.value for x in consume(2)]
                # No host-language truthiness / VM numeric coercion assumptions.
                expression = _symbol("operator", operator=name, operands=operands)
                stack.append(expression if len(_format(expression.value)) < 2048
                             else _unknown("expression_size_limit"))
            elif name in {"call", "syscall"}:
                if name == "call":
                    address = item.operands["target"]
                    callee = self.regions_by_start.get(address)
                    argc = callee.args if callee else None
                    identity = {"target": address, "function": self.label(address),
                                "role": self.role(address)}
                else:
                    syscall_id = item.operands["id"]
                    syscall = (self.document.header.syscalls[syscall_id]
                               if 0 <= syscall_id < len(self.document.header.syscalls) else None)
                    argc = syscall.args if syscall else None
                    identity = {"syscall_id": syscall_id, "name": syscall.name if syscall else "unknown"}
                arguments = consume(argc) if argc is not None else []
                if argc is None:
                    stack.clear()
                public = [x.value for x in arguments]
                calls.append({
                    "offset": item.offset, "end_offset": item.offset + item.size,
                    "kind": name, **identity, "argument_count": argc,
                    "arguments": public if argc is not None else None,
                    "argument_string_offsets": [x.string_offset for x in arguments],
                    "argument_status": ("unknown_arity" if argc is None else
                                        "symbolic_or_unknown" if any(isinstance(x, dict) for x in public)
                                        else "literal"),
                    "basic_block": block,
                })
                returned = _symbol("return", call_offset=item.offset)
            elif name in {"jmp", "jz", "ret", "retv"}:
                record = {"offset": item.offset, "kind": name, "basic_block": block}
                if name in {"jmp", "jz"}:
                    record["target"] = item.operands["target"]
                    record["backward_or_external"] = not item.offset < record["target"] < region.end
                if name in {"jz", "retv"}:
                    record["condition" if name == "jz" else "value"] = consume(1)[0].value
                control.append(record)
                reset = True
            elif name != "nop":
                control.append({"offset": item.offset, "kind": "unhandled_instruction",
                                "mnemonic": name, "basic_block": block})
                reset = True
            if len(stack) > 1024:
                stack.clear()
                control.append({"offset": item.offset, "kind": "stack_limit"})
        return calls, control

    def _speaker(self, calls: list[dict], text_call: dict) -> dict:
        candidates = [c for c in calls if c["offset"] < text_call["offset"]
                      and c.get("target") in self.speakers]
        if not candidates:
            return {"status": "no_direct_speaker_in_span", "names": [],
                    "note": "未发现本段直接说话人调用；不继承上一句，也不据此断言旁白。"}
        call = candidates[-1]
        entry = self.speakers[call["target"]]
        args = call["arguments"] or []
        selector_index = entry.get("selector_argument_index")
        selector = (args[selector_index] if selector_index is not None and selector_index < len(args)
                    else {"unknown": "selector"})
        alias = entry.get("alias") or {}
        if alias.get("alias_kind") == "forced_selector" and alias.get("target") in self.speakers:
            selector = alias["forced_selector"]
            entry = self.speakers[alias["target"]]
        names = entry.get("name_variants", [])
        branches = entry.get("selector_branches", {}).get("branches", [])
        if branches and not isinstance(selector, dict):
            matching = [b for b in branches if b["selector_kind"] == "integer"
                        and type(selector) is int and b["selector_value"] == selector]
            if not matching:
                matching = [b for b in branches if b["selector_kind"] == "default_fallthrough"]
            if matching:
                names = list(dict.fromkeys(n for b in matching for n in b["name_variants"]))
        return {
            "status": ("static_wrapper_candidate" if call["basic_block"] == text_call["basic_block"]
                       else "branch_dependent_wrapper_candidate"),
            "names": names, "call_offset": call["offset"], "function": call["function"],
            "selector": selector,
            "first_argument": args[0] if args else None,
            "note": "名称按包装函数分支静态识别；第一参数保留原值，不凭编号拼造语音文件名。",
        }

    def analyse_region(self, region) -> dict:
        calls, control = self._scan(region)
        prints = [i for i, c in enumerate(calls) if c.get("target") == self.print_target]
        rows, cursor = [], 0
        source_start = region.start
        has_branches = any(c["kind"] in {"jmp", "jz", "unhandled_instruction", "stack_limit"}
                           for c in control)
        for n, index in enumerate(prints):
            text_call = calls[index]
            next_print = prints[n + 1] if n + 1 < len(prints) else len(calls)
            waits = [j for j in range(index + 1, next_print)
                     if calls[j].get("target") == self.wait_target]
            end_index = index if self.print_includes_wait or not waits else waits[0]
            end_offset = calls[end_index]["end_offset"]
            span = calls[cursor:end_index + 1]
            args = text_call["arguments"] or []
            source_offsets = text_call["argument_string_offsets"]
            text = args[0] if args and isinstance(args[0], str) else None
            rows.append({
                "id": f"hcb:0x{text_call['offset']:X}", "line_in_function": n + 1,
                "function": self.label(region.start), "function_address": region.start,
                "text": text, "text_status": "literal" if text is not None else "unresolved",
                "text_slot": source_offsets[0] if source_offsets else None,
                "text_call": text_call["offset"],
                "wait_call": calls[end_index]["offset"] if end_index != index else None,
                "wait_status": ("inside_print_wrapper" if self.print_includes_wait else
                                "source_order_pair" if waits else "not_found_before_next_text"),
                "span_start": source_start, "span_end_exclusive": end_offset,
                "function_has_control_flow": has_branches,
                "speaker": self._speaker(span, text_call),
                "calls": [{**c, "phase": (
                    "text" if c["offset"] == text_call["offset"] else
                    "wait" if c["offset"] == calls[end_index]["offset"] and end_index != index else
                    "before_text" if c["offset"] < text_call["offset"] else "after_text_before_wait"
                )} for c in span],
                "control_flow": [c for c in control if source_start <= c["offset"] < end_offset],
            })
            source_start, cursor = end_offset, end_index + 1
        return {"rows": rows, "calls": calls, "control_flow": control,
                "tail_calls": calls[cursor:] if rows else [],
                "tail_control_flow": [c for c in control if c["offset"] >= source_start] if rows else []}

    def function_record(self, region, analysed: dict, *, text_file: str | None = None) -> dict:
        strings = list(dict.fromkeys(region.strings))
        return {
            "function": self.label(region.start), "address": region.start, "end": region.end,
            "ordinal_zero_based": self.ordinals[region.start], "arguments": region.args,
            "locals": region.locals, "role": self.role(region.start),
            "direct_syscalls": list(dict.fromkeys(region.syscalls)),
            "direct_function_targets": list(dict.fromkeys(region.call_targets)),
            "string_constants": strings[:32] if not analysed["rows"] else [],
            "string_constant_count": len(strings),
            "dialogue_count": len(analysed["rows"]), "dialogue_file": text_file,
            # Story calls live in the per-line data plus the tail, not duplicated here.
            "calls": [] if analysed["rows"] else analysed["calls"],
            "control_flow": analysed["control_flow"],
            "tail_calls_after_last_dialogue": analysed["tail_calls"],
        }

    def call_text(self, call: dict) -> str:
        identity = (f"{call['function']} @0x{call['target']:X}" if call["kind"] == "call"
                    else f"{call['name']} [syscall {call['syscall_id']}]")
        arguments = call["arguments"]
        rendered = "参数个数未知" if arguments is None else ", ".join(map(_format, arguments))
        hint = call.get("role", "")
        # Exact syscall names come from this HCB's import table, not an alias database.
        if not hint and call.get("target") in self.regions_by_start:
            names = list(dict.fromkeys(self.regions_by_start[call["target"]].syscalls))
            if names:
                hint = "内部直接含 " + ", ".join(names[:5]) + (" …" if len(names) > 5 else "")
        return f"0x{call['offset']:X}  {identity}({rendered})" + (f"  // {hint}" if hint else "")

    def row_text(self, row: dict) -> str:
        title = f"第 {row['line_in_function']} 句 | {row['function']} | {row['id']}"
        speaker = row["speaker"]
        names = " / ".join(speaker["names"]) or "未确定"
        lines = [title, "说话人（静态识别）：" + names,
                 "原文：" + (row["text"] if row["text"] is not None else "[文本参数未解出]")]
        if "translation" in row:
            lines.append("汉化对照：" + row["translation"]["text"])
        if "first_argument" in speaker:
            lines.append("说话人包装函数第一参数：" + _format(speaker["first_argument"])
                         + "（原作编号/参数，未展开成音频文件名）")
        lines.append(f"源码区间：0x{row['span_start']:X} ～ 0x{row['span_end_exclusive']:X}（不含末端）")
        if row["function_has_control_flow"]:
            lines.append("注意：所在函数有分支/跳转；以下是地址顺序，不表示每个调用都会执行。")
        if row["wait_status"] == "not_found_before_next_text":
            lines.append("注意：下一台词前未发现直接等待调用；不跨句拼接。")
        phase_names = {"before_text": "台词前", "text": "台词",
                       "after_text_before_wait": "提交后", "wait": "等待"}
        events = [(c["offset"], f"  [{phase_names[c['phase']]}] {self.call_text(c)}")
                  for c in row["calls"]]
        events.extend((c["offset"], f"  [控制流] 0x{c['offset']:X}  {_format(c)}")
                      for c in row["control_flow"])
        lines.extend(text for _, text in sorted(events))
        return "\n".join(lines) + "\n\n"


def bind_translation(document: HcbDocument, path: Path, encoding: str) -> tuple[bytes, dict]:
    """Text-only comparison; ensure every original non-string instruction agrees."""
    raw = path.read_bytes()
    changed = [x.offset for x in document.instructions if x.mnemonic != "push_string"
               and raw[x.offset:x.offset + x.size] != x.raw]
    if changed:
        raise HcbError(f"汉化对照与基准 HCB 有 {len(changed)} 处非字符串指令差异；拒绝按地址乱配。")
    return raw, {
        "path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
        "encoding": normalize_encoding(encoding), "non_string_instructions_match": True,
        "scope": "text-only-comparison; calls-and-syscalls-come-from-base-hcb",
    }


def _write_json_line(stream, data: dict) -> None:
    stream.write(json.dumps(data, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n")


def export_table(table: OriginalCallTable, output: Path, *, translation_path: Path | None = None,
                 translation_encoding: str = "gb18030", sample_function: int | None = None,
                 sample_start: int = 1, sample_count: int = 20) -> dict:
    output = output.resolve()
    inputs = [p.resolve() for p in (table.document.path, translation_path) if p is not None]
    if any(output == p.parent or p.parent in output.parents for p in inputs):
        raise HcbError("输出必须放在游戏/HCB 目录之外，避免向原作目录写入文件。")
    if output.exists():
        raise HcbError("输出目录已存在；请选择新目录，不覆盖已有报告。")
    if sample_start < 1 or not 1 <= sample_count <= 200:
        raise HcbError("示例起点须 >= 1，示例长度须为 1～200。")
    if sample_function is not None and sample_function not in table.regions_by_start:
        raise HcbError("示例函数地址不是当前 HCB 的函数入口。")
    if sample_function is not None:
        count = table.regions_by_start[sample_function].call_targets.count(table.print_target)
        if sample_start > count:
            raise HcbError("所选函数没有这么多台词调用位置，请调整示例起点。")
    translated, translation_info = None, None
    if translation_path is not None:
        translated, translation_info = bind_translation(table.document, translation_path, translation_encoding)
    # Only a new isolated output directory is ever written.
    output.mkdir(parents=True, exist_ok=False)
    sections = output / "按脚本函数分组"
    sections.mkdir()
    counts: Counter = Counter({
        key: 0 for key in (
            "functions", "all_direct_call_sites", "dialogue_calls", "literal_text",
            "unresolved_text", "direct_calls_in_dialogue_spans",
            "symbolic_or_unknown_calls", "without_direct_wait", "translation_matches",
            "dialogue_functions", "tail_calls_after_last_dialogue", "sample_lines",
        )
    })
    section_index, example_rows, failures = [], [], []
    sample_targets: set[int] = set()
    generated_functions: dict[int, dict] = {}
    line_path = output / "逐句调用表.jsonl"
    function_path = output / "函数内部调用.jsonl"
    with line_path.open("x", encoding="utf-8") as line_stream, \
            function_path.open("x", encoding="utf-8") as function_stream:
        for region in table.regions:
            analysed = table.analyse_region(region)
            rows = analysed["rows"]
            text_file = f"按脚本函数分组/{table.label(region.start)}0x{region.start:X}.txt" if rows else None
            for row in rows:
                counts["dialogue_calls"] += 1
                counts["literal_text" if row["text_status"] == "literal" else "unresolved_text"] += 1
                counts["direct_calls_in_dialogue_spans"] += len(row["calls"])
                counts["symbolic_or_unknown_calls"] += sum(c["argument_status"] != "literal" for c in row["calls"])
                counts["without_direct_wait"] += row["wait_status"] == "not_found_before_next_text"
                if translated is not None and row["text_slot"] is not None:
                    try:
                        text, offset = read_active_string(translated, row["text_slot"],
                                                          translation_info["encoding"])
                        row["translation"] = {"text": text, "resolved_offset": offset}
                        counts["translation_matches"] += 1
                    except OriginalImportError as exc:
                        failures.append({"id": row["id"], "reason": str(exc)})
                _write_json_line(line_stream, row)
                if (sample_function is None or region.start == sample_function) \
                        and row["line_in_function"] >= sample_start and len(example_rows) < sample_count:
                    example_rows.append(row)
                    sample_targets.update(c["target"] for c in row["calls"] if c["kind"] == "call")
            record = table.function_record(region, analysed, text_file=text_file)
            _write_json_line(function_stream, record)
            # Small support-function records enable a readable one-level sample appendix.
            if not rows:
                generated_functions[region.start] = record
            counts["functions"] += 1
            counts["all_direct_call_sites"] += len(analysed["calls"])
            if not rows:
                continue
            counts["dialogue_functions"] += 1
            counts["tail_calls_after_last_dialogue"] += len(analysed["tail_calls"])
            section_index.append({
                "function": table.label(region.start), "address": region.start,
                "line_count": len(rows), "file": text_file, "first_text": rows[0]["text"],
            })
            with (output / text_file).open("x", encoding="utf-8") as stream:
                stream.write("原作 HCB 逐句调用表（静态源码，不是运行轨迹）\n")
                stream.write(f"SHA256: {table.sha256}\n\n")
                for row in rows:
                    stream.write(table.row_text(row))
                if analysed["tail_calls"] or analysed["tail_control_flow"]:
                    stream.write("【最后一句等待结束后的函数尾部；不冒充某句的演出】\n")
                    events = [(c["offset"], table.call_text(c)) for c in analysed["tail_calls"]]
                    events.extend((c["offset"], _format(c)) for c in analysed["tail_control_flow"])
                    for _, text in sorted(events):
                        stream.write(text + "\n")
    with (output / "先看这个_逐句示例.txt").open("x", encoding="utf-8") as stream:
        stream.write("原作逐句函数调用示例\n\n")
        stream.write("函数编号和地址只属于本次 HCB；不是跨游戏通用函数号。\n")
        stream.write("所有调用按源码地址列出；分支、循环、线程不会被当成已执行。\n")
        stream.write("台词前 = 上一句等待之后至本句提交；提交后 = 本句提交至其直接等待。\n")
        stream.write("Nil 与 0/False 不混同；? 表示参数未解出，arg/global 表示符号值。\n")
        stream.write("汉化文本（若有）仅供对照，调用和系统函数表仍取自基准原版。\n\n")
        for row in example_rows:
            stream.write(table.row_text(row))
        stream.write("\n【示例涉及的直接被调函数：再展开一层】\n")
        stream.write("这里只列静态调用点，不是把被调函数所有分支合成必然执行顺序。\n")
        for address in sorted(sample_targets):
            record = generated_functions.get(address)
            if record is None:
                continue
            stream.write(f"\n{record['function']} @0x{address:X}，参数 {record['arguments']} 个\n")
            if record["control_flow"]:
                stream.write("  含控制流，完整分支条件见「函数内部调用.jsonl」。\n")
            if record["string_constants"]:
                stream.write("  字符串常量：" + _format(record["string_constants"]) + "\n")
            for call in record["calls"]:
                stream.write("  " + table.call_text(call) + "\n")
    counts["sample_lines"] = len(example_rows)
    manifest = {
        "schema": SCHEMA, "scope": SCOPE, "source": str(table.document.path),
        "source_sha256": table.sha256, "encoding": table.document.encoding,
        "runtime_executed": False, "original_modified": False,
        "dialogue_discovery": table.dialogue_discovery,
        "print_target": table.print_target, "wait_target": table.wait_target,
        "print_includes_wait": table.print_includes_wait,
        "speaker_discovery_status": table.speaker_discovery_status,
        "translation": translation_info, "translation_failures": failures,
        "counts": dict(counts), "sections": section_index,
        "limitations": [
            "只统计已定位台词包装函数的直接调用点，不宣称涵盖所有系统提示/菜单/动态生成文本。",
            "源码地址顺序不是游玩顺序；分支/循环不展开为运行轨迹。",
            "参数只在基本块内传播，不推测跨分支变量值或被调函数副作用。",
            "间隔内的调用可能承接上一句或准备下一句，不等于全部由本句触发。",
            "没有当前段的说话人调用不自动判为旁白；原作语音编号保留原值。",
            "线程入口可能作为 ThreadStart 参数传递；不推测线程运行次数/结束时机。",
            "函数序号为本文件 init_stack 的零基序号，不可跨版本/跨游戏套用。",
        ],
    }
    (output / "报告索引.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    notes = [
        "原作 HCB 逐句函数调用表", "",
        f"源文件：{table.document.path}", f"SHA256：{table.sha256}",
        f"台词调用位置：{counts['dialogue_calls']}；解出文本：{counts['literal_text']}；未解出：{counts['unresolved_text']}",
        f"含台词的脚本函数：{counts['dialogue_functions']}；台词区间直接调用：{counts['direct_calls_in_dialogue_spans']}",
        f"汉化文本对照：{counts['translation_matches']}；读取失败：{len(failures)}",
        "", "先打开「先看这个_逐句示例.txt」。完整易读版在「按脚本函数分组」内。",
        "「逐句调用表.jsonl」每行对应一个台词调用位置。",
        "「函数内部调用.jsonl」可按 target/address 继续查询间接调用。",
        "脚本函数的 calls 不重复存储：查逐句表，并接上 tail_calls_after_last_dialogue。",
        "语音原始参数通常在说话人调用中；不拼造音频名，不按文件名猜话者。",
        "", "边界说明：", *("  - " + x for x in manifest["limitations"]),
        "", "全文分组（源码顺序，不是章节标题/游玩顺序）：",
        *(f"  {x['function']} @0x{x['address']:X} | {x['line_count']} 句 | {x['file']}" for x in section_index),
    ]
    (output / "说明与目录.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="只读导出原作 HCB 的逐句函数调用表；不执行/修改游戏。")
    parser.add_argument("--hcb", type=Path, required=True)
    parser.add_argument("--encoding", default="cp932")
    parser.add_argument("--output", type=Path, required=True, help="游戏目录之外的新目录；不得覆盖")
    parser.add_argument("--translation-hcb", type=Path)
    parser.add_argument("--translation-encoding", default="gb18030")
    address = lambda text: int(text, 0)
    parser.add_argument("--print-target", type=address)
    parser.add_argument("--wait-target", type=address)
    parser.add_argument("--print-includes-wait", action="store_true")
    parser.add_argument("--sample-function", type=address)
    parser.add_argument("--sample-start", type=int, default=1)
    parser.add_argument("--sample-count", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        table = OriginalCallTable(load(args.hcb, args.encoding), print_target=args.print_target,
                                  wait_target=args.wait_target,
                                  print_includes_wait=args.print_includes_wait)
        result = export_table(
            table, args.output, translation_path=args.translation_hcb,
            translation_encoding=args.translation_encoding, sample_function=args.sample_function,
            sample_start=args.sample_start, sample_count=args.sample_count,
        )
    except (HcbError, OSError, ValueError) as exc:
        parser.exit(2, f"无法生成调用表：{exc}\n")
    print(json.dumps({"output": str(args.output.resolve()), "counts": result["counts"],
                      "source_sha256": result["source_sha256"], "runtime_executed": False},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
