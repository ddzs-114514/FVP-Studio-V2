"""Source-bound Graph/Parts handle flow for a native portrait carrier.

Different resource strings or primitive IDs alone do not reserve Parts slots.
This extractor follows actual dispatcher operands, including both buffer arms,
the sprite binding helper, and dominating writes used by PartsAssign/Select.
It is read-only evidence, not a renderer or permission to write a game script.
"""
from __future__ import annotations

from collections import Counter
from itertools import product
from typing import Any, Mapping

from .hcb import HcbDocument
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import NativePortraitAcceptanceError
from .native_portrait_carriers import carrier_layout


SCHEMA = "fvp-native-portrait-dispatcher-handles/1"


def _integer_values(value: Mapping[str, Any]) -> frozenset[int]:
    """Evaluate only bounded, exact integer handle expressions; never globals."""
    kind = value.get("kind")
    if kind == "literal" and value.get("type") == "int" and type(value.get("value")) is int:
        result = {value["value"]}
    elif kind == "choice":
        children = value.get("operands", ())
        if not children or len(children) > 16:
            raise NativePortraitAcceptanceError("原生资源槽的分支范围无法确定。")
        result = set().union(*(_integer_values(x) for x in children))
    elif kind in {"add", "sub"}:
        children = value.get("operands", ())
        if len(children) != 2:
            raise NativePortraitAcceptanceError("原生资源槽算式未闭合。")
        left, right = (_integer_values(x) for x in children)
        result = {a + b if kind == "add" else a - b for a, b in product(left, right)}
    else:
        raise NativePortraitAcceptanceError("资源槽取决于未证明的全局变量、参数或调用返回值。")
    if not result or len(result) > 16 or any(not -2147483648 <= x <= 2147483647 for x in result):
        raise NativePortraitAcceptanceError("原生资源槽算式超出有界整数范围。")
    return frozenset(result)


def _substitute(value, expression, replacement):
    if value == expression:
        return dict(kind="literal", type="int", value=replacement)
    if value.get("kind") in {"add", "sub", "choice"}:
        return dict(value, operands=[_substitute(x, expression, replacement)
                                   for x in value.get("operands", ())])
    return value


def _buffer_mapping(primitive_expression, graph_expression, primitives):
    """Keep arm correlation; sorting two independent sets is not a mapping."""
    result = []
    for primitive in primitives:
        values = _integer_values(_substitute(graph_expression, primitive_expression, primitive))
        if len(values) != 1:
            raise NativePortraitAcceptanceError("图元与资源槽的双缓冲对应关系未确定。")
        result.append(dict(primitive=primitive, graph=next(iter(values)), parts=next(iter(values))))
    if len({x["graph"] for x in result}) != len(result):
        raise NativePortraitAcceptanceError("双缓冲图元共用同一资源槽。")
    return result


def _dominates(body, write_offset: int, read_offset: int) -> bool:
    """A read is unreachable from the function entry when its write is removed."""
    by_offset = {x.offset: i for i, x in enumerate(body)}
    if write_offset not in by_offset or read_offset not in by_offset:
        return False
    pending, visited = [0], set()
    while pending:
        index = pending.pop()
        if index in visited or not 0 <= index < len(body):
            continue
        visited.add(index)
        item = body[index]
        if item.offset == read_offset:
            return False
        if item.offset == write_offset or item.mnemonic in {"ret", "retv"}:
            continue
        if item.mnemonic in {"jmp", "jz"}:
            target = by_offset.get(item.operands["target"])
            if target is None:
                return False
            pending.append(target)
            if item.mnemonic == "jmp":
                continue
        pending.append(index + 1)
    return True


def _resolve_handle(value, trace, body, document):
    """Use a dominating same-function write, without assuming callee effects."""
    if value.get("kind") != "global_read":
        return value, set(), []
    slot, offset = int(value["slot"]), int(value["offset"])
    reads = [x for x in body if x.offset == offset]
    if (len(reads) != 1 or reads[0].mnemonic != "push_global"
            or reads[0].operands["value"] != slot):
        raise NativePortraitAcceptanceError("资源槽全局读取不是当前函数的原生指令。")
    writers = [x for x in trace["global_writes"] if int(x["slot"]) == slot and int(x["offset"]) < offset]
    if len(writers) != 1 or not _dominates(body, int(writers[0]["offset"]), offset):
        raise NativePortraitAcceptanceError("资源槽读取没有唯一、必经的原生赋值。")
    writer = writers[0]
    for item in body:
        if not int(writer["offset"]) < item.offset < offset:
            continue
        if item.mnemonic == "call":
            raise NativePortraitAcceptanceError("资源槽赋值后经过未展开的函数调用。")
        if item.mnemonic == "syscall" and document.syscall_names[item.operands["id"]] not in {"PartsAssign", "PartsSelect"}:
            raise NativePortraitAcceptanceError("资源槽赋值后经过未审核的系统调用。")
        if item.mnemonic == "pop_global" and item.operands["value"] == slot:
            raise NativePortraitAcceptanceError("资源槽读取前存在另一处赋值。")
    _integer_values(writer["value"])
    return writer["value"], {slot}, [dict(global_id=slot, write_offset=int(writer["offset"]),
                                        read_offset=offset, dominating_write=True)]


def _sprite_helpers(document, source, flow, trace, primitive_expression, graph_expression):
    results, dependencies = [], {}
    for call in trace["calls"]:
        if call["kind"] == "syscall" and call.get("name") == "PrimSetSprt":
            if call["argument_count"] == 4 and call["arguments"][:2] == [primitive_expression, graph_expression]:
                results.append(dict(offset=call["offset"], strategy="direct_native_syscall"))
            continue
        if call["kind"] != "call":
            continue
        address = int(call["address"])
        first, end = flow.entries[address]
        body = document.instructions[first:end]
        syscall_counts = Counter(document.syscall_names[x.operands["id"]] for x in body if x.mnemonic == "syscall")
        if syscall_counts.get("PrimSetSprt", 0) == 0:
            continue
        if (body[0].operands["args"] != 4 or syscall_counts != Counter(FloatToInt=2, PrimSetSprt=1)
                or any(x.mnemonic == "call" for x in body)):
            raise NativePortraitAcceptanceError("立绘 sprite 绑定不是已识别的纯原生包装层。")
        helper = flow.trace(address)
        sprite = [x for x in helper["calls"] if x.get("name") == "PrimSetSprt"]
        if (helper["status"] != "proven_static_argument_flow" or helper["global_writes"]
                or len(sprite) != 1 or sprite[0]["argument_count"] != 4
                or sprite[0]["arguments"][:2] != [{"kind": "argument", "index": 0}, {"kind": "argument", "index": 1}]
                or call["arguments"][:2] != [primitive_expression, graph_expression]):
            raise NativePortraitAcceptanceError("立绘 sprite 的图元／身体槽参数流未闭合。")
        last = body[-1].offset + body[-1].size
        raw = document.original_bytes[address:last]
        if source.original_bytes[address:last] != raw:
            raise NativePortraitAcceptanceError("运行／分析脚本的 sprite 包装函数已漂移。")
        dependencies[address] = (last, raw)
        results.append(dict(offset=call["offset"], strategy="exact_native_sprite_helper",
                            helper_address=address, syscall_offset=sprite[0]["offset"]))
    if len(results) != 1:
        raise NativePortraitAcceptanceError("身体图元与 Graph 槽没有唯一的原生绑定。")
    return results[0], dependencies


def extract_dispatcher_handles(source: HcbDocument, analysis: HcbDocument, dispatcher_record,
                               *, selector: int, primitive_ids: tuple[int, int],
                               action_code: int, outfit_code: int, flow=None):
    """Prove one patched-resource carrier; form/expression remain unrestricted.

    Only the chosen native action/outfit carrier is specialised. Imported
    resource literals are changed later in a separate compiler. Both primitive
    buffer arms, all remaining arguments and all global conditions are retained.
    """
    start, end, argc = (int(dispatcher_record[x]) for x in ("start", "end", "args"))
    layout = carrier_layout(argc)
    if source.original_bytes[start:end] != analysis.original_bytes[start:end]:
        raise NativePortraitAcceptanceError("立绘资源槽证据与运行 dispatcher 字节不一致。")
    if [(x.name, x.args) for x in source.header.syscalls] != [(x.name, x.args) for x in analysis.header.syscalls]:
        raise NativePortraitAcceptanceError("立绘资源槽的系统调用表已漂移。")
    flow = flow or NativeFunctionFlow(analysis)
    if flow.document is not analysis or start not in flow.entries:
        raise NativePortraitAcceptanceError("立绘参数流属于另一份脚本。")
    first, last = flow.entries[start]
    body = analysis.instructions[first:last]
    if (not body or body[0].operands["args"] != argc
            or body[-1].offset + body[-1].size != end):
        raise NativePortraitAcceptanceError("立绘资源槽范围不是完整的原生函数。")
    literals = {layout.selector + argc + 1: selector, layout.action + argc + 1: action_code,
                layout.outfit + argc + 1: outfit_code}
    if argc == 14:
        # The optional _ru overlay needs an additional resource, sprite and
        # cleanup contract. Prove the plain import carrier with that native
        # field explicitly off; do not ignore a reachable second GraphLoad.
        literals[13] = 0
    trace = flow.trace(start, literal_arguments=literals, max_instructions=16384, max_joined_values=64)
    if trace["status"] != "proven_static_argument_flow":
        raise NativePortraitAcceptanceError("立绘资源槽参数流未确定：" + ", ".join(trace["blockers"]))
    calls = {}
    for name in ("GraphLoad", "PartsLoad", "PartsAssign", "PartsSelect"):
        matches = [x for x in trace["calls"] if x.get("name") == name]
        if len(matches) != 1 or matches[0]["argument_count"] != 2:
            raise NativePortraitAcceptanceError("立绘加载链未唯一匹配：" + name)
        calls[name] = matches[0]
    graph_expression = calls["GraphLoad"]["arguments"][0]
    parts_expression = calls["PartsLoad"]["arguments"][0]
    graph_ids = _integer_values(graph_expression)
    parts_ids = _integer_values(parts_expression)
    if (graph_expression != parts_expression or len(graph_ids) != 2 or any(x < 0 for x in graph_ids)):
        raise NativePortraitAcceptanceError("身体和表情未绑定同一组原生双缓冲资源槽。")
    total_globals = analysis.header.non_volatile_globals + analysis.header.volatile_globals
    binding_globals, reads = set(), []
    for name, position in (("PartsAssign", 0), ("PartsAssign", 1), ("PartsSelect", 0)):
        resolved, globals_, sites = _resolve_handle(calls[name]["arguments"][position], trace, body, analysis)
        if resolved != graph_expression:
            raise NativePortraitAcceptanceError(name + " 使用的资源槽与原生加载槽不同。")
        binding_globals.update(globals_)
        reads.extend(sites)
    if any(not 0 <= x < total_globals for x in binding_globals):
        raise NativePortraitAcceptanceError("资源槽状态变量超出目标声明。")
    # Locate the actual primitive expression from a sprite call. Its set must
    # match the selector branch, while its Graph expression must be identical
    # to GraphLoad's expression (not merely an equal set that could swap arms).
    primitive_expressions = []
    for call in trace["calls"]:
        if call["argument_count"] != 4:
            continue
        if call["kind"] == "syscall" and call.get("name") != "PrimSetSprt":
            continue
        if call["arguments"][1] != graph_expression:
            continue
        try:
            if _integer_values(call["arguments"][0]) == frozenset(primitive_ids):
                primitive_expressions.append(call["arguments"][0])
        except NativePortraitAcceptanceError:
            pass
    unique = {repr(x): x for x in primitive_expressions}
    if len(unique) != 1:
        raise NativePortraitAcceptanceError("原生 sprite 的图元表达式未确定。")
    sprite, dependencies = _sprite_helpers(analysis, source, flow, trace, next(iter(unique.values())), graph_expression)
    buffer_mapping = _buffer_mapping(next(iter(unique.values())), graph_expression, primitive_ids)
    report = dict(schema=SCHEMA, selector=selector, dispatcher=start,
        source_sha256=source.source_sha256, analysis_sha256=analysis.source_sha256,
        carrier_literal_arguments=literals, form_and_expression_specialized=False,
        optional_auxiliary_layer_disabled=argc == 14,
        auxiliary_layer_argument_index=13 if argc == 14 else None,
        primitive_ids=list(primitive_ids), graph_ids=sorted(graph_ids), parts_ids=sorted(parts_ids),
        buffers=buffer_mapping,
        binding_global_ids=sorted(binding_globals), dominating_global_reads=reads,
        load_offsets={name: call["offset"] for name, call in calls.items()}, sprite_binding=sprite,
        dispatcher_global_write_ids=sorted({int(x["slot"]) for x in trace["global_writes"]}),
        scope="carrier_dispatcher_and_exact_sprite_binding",
        dispatcher_handles_verified=True, lifecycle_side_effects_verified=False,
        callee_side_effects_expanded=False, hcb_rendering_ready=False,
        runtime_verified=False, writes_performed=False, game_name_switch_used=False)
    return report, dependencies


def handles_conflict(left, right):
    """Graph and Parts are distinct namespaces; check each, not their union."""
    return (bool(set(left["graph_ids"]) & set(right["graph_ids"]))
            or bool(set(left["parts_ids"]) & set(right["parts_ids"])))
