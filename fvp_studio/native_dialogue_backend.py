"""Discover the five-argument FVP printer that already waits for a click.

Bind the complete source wrapper, its forwarded four text arguments, the Nil
fifth-argument branch, and its native input-polling wait. Never substitute an
arbitrary post-print callback for the click wait seen inside that wrapper.
"""
from collections import Counter

from .native_call_flow import NativeFunctionFlow


def _contains_text_argument(value):
    if value == {"kind":"argument", "index":0}:
        return True
    return any(_contains_text_argument(item) for item in value.get("operands", []))


def _native_text_handoff(document, core, regions, flow):
    """A native text worker can consume a producer's shared string slot."""
    producer = flow.trace(core.start)
    if producer["status"] != "proven_static_argument_flow":
        return []
    slots = {write["slot"] for write in producer["global_writes"]
             if _contains_text_argument(write["value"])}
    consumers = []
    for region in regions:
        if "TextPrint" not in region.syscalls:
            continue
        body = document.instructions[region.instruction_start_index:region.instruction_end_index]
        for index, item in enumerate(body):
            if index < 2 or item.mnemonic != "syscall":
                continue
            syscall = document.header.syscalls[item.operands["id"]]
            layer, string = body[index-2:index]
            if (syscall.name == "TextPrint" and syscall.args == 2
                    and string.mnemonic == "push_global" and string.operands["value"] in slots
                    and layer.mnemonic in {"push_i8", "push_i16", "push_i32"}
                    and layer.operands["value"] >= 0):
                consumers.append(dict(function=region.start, syscall_offset=item.offset,
                                      text_global=string.operands["value"], producer=core.start))
    return consumers


def discover_internal_wait_printer(document, regions):
    by_start = {r.start:r for r in regions}
    indexes = {r.start:i for i,r in enumerate(regions)}
    flow = NativeFunctionFlow(document)
    instructions = document.instructions
    motifs = Counter()
    for index, item in enumerate(instructions[:-5]):
        if item.opcode == 0x0E and tuple(x.opcode for x in instructions[index+1:index+6]) == (8,8,8,8,2):
            motifs[instructions[index+5].operands["target"]] += 1
    candidates = []
    for region in regions:
        if region.args != 5 or region.locals != 0 or motifs[region.start] < 8:
            continue
        body = instructions[region.instruction_start_index:region.instruction_end_index]
        opcodes = tuple(x.opcode for x in body)
        if opcodes not in {(1,16,16,16,16,2,16,12,34,7,2,2,4),
                           (1,16,16,16,16,2,16,12,34,7,2,2,4,4)}:
            continue
        if (body[7].operands.get("value") != -1 or body[9].operands["target"] != body[11].offset
                or [x.operands.get("value") for x in body[1:5]] != [-6,-5,-4,-3]
                or body[6].operands.get("value") != -2):
            continue
        core, wait = by_start.get(body[5].operands["target"]), by_start.get(body[11].operands["target"])
        if (core is None or wait is None or core.args != 4
                or indexes[core.start] != indexes[region.start]-1
                or wait.args != 0 or wait.locals != 0 or wait.instruction_count != 4
                or wait.syscalls or len(wait.call_targets) != 1
                or indexes.get(wait.call_targets[0]) != indexes[wait.start]-2):
            continue
        implementation = by_start[wait.call_targets[0]]
        if not ({"InputGetState", "ThreadNext"}.issubset(implementation.syscalls)
                and any(x in implementation.syscalls for x in ("InputGetUp", "InputGetDown"))):
            continue
        # The text argument is forwarded unchanged into the preceding native
        # text function. Its dependency graph must actually reach text output.
        pending, seen, text_syscalls = [(core.start, 0)], set(), set()
        while pending:
            address, depth = pending.pop()
            if address in seen or address not in by_start or depth > 5:
                continue
            seen.add(address)
            callee = by_start[address]
            text_syscalls.update(callee.syscalls)
            pending.extend((x, depth+1) for x in callee.call_targets)
        text_handoff = []
        if not {"TextPrint", "TextBuff"}.intersection(text_syscalls):
            text_handoff = _native_text_handoff(document, core, regions, flow)
        if not {"TextPrint", "TextBuff"}.intersection(text_syscalls) and not text_handoff:
            continue
        specialized = flow.trace(region.start, literal_arguments={4:None})
        calls = specialized.get("calls", [])
        if (specialized["status"] != "proven_static_argument_flow" or len(calls) != 2
                or [c.get("address") for c in calls] != [core.start, wait.start]
                or calls[0]["arguments"] != [{"kind":"argument", "index":i} for i in range(4)]
                or calls[1]["arguments"] or specialized["global_writes"]):
            continue
        candidates.append(dict(print=region.public(), wait=wait.public(), print_includes_wait=True,
            print_argument_count=5, motif_nil_count=4, motif_count=motifs[region.start],
            discovery_mode="native_print_internal_click_wait", core=core.public(),
            wait_implementation=implementation.public(), nil_fifth_argument_flow=specialized,
            text_global_handoff=text_handoff,
            evidence=["exact_five_argument_forwarding_wrapper", "nil_flag_skips_optional_callback",
                      "native_input_polling_click_wait_inside_print", "repeated_string_nil4_print_calls"]))
    selected = candidates[0] if len(candidates) == 1 else None
    return dict(status="candidate_unique_relation" if selected else "ambiguous",
                pairs=candidates, selected=selected, warning="原生打印内部已等待点击，不再额外等待" if selected else "")


def validate_internal_wait_source(runtime, analysis, selected):
    """Bind the discovered print/wait dependency closure to runtime bytes."""
    from .hcb import HcbError
    from .native_target_discovery import _function_regions

    regions = {region.start:region for region in _function_regions(analysis)}
    pending = [selected["print"]["start"], selected["wait"]["start"]]
    pending.extend(item["function"] for item in selected.get("text_global_handoff", []))
    seen = set()
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        region = regions.get(address)
        if region is None:
            raise HcbError("原生打印/等待依赖不是函数边界")
        seen.add(address)
        if runtime.original_bytes[region.start:region.end] != analysis.original_bytes[region.start:region.end]:
            raise HcbError("运行脚本的打印/等待调用链与分析证据不同")
        pending.extend(region.call_targets)
        for instruction in analysis.instructions[region.instruction_start_index:region.instruction_end_index]:
            if instruction.address_role == "thread_start_function_pointer":
                pending.append(instruction.operands["value"])
    return dict(mode="exact_native_print_wait_dependency_bytes", function_count=len(seen),
                print_includes_wait=True, runtime_verified=False)
