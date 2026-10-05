"""Native-entry CFG evidence for selecting a rehearsal dialogue hook.

Do not rank dialogue by its wording, face size, game title or number of lines.
Follow real CALL/JMP/ThreadStart addresses. Prune only exact Nil/bool/integer
comparisons against a global with ONE script writer: a literal assignment in
the entry's unconditional prefix. Unknown branches remain reachable; native
runtime/load effects are not simulated and still require in-game acceptance.
"""
from __future__ import annotations

from collections import defaultdict

from .hcb import HcbError
from .native_call_flow import _constant_operator, _literal


def _value(instruction):
    if instruction.mnemonic == "push_nil":
        return True, None
    if instruction.mnemonic == "push_true":
        return True, True
    if instruction.mnemonic in {"push_i8", "push_i16", "push_i32"}:
        return True, instruction.operands["value"]
    return False, None


def reachable_native_instructions(document, runtime_document=None):
    instructions = document.instructions
    indexes = {item.offset: index for index, item in enumerate(instructions)}
    entry = indexes.get(document.header.entry_point)
    if entry is None or instructions[entry].mnemonic != "init_stack":
        raise HcbError("原生入口不是已解析的函数边界")
    runtime = runtime_document or document
    if runtime.header.entry_point != document.header.entry_point:
        raise HcbError("运行脚本与分析脚本的原生入口不同")
    def unchanged(item):
        if runtime.original_bytes[item.offset:item.offset+item.size] != item.raw:
            raise HcbError("运行脚本的原生入口控制指令与分析证据不同")
    writers = defaultdict(list)
    for index, item in enumerate(instructions):
        if item.mnemonic in {"pop_global", "pop_global_table"}:
            writers[item.operands["value"]].append(index)
    prefix_end = entry + 1
    while prefix_end < len(instructions) and instructions[prefix_end].mnemonic not in {
            "init_stack", "call", "syscall", "jmp", "jz", "ret", "retv"}:
        prefix_end += 1
    constants, initializers = {}, []
    for slot, sites in writers.items():
        if len(sites) != 1 or not entry < sites[0] < prefix_end:
            continue
        index = sites[0]
        valid, value = _value(instructions[index-1])
        if valid and instructions[index].mnemonic == "pop_global":
            unchanged(instructions[index-1])
            unchanged(instructions[index])
            constants[slot] = value
            initializers.append(dict(slot=slot, value=value, assignment_offset=instructions[index].offset,
                                     writer_count=1, unconditional_entry_prefix=True))

    def branch(index):
        if index < 3:
            return None
        a, b, operation = instructions[index-3:index]
        if (a.mnemonic != "push_global" or a.operands["value"] not in constants
                or operation.mnemonic not in {"set_e", "set_ne"}):
            return None
        valid, value = _value(b)
        if not valid:
            return None
        evaluated = _constant_operator(operation.mnemonic,
            (_literal(constants[a.operands["value"]]), _literal(value)))
        for item in (a, b, operation):
            unchanged(item)
        return evaluated.data[1] if evaluated.kind == "literal" and type(evaluated.data[1]) is bool else None

    # Offset-level reachability handles loops without executing them. CALL
    # continuations remain reachable; callee effects/returns are not guessed.
    pending, visited, decisions = [entry], set(), {}
    while pending:
        index = pending.pop()
        if index in visited or not 0 <= index < len(instructions):
            continue
        visited.add(index)
        item = instructions[index]
        if item.mnemonic in {"init_stack", "call", "jmp", "jz", "ret", "retv"} or item.address_role:
            unchanged(item)
        if item.warning:
            raise HcbError("原生入口控制流含未解析指令")
        if item.mnemonic in {"ret", "retv"}:
            continue
        if item.mnemonic in {"jmp", "jz"}:
            target = indexes.get(item.operands["target"])
            if target is None:
                raise HcbError("原生入口控制流跳转不是指令边界")
            if item.mnemonic == "jmp":
                pending.append(target)
                continue
            condition = branch(index)
            if condition is not None:
                pending.append(index+1 if condition else target)
                decisions[item.offset] = dict(offset=item.offset, condition=condition,
                    selected_target=instructions[index+1].offset if condition else item.operands["target"])
                continue
            pending.append(target)
        if item.mnemonic == "call":
            target = indexes.get(item.operands["target"])
            if target is None or instructions[target].mnemonic != "init_stack":
                raise HcbError("原生入口控制流 CALL 不是函数边界")
            pending.append(target)
        if item.address_role == "thread_start_function_pointer":
            target = indexes.get(item.operands["value"])
            if target is None or instructions[target].mnemonic != "init_stack":
                raise HcbError("原生线程入口不是函数边界")
            pending.append(target)
        if index+1 < len(instructions) and instructions[index+1].mnemonic != "init_stack":
            pending.append(index+1)
    return frozenset(instructions[index].offset for index in visited), dict(
        entry_point=document.header.entry_point, mode="native_entry_cfg_with_unique_initializers",
        reachable_instruction_count=len(visited), initializers=initializers,
        known_branch_decisions=list(decisions.values()), unknown_branches_followed=True,
        native_runtime_effects_verified=False, runtime_verified=False, writes_performed=False)
