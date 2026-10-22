"""Bounded native menu table-cell snapshots, without copying table references.

Only source-proven finite integer write keys qualify. Reads outside that set
stay untouched. Native table stores consume (key, value), in that order on the
operand stack; restoring cells before their original container also preserves
an originally Nil/scalar global. Sparse absent/Nil keys are lookup-equivalent,
not a claim of restoring native allocator or sparse-container internals.
"""
from collections import deque
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _push_global, _pop_global
from .portrait_emitter import _encode_push


UNKNOWN = object()


@dataclass(frozen=True)
class Integer:
    low: int
    high: int
    origin: int | None = None


@dataclass(frozen=True)
class Constant:
    value: object


@dataclass(frozen=True)
class Condition:
    slot: int
    value: Integer
    operator: str
    constant: int


def integer(low, high, origin=None):
    if not -(2**31) <= low <= high < 2**31 or high-low > 256:
        return UNKNOWN
    return Integer(low, high, origin)


def strip(value):
    return Integer(value.low, value.high) if isinstance(value, Integer) else value


def join(left, right):
    if left == right:
        return left
    if isinstance(left, Integer) and isinstance(right, Integer):
        return integer(min(left.low, right.low), max(left.high, right.high),
                       left.origin if left.origin == right.origin else None)
    if (isinstance(left, Condition) and isinstance(right, Condition)
            and (left.slot, left.operator, left.constant) == (right.slot, right.operator, right.constant)):
        combined = join(left.value, right.value)
        if isinstance(combined, Integer):
            return Condition(left.slot, combined, left.operator, left.constant)
    return UNKNOWN


def narrow(value, operator, constant, truth):
    if not truth:
        operator = {"set_e": "set_ne", "set_ne": "set_e", "set_g": "set_le",
                    "set_ge": "set_l", "set_l": "set_ge", "set_le": "set_g"}[operator]
    low, high = value.low, value.high
    if operator == "set_e":
        low, high = max(low, constant), min(high, constant)
    elif operator == "set_ne":
        if low == constant:
            low += 1
        if high == constant:
            high -= 1
    elif operator == "set_l":
        high = min(high, constant-1)
    elif operator == "set_le":
        high = min(high, constant)
    elif operator == "set_g":
        low = max(low, constant+1)
    else:
        low = max(low, constant)
    return None if low > high else integer(low, high)


def binary(name, left, right):
    if name.startswith("set_"):
        if isinstance(left, Integer) and isinstance(right, Integer):
            if right.low == right.high and left.origin is not None:
                return Condition(left.origin, left, name, right.low)
            if left.low == left.high and right.origin is not None:
                reverse = {"set_e": "set_e", "set_ne": "set_ne", "set_g": "set_l",
                           "set_ge": "set_le", "set_l": "set_g", "set_le": "set_ge"}
                return Condition(right.origin, right, reverse[name], left.low)
        if isinstance(left, Constant) and isinstance(right, Constant) and name in {"set_e", "set_ne"}:
            same = type(left.value) is type(right.value) and left.value == right.value
            return Constant(same if name == "set_e" else not same)
        return UNKNOWN
    if isinstance(left, Integer) and isinstance(right, Integer):
        if name == "add":
            return integer(left.low+right.low, left.high+right.high)
        if name == "sub":
            return integer(left.low-right.high, left.high-right.low)
        if name == "mul":
            values = [a*b for a in (left.low, left.high) for b in (right.low, right.high)]
            return integer(min(values), max(values))
    return UNKNOWN


def trace(document, entries, address, arguments):
    """Integer-range CFG fixpoint; calls never supply guessed return values."""
    span = entries[address]
    body = span.instructions
    offsets = {i.offset: n for n, i in enumerate(body)}
    frame = {i: UNKNOWN for i in range(span.locals)}
    frame.update({i-span.args-1: strip(v) for i, v in enumerate(arguments)})
    states, pending = {1: ((), frame)}, deque([1])
    writes, calls, visits = {}, {}, 0

    def enqueue(index, stack, slots):
        if not 1 <= index < len(body):
            raise ValueError("选项共享表的数据流越过原生函数。")
        prior = states.get(index)
        incoming = (tuple(stack), dict(slots))
        if prior is not None:
            if len(prior[0]) != len(stack):
                raise ValueError("选项共享表的原生分支栈不一致。")
            incoming = (tuple(join(a, b) for a, b in zip(prior[0], stack)),
                        {k: join(prior[1][k], slots[k]) for k in slots})
            if incoming == prior:
                return
        states[index] = incoming
        pending.append(index)

    while pending:
        visits += 1
        if visits > 100000:
            raise ValueError("选项共享表的数据流尚不能在限定范围收敛。")
        index = pending.popleft()
        stack, slots = states[index]
        stack, slots = list(stack), dict(slots)
        item = body[index]
        name, operands = item.mnemonic, item.operands

        def consume(count):
            if len(stack) < count:
                raise ValueError("选项共享表的原生参数栈不完整。")
            values = stack[-count:] if count else []
            if count:
                del stack[-count:]
            return values

        if name in {"push_i8", "push_i16", "push_i32"}:
            stack.append(integer(operands["value"], operands["value"]))
        elif name in {"push_nil", "push_true"}:
            stack.append(Constant(None if name == "push_nil" else True))
        elif name == "push_string":
            stack.append(Constant(item.text))
        elif name in {"push_global", "push_f32", "push_return"}:
            stack.append(UNKNOWN)
        elif name == "push_stack":
            value = slots[int(operands["value"])]
            stack.append(Integer(value.low, value.high, int(operands["value"]))
                         if isinstance(value, Integer) else value)
        elif name == "pop_stack":
            slot = int(operands["value"])
            if slot not in slots:
                raise ValueError("选项共享表使用了无效的原生帧变量。")
            slots[slot] = strip(consume(1)[0])
        elif name == "pop_global":
            consume(1)
        elif name == "push_top":
            stack.append(stack[-1])
        elif name in {"push_global_table", "push_local_table"}:
            consume(1)
            stack.append(UNKNOWN)
        elif name in {"pop_global_table", "pop_local_table"}:
            key, _value = consume(2)  # Verified native (key below value), not RFVP's old portable order.
            if name == "pop_global_table":
                prior = writes.get(item.offset)
                writes[item.offset] = strip(key) if prior is None else join(prior, strip(key))
            else:
                # A store can cast a former Nil local to a table. Never keep
                # that old Nil/number as a later branch fact.
                slots[int(operands["value"])] = UNKNOWN
        elif name == "neg":
            value = consume(1)[0]
            stack.append(integer(-value.high, -value.low) if isinstance(value, Integer) else UNKNOWN)
        elif name in {"add", "sub", "mul", "div", "mod", "bit_test", "and", "or",
                      "set_e", "set_ne", "set_l", "set_le", "set_g", "set_ge"}:
            stack.append(binary(name, *consume(2)))
        elif name in {"call", "syscall"}:
            if name == "call":
                target = int(operands["target"])
                argc = entries[target].args
            else:
                argc = document.header.syscalls[int(operands["id"])].args
            values = tuple(strip(v) for v in consume(argc))
            if name == "call":
                prior = calls.get(item.offset)
                calls[item.offset] = (target, values if prior is None else tuple(
                    join(a, b) for a, b in zip(prior[1], values)))
        elif name in {"jmp", "jz"}:
            target = int(operands["target"])
            if target not in offsets:
                raise ValueError("选项共享表的原生跳转越过函数。")
            if name == "jmp":
                enqueue(offsets[target], stack, slots)
                continue
            condition = consume(1)[0]
            for truth, successor in ((False, offsets[target]), (True, index+1)):
                branch_slots = dict(slots)
                if (isinstance(condition, Constant) and condition.value in (None, True, False)
                        and type(condition.value) in {type(None), bool}
                        and bool(condition.value) != truth):
                    continue
                if isinstance(condition, Integer) and condition.low == condition.high and bool(condition.low) != truth:
                    continue
                if (isinstance(condition, Condition) and strip(condition.value) == slots[condition.slot]
                        and index > 0 and body[index-1].mnemonic.startswith("set_")):
                    value = narrow(condition.value, condition.operator, condition.constant, truth)
                    if value is None:
                        continue
                    branch_slots[condition.slot] = value
                enqueue(successor, stack, branch_slots)
            continue
        elif name in {"ret", "retv"}:
            if name == "retv":
                consume(1)
            if stack:
                raise ValueError("选项共享表的原生返回留下了未消费的参数。")
            continue
        elif name != "nop":
            raise ValueError("选项共享表出现未接通的原生指令。")
        if len(stack) > 512:
            raise ValueError("选项共享表的原生参数栈超过限定范围。")
        enqueue(index+1, stack, slots)
    return writes, calls


def compile_table_snapshot(document, entries, closure, roots):
    """Append cell pairs to scalar snapshots; restore cells BEFORE containers."""
    table_sites = {i.offset: (a, int(i.operands["value"])) for a in closure.dependencies
                   for i in entries[a].instructions if i.mnemonic == "pop_global_table"}
    scalar = closure.compile_snapshot(document)
    if not table_sites:
        result = dict(**scalar, table_report=dict(mode="no_native_table_writes", tables=[]))
        return compact_snapshot(result, document, closure.global_ids, {})
    tables = {slot for _a, slot in table_sites.values()}
    total_globals = document.header.non_volatile_globals+document.header.volatile_globals
    if any(not 0 <= slot < total_globals for slot in tables):
        raise ValueError("选项共享表越过原生脚本声明的变量范围。")
    # Whole-container aliases/replacements and writes through borrowed local
    # tables need a different ownership proof. Do not pretend cell snapshots
    # can undo nested-reference mutation or a callee swapping the container.
    for a in closure.dependencies:
        span = entries[a]
        for n, item in enumerate(span.instructions):
            if item.mnemonic in {"push_global", "pop_global"} and item.operands["value"] in tables:
                raise ValueError("选项共享表有整表替换或别名，暂不能恢复。")
            if item.mnemonic == "pop_local_table":
                base = item.operands["value"]
                assigned = [p for p, x in enumerate(span.instructions)
                            if x.mnemonic == "pop_stack" and x.operands["value"] == base]
                if base < 0 or any(p == 0 or span.instructions[p-1].mnemonic != "push_nil" for p in assigned):
                    raise ValueError("选项共享表可能通过借用的局部表改写，暂不能恢复。")
    # Trace only writers and their ancestors. Unrelated text/resource callees
    # still have exact-byte closure checks but cannot furnish guessed integers.
    relevant = {a for a, _slot in table_sites.values()}
    while True:
        ancestors = {a for a in closure.dependencies if set(entries[a].calls) & relevant}
        if ancestors <= relevant:
            break
        relevant.update(ancestors)
    inputs, pending = {}, deque()

    def schedule(address, values):
        if address not in relevant:
            return
        prior = inputs.get(address)
        incoming = values if prior is None else tuple(join(a, b) for a, b in zip(prior, values))
        if prior == incoming:
            return
        inputs[address] = incoming
        pending.append(address)

    # Also inspect zero-argument lifecycle entry points in the audited closure.
    # This is a deliberate overapproximation: a native worker may dispatch a
    # zero-argument callback from its UI state instead of our selected caller.
    # It neither executes those functions nor assumes a nonzero-argument key.
    range_roots = set(roots) | {a for a in relevant if entries[a].args == 0}
    for a in range_roots:
        schedule(a, (UNKNOWN,)*entries[a].args)
    proven, function_count = {}, 0
    while pending:
        function_count += 1
        if function_count > 2048:
            raise ValueError("选项共享表的原生调用范围尚不能收敛。")
        a = pending.popleft()
        writes, calls = trace(document, entries, a, inputs[a])
        for site, value in writes.items():
            proven[site] = value
        for _site, (called, values) in calls.items():
            schedule(called, values)
    if set(table_sites) - proven.keys():
        raise ValueError("选项共享表还有未覆盖的原生写入位置。")
    keys, evidence = {}, []
    for site, value in sorted(proven.items()):
        owner, slot = table_sites[site]
        if not isinstance(value, Integer) or value.low < 0 or value.high-value.low >= 64:
            raise ValueError("选项共享表的写入位置尚不能确定有限范围。")
        keys.setdefault(slot, set()).update(range(value.low, value.high+1))
        evidence.append(dict(function=owner, offset=site, global_id=slot,
                             minimum_key=value.low, maximum_key=value.high))
    if not keys or len(keys) > 16 or any(len(values) > 64 for values in keys.values()):
        raise ValueError("选项共享表的快照超出限定范围。")
    snapshot = bytearray(scalar["snapshot"])
    restore = bytearray()
    for slot, values in sorted(keys.items()):
        snapshot.extend(_push_global(slot))
        for key in sorted(values):
            encoded = _encode_push(key, document.encoding)
            snapshot.extend(encoded+encoded+b"\x11"+struct.pack("<H", slot))
    for slot, values in reversed(sorted(keys.items())):
        restore.extend((b"\x17"+struct.pack("<H", slot))*len(values))
        restore.extend(_pop_global(slot))
    restore.extend(scalar["restore"])
    count = len(closure.global_ids)+sum(1+2*len(v) for v in keys.values())
    result = dict(snapshot=bytes(snapshot), restore=bytes(restore), report=dict(
        **{k: v for k, v in scalar["report"].items() if k not in {"operand_stack_value_count", "code_sha256"}},
        operand_stack_value_count=count, includes_native_table_cells=True,
        native_table_store_order="key_then_value"), table_report=dict(
            mode="source_proven_finite_write_keys", tables=[dict(global_id=g, keys=sorted(v))
                                                          for g, v in sorted(keys.items())],
            write_key_evidence=evidence, scalar_callee_returns_assumed=False,
            zero_argument_lifecycle_overapproximation=True,
            original_container_restored_after_cells=True,
            sparse_nil_keys_lookup_equivalent=True, sparse_allocation_layout_restored=False,
            nested_table_aliases_supported=False, runtime_verified=False))
    return compact_snapshot(result, document, closure.global_ids, keys)


def compact_snapshot(snapshot, document, scalar_globals, tables):
    """A large native closure must not overflow FVP's 256-cell thread stack."""
    # Leave room for the original caller, native menu frames and owned scene
    # state. A 123-cell legacy snapshot is already too costly for combinations.
    if snapshot["report"]["operand_stack_value_count"] <= 64:
        snapshot["report"]["storage"] = "bounded_operand_stack"
        return snapshot
    # Use one scene-local table VALUE, not a new script global. Native function
    # frames hold the builder in local 0; returning it leaves just one operand
    # across the native menu call. Original values (including references) stay
    # alive in that table until selected-route restoration consumes it.
    fields = [("global", slot, None) for slot in scalar_globals]
    fields.extend(("container", slot, None) for slot in sorted(tables))
    fields.extend(("cell", slot, key) for slot, keys in sorted(tables.items()) for key in sorted(keys))
    if len(fields) > 8192:
        raise ValueError("选项状态备份超出限定范围。")
    save = bytearray(b"\x01\0\x01")
    indices = {}
    for index, (kind, slot, key) in enumerate(fields):
        indices[(kind, slot, key)] = index
        save.extend(_encode_push(index, document.encoding))
        if kind == "cell":
            save.extend(_encode_push(key, document.encoding)+b"\x11"+struct.pack("<H", slot))
        else:
            save.extend(_push_global(slot))
        save.extend(b"\x18\0")
    save.extend(b"\x10\0\x05")  # Return the new local table, never a guessed callee value.
    restore = bytearray(b"\x01\x01\0")

    def field(kind, slot, key):
        return _encode_push(indices[(kind, slot, key)], document.encoding)+b"\x12\xfe"

    for slot, keys in reversed(sorted(tables.items())):
        for key in reversed(sorted(keys)):
            restore.extend(_encode_push(key, document.encoding)+field("cell", slot, key)
                           +b"\x17"+struct.pack("<H", slot))
        restore.extend(field("container", slot, None)+_pop_global(slot))
    for slot in reversed(scalar_globals):
        restore.extend(field("global", slot, None)+_pop_global(slot))
    restore.extend(b"\x04")
    snapshot.update(snapshot=b"", restore=b"", helper_programs=(bytes(save), bytes(restore)))
    snapshot["report"].update(storage="scene_local_vm_table", operand_stack_value_count=1,
        stored_value_count=len(fields), requires_scene_local_helpers=True,
        additional_script_globals=0, native_stack_cells=256,
        helper_body_sha256=[hashlib.sha256(x).hexdigest() for x in (save, restore)])
    return snapshot


def install_snapshot_helpers(snapshot, document, output):
    """Append jump-skipped native-VM helpers without changing the source image."""
    programs = snapshot.get("helper_programs")
    if programs is None:
        return
    if snapshot.get("helper_entries"):
        raise ValueError("选项状态备份已绑定到另一处场景代码。")
    save = len(document.original_bytes)+len(output)+5
    restore = save+len(programs[0])
    end = restore+len(programs[1])
    if end >= 2**31:
        raise ValueError("选项状态备份函数地址超出原生范围。")
    output.extend(b"\x06"+struct.pack("<I", end)+b"".join(programs))
    snapshot.update(snapshot=b"\x02"+struct.pack("<I", save)+b"\x14",
                    restore=b"\x02"+struct.pack("<I", restore), helper_entries=(save, restore))
    snapshot["report"].update(helper_entries=[save, restore])
