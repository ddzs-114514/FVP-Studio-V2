"""Bounded, read-only argument flow for native FVP functions.

This is not an engine emulator.  Forward control-flow paths are joined with
explicit choices; unknown instructions, loops and stack inconsistencies fail
closed.  Calls consume the arity from the actual callee entry / HCB syscall
table.  Their return values and side effects are not guessed or executed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import heapq
import math
from typing import Any, Iterable, Mapping

from .hcb import HcbDocument, HcbError


FLOW_SCHEMA = "fvp-native-function-argument-flow/1"


class NativeCallFlowError(HcbError):
    pass


@dataclass(frozen=True)
class _Value:
    kind: str
    data: tuple[Any, ...] = ()

    def public(self) -> dict[str, Any]:
        if self.kind == "literal":
            return {"kind": self.kind, "type": self.data[0], "value": self.data[1]}
        if self.kind == "argument":
            return {"kind": self.kind, "index": self.data[0]}
        if self.kind == "global_read":
            return {"kind": self.kind, "slot": self.data[0], "offset": self.data[1]}
        if self.kind == "uninitialized_local":
            return {"kind": self.kind, "slot": self.data[0]}
        if self.kind == "unknown_return":
            return {"kind": self.kind}
        if self.kind == "call_return":
            return {
                "kind": self.kind, "call_kind": self.data[0], "target": self.data[1],
                "offset": self.data[2],
                "arguments": [x.public() for x in self.data[3]],
                "semantics_reviewed": False,
            }
        return {"kind": self.kind, "operands": [x.public() for x in self.data]}

    def dependencies(self) -> set[int]:
        if self.kind == "argument":
            return {self.data[0]}
        children = self.data[3] if self.kind == "call_return" else self.data
        return set().union(*(x.dependencies() for x in children if isinstance(x, _Value)))

    def size(self) -> int:
        children = self.data[3] if self.kind == "call_return" else self.data
        return 1 + sum(x.size() for x in children if isinstance(x, _Value))


def _literal(value: Any) -> _Value:
    if type(value) is float and not math.isfinite(value):
        raise NativeCallFlowError("non_finite_literal")
    return _Value("literal", (type(value).__name__, value))


def _choice(left: _Value, right: _Value, *, limit: int = 16) -> _Value:
    if left == right:
        return left
    members = set(left.data if left.kind == "choice" else (left,))
    members.update(right.data if right.kind == "choice" else (right,))
    if len(members) > limit:
        raise NativeCallFlowError("too_many_joined_values")
    return _Value("choice", tuple(sorted(members, key=repr)))


def _constant_operator(name: str, operands: tuple[_Value, ...], non_nil_arguments=frozenset()) -> _Value:
    """Fold only integer/boolean branch facts, never float or callee effects."""
    symbolic = _Value(name, operands)
    if name in {"set_e", "set_ne"} and len(operands) == 2:
        left, right = operands
        if ((left.kind == "argument" and left.data[0] in non_nil_arguments and right == _literal(None))
                or (right.kind == "argument" and right.data[0] in non_nil_arguments and left == _literal(None))):
            return _literal(name == "set_ne")
    if not all(x.kind == "literal" for x in operands):
        return symbolic
    values = [x.data[1] for x in operands]
    if name == "neg" and type(values[0]) is int:
        result = -values[0]
        return _literal(result) if -(2 ** 31) <= result < 2 ** 31 else symbolic
    if len(values) != 2:
        return symbolic
    left, right = values
    if name in {"set_e", "set_ne"}:
        # Nil has a distinct VM type.  Do not assume bool/int coercion or
        # compare floats through the host language's equality rules.
        if left is None or right is None:
            equal = left is None and right is None
        elif type(left) is type(right) and type(left) in {int, bool, str}:
            equal = left == right
        else:
            return symbolic
        return _literal(equal if name == "set_e" else not equal)
    if name in {"and", "or"} and all(type(x) is bool for x in values):
        return _literal(left and right if name == "and" else left or right)
    return symbolic


@dataclass
class _State:
    stack: tuple[_Value, ...] = ()
    slots: dict[int, _Value] = field(default_factory=dict)
    returned: _Value = field(default_factory=lambda: _Value("unknown_return"))

    def clone(self) -> _State:
        return _State(self.stack, dict(self.slots), self.returned)


class NativeFunctionFlow:
    """Index one document once and inspect only explicitly selected functions."""

    def __init__(self, document: HcbDocument):
        self.document = document
        starts = [i for i, x in enumerate(document.instructions) if x.mnemonic == "init_stack"]
        self.entries = {
            document.instructions[i].offset: (i, starts[n + 1] if n + 1 < len(starts)
                                               else len(document.instructions))
            for n, i in enumerate(starts)
        }

    def trace(self, address: int, *, max_instructions: int = 2048,
              literal_arguments: Mapping[int, Any] | None = None,
              max_joined_values: int = 16,
              non_nil_arguments: Iterable[int] | None = None) -> dict[str, Any]:
        base = {
            "schema": FLOW_SCHEMA, "source_sha256": self.document.source_sha256,
            "function_address": address, "writes_performed": False,
            "runtime_verified": False, "semantics_reviewed": False,
            "scope": "intraprocedural_forward_cfg_overapproximation",
        }
        try:
            if type(max_joined_values) is not int or not 1 <= max_joined_values <= 128:
                raise NativeCallFlowError("invalid_joined_value_limit")
            if type(address) is not int or address not in self.entries:
                raise NativeCallFlowError("address_is_not_an_exact_function_entry")
            first, end = self.entries[address]
            body = self.document.instructions[first:end]
            if len(body) > max_instructions:
                raise NativeCallFlowError("function_instruction_limit")
            if any(x.warning or x.dirty or not x.known for x in body):
                raise NativeCallFlowError("unknown_or_modified_function_instructions")
            count = int(body[0].operands["args"])
            local_count = int(body[0].operands["locals"])
            literals = dict(literal_arguments or {})
            if any(type(k) is not int or not 0 <= k < count or
                   not (v is None or type(v) in {int, bool, str}) for k, v in literals.items()):
                raise NativeCallFlowError("invalid_literal_argument_specialization")
            if literals:
                base["literal_arguments"] = literals
            if non_nil_arguments is not None and type(non_nil_arguments) not in (tuple, list, set, frozenset, range):
                raise NativeCallFlowError("invalid_non_nil_argument_facts")
            facts = tuple(non_nil_arguments or ())
            if any(type(i) is not int or not 0 <= i < count for i in facts) or len(set(facts)) != len(facts):
                raise NativeCallFlowError("invalid_non_nil_argument_facts")
            if any(i in literals and literals[i] is None for i in facts):
                raise NativeCallFlowError("conflicting_non_nil_argument_facts")
            if facts:
                base["non_nil_arguments"] = sorted(facts)
            base.update(argument_count=count, local_count=local_count)
            base["max_joined_values"] = max_joined_values
            result = self._trace_body(body, count, local_count, literals, max_joined_values, frozenset(facts))
            return {**base, "status": "proven_static_argument_flow", "blockers": [], **result}
        except (NativeCallFlowError, KeyError, IndexError) as exc:
            return {**base, "status": "blocked", "calls": [], "global_writes": [],
                    "blockers": [str(exc)]}

    def _trace_body(self, body, count: int, local_count: int,
                    literal_arguments: Mapping[int, Any] | None = None,
                    max_joined_values: int = 16, non_nil_arguments=frozenset()) -> dict[str, Any]:
        by_offset = {x.offset: i for i, x in enumerate(body)}
        states: dict[int, _State] = {1: _State()}
        queue = [1]
        calls: list[dict[str, Any]] = []
        global_writes: list[dict[str, Any]] = []
        branches: list[dict[str, Any]] = []
        returns: list[dict[str, Any]] = []
        visited = 0

        def original(slot: int) -> _Value:
            if -(count + 1) <= slot <= -2:
                parameter = slot + count + 1
                if literal_arguments and parameter in literal_arguments:
                    return _literal(literal_arguments[parameter])
                return _Value("argument", (parameter,))
            if 0 <= slot < local_count:
                return _Value("uninitialized_local", (slot,))
            raise NativeCallFlowError(f"invalid_frame_slot:{slot}")

        def push_state(index: int, incoming: _State) -> None:
            if index >= len(body):
                raise NativeCallFlowError("control_flow_falls_outside_function")
            prior = states.get(index)
            if prior is None:
                states[index] = incoming.clone()
                heapq.heappush(queue, index)
            else:
                if len(prior.stack) != len(incoming.stack):
                    raise NativeCallFlowError("branch_stack_height_mismatch")
                prior.stack = tuple(_choice(a, b, limit=max_joined_values) for a, b in zip(prior.stack, incoming.stack))
                prior.returned = _choice(prior.returned, incoming.returned, limit=max_joined_values)
                keys = prior.slots.keys() | incoming.slots.keys()
                prior.slots = {k: _choice(prior.slots.get(k, original(k)),
                                        incoming.slots.get(k, original(k)), limit=max_joined_values) for k in keys}

        def consume(stack: list[_Value], argc: int) -> tuple[_Value, ...]:
            if len(stack) < argc:
                raise NativeCallFlowError("call_or_operator_stack_underflow")
            arguments = tuple(stack[-argc:]) if argc else ()
            if argc:
                del stack[-argc:]
            return arguments

        while queue:
            index = heapq.heappop(queue)
            state = states[index].clone()
            item = body[index]
            name = item.mnemonic
            stack = list(state.stack)
            visited += 1
            if name in {"push_i8", "push_i16", "push_i32", "push_f32"}:
                stack.append(_literal(item.operands["value"]))
            elif name == "push_string":
                stack.append(_literal(item.text))
            elif name == "push_nil":
                stack.append(_literal(None))
            elif name == "push_true":
                stack.append(_literal(True))
            elif name == "push_stack":
                slot = int(item.operands["value"])
                stack.append(state.slots.get(slot, original(slot)))
            elif name == "pop_stack":
                slot = int(item.operands["value"])
                original(slot)  # Reserved and out-of-frame slots are not values.
                state.slots[slot] = consume(stack, 1)[0]
            elif name == "push_global":
                # Even after a prior assignment, a native callee may have changed
                # the global. Do not invent interprocedural state invariants.
                stack.append(_Value("global_read", (int(item.operands["value"]), item.offset)))
            elif name == "pop_global":
                value = consume(stack, 1)[0]
                global_writes.append({"offset": item.offset, "slot": item.operands["value"],
                                      "value": value.public()})
            elif name == "push_return":
                stack.append(state.returned)
            elif name == "neg":
                operands = consume(stack, 1)
                stack.append(_constant_operator("neg", operands, non_nil_arguments)
                             if literal_arguments or non_nil_arguments else _Value("neg", operands))
            # Binary stack effects agree with RFVP's script/context.rs.
            # Keep operators symbolic; do not invent their concrete result or
            # simplify branch-dependent Nil/default values into a single value.
            elif name in {"add", "sub", "mul", "div", "and", "or", "set_e", "set_ne",
                          "set_g", "set_ge", "set_l", "set_le"}:
                operands = consume(stack, 2)
                stack.append(_constant_operator(name, operands, non_nil_arguments)
                             if literal_arguments or non_nil_arguments else _Value(name, operands))
            elif name in {"call", "syscall"}:
                if name == "syscall":
                    syscall_id = int(item.operands["id"])
                    if not 0 <= syscall_id < len(self.document.header.syscalls):
                        raise NativeCallFlowError("syscall_outside_exact_header_table")
                    syscall = self.document.header.syscalls[syscall_id]
                    target, argc = syscall.name, syscall.args
                    identity = {"syscall_id": syscall_id, "name": target}
                else:
                    target = int(item.operands["target"])
                    if target not in self.entries:
                        raise NativeCallFlowError("callee_is_not_an_exact_function_entry")
                    entry = self.document.instructions[self.entries[target][0]]
                    if entry.dirty or entry.warning:
                        raise NativeCallFlowError("callee_entry_modified")
                    argc = int(entry.operands["args"])
                    identity = {"address": target}
                arguments = consume(stack, argc)
                calls.append({"offset": item.offset, "kind": name, **identity,
                              "argument_count": argc, "arguments": [x.public() for x in arguments],
                              "parameter_dependencies": sorted(set().union(*(x.dependencies() for x in arguments))),
                              "callee_semantics_reviewed": False})
                state.returned = _Value("call_return", (name, target, item.offset, arguments))
            elif name in {"jmp", "jz"}:
                target = int(item.operands["target"])
                if target not in by_offset or target <= item.offset:
                    raise NativeCallFlowError("loop_or_out_of_function_jump")
                if name == "jz":
                    condition = consume(stack, 1)[0]
                    branches.append({"offset": item.offset, "false_target": target,
                                     "condition": condition.public()})
                state.stack = tuple(stack)
                constant = (condition.data[1] if name == "jz" and condition.kind == "literal"
                            and type(condition.data[1]) is bool else None)
                if name == "jmp" or constant is not True:
                    push_state(by_offset[target], state)
                if name == "jz" and constant is not False:
                    push_state(index + 1, state)
                continue
            elif name in {"ret", "retv"}:
                value = consume(stack, 1)[0] if name == "retv" else None
                if stack:
                    raise NativeCallFlowError("return_has_unconsumed_stack_values")
                returns.append({"offset": item.offset, "value": value.public() if value else None})
                continue
            elif name != "nop":
                raise NativeCallFlowError(f"unproven_instruction:{name}")
            if len(stack) > 1024 or any(x.size() > 1024 for x in stack):
                raise NativeCallFlowError("expression_or_stack_limit")
            state.stack = tuple(stack)
            push_state(index + 1, state)
        if not returns:
            raise NativeCallFlowError("no_reachable_return")
        return {"calls": calls, "global_writes": global_writes, "branches": branches,
                "returns": returns, "reachable_instruction_count": visited,
                "callee_effects": "not_expanded_or_reviewed"}
