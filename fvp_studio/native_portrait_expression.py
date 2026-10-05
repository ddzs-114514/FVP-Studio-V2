"""Bind expression changes to a target's own dispatcher/apply parameter flow.

Header arity alone is not an expression contract. The selected native branch
must write the expression argument to the same pending-frame global consumed
by PartsMotion, and its apply chain must commit that frame before the call.
This does not certify engine timing or restore original image resources.
"""
from __future__ import annotations

from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans
from .native_call_flow import NativeFunctionFlow
from .native_script_state import NativeScriptStateClosure


SCHEMA = "fvp-native-portrait-expression-binding/1"


def bind_native_expressions(source, analysis, catalog, record, layout):
    closure = NativeScriptStateClosure(source, analysis, [catalog.apply_target],
                                       runtime_context=getattr(catalog, "_runtime_context", None))
    spans = {x.start: x for x in _function_spans(analysis)}
    dispatcher = spans.get(int(record["start"]))
    if dispatcher is None or dispatcher.end != int(record["end"]):
        raise NativePortraitAcceptanceError("表情切换缺少完整的目标原生载体。")
    calls = {x.name: x.args for x in source.header.syscalls}
    if calls.get("PartsMotion") != 3 or calls.get("PartsSelect") != 2:
        raise NativePortraitAcceptanceError("表情切换的原生参数布局未接通。")
    native_sites = set(closure.describe()["syscall_sites"].get("PartsMotion", ()))
    candidates = []
    for address in closure.dependencies:
        body = spans[address].instructions
        for index, item in enumerate(body):
            if item.offset not in native_sites or index < 5:
                continue
            commit_read, commit_write, handle, frame, duration = body[index - 5:index]
            if (commit_read.mnemonic != "push_global" or commit_write.mnemonic != "pop_global"
                    or handle.mnemonic != "push_global" or frame.mnemonic != "push_global"
                    or commit_read.operands != frame.operands
                    or commit_write.operands == frame.operands
                    or duration.mnemonic not in {"push_global", "push_stack"}):
                continue
            candidates.append(dict(function=address, syscall_offset=item.offset,
                parts_global_id=handle.operands["value"], pending_frame_global_id=frame.operands["value"],
                committed_frame_global_id=commit_write.operands["value"],
                commit_read_offset=commit_read.offset, commit_write_offset=commit_write.offset,
                duration_operand=dict(mnemonic=duration.mnemonic, **duration.operands)))
    total = source.header.non_volatile_globals + source.header.volatile_globals
    flow = NativeFunctionFlow(analysis)
    results, used_frame_globals = {}, set()
    for slot in catalog.slots:
        handles = slot.evidence.get("dispatcher_handles", {})
        ids = handles.get("binding_global_ids", ())
        literals = handles.get("carrier_literal_arguments")
        if len(ids) != 1 or not literals:
            raise NativePortraitAcceptanceError("表情切换缺少当前角色的原生参数分支。")
        # Several targets write frame state in a later selector block, not
        # in the initial resource-root block. Follow the whole exact native
        # dispatcher with its proven carrier arguments, rather than assuming
        # both blocks share a byte interval.
        trace = flow.trace(dispatcher.start, literal_arguments=literals,
            max_instructions=16384, max_joined_values=64)
        if trace["status"] != "proven_static_argument_flow":
            raise NativePortraitAcceptanceError("角色表情状态的原生参数流未闭合。")
        matches = []
        for candidate in candidates:
            if candidate["parts_global_id"] != ids[0]:
                continue
            frame_id = candidate["pending_frame_global_id"]
            writers = [x for x in trace["global_writes"] if x["slot"] == frame_id]
            argument_index = layout.expression + int(record["args"]) + 1
            if (len(writers) != 1
                    or writers[0]["value"] != dict(kind="argument", index=argument_index)):
                continue
            matches.append(dict(candidate, expression_argument_stack=layout.expression,
                dispatcher_expression_write_offset=writers[0]["offset"]))
        if len(matches) != 1:
            raise NativePortraitAcceptanceError("角色的原生表情参数到 PartsMotion 没有唯一匹配。")
        match = matches[0]
        globals_ = {match["pending_frame_global_id"], match["committed_frame_global_id"]}
        if (any(type(x) is not int or not 0 <= x < total for x in globals_)
                or len(globals_) != 2 or ids[0] in globals_ or used_frame_globals & globals_):
            raise NativePortraitAcceptanceError("角色表情状态槽与其他原生槽冲突。")
        used_frame_globals.update(globals_)
        results[slot.selector] = dict(schema=SCHEMA, selector=slot.selector,
            source_sha256=source.source_sha256, **match,
            native_expression_parameter_flow_bound=True, header_arity_only=False,
            engine_time_unit_independently_verified=False, runtime_verified=False)
    return results
