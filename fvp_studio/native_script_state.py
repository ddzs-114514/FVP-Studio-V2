"""Byte-bound native script state closure, including called functions.

This is a conservative access inventory, not callee execution or a proof that
engine resources can be restored by restoring script globals. Every reachable
function is checked against the running source image. The scene compiler may
use the generated operand-stack snapshot only after separately owning its
graphics/audio resources and reviewing their cleanup semantics.
"""
from __future__ import annotations

import hashlib
from types import MappingProxyType

from .hcb import HcbDocument
from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_portrait_acceptance import NativePortraitAcceptanceError, _function_spans


SCHEMA = "fvp-native-script-state-closure/1"


def validate_native_script_pair(source, analysis, *, runtime_context=None):
    """Allow a paired translation only through its already-bound scene context.

    This does NOT validate unparsed runtime bytes as instructions. Callers must
    still compare every native function they use with the clean analysis image
    and inspect that function's control flow. No boolean warning bypass exists.
    """
    if not isinstance(source, HcbDocument) or not isinstance(analysis, HcbDocument):
        raise NativePortraitAcceptanceError("原生调用缺少配对 HCB。")
    from .native_scene_candidate import (
        NativeSceneMemoryContext, NATIVE_MEMORY_CONTEXT_SCHEMA, _header_signature,
    )
    if (analysis.warnings or source.modified or analysis.modified
            or _header_signature(source) != _header_signature(analysis)):
        raise NativePortraitAcceptanceError("原生调用的分析指令或 VM 头部不一致。")
    paired = source.source_sha256 != analysis.source_sha256
    if source.warnings or paired:
        if (not isinstance(runtime_context, NativeSceneMemoryContext)
                or runtime_context.document is not source
                or runtime_context.analysis_document is not analysis):
            raise NativePortraitAcceptanceError("运行脚本需要已绑定的汉化脚本与原生分析配对。")
        report = runtime_context.report
        if (report.get("schema") != NATIVE_MEMORY_CONTEXT_SCHEMA
                or report.get("analysis_mode") != "generic_hidden_overlay_memory"
                or report.get("target_id") != runtime_context.target_id
                or report.get("profile_sha256") != runtime_context.profile_sha256
                or report.get("source", {}).get("sha256") != source.source_sha256
                or report.get("analysis_source", {}).get("sha256") != analysis.source_sha256
                or report.get("source", {}).get("size") != len(source.original_bytes)
                or report.get("analysis_source", {}).get("size") != len(analysis.original_bytes)
                or len(source.original_bytes) < len(analysis.original_bytes)):
            raise NativePortraitAcceptanceError("汉化脚本配对身份已变化。")
    return dict(paired_runtime_overlay=paired, runtime_parser_warning_count=len(source.warnings),
                analysis_parser_warning_count=0, native_dependencies_require_exact_bytes=True,
                full_runtime_instruction_parse_claimed=not bool(source.warnings))


class NativeScriptStateClosure:
    def __init__(self, source: HcbDocument, analysis: HcbDocument, roots, *,
                 max_functions=256, max_instructions=131072, runtime_context=None):
        if not isinstance(source, HcbDocument) or not isinstance(analysis, HcbDocument):
            raise NativePortraitAcceptanceError("原生状态检查缺少配对 HCB。")
        if (type(max_functions) is not int or not 1 <= max_functions <= 1024
                or type(max_instructions) is not int or not 1 <= max_instructions <= 1048576):
            raise NativePortraitAcceptanceError("原生状态检查范围无效。")
        pair_report = validate_native_script_pair(source, analysis, runtime_context=runtime_context)
        roots = tuple(roots)
        if not roots or any(type(x) is not int for x in roots) or len(set(roots)) != len(roots):
            raise NativePortraitAcceptanceError("原生状态检查须给出不同的函数入口。")
        entries = {s.start: s for s in _function_spans(analysis)}
        total_globals = analysis.header.non_volatile_globals + analysis.header.volatile_globals
        queue = list(roots)
        dependencies, accesses, edges, syscalls = {}, {}, {}, {}
        scanned = 0
        while queue:
            address = queue.pop()
            if address in dependencies:
                continue
            span = entries.get(address)
            if span is None:
                raise NativePortraitAcceptanceError("原生调用指向未确认的函数入口。")
            if len(dependencies) >= max_functions:
                raise NativePortraitAcceptanceError("原生状态调用链超出限定函数数目。")
            raw = analysis.original_bytes[span.start:span.end]
            if source.original_bytes[span.start:span.end] != raw:
                raise NativePortraitAcceptanceError("运行／分析脚本的原生状态依赖已漂移。")
            offsets = {x.offset: i for i, x in enumerate(span.instructions)}
            pending, visited, called = [0], set(), set()
            while pending:
                index = pending.pop()
                if index in visited:
                    continue
                if not 0 <= index < len(span.instructions):
                    raise NativePortraitAcceptanceError("原生状态分支越过函数边界。")
                visited.add(index)
                scanned += 1
                if scanned > max_instructions:
                    raise NativePortraitAcceptanceError("原生状态调用链超出限定指令数目。")
                item = span.instructions[index]
                if item.warning or item.dirty or not item.known:
                    raise NativePortraitAcceptanceError("原生状态依赖含有未确认的指令。")
                if index and item.mnemonic == "init_stack":
                    raise NativePortraitAcceptanceError("原生状态函数出现额外入口。")
                if item.mnemonic in ("push_global", "pop_global"):
                    slot = int(item.operands["value"])
                    if not 0 <= slot < total_globals:
                        raise NativePortraitAcceptanceError("原生状态变量越过脚本声明。")
                    role = "write" if item.mnemonic == "pop_global" else "read"
                    accesses.setdefault(slot, {"read": [], "write": []})[role].append(item.offset)
                if item.mnemonic == "call":
                    target = int(item.operands["target"])
                    if target not in entries:
                        raise NativePortraitAcceptanceError("原生状态依赖的调用不是函数入口。")
                    called.add(target)
                elif item.mnemonic == "syscall":
                    ident = int(item.operands["id"])
                    if not 0 <= ident < len(analysis.header.syscalls):
                        raise NativePortraitAcceptanceError("原生状态依赖的系统调用越界。")
                    syscalls.setdefault(analysis.header.syscalls[ident].name, []).append(item.offset)
                if item.mnemonic in ("ret", "retv"):
                    continue
                if item.mnemonic in ("jmp", "jz"):
                    target = int(item.operands["target"])
                    if target not in offsets:
                        raise NativePortraitAcceptanceError("原生状态分支不是本函数指令边界。")
                    pending.append(offsets[target])
                    if item.mnemonic == "jmp":
                        continue
                pending.append(index + 1)
            dependencies[address] = (span.end, raw)
            edges[address] = sorted(called)
            queue.extend(called - dependencies.keys())

        self._source_bytes = source.original_bytes
        self.source_sha256 = source.source_sha256
        self.analysis_sha256 = analysis.source_sha256
        self.dependencies = MappingProxyType(dependencies)
        self.global_ids = tuple(sorted(g for g, sites in accesses.items() if sites["write"]))
        self.read_global_ids = tuple(sorted(g for g, sites in accesses.items() if sites["read"]))
        self._report = dict(schema=SCHEMA, source_sha256=self.source_sha256,
            analysis_sha256=self.analysis_sha256, runtime_binding=pair_report,
            roots=list(roots), function_count=len(dependencies),
            reachable_instruction_count=scanned, global_write_ids=list(self.global_ids),
            global_read_ids=list(self.read_global_ids), global_accesses={str(g): sites for g, sites in sorted(accesses.items())},
            call_edges={str(g): calls for g, calls in sorted(edges.items())},
            dependencies={str(g): dict(end=end, byte_sha256=hashlib.sha256(raw).hexdigest())
                          for g, (end, raw) in sorted(dependencies.items())},
            syscall_sites=syscalls, scope="conservative_reachable_script_accesses_including_callees",
            arguments_specialized=False, script_global_access_closure_complete=True,
            callee_runtime_semantics_reviewed=False, engine_resource_restoration_proven=False,
            hcb_rendering_ready=False, runtime_verified=False, writes_performed=False)

    def describe(self):
        from copy import deepcopy
        return deepcopy(self._report)

    def compile_snapshot(self, document):
        if document.source_sha256 != self.source_sha256 or document.original_bytes != self._source_bytes:
            raise NativePortraitAcceptanceError("原生状态快照属于另一份目标脚本。")
        snapshot = b"".join(_push_global(x) for x in self.global_ids)
        restore = b"".join(_pop_global(x) for x in reversed(self.global_ids))
        return dict(snapshot=snapshot, restore=restore, report=dict(
            schema=SCHEMA, global_ids=list(self.global_ids), operand_stack_value_count=len(self.global_ids),
            includes_script_callee_writes=True, header_unchanged=True,
            engine_resource_restoration_proven=False, hcb_rendering_ready=False,
            code_sha256={name: hashlib.sha256(code).hexdigest() for name, code in
                         (("snapshot", snapshot), ("restore", restore))}))

