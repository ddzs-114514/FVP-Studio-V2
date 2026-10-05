"""Target-derived background calls for different FVP script generations.

The eight-argument state wrappers and early single-layer loader are not the
nine-argument, archive-selecting ABI.  Bind their resource flow from the current
HCB rather than choosing addresses, graphics slots or geometry by game name.
This module emits calls in memory only; it does not select a game executable,
write archives or authorize installation.
"""
from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping

from .hcb import HcbDocument, HcbError
from .native_call_flow import NativeFunctionFlow
from .native_target_discovery import (
    _discover_background_dissolve_family,
    _discover_visual_loader_family,
    _function_regions,
)


class NativeBackgroundBackendError(HcbError):
    pass


@dataclass(frozen=True)
class NativeBackgroundCalls:
    code: bytes
    report: Mapping[str, Any]


def _dependencies(value: Mapping[str, Any]) -> set[int]:
    if value.get("kind") == "argument":
        return {int(value["index"])}
    children = value.get("arguments", ()) if value.get("kind") == "call_return" else value.get("operands", ())
    return set().union(*(_dependencies(x) for x in children if isinstance(x, Mapping)))


def _substitute(value: Mapping[str, Any], arguments: tuple[Mapping[str, Any], ...]) -> dict[str, Any]:
    if value.get("kind") == "argument":
        return copy.deepcopy(dict(arguments[int(value["index"])]))
    result = dict(value)
    for key in ("operands", "arguments"):
        if key in value:
            result[key] = [_substitute(x, arguments) for x in value[key]]
    return result


def _literal(value: Any) -> dict[str, Any]:
    return {"kind": "literal", "type": type(value).__name__, "value": value}


class NativeBackgroundBackend:
    """Immutable source-bound load/transition recipe, with native defaults.

    ``archive_selectors`` is the already locked modern namespace routing from
    the target profile.  Selector-less targets must instead prove a single
    namespace reaching GraphLoad through their actual function argument flow.
    """

    def __init__(self, source: HcbDocument, analysis: HcbDocument, *,
                 archive_selectors: Mapping[str, int | None] | None = None):
        if not isinstance(source, HcbDocument) or not isinstance(analysis, HcbDocument):
            raise NativeBackgroundBackendError("背景后端缺少当前目标的 HCB 文档")
        if not source.original_bytes or not analysis.original_bytes or analysis.warnings:
            raise NativeBackgroundBackendError("背景后端需要可完整解析的分析 HCB")
        if [(x.name, x.args) for x in source.header.syscalls] != [(x.name, x.args) for x in analysis.header.syscalls]:
            raise NativeBackgroundBackendError("运行和分析 HCB 的系统调用表不同")
        self.source_sha256 = source.source_sha256
        self.analysis_sha256 = analysis.source_sha256
        self._source = source
        self._analysis = analysis
        self._regions = _function_regions(analysis)
        self._by_start = {x.start: x for x in self._regions}
        self._flow = NativeFunctionFlow(analysis)
        self._traces: dict[int, dict[str, Any]] = {}
        self._used: set[int] = set()
        self.primary_target: int
        self.blur_target: int | None
        self.argument_count: int
        self.strategy: str
        self.archive_selectors: dict[str, int | None]
        self.runtime_namespace_alternatives: tuple[str, ...] = ()

        family = _discover_visual_loader_family(self._regions).get("selected")
        if family:
            counts = {int(x["args"]) for x in family[:2]}
            if len(counts) != 1 or next(iter(counts)) not in {8, 9}:
                raise NativeBackgroundBackendError("背景层的原生参数布局不一致")
            self.primary_target = int(family[0]["start"])
            self.blur_target = int(family[1]["start"])
            self.argument_count = next(iter(counts))
            self.strategy = "native_paired_layers"
            for target in (self.primary_target, self.blur_target):
                self._trace(target)
            if self.argument_count == 9:
                if not archive_selectors:
                    raise NativeBackgroundBackendError("九参数背景调用缺少已锁定的归档选择路由")
                self.archive_selectors = dict(archive_selectors)
            else:
                namespaces = [self._resource_namespaces(x) for x in (self.primary_target, self.blur_target)]
                if namespaces[0] != namespaces[1]:
                    raise NativeBackgroundBackendError("八参数背景层的资源路由不一致")
                graphics = {x for x in namespaces[0] if re.fullmatch(r"graph(?:_bg)?/", x)}
                if len(graphics) != 1 or namespaces[0] - graphics - {"etc/"}:
                    raise NativeBackgroundBackendError("八参数背景调用没有唯一的背景资源链")
                namespace = next(iter(graphics))
                self.archive_selectors = {namespace[:-1] + ".bin": None}
                # Some native scripts route test-mode graphics to etc/.  Keep
                # that original runtime decision; do not assign its global or
                # advertise etc.bin as the normal background archive.
                self.runtime_namespace_alternatives = tuple(sorted(namespaces[0] - graphics))
        else:
            # An early engine owns one double-buffered plane, not the later
            # clear/blur pair.  Calling it twice would discard the first load.
            candidates = []
            for region in self._regions:
                counts = Counter(region.syscalls)
                if not (region.args == 6 and region.locals == 0
                        and counts == Counter({"PrimSetNull": 4, "GraphLoad": 2, "DissolveWait": 1})):
                    continue
                try:
                    if self._resource_namespaces(region.start) == {"graph/"}:
                        candidates.append(region)
                except NativeBackgroundBackendError:
                    continue
            if len(candidates) != 1:
                raise NativeBackgroundBackendError("没有唯一可证明的原生背景加载布局")
            self.primary_target = candidates[0].start
            self.blur_target = None
            self.argument_count = candidates[0].args
            self.strategy = "native_single_layer"
            self.archive_selectors = {"graph.bin": None}

        selected = _discover_background_dissolve_family(self._regions).get("selected")
        if selected:
            self.dissolve_target = int(selected["start"])
            self.dissolve_argument_count = 9
            self._used.add(self.dissolve_target)
        else:
            candidates = []
            for region in self._regions:
                if not (region.args in {5, 7, 8, 9} and region.locals in {1, 2, 3}
                        and region.syscalls in {
                            ("Dissolve", "DissolveWait"),
                            ("MotionAlphaTest", "MotionAlphaTest", "PrimSetAlpha", "PrimSetAlpha", "Dissolve", "DissolveWait"),
                            ("MotionAlphaTest", "MotionAlphaTest", "PrimSetAlpha", "PrimSetAlpha", "Dissolve", "DissolveWait", "DissolveWait"),
                        }
                        and {"graph/diss00", "graph/diss01", "graph/diss02", "graph/diss03"}.issubset(region.strings)):
                    continue
                # The exact stack slice into Dissolve proves duration/mask
                # positions without pretending to execute the native wait
                # loop.  Nil defaults and skip-mode behavior remain inside
                # the original wrapper, not copied into Python.
                if self._mask_zero_branch(region) and self._dissolve_operand_layout(region):
                    candidates.append(region)
            if len(candidates) != 1:
                raise NativeBackgroundBackendError("没有唯一可证明的原生背景转场布局")
            self.dissolve_target = candidates[0].start
            self.dissolve_argument_count = candidates[0].args
            self._used.add(self.dissolve_target)
        self._validate_dependency_bytes()

    def _trace(self, target: int) -> dict[str, Any]:
        if target not in self._traces:
            trace = self._flow.trace(target)
            if trace["status"] != "proven_static_argument_flow":
                raise NativeBackgroundBackendError(f"原生背景参数流未确定: 0x{target:X}")
            self._traces[target] = trace
        self._used.add(target)
        return self._traces[target]

    def _resource_namespaces(self, target: int) -> set[str]:
        paths: set[str] = set()
        visited: set[tuple[int, str]] = set()

        def namespace(value: Mapping[str, Any]) -> None:
            if value.get("kind") == "choice":
                for member in value.get("operands", ()):
                    namespace(member)
            elif value.get("kind") == "add":
                left, right = value.get("operands", (None, None))
                prefixes = left.get("operands", ()) if isinstance(left, Mapping) and left.get("kind") == "choice" else (left,)
                if not (isinstance(right, Mapping) and right == {"kind": "argument", "index": 0}
                        and prefixes and all(isinstance(x, Mapping) and x.get("kind") == "literal"
                                            and isinstance(x.get("value"), str) for x in prefixes)):
                    raise NativeBackgroundBackendError("背景资源路径不是已证明的原生前缀加资源名")
                paths.update(str(x["value"]) for x in prefixes)
            elif _dependencies(value):
                raise NativeBackgroundBackendError("背景资源路径包含未解析的调用返回值")

        def visit(address: int, args: tuple[Mapping[str, Any], ...], depth: int) -> None:
            if depth > 5:
                raise NativeBackgroundBackendError("背景资源调用链超过解析边界")
            key = (address, repr(args))
            if key in visited:
                return
            visited.add(key)
            literals = {i: value["value"] for i, value in enumerate(args)
                        if value.get("kind") == "literal" and
                        (value.get("value") is None or type(value.get("value")) in {int, bool, str})}
            trace = self._flow.trace(address, literal_arguments=literals)
            if trace["status"] != "proven_static_argument_flow":
                raise NativeBackgroundBackendError(f"背景资源调用链未确定: 0x{address:X}")
            self._used.add(address)
            for call in trace["calls"]:
                values = tuple(_substitute(x, args) for x in call["arguments"])
                if call["kind"] == "syscall" and call.get("name") == "GraphLoad":
                    if len(values) != 2:
                        raise NativeBackgroundBackendError("GraphLoad 参数布局不匹配")
                    namespace(values[1])
                elif call["kind"] == "call" and any(_dependencies(x) for x in values):
                    visit(int(call["address"]), values, depth + 1)

        count = self._by_start[target].args
        visit(target, ({"kind": "argument", "index": 0}, *(_literal(None) for _ in range(count - 1))), 0)
        return paths

    def _mask_zero_branch(self, region: Any) -> bool:
        body = self._analysis.instructions[region.instruction_start_index:region.instruction_end_index]
        slot = -(region.args + 1)
        for i in range(len(body) - 5):
            a, b, c, d, e, f = body[i:i + 6]
            if (a.mnemonic == "push_stack" and a.operands.get("value") == slot
                    and b.mnemonic in {"push_i8", "push_i16", "push_i32"} and b.operands.get("value") == 0
                    and c.mnemonic == "set_e" and d.mnemonic == "jz"
                    and e.mnemonic == "push_string" and e.text == "graph/diss00"
                    and f.mnemonic == "pop_stack" and f.operands.get("value") == slot):
                return True
        return False

    def _dissolve_operand_layout(self, region: Any) -> bool:
        body = self._analysis.instructions[region.instruction_start_index:region.instruction_end_index]
        sites = [i for i, x in enumerate(body) if x.mnemonic == "syscall"
                 and self._analysis.header.syscalls[x.operands["id"]].name == "Dissolve"]
        if len(sites) != 1 or sites[0] < 7:
            return False
        syscall = self._analysis.header.syscalls[body[sites[0]].operands["id"]]
        if syscall.args != 7:
            return False
        values = body[sites[0] - 7:sites[0]]
        return bool(
            values[0].mnemonic == "push_stack" and values[0].operands.get("value") == -region.args
            and values[1].mnemonic == "push_stack" and values[1].operands.get("value") == -(region.args + 1)
            and values[2].mnemonic in {"push_stack", "push_nil", "push_true"}
            and all(x.mnemonic == "push_nil" for x in values[3:])
        )

    def _validate_dependency_bytes(self) -> None:
        pending = list(self._used)
        visited: set[int] = set()
        while pending:
            target = pending.pop()
            if target in visited:
                continue
            visited.add(target)
            if len(visited) > 256 or target not in self._by_start:
                raise NativeBackgroundBackendError("原生背景依赖范围无法确定")
            region = self._by_start[target]
            if self._source.original_bytes[region.start:region.end] != self._analysis.original_bytes[region.start:region.end]:
                raise NativeBackgroundBackendError("运行 HCB 的背景函数或依赖与分析证据不一致")
            pending.extend(region.call_targets)
        self._used = visited

    def describe(self) -> dict[str, Any]:
        return {
            "schema": "fvp-native-background-backend/1",
            "source_sha256": self.source_sha256,
            "analysis_sha256": self.analysis_sha256,
            "strategy": self.strategy,
            "primary_target": self.primary_target,
            "blur_target": self.blur_target,
            "load_argument_count": self.argument_count,
            "dissolve_target": self.dissolve_target,
            "dissolve_argument_count": self.dissolve_argument_count,
            "archive_selectors": dict(self.archive_selectors),
            "runtime_namespace_alternatives": list(self.runtime_namespace_alternatives),
            "runtime_state_is_not_overridden": True,
            "native_geometry_defaults_preserved": True,
            "distinct_blur_layer": self.blur_target is not None,
            "dependency_count": len(self._used),
            "game_name_switch_used": False,
            "writes_performed": False,
            "runtime_verified": False,
        }

    def compile_load(self, document: HcbDocument, *, resource_name: str,
                     archive_name: str, duration_ms: int,
                     blur_resource_name: str | None = None) -> NativeBackgroundCalls:
        if document.source_sha256 != self.source_sha256 or document.original_bytes != self._source.original_bytes:
            raise NativeBackgroundBackendError("背景调用属于另一份目标 HCB，不能复用")
        if type(duration_ms) is not int or not 0 <= duration_ms <= 60000:
            raise NativeBackgroundBackendError("背景转场时间必须是 0～60000 毫秒整数")
        archive = str(archive_name).strip().casefold()
        if archive not in self.archive_selectors:
            raise NativeBackgroundBackendError("背景归档不在当前目标的原生资源路由中")
        blur = resource_name if blur_resource_name is None else blur_resource_name
        for name in (resource_name, blur):
            if not isinstance(name, str) or not name or any(x in name for x in ("/", "\\", ":", "\0")) or name in {".", ".."}:
                raise NativeBackgroundBackendError("背景资源必须是归档内的直属资源名")
        if self.blur_target is None and blur != resource_name:
            raise NativeBackgroundBackendError("此原生布局没有独立模糊层，不能加载另一个模糊资源")
        from .hoshimemo_scene_hook import _arguments, _call, _push_string

        tail = [None] * (self.argument_count - 1)
        if self.argument_count == 9:
            tail[-1] = self.archive_selectors[archive]
        calls = [{"address": self.primary_target, "arguments": [resource_name, *tail]}]
        code = _push_string(resource_name, document.encoding) + _arguments(tail) + _call(self.primary_target)
        if self.blur_target is not None:
            calls.append({"address": self.blur_target, "arguments": [blur, *tail]})
            code += _push_string(blur, document.encoding) + _arguments(tail) + _call(self.blur_target)
        dissolve = [0, duration_ms, *([None] * (self.dissolve_argument_count - 2))]
        calls.append({"address": self.dissolve_target, "arguments": dissolve})
        code += _arguments(dissolve) + _call(self.dissolve_target)
        return NativeBackgroundCalls(code, {
            **self.describe(), "resource_name": resource_name,
            "runtime_blur_resource_name": blur, "archive_name": archive,
            "duration_ms": duration_ms, "calls": calls,
            "code_sha256": hashlib.sha256(code).hexdigest(), "byte_count": len(code),
        })
