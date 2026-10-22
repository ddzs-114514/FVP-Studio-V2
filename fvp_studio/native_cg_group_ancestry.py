"""Bind CG's source-normalized ancestor chain, without acquiring runtime groups.

The bound normalizer must be in the actual CG creator's native call closure.
All forward paths must end with the same parent chain. Helpers' grouping and
primitive-recreation effects are included; unrelated children are projected
away only after the complete paths are inspected. Root 0 is a sentinel, not
an owned primitive or a new graph handle. No original normalizer is emitted.
"""
from copy import deepcopy

from .native_background_backend import _literal, _substitute
from .native_cg_staged_load import NativeCGStagedLoad
from .native_cg_primitive_groups import NativeCGPrimitiveGroups
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair


SCHEMA = "fvp-native-cg-group-ancestry/1"
GROUP_IN = {"PrimGroup", "PrimGroupIn"}
RESET = {"PrimGroupOut", "PrimSetNull", "PrimSetSprt", "PrimSetGroup", "PrimSetTile", "PrimSetText"}
OTHER_PRIMITIVES = {"PrimSetAlpha", "PrimSetDraw", "PrimSetXY", "PrimSetWH", "PrimSetUV",
    "PrimSetZ", "PrimSetRS", "PrimSetRS2", "PrimSetOP", "PrimHit"}


def integer(value):
    if value.get("kind") != "literal" or type(value.get("value")) is not int:
        raise ValueError("CG 上层分组仍依赖未确定的原剧情句柄。")
    return value["value"]


class NativeCGGroupAncestry:
    def __init__(self, stage, *, native_groups=None):
        if not isinstance(stage, NativeCGStagedLoad):
            raise ValueError("CG 分组必须属于目标自己的完整创建流程。")
        self.stage, self.backend = stage, stage.backend
        self.source, self.analysis = stage.source, stage.analysis
        self.context = stage.context
        if native_groups is not None:
            if (not isinstance(native_groups,NativeCGPrimitiveGroups)
                    or not isinstance(stage.executable,bytes) or not stage.executable):
                raise ValueError("CG 分组恢复需要同一目标的完整原生分组绑定。")
            native_groups.validate(stage.executable)
        self.native_groups = native_groups
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        self.direct_parents, self.links = set(), []
        candidates = set()
        phase_contexts = {}
        for plan in stage.plans:
            plan["closure"].compile_snapshot(self.source)
            effects, _, traces, _ = stage._creator(plan["creator"],
                tuple(_literal(v) for v in plan["creator_arguments"]),
                plan["creator_globals"], plan["graph"])
            groups = [c for c in effects if c["name"] in GROUP_IN]
            if len(groups) != 1 or groups[0] != plan["source_group_call"]:
                raise ValueError("CG 分组与本目标创建路径不一致。")
            child, parent = map(integer, groups[0]["arguments"])
            if child != plan["primitive"] or parent <= 0 or parent in self.backend.planes:
                raise ValueError("CG 父分组与原生图层身份冲突。")
            self.direct_parents.add(parent)
            self.links.append(deepcopy(groups[0]))
            candidates.update(plan["closure"].dependencies)
            for trace in traces.values():
                for call in trace["calls"]:
                    if call["kind"] == "call" and not self.backend.spans[call["address"]].args:
                        facts = call["literal_globals_before_call"]
                        contexts = phase_contexts.setdefault(call["address"],[])
                        if facts not in contexts:
                            contexts.append(deepcopy(facts))
        self.direct_parents = frozenset(self.direct_parents)
        if self.native_groups is not None:
            for row in self.links:
                self.native_groups.validate_pair(*(integer(v) for v in row['arguments']))
        self.plan_signature = self._plan_signature()
        self._possible_cache = {}
        proofs, rejected = [], []
        for address in sorted(candidates):
            span = self.backend.spans[address]
            if span.args or not set(span.syscalls) & GROUP_IN or set(span.syscalls) - GROUP_IN:
                continue
            try:
                contexts = phase_contexts.get(address,[{}])
                paths, used, variants = set(), set(), 0
                for facts in contexts:
                    relevant = self._relevant_groups(address,facts)
                    sequences, children = self._sequences(address, (), facts, (), relevant)
                    used.update(children)
                    variants += len(sequences)
                    paths.update(self._chains(sequence) for sequence in sequences)
                if len(paths) != 1:
                    raise ValueError("原生分组的不同路径会给 CG 选择不同上层分组。")
                proofs.append(dict(function=address, paths=next(iter(paths)),
                    projected_end_states=variants, creator_phase_globals=contexts,
                    dependencies=sorted(used)))
            except ValueError as exc:
                rejected.append(dict(function=address, reason=str(exc)))
        if not proofs or len({p["paths"] for p in proofs}) != 1:
            error = ValueError("CG 上层分组尚未找到一致的本目标原生归一调用链。")
            error.native_details = dict(rejected=rejected, proofs=proofs)
            raise error
        self.paths = proofs[0]["paths"]
        self.ancestors = frozenset(node for path in self.paths for node in path if node)
        if self.native_groups is not None:
            for path in self.paths:
                for child,parent in zip(path,path[1:]):
                    self.native_groups.validate_pair(child,parent)
        if self.ancestors & set(self.backend.planes):
            raise ValueError("CG 上层分组与图像图元重叠。")
        self.proofs = proofs
        self.closure = NativeScriptStateClosure(self.source, self.analysis,
            sorted({p["function"] for p in proofs}), runtime_context=self.context,
            max_functions=256, max_instructions=131072)
        self.table = tuple((d.name, d.args) for d in self.source.header.syscalls)

    def _possible(self, address, parents=()):
        if address in self._possible_cache:
            return self._possible_cache[address]
        if address in parents or len(parents) > 16:
            raise ValueError("CG 分组辅助调用出现循环或越界。")
        span = self.backend.spans[address]
        if "ThreadStart" in span.syscalls:
            raise ValueError("CG 分组归一包含未交接的异步原剧情线程。")
        if any(n.startswith("Prim") and n not in GROUP_IN | RESET | OTHER_PRIMITIVES for n in span.syscalls):
            raise ValueError("CG 分组辅助调用含有尚未识别的图元操作。")
        result = bool(set(span.syscalls) & (GROUP_IN | RESET)) or any(
            self._possible(a, (*parents, address)) for a in span.calls)
        self._possible_cache[address] = result
        return result

    def _relevant_groups(self,address,facts):
        trace = self.backend.flow.trace(address,track_global_literals=True,literal_globals=facts,
            max_joined_values=128,max_instructions=8192)
        if trace["status"] != "proven_static_argument_flow":
            raise ValueError("CG 分组归一缺少完整的原生前向流程。")
        edges = {}
        for call in trace["calls"]:
            if call.get("name") in GROUP_IN:
                child,parent = map(integer,call["arguments"])
                edges.setdefault(child,set()).add(parent)
        pending, relevant = list(self.direct_parents), set()
        while pending:
            node = pending.pop()
            if node in relevant or node == 0:
                continue
            if node <= 0 or len(relevant) >= 256 or node not in edges:
                raise ValueError("CG 分组归一未显式定义完整的本目标祖先结构。")
            relevant.add(node)
            pending.extend(edges[node])
        return frozenset(relevant)

    def _sequences(self, address, arguments, facts, parents, relevant):
        if address in parents or len(parents) > 16:
            raise ValueError("CG 分组归一调用链出现递归。")
        span = self.backend.spans[address]
        if (any(i.dirty or i.warning or not i.known for i in span.instructions)
                or self.source.original_bytes[span.start:span.end]
                != self.analysis.original_bytes[span.start:span.end]):
            raise ValueError("CG 分组原生函数已修改或未完整解析。")
        trace = self.backend.flow.trace(address,
            literal_arguments={i:v["value"] for i,v in enumerate(arguments) if v.get("kind") == "literal"},
            track_global_literals=True, literal_globals=facts, max_joined_values=128,
            max_instructions=8192)
        if trace["status"] != "proven_static_argument_flow":
            raise ValueError("CG 分组归一函数不是完整的前向参数流。")
        effects, used = {}, {address}
        for call in trace["calls"]:
            values = tuple(_substitute(v, arguments) for v in call["arguments"])
            if call["kind"] == "call":
                if not self._possible(call["address"]):
                    continue
                options, children = self._sequences(call["address"], values,
                    call["literal_globals_before_call"], (*parents, address),relevant)
                used.update(children)
            elif call["name"] in GROUP_IN:
                if len(values) != 2:
                    raise ValueError("CG 原生分组入口参数不一致。")
                child, parent = map(integer, values)
                if not 0 < child < 2**31 or not 0 <= parent < 2**31 or child == parent:
                    raise ValueError("CG 上层分组句柄或父子关系无效。")
                if child not in relevant:
                    continue
                options = {(("in", child, parent),)}
            elif call["name"] in RESET:
                primitive = integer(values[0])
                if not 0 <= primitive < 2**31:
                    raise ValueError("CG 分组重建使用未确定的全局句柄。")
                if primitive and primitive not in relevant:
                    continue
                options = {(("reset", primitive, 0),)}
            else:
                continue
            site = call["offset"]
            if site in effects and effects[site] != options:
                raise ValueError("CG 分组同一调用点存在不同的未分离参数路径。")
            effects[site] = options
        indexes = {i.offset:n for n,i in enumerate(span.instructions)}
        conditions = {b["offset"]:b["condition"] for b in trace["branches"]}
        pending, seen, endings = [(1, ())], set(), set()
        while pending:
            index, sequence = pending.pop()
            if (index, sequence) in seen:
                continue
            seen.add((index, sequence))
            if len(seen) > 16384 or not 0 < index < len(span.instructions):
                raise ValueError("CG 分组投影超出限定函数范围。")
            ins = span.instructions[index]
            variants = {self._canonical(sequence+v) for v in effects.get(ins.offset, {()})}
            for current in variants:
                if ins.mnemonic in {"ret", "retv"}:
                    endings.add(current)
                elif ins.mnemonic in {"jmp", "jz"}:
                    target = indexes.get(ins.operands["target"])
                    if target is None or target <= index:
                        raise ValueError("CG 分组投影不是函数内的前向路径。")
                    value = conditions.get(ins.offset, {})
                    fact = value.get("value") if value.get("kind") == "literal" and type(value.get("value")) is bool else None
                    if ins.mnemonic == "jmp" or fact is not True:
                        pending.append((target, current))
                    if ins.mnemonic == "jz" and fact is not False:
                        pending.append((index+1, current))
                else:
                    pending.append((index+1, current))
        if not endings or len(endings) > 64:
            raise ValueError("CG 分组没有有限且完整的返回路径。")
        return endings, sorted(used)

    @staticmethod
    def _canonical(sequence):
        reset_all, last = False, {}
        for op,child,parent in sequence:
            if op == "reset" and child == 0:
                reset_all, last = True, {}
            else:
                last[child] = (op,child,parent)
        return (("reset",0,0),) * int(reset_all)+tuple(last[key] for key in sorted(last))

    def _chains(self, sequence):
        edges = {}
        for op, child, parent in sequence:
            if op == "in":
                edges[child] = parent
            elif child == 0:
                edges.clear()
            else:
                edges.pop(child, None)
        paths = []
        for parent in sorted(self.direct_parents):
            path = [parent]
            while path[-1] != 0:
                node = edges.get(path[-1])
                if node is None or node in path or len(path) > 16:
                    raise ValueError("CG 上层分组不完整、未归根或存在循环。")
                path.append(node)
            paths.append(tuple(path))
        return tuple(paths)

    def validate(self, stage):
        if stage is not self.stage or stage.backend is not self.backend:
            raise ValueError("CG 上层分组属于另一份目标创建流程。")
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        if self.native_groups is not None:
            if not isinstance(stage.executable,bytes) or not stage.executable:
                raise ValueError("CG 分组恢复的原生程序绑定已经变化。")
            self.native_groups.validate(stage.executable)
        self.closure.compile_snapshot(self.source)
        for address in self.closure.dependencies:
            if any(i.dirty or i.warning or not i.known for i in self.backend.spans[address].instructions):
                raise ValueError("CG 上层分组的原生指令已经变化。")
        if self._plan_signature() != self.plan_signature:
            raise ValueError("CG 上层分组的原生创建参数已经变化。")
        if tuple((d.name,d.args) for d in self.source.header.syscalls) != self.table:
            raise ValueError("CG 上层分组的原生调用表已经变化。")

    def _plan_signature(self):
        return deepcopy([(p["graph"],p["primitive"],p["creator"],p["creator_arguments"],
            p["creator_globals"],p["source_group_call"]) for p in self.stage.plans])

    def report(self):
        self.validate(self.stage)
        return dict(schema=SCHEMA, source_sha256=self.source.source_sha256,
            native_group_mutation=(self.native_groups.report() if self.native_groups is not None else None),
            direct_parent_groups=sorted(self.direct_parents), ancestor_groups=sorted(self.ancestors),
            paths=[list(p) for p in self.paths], root_sentinel=0,
            root_sentinel_owned=False, source_normalizers=deepcopy(self.proofs),
            source_creator_links=deepcopy(self.links), all_forward_paths_agree=True,
            helper_membership_effects_included=True,
            grouping_projected_after_creator_phase_specialization=True,
            unproven_cg_branch_assumed=False,
            original_normalizers_emitted=False, original_functions_patched=False,
            parent_and_ancestor_ownership_granted=False, inherited_membership_restored=False,
            runtime_verified=False)
