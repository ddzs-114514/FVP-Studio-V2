"""Bind an event-picture transaction to its own native wrapper/resource flow.

This is a discovery/binding stage, not permission to display an unprepared
picture. In particular, the legacy normal/large pair is NOT a modern buffer
pair. Geometry, hidden initialization and the transition owner must be bound
before a scene emitter may advertise CG support. No title/address whitelist,
foreign viewport or production portrait-size rule is used here.
"""
from collections import defaultdict
from copy import deepcopy
from pathlib import PurePosixPath
import re

from .native_background_backend import _dependencies, _literal, _substitute
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import _function_spans
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair


SCHEMA = "fvp-native-cg-backend/1"
RESOURCE = dict(kind="argument", index=0)


def _integers(value):
    if value.get("kind") == "literal":
        return {value["value"]} if type(value.get("value")) is int else set()
    return set().union(*(_integers(x) for x in value.get("operands", ())))


def _path_tokens(value):
    """Finite string concatenation, keeping the resource placeholder distinct."""
    kind = value.get("kind")
    if value == RESOURCE:
        return {(None,)}
    if kind == "literal" and isinstance(value.get("value"), str):
        return {(value["value"],)}
    if kind == "choice":
        result = set().union(*(_path_tokens(x) for x in value["operands"]))
    elif kind == "add" and len(value.get("operands", ())) == 2:
        left, right = value["operands"]
        result = {a+b for a in _path_tokens(left) for b in _path_tokens(right)}
    else:
        raise ValueError("CG 资源名还有未解析的变量或调用返回值。")
    if len(result) > 16 or any(len(x) > 16 for x in result):
        raise ValueError("CG 资源路径分支超出限定范围。")
    return result


def _resource_paths(value):
    result = set()
    for parts in _path_tokens(value):
        if parts.count(None) != 1:
            raise ValueError("CG 资源路径不是一个资源名加原生前后缀。")
        index = parts.index(None)
        prefix, suffix = "".join(parts[:index]), "".join(parts[index+1:])
        if (not re.fullmatch(r"[A-Za-z0-9_]+/", prefix)
                or len(suffix) > 64 or any(c in suffix for c in ("/", "\\", ":", "\0"))):
            raise ValueError("CG 资源路径不属于已绑定的根目录归档。")
        result.add((prefix, suffix))
    return result


class NativeCGBackend:
    """Source-byte-bound CG family and graph paths, still hidden-loader-gated."""
    def __init__(self, context):
        self.context = context
        self.source, self.analysis = context.document, context.analysis_document
        pair = validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        self.spans = {s.start: s for s in _function_spans(self.analysis)}
        self.strings = {s.start: tuple(i.text for i in s.instructions
            if i.mnemonic == "push_string" and i.text) for s in self.spans.values()}
        syscalls = {s.name: s.args for s in self.source.header.syscalls}
        if (len(syscalls) != len(self.source.header.syscalls)
                or any(syscalls.get(name) != count for name, count in
                    (("GraphLoad", 2), ("PrimSetOP", 3), ("PrimSetZ", 2)))):
            raise ValueError("CG 的图像和构图系统调用表未唯一确定。")
        self.flow = NativeFunctionFlow(self.analysis)
        self.traces = {}
        self._trace_cache = {}
        families = defaultdict(list)
        for span in self.spans.values():
            strings = self.strings[span.start]
            if (span.syscalls or span.locals or len(span.instructions) > 128
                    or len(strings) != 1 or len(span.calls) != 3):
                continue
            trace = self.flow.trace(span.start)
            if (trace["status"] != "proven_static_argument_flow"
                    or len(trace["global_writes"]) > 4
                    or any(w["value"] != _literal(True) for w in trace["global_writes"])
                    or trace["branches"] or len(trace["calls"]) != 3):
                continue
            calls = trace["calls"]
            if any(c["kind"] != "call" or c["address"] not in self.spans for c in calls):
                continue
            picture = [c for c in calls if self.spans[c["address"]].args in (8, 10)
                and c["arguments"] and c["arguments"][0] == _literal(strings[0])]
            if len(picture) != 1:
                continue
            target = picture[0]["address"]
            show = self.spans[target]
            # Geometry belongs to the event-picture wrapper, not an arbitrary
            # repeated sound or portrait-name wrapper which happens to load.
            if "PrimSetZ" not in show.syscalls or "PrimSetOP" not in show.syscalls and not show.calls:
                continue
            families[tuple(c["address"] for c in calls)].append((span, target))
        candidates, rejected = [], []
        for chain, wrappers in families.items():
            if len({self.strings[s.start][0] for s, _ in wrappers}) < 3 or len({a for _, a in wrappers}) != 1:
                continue
            address = wrappers[0][1]
            try:
                candidate = self._bind_show(address)
                candidates.append((chain, wrappers, candidate))
            except (ValueError, KeyError) as exc:
                rejected.append(dict(chain=list(chain), message=str(exc)))
        if len(candidates) != 1:
            error = ValueError("CG 的原生加载、大小与资源配对尚不能唯一确定。")
            error.native_details = dict(candidates=[list(c) for c, _, _ in candidates], rejected=rejected)
            raise error
        chain, wrappers, candidate = candidates[0]
        self.address = wrappers[0][1]
        self.arity = self.spans[self.address].args
        self.depth = candidate["depth"]
        self.primary_primitive = candidate["primary_primitive"]
        self.planes = candidate["planes"]
        self.routes = candidate["routes"]
        self.archive_selectors = {name: rows[0]["selector"] for name, rows in self.routes.items()}
        self.resource_graphs = candidate["resource_graphs"]
        self.resource_contexts = candidate["resource_contexts"]
        self.roots = candidate["roots"]
        self._parameters = candidate["parameters"]
        self.show_flow = candidate["show_flow"]
        self.resource_names = tuple(sorted({self.strings[s.start][0] for s, _ in wrappers}))
        self.gallery_global_ids = frozenset(w["slot"] for s, _ in wrappers
            for w in self.flow.trace(s.start)["global_writes"])
        self.closure = NativeScriptStateClosure(self.source, self.analysis, self.roots,
            runtime_context=context, max_functions=512, max_instructions=262144)
        self._report = dict(schema=SCHEMA, source_sha256=self.source.source_sha256,
            analysis_sha256=self.analysis.source_sha256, runtime_binding=pair,
            native_wrapper_chain=list(chain), native_show=self.address, native_arguments=self.arity,
            wrapper_count=len(wrappers), wrapper_resources=list(self.resource_names[:8]),
            native_primary_primitive=self.primary_primitive, native_default_depth=self.depth,
            native_geometry_planes=deepcopy(self.planes),
            routes=deepcopy(self.routes), resource_graphs=deepcopy(self.resource_graphs),
            resource_call_contexts=[dict(function=c["function"], arguments=deepcopy(c["arguments"]),
                literal_globals=deepcopy(c["literal_globals"])) for c in self.resource_contexts],
            fresh_load_parameters=deepcopy(self._parameters), native_show_flow=self.show_flow,
            resource_argument_flows=deepcopy(self.traces), source_dependencies=self.closure.describe(),
            normal_large_resources_distinct=len({r["suffix"] for r in self.resource_graphs}) > 1,
            game_name_switch_used=False, original_functions_patched=False,
            named_wrapper_gallery_flags_not_emitted=True,
            source_size_rule_changed=False, image_resampled=False,
            hidden_initialization_proven=False, transition_owner_bound=False,
            scene_export_connected=False, runtime_verified=False)

    def _bind_show(self, address):
        span = self.spans[address]
        generic = self.flow.trace(address, max_joined_values=128)
        if generic["status"] != "proven_static_argument_flow":
            raise ValueError("CG 构图参数流尚未确定。")
        primary = [c for c in generic["calls"] if c.get("name") == "PrimSetZ"
            and len(c["arguments"]) == 2 and 6 in _dependencies(c["arguments"][1])]
        primitives = {c["arguments"][0].get("value") for c in primary
            if c["arguments"][0].get("kind") == "literal" and type(c["arguments"][0].get("value")) is int}
        defaults = set().union(*(_integers(c["arguments"][1]) for c in primary))
        defaults = {n for n in defaults if n > 0}
        if len(primitives) != 1 or len(defaults) != 1:
            raise ValueError("CG 原生默认景深与主图元不能唯一确定。")
        depth = next(iter(defaults))
        planes = {}
        for c in generic["calls"]:
            if c.get("name") != "PrimSetZ":
                continue
            primitive, z = c["arguments"]
            if primitive.get("kind") != "literal" or type(primitive.get("value")) is not int:
                raise ValueError("CG 构图图元不是目标自己的固定槽。")
            p = primitive["value"]
            plane = depth if p in primitives else z.get("value") if z.get("kind") == "literal" else None
            if type(plane) is not int or plane <= 0 or p in planes and planes[p] != plane:
                raise ValueError("CG 的普通图与大图景深尚不能唯一确定。")
            planes[p] = plane
        # These are the exact two native wrapper layouts recognised here.
        # The argument FLOW, graph suffixes and archive routes are proven for
        # every target; arity is a version recipe, never a title switch.
        parameters = [RESOURCE, _literal(0), _literal(1), _literal(0), _literal(0),
                      _literal(0), _literal(depth), _literal(0)]
        if span.args == 10:
            parameters += [_literal(None), _literal(0)]
        routes, graph_rows, roots, proofs, contexts = defaultdict(list), [], {address}, {}, []
        variants = (0, 1, 2) if span.args == 10 else (None,)
        for selector in variants:
            args = list(parameters)
            if span.args == 10:
                args[9] = _literal(selector)
            rows, used, trace, specialized = self._resource_tree(address, tuple(args))
            if not rows:
                raise ValueError("CG 原生资源名没有到达图像加载调用。")
            namespaces = {r["prefix"] for r in rows}
            if len(namespaces) != 1:
                raise ValueError("CG 的一个归档选择还有多个未分离的资源包。")
            prefix = next(iter(namespaces))
            archive = prefix[:-1].casefold()+".bin"
            entry = dict(selector=selector, prefix=prefix,
                resources=sorted({r["suffix"] for r in rows}))
            # Some versions ignore the selector and use the same archive for
            # every value. One native route is sufficient; do not invent bins.
            if not routes[archive]:
                routes[archive].append(entry)
                graph_rows.extend(rows)
                roots.update(used)
                proofs[str(selector)] = trace
                contexts.extend(specialized)
        self.traces[address] = proofs
        return dict(depth=depth, primary_primitive=next(iter(primitives)), planes=planes,
            routes=dict(routes), resource_graphs=graph_rows, roots=sorted(roots),
            resource_contexts=contexts,
            parameters=parameters, show_flow=generic)

    def _resource_tree(self, address, arguments):
        rows, roots, active, visited, contexts = [], set(), set(), set(), []
        def visit(a, values, globals_):
            global_key = tuple(sorted(globals_.items()))
            key = (a, repr(values), global_key)
            if key in visited:
                return
            if a in active or len(active) > 8 or len(visited) >= 128:
                raise ValueError("CG 图像加载调用链超出限定范围。")
            visited.add(key)
            active.add(a)
            roots.add(a)
            literals = {i: v["value"] for i, v in enumerate(values) if v.get("kind") == "literal"
                and (v["value"] is None or type(v["value"]) in {int, bool, str})}
            non_nil = tuple(i for i, v in enumerate(values) if 0 in _dependencies(v))
            cache_key = (a, repr(literals), non_nil, global_key)
            if cache_key not in self._trace_cache:
                self._trace_cache[cache_key] = self.flow.trace(a, literal_arguments=literals,
                    non_nil_arguments=non_nil,
                    track_global_literals=True, literal_globals=globals_,
                    max_joined_values=128)
            trace = self._trace_cache[cache_key]
            if trace["status"] != "proven_static_argument_flow":
                raise ValueError("CG 图像加载参数还存在未解析的路径。")
            self.traces.setdefault(a, trace)
            contexts.append(dict(function=a, arguments=deepcopy(values), literal_globals=dict(globals_), trace=trace))
            for call in trace["calls"]:
                args = tuple(_substitute(v, values) for v in call["arguments"])
                if call.get("name") == "GraphLoad" and 0 in _dependencies(args[1]):
                    graph = args[0]
                    if graph.get("kind") != "literal" or type(graph.get("value")) is not int or graph["value"] < 0:
                        raise ValueError("CG 的目标图像槽未唯一绑定。")
                    for prefix, suffix in sorted(_resource_paths(args[1])):
                        row = dict(graph=graph["value"], prefix=prefix, suffix=suffix,
                            function=a, offset=call["offset"])
                        if row not in rows:
                            rows.append(row)
                elif call["kind"] == "call" and any(0 in _dependencies(v) for v in args):
                    visit(call["address"], args, call["literal_globals_before_call"])
            active.remove(a)
            return trace
        top = visit(address, arguments, {})
        return rows, roots, top, contexts

    def resource_plan(self, archive, resource):
        """Names/slots only: an unsafe raw show call is deliberately not emitted."""
        archive = archive.casefold() if isinstance(archive, str) else None
        if (archive not in self.routes or not isinstance(resource, str) or not resource
                or len(resource) > 1024 or any(c in resource for c in ("/", "\\", ":", "\0"))
                or resource in {".", ".."}
                or PurePosixPath(resource).name != resource):
            raise ValueError("CG 资源或目标归档不属于当前原生调用链。")
        entry = self.routes[archive][0]
        return dict(archive=archive, selector=entry["selector"], native_show=self.address,
            resources=[dict(suffix=suffix, resource=resource+suffix) for suffix in entry["resources"]],
            geometry_not_yet_prepared=True, hidden_initialization_required=True,
            scene_export_connected=False, runtime_verified=False)

    def report(self):
        return deepcopy(self._report)
