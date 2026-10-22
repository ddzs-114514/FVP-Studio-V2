"""Source-bound BG Graph/Prim ownership, not a sprite-default assumption.

Older scripts can use the SAME Graph/Prim for BG and CG. Merely restoring
Draw on that handle cannot restore the overwritten background image. This
inventory deliberately keeps graph and primitive namespaces separate.
"""
from copy import deepcopy

from .native_background_backend import NativeBackgroundBackend, _literal, _substitute
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import _function_spans
from .native_script_state import validate_native_script_pair


SCHEMA = "fvp-native-background-layers/1"
_RESOURCE = "FVP_OWNED_BACKGROUND_RESOURCE"
_CORE = {"GraphLoad", "PrimSetSprt", "PrimGroupIn", "PrimGroup"}


def _int(value, depth=0):
    if depth > 16:
        raise ValueError("背景句柄表达式超出限定范围。")
    if value.get("kind") in {"add", "sub"} and len(value.get("operands", ())) == 2:
        a,b = (_int(v, depth+1) for v in value["operands"])
        result = a+b if value["kind"] == "add" else a-b
        if result < 0:
            raise ValueError("背景句柄不能是负数。")
        return result
    if value.get("kind") != "literal" or type(value.get("value")) is not int or value["value"] < 0:
        raise ValueError("背景图像／图层句柄尚未确定。")
    return value["value"]


def _resource(value):
    if value.get("kind") == "literal" and isinstance(value.get("value"), str):
        return _RESOURCE in value["value"]
    return any(_resource(v) for key in ("operands", "arguments") for v in value.get(key, ()))


class NativeBackgroundLayers:
    def __init__(self, context):
        self.context = context
        self.source, self.analysis = context.document, context.analysis_document
        validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        self.backend = context.abi.native_background_backend
        if (not isinstance(self.backend, NativeBackgroundBackend)
                or self.backend._source is not self.source or self.backend._analysis is not self.analysis):
            raise ValueError("背景图层必须来自当前目标已绑定的背景调用链。")
        self.spans = {s.start:s for s in _function_spans(self.analysis)}
        self.flow = NativeFunctionFlow(self.analysis)
        self.used, self.layers = set(), {}
        self.non_resource_nil_calls = set()
        self._core_cache = {}
        for archive in self.backend.archive_selectors:
            recipe = self.backend.compile_load(self.source, resource_name=_RESOURCE,
                blur_resource_name=_RESOURCE if self.backend.blur_target is not None else None,
                archive_name=archive, duration_ms=0, transition=False)
            roles = ("background", "blur") if self.backend.blur_target is not None else ("background",)
            for role, entry in zip(roles, recipe.report["calls"]):
                layer = self._bind(entry)
                previous = self.layers.get(role)
                if previous and (previous["graph"], previous["primitive"]) != (layer["graph"], layer["primitive"]):
                    raise ValueError("不同归档的背景使用不同图层，尚不能统一交接。")
                if previous:
                    previous["archive_evidence"][archive] = layer
                else:
                    self.layers[role] = dict(layer, archive_evidence={archive:deepcopy(layer)})
        self.validate()

    def _core_possible(self, address, parents=()):
        if address in self._core_cache:
            return self._core_cache[address]
        if address in parents:
            return False
        span = self.spans.get(address)
        if span is None or len(parents) > 16:
            raise ValueError("背景图层依赖超出已确认的函数边界。")
        result = bool(set(span.syscalls) & _CORE) or any(
            self._core_possible(a, (*parents, address)) for a in span.calls)
        self._core_cache[address] = result
        return result

    def _bind(self, entry):
        calls, visited = [], set()
        def visit(address, values, facts, parents=()):
            if address in parents or len(parents) > 16 or len(visited) >= 256:
                raise ValueError("背景图层参数流出现递归或超出限定范围。")
            key = (address, repr(values), repr(sorted(facts.items())))
            if key in visited:
                return
            visited.add(key)
            self.used.add(address)
            trace = self.flow.trace(address,
                literal_arguments={i:v["value"] for i,v in enumerate(values) if v.get("kind") == "literal"},
                non_nil_arguments=tuple(i for i,v in enumerate(values) if v.get("kind") != "literal"),
                track_global_literals=True, literal_globals=facts, max_joined_values=128)
            if trace["status"] != "proven_static_argument_flow":
                raise ValueError("背景图层的原生参数流尚未确定。")
            for call in trace["calls"]:
                arguments = tuple(_substitute(v, values) for v in call["arguments"])
                if call["kind"] == "call":
                    # Nil-only entry helpers operate on inherited UI/portrait
                    # state, not on the fresh resource marker. Do not mistake
                    # that unknown state for a background sprite. If the marker
                    # was stored in a literal global, the helper IS relevant.
                    facts = call.get("literal_globals_before_call", {})
                    if (not any(_resource(v) for v in arguments)
                            and not any(_resource(_literal(v)) for v in facts.values())
                            and all(v.get("kind") == "literal" and v.get("value") is None for v in arguments)):
                        self.non_resource_nil_calls.add(call["address"])
                        continue
                    if self._core_possible(call["address"]):
                        visit(call["address"], arguments, facts, (*parents,address))
                elif call.get("name") in _CORE:
                    calls.append(dict(name=call["name"], arguments=arguments, function=address, offset=call["offset"]))
        visit(entry["address"], tuple(_literal(v) for v in entry["arguments"]), {})
        loads = [c for c in calls if c["name"] == "GraphLoad" and len(c["arguments"]) == 2
                 and _resource(c["arguments"][1])]
        graphs = {_int(c["arguments"][0]) for c in loads}
        if len(graphs) != 1:
            raise ValueError("背景资源没有唯一的原生 Graph 槽。")
        graph = next(iter(graphs))
        sprites = [c for c in calls if c["name"] == "PrimSetSprt" and len(c["arguments"]) == 4
                   and _int(c["arguments"][1]) == graph]
        primitives = {_int(c["arguments"][0]) for c in sprites}
        if len(primitives) != 1:
            raise ValueError("背景 Graph 槽没有唯一配对的原生图层。")
        primitive = next(iter(primitives))
        groups = [c for c in calls if c["name"] in {"PrimGroupIn", "PrimGroup"}
                  and len(c["arguments"]) == 2 and _int(c["arguments"][0]) == primitive]
        return dict(graph=graph, primitive=primitive, native_entry=entry["address"],
            resource_load_sites=deepcopy(loads), sprite_sites=deepcopy(sprites),
            parent_groups=sorted({_int(c["arguments"][1]) for c in groups}),
            parent_sites=deepcopy(groups), reachability="resource_and_literal_creator_paths",
            complete_parent_or_thread_ownership_proven=False,
            default_draw_or_alpha_assumed=False)

    def validate(self):
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        for address in self.used:
            span = self.spans[address]
            if (self.source.original_bytes[span.start:span.end] != self.analysis.original_bytes[span.start:span.end]
                    or any(i.dirty or i.warning or not i.known for i in span.instructions)):
                raise ValueError("背景图层绑定的原生证据已变化。")

    def report(self):
        self.validate()
        return dict(schema=SCHEMA, source_sha256=self.source.source_sha256,
            layers=deepcopy(self.layers), native_functions=sorted(self.used),
            omitted_nil_only_inherited_state_helpers=sorted(self.non_resource_nil_calls),
            game_name_switch_used=False, runtime_verified=False)

    def cg_handoff(self, *, cg_graphs, cg_primitives):
        self.validate()
        graph_set, prim_set = set(cg_graphs), set(cg_primitives)
        collisions = [dict(role=role, graph=layer["graph"], primitive=layer["primitive"],
                           graph_overwritten=layer["graph"] in graph_set,
                           primitive_overwritten=layer["primitive"] in prim_set)
            for role, layer in self.layers.items()
            if layer["graph"] in graph_set or layer["primitive"] in prim_set]
        return dict(schema="fvp-native-cg-underlay-ownership/1", layers=deepcopy(self.layers),
            cg_graphs=sorted(graph_set), cg_primitives=sorted(prim_set), collisions=collisions,
            restoration="reload_native_background" if collisions else "retain_images_and_restore_draw",
            background_reload_required=bool(collisions),
            shared_slot_restore_connected=False, scene_export_connected=False, runtime_verified=False)
