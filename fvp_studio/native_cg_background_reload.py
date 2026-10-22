"""Reconstruct a compiler-owned BG after CG overwrites its native slot.

The source BG entry supplies the resource route, sprite initialization and
runtime parent selection. Only copies are used: inherited UI/portrait helpers,
foreign planes and waits are isolated. This is not acquisition of engine
threads/parents, reconstruction of an inherited story, or a complete exporter.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_background_backend import _literal, _substitute
from .native_background_layers import NativeBackgroundLayers
from .native_cg_staged_load import NativeCGStagedLoad
from .native_script_state import validate_native_script_pair
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-cg-background-reload/1"
RESOURCE = "FVP_OWNED_BG_RELOAD"
PRIMITIVE_WRITES = {"PrimSetNull": 1, "PrimSetSprt": 4, "PrimGroup": 2,
    "PrimGroupIn": 2, "PrimSetXY": 3, "PrimSetOP": 3, "PrimSetZ": 2,
    "PrimSetRS": 3, "PrimSetRS2": 4, "PrimSetAlpha": 2, "PrimSetDraw": 2}


def _facts(value):
    if value.get("kind") == "choice":
        return set().union(*(_facts(v) for v in value.get("operands", ())))
    if value.get("kind") in {"add", "sub"} and len(value.get("operands", ())) == 2:
        left,right = (_facts(v) for v in value["operands"])
        result = {a+b if value["kind"] == "add" else a-b for a in left for b in right}
        if len(result) <= 16 and all(0 <= v < 2**31 for v in result):
            return result
    if value.get("kind") == "literal" and type(value.get("value")) is int:
        return {value["value"]}
    raise ValueError("背景重载的图像／图层槽还依赖未知状态。")


def _returns(value):
    result = {value["offset"]} if value.get("kind") == "call_return" else set()
    return result | set().union(*(_returns(v) for k in ("arguments", "operands")
                                 for v in value.get(k, ())))


@dataclass(frozen=True)
class NativeCGBackgroundReloadLibrary:
    code: bytes
    report: dict


@dataclass(frozen=True)
class NativeCGBackgroundRestore:
    """The current SCENE BG resource, not a remembered original-story image."""
    binding: object
    archive: str
    resource: str

    def compile(self, *, append_offset=None):
        return self.binding.compile(self.archive,self.resource,append_offset=append_offset)


class NativeCGBackgroundReload:
    """Bind exact BG default calls; never use a CG loader to invent a BG."""
    def __init__(self, layers, stage):
        if (not isinstance(layers, NativeBackgroundLayers)
                or not isinstance(stage, NativeCGStagedLoad)
                or layers.context is not stage.context):
            raise ValueError("背景重载必须使用同一目标的背景与 CG 调用链。")
        self.layers, self.stage, self.context = layers, stage, stage.context
        self.source, self.analysis = stage.source, stage.analysis
        self.plans = {}
        # A source with an independent blur image needs a complete paired
        # restoration, not silently discarding that plane. Non-aliased targets
        # already have the retained-underlay path and need no reload.
        if set(layers.layers) != {"background"}:
            raise ValueError("背景重载暂需单一原生背景层；独立模糊层应使用保留式交接。")
        self.graph = layers.layers["background"]["graph"]
        self.primitive = layers.layers["background"]["primitive"]
        for archive in layers.backend.archive_selectors:
            call = layers.backend.compile_load(self.source, resource_name=RESOURCE,
                archive_name=archive, duration_ms=0, transition=False).report["calls"][0]
            self.plans[archive] = self._bind(call)

    def capture(self, archive, resource):
        self._validate()
        self.layers.backend.compile_load(self.source,resource_name=resource,
            archive_name=archive,duration_ms=0,transition=False)
        return NativeCGBackgroundRestore(self,archive.strip().casefold(),resource)

    def _bind(self, entry):
        records, states, active, effects = {}, {}, set(), []
        flow, spans = self.layers.flow, self.layers.spans

        def visit(address, values, globals_, parents=()):
            if address in parents or len(parents) > 12 or len(states) >= 128:
                raise ValueError("背景重载调用链出现递归或超出限定范围。")
            key = address, repr(values), repr(sorted(globals_.items()))
            if key in states:
                return states[key]
            span = spans[address]
            trace = flow.trace(address, literal_arguments={i:v["value"] for i,v in enumerate(values)
                if v.get("kind") == "literal"}, track_global_literals=True,
                literal_globals=globals_, max_joined_values=128)
            if trace["status"] != "proven_static_argument_flow":
                raise ValueError("背景重载的原生参数流未确定。")
            retained, removed, used = set(), set(), []
            for call in trace["calls"]:
                args = tuple(_substitute(v, values) for v in call["arguments"])
                if call["kind"] == "call":
                    # Source-bound inventory already classified these helpers
                    # as inherited UI/portrait refresh, not fresh BG resources.
                    if (call["address"] in self.layers.non_resource_nil_calls
                            and all(v == _literal(None) for v in args)):
                        keep = False
                    else:
                        keep = visit(call["address"], args,
                            call.get("literal_globals_before_call", {}), (*parents, address))
                else:
                    name = call["name"]
                    keep = False
                    if name == "GraphLoad" or name in PRIMITIVE_WRITES:
                        expected = 2 if name == "GraphLoad" else PRIMITIVE_WRITES[name]
                        if len(args) != expected:
                            raise ValueError("背景重载系统调用参数数量不符。")
                        owned = self.graph if name == "GraphLoad" else self.primitive
                        handles = _facts(args[0])
                        if owned in handles and handles != {owned}:
                            raise ValueError("背景重载可能修改场景不拥有的图层。")
                        keep = handles == {owned}
                        if keep and name == "PrimSetSprt" and args[1] != _literal(self.graph):
                            raise ValueError("背景重载的原生图层与资源槽不配对。")
                        if keep:
                            effects.append(dict(function=address, offset=call["offset"],
                                name=name, arguments=deepcopy(args)))
                (retained if keep else removed).add(call["offset"])
                if keep:
                    used.extend(args)
            if not retained:
                states[key] = False
                return False
            # Nil stubs may not supply input to a retained call, a native
            # condition or a global assignment. Preserve native branch tests,
            # especially the BG parent's runtime 8/12 selection in old ABIs.
            used.extend(b["condition"] for b in trace.get("branches", ()))
            used.extend(w["value"] for w in trace.get("global_writes", ()))
            if set().union(*(_returns(v) for v in used)) & removed:
                raise ValueError("背景重载依赖被隔离的辅助调用返回值。")
            if address in records and set(records[address]["retained_sites"]) != retained:
                raise ValueError("背景重载同一函数需要不一致的参数专用副本。")
            records[address] = dict(deepcopy(trace), retained_sites=sorted(retained),
                isolated_auxiliary_sites=sorted(removed))
            active.add(address)
            states[key] = True
            return True

        if not visit(entry["address"], tuple(_literal(v) for v in entry["arguments"]), {}):
            raise ValueError("背景重载没有保留下原生资源加载。")
        loads = [e for e in effects if e["name"] == "GraphLoad"
                 and RESOURCE in repr(e["arguments"][1])]
        sprites = [e for e in effects if e["name"] == "PrimSetSprt"]
        if len({e["offset"] for e in loads}) != 1 or len({e["offset"] for e in sprites}) != 1:
            raise ValueError("背景资源和原生图元创建没有唯一配对。")
        # Copies retain the native conditional VM assignments. The same
        # helper can be reached with different parent arguments: a specialised
        # trace of its LAST invocation would miss writes in another branch.
        # Snapshot the complete copied functions, not just one parameter view.
        instructions = [i for a in active for i in spans[a].instructions]
        if any(i.mnemonic == "pop_global_table" for i in instructions):
            raise ValueError("背景重载包含尚未隔离的全局表写入。")
        writes = sorted({i.operands["value"] for i in instructions if i.mnemonic == "pop_global"})
        total = self.source.header.non_volatile_globals+self.source.header.volatile_globals
        if any(not 0 <= g < total for g in writes):
            raise ValueError("背景重载的状态槽超出当前脚本声明。")
        return dict(creator=entry["address"], creator_flows={str(a):t for a,t in records.items()},
            arguments=deepcopy(entry["arguments"]), globals=writes,
            functions=sorted(active), effects=effects)

    def _validate(self):
        self.layers.validate()
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        for plan in self.plans.values():
            for address in plan["functions"]:
                span = self.layers.spans[address]
                if (self.source.original_bytes[span.start:span.end] != self.analysis.original_bytes[span.start:span.end]
                        or any(i.dirty or i.warning or not i.known for i in span.instructions)):
                    raise ValueError("背景重载绑定的原生证据已改变。")

    def compile(self, archive, resource, *, append_offset=None):
        self._validate()
        # Reuse the resource-name/namespace validation of the target BG ABI.
        call = self.layers.backend.compile_load(self.source, resource_name=resource,
            archive_name=archive, duration_ms=0, transition=False).report["calls"][0]
        key = archive.strip().casefold()
        plan = self.plans[key]
        base = len(self.source.original_bytes) if append_offset is None else append_offset
        if type(base) is not int or not len(self.source.original_bytes) <= base < 2**32:
            raise ValueError("背景重载库必须附加到当前运行脚本之后。")
        code = bytearray(b"\x06\0\0\0\0")
        native, copied = self.stage._private_creator(code, plan, base)
        entry = base+len(code)
        code.extend(b"\x01\0\0"+b"".join(_push_global(g) for g in plan["globals"]))
        code.extend(self.stage.syscall("PrimSetDraw", [self.primitive,0]))
        code.extend(b"".join(_encode_push(v,self.source.encoding) for v in call["arguments"])+_call(native))
        # Native sprite initialization is retained verbatim. There is no yield
        # between that initialization and hiding it for the caller's reveal.
        code.extend(self.stage.syscall("PrimSetDraw", [self.primitive,0]))
        code.extend(b"".join(_pop_global(g) for g in reversed(plan["globals"]))+b"\x04\x00")
        if base+len(code) >= 2**32:
            raise ValueError("背景重载库超出原生地址范围。")
        struct.pack_into("<I",code,1,base+len(code)-1)
        return NativeCGBackgroundReloadLibrary(bytes(code), dict(schema=SCHEMA,
            source_sha256=self.source.source_sha256, append_offset=base, entry_address=entry,
            archive=key, resource=resource, graph=self.graph, primitive=self.primitive,
            native_entry=plan["creator"], private_entry=native, native_copy=copied,
            source_effects=deepcopy(plan["effects"]), global_snapshot_ids=list(plan["globals"]),
            global_snapshot_scope="all_scalar_assignments_in_complete_private_functions",
            source_default_geometry_and_runtime_parent_selection_preserved=True,
            hidden_at_return=True, script_waits_before_hidden=0, native_dissolves=0,
            camera_modified=False, portraits_modified=False, original_functions_patched=False,
            inherited_story_images_restored=False, engine_threads_and_parents_owned=False,
            scene_export_connected=False, runtime_verified=False,
            code_size=len(code), code_sha256=hashlib.sha256(code).hexdigest()))
