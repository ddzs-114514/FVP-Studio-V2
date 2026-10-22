"""Compile a source-bound CG preparation that returns with every plane hidden.

Target-owned primitive stop calls precede the proven GraphLoad leaf and
isolated copies of its native sprite/group creator. Named gallery/old-scene
refreshes are omitted.
There is no fade, transition/cache commit, scene hook or disk installation in
this stage. A caller must own these CG slots and the camera before using it.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_background_backend import _literal, _substitute
from .native_cg_backend import RESOURCE, _resource_paths
from .native_cg_motion_quiescence import NativeCGMotionQuiescence
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-cg-staged-load/1"
SETTERS = {"PrimSetOP":3, "PrimSetXY":3, "PrimSetZ":2, "PrimSetRS":3,
           "PrimSetAlpha":2, "PrimSetDraw":2, "V3DSet":3}
GROUP_EFFECTS = frozenset({"PrimGroup", "PrimGroupIn"})
CREATOR_EFFECTS = frozenset({"PrimSetSprt", *GROUP_EFFECTS, "PrimSetAlpha", "PrimSetDraw",
    "PrimSetXY", "PrimSetZ", "PrimSetOP", "PrimSetRS", "FloatToInt"})


def _constant(value):
    if value.get("kind") != "literal" or not (value.get("value") is None or type(value["value"]) in {int, bool, str}):
        raise ValueError("CG 加载还有未确定的原生参数。")
    return value["value"]


def _resolved_branches(trace):
    return all(b["condition"].get("kind") == "literal" and type(b["condition"].get("value")) is bool
               for b in trace.get("branches", ()))


@dataclass(frozen=True)
class NativeCGPreparation:
    code: bytes
    report: dict


class NativeCGStagedLoad:
    def __init__(self, context, backend, geometry, *, executable=None):
        if (backend.source is not context.document or backend.analysis is not context.analysis_document
                or geometry.planes != backend.planes or geometry.primitive.camera != (0, 0, 0)):
            raise ValueError("CG 准备流程与目标或几何绑定不一致。")
        self.context, self.backend, self.geometry = context, backend, geometry
        self.executable = executable
        self.source, self.analysis = backend.source, backend.analysis
        self.syscalls = {s.name:(n, s.args) for n, s in enumerate(self.source.header.syscalls)}
        if (len(self.syscalls) != len(self.source.header.syscalls)
                or any(self.syscalls.get(n, (None, None))[1] != c for n, c in SETTERS.items())
                or self.syscalls.get("PrimSetSprt", (None, None))[1] != 4):
            raise ValueError("CG 隐藏、构图或原生图元创建的调用表未绑定。")
        plans = []
        for row in backend.resource_graphs:
            possible, rejected = [], []
            for parent in backend.resource_contexts:
                calls = parent["trace"]["calls"]
                if (len(calls) != 2 or calls[0]["kind"] != "call" or calls[0]["address"] != row["function"]
                        or calls[1]["kind"] != "call" or not _resolved_branches(parent["trace"])):
                    continue
                load_args = tuple(_substitute(v, parent["arguments"]) for v in calls[0]["arguments"])
                create_args = tuple(_substitute(v, parent["arguments"]) for v in calls[1]["arguments"])
                globals_ = calls[0]["literal_globals_before_call"]
                literals = {i:v["value"] for i,v in enumerate(load_args) if v.get("kind") == "literal"}
                leaf = backend.flow.trace(row["function"], literal_arguments=literals,
                    non_nil_arguments=tuple(i for i,v in enumerate(load_args) if v.get("kind") != "literal"),
                    track_global_literals=True, literal_globals=globals_, max_joined_values=128)
                if leaf["status"] != "proven_static_argument_flow" or not _resolved_branches(leaf):
                    continue
                native = [dict(c, arguments=[_substitute(v, load_args) for v in c["arguments"]]) for c in leaf["calls"]]
                if (leaf["global_writes"] or len(native) != 3
                        or [c.get("name") for c in native] != ["PrimSetNull", "GraphLoad", "GraphLoad"]
                        or any(c["arguments"][0] != _literal(row["graph"]) for c in native)
                        or native[1]["arguments"][1] != _literal(None)):
                    continue
                try:
                    if _resource_paths(native[2]["arguments"][1]) != {(row["prefix"], row["suffix"])}:
                        continue
                    create_values = tuple(_constant(v) for v in create_args)
                    creator_facts = calls[1]["literal_globals_before_call"]
                    effects, roots, traces, writes = self._creator(calls[1]["address"], create_args,
                        creator_facts, row["graph"])
                    read_ids = {g["slot"] for trace in traces.values() for g in trace.get("global_reads", ())}
                    creator_globals = {g:creator_facts[g] for g in sorted(read_ids & creator_facts.keys())}
                    checked, _, _, _ = self._creator(calls[1]["address"], create_args, creator_globals, row["graph"])
                    if checked != effects:
                        raise ValueError("CG 创建依赖未显式设置的上层状态。")
                    sprite = [c for c in effects if c["name"] == "PrimSetSprt"]
                    groups = [c for c in effects if c["name"] in GROUP_EFFECTS]
                    if (len(sprite) != 1 or len(groups) != 1
                            or sprite[0]["arguments"][:2] != [_literal(row["graph"])]*2):
                        continue
                    needed = {i.operands["value"] for i in backend.spans[row["function"]].instructions
                              if i.mnemonic == "push_global"}
                    if not needed <= globals_.keys():
                        continue
                    # These route values are restored immediately after native
                    # loading; no gallery or preference global is fabricated.
                    routing = {g: globals_[g] for g in sorted(needed)}
                    if (set(routing) | set(creator_globals) | writes) & backend.gallery_global_ids:
                        raise ValueError("CG 准备路径与原作鉴赏标记相冲突。")
                    closure = NativeScriptStateClosure(self.source, self.analysis, sorted({row["function"], *roots}),
                        runtime_context=context, max_functions=64, max_instructions=16384)
                    possible.append(dict(graph=row["graph"], primitive=row["graph"], prefix=row["prefix"],
                        suffix=row["suffix"], load=row["function"], load_arguments=load_args,
                        creator=calls[1]["address"], creator_arguments=create_values,
                        route_globals=routing, creator_globals=creator_globals, active_creator_global_writes=sorted(writes),
                        creator_effects=effects, creator_flows=traces, closure=closure,
                        source_sprite_graph_link=sprite[0], source_group_call=groups[0]))
                except (ValueError, KeyError) as exc:
                    rejected.append(dict(parent=parent["function"], creator=calls[1]["address"], reason=str(exc),
                        details=getattr(exc, "native_details", None)))
                    continue
            unique = {(p["load"], repr(p["load_arguments"]), p["creator"], p["creator_arguments"],
                       tuple(sorted(p["route_globals"].items())), tuple(sorted(p["creator_globals"].items()))):p for p in possible}
            if len(unique) != 1:
                error = ValueError("CG 图像加载、图元创建及无等待准备流程尚未唯一配对。")
                error.native_details = dict(resource=row, candidate_count=len(unique), rejected=rejected)
                raise error
            plans.append(next(iter(unique.values())))
        self.plans = tuple(plans)
        self.motion_quiescence = NativeCGMotionQuiescence(context, backend, executable=executable)

    def _creator(self, address, values, globals_, graph):
        effects, roots, traces, writes = [], set(), {}, set()
        def core_possible(a, seen=()):
            if a in seen or len(seen) > 6:
                return False
            span = self.backend.spans[a]
            return (any(n in {"PrimSetSprt", *GROUP_EFFECTS} for n in span.syscalls)
                    or any(core_possible(child, (*seen, a)) for child in span.calls))
        def returned_sites(v):
            result = {v["offset"]} if v.get("kind") == "call_return" else set()
            return result | set().union(*(returned_sites(c) for key in ("operands", "arguments") for c in v.get(key, ())))
        def same_core_sequence(a, trace, retained):
            span = self.backend.spans[a]
            by_offset = {i.offset:n for n,i in enumerate(span.instructions)}
            conditions = {b["offset"]:b["condition"] for b in trace["branches"]}
            pending, visited, endings = [(1, ())], set(), set()
            while pending:
                n, sequence = pending.pop()
                if (n, sequence) in visited:
                    continue
                visited.add((n, sequence))
                if len(visited) > 2048 or n >= len(span.instructions):
                    raise ValueError("CG 创建分支路径越界。")
                ins = span.instructions[n]
                if ins.offset in retained:
                    sequence += (ins.offset,)
                if ins.mnemonic in {"ret", "retv"}:
                    endings.add(sequence)
                elif ins.mnemonic == "jmp":
                    pending.append((by_offset[ins.operands["target"]], sequence))
                elif ins.mnemonic == "jz":
                    value = conditions.get(ins.offset, {})
                    constant = value.get("value") if value.get("kind") == "literal" and type(value.get("value")) is bool else None
                    if constant is not True:
                        pending.append((by_offset[ins.operands["target"]], sequence))
                    if constant is not False:
                        pending.append((n+1, sequence))
                else:
                    pending.append((n+1, sequence))
            if len(endings) != 1:
                raise ValueError("未确定分支会改变 CG 创建或分组顺序。")
        def visit(a, arguments, facts, parents=()):
            if a in parents or len(parents) > 6 or len(traces) >= 64:
                raise ValueError("CG 图元创建调用链越界。")
            literals = {i:v["value"] for i,v in enumerate(arguments) if v.get("kind") == "literal"}
            trace = self.backend.flow.trace(a, literal_arguments=literals,
                track_global_literals=True, literal_globals=facts, max_joined_values=128)
            if trace["status"] != "proven_static_argument_flow":
                error = ValueError("CG 创建路径含未确定分支。")
                error.native_details = dict(function=a, blockers=trace.get("blockers"),
                    unresolved_branches=[b for b in trace.get("branches", ())
                        if b["condition"].get("kind") != "literal" or type(b["condition"].get("value")) is not bool])
                raise error
            roots.add(a)
            trace = deepcopy(trace)
            traces[str(a)+":"+repr(literals)] = trace
            writes.update(w["slot"] for w in trace["global_writes"])
            retained, removed, used_values = set(), set(), []
            for c in trace["calls"]:
                args = tuple(_substitute(v, arguments) for v in c["arguments"])
                if c["kind"] == "call":
                    if _literal(graph) in args and core_possible(c["address"]):
                        retained.add(c["offset"])
                        used_values.extend(args)
                        visit(c["address"], args, c["literal_globals_before_call"], (*parents, a))
                    else:
                        removed.add(c["offset"])
                    continue
                name = c["name"]
                if name not in CREATOR_EFFECTS or (name != "FloatToInt" and _literal(graph) not in args):
                    removed.add(c["offset"])
                    continue
                if name in GROUP_EFFECTS:
                    if any(v.get("kind") != "literal" for v in args):
                        raise ValueError("CG 分组参数还依赖原剧情状态。")
                elif name != "FloatToInt" and args[0] != _literal(graph):
                    raise ValueError("CG 创建修改了其他图元。")
                retained.add(c["offset"])
                used_values.extend(args)
                effects.append(dict(name=name, arguments=list(args), offset=c["offset"], function=a))
            if set().union(*(returned_sites(v) for v in used_values)) & removed:
                raise ValueError("CG 创建参数依赖被隔离的旧剧情辅助调用。")
            same_core_sequence(a, trace, retained)
            trace["retained_sites"] = sorted(retained)
            trace["isolated_auxiliary_sites"] = sorted(removed)
        visit(address, values, globals_)
        return effects, roots, traces, writes

    def _private_creator(self, output, plan, base):
        """Relocate copies only; auxiliary CALL/SYSCALL sites consume via Nil stubs."""
        functions = {}
        for trace in plan["creator_flows"].values():
            address = trace["function_address"]
            sites = frozenset(trace["retained_sites"])
            if address in functions and functions[address] != sites:
                raise ValueError("CG 创建副本需要不同的未分离参数路径。")
            functions[address] = sites
        stubs, routes, mappings, replacements = {}, {}, {}, {}
        for address, retained in functions.items():
            for ins in self.backend.spans[address].instructions:
                if ins.mnemonic in {"call", "syscall"} and ins.offset not in retained:
                    count = (self.backend.spans[ins.operands["target"]].args if ins.mnemonic == "call"
                             else self.analysis.header.syscalls[ins.operands["id"]].args)
                    if count not in stubs:
                        stubs[count] = base+len(output)
                        output.extend(bytes((1, count, 0, 8, 5)))
                    replacements[ins.offset] = _call(stubs[count])
        cursor = base+len(output)
        for address in functions:
            routes[address] = cursor
            mapping = {}
            for ins in self.backend.spans[address].instructions:
                mapping[ins.offset] = cursor
                cursor += len(replacements.get(ins.offset, ins.raw))
            mappings[address] = mapping
        for address in functions:
            span, mapping = self.backend.spans[address], mappings[address]
            if self.source.original_bytes[span.start:span.end] != self.analysis.original_bytes[span.start:span.end]:
                raise ValueError("CG 创建副本与当前运行脚本不一致。")
            for ins in span.instructions:
                raw = replacements.get(ins.offset, ins.raw)
                if ins.mnemonic in {"jmp", "jz"}:
                    if ins.operands["target"] not in mapping:
                        raise ValueError("CG 创建副本出现跨函数跳转。")
                    raw = bytes((ins.opcode,))+struct.pack("<I", mapping[ins.operands["target"]])
                elif ins.mnemonic == "call" and ins.offset not in replacements:
                    if ins.operands["target"] not in routes:
                        raise ValueError("CG 创建副本出现未隔离的辅助函数。")
                    raw = _call(routes[ins.operands["target"]])
                output.extend(raw)
        return routes[plan["creator"]], dict(function_routes=routes, isolated_sites=sorted(replacements),
            nil_return_stubs=stubs, variable_width_jumps_relocated=True, original_functions_patched=False)

    def syscall(self, name, values):
        ident, count = self.syscalls[name]
        if len(values) != count:
            raise ValueError("CG 系统调用参数与当前目标不符。")
        return b"".join(_encode_push(v, self.source.encoding) for v in values)+b"\x03"+struct.pack("<H", ident)

    def compile(self, archive, resource, metadata_by_suffix, *, x=0, y=0, percentage=100,
                depth_zoom=False, append_offset=None):
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        reference = self.backend.resource_plan(archive, resource)
        entry = self.backend.routes[reference["archive"]][0]
        plans = [p for p in self.plans if p["prefix"] == entry["prefix"]]
        if (not isinstance(metadata_by_suffix, dict) or set(metadata_by_suffix) != set(entry["resources"])
                or len(plans) != len(entry["resources"]) or len({p["primitive"] for p in plans}) != len(plans)):
            raise ValueError("CG 需要完整的目标原生普通图／大图配对，不会补图或缩放原图。")
        if not resource.isascii():
            raise ValueError("CG 准备阶段暂只接受 ASCII 原生资源名；不会猜测脚本编码。")
        frames = [(p, *self.geometry.frame(p["primitive"], metadata_by_suffix[p["suffix"]],
                    x=x, y=y, percentage=percentage, depth_zoom=depth_zoom)) for p in plans]
        base = len(self.source.original_bytes) if append_offset is None else append_offset
        if type(base) is not int or not len(self.source.original_bytes) <= base < 2**32:
            raise ValueError("CG 准备库必须附加到这个运行脚本末尾之后。")
        all_globals = sorted(set().union(*(set(p["closure"].global_ids) | set(p["route_globals"])
            | set(p["creator_globals"]) for p in plans)))
        code = bytearray(b"\x06\0\0\0\0")
        copies = [self._private_creator(code, p, base) for p in plans]
        entry_address = base+len(code)
        code.extend(b"\x01\0\0"+b"".join(_push_global(g) for g in all_globals))
        # Reusing a sprite/graph does not prove that a previously scheduled
        # primitive motion has disappeared. Stop only our source-owned planes
        # before any load/create/yield can apply an old endpoint to the new CG.
        code.extend(self.motion_quiescence.code())
        operations = []
        # Every plane is hidden before the first load. In the legacy recipe,
        # loading the ordinary plane must not leave the large plane visible.
        for p in plans:
            for name in ("PrimSetDraw", "PrimSetAlpha"):
                code.extend(self.syscall(name, [p["primitive"], 0]))
        code.extend(self.syscall("V3DSet", [0, 0, 0]))
        for (p, frame, proof), (creator_address, copy_report) in zip(frames, copies):
            for g, v in p["route_globals"].items():
                code.extend(_encode_push(v, self.source.encoding)+_pop_global(g))
            def resolve(v):
                if v == RESOURCE:
                    return resource
                if v.get("kind") == "add" and len(v["operands"]) == 2:
                    left, right = (resolve(c) for c in v["operands"])
                    if type(left) is str and type(right) is str:
                        return left+right
                    raise ValueError("CG 资源表达式不是字符串拼接。")
                return _constant(v)
            args = [resolve(v) for v in p["load_arguments"]]
            code.extend(b"".join(_encode_push(v, self.source.encoding) for v in args)+_call(p["load"]))
            for g, v in p["creator_globals"].items():
                code.extend(_encode_push(v, self.source.encoding)+_pop_global(g))
            code.extend(b"".join(_encode_push(v, self.source.encoding) for v in p["creator_arguments"])+_call(creator_address))
            # The isolated creator path contains only checked, non-waiting
            # sprite/group/coordinate operations. Hide before any caller yield.
            for name in ("PrimSetAlpha", "PrimSetDraw"):
                code.extend(self.syscall(name, [p["primitive"], 0]))
            for name, values in (("PrimSetOP", frame["pivot"]), ("PrimSetXY", [frame["x"], frame["y"]]),
                    ("PrimSetZ", [frame["z"]]), ("PrimSetRS", [frame["rotation"], frame["scale"]])):
                code.extend(self.syscall(name, [p["primitive"], *values]))
            operations.append(dict(primitive=p["primitive"], graph=p["graph"], resource=resource+p["suffix"],
                load=p["load"], load_arguments=args, creator=p["creator"], creator_arguments=list(p["creator_arguments"]),
                route_globals=deepcopy(p["route_globals"]), creator_globals=deepcopy(p["creator_globals"]),
                native_geometry=frame, geometry_proof=proof,
                isolated_creator=copy_report, private_creator_address=creator_address,
                native_dependencies=p["closure"].describe(), creator_effects=deepcopy(p["creator_effects"])))
        code.extend(b"".join(_pop_global(g) for g in reversed(all_globals))+b"\x04\x00")
        if base+len(code) >= 2**32:
            raise ValueError("CG 准备库超出原生地址范围。")
        struct.pack_into("<I", code, 1, base+len(code)-1)
        report = dict(schema=SCHEMA, source_sha256=self.source.source_sha256, operations=operations,
            append_offset=base, entry_address=entry_address, inline_library_skipped=True,
            native_viewport=list(self.geometry.primitive.viewport), global_snapshot_ids=all_globals,
            code_size=len(code), code_sha256=hashlib.sha256(code).hexdigest(),
            graph_primitive_link_proven=True, native_sprite_and_group_used=True,
            all_planes_hidden_before_first_load=True, hidden_at_return=True,
            script_waits_before_geometry=0, hidden_before_script_wait_proven=True,
            native_syscall_scheduling_reviewed=False, primitive_ownership_required=True,
            native_motion_quiescence=self.motion_quiescence.report(),
            owned_plane_stop_calls_precede_first_load=True,
            baseline_camera_installed=True, camera_and_native_pending_cache_commit_proven=False,
            native_gallery_flags_emitted=False, original_functions_patched=False,
            inherited_scene_refresh_isolated_in_private_copies=True,
            original_game_written=False, image_resampled=False, source_size_rule_changed=False,
            transition_owner_bound=False, scene_export_connected=False, runtime_verified=False)
        return NativeCGPreparation(bytes(code), report)
