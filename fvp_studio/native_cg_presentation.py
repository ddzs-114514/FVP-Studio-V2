"""Owned CG visibility plus one source-local native reveal/wait transaction.

This is an appended library, not a public scene/export feature. It deliberately
does not execute the original event-picture show or its inherited-scene cache
refresh. An optional target-bound retained underlay hides/resumes owned scene
layers and the bound camera. Full scene integration must still acquire native
threads/parents and pending caches, and reconstruct aliased or original images.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import struct

from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_background_backend import _literal, _substitute
from .native_cg_staged_load import NativeCGStagedLoad
from .native_cg_motion_quiescence import NativeCGMotionQuiescence
from .native_screen_transition import NativeScreenTransition
from .native_script_state import validate_native_script_pair
from .native_legacy_visibility import extract_legacy_visibility


SCHEMA = "fvp-native-cg-presentation/1"


def _bool_fact(value):
    """Only typed boolean and exact boolean short-circuit facts. No call effects."""
    if value.get("kind") == "literal" and type(value.get("value")) is bool:
        return value["value"]
    if value.get("kind") in {"and", "or"}:
        operands = [_bool_fact(v) for v in value.get("operands", ())]
        if len(operands) == 2:
            if value["kind"] == "and":
                return False if False in operands else True if operands == [True, True] else None
            return True if True in operands else False if operands == [False, False] else None
    return None


def _literal_int(value):
    if value.get("kind") == "literal" and type(value.get("value")) is int:
        return value["value"]
    raise ValueError("CG 显示规则还依赖未确定的图层或状态。")


class NativeCGVisibility:
    """Select this target's own planes, starting from the prepared hidden state.

For a single proven resource plane, visibility is explicit scene ownership,
not an assertion about PrimSetSprt's undocumented default draw/alpha. For a
normal/large family, every reachable source Draw path must agree on exactly
one displayed plane. Unknown branches are followed, not assumed false.
"""
    def __init__(self, context, backend):
        if backend.source is not context.document or backend.analysis is not context.analysis_document:
            raise ValueError("CG 显示规则与当前原生脚本不一致。")
        validate_native_script_pair(backend.source, backend.analysis, runtime_context=context)
        self.context, self.backend = context, backend
        self.policies = {}
        for archive, routes in backend.routes.items():
            entry = routes[0]
            planes = sorted({r["graph"] for r in backend.resource_graphs if r["prefix"] == entry["prefix"]})
            if not planes or not set(planes) <= set(backend.planes):
                raise ValueError("CG 图像槽与构图图层尚未配对。")
            trace = backend.traces[backend.address][str(entry["selector"])]
            calls = {c["offset"]:c for c in trace["calls"] if c.get("name") == "PrimSetDraw"}
            writes = {}
            for site, call in calls.items():
                p, draw = map(_literal_int, call["arguments"])
                if p in planes:
                    if draw not in (0, 1):
                        raise ValueError("CG 原生显示开关不是已支持的 0/1。")
                    writes[site] = (planes.index(p), draw)
            if not writes:
                if len(planes) != 1 or planes[0] != backend.primary_primitive:
                    raise ValueError("CG 普通图／大图没有唯一的原生显示规则。")
                draws, path_count, method = (1,), None, "explicit_owned_single_resource_plane"
            else:
                endings, path_count = self._end_states(backend.spans[backend.address], trace, planes, writes)
                if len(endings) != 1:
                    raise ValueError("CG 的未确定分支会选择不同的普通图／大图。")
                draws = next(iter(endings))
                method = "source_draw_cfg_from_all_planes_hidden"
            if sum(draws) != 1:
                raise ValueError("CG 原生显示规则不是恰好一张图；不会擅自叠图或挑图。")
            self.policies[archive] = dict(archive=archive, selector=entry["selector"],
                draws=dict(zip(planes, draws)), visible_primitive=planes[draws.index(1)],
                method=method, source_draw_sites=sorted(writes), cfg_states_visited=path_count,
                prepared_hidden_precondition=True, original_show_not_executed=True,
                sprite_default_visibility_assumed=False, runtime_verified=False)

    @staticmethod
    def _end_states(span, trace, planes, writes):
        indexes = {i.offset:n for n,i in enumerate(span.instructions)}
        conditions = {b["offset"]:_bool_fact(b["condition"]) for b in trace["branches"]}
        pending, visited, endings = [(1, (0,)*len(planes))], set(), set()
        while pending:
            index, state = pending.pop()
            if (index, state) in visited:
                continue
            visited.add((index, state))
            if len(visited) > 8192 or not 0 < index < len(span.instructions):
                raise ValueError("CG 显示分支超出限定范围。")
            ins = span.instructions[index]
            if ins.offset in writes:
                position, draw = writes[ins.offset]
                state = (*state[:position], draw, *state[position+1:])
            if ins.mnemonic in {"ret", "retv"}:
                endings.add(state)
            elif ins.mnemonic in {"jmp", "jz"}:
                target = indexes.get(ins.operands["target"])
                if target is None or target <= index:
                    raise ValueError("CG 显示分支不是函数内的前向跳转。")
                if ins.mnemonic == "jmp":
                    pending.append((target, state))
                else:
                    condition = conditions.get(ins.offset)
                    if condition is not True:
                        pending.append((target, state))
                    if condition is not False:
                        pending.append((index+1, state))
            else:
                pending.append((index+1, state))
        if not endings:
            raise ValueError("CG 显示规则没有可达的返回。")
        return endings, len(visited)

    def policy(self, archive):
        validate_native_script_pair(self.backend.source, self.backend.analysis, runtime_context=self.context)
        key = archive.casefold() if isinstance(archive, str) else None
        if key not in self.policies:
            raise ValueError("CG 显示规则不属于当前目标的归档。")
        # Bind the exact source bytes again. A cached policy is not permission
        # to emit after a source function/instruction is modified in memory.
        span = self.backend.spans[self.backend.address]
        if (self.backend.source.original_bytes[span.start:span.end]
                != self.backend.analysis.original_bytes[span.start:span.end]
                or any(i.dirty or i.warning or not i.known for i in span.instructions)):
            raise ValueError("CG 显示规则的原生证据已变化。")
        return deepcopy(self.policies[key])


@dataclass(frozen=True)
class NativeCGPresentationLibrary:
    code: bytes
    report: dict


class NativeCGPresentation:
    """Prepare, show or hide owned CG planes using exactly one native dissolve.

Only call the returned functions after the scene has acquired the CG slots
and zero-camera baseline. With underlay=None these helpers only own CG; an
explicit NativeCGUnderlay can retain scene BG/portrait resources and use a
captured native BG reload if CG overwrites the current scene's background.
Public/export capability remains false until the remaining owners integrate.
"""
    def __init__(self, context, stage, fade=None, *, executable=None):
        if not isinstance(stage, NativeCGStagedLoad) or stage.context is not context:
            raise ValueError("CG 显示必须使用当前目标已绑定的隐藏准备流程。")
        if executable is None:
            executable = stage.executable
        elif stage.executable is not None and executable != stage.executable:
            raise ValueError("CG 显示和准备流程使用了不同的原生程序。")
        self.context, self.stage = context, stage
        self.backend, self.source, self.analysis = stage.backend, stage.source, stage.analysis
        self.visibility = NativeCGVisibility(context, self.backend)
        self.fade = NativeScreenTransition(context) if fade is None else fade
        if (not isinstance(self.fade, NativeScreenTransition) or self.fade.source is not self.source
                or self.fade.analysis is not self.analysis):
            raise ValueError("CG 渐变不属于当前目标的原生调用链。")
        reveal = self.fade.report()["native_reveal_flow"]
        # Bind opaque alpha to this target's own CG reset sites. Never infer a
        # sprite default or borrow a different title's alpha/reset primitive.
        alpha, alpha_sites = {}, {}
        for c in reveal["calls"]:
            if c.get("name") == "PrimSetAlpha":
                p, value = map(_literal_int, c["arguments"])
                alpha_sites.setdefault(p, []).append(dict(offset=c["offset"], value=value))
                if p in self.backend.planes:
                    alpha.setdefault(p, set()).add(value)
        used = set().union(*(set(p["draws"]) for p in self.visibility.policies.values()))
        self.alpha_proof = dict(method="source_cg_reveal_alpha_reset", native_reveal=self.fade.reveal.start)
        if any(alpha.get(p) != {255} for p in used):
            if executable is None:
                raise ValueError("CG 完全显示的透明度需要本目标的原生复位或引擎证据。")
            proof = extract_legacy_visibility(executable)
            geometry = stage.geometry.primitive.evidence
            if (proof["exe_sha256"] != geometry.get("native_scale", {}).get("exe_sha256")
                    or proof["exe_sha256"] != geometry.get("viewport", {}).get("exe_sha256")
                    or any(not proof["alpha_primitive_range"][0] <= p <= proof["alpha_primitive_range"][1]
                           or not proof["draw_primitive_range"][0] <= p <= proof["draw_primitive_range"][1] for p in used)):
                raise ValueError("旧版 CG 显示证据与当前几何／图层不一致。")
            self.alpha_proof = dict(method="own_engine_sprite_initializer_and_registered_setter", **proof)
            self.alpha = {p:proof["opaque_alpha"] for p in used}
        else:
            self.alpha = {p:next(iter(alpha[p])) for p in used}
        # Some versions clear an extra CG graph/primitive before loading the
        # displayed graph. It is NOT a spare buffer to invent or reuse. Own it
        # only when BOTH this archive's source show clears it and the unique
        # source CG reveal resets its alpha. Leave all other native handles
        # alone; absence of a geometry plane is not a reason to borrow one.
        self.companions = {}
        for archive, policy in self.visibility.policies.items():
            trace = self.backend.traces[self.backend.address][str(policy["selector"])]
            unloads, nulls = {}, {}
            for c in trace["calls"]:
                args = c["arguments"]
                if c.get("name") == "GraphLoad" and len(args) == 2 and args[1].get("kind") == "literal" and args[1].get("value") is None:
                    unloads.setdefault(_literal_int(args[0]), []).append(c["offset"])
                elif c.get("name") == "PrimSetNull" and len(args) == 1:
                    nulls.setdefault(_literal_int(args[0]), []).append(c["offset"])
            self.companions[archive] = {p:dict(graph_unload_sites=unloads[p], primitive_clear_sites=nulls[p],
                cg_reveal_alpha_sites=alpha_sites[p]) for p in sorted(set(unloads) & set(nulls) & set(alpha_sites))
                if p not in policy["draws"] and p > 0 and all(c["value"] == 255 for c in alpha_sites[p])}
        self.fade_globals = tuple(sorted({w["slot"] for w in reveal["global_writes"]}))
        if set(self.fade_globals) & self.backend.gallery_global_ids:
            raise ValueError("CG 渐变待提交状态与原作鉴赏标记相冲突。")
        self.motion_quiescence = NativeCGMotionQuiescence(context, self.backend,
            presentation=self, executable=executable)

    def compile(self, archive, resource, metadata_by_suffix, *, x=0, y=0, percentage=100,
                duration_ms=200, append_offset=None, underlay=None, background_reload=None,
                release_resources=False, depth_zoom=False, display_launch=b''):
        if type(duration_ms) is not int or not 0 <= duration_ms <= 3000:
            raise ValueError("CG 切换时间应为 0～3000 毫秒。")
        if type(release_resources) is not bool:
            raise ValueError("CG 资源释放须明确选择，不能使用未确定的状态。")
        if type(display_launch) is not bytes:
            raise ValueError('CG 同拍构图必须是本机编译的原生调用。')
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        handoff = None
        if underlay is not None:
            from .native_cg_underlay import NativeCGUnderlay
            if not isinstance(underlay, NativeCGUnderlay):
                raise ValueError("CG 舞台交接必须使用已绑定的原生图层。")
            handoff = underlay.fragments(self)
        reload_library = None
        prefix = b""
        base = len(self.source.original_bytes) if append_offset is None else append_offset
        if type(base) is not int or not len(self.source.original_bytes) <= base < 2**32:
            raise ValueError("CG 显示库必须附加到当前运行脚本之后。")
        restore_background = handoff.get("background_reload") if handoff else None
        if background_reload is not None and underlay is not None:
            raise ValueError("背景重载请随舞台交接一起捕获，不能提供两份恢复状态。")
        if background_reload is not None:
            restore_background = background_reload
        if restore_background is not None:
            from .native_cg_background_reload import NativeCGBackgroundRestore
            if (not isinstance(restore_background, NativeCGBackgroundRestore)
                    or restore_background.binding.stage is not self.stage):
                raise ValueError("背景重载须属于当前 CG 显示库。")
            reload_library = restore_background.compile(append_offset=base)
            prefix = reload_library.code
        policy = self.visibility.policy(archive)
        preparation = self.stage.compile(archive, resource, metadata_by_suffix, x=x, y=y,
            percentage=percentage, depth_zoom=depth_zoom, append_offset=base+len(prefix))
        release_code, release_report = (self._resource_release(policy, underlay, restore_background)
            if release_resources else (b"", None))
        code = bytearray(prefix+preparation.code)
        reveal_address, reveal_copy = self.fade.prepare_reveal(code, append_offset=base)
        snapshot = b"".join(_push_global(g) for g in self.fade_globals)
        restore = b"".join(_pop_global(g) for g in reversed(self.fade_globals))
        wait = self.fade.syscall("DissolveWait", (True,))
        companions = self.companions[policy["archive"]]
        entries = {}
        for operation in ("display", "hide"):
            entries[operation] = base+len(code)
            code.extend(b"\x01\0\0"+snapshot+wait)
            # Include the source-owned reveal companions too. An old animation
            # must not re-enable an unloaded companion during our fade/wait.
            code.extend(self.motion_quiescence.code())
            if handoff and operation == "display":
                code.extend(handoff["before_display"])
            for p in companions:
                code.extend(self.stage.syscall("PrimSetDraw", [p,0]))
                code.extend(self.stage.syscall("PrimSetAlpha", [p,0]))
            if operation == "display":
                for p in companions:
                    code.extend(self.stage.syscall("GraphLoad", [p,None]))
                    code.extend(self.stage.syscall("PrimSetNull", [p]))
                code.extend(_call(preparation.report["entry_address"]))
            for p, draw in policy["draws"].items():
                visible = draw if operation == "display" else 0
                code.extend(self.stage.syscall("PrimSetAlpha", [p, self.alpha[p] if visible else 0]))
                code.extend(self.stage.syscall("PrimSetDraw", [p, visible]))
            if reload_library is not None and operation == "hide":
                # The BG sprite may have the SAME handle as a CG plane. Load
                # it after hiding CG, then reveal it in this ONE transaction.
                # Native source geometry/parent selection are reconstructed;
                # Restore owned camera/portrait visibility AFTER native BG
                # creation, then commit the whole stage in this one reveal.
                code.extend(_call(reload_library.report["entry_address"]))
                if handoff is None:
                    code.extend(self.stage.syscall("PrimSetDraw", [reload_library.report["primitive"],1]))
            if handoff and operation == "hide":
                code.extend(handoff["before_hide"])
            if duration_ms:
                code.extend(self.fade.reveal_code(reveal_address, duration_ms))
            if operation == 'display':
                code.extend(display_launch)
            if duration_ms:
                code.extend(wait)
            if operation == "hide":
                # Release only AFTER the native fade has joined. In an aliased
                # BG/CG generation the hide path has already reconstructed BG;
                # graph and primitive identities must be retained independently.
                code.extend(release_code)
            # A zero-duration request is a real direct visibility change:
            # previous fades have been joined, no Dissolve(0) is guessed.
            code.extend(restore+b"\x04")
        code.extend(b"\x00")
        if base+len(code) >= 2**32:
            raise ValueError("CG 显示库超出原生地址范围。")
        # Skip ALL appended functions, not just the hidden preparation portion.
        struct.pack_into("<I", code, 1, base+len(code)-1)
        report = dict(schema=SCHEMA, source_sha256=self.source.source_sha256,
            append_offset=base, entry_address=entries["display"], entries=entries,
            preparation=deepcopy(preparation.report), visibility=policy,
            opaque_alpha=deepcopy(self.alpha), alpha_proof=deepcopy(self.alpha_proof),
            source_owned_companions=deepcopy(companions), companion_graphs_unloaded_before_load=True,
            reveal_address=reveal_address, reveal_copy=reveal_copy,
            fade_global_snapshot_ids=list(self.fade_globals), duration_ms=duration_ms,
            reveal_binding=self.fade.report(), code_size=len(code),
            code_sha256=hashlib.sha256(code).hexdigest(), one_native_dissolve_owner=True,
            requested_dissolves_per_call=1 if duration_ms else 0,
            prior_dissolve_joined_before_load=True, waits_after_own_fade=bool(duration_ms),
            display_motion_before_reveal_wait=bool(display_launch),
            native_timing_policy_preserved=True, original_show_not_executed=True,
            original_functions_patched=False, original_game_written=False,
            native_gallery_flags_emitted=False, bg_and_portrait_ownership_required=True,
            retained_underlay=handoff["report"] if handoff else None,
            background_reload=deepcopy(reload_library.report) if reload_library else None,
            compiler_owned_background_reloaded_on_hide=reload_library is not None,
            retained_scene_layer_handoff_connected=handoff is not None,
            native_motion_quiescence=self.motion_quiescence.report(),
            owned_cg_stop_calls_precede_slot_reuse_or_hide=True,
            resource_release=release_report,
            owned_cg_resources_released_after_hide_wait=release_resources,
            original_engine_thread_and_parent_ownership_required=True,
            camera_and_pending_cg_cache_commit_proven=False,
            original_images_restored=False, scene_export_connected=False, runtime_verified=False)
        return NativeCGPresentationLibrary(bytes(code), report)

    def _resource_release(self, policy, underlay, restore_background):
        """Use the native clear pairs, excluding retained scene namespaces.

        This is an opt-in for an enclosing owned scene, not acquisition of
        original VM threads/groups or permission to enable public CG export.
        The existing retained-hide library remains byte-identical by default.
        """
        keep_graphs, keep_primitives = set(), set()
        if underlay is not None:
            underlay._validate(self)
            for role, layer in underlay.layers.layers.items():
                present = underlay.background_present if role == "background" else underlay.blur_present
                if present:
                    keep_graphs.add(layer["graph"])
                    keep_primitives.add(layer["primitive"])
        if restore_background is not None:
            binding = restore_background.binding
            binding._validate()
            keep_graphs.add(binding.graph)
            keep_primitives.add(binding.primitive)
        calls = []
        prefix = self.backend.routes[policy["archive"]][0]["prefix"]
        for plan in self.stage.plans:
            if plan["prefix"] != prefix:
                continue
            # Stage binding proves this exact leaf starts with PrimSetNull
            # then GraphLoad(Nil). Keep its order, not a title-specific recipe.
            values = plan["load_arguments"]
            trace = self.backend.flow.trace(plan["load"],
                literal_arguments={i: v["value"] for i, v in enumerate(values) if v.get("kind") == "literal"},
                non_nil_arguments=tuple(i for i, v in enumerate(values) if v.get("kind") != "literal"),
                track_global_literals=True, literal_globals=plan["route_globals"], max_joined_values=128)
            sites = trace.get("calls", ())
            args = [tuple(_substitute(v, values) for v in c["arguments"]) for c in sites]
            if (trace["status"] != "proven_static_argument_flow" or len(sites) != 3
                    or [c.get("name") for c in sites] != ["PrimSetNull", "GraphLoad", "GraphLoad"]
                    or args[0] != (_literal(plan["primitive"]),)
                    or args[1] != (_literal(plan["graph"]), _literal(None))):
                raise ValueError("CG 资源释放的原生清图顺序已经变化。")
            calls.extend((dict(name="PrimSetNull", values=[plan["primitive"]],
                namespace="primitive", source_site=sites[0]["offset"]),
                dict(name="GraphLoad", values=[plan["graph"], None],
                namespace="graph", source_site=sites[1]["offset"])))
        for primitive, proof in self.companions[policy["archive"]].items():
            calls.extend((dict(name="GraphLoad", values=[primitive, None], namespace="graph",
                source_site=proof["graph_unload_sites"][0]),
                dict(name="PrimSetNull", values=[primitive], namespace="primitive",
                source_site=proof["primitive_clear_sites"][0])))
        retained, emitted, seen = [], [], set()
        for call in calls:
            keep = keep_graphs if call["namespace"] == "graph" else keep_primitives
            if call["values"][0] in keep:
                retained.append(call)
            elif (call["name"], call["values"][0]) not in seen:
                emitted.append(call)
                seen.add((call["name"], call["values"][0]))
        return b"".join(self.stage.syscall(c["name"], c["values"]) for c in emitted), dict(
            schema="fvp-native-cg-resource-release/1", native_clear_calls=emitted,
            retained_alias_calls=retained, retained_scene_graphs=sorted(keep_graphs),
            retained_scene_primitives=sorted(keep_primitives),
            graph_and_primitive_namespaces_separate=True, release_follows_own_fade_wait=True,
            parent_groups_cleared=False, parts_or_portrait_resources_cleared=False,
            engine_threads_and_groups_must_already_be_owned=True,
            original_images_restored=False, scene_export_connected=False, runtime_verified=False)
