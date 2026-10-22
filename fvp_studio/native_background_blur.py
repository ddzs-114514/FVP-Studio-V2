"""Target-derived control of an original pre-blurred background layer.

Bind the layer, preference guard, alpha child and target cache from THIS HCB.
Manual strength calls that native alpha child, not fabricated camera Z or a
web/generated blur. Only an appended loader copy bypasses the preference.
Discovery alone grants neither resource ownership nor a usable scene event.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import struct

from .hoshimemo_scene_hook import _arguments, _call, _pop_global
from .native_background_backend import NativeBackgroundBackend, _literal, _substitute, _dependencies
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import _function_spans
from .native_portrait_alpha import NativePortraitAlpha
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-background-blur/1"


def _normal(value):
    if isinstance(value, dict):
        return {k: _normal(v) for k, v in value.items() if k not in {"offset", "semantics_reviewed"}}
    if isinstance(value, (list, tuple)):
        return [_normal(v) for v in value]
    return value


def _global_reads(value):
    if value.get("kind") == "global_read":
        return {value["slot"]}
    children = value.get("arguments", ()) if value.get("kind") == "call_return" else value.get("operands", ())
    return set().union(*(_global_reads(v) for v in children))


def _cache_start(value, slot):
    if value.get("kind") == "global_read":
        return value["slot"] == slot
    if value.get("kind") != "choice":
        return False
    members = value.get("operands", ())
    return (bool(members) and any(v.get("kind") == "global_read" and v["slot"] == slot for v in members)
            and all(v.get("kind") == "global_read" and v["slot"] == slot
                or v == _literal(0) or v == _literal(255) for v in members))


class NativeBackgroundBlur:
    def __init__(self, context):
        self.source, self.analysis = context.document, context.analysis_document
        pair = validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        backend = context.abi.native_background_backend
        if (not isinstance(backend, NativeBackgroundBackend) or backend.source_sha256 != self.source.source_sha256
                or backend.blur_target is None or backend.argument_count not in (8, 9)):
            raise ValueError("这个背景布局没有已接通的独立原作模糊层。")
        self.backend = backend
        self.flow = NativeFunctionFlow(self.analysis)
        self.spans = {s.start: s for s in _function_spans(self.analysis)}
        self.loader = self.spans[backend.blur_target]
        self.alpha = NativePortraitAlpha(self.source, self.analysis, runtime_context=context)

        def plane(address, alpha):
            trace = self.flow.trace(address)
            calls = [c for c in trace.get("calls", ()) if c.get("name") == "PrimSetAlpha"]
            if (trace["status"] != "proven_static_argument_flow" or len(calls) != 1 or len(calls[0]["arguments"]) != 2
                    or calls[0]["arguments"][1] != _literal(alpha)
                    or calls[0]["arguments"][0].get("kind") != "literal"
                    or type(calls[0]["arguments"][0].get("value")) is not int):
                raise ValueError("清晰/模糊背景的原生图层身份尚未确定。")
            return calls[0]["arguments"][0]["value"]

        self.primitive = plane(backend.blur_target, 0)
        self.primary_primitive = plane(backend.primary_target, 255)
        if self.primitive < 0 or self.primitive == self.primary_primitive:
            raise ValueError("原作清晰背景与模糊背景没有独立图层。")
        alpha_options = self.alpha.report()["nonblocking_arguments"]
        self.alpha_flow = self.flow.trace(self.alpha.address,
            literal_arguments={0: self.primitive, **alpha_options}, max_joined_values=128)
        active_calls = self.alpha_flow.get("calls", ())
        if (self.alpha_flow["status"] != "proven_static_argument_flow" or len(active_calls) != 1
                or active_calls[0].get("name") != "MotionAlpha"
                or active_calls[0]["arguments"][0] != _literal(self.primitive)):
            raise ValueError("原生透明度函数尚不能独立控制当前模糊背景图层。")
        self.active_alpha_global_ids = tuple(sorted({w["slot"] for w in self.alpha_flow["global_writes"]}))

        body = self.loader.instructions
        if ([i.mnemonic for i in body[:5]] != ["init_stack", "push_global", "push_true", "set_e", "jz"]
                or body[-1].mnemonic != "ret"):
            raise ValueError("模糊背景的原生设置开关尚未接通。")
        self.preference = body[1].operands["value"]
        self.guard_offset, self.guard_body = body[4].offset, body[5].offset
        by_offset = {i.offset: i for i in body}
        if (body[4].operands["target"] not in by_offset
                or by_offset[body[4].operands["target"]].mnemonic != "ret"):
            raise ValueError("原生模糊设置开关并非独立的函数退出分支。")

        candidates = []
        for span in self.spans.values():
            if (span.args != 3 or span.locals > 2 or len(span.instructions) > 256
                    or set(span.calls) != {self.alpha.address} or span.syscalls != ("PrimSetAlpha",)):
                continue
            trace = self.flow.trace(span.start, max_joined_values=128)
            calls, writes = trace.get("calls", ()), trace.get("global_writes", ())
            motion = [c for c in calls if c["kind"] == "call" and c["address"] == self.alpha.address]
            direct = [c for c in calls if c.get("name") == "PrimSetAlpha"]
            if (trace["status"] != "proven_static_argument_flow" or len(motion) != 1
                    or len(direct) != 1 or len(calls) != 2 or len(writes) != 1):
                continue
            args, write = motion[0]["arguments"], writes[0]
            if (args[0] != _literal(self.primitive) or args[3] != dict(kind="argument", index=1)
                    or _dependencies(args[2]) != {0} or _global_reads(args[2])
                    or _normal(write["value"]) != _normal(args[2])
                    or not _cache_start(args[1], write["slot"])
                    or direct[0]["arguments"] != [args[0], args[2]]):
                continue
            # A camera-depth threshold is recorded, never reinterpreted as
            # continuous strength. We call its independently proven alpha child.
            candidates.append((span, write["slot"], trace))
        if len(candidates) != 1:
            raise ValueError("原作模糊背景的透明度缓存及渐变调用尚不能唯一确定。")
        controller, self.cache, controller_flow = candidates[0]
        if self.cache == self.preference:
            raise ValueError("模糊强度缓存与原作设置开关不能是同一个变量。")
        self.controller = controller.start
        self._path_proofs = []
        for archive in backend.archive_selectors:
            self._prove_loader_path(archive)
        self.closure = NativeScriptStateClosure(self.source, self.analysis,
            [backend.blur_target, controller.start, self.alpha.address], runtime_context=context,
            max_functions=256, max_instructions=262144)
        self.snapshot = self.closure.compile_snapshot(self.source)
        self._syscalls = {}
        for index, syscall in enumerate(self.source.header.syscalls):
            if syscall.name in self._syscalls:
                raise ValueError("背景模糊系统调用名重复，不能确定目标。")
            self._syscalls[syscall.name] = (index, syscall.args)
        for name, count in (("MotionAlphaStop", 1), ("MotionAlphaTest", 1),
                            ("PrimSetAlpha", 2), ("GraphLoad", 2), ("ThreadWait", 1)):
            if self._syscalls.get(name, (None, None))[1] != count:
                raise ValueError("背景模糊原生等待/清理调用不匹配：" + name)
        self._report = dict(schema=SCHEMA, loader=backend.blur_target, loader_args=backend.argument_count,
            primitive=self.primitive, primary_primitive=self.primary_primitive,
            preference_global=self.preference, cache_global=self.cache,
            native_depth_controller=controller.start, native_depth_flow=controller_flow,
            alpha_child=self.alpha.report(), owned_background_alpha_flow=deepcopy(self.alpha_flow),
            resource_path_proofs=deepcopy(self._path_proofs),
            source_dependencies=self.closure.describe(), runtime_binding=pair,
            native_preblurred_image=True, continuous_strength="target_native_alpha_child",
            fake_camera_depth_used=False, changes_camera=False, changes_original_preference=False,
            native_geometry_defaults_preserved=True, game_name_switch_used=False, runtime_verified=False)

    def _prove_loader_path(self, archive):
        values = [_literal("BG_FVP_BLUR_BINDING"), *(_literal(None) for _ in range(self.backend.argument_count - 1))]
        if self.backend.argument_count == 9:
            values[-1] = _literal(self.backend.archive_selectors[archive])
        seen, loaded, affected, roots = set(), [], set(), set()
        graph_writes, primitive_writes, global_writes = set(), set(), set()
        mutators = {"GraphLoad", "GraphRGB", "PrimSetNull", "PrimGroupOut", "PrimGroupIn",
            "PrimSetAlpha", "PrimSetZ", "PrimSetRS", "PrimSetSprt", "PrimSetOP", "PrimSetXY",
            "PrimSetDraw", "MotionMoveStop", "MotionMoveZStop", "MotionAnimStop"}
        others = {"FloatToInt", "DissolveWait", "ThreadWait"}
        def visit(address, args, ancestors=()):
            key = (address, repr(args))
            if key in seen:
                return
            if address in ancestors or len(ancestors) > 8 or len(seen) >= 128:
                raise ValueError("模糊背景的资源调用越过独立图层范围。")
            seen.add(key)
            roots.add(address)
            trace = self.flow.trace(address, literal_arguments={i: v["value"] for i, v in enumerate(args)
                if v.get("kind") == "literal"}, max_joined_values=128)
            if trace["status"] != "proven_static_argument_flow":
                raise ValueError("模糊背景的独立资源参数尚未确定。")
            global_writes.update(w["slot"] for w in trace["global_writes"])
            if any(w["slot"] == self.preference for w in trace["global_writes"]):
                raise ValueError("模糊图层加载会改变原作设置，不能作为手动控制入口。")
            if any(self.preference in _global_reads(b["condition"]) and b["offset"] != self.guard_offset
                   for b in trace["branches"]):
                raise ValueError("模糊资源链还有未分离的原作设置分支。")
            for call in trace["calls"]:
                values = [_substitute(v, tuple(args)) for v in call["arguments"]]
                if call["kind"] == "call":
                    visit(call["address"], values, (*ancestors, address))
                    continue
                name = call["name"]
                if name in others:
                    continue
                if name not in mutators or not values or values[0].get("kind") != "literal" or type(values[0].get("value")) is not int:
                    raise ValueError("模糊资源路径含有未识别的画面/镜头修改。")
                primitive = values[0]["value"]
                if primitive == self.primary_primitive:
                    raise ValueError("模糊资源路径会改动当前清晰背景。")
                affected.add(primitive)
                (graph_writes if name in {"GraphLoad", "GraphRGB"} else primitive_writes).add(primitive)
                if name == "GraphLoad" and values[1] != _literal(None):
                    if primitive != self.primitive:
                        raise ValueError("模糊加载路径同时装入了其他画面资源。")
                    loaded.append(values[1])
        visit(self.backend.blur_target, values)
        if len(loaded) != 1:
            raise ValueError("模糊背景没有唯一的图层资源加载调用。")
        self._path_proofs.append(dict(archive=archive, resource_operand=loaded[0],
            functions=sorted(roots), native_auxiliary_primitives=sorted(affected - {self.primitive}),
            graph_mutation_ids=sorted(graph_writes), primitive_mutation_ids=sorted(primitive_writes),
            global_write_ids=sorted(global_writes),
            clear_background_untouched=True, camera_untouched=True))

    def assert_portrait_ownership(self, slots):
        """Keep Graph and Prim namespaces distinct; require disjoint owned slots.

        A Graph ID can equal an unrelated Prim ID. Shared loader cache writes
        may be preserved around the synchronous call only AFTER all affected
        engine handles are proved disjoint. Sharing the strength cache itself
        remains unsupported. This is not proof of engine parent-group semantics.
        """
        primitives, graphs, globals_ = set(), set(), set()
        selectors = []
        for slot in slots:
            handles = slot.evidence.get("dispatcher_handles", {})
            if handles.get("dispatcher_handles_verified") is not True:
                raise ValueError("立绘与模糊背景的原生资源槽尚未确定。")
            primitives.update(slot.primitive_ids)
            graphs.update(handles["graph_ids"])
            globals_.update(slot.global_ids)
            globals_.update(slot.read_global_ids)
            selectors.append(slot.selector)
        if not selectors:
            raise ValueError("没有可核对的当前场景角色槽。")
        # The closure also includes the native blocking/wait path. Our call's
        # exact nonblocking arguments exclude it; only the specialised writes
        # may be treated as active strength writes. Keep the whole closure
        # byte-bound for drift detection and the outer scene snapshot.
        strength_writes = {self.cache, *self.active_alpha_global_ids}
        if strength_writes & globals_:
            raise ValueError("模糊强度和当前场景角色共用原生缓存，尚未接通这种布局。")
        writes = set()
        for proof in self._path_proofs:
            if (primitives & set(proof["primitive_mutation_ids"])
                    or graphs & set(proof["graph_mutation_ids"])):
                raise ValueError("模糊背景的原生加载会改动当前场景的立绘资源槽。")
            writes.update(proof["global_write_ids"])
        protected = sorted(writes & globals_)
        return dict(selectors=sorted(selectors), explicit_graph_and_primitive_handles_disjoint=True,
            specialised_cache_writes_disjoint=not protected,
            protected_shared_loader_cache_ids=protected,
            protection_scope="synchronous_blur_resource_loader_only",
            engine_parent_group_semantics_verified=False,
            runtime_verified=False)

    def prepare_loader(self, output):
        """Copy exactly one source wrapper and rehome ONLY its internal jumps."""
        start, end = self.loader.start, self.loader.end
        raw = bytearray(self.source.original_bytes[start:end])
        address = len(self.source.original_bytes) + len(output) + 5
        offsets = {i.offset for i in self.loader.instructions}
        edits = []
        for item in self.loader.instructions:
            if item.mnemonic in {"jmp", "jz"}:
                original = item.operands["target"]
                if original not in offsets:
                    raise ValueError("模糊背景函数的分支越过原生边界。")
                target = self.guard_body if item.offset == self.guard_offset else original
                relocated = address + target - start
                struct.pack_into("<I", raw, item.offset - start + 1, relocated)
                edits.append(dict(source=item.offset, original=original, relocated=relocated))
        if address + len(raw) >= 2**31:
            raise ValueError("模糊背景副本超过原生函数地址范围。")
        output.extend(b"\x06" + struct.pack("<I", address + len(raw)) + raw)
        return address, dict(source=[start, end], address=address, byte_count=len(raw),
            address_edits=edits, source_sha256=hashlib.sha256(self.source.original_bytes[start:end]).hexdigest(),
            clone_sha256=hashlib.sha256(raw).hexdigest(), only_private_preference_guard_bypassed=True,
            original_functions_patched=False)

    def load_code(self, address, resource, archive):
        # Reuse the established native resource-name and archive validation.
        self.backend.compile_load(self.source, resource_name=resource, archive_name=archive, duration_ms=0)
        tail = [None] * (self.backend.argument_count - 1)
        if self.backend.argument_count == 9:
            tail[-1] = self.backend.archive_selectors[archive]
        return _encode_push(resource, self.source.encoding) + _arguments(tail) + _call(address)

    def syscall(self, name, values):
        index, count = self._syscalls[name]
        if count != len(values):
            raise ValueError("背景模糊调用参数不匹配。")
        return b"".join(_encode_push(v, self.source.encoding) for v in values) + b"\x03" + struct.pack("<H", index)

    def cache_code(self, alpha):
        if type(alpha) is not int or not 0 <= alpha <= 255:
            raise ValueError("模糊图层原生透明度须为 0～255 整数。")
        return _encode_push(alpha, self.source.encoding) + _pop_global(self.cache)

    def alpha_code(self, start, end, duration_ms):
        if (any(type(v) is not int or not 0 <= v <= 255 for v in (start, end))
                or type(duration_ms) is not int or not 0 <= duration_ms <= 6000):
            raise ValueError("背景模糊原生透明度或渐变时长无效。")
        code = self.alpha.call(self.primitive, start, end, duration_ms) if duration_ms else (
            self.syscall("MotionAlphaStop", (self.primitive,)) + self.syscall("PrimSetAlpha", (self.primitive, end)))
        return code + self.cache_code(end)

    def report(self):
        return deepcopy(self._report)
