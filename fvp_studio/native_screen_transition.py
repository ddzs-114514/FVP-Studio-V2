"""Source-local black/white fades with an isolated native scene-reveal copy.

The target HCB proves colour slots, duration policy and the Dissolve operands.
Only appended colour/reveal copies omit inherited CG alpha/auxiliary refreshes;
native timing branches, fade calls and waits stay intact. No borrowed palette,
primitive, address, global or guessed engine overlay is emitted.
"""
from copy import deepcopy
import hashlib
import struct

from .hoshimemo_scene_hook import _arguments, _call, _push_global, _pop_global
from .native_background_backend import _literal, _substitute, _dependencies
from .native_call_flow import NativeFunctionFlow
from .native_portrait_acceptance import _function_spans
from .native_script_state import NativeScriptStateClosure, validate_native_script_pair
from .native_story_hooks import reachable_native_instructions


SCHEMA = "fvp-native-screen-transition/1"
METHODS = ("black_out", "white_out", "reveal", "black_return", "white_return")


def _constant(v):
    if v.get("kind") == "literal":
        return v["value"]
    if v.get("kind") == "neg" and len(v.get("operands", ())) == 1:
        n = _constant(v["operands"][0])
        if type(n) is int:
            return -n
    raise ValueError("不是原生常量。")


def _duration(v):
    kind = v.get("kind")
    if kind == "literal":
        return type(v.get("value")) is int and 0 <= v["value"] <= 60000
    if kind == "argument":
        return v.get("index") == 0
    if kind == "global_read":
        return True
    return kind in {"choice", "mul", "div", "sub", "add"} and all(_duration(x) for x in v.get("operands", ()))


def _has_return(v):
    return v.get("kind") == "call_return" or any(_has_return(x) for x in v.get("operands", ()))


def _global_reads(v):
    if v.get("kind") == "global_read":
        return {v["slot"]}
    return set().union(*(_global_reads(x) for x in v.get("operands", ())))


class NativeScreenTransition:
    def __init__(self, context):
        self.source, self.analysis = context.document, context.analysis_document
        pair = validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        self.spans = {s.start: s for s in _function_spans(self.analysis)}
        self.flow = NativeFunctionFlow(self.analysis)
        self._syscalls = {}
        for index, syscall in enumerate(self.source.header.syscalls):
            if syscall.name in self._syscalls:
                raise ValueError("整幕转场的系统调用名重复。")
            self._syscalls[syscall.name] = (index, syscall.args)
        if (self._syscalls.get("Dissolve", (None, None))[1] != 7
                or self._syscalls.get("DissolveWait", (None, None))[1] != 1):
            raise ValueError("这个版本的原生整幕转场参数尚未接通。")
        palettes = {}
        palette_sites = {}
        reachable, reachability = reachable_native_instructions(self.analysis, self.source)
        instructions = self.analysis.instructions
        for n, ins in enumerate(instructions):
            if (ins.mnemonic != "syscall" or self.analysis.header.syscalls[ins.operands["id"]].name != "ColorSet"
                    or n < 5 or ins.offset not in reachable):
                continue
            prev = instructions[n-5:n]
            if all(i.mnemonic in {"push_i8", "push_i16", "push_i32"} for i in prev):
                p, *rgba = (i.operands["value"] for i in prev)
                if any(self.source.original_bytes[i.offset:i.offset+i.size] != i.raw for i in (*prev, ins)):
                    raise ValueError("原生色场初始化与运行脚本不一致。")
                palettes.setdefault(p, set()).add(tuple(rgba))
                palette_sites.setdefault(p, []).append(ins.offset)
        candidates, colour_errors = [], []
        for span in self.spans.values():
            if (span.args not in (5, 8) or span.locals > 1 or len(span.instructions) > 1024
                    or span.syscalls.count("ColorSet") != 1):
                continue
            generic = self.flow.trace(span.start, max_joined_values=128)
            colors = [c for c in generic["calls"] if c.get("name") == "ColorSet"]
            if (generic["status"] != "proven_static_argument_flow" or len(colors) != 1
                    or colors[0]["arguments"][1:] != [dict(kind="argument", index=i) for i in range(1, 5)]):
                continue
            try:
                proofs = {}
                for selector, color in ((-1, (0, 0, 0, 255)), (-2, (255, 255, 255, 255))):
                    params = [2309, selector, None, None, None] + ([1, 0, -1] if span.args == 8 else [])
                    trace = self.flow.trace(span.start, literal_arguments={i: v for i, v in enumerate(params) if i},
                        non_nil_arguments=(0,), max_joined_values=128)
                    effects, roots, writes, retained = [], {span.start}, set(), []
                    if (trace["status"] != "proven_static_argument_flow"
                            or any(_has_return(b["condition"]) for b in trace["branches"])
                            or any(_has_return(w["value"]) for w in trace["global_writes"])):
                        raise ValueError("色场时间依赖未隔离的辅助函数结果。")
                    writes.update(w["slot"] for w in trace["global_writes"])
                    for c in trace["calls"]:
                        args = c["arguments"]
                        if c.get("name") == "Dissolve":
                            effects.append(dict(name="Dissolve", offset=c["offset"], arguments=args))
                        elif c["kind"] == "call":
                            if len(args) == 7 and args[2:] == [_literal(None)] * 5:
                                child, dependencies, cache = self._expand(c["address"], args)
                                if cache or len(child) != 1:
                                    raise ValueError("色场渐变子函数含有其他修改。")
                                effects.extend(child)
                                roots.update(dependencies)
                                retained.append(c["offset"])
                            # All other preparation/cursor/old-scene refresh
                            # calls are omitted only in the appended copy.
                        else:
                            raise ValueError("色场路径含有未分离的系统调用。")
                    if (len(effects) != 1 or effects[0]["name"] != "Dissolve"
                            or effects[0]["arguments"][2:] != [_literal(None)] * 5
                            or not _duration(effects[0]["arguments"][0])
                            or _dependencies(effects[0]["arguments"][0]) != {0}):
                        raise ValueError("色场路径含有额外画面修改。")
                    palette = _constant(effects[0]["arguments"][1])
                    if type(palette) is not int or palettes.get(palette) != {color}:
                        raise ValueError("黑白色场没有唯一的原作颜色初始化。")
                    proofs[selector] = dict(palette=palette, effects=effects, roots=sorted(roots), writes=sorted(writes),
                        retained_calls=retained, native_argument_flow=trace)
                if proofs[-1]["palette"] == proofs[-2]["palette"]:
                    continue
                if proofs[-1]["retained_calls"] != proofs[-2]["retained_calls"]:
                    continue
                candidates.append((span, proofs))
            except (ValueError, KeyError) as exc:
                colour_errors.append(dict(address=span.start, message=str(exc)))
                continue
        if len(candidates) != 1:
            error = ValueError("原生黑场和白场的颜色、时间及无清场调用尚不能唯一确定。")
            error.native_details = dict(candidates=[s.start for s, _ in candidates], rejected=colour_errors,
                palettes={str(p): [list(c) for c in colors] for p, colors in palettes.items()})
            raise error
        self.colour, colour_proofs = candidates[0]
        self._colour_retained_calls = tuple(colour_proofs[-1]["retained_calls"])
        self._colour_params = (1, 0, -1) if self.colour.args == 8 else ()
        reveal_candidates = []
        for span in self.spans.values():
            if span.args not in (1, 2) or span.locals or len(span.instructions) > 256:
                continue
            trace = self.flow.trace(span.start, literal_arguments={1: 1} if span.args == 2 else {},
                                    non_nil_arguments=(0,), max_joined_values=128)
            if trace["status"] != "proven_static_argument_flow":
                continue
            fade, skipped, removed_alpha = [], [], []
            try:
                for c in trace["calls"]:
                    args = c["arguments"]
                    if c["kind"] == "syscall" and c.get("name") == "Dissolve":
                        fade.append((c, args, set()))
                    elif c["kind"] == "syscall" and c.get("name") == "PrimSetAlpha":
                        if len(args) != 2 or type(_constant(args[0])) is not int or _constant(args[1]) != 255:
                            raise ValueError("不是原生 CG 透明度复位。")
                        removed_alpha.append(c["offset"])
                    elif c["kind"] == "call":
                        # Expand only a pure seven-operand Dissolve delegate.
                        if len(args) == 7 and args[1:] == [_literal(None)] * 6:
                            effects, roots, writes = self._expand(c["address"], args)
                            if writes or len(effects) != 1 or effects[0]["name"] != "Dissolve":
                                raise ValueError("显现渐变子函数含有其他画面或缓存修改。")
                            fade.append((c, effects[0]["arguments"], roots))
                        else:
                            skipped.append(c)
                    else:
                        raise ValueError("显现函数含有未分离的系统调用。")
                if (len(fade) != 1 or len(fade[0][1]) != 7 or fade[0][1][1:] != [_literal(None)] * 6
                        or not _duration(fade[0][1][0]) or _dependencies(fade[0][1][0]) != {0}):
                    continue
                if any(w["value"].get("kind") != "literal" for w in trace["global_writes"]):
                    continue
                if any(_has_return(b["condition"]) for b in trace["branches"]):
                    continue
                reveal_candidates.append((span, trace, fade[0], skipped, removed_alpha))
            except (ValueError, KeyError):
                continue
        if len(reveal_candidates) != 1:
            raise ValueError("原生淡入与旧 CG／旧剧情刷新尚不能唯一分离。")
        self.reveal, reveal_flow, fade, self.skipped, self.removed_alpha = reveal_candidates[0]
        self._retained_call = fade[0]["offset"] if fade[0]["kind"] == "call" else None
        roots = sorted({self.colour.start, *fade[2]})
        self.closure = NativeScriptStateClosure(self.source, self.analysis, roots,
            runtime_context=context, max_functions=128, max_instructions=32768)
        raw = self.analysis.original_bytes[self.reveal.start:self.reveal.end]
        if self.source.original_bytes[self.reveal.start:self.reveal.end] != raw:
            raise ValueError("原生淡入函数与运行脚本不一致。")
        # The full colour dependency closure binds source bytes conservatively.
        # Only the isolated, actually callable paths grant snapshot authority;
        # omitted scene/cursor helpers' unrelated variables are not restored.
        self.global_ids = tuple(sorted(set().union(*(set(p["writes"]) for p in colour_proofs.values()))
            | {w["slot"] for w in reveal_flow["global_writes"]}))
        # The flow joins conditional duration assignments into a choice of
        # values. Its operands do not retain the deciding branch condition,
        # so bind the policy's control reads too (conservatively, including
        # auxiliary guards). A shared native skip/timing setting must never
        # be mistaken for an actor cache that can be temporarily overwritten.
        policy_values = [p["effects"][0]["arguments"][0] for p in colour_proofs.values()] + [fade[1][0]]
        policy_values.extend(b["condition"] for p in colour_proofs.values()
            for b in p["native_argument_flow"]["branches"])
        policy_values.extend(b["condition"] for b in reveal_flow["branches"])
        self.duration_globals = set().union(*(_global_reads(v) for v in policy_values))
        total = self.analysis.header.non_volatile_globals + self.analysis.header.volatile_globals
        if any(not 0 <= g < total for g in self.global_ids):
            raise ValueError("整幕转场缓存超出原生声明。")
        self.snapshot = dict(snapshot=b"".join(_push_global(g) for g in self.global_ids),
            restore=b"".join(_pop_global(g) for g in reversed(self.global_ids)))
        self._report = dict(schema=SCHEMA, source_sha256=self.source.source_sha256,
            analysis_sha256=self.analysis.source_sha256, runtime_binding=pair,
            colour_target=self.colour.start, colour_arguments=self.colour.args,
            colour_proofs=colour_proofs, reveal_target=self.reveal.start,
            native_colour_initialization_sites={str(p["palette"]): palette_sites[p["palette"]]
                for p in colour_proofs.values()},
            native_entry_reachability=reachability,
            reveal_arguments=self.reveal.args, native_reveal_flow=reveal_flow,
            native_dependencies=self.closure.describe(), global_ids=list(self.global_ids),
            global_snapshot_scope="isolated_active_paths_only", duration_global_ids=sorted(self.duration_globals),
            methods=list(METHODS), native_duration_policy_preserved=True,
            original_preference_unchanged=True, inherited_refresh_isolated=True,
            native_reveal_source_sha256=hashlib.sha256(raw).hexdigest(),
            game_name_switch_used=False, source_size_rule_changed=False,
            original_functions_patched=False, runtime_verified=False)

    def _expand(self, address, values):
        effects, roots, writes, visited = [], set(), set(), set()
        def visit(a, args, ancestors=()):
            key = (a, repr(args))
            if key in visited:
                return
            if a in ancestors or len(ancestors) > 6 or len(visited) >= 64:
                raise ValueError("色场调用链超出限定范围。")
            visited.add(key)
            roots.add(a)
            literals = {i: v["value"] for i, v in enumerate(args) if v.get("kind") == "literal"
                        and (v["value"] is None or type(v["value"]) in {int, bool, str})}
            trace = self.flow.trace(a, literal_arguments=literals, max_joined_values=128)
            if trace["status"] != "proven_static_argument_flow":
                raise ValueError("色场参数流未确定。")
            writes.update(w["slot"] for w in trace["global_writes"])
            for c in trace["calls"]:
                operands = [_substitute(v, tuple(args)) for v in c["arguments"]]
                if c["kind"] == "call":
                    visit(c["address"], operands, (*ancestors, a))
                elif c.get("name") == "Dissolve":
                    effects.append(dict(name="Dissolve", offset=c["offset"], arguments=operands))
                else:
                    raise ValueError("色场路径还有未隔离的系统调用："+str(c.get("name"))+" @"+str(c["offset"]))
        visit(address, values)
        return effects, roots, writes

    def syscall(self, name, args):
        ident, count = self._syscalls[name]
        if count != len(args):
            raise ValueError("整幕转场系统调用参数不完整。")
        return _arguments(args) + b"\x03" + struct.pack("<H", ident)

    def _prepare_copy(self, output, span, retained_calls, allowed_syscalls, removed_alpha=(), *,
                      append_offset=None, removed_syscalls=()):
        if (self.source.original_bytes[span.start:span.end] != self.analysis.original_bytes[span.start:span.end]
                or any(i.dirty or i.warning or not i.known for i in span.instructions)):
            raise ValueError("转场副本的原生函数证据已变化。")
        base = len(self.source.original_bytes) if append_offset is None else append_offset
        if type(base) is not int or not len(self.source.original_bytes) <= base < 2**32:
            raise ValueError("转场副本必须附加到这个运行脚本末尾之后。")
        if base+len(output)+(span.end-span.start)+6*len(span.instructions)+5 >= 2**32:
            raise ValueError("转场副本超出原生地址范围。")
        start = len(output)
        output.extend(b"\x06\0\0\0\0")
        stubs, edits = {}, []
        # Syscall->CALL replacements consume the same declared operands. A
        # native ret unwinds the stub frame; no VM globals/header slots added.
        def stub(count):
            if count not in stubs:
                stubs[count] = base + len(output)
                output.extend(bytes((1, count, 0, 4)))
            return stubs[count]
        replacements = {}
        for ins in span.instructions:
            if ins.mnemonic == "call" and ins.offset not in retained_calls:
                count = self.spans[ins.operands["target"]].args
                replacements[ins.offset] = _call(stub(count))
            elif ins.mnemonic == "syscall":
                name = self.analysis.header.syscalls[ins.operands["id"]].name
                if ins.offset in removed_syscalls:
                    replacements[ins.offset] = _call(stub(self.analysis.header.syscalls[ins.operands["id"]].args))
                elif name == "PrimSetAlpha":
                    if ins.offset not in removed_alpha:
                        raise ValueError("显现副本出现未检查的透明度调用。")
                    replacements[ins.offset] = _call(stub(2))
                elif name not in allowed_syscalls:
                    raise ValueError("显现副本出现未检查的系统调用。")
        address, cursor = base + len(output), base + len(output)
        mapping = {}
        for ins in span.instructions:
            mapping[ins.offset] = cursor
            cursor += len(replacements.get(ins.offset, ins.raw))
        for ins in span.instructions:
            raw = replacements.get(ins.offset, ins.raw)
            if ins.mnemonic in {"jmp", "jz"}:
                target = ins.operands["target"]
                if target not in mapping:
                    raise ValueError("显现副本出现跨函数跳转。")
                raw = bytes((ins.opcode,)) + struct.pack("<I", mapping[target])
            if ins.offset in replacements:
                edits.append(dict(source_offset=ins.offset, operation=ins.mnemonic,
                    replacement_target=struct.unpack_from("<I", raw, 1)[0]))
            output.extend(raw)
        struct.pack_into("<I", output, start+1, base+len(output))
        return address, dict(address=address, source=[span.start, span.end],
            edits=edits, stubs=stubs, variable_width_jumps_relocated=True,
            original_functions_patched=False, camera_unchanged=True,
            portrait_and_cg_alpha_unchanged=True, runtime_verified=False)

    def prepare_colour(self, output):
        return self._prepare_copy(output, self.colour, self._colour_retained_calls, {"ColorSet", "Dissolve"})

    def prepare_reveal(self, output, *, append_offset=None):
        retained = () if self._retained_call is None else (self._retained_call,)
        return self._prepare_copy(output, self.reveal, retained, {"Dissolve"}, self.removed_alpha,
                                  append_offset=append_offset)

    def colour_code(self, address, colour, duration):
        if colour not in {"black", "white"}:
            raise ValueError("不是已绑定的原生黑白色场。")
        return _arguments([duration, -1 if colour == "black" else -2, None, None, None,
                           *self._colour_params]) + _call(address)

    def reveal_code(self, address, duration):
        return _arguments([duration, *([1] if self.reveal.args == 2 else [])]) + _call(address)

    def report(self):
        return deepcopy(self._report)

    def portrait_cache_protection(self, slots):
        used = set().union(*(set(s.global_ids) | set(s.read_global_ids) for s in slots))
        protected = sorted(used & set(self.global_ids))
        if set(protected) & self.duration_globals:
            raise ValueError("转场时间设置与当前角色缓存冲突，不能套用这个原生入口。")
        return dict(protected_shared_global_ids=protected, graph_handles_unchanged=True,
            primitive_handles_unchanged=True, synchronous_native_fade_waits_required=True,
            runtime_verified=False)


class NativeSceneScreenTransition:
    def __init__(self, target, output):
        self.binding, self.output = NativeScreenTransition(target.context), output
        self.target = target
        self.chapter_masks = None
        self.snapshot = self.binding.snapshot
        output.extend(self.snapshot["snapshot"])
        self.colour, self.colour_copy = self.binding.prepare_colour(output)
        self.reveal, self.copy = self.binding.prepare_reveal(output)
        self.covered, self.operations = None, []
        self._protected_prefix, self._protected_suffix = b"", b""
        self.portrait_ownership = None

    def bind_portraits(self, slots):
        self.portrait_ownership = self.binding.portrait_cache_protection(tuple(slots))
        ids = self.portrait_ownership["protected_shared_global_ids"]
        self._protected_prefix = b"".join(_push_global(g) for g in ids)
        self._protected_suffix = b"".join(_pop_global(g) for g in reversed(ids))

    def state(self):
        return self.covered

    def restore_compiler_state(self, state):
        self.covered = state

    def emit(self, event):
        if (set(event) != {"kind", "method", "duration_ms"} or event["kind"] != "Transition"
                or event["method"] not in METHODS or type(event["duration_ms"]) is not int
                or not 100 <= event["duration_ms"] <= 3000):
            raise ValueError("整幕转场支持黑／白淡出、淡入和往返，单程 100～3000 毫秒；遮罩转场尚未接通。")
        method, duration = event["method"], event["duration_ms"]
        wait = self.binding.syscall("DissolveWait", (True,))
        self.output.extend(self._protected_prefix + wait)
        if method.startswith(("black", "white")):
            colour = "black" if method.startswith("black") else "white"
            self.output.extend(self.binding.colour_code(self.colour, colour, duration) + wait)
            self.covered = colour
        if method in {"reveal", "black_return", "white_return"}:
            self.output.extend(self.binding.reveal_code(self.reveal, duration) + wait)
            self.covered = None
        self.operations.append(deepcopy(event))
        self.output.extend(self._protected_suffix)

    def before_background(self, duration):
        if self.covered is not None and duration:
            raise ValueError("黑白场下请直接换背景，再添加淡入恢复画面。")
        return self.covered is None

    def chapter_before(self, transition):
        from .gui_chapter_transition import transition_values
        transition = transition_values(transition)
        method = transition["type"]
        if method in {"black", "white"} and self.covered != method:
            self.emit(dict(kind="Transition", method=method+"_out", duration_ms=transition["duration_ms"]))
        else:
            self.output.extend(self.binding.syscall("DissolveWait", (True,)))

    def chapter_after(self, transition):
        from .gui_chapter_transition import transition_values
        transition = transition_values(transition)
        duration = max(1, transition["duration_ms"])
        wait = self.binding.syscall("DissolveWait", (True,))
        self.output.extend(self._protected_prefix)
        if transition["type"] == "mask":
            if self.chapter_masks is None:
                from .native_transition_masks import NativeTransitionMasks
                self.chapter_masks = NativeTransitionMasks(self.binding,
                    self.target.context.abi.native_background_backend, self.target.root)
                self.chapter_mask_address, self.chapter_mask_copy = self.chapter_masks.prepare(self.output)
            self.output.extend(self.chapter_masks.code(self.chapter_mask_address, transition["mask"], duration))
        else:
            # Nil source is the native previous-frame -> new-frame blend;
            # a 1ms native instant is a cut, not a 100ms UI fade.
            self.output.extend(self.binding.reveal_code(self.reveal, duration))
        self.output.extend(wait + self._protected_suffix)
        self.covered = None
        self.operations.append(dict(kind="ChapterTransition", **transition))

    def finish(self):
        if self.operations:
            # Remove only this test scene's solid cover before returning. This
            # does not rebuild the inherited story's BG/CG/portrait resources.
            # Unconditional for scene-exit choices: their final cover can differ
            # and only the selected route will have executed at runtime.
            self.output.extend(self._protected_prefix + self.binding.reveal_code(self.reveal, 1)
                + self.binding.syscall("DissolveWait", (True,)) + self._protected_suffix)
            self.covered = None
        self.output.extend(self.snapshot["restore"])

    def report(self):
        return dict(binding=self.binding.report(), colour_copy=deepcopy(self.colour_copy), reveal_copy=deepcopy(self.copy),
            chapter_masks=self.chapter_masks.report() if self.chapter_masks else None,
            portrait_ownership=deepcopy(self.portrait_ownership),
            operations=deepcopy(self.operations), waits_each_leg=True,
            removes_scene_cover_at_end=True, original_images_restored=False,
            runtime_verified=False)
