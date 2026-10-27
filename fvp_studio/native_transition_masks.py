"""Masks proved through the selected game's own Dissolve argument flow.

Only the isolated dissolve/duration path is copied. Native scene refresh,
CG-alpha changes and waits on inherited workers are not chapter transitions.
Resource IDs are not interpreted as directions or borrowed across games.
"""
from pathlib import Path
import re

from .bin_archive import archive_entry_table_file, hzc_metadata
from .gui_runtime import fingerprint
from .hoshimemo_scene_hook import _arguments, _call, _push_global, _pop_global
from .native_background_backend import _literal
from .native_screen_transition import _duration, _has_return

PATH = re.compile(r"([A-Za-z0-9_]+)/(?P<id>diss[0-9]{2,3})\Z")


def _independent_of_return(value):
    if not _has_return(value):
        return True
    operands = value.get("operands", [])
    # The native forced/default path often has (old_refresh() != True OR
    # True). Its unreviewed result is dead, even if the symbolic flow has not
    # folded the enclosing boolean expression. Do not allow live results.
    return ((value.get("kind") == "or" and _literal(True) in operands)
            or (value.get("kind") == "and" and _literal(False) in operands))


class NativeTransitionMasks:
    def __init__(self, screen, backend, root):
        if backend is None or backend.source_sha256 != screen.source.source_sha256:
            raise ValueError("遮罩必须来自当前游戏已绑定的原生转场链。")
        self.screen, self.root = screen, Path(root).resolve()
        self.span = screen.spans[backend.dissolve_target]
        self.items, self.proofs, self.files = {}, {}, {}
        self.retained, self.removed_alpha, self.globals = set(), set(), set()
        body = self.span.instructions
        selectors = {}
        # Bind each integer selector to its actual literal branch, not to a
        # title-specific numbering table. Other branches remain unadvertised.
        for i in range(len(body)-5):
            a, b, c, d, e, f = body[i:i+6]
            if (a.mnemonic == "push_stack" and a.operands.get("value") == -(self.span.args+1)
                    and b.mnemonic in {"push_i8", "push_i16", "push_i32"}
                    and type(b.operands.get("value")) is int and b.operands["value"] >= 0
                    and c.mnemonic == "set_e" and d.mnemonic == "jz"
                    and e.mnemonic == "push_string" and PATH.fullmatch(e.text or "")
                    and f.mnemonic == "pop_stack" and f.operands.get("value") == -(self.span.args+1)):
                selectors[b.operands["value"]] = e.text
        if not selectors or len(selectors) > 128:
            raise ValueError("没有可确认的原作遮罩选择表。")
        tables = {}
        for selector, path in sorted(selectors.items()):
            match = PATH.fullmatch(path)
            archive, mask = match[1]+".bin", match["id"]
            file = self.root / archive
            if not file.is_file() or file.resolve().parent != self.root:
                continue
            if archive not in tables:
                stamp = fingerprint(file)
                rows = list(archive_entry_table_file(file))
                names = [row[2] for row in rows]
                if len(names) != len(set(names)) or fingerprint(file) != stamp:
                    raise ValueError("原作遮罩档案重名或读取期间变化。")
                tables[archive] = {row[2]: row for row in rows}
                self.files[archive] = stamp
            row = tables[archive].get(mask)
            if row is None:
                continue
            offset, size, _ = row
            if not 44 < size <= 32*1024*1024:
                continue
            with file.open("rb") as stream:
                stream.seek(offset)
                header = stream.read(44)
            try:
                meta = hzc_metadata(header, validate_pixels=False).to_dict()
            except ValueError:
                continue
            if meta["kind"] not in (3, 4) or meta["frame_count"] != 1 or meta["raw_length"] > 32*1024*1024:
                continue
            # The native default parameters decide the mode/skip policy. The
            # output copy receives these same parameters, not a guessed bool.
            literals = {i: None for i in range(self.span.args) if i != 1}
            literals[0] = selector
            trace = screen.flow.trace(self.span.start, literal_arguments=literals,
                non_nil_arguments=(1,), max_joined_values=128)
            if trace["status"] != "proven_static_argument_flow" or any(not _independent_of_return(b["condition"]) for b in trace["branches"]):
                continue
            effects, retained, alpha = [], set(), set()
            for c in trace["calls"]:
                arguments = c["arguments"]
                if c.get("name") == "Dissolve":
                    effects.append(c)
                elif (c["kind"] == "call" and len(arguments) == 7
                        and arguments[1] == _literal(path)):
                    expanded, _roots, writes = screen._expand(c["address"], arguments)
                    if writes:
                        raise ValueError("遮罩子函数包含未隔离的原生状态修改。")
                    effects.extend(expanded)
                    retained.add(c["offset"])
                elif c.get("name") == "PrimSetAlpha":
                    alpha.add(c["offset"])
                elif c["kind"] == "syscall" and c.get("name") != "DissolveWait":
                    raise ValueError("遮罩路径含有未隔离的系统调用。")
            if len(effects) != 1:
                continue
            operands = effects[0]["arguments"]
            duration = operands[0]
            # _duration describes a first-parameter timer; this wrapper's
            # timer is the second argument, so rename only that proven leaf.
            def timer(value):
                if value.get("kind") == "argument":
                    return {**value, "index": 0} if value.get("index") == 1 else value
                return {**value, **({"operands": [timer(x) for x in value["operands"]]}
                    if "operands" in value else {})}
            if (len(operands) != 7 or operands[1] != _literal(path)
                    or operands[2] not in (_literal(True), _literal(None), _literal(False))
                    or operands[3:] != [_literal(None)]*4 or not _duration(timer(duration))):
                continue
            if mask in self.items:
                raise ValueError("原作遮罩 ID 不能唯一对应。")
            self.retained.update(retained)
            self.removed_alpha.update(alpha)
            self.globals.update(w["slot"] for w in trace["global_writes"])
            self.items[mask] = dict(id=mask, label=mask, archive=archive, resource=mask,
                path=path, selector=selector, offset=offset, size=size,
                width=meta["width"], height=meta["height"], metadata=meta, runtime_verified=False)
            self.proofs[mask] = dict(selector=selector, path=path, dissolve_offset=effects[0]["offset"],
                mode=operands[2], native_duration_policy_preserved=True)
        if not self.items:
            raise ValueError("当前游戏尚无资源与原生调用链同时匹配的遮罩。")
        self.removed_alpha.update(i.offset for i in body if i.mnemonic == "syscall"
            and screen.analysis.header.syscalls[i.operands["id"]].name == "PrimSetAlpha")
        # These occur only in selector-negative/non-mask branches. Every
        # advertised positive selector was traced above and rejects any such
        # reachable effect. Balanced stubs keep the copied dormant code valid.
        self.removed_syscalls = {i.offset for i in body if i.mnemonic == "syscall"
            and screen.analysis.header.syscalls[i.operands["id"]].name not in {"PrimSetAlpha", "Dissolve", "DissolveWait"}}
        total = screen.source.header.non_volatile_globals + screen.source.header.volatile_globals
        if any(not 0 <= g < total for g in self.globals):
            raise ValueError("遮罩状态超出当前脚本声明。")
        self.check_unchanged()

    def check_unchanged(self):
        for archive, stamp in self.files.items():
            file = self.root / archive
            if file.resolve().parent != self.root or fingerprint(file) != stamp:
                raise ValueError("原作遮罩档案已经变化，请重新选择输出游戏。")

    def prepare(self, output, *, append_offset=None, nonblocking=False):
        if type(nonblocking) is not bool:
            raise ValueError('遮罩等待策略须为布尔值。')
        # Ordinary parallel beats own their old-effect wait before resource
        # preparation and their final wait after all channels have launched.
        # Retained callees are proven Dissolve-only by _expand above.
        removed = set(self.removed_syscalls)
        if nonblocking:
            removed.update(i.offset for i in self.span.instructions if i.mnemonic == 'syscall'
                and self.screen.analysis.header.syscalls[i.operands['id']].name == 'DissolveWait')
        return self.screen._prepare_copy(output, self.span, self.retained,
            {"Dissolve", "DissolveWait"}, self.removed_alpha, append_offset=append_offset,
            removed_syscalls=removed)

    def code(self, address, mask, duration):
        self.check_unchanged()
        if mask not in self.items:
            raise ValueError("选中的遮罩不属于当前输出游戏，不能借用其他游戏的编号。")
        slots = sorted(self.globals)
        return (b"".join(_push_global(g) for g in slots)
            + _arguments([self.items[mask]["selector"], duration, *([None]*(self.span.args-2))])
            + _call(address) + b"".join(_pop_global(g) for g in reversed(slots)))

    def report(self):
        return dict(schema="fvp-native-transition-masks/1", source_sha256=self.screen.source.source_sha256,
            wrapper=self.span.start, masks=list(self.items), proofs=self.proofs,
            extra_globals_allocated=False, original_functions_patched=False,
            names_are_not_directions=True, runtime_verified=False)
