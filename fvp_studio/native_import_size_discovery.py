"""Read-only native import-size evidence, selected by code shape, not title.

This is a bounded static extractor, not a VM or a source-frame renderer.
It extracts regular, explicit form branches and the fresh-load Nil-Z default.
Cached actor state, special suffix overrides and story V3D are not imported.
Missing/ambiguous code shapes fail closed. Legacy implicit RS requires a
separate native initializer proof, never the modern engine's assumed value.
"""
from __future__ import annotations

from .engine_patterns import engine_pattern

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct

from .hcb import parse_bytes
from .native_portrait_acceptance import _function_spans, _integer_value

SCHEMA = "fvp-native-import-size-discovery/1"


class NativeSizeDiscoveryError(ValueError):
    pass


@dataclass(frozen=True)
class _Expr:
    operation: str
    arguments: tuple


def _binary(op, left, right):
    if isinstance(left, _Expr) or isinstance(right, _Expr):
        return _Expr(op, (left, right))
    if op in ("set_e", "set_ne"):
        same = type(left) is type(right) and left == right
        return same if op == "set_e" else not same
    if op == "add":
        return left + right
    if op == "sub":
        return left - right
    if op == "mul":
        return left * right
    if op == "div":
        if not right:
            raise NativeSizeDiscoveryError("静态大小分支除零")
        value = left / right
        return int(value) if type(left) is type(right) is int else value
    raise NativeSizeDiscoveryError(f"不支持的大小算式 {op}")


def _comparison(body, index):
    if index + 3 >= len(body) or body[index].mnemonic != "push_stack":
        return None
    slot = body[index].operands["value"]
    if slot >= -1:
        return None
    code = _integer_value(body[index + 1])
    if code is None:
        return None
    cursor = index + 2
    if body[cursor].mnemonic == "neg":
        code, cursor = -code, cursor + 1
    if (cursor + 1 >= len(body) or body[cursor].mnemonic != "set_e"
            or body[cursor + 1].mnemonic != "jz"):
        return None
    target = body[cursor + 1].operands["target"]
    stop = next((n for n in range(cursor + 2, len(body))
                 if body[n].offset == target), None)
    if stop is None:
        raise NativeSizeDiscoveryError("形态条件跳转不在当前函数指令边界")
    return slot, code, cursor + 2, stop


def _literal_assignment(body, start, stop):
    if start >= stop:
        return None
    value = _integer_value(body[start])
    cursor = start + 1
    if cursor < stop and body[cursor].mnemonic == "neg":
        value, cursor = -value if value is not None else None, cursor + 1
    if value is None or cursor >= stop or body[cursor].mnemonic != "pop_stack":
        return None
    if cursor + 1 < stop and body[cursor + 1].mnemonic not in ("jmp", "nop"):
        return None
    return body[cursor].operands["value"], value, body[start].offset


def _nil_defaults(body):
    """Recognise both Nil== and Nil!= arms; require the opposite argument arm."""
    by_offset = {item.offset: n for n, item in enumerate(body)}
    found = {}
    for n in range(len(body) - 7):
        a, b, comparison, branch = body[n:n + 4]
        if (a.mnemonic != "push_stack" or a.operands["value"] >= -1
                or b.mnemonic != "push_nil"
                or comparison.mnemonic not in ("set_e", "set_ne")
                or branch.mnemonic != "jz"):
            continue
        start, false = n + 4, by_offset.get(branch.operands["target"])
        if false is None or not start < false <= start + 8:
            continue
        argument = a.operands["value"]
        if comparison.mnemonic == "set_e":
            literal = _literal_assignment(body, start, false)
            opposite = body[false:false + 2]
        else:
            opposite = body[start:start + 2]
            jump = body[false - 1]
            if jump.mnemonic != "jmp":
                continue
            join = by_offset.get(jump.operands["target"])
            literal = _literal_assignment(body, false, join or false)
        if (literal is None or len(opposite) != 2
                or opposite[0].mnemonic != "push_stack"
                or opposite[0].operands["value"] != argument
                or opposite[1].mnemonic != "pop_stack"
                or opposite[1].operands["value"] != literal[0]):
            continue
        local, value, offset = literal
        found.setdefault(local, set()).add((value, argument, offset))
    return {slot: next(iter(values)) for slot, values in found.items()
            if len({(row[0], row[1]) for row in values}) == 1}


def _linear_calls(doc, body, start, stop, defaults):
    values, locals_, calls = [], {slot: value[0] for slot, value in defaults.items()}, []
    for item in body[start:stop]:
        name = item.mnemonic
        if name in ("push_i8", "push_i16", "push_i32", "push_f32"):
            values.append(item.operands["value"])
        elif name == "push_stack":
            slot = item.operands["value"]
            values.append(locals_.get(slot, _Expr("local", (slot,))))
        elif name == "pop_stack" and values:
            locals_[item.operands["value"]] = values.pop()
        elif name == "push_nil":
            values.append(None)
        elif name == "push_true":
            values.append(True)
        elif name == "push_string":
            values.append(item.text)
        elif name == "neg" and values:
            value = values.pop()
            values.append(_Expr("neg", (value,)) if isinstance(value, _Expr) else -value)
        elif name in ("add", "sub", "mul", "div", "set_e", "set_ne") and len(values) >= 2:
            right, left = values.pop(), values.pop()
            values.append(_binary(name, left, right))
        elif name == "syscall":
            syscall = doc.header.syscalls[item.operands["id"]]
            argc = syscall.args
            if len(values) < argc:
                raise NativeSizeDiscoveryError("大小分支的系统调用参数不足")
            arguments = tuple(values[-argc:]) if argc else ()
            if argc:
                del values[-argc:]
            calls.append((syscall.name, arguments, item.offset))
        elif name == "jmp":
            if item.operands["target"] < body[stop].offset:
                raise NativeSizeDiscoveryError("大小分支存在非直线跳转")
            break
        elif name != "nop":
            raise NativeSizeDiscoveryError(f"大小分支含未证明指令 {name}")
    if values:
        raise NativeSizeDiscoveryError("大小分支有未消费的栈值")
    return calls


def _suffixes(doc, body):
    """Only suffix concatenation immediately upstream of paired body/Parts loading."""
    loads = [n for n, item in enumerate(body) if item.mnemonic == "syscall"
             and doc.syscall_names[item.operands["id"]] == "GraphLoad"
             and any(x.mnemonic == "syscall" and doc.syscall_names[x.operands["id"]]
                     == "PartsLoad" for x in body[n + 1:n + 13])]
    if len(loads) != 1 or loads[0] < 2 or body[loads[0] - 1].mnemonic != "push_stack":
        raise NativeSizeDiscoveryError("没有唯一的身体/表情成对加载路径")
    load = loads[0]
    resource_slot = body[load - 1].operands["value"]
    result = {}
    for n in range(max(0, load - 160), load):
        branch = _comparison(body, n)
        if branch is None:
            continue
        slot, code, start, stop = branch
        if stop > load or stop - start > 45:
            continue
        suffixes = [body[k + 1].text for k in range(start, stop - 3)
                    if body[k].mnemonic == "push_stack"
                    and body[k].operands["value"] == resource_slot
                    and body[k + 1].mnemonic == "push_string"
                    and body[k + 2].mnemonic == "add"
                    and body[k + 3].mnemonic == "pop_stack"
                    and body[k + 3].operands["value"] == resource_slot]
        if len(suffixes) == 1:
            result[(slot, code)] = dict(suffix=suffixes[0], guard=body[n].offset,
                                       conditional_override=any(x.mnemonic == "jz"
                                                                for x in body[start:stop]))
        elif not suffixes and all(x.mnemonic in ("jmp", "nop") for x in body[start:stop]):
            result[(slot, code)] = dict(suffix="", guard=body[n].offset,
                                       conditional_override=False)
    if not result:
        raise NativeSizeDiscoveryError("无法从原生加载分支提取资源后缀")
    return result


def extract_hcb_size_rules(document):
    spans = _function_spans(document)
    candidates = [span for span in spans
                  if {"GraphLoad", "PartsLoad", "PrimSetZ"}
                  <= set(span.syscalls)
                  and any(item.mnemonic == "push_string" and item.text
                          and re.search(r"(?:graph_bs|graph)/CHR_", item.text)
                          for item in span.instructions)]
    matched = []
    for span in candidates:
        if any(item.mnemonic.startswith("unknown") for item in span.instructions):
            continue
        try:
            suffixes = _suffixes(document, span.instructions)
        except NativeSizeDiscoveryError:
            continue
        matched.append((span, suffixes))
    if len(matched) != 1:
        raise NativeSizeDiscoveryError("原生立绘分派器不是唯一可识别结构")
    span, suffixes = matched[0]
    body = span.instructions
    defaults, rows = _nil_defaults(body), []
    if any(not -(span.args + 1) <= slot <= -2 for slot, _code in suffixes):
        raise NativeSizeDiscoveryError("形态参数位超出原生函数参数范围")
    for n in range(len(body) - 4):
        branch = _comparison(body, n)
        if branch is None:
            continue
        slot, code, start, stop = branch
        if (slot, code) not in suffixes or stop - start > 180:
            continue
        section = body[start:stop]
        if not any(item.mnemonic == "syscall"
                   and document.syscall_names[item.operands["id"]] == "PrimSetRS"
                   for item in section):
            continue
        # Character-dependent OP/XY form branches can enclose later RS form
        # branches. Only the innermost RS/Z block is a linear size proof.
        if any(item.mnemonic == "jz" for item in section):
            continue
        calls = _linear_calls(document, body, start, stop, defaults)
        rs_calls = [call for call in calls if call[0] == "PrimSetRS"]
        z_calls = [call for call in calls if call[0] == "PrimSetZ"]
        if (not rs_calls or len(rs_calls) != len(z_calls)
                or any(len(call[1]) != 3 for call in rs_calls)
                or any(len(call[1]) != 2 for call in z_calls)
                or {call[1][0] for call in rs_calls} != {call[1][0] for call in z_calls}):
            raise NativeSizeDiscoveryError("身体与表情的 RS/Z 配对不闭合")
        scales, depths = {call[1][2] for call in rs_calls}, {call[1][1] for call in z_calls}
        if (len(scales) != 1 or len(depths) != 1
                or any(type(value) is not int or value <= 0 for value in scales | depths)):
            raise NativeSizeDiscoveryError("原生 RS/Z 不是唯一正整数")
        rows.append(dict(form=code, form_slot=slot, **suffixes[(slot, code)],
                         rs=next(iter(scales)), source_z=next(iter(depths)),
                         rs_sites=[call[2] for call in rs_calls],
                         z_sites=[call[2] for call in z_calls],
                         geometry_guard=body[n].offset))
    if len({row["form"] for row in rows}) != len(rows):
        raise NativeSizeDiscoveryError("同一形态存在多组默认大小")
    direct_geometry_sites = {item.offset for item in body
                             if item.mnemonic == "syscall" and document.syscall_names[
                                 item.operands["id"]] in ("PrimSetRS", "PrimSetZ")}
    extracted_sites = {site for row in rows for site in row["rs_sites"] + row["z_sites"]}
    if rows and direct_geometry_sites != extracted_sites:
        raise NativeSizeDiscoveryError("分派器还有未解析的 RS/Z 分支，不能称为通用默认大小")
    spans_by_start = {region.start: region for region in spans}
    visited, pending, reachable_syscalls = set(), [span.start], set()
    while pending:
        target = pending.pop()
        if target in visited:
            continue
        visited.add(target)
        region = spans_by_start.get(target)
        if region is None:
            raise NativeSizeDiscoveryError("分派器调用了无法解析的函数入口")
        if (any(item.mnemonic.startswith("unknown") for item in region.instructions)
                or "<unknown>" in region.syscalls):
            raise NativeSizeDiscoveryError("原生大小调用链中存在未解析指令，不能忽略下游证据")
        if target != span.start and set(region.syscalls) & {"PrimSetRS", "PrimSetZ"}:
            raise NativeSizeDiscoveryError("下游函数还会修改 RS/Z；当前直线分支解析不足以证明默认大小")
        reachable_syscalls.update(region.syscalls)
        pending.extend(region.calls)
    implicit = "PrimSetRS" not in reachable_syscalls
    implicit_z = []
    if implicit:
        for n, item in enumerate(body):
            if item.mnemonic != "syscall" or document.syscall_names[item.operands["id"]] != "PrimSetZ":
                continue
            start = n
            while start > 0 and n - start < 12 and body[start - 1].mnemonic not in (
                    "call", "syscall", "jmp", "jz", "init_stack"):
                start -= 1
            try:
                calls = _linear_calls(document, body, start, n + 1, defaults)
            except NativeSizeDiscoveryError:
                continue
            for label, arguments, site in calls:
                if label == "PrimSetZ" and len(arguments) == 2 and type(arguments[1]) is int:
                    implicit_z.append(dict(source_z_if_fresh=arguments[1], site=site))
    return dict(schema=SCHEMA, hcb_sha256=document.source_sha256,
                dispatcher=span.start, argument_count=span.args,
                resource_prefixes=sorted({item.text for item in body
                    if item.mnemonic == "push_string" and item.text
                    and re.search(r"(?:graph_bs|graph)/CHR_", item.text)}),
                forms=rows, implicit_engine_rs_required=implicit,
                implicit_z_evidence=implicit_z,
                unresolved_geometry_sites=sorted(direct_geometry_sites - extracted_sites
                    - {row["site"] for row in implicit_z}),
                native_size_syscall_arities={call.name: call.args for call in document.header.syscalls
                    if call.name in ("PrimSetRS", "PrimSetSprt")},
                reached_syscall_names=sorted(reachable_syscalls),
                source_suffix_forms=[dict(form=code, form_slot=slot, **value)
                                     for (slot, code), value in sorted(suffixes.items())],
                nil_defaults=[dict(local=slot, value=row[0], argument=row[1], site=row[2])
                              for slot, row in sorted(defaults.items())],
                unrelated_parse_warning_count=len(document.warnings),
                uses_face_matching=False, uses_story_camera=False,
                runtime_visual_verified=False, discovery_is_read_only=True)


def _pe_sections(raw):
    if len(raw) < 64 or raw[:2] != b"MZ":
        raise NativeSizeDiscoveryError("来源不是 PE EXE")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if pe + 24 > len(raw) or raw[pe:pe + 4] != b"PE\0\0":
        raise NativeSizeDiscoveryError("PE 文件头无效")
    if struct.unpack_from("<H", raw, pe + 4)[0] != 0x14C:
        raise NativeSizeDiscoveryError("此画幅读取器只接受已识别的 x86 机器类型")
    count, size = struct.unpack_from("<H", raw, pe + 6)[0], struct.unpack_from("<H", raw, pe + 20)[0]
    optional = pe + 24
    if size < 32 or optional + size > len(raw) or struct.unpack_from("<H", raw, optional)[0] != 0x10B:
        raise NativeSizeDiscoveryError("尚未证明此 PE 机器类型的画幅读取方式")
    image_base = struct.unpack_from("<I", raw, optional + 28)[0]
    sections = []
    for n in range(count):
        pos = optional + size + n * 40
        if pos + 40 > len(raw):
            raise NativeSizeDiscoveryError("PE 分节表越界")
        virtual_size, rva, raw_size, pointer = struct.unpack_from("<IIII", raw, pos + 8)
        flags = struct.unpack_from("<I", raw, pos + 36)[0]
        if pointer + raw_size > len(raw):
            raise NativeSizeDiscoveryError("PE 分节内容越界")
        sections.append((virtual_size, rva, raw_size, pointer, flags))
    return image_base, sections


def extract_exe_viewport(raw, mode):
    """Match bounded 16-mode x86 indexed width/height loads, relocating PE VAs.

    No known file offset, executable hash, game title or BG dimensions selects
    the result. Unsupported native reader shapes are explicitly rejected.
    """
    if type(mode) is not int or not 0 <= mode < 16:
        raise NativeSizeDiscoveryError("原生画幅模式不在此读取器已证明范围")
    image, sections = _pe_sections(raw)
    reader = re.compile(engine_pattern('native_import_size_discovery:363:24'), re.DOTALL)
    candidates = set()
    for _virtual_size, _rva, size, pointer, flags in sections:
        if not flags & 0x20000000:
            continue
        code = raw[pointer:pointer + size]
        reads = list(reader.finditer(code))
        for left, right in zip(reads, reads[1:]):
            address = struct.unpack("<I", left.group(2))[0]
            if (right.start() - left.start() > 48 or left.group(1) != right.group(1)
                    or struct.unpack("<I", right.group(2))[0] != address + 2
                    or not code[max(0, left.start() - 9):left.start()].endswith(
                        engine_pattern('native_import_size_discovery:376:24'))):
                continue
            entries = [part for part in sections if not part[4] & 0x20000000
                       and part[1] <= address - image < part[1] + part[2] - 63]
            if len(entries) != 1:
                continue
            part = entries[0]
            offset = part[3] + address - image - part[1]
            table = [struct.unpack_from("<HH", raw, offset + n * 4) for n in range(16)]
            if any(not (320 <= width <= 16384 and 200 <= height <= 16384)
                   for width, height in table):
                continue
            candidates.add((offset, pointer + left.start(), table[mode]))
    from .native_legacy_size_discovery import legacy_viewport_candidates
    matches = legacy_viewport_candidates(raw, mode, image, sections)
    for offset, site, viewport in candidates:
        matches.append(dict(viewport=list(viewport), mode=mode, table_offset=offset,
            reader_offset=site, exe_sha256=hashlib.sha256(raw).hexdigest(),
            evidence="bounded-x86-16-mode-indexed-width-height-reader/1"))
    if len(matches) != 1:
        raise NativeSizeDiscoveryError("原生 EXE 画幅读取器没有唯一匹配，不能猜画幅")
    return matches[0]


def _exe_size_evidence(raw, mode, proof):
    result = extract_exe_viewport(raw, mode)
    if not proof["implicit_engine_rs_required"]:
        return result
    result["implicit_engine_rs_resolved"] = False
    try:
        from .native_legacy_size_discovery import extract_legacy_engine_rs
        if proof["native_size_syscall_arities"] != {"PrimSetRS": 3, "PrimSetSprt": 4}:
            raise NativeSizeDiscoveryError("脚本与旧版原生大小调用的参数契约不匹配")
        suffixes, depths = proof["source_suffix_forms"], proof["implicit_z_evidence"]
        if (not suffixes or len({row["form_slot"] for row in suffixes}) != 1
                or len({row["form"] for row in suffixes}) != len(suffixes)
                or any(row["conditional_override"] for row in suffixes)
                or len(depths) != 1 or depths[0]["source_z_if_fresh"] <= 0
                or proof["unresolved_geometry_sites"]):
            raise NativeSizeDiscoveryError("旧版原生形态与 fresh-load Z 不是唯一闭合分支")
        engine = extract_legacy_engine_rs(raw)
        result.update(engine_rs_evidence=engine, implicit_engine_rs_resolved=True,
            forms=[dict(**row, rs=engine["rs"], source_z=depths[0]["source_z_if_fresh"],
                        rs_sites=[], engine_rs_sites=engine["initializer_rs_sites"],
                        z_sites=[depths[0]["site"]], geometry_guard=depths[0]["site"],
                        rs_origin="native-engine-initializer") for row in suffixes])
    except NativeSizeDiscoveryError as exc:
        result["implicit_engine_rs_reason"] = str(exc)
    return result


def discover_native_size(hcb_path: Path, exe_path: Path):
    document = parse_bytes(Path(hcb_path).read_bytes(), encoding="shift_jis")
    result = extract_hcb_size_rules(document)
    try:
        result.update(_exe_size_evidence(Path(exe_path).read_bytes(), document.header.game_mode, result))
        result["viewport_resolved"] = True
    except NativeSizeDiscoveryError as exc:
        result["viewport_resolved"] = False
        result["viewport_reason"] = str(exc)
    return result


def native_size_signature(proof):
    """Compare size semantics only, never choose the active story/launcher.

    Relocated call sites and script hashes can differ after translation while
    the same dispatcher still yields identical source sizes. Include prefixes,
    parameter slots and special-override policy so unrelated rules cannot pass
    merely because their numeric RS/Z happen to coincide.
    """
    return {
        "viewport": list(proof["viewport"]),
        "resource_prefixes": sorted(proof["resource_prefixes"]),
        "argument_count": proof["argument_count"],
        "native_size_syscall_arities": dict(proof["native_size_syscall_arities"]),
        "implicit_engine_rs_required": proof["implicit_engine_rs_required"],
        "forms": [{key: row.get(key) for key in
                   ("form", "form_slot", "suffix", "rs", "source_z", "conditional_override")}
                  for row in sorted(proof["forms"], key=lambda row: row["form"])],
    }


def _resolve_script_size(script, executables):
    document = parse_bytes(script.read_bytes(), encoding="shift_jis")
    proof = extract_hcb_size_rules(document)
    if not proof["forms"] and not proof["implicit_engine_rs_required"]:
        raise NativeSizeDiscoveryError("没有完整的原生大小分支")
    matches = []
    for executable, raw in executables:
        try:
            viewport = _exe_size_evidence(raw, document.header.game_mode, proof)
        except NativeSizeDiscoveryError:
            continue
        matches.append((executable, viewport))
    if not matches or len({tuple(viewport["viewport"]) for _exe, viewport in matches}) != 1:
        raise NativeSizeDiscoveryError("没有唯一的原生 EXE 画幅证据；不使用 BG 尺寸或预设分辨率代替")
    if proof["implicit_engine_rs_required"]:
        if any(not evidence["implicit_engine_rs_resolved"] for _exe, evidence in matches):
            raise NativeSizeDiscoveryError("原生 EXE 隐含 RS 仍有未闭合证据，不套用现代版参数")
        rules = {tuple((row["form"], row["rs"], row["source_z"]) for row in evidence["forms"])
                 for _exe, evidence in matches}
        if len(rules) != 1:
            raise NativeSizeDiscoveryError("来源 EXE 的隐含原生 RS 结论不一致，不能任选一份")
    # Patched/unpatched EXEs can share a source folder. Require every matching
    # native reader to agree and retain all fingerprints, not a guessed launcher.
    executable, viewport = matches[0]
    return {**proof, **viewport, "source_hcb": str(script),
            "source_exe": str(executable),
            "exe_evidence": [dict(path=str(exe), **evidence) for exe, evidence in matches],
            "viewport_resolved": True}


def discover_source_root(root: Path):
    """Require every candidate script to prove the same native size policy.

    This agreement authorises size extraction only. It cannot determine which
    HCB/BCH the game actually executes, nor authorise writes to any candidate.
    Any unparseable candidate, unresolved native shape or disagreement fails
    closed instead of favouring a visible/hidden filename or known title.
    """
    root = Path(root).resolve(strict=True)
    inputs = sorted(path for path in root.iterdir()
                    if path.is_file() and not path.is_symlink())
    scripts = [path for path in inputs if path.suffix.casefold() in (".hcb", ".bch")]
    if not scripts:
        raise NativeSizeDiscoveryError("来源没有 HCB/BCH，不能猜测原生大小")
    executables = [(path, path.read_bytes()) for path in inputs if path.suffix.casefold() == ".exe"]
    proofs = []
    for script in scripts:
        try:
            proofs.append(_resolve_script_size(script, executables))
        except ValueError as exc:
            raise NativeSizeDiscoveryError(f"来源脚本 {script.name} 的大小证据未闭合：{exc}") from exc
    signatures = {json.dumps(native_size_signature(proof), sort_keys=True) for proof in proofs}
    if len(signatures) != 1:
        raise NativeSizeDiscoveryError("来源多个脚本的原生大小规则不一致，不能任选一份："
                                       + ", ".join(path.name for path in scripts))
    # A representative holds call-site metadata; it has no runtime authority.
    representative = proofs[0]
    return {**representative,
            "script_selection": ("single_size_evidence" if len(proofs) == 1
                                  else "all_candidate_size_rules_agree"),
            "script_evidence": [{key: proof[key] for key in
                ("source_hcb", "hcb_sha256", "dispatcher", "forms", "exe_evidence")}
                for proof in proofs],
            "size_consensus": True, "runtime_active_script_determined": False}


def select_body_size_rule(proof, body, available_names):
    """Resolve a regular source form by parsed suffixes + real resource siblings.

    Filename suffixes alone cannot establish a form. A prefix in the selected
    source dispatcher and at least one real sibling are also required. Longest
    parsed suffix wins (LL must not be mistaken for L). No face-size metric is
    consulted; a caller must additionally validate actual body/Parts metadata.
    """
    prefixes = [value.split("/", 1)[1] for value in proof["resource_prefixes"]]
    if not any(body.startswith(prefix + "_") for prefix in prefixes):
        raise NativeSizeDiscoveryError("该身体没有对应的原生角色资源前缀证据")
    forms = proof["forms"]
    candidates = []
    for form in forms:
        suffix = form["suffix"]
        if suffix and not body.endswith(suffix):
            continue
        base = body[:-len(suffix)] if suffix else body
        siblings = [base + row["suffix"] for row in forms
                    if row["suffix"] != suffix and base + row["suffix"] in available_names]
        if siblings:
            candidates.append((len(suffix), form))
    if not candidates:
        raise NativeSizeDiscoveryError("此身体缺少可核对的原生形态同族资源；不按名称猜大小")
    longest = max(length for length, _form in candidates)
    selected = [form for length, form in candidates if length == longest]
    if len(selected) != 1:
        raise NativeSizeDiscoveryError("该身体对应多个原生大小规则，请明确选择形态")
    return dict(selected[0])
