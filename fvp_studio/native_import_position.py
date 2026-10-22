"""Source-code-derived FVP portrait placement, independent of titles/characters.

Extract regular fresh-load OP and XY branches, combine HZC crop offsets with
the same neutral RS/Z/viewport basis used by native import size, and convert
to Studio's cropped-bitmap bottom anchor. No scene camera or face alignment.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, replace
from copy import deepcopy
from functools import lru_cache
import hashlib
from pathlib import Path

from .hcb import parse_bytes
from .native_import_size_discovery import _comparison, extract_hcb_size_rules
from .native_portrait_acceptance import (
    _DispatcherStackLayout, _direct_branch_literal, _embedded_native_form_pivots,
    _evaluate_pivot_branch, _extract_direct_xy_scales, _function_spans, _integer_value,
)
from .performance_geometry import nearest


class NativePositionError(ValueError):
    pass


def normalized_bottom(metadata, *, pivot_y, native_y, rs, source_z, viewport_height):
    """Map the source anchor-relative lower edge, preserving approved size.

    The existing ordinary portrait node anchors the CROPPED bitmap lower edge.
    HZC offset_y must therefore participate in the conversion. This function
    never measures a head/face or changes the source height/RS/Z.
    """
    if min(rs, source_z, viewport_height, metadata["height"]) <= 0:
        raise NativePositionError("来源坐标换算的大小/画幅无效")
    factor = rs / source_z * 720 / viewport_height
    bottom = 360 + factor * (
        metadata["offset_y"] + metadata["height"] - pivot_y + native_y)
    return dict(bottom_y=nearest(bottom), exact_bottom_y=bottom,
                exact_top_y=bottom - metadata["height"] * factor,
                exact_height=metadata["height"] * factor)


def _codes(region, slot):
    return sorted({decoded[1] for index in range(len(region))
                   if region[index].mnemonic == "push_stack"
                   and region[index].operands["value"] == slot
                   and (decoded := _comparison(region, index))})


def _pose_candidates(region, slot, code):
    """Direct suffix, or a proven two-arm global-controlled suffix append.

    An explicit archive body identifies the selected suffix; this does NOT
    infer the live value of the source global. OP evaluation must still be
    independent of that unresolved global or fail closed.
    """
    try:
        return [_direct_branch_literal(region, stack_offset=slot, value=code,
                                       label="来源姿势")]
    except ValueError:
        pass
    result = []
    for index in range(len(region)):
        branch = _comparison(region, index)
        if not branch or branch[:2] != (slot, code):
            continue
        start, stop = branch[2:]
        items = region[start:stop]
        shape = ["push_global", "push_i8", "set_e", "jz", "push_stack",
                 "push_string", "add", "pop_stack", "jmp", "push_stack",
                 "push_string", "add", "pop_stack", "jmp"]
        if len(items) != len(shape) or any(item.mnemonic != name
                                           for item, name in zip(items, shape)):
            continue
        local = items[4].operands["value"]
        if not (local >= 0 and all(items[n].operands["value"] == local for n in (7, 9, 12))
                and items[3].operands["target"] == items[9].offset
                and items[8].operands["target"] == items[13].offset
                and items[13].operands["target"] >= region[stop].offset
                and all(str(items[n].text or "").startswith("_") for n in (5, 10))):
            continue
        result.extend([items[5], items[10]])
    if not result:
        raise NativePositionError("姿势后缀不属于已验证的直接/双分支拼接形态")
    return result


def _bindings(body, instructions, proof, form):
    count = proof["argument_count"]
    if form["form_slot"] != -(count - 3):
        raise NativePositionError("来源资源参数与形态参数布局尚未闭合")
    # Validate this layout against resource-root + pose + outfit branches below.
    # Unlike the TARGET compiler this source-only audit accepts a proven 14-arg
    # shape; it does not expand the target compiler's supported ABIs.
    layout = _DispatcherStackLayout(count, count - 4, -(count + 1), -count,
                                    -(count - 1), -(count - 2), form["form_slot"])
    suffix = form["suffix"]
    base = body[:-len(suffix)] if suffix else body
    matches = []
    for index, literal in enumerate(instructions):
        if literal.mnemonic != "push_string" or literal.text not in proof["resource_prefixes"]:
            continue
        root = str(literal.text).split("/", 1)[1]
        if not base.startswith(root + "_"):
            continue
        for parent in range(index):
            decoded = _comparison(instructions, parent)
            if (not decoded or decoded[0] != layout.selector
                    or not decoded[2] <= index < decoded[3]):
                continue
            selector = decoded[1]
            # Ignore alternative resource-name paths before the selected root.
            region = instructions[index:decoded[3] + 1]
            for action in _codes(region, layout.action):
                try:
                    poses = _pose_candidates(region, layout.action, action)
                except ValueError:
                    continue
                selected = [pose for pose in poses if base.startswith(root + str(pose.text) + "_")]
                if len(selected) != 1:
                    continue
                pose = selected[0]
                matching_outfit = False
                for outfit in _codes(region, layout.outfit):
                    try:
                        clothing = _direct_branch_literal(region, stack_offset=layout.outfit,
                            value=outfit, label="来源衣装")
                    except ValueError:
                        continue
                    if root + str(pose.text) + str(clothing.text) == base:
                        matching_outfit = True
                        matches.append(dict(selector=selector, action=action,
                            outfit=outfit, resource_root=literal.text,
                            root_site=literal.offset, selector_guard=instructions[parent].offset,
                            pose_site=pose.offset, outfit_site=clothing.offset,
                            pose_global_value_inferred=False,
                            outfit_name_referenced=True))
                if not matching_outfit and base.startswith(root + str(pose.text) + "_"):
                    # Archives can retain an unused wardrobe (e.g. a shared
                    # sequel asset). Do NOT invent its outfit code. An unknown
                    # outfit is accepted later ONLY if OP evaluation proves the
                    # selected role/pose origin does not depend on that argument.
                    matches.append(dict(selector=selector, action=action,
                        outfit=None, resource_root=literal.text, root_site=literal.offset,
                        selector_guard=instructions[parent].offset, pose_site=pose.offset,
                        outfit_site=None, outfit_name_referenced=False))
    signatures = {(row["selector"], row["action"], row["outfit"]) for row in matches}
    if not signatures:
        raise NativePositionError("身体资源不能绑定角色/姿势/衣装；不猜原点")
    # A source can expose several aliases for an identical body. Never select
    # the first alias blindly: every alias must prove the same native placement.
    unique = {tuple(row[key] for key in ("selector", "action", "outfit")): row for row in matches}
    return [unique[key] for key in sorted(unique,
            key=lambda values: tuple(-1 if value is None else value for value in values))], layout


def _baseline_tail(tail, *, x_local, y_local, stop_offset=None):
    """Strict constant baseline + optional caller XY additions, not a VM."""
    if len(tail) not in (18, 19) or _integer_value(tail[0]) is None:
        raise NativePositionError("默认 Y 尾段不属于已验证的常量/可选 XY 形态")
    if tail[1].mnemonic != "pop_stack" or tail[1].operands["value"] != y_local:
        raise NativePositionError("默认 Y 常量没有写入实际 XY 的 Y 槽")
    for start, local in ((2, x_local), (10, y_local)):
        a, nil, comparison, branch, old, argument, add, store = tail[start:start + 8]
        if not (a.mnemonic == "push_stack" and a.operands["value"] < -1
                and nil.mnemonic == "push_nil" and comparison.mnemonic == "set_ne"
                and branch.mnemonic == "jz" and old.mnemonic == "push_stack"
                and old.operands["value"] == local and argument.mnemonic == "push_stack"
                and argument.operands == a.operands and add.mnemonic == "add"
                and store.mnemonic == "pop_stack" and store.operands["value"] == local
                and branch.operands["target"] == (
                    tail[start + 8].offset if start + 8 < len(tail) else stop_offset)):
            raise NativePositionError("默认坐标可选覆盖分支发生变化，拒绝沿用")
    if len(tail) == 19 and (tail[-1].mnemonic != "jmp"
            or tail[-1].operands["target"] <= tail[-1].offset):
        raise NativePositionError("默认坐标尾段不是前向汇合")
    return _integer_value(tail[0])


def _guard_later_y_writes(instructions, start, stop, y_local):
    """Allow cached positions ONLY under the source's >=2 existing-state guard.

    We explicitly request a fresh actor without a previous-position cache. This
    does not determine any game's current story state or active entry script.
    """
    guards = []
    for index in range(start, stop - 3):
        a, b, comparison, jump = instructions[index:index + 4]
        if (a.mnemonic == "push_global" and _integer_value(b) == 2
                and comparison.mnemonic == "set_ge" and jump.mnemonic == "jz"):
            guards.append((a.offset, jump.operands["target"], a.operands["value"]))
    writes = []
    for item in instructions[start:stop]:
        if item.mnemonic == "pop_stack" and item.operands["value"] == y_local:
            enclosing = [row for row in guards if row[0] < item.offset < row[1]]
            if len(enclosing) != 1:
                raise NativePositionError("原点之后存在非缓存 Y 改写，不能称为新入场默认坐标")
            writes.append(dict(site=item.offset, state_global=enclosing[0][2],
                               guard=enclosing[0][0]))
        if item.mnemonic in ("call", "syscall"):
            raise NativePositionError("原点与 XY 之间还有未验证下游调用")
    return writes


def extract_position(document, proof, body, form, metadata, *, spans=None):
    if proof["hcb_sha256"] != document.source_sha256:
        raise NativePositionError("位置证据与大小证据不属于同一份来源脚本")
    spans = _function_spans(document) if spans is None else spans
    dispatcher = next(span for span in spans if span.start == proof["dispatcher"])
    instructions = dispatcher.instructions
    bindings, layout = _bindings(body, instructions, proof, form)
    rows = [_extract_bound_position(document, proof, body, form, metadata,
                spans, dispatcher, binding, layout) for binding in bindings]
    signatures = {(tuple(row["native_pivot"]), tuple(row["logical_xy_scale"]),
                   row["logical_default_y"], row["native_default_y"]) for row in rows}
    if len(signatures) != 1:
        raise NativePositionError("同一身体的原作别名有不同站位，必须由用户选择而非猜测")
    rows[0]["resource_binding_consensus"] = [
        {key: row[key] for key in ("selector", "action", "outfit", "root_site",
                                  "native_pivot", "logical_default_y", "pivot_evidence")}
        for row in rows]
    return rows[0]


def _wrapped_pivot(document, instructions, spans, dispatcher, form, binding, layout, xs, ys):
    """Prove either the three-arg wrapper or its four-arg debug variant."""
    helpers = [span for span in spans if span.start in dispatcher.calls and span.args in (3, 4)
               and span.syscalls.count("PrimSetOP") == 1]
    if len(helpers) != 1:
        raise NativePositionError("来源 OP 换算包装函数不唯一")
    helper = helpers[0]
    items = helper.instructions
    op_id = next(key for key, name in document.syscall_names.items() if name == "PrimSetOP")
    op_index = next(index for index, item in enumerate(items)
                    if item.mnemonic == "syscall" and item.operands["id"] == op_id)
    pure_start = op_index - 11
    pure = items[pure_start:op_index + 1]
    expected = ["push_stack", "push_stack", "push_f32", "mul",
                "syscall", "push_return", "push_stack", "push_f32", "mul",
                "syscall", "push_return", "syscall"]
    count = helper.args
    if ([item.mnemonic for item in pure] != expected
            or any(item.mnemonic != "ret" for item in items[op_index + 1:])
            or [pure[n].operands.get("value") for n in (0, 1, 6)] != [-count-1, -count, -count+1]
            or (pure[2].operands.get("value"), pure[7].operands.get("value")) != (xs, ys)
            or [document.syscall_names[pure[n].operands["id"]] for n in (4, 9, 11)]
                 != ["FloatToInt", "FloatToInt", "PrimSetOP"]
            or items[0].operands.get("locals") != 0):
        raise NativePositionError("来源 OP 包装函数不属于已验证 XY 同倍率纯换算形态")
    if count == 3:
        if pure_start != 1:
            raise NativePositionError("三参数 OP 包装函数存在未知前置行为")
    else:
        prelude = items[1:pure_start]
        names = ["push_stack", "push_true", "set_e", "jz"] + [
            "push_string", "push_stack", "push_f32", "mul", "syscall", "push_return", "syscall"] * 2
        if ([item.mnemonic for item in prelude] != names
                or prelude[0].operands.get("value") != -2
                or prelude[3].operands.get("target") != pure[0].offset
                or [prelude[n].operands.get("value") for n in (5, 12)] != [-4, -3]
                or [prelude[n].operands.get("value") for n in (6, 13)] != [xs, ys]
                or [document.syscall_names[prelude[n].operands["id"]] for n in (8, 10, 15, 17)]
                    != ["FloatToInt", "Debmess", "FloatToInt", "Debmess"]):
            raise NativePositionError("四参数 OP 前段不属于仅输出坐标日志的已验证形态")
    # A verified pure three-argument wrapper can be traversed as a logical OP
    # syscall. This is an in-memory inspection view, not edited source bytes.
    logical_view = tuple(replace(item, mnemonic="syscall", operands={"id": op_id})
        if count == 3 and item.mnemonic == "call" and item.operands["target"] == helper.start
        else item for item in instructions)
    known = {layout.selector: binding["selector"], layout.action: binding["action"],
             layout.expression: 0}
    if binding["outfit"] is not None:
        known[layout.outfit] = binding["outfit"]
    matches = []
    for index in range(len(instructions)):
        branch = _comparison(instructions, index)
        if not branch or branch[:2] != (form["form_slot"], form["form"]):
            continue
        _slot, _code, start, stop = branch
        if not any(item.mnemonic == "call" and item.operands["target"] == helper.start
                   for item in instructions[start:stop]):
            continue
        resolved = _evaluate_pivot_branch(logical_view,
            branch_start=instructions[start].offset, branch_end=instructions[stop].offset,
            primsetop_syscall_id=op_id if count == 3 else None,
            primsetop_target=helper.start if count == 4 else None, known_arguments=known)
        if resolved is not None:
            matches.append(resolved)
    if len(matches) != 1:
        raise NativePositionError("来源 OP 逻辑原点没有唯一已知参数分支")
    x, y, site = matches[0]
    native = (math.trunc(x * xs), math.trunc(y * ys))
    evidence = dict(strategy=f"verified-source-args{count}-op-wrapper", helper=helper.start,
                    helper_range=[helper.start, helper.end], logical_pivot=[x, y],
                    native_pivot=list(native), call_offsets=[site], xy_scale=[xs, ys])
    return {form["form"]: native}, evidence, {helper.start}, [site]


def _extract_bound_position(document, proof, body, form, metadata,
                            spans, dispatcher, binding, layout):
    instructions = dispatcher.instructions
    xy_helpers = [span for span in spans if span.start in dispatcher.calls
                  and span.syscalls == ("FloatToInt", "FloatToInt", "PrimSetXY")]
    if xy_helpers:
        if len(xy_helpers) != 1:
            raise NativePositionError("来源 XY 换算包装函数不唯一")
        xs, ys = _extract_direct_xy_scales(xy_helpers[0].instructions, document.syscall_names)
        xy_sites = [index for index, item in enumerate(instructions)
                    if item.mnemonic == "call" and item.operands["target"] == xy_helpers[0].start]
        pivots, pivot_evidence, op_helpers, native_op_sites = _wrapped_pivot(
            document, instructions, spans, dispatcher, form, binding, layout, xs, ys)
        is_op = lambda item: item.mnemonic == "call" and item.operands["target"] in op_helpers
    else:
        xs = ys = 1.0
        xy_sites = [index for index, item in enumerate(instructions)
                    if item.mnemonic == "syscall"
                    and document.syscall_names[item.operands["id"]] == "PrimSetXY"]
        pivots, pivot_evidence = _embedded_native_form_pivots(instructions, document.syscall_names,
            selector=binding["selector"], action_code=binding["action"],
            outfit_code=binding["outfit"], expression_code=0,
            form_codes=[form["form"]], layout=layout)
        is_op = lambda item: item.mnemonic == "syscall" and document.syscall_names[
            item.operands["id"]] == "PrimSetOP"
        native_op_sites = pivot_evidence["forms"][0]["syscall_offsets"]
    if not native_op_sites or not xy_sites:
        raise NativePositionError("此档位的原点/XY 没有完整直接分支，不假定原点为零")
    matched = []
    for index in range(len(instructions)):
        branch = _comparison(instructions, index)
        if not branch or branch[:2] != (form["form_slot"], form["form"]):
            continue
        _slot, _code, start, stop = branch
        op_indices = [n for n in range(start, stop) if is_op(instructions[n])]
        if not op_indices or not any(instructions[n].offset in native_op_sites for n in op_indices):
            continue
        inside_xy = [n for n in xy_sites if op_indices[-1] < n < stop]
        if len(inside_xy) > 1:
            raise NativePositionError("同一档位原点之后存在多个 XY 调用")
        first_xy = inside_xy[0] if inside_xy else next((n for n in xy_sites if n >= stop), None)
        if first_xy is None:
            raise NativePositionError("此档位实际 XY 调用缺失")
        arguments = instructions[first_xy - 3:first_xy]
        if len(arguments) != 3 or any(item.mnemonic != "push_stack" for item in arguments):
            raise NativePositionError("来源 XY 的实际局部参数形态不匹配")
        x_local, y_local = [item.operands["value"] for item in arguments[1:]]
        if min(x_local, y_local) < 0 or x_local == y_local:
            raise NativePositionError("来源 XY 局部参数不明确")
        tail_end = first_xy - 3 if inside_xy else stop
        logical_y = _baseline_tail(instructions[op_indices[-1] + 1:tail_end],
            x_local=x_local, y_local=y_local, stop_offset=instructions[tail_end].offset)
        if inside_xy:
            remainder = instructions[first_xy+1:stop]
            if len(remainder) > 1 or remainder and (remainder[0].mnemonic != "jmp"
                    or remainder[0].operands["target"] < instructions[stop].offset):
                raise NativePositionError("档位内 XY 之后存在未证明的指令，不假定站位已确定")
            matched.append((logical_y, instructions[op_indices[-1]+1].offset, [], first_xy))
            continue
        # Other form arms lie before the shared forward merge, so do not execute
        # them or accidentally count their writes as the selected form's writes.
        merge = (instructions[stop - 1].operands["target"]
                 if instructions[stop - 1].mnemonic == "jmp" else instructions[stop].offset)
        merge_index = next((n for n, item in enumerate(instructions) if item.offset == merge), None)
        if merge_index is None or not stop <= merge_index < first_xy:
            raise NativePositionError("来源形态坐标汇合点不在实际 XY 前")
        cache = _guard_later_y_writes(instructions, merge_index, first_xy, y_local)
        matched.append((logical_y, instructions[op_indices[-1] + 1].offset, cache, first_xy))
    if len(matched) != 1:
        raise NativePositionError("来源默认 Y 常量没有唯一闭合分支")
    logical_y, baseline_site, cache, first_xy = matched[0]
    native_y = math.trunc(logical_y * ys)
    pivot_x, pivot_y = pivots[form["form"]]
    coordinate = normalized_bottom(metadata, pivot_y=pivot_y, native_y=native_y,
        rs=form["rs"], source_z=form["source_z"], viewport_height=proof["viewport"][1])
    return dict(schema="fvp-native-import-position/1", body=body,
        source_hcb_sha256=document.source_sha256, source_form=form["form"],
        **binding, native_pivot=[pivot_x, pivot_y], logical_xy_scale=[xs, ys],
        logical_default_y=logical_y, native_default_y=native_y,
        default_y_site=baseline_site, xy_site=instructions[first_xy].offset,
        pivot_evidence=pivot_evidence, cached_y_excluded=cache, **coordinate,
        coordinate_policy="regular-form-fresh-load-neutral-vertical-placement",
        source_camera_policy="same-neutral-basis-as-approved-size",
        face_alignment=False, cropped_bottom_alignment=False, size_changed=False,
        physical_height_cm_known=False, runtime_visual_verified=False,
        source_float_conversion_note="Existing audited wrapper truncation model; float-boundary rounding may differ by one native unit.")



def _script_stamp(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


@dataclass(frozen=True)
class _PositionSource:
    source_sha256: str
    syscall_names: dict


@lru_cache(maxsize=16)
def _position_source(path, stamp, expected_sha):
    script = Path(path)
    raw = script.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha or _script_stamp(script) != stamp:
        raise ValueError("来源脚本在原生大小与站位解析之间变化")
    document = parse_bytes(raw, encoding="shift_jis")
    rules = extract_hcb_size_rules(document)
    spans = _function_spans(document)
    dispatcher = next(span for span in spans if span.start == rules["dispatcher"])
    needed = {dispatcher.start, *dispatcher.calls}
    # Keep only the already-validated dispatcher and its immediate helpers.
    # Caching full parsed stories for several games would retain millions of
    # unrelated instructions; placement never reads those story instructions.
    source = _PositionSource(document.source_sha256, document.syscall_names)
    return source, rules, tuple(span for span in spans if span.start in needed)


@lru_cache(maxsize=256)
def _body_position(path, stamp, expected_sha, body, form_code, rs, z, viewport, image,
                   implicit_rs_verified=False):
    document, rules, spans = _position_source(path, stamp, expected_sha)
    rules = {**rules, "viewport": list(viewport)}
    forms = [row for row in rules["forms"] if row["form"] == form_code]
    # Some old FVP engines initialize RS in EXE code. The size importer has
    # already proven that initializer. Re-bind its value to THIS script's
    # suffix and fresh Z rather than assuming that absent HCB RS means 1000.
    if not forms and rules.get("implicit_engine_rs_required") and implicit_rs_verified:
        suffixes = rules.get("source_suffix_forms", [])
        depths = rules.get("implicit_z_evidence", [])
        if (len(depths) != 1 or depths[0]["source_z_if_fresh"] != z
                or rules.get("unresolved_geometry_sites")
                or any(row["conditional_override"] for row in suffixes)):
            raise NativePositionError("旧版站位与已验证的隐含大小不一致")
        forms = [dict(row, rs=rs, source_z=z) for row in suffixes
                 if row["form"] == form_code]
    if len(forms) != 1:
        raise NativePositionError("来源站位没有唯一的大小档位")
    form = {**forms[0]}
    if (form.get("rs"), form.get("source_z")) != (rs, z):
        raise NativePositionError("站位档位与已解析大小不一致")
    metadata = dict(zip(("width", "height", "offset_x", "offset_y", "payload_sha256"), image))
    try:
        return extract_position(document, rules, body, form, metadata, spans=spans)
    except ValueError as exc:
        raise NativePositionError(str(exc)) from exc


def source_native_position(proof, body, form, metadata):
    """All candidate scripts must agree; X stays authored, no existing edits.

    Unsupported OP/XY shapes raise NativePositionError. Source changes raise
    ValueError separately so callers cannot silently accept stale evidence.
    """
    scripts = proof.get("script_evidence") or []
    if not scripts or not proof.get("size_consensus"):
        raise NativePositionError("没有与大小证据绑定的来源脚本集合")
    viewport = tuple(proof["viewport"])
    image = tuple(metadata[key] for key in
                  ("width", "height", "offset_x", "offset_y", "payload_sha256"))
    if any(type(v) is not int for v in image[:4]) or min(image[:2]) <= 0:
        raise NativePositionError("无效的来源 HZC 画布/裁切偏移")
    rows = []
    for entry in scripts:
        path = Path(entry["source_hcb"])
        stamp = _script_stamp(path)
        row = deepcopy(_body_position(str(path), stamp, entry["hcb_sha256"], body,
            form["form"], form["rs"], form["source_z"], viewport, image,
            implicit_rs_verified=bool(proof.get("implicit_engine_rs_resolved")
                and form.get("rs_origin") == "native-engine-initializer")))
        if _script_stamp(path) != stamp:
            raise ValueError("来源脚本在站位解析期间变化")
        rows.append({"source_hcb": str(path), **row})
    signatures = {(tuple(row["native_pivot"]), tuple(row["logical_xy_scale"]),
                   row["logical_default_y"], row["native_default_y"], row["exact_bottom_y"])
                  for row in rows}
    if len(signatures) != 1:
        raise NativePositionError("来源多个脚本的原生站位不一致；不任选一份")
    first = rows[0]
    return dict(schema="fvp-native-import-position/1", verified=True,
        body=body, body_sha256=metadata["payload_sha256"],
        source_form=form["form"], source_rs=form["rs"], source_z=form["source_z"],
        source_viewport=list(viewport), target_viewport=[1280, 720],
        image={key: metadata[key] for key in ("width", "height", "offset_x", "offset_y")},
        native_pivot=first["native_pivot"], native_default_y=first["native_default_y"],
        logical_default_y=first["logical_default_y"], bottom_y=first["bottom_y"],
        exact_bottom_y=first["exact_bottom_y"], exact_top_y=first["exact_top_y"],
        coordinate_policy="regular-form-fresh-load-neutral-vertical-placement",
        x_policy="author-selected-horizontal-position", coordinates_editable=True,
        script_position_consensus=rows, runtime_active_script_determined=False,
        uses_story_camera=False, uses_face_matching=False, size_changed=False,
        runtime_visual_verified=False)
