"""Read-only clear/blur pairing from actual FVP HCB call tails, not filenames.

Accept only a contiguous native primary/blur loader family with alpha=255/0,
and a wrapper tail that loads a selected global, appends a literal suffix to
THAT global, then forwards identical geometry to the blur loader. Resource
names must be actual string assignments to that global in the same wrapper.
Unrecognized engines fail closed; there is no guessed 'b' suffix fallback.
"""
from copy import deepcopy
from functools import lru_cache
from pathlib import Path

from .gui_runtime import GuiRuntimeError, fingerprint
from .hcb import parse_bytes
from .native_target_discovery import (_select_analysis_hcb, _function_regions,
                                     _discover_visual_loader_family)

SCHEMA = "fvp-native-background-pair/1"


def _alpha_target(document, region):
    body = document.instructions[region.instruction_start_index:region.instruction_end_index]
    targets = []
    for index, ins in enumerate(body):
        if ins.mnemonic == "syscall" and document.header.syscalls[ins.operands["id"]].name == "PrimSetAlpha":
            if index == 0:
                return None
            before = body[index-1]
            if before.mnemonic not in ("push_i8", "push_i16", "push_i32"):
                return None
            targets.append(before.operands["value"])
    return targets[0] if len(targets) == 1 else None


def _tail(body, first, second, arity):
    if first < arity or second < arity:
        return None
    primary, blur = body[first-arity:first], body[second-arity:second]
    if any(not i.mnemonic.startswith("push_") for i in (*primary, *blur)):
        return None
    if primary[0].mnemonic != "push_global" or blur[0].raw != primary[0].raw:
        return None
    if [i.raw for i in primary[1:]] != [i.raw for i in blur[1:]]:
        return None
    middle = body[first+1:second-arity]
    if [i.mnemonic for i in middle] != ["push_global", "push_string", "add", "pop_global"]:
        return None
    slot = primary[0].operands["value"]
    suffix = middle[1].text
    if (middle[0].operands["value"] != slot or middle[3].operands["value"] != slot
            or not isinstance(suffix, str) or not suffix or len(suffix) > 16
            or any(c in suffix for c in ("/", "\\", "\0"))):
        return None
    assignments = [(i.offset, i.text) for n, i in enumerate(body[:first-arity])
        if i.mnemonic == "push_string" and body[n+1].mnemonic == "pop_global"
        and body[n+1].operands["value"] == slot and isinstance(i.text, str)]
    return dict(slot=slot, suffix=suffix, assignments=assignments,
                primary_call=body[first].offset, blur_call=body[second].offset)


def pair_records(document):
    regions = _function_regions(document)
    selected = _discover_visual_loader_family(regions).get("selected")
    if not selected or len(selected) < 2 or selected[0]["args"] != selected[1]["args"]:
        return {}
    by_start = {r.start: r for r in regions}
    primary, blur = (by_start[selected[i]["start"]] for i in (0, 1))
    if _alpha_target(document, primary) != 255 or _alpha_target(document, blur) != 0:
        return {}
    records = {}
    for region in regions:
        if not {primary.start, blur.start} <= set(region.call_targets):
            continue
        body = document.instructions[region.instruction_start_index:region.instruction_end_index]
        calls = [(n, i.operands["target"]) for n, i in enumerate(body)
                 if i.mnemonic == "call" and i.operands["target"] in (primary.start, blur.start)]
        for (first, target), (second, other) in zip(calls, calls[1:]):
            if target != primary.start or other != blur.start:
                continue
            tail = _tail(body, first, second, primary.args)
            if tail is None:
                continue
            for offset, resource in tail.pop("assignments"):
                if not resource or len(resource) > 256 or any(c in resource for c in ("/", "\\", "\0")):
                    continue
                evidence = dict(schema=SCHEMA, resource=resource,
                    blur_resource=resource + tail["suffix"], primary_function=primary.start,
                    blur_function=blur.start, wrapper=region.start, string_assignment=offset,
                    **tail, pairing_basis="native_primary_then_same_global_suffix_blur")
                records.setdefault(resource, []).append(evidence)
    return records


@lru_cache(maxsize=8)
def _read_pairs(path_string, stamp):
    path = Path(path_string)
    if path.stat().st_size > 32 * 1024 * 1024:
        raise GuiRuntimeError("background_blur_unavailable", "这份原作脚本超过当前解析范围。", 422)
    payload = path.read_bytes()
    if len(payload) > 32 * 1024 * 1024:
        raise GuiRuntimeError("source_changed", "读取原作脚本时文件大小发生变化。", 409)
    document = parse_bytes(payload, "shift_jis")
    records = pair_records(document)
    if fingerprint(path) != stamp:
        raise GuiRuntimeError("source_changed", "读取背景配对时原作脚本发生变化。", 409)
    return records, document.source_sha256


def lookup(root, resource):
    root = Path(root).resolve(strict=True)
    candidates = [p for p in root.iterdir() if p.suffix.casefold() in (".hcb", ".bch")
                  and p.is_file() and not p.is_symlink()]
    if not candidates:
        raise GuiRuntimeError("background_blur_unavailable", "未找到原作脚本，不能判断模糊背景配对。", 422)
    try:
        path, basis = _select_analysis_hcb(candidates)
    except ValueError as exc:
        raise GuiRuntimeError("background_blur_unavailable", "原作脚本不明确，不能猜测模糊背景配对。", 422) from exc
    if path.resolve().parent != root:
        raise GuiRuntimeError("source_changed", "原作脚本不在登记目录内。", 409)
    stamp = fingerprint(path)
    pairs, sha = _read_pairs(str(path), stamp)
    found = pairs.get(resource, [])
    names = {p["blur_resource"] for p in found}
    if len(names) != 1:
        raise GuiRuntimeError("background_blur_unavailable", "这张背景尚未找到明确的原生模糊图配对。", 422)
    evidence = deepcopy(found[0])
    evidence.update(hcb_sha256=sha, hcb_selection=basis, wrapper_count=len(found))
    return evidence, path, stamp
