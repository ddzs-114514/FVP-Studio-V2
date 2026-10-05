"""Scanned, stable speaker identities for the V2 Hoshimemo story editor.

The runtime-name index records the visible name and the decoder label used by
each original dialogue (``SPEAK_0_`` ... ``SPEAK_24_``).  Several labels can
show more than one name, selected by the second native argument.  This module
joins those two pieces of evidence with the currently opened HCB without ever
accepting a call target supplied by the browser.
"""

from __future__ import annotations

from collections import Counter, defaultdict
import copy
import hashlib
import re
from typing import Any, Mapping, Sequence

from .hcb import HcbDocument, HcbError, Instruction
from .hoshimemo_overlay import resolve_hoshimemo_analysis_document


STORY_SPEAKER_CATALOG_SCHEMA = "fvp-studio-v2.story-speaker-catalog.v1"
SPEAKER_FUNCTION_RE = re.compile(r"^SPEAK_(\d+)_$")

# Exact function entries verified against the original Hoshimemo HD HCB.  A
# matching profile record is still required before an entry becomes selectable
# for compilation.  The function entry and argument count are rechecked on the
# currently opened document every time a new catalog is built.
HOSHIMEMO_SPEAKER_FUNCTIONS: tuple[tuple[int, int], ...] = (
    (0x000004, 3),
    (0x00010E, 3),
    (0x00011F, 3),
    (0x000206, 3),
    (0x0002ED, 3),
    (0x0003D4, 3),
    (0x000494, 3),
    (0x000554, 3),
    (0x000614, 3),
    (0x0006F7, 3),
    (0x0007B7, 3),
    (0x000879, 3),
    (0x000939, 3),
    (0x0009F9, 3),
    (0x000ABD, 3),
    (0x000BA4, 3),
    (0x000C68, 3),
    (0x000D72, 3),
    (0x000E57, 3),
    (0x000EF3, 3),
    (0x000F8F, 3),
    (0x00102B, 3),
    (0x0010ED, 3),
    (0x00112A, 3),
    (0x001167, 5),
)

LEGACY_SPEAKERS: Mapping[tuple[str, int | None], tuple[str, str, bool]] = {
    ("SPEAK_0_", None): ("meya", "梅娅", True),
    ("SPEAK_0_", -1): ("unknown", "？？？", False),
    ("SPEAK_8_", None): ("yume", "梦", True),
    ("SPEAK_24_", None): ("you", "洋", False),
}

# ``？？？`` legitimately appears under many character-specific SPEAK
# wrappers.  Picking one of those wrappers from the display name alone would
# be unsafe.  Hoshimemo itself, however, contains an audited generic fallback:
# SPEAK_0_'s second argument ``-1`` selects the native unknown-name branch.
# The catalog may expose this stable identity only after the currently opened
# HCB proves that exact call/selector pair and the profile compatibility gate
# passes.  Other ambiguous names remain preview-only.
HOSHIMEMO_CANONICAL_AMBIGUOUS_SPEAKERS: Mapping[
    str, tuple[str, int]
] = {
    "？？？": ("SPEAK_0_", -1),
}


class StorySpeakerError(HcbError):
    """Raised when a browser speaker id cannot be resolved to scanned proof."""


def _narration_entry() -> dict[str, Any]:
    return {
        "speaker_id": "narration",
        "display_name": "旁白",
        "scanned_name": "",
        "raw_names": [],
        "speaker_function": None,
        "speaker_functions": [],
        "name_selector": None,
        "call_target": None,
        "call_target_hex": None,
        "argument_count": 0,
        "dialogue_count": 0,
        "compile_ready": True,
        "voice_ready": False,
        "source": "native_narration",
        "reason": "旁白不调用角色 SPEAK 函数",
    }


def _fallback_legacy_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for (function_name, selector), (speaker_id, display_name, voice_ready) in LEGACY_SPEAKERS.items():
        match = SPEAKER_FUNCTION_RE.fullmatch(function_name)
        if match is None:
            continue
        target, argument_count = HOSHIMEMO_SPEAKER_FUNCTIONS[int(match.group(1))]
        entries.append(
            {
                "speaker_id": speaker_id,
                "display_name": display_name,
                "scanned_name": "",
                "raw_names": [],
                "speaker_function": function_name,
                "speaker_functions": [function_name],
                "name_selector": selector,
                "call_target": target,
                "call_target_hex": f"0x{target:X}",
                "argument_count": argument_count,
                "dialogue_count": 0,
                "compile_ready": False,
                "voice_ready": voice_ready,
                "source": "legacy_fallback",
                "reason": "当前索引没有该角色的运行时名字证据",
            }
        )
    return entries


def _function_info(function_name: str) -> tuple[int, int, int] | None:
    match = SPEAKER_FUNCTION_RE.fullmatch(function_name)
    if match is None:
        return None
    index = int(match.group(1))
    if not 0 <= index < len(HOSHIMEMO_SPEAKER_FUNCTIONS):
        return None
    target, argument_count = HOSHIMEMO_SPEAKER_FUNCTIONS[index]
    return index, target, argument_count


def _decode_simple_push_ending_at(
    instructions: Sequence[Instruction], cursor: int
) -> tuple[int | bool | None, int] | None:
    """Decode one literal argument ending at *cursor* and return the next cursor."""

    if cursor < 0:
        return None
    item = instructions[cursor]
    if item.mnemonic == "neg":
        inner = _decode_simple_push_ending_at(instructions, cursor - 1)
        if inner is None or isinstance(inner[0], bool) or inner[0] is None:
            return None
        return -int(inner[0]), inner[1]
    if item.mnemonic == "push_nil":
        return None, cursor - 1
    if item.mnemonic == "push_true":
        return True, cursor - 1
    if item.mnemonic in {"push_i8", "push_i16", "push_i32"}:
        try:
            return int(item.operands["value"]), cursor - 1
        except (KeyError, TypeError, ValueError):
            return None
    return None


def _selector_before_call(
    instructions: Sequence[Instruction],
    call_index: int,
    *,
    call_target: int,
    argument_count: int,
) -> tuple[bool, int | None]:
    """Recover the second native argument from one original SPEAK call."""

    if call_index < 0:
        return False, None
    call = instructions[call_index]
    if call.mnemonic != "call" or int(call.operands.get("target", -1)) != call_target:
        return False, None
    cursor = call_index - 1
    # Arguments are pushed left-to-right.  Skip the arguments after the second
    # one, then decode the name selector itself.  For Hoshimemo these are all
    # literal Nil/True/integer expressions; a calculated value is not guessed.
    for _ in range(max(0, argument_count - 2)):
        decoded = _decode_simple_push_ending_at(instructions, cursor)
        if decoded is None:
            return False, None
        _, cursor = decoded
    decoded = _decode_simple_push_ending_at(instructions, cursor)
    if decoded is None:
        return False, None
    value, _ = decoded
    if value is None:
        return True, None
    if isinstance(value, bool):
        return False, None
    return True, int(value)


def _dynamic_speaker_id(function_name: str, selector: int | None, name: str) -> str:
    function_token = function_name.removeprefix("SPEAK_").removesuffix("_").casefold()
    selector_token = "default" if selector is None else f"selector-{abs(selector)}"
    name_digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]
    return f"profile:speak-{function_token}:{selector_token}:{name_digest}"


def _preview_speaker_id(name: str) -> str:
    return f"profile:preview:{hashlib.sha1(name.encode('utf-8')).hexdigest()[:12]}"


def _catalog_cache_key(
    document: HcbDocument | None,
    analysis_document: HcbDocument | None,
    profile: Any,
) -> tuple[str, str, str]:
    return (
        str(getattr(document, "source_sha256", "") or ""),
        str(getattr(analysis_document, "source_sha256", "") or ""),
        str(getattr(profile, "index_fingerprint", "") or ""),
    )


def discover_story_speakers(
    document: HcbDocument | None,
    profile: Any | None,
) -> dict[str, Any]:
    """Return every distinct runtime name and its audited native identity."""

    if profile is None:
        entries = [_narration_entry(), *_fallback_legacy_entries()]
        return {
            "schema": STORY_SPEAKER_CATALOG_SCHEMA,
            "entries": entries,
            "scanned_name_count": 0,
            "compile_ready_count": 0,
            "preview_only_count": 0,
            "document_loaded": document is not None,
            "profile_loaded": False,
        }

    records = getattr(profile, "records", ()) or ()
    function_counts_by_name: dict[str, Counter[str]] = defaultdict(Counter)
    raw_names_by_name: dict[str, Counter[str]] = defaultdict(Counter)
    sample_offsets: dict[tuple[str, str], list[int]] = defaultdict(list)
    for record in records:
        if not isinstance(record, Mapping):
            continue
        name = str(record.get("name") or "").strip()
        if not name:
            continue
        function_name = str(record.get("speaker_function") or "").strip()
        function_counts_by_name[name][function_name] += 1
        raw_name = str(record.get("raw_name") or "").strip()
        if raw_name:
            raw_names_by_name[name][raw_name] += 1
        key = (name, function_name)
        if len(sample_offsets[key]) < 8:
            try:
                sample_offsets[key].append(int(record["slot_offset"]))
            except (KeyError, TypeError, ValueError):
                pass

    compatibility = {
        "safe": False,
        "reason": "尚未打开与索引匹配的 HCB",
    }
    analysis_document = document
    if document is not None:
        try:
            analysis_document, compatibility = resolve_hoshimemo_analysis_document(
                document,
                profile,
            )
        except HcbError as exc:
            analysis_document = None
            compatibility = {"safe": False, "reason": str(exc)}

    cache_key = _catalog_cache_key(document, analysis_document, profile)
    cache = getattr(profile, "_story_speaker_catalog_cache", None)
    if isinstance(cache, dict) and cache.get("key") == cache_key and isinstance(cache.get("value"), dict):
        return copy.deepcopy(cache["value"])

    wanted_offsets = {
        offset for offsets in sample_offsets.values() for offset in offsets
    }
    wanted_offsets.update(target for target, _ in HOSHIMEMO_SPEAKER_FUNCTIONS)
    positions: dict[int, int] = {}
    if analysis_document is not None and wanted_offsets:
        for index, instruction in enumerate(analysis_document.instructions):
            if instruction.offset in wanted_offsets:
                positions[instruction.offset] = index
                if len(positions) == len(wanted_offsets):
                    break

    function_validation: dict[str, tuple[bool, str]] = {}
    for function_index, (target, argument_count) in enumerate(HOSHIMEMO_SPEAKER_FUNCTIONS):
        function_name = f"SPEAK_{function_index}_"
        position = positions.get(target)
        if analysis_document is None:
            function_validation[function_name] = (False, "尚未打开 HCB")
        elif position is None:
            function_validation[function_name] = (False, f"找不到原生入口 0x{target:X}")
        else:
            item = analysis_document.instructions[position]
            actual_args = item.operands.get("args")
            if item.mnemonic != "init_stack" or actual_args != argument_count:
                function_validation[function_name] = (
                    False,
                    f"0x{target:X} 参数门禁不匹配（需要 {argument_count}，实际 {actual_args}）",
                )
            elif document is not None and document is not analysis_document and (
                document.original_bytes[item.offset : item.offset + item.size] != item.raw
            ):
                function_validation[function_name] = (
                    False,
                    f"0x{target:X} 在中文隐藏 HCB 中的入口字节与原版证据不一致",
                )
            else:
                function_validation[function_name] = (True, "原生函数入口与参数数已核验")

    selector_evidence: dict[tuple[str, str], set[int | None]] = defaultdict(set)
    selector_failures: set[tuple[str, str]] = set()
    if analysis_document is not None:
        for key, offsets in sample_offsets.items():
            _, function_name = key
            info = _function_info(function_name)
            if info is None:
                selector_failures.add(key)
                continue
            _, target, argument_count = info
            for offset in offsets:
                string_index = positions.get(offset)
                if string_index is None:
                    selector_failures.add(key)
                    continue
                proven, selector = _selector_before_call(
                    analysis_document.instructions,
                    string_index - 1,
                    call_target=target,
                    argument_count=argument_count,
                )
                if proven:
                    selector_evidence[key].add(selector)
                else:
                    selector_failures.add(key)

    entries: list[dict[str, Any]] = [_narration_entry()]
    scanned_ids: set[str] = set()
    for name, function_counts in function_counts_by_name.items():
        functions = sorted(function_counts)
        dialogue_count = sum(function_counts.values())
        raw_names = [value for value, _ in raw_names_by_name[name].most_common()]
        compile_ready = False
        voice_ready = False
        selector: int | None = None
        function_name: str | None = None
        call_target: int | None = None
        argument_count: int | None = None
        source = "runtime_name_index"
        display_name = name
        canonical = HOSHIMEMO_CANONICAL_AMBIGUOUS_SPEAKERS.get(name)
        if canonical is not None and (len(functions) != 1 or not functions[0]):
            function_name, selector = canonical
            info = _function_info(function_name)
            key = (name, function_name)
            selectors = selector_evidence.get(key, set())
            legacy = LEGACY_SPEAKERS.get((function_name, selector))
            if legacy is not None:
                speaker_id, display_name, voice_ready = legacy
            else:  # The profile constant and legacy identity must move together.
                speaker_id = _preview_speaker_id(name)
            if function_name not in functions:
                reason = (
                    f"固定未知身份 {function_name} 未出现在当前索引的 {name} 台词中，"
                    "只能预览"
                )
            elif info is None:
                reason = f"固定未知身份函数不在 Hoshimemo SPEAK 范围: {function_name}"
            else:
                _, call_target, argument_count = info
                function_ok, function_reason = function_validation.get(
                    function_name, (False, "原生函数入口尚未核验")
                )
                if not compatibility.get("safe"):
                    reason = str(compatibility.get("reason") or "HCB 与索引不兼容")
                elif not function_ok:
                    reason = function_reason
                elif selectors != {selector} or key in selector_failures:
                    reason = (
                        f"未能从当前原始台词证明 {function_name} 的名字切换参数 "
                        f"{selector}"
                    )
                elif legacy is None:
                    reason = "固定未知身份缺少受信任的角色定义"
                else:
                    compile_ready = True
                    source = "runtime_name_index+profile_unknown_fallback"
                    reason = (
                        f"已核验原生未知身份 {function_name} / 名字切换参数 {selector}"
                    )
        elif len(functions) != 1 or not functions[0]:
            reason = (
                f"同一显示名对应 {len([value for value in functions if value])} 个 SPEAK 函数，"
                "只能预览，不能猜测调用目标"
            )
            speaker_id = _preview_speaker_id(name)
        else:
            function_name = functions[0]
            info = _function_info(function_name)
            key = (name, function_name)
            selectors = selector_evidence.get(key, set())
            if len(selectors) == 1:
                selector = next(iter(selectors))
            legacy = LEGACY_SPEAKERS.get((function_name, selector))
            if legacy is not None:
                speaker_id, display_name, voice_ready = legacy
            else:
                speaker_id = _dynamic_speaker_id(function_name, selector, name)
                display_name = name
            if info is None:
                reason = f"索引中的函数标签不在 Hoshimemo SPEAK_0_–SPEAK_24_ 范围: {function_name}"
            else:
                _, call_target, argument_count = info
                function_ok, function_reason = function_validation.get(
                    function_name, (False, "原生函数入口尚未核验")
                )
                if not compatibility.get("safe"):
                    reason = str(compatibility.get("reason") or "HCB 与索引不兼容")
                elif not function_ok:
                    reason = function_reason
                elif len(selectors) != 1 or key in selector_failures:
                    reason = "未能从原始台词稳定恢复名字切换参数"
                elif selector not in {None, -1, -2, -3}:
                    reason = f"名字切换参数 {selector} 不在已验证范围"
                else:
                    compile_ready = True
                    reason = "原生 SPEAK 函数与名字切换参数均已核验"
            if legacy is None:
                display_name = name
        if (len(functions) != 1 or not functions[0]) and canonical is None:
            display_name = name
        entry = {
            "speaker_id": speaker_id,
            "display_name": display_name,
            "scanned_name": name,
            "raw_names": raw_names,
            "speaker_function": function_name,
            "speaker_functions": [value for value in functions if value],
            "name_selector": selector,
            "call_target": call_target,
            "call_target_hex": f"0x{call_target:X}" if call_target is not None else None,
            "argument_count": argument_count,
            "dialogue_count": dialogue_count,
            "compile_ready": compile_ready,
            "voice_ready": bool(voice_ready),
            "source": source,
            "reason": reason,
        }
        entries.append(entry)
        scanned_ids.add(str(speaker_id))

    # Keep old projects containing yume/meya/you lines readable even when an
    # unrelated or synthetic profile has no runtime-name evidence.
    for fallback in _fallback_legacy_entries():
        if fallback["speaker_id"] not in scanned_ids:
            entries.append(fallback)

    entries[1:] = sorted(
        entries[1:],
        key=lambda item: (
            not bool(item.get("scanned_name")),
            not bool(item.get("compile_ready")),
            -int(item.get("dialogue_count") or 0),
            str(item.get("display_name") or ""),
        ),
    )
    scanned_entries = [entry for entry in entries if entry.get("scanned_name")]
    result = {
        "schema": STORY_SPEAKER_CATALOG_SCHEMA,
        "entries": entries,
        "scanned_name_count": len(scanned_entries),
        "compile_ready_count": sum(bool(entry.get("compile_ready")) for entry in scanned_entries),
        "preview_only_count": sum(not bool(entry.get("compile_ready")) for entry in scanned_entries),
        "document_loaded": document is not None,
        "profile_loaded": True,
        "source_sha256": getattr(document, "source_sha256", None),
        "analysis_source_sha256": getattr(analysis_document, "source_sha256", None),
        "analysis_mode": compatibility.get("mode"),
        "index_fingerprint": getattr(profile, "index_fingerprint", None),
        "compatibility": compatibility,
    }
    try:
        profile._story_speaker_catalog_cache = {"key": cache_key, "value": copy.deepcopy(result)}
    except (AttributeError, TypeError):
        pass
    return result


def resolve_story_speaker(catalog: Mapping[str, Any], speaker_id: str) -> dict[str, Any]:
    token = str(speaker_id or "narration").strip().casefold()
    entries = catalog.get("entries") if isinstance(catalog, Mapping) else None
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
        raise StorySpeakerError("说话人目录损坏")
    matches = [
        entry
        for entry in entries
        if isinstance(entry, Mapping)
        and str(entry.get("speaker_id") or "").strip().casefold() == token
    ]
    if len(matches) != 1:
        raise StorySpeakerError(f"当前索引找不到唯一说话人: {token or '<空>'}")
    return copy.deepcopy(dict(matches[0]))
