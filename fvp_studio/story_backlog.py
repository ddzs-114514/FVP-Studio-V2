"""Native B.LOG avatar discovery for the V2 story-stage preview.

Hoshimemo does not choose backlog portraits from the ``SPEAK_*`` wrapper
number.  Its native B.LOG helper compares the visible name, then returns one
of the dim/selected 190x190 cell pairs in ``graph.bin``'s ``bl_char`` atlas.
This module recovers that table from the currently opened HCB instead of
maintaining a second hand-written character list.

The recovered coordinates are preview metadata only.  Browser input never
selects an atlas coordinate directly, and an unrecognised name follows the
game's own question-mark fallback.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from .hcb import HcbDocument, HcbError, Instruction


STORY_BACKLOG_SCHEMA = "fvp-studio-v2.story-backlog-profile.v1"
HOSHIMEMO_BACKLOG_PROFILE_ID = "hoshimemo-hd-native-backlog-v1"
HOSHIMEMO_BACKLOG_FUNCTION = 0x03D6A9
HOSHIMEMO_BACKLOG_ARCHIVE = "graph.bin"
HOSHIMEMO_BACKLOG_ENTRY_INDEX = 216
HOSHIMEMO_BACKLOG_ATLAS_SIZE = (1900, 950)
HOSHIMEMO_BACKLOG_CELL_SIZE = (190, 190)
HOSHIMEMO_BACKLOG_PAIR_STRIDE = 380
_UNKNOWN_NAME = "？？？"
_COMPARISON_OPS = {"push_stack", "push_string", "set_e", "or"}
_INTEGER_PUSHES = {"push_i8", "push_i16", "push_i32"}


class StoryBacklogError(HcbError):
    """Raised when a B.LOG avatar cannot be resolved safely."""


def _unavailable(reason: str, *, document: HcbDocument | None = None) -> dict[str, Any]:
    return {
        "schema": STORY_BACKLOG_SCHEMA,
        "profile_id": None,
        "available": False,
        "reason": str(reason),
        "source_sha256": getattr(document, "source_sha256", None),
        "archive": HOSHIMEMO_BACKLOG_ARCHIVE,
        "entry_index": HOSHIMEMO_BACKLOG_ENTRY_INDEX,
        "atlas_size": list(HOSHIMEMO_BACKLOG_ATLAS_SIZE),
        "cell_size": list(HOSHIMEMO_BACKLOG_CELL_SIZE),
        "native_name_count": 0,
        "_name_cells": {},
    }


def _normalise_name(value: Any) -> str:
    return str(value or "").strip(" \t\r\n\u3000")


def _integer_value(item: Instruction) -> int | None:
    if item.mnemonic not in _INTEGER_PUSHES:
        return None
    try:
        return int(item.operands["value"])
    except (KeyError, TypeError, ValueError):
        return None


def _comparison_names(instructions: Sequence[Instruction], branch_index: int) -> list[str]:
    """Return literal names from the equality/or expression before one jz."""

    cursor = branch_index - 1
    segment: list[Instruction] = []
    while cursor >= 0 and instructions[cursor].mnemonic in _COMPARISON_OPS:
        segment.append(instructions[cursor])
        cursor -= 1
    segment.reverse()
    names = [
        _normalise_name(item.text)
        for item in segment
        if item.mnemonic == "push_string" and _normalise_name(item.text)
    ]
    if not names:
        return []
    # Native B.LOG name branches compare local stack slot zero.  Requiring
    # that operand keeps the later story-state jz blocks out of this table.
    if not any(
        item.mnemonic == "push_stack" and int(item.operands.get("value", -99)) == 0
        for item in segment
    ):
        return []
    return list(dict.fromkeys(names))


def _coordinate_pairs(instructions: Sequence[Instruction]) -> list[tuple[int, int]]:
    """Recover pair-column/row assignments from one native name branch."""

    pairs: list[tuple[int, int]] = []
    cursor = 0
    while cursor + 7 < len(instructions):
        group = instructions[cursor : cursor + 8]
        x_value = _integer_value(group[1])
        y_value = _integer_value(group[5])
        if (
            group[0].mnemonic == "push_stack"
            and int(group[0].operands.get("value", -99)) == 4
            and x_value is not None
            and group[2].mnemonic == "mul"
            and group[3].mnemonic == "pop_stack"
            and int(group[3].operands.get("value", -99)) == 4
            and group[4].mnemonic == "push_stack"
            and int(group[4].operands.get("value", -99)) == 5
            and y_value is not None
            and group[6].mnemonic == "mul"
            and group[7].mnemonic == "pop_stack"
            and int(group[7].operands.get("value", -99)) == 5
            and 0 <= x_value <= 4
            and 0 <= y_value <= 4
        ):
            pair = (x_value, y_value)
            if pair not in pairs:
                pairs.append(pair)
            cursor += 8
            continue
        cursor += 1
    return pairs


def _native_name_cells(document: HcbDocument) -> dict[str, dict[str, Any]]:
    try:
        start_index, entry = document.find_with_index(HOSHIMEMO_BACKLOG_FUNCTION)
    except HcbError as exc:
        raise StoryBacklogError(
            f"找不到 Hoshimemo 原生 B.LOG 函数 0x{HOSHIMEMO_BACKLOG_FUNCTION:X}"
        ) from exc
    if (
        entry.mnemonic != "init_stack"
        or int(entry.operands.get("args", -1)) != 3
        or int(entry.operands.get("locals", -1)) != 6
    ):
        raise StoryBacklogError("原生 B.LOG 函数入口或参数门禁不匹配")

    function: list[Instruction] = []
    for item in document.instructions[start_index : start_index + 700]:
        function.append(item)
        if item.mnemonic == "retv":
            break
    if not function or function[-1].mnemonic != "retv":
        raise StoryBacklogError("原生 B.LOG 函数边界不完整")

    offsets = {item.offset: index for index, item in enumerate(function)}
    result: dict[str, dict[str, Any]] = {}
    for index, branch in enumerate(function):
        if branch.mnemonic != "jz":
            continue
        names = _comparison_names(function, index)
        if not names:
            continue
        try:
            target_index = offsets[int(branch.operands["target"])]
        except (KeyError, TypeError, ValueError):
            continue
        if target_index <= index:
            continue
        pairs = _coordinate_pairs(function[index + 1 : target_index])
        if not pairs:
            continue
        primary = pairs[0]
        for name in names:
            result[name] = {
                "pair_column": primary[0],
                "row": primary[1],
                "alternatives": [list(value) for value in pairs[1:]],
                "conditional": len(pairs) > 1,
            }

    unknown = result.get(_UNKNOWN_NAME)
    if unknown is None or (unknown["pair_column"], unknown["row"]) != (2, 4):
        raise StoryBacklogError("原生 B.LOG 问号头像门禁不匹配")
    # These two names plus the exact function signature distinguish this
    # profile from unrelated FVP games that happen to use a similar atlas.
    if "メア" not in result or "夢" not in result:
        raise StoryBacklogError("原生 B.LOG 角色映射标记不匹配")
    return result


def discover_story_backlog(document: HcbDocument | None) -> dict[str, Any]:
    """Recover the active HCB's native B.LOG name table once per document."""

    if document is None:
        return _unavailable("尚未打开目标 HCB")
    cache_key = (
        str(getattr(document, "source_sha256", "") or ""),
        len(getattr(document, "instructions", ()) or ()),
    )
    cache = getattr(document, "_story_backlog_profile_cache", None)
    if isinstance(cache, dict) and cache.get("key") == cache_key:
        value = cache.get("value")
        if isinstance(value, dict):
            return copy.deepcopy(value)
    try:
        name_cells = _native_name_cells(document)
        result = {
            "schema": STORY_BACKLOG_SCHEMA,
            "profile_id": HOSHIMEMO_BACKLOG_PROFILE_ID,
            "available": True,
            "reason": f"已从当前 HCB 原生 B.LOG 函数恢复 {len(name_cells)} 个姓名映射",
            "source_sha256": getattr(document, "source_sha256", None),
            "function_offset": HOSHIMEMO_BACKLOG_FUNCTION,
            "function_offset_hex": f"0x{HOSHIMEMO_BACKLOG_FUNCTION:X}",
            "archive": HOSHIMEMO_BACKLOG_ARCHIVE,
            "entry_index": HOSHIMEMO_BACKLOG_ENTRY_INDEX,
            "atlas_size": list(HOSHIMEMO_BACKLOG_ATLAS_SIZE),
            "cell_size": list(HOSHIMEMO_BACKLOG_CELL_SIZE),
            "pair_stride": HOSHIMEMO_BACKLOG_PAIR_STRIDE,
            "native_name_count": len(name_cells),
            "_name_cells": name_cells,
        }
    except StoryBacklogError as exc:
        result = _unavailable(str(exc), document=document)
    try:
        document._story_backlog_profile_cache = {
            "key": cache_key,
            "value": copy.deepcopy(result),
        }
    except (AttributeError, TypeError):
        pass
    return copy.deepcopy(result)


def _public_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): copy.deepcopy(value)
        for key, value in profile.items()
        if not str(key).startswith("_")
    }


def attach_story_backlog_avatars(
    catalog: Mapping[str, Any],
    document: HcbDocument | None,
) -> dict[str, Any]:
    """Attach server-trusted avatar metadata to every scanned speaker."""

    result = copy.deepcopy(dict(catalog))
    profile = discover_story_backlog(document)
    result["backlog"] = _public_profile(profile)
    entries = result.get("entries")
    if not isinstance(entries, list):
        return result
    cells = profile.get("_name_cells") if profile.get("available") else None
    if not isinstance(cells, Mapping):
        cells = {}
    unknown = cells.get(_UNKNOWN_NAME) if isinstance(cells, Mapping) else None

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        speaker_id = str(entry.get("speaker_id") or "")
        if speaker_id == "narration":
            entry["backlog_avatar"] = {
                "available": False,
                "kind": "none",
                "reason": "旁白在原生 B.LOG 中不显示角色头像",
            }
            continue
        if not profile.get("available") or not isinstance(unknown, Mapping):
            entry["backlog_avatar"] = {
                "available": False,
                "kind": "unavailable",
                "reason": str(profile.get("reason") or "当前游戏没有已识别的 B.LOG 头像表"),
            }
            continue

        candidate_names = [entry.get("scanned_name")]
        raw_names = entry.get("raw_names")
        if isinstance(raw_names, Sequence) and not isinstance(raw_names, (str, bytes, bytearray)):
            candidate_names.extend(raw_names)
        candidate_names.append(entry.get("display_name"))
        matched_name = next(
            (
                name
                for name in (_normalise_name(value) for value in candidate_names)
                if name and name in cells
            ),
            None,
        )
        cell = cells.get(matched_name) if matched_name else unknown
        if not isinstance(cell, Mapping):
            entry["backlog_avatar"] = {
                "available": False,
                "kind": "unavailable",
                "reason": "原生 B.LOG 问号头像缺失",
            }
            continue
        pair_column = int(cell["pair_column"])
        row = int(cell["row"])
        kind = "unknown" if matched_name in {None, _UNKNOWN_NAME} else "native"
        pair_x = pair_column * HOSHIMEMO_BACKLOG_PAIR_STRIDE
        y = row * HOSHIMEMO_BACKLOG_CELL_SIZE[1]
        conditional = bool(cell.get("conditional"))
        reason = (
            "原生姓名未单独映射，按游戏规则显示问号头像"
            if kind == "unknown" and matched_name is None
            else "该角色的原生头像会随剧情状态切换为问号"
            if conditional
            else "使用当前游戏原生 B.LOG 头像"
        )
        entry["backlog_avatar"] = {
            "available": True,
            "kind": kind,
            "reason": reason,
            "native_name": matched_name or _UNKNOWN_NAME,
            "archive": HOSHIMEMO_BACKLOG_ARCHIVE,
            "entry_index": HOSHIMEMO_BACKLOG_ENTRY_INDEX,
            "dim_x": pair_x,
            "selected_x": pair_x + HOSHIMEMO_BACKLOG_CELL_SIZE[0],
            "y": y,
            "width": HOSHIMEMO_BACKLOG_CELL_SIZE[0],
            "height": HOSHIMEMO_BACKLOG_CELL_SIZE[1],
            "conditional": conditional,
            "alternatives": copy.deepcopy(cell.get("alternatives") or []),
        }
    return result


def resolve_story_backlog_avatar(
    catalog: Mapping[str, Any],
    document: HcbDocument | None,
    speaker_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve one browser speaker id to its trusted native crop."""

    from .story_speakers import resolve_story_speaker

    enriched = attach_story_backlog_avatars(catalog, document)
    speaker = resolve_story_speaker(enriched, speaker_id)
    avatar = speaker.get("backlog_avatar")
    if not isinstance(avatar, Mapping) or not avatar.get("available"):
        reason = avatar.get("reason") if isinstance(avatar, Mapping) else "头像元数据缺失"
        raise StoryBacklogError(str(reason))
    return speaker, copy.deepcopy(dict(avatar))
