"""Pure-memory, fail-closed scene candidates for discovered FVP targets.

The established scene emitter is byte-oriented and already models the common
FVP dialogue/background/event-CG call shapes.  This module supplies a narrow
data-driven adapter around it: immutable identities come from one read-only
discovery report and its matching target-profile draft, while every output is
kept in memory and explicitly remains non-installable.

The generic boundary supports existing target-owned resources, narration,
explicit integer-selector speaker branches, and the structurally discovered
background/event-CG chains.  Portraits stop at a deterministic lifecycle audit
plan until private primitive ownership and cleanup are reviewed.  Audio remains
unavailable.  No path is accepted or opened here.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
import hashlib
import json
import struct
from typing import Any, Mapping, Sequence

from .hcb import HcbDocument, HcbError, Instruction, decode_bytes, parse_bytes
from .hoshimemo_scene_hook import (
    HoshimemoSceneHookAbi,
    HoshimemoSceneHookError,
    SpeakerHookAbi,
    build_hoshimemo_story_project_candidate,
    inspect_hoshimemo_dialogue_anchor,
)
from .native_portrait_compile import (
    NativePortraitCompileError,
    build_native_portrait_story_plan,
)
from .native_target_discovery import DISCOVERY_SCHEMA
from .native_target_profile import (
    NATIVE_TARGET_PROFILE_REVIEW_SCHEMA,
    NATIVE_TARGET_PROFILE_SCHEMA,
    build_native_target_profile_template,
)


NATIVE_MEMORY_CONTEXT_SCHEMA = "fvp-studio-v2.native-scene-memory-context.v1"
NATIVE_MEMORY_CANDIDATE_SCHEMA = (
    "fvp-studio-v2.native-scene-memory-candidate.v1"
)


class NativeSceneCandidateError(HcbError):
    """Raised when a generic target cannot produce a pure-memory candidate."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256(payload)


def _append_once(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _header_signature(document: HcbDocument) -> tuple[Any, ...]:
    header = document.header
    return (
        int(header.sysdesc_offset),
        int(header.entry_point),
        int(header.non_volatile_globals),
        int(header.volatile_globals),
        int(header.game_mode),
        int(header.game_mode_reserved),
        int(header.custom_syscall_count),
        bytes(header.title_raw),
        tuple(
            (int(item.args), bytes(item.raw_name))
            for item in header.syscalls
        ),
    )


def _binding_identity(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        "address": value.get("address"),
        "argument_count": value.get("argument_count"),
        "structure_sha256": value.get("structure_sha256"),
        "syscalls": copy.deepcopy(value.get("syscalls")),
    }


def _archive_identity(value: Any) -> dict[str, Any]:
    item = value if isinstance(value, Mapping) else {}
    return {
        "name": item.get("name"),
        "size": item.get("size"),
        "entry_count": item.get("entry_count"),
        "directory_sha256": item.get("directory_sha256"),
    }


def _route_identity(value: Any) -> dict[str, Any]:
    item = value if isinstance(value, Mapping) else {}
    bindings = item.get("bindings") if isinstance(item.get("bindings"), Mapping) else {}
    routes = item.get("routes") if isinstance(item.get("routes"), list) else []
    return {
        "discovery_status": item.get("discovery_status"),
        "candidate_sha256": item.get("candidate_sha256"),
        "bindings": {
            str(name): _binding_identity(binding)
            for name, binding in bindings.items()
        },
        "selector": copy.deepcopy(item.get("selector")),
        "routes": [
            {
                "namespace": route.get("namespace"),
                "archive": route.get("archive"),
                "selector_kind": route.get("selector_kind"),
                "selector_value": route.get("selector_value"),
                "archive_identity": _archive_identity(
                    route.get("archive_identity")
                ),
            }
            for route in routes
            if isinstance(route, Mapping)
        ],
    }


def _locked_profile_identity(profile: Mapping[str, Any]) -> dict[str, Any]:
    scene = profile.get("scene_bindings")
    scene_value = scene if isinstance(scene, Mapping) else {}
    routing = profile.get("archive_routing")
    routing_value = routing if isinstance(routing, Mapping) else {}
    runtime = profile.get("runtime_activation")
    runtime_value = runtime if isinstance(runtime, Mapping) else {}
    return {
        "schema": profile.get("schema"),
        "target_id": profile.get("target_id"),
        "engine_family_id": profile.get("engine_family_id"),
        "discovery_manifest_sha256": profile.get("discovery_manifest_sha256"),
        "analysis_hcb": copy.deepcopy(profile.get("analysis_hcb")),
        "runtime_activation": {
            "active_hcb_name": runtime_value.get("active_hcb_name"),
            "active_hcb_sha256": runtime_value.get("active_hcb_sha256"),
        },
        "native_symbols": copy.deepcopy(profile.get("native_symbols")),
        # Speaker IDs and selector evidence are part of the immutable target
        # identity.  The browser must never be able to substitute a function
        # address or selector while retaining the same profile hash.
        "speakers": copy.deepcopy(profile.get("speakers")),
        "scene_bindings": {
            str(role): _binding_identity(binding)
            for role, binding in scene_value.items()
            if role != "visual_reset"
        }
        | {
            "visual_reset": [
                _binding_identity(binding)
                for binding in (
                    scene_value.get("visual_reset")
                    if isinstance(scene_value.get("visual_reset"), list)
                    else []
                )
            ]
        },
        "archive_routing": {
            role: _route_identity(routing_value.get(role))
            for role in ("background", "portrait", "event_visual")
        },
    }


def _validate_target_profile(
    discovery: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> str:
    if profile.get("schema") != NATIVE_TARGET_PROFILE_SCHEMA:
        raise NativeSceneCandidateError("目标 profile schema 不受支持")
    if bool(profile.get("write_enabled")):
        raise NativeSceneCandidateError("自启写入的目标 profile 被拒绝")
    expected = build_native_target_profile_template(discovery)
    if _canonical_sha256(_locked_profile_identity(profile)) != _canonical_sha256(
        _locked_profile_identity(expected)
    ):
        raise NativeSceneCandidateError(
            "目标 profile 的 HCB、函数地址或资源路由已偏离只读发现结果"
        )
    return _canonical_sha256(profile)


def _review_blockers(
    review: Mapping[str, Any] | None,
    *,
    target_id: str,
    profile_sha256: str,
) -> list[str]:
    if review is None:
        return ["target_profile_review_missing"]
    if review.get("schema") != NATIVE_TARGET_PROFILE_REVIEW_SCHEMA:
        raise NativeSceneCandidateError("目标 profile review schema 不受支持")
    if review.get("mode") != "read_only" or bool(review.get("writes_performed")):
        raise NativeSceneCandidateError("目标 profile review 不是只读结果")
    if str(review.get("target_id") or "") != target_id:
        raise NativeSceneCandidateError("目标 profile review 的 target_id 已漂移")
    if str(review.get("profile_sha256") or "") != profile_sha256:
        raise NativeSceneCandidateError("目标 profile review 不属于当前 profile")
    gate = review.get("write_gate")
    if not isinstance(gate, Mapping) or bool(gate.get("enabled")):
        raise NativeSceneCandidateError("目标 profile review 非法开启了写入闸门")
    blockers = review.get("blockers")
    values = [str(item) for item in blockers] if isinstance(blockers, list) else []
    gate_blockers = gate.get("blockers")
    if isinstance(gate_blockers, list):
        for blocker in gate_blockers:
            _append_once(values, str(blocker))
    return values


def _required_binding(
    profile: Mapping[str, Any],
    role: str,
    expected_args: int,
) -> int:
    scene = profile.get("scene_bindings")
    binding = scene.get(role) if isinstance(scene, Mapping) else None
    if not isinstance(binding, Mapping):
        raise NativeSceneCandidateError(f"目标 profile 缺少 {role} binding")
    try:
        address = int(binding.get("address"))
        argument_count = int(binding.get("argument_count"))
    except (TypeError, ValueError) as exc:
        raise NativeSceneCandidateError(f"目标 profile 的 {role} binding 无效") from exc
    if argument_count != expected_args:
        raise NativeSceneCandidateError(
            f"目标 {role} ABI 参数数不是通用场景发射器所需的 {expected_args}"
        )
    return address


def _required_binding_with_argument_count(
    profile: Mapping[str, Any],
    role: str,
    allowed_args: frozenset[int],
) -> tuple[int, int]:
    """Return one exact binding whose ABI is in a deliberately small family."""

    scene = profile.get("scene_bindings")
    binding = scene.get(role) if isinstance(scene, Mapping) else None
    if not isinstance(binding, Mapping):
        raise NativeSceneCandidateError(f"目标 profile 缺少 {role} binding")
    try:
        address = int(binding.get("address"))
        argument_count = int(binding.get("argument_count"))
    except (TypeError, ValueError) as exc:
        raise NativeSceneCandidateError(f"目标 profile 的 {role} binding 无效") from exc
    if argument_count not in allowed_args:
        expected = "/".join(str(value) for value in sorted(allowed_args))
        raise NativeSceneCandidateError(
            f"目标 {role} ABI 参数数不在通用场景发射器支持的 {expected} 范围"
        )
    return address, argument_count


def _optional_binding(
    profile: Mapping[str, Any],
    role: str,
    expected_args: int,
) -> int | None:
    """Return one exact discovered binding or leave the capability absent.

    Dialogue browsing must not depend on unrelated visual families.  A target
    that has no proven background/CG ABI can still expose its native dialogue
    and portrait lifecycle.  Mismatched argument counts are deliberately not
    coerced into another title's ABI.
    """

    scene = profile.get("scene_bindings")
    binding = scene.get(role) if isinstance(scene, Mapping) else None
    if not isinstance(binding, Mapping):
        return None
    try:
        address = int(binding.get("address"))
        argument_count = int(binding.get("argument_count"))
    except (TypeError, ValueError):
        return None
    if argument_count != expected_args:
        return None
    return address


def _archive_selectors(
    profile: Mapping[str, Any],
    role: str,
    *,
    default_selector: int | None,
) -> dict[str, int | None]:
    routing = profile.get("archive_routing")
    value = routing.get(role) if isinstance(routing, Mapping) else None
    routes = value.get("routes") if isinstance(value, Mapping) else None
    if not isinstance(routes, list):
        raise NativeSceneCandidateError(f"目标 profile 缺少 {role} 资源路由")
    result: dict[str, int | None] = {}
    for route in routes:
        if not isinstance(route, Mapping):
            continue
        archive = str(route.get("archive") or "").strip().casefold()
        selector_kind = str(route.get("selector_kind") or "").strip()
        if not archive:
            continue
        if selector_kind == "integer":
            try:
                selector: int | None = int(route.get("selector_value"))
            except (TypeError, ValueError) as exc:
                raise NativeSceneCandidateError(
                    f"目标 {role} 归档 {archive} selector 无效"
                ) from exc
        elif selector_kind == "default_fallthrough":
            selector = default_selector
        else:
            raise NativeSceneCandidateError(
                f"目标 {role} 归档 {archive} selector 类型尚不受支持"
            )
        if archive in result:
            raise NativeSceneCandidateError(
                f"目标 {role} 归档 {archive} 出现重复路由"
            )
        result[archive] = selector
    if not result:
        raise NativeSceneCandidateError(f"目标 profile 没有可用的 {role} 归档路由")
    return result


def _archive_selectors_optional(
    profile: Mapping[str, Any],
    role: str,
    *,
    default_selector: int | None,
) -> dict[str, int | None]:
    """Read a proven route when present without inventing a missing one."""

    routing = profile.get("archive_routing")
    value = routing.get(role) if isinstance(routing, Mapping) else None
    routes = value.get("routes") if isinstance(value, Mapping) else None
    if not isinstance(routes, list) or not routes:
        return {}
    return _archive_selectors(
        profile,
        role,
        default_selector=default_selector,
    )


def _native_speaker_catalog(
    profile: Mapping[str, Any],
    *,
    target_id: str,
) -> tuple[dict[str, SpeakerHookAbi], dict[str, Any]]:
    """Create a browser catalog and memory-only ABI from locked discovery data.

    Only an explicit integer selector at the structurally proven second
    argument is representable.  Default branches, fixed-name wrappers and
    unresolved selectors remain visible in the UI but cannot be compiled.
    """

    raw_entries = profile.get("speakers")
    values = raw_entries if isinstance(raw_entries, list) else []
    entries: list[dict[str, Any]] = [
        {
            "speaker_id": "narration",
            "display_name": "旁白",
            "scanned_name": "",
            "raw_names": [],
            "name_variants": [],
            "speaker_function": None,
            "speaker_functions": [],
            "name_selector": None,
            "selector_argument_index": None,
            "call_target": None,
            "call_target_hex": None,
            "argument_count": 0,
            "dialogue_count": 0,
            "compile_ready": True,
            "compile_scope": "memory_only",
            "install_ready": False,
            "voice_ready": False,
            "source": "native_target_profile_discovery",
            "reason": "通用旁白可进行纯内存编译验证",
            "backlog_avatar": {"available": False, "reason": "通用目标未审核 B.LOG 头像 ABI"},
        }
    ]
    abis: dict[str, SpeakerHookAbi] = {}
    seen_ids = {"narration"}
    for index, raw in enumerate(values):
        if not isinstance(raw, Mapping):
            continue
        speaker_id = str(raw.get("speaker_id") or "").strip().casefold()
        if not speaker_id or speaker_id in seen_ids:
            raise NativeSceneCandidateError(
                f"目标 profile 的说话人稳定身份重复或为空: {speaker_id or index}"
            )
        seen_ids.add(speaker_id)
        variants = (
            [str(item) for item in raw.get("name_variants", []) if str(item).strip()]
            if isinstance(raw.get("name_variants"), list)
            else []
        )
        display_name = str(raw.get("display_name") or "").strip()
        binding = raw.get("binding") if isinstance(raw.get("binding"), Mapping) else {}
        selector = (
            raw.get("name_selector")
            if isinstance(raw.get("name_selector"), Mapping)
            else {}
        )
        try:
            call_target = int(binding.get("address"))
            argument_count = int(binding.get("argument_count"))
        except (TypeError, ValueError):
            call_target = -1
            argument_count = -1
        selector_value = selector.get("value")
        selector_integer = (
            not isinstance(selector_value, bool)
            and isinstance(selector_value, int)
        )
        branch_sha256 = str(selector.get("branch_candidate_sha256") or "").strip()
        compile_ready = bool(
            str(raw.get("selection_mode") or "") == "selector_argument"
            and argument_count in {3, 5}
            and call_target >= 4
            and str(binding.get("structure_sha256") or "").strip()
            and selector.get("argument_index") == 1
            and str(selector.get("position_status") or "")
            == "verified_by_stack_read"
            and str(selector.get("value_kind") or "") == "integer"
            and selector_integer
            and branch_sha256
            and bool(display_name)
            and bool(variants)
        )
        if compile_ready:
            selector_number = int(selector_value)
            arguments: list[int | bool | None] = [None] * argument_count
            arguments[1] = selector_number
            abis[speaker_id] = SpeakerHookAbi(
                speaker_id=speaker_id,
                display_name=display_name,
                call_target=call_target,
                argument_count=argument_count,
                voiced_tail=None,
                unvoiced_arguments=tuple(arguments),
                name_selector=selector_number,
                selector_argument_index=1,
            )
            reason = (
                "显式整数名字 selector 可进行纯内存编译；"
                "语音、安装和实机 ABI 仍未开放"
            )
        else:
            selector_number = int(selector_value) if selector_integer else None
            reason = (
                "仅可预览：只有第二参数上的显式整数名字 selector "
                "才能进入通用纯内存编译"
            )
        function_label = (
            f"native@0x{call_target:06X}" if call_target >= 0 else None
        )
        entries.append(
            {
                "speaker_id": speaker_id,
                "display_name": display_name or f"候选说话人 {index + 1}",
                "scanned_name": variants[0] if variants else display_name,
                "raw_names": variants,
                "name_variants": variants,
                "speaker_function": function_label,
                "speaker_functions": [function_label] if function_label else [],
                "name_selector": selector_number,
                "selector_argument_index": selector.get("argument_index"),
                "call_target": call_target if call_target >= 0 else None,
                "call_target_hex": (
                    f"0x{call_target:06X}" if call_target >= 0 else None
                ),
                "argument_count": argument_count if argument_count >= 0 else None,
                "dialogue_count": 0,
                "compile_ready": compile_ready,
                "compile_scope": "memory_only" if compile_ready else "preview_only",
                "install_ready": False,
                "voice_ready": False,
                "selection_mode": str(raw.get("selection_mode") or ""),
                "source": "native_target_profile_discovery",
                "reason": reason,
                "branch_candidate_sha256": branch_sha256 or None,
                "backlog_avatar": {
                    "available": False,
                    "reason": "通用目标未审核 B.LOG 头像 ABI",
                },
            }
        )
    speaker_entries = entries[1:]
    catalog = {
        "schema": "fvp-studio-v2.story-speaker-catalog.v1",
        "entries": entries,
        "scanned_name_count": len(speaker_entries),
        "compile_ready_count": sum(
            bool(item.get("compile_ready")) for item in speaker_entries
        ),
        "preview_only_count": sum(
            not bool(item.get("compile_ready")) for item in speaker_entries
        ),
        "document_loaded": True,
        "profile_loaded": True,
        "target_id": target_id,
        "analysis_mode": "native_target_profile_discovery",
        "index_fingerprint": _canonical_sha256(entries),
        "compatibility": {
            "mode": "generic_native_memory_only",
            "install_ready": False,
            "voice_ready": False,
        },
    }
    return abis, catalog


def _scene_abi(
    discovery: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    speakers: Mapping[str, SpeakerHookAbi] | None = None,
) -> HoshimemoSceneHookAbi:
    background_selectors = _archive_selectors_optional(
        profile,
        "background",
        default_selector=None,
    )
    event_selectors_raw = _archive_selectors_optional(
        profile,
        "event_visual",
        default_selector=0,
    )
    event_selectors: dict[str, int] = {}
    for archive, selector in event_selectors_raw.items():
        if selector is None:
            raise NativeSceneCandidateError(
                f"目标 CG 归档 {archive} 缺少可发射的 selector"
            )
        event_selectors[archive] = int(selector)
    graph_selector = background_selectors.get("graph.bin", 1)
    if graph_selector is None:
        graph_selector = 1
    print_target, print_argument_count = _required_binding_with_argument_count(
        profile,
        "dialogue_print",
        frozenset({3, 4, 5}),
    )
    family = discovery.get("native_functions", {}).get("story_dialogue_family", {})
    selected = family.get("selected") or {}
    print_includes_wait = selected.get("print_includes_wait") is True
    wait_target = _required_binding(profile, "dialogue_wait", 0)
    if print_includes_wait or print_argument_count == 5:
        if not (print_includes_wait and print_argument_count == 5
                and selected.get("discovery_mode") == "native_print_internal_click_wait"
                and selected.get("print", {}).get("start") == print_target
                and selected.get("wait", {}).get("start") == wait_target):
            raise NativeSceneCandidateError("五参数打印缺少同一目标内部等待调用链证据")
    return HoshimemoSceneHookAbi(
        profile_id=(
            "fvp-native-memory:"
            + str(discovery.get("target_id") or "unknown")
        ),
        native_background_bindings={},
        dissolve_target=_optional_binding(
            profile, "background_dissolve", 9
        ),
        print_target=print_target,
        wait_target=wait_target,
        speakers=dict(speakers or {}),
        print_argument_count=print_argument_count,
        print_includes_wait=print_includes_wait,
        prefer_pre_speaker_before_hook=True,
        clean_source_sha256=None,
        generic_background_primary_target=_optional_binding(
            profile, "background_primary", 9
        ),
        generic_background_blur_target=_optional_binding(
            profile, "background_blur", 9
        ),
        generic_background_archive_selector=int(graph_selector),
        generic_background_archive_selectors=background_selectors,
        generic_event_visual_prepare_target=_optional_binding(
            profile, "event_visual_prepare", 0
        ),
        generic_event_visual_target=_optional_binding(
            profile, "event_visual_show", 10
        ),
        generic_event_visual_finish_target=_optional_binding(
            profile, "event_visual_finish", 3
        ),
        generic_event_visual_archive_selectors=event_selectors,
        # Generic browsing/visual compilation must not imply private selector
        # ownership from a clear/apply pair alone.  Exact portrait acceptance
        # installs its proven lifecycle targets into a candidate-local ABI.
        portrait_clear_target=None,
        portrait_apply_target=None,
        visual_reset_targets=(),
    )


def _decode_overlay_text(payload: bytes, encoding: str, label: str) -> str:
    if b"\0" not in payload:
        raise NativeSceneCandidateError(f"{label}没有 NUL 结尾")
    encoded, padding = payload.split(b"\0", 1)
    if any(padding):
        raise NativeSceneCandidateError(f"{label}的 NUL 后包含非零字节")
    text = decode_bytes(encoded, encoding)
    if "\ufffd" in text:
        raise NativeSceneCandidateError(f"{label}不能按 {encoding} 无损解码")
    return text


def _source_dialogue_text(
    source_document: HcbDocument,
    analysis_document: HcbDocument,
    selected: Instruction,
) -> str:
    if source_document.source_sha256 == analysis_document.source_sha256:
        return str(selected.text or "")
    offset = int(selected.offset)
    return_offset = offset + int(selected.size)
    source = source_document.original_bytes
    if offset < 4 or return_offset > len(source):
        raise NativeSceneCandidateError("运行 HCB 的台词槽超出范围")
    # Most translated Overlays leave the overwhelming majority of original
    # strings byte-identical.  Avoid decoding those Shift-JIS bytes through a
    # GB18030 runtime codec one record at a time; the exact-byte equality is a
    # stronger proof and keeps target switching responsive.
    if source[offset:return_offset] == selected.raw:
        return str(selected.text or "")
    opcode = source[offset]
    if opcode == 0x0E:
        if offset + 2 > len(source):
            raise NativeSceneCandidateError("运行 HCB 的定长台词头不完整")
        source_length = int(source[offset + 1])
        if source_length != int(selected.size) - 2:
            raise NativeSceneCandidateError("运行 HCB 的定长台词长度已漂移")
        return _decode_overlay_text(
            source[offset + 2 : return_offset],
            source_document.encoding,
            "运行 HCB 定长台词",
        )
    if opcode != 0x06 or offset + 5 > len(source):
        raise NativeSceneCandidateError("运行 HCB 的台词槽不是定长文本或 Overlay 跳转")
    redirect_target = struct.unpack_from("<I", source, offset + 1)[0]
    if redirect_target < len(analysis_document.original_bytes):
        raise NativeSceneCandidateError("运行 HCB 的台词跳转没有指向分析 HCB 末尾之后")
    if redirect_target + 2 > len(source) or source[redirect_target] != 0x0E:
        raise NativeSceneCandidateError("运行 HCB 的台词跳转目标不是 push_string")
    payload_length = int(source[redirect_target + 1])
    payload_start = redirect_target + 2
    payload_end = payload_start + payload_length
    stub_end = payload_end + 5
    if stub_end > len(source) or source[payload_end] != 0x06:
        raise NativeSceneCandidateError("运行 HCB 的翻译尾桩不完整")
    stub_return = struct.unpack_from("<I", source, payload_end + 1)[0]
    if stub_return != return_offset:
        raise NativeSceneCandidateError("运行 HCB 的翻译尾桩返回地址已漂移")
    return _decode_overlay_text(
        source[payload_start:payload_end],
        source_document.encoding,
        "运行 HCB 翻译尾桩",
    )


class MemoryDialogueProfile:
    """Minimal in-memory ProjectIndex-compatible view of native dialogue."""

    def __init__(
        self,
        source_document: HcbDocument,
        analysis_document: HcbDocument,
        records: Sequence[Mapping[str, Any]],
        *,
        skipped_dialogue_count: int = 0,
    ) -> None:
        self.source_sha256 = source_document.source_sha256
        self.analysis_source_sha256 = analysis_document.source_sha256
        self.encoding = source_document.encoding
        self.analysis_encoding = analysis_document.encoding
        self._source_document = source_document
        self._analysis_document = analysis_document
        self.skipped_dialogue_count = int(skipped_dialogue_count)
        self.records = [copy.deepcopy(dict(record)) for record in records]
        self.by_offset = {
            int(record["slot_offset"]): record for record in self.records
        }
        wanted_offsets = set(self.by_offset)
        self._selected_by_offset = {
            int(item.offset): item
            for item in analysis_document.instructions
            if int(item.offset) in wanted_offsets
        }
        self._current_text_cache: dict[int, str] = {}
        self._runtime_search_spans: tuple[tuple[int, int, int], ...] | None = None
        self.index_fingerprint = _canonical_sha256(
            {
                "source_sha256": self.source_sha256,
                "analysis_source_sha256": self.analysis_source_sha256,
                "encoding": self.encoding,
                "analysis_encoding": self.analysis_encoding,
                "dialogues": [
                    {
                        "slot_offset": int(record["slot_offset"]),
                        "original_text_sha256": _sha256(
                            str(record.get("original_text") or "").encode("utf-8")
                        ),
                    }
                    for record in self.records
                ],
            }
        )

    def compatibility_for(self, document: HcbDocument) -> dict[str, Any]:
        reasons: list[str] = []
        if document.source_sha256 != self.source_sha256:
            reasons.append("HCB SHA-256 与内存台词索引不一致")
        if document.encoding != self.encoding:
            reasons.append("HCB 文本编码与内存台词索引不一致")
        paired_overlay = self.source_sha256 != self.analysis_source_sha256
        if document.warnings and not paired_overlay:
            reasons.append(f"HCB 解析产生 {len(document.warnings):,} 个警告")
        if paired_overlay and not reasons:
            reasons.append("运行 Overlay 必须使用已绑定的线性分析 HCB")
        return {
            "safe": not reasons,
            "reason": (
                "；".join(reasons)
                if reasons
                else "线性 HCB 与内存台词索引一致"
            ),
            "warning_count": len(document.warnings),
            "source_sha256": document.source_sha256,
            "index_fingerprint": self.index_fingerprint,
        }

    def analysis_document_for(
        self,
        document: HcbDocument,
    ) -> tuple[HcbDocument, dict[str, Any]]:
        if document.source_sha256 != self.source_sha256:
            raise NativeSceneCandidateError("运行 HCB 与内存 Overlay bridge 身份不一致")
        if document.encoding != self.encoding:
            raise NativeSceneCandidateError("运行 HCB 与内存 Overlay bridge 编码不一致")
        analysis = self._analysis_document
        if analysis.source_sha256 != self.analysis_source_sha256 or analysis.warnings:
            raise NativeSceneCandidateError("内存 Overlay bridge 的分析 HCB 已漂移")
        if _header_signature(document) != _header_signature(analysis):
            raise NativeSceneCandidateError("运行 HCB 与分析 HCB 的 VM 头部不一致")
        if len(document.original_bytes) < len(analysis.original_bytes):
            raise NativeSceneCandidateError("运行 HCB 比分析 HCB 更短")
        return analysis, {
            "safe": True,
            "reason": (
                "运行 Overlay 已通过内存 SHA-256、VM 头部和台词尾桩绑定到"
                "线性分析 HCB；候选只修改运行 bytes"
            ),
            "mode": "generic_hidden_overlay_memory",
            "warning_count": len(document.warnings),
            "source_sha256": document.source_sha256,
            "analysis_source_sha256": analysis.source_sha256,
            "analysis_path": None,
            "index_fingerprint": self.index_fingerprint,
        }

    def _current_text(self, offset: int) -> str:
        slot = int(offset)
        cached = self._current_text_cache.get(slot)
        if cached is not None:
            return cached
        selected = self._selected_by_offset.get(slot)
        if selected is None:
            raise NativeSceneCandidateError(
                f"内存台词索引缺少 0x{slot:X} 的分析指令"
            )
        text = _source_dialogue_text(
            self._source_document,
            self._analysis_document,
            selected,
        )
        self._current_text_cache[slot] = text
        return text

    def _hydrate_record(
        self,
        record: Mapping[str, Any],
        *,
        strict: bool,
    ) -> dict[str, Any]:
        result = copy.deepcopy(dict(record))
        try:
            result["current_text"] = self._current_text(
                int(result["slot_offset"])
            )
            result["current_text_status"] = "verified"
        except (KeyError, TypeError, ValueError, HcbError) as exc:
            if strict:
                raise NativeSceneCandidateError(str(exc)) from exc
            result["current_text"] = str(result.get("original_text") or "")
            result["current_text_status"] = "unavailable"
            result["current_text_reason"] = str(exc)
        return result

    def hydrate_context(self, offset: int) -> None:
        slot = int(offset)
        index = next(
            (
                current
                for current, record in enumerate(self.records)
                if int(record.get("slot_offset", -1)) == slot
            ),
            None,
        )
        if index is None:
            return
        for current in range(max(0, index - 1), min(len(self.records), index + 2)):
            hydrated = self._hydrate_record(self.records[current], strict=False)
            self.records[current].update(hydrated)

    def record_for_offset(self, offset: int) -> dict[str, Any] | None:
        record = self.by_offset.get(int(offset))
        return self._hydrate_record(record, strict=True) if record is not None else None

    def _overlay_runtime_search_spans(self) -> tuple[tuple[int, int, int], ...]:
        """Map translated payload byte ranges to their stable dialogue slots.

        Building this map inspects only opcodes, lengths and redirect targets;
        it does not decode or deep-copy 50,000 translated records.  The map is
        used to narrow a runtime-language search before hydrating matches.
        """

        cached = self._runtime_search_spans
        if cached is not None:
            return cached
        if self.source_sha256 == self.analysis_source_sha256:
            self._runtime_search_spans = ()
            return ()
        source = self._source_document.original_bytes
        analysis_size = len(self._analysis_document.original_bytes)
        spans: list[tuple[int, int, int]] = []
        for slot, selected in self._selected_by_offset.items():
            return_offset = int(slot) + int(selected.size)
            if int(slot) < 0 or return_offset > len(source):
                continue
            if source[int(slot) : return_offset] == selected.raw:
                continue
            opcode = source[int(slot)]
            if opcode == 0x0E and int(slot) + 2 <= return_offset:
                payload_length = int(source[int(slot) + 1])
                payload_start = int(slot) + 2
                payload_end = payload_start + payload_length
                if payload_end == return_offset:
                    spans.append((payload_start, payload_end, int(slot)))
                continue
            if opcode != 0x06 or int(slot) + 5 > len(source):
                continue
            redirect_target = struct.unpack_from("<I", source, int(slot) + 1)[0]
            if (
                redirect_target < analysis_size
                or redirect_target + 2 > len(source)
                or source[redirect_target] != 0x0E
            ):
                continue
            payload_length = int(source[redirect_target + 1])
            payload_start = redirect_target + 2
            payload_end = payload_start + payload_length
            if payload_end <= len(source):
                spans.append((payload_start, payload_end, int(slot)))
        self._runtime_search_spans = tuple(spans)
        return self._runtime_search_spans

    def _runtime_query_offsets(self, query: str) -> frozenset[int]:
        raw_query = str(query or "").strip()
        if not raw_query:
            return frozenset()
        patterns: set[bytes] = set()
        for variant in {
            raw_query,
            raw_query.casefold(),
            raw_query.lower(),
            raw_query.upper(),
        }:
            try:
                encoded = variant.encode(self.encoding)
            except UnicodeEncodeError:
                continue
            if encoded:
                patterns.add(encoded)
        if not patterns:
            return frozenset()
        source = self._source_document.original_bytes
        matches = {
            slot
            for start, end, slot in self._overlay_runtime_search_spans()
            if any(source.find(pattern, start, end) >= 0 for pattern in patterns)
        }
        return frozenset(matches)

    def search_text(
        self,
        query: str = "",
        speaker: str = "",
        dialogue_only: bool = False,
        offset: int = 0,
        limit: int = 200,
    ) -> dict[str, Any]:
        raw_query = str(query or "").strip()
        needle = raw_query.casefold()
        speaker_needle = str(speaker or "").casefold().strip()
        runtime_query_offsets = (
            self._runtime_query_offsets(raw_query) if needle else frozenset()
        )
        matches: list[dict[str, Any]] = []
        total = 0
        for record in self.records:
            if dialogue_only and not record.get("dialogue"):
                continue
            original_text = str(record.get("original_text") or "")
            name = str(record.get("name") or "")
            if speaker_needle and speaker_needle not in name.casefold():
                continue
            hydrated: dict[str, Any] | None = None
            original_match = not needle or needle in original_text.casefold()
            runtime_match = int(record.get("slot_offset", -1)) in runtime_query_offsets
            if needle and not original_match and not runtime_match:
                continue
            if runtime_match:
                hydrated = self._hydrate_record(record, strict=False)
                if needle not in str(hydrated.get("current_text") or "").casefold():
                    continue
            if total >= max(0, int(offset)) and len(matches) < max(1, int(limit)):
                matches.append(
                    hydrated
                    if hydrated is not None
                    else self._hydrate_record(record, strict=False)
                )
            total += 1
        return {
            "items": matches,
            "total": total,
            "offset": max(0, int(offset)),
            "limit": max(1, int(limit)),
        }


def _memory_dialogue_profile(
    source_document: HcbDocument,
    analysis_document: HcbDocument,
    abi: HoshimemoSceneHookAbi,
) -> MemoryDialogueProfile:
    instructions = analysis_document.instructions
    records: list[dict[str, Any]] = []
    skipped = 0
    if abi.print_argument_count not in {3, 4, 5}:
        raise NativeSceneCandidateError(
            "目标台词输出函数参数数不在已审核的 3/4/5 参数范围"
        )
    expected = (
        (0x0E,)
        + ((0x08,) * (abi.print_argument_count - 1))
        + ((0x02,) if abi.print_includes_wait else (0x02, 0x02))
    )
    for index in range(max(0, len(instructions) - len(expected) + 1)):
        window = instructions[index : index + len(expected)]
        if tuple(item.opcode for item in window) != expected:
            continue
        selected = window[0]
        print_call = window[-1] if abi.print_includes_wait else window[-2]
        wait_call = window[-1]
        if selected.text is None or not selected.text.strip():
            continue
        if int(print_call.operands.get("target", -1)) != abi.print_target:
            continue
        if not abi.print_includes_wait and int(wait_call.operands.get("target", -1)) != abi.wait_target:
            continue
        records.append(
            {
                "id": f"native:hcb:0x{selected.offset:06X}",
                "slot_offset": int(selected.offset),
                "original_text": str(selected.text),
                "current_text": None,
                "name": "",
                "raw_name": "",
                "speaker_function": None,
                "dialogue": True,
                "voice_links": [],
                "visual_links": [],
            }
        )
    if not records:
        raise NativeSceneCandidateError(
            "目标 HCB 没有找到可由已发现 print/wait ABI 证明的线性台词"
        )
    return MemoryDialogueProfile(
        source_document,
        analysis_document,
        records,
        skipped_dialogue_count=skipped,
    )


@dataclass(frozen=True)
class NativeSceneMemoryContext:
    document: HcbDocument
    analysis_document: HcbDocument
    dialogue_profile: MemoryDialogueProfile
    abi: HoshimemoSceneHookAbi
    speaker_catalog: Mapping[str, Any]
    portrait_lifecycle_bindings: Mapping[str, Any]
    target_id: str
    profile_sha256: str
    blockers: tuple[str, ...]
    report: Mapping[str, Any]


@dataclass(frozen=True)
class NativeSceneMemoryCandidate:
    hcb: bytes
    report: Mapping[str, Any]
    install_ready: bool = False
    graph_bs: bytes | None = None
    graph_bs_source_sha256: str | None = None
    resource_archives: Mapping[str, bytes] = field(default_factory=dict)
    resource_archive_files: Mapping[str, Any] = field(default_factory=dict)
    resource_archive_source_sha256: Mapping[str, str] = field(default_factory=dict)
    portrait_resource_payloads: Mapping[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.hcb, bytes):
            raise TypeError("hcb 必须是 bytes")
        if self.install_ready:
            raise TypeError("通用纯内存候选不能标记为可安装")
        if self.graph_bs is not None and not isinstance(self.graph_bs, bytes):
            raise TypeError("graph_bs 必须是 bytes 或 None")
        for label, values in (
            ("resource_archives", self.resource_archives),
            ("portrait_resource_payloads", self.portrait_resource_payloads),
        ):
            if any(not isinstance(value, bytes) for value in values.values()):
                raise TypeError(f"{label} 的负载必须全部是 bytes")
        json.dumps(self.report, ensure_ascii=False, sort_keys=True)


def prepare_native_scene_memory_context_from_documents(
    source_document: HcbDocument,
    analysis_document: HcbDocument,
    discovery: Mapping[str, Any],
    target_profile: Mapping[str, Any],
    *,
    target_profile_review: Mapping[str, Any] | None = None,
) -> NativeSceneMemoryContext:
    """Bind already parsed runtime/analysis documents to one discovered ABI.

    This entry point lets the local server reuse its active ``HcbDocument``
    instead of parsing a million-instruction Overlay for a second time.  It
    performs no path I/O; any ``path`` carried by the supplied documents is
    treated as metadata and is deliberately omitted from the returned report.
    """

    if not isinstance(source_document, HcbDocument):
        raise NativeSceneCandidateError("纯内存候选缺少已解析的运行 HCB")
    if not isinstance(analysis_document, HcbDocument):
        raise NativeSceneCandidateError("纯内存候选缺少已解析的分析 HCB")
    if not source_document.original_bytes:
        raise NativeSceneCandidateError("纯内存候选需要非空运行 HCB")
    if not analysis_document.original_bytes:
        raise NativeSceneCandidateError("纯内存候选需要非空分析 HCB")
    if not isinstance(discovery, Mapping):
        raise NativeSceneCandidateError("缺少原生目标发现报告")
    if (
        discovery.get("schema") != DISCOVERY_SCHEMA
        or discovery.get("mode") != "read_only"
        or bool(discovery.get("writes_performed"))
    ):
        raise NativeSceneCandidateError("原生目标发现报告不是受支持的只读报告")
    target_id = str(discovery.get("target_id") or "")
    if not target_id:
        raise NativeSceneCandidateError("原生目标发现报告缺少 target_id")
    profile_sha256 = _validate_target_profile(discovery, target_profile)
    review_values = _review_blockers(
        target_profile_review,
        target_id=target_id,
        profile_sha256=profile_sha256,
    )
    analysis_hcb = target_profile.get("analysis_hcb")
    expected_sha256 = (
        str(analysis_hcb.get("sha256") or "")
        if isinstance(analysis_hcb, Mapping)
        else ""
    )
    if not expected_sha256:
        raise NativeSceneCandidateError("目标 profile 缺少线性分析 HCB 身份")
    if analysis_document.source_sha256 != expected_sha256:
        raise NativeSceneCandidateError(
            "分析 HCB 不是当前发现报告锁定的线性分析 HCB"
        )
    if source_document.source_sha256 == expected_sha256:
        if source_document.encoding != analysis_document.encoding:
            raise NativeSceneCandidateError(
                "线性运行 HCB 与发现阶段分析 HCB 的文本编码不一致"
            )
        overlay_mode = "linear"
    else:
        runtime = target_profile.get("runtime_activation")
        expected_runtime_sha256 = (
            str(runtime.get("active_hcb_sha256") or "")
            if isinstance(runtime, Mapping)
            else ""
        )
        if (
            not expected_runtime_sha256
            or source_document.source_sha256 != expected_runtime_sha256
        ):
            raise NativeSceneCandidateError(
                "运行 HCB bytes 不是当前发现报告锁定的活动 Overlay"
            )
        if _header_signature(source_document) != _header_signature(
            analysis_document
        ):
            raise NativeSceneCandidateError("运行 HCB 与分析 HCB 的 VM 头部不一致")
        if len(source_document.original_bytes) < len(
            analysis_document.original_bytes
        ):
            raise NativeSceneCandidateError("运行 HCB 比配对分析 HCB 更短")
        overlay_mode = "generic_hidden_overlay_memory"
    if analysis_document.warnings:
        raise NativeSceneCandidateError(
            f"线性分析 HCB 产生 {len(analysis_document.warnings):,} 个解析警告"
        )
    speaker_abis, speaker_catalog = _native_speaker_catalog(
        target_profile,
        target_id=target_id,
    )
    abi = _scene_abi(
        discovery,
        target_profile,
        speakers=speaker_abis,
    )
    dialogue_backend_report = None
    if abi.print_includes_wait:
        from .native_dialogue_backend import validate_internal_wait_source
        selected = discovery["native_functions"]["story_dialogue_family"]["selected"]
        dialogue_backend_report = validate_internal_wait_source(
            source_document, analysis_document, selected)
    background_backend_report: dict[str, Any] | None = None
    from .native_background_backend import NativeBackgroundBackend, NativeBackgroundBackendError

    try:
        background_backend = NativeBackgroundBackend(
            source_document, analysis_document,
            archive_selectors=abi.generic_background_archive_selectors,
        )
        abi = replace(abi, native_background_backend=background_backend)
        background_backend_report = background_backend.describe()
    except NativeBackgroundBackendError as exc:
        # Missing background capability must not remove dialogue browsing or
        # silently switch to another game's loader/default geometry. Existing
        # independently locked nine-argument bindings remain available.
        background_backend_report = {"status": "unavailable", "reason": str(exc)}
    dialogue_profile = _memory_dialogue_profile(
        source_document,
        analysis_document,
        abi,
    )
    blockers: list[str] = []
    discovery_gate = discovery.get("write_gate")
    if isinstance(discovery_gate, Mapping):
        for blocker in discovery_gate.get("blockers", []):
            _append_once(blockers, str(blocker))
    for blocker in review_values:
        _append_once(blockers, blocker)
    for blocker in (
        "generic_candidate_is_compile_only",
        "generic_portrait_hcb_backend_not_available",
        "generic_audio_backend_not_available",
        "profile_not_registered_in_trusted_registry",
    ):
        _append_once(blockers, blocker)
    report = {
        "schema": NATIVE_MEMORY_CONTEXT_SCHEMA,
        "mode": "compile_only",
        "writes_performed": False,
        "target_id": target_id,
        "profile_sha256": profile_sha256,
        "profile_id": abi.profile_id,
        "native_background_backend": background_backend_report,
        "native_dialogue_backend": dialogue_backend_report,
        "analysis_mode": overlay_mode,
        "source": {
            "size": len(source_document.original_bytes),
            "sha256": source_document.source_sha256,
            "encoding": source_document.encoding,
            "path": None,
        },
        "analysis_source": {
            "size": len(analysis_document.original_bytes),
            "sha256": analysis_document.source_sha256,
            "encoding": analysis_document.encoding,
            "path": None,
        },
        "dialogue_count": len(dialogue_profile.records),
        "skipped_dialogue_count": dialogue_profile.skipped_dialogue_count,
        "deferred_runtime_text_count": len(dialogue_profile.records),
        "capabilities": {
            "background_existing_resource": bool(
                abi.native_background_backend is not None or (abi.generic_background_archive_selectors
                and abi.dissolve_target is not None
                and abi.generic_background_primary_target is not None
                and abi.generic_background_blur_target is not None)
            ),
            "background_inherit_current": True,
            "event_visual_existing_resource": bool(
                abi.generic_event_visual_archive_selectors
                and abi.generic_event_visual_prepare_target is not None
                and abi.generic_event_visual_target is not None
                and abi.generic_event_visual_finish_target is not None
            ),
            "narration": True,
            "speaker_memory_compile_count": len(speaker_abis),
            "speaker_preview_count": int(
                speaker_catalog.get("preview_only_count") or 0
            ),
            "portrait_lifecycle_plan": True,
            "portrait_hcb_emission": False,
            "portraits": False,
            "audio": False,
        },
        "write_gate": {
            "enabled": False,
            "policy": "trusted_profile_and_real_game_acceptance_required",
            "blockers": blockers,
        },
    }
    speaker_catalog = copy.deepcopy(speaker_catalog)
    speaker_catalog["source_sha256"] = source_document.source_sha256
    speaker_catalog["analysis_source_sha256"] = analysis_document.source_sha256
    speaker_catalog["analysis_mode"] = overlay_mode
    lifecycle_bindings = {
        role: _binding_identity(
            (
                target_profile.get("scene_bindings")
                if isinstance(target_profile.get("scene_bindings"), Mapping)
                else {}
            ).get(role)
        )
        for role in ("portrait_clear", "portrait_apply")
    }
    return NativeSceneMemoryContext(
        document=source_document,
        analysis_document=analysis_document,
        dialogue_profile=dialogue_profile,
        abi=abi,
        speaker_catalog=speaker_catalog,
        portrait_lifecycle_bindings=lifecycle_bindings,
        target_id=target_id,
        profile_sha256=profile_sha256,
        blockers=tuple(blockers),
        report=report,
    )


def prepare_native_scene_memory_context(
    hcb_bytes: bytes,
    encoding: str,
    discovery: Mapping[str, Any],
    target_profile: Mapping[str, Any],
    *,
    target_profile_review: Mapping[str, Any] | None = None,
    analysis_hcb_bytes: bytes | None = None,
    analysis_encoding: str = "sjis",
) -> NativeSceneMemoryContext:
    """Bind exact runtime/analysis HCB bytes to one discovered target ABI."""

    if not isinstance(hcb_bytes, bytes) or not hcb_bytes:
        raise NativeSceneCandidateError("纯内存候选需要非空 HCB bytes")
    source_document = parse_bytes(hcb_bytes, encoding=encoding)
    if source_document.path is not None:
        raise NativeSceneCandidateError("纯内存 HCB 意外绑定了文件路径")
    if analysis_hcb_bytes is None:
        analysis_document = source_document
    else:
        if not isinstance(analysis_hcb_bytes, bytes) or not analysis_hcb_bytes:
            raise NativeSceneCandidateError("Overlay 配对的分析 HCB 必须是非空 bytes")
        analysis_document = parse_bytes(
            analysis_hcb_bytes,
            encoding=analysis_encoding,
        )
        if analysis_document.path is not None:
            raise NativeSceneCandidateError("分析 HCB 意外绑定了文件路径")
    return prepare_native_scene_memory_context_from_documents(
        source_document,
        analysis_document,
        discovery,
        target_profile,
        target_profile_review=target_profile_review,
    )


def inspect_native_scene_anchor(
    context: NativeSceneMemoryContext,
    offset: int,
    timing: str = "before",
) -> dict[str, Any]:
    """Inspect a dialogue anchor through the context's discovered ABI."""

    context.dialogue_profile.hydrate_context(int(offset))
    return inspect_hoshimemo_dialogue_anchor(
        context.document,
        context.dialogue_profile,
        int(offset),
        str(timing),
        abi=context.abi,
    )


def native_story_speaker_catalog(
    context: NativeSceneMemoryContext,
) -> dict[str, Any]:
    """Return the locked generic speaker catalog without exposing live state."""

    if not isinstance(context, NativeSceneMemoryContext):
        raise NativeSceneCandidateError("缺少已绑定的原生纯内存上下文")
    return copy.deepcopy(dict(context.speaker_catalog))


def _normalise_available_resources(
    value: Mapping[str, Sequence[str]],
) -> dict[str, frozenset[str]]:
    if not isinstance(value, Mapping):
        raise NativeSceneCandidateError("本作资源目录必须是 Mapping")
    result: dict[str, frozenset[str]] = {}
    for archive, names in value.items():
        archive_name = str(archive or "").strip().casefold()
        if not archive_name or isinstance(names, (str, bytes, bytearray)):
            raise NativeSceneCandidateError("本作资源目录条目无效")
        try:
            result[archive_name] = frozenset(str(name) for name in names)
        except TypeError as exc:
            raise NativeSceneCandidateError("本作资源目录名称列表无效") from exc
    return result


def _require_resource(
    resources: Mapping[str, frozenset[str]],
    archive_name: str,
    resource_name: str,
) -> None:
    names = resources.get(archive_name)
    if names is None:
        raise NativeSceneCandidateError(
            f"纯内存候选缺少 {archive_name} 的只读资源目录"
        )
    if resource_name not in names:
        raise NativeSceneCandidateError(
            f"本作归档 {archive_name} 中找不到冻结资源 {resource_name}"
        )


def _audio_is_noop(audio: Any) -> bool:
    value = audio if isinstance(audio, Mapping) else {}
    bgm = value.get("bgm") if isinstance(value.get("bgm"), Mapping) else {}
    se = value.get("se") if isinstance(value.get("se"), Mapping) else {}
    return (
        str(bgm.get("action") or "keep").strip().casefold() == "keep"
        and str(se.get("action") or "none").strip().casefold() == "none"
    )


def _generic_story(
    story: Mapping[str, Any],
    context: NativeSceneMemoryContext,
    available_resources: Mapping[str, frozenset[str]],
    *,
    preserve_portraits: bool = False,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    from .visual_scene_project import VisualSceneProjectError, buildable_story_scenes

    value = copy.deepcopy(dict(story))
    try:
        scenes = buildable_story_scenes(value)
    except VisualSceneProjectError as exc:
        raise NativeSceneCandidateError(str(exc)) from exc
    if preserve_portraits:
        visible_count = sum(
            1
            for scene in scenes
            for actor in (
                scene.get("cue", {}).get("actors", [])
                if isinstance(scene.get("cue"), Mapping)
                and isinstance(scene.get("cue", {}).get("actors"), list)
                else []
            )
            if isinstance(actor, Mapping) and bool(actor.get("visible", True))
        )
        if visible_count < 1:
            raise NativeSceneCandidateError(
                "原生立绘验收模式要求至少一个可见角色"
            )
        portrait_plan = {
            "schema": "fvp-studio-v2.native-portrait-acceptance-plan.v1",
            "mode": "exact_target_emission",
            "visible_actor_snapshot_count": visible_count,
            "blockers": [],
        }
    else:
        try:
            portrait_plan = build_native_portrait_story_plan(
                value,
                available_resources,
                lifecycle_bindings=context.portrait_lifecycle_bindings,
            )
        except NativePortraitCompileError as exc:
            raise NativeSceneCandidateError(str(exc)) from exc
    background_routes = set(context.abi.generic_background_archive_selectors)
    background_backend = context.abi.native_background_backend
    if background_backend is not None:
        background_routes.update(background_backend.archive_selectors)
    event_routes = set(context.abi.generic_event_visual_archive_selectors)
    background_emission_ready = bool(
        background_backend is not None or (background_routes
        and context.abi.dissolve_target is not None
        and context.abi.generic_background_primary_target is not None
        and context.abi.generic_background_blur_target is not None)
    )
    scene_by_id = {
        str(item.get("scene_id") or ""): item
        for item in value.get("scenes", [])
        if isinstance(item, Mapping)
    }
    for scene in scenes:
        scene_id = str(scene.get("scene_id") or "")
        mutable_scene = scene_by_id.get(scene_id)
        if not isinstance(mutable_scene, dict):
            raise NativeSceneCandidateError("剧情场景稳定身份已漂移")
        cue = mutable_scene.get("cue")
        if not isinstance(cue, dict):
            raise NativeSceneCandidateError("剧情场景缺少舞台快照")
        if not _audio_is_noop(cue.get("audio")):
            raise NativeSceneCandidateError(
                "通用纯内存首版不允许 BGM/SE 演出；目标音频 ABI 尚未审核"
            )
        lines = mutable_scene.get("inserted_lines")
        if isinstance(lines, list):
            for line in lines:
                if not isinstance(line, Mapping):
                    raise NativeSceneCandidateError("新增台词不是对象")
                speaker_id = str(
                    line.get("speaker_id") or "narration"
                ).strip().casefold()
                if speaker_id != "narration" and speaker_id not in context.abi.speakers:
                    catalog_entries = context.speaker_catalog.get("entries")
                    preview = next(
                        (
                            item
                            for item in catalog_entries
                            if isinstance(item, Mapping)
                            and str(item.get("speaker_id") or "").casefold()
                            == speaker_id
                        ),
                        None,
                    ) if isinstance(catalog_entries, list) else None
                    if isinstance(preview, Mapping):
                        raise NativeSceneCandidateError(
                            f"说话人 {preview.get('display_name') or speaker_id} "
                            f"仅可预览：{preview.get('reason') or '名字 selector 尚不可发射'}"
                        )
                    raise NativeSceneCandidateError(
                        f"当前通用目标找不到说话人稳定身份: {speaker_id or '<空>'}"
                    )
                if line.get("voice_id") is not None:
                    raise NativeSceneCandidateError(
                        "通用纯内存候选尚未审核角色语音 ABI；voice_id 必须留空"
                    )
        # Normal generic compilation stops at the target-neutral lifecycle
        # plan.  Explicit isolated acceptance may retain actors only after an
        # exact-byte target compile profile has been supplied by the caller.
        if not preserve_portraits:
            cue["actors"] = []
        event_visual = cue.get("event_visual")
        if isinstance(event_visual, dict):
            if str(event_visual.get("build_mode") or "").casefold() != "direct_reference":
                raise NativeSceneCandidateError(
                    "通用纯内存首版的 CG 只允许本作已有资源直引"
                )
            archive_name = str(event_visual.get("archive_name") or "").casefold()
            resource_name = str(event_visual.get("resource_name") or "").strip()
            if archive_name not in event_routes:
                raise NativeSceneCandidateError(
                    f"CG 归档 {archive_name or '<空>'} 不在目标发现路由中"
                )
            _require_resource(
                available_resources,
                archive_name,
                resource_name,
            )
            event_visual["archive_selector"] = (
                context.abi.generic_event_visual_archive_selectors[archive_name]
            )
            continue
        background = cue.get("background")
        if preserve_portraits and (
            not isinstance(background, Mapping)
            or not background_emission_ready
        ):
            preview = background if isinstance(background, Mapping) else {}
            background = {
                "asset_id": "inherit-current-runtime-background",
                "label": "继承挂接点当前背景",
                "resource_name": "",
                "archive_name": "",
                "entry_index": 0,
                "build_mode": "inherit_current",
                "fit": "inherit",
                "project_dir": "",
                "preview_background": {
                    "asset_id": str(preview.get("asset_id") or ""),
                    "resource_name": str(preview.get("resource_name") or ""),
                    "archive_name": str(preview.get("archive_name") or ""),
                },
            }
            cue["background"] = background
            if scene_id == str(value.get("active_scene_id") or ""):
                value["cue"] = copy.deepcopy(cue)
            continue
        if not isinstance(background, dict):
            raise NativeSceneCandidateError("剧情场景没有背景或 CG")
        mode = str(background.get("build_mode") or "").casefold()
        if mode not in {"direct_reference", "generic_direct_reference", "generic_native_background"}:
            raise NativeSceneCandidateError(
                "通用纯内存首版的背景只允许本作已有资源直引"
            )
        archive_name = str(background.get("archive_name") or "").casefold()
        resource_name = str(background.get("resource_name") or "").strip()
        if archive_name not in background_routes:
            raise NativeSceneCandidateError(
                f"背景归档 {archive_name or '<空>'} 不在目标发现路由中"
            )
        _require_resource(available_resources, archive_name, resource_name)
        blur_name = str(
            background.get("runtime_blur_resource_name") or resource_name
        ).strip()
        _require_resource(available_resources, archive_name, blur_name)
        background["runtime_blur_resource_name"] = blur_name
        background["build_mode"] = (
            "generic_native_background" if background_backend is not None else "generic_direct_reference"
        )
    return value, portrait_plan


def _refresh_portrait_story_anchors(
    story: Mapping[str, Any],
    context: NativeSceneMemoryContext,
    abi: HoshimemoSceneHookAbi,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Refresh only candidate-local anchor identities with lifecycle proof."""

    value = copy.deepcopy(dict(story))
    scene_values = value.get("scenes")
    if not isinstance(scene_values, list):
        raise NativeSceneCandidateError("剧情工程缺少场景数组")
    refreshed: list[dict[str, Any]] = []
    active_scene_id = str(value.get("active_scene_id") or "")
    for scene in scene_values:
        if not isinstance(scene, dict):
            raise NativeSceneCandidateError("剧情工程场景不是对象")
        cue = scene.get("cue")
        anchor = scene.get("anchor")
        if not isinstance(cue, dict) or not isinstance(anchor, Mapping):
            continue
        actors = cue.get("actors") if isinstance(cue.get("actors"), list) else []
        visible = [
            actor
            for actor in actors
            if isinstance(actor, Mapping) and bool(actor.get("visible", True))
        ]
        if not visible:
            continue
        try:
            offset = int(anchor.get("hcb_offset"))
        except (TypeError, ValueError) as exc:
            raise NativeSceneCandidateError("立绘场景挂点偏移无效") from exc
        context.dialogue_profile.hydrate_context(offset)
        fresh = inspect_hoshimemo_dialogue_anchor(
            context.document,
            context.dialogue_profile,
            offset,
            str(anchor.get("timing") or "before"),
            abi=abi,
        )
        visual_safety = (
            fresh.get("visual_safety")
            if isinstance(fresh.get("visual_safety"), Mapping)
            else {}
        )
        if not fresh.get("safe") or visual_safety.get("installable_visuals") is not True:
            reasons = list(fresh.get("reasons") or [])
            reason = str(visual_safety.get("reason") or "")
            if reason:
                reasons.append(reason)
            raise NativeSceneCandidateError(
                "立绘场景挂点没有通过目标生命周期复检："
                + "；".join(reasons or ["未知原因"])
            )
        boundary = visual_safety.get("lifecycle_boundary")
        if not isinstance(boundary, Mapping):
            raise NativeSceneCandidateError("立绘场景挂点缺少原生清理边界")
        scene["anchor"] = fresh
        cue["anchor_id"] = fresh["anchor_id"]
        scene_id = str(scene.get("scene_id") or "")
        if scene_id == active_scene_id:
            value["anchor"] = copy.deepcopy(fresh)
            value["cue"] = copy.deepcopy(cue)
        refreshed.append(
            {
                "scene_id": scene_id,
                "anchor_id": fresh["anchor_id"],
                "hcb_offset": offset,
                "lifecycle_boundary": copy.deepcopy(boundary),
            }
        )
    if not refreshed:
        raise NativeSceneCandidateError("原生立绘验收没有可复检的可见角色场景")
    return value, refreshed


def build_native_story_memory_candidate(
    context: NativeSceneMemoryContext,
    story: Mapping[str, Any],
    *,
    available_resources: Mapping[str, Sequence[str]],
    duration_ms: int = 1000,
    portrait_acceptance: Any | None = None,
    target_graph_bs: bytes | None = None,
    runtime_text_bridge: Mapping[str, Any] | None = None,
) -> NativeSceneMemoryCandidate:
    """Build one generic scene candidate entirely in memory.

    The default path remains HCB-only and strips portraits after producing a
    target-neutral audit plan.  ``portrait_acceptance`` is an explicit,
    caller-supplied exact-byte profile; when present it may emit one reviewed
    target portrait-archive candidate while this object itself still remains
    non-installable until the server's isolated-copy gate promotes it.
    """

    if not isinstance(context, NativeSceneMemoryContext):
        raise NativeSceneCandidateError("缺少已绑定的原生纯内存上下文")
    resources = _normalise_available_resources(available_resources)
    acceptance_enabled = portrait_acceptance is not None
    compile_target = None
    acceptance_report: Mapping[str, Any] | None = None
    anchor_refresh: list[dict[str, Any]] = []
    candidate_abi = context.abi
    if runtime_text_bridge is not None:
        candidate_abi = replace(
            candidate_abi,
            runtime_text_bridge=runtime_text_bridge,
        )
    story_value: Mapping[str, Any] = story
    if acceptance_enabled:
        if not isinstance(target_graph_bs, bytes) or not target_graph_bs:
            raise NativeSceneCandidateError(
                "原生立绘验收必须提供当前目标角色资源归档 bytes"
            )
        compile_target = getattr(portrait_acceptance, "compile_target", None)
        acceptance_report = getattr(portrait_acceptance, "report", None)
        try:
            clear_target = int(getattr(portrait_acceptance, "clear_target"))
            apply_target = int(getattr(portrait_acceptance, "apply_target"))
            apply_argument_count = int(
                getattr(portrait_acceptance, "apply_argument_count")
            )
            registration_argument_count = int(
                getattr(portrait_acceptance, "registration_argument_count")
            )
            registration_targets = tuple(
                int(value)
                for value in getattr(portrait_acceptance, "registration_targets")
            )
            registration_argument_counts = {
                int(value): int(count)
                for value, count in getattr(
                    portrait_acceptance,
                    "registration_argument_counts",
                ).items()
            }
        except (TypeError, ValueError) as exc:
            raise NativeSceneCandidateError(
                "原生立绘验收 profile 缺少 clear/apply/registration 目标"
            ) from exc
        if not registration_targets:
            raise NativeSceneCandidateError(
                "原生立绘验收 profile 没有活动 selector 的角色注册目标"
            )
        if apply_argument_count not in {2, 3}:
            raise NativeSceneCandidateError(
                "原生立绘验收 profile 的 apply 参数数不受支持"
            )
        if registration_argument_count not in {8, 9}:
            raise NativeSceneCandidateError(
                "原生立绘验收 profile 的 registration 参数数不受支持"
            )
        if not registration_argument_counts or any(
            count not in {8, 9, 12, 13}
            for count in registration_argument_counts.values()
        ):
            raise NativeSceneCandidateError(
                "原生立绘验收 profile 的逐目标 registration ABI 无效"
            )
        if compile_target is None or not isinstance(acceptance_report, Mapping):
            raise NativeSceneCandidateError("原生立绘验收 profile 不完整")
        candidate_abi = replace(
            candidate_abi,
            portrait_clear_target=clear_target,
            portrait_apply_target=apply_target,
            portrait_apply_argument_count=apply_argument_count,
            portrait_registration_argument_count=registration_argument_count,
            portrait_registration_targets=registration_targets,
            portrait_registration_argument_counts=registration_argument_counts,
        )
        story_value, anchor_refresh = _refresh_portrait_story_anchors(
            story,
            context,
            candidate_abi,
        )
    elif target_graph_bs is not None:
        raise NativeSceneCandidateError(
            "普通通用候选不能接收角色资源归档；需要显式原生立绘验收 profile"
        )

    generic_story, portrait_plan = _generic_story(
        story_value,
        context,
        resources,
        preserve_portraits=acceptance_enabled,
    )
    try:
        candidate = build_hoshimemo_story_project_candidate(
            context.document,
            context.dialogue_profile,
            generic_story,
            duration_ms=int(duration_ms),
            target_graph_bs=target_graph_bs if acceptance_enabled else None,
            abi=candidate_abi,
            portrait_compile_target=compile_target,
        )
    except HoshimemoSceneHookError as exc:
        raise NativeSceneCandidateError(str(exc)) from exc
    if not acceptance_enabled and (
        candidate.graph_bs is not None
        or candidate.resource_archives
        or candidate.resource_archive_files
        or candidate.portrait_resource_payloads
    ):
        raise NativeSceneCandidateError(
            "通用纯内存首版意外生成了目标专属 BIN/立绘副产物"
        )
    blockers = list(context.blockers)
    if isinstance(portrait_plan, Mapping):
        for blocker in portrait_plan.get("blockers", []):
            _append_once(blockers, str(blocker))
    _append_once(blockers, "real_game_candidate_not_accepted")
    report = copy.deepcopy(dict(candidate.report))
    report["native_portrait_plan"] = copy.deepcopy(portrait_plan)
    if acceptance_enabled:
        report["native_portrait_acceptance_profile"] = copy.deepcopy(
            dict(acceptance_report or {})
        )
        report["native_portrait_anchor_refresh"] = copy.deepcopy(anchor_refresh)
    archive_outputs = {
        str(name): {
            "size": len(payload),
            "sha256": _sha256(payload),
        }
        for name, payload in sorted(candidate.resource_archives.items())
    }
    report["native_target_candidate"] = {
        "schema": NATIVE_MEMORY_CANDIDATE_SCHEMA,
        "mode": (
            "compile_only_with_exact_portrait_emission"
            if acceptance_enabled
            else (
                "compile_only_with_portrait_plan"
                if portrait_plan is not None
                else "compile_only"
            )
        ),
        "writes_performed": False,
        "target_id": context.target_id,
        "profile_sha256": context.profile_sha256,
        "profile_id": context.abi.profile_id,
        "source_path": None,
        "resource_catalog_sha256": _canonical_sha256(
            {
                archive: sorted(names)
                for archive, names in sorted(resources.items())
            }
        ),
        "output": {
            "hcb_size": len(candidate.hcb),
            "hcb_sha256": _sha256(candidate.hcb),
            "resource_archive_count": len(candidate.resource_archives),
            "resource_archives": archive_outputs,
            "portrait_hcb_emission_ready": acceptance_enabled,
            "portrait_resource_count": len(candidate.portrait_resource_payloads),
        },
    }
    report["install_ready"] = False
    report["download_ready"] = False
    report["write_gate"] = {
        "enabled": False,
        "policy": "trusted_profile_and_real_game_acceptance_required",
        "blockers": blockers,
    }
    return NativeSceneMemoryCandidate(
        hcb=bytes(candidate.hcb),
        report=report,
        install_ready=False,
        graph_bs=candidate.graph_bs,
        graph_bs_source_sha256=candidate.graph_bs_source_sha256,
        resource_archives=dict(candidate.resource_archives),
        resource_archive_files=dict(candidate.resource_archive_files),
        resource_archive_source_sha256=dict(
            candidate.resource_archive_source_sha256
        ),
        portrait_resource_payloads=dict(candidate.portrait_resource_payloads),
    )


__all__ = [
    "MemoryDialogueProfile",
    "NATIVE_MEMORY_CANDIDATE_SCHEMA",
    "NATIVE_MEMORY_CONTEXT_SCHEMA",
    "NativeSceneCandidateError",
    "NativeSceneMemoryCandidate",
    "NativeSceneMemoryContext",
    "build_native_story_memory_candidate",
    "inspect_native_scene_anchor",
    "native_story_speaker_catalog",
    "prepare_native_scene_memory_context",
    "prepare_native_scene_memory_context_from_documents",
]
