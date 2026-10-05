"""Fail-closed review contract for data-driven FVP target profiles.

Discovery answers which native structures are present.  A target profile adds
game-specific meanings, lifecycle boundaries and archive routes, but remains a
draft until its exact HCB identity and real-game evidence are reviewed.  This
module never writes a game file and never turns an API-submitted draft into a
trusted writer profile.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Iterable, Mapping

from .hcb import HcbError
from .native_target_discovery import (
    DISCOVERY_SCHEMA,
    inspect_native_function_addresses,
)


NATIVE_TARGET_PROFILE_SCHEMA = "fvp-studio-v2.native-target-profile.v1"
NATIVE_TARGET_PROFILE_REVIEW_SCHEMA = (
    "fvp-studio-v2.native-target-profile-review.v1"
)

REQUIRED_SCENE_BINDINGS = (
    "dialogue_print",
    "dialogue_wait",
    "background_primary",
    "background_blur",
    "background_dissolve",
    "portrait_clear",
    "portrait_apply",
)
REQUIRED_ACCEPTANCE_CASES = (
    "hcb_load",
    "dialogue",
    "background",
    "portrait",
    "lifecycle_cleanup",
    "save_load",
    "rollback",
)
ALLOWED_ARCHIVE_MODES = frozenset({"native_reference", "additive_hzc"})


class NativeTargetProfileError(HcbError):
    """Raised when a discovery report cannot seed a target profile."""


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _require_discovery(discovery: Mapping[str, Any]) -> None:
    if not isinstance(discovery, Mapping):
        raise NativeTargetProfileError("缺少原生目标发现报告")
    if discovery.get("schema") != DISCOVERY_SCHEMA:
        raise NativeTargetProfileError("原生目标发现报告 schema 不受支持")
    if discovery.get("mode") != "read_only" or discovery.get("writes_performed"):
        raise NativeTargetProfileError("原生目标发现报告不是只读报告")
    if not discovery.get("target_id") or not discovery.get("manifest_sha256"):
        raise NativeTargetProfileError("原生目标发现报告缺少稳定身份")


def _active_hcb_record(discovery: Mapping[str, Any]) -> dict[str, Any] | None:
    hcb = discovery.get("hcb") if isinstance(discovery.get("hcb"), Mapping) else {}
    runtime = (
        hcb.get("runtime_resolution")
        if isinstance(hcb.get("runtime_resolution"), Mapping)
        else {}
    )
    active_name = str(runtime.get("active_candidate") or "")
    for record in hcb.get("candidates", []) if isinstance(hcb.get("candidates"), list) else []:
        if isinstance(record, Mapping) and str(record.get("name")) == active_name:
            return dict(record)
    return None


def _archive_route(archive: str | None) -> dict[str, Any]:
    return {
        "archive": archive,
        "mode": "unreviewed",
        "evidence": [],
    }


def _archive_identity(summary: Any) -> dict[str, Any]:
    value = summary if isinstance(summary, Mapping) else {}
    return {
        "name": value.get("name"),
        "size": value.get("size"),
        "entry_count": value.get("entry_count"),
        "directory_sha256": value.get("directory_sha256"),
    }


def _resource_route_role_template(
    role: str,
    report: Any,
) -> dict[str, Any]:
    role_report = report if isinstance(report, Mapping) else {}
    selected = (
        role_report.get("selected")
        if isinstance(role_report.get("selected"), Mapping)
        else None
    )
    bindings: dict[str, Any] = {}
    selector = None
    routes: list[dict[str, Any]] = []
    if selected is not None:
        if role == "background":
            bindings = {
                "resolver": _draft_binding(selected.get("resolver")),
                "loader": _draft_binding(selected.get("loader_caller")),
                "path_loader": _draft_binding(selected.get("path_loader")),
            }
        elif role == "portrait":
            bindings = {
                "dispatcher": _draft_binding(selected.get("dispatcher")),
            }
        elif role == "event_visual":
            bindings = {
                "resolver": _draft_binding(selected.get("resolver")),
                "path_loader": _draft_binding(selected.get("path_loader")),
            }
        selected_selector = selected.get("selector")
        if isinstance(selected_selector, Mapping):
            selector = {
                "argument_index": selected_selector.get(
                    "selector_argument_index"
                ),
                "stack_offset": selected_selector.get(
                    "selector_stack_offset"
                ),
                "candidate_sha256": selected_selector.get(
                    "candidate_sha256"
                ),
            }
        for item in selected.get("routes", []):
            if not isinstance(item, Mapping):
                continue
            routes.append(
                {
                    "namespace": item.get("namespace"),
                    "archive": item.get("archive"),
                    "selector_kind": item.get("selector_kind"),
                    "selector_value": item.get("selector_value"),
                    "archive_identity": _archive_identity(
                        item.get("archive_summary")
                    ),
                    "mode": "unreviewed",
                    "evidence": [],
                }
            )
    return {
        "discovery_status": role_report.get("status", "missing"),
        "candidate_sha256": (
            selected.get("candidate_sha256") if selected is not None else None
        ),
        "bindings": bindings,
        "selector": selector,
        "routes": routes,
        "review_status": "unreviewed",
        "review_evidence": [],
    }


def _binding_identity(binding: Any) -> dict[str, Any] | None:
    if not isinstance(binding, Mapping):
        return None
    return {
        "address": binding.get("address"),
        "argument_count": binding.get("argument_count"),
        "structure_sha256": binding.get("structure_sha256"),
        "syscalls": binding.get("syscalls"),
    }


def _resource_route_locked_identity(role: Any) -> dict[str, Any]:
    value = role if isinstance(role, Mapping) else {}
    bindings = value.get("bindings")
    routes = value.get("routes")
    return {
        "discovery_status": value.get("discovery_status"),
        "candidate_sha256": value.get("candidate_sha256"),
        "bindings": {
            str(name): _binding_identity(binding)
            for name, binding in (
                bindings.items() if isinstance(bindings, Mapping) else []
            )
        },
        "selector": copy.deepcopy(value.get("selector")),
        "routes": [
            {
                "namespace": item.get("namespace"),
                "archive": item.get("archive"),
                "selector_kind": item.get("selector_kind"),
                "selector_value": item.get("selector_value"),
                "archive_identity": _archive_identity(
                    item.get("archive_identity")
                ),
            }
            for item in (routes if isinstance(routes, list) else [])
            if isinstance(item, Mapping)
        ],
    }


def _draft_binding(record: Any) -> dict[str, Any] | None:
    if not isinstance(record, Mapping) or record.get("start") is None:
        return None
    return {
        "address": int(record["start"]),
        "argument_count": int(record.get("args", 0)),
        "structure_sha256": str(record.get("structure_sha256") or ""),
        "syscalls": list(record.get("syscalls", [])),
        # Structural discovery is a lead, not human/runtime evidence.
        "evidence": [],
    }


def _speaker_display_name(variants: Iterable[Any], index: int) -> str:
    values = [str(item) for item in variants if str(item)]
    for value in reversed(values):
        if value.strip("?？"):
            return value
    return values[-1] if values else f"候选说话人 {index + 1}"


def _selector_token(kind: str, value: Any, branch_index: int) -> str:
    if kind == "default_fallthrough":
        return "default"
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return f"branch-{branch_index}"
    return f"neg-{abs(integer)}" if integer < 0 else f"pos-{integer}"


def build_native_target_profile_template(
    discovery: Mapping[str, Any],
) -> dict[str, Any]:
    """Create a target-bound, non-writable profile template."""

    _require_discovery(discovery)
    hcb = discovery.get("hcb") if isinstance(discovery.get("hcb"), Mapping) else {}
    runtime = (
        hcb.get("runtime_resolution")
        if isinstance(hcb.get("runtime_resolution"), Mapping)
        else {}
    )
    active = _active_hcb_record(discovery) or {}
    archives = (
        discovery.get("archives")
        if isinstance(discovery.get("archives"), Mapping)
        else {}
    )
    engine = (
        discovery.get("engine")
        if isinstance(discovery.get("engine"), Mapping)
        else {}
    )
    seed = (
        discovery.get("profile_seed")
        if isinstance(discovery.get("profile_seed"), Mapping)
        else {}
    )
    native_functions = (
        discovery.get("native_functions")
        if isinstance(discovery.get("native_functions"), Mapping)
        else {}
    )
    visual_loader = (
        native_functions.get("visual_loader_family")
        if isinstance(native_functions.get("visual_loader_family"), Mapping)
        else {}
    )
    visual_selected = (
        visual_loader.get("selected")
        if isinstance(visual_loader.get("selected"), list)
        else []
    )
    portrait_lifecycle = (
        native_functions.get("portrait_lifecycle_family")
        if isinstance(native_functions.get("portrait_lifecycle_family"), Mapping)
        else {}
    )
    lifecycle_selected = (
        portrait_lifecycle.get("selected")
        if isinstance(portrait_lifecycle.get("selected"), Mapping)
        else {}
    )
    story_dialogue = (
        native_functions.get("story_dialogue_family")
        if isinstance(native_functions.get("story_dialogue_family"), Mapping)
        else {}
    )
    story_selected = (
        story_dialogue.get("selected")
        if isinstance(story_dialogue.get("selected"), Mapping)
        else {}
    )
    background_dissolve_family = (
        native_functions.get("background_dissolve_family")
        if isinstance(
            native_functions.get("background_dissolve_family"), Mapping
        )
        else {}
    )
    background_dissolve_selected = (
        background_dissolve_family.get("selected")
        if isinstance(background_dissolve_family.get("selected"), Mapping)
        else None
    )
    event_visual_chain = (
        native_functions.get("event_visual_chain")
        if isinstance(native_functions.get("event_visual_chain"), Mapping)
        else {}
    )
    event_visual_selected = (
        event_visual_chain.get("selected")
        if isinstance(event_visual_chain.get("selected"), Mapping)
        else {}
    )
    speaker_family = (
        native_functions.get("speaker_wrapper_family")
        if isinstance(native_functions.get("speaker_wrapper_family"), Mapping)
        else {}
    )
    resource_routes = (
        native_functions.get("resource_archive_routes")
        if isinstance(
            native_functions.get("resource_archive_routes"), Mapping
        )
        else {}
    )
    speaker_entries = (
        speaker_family.get("entries")
        if isinstance(speaker_family.get("entries"), list)
        else []
    )
    speaker_drafts = []
    for fallback_index, entry in enumerate(speaker_entries):
        if not isinstance(entry, Mapping):
            continue
        variants = (
            [str(value) for value in entry.get("name_variants", [])]
            if isinstance(entry.get("name_variants"), list)
            else []
        )
        speaker_index = int(entry.get("speaker_index", fallback_index))
        selection_mode = str(entry.get("selection_mode") or "")
        branch_report = (
            entry.get("selector_branches")
            if isinstance(entry.get("selector_branches"), Mapping)
            else {}
        )
        branches = (
            branch_report.get("branches")
            if branch_report.get("status") == "candidate_local_control_flow"
            and isinstance(branch_report.get("branches"), list)
            else []
        )
        if selection_mode == "selector_argument" and branches:
            for branch_index, branch in enumerate(branches):
                if not isinstance(branch, Mapping):
                    continue
                branch_variants = (
                    [str(value) for value in branch.get("name_variants", [])]
                    if isinstance(branch.get("name_variants"), list)
                    else []
                )
                if not branch_variants and not branch.get(
                    "blank_name_candidate"
                ):
                    continue
                selector_kind = str(branch.get("selector_kind") or "")
                selector_value = branch.get("selector_value")
                speaker_drafts.append(
                    {
                        "speaker_id": (
                            f"candidate:speaker-{speaker_index}:selector-"
                            f"{_selector_token(selector_kind, selector_value, branch_index)}"
                        ),
                        "display_name": (
                            branch_variants[0]
                            if branch_variants
                            else "（空白名）"
                        ),
                        "name_variants": branch_variants,
                        "binding": _draft_binding(entry),
                        "selection_mode": selection_mode,
                        "name_selector": {
                            "status": "unreviewed",
                            "argument_index": entry.get(
                                "selector_argument_index"
                            ),
                            "position_status": entry.get(
                                "selector_position_status"
                            ),
                            "value_kind": selector_kind,
                            "value": selector_value,
                            "branch_candidate_sha256": branch_report.get(
                                "candidate_sha256"
                            ),
                            "evidence": [],
                        },
                        "fixed_name_review": {
                            "status": "not_applicable",
                            "evidence": [],
                        },
                        "compile_ready": False,
                    }
                )
            continue
        if not variants:
            continue
        speaker_drafts.append(
            {
                "speaker_id": f"candidate:speaker-{speaker_index}",
                "display_name": _speaker_display_name(variants, speaker_index),
                "name_variants": variants,
                "binding": _draft_binding(entry),
                "selection_mode": selection_mode,
                "name_selector": {
                    "status": (
                        "unreviewed"
                        if selection_mode == "selector_argument"
                        else "not_applicable"
                    ),
                    "argument_index": entry.get("selector_argument_index"),
                    "position_status": entry.get("selector_position_status"),
                    "value_kind": "unresolved",
                    "value": None,
                    "branch_candidate_sha256": branch_report.get(
                        "candidate_sha256"
                    ),
                    "evidence": [],
                },
                "fixed_name_review": {
                    "status": "not_applicable"
                    if selection_mode == "selector_argument"
                    else "unreviewed",
                    "evidence": [],
                },
                "compile_ready": False,
            }
        )
    audio_routes = [
        _archive_route(str(item.get("name") or ""))
        for item in archives.get("audio", [])
        if isinstance(item, Mapping) and item.get("name")
    ]
    return {
        "schema": NATIVE_TARGET_PROFILE_SCHEMA,
        "target_id": discovery.get("target_id"),
        "display_name": discovery.get("display_name"),
        "engine_family_id": engine.get("family_id"),
        "discovery_manifest_sha256": discovery.get("manifest_sha256"),
        "analysis_hcb": {
            "name": hcb.get("analysis_source"),
            "sha256": next(
                (
                    record.get("sha256")
                    for record in hcb.get("candidates", [])
                    if isinstance(record, Mapping)
                    and record.get("analysis_source")
                ),
                None,
            ),
        },
        "runtime_activation": {
            "active_hcb_name": runtime.get("active_candidate"),
            "active_hcb_sha256": active.get("sha256"),
            "status": "unreviewed",
            "evidence": [],
        },
        "native_symbols": copy.deepcopy(seed.get("native_symbols", {})),
        "scene_bindings": {
            "dialogue_print": _draft_binding(story_selected.get("print")),
            "dialogue_wait": _draft_binding(story_selected.get("wait")),
            "background_primary": _draft_binding(
                visual_selected[0] if len(visual_selected) >= 1 else None
            ),
            "background_blur": _draft_binding(
                visual_selected[1] if len(visual_selected) >= 2 else None
            ),
            "background_dissolve": _draft_binding(
                background_dissolve_selected
            ),
            "portrait_clear": _draft_binding(lifecycle_selected.get("clear")),
            "portrait_apply": _draft_binding(lifecycle_selected.get("apply")),
            "visual_reset": [],
            "event_visual_prepare": _draft_binding(
                event_visual_selected.get("prepare")
            ),
            "event_visual_show": _draft_binding(
                event_visual_selected.get("show")
            ),
            "event_visual_finish": _draft_binding(
                event_visual_selected.get("finish")
            ),
            "bgm_play": None,
            "bgm_stop": None,
            "se_play": None,
            "se_stop_all": None,
        },
        "speakers": speaker_drafts,
        "archive_routing": {
            role: _resource_route_role_template(
                role,
                resource_routes.get(role),
            )
            for role in ("background", "portrait", "event_visual")
        } | {
            "audio": audio_routes,
        },
        "acceptance": {
            "status": "not_run",
            "cases": [
                {"id": case_id, "status": "not_run", "evidence": []}
                for case_id in REQUIRED_ACCEPTANCE_CASES
            ],
        },
        "review": {
            "status": "draft",
            "reviewer": "",
            "source_revision": "",
            "evidence": [],
        },
        "write_enabled": False,
    }


def _binding_items(profile: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    items: list[tuple[str, Mapping[str, Any]]] = []
    scene = profile.get("scene_bindings")
    if isinstance(scene, Mapping):
        for role, binding in scene.items():
            if role == "visual_reset":
                if isinstance(binding, list):
                    for index, value in enumerate(binding):
                        if isinstance(value, Mapping):
                            items.append((f"visual_reset[{index}]", value))
                continue
            if isinstance(binding, Mapping):
                items.append((str(role), binding))
    speakers = profile.get("speakers")
    if isinstance(speakers, list):
        for index, speaker in enumerate(speakers):
            if not isinstance(speaker, Mapping):
                continue
            binding = speaker.get("binding")
            if isinstance(binding, Mapping):
                items.append((f"speaker[{index}]", binding))
    return items


def _binding_addresses(
    items: Iterable[tuple[str, Mapping[str, Any]]],
) -> list[int]:
    addresses: list[int] = []
    for _role, binding in items:
        raw = binding.get("address")
        if isinstance(raw, bool) or raw is None:
            continue
        try:
            addresses.append(int(raw, 0) if isinstance(raw, str) else int(raw))
        except (TypeError, ValueError):
            continue
    return addresses


def _append_once(blockers: list[str], blocker: str) -> None:
    if blocker not in blockers:
        blockers.append(blocker)


def _known_archive_names(discovery: Mapping[str, Any]) -> set[str]:
    archives = discovery.get("archives")
    if not isinstance(archives, Mapping):
        return set()
    names: set[str] = set()
    for key in ("mixed_visual", "background", "portrait"):
        record = archives.get(key)
        if isinstance(record, Mapping) and record.get("name"):
            names.add(str(record["name"]).casefold())
    for key in ("event_visual", "audio"):
        values = archives.get(key)
        if isinstance(values, list):
            names.update(
                str(item.get("name")).casefold()
                for item in values
                if isinstance(item, Mapping) and item.get("name")
            )
    return names


def review_native_target_profile(
    discovery: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    """Review a profile draft against its exact read-only target.

    A clean result is only a candidate for source review.  API-submitted data
    is never trusted as an installed writer profile, so ``write_gate.enabled``
    intentionally remains false even when every declared check passes.
    """

    _require_discovery(discovery)
    if not isinstance(profile, Mapping):
        raise NativeTargetProfileError("目标 profile 必须是 JSON 对象")
    blockers: list[str] = []
    if profile.get("schema") != NATIVE_TARGET_PROFILE_SCHEMA:
        _append_once(blockers, "profile_schema_mismatch")
    if profile.get("target_id") != discovery.get("target_id"):
        _append_once(blockers, "target_id_mismatch")
    engine = discovery.get("engine") if isinstance(discovery.get("engine"), Mapping) else {}
    if profile.get("engine_family_id") != engine.get("family_id"):
        _append_once(blockers, "engine_family_id_mismatch")
    if profile.get("discovery_manifest_sha256") != discovery.get("manifest_sha256"):
        _append_once(blockers, "discovery_manifest_mismatch")
    if bool(profile.get("write_enabled")):
        _append_once(blockers, "self_enabled_profile_rejected")

    hcb = discovery.get("hcb") if isinstance(discovery.get("hcb"), Mapping) else {}
    analysis = profile.get("analysis_hcb") if isinstance(profile.get("analysis_hcb"), Mapping) else {}
    expected_analysis = next(
        (
            record
            for record in hcb.get("candidates", [])
            if isinstance(record, Mapping) and record.get("analysis_source")
        ),
        {},
    )
    if (
        analysis.get("name") != hcb.get("analysis_source")
        or analysis.get("sha256") != expected_analysis.get("sha256")
    ):
        _append_once(blockers, "analysis_hcb_identity_mismatch")

    seed = discovery.get("profile_seed") if isinstance(discovery.get("profile_seed"), Mapping) else {}
    if _canonical_sha256(profile.get("native_symbols", {})) != _canonical_sha256(
        seed.get("native_symbols", {})
    ):
        _append_once(blockers, "discovered_native_symbols_changed")

    runtime = profile.get("runtime_activation") if isinstance(profile.get("runtime_activation"), Mapping) else {}
    active = _active_hcb_record(discovery) or {}
    if (
        runtime.get("active_hcb_name") != active.get("name")
        or runtime.get("active_hcb_sha256") != active.get("sha256")
    ):
        _append_once(blockers, "runtime_hcb_identity_mismatch")
    if runtime.get("status") != "runtime_verified" or not runtime.get("evidence"):
        _append_once(blockers, "runtime_activation_not_reviewed")

    scene = profile.get("scene_bindings") if isinstance(profile.get("scene_bindings"), Mapping) else {}
    for role in REQUIRED_SCENE_BINDINGS:
        if not isinstance(scene.get(role), Mapping):
            _append_once(blockers, f"missing_scene_binding:{role}")
    resets = scene.get("visual_reset")
    if not isinstance(resets, list) or not any(isinstance(item, Mapping) for item in resets):
        _append_once(blockers, "missing_scene_binding:visual_reset")

    speakers = profile.get("speakers")
    native_functions = (
        discovery.get("native_functions")
        if isinstance(discovery.get("native_functions"), Mapping)
        else {}
    )
    discovered_speakers = (
        native_functions.get("speaker_wrapper_family")
        if isinstance(native_functions.get("speaker_wrapper_family"), Mapping)
        else {}
    )
    story_family = (
        native_functions.get("story_dialogue_family")
        if isinstance(native_functions.get("story_dialogue_family"), Mapping)
        else {}
    )
    story_selected = (
        story_family.get("selected")
        if isinstance(story_family.get("selected"), Mapping)
        else {}
    )
    lifecycle_family = (
        native_functions.get("portrait_lifecycle_family")
        if isinstance(native_functions.get("portrait_lifecycle_family"), Mapping)
        else {}
    )
    lifecycle_selected = (
        lifecycle_family.get("selected")
        if isinstance(lifecycle_family.get("selected"), Mapping)
        else {}
    )
    visual_loader_family = (
        native_functions.get("visual_loader_family")
        if isinstance(native_functions.get("visual_loader_family"), Mapping)
        else {}
    )
    visual_selected = (
        visual_loader_family.get("selected")
        if isinstance(visual_loader_family.get("selected"), list)
        else []
    )
    dissolve_family = (
        native_functions.get("background_dissolve_family")
        if isinstance(
            native_functions.get("background_dissolve_family"), Mapping
        )
        else {}
    )
    dissolve_selected = (
        dissolve_family.get("selected")
        if isinstance(dissolve_family.get("selected"), Mapping)
        else None
    )
    event_chain = (
        native_functions.get("event_visual_chain")
        if isinstance(native_functions.get("event_visual_chain"), Mapping)
        else {}
    )
    event_selected = (
        event_chain.get("selected")
        if isinstance(event_chain.get("selected"), Mapping)
        else {}
    )
    expected_scene_roles = {
        "dialogue_print": story_selected.get("print"),
        "dialogue_wait": story_selected.get("wait"),
        "background_primary": (
            visual_selected[0] if len(visual_selected) >= 1 else None
        ),
        "background_blur": (
            visual_selected[1] if len(visual_selected) >= 2 else None
        ),
        "background_dissolve": dissolve_selected,
        "portrait_clear": lifecycle_selected.get("clear"),
        "portrait_apply": lifecycle_selected.get("apply"),
        "event_visual_prepare": event_selected.get("prepare"),
        "event_visual_show": event_selected.get("show"),
        "event_visual_finish": event_selected.get("finish"),
    }
    for role, expected in expected_scene_roles.items():
        binding = scene.get(role)
        if not isinstance(binding, Mapping) or not isinstance(expected, Mapping):
            continue
        try:
            declared_address = int(binding.get("address"))
            expected_address = int(expected.get("start"))
        except (TypeError, ValueError):
            continue
        if declared_address != expected_address:
            _append_once(blockers, f"binding_role_mismatch:{role}")
    expected_speaker_entries = {
        int(item["start"]): item
        for item in discovered_speakers.get("entries", [])
        if isinstance(item, Mapping) and item.get("start") is not None
    }
    if not isinstance(speakers, list) or not speakers:
        _append_once(blockers, "speaker_abi_not_reviewed")
    else:
        for speaker in speakers:
            if not isinstance(speaker, Mapping) or not speaker.get("speaker_id"):
                _append_once(blockers, "speaker_abi_invalid")
                continue
            if not isinstance(speaker.get("binding"), Mapping):
                _append_once(blockers, "speaker_abi_invalid")
                continue
            binding = speaker["binding"]
            try:
                speaker_address = int(binding.get("address"))
            except (TypeError, ValueError):
                speaker_address = -1
            expected_speaker = expected_speaker_entries.get(speaker_address)
            if expected_speaker is None:
                _append_once(
                    blockers,
                    f"speaker_binding_not_discovered:{speaker.get('speaker_id')}",
                )
            selector = speaker.get("name_selector")
            speaker_id = str(speaker.get("speaker_id"))
            expected_mode = (
                expected_speaker.get("selection_mode")
                if expected_speaker is not None
                else None
            )
            if speaker.get("selection_mode") != expected_mode:
                _append_once(
                    blockers,
                    f"speaker_selection_mode_mismatch:{speaker_id}",
                )
            if expected_mode == "selector_argument":
                branch_report = (
                    expected_speaker.get("selector_branches")
                    if isinstance(
                        expected_speaker.get("selector_branches"), Mapping
                    )
                    else {}
                )
                expected_branches = (
                    branch_report.get("branches")
                    if branch_report.get("status")
                    == "candidate_local_control_flow"
                    and isinstance(branch_report.get("branches"), list)
                    else []
                )
                if (
                    expected_speaker.get("selector_position_status")
                    != "verified_by_stack_read"
                    or not isinstance(selector, Mapping)
                    or selector.get("argument_index")
                    != expected_speaker.get("selector_argument_index")
                ):
                    _append_once(
                        blockers,
                        f"speaker_selector_position_mismatch:{speaker_id}",
                    )
                selector_kind = (
                    str(selector.get("value_kind") or "")
                    if isinstance(selector, Mapping)
                    else ""
                )
                selector_value = (
                    selector.get("value")
                    if isinstance(selector, Mapping)
                    else None
                )
                branch_matches = [
                    branch
                    for branch in expected_branches
                    if isinstance(branch, Mapping)
                    and str(branch.get("selector_kind") or "")
                    == selector_kind
                    and branch.get("selector_value") == selector_value
                ]
                if (
                    len(branch_matches) != 1
                    or not isinstance(selector, Mapping)
                    or selector.get("branch_candidate_sha256")
                    != branch_report.get("candidate_sha256")
                ):
                    _append_once(
                        blockers,
                        f"speaker_selector_not_discovered:{speaker_id}",
                    )
                selector_value_ready = (
                    selector_value is not None
                    or selector_kind == "default_fallthrough"
                )
                if (
                    not isinstance(selector, Mapping)
                    or selector.get("status") != "reviewed"
                    or not selector_value_ready
                    or not selector.get("evidence")
                ):
                    _append_once(
                        blockers,
                        f"speaker_selector_not_reviewed:{speaker_id}",
                    )
            elif expected_mode == "fixed_or_delegated_candidate":
                fixed_review = speaker.get("fixed_name_review")
                if (
                    not isinstance(fixed_review, Mapping)
                    or fixed_review.get("status") != "reviewed"
                    or not fixed_review.get("evidence")
                ):
                    _append_once(
                        blockers,
                        f"speaker_fixed_name_not_reviewed:{speaker_id}",
                    )

    binding_items = _binding_items(profile)
    addresses = _binding_addresses(binding_items)
    inspection: dict[str, Any] | None = None
    if addresses:
        try:
            inspection = inspect_native_function_addresses(
                str(discovery.get("game_dir") or ""),
                addresses,
                active_script_name=str(
                    (
                        discovery.get("hcb", {})
                        if isinstance(discovery.get("hcb"), Mapping)
                        else {}
                    ).get("analysis_source")
                    or ""
                ),
            )
        except HcbError:
            _append_once(blockers, "function_inspection_failed")
    actual_functions = inspection.get("functions", {}) if inspection else {}
    for role, binding in binding_items:
        raw_address = binding.get("address")
        try:
            address = int(raw_address, 0) if isinstance(raw_address, str) else int(raw_address)
        except (TypeError, ValueError):
            _append_once(blockers, f"binding_address_invalid:{role}")
            continue
        actual = actual_functions.get(str(address))
        if not isinstance(actual, Mapping):
            _append_once(blockers, f"binding_not_function_boundary:{role}")
            continue
        try:
            argument_count = int(binding.get("argument_count"))
        except (TypeError, ValueError):
            argument_count = -1
        if argument_count != int(actual.get("args", -2)):
            _append_once(blockers, f"binding_argument_count_mismatch:{role}")
        if binding.get("structure_sha256") != actual.get("structure_sha256"):
            _append_once(blockers, f"binding_structure_mismatch:{role}")
        declared_syscalls = binding.get("syscalls")
        if not isinstance(declared_syscalls, list) or declared_syscalls != actual.get("syscalls"):
            _append_once(blockers, f"binding_syscalls_mismatch:{role}")
        if not binding.get("evidence"):
            _append_once(blockers, f"binding_evidence_missing:{role}")

    known_archives = _known_archive_names(discovery)
    routing = profile.get("archive_routing") if isinstance(profile.get("archive_routing"), Mapping) else {}
    discovered_routing = (
        native_functions.get("resource_archive_routes")
        if isinstance(
            native_functions.get("resource_archive_routes"), Mapping
        )
        else {}
    )
    for role in ("background", "portrait", "event_visual"):
        expected_report = discovered_routing.get(role)
        expected = _resource_route_role_template(role, expected_report)
        if (
            not isinstance(expected_report, Mapping)
            or expected_report.get("status") != "candidate_unique_structure"
            or not isinstance(expected_report.get("selected"), Mapping)
        ):
            _append_once(blockers, f"archive_route_not_discovered:{role}")
            continue
        declared = routing.get(role)
        if not isinstance(declared, Mapping):
            _append_once(blockers, f"archive_route_missing:{role}")
            continue
        if _canonical_sha256(
            _resource_route_locked_identity(declared)
        ) != _canonical_sha256(_resource_route_locked_identity(expected)):
            _append_once(
                blockers,
                f"archive_route_discovery_mismatch:{role}",
            )
        declared_routes = (
            declared.get("routes")
            if isinstance(declared.get("routes"), list)
            else []
        )
        for index, route in enumerate(declared_routes):
            if not isinstance(route, Mapping):
                _append_once(
                    blockers,
                    f"archive_route_invalid:{role}:{index}",
                )
                continue
            archive_name = str(route.get("archive") or "").casefold()
            route_id = archive_name or str(index)
            if archive_name not in known_archives:
                _append_once(
                    blockers,
                    f"archive_route_unknown:{role}:{route_id}",
                )
            if (
                route.get("mode") not in ALLOWED_ARCHIVE_MODES
                or not route.get("evidence")
            ):
                _append_once(
                    blockers,
                    f"archive_route_not_reviewed:{role}:{route_id}",
                )
        if (
            declared.get("review_status") != "reviewed"
            or not declared.get("review_evidence")
        ):
            _append_once(
                blockers,
                f"archive_routing_role_not_reviewed:{role}",
            )

    acceptance = profile.get("acceptance") if isinstance(profile.get("acceptance"), Mapping) else {}
    case_records = {
        str(item.get("id")): item
        for item in acceptance.get("cases", [])
        if isinstance(item, Mapping) and item.get("id")
    }
    if acceptance.get("status") != "passed":
        _append_once(blockers, "real_game_acceptance_not_passed")
    for case_id in REQUIRED_ACCEPTANCE_CASES:
        item = case_records.get(case_id)
        if not isinstance(item, Mapping) or item.get("status") != "passed" or not item.get("evidence"):
            _append_once(blockers, f"acceptance_case_missing:{case_id}")

    review = profile.get("review") if isinstance(profile.get("review"), Mapping) else {}
    if (
        review.get("status") != "accepted"
        or not review.get("reviewer")
        or not review.get("source_revision")
        or not review.get("evidence")
    ):
        _append_once(blockers, "source_review_not_accepted")

    candidate_ready = not blockers
    write_blockers = list(blockers)
    _append_once(write_blockers, "profile_not_registered_in_trusted_registry")
    return {
        "schema": NATIVE_TARGET_PROFILE_REVIEW_SCHEMA,
        "mode": "read_only",
        "writes_performed": False,
        "target_id": discovery.get("target_id"),
        "profile_sha256": _canonical_sha256(profile),
        "candidate_ready_for_registry": candidate_ready,
        "checked_binding_count": len(binding_items),
        "function_inspection": copy.deepcopy(inspection),
        "blockers": blockers,
        "write_gate": {
            "enabled": False,
            "policy": "trusted_registry_and_runtime_acceptance_required",
            "blockers": write_blockers,
        },
    }


__all__ = [
    "ALLOWED_ARCHIVE_MODES",
    "NATIVE_TARGET_PROFILE_REVIEW_SCHEMA",
    "NATIVE_TARGET_PROFILE_SCHEMA",
    "NativeTargetProfileError",
    "REQUIRED_ACCEPTANCE_CASES",
    "REQUIRED_SCENE_BINDINGS",
    "build_native_target_profile_template",
    "review_native_target_profile",
]
