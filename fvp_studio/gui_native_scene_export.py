"""Portable current-scene rehearsal, installed only in a brand-new copy.

Keep the production write gate and the Hoshi independent-startup exporter
unchanged. This generic route attaches a background/dialogue/portrait/choice
scene at an exact native dialogue boundary, preserves native startup and
returns to the original story. The chapter adapter reuses this compiler with
one paired state lifetime. No browser-supplied function addresses are used.
Portraits use target-owned carriers, stable native slots and native expression
blending; each motion binds the target's own complete parameter flow.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, replace
import json
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import stat
import struct
import subprocess

from .gui_native_preflight import SceneBuilder, checksum
from .gui_cg_stage_handoff import POSE_KIND
from .gui_runtime import fingerprint
from .gui_scene_export import ExportError, new_target, now, TARGET_ENCODINGS
from .gui_target_selection import OPTION_FIELDS, select_source
from .hcb import normalize_encoding, parse_bytes
from .hoshimemo_scene_hook import _compile_inserted_dialogue
from .native_scene_candidate import (
    NativeSceneMemoryContext, inspect_native_scene_anchor,
    prepare_native_scene_memory_context,
)
from .native_target_discovery import discover_fvp_target, _runtime_hcb_resolution, _select_analysis_hcb
from .native_target_profile import build_native_target_profile_template
from .native_graphics_imports import NativeGraphicsImports, NativeExportResources
from .native_portrait_scene import NativePortraitScene, KINDS as PORTRAIT_KINDS
from .gui_actor_sway import KINDS as SWAY_KINDS, validate_events as validate_sway_events
from .native_portrait_sway import NativePortraitSway
from .native_audio import NativeAudioBackend
from .native_audio_bindings import NativeAudioBindings
from .native_audio_program import NativeAudioProgram, KINDS as AUDIO_KINDS
from .native_rotation_degrees import NativeRotationDegrees
from .native_scene_camera import NativeSceneCamera
from .native_scene_background_blur import NativeSceneBackgroundBlur
from .native_screen_transition import NativeSceneScreenTransition
from .native_scene_choice_tracks import NativeSceneChoiceTracks, KINDS as CHOICE_KINDS
from .native_scene_cg import NativeSceneCG
from .gui_native_cg import KINDS as CG_KINDS
from .native_vm_backend import _binary_script_evidence
from .performance_compile import sha
from .performance_install import TEST_PARENT, _robocopy_executable, _safe, inventory

SCHEMA = "fvp-gui-native-scene-export/1"
SCOPE = "native_dialogue_hook_new_test_copy"
FEATURES = {"Scene", "Background", "GuiBackgroundChange", "GuiBackgroundBlur", "Text", "Speech", "Wait", "End", "CameraShot", "Transition"} | PORTRAIT_KINDS | CHOICE_KINDS | AUDIO_KINDS
CG_EXPORT_KINDS = {"GuiCGLoad", "GuiCGExit", "GuiCGTransform"}


def _filename(value, suffixes):
    if (not isinstance(value, str) or not value
            or any(c in value for c in ("/", "\\", ":", "\0"))
            or Path(value).name != value or Path(value).suffix.casefold() not in suffixes):
        raise ExportError("invalid_target_registration", "目标入口须为游戏根目录直属文件名。")
    return value


def _file_identity(path):
    """Hash a candidate in bounded chunks, checking for concurrent changes."""
    path = _safe(Path(path), file=True)
    before = fingerprint(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    if fingerprint(path) != before:
        raise ExportError("candidate_changed", "生成的资源包发生变化，已停止。")
    return dict(size=path.stat().st_size, sha256=digest.hexdigest())


@dataclass(frozen=True)
class BoundTarget:
    root: Path
    script: str
    analysis_script: str
    executable: str
    executable_sha256: str
    context: NativeSceneMemoryContext
    stamps: dict
    activation: dict
    encoding_confirmed: bool
    discovery: dict = field(default_factory=dict)

    def check_unchanged(self):
        for name, expected in self.stamps.items():
            if fingerprint(_safe(self.root / name, file=True, independent=False)) != expected:
                raise ExportError("source_changed", "目标游戏的脚本、程序或资源已变化，请重新生成。")


def bind_target(source):
    """Resolve files from local registration and the current native discovery.

    A paired hidden overlay is bound to its visible analysis sibling. Distinct
    HCB/BCH candidates need explicit local target_script selection. EXE string
    evidence is recorded as such, never promoted to runtime verification.
    """
    root = _safe(source.root)
    files = {}
    for path in root.iterdir():
        if path.is_file():
            name = path.name.casefold()
            if name in files:
                raise ExportError("ambiguous_target", "游戏目录有大小写冲突的文件名。")
            files[name] = _safe(path, file=True, independent=False)
    selected = getattr(source, "target_script", None)
    if selected is not None:
        _filename(selected, {".hcb", ".bch"})
        if selected.casefold() not in files:
            raise ExportError("script_unavailable", "登记的目标剧情脚本不存在。")
    # When the explicit selected file is a hidden overlay, discovery must still
    # analyse the visible sibling, not try to parse the translated tail as code.
    analysis_choice = selected
    if selected and selected.startswith(".") and selected[1:].casefold() in files:
        analysis_choice = None
    encoding_option = getattr(source, "target_encoding", None)
    encoding = normalize_encoding(encoding_option or "sjis")
    try:
        scripts = [p for p in files.values() if p.suffix.casefold() in {".hcb", ".bch"}]
        analysis_path, _ = _select_analysis_hcb(scripts, analysis_choice)
        resolution = _runtime_hcb_resolution(scripts, files, analysis_choice)
        if not resolution.get("active_candidate") or resolution.get("status") == "ambiguous":
            raise ValueError("运行脚本有歧义，需要本机明确选择")
        same_file = resolution["active_candidate"].casefold() == analysis_path.name.casefold()
        analysis_encoding = normalize_encoding(getattr(source, "target_analysis_encoding", None)
            or (encoding if same_file else "sjis"))
        if same_file and encoding != analysis_encoding:
            raise ValueError("单一线性脚本的运行编码与分析编码必须一致")
        discovery = discover_fvp_target(root, active_script_name=analysis_choice,
                                        analysis_encoding=analysis_encoding)
    except ValueError as exc:
        raise ExportError("target_selection_needed", "目标脚本尚不能唯一确定：" + str(exc)[:240]) from exc
    runtime = discovery["hcb"]["runtime_resolution"]
    active = runtime.get("active_candidate")
    if not active or runtime.get("status") == "ambiguous":
        raise ExportError("target_selection_needed", "有多个运行脚本，请在本机来源登记中选择 target_script。")
    if selected and active.casefold() != selected.casefold():
        raise ExportError("target_selection_needed", "登记的运行脚本与原生发现结果不一致。")
    analysis_name = discovery["hcb"]["analysis_source"]
    script_path, analysis_path = files[active.casefold()], files[analysis_name.casefold()]
    executable = getattr(source, "target_executable", None)
    if executable is not None:
        _filename(executable, {".exe"})
        if executable.casefold() not in files:
            raise ExportError("executable_unavailable", "登记的游戏启动程序不存在。")
        exe_path = files[executable.casefold()]
        evidence = _binary_script_evidence(exe_path)
        basis = "local_explicit_executable"
    else:
        candidates = [(p, _binary_script_evidence(p)) for p in files.values()
                      if p.suffix.casefold() == ".exe"]
        candidates = [(p, e) for p, e in candidates
                      if any(r["suffix"] == script_path.suffix.casefold() for r in e["references"])]
        if len(candidates) != 1:
            raise ExportError("target_selection_needed", "启动程序尚不能唯一确定，请在本机来源登记中选择 target_executable。")
        exe_path, evidence = candidates[0]
        basis = "unique_executable_extension_candidate"
    if exe_path.read_bytes()[:2] != b"MZ":
        raise ExportError("invalid_executable", "目标启动程序不是 Windows EXE。")
    suffixes = {r["suffix"] for r in evidence.get("references", ())}
    if suffixes and script_path.suffix.casefold() not in suffixes:
        raise ExportError("target_selection_needed", "启动程序与所选脚本的扩展名证据冲突。")
    names = {script_path.name, analysis_path.name, exe_path.name}
    if "fvpkernel.dll" in files:
        names.add(files["fvpkernel.dll"].name)
    stamps = {name: fingerprint(files[name.casefold()]) for name in names}
    source_bytes, analysis_bytes = script_path.read_bytes(), analysis_path.read_bytes()
    profile = build_native_target_profile_template(discovery)
    context = prepare_native_scene_memory_context(source_bytes, encoding, discovery, profile,
        analysis_hcb_bytes=analysis_bytes if script_path != analysis_path else None,
        analysis_encoding=discovery["hcb"]["analysis_encoding"])
    target = BoundTarget(root, script_path.name, analysis_path.name, exe_path.name,
        sha(exe_path.read_bytes()), context, stamps,
        dict(status=runtime["status"], script=script_path.name,
             executable_selection=basis, executable_evidence=evidence,
             runtime_verified=False), encoding_option is not None, discovery)
    target.check_unchanged()
    return target


def source_for_request(runtime, request):
    """Freeze explicit native entry/code-page choices for this output only.

    Only basenames in the registered root are accepted; native discovery still
    binds every dependency. No source registration, project or hook is changed.
    """
    source = runtime._source(request["document"]["project"]["source"])
    return select_source(source, {key: request[key] for key in OPTION_FIELDS if key in request})


def select_hook(context, explicit_offset=None):
    # A hook is not a guessed standalone entry. Preserve the game's startup,
    # then attach to an exact native text boundary. Report the triggering line
    # so users can locate it; reaching that line still needs a real-game check.
    from .native_story_hooks import reachable_native_instructions
    if explicit_offset is not None:
        if type(explicit_offset) is not int:
            raise ExportError("invalid_target_registration", "登记的剧情接入位置须为整数。")
        candidates = [r for r in context.dialogue_profile.records if r["slot_offset"] == explicit_offset]
        evidence = dict(mode="explicit_local_native_dialogue", runtime_verified=False)
    else:
        reachable, evidence = reachable_native_instructions(context.analysis_document, context.document)
        candidates = [r for r in context.dialogue_profile.records if r["slot_offset"] in reachable][:64]
    for record in candidates:
        anchor = inspect_native_scene_anchor(context, record["slot_offset"], "before")
        patch = anchor.get("patch") or {}
        if anchor.get("safe") and patch.get("replay_order") == "custom_then_original":
            anchor["native_entry_selection"] = evidence
            return anchor
    raise ExportError("native_hook_unavailable", "没有找到可安全接入测试场景的原生台词位置。")


def compile_scene(target, program, anchor, *, graphics_imports=None, audio_bindings=None, motion_contract=None,
                  rotation_contract=None, _cg_memory_only=False, cg_source_targets=None,
                  _cg_threaded_memory_only=False,_cg_original_graph_journal=False,
                  _cg_native_state_bridge_out=None, _scene_native_state_bridge_out=None,
                  _scene_state_binding=None):
    """Emit target-exact calls; raw CG bytecode needs its matching test EXE.

    The scene exporter selects the paired native-state route for CG scenes.
    A raw in-memory caller can still compile libraries without installing
    them; only a matched EXE/HCB pair may enter a new game copy.
    """
    context = target.context
    try:
        validate_sway_events(program['events'])
    except (ValueError, KeyError, TypeError) as exc:
        raise ExportError('invalid_actor_sway', str(exc)) from exc
    from .gui_native_chapter_export import validate_native_chapter_program, ROUTED_SCHEMA
    from .native_chapter_routes import EXIT_KIND, NativeChapterRoutes
    chapter = validate_native_chapter_program(program)
    routed_chapter = chapter is not None and chapter["schema"] == ROUTED_SCHEMA
    from .gui_story_logic import KINDS as LOGIC_KINDS
    story_bank = None
    parallel_swaps, parallel_consumed, batch_swaps, batch_consumed, batch_actions = {}, {}, {}, {}, {}
    for group in program.get('native_parallel_swaps', []):
        if not isinstance(group,dict) or set(group)-{'swap_index','swap_indexes','action_indexes','beat_id'}:
            raise ExportError('invalid_parallel_swap', '同拍换装的节拍范围不完整。')
        index, actions = group.get('swap_index'), group.get('action_indexes')
        if 'swap_indexes' in group:
            swaps = group['swap_indexes']
            if (not isinstance(swaps,list) or not 1 <= len(swaps) <= 4 or not isinstance(actions,list)
                    or type(index) is not int or swaps[0]!=index
                    or any(type(i) is not int or not 0 <= i < len(program['events'])
                        or program['events'][i]['kind']!='GuiActorSwap'
                        or program['events'][i].get('duration_ms',0)<=0
                        or i in batch_consumed or i in parallel_consumed
                        or i in parallel_swaps or i in batch_swaps for i in swaps)
                    or swaps!=sorted(set(swaps))):
                raise ExportError('invalid_parallel_swap','多角色换装须引用本节拍中唯一的原生渐变事件。')
            actors = [program['events'][i]['portrait']['actor'] for i in swaps]
            if len(set(actors))!=len(actors):
                raise ExportError('invalid_parallel_swap','多角色同拍换装不能重复同一个演员。')
            if (any(type(i) is not int or not index < i < len(program['events'])
                    or program['events'][i]['kind'] not in {'Action','GuiActorMove','GuiActorSlide','CameraShot','GuiBackgroundBlur'}
                    or (program['events'][i]['kind'] in {'Action','GuiActorMove','GuiActorSlide'} and (
                        type(program['events'][i].get('actor')) is not int
                        or not 1 <= program['events'][i]['actor'] <= 4))
                    or i in swaps or i in batch_consumed or i in parallel_consumed
                    or i in parallel_swaps or i in batch_swaps for i in actions)
                    or len(set(actions))!=len(actions)
                    or any(i not in swaps and i not in actions for i in range(index,max(swaps+actions)+1))):
                raise ExportError('invalid_parallel_swap','同拍运动须属于本场景已入场的角色，不可跨台词、分支或另一提交组。')
            if len(swaps)==1 and not any(program['events'][i].get('actor') not in actors for i in actions):
                raise ExportError('invalid_parallel_swap','单角色自身运动应使用原有成对启动，不建立空的其他角色批次。')
            batch_swaps[index] = [program['events'][i] for i in swaps]
            batch_actions[index] = [program['events'][i] for i in actions]
            batch_consumed.update((i,index) for i in swaps[1:])
            parallel_consumed.update((i,index) for i in actions)
            continue
        if (type(index) is not int or not 0 <= index < len(program['events'])
                or program['events'][index]['kind']!='GuiActorSwap' or index in parallel_swaps
                or index in batch_swaps or index in batch_consumed or index in parallel_consumed
                or not isinstance(actions,list) or not actions
                or any(type(i) is not int or not index < i < len(program['events'])
                       or i in parallel_consumed or i in batch_swaps or i in batch_consumed
                       or i in parallel_swaps for i in actions) or len(set(actions)) != len(actions)):
            raise ExportError('invalid_parallel_swap', '同拍换装必须引用本节拍中换装之后的唯一运动事件。')
        parallel_swaps[index] = [program['events'][i] for i in actions]
        parallel_consumed.update((i,index) for i in actions)
    from .native_portrait_motion_group import bind_motion_groups
    try:
        motion_groups, motion_consumed = bind_motion_groups(program['events'],
            program.get('native_parallel_motion', []),
            set(parallel_swaps) | set(parallel_consumed) | set(batch_swaps) | set(batch_consumed))
    except ValueError as exc:
        raise ExportError('invalid_parallel_motion', str(exc)) from exc
    cg_groups, cg_consumed = {}, {}
    for group in program.get('native_parallel_cg', []):
        indexes = group.get('action_indexes') if isinstance(group,dict) else None
        if (not isinstance(indexes,list) or len(indexes)!=2 or not group.get('beat_id')
                or any(type(i) is not int or not 0 <= i < len(program['events']) for i in indexes)
                or indexes[1]!=indexes[0]+1
                or [program['events'][i]['kind'] for i in indexes]!=['GuiCGLoad','GuiCGTransform']
                or any(i in cg_groups or i in cg_consumed or i in parallel_consumed
                    or i in motion_consumed or i in batch_consumed for i in indexes)):
            raise ExportError('invalid_parallel_cg', 'CG 同拍提交必须是本节拍连续的一次加载与一次构图。')
        cg_groups[indexes[0]] = program['events'][indexes[1]]
        cg_consumed[indexes[1]] = indexes[0]
    if any(type(v) is not bool for v in (_cg_memory_only,_cg_threaded_memory_only,_cg_original_graph_journal)):
        raise ExportError("invalid_cg_compile_mode", "CG 内存编译模式须由本机明确选择。")
    has_cg = any(e["kind"] in CG_KINDS for e in program["events"])
    scene_state = _scene_state_binding
    if _scene_native_state_bridge_out is not None:
        from .native_scene_state import NativeSceneState
        if (has_cg or _cg_native_state_bridge_out is not None or _cg_threaded_memory_only
                or type(_scene_native_state_bridge_out) is not dict or _scene_native_state_bridge_out
                or not isinstance(scene_state, NativeSceneState) or scene_state.target is not target):
            raise ExportError("invalid_scene_state_mode", "普通场景需要本目标独立配对的状态恢复接口。")
    elif scene_state is not None:
        raise ExportError("invalid_scene_state_mode", "普通场景状态恢复须同时提供配对接口结果容器。")
    threaded_state = _cg_threaded_memory_only or scene_state is not None
    has_sway = any(e['kind'] in SWAY_KINDS for e in program['events'])
    has_audio = any(e['kind'] in AUDIO_KINDS for e in program['events'])
    if has_audio and (not threaded_state or not isinstance(audio_bindings, NativeAudioBindings)):
        raise ExportError('native_audio_state_required', '通用声音须配对本目标的原生状态接口和声音素材。')
    if has_sway and not threaded_state:
        raise ExportError('native_actor_sway_state_required', '持续摇摆须配对本目标的原生状态接口。')
    if chapter is not None and scene_state is None and not (
            has_cg and _cg_memory_only and _cg_threaded_memory_only
            and _cg_original_graph_journal and type(_cg_native_state_bridge_out) is dict):
        raise ExportError("native_chapter_state_required", "通用多场景必须使用同一目标配对的原生状态接口。")
    if motion_groups and not threaded_state:
        raise ExportError('native_parallel_motion_state_required',
            '普通移动与缩放或景深同拍，需要本目标配对的原生状态接口；不会改为串行输出。')
    if _cg_threaded_memory_only and (not _cg_memory_only or not has_cg):
        raise ExportError("invalid_cg_compile_mode", "CG 线程整场景装配只能用于私有 CG 内存编译。")
    if _cg_original_graph_journal and not _cg_threaded_memory_only:
        raise ExportError("invalid_cg_compile_mode", "原剧情图像记录只能用于私有 CG 线程场景编译。")
    if _cg_native_state_bridge_out is not None and (
            type(_cg_native_state_bridge_out) is not dict or _cg_native_state_bridge_out
            or not _cg_original_graph_journal):
        raise ExportError("invalid_cg_compile_mode", "原生状态接口需要独立结果容器和完整场景恢复路径。")
    if has_cg and not _cg_memory_only:
        raise ExportError("generic_feature_not_connected", "完整通用 CG 输出尚未接通，不能省略后生成。")
    if rotation_contract is not None:
        rotation_contract.assert_target(target)
    backend = context.abi.native_background_backend
    if backend is None:
        raise ExportError("background_not_supported", "此版本的原生背景加载尚未接通。")
    if graphics_imports is not None and (graphics_imports.root != target.root
            or graphics_imports.routes.get("background") != dict(backend.archive_selectors)):
        raise ExportError("invalid_resource_route", "素材打包器不属于当前目标的原生路由。")
    source = context.document.original_bytes
    code, events, references, stamps = bytearray(b"\x01\0\0" if threaded_state else b""), [], [], {}
    if scene_state is not None:
        scene_state.start(code)
    portrait_scene, camera, choices, blur, screen = None, None, None, None, None
    cg = None
    sway = None
    audio = None
    if has_cg:
        try:
            cg = NativeSceneCG(target, code, graphics_imports, source_targets=cg_source_targets,
                               use_snapshot_storage=_cg_threaded_memory_only,
                               use_native_resource_snapshot=(
                                   _cg_native_state_bridge_out is not None),
                               **(dict(use_original_graph_journal=True) if _cg_original_graph_journal else {}))
        except (ValueError, KeyError) as exc:
            raise ExportError("native_cg_memory_binding_rejected", str(exc)) from exc
    if any(e["kind"] in {"Transition", "GuiCGExit"} for e in program["events"]):
        try:
            screen = NativeSceneScreenTransition(target, code)
        except (ValueError, KeyError) as exc:
            raise ExportError("native_screen_transition_not_connected", str(exc)) from exc
    if any(e["kind"] == "GuiBackgroundBlur" for e in program["events"]):
        try:
            blur = NativeSceneBackgroundBlur(target, code, graphics_imports)
        except (ValueError, KeyError) as exc:
            raise ExportError("native_background_blur_not_connected", str(exc)) from exc
    has_choices = routed_chapter or any(e["kind"] in CHOICE_KINDS for e in program["events"])
    if has_choices and ([e["kind"] for e in program["events"]].count("End") != 1
            or program["events"][-1]["kind"] != "End"):
        raise ExportError("invalid_scene_end", "使用选项的测试场景须只有一个结束节点，并放在最后。")
    if any(e["kind"] == "CameraShot" for e in program["events"]) or (cg and cg.requires_retained_camera):
        try:
            camera = NativeSceneCamera(target, code)
        except (ValueError, KeyError) as exc:
            raise ExportError("native_camera_not_connected", str(exc)) from exc
        storage = cg.snapshot_storage if cg else scene_state.snapshot_storage if scene_state is not None else None
        if storage is not None:
            camera.snapshot = storage.reserve(camera.snapshot,"scene_camera")
        code.extend(camera.snapshot["snapshot"])
        camera.restore_current()
    if cg:
        try:
            cg.bind_camera(camera, screen)
        except (ValueError, KeyError) as exc:
            raise ExportError("native_cg_camera_handoff_rejected", str(exc)) from exc
    if scene_state is not None:
        try:
            scene_state.bind_camera(camera)
        except (ValueError, KeyError) as exc:
            raise ExportError("native_scene_state_dialogue_rejected", str(exc)) from exc
    if has_sway:
        try:
            sway = NativePortraitSway(target, cg or scene_state, program['events'], code, rotation_contract)
        except (ValueError, KeyError) as exc:
            raise ExportError('native_actor_sway_not_connected', str(exc)) from exc
    if any(e["kind"] in PORTRAIT_KINDS for e in program["events"]):
        try:
            portrait_scene = NativePortraitScene(target, program["events"], anchor,
                graphics_imports, code, motion_contract=motion_contract, scene_camera=camera,
                rotation_contract=rotation_contract,
                **(dict(cg_guard=cg.guard, snapshot_storage=cg.snapshot_storage) if cg else
                   dict(cg_guard=scene_state.guard, snapshot_storage=scene_state.snapshot_storage,
                        slot_catalog=scene_state.catalog) if scene_state is not None else {}))
        except (ValueError, KeyError) as exc:
            raise ExportError("native_portraits_not_connected", str(exc)) from exc
        if screen is not None:
            try:
                screen.bind_portraits(portrait_scene.loader.assignments.values())
            except (ValueError, KeyError) as exc:
                raise ExportError("native_screen_portrait_ownership_conflict", str(exc)) from exc
        if blur is not None:
            try:
                blur.bind_portraits(portrait_scene.loader.assignments.values())
            except (ValueError, KeyError) as exc:
                raise ExportError("native_blur_portrait_ownership_conflict", str(exc)) from exc
        if sway:
            try:
                sway.bind_portraits(portrait_scene)
            except (ValueError, KeyError) as exc:
                raise ExportError('native_actor_sway_not_connected', str(exc)) from exc
    if cg:
        try:
            cg.bind_retained_scene(portrait_scene, blur)
            if any(e["kind"] == "GuiCGTransform" for e in program["events"]):
                cg.bind_motion()
        except (ValueError, KeyError) as exc:
            raise ExportError("native_cg_scene_handoff_rejected", str(exc)) from exc
    if scene_state is not None:
        try:
            scene_state.bind_retained_scene(portrait_scene)
        except (ValueError, KeyError) as exc:
            raise ExportError("native_scene_state_dialogue_rejected", str(exc)) from exc
    if has_audio:
        try:
            audio = NativeAudioProgram(target, cg or scene_state, program['events'], code, audio_bindings)
        except (ValueError, KeyError) as exc:
            raise ExportError('native_audio_not_connected', str(exc)) from exc
    if (camera or portrait_scene or blur or screen or cg or audio) and ([e["kind"] for e in program["events"]].count("End") != 1
            or program["events"][-1]["kind"] != "End"):
        raise ExportError("invalid_scene_end", "使用镜头或立绘的测试场景须只有一个结束节点，并放在最后。")
    if routed_chapter and chapter.get("variables"):
        from .native_story_variables import NativeStoryVariableBank
        try:
            storage = cg.snapshot_storage if cg else scene_state.snapshot_storage
            story_bank = NativeStoryVariableBank(target, code, chapter["variables"], storage)
            story_bank.initialize()
        except (ValueError, KeyError) as exc:
            raise ExportError("native_chapter_variables_not_connected", str(exc)) from exc
    if has_choices:
        try:
            choice_class = NativeChapterRoutes if routed_chapter else NativeSceneChoiceTracks
            choices = choice_class(target, program["events"], code,
                portraits=portrait_scene, camera=camera, blur=blur, screen=screen,
                audio=audio,
                **(dict(boundary_ms=chapter["boundary_ms"], story_bank=story_bank,
                    subroutine_entries=any("transition" in r for r in chapter["routes"]),
                    menu_required=(any(r["mode"] == "choice" for r in chapter["routes"])
                        or any(e["kind"] in CHOICE_KINDS for e in program["events"]))) if routed_chapter else {}),
                **(dict(cg=cg) if cg else dict(scene_state=scene_state) if scene_state is not None else {}))
        except (ValueError, KeyError) as exc:
            raise ExportError("native_choices_not_connected", str(exc)) from exc

    def choice_prompt(text, choice_id):
        if not target.encoding_confirmed and not text.isascii():
            raise ExportError("target_encoding_needed", "输出选项提示或标题前，请确认这份游戏脚本的文字编码。")
        prompt_abi = choices.menu.prompt_abi
        payload, report = _compile_inserted_dialogue(context.document,
            context.dialogue_profile, [dict(line_id="choice_prompt_"+choice_id,
                speaker_id="narration", text=text, voice_id=None)], prompt_abi,
            analysis_document=context.analysis_document)
        wait = b"\x02"+struct.pack("<I", prompt_abi.wait_target)
        if prompt_abi.print_includes_wait or not payload.endswith(wait):
            raise ValueError("选项提示的原生打印和点击等待尚不能分开。")
        # Retain the exact native text bridge/name/backlog chain, dropping only
        # its separately proven final click call. Native show owns the wait.
        payload = payload[:-len(wait)]
        if cg:
            payload = cg.dialogue.rewrite(payload)
        elif scene_state is not None:
            payload = scene_state.dialogue.rewrite(payload)
        elif portrait_scene:
            payload = portrait_scene.dialogue.rewrite(payload)
        report = deepcopy(report)
        report[0].update(separate_wait_emitted=False, byte_count=len(payload),
                         native_menu_wait_replaces_dialogue_wait=True)
        return payload, report

    lines = 0
    for index, event in enumerate(program["events"]):
        kind, before = event["kind"], len(code)
        if index in cg_consumed:
            events.append(dict(event_index=index,kind=kind,byte_range=[before,before],
                compiled_with_native_cg=cg_consumed[index],native_parallel_launch=True))
            continue
        if index in motion_consumed:
            events.append(dict(event_index=index, kind=kind, byte_range=[before, before],
                target_native_portrait=True, compiled_with_native_motion=motion_consumed[index],
                native_parallel_launch=True))
            continue
        if index in batch_consumed:
            events.append(dict(event_index=index,kind=kind,byte_range=[before,before],
                target_native_portrait=True,compiled_with_native_batch=batch_consumed[index],
                native_parallel_launch=True))
            continue
        if index in parallel_consumed:
            events.append(dict(event_index=index, kind=kind, byte_range=[before,before],
                target_native_portrait=True, compiled_with_native_swap=parallel_consumed[index],
                native_parallel_launch=True))
            continue
        if kind not in FEATURES | (CG_KINDS if cg else set()) | ({EXIT_KIND} | LOGIC_KINDS if routed_chapter else set()):
            raise ExportError("generic_feature_not_connected", f"其他游戏的 {kind} 输出尚未接通，场景不会被删减输出。")
        if cg:
            try:
                cg.assert_stage_event(kind)
            except ValueError as exc:
                raise ExportError("native_cg_stage_event_rejected", str(exc), issues=[dict(
                    level="error", code="native_cg_stage_event_rejected", event_index=index,
                    kind=kind, message=str(exc))]) from exc
        if (routed_chapter and choices.subroutine_entries
                and index in {r["setup_end"] for r in chapter["scenes"]}):
            choices.ready()
            details = dict(chapter_setup_subroutine_complete=True, reveal_owned_by_source_exit=True)
        elif kind == "Scene" and routed_chapter:
            choices.enter(event["scene_id"])
            details = dict(native_chapter_scene_id=event["scene_id"], stable_scene_entry=True,
                previous_authored_stage_cleared_at_exit=True, original_story_not_resumed=True)
        elif kind == EXIT_KIND and routed_chapter:
            if not target.encoding_confirmed and any(not text.isascii() for text in
                    [event["prompt"], *[o["label"] for o in event["options"]]]):
                raise ExportError("target_encoding_needed", "输出场景选项前，请确认这份游戏脚本的文字编码。")
            try:
                choices.exit(event, choice_prompt)
            except (ValueError, KeyError) as exc:
                raise ExportError("native_chapter_exit_rejected", str(exc), issues=[dict(
                    level="error", code="native_chapter_exit_rejected", scene_id=event["scene_id"],
                    field="exit", message=str(exc))]) from exc
            if event["mode"] == "choice":
                lines += 1
            details = dict(target_native_chapter_exit=True, selected_route_only=True)
        elif kind == "Scene" and chapter is not None:
            # All authored scenes share one outer capture/restore. This is
            # only a scene boundary, never a return to the original caller.
            if cg:
                cg.leave_scene()
            if portrait_scene:
                for actor in sorted(portrait_scene.states):
                    portrait_scene.emit(dict(kind="Hide", actor=actor))
            if blur:
                blur.clear()
            if camera:
                camera.finish()
            (cg if cg is not None else scene_state).cleanup_owned_threads(reason="chapter_scene_boundary")
            details = dict(native_chapter_scene_id=event["scene_id"],
                previous_authored_stage_cleared=True, original_story_not_resumed=True)
        elif kind in CHOICE_KINDS:
            if blur:
                blur.join()
            if not target.encoding_confirmed and any(isinstance(event.get(key), str)
                    and not event[key].isascii() for key in ("prompt", "option_1", "option_2", "option_3", "option_4")):
                raise ExportError("target_encoding_needed", "输出选项提示或标题前，请确认这份游戏脚本的文字编码。")
            try:
                choices.emit(event, choice_prompt)
            except (ValueError, KeyError) as exc:
                raise ExportError("native_choice_event_rejected", str(exc), issues=[dict(
                    level="error", code="native_choice_event_rejected", event_index=index,
                    kind=kind, choice_id=event.get("choice_id"), message=str(exc))]) from exc
            if kind in {"Choice", "GuiChoice"}:
                lines += 1
            details = dict(target_native_choice=True)
        elif kind in CG_KINDS:
            try:
                if camera:
                    camera.join()
                if portrait_scene:
                    portrait_scene.join()
                if blur:
                    blur.join()
                if index in cg_groups:
                    cg.emit_load_with_transform(event,cg_groups[index])
                else:
                    cg.emit(event)
            except (ValueError, KeyError) as exc:
                raise ExportError("native_cg_memory_event_rejected", str(exc), issues=[dict(
                    level="error", code="native_cg_memory_event_rejected", event_index=index,
                    kind=kind, message=str(exc))]) from exc
            details = dict(target_native_cg_memory_assembly=True, public_export_connected=False)
            if index in cg_groups:
                details.update(native_parallel_launch=True, native_cg_motion_before_reveal_wait=True)
        elif kind in PORTRAIT_KINDS:
            try:
                if kind == POSE_KIND and (screen is None or screen.covered is None):
                    raise ValueError("直接设置角色姿态需要黑／白场遮盖；可见运动仍须使用运动时长。")
                if blur:
                    blur.join()
                if kind in SWAY_KINDS:
                    sway.emit(event)
                elif index in motion_groups:
                    portrait_scene.motion_batch(motion_groups[index])
                elif index in batch_swaps:
                    stage_events = [e for e in batch_actions[index] if e['kind'] in {'CameraShot','GuiBackgroundBlur','GuiActorSlide'}
                        or e['kind']=='Action' and e.get('channels')=='alpha']
                    if stage_events:
                        portrait_scene.join()
                        if camera:
                            camera.join()
                    portrait_scene.swap_batch(batch_swaps[index],parallel_events=[e for e in batch_actions[index]
                        if e not in stage_events],stage_events=stage_events,blur=blur)
                else:
                    portrait_scene.emit(event, **(dict(parallel_events=parallel_swaps[index])
                        if index in parallel_swaps else {}))
                if (blur and kind in {"Portrait", "GuiActorSwap", "Hide"}
                        and not (index in batch_actions and any(e['kind']=='GuiBackgroundBlur' for e in batch_actions[index]))):
                    blur.reassert()
            except (ValueError, KeyError) as exc:
                raise ExportError("native_portrait_event_rejected", str(exc), issues=[dict(
                    level="error", code="native_portrait_event_rejected", event_index=index,
                    kind=kind, message=str(exc))]) from exc
            details = dict(target_native_portrait=True)
            if kind == POSE_KIND:
                details.update(instantaneous_pose_set=True, motion_zero_used=False)
            if index in motion_groups:
                details.update(native_parallel_launch=True,
                    native_parallel_action_count=len(motion_groups[index]),
                    native_current_buffer_only=True, native_complete_apply_count=0)
            if index in parallel_swaps:
                details.update(native_parallel_launch=True, native_parallel_action_count=len(parallel_swaps[index]))
            if index in batch_swaps:
                details.update(native_parallel_launch=True,native_parallel_actor_count=len(batch_swaps[index]),
                    native_parallel_action_count=len(batch_actions[index]),
                    native_complete_apply_count=1)
        elif kind in {"Background", "GuiBackgroundChange"}:
            if camera:
                camera.join()
            if portrait_scene:
                portrait_scene.join()
            if blur:
                blur.clear()
            path = _safe(Path(event["archive"]), file=True, independent=False)
            if graphics_imports is not None:
                try:
                    reference = graphics_imports.bind("background", path, event["resource"])
                except ValueError as exc:
                    raise ExportError("invalid_background_import", str(exc)) from exc
                archive = reference["target_archive"]
                name = reference["target_resource_name"]
            elif path.parent != target.root:
                raise ExportError("cross_game_background_not_connected", "目前通用输出先用目标游戏自身的背景；跨游戏背景打包尚未接通。")
            else:
                archive, name = path.name.casefold(), event["resource"]
                from .performance_compile import resource_reference
                _payload, reference = resource_reference(path, event["resource"])
            if archive not in backend.archive_selectors:
                raise ExportError("invalid_resource_route", "背景不在目标游戏的原生加载路由中。")
            if reference["kind"] != 0 or reference["frame_count"] != 1:
                raise ExportError("unsupported_background", "通用输出目前只支持完整单帧背景。")
            if path.parent == target.root:
                stamps[path.name] = fingerprint(path)
            duration = event.get("duration_ms", 0)
            try:
                transition = screen.before_background(duration) if screen else True
            except ValueError as exc:
                raise ExportError("native_background_under_cover_rejected", str(exc)) from exc
            options = {} if transition else dict(transition=False)
            load = backend.compile_load(context.document, resource_name=name,
                archive_name=archive, duration_ms=duration, **options)
            code.extend(load.code)
            if portrait_scene:
                portrait_scene.reset_camera()
            elif camera:
                camera.restore_current()
            references.append(reference)
            if blur:
                blur.background_loaded(event, dict(reference, target_archive=archive, target_resource_name=name))
            if choices:
                choices.background_loaded(dict(target_archive=archive, target_resource_name=name))
            if cg:
                cg.background_loaded(dict(target_archive=archive, target_resource_name=name))
            details = dict(native_background=load.report)
        elif kind == "Transition":
            if camera:
                camera.join()
            if portrait_scene:
                portrait_scene.join()
            if blur:
                blur.join()
            try:
                screen.emit(event)
            except (ValueError, KeyError) as exc:
                raise ExportError("native_screen_transition_event_rejected", str(exc), issues=[dict(
                    level="error", code="native_screen_transition_event_rejected", event_index=index,
                    kind=kind, message=str(exc))]) from exc
            details = dict(target_native_screen_transition=True)
        elif kind == "GuiBackgroundBlur":
            try:
                if camera:
                    camera.join()
                if portrait_scene:
                    portrait_scene.join()
                blur.emit(event)
            except (ValueError, KeyError) as exc:
                raise ExportError("native_background_blur_event_rejected", str(exc), issues=[dict(
                    level="error", code="native_background_blur_event_rejected", event_index=index,
                    kind=kind, message=str(exc))]) from exc
            details = dict(target_native_background_blur=True)
        elif kind == "CameraShot":
            try:
                if event.get("duration_ms") == 0 and (screen is None or screen.covered is None):
                    raise ValueError("直接设置镜头只用于黑／白场遮盖内的布置；可见镜头仍使用运动时长。")
                if blur:
                    blur.join()
                camera.emit(event, portrait_scene.states.values() if portrait_scene else ())
                if blur:
                    blur.reassert()
            except (ValueError, KeyError) as exc:
                raise ExportError("native_camera_event_rejected", str(exc)) from exc
            details = dict(target_native_camera=True)
        elif kind in {"Text", "Speech", "GuiVoiceLine"}:
            if not target.encoding_confirmed and not event["text"].isascii():
                raise ExportError("target_encoding_needed", "输出非 ASCII 台词前，请在本机来源登记中确认 target_encoding；不会猜测日文或汉化版编码。")
            speaker = "narration"
            if kind == "Speech" or kind == 'GuiVoiceLine' and event['speaker_mode'] != 'narration':
                matches = [key for key, value in context.abi.speakers.items()
                           if value.display_name == event["display_name"]]
                if len(matches) != 1:
                    raise ExportError("speaker_not_connected", "当前目标没有唯一对应的原生说话人：" + event["display_name"])
                speaker = matches[0]
            payload, dialogue_report = _compile_inserted_dialogue(context.document,
                context.dialogue_profile, [dict(line_id=event["line_id"],
                    speaker_id=speaker, text=event["text"], voice_id=None)],
                audio.native.voice.dialogue_abi if kind == 'GuiVoiceLine' else context.abi,
                analysis_document=context.analysis_document,
                after_print_bytes=audio.voice_start(event) if kind == 'GuiVoiceLine' else b'')
            if cg:
                payload = cg.dialogue.rewrite(payload)
            elif scene_state is not None:
                payload = scene_state.dialogue.rewrite(payload)
            elif portrait_scene:
                payload = portrait_scene.dialogue.rewrite(payload)
            code.extend(payload)
            if kind == 'GuiVoiceLine':
                code.extend(audio.voice_end())
            lines += 1
            details = dict(native_dialogue=dialogue_report)
        elif kind in AUDIO_KINDS:
            try:
                audio.emit(event)
            except (ValueError, KeyError) as exc:
                raise ExportError('native_audio_event_rejected', str(exc)) from exc
            details = dict(target_native_audio=True)
        elif kind in LOGIC_KINDS:
            if story_bank is None:
                raise ExportError("native_chapter_variables_not_connected", "剧情赋值缺少本章节私有变量表。")
            story_bank.emit_effect({k: v for k, v in event.items() if k != "kind"})
            details = dict(chapter_story_effect=True)
        elif kind == "End":
            if routed_chapter:
                choices.finalize(len(code))
            if portrait_scene:
                portrait_scene.bind_abort_cleanup(len(source)+len(code))
            if sway:
                sway.finish()
            if story_bank:
                story_bank.clear()
            if cg:
                try:
                    cg.finish()
                except (ValueError, KeyError) as exc:
                    raise ExportError("native_cg_end_handoff_rejected", str(exc)) from exc
            if scene_state is not None:
                scene_state.cleanup_owned_threads(reason="before_scene_end_restore")
            if camera:
                camera.finish()
            if portrait_scene:
                portrait_scene.finish()
            if camera:
                code.extend(camera.snapshot["restore"])
            if blur:
                blur.finish()
            if screen:
                screen.finish()
            if scene_state is not None:
                scene_state.finish()
            if audio:
                # Clear the original wrapper's cached IDs AFTER script-state
                # restoration; a restored stale ID must not suppress its next play.
                audio.finish()
            details = dict(allocated_portraits_cleared=bool(portrait_scene),
                allocated_cg_cleared=bool(cg), script_state_restored=bool(portrait_scene or camera or blur or screen))
        else:
            details = {}
            if kind == "Wait" and portrait_scene:
                portrait_scene.join()
                details = dict(target_native_motions_joined=True)
            if kind == "Wait" and camera:
                camera.join()
                details["target_native_camera_joined"] = True
            if kind == "Wait" and blur:
                blur.join()
                details["target_native_background_blur_joined"] = True
            if kind == "Wait" and cg:
                cg.join()
                details["target_native_cg_joined"] = True
        events.append(dict(event_index=index, kind=kind, byte_range=[before, len(code)], **details))
    if not lines:
        raise ExportError("missing_dialogue", "测试场景需要至少一句台词作为可见的停留点。")
    patch = anchor["patch"]
    offset, expected = int(patch["patch_offset"]), bytes.fromhex(patch["expected_hex"])
    replay = bytes.fromhex(patch["replay_hex"])
    replay_start, replay_size = int(patch["replay_offset"]), int(patch["replay_size"])
    if (len(expected) != 5 or source[offset:offset+5] != expected
            or source[replay_start:replay_start+replay_size] != replay):
        raise ExportError("source_changed", "原生台词接入位置发生变化，已停止。")
    if threaded_state:
        # Native continuations belong to the original caller, not the authored
        # scene's own frame. The image assembler emits their entry trampolines.
        code.extend(b"\x04")
    else:
        code.extend(replay)
        if not patch.get("replay_terminal"):
            code.extend(b"\x06" + struct.pack("<I", patch["return_offset"]))
    payload = bytearray(source + bytes(code))
    payload[offset:offset+5] = b"\x06" + struct.pack("<I", len(source))
    restored = bytearray(payload[:len(source)])
    restored[offset:offset+5] = expected
    if bytes(restored) != source:
        raise ExportError("invalid_candidate", "生成意外改变了台词接入点之外的原始脚本。")
    # Reparse only the new code against the exact native syscall table, not the
    # translated overlay tail. Absolute native/new targets must be boundaries.
    table = context.analysis_document.header.sysdesc_offset
    decoded = parse_bytes(struct.pack("<I", 4+len(code)) + bytes(code)
        + context.analysis_document.original_bytes[table:], context.document.encoding)
    boundaries = ({ins.offset for ins in context.analysis_document.instructions}
                  | {ins.offset for ins in context.document.instructions}
                  | {len(source) + ins.offset - 4 for ins in decoded.instructions})
    if decoded.warnings or any(ins.opcode in {2, 6, 7}
            and ins.operands["target"] not in boundaries for ins in decoded.instructions):
        raise ExportError("invalid_candidate", "生成的原生调用或返回位置不完整。")
    target.check_unchanged()
    if graphics_imports is not None:
        graphics_imports.check_unchanged()
    for name, stamp in stamps.items():
        if fingerprint(target.root / name) != stamp:
            raise ExportError("source_changed", "生成期间背景资源发生变化。")
    report = dict(schema=SCHEMA, scope=SCOPE, passed=True, rehearsal_only=True,
        rehearsal_copy_ready=not bool(cg), install_ready=False, production_candidate_accepted=False,
        runtime_verified=False, standalone_startup=False, original_startup_preserved=True,
        target_id=context.target_id, profile_id=context.abi.profile_id,
        script=target.script, analysis_script=target.analysis_script,
        activation=deepcopy(target.activation), encoding=context.document.encoding,
        encoding_confirmed=target.encoding_confirmed, plan_sha256=checksum(program),
        source=dict(hcb_sha256=sha(source)), output=dict(hcb_sha256=sha(payload)),
        original_prefix_unchanged_outside_hook=True, instruction_boundaries_checked=True,
        new_instruction_count=len(decoded.instructions), hook=deepcopy(anchor),
        returns_to_original_story=True, original_visual_state_inherited=True,
        resource_pack_changed=bool(graphics_imports and graphics_imports.payloads),
        resource_references=references, events=events,
        native_background_backend=backend.describe(),
        limitations=["启动后进入原生剧情，在报告指定台词前播放测试场景；并非独立开机直接试演",
                     "结束后接回原生剧情；旧剧情画面重建、音乐和章节交接仍需补齐",
                     "CG 尚未接入此通用输出；整幕黑白转场与换装渐变按目标原生绑定，遮罩转场及未匹配的动作会明确拒绝",
                     "跨游戏背景保留原 HZC 像素并使用目标原生几何默认值；不同画幅的显示仍需实机确认"])
    if portrait_scene:
        report.update(native_portraits=portrait_scene.report(),
                      original_visual_state_inherited=False,
                      known_inherited_portrait_selectors_cleared=True,
                      original_engine_resources_restored=False)
        report["resource_references"].extend(portrait_scene.references)
        report["limitations"].append("结束时清理测试角色并恢复脚本变量，但尚未重建旧剧情的图像资源；只能在新测试副本验收")
    if camera:
        report["native_camera"] = camera.report()
        report.update(original_visual_state_inherited=False, original_engine_resources_restored=False)
        report["limitations"].append("镜头使用目标原生运动和参考景深；尚未实机确认旧剧情接回后的完整画面恢复。")
    if sway:
        report['native_actor_sway'] = sway.report()
    if audio:
        report['native_audio'] = dict(audio.report(), scene_export_connected=True,
            chapter_mainline_connected=True, local_choice_branch_connected=bool(choices))
        report['audio_bindings'] = audio_bindings.report()
        report['resource_pack_changed'] |= bool(audio_bindings.groups)
        report['limitations'].append('声音只执行选中路线；配音使用目标原生人声槽和台词等待，进入下一句即停止。回看重播配音、原剧情音频播放位置恢复尚未接入。')
    if choices:
        report["native_chapter_routes" if routed_chapter else "native_choices"] = choices.report()
        report["limitations"].append(
            "场内和场景末尾选项仅播放选中路线；跳转前按出口转场清场。剧情变量跨场景保留，尚未实机确认存读档与回溯。"
            if routed_chapter else
            "选项分支可换背景、原生换身体、角色进退场和嵌套选项；嵌套选项接回所在分支，公共汇合时素材、角色、模糊和镜头须一致。")
    if story_bank:
        report["native_story_variables"] = story_bank.report()
    if blur:
        report["native_background_blur"] = blur.report()
        report["resource_references"].extend(blur.references)
        report.update(original_visual_state_inherited=False, original_engine_resources_restored=False)
        report["limitations"].append("背景模糊使用来源原作的配对图和目标原生透明度渐变；不生成模糊图，原剧情图像重建尚未接完。")
    if screen:
        report["native_screen_transition"] = screen.report()
        report.update(original_visual_state_inherited=False, original_engine_resources_restored=False)
        report["limitations"].append("黑白转场保留目标原生快进／时长设置，不改角色和镜头；结束时移除测试场景色场，不代表旧剧情图像已重建。")
    if cg:
        report.update(memory_only=True, native_cg=cg.report(),
            original_visual_state_inherited=False, original_engine_resources_restored=False)
        report["resource_references"].extend(cg.references)
        report["resource_pack_changed"] = bool(cg.imports.payloads or audio and audio_bindings.groups)
        report["limitations"].append("CG 已串接内存场景编译；公共 GUI 输出尚未接通，纯内存候选不能单独写入游戏。")
    if _cg_threaded_memory_only:
        try:
            payload,thread_image = cg.prepare_threaded_scene_image(bytes(payload),anchor,
                _defer_preserved_source_cycles=_cg_native_state_bridge_out is not None)
        except (ValueError,KeyError) as exc:
            raise ExportError("native_cg_thread_image_rejected",str(exc)) from exc
        report.update(native_cg=cg.report(),native_cg_thread_image=thread_image,
            output=dict(hcb_sha256=sha(payload)),new_instruction_count=thread_image["new_instruction_count"],
            original_prefix_unchanged_outside_hook=False,
            original_prefix_unchanged_outside_declared_thread_handoff=True,
            original_thread_start_pointers_changed_in_memory=thread_image["original_start_patches_applied_in_memory"],
            original_global_ids_unchanged=True)
        report["limitations"].append("线程交接已装配到私有内存映像；整游戏的线程调度与画面恢复仍待实机确认。")
        if thread_image['native_stack_usage'].get('preserved_original_cycles_deferred'):
            report['limitations'].append('保留了原作已有的菜单循环，尚未求出其最大栈深度；仅生成隔离测试副本，不能视为实机通过。')
        if _cg_native_state_bridge_out is not None:
            from .native_cg_state_bridge import build_state_bridge,link_state_bridge
            try:
                bridge=build_state_bridge((target.root/target.executable).read_bytes(),
                    cg.group_ancestry.native_groups.report(),
                    cg.presentation.motion_quiescence.native_binding.report(),
                    thread_image['native_vm_syscall_catalogue'],
                    original_volatile_globals=context.analysis_document.header.volatile_globals)
                payload,bridge_report=link_state_bridge(payload,thread_image,bridge,
                    encoding=context.document.encoding)
            except (ValueError,KeyError) as exc:
                raise ExportError('native_cg_state_bridge_rejected',str(exc)) from exc
            _cg_native_state_bridge_out.update(executable=bridge.executable,report=bridge_report)
            report.update(native_cg_state_bridge=bridge_report,output=dict(hcb_sha256=sha(payload)))
    if scene_state is not None:
        try:
            payload, thread_image = scene_state.prepare_threaded_scene_image(bytes(payload), anchor,
                _defer_preserved_source_cycles=True)
            payload, bridge = scene_state.build_bridge(payload, thread_image)
        except (ValueError, KeyError) as exc:
            raise ExportError("native_scene_state_bridge_rejected", str(exc)) from exc
        _scene_native_state_bridge_out.update(bridge)
        report.update(native_scene_state=scene_state.report(), native_scene_thread_image=thread_image,
            native_scene_state_bridge=bridge['report'],
            output=dict(hcb_sha256=sha(payload)), new_instruction_count=thread_image['new_instruction_count'],
            original_prefix_unchanged_outside_hook=False,
            original_prefix_unchanged_outside_declared_thread_handoff=True,
            original_thread_start_pointers_changed_in_memory=thread_image['original_start_patches_applied_in_memory'],
            original_global_ids_unchanged=True, original_engine_resources_restored=False,
            original_scene_native_restore_connected=True, requires_matching_new_test_executable=True)
        report['native_scene_state']['scene_export_connected'] = True
        report['limitations'].append("普通场景已接入配套测试程序的原剧情资源、动画与镜头恢复；尚未实机验收，不代表原剧情画面已确认恢复。")
    if chapter is not None:
        report["limitations"] = [s for s in report["limitations"]
            if s != "结束后接回原生剧情；旧剧情画面重建、音乐和章节交接仍需补齐"]
        report["limitations"].append("章节按来源场景的出口转场衔接（旧工程默认黑场 800ms）；变量、条件和循环路线已接编译，声音仍未接入。")
        report["native_chapter"] = dict(chapter, one_native_state_capture=True,
            original_story_resumed_only_after_final_scene=True, standalone_startup=False,
            cross_chapter_explicit_jumps=True, branches_supported=bool(routed_chapter),
            source_exit_transitions=bool(routed_chapter and choices.subroutine_entries),
            scene_exit_choices_supported=True, local_beat_choices_supported=True,
            variables_supported=True, conditional_routes_supported=True, loops_supported=True,
            cg_supported=True, cg_used=bool(cg), runtime_verified=False)
    return bytes(payload), report, stamps


@dataclass(frozen=True)
class BuiltScene:
    folder: Path
    payload: bytes
    report: dict
    target: BoundTarget
    resources: object
    issues: list
    archive_files: dict = field(default_factory=dict)
    native_executable: bytes | None = None


def bind_cg_sources(runtime, target, events):
    """Bind selected CG assets to their registered source, not a display name.

    Older intermediate programs used names; their archive root disambiguates
    them. Every foreign source retains its OWN native resource-family binding.
    """
    bound = {}
    for event in events:
        if event["kind"] != "GuiCGLoad":
            continue
        key, root = event["source_game"], Path(event["archive"]).resolve().parent
        source = runtime.sources.get(key)
        if source is None:
            matches = [s for s in runtime.sources.values() if s.name == key and s.root == root]
            if len(matches) != 1:
                raise ExportError("cg_source_unavailable", "CG 来源游戏未登记或无法确定，请重新选择素材。")
            source = matches[0]
        if source.root != root:
            raise ExportError("cg_source_mismatch", "CG 素材不属于选择的来源游戏，请重新选择素材。")
        if key not in bound:
            bound[key] = target if root == target.root else bind_target(source)
    return bound


class NativeSceneExporter:
    """The GUI's explicit new-copy endpoint, not a production install gate."""
    requires_paired_scene_state = False
    extra_event_kinds = frozenset()

    def __init__(self, runtime, output_root, *, test_parent=TEST_PARENT):
        self.runtime = runtime
        self.output_root, self.test_parent = _safe(Path(output_root)), _safe(Path(test_parent))
        for source in runtime.sources.values():
            root = _safe(source.root)
            for destination in (self.output_root, self.test_parent):
                if destination == root or root in destination.parents or destination in root.parents:
                    raise ExportError("unsafe_target", "输出位置不能与已登记的游戏来源重叠。")

    def make_builder(self, request, *, native_rotation_converter):
        project = request["document"]["project"]
        return SceneBuilder(self.runtime, project, project["scenes"][request["scene_id"]],
            native_export_target=True, native_rotation_converter=native_rotation_converter)

    def build(self, request, update, *, _cg_native_state_candidate=None, _scene_native_state_candidate=None):
        if _cg_native_state_candidate is not None and type(_cg_native_state_candidate) is not bool:
            raise ExportError("invalid_cg_compile_mode", "CG 测试副本须由本机明确选择。")
        if _scene_native_state_candidate is not None and type(_scene_native_state_candidate) is not bool:
            raise ExportError("invalid_scene_state_mode", "普通场景测试副本须由本机明确选择。")
        project = request["document"]["project"]
        scene = project["scenes"][request["scene_id"]]
        # Reject unconnected semantics before expensive size/resource work.
        issues = []
        bound = {}
        def rotation_converter(degrees):
            # Binding is lazy: an unsupported scene without tilt is rejected
            # before costly discovery. Use the request's exact local target
            # selection, then reuse that SAME target for the final compiler.
            if "target" not in bound:
                bound["target"] = bind_target(source_for_request(self.runtime, request))
            if "rotation" not in bound:
                bound["rotation"] = NativeRotationDegrees(bound["target"])
            return bound["rotation"](degrees)
        builder = self.make_builder(request, native_rotation_converter=rotation_converter)
        if not issues:
            program = builder.translate()
            issues = [i for i in builder.issues if i["level"] == "error"]
            if not issues:
                if _cg_native_state_candidate is None:
                    _cg_native_state_candidate = any(e["kind"] in CG_KINDS for e in program["events"])
                for index, event in enumerate(program["events"]):
                    if event["kind"] not in FEATURES | self.extra_event_kinds | (CG_EXPORT_KINDS if _cg_native_state_candidate else set()):
                        where = next((m for m in builder.mapping if index in m["event_indexes"]), {})
                        issues.append(dict(level="error", scene_id=scene["id"],
                            **{k:v for k,v in where.items() if k not in {"scene_id", "event_indexes"}},
                            code="generic_feature_not_connected",
                            message=f"当前目标的 {event['kind']} 输出尚未接通，不能省略后生成。"))
        if issues:
            raise ExportError("scene_needs_changes", "当前场景有内容尚不能输出到该游戏。", issues=issues)
        source = source_for_request(self.runtime, request)
        update("compiling", "正在按目标游戏的原生调用生成场景…")
        target = bound.get("target") or bind_target(source)
        anchor = select_hook(target.context, getattr(source, "target_hook_offset", None))
        builder.resources.check_unchanged()
        backend = target.context.abi.native_background_backend
        portrait_record = target.discovery.get("profile_seed", {}).get("native_symbols", {}).get("portrait_dispatcher")
        portrait_routes = ({portrait_record["resource_namespace"].rstrip("/\\").casefold() + ".bin": None}
                           if portrait_record else {})
        import_routes={
            "background": backend.archive_selectors if backend is not None else {},
            "portrait": portrait_routes}
        native_state, cg_sources = None, None
        if _cg_native_state_candidate:
            if not any(event["kind"] in CG_KINDS for event in program["events"]):
                raise ExportError("invalid_cg_compile_mode", "原生 CG 状态副本需要实际的 CG 场景。")
            from .native_cg_backend import NativeCGBackend
            cg_backend=NativeCGBackend(target.context)
            import_routes["event_visual"]=dict(cg_backend.archive_selectors)
            cg_sources = bind_cg_sources(self.runtime, target, program["events"])
            native_state={}
        scene_state, restore_pending = None, None
        visual_kinds = PORTRAIT_KINDS | AUDIO_KINDS | {"Background", "GuiBackgroundChange", "GuiBackgroundBlur", "CameraShot", "Transition"}
        ordinary_state_requested = (_scene_native_state_candidate is True or
            _scene_native_state_candidate is None and isinstance(target, BoundTarget)
            and any(e['kind'] in visual_kinds for e in program['events']))
        if not _cg_native_state_candidate and ordinary_state_requested:
            from .native_scene_state import NativeSceneState
            try:
                scene_state = NativeSceneState(target)
                native_state = {}
            except (ValueError, KeyError) as exc:
                restore_pending = str(exc)
        if self.requires_paired_scene_state and scene_state is None and not _cg_native_state_candidate:
            raise ExportError("native_chapter_state_required", "此目标尚不能完整接通章节的原生状态保存／恢复。" + (restore_pending or ""))
        imports=NativeGraphicsImports(target.root,import_routes)
        audio_bindings = None
        if any(e['kind'] in AUDIO_KINDS for e in program['events']):
            try:
                audio_bindings = NativeAudioBindings(target, NativeAudioBackend(target.context), builder.resources)
            except (ValueError, KeyError) as exc:
                raise ExportError('native_audio_not_connected', str(exc)) from exc
        resources = NativeExportResources(builder.resources, imports)
        compile_options = (dict(_cg_memory_only=True,_cg_threaded_memory_only=True,
                    _cg_original_graph_journal=True,_cg_native_state_bridge_out=native_state,
                    cg_source_targets=cg_sources)
            if _cg_native_state_candidate else
            dict(_scene_state_binding=scene_state, _scene_native_state_bridge_out=native_state)
            if scene_state is not None else {})
        try:
            payload, report, resource_stamps = compile_scene(target, program, anchor, graphics_imports=imports,
                audio_bindings=audio_bindings, rotation_contract=bound.get("rotation"), **compile_options)
        except ExportError as exc:
            if scene_state is None or self.requires_paired_scene_state or audio_bindings is not None:
                raise
            # This is an optional restoration enhancement, not an authored
            # scene feature. Unsupported native state layouts retain the SAME
            # event stream and the existing explicit restoration limitation.
            # No game/candidate has been written; this is one in-memory fallback.
            restore_pending = str(exc)
            scene_state = native_state = None
            payload, report, resource_stamps = compile_scene(target, program, anchor, graphics_imports=imports,
                rotation_contract=bound.get("rotation"))
        if native_state is not None:
            report.update(memory_only=False, rehearsal_copy_ready=True,
                native_state_test_copy_candidate=True)
            if _cg_native_state_candidate:
                report['cg_export_mode'] = "target_native_calls_matched_executable_new_copy"
                report["native_cg"].update(scene_export_connected=True,
                    public_export_requires_remaining_native_owners=False,
                    matching_test_executable_required=True)
                report["limitations"] = [message for message in report["limitations"]
                    if not message.startswith("CG 尚未接入此通用输出")]
                report["limitations"].append("CG 加载、差分、构图运动和退场已接入；与其他动作的同时演出仍受目标原生组合能力限制。")
                for source_target in cg_sources.values():
                    source_target.check_unchanged()
            else:
                report['scene_state_export_mode'] = "ordinary_scene_matched_executable_new_copy"
        if restore_pending is not None:
            report['native_scene_restore_pending'] = dict(reason=restore_pending,
                authored_events_unchanged=True, original_visual_restore_connected=False)
        if "rotation" in bound:
            report["rotation_degrees"] = dict(binding=bound["rotation"].report(),
                conversions=deepcopy(builder.rotation_conversions),scene_export_connected=True,
                runtime_verified=False)
        target.stamps.update(resource_stamps)
        report.update(scene_id=scene["id"], scene_sha256=checksum(scene),
            document_sha256=checksum(request["document"]), mapping=deepcopy(builder.mapping),
            source_id=source.id, created_at=now())
        target.check_unchanged()
        resources.check_unchanged()
        folder = self.output_root / ("native-scene-" + report["plan_sha256"][:12] + "-" + secrets.token_hex(8))
        folder.mkdir(exist_ok=False)
        update("publishing", "正在保存场景文件…", output=dict(candidate_directory=str(folder)))
        try:
            archive_files, archive_sources, archive_outputs = imports.publish(folder)
            archive_reports = dict(imports.reports)
            if audio_bindings is not None:
                if set(audio_bindings.groups) & set(archive_files):
                    raise ValueError('声音与图像不能同时替换同一素材包。')
                sound_files, sound_sources, sound_outputs, sound_reports = audio_bindings.publish(folder, self.runtime.audio)
                archive_files.update(sound_files)
                archive_sources.update(sound_sources)
                archive_outputs.update({name:{k:v[k] for k in ('size','sha256')}
                    for name,v in sound_outputs.items()})
                archive_reports.update(sound_reports)
                report['audio_bindings'] = dict(audio_bindings.report(), scene_export_connected=True)
        except ValueError as exc:
            raise ExportError("resource_pack_failed", str(exc)) from exc
        report.update(resource_archives=dict(sources=archive_sources, outputs=archive_outputs,
                                            reports=archive_reports))
        target.check_unchanged()
        resources.check_unchanged()
        with (folder / "candidate.hcb").open("xb") as stream:
            stream.write(payload)
        if native_state is not None:
            with (folder / "candidate.exe").open("xb") as stream:
                stream.write(native_state["executable"])
            report["native_state_test_copy_candidate"]=True
        for name, value in (("project.json", request["document"]), ("request.json", request),
                            ("program.json", program), ("report.json", report)):
            with (folder / name).open("x", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        warnings = [i for i in builder.issues if i["level"] in {"warn", "warning"}]
        warnings.append(dict(level="warn", code="native_story_hook_rehearsal", scene_id=scene["id"],
            message="当前是原生剧情接入测试副本，不是独立开机试演；到指定台词播放，结束后接回原剧情。"))
        if report.get("original_scene_native_restore_connected"):
            warnings.append(dict(level="warn", code="native_story_visual_restore_runtime_pending", scene_id=scene['id'],
                message="结束后恢复原剧情画面的后端已接入，实机效果仍待验收；只用于新测试副本。"))
        elif report.get("native_portraits") or restore_pending is not None:
            warnings.append(dict(level="warn", code="native_story_visual_restore_pending", scene_id=scene["id"],
                message="旧剧情画面尚不能完整恢复；请只在新副本验收当前场景。"))
        if audio_bindings is not None:
            warnings.append(dict(level='warn',code='native_story_audio_restore_pending',scene_id=scene['id'],
                message='声音只在新测试副本验收；结束时清理本次使用的声音类型，尚不恢复原剧情声音和播放位置。'))
            if report.get('native_audio',{}).get('voice_connected'):
                warnings.append(dict(level='warn',code='native_voice_backlog_pending',scene_id=scene['id'],
                    message='配音随台词播放，切到下一句即停止；回看中的配音重播尚未接入。'))
        return BuiltScene(folder, payload, report, target, resources, warnings, archive_files,
                          native_state["executable"] if native_state is not None else None)

    def install(self, built, update, *, _cg_native_state_candidate=None):
        if _cg_native_state_candidate is None:
            _cg_native_state_candidate = built.report.get("native_state_test_copy_candidate") is True
        if type(_cg_native_state_candidate) is not bool:
            raise ExportError("invalid_cg_compile_mode", "CG 测试副本须由本机明确选择。")
        bridge=built.report.get("native_scene_state_bridge") or built.report.get("native_cg_state_bridge",{})
        paired_state=(_cg_native_state_candidate and bridge.get("script_linked") is True
            and bridge.get("new_test_copy_only") is True
            and bridge.get("animated_parts_clock_snapshot") is True
            and bridge.get("camera_native_state_snapshot") is True
            and bridge.get("requires_matching_new_test_executable") is True
            and isinstance(built.native_executable,bytes))
        if bridge and not paired_state:
            raise ExportError("missing_native_state_pair", "必须同时提供本次生成的原生接口程序和脚本。")
        if not paired_state and (built.report.get("memory_only") or (built.report.get("native_cg")
                and built.report["native_cg"].get("scene_export_connected") is not True)):
            raise ExportError("memory_only_candidate", "CG 内存编译结果尚不能发布或写入测试游戏。")
        if _cg_native_state_candidate and not paired_state:
            raise ExportError("missing_native_state_pair", "必须同时提供本次生成的原生接口程序和脚本。")
        root, folder = built.target.root, _safe(built.folder)
        _safe(self.test_parent)
        target = new_target(self.test_parent / ("FVP_Native_Run_" + built.target.context.target_id[:12]
            + "_" + secrets.token_hex(8)), root, self.test_parent)
        if sha((folder / "candidate.hcb").read_bytes()) != built.report["output"]["hcb_sha256"]:
            raise ExportError("candidate_changed", "保存的场景文件发生变化，已停止复制。")
        if paired_state and (
                bridge["source_executable_sha256"] != built.target.executable_sha256
                or bridge["output_executable_sha256"] != sha(built.native_executable)
                or bridge["output_script_sha256"] != sha(built.payload)
                or _file_identity(folder/"candidate.exe") != dict(
                    size=len(built.native_executable),sha256=bridge["output_executable_sha256"])):
            raise ExportError("candidate_changed", "原生状态程序与这次场景脚本不配套，已停止复制。")
        archives = built.report.get("resource_archives", {})
        archive_sources, archive_outputs = archives.get("sources", {}), archives.get("outputs", {})
        if set(built.archive_files) != set(archive_sources) or set(built.archive_files) != set(archive_outputs):
            raise ExportError("candidate_changed", "生成的素材包清单不完整。")
        for name, path in built.archive_files.items():
            _filename(name, {".bin"})
            if Path(path).resolve() != (folder / name).resolve() or _file_identity(path) != archive_outputs[name]:
                raise ExportError("candidate_changed", "保存的素材包与生成结果不一致。")
        built.target.check_unchanged()
        built.resources.check_unchanged()
        robocopy = _robocopy_executable()
        import psutil
        original = inventory(root, False)
        stamps = {name: fingerprint(root / name) for name in original}
        if (original[built.target.script]["sha256"] != built.report["source"]["hcb_sha256"]
                or original[built.target.executable]["sha256"] != built.target.executable_sha256):
            raise ExportError("source_changed", "复制前目标游戏脚本或启动程序发生变化。")
        if any(original.get(name) != expected for name, expected in archive_sources.items()):
            raise ExportError("source_changed", "目标素材包不是此次生成所依据的原包。")

        def protect():
            files = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}
            if files != set(original) or any(fingerprint(_safe(root / name,
                    file=True, independent=False)) != stamp for name, stamp in stamps.items()):
                raise ExportError("source_changed", "复制期间原作发生变化；保留新副本，没有修改原作。")
            built.target.check_unchanged()
            built.resources.check_unchanged()

        required = (sum(v["size"] for v in original.values()) + len(built.payload)*2
                    + (len(built.native_executable)*2 if paired_state else 0)
                    + sum(v["size"] + archive_sources[n]["size"] for n, v in archive_outputs.items())
                    + 512*1024**2)
        if shutil.disk_usage(self.test_parent).free < required:
            raise ExportError("disk_full", "测试盘空间不足，已保留生成文件。")
        protect()
        new_target(target, root, self.test_parent)
        target.mkdir(exist_ok=False)
        _safe(target)
        partial = dict(candidate_directory=str(folder), test_directory=str(target))
        update("copying", "正在创建新的游戏测试副本，原作不修改…", output=partial)
        result = subprocess.run([robocopy, str(root), str(target), "/E", "/COPY:DAT", "/DCOPY:DAT", "/XJ",
            "/R:1", "/W:1", "/NFL", "/NDL", "/NP", "/NJH", "/NJS"], capture_output=True)
        if result.returncode >= 8:
            raise ExportError("copy_failed", "复制未完成；已保留新目录，没有写入原作。")
        update("checking_copy", "正在确认测试副本文件…")
        _safe(target)
        copied = inventory(target, True)
        if copied != original:
            raise ExportError("copy_changed", "测试副本复制不完整，没有安装场景；目录已保留。")
        protect()
        for process in psutil.process_iter(["exe"]):
            try:
                exe = process.info.get("exe")
                if exe and target in Path(exe).resolve().parents:
                    raise ExportError("game_running", "新副本正在运行，已停止写入。")
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied as exc:
                raise ExportError("process_unknown", "无法确认新副本运行状态，已停止写入。") from exc
        destination = _safe(target / built.target.script, file=True)
        original_script = destination.read_bytes()
        if sha(original_script) != built.report["source"]["hcb_sha256"]:
            raise ExportError("copy_changed", "新副本中的脚本发生变化，已停止写入。")
        # Prepare and verify every replacement before changing anything.
        # Additive BINs and the matching native EXE commit before the referring
        # HCB, which commits LAST. If a
        # later step fails, this copy retains complete original-file backups.
        replacements = []
        staged_inventory = dict(original)
        for name in [*sorted(built.archive_files),
                     *([built.target.executable] if paired_state else []),built.target.script]:
            destination = _safe(target / name, file=True)
            # Some FVP engines load the first FindFirstFile("*.hcb") result.
            # A leading dot does not hide a backup from that wildcard: keep
            # backups out of every native script/archive/executable suffix.
            backup = target / (".fvp-original-" + name + ".bak")
            staged = target / (".fvp-new-" + secrets.token_hex(8))
            generated=(built.payload if name==built.target.script else
                       built.native_executable if paired_state and name==built.target.executable else None)
            output_identity = (dict(size=len(generated), sha256=sha(generated))
                               if generated is not None else archive_outputs[name])
            with destination.open("rb") as incoming, backup.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            if _file_identity(backup) != original[name]:
                raise ExportError("copy_changed", "新副本的原文件备份不完整，已停止安装。")
            with staged.open("xb") as stream:
                if generated is not None:
                    stream.write(generated)
                else:
                    with _safe(Path(built.archive_files[name]), file=True).open("rb") as incoming:
                        shutil.copyfileobj(incoming, stream, 1024 * 1024)
            if _file_identity(staged) != output_identity:
                raise ExportError("candidate_changed", "安装暂存文件与生成结果不一致。")
            staged_inventory[backup.name], staged_inventory[staged.name] = original[name], output_identity
            replacements.append((name, destination, backup, staged, output_identity))
        script_backup = next(row[2] for row in replacements if row[0] == built.target.script)
        record = dict(schema=SCHEMA, scope=SCOPE, status="prepared", source_root=str(root),
            target_root=str(target), candidate_directory=str(folder), script=built.target.script,
            executable=built.target.executable, project_file=str(folder / "project.json"),
            scene_id=built.report["scene_id"], document_sha256=built.report["document_sha256"],
            original_unchanged=True, runtime_verified=False, standalone_startup=False,
            copy_file_count=len(copied), copy_all_sha256_equal=True, copy_all_files_single_link=True,
            source_script_sha256=sha(original_script), output_script_sha256=sha(built.payload),
            original_script_backup=str(script_backup), hook=built.report["hook"]["dialogue"],
            resource_archives=deepcopy(archives),
            original_file_backups={name: str(backup) for name, _, backup, _, _ in replacements})
        original_story_restore = dict(mode="native_state_pair" if paired_state else "legacy_restore_pending",
            connected=paired_state, runtime_verified=False, matching_test_executable_required=paired_state)
        record['original_story_restore'] = original_story_restore
        if paired_state:
            record.update(native_state_bridge=deepcopy(bridge),native_state_test_copy=True,
                original_executable_backup=str(next(row[2] for row in replacements
                                                   if row[0]==built.target.executable)))
        with (folder / "copy-install-prepared.json").open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
        protect()
        if inventory(target, True) != staged_inventory:
            raise ExportError("copy_changed", "安装前新副本发生变化，备份和生成文件已保留。")
        update("installing", "正在把场景放入新副本…", output=partial)
        expected = dict(staged_inventory)
        for name, destination, backup, staged, identity in replacements:
            protect()
            if _file_identity(destination) != original[name] or _file_identity(staged) != identity:
                raise ExportError("copy_changed", "安装期间新副本文件发生变化，已保留备份。")
            os.chmod(destination, destination.stat().st_mode | stat.S_IWRITE)
            os.replace(staged, destination)
            expected.pop(staged.name)
            expected[name] = identity
        protect()
        if inventory(target, True) != expected:
            raise ExportError("install_failed", "副本安装结果不一致；原始脚本备份已保留。")
        record["status"] = "installed_not_launched"
        record["installed_files_verified"] = True
        with (folder / "installation.json").open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
        return dict(test_directory=str(target), candidate_directory=str(folder),
            project_file=str(folder / "project.json"), game_executable=str(target / built.target.executable),
            original_unchanged=True, runtime_verified=False, scope=SCOPE, standalone_startup=False,
            native_hook=record["hook"], original_script_backup=str(script_backup),
            resource_archives=list(built.archive_files),
            **(dict(native_state_test_copy=True,
                    original_executable_backup=record["original_executable_backup"])
               if paired_state else {}), original_story_restore=original_story_restore)

    def run(self, request, update):
        built = self.build(request, update)
        return self.install(built, update), built.issues
