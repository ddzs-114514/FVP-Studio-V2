"""Portable current-scene rehearsal, installed only in a brand-new copy.

Keep the production write gate and the Hoshi independent-startup exporter
unchanged. This generic route attaches a linear background/dialogue/portrait
scene at an exact native dialogue boundary, preserves native startup and
returns to the original story. It is not a whole-chapter or standalone engine
adapter. No browser-supplied function addresses, paths or encoding are used.
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
from .gui_runtime import fingerprint
from .gui_scene_export import ExportError, new_target, now, TARGET_ENCODINGS
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
from .native_vm_backend import _binary_script_evidence
from .performance_compile import sha
from .performance_install import TEST_PARENT, _robocopy_executable, _safe, inventory

SCHEMA = "fvp-gui-native-scene-export/1"
SCOPE = "native_dialogue_hook_new_test_copy"
FEATURES = {"Scene", "Background", "GuiBackgroundChange", "Text", "Speech", "Wait", "End"} | PORTRAIT_KINDS


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
    """Freeze an explicit code page for this output, not the registry/project.

    File paths, script/executable choice and hook authority remain local-only.
    The actual native adapter is rebound with this encoding before generation.
    """
    source = runtime._source(request["document"]["project"]["source"])
    if "target_encoding" not in request:
        return source
    value = request["target_encoding"]
    if source.id == "hoshi" or type(value) is not str or value not in TARGET_ENCODINGS:
        raise ExportError("invalid_target_encoding", "输出游戏的文字编码选择不正确。")
    return replace(source, target_encoding=normalize_encoding(value))


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


def compile_scene(target, program, anchor, *, graphics_imports=None, motion_contract=None):
    """Emit target-exact scene calls and one audited original dialogue hook."""
    context = target.context
    backend = context.abi.native_background_backend
    if backend is None:
        raise ExportError("background_not_supported", "此版本的原生背景加载尚未接通。")
    if graphics_imports is not None and (graphics_imports.root != target.root
            or graphics_imports.routes.get("background") != dict(backend.archive_selectors)):
        raise ExportError("invalid_resource_route", "素材打包器不属于当前目标的原生路由。")
    source = context.document.original_bytes
    code, events, references, stamps = bytearray(), [], [], {}
    portrait_scene = None
    if any(e["kind"] in PORTRAIT_KINDS for e in program["events"]):
        try:
            portrait_scene = NativePortraitScene(target, program["events"], anchor,
                                                 graphics_imports, code, motion_contract=motion_contract)
        except (ValueError, KeyError) as exc:
            raise ExportError("native_portraits_not_connected", str(exc)) from exc
    lines = 0
    for index, event in enumerate(program["events"]):
        kind, before = event["kind"], len(code)
        if kind not in FEATURES:
            raise ExportError("generic_feature_not_connected", f"其他游戏的 {kind} 输出尚未接通，场景不会被删减输出。")
        if kind in PORTRAIT_KINDS:
            try:
                portrait_scene.emit(event)
            except (ValueError, KeyError) as exc:
                raise ExportError("native_portrait_event_rejected", str(exc), issues=[dict(
                    level="error", code="native_portrait_event_rejected", event_index=index,
                    kind=kind, message=str(exc))]) from exc
            details = dict(target_native_portrait=True)
        elif kind in {"Background", "GuiBackgroundChange"}:
            if portrait_scene:
                portrait_scene.join()
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
            load = backend.compile_load(context.document, resource_name=name,
                archive_name=archive, duration_ms=event.get("duration_ms", 0))
            code.extend(load.code)
            if portrait_scene:
                portrait_scene.reset_camera()
            references.append(reference)
            details = dict(native_background=load.report)
        elif kind in {"Text", "Speech"}:
            if not target.encoding_confirmed and not event["text"].isascii():
                raise ExportError("target_encoding_needed", "输出非 ASCII 台词前，请在本机来源登记中确认 target_encoding；不会猜测日文或汉化版编码。")
            speaker = "narration"
            if kind == "Speech":
                matches = [key for key, value in context.abi.speakers.items()
                           if value.display_name == event["display_name"]]
                if len(matches) != 1:
                    raise ExportError("speaker_not_connected", "当前目标没有唯一对应的原生说话人：" + event["display_name"])
                speaker = matches[0]
            payload, dialogue_report = _compile_inserted_dialogue(context.document,
                context.dialogue_profile, [dict(line_id=event["line_id"],
                    speaker_id=speaker, text=event["text"], voice_id=None)], context.abi,
                analysis_document=context.analysis_document)
            if portrait_scene:
                payload = portrait_scene.dialogue.rewrite(payload)
            code.extend(payload)
            lines += 1
            details = dict(native_dialogue=dialogue_report)
        elif kind == "End" and portrait_scene:
            portrait_scene.finish()
            details = dict(allocated_portraits_cleared=True, script_state_restored=True)
        else:
            details = {}
            if kind == "Wait" and portrait_scene:
                portrait_scene.join()
                details = dict(target_native_motions_joined=True)
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
        rehearsal_copy_ready=True, install_ready=False, production_candidate_accepted=False,
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
                     "CG、整幕黑白转场、选项尚未接入此通用输出；换装渐变及未匹配的动作会明确拒绝",
                     "跨游戏背景保留原 HZC 像素并使用目标原生几何默认值；不同画幅的显示仍需实机确认"])
    if portrait_scene:
        report.update(native_portraits=portrait_scene.report(),
                      original_visual_state_inherited=False,
                      known_inherited_portrait_selectors_cleared=True,
                      original_engine_resources_restored=False)
        report["resource_references"].extend(portrait_scene.references)
        report["limitations"].append("结束时清理测试角色并恢复脚本变量，但尚未重建旧剧情的图像资源；只能在新测试副本验收")
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


class NativeSceneExporter:
    """The GUI's explicit new-copy endpoint, not a production install gate."""
    def __init__(self, runtime, output_root, *, test_parent=TEST_PARENT):
        self.runtime = runtime
        self.output_root, self.test_parent = _safe(Path(output_root)), _safe(Path(test_parent))
        for source in runtime.sources.values():
            root = _safe(source.root)
            for destination in (self.output_root, self.test_parent):
                if destination == root or root in destination.parents or destination in root.parents:
                    raise ExportError("unsafe_target", "输出位置不能与已登记的游戏来源重叠。")

    def build(self, request, update):
        project = request["document"]["project"]
        scene = project["scenes"][request["scene_id"]]
        # Reject unconnected semantics before expensive size/resource work.
        issues = []
        builder = SceneBuilder(self.runtime, project, scene, native_export_target=True)
        if not issues:
            program = builder.translate()
            issues = [i for i in builder.issues if i["level"] == "error"]
            if not issues:
                for index, event in enumerate(program["events"]):
                    if event["kind"] not in FEATURES:
                        where = next((m for m in builder.mapping if index in m["event_indexes"]), {})
                        issues.append(dict(level="error", scene_id=scene["id"],
                            **{k:v for k,v in where.items() if k not in {"scene_id", "event_indexes"}},
                            code="generic_feature_not_connected",
                            message=f"当前目标的 {event['kind']} 输出尚未接通，不能省略后生成。"))
        if issues:
            raise ExportError("scene_needs_changes", "当前场景有内容尚不能输出到该游戏。", issues=issues)
        source = source_for_request(self.runtime, request)
        update("compiling", "正在按目标游戏的原生调用生成场景…")
        target = bind_target(source)
        anchor = select_hook(target.context, getattr(source, "target_hook_offset", None))
        builder.resources.check_unchanged()
        backend = target.context.abi.native_background_backend
        portrait_record = target.discovery.get("profile_seed", {}).get("native_symbols", {}).get("portrait_dispatcher")
        portrait_routes = ({portrait_record["resource_namespace"].rstrip("/\\").casefold() + ".bin": None}
                           if portrait_record else {})
        imports = NativeGraphicsImports(target.root, {
            "background": backend.archive_selectors if backend is not None else {},
            "portrait": portrait_routes})
        resources = NativeExportResources(builder.resources, imports)
        payload, report, resource_stamps = compile_scene(target, program, anchor, graphics_imports=imports)
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
        except ValueError as exc:
            raise ExportError("resource_pack_failed", str(exc)) from exc
        report.update(resource_archives=dict(sources=archive_sources, outputs=archive_outputs,
                                            reports=imports.reports))
        target.check_unchanged()
        resources.check_unchanged()
        with (folder / "candidate.hcb").open("xb") as stream:
            stream.write(payload)
        for name, value in (("project.json", request["document"]), ("request.json", request),
                            ("program.json", program), ("report.json", report)):
            with (folder / name).open("x", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        warnings = [i for i in builder.issues if i["level"] in {"warn", "warning"}]
        warnings.append(dict(level="warn", code="native_story_hook_rehearsal", scene_id=scene["id"],
            message="当前是原生剧情接入测试副本，不是独立开机试演；到指定台词播放，结束后接回原剧情。"))
        if report.get("native_portraits"):
            warnings.append(dict(level="warn", code="native_story_visual_restore_pending", scene_id=scene["id"],
                message="测试角色会清理；旧剧情角色画面尚不能完整恢复，请只在新副本验收当前场景。"))
        return BuiltScene(folder, payload, report, target, resources, warnings, archive_files)

    def install(self, built, update):
        root, folder = built.target.root, _safe(built.folder)
        _safe(self.test_parent)
        target = new_target(self.test_parent / ("FVP_Native_Run_" + built.target.context.target_id[:12]
            + "_" + secrets.token_hex(8)), root, self.test_parent)
        if sha((folder / "candidate.hcb").read_bytes()) != built.report["output"]["hcb_sha256"]:
            raise ExportError("candidate_changed", "保存的场景文件发生变化，已停止复制。")
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
        # Additive BINs commit first and the referring HCB commits LAST. If a
        # later step fails, this copy retains complete original-file backups.
        replacements = []
        staged_inventory = dict(original)
        for name in [*sorted(built.archive_files), built.target.script]:
            destination = _safe(target / name, file=True)
            backup = target / (".fvp-original-" + name)
            staged = target / (".fvp-new-" + secrets.token_hex(8))
            output_identity = (dict(size=len(built.payload), sha256=sha(built.payload))
                               if name == built.target.script else archive_outputs[name])
            with destination.open("rb") as incoming, backup.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            if _file_identity(backup) != original[name]:
                raise ExportError("copy_changed", "新副本的原文件备份不完整，已停止安装。")
            with staged.open("xb") as stream:
                if name == built.target.script:
                    stream.write(built.payload)
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
            resource_archives=list(built.archive_files))

    def run(self, request, update):
        built = self.build(request, update)
        return self.install(built, update), built.issues
