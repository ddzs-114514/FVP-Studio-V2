"""Explicit current-scene export to a NEW independent game copy.

The browser supplies a project snapshot, never an output/installation path.
This separate rehearsal route does not widen the production program validator,
the read-only preflight endpoint, or original-game writeback. No game is launched.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
from threading import BoundedSemaphore, RLock, Thread

from .gui_native_cg import GuiCgEmitter, SCHEMA as CG_SCHEMA, validate_gui_program
from .gui_background_program import report as background_report
from .gui_background_blur import report as blur_report
from .gui_choice_tracks import SCHEMA as TRACK_SCHEMA
from .gui_native_preflight import (MAX_BYTES, PROJECT_SCHEMA, SCENE_RE,
    SceneBuilder, canonical, checksum, ident, object_only)
from .gui_runtime import GuiRuntimeError, fingerprint
from .hcb import parse_bytes
from .hoshimemo_portrait_transaction import (
    SceneTransactionTarget, ValidatedSceneOutput, install_scene_transaction)
from .performance_compile import (CLEAN_SHA, ENTRY, ENTRY_BYTES, EXE_SHA,
    GRAPH_VIS_SHA, PROFILE, SOURCE_SHA, Emitter, Resources, resource_reference, sha)
from .performance_install import (
    TEST_PARENT, _fingerprint, _robocopy_executable, _safe, inventory, new_test_target)
from .performance_workflow import digest
from .gui_cg_imports import GuiCgImports
from .bin_archive import append_hzc_entries

REQUEST_SCHEMA = "fvp-gui-scene-export-request/1"
JOB_SCHEMA = "fvp-gui-scene-export-job/1"
CONTRACT_SCHEMA = "fvp-gui-scene-export/1"
REPORT_SCHEMA = "fvp-studio.gui-scene-export-candidate/1"
EMITTER = "fvp-studio.gui-scene-export/1"
SCOPE = "current_scene_new_test_copy"
JOB_RE = re.compile(r"[0-9a-f]{32}\Z")
MAX_JOBS = 32
TARGET_ENCODINGS = ("shift_jis", "cp932", "gbk", "utf-8")
SOURCE_FILES = (".Hoshimemo_HD.hcb", "Hoshimemo_HD.hcb", "Hoshimemo_HD.exe",
                "graph.bin", "graph_bs.bin", "graph_bg.bin", "graph_vis.bin")


def now():
    return datetime.now(timezone.utc).isoformat()


class ExportError(GuiRuntimeError):
    def __init__(self, code, message, *, issues=(), status=422):
        super().__init__(code, message, status)
        self.issues = list(issues)


def export_snapshot(request):
    """Validate the closed wire shape and detach it from caller-owned state."""
    try:
        object_only(request, "请求")
        required = {"schema", "request_id", "scene_id", "document"}
        if not required.issubset(request) or set(request) - required - {"target_encoding"}:
            raise ValueError("生成请求缺少内容或包含未允许的选项")
        if request["schema"] != REQUEST_SCHEMA:
            raise ValueError("生成请求格式不支持")
        ident(request["request_id"], "请求 ID")
        sid = request["scene_id"]
        if not isinstance(sid, str) or not SCENE_RE.fullmatch(sid):
            raise ValueError("场景 ID 不合法")
        doc = object_only(request["document"], "工程文件")
        if doc.get("schema") != PROJECT_SCHEMA:
            raise ValueError("工程文件格式不支持")
        project = object_only(doc.get("project"), "工程")
        scene = object_only(object_only(project.get("scenes"), "场景表").get(sid), "当前场景")
        if scene.get("id") != sid:
            raise ValueError("场景 ID 不一致")
        ident(project.get("source"), "目标游戏 ID")
        if "target_encoding" in request and (project["source"] == "hoshi"
                or type(request["target_encoding"]) is not str
                or request["target_encoding"] not in TARGET_ENCODINGS):
            raise ValueError("文字编码只接受其他游戏明确选择的 Shift-JIS、CP932、GBK 或 UTF-8。")
        if not isinstance(scene.get("title"), str) or len(scene["title"]) > 512:
            raise ValueError("场景标题过长或不是文本")
        if len(canonical(request)) > MAX_BYTES:
            raise GuiRuntimeError("request_too_large", "工程超过 16 MiB", 413)
        if len(canonical(scene)) > 512 * 1024:
            raise ValueError("当前场景太大，请拆成较小场景")
        return deepcopy(request)
    except GuiRuntimeError:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise GuiRuntimeError("invalid_request", str(exc)[:300]) from exc


def new_target(target, source, parent):
    """Check the exact target before any directory reservation or copy."""
    parent = _safe(Path(parent))
    raw = Path(target)
    if (not raw.is_absolute() or str(raw).startswith(("\\\\", "//"))
            or raw.parent != parent or raw.exists() or raw.is_symlink()
            or not raw.name or raw.name in (".", "..")):
        raise ExportError("unsafe_target", "只能生成全新的测试目录，不能覆盖原作或已有副本。")
    source = _safe(Path(source))
    if source == raw or source in raw.parents or raw in source.parents:
        raise ExportError("unsafe_target", "测试目录不能与原作重叠。")
    return raw


def validate_bytes(source, clean, payload, emitter):
    prefix = bytearray(payload[:len(source)])
    prefix[ENTRY:ENTRY + 5] = ENTRY_BYTES
    emitter.native_speakers.validate_patches(payload, prefix)
    bank = getattr(emitter, "story_bank", None)
    if bank is not None:
        from .gui_story_program import StoryVariableBank
        if not isinstance(bank, StoryVariableBank) or bank.e is not emitter or emitter.source != source:
            raise ExportError("invalid_candidate", "剧情变量分配与当前生成器不一致。")
        offset, original = bank.validate_header(payload)
        prefix[offset:offset + 2] = original
    if prefix != source or payload[ENTRY:ENTRY + 5] != b"\x06" + struct.pack("<I", emitter.entry):
        raise ExportError("invalid_candidate", "场景生成失败：游戏入口或原始脚本发生了意外变化。")
    append = payload[len(source):]
    table = struct.unpack_from("<I", clean)[0]
    decoded = parse_bytes(struct.pack("<I", 4 + len(append)) + append + clean[table:], encoding="gbk")
    bounds = {len(source) + ins.offset - 4 for ins in decoded.instructions} | set(emitter.by_offset)
    if decoded.warnings or any(ins.opcode in (2, 6, 7) and ins.operands["target"] not in bounds
                               for ins in decoded.instructions):
        raise ExportError("invalid_candidate", "场景生成失败：生成的游戏脚本无法正确读取。")
    if bank is not None:
        total = bank.total_before + len(bank.slots)
        if any(ins.opcode in (0x0F, 0x11, 0x15, 0x17) and ins.operands["value"] >= total
               for ins in decoded.instructions):
            raise ExportError("invalid_candidate", "剧情指令引用了未分配的变量。")
    return len(decoded.instructions)


class ExportResources:
    """Replace virtual preflight names with actual additive/native bindings."""
    def __init__(self, root, frozen):
        self.root, self.frozen = root, frozen
        self.references, self.cgs = [], {}
        self.speaker_payloads, self.speaker_bindings = {}, {}
        for path, _stamp in frozen.references:
            _safe(path, file=True, independent=False)
        frozen.check_unchanged()
        self.packs = Resources(root)
        self.cg_imports = GuiCgImports(root, self.packs, streaming=True)

    def bg(self, event):
        self.frozen.check_unchanged()
        path = _safe(Path(event["archive"]), file=True, independent=False)
        _payload, ref = resource_reference(path, event["resource"])
        if self.frozen.bg(event) != "BG_PREFLIGHT_" + ref["payload_sha256"][:20].upper():
            raise ExportError("source_changed", "背景素材已变化，请重新导入。")
        return self.packs.bg(event)

    def portrait(self, event):
        self.frozen.check_unchanged()
        _safe(Path(event["archive"]), file=True, independent=False)
        _virtual, body, face = self.frozen.portrait(event)
        actual = self.packs.portrait(event)
        if any(actual[index]["payload_sha256"] != expected["payload_sha256"]
               for index, expected in ((1, body), (2, face))):
            raise ExportError("source_changed", "立绘素材已变化，请重新导入；不会猜测大小。")
        return actual

    def cg(self, event):
        self.frozen.check_unchanged()
        # The selected source is checked against the frozen registered entry.
        # Imported bytes receive a content name in the target graph_vis.bin;
        # never borrow a same-named target CG or infer a source archive selector.
        path = _safe(Path(event["archive"]), file=True, independent=False)
        key = event["archive"], event["resource"]
        if key not in self.cgs:
            payload, ref = resource_reference(path, event["resource"])
            frozen = self.frozen.cg(event)
            if frozen["name"] != "CG_PREFLIGHT_" + sha(payload).upper() or any(
                frozen["metadata"].get(k) != ref[k]
                for k in ("width", "height", "offset_x", "offset_y", "kind", "frame_count")):
                raise ExportError("source_changed", "CG 素材已变化，请重新导入。")
            if ref["kind"] != 0 or ref["frame_count"] != 1:
                raise ExportError("unsupported_cg", "当前只能输出完整的单帧 CG。")
            name = (event["resource"] if path == self.root / "graph_vis.bin"
                    else self.cg_imports.bind(payload, ref))
            self.cgs[key] = dict(name=name, metadata=deepcopy(frozen["metadata"]))
            self.references.append(ref)
        return self.cgs[key]

    def finish(self):
        if self.speaker_payloads:
            built = append_hzc_entries(self.packs.graph, self.speaker_payloads)
            self.packs.graph = built.data
            self.packs.reports.append(dict(kind="gui_native_backlog_pairs",
                portrait_size_unchanged=True, **built.validation_dict()))
        self.packs.finish()
        self.cg_imports.finish()
        return self.packs.archives

    def audio(self, event):
        self.frozen.check_unchanged()
        # Direct references only: these archives are copied from the audited
        # target, not added to the visual BIN builder or silently rewritten.
        binding = self.frozen.audio(event)
        _safe(self.root / binding["target_archive"], file=True, independent=False)
        return binding

    def speech(self, event):
        self.frozen.check_unchanged()
        key = (event.get("source_game", event.get("speaker_source", "")), event["display_name"])
        if key in self.speaker_bindings:
            return deepcopy(self.speaker_bindings[key])
        binding = deepcopy(self.frozen.speakers.get(key))
        if binding and binding.get("source") != "hoshi" and binding.get("avatar"):
            from .gui_speaker_identity import avatar_pair
            payload = avatar_pair(binding)
            name = "BL_GUI_" + sha(payload).upper()
            self.speaker_payloads[name] = payload
            binding["resource"] = name
        self.speaker_bindings[key] = binding
        return deepcopy(binding)

    def check_unchanged(self):
        self.frozen.check_unchanged()
        self.cg_imports.check_unchanged()
        for ref in self.references:
            _payload, fresh = resource_reference(ref["archive_path"], ref["resource_name"])
            if fresh != ref:
                raise ExportError("source_changed", "生成期间 CG 来源发生变化，已停止。")


class SceneExporter:
    scope = SCOPE
    report_schema = REPORT_SCHEMA
    emitter_id = EMITTER
    install_schema = "fvp-gui-scene-export-install/1"
    family = "scene"
    label = "当前场景"

    def __init__(self, runtime, output_root, *, test_parent=TEST_PARENT):
        self.runtime = runtime
        self.output_root, self.test_parent = _safe(Path(output_root)), _safe(Path(test_parent))
        for source in runtime.sources.values():
            root = _safe(source.root)
            for destination in (self.output_root, self.test_parent):
                if destination == root or root in destination.parents or destination in root.parents:
                    raise ValueError("输出目录不能与任何已登记游戏来源重叠")

    def prepare(self, request):
        project = request["document"]["project"]
        scene = project["scenes"][request["scene_id"]]
        builder = SceneBuilder(self.runtime, project, scene)
        program = builder.translate()
        if builder.has_errors:
            raise ExportError("scene_needs_changes", "当前场景有内容暂时不能输出，请修改列出的位置。",
                              issues=[i for i in builder.issues if i["level"] != "info"])
        return program, builder, dict(scene_id=request["scene_id"], scene_sha256=checksum(scene),
                                      mapping=builder.mapping)

    def validate(self, program):
        return validate_gui_program(program)

    def make_emitter(self, source, clean, program):
        from .gui_audio_program import KINDS as AUDIO_KINDS, GuiAudioEmitter
        return (GuiAudioEmitter(source, clean) if any(e["kind"] in AUDIO_KINDS for e in program["events"])
                else GuiCgEmitter(source, clean))

    def build(self, request, update):
        program, builder, metadata = self.prepare(request)
        self.validate(program)
        root = _safe(Path(program["source_root"]))
        if root != _safe(self.runtime._source("hoshi").root):
            raise ExportError("unsupported_target", "场景目标不是已登记的游戏来源。")
        stamps = {name: fingerprint(_safe(root / name, file=True, independent=False)) for name in SOURCE_FILES}
        source, clean, exe = ((root / name).read_bytes() for name in SOURCE_FILES[:3])
        if ([sha(data) for data in (source, clean, exe)] != [SOURCE_SHA, CLEAN_SHA, EXE_SHA]
                or source[ENTRY:ENTRY + 5] != ENTRY_BYTES):
            raise ExportError("target_changed", "原作版本与已支持版本不一致，已停止生成。")
        update("compiling", "正在生成" + self.label + "…")
        resources = ExportResources(root, builder.resources)
        emitter = self.make_emitter(source, clean, program)
        payload = emitter.compile(program, resources)
        archives = resources.finish()
        count = validate_bytes(source, clean, payload, emitter)
        resources.check_unchanged()
        if any(fingerprint(root / name) != stamp for name, stamp in stamps.items()):
            raise ExportError("source_changed", "生成期间原作文件发生变化，已停止。")
        source_archives = {n: dict(size=len(b), sha256=sha(b)) for n, b in resources.packs.source.items()}
        output_archives = {n: dict(size=len(b), sha256=sha(b),
            added_bytes=len(b) - len(resources.packs.source[n])) for n, b in archives.items()}
        report = dict(schema=self.report_schema, emitter_id=self.emitter_id, profile_id=PROFILE,
            plan_sha256=digest(program), passed=True, dry_run_passed=True, install_ready=True,
            runtime_verified=False, rehearsal_only=True, production_candidate_accepted=False,
            source=dict(hcb_sha256=SOURCE_SHA, resource_archives=source_archives),
            output=dict(hcb_sha256=sha(payload), resource_archives=output_archives),
            required_exe_sha256=EXE_SHA, source_fingerprints=stamps,
            original_prefix_unchanged_outside_entry=getattr(emitter, "story_bank", None) is None and not emitter.native_speakers.patches,
            original_code_unchanged_outside_entry=not emitter.native_speakers.patches, instruction_boundaries_checked=True,
            new_instruction_count=count, events=emitter.events, resource_reports=resources.packs.reports,
            native_motion_contract=emitter.stage_motion.report(),
            native_stage_helpers=emitter.stage_helpers.report(),
            speaker_identity_contract=emitter.native_speakers.report(),
            background_change_contract=background_report(emitter),
            background_blur_contract=blur_report(emitter),
            native_cg_references=resources.references,
            cg_adapters=[v for k, v in emitter.helpers.items() if isinstance(k, tuple) and k[0] == "gui_cg_loader"],
            audio_adapters=[v for k, v in emitter.helpers.items() if isinstance(k, tuple) and k[0] in ("gui_bgm_asset_loader", "gui_voice_asset_loader")],
            scope=self.scope, document_sha256=checksum(request["document"]), **metadata,
            entry=dict(offset=ENTRY, expected=ENTRY_BYTES.hex(), target=emitter.entry))
        if hasattr(emitter, "route_reports"):
            report.update(native_routes=emitter.route_reports, scene_labels=emitter.scene_labels,
                          scene_jumps=emitter.jumps)
        if getattr(emitter, "story_bank", None) is not None:
            report["story_state"] = emitter.story_bank.report()
        folder = self.output_root / (self.family + "-" + digest(program)[:12] + "-" + secrets.token_hex(8))
        folder.mkdir(exist_ok=False)
        update("publishing", "正在保存生成文件…", output=dict(candidate_directory=str(folder)))
        cg_files, cg_sources, cg_outputs = resources.cg_imports.publish(folder)
        source_archives.update(cg_sources)
        output_archives.update(cg_outputs)
        stamps.update({name: resources.cg_imports.source_stamp for name in cg_files})
        audio_plan = resources.frozen.audio_binding_plan()
        if audio_plan.groups:
            update("publishing", "正在打包导入的音乐和音效…")
        audio_files, audio_sources, audio_outputs, audio_reports = audio_plan.publish(folder, self.runtime.audio)
        source_archives.update(audio_sources)
        output_archives.update(audio_outputs)
        stamps.update({name:fingerprint(root / name) for name in audio_files})
        report.update(audio_bindings={**audio_plan.report(), "pack_built":True},
                      audio_resource_reports=audio_reports)
        resources.check_unchanged()
        with (folder / "candidate.hcb").open("xb") as stream:
            stream.write(payload)
        changed = {**audio_files, **cg_files}
        for name, data in archives.items():
            if output_archives[name]["sha256"] != source_archives[name]["sha256"]:
                with (folder / name).open("xb") as stream:
                    stream.write(data)
                changed[name] = folder / name
        for name, value in (("project.json", request["document"]), ("request.json", request),
                            ("program.json", program), ("report.json", report)):
            with (folder / name).open("x", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        outputs = ValidatedSceneOutput(hcb=payload, source_sha256=SOURCE_SHA,
            plan_sha256=digest(program), emitter_id=self.emitter_id, profile_id=PROFILE, validation=report,
            resource_archive_files=changed,
            resource_archive_source_sha256={n: source_archives[n]["sha256"] for n in changed})
        return folder, outputs, program, report, resources, [i for i in builder.issues if i["level"] in ("warn", "warning")]

    def install(self, folder, outputs, program, report, resources, update):
        source = _safe(Path(program["source_root"]))
        _safe(self.test_parent)
        # Name generated internally; the browser cannot choose or overwrite it.
        target = new_target(self.test_parent / new_test_target(digest(program)).name, source, self.test_parent)
        robocopy = _robocopy_executable()
        import psutil  # ensure the process gate is available before any copy
        protected = tuple(_safe(p) for p in self.test_parent.iterdir() if p.is_dir())
        protected_hashes = {str(p / ".Hoshimemo_HD.hcb"): _fingerprint(
            p / ".Hoshimemo_HD.hcb", independent=False)["sha256"] for p in protected
            if (p / ".Hoshimemo_HD.hcb").is_file()}
        update("checking_copy", "正在准备新的测试副本…")
        original = inventory(source, False)
        original_stamps = {name: fingerprint(source / name) for name in original}
        if (original[".Hoshimemo_HD.hcb"]["sha256"] != SOURCE_SHA
                or original["Hoshimemo_HD.exe"]["sha256"] != EXE_SHA):
            raise ExportError("source_changed", "复制前原作版本发生变化，已停止。")
        for name, item in report["source"]["resource_archives"].items():
            if original[name] != item:
                raise ExportError("source_changed", "复制前原作素材发生变化，已停止。")
        if resources.references and original["graph_vis.bin"]["sha256"] != GRAPH_VIS_SHA["graph_vis.bin"]:
            raise ExportError("source_changed", "CG 素材包不是已支持的原作版本，已停止。")

        def protect():
            if set(original) != {str(p.relative_to(source)) for p in source.rglob("*") if p.is_file()}:
                raise ExportError("source_changed", "原作文件列表发生变化，已停止。")
            if any(fingerprint(_safe(source / n, file=True, independent=False)) != stamp
                   for n, stamp in original_stamps.items()):
                raise ExportError("source_changed", "复制期间原作发生变化，已停止。")
            if any(fingerprint(source / n) != tuple(stamp) for n, stamp in report["source_fingerprints"].items()):
                raise ExportError("source_changed", "生成后的原作发生变化，已停止。")
            resources.check_unchanged()
            for path, expected in protected_hashes.items():
                if _fingerprint(Path(path), independent=False)["sha256"] != expected:
                    raise ExportError("protected_changed", "已有测试副本发生变化，已停止。")

        required = sum(item["size"] for item in original.values()) + sum(
            p.stat().st_size for p in outputs.resource_archive_files.values()) * 2 + 4 * 1024**3
        if shutil.disk_usage(self.test_parent).free < required:
            raise ExportError("disk_full", "测试盘空间不足；生成文件已保留。")
        protect()
        new_target(target, source, self.test_parent)
        target.mkdir(exist_ok=False)
        _safe(target)
        partial = dict(candidate_directory=str(folder), test_directory=str(target))
        update("copying", "正在复制游戏，原作不会被修改…", output=partial)
        result = subprocess.run([robocopy, str(source), str(target), "/E", "/COPY:DAT", "/DCOPY:DAT", "/XJ",
            "/R:1", "/W:1", "/NFL", "/NDL", "/NP", "/NJH", "/NJS"], capture_output=True)
        if result.returncode >= 8:
            raise ExportError("copy_failed", "复制游戏失败；已保留不完整的新目录，没有写入原作。")
        update("checking_copy", "正在确认新副本已完整复制…")
        _safe(target)
        copied = inventory(target, True)
        if copied != original:
            raise ExportError("copy_changed", "新副本复制不完整；没有安装场景，目录已保留。")
        protect()
        for process in psutil.process_iter(["exe"]):
            try:
                exe = process.info.get("exe")
                if exe and target in Path(exe).resolve().parents:
                    raise ExportError("game_running", "新副本游戏已在运行，已停止安装。")
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied as exc:
                raise ExportError("process_unknown", "无法确认新副本是否正在运行，已停止安装。") from exc
        update("installing", "正在把" + self.label + "放入新副本…")
        transaction = install_scene_transaction(SceneTransactionTarget(target, PROFILE,
            protected_roots=tuple({source, *protected, *(s.root for s in self.runtime.sources.values())}),
            active_hcb_name=".Hoshimemo_HD.hcb"), outputs)
        protect()
        # Compare actual installed bytes before a completed result is returned.
        if _fingerprint(target / ".Hoshimemo_HD.hcb", independent=True)["sha256"] != report["output"]["hcb_sha256"]:
            raise ExportError("install_failed", "新副本的场景文件不完整，已保留目录供检查。")
        for name in outputs.resource_archive_files:
            if _fingerprint(target / name, independent=True)["sha256"] != report["output"]["resource_archives"][name]["sha256"]:
                raise ExportError("install_failed", "新副本的场景素材不完整，已保留目录供检查。")
        project_file = folder / "project.json"
        selection = {k: deepcopy(report[k]) for k in ("chapter_id", "chapter_title", "entry_scene_id", "scene_ids",
                                                    "chapter_sha256", "routes") if k in report}
        record = dict(schema=self.install_schema, scope=self.scope, **selection,
            original_unchanged=True, old_test_scripts_unchanged=True, runtime_verified=False,
            source_root=str(source), target_root=str(target), candidate_directory=str(folder),
            project_file=str(project_file), scene_id=report["scene_id"],
            document_sha256=report["document_sha256"], plan_sha256=report["plan_sha256"],
            copy_file_count=len(copied), copy_bytes=sum(v["size"] for v in copied.values()),
            copy_all_sha256_equal=True, copy_all_files_single_link=True, transaction=transaction)
        with (folder / "installation.json").open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
        return dict(test_directory=str(target), candidate_directory=str(folder),
            project_file=str(project_file), game_executable=str(target / "Hoshimemo_HD.exe"),
            original_unchanged=True, runtime_verified=False, scope=self.scope, **selection)

    def run(self, request, update):
        if request["document"]["project"]["source"] != "hoshi":
            if self.scope != SCOPE:
                raise ExportError("unsupported_target", "其他游戏目前只接当前场景输出，章节输出尚未接通。")
            from .gui_native_scene_export import NativeSceneExporter
            return NativeSceneExporter(self.runtime, self.output_root,
                test_parent=self.test_parent).run(request, update)
        folder, outputs, program, report, resources, issues = self.build(request, update)
        return self.install(folder, outputs, program, report, resources, update), issues


class ExportJobs:
    """One worker; stable IDs make network-unknown POSTs recoverable by GET."""
    job_schema = JOB_SCHEMA
    snapshot = staticmethod(export_snapshot)

    def __init__(self, exporter, *, worker_gate=None):
        self.exporter = exporter
        self.lock = RLock()
        self.jobs, self.requests = {}, {}
        self.latest = None
        self.worker_gate = worker_gate if worker_gate is not None else BoundedSemaphore(1)

    @classmethod
    def wrap(cls, job):
        wire = deepcopy(job)
        # In-progress output is not usable. Keep its locations internally so a
        # failed job can expose preserved files without claiming completion.
        if wire and wire["status"] in ("queued", "running"):
            wire["output"] = None
        return dict(ok=True, schema=cls.job_schema, job=wire)

    def job_metadata(self, snapshot):
        scene = snapshot["document"]["project"]["scenes"][snapshot["scene_id"]]
        # Retain the frozen output target while the job is pending, so a GUI
        # reconnect cannot mistake an export to another game for the editor's
        # current source. This is metadata only; browser paths remain forbidden.
        result = dict(scene_id=snapshot["scene_id"], scene_title=scene["title"],
                      target_source=snapshot["document"]["project"]["source"])
        if "target_encoding" in snapshot:
            result["target_encoding"] = snapshot["target_encoding"]
        return result

    def get(self, job_id=None):
        with self.lock:
            if job_id is None:
                return self.wrap(self.jobs.get(self.latest))
            if not JOB_RE.fullmatch(job_id) or job_id not in self.jobs:
                raise GuiRuntimeError("job_not_found", "没有找到这次生成记录。", 404)
            return self.wrap(self.jobs[job_id])

    def submit(self, request):
        snapshot = self.snapshot(request)
        identity = checksum(snapshot)
        rid = snapshot["request_id"]
        with self.lock:
            if rid in self.requests:
                job_id, known = self.requests[rid]
                if known != identity:
                    raise GuiRuntimeError("request_conflict", "同一次生成请求的内容不一致；没有重复生成。", 409)
                return self.wrap(self.jobs[job_id])
            if any(j["status"] in ("queued", "running") for j in self.jobs.values()):
                raise GuiRuntimeError("busy", "已有测试副本正在生成，请等它完成。", 409)
            if len(self.jobs) >= MAX_JOBS:
                raise GuiRuntimeError("session_full", "本次服务的生成记录已满，请先保留现有结果。", 503)
            job_id = secrets.token_hex(16)
            job = dict(id=job_id, request_id=rid, **self.job_metadata(snapshot),
                document_sha256=checksum(snapshot["document"]),
                status="queued", stage="queued", message="正在准备…", issues=[],
                output=None, error=None, started_at=now(), finished_at=None)
            if not self.worker_gate.acquire(blocking=False):
                raise GuiRuntimeError("busy", "已有测试副本正在生成，请等它完成。", 409)
            self.jobs[job_id] = job
            self.requests[rid] = job_id, identity
            self.latest = job_id
            thread = Thread(target=self._run, args=(job_id, snapshot), daemon=True)
            try:
                thread.start()
            except Exception:
                self.worker_gate.release()
                self.update(job_id, "failed", "生成任务无法启动，请保留工程后再试。", status="failed",
                            error=dict(code="start_failed", message="生成任务无法启动。"), finished_at=now())
            return self.wrap(job)

    def update(self, job_id, stage, message, **fields):
        with self.lock:
            self.jobs[job_id].update(status="running", stage=stage, message=message)
            self.jobs[job_id].update(fields)

    def _run(self, job_id, request):
        def progress(stage, message, **fields):
            self.update(job_id, stage, message, **fields)
        try:
            output, issues = self.exporter.run(request, progress)
            self.update(job_id, "completed", "测试副本已生成，原作未修改。", status="completed",
                        output=output, issues=issues, error=None, finished_at=now())
        except GuiRuntimeError as exc:
            self.update(job_id, "failed", str(exc)[:300], status="failed",
                error=dict(code=exc.code, message=str(exc)[:300]),
                issues=getattr(exc, "issues", []), finished_at=now())
        except (ValueError, KeyError, UnicodeError) as exc:
            self.update(job_id, "failed", self.exporter.label + "暂时不能生成，工程没有改变。", status="failed",
                error=dict(code=self.exporter.family + "_rejected", message=str(exc)[:300]), finished_at=now())
        except Exception:
            # Do not expose filesystem stacks, credentials, or imply zero writes
            # after a candidate/new directory has already been reserved.
            self.update(job_id, "failed", "生成没有完成；工程未改动，已生成的文件会保留。", status="failed",
                error=dict(code="export_failed", message="生成没有完成，请保留工程和生成记录。"), finished_at=now())
        finally:
            self.worker_gate.release()
