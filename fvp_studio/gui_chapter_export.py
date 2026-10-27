"""Whole-chapter new-copy export; original and existing copies stay protected."""
from .gui_chapter import ChapterBuilder, chapter_plan, chapter_snapshot
from .gui_chapter_program import GuiChapterEmitter, validate_chapter_program
from .gui_scene_export import ExportError, ExportJobs, SceneExporter
from .gui_audio_checkpoint import REQUEST_FIELD as CHECKPOINT_FIELD

CONTRACT_SCHEMA = "fvp-gui-chapter-export/1"
SCOPE = "connected_chapter_new_test_copy"


class ChapterExporter(SceneExporter):
    scope = SCOPE
    report_schema = "fvp-studio.gui-chapter-export-candidate/1"
    emitter_id = "fvp-studio.gui-chapter-export/1"
    install_schema = "fvp-gui-chapter-export-install/1"
    family = "chapter"
    label = "当前章节"

    def run(self, request, update):
        # OP and opening CG need the target-bound paired state path even
        # when an older client uses this endpoint.
        plan = chapter_plan(request['document'], request['chapter_id'])
        project = request['document']['project']
        scenes = [project['scenes'][sid] for sid in plan['scene_ids']]
        from .gui_native_feature_routing import needs_native_gestures_or_cg_transition
        if any((isinstance(scene.get('setup'), dict) and scene['setup'].get('cg') is not None)
               or any(isinstance(b, dict) and b.get('kind') == 'movie' for b in scene.get('beats', []))
               or needs_native_gestures_or_cg_transition(scene)
               for scene in scenes):
            from .gui_native_chapter_export import NativeChapterExporter, REQUEST_SCHEMA
            native_request = dict(request, schema=REQUEST_SCHEMA)
            return NativeChapterExporter(self.runtime,self.output_root,test_parent=self.test_parent).run(native_request,update)
        # A chapter request intentionally has chapter_id, not scene_id. The
        # scene dispatcher reads scene_id before prepare(), so invoke this
        # exporter's inherited build/install pipeline directly.
        folder, outputs, program, report, resources, issues = self.build(request, update)
        return self.install(folder, outputs, program, report, resources, update), issues

    def prepare(self, request):
        builder = ChapterBuilder(self.runtime, request["document"], request["chapter_id"])
        program = builder.translate()
        if builder.has_errors:
            raise ExportError("chapter_needs_changes", "这章有内容暂时不能输出，请修改列出的位置。",
                              issues=[i for i in builder.issues if i["level"] != "info"])
        return program, builder, builder.metadata()

    def validate(self, program):
        return validate_chapter_program(program)

    def make_emitter(self, source, clean, program):
        masks = None
        wanted = {e["transition"]["mask"] for e in program["events"]
                  if e.get("kind") == "GuiChapterExit" and e.get("transition", {}).get("type") == "mask"
                  and e.get("mode") != "end"}
        if wanted:
            binding = self.runtime.chapter_transitions().binding("hoshi")
            masks = binding["masks"]
            if masks is None or not wanted <= set(masks.items) or masks.screen.source.original_bytes != source:
                raise ExportError("chapter_mask_not_connected", "章节选择的遮罩与当前原作资源、运行脚本不匹配。")
        return GuiChapterEmitter(source, clean, transition_masks=masks)


class ChapterExportJobs(ExportJobs):
    job_schema = "fvp-gui-chapter-export-job/1"
    snapshot = staticmethod(chapter_snapshot)

    def job_metadata(self, snapshot):
        plan = chapter_plan(snapshot["document"], snapshot["chapter_id"])
        result = dict(chapter_id=plan["chapter_id"], chapter_title=plan["title"],
                    entry_scene_id=plan["entry_scene_id"], scene_ids=plan["scene_ids"],
                    chapter_ids=plan["chapter_ids"], scene_chapters=plan["scene_chapters"])
        if CHECKPOINT_FIELD in snapshot:
            result[CHECKPOINT_FIELD] = snapshot[CHECKPOINT_FIELD]
        return result
