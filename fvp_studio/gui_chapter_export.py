"""Whole-chapter new-copy export; original and existing copies stay protected."""
from .gui_chapter import ChapterBuilder, chapter_plan, chapter_snapshot
from .gui_chapter_program import GuiChapterEmitter, validate_chapter_program
from .gui_scene_export import ExportError, ExportJobs, SceneExporter

CONTRACT_SCHEMA = "fvp-gui-chapter-export/1"
SCOPE = "connected_chapter_new_test_copy"


class ChapterExporter(SceneExporter):
    scope = SCOPE
    report_schema = "fvp-studio.gui-chapter-export-candidate/1"
    emitter_id = "fvp-studio.gui-chapter-export/1"
    install_schema = "fvp-gui-chapter-export-install/1"
    family = "chapter"
    label = "当前章节"

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
        return GuiChapterEmitter(source, clean)


class ChapterExportJobs(ExportJobs):
    job_schema = "fvp-gui-chapter-export-job/1"
    snapshot = staticmethod(chapter_snapshot)

    def job_metadata(self, snapshot):
        plan = chapter_plan(snapshot["document"], snapshot["chapter_id"])
        return dict(chapter_id=plan["chapter_id"], chapter_title=plan["title"],
                    entry_scene_id=plan["entry_scene_id"], scene_ids=plan["scene_ids"],
                    chapter_ids=plan["chapter_ids"], scene_chapters=plan["scene_chapters"])
