"""Loopback chapter export, retaining the existing scene/assets/audio APIs."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from .gui_audio_server import AudioRuntime, GuiAudioHandler, GuiAudioServer
from .gui_chapter import MAX_SCENES, chapter_plan
from .gui_chapter_export import CONTRACT_SCHEMA, SCOPE, ChapterExporter, ChapterExportJobs
from .gui_native_preflight import MAX_BYTES, object_only
from .gui_preflight_server import unique_object
from .gui_runtime import API_ROOT, GuiRuntimeError, load_sources
from .gui_story_logic import CONTRACT as STORY_CONTRACT, INT_LIMIT, MAX_VARIABLES

PLAN_REQUEST_SCHEMA = "fvp-gui-chapter-plan-request/1"


class ChapterRuntime(AudioRuntime):
    def health(self):
        result = super().health()
        result["capabilities"].update(chapter_plan=True, chapter_export=True,
            cross_chapter_routes=True, story_variables=True, conditional_routes=True)
        result["chapter_export_contract"] = dict(schema=CONTRACT_SCHEMA, scope=SCOPE,
            target="hoshi", graph_target_independent=True, max_scenes=MAX_SCENES,
            exit_modes=["next", "jump", "choice", "condition", "end"], wait_for_selection=True,
            selected_route_only=True, stable_scene_ids=True, backward_edges=True,
            cross_chapter_routes=True, next_is_chapter_local=True,
            scene_setup_reset=True, audio_preserved_between_scenes=True,
            original_game_read_only=True, launch_game=False, runtime_verified=False)
        result["story_logic_contract"] = dict(schema=STORY_CONTRACT, target="hoshi",
            project_field="variables", beat_field="effects", choice_option_field="effects",
            variable_types=["bool", "int"], max_variables=MAX_VARIABLES,
            assignment_ops=["set", "add"], comparison_ops=["eq", "ne", "gt", "ge", "lt", "le"],
            integer_range=[-INT_LIMIT, INT_LIMIT], integer_add_policy="saturate",
            shared_between_scenes=True, shared_between_chapters=True,
            reset_on_scene_entry=False, original_variable_slots_unchanged=True,
            native_export=True, runtime_verified=False, save_load_verified=False, rewind_verified=False)
        return result


class GuiChapterServer(GuiAudioServer):
    def __init__(self, address, runtime, html, output_root, *, exporter=None, chapter_exporter=None):
        super().__init__(address, runtime, html, output_root, exporter=exporter)
        self.chapter_exports = ChapterExportJobs(chapter_exporter or ChapterExporter(runtime, output_root),
                                                 worker_gate=self.exports.worker_gate)
        self.RequestHandlerClass = GuiChapterHandler


class GuiChapterHandler(GuiAudioHandler):
    def read_chapter_request(self, marker):
        if self.headers.get("X-FVP-GUI-Request") != marker:
            raise GuiRuntimeError("request_rejected", "缺少明确的章节请求标记。", 403)
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json":
            raise GuiRuntimeError("media_type_rejected", "章节请求只接受 JSON。", 415)
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit():
            raise GuiRuntimeError("invalid_request", "请求长度不明确。")
        size = int(lengths[0])
        if not 1 <= size <= MAX_BYTES:
            raise GuiRuntimeError("request_too_large", "工程过大或请求为空。", 413)
        self.connection.settimeout(10)
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise ValueError("工程请求不完整。")
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object,
            parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("JSON 不允许 NaN/Infinity")))

    def do_GET(self):
        url = urlsplit(self.path)
        prefix = API_ROOT + "chapter-export/"
        if not url.path.startswith(prefix):
            return super().do_GET()
        try:
            self._local_request()
            if url.query or len(self.path) > 256:
                raise GuiRuntimeError("invalid_request", "章节记录的请求不正确。")
            suffix = url.path[len(prefix):]
            if suffix == "active":
                self._json(self.server.chapter_exports.get())
            elif suffix.startswith("jobs/"):
                self._json(self.server.chapter_exports.get(suffix[5:]))
            else:
                raise GuiRuntimeError("not_found", "没有找到这次章节生成记录。", 404)
        except GuiRuntimeError as exc:
            self._error(exc)
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_POST(self):
        url = urlsplit(self.path)
        paths = {API_ROOT + "chapter-plan": "chapter-plan/1", API_ROOT + "chapter-export": "chapter-export/1"}
        if url.path not in paths:
            return super().do_POST()
        try:
            self._local_request()
            if url.query:
                raise GuiRuntimeError("invalid_request", "章节请求不能附带输出路径。")
            request = self.read_chapter_request(paths[url.path])
            if url.path.endswith("chapter-export"):
                self._json(self.server.chapter_exports.submit(request), 202)
            else:
                object_only(request, "章节请求")
                if set(request) != {"schema", "chapter_id", "document"} or request["schema"] != PLAN_REQUEST_SCHEMA:
                    raise ValueError("章节请求格式不正确。")
                # This route only resolves the graph, not resources or HCB.
                self._json(chapter_plan(request["document"], request["chapter_id"]))
        except GuiRuntimeError as exc:
            self._error(exc)
        except (ValueError, KeyError, TypeError, RecursionError, UnicodeError) as exc:
            self._error(GuiRuntimeError("invalid_request", str(exc)[:300]))
        except (BrokenPipeError, ConnectionResetError):
            return
        except (OSError, TimeoutError):
            self._error(GuiRuntimeError("request_failed", "请求未能确认，请查看章节生成记录。", 503))
        except Exception:
            self._error(GuiRuntimeError("internal_error", "请求未能确认，请保留工程并查看生成记录。", 500))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18806)
    options = parser.parse_args()
    if not 1024 <= options.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    server = GuiChapterServer(("127.0.0.1", options.port), ChapterRuntime(load_sources(options.sources)),
                              options.html, options.output_root)
    print(f"GUI_CHAPTER_READY http://127.0.0.1:{options.port}/fvp_story_studio_prototype.html", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
