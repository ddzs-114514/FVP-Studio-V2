"""New loopback GUI listener: optional checks and explicit new-copy export."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .gui_native_preflight import MAX_BYTES
from .gui_preflight_server import GuiPreflightHandler, GuiPreflightServer, PreflightRuntime, unique_object
from .gui_runtime import API_ROOT, GuiRuntimeError, load_sources
from .gui_scene_export import (CONTRACT_SCHEMA, SCOPE, ExportJobs, SceneExporter, TARGET_ENCODINGS)


class ExportRuntime(PreflightRuntime):
    def export_target_info(self, source_id):
        from .gui_export_targets import NativeExportTargetCatalog
        # Runtime construction remains cheap; inspect only the target the
        # author selects. The catalog invalidates on native input changes.
        if not hasattr(self, "_export_target_catalog"):
            self._export_target_catalog = NativeExportTargetCatalog(self)
        return self._export_target_catalog.info(source_id)

    def health(self):
        result = super().health()
        # Preserve the old read-only ASSET/preflight contract; write authority
        # exists solely in this separate explicit new-copy endpoint.
        result["capabilities"]["scene_export"] = True
        result["scene_export_contract"] = dict(schema=CONTRACT_SCHEMA, scope=SCOPE,
            target="hoshi", original_game_read_only=True, launch_game=False,
            generic_targets=dict(source_ids=[sid for sid in self.sources if sid != "hoshi"],
                scope="native_dialogue_hook_new_test_copy", features=["background", "background_change", "native_speech", "wait",
                    "target_native_portrait", "native_expression_blend", "native_body_swap", "portrait_hide"],
                resource_mode="target_existing_or_additive_import", entry_mode="native_story_dialogue_hook",
                cross_game_background=True, streamed_target_pack=True,
                native_geometry_defaults_preserved=True,
                cross_game_portrait=True, cross_game_cg=False,
                portrait_binding="target_native_carrier_and_independent_slots",
                portrait_support_confirmed_on_export=True,
                target_info_schema="fvp-gui-export-target/1",
                target_info_endpoint="scene-export-target",
                target_encoding_selection=dict(request_field="target_encoding",
                    allowed=list(TARGET_ENCODINGS), session_only=True),
                portrait_expression_default_ms=200, body_swap_blend=False,
                body_swap_duration_control=False, instant_body_swap_proven=False,
                portrait_motion=dict(channels=["alpha", "xy", "z", "s2"],
                    requires_target_native_parameter_flow=True, unmatched_target_rejected=True,
                    cross_game_reference_required=False,
                    rotation_degree_conversion=False,
                    alpha_binding="target_native_parameter_flow_and_cache_writes"),
                original_portrait_images_restored=False,
                registration_only=True, bind_on_export=True,
                job_target_field="target_source",
                standalone_startup=False, chapter_export=False, runtime_verified=False))
        result["cg_import_contract"] = dict(schema="fvp-gui-cross-game-cg/1", target="hoshi",
            source="registered_graphics", cross_game=True, cross_archive=True,
            whole_single_frame=True, image_resampled=False,
            target_archive="graph_vis.bin", original_game_read_only=True,
            streamed_target_pack=True,
            runtime_verified=False)
        return result


class GuiExportServer(GuiPreflightServer):
    def __init__(self, address, runtime, html, output_root, *, exporter=None):
        self.exports = ExportJobs(exporter or SceneExporter(runtime, output_root))
        super().__init__(address, runtime, html)
        self.RequestHandlerClass = GuiExportHandler


class GuiExportHandler(GuiPreflightHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == API_ROOT + "scene-export-target":
            acquired = False
            try:
                self._local_request()
                if len(self.path) > 256:
                    raise GuiRuntimeError("invalid_request", "输出游戏请求过长。")
                q = self._query(parse_qs(url.query, keep_blank_values=True, max_num_fields=4),
                                ("source",), ("source",))
                acquired = self.server.heavy_requests.acquire(blocking=False)
                if not acquired:
                    raise GuiRuntimeError("busy", "正在读取游戏，请稍后再选择。", 503)
                self._json(self.server.runtime.export_target_info(q["source"]))
            except GuiRuntimeError as exc:
                self._error(exc)
            except ValueError:
                self._error(GuiRuntimeError("invalid_request", "输出游戏请求不正确。"))
            except OSError:
                self._error(GuiRuntimeError("source_unavailable", "游戏文件暂不可读取，请重新选择。", 503))
            except Exception:
                self._error(GuiRuntimeError("native_target_unavailable", "此版本的输出支持尚不能确认。", 503))
            finally:
                if acquired:
                    self.server.heavy_requests.release()
            return
        prefix = API_ROOT + "scene-export/"
        if not url.path.startswith(prefix):
            return super().do_GET()
        try:
            self._local_request()
            if url.query or len(self.path) > 256:
                raise GuiRuntimeError("invalid_request", "生成记录的请求不正确。")
            suffix = url.path[len(prefix):]
            if suffix == "active":
                self._json(self.server.exports.get())
            elif suffix.startswith("jobs/"):
                self._json(self.server.exports.get(suffix[5:]))
            else:
                raise GuiRuntimeError("not_found", "没有找到这次生成记录。", 404)
        except GuiRuntimeError as exc:
            self._error(exc)
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_POST(self):
        url = urlsplit(self.path)
        if url.path != API_ROOT + "scene-export":
            return super().do_POST()
        try:
            self._local_request()
            if url.query:
                raise GuiRuntimeError("invalid_request", "生成请求不能附带输出路径。")
            if self.headers.get("X-FVP-GUI-Request") != "scene-export/1":
                raise GuiRuntimeError("request_rejected", "缺少明确的生成请求标记。", 403)
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json":
                raise GuiRuntimeError("media_type_rejected", "生成请求只接受 JSON。", 415)
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit():
                raise GuiRuntimeError("invalid_request", "请求长度不明确。")
            size = int(lengths[0])
            if not 1 <= size <= MAX_BYTES:
                raise GuiRuntimeError("request_too_large", "工程过大或请求为空。", 413)
            self.connection.settimeout(10)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("工程请求不完整")
            request = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object,
                parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("JSON 不允许 NaN/Infinity")))
            self._json(self.server.exports.submit(request), 202)
        except GuiRuntimeError as exc:
            self._error(exc)
        except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
            self._error(GuiRuntimeError("invalid_request", str(exc)[:300]))
        except (BrokenPipeError, ConnectionResetError):
            return
        except (OSError, TimeoutError):
            self._error(GuiRuntimeError("request_failed", "请求未能确认，请查看生成记录，不要重复提交。", 503))
        except Exception:
            self._error(GuiRuntimeError("internal_error", "请求未能确认，请查看生成记录。", 500))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18803)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    runtime = ExportRuntime(load_sources(args.sources))
    server = GuiExportServer(("127.0.0.1", args.port), runtime, args.html, args.output_root)
    print(f"GUI_EXPORT_READY http://127.0.0.1:{args.port}/fvp_story_studio_prototype.html", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
