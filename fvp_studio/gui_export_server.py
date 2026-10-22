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
from .gui_target_selection import SCHEMA as ENTRY_SCHEMA, FILE_OPTIONS, OPTION_FIELDS
from .native_scene_choice_structure import MAX_NESTING
from .native_screen_transition import METHODS as SCREEN_TRANSITION_METHODS
from .camera_zoom_limits import zoom_range


class ExportRuntime(PreflightRuntime):
    def export_target_info(self, source_id, **options):
        from .gui_export_targets import NativeExportTargetCatalog
        # Runtime construction remains cheap; inspect only the target the
        # author selects. The catalog invalidates on native input changes.
        if not hasattr(self, "_export_target_catalog"):
            self._export_target_catalog = NativeExportTargetCatalog(self)
        return self._export_target_catalog.info(source_id, **options)

    def health(self):
        result = super().health()
        # Preserve the old read-only ASSET/preflight contract; write authority
        # exists solely in this separate explicit new-copy endpoint.
        result["capabilities"]["scene_export"] = True
        result["scene_export_contract"] = dict(schema=CONTRACT_SCHEMA, scope=SCOPE,
            target="hoshi", original_game_read_only=True, launch_game=False,
            camera=dict(supported=True,
                zoom_range=zoom_range(1900, (0, 0, -200), (1920, 1080), minimum_layer_distance=100),
                cg_zoom_range=zoom_range(2000, (0, 0, 0), (1920, 1080), minimum_layer_distance=100),
                runtime_verified=False),
            generic_targets=dict(source_ids=[sid for sid in self.sources if sid != "hoshi"],
                scope="native_dialogue_hook_new_test_copy", features=["background", "background_change", "background_blur", "native_speech", "wait",
                    "target_native_portrait", "native_expression_blend", "native_body_swap", "portrait_hide", "camera", "choices", "screen_transition", "cg"],
                resource_mode="target_existing_or_additive_import", entry_mode="native_story_dialogue_hook",
                cross_game_background=True, streamed_target_pack=True,
                native_geometry_defaults_preserved=True,
                cross_game_portrait=True, cross_game_cg=True,
                cg=dict(operations=["load", "difference", "exit", "transform"],
                    geometry_support_confirmed_on_export=True, motion_channels=["xy", "z"],
                    zoom_channel="z", native_state_bridge_required=True,
                    new_test_copy_only=True, support_confirmed_on_export=True,
                    binding="target_native_calls_and_source_native_resource_family",
                    source_size_rule_changed=False, runtime_verified=False),
                portrait_binding="target_native_carrier_and_independent_slots",
                portrait_support_confirmed_on_export=True,
                background_blur=dict(binding="target_native_preblurred_layer_and_alpha_child",
                    support_confirmed_on_export=True, original_pair_required=True,
                    original_preference_unchanged=True, changes_camera=False,
                    source_size_rule_changed=False, runtime_verified=False),
                screen_transition=dict(binding="target_native_colour_and_isolated_reveal",
                    support_confirmed_on_export=True, methods=list(SCREEN_TRANSITION_METHODS),
                    waits_each_leg=True, native_duration_policy_preserved=True,
                    original_preference_unchanged=True, mask_dissolve_supported=False,
                    source_size_rule_changed=False, runtime_verified=False),
                camera=dict(binding="target_native_wrapper_argument_flow",
                    reference_plane="target_native_background_defaults", viewport="target_executable",
                    preserves_native_skip_policy=True, unmatched_target_rejected=True,
                    source_size_rule_changed=False, runtime_verified=False),
                choices=dict(binding="target_native_registration_input_and_result",
                    support_confirmed_on_export=True, waits_for_selection=True,
                    selected_route_only=True, maximum_options=4, nested_choices=True, max_nesting=MAX_NESTING,
                    nested_completion="merge_within_selected_parent_route",
                    branch_resource_changes=True, prompt_requires_extra_click=False,
                    merge_requires_equal_state=True, runtime_verified=False),
                target_info_schema="fvp-gui-export-target/1",
                target_info_endpoint="scene-export-target",
                entry_selection=dict(schema=ENTRY_SCHEMA, request_fields=list(FILE_OPTIONS),
                    query_fields=list(OPTION_FIELDS), basenames_only=True,
                    session_only=True, persists_in_project=False, original_game_read_only=True),
                target_encoding_selection=dict(request_field="target_encoding",
                    allowed=list(TARGET_ENCODINGS), session_only=True),
                portrait_expression_default_ms=200, body_swap_blend=True,
                body_swap_duration_control=True, body_swap_default_ms=200,
                body_swap_support_confirmed_on_export=True, instant_body_swap_proven=False,
                portrait_motion=dict(channels=["alpha", "xy", "z", "s2", "r"],
                    raw_channels=["alpha", "xy", "z", "s2", "r"],
                    raw_rotation_units="target_native_raw_R_not_degrees",
                    requires_target_native_parameter_flow=True, unmatched_target_rejected=True,
                    cross_game_reference_required=False,
                    rotation_degree_conversion=True,
                    rotation_support_confirmed_on_export=True,
                    rotation_conversion_binding="target_registered_R_field_and_renderer_import",
                    alpha_binding="target_native_parameter_flow_and_cache_writes"),
                original_portrait_images_restored=False,
                registration_only=True, bind_on_export=True,
                job_target_field="target_source",
                standalone_startup=False, chapter_export=True, runtime_verified=False))
        result["cg_import_contract"] = dict(schema="fvp-gui-cross-game-cg/1", target="hoshi",
            source="registered_graphics", cross_game=True, cross_archive=True,
            whole_single_frame=True, image_resampled=False,
            target_archive="graph_vis.bin", original_game_read_only=True,
            streamed_target_pack=True,
            runtime_verified=False)
        generic = result['scene_export_contract']['generic_targets']
        from .gui_actor_sway import contract as sway_contract
        generic['portrait_sway'] = sway_contract()
        generic['body_swap_alpha_fusion'] = dict(supported=True,duration_policy='max',
            actions=['fade','enter_fade','exit_fade','enter_slide','exit_slide'],event_field='target_alpha',
            slide_fusion=True,target_support_required=True,runtime_verified=False)
        generic['body_swap_parallel_stage'] = dict(supported=True,camera=True,background_blur=True,
            other_actor_fade=True,same_actor_alpha=False,other_actor_slide=True,
            native_apply_frontier=True,target_support_required=True,runtime_verified=False)
        generic['cg']['load_with_transform'] = True
        from .gui_cg_stage_handoff import contract as cg_exit_setup_contract
        generic['cg']['exit_stage_setup'] = cg_exit_setup_contract()
        generic['audio'] = dict(schema='fvp-native-audio-capability/1',kinds=['bgm','se','voice'],
            binding='target_native_wrapper_argument_flow',support_confirmed_on_export=True,
            target_info_required=True,paired_native_state_required=True,voice=True,voice_backlog_replay=False,
            local_choice_branches=True,original_playback_restore=False,runtime_verified=False)
        from .gui_audio_program import playback_contract
        generic['audio']['playback'] = playback_contract(['bgm','se','voice'])
        result["scene_export_contract"]["generic_targets"]["linear_chapter"] = dict(
            schema="fvp-gui-native-linear-chapter-export/1",
            job_schema="fvp-gui-native-chapter-export-job/1", max_scenes=64,
            endpoint="native-chapter-export", request_schema="fvp-gui-native-chapter-export-request/1",
            scope="native_dialogue_hook_new_test_copy", route_scope="explicit_linear_route_one_matched_test_copy", support_confirmed_on_export=True,
            exit_modes=["next", "jump", "end"], cross_chapter_explicit_jumps=True,
            paired_native_state_required=True, one_original_state_capture=True,
            original_story_restored_after_final_scene=True, boundary_colour="black", boundary_ms=800, boundary_default_only=True,
            cg=True, choices=True, local_beat_choices=True, conditional_routes=False, loops=False, audio=False,
            standalone_startup=False, runtime_verified=False)
        result["scene_export_contract"]["generic_targets"]["scene_route_chapter"] = dict(
            schema="fvp-gui-native-scene-route-chapter-export/1",
            job_schema="fvp-gui-native-chapter-export-job/1", max_scenes=64,
            endpoint="native-chapter-export", request_schema="fvp-gui-native-chapter-export-request/1",
            scope="native_dialogue_hook_new_test_copy", route_scope="explicit_scene_graph_one_matched_test_copy", support_confirmed_on_export=True,
            exit_modes=["next", "jump", "choice", "condition", "end"], cross_chapter_explicit_jumps=True,
            scene_exit_choices=True, selected_route_only=True, shared_scene_compiled_once=True,
            paired_native_state_required=True, target_native_menu_required=True,
            one_original_state_capture=True, original_story_restored_after_selected_route_ends=True,
            boundary_colour="black", boundary_ms=800, boundary_default_only=True, local_beat_choices=True,
            cg=True, conditional_routes=True, variables=True, loops=True, audio=False,
            option_effects=True, beat_effects=True, state_storage="private_volatile_tail",
            reset_variables_on_scene_entry=False, save_load_verified=False, rewind_verified=False,
            standalone_startup=False, runtime_verified=False)
        from .gui_chapter_transition import contract
        for route in ("linear_chapter", "scene_route_chapter"):
            result["scene_export_contract"]["generic_targets"][route]["transitions"] = contract()
            result["scene_export_contract"]["generic_targets"][route]["cg_with_local_choices"] = True
            result["scene_export_contract"]["generic_targets"][route]["audio_kinds"] = ['bgm','se','voice']
            result["scene_export_contract"]["generic_targets"][route]["audio"] = True
        return result


class GuiExportServer(GuiPreflightServer):
    def __init__(self, address, runtime, html, output_root, *, exporter=None):
        self.exports = ExportJobs(exporter or SceneExporter(runtime, output_root))
        self.native_chapter_output_root = output_root
        super().__init__(address, runtime, html)
        self.RequestHandlerClass = GuiExportHandler

    def native_chapter_jobs(self):
        # No extra discovery, game scans or worker at server construction.
        # Use the existing lock and gate so scene/chapter jobs cannot overlap.
        with self.exports.lock:
            if not hasattr(self, "_native_chapter_exports"):
                from .gui_native_chapter_export import NativeChapterExporter, NativeChapterExportJobs
                try:
                    self._native_chapter_exports = NativeChapterExportJobs(
                        NativeChapterExporter(self.runtime, self.native_chapter_output_root),
                        worker_gate=self.exports.worker_gate)
                except (OSError, ValueError) as exc:
                    raise GuiRuntimeError("native_chapter_unavailable", "通用章节的输出目录或游戏登记尚未准备好。", 503) from exc
            return self._native_chapter_exports


class GuiExportHandler(GuiPreflightHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == API_ROOT + "scene-export-target":
            acquired = False
            try:
                self._local_request()
                if len(self.path) > 4096:
                    raise GuiRuntimeError("invalid_request", "输出游戏请求过长。")
                q = self._query(parse_qs(url.query, keep_blank_values=True, max_num_fields=4),
                                ("source", *OPTION_FIELDS), ("source",))
                acquired = self.server.heavy_requests.acquire(blocking=False)
                if not acquired:
                    raise GuiRuntimeError("busy", "正在读取游戏，请稍后再选择。", 503)
                self._json(self.server.runtime.export_target_info(q["source"],
                    **{key: q[key] for key in OPTION_FIELDS if key in q}))
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
        native_chapter = url.path.startswith(API_ROOT + "native-chapter-export/")
        prefix = API_ROOT + ("native-chapter-export/" if native_chapter else "scene-export/")
        if not url.path.startswith(prefix):
            return super().do_GET()
        try:
            self._local_request()
            if url.query or len(self.path) > 256:
                raise GuiRuntimeError("invalid_request", "生成记录的请求不正确。")
            suffix = url.path[len(prefix):]
            jobs = self.server.native_chapter_jobs() if native_chapter else self.server.exports
            if suffix == "active":
                self._json(jobs.get())
            elif suffix.startswith("jobs/"):
                self._json(jobs.get(suffix[5:]))
            else:
                raise GuiRuntimeError("not_found", "没有找到这次生成记录。", 404)
        except GuiRuntimeError as exc:
            self._error(exc)
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_POST(self):
        url = urlsplit(self.path)
        native_chapter = url.path == API_ROOT + "native-chapter-export"
        if url.path not in {API_ROOT + "scene-export", API_ROOT + "native-chapter-export"}:
            return super().do_POST()
        try:
            self._local_request()
            if url.query:
                raise GuiRuntimeError("invalid_request", "生成请求不能附带输出路径。")
            marker = "native-chapter-export/1" if native_chapter else "scene-export/1"
            if self.headers.get("X-FVP-GUI-Request") != marker:
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
            jobs = self.server.native_chapter_jobs() if native_chapter else self.server.exports
            self._json(jobs.submit(request), 202)
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
