"""Additional loopback listener: read-only assets plus explicit native preflight.

POST parses GUI JSON and validates in memory. There is no output path, installer,
candidate creation or original-game write. Existing GET-only listeners stay up.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from threading import BoundedSemaphore
from urllib.parse import urlsplit

from .gui_runtime import API_ROOT, GuiRuntime, GuiRuntimeError, load_sources
from .gui_runtime_server import GuiRuntimeHandler, GuiRuntimeServer
from .gui_native_preflight import GuiNativePreflight, MAX_BYTES
from .performance_workflow import EXPRESSION_DEFAULT_DURATION_MS
from .gui_actor_swap_blend import DEFAULT_DURATION_MS as SWAP_DEFAULT_DURATION_MS


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON 含重复字段")
        result[key] = value
    return result


class PreflightRuntime(GuiRuntime):
    def health(self):
        result = super().health()
        result["capabilities"]["native_preflight"] = True
        result["capabilities"]["native_cg_preflight"] = True
        result["capabilities"]["native_compile"] = False
        result["capabilities"]["game_writeback"] = False
        result["preflight_scope"] = "selected_scene_independent_rehearsal"
        result["expression_transition_contract"] = dict(
            schema="fvp-gui-expression-transition/1",
            default_duration_ms=EXPRESSION_DEFAULT_DURATION_MS,
            default_basis="user_selected", direct_duration_ms=0,
            blend_min_duration_ms=100, blend_max_duration_ms=6000,
            parallel_text=True, native_curve=False)
        result["actor_actions_contract"] = dict(schema="fvp-gui-actor-actions/1", target="hoshi",
            slide_enter=True, slide_exit=True, slide_alpha="full_duration_native_fade",
            tilt_degrees=True, depth=True, swap=True,
            swap_policies=["keep", "source"], swap_keeps_position=True,
            swap_blend=True, swap_default_duration_ms=SWAP_DEFAULT_DURATION_MS,
            swap_legacy_duration_ms=0, swap_blend_max_duration_ms=6000,
            swap_whole_body_and_expression=True, swap_same_actor_alpha_overlap=False,
            move_after_scale=True, simultaneous_scale_move=False,
            simultaneous_depth_move=False, native_import_size_unchanged=True,
            runtime_verified=False)
        result["speaker_identity_contract"] = dict(schema="fvp-gui-speaker-identity/1", target="hoshi",
            name_visibility=True, native_text_colour=True, same_game_native_avatar=True,
            cross_game_native_avatar_pairs=True, source_tables="registered_hcb_native_calls",
            unknown_identity="no_borrowed_foreign_avatar", original_window_art_unchanged=True,
            portrait_size_unchanged=True, scene=True, chapter=True, choice_tracks=True,
            voiced_lines=True, runtime_verified=False)
        result["background_change_contract"] = dict(schema="fvp-gui-background-change/1", target="hoshi",
            cut=True, dissolve=True, duration_min_ms=100, duration_max_ms=6000,
            cut_duration_ms=0, camera_preserved=True, portrait_geometry_unchanged=True,
            parallel_text=True, parallel_audio=True, simultaneous_visual_dissolve=False,
            scene=True, chapter=True, choice_tracks=True, runtime_verified=False)
        result["background_blur_contract"] = dict(schema="fvp-gui-background-blur/1", target="hoshi",
            native_preblurred_pair=True, amount_min=0, amount_max=100,
            direct_duration_ms=0, blend_min_duration_ms=100, blend_max_duration_ms=6000,
            camera_preserved=True, portrait_geometry_unchanged=True, native_curve=False,
            uses_generated_blur=False, uses_web_filter=False, parallel_text=True,
            parallel_portraits=True, parallel_camera=True, scene=True, chapter=True,
            choice_tracks=True, runtime_verified=False)
        result["choice_contract"] = dict(schema="fvp-gui-choice-tracks/1",
            program_schema="fvp-gui-branch-program/1",
            target="hoshi", option_min=2, option_max=4, wait_for_selection=True,
            settles_motion_before_menu=True, automatic_selection=False,
            branches="complete_beats", legacy_branches="inline_speaker_text_lines",
            merge="explicit_next_scene_beat_or_scene_end", unequal_lengths=True,
            nested_choices=False, scene_exit_branches=False, runtime_verified=False)
        result["cg_preflight_contract"] = dict(schema="fvp-gui-cg-preflight/1",
            program_schema="fvp-gui-preflight-program/2", target="hoshi",
            scope="memory_only", whole_single_frame=True, fit="contain",
            parallel_text=True, stable_variant_pose=True,
            local_move=True, local_scale="origin_only", runtime_verified=False)
        return result


class GuiPreflightServer(GuiRuntimeServer):
    def __init__(self, address, runtime, html):
        super().__init__(address, runtime, html)
        self.RequestHandlerClass = GuiPreflightHandler
        self.preflight = GuiNativePreflight(runtime)
        self.preflight_requests = BoundedSemaphore(1)


class GuiPreflightHandler(GuiRuntimeHandler):
    def do_POST(self):
        acquired = False
        try:
            self._local_request()
            url = urlsplit(self.path)
            if url.path != API_ROOT + "native-preflight" or url.query:
                raise GuiRuntimeError("read_only", "仅开放原生预检，写回与安装未开放", 405)
            if self.headers.get("X-FVP-GUI-Request") != "native-preflight/1":
                raise GuiRuntimeError("request_rejected", "缺少明确原生预检请求标记", 403)
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json":
                raise GuiRuntimeError("media_type_rejected", "预检只接受 JSON", 415)
            lengths = self.headers.get_all("Content-Length", [])
            if (self.headers.get("Transfer-Encoding") or len(lengths) != 1
                    or not lengths[0].isdigit()):
                raise GuiRuntimeError("invalid_request", "请求长度缺失或不明确")
            size = int(lengths[0])
            if not 1 <= size <= MAX_BYTES:
                raise GuiRuntimeError("request_too_large", "工程超过 16 MiB 或为空", 413)
            acquired = self.server.preflight_requests.acquire(timeout=0.1)
            if not acquired:
                raise GuiRuntimeError("busy", "已有原生预检正在执行，请勿重复提交", 503)
            self.connection.settimeout(10)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError("JSON 请求不完整")
            request = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("JSON 不允许 NaN/Infinity")))
            self._json(self.server.preflight.run(request))
        except GuiRuntimeError as exc:
            self._error(exc)
        except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
            self._error(GuiRuntimeError("invalid_request", str(exc)[:300]))
        except (BrokenPipeError, ConnectionResetError):
            return
        except (OSError, TimeoutError):
            self._error(GuiRuntimeError("source_unavailable", "预检来源不可用或请求超时；未写入任何游戏文件", 503))
        except Exception:
            self._error(GuiRuntimeError("internal_error", "原生预检失败；未写入游戏或生成候选", 500))
        finally:
            if acquired:
                self.server.preflight_requests.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18799)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    runtime = PreflightRuntime(load_sources(args.sources))
    server = GuiPreflightServer(("127.0.0.1", args.port), runtime, args.html)
    print(f"GUI_PREFLIGHT_READY http://127.0.0.1:{args.port}/fvp_story_studio_prototype.html", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
