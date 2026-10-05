"""Read-only, target-bound capabilities for the explicit GUI export picker.

Registration is not compatibility. Probe the same native adapters used by
scene output in RAM, never compile a game copy, write a BIN or launch an EXE.
Do not use title switches, foreign addresses, or source-size guesses.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from threading import RLock

from .gui_runtime import GuiRuntimeError, fingerprint
from .gui_scene_export import ExportError
from .gui_native_scene_export import bind_target, select_hook, SCOPE
from .native_graphics_imports import NativeGraphicsImports
from .native_portrait_alpha import NativePortraitAlpha
from .native_portrait_motion import NativePortraitMotion
from .native_portrait_scene import NativePortraitScene
from .native_portrait_slots import allocate_native_slots


SCHEMA = "fvp-gui-export-target/1"


class NativeExportTargetCatalog:
    def __init__(self, runtime):
        self.runtime, self._cache, self._lock = runtime, {}, RLock()

    @staticmethod
    def _stamp(source):
        root = Path(source.root)
        files = tuple(sorted((p.name, fingerprint(p)) for p in root.iterdir()
            if p.is_file() and p.suffix.casefold() in {".hcb", ".bch", ".exe", ".dll", ".bin"}))
        registration = tuple(getattr(source, key, None) for key in (
            "target_script", "target_executable", "target_encoding",
            "target_analysis_encoding", "target_hook_offset"))
        return fingerprint(root), registration, files

    def info(self, source_id):
        source = self.runtime._source(source_id)
        if source_id == "hoshi":
            raise GuiRuntimeError("invalid_request", "星空沿用现有的独立测试副本输出。")
        with self._lock:
            before = self._stamp(source)
            cached = self._cache.get(source_id)
            if cached and cached[0] == before:
                return deepcopy(cached[1])
            report = self._inspect(source)
            if before != self._stamp(source):
                raise GuiRuntimeError("source_changed", "游戏文件刚发生变化，请重新选择输出游戏。", 409)
            self._cache[source_id] = before, deepcopy(report)
            return report

    @staticmethod
    def _inspect(source):
        report = dict(ok=True, schema=SCHEMA, source=source.id, name=source.name, scope=SCOPE,
            status="unavailable", allowed_features=[], native_motion_channels=[],
            portrait=dict(supported=False, capacity=0, expression_default_ms=200,
                body_swap_blend=False, body_swap_duration_control=False,
                instant_body_swap_proven=False),
            encoding_confirmed=False, runtime_verified=False, probe_is_read_only=True,
            writes_game_files=False, standalone_startup=False, chapter_export=False,
            limitations=["测试场景插在原作某句台词前，保留原作开头；不是启动后直接进入测试场景。",
                "结束后旧剧情图像的恢复尚未接完，请只在新生成的测试副本里使用。",
                "其他目标的 CG、镜头、模糊、整幕转场、声音、选项和整章输出仍未接入。"])
        try:
            target = bind_target(source)
            anchor = select_hook(target.context, getattr(source, "target_hook_offset", None))
        except ExportError as exc:
            report.update(status="needs_configuration" if exc.code in {
                "target_selection_needed", "target_encoding_needed", "invalid_target_registration"}
                else "unavailable", code=exc.code, message=str(exc))
            return report
        except (ValueError, KeyError):
            report.update(code="native_target_unavailable", message="此版本的原生输出入口尚未接通。")
            return report
        context = target.context
        report.update(status="bound", target_id=context.target_id,
                      encoding_confirmed=target.encoding_confirmed,
                      allowed_features=["native_speech", "wait"])
        if not target.encoding_confirmed:
            report["limitations"].append("输出中文或日文台词前，请选择这份游戏脚本使用的文字编码。")
        backend = context.abi.native_background_backend
        if backend is not None:
            report["allowed_features"].extend(["background", "background_change"])
        else:
            # The current native compiler requires a bound background chain,
            # including for text-only scenes. Do not advertise a false route.
            report.update(status="unavailable", allowed_features=[],
                code="background_not_supported", message="此版本的原生背景加载尚未接通。")
            return report
        record = target.discovery.get("profile_seed", {}).get("native_symbols", {}).get("portrait_dispatcher")
        if record:
            routes = {record["resource_namespace"].rstrip("/\\").casefold() + ".bin": None}
            try:
                imports = NativeGraphicsImports(target.root, {"portrait": routes})
                scene = NativePortraitScene(target, [dict(kind="Portrait", actor=1)],
                                            anchor, imports, bytearray())
                supported_counts = []
                for count in range(1, 5):
                    try:
                        allocate_native_slots(scene.loader.catalog.slots,
                                              ["probe_actor_" + str(i) for i in range(count)])
                        supported_counts.append(count)
                    except ValueError:
                        continue
                if supported_counts:
                    report["portrait"].update(supported=True, capacity=max(supported_counts),
                                              supported_actor_counts=supported_counts)
                    report["allowed_features"].extend(["target_native_portrait",
                        "native_expression_blend", "native_body_swap", "portrait_hide"])
                source_doc, analysis_doc = context.document, context.analysis_document
                for channel in ("alpha", "xy", "z", "s2"):
                    try:
                        if channel == "alpha":
                            NativePortraitAlpha(source_doc, analysis_doc, runtime_context=context)
                        else:
                            NativePortraitMotion(source_doc, analysis_doc, {channel}, runtime_context=context)
                        report["native_motion_channels"].append(channel)
                    except ValueError:
                        continue
            except (ValueError, KeyError):
                report["portrait"]["message"] = "此版本的立绘加载、站位或独立角色槽尚未接通。"
        if report["portrait"]["supported"]:
            report["limitations"].append("换身体沿用原作处理，目前不能指定换装渐变时长；旋转尚未接入。")
        else:
            report["limitations"].append("此版本暂不能输出角色立绘，仍可使用已接通的背景和台词。")
        target.check_unchanged()
        return report
