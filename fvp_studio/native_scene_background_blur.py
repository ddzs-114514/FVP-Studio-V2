"""Own a proven original blur pair in a generic scene, including branch state.

The source HCB proves the sharp/blur pair; the TARGET proves the load/alpha
calls. Cross-game payloads keep their exact pixels in the target's native
archive route. This is neither an image blur nor original-scene restoration.
"""
from copy import deepcopy
from pathlib import Path
import struct

from .gui_background_blur import event_values
from .hoshimemo_scene_hook import _push_global, _pop_global
from .gui_runtime import fingerprint
from .native_background_blur import NativeBackgroundBlur
from .native_background_pairs import lookup
from .performance_compile import resource_reference, rounded
from .performance_install import _safe


class NativeSceneBackgroundBlur:
    def __init__(self, target, output, imports):
        self.target, self.output, self.imports = target, output, imports
        self.binding = NativeBackgroundBlur(target.context)
        if (imports is not None and (imports.root != target.root
                or imports.routes.get("background") != self.binding.backend.archive_selectors)):
            raise ValueError("模糊背景打包器不属于当前目标的背景路由。")
        self.snapshot = self.binding.snapshot
        output.extend(self.snapshot["snapshot"])
        self.loader, self.loader_report = self.binding.prepare_loader(output)
        self.background, self.current, self.pending = None, None, False
        self.references, self.operations, self.stamps = [], [], {}
        self.portrait_ownership = None
        self._portrait_cache_snapshot, self._portrait_cache_restore = b"", b""

    def bind_portraits(self, slots):
        self.portrait_ownership = self.binding.assert_portrait_ownership(slots)
        protected = self.portrait_ownership["protected_shared_loader_cache_ids"]
        self._portrait_cache_snapshot = b"".join(_push_global(g) for g in protected)
        self._portrait_cache_restore = b"".join(_pop_global(g) for g in reversed(protected))

    def emit_loader(self, code):
        # The proven path has no asynchronous script spawn and touches no owned
        # portrait engine handle. Keep current scene caches, not the old story's
        # values. Native calls / geometry / original source bytes are unchanged.
        self.output.extend(self._portrait_cache_snapshot + code + self._portrait_cache_restore)

    def background_loaded(self, event, reference):
        self.background = dict(archive=str(_safe(Path(event["archive"]), file=True, independent=False)),
            resource=event["resource"], fit=event["fit"],
            target_archive=reference["target_archive"], target_resource=reference["target_resource_name"])
        self.current = None

    def state(self):
        return dict(background=deepcopy(self.background), current=deepcopy(self.current))

    def restore_compiler_state(self, state):
        if self.pending:
            raise ValueError("分支状态切换前须等待模糊渐变完成。")
        self.background, self.current = deepcopy(state["background"]), deepcopy(state["current"])

    def join(self):
        if not self.pending:
            return
        binding = self.binding
        start = len(binding.source.original_bytes) + len(self.output)
        test = binding.syscall("MotionAlphaTest", (binding.primitive,)) + b"\x14"
        wait = binding.syscall("ThreadWait", (1,))
        finish = start + len(test) + 5 + len(wait) + 5
        self.output.extend(test + b"\x07" + struct.pack("<I", finish)
            + wait + b"\x06" + struct.pack("<I", start))
        self.pending = False

    def clear(self):
        self.join()
        if self.current is not None:
            binding = self.binding
            self.output.extend(binding.alpha_code(self.current["alpha"], 0, 0))
            self.output.extend(binding.syscall("GraphLoad", (binding.primitive, None)))
            self.current = None

    def reassert(self):
        # Native body loads/menus may touch shared scene caches. Preserve the
        # authored manual layer after those completed transactions; never fake
        # a camera move to obtain the requested strength.
        self.join()
        if self.current is not None:
            alpha = self.current["alpha"]
            self.output.extend(self.binding.alpha_code(alpha, alpha, 0))

    def emit(self, event):
        self.output.extend(self.prepare_event(event))

    def prepare_event(self, event):
        """Prepare pixels now; return the nonblocking alpha launch for a frontier."""
        fields = event_values("GuiBackgroundBlur", {k: v for k, v in event.items() if k != "kind"})
        sharp = _safe(Path(fields["sharp_archive"]), file=True, independent=False)
        path = _safe(Path(fields["archive"]), file=True, independent=False)
        background = self.background
        if (background is None or (str(sharp), fields["sharp_resource"], fields["fit"])
                != (background["archive"], background["resource"], background["fit"])):
            raise ValueError("请先显示这张清晰背景，再调节它的原作模糊层。")
        evidence, hcb, stamp = lookup(sharp.parent, fields["sharp_resource"])
        if path != sharp or fields["resource"] != evidence["blur_resource"]:
            raise ValueError("模糊图并非当前背景在原作里的同归档配对。")
        if hcb in self.stamps and self.stamps[hcb] != stamp:
            raise ValueError("背景配对脚本在生成期间发生变化。")
        self.stamps[hcb] = stamp
        _, sharp_ref = resource_reference(sharp, fields["sharp_resource"])
        _, blur_ref = resource_reference(path, fields["resource"])
        shape = ("kind", "width", "height", "offset_x", "offset_y", "frame_count")
        if (any(sharp_ref[k] != blur_ref[k] for k in shape)
                or blur_ref["kind"] != 0 or blur_ref["frame_count"] != 1):
            raise ValueError("原作清晰/模糊背景的画布不一致，不缩放修补配对。")
        if self.imports is not None:
            reference = self.imports.bind("background", path, fields["resource"],
                target_archive=background["target_archive"])
        else:
            if path.parent != self.target.root or path.name.casefold() != background["target_archive"]:
                raise ValueError("跨游戏模糊背景缺少当前目标的素材打包器。")
            reference = dict(blur_ref, target_archive=path.name.casefold(), target_resource_name=fields["resource"])
            self.stamps[path] = fingerprint(path)
        identity = (reference["target_archive"], reference["target_resource_name"], fields["fit"])
        self.join()
        if self.current is None or self.current["identity"] != identity:
            self.clear()
            self.emit_loader(self.binding.load_code(self.loader, identity[1], identity[0]))
            self.output.extend(self.binding.alpha_code(0, 0, 0))
            self.current = dict(identity=identity, alpha=0)
        previous, alpha = self.current["alpha"], rounded(fields["amount"] * 255 / 100)
        launch = self.binding.alpha_code(previous, alpha, fields["duration_ms"])
        self.current["alpha"] = alpha
        self.pending = bool(fields["duration_ms"])
        self.references.append(dict(reference, native_pair=deepcopy(evidence)))
        self.operations.append(dict(identity=identity, start_alpha=previous, target_alpha=alpha,
            duration_ms=fields["duration_ms"], native_pair_hcb=evidence["hcb_sha256"]))
        self.check_unchanged()
        return launch

    def check_unchanged(self):
        for path, expected in self.stamps.items():
            if fingerprint(path) != expected:
                raise ValueError("生成期间背景或配对脚本发生变化。")
        if self.imports is not None:
            self.imports.check_unchanged()

    def finish(self):
        self.clear()
        self.output.extend(self.snapshot["restore"])
        self.check_unchanged()

    def report(self):
        return dict(self.binding.report(), loader_copy=deepcopy(self.loader_report),
            portrait_ownership=deepcopy(self.portrait_ownership),
            operations=deepcopy(self.operations), branch_state_includes_manual_blur=True,
            original_image_pixels_preserved=True, uses_generated_blur=False,
            original_engine_resources_restored=False, runtime_verified=False)
