"""Editor framing -> explicit target-native sprite geometry.

Import height is already resolved by the source-size bridge. This layer does
not estimate character height, fit heads, resample art or use a story camera
to infer size. It maps that locked editor height to a target-proven viewport,
using an explicitly reset V3D baseline and the HZC composition origin.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from .bin_archive import hzc_metadata
from .native_import_size_discovery import NativeSizeDiscoveryError, extract_exe_viewport
from .native_legacy_size_discovery import extract_legacy_engine_rs
from .native_primitive_scale import extract_modern_rs_limits


SCHEMA = "fvp-native-portrait-scene-geometry/1"
EDITOR_VIEWPORT = (1280, 720)


def _number(value, low, high, label):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError(label + "无效。")
    return value


def _round(value):
    return int(math.floor(value + .5)) if value >= 0 else int(math.ceil(value - .5))


@dataclass(frozen=True)
class NativePortraitGeometry:
    viewport: tuple[int, int]
    scale_range: tuple[int, int]
    evidence: dict
    camera: tuple[int, int, int] = (0, 0, 0)

    @classmethod
    def from_executable(cls, raw, mode, *, camera=(0, 0, 0)):
        if (not isinstance(camera, (list, tuple)) or len(camera) != 3
                or any(type(v) is not int for v in camera)):
            raise ValueError("目标基准相机参数未确定。")
        viewport = extract_exe_viewport(raw, mode)
        failures = []
        for extractor in (extract_modern_rs_limits, extract_legacy_engine_rs):
            try:
                limits = extractor(raw)
                break
            except NativeSizeDiscoveryError as exc:
                failures.append(str(exc))
        else:
            raise ValueError("目标原生缩放范围尚未识别：" + "; ".join(failures))
        return cls(tuple(viewport["viewport"]), tuple(limits["native_scale_range"]),
                   dict(viewport=viewport, native_scale=limits), tuple(camera))

    def portrait(self, event, body_payload):
        meta = hzc_metadata(body_payload)
        if meta.kind != 1 or meta.frame_count != 1 or min(meta.width, meta.height) <= 0:
            raise ValueError("需要单帧原生身体素材。")
        height = _number(event.get("height"), 1, 10000, "保存的显示高度")
        x = _number(event.get("stage_x"), -640, 1920, "保存的横坐标")
        bottom = _number(event.get("bottom_y"), -720, 1800, "保存的下缘坐标")
        z = _number(event.get("depth"), 500, 2400, "目标景深")
        alpha = _number(event.get("alpha", 255), 0, 255, "透明度")
        # Uniform VERTICAL scale preserves full/half-body framing even when
        # exporting the 16:9 editor to a 4:3 FVP target. X placement, separately,
        # remains a normalised fraction of the target viewport width.
        ratio = height * self.viewport[1] / EDITOR_VIEWPORT[1] / meta.height
        distance = z - self.camera[2]
        if distance <= 0:
            raise ValueError("立绘位于目标基准相机后方。")
        scale = _round(distance * ratio)
        if not self.scale_range[0] <= scale <= self.scale_range[1]:
            raise ValueError("保存的立绘大小超出目标原生缩放范围；请调整景深，不会夹紧或猜测大小。")
        nx = _round((x - EDITOR_VIEWPORT[0] / 2) * self.viewport[0]
                    / EDITOR_VIEWPORT[0] * distance / scale + 1000 * self.camera[0] / scale)
        ny = _round((bottom - EDITOR_VIEWPORT[1] / 2) * self.viewport[1]
                    / EDITOR_VIEWPORT[1] * distance / scale + 1000 * self.camera[1] / scale)
        pivot = [_round(meta.offset_x + meta.width / 2), meta.offset_y + meta.height]
        rendered_height = meta.height * scale / distance
        result = dict(pivot=pivot, x=nx, y=ny, z=int(z), scale=scale,
                      rotation=0, alpha=int(alpha))
        report = dict(schema=SCHEMA, native_viewport=list(self.viewport),
            native_scale_range=list(self.scale_range), baseline_camera=list(self.camera),
            native_geometry=result, authored_height=height,
            target_height=height * self.viewport[1] / EDITOR_VIEWPORT[1],
            projected_height=rendered_height,
            projected_height_error=rendered_height - height * self.viewport[1] / EDITOR_VIEWPORT[1],
            image_resampled=False, face_alignment_used=False,
            source_size_rule_changed=False, story_camera_used_for_import_size=False)
        return result, report

    def describe(self):
        return dict(schema=SCHEMA, viewport=list(self.viewport),
                    scale_range=list(self.scale_range), evidence=self.evidence,
                    explicit_baseline_camera=list(self.camera), runtime_verified=False)

    def native_xy(self, state, x, y):
        """Map an authored position using the actor's actual current transform."""
        x = _number(x, -640, 1920, "目标横坐标")
        y = _number(y, -720, 1800, "目标下缘坐标")
        distance = state["z"] - self.camera[2]
        if distance <= 0 or min(state["sx"], state["sy"]) <= 0:
            raise ValueError("当前立绘变换无法映射位置。")
        return (_round((x - 640) * self.viewport[0] / 1280 * distance / state["sx"]
                       + 1000 * self.camera[0] / state["sx"]),
                _round((y - 360) * self.viewport[1] / 720 * distance / state["sy"]
                       + 1000 * self.camera[1] / state["sy"]))

    def editor_position(self, state):
        distance = state["z"] - self.camera[2]
        if distance <= 0:
            raise ValueError("立绘处于镜头后方。")
        return (640 + (state["x"] * state["sx"] - 1000 * self.camera[0])
                / distance * 1280 / self.viewport[0],
                360 + (state["y"] * state["sy"] - 1000 * self.camera[1])
                / distance * 720 / self.viewport[1])
