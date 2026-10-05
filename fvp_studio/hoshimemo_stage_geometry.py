"""Convert the 1280x720 V2 stage into Hoshimemo's native geometry.

The browser intentionally stores simple, editor-facing values: ``x`` is an
offset from the horizontal centre, ``y`` is the bitmap's top edge and
``scale`` is a conventional 1000-based image scale.  Hoshimemo does not use
that coordinate system.  Its wrappers convert X/Y through 2.4/1.8 logical
scales, install form-dependent primitive origins and render portraits through
the V3D camera left by ``function_4383_``.

Keeping the inverse conversion here makes the UI remain pleasant to edit while
the emitted HCB receives the exact native values it expects.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Mapping

from .bin_archive import HzcMetadata
from .portrait_project import StageTransform


EDITOR_WIDTH = 1280
EDITOR_HEIGHT = 720
NATIVE_WIDTH = 1920
NATIVE_HEIGHT = 1080
LOGICAL_X_SCALE = 2.4
LOGICAL_Y_SCALE = 1.8

# function_4383_/4384_ finish with function_4411_(0, 0, -200, true).
PORTRAIT_V3D_CAMERA_Z = -200

# function_4477_ calls function_4278_ (logical X*2.4, Y*1.8) for these
# form branches.  U/S do not call PrimSetOP after the primitive is reset, so
# their native origin remains zero.
_FORM_LOGICAL_PIVOTS = {
    -1: (0, 0),
    0: (800, 1100),
    1: (800, 975),
    2: (0, 0),
}

# The generic background wrapper accepts several native canvas widths.  Its
# X/Y=(0,50), Z=1900, scale=2000, OP=(425,485) and V3D Z=-200 are fixed, so
# solving the projection against 1920x1080 always yields this exact source
# crop; the crop does not scale with the underlying HZC width.
CANONICAL_BACKGROUND_CANVAS = (2400, 1560)
CANONICAL_BACKGROUND_VIEWPORT = (12, 216, 2028, 1350)


class HoshimemoStageGeometryError(ValueError):
    """Raised when an editor transform cannot be represented safely."""


@dataclass(frozen=True)
class NativePortraitGeometry:
    transform: StageTransform
    report: Mapping[str, Any]


@dataclass(frozen=True)
class NativeBackgroundCanvasGeometry:
    canvas_width: int
    canvas_height: int
    viewport_left: int
    viewport_top: int
    viewport_right: int
    viewport_bottom: int
    canonical_profile: bool

    @property
    def viewport_width(self) -> int:
        return self.viewport_right - self.viewport_left

    @property
    def viewport_height(self) -> int:
        return self.viewport_bottom - self.viewport_top

    def to_dict(self) -> dict[str, Any]:
        return {
            "canvas": [self.canvas_width, self.canvas_height],
            "viewport": [
                self.viewport_left,
                self.viewport_top,
                self.viewport_right,
                self.viewport_bottom,
            ],
            "viewport_size": [self.viewport_width, self.viewport_height],
            "canonical_profile": self.canonical_profile,
            "exact_native_viewport": self.canonical_profile,
            "native_evidence": (
                "function_4383_/4384_: XY=(0,50), Z=1900, scale=2000, "
                "OP=(425,485), function_4411_ V3D Z=-200"
            ),
        }


def _round_nearest(value: float) -> int:
    """Round halves away from zero, avoiding Python's banker rounding."""

    if value >= 0:
        return int(math.floor(value + 0.5))
    return int(math.ceil(value - 0.5))


def _native_pivot(form_code: int, selector: int) -> tuple[int, int]:
    try:
        logical_x, logical_y = _FORM_LOGICAL_PIVOTS[int(form_code)]
    except (KeyError, TypeError, ValueError) as exc:
        raise HoshimemoStageGeometryError(
            f"不支持的 Hoshimemo 立绘尺寸类型: {form_code}"
        ) from exc
    # function_4477_ has one selector-14 adjustment in the form=1 branch.
    if int(form_code) == 1 and int(selector) == 14:
        logical_y = 950
    return (
        _round_nearest(logical_x * LOGICAL_X_SCALE),
        _round_nearest(logical_y * LOGICAL_Y_SCALE),
    )


def editor_portrait_to_native(
    editor: StageTransform,
    body: HzcMetadata,
    *,
    form_code: int,
    selector: int,
) -> NativePortraitGeometry:
    """Invert Hoshimemo's V3D projection for one editor-facing portrait."""

    if editor.scale <= 0:
        raise HoshimemoStageGeometryError("舞台立绘缩放必须大于 0")
    depth = int(editor.z) - PORTRAIT_V3D_CAMERA_Z
    if depth <= 0:
        raise HoshimemoStageGeometryError(
            "舞台立绘 Z 位于 Hoshimemo V3D 相机后方"
        )

    pivot_x, pivot_y = _native_pivot(form_code, selector)
    angle = math.radians(-int(editor.rotation))
    cosine = math.cos(angle)
    sine = math.sin(angle)
    local_center_x = float(body.offset_x) + float(body.width) / 2.0 - pivot_x
    local_center_y = float(body.offset_y) + float(body.height) / 2.0 - pivot_y
    rotated_center_x = cosine * local_center_x - sine * local_center_y
    rotated_center_y = sine * local_center_x + cosine * local_center_y

    # The desired centre is the same centre produced by the browser's
    # left=640+x-width/2, top=y and transform-origin:center rules.
    desired_local_x = 1000.0 * float(editor.x) / float(editor.scale)
    desired_local_y = (
        1000.0 * (float(editor.y) - EDITOR_HEIGHT / 2.0) / float(editor.scale)
        + float(body.height) / 2.0
    )
    native_x = _round_nearest(
        (desired_local_x - rotated_center_x) / LOGICAL_X_SCALE
    )
    native_y = _round_nearest(
        (desired_local_y - rotated_center_y) / LOGICAL_Y_SCALE
    )
    native_scale = _round_nearest(
        depth * (NATIVE_WIDTH / EDITOR_WIDTH) * float(editor.scale) / 1000.0
    )
    if native_scale <= 0:
        raise HoshimemoStageGeometryError("换算后的原生立绘缩放无效")

    native = StageTransform(
        x=native_x,
        y=native_y,
        z=int(editor.z),
        scale=native_scale,
        rotation=int(editor.rotation),
        opacity=int(editor.opacity),
    )

    projected_scale = float(native_scale) / float(depth)
    projected_center_x = NATIVE_WIDTH / 2.0 + projected_scale * (
        LOGICAL_X_SCALE * native_x + rotated_center_x
    )
    projected_center_y = NATIVE_HEIGHT / 2.0 + projected_scale * (
        LOGICAL_Y_SCALE * native_y + rotated_center_y
    )
    desired_center_x = (EDITOR_WIDTH / 2.0 + float(editor.x)) * (
        NATIVE_WIDTH / EDITOR_WIDTH
    )
    desired_center_y = (
        float(editor.y) + float(body.height) * float(editor.scale) / 2000.0
    ) * (NATIVE_HEIGHT / EDITOR_HEIGHT)

    report = {
        "schema": "fvp-studio-v2.hoshimemo-stage-geometry.v1",
        "editor_transform": editor.to_dict(),
        "native_transform": native.to_dict(),
        "body_hzc": body.to_dict(),
        "form_code": int(form_code),
        "selector": int(selector),
        "native_pivot": [pivot_x, pivot_y],
        "v3d_camera": [0, 0, PORTRAIT_V3D_CAMERA_Z],
        "logical_xy_scale": [LOGICAL_X_SCALE, LOGICAL_Y_SCALE],
        "editor_size": [EDITOR_WIDTH, EDITOR_HEIGHT],
        "native_size": [NATIVE_WIDTH, NATIVE_HEIGHT],
        "projected_center_error_pixels": [
            projected_center_x - desired_center_x,
            projected_center_y - desired_center_y,
        ],
        "native_evidence": (
            "function_4277_ scales XY by 2.4/1.8; function_4477_ installs "
            "form origins; function_4383_ leaves V3D Z=-200"
        ),
    }
    return NativePortraitGeometry(transform=native, report=report)


def background_canvas_geometry(metadata: HzcMetadata) -> NativeBackgroundCanvasGeometry:
    """Return the source-pixel rectangle shown by the native background ABI.

    Production Hoshimemo uses both 2040x1560 and 2400x1560 background canvases
    with the same fixed generic-wrapper projection.  Proportional scaling is
    only a fallback for deliberately tiny synthetic fixtures.
    """

    width = int(metadata.width)
    height = int(metadata.height)
    left, top, right, bottom = CANONICAL_BACKGROUND_VIEWPORT
    exact_viewport = (
        0 <= left - int(metadata.offset_x) < right - int(metadata.offset_x) <= width
        and 0 <= top - int(metadata.offset_y) < bottom - int(metadata.offset_y) <= height
    )
    if exact_viewport:
        viewport_left = left - int(metadata.offset_x)
        viewport_top = top - int(metadata.offset_y)
        viewport_right = right - int(metadata.offset_x)
        viewport_bottom = bottom - int(metadata.offset_y)
    else:
        canonical_width, canonical_height = CANONICAL_BACKGROUND_CANVAS
        scale_x = width / float(canonical_width)
        scale_y = height / float(canonical_height)
        viewport_left = _round_nearest(left * scale_x) - int(metadata.offset_x)
        viewport_top = _round_nearest(top * scale_y) - int(metadata.offset_y)
        viewport_right = _round_nearest(right * scale_x) - int(metadata.offset_x)
        viewport_bottom = _round_nearest(bottom * scale_y) - int(metadata.offset_y)
    if not (
        0 <= viewport_left < viewport_right <= width
        and 0 <= viewport_top < viewport_bottom <= height
    ):
        raise HoshimemoStageGeometryError(
            "目标背景 HZC 的尺寸/偏移无法容纳原生 16:9 可视窗口"
        )
    return NativeBackgroundCanvasGeometry(
        canvas_width=width,
        canvas_height=height,
        viewport_left=viewport_left,
        viewport_top=viewport_top,
        viewport_right=viewport_right,
        viewport_bottom=viewport_bottom,
        canonical_profile=exact_viewport,
    )


__all__ = [
    "CANONICAL_BACKGROUND_CANVAS",
    "CANONICAL_BACKGROUND_VIEWPORT",
    "HoshimemoStageGeometryError",
    "NativeBackgroundCanvasGeometry",
    "NativePortraitGeometry",
    "PORTRAIT_V3D_CAMERA_Z",
    "background_canvas_geometry",
    "editor_portrait_to_native",
]
