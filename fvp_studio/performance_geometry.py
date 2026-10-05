"""Shared authoring/compile projection contract for ordinary Hoshimemo bitmaps.

Units are explicit: the editor is 1280x720, host canvas 1920x1080,
actor/camera wrapper XY factors are 2.4/1.8, and R is NOT degrees.
This is a bounded mathematical preview, not a GPU/runtime emulator.
"""
from __future__ import annotations

import math

EDITOR = (1280, 720)
HOST = (1920, 1080)
WRAPPER = (2.4, 1.8)
SAFE_DEPTH = 100


def nearest(value):
    return math.floor(value + .5) if value >= 0 else math.ceil(value - .5)


def shot_camera(center_x, center_y, zoom, plane=1900, baseline=-200):
    """A rectangle in the baseline BG/CG reference plane -> native wrapper XYZ.

    The reference determines framing only. V3D still affects ALL enabled planes.
    Preserve different depths' parallax; never uniformly scale the finished frame.
    """
    distance = plane - baseline
    return [nearest((center_x - 640) * 1.5 * distance / 1000 / WRAPPER[0]),
            nearest((center_y - 360) * 1.5 * distance / 1000 / WRAPPER[1]),
            nearest(plane - distance * 100 / zoom)]


def projection_matrix(state, meta, camera):
    d = state['z'] - camera[2]
    if d < SAFE_DEPTH or min(state['sx'], state['sy']) <= 0:
        raise ValueError('图元与镜头深度距离不足，拒绝退化投影')
    # The fixed EXE uses R / 3600 * pi, NOT R / 1800 * pi.
    angle = state['r'] / 3600 * math.pi
    c, s = math.cos(angle), math.sin(angle)
    sx, sy = state['sx'] / d / 1.5, state['sy'] / d / 1.5
    qx, qy = meta['offset_x'] - state['pivot'][0], meta['offset_y'] - state['pivot'][1]
    return [sx*c, sy*s, -sx*s, sy*c,
            640 - .5/1.5 + sx*(c*qx-s*qy+state['x']*2.4) - camera[0]*2.4*1000/d/1.5,
            360 - .5/1.5 + sy*(s*qx+c*qy+state['y']*1.8) - camera[1]*1.8*1000/d/1.5]


def projected_rect_bounds(state, meta, camera, rect):
    """Project a body-local rectangle, including source Parts/face offsets."""
    a, b, c, d, x, y = projection_matrix(state, meta, camera)
    ox = x + a * rect.get('offset_x', 0) + c * rect.get('offset_y', 0)
    oy = y + b * rect.get('offset_x', 0) + d * rect.get('offset_y', 0)
    w, h = rect['width'], rect['height']
    xs = (ox, ox + a*w, ox + c*h, ox + a*w + c*h)
    ys = (oy, oy + b*w, oy + d*h, oy + b*w + d*h)
    left, right, top, bottom = min(xs), max(xs), min(ys), max(ys)
    return dict(left=left, right=right, top=top, bottom=bottom,
                width=right-left, height=bottom-top)


def projected_anchor(state, camera):
    d = state['z'] - camera[2]
    if d < SAFE_DEPTH:
        raise ValueError('图元与镜头过近')
    return [640 + (state['x']*2.4*state['sx']-camera[0]*2.4*1000)/d/1.5,
            360 + (state['y']*1.8*state['sy']-camera[1]*1.8*1000)/d/1.5]
