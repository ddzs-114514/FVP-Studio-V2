"""Camera authoring bounds derived from a target plane and occupied depths.

The near distance is an editor safety policy, not an engine zoom limit.
V3DMotion stores XYZ in signed 16-bit fields even when V3DSet accepts more.
Keep percent validation separate from target/scene validation; a schema bound
alone must never be advertised as a usable zoom for a particular scene.
"""
from __future__ import annotations

SCHEMA = "fvp-camera-zoom-range/1"
COORD_MIN, COORD_MAX = -32768, 32767
ZOOM_MIN = 80
# Largest possible plane-to-base distance / smallest supported near distance.
ZOOM_SCHEMA_MAX = (COORD_MAX - COORD_MIN) * 100 // 64


def zoom_range(plane, baseline, viewport, *, minimum_layer_distance=64, depths=()):
    if (type(plane) is not int or not 0 < plane <= COORD_MAX
            or len(baseline) != 3 or any(type(v) is not int or not COORD_MIN <= v <= COORD_MAX for v in baseline)
            or baseline[2] >= plane or type(minimum_layer_distance) is not int
            or not 64 <= minimum_layer_distance <= COORD_MAX
            or len(viewport) != 2 or any(type(v) is not int or not 1 <= v <= 16384 for v in viewport)):
        raise ValueError("镜头参考平面或原生坐标范围未确认。")
    depths = tuple(depths)
    if any(type(v) is not int or not COORD_MIN <= v <= COORD_MAX for v in depths):
        raise ValueError("在场图层景深超出原生坐标范围。")
    limit = min((plane, *depths)) - minimum_layer_distance
    maximum = (plane - baseline[2]) * 100 // (plane - limit)
    return dict(schema=SCHEMA, min_percent=ZOOM_MIN, max_percent=maximum,
        reference_plane_z=plane, baseline=list(baseline), viewport=list(viewport),
        minimum_layer_distance=minimum_layer_distance,
        coordinate_min=COORD_MIN, coordinate_max=COORD_MAX,
        dynamic_scene_depth=True, runtime_verified=False)


def check_camera_path(current, target, depths, *, minimum_layer_distance=64):
    """Validate actual native endpoints before emitting any motion bytecode."""
    if (len(current) != 3 or len(target) != 3
            or any(type(v) is not int or not COORD_MIN <= v <= COORD_MAX
                   for v in (*current, *target))):
        raise ValueError("镜头坐标超出原生运动的有符号16位范围；不会截断或回绕。")
    near = max(current[2], target[2])
    for z in depths:
        if type(z) is not int or not COORD_MIN <= z <= COORD_MAX:
            raise ValueError("在场图层景深超出原生坐标范围。")
        if z - near < minimum_layer_distance:
            raise ValueError("镜头取景会越过在场图层或进入安全边界；请调低倍率或调整景深。")


def camera_near_z(camera):
    """Near-most camera endpoint while a monotonic type-2/3 move is pending."""
    start = getattr(camera, "_motion_start", camera.current)
    return max(camera.current[2], start[2]) if getattr(camera, "pending", False) else camera.current[2]
