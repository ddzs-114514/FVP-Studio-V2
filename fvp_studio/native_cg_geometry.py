"""Full-frame CG geometry from the current executable and native CG planes.

Image pixels and the portrait source-size bridge are unchanged. The caller
must explicitly install the zero V3D baseline, prepare each resource before
showing it, and own/cache the native transaction. This calculation alone does
not enable the scene exporter or prove a hidden loading path.
"""
from dataclasses import dataclass
from copy import deepcopy

from .native_portrait_geometry import NativePortraitGeometry, _number, _round


SCHEMA = "fvp-native-cg-geometry/1"
EDITOR_VIEWPORT = (1280, 720)


@dataclass(frozen=True)
class NativeCGGeometry:
    primitive: NativePortraitGeometry
    planes: dict

    @classmethod
    def from_target(cls, target, backend):
        if (backend.source is not target.context.document
                or backend.analysis is not target.context.analysis_document):
            raise ValueError("CG 几何与目标原生脚本不是同一份。")
        raw = (target.root / target.executable).read_bytes()
        geometry = NativePortraitGeometry.from_executable(raw, backend.analysis.header.game_mode,
            camera=(0, 0, 0))
        target.check_unchanged()
        return cls(geometry, deepcopy(backend.planes))

    def frame(self, primitive, metadata, *, x=0, y=0, percentage=100, depth_zoom=False):
        if type(depth_zoom) is not bool:
            raise ValueError("CG 景深构图方式必须明确。")
        if (type(primitive) is not int or primitive not in self.planes
                or self.primitive.camera != (0, 0, 0)):
            raise ValueError("CG 图元或原生基准镜头未明确设置。")
        z = self.planes[primitive]
        if type(z) is not int or z <= 0:
            raise ValueError("CG 景深须来自这个目标的原生调用。")
        if (not isinstance(metadata, dict) or type(metadata.get("kind")) is not int or metadata["kind"] != 0
                or type(metadata.get("frame_count")) is not int or metadata["frame_count"] != 1
                or any(type(metadata.get(k)) is not int for k in ("width", "height", "offset_x", "offset_y"))
                or not 1 <= metadata["width"] <= 65535 or not 1 <= metadata["height"] <= 65535):
            raise ValueError("CG 需要完整单帧原生图像，不能用立绘或差分页代替。")
        x, y = _number(x, -1280, 1280, "CG 横向构图"), _number(y, -720, 720, "CG 纵向构图")
        percentage = _number(percentage, 10, 400, "CG 构图倍率")
        w, h = metadata["width"], metadata["height"]
        vw, vh = self.primitive.viewport
        native_depth = z
        baseline = native_depth * min(vw/w, vh/h)
        exact = baseline if depth_zoom else baseline * percentage/100
        scale = _round(exact)
        if not self.primitive.scale_range[0] <= scale <= self.primitive.scale_range[1]:
            raise ValueError("CG 完整显示所需倍率超出当前引擎范围；不会静默夹紧或缩放图片。")
        if depth_zoom:
            z = _round(native_depth * 100 / percentage)
            if not 1 <= z < 2**31:
                raise ValueError("CG 构图景深超出目标原生范围。")
        result = dict(pivot=[_round(metadata["offset_x"]+w/2), _round(metadata["offset_y"]+h/2)],
            x=_round(x*vw/EDITOR_VIEWPORT[0]*z/scale),
            y=_round(y*vh/EDITOR_VIEWPORT[1]*z/scale),
            z=z, scale=scale, rotation=0, alpha=0)
        if any(not -2**31 <= v < 2**31 for v in (*result["pivot"], result["x"], result["y"])):
            raise ValueError("CG 构图超出原生整数范围。")
        projected = [w*scale/z, h*scale/z]
        desired = [w*baseline/native_depth*percentage/100, h*baseline/native_depth*percentage/100]
        report = dict(schema=SCHEMA, primitive=primitive, native_viewport=[vw, vh],
            native_scale_range=list(self.primitive.scale_range), native_depth=z,
            native_geometry=deepcopy(result), authored=dict(x=x, y=y, percentage=percentage),
            projected_dimensions=projected, desired_dimensions=desired,
            scale_quantization_error=[projected[i]-desired[i] for i in range(2)],
            baseline_camera=[0, 0, 0], baseline_must_be_installed_explicitly=True,
            prepared_alpha=0, source_size_rule_changed=False, image_resampled=False,
            zoom_channel="z" if depth_zoom else "scale", reference_depth=native_depth,
            hidden_initialization_proven=False, scene_export_connected=False, runtime_verified=False)
        return result, report

    def describe(self):
        return dict(schema=SCHEMA, native_primitive_geometry=self.primitive.describe(),
            native_planes=deepcopy(self.planes), baseline_camera=[0, 0, 0],
            portraits_unchanged=True, image_resampled=False, scene_export_connected=False,
            runtime_verified=False)
