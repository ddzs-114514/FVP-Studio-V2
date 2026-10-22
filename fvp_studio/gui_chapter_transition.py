"""Persisted scene-exit transitions, independent of a game's addresses/palette."""
from copy import deepcopy
import re

SCHEMA = "fvp-gui-chapter-transition/1"
METHODS = ("cut", "black", "white", "dissolve", "mask")
DEFAULT = dict(type="black", duration_ms=800)
MASK_ID = re.compile(r"diss[0-9]{2,3}\Z")


def transition_values(value=None):
    if value is None:
        return deepcopy(DEFAULT)
    if not isinstance(value, dict) or value.get("type") not in METHODS:
        raise ValueError("衔接请选择直切、黑场、白场、画面溶解或原作遮罩。")
    expected = {"type", "duration_ms"} | ({"mask"} if value["type"] == "mask" else set())
    if set(value) != expected:
        raise ValueError("衔接设置字段不完整。")
    duration = value["duration_ms"]
    if type(duration) is not int or (duration != 0 if value["type"] == "cut" else not 100 <= duration <= 3000):
        raise ValueError("直切时间为 0；其他衔接时间须为 100～3000 毫秒整数。")
    if value["type"] == "mask" and (not isinstance(value["mask"], str) or not MASK_ID.fullmatch(value["mask"])):
        raise ValueError("请选择输出游戏登记的原作遮罩，不接受路径。")
    return deepcopy(value)


def contract():
    return dict(schema=SCHEMA, field="exit.transition", methods=list(METHODS),
        default=deepcopy(DEFAULT), duration_ms=[100, 3000],
        catalog_endpoint="chapter-transition-catalog", mask_names_are_not_directions=True,
        colour_duration_is_each_leg=True, source_exit_owns_transition=True,
        target_setup_called_once=True, audio_unchanged=True, runtime_verified=False)


class ChapterTransitionCatalog:
    """Lazy read-only target binding; no original assets are copied or changed."""
    def __init__(self, runtime):
        from threading import RLock
        self.runtime, self.cache, self.lock = runtime, {}, RLock()

    def binding(self, source_id, **options):
        from .gui_target_selection import select_source, validate_options
        from .gui_export_targets import NativeExportTargetCatalog
        from .gui_native_scene_export import bind_target
        from .native_screen_transition import NativeScreenTransition
        from .native_transition_masks import NativeTransitionMasks
        options = validate_options(options)
        source = select_source(self.runtime._source(source_id), options)
        key = (source_id, tuple(sorted(options.items())))
        with self.lock:
            stamp = NativeExportTargetCatalog._stamp(source)
            if key in self.cache and self.cache[key][0] == stamp:
                return self.cache[key][1]
            target = bind_target(source)
            screen = NativeScreenTransition(target.context)
            screen.prepare_reveal(bytearray())
            screen.prepare_colour(bytearray())
            masks, message = None, None
            try:
                masks = NativeTransitionMasks(screen, target.context.abi.native_background_backend, source.root)
                masks.prepare(bytearray())
            except (ValueError, KeyError) as exc:
                masks = None
                message = str(exc)
            target.check_unchanged()
            if NativeExportTargetCatalog._stamp(source) != stamp:
                raise ValueError("输出游戏在读取转场时发生变化。")
            result = dict(target=target, screen=screen, masks=masks, mask_message=message)
            self.cache[key] = (stamp, result)
            if len(self.cache) > 16:
                self.cache.pop(next(iter(self.cache)))
            return result

    def info(self, source_id, **options):
        from urllib.parse import urlencode
        from .gui_runtime import API_ROOT
        binding = self.binding(source_id, **options)
        masks = binding["masks"]
        items = []
        if masks:
            for entry in masks.items.values():
                items.append(dict(id=entry["id"], label=entry["label"],
                    width=entry["width"], height=entry["height"], runtime_verified=False,
                    preview_url=API_ROOT+"chapter-transition-mask?"+urlencode(
                        dict(source=source_id, mask=entry["id"], **options))))
        return dict(ok=True, schema="fvp-gui-chapter-transition-catalog/1", source=source_id,
            methods=[m for m in METHODS if m != "mask" or masks], items=items,
            message=binding["mask_message"], runtime_verified=False)

    def preview(self, source_id, mask, **options):
        from hashlib import sha256
        from io import BytesIO
        import zlib
        from PIL import Image
        from .gui_runtime import GuiRuntimeError
        masks = self.binding(source_id, **options)["masks"]
        if masks is None or mask not in masks.items:
            raise GuiRuntimeError("mask_not_found", "当前输出游戏没有这个已核对的遮罩。", 404)
        masks.check_unchanged()
        entry = masks.items[mask]
        with (masks.root / entry["archive"]).open("rb") as stream:
            stream.seek(entry["offset"])
            payload = stream.read(entry["size"])
        inflater = zlib.decompressobj()
        raw = inflater.decompress(payload[44:], entry["metadata"]["raw_length"]+1)
        if len(raw) != entry["metadata"]["raw_length"] or not inflater.eof:
            raise ValueError("原作遮罩解压长度不正确。")
        bitmap = Image.frombytes("L", (entry["width"], entry["height"]), raw)
        if entry["metadata"]["kind"] == 4:
            bitmap = bitmap.point(lambda v: 255 if v else 0)
        bitmap.thumbnail((240, 150))
        output = BytesIO()
        bitmap.save(output, format="PNG")
        masks.check_unchanged()
        data = output.getvalue()
        return data, sha256(data).hexdigest()
