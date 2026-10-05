"""Bounded, read-only BG/event-CG bridge for the independent GUI.

Catalog classification is directory/name evidence, not visual acceptance.
Decode the frozen HZC payload, not the path-only decoder cache: the PNG must
belong to the SHA which the user selected even after archive replacements.
"""
from collections import OrderedDict
from hashlib import sha256
from io import BytesIO
import re
from threading import RLock
from urllib.parse import urlencode
import zlib

from .bin_archive import archive_entry_table_file, hzc_metadata
from .gui_runtime import API_ROOT, GuiRuntimeError, SHA_RE, fingerprint, integer
from .resource_builder import _decode_hzc_frame

SCHEMA = "fvp-gui-graphic/1"
ARCHIVES = {
    "background": ("graph_bg.bin", "graph.bin"),
    "cg": ("graph_vis.bin", "graph_vis1.bin", "graph_vis2.bin", "graph.bin"),
}
BG_NAME = re.compile(r"^(?:bg|back|background)(?:[_\-0-9]|$)", re.I)
CG_NAME = re.compile(r"^(?!(?:album|sys|window|chr|char|face|bg))(?:.+[_-])(?:e|ev|cg|h)[0-9]", re.I)
MAX_PIXELS = 24_000_000
MAX_DECODE_BYTES = 256 * 1024 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_PNG_CACHE_BYTES = 64 * 1024 * 1024


class GuiGraphics:
    def __init__(self, runtime):
        self.runtime = runtime
        self._tables = {}
        self._pngs = OrderedDict()
        self._png_bytes = 0
        self._lock = RLock()

    @staticmethod
    def descriptor(source):
        result = source.descriptor()
        result["graphics_archives"] = {
            category: [name for name in names if (source.root / name).is_file()
                       and (source.root / name).resolve().parent == source.root]
            for category, names in ARCHIVES.items()
        }
        return result

    @staticmethod
    def _category(category):
        if not isinstance(category, str) or category not in ARCHIVES:
            raise GuiRuntimeError("invalid_request", "素材分类须为 background 或 cg")

    def _archive(self, source_id, category, archive):
        self._category(category)
        source = self.runtime._source(source_id)
        if not isinstance(archive, str) or archive not in ARCHIVES[category]:
            raise GuiRuntimeError("invalid_request", "档案不在该分类的只读允许列表内")
        path = source.root / archive
        if not path.is_file():
            raise GuiRuntimeError("archive_unavailable", "所选素材档案不存在", 404)
        if path.resolve().parent != source.root:
            raise GuiRuntimeError("source_changed", "素材档案已指向注册目录之外", 409)
        return source, path

    @staticmethod
    def _basis(category, archive, resource):
        if category == "background":
            if archive == "graph_bg.bin":
                return "background_archive"
            return "background_name" if BG_NAME.match(resource) else None
        if archive.startswith("graph_vis"):
            return "event_archive"
        return "event_name_candidate" if CG_NAME.match(resource) else None

    def _table(self, path):
        stamp = fingerprint(path)
        with self._lock:
            cached = self._tables.get(str(path))
            if cached and cached[0] == stamp:
                return cached[1], stamp
        rows = tuple(archive_entry_table_file(path))
        names = [row[2] for row in rows]
        if len(names) != len(set(names)):
            raise GuiRuntimeError("ambiguous_resource", "BIN 中资源重名，拒绝选择", 422)
        if fingerprint(path) != stamp:
            raise GuiRuntimeError("source_changed", "素材档案在读取目录时变化", 409)
        with self._lock:
            self._tables[str(path)] = (stamp, rows)
        return rows, stamp

    def catalog(self, source_id, category, q="", offset=0, limit=40, archive=None):
        self._category(category)
        source = self.runtime._source(source_id)
        if not isinstance(q, str) or len(q) > 128 or "\x00" in q:
            raise GuiRuntimeError("invalid_request", "检索文字过长或不合法")
        offset = integer(offset, "offset", 0, 1_000_000)
        limit = integer(limit, "limit", 1, 60)
        if archive is not None:
            self._archive(source_id, category, archive)
            names = (archive,)
        else:
            names = self.descriptor(source)["graphics_archives"][category]
        items = []
        for name in names:
            _, path = self._archive(source_id, category, name)
            rows, stamp = self._table(path)
            for _, _, resource in rows:
                basis = self._basis(category, name, resource)
                if basis and q.casefold() in resource.casefold():
                    items.append(dict(archive=name, resource=resource,
                                      display_name=resource, category_basis=basis))
            if fingerprint(path) != stamp:
                raise GuiRuntimeError("source_changed", "素材档案在检索时变化", 409)
        return dict(ok=True, source=source.id, category=category, offset=offset,
                    limit=limit, total=len(items), items=items[offset:offset + limit])

    def _entry(self, source_id, category, archive, resource):
        source, path = self._archive(source_id, category, archive)
        if (not isinstance(resource, str) or not resource or len(resource) > 256
                or "\x00" in resource or not self._basis(category, archive, resource)):
            raise GuiRuntimeError("graphic_not_found", "该素材不属于选定分类", 404)
        rows, stamp = self._table(path)
        found = [(i, row) for i, row in enumerate(rows) if row[2] == resource]
        if len(found) != 1:
            raise GuiRuntimeError("graphic_not_found", "选定资源不存在或重名", 404)
        index, (offset, size, _) = found[0]
        if size > MAX_PAYLOAD_BYTES:
            raise GuiRuntimeError("image_too_large", "单个素材超过当前只读预览上限", 422)
        with path.open("rb") as stream:
            stream.seek(offset)
            payload = stream.read(size)
        if len(payload) != size or fingerprint(path) != stamp:
            raise GuiRuntimeError("source_changed", "素材档案在读取资源时变化", 409)
        try:
            meta = hzc_metadata(payload, validate_pixels=False).to_dict()
        except ValueError as exc:
            raise GuiRuntimeError("graphic_unresolved", "选定资源不是可解析的 HZC 图像", 422) from exc
        if meta["kind"] not in (0, 1, 2):
            raise GuiRuntimeError("graphic_unresolved", "此资源为遮罩，不能作为背景或事件 CG", 422)
        if (meta["width"] * meta["height"] > MAX_PIXELS
                or meta["frame_count"] > 256 or meta["raw_length"] > MAX_DECODE_BYTES):
            raise GuiRuntimeError("image_too_large", "素材画布或解压大小超过只读预览上限", 422)
        return source, path, stamp, index, payload, meta

    @staticmethod
    def _url(source, category, archive, resource, digest, frame=0):
        return API_ROOT + "graphic.png?" + urlencode(dict(source=source,
            category=category, archive=archive, resource=resource, frame=frame,
            payload_sha256=digest))

    def graphic(self, source_id, category, archive, resource):
        source, path, stamp, index, payload, meta = self._entry(
            source_id, category, archive, resource)
        digest = sha256(payload).hexdigest()
        if fingerprint(path) != stamp:
            raise GuiRuntimeError("source_changed", "素材档案在解析证据时变化", 409)
        return dict(ok=True, schema=SCHEMA,
            source=dict(id=source.id, name=source.name, archive=archive),
            category=category, resource=resource,
            category_basis=self._basis(category, archive, resource),
            image=dict(width=meta["width"], height=meta["height"],
                frame_count=meta["frame_count"],
                url=self._url(source.id, category, archive, resource, digest)),
            identity=dict(archive=archive, entry_index=index, payload_sha256=digest),
            notice="原作素材画布与来源指纹已读取；分类依据为档案或资源名，非人物内容视觉验收。"
                   "舞台为二维构图预览，镜头与局部动作不代表原作 V3D 实机渲染。")

    def png(self, source_id, category, archive, resource, frame=0, payload_sha256=None):
        if not isinstance(payload_sha256, str) or not SHA_RE.fullmatch(payload_sha256):
            raise GuiRuntimeError("invalid_request", "须提供选定素材的 SHA256 指纹")
        source, path, stamp, index, payload, meta = self._entry(
            source_id, category, archive, resource)
        digest = sha256(payload).hexdigest()
        if digest != payload_sha256.lower():
            raise GuiRuntimeError("source_changed", "素材指纹已变化，请重新核对", 409)
        frame = integer(frame, "frame", 0, meta["frame_count"] - 1)
        key = (stamp, index, digest, frame)
        with self._lock:
            cached = self._pngs.get(key)
            if cached:
                self._pngs.move_to_end(key)
                return cached
        try:
            inflater = zlib.decompressobj()
            raw = inflater.decompress(payload[44:], meta["raw_length"] + 1)
            if len(raw) != meta["raw_length"] or not inflater.eof:
                raise ValueError("HZC 解压长度不一致")
            bitmap = _decode_hzc_frame(raw, meta, frame)
        except (ValueError, zlib.error) as exc:
            raise GuiRuntimeError("graphic_unresolved", "HZC 图像解码失败", 422) from exc
        if bitmap.size != (meta["width"], meta["height"]):
            raise GuiRuntimeError("graphic_unresolved", "解码尺寸与选定画布不一致", 422)
        output = BytesIO()
        bitmap.save(output, format="PNG")
        data = output.getvalue()
        if fingerprint(path) != stamp:
            raise GuiRuntimeError("source_changed", "素材档案在解码期间变化", 409)
        answer = data, sha256(data).hexdigest()
        with self._lock:
            if len(data) <= MAX_PNG_CACHE_BYTES:
                # Another request may have filled the same key while decoding.
                old = self._pngs.pop(key, None)
                if old:
                    self._png_bytes -= len(old[0])
                self._pngs[key] = answer
                self._png_bytes += len(data)
                while len(self._pngs) > 8 or self._png_bytes > MAX_PNG_CACHE_BYTES:
                    _, removed = self._pngs.popitem(last=False)
                    self._png_bytes -= len(removed[0])
        return answer

    def blur_pair(self, source_id, archive, resource):
        from .native_background_pairs import lookup
        source = self.runtime._source(source_id)
        archives = self.descriptor(source)["graphics_archives"]["background"]
        stamps = {source.root / a: fingerprint(source.root / a) for a in archives}
        sharp = self.graphic(source_id, "background", archive, resource)
        evidence, path, stamp = lookup(source.root, resource)
        name = evidence["blur_resource"]
        # Names come from the HCB relationship, not a catalog naming heuristic.
        found = []
        for candidate in archives:
            table, _ = self._table(source.root / candidate)
            if sum(row[2] == name for row in table) == 1:
                found.append(candidate)
        if len(found) != 1:
            raise GuiRuntimeError("background_blur_unavailable", "原作模糊图缺失或存在多个来源，不能自动配对。", 422)
        blur = self.graphic(source_id, "background", found[0], name)
        if (sharp["identity"]["payload_sha256"] == blur["identity"]["payload_sha256"]
                or any(sharp["image"][k] != blur["image"][k] for k in ("width", "height", "frame_count"))
                or sharp["image"]["frame_count"] != 1):
            raise GuiRuntimeError("background_blur_unavailable", "清晰图与模糊图的画布不一致，或实际为同一图。", 422)
        # The two native layers need the same canvas/pivot, not just equal PNG size.
        entries = [self._entry(source_id, "background", a, n)
                   for a,n in ((archive, resource), (found[0], name))]
        for selected, entry in zip((sharp, blur), entries):
            if (sha256(entry[4]).hexdigest() != selected["identity"]["payload_sha256"]
                    or entry[3] != selected["identity"]["entry_index"]
                    or any(entry[5][k] != selected["image"][k]
                           for k in ("width", "height", "frame_count"))):
                raise GuiRuntimeError("source_changed", "读取背景配对时素材发生变化。", 409)
        sharp_meta, blur_meta = (entry[-1] for entry in entries)
        if (sharp_meta["kind"] != 0 or blur_meta["kind"] != 0
                or any(sharp_meta[k] != blur_meta[k] for k in ("offset_x", "offset_y"))):
            raise GuiRuntimeError("background_blur_unavailable", "这组背景无法按原作同一画布叠加。", 422)
        if fingerprint(path) != stamp:
            raise GuiRuntimeError("source_changed", "读取背景配对时原作脚本发生变化。", 409)
        if any(fingerprint(p) != s for p,s in stamps.items()):
            raise GuiRuntimeError("source_changed", "读取背景配对时素材档案发生变化。", 409)
        return dict(ok=True, schema="fvp-gui-background-blur-pair/1", sharp=sharp, blur=blur,
                    native_pair=evidence, uses_generated_blur=False)
