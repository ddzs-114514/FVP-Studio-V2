"""Read-only GUI bridge to the shared, fail-closed native portrait importer.

Source registration selects files, never game-specific size rules. Browser
requests contain opaque registered IDs and exact BIN resource names, not paths.
No scene/session mutation, archive builder, compiler or installer is imported.
"""
from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
from threading import RLock
from urllib.parse import urlencode

from .bin_archive import archive_entry_table_file
from .performance_compile import resource_reference
from .performance_portrait_defaults import native_portrait_defaults, PORTRAIT_ARCHIVES
from .resource_builder import decoded_bin_entry_image

SCHEMA = "fvp-gui-runtime/1"
SOURCE_SCHEMA = "fvp-gui-runtime-sources/1"
API_ROOT = "/api/gui-runtime/"
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
SHA_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
MAX_BODY_PIXELS = 24_000_000
MAX_FACE_PIXELS = 8_000_000


class GuiRuntimeError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


def integer(value, name, minimum, maximum):
    if isinstance(value, bool):
        raise GuiRuntimeError("invalid_request", f"{name} 必须为整数")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        result = int(value)
    else:
        raise GuiRuntimeError("invalid_request", f"{name} 必须为整数")
    if not minimum <= result <= maximum:
        raise GuiRuntimeError("invalid_request", f"{name} 超出允许范围")
    return result


def fingerprint(path: Path):
    stat = path.stat()
    return (str(path), stat.st_dev, stat.st_ino, stat.st_size,
            stat.st_mtime_ns, stat.st_ctime_ns)


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    root: Path
    archive: str
    # Local registration only: the browser cannot supply script/executable
    # paths or change the target's text encoding in an export request.
    target_script: str | None = None
    target_executable: str | None = None
    target_encoding: str | None = None
    target_analysis_encoding: str | None = None
    target_hook_offset: int | None = None

    @property
    def path(self):
        return self.root / self.archive

    def descriptor(self):
        # Availability is cheap; source rule verification occurs on selection.
        return dict(id=self.id, name=self.name, archive=self.archive,
                    available=self.root.is_dir() and self.path.is_file())


def load_sources(path: Path, *, allow_empty=False) -> list[Source]:
    content = path.read_bytes()
    if len(content) > 1024 * 1024:
        raise GuiRuntimeError("invalid_config", "来源注册文件过大")
    config = json.loads(content)
    if not isinstance(config, dict) or config.get("schema") != SOURCE_SCHEMA:
        raise GuiRuntimeError("invalid_config", "来源注册格式或版本不正确")
    rows = config.get("sources")
    if not isinstance(rows, list) or (not rows and not allow_empty) or len(rows) > 64:
        raise GuiRuntimeError("invalid_config", "来源注册应含 1 至 64 项")
    result, seen = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise GuiRuntimeError("invalid_config", "来源注册项必须为对象")
        sid, name, root, archive = (row.get(key) for key in ("id", "name", "root", "archive"))
        if not isinstance(sid, str) or not ID_RE.fullmatch(sid) or sid in seen:
            raise GuiRuntimeError("invalid_config", "来源 ID 不合法或重复")
        if not isinstance(name, str) or not name.strip() or len(name) > 256:
            raise GuiRuntimeError("invalid_config", "来源显示名称不合法")
        if sid == "sakura" and name.strip() == "樱花开了":
            name = "樱花萌放"
        if not isinstance(root, str) or not Path(root).is_absolute():
            raise GuiRuntimeError("invalid_config", "来源根目录必须为绝对路径")
        if not isinstance(archive, str) or archive not in PORTRAIT_ARCHIVES:
            raise GuiRuntimeError("invalid_config", "立绘档案须为 graph_bs.bin 或 graph.bin")
        seen.add(sid)
        options = {}
        for key, suffixes in (("target_script", {".hcb", ".bch"}),
                              ("target_executable", {".exe"})):
            value = row.get(key)
            if value is not None and (not isinstance(value, str) or not value
                    or any(c in value for c in ("/", "\\", ":", "\0"))
                    or Path(value).name != value or Path(value).suffix.casefold() not in suffixes):
                raise GuiRuntimeError("invalid_config", "目标脚本/程序须为游戏根目录直属文件名")
            options[key] = value
        for key in ("target_encoding", "target_analysis_encoding"):
            encoding = row.get(key)
            if encoding is not None:
                from .hcb import normalize_encoding
                try:
                    if not isinstance(encoding, str):
                        raise ValueError("编码须为字符串")
                    encoding = normalize_encoding(encoding)
                except ValueError as exc:
                    raise GuiRuntimeError("invalid_config", "目标文本编码不支持") from exc
            options[key] = encoding
        hook = row.get("target_hook_offset")
        if hook is not None and (type(hook) is not int or not 4 <= hook <= 0xFFFFFFFF):
            raise GuiRuntimeError("invalid_config", "目标剧情接入位置须为脚本中的整数偏移")
        options["target_hook_offset"] = hook
        result.append(Source(sid, name.strip(), Path(root).resolve(), archive, **options))
    return result


class GuiRuntime:
    def __init__(self, sources: list[Source]):
        self.sources = {source.id: source for source in sources}
        if len(self.sources) != len(sources) or (not sources and not getattr(self, "allow_empty_sources", False)):
            raise GuiRuntimeError("invalid_config", "来源不能为空或重复")
        self._catalogs = {}
        self._pngs = OrderedDict()
        self._lock = RLock()
        # Kept separate from native portrait size discovery and compilation.
        from .gui_graphics import GuiGraphics
        self.graphics = GuiGraphics(self)
        from .gui_speakers import GuiSpeakers
        self.speakers = GuiSpeakers(self)

    def health(self):
        return dict(ok=True, schema=SCHEMA, read_only=True, stage=[1280, 720],
                    capabilities=dict(background_blur_pair=True, portrait_catalog=True, native_size=True,
                                      portrait_png=True, speaker_catalog=True, speaker_info=True,
                                      speaker_avatar_png=True, graphics_catalog=True,
                                      graphics_png=True, native_compile=False,
                                      game_writeback=False),
                    sources=[self.graphics.descriptor(source) for source in self.sources.values()],
                    speaker_gui_contract=dict(schema='fvp-gui-native-speaker/1',
                        native_names=True, native_default_colour=True, genuine_backlog_avatar=True,
                        source='registered_hcb_native_calls', readonly=True,
                        body_name_matching=False, age_variant_guessing=False))

    def _source(self, source_id):
        if not isinstance(source_id, str) or not ID_RE.fullmatch(source_id):
            raise GuiRuntimeError("invalid_request", "来源 ID 不合法")
        source = self.sources.get(source_id)
        if source is None:
            raise GuiRuntimeError("source_not_found", "该来源尚未注册", 404)
        if not source.descriptor()["available"]:
            raise GuiRuntimeError("source_unavailable", "来源立绘档案不存在或暂不可读取", 404)
        # A replaced symlink must not silently change the registered source root.
        if source.path.resolve().parent != source.root:
            raise GuiRuntimeError("source_changed", "立绘档案已指向注册目录之外", 409)
        return source

    def _bodies(self, source):
        stamp = fingerprint(source.path)
        with self._lock:
            cached = self._catalogs.get(source.id)
            if cached and cached[0] == stamp:
                return cached[1]
        entries = archive_entry_table_file(source.path)
        names = [entry[2] for entry in entries]
        if len(names) != len(set(names)):
            raise GuiRuntimeError("ambiguous_resource", "BIN 中资源重名，拒绝选择", 422)
        available = set(names)
        bodies = tuple(name for name in names if name + "_表情" in available
                       and not name.endswith("_表情") and "吹出" not in name)
        if fingerprint(source.path) != stamp:
            raise GuiRuntimeError("source_changed", "来源档案在读取目录时变化", 409)
        with self._lock:
            self._catalogs[source.id] = (stamp, bodies)
        return bodies

    @staticmethod
    def _url(source_id, body, expression=0, body_sha=None):
        query = dict(source=source_id, body=body, expression=expression)
        if body_sha:
            query["body_sha256"] = body_sha
        return API_ROOT + "portrait.png?" + urlencode(query)

    def catalog(self, source_id, q="", offset=0, limit=40):
        source = self._source(source_id)
        if not isinstance(q, str) or len(q) > 128 or "\x00" in q:
            raise GuiRuntimeError("invalid_request", "检索文字过长或不合法")
        offset = integer(offset, "offset", 0, 1_000_000)
        limit = integer(limit, "limit", 1, 60)
        bodies = self._bodies(source)
        query = q.casefold()
        filtered = [body for body in bodies if query in body.casefold()]
        return dict(ok=True, source=source.id, offset=offset, limit=limit,
                    total=len(filtered), items=[dict(body=body, display_name=body,
                        preview_url=self._url(source.id, body))
                        for body in filtered[offset:offset + limit]])

    def _pair(self, source_id, body):
        source = self._source(source_id)
        if (not isinstance(body, str) or not body or len(body) > 256
                or "\x00" in body or body not in self._bodies(source)):
            raise GuiRuntimeError("portrait_not_found", "该分层立绘不存在或未配对", 404)
        stamp = fingerprint(source.path)
        _, b = resource_reference(source.path, body)
        _, f = resource_reference(source.path, body + "_表情")
        if (b["kind"] != 1 or b["frame_count"] != 1 or f["kind"] != 2
                or f["frame_count"] < 1 or min(f["offset_x"], f["offset_y"]) < 0
                or f["offset_x"] + f["width"] > b["width"]
                or f["offset_y"] + f["height"] > b["height"]):
            raise GuiRuntimeError("invalid_pair", "身体和表情 HZC 的格式或原生区域不配对", 422)
        if (min(b["width"], b["height"], f["width"], f["height"]) <= 0
                or b["width"] * b["height"] > MAX_BODY_PIXELS
                or f["width"] * f["height"] > MAX_FACE_PIXELS):
            raise GuiRuntimeError("image_too_large", "素材尺寸超过当前只读预览的上限", 422)
        if fingerprint(source.path) != stamp:
            raise GuiRuntimeError("source_changed", "来源档案在读取分层素材时变化", 409)
        return source, b, f, stamp

    def portrait(self, source_id, body):
        source, b, f, stamp = self._pair(source_id, body)
        try:
            planned = native_portrait_defaults(dict(source_game=str(source.root),
                archive=str(source.path), body=body, actor=1, expression=0))
        except ValueError as exc:
            raise GuiRuntimeError("native_size_unresolved", str(exc), 422) from exc
        contract = planned.get("size_contract", {})
        if (contract.get("schema") != "fvp-native-import-size/1"
                or contract.get("body") != body
                or contract.get("body_sha256") != b["payload_sha256"]
                or contract.get("uses_face_matching") is not False
                or contract.get("uses_story_camera") is not False
                or contract.get("height") != planned["values"]["height"]):
            raise GuiRuntimeError("invalid_native_evidence", "原生大小证据与选定身体不一致", 422)
        if fingerprint(source.path) != stamp:
            raise GuiRuntimeError("source_changed", "来源档案在解析大小期间变化", 409)
        values = {key: planned["values"][key] for key in
                  ("stage_x", "bottom_y", "height", "depth", "alpha")}
        return dict(ok=True, source=dict(id=source.id, name=source.name, archive=source.archive),
                    body=body, values=values, image=dict(width=b["width"], height=b["height"],
                    expression_count=f["frame_count"], url=self._url(source.id, body,
                        body_sha=b["payload_sha256"])),
                    native_size=deepcopy(contract), notice=planned["notice"])

    def portrait_png(self, source_id, body, expression=0, body_sha256=None):
        source, b, f, stamp = self._pair(source_id, body)
        expression = integer(expression, "expression", 0, f["frame_count"] - 1)
        if body_sha256 is not None:
            if not isinstance(body_sha256, str) or not SHA_RE.fullmatch(body_sha256):
                raise GuiRuntimeError("invalid_request", "身体指纹须为 SHA256")
            if body_sha256.lower() != b["payload_sha256"].lower():
                raise GuiRuntimeError("source_changed", "身体指纹已变化，请重新核对原生大小", 409)
        key = (stamp, b["payload_sha256"], f["payload_sha256"], expression)
        with self._lock:
            cached = self._pngs.get(key)
            if cached:
                self._pngs.move_to_end(key)
                return cached
        bitmap, _ = decoded_bin_entry_image(source.path, b["entry_index"], 0)
        face, _ = decoded_bin_entry_image(source.path, f["entry_index"], expression)
        if bitmap.size != (b["width"], b["height"]) or face.size != (f["width"], f["height"]):
            raise GuiRuntimeError("invalid_pair", "解码尺寸与原生 HZC 元数据不一致", 422)
        result = bitmap.convert("RGBA")
        result.alpha_composite(face.convert("RGBA"), (f["offset_x"], f["offset_y"]))
        buffer = BytesIO()
        result.save(buffer, format="PNG")
        payload = buffer.getvalue()
        if fingerprint(source.path) != stamp:
            raise GuiRuntimeError("source_changed", "来源档案在解码期间变化", 409)
        answer = (payload, sha256(payload).hexdigest())
        with self._lock:
            self._pngs[key] = answer
            self._pngs.move_to_end(key)
            while len(self._pngs) > 8:
                self._pngs.popitem(last=False)
        return answer
