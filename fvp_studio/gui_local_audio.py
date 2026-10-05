"""Owned GUI audio bank; browser uploads bytes, never filesystem paths.

The existing portable audio store owns the payloads. Voice uses a separate
voice bank with its Vorbis-oriented storage track; GUI identity keeps it voice.
No core project/Comfy audio schema or original game archive is modified.
"""
import json
from pathlib import Path
import re
from threading import RLock

from .audio_project import (PROJECT_AUDIO_MAX_BYTES, import_project_audio_bytes,
    list_project_audio_assets, validate_project_audio_asset)
from .gui_audio import GuiAudio, SCHEMA
from .gui_runtime import GuiRuntimeError, SHA_RE, fingerprint, integer
from .performance_install import _safe

SOURCE = "project-audio"
KINDS = {"bgm", "se", "voice"}
RESOURCE_RE = re.compile(r"project-audio-[0-9a-f]{32}\Z")
LOCAL_ARCHIVES = {"local-" + kind:kind for kind in KINDS}


class GuiLocalAudio:
    def __init__(self, root, protected_roots=()):
        self.root = _safe(Path(root))
        for protected in protected_roots:
            protected = Path(protected).resolve(strict=True)
            if self.root == protected or self.root in protected.parents or protected in self.root.parents:
                raise ValueError("本地声音库不能与游戏来源重叠。")
        self.lock = RLock()

    @staticmethod
    def wire(reference, kind):
        return dict(name=reference["label"], kind=kind, source=SOURCE, archive="local-" + kind,
            resource=reference["asset_id"], sha256=reference["payload_sha256"], size=reference["size"],
            format=reference["format"], mime=reference["mime"], local=True,
            id=GuiAudio._id(SOURCE, "local-" + kind, reference["asset_id"]),
            url=GuiAudio._url(SOURCE, "local-" + kind,
                reference["asset_id"], reference["payload_sha256"]))

    def import_bytes(self, payload, *, kind, name):
        if (kind not in KINDS or not isinstance(name, str) or not name.strip() or len(name) > 256
                or "\0" in name or "/" in name or "\\" in name or re.match(r"^[A-Za-z]:", name)):
            raise ValueError("请选择声音类型，并填写简短名称。")
        if not 0 < len(payload) <= PROJECT_AUDIO_MAX_BYTES:
            raise GuiRuntimeError("audio_too_large", "单段声音须在 128 MiB 以内。", 413)
        with self.lock:
            reference = import_project_audio_bytes(self.root / kind, payload,
                track="bgm" if kind == "voice" else kind, label=name)
        return dict(ok=True, schema=SCHEMA, asset=self.wire(reference, kind),
                    original_game_written=False)

    def catalog(self, *, kind="bgm", query="", offset=0, limit=80):
        if kind not in KINDS or not isinstance(query, str) or len(query) > 128:
            raise ValueError("声音搜索条件不正确。")
        offset, limit = integer(offset, "列表起点", 0, 1_000_000), integer(limit, "列表长度", 1, 200)
        with self.lock:
            rows = list_project_audio_assets(self.root / kind, verify_payloads=False)["entries"]
        rows = [self.wire(row, kind) for row in rows if query.casefold() in row["label"].casefold()]
        return dict(ok=True, schema=SCHEMA, source=SOURCE, kind=kind, total=len(rows), offset=offset,
            next_offset=offset+limit if offset+limit < len(rows) else None, entries=rows[offset:offset+limit])

    def asset(self, archive, resource, expected_sha=None):
        kind = LOCAL_ARCHIVES.get(archive)
        if (kind is None or not isinstance(resource, str) or not RESOURCE_RE.fullmatch(resource)
                or expected_sha is not None and (not isinstance(expected_sha, str) or not SHA_RE.fullmatch(expected_sha))):
            raise GuiRuntimeError("invalid_request", "本地声音引用不正确。")
        root = self.root / kind
        record_path = root / "records" / (resource + ".json")
        if not record_path.exists():
            raise GuiRuntimeError("audio_not_found", "找不到这段本地声音，请重新导入。", 404)
        record = _safe(record_path, file=True, independent=False)
        if record.stat().st_size > 16 * 1024:
            raise ValueError("本地声音记录不完整，请重新导入。")
        with self.lock:
            reference = json.loads(record.read_text(encoding="utf-8"))
            checked = validate_project_audio_asset(reference, root)["asset_ref"]
            if checked["asset_id"] != resource or checked["track"] != ("bgm" if kind == "voice" else kind):
                raise GuiRuntimeError("source_changed", "本地声音记录发生变化，请重新导入。", 409)
            path = _safe(root / "assets" / checked["relative_path"], file=True, independent=False)
            stamp = fingerprint(path)
            payload = path.read_bytes()
        info = self.wire(checked, kind)
        from hashlib import sha256
        if (len(payload) != info["size"] or sha256(payload).hexdigest() != info["sha256"]
                or expected_sha is not None and expected_sha.lower() != info["sha256"]
                or fingerprint(path) != stamp):
            raise GuiRuntimeError("source_changed", "这段本地声音已变化，请重新导入。", 409)
        return payload, info, (path, stamp)


class GuiHybridAudio(GuiAudio):
    def __init__(self, runtime, root):
        super().__init__(runtime)
        self.local = GuiLocalAudio(root, (source.root for source in runtime.sources.values()))

    def catalog(self, sid, **options):
        return self.local.catalog(**options) if sid == SOURCE else super().catalog(sid, **options)

    def asset(self, sid, archive, resource, expected_sha=None):
        return (self.local.asset(archive, resource, expected_sha) if sid == SOURCE else
                super().asset(sid, archive, resource, expected_sha))
