"""Read-only, registered-source FVP audio catalog and bounded entry playback.

The browser supplies source IDs and exact directory names, never local paths.
Listing reads only directory metadata and 12-byte format probes on one page.
Selecting an asset freezes its bytes; original archives are never changed.
"""
from __future__ import annotations

from collections import OrderedDict
from hashlib import sha256
from threading import RLock
from urllib.parse import urlencode

from .audio_workspace import _audio_type
from .bin_archive import BinArchiveError, archive_entry_table_file
from .gui_runtime import API_ROOT, GuiRuntimeError, ID_RE, SHA_RE, fingerprint, integer

SCHEMA = "fvp-gui-audio/1"
ARCHIVES = {"bgm.bin": "bgm", "bgm2.bin": "bgm", "se.bin": "se",
            "voice.bin": "voice", "voice2.bin": "voice"}
MAX_BYTES = 128 * 1024 * 1024
CACHE_BYTES = 64 * 1024 * 1024


class GuiAudio:
    def __init__(self, runtime):
        self.runtime = runtime
        self._tables, self._bytes = {}, OrderedDict()
        self._cache_size = 0
        self._lock = RLock()

    def _source(self, sid):
        if not isinstance(sid, str) or not ID_RE.fullmatch(sid):
            raise GuiRuntimeError("invalid_request", "声音来源不正确。")
        source = self.runtime.sources.get(sid)
        if source is None or not source.root.is_dir():
            raise GuiRuntimeError("source_not_found", "这个声音来源暂时无法读取。", 404)
        return source

    def _path(self, sid, archive):
        source = self._source(sid)
        if archive not in ARCHIVES:
            raise GuiRuntimeError("invalid_request", "声音档案不正确。")
        path = source.root / archive
        if not path.is_file():
            raise GuiRuntimeError("audio_unavailable", "这个游戏没有该声音档案。", 404)
        if path.resolve().parent != source.root or path.is_symlink():
            raise GuiRuntimeError("source_changed", "声音档案已移到来源目录之外。", 409)
        return source, path

    def descriptor(self, source):
        return dict(source=source.id, name=source.name,
                    kinds=sorted({kind for name, kind in ARCHIVES.items()
                                  if (source.root / name).is_file()}))

    def _table(self, sid, archive):
        _source, path = self._path(sid, archive)
        stamp = fingerprint(path)
        key = sid, archive
        with self._lock:
            cached = self._tables.get(key)
            if cached and cached[0] == stamp:
                return path, stamp, cached[1]
        try:
            rows = archive_entry_table_file(path)
        except (OSError, BinArchiveError) as exc:
            raise GuiRuntimeError("invalid_archive", "这个声音档案无法正确读取。", 422) from exc
        if len({r[2] for r in rows}) != len(rows):
            raise GuiRuntimeError("ambiguous_resource", "声音资源重名，无法确定要用哪一个。", 422)
        if fingerprint(path) != stamp:
            raise GuiRuntimeError("source_changed", "读取时声音档案发生了变化。", 409)
        with self._lock:
            self._tables[key] = stamp, rows
        return path, stamp, rows

    @staticmethod
    def _url(sid, archive, resource, digest):
        return API_ROOT + "audio?" + urlencode(dict(source=sid, archive=archive,
                                                    resource=resource, sha256=digest))

    @staticmethod
    def _id(sid, archive, resource):
        return "au-" + sha256((sid + "\0" + archive + "\0" + resource).encode()).hexdigest()[:24]

    def catalog(self, sid, *, kind="bgm", query="", offset=0, limit=80):
        self._source(sid)
        if kind not in ("bgm", "se", "voice") or not isinstance(query, str) or len(query) > 128:
            raise GuiRuntimeError("invalid_request", "声音搜索条件不正确。")
        offset = integer(offset, "列表起点", 0, 1_000_000)
        limit = integer(limit, "列表长度", 1, 200)
        matches, refs = [], []
        for archive, track in ARCHIVES.items():
            if track != kind or not (self._source(sid).root / archive).is_file():
                continue
            path, stamp, rows = self._table(sid, archive)
            refs.append((path, stamp))
            matches.extend((archive, index, row) for index, row in enumerate(rows)
                           if query.casefold() in row[2].casefold() and 0 < row[1] <= MAX_BYTES)
        result = []
        for archive, index, (at, size, resource) in matches[offset:offset + limit]:
            _source, path = self._path(sid, archive)
            with path.open("rb") as stream:
                stream.seek(at)
                fmt = _audio_type(stream.read(min(12, size)))
            if fmt:
                result.append(dict(id=self._id(sid, archive, resource), kind=kind, source=sid,
                    archive=archive, resource=resource, name=resource, entry_index=index,
                    size=size, format=fmt[0], mime=fmt[1]))
        if any(fingerprint(path) != stamp for path, stamp in refs):
            raise GuiRuntimeError("source_changed", "读取时声音档案发生了变化。", 409)
        next_offset = offset + limit
        return dict(ok=True, schema=SCHEMA, source=sid, kind=kind, total=len(matches),
                    offset=offset, next_offset=next_offset if next_offset < len(matches) else None,
                    entries=result)

    def asset(self, sid, archive, resource, expected_sha=None):
        if not isinstance(resource, str) or not resource or len(resource) > 256 or "\0" in resource:
            raise GuiRuntimeError("invalid_request", "声音资源名称不正确。")
        if expected_sha is not None and (not isinstance(expected_sha, str) or not SHA_RE.fullmatch(expected_sha)):
            raise GuiRuntimeError("invalid_request", "声音资源引用不完整。")
        path, stamp, rows = self._table(sid, archive)
        match = next(((i, row) for i, row in enumerate(rows) if row[2] == resource), None)
        if match is None:
            raise GuiRuntimeError("audio_not_found", "找不到这段声音，请重新选择。", 404)
        index, (at, size, _name) = match
        if not 0 < size <= MAX_BYTES:
            raise GuiRuntimeError("audio_too_large", "这段声音太大，暂时不能试听。", 413)
        cache_key = sid, archive, resource, stamp
        with self._lock:
            item = self._bytes.get(cache_key)
            if item:
                self._bytes.move_to_end(cache_key)
        if item is None:
            with path.open("rb") as stream:
                stream.seek(at)
                payload = stream.read(size)
            if len(payload) != size:
                raise GuiRuntimeError("source_changed", "声音读取不完整，请重新选择。", 409)
            fmt = _audio_type(payload[:12])
            if fmt is None:
                raise GuiRuntimeError("unsupported_audio", "这段声音的格式暂时不能播放。", 422)
            item = payload, fmt, sha256(payload).hexdigest()
            if size <= CACHE_BYTES:
                with self._lock:
                    if cache_key not in self._bytes:
                        while self._bytes and self._cache_size + size > CACHE_BYTES:
                            _key, old = self._bytes.popitem(last=False)
                            self._cache_size -= len(old[0])
                        self._bytes[cache_key] = item
                        self._cache_size += size
        if fingerprint(path) != stamp:
            raise GuiRuntimeError("source_changed", "声音档案发生了变化，请重新选择。", 409)
        payload, fmt, digest = item
        if expected_sha is not None and digest != expected_sha.lower():
            raise GuiRuntimeError("source_changed", "这段声音已变化，请重新选择。", 409)
        info = dict(id=self._id(sid, archive, resource), name=resource, kind=ARCHIVES[archive],
                    source=sid, archive=archive, resource=resource, sha256=digest,
                    size=size, format=fmt[0], mime=fmt[1], entry_index=index,
                    url=self._url(sid, archive, resource, digest))
        return payload, info, (path, stamp)

    def info(self, sid, archive, resource):
        _payload, info, _ref = self.asset(sid, archive, resource)
        return dict(ok=True, schema=SCHEMA, asset=info)


def byte_range(header, size):
    """One bounded HTTP range; no multipart response or arbitrary suffix syntax."""
    import re
    if header is None:
        return 0, size - 1, False
    match = re.fullmatch(r"bytes=([0-9]*)-([0-9]*)", header)
    if not match or not any(match.groups()):
        raise GuiRuntimeError("range_not_satisfiable", "播放范围不正确。", 416)
    left, right = match.groups()
    if not left:
        length = int(right)
        if length == 0:
            raise GuiRuntimeError("range_not_satisfiable", "播放范围不正确。", 416)
        start, end = max(0, size - length), size - 1
    else:
        start, end = int(left), min(int(right), size - 1) if right else size - 1
    if start >= size or start > end:
        raise GuiRuntimeError("range_not_satisfiable", "播放范围不正确。", 416)
    return start, end, True
