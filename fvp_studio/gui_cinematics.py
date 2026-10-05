"""Registered, read-only movie assets for intro/OP/ED authoring.

No native movie emitter is claimed here: modern Movie/MovieState/MovieStop
and legacy MoviePlay have different ABIs, and original EDs may be graphics.
Cataloguing a file is not verification that an engine can play that file.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import shutil
import subprocess

from .gui_runtime import GuiRuntimeError, fingerprint, integer

SCHEMA = 'fvp-gui-movie-catalog/1'
INFO_SCHEMA = 'fvp-gui-movie-info/1'
MIME = {'.mp4': 'video/mp4', '.webm': 'video/webm', '.ogv': 'video/ogg',
        '.wmv': 'video/x-ms-wmv', '.avi': 'video/x-msvideo', '.mpg': 'video/mpeg', '.mpeg': 'video/mpeg'}


def identity(path):
    # Metadata identity, explicitly not a content SHA-256.
    return hashlib.sha256(json.dumps(fingerprint(path), ensure_ascii=False).encode('utf-8')).hexdigest()


class GuiCinematics:
    def __init__(self, runtime):
        self.runtime = runtime

    def source(self, sid):
        source = self.runtime.sources.get(sid)
        if source is None:
            raise GuiRuntimeError('source_unknown', '请先选择已登记的游戏。', 404)
        if not source.root.is_dir():
            raise GuiRuntimeError('source_unavailable', '该游戏目录暂不可读取。', 503)
        return source

    @staticmethod
    def _entries(source):
        root = source.root.resolve()
        folders = [root]
        folders.extend(p for p in root.iterdir() if p.is_dir() and p.name.casefold() == 'movie')
        result = []
        for folder in folders:
            if not folder.resolve().is_relative_to(root):
                continue
            for path in folder.iterdir():
                if not path.is_file() or path.suffix.casefold() not in MIME or not path.resolve().is_relative_to(root):
                    continue
                stat = path.stat()
                if stat.st_size <= 0:
                    continue
                resource = path.relative_to(root).as_posix()
                result.append(dict(source=source.id, resource=resource, label=path.name,
                    size=stat.st_size, extension=path.suffix.casefold(), file_identity=identity(path),
                    browser_preview='try' if path.suffix.casefold() in ('.mp4','.webm','.ogv') else 'unsupported',
                    native_export=False))
                if len(result) > 1000:
                    raise GuiRuntimeError('too_many_movies', '影片文件超过 1000 个，请缩小登记目录。', 422)
        return sorted(result, key=lambda item: item['resource'].casefold())

    def catalog(self, sid, query='', offset=0, limit=100):
        source = self.source(sid)
        if not isinstance(query, str) or len(query) > 100 or '\0' in query:
            raise GuiRuntimeError('invalid_query', '搜索词不正确。')
        offset, limit = integer(offset,'offset',0,1000), integer(limit,'limit',1,100)
        rows = [r for r in self._entries(source) if query.casefold() in r['resource'].casefold()]
        return dict(ok=True, schema=SCHEMA, source=sid, total=len(rows), offset=offset, limit=limit,
            items=rows[offset:offset+limit], read_only=True, native_export=False,
            notice='影片目录已接入；原作影片调用与 ED 字幕的游戏输出尚未接通。')

    def resolve(self, sid, resource, expected=None):
        source = self.source(sid)
        if (not isinstance(resource,str) or not resource or len(resource)>256
                or '\\' in resource or ':' in resource or '\0' in resource):
            raise GuiRuntimeError('invalid_movie', '影片资源名不正确。')
        parts = PurePosixPath(resource).parts
        if PurePosixPath(resource).is_absolute() or any(p in ('','.','..') for p in parts):
            raise GuiRuntimeError('invalid_movie', '影片资源名不正确。')
        rows = self._entries(source)
        row = next((item for item in rows if item['resource']==resource), None)
        if row is None:
            raise GuiRuntimeError('movie_missing', '所选影片不在该游戏的影片目录中。', 404)
        if expected is not None and expected != row['file_identity']:
            raise GuiRuntimeError('source_changed', '影片文件已改变，请重新选择。', 409)
        path = source.root.joinpath(*parts)
        if not path.resolve().is_relative_to(source.root.resolve()):
            raise GuiRuntimeError('invalid_movie', '影片不属于已登记的游戏。', 403)
        return row, path

    def info(self, sid, resource, expected):
        row, path = self.resolve(sid, resource, expected)
        result = dict(row, ok=True, schema=INFO_SCHEMA, duration_ms=None,
            width=None, height=None, codecs=[], native_export=False, probe_status='unavailable')
        executable = shutil.which('ffprobe')
        if executable:
            try:
                process = subprocess.run([executable,'-v','error','-protocol_whitelist','file',
                    '-show_entries','format=duration:stream=codec_type,codec_name,width,height',
                    '-of','json',str(path)], capture_output=True, text=True, encoding='utf-8',
                    errors='replace', timeout=10, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                if process.returncode == 0 and len(process.stdout) <= 65536:
                    data = json.loads(process.stdout)
                    duration = float(data.get('format',{}).get('duration',0))
                    if math.isfinite(duration) and 0 < duration <= 86400:
                        result['duration_ms'] = round(duration*1000)
                    streams = data.get('streams',[])
                    for stream in streams[:16]:
                        if isinstance(stream.get('codec_name'), str):
                            result['codecs'].append(stream['codec_name'][:32])
                        if stream.get('codec_type')=='video':
                            for key in ('width','height'):
                                value = stream.get(key)
                                if type(value) is int and 1 <= value <= 16384:
                                    result[key] = value
                    result['probe_status'] = 'metadata_read'
                else:
                    result['probe_status'] = 'unreadable'
            except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, AttributeError):
                result['probe_status'] = 'unavailable'
        if identity(path) != row['file_identity']:
            raise GuiRuntimeError('source_changed','读取时影片已改变，请重新选择。',409)
        return result


def byte_range(header, size):
    """Return one HTTP byte range, refusing malformed or multiple ranges."""
    import re
    if header is None:
        return 0, size-1, False
    match = re.fullmatch(r'bytes=(\d*)-(\d*)',header)
    if match is None or not any(match.groups()):
        raise GuiRuntimeError('range_rejected','影片读取范围不正确。',416)
    a,b = match.groups()
    if a:
        start, end = int(a), int(b) if b else size-1
    else:
        length=int(b)
        if length<=0:
            raise GuiRuntimeError('range_rejected','影片读取范围不正确。',416)
        start,end=max(0,size-length),size-1
    if start>=size or end<start:
        raise GuiRuntimeError('range_rejected','影片读取范围超出文件。',416)
    return start,min(end,size-1),True
