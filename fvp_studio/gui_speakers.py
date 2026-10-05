"""Read-only native names, default colours and genuine B.LOG GUI thumbnails.

Source ids select registered games. Names come from the original HCB speaker
wrappers; no CHR filename is interpreted as a speaker identity. No compiler,
installer, portrait scaling or original file write is performed here.
"""
from collections import OrderedDict
from io import BytesIO
from pathlib import Path
from threading import RLock
from urllib.parse import urlencode
import hashlib
import json
import zlib

from PIL import Image

from .bin_archive import convert_hzc_to_premultiplied_alpha
from .gui_runtime import API_ROOT, GuiRuntimeError, fingerprint, integer, SHA_RE
from .gui_speaker_identity import resolve_identity, source_catalog
from .performance_compile import resource_reference

SCHEMA = 'fvp-gui-native-speaker/1'
CATALOG_SCHEMA = 'fvp-gui-speaker-catalog/1'


def identity_digest(binding):
    evidence = {key: binding.get(key) for key in
                ('source', 'name', 'rgb', 'native_id', 'source_hcb_sha256', 'avatar')}
    wire = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(wire).hexdigest()


class GuiSpeakers:
    def __init__(self, runtime):
        self.runtime = runtime
        self._lock = RLock()
        self._pngs = OrderedDict()

    @staticmethod
    def _name(name):
        if not isinstance(name, str) or not name.strip() or len(name) > 128 or '\0' in name:
            raise GuiRuntimeError('invalid_request', '人物名字不正确。')
        return name

    @staticmethod
    def _scripts(source):
        root = source.root
        if source.target_script:
            paths = [root / source.target_script]
        else:
            paths = sorted(p for p in root.iterdir() if p.is_file() and not p.is_symlink()
                           and p.suffix.casefold() in {'.hcb', '.bch'})
            # The project keeps translated active overlays beside clean native
            # scripts (.name.hcb / name.hcb). Use the original for GUI names;
            # explicit registered analysis-script selection takes precedence.
            paths = [p for p in paths if not (p.name.startswith('.') and
                     (root / p.name[1:]).is_file())]
        if len(paths) > 8:
            raise GuiRuntimeError('speaker_scripts_ambiguous', '这个游戏的脚本不止一套，需先确定人物资料来源。', 422)
        if any(not p.is_file() or p.is_symlink() or p.resolve().parent != root for p in paths):
            raise GuiRuntimeError('source_changed', '人物资料来源已变化，请重新选择游戏。', 409)
        return [(p, fingerprint(p)) for p in paths]

    def catalog(self, source_id, q='', offset=0, limit=40):
        source = self.runtime._source(source_id)
        if not isinstance(q, str) or len(q) > 128 or '\0' in q:
            raise GuiRuntimeError('invalid_request', '人物检索文字过长或不正确。')
        offset = integer(offset, 'offset', 0, 100000)
        limit = integer(limit, 'limit', 1, 60)
        names = {}
        refs = self._scripts(source)
        with self._lock:
            for path, stamp in refs:
                catalog = source_catalog(str(path), stamp, source.target_analysis_encoding or 'sjis')
                for name, entries in catalog.get('names', {}).items():
                    if '\ufffd' in name or not name.strip():
                        continue
                    names.setdefault(name, set()).update(row['native_id'] for row in entries)
        if any(fingerprint(p) != stamp for p, stamp in refs):
            raise GuiRuntimeError('source_changed', '读取期间人物资料发生变化，请重新选择。', 409)
        filtered = sorted(name for name in names if q.casefold() in name.casefold())
        items = [dict(name=name, native_ids=sorted(names[name]),
                      info_url=API_ROOT + 'speaker?' + urlencode(dict(source=source.id, name=name)))
                 for name in filtered[offset:offset+limit]]
        return dict(ok=True, schema=CATALOG_SCHEMA, source=source.id, total=len(filtered),
                    offset=offset, limit=limit, items=items, native_names_only=True, read_only=True)

    def _binding(self, source_id, name):
        source = self.runtime._source(source_id)
        self._scripts(source)  # Validate registered root, including explicit files.
        with self._lock:
            binding, refs = resolve_identity(source, self._name(name))
        if not binding.get('available'):
            raise GuiRuntimeError('speaker_not_found', '原作人物名单里没有这个名字，请重新选择。', 404)
        if any(fingerprint(p) != stamp for p, stamp in refs):
            raise GuiRuntimeError('source_changed', '人物资料已变化，请重新选择。', 409)
        return binding, refs

    def info(self, source_id, name):
        binding, _refs = self._binding(source_id, name)
        identity = identity_digest(binding)
        rgb = binding.get('rgb')
        avatar = binding.get('avatar')
        urls = {}
        if avatar:
            for state in ('normal', 'selected'):
                urls[state + '_url'] = API_ROOT + 'speaker-avatar.png?' + urlencode(dict(
                    source=source_id, name=name, state=state, identity_sha256=identity))
        return dict(ok=True, schema=SCHEMA, source=source_id, name=binding['name'],
                    identity_sha256=identity,
                    native_ids=sorted({r['native_id'] for r in binding.get('native_wrappers', [])}),
                    rgb=rgb, color=('#' + ''.join(f'{v:02x}' for v in rgb)) if rgb else None,
                    avatar=dict(available=bool(avatar), width=avatar['width'] if avatar else None,
                                height=avatar['height'] if avatar else None, **urls),
                    read_only=True, portrait_size_unchanged=True, runtime_verified=False)

    def avatar_png(self, source_id, name, identity_sha256, state='normal'):
        if not isinstance(identity_sha256, str) or not SHA_RE.fullmatch(identity_sha256):
            raise GuiRuntimeError('invalid_request', '头像资料标记不正确，请重新选择人物。')
        if state not in ('normal', 'selected'):
            raise GuiRuntimeError('invalid_request', '头像状态不正确。')
        binding, refs = self._binding(source_id, name)
        if identity_digest(binding) != identity_sha256.lower():
            raise GuiRuntimeError('source_changed', '人物资料已更新，请重新选择人物。', 409)
        avatar = binding.get('avatar')
        if not avatar:
            raise GuiRuntimeError('speaker_avatar_unavailable', '没有读到这个人物的原作回看头像。', 404)
        key = identity_sha256.lower(), state
        with self._lock:
            if key in self._pngs:
                self._pngs.move_to_end(key)
                return self._pngs[key]
        ref = avatar['reference']
        if ref['width'] * ref['height'] > 24_000_000:
            raise GuiRuntimeError('speaker_avatar_too_large', '这个回看头像图集过大，暂不能预览。', 422)
        payload, fresh = resource_reference(Path(ref['archive_path']), ref['resource_name'])
        if fresh != ref:
            raise GuiRuntimeError('source_changed', '原作回看头像已变化，请重新选择人物。', 409)
        normalized, _report = convert_hzc_to_premultiplied_alpha(payload)
        raw = zlib.decompress(normalized[44:])
        atlas = Image.frombytes('RGBA', (ref['width'], ref['height']), raw, 'raw', 'BGRa')
        x, y, w, h = (avatar[k] for k in ('x', 'y', 'width', 'height'))
        x += w if state == 'selected' else 0
        cell = atlas.crop((x, y, x+w, y+h))
        output = BytesIO()
        cell.save(output, format='PNG')
        if any(fingerprint(p) != stamp for p, stamp in refs):
            raise GuiRuntimeError('source_changed', '读取期间头像发生变化，请重新选择。', 409)
        png = output.getvalue()
        result = png, hashlib.sha256(png).hexdigest()
        with self._lock:
            self._pngs[key] = result
            while len(self._pngs) > 64:
                self._pngs.popitem(last=False)
        return result
