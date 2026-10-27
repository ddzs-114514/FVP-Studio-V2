"""Freeze registered movie references without decoding or modifying videos."""
from copy import deepcopy
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil

from .gui_runtime import ID_RE, SHA_RE, fingerprint
from .gui_cinematics import GuiCinematics, identity

KIND = 'GuiMovie'
IMPORT_NAME_RE = re.compile(r'FVP_MOVIE_[0-9a-f]{64}(?:_[1-9][0-9]*)?\.(?:wmv|mpg|mpeg|avi)')


def movie_scene_ids(program, chapter):
    """No dialogue/actor/choice body may be silently swallowed by an OP."""
    events = program['events']
    if not any(e['kind'] == KIND for e in events):
        return set()
    if chapter is None:
        if any(e['kind'] not in {'Scene','Background',KIND,'End'} for e in events):
            raise ValueError('OP 须放在独立场景，不能与台词、角色或同拍动作混排。')
        return {e['scene_id'] for e in events if e['kind'] == 'Scene'}
    if 'routes' not in chapter:
        raise ValueError('章节 OP 须使用具有明确出口的场景路线。')
    result = set()
    routes = {r['scene_id']:r for r in chapter['routes']}
    for row in chapter['scenes']:
        block = events[row['event_index']+1:row['exit_index']]
        if not any(e['kind'] == KIND for e in block):
            continue
        setup = events[row['event_index']+1:row['setup_end']]
        body = events[row['setup_end']+1:row['exit_index']]
        if (any(e['kind'] != 'Background' for e in setup)
                or not body or any(e['kind'] != KIND for e in body)):
            raise ValueError('章节内 OP 场景只能顺序放置影片，不混排其他节拍或角色。')
        if routes[row['scene_id']]['mode'] not in {'next','jump','end'}:
            raise ValueError('OP 结束请顺接、跳转或结束；选项／条件出口请放在相邻普通场景。')
        result.add(row['scene_id'])
    return result


def event_values(fields):
    if not isinstance(fields, dict) or set(fields) != {'source','resource','file_identity','skippable','duration_ms'}:
        raise ValueError('影片指令字段不完整。')
    resource = fields['resource']
    if (not isinstance(fields['source'], str) or not ID_RE.fullmatch(fields['source'])
            or not isinstance(fields['file_identity'], str) or not SHA_RE.fullmatch(fields['file_identity'])
            or not isinstance(resource, str) or not resource or len(resource) > 254
            or any(c in resource for c in ('\\', ':', '\0'))
            or resource != PurePosixPath(resource).as_posix()
            or PurePosixPath(resource).is_absolute() or '..' in PurePosixPath(resource).parts):
        raise ValueError('影片引用不是已登记游戏内的安全相对路径。')
    if type(fields['skippable']) is not bool:
        raise ValueError('影片是否允许跳过须为布尔值。')
    if type(fields['duration_ms']) is not int or not 1000 <= fields['duration_ms'] <= 86400000:
        raise ValueError('影片时间轴估计时长须为 1 秒～24 小时。')
    return deepcopy(fields)


def file_hash(path):
    before = fingerprint(path)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    if fingerprint(path) != before:
        raise ValueError('读取期间影片文件发生变化，请重新选择。')
    return digest.hexdigest()


def key(event):
    return tuple(event[k] for k in ('source', 'resource', 'file_identity'))


def freeze(runtime, event):
    event_values(event)
    reader = getattr(runtime, 'cinematics', None) or GuiCinematics(runtime)
    row, path = reader.resolve(event['source'], event['resource'], event['file_identity'])
    stamp = fingerprint(path)
    result = dict(root=reader.source(event['source']).root.resolve(), path=path,
                  stamp=stamp, sha256=file_hash(path), size=row['size'])
    if fingerprint(path) != stamp or identity(path) != event['file_identity']:
        raise ValueError('冻结期间影片文件发生变化。')
    return result


def check_asset(asset):
    path, root = Path(asset['path']), Path(asset['root']).resolve()
    if (not path.resolve().is_relative_to(root) or fingerprint(path) != asset['stamp']
            or file_hash(path) != asset['sha256']):
        raise ValueError('影片内容或位置已改变，请重新生成。')


class NativeMovieBindings:
    def __init__(self, target, frozen):
        from .native_movie import NativeMovieBinding
        self.target, self.frozen = target, frozen
        self.native = NativeMovieBinding(target.context)
        self.assets = {}
        self.imports = {}
        root = target.root.resolve()
        occupied = {p.name.casefold() for p in root.iterdir()}
        imported = {}
        for reference, asset in sorted(frozen.movies.items()):
            source_root = Path(asset['root']).resolve()
            suffix = PurePosixPath(reference[1]).suffix.lower()
            if Path(asset['path']).resolve() != (source_root/reference[1]).resolve():
                raise ValueError('影片路径与已冻结的来源引用不一致。')
            if suffix not in self.native.suffixes:
                raise ValueError('此影片不是目标游戏已使用的文件类型；尚不自动转码。')
            check_asset(asset)
            foreign = source_root != root
            resource = reference[1]
            if foreign:
                identity = (asset['sha256'], suffix)
                if identity not in imported:
                    stem = 'FVP_MOVIE_' + asset['sha256']
                    resource, number = stem + suffix, 0
                    while resource.casefold() in occupied:
                        number += 1
                        resource = stem + '_' + str(number) + suffix
                    occupied.add(resource.casefold())
                    imported[identity] = resource
                resource = imported[identity]
            bound = dict(asset, target_resource=resource, imported=foreign)
            self.assets[reference] = bound
            if foreign:
                self.imports.setdefault(resource, bound)

    def resolve(self, event):
        event_values({k:v for k,v in event.items() if k != 'kind'})
        asset = self.assets.get(key(event))
        if asset is None:
            raise ValueError('影片缺少本次导出的冻结素材绑定。')
        check_asset(asset)
        return asset

    def publish(self, folder):
        """Stream only selected foreign files into the internal candidate."""
        from .performance_install import _safe
        folder = _safe(folder)
        roots = {self.target.root.resolve(), *(Path(v['root']).resolve() for v in self.assets.values())}
        if any(folder.is_relative_to(root) or root.is_relative_to(folder) for root in roots):
            raise ValueError('影片候选目录不能与游戏来源重叠。')
        files, outputs = {}, {}
        for name, asset in self.imports.items():
            check_asset(asset)
            path = folder/name
            with Path(asset['path']).open('rb') as incoming, path.open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            output = dict(size=path.stat().st_size, sha256=file_hash(path))
            if output != {k:asset[k] for k in ('size','sha256')}:
                raise ValueError('复制的影片与冻结素材不一致，已停止生成。')
            check_asset(asset)
            files[name], outputs[name] = path, output
        return files, outputs

    def report(self):
        return dict(native=self.native.report(), files=[dict(source=k[0], resource=k[1],
            file_identity=k[2], sha256=v['sha256'], size=v['size'],
            target_resource=v['target_resource'], imported=v['imported']) for k,v in self.assets.items()],
            registered_source_import=True, unique_imported_files=len(self.imports),
            imported_name_policy='content_hash_no_overwrite', external_transcoding=False,
            target_native_extensions=list(self.native.suffixes), decoder_compatibility_verified=False,
            copied_with_new_game_directory=True, original_movie_files_modified=False,
            content_hash_checked=True, runtime_verified=False)
