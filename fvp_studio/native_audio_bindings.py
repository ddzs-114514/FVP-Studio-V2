"""Additive audio assets for a target-bound generic audio adapter.

Reuse the existing streamed pack publisher, but never reuse Hoshi IDs, its
fixed BGM table, name widths or archive preference as a compatibility test.
Every selected asset receives an explicit path in a target-proven namespace.
"""
from copy import deepcopy
from pathlib import Path

from .bin_archive import archive_entry_names_file
from .gui_audio_bindings import GuiAudioBindings, MAX_IMPORTED
from .gui_runtime import GuiRuntimeError, SHA_RE, fingerprint
from .performance_install import _safe

SCHEMA = 'fvp-native-audio-bindings/1'


class NativeAudioBindings(GuiAudioBindings):
    def __init__(self, target, native, frozen):
        self.root, self.frozen = _safe(Path(target.root)), frozen
        if native.source is not target.context.document:
            raise ValueError('声音调用与素材目标不是同一份游戏脚本。')
        native.validate()
        self.native, self.bindings, self.groups, self.published = native, {}, {}, False
        self.voice_replay_next = None
        self.voice_replay_tokens = []
        grouped = {}
        for key, asset in sorted(frozen.audios.items()):
            kind = asset.get('kind')
            if kind not in native.bindings:
                raise ValueError('当前目标尚未绑定这类声音：' + str(kind))
            if (len(key) != 4 or not isinstance(key[3],str) or not SHA_RE.fullmatch(key[3])
                    or asset.get('sha256') != key[3] or asset.get('archive') != key[1]
                    or asset.get('resource') != key[2] or type(asset.get('size')) is not int
                    or not 0 < asset['size'] <= 128*1024*1024):
                raise ValueError('声音的冻结素材引用不完整。')
            grouped.setdefault(kind, {}).setdefault(key[3], []).append((key, asset))
        if sum(map(len,grouped.values())) > MAX_IMPORTED:
            raise ValueError('这章新增声音太多，请拆成较小章节。')
        for kind, assets in sorted(grouped.items()):
            candidates = [self.root/name for name in sorted(native.bindings[kind]['routes'])
                          if (self.root/name).is_file()]
            if not candidates:
                raise ValueError('目标游戏缺少已匹配的声音素材包：' + kind)
            path = _safe(candidates[0],file=True,independent=False)
            if path.parent != self.root:
                raise ValueError('目标声音包不能位于登记目录之外。')
            stamp = fingerprint(path)
            names = set(archive_entry_names_file(path))
            ids = {int(n) for n in names if n.isascii() and n.isdigit()}
            group = self.groups[path.name] = dict(path=path,stamp=stamp,items=[])
            frozen.references.append((path,stamp))
            allocated = 0
            for digest, references in sorted(assets.items()):
                while allocated in ids or allocated == 0:
                    allocated += 1
                if allocated > 0x7fffffff:
                    raise ValueError('目标声音资源编号已用尽。')
                native_id=allocated;ids.add(native_id)
                name='FVP_A_'+digest[:24]
                suffix=0
                while name.casefold() in {n.casefold() for n in names}:
                    suffix+=1;name='FVP_A_'+digest[:24]+'_'+str(suffix)
                names.add(name)
                binding=dict(native_id=native_id,target_archive=path.name,target_resource=name,
                    sha256=digest,kind=kind,imported=True)
                for key,asset in references:
                    if any(asset.get(f)!=references[0][1].get(f) for f in ('kind','size','format')):
                        raise ValueError('同一声音哈希的保存信息互相冲突。')
                    self.bindings[key]={**deepcopy(asset),**binding}
                group['items'].append(dict(key=references[0][0],resource=name,native_id=native_id,
                    kind=kind,size=references[0][1]['size'],sha256=digest))
            if fingerprint(path)!=stamp:
                raise GuiRuntimeError('source_changed','分配声音时目标资源包发生变化。',409)
        frozen.check_unchanged()

    def reserve_voice_replay_token(self):
        if 'voice' not in self.native.bindings or not any(b.get('kind') == 'voice' for b in self.bindings.values()):
            raise ValueError('回看配音编号缺少已绑定的人声素材。')
        # Token space is shared by native replay metadata, not scoped to the
        # selected output archive. Reuse the same two-pack/new-entry allocator
        # as the legacy exporter; keep playback paths target-bound above.
        return super().reserve_voice_replay_token()

    def report(self):
        result = super().report()
        result.update(schema=SCHEMA,target=getattr(self.native.context,'target_id',None),
            game_name_switch_used=False,explicit_target_paths=True,
            original_ids_reused=False,pack_built=self.published,
            voice_replay_tokens=list(self.voice_replay_tokens),
            scene_export_connected=False,runtime_verified=False)
        return result

    def publish(self, folder, reader):
        if self.published:
            raise ValueError('声音素材包不能重复生成。')
        self.native.validate()
        result = super().publish(folder,reader)
        self.native.validate()
        self.published=True
        return result
