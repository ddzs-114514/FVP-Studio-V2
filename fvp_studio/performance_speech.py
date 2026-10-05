"""Owned-stage names and native B.LOG keys; never call a SPEAK wrapper.

Native B.LOG couples its history name and avatar lookup. Manual selection is
therefore a history identity, not an independently replaceable atlas image.
"""
from functools import lru_cache
import hashlib
import io

from .story_backlog import discover_story_backlog, _normalise_name
from .portrait_emitter import _encode_push


def speech_catalog(document, source):
    profile = discover_story_backlog(document)
    if not profile['available']:
        raise ValueError(profile['reason'])
    cells = profile['_name_cells']
    result, seen = [], set()
    for item in document.instructions:
        if not 0x3D6A9 <= item.offset < 0x3E100 or item.mnemonic != 'push_string':
            continue
        name = _normalise_name(item.text)
        if name not in cells or name in seen:
            continue
        seen.add(name)
        # Use the active translated literal, including its exact padding.
        raw = source[item.offset:item.offset+item.size]
        if raw[0] != 14 or raw[1] != len(raw)-2 or raw[-1] != 0:
            raise ValueError('B.LOG 姓名指令漂移')
        key = raw[2:-1].decode('gbk', errors='strict')
        ident = 'native-' + hashlib.sha256(item.text.encode()).hexdigest()[:16]
        cell = cells[name]
        result.append(dict(id=ident, name=_normalise_name(key), source='星空的记忆HD',
            native_key=key, canonical_name=name, cell=cell, avatar_available=True,
            avatar_reason='剧情条件会影响此头像' if cell['conditional'] else '原作 B.LOG 头像'))
    return result


def resolve_speech(event, catalog):
    lookup = {e['id']: e for e in catalog}
    mode = event['speaker_mode']
    selected = lookup.get(event['speaker_id'])
    unknown = next(e for e in catalog if e['canonical_name'] == '？？？')
    if mode == 'character' and selected is None:
        raise ValueError('请从角色列表选择说话人；其他作品或原创角色请使用自定义姓名')
    name = (event['display_name'].strip() or selected['name']) if mode == 'character' else (
        event['display_name'].strip() if mode == 'custom' else '？？？' if mode == 'unknown' else '')
    if mode == 'custom' and not name:
        raise ValueError('自定义说话人姓名不能为空')
    _encode_push(name, 'gbk')
    blog_mode = event['blog_mode']
    history = None if mode == 'narration' else (selected if mode == 'character' else unknown)
    history_key = None if mode == 'narration' else (selected['native_key'] if mode == 'character' else
        unknown['native_key'] if mode == 'unknown' else name)
    if blog_mode == 'manual':
        history = lookup.get(event['blog_speaker_id'])
        if history is None:
            raise ValueError('请指定 B.LOG 回放角色')
        history_key = history['native_key']
    elif blog_mode == 'none':
        history = None
        history_key = None
    return dict(name=name, text=event['text'], history_key=history_key,
        blog_speaker_id=history['id'] if history else None,
        blog_name=_normalise_name(history_key), blog_mode=blog_mode,
        speaker_mode=mode, source_game=event['source_game'])


@lru_cache(maxsize=4)
def avatar_payloads(archive, size, mtime, cells):
    """Fingerprint-keyed bounded atlas decode, shared across keystroke previews."""
    from pathlib import Path
    from .bin_archive import archive_entry_table_file
    from .resource_builder import _decoded_entry_image
    path = Path(archive)
    records = archive_entry_table_file(path)
    entry = next((i for i, r in enumerate(records) if r[2] == 'bl_char'), None)
    if entry is None:
        raise ValueError('B.LOG 原作图集 bl_char 不存在')
    atlas, _ = _decoded_entry_image(path, entry, 0)
    if atlas.size != (1900, 950):
        raise ValueError('B.LOG 头像图集尺寸不匹配')
    result = {}
    for col, row in cells:
        x, y = col*380+190, row*190
        buffer = io.BytesIO()
        atlas.crop((x,y,x+190,y+190)).save(buffer, format='PNG')
        result[f'blog:{col}:{row}'] = buffer.getvalue()
    return result
