"""Standalone stream rebuild interface using our checked BIN directory reader.

Only brand-new workspace outputs are allowed. Source archives are read-only.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from dataclasses import dataclass
from pathlib import Path
import hashlib
import shutil
import struct
from ..bin_archive import _parse_archive_file_index
from ..local_binding import stat_identity

CHUNK_SIZE = 1024 * 1024

@dataclass(frozen=True)
class Entry:
    name_offset: int
    offset: int
    size: int

def read_archive(path):
    path = Path(path)
    index, total, metadata, before = _parse_archive_file_index(path)
    cursor = index.metadata_end
    rows = []
    for item in index.entries:
        if item.file_offset != cursor:
            raise ValueError("流式替换要求连续、无填充的原始 BIN；拒绝猜测布局")
        rows.append(Entry(item.name_offset, item.file_offset, item.file_size))
        cursor += item.file_size
    if cursor != total or stat_identity(path.stat()) != stat_identity(before):
        raise ValueError("BIN 覆盖范围不完整或读取时发生变化")
    return rows, metadata[8 + 12 * len(rows):]

def sha256(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            result.update(chunk)
    return result.hexdigest()

def workspace_output(archive, output):
    archive = Path(archive).resolve(strict=True)
    raw = Path(output).absolute()
    if raw.is_symlink():
        raise ValueError("输出不能是链接")
    for parent in raw.parents:
        if parent.exists() and (parent.is_symlink() or getattr(parent.stat(), "st_file_attributes", 0) & 0x400):
            raise ValueError("输出目录不能包含链接或联接")
    output = raw.resolve()
    if output.exists() or archive.parent == output.parent or archive.parent in output.parents:
        raise ValueError("只能写入原作目录之外的新工作文件；拒绝覆盖")
    return archive, output

def _copy_exact(source, destination, size):
    while size:
        chunk = source.read(min(size, CHUNK_SIZE))
        if not chunk:
            raise ValueError("BIN 负载被截断")
        destination.write(chunk)
        size -= len(chunk)

def build(archive, replacements, output):
    archive, output = workspace_output(archive, output)
    entries, names = read_archive(archive)
    before = archive.stat()
    replacement_paths = {}
    details = []
    with archive.open("rb") as source:
        for number, path in replacements.items():
            if type(number) is not int or not 0 <= number < len(entries):
                raise ValueError("替换索引无效")
            path = Path(path).resolve(strict=True)
            if not path.is_file() or path == archive:
                raise ValueError("替换项不是独立工作文件")
            source.seek(entries[number].offset)
            old_magic = source.read(4)
            with path.open("rb") as replacement:
                new_magic = replacement.read(4)
            if old_magic in {b"hzc1", b"OggS", b"RIFF"} and old_magic != new_magic:
                raise ValueError("替换项格式与原条目不一致")
            replacement_paths[number] = (path, path.stat(), sha256(path))
            details.append(dict(entry_index=number, replacement_size=path.stat().st_size,
                                original_magic=old_magic.decode("latin1"), replacement_magic=new_magic.decode("latin1")))
    sizes = [replacement_paths[i][1].st_size if i in replacement_paths else e.size for i, e in enumerate(entries)]
    cursor = 8 + len(entries) * 12 + len(names)
    offsets = []
    for size in sizes:
        offsets.append(cursor)
        cursor += size
    if cursor > 0xFFFFFFFF:
        raise ValueError("BIN 输出超过 32 位格式上限")
    output.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("rb") as source, output.open("xb") as target:
        target.write(struct.pack("<II", len(entries), len(names)))
        for i, entry in enumerate(entries):
            target.write(struct.pack("<III", entry.name_offset, offsets[i], sizes[i]))
        target.write(names)
        for i, entry in enumerate(entries):
            if i in replacement_paths:
                path, stat, expected = replacement_paths[i]
                with path.open("rb") as stream:
                    _copy_exact(stream, target, sizes[i])
                if stat_identity(path.stat()) != stat_identity(stat) or sha256(path) != expected:
                    raise ValueError("构建时替换文件发生变化；不允许安装该输出")
            else:
                source.seek(entry.offset)
                _copy_exact(source, target, entry.size)
    if stat_identity(archive.stat()) != stat_identity(before):
        raise ValueError("构建时原始 BIN 发生变化；不允许安装该输出")
    read_archive(output)
    return dict(archive=str(archive), output=str(output), entry_count=len(entries),
                replacement_count=len(replacements), output_size=output.stat().st_size,
                output_sha256=sha256(output), replacements=details)
