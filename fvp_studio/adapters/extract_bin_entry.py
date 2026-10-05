"""Bounded single-entry extraction to a new workspace file, never a game."""
# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
from ..bin_archive import archive_entry_table_file
from ..local_binding import stat_identity
from .build_bin_patch import workspace_output, _copy_exact

def extract(archive, entry_index, output):
    archive, output = workspace_output(archive, output)
    before = archive.stat()
    entries = archive_entry_table_file(archive)
    if type(entry_index) is not int or not 0 <= entry_index < len(entries):
        raise ValueError("BIN 条目索引无效")
    offset, size, _name = entries[entry_index]
    if size > 256 * 1024 * 1024:
        raise ValueError("条目超过独立提取上限")
    output.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("rb") as stream, output.open("xb") as target:
        stream.seek(offset)
        magic = stream.read(min(4, size))
        stream.seek(offset)
        _copy_exact(stream, target, size)
    if stat_identity(archive.stat()) != stat_identity(before):
        raise ValueError("提取时来源发生变化")
    return dict(size=size, magic=magic)
