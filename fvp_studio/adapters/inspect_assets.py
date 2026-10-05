"""Only the required BIN interface, not the external HCB text parser."""
# SPDX-License-Identifier: GPL-3.0-or-later
from ..bin_archive import archive_entry_table_file

def parse_bin(path):
    rows = archive_entry_table_file(path)
    return {"assets": [dict(index=i, offset=offset, size=size, name=name)
                       for i, (offset, size, name) in enumerate(rows)]}
