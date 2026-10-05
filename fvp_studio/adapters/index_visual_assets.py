"""Read-only classification and header metadata for the portable profile."""
# SPDX-License-Identifier: GPL-3.0-or-later
from .hzc_template_codec import metadata

def classify(archive, name):
    upper = name.upper()
    if archive == "graph_bs.bin" or upper.startswith("CHR_"):
        return "portrait"
    if archive == "graph_bg.bin" or upper.startswith("BG"):
        return "background"
    if archive == "graph_vis2.bin" or upper.startswith("VIS_"):
        return "cutscene_visual"
    if archive in {"graph_vis.bin", "graph_vis1.bin"}:
        return "event_visual"
    return "misc_visual" if upper.startswith("ETC") else "graph_misc"

def hzc_metadata(archive, offset, size):
    with archive.open("rb") as stream:
        stream.seek(offset)
        header = stream.read(min(44, size))
    if len(header) < 44 or header[:4] != b"hzc1" or header[12:16] != b"NVSG":
        return dict(container="unknown", magic=header[:4].hex())
    result = metadata(header)
    result.pop("header")
    result.update(container="hzc1/nvsg", offset_x=int.from_bytes(header[24:26], "little", signed=True),
                  offset_y=int.from_bytes(header[26:28], "little", signed=True))
    return result
