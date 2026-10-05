"""Self-written compatibility interfaces; no external workspace imports."""
# SPDX-License-Identifier: GPL-3.0-or-later
from importlib import import_module

NAMES = frozenset({"hzc_template_codec", "build_bin_patch", "extract_bin_entry", "inspect_assets", "index_visual_assets"})

def load(name):
    if name not in NAMES:
        raise ValueError("未登记的资源接口")
    return import_module(f"{__name__}.{name}")
