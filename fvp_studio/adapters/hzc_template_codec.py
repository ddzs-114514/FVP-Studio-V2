"""HZC metadata interface backed by this project's validated format reader."""
# SPDX-License-Identifier: GPL-3.0-or-later
from ..bin_archive import hzc_metadata

TYPE_NAMES = {0: "single24", 1: "single32", 2: "multi32", 3: "single8", 4: "single1"}
DEPTHS = {0: 3, 1: 4, 2: 4, 3: 1, 4: 1}

def metadata(data):
    info = hzc_metadata(data, validate_pixels=False)
    return dict(kind=info.kind, type=TYPE_NAMES[info.kind], width=info.width,
                height=info.height, frame_count=info.frame_count,
                payload_length=info.raw_length, header=data[:44])

def premul(value, alpha):
    return (value * alpha + 127) // 255

def unpremul(value, alpha):
    return 0 if not alpha else min(255, (value * 255 + alpha // 2) // alpha)
