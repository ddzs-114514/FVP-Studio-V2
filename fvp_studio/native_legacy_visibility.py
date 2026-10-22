"""Read-only legacy primitive alpha/draw proofs from registered x86 handlers.

This does not apply a known title's struct layout. The handlers must address
the same primitive array/stride already proven by the sprite/RS chain, and
their written fields must match that chain's fully checked initializers.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import NativeSizeDiscoveryError, _pe_sections
from .native_legacy_size_discovery import _handler, _function, extract_legacy_engine_rs


def extract_legacy_visibility(raw):
    image, sections = _pe_sections(raw)
    sprite = _handler(raw, image, sections, "PrimSetSprt", 4)
    alpha = _handler(raw, image, sections, "PrimSetAlpha", 2)
    draw = _handler(raw, image, sections, "PrimSetDraw", 2)
    if len({p["registrar"] for p in (sprite, alpha, draw)}) != 1:
        raise NativeSizeDiscoveryError("旧版显示调用没有注册到同一分派器。")
    scale = extract_legacy_engine_rs(raw)
    _, alpha_code = _function(raw, image, sections, alpha["address"])
    a = re.fullmatch(
        engine_pattern('native_legacy_visibility:25:8'), alpha_code, re.DOTALL)
    _, draw_code = _function(raw, image, sections, draw["address"])
    d = re.fullmatch(
        engine_pattern('native_legacy_visibility:31:8'), draw_code, re.DOTALL)
    if a is None or d is None:
        raise NativeSizeDiscoveryError("旧版透明度范围或显示 0/1 分支尚未闭合。")
    count = struct.unpack("<I", a["count"])[0]
    opaque = struct.unpack("<I", a["max"])[0]
    base, stride = scale["primitive_array_offset"], scale["primitive_stride"]
    alpha_field = struct.unpack("<I", a["storage"])[0]-base
    draw_field = struct.unpack("<I", d["storage"])[0]-base
    if (not 1 < count <= 65536 or not 0 < stride < 128 or a["count"] != d["count"] or opaque != 255
            or a["stride"][0] != stride or d["stride"][0] != stride
            or not 0 <= alpha_field < stride or not 0 <= draw_field < stride
            or alpha_field == draw_field or {alpha_field, draw_field} & set(scale["rs_fields"])):
        raise NativeSizeDiscoveryError("旧版透明度／显示字段不属于已绑定的图元布局。")
    # RS discovery validates the WHOLE sprite initializer and allocator code,
    # including these byte writes and their returned primitive pointer. Match
    # their fields against the independently registered setters, not a label.
    sprite_offset, sprite_code = _function(raw, image, sections, sprite["address"])
    helper_offset = scale["primitive_helper_offset"]
    helper_address = image+next(row[1]+helper_offset-row[3] for row in sections
        if row[3] <= helper_offset < row[3]+row[2])
    _, helper_code = _function(raw, image, sections, helper_address)
    alpha_init = b"\xc6\x40"+bytes((alpha_field, opaque))
    draw_init = b"\xc6\x46"+bytes((draw_field, 1))
    if sprite_code.count(alpha_init) != 1 or helper_code.count(draw_init) != 1:
        raise NativeSizeDiscoveryError("旧版显示字段与原生图元初始化没有唯一配对。")
    return dict(schema="fvp-native-legacy-visibility/1", exe_sha256=hashlib.sha256(raw).hexdigest(),
        primitive_stride=stride, primitive_array_offset=base,
        alpha_field=alpha_field, draw_field=draw_field,
        alpha_range=[0, opaque], opaque_alpha=opaque, draw_values=[0, 1],
        alpha_primitive_range=[1, count-1], draw_primitive_range=[0, count-1],
        alpha_registration=alpha, draw_registration=draw, sprite_registration=sprite,
        alpha_initializer_offset=sprite_offset+sprite_code.index(alpha_init),
        draw_initializer_offset=helper_offset+helper_code.index(draw_init),
        source_sprite_and_setters_share_storage=True, original_game_written=False,
        source_size_rule_changed=False, runtime_verified=False)
