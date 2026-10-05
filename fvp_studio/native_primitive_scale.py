"""Bounded read-only proof of a modern registered primitive RS clamp.

Registration names locate candidates; the complete third-argument setter,
paired 16-bit stores and clamp branches establish the scale range. Addresses,
scale bounds and storage fields are read from the current PE, not title names.
"""
from __future__ import annotations

from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import NativeSizeDiscoveryError, _pe_sections
from .native_legacy_size_discovery import _relocated, _function


def extract_modern_rs_limits(raw):
    image, sections = _pe_sections(raw)
    registration = re.compile(
        engine_pattern('native_primitive_scale:20:8'),
        re.DOTALL)
    matches = []
    for _size, rva, length, pointer, flags in sections:
        if not flags & 0x20000000:
            continue
        for match in registration.finditer(raw[pointer:pointer + length]):
            try:
                label = _relocated(raw, image, sections, struct.unpack("<I", match["label"])[0],
                                   executable=False, length=10)
                if raw[label:label + 10] != engine_pattern('native_primitive_scale:31:44'):
                    continue
                address = struct.unpack("<I", match["handler"])[0]
                offset, code = _function(raw, image, sections, address)
                registrar = image + rva + match.end() + struct.unpack("<i", match["register"])[0]
                _relocated(raw, image, sections, registrar, executable=True)
            except NativeSizeDiscoveryError:
                continue
            matches.append((offset, code, pointer + match.start()))
    if len(matches) != 1:
        raise NativeSizeDiscoveryError("现代 PrimSetRS 没有唯一的参数3注册器证据")
    offset, code, site = matches[0]
    setter = re.fullmatch(
        engine_pattern('native_primitive_scale:44:8'),
        code, re.DOTALL)
    if setter is None:
        raise NativeSizeDiscoveryError("现代 RS 第三参数的完整钳位/成对字段写入证据不闭合")
    low, high = (struct.unpack("<i", setter[key])[0] for key in ("low", "high"))
    fields = [setter[key][0] for key in ("rsx", "rsy")]
    stride, rotation = setter["stride"][0], setter["rotation"][0]
    if (not 0 < low < high <= 0x7fff or low != struct.unpack("<b", setter["low8"])[0]
            or fields[1] != fields[0] + 2 or fields[1] + 2 > stride
            or rotation + 2 > stride or any(abs(rotation - field) < 2 for field in fields)):
        raise NativeSizeDiscoveryError("现代 RS 原生范围、步长或字段布局不一致")
    return dict(native_scale_range=[low, high], rs_fields=fields, rotation_field=rotation,
                primitive_stride=stride, primitive_array_offset=struct.unpack("<I", setter["base"])[0],
                setter_handler_offset=offset, setter_registration_offset=site,
                setter_sha256=hashlib.sha256(code).hexdigest(), exe_sha256=hashlib.sha256(raw).hexdigest(),
                evidence="x86-registered-modern-rs-third-argument-clamp-paired-fields/1")
