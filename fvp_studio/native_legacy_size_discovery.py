"""Bounded old-x86 FVP engine proofs, without game identities or addresses.

Registration labels locate candidate handlers only. RS meaning is established
by the third-argument setter, shared primitive-array addressing, and paired
field initialisation. Unrecognised code does not inherit these rules.
"""
from __future__ import annotations

from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import NativeSizeDiscoveryError, _pe_sections


def _relocated(raw, image, sections, address, *, executable, length=1):
    matches = [row for row in sections if bool(row[4] & 0x20000000) == executable
               and row[1] <= address - image
               and address - image + length <= row[1] + row[2]]
    if len(matches) != 1:
        raise NativeSizeDiscoveryError("旧版证据地址不在唯一匹配的 PE 分节内")
    row = matches[0]
    return row[3] + address - image - row[1]


def legacy_viewport_candidates(raw, mode, image, sections):
    # HCB byte fetched from the script stream, followed by the zero/nonzero
    # width/height stores. Field offsets differ across these engine versions.
    pattern = re.compile(
        engine_pattern('native_legacy_size_discovery:30:8'), re.DOTALL)
    matches = []
    for _size, _rva, length, pointer, flags in sections:
        if not flags & 0x20000000:
            continue
        for found in pattern.finditer(raw[pointer:pointer + length]):
            if found["hfield"][0] != found["wfield"][0] + 4:
                continue
            address = struct.unpack("<I", found["global"])[0]
            try:
                _relocated(raw, image, sections, address, executable=False, length=4)
            except NativeSizeDiscoveryError:
                continue
            widths = [struct.unpack("<I", found[key])[0] for key in ("w0", "w1")]
            heights = [struct.unpack("<I", found[key])[0] for key in ("h0", "h1")]
            if any(not (320 <= w <= 16384 and 200 <= h <= 16384)
                   for w, h in zip(widths, heights)):
                continue
            selected = int(mode != 0)
            matches.append(dict(viewport=[widths[selected], heights[selected]], mode=mode,
                reader_offset=pointer + found.start(),
                viewport_fields=[found["wfield"][0], found["hfield"][0]],
                renderer_pointer_va=address, zero_mode_viewport=[widths[0], heights[0]],
                nonzero_mode_viewport=[widths[1], heights[1]],
                exe_sha256=hashlib.sha256(raw).hexdigest(),
                evidence="x86-script-mode-byte-boolean-viewport-initializer/1"))
    return matches


def _handler(raw, image, sections, label, argc):
    pattern = re.compile(
        engine_pattern('native_legacy_size_discovery:66:8') + bytes((argc,))
        + engine_pattern('native_legacy_size_discovery:68:10'),
        re.DOTALL)
    matches = []
    for _size, rva, length, pointer, flags in sections:
        if not flags & 0x20000000:
            continue
        for found in pattern.finditer(raw[pointer:pointer + length]):
            try:
                name = _relocated(raw, image, sections, struct.unpack("<I", found["label"])[0],
                                  executable=False, length=len(label) + 1)
                if raw[name:name + len(label) + 1] != label.encode("ascii") + b"\0":
                    continue
                address = struct.unpack("<I", found["handler"])[0]
                offset = _relocated(raw, image, sections, address, executable=True)
                registrar = (image + rva + found.end()
                             + struct.unpack("<i", found["register"])[0])
                _relocated(raw, image, sections, registrar, executable=True)
            except NativeSizeDiscoveryError:
                continue
            matches.append(dict(address=address, offset=offset, registrar=registrar,
                                registration_offset=pointer + found.start()))
    if len(matches) != 1:
        raise NativeSizeDiscoveryError(f"{label} 没有唯一闭合的原生注册记录")
    return matches[0]


def _function(raw, image, sections, address):
    offset = _relocated(raw, image, sections, address, executable=True)
    section = next(row for row in sections if row[3] <= offset < row[3] + row[2])
    stop = min(offset + 512, section[3] + section[2])
    padding = raw.find(b"\xcc\xcc", offset + 8, stop)
    return offset, raw[offset:padding if padding >= 0 else stop]


def extract_legacy_engine_rs(raw):
    image, sections = _pe_sections(raw)
    setter = _handler(raw, image, sections, "PrimSetRS", 3)
    sprite = _handler(raw, image, sections, "PrimSetSprt", 4)
    if setter["registrar"] != sprite["registrar"]:
        raise NativeSizeDiscoveryError("旧版原生调用未注册到同一分派器")
    setter_offset, setter_code = _function(raw, image, sections, setter["address"])
    layout = re.findall(engine_pattern('native_legacy_size_discovery:109:24'), setter_code, re.DOTALL)
    clamp = re.search(
        engine_pattern('native_legacy_size_discovery:111:8'), setter_code, re.DOTALL)
    if len(layout) != 1 or clamp is None or not setter_code.startswith(engine_pattern('native_legacy_size_discovery:116:71')):
        raise NativeSizeDiscoveryError("旧版 RS 设置器的第三参数/成对字段写入结构未闭合")
    stride, base = layout[0][0][0], struct.unpack("<I", layout[0][1])[0]
    fields = [clamp["rsx"][0], clamp["rsy"][0]]
    lower, upper = struct.unpack("<i", clamp["low32"])[0], struct.unpack("<i", clamp["high"])[0]
    if (lower != struct.unpack("<b", clamp["low"])[0] or not 0 < lower < upper
            or fields[1] != fields[0] + 2 or fields[1] + 2 > stride):
        raise NativeSizeDiscoveryError("旧版 RS 字段或原生范围不一致")

    sprite_offset, code = _function(raw, image, sections, sprite["address"])
    calls = list(re.finditer(engine_pattern('native_legacy_size_discovery:126:29'), code, re.DOTALL))
    if len(calls) != 1 or not code.startswith(engine_pattern('native_legacy_size_discovery:127:46')):
        raise NativeSizeDiscoveryError("旧版身体初始化没有唯一的 primitive 分配调用")
    call = calls[0]
    helper_address = sprite["address"] + call.end() + struct.unpack("<i", call[1])[0]
    helper_offset, helper = _function(raw, image, sections, helper_address)
    storage = re.fullmatch(
        engine_pattern('native_legacy_size_discovery:133:8'), helper, re.DOTALL)
    if (storage is None or storage["stride"][0] != stride
            or struct.unpack("<I", storage["base"])[0] != base
            or not 0 <= struct.unpack("<I", storage["next"])[0] - base < stride):
        raise NativeSizeDiscoveryError("身体初始化与 RS 设置器没有共享的 primitive 存储布局证据")
    xy = [storage["x"][0], storage["y"][0]]
    if (xy[1] != xy[0] + 2 or any(field in fields for field in xy)
            or storage["link1"][0] != storage["link0"][0] + 2):
        raise NativeSizeDiscoveryError("旧版 primitive 字段布局相互冲突")

    after_call = code[call.end():]
    variants = (
        (engine_pattern('native_legacy_size_discovery:152:9'), 1,
         engine_pattern('native_legacy_size_discovery:153:9')),
        (engine_pattern('native_legacy_size_discovery:155:9'), 2,
         engine_pattern('native_legacy_size_discovery:156:9')),
    )
    initialized = []
    for prefix, register, tail in variants:
        initial = re.match(prefix, after_call, re.DOTALL)
        if initial is None:
            continue
        rs = struct.unpack("<I", initial[1])[0]
        cursor, writes = initial.end(), []
        while (cursor + 4 <= len(after_call) and after_call[cursor:cursor + 2] == b"\x66\x89"
               and after_call[cursor + 2] & 0xC7 == 0x40):
            writes.append((after_call[cursor + 3], (after_call[cursor + 2] >> 3) & 7,
                           sprite_offset + call.end() + cursor))
            cursor += 4
        remaining = re.fullmatch(tail, after_call[cursor:], re.DOTALL)
        size_writes = [(field, source, site) for field, source, site in writes if field in fields]
        if (remaining is None or [remaining[1][0], remaining[2][0]] != xy
                or len(size_writes) != 2 or [row[0] for row in size_writes] != fields
                or any(row[1] != register for row in size_writes) or not lower <= rs <= upper):
            continue
        initialized.append((rs, [row[2] for row in size_writes]))
    if len(initialized) != 1:
        raise NativeSizeDiscoveryError("旧版 RS 常量没有完整、不被后续覆盖的成对初始化证据")
    rs, sites = initialized[0]
    return dict(rs=rs, rs_fields=fields, primitive_stride=stride, primitive_array_offset=base,
        native_scale_range=[lower, upper], initializer_rs_sites=sites,
        sprite_handler_offset=sprite_offset, setter_handler_offset=setter_offset,
        primitive_helper_offset=helper_offset, setter_scale_branch=setter_offset + clamp.start(),
        sprite_registration_offset=sprite["registration_offset"],
        setter_registration_offset=setter["registration_offset"],
        exe_sha256=hashlib.sha256(raw).hexdigest(),
        evidence="x86-registered-sprite-init-and-third-argument-rs-paired-fields/1")
