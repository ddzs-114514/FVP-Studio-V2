"""GUI speech identity on native name, colour and backlog calls.

Canonical names/cells/default colours are read from registered source HCBs.
Foreign avatars are genuine native dim/selected cell pairs, not portrait crops.
Only generated candidates may redirect the audited backlog avatar callback;
original source files, the normal Comfy emitter and import sizes stay unchanged.
"""
from copy import deepcopy
from collections import Counter
from functools import lru_cache
from pathlib import Path
import hashlib
import struct
import zlib

from PIL import Image, ImageChops

from .gui_runtime import fingerprint
from .bin_archive import convert_hzc_to_premultiplied_alpha
from .hcb import parse_bytes
from .native_call_flow import NativeFunctionFlow
from .native_target_discovery import _function_regions, _discover_speaker_wrapper_family
from .performance_compile import args, call, jump, resource_reference, sha, CLEAN_SHA, SOURCE_SHA
from .performance_speech import speech_catalog, resolve_speech

CONTRACT = "fvp-gui-speaker-identity/1"
AVATAR_CALLBACK = 0x3D6A9
AVATAR_END = 0x3DBC0
COLOUR_FUNCTION = 0x11EB
AVATAR_SETUP = 0x80EA8
CUSTOM_PALETTE = 51  # Native neutral-speaker palette; original 25 resets it.


def constant(value):
    if value.get("kind") == "literal":
        return value.get("value")
    children = value.get("operands", [])
    if value.get("kind") in {"add", "sub", "mul", "div", "neg"}:
        numbers = [constant(v) for v in children]
        if all(type(v) is int for v in numbers):
            if value["kind"] == "neg": return -numbers[0]
            a, b = numbers
            if value["kind"] == "add": return a + b
            if value["kind"] == "sub": return a - b
            if value["kind"] == "mul": return a * b
            if b: return int(a / b)
    raise ValueError("原生角色资料包含未确定的动态值")


def literal_args_before(instructions, index, count):
    """Read contiguous constant expressions, never execute source calls.

    Native defaults can use arithmetic such as ``157 - 20`` for a channel.
    Globals, stack locals, jumps, calls and comparisons are not constants.
    """
    result = []
    cursor = index - 1
    budget = 96

    def take():
        nonlocal cursor, budget
        if cursor < 0 or budget <= 0: raise ValueError("not a bounded constant")
        item = instructions[cursor]
        cursor -= 1
        budget -= 1
        if item.mnemonic in {"push_i8", "push_i16", "push_i32"}:
            return item.operands["value"]
        if item.mnemonic == "push_nil": return None
        if item.mnemonic == "push_true": return True
        if item.mnemonic == "push_string": return item.text
        if item.mnemonic == "neg":
            value = take()
            if type(value) is int: return -value
        if item.mnemonic in {"add", "sub", "mul"}:
            right, left = take(), take()
            if type(left) is int and type(right) is int:
                if item.mnemonic == "add": return left + right
                if item.mnemonic == "sub": return left - right
                return left * right
        raise ValueError("not a constant")

    for _ in range(count):
        try: result.append(take())
        except ValueError: return None
    return list(reversed(result))


class ColourDefaults:
    """Resolve default RGB through literal setting calls and global copies.

    UI slider writes are not defaults. Only a source function's actual literal
    call sites are specialised; uncertain branches/values are left unresolved.
    """
    def __init__(self, document, regions, flow):
        self.flow = flow
        self.writers, self.calls, self.traces, self.cache = {}, {}, {}, {}
        by_start = {r.start: r for r in regions}
        for region in regions:
            body = document.instructions[region.instruction_start_index:region.instruction_end_index]
            for slot in {i.operands["value"] for i in body if i.mnemonic == "pop_global"}:
                self.writers.setdefault(slot, set()).add(region.start)
        for index, ins in enumerate(document.instructions):
            if ins.mnemonic != "call" or ins.operands["target"] not in by_start: continue
            region = by_start[ins.operands["target"]]
            values = literal_args_before(document.instructions, index, region.args)
            if values is not None:
                self.calls.setdefault(region.start, set()).add(tuple(values))

    def rgb(self, slots, seen=()):
        slots = tuple(slots)
        if slots in seen or len(seen) > 4: return None
        if slots in self.cache: return self.cache[slots]
        common = set.intersection(*(self.writers.get(s, set()) for s in slots))
        defaults = set()
        for address in common:
            for values in self.calls.get(address, ()):
                key = address, values
                if key not in self.traces:
                    self.traces[key] = self.flow.trace(address, literal_arguments=dict(enumerate(values)))
                trace = self.traces[key]
                if trace["blockers"]: continue
                selected = []
                for slot in slots:
                    writes = [w["value"] for w in trace["global_writes"] if w["slot"] == slot]
                    # Do not silently choose the last of uncertain branch writes.
                    if len(writes) != 1: break
                    selected.append(writes[0])
                if len(selected) != len(slots): continue
                try: rgb = tuple(constant(v) for v in selected)
                except ValueError:
                    if any(v.get("kind") != "global_read" for v in selected): continue
                    rgb = self.rgb([v["slot"] for v in selected], seen + (slots,))
                if rgb is not None and all(type(v) is int and 0 <= v <= 255 for v in rgb):
                    defaults.add(tuple(rgb))
        result = tuple(defaults.pop()) if len(defaults) == 1 else None
        # A failed cyclic path is not evidence that a later noncyclic path fails.
        if result is not None or not seen: self.cache[slots] = result
        return result


def native_default_colour(document, regions, flow, colour_address, identity, defaults=None):
    defaults = defaults or ColourDefaults(document, regions, flow)
    trace = flow.trace(colour_address, literal_arguments={0: identity})
    for item in trace["calls"]:
        if item["kind"] != "call" or item["argument_count"] != 2: continue
        try: numbers = [constant(v) for v in item["arguments"]]
        except ValueError: continue
        child = flow.trace(item["address"], literal_arguments=dict(enumerate(numbers)))
        colours = [c for c in child["calls"] if c.get("name") == "ColorSet"]
        if len(colours) != 1: continue
        channels = colours[0]["arguments"][1:4]
        if any(v.get("kind") != "global_read" for v in channels): continue
        slots = [v["slot"] for v in channels]
        rgb = defaults.rgb(slots)
        if rgb is not None: return list(rgb)
    return None


def native_avatar(document, regions, flow, name):
    candidates = []
    by_start = {r.start: r for r in regions}
    for region in regions:
        names = [s for s in region.strings if s.strip() == name]
        if region.args != 3 or region.locals != 6 or "PrimSetUV" not in region.syscalls or not names:
            continue
        trace = flow.trace(region.start, literal_arguments={1: names[0]})
        uv = [c for c in trace["calls"] if c.get("name") == "PrimSetUV"]
        setup = [c for c in trace["calls"] if c["kind"] == "call" and c["argument_count"] == 5]
        if len(uv) != 1 or len(setup) != 1: continue
        helper = flow.trace(setup[0]["address"])
        wh = [c for c in helper["calls"] if c.get("name") == "PrimSetWH"]
        if len(wh) != 1: continue
        try:
            x, y = [constant(v) for v in uv[0]["arguments"][1:]]
            w, h = [constant(v) for v in wh[0]["arguments"][1:]]
            atlas_slot = constant(setup[0]["arguments"][1])
        except ValueError: continue
        if not all(type(v) is int for v in (x, y, w, h, atlas_slot)) or not 0 < w <= 1024 or not 0 < h <= 1024:
            continue
        # Verify the native atlas load references the very same graphics slot.
        loaded = False
        for index, ins in enumerate(document.instructions):
            if ins.mnemonic not in {"call", "syscall"}: continue
            if ins.mnemonic == "call":
                entry = by_start.get(ins.operands["target"])
                count = entry.args if entry else 0
            else: count = document.header.syscalls[ins.operands["id"]].args
            values = literal_args_before(document.instructions, index, count)
            if values and values[0] == atlas_slot and any(v in ("bl_char", "graph/bl_char") for v in values):
                loaded = True
                break
        if loaded:
            candidates.append(dict(x=x, y=y, width=w, height=h, callback=region.start,
                atlas_slot=atlas_slot, native_key=names[0]))
    if len(candidates) != 1: return None
    return candidates[0]


@lru_cache(maxsize=8)
def source_catalog(path, stamp, encoding):
    data = Path(path).read_bytes()
    if len(data) > 32 * 1024 * 1024 or fingerprint(Path(path)) != stamp:
        raise ValueError("说话人来源脚本变化或过大")
    document = parse_bytes(data, encoding=encoding)
    regions = _function_regions(document)
    family = _discover_speaker_wrapper_family(document, regions)
    if family["status"] != "candidate_contiguous_prefix" or not family.get("color_table"):
        return {}
    flow = NativeFunctionFlow(document)
    colour = family["color_table"]["start"]
    call_counts = Counter(i.operands["target"] for i in document.instructions if i.mnemonic == "call")
    found = {}
    for entry in family["entries"]:
        # Only a real visible default name; do not pick a hidden-name selector.
        default = next((b for b in entry.get("selector_branches", {}).get("branches", [])
                        if b["selector_kind"] == "default_fallthrough"), None)
        names = default["name_variants"] if default else entry["name_variants"]
        trace = flow.trace(entry["start"], literal_arguments={0: None, 1: 0, 2: None}
                           if entry["args"] == 3 else None)
        calls = [c for c in trace["calls"] if c.get("address") == colour]
        if len(calls) != 1: continue
        value = calls[0]["arguments"][0]
        if value.get("kind") == "global_read":
            writes = [w for w in trace["global_writes"] if w["slot"] == value["slot"] and w["offset"] < calls[0]["offset"]]
            if not writes: continue
            value = writes[-1]["value"]
        try: identity = constant(value)
        except ValueError: continue
        if type(identity) is not int: continue
        for name in names:
            if not name or name.startswith("？") or "/" in name or "／" in name: continue
            found.setdefault(name, []).append(dict(native_id=identity, wrapper=entry["start"],
                source_call_sites=call_counts[entry["start"]]))
    for name, entries in found.items():
        # An unused same-name stub is not a second active character identity.
        # If several wrappers are used, keep all and require their facts to agree.
        used = [entry for entry in entries if entry["source_call_sites"]]
        if used: found[name] = used
    # Catalogue construction remains small; expensive per-name facts are lazy.
    return dict(document=document, regions=regions, flow=flow, colour=colour, names=found,
                defaults=ColourDefaults(document, regions, flow),
                hcb_sha256=sha(data))


def resolve_identity(source, name):
    """Registered files only; filename/game title never determines cell or RGB."""
    root = source.root
    candidates = sorted(p for p in root.iterdir() if p.is_file() and not p.is_symlink()
                        and p.suffix.casefold() in {".hcb", ".bch"})
    if len(candidates) > 8: raise ValueError("说话人来源脚本过多，须先登记分析脚本")
    if source.target_script:
        candidates = [root / source.target_script]
    stamps = tuple((str(path), fingerprint(path)) for path in candidates)
    atlas = root / "graph.bin"
    atlas_stamp = fingerprint(atlas) if atlas.is_file() else None
    result, references = _resolve_identity(source.id, name, stamps,
        source.target_analysis_encoding or "sjis", str(atlas), atlas_stamp)
    return deepcopy(result), list(references)


@lru_cache(maxsize=128)
def _resolve_identity(source_id, name, stamps, encoding, atlas_path, atlas_stamp):
    matches = []
    references = []
    for path_string, stamp in stamps:
        path = Path(path_string)
        catalog = source_catalog(path_string, stamp, encoding)
        if name not in catalog.get("names", {}): continue
        entries = catalog["names"][name]
        colours = [native_default_colour(catalog["document"], catalog["regions"], catalog["flow"],
                    catalog["colour"], row["native_id"], catalog["defaults"]) for row in entries]
        unique = {tuple(c) for c in colours if c is not None}
        rgb = list(unique.pop()) if len(unique) == 1 and all(c is not None for c in colours) else None
        avatar = native_avatar(catalog["document"], catalog["regions"], catalog["flow"], name)
        matches.append(dict(native_ids=[r["native_id"] for r in entries], rgb=rgb, avatar=avatar,
                            wrappers=deepcopy(entries), hcb_sha256=catalog["hcb_sha256"], hcb=str(path)))
        references.append((path, stamp))
    if not matches:
        return dict(source=source_id, name=name, available=False, rgb=None, avatar=None), references
    # Translated/clean files may differ in names. Any matching semantic tables
    # must agree; an unrecognised name is not a claim to identify an active HCB.
    first = matches[0]
    signature = lambda v: (v["rgb"], None if not v["avatar"] else
                          tuple(v["avatar"][k] for k in ("x", "y", "width", "height")))
    if any(signature(v) != signature(first) for v in matches[1:]):
        raise ValueError("来源多个脚本的头像或配色不一致，不能任选一份")
    avatar = deepcopy(first["avatar"])
    if avatar:
        archive = Path(atlas_path)
        stamp = fingerprint(archive)
        if stamp != atlas_stamp: raise ValueError("回看头像来源在读取期间发生变化")
        payload, reference = resource_reference(archive, "bl_char")
        x, y, w, h = (avatar[k] for k in ("x", "y", "width", "height"))
        if (reference["kind"] != 1 or reference["frame_count"] != 1 or reference["offset_x"] != 0
                or reference["offset_y"] != 0 or x < 0 or y < 0
                or x + 2*w > reference["width"] or y + h > reference["height"]):
            raise ValueError("原生回看头像坐标超出来源图集")
        avatar.update(reference=reference)
        references.append((archive, stamp))
    result = dict(source=source_id, name=name, available=True, rgb=first["rgb"], avatar=avatar,
        native_id=first["native_ids"][0] if len(first["native_ids"]) == 1 else None,
        source_hcb=first["hcb"], source_hcb_sha256=first["hcb_sha256"],
        native_wrappers=first["wrappers"],
        default_colour_basis="native_default_settings_calls", runtime_verified=False)
    if source_id != "hoshi":
        result["history_key"] = "FVP:" + source_id + ":" + name
    return result, references


def avatar_pair(binding):
    """Crop actual native pair using the target's existing alpha policy.

    Only the backlog thumbnail is resampled to the target's native 190px cell;
    imported stage portraits and their native-size conversion are untouched.
    """
    avatar = binding["avatar"]
    ref = avatar["reference"]
    payload, fresh = resource_reference(ref["archive_path"], ref["resource_name"])
    if fresh != ref: raise ValueError("来源回看头像发生变化")
    payload, _alpha_report = convert_hzc_to_premultiplied_alpha(payload)
    raw = zlib.decompress(payload[44:])
    image = Image.frombytes("RGBA", (ref["width"], ref["height"]), raw, "raw", "BGRA")
    x, y, w, h = (avatar[k] for k in ("x", "y", "width", "height"))
    # Fit the entire source thumbnail; keep its aspect ratio (e.g. 140x130).
    # Premultiplied channels are resized as raw channels, not unpremultiplied.
    target = Image.new("RGBA", (380, 190))
    scale = min(190 / w, 190 / h)
    size = (max(1, round(w*scale)), max(1, round(h*scale)))
    for index in (0, 1):
        cell = image.crop((x + index*w, y, x + (index+1)*w, y+h))
        if cell.size != size:
            channels = tuple(c.resize(size, Image.Resampling.LANCZOS) for c in cell.split())
            # Filter ringing must not produce RGB > A in premultiplied pixels.
            cell = Image.merge("RGBA", tuple(ImageChops.darker(c, channels[3])
                                            for c in channels[:3]) + (channels[3],))
        target.paste(cell, (index*190+(190-size[0])//2, (190-size[1])//2))
    pixels = target.tobytes("raw", "BGRA")
    header = bytearray(payload[:44])
    struct.pack_into("<I", header, 4, len(pixels))
    struct.pack_into("<HHhh", header, 20, 380, 190, 0, 0)
    return bytes(header) + zlib.compress(pixels, 9)


class NativeSpeakerBridge:
    def __init__(self, emitter):
        self.e = emitter
        self.patches, self.bindings, self.lines = [], {}, []
        self.catalog = None
        self.callback = None

    def set_identity(self, name=None, history_key=None, *, narration=True, binding=None):
        e = self.e
        if e.document.source_sha256 != CLEAN_SHA or sha(e.source) != SOURCE_SHA:
            raise ValueError("姓名/回看接入目标不是已审核星空原版")
        # Use original 25 and 4337/4338, with the native visibility gate G28.
        native_id = 0 if narration else 99
        if not narration and binding and binding.get("source") == "hoshi" and binding.get("native_id") is not None:
            native_id = binding["native_id"]
        e.output.extend(args([native_id]) + call(COLOUR_FUNCTION))
        if not narration and binding and binding.get("source") != "hoshi" and binding.get("rgb"):
            e.output.extend(e.syscall("ColorSet", (CUSTOM_PALETTE, *binding["rgb"], 255)))
            for slot in (0, 5):
                e.output.extend(e.syscall("TextColor", (slot, 10, CUSTOM_PALETTE, 100)))
        e.output.extend(args([0 if narration else 1]) + b"\x15" + struct.pack("<H", 28))
        # The existing clone owns name text and removes only actor refresh/wait.
        from .performance_compile import Emitter
        Emitter.set_speech_identity(e, name, history_key, narration=narration)
        self.lines.append(dict(name=name or "", history_key=history_key, native_colour_id=native_id,
                               source=binding.get("source") if binding else None,
                               rgb=binding.get("rgb") if binding else None))

    def speech(self, event, resources, *, text_target=None):
        e = self.e
        if e.covered: raise ValueError("黑/白场仍未恢复，不能开始台词")
        resolver = getattr(resources, "speech", None)
        binding = resolver(event) if callable(resolver) else None
        if binding and not isinstance(binding, dict): binding = None
        if self.catalog is None: self.catalog = speech_catalog(e.document, e.source)
        resolved = resolve_speech(event, self.catalog)
        name = resolved["name"]
        narration = event["speaker_mode"] == "narration"
        history = resolved["history_key"]
        automatic = not narration and event["blog_mode"] == "follow"
        if automatic and binding and binding.get("source") == "hoshi":
            canonical = binding.get('name', name)
            selected = next((c for c in self.catalog if c["canonical_name"] == canonical or c["name"] == canonical), None)
            if selected: history = selected["native_key"]
        elif automatic and binding and binding.get("source") != "hoshi":
            # An unresolved foreign name must not accidentally borrow a
            # same-named target-game character's original avatar.
            history = None
            if binding.get("avatar") and binding.get("resource"):
                history = binding["history_key"]
                self.bindings[history] = deepcopy(binding)
        self.set_identity(name or None, history, narration=narration, binding=binding)
        e.speech = {**resolved, "history_key": history, "speaker_identity": bool(binding)}
        e.output.extend(args([event["text"], None, None, None]) + call(text_target or e.text_target))
        e.output.extend(e.native("text_wait"))
        e.join()
        return True

    def finish(self):
        """One exact 5-byte redirect in the NEW candidate, fallback unchanged."""
        e = self.e
        if not self.bindings or self.callback is not None: return
        start, end = AVATAR_CALLBACK, AVATAR_END
        if e.by_offset[start].operands != {"args":3, "locals":6}:
            raise ValueError("原生回看头像回调接口变化")
        body = e.source[start:end]
        # The exact audited translated file also translates some actor names
        # (e.g. 夢 -> 梦), not merely their encoding. Its whole-file hash is
        # checked above; retain these active literals in the fallback clone.
        for ins in e.document.instructions:
            if not start <= ins.offset < end: continue
            active = e.source[ins.offset:ins.offset+ins.size]
            if ins.opcode == 14:
                if len(active) != ins.size or active[:2] != ins.raw[:2] or active[-1] != 0:
                    raise ValueError("原生回看头像姓名指令变化")
                active[2:-1].decode("gbk", errors="strict")
            elif active != ins.raw:
                raise ValueError("原生回看头像回调指纹变化")
        # Finalized scenes/chapter exits already end in a native terminal
        # jump. Append the callable fallback/dispatcher after that tail;
        # another skip would jump to EOF, which is not an instruction.
        fallback = len(e.output)
        clone = bytearray(body)
        for ins in e.document.instructions:
            if start <= ins.offset < end and ins.opcode in (6, 7):
                target = ins.operands["target"]
                if not start <= target < end: raise ValueError("回看头像回调有未知外部跳转")
                struct.pack_into("<I", clone, ins.offset-start+1, fallback+target-start)
        e.output.extend(clone)
        self.callback = len(e.output)
        for history, binding in sorted(self.bindings.items()):
            # [-4] is the native row primitive; its same-number graphic slot
            # stays row-local so several foreign avatars never overwrite each other.
            e.output.extend(b"\x10\xfd" + args([history]) + b"\x22")
            no = len(e.output)
            e.output.extend(b"\x07\0\0\0\0")
            e.output.extend(b"\x10\xfc" + args(["graph/" + binding["resource"]])
                            + b"\x03" + struct.pack("<H", e.syscalls["GraphLoad"][0]))
            e.output.extend(b"\x10\xfc\x10\xfc" + args([None, 20, 70]) + call(AVATAR_SETUP))
            e.output.extend(args([0]) + b"\x05")
            struct.pack_into("<I", e.output, no+1, len(e.output))
        e.output.extend(jump(fallback+3))  # Reuse the existing caller's frame.
        offset = start + 3
        original = e.source[offset:offset+5]
        replacement = jump(self.callback)
        e.output[offset:offset+5] = replacement
        self.patches.append(dict(offset=offset, expected=original.hex(), replacement=replacement.hex(),
                                 role="native_backlog_avatar_callback"))

    def validate_patches(self, payload, prefix):
        for patch in self.patches:
            offset = patch["offset"]
            old, new = bytes.fromhex(patch["expected"]), bytes.fromhex(patch["replacement"])
            if (offset != AVATAR_CALLBACK+3 or old != self.e.source[offset:offset+5]
                    or new != jump(self.callback) or payload[offset:offset+5] != new):
                raise ValueError("回看头像接入超出已审核回调范围")
            prefix[offset:offset+5] = old

    def report(self):
        return dict(schema=CONTRACT, name_visibility=True, native_text_colour=True,
            same_game_native_avatar=True, cross_game_native_avatar_pairs=True,
            original_window_art_unchanged=True, portrait_size_unchanged=True,
            lines=deepcopy(self.lines), avatars=[{k:v for k,v in b.items() if k != "avatar"}
                                              for b in self.bindings.values()],
            candidate_callback_patches=deepcopy(self.patches), runtime_verified=False)
