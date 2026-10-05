"""Hoshimemo-only multi-scene performance candidate; no game writes.

Own four primitive/Parts pairs (122/23,124/25,130/31,126/27). These are complete
portraits, not body/face layers. Loading follows 4477's GraphLoad/PartsLoad/
sprite/PartsAssign chain. Motion uses the original 4405..4409 and 4412 ABI.
No 4485 cache, original dispatcher edit, scratch global or thread-9 takeover.
This is an experimental independent scene path, NOT widened original-writeback.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import OrderedDict
import hashlib
import json
import math
from pathlib import Path
import re
import struct
from threading import Lock

from .bin_archive import (append_hzc_entries, archive_entry_table_file,
    convert_hzc_to_premultiplied_alpha, hzc_metadata)
from .hcb import parse_bytes
from .portrait_emitter import _encode_push
from .performance_workflow import SCHEMA, digest, values
from .performance_native_layout import resolve_native_layout
from .performance_cg import make_adapter
from .performance_framing import resolve_framing
from .performance_geometry import shot_camera, SAFE_DEPTH
from .performance_portrait_limits import checked_portrait_scale, check_native_portrait_scales
from .performance_choices import CHOICE_KINDS, ChoiceEmitter, validate_choices
from functools import lru_cache
from .visual_scene_background_compile import compile_visual_scene_background
from .visual_scene_cg_compile import compile_visual_scene_cg
from .cg_workspace import CG_ARCHIVE_SELECTORS, fit_cg_scale

SOURCE_SHA = "224ecf63f635d3229de0022ce880932fd034f20cb7985960ee68a9a38d7edc5c"
CLEAN_SHA = "e23b7958f897392e3535370956b7c9a722c562f0a6d65e91d589cfdd2b741802"
EXE_SHA = "d195c8916ba32089347b79e0ee24c505a6cd2cd230c6f3b1d97584c9fa9f8b0c"
GRAPH_SHA = {"graph.bin": "0e67c173860c7b3babb0fcff1bd530ccaf23b61d1262fdda34231b06912dc63a",
    "graph_bs.bin": "a9f0cae100c445ccfec7fcc2dba0dbd2a485a06ac1a84ba8832c5b458eee9c10"}
GRAPH_VIS_SHA = {"graph_vis.bin": "c8d533cf1c85ca735ee734b0976f99a08932462398847dce9576693f635f7796",
    "graph_vis1.bin": "fe0406137d91bd6ebb69c849a7ebc86c18f204f0cf0fedb9f27e0f4bba63de70",
    "graph_vis2.bin": "fb7e5f5062870f66518778541d9d2e2c488ea9f379649b413e7d02d3d7e17cae"}
from .local_binding import BINDING, require_binding
# Zero/empty sentinels permit read-only GUI startup without a game. Every
# emitter/resource/build path requires a verified binding before using them.
ENTRY = BINDING.entry_offset if BINDING else 0
ENTRY_BYTES = BINDING.entry_bytes if BINDING else b""
CONTINUE = BINDING.continue_offset if BINDING else 0
EMITTER = "fvp-studio.performance-emitter/8"
PROFILE = "hoshimemo-hd-independent-performance-v1"
PRIMS = {1: 122, 2: 124, 3: 130, 4: 126}
CALLS = {"sprite": (0x4AF33, 4), "xy_set": (0x4B0A3, 3), "group": (0x3723D, 2),
    "bg": (0x52BBA, 9), "bg_blur": (0x52CCF, 9), "clear": (0x61E29, 2), "apply": (0x61E37, 3),
    "alpha": (0x54343, 8), "xy": (0x543F0, 10), "z": (0x5447C, 8),
    "s2": (0x544F8, 10), "r": (0x54578, 8), "camera": (0x546DA, 11),
    "colour": (0x57EBA, 7), "reveal": (0x57BA4, 2), "dissolve": (0x57F42, 9),
    "text_wait": (0x50345, 0), "choice_add": (0x689BD, 3), "choice_show": (0x69258, 0)}
TESTS = {"xy": "MotionMoveTest", "z": "MotionMoveZTest", "r": "MotionMoveRTest",
    "s2": "MotionMoveS2Test", "alpha": "MotionAlphaTest", "parts": "PartsMotionTest",
    "camera": "V3DMotionTest"}
STOPS = {"xy": "MotionMoveStop", "z": "MotionMoveZStop", "r": "MotionMoveRStop",
    "s2": "MotionMoveS2Stop", "alpha": "MotionAlphaStop", "parts": "PartsMotionStop"}
CG_WRAPPERS = {"MARE_e01a": (29, 0x1A20), "MARE_e01b": (30, 0x1A57), "MARE_e01c": (31, 0x1A8E)}
RESUME_START = BINDING.resume_start if BINDING else 0
RESUME_VISIBLE = BINDING.resume_visible if BINDING else 0

# Metadata alone is cached, never the potentially large HZC payload. Every
# lookup still rereads and hashes the exact archive entry after stat checks.
_RESOURCE_META: OrderedDict[str, dict[str, int]] = OrderedDict()
_RESOURCE_META_LOCK = Lock()
_RESOURCE_META_LIMIT = 96


def _resource_metadata(payload: bytes, payload_sha: str) -> dict[str, int]:
    with _RESOURCE_META_LOCK:
        cached = _RESOURCE_META.get(payload_sha)
        if cached is not None:
            _RESOURCE_META.move_to_end(payload_sha)
            return dict(cached)
    metadata = hzc_metadata(payload).to_dict()
    with _RESOURCE_META_LOCK:
        _RESOURCE_META[payload_sha] = metadata
        _RESOURCE_META.move_to_end(payload_sha)
        if len(_RESOURCE_META) > _RESOURCE_META_LIMIT:
            _RESOURCE_META.popitem(last=False)
    return dict(metadata)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def args(v):
    return b"".join(_encode_push(x, "gbk") for x in v)


def call(address):
    return b"\x02" + struct.pack("<I", address)


def jump(address):
    return b"\x06" + struct.pack("<I", address)


def rounded(x):
    return math.floor(x + 0.5) if x >= 0 else math.ceil(x - 0.5)


def camera_xyz(x, y, zoom, plane=1900, base=-200):
    # This independent path uses generic BG's proven baseline -200, NOT the
    # original 158-210 camera base +400. Keep those coordinate systems separate.
    return [x, y, rounded(plane - (plane - base) * 100 / zoom)]


def validate_program(program, *, choice_branch_kinds=None):
    if program.get("schema") != SCHEMA or not program.get("source_root"):
        raise ValueError("缺少综合演出工程/只读来源")
    events = program.get("events", [])
    validate_choices(events, branch_kinds=choice_branch_kinds)
    if not 3 <= len(events) <= 500:
        raise ValueError("综合演出事件数必须为3～500")
    scene_ids, case_ids = [], []
    expect_scene, ended = True, False
    previous = None
    for e in events:
        kind = e.get("kind")
        values(kind, {k: v for k, v in e.items() if k != "kind"})
        if kind in ("Project", "Build") or ended:
            raise ValueError("工程入口/构建节点不能出现在场景内部，结束之后不能有事件")
        if kind == "Scene":
            sid = e["scene_id"]
            if not expect_scene or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", sid) or sid in scene_ids:
                raise ValueError("场景必须唯一且通过显式跳转进入")
            if previous and previous.get("target") != sid:
                raise ValueError("本版跳转须指向连接的下一场景；拒绝隐式漏测/循环")
            scene_ids.append(sid)
            expect_scene = False
        elif expect_scene:
            raise ValueError("工程/跳转之后必须连接场景入口")
        elif kind == "Jump":
            expect_scene = True
        elif kind in ("Dialogue", "Text", "Speech"):
            ident = e["case_id"] if kind == "Dialogue" else e["line_id"]
            if not e["text"].strip() or not ident.strip() or ident in case_ids:
                raise ValueError("观察点须有唯一编号和非空台词")
            # Runtime GBK has the same finite string limit as existing scene.py.
            _encode_push((ident + " " if kind == "Dialogue" else "") + e["text"], "gbk")
            case_ids.append(ident)
        elif kind == "End":
            ended = True
        previous = e
    has_observation = bool(case_ids) or any(e["kind"] == "Choice" for e in events)
    if not ended or expect_scene or not has_observation or len(scene_ids) > 32:
        raise ValueError("必须有台词或选项、明确结束且场景数不超过32")
    return scene_ids, case_ids


def resource_reference(path, name):
    """Read a single bounded HZC; freeze directory identity, file stat and bytes."""
    path = Path(path).resolve(strict=True)
    before = path.stat()
    table = archive_entry_table_file(path)
    matches = [(i, row) for i, row in enumerate(table) if row[2] == name]
    if len(matches) != 1:
        raise ValueError(f"资源不存在或重名: {path.name}/{name}")
    index, (offset, size, _) = matches[0]
    if size > 256 * 1024 * 1024:
        raise ValueError("单个测试素材超过256MB")
    with path.open("rb") as stream:
        stream.seek(offset)
        payload = stream.read(size)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or len(payload) != size:
        raise ValueError("读取中素材来源发生变化")
    payload_sha = sha(payload)
    meta = _resource_metadata(payload, payload_sha)
    return payload, {"archive_path": str(path), "archive_name": path.name,
        "archive_size": before.st_size, "archive_mtime_ns": before.st_mtime_ns,
        "entry_index": index, "entry_size": size, "resource_name": name,
        "payload_sha256": payload_sha, **meta}


class Resources:
    def __init__(self, root):
        require_binding(root=root)
        self.root = root
        self.source = {n: (root / n).read_bytes() for n in ("graph.bin", "graph_bs.bin")}
        if any(sha(data) != GRAPH_SHA[name] for name, data in self.source.items()):
            raise ValueError("目标基础资源包不是已审核的原始版本；不在旧补丁包上叠加")
        self.graph = self.source["graph.bin"]
        self.archives = dict(self.source)
        self.portrait_payloads, self.cache, self.references, self.reports = {}, {}, [], []

    def bg(self, e):
        key = ("bg", e["archive"], e["resource"], e["fit"])
        if key not in self.cache:
            _, ref = resource_reference(e["archive"], e["resource"])
            if ref["kind"] != 0:
                raise ValueError("背景须是无透明的完整 HZC 背景")
            build = compile_visual_scene_background({**ref, "build_mode": "copy_hzc", "fit": e["fit"]}, self.graph)
            self.graph = build.graph
            self.references.append(ref)
            self.reports.append(dict(build.report))
            self.cache[key] = build.target_resource_name
        return self.cache[key]

    def portrait(self, e):
        if Path(e["archive"]).name.casefold() not in ("graph_bs.bin", "graph.bin"):
            raise ValueError("立绘须来自 graph_bs.bin 或 graph.bin 的身体/表情配对资源")
        if "吹出" in e["body"]:
            raise ValueError("仅支持正式分层立绘，不接受吹出气泡素材")
        key = ("portrait", e["archive"], e["body"])
        if key not in self.cache:
            body, b = resource_reference(e["archive"], e["body"])
            face, f = resource_reference(e["archive"], e["body"] + "_表情")
            if b["kind"] != 1 or f["kind"] != 2 or b["frame_count"] != 1:
                raise ValueError("须为身体kind1单帧 + 表情kind2多帧")
            # Parts headers use offsets relative to the cropped body bitmap;
            # the body's own offset belongs to the larger primitive canvas.
            if not (0 <= f["offset_x"] and 0 <= f["offset_y"]
                    and f["offset_x"] + f["width"] <= b["width"]
                    and f["offset_y"] + f["height"] <= b["height"]):
                raise ValueError("表情坐标不在身体范围内，不猜测跨引擎偏移")
            body, br = convert_hzc_to_premultiplied_alpha(body)
            face, fr = convert_hzc_to_premultiplied_alpha(face)
            name = "CHR_FVPV14_" + sha(body + face)[:20].upper()
            for n, payload in ((name, body), (name + "_表情", face)):
                if n in self.portrait_payloads and self.portrait_payloads[n] != payload:
                    raise ValueError("新立绘资源名冲突")
                self.portrait_payloads[n] = payload
            self.references.extend((b, f))
            self.reports.append({"kind": "portrait", "name": name, "source_game": e["source_game"],
                "body": b, "face": f, "alpha_normalization": [br, fr]})
            self.cache[key] = name, b, f
        return self.cache[key]

    def cg(self, e):
        if e.get("kind") == "CGImported":
            archive = Path(e["archive"]).resolve(strict=True)
            archive_name = archive.name.casefold()
            if archive_name not in CG_ARCHIVE_SELECTORS:
                raise ValueError("导入 CG 须来自 graph_vis/graph_vis1/graph_vis2 BIN")
            key = ("cg_imported", str(archive), e["resource"])
            if key not in self.cache:
                _, ref = resource_reference(archive, e["resource"])
                if ref["kind"] != 0 or ref["frame_count"] != 1:
                    raise ValueError("导入 CG 须为完整单帧 HZC 图像")
                if archive_name not in self.source:
                    target = (self.root / archive_name).read_bytes()
                    if sha(target) != GRAPH_VIS_SHA[archive_name]:
                        raise ValueError("目标 graph_vis 不是已审核的原始版本；拒绝叠加旧候选")
                    self.source[archive_name] = target
                    self.archives[archive_name] = target
                build = compile_visual_scene_cg({**ref, "build_mode": "copy_hzc",
                    "archive_selector": CG_ARCHIVE_SELECTORS[archive_name]}, self.archives[archive_name])
                self.archives[archive_name] = build.archive
                self.references.append(ref)
                self.reports.append({**build.report, "kind": "cg_imported",
                    "source_game": e["source_game"]})
                self.cache[key] = {"target_resource_name": build.target_resource_name,
                    "archive_selector": build.archive_selector, "metadata": ref}
            return self.cache[key]
        key = ("cg", e["resource"])
        if key not in self.cache:
            _, ref = resource_reference(self.root / "graph_vis1.bin", e["resource"])
            if ref["kind"] != 0:
                raise ValueError("原作CG须为已审核包装对应的完整图像")
            self.references.append(ref)
            self.reports.append({**ref, "kind": "cg", "hzc_kind": ref["kind"],
                                 "native_wrapper": CG_WRAPPERS[e["resource"]][0]})
            self.cache[key] = ref
        return self.cache[key]

    def finish(self):
        if self.portrait_payloads:
            result = append_hzc_entries(self.source["graph_bs.bin"], self.portrait_payloads)
            self.reports.append({"kind": "portrait_archive", **result.validation_dict()})
            self.archives["graph_bs.bin"] = result.data
        else:
            self.reports.append({"kind": "portrait_archive", "added_resource_names": [],
                "source_payloads_preserved_exactly": True, "unchanged": True})
        # Source references must still match the snapshots after the whole build.
        for ref in self.references:
            stat = Path(ref["archive_path"]).stat()
            if (stat.st_size, stat.st_mtime_ns) != (ref["archive_size"], ref["archive_mtime_ns"]):
                raise ValueError("构建期间来源素材漂移")
        self.archives["graph.bin"] = self.graph
        return self.archives


@lru_cache(maxsize=1)
def _baseline_document(clean):
    # Immutable source parse shared by preview/build. Keyed by the actual bytes,
    # never a path/mtime shortcut; Emitter owns every mutable output/state map.
    return parse_bytes(clean, encoding="shift_jis")


class Emitter:
    def __init__(self, source, clean):
        require_binding(source=source, clean=clean)
        self.source, self.clean = source, clean
        self.document = _baseline_document(clean)
        self.by_offset = {i.offset: i for i in self.document.instructions}
        self.syscalls = {s.name: (i, s.args) for i, s in enumerate(self.document.header.syscalls)}
        if len(self.syscalls) != len(self.document.header.syscalls):
            raise ValueError("重复 syscall 名称")
        self.output = bytearray(source)
        self.pending, self.actors, self.helpers, self.events = {}, {}, {}, []
        self.depth_envelopes, self.camera_envelope = {}, []
        self.scene_labels, self.jumps, self.current_scene = {}, [], ""
        self.camera = [0, 0, -200]
        self.camera_reference = (1900, -200)
        self.cg = None
        self.background_loaded = False
        self.covered = False
        self.calls = []
        self.speech = None
        entries = [i for i in self.document.instructions if i.opcode == 1]
        self.call_table = dict(CALLS)
        for name, number, arity in (("cg_reset", 4399, 1), ("cg_prepare", 858, 0),
                                    ("cg_loader", 4395, 10), ("cg_finish", 859, 3),
                                    ("bg_black", 860, 0), ("bg_white", 861, 0)):
            self.call_table[name] = (entries[number].offset, arity)
        for resource, (number, address) in CG_WRAPPERS.items():
            if entries[number].offset != address:
                raise ValueError("原作CG包装函数索引漂移")
            self.call_table[resource] = (address, 6)
        for name, (address, arity) in self.call_table.items():
            i = self.by_offset.get(address)
            if not i or i.opcode != 1 or i.operands["args"] != arity:
                raise ValueError(f"原生函数 ABI 漂移: {name}")
        # Whole-file fingerprint is the primary guard; native function equality
        # below also prevents using a clean dump as an active translated build.
        self.text_target = self.private_text()
        self.name_target = self.private_text(0x4F1F3, 0x4F268, 'name')
        self.entry = len(self.output)

    def syscall(self, name, v=()):
        ident, count = self.syscalls[name]
        if len(v) != count:
            raise ValueError(f"{name} 应为{count}入参")
        return args(v) + b"\x03" + struct.pack("<H", ident)

    def native(self, name, v=()):
        target, count = self.call_table[name]
        if len(v) != count:
            raise ValueError(f"{name} 应为{count}入参")
        self.calls.append({"function": name, "address": target, "arguments": list(v)})
        return args(v) + call(target)

    def set_speech_identity(self, name=None, history_key=None, *, narration=True):
        # Owned clone of 4337: no original actor dispatcher or implicit motion wait.
        self.output.extend(self.syscall('TextClear', (5,)))
        for glob, value in ((218, 0 if narration else 1), (276, None), (277, None)):
            self.output.extend(args([value]) + b'\x15' + struct.pack('<H', glob))
        self.output.extend(args([name or None, None]) + call(self.name_target))
        self.output.extend(args([history_key]) + b'\x15' + struct.pack('<H', 225))

    def private_text(self, start=0x4F268, end=0x4F429, helper='text'):
        """Clone bounded name/text helpers. Skip refresh/wait via balanced stubs.

        4338 calls 4483(3 args),4486(1 arg) before printing. Both must be removed
        from this owned-stage path; changing camera wait alone cannot fix it.
        All internal jump destinations are relocated; source bytes stay intact.
        """
        # The translated HCB changes only five punctuation literals here from
        # CP932 to GBK, at identical byte lengths. Preserve those active bytes;
        # permit no altered instruction, call, argument or jump.
        for i in self.document.instructions:
            if start <= i.offset < end:
                expected = _encode_push(i.text, "gbk") if i.opcode == 14 else i.raw
                if len(expected) != len(i.raw) or self.source[i.offset:i.offset + len(i.raw)] != expected:
                    raise ValueError(f"文本初始化指令漂移 @{i.offset:X}")
        redirect = {}
        for target, arity in ((0x620E6, 3), (0x67507, 1)):
            if self.by_offset[target].operands["args"] != arity:
                raise ValueError("文本刷新 ABI 漂移")
            redirect[target] = len(self.output)
            self.output.extend(bytes((1, arity, 0, 4)))
        destination = len(self.output)
        body = bytearray(self.source[start:end])
        counts = {k: 0 for k in redirect}
        for i in self.document.instructions:
            if not start <= i.offset < end:
                continue
            if i.opcode in (2, 6, 7):
                t = i.operands["target"]
                new = t
                if i.opcode in (6, 7):
                    if not start <= t < end:
                        raise ValueError("私有文本函数含未审核的外部跳转")
                    new = destination + t - start
                elif t in redirect:
                    counts[t] += 1
                    new = redirect[t]
                struct.pack_into("<I", body, i.offset - start + 1, new)
        if counts != {0x620E6: 1, 0x67507: 1}:
            raise ValueError("文本中应各有一个立绘刷新/等待调用")
        self.output.extend(body)
        self.helpers[helper] = {"address": destination, "source": [start, end],
            "source_sha256": sha(self.clean[start:end]), "skipped": list(redirect),
            "reason": "owned stage; text must not resubmit or join portrait motions"}
        return destination

    def wait_helper(self, channel, ident):
        key = (channel, ident)
        if key in self.helpers:
            return self.helpers[key]
        # Helpers are placed inline but jumped over on the normal execution path.
        start = len(self.output) + 5
        test = self.syscall(TESTS[channel], () if channel == "camera" else (ident,)) + b"\x14"
        wait = self.syscall("ThreadWait", (1,))
        loop = start + 3
        finish = loop + len(test) + 5 + len(wait) + 5
        body = b"\x01\x00\x00" + test + b"\x07" + struct.pack("<I", finish) + wait + jump(loop) + b"\x04"
        self.output.extend(jump(start + len(body)) + body)
        self.helpers[key] = start
        return start

    def join(self):
        for (channel, ident) in self.pending:
            self.output.extend(call(self.wait_helper(channel, ident)))
        self.pending.clear()
        self.depth_envelopes.clear()
        self.camera_envelope.clear()

    def start_motion(self, channel, ident, code):
        key = (channel, ident)
        if key in self.pending:
            raise ValueError(f"同一{channel}通道不能连续排队；请插入台词/等待汇合节点")
        self.output.extend(code)
        self.pending[key] = True

    def clear_actor(self, actor):
        p, parts = PRIMS[actor], PRIMS[actor] - 99
        for channel, stop in STOPS.items():
            self.output.extend(self.syscall(stop, (parts if channel == "parts" else p,)))
        self.output.extend(self.syscall("PrimSetNull", (p,)))
        self.actors.pop(actor, None)

    def cleanup(self):
        self.join()
        for actor in PRIMS:
            self.clear_actor(actor)
        if self.cg is not None:
            for p in (190, 191):
                for channel, stop in STOPS.items():
                    if channel != "parts":
                        self.output.extend(self.syscall(stop, (p,)))
                self.output.extend(self.syscall("PrimSetNull", (p,)))
                self.output.extend(self.syscall("GraphLoad", (p, None)))
            self.output.extend(self.native("cg_reset", (None,)))
            self.cg = None
        self.output.extend(self.syscall("V3DMotionStop"))
        self.output.extend(self.syscall("V3DSet", (0, 0, -200)))
        self.camera = [0, 0, -200]
        self.camera_reference = (1900, -200)

    def portrait(self, e, resources, *, replacing=False, keep=False, keep_position=False):
        actor = e["actor"]
        previous = self.actors.get(actor)
        if replacing:
            if previous is None:
                raise ValueError("换角需要已在场的角色槽；空槽请使用新增立绘")
            if keep_position and not keep:
                # SOURCE means adopt the new source size, not reset the user's
                # stage position/depth to the source's default placement.
                e = {**e, 'depth': previous['z']}
            # Settle ONLY this actor. Another actor / shared camera keeps moving.
            owned = {PRIMS[actor], PRIMS[actor]-99}
            for key in list(self.pending):
                if key[0] != 'camera' and key[1] in owned:
                    self.output.extend(call(self.wait_helper(*key)))
                    self.pending.pop(key)
            self.depth_envelopes.pop(PRIMS[actor], None)
        else:
            self.join()
        if previous is not None and not replacing:
            raise ValueError("换身体须先用原地消失/清除节点，避免旧表情运动写新资源")
        framing = resolve_framing(e) if e['kind'] == 'PortraitFraming' else None
        if not replacing:
            # A new sprite inherits the settled shared V3D camera. The old
            # baseline-camera restriction was an authoring assumption, not a
            # native loading requirement. Keep the projection depth safe.
            depth = framing['depth'] if framing else e['depth']
            if depth - self.camera[2] < SAFE_DEPTH:
                raise ValueError('新立绘位于当前镜头后方或过近；请调整景深或镜头')
        name, b, f = resources.portrait({**e, 'body': framing['body']} if framing else e)
        if framing and framing.get('body_sha') and b.get('payload_sha256') != framing['body_sha']:
            raise ValueError('所选景别身体资源指纹漂移')
        if e["expression"] >= f["frame_count"]:
            raise ValueError("表情帧越界")
        p, part = PRIMS[actor], PRIMS[actor] - 99
        layout = framing or (resolve_native_layout(e) if e["kind"] == "PortraitNative" else None)
        if framing:
            scale, x, y, pivot = (framing[k] for k in ('scale','x','y','pivot'))
            e = {**e, 'depth': framing['depth']}
        elif layout:
            scale = layout["scale"]
            x = rounded(e["native_x"] * layout["xy"][0] / 2.4)
            y = rounded(e["native_y"] * layout["xy"][1] / 1.8)
            pivot = layout["pivot"]
        else:
            depth = e["depth"] + 200
            scale = checked_portrait_scale(e["height"], b["height"], e["depth"])
            x = rounded((e["stage_x"] - 640) * 1.5 * depth / scale / 2.4)
            y = rounded((e["bottom_y"] - 360) * 1.5 * depth / scale / 1.8)
            pivot = (b["offset_x"] + b["width"] // 2, b["offset_y"] + b["height"])
        rotation, alpha, sx, sy = 0, e['alpha'], scale, scale
        base_scale = scale
        if replacing and (keep or keep_position):
            # Both policies retain the authored bottom-centre/depth/rotation.
            # Only KEEP retains old size and anisotropy; SOURCE keeps the new
            # uniform native size calculated above at the authored depth.
            if keep:
                ratio = previous['body_meta']['height'] / b['height']
                sx, sy = rounded(previous['sx']*ratio), rounded(previous['sy']*ratio)
                base_scale = rounded(previous['base_scale']*ratio)
            if min(sx, sy, base_scale) <= 0:
                raise ValueError('换角后比例退化')
            old = previous['body_meta']
            qx = old['offset_x'] + old['width']/2 - previous['pivot'][0]
            qy = old['offset_y'] + old['height'] - previous['pivot'][1]
            angle = previous['r']/3600*math.pi
            x = rounded((previous['x']*2.4 + math.cos(angle)*qx-math.sin(angle)*qy)*previous['sx']/sx/2.4)
            y = rounded((previous['y']*1.8 + math.sin(angle)*qx+math.cos(angle)*qy)*previous['sy']/sy/1.8)
            pivot = (b['offset_x']+b['width']/2, b['offset_y']+b['height'])
            pivot = tuple(rounded(v) for v in pivot)
            rotation, alpha = previous['r'], previous['alpha']
            e = {**e, 'depth': previous['z']}
            layout = ({'label': '换角：保留画面位置 / 显示高度', 'geometry_mode': 'swap-keep/1'}
                if keep else {'label': '换角：采用新来源大小，保留创作站位',
                              'geometry_mode': 'swap-source-size/1'})
        check_native_portrait_scales(sx, sy, base_scale)
        self.clear_actor(actor)
        for syscall, v in (("GraphLoad", (part, "graph_bs/" + name)),
                ("PartsLoad", (part, "graph_bs/" + name + "_表情"))):
            # Japanese resource bytes are CP932, never GBK. All added names
            # apart from the proven _表情 suffix are ASCII.
            idx, count = self.syscalls[syscall]
            if count != 2:
                raise ValueError("资源加载 ABI 漂移")
            self.output.extend(b"".join(_encode_push(a, "shift_jis") for a in v) + b"\x03" + struct.pack("<H", idx))
        self.output.extend(self.native("sprite", (p, part, None, None)))
        self.output.extend(self.syscall("PartsAssign", (part, part)))
        self.output.extend(self.syscall("PartsSelect", (part, e["expression"])))
        self.output.extend(self.native("group", (p, 7 + actor)))
        # The legacy explicit-fit node retains its old interpretation. Native-M
        # uses the source canvas pivot and never rescales by cropped-body height.
        self.output.extend(self.syscall("PrimSetOP", (p, *pivot)))
        self.output.extend(self.native("xy_set", (p, x, y)))
        self.output.extend(self.syscall("PrimSetZ", (p, e["depth"])))
        self.output.extend(self.syscall("PrimSetRS", (p, rotation, sx)))
        if sx != sy:
            self.output.extend(self.syscall("PrimSetRS2", (p, rotation, sx, sy)))
        self.output.extend(self.syscall("PrimSetAlpha", (p, alpha)))
        self.output.extend(self.syscall("PrimSetDraw", (p, True)))
        self.actors[actor] = {"x": x, "y": y, "z": e["depth"], "r": rotation, "sx": sx, "sy": sy,
            "base_scale": base_scale, "alpha": alpha, "frames": f["frame_count"], "expression": e["expression"],
            "resource": name, "layout": layout, "pivot": list(pivot),
            "stage": None if layout else [e["stage_x"], e["bottom_y"], e["height"]],
            "body_meta": b, "face_meta": f, "source_event": dict(e)}

    def camera_motion(self, target, e):
        depths = [a["z"] for a in self.actors.values()] + ([self.cg["z"]] if self.cg else [])
        depths += [min(bounds) for bounds in self.depth_envelopes.values()]
        if not self.background_loaded and self.cg is None:
            raise ValueError("镜头运动前须有明确BG或CG基准")
        if any(z-max(self.camera[2],target[2]) < SAFE_DEPTH for z in depths):
            raise ValueError("镜头不能穿过图元深度或进入100以内的退化安全边界")
        self.start_motion("camera", 0, self.native("camera", (*target, e["duration_ms"], e["curve"], True, 0, -1, 0, 0, None)))
        self.camera_envelope = [self.camera[2],target[2]]
        self.camera = target

    def load_cg(self, e, resources):
        self.join()
        if self.actors:
            raise ValueError("本轮CG使用原作整场模式；先明确退场/清除立绘，不能承诺保留叠层")
        cg_source = resources.cg(e)
        if e['kind'] == 'CGImported':
            resource_name = cg_source['target_resource_name']
            selector = cg_source['archive_selector']
            metadata = cg_source['metadata']
            scale = round(fit_cg_scale(metadata['width'], metadata['height'])
                          * e['scale_percent'] / 100)
            if not 1 <= scale <= 4000:
                raise ValueError('导入 CG 的原生大小超出安全范围')
            pose = dict(x=math.trunc(e['x']*.75), y=e['y'], z=e['depth'],
                        r=e['rotation'], scale=scale, resource=resource_name)
            duration = e['duration_ms'] or None
            # Reuse the audited generic 858 -> 4395 -> 859 event-CG chain.
            # The explicit XY/RS writes pin the same primitive 191 pose that
            # subsequent CGAction nodes use, without impersonating a BG load.
            self.output.extend(self.native('cg_prepare'))
            self.output.extend(self.native('cg_loader', (resource_name, 0, 1, None,
                e['x'], e['y'], e['depth'], e['rotation'], None, selector)))
            self.output.extend(self.native('xy_set', (191, pose['x'], pose['y'])))
            self.output.extend(self.syscall('PrimSetRS', (191, pose['r'], scale)))
            self.output.extend(self.native('cg_finish', (None, None, duration)))
            self.output.extend(self.syscall('DissolveWait', (True,)))
            self.camera = [0, 0, 0]
            self.camera_reference = (e['depth'], 0)
            self.cg = pose
            self.background_loaded = False
            self.covered = False
            return
        variant = e['kind'] == 'CGVariant'
        if variant and self.cg is None:
            raise ValueError('CG差分必须在已加载CG之后，不能猜测继承姿态')
        keep_camera = variant and e['mode'] == 'keep_v3d'
        if variant and not keep_camera and self.camera != [0,0,0]:
            raise ValueError('原作局部继承对照需要镜头先归零；保留共享镜头请选择keep_v3d')
        pose = dict(self.cg) if variant else dict(x=math.trunc(e['x']*.75),y=e['y'],z=e['depth'],r=e['rotation'])
        pose['resource'] = e['resource']
        adapter = make_adapter(self, e['resource'], pose, keep_camera)
        duration = e['duration_ms'] or None
        parameters = (None,None,None,None,None,duration) if variant else (None,e['x'],e['y'],e['depth'],e['rotation'],duration)
        self.calls.append(dict(function=e['resource'], address=adapter, arguments=list(parameters),
            source_address=CG_WRAPPERS[e['resource']][1], adapter='hidden-before-group/single-native-transition',
            keep_camera=keep_camera, inherit_pose=variant))
        self.output.extend(args(parameters) + call(adapter))
        self.output.extend(self.syscall("DissolveWait", (True,)))
        if not keep_camera:
            self.camera = [0,0,0]
        if not variant:
            self.camera_reference = (e['depth'],0)
        self.cg = pose
        self.background_loaded = False
        self.covered = False

    def cg_action(self, e):
        if self.cg is None:
            raise ValueError("CG动作前须明确加载CG")
        s, p, t, typ = self.cg, 191, e["duration_ms"], e["curve"]
        for channel in e["channels"].split("+"):
            if channel == "xy":
                x, y = math.trunc(e["x"] * .75), e["y"]
                code = self.native("xy", (p, s["x"], s["y"], x, y, t, typ, True, 0, -1))
                s.update(x=x, y=y)
                cache = ((161, x), (162, y))
            else:
                value = e["depth" if channel == "z" else "rotation"]
                if channel == "z" and min(s['z'],value)-max([self.camera[2],*self.camera_envelope]) < SAFE_DEPTH:
                    raise ValueError("CG不能移到镜头后方或退化深度")
                if channel == 'z':
                    self.depth_envelopes[p] = [s['z'],value]
                code = self.native(channel, (p, s[channel], value, t, typ, True, 0, -1))
                s[channel] = value
                cache = ((157, value), (158, value)) if channel == "z" else ((159, value), (160, value))
            self.start_motion(channel, p, code)
            for glob, value in cache:
                self.output.extend(args([value]) + b"\x15" + struct.pack("<H", glob))

    def resume_original(self):
        # V14 jumped to 9B134 while its black dissolve remained active and the
        # original scene prelude was missing. Rebuild that exact prelude before
        # the FIRST original voice/text, then continue without looping the hook.
        for lo, hi in ((RESUME_START, RESUME_VISIBLE), (RESUME_VISIBLE, CONTINUE)):
            section = [i for i in self.document.instructions if lo <= i.offset < hi]
            if not section or section[0].offset != lo or section[-1].offset + len(section[-1].raw) != hi:
                raise ValueError("原作恢复片段没有完整指令边界")
            if any(i.opcode in (1, 4, 6, 7) for i in section):
                raise ValueError("原作恢复片段含未审核控制流，不能原样搬移")
            self.output.extend(self.source[lo:hi])
            if hi == RESUME_VISIBLE:
                self.output.extend(self.native("reveal", (400, 1)))
                self.output.extend(self.syscall("DissolveWait", (True,)))
                self.covered = False
        self.output.extend(jump(CONTINUE))

    def action(self, e):
        actor = e["actor"]
        if actor not in self.actors:
            raise ValueError("立绘动作引用了未出现/已清除的角色")
        p, part, s, t, typ = PRIMS[actor], PRIMS[actor] - 99, self.actors[actor], e["duration_ms"], e["curve"]
        for channel in e["channels"].split("+"):
            if channel == "xy":
                x, y = s["x"] + e["dx"], s["y"] + e["dy"]
                code = self.native("xy", (p, s["x"], s["y"], x, y, t, typ, True, 0, -1))
                s.update(x=x, y=y)
            elif channel in ("z", "r"):
                value = e["depth" if channel == "z" else "rotation"]
                if channel == 'z' and min(s['z'],value)-max([self.camera[2],*self.camera_envelope]) < SAFE_DEPTH:
                    raise ValueError('立绘不能移到镜头后方或退化深度')
                if channel == 'z':
                    self.depth_envelopes[p] = [s['z'],value]
                code = self.native(channel, (p, s[channel], value, t, typ, True, 0, -1))
                s[channel] = value
            elif channel == "s2":
                sx, sy = (rounded(s["base_scale"] * e[k] / 100) for k in ("scale_x", "scale_y"))
                code = self.native("s2", (p, s["sx"], sx, s["sy"], sy, t, typ, True, 0, -1))
                s.update(sx=sx, sy=sy)
            elif channel == "alpha":
                code = self.native("alpha", (p, s["alpha"], e["alpha"], t, 0, None, True, 0))
                s["alpha"] = e["alpha"]
            else:
                if not 0 <= e["expression"] < s["frames"]:
                    raise ValueError("目标表情帧越界")
                if ("parts", part) in self.pending:
                    raise ValueError("表情渐变尚未完成；请先接台词或等待，再切换表情")
                if t == 0:
                    # An immediate selection must not create a motion waiter or
                    # join unrelated same-beat movement, alpha or camera work.
                    self.output.extend(self.syscall("PartsSelect", (part, e["expression"])))
                    s["expression"] = e["expression"]
                    continue
                code = self.syscall("PartsMotion", (part, e["expression"], t))
                s["expression"] = e["expression"]
            self.start_motion(channel, part if channel == "parts" else p, code)

    def transition(self, e):
        self.join()
        method, t = e["method"], e["duration_ms"]
        if method == 'reveal' and not self.covered and self.events and self.events[-1]['kind'] in ('CG','CGVariant','CGImported'):
            self.transition_note = 'CG节点已由原作859显现，合并重复reveal，避免再次切换。'
            return
        self.output.extend(self.syscall("DissolveWait", (True,)))
        if method.startswith(("black", "white")):
            self.output.extend(self.native("colour", (t, -1 if method.startswith("black") else -2, None, None, None, 1, 0)))
            self.covered = True
        if method in ("reveal", "black_return", "white_return"):
            self.output.extend(self.native("reveal", (t, 1)))
            self.covered = False
        if method == "dissolve":
            self.output.extend(self.native("dissolve", (0, t, None, None, None, None, None, None, None)))
            self.covered = False
        self.output.extend(self.syscall("DissolveWait", (True,)))

    def emit_extension(self, event, resources):
        """Reserved for separately typed, memory-only bridge subclasses."""
        return False

    def compile(self, program, resources, *, finalize_jumps=True):
        # The existing guarded launcher entry is after engine initialization but
        # before the decorative opening sprites. All test actors below are real
        # layered portraits. The original date/opening section is not measured.
        # A separately typed GUI chapter may include its own validated story
        # effects. Ordinary production/Comfy emitters retain the default set.
        validate_choices(program["events"], partial=not finalize_jumps,
                         branch_kinds=getattr(self, "choice_validation_branch_kinds", None))
        choices = ChoiceEmitter(self)
        self.output.extend(self.native("clear", (None, 0)))
        self.output.extend(self.native("apply", (None, None, 0)))
        self.cleanup()
        for e in program["events"]:
            before, calls_before = len(self.output), len(self.calls)
            self.transition_note = None
            kind = e["kind"]
            if self.emit_extension(e, resources):
                pass
            elif kind == "Scene":
                self.scene_labels[e["scene_id"]] = len(self.output)
                self.current_scene = e["scene_id"]
            elif kind == "Background":
                if self.cg is not None:
                    raise ValueError("CG后须明确CG退场，不能仅加载BG冒充完整清理")
                self.join()
                resource = resources.bg(e)
                v = [resource, None, 50, None, None, None, None, None, 1]
                self.output.extend(self.native("bg", v) + self.native("bg_blur", v))
                self.camera = [0, 0, -200]
                self.camera_reference = (1900, -200)
                self.background_loaded = True
            elif kind in ("Portrait", "PortraitNative", "PortraitFraming"):
                if not self.background_loaded:
                    raise ValueError("立绘加载前须有BG，不能猜测初始投影平面")
                self.portrait(e, resources)
            elif kind == 'PortraitSwap':
                if not self.background_loaded or self.cg is not None:
                    raise ValueError('换角需要已有立绘舞台')
                from .performance_portrait_defaults import native_portrait_defaults
                planned = native_portrait_defaults(e)
                target = {'kind': planned['kind'], **values(planned['kind'], planned['values'])}
                target['alpha'] = self.actors.get(e['actor'], {}).get('alpha', 255)
                self.portrait(target, resources, replacing=True,
                              keep=e['framing_policy']=='keep', keep_position=True)
            elif kind == "Action":
                self.action(e)
            elif kind in ("CG", "CGVariant", "CGImported"):
                self.load_cg(e, resources)
            elif kind == "CGAction":
                self.cg_action(e)
            elif kind == "CGExit":
                if self.cg is None:
                    raise ValueError("没有已加载CG可退场")
                self.join()
                self.output.extend(self.native("bg_" + e["colour"]))
                self.output.extend(self.native("dissolve", (0, e["duration_ms"], None, None, None, None, None, None, 1)))
                self.output.extend(self.syscall("DissolveWait", (True,)))
                self.cleanup()
                self.background_loaded = False
                self.covered = True
            elif kind in ("Camera", "CameraNative", "CameraShot"):
                if kind == 'CameraShot':
                    target = shot_camera(e['center_x'],e['center_y'],e['zoom'],*self.camera_reference)
                else:
                    target = camera_xyz(e["x"], e["y"], e["zoom"], *self.camera_reference) if kind == "Camera" else [e["x"], e["y"], e["z"]]
                self.camera_motion(target, e)
            elif kind in CHOICE_KINDS:
                choices.emit(e)
            elif kind in ("Dialogue", "Text", "Speech"):
                if self.covered:
                    raise ValueError("黑/白场仍未恢复，不能开始观察台词")
                # Motion is already running. BOTH its wrapper wait and G27 text
                # gate are off. This private copy also skips the text's 4486.
                text = e["case_id"] + " " + e["text"] if kind == "Dialogue" else e["text"]
                if kind == 'Speech':
                    from .performance_speech import speech_catalog, resolve_speech
                    if not hasattr(self, 'speaker_catalog'):
                        self.speaker_catalog = speech_catalog(self.document, self.source)
                    self.speech = resolve_speech(e, self.speaker_catalog)
                    # Name initializer 4337 cloned without original actor refresh.
                    # G218 selects narration/quotes; voice globals must not leak
                    # from an earlier line. No SPEAK_* dispatch is performed.
                    self.set_speech_identity(self.speech['name'], self.speech['history_key'],
                                             narration=e['speaker_mode']=='narration')
                else:
                    self.speech = dict(name='', text=text)
                    self.set_speech_identity()
                self.output.extend(args([text, None, None, None]) + call(self.text_target))
                self.output.extend(self.native("text_wait"))
                # Only after the user's click do we join remaining work. A fast
                # click cannot let stale motion overwrite the following scene.
                self.join()
            elif kind == "Wait":
                self.join()
            elif kind == "Hide":
                self.join()
                self.clear_actor(e["actor"])
            elif kind == "Transition":
                self.transition(e)
            elif kind == "Jump":
                if not self.covered:
                    raise ValueError("场景跳转前须接黑/白淡出节点，以遮蔽完整清场与资源加载")
                self.cleanup()
                self.background_loaded = False
                self.jumps.append((len(self.output), e["target"]))
                self.output.extend(jump(0))
            elif kind == "End":
                self.transition({"method": "black_out", "duration_ms": 800})
                self.cleanup()
                self.resume_original()
            self.events.append({"scene": self.current_scene, **e, "byte_range": [before, len(self.output)],
                "calls": self.calls[calls_before:], "actors_after": json.loads(json.dumps(self.actors)),
                "cg_after": dict(self.cg) if self.cg else None, "camera_after": list(self.camera),
                "camera_reference": list(self.camera_reference), "covered_after": self.covered,
                "transition_note": self.transition_note,
                "speech_after": dict(self.speech) if self.speech else None,
                "pending_after": [list(k) for k in self.pending]})
        if finalize_jumps:
            for offset, scene_id in self.jumps:
                struct.pack_into("<I", self.output, offset + 1, self.scene_labels[scene_id])
        self.output[ENTRY:ENTRY + 5] = jump(self.entry)
        return bytes(self.output)


@dataclass
class Candidate:
    payload: bytes
    archives: dict
    report: dict
    program: dict


def build_candidate(program):
    require_binding(root=program.get("source_root"))
    scenes, cases = validate_program(program)
    root = Path(program["source_root"]).resolve(strict=True)
    source, clean = ((root / name).read_bytes() for name in (".Hoshimemo_HD.hcb", "Hoshimemo_HD.hcb"))
    if sha(source) != SOURCE_SHA or sha(clean) != CLEAN_SHA or sha((root / "Hoshimemo_HD.exe").read_bytes()) != EXE_SHA:
        raise ValueError("综合演出只支持已审核的星空HD原始母本；不能以已安装候选为基底")
    if source[ENTRY:ENTRY + 5] != ENTRY_BYTES:
        raise ValueError("综合演出入口指纹不匹配")
    resources, emitter = Resources(root), Emitter(source, clean)
    payload = emitter.compile(program, resources)
    archives = resources.finish()
    prefix = bytearray(payload[:len(source)])
    prefix[ENTRY:ENTRY + 5] = ENTRY_BYTES
    if bytes(prefix) != source:
        raise ValueError("修改了登记入口之外的原始HCB")
    # Parse appended executable bytes separately; physical EOF is after the
    # original syscall table, so the unchanged original header cannot delimit it.
    header_at = struct.unpack_from("<I", clean)[0]
    appended = payload[len(source):]
    synthetic = struct.pack("<I", 4 + len(appended)) + appended + clean[header_at:]
    decoded = parse_bytes(synthetic, encoding="gbk")
    if decoded.warnings:
        raise ValueError(f"新增字节码解码失败: {decoded.warnings[:3]}")
    boundaries = {len(source) + i.offset - 4 for i in decoded.instructions}
    original_boundaries = set(emitter.by_offset)
    for i in decoded.instructions:
        if i.opcode in (2, 6, 7) and i.operands["target"] not in boundaries | original_boundaries:
            raise ValueError("新增调用/跳转未落在指令边界")
    source_files = {n: {"size": len(b), "sha256": sha(b)} for n, b in resources.source.items()}
    output_files = {n: {"size": len(b), "sha256": sha(b), "added_bytes": len(b) - len(resources.source[n])} for n, b in archives.items()}
    imported_cg = any(e["kind"] == "CGImported" for e in program["events"])
    report = {"schema": "fvp-studio.performance-candidate.v1", "emitter_id": EMITTER, "profile_id": PROFILE,
        "plan_sha256": digest(program), "passed": True, "dry_run_passed": True,
        # Ready means the candidate passed the bounded static checks and may be
        # installed to a NEW independent test copy. It is not runtime approval.
        # The installer itself still refuses existing copies and the mother.
        "install_ready": True,
        "runtime_verified": False, "source": {"hcb_sha256": SOURCE_SHA, "resource_archives": source_files},
        "output": {"hcb_sha256": sha(payload), "resource_archives": output_files},
        "required_exe_sha256": EXE_SHA, "entry": {"offset": ENTRY, "expected": ENTRY_BYTES.hex(), "target": emitter.entry},
        "scenes": scenes, "cases": cases, "events": emitter.events,
        "scene_labels": emitter.scene_labels, "jumps": emitter.jumps,
        "text_helper": emitter.helpers["text"], "resource_reports": resources.reports,
        "cg_adapters": [v for k,v in emitter.helpers.items() if isinstance(k,tuple) and k[0] == "cg_adapter"],
        "cg_policy": ("imported CG: audited generic 858/4395/859 chain, additive graph_vis candidate; "
                      "independent-copy installation is for runtime acceptance, not production approval" if imported_cg else
                      "hidden before group attachment; original859 owns transition; stable pose only; no mid-motion capture"),
        "original_prefix_unchanged_outside_entry": True, "new_instruction_count": len(decoded.instructions),
        "owned_primitives": PRIMS, "base_camera": [0, 0, -200],
        "wait_policy": "launch -> private native text -> user click -> channel-specific join",
        "resume_original": {"replayed_source": [RESUME_START, CONTINUE], "reveal_before_first_voice_text": RESUME_VISIBLE,
            "continuation": CONTINUE, "original_scene_setup_preserved": True},
        "limits": ["实机待验收，不等于通过", "不支持存档/回退验证；留待最后",
            "同一通道须显式汇合，不把连续调用当队列", "type4/5与暂停/中途接管尚未接入",
            "独立四槽舞台不覆盖原作4477/4485缓存；运动/转场仍用原生函数",
            "CG差分保留共享V3D是私有适配；原作局部构图继承与其分开测试",
             "原作默认转场受游戏设置影响；时长参数不等于固定墙钟时间"]
             + (["导入CG仅通过静态校验；只允许新建独立副本试装，画面与游戏行为仍须实机验收"] if imported_cg else [])}
    return Candidate(payload, archives, report, program)


def publish_candidate(candidate, output_root):
    root = Path(output_root).resolve()
    # A compiler revision may change bytes for the SAME visible graph. Never
    # reuse/overwrite the old artifact merely because the graph hash matches.
    identity = json.dumps({"report": candidate.report, "program": candidate.program},
                          ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    destination = root / (candidate.report["plan_sha256"][:20] + "-" + sha(identity)[:12])
    if destination.exists():
        # Never overwrite user artifacts. A prior byte-identical output is okay.
        for name, data in {"candidate.hcb": candidate.payload, **candidate.archives}.items():
            if not (destination / name).is_file() or sha((destination / name).read_bytes()) != sha(data):
                raise ValueError("同名候选目录已存在且内容不同，拒绝覆盖")
        for name, data in (("report.json", candidate.report), ("program.json", candidate.program)):
            # JSON makes object keys strings and tuples arrays. Compare wire
            # values, not Python-only types (primitive maps / jump tuples).
            wire_data = json.loads(json.dumps(data, ensure_ascii=False))
            if json.loads((destination / name).read_text(encoding="utf-8")) != wire_data:
                raise ValueError("已有候选的证明/程序快照不匹配，拒绝复用")
        return destination
    destination.mkdir(parents=True)
    for name, data in {"candidate.hcb": candidate.payload, **candidate.archives}.items():
        with (destination / name).open("xb") as f:
            f.write(data)
    for name, value in (("report.json", candidate.report), ("program.json", candidate.program)):
        with (destination / name).open("x", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
    return destination
