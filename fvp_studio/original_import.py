"""Read-only, fingerprint-gated opening narrative extraction.

This is a bounded importer, not an HCB interpreter or native compiler.  The
clean companion supplies verified instruction boundaries; text is read from
the active HCB, including the translation's out-of-line string trampolines.
Addresses below belong ONLY to the two explicitly fingerprinted HD files.
"""
from __future__ import annotations

import copy
import hashlib
import math
from functools import lru_cache
from pathlib import Path
from typing import Any

from .hcb import parse_bytes
from .bin_archive import _parse_archive_file_index, hzc_metadata
from .hoshimemo_stage_geometry import (
    EDITOR_WIDTH, EDITOR_HEIGHT, NATIVE_WIDTH, LOGICAL_X_SCALE,
    LOGICAL_Y_SCALE, _native_pivot,
)

SCHEMA = "fvp-studio-v2.original-import.v1"
CLEAN_SHA256 = "e23b7958f897392e3535370956b7c9a722c562f0a6d65e91d589cfdd2b741802"
CHINESE_SHA256 = "224ecf63f635d3229de0022ce880932fd034f20cb7985960ee68a9a38d7edc5c"
SUPPORTED = {CLEAN_SHA256: "cp932", CHINESE_SHA256: "gb18030"}
OPENING = 0x9A45B
REGISTER_TEXT = 0x4F429
PRINT_TEXT = 0x50345
END_LINE_40 = 0x9B134
END_LINE_60 = 0x9B6BA
SPEAK_CHILD = 0x614
SPEAK_YOU = 0x1167
MAX_HCB_BYTES = 16 * 1024 * 1024


class OriginalImportError(ValueError):
    pass


@lru_cache(maxsize=12)
def _visual_directory(path: str, size: int, mtime_ns: int):
    index, actual_size, table, stat = _parse_archive_file_index(path)
    if actual_size != size or stat.st_mtime_ns != mtime_ns:
        raise OriginalImportError("素材归档扫描期间发生变化")
    return index, hashlib.sha256(table).hexdigest()


def original_asset_record(root: Path, name: str) -> tuple[dict, str]:
    """Read only visual directory tables and the one matching HZC header.

    Importing this bounded range must not scan thousands of voice entries.
    Directory caching is source/stat bound and contains no decoded pixels.
    """
    matches = []
    for filename in ("graph.bin", "graph_bg.bin", "graph_bs.bin", "graph_vis.bin", "graph_vis1.bin", "graph_vis2.bin"):
        path = root / filename
        if not path.is_file():
            continue
        if path.is_symlink() or path.resolve().parent != root:
            raise OriginalImportError("原作素材归档不能链接到其他目录")
        stat = path.stat()
        index, directory_sha = _visual_directory(str(path), stat.st_size, stat.st_mtime_ns)
        for item in index.entries:
            if item.name == name:
                matches.append((path, stat, item, directory_sha))
    if len(matches) != 1:
        raise OriginalImportError(f"原作素材 {name} 未唯一匹配；不会替换成示例素材")
    path, stat, item, directory_sha = matches[0]
    if item.file_size < 44:
        raise OriginalImportError(f"原作素材 {name} 不是有效图片")
    with path.open("rb") as stream:
        stream.seek(item.file_offset)
        header = stream.read(44)
    meta = hzc_metadata(header, validate_pixels=False)
    fingerprint = hashlib.sha256(f"{root}|{path.name}|{stat.st_size}|{stat.st_mtime_ns}|{directory_sha}".encode()).hexdigest()
    return {"resource_name": name, "archive": path.name, "entry_index": item.index,
        "archive_offset": item.file_offset, "size": item.file_size,
        "category": "background" if name.startswith("BG") else "portrait",
        **meta.to_dict(), "type": {0: "single24", 1: "single32", 2: "multi32", 3: "single8", 4: "single1"}[meta.kind],
        "source_archive_size": stat.st_size, "source_archive_mtime_ns": stat.st_mtime_ns,
        "directory_sha256": directory_sha}, fingerprint


def line_range(start: Any = 1, end: Any = 60) -> tuple[int, int]:
    def number(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise OriginalImportError("句号必须是整数，不能是布尔值或小数")
        try:
            result = int(value)
        except ValueError as exc:
            raise OriginalImportError("句号必须是整数") from exc
        if not 1 <= result <= 60:
            raise OriginalImportError("当前已验证的导入范围为第 1～60 句")
        return result
    first, last = number(start), number(end)
    if first > last:
        raise OriginalImportError("起始句不能大于结束句")
    return first, last


def read_active_string(raw: bytes, offset: int, encoding: str) -> tuple[str, int]:
    """Follow bounded translation jumps; never mistake padding for text."""
    seen: set[int] = set()
    for _ in range(8):
        if offset in seen or not 0 <= offset < len(raw) - 1:
            raise OriginalImportError("原文字符串跳转越界或形成循环")
        seen.add(offset)
        if raw[offset] == 6:
            if offset + 5 > len(raw):
                raise OriginalImportError("原文字符串跳转被截断")
            offset = int.from_bytes(raw[offset + 1:offset + 5], "little")
            continue
        if raw[offset] != 14:
            raise OriginalImportError(f"原文槽 0x{offset:X} 不是已支持的字符串")
        size = raw[offset + 1]
        payload = raw[offset + 2:offset + 2 + size]
        if size < 1 or len(payload) != size or b"\0" not in payload:
            raise OriginalImportError("原文字符串缺少结束标记或被截断")
        try:
            return payload.split(b"\0", 1)[0].decode(encoding), offset
        except UnicodeDecodeError as exc:
            raise OriginalImportError("原文编码与已验证源版本不一致") from exc
    raise OriginalImportError("原文字符串跳转超过安全上限")


@lru_cache(maxsize=2)
def _extract(active: bytes, clean: bytes) -> tuple[dict, ...]:
    active_sha = hashlib.sha256(active).hexdigest()
    if hashlib.sha256(clean).hexdigest() != CLEAN_SHA256 or active_sha not in SUPPORTED:
        raise OriginalImportError("尚未验证此 HCB 版本的原作入口；不会套用其他游戏的地址")
    document = parse_bytes(clean, encoding="sjis")
    instructions = [i for i in document.instructions if OPENING <= i.offset < END_LINE_60]
    if not instructions or instructions[0].mnemonic != "init_stack":
        raise OriginalImportError("原作入口校验失败")
    rows: list[dict] = []
    calls: list[dict] = []
    pushes: list[Any] = []
    source_start = OPENING
    latest_text = None
    registration = None
    speaker = None
    for instruction in instructions:
        op, fields = instruction.mnemonic, instruction.operands
        if op == "push_string":
            text, resolved = read_active_string(active, instruction.offset, SUPPORTED[active_sha])
            latest_text = (text, instruction.offset, resolved)
            pushes.append({"text_slot_offset": instruction.offset})
        elif op in {"push_i8", "push_i16", "push_i32", "push_f32"}:
            pushes.append(fields["value"])
        elif op in {"push_nil", "push_true"}:
            pushes.append(None if op == "push_nil" else True)
        elif op == "neg" and pushes and isinstance(pushes[-1], (int, float)):
            pushes[-1] = -pushes[-1]
        elif op == "call":
            if active[instruction.offset:instruction.offset + instruction.size] != instruction.raw:
                raise OriginalImportError("原作调用点与已验证控制流不一致")
            target = fields["target"]
            calls.append({"offset": instruction.offset, "target": target, "literal_arguments": pushes[:]})
            if target in {SPEAK_CHILD, SPEAK_YOU}:
                # These are the ONLY verified speaker branches in this range.
                # A name/voice never carries into a subsequent narration line.
                if target == SPEAK_CHILD:
                    if len(pushes) != 3 or pushes[1:] != [-2, None] or not isinstance(pushes[0], int):
                        raise OriginalImportError("原作幼年角色说话分支与已验证参数不符")
                    name_slot, actor_id, voice = 0x683, "native-actor-8", str(pushes[0])
                else:
                    if pushes != [None] * 5:
                        raise OriginalImportError("原作主人公说话分支与已验证参数不符")
                    name_slot, actor_id, voice = 0x11A7, "native-actor-99", ""
                speaker = {"speaker_id": actor_id,
                    "speaker": read_active_string(active, name_slot, SUPPORTED[active_sha])[0].strip(),
                    "voice_id": voice, "speaker_call_offset": instruction.offset,
                    "speaker_name_slot": name_slot}
            pushes.clear()
            if target == REGISTER_TEXT:
                if latest_text is None:
                    raise OriginalImportError("原作台词调用缺少文本槽")
                registration = instruction.offset
            elif target == PRINT_TEXT:
                if latest_text is None or registration is None:
                    raise OriginalImportError("原作显示调用缺少已注册台词")
                number = len(rows) + 1
                end = instruction.offset + instruction.size
                text, slot, resolved = latest_text
                rows.append({
                    "number": number, "line_id": f"original:{active_sha[:16]}:{slot:06x}",
                    "kind": "intro" if number < 40 else "dialogue" if speaker else "narration", "text": text,
                    "speaker_id": speaker["speaker_id"] if speaker else "",
                    "speaker": speaker["speaker"] if speaker else "",
                    "voice_id": speaker["voice_id"] if speaker else "",
                    "source": {"text_slot_offset": slot, "resolved_text_offset": resolved,
                        "registration_offset": registration, "print_call_offset": instruction.offset,
                        "start_offset": source_start, "end_offset": end,
                        **({k: speaker[k] for k in ("speaker_call_offset", "speaker_name_slot")} if speaker else {})},
                    "functions": {"placeholder": True, "call_count": len(calls), "source_ref": {
                        "hcb_sha256": active_sha, "start_offset": source_start, "end_offset": end,
                        "calls": calls, "execution": "not-executed", "scope": "source-span-not-runtime-trace"}},
                    "warnings": [],
                })
                calls = []
                source_start = end
                latest_text = None
                registration = None
                speaker = None
        else:
            # Do not present an unknown stack expression as a literal ABI arg.
            pushes.clear()
    if (len(rows) != 60 or rows[39]["source"]["end_offset"] != END_LINE_40
            or rows[-1]["source"]["end_offset"] != END_LINE_60):
        raise OriginalImportError("原作第 1～60 句边界校验失败")
    return tuple(rows)


def extract_original_opening(game_root: str | Path, hcb_path: str | Path | None = None,
                             *, start_line: Any = 1, end_line: Any = 60,
                             expected_hcb_sha256: str = "") -> dict:
    first, last = line_range(start_line, end_line)
    root = Path(game_root).resolve(strict=True)
    if not root.is_dir():
        raise OriginalImportError("请选择游戏目录")
    source = Path(hcb_path) if hcb_path else root / ".Hoshimemo_HD.hcb"
    if not source.is_absolute():
        source = root / source
    source = source.resolve(strict=True)
    if source.parent != root or source.name not in {".Hoshimemo_HD.hcb", "Hoshimemo_HD.hcb"}:
        raise OriginalImportError("此版本仅支持所选原作目录内已验证的 HCB")
    companion = (root / "Hoshimemo_HD.hcb").resolve(strict=True)
    if companion.parent != root:
        raise OriginalImportError("原作控制流伴随文件不能指向其他目录")
    for path in (source, companion):
        if not path.is_file() or not 1 <= path.stat().st_size <= MAX_HCB_BYTES:
            raise OriginalImportError("HCB 文件不存在或超过读取上限")
    raw, clean = source.read_bytes(), companion.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if expected_hcb_sha256 and expected_hcb_sha256 != sha:
        raise OriginalImportError("源 HCB 已变化，停止恢复旧工作流；请重新读取并审查")
    rows = copy.deepcopy(_extract(raw, clean))
    return {"schema": SCHEMA, "mode": "original",
        "import_id": "original-" + hashlib.sha256(f"{root}|{sha}|{first}|{last}".encode()).hexdigest()[:24],
        "source": {"game_root": str(root), "hcb_path": str(source),
            "encoding": "gbk" if sha == CHINESE_SHA256 else "sjis", "profile": "hoshimemo_hd",
            "hcb_sha256": sha, "hcb_size": len(raw), "clean_sha256": CLEAN_SHA256},
        "range": {"start": first, "end": last, "count": last-first+1,
            "after_offset": rows[last-1]["source"]["end_offset"]},
        # Caller resolves material state from the opening, THEN slices. This
        # prevents a range beginning at line 25 from losing inherited state.
        "lines": list(rows),
        "warnings": ["函数仅占位：转场过程、镜头运动、文字速度和语音播放尚未执行；立绘按原作参数投影到静态终点，不能据此认定原作演出已完全复刻。"],
        "writes_performed": False, "native_execution_supported": False}


def portrait_preview_geometry(metadata: dict, *, form: int, reference_z: int,
                              camera: tuple[float, float, float]) -> dict:
    """Project the two verified dream forms into the Comfy stage's anchor ABI.

    Reuses V2's native XY/pivot/depth model. Comfy uses a bottom-centre anchor
    and a base image height of 88% of 720, NOT V2's top-left/1000-scale editor
    transform. Preserve off-screen edges: fitting to 720 would erase zoom.
    This is a static camera endpoint, not a V3DMotion implementation.
    """
    if form not in {0, 1}:
        raise OriginalImportError("尚未验证此原作立绘尺寸分支")
    values = [metadata.get(k) for k in ("width", "height", "offset_x", "offset_y")]
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in values):
        raise OriginalImportError("原作立绘缺少有效 HZC 尺寸／偏移")
    width, height, offset_x, offset_y = values
    if width <= 0 or height <= 0:
        raise OriginalImportError("原作立绘尺寸无效")
    pivot_x, pivot_y = _native_pivot(form, 8)
    logical_y = 260 if form == 0 else 340
    native_z = reference_z - 400 if form == 0 else reference_z
    native_scale = 600 if form == 0 else 1000
    depth = native_z - camera[2]
    if depth <= 0:
        raise OriginalImportError("原作立绘位于相机后方，不能生成伪预览")
    factor = native_scale / depth * EDITOR_WIDTH / NATIVE_WIDTH
    center_x = EDITOR_WIDTH / 2 + (offset_x + width / 2 - pivot_x - camera[0] * LOGICAL_X_SCALE) * factor
    top = EDITOR_HEIGHT / 2 + (offset_y - pivot_y + (logical_y - camera[1]) * LOGICAL_Y_SCALE) * factor
    projected_height = height * factor
    scale = projected_height / (EDITOR_HEIGHT * 0.88)
    if not 0.01 <= scale <= 8:
        raise OriginalImportError("原作立绘投影超出当前画布缩放范围")
    return {"x": center_x, "y": top + projected_height, "scale": scale,
        "projection": {"schema": "fvp-studio-v2.original-portrait-projection.v1",
            "form": form, "reference_z": reference_z, "native_z": native_z,
            "native_scale": native_scale, "native_xy": [0, logical_y],
            "native_pivot": [pivot_x, pivot_y], "camera": list(camera),
            "stage_size": [EDITOR_WIDTH, EDITOR_HEIGHT], "stage_base_image_height": EDITOR_HEIGHT * 0.88,
            "bounds": [center_x - width * factor / 2, top, width * factor, projected_height],
            "preview_geometry": "v2-native-parameter-static-endpoint",
            "runtime_verified": False, "animated": False}}


def _require_call(line: dict, callsite: int, wrapper: int, arguments=None) -> dict:
    for call in line["functions"]["source_ref"]["calls"]:
        if call["offset"] == callsite and call["target"] == wrapper:
            if arguments is not None and call["literal_arguments"] != arguments:
                raise OriginalImportError(f"原作调用 0x{callsite:X} 参数与已验证分支不符")
            return call
    raise OriginalImportError(f"素材切换与第 {line['number']} 句调用点 0x{callsite:X} 不符")


def attach_original_materials(manifest: dict, asset) -> None:
    """Material-only projection for the fingerprinted opening, not native effects.

    Each change is paired with its actual callsite and wrapper. BG061 follows
    the opening's date/time globals;
    BG033's eighth argument -1 selects its explicit special branch.
    """
    if manifest.get("source", {}).get("hcb_sha256") not in SUPPORTED:
        raise OriginalImportError("原作素材映射未通过源指纹门禁")
    changes = {
        1: ("BG070_000", 0x9A4CD, 0x1A23C),
        25: ("BG011_000", 0x9AC1D, 0xE77C),
        38: ("BG061_000", 0x9AFE8, 0x19851),
        40: ("BG033_021", 0x9B0B7, 0x1433B),
        52: ("BG063_021", 0x9B43E, 0x19E4C),
    }
    background = None
    actors = []
    # The BG063 variant is date-selected, not guessed from a filename. Opening
    # function_4329_(2,4,7,1,nil) sets month/day=7/4; its later nils keep them.
    _require_call(manifest["lines"][0], 0x9A46E, 0x4D67F, [2, 4, 7, 1, None])
    _require_call(manifest["lines"][0], 0x9A4C0, 0x4D67F, [12, None, None, None, None])
    for line in manifest["lines"]:
        number = line["number"]
        events = []
        changed_actor = False
        if number in changes:
            resource, callsite, wrapper = changes[number]
            _require_call(line, callsite, wrapper)
            background = {"kind": "background", "resource_id": resource,
                "label": resource, "fit": "cover", "layer_id": "background-main",
                "asset_ref": asset(resource), "source_ref": {"callsite": callsite,
                    "wrapper": wrapper, "evidence": "source-material-selection"}}
            if number == 52:
                background["source_ref"]["date_branch"] = {"month": 7, "day": 4,
                    "condition": "month == 7 and day >= 7", "selected": False}
        if number in {41, 52}:
            if number == 41:
                _require_call(line, 0x9B15D, 0x61E29, [8, None])
                _require_call(line, 0x9B167, 0x61E37, [1000, None, None])
                ref = {"callsite": 0x9B15D, "wrapper": 0x61E29,
                    "commit_callsite": 0x9B167, "commit_wrapper": 0x61E37,
                    "evidence": "4479-pending-removal-followed-by-4480-commit"}
            else:
                # Fingerprinted function_911_ -> 926 -> 4482(0) -> 4483.
                # Do NOT generalise 4482 into a cross-game clear function.
                ref = {"callsite": 0x9B43E, "wrapper": 0x19E4C,
                    "source_chain": [911, 926, 4482, 4483], "clear_argument": 0,
                    "evidence": "verified-opening-background-wrapper-commits-portrait-clear"}
            events = [{"kind": "hide", "actor_id": a["actor_id"], "source_ref": ref} for a in actors]
            actors = []
        if number in {40, 44, 46, 50}:
            callsite = {40: 0x9B0D6, 44: 0x9B231, 46: 0x9B2E3, 50: 0x9B3CF}[number]
            wrapper = 0x31BD1 if number in {40, 46} else 0x31C17
            frame = 1 if number in {40, 46} else 3
            arguments = ([1, 1, None, 1300] + [None] * 5 if number == 40 else
                         [0, 1, None, 1400] + [None] * 5 if number == 44 else [None] * 9)
            _require_call(line, callsite, wrapper, arguments)
            if number in {40, 44}:
                if number == 40:
                    _require_call(line, 0x9B0C4, 0x5465A, [0, 100, 400, None])
                    _require_call(line, 0x9B0DF, 0x61E37, [1, None, None])
                else:
                    _require_call(line, 0x9B21F, 0x546DA, [0, 100, 200, 1200] + [None] * 7)
                    _require_call(line, 0x9B23B, 0x61E37, [1000, None, None])
                resource = "CHR_夢_幼少" + ("L" if number == 44 else "")
                body, expression = asset(resource), asset(resource + "_表情")
                geometry = portrait_preview_geometry(body["metadata"], form=arguments[0],
                    reference_z=arguments[3], camera=(0, 100, 400 if number == 40 else 200))
            else:
                if len(actors) != 1 or actors[0]["actor_id"] != "native-actor-8":
                    raise OriginalImportError("表情切换缺少原作已显示角色，不能凭说话人自动创建立绘")
                previous = actors[0]
                resource = previous["resource_id"]
                body, expression = previous["body_asset_ref"], previous["expression_asset_ref"]
                geometry = {k: previous[k] for k in ("x", "y", "scale")}
                geometry["projection"] = previous["source_ref"]["projection"]
            actor_id = "native-actor-8"
            recipe = {"body_asset_id": body["asset_id"], "expression_asset_id": expression["asset_id"],
                "expression_frame": frame, "actor_id": actor_id, "display_name": line["speaker"]}
            identity = f"{body['asset_id']}|{expression['asset_id']}|{frame}"
            composed = {**body, "asset_id": "original-composed-" + hashlib.sha256(identity.encode()).hexdigest()[:24],
                "original_composition": recipe, "body_asset_id": body["asset_id"],
                "expression_asset_id": expression["asset_id"], "expression_frame": frame}
            actors = [{"actor_id": actor_id, "display_name": line["speaker"],
                "resource_id": resource, "asset_ref": composed,
                "body_asset_ref": body, "expression_asset_ref": expression,
                "expression_frame": frame, **{k: geometry[k] for k in ("x", "y", "scale")},
                "rotation_deg": 0, "opacity": 1,
                "layer_id": "portrait:native-actor-8",
                "source_ref": {"callsite": callsite, "wrapper": wrapper,
                    "native_identity": [8, 10, 9, frame], "native_arguments": arguments,
                    "change": "expression-only" if number in {46, 50} else "show",
                    "projection": geometry["projection"]}}]
            changed_actor = True
            line["warnings"].append("立绘使用原作身体／表情层和尺寸投影；只显示静态终点，运动过程与原生像素一致性仍待实机验收。")
        line.update({"background": copy.deepcopy(background), "cg": None, "actors": copy.deepcopy(actors),
            "actor_events": copy.deepcopy(events),
            "inherited": {"background": number not in changes, "cg": False,
                "actors": [] if changed_actor else [a["actor_id"] for a in actors]}})
    first, last = manifest["range"]["start"], manifest["range"]["end"]
    manifest["lines"] = manifest["lines"][first-1:last]
    manifest["material_summary"] = {"backgrounds": len({r["background"]["resource_id"] for r in manifest["lines"]}),
        "portraits": len({a["actor_id"] for r in manifest["lines"] for a in r["actors"]}), "cg": 0}
