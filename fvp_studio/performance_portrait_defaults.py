"""Read-only portrait defaults with explicit source-evidence boundaries.

New imports use native_portrait_defaults: only an evidenced camera-neutral
source size is accepted. portrait_defaults retains labelled reference values
for explicit compatibility callers, never as an automatic native-size fallback.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from functools import lru_cache
from hashlib import sha256
import math
from pathlib import Path
import struct

from .bin_archive import archive_entry_names_file
from .performance_compile import resource_reference
from .performance_framing import FORMS, resolve_framing
from .performance_geometry import nearest, projected_rect_bounds
from .performance_native_layout import PROFILES
from .performance_portrait_limits import (
    checked_portrait_scale, NATIVE_RS_MIN, NATIVE_RS_MAX, TARGET_EXE_SHA256,
)
from .native_import_size_discovery import (
    discover_source_root, select_body_size_rule,
)


_HOSHIMEMO_PROFILE = next(
    (profile for profile in PROFILES if profile["file"] == ".Hoshimemo_HD.hcb"),
    None,
)
_HOSHIMEMO_REFERENCE_BODY = "CHR_明日歩_喜_夏制服"
_GENERIC_REFERENCE_SCALE = 1000
_GENERIC_REFERENCE_DEPTH = 1600
_GENERIC_BOTTOM_Y = 800
# Authoring-only reference, rounded from the audited Hoshimemo Asuho V16
# reference projection at 1280x720 (Parts metric ~=95.7, top ~=216.3).
# This is *not* an original framing claim for another game's character.
_STUDIO_FACE_METRIC = 96
_STUDIO_FACE_TOP = 216
_ARCHIVE_ERROR = (
    "立绘素材须来自 FVP 的绝对路径 graph_bs.bin 或 graph.bin，"
    "并有可核对的身体/表情与原生大小证据"
)
PORTRAIT_ARCHIVES = frozenset(("graph_bs.bin", "graph.bin"))

# The source-form branch and 1200 reference Z were checked against these exact
# HCBs. The EXE mode table fixes the actual display viewport; BG pixels do not.
# Bind graph_bs.bin too: the same HCB next to swapped assets cannot make an
# unreviewed body a verified source form. World/Dawn share this exact archive.
# This is a camera-neutral import-size rule, not original story-frame parity.
_NEUTRAL_SOURCE_FAMILIES = (
    dict(hcb=".Hoshimemo_HD.hcb", exe="Hoshimemo_HD.exe",
         hcb_sha="224ecf63f635d3229de0022ce880932fd034f20cb7985960ee68a9a38d7edc5c",
         exe_sha="d195c8916ba32089347b79e0ee24c505a6cd2cd230c6f3b1d97584c9fa9f8b0c",
         archive_sha="a9f0cae100c445ccfec7fcc2dba0dbd2a485a06ac1a84ba8832c5b458eee9c10",
         mode=14, viewport=(1920, 1080)),
    dict(hcb=".iroseka.hcb", exe="iroseka_HD.exe",
         hcb_sha="baf7bee965c1bf88a2a4f1a595fa9b66300049a37a1c17835809d1f853869de5",
         exe_sha="cacdbe6ba9bb90b3818e0ac748b391681d5483db406b90ea7319204e0c3ab90a",
         archive_sha="9d07725af2dfd40da314af2476172abffe1040fc43a5b16342866e92f5c9ffee",
         mode=14, viewport=(1920, 1080)),
    dict(hcb=".irohika.hcb", exe="irohika_HD.exe",
         hcb_sha="feb0793d045597c327db61a6bbf15b1315efb68b13f2ddbd405dbac264bff054",
         exe_sha="adb556478ad608a3a0321f7d3b6e7e3c8394c648ca4758fea80e2ac0c683a492",
         archive_sha="9d07725af2dfd40da314af2476172abffe1040fc43a5b16342866e92f5c9ffee",
         mode=14, viewport=(1920, 1080)),
)


def _fingerprint(path: Path) -> tuple[str, int, int, int, int, int]:
    stat = path.stat()
    return (
        str(path),
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
    )


@lru_cache(maxsize=256)
def _cached_metadata(
    archive: str,
    resource: str,
    fingerprint: tuple[str, int, int, int, int, int],
) -> dict:
    # Keep only small metadata in the cache; resource_reference verifies that
    # the archive did not change while it was read.
    _payload, metadata = resource_reference(archive, resource)
    return metadata


def _metadata(archive: Path, resource: str) -> dict:
    return deepcopy(_cached_metadata(str(archive), resource, _fingerprint(archive)))


@lru_cache(maxsize=128)
def _cached_framing(
    archive: str,
    body: str,
    framing: str,
    fingerprints: tuple[tuple[str, int, int, int, int, int] | None, ...],
) -> dict:
    # stage_x is fixed at center because the cached result is used only for
    # source policy and its source framing fields do not depend on the widget.
    return resolve_framing({
        "archive": archive,
        "body": body,
        "framing": framing,
        "stage_x": 640,
        "offset_y": 0,
        "size_percent": 100,
    })


def _resolve_framing(archive: Path, body: str, framing: str, profile: dict) -> dict:
    root = archive.parent
    hcb = root / profile["file"]
    bg = root / "graph_bg.bin"
    form = FORMS.get(profile["file"])
    executable = root / form["executable"] if form else None
    fingerprints = (
        _fingerprint(archive),
        _fingerprint(hcb) if hcb.is_file() else None,
        _fingerprint(bg) if bg.is_file() else None,
        _fingerprint(executable) if executable is not None and executable.is_file() else None,
    )
    return deepcopy(_cached_framing(str(archive), body, framing, fingerprints))


@lru_cache(maxsize=64)
def _cached_sha256(
    path: str,
    fingerprint: tuple[str, int, int, int, int, int],
) -> str:
    digest = sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_profile(archive: Path, body: str) -> dict | None:
    """Bind a body to its source HCB, not merely a shared resource name."""
    for profile in PROFILES:
        if body not in profile["bodies"]:
            continue
        hcb = archive.parent / profile["file"]
        if not hcb.is_file():
            continue
        if _cached_sha256(str(hcb), _fingerprint(hcb)) != profile["sha256"]:
            raise ValueError("来源 HCB 指纹漂移，不能沿用旧的立绘构图档案")
        return profile
    return None


def _neutral_source_family(archive: Path) -> dict | None:
    """Require exact source code and viewport, never merely a game name."""
    root = archive.parent
    for family in _NEUTRAL_SOURCE_FAMILIES:
        hcb = root / family["hcb"]
        if not hcb.is_file():
            continue
        if _cached_sha256(str(hcb), _fingerprint(hcb)) != family["hcb_sha"]:
            raise ValueError("来源 HCB 指纹漂移，不能沿用原作默认大小")
        if _cached_sha256(str(archive), _fingerprint(archive)) != family["archive_sha"]:
            raise ValueError("来源立绘档案指纹漂移，不能沿用原作默认大小")
        exe = root / family["exe"]
        if not exe.is_file() or _cached_sha256(str(exe), _fingerprint(exe)) != family["exe_sha"]:
            raise ValueError("来源 EXE 指纹漂移，不能沿用原作画幅")
        with hcb.open("rb") as stream:
            descriptor = struct.unpack("<I", stream.read(4))[0]
            stream.seek(descriptor + 8)
            mode = stream.read(1)
        with exe.open("rb") as stream:
            stream.seek(0x5C550 + family["mode"] * 4)
            viewport = struct.unpack("<HH", stream.read(4))
        if mode != bytes((family["mode"],)) or viewport != family["viewport"]:
            raise ValueError("来源 HCB/EXE 的原生画幅模式漂移")
        return family
    return None


def _neutral_source_form(archive: Path, body: str) -> dict | None:
    """Only original CHR bodies with a real base/L pair use this family rule."""
    if not body.startswith("CHR_"):
        return None
    names = archive_entry_names_file(archive)
    if body.endswith("L") and body[:-1] in names:
        return dict(form=0, rs=600, source_z=800)
    if body + "L" in names:
        return dict(form=1, rs=1000, source_z=1200)
    return None


def _source_reference(archive: Path) -> dict | None:
    """Return Hoshimemo's audited Asuho reference when its HCB matches."""
    profile = _HOSHIMEMO_PROFILE
    if profile is None:
        return None
    hcb = archive.parent / profile["file"]
    if not hcb.is_file():
        return None
    fingerprint = _fingerprint(hcb)
    if _cached_sha256(str(hcb), fingerprint) != profile["sha256"]:
        return None

    resolved = _resolve_framing(archive, _HOSHIMEMO_REFERENCE_BODY, "reference", profile)
    reference_meta = _metadata(archive, _HOSHIMEMO_REFERENCE_BODY)
    if reference_meta["kind"] != 1 or reference_meta["frame_count"] != 1:
        raise ValueError("Asuho reference body no longer matches its audited single-body resource")
    return {"layout": resolved, "body": reference_meta}


def _integer(value, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low}, {high}]")
    return value


def _common_values(event: Mapping, archive: Path, body: str) -> dict:
    source_game = event.get("source_game")
    if not isinstance(source_game, str) or not source_game.strip() or len(source_game) > 4096:
        raise ValueError("source_game must identify the portrait source")
    if Path(source_game).is_absolute():
        source_root = Path(source_game).resolve(strict=True)
        if not source_root.is_dir() or source_root != archive.parent:
            raise ValueError("source_game directory must match the portrait archive directory")
    actor = _integer(event.get("actor", 1), "actor", 1, 4)
    expression = _integer(event.get("expression", 0), "expression", 0, 999)
    return {
        "actor": actor,
        "source_game": source_game,
        "archive": str(archive),
        "body": body,
        "expression": expression,
    }


def _body_metadata(archive: Path, body: str) -> dict:
    if archive.name.casefold() not in PORTRAIT_ARCHIVES:
        raise ValueError(_ARCHIVE_ERROR)
    if "吹出" in body:
        raise ValueError("speech-bubble portraits are not supported by the Portrait node")
    metadata = _metadata(archive, body)
    if metadata["kind"] != 1 or metadata["frame_count"] != 1:
        raise ValueError("body must be a single-frame 32-bit portrait layer")
    return metadata


def _framing_values(common: dict, stage_x: int, form: str, alpha: int) -> dict:
    return {
        **common,
        "framing": form,
        "stage_x": stage_x,
        "offset_y": 0,
        "size_percent": 100,
        "alpha": alpha,
    }


def _profile_default(
    archive: Path,
    body: str,
    common: dict,
    stage_x: int,
    alpha: int,
) -> dict | None:
    profile = _source_profile(archive, body)
    if profile is None:
        return None
    resolved = _resolve_framing(archive, body, "auto", profile)
    if resolved.get("body_sha"):
        actual_body = _metadata(archive, resolved["body"])
        if actual_body["payload_sha256"] != resolved["body_sha"]:
            raise ValueError("profiled portrait body fingerprint changed")
    source_form_verified = resolved["form"] in ("M", "L") and bool(resolved.get("body_sha"))
    return {
        "kind": "PortraitFraming",
        "values": _framing_values(common, stage_x, resolved["form"], alpha),
        "source_form_verified": source_form_verified,
        "native_size_verified": resolved.get("native_size_verified", False),
        "notice": (
            (f"已复用审核过的来源景别参数：{resolved['label']}；"
             "原作入场镜头未绑定，暂不能保证与原作画面同大。"
             if source_form_verified else
             f"仅按来源包装器原点使用 {resolved['label']}；缩放/深度未绑定该立绘的原作出场镜头。")
            + "这不表示运行时画面已验收。"
        ),
    }


def _portrait_fallback(
    event: Mapping,
    archive: Path,
    common: dict,
    metadata: dict,
    alpha: int,
) -> dict:
    stage_x = _integer(event.get("stage_x", 640), "stage_x", -640, 1920)
    reference = _source_reference(archive)

    if reference is not None:
        layout = reference["layout"]
        depth = layout["depth"]
        scale = layout["scale"]
        anchor_y = layout["y"]
        height = nearest(scale * metadata["height"] / (1.5 * (depth + 200)))
        height = max(100, min(1400, height))
        source_bottom_y = metadata["offset_y"] + metadata["height"]
        pivot_y = reference["layout"]["pivot"][1]
        bottom_y = nearest(
            360
            + (
                source_bottom_y
                - pivot_y
                + anchor_y * 1.8
            )
            * scale
            / (1.5 * (depth + 200))
        )
        reference_body = reference["body"]
        basis = (
            "Hoshimemo Asuho PortraitFraming reference "
            f"body={reference_body['width']}×{reference_body['height']}, "
            f"offset=({reference_body['offset_x']},{reference_body['offset_y']}), "
            f"(scale={scale}, depth={depth}, source Y={anchor_y})"
        )
        notice_prefix = (
            "来源 HZC 元数据比例参考，不是该身体的原作构图。"
            f"以 {basis} 校准自由 Portrait 数值；"
        )
    else:
        depth = _GENERIC_REFERENCE_DEPTH
        face_name = common["body"] + "_表情"
        face = _metadata(archive, face_name) if face_name in archive_entry_names_file(archive) else None
        if face is not None:
            if (face["kind"] != 2 or face["width"] <= 0 or face["height"] <= 0
                    or face["offset_x"] < 0 or face["offset_y"] < 0
                    or face["offset_x"] + face["width"] > metadata["width"]
                    or face["offset_y"] + face["height"] > metadata["height"]):
                raise ValueError("表情层与身体 HZC 元数据不匹配")
            face_metric = math.sqrt(face["width"] * face["height"])
            height = max(100, min(1400, nearest(
                _STUDIO_FACE_METRIC * metadata["height"] / face_metric)))
            bottom_y = nearest(_STUDIO_FACE_TOP + height * (
                1 - face["offset_y"] / metadata["height"]))
            bottom_y = max(-720, min(1440, bottom_y))
            notice_prefix = (
                "Studio 同场脸部参考，不是来源原作构图；"
                f"按实际 Parts 矩形约 {_STUDIO_FACE_METRIC}px、顶部约"
                f" {_STUDIO_FACE_TOP}px 推导显示高度与位置。允许原作式底边裁切。"
            )
        else:
            # Keep metadata-only imports usable when the caller has not yet
            # supplied a Parts layer. The compiler will require one later.
            scale = _GENERIC_REFERENCE_SCALE
            height = nearest(scale * metadata["height"] / (1.5 * (depth + 200)))
            height = max(100, min(1400, height))
            bottom_y = _GENERIC_BOTTOM_Y
            notice_prefix = (
                "Studio 通用比例参考，不是来源原作构图；"
                f"按 HZC 身体高度派生 size，使用 scale={scale}、depth={depth}。"
            )

    values = {
        **common,
        "stage_x": stage_x,
        "bottom_y": bottom_y,
        "height": height,
        "depth": depth,
        "alpha": alpha,
    }
    notice = (
        f"{notice_prefix}身体 {metadata['width']}×{metadata['height']}，"
        f"HZC offset=({metadata['offset_x']},{metadata['offset_y']})；"
        "现有 Portrait 编译器以身体 offset 和尺寸生成枢轴并等比缩放。"
        "这是可调整初值；该身体的原作 M 景别尚未审核。"
    )
    return {"kind": "Portrait", "values": values, "source_form_verified": False, "notice": notice}


def _neutral_source_default(
    event: Mapping,
    archive: Path,
    common: dict,
    metadata: dict,
    alpha: int,
    profiled: dict | None,
) -> dict | None:
    family = _neutral_source_family(archive)
    if family is None:
        return None
    form = _neutral_source_form(archive, common["body"])
    if form is None:
        return None
    face_name = common["body"] + "_表情"
    if face_name not in archive_entry_names_file(archive):
        raise ValueError("来源景别身体缺少配套表情，不能自动导入")
    face = _metadata(archive, face_name)
    if (face["kind"] != 2 or face["frame_count"] < 1
            or face["offset_x"] < 0 or face["offset_y"] < 0
            or face["offset_x"] + face["width"] > metadata["width"]
            or face["offset_y"] + face["height"] > metadata["height"]):
        raise ValueError("来源景别身体与表情 HZC 不配对")

    # Size uses native RS/Z and viewport only. Do not bake a story V3D camera
    # or face metric into this initial height. Stage placement stays at the
    # previous default, so size and coordinates can be reviewed separately.
    height = nearest(metadata["height"] * form["rs"] * 720 /
                     (form["source_z"] * family["viewport"][1]))
    if not 100 <= height <= 1600:
        raise ValueError("来源原作默认大小超出普通立绘节点范围，请手动选择构图")
    if profiled is not None:
        profile = _source_profile(archive, common["body"])
        resolved = _resolve_framing(archive, common["body"], "auto", profile)
        state = dict(x=resolved["x"], y=resolved["y"], z=resolved["depth"],
                     r=0, sx=resolved["scale"], sy=resolved["scale"],
                     pivot=resolved["pivot"])
        bottom_y = nearest(projected_rect_bounds(
            state, metadata, [0, 0, -200],
            {"width": metadata["width"], "height": metadata["height"]})["bottom"])
        depth = resolved["depth"]
    else:
        previous = _portrait_fallback(event, archive, common, metadata, alpha)
        bottom_y = previous["values"]["bottom_y"]
        depth = previous["values"]["depth"]
    if not -720 <= bottom_y <= 1800:
        raise ValueError("原有站位超出普通立绘节点范围，请手动设置坐标")
    return {
        "kind": "Portrait",
        "values": {**common, "stage_x": _integer(event.get("stage_x", 640),
                                          "stage_x", -640, 1920),
                   "bottom_y": bottom_y, "height": height,
                   "depth": depth, "alpha": alpha},
        "source_form_verified": True,
        "source_size_rule_verified": True,
        "native_size_verified": False,
        "size_contract": {
            "schema": "fvp-native-import-size/1",
            "body": common["body"],
            "body_sha256": metadata["payload_sha256"],
            "archive_sha256": family["archive_sha"],
            "hcb_sha256": family["hcb_sha"],
            "exe_sha256": family["exe_sha"],
            "source_form": form["form"],
            "source_rs": form["rs"],
            "source_z": form["source_z"],
            "source_viewport": list(family["viewport"]),
            "target_viewport": [1280, 720],
            "height": height,
            "uses_face_matching": False,
            "uses_story_camera": False,
            "runtime_visual_verified": False,
        },
        "notice": (
            f"来源原作 form {form['form']} 默认大小：身体 HZC×RS/Z×原生画幅，"
            f"显示高度 {height}；未按脸部或剧情 V3D 缩放。"
            "舞台位置沿用此前默认值，可单独拖动；不是原作剧情同帧验收。"
        ),
    }


def _source_code_fingerprints(root: Path) -> tuple:
    return tuple(_fingerprint(path) for path in sorted(root.iterdir())
                 if path.is_file() and not path.is_symlink()
                 and path.suffix.casefold() in (".hcb", ".bch", ".exe"))


@lru_cache(maxsize=32)
def _cached_discovered_source(root: str, fingerprints: tuple) -> dict:
    directory = Path(root)
    proof = discover_source_root(directory)
    if _source_code_fingerprints(directory) != fingerprints:
        raise ValueError("来源原生代码在解析期间变化，拒绝沿用大小证据")
    return proof


def _discovered_native_default(event, archive, common, metadata, alpha, archive_fingerprint):
    try:
        proof = deepcopy(_cached_discovered_source(str(archive.parent),
                         _source_code_fingerprints(archive.parent)))
        if not any(prefix.split("/", 1)[0].casefold() == archive.stem.casefold()
                   for prefix in proof["resource_prefixes"]):
            raise ValueError("选定 BIN 与来源身体分派器的原生档案角色不一致")
        names = archive_entry_names_file(archive)
        form = select_body_size_rule(proof, common["body"], names)
    except ValueError as exc:
        raise ValueError(
            "此身体尚无闭合的原生大小规则；不会按脸部或同场角色猜尺寸。"
            f"原因：{exc}。可手动设置大小，或明确保留已有创作大小。"
        ) from exc
    face_name = common["body"] + "_表情"
    if face_name not in names:
        raise ValueError("来源原生身体缺少配套表情，不能自动导入")
    face = _metadata(archive, face_name)
    if (face["kind"] != 2 or face["frame_count"] < 1
            or min(face["offset_x"], face["offset_y"]) < 0
            or face["offset_x"] + face["width"] > metadata["width"]
            or face["offset_y"] + face["height"] > metadata["height"]):
        raise ValueError("来源原生身体与表情 HZC 不配对")
    height = nearest(metadata["height"] * form["rs"] * 720 /
                     (form["source_z"] * proof["viewport"][1]))
    target_scale = checked_portrait_scale(height, metadata["height"], _GENERIC_REFERENCE_DEPTH)
    archive_sha = _cached_sha256(str(archive), archive_fingerprint)
    if _fingerprint(archive) != archive_fingerprint:
        raise ValueError("来源立绘档案在解析期间变化，拒绝沿用大小证据")
    # Placement is explicitly an editable authoring default, NOT original XY.
    # Existing authored nodes are not changed by this import-only resolver.
    return {
        "kind": "Portrait",
        "values": {**common, "stage_x": _integer(event.get("stage_x", 640),
                                                "stage_x", -640, 1920),
                   "bottom_y": _GENERIC_BOTTOM_Y, "height": height,
                   "depth": _GENERIC_REFERENCE_DEPTH, "alpha": alpha},
        "source_form_verified": True, "source_size_rule_verified": True,
        "native_size_verified": False,
        "size_contract": {
            "schema": "fvp-native-import-size/1", "body": common["body"],
            "body_sha256": metadata["payload_sha256"],
            "archive_sha256": archive_sha,
            "hcb_sha256": proof["hcb_sha256"], "exe_sha256": proof["exe_sha256"],
            "source_hcb": proof["source_hcb"], "source_exe": proof["source_exe"],
            "exe_evidence": deepcopy(proof["exe_evidence"]),
            "script_evidence": deepcopy(proof["script_evidence"]),
            "size_consensus": proof["size_consensus"],
            "runtime_active_script_determined": False,
            "source_form": form["form"], "source_rs": form["rs"],
            "source_z": form["source_z"], "source_viewport": proof["viewport"],
            "target_viewport": [1280, 720], "height": height,
            "target_neutral_rs": target_scale,
            "target_native_rs_range": [NATIVE_RS_MIN, NATIVE_RS_MAX],
            "target_exe_sha256": TARGET_EXE_SHA256,
            "extraction_schema": proof["schema"], "dispatcher": proof["dispatcher"],
            "geometry_guard": form["geometry_guard"], "suffix_guard": form["guard"],
            "rs_sites": form["rs_sites"], "z_sites": form["z_sites"],
            "source_policy": "regular-form-fresh-load-neutral-import",
            "uses_face_matching": False, "uses_story_camera": False,
            "runtime_visual_verified": False,
        },
        "notice": ("已从来源 HCB 分派器与 EXE 画幅读取器解析原生大小；"
                   "不按游戏名套参数，不对齐脸、不等高。"
                   "坐标是可拖动的创作初值，不表示原作站位；特殊后缀覆盖、"
                   "既存角色缓存和剧情镜头不烘焙进导入大小。实机画面尚未验收。"),
    }


def portrait_defaults(event: Mapping, *, require_source_size: bool = False) -> dict:
    """Read a default; labelled legacy references require a compatibility caller.

    PortraitSwap with framing_policy=keep returns only Portrait identity fields;
    the caller must retain the current actor's transform, depth, and alpha.
    New imports pass require_source_size=True. A SOURCE swap is always strict,
    even when this compatibility function is called directly. Authored explicit
    Portrait/PortraitFraming events are not rewritten by this resolver.
    """
    if not isinstance(event, Mapping):
        raise TypeError("event must be a mapping")
    body = event.get("body")
    if not isinstance(body, str) or not body or len(body) > 4096:
        raise ValueError("body must be a resource name")
    kind = event.get("kind")
    if kind not in (None, "Portrait", "PortraitFraming", "PortraitSwap"):
        raise ValueError("kind must be Portrait, PortraitFraming, or PortraitSwap")
    policy = event.get("framing_policy", "source")
    if policy not in ("keep", "source"):
        raise ValueError("framing_policy must be keep or source")

    archive_value = event.get("archive")
    if not isinstance(archive_value, str) or not archive_value:
        raise ValueError(_ARCHIVE_ERROR)
    archive_input = Path(archive_value)
    if not archive_input.is_absolute():
        raise ValueError(_ARCHIVE_ERROR)
    archive = archive_input.resolve(strict=True)
    if not archive.is_file() or archive.name.casefold() not in PORTRAIT_ARCHIVES:
        raise ValueError(_ARCHIVE_ERROR)
    common = _common_values(event, archive, body)
    archive_fingerprint = _fingerprint(archive)
    metadata = _body_metadata(archive, body)
    alpha = _integer(event.get("alpha", 255), "alpha", 0, 255)

    if policy == "keep":
        # Partial values are all valid Portrait schema fields. Geometry is
        # deliberately left to the swap caller's current actor state.
        return {
            "kind": "Portrait",
            "values": common,
            "source_form_verified": False,
            "notice": (
                "framing_policy=keep：只更换身体/表情身份；调用方保留当前角色的位置、"
                "大小、深度和透明度。源 HZC 元数据已读取，但不会冒充原作构图。"
            ),
        }

    if require_source_size or kind == "PortraitSwap" or archive.name.casefold() == "graph.bin":
        return _discovered_native_default(event, archive, common, metadata, alpha, archive_fingerprint)
    stage_x = _integer(event.get("stage_x", 640), "stage_x", -640, 1920)
    profiled = _profile_default(archive, body, common, stage_x, alpha)
    # Preserve Hoshimemo's accepted named profiles; newly imported paired
    # bodies and the Iro HD families use the audited neutral size rule.
    if (profiled is not None and _HOSHIMEMO_PROFILE is not None
            and body in _HOSHIMEMO_PROFILE["bodies"]
            and (archive.parent / _HOSHIMEMO_PROFILE["file"]).is_file()):
        return profiled
    neutral = _neutral_source_default(event, archive, common, metadata, alpha, profiled)
    if neutral is not None:
        return neutral
    if profiled is not None:
        return profiled
    return _portrait_fallback(event, archive, common, metadata, alpha)


def native_portrait_defaults(event: Mapping) -> dict:
    """The shared fail-closed size contract for all new native-size imports."""
    return portrait_defaults(event, require_source_size=True)
