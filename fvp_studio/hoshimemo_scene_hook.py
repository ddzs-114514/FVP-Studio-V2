"""Auditable Hoshimemo HCB-only story attachment for FVP Studio V2.

This is intentionally separate from ``scene.py``.  The latter is the older
broadcast-drama scene compiler; this module consumes the V2 visual-scene state
and patches one exact dialogue boundary in memory.  It never guesses a raw
offset, never writes a game path, and emits only native background bindings
whose wrapper ABI has been explicitly verified for this game.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path
import struct
from typing import Any, Mapping, Sequence

from .cg_workspace import CG_SCALE_MAX, CG_SCALE_MIN, fit_cg_scale
from .hcb import HcbDocument, HcbError, Instruction, decode_bytes, encode_text
from .hoshimemo_overlay import resolve_hoshimemo_analysis_document
from .story_speakers import discover_story_speakers, resolve_story_speaker


HOOK_REPORT_SCHEMA = "fvp-studio-v2.hoshimemo-scene-hook-report.v1"
HOOK_EMITTER_ID = "fvp-studio-v2.hoshimemo-native-background-hook/1"
BATCH_HOOK_REPORT_SCHEMA = "fvp-studio-v2.hoshimemo-story-project-hook-report.v1"
BATCH_HOOK_EMITTER_ID = "fvp-studio-v2.hoshimemo-native-story-project-hook/1"
RUNTIME_TEXT_BRIDGE_SCHEMA = (
    "fvp-studio-v2.uif-drawtexta-replace-chars.v1"
)
NATIVE_ANSI_TEXT_BRIDGE_SCHEMA = (
    "fvp-studio-v2.native-ansi-drawtexta.v1"
)


class HoshimemoSceneHookError(HcbError):
    """Raised when an exact story attachment cannot be proven safe."""


@dataclass(frozen=True)
class SpeakerHookAbi:
    speaker_id: str
    display_name: str
    call_target: int
    argument_count: int
    voiced_tail: tuple[int | bool | None, ...] | None = None
    # A discovered target may select the displayed name through one explicit
    # argument even when no voice is played.  Keep that complete argument
    # vector on the ABI instead of teaching the shared dialogue emitter that
    # every FVP title uses Hoshimemo's selector values.  Existing reviewed
    # Hoshimemo entries leave this as ``None`` and retain their old Nil fill.
    unvoiced_arguments: tuple[int | bool | None, ...] | None = None
    name_selector: int | None = None
    selector_argument_index: int | None = None


@dataclass(frozen=True)
class NativeBackgroundBinding:
    """One evidence-backed native background wrapper binding."""

    resource_name: str
    native_wrapper_target: int
    native_wrapper_argument_count: int
    native_wrapper_arguments: tuple[int | bool | None, ...]
    native_variant: str
    native_evidence: str


@dataclass(frozen=True)
class HoshimemoSceneHookAbi:
    profile_id: str
    native_background_bindings: Mapping[str, NativeBackgroundBinding]
    dissolve_target: int | None
    print_target: int
    wait_target: int
    speakers: Mapping[str, SpeakerHookAbi]
    # FVP titles do not all expose the same thin text wrapper.  Later builds
    # use ``text + Nil x3`` (four arguments), while early builds such as
    # AngelWish use ``text + Nil x2`` (three arguments).  The value must come
    # from the current target's discovered function entry; it is never chosen
    # from a game name or path. Five-argument wrappers can contain their own
    # native click wait; this flag requires complete target-derived evidence.
    print_argument_count: int = 4
    print_includes_wait: bool = False
    clean_source_sha256: str | None = None
    generic_background_primary_target: int | None = None
    generic_background_blur_target: int | None = None
    generic_background_archive_selector: int = 1
    generic_background_archive_selectors: Mapping[str, int | None] = field(
        default_factory=dict
    )
    # Generic targets can bind a source-derived six/eight/nine-argument load
    # recipe instead of borrowing this module's reviewed Hoshi-HD constants.
    native_background_backend: Any | None = None
    generic_event_visual_prepare_target: int | None = None
    generic_event_visual_target: int | None = None
    generic_event_visual_finish_target: int | None = None
    generic_event_visual_archive_selectors: Mapping[str, int] = field(
        default_factory=dict
    )
    # Dialogue control-flow can be byte-safe while still being an unsafe
    # lifecycle point for a new visual scene.  Keep evidence-backed blocks
    # separate from ``safe`` so the dialogue remains selectable/readable, but
    # fail closed before emitting background, portrait or CG primitives.
    blocked_visual_anchor_offsets: Mapping[int, str] = field(default_factory=dict)
    # Imported portraits use cloned dispatchers backed by native selector/state
    # slots.  The original script does not know that a V2 cue activated those
    # slots, so a second exact hook must hand ownership back before the next
    # original registration, portrait-apply, or scene-reset boundary.
    portrait_clear_target: int | None = None
    portrait_apply_target: int | None = None
    # Earlier FVP builds expose apply(Nil, Nil), while later builds use three
    # arguments.  This count is accepted only from the current target's
    # discovered lifecycle wrapper and drives every emitted apply vector.
    portrait_apply_argument_count: int = 3
    # The active registration wrapper exposes dispatcher_args - 4 runtime
    # values: eight on early 12-argument FVP and nine on later 13-argument FVP.
    portrait_registration_argument_count: int = 9
    portrait_registration_targets: tuple[int, ...] = ()
    # Direct story calls may target the full 12/13-argument dispatcher while
    # wrapper calls target its 8/9 runtime-argument adapters.  Keep an exact
    # per-target ABI map so either form can be used as a source-proven handoff
    # boundary without weakening function-entry validation.
    portrait_registration_argument_counts: Mapping[int, int] = field(
        default_factory=dict
    )
    visual_reset_targets: tuple[int, ...] = ()
    # Native audio wrappers are kept explicit and optional so synthetic/test
    # profiles and future FVP games fail closed instead of inheriting the
    # Hoshimemo ABI by name alone.
    bgm_play_target: int | None = None
    bgm_stop_target: int | None = None
    se_play_target: int | None = None
    se_stop_all_target: int | None = None
    # A translated generic target may place the selected ``push_string``
    # immediately after its native SPEAK call.  Hooking the string itself is
    # too late for inserted narration: the original name has already been
    # installed and leaks into the custom line.  When enabled, a ``before``
    # hook may replace that exact five-byte SPEAK call instead, run the custom
    # block while the previous wait has left the box nameless, replay the call,
    # and return to the untouched (possibly Overlay-redirected) string.
    prefer_pre_speaker_before_hook: bool = False
    # Some translated FVP releases keep the HCB in CP932 and use their own
    # runtime DrawTextA character table to render Chinese.  The bridge is
    # derived from that target's configuration bytes and remains optional so
    # ordinary games continue to use their declared HCB encoding directly.
    runtime_text_bridge: Mapping[str, Any] | None = None


HOSHIMEMO_SCENE_HOOK_ABI = HoshimemoSceneHookAbi(
    profile_id="hoshimemo-hd-native-scene-hook-v1",
    native_background_bindings={
        # The target and eight Nil template are preserved byte-for-byte from
        # the already accepted BG051_000 native emission.
        "BG051_000": NativeBackgroundBinding(
            resource_name="BG051_000",
            native_wrapper_target=0x01892F,  # function_904_
            native_wrapper_argument_count=8,
            native_wrapper_arguments=(None,) * 8,
            native_variant="function_904_ normal native variant",
            native_evidence=(
                "原作 HCB dump 的 function_904_ 为 initstack 8；"
                "BG051_000 八个 Nil 的发射字节已由 HOOK2 实机路径验证"
            ),
        ),
        # function_906_ selects BG053_010 and its tail appends b, producing the
        # adjacent blur-layer resource BG053_010b.
        "BG053_010b": NativeBackgroundBinding(
            resource_name="BG053_010b",
            native_wrapper_target=0x0194E4,  # function_906_
            native_wrapper_argument_count=9,
            native_wrapper_arguments=(None, None, None, None, None, None, 2, None, None),
            native_variant="function_906_ BG053_010 plus adjacent blur layer",
            native_evidence=(
                "原作 HCB dump 的 function_906_ 为 initstack 9；"
                "其分支选择 BG053_010，函数尾统一追加 b 形成 BG053_010b"
            ),
        ),
    },
    dissolve_target=0x057F42,          # function_4466_, 9 args
    # The HCB call sequence is push_string + Nil x3, so init_stack sees four
    # arguments even though older notes described only the three trailing Nil.
    print_target=0x04F429,             # function_4339_, 4 args total
    wait_target=0x050345,              # function_4353_, 0 args
    speakers={
        "meya": SpeakerHookAbi("meya", "梅娅", 0x000004, 3, (None, None)),
        "yume": SpeakerHookAbi("yume", "梦", 0x000614, 3, (None, None)),
        "you": SpeakerHookAbi("you", "洋", 0x001167, 5, None),
    },
    clean_source_sha256="e23b7958f897392e3535370956b7c9a722c562f0a6d65e91d589cfdd2b741802",
    generic_background_primary_target=0x052BBA,  # function_4383_, 9 args
    generic_background_blur_target=0x052CCF,    # function_4384_, 9 args
    # function_4390_ selector 1 resolves graph/<resource>; cross-game HZC
    # payloads are appended additively to graph.bin, never into an old slot.
    generic_background_archive_selector=1,
    generic_background_archive_selectors={
        "graph.bin": 1,
        "graph_bg.bin": 0,
    },
    # Native event-CG chain recovered from the original wrappers:
    # function_858_ -> function_4395_ -> function_859_.  function_4395_
    # selects graph_vis / graph_vis1 / graph_vis2 through its final argument.
    generic_event_visual_prepare_target=0x00CEE7,  # function_858_, 0 args
    generic_event_visual_target=0x05368B,          # function_4395_, 10 args
    generic_event_visual_finish_target=0x00CF0E,   # function_859_, 3 args
    generic_event_visual_archive_selectors={
        "graph_vis.bin": 0,
        "graph_vis1.bin": 1,
        "graph_vis2.bin": 2,
    },
    blocked_visual_anchor_offsets={
        0x09B10D: (
            "该台词位于 7 月 9 日日期过场完成之前；日期函数只清理其原生层，"
            "不会清理 V2 新增立绘 primitive，视觉内容会残留到日期画面"
        ),
        0x09EC94: (
            "该台词的上一轮隔离副本实机候选未形成可辨别的稳定场景，且随后进入"
            "7 月 9 日日期流程；在新的生命周期清理路径完成实机验收前禁止重复安装"
        ),
    },
    portrait_clear_target=0x061E29,      # function_4479_, 2 args
    portrait_apply_target=0x061E37,      # function_4480_, 3 args
    visual_reset_targets=(0x04DD3D,),    # function_4333_, date/eyecatch reset
    # Verified against the active translated hidden HCB and the clean dump.
    # function_4442_(track, old-track transition, loop, volume, compatibility)
    # function_4444_(transition), function_4435_(id, transition, mode, volume),
    # function_4436_(transition).
    bgm_play_target=0x056C8C,
    bgm_stop_target=0x05731E,
    se_play_target=0x0566D6,
    se_stop_all_target=0x0569DA,
)


@dataclass(frozen=True)
class SceneHookCandidate:
    hcb: bytes
    report: Mapping[str, Any]
    install_ready: bool
    graph_bs: bytes | None = None
    graph_bs_source_sha256: str | None = None
    resource_archives: Mapping[str, bytes] = field(default_factory=dict)
    resource_archive_files: Mapping[str, Path] = field(default_factory=dict)
    resource_archive_source_sha256: Mapping[str, str] = field(default_factory=dict)
    portrait_resource_payloads: Mapping[str, bytes] = field(default_factory=dict)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256(payload)


def _u32(value: int, label: str) -> bytes:
    number = int(value)
    if not 0 <= number <= 0xFFFFFFFF:
        raise HoshimemoSceneHookError(f"{label}超出 u32 范围: {number}")
    return struct.pack("<I", number)


def _call(target: int) -> bytes:
    return b"\x02" + _u32(target, "call 地址")


def _syscall(syscall_id: int) -> bytes:
    number = int(syscall_id)
    if not 0 <= number <= 0xFFFF:
        raise HoshimemoSceneHookError(f"syscall ID 超出 u16 范围: {number}")
    return b"\x03" + struct.pack("<H", number)


def _pop_global(global_id: int) -> bytes:
    number = int(global_id)
    if not 0 <= number <= 0xFFFF:
        raise HoshimemoSceneHookError(f"global ID 超出 u16 范围: {number}")
    return b"\x15" + struct.pack("<H", number)


def _push_global(global_id: int) -> bytes:
    number = int(global_id)
    if not 0 <= number <= 0xFFFF:
        raise HoshimemoSceneHookError(f"global ID 超出 u16 范围: {number}")
    return b"\x0F" + struct.pack("<H", number)


def _require_named_syscall(document: HcbDocument, name: str, args: int) -> int:
    matches = [
        (index, item)
        for index, item in enumerate(document.header.syscalls)
        if item.name == name
    ]
    if len(matches) != 1:
        raise HoshimemoSceneHookError(
            f"目标 HCB 必须且只能登记一个 {name} syscall，实际 {len(matches)} 个"
        )
    syscall_id, syscall = matches[0]
    if int(syscall.args) != int(args):
        raise HoshimemoSceneHookError(
            f"目标 HCB 的 {name} 参数数应为 {args}，实际 {syscall.args}"
        )
    return syscall_id


def _jump(target: int) -> bytes:
    return b"\x06" + _u32(target, "jmp 地址")


def _push_value(value: int | bool | None) -> bytes:
    if value is None or value is False:
        return b"\x08"
    if value is True:
        return b"\x09"
    number = int(value)
    if -0x80 <= number <= 0x7F:
        return b"\x0C" + struct.pack("<b", number)
    if -0x8000 <= number <= 0x7FFF:
        return b"\x0B" + struct.pack("<h", number)
    if -0x80000000 <= number <= 0x7FFFFFFF:
        return b"\x0A" + struct.pack("<i", number)
    raise HoshimemoSceneHookError(f"整数参数超出 i32 范围: {number}")


def _arguments(values: Sequence[int | bool | None]) -> bytes:
    return b"".join(_push_value(value) for value in values)


def _push_string(text: str, encoding: str) -> bytes:
    try:
        encoded = encode_text(text, encoding)
    except (HcbError, UnicodeEncodeError, LookupError) as exc:
        raise HoshimemoSceneHookError(f"新增台词不能编码为 {encoding}: {text!r}") from exc
    return _push_encoded_string(encoded, text=text, encoding=encoding)


def _push_encoded_string(encoded: bytes, *, text: str, encoding: str) -> bytes:
    if not isinstance(encoded, bytes):
        raise HoshimemoSceneHookError("新增台词编码结果不是 bytes")
    payload = encoded + b"\0"
    if len(payload) > 0xFF:
        raise HoshimemoSceneHookError(
            f"新增台词超过 HCB 255 字节字段: {text!r} ({len(payload)} bytes)"
        )
    return bytes((0x0E, len(payload))) + payload


def build_native_ansi_drawtexta_text_bridge(
    *,
    source_encoding: str,
    runtime_encoding: str,
    code_page: int,
    executable_name: str,
    executable_size: int,
    executable_sha256: str,
) -> dict[str, Any]:
    """Describe an explicit target-owned ANSI DrawTextA dialogue route.

    This does not reinterpret the source HCB or resource strings.  It only
    allows newly emitted dialogue bytes to use the current process ANSI code
    page after the server has proven a target-owned executable imports
    ``DrawTextA``.  CP936 is intentionally strict GBK (one/two-byte DBCS), not
    GB18030, because early FVP glyph loops consume at most two bytes per glyph.
    """

    source = str(source_encoding or "").strip().casefold()
    runtime = str(runtime_encoding or "").strip().casefold()
    name = str(executable_name or "").strip()
    digest = str(executable_sha256 or "").strip().casefold()
    try:
        cp = int(code_page)
        size = int(executable_size)
    except (TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError("ANSI DrawTextA 文本通道数值字段无效") from exc
    if source not in {"shift_jis", "sjis"}:
        raise HoshimemoSceneHookError("ANSI DrawTextA 文本通道目前只接受 CP932 来源 HCB")
    if runtime not in {"gbk", "cp936"} or cp != 936:
        raise HoshimemoSceneHookError("ANSI DrawTextA 文本通道编码与系统代码页不一致")
    if (
        not name
        or Path(name).name != name
        or any(separator in name for separator in ("/", "\\"))
        or Path(name).suffix.casefold() != ".exe"
        or size <= 0
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise HoshimemoSceneHookError("ANSI DrawTextA 文本通道 EXE 身份字段无效")
    return {
        "schema": NATIVE_ANSI_TEXT_BRIDGE_SCHEMA,
        "mode": "target_owned_drawtexta_acp",
        "enabled": True,
        "source_encoding": "shift_jis",
        "encoding": "gbk",
        "code_page": 936,
        "api": "DrawTextA",
        "executable_name": name,
        "executable_size": size,
        "executable_sha256": digest,
        "strict_two_byte_dbcs": True,
        "user_selected": True,
    }


def build_uif_drawtexta_text_bridge(
    config_bytes: bytes,
    *,
    encoding: str,
    config_name: str = "uif_config.json",
) -> dict[str, Any]:
    """Derive one audited CP932 carrier table from a target-owned UIF file."""

    if not isinstance(config_bytes, bytes) or not config_bytes:
        raise HoshimemoSceneHookError("UIF 文本桥配置必须是非空 bytes")
    name = str(config_name).strip()
    if (
        not name
        or name in {".", ".."}
        or Path(name).name != name
        or any(separator in name for separator in ("/", "\\"))
    ):
        raise HoshimemoSceneHookError("UIF 文本桥配置名必须是单个文件名")
    try:
        value = json.loads(config_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HoshimemoSceneHookError("UIF 文本桥配置不是有效 UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise HoshimemoSceneHookError("UIF 文本桥配置根节点必须是对象")
    processor = value.get("text_processor")
    if not isinstance(processor, Mapping) or processor.get("enable") is not True:
        raise HoshimemoSceneHookError("UIF DrawTextA 文本处理器未启用")
    rules = processor.get("rules")
    if not isinstance(rules, list):
        raise HoshimemoSceneHookError("UIF 文本处理规则不是列表")
    matches: list[tuple[int, Mapping[str, Any]]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            continue
        apis = rule.get("apis")
        if (
            str(rule.get("type") or "").strip().casefold() == "replace_chars"
            and isinstance(apis, list)
            and any(str(api).strip().casefold() == "drawtexta" for api in apis)
        ):
            matches.append((index, rule))
    if len(matches) != 1:
        raise HoshimemoSceneHookError(
            "UIF 配置必须且只能包含一条 DrawTextA replace_chars 规则，"
            f"实际 {len(matches)} 条"
        )
    rule_index, rule = matches[0]
    source_chars = rule.get("source_chars")
    target_chars = rule.get("target_chars")
    if (
        not isinstance(source_chars, str)
        or not isinstance(target_chars, str)
        or not source_chars
        or len(source_chars) != len(target_chars)
    ):
        raise HoshimemoSceneHookError("UIF 字符替换表为空或两侧长度不一致")
    if len(set(source_chars)) != len(source_chars):
        raise HoshimemoSceneHookError("UIF 字符替换表的载体字符不唯一")
    if len(set(target_chars)) != len(target_chars):
        raise HoshimemoSceneHookError("UIF 字符替换表的显示字符不唯一")
    try:
        encode_text(source_chars, encoding)
    except (HcbError, UnicodeEncodeError, LookupError) as exc:
        raise HoshimemoSceneHookError(
            f"UIF 载体字符表不能完整编码为 {encoding}"
        ) from exc
    return {
        "schema": RUNTIME_TEXT_BRIDGE_SCHEMA,
        "mode": "target_owned_uif_drawtexta_replace_chars",
        "enabled": True,
        "config_name": name,
        "config_size": len(config_bytes),
        "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "encoding": str(encoding),
        "api": "DrawTextA",
        "rule_index": rule_index,
        "mapping_count": len(source_chars),
        "source_chars": source_chars,
        "target_chars": target_chars,
    }


def _runtime_text_bridge_report(
    bridge: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if bridge is None:
        return {
            "schema": RUNTIME_TEXT_BRIDGE_SCHEMA,
            "mode": "direct_hcb_encoding",
            "enabled": False,
        }
    if not isinstance(bridge, Mapping):
        raise HoshimemoSceneHookError("运行时文本桥不是对象")
    mode = str(bridge.get("mode") or "")
    if mode == "target_owned_drawtexta_acp":
        try:
            code_page = int(bridge.get("code_page"))
            executable_size = int(bridge.get("executable_size"))
        except (TypeError, ValueError) as exc:
            raise HoshimemoSceneHookError("运行时 ANSI 文本通道数值字段无效") from exc
        executable_name = str(bridge.get("executable_name") or "")
        executable_sha256 = str(bridge.get("executable_sha256") or "").casefold()
        if (
            bridge.get("schema") != NATIVE_ANSI_TEXT_BRIDGE_SCHEMA
            or bridge.get("enabled") is not True
            or bridge.get("api") != "DrawTextA"
            or bridge.get("source_encoding") != "shift_jis"
            or bridge.get("encoding") != "gbk"
            or code_page != 936
            or bridge.get("strict_two_byte_dbcs") is not True
            or bridge.get("user_selected") is not True
            or Path(executable_name).name != executable_name
            or Path(executable_name).suffix.casefold() != ".exe"
            or any(separator in executable_name for separator in ("/", "\\"))
            or executable_size <= 0
            or len(executable_sha256) != 64
            or any(char not in "0123456789abcdef" for char in executable_sha256)
        ):
            raise HoshimemoSceneHookError("运行时 ANSI DrawTextA 文本通道结构无效")
        return {
            "schema": NATIVE_ANSI_TEXT_BRIDGE_SCHEMA,
            "mode": "target_owned_drawtexta_acp",
            "enabled": True,
            "source_encoding": "shift_jis",
            "encoding": "gbk",
            "code_page": 936,
            "api": "DrawTextA",
            "executable_name": executable_name,
            "executable_size": executable_size,
            "executable_sha256": executable_sha256,
            "strict_two_byte_dbcs": True,
            "user_selected": True,
            "target_executable_unchanged": True,
        }
    source_chars = bridge.get("source_chars")
    target_chars = bridge.get("target_chars")
    if (
        bridge.get("schema") != RUNTIME_TEXT_BRIDGE_SCHEMA
        or mode != "target_owned_uif_drawtexta_replace_chars"
        or bridge.get("enabled") is not True
        or bridge.get("api") != "DrawTextA"
        or not isinstance(source_chars, str)
        or not isinstance(target_chars, str)
        or not source_chars
        or len(source_chars) != len(target_chars)
        or len(set(source_chars)) != len(source_chars)
        or len(set(target_chars)) != len(target_chars)
    ):
        raise HoshimemoSceneHookError("运行时 UIF 文本桥结构无效")
    config_name = str(bridge.get("config_name") or "")
    config_sha256 = str(bridge.get("config_sha256") or "").casefold()
    try:
        config_size = int(bridge.get("config_size"))
        mapping_count = int(bridge.get("mapping_count"))
        rule_index = int(bridge.get("rule_index"))
    except (TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError("运行时 UIF 文本桥数值字段无效") from exc
    if (
        Path(config_name).name != config_name
        or any(separator in config_name for separator in ("/", "\\"))
        or len(config_sha256) != 64
        or any(char not in "0123456789abcdef" for char in config_sha256)
        or config_size <= 0
        or mapping_count != len(source_chars)
        or rule_index < 0
    ):
        raise HoshimemoSceneHookError("运行时 UIF 文本桥身份字段无效")
    return {
        "schema": RUNTIME_TEXT_BRIDGE_SCHEMA,
        "mode": "target_owned_uif_drawtexta_replace_chars",
        "enabled": True,
        "config_name": config_name,
        "config_size": config_size,
        "config_sha256": config_sha256,
        "encoding": str(bridge.get("encoding") or ""),
        "api": "DrawTextA",
        "rule_index": rule_index,
        "mapping_count": mapping_count,
        "table_sha256": hashlib.sha256(
            (source_chars + "\0" + target_chars).encode("utf-8")
        ).hexdigest(),
        "target_config_unchanged": True,
    }


def _push_dialogue_string(
    text: str,
    encoding: str,
    bridge: Mapping[str, Any] | None,
) -> tuple[bytes, dict[str, Any]]:
    if bridge is None:
        payload = _push_string(text, encoding)
        return payload, {
            "mode": "direct_hcb_encoding",
            "encoding": encoding,
            "runtime_roundtrip": True,
            "display_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "payload_sha256": _sha256(payload),
        }
    bridge_report = _runtime_text_bridge_report(bridge)
    if bridge_report["mode"] == "target_owned_drawtexta_acp":
        if str(bridge.get("source_encoding") or "") != str(encoding):
            raise HoshimemoSceneHookError(
                "运行时 ANSI 文本通道的来源编码与当前 HCB 不一致"
            )
        try:
            encoded = text.encode("gbk", errors="strict")
        except UnicodeEncodeError as exc:
            raise HoshimemoSceneHookError(
                f"新增台词不能编码为严格 GBK/CP936: {text!r}"
            ) from exc
        payload = _push_encoded_string(encoded, text=text, encoding="gbk")
        return payload, {
            "mode": "target_owned_drawtexta_acp",
            "source_encoding": encoding,
            "encoding": "gbk",
            "code_page": 936,
            "runtime_roundtrip": encoded.decode("gbk") == text,
            "display_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "encoded_payload_hex": encoded.hex(" "),
            "encoded_payload_sha256": _sha256(encoded),
            "payload_sha256": _sha256(payload),
            "executable_name": bridge_report["executable_name"],
            "executable_sha256": bridge_report["executable_sha256"],
            "strict_two_byte_dbcs": True,
        }
    if str(bridge.get("encoding") or "") != str(encoding):
        raise HoshimemoSceneHookError(
            "运行时 UIF 文本桥编码与当前 HCB 编码不一致"
        )
    source_chars = str(bridge["source_chars"])
    target_chars = str(bridge["target_chars"])
    reverse = dict(zip(target_chars, source_chars, strict=True))
    forward = dict(zip(source_chars, target_chars, strict=True))
    carrier_text = "".join(reverse.get(char, char) for char in text)
    runtime_text = "".join(forward.get(char, char) for char in carrier_text)
    if runtime_text != text:
        raise HoshimemoSceneHookError(
            "UIF 载体字符串无法在 DrawTextA 映射后还原指定台词"
        )
    payload = _push_string(carrier_text, encoding)
    encoded_carrier = payload[2:-1]
    return payload, {
        "mode": "target_owned_uif_drawtexta_replace_chars",
        "encoding": encoding,
        "runtime_roundtrip": True,
        "display_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "carrier_text": carrier_text,
        "carrier_payload_hex": encoded_carrier.hex(" "),
        "carrier_payload_sha256": _sha256(encoded_carrier),
        "payload_sha256": _sha256(payload),
        "config_name": bridge_report["config_name"],
        "config_size": bridge_report["config_size"],
        "config_sha256": bridge_report["config_sha256"],
        "table_sha256": bridge_report["table_sha256"],
    }


def _instruction_public(item: Instruction) -> dict[str, Any]:
    return {
        "offset": item.offset,
        "offset_hex": f"0x{item.offset:X}",
        "mnemonic": item.mnemonic,
        "size": item.size,
        "raw_hex": item.raw.hex(" "),
        "text": item.text if item.opcode == 0x0E else None,
        "target": item.operands.get("target") if item.opcode in (0x02, 0x06, 0x07) else None,
        "warning": item.warning,
    }


def _dialogue_context(profile: Any, offset: int) -> list[dict[str, Any]]:
    records = list(getattr(profile, "records", ()) or ())
    current_index = next(
        (index for index, record in enumerate(records) if int(record.get("slot_offset", -1)) == offset),
        None,
    )
    if current_index is None:
        return []

    def public(record: Mapping[str, Any], relation: str) -> dict[str, Any]:
        slot = int(record.get("slot_offset", 0))
        return {
            "relation": relation,
            "id": str(record.get("id") or f"hcb:0x{slot:06X}"),
            "offset": slot,
            "offset_hex": f"0x{slot:X}",
            "speaker": str(record.get("name") or record.get("raw_name") or ""),
            "text": str(record.get("current_text") or record.get("original_text") or ""),
            "voice_count": len(getattr(profile, "voices_by_offset", {}).get(slot, ())),
            "visual_count": len(getattr(profile, "visuals_by_offset", {}).get(slot, ())),
        }

    previous = next(
        (record for record in reversed(records[:current_index]) if record.get("dialogue")),
        None,
    )
    current = records[current_index]
    following = next(
        (record for record in records[current_index + 1 :] if record.get("dialogue")),
        None,
    )
    result: list[dict[str, Any]] = []
    if previous is not None:
        result.append(public(previous, "previous"))
    result.append(public(current, "current"))
    if following is not None:
        result.append(public(following, "next"))
    return result


def _first_index_at_or_after(document: HcbDocument, offset: int) -> int:
    for index, item in enumerate(document.instructions):
        if item.offset >= offset:
            return index
    raise HoshimemoSceneHookError(f"HCB 代码区没有 0x{offset:X} 之后的指令")


def _reject_interior_targets(document: HcbDocument, patch_offset: int) -> None:
    interior = set(range(patch_offset + 1, patch_offset + 5))
    for item in document.instructions:
        targets: list[int] = []
        if item.opcode in (0x02, 0x06, 0x07):
            targets.append(int(item.operands.get("target", -1)))
        if item.address_role == "thread_start_function_pointer":
            targets.append(int(item.operands.get("value", -1)))
        if any(target in interior for target in targets):
            raise HoshimemoSceneHookError(
                f"0x{item.offset:X} 的控制流目标落入五字节挂接内部"
            )


def _inspect_visual_lifecycle_boundary(
    analysis_document: HcbDocument,
    source_document: HcbDocument,
    start_offset: int,
    abi: HoshimemoSceneHookAbi,
) -> dict[str, Any]:
    """Find the first provably linear native boundary that can retire V2 portraits.

    Calls are allowed because they return to the linear story stream.  A RET or
    either jump opcode before the boundary makes reachability ambiguous, so the
    visual gate fails closed instead of scanning into another branch/function.
    """

    apply_target = (
        None if abi.portrait_apply_target is None else int(abi.portrait_apply_target)
    )
    registration_targets = {
        int(value) for value in abi.portrait_registration_targets
    } | {
        int(value) for value in abi.portrait_registration_argument_counts
    }
    reset_targets = {int(value) for value in abi.visual_reset_targets}
    if apply_target is None and not registration_targets and not reset_targets:
        return {
            "status": "not_required",
            "installable_visuals": True,
            "reason": "当前测试 ABI 未要求原生立绘生命周期清理挂接",
            "policy": "linear_native_lifecycle_boundary_v2",
            "lifecycle_boundary": None,
        }

    start_index = _first_index_at_or_after(analysis_document, int(start_offset))
    for item in analysis_document.instructions[start_index:]:
        if item.warning:
            return {
                "status": "unverified",
                "installable_visuals": False,
                "reason": (
                    f"从挂接返回点到下一原生视觉边界之间在 0x{item.offset:X} "
                    "遇到未解析指令"
                ),
                "policy": "linear_native_lifecycle_boundary_v2",
                "lifecycle_boundary": None,
            }
        if item.opcode in (0x04, 0x06, 0x07):
            return {
                "status": "unverified",
                "installable_visuals": False,
                "reason": (
                    f"从挂接返回点到下一原生视觉边界之间先在 0x{item.offset:X} "
                    f"遇到 {item.mnemonic}，不能证明单一路径"
                ),
                "policy": "linear_native_lifecycle_boundary_v2",
                "lifecycle_boundary": None,
            }
        if item.opcode != 0x02:
            continue
        target = int(item.operands.get("target", -1))
        if (
            target != apply_target
            and target not in registration_targets
            and target not in reset_targets
        ):
            continue
        if item.size != 5:
            return {
                "status": "unverified",
                "installable_visuals": False,
                "reason": f"原生视觉边界 0x{item.offset:X} 不是标准五字节 CALL",
                "policy": "linear_native_lifecycle_boundary_v2",
                "lifecycle_boundary": None,
            }
        source_raw = source_document.original_bytes[item.offset : item.offset + item.size]
        if source_raw != item.raw:
            return {
                "status": "unverified",
                "installable_visuals": False,
                "reason": (
                    f"原生视觉边界 0x{item.offset:X} 在当前活动 HCB 中已漂移"
                ),
                "policy": "linear_native_lifecycle_boundary_v2",
                "lifecycle_boundary": None,
            }
        try:
            _reject_interior_targets(analysis_document, item.offset)
        except HcbError as exc:
            return {
                "status": "unverified",
                "installable_visuals": False,
                "reason": str(exc),
                "policy": "linear_native_lifecycle_boundary_v2",
                "lifecycle_boundary": None,
            }
        if target == apply_target:
            kind = "portrait_apply"
            boundary_label = "立绘布局更新"
        elif target in registration_targets:
            kind = "portrait_registration"
            boundary_label = "立绘角色注册"
        else:
            kind = "visual_reset"
            boundary_label = "场景/日期重置"
        return {
            "status": "verified_with_cleanup",
            "installable_visuals": True,
            "reason": (
                f"已证明从挂接返回点线性到达 0x{item.offset:X} 的原生"
                f"{boundary_label}；"
                "含立绘的候选会在该 CALL 前清理本次私有 selector 并原样重放 CALL"
            ),
            "policy": "linear_native_lifecycle_boundary_v2",
            "lifecycle_boundary": {
                "kind": kind,
                "patch_offset": item.offset,
                "patch_offset_hex": f"0x{item.offset:X}",
                "expected_hex": source_raw.hex(" "),
                "target": target,
                "target_hex": f"0x{target:X}",
                "return_offset": item.offset + item.size,
                "return_offset_hex": f"0x{item.offset + item.size:X}",
                "linear_from_offset": int(start_offset),
                "linear_from_offset_hex": f"0x{int(start_offset):X}",
            },
        }

    return {
        "status": "unverified",
        "installable_visuals": False,
        "reason": "当前函数结束前没有找到可证明可达的原生视觉生命周期边界",
        "policy": "linear_native_lifecycle_boundary_v2",
        "lifecycle_boundary": None,
    }


def _resolve_patch(
    document: HcbDocument,
    selected_index: int,
    timing: str,
    abi: HoshimemoSceneHookAbi,
) -> dict[str, Any]:
    selected = document.instructions[selected_index]
    if selected.opcode != 0x0E or selected.text is None:
        raise HoshimemoSceneHookError("选择项不是可验证的 push_string 台词")
    if selected.size < 5:
        raise HoshimemoSceneHookError("该台词指令不足五字节，第一版不能安全挂接")

    if timing == "before":
        patch_item = selected
        replay_item = selected
        replay_order = "custom_then_original"
        return_offset = selected.offset + selected.size
        hook_mode = "dialogue_instruction"
        if abi.prefer_pre_speaker_before_hook and selected_index > 0:
            previous = document.instructions[selected_index - 1]
            speaker_targets = {
                int(speaker.call_target) for speaker in abi.speakers.values()
            }
            if (
                previous.opcode == 0x02
                and previous.size == 5
                and int(previous.operands.get("target", -1)) in speaker_targets
                and previous.offset + previous.size == selected.offset
            ):
                patch_item = previous
                replay_item = previous
                return_offset = selected.offset
                hook_mode = "pre_speaker_call"
        if hook_mode == "dialogue_instruction":
            try:
                next_item = document.instructions[selected_index + 1]
            except IndexError as exc:
                raise HoshimemoSceneHookError("台词后没有可返回的指令边界") from exc
            if next_item.offset != return_offset:
                raise HoshimemoSceneHookError("台词结束位置不是连续指令边界")
    elif timing == "after":
        hook_mode = "dialogue_wait_call"
        if abi.print_argument_count not in {3, 4, 5}:
            raise HoshimemoSceneHookError(
                "目标台词输出函数参数数不在已审核的 3/4/5 参数范围"
            )
        nil_count = abi.print_argument_count - 1
        expected = ((0x08,) * nil_count) + ((0x02,) if abi.print_includes_wait else (0x02, 0x02))
        following = document.instructions[
            selected_index + 1 : selected_index + 1 + len(expected)
        ]
        if len(following) != len(expected) or tuple(item.opcode for item in following) != expected:
            raise HoshimemoSceneHookError(
                f"本句之后挂接需要原生 push_string → Nil×{nil_count} → print → wait 序列"
            )
        print_call = following[nil_count]
        wait_call = print_call if abi.print_includes_wait else following[nil_count + 1]
        if int(print_call.operands.get("target", -1)) != abi.print_target:
            raise HoshimemoSceneHookError("台词 print 调用目标与 Hoshimemo ABI 不一致")
        if not abi.print_includes_wait and int(wait_call.operands.get("target", -1)) != abi.wait_target:
            raise HoshimemoSceneHookError("台词 wait 调用目标与 Hoshimemo ABI 不一致")
        if print_call.size != 5 or wait_call.size != 5:
            raise HoshimemoSceneHookError("台词结尾 call 不是标准五字节指令")
        patch_item = wait_call
        replay_item = wait_call
        replay_order = "original_then_custom"
        return_offset = wait_call.offset + wait_call.size
        next_index = selected_index + 1 + len(expected)
        if next_index >= len(document.instructions):
            raise HoshimemoSceneHookError("台词等待后没有可返回的指令边界")
        if document.instructions[next_index].offset != return_offset:
            raise HoshimemoSceneHookError("台词等待结束位置不是连续指令边界")
    else:
        raise HoshimemoSceneHookError("第一版剧情时序只支持本句之前或本句之后")

    if patch_item.offset < 4 or patch_item.offset + 5 > document.code_end:
        raise HoshimemoSceneHookError("五字节挂接不完整位于 HCB 代码区")
    if patch_item.warning or replay_item.warning:
        raise HoshimemoSceneHookError("挂接附近包含未解析指令警告")
    _reject_interior_targets(document, patch_item.offset)
    expected_bytes = document.original_bytes[patch_item.offset : patch_item.offset + 5]
    if len(expected_bytes) != 5 or expected_bytes != patch_item.raw[:5]:
        raise HoshimemoSceneHookError("挂接点原始五字节与解析指令不一致")
    return {
        "patch_offset": patch_item.offset,
        "patch_offset_hex": f"0x{patch_item.offset:X}",
        "expected_hex": expected_bytes.hex(" "),
        "replay_offset": replay_item.offset,
        "replay_offset_hex": f"0x{replay_item.offset:X}",
        "replay_size": replay_item.size,
        "replay_hex": replay_item.raw.hex(" "),
        "replay_order": replay_order,
        "return_offset": return_offset,
        "return_offset_hex": f"0x{return_offset:X}",
        "hook_mode": hook_mode,
    }


def _decode_source_string(payload: bytes, encoding: str, label: str) -> str:
    """Decode one runtime string while accepting only zero-filled fixed slots."""

    if b"\0" not in payload:
        raise HoshimemoSceneHookError(f"{label}没有 NUL 结尾")
    encoded, padding = payload.split(b"\0", 1)
    if any(padding):
        raise HoshimemoSceneHookError(f"{label}的 NUL 后包含非零数据，不能视为定长译文")
    text = decode_bytes(encoded, encoding)
    if "\ufffd" in text:
        raise HoshimemoSceneHookError(f"{label}不能按 {encoding} 无损解码")
    return text


def _resolve_source_dialogue(
    source_document: HcbDocument,
    analysis_document: HcbDocument,
    selected: Instruction,
) -> dict[str, Any]:
    """Prove how the active source represents a clean-index dialogue slot."""

    offset = int(selected.offset)
    return_offset = offset + int(selected.size)
    source = source_document.original_bytes
    if offset < 4 or return_offset > len(source):
        raise HoshimemoSceneHookError("索引台词超出当前来源 HCB 的原始地址范围")

    opcode = source[offset]
    if opcode == 0x0E:
        if offset + 2 > len(source):
            raise HoshimemoSceneHookError("当前来源 HCB 的定长台词头不完整")
        source_length = int(source[offset + 1])
        clean_length = int(selected.size) - 2
        if source_length != clean_length:
            raise HoshimemoSceneHookError(
                "当前来源 HCB 的定长台词长度字节已改变："
                f"需要 {clean_length}，实际 {source_length}"
            )
        raw = source[offset:return_offset]
        if len(raw) != selected.size:
            raise HoshimemoSceneHookError("当前来源 HCB 的定长台词槽不完整")
        text = _decode_source_string(raw[2:], source_document.encoding, "当前来源台词")
        return {
            "mode": "fixed_width_string",
            "text": text,
            "replay_offset": offset,
            "replay": raw,
            "replay_terminal": False,
            "redirect_target": None,
            "return_offset": return_offset,
        }

    if opcode != 0x06:
        raise HoshimemoSceneHookError(
            f"当前来源 HCB 在索引台词处既不是定长字符串也不是翻译跳转: 0x{opcode:02X}"
        )
    if offset + 5 > len(source):
        raise HoshimemoSceneHookError("当前来源 HCB 的翻译跳转不完整")
    redirect_target = struct.unpack_from("<I", source, offset + 1)[0]
    if redirect_target < len(analysis_document.original_bytes):
        raise HoshimemoSceneHookError(
            "翻译跳转没有指向同目录原版 HCB 物理末尾之后，不能证明为 Overlay 尾桩"
        )
    if redirect_target + 2 > len(source) or source[redirect_target] != 0x0E:
        raise HoshimemoSceneHookError("翻译跳转目标不是完整的 push_string 尾桩")
    payload_length = int(source[redirect_target + 1])
    payload_start = redirect_target + 2
    payload_end = payload_start + payload_length
    stub_end = payload_end + 5
    if stub_end > len(source):
        raise HoshimemoSceneHookError("翻译 push_string 尾桩超出当前来源 HCB")
    text = _decode_source_string(
        source[payload_start:payload_end],
        source_document.encoding,
        "当前来源翻译尾桩",
    )
    if source[payload_end] != 0x06:
        raise HoshimemoSceneHookError("翻译 push_string 尾桩后没有无条件返回跳转")
    stub_return = struct.unpack_from("<I", source, payload_end + 1)[0]
    if stub_return != return_offset:
        raise HoshimemoSceneHookError(
            "翻译尾桩返回地址与原版台词边界不一致："
            f"需要 0x{return_offset:X}，实际 0x{stub_return:X}"
        )
    return {
        "mode": "overlay_redirect",
        "text": text,
        "replay_offset": offset,
        "replay": source[offset : offset + 5],
        # Replaying this jump enters the existing translation stub, whose own
        # final jump returns to the clean slot boundary.  Appending a second
        # return after it would be unreachable and would hide a modelling bug.
        "replay_terminal": True,
        "redirect_target": redirect_target,
        "return_offset": return_offset,
    }


def _adapt_patch_to_source(
    source_document: HcbDocument,
    analysis_document: HcbDocument,
    selected: Instruction,
    clean_patch: Mapping[str, Any],
    timing: str,
) -> dict[str, Any]:
    """Turn a clean control-flow plan into exact active-source byte evidence."""

    source_dialogue = _resolve_source_dialogue(source_document, analysis_document, selected)
    patch = dict(clean_patch)
    if timing == "before" and clean_patch.get("hook_mode") == "pre_speaker_call":
        patch_offset = int(clean_patch["patch_offset"])
        replay_offset = int(clean_patch["replay_offset"])
        replay_size = int(clean_patch["replay_size"])
        expected = source_document.original_bytes[patch_offset : patch_offset + 5]
        replay = source_document.original_bytes[
            replay_offset : replay_offset + replay_size
        ]
        clean_expected = bytes.fromhex(str(clean_patch["expected_hex"]))
        clean_replay = bytes.fromhex(str(clean_patch["replay_hex"]))
        if len(expected) != 5 or expected != clean_expected:
            raise HoshimemoSceneHookError(
                f"当前来源 HCB 的原作说话人调用已漂移 @0x{patch_offset:X}"
            )
        if replay != clean_replay:
            raise HoshimemoSceneHookError("当前来源 HCB 的说话人调用重放字节与原版证据不一致")
        patch.update(
            {
                "patch_offset": patch_offset,
                "patch_offset_hex": f"0x{patch_offset:X}",
                "expected_hex": expected.hex(" "),
                "replay_offset": replay_offset,
                "replay_offset_hex": f"0x{replay_offset:X}",
                "replay_size": replay_size,
                "replay_hex": replay.hex(" "),
                "return_offset": int(selected.offset),
                "return_offset_hex": f"0x{int(selected.offset):X}",
                "replay_terminal": False,
            }
        )
    elif timing == "before":
        patch_offset = int(selected.offset)
        replay = bytes(source_dialogue["replay"])
        expected = source_document.original_bytes[patch_offset : patch_offset + 5]
        if len(expected) != 5:
            raise HoshimemoSceneHookError("当前来源台词处没有完整五字节挂接槽")
        patch.update(
            {
                "patch_offset": patch_offset,
                "patch_offset_hex": f"0x{patch_offset:X}",
                "expected_hex": expected.hex(" "),
                "replay_offset": int(source_dialogue["replay_offset"]),
                "replay_offset_hex": f"0x{int(source_dialogue['replay_offset']):X}",
                "replay_size": len(replay),
                "replay_hex": replay.hex(" "),
                "return_offset": int(source_dialogue["return_offset"]),
                "return_offset_hex": f"0x{int(source_dialogue['return_offset']):X}",
                "replay_terminal": bool(source_dialogue["replay_terminal"]),
            }
        )
    else:
        # The clean plan patches the native wait call after the line.  The
        # translated source must retain those exact five bytes, regardless of
        # whether the preceding string is inline or redirected to an EOF stub.
        patch_offset = int(clean_patch["patch_offset"])
        clean_expected = bytes.fromhex(str(clean_patch["expected_hex"]))
        source_expected = source_document.original_bytes[patch_offset : patch_offset + 5]
        if len(source_expected) != 5 or source_expected != clean_expected:
            raise HoshimemoSceneHookError(
                f"当前来源 HCB 的台词 wait 调用已漂移 @0x{patch_offset:X}"
            )
        replay_offset = int(clean_patch["replay_offset"])
        replay_size = int(clean_patch["replay_size"])
        source_replay = source_document.original_bytes[
            replay_offset : replay_offset + replay_size
        ]
        if source_replay != bytes.fromhex(str(clean_patch["replay_hex"])):
            raise HoshimemoSceneHookError("当前来源 HCB 的 wait 重放字节与原版证据不一致")
        patch.update(
            {
                "expected_hex": source_expected.hex(" "),
                "replay_hex": source_replay.hex(" "),
                "replay_terminal": False,
            }
        )
    patch.update(
        {
            "source_dialogue_mode": str(source_dialogue["mode"]),
            "source_dialogue_text": str(source_dialogue["text"]),
            "source_redirect_target": source_dialogue["redirect_target"],
            "source_redirect_target_hex": (
                f"0x{int(source_dialogue['redirect_target']):X}"
                if source_dialogue["redirect_target"] is not None
                else None
            ),
        }
    )
    return patch


def inspect_hoshimemo_dialogue_anchor(
    document: HcbDocument,
    profile: Any,
    offset: int,
    timing: str,
    *,
    abi: HoshimemoSceneHookAbi = HOSHIMEMO_SCENE_HOOK_ABI,
) -> dict[str, Any]:
    """Inspect one profile-linked dialogue and return an auditable anchor."""

    selected_offset = int(offset)
    timing_value = str(timing or "before").strip().casefold()
    index_fingerprint = str(getattr(profile, "index_fingerprint", "") or "")
    blocked_visual_reason = str(
        abi.blocked_visual_anchor_offsets.get(selected_offset) or ""
    )
    anchor: dict[str, Any] = {
        "schema": "fvp-studio-v2.story-anchor.v1",
        "anchor_id": "",
        "profile_id": abi.profile_id,
        "timing": timing_value,
        "hcb_offset": selected_offset,
        "hcb_offset_hex": f"0x{selected_offset:X}",
        "source_sha256": document.source_sha256,
        "encoding": document.encoding,
        "index_fingerprint": index_fingerprint,
        "compatibility": None,
        "analysis": None,
        "safe": False,
        "reasons": [],
        "dialogue": None,
        "dialogue_context": _dialogue_context(profile, selected_offset),
        "instruction_context": [],
        "patch": None,
        "visual_safety": {
            "status": "blocked" if blocked_visual_reason else "pending",
            "installable_visuals": False if blocked_visual_reason else None,
            "reason": (
                blocked_visual_reason
                or "正在核对该台词之后可证明可达的原生视觉生命周期边界"
            ),
            "policy": (
                "evidence_backed_failed_anchor_v2"
                if blocked_visual_reason
                else "linear_native_lifecycle_boundary_v2"
            ),
            "lifecycle_boundary": None,
        },
    }
    anchor["anchor_id"] = _canonical_sha256(
        {
            "source_sha256": document.source_sha256,
            "index_fingerprint": index_fingerprint,
            "hcb_offset": selected_offset,
            "timing": timing_value,
        }
    )[:24]
    try:
        if timing_value not in {"before", "after"}:
            raise HoshimemoSceneHookError("第一版剧情时序只支持本句之前或本句之后")
        if document.modified or document.insertions or document.fixed_patches or document.overlay_text_relocations:
            raise HoshimemoSceneHookError("剧情候选不能与当前会话中的其他 HCB 编辑混用")
        analysis_document, compatibility = resolve_hoshimemo_analysis_document(
            document,
            profile,
            expected_clean_sha256=abi.clean_source_sha256,
        )
        anchor["compatibility"] = dict(compatibility)
        anchor["analysis"] = {
            "mode": compatibility.get("mode"),
            "source_sha256": analysis_document.source_sha256,
            "path": str(analysis_document.path) if analysis_document.path is not None else None,
        }
        profile_record = profile.record_for_offset(selected_offset)
        if not isinstance(profile_record, Mapping):
            raise HoshimemoSceneHookError("该偏移没有项目对话索引")
        if not profile_record.get("dialogue"):
            raise HoshimemoSceneHookError("所选字符串不是项目索引确认的对话")
        selected_index, selected = analysis_document.find_with_index(selected_offset)
        if selected.opcode != 0x0E or selected.text is None:
            raise HoshimemoSceneHookError("索引台词在原版控制流证据中不是 push_string 指令")
        indexed_texts = {
            str(value)
            for value in (
                profile_record.get("original_text"),
                profile_record.get("current_text"),
            )
            if isinstance(value, str)
        }
        if indexed_texts and selected.text not in indexed_texts:
            raise HoshimemoSceneHookError(
                "原版控制流证据的文本编码或 HCB 版本与项目索引不匹配："
                "台词与索引原文/译文均不一致"
            )
        clean_patch = _resolve_patch(analysis_document, selected_index, timing_value, abi)
        patch = _adapt_patch_to_source(
            document,
            analysis_document,
            selected,
            clean_patch,
            timing_value,
        )
        source_text = str(patch["source_dialogue_text"])
        if indexed_texts and source_text not in indexed_texts:
            raise HoshimemoSceneHookError(
                "当前文本编码或 HCB 版本不匹配：来源台词与索引原文/译文均不一致"
            )
        context_start = max(0, selected_index - 3)
        patch_index = _first_index_at_or_after(analysis_document, int(patch["patch_offset"]))
        context_end = min(
            len(analysis_document.instructions),
            max(selected_index, patch_index) + 7,
        )
        anchor["instruction_context"] = [
            _instruction_public(item)
            for item in analysis_document.instructions[context_start:context_end]
        ]
        anchor["dialogue"] = {
            "id": str(profile_record.get("id") or f"hcb:0x{selected_offset:06X}"),
            "speaker": str(profile_record.get("name") or profile_record.get("raw_name") or ""),
            "text": source_text,
            "analysis_text": str(selected.text),
            "source_mode": str(patch["source_dialogue_mode"]),
            "indexed_text": str(
                profile_record.get("current_text") or profile_record.get("original_text") or ""
            ),
            "voice_links": list(profile_record.get("voice_links") or []),
            "visual_links": list(profile_record.get("visual_links") or []),
        }
        anchor["patch"] = patch
        if not blocked_visual_reason:
            anchor["visual_safety"] = _inspect_visual_lifecycle_boundary(
                analysis_document,
                document,
                int(patch["return_offset"]),
                abi,
            )
        identity = {
            "source_sha256": document.source_sha256,
            "index_fingerprint": index_fingerprint,
            "hcb_offset": selected_offset,
            "timing": timing_value,
            "patch_offset": patch["patch_offset"],
            "expected_hex": patch["expected_hex"],
            "analysis_source_sha256": analysis_document.source_sha256,
            "visual_lifecycle_boundary": (
                anchor["visual_safety"].get("lifecycle_boundary")
                if isinstance(anchor.get("visual_safety"), Mapping)
                else None
            ),
        }
        anchor["anchor_id"] = _canonical_sha256(identity)[:24]
        anchor["safe"] = True
    except HcbError as exc:
        anchor["reasons"] = [str(exc)]
    return anchor


def _require_function_entry(
    document: HcbDocument,
    target: int,
    expected_args: int,
    label: str,
    *,
    source_document: HcbDocument | None = None,
) -> None:
    try:
        item = document.find(int(target))
    except HcbError as exc:
        raise HoshimemoSceneHookError(
            f"{label} 目标 0x{int(target):X} 不是当前 HCB 指令边界"
        ) from exc
    if item.opcode != 0x01:
        raise HoshimemoSceneHookError(f"{label} 目标不是 init_stack 函数入口")
    if int(item.operands.get("args", -1)) != int(expected_args):
        raise HoshimemoSceneHookError(
            f"{label} ABI 参数数不匹配：预期 {expected_args}，实际 {item.operands.get('args')}"
        )
    if source_document is not None and source_document is not document:
        source_raw = source_document.original_bytes[item.offset : item.offset + item.size]
        if source_raw != item.raw:
            raise HoshimemoSceneHookError(
                f"{label} 在中文隐藏 HCB 中的函数入口字节与原版证据不一致"
            )


def _resolve_native_background_binding(
    abi: HoshimemoSceneHookAbi,
    resource: str,
) -> NativeBackgroundBinding:
    try:
        binding = abi.native_background_bindings.get(resource)
    except AttributeError as exc:
        raise HoshimemoSceneHookError(
            "原生背景 binding 目录缺失，拒绝猜测 wrapper ABI"
        ) from exc
    if binding is None:
        raise HoshimemoSceneHookError(
            f"resource_name {resource or '<空>'} 未登记在已验证的本作原生背景 binding 目录中"
        )
    if not isinstance(binding, NativeBackgroundBinding):
        raise HoshimemoSceneHookError(
            f"resource_name {resource or '<空>'} 的原生背景 binding 无效，拒绝猜测 wrapper ABI"
        )
    if binding.resource_name != resource:
        raise HoshimemoSceneHookError(
            f"原生背景 binding 键与 resource_name 不一致：{resource or '<空>'}"
        )
    expected_count = int(binding.native_wrapper_argument_count)
    arguments = tuple(binding.native_wrapper_arguments)
    if expected_count < 0 or len(arguments) != expected_count:
        raise HoshimemoSceneHookError(
            f"{resource} 原生背景 binding 参数模板长度不匹配："
            f"预期 {expected_count}，实际 {len(arguments)}"
        )
    return binding


def _compile_native_background(
    document: HcbDocument,
    background: Mapping[str, Any],
    duration_ms: int,
    abi: HoshimemoSceneHookAbi,
    *,
    analysis_document: HcbDocument | None = None,
) -> tuple[bytes, dict[str, Any]]:
    build_mode = str(background.get("build_mode") or "").strip().casefold()
    duration = int(duration_ms)
    if not 0 <= duration <= 60000:
        raise HoshimemoSceneHookError("背景转场时长必须在 0–60000 ms")
    if build_mode == "inherit_current":
        if duration != 0:
            raise HoshimemoSceneHookError(
                "继承挂接点当前背景时不得发射背景转场；时长必须为 0 ms"
            )
        return b"", {
            "asset_id": str(background.get("asset_id") or ""),
            "source_resource_name": "",
            "source_archive_name": "",
            "entry_index": 0,
            "resource_name": "",
            "runtime_blur_resource_name": "",
            "archive_name": "",
            "build_mode": "inherit_current",
            "inherited": True,
            "emitted": False,
            "byte_count": 0,
            "dissolve": None,
            "dissolve_target": None,
            "dissolve_target_hex": None,
            "duration": 0,
            "duration_ms": 0,
            "stage_fit": "inherit",
            "preview_fit_is_not_compiled": True,
            "native_evidence": (
                "目标未发现可证明的背景 resolver；候选显式保留挂接点的"
                "原生运行时背景，未发射背景加载或转场字节"
            ),
        }
    if build_mode == "generic_native_background":
        if abi.native_background_backend is None:
            raise HoshimemoSceneHookError("当前目标没有已绑定的原生背景调用链")
        native = abi.native_background_backend.compile_load(
            document,
            resource_name=str(background.get("resource_name") or ""),
            archive_name=str(background.get("archive_name") or ""),
            blur_resource_name=background.get("runtime_blur_resource_name"),
            duration_ms=duration,
        )
        last = native.report["calls"][-1]
        return native.code, {
            "asset_id": str(background.get("asset_id") or ""),
            "source_resource_name": str(background.get("resource_name") or ""),
            "source_archive_name": str(background.get("archive_name") or ""),
            "entry_index": int(background.get("entry_index") or 0),
            "resource_name": native.report["resource_name"],
            "runtime_blur_resource_name": native.report["runtime_blur_resource_name"],
            "archive_name": native.report["archive_name"],
            "build_mode": build_mode,
            "dissolve": {"target": last["address"], "target_hex": f"0x{last['address']:X}",
                         "argument_count": len(last["arguments"]), "arguments": last["arguments"]},
            "dissolve_target": last["address"],
            "dissolve_target_hex": f"0x{last['address']:X}",
            "duration": duration, "duration_ms": duration,
            "stage_fit": "native", "preview_fit_is_not_compiled": True,
            "generic_background": dict(native.report),
        }
    if abi.dissolve_target is None:
        raise HoshimemoSceneHookError(
            "目标 profile 未登记可证明的原生背景转场 ABI"
        )
    dissolve_target = int(abi.dissolve_target)
    evidence = analysis_document or document
    # Clean HCB defaults compare against opcode 08 (Nil). The legacy dump's
    # inverted "pushtrue" name must not be translated to Python True (09).
    default = None
    dissolve_arguments = (0, duration, *([default] * 7))
    _require_function_entry(
        evidence,
        dissolve_target,
        9,
        "原生转场函数",
        source_document=document,
    )
    common_report = {
        "asset_id": str(background.get("asset_id") or ""),
        "source_resource_name": str(background.get("resource_name") or ""),
        "source_archive_name": str(background.get("archive_name") or ""),
        "entry_index": int(background.get("entry_index") or 0),
        "dissolve": {
            "target": dissolve_target,
            "target_hex": f"0x{dissolve_target:X}",
            "argument_count": 9,
            "arguments": list(dissolve_arguments),
        },
        "dissolve_target": dissolve_target,
        "dissolve_target_hex": f"0x{dissolve_target:X}",
        "duration": duration,
        "duration_ms": duration,
        "stage_fit": str(background.get("fit") or "cover"),
    }

    if build_mode == "generic_direct_reference":
        resource = str(background.get("resource_name") or "").strip()
        archive_name = str(background.get("archive_name") or "").strip().casefold()
        if not resource or not archive_name:
            raise HoshimemoSceneHookError(
                "通用本作背景直引缺少 resource_name 或 archive_name"
            )
        selectors = dict(abi.generic_background_archive_selectors or {})
        if not selectors and archive_name == "graph.bin":
            selectors[archive_name] = int(abi.generic_background_archive_selector)
        if archive_name not in selectors:
            raise HoshimemoSceneHookError(
                f"背景归档 {archive_name} 没有已发现的原生 selector"
            )
        primary_target = abi.generic_background_primary_target
        blur_target = abi.generic_background_blur_target
        if primary_target is None or blur_target is None:
            raise HoshimemoSceneHookError(
                "目标 profile 未登记通用背景清晰层/模糊层 ABI"
            )
        _require_function_entry(
            evidence,
            primary_target,
            9,
            "通用清晰背景函数",
            source_document=document,
        )
        _require_function_entry(
            evidence,
            blur_target,
            9,
            "通用模糊背景函数",
            source_document=document,
        )
        selector = selectors[archive_name]
        blur_resource = str(
            background.get("runtime_blur_resource_name") or resource
        ).strip()
        generic_tail: tuple[int | bool | None, ...] = (
            None,
            50,
            default,
            default,
            default,
            background.get("native_pivot_x", default),
            default,
            selector,
        )
        payload = (
            _push_string(resource, document.encoding)
            + _arguments(generic_tail)
            + _call(primary_target)
            + _push_string(blur_resource, document.encoding)
            + _arguments(generic_tail)
            + _call(blur_target)
            + _arguments(dissolve_arguments)
            + _call(dissolve_target)
        )
        return payload, {
            **common_report,
            "resource_name": resource,
            "runtime_blur_resource_name": blur_resource,
            "archive_name": archive_name,
            "build_mode": "generic_direct_reference",
            "preview_fit_is_not_compiled": str(background.get("fit") or "cover"),
            "generic_background": {
                "primary_target": primary_target,
                "primary_target_hex": f"0x{primary_target:X}",
                "blur_target": blur_target,
                "blur_target_hex": f"0x{blur_target:X}",
                "argument_count": 9,
                "tail_arguments": list(generic_tail),
                "archive_selector": selector,
                "one_resource_reused_for_two_layers": resource == blur_resource,
                "native_evidence": (
                    "目标 profile 的背景 resolver 已证明 resource namespace、"
                    "archive selector 与原生 GraphLoad 路径；候选仅直引本作已有资源"
                ),
            },
        }

    if build_mode == "direct_reference":
        resource = str(background.get("resource_name") or "").strip()
        if not resource:
            raise HoshimemoSceneHookError(
                "HOOK1 原生背景 resource_name 为空，拒绝猜测 wrapper ABI"
            )
        binding = _resolve_native_background_binding(abi, resource)
        _require_function_entry(
            evidence,
            binding.native_wrapper_target,
            binding.native_wrapper_argument_count,
            f"{resource} 原生包装函数",
            source_document=document,
        )
        payload = (
            _arguments(binding.native_wrapper_arguments)
            + _call(binding.native_wrapper_target)
            + _arguments(dissolve_arguments)
            + _call(dissolve_target)
        )
        return payload, {
            **common_report,
            "resource_name": resource,
            "archive_name": str(background.get("archive_name") or ""),
            "build_mode": "direct_reference",
            "native_wrapper_target": binding.native_wrapper_target,
            "native_wrapper_target_hex": f"0x{binding.native_wrapper_target:X}",
            "native_wrapper_argument_count": binding.native_wrapper_argument_count,
            "native_wrapper_arguments": list(binding.native_wrapper_arguments),
            "native_variant": binding.native_variant,
            "native_evidence": binding.native_evidence,
            "preview_fit_is_not_compiled": str(background.get("fit") or "cover"),
        }

    if build_mode != "copy_hzc":
        raise HoshimemoSceneHookError(
            f"不支持的背景构建模式: {build_mode or '<空>'}"
        )
    target_archive = str(background.get("target_archive_name") or "").casefold()
    primary_resource = str(background.get("target_resource_name") or "").strip()
    blur_resource = str(background.get("runtime_blur_resource_name") or "").strip()
    resource_compile = background.get("resource_compile")
    if not isinstance(resource_compile, Mapping):
        raise HoshimemoSceneHookError("跨游戏背景缺少资源编译报告")
    if resource_compile.get("fit_compiled_to_target_canvas") is not True:
        raise HoshimemoSceneHookError(
            "跨游戏背景尚未归一化到目标游戏原生画布"
        )
    if target_archive != "graph.bin":
        raise HoshimemoSceneHookError(
            "跨游戏背景必须由已验证编译器追加到目标 graph.bin"
        )
    if not primary_resource or not blur_resource:
        raise HoshimemoSceneHookError(
            "跨游戏背景缺少已验证的目标清晰层或模糊层资源名"
        )
    primary_target = abi.generic_background_primary_target
    blur_target = abi.generic_background_blur_target
    if primary_target is None or blur_target is None:
        raise HoshimemoSceneHookError(
            "目标 profile 未登记通用背景清晰层/模糊层 ABI"
        )
    _require_function_entry(
        evidence,
        primary_target,
        9,
        "通用清晰背景函数 function_4383_",
        source_document=document,
    )
    _require_function_entry(
        evidence,
        blur_target,
        9,
        "通用模糊背景函数 function_4384_",
        source_document=document,
    )
    selector = int(abi.generic_background_archive_selector)
    if selector != 1:
        raise HoshimemoSceneHookError(
            "当前追加式背景后端只允许 function_4390_ 的 graph 选择器 1"
        )
    # This is the exact tail used by the original background wrappers:
    # resource, Nil (08), 50, five layout defaults, archive selector.
    generic_tail = (None, 50, default, default, default, default, default, selector)
    payload = (
        _push_string(primary_resource, document.encoding)
        + _arguments(generic_tail)
        + _call(primary_target)
        + _push_string(blur_resource, document.encoding)
        + _arguments(generic_tail)
        + _call(blur_target)
        + _arguments(dissolve_arguments)
        + _call(dissolve_target)
    )
    return payload, {
        **common_report,
        "resource_name": primary_resource,
        "runtime_blur_resource_name": blur_resource,
        "archive_name": target_archive,
        "build_mode": "copy_hzc",
        "fit_compiled_to_target_canvas": True,
        "generic_background": {
            "primary_target": primary_target,
            "primary_target_hex": f"0x{primary_target:X}",
            "blur_target": blur_target,
            "blur_target_hex": f"0x{blur_target:X}",
            "argument_count": 9,
            "tail_arguments": list(generic_tail),
            "archive_selector": selector,
            "one_resource_reused_for_two_layers": primary_resource == blur_resource,
            "native_evidence": (
                "function_4383_/4384_ 均为 initstack 9；原作包装尾按"
                "资源名、true、50、五个布局参数、selector=1 调用 graph 路径"
            ),
        },
        "resource_compile": dict(resource_compile),
    }


def _compile_event_visual(
    document: HcbDocument,
    event_visual: Mapping[str, Any],
    duration_ms: int,
    abi: HoshimemoSceneHookAbi,
    *,
    analysis_document: HcbDocument | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Emit the original generic event-CG prepare/load/finish sequence."""

    evidence = analysis_document or document
    prepare_target = abi.generic_event_visual_prepare_target
    loader_target = abi.generic_event_visual_target
    finish_target = abi.generic_event_visual_finish_target
    if prepare_target is None or loader_target is None or finish_target is None:
        raise HoshimemoSceneHookError("目标 profile 未登记通用原生 CG ABI")
    _require_function_entry(
        evidence,
        prepare_target,
        0,
        "CG 场景准备函数 function_858_",
        source_document=document,
    )
    _require_function_entry(
        evidence,
        loader_target,
        10,
        "通用 CG 加载函数 function_4395_",
        source_document=document,
    )
    _require_function_entry(
        evidence,
        finish_target,
        3,
        "CG 转场收尾函数 function_859_",
        source_document=document,
    )
    duration = int(duration_ms)
    if not 0 <= duration <= 60000:
        raise HoshimemoSceneHookError("CG 转场时长必须在 0–60000 ms")
    build_mode = str(event_visual.get("build_mode") or "").strip().casefold()
    if build_mode not in {"direct_reference", "copy_hzc"}:
        raise HoshimemoSceneHookError(
            f"不支持的 CG 构建模式: {build_mode or '<空>'}"
        )
    source_resource_name = str(event_visual.get("resource_name") or "").strip()
    archive_value = (
        event_visual.get("target_archive_name")
        if build_mode == "copy_hzc"
        else event_visual.get("archive_name")
    )
    archive_name = str(archive_value or "").strip().casefold()
    resource_value = (
        event_visual.get("target_resource_name")
        if build_mode == "copy_hzc"
        else source_resource_name
    )
    resource_name = str(resource_value or "").strip()
    selectors = dict(abi.generic_event_visual_archive_selectors or {})
    if archive_name not in selectors:
        raise HoshimemoSceneHookError(
            f"CG 归档 {archive_name or '<空>'} 没有已验证的 graph_vis selector"
        )
    selector = int(event_visual.get("archive_selector", selectors[archive_name]))
    if selector != int(selectors[archive_name]):
        raise HoshimemoSceneHookError("CG archive_selector 与目标归档不一致")
    if not resource_name:
        raise HoshimemoSceneHookError("CG 缺少可交给 function_4395_ 的 resource_name")

    transform = (
        event_visual.get("transform")
        if isinstance(event_visual.get("transform"), Mapping)
        else {}
    )
    display_mode = str(event_visual.get("display_mode") or "standard").strip().casefold()
    if display_mode not in {"standard", "closeup", "custom"}:
        raise HoshimemoSceneHookError("CG display_mode 未通过 V2 舞台门禁")
    default_scale = (
        1000
        if display_mode == "closeup"
        else fit_cg_scale(
            int(event_visual.get("width") or 0),
            int(event_visual.get("height") or 0),
        )
    )
    try:
        x = int(transform.get("x", 0))
        y = int(transform.get("y", 0))
        depth = int(transform.get("depth", 2000))
        rotation = int(transform.get("rotation", 0))
        scale = int(transform.get("scale", default_scale))
    except (TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError("CG 舞台变换参数必须是整数") from exc
    if not -4096 <= x <= 4096 or not -4096 <= y <= 4096:
        raise HoshimemoSceneHookError("CG X/Y 必须在 -4096 到 4096 之间")
    if not 1 <= depth <= 4000:
        raise HoshimemoSceneHookError("CG depth 必须在 1 到 4000 之间")
    if not -3600 <= rotation <= 3600:
        raise HoshimemoSceneHookError("CG rotation 必须在 -3600 到 3600 之间")
    if not CG_SCALE_MIN <= scale <= CG_SCALE_MAX:
        raise HoshimemoSceneHookError(
            f"CG scale 必须在 {CG_SCALE_MIN} 到 {CG_SCALE_MAX} 之间"
        )
    prim_set_rs_id = _require_named_syscall(document, "PrimSetRS", 3)

    # Clean HCB 0x5370E/0x53784/etc compare defaults with raw opcode 08 (Nil).
    # The legacy dump calls that byte "pushtrue"; Python True emits 09 instead.
    # Integer 0 intentionally resets layout and disables 859's auto-transition;
    # the original-writeback caller therefore owns the explicit stage commit.
    if display_mode == "standard" and (x, y, depth, rotation) == (0, 0, 2000, 0):
        runtime_layout: tuple[int | bool | None, ...] = (0, None, None, None, None)
    else:
        runtime_layout = (0, x, y, depth, None if rotation == 0 else rotation)
    loader_tail: tuple[int | bool | None, ...] = (
        runtime_layout[0],
        1,
        None,
        runtime_layout[1],
        runtime_layout[2],
        runtime_layout[3],
        runtime_layout[4],
        None,
        selector,
    )
    finish_arguments: tuple[int | bool | None, ...] = (None, None, duration)
    payload = (
        _call(prepare_target)
        + _push_string(resource_name, document.encoding)
        + _arguments(loader_tail)
        + _call(loader_target)
        + _arguments((191, rotation, scale))
        + _syscall(prim_set_rs_id)
        + _arguments(finish_arguments)
        + _call(finish_target)
    )
    return payload, {
        "asset_id": str(event_visual.get("asset_id") or ""),
        "source_resource_name": source_resource_name,
        "resource_name": resource_name,
        "source_archive_name": str(event_visual.get("archive_name") or ""),
        "archive_name": archive_name,
        "archive_selector": selector,
        "entry_index": int(event_visual.get("entry_index") or 0),
        "build_mode": build_mode,
        "display_mode": display_mode,
        "transform": {
            "x": x,
            "y": y,
            "depth": depth,
            "rotation": rotation,
            "scale": scale,
        },
        "prepare": {
            "target": prepare_target,
            "target_hex": f"0x{prepare_target:X}",
            "argument_count": 0,
        },
        "loader": {
            "target": loader_target,
            "target_hex": f"0x{loader_target:X}",
            "argument_count": 10,
            "tail_arguments": list(loader_tail),
        },
        "scale_override": {
            "primitive_id": 191,
            "syscall_id": prim_set_rs_id,
            "syscall_name": "PrimSetRS",
            "argument_count": 3,
            "arguments": [191, rotation, scale],
            "scale_unit": "1000 = 100%",
        },
        "finish": {
            "target": finish_target,
            "target_hex": f"0x{finish_target:X}",
            "argument_count": 3,
            "arguments": list(finish_arguments),
        },
        "duration_ms": duration,
        "suppresses_background_and_portraits": True,
        "resource_compile": dict(event_visual.get("resource_compile") or {}),
        "native_evidence": (
            "原作 CG wrapper 固定执行 function_858_ -> function_4395_ -> "
            "function_859_；function_4395_ 最后一参选择 graph_vis*，并以 "
            "PrimSetRS(191, rotation, 1000) 固定原图 100%。V2 在加载后对同一图元"
            "重设已冻结的 rotation/scale，再进入原生收尾。"
        ),
    }


def _audio_integer(
    value: Any,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool):
        raise HoshimemoSceneHookError(f"{field_name} 必须是整数，不能是布尔值")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError(f"{field_name} 必须是整数") from exc
    if not minimum <= number <= maximum:
        raise HoshimemoSceneHookError(
            f"{field_name} 必须在 {minimum}–{maximum} 之间"
        )
    return number


def _compile_audio_cue(
    document: HcbDocument,
    audio: Mapping[str, Any] | None,
    abi: HoshimemoSceneHookAbi,
    *,
    analysis_document: HcbDocument | None = None,
    resolved_audio_bindings: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Compile one frozen BGM/SE state through verified native wrappers.

    The audio layer deliberately has explicit no-op actions.  Missing legacy
    state is migrated to BGM ``keep`` and SE ``none``; it must never be
    interpreted as a stop command.  Cross-game entries remain preview-only
    until an additive audio-resource ABI is proven for that title.
    """

    value = audio if isinstance(audio, Mapping) else {}
    bgm = value.get("bgm") if isinstance(value.get("bgm"), Mapping) else {}
    se = value.get("se") if isinstance(value.get("se"), Mapping) else {}
    bgm_action = str(bgm.get("action") or "keep").strip().casefold()
    se_action = str(se.get("action") or "none").strip().casefold()
    if bgm_action not in {"keep", "play", "stop"}:
        raise HoshimemoSceneHookError("冻结 BGM action 必须是 keep、play 或 stop")
    if se_action not in {"none", "play", "stop_all"}:
        raise HoshimemoSceneHookError("冻结 SE action 必须是 none、play 或 stop_all")

    evidence = analysis_document or document
    payload = bytearray()
    reports: dict[str, Any] = {}

    def require_target(target: int | None, args: int, label: str) -> int:
        if target is None:
            raise HoshimemoSceneHookError(
                f"当前 profile 未登记已验证的{label} ABI，拒绝猜测"
            )
        _require_function_entry(
            evidence,
            int(target),
            args,
            label,
            source_document=document,
        )
        return int(target)

    def resolve_play_source(
        asset: Mapping[str, Any],
        expected_track: str,
    ) -> tuple[dict[str, Any], int, str, str]:
        build_mode = str(asset.get("build_mode") or "").strip().casefold()
        if build_mode == "additive_resource":
            asset_id = str(asset.get("asset_id") or "").strip()
            binding = (
                resolved_audio_bindings.get(asset_id)
                if resolved_audio_bindings is not None
                else None
            )
            if not isinstance(binding, Mapping):
                raise HoshimemoSceneHookError(
                    f"项目音频 {asset_id or '<missing>'} 尚未分配目标原生 ID"
                )
            if str(binding.get("scene_profile_id") or "") != abi.profile_id:
                raise HoshimemoSceneHookError("项目音频目标 profile 与场景 ABI 不一致")
            if str(binding.get("track") or "") != expected_track:
                raise HoshimemoSceneHookError("项目音频目标绑定轨道不一致")
            if str(binding.get("asset_id") or "") != asset_id:
                raise HoshimemoSceneHookError("项目音频目标绑定 asset_id 不一致")
            if str(binding.get("source_payload_sha256") or "") != str(
                asset.get("payload_sha256") or ""
            ):
                raise HoshimemoSceneHookError("项目音频目标绑定来源哈希已漂移")
            archive_name = str(binding.get("archive_name") or "").casefold()
            allowed = {"bgm.bin", "bgm2.bin"} if expected_track == "bgm" else {"se.bin"}
            if archive_name not in allowed:
                raise HoshimemoSceneHookError("项目音频目标归档类型不一致")
            native_id = _audio_integer(
                binding.get("native_id"),
                field_name="项目音频目标原生 ID",
                minimum=1,
                maximum=0x7FFFFFFF,
            )
            resource_name = str(binding.get("resource_name") or "")
            if not resource_name.isdecimal():
                raise HoshimemoSceneHookError("项目音频目标资源名不是数字")
            validation = {
                "valid": True,
                "ok": True,
                "source_kind": "project_asset",
                "build_mode": "additive_resource",
                "compile_ready": True,
                "preview_only": False,
                "target_binding_required": False,
                "target_profile_id": binding.get("target_profile_id"),
                "archive": archive_name,
                "resource_name": resource_name,
                "native_id": native_id,
                "source_payload_sha256": binding.get("source_payload_sha256"),
                "target_payload_sha256": binding.get("target_payload_sha256"),
            }
            return validation, native_id, resource_name, archive_name

        try:
            from .audio_workspace import (
                AudioWorkspaceError,
                validate_staged_audio_source,
            )

            validation = validate_staged_audio_source(
                asset,
                current_game_dir=(
                    document.path.parent
                    if document.path is not None
                    else asset.get("project_dir")
                ),
            )
        except (AudioWorkspaceError, OSError, TypeError, ValueError) as exc:
            raise HoshimemoSceneHookError(
                f"冻结 {'BGM' if expected_track == 'bgm' else 'SE'} 来源复检失败: {exc}"
            ) from exc
        native_id = _audio_integer(
            asset.get("native_id"),
            field_name=("BGM 原生曲目 ID" if expected_track == "bgm" else "SE 原生效果 ID"),
            minimum=1,
            maximum=0x7FFFFFFF,
        )
        if native_id != int(validation.get("native_id", native_id)):
            raise HoshimemoSceneHookError(
                f"冻结 {'BGM' if expected_track == 'bgm' else 'SE'} 原生 ID 已漂移"
            )
        return (
            dict(validation),
            native_id,
            str(asset.get("resource_name") or ""),
            str(asset.get("archive_name") or ""),
        )

    if bgm_action == "keep":
        reports["bgm"] = {"action": "keep", "emitted": False}
    elif bgm_action == "stop":
        transition = _audio_integer(
            bgm.get("transition_ms", 0),
            field_name="BGM 过渡时长",
            minimum=0,
            maximum=60000,
        )
        target = require_target(abi.bgm_stop_target, 1, "原生 BGM 停止函数")
        start = len(payload)
        payload.extend(_arguments([transition]))
        payload.extend(_call(target))
        reports["bgm"] = {
            "action": "stop",
            "emitted": True,
            "transition_ms": transition,
            "target": target,
            "target_hex": f"0x{target:X}",
            "byte_count": len(payload) - start,
        }
    else:
        asset = bgm.get("asset") if isinstance(bgm.get("asset"), Mapping) else bgm
        if not isinstance(asset, Mapping):
            raise HoshimemoSceneHookError("冻结 BGM 播放状态缺少资源身份")
        if str(asset.get("kind") or bgm.get("kind") or "").casefold() not in {
            "bgm",
            "bgm2",
        }:
            raise HoshimemoSceneHookError("冻结 BGM 资源类型不匹配")
        source_validation, native_id, resource_name, archive_name = (
            resolve_play_source(asset, "bgm")
        )
        transition = _audio_integer(
            bgm.get("transition_ms", 0),
            field_name="BGM 过渡时长",
            minimum=0,
            maximum=60000,
        )
        volume = _audio_integer(
            bgm.get("volume", 100),
            field_name="BGM 音量",
            minimum=0,
            maximum=100,
        )
        loop_value = bgm.get("loop", True)
        if not isinstance(loop_value, bool):
            raise HoshimemoSceneHookError("BGM loop 必须是布尔值")
        loop = loop_value
        target = require_target(abi.bgm_play_target, 5, "原生 BGM 播放函数")
        arguments: list[int | bool | None] = [
            native_id,
            transition,
            loop,
            volume,
            True,
        ]
        start = len(payload)
        payload.extend(_arguments(arguments))
        payload.extend(_call(target))
        reports["bgm"] = {
            "action": "play",
            "emitted": True,
            "asset_id": str(asset.get("asset_id") or ""),
            "resource_name": resource_name,
            "archive_name": archive_name,
            "native_id": native_id,
            "transition_ms": transition,
            "volume": volume,
            "loop": loop,
            "arguments": arguments,
            "target": target,
            "target_hex": f"0x{target:X}",
            "byte_count": len(payload) - start,
            "source_validation": dict(source_validation),
        }

    if se_action == "none":
        reports["se"] = {"action": "none", "emitted": False}
    elif se_action == "stop_all":
        transition = _audio_integer(
            se.get("transition_ms", 0),
            field_name="SE 过渡时长",
            minimum=0,
            maximum=60000,
        )
        target = require_target(abi.se_stop_all_target, 1, "原生 SE 全部停止函数")
        start = len(payload)
        payload.extend(_arguments([transition]))
        payload.extend(_call(target))
        reports["se"] = {
            "action": "stop_all",
            "emitted": True,
            "transition_ms": transition,
            "target": target,
            "target_hex": f"0x{target:X}",
            "byte_count": len(payload) - start,
        }
    else:
        asset = se.get("asset") if isinstance(se.get("asset"), Mapping) else se
        if not isinstance(asset, Mapping):
            raise HoshimemoSceneHookError("冻结 SE 播放状态缺少资源身份")
        if str(asset.get("kind") or se.get("kind") or "").casefold() != "se":
            raise HoshimemoSceneHookError("冻结 SE 资源类型不匹配")
        source_validation, native_id, resource_name, archive_name = (
            resolve_play_source(asset, "se")
        )
        transition = _audio_integer(
            se.get("transition_ms", 0),
            field_name="SE 过渡时长",
            minimum=0,
            maximum=60000,
        )
        volume = _audio_integer(
            se.get("volume", 100),
            field_name="SE 音量",
            minimum=0,
            maximum=100,
        )
        target = require_target(abi.se_play_target, 4, "原生 SE 播放函数")
        arguments = [native_id, transition, True, volume]
        start = len(payload)
        payload.extend(_arguments(arguments))
        payload.extend(_call(target))
        reports["se"] = {
            "action": "play",
            "emitted": True,
            "asset_id": str(asset.get("asset_id") or ""),
            "resource_name": resource_name,
            "archive_name": archive_name,
            "native_id": native_id,
            "transition_ms": transition,
            "volume": volume,
            "arguments": arguments,
            "target": target,
            "target_hex": f"0x{target:X}",
            "byte_count": len(payload) - start,
            "source_validation": dict(source_validation),
        }

    reports.update(
        {
            "schema": "fvp-studio-v2.native-audio-cue-report.v1",
            "emitted": bool(payload),
            "byte_count": len(payload),
            "emission_order": "audio_before_visual",
            "native_evidence": (
                "function_4442_/4444_ and function_4435_/4436_ entry bytes, "
                "argument use and syscall arity were verified against the clean dump "
                "and active hidden HCB; external audio remains preview-only"
            ),
        }
    )
    return bytes(payload), reports


def _compile_inserted_dialogue(
    document: HcbDocument,
    profile: Any,
    lines: Sequence[Mapping[str, Any]],
    abi: HoshimemoSceneHookAbi,
    *,
    analysis_document: HcbDocument | None = None,
    after_print_bytes: bytes = b"",
    before_line_bytes: Mapping[str, bytes] | None = None,
    after_print_bytes_by_line: Mapping[str, bytes] | None = None,
) -> tuple[bytes, list[dict[str, Any]]]:
    evidence = analysis_document or document
    _require_function_entry(
        evidence,
        abi.print_target,
        abi.print_argument_count,
        "原生文本输出函数",
        source_document=document,
    )
    if abi.print_argument_count not in {3, 4, 5}:
        raise HoshimemoSceneHookError(
            "目标台词输出函数参数数不在已审核的 3/4/5 参数范围"
        )
    if abi.print_includes_wait and (
        after_print_bytes or any((before_line_bytes or {}).values())
        or any((after_print_bytes_by_line or {}).values())
    ):
        raise HoshimemoSceneHookError("打印内部等待的目标尚未接入台词中途立绘重应用")
    _require_function_entry(
        evidence,
        abi.wait_target,
        0,
        "原生文本等待函数",
        source_document=document,
    )
    speaker_catalog = discover_story_speakers(document, profile)
    if not isinstance(after_print_bytes, bytes):
        raise HoshimemoSceneHookError("台词初始化后的立绘重应用程序必须是 bytes")
    line_ids = [
        str(line.get("line_id") or f"line-{index}")
        if isinstance(line, Mapping)
        else f"line-{index}"
        for index, line in enumerate(lines, 1)
    ]
    if len(line_ids) != len(set(line_ids)):
        raise HoshimemoSceneHookError("新增台词含重复 line_id")

    def byte_map(
        value: Mapping[str, bytes] | None, label: str
    ) -> dict[str, bytes]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise HoshimemoSceneHookError(f"{label}必须是 line_id -> bytes 映射")
        unknown = sorted(str(key) for key in value if str(key) not in line_ids)
        if unknown:
            raise HoshimemoSceneHookError(
                f"{label}引用了未知台词: {', '.join(unknown)}"
            )
        result: dict[str, bytes] = {}
        for key, payload in value.items():
            if not isinstance(payload, bytes):
                raise HoshimemoSceneHookError(f"{label} {key} 的程序必须是 bytes")
            result[str(key)] = payload
        return result

    before_by_line = byte_map(before_line_bytes, "逐句立绘切换程序")
    reapply_by_line = byte_map(
        after_print_bytes_by_line, "逐句台词后的立绘重应用程序"
    )
    output = bytearray()
    report: list[dict[str, Any]] = []
    for index, line in enumerate(lines, 1):
        if not isinstance(line, Mapping):
            raise HoshimemoSceneHookError(f"新增台词 {index} 不是对象")
        speaker_id = str(line.get("speaker_id") or "narration").strip().casefold()
        text = line.get("text")
        if not isinstance(text, str) or not text.strip():
            raise HoshimemoSceneHookError(f"新增台词 {index} 内容为空")
        voice_id = line.get("voice_id")
        line_id = str(line.get("line_id") or f"line-{index}")
        start = len(output)
        transition = before_by_line.get(line_id, b"")
        transition_start = len(output)
        output.extend(transition)
        transition_end = len(output)
        if speaker_id != "narration":
            speaker = abi.speakers.get(speaker_id)
            if speaker is not None:
                call_target = speaker.call_target
                argument_count = speaker.argument_count
                name_selector = speaker.name_selector
                speaker_name = speaker.display_name
                speaker_function = None
                voiced_tail = speaker.voiced_tail
                unvoiced_arguments = speaker.unvoiced_arguments
            else:
                try:
                    scanned = resolve_story_speaker(speaker_catalog, speaker_id)
                except HcbError as exc:
                    raise HoshimemoSceneHookError(
                        f"新增台词 {index} 说话人身份无法复检: {exc}"
                    ) from exc
                if not scanned.get("compile_ready"):
                    raise HoshimemoSceneHookError(
                        f"新增台词 {index} 的 {scanned.get('display_name') or speaker_id} "
                        f"仅可预览：{scanned.get('reason') or '原生调用尚未核验'}"
                    )
                try:
                    call_target = int(scanned["call_target"])
                    argument_count = int(scanned["argument_count"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise HoshimemoSceneHookError(
                        f"新增台词 {index} 的扫描说话人 ABI 不完整"
                    ) from exc
                name_selector = scanned.get("name_selector")
                if name_selector is not None:
                    try:
                        name_selector = int(name_selector)
                    except (TypeError, ValueError) as exc:
                        raise HoshimemoSceneHookError(
                            f"新增台词 {index} 的名字切换参数无效"
                        ) from exc
                speaker_name = str(scanned.get("display_name") or speaker_id)
                speaker_function = scanned.get("speaker_function")
                voiced_tail = None
                unvoiced_arguments = None
            _require_function_entry(
                evidence,
                call_target,
                argument_count,
                f"{speaker_name} SPEAK",
                source_document=document,
            )
            if voice_id is None:
                if unvoiced_arguments is not None:
                    arguments = list(unvoiced_arguments)
                    if len(arguments) != argument_count:
                        raise HoshimemoSceneHookError(
                            f"新增台词 {index} 的 {speaker_name} 无语音参数模板长度错误"
                        )
                else:
                    arguments = [None] * argument_count
                if name_selector is not None and unvoiced_arguments is None:
                    if argument_count < 2:
                        raise HoshimemoSceneHookError(
                            f"新增台词 {index} 的 {speaker_name} 没有名字切换参数位"
                        )
                    arguments[1] = name_selector
                output.extend(_arguments(arguments))
            else:
                if voiced_tail is None:
                    raise HoshimemoSceneHookError(
                        f"新增台词 {index} 的 {speaker_name} 语音参数尚未验证"
                    )
                number = int(voice_id)
                if not 0 <= number <= 0x7FFFFFFF:
                    raise HoshimemoSceneHookError(f"新增台词 {index} 语音 ID 超出正 i32")
                output.extend(_push_value(number))
                output.extend(_arguments(voiced_tail))
            output.extend(_call(call_target))
        else:
            if voice_id is not None:
                raise HoshimemoSceneHookError(f"新增台词 {index} 的旁白不能绑定角色语音")
            speaker_name = "旁白"
        dialogue_payload, text_emission = _push_dialogue_string(
            text,
            document.encoding,
            abi.runtime_text_bridge,
        )
        output.extend(dialogue_payload)
        output.extend(_arguments([None] * (abi.print_argument_count - 1)))
        output.extend(_call(abi.print_target))
        line_reapply = reapply_by_line.get(line_id, after_print_bytes)
        reapply_start = len(output)
        output.extend(line_reapply)
        reapply_end = len(output)
        if not abi.print_includes_wait:
            output.extend(_call(abi.wait_target))
        report.append(
            {
                "line_id": line_id,
                "speaker_id": speaker_id,
                "speaker": speaker_name,
                "speaker_function": speaker_function if speaker_id != "narration" else None,
                "name_selector": name_selector if speaker_id != "narration" else None,
                "text": text,
                "text_emission": dict(text_emission),
                "print_argument_count": abi.print_argument_count,
                "print_includes_wait": abi.print_includes_wait,
                "separate_wait_emitted": not abi.print_includes_wait,
                "voice_id": voice_id,
                "block_offset": start,
                "byte_count": len(output) - start,
                "portrait_transition_range": (
                    [transition_start, transition_end] if transition else None
                ),
                "portrait_transition_sha256": (
                    _sha256(transition) if transition else None
                ),
                "portrait_reapply_range": (
                    [reapply_start, reapply_end] if line_reapply else None
                ),
                "portrait_reapply_sha256": (
                    _sha256(line_reapply) if line_reapply else None
                ),
                "actor_expressions": [
                    dict(item)
                    for item in line.get("actor_expressions", ())
                    if isinstance(item, Mapping)
                ],
            }
        )
    return bytes(output), report


_PORTRAIT_SETUP_OPERATION_KINDS = frozenset(
    {"call_registration_wrapper", "call_native_layout"}
)
_PORTRAIT_REAPPLY_OPERATION_KINDS = frozenset(
    {
        "call_final_transform",
        "call_portrait_geometry",
        "call_portrait_opacity",
        "call_portrait_rotation",
    }
)


def _portrait_reapply_suffix(
    data: bytes,
    validation: Mapping[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    """Extract the audited final-effect suffix from one emitted program.

    ``function_4339_`` enters ``function_4338_`` and that function invokes the
    native portrait refresh before a line becomes interactive.  Registration
    and the one native layout call therefore stay in the initial stream, while
    the final geometry/opacity/rotation suffix must be replayable immediately
    after every dialogue prepare call.
    """

    if not isinstance(data, bytes) or not data:
        raise HoshimemoSceneHookError("立绘可组合程序为空")
    operations = validation.get("operations")
    if not isinstance(operations, list) or not operations:
        raise HoshimemoSceneHookError("立绘发射验证缺少逻辑操作范围")
    cursor = 0
    reapply_start: int | None = None
    setup_kinds: list[str] = []
    reapply_kinds: list[str] = []
    layout_count = 0
    for index, item in enumerate(operations):
        if not isinstance(item, Mapping):
            raise HoshimemoSceneHookError("立绘发射验证含无效逻辑操作")
        byte_range = item.get("byte_range")
        if (
            not isinstance(byte_range, list)
            or len(byte_range) != 2
            or isinstance(byte_range[0], bool)
            or isinstance(byte_range[1], bool)
        ):
            raise HoshimemoSceneHookError("立绘逻辑操作缺少有效字节范围")
        try:
            start, end = (int(byte_range[0]), int(byte_range[1]))
        except (TypeError, ValueError) as exc:
            raise HoshimemoSceneHookError("立绘逻辑操作字节范围不是整数") from exc
        if start != cursor or not start < end or end > len(data):
            raise HoshimemoSceneHookError(
                f"立绘逻辑操作 #{index} 的字节范围不连续"
            )
        cursor = end
        kind = str(item.get("kind") or "")
        if reapply_start is None and kind in _PORTRAIT_SETUP_OPERATION_KINDS:
            setup_kinds.append(kind)
            if kind == "call_native_layout":
                layout_count += 1
            continue
        if kind not in _PORTRAIT_REAPPLY_OPERATION_KINDS:
            raise HoshimemoSceneHookError(
                f"立绘台词后重应用出现不受支持的逻辑操作: {kind or '<缺失>'}"
            )
        if reapply_start is None:
            reapply_start = start
        reapply_kinds.append(kind)
    if cursor != len(data):
        raise HoshimemoSceneHookError("立绘逻辑操作没有覆盖完整可组合程序")
    if (
        not setup_kinds
        or setup_kinds[-1] != "call_native_layout"
        or layout_count != 1
        or any(kind != "call_registration_wrapper" for kind in setup_kinds[:-1])
    ):
        raise HoshimemoSceneHookError("立绘初始程序不是注册角色后调用一次原生布局")
    if reapply_start is None or not reapply_kinds:
        raise HoshimemoSceneHookError("立绘程序缺少台词初始化后的最终效果段")
    reapply = data[reapply_start:]
    return reapply, {
        "schema": "fvp-studio-v2.portrait-dialogue-reapply.v1",
        "passed": True,
        "initial_program_bytes": len(data),
        "initial_program_sha256": _sha256(data),
        "setup_range": [0, reapply_start],
        "setup_operation_kinds": setup_kinds,
        "reapply_range": [reapply_start, len(data)],
        "reapply_operation_kinds": reapply_kinds,
        "reapply_bytes": len(reapply),
        "reapply_sha256": _sha256(reapply),
        "native_dialogue_refresh": "function_4339_ -> function_4338_ -> function_4483_",
    }


def _portrait_cache_guard(
    portrait_compile_target: Any | None,
) -> tuple[bytes, dict[str, Any] | None]:
    """Compile an evidence-bound cache invalidation around imported portraits."""

    if portrait_compile_target is None:
        return b"", None
    evidence = getattr(portrait_compile_target, "evidence", None)
    if not isinstance(evidence, Mapping):
        return b"", None
    value = evidence.get("cache_guard")
    if value is None:
        return b"", None
    if not isinstance(value, Mapping):
        raise HoshimemoSceneHookError("目标立绘缓存保护证据不是对象")
    if str(value.get("schema") or "") != (
        "fvp-studio-v2.native-portrait-cache-guard.v1"
    ):
        raise HoshimemoSceneHookError("目标立绘缓存保护 schema 不受支持")
    if str(value.get("strategy") or "") != "set_nil_before_custom_portrait_program":
        raise HoshimemoSceneHookError("目标立绘缓存保护策略不受支持")
    try:
        selector = int(value["selector"])
        argument_stack = int(value["argument_stack"])
        dispatcher_argument_count = int(
            value.get(
                "dispatcher_argument_count",
                13 if argument_stack == -13 else -1,
            )
        )
        global_id = int(value["global_id"])
        read_offset = int(value["read_offset"])
        write_offset = int(value["write_offset"])
        gate_offset = int(value["gate_offset"])
        gate_target = int(value["gate_target"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError("目标立绘缓存保护证据字段无效") from exc
    if (
        selector < 0
        or dispatcher_argument_count not in {12, 13}
        or argument_stack != -dispatcher_argument_count
    ):
        raise HoshimemoSceneHookError("目标立绘缓存保护没有绑定已证明的 action 参数")
    if not 0 <= global_id <= 0xFFFF:
        raise HoshimemoSceneHookError("目标立绘缓存保护 global ID 无效")
    if not (0 <= read_offset < gate_offset < gate_target < write_offset):
        raise HoshimemoSceneHookError("目标立绘缓存保护控制流顺序无效")
    payload = _push_value(None) + _pop_global(global_id)
    return payload, {
        "schema": "fvp-studio-v2.native-portrait-cache-guard-emission.v1",
        "passed": True,
        "selector": selector,
        "argument_stack": argument_stack,
        "dispatcher_argument_count": dispatcher_argument_count,
        "argument_role": str(value.get("argument_role") or ""),
        "global_id": global_id,
        "source_read_offset": read_offset,
        "source_write_offset": write_offset,
        "source_gate_offset": gate_offset,
        "source_gate_target": gate_target,
        "placement": "before_portrait_program",
        "native_postcondition": "dispatcher_rewrites_action_cache",
        "restore_owner": "proven_native_lifecycle_cleanup",
        "byte_count": len(payload),
        "sha256": _sha256(payload),
    }


def _portrait_state_isolation(
    portrait_compile_target: Any | None,
    document: HcbDocument,
) -> tuple[bytes, bytes, bytes, dict[str, Any] | None]:
    """Spill one selector-state snapshot onto the VM operand stack.

    The target-side extractor supplies every global written by the active
    native selector branch.  Values remain below the balanced custom calls and
    are popped back in reverse order before the untouched original call is
    replayed.  This deliberately changes neither declared global table nor HCB
    system-description bytes, which must stay identical across paired runtime
    and analysis HCBs.
    """

    if portrait_compile_target is None:
        return b"", b"", b"", None
    evidence = getattr(portrait_compile_target, "evidence", None)
    if not isinstance(evidence, Mapping):
        return b"", b"", b"", None
    value = evidence.get("state_isolation")
    if value is None:
        return b"", b"", b"", None
    if not isinstance(value, Mapping):
        raise HoshimemoSceneHookError("目标立绘状态隔离证据不是对象")
    if str(value.get("schema") or "") != (
        "fvp-studio-v2.native-portrait-state-isolation.v1"
    ):
        raise HoshimemoSceneHookError("目标立绘状态隔离 schema 不受支持")
    if str(value.get("strategy") or "") != (
        "snapshot_on_operand_stack_restore_before_original_replay"
    ):
        raise HoshimemoSceneHookError("目标立绘状态隔离策略不受支持")
    if str(value.get("scratch_allocation") or "") != (
        "vm_operand_stack"
    ):
        raise HoshimemoSceneHookError("目标立绘状态隔离没有使用 VM 操作数栈")
    if str(value.get("cache_rearm") or "") != (
        "set_nil_at_cleanup_before_native_replay"
    ):
        raise HoshimemoSceneHookError("目标立绘状态隔离缓存恢复策略不受支持")
    globals_value = value.get("global_ids")
    if not isinstance(globals_value, Sequence) or isinstance(
        globals_value, (str, bytes, bytearray)
    ):
        raise HoshimemoSceneHookError("目标立绘状态隔离 global 列表无效")
    try:
        selector = int(value["selector"])
        global_ids = tuple(int(item) for item in globals_value)
        cache_global_id = int(value["cache_global_id"])
        source_branch_range = tuple(int(item) for item in value["source_branch_range"])
        resource_root_offset = int(value["resource_root_offset"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError("目标立绘状态隔离证据字段无效") from exc
    if selector < 0:
        raise HoshimemoSceneHookError("目标立绘状态隔离 selector 无效")
    if not global_ids or global_ids != tuple(sorted(set(global_ids))):
        raise HoshimemoSceneHookError("目标立绘状态 global 必须是非空有序唯一列表")
    if cache_global_id not in global_ids:
        raise HoshimemoSceneHookError("目标立绘缓存 global 不在状态快照列表中")
    if len(source_branch_range) != 2 or not (
        0 <= source_branch_range[0] < resource_root_offset < source_branch_range[1]
    ):
        raise HoshimemoSceneHookError("目标立绘状态隔离来源分支范围无效")

    cache_value = evidence.get("cache_guard")
    if not isinstance(cache_value, Mapping):
        raise HoshimemoSceneHookError("目标立绘状态隔离缺少缓存保护证据")
    try:
        cache_selector = int(cache_value["selector"])
        guard_global_id = int(cache_value["global_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError("目标立绘缓存保护证据字段无效") from exc
    if cache_selector != selector or guard_global_id != cache_global_id:
        raise HoshimemoSceneHookError("目标立绘状态隔离与缓存保护身份不一致")

    non_volatile = int(document.header.non_volatile_globals)
    volatile = int(document.header.volatile_globals)
    source_total = non_volatile + volatile
    if any(global_id < 0 or global_id >= source_total for global_id in global_ids):
        raise HoshimemoSceneHookError("目标立绘状态 global 超出来源 HCB 声明范围")
    snapshot = b"".join(_push_global(global_id) for global_id in global_ids)
    restore = b"".join(_pop_global(global_id) for global_id in reversed(global_ids))
    cache_rearm = _push_value(None) + _pop_global(cache_global_id)
    report = {
        "schema": "fvp-studio-v2.portrait-state-isolation-emission.v1",
        "passed": True,
        "selector": selector,
        "source_global_ids": list(global_ids),
        "cache_global_id": cache_global_id,
        "source_branch_range": list(source_branch_range),
        "resource_root_offset": resource_root_offset,
        "scratch_allocation": "vm_operand_stack",
        "strategy": "snapshot_on_operand_stack_restore_before_original_replay",
        "source_non_volatile_globals": non_volatile,
        "source_volatile_globals": volatile,
        "source_total_globals": source_total,
        "stack_value_count": len(global_ids),
        "header_unchanged": True,
        "snapshot_placement": "before_cache_guard_and_portrait_program",
        "restore_placement": "after_custom_scene_before_original_replay",
        "cache_rearm": "set_nil_at_cleanup_before_native_replay",
        "cache_rearm_placement": "after_lifecycle_handoff_before_native_replay",
        "snapshot_byte_count": len(snapshot),
        "snapshot_sha256": _sha256(snapshot),
        "restore_byte_count": len(restore),
        "restore_sha256": _sha256(restore),
        "cache_rearm_byte_count": len(cache_rearm),
        "cache_rearm_sha256": _sha256(cache_rearm),
    }
    return snapshot, restore, cache_rearm, report


def _compile_portrait_pre_scene_clear(
    portrait_compile_target: Any | None,
    document: HcbDocument,
    analysis_document: HcbDocument,
    selectors: Sequence[int],
    abi: HoshimemoSceneHookAbi,
) -> tuple[bytes, dict[str, Any] | None]:
    """Remove the inherited native portrait before changing the visual.

    The exact ``clear(selector, Nil)`` + ``apply(Nil, Nil, Nil)`` sequence is
    accepted only when it was extracted from this target's original HCB.  The
    caller places the emitted bytes after the selector-state snapshot and
    before any background/CG transition, preventing one stale native frame.
    """

    if portrait_compile_target is None:
        return b"", None
    evidence = getattr(portrait_compile_target, "evidence", None)
    if not isinstance(evidence, Mapping):
        return b"", None
    lifecycle = evidence.get("lifecycle")
    if not isinstance(lifecycle, Mapping):
        raise HoshimemoSceneHookError("目标立绘证据缺少生命周期对象")
    value = lifecycle.get("pre_scene_clear")
    if not isinstance(value, Mapping):
        raise HoshimemoSceneHookError("目标立绘证据缺少原作入场清场序列")
    if str(value.get("schema") or "") != (
        "fvp-studio-v2.native-portrait-pre-scene-clear.v1"
    ):
        raise HoshimemoSceneHookError("目标立绘入场清场 schema 不受支持")
    if str(value.get("strategy") or "") != (
        "clear_then_nil_apply_before_visual"
    ):
        raise HoshimemoSceneHookError("目标立绘入场清场策略不受支持")
    try:
        selector = int(value["selector"])
        clear_target = int(value["clear_target"])
        apply_target = int(value["apply_target"])
        source_count = int(value["source_sequence_count"])
        source_offsets = [int(item) for item in value["source_sequence_offsets"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError("目标立绘入场清场证据字段无效") from exc
    normalized_selectors = tuple(sorted({int(item) for item in selectors}))
    if normalized_selectors != (selector,):
        raise HoshimemoSceneHookError("入场清场 selector 与舞台分配不一致")
    if (
        clear_target != abi.portrait_clear_target
        or apply_target != abi.portrait_apply_target
    ):
        raise HoshimemoSceneHookError("入场清场目标与当前 profile ABI 不一致")
    if value.get("clear_arguments") != [selector, None]:
        raise HoshimemoSceneHookError("入场清场 clear 参数不是原作证据值")
    apply_argument_count = int(abi.portrait_apply_argument_count)
    if apply_argument_count not in {2, 3}:
        raise HoshimemoSceneHookError("入场清场 apply 参数数不受支持")
    apply_arguments = [None] * apply_argument_count
    try:
        evidence_apply_argument_count = int(
            value.get("apply_argument_count", apply_argument_count)
        )
    except (TypeError, ValueError) as exc:
        raise HoshimemoSceneHookError(
            "立绘预清场证据的 apply 参数数无效"
        ) from exc
    if (
        evidence_apply_argument_count != apply_argument_count
        or value.get("apply_arguments") != apply_arguments
    ):
        raise HoshimemoSceneHookError("入场清场 apply 参数不是原作 Nil 序列")
    if source_count < 1 or source_count != len(source_offsets):
        raise HoshimemoSceneHookError("入场清场原作证据计数无效")
    source_offsets_sha256 = hashlib.sha256(
        ",".join(str(item) for item in source_offsets).encode("ascii")
    ).hexdigest()
    if str(value.get("source_sequence_offsets_sha256") or "") != (
        source_offsets_sha256
    ):
        raise HoshimemoSceneHookError("入场清场原作证据摘要无效")

    payload = (
        _arguments([selector, None])
        + _call(clear_target)
        + _arguments(apply_arguments)
        + _call(apply_target)
    )
    for offset in source_offsets:
        end = offset + len(payload)
        if (
            analysis_document.original_bytes[offset:end] != payload
            or document.original_bytes[offset:end] != payload
        ):
            raise HoshimemoSceneHookError(
                f"入场清场原作序列已漂移 @0x{offset:X}"
            )
    report = {
        "schema": "fvp-studio-v2.portrait-pre-scene-clear-emission.v1",
        "passed": True,
        "selector": selector,
        "clear_target": clear_target,
        "apply_target": apply_target,
        "clear_arguments": [selector, None],
        "apply_argument_count": apply_argument_count,
        "apply_arguments": apply_arguments,
        "source_sequence_count": source_count,
        "source_sequence_offsets": source_offsets,
        "source_sequence_offsets_sha256": source_offsets_sha256,
        "strategy": "clear_then_nil_apply_before_visual",
        "placement": "after_state_snapshot_before_audio_and_visual",
        "purpose": "remove_previous_native_primitive_before_visual_transition",
        "byte_count": len(payload),
        "sha256": _sha256(payload),
    }
    return payload, report


def _compile_portrait_print_wrapper(
    print_target: int,
    reapply_bytes: bytes,
    argument_count: int = 4,
) -> bytes:
    """Forward the discovered native print arguments, then restore effects."""

    if not reapply_bytes:
        raise HoshimemoSceneHookError("原文台词立绘刷新包装缺少重应用程序")
    if argument_count not in (3, 4):
        raise HoshimemoSceneHookError(
            f"原文台词立绘刷新包装不支持 {argument_count} 参数的文本 ABI"
        )
    push_arguments = b"".join(
        b"\x10" + struct.pack("<b", stack_index)
        for stack_index in range(-(argument_count + 1), -1)
    )
    return (
        b"\x01" + struct.pack("<H", argument_count)
        + push_arguments
        + _call(print_target)
        + reapply_bytes
        + b"\x04"
    )


def _portrait_source_print_call_sites(
    document: HcbDocument,
    analysis_document: HcbDocument,
    *,
    start: int,
    end: int,
    print_target: int,
) -> tuple[int, ...]:
    """Prove every source-dialogue refresh call before portrait cleanup."""

    if start < 0 or end <= start:
        raise HoshimemoSceneHookError("立绘生命周期中的原文台词扫描范围无效")
    if end > len(document.original_bytes) or end > len(analysis_document.original_bytes):
        raise HoshimemoSceneHookError("立绘生命周期中的原文台词扫描越过 HCB")

    def collect(source: HcbDocument) -> tuple[int, ...]:
        return tuple(
            int(item.offset)
            for item in source.instructions
            if (
                start <= int(item.offset) < end
                and item.opcode == 0x02
                and int(item.operands.get("target", -1)) == int(print_target)
            )
        )

    source_offsets = collect(document)
    analysis_offsets = collect(analysis_document)
    if source_offsets != analysis_offsets:
        raise HoshimemoSceneHookError(
            "翻译 HCB 与原版 HCB 的原文台词刷新调用位置不一致"
        )
    expected = _call(print_target)
    for offset in source_offsets:
        if (
            document.original_bytes[offset : offset + 5] != expected
            or analysis_document.original_bytes[offset : offset + 5] != expected
        ):
            raise HoshimemoSceneHookError(
                f"原文台词刷新调用五字节已漂移 @0x{offset:X}"
            )
    return source_offsets


def _compile_portrait_lifecycle_cleanup(
    document: HcbDocument,
    analysis_document: HcbDocument,
    selectors: Sequence[int],
    boundary: Mapping[str, Any],
    abi: HoshimemoSceneHookAbi,
    *,
    cache_rearm_bytes: bytes = b"",
    state_isolation_report: Mapping[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Clear imported selector state, replay the native boundary, and return."""

    if abi.portrait_clear_target is None or abi.portrait_apply_target is None:
        raise HoshimemoSceneHookError("当前 profile 没有登记立绘生命周期清理 ABI")
    clear_target = int(abi.portrait_clear_target)
    apply_target = int(abi.portrait_apply_target)
    apply_argument_count = int(abi.portrait_apply_argument_count)
    if apply_argument_count not in {2, 3}:
        raise HoshimemoSceneHookError("原生立绘 apply 参数数不受支持")
    nil_apply_arguments = [None] * apply_argument_count
    _require_function_entry(
        analysis_document,
        clear_target,
        2,
        "原生立绘状态清理函数",
        source_document=document,
    )
    _require_function_entry(
        analysis_document,
        apply_target,
        apply_argument_count,
        "原生立绘布局应用函数",
        source_document=document,
    )

    normalized_selectors = tuple(sorted({int(value) for value in selectors}))
    if not normalized_selectors:
        raise HoshimemoSceneHookError("立绘生命周期清理没有实际 selector")
    if any(value < 0 for value in normalized_selectors):
        raise HoshimemoSceneHookError("立绘生命周期清理 selector 无效")

    kind = str(boundary.get("kind") or "")
    patch_offset = int(boundary.get("patch_offset", -1))
    return_offset = int(boundary.get("return_offset", -1))
    expected = bytes.fromhex(str(boundary.get("expected_hex") or ""))
    if kind not in {"portrait_apply", "portrait_registration", "visual_reset"}:
        raise HoshimemoSceneHookError("立绘生命周期边界类型无效")
    try:
        analysis_call = analysis_document.find(patch_offset)
    except HcbError as exc:
        raise HoshimemoSceneHookError("立绘生命周期边界不是原版指令边界") from exc
    if analysis_call.opcode != 0x02 or analysis_call.size != 5:
        raise HoshimemoSceneHookError("立绘生命周期边界不是标准五字节 CALL")
    target = int(analysis_call.operands.get("target", -1))
    expected_target = (
        apply_target if kind == "portrait_apply" else int(boundary.get("target", -1))
    )
    if target != expected_target:
        raise HoshimemoSceneHookError("立绘生命周期边界 CALL 目标已漂移")
    registration_argument_count: int | None = None
    if kind == "portrait_registration":
        registration_argument_counts = {
            int(value): int(count)
            for value, count in abi.portrait_registration_argument_counts.items()
        }
        for value in abi.portrait_registration_targets:
            registration_argument_counts.setdefault(
                int(value),
                int(abi.portrait_registration_argument_count),
            )
        if target not in registration_argument_counts:
            raise HoshimemoSceneHookError("立绘角色注册边界没有登记在当前 profile")
        registration_argument_count = registration_argument_counts[target]
        if registration_argument_count not in {8, 9, 12, 13}:
            raise HoshimemoSceneHookError("原生立绘角色注册参数数不受支持")
        _require_function_entry(
            analysis_document,
            target,
            registration_argument_count,
            "原生立绘角色注册函数",
            source_document=document,
        )
    if kind == "visual_reset" and target not in {
        int(value) for value in abi.visual_reset_targets
    }:
        raise HoshimemoSceneHookError("场景重置边界没有登记在当前 profile")
    actual = document.original_bytes[patch_offset : patch_offset + 5]
    if len(expected) != 5 or expected != analysis_call.raw or actual != expected:
        raise HoshimemoSceneHookError(
            f"立绘生命周期边界五字节漂移 @0x{patch_offset:X}"
        )
    if return_offset != patch_offset + 5:
        raise HoshimemoSceneHookError("立绘生命周期边界返回地址不是下一指令")
    _reject_interior_targets(analysis_document, patch_offset)

    payload = bytearray()
    restored_registration_handoff = (
        kind == "portrait_registration" and state_isolation_report is not None
    )
    # A registration whose runtime geometry arguments are Nil intentionally
    # inherits the preceding native selector state.  That state was restored
    # by the main scene trampoline.  Clearing here would erase its form/pivot
    # caches and make the untouched registration fall back to malformed
    # coordinates.  Re-apply the restored layout instead; the cache guard below
    # forces the original resource to reload on the same primitive pair.
    if restored_registration_handoff:
        payload.extend(_arguments(nil_apply_arguments))
        payload.extend(_call(apply_target))
    else:
        for selector in normalized_selectors:
            payload.extend(_arguments([selector, None]))
            payload.extend(_call(clear_target))
    # A native portrait-apply boundary already has its three original
    # arguments on the VM stack and will apply the cleared states when replayed.
    # A visual reset uses its source-proven one-tick flush.  Registration with
    # isolated state uses the Nil apply above and must not clear inherited
    # geometry.
    explicit_apply = kind == "visual_reset" or (
        kind == "portrait_registration" and not restored_registration_handoff
    )
    if explicit_apply:
        flush_duration = (
            (0 if kind == "portrait_registration" else 1)
            if apply_argument_count == 3
            else None
        )
        explicit_apply_arguments = (
            [flush_duration, None, None]
            if apply_argument_count == 3
            else list(nil_apply_arguments)
        )
        payload.extend(_arguments(explicit_apply_arguments))
        payload.extend(_call(apply_target))
    if bool(cache_rearm_bytes) != bool(state_isolation_report):
        raise HoshimemoSceneHookError("立绘缓存重置字节与状态隔离证据必须同时提供")
    cache_rearm_range: list[int] | None = None
    if cache_rearm_bytes:
        try:
            state_selector = int(state_isolation_report["selector"])
            restored_globals = [
                int(value) for value in state_isolation_report["source_global_ids"]
            ]
            cache_global_id = int(state_isolation_report["cache_global_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HoshimemoSceneHookError("立绘状态恢复证据字段无效") from exc
        if state_selector not in normalized_selectors:
            raise HoshimemoSceneHookError("立绘状态隔离 selector 不在清理集合中")
        if cache_global_id not in restored_globals:
            raise HoshimemoSceneHookError("立绘状态隔离缺少缓存 global")
        if str(state_isolation_report.get("restore_placement") or "") != (
            "after_custom_scene_before_original_replay"
        ):
            raise HoshimemoSceneHookError("立绘状态没有在主场景跳板中恢复")
        rearm_start = len(payload)
        payload.extend(cache_rearm_bytes)
        cache_rearm_range = [rearm_start, len(payload)]
    payload.extend(expected)
    payload.extend(_jump(return_offset))
    report = {
        "kind": kind,
        "selectors": list(normalized_selectors),
        "clear": {
            "performed": not restored_registration_handoff,
            "target": clear_target,
            "target_hex": f"0x{clear_target:X}",
            "argument_count": 2,
        },
        "restored_layout_apply_before_replay": {
            "enabled": restored_registration_handoff,
            "target": apply_target,
            "target_hex": f"0x{apply_target:X}",
            "arguments": list(nil_apply_arguments),
            "argument_count": apply_argument_count,
            "reason": (
                "preserve_nil_inherited_native_geometry"
                if restored_registration_handoff
                else None
            ),
        },
        "explicit_apply_before_replay": (
            explicit_apply or restored_registration_handoff
        ),
        "explicit_apply_reason": (
            "restored_native_layout_handoff"
            if restored_registration_handoff
            else (
                "zero_duration_selector_ownership_handoff"
                if kind == "portrait_registration"
                else ("pre_reset_selector_flush" if kind == "visual_reset" else None)
            )
        ),
        "explicit_apply_duration": (
            None
            if restored_registration_handoff
            else (
                0
                if kind == "portrait_registration"
                else (1 if explicit_apply else None)
            )
        ),
        "apply": {
            "target": apply_target,
            "target_hex": f"0x{apply_target:X}",
            "argument_count": apply_argument_count,
        },
        "registration_argument_count": (
            registration_argument_count
            if kind == "portrait_registration"
            else None
        ),
        "state_restore_before_replay": (
            {
                "enabled": False,
                "placement": "scene_trampoline_before_original_replay",
                "selector": int(state_isolation_report["selector"]),
                "source_global_ids": list(
                    state_isolation_report["source_global_ids"]
                ),
                "cache_global_id": int(state_isolation_report["cache_global_id"]),
            }
            if state_isolation_report is not None
            else {"enabled": False}
        ),
        "cache_rearm_before_native_replay": (
            {
                "enabled": True,
                "byte_range": cache_rearm_range,
                "byte_count": len(cache_rearm_bytes),
                "sha256": _sha256(cache_rearm_bytes),
                "selector": int(state_isolation_report["selector"]),
                "cache_global_id": int(state_isolation_report["cache_global_id"]),
                "value": None,
            }
            if state_isolation_report is not None
            else {"enabled": False}
        ),
        "patch_offset": patch_offset,
        "patch_offset_hex": f"0x{patch_offset:X}",
        "expected_hex": expected.hex(" "),
        "replayed_target": target,
        "replayed_target_hex": f"0x{target:X}",
        "return_offset": return_offset,
        "return_offset_hex": f"0x{return_offset:X}",
        "byte_count": len(payload),
    }
    return bytes(payload), report


def _namespace_portrait_plan(plan: Any, scene_id: str) -> Any:
    """Give one scene private clone/wrapper symbols without changing native symbols."""

    token = hashlib.sha256(str(scene_id).encode("utf-8")).hexdigest()[:16]
    prefix = f"story_scene::{token}::"
    clone_symbols = {
        clone.output_symbol: prefix + clone.output_symbol
        for clone in plan.dispatcher_clones
    }
    wrapper_symbols = {
        wrapper.symbol: prefix + wrapper.symbol for wrapper in plan.wrappers
    }
    clones = tuple(
        replace(clone, output_symbol=clone_symbols[clone.output_symbol])
        for clone in plan.dispatcher_clones
    )
    wrappers = tuple(
        replace(
            wrapper,
            symbol=wrapper_symbols[wrapper.symbol],
            dispatcher_symbol=clone_symbols.get(
                wrapper.dispatcher_symbol,
                wrapper.dispatcher_symbol,
            ),
        )
        for wrapper in plan.wrappers
    )
    operations: list[Mapping[str, Any]] = []
    for operation in plan.script_operations:
        item = dict(operation)
        symbol = item.get("symbol")
        if isinstance(symbol, str) and symbol in wrapper_symbols:
            item["symbol"] = wrapper_symbols[symbol]
        operations.append(item)
    return replace(
        plan,
        dispatcher_clones=clones,
        wrappers=wrappers,
        script_operations=tuple(operations),
    )


def _filter_reused_portrait_resources(
    plan: Any,
    payloads: Mapping[str, bytes],
    existing_payloads: Mapping[str, bytes],
) -> tuple[Any, dict[str, bytes], list[str]]:
    """Reuse only byte-identical prior additions; partial/conflicting pairs fail."""

    resources: list[Any] = []
    additions: dict[str, bytes] = {}
    reused: list[str] = []
    for resource in plan.resources:
        names = (resource.target_body_name, resource.target_face_name)
        present = [name in existing_payloads for name in names]
        if any(present) and not all(present):
            raise HoshimemoSceneHookError(
                f"跨场景立绘资源对只有一层已存在: {names[0]} / {names[1]}"
            )
        if all(present):
            for name in names:
                payload = payloads.get(name)
                if not isinstance(payload, bytes) or existing_payloads[name] != payload:
                    raise HoshimemoSceneHookError(
                        f"跨场景立绘资源名冲突且负载不同: {name}"
                    )
            reused.extend(names)
            continue
        resources.append(resource)
        for name in names:
            payload = payloads.get(name)
            if not isinstance(payload, bytes) or not payload:
                raise HoshimemoSceneHookError(f"立绘资源负载缺失: {name}")
            additions[name] = payload
    return replace(plan, resources=tuple(resources)), additions, sorted(reused)


def _dialogue_portrait_expression_states(
    cue: Mapping[str, Any],
    lines: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Resolve each line to an exact stable actor-id/frame state.

    Older projects have no ``actor_expressions`` field and intentionally fall
    back to the frozen cue.  Once the field exists it must cover every visible
    cue actor exactly; a stale actor ID cannot silently borrow another actor's
    body, face or transform.
    """

    actors = cue.get("actors")
    if not isinstance(actors, list):
        raise HoshimemoSceneHookError("剧情舞台角色快照必须是数组")
    visible = [
        actor
        for actor in actors
        if isinstance(actor, Mapping) and bool(actor.get("visible", True))
    ]
    actor_ids = [str(actor.get("actor_id") or "").strip() for actor in visible]
    if any(not actor_id for actor_id in actor_ids) or len(actor_ids) != len(set(actor_ids)):
        raise HoshimemoSceneHookError("剧情舞台角色缺少唯一稳定 actor_id")
    base_frames: dict[str, int] = {}
    allowed_frames: dict[str, set[int]] = {}
    for actor_id, actor in zip(actor_ids, visible):
        try:
            frame = int(actor.get("expression_frame", 0))
        except (TypeError, ValueError) as exc:
            raise HoshimemoSceneHookError(
                f"角色 {actor_id} 的冻结表情帧不是整数"
            ) from exc
        variant = actor.get("variant")
        expressions = variant.get("expressions") if isinstance(variant, Mapping) else None
        frames: set[int] = set()
        if isinstance(expressions, list):
            for item in expressions:
                if not isinstance(item, Mapping):
                    continue
                try:
                    frames.add(int(item.get("frame")))
                except (TypeError, ValueError):
                    continue
        if frames and frame not in frames:
            raise HoshimemoSceneHookError(
                f"角色 {actor_id} 的冻结表情帧 {frame} 不属于当前变体"
            )
        base_frames[actor_id] = frame
        allowed_frames[actor_id] = frames

    states_by_key: dict[tuple[tuple[str, int], ...], dict[str, Any]] = {}
    line_state_ids: list[str] = []
    source_lines: Sequence[Mapping[str, Any] | None] = lines or (None,)
    for index, line in enumerate(source_lines, 1):
        frames = dict(base_frames)
        legacy_fallback = line is None or "actor_expressions" not in line
        if line is not None and not legacy_fallback:
            raw = line.get("actor_expressions")
            if not isinstance(raw, list):
                raise HoshimemoSceneHookError(
                    f"新增台词 {index} 的逐句表情快照必须是数组"
                )
            parsed: dict[str, int] = {}
            for item in raw:
                if not isinstance(item, Mapping):
                    raise HoshimemoSceneHookError(
                        f"新增台词 {index} 的逐句表情快照含无效对象"
                    )
                actor_id = str(item.get("actor_id") or "").strip()
                if not actor_id or actor_id in parsed:
                    raise HoshimemoSceneHookError(
                        f"新增台词 {index} 的逐句表情 actor_id 缺失或重复"
                    )
                try:
                    frame = int(item.get("expression_frame"))
                except (TypeError, ValueError) as exc:
                    raise HoshimemoSceneHookError(
                        f"新增台词 {index} 的角色 {actor_id} 表情帧不是整数"
                    ) from exc
                if frame < 0:
                    raise HoshimemoSceneHookError(
                        f"新增台词 {index} 的角色 {actor_id} 表情帧不能为负数"
                    )
                parsed[actor_id] = frame
            if set(parsed) != set(actor_ids):
                raise HoshimemoSceneHookError(
                    f"新增台词 {index} 的逐句表情角色集合与冻结舞台不一致"
                )
            frames = parsed
        for actor_id, frame in frames.items():
            available = allowed_frames.get(actor_id, set())
            if available and frame not in available:
                raise HoshimemoSceneHookError(
                    f"新增台词 {index} 的角色 {actor_id} 不包含表情帧 {frame}"
                )
        key = tuple((actor_id, frames[actor_id]) for actor_id in actor_ids)
        state = states_by_key.get(key)
        if state is None:
            state_id = "portrait-expr-" + _canonical_sha256(
                {"actors": [{"actor_id": actor_id, "expression_frame": frame} for actor_id, frame in key]}
            )[:16]
            state = {
                "state_id": state_id,
                "actor_expressions": [
                    {"actor_id": actor_id, "expression_frame": frame}
                    for actor_id, frame in key
                ],
                "line_ids": [],
                "legacy_fallback": legacy_fallback,
            }
            states_by_key[key] = state
        elif not legacy_fallback:
            state["legacy_fallback"] = False
        if line is not None:
            line_id = str(line.get("line_id") or f"line-{index}")
            state["line_ids"].append(line_id)
            line_state_ids.append(str(state["state_id"]))
    return list(states_by_key.values()), line_state_ids


def _portrait_plan_for_expression_state(
    plan: Any,
    state: Mapping[str, Any],
    *,
    namespace_wrappers: bool,
) -> Any:
    """Derive a re-registration plan; only resource argument 4 may change."""

    frames = {
        str(item.get("actor_id") or ""): int(item.get("expression_frame"))
        for item in state.get("actor_expressions", ())
        if isinstance(item, Mapping)
    }
    wrapper_actor_ids = [str(wrapper.actor_id) for wrapper in plan.wrappers]
    if set(wrapper_actor_ids) != set(frames):
        raise HoshimemoSceneHookError("逐句表情状态与原生立绘包装函数角色集合不一致")
    token = str(state.get("state_id") or "").removeprefix("portrait-expr-")
    symbol_map: dict[str, str] = {}
    wrappers: list[Any] = []
    for wrapper in plan.wrappers:
        resource_args = list(wrapper.resource_args)
        if len(resource_args) != 4:
            raise HoshimemoSceneHookError("逐句表情切换仅支持已审核的 4 项资源参数")
        resource_args[3] = frames[str(wrapper.actor_id)]
        symbol = (
            f"{wrapper.symbol}::expression::{token}"
            if namespace_wrappers
            else wrapper.symbol
        )
        symbol_map[wrapper.symbol] = symbol
        wrappers.append(
            replace(wrapper, symbol=symbol, resource_args=tuple(resource_args))
        )
    operations: list[Mapping[str, Any]] = []
    for operation in plan.script_operations:
        item = dict(operation)
        symbol = item.get("symbol")
        if isinstance(symbol, str) and symbol in symbol_map:
            item["symbol"] = symbol_map[symbol]
        operations.append(item)
    return replace(
        plan,
        wrappers=tuple(wrappers),
        script_operations=tuple(operations),
    )


def _merge_portrait_expression_plans(plans: Sequence[Any]) -> Any:
    if not plans:
        raise HoshimemoSceneHookError("逐句表情没有可合并的立绘计划")
    if len(plans) == 1:
        return plans[0]
    first = plans[0]
    wrappers: list[Any] = []
    symbols: set[str] = set()
    for plan in plans:
        if (
            plan.profile != first.profile
            or plan.resources != first.resources
            or plan.dispatcher_clones != first.dispatcher_clones
        ):
            raise HoshimemoSceneHookError("逐句表情意外改变了立绘资源或 dispatcher 克隆")
        for wrapper in plan.wrappers:
            if wrapper.symbol in symbols:
                raise HoshimemoSceneHookError(
                    f"逐句表情生成了重复包装函数符号: {wrapper.symbol}"
                )
            symbols.add(wrapper.symbol)
            wrappers.append(wrapper)
    return replace(first, wrappers=tuple(wrappers))


def _flat_story_scene(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": str(item.get("schema") or "fvp-studio-v2.story-scene.v1"),
        "scene_id": str(item.get("scene_id") or ""),
        "title": str(item.get("title") or ""),
        "anchor": item.get("anchor"),
        "cue": item.get("cue"),
        "inserted_lines": item.get("inserted_lines") or [],
        "next_line_serial": int(item.get("next_line_serial") or 1),
        "revision": int(item.get("revision") or 0),
    }


def build_hoshimemo_scene_candidate(
    document: HcbDocument,
    profile: Any,
    story: Mapping[str, Any],
    *,
    duration_ms: int = 1000,
    target_graph: bytes | None = None,
    target_graph_bs: bytes | None = None,
    target_event_visual_archives: Mapping[str, bytes] | None = None,
    abi: HoshimemoSceneHookAbi = HOSHIMEMO_SCENE_HOOK_ABI,
    portrait_compile_target: Any | None = None,
    _base_candidate_hcb: bytes | None = None,
    _registered_prefix_hooks: Sequence[Mapping[str, Any]] = (),
    _portrait_namespace: str | None = None,
    _portrait_preflight_graph_bs: bytes | None = None,
    _portrait_plan_graph_bs: bytes | None = None,
    _portrait_existing_payloads: Mapping[str, bytes] | None = None,
    _resource_compile_cache: dict[str, Mapping[str, Any]] | None = None,
    _audio_bindings: Mapping[str, Mapping[str, Any]] | None = None,
) -> SceneHookCandidate:
    """Build one complete HCB candidate in memory without touching a path."""

    if not isinstance(story, Mapping):
        raise HoshimemoSceneHookError("剧情工程状态必须是对象")
    base_candidate_hcb = (
        document.original_bytes
        if _base_candidate_hcb is None
        else bytes(_base_candidate_hcb)
    )
    if len(base_candidate_hcb) < len(document.original_bytes):
        raise HoshimemoSceneHookError("组合候选 HCB 短于原始来源")
    anchor_value = story.get("anchor")
    cue = story.get("cue")
    lines = story.get("inserted_lines") or []
    if not isinstance(anchor_value, Mapping):
        raise HoshimemoSceneHookError("尚未选择剧情挂接点")
    if not isinstance(cue, Mapping):
        raise HoshimemoSceneHookError("尚未把当前舞台应用到所选台词")
    if not isinstance(lines, Sequence) or isinstance(lines, (str, bytes, bytearray)):
        raise HoshimemoSceneHookError("剧情新增台词必须是数组")
    if str(anchor_value.get("source_sha256") or "") != document.source_sha256:
        raise HoshimemoSceneHookError("来源 HCB 指纹已变化，请重新选择剧情台词")
    if str(anchor_value.get("index_fingerprint") or "") != str(
        getattr(profile, "index_fingerprint", "") or ""
    ):
        raise HoshimemoSceneHookError("项目对话索引已变化，请重新选择剧情台词")

    anchor = inspect_hoshimemo_dialogue_anchor(
        document,
        profile,
        int(anchor_value.get("hcb_offset")),
        str(anchor_value.get("timing") or ""),
        abi=abi,
    )
    if not anchor.get("safe"):
        raise HoshimemoSceneHookError(
            "挂接点复检失败：" + "；".join(anchor.get("reasons") or ["未知原因"])
        )
    if str(anchor_value.get("anchor_id") or "") != anchor["anchor_id"]:
        raise HoshimemoSceneHookError("剧情挂接身份已漂移，请重新选择台词")
    if str(cue.get("anchor_id") or "") != anchor["anchor_id"]:
        raise HoshimemoSceneHookError("舞台快照不属于当前剧情挂接点")
    visual_safety = anchor.get("visual_safety")
    if (
        isinstance(visual_safety, Mapping)
        and visual_safety.get("installable_visuals") is False
    ):
        raise HoshimemoSceneHookError(
            "该台词可作为对白定位点，但不能承载背景/立绘/CG："
            + str(visual_safety.get("reason") or "视觉挂接时序已被当前 profile 阻止")
            + "；请选择标记为已证明生命周期安全的台词"
        )
    compile_scope = str(cue.get("compile_scope") or "")
    if compile_scope not in {
        "native_background_and_dialogue",
        "native_background_portraits_and_dialogue",
        "native_event_visual_and_dialogue",
    }:
        raise HoshimemoSceneHookError("剧情构建范围不是受支持的统一场景快照")
    event_visual = (
        cue.get("event_visual")
        if isinstance(cue.get("event_visual"), Mapping)
        else None
    )
    if compile_scope == "native_event_visual_and_dialogue" and event_visual is None:
        raise HoshimemoSceneHookError("CG 场景快照缺少冻结 event_visual")
    if event_visual is not None and compile_scope != "native_event_visual_and_dialogue":
        raise HoshimemoSceneHookError("冻结 CG 与剧情构建范围不一致")
    actors = cue.get("actors") if isinstance(cue.get("actors"), list) else []
    visible_actors = [
        actor
        for actor in actors
        if (
            event_visual is None
            and isinstance(actor, Mapping)
            and bool(actor.get("visible", True))
        )
    ]
    portrait_archive_name: str | None = None
    if visible_actors:
        target_profile = getattr(portrait_compile_target, "target_profile", None)
        portrait_archive_name = str(
            getattr(target_profile, "portrait_archive_name", "") or ""
        ).strip()
        if portrait_archive_name not in {"graph.bin", "graph_bs.bin"}:
            raise HoshimemoSceneHookError(
                "舞台立绘目标没有受支持的原生角色资源归档"
            )
    if visible_actors and (
        not isinstance(target_graph_bs, bytes) or not target_graph_bs
    ):
        raise HoshimemoSceneHookError(
            "舞台含可见角色，统一 dry-run 必须提供当前目标角色资源归档"
        )
    background = cue.get("background")
    if event_visual is None and not isinstance(background, Mapping):
        raise HoshimemoSceneHookError("当前剧情快照没有背景")

    resource_archives: dict[str, bytes] = {}
    resource_archive_source_sha256: dict[str, str] = {}
    resource_archive_before_sizes: dict[str, int] = {}
    if (
        event_visual is None
        and isinstance(background, Mapping)
        and str(background.get("build_mode") or "").strip().casefold() == "copy_hzc"
    ):
        if not isinstance(target_graph, bytes) or not target_graph:
            raise HoshimemoSceneHookError(
                "跨游戏背景 dry-run 必须提供当前目标 graph.bin"
            )
        from .visual_scene_background_compile import (
            VisualSceneBackgroundCompileError,
            background_target_canvas_fingerprint,
            compile_visual_scene_background,
        )

        try:
            target_canvas_fingerprint = background_target_canvas_fingerprint(
                target_graph
            )
        except VisualSceneBackgroundCompileError as exc:
            raise HoshimemoSceneHookError(
                f"目标 graph.bin 无法确认原生背景画布: {exc}"
            ) from exc
        cache_key = (
            "background::"
            + _canonical_sha256(background)
            + "::"
            + target_canvas_fingerprint
        )
        cached_background = (
            _resource_compile_cache.get(cache_key)
            if _resource_compile_cache is not None
            else None
        )
        if isinstance(cached_background, Mapping):
            compiled_value = cached_background.get("compiled")
            if not isinstance(compiled_value, Mapping):
                raise HoshimemoSceneHookError("跨场景背景资源缓存损坏")
            background = dict(compiled_value)
            background["resource_compile"] = {
                **dict(background.get("resource_compile") or {}),
                "reused_from_prior_scene": True,
            }
        else:
            try:
                background_build = compile_visual_scene_background(
                    background,
                    target_graph,
                )
            except VisualSceneBackgroundCompileError as exc:
                raise HoshimemoSceneHookError(
                    f"跨游戏背景无法编译为原生 graph.bin 追加事务: {exc}"
                ) from exc
            compiled_background = dict(background)
            compiled_background.update(
                {
                    "target_archive_name": "graph.bin",
                    "target_resource_name": background_build.target_resource_name,
                    "runtime_blur_resource_name": (
                        background_build.runtime_blur_resource_name
                    ),
                    "resource_compile": dict(background_build.report),
                }
            )
            background = compiled_background
            resource_archives["graph.bin"] = background_build.graph
            resource_archive_source_sha256["graph.bin"] = (
                background_build.graph_source_sha256
            )
            resource_archive_before_sizes["graph.bin"] = len(target_graph)
            if _resource_compile_cache is not None:
                _resource_compile_cache[cache_key] = {
                    "compiled": dict(compiled_background),
                }

    if (
        isinstance(event_visual, Mapping)
        and str(event_visual.get("build_mode") or "").strip().casefold() == "copy_hzc"
    ):
        from .visual_scene_cg_compile import (
            VisualSceneCgCompileError,
            compile_visual_scene_cg,
        )

        archive_name = str(event_visual.get("archive_name") or "").strip().casefold()
        archive_inputs = target_event_visual_archives or {}
        target_event_archive = archive_inputs.get(archive_name)
        if not isinstance(target_event_archive, bytes) or not target_event_archive:
            raise HoshimemoSceneHookError(
                f"跨游戏 CG dry-run 必须提供当前目标 {archive_name or 'graph_vis*'}"
            )
        cache_key = "event_visual::" + _canonical_sha256(event_visual)
        cached_event_visual = (
            _resource_compile_cache.get(cache_key)
            if _resource_compile_cache is not None
            else None
        )
        if isinstance(cached_event_visual, Mapping):
            compiled_value = cached_event_visual.get("compiled")
            if not isinstance(compiled_value, Mapping):
                raise HoshimemoSceneHookError("跨场景 CG 资源缓存损坏")
            event_visual = dict(compiled_value)
            event_visual["resource_compile"] = {
                **dict(event_visual.get("resource_compile") or {}),
                "reused_from_prior_scene": True,
            }
        else:
            try:
                cg_build = compile_visual_scene_cg(event_visual, target_event_archive)
            except VisualSceneCgCompileError as exc:
                raise HoshimemoSceneHookError(
                    f"跨游戏 CG 无法编译为原生 {archive_name} 追加事务: {exc}"
                ) from exc
            compiled_event_visual = dict(event_visual)
            compiled_event_visual.update(
                {
                    "target_archive_name": cg_build.target_archive_name,
                    "target_resource_name": cg_build.target_resource_name,
                    "archive_selector": cg_build.archive_selector,
                    "resource_compile": dict(cg_build.report),
                }
            )
            event_visual = compiled_event_visual
            resource_archives[archive_name] = cg_build.archive
            resource_archive_source_sha256[archive_name] = (
                cg_build.archive_source_sha256
            )
            resource_archive_before_sizes[archive_name] = len(target_event_archive)
            if _resource_compile_cache is not None:
                _resource_compile_cache[cache_key] = {
                    "compiled": dict(compiled_event_visual),
                }

    analysis_document, analysis_report = resolve_hoshimemo_analysis_document(
        document,
        profile,
        expected_clean_sha256=abi.clean_source_sha256,
    )
    audio_bytes, audio_report = _compile_audio_cue(
        document,
        cue.get("audio") if isinstance(cue.get("audio"), Mapping) else None,
        abi,
        analysis_document=analysis_document,
        resolved_audio_bindings=_audio_bindings,
    )
    event_visual_report: dict[str, Any] | None = None
    if isinstance(event_visual, Mapping):
        visual_bytes, event_visual_report = _compile_event_visual(
            document,
            event_visual,
            duration_ms,
            abi,
            analysis_document=analysis_document,
        )
        background_report: dict[str, Any] = {
            "suppressed_by_event_visual": True,
            "frozen_background_present": isinstance(background, Mapping),
        }
    else:
        assert isinstance(background, Mapping)
        visual_bytes, background_report = _compile_native_background(
            document,
            background,
            duration_ms,
            abi,
            analysis_document=analysis_document,
        )
    patch = anchor.get("patch")
    if not isinstance(patch, Mapping):
        raise HoshimemoSceneHookError("剧情挂接缺少五字节补丁计划")
    patch_offset = int(patch["patch_offset"])
    expected = bytes.fromhex(str(patch["expected_hex"]))
    replay = bytes.fromhex(str(patch["replay_hex"]))
    return_offset = int(patch["return_offset"])
    replay_offset = int(patch["replay_offset"])
    replay_size = int(patch["replay_size"])
    source_replay = document.original_bytes[replay_offset : replay_offset + replay_size]
    if replay != source_replay:
        raise HoshimemoSceneHookError("需要重放的原指令字节已漂移")
    actual = document.original_bytes[patch_offset : patch_offset + 5]
    if len(expected) != 5 or actual != expected:
        raise HoshimemoSceneHookError(
            f"挂接点五字节漂移 @0x{patch_offset:X}: "
            f"预期 {expected.hex(' ')}, 实际 {actual.hex(' ')}"
        )

    portrait_build = None
    portrait_candidate = None
    portrait_inline_bytes = b""
    portrait_inline_validation: Mapping[str, Any] | None = None
    portrait_reapply_bytes = b""
    portrait_reapply_validation: Mapping[str, Any] | None = None
    portrait_before_line_bytes: dict[str, bytes] = {}
    portrait_after_print_by_line: dict[str, bytes] = {}
    portrait_expression_states_report: list[dict[str, Any]] = []
    portrait_expression_line_state_ids: list[str] = []
    portrait_cache_guard_bytes = b""
    portrait_cache_guard_report: dict[str, Any] | None = None
    (
        portrait_state_snapshot_template,
        portrait_state_restore_template,
        portrait_state_cache_rearm_template,
        portrait_state_template_report,
    ) = _portrait_state_isolation(portrait_compile_target, document)
    portrait_state_snapshot_bytes = b""
    portrait_state_restore_bytes = b""
    portrait_state_cache_rearm_bytes = b""
    portrait_state_report: dict[str, Any] | None = None
    portrait_pre_scene_clear_bytes = b""
    portrait_pre_scene_clear_report: dict[str, Any] | None = None
    portrait_source_print_offsets: tuple[int, ...] = ()
    graph_candidate: bytes | None = None
    graph_source_sha256: str | None = None
    lifecycle_cleanup_bytes = b""
    lifecycle_cleanup_report: dict[str, Any] | None = None
    portrait_resource_payloads: dict[str, bytes] = {}
    base_hcb = base_candidate_hcb
    if visible_actors:
        from .portrait_emitter import (
            PortraitEmitterError,
            emit_portrait_candidates,
            emit_portrait_script_program,
        )
        from .visual_scene_portrait_compile import (
            VisualScenePortraitCompileError,
            compile_visual_scene_portraits,
        )

        assert isinstance(target_graph_bs, bytes)
        assert portrait_archive_name is not None
        portrait_archive_base = resource_archives.get(
            portrait_archive_name,
            target_graph_bs,
        )
        plan_graph_bs = (
            _portrait_plan_graph_bs
            if isinstance(_portrait_plan_graph_bs, bytes)
            else portrait_archive_base
        )
        preflight_graph_bs = (
            _portrait_preflight_graph_bs
            if isinstance(_portrait_preflight_graph_bs, bytes)
            else plan_graph_bs
        )
        try:
            expression_states, portrait_expression_line_state_ids = (
                _dialogue_portrait_expression_states(cue, lines)
            )
            portrait_build = compile_visual_scene_portraits(
                cue,
                plan_graph_bs,
                target=portrait_compile_target,
            )
            portrait_resource_payloads = dict(portrait_build.resource_payloads)
            base_portrait_plan = portrait_build.plan
            base_expression_frames = {
                str(actor.get("actor_id") or ""): int(
                    actor.get("expression_frame", 0)
                )
                for actor in visible_actors
            }
            multiple_expression_states = len(expression_states) > 1
            expression_plans: dict[str, Any] = {}
            for state in expression_states:
                state_id = str(state["state_id"])
                state_frames = {
                    str(item["actor_id"]): int(item["expression_frame"])
                    for item in state["actor_expressions"]
                }
                if state_frames == base_expression_frames and not multiple_expression_states:
                    state_plan = base_portrait_plan
                else:
                    state_plan = _portrait_plan_for_expression_state(
                        base_portrait_plan,
                        state,
                        namespace_wrappers=multiple_expression_states,
                    )
                expression_plans[state_id] = state_plan
            portrait_plan = _merge_portrait_expression_plans(
                list(expression_plans.values())
            )
            append_payloads = dict(portrait_resource_payloads)
            reused_resource_names: list[str] = []
            plan_changed = portrait_plan != base_portrait_plan
            if _portrait_namespace:
                portrait_plan = _namespace_portrait_plan(
                    portrait_plan,
                    _portrait_namespace,
                )
                expression_plans = {
                    state_id: _namespace_portrait_plan(plan, _portrait_namespace)
                    for state_id, plan in expression_plans.items()
                }
                plan_changed = True
            if _portrait_existing_payloads is not None:
                portrait_plan, append_payloads, reused_resource_names = _filter_reused_portrait_resources(
                    portrait_plan,
                    portrait_resource_payloads,
                    _portrait_existing_payloads,
                )
                plan_changed = True
            portrait_report = copy.deepcopy(dict(portrait_build.report))
            initial_state_id = (
                portrait_expression_line_state_ids[0]
                if portrait_expression_line_state_ids
                else str(expression_states[0]["state_id"])
            )
            initial_frames = {
                str(item["actor_id"]): int(item["expression_frame"])
                for item in next(
                    state for state in expression_states
                    if str(state["state_id"]) == initial_state_id
                )["actor_expressions"]
            }
            actor_reports = portrait_report.get("actors")
            if isinstance(actor_reports, list):
                for actor_report in actor_reports:
                    if not isinstance(actor_report, dict):
                        continue
                    actor_id = str(actor_report.get("actor_id") or "")
                    if actor_id in initial_frames:
                        actor_report["expression_frame"] = initial_frames[actor_id]
            portrait_expression_states_report = [
                {
                    **copy.deepcopy(state),
                    "initial": str(state["state_id"]) == initial_state_id,
                    "wrapper_symbols": [
                        wrapper.symbol
                        for wrapper in getattr(
                            expression_plans[str(state["state_id"])],
                            "wrappers",
                            (),
                        )
                    ],
                }
                for state in expression_states
            ]
            portrait_report["dialogue_expression_states"] = copy.deepcopy(
                portrait_expression_states_report
            )
            portrait_report["dialogue_line_state_ids"] = list(
                portrait_expression_line_state_ids
            )
            if plan_changed:
                portrait_report.update(
                    {
                    "plan": portrait_plan.to_dict(),
                    "resource_names_appended": sorted(append_payloads),
                    "resource_names_reused": reused_resource_names,
                    "resource_payload_bytes_appended": sum(
                        len(payload) for payload in append_payloads.values()
                    ),
                    }
                )
            if plan_changed:
                portrait_build = replace(
                    portrait_build,
                    plan=portrait_plan,
                    resource_payloads=append_payloads,
                    report=portrait_report,
                )
            portrait_candidate = emit_portrait_candidates(
                portrait_build.plan,
                document.original_bytes,
                preflight_graph_bs,
                portrait_build.resource_payloads,
                base_hcb=base_candidate_hcb,
                base_graph_bs=portrait_archive_base,
            )
            portrait_programs = {
                state_id: emit_portrait_script_program(
                    state_plan,
                    portrait_candidate.symbols,
                )
                for state_id, state_plan in expression_plans.items()
            }
        except (VisualScenePortraitCompileError, PortraitEmitterError) as exc:
            raise HoshimemoSceneHookError(
                f"舞台立绘无法编译为原生场景事务: {exc}"
            ) from exc
        if portrait_candidate.validation.get("scene_hook") is not None:
            raise HoshimemoSceneHookError("统一场景的立绘函数库意外安装了独立剧情挂接")
        initial_state_id = (
            portrait_expression_line_state_ids[0]
            if portrait_expression_line_state_ids
            else str(expression_states[0]["state_id"])
        )
        portrait_program = portrait_programs[initial_state_id]
        portrait_program_bytes = portrait_program.data
        portrait_inline_validation = dict(portrait_program.validation)
        if not portrait_program_bytes:
            raise HoshimemoSceneHookError("立绘生成器没有返回可组合的脚本字节")
        portrait_reapply_by_state: dict[str, bytes] = {}
        portrait_reapply_validation_by_state: dict[str, dict[str, Any]] = {}
        for state_id, program in portrait_programs.items():
            if not program.data:
                raise HoshimemoSceneHookError(
                    f"逐句表情状态 {state_id} 没有可组合的脚本字节"
                )
            reapply, validation = _portrait_reapply_suffix(
                program.data,
                program.validation,
            )
            portrait_reapply_by_state[state_id] = reapply
            portrait_reapply_validation_by_state[state_id] = dict(validation)
        if len(set(portrait_reapply_by_state.values())) != 1:
            raise HoshimemoSceneHookError(
                "逐句表情切换意外改变了最终几何/透明度/旋转重应用程序"
            )
        final_state_id = (
            portrait_expression_line_state_ids[-1]
            if portrait_expression_line_state_ids
            else initial_state_id
        )
        portrait_reapply_bytes = portrait_reapply_by_state[final_state_id]
        portrait_reapply_validation = {
            **portrait_reapply_validation_by_state[final_state_id],
            "expression_state_id": final_state_id,
            "all_expression_state_ids": sorted(portrait_reapply_by_state),
            "all_states_share_identical_reapply": True,
        }
        portrait_cache_guard_bytes, portrait_cache_guard_report = (
            _portrait_cache_guard(portrait_compile_target)
        )
        if (
            portrait_cache_guard_report is not None
            and portrait_state_template_report is None
        ):
            raise HoshimemoSceneHookError(
                "目标立绘使用共享 selector 缓存，但缺少完整状态隔离证据"
            )
        if portrait_state_template_report is not None:
            portrait_state_snapshot_bytes = portrait_state_snapshot_template
            portrait_state_restore_bytes = portrait_state_restore_template
            portrait_state_cache_rearm_bytes = portrait_state_cache_rearm_template
            portrait_state_report = dict(portrait_state_template_report)
        previous_state_id = initial_state_id
        for index, line in enumerate(lines):
            line_id = str(line.get("line_id") or f"line-{index + 1}")
            state_id = portrait_expression_line_state_ids[index]
            if index > 0 and state_id != previous_state_id:
                portrait_before_line_bytes[line_id] = (
                    portrait_cache_guard_bytes + portrait_programs[state_id].data
                )
            portrait_after_print_by_line[line_id] = portrait_reapply_by_state[state_id]
            previous_state_id = state_id
        portrait_inline_bytes = portrait_cache_guard_bytes + portrait_program_bytes
        portrait_inline_validation = {
            **dict(portrait_inline_validation),
            "expression_state_id": initial_state_id,
            "dialogue_line_state_ids": list(portrait_expression_line_state_ids),
            "expression_state_count": len(expression_states),
            "transition_line_ids": sorted(portrait_before_line_bytes),
        }
        if (
            portrait_cache_guard_report is not None
            or portrait_state_report is not None
        ):
            portrait_inline_validation = {
                **dict(portrait_inline_validation),
                "cache_guard": (
                    dict(portrait_cache_guard_report)
                    if portrait_cache_guard_report is not None
                    else None
                ),
                "state_isolation": portrait_state_report,
                "unguarded_program_bytes": len(portrait_program_bytes),
                "guarded_program_bytes": len(portrait_inline_bytes),
            }
        base_hcb = portrait_candidate.hcb
        graph_candidate = portrait_candidate.graph_bs
        graph_source_sha256 = _sha256(preflight_graph_bs)
        resource_archives[portrait_archive_name] = graph_candidate
        resource_archive_source_sha256[
            portrait_archive_name
        ] = graph_source_sha256
        resource_archive_before_sizes[portrait_archive_name] = len(target_graph_bs)
        lifecycle_boundary = (
            visual_safety.get("lifecycle_boundary")
            if isinstance(visual_safety, Mapping)
            else None
        )
        if not isinstance(lifecycle_boundary, Mapping):
            raise HoshimemoSceneHookError(
                "含立绘的剧情候选缺少已证明可达的原生生命周期清理边界"
            )
        actor_reports = portrait_build.report.get("actors")
        if not isinstance(actor_reports, list):
            raise HoshimemoSceneHookError("立绘编译报告缺少 selector 分配")
        if len(actor_reports) != len(visible_actors):
            raise HoshimemoSceneHookError("立绘编译报告的 selector 数量与可见角色不一致")
        try:
            cleanup_selectors = [
                int(item["selector"])
                for item in actor_reports
                if isinstance(item, Mapping)
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise HoshimemoSceneHookError("立绘编译报告的 selector 分配无效") from exc
        if (
            len(cleanup_selectors) != len(actor_reports)
            or len(set(cleanup_selectors)) != len(cleanup_selectors)
        ):
            raise HoshimemoSceneHookError("立绘编译报告的 selector 分配缺失或重复")
        (
            portrait_pre_scene_clear_bytes,
            portrait_pre_scene_clear_report,
        ) = _compile_portrait_pre_scene_clear(
            portrait_compile_target,
            document,
            analysis_document,
            cleanup_selectors,
            abi,
        )
        lifecycle_cleanup_bytes, lifecycle_cleanup_report = (
            _compile_portrait_lifecycle_cleanup(
                document,
                analysis_document,
                cleanup_selectors,
                lifecycle_boundary,
                abi,
                cache_rearm_bytes=portrait_state_cache_rearm_bytes,
                state_isolation_report=portrait_state_report,
            )
        )
        portrait_source_print_offsets = _portrait_source_print_call_sites(
            document,
            analysis_document,
            start=return_offset,
            end=int(lifecycle_cleanup_report["patch_offset"]),
            print_target=abi.print_target,
        )

    dialogue_bytes, dialogue_report = _compile_inserted_dialogue(
        document,
        profile,
        lines,
        abi,
        analysis_document=analysis_document,
        after_print_bytes=portrait_reapply_bytes,
        before_line_bytes=portrait_before_line_bytes,
        after_print_bytes_by_line=portrait_after_print_by_line,
    )

    # Snapshot the inherited selector state first, then use the target game's
    # own clear/apply sequence before audio or visual changes can render a
    # stale native portrait.  The custom portrait is emitted only after the
    # background/CG transition.  Pop the snapshot back before control returns
    # to untouched source flow; the later lifecycle hook re-applies that
    # restored layout rather than deleting Nil-inherited geometry.
    custom = (
        portrait_state_snapshot_bytes
        + portrait_pre_scene_clear_bytes
        + audio_bytes
        + visual_bytes
        + portrait_inline_bytes
        + dialogue_bytes
        + portrait_state_restore_bytes
    )
    if patch.get("replay_order") == "custom_then_original":
        program_without_return = custom + replay
        portrait_state_snapshot_relative_start = 0
        portrait_pre_scene_clear_relative_start = len(
            portrait_state_snapshot_bytes
        )
        portrait_inline_relative_start = (
            len(portrait_state_snapshot_bytes)
            + len(portrait_pre_scene_clear_bytes)
            + len(audio_bytes)
            + len(visual_bytes)
        )
        dialogue_relative_start = (
            portrait_inline_relative_start + len(portrait_inline_bytes)
        )
        portrait_state_restore_relative_start = (
            dialogue_relative_start + len(dialogue_bytes)
        )
    elif patch.get("replay_order") == "original_then_custom":
        program_without_return = replay + custom
        portrait_state_snapshot_relative_start = len(replay)
        portrait_pre_scene_clear_relative_start = (
            len(replay) + len(portrait_state_snapshot_bytes)
        )
        portrait_inline_relative_start = (
            len(replay)
            + len(portrait_state_snapshot_bytes)
            + len(portrait_pre_scene_clear_bytes)
            + len(audio_bytes)
            + len(visual_bytes)
        )
        dialogue_relative_start = (
            portrait_inline_relative_start + len(portrait_inline_bytes)
        )
        portrait_state_restore_relative_start = (
            dialogue_relative_start + len(dialogue_bytes)
        )
    else:
        raise HoshimemoSceneHookError("剧情挂接的原指令重放顺序无效")
    candidate = bytearray(base_hcb)
    # The resource emitter leaves the source story untouched.  The unified
    # scene owns the main jump; imported portraits also wrap each exact native
    # print CALL before the proven cleanup boundary so function_4338_'s refresh
    # cannot discard the authored stage geometry on the following source lines.
    if bytes(candidate[patch_offset : patch_offset + 5]) != expected:
        raise HoshimemoSceneHookError(
            f"组合候选的挂接窗口已被其他场景占用 @0x{patch_offset:X}"
        )
    candidate[patch_offset : patch_offset + 5] = expected
    portrait_print_wrapper_bytes = b""
    portrait_print_wrapper_start: int | None = None
    portrait_source_refresh_report: dict[str, Any] | None = None
    if portrait_source_print_offsets:
        expected_print_call = _call(abi.print_target)
        for offset in portrait_source_print_offsets:
            if bytes(candidate[offset : offset + 5]) != expected_print_call:
                raise HoshimemoSceneHookError(
                    f"追加原文台词立绘刷新前，CALL 五字节已漂移 @0x{offset:X}"
                )
        portrait_print_wrapper_bytes = _compile_portrait_print_wrapper(
            abi.print_target,
            portrait_reapply_bytes,
            abi.print_argument_count,
        )
        portrait_print_wrapper_start = len(candidate)
        candidate.extend(portrait_print_wrapper_bytes)
        replacement = _call(portrait_print_wrapper_start)
        for offset in portrait_source_print_offsets:
            candidate[offset : offset + 5] = replacement
        portrait_source_refresh_report = {
            "schema": "fvp-studio-v2.portrait-source-dialogue-refresh.v1",
            "passed": True,
            "native_print_target": abi.print_target,
            "native_print_target_hex": f"0x{abi.print_target:X}",
            "wrapper_argument_count": abi.print_argument_count,
            "wrapper_range": [
                portrait_print_wrapper_start,
                portrait_print_wrapper_start + len(portrait_print_wrapper_bytes),
            ],
            "wrapper_sha256": _sha256(portrait_print_wrapper_bytes),
            "reapply_sha256": _sha256(portrait_reapply_bytes),
            "call_sites": [
                {
                    "patch_offset": offset,
                    "patch_offset_hex": f"0x{offset:X}",
                    "expected_hex": expected_print_call.hex(" "),
                    "patched_hex": replacement.hex(" "),
                }
                for offset in portrait_source_print_offsets
            ],
        }
    trampoline_start = len(candidate)
    replay_terminal = bool(patch.get("replay_terminal", False))
    if replay_terminal:
        if patch.get("replay_order") != "custom_then_original":
            raise HoshimemoSceneHookError("终止型翻译跳转只能在自定义内容之后重放")
        trampoline = program_without_return
    else:
        trampoline = program_without_return + _jump(return_offset)
    candidate.extend(trampoline)
    candidate[patch_offset : patch_offset + 5] = _jump(trampoline_start)
    portrait_inline_range = (
        [
            trampoline_start + portrait_inline_relative_start,
            trampoline_start + portrait_inline_relative_start + len(portrait_inline_bytes),
        ]
        if portrait_inline_bytes
        else None
    )
    portrait_state_snapshot_range = (
        [
            trampoline_start + portrait_state_snapshot_relative_start,
            trampoline_start
            + portrait_state_snapshot_relative_start
            + len(portrait_state_snapshot_bytes),
        ]
        if portrait_state_snapshot_bytes
        else None
    )
    portrait_pre_scene_clear_range = (
        [
            trampoline_start + portrait_pre_scene_clear_relative_start,
            trampoline_start
            + portrait_pre_scene_clear_relative_start
            + len(portrait_pre_scene_clear_bytes),
        ]
        if portrait_pre_scene_clear_bytes
        else None
    )
    portrait_state_restore_range = (
        [
            trampoline_start + portrait_state_restore_relative_start,
            trampoline_start
            + portrait_state_restore_relative_start
            + len(portrait_state_restore_bytes),
        ]
        if portrait_state_restore_bytes
        else None
    )
    portrait_dialogue_transition_ranges: list[list[int]] = []
    portrait_dialogue_reapply_ranges: list[list[int]] = []
    for line_report in dialogue_report:
        transition_range = line_report.get("portrait_transition_range")
        if isinstance(transition_range, list) and len(transition_range) == 2:
            absolute_transition_range = [
                trampoline_start + dialogue_relative_start + int(transition_range[0]),
                trampoline_start + dialogue_relative_start + int(transition_range[1]),
            ]
            line_report["portrait_transition_absolute_range"] = (
                absolute_transition_range
            )
            portrait_dialogue_transition_ranges.append(absolute_transition_range)
        relative_range = line_report.get("portrait_reapply_range")
        if isinstance(relative_range, list) and len(relative_range) == 2:
            absolute_range = [
                trampoline_start + dialogue_relative_start + int(relative_range[0]),
                trampoline_start + dialogue_relative_start + int(relative_range[1]),
            ]
            line_report["portrait_reapply_absolute_range"] = absolute_range
            portrait_dialogue_reapply_ranges.append(absolute_range)

    if lifecycle_cleanup_report is not None:
        cleanup_patch_offset = int(lifecycle_cleanup_report["patch_offset"])
        cleanup_expected = bytes.fromhex(
            str(lifecycle_cleanup_report["expected_hex"])
        )
        if candidate[cleanup_patch_offset : cleanup_patch_offset + 5] != cleanup_expected:
            raise HoshimemoSceneHookError("追加生命周期清理前，原生边界五字节已漂移")
        cleanup_trampoline_start = len(candidate)
        candidate.extend(lifecycle_cleanup_bytes)
        candidate[cleanup_patch_offset : cleanup_patch_offset + 5] = _jump(
            cleanup_trampoline_start
        )
        lifecycle_cleanup_report.update(
            {
                "patched_hex": bytes(
                    candidate[cleanup_patch_offset : cleanup_patch_offset + 5]
                ).hex(" "),
                "trampoline_range": [
                    cleanup_trampoline_start,
                    cleanup_trampoline_start + len(lifecycle_cleanup_bytes),
                ],
                "trampoline_sha256": _sha256(lifecycle_cleanup_bytes),
            }
        )

    restored_prefix = bytearray(candidate[: len(document.original_bytes)])
    for registered in _registered_prefix_hooks:
        registered_offset = int(registered.get("patch_offset", -1))
        registered_expected_value = registered.get("expected")
        if isinstance(registered_expected_value, bytes):
            registered_expected = registered_expected_value
        else:
            registered_expected = bytes.fromhex(
                str(registered.get("expected_hex") or "")
            )
        if registered_offset < 0 or len(registered_expected) != 5:
            raise HoshimemoSceneHookError("组合候选含无效的既有挂接登记")
        restored_prefix[
            registered_offset : registered_offset + 5
        ] = registered_expected
    restored_prefix[patch_offset : patch_offset + 5] = expected
    if portrait_source_refresh_report is not None:
        for call_site in portrait_source_refresh_report["call_sites"]:
            source_print_offset = int(call_site["patch_offset"])
            restored_prefix[source_print_offset : source_print_offset + 5] = (
                bytes.fromhex(str(call_site["expected_hex"]))
            )
    if lifecycle_cleanup_report is not None:
        cleanup_patch_offset = int(lifecycle_cleanup_report["patch_offset"])
        restored_prefix[cleanup_patch_offset : cleanup_patch_offset + 5] = bytes.fromhex(
            str(lifecycle_cleanup_report["expected_hex"])
        )
    if bytes(restored_prefix) != document.original_bytes:
        raise HoshimemoSceneHookError("生成器改变了已登记挂接点之外的原 HCB 字节")

    candidate_bytes = bytes(candidate)
    plan_identity = {
        "story_revision": int(story.get("revision") or 0),
        "scene_id": str(story.get("scene_id") or ""),
        "scene_title": str(story.get("title") or ""),
        "anchor_id": anchor["anchor_id"],
        "cue_id": str(cue.get("cue_id") or ""),
        "background": background_report,
        "event_visual": event_visual_report,
        "audio": audio_report,
        "dialogue_lines": dialogue_report,
        "portraits": (
            dict(portrait_build.report) if portrait_build is not None else None
        ),
        "portrait_inline": portrait_inline_validation,
        "portrait_state_isolation": portrait_state_report,
        "portrait_pre_scene_clear": portrait_pre_scene_clear_report,
        "portrait_dialogue_reapply": portrait_reapply_validation,
        "portrait_expression_states": portrait_expression_states_report,
        "portrait_expression_line_state_ids": portrait_expression_line_state_ids,
        "portrait_source_dialogue_refresh": portrait_source_refresh_report,
        "portrait_lifecycle_cleanup": lifecycle_cleanup_report,
        "duration_ms": int(duration_ms),
    }
    report: dict[str, Any] = {
        "schema": HOOK_REPORT_SCHEMA,
        "emitter_id": HOOK_EMITTER_ID,
        "passed": True,
        "dry_run_passed": True,
        # The byte candidate has passed the exact source, anchor, ABI and
        # return-path gates.  Installation still requires the separate
        # isolated-copy transaction to match the runtime-active target HCB.
        "install_ready": True,
        "transaction_mode": (
            "resource_archives_and_hcb" if resource_archives else "hcb_only"
        ),
        "profile_id": abi.profile_id,
        "plan_sha256": _canonical_sha256(plan_identity),
        "source": {
            "hcb_sha256": document.source_sha256,
            "hcb_size": len(document.original_bytes),
            "path": str(document.path) if document.path is not None else None,
            "index_fingerprint": str(getattr(profile, "index_fingerprint", "") or ""),
            "analysis_mode": analysis_report.get("mode"),
            "analysis_hcb_sha256": analysis_document.source_sha256,
            "analysis_path": (
                str(analysis_document.path) if analysis_document.path is not None else None
            ),
            "graph_bs_sha256": graph_source_sha256,
            "resource_archives": {
                name: {
                    "size": resource_archive_before_sizes[name],
                    "sha256": resource_archive_source_sha256[name],
                }
                for name in sorted(resource_archives)
            },
        },
        "anchor": anchor,
        "background": background_report,
        "event_visual": event_visual_report,
        "audio": audio_report,
        "inserted_dialogue": dialogue_report,
        "runtime_text_bridge": _runtime_text_bridge_report(
            abi.runtime_text_bridge
        ),
        "hook": {
            "patch_offset": patch_offset,
            "patch_offset_hex": f"0x{patch_offset:X}",
            "expected_hex": expected.hex(" "),
            "patched_hex": bytes(candidate[patch_offset : patch_offset + 5]).hex(" "),
            "replay_order": patch["replay_order"],
            "hook_mode": patch.get("hook_mode"),
            "replay_hex": replay.hex(" "),
            "replay_terminal": replay_terminal,
            "source_dialogue_mode": patch.get("source_dialogue_mode"),
            "source_redirect_target": patch.get("source_redirect_target"),
            "source_redirect_target_hex": patch.get("source_redirect_target_hex"),
            "return_offset": return_offset,
            "return_offset_hex": f"0x{return_offset:X}",
            "trampoline_range": [trampoline_start, trampoline_start + len(trampoline)],
            "trampoline_sha256": _sha256(trampoline),
            "portrait_emission_mode": (
                "inline_with_post_print_reapply" if portrait_inline_bytes else None
            ),
            "portrait_inline_range": portrait_inline_range,
            "portrait_inline_sha256": (
                _sha256(portrait_inline_bytes) if portrait_inline_bytes else None
            ),
            "portrait_inline_byte_count": len(portrait_inline_bytes),
            "portrait_reapply_validation": portrait_reapply_validation,
            "portrait_cache_guard": portrait_cache_guard_report,
            "portrait_state_isolation": portrait_state_report,
            "portrait_state_snapshot_range": portrait_state_snapshot_range,
            "portrait_pre_scene_clear": portrait_pre_scene_clear_report,
            "portrait_pre_scene_clear_range": portrait_pre_scene_clear_range,
            "portrait_state_restore_range": portrait_state_restore_range,
            "portrait_dialogue_transition_ranges": portrait_dialogue_transition_ranges,
            "portrait_dialogue_transition_count": len(
                portrait_dialogue_transition_ranges
            ),
            "portrait_dialogue_reapply_ranges": portrait_dialogue_reapply_ranges,
            "portrait_dialogue_reapply_count": len(
                portrait_dialogue_reapply_ranges
            ),
            "portrait_source_refresh": portrait_source_refresh_report,
            "portrait_subroutine_entry": None,
            "portrait_subroutine_entry_hex": None,
            "patch_count": (
                1
                + len(portrait_source_print_offsets)
                + int(lifecycle_cleanup_report is not None)
            ),
            "lifecycle_cleanup": lifecycle_cleanup_report,
        },
        "portraits": {
            "actor_count": len(actors),
            "visible_actor_count": len(visible_actors),
            "actors_emitted": bool(visible_actors),
            "suppressed_by_event_visual": event_visual_report is not None,
            "dialogue_expression_states": portrait_expression_states_report,
            "dialogue_expression_line_state_ids": portrait_expression_line_state_ids,
            "compile": (
                dict(portrait_build.report) if portrait_build is not None else None
            ),
            "emitter_validation": (
                {
                    **dict(portrait_candidate.validation),
                    "unified_scene_inline": dict(portrait_inline_validation or {}),
                    "dialogue_reapply": dict(portrait_reapply_validation or {}),
                    "composed_install_ready": True,
                }
                if portrait_candidate is not None
                else None
            ),
        },
        "deferred": {
            "actor_count": len(actors),
            "actors_emitted": bool(visible_actors),
            "reason": (
                "原生 CG 为全屏事件视觉，本 cue 不重复编译其下方立绘"
                if event_visual_report is not None
                else (
                    "所有可见舞台角色已编译到统一 graph_bs + HCB 事务"
                    if visible_actors
                    else "舞台快照没有可见角色，无需生成立绘资源"
                )
            ),
        },
        "output": {
            "hcb_sha256": _sha256(candidate_bytes),
            "hcb_size": len(candidate_bytes),
            "appended_bytes": len(candidate_bytes) - len(document.original_bytes),
            "scene_trampoline_bytes": len(trampoline),
            "audio_cue_bytes": len(audio_bytes),
            "portrait_print_wrapper_bytes": len(portrait_print_wrapper_bytes),
            "portrait_reapply_bytes_each": len(portrait_reapply_bytes),
            "portrait_dialogue_transition_bytes": sum(
                len(payload) for payload in portrait_before_line_bytes.values()
            ),
            "portrait_cache_guard_bytes": len(portrait_cache_guard_bytes),
            "portrait_state_snapshot_bytes": len(portrait_state_snapshot_bytes),
            "portrait_pre_scene_clear_bytes": len(
                portrait_pre_scene_clear_bytes
            ),
            "portrait_state_restore_bytes": len(portrait_state_restore_bytes),
            "portrait_state_cache_rearm_bytes": len(
                portrait_state_cache_rearm_bytes
            ),
            "lifecycle_cleanup_bytes": len(lifecycle_cleanup_bytes),
            "graph_bs_sha256": (
                _sha256(graph_candidate) if graph_candidate is not None else None
            ),
            "graph_bs_size": (
                len(graph_candidate) if graph_candidate is not None else None
            ),
            "graph_bs_added_bytes": (
                None
                if graph_candidate is None or target_graph_bs is None
                else len(graph_candidate) - len(target_graph_bs)
            ),
            "portrait_archive_name": portrait_archive_name,
            "resource_archives": {
                name: {
                    "size": len(payload),
                    "sha256": _sha256(payload),
                    "added_bytes": (
                        len(payload) - resource_archive_before_sizes[name]
                    ),
                }
                for name, payload in sorted(resource_archives.items())
            },
            "original_prefix_unchanged_except_hook": True,
            "original_prefix_unchanged_except_registered_hooks": True,
        },
    }
    json.dumps(report, ensure_ascii=False, sort_keys=True)
    return SceneHookCandidate(
        hcb=candidate_bytes,
        report=report,
        install_ready=True,
        graph_bs=(
            graph_candidate
            if portrait_archive_name == "graph_bs.bin"
            else None
        ),
        graph_bs_source_sha256=(
            graph_source_sha256
            if portrait_archive_name == "graph_bs.bin"
            else None
        ),
        resource_archives=dict(resource_archives),
        resource_archive_source_sha256=dict(resource_archive_source_sha256),
        portrait_resource_payloads=dict(portrait_resource_payloads),
    )


def _attach_audio_resource_build(
    candidate: SceneHookCandidate,
    audio_build: Any | None,
) -> SceneHookCandidate:
    if audio_build is None:
        return candidate
    bindings = dict(getattr(audio_build, "bindings", {}) or {})
    files = {
        str(name).casefold(): Path(path).expanduser().resolve()
        for name, path in dict(
            getattr(audio_build, "resource_archive_files", {}) or {}
        ).items()
    }
    sources = {
        str(name).casefold(): str(value).casefold()
        for name, value in dict(
            getattr(audio_build, "resource_archive_source_sha256", {}) or {}
        ).items()
    }
    audio_report = dict(getattr(audio_build, "report", {}) or {})
    if not bindings or not files or set(files) != set(sources):
        raise HoshimemoSceneHookError("项目音频构建结果不完整")
    if set(files).intersection(candidate.resource_archives) or set(files).intersection(
        candidate.resource_archive_files
    ):
        raise HoshimemoSceneHookError("项目音频归档与视觉资源候选发生重名")
    archives_report = (
        audio_report.get("archives")
        if isinstance(audio_report.get("archives"), Mapping)
        else {}
    )
    report = json.loads(json.dumps(candidate.report, ensure_ascii=False))
    source = report.setdefault("source", {})
    output = report.setdefault("output", {})
    source_archives = source.setdefault("resource_archives", {})
    output_archives = output.setdefault("resource_archives", {})
    for name, path in sorted(files.items()):
        record = archives_report.get(name)
        if not isinstance(record, Mapping):
            raise HoshimemoSceneHookError(f"项目音频构建缺少 {name} 审计记录")
        source_hash = str(record.get("source_sha256") or "").casefold()
        output_hash = str(record.get("output_sha256") or "").casefold()
        try:
            source_size = int(record.get("source_size"))
            output_size = int(record.get("output_size"))
        except (TypeError, ValueError) as exc:
            raise HoshimemoSceneHookError(
                f"项目音频构建 {name} 大小记录无效"
            ) from exc
        if source_hash != sources[name]:
            raise HoshimemoSceneHookError(f"项目音频构建 {name} 源哈希不一致")
        if not path.is_file() or _sha256_file(path) != output_hash:
            raise HoshimemoSceneHookError(f"项目音频构建 {name} 文件已漂移")
        if path.stat().st_size != output_size:
            raise HoshimemoSceneHookError(f"项目音频构建 {name} 大小已漂移")
        source_archives[name] = {"size": source_size, "sha256": source_hash}
        output_archives[name] = {
            "size": output_size,
            "sha256": output_hash,
            "added_bytes": output_size - source_size,
        }
    prior_plan = str(report.get("plan_sha256") or "")
    report["plan_sha256"] = _canonical_sha256(
        {
            "scene_plan_sha256": prior_plan,
            "audio_plan_sha256": str(audio_report.get("plan_sha256") or ""),
        }
    )
    report["transaction_mode"] = "resource_archives_and_hcb"
    report["audio_resources"] = audio_report
    output["audio_resource_archive_count"] = len(files)
    json.dumps(report, ensure_ascii=False, sort_keys=True)
    return replace(
        candidate,
        report=report,
        resource_archive_files={
            **dict(candidate.resource_archive_files),
            **files,
        },
        resource_archive_source_sha256={
            **dict(candidate.resource_archive_source_sha256),
            **sources,
        },
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_hoshimemo_story_project_candidate(
    document: HcbDocument,
    profile: Any,
    story: Mapping[str, Any],
    *,
    duration_ms: int = 1000,
    target_graph: bytes | None = None,
    target_graph_bs: bytes | None = None,
    target_event_visual_archives: Mapping[str, bytes] | None = None,
    target_audio_build: Any | None = None,
    abi: HoshimemoSceneHookAbi = HOSHIMEMO_SCENE_HOOK_ABI,
    portrait_compile_target: Any | None = None,
) -> SceneHookCandidate:
    """Compile every complete story scene into one deterministic transaction."""

    from .visual_scene_project import (
        VisualSceneProjectError,
        buildable_story_scenes,
    )

    try:
        scenes = buildable_story_scenes(story)
    except VisualSceneProjectError as exc:
        raise HoshimemoSceneHookError(str(exc)) from exc
    audio_bindings = dict(getattr(target_audio_build, "bindings", {}) or {})
    if len(scenes) == 1:
        candidate = build_hoshimemo_scene_candidate(
            document,
            profile,
            _flat_story_scene(scenes[0]),
            duration_ms=duration_ms,
            target_graph=target_graph,
            target_graph_bs=target_graph_bs,
            target_event_visual_archives=target_event_visual_archives,
            abi=abi,
            portrait_compile_target=portrait_compile_target,
            _audio_bindings=audio_bindings,
        )
        return _attach_audio_resource_build(candidate, target_audio_build)

    # Re-inspect every live anchor before allocating EOF bytes.  Register main
    # and lifecycle windows together so no later scene can silently overwrite
    # an earlier five-byte patch (including partial overlap).
    patch_windows: list[dict[str, Any]] = []

    def register_window(
        patch_offset: int,
        expected_hex: str,
        owner: str,
        kind: str,
    ) -> None:
        expected = bytes.fromhex(expected_hex)
        if len(expected) != 5:
            raise HoshimemoSceneHookError(f"{owner} 的 {kind} 不是五字节窗口")
        start = int(patch_offset)
        end = start + 5
        for prior in patch_windows:
            if start < int(prior["end"]) and end > int(prior["start"]):
                raise HoshimemoSceneHookError(
                    "多场景挂接窗口重叠："
                    f"{prior['owner']} {prior['kind']} "
                    f"0x{int(prior['start']):X}-0x{int(prior['end']):X} 与 "
                    f"{owner} {kind} 0x{start:X}-0x{end:X}"
                )
        patch_windows.append(
            {
                "patch_offset": start,
                "start": start,
                "end": end,
                "expected": expected,
                "expected_hex": expected.hex(" "),
                "owner": owner,
                "kind": kind,
            }
        )

    for item in scenes:
        flat = _flat_story_scene(item)
        anchor_value = flat.get("anchor")
        cue = flat.get("cue")
        assert isinstance(anchor_value, Mapping)
        assert isinstance(cue, Mapping)
        fresh_anchor = inspect_hoshimemo_dialogue_anchor(
            document,
            profile,
            int(anchor_value.get("hcb_offset")),
            str(anchor_value.get("timing") or ""),
            abi=abi,
        )
        patch = fresh_anchor.get("patch")
        if not fresh_anchor.get("safe") or not isinstance(patch, Mapping):
            raise HoshimemoSceneHookError(
                f"剧情场景 {flat['title']} 的挂接点复检失败"
            )
        register_window(
            int(patch["patch_offset"]),
            str(patch["expected_hex"]),
            str(flat["title"] or flat["scene_id"]),
            "main",
        )
        event_visual = cue.get("event_visual")
        actors = cue.get("actors") if isinstance(cue.get("actors"), list) else []
        visible = [
            actor
            for actor in actors
            if (
                not isinstance(event_visual, Mapping)
                and isinstance(actor, Mapping)
                and bool(actor.get("visible", True))
            )
        ]
        if visible:
            visual_safety = fresh_anchor.get("visual_safety")
            boundary = (
                visual_safety.get("lifecycle_boundary")
                if isinstance(visual_safety, Mapping)
                else None
            )
            if not isinstance(boundary, Mapping):
                raise HoshimemoSceneHookError(
                    f"剧情场景 {flat['title']} 缺少立绘生命周期清理边界"
                )
            register_window(
                int(boundary["patch_offset"]),
                str(boundary["expected_hex"]),
                str(flat["title"] or flat["scene_id"]),
                "lifecycle",
            )
            source_print_offsets = _portrait_source_print_call_sites(
                document,
                document,
                start=int(patch["return_offset"]),
                end=int(boundary["patch_offset"]),
                print_target=abi.print_target,
            )
            for source_print_offset in source_print_offsets:
                register_window(
                    source_print_offset,
                    _call(abi.print_target).hex(" "),
                    str(flat["title"] or flat["scene_id"]),
                    "portrait-dialogue-refresh",
                )

    original_graph = target_graph
    original_graph_bs = target_graph_bs
    original_event_archives = dict(target_event_visual_archives or {})
    current_graph = target_graph
    current_graph_bs = target_graph_bs
    current_event_archives = dict(original_event_archives)
    current_hcb = document.original_bytes
    registered_hooks: list[Mapping[str, Any]] = []
    portrait_payloads: dict[str, bytes] = {}
    resource_compile_cache: dict[str, Mapping[str, Any]] = {}
    scene_reports: list[dict[str, Any]] = []

    for item in scenes:
        flat = _flat_story_scene(item)
        candidate = build_hoshimemo_scene_candidate(
            document,
            profile,
            flat,
            duration_ms=duration_ms,
            target_graph=current_graph,
            target_graph_bs=current_graph_bs,
            target_event_visual_archives=current_event_archives,
            abi=abi,
            portrait_compile_target=portrait_compile_target,
            _base_candidate_hcb=current_hcb,
            _registered_prefix_hooks=registered_hooks,
            _portrait_namespace=str(flat["scene_id"]),
            _portrait_preflight_graph_bs=original_graph_bs,
            _portrait_plan_graph_bs=original_graph_bs,
            _portrait_existing_payloads=portrait_payloads,
            _resource_compile_cache=resource_compile_cache,
            _audio_bindings=audio_bindings,
        )
        current_hcb = candidate.hcb
        for name, payload in candidate.resource_archives.items():
            archive_name = str(name).casefold()
            if archive_name == "graph.bin":
                current_graph = payload
            elif archive_name == "graph_bs.bin":
                current_graph_bs = payload
            else:
                current_event_archives[archive_name] = payload
        for name, payload in candidate.portrait_resource_payloads.items():
            prior = portrait_payloads.get(name)
            if prior is not None and prior != payload:
                raise HoshimemoSceneHookError(
                    f"跨场景立绘资源 {name} 出现不同负载"
                )
            portrait_payloads[name] = payload
        hook = candidate.report.get("hook")
        if not isinstance(hook, Mapping):
            raise HoshimemoSceneHookError("单场景候选缺少挂接报告")
        registered_hooks.append(
            {
                "patch_offset": int(hook["patch_offset"]),
                "expected_hex": str(hook["expected_hex"]),
            }
        )
        cleanup = hook.get("lifecycle_cleanup")
        if isinstance(cleanup, Mapping):
            registered_hooks.append(
                {
                    "patch_offset": int(cleanup["patch_offset"]),
                    "expected_hex": str(cleanup["expected_hex"]),
                }
            )
        source_refresh = hook.get("portrait_source_refresh")
        if isinstance(source_refresh, Mapping):
            call_sites = source_refresh.get("call_sites")
            if not isinstance(call_sites, list):
                raise HoshimemoSceneHookError("原文台词立绘刷新报告缺少调用点")
            for call_site in call_sites:
                if not isinstance(call_site, Mapping):
                    raise HoshimemoSceneHookError("原文台词立绘刷新调用点无效")
                registered_hooks.append(
                    {
                        "patch_offset": int(call_site["patch_offset"]),
                        "expected_hex": str(call_site["expected_hex"]),
                    }
                )
        scene_reports.append(
            {
                "scene_id": str(flat["scene_id"]),
                "title": str(flat["title"]),
                "revision": int(flat["revision"]),
                "anchor_id": str((flat.get("anchor") or {}).get("anchor_id") or ""),
                "report": dict(candidate.report),
            }
        )

    restored_prefix = bytearray(current_hcb[: len(document.original_bytes)])
    for registered in registered_hooks:
        offset = int(registered["patch_offset"])
        expected = bytes.fromhex(str(registered["expected_hex"]))
        restored_prefix[offset : offset + 5] = expected
    if bytes(restored_prefix) != document.original_bytes:
        raise HoshimemoSceneHookError(
            "多场景生成器改变了登记挂接窗口之外的原 HCB 字节"
        )

    resource_archives: dict[str, bytes] = {}
    resource_sources: dict[str, str] = {}
    resource_source_sizes: dict[str, int] = {}
    if original_graph is not None and current_graph is not None and current_graph != original_graph:
        resource_archives["graph.bin"] = current_graph
        resource_sources["graph.bin"] = _sha256(original_graph)
        resource_source_sizes["graph.bin"] = len(original_graph)
    if (
        original_graph_bs is not None
        and current_graph_bs is not None
        and current_graph_bs != original_graph_bs
    ):
        resource_archives["graph_bs.bin"] = current_graph_bs
        resource_sources["graph_bs.bin"] = _sha256(original_graph_bs)
        resource_source_sizes["graph_bs.bin"] = len(original_graph_bs)
    for name, original in sorted(original_event_archives.items()):
        current = current_event_archives.get(name)
        if current is not None and current != original:
            resource_archives[name] = current
            resource_sources[name] = _sha256(original)
            resource_source_sizes[name] = len(original)

    plan_identity = {
        "story_schema": str(story.get("schema") or ""),
        "story_revision": int(story.get("revision") or 0),
        "duration_ms": int(duration_ms),
        "scenes": [
            {
                "scene_id": item["scene_id"],
                "revision": item["revision"],
                "anchor_id": item["anchor_id"],
                "plan_sha256": item["report"]["plan_sha256"],
            }
            for item in scene_reports
        ],
        "resource_sources": dict(sorted(resource_sources.items())),
    }
    audio_cue_bytes = sum(
        int(item["report"].get("output", {}).get("audio_cue_bytes") or 0)
        for item in scene_reports
    )
    report: dict[str, Any] = {
        "schema": BATCH_HOOK_REPORT_SCHEMA,
        "emitter_id": BATCH_HOOK_EMITTER_ID,
        "passed": True,
        "dry_run_passed": True,
        "install_ready": True,
        "transaction_mode": (
            "resource_archives_and_hcb" if resource_archives else "hcb_only"
        ),
        "profile_id": abi.profile_id,
        "plan_sha256": _canonical_sha256(plan_identity),
        "source": {
            "hcb_sha256": document.source_sha256,
            "hcb_size": len(document.original_bytes),
            "path": str(document.path) if document.path is not None else None,
            "index_fingerprint": str(getattr(profile, "index_fingerprint", "") or ""),
            "resource_archives": {
                name: {
                    "size": resource_source_sizes[name],
                    "sha256": resource_sources[name],
                }
                for name in sorted(resource_archives)
            },
        },
        "story_project": {
            "schema": str(story.get("schema") or ""),
            "revision": int(story.get("revision") or 0),
            "scene_count": len(scene_reports),
            "compile_order": [item["scene_id"] for item in scene_reports],
        },
        "scenes": scene_reports,
        "hooks": [dict(item["report"]["hook"]) for item in scene_reports],
        "output": {
            "hcb_sha256": _sha256(current_hcb),
            "hcb_size": len(current_hcb),
            "appended_bytes": len(current_hcb) - len(document.original_bytes),
            "audio_cue_bytes": audio_cue_bytes,
            "resource_archives": {
                name: {
                    "size": len(payload),
                    "sha256": _sha256(payload),
                    "added_bytes": len(payload) - resource_source_sizes[name],
                }
                for name, payload in sorted(resource_archives.items())
            },
            "hook_count": len(scene_reports),
            "registered_patch_count": len(registered_hooks),
            "original_prefix_unchanged_except_registered_hooks": True,
        },
    }
    json.dumps(report, ensure_ascii=False, sort_keys=True)
    graph_candidate = resource_archives.get("graph_bs.bin")
    candidate = SceneHookCandidate(
        hcb=current_hcb,
        report=report,
        install_ready=True,
        graph_bs=graph_candidate,
        graph_bs_source_sha256=(
            resource_sources.get("graph_bs.bin") if graph_candidate is not None else None
        ),
        resource_archives=resource_archives,
        resource_archive_source_sha256=resource_sources,
        portrait_resource_payloads=portrait_payloads,
    )
    return _attach_audio_resource_build(candidate, target_audio_build)
