"""GUI voiced lines on the audited native voice channel and text wait.

The original voice wrapper is reused except its filename/character-ID lookup.
Text keeps its native initialization and click/auto wait, never a SPEAK_* call.
No original HCB, production speaker ABI, or portrait/camera code is edited.
"""
from copy import deepcopy
import struct

from .gui_runtime import ID_RE, SHA_RE
from .performance_compile import args, call, jump, sha
from .portrait_emitter import _encode_push

KIND = "GuiVoiceLine"
CONTRACT = "fvp-gui-voice-line/1"


def event_values(fields):
    required = {"line_id", "text", "speaker_mode", "display_name", "source", "archive", "resource", "sha256", "volume"}
    if set(fields) not in (required, required | {"speaker_source"}):
        raise ValueError("配音台词字段不完整。")
    if "speaker_source" in fields and (not isinstance(fields["speaker_source"], str)
            or fields["speaker_source"] and not ID_RE.fullmatch(fields["speaker_source"])):
        raise ValueError("配音台词角色来源不正确。")
    if (not isinstance(fields["line_id"], str) or not ID_RE.fullmatch(fields["line_id"])
            or not isinstance(fields["text"], str) or not fields["text"].strip() or len(fields["text"]) > 10000):
        raise ValueError("配音台词不能为空或过长。")
    mode, name = fields["speaker_mode"], fields["display_name"]
    if (mode not in ("narration", "custom") or not isinstance(name, str) or len(name) > 256
            or mode == "narration" and name != "" or mode == "custom" and not name.strip()):
        raise ValueError("配音台词的说话人不正确。")
    if (not isinstance(fields["source"], str) or not ID_RE.fullmatch(fields["source"])
            or fields["archive"] not in ("voice.bin", "voice2.bin", "local-voice")
            or not isinstance(fields["resource"], str) or not 0 < len(fields["resource"]) <= 256
            or "\0" in fields["resource"] or not isinstance(fields["sha256"], str)
            or not SHA_RE.fullmatch(fields["sha256"]) or type(fields["volume"]) is not int
            or not 0 <= fields["volume"] <= 100):
        raise ValueError("配音素材引用或音量不正确。")
    _encode_push(fields["text"], "gbk")
    _encode_push(name, "gbk")
    return deepcopy(fields)


def loader(emitter):
    key = ("gui_voice_asset_loader", CONTRACT)
    if key in emitter.helpers:
        return emitter.helpers[key]["address"]
    lo, split, tail, hi = 0x57495, 0x574EF, 0x57542, 0x5757B
    doc = emitter.document.instructions
    sections = [[i for i in doc if a <= i.offset < b] for a,b in ((lo,split),(tail,hi))]
    if (emitter.source[lo:hi] != emitter.clean[lo:hi]
            or emitter.by_offset[lo].operands != {"args":3,"locals":7}
            or any(not items or items[0].offset != a or items[-1].offset+len(items[-1].raw) != b
                   for items,(a,b) in zip(sections, ((lo,split),(tail,hi))))
            or emitter.by_offset[0x574A6].operands != {"value":-4}
            or emitter.by_offset[0x574F8].operands != {"value":0}):
        raise ValueError("语音加载函数与已支持的游戏版本不一致。")
    skip = len(emitter.output)
    emitter.output.extend(jump(0))
    address = len(emitter.output)
    body, mapping, relocations = bytearray(), {}, []
    for index, items in enumerate(sections):
        for ins in items:
            mapping[ins.offset] = address + len(body)
            if ins.opcode in (6,7):
                relocations.append((len(body)+1, ins.operands["target"]))
            body.extend(ins.raw)
        if index == 0:
            # Prepend a filepath argument: original [-4,-3,-2] stay unchanged.
            push = bytearray(emitter.by_offset[0x574A6].raw)
            if len(push) != 2:
                raise ValueError("语音路径参数编码发生变化。")
            push[1] = 0xFB  # [-5]
            body.extend(push + emitter.by_offset[0x574F8].raw)
    body[1] = 4
    for at, old in relocations:
        if old not in mapping:
            raise ValueError("语音加载片段含未审核的跳转。")
        struct.pack_into("<I", body, at, mapping[old])
    emitter.output.extend(body)
    struct.pack_into("<I", emitter.output, skip+1, len(emitter.output))
    emitter.call_table["gui_voice_asset_play"] = address, 4
    emitter.helpers[key] = dict(address=address, source=[lo,hi], source_sha256=sha(emitter.clean[lo:hi]),
        retained=[[lo,split],[tail,hi]], omitted_filename_lookup=[split,tail], argument_count=4,
        path_argument_index=-5, native_voice_channel_global=208, native_mute_skip_guards=True,
        original_args_unchanged=True, character_id_remap_bypassed=True, runtime_verified=False)
    return address


def text_helper(emitter):
    if "gui_voice_text" in emitter.helpers:
        return emitter.helpers["gui_voice_text"]["address"]
    skip = len(emitter.output)
    emitter.output.extend(jump(0))
    stub = len(emitter.output)
    emitter.output.extend(bytes((1,3,0,4)))
    target = emitter.private_text(helper="gui_voice_text")
    call_at = target + 0x4F353 - 0x4F268
    if (emitter.by_offset[0x4F353].operands != {"target":0x57495}
            or emitter.by_offset[0x57495].operands["args"] != 3
            or emitter.output[call_at] != 2
            or struct.unpack_from("<I", emitter.output, call_at+1)[0] != 0x57495):
        raise ValueError("台词与语音的衔接函数发生变化。")
    struct.pack_into("<I", emitter.output, call_at+1, stub)
    struct.pack_into("<I", emitter.output, skip+1, len(emitter.output))
    emitter.helpers["gui_voice_text"].update(native_voice_dispatch_skipped=True,
        voice_dispatch="exact selected asset before native text_wait", native_text_wait=True)
    return target


def stop_helper(emitter):
    key = ("gui_voice_stop", CONTRACT)
    if key in emitter.helpers:
        return
    # Original dynamic G208, zero-time AudioStop and ret, with a zero-arg frame.
    for a,b in ((0x57495,0x57498),(0x574AF,0x574B2),(0x574E1,0x574E3),(0x574B4,0x574B7),(0x57579,0x5757A)):
        if emitter.source[a:b] != emitter.clean[a:b]:
            raise ValueError("语音停止函数与已支持版本不一致。")
    skip = len(emitter.output)
    emitter.output.extend(jump(0))
    target = len(emitter.output)
    header = bytearray(emitter.by_offset[0x57495].raw)
    header[1], header[2] = 0, 0
    emitter.output.extend(header + emitter.source[0x574AF:0x574B2]
        + emitter.source[0x574E1:0x574E3] + emitter.source[0x574B4:0x574B7])
    for glob in (276,277):
        emitter.output.extend(args([None]) + b"\x15" + struct.pack("<H", glob))
    emitter.output.extend(emitter.source[0x57579:0x5757A])
    struct.pack_into("<I", emitter.output, skip+1, len(emitter.output))
    emitter.call_table["gui_voice_stop"] = target, 0
    emitter.helpers[key] = dict(address=target, native_voice_channel_global=208, clears=[276,277],
                               runtime_verified=False)


def emit_line(emitter, event, resources):
    fields = event_values({k:v for k,v in event.items() if k != "kind"})
    if emitter.covered:
        raise ValueError("黑/白场仍未恢复，不能开始配音台词。")
    binding = resources.audio(event)
    loader(emitter)
    target = text_helper(emitter)
    stop_helper(emitter)
    emitter.output.extend(emitter.native("gui_voice_stop"))
    resolver = getattr(resources, "speech", None)
    identity = resolver(fields) if callable(resolver) else None
    if identity and not isinstance(identity, dict): identity = None
    history = None if fields["speaker_mode"] == "narration" else fields["display_name"]
    if identity and identity.get("source") == "hoshi":
        from .performance_speech import speech_catalog
        catalog = speech_catalog(emitter.document, emitter.source)
        canonical = identity.get('name', fields['display_name'])
        selected = next((c for c in catalog if c["canonical_name"] == canonical or c["name"] == canonical), None)
        if selected: history = selected["native_key"]
    elif identity and identity.get("source") != "hoshi":
        history = None
        if fields["speaker_mode"] != "narration" and identity.get("avatar") and identity.get("resource"):
            history = identity["history_key"]
            emitter.native_speakers.bindings[history] = deepcopy(identity)
    emitter.native_speakers.set_identity(fields["display_name"] or None, history,
        narration=fields["speaker_mode"] == "narration", binding=identity)
    for glob, value in ((276,binding["native_id"]),(277,None),(278,fields["volume"])):
        emitter.output.extend(args([value]) + b"\x15" + struct.pack("<H", glob))
    emitter.speech = dict(name=fields["display_name"], text=fields["text"], voice_sha256=fields["sha256"],
        history_key=history, speaker_identity=bool(identity))
    emitter.output.extend(args([fields["text"],None,None,None]) + call(target))
    directory = "voice2/" if binding["target_archive"] == "voice2.bin" else "voice/"
    emitter.output.extend(emitter.native("gui_voice_asset_play", (directory + binding["target_resource"],
        binding["native_id"], None, None)))
    emitter.output.extend(emitter.native("text_wait"))
    # A user's early click must not leave this voice on the next line/route.
    emitter.output.extend(emitter.native("gui_voice_stop"))
    emitter.join()
    emitter.gui_voice_used = True
    return True
