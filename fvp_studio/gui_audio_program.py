"""GUI-only music/SE events using the existing audited Hoshimemo audio ABI.

No per-title size rule, production node type, or speech/voice ABI is inferred.
Playback assets have already been frozen by the registered-source audio reader.
"""
from copy import deepcopy
import struct

from .gui_native_cg import GuiCgEmitter
from .hoshimemo_scene_hook import HOSHIMEMO_SCENE_HOOK_ABI
from .gui_runtime import ID_RE, SHA_RE
from .performance_compile import jump, sha

KINDS = {"GuiBGM", "GuiSE", "GuiVoiceLine"}


def event_values(kind, fields):
    if kind == "GuiVoiceLine":
        from .gui_voice_program import event_values as voice_values
        return voice_values(fields)
    if kind not in KINDS or set(fields) != {"op", "source", "archive", "resource", "sha256",
                                           "volume", "loop", "duration_ms"}:
        raise ValueError("声音指令字段不完整。")
    if fields["op"] not in ("play", "stop"):
        raise ValueError("声音操作只能是播放或停止。")
    for key, high in (("volume", 100), ("duration_ms", 6000)):
        if type(fields[key]) is not int or not 0 <= fields[key] <= high:
            raise ValueError("声音音量或切换时间不正确。")
    if type(fields["loop"]) is not bool or kind == "GuiSE" and fields["loop"]:
        raise ValueError("循环设置不正确；音效不循环。")
    if fields["op"] == "stop":
        if any(fields[key] is not None for key in ("source", "archive", "resource", "sha256")):
            raise ValueError("停止声音不能附带素材引用。")
    else:
        if (not isinstance(fields["source"], str) or not ID_RE.fullmatch(fields["source"])
                or not isinstance(fields["sha256"], str) or not SHA_RE.fullmatch(fields["sha256"])
                or not isinstance(fields["resource"], str) or not fields["resource"]
                or len(fields["resource"]) > 256 or "\0" in fields["resource"]):
            raise ValueError("这段声音暂时不能生成到游戏，请重新选择游戏内的声音。")
        if fields["archive"] not in ({"bgm.bin", "bgm2.bin", "local-bgm"} if kind == "GuiBGM" else {"se.bin", "local-se"}):
            raise ValueError("声音素材类型不匹配。")
    return deepcopy(fields)


class GuiAudioEmitter(GuiCgEmitter):
    def __init__(self, source, clean):
        super().__init__(source, clean)
        abi = HOSHIMEMO_SCENE_HOOK_ABI
        wrappers = {"gui_bgm_play": (abi.bgm_play_target, 5),
                    "gui_bgm_stop": (abi.bgm_stop_target, 1),
                    "gui_se_play": (abi.se_play_target, 4),
                    "gui_se_stop": (abi.se_stop_all_target, 1)}
        for name, (address, arity) in wrappers.items():
            instruction = self.by_offset.get(address)
            if (instruction is None or instruction.opcode != 1
                    or instruction.operands.get("args") != arity
                    or source[address:address + len(instruction.raw)] != instruction.raw):
                raise ValueError("游戏声音调用与已支持版本不一致，已停止生成。")
            self.call_table[name] = address, arity
        self.gui_audio_used = False
        self.gui_voice_used = False

    def asset_bgm_helper(self):
        """Reuse 4442's actual loader/two-channel tail, bypass only its ID table.

        A file-path argument is prepended: the original five argument stack
        indices stay unchanged. No G3060 arrangement setting is written.
        """
        key = ("gui_bgm_asset_loader", "fvp-gui-audio-bindings/1")
        if key in self.helpers:
            return self.helpers[key]["address"]
        lo, hi = 0x57268, 0x572F6
        section = [i for i in self.document.instructions if lo <= i.offset < hi]
        if (not section or section[0].offset != lo or section[-1].offset + len(section[-1].raw) != hi
                or self.source[lo:hi] != self.clean[lo:hi]
                or self.clean[0x56C8C:0x56C8F] != b"\x01\x05\x03"):
            raise ValueError("音乐资源加载函数与已支持版本不一致。")
        skipped = len(self.output)
        self.output.extend(jump(0))
        target = len(self.output)
        # Reuse actual operand encodings, not guessed VM instructions.
        # init_stack 6, 3; path [-7] -> local0; original ID [-6] -> G204.
        header = bytearray(self.by_offset[0x56C8C].raw)
        path_push = bytearray(self.by_offset[0x56CEF].raw)
        if (len(header) != 3 or len(path_push) != 2
                or self.by_offset[0x56CEF].operands != {"value":-6}
                or self.by_offset[0x56CA3].operands != {"value":0}
                or self.by_offset[0x56CF1].operands != {"value":204}
                or any(self.source[a:b] != self.clean[a:b] for a,b in
                       ((0x56CA3,0x56CA5),(0x56CEF,0x56CF4)))):
            raise ValueError("音乐加载参数编码发生变化。")
        header[1], path_push[1] = 6, 0xF9
        self.output.extend(bytes(header) + bytes(path_push) + self.source[0x56CA3:0x56CA5]
                           + self.source[0x56CEF:0x56CF4])
        destination = len(self.output)
        body = bytearray(self.source[lo:hi])
        for ins in section:
            if ins.opcode in (6, 7):
                address = ins.operands["target"]
                if not lo <= address < hi:
                    raise ValueError("音乐加载片段含未审核的跳转。")
                struct.pack_into("<I", body, ins.offset-lo+1, destination+address-lo)
        self.output.extend(body)
        struct.pack_into("<I", self.output, skipped+1, len(self.output))
        self.call_table["gui_bgm_asset_play"] = target, 6
        self.helpers[key] = dict(address=target, source=[lo, hi], source_sha256=sha(self.clean[lo:hi]),
            argument_count=6, path_argument_index=-7, original_args_unchanged=True,
            original_music_channels=True, id_switch_bypassed=True, runtime_verified=False)
        return target

    def emit_extension(self, event, resources):
        kind = event["kind"]
        if kind == "GuiVoiceLine":
            from .gui_voice_program import emit_line
            return emit_line(self, event, resources)
        if kind not in KINDS:
            return super().emit_extension(event, resources)
        fields = event_values(kind, {k: v for k, v in event.items() if k != "kind"})
        prefix = "gui_bgm_" if kind == "GuiBGM" else "gui_se_"
        if fields["op"] == "stop":
            self.output.extend(self.native(prefix + "stop", (fields["duration_ms"],)))
        else:
            binding = resources.audio(event)
            native_id = binding["native_id"]
            if kind == "GuiBGM":
                self.asset_bgm_helper()
                directory = "BGM2/" if binding["target_archive"] == "bgm2.bin" else "BGM/"
                self.output.extend(self.native("gui_bgm_asset_play", (directory + binding["target_resource"],
                    native_id, fields["duration_ms"], fields["loop"], fields["volume"], True)))
            else:
                self.output.extend(self.native(prefix + "play", (native_id, fields["duration_ms"],
                                                               True, fields["volume"])))
        self.gui_audio_used = True
        return True

    def resume_original(self):
        if self.gui_voice_used:
            from .gui_voice_program import stop_helper
            stop_helper(self)
            self.output.extend(self.native("gui_voice_stop"))
        if self.gui_audio_used:
            self.output.extend(self.native("gui_bgm_stop", (0,)))
            self.output.extend(self.native("gui_se_stop", (0,)))
        return super().resume_original()
