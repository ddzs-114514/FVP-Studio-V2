"""GUI chapter listener with owned byte uploads and native voiced lines."""
import argparse
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .audio_project import PROJECT_AUDIO_MAX_BYTES
from .gui_chapter_server import ChapterRuntime, GuiChapterHandler, GuiChapterServer
from .gui_local_audio import GuiHybridAudio, KINDS, SOURCE
from .gui_runtime import API_ROOT, GuiRuntimeError, load_sources
from .gui_voice_program import CONTRACT


class SoundRuntime(ChapterRuntime):
    def __init__(self, sources, audio_root):
        super().__init__(sources)
        self.audio = GuiHybridAudio(self, audio_root)

    def health(self):
        result = super().health()
        result["capabilities"].update(audio_import=True, native_voice_lines=True)
        result["audio_contract"].update(local_export=True, voice_export=True,
            native_export_kinds=["bgm","se","voice"], local_and_cross_game_export=True,
            upload_max_bytes=PROJECT_AUDIO_MAX_BYTES, uploaded_source=SOURCE,
            upload_original_path_saved=False, native_export_source="hoshi")
        result["audio_contract"]["sources"].append(dict(source=SOURCE, name="本地声音",
                                                       kinds=sorted(KINDS), local=True))
        result["voice_contract"] = dict(schema=CONTRACT, target="hoshi", sources="registered_or_uploaded",
            beat_field="voice", volume_default=100, exact_selected_asset=True,
            native_voice_channel=True, native_text_wait=True, native_mute_skip_guards=True,
            stop_on_next_line=True, forced_speaker_identity=False,
            backlog_replay_verified=False, save_load_verified=False, runtime_verified=False)
        return result


class GuiSoundServer(GuiChapterServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.RequestHandlerClass = GuiSoundHandler


class GuiSoundHandler(GuiChapterHandler):
    def do_POST(self):
        url = urlsplit(self.path)
        if url.path != API_ROOT + "audio-import":
            return super().do_POST()
        acquired = False
        try:
            self._local_request()
            if len(self.path) > 4096 or self.headers.get("X-FVP-GUI-Request") != "audio-import/1":
                raise GuiRuntimeError("request_rejected", "请通过声音导入操作选择文件。", 403)
            if self.headers.get("Content-Type", "").split(";",1)[0].strip() != "application/octet-stream":
                raise GuiRuntimeError("media_type_rejected", "声音导入须发送文件内容。", 415)
            q = self._query(parse_qs(url.query, keep_blank_values=True, max_num_fields=3),
                            ("kind","name"), ("kind","name"))
            if q["kind"] not in KINDS or len(q["name"]) > 256 or "\0" in q["name"]:
                raise ValueError("声音类型或名称不正确。")
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit():
                raise ValueError("声音文件长度不明确。")
            size = int(lengths[0])
            if not 0 < size <= PROJECT_AUDIO_MAX_BYTES:
                raise GuiRuntimeError("audio_too_large", "单段声音须在 128 MiB 以内。", 413)
            acquired = self.server.heavy_requests.acquire(timeout=0.1)
            if not acquired:
                raise GuiRuntimeError("busy", "正在读取声音，请稍后导入。", 503)
            self.connection.settimeout(30)
            payload = self.rfile.read(size)
            if len(payload) != size:
                raise ValueError("声音上传不完整，请重新选择。")
            self._json(self.server.runtime.audio.local.import_bytes(payload, kind=q["kind"], name=q["name"]), 201)
        except GuiRuntimeError as exc:
            self._error(exc)
        except (ValueError, TypeError, UnicodeError) as exc:
            self._error(GuiRuntimeError("invalid_audio", str(exc)[:300]))
        except (BrokenPipeError, ConnectionResetError):
            return
        except (OSError, TimeoutError):
            self._error(GuiRuntimeError("import_failed", "声音导入未能确认，请查看本地声音列表后再试。", 503))
        except Exception:
            self._error(GuiRuntimeError("import_failed", "声音导入未能确认，请保留文件并重试。", 500))
        finally:
            if acquired:
                self.server.heavy_requests.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "html", "output-root", "audio-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--port", type=int, default=18808)
    options = parser.parse_args()
    if not 1024 <= options.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    server = GuiSoundServer(("127.0.0.1", options.port),
        SoundRuntime(load_sources(options.sources), options.audio_root), options.html, options.output_root)
    print(f"GUI_SOUND_READY http://127.0.0.1:{options.port}/fvp_story_studio_prototype.html", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
