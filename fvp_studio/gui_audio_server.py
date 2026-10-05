"""GUI listener with registered audio playback and explicit scene export."""
from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .gui_audio import GuiAudio, SCHEMA, byte_range
from .gui_export_server import ExportRuntime, GuiExportHandler, GuiExportServer
from .gui_runtime import API_ROOT, GuiRuntimeError, load_sources


class AudioRuntime(ExportRuntime):
    def __init__(self, sources):
        super().__init__(sources)
        self.audio = GuiAudio(self)

    def health(self):
        result = super().health()
        result["capabilities"].update(audio_catalog=True, audio_playback=True)
        result["audio_contract"] = dict(schema=SCHEMA, kinds=["bgm", "se", "voice"],
            native_export_kinds=["bgm", "se"], native_export_source="hoshi",
            registered_cross_game_export=True, local_export=False,
            local_and_cross_game_export=False, voice_export=False, exact_selected_bgm=True,
            original_read_only=True, sources=[self.audio.descriptor(s) for s in self.sources.values()])
        return result


class GuiAudioServer(GuiExportServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.RequestHandlerClass = GuiAudioHandler


class GuiAudioHandler(GuiExportHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path not in tuple(API_ROOT + p for p in ("audio-catalog", "audio-info", "audio")):
            return super().do_GET()
        try:
            self._local_request()
            if len(self.path) > 4096:
                raise GuiRuntimeError("invalid_request", "声音请求过长。")
            values = parse_qs(url.query, keep_blank_values=True, max_num_fields=10)
            audio = self.server.runtime.audio
            if not self.server.heavy_requests.acquire(timeout=0.1):
                raise GuiRuntimeError("busy", "正在读取声音，请稍后再选。", 503)
            try:
                if url.path.endswith("audio-catalog"):
                    q = self._query(values, ("source", "kind", "q", "offset", "limit"), ("source",))
                    self._json(audio.catalog(q["source"], kind=q.get("kind", "bgm"),
                        query=q.get("q", ""), offset=q.get("offset", 0), limit=q.get("limit", 80)))
                else:
                    required = ("source", "archive", "resource")
                    if url.path.endswith("audio-info"):
                        q = self._query(values, required, required)
                        self._json(audio.info(q["source"], q["archive"], q["resource"]))
                    else:
                        q = self._query(values, required + ("sha256",), required + ("sha256",))
                        payload, info, _ref = audio.asset(q["source"], q["archive"], q["resource"], q["sha256"])
                        start, end, ranged = byte_range(self.headers.get("Range"), len(payload))
                        self.send_response(206 if ranged else 200)
                        self.send_header("Content-Type", info["mime"])
                        self.send_header("Content-Length", str(end - start + 1))
                        self.send_header("Accept-Ranges", "bytes")
                        self.send_header("Cache-Control", "private, no-cache")
                        self.send_header("ETag", '"' + info["sha256"] + '"')
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
                        if ranged:
                            self.send_header("Content-Range", f"bytes {start}-{end}/{len(payload)}")
                        self.end_headers()
                        self.wfile.write(payload[start:end + 1])
            finally:
                self.server.heavy_requests.release()
        except GuiRuntimeError as exc:
            self._error(exc)
        except (BrokenPipeError, ConnectionResetError):
            return
        except (ValueError, KeyError, TypeError):
            self._error(GuiRuntimeError("invalid_request", "声音请求不正确。"))
        except OSError:
            self._error(GuiRuntimeError("source_unavailable", "声音来源暂时无法读取。", 503))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18805)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    server = GuiAudioServer(("127.0.0.1", args.port), AudioRuntime(load_sources(args.sources)),
                            args.html, args.output_root)
    print(f"GUI_AUDIO_READY http://127.0.0.1:{args.port}/fvp_story_studio_prototype.html", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
