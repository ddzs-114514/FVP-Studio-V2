"""Loopback-only, GET-only GUI + native portrait read bridge.

This separate listener leaves the user's existing 18795 prototype untouched.
Only one explicitly configured HTML and the bounded read-only API are served.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import BoundedSemaphore
from urllib.parse import parse_qs, urlsplit

from .gui_runtime import API_ROOT, GuiRuntime, GuiRuntimeError, load_sources


class GuiRuntimeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, runtime, html):
        if address[0] != "127.0.0.1":
            raise ValueError("GUI runtime must bind only to 127.0.0.1")
        self.runtime = runtime
        self.html = Path(html).resolve(strict=True)
        if self.html.suffix.casefold() != ".html" or not self.html.is_file():
            raise ValueError("GUI file must be an existing HTML file")
        self.heavy_requests = BoundedSemaphore(2)
        super().__init__(address, GuiRuntimeHandler)


class GuiRuntimeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Do not log source resources, query strings, or local filesystem paths.
        print("GUI_RUNTIME_REQUEST", self.command, flush=True)

    def _send(self, status, payload, mime, etag=None):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if etag:
            self.send_header("ETag", '"' + etag + '"')
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, value, status=200):
        self._send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, error):
        self._json(dict(ok=False, error=dict(code=error.code, message=str(error))), error.status)

    def _local_request(self):
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host", "") not in hosts:
            raise GuiRuntimeError("host_rejected", "仅允许本机来源", 403)
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + host for host in hosts}:
            raise GuiRuntimeError("origin_rejected", "拒绝跨来源读取原作素材", 403)
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise GuiRuntimeError("origin_rejected", "拒绝跨站读取原作素材", 403)

    @staticmethod
    def _query(values, allowed, required=()):
        if set(values) - set(allowed) or any(len(v) != 1 for v in values.values()):
            raise GuiRuntimeError("invalid_request", "未知或重复的请求参数")
        result = {key: value[0] for key, value in values.items()}
        if any(not result.get(key) for key in required):
            raise GuiRuntimeError("invalid_request", "缺少来源或身体参数")
        return result

    def do_GET(self):
        try:
            self._local_request()
            if len(self.path) > 4096:
                raise GuiRuntimeError("invalid_request", "请求路径过长")
            url = urlsplit(self.path)
            if url.path in ("/", "/fvp_story_studio_prototype.html"):
                self._send(200, self.server.html.read_bytes(), "text/html; charset=utf-8")
                return
            values = parse_qs(url.query, keep_blank_values=True, max_num_fields=12)
            if url.path == API_ROOT + "health":
                self._query(values, ())
                self._json(self.server.runtime.health())
            elif url.path == API_ROOT + "catalog":
                q = self._query(values, ("source", "q", "offset", "limit"), ("source",))
                self._json(self.server.runtime.catalog(q["source"], q.get("q", ""),
                            q.get("offset", 0), q.get("limit", 40)))
            elif url.path in (API_ROOT + 'speaker-catalog', API_ROOT + 'speaker', API_ROOT + 'speaker-avatar.png'):
                catalog = url.path.endswith('speaker-catalog')
                png = url.path.endswith('.png')
                required = ('source',) if catalog else ('source', 'name')
                allowed = ('source', 'q', 'offset', 'limit') if catalog else ('source', 'name')
                if png:
                    required += ('identity_sha256',)
                    allowed += ('identity_sha256', 'state')
                q = self._query(values, allowed, required)
                if not self.server.heavy_requests.acquire(blocking=False):
                    raise GuiRuntimeError('busy', '正在读取素材，请稍后选择人物。', 503)
                try:
                    if catalog:
                        self._json(self.server.runtime.speakers.catalog(q['source'], q.get('q', ''),
                                   q.get('offset', 0), q.get('limit', 40)))
                    elif png:
                        data, tag = self.server.runtime.speakers.avatar_png(q['source'], q['name'],
                                      q['identity_sha256'], q.get('state', 'normal'))
                        self._send(200, data, 'image/png', tag)
                    else:
                        self._json(self.server.runtime.speakers.info(q['source'], q['name']))
                finally:
                    self.server.heavy_requests.release()
            elif url.path == API_ROOT + "graphics-catalog":
                q = self._query(values, ("source", "category", "q", "offset", "limit", "archive"),
                                ("source", "category"))
                self._json(self.server.runtime.graphics.catalog(q["source"], q["category"],
                    q.get("q", ""), q.get("offset", 0), q.get("limit", 40), q.get("archive")))
            elif url.path == API_ROOT + "background-blur-pair":
                q = self._query(parse_qs(url.query, keep_blank_values=True),
                                ("source", "archive", "resource"), ("source", "archive", "resource"))
                if not self.server.heavy_requests.acquire(blocking=False):
                    raise GuiRuntimeError("busy", "正在读取素材，请稍后再试。", 503)
                try:
                    self._json(self.server.runtime.graphics.blur_pair(q["source"], q["archive"], q["resource"]))
                finally:
                    self.server.heavy_requests.release()
            elif url.path in (API_ROOT + "graphic", API_ROOT + "graphic.png"):
                required = ("source", "category", "archive", "resource")
                allowed = required if url.path.endswith("graphic") else required + ("frame", "payload_sha256")
                if url.path.endswith(".png"):
                    required += ("payload_sha256",)
                q = self._query(values, allowed, required)
                if not self.server.heavy_requests.acquire(timeout=0.1):
                    raise GuiRuntimeError("busy", "正在读取素材，请稍后再选", 503)
                try:
                    if url.path.endswith("graphic"):
                        self._json(self.server.runtime.graphics.graphic(q["source"], q["category"],
                            q["archive"], q["resource"]))
                    else:
                        payload, digest = self.server.runtime.graphics.png(q["source"], q["category"],
                            q["archive"], q["resource"], q.get("frame", 0), q["payload_sha256"])
                        self._send(200, payload, "image/png", digest)
                finally:
                    self.server.heavy_requests.release()
            elif url.path in (API_ROOT + "portrait", API_ROOT + "portrait.png"):
                allowed = ("source", "body") if url.path.endswith("portrait") else (
                    "source", "body", "expression", "body_sha256")
                q = self._query(values, allowed, ("source", "body"))
                if not self.server.heavy_requests.acquire(timeout=0.1):
                    raise GuiRuntimeError("busy", "正在读取素材，请稍后再选", 503)
                try:
                    if url.path.endswith("portrait"):
                        self._json(self.server.runtime.portrait(q["source"], q["body"]))
                    else:
                        payload, digest = self.server.runtime.portrait_png(q["source"], q["body"],
                            q.get("expression", 0), q.get("body_sha256"))
                        self._send(200, payload, "image/png", digest)
                finally:
                    self.server.heavy_requests.release()
            else:
                raise GuiRuntimeError("not_found", "不存在该只读接口", 404)
        except GuiRuntimeError as error:
            self._error(error)
        except (ValueError, KeyError) as error:
            self._error(GuiRuntimeError("resource_unresolved", str(error), 422))
        except (BrokenPipeError, ConnectionResetError):
            return
        except OSError:
            self._error(GuiRuntimeError("source_unavailable", "本机来源暂不可读取", 503))
        except Exception:
            self._error(GuiRuntimeError("internal_error", "只读解析失败，未修改任何工程或游戏文件", 500))

    def _readonly(self):
        self._error(GuiRuntimeError("read_only", "此服务只读；编译、写回与安装未开放", 405))

    do_POST = _readonly
    do_PUT = _readonly
    do_PATCH = _readonly
    do_DELETE = _readonly
    do_OPTIONS = _readonly


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--html", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18796)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    runtime = GuiRuntime(load_sources(args.sources))
    server = GuiRuntimeServer(("127.0.0.1", args.port), runtime, args.html)
    print("GUI_RUNTIME_READY http://127.0.0.1:" + str(args.port) + "/fvp_story_studio_prototype.html", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
