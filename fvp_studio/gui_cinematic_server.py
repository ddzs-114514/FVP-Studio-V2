"""Isolated preview listener with read-only registered OP/ED movie assets."""
import argparse
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .gui_cinematics import GuiCinematics, MIME, byte_range, identity
from .gui_runtime import API_ROOT, GuiRuntimeError, load_sources
from .gui_sound_server import GuiSoundHandler, GuiSoundServer, SoundRuntime


class CinematicRuntime(SoundRuntime):
    def __init__(self,sources,audio_root):
        super().__init__(sources,audio_root)
        self.cinematics=GuiCinematics(self)

    def health(self):
        result=super().health()
        result['capabilities'].update(movie_catalog=True,movie_info=True,movie_file=True,
            cinematic_native_export=False)
        result['cinematic_contract']=dict(schema='fvp-gui-cinematics/1',native_export=False,
            movie_catalog=API_ROOT+'movie-catalog',movie_info=API_ROOT+'movie-info',
            movie_file=API_ROOT+'movie-file',duration_unit='ms',file_identity='metadata_not_content_hash',
            original_files_read_only=True,browser_preview_does_not_prove_native_playback=True)
        return result


class CinematicHandler(GuiSoundHandler):
    def do_GET(self):
        url=urlsplit(self.path)
        route=url.path.removeprefix(API_ROOT)
        if route not in ('movie-catalog','movie-info','movie-file'):
            return super().do_GET()
        try:
            self._local_request()
            if len(self.path)>4096:
                raise GuiRuntimeError('invalid_request','请求过长。')
            values=parse_qs(url.query,keep_blank_values=True,max_num_fields=6)
            movies=self.server.runtime.cinematics
            if route=='movie-catalog':
                q=self._query(values,('source','q','offset','limit'),('source',))
                return self._json(movies.catalog(q['source'],q.get('q',''),q.get('offset',0),q.get('limit',100)))
            q=self._query(values,('source','resource','file_identity'),('source','resource','file_identity'))
            if route=='movie-info':
                acquired=self.server.heavy_requests.acquire(timeout=0.1)
                if not acquired:
                    raise GuiRuntimeError('busy','正在读取影片资料，请稍后再选。',503)
                try:
                    return self._json(movies.info(q['source'],q['resource'],q['file_identity']))
                finally:
                    self.server.heavy_requests.release()
            row,path=movies.resolve(q['source'],q['resource'],q['file_identity'])
            start,end,partial=byte_range(self.headers.get('Range'),row['size'])
            with path.open('rb') as stream:
                if identity(path)!=row['file_identity']:
                    raise GuiRuntimeError('source_changed','影片已改变，请重新选择。',409)
                self.send_response(206 if partial else 200)
                self.send_header('Content-Type',MIME[path.suffix.casefold()])
                self.send_header('Content-Length',str(end-start+1))
                self.send_header('Accept-Ranges','bytes')
                self.send_header('Cache-Control','no-store')
                self.send_header('ETag','"'+row['file_identity']+'"')
                self.send_header('X-Content-Type-Options','nosniff')
                self.send_header('Cross-Origin-Resource-Policy','same-origin')
                if partial:
                    self.send_header('Content-Range',f'bytes {start}-{end}/{row["size"]}')
                self.end_headers()
                stream.seek(start)
                remaining=end-start+1
                while remaining:
                    block=stream.read(min(remaining,256*1024))
                    if not block:
                        break
                    self.wfile.write(block)
                    remaining-=len(block)
        except GuiRuntimeError as exc:
            self._error(exc)
        except (BrokenPipeError,ConnectionResetError):
            pass
        except (OSError,ValueError,KeyError):
            self._error(GuiRuntimeError('movie_unavailable','影片目录或文件暂不可读取。',503))


class CinematicServer(GuiSoundServer):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.RequestHandlerClass=CinematicHandler


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('sources','html','output-root','audio-root'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--port',type=int,default=18816)
    options=parser.parse_args()
    if not 1024<=options.port<=65535:
        parser.error('port must be between 1024 and 65535')
    server=CinematicServer(('127.0.0.1',options.port),
        CinematicRuntime(load_sources(options.sources),options.audio_root),options.html,options.output_root)
    print(f'GUI_CINEMATIC_READY http://127.0.0.1:{options.port}/fvp_story_studio_prototype.html',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__=='__main__':
    main()
