"""Portable loopback launcher; no developer workspace discovery."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import os
import sys
from pathlib import Path

def checked_workspaces(sources, paths):
    """Reject source/output overlap and linked ancestors before startup writes."""
    for raw in paths:
        raw = Path(raw).expanduser().absolute()
        for parent in (raw, *raw.parents):
            if parent.exists() and (parent.is_symlink() or getattr(parent.stat(), "st_file_attributes", 0) & 0x400):
                raise ValueError("工作目录拒绝链接或目录联接")
        path = raw.resolve()
        for source in sources:
            root = source.root.resolve()
            if path == root or root in path.parents or path in root.parents:
                raise ValueError("工作/副本目录与原作来源重叠；拒绝启动写入接口")

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--html", type=Path, default=Path("web/fvp_story_studio_prototype.html"))
    parser.add_argument("--output-root", type=Path, default=Path("local-workspace/outputs"))
    parser.add_argument("--audio-root", type=Path, default=Path("local-workspace/audio"))
    parser.add_argument("--test-root", type=Path)
    parser.add_argument("--hoshi-binding", type=Path)
    parser.add_argument("--engine-patterns", type=Path)
    parser.add_argument("--empty-preview", action="store_true", help="只允许空来源启动，不挂接任何游戏")
    parser.add_argument("--port", type=int, default=18826)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("端口必须在 1024 至 65535 之间")
    if not args.html.is_file():
        parser.error("GUI HTML 不存在；可通过 --html 明确指定")
    for option, variable in ((args.hoshi_binding, "FVP_STUDIO_HOSHI_BINDING"),
                             (args.engine_patterns, "FVP_STUDIO_ENGINE_PATTERNS"),
                             (args.test_root, "FVP_STUDIO_TEST_ROOT")):
        if option is not None:
            os.environ[variable] = str(option.expanduser().absolute())
    # Bindings must be set before importing the emitter's immutable constants.
    from .gui_cinematic_server import CinematicRuntime, CinematicServer
    from .gui_runtime import load_sources
    from .local_binding import BINDING
    sources = load_sources(args.sources, allow_empty=args.empty_preview)
    if args.empty_preview and sources:
        parser.error("空预览不能同时登记真实来源")
    from .performance_install import TEST_PARENT
    checked_workspaces(sources, (args.output_root, args.audio_root, TEST_PARENT))
    args.output_root = args.output_root.expanduser().absolute()
    args.audio_root = args.audio_root.expanduser().absolute()
    for workspace in (args.output_root, args.audio_root, TEST_PARENT):
        workspace.mkdir(parents=True, exist_ok=True)
    # These are empty workspace roots, not game copies. Export still requires
    # an explicit request and atomic reservation of a brand-new child.
    class EmptyRuntime(CinematicRuntime):
        allow_empty_sources = True
    runtime_class = EmptyRuntime if args.empty_preview else CinematicRuntime
    runtime = runtime_class(sources, args.audio_root)
    server = CinematicServer(("127.0.0.1", args.port), runtime, args.html, args.output_root)
    print(f"FVP_STUDIO_READY http://127.0.0.1:{args.port}/fvp_story_studio_prototype.html", flush=True)
    print(f"Registered sources: {len(sources)}; Hoshimemo binding: {bool(BINDING)}; original games read-only", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
