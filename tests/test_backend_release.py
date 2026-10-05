"""Synthetic-only portable backend and fail-closed packaging checks.

No original games are read, copied or launched. All binary-format fixtures
are constructed inside TemporaryDirectory and are not repository artifacts.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
import ast
import hashlib
import http.client
import importlib
import json
import os
from pathlib import Path
import pkgutil
import struct
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Only this test process is affected; never reuse a user's real game bindings.
for variable in ("FVP_STUDIO_HOSHI_BINDING", "FVP_STUDIO_ENGINE_PATTERNS", "FVP_STUDIO_TEST_ROOT"):
    os.environ.pop(variable, None)
from fvp_studio import local_binding as lb
from fvp_studio import engine_patterns as ep
from fvp_studio.gui_runtime import load_sources, GuiRuntime, GuiRuntimeError, Source
from fvp_studio.performance_install import checked_new_target
from fvp_studio.bin_archive import build_archive, archive_entry_table_file
from fvp_studio.adapters import load

def toy_texture(colour=30):
    header = bytearray(44)
    header[:4] = b"hzc1"
    struct.pack_into("<I", header, 4, 8)
    header[12:16] = b"NVSG"
    struct.pack_into("<HHH", header, 18, 1, 2, 1)
    return bytes(header) + zlib.compress(bytes((colour, 20, 10, 255)) * 2)

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def config(self, sources):
        path = self.root / "sources.local.json"
        path.write_text(json.dumps(dict(schema="fvp-gui-runtime-sources/1", sources=sources)), encoding="utf-8")
        return path

    def toy_layout_gate(self, config):
        values = [config[key] for key in lb.FIELDS]
        digest = hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()
        return mock.patch.object(lb, "LAYOUT_DIGEST", digest)

    def test_all_modules_import_without_external_workspace(self):
        script = "import sys,pkgutil,importlib;sys.path.insert(0,sys.argv[1]);import fvp_studio;mods=[m.name for m in pkgutil.walk_packages(fvp_studio.__path__,fvp_studio.__name__+'.')];[importlib.import_module(m) for m in mods];assert not any(n in sys.modules for n in ('hzc_template_codec','build_bin_patch','inspect_assets','index_visual_assets'));print('ISOLATED_IMPORT',len(mods))"
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT)], cwd=self.root,
                                env=env, check=True, capture_output=True, text=True, encoding="utf-8")
        self.assertIn("ISOLATED_IMPORT", result.stdout)

    def test_empty_registration_requires_explicit_preview(self):
        path = self.config([])
        with self.assertRaises(GuiRuntimeError):
            load_sources(path)
        self.assertEqual(load_sources(path, allow_empty=True), [])
        with self.assertRaises(GuiRuntimeError):
            GuiRuntime([])

    def test_duplicate_source_id_rejected(self):
        row = dict(id="demo", name="Demo", root=str(self.root), archive="graph.bin")
        with self.assertRaises(GuiRuntimeError):
            load_sources(self.config([row, row]))

    def test_sakura_display_correction_preserves_technical_id(self):
        row = dict(id="sakura", name="樱花开了", root=str(self.root), archive="graph.bin")
        source = load_sources(self.config([row]))[0]
        self.assertEqual((source.id, source.name), ("sakura", "樱花萌放"))

    def test_missing_hoshi_binding_rejected(self):
        with self.assertRaisesRegex(ValueError, "本机接入绑定"):
            lb.require_binding()
        with self.assertRaises(ValueError):
            lb.validate_binding(json.loads((ROOT / "examples/hoshi_binding.example.json").read_text()))

    def test_read_access_time_change_is_not_content_drift(self):
        from types import SimpleNamespace
        fields = dict(st_dev=1, st_ino=2, st_mode=3, st_nlink=1, st_size=10,
                      st_mtime_ns=100, st_ctime_ns=200, st_file_attributes=0,
                      st_atime_ns=300)
        before = SimpleNamespace(**fields)
        after_read = SimpleNamespace(**{**fields, "st_atime_ns": 400})
        after_write = SimpleNamespace(**{**fields, "st_mtime_ns": 101})
        self.assertEqual(lb.stat_identity(before), lb.stat_identity(after_read))
        self.assertNotEqual(lb.stat_identity(before), lb.stat_identity(after_write))

    def toy_binding(self):
        folder = self.root / "synthetic-source"
        folder.mkdir()
        code = bytes((1, 0, 0, 12, 1, 11, 2, 0, 0, 0, 0, 0))
        body = struct.pack("<I", 4 + len(code)) + code + struct.pack("<IHHBB", 4, 0, 0, 0, 0) + bytes((0,)) + struct.pack("<HH", 0, 0)
        files = {".Hoshimemo_HD.hcb": body, "Hoshimemo_HD.hcb": body, "Hoshimemo_HD.exe": b"synthetic-non-executable-fixture"}
        for name, data in files.items():
            (folder / name).write_bytes(data)
        gates = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        config = dict(schema=lb.SCHEMA, source_root=str(folder), entry_offset=7,
                      continue_offset=13, resume_start=4, resume_visible=12)
        return folder, files, gates, config, hashlib.sha256(body[7:12]).hexdigest()

    def test_binding_derives_expected_bytes_from_synthetic_local_file(self):
        folder, files, gates, config, digest = self.toy_binding()
        with mock.patch.object(lb, "SUPPORTED", gates), mock.patch.object(lb, "ENTRY_DIGEST", digest), self.toy_layout_gate(config):
            binding = lb.validate_binding(config)
            self.assertEqual(binding.entry_bytes, files[".Hoshimemo_HD.hcb"][7:12])
            binding.verify(root=folder, source=files[".Hoshimemo_HD.hcb"], clean=files["Hoshimemo_HD.hcb"])

    def test_binding_rejects_instruction_boundary_and_digest_mismatch(self):
        _folder, _files, gates, config, digest = self.toy_binding()
        with mock.patch.object(lb, "SUPPORTED", gates), mock.patch.object(lb, "ENTRY_DIGEST", digest), self.toy_layout_gate(config):
            with self.assertRaises(ValueError):
                lb.validate_binding({**config, "entry_offset": 8})
            with mock.patch.object(lb, "ENTRY_DIGEST", "0" * 64), self.assertRaises(ValueError):
                lb.validate_binding(config)

    def test_binding_rejects_mother_and_config_drift(self):
        folder, files, gates, config, digest = self.toy_binding()
        path = self.root / "binding.local.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        with mock.patch.object(lb, "SUPPORTED", gates), mock.patch.object(lb, "ENTRY_DIGEST", digest), self.toy_layout_gate(config):
            binding = lb.load_binding(path)
            (folder / "Hoshimemo_HD.exe").write_bytes(b"different synthetic fixture")
            with self.assertRaises(ValueError):
                binding.verify()
            (folder / "Hoshimemo_HD.exe").write_bytes(files["Hoshimemo_HD.exe"])
            path.write_text(json.dumps({**config, "entry_offset": 8}), encoding="utf-8")
            with self.assertRaises(ValueError):
                binding.verify()

    def test_binding_bool_offsets_and_unknown_fields_rejected(self):
        _folder, _files, _gates, config, _digest = self.toy_binding()
        with self.assertRaises(ValueError):
            lb.validate_binding({**config, "entry_offset": True})
        with self.assertRaises(ValueError):
            lb.validate_binding({**config, "extra": 1})

    def test_unconfigured_or_changed_engine_pattern_rejected(self):
        with self.assertRaises(ValueError):
            ep.engine_pattern(next(iter(ep.APPROVED)))
        with self.assertRaises(ValueError):
            ep.validate_patterns(dict(schema=ep.SCHEMA, patterns={"unknown": "00"}))
        with self.assertRaises(ValueError):
            ep.validate_patterns(dict(schema=ep.SCHEMA, patterns={next(iter(ep.APPROVED)): "00"}))

    def test_exact_local_pattern_and_missing_key(self):
        toy = b"synthetic-regex-only"
        path = self.root / "patterns.local.json"
        path.write_text(json.dumps(dict(schema=ep.SCHEMA, patterns={"toy": toy.hex()})), encoding="utf-8")
        with mock.patch.object(ep, "APPROVED", {"toy": hashlib.sha256(toy).hexdigest()}), mock.patch.dict(os.environ, FVP_STUDIO_ENGINE_PATTERNS=str(path)):
            ep._read.cache_clear()
            self.assertEqual(ep.engine_pattern("toy"), toy)
            with self.assertRaises(ValueError):
                ep.engine_pattern("missing")
        ep._read.cache_clear()

    def test_new_copy_gate_never_creates_and_rejects_existing(self):
        source, parent = self.root / "source", self.root / "copies"
        source.mkdir(); parent.mkdir()
        target = parent / "new"
        self.assertEqual(checked_new_target(source, target, parent), target)
        self.assertFalse(target.exists())
        target.mkdir()
        with self.assertRaises(ValueError):
            checked_new_target(source, target, parent)

    def test_source_overlap_and_wrong_parent_rejected(self):
        source, parent = self.root / "source", self.root / "copies"
        source.mkdir(); parent.mkdir()
        for target, gate in ((source / "child", source), (self.root / "outside", parent), (source, parent)):
            with self.assertRaises(ValueError):
                checked_new_target(source, target, gate)

    def test_symlink_or_junction_target_rejected(self):
        source, parent = self.root / "source", self.root / "copies"
        source.mkdir(); parent.mkdir()
        try:
            (parent / "link").symlink_to(source, target_is_directory=True)
        except OSError:
            self.skipTest("Host cannot create a synthetic symlink")
        with self.assertRaises(ValueError):
            checked_new_target(source, parent / "link", parent)

    def test_atomic_reservation_stops_before_copy(self):
        from fvp_studio import performance_install as installer
        target = self.root / "already-there"
        target.mkdir()
        checked = dict(outputs=object(), source=self.root, target=target, protect=mock.Mock())
        with mock.patch.object(installer, "preflight", return_value=checked), mock.patch.object(installer.subprocess, "run") as run:
            with self.assertRaises(FileExistsError):
                installer.install(self.root, target)
            run.assert_not_called()

    def test_reparse_metadata_is_rejected_without_host_symlink_privilege(self):
        from fvp_studio.performance_install import _safe
        original = Path.lstat
        def attributes(path):
            if path == self.root:
                value = mock.Mock(st_mode=0, st_file_attributes=0x400)
                return value
            return original(path)
        with mock.patch.object(Path, "lstat", attributes), self.assertRaises(ValueError):
            _safe(self.root)

    def test_launcher_rejects_workspace_source_overlap(self):
        from fvp_studio.__main__ import checked_workspaces
        source = Source("demo", "Demo", self.root, "graph.bin")
        with self.assertRaises(ValueError):
            checked_workspaces([source], [self.root / "output"])

    def toy_archive(self):
        folder = self.root / "read-only-fixture"
        folder.mkdir()
        path = folder / "graph.bin"
        path.write_bytes(build_archive([("BG_DEMO", toy_texture()), ("CHR_DEMO", toy_texture(50))]))
        return path

    def test_bundled_bin_profile_and_hzc_interfaces(self):
        archive = self.toy_archive()
        from fvp_studio.profile import ProjectIndex, adapter_root_dir
        self.assertTrue(adapter_root_dir().is_relative_to(ROOT))
        index = ProjectIndex.from_game_dir(archive.parent)
        self.assertEqual(len(index.assets), 2)
        self.assertEqual(load("hzc_template_codec").metadata(toy_texture())["width"], 2)
        with self.assertRaises(ValueError):
            load("not-an-adapter")

    def test_stream_rebuild_is_new_only_and_keeps_source_unchanged(self):
        archive = self.toy_archive()
        original = archive.read_bytes()
        workspace = self.root / "workspace"
        workspace.mkdir()
        replacement = workspace / "replacement.hzc"
        replacement.write_bytes(toy_texture(90))
        builder = load("build_bin_patch")
        target = workspace / "rebuilt.bin"
        builder.build(archive, {0: replacement}, target)
        self.assertEqual(archive.read_bytes(), original)
        self.assertEqual(len(archive_entry_table_file(target)), 2)
        with self.assertRaises(ValueError):
            builder.build(archive, {0: replacement}, target)
        with self.assertRaises(ValueError):
            builder.build(archive, {0: replacement}, archive.parent / "new.bin")
        with self.assertRaises(ValueError):
            builder.build(archive, {True: replacement}, workspace / "invalid.bin")

    def test_extract_new_only_and_existing_output_refused(self):
        archive = self.toy_archive()
        output = self.root / "workspace" / "one.hzc"
        load("extract_bin_entry").extract(archive, 0, output)
        self.assertEqual(output.read_bytes(), toy_texture())
        with self.assertRaises(ValueError):
            load("extract_bin_entry").extract(archive, 0, output)

    def test_template_cache_reuse_requires_exact_identity(self):
        from fvp_studio.resource_builder import _entry_template
        archive = self.toy_archive()
        workspace = self.root / "templates"
        target = _entry_template(archive, 0, workspace)
        before = target.stat().st_mtime_ns
        self.assertEqual(_entry_template(archive, 0, workspace), target)
        self.assertEqual(target.stat().st_mtime_ns, before)
        target.write_bytes(b"changed synthetic cache")
        with self.assertRaises(ValueError):
            _entry_template(archive, 0, workspace)

    def test_loopback_empty_server_html_health_and_host_gate(self):
        from fvp_studio.gui_cinematic_server import CinematicRuntime, CinematicServer
        from fvp_studio.gui_scene_export import SceneExporter
        from fvp_studio.gui_chapter_export import ChapterExporter
        class EmptyRuntime(CinematicRuntime):
            allow_empty_sources = True
        for name in ("audio", "output", "copies"):
            (self.root / name).mkdir()
        runtime = EmptyRuntime([], self.root / "audio")
        server = CinematicServer(("127.0.0.1", 0), runtime,
                                 ROOT / "web/fvp_story_studio_prototype.html", self.root / "output",
                                 exporter=SceneExporter(runtime, self.root / "output", test_parent=self.root / "copies"),
                                 chapter_exporter=ChapterExporter(runtime, self.root / "output", test_parent=self.root / "copies"))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            connection.request("GET", "/api/gui-runtime/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            health = json.loads(response.read())
            self.assertTrue(health["ok"])
            self.assertEqual(health["sources"], [])
            connection.request("GET", "/fvp_story_studio_prototype.html")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), (ROOT / "web/fvp_story_studio_prototype.html").read_bytes())
            connection.request("GET", "/api/gui-runtime/health", headers={"Host": "untrusted.invalid"})
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read(); connection.close()
        finally:
            server.shutdown(); thread.join(timeout=5); server.server_close()

    def test_real_launcher_starts_outside_checkout_without_games(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        self.assertNotIn(port, (18815, 18816))
        entry = "import sys;sys.path.insert(0,sys.argv.pop(1));from fvp_studio.__main__ import main;main()"
        command = [sys.executable, "-I", "-B", "-c", entry, str(ROOT),
                   "--sources", str(ROOT / "sources.example.json"), "--empty-preview",
                   "--html", str(ROOT / "web/fvp_story_studio_prototype.html"),
                   "--output-root", str(self.root / "output"), "--audio-root", str(self.root / "audio"),
                   "--test-root", str(self.root / "copies"), "--port", str(port)]
        child = subprocess.Popen(command, cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            deadline = time.monotonic() + 8
            ready = False
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    out, err = child.communicate()
                    self.fail((out + err).decode("utf-8", errors="replace"))
                try:
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
                    connection.request("GET", "/api/gui-runtime/health")
                    response = connection.getresponse()
                    ready = response.status == 200 and json.loads(response.read())["ok"] is True
                    connection.close()
                    if ready:
                        break
                except OSError:
                    time.sleep(0.05)
            self.assertTrue(ready, "Explicit empty-source launcher failed to start")
            self.assertEqual(list((self.root / "copies").iterdir()), [])
        finally:
            if child.poll() is None:
                child.terminate()
            child.communicate(timeout=5)

if __name__ == "__main__":
    unittest.main()
