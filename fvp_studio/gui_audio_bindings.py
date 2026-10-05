"""Registered/local audio imports: generic references, target-owned bindings.

IDs in another game are not IDs in the target. The known Hoshi adapter allocates
new entries and reuses the existing streamed additive archive/conversion path.
The read-only plan never writes files or pretends a pack has been built.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import shutil

from .bin_archive import append_entries_file
from .gui_runtime import GuiRuntimeError, fingerprint
from .hoshimemo_audio_compile import (_allocate_names, _numeric_names, _prepare_payload,
                                      _select_bgm_archive)

SCHEMA = "fvp-gui-audio-bindings/1"
MAX_IMPORTED = 128


def asset_key(event):
    return tuple(event[k] for k in ("source", "archive", "resource", "sha256"))


def direct_id(source, archive, resource):
    if source != "hoshi" or not resource.isascii() or not resource.isdigit():
        return None
    value = int(resource)
    if archive not in ("bgm.bin", "bgm2.bin", "se.bin"):
        return None
    if archive == "se.bin" and resource != str(value).zfill(3):
        # Native SE uses IntToText(id, 3); a differently padded exact name
        # needs an additive alias, not a call to an absent filename.
        return None
    if archive == "bgm.bin" and not 1 <= value < 1000:
        return None
    if archive == "bgm2.bin":
        value += 1000
    return value if 1 <= value <= 0x7FFFFFFF else None


class GuiAudioBindings:
    def __init__(self, target_root, frozen):
        self.root, self.frozen = Path(target_root).resolve(strict=True), frozen
        self.bindings, self.groups = {}, {}
        imported = {"bgm": {}, "se": {}, "voice": {}}
        for key, asset in sorted(frozen.audios.items()):
            if asset.get("native_id") is not None:
                self.bindings[key] = dict(asset, target_archive=asset["archive"], target_resource=asset["resource"],
                                          imported=False)
                continue
            kind = asset.get("kind")
            if kind not in imported:
                raise ValueError("这段声音尚未接通游戏输出。")
            # Reusing identical bytes in several scenes/sources is one entry,
            # but a BGM and an SE deliberately retain their different loaders.
            imported[kind].setdefault(key[3], []).append((key, asset))
        if sum(len(group) for group in imported.values()) > MAX_IMPORTED:
            raise ValueError("这章新增声音太多，请拆成较小章节。")
        for kind in ("bgm", "se", "voice"):
            assets = sorted(imported[kind].items())
            if not assets:
                continue
            names = ("bgm.bin", "bgm2.bin") if kind == "bgm" else ("voice.bin",) if kind == "voice" else ("se.bin",)
            stamps = {name: fingerprint(self.root / name) for name in names if (self.root / name).is_file()}
            if kind == "bgm":
                path, existing, maximum = _select_bgm_archive(self.root, len(assets))
            else:
                path = self.root / names[0]
                if path.is_symlink() or not path.is_file():
                    raise ValueError("目标游戏缺少这类声音的素材包。")
                existing, maximum = _numeric_names(path)
            if any(fingerprint(self.root / name) != stamp for name, stamp in stamps.items()):
                raise GuiRuntimeError("source_changed", "分配声音资源时原作发生变化。", 409)
            allocated = _allocate_names(path.name, existing, maximum, len(assets))
            # SE's 0x566E5..0x566E9 uses IntToText(id, 3). BGM uses
            # our explicit asset-path shim, not its original fixed ID table.
            width = 2 if kind == "bgm" else 7 if kind == "voice" else 3
            group = self.groups[path.name] = dict(path=path, stamp=stamps[path.name], items=[])
            frozen.references.append((path, stamps[path.name]))
            for (digest, references), (name, native_id) in zip(assets, allocated):
                name = name.zfill(width)
                binding = dict(native_id=native_id, target_archive=path.name, target_resource=name,
                               sha256=digest, kind=kind, imported=True)
                for key, asset in references:
                    self.bindings[key] = {**deepcopy(asset), **binding}
                group["items"].append(dict(key=references[0][0], resource=name, native_id=native_id,
                                           kind=kind, size=references[0][1]["size"], sha256=digest))

    def audio(self, event):
        return deepcopy(self.bindings[asset_key(event)])

    def report(self):
        return dict(schema=SCHEMA, target="hoshi", original_entries_replaced=False,
            pack_built=False, imports=[dict(kind=item["kind"], source=item["key"][0],
                source_archive=item["key"][1], source_resource=item["key"][2],
                target_archive=name, target_resource=item["resource"], native_id=item["native_id"],
                sha256=item["sha256"]) for name, group in self.groups.items() for item in group["items"]])

    def publish(self, folder, reader):
        """Publish only inside an internally reserved candidate directory."""
        if not self.groups:
            return {}, {}, {}, {}
        folder = Path(folder).resolve(strict=True)
        if self.root == folder or self.root in folder.parents or folder in self.root.parents:
            raise ValueError("声音候选目录不能与原作重叠。")
        self.frozen.check_unchanged()
        needed = sum(group["stamp"][3] + sum(i["size"] for i in group["items"]) * 3
                     for group in self.groups.values())
        if shutil.disk_usage(folder).free < needed + 256 * 1024 * 1024:
            raise ValueError("生成声音素材的空间不足，工程没有改变。")
        inputs = folder / "audio-inputs"
        inputs.mkdir(exist_ok=False)
        files, sources, outputs, reports = {}, {}, {}, {}
        for archive, group in self.groups.items():
            additions, conversions = {}, {}
            for item in group["items"]:
                sid, source_archive, resource, digest = item["key"]
                payload, info, _ref = reader.asset(sid, source_archive, resource, digest)
                if (info["kind"] != item["kind"] or len(payload) != item["size"]
                        or sha256(payload).hexdigest() != digest):
                    raise ValueError("声音来源发生变化，请重新选择。")
                source = inputs / (item["kind"] + "-" + digest + "." + info["format"])
                with source.open("xb") as stream:
                    stream.write(payload)
                prepared, conversion = _prepare_payload(dict(track="bgm" if item["kind"] == "voice" else item["kind"], format=info["format"],
                    payload_sha256=digest), source, folder)
                additions[item["resource"]] = prepared
                conversions[item["resource"]] = conversion
            result = append_entries_file(group["path"], folder / archive, additions)
            if fingerprint(group["path"]) != group["stamp"]:
                raise GuiRuntimeError("source_changed", "生成期间目标声音素材包发生变化，已停止。", 409)
            files[archive] = result.path
            sources[archive] = dict(size=result.source_size, sha256=result.source_sha256)
            outputs[archive] = dict(size=result.output_size, sha256=result.output_sha256,
                                    added_bytes=result.output_size-result.source_size)
            reports[archive] = {**result.validation_dict(), "conversions": conversions}
        self.frozen.check_unchanged()
        return files, sources, outputs, reports
