"""Additive graphics packs bound to a target's discovered native routes.

Names in an imported game are never looked up in the target game. Only the
selected HZC payload is copied, without resizing or altering its geometry.
Target BINs are streamed into new candidate files; originals remain read-only.
This packer does not infer native call signatures or enable unsupported effects.
"""
from __future__ import annotations

from pathlib import Path

from .bin_archive import append_entries_file, archive_entry_table_file, hzc_metadata
from .gui_runtime import fingerprint
from .performance_compile import resource_reference, sha
from .performance_install import _safe


SCHEMA = "fvp-native-graphics-imports/1"


def default_archive(routes):
    """Use the proven native fallthrough/zero route, not a title-name switch."""
    if not routes:
        raise ValueError("目标没有已接通的原生素材路由。")
    for selector in (None, 0):
        names = [name for name, value in routes.items() if value == selector]
        if len(names) == 1:
            return names[0]
        if len(names) > 1:
            raise ValueError("目标默认素材路由不唯一，不能猜测资源包。")
    if len(routes) == 1:
        return next(iter(routes))
    raise ValueError("目标没有唯一默认素材路由，不能猜测资源包。")


class NativeGraphicsImports:
    def __init__(self, root, routes):
        self.root = _safe(Path(root))
        self.routes = {}
        for role, values in routes.items():
            bound = {}
            for name, selector in values.items():
                if (not isinstance(name, str) or Path(name).name != name
                        or any(c in name for c in ("/", "\\", ":", "\0"))
                        or Path(name).suffix.casefold() != ".bin"):
                    raise ValueError("原生素材路由不是游戏根目录的 BIN 文件。")
                if selector is not None and type(selector) is not int:
                    raise ValueError("原生素材路由 selector 无效。")
                bound[name.casefold()] = selector
            self.routes[role] = bound
        self.stamps, self.names, self.payloads = {}, {}, {}
        self.references, self.reports = [], []
        self.published = False

    def _freeze(self, path):
        path = _safe(Path(path), file=True, independent=False)
        current = fingerprint(path)
        if path in self.stamps and self.stamps[path] != current:
            raise ValueError("生成期间素材来源发生变化。")
        self.stamps[path] = current
        return path

    def _queue(self, archive, payloads):
        destination = self._freeze(self.root / archive)
        if archive not in self.names:
            self.names[archive] = {row[2] for row in archive_entry_table_file(destination)}
            self.check_unchanged()
        additions = self.payloads.setdefault(archive, {})
        # Check the entire body/face pair before adding either entry.
        for name, payload in payloads.items():
            if name in self.names[archive]:
                raise ValueError("导入素材名与目标已有资源冲突，不覆盖原资源。")
            if name in additions and additions[name] != payload:
                raise ValueError("导入素材内容标识冲突。")
        additions.update(payloads)

    def bind(self, role, archive_path, resource_name, *, target_archive=None):
        if self.published:
            raise ValueError("素材包已生成，不能再追加资源。")
        routes = self.routes.get(role, {})
        if not routes:
            raise ValueError("此类素材没有已接通的目标原生路由。")
        requested_archive = None if target_archive is None else str(target_archive).casefold()
        if requested_archive is not None and requested_archive not in routes:
            raise ValueError("导入目的资源包不在目标的原生路由中。")
        path = self._freeze(archive_path)
        payload, reference = resource_reference(path, resource_name)
        self.check_unchanged()
        meta = hzc_metadata(payload).to_dict()
        if role in {"background", "event_visual"}:
            if meta["kind"] != 0 or meta["frame_count"] != 1:
                raise ValueError("当前只支持完整单帧背景或 CG。")
        else:
            raise ValueError("未知的原生素材类型。")
        # A target-owned resource retains its original route and name.
        if (path.parent == self.root and path.name.casefold() in routes
                and requested_archive in (None, path.name.casefold())):
            result = dict(reference, target_archive=path.name.casefold(),
                          target_resource_name=resource_name, imported=False)
            self.references.append(result)
            return result
        archive = default_archive(routes) if requested_archive is None else requested_archive
        if archive not in routes:
            raise ValueError("导入目的资源包不在目标的原生路由中。")
        name = "FVP_GUI_" + role.upper() + "_" + sha(payload).upper()
        self._queue(archive, {name: payload})
        result = dict(reference, target_archive=archive, target_resource_name=name,
                      imported=True, source_payload_preserved_exactly=True,
                      image_resampled=False, native_geometry_defaults_preserved=True)
        self.references.append(result)
        return result

    def bind_portrait_pair(self, archive_path, body_name, *, target_archive=None):
        """Keep native body/face geometry and one atomic, paired resource name.

        No source character height, face position, viewport or pixel data is
        normalized here. Alpha conversion, when needed, belongs to a separate
        target-proven loading adapter; this raw-payload pack is not that proof.
        """
        if self.published:
            raise ValueError("素材包已生成，不能再追加资源。")
        routes = self.routes.get("portrait", {})
        if not routes:
            raise ValueError("目标没有已接通的原生立绘资源路由。")
        requested_archive = None if target_archive is None else str(target_archive).casefold()
        if requested_archive is not None and requested_archive not in routes:
            raise ValueError("导入目的资源包不在目标的原生立绘路由中。")
        path = self._freeze(archive_path)
        body, body_ref = resource_reference(path, body_name)
        face_name = body_name + "_表情"
        face, face_ref = resource_reference(path, face_name)
        self.check_unchanged()
        if (body_ref["kind"] != 1 or body_ref["frame_count"] != 1
                or face_ref["kind"] != 2 or face_ref["frame_count"] < 1):
            raise ValueError("立绘须为单帧身体和对应的多帧表情，不使用整张背景替代。")
        if (path.parent == self.root and path.name.casefold() in routes
                and requested_archive in (None, path.name.casefold())):
            archive, name, imported = path.name.casefold(), body_name, False
        else:
            archive = default_archive(routes) if requested_archive is None else requested_archive
            if archive not in routes:
                raise ValueError("导入目的资源包不在目标的原生立绘路由中。")
            # Include BOTH payload hashes so changing just the expression
            # atlas cannot accidentally reuse an earlier character's pair.
            name = "FVP_GUI_PORTRAIT_" + sha((sha(body) + sha(face)).encode("ascii")).upper()
            self._queue(archive, {name: body, name + "_表情": face})
            imported = True
        result = dict(body=dict(body_ref, target_resource_name=name),
                      face=dict(face_ref, target_resource_name=name + "_表情"),
                      target_archive=archive, imported=imported,
                      expression_count=face_ref["frame_count"],
                      source_payload_preserved_exactly=True, image_resampled=False,
                      face_alignment_used=False, native_geometry_preserved=True,
                      target_alpha_conversion_performed=False,
                      native_loading_ready=False)
        self.references.append(result)
        return result

    def check_unchanged(self):
        for path, expected in self.stamps.items():
            if fingerprint(_safe(path, file=True, independent=False)) != expected:
                raise ValueError("生成期间素材来源或目标资源包发生变化。")

    def bind_portrait_loading(self, archive_path, body_name, loader, *, load_index=-1):
        """Queue the exact names referenced by a target-native carrier clone.

        Generic content names alone are not usable by a dispatcher that builds
        its resource path from root/action/outfit/form strings. Bind BOTH raw
        payloads to the compiled loader's names and original native namespace.
        Scene entry, native-size conversion and runtime acceptance are separate
        contracts; this does not enable unsupported GUI character output.
        """
        from .native_portrait_loading import NativePortraitLoading

        if self.published:
            raise ValueError("素材包已生成，不能再追加资源。")
        if (not isinstance(loader, NativePortraitLoading) or type(load_index) is not int
                or not -len(loader.loads) <= load_index < len(loader.loads)):
            raise ValueError("立绘打包缺少当前目标已编译的原生加载记录。")
        native_namespace = loader._record["resource_namespace"]
        archive = native_namespace.rstrip("/\\").casefold() + ".bin"
        if archive not in self.routes.get("portrait", {}):
            raise ValueError("立绘原生载体路径不在目标已接通的资源路由中。")
        load = loader.loads[load_index]
        path = self._freeze(archive_path)
        body, body_ref = resource_reference(path, body_name)
        face, face_ref = resource_reference(path, body_name + "_表情")
        self.check_unchanged()
        body_target, face_target = load["body_resource"], load["face_resource"]
        if (face_target != body_target + "_表情"
                or loader.payloads.get(body_target) != body
                or loader.payloads.get(face_target) != face
                or load["body_payload_sha256"] != sha(body)
                or load["face_payload_sha256"] != sha(face)):
            raise ValueError("立绘素材与当前加载代码引用的身体／表情不一致。")
        if (body_ref["kind"] != 1 or body_ref["frame_count"] != 1
                or face_ref["kind"] != 2 or face_ref["frame_count"] < 1):
            raise ValueError("立绘配对格式无效。")
        self._queue(archive, {body_target: body, face_target: face})
        result = dict(body=dict(body_ref, target_resource_name=body_target),
            face=dict(face_ref, target_resource_name=face_target),
            target_archive=archive, native_namespace=native_namespace,
            source_hcb_sha256=loader.source_sha256, actor_id=load["actor_id"],
            selector=load["selector"], clone_address=load["clone_address"], imported=True,
            expression_count=face_ref["frame_count"],
            source_payload_preserved_exactly=True, image_resampled=False,
            face_alignment_used=False, native_geometry_preserved=True,
            native_loading_bytecode_compiled=True, scene_export_connected=False,
            runtime_verified=False)
        self.references.append(result)
        return result

    def publish(self, directory):
        if self.published:
            raise ValueError("素材包不能重复生成。")
        directory = _safe(Path(directory))
        if directory == self.root or self.root in directory.parents:
            raise ValueError("素材候选不能生成到原作目录。")
        self.check_unchanged()
        files, sources, outputs = {}, {}, {}
        for archive, additions in sorted(self.payloads.items()):
            result = append_entries_file(self.root / archive, directory / archive, additions)
            self.check_unchanged()
            files[archive] = result.path
            sources[archive] = dict(size=result.source_size, sha256=result.source_sha256)
            outputs[archive] = dict(size=result.output_size, sha256=result.output_sha256)
            self.reports.append(dict(schema=SCHEMA, target_archive=archive,
                image_resampled=False, source_payload_preserved_exactly=True,
                game_name_switch_used=False, streaming=True, **result.validation_dict()))
        self.published = True
        return files, sources, outputs


class NativeExportResources:
    """Freeze both GUI-selected sources and target-bound graphics candidates."""
    def __init__(self, frozen, imports):
        self.frozen, self.imports = frozen, imports

    def check_unchanged(self):
        self.frozen.check_unchanged()
        self.imports.check_unchanged()
