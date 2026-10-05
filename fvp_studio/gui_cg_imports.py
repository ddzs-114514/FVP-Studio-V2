"""Pack registered cross-game CGs into the target's owned event archive.

Source archive naming and target routing are separate. A legacy graph.bin CG
or graph_vis2 CG does not require a matching source archive in the target.
No image is resized and no original payload or original file is overwritten.
"""
from pathlib import Path

from .bin_archive import (append_hzc_entries, append_entries_file,
    archive_entry_names, archive_entry_table_file, hzc_metadata)
from .gui_runtime import fingerprint
from .performance_compile import GRAPH_VIS_SHA, sha

TARGET_ARCHIVE = "graph_vis.bin"
CONTRACT = "fvp-gui-cross-game-cg/1"


class GuiCgImports:
    def __init__(self, root, packs, *, streaming=False):
        self.root, self.packs = Path(root), packs
        self.streaming = streaming
        self.payloads = {}
        self.original_names = None
        self.source_stamp = None
        self.published = False

    def bind(self, payload, reference):
        if self.published:
            raise ValueError("CG 打包已结束，不能继续追加素材。")
        if reference["kind"] != 0 or reference["frame_count"] != 1:
            raise ValueError("只能导入完整的单帧 CG。")
        if sha(payload) != reference["payload_sha256"]:
            raise ValueError("CG 内容与来源记录不一致。")
        meta = hzc_metadata(payload).to_dict()
        if any(meta[k] != reference[k] for k in
               ("kind", "frame_count", "width", "height", "offset_x", "offset_y")):
            raise ValueError("CG 图片尺寸与来源记录不一致。")
        if self.original_names is None:
            path = self.root / TARGET_ARCHIVE
            if self.streaming:
                self.source_stamp = fingerprint(path)
                self.original_names = {row[2] for row in archive_entry_table_file(path)}
                self.check_unchanged()
            else:
                original = path.read_bytes()
                if sha(original) != GRAPH_VIS_SHA[TARGET_ARCHIVE]:
                    raise ValueError("目标 CG 资源包与原始版本不一致；不覆盖已有改动。")
                self.original_names = set(archive_entry_names(original))
                self.packs.source[TARGET_ARCHIVE] = original
                self.packs.archives[TARGET_ARCHIVE] = original
        name = "CG_GUI_" + sha(payload).upper()
        if name in self.original_names:
            raise ValueError("导入 CG 名称与目标已有素材冲突，拒绝覆盖。")
        if name in self.payloads and self.payloads[name] != payload:
            raise ValueError("导入 CG 内容标识冲突。")
        self.payloads[name] = payload
        return name

    def finish(self):
        if not self.payloads or self.streaming:
            return
        built = append_hzc_entries(self.packs.source[TARGET_ARCHIVE], self.payloads)
        self.packs.archives[TARGET_ARCHIVE] = built.data
        self.packs.reports.append(dict(kind="gui_cross_game_cg", schema=CONTRACT,
            target_archive=TARGET_ARCHIVE, image_resampled=False,
            source_payload_preserved_exactly=True, **built.validation_dict()))

    def check_unchanged(self):
        if self.source_stamp is not None and fingerprint(self.root / TARGET_ARCHIVE) != self.source_stamp:
            raise ValueError("打包期间目标 CG 素材发生变化，已停止。")

    def publish(self, directory):
        """Write a new candidate in bounded chunks, never load the target BIN.

        Directory selection belongs to the exporter. The original hash is
        computed during the copy; a mismatch keeps the candidate for diagnosis
        but cannot reach the game's installer.
        """
        if not self.streaming:
            raise ValueError("只有分块打包模式可以发布 CG 文件。")
        if not self.payloads:
            return {}, {}, {}
        if self.published:
            raise ValueError("CG 素材包不能重复发布。")
        self.check_unchanged()
        result = append_entries_file(self.root / TARGET_ARCHIVE,
            Path(directory) / TARGET_ARCHIVE, self.payloads)
        self.check_unchanged()
        if result.source_sha256 != GRAPH_VIS_SHA[TARGET_ARCHIVE]:
            raise ValueError("目标 CG 素材包与原始版本不一致，生成文件已保留但不会安装。")
        self.published = True
        self.packs.reports.append(dict(kind="gui_cross_game_cg", schema=CONTRACT,
            target_archive=TARGET_ARCHIVE, image_resampled=False,
            source_payload_preserved_exactly=True, streaming=True,
            **result.validation_dict()))
        return ({TARGET_ARCHIVE: result.path},
            {TARGET_ARCHIVE: dict(size=result.source_size, sha256=result.source_sha256)},
            {TARGET_ARCHIVE: dict(size=result.output_size, sha256=result.output_sha256,
                added_bytes=result.output_size-result.source_size)})
