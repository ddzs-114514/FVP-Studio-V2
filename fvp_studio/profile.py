"""Game-specific analysis indexes used by the generic FVP Studio UI.

The HCB reader stays game-agnostic.  A :class:`ProjectIndex` is an optional
profile layer: it consumes the indexes produced by the existing Hoshimemo
analysis tools and exposes dialogue/name/voice/visual associations without
pretending that static call-site order is story chronology.
"""

from __future__ import annotations

from collections import defaultdict
from collections import Counter
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable

from .hcb import HcbError

class ProfileError(HcbError):
    pass


# The indexer keeps the original, more granular category names.  The UI can
# still expose a small set of stable buckets without flattening different
# visual types into one list.
ASSET_CATEGORY_ALIASES: dict[str, frozenset[str]] = {
    "": frozenset(),
    "all": frozenset(),
    "other": frozenset({"graph_misc", "misc_visual", "other"}),
    "visual": frozenset({"portrait", "background", "event_visual", "cutscene_visual"}),
}

JUMP_STATE_REQUIREMENTS = (
    "text_initialized",
    "scene_initialized",
    "effects_cleaned",
    "stack_valid",
    "runtime_verified",
)


def _asset_category_matches(actual: Any, requested: str) -> bool:
    requested = requested.casefold().strip()
    if not requested or requested in {"all", "全部资源类别"}:
        return True
    normalized = str(actual or "").casefold().strip()
    aliases = ASSET_CATEGORY_ALIASES.get(requested)
    if aliases is not None:
        return normalized in aliases
    return normalized == requested


def adapter_root_dir() -> Path:
    """Return the bundled self-written interfaces, without workspace search."""
    return Path(__file__).resolve().parent / "adapters"


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"无法读取索引 {path}: {exc}") from exc


def _public(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if not key.startswith("_")}


class ProjectIndex:
    """A lazily optional profile loaded from one analysis-index directory."""

    def __init__(self, index_dir: Path) -> None:
        self.index_dir = index_dir.expanduser().resolve()
        if not self.index_dir.is_dir():
            raise ProfileError(f"索引目录不存在: {self.index_dir}")

        dataset = _read_json(self.index_dir / "editor_dataset.json", {})
        records = dataset.get("records", []) if isinstance(dataset, dict) else []
        if not isinstance(records, list):
            raise ProfileError("editor_dataset.json 的 records 不是数组")

        runtime_by_offset: dict[int, dict[str, Any]] = {}
        runtime_path = self.index_dir.parent / "build" / "runtime_names" / "japanese_fvp_names.lines.jsonl"
        if runtime_path.is_file():
            for line in runtime_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    runtime_by_offset[int(item["opcode_addr"])] = item
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    continue

        self.records: list[dict[str, Any]] = []
        self.by_offset: dict[int, dict[str, Any]] = {}
        for source in records:
            try:
                offset = int(source["slot_offset"])
            except (KeyError, TypeError, ValueError):
                continue
            runtime = runtime_by_offset.get(offset, {})
            record = dict(source)
            record["slot_offset"] = offset
            record["original_text"] = runtime.get("message", record.get("original_text", ""))
            record["name"] = runtime.get("name", record.get("name", ""))
            record["raw_name"] = runtime.get("fvp_raw_name", record.get("raw_name", ""))
            record["speaker_function"] = runtime.get("speaker_function", record.get("speaker_function"))
            record["dialogue"] = bool(runtime) or bool(record.get("dialogue", False))
            record["id"] = record.get("id", f"hcb:0x{offset:06X}")
            record["_haystack"] = " ".join(
                str(record.get(key, ""))
                for key in ("id", "original_text", "current_text", "name", "raw_name", "kind", "slot_offset")
            ).casefold()
            record["_name_haystack"] = " ".join(
                str(record.get(key, "")) for key in ("name", "raw_name")
            ).casefold()
            self.records.append(record)
            self.by_offset[offset] = record
        self.records.sort(key=lambda item: item["slot_offset"])

        voice_data = _read_json(self.index_dir / "text_voice_links.json", {})
        hidden_data = _read_json(self.index_dir / "hidden_hcb_resource_index.json", {})
        self.voice_entries: dict[str, dict[str, Any]] = {}
        for archive in hidden_data.get("archives", []) if isinstance(hidden_data, dict) else []:
            archive_name = Path(str(archive.get("path", ""))).name
            if archive_name != "voice.bin":
                continue
            for asset in archive.get("assets", []):
                if isinstance(asset, dict):
                    self.voice_entries[str(asset.get("name", ""))] = {
                        "archive": archive_name,
                        "archive_index": asset.get("index"),
                    }
        self.voices_by_offset: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for link in voice_data.get("links", []) if isinstance(voice_data, dict) else []:
            try:
                item = dict(link)
                entry = self.voice_entries.get(str(item.get("voice_name", item.get("voice_id", ""))))
                if entry:
                    item.update(entry)
                self.voices_by_offset[int(item["text_slot_offset"])].append(item)
            except (KeyError, TypeError, ValueError):
                continue

        visual_data = _read_json(self.index_dir / "visual_resource_links.json", {})
        self.visuals_by_offset: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for link in visual_data.get("references", []) if isinstance(visual_data, dict) else []:
            try:
                self.visuals_by_offset[int(link["script_slot_offset"])].append(dict(link))
            except (KeyError, TypeError, ValueError):
                continue

        asset_data = _read_json(self.index_dir / "visual_asset_index.json", {})
        assets = asset_data.get("assets", []) if isinstance(asset_data, dict) else []
        self.assets: list[dict[str, Any]] = []
        for source in assets:
            if not isinstance(source, dict):
                continue
            item = dict(source)
            archive = str(item.get("archive", ""))
            entry_index = item.get("entry_index")
            item["asset_key"] = (
                f"{archive}#{entry_index}" if archive and entry_index is not None else str(item.get("resource_name", ""))
            )
            item["archive_entry"] = f"{archive}#{entry_index}" if archive and entry_index is not None else ""
            item["archive_offset_hex"] = (
                f"0x{int(item['archive_offset']):X}"
                if item.get("archive_offset") is not None else ""
            )
            self.assets.append(item)
        self.assets_by_name = {str(item.get("resource_name", "")).casefold(): item for item in self.assets}
        self.resource_map = _read_json(self.index_dir / "hcb_resource_call_map.json", {})
        recipes_data = _read_json(self.index_dir / "jump_recipes.json", {})
        recipes = recipes_data.get("recipes", []) if isinstance(recipes_data, dict) else []
        self.jump_recipes: list[dict[str, Any]] = []
        for source in recipes:
            if not isinstance(source, dict) or not source.get("id"):
                continue
            item = dict(source)
            item["id"] = str(item["id"])
            item["label"] = str(item.get("label", item["id"]))
            item["query"] = [str(value) for value in item.get("query", []) if value is not None]
            item["verification_status"] = str(item.get("verification_status", "unverified"))
            contract_source = item.get("state_contract", {})
            contract = dict(contract_source) if isinstance(contract_source, dict) else {}
            item["state_contract"] = {
                key: bool(contract.get(key, False)) for key in JUMP_STATE_REQUIREMENTS
            }
            item["missing_requirements"] = [
                key for key in JUMP_STATE_REQUIREMENTS if not item["state_contract"][key]
            ]
            hashes = item.get("source_sha256", [])
            if isinstance(hashes, str):
                hashes = [hashes]
            item["source_sha256"] = [
                str(value).strip().casefold()
                for value in hashes
                if len(str(value).strip()) == 64
            ]
            result_sha256 = str(item.get("result_sha256", "")).strip().casefold()
            item["result_sha256"] = result_sha256 if len(result_sha256) == 64 else ""
            normalized_patches: list[dict[str, Any]] = []
            for patch in item.get("patches", []):
                if not isinstance(patch, dict):
                    continue
                try:
                    offset = int(str(patch["offset"]), 0)
                except (KeyError, TypeError, ValueError):
                    continue
                expected = "".join(str(patch.get("expected_hex", "")).split()).upper()
                replacement = "".join(str(patch.get("replacement_hex", "")).split()).upper()
                patch_kind = str(patch.get("patch_type", "jump")).casefold()
                if not expected or len(expected) % 2:
                    continue
                normalized: dict[str, Any] = {
                    "offset": offset,
                    "offset_hex": f"0x{offset:X}",
                    "expected_hex": expected,
                    "patch_type": patch_kind,
                    "note": str(patch.get("note", "")),
                }
                if patch_kind == "bytes":
                    if len(replacement) != len(expected):
                        continue
                    normalized["replacement_hex"] = replacement
                else:
                    try:
                        target = int(str(patch["target"]), 0)
                    except (KeyError, TypeError, ValueError):
                        continue
                    normalized.update({
                        "target": target,
                        "target_hex": f"0x{target:X}",
                        "kind": str(patch.get("kind", "always")),
                    })
                normalized_patches.append(normalized)
            if not normalized_patches:
                continue
            item["patches"] = normalized_patches
            item["target_resource"] = str(item.get("target_resource", ""))
            item["installable"] = (
                item["verification_status"] == "runtime_verified"
                and not item["missing_requirements"]
                and bool(item["source_sha256"])
                and bool(item["result_sha256"])
            )
            self.jump_recipes.append(item)
        self.asset_data = asset_data if isinstance(asset_data, dict) else {}
        self.game_dir = Path(str(self.asset_data.get("game_dir", ""))).expanduser() if self.asset_data.get("game_dir") else None
        self.voice_data = voice_data if isinstance(voice_data, dict) else {}
        self.visual_data = visual_data if isinstance(visual_data, dict) else {}
        fingerprint_payload = {
            "record_offsets": [item["slot_offset"] for item in self.records],
            "asset_keys": [item.get("asset_key", "") for item in self.assets],
            "resource_map_opcode_end": self.resource_map.get("opcode_end"),
        }
        self.index_fingerprint = hashlib.sha256(
            json.dumps(fingerprint_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "index_dir": str(self.index_dir),
            "record_count": len(self.records),
            "dialogue_count": sum(1 for item in self.records if item.get("dialogue")),
            "voice_link_count": sum(len(items) for items in self.voices_by_offset.values()),
            "visual_link_count": sum(len(items) for items in self.visuals_by_offset.values()),
            "asset_count": len(self.assets),
            "jump_recipe_count": len(self.jump_recipes),
            "asset_categories": self.asset_data.get("category_counts", {}),
            "game_dir": str(self.game_dir) if self.game_dir is not None else None,
            "index_fingerprint": self.index_fingerprint,
        }

    def search_jump_recipes(self, query: str = "", limit: int = 50) -> dict[str, Any]:
        """Return audited, game-specific jump recipes matching a resource/name."""

        needle = str(query or "").casefold().strip()
        items: list[dict[str, Any]] = []
        for recipe in self.jump_recipes:
            haystack = " ".join([
                str(recipe.get("id", "")),
                str(recipe.get("label", "")),
                str(recipe.get("target_resource", "")),
                *[str(value) for value in recipe.get("query", [])],
            ]).casefold()
            if needle and needle not in haystack:
                continue
            public = {key: value for key, value in recipe.items() if not key.startswith("_")}
            items.append(public)
            if len(items) >= max(1, min(int(limit), 200)):
                break
        return {"items": items, "total": len(items), "query": query}

    def compatibility_for(self, document: Any) -> dict[str, Any]:
        """Describe whether this optional index can safely edit *document*.

        The Chinese Hoshimemo overlay is not a fresh linear HCB program: its
        original instruction boundaries must come from the Japanese source.
        A large unknown-opcode warning count or a string-count mismatch is a
        reliable signal that the generic parser would be unsafe to rebuild.
        Resource browsing remains available; only HCB mutation is guarded.
        """

        warning_count = len(getattr(document, "warnings", ()) or ())
        parsed_strings = int(getattr(document, "string_count", 0) or 0)
        expected_strings = len(self.records) if self.records else None
        reasons: list[str] = []
        if warning_count:
            reasons.append(f"HCB 解析产生 {warning_count:,} 个未知/失步警告")
        if expected_strings is not None and parsed_strings != expected_strings:
            reasons.append(f"字符串数量 {parsed_strings:,} 与索引 {expected_strings:,} 不一致")
        safe = not reasons
        return {
            "safe": safe,
            "reason": "；".join(reasons) if reasons else "HCB 与项目索引边界一致",
            "warning_count": warning_count,
            "parsed_string_count": parsed_strings,
            "expected_string_count": expected_strings,
            "source_sha256": getattr(document, "source_sha256", None),
            "index_dir": str(self.index_dir),
            "index_fingerprint": self.index_fingerprint,
        }

    def record_for_offset(self, offset: int) -> dict[str, Any] | None:
        record = self.by_offset.get(offset)
        if record is None:
            return None
        result = _public(record)
        result["voice_links"] = list(self.voices_by_offset.get(offset, ()))
        result["visual_links"] = list(self.visuals_by_offset.get(offset, ()))
        return result

    def search_text(
        self,
        query: str = "",
        speaker: str = "",
        dialogue_only: bool = False,
        offset: int = 0,
        limit: int = 200,
    ) -> dict[str, Any]:
        needle = query.casefold().strip()
        speaker_needle = speaker.casefold().strip()
        matches: list[dict[str, Any]] = []
        total = 0
        for record in self.records:
            if dialogue_only and not record.get("dialogue"):
                continue
            if needle and needle not in record["_haystack"]:
                continue
            if speaker_needle and speaker_needle not in record["_name_haystack"]:
                continue
            if total >= offset and len(matches) < limit:
                item = _public(record)
                item["voice_links"] = list(self.voices_by_offset.get(record["slot_offset"], ()))
                item["visual_links"] = list(self.visuals_by_offset.get(record["slot_offset"], ()))
                matches.append(item)
            total += 1
        return {"items": matches, "total": total, "offset": offset, "limit": limit}

    def search_assets(
        self,
        query: str = "",
        category: str = "",
        archive: str = "",
        offset: int = 0,
        limit: int = 200,
    ) -> dict[str, Any]:
        needle = query.casefold().strip()
        category = category.casefold().strip()
        archive = archive.casefold().strip()
        items: list[dict[str, Any]] = []
        total = 0
        for asset in self.assets:
            if not _asset_category_matches(asset.get("category", ""), category):
                continue
            if archive and str(asset.get("archive", "")).casefold() != archive:
                continue
            if needle and needle not in json.dumps(asset, ensure_ascii=False).casefold():
                continue
            if total >= offset and len(items) < limit:
                items.append(dict(asset))
            total += 1
        return {"items": items, "total": total, "offset": offset, "limit": limit}

    def links_for_offset(self, offset: int) -> dict[str, Any]:
        return {
            "offset": offset,
            "record": self.record_for_offset(offset),
            "voice_links": list(self.voices_by_offset.get(offset, ())),
            "visual_links": list(self.visuals_by_offset.get(offset, ())),
        }

    @classmethod
    def from_game_dir(cls, game_dir: Path) -> "ProjectIndex":
        """Build a generic visual-only profile from graph BIN headers.

        This path does not need a precomputed JSON index and works for other
        FVP games.  It reads archive tables and HZC headers only; script text
        and voice associations remain available when a game-specific profile
        is loaded later.
        """

        game_dir = game_dir.expanduser().resolve()
        if not game_dir.is_dir():
            raise ProfileError(f"游戏目录不存在: {game_dir}")
        try:
            from .adapters import load
            inspect_assets = load("inspect_assets")
            visual_index = load("index_visual_assets")
        except ImportError as exc:
            raise ProfileError(f"无法加载通用 BIN 索引器: {exc}") from exc
        allowed = {"graph.bin", "graph_bg.bin", "graph_bs.bin", "graph_vis.bin", "graph_vis1.bin", "graph_vis2.bin"}
        assets: list[dict[str, Any]] = []
        category_counts: Counter[str] = Counter()
        archive_counts: Counter[str] = Counter()
        type_counts: Counter[str] = Counter()
        for archive_path in sorted(game_dir.glob("graph*.bin")):
            if archive_path.name not in allowed:
                continue
            try:
                parsed = inspect_assets.parse_bin(archive_path)
                for source in parsed["assets"]:
                    metadata = visual_index.hzc_metadata(archive_path, source["offset"], source["size"])
                    category = visual_index.classify(archive_path.name, source["name"])
                    record = {
                        "resource_name": source["name"],
                        "archive": archive_path.name,
                        "entry_index": source["index"],
                        "archive_offset": source["offset"],
                        "size": source["size"],
                        "category": category,
                        "reference_count": 0,
                        "script_slots": [],
                        **metadata,
                    }
                    assets.append(record)
                    archive_counts[archive_path.name] += 1
                    category_counts[category] += 1
                    type_counts[metadata.get("type", "unknown")] += 1
            except (OSError, ValueError) as exc:
                raise ProfileError(f"扫描 {archive_path.name} 失败: {exc}") from exc
        # Generic FVP installations often have no precomputed dialogue/voice
        # index.  Still expose raw audio entries so a user can select an
        # OGG/WAV/MP3 resource and add it to a replacement plan directly.
        audio_prefixes = ("voice", "bgm", "se")
        for archive_path in sorted(game_dir.glob("*.bin")):
            lower_name = archive_path.name.casefold()
            if not lower_name.startswith(audio_prefixes) or lower_name.startswith("graph"):
                continue
            try:
                parsed = inspect_assets.parse_bin(archive_path)
                with archive_path.open("rb") as source:
                    for source_item in parsed["assets"]:
                        source.seek(source_item["offset"])
                        magic = source.read(12)
                        if magic.startswith(b"OggS"):
                            audio_type = "ogg"
                        elif magic.startswith(b"RIFF") and magic[8:12] == b"WAVE":
                            audio_type = "wav"
                        elif magic.startswith(b"ID3") or (len(magic) >= 2 and magic[0] == 0xFF and magic[1] & 0xE0 == 0xE0):
                            audio_type = "mp3"
                        elif magic.startswith(b"fLaC"):
                            audio_type = "flac"
                        else:
                            continue
                        record = {
                            "resource_name": source_item["name"],
                            "archive": archive_path.name,
                            "entry_index": source_item["index"],
                            "archive_offset": source_item["offset"],
                            "size": source_item["size"],
                            "category": "audio",
                            "reference_count": 0,
                            "script_slots": [],
                            "container": audio_type,
                            "type": audio_type,
                            "frame_count": 1,
                        }
                        assets.append(record)
                        archive_counts[archive_path.name] += 1
                        category_counts["audio"] += 1
                        type_counts[audio_type] += 1
            except (OSError, ValueError) as exc:
                raise ProfileError(f"扫描 {archive_path.name} 失败: {exc}") from exc
        obj = cls.__new__(cls)
        obj.index_dir = game_dir
        obj.records = []
        obj.by_offset = {}
        obj.voices_by_offset = defaultdict(list)
        obj.visuals_by_offset = defaultdict(list)
        obj.voice_entries = {}
        obj.jump_recipes = []
        obj.assets = []
        for source in assets:
            item = dict(source)
            archive = str(item.get("archive", ""))
            entry_index = item.get("entry_index")
            item["asset_key"] = (
                f"{archive}#{entry_index}" if archive and entry_index is not None else str(item.get("resource_name", ""))
            )
            item["archive_entry"] = f"{archive}#{entry_index}" if archive and entry_index is not None else ""
            item["archive_offset_hex"] = (
                f"0x{int(item['archive_offset']):X}"
                if item.get("archive_offset") is not None else ""
            )
            obj.assets.append(item)
        obj.assets_by_name = {str(item.get("resource_name", "")).casefold(): item for item in obj.assets}
        obj.resource_map = {}
        obj.asset_data = {
            "game_dir": str(game_dir),
            "asset_count": len(assets),
            "archive_counts": dict(archive_counts),
            "category_counts": dict(category_counts),
            "type_counts": dict(type_counts),
        }
        obj.game_dir = game_dir
        obj.voice_data = {}
        obj.visual_data = {}
        fingerprint_payload = {
            "record_offsets": [],
            "asset_keys": [item.get("asset_key", "") for item in obj.assets],
            "resource_map_opcode_end": None,
        }
        obj.index_fingerprint = hashlib.sha256(
            json.dumps(fingerprint_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        return obj


def default_index_dir() -> Path:
    configured = os.environ.get("FVP_STUDIO_INDEX_DIR", "").strip()
    return Path(configured).expanduser().resolve() if configured else adapter_root_dir() / "index"
