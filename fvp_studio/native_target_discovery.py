"""Read-only discovery of FVP game targets and native script capabilities.

The visual workspaces are intentionally game-agnostic.  Native HCB emission is
not: private wrapper addresses, active translated overlays and scene lifecycle
rules can differ between titles even when their ``FVPKernel.dll`` is identical.

This module bridges those two facts without adding one Python branch per game.
It inspects a game root, selects a clean analysis HCB conservatively, indexes
native function *shapes* with call addresses removed, and returns a serialisable
capability manifest.  Discovery is always read-only and never enables writes;
an installable target must later add reviewed dialogue, lifecycle and runtime
acceptance evidence to the generated profile seed.
"""

from __future__ import annotations

import copy
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import threading
from typing import Any, Iterable, Mapping, Sequence

from .bin_archive import BinArchiveError, archive_directory_identity_file
from .hcb import HcbDocument, HcbError, Instruction, normalize_encoding, parse_bytes


DISCOVERY_SCHEMA = "fvp-studio-v2.native-target-discovery.v1"
FUNCTION_INSPECTION_SCHEMA = "fvp-studio-v2.native-function-inspection.v1"
PROFILE_SEED_SCHEMA = "fvp-studio-v2.native-target-profile-seed.v1"
_DISCOVERY_CACHE_LIMIT = 16
_SCRIPT_SUFFIXES = frozenset({".hcb", ".bch"})
_DISCOVERY_INPUT_SUFFIXES = frozenset(
    {".hcb", ".bch", ".dll", ".exe", ".bin", ".bat", ".cmd"}
)
_DISCOVERY_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
_DISCOVERY_CACHE_LOCK = threading.Lock()


class NativeTargetDiscoveryError(HcbError):
    """Raised when a directory cannot be treated as an FVP target root."""


def _analysis_encoding(name: str) -> str:
    if not isinstance(name, str):
        raise NativeTargetDiscoveryError("分析脚本文本编码必须是字符串")
    try:
        return normalize_encoding(name)
    except HcbError as exc:
        raise NativeTargetDiscoveryError(str(exc)) from exc


@dataclass(frozen=True)
class _FunctionRegion:
    start: int
    end: int
    args: int
    locals: int
    instruction_count: int
    syscalls: tuple[str, ...]
    call_targets: tuple[int, ...]
    strings: tuple[str, ...]
    stack_reads: tuple[int, ...]
    instruction_start_index: int
    instruction_end_index: int
    structure_sha256: str

    def public(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "start_hex": f"0x{self.start:X}",
            "end": self.end,
            "end_hex": f"0x{self.end:X}",
            "args": self.args,
            "locals": self.locals,
            "instruction_count": self.instruction_count,
            "syscalls": list(self.syscalls),
            "call_count": len(self.call_targets),
            "string_count": len(self.strings),
            "stack_reads": list(self.stack_reads),
            "structure_sha256": self.structure_sha256,
        }


_GRAPH_VIS = re.compile(r"^graph_vis(?:\d+)?\.bin$", re.IGNORECASE)
_AUDIO_ARCHIVE = re.compile(r"^(?:voice|bgm|se)[^\\/]*\.bin$", re.IGNORECASE)
_RESOURCE_PATH = re.compile(r"^(?P<archive>graph_[^/]+)/", re.IGNORECASE)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _file_stat(path: Path, *, with_hash: bool = False) -> dict[str, Any]:
    stat = path.stat()
    result: dict[str, Any] = {
        "name": path.name,
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }
    if with_hash:
        result["sha256"] = _sha256_file(path)
    return result


def _root_files(root: Path) -> dict[str, Path]:
    return {
        item.name.casefold(): item
        for item in root.iterdir()
        if item.is_file() and not item.is_symlink()
    }


def _discovery_cache_key(
    root: Path,
    root_files: Mapping[str, Path],
) -> tuple[Any, ...]:
    """Fingerprint the root inputs that can affect read-only discovery.

    This is only a responsiveness cache. A future build/install path must hash
    its concrete inputs again immediately before writing.
    """

    records: list[tuple[str, int, int]] = []
    for folded_name, path in sorted(root_files.items()):
        if path.suffix.casefold() not in _DISCOVERY_INPUT_SUFFIXES:
            continue
        try:
            stat = path.stat()
        except OSError as exc:
            raise NativeTargetDiscoveryError(
                f"无法读取 FVP 目标文件状态 {path.name}: {exc}"
            ) from exc
        records.append((folded_name, int(stat.st_size), int(stat.st_mtime_ns)))
    return (str(root).casefold(), tuple(records))


def _cached_discovery(key: tuple[Any, ...]) -> dict[str, Any] | None:
    with _DISCOVERY_CACHE_LOCK:
        report = _DISCOVERY_CACHE.get(key)
        if report is None:
            return None
        # Callers may attach transient UI state to the returned JSON object.
        return copy.deepcopy(report)


def _store_cached_discovery(
    key: tuple[Any, ...],
    report: Mapping[str, Any],
) -> None:
    with _DISCOVERY_CACHE_LOCK:
        _DISCOVERY_CACHE[key] = copy.deepcopy(dict(report))
        while len(_DISCOVERY_CACHE) > _DISCOVERY_CACHE_LIMIT:
            oldest = next(iter(_DISCOVERY_CACHE))
            del _DISCOVERY_CACHE[oldest]


def _hcb_pair_key(name: str) -> str:
    return name.lstrip(".").casefold()


def _select_analysis_hcb(
    candidates: Sequence[Path],
    active_script_name: str | None = None,
) -> tuple[Path, str]:
    """Prefer the visible member of a same-stem hidden/visible HCB pair."""

    if active_script_name not in (None, ""):
        name = str(active_script_name).strip()
        if (
            not name
            or Path(name).name != name
            or Path(name).suffix.casefold() not in _SCRIPT_SUFFIXES
        ):
            raise NativeTargetDiscoveryError(
                "活动剧情脚本必须是根目录直属的 .hcb 或 .bch 文件名"
            )
        matches = [
            item for item in candidates if item.name.casefold() == name.casefold()
        ]
        if len(matches) != 1:
            raise NativeTargetDiscoveryError(
                "游戏根目录缺少明确指定的活动剧情脚本 "
                f"{name}；候选为: {', '.join(item.name for item in candidates)}"
            )
        return matches[0], "explicit_active_script"

    by_key: dict[str, list[Path]] = {}
    for candidate in candidates:
        by_key.setdefault(_hcb_pair_key(candidate.name), []).append(candidate)
    paired_visible = sorted(
        (
            item
            for values in by_key.values()
            if len(values) >= 2
            for item in values
            if not item.name.startswith(".")
        ),
        key=lambda item: item.name.casefold(),
    )
    if paired_visible:
        return paired_visible[0], "visible_member_of_hidden_overlay_pair"
    visible = sorted(
        (item for item in candidates if not item.name.startswith(".")),
        key=lambda item: item.name.casefold(),
    )
    if len(visible) == 1:
        return visible[0], "only_visible_root_hcb"
    if len(candidates) == 1:
        return candidates[0], "single_root_hcb"
    raise NativeTargetDiscoveryError(
        "根目录含多个无法配对的 HCB/BCH，不能自动选择原生分析来源: "
        + ", ".join(item.name for item in candidates)
    )


def _runtime_hcb_resolution(
    candidates: Sequence[Path],
    root_files: Mapping[str, Path],
    active_script_name: str | None = None,
) -> dict[str, Any]:
    by_key: dict[str, list[Path]] = {}
    for candidate in candidates:
        by_key.setdefault(_hcb_pair_key(candidate.name), []).append(candidate)
    pairs: list[dict[str, Any]] = []
    for key, values in sorted(by_key.items()):
        hidden = next((item for item in values if item.name.startswith(".")), None)
        visible = next((item for item in values if not item.name.startswith(".")), None)
        if hidden is not None and visible is not None:
            pairs.append(
                {
                    "pair_key": key,
                    "hidden": hidden.name,
                    "visible": visible.name,
                }
            )

    loader_present = "fvploadergui.exe" in root_files
    batch_evidence: list[str] = []
    for item in root_files.values():
        if item.suffix.casefold() not in {".bat", ".cmd"}:
            continue
        try:
            payload = item.read_bytes()[:65536]
        except OSError:
            continue
        text = payload.decode("utf-8", errors="replace")
        if "FVPLoaderGui" not in text:
            text = payload.decode("cp932", errors="replace")
        if "fvploadergui" in text.casefold():
            batch_evidence.append(item.name)

    if active_script_name not in (None, ""):
        name = str(active_script_name).strip()
        active = next(
            (
                item
                for item in candidates
                if item.name.casefold() == name.casefold()
            ),
            None,
        )
        if active is None:
            raise NativeTargetDiscoveryError(
                "活动剧情脚本不在发现候选中: "
                f"{name}；候选为: {', '.join(item.name for item in candidates)}"
            )
        return {
            "status": "explicit_active_script",
            "active_candidate": active.name,
            "candidates": [item.name for item in candidates],
            "pairs": pairs,
            "evidence": ["opened_document_exact_name"],
            "write_verified": False,
        }
    if len(candidates) == 1:
        return {
            "status": "unambiguous_by_layout",
            "active_candidate": candidates[0].name,
            "candidates": [candidates[0].name],
            "pairs": pairs,
            "evidence": ["single_root_hcb"],
            "write_verified": False,
        }
    if len(pairs) == 1 and len(candidates) == 2:
        evidence = ["same_stem_hidden_visible_pair"]
        if loader_present:
            evidence.append("fvploadergui_present")
        evidence.extend(f"launcher_script:{name}" for name in batch_evidence)
        return {
            # A leading-dot convention is strong discovery evidence but not a
            # substitute for a reviewed launcher/runtime trace.
            "status": "hidden_overlay_candidate",
            "active_candidate": pairs[0]["hidden"],
            "candidates": [item.name for item in candidates],
            "pairs": pairs,
            "evidence": evidence,
            "write_verified": False,
        }
    return {
        "status": "ambiguous",
        "active_candidate": None,
        "candidates": [item.name for item in candidates],
        "pairs": pairs,
        "evidence": ["multiple_root_hcbs"],
        "write_verified": False,
    }


def _archive_roles(root_files: Mapping[str, Path]) -> dict[str, Any]:
    def record(name: str) -> dict[str, Any] | None:
        path = root_files.get(name.casefold())
        return _file_stat(path) if path is not None else None

    event_visuals = [
        _file_stat(path)
        for name, path in sorted(root_files.items())
        if _GRAPH_VIS.fullmatch(name)
    ]
    audio = [
        _file_stat(path)
        for name, path in sorted(root_files.items())
        if _AUDIO_ARCHIVE.fullmatch(name)
    ]
    return {
        "mixed_visual": record("graph.bin"),
        "background": record("graph_bg.bin"),
        "portrait": record("graph_bs.bin"),
        "event_visual": event_visuals,
        "audio": audio,
        "background_preference": (
            "graph_bg.bin"
            if "graph_bg.bin" in root_files
            else "graph.bin" if "graph.bin" in root_files else None
        ),
        "portrait_preference": (
            "graph_bs.bin"
            if "graph_bs.bin" in root_files
            else "graph.bin" if "graph.bin" in root_files else None
        ),
    }


def _layout_classification(
    root_files: Mapping[str, Path],
    document: HcbDocument,
    archives: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify native FVP roots and conservative compatible layouts.

    A parseable HCB by itself is not enough: arbitrary files could happen to
    use the extension.  Without the native kernel/loader marker we require a
    visual archive plus the characteristic graph, primitive and motion syscall
    families.  Compatible-layout targets are admitted for read-only analysis
    only and receive an additional write blocker later in discovery.
    """

    native_markers = [
        name
        for name in ("fvpkernel.dll", "fvploadergui.exe")
        if name in root_files
    ]
    syscall_names = {item.name for item in document.header.syscalls}
    primitive_names = {"PrimSetXY", "PrimSetZ", "PrimSetRS", "PrimSetAlpha"}
    primitive_matches = sorted(primitive_names & syscall_names)
    motion_matches = sorted(
        name for name in syscall_names if name.startswith("Motion")
    )
    visual_archives = sorted(
        {
            str(record.get("name"))
            for key in ("mixed_visual", "background", "portrait")
            for record in [archives.get(key)]
            if isinstance(record, Mapping) and record.get("name")
        }
        | {
            str(record.get("name"))
            for record in archives.get("event_visual", [])
            if isinstance(record, Mapping) and record.get("name")
        },
        key=str.casefold,
    )
    if native_markers:
        return {
            "kind": "native_fvp",
            "confidence": "native_binary_marker",
            "native_binary_present": True,
            "native_markers": native_markers,
            "visual_archives": visual_archives,
            "primitive_syscalls": primitive_matches,
            "motion_syscall_count": len(motion_matches),
            "evidence": [f"native_marker:{name}" for name in native_markers],
        }
    compatible = (
        bool(visual_archives)
        and "GraphLoad" in syscall_names
        and len(primitive_matches) >= 3
        and bool(motion_matches)
    )
    if not compatible:
        raise NativeTargetDiscoveryError(
            "目录既无 FVPKernel.dll/FVPLoaderGui.exe，也未同时满足可解析 "
            "HCB、graph 视觉归档、GraphLoad、PrimSet 和 Motion 系统调用簇；"
            "不能作为 FVP 兼容目标"
        )
    return {
        "kind": "fvp_compatible_layout_candidate",
        "confidence": "structural_candidate",
        "native_binary_present": False,
        "native_markers": [],
        "visual_archives": visual_archives,
        "primitive_syscalls": primitive_matches,
        "motion_syscall_count": len(motion_matches),
        "evidence": [
            "parseable_hcb",
            "graph_visual_archive_present",
            "graphload_syscall_present",
            "primitive_syscall_cluster_present",
            "motion_syscall_cluster_present",
        ],
    }


def _instruction_token(
    instruction: Instruction,
    syscall_names: Mapping[int, str],
) -> str:
    mnemonic = instruction.mnemonic
    operands = instruction.operands
    if mnemonic == "syscall":
        return f"syscall:{syscall_names.get(int(operands.get('id', -1)), 'unknown')}"
    if mnemonic == "call":
        return "call:<target>"
    if mnemonic in {"jmp", "jz"}:
        target = int(operands.get("target", instruction.offset))
        direction = "forward" if target >= instruction.offset else "backward"
        return f"{mnemonic}:{direction}"
    if mnemonic == "push_string":
        text = str(instruction.text or "")
        match = _RESOURCE_PATH.match(text)
        return f"push_string:<{match.group('archive').casefold()}>" if match else "push_string:<text>"
    if mnemonic in {"push_stack", "pop_stack"}:
        return f"{mnemonic}:{int(operands.get('value', 0))}"
    if mnemonic.startswith("push_i"):
        return f"{mnemonic}:{int(operands.get('value', 0))}"
    if mnemonic in {
        "push_global",
        "pop_global",
        "push_global_table",
        "pop_global_table",
        "push_local_table",
        "pop_local_table",
    }:
        return f"{mnemonic}:<slot>"
    if mnemonic == "init_stack":
        return f"init_stack:{int(operands.get('args', 0))}:{int(operands.get('locals', 0))}"
    return mnemonic


def _function_regions(document: HcbDocument) -> list[_FunctionRegion]:
    instructions = document.instructions
    starts = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic == "init_stack"
    ]
    syscall_names = {
        index: syscall.name for index, syscall in enumerate(document.header.syscalls)
    }
    regions: list[_FunctionRegion] = []
    for position, start_index in enumerate(starts):
        end_index = starts[position + 1] if position + 1 < len(starts) else len(instructions)
        body = instructions[start_index:end_index]
        if not body:
            continue
        entry = body[0]
        syscalls = tuple(
            syscall_names.get(int(item.operands.get("id", -1)), "<unknown>")
            for item in body
            if item.mnemonic == "syscall"
        )
        calls = tuple(
            int(item.operands["target"])
            for item in body
            if item.mnemonic == "call" and "target" in item.operands
        )
        strings = tuple(
            str(item.text)
            for item in body
            if item.mnemonic == "push_string" and item.text
        )
        stack_reads = tuple(
            int(item.operands.get("value", 0))
            for item in body
            if item.mnemonic == "push_stack"
        )
        tokens = [_instruction_token(item, syscall_names) for item in body]
        end = (
            instructions[end_index].offset
            if end_index < len(instructions)
            else document.header.sysdesc_offset
        )
        regions.append(
            _FunctionRegion(
                start=int(entry.offset),
                end=int(end),
                args=int(entry.operands.get("args", 0)),
                locals=int(entry.operands.get("locals", 0)),
                instruction_count=len(body),
                syscalls=syscalls,
                call_targets=calls,
                strings=strings,
                stack_reads=stack_reads,
                instruction_start_index=start_index,
                instruction_end_index=end_index,
                structure_sha256=_canonical_sha256(tokens),
            )
        )
    return regions


def _matches(
    region: _FunctionRegion,
    *,
    args: int,
    locals: int,
    syscalls: Sequence[str],
) -> bool:
    return (
        region.args == args
        and region.locals == locals
        and region.syscalls == tuple(syscalls)
    )


def _discover_transform_family(regions: Sequence[_FunctionRegion]) -> dict[str, Any]:
    direct_xy = [
        region
        for region in regions
        if region.args == 3
        and region.locals == 2
        and region.syscalls.count("PrimSetXY") == 1
        and set(region.syscalls).issubset({"FloatToInt", "PrimSetXY"})
        and region.instruction_count <= 96
    ]
    families: list[dict[str, _FunctionRegion]] = []
    for index in range(max(0, len(regions) - 4)):
        group = regions[index : index + 5]
        if len(group) != 5:
            continue
        alpha, xy, z, scale, rotation = group
        if not _matches(
            alpha,
            args=8,
            locals=0,
            syscalls=("MotionAlpha", "MotionAlphaTest"),
        ):
            continue
        if not _matches(xy, args=10, locals=0, syscalls=("MotionMoveTest",)):
            continue
        if not _matches(
            z,
            args=8,
            locals=0,
            syscalls=("MotionMoveZ", "MotionMoveZTest"),
        ):
            continue
        if not _matches(
            scale,
            args=10,
            locals=0,
            syscalls=("MotionMoveS2", "MotionMoveS2Test"),
        ):
            continue
        if not _matches(
            rotation,
            args=8,
            locals=0,
            syscalls=("MotionMoveR", "MotionMoveRTest"),
        ):
            continue
        families.append(
            {
                "opacity": alpha,
                "xy": xy,
                "z": z,
                "scale": scale,
                "rotation": rotation,
            }
        )

    selected = families[0] if len(families) == 1 else None
    selected_public = (
        {name: region.public() for name, region in selected.items()}
        if selected is not None
        else None
    )
    return {
        "status": "verified_unique_structure" if selected is not None and len(direct_xy) == 1 else "ambiguous",
        "direct_xy_candidates": [item.public() for item in direct_xy],
        "motion_family_candidates": [
            {name: region.public() for name, region in family.items()}
            for family in families
        ],
        "selected": selected_public,
        "family_shape_sha256": (
            _canonical_sha256(
                {
                    name: region.structure_sha256
                    for name, region in selected.items()
                }
            )
            if selected is not None
            else None
        ),
    }


def _discover_portrait_dispatcher(
    regions: Sequence[_FunctionRegion],
    direct_xy_addresses: set[int],
) -> dict[str, Any]:
    required = {"PrimSetAlpha", "PrimSetZ", "PrimSetRS"}
    candidates: list[tuple[_FunctionRegion, list[str], str, str]] = []
    for region in regions:
        roots = sorted(
            {
                value
                for value in region.strings
                if value.casefold().startswith(
                    ("graph_bs/chr_", "graph/chr_")
                )
            }
        )
        if not roots:
            continue
        namespaces = {
            f"{value.split('/', 1)[0].casefold()}/"
            for value in roots
            if "/" in value
        }
        if len(namespaces) != 1:
            continue
        namespace = next(iter(namespaces))
        archive_name = _archive_name_for_namespace(namespace)
        if archive_name is None:
            continue

        counts = Counter(region.syscalls)
        if namespace == "graph_bs/" and region.args == 14:
            selector_count = counts["PartsAssign"]
            expected = Counter(GraphLoad=2, PartsLoad=1, PrimSetSprt=2,
                PrimSetBlend=1, PartsAssign=selector_count, PartsSelect=selector_count,
                PrimSetOP=6, PrimSetXY=2, PrimSetAlpha=2, PrimSetZ=8, PrimSetRS=8)
            if (region.locals != 17 or not 1 <= selector_count <= 64 or counts != expected
                    or not {-15, -11, -2}.issubset(region.stack_reads)):
                continue
            engine_variant = "composite_fvp"
            geometry_mode = "embedded_xy"
        elif namespace == "graph_bs/":
            if region.args != 13 or region.locals != 16:
                continue
            if not required.issubset(set(region.syscalls)):
                continue
            if direct_xy_addresses and not direct_xy_addresses.intersection(
                region.call_targets
            ):
                continue
            engine_variant = "modern_fvp"
            geometry_mode = "direct_xy_wrapper"
        elif namespace == "graph/" and region.args == 13:
            # Two observed native layouts use the same resource/runtime ABI,
            # but have different selector counts and one additional local.
            # Keep each complete syscall signature, rather than accepting
            # arbitrary counts or selecting a layout from a title string.
            selector_count = {(13, 15): 15, (13, 16): 20}.get(
                (region.args, region.locals)
            )
            if selector_count is None:
                continue
            expected = Counter(
                {
                    "GraphLoad": 1,
                    "PartsLoad": 1,
                    "PrimSetSprt": 1,
                    "PartsAssign": selector_count,
                    "PartsSelect": selector_count,
                    "PrimSetXY": 1,
                    "PrimSetAlpha": 1,
                    "PrimSetZ": 4,
                    "PrimSetRS": 4,
                    "PrimSetOP": 4,
                }
            )
            if (
                counts != expected
                or not {-14, -10}.issubset(region.stack_reads)
            ):
                continue
            engine_variant = "old_fvp"
            geometry_mode = "embedded_xy"
        elif namespace == "graph/" and region.args == 12:
            # Earlier FVP portrait dispatchers use the same four resource
            # selectors but expose eight runtime fields (there is no unused
            # registration-rotation placeholder).  Keep this as an exact
            # structural fingerprint instead of selecting it by game title.
            expected = Counter(
                {
                    "GraphLoad": 1,
                    "PartsLoad": 1,
                    "PartsAssign": 1,
                    "PrimSetSprt": 1,
                    "PartsSelect": 11,
                    "PrimSetOP": 3,
                    "PrimSetXY": 3,
                    "PrimSetAlpha": 1,
                    "PrimSetZ": 1,
                }
            )
            if (
                region.locals != 11
                or counts != expected
                or not {-13, -9}.issubset(region.stack_reads)
            ):
                continue
            engine_variant = "legacy_fvp"
            geometry_mode = "embedded_xy"
        else:
            continue
        candidates.append((region, roots, engine_variant, geometry_mode))
    public = []
    for region, roots, engine_variant, geometry_mode in candidates:
        namespace = f"{roots[0].split('/', 1)[0].casefold()}/"
        value = region.public()
        value.update(
            {
                "character_resource_roots": roots,
                "character_root_count": len(roots),
                "engine_variant": engine_variant,
                "geometry_mode": geometry_mode,
                "resource_namespace": namespace,
                "resource_archive_name": _archive_name_for_namespace(namespace),
                "portrait_output_compiler_abi_supported": region.args in {12, 13},
            }
        )
        public.append(value)
    return {
        "status": "verified_unique_structure" if len(public) == 1 else "ambiguous",
        "candidates": public,
        "selected": public[0] if len(public) == 1 else None,
    }


def _discover_visual_loader_family(regions: Sequence[_FunctionRegion]) -> dict[str, Any]:
    primitive_names = {"PrimSetZ", "PrimSetRS", "PrimSetAlpha"}
    candidates = [
        region
        for region in regions
        if region.locals == 2
        and region.args in {8, 9}
        and tuple(
            name for name in region.syscalls if name in primitive_names
        ) == ("PrimSetZ", "PrimSetRS", "PrimSetAlpha")
    ]
    groups: list[list[_FunctionRegion]] = []
    for index in range(len(candidates)):
        group = candidates[index : index + 3]
        if len(group) != 3:
            continue
        if group[0].end == group[1].start and group[1].end == group[2].start:
            groups.append(group)
    return {
        "status": "candidate_unique_structure" if len(groups) == 1 else "ambiguous",
        "groups": [[item.public() for item in group] for group in groups],
        "selected": [item.public() for item in groups[0]] if len(groups) == 1 else None,
        "warning": (
            "结构可证明属于视觉 primitive 状态包装层；具体背景/CG 归档选择仍需调用链证据"
            if len(groups) == 1
            else ""
        ),
    }


def _forwarded_call_target(
    document: HcbDocument,
    region: _FunctionRegion,
) -> int | None:
    """Return the callee of a tiny wrapper that forwards every argument.

    Compilers may emit one or two terminal ``ret`` instructions, so the match
    intentionally keys on argument order instead of total instruction count.
    """

    body = document.instructions[
        region.instruction_start_index : region.instruction_end_index
    ]
    if not body or body[0].mnemonic != "init_stack":
        return None
    expected_reads = list(range(-(region.args + 1), -1))
    forwarded = body[1 : 1 + region.args]
    if [item.mnemonic for item in forwarded] != ["push_stack"] * region.args:
        return None
    if [int(item.operands.get("value", 0)) for item in forwarded] != expected_reads:
        return None
    call_index = 1 + region.args
    if call_index >= len(body) or body[call_index].mnemonic != "call":
        return None
    tail = body[call_index + 1 :]
    if not tail or any(item.mnemonic != "ret" for item in tail):
        return None
    target = body[call_index].operands.get("target")
    return int(target) if target is not None else None


def _native_clear_apply_sequences(
    document: HcbDocument,
    regions: Sequence[_FunctionRegion],
    *,
    clear_target: int,
    apply_target: int,
    apply_argument_count: int,
) -> list[dict[str, Any]]:
    """Find literal selector/Nil clear followed by an immediate Nil apply.

    Match parsed instructions within one function, not caller-overlap ratios or
    guessed wrapper addresses.  A clear-only story caller does not invalidate
    this relation when separate native callers contain the exact handoff.
    These sites identify a lifecycle candidate; they do not approve rendering.
    """

    result: list[dict[str, Any]] = []
    sequence_length = 4 + apply_argument_count
    for region in regions:
        if clear_target not in region.call_targets or apply_target not in region.call_targets:
            continue
        body = document.instructions[
            region.instruction_start_index : region.instruction_end_index
        ]
        for index in range(max(0, len(body) - sequence_length + 1)):
            sequence = body[index : index + sequence_length]
            first, clear_nil, clear_call = sequence[:3]
            if first.mnemonic not in {"push_i8", "push_i16", "push_i32"}:
                continue
            selector = int(first.operands["value"])
            if not (
                selector > 0
                and clear_nil.mnemonic == "push_nil"
                and clear_call.mnemonic == "call"
                and int(clear_call.operands.get("target", -1)) == clear_target
                and all(item.mnemonic == "push_nil" for item in sequence[3:-1])
                and sequence[-1].mnemonic == "call"
                and int(sequence[-1].operands.get("target", -1)) == apply_target
            ):
                continue
            start = int(first.offset)
            end = int(sequence[-1].offset) + int(sequence[-1].size)
            payload = b"".join(item.raw for item in sequence)
            if document.original_bytes[start:end] != payload:
                continue
            result.append(
                dict(
                    caller=region.start,
                    selector=selector,
                    start=start,
                    end=end,
                    clear_call_offset=int(clear_call.offset),
                    apply_call_offset=int(sequence[-1].offset),
                    byte_sha256=_sha256_bytes(payload),
                )
            )
    return result


def _native_clear_apply_batches(
    document: HcbDocument,
    regions: Sequence[_FunctionRegion],
    *,
    clear_target: int,
    apply_target: int,
    apply_argument_count: int,
) -> list[dict[str, Any]]:
    """Keep a contiguous native multi-clear/Nil-apply transaction whole.

    The second clear argument is recorded, not reinterpreted as a duration or
    replaced with Nil. A batch is not evidence of an individual actor's exit.
    Reject entry edges into its interior and never lift a trailing suffix out
    of a larger native batch. No callee effects or runtime completion are
    claimed by this byte-bound record.
    """
    if apply_argument_count not in (2, 3, 4):
        return []
    result = []
    literals = {"push_i8", "push_i16", "push_i32"}
    for region in regions:
        if clear_target not in region.call_targets or apply_target not in region.call_targets:
            continue
        body = document.instructions[region.instruction_start_index:region.instruction_end_index]
        entries = {int(x.operands["target"]) for x in body if x.mnemonic in ("jmp", "jz")}
        for index, item in enumerate(body):
            if (item.mnemonic != "call" or item.operands.get("target") != apply_target
                    or index < apply_argument_count + 6):
                continue
            cursor = index - apply_argument_count
            if any(x.mnemonic != "push_nil" for x in body[cursor:index]):
                continue
            members = []
            while cursor >= 3:
                first, mode, call = body[cursor - 3:cursor]
                if (first.mnemonic not in literals or int(first.operands["value"]) <= 0
                        or mode.mnemonic not in literals | {"push_nil"}
                        or call.mnemonic != "call" or call.operands.get("target") != clear_target):
                    break
                members.insert(0, dict(selector=int(first.operands["value"]),
                    clear_arguments=[int(first.operands["value"]), mode.operands.get("value")],
                    clear_call_offset=call.offset))
                cursor -= 3
            if not 2 <= len(members) <= 32:
                continue
            selectors = [x["selector"] for x in members]
            if len(set(selectors)) != len(selectors):
                continue
            sequence = body[cursor:index + 1]
            start, end = sequence[0].offset, item.offset + item.size
            if any(start < target < end for target in entries):
                continue
            payload = b"".join(x.raw for x in sequence)
            if document.original_bytes[start:end] != payload:
                continue
            result.append(dict(caller=region.start, start=start, end=end,
                selectors=selectors, clears=members, apply_call_offset=item.offset,
                apply_argument_count=apply_argument_count,
                apply_arguments=[None] * apply_argument_count,
                byte_sha256=_sha256_bytes(payload),
                strategy="whole_native_clear_batch_not_individual_exit"))
    return result


def _split_portrait_apply_targets(document, region):
    """Exact four-argument wrapper: forward three fields, then finish cleanup.

    The native fourth field is retained in the ABI even though this wrapper
    does not read it. Do not collapse it into the later three-argument wrapper.
    """
    body = document.instructions[region.instruction_start_index:region.instruction_end_index]
    if (region.args != 4 or region.locals != 0 or len(body) < 7
            or [x.mnemonic for x in body[1:6]] != ["push_stack"] * 3 + ["call", "call"]
            or [x.operands.get("value") for x in body[1:4]] != [-5, -4, -3]
            or any(x.mnemonic != "ret" for x in body[6:])):
        return None
    return int(body[4].operands["target"]), int(body[5].operands["target"])


def _discover_portrait_lifecycle_family(
    document: HcbDocument,
    regions: Sequence[_FunctionRegion],
    portrait: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Find portrait clear/apply wrappers by forwarding and call-graph relation.

    The reviewed targets share a stronger relation than raw function size:
    adjacent forwarding wrappers, a clear-side state dispatcher, an apply-side
    native load cluster, and a target-native relation tying both operations
    together.  Later/old FVP variants expose a 2/3 wrapper pair and strong
    caller overlap.  Earlier 12-argument portrait dispatchers expose a 2/2
    pair followed by an exact all-selector reset wrapper.  The result remains
    a review candidate until a real target proves the visual cleanup boundary.
    """

    by_start = {region.start: region for region in regions}
    index_by_start = {region.start: index for index, region in enumerate(regions)}
    portrait_selected = (
        portrait.get("selected")
        if isinstance(portrait, Mapping)
        and isinstance(portrait.get("selected"), Mapping)
        else {}
    )
    legacy_dispatcher_end = None
    if (
        portrait_selected.get("engine_variant") == "legacy_fvp"
        and int(portrait_selected.get("args", -1)) == 12
    ):
        try:
            legacy_dispatcher_end = int(portrait_selected["end"])
        except (KeyError, TypeError, ValueError):
            legacy_dispatcher_end = None
    candidates: list[dict[str, Any]] = []
    for clear_region, apply_region in zip(regions, regions[1:]):
        if not (
            clear_region.end == apply_region.start
            and clear_region.args == 2
            and clear_region.locals == 0
            and not clear_region.syscalls
            and apply_region.args in {2, 3, 4}
            and apply_region.locals == 0
            and not apply_region.syscalls
        ):
            continue
        clear_target = _forwarded_call_target(document, clear_region)
        apply_cleanup = None
        if apply_region.args == 4:
            if portrait_selected.get("engine_variant") != "composite_fvp":
                continue
            split = _split_portrait_apply_targets(document, apply_region)
            if split is None:
                continue
            apply_target, cleanup_target = split
            apply_cleanup = by_start.get(cleanup_target)
            if (apply_cleanup is None or apply_cleanup.args != 0 or apply_cleanup.locals != 0
                    or not apply_cleanup.syscalls):
                continue
        else:
            apply_target = _forwarded_call_target(document, apply_region)
        if clear_target is None or apply_target is None:
            continue
        clear_delegate = by_start.get(clear_target)
        apply_delegate = by_start.get(apply_target)
        if clear_delegate is None or apply_delegate is None:
            continue
        if not (
            clear_delegate.args == 2
            and clear_delegate.locals == 0
            and not clear_delegate.syscalls
        ):
            continue
        clear_inner = None
        if len(clear_delegate.call_targets) == 1:
            if apply_region.args not in {3, 4}:
                continue
            clear_inner = by_start.get(clear_delegate.call_targets[0])
            if not (
                clear_inner is not None
                and clear_inner.args == 2
                and not clear_inner.syscalls
            ):
                continue
            engine_variant = "modern_fvp"
            if portrait_selected.get("engine_variant") == "composite_fvp":
                engine_variant = "composite_fvp"
            clear_evidence = "clear_dispatcher_chain"
        elif not clear_delegate.call_targets:
            if apply_region.args == 2:
                engine_variant = "legacy_fvp"
                clear_evidence = "direct_clear_delegate_after_legacy_dispatcher"
            else:
                engine_variant = "old_fvp"
                clear_evidence = "direct_clear_delegate"
        else:
            continue

        apply_syscalls = Counter(apply_delegate.syscalls)
        if apply_cleanup is not None:
            apply_syscalls.update(apply_cleanup.syscalls)
        load_count = apply_syscalls["GraphLoad"]
        if engine_variant == "legacy_fvp":
            if not (
                legacy_dispatcher_end is not None
                and clear_delegate.start == legacy_dispatcher_end
                and clear_delegate.end == clear_region.start
                and apply_delegate.args == 2
                and load_count == 46
                and apply_syscalls["PartsLoad"] == 23
                and apply_syscalls["PrimSetNull"] == 23
                and apply_syscalls["GraphRGB"] == 11
                and apply_syscalls["PartsRGB"] == 11
                and apply_syscalls["PartsMotion"] == 11
                and apply_syscalls["MotionAlpha"] == 22
                and apply_syscalls["MotionMove"] == 22
                and apply_syscalls["MotionAlphaTest"] == 11
                and set(apply_syscalls).issubset(
                    {
                        "GraphLoad",
                        "PartsLoad",
                        "PrimSetNull",
                        "GraphRGB",
                        "PartsRGB",
                        "PartsMotion",
                        "MotionAlpha",
                        "MotionMove",
                        "MotionAlphaTest",
                    }
                )
            ):
                continue
        elif not (
            apply_delegate.args == 3
            and load_count > 0
            and apply_syscalls["PartsLoad"] == load_count
            and apply_syscalls["PrimSetNull"] == (
                load_count * 2 if engine_variant == "composite_fvp" else load_count
            )
            and apply_syscalls["MotionAlpha"] > 0
            and apply_syscalls["MotionMoveZ"] > 0
        ):
            continue
        if engine_variant == "old_fvp" and not (
            load_count % 3 == 0
            and apply_syscalls["GraphRGB"] == load_count // 3
            and apply_syscalls["PartsRGB"] == load_count // 3
            and apply_syscalls["PartsMotion"] == load_count // 3
            and apply_syscalls["MotionAlpha"] == (
                (load_count * 4) // 3
                if portrait_selected.get("engine_variant") == "old_fvp"
                and int(portrait_selected.get("args", -1)) == 13
                and int(portrait_selected.get("locals", -1)) == 16
                else (load_count * 2) // 3
            )
            and apply_syscalls["MotionMove"] == (load_count * 2) // 3
            and apply_syscalls["MotionMoveZ"] == (load_count * 2) // 3
            and set(apply_syscalls).issubset(
                {
                    "GraphLoad",
                    "PartsLoad",
                    "PrimSetNull",
                    "GraphRGB",
                    "PartsRGB",
                    "PartsMotion",
                    "MotionAlpha",
                    "MotionMove",
                    "MotionMoveZ",
                    "MotionAlphaTest",
                    "MotionMoveStop",
                }
            )
            and apply_syscalls["MotionAlphaTest"] in {0, load_count // 3}
            and 0 <= apply_syscalls["MotionMoveStop"] <= load_count
        ):
            continue

        all_selector_reset = None
        if engine_variant == "legacy_fvp":
            apply_index = index_by_start[apply_region.start]
            if apply_index + 1 >= len(regions):
                continue
            reset_region = regions[apply_index + 1]
            reset_calls = Counter(reset_region.call_targets)
            if not (
                apply_region.end == reset_region.start
                and reset_region.end == apply_delegate.start
                and reset_region.args == 0
                and reset_region.locals == 0
                and not reset_region.syscalls
                and reset_calls == Counter(
                    {clear_delegate.start: 11, apply_delegate.start: 1}
                )
            ):
                continue
            all_selector_reset = reset_region.public()

        clear_callers = {
            region.start
            for region in regions
            if clear_region.start in region.call_targets
        }
        apply_callers = {
            region.start
            for region in regions
            if apply_region.start in region.call_targets
        }
        shared_callers = clear_callers & apply_callers
        smaller_caller_count = min(len(clear_callers), len(apply_callers))
        caller_overlap_ratio = (
            len(shared_callers) / smaller_caller_count
            if smaller_caller_count
            else 0.0
        )
        immediate_clear_apply: list[dict[str, Any]] = []
        if engine_variant in {"modern_fvp", "composite_fvp"}:
            if len(clear_callers) < 2 or not shared_callers:
                continue
            if not clear_callers.issubset(apply_callers):
                immediate_clear_apply = _native_clear_apply_sequences(
                    document,
                    regions,
                    clear_target=clear_region.start,
                    apply_target=apply_region.start,
                    apply_argument_count=apply_region.args,
                )
                # Repeated source sequences in independent native callers are
                # stronger evidence than lowering an overlap percentage.  One
                # incidental site, or only non-Nil/delayed applies, is not enough.
                if len({site["caller"] for site in immediate_clear_apply}) < 2:
                    continue
        if engine_variant == "old_fvp" and not (
            smaller_caller_count >= 8 and caller_overlap_ratio >= 0.8
        ):
            continue
        if engine_variant == "legacy_fvp" and not shared_callers:
            continue
        candidates.append(
            {
                "clear": clear_region.public(),
                "apply": apply_region.public(),
                "delegates": {
                    "clear": clear_delegate.public(),
                    "clear_inner": (
                        clear_inner.public() if clear_inner is not None else None
                    ),
                    "apply": apply_delegate.public(),
                    "apply_cleanup": apply_cleanup.public() if apply_cleanup else None,
                },
                "engine_variant": engine_variant,
                "apply_argument_count": int(apply_region.args),
                "all_selector_reset": all_selector_reset,
                "immediate_clear_apply_sequences": immediate_clear_apply,
                "call_graph": {
                    "clear_caller_count": len(clear_callers),
                    "apply_caller_count": len(apply_callers),
                    "shared_caller_count": len(shared_callers),
                    "clear_callers_are_apply_callers": clear_callers.issubset(
                        apply_callers
                    ),
                    "caller_overlap_ratio": round(caller_overlap_ratio, 6),
                },
                "native_load_cluster": {
                    "graph_load_count": load_count,
                    "parts_load_count": apply_syscalls["PartsLoad"],
                    "prim_set_null_count": apply_syscalls["PrimSetNull"],
                    "motion_alpha_count": apply_syscalls["MotionAlpha"],
                    "motion_move_z_count": apply_syscalls["MotionMoveZ"],
                },
                "evidence": [
                    "adjacent_exact_argument_forwarders",
                    clear_evidence,
                    "balanced_native_portrait_load_cluster",
                    (
                        "all_selector_reset_calls_clear_x11_then_apply"
                        if engine_variant == "legacy_fvp"
                        else (
                        "repeated_exact_clear_nil_apply_in_native_callers"
                        if immediate_clear_apply
                        else "clear_callers_subset_of_apply_callers"
                        if clear_callers.issubset(apply_callers)
                        else "clear_apply_callers_high_overlap"
                        )
                    ),
                ],
            }
        )
    selected = candidates[0] if len(candidates) == 1 else None
    return {
        "status": (
            "candidate_unique_call_graph_relation" if selected else "ambiguous"
        ),
        "pairs": candidates,
        "selected": selected,
        "warning": (
            "唯一 clear/apply 调用图关系已定位；仍需目标 profile 审核与实机清理边界证据"
            if selected
            else ""
        ),
    }


def _discover_story_dialogue_family(
    document: HcbDocument,
    regions: Sequence[_FunctionRegion],
) -> dict[str, Any]:
    """Find the engine-family print/wait wrapper pair by call-graph relation.

    The tiny wrapper shapes are not unique by themselves.  The reviewed FVP
    family instead has a stable relation: print delegates to the immediately
    preceding function, wait delegates two function entries back, the wrappers
    are thirteen or fourteen entries apart, and their many story callers almost
    entirely overlap.  This avoids copying either game's absolute addresses.
    """

    index_by_start = {region.start: index for index, region in enumerate(regions)}
    callers: dict[int, set[int]] = {region.start: set() for region in regions}
    for caller in regions:
        for target in caller.call_targets:
            if target in callers:
                callers[target].add(caller.start)
    print_candidates = [
        region
        for index, region in enumerate(regions)
        if region.args == 4
        and region.locals == 0
        and region.instruction_count == 8
        and not region.syscalls
        and len(region.call_targets) == 1
        and index_by_start.get(region.call_targets[0]) == index - 1
    ]
    wait_candidates = [
        region
        for index, region in enumerate(regions)
        if region.args == 0
        and region.locals == 0
        and region.instruction_count == 4
        and not region.syscalls
        and len(region.call_targets) == 1
        and index_by_start.get(region.call_targets[0]) == index - 2
    ]
    pairs: list[dict[str, Any]] = []
    for print_region in print_candidates:
        for wait_region in wait_candidates:
            function_index_delta = (
                index_by_start[wait_region.start]
                - index_by_start[print_region.start]
            )
            if function_index_delta not in {13, 14}:
                continue
            print_callers = callers[print_region.start]
            wait_callers = callers[wait_region.start]
            smaller_count = min(len(print_callers), len(wait_callers))
            overlap = (
                len(print_callers & wait_callers) / smaller_count
                if smaller_count
                else 0.0
            )
            if smaller_count < 8 or overlap < 0.8:
                continue
            pairs.append(
                {
                    "print": print_region.public(),
                    "wait": wait_region.public(),
                    "function_index_delta": function_index_delta,
                    "print_caller_count": len(print_callers),
                    "wait_caller_count": len(wait_callers),
                    "caller_overlap_ratio": round(overlap, 6),
                }
            )
    if len(pairs) == 1:
        pairs[0]["discovery_mode"] = "wrapper_call_graph_relation"
        pairs[0]["evidence"] = [
            "print_wait_wrapper_shape",
            "dominant_shared_story_callers",
        ]
        return {
            "status": "candidate_unique_relation",
            "pairs": pairs,
            "selected": pairs[0],
            "warning": "台词输出/等待关系唯一；说话人选择器仍需独立证据和审核",
        }

    # Early FVP builds use a shorter three-argument print wrapper and do not
    # retain the later family's fixed function-index spacing.  Recover that
    # ABI only when one exact linear callsite motif overwhelmingly dominates:
    # push_string, Nil x (args-1), print, wait.  This is structural and
    # address-free; weak or competing motifs remain ambiguous.
    regions_by_start = {region.start: region for region in regions}
    motif_counts: Counter[tuple[int, int, int]] = Counter()
    motif_totals: Counter[int] = Counter()
    instructions = document.instructions
    for nil_count in (2, 3):
        expected = (0x0E,) + ((0x08,) * nil_count) + (0x02, 0x02)
        for index in range(max(0, len(instructions) - len(expected) + 1)):
            window = instructions[index : index + len(expected)]
            if tuple(item.opcode for item in window) != expected:
                continue
            selected = window[0]
            print_call = window[-2]
            wait_call = window[-1]
            if selected.text is None or not selected.text.strip():
                continue
            print_target = int(print_call.operands.get("target", -1))
            wait_target = int(wait_call.operands.get("target", -1))
            print_region = regions_by_start.get(print_target)
            wait_region = regions_by_start.get(wait_target)
            if print_region is None or wait_region is None:
                continue
            if not (
                print_region.args == nil_count + 1
                and print_region.locals == 0
                and not print_region.syscalls
                and len(print_region.call_targets) == 1
                and wait_region.args == 0
                and wait_region.locals == 0
                and not wait_region.syscalls
                and len(wait_region.call_targets) == 1
            ):
                continue
            motif_counts[(nil_count, print_target, wait_target)] += 1
            motif_totals[nil_count] += 1

    motif_candidates: list[dict[str, Any]] = []
    for (nil_count, print_target, wait_target), count in motif_counts.items():
        total = motif_totals[nil_count]
        dominance = count / total if total else 0.0
        if count < 8 or dominance < 0.8:
            continue
        motif_candidates.append(
            {
                "print": regions_by_start[print_target].public(),
                "wait": regions_by_start[wait_target].public(),
                "print_caller_count": count,
                "wait_caller_count": count,
                "caller_overlap_ratio": 1.0,
                "motif_nil_count": nil_count,
                "motif_count": count,
                "motif_family_total": total,
                "motif_dominance_ratio": round(dominance, 6),
                "discovery_mode": "dominant_linear_callsite_motif",
                "evidence": [
                    "push_string_nil_print_wait_linear_motif",
                    "exact_function_entry_argument_counts",
                    "dominant_target_pair",
                ],
            }
        )
    selected = motif_candidates[0] if len(motif_candidates) == 1 else None
    if selected is None and not motif_candidates:
        from .native_dialogue_backend import discover_internal_wait_printer
        internal = discover_internal_wait_printer(document, regions)
        if internal["selected"] is not None:
            return internal
    return {
        "status": "candidate_unique_relation" if selected else "ambiguous",
        "pairs": motif_candidates,
        "selected": selected,
        "warning": (
            "早期 FVP 台词调用序列唯一且占绝对多数；说话人选择器仍需独立证据和审核"
            if selected
            else ""
        ),
    }


def _discover_background_dissolve_family(
    regions: Sequence[_FunctionRegion],
) -> dict[str, Any]:
    """Find the native nine-argument background dissolve wrapper.

    Both reviewed engine-family targets use one wrapper that owns the four
    ``graph/diss0*`` resources and performs the same paired alpha-test / alpha
    update / dissolve-wait sequence.  Requiring the resource family as well as
    the complete syscall order avoids treating an unrelated wait helper as the
    scene transition ABI.
    """

    expected_syscalls = (
        "MotionAlphaTest",
        "MotionAlphaTest",
        "PrimSetAlpha",
        "PrimSetAlpha",
        "DissolveWait",
        "DissolveWait",
    )
    candidates = []
    for region in regions:
        dissolve_resources = sorted(
            {
                value.casefold()
                for value in region.strings
                if re.fullmatch(r"graph/diss0[0-3]", value, re.IGNORECASE)
            }
        )
        if not (
            region.args == 9
            and region.locals == 3
            and region.syscalls == expected_syscalls
            and dissolve_resources
            == [
                "graph/diss00",
                "graph/diss01",
                "graph/diss02",
                "graph/diss03",
            ]
        ):
            continue
        value = region.public()
        value["dissolve_resources"] = dissolve_resources
        candidates.append(value)
    return {
        "status": (
            "candidate_unique_structure" if len(candidates) == 1 else "ambiguous"
        ),
        "candidates": candidates,
        "selected": candidates[0] if len(candidates) == 1 else None,
        "warning": (
            "背景转场包装器结构唯一；具体参数语义仍须目标 profile 审核"
            if len(candidates) == 1
            else ""
        ),
    }


def _speaker_name_variants(strings: Sequence[str]) -> list[str]:
    variants: list[str] = []
    for raw in strings:
        value = re.sub(r"[\s　]+", "", str(raw))
        if not value or value in variants:
            continue
        variants.append(value)
    return variants


_INTEGER_PUSH_MNEMONICS = frozenset({"push_i8", "push_i16", "push_i32"})


def _decode_forward_integer(
    instructions: Sequence[Instruction],
    index: int,
) -> tuple[int, int] | None:
    if index >= len(instructions):
        return None
    item = instructions[index]
    if item.mnemonic not in _INTEGER_PUSH_MNEMONICS:
        return None
    try:
        value = int(item.operands["value"])
    except (KeyError, TypeError, ValueError):
        return None
    next_index = index + 1
    if (
        next_index < len(instructions)
        and instructions[next_index].mnemonic == "neg"
    ):
        value = -value
        next_index += 1
    return value, next_index


def _speaker_name_block(
    instructions: Sequence[Instruction],
) -> dict[str, Any]:
    raw_strings = [
        str(item.text)
        for item in instructions
        if item.mnemonic == "push_string" and item.text is not None
    ]
    variants = _speaker_name_variants(raw_strings)
    return {
        "name_variants": variants,
        "raw_string_count": len(raw_strings),
        "blank_name_candidate": bool(raw_strings) and not variants,
    }


def _speaker_selector_branches(
    document: HcbDocument,
    region: _FunctionRegion,
) -> dict[str, Any]:
    body = document.instructions[
        region.instruction_start_index : region.instruction_end_index
    ]
    selector_stack_offset = -region.args
    offset_to_index = {item.offset: index for index, item in enumerate(body)}
    conditions: list[dict[str, Any]] = []
    malformed_condition_count = 0
    for index, item in enumerate(body):
        if (
            item.mnemonic != "push_stack"
            or int(item.operands.get("value", 0)) != selector_stack_offset
        ):
            continue
        decoded = _decode_forward_integer(body, index + 1)
        if decoded is None:
            continue
        selector_value, cursor = decoded
        if (
            cursor + 1 >= len(body)
            or body[cursor].mnemonic != "set_e"
            or body[cursor + 1].mnemonic != "jz"
        ):
            continue
        jz = body[cursor + 1]
        false_target = int(jz.operands.get("target", -1))
        false_index = offset_to_index.get(false_target)
        if false_index is None or false_index <= cursor + 1:
            malformed_condition_count += 1
            continue
        block = body[cursor + 2 : false_index]
        name_block = _speaker_name_block(block)
        jump_targets = [
            int(branch.operands.get("target", -1))
            for branch in block
            if branch.mnemonic == "jmp"
        ]
        conditions.append(
            {
                "selector_kind": "integer",
                "selector_value": selector_value,
                "condition_offset": int(item.offset),
                "condition_offset_hex": f"0x{item.offset:X}",
                "false_target": false_target,
                "false_target_hex": f"0x{false_target:X}",
                "block_start": int(block[0].offset) if block else false_target,
                "block_end": false_target,
                "jump_targets": jump_targets,
                **name_block,
            }
        )

    duplicate_values = sorted(
        value
        for value, count in Counter(
            item["selector_value"] for item in conditions
        ).items()
        if count > 1
    )
    jump_targets = [
        target
        for item in conditions
        for target in item["jump_targets"]
        if target >= 0
    ]
    common_exit = None
    if jump_targets:
        counts = Counter(jump_targets)
        top = counts.most_common()
        if len(top) == 1 or top[0][1] > top[1][1]:
            common_exit = int(top[0][0])

    branches = []
    for item in conditions:
        branch = dict(item)
        branch.pop("jump_targets", None)
        branches.append(branch)
    if conditions and common_exit is not None:
        default_start = int(conditions[-1]["false_target"])
        default_index = offset_to_index.get(default_start)
        exit_index = offset_to_index.get(common_exit, len(body))
        if default_index is not None and exit_index >= default_index:
            default_block = body[default_index:exit_index]
            default_names = _speaker_name_block(default_block)
            if default_names["raw_string_count"]:
                branches.append(
                    {
                        "selector_kind": "default_fallthrough",
                        "selector_value": None,
                        "condition_offset": None,
                        "condition_offset_hex": None,
                        "false_target": None,
                        "false_target_hex": None,
                        "block_start": default_start,
                        "block_end": common_exit,
                        **default_names,
                    }
                )

    explicit_branches = [
        item for item in branches if item["selector_kind"] == "integer"
    ]
    missing_name_branches = [
        item["selector_value"]
        for item in explicit_branches
        if not item["raw_string_count"]
    ]
    status = (
        "candidate_local_control_flow"
        if explicit_branches
        and not duplicate_values
        and not missing_name_branches
        and not malformed_condition_count
        else "ambiguous"
        if conditions or malformed_condition_count
        else "not_discovered"
    )
    result = {
        "status": status,
        "selector_argument_index": 1,
        "selector_stack_offset": selector_stack_offset,
        "branches": branches,
        "explicit_branch_count": len(explicit_branches),
        "default_branch_present": any(
            item["selector_kind"] == "default_fallthrough"
            for item in branches
        ),
        "duplicate_selector_values": duplicate_values,
        "missing_name_selector_values": missing_name_branches,
        "malformed_condition_count": malformed_condition_count,
        "common_exit": common_exit,
        "common_exit_hex": (
            f"0x{common_exit:X}" if common_exit is not None else None
        ),
    }
    result["candidate_sha256"] = _canonical_sha256(result)
    return result


def _decode_alias_arguments(
    instructions: Sequence[Instruction],
    source_args: int,
) -> list[dict[str, Any]] | None:
    values: list[dict[str, Any]] = []
    index = 0
    while index < len(instructions):
        item = instructions[index]
        if item.mnemonic == "push_stack":
            stack_offset = int(item.operands.get("value", 0))
            argument_index = stack_offset + source_args + 1
            if not 0 <= argument_index < source_args:
                return None
            values.append(
                {
                    "kind": "argument",
                    "argument_index": argument_index,
                    "stack_offset": stack_offset,
                }
            )
            index += 1
            continue
        if item.mnemonic == "push_nil":
            values.append({"kind": "nil", "value": None})
            index += 1
            continue
        if item.mnemonic in {"push_true", "push_false"}:
            values.append(
                {"kind": "boolean", "value": item.mnemonic == "push_true"}
            )
            index += 1
            continue
        decoded = _decode_forward_integer(instructions, index)
        if decoded is not None:
            value, index = decoded
            values.append({"kind": "integer", "value": value})
            continue
        return None
    return values


def _speaker_alias_candidate(
    document: HcbDocument,
    region: _FunctionRegion,
    wrapper_by_start: Mapping[int, _FunctionRegion],
) -> dict[str, Any] | None:
    body = document.instructions[
        region.instruction_start_index : region.instruction_end_index
    ]
    target_calls = [
        (index, int(item.operands.get("target", -1)))
        for index, item in enumerate(body)
        if item.mnemonic == "call"
        and int(item.operands.get("target", -1)) in wrapper_by_start
    ]
    if len(target_calls) != 1 or len(region.call_targets) != 1:
        return None
    call_index, target = target_calls[0]
    target_region = wrapper_by_start[target]
    arguments = _decode_alias_arguments(body[1:call_index], region.args)
    status = "ambiguous"
    alias_kind = "unknown"
    forced_selector = None
    if arguments is not None and len(arguments) == target_region.args:
        expected = [
            {"kind": "argument", "argument_index": index}
            for index in range(target_region.args)
        ]
        simplified = [
            {
                key: value
                for key, value in item.items()
                if key in {"kind", "argument_index"}
            }
            for item in arguments
        ]
        if simplified == expected:
            status = "candidate_exact_forward"
            alias_kind = "forward"
        elif (
            target_region.args == region.args
            and len(arguments) >= 2
            and arguments[1].get("kind") == "integer"
            and all(
                arguments[index].get("kind") == "argument"
                and arguments[index].get("argument_index") == index
                for index in range(len(arguments))
                if index != 1
            )
        ):
            status = "candidate_forced_selector"
            alias_kind = "forced_selector"
            forced_selector = int(arguments[1]["value"])
    return {
        "status": status,
        "alias_kind": alias_kind,
        "address": region.start,
        "address_hex": f"0x{region.start:X}",
        "target": target,
        "target_hex": f"0x{target:X}",
        "arguments": arguments or [],
        "forced_selector": forced_selector,
    }


def _discover_direct_speaker_wrapper_family(
    document: HcbDocument,
    regions: Sequence[_FunctionRegion],
) -> dict[str, Any]:
    """Find the contiguous entry-prefix speaker wrappers and color table."""

    wrappers: list[_FunctionRegion] = []
    for region in regions:
        if region.args not in {3, 5} or region.locals != 0 or region.syscalls:
            break
        wrappers.append(region)
    anchor = regions[len(wrappers)] if len(wrappers) < len(regions) else None
    color_count = (
        anchor.syscalls.count("TextColor") if anchor is not None else 0
    )
    valid = len(wrappers) >= 3 and anchor is not None and color_count >= 3
    entries = []
    aliases: list[dict[str, Any]] = []
    wrapper_by_start = {region.start: region for region in wrappers}
    if valid:
        for index, region in enumerate(wrappers):
            public = region.public()
            selector_stack_offset = -region.args
            selector_position_verified = (
                selector_stack_offset in region.stack_reads
            )
            selector_branches = (
                _speaker_selector_branches(document, region)
                if selector_position_verified
                else {
                    "status": "not_discovered",
                    "selector_argument_index": None,
                    "selector_stack_offset": selector_stack_offset,
                    "branches": [],
                    "explicit_branch_count": 0,
                    "default_branch_present": False,
                }
            )
            alias = _speaker_alias_candidate(
                document,
                region,
                wrapper_by_start,
            )
            if alias is not None:
                aliases.append(alias)
            public.update(
                {
                    "speaker_index": index,
                    "name_variants": _speaker_name_variants(region.strings),
                    "selector_argument_index": (
                        1 if selector_position_verified else None
                    ),
                    "selector_stack_offset": selector_stack_offset,
                    "selector_position_status": (
                        "verified_by_stack_read"
                        if selector_position_verified
                        else "not_directly_read"
                    ),
                    "selection_mode": (
                        f"alias_{alias['alias_kind']}"
                        if alias is not None
                        and alias["status"].startswith("candidate_")
                        else "selector_argument"
                        if selector_position_verified
                        else "fixed_or_delegated_candidate"
                    ),
                    "selector_branches": selector_branches,
                    "alias": alias,
                }
            )
            entries.append(public)
    named_entries = [item for item in entries if item["name_variants"]]
    selector_entries = [
        item
        for item in named_entries
        if item["selector_position_status"] == "verified_by_stack_read"
    ]
    selector_position_verified = bool(selector_entries) and all(
        item["selector_argument_index"] == 1
        for item in selector_entries
    )
    non_selector_named_entries = [
        item
        for item in named_entries
        if item["selector_position_status"] != "verified_by_stack_read"
    ]
    selector_position_consistent = selector_position_verified and all(
        item["selector_position_status"] == "verified_by_stack_read"
        for item in selector_entries
    )
    return {
        "status": "candidate_contiguous_prefix" if valid else "ambiguous",
        "entries": entries,
        "entry_count": len(entries),
        "named_entry_count": sum(bool(item["name_variants"]) for item in entries),
        "selector_entry_count": len(selector_entries),
        "non_selector_named_entry_count": len(non_selector_named_entries),
        "selector_argument_index": 1 if selector_position_consistent else None,
        "selector_position_status": (
            "verified_for_selector_readers"
            if selector_position_consistent
            else "not_discovered"
        ),
        "aliases": aliases,
        "alias_count": len(aliases),
        "color_table": anchor.public() if valid and anchor is not None else None,
        "color_table_textcolor_count": color_count if valid else 0,
        "warning": (
            "说话人包装前缀已定位；分支型 wrapper 的 selector 参数位置已证明，"
            "固定/转发型 wrapper 与 selector 数值仍须按目标审核"
            if valid
            else ""
        ),
    }


def _decode_argument_ending_at(
    instructions: Sequence[Instruction],
    index: int,
) -> tuple[dict[str, Any], int] | None:
    """Decode one literal/stack argument immediately before a call.

    Early FVP titles delegate their visible-name selection through a common
    character-state function.  Keeping this decoder deliberately small makes
    the evidence fail closed when an argument is calculated instead of being
    a direct Nil/integer/stack forwarding operation.
    """

    if index < 0:
        return None
    item = instructions[index]
    if item.mnemonic == "neg":
        if index == 0:
            return None
        decoded = _decode_argument_ending_at(instructions, index - 1)
        if decoded is None or decoded[0].get("kind") != "integer":
            return None
        value = -int(decoded[0]["value"])
        return {"kind": "integer", "value": value}, decoded[1]
    if item.mnemonic == "push_nil":
        return {"kind": "nil", "value": None}, index - 1
    if item.mnemonic == "push_true":
        return {"kind": "boolean", "value": True}, index - 1
    if item.mnemonic in _INTEGER_PUSH_MNEMONICS:
        try:
            value = int(item.operands["value"])
        except (KeyError, TypeError, ValueError):
            return None
        return {"kind": "integer", "value": value}, index - 1
    if item.mnemonic == "push_stack":
        try:
            stack_offset = int(item.operands["value"])
        except (KeyError, TypeError, ValueError):
            return None
        return {
            "kind": "stack",
            "stack_offset": stack_offset,
        }, index - 1
    return None


def _arguments_ending_before_call(
    instructions: Sequence[Instruction],
    call_index: int,
    argument_count: int,
) -> list[dict[str, Any]] | None:
    cursor = call_index - 1
    reversed_arguments: list[dict[str, Any]] = []
    for _ in range(argument_count):
        decoded = _decode_argument_ending_at(instructions, cursor)
        if decoded is None:
            return None
        value, cursor = decoded
        reversed_arguments.append(value)
    return list(reversed(reversed_arguments))


def _delegated_speaker_call(
    document: HcbDocument,
    region: _FunctionRegion,
) -> dict[str, Any] | None:
    body = document.instructions[
        region.instruction_start_index : region.instruction_end_index
    ]
    matches: list[dict[str, Any]] = []
    selector_stack_offset = -region.args
    for index, item in enumerate(body):
        if item.mnemonic != "call":
            continue
        arguments = _arguments_ending_before_call(body, index, 3)
        if arguments is None:
            continue
        if not (
            arguments[0].get("kind") == "integer"
            and arguments[1].get("kind") == "nil"
            and arguments[2].get("kind") == "stack"
            and int(arguments[2].get("stack_offset", 0))
            == selector_stack_offset
        ):
            continue
        matches.append(
            {
                "call_offset": int(item.offset),
                "call_offset_hex": f"0x{item.offset:X}",
                "dispatcher_target": int(item.operands.get("target", -1)),
                "dispatcher_target_hex": (
                    f"0x{int(item.operands.get('target', -1)):X}"
                ),
                "character_selector": int(arguments[0]["value"]),
                "selector_stack_offset": selector_stack_offset,
                "selector_argument_index": 1,
                "arguments": arguments,
            }
        )
    return matches[0] if len(matches) == 1 else None


_SPEAKER_NAME_RESOURCE = re.compile(r"^name_(?P<name>.+)$", re.IGNORECASE)


def _speaker_asset_name_block(
    instructions: Sequence[Instruction],
) -> dict[str, Any]:
    resources: list[str] = []
    variants: list[str] = []
    for item in instructions:
        if item.mnemonic != "push_string" or item.text is None:
            continue
        raw = str(item.text)
        match = _SPEAKER_NAME_RESOURCE.fullmatch(raw)
        if match is None:
            continue
        resource = raw
        if resource not in resources:
            resources.append(resource)
        name = re.sub(r"[\s　]+", "", match.group("name"))
        if not name:
            continue
        # Older FVP projects commonly label the graphic that visibly contains
        # "？？？" as ``name_ハテナ``.  The resource token is retained below;
        # only the editor-facing display identity is normalised.
        display_name = "？？？" if name == "ハテナ" else name
        if display_name not in variants:
            variants.append(display_name)
    return {
        "name_variants": variants,
        "name_resources": resources,
        "raw_string_count": len(resources),
        "blank_name_candidate": False,
    }


def _speaker_asset_selector_branches(
    document: HcbDocument,
    region: _FunctionRegion,
    selector_global: int,
) -> dict[str, Any]:
    body = document.instructions[
        region.instruction_start_index : region.instruction_end_index
    ]
    offset_to_index = {item.offset: index for index, item in enumerate(body)}
    conditions: list[dict[str, Any]] = []
    malformed_count = 0
    for index, item in enumerate(body):
        if (
            item.mnemonic != "push_global"
            or int(item.operands.get("value", -1)) != selector_global
        ):
            continue
        decoded = _decode_forward_integer(body, index + 1)
        if decoded is None:
            continue
        selector_value, cursor = decoded
        if (
            cursor + 1 >= len(body)
            or body[cursor].mnemonic != "set_e"
            or body[cursor + 1].mnemonic != "jz"
        ):
            continue
        false_target = int(body[cursor + 1].operands.get("target", -1))
        false_index = offset_to_index.get(false_target)
        if false_index is None or false_index <= cursor + 1:
            malformed_count += 1
            continue
        block = body[cursor + 2 : false_index]
        names = _speaker_asset_name_block(block)
        conditions.append(
            {
                "selector_kind": "integer",
                "selector_value": selector_value,
                "condition_offset": int(item.offset),
                "condition_offset_hex": f"0x{item.offset:X}",
                "false_target": false_target,
                "false_target_hex": f"0x{false_target:X}",
                "block_start": int(block[0].offset) if block else false_target,
                "block_end": false_target,
                "jump_targets": [
                    int(branch.operands.get("target", -1))
                    for branch in block
                    if branch.mnemonic == "jmp"
                ],
                **names,
            }
        )

    duplicate_values = sorted(
        value
        for value, count in Counter(
            item["selector_value"] for item in conditions
        ).items()
        if count > 1
    )
    jump_targets = [
        target
        for item in conditions
        for target in item["jump_targets"]
        if target >= 0
    ]
    common_exit = None
    if jump_targets:
        counts = Counter(jump_targets)
        top = counts.most_common()
        if len(top) == 1 or top[0][1] > top[1][1]:
            common_exit = int(top[0][0])

    branches: list[dict[str, Any]] = []
    for item in conditions:
        branch = dict(item)
        branch.pop("jump_targets", None)
        branches.append(branch)
    if conditions and common_exit is not None:
        default_start = int(conditions[-1]["false_target"])
        default_index = offset_to_index.get(default_start)
        exit_index = offset_to_index.get(common_exit, len(body))
        if default_index is not None and exit_index >= default_index:
            default_names = _speaker_asset_name_block(
                body[default_index:exit_index]
            )
            if default_names["raw_string_count"]:
                branches.append(
                    {
                        "selector_kind": "default_fallthrough",
                        "selector_value": None,
                        "condition_offset": None,
                        "condition_offset_hex": None,
                        "false_target": None,
                        "false_target_hex": None,
                        "block_start": default_start,
                        "block_end": common_exit,
                        **default_names,
                    }
                )

    explicit = [
        item for item in branches if item["selector_kind"] == "integer"
    ]
    missing_names = [
        item["selector_value"]
        for item in explicit
        if not item["name_variants"]
    ]
    status = (
        "candidate_local_control_flow"
        if explicit
        and common_exit is not None
        and not duplicate_values
        and not missing_names
        and not malformed_count
        else "ambiguous"
        if conditions or malformed_count
        else "not_discovered"
    )
    result = {
        "status": status,
        "selector_argument_index": 1,
        "selector_global": selector_global,
        "branches": branches,
        "explicit_branch_count": len(explicit),
        "default_branch_present": any(
            item["selector_kind"] == "default_fallthrough"
            for item in branches
        ),
        "duplicate_selector_values": duplicate_values,
        "missing_name_selector_values": missing_names,
        "malformed_condition_count": malformed_count,
        "common_exit": common_exit,
        "common_exit_hex": (
            f"0x{common_exit:X}" if common_exit is not None else None
        ),
        "name_loader": region.public(),
    }
    result["candidate_sha256"] = _canonical_sha256(result)
    return result


def _dispatcher_name_routes(
    document: HcbDocument,
    dispatcher: _FunctionRegion,
    regions_by_start: Mapping[int, _FunctionRegion],
) -> dict[int, dict[str, Any]]:
    body = document.instructions[
        dispatcher.instruction_start_index : dispatcher.instruction_end_index
    ]
    offset_to_index = {item.offset: index for index, item in enumerate(body)}
    first_argument_stack = -(dispatcher.args + 1)
    forwarded_selector_stack = -(dispatcher.args - 1)
    routes: dict[int, dict[str, Any]] = {}
    for index, item in enumerate(body):
        if (
            item.mnemonic != "push_stack"
            or int(item.operands.get("value", 0)) != first_argument_stack
        ):
            continue
        decoded = _decode_forward_integer(body, index + 1)
        if decoded is None:
            continue
        character_selector, cursor = decoded
        if (
            cursor + 1 >= len(body)
            or body[cursor].mnemonic != "set_e"
            or body[cursor + 1].mnemonic != "jz"
        ):
            continue
        false_target = int(body[cursor + 1].operands.get("target", -1))
        false_index = offset_to_index.get(false_target)
        if false_index is None or false_index <= cursor + 1:
            continue
        block = body[cursor + 2 : false_index]
        loader_targets = {
            int(branch.operands.get("target", -1))
            for branch in block
            if branch.mnemonic == "call"
            and int(branch.operands.get("target", -1)) in regions_by_start
            and any(
                _SPEAKER_NAME_RESOURCE.fullmatch(value)
                for value in regions_by_start[
                    int(branch.operands.get("target", -1))
                ].strings
            )
        }
        forwarded_globals = {
            int(block[position + 1].operands.get("value", -1))
            for position, branch in enumerate(block[:-1])
            if branch.mnemonic == "push_stack"
            and int(branch.operands.get("value", 0))
            == forwarded_selector_stack
            and block[position + 1].mnemonic == "pop_global"
        }
        if len(loader_targets) != 1 or len(forwarded_globals) != 1:
            continue
        loader_target = next(iter(loader_targets))
        selector_global = next(iter(forwarded_globals))
        loader = regions_by_start[loader_target]
        branches = _speaker_asset_selector_branches(
            document,
            loader,
            selector_global,
        )
        routes[character_selector] = {
            "character_selector": character_selector,
            "selector_global": selector_global,
            "name_loader_target": loader_target,
            "name_loader_target_hex": f"0x{loader_target:X}",
            "selector_branches": branches,
        }
    return routes


def _discover_delegated_speaker_wrapper_family(
    document: HcbDocument,
    regions: Sequence[_FunctionRegion],
) -> dict[str, Any]:
    """Discover early-FVP wrappers whose names live in delegated assets."""

    wrappers: list[tuple[_FunctionRegion, dict[str, Any]]] = []
    for region in regions:
        if region.args != 3 or region.locals != 0:
            break
        delegated = _delegated_speaker_call(document, region)
        if delegated is None:
            break
        wrappers.append((region, delegated))
    dispatcher_targets = {
        int(item["dispatcher_target"]) for _region, item in wrappers
    }
    regions_by_start = {region.start: region for region in regions}
    dispatcher = (
        regions_by_start.get(next(iter(dispatcher_targets)))
        if len(dispatcher_targets) == 1
        else None
    )
    routes = (
        _dispatcher_name_routes(document, dispatcher, regions_by_start)
        if dispatcher is not None and dispatcher.args == 3
        else {}
    )
    entries: list[dict[str, Any]] = []
    for index, (region, delegated) in enumerate(wrappers):
        route = routes.get(int(delegated["character_selector"]))
        branch_report = (
            route.get("selector_branches")
            if isinstance(route, Mapping)
            and isinstance(route.get("selector_branches"), Mapping)
            else {
                "status": "not_discovered",
                "selector_argument_index": None,
                "branches": [],
                "explicit_branch_count": 0,
                "default_branch_present": False,
            }
        )
        branch_values = (
            branch_report.get("branches")
            if isinstance(branch_report.get("branches"), list)
            else []
        )
        variants: list[str] = []
        for branch in branch_values:
            if not isinstance(branch, Mapping):
                continue
            for name in branch.get("name_variants", []):
                value = str(name)
                if value and value not in variants:
                    variants.append(value)
        selector_ready = (
            branch_report.get("status") == "candidate_local_control_flow"
            and bool(variants)
        )
        public = region.public()
        public.update(
            {
                "speaker_index": index,
                "name_variants": variants,
                "selector_argument_index": 1 if selector_ready else None,
                "selector_stack_offset": -region.args,
                "selector_position_status": (
                    "verified_by_stack_read"
                    if selector_ready
                    else "not_directly_read"
                ),
                "selection_mode": (
                    "selector_argument"
                    if selector_ready
                    else "fixed_or_delegated_candidate"
                ),
                "selector_branches": branch_report,
                "alias": None,
                "delegation": {
                    **delegated,
                    **(
                        {
                            key: copy.deepcopy(value)
                            for key, value in route.items()
                            if key != "selector_branches"
                        }
                        if isinstance(route, Mapping)
                        else {}
                    ),
                },
            }
        )
        entries.append(public)

    named_entries = [item for item in entries if item["name_variants"]]
    selector_entries = [
        item
        for item in named_entries
        if item["selector_position_status"] == "verified_by_stack_read"
    ]
    valid = (
        len(wrappers) >= 3
        and dispatcher is not None
        and bool(routes)
        and bool(selector_entries)
    )
    return {
        "status": "candidate_contiguous_prefix" if valid else "ambiguous",
        "discovery_mode": "delegated_name_asset_prefix" if valid else None,
        "entries": entries if valid else [],
        "entry_count": len(entries) if valid else 0,
        "named_entry_count": len(named_entries) if valid else 0,
        "selector_entry_count": len(selector_entries) if valid else 0,
        "non_selector_named_entry_count": (
            len(named_entries) - len(selector_entries) if valid else 0
        ),
        "selector_argument_index": 1 if valid else None,
        "selector_position_status": (
            "verified_for_selector_readers" if valid else "not_discovered"
        ),
        "aliases": [],
        "alias_count": 0,
        "color_table": None,
        "color_table_textcolor_count": 0,
        "dispatcher": dispatcher.public() if valid and dispatcher else None,
        "dispatcher_route_count": len(routes) if valid else 0,
        "warning": (
            "早期 FVP 说话人包装前缀、委托分派和 name_ 资源分支已定位；"
            "仅显式整数 selector 可用于纯内存编译"
            if valid
            else ""
        ),
    }


def _discover_speaker_wrapper_family(
    document: HcbDocument,
    regions: Sequence[_FunctionRegion],
) -> dict[str, Any]:
    direct = _discover_direct_speaker_wrapper_family(document, regions)
    if direct.get("status") == "candidate_contiguous_prefix":
        return direct
    return _discover_delegated_speaker_wrapper_family(document, regions)


_RESOURCE_NAMESPACE = re.compile(r"^(graph(?:_[a-z0-9]+)?)/$", re.IGNORECASE)


def _archive_name_for_namespace(namespace: str) -> str | None:
    match = _RESOURCE_NAMESPACE.fullmatch(str(namespace).casefold())
    return f"{match.group(1)}.bin" if match is not None else None


def _archive_directory_summary(
    root_files: Mapping[str, Path],
    archive_name: str,
) -> dict[str, Any]:
    path = root_files.get(archive_name.casefold())
    if path is None:
        return {
            "status": "missing",
            "name": archive_name,
            "entry_count": 0,
            "directory_sha256": None,
        }
    record = _file_stat(path)
    try:
        names, directory_sha256 = archive_directory_identity_file(path)
    except (OSError, BinArchiveError) as exc:
        return {
            **record,
            "status": "invalid_directory",
            "entry_count": 0,
            "directory_sha256": None,
            "error": str(exc),
        }
    return {
        **record,
        "status": "validated_directory",
        "entry_count": len(names),
        "directory_sha256": directory_sha256,
    }


def _namespace_selector_branches(
    document: HcbDocument,
    region: _FunctionRegion,
    allowed_namespaces: Iterable[str],
) -> dict[str, Any]:
    allowed = {str(value).casefold() for value in allowed_namespaces}
    body = document.instructions[
        region.instruction_start_index : region.instruction_end_index
    ]
    offset_to_index = {item.offset: index for index, item in enumerate(body)}
    conditions: list[dict[str, Any]] = []
    malformed_count = 0
    for index, item in enumerate(body):
        if item.mnemonic != "push_stack":
            continue
        decoded = _decode_forward_integer(body, index + 1)
        if decoded is None:
            continue
        selector_value, cursor = decoded
        if (
            cursor + 1 >= len(body)
            or body[cursor].mnemonic != "set_e"
            or body[cursor + 1].mnemonic != "jz"
        ):
            continue
        false_target = int(body[cursor + 1].operands.get("target", -1))
        false_index = offset_to_index.get(false_target)
        if false_index is None or false_index <= cursor + 1:
            malformed_count += 1
            continue
        block = body[cursor + 2 : false_index]
        namespaces = sorted(
            {
                str(branch.text).casefold()
                for branch in block
                if branch.mnemonic == "push_string"
                and branch.text is not None
                and str(branch.text).casefold() in allowed
            }
        )
        if not namespaces:
            continue
        if len(namespaces) != 1:
            malformed_count += 1
            continue
        conditions.append(
            {
                "selector_stack_offset": int(item.operands.get("value", 0)),
                "selector_kind": "integer",
                "selector_value": selector_value,
                "namespace": namespaces[0],
                "condition_offset": int(item.offset),
                "condition_offset_hex": f"0x{item.offset:X}",
                "false_target": false_target,
                "jump_targets": [
                    int(branch.operands.get("target", -1))
                    for branch in block
                    if branch.mnemonic == "jmp"
                ],
            }
        )

    jump_targets = [
        target
        for condition in conditions
        for target in condition["jump_targets"]
        if target >= 0
    ]
    common_exit = None
    if jump_targets:
        counts = Counter(jump_targets)
        ranked = counts.most_common()
        if len(ranked) == 1 or ranked[0][1] > ranked[1][1]:
            common_exit = int(ranked[0][0])

    branches: list[dict[str, Any]] = []
    for condition in conditions:
        branch = dict(condition)
        branch.pop("jump_targets", None)
        branches.append(branch)
    if conditions and common_exit is not None:
        default_start = int(conditions[-1]["false_target"])
        default_index = offset_to_index.get(default_start)
        exit_index = offset_to_index.get(common_exit, len(body))
        if default_index is not None and exit_index >= default_index:
            default_namespaces = sorted(
                {
                    str(item.text).casefold()
                    for item in body[default_index:exit_index]
                    if item.mnemonic == "push_string"
                    and item.text is not None
                    and str(item.text).casefold() in allowed
                }
            )
            if len(default_namespaces) == 1:
                branches.append(
                    {
                        "selector_stack_offset": conditions[-1][
                            "selector_stack_offset"
                        ],
                        "selector_kind": "default_fallthrough",
                        "selector_value": None,
                        "namespace": default_namespaces[0],
                        "condition_offset": None,
                        "condition_offset_hex": None,
                        "false_target": None,
                    }
                )
            elif default_namespaces:
                malformed_count += 1

    selector_offsets = {
        int(item["selector_stack_offset"]) for item in conditions
    }
    selector_offset = next(iter(selector_offsets)) if len(selector_offsets) == 1 else None
    selector_index = (
        selector_offset + region.args + 1
        if selector_offset is not None
        else None
    )
    duplicate_values = sorted(
        value
        for value, count in Counter(
            item["selector_value"] for item in conditions
        ).items()
        if count > 1
    )
    used_namespaces = [str(item["namespace"]) for item in branches]
    complete = (
        bool(conditions)
        and common_exit is not None
        and len(branches) == len(allowed)
        and set(used_namespaces) == allowed
        and len(used_namespaces) == len(set(used_namespaces))
        and not duplicate_values
        and malformed_count == 0
        and selector_index is not None
        and 0 <= selector_index < region.args
    )
    canonical = [
        {
            "selector_kind": item["selector_kind"],
            "selector_value": item["selector_value"],
            "namespace": item["namespace"],
        }
        for item in branches
    ]
    return {
        "status": "candidate_namespace_selector" if complete else "ambiguous",
        "selector_argument_index": selector_index,
        "selector_stack_offset": selector_offset,
        "branches": branches,
        "explicit_branch_count": len(conditions),
        "default_branch_present": any(
            item["selector_kind"] == "default_fallthrough" for item in branches
        ),
        "candidate_sha256": (
            _canonical_sha256(
                {
                    "resolver_structure_sha256": region.structure_sha256,
                    "selector_argument_index": selector_index,
                    "branches": canonical,
                }
            )
            if complete
            else None
        ),
        "blockers": [
            value
            for condition, value in (
                (not conditions, "namespace_selector_conditions_missing"),
                (common_exit is None, "namespace_selector_exit_ambiguous"),
                (set(used_namespaces) != allowed, "namespace_routes_incomplete"),
                (
                    len(used_namespaces) != len(set(used_namespaces)),
                    "namespace_route_duplicate",
                ),
                (bool(duplicate_values), "namespace_selector_value_duplicate"),
                (malformed_count > 0, "namespace_selector_control_flow_malformed"),
                (
                    selector_index is None
                    or not 0 <= selector_index < region.args,
                    "namespace_selector_position_invalid",
                ),
            )
            if condition
        ],
    }


def _namespace_selector_path_routes(
    document: HcbDocument,
    region: _FunctionRegion,
    allowed_namespaces: Iterable[str],
) -> dict[str, Any]:
    """Prove selector branches build one namespace-qualified load path.

    This is intentionally stricter than the generic string-branch extractor:
    every explicit branch must jump to one shared exit, a default route is
    mandatory, and every namespace must be concatenated with the same resource
    argument into the same stack slot that is then forwarded to a callee.
    """

    allowed = {str(value).casefold() for value in allowed_namespaces}
    body = document.instructions[
        region.instruction_start_index : region.instruction_end_index
    ]
    offset_to_index = {item.offset: index for index, item in enumerate(body)}

    def path_flow(
        block: Sequence[Any],
        namespace: str,
    ) -> dict[str, int] | None:
        matches: list[dict[str, int]] = []
        for index in range(max(0, len(block) - 3)):
            if (
                block[index].mnemonic == "push_string"
                and str(block[index].text or "").casefold() == namespace
                and block[index + 1].mnemonic == "push_stack"
                and block[index + 2].mnemonic == "add"
                and block[index + 3].mnemonic == "pop_stack"
            ):
                matches.append(
                    {
                        "source_stack_offset": int(
                            block[index + 1].operands.get("value", 0)
                        ),
                        "destination_stack_offset": int(
                            block[index + 3].operands.get("value", 0)
                        ),
                    }
                )
        return matches[0] if len(matches) == 1 else None

    conditions: list[dict[str, Any]] = []
    malformed_count = 0
    for index, item in enumerate(body):
        if item.mnemonic != "push_stack":
            continue
        decoded = _decode_forward_integer(body, index + 1)
        if decoded is None:
            continue
        selector_value, cursor = decoded
        if (
            cursor + 1 >= len(body)
            or body[cursor].mnemonic != "set_e"
            or body[cursor + 1].mnemonic != "jz"
        ):
            continue
        false_target = int(body[cursor + 1].operands.get("target", -1))
        false_index = offset_to_index.get(false_target)
        if false_index is None or false_index <= cursor + 1:
            malformed_count += 1
            continue
        block = body[cursor + 2 : false_index]
        namespaces = sorted(
            {
                str(branch.text).casefold()
                for branch in block
                if branch.mnemonic == "push_string"
                and branch.text is not None
                and str(branch.text).casefold() in allowed
            }
        )
        if not namespaces:
            continue
        if len(namespaces) != 1:
            malformed_count += 1
            continue
        flow = path_flow(block, namespaces[0])
        if flow is None:
            malformed_count += 1
        conditions.append(
            {
                "selector_stack_offset": int(item.operands.get("value", 0)),
                "selector_kind": "integer",
                "selector_value": selector_value,
                "namespace": namespaces[0],
                "condition_offset": int(item.offset),
                "condition_offset_hex": f"0x{item.offset:X}",
                "false_target": false_target,
                "path_source_stack_offset": (
                    flow["source_stack_offset"] if flow is not None else None
                ),
                "path_destination_stack_offset": (
                    flow["destination_stack_offset"]
                    if flow is not None
                    else None
                ),
                "jump_targets": [
                    int(branch.operands.get("target", -1))
                    for branch in block
                    if branch.mnemonic == "jmp"
                ],
            }
        )

    jump_lists = [
        [target for target in item["jump_targets"] if target >= 0]
        for item in conditions
    ]
    common_exit = None
    if (
        conditions
        and all(len(targets) == 1 for targets in jump_lists)
        and len({targets[0] for targets in jump_lists}) == 1
    ):
        common_exit = int(jump_lists[0][0])

    branches: list[dict[str, Any]] = []
    for condition in conditions:
        branch = dict(condition)
        branch.pop("jump_targets", None)
        branches.append(branch)

    if conditions and common_exit is not None:
        default_start = int(conditions[-1]["false_target"])
        default_index = offset_to_index.get(default_start)
        exit_index = offset_to_index.get(common_exit)
        if (
            default_index is not None
            and exit_index is not None
            and exit_index >= default_index
        ):
            default_block = body[default_index:exit_index]
            default_namespaces = sorted(
                {
                    str(item.text).casefold()
                    for item in default_block
                    if item.mnemonic == "push_string"
                    and item.text is not None
                    and str(item.text).casefold() in allowed
                }
            )
            if len(default_namespaces) == 1:
                flow = path_flow(default_block, default_namespaces[0])
                if flow is None:
                    malformed_count += 1
                branches.append(
                    {
                        "selector_stack_offset": conditions[-1][
                            "selector_stack_offset"
                        ],
                        "selector_kind": "default_fallthrough",
                        "selector_value": None,
                        "namespace": default_namespaces[0],
                        "condition_offset": None,
                        "condition_offset_hex": None,
                        "false_target": None,
                        "path_source_stack_offset": (
                            flow["source_stack_offset"]
                            if flow is not None
                            else None
                        ),
                        "path_destination_stack_offset": (
                            flow["destination_stack_offset"]
                            if flow is not None
                            else None
                        ),
                    }
                )
            elif default_namespaces:
                malformed_count += 1

    selector_offsets = {
        int(item["selector_stack_offset"]) for item in conditions
    }
    selector_offset = (
        next(iter(selector_offsets)) if len(selector_offsets) == 1 else None
    )
    selector_index = (
        selector_offset + region.args + 1
        if selector_offset is not None
        else None
    )
    path_sources = {
        item.get("path_source_stack_offset") for item in branches
    }
    path_destinations = {
        item.get("path_destination_stack_offset") for item in branches
    }
    source_offset = next(iter(path_sources)) if len(path_sources) == 1 else None
    destination_offset = (
        next(iter(path_destinations)) if len(path_destinations) == 1 else None
    )
    source_argument_index = (
        source_offset + region.args + 1
        if isinstance(source_offset, int) and source_offset < 0
        else None
    )
    destination_kind = None
    destination_index = None
    if isinstance(destination_offset, int):
        if 0 <= destination_offset < region.locals:
            destination_kind = "local"
            destination_index = destination_offset
        elif destination_offset < 0:
            argument_index = destination_offset + region.args + 1
            if 0 <= argument_index < region.args:
                destination_kind = "argument"
                destination_index = argument_index

    consumer_targets: list[int] = []
    if common_exit is not None and destination_offset is not None:
        exit_index = offset_to_index.get(common_exit)
        if exit_index is not None:
            for index in range(exit_index, min(len(body), exit_index + 96)):
                item = body[index]
                if (
                    item.mnemonic != "push_stack"
                    or int(item.operands.get("value", 0)) != destination_offset
                ):
                    continue
                for following in body[index + 1 : index + 17]:
                    if (
                        following.mnemonic == "pop_stack"
                        and int(following.operands.get("value", 0))
                        == destination_offset
                    ):
                        break
                    if following.mnemonic == "call":
                        target = int(following.operands.get("target", -1))
                        if target >= 0 and target not in consumer_targets:
                            consumer_targets.append(target)
                        break

    default_present = any(
        item["selector_kind"] == "default_fallthrough" for item in branches
    )
    duplicate_values = {
        value
        for value, count in Counter(
            item["selector_value"] for item in conditions
        ).items()
        if count > 1
    }
    used_namespaces = [str(item["namespace"]) for item in branches]
    path_proven = (
        None not in path_sources
        and None not in path_destinations
        and len(path_sources) == 1
        and len(path_destinations) == 1
        and source_argument_index is not None
        and 0 <= source_argument_index < region.args
        and destination_kind is not None
        and bool(consumer_targets)
    )
    complete = (
        len(conditions) == len(allowed) - 1
        and common_exit is not None
        and len(branches) == len(allowed)
        and default_present
        and set(used_namespaces) == allowed
        and len(used_namespaces) == len(set(used_namespaces))
        and not duplicate_values
        and malformed_count == 0
        and selector_index is not None
        and 0 <= selector_index < region.args
        and path_proven
    )
    canonical_branches = [
        {
            "selector_kind": item["selector_kind"],
            "selector_value": item["selector_value"],
            "namespace": item["namespace"],
            "path_source_stack_offset": item.get(
                "path_source_stack_offset"
            ),
            "path_destination_stack_offset": item.get(
                "path_destination_stack_offset"
            ),
        }
        for item in branches
    ]
    blockers = [
        value
        for condition, value in (
            (not conditions, "namespace_selector_conditions_missing"),
            (common_exit is None, "namespace_selector_exit_ambiguous"),
            (
                len(conditions) != len(allowed) - 1 or not default_present,
                "namespace_selector_default_branch_missing",
            ),
            (set(used_namespaces) != allowed, "namespace_routes_incomplete"),
            (
                len(used_namespaces) != len(set(used_namespaces)),
                "namespace_route_duplicate",
            ),
            (bool(duplicate_values), "namespace_selector_value_duplicate"),
            (malformed_count > 0, "namespace_selector_control_flow_malformed"),
            (not path_proven, "namespace_path_flow_not_proven"),
            (
                selector_index is None
                or not 0 <= selector_index < region.args,
                "namespace_selector_position_invalid",
            ),
        )
        if condition
    ]
    return {
        "status": "candidate_namespace_path_flow" if complete else "ambiguous",
        "selector_argument_index": selector_index,
        "selector_stack_offset": selector_offset,
        "branches": branches,
        "explicit_branch_count": len(conditions),
        "default_branch_present": default_present,
        "path_flow": {
            "source_stack_offset": source_offset,
            "source_argument_index": source_argument_index,
            "destination_stack_offset": destination_offset,
            "destination_kind": destination_kind,
            "destination_index": destination_index,
            "consumer_call_targets": consumer_targets,
            "consumer_call_count": len(consumer_targets),
            "common_exit_offset": common_exit,
            "common_exit_offset_hex": (
                f"0x{common_exit:X}" if common_exit is not None else None
            ),
        },
        "candidate_sha256": (
            _canonical_sha256(
                {
                    "resolver_structure_sha256": region.structure_sha256,
                    "selector_argument_index": selector_index,
                    "path_source_argument_index": source_argument_index,
                    "path_destination_kind": destination_kind,
                    "path_destination_index": destination_index,
                    "path_consumer_count": len(consumer_targets),
                    "branches": canonical_branches,
                }
            )
            if complete
            else None
        ),
        "blockers": blockers,
    }


def _routed_branches(
    branch_report: Mapping[str, Any],
    root_files: Mapping[str, Path],
) -> tuple[list[dict[str, Any]], list[str]]:
    routes: list[dict[str, Any]] = []
    blockers: list[str] = []
    for branch in branch_report.get("branches", []):
        if not isinstance(branch, Mapping):
            continue
        namespace = str(branch.get("namespace") or "").casefold()
        archive_name = _archive_name_for_namespace(namespace)
        if archive_name is None:
            blockers.append(f"archive_namespace_invalid:{namespace}")
            continue
        summary = _archive_directory_summary(root_files, archive_name)
        if summary.get("status") != "validated_directory":
            blockers.append(f"archive_directory_not_valid:{archive_name}")
        routes.append(
            {
                "namespace": namespace,
                "archive": archive_name,
                "selector_kind": branch.get("selector_kind"),
                "selector_value": branch.get("selector_value"),
                "archive_summary": summary,
            }
        )
    return routes, blockers


def _discover_resource_archive_routes(
    document: HcbDocument,
    regions: Sequence[_FunctionRegion],
    root_files: Mapping[str, Path],
    portrait: Mapping[str, Any],
) -> dict[str, Any]:
    region_by_start = {region.start: region for region in regions}

    def path_loaders(selector: Mapping[str, Any]) -> list[_FunctionRegion]:
        path_flow = (
            selector.get("path_flow")
            if isinstance(selector.get("path_flow"), Mapping)
            else {}
        )
        candidates: list[_FunctionRegion] = []
        for raw_target in path_flow.get("consumer_call_targets", []):
            try:
                target = int(raw_target)
            except (TypeError, ValueError):
                continue
            consumer = region_by_start.get(target)
            if consumer is None or consumer in candidates:
                continue
            counts = Counter(consumer.syscalls)
            if counts["GraphLoad"] >= 2 and counts["PrimSetNull"] >= 1:
                candidates.append(consumer)
        return candidates

    background_candidates: list[dict[str, Any]] = []
    for region in regions:
        if region.args != 3 or region.locals != 1 or region.syscalls:
            continue
        selector = _namespace_selector_path_routes(
            document,
            region,
            {"graph/", "graph_bg/"},
        )
        if selector.get("status") != "candidate_namespace_path_flow":
            continue
        load_consumers = path_loaders(selector)
        if len(load_consumers) != 1:
            continue
        callers = [
            caller for caller in regions if region.start in caller.call_targets
        ]
        loader_callers = []
        for caller in callers:
            counts = Counter(caller.syscalls)
            if (
                counts["GraphLoad"] == 2
                and counts["PrimSetNull"] >= 2
                and counts["DissolveWait"] == 1
            ):
                loader_callers.append(caller)
        if len(loader_callers) != 1:
            continue
        routes, route_blockers = _routed_branches(selector, root_files)
        background_candidates.append(
            {
                "resolver": region.public(),
                "loader_caller": loader_callers[0].public(),
                "path_loader": load_consumers[0].public(),
                "selector": selector,
                "routes": routes,
                "blockers": route_blockers,
                "candidate_sha256": _canonical_sha256(
                    {
                        "resolver": region.structure_sha256,
                        "loader_caller": loader_callers[0].structure_sha256,
                        "path_loader": load_consumers[0].structure_sha256,
                        "selector": selector.get("candidate_sha256"),
                        "routes": [
                            {
                                "namespace": item["namespace"],
                                "archive": item["archive"],
                                "selector_kind": item["selector_kind"],
                                "selector_value": item["selector_value"],
                            }
                            for item in routes
                        ],
                    }
                ),
            }
        )

    event_candidates: list[dict[str, Any]] = []
    for region in regions:
        counts = Counter(region.syscalls)
        if not (
            region.args == 10
            and region.locals == 0
            and counts["GraphLoad"] == 2
            and counts["PrimSetNull"] == 2
            and counts["PrimSetZ"] >= 1
            and counts["PrimSetRS"] >= 1
        ):
            continue
        selector = _namespace_selector_path_routes(
            document,
            region,
            {"graph_vis/", "graph_vis1/", "graph_vis2/"},
        )
        if selector.get("status") != "candidate_namespace_path_flow":
            continue
        load_consumers = path_loaders(selector)
        if len(load_consumers) != 1:
            continue
        routes, route_blockers = _routed_branches(selector, root_files)
        event_candidates.append(
            {
                "resolver": region.public(),
                "path_loader": load_consumers[0].public(),
                "selector": selector,
                "routes": routes,
                "blockers": route_blockers,
                "candidate_sha256": _canonical_sha256(
                    {
                        "resolver": region.structure_sha256,
                        "path_loader": load_consumers[0].structure_sha256,
                        "selector": selector.get("candidate_sha256"),
                        "routes": [
                            {
                                "namespace": item["namespace"],
                                "archive": item["archive"],
                                "selector_kind": item["selector_kind"],
                                "selector_value": item["selector_value"],
                            }
                            for item in routes
                        ],
                    }
                ),
            }
        )

    portrait_candidates: list[dict[str, Any]] = []
    selected_portrait = portrait.get("selected")
    if isinstance(selected_portrait, Mapping):
        namespaces = sorted(
            {
                f"{str(root).split('/', 1)[0].casefold()}/"
                for root in selected_portrait.get("character_resource_roots", [])
                if "/" in str(root)
            }
        )
        if len(namespaces) == 1 and namespaces[0] in {"graph/", "graph_bs/"}:
            archive_name = _archive_name_for_namespace(namespaces[0])
            if archive_name is not None:
                summary = _archive_directory_summary(root_files, archive_name)
                blockers = []
                if summary.get("status") != "validated_directory":
                    blockers.append(f"archive_directory_not_valid:{archive_name}")
                portrait_candidates.append(
                    {
                        "dispatcher": copy.deepcopy(dict(selected_portrait)),
                        "routes": [
                            {
                                "namespace": namespaces[0],
                                "archive": archive_name,
                                "selector_kind": "resource_root",
                                "selector_value": None,
                                "archive_summary": summary,
                            }
                        ],
                        "blockers": blockers,
                        "candidate_sha256": _canonical_sha256(
                            {
                                "dispatcher": selected_portrait.get(
                                    "structure_sha256"
                                ),
                                "namespace": namespaces[0],
                                "archive": archive_name,
                            }
                        ),
                    }
                )

    def role_report(candidates: list[dict[str, Any]]) -> dict[str, Any]:
        selected = candidates[0] if len(candidates) == 1 else None
        blockers: list[str] = []
        if not candidates:
            blockers.append("route_candidate_missing")
        elif len(candidates) > 1:
            blockers.append("route_candidate_ambiguous")
        if selected is not None:
            blockers.extend(str(item) for item in selected.get("blockers", []))
        return {
            "status": (
                "candidate_unique_structure"
                if selected is not None and not blockers
                else "blocked"
            ),
            "candidate_count": len(candidates),
            "candidates": candidates,
            "selected": selected if selected is not None and not blockers else None,
            "blockers": blockers,
        }

    background = role_report(background_candidates)
    portrait_route = role_report(portrait_candidates)
    event_visual = role_report(event_candidates)
    roles = {
        "background": background,
        "portrait": portrait_route,
        "event_visual": event_visual,
    }
    complete = all(
        role["status"] == "candidate_unique_structure" for role in roles.values()
    )
    return {
        "status": "candidate_complete" if complete else "blocked",
        **roles,
        "blockers": [
            f"{name}:{blocker}"
            for name, role in roles.items()
            for blocker in role["blockers"]
        ],
        "warning": (
            "HCB namespace 到 BIN 的路由结构已唯一定位；仍须目标 profile 审核"
            if complete
            else ""
        ),
    }


def _discover_event_visual_chain(
    regions: Sequence[_FunctionRegion],
    archive_routes: Mapping[str, Any],
) -> dict[str, Any]:
    """Find the native prepare -> resolver -> finish event-CG chain.

    Event resources have hundreds of tiny wrappers.  Their resource names vary
    by game, while the three-call skeleton is stable: a zero-argument prepare
    function, the ten-argument archive resolver already proven by namespace
    data flow, and an adjacent three-argument finish function.  A repeated
    caller family is considerably stronger evidence than address proximity or
    one coincidental call site.
    """

    event_report = (
        archive_routes.get("event_visual")
        if isinstance(archive_routes.get("event_visual"), Mapping)
        else {}
    )
    selected_route = (
        event_report.get("selected")
        if isinstance(event_report.get("selected"), Mapping)
        else None
    )
    resolver_record = (
        selected_route.get("resolver")
        if isinstance(selected_route, Mapping)
        and isinstance(selected_route.get("resolver"), Mapping)
        else None
    )
    if resolver_record is None or resolver_record.get("start") is None:
        return {
            "status": "blocked",
            "candidate_count": 0,
            "candidates": [],
            "selected": None,
            "blockers": ["event_visual_resolver_not_available"],
        }

    resolver_start = int(resolver_record["start"])
    by_start = {region.start: region for region in regions}
    groups: dict[tuple[int, int], list[_FunctionRegion]] = {}
    for caller in regions:
        calls = caller.call_targets
        if (
            caller.syscalls
            or len(calls) != 3
            or calls[1] != resolver_start
            or len(caller.strings) != 1
        ):
            continue
        prepare = by_start.get(calls[0])
        finish = by_start.get(calls[2])
        if not (
            prepare is not None
            and finish is not None
            and prepare.end == finish.start
            and prepare.args == 0
            and prepare.locals == 0
            and not prepare.syscalls
            and finish.args == 3
            and finish.locals == 1
            and not finish.syscalls
        ):
            continue
        groups.setdefault((prepare.start, finish.start), []).append(caller)

    candidates: list[dict[str, Any]] = []
    for (prepare_start, finish_start), callers in sorted(groups.items()):
        resource_names = sorted({caller.strings[0] for caller in callers})
        if len(callers) < 3 or len(resource_names) < 3:
            continue
        prepare = by_start[prepare_start]
        resolver = by_start.get(resolver_start)
        finish = by_start[finish_start]
        if resolver is None:
            continue
        candidates.append(
            {
                "prepare": prepare.public(),
                "show": resolver.public(),
                "finish": finish.public(),
                "caller_count": len(callers),
                "caller_argument_counts": sorted({caller.args for caller in callers}),
                "sample_resources": resource_names[:8],
                "candidate_sha256": _canonical_sha256(
                    {
                        "prepare": prepare.structure_sha256,
                        "show": resolver.structure_sha256,
                        "finish": finish.structure_sha256,
                        "caller_shapes": sorted(
                            {caller.structure_sha256 for caller in callers}
                        ),
                    }
                ),
            }
        )
    selected = candidates[0] if len(candidates) == 1 else None
    blockers: list[str] = []
    if not candidates:
        blockers.append("event_visual_chain_missing")
    elif len(candidates) > 1:
        blockers.append("event_visual_chain_ambiguous")
    return {
        "status": "candidate_unique_call_graph" if selected else "blocked",
        "candidate_count": len(candidates),
        "candidates": candidates,
        "selected": selected,
        "blockers": blockers,
        "warning": (
            "CG 准备/显示/收尾三段调用链唯一；仍须目标 profile 审核与实机验收"
            if selected
            else ""
        ),
    }


def _syscall_report(document: HcbDocument) -> dict[str, Any]:
    table = [
        {"id": index, "args": item.args, "name": item.name}
        for index, item in enumerate(document.header.syscalls)
    ]
    wanted = {
        "MotionAlpha",
        "MotionAlphaTest",
        "MotionMoveR",
        "MotionMoveRTest",
        "MotionMoveS2",
        "MotionMoveS2Test",
        "MotionMoveTest",
        "MotionMoveZ",
        "MotionMoveZTest",
        "PrimSetAlpha",
        "PrimSetRS",
        "PrimSetXY",
        "PrimSetZ",
    }
    return {
        "count": len(table),
        "table_sha256": _canonical_sha256(table),
        # Indices and arities belong to this HCB, not to a game-name registry.
        # A declared arity is not proof of parameter semantics or runtime safety.
        "table": table,
        "required_primitives": [item for item in table if item["name"] in wanted],
        "required_primitive_count": sum(item["name"] in wanted for item in table),
    }


def _capabilities(
    archives: Mapping[str, Any],
    document: HcbDocument,
    runtime_hcb: Mapping[str, Any],
    transform: Mapping[str, Any],
    portrait: Mapping[str, Any],
    visual_loader: Mapping[str, Any],
    portrait_lifecycle: Mapping[str, Any],
    story_dialogue: Mapping[str, Any],
    speaker_wrappers: Mapping[str, Any],
    archive_routes: Mapping[str, Any],
    background_dissolve: Mapping[str, Any],
    event_visual_chain: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    capabilities = {
        "resource_layout": {
            "status": "verified_by_filesystem",
            "available": bool(
                archives.get("mixed_visual")
                or archives.get("background")
                or archives.get("portrait")
                or archives.get("event_visual")
            ),
        },
        "background_scan": {
            "status": "available" if archives.get("background_preference") else "missing",
            "archive": archives.get("background_preference"),
        },
        "portrait_scan": {
            "status": "available" if archives.get("portrait_preference") else "missing",
            "archive": archives.get("portrait_preference"),
        },
        "cg_scan": {
            "status": "available" if archives.get("event_visual") else "missing",
            "archives": [item["name"] for item in archives.get("event_visual", [])],
        },
        "audio_scan": {
            "status": "available" if archives.get("audio") else "missing",
            "archives": [item["name"] for item in archives.get("audio", [])],
        },
        "linear_script_analysis": {
            "status": "verified" if not document.warnings else "read_only_warning",
            "warning_count": len(document.warnings),
        },
        "runtime_hcb_resolution": {
            "status": str(runtime_hcb.get("status") or "ambiguous"),
            "write_verified": bool(runtime_hcb.get("write_verified")),
        },
        "native_transform_family": {
            "status": transform.get("status"),
        },
        "native_portrait_dispatcher": {
            "status": portrait.get("status"),
        },
        "native_visual_loader_family": {
            "status": visual_loader.get("status"),
        },
        "native_portrait_lifecycle_family": {
            "status": portrait_lifecycle.get("status"),
        },
        "story_dialogue_abi": {
            "status": (
                "print_wait_and_speaker_candidates"
                if story_dialogue.get("status") == "candidate_unique_relation"
                and speaker_wrappers.get("status") == "candidate_contiguous_prefix"
                else "print_wait_candidate"
                if story_dialogue.get("status") == "candidate_unique_relation"
                else "not_discovered"
            )
        },
        "native_speaker_wrapper_family": {
            "status": speaker_wrappers.get("status"),
            "entry_count": int(speaker_wrappers.get("entry_count") or 0),
        },
        "visual_lifecycle": {
            "status": (
                "clear_apply_call_graph_candidate"
                if portrait_lifecycle.get("status")
                == "candidate_unique_call_graph_relation"
                else "not_discovered"
            )
        },
        "resource_archive_routing": {
            "status": (
                "namespace_routes_candidate"
                if archive_routes.get("status") == "candidate_complete"
                else "not_verified"
            ),
            "roles": {
                role: (
                    archive_routes.get(role, {}).get("status")
                    if isinstance(archive_routes.get(role), Mapping)
                    else "missing"
                )
                for role in ("background", "portrait", "event_visual")
            },
        },
        "native_scene_effects": {
            "background_dissolve": background_dissolve.get("status"),
            "event_visual_chain": event_visual_chain.get("status"),
        },
        "native_write": {"status": "blocked"},
    }
    blockers = [
        "runtime_active_hcb_not_runtime_verified",
        "real_game_acceptance_not_completed",
    ]
    if archive_routes.get("status") == "candidate_complete":
        blockers.append("resource_archive_write_routing_not_reviewed")
    else:
        blockers.append("resource_archive_write_routing_not_verified")
    if (
        portrait_lifecycle.get("status")
        == "candidate_unique_call_graph_relation"
    ):
        blockers.append("visual_lifecycle_cleanup_not_reviewed")
    else:
        blockers.append("visual_lifecycle_cleanup_not_discovered")
    if (
        story_dialogue.get("status") == "candidate_unique_relation"
        and speaker_wrappers.get("status") == "candidate_contiguous_prefix"
    ):
        blockers.append("story_speaker_selector_abi_not_reviewed")
    elif story_dialogue.get("status") == "candidate_unique_relation":
        blockers.append("story_speaker_abi_not_discovered")
    else:
        blockers.append("story_dialogue_and_speaker_abi_not_discovered")
        blockers.append("story_dialogue_family_ambiguous")
    if transform.get("status") != "verified_unique_structure":
        blockers.append("native_transform_family_ambiguous")
    if portrait.get("status") != "verified_unique_structure":
        blockers.append("native_portrait_dispatcher_ambiguous")
    if background_dissolve.get("status") != "candidate_unique_structure":
        blockers.append("background_dissolve_abi_not_discovered")
    else:
        blockers.append("background_dissolve_abi_not_reviewed")
    if event_visual_chain.get("status") != "candidate_unique_call_graph":
        blockers.append("event_visual_chain_not_discovered")
    else:
        blockers.append("event_visual_chain_not_reviewed")
    if (
        portrait_lifecycle.get("status")
        != "candidate_unique_call_graph_relation"
    ):
        blockers.append("native_portrait_lifecycle_family_ambiguous")
    return capabilities, blockers


def discover_fvp_target(
    game_dir: str | Path,
    *,
    active_script_name: str | None = None,
    analysis_encoding: str = "sjis",
) -> dict[str, Any]:
    """Return a deterministic, read-only native capability manifest."""

    normalized_encoding = _analysis_encoding(analysis_encoding)
    root = Path(game_dir).expanduser().resolve()
    if not root.is_dir():
        raise NativeTargetDiscoveryError(f"FVP 游戏目录不存在: {root}")
    if root.is_symlink():
        raise NativeTargetDiscoveryError(f"FVP 游戏目录是符号链接，拒绝分析: {root}")
    root_files = _root_files(root)
    hcb_candidates = sorted(
        (
            path
            for path in root_files.values()
            if path.suffix.casefold() in _SCRIPT_SUFFIXES
        ),
        key=lambda item: item.name.casefold(),
    )
    if not hcb_candidates:
        raise NativeTargetDiscoveryError(f"游戏根目录没有 HCB/BCH 剧情脚本: {root}")
    normalized_active_script_name = (
        str(active_script_name).strip().casefold()
        if active_script_name not in (None, "")
        else ""
    )
    cache_key = (
        *_discovery_cache_key(root, root_files),
        normalized_active_script_name,
        normalized_encoding,
    )
    cached = _cached_discovery(cache_key)
    if cached is not None:
        return cached

    analysis_hcb, analysis_reason = _select_analysis_hcb(
        hcb_candidates,
        active_script_name,
    )
    try:
        document = parse_bytes(
            analysis_hcb.read_bytes(),
            encoding=normalized_encoding,
            path=analysis_hcb,
        )
    except (OSError, HcbError) as exc:
        raise NativeTargetDiscoveryError(
            f"无法解析分析 HCB {analysis_hcb.name}: {exc}"
        ) from exc

    hcb_records = []
    for candidate in hcb_candidates:
        record = _file_stat(candidate, with_hash=True)
        record.update(
            {
                "hidden": candidate.name.startswith("."),
                "pair_key": _hcb_pair_key(candidate.name),
                "analysis_source": candidate == analysis_hcb,
            }
        )
        hcb_records.append(record)
    runtime_hcb = _runtime_hcb_resolution(
        hcb_candidates,
        root_files,
        active_script_name,
    )
    archives = _archive_roles(root_files)
    syscalls = _syscall_report(document)
    layout = _layout_classification(root_files, document, archives)
    regions = _function_regions(document)
    transform = _discover_transform_family(regions)
    direct_xy_addresses = {
        int(item["start"])
        for item in transform.get("direct_xy_candidates", [])
    }
    portrait = _discover_portrait_dispatcher(regions, direct_xy_addresses)
    visual_loader = _discover_visual_loader_family(regions)
    portrait_lifecycle = _discover_portrait_lifecycle_family(
        document,
        regions,
        portrait,
    )
    story_dialogue = _discover_story_dialogue_family(document, regions)
    speaker_wrappers = _discover_speaker_wrapper_family(document, regions)
    background_dissolve = _discover_background_dissolve_family(regions)
    archive_routes = _discover_resource_archive_routes(
        document,
        regions,
        root_files,
        portrait,
    )
    event_visual_chain = _discover_event_visual_chain(regions, archive_routes)
    capabilities, blockers = _capabilities(
        archives,
        document,
        runtime_hcb,
        transform,
        portrait,
        visual_loader,
        portrait_lifecycle,
        story_dialogue,
        speaker_wrappers,
        archive_routes,
        background_dissolve,
        event_visual_chain,
    )
    capabilities["target_layout"] = {
        "status": layout["kind"],
        "confidence": layout["confidence"],
        "native_binary_present": layout["native_binary_present"],
    }
    if layout["kind"] == "fvp_compatible_layout_candidate":
        blockers.append("engine_binary_identity_not_present")

    kernel = root_files.get("fvpkernel.dll")
    kernel_record = _file_stat(kernel, with_hash=True) if kernel is not None else None
    engine_identity = {
        "kernel_sha256": kernel_record.get("sha256") if kernel_record else None,
        "binary_identity_status": (
            "kernel_sha256" if kernel_record else "unavailable"
        ),
        "layout_class": layout["kind"],
        "syscall_table_sha256": syscalls["table_sha256"],
        "syscall_count": syscalls["count"],
        "game_mode": int(document.header.game_mode),
    }
    engine_family_id = _canonical_sha256(engine_identity)[:24]
    target_identity = {
        "engine_family_id": engine_family_id,
        "analysis_hcb_sha256": document.source_sha256,
        "hcb_pair_key": _hcb_pair_key(analysis_hcb.name),
        "archive_names": sorted(
            item["name"]
            for values in (
                [archives["mixed_visual"]] if archives.get("mixed_visual") else [],
                [archives["background"]] if archives.get("background") else [],
                [archives["portrait"]] if archives.get("portrait") else [],
                list(archives.get("event_visual", [])),
                list(archives.get("audio", [])),
            )
            for item in values
        ),
    }
    target_id = _canonical_sha256(target_identity)[:24]
    selected_transform = transform.get("selected") or {}
    selected_direct_xy = (
        transform["direct_xy_candidates"][0]
        if len(transform.get("direct_xy_candidates", [])) == 1
        else None
    )
    profile_seed = {
        "schema": PROFILE_SEED_SCHEMA,
        "target_id": target_id,
        "display_name": document.header.title or root.name,
        "engine_family_id": engine_family_id,
        "engine_identity": engine_identity,
        "target_identity": target_identity,
        "hcb": {
            "analysis_name": analysis_hcb.name,
            "analysis_sha256": document.source_sha256,
            "runtime_active_candidate": runtime_hcb.get("active_candidate"),
            "runtime_active_verified": False,
        },
        "archives": {
            "background": archives.get("background_preference"),
            "portrait": archives.get("portrait_preference"),
            "event_visual": [item["name"] for item in archives.get("event_visual", [])],
            "audio": [item["name"] for item in archives.get("audio", [])],
            "native_routes": copy.deepcopy(archive_routes),
        },
        "native_symbols": {
            "direct_xy": selected_direct_xy,
            "transform": selected_transform,
            "portrait_dispatcher": portrait.get("selected"),
            "visual_loader_family": visual_loader.get("selected"),
            "portrait_lifecycle_family": portrait_lifecycle.get("selected"),
            "story_dialogue_family": story_dialogue.get("selected"),
            "background_dissolve_family": background_dissolve.get("selected"),
            "event_visual_chain": event_visual_chain.get("selected"),
            "resource_archive_routes": copy.deepcopy(archive_routes),
            "speaker_wrapper_family": {
                "status": speaker_wrappers.get("status"),
                "entries": speaker_wrappers.get("entries", []),
                "color_table": speaker_wrappers.get("color_table"),
            },
        },
        "write_enabled": False,
        "required_reviews": list(blockers),
    }

    report: dict[str, Any] = {
        "schema": DISCOVERY_SCHEMA,
        "mode": "read_only",
        "writes_performed": False,
        "game_dir": str(root),
        "target_id": target_id,
        "target_identity": target_identity,
        "display_name": document.header.title or root.name,
        "engine": {
            "recognized_fvp_layout": True,
            "layout_class": layout["kind"],
            "layout_confidence": layout["confidence"],
            "layout_evidence": layout["evidence"],
            "native_binary_present": layout["native_binary_present"],
            "native_markers": layout["native_markers"],
            "kernel": kernel_record,
            "loader_present": "fvploadergui.exe" in root_files,
            "family_id": engine_family_id,
            "identity": engine_identity,
        },
        "hcb": {
            "analysis_source": analysis_hcb.name,
            "analysis_source_reason": analysis_reason,
            "analysis_encoding": document.encoding,
            "analysis_warning_count": len(document.warnings),
            "analysis_instruction_count": len(document.instructions),
            "analysis_function_count": len(regions),
            "analysis_string_count": document.string_count,
            "entry_point": int(document.header.entry_point),
            "candidates": hcb_records,
            "runtime_resolution": runtime_hcb,
        },
        "syscalls": syscalls,
        "archives": archives,
        "native_functions": {
            "transform_family": transform,
            "portrait_dispatcher": portrait,
            "visual_loader_family": visual_loader,
            "portrait_lifecycle_family": portrait_lifecycle,
            "story_dialogue_family": story_dialogue,
            "background_dissolve_family": background_dissolve,
            "event_visual_chain": event_visual_chain,
            "speaker_wrapper_family": speaker_wrappers,
            "resource_archive_routes": archive_routes,
        },
        "capabilities": capabilities,
        "write_gate": {
            "enabled": False,
            "policy": "fail_closed_until_reviewed_profile_and_runtime_acceptance",
            "blockers": blockers,
        },
        "profile_seed": profile_seed,
    }
    report["manifest_sha256"] = _canonical_sha256(report)
    _store_cached_discovery(cache_key, report)
    return copy.deepcopy(report)


def inspect_native_function_addresses(
    game_dir: str | Path,
    addresses: Iterable[int | str],
    *,
    active_script_name: str | None = None,
    analysis_encoding: str = "sjis",
) -> dict[str, Any]:
    """Inspect exact function entries for a reviewed target-profile draft.

    The returned structure hash removes absolute call targets, but the lookup
    itself requires an exact function boundary in this target's clean HCB.
    This helper is read-only and deliberately bounded so it cannot become a
    full-script export endpoint.
    """

    normalized_encoding = _analysis_encoding(analysis_encoding)
    requested: set[int] = set()
    for raw in addresses:
        if isinstance(raw, bool):
            raise NativeTargetDiscoveryError("函数地址不能是布尔值")
        try:
            value = int(raw, 0) if isinstance(raw, str) else int(raw)
        except (TypeError, ValueError) as exc:
            raise NativeTargetDiscoveryError(f"函数地址无效: {raw!r}") from exc
        if value < 4:
            raise NativeTargetDiscoveryError(f"函数地址超出代码区: 0x{value:X}")
        requested.add(value)
    if len(requested) > 256:
        raise NativeTargetDiscoveryError("单次最多核对 256 个函数地址")

    root = Path(game_dir).expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise NativeTargetDiscoveryError(f"FVP 游戏目录不可用于函数核对: {root}")
    root_files = _root_files(root)
    hcb_candidates = sorted(
        (
            path
            for path in root_files.values()
            if path.suffix.casefold() in _SCRIPT_SUFFIXES
        ),
        key=lambda item: item.name.casefold(),
    )
    if not hcb_candidates:
        raise NativeTargetDiscoveryError(f"游戏根目录没有 HCB/BCH 剧情脚本: {root}")
    analysis_hcb, analysis_reason = _select_analysis_hcb(
        hcb_candidates,
        active_script_name,
    )
    try:
        document = parse_bytes(
            analysis_hcb.read_bytes(),
            encoding=normalized_encoding,
            path=analysis_hcb,
        )
    except (OSError, HcbError) as exc:
        raise NativeTargetDiscoveryError(
            f"无法解析分析 HCB {analysis_hcb.name}: {exc}"
        ) from exc
    layout = _layout_classification(
        root_files,
        document,
        _archive_roles(root_files),
    )
    region_by_start = {region.start: region for region in _function_regions(document)}
    functions = {
        str(address): region_by_start[address].public()
        for address in sorted(requested)
        if address in region_by_start
    }
    missing = [address for address in sorted(requested) if address not in region_by_start]
    return {
        "schema": FUNCTION_INSPECTION_SCHEMA,
        "mode": "read_only",
        "writes_performed": False,
        "game_dir": str(root),
        "analysis_hcb": analysis_hcb.name,
        "analysis_reason": analysis_reason,
        "analysis_encoding": document.encoding,
        "analysis_sha256": document.source_sha256,
        "layout_class": layout["kind"],
        "functions": functions,
        "missing_addresses": missing,
        "missing_addresses_hex": [f"0x{address:X}" for address in missing],
    }


__all__ = [
    "DISCOVERY_SCHEMA",
    "FUNCTION_INSPECTION_SCHEMA",
    "NativeTargetDiscoveryError",
    "PROFILE_SEED_SCHEMA",
    "discover_fvp_target",
    "inspect_native_function_addresses",
]
