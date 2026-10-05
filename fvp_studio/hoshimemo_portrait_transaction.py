"""Transactional installer for validated Hoshimemo portrait and scene outputs.

The portrait backend deliberately stops at a deterministic patch plan.  A
byte emitter turns that plan into complete HCB and ``graph_bs.bin`` candidate
byte streams.  HOOK1 independently emits one HCB-only scene candidate.  This
module is the safety boundary between those already-validated candidates and
an isolated game copy.

It does *not* emit HCB bytecode or rebuild a BIN archive.  It provides:

* exact source/profile preflight before any write;
* plan-bound emitter attestation;
* a read-only dry-run report;
* verified backups and staged files;
* journaled two-file portrait commit (graph first, then HCB);
* journaled single-active-HCB scene commit with Hoshimemo overlay selection;
* compensating rollback if either replacement fails;
* drift-safe manual rollback.

Two files cannot be replaced atomically as one Windows filesystem operation.
The journal plus verified compensating rollback is therefore the transaction
model used here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Callable, Mapping
from uuid import uuid4

from .hoshimemo_portrait_backend import (
    BinaryFingerprint,
    HoshimemoPortraitBackendError,
    HoshimemoPortraitPatchPlan,
    preflight_target,
)


PORTRAIT_TRANSACTION_SCHEMA = (
    "fvp-studio-v2.hoshimemo-portrait-transaction.v1"
)
SCENE_TRANSACTION_SCHEMA = "fvp-studio-v2.hoshimemo-scene-transaction.v1"
PORTRAIT_TRANSACTION_BACKUP_DIR = ".fvpstudio-v2-backups"
PORTRAIT_TRANSACTION_MANIFEST = "portrait-transaction.json"
SCENE_TRANSACTION_MANIFEST = "scene-transaction.json"
_TX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SCENE_SCRIPT_SUFFIXES = frozenset({".hcb", ".bch"})
_SCENE_RESOURCE_ARCHIVE_RE = re.compile(
    r"^(?:graph|graph_bs|graph_bg|graph_vis(?:[0-9]+)?|bgm|bgm2|se)\.bin$",
    re.IGNORECASE,
)
_RUNTIME_TEXT_COMPANION_NAMES = (
    "LoaderDll.dll",
    "LocaleEmulator.dll",
    "uif_config.json",
    "winmm.dll",
)
_RUNTIME_TEXT_COMPANION_BY_CASEFOLD = {
    name.casefold(): name for name in _RUNTIME_TEXT_COMPANION_NAMES
}
_RUNTIME_TEXT_COMPANION_KIND_BY_NAME = {
    name.casefold(): f"runtime_text_{index}"
    for index, name in enumerate(_RUNTIME_TEXT_COMPANION_NAMES, start=1)
}
_RUNTIME_TEXT_COMPANION_NAME_BY_KIND = {
    kind: _RUNTIME_TEXT_COMPANION_BY_CASEFOLD[name]
    for name, kind in _RUNTIME_TEXT_COMPANION_KIND_BY_NAME.items()
}


class HoshimemoPortraitTransactionError(HoshimemoPortraitBackendError):
    """Raised when a portrait transaction is unsafe or cannot complete."""

    def __init__(self, message: str, *, manifest_path: Path | None = None) -> None:
        super().__init__(message)
        self.manifest_path = manifest_path


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise HoshimemoPortraitTransactionError(
            f"事务元数据不能序列化为 JSON: {exc}"
        ) from exc
    return encoded.encode("utf-8")


def patch_plan_sha256(plan: HoshimemoPortraitPatchPlan) -> str:
    """Return the stable identity to which emitted candidate bytes are bound."""

    return _sha256_bytes(_canonical_json_bytes(plan.to_dict()))


def _normalise_sha256(value: str, label: str) -> str:
    value = str(value).strip().lower()
    if not _SHA256_RE.fullmatch(value):
        raise HoshimemoPortraitTransactionError(f"{label}不是有效 SHA-256")
    return value


def _required_text(value: str, label: str) -> str:
    value = str(value).strip()
    if not value:
        raise HoshimemoPortraitTransactionError(f"{label}不能为空")
    return value


def _safe_filename(value: str, label: str) -> str:
    value = _required_text(value, label)
    path = Path(value)
    if value in {".", ".."} or path.name != value or path.is_absolute():
        raise HoshimemoPortraitTransactionError(
            f"{label}必须是目标根目录中的单个文件名"
        )
    return value


def _scene_archive_kind(filename: str) -> str:
    name = _safe_filename(filename, "剧情资源归档文件名").casefold()
    if not _SCENE_RESOURCE_ARCHIVE_RE.fullmatch(name):
        raise HoshimemoPortraitTransactionError(
            f"剧情资源归档不在允许范围内: {name}"
        )
    return name[:-4]


def _scene_kind_archive_name(kind: str) -> str | None:
    value = str(kind or "").strip().casefold()
    if not value or value == "hcb":
        return None
    filename = f"{value}.bin"
    return filename if _SCENE_RESOURCE_ARCHIVE_RE.fullmatch(filename) else None


def _scene_runtime_kind(filename: str) -> str:
    name = _safe_filename(filename, "运行时文字伴随组件文件名").casefold()
    kind = _RUNTIME_TEXT_COMPANION_KIND_BY_NAME.get(name)
    if kind is None:
        raise HoshimemoPortraitTransactionError(
            f"运行时文字伴随组件不在允许范围内: {filename}"
        )
    return kind


def _scene_kind_runtime_name(kind: str) -> str | None:
    return _RUNTIME_TEXT_COMPANION_NAME_BY_KIND.get(
        str(kind or "").strip().casefold()
    )


@dataclass(frozen=True)
class ValidatedPortraitOutputs:
    """Complete candidate files emitted and validated for one exact plan."""

    hcb: bytes
    graph_bs: bytes
    plan_sha256: str
    emitter_id: str
    validation: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.hcb, bytes) or not self.hcb:
            raise HoshimemoPortraitTransactionError("候选 HCB 必须是非空 bytes")
        if not isinstance(self.graph_bs, bytes) or not self.graph_bs:
            raise HoshimemoPortraitTransactionError(
                "候选 graph_bs.bin 必须是非空 bytes"
            )
        object.__setattr__(
            self,
            "plan_sha256",
            _normalise_sha256(self.plan_sha256, "候选计划哈希"),
        )
        object.__setattr__(
            self,
            "emitter_id",
            _required_text(self.emitter_id, "字节生成器 ID"),
        )
        validation = dict(self.validation)
        if validation.get("passed") is not True:
            raise HoshimemoPortraitTransactionError(
                "候选字节缺少 passed=true 的生成器校验报告"
            )
        if validation.get("install_ready") is not True:
            raise HoshimemoPortraitTransactionError(
                "候选字节尚未完成精确场景挂接，缺少 install_ready=true"
            )
        _canonical_json_bytes(validation)
        object.__setattr__(self, "validation", validation)


@dataclass(frozen=True)
class ValidatedSceneOutput:
    """One scene candidate bound to its exact source and plan.

    ``resource_archives`` contains complete additive BIN candidates keyed by
    their target filename.  The legacy ``graph_bs`` fields remain accepted so
    older callers and already-generated manifests stay usable; they are folded
    into the canonical resource mapping during validation.
    """

    hcb: bytes
    source_sha256: str
    plan_sha256: str
    emitter_id: str
    profile_id: str
    validation: Mapping[str, Any] = field(default_factory=dict)
    graph_bs: bytes | None = None
    graph_bs_source_sha256: str | None = None
    resource_archives: Mapping[str, bytes] = field(default_factory=dict)
    resource_archive_files: Mapping[str, Path] = field(default_factory=dict)
    resource_archive_source_sha256: Mapping[str, str] = field(default_factory=dict)
    runtime_text_companion_files: Mapping[str, bytes] = field(default_factory=dict)
    resource_archive_source_size: Mapping[str, int] = field(
        init=False,
        repr=False,
        default_factory=dict,
    )
    resource_archive_added_bytes: Mapping[str, int] = field(
        init=False,
        repr=False,
        default_factory=dict,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.hcb, bytes) or not self.hcb:
            raise HoshimemoPortraitTransactionError("剧情候选 HCB 必须是非空 bytes")
        source_sha256 = _normalise_sha256(self.source_sha256, "剧情候选源 HCB 哈希")
        plan_sha256 = _normalise_sha256(self.plan_sha256, "剧情候选计划哈希")
        emitter_id = _required_text(self.emitter_id, "剧情字节生成器 ID")
        profile_id = _required_text(self.profile_id, "剧情目标 profile ID")
        validation = dict(self.validation)
        if validation.get("passed") is not True or validation.get("dry_run_passed") is not True:
            raise HoshimemoPortraitTransactionError(
                "剧情候选缺少 passed=true 与 dry_run_passed=true 的生成器校验"
            )
        if validation.get("install_ready") is not True:
            raise HoshimemoPortraitTransactionError(
                "剧情候选尚未完成精确挂接验证，缺少 install_ready=true"
            )
        if str(validation.get("emitter_id") or "") != emitter_id:
            raise HoshimemoPortraitTransactionError("剧情候选生成器身份与报告不一致")
        if str(validation.get("profile_id") or "") != profile_id:
            raise HoshimemoPortraitTransactionError("剧情候选 profile 与报告不一致")
        if str(validation.get("plan_sha256") or "").casefold() != plan_sha256:
            raise HoshimemoPortraitTransactionError("剧情候选计划哈希与报告不一致")
        source = validation.get("source") if isinstance(validation.get("source"), Mapping) else {}
        if str(source.get("hcb_sha256") or "").casefold() != source_sha256:
            raise HoshimemoPortraitTransactionError("剧情候选源 HCB 哈希与报告不一致")
        output = validation.get("output") if isinstance(validation.get("output"), Mapping) else {}
        if str(output.get("hcb_sha256") or "").casefold() != _sha256_bytes(self.hcb):
            raise HoshimemoPortraitTransactionError("剧情候选字节哈希与报告不一致")
        archives = dict(self.resource_archives)
        archive_files = dict(self.resource_archive_files)
        archive_sources = dict(self.resource_archive_source_sha256)
        graph = self.graph_bs
        graph_source = self.graph_bs_source_sha256
        if graph is None:
            if graph_source not in (None, ""):
                raise HoshimemoPortraitTransactionError(
                    "HCB-only 剧情候选不能携带 graph_bs 源哈希"
                )
            graph_source = None
        else:
            if not isinstance(graph, bytes) or not graph:
                raise HoshimemoPortraitTransactionError(
                    "剧情立绘候选 graph_bs.bin 必须是非空 bytes"
                )
            graph_source = _normalise_sha256(
                str(graph_source or ""),
                "剧情候选源 graph_bs 哈希",
            )
            existing_graph = archives.get("graph_bs.bin")
            if existing_graph is not None and existing_graph != graph:
                raise HoshimemoPortraitTransactionError(
                    "graph_bs 兼容字段与通用资源归档候选不一致"
                )
            existing_source = archive_sources.get("graph_bs.bin")
            if existing_source not in (None, "") and str(existing_source).casefold() != graph_source:
                raise HoshimemoPortraitTransactionError(
                    "graph_bs 兼容字段与通用资源归档源哈希不一致"
                )
            archives["graph_bs.bin"] = graph
            archive_sources["graph_bs.bin"] = graph_source

        if set(archives).intersection(archive_files):
            raise HoshimemoPortraitTransactionError(
                "同一剧情资源归档不能同时提供内存候选和文件候选"
            )

        source_archives_report = (
            source.get("resource_archives")
            if isinstance(source.get("resource_archives"), Mapping)
            else {}
        )
        output_archives_report = (
            output.get("resource_archives")
            if isinstance(output.get("resource_archives"), Mapping)
            else {}
        )
        all_archive_names = set(archives).union(archive_files)
        if all_archive_names != set(archive_sources):
            raise HoshimemoPortraitTransactionError(
                "剧情候选资源归档与源哈希文件集合不一致"
            )
        canonical_archives: dict[str, bytes] = {}
        canonical_archive_files: dict[str, Path] = {}
        canonical_sources: dict[str, str] = {}
        canonical_source_sizes: dict[str, int] = {}
        canonical_added_bytes: dict[str, int] = {}
        for raw_name in [*archives, *archive_files]:
            name = _safe_filename(str(raw_name), "剧情资源归档文件名")
            if not _SCENE_RESOURCE_ARCHIVE_RE.fullmatch(name):
                raise HoshimemoPortraitTransactionError(
                    f"剧情资源归档不在允许范围内: {name}"
                )
            canonical_name = name.casefold()
            if (
                canonical_name in canonical_archives
                or canonical_name in canonical_archive_files
            ):
                raise HoshimemoPortraitTransactionError(
                    f"剧情资源归档文件名大小写冲突: {name}"
                )
            payload = archives.get(raw_name)
            candidate_path: Path | None = None
            if raw_name in archives:
                if not isinstance(payload, bytes) or not payload:
                    raise HoshimemoPortraitTransactionError(
                        f"剧情资源归档 {name} 必须是非空 bytes"
                    )
                candidate_size = len(payload)
                candidate_hash = _sha256_bytes(payload)
            else:
                raw_candidate_path = Path(archive_files[raw_name]).expanduser()
                if raw_candidate_path.is_symlink():
                    raise HoshimemoPortraitTransactionError(
                        f"剧情资源归档文件候选不能是符号链接: {raw_candidate_path}"
                    )
                candidate_path = raw_candidate_path.resolve()
                if not candidate_path.is_file():
                    raise HoshimemoPortraitTransactionError(
                        f"剧情资源归档文件候选不存在: {candidate_path}"
                    )
                try:
                    candidate_size = int(candidate_path.stat().st_size)
                    candidate_hash = _sha256_file(candidate_path)
                except OSError as exc:
                    raise HoshimemoPortraitTransactionError(
                        f"无法读取剧情资源归档文件候选: {candidate_path}"
                    ) from exc
                if candidate_size <= 0:
                    raise HoshimemoPortraitTransactionError(
                        f"剧情资源归档文件候选为空: {candidate_path}"
                    )
            source_hash = _normalise_sha256(
                str(archive_sources.get(raw_name) or ""),
                f"剧情候选源 {name} 哈希",
            )
            source_record = source_archives_report.get(raw_name)
            if source_record is None:
                source_record = source_archives_report.get(canonical_name)
            output_record = output_archives_report.get(raw_name)
            if output_record is None:
                output_record = output_archives_report.get(canonical_name)
            if name.casefold() == "graph_bs.bin":
                legacy_source_hash = str(source.get("graph_bs_sha256") or "").casefold()
                legacy_output_hash = str(output.get("graph_bs_sha256") or "").casefold()
            else:
                legacy_source_hash = ""
                legacy_output_hash = ""
            reported_source_hash = (
                str(source_record.get("sha256") or "").casefold()
                if isinstance(source_record, Mapping)
                else legacy_source_hash
            )
            reported_output_hash = (
                str(output_record.get("sha256") or "").casefold()
                if isinstance(output_record, Mapping)
                else legacy_output_hash
            )
            if reported_source_hash != source_hash:
                raise HoshimemoPortraitTransactionError(
                    f"剧情候选源 {name} 哈希与报告不一致"
                )
            if reported_output_hash != candidate_hash:
                raise HoshimemoPortraitTransactionError(
                    f"剧情候选 {name} 字节哈希与报告不一致"
                )
            if isinstance(source_record, Mapping):
                try:
                    reported_source_size = int(source_record.get("size"))
                except (TypeError, ValueError) as exc:
                    raise HoshimemoPortraitTransactionError(
                        f"剧情候选源 {name} 大小报告无效"
                    ) from exc
                if reported_source_size <= 0:
                    raise HoshimemoPortraitTransactionError(
                        f"剧情候选源 {name} 大小报告无效"
                    )
            else:
                reported_source_size = None
            if isinstance(output_record, Mapping):
                try:
                    reported_output_size = int(output_record.get("size"))
                except (TypeError, ValueError) as exc:
                    raise HoshimemoPortraitTransactionError(
                        f"剧情候选 {name} 大小报告无效"
                    ) from exc
                if reported_output_size != candidate_size:
                    raise HoshimemoPortraitTransactionError(
                        f"剧情候选 {name} 字节大小与报告不一致"
                    )
                if reported_source_size is not None:
                    try:
                        reported_added = int(output_record.get("added_bytes"))
                    except (TypeError, ValueError) as exc:
                        raise HoshimemoPortraitTransactionError(
                            f"剧情候选 {name} 增量报告无效"
                        ) from exc
                    if reported_added != candidate_size - reported_source_size:
                        raise HoshimemoPortraitTransactionError(
                            f"剧情候选 {name} 增量字节与报告不一致"
                        )
                    canonical_added_bytes[canonical_name] = reported_added
            if candidate_path is None:
                assert isinstance(payload, bytes)
                canonical_archives[canonical_name] = payload
            else:
                canonical_archive_files[canonical_name] = candidate_path
            canonical_sources[canonical_name] = source_hash
            if reported_source_size is not None:
                canonical_source_sizes[canonical_name] = reported_source_size

        raw_runtime_files = dict(self.runtime_text_companion_files)
        runtime_report = (
            output.get("runtime_text_companion_files")
            if isinstance(output.get("runtime_text_companion_files"), Mapping)
            else {}
        )
        canonical_runtime_files: dict[str, bytes] = {}
        if raw_runtime_files:
            supplied_names = {str(name).casefold() for name in raw_runtime_files}
            if supplied_names != set(_RUNTIME_TEXT_COMPANION_BY_CASEFOLD):
                raise HoshimemoPortraitTransactionError(
                    "运行时文字伴随组件必须完整包含 winmm.dll、LoaderDll.dll、"
                    "LocaleEmulator.dll 与 uif_config.json"
                )
            if {str(name).casefold() for name in runtime_report} != supplied_names:
                raise HoshimemoPortraitTransactionError(
                    "运行时文字伴随组件与候选报告文件集合不一致"
                )
            for raw_name, payload in raw_runtime_files.items():
                folded = str(raw_name).casefold()
                name = _RUNTIME_TEXT_COMPANION_BY_CASEFOLD[folded]
                if not isinstance(payload, bytes) or not payload:
                    raise HoshimemoPortraitTransactionError(
                        f"运行时文字伴随组件 {name} 必须是非空 bytes"
                    )
                report_record = runtime_report.get(raw_name)
                if report_record is None:
                    report_record = next(
                        (
                            value
                            for key, value in runtime_report.items()
                            if str(key).casefold() == folded
                        ),
                        None,
                    )
                if not isinstance(report_record, Mapping):
                    raise HoshimemoPortraitTransactionError(
                        f"运行时文字伴随组件 {name} 缺少候选报告"
                    )
                try:
                    reported_size = int(report_record.get("size"))
                except (TypeError, ValueError) as exc:
                    raise HoshimemoPortraitTransactionError(
                        f"运行时文字伴随组件 {name} 大小报告无效"
                    ) from exc
                digest = _sha256_bytes(payload)
                if (
                    reported_size != len(payload)
                    or str(report_record.get("sha256") or "").casefold() != digest
                ):
                    raise HoshimemoPortraitTransactionError(
                        f"运行时文字伴随组件 {name} 与候选报告不一致"
                    )
                canonical_runtime_files[name] = payload
        elif runtime_report:
            raise HoshimemoPortraitTransactionError(
                "候选报告声明了运行时文字伴随组件，但没有提供文件负载"
            )
        _canonical_json_bytes(validation)
        object.__setattr__(self, "source_sha256", source_sha256)
        object.__setattr__(self, "plan_sha256", plan_sha256)
        object.__setattr__(self, "emitter_id", emitter_id)
        object.__setattr__(self, "profile_id", profile_id)
        object.__setattr__(self, "validation", validation)
        object.__setattr__(self, "graph_bs", canonical_archives.get("graph_bs.bin"))
        object.__setattr__(
            self,
            "graph_bs_source_sha256",
            canonical_sources.get("graph_bs.bin"),
        )
        object.__setattr__(self, "resource_archives", canonical_archives)
        object.__setattr__(self, "resource_archive_files", canonical_archive_files)
        object.__setattr__(self, "resource_archive_source_sha256", canonical_sources)
        object.__setattr__(self, "resource_archive_source_size", canonical_source_sizes)
        object.__setattr__(self, "resource_archive_added_bytes", canonical_added_bytes)
        object.__setattr__(self, "runtime_text_companion_files", canonical_runtime_files)


@dataclass(frozen=True)
class PortraitTransactionTarget:
    """One explicit isolated game-copy target."""

    root: Path
    hcb_name: str
    graph_bs_name: str = "graph_bs.bin"
    protected_roots: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root).expanduser().resolve())
        object.__setattr__(
            self,
            "hcb_name",
            _safe_filename(self.hcb_name, "HCB 文件名"),
        )
        graph_name = _safe_filename(self.graph_bs_name, "graph_bs 文件名")
        if graph_name.lower() != "graph_bs.bin":
            raise HoshimemoPortraitTransactionError(
                "当前 Hoshimemo 立绘后端只允许事务写入 graph_bs.bin"
            )
        object.__setattr__(self, "graph_bs_name", graph_name)
        object.__setattr__(
            self,
            "protected_roots",
            tuple(Path(item).expanduser().resolve() for item in self.protected_roots),
        )

    @property
    def hcb_path(self) -> Path:
        return self.root / self.hcb_name

    @property
    def graph_bs_path(self) -> Path:
        return self.root / self.graph_bs_name


@dataclass(frozen=True)
class SceneTransactionTarget:
    """A proven game target, isolated unless its exact active root is authorized."""

    root: Path
    profile_id: str
    protected_roots: tuple[Path, ...] = ()
    graph_bs_name: str = "graph_bs.bin"
    active_hcb_name: str | None = None
    active_source_root_authorized: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root).expanduser().resolve())
        object.__setattr__(
            self,
            "profile_id",
            _required_text(self.profile_id, "剧情目标 profile ID"),
        )
        object.__setattr__(
            self,
            "protected_roots",
            tuple(Path(item).expanduser().resolve() for item in self.protected_roots),
        )
        if not isinstance(self.active_source_root_authorized, bool):
            raise HoshimemoPortraitTransactionError(
                "活动来源根目录授权必须是显式布尔值"
            )
        graph_name = _safe_filename(self.graph_bs_name, "graph_bs 文件名")
        if graph_name.casefold() != "graph_bs.bin":
            raise HoshimemoPortraitTransactionError(
                "当前统一剧情事务只允许写入 graph_bs.bin"
            )
        object.__setattr__(self, "graph_bs_name", graph_name)
        active_name = self.active_hcb_name
        if active_name in (None, ""):
            object.__setattr__(self, "active_hcb_name", None)
        else:
            active_name = _safe_filename(str(active_name), "活动剧情脚本文件名")
            if Path(active_name).suffix.casefold() not in _SCENE_SCRIPT_SUFFIXES:
                raise HoshimemoPortraitTransactionError(
                    "活动剧情脚本文件名必须以 .hcb 或 .bch 结尾"
                )
            object.__setattr__(self, "active_hcb_name", active_name)

    @property
    def graph_bs_path(self) -> Path:
        return self.root / self.graph_bs_name

    def resource_archive_path(self, name: str) -> Path:
        filename = _safe_filename(name, "剧情资源归档文件名")
        if not _SCENE_RESOURCE_ARCHIVE_RE.fullmatch(filename):
            raise HoshimemoPortraitTransactionError(
                f"剧情资源归档不在允许范围内: {filename}"
            )
        if filename.casefold() == "graph_bs.bin":
            filename = self.graph_bs_name
        return self.root / filename


def _paths_overlap(left: Path, right: Path) -> bool:
    return (
        left == right
        or left.is_relative_to(right)
        or right.is_relative_to(left)
    )


def _validate_target(target: PortraitTransactionTarget) -> tuple[Path, Path]:
    root = target.root
    if not root.is_dir():
        raise HoshimemoPortraitTransactionError(
            f"隔离测试副本目录不存在: {root}"
        )
    for protected in target.protected_roots:
        if _paths_overlap(root, protected):
            raise HoshimemoPortraitTransactionError(
                f"目标目录与受保护原目录重叠，拒绝写入: {protected}"
            )

    hcb_path = target.hcb_path
    graph_path = target.graph_bs_path
    for path, label in ((hcb_path, "HCB"), (graph_path, "graph_bs.bin")):
        if path.is_symlink():
            raise HoshimemoPortraitTransactionError(
                f"{label} 是符号链接，拒绝事务写入: {path}"
            )
        resolved = path.resolve()
        if resolved.parent != root or not resolved.is_file():
            raise HoshimemoPortraitTransactionError(
                f"隔离副本缺少根目录直属 {label}: {path}"
            )

    hcb_candidates = sorted(
        item.resolve()
        for item in root.iterdir()
        if item.is_file() and item.suffix.lower() == ".hcb"
    )
    if hcb_candidates != [hcb_path.resolve()]:
        names = ", ".join(item.name for item in hcb_candidates) or "<无>"
        raise HoshimemoPortraitTransactionError(
            f"隔离副本必须恰好有一个活动 HCB；当前为: {names}"
        )
    return hcb_path.resolve(), graph_path.resolve()


def _fingerprint_dict(data: bytes) -> dict[str, Any]:
    return BinaryFingerprint.from_bytes(data).to_dict()


def _fingerprint_file_dict(path: Path) -> dict[str, Any]:
    try:
        size = int(path.stat().st_size)
        digest = _sha256_file(path)
    except OSError as exc:
        raise HoshimemoPortraitTransactionError(
            f"无法读取文件指纹: {path}"
        ) from exc
    return {"sha256": digest, "size": size}


def _scene_resource_names(outputs: ValidatedSceneOutput) -> tuple[str, ...]:
    names = set(outputs.resource_archives).union(outputs.resource_archive_files)
    return tuple(sorted(names, key=lambda item: item.casefold()))


def _scene_runtime_companion_names(
    outputs: ValidatedSceneOutput,
) -> tuple[str, ...]:
    supplied = {str(name).casefold() for name in outputs.runtime_text_companion_files}
    return tuple(
        name
        for name in _RUNTIME_TEXT_COMPANION_NAMES
        if name.casefold() in supplied
    )


def _scene_resource_after_fingerprint(
    outputs: ValidatedSceneOutput,
    name: str,
) -> dict[str, Any]:
    payload = outputs.resource_archives.get(name)
    if payload is not None:
        return _fingerprint_dict(payload)
    candidate = outputs.resource_archive_files.get(name)
    if candidate is None:
        raise HoshimemoPortraitTransactionError(
            f"剧情候选缺少资源归档负载: {name}"
        )
    return _fingerprint_file_dict(candidate)


def prepare_portrait_transaction(
    plan: HoshimemoPortraitPatchPlan,
    target: PortraitTransactionTarget,
    outputs: ValidatedPortraitOutputs,
) -> dict[str, Any]:
    """Perform the complete read-only dry run for an install."""

    plan_hash = patch_plan_sha256(plan)
    if outputs.plan_sha256 != plan_hash:
        raise HoshimemoPortraitTransactionError(
            "候选字节绑定的计划哈希与当前补丁计划不一致"
        )
    hcb_path, graph_path = _validate_target(target)
    hcb_before = hcb_path.read_bytes()
    graph_before = graph_path.read_bytes()
    preflight = preflight_target(plan.profile, hcb_before, graph_before)
    if outputs.hcb == hcb_before:
        raise HoshimemoPortraitTransactionError("候选 HCB 没有任何变化")
    if outputs.graph_bs == graph_before:
        raise HoshimemoPortraitTransactionError(
            "候选 graph_bs.bin 没有任何变化"
        )

    return {
        "schema": PORTRAIT_TRANSACTION_SCHEMA,
        "mode": "dry-run",
        "writes_performed": False,
        "profile_id": plan.profile.profile_id,
        "plan_sha256": plan_hash,
        "target_root": str(target.root),
        "preflight": preflight.to_dict(),
        "emitter": {
            "id": outputs.emitter_id,
            "validation": dict(outputs.validation),
        },
        "commit_order": ["graph_bs", "hcb"],
        "files": [
            {
                "kind": "hcb",
                "path": str(hcb_path),
                "before": _fingerprint_dict(hcb_before),
                "after": _fingerprint_dict(outputs.hcb),
            },
            {
                "kind": "graph_bs",
                "path": str(graph_path),
                "before": _fingerprint_dict(graph_before),
                "after": _fingerprint_dict(outputs.graph_bs),
            },
        ],
        "safety": {
            "single_active_hcb": True,
            "protected_roots_checked": True,
            "source_fingerprints_match": True,
            "candidate_validation_passed": True,
            "original_studio_untouched": True,
        },
    }


def _write_bytes_fsynced(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _copy_file_fsynced(source: Path, destination: Path) -> None:
    try:
        with source.open("rb") as input_handle, destination.open("xb") as output_handle:
            shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
            output_handle.flush()
            os.fsync(output_handle.fileno())
    except OSError as exc:
        raise HoshimemoPortraitTransactionError(
            f"无法暂存文件候选 {source.name}: {exc}"
        ) from exc


def _write_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        encoded = json.dumps(
            manifest,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ).encode("utf-8")
        _write_bytes_fsynced(temporary, encoded)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _new_transaction_id() -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{stamp}_{uuid4().hex[:10]}"


def _validate_transaction_id(value: str | None) -> str:
    value = _new_transaction_id() if value is None else str(value)
    if not _TX_ID_RE.fullmatch(value):
        raise HoshimemoPortraitTransactionError("事务 ID 含不安全字符")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _restore_one(file_record: Mapping[str, Any], *, transaction_id: str) -> str:
    destination = Path(str(file_record["destination"]))
    before = file_record["before"]
    after_sha = str(file_record["after"]["sha256"])
    if before.get("exists", True) is False:
        if destination.is_symlink():
            raise HoshimemoPortraitTransactionError(
                f"事务后运行时组件变成符号链接，拒绝删除: {destination.name}"
            )
        if not destination.exists():
            return "already_removed"
        if not destination.is_file() or _sha256_file(destination) != after_sha:
            raise HoshimemoPortraitTransactionError(
                f"事务后运行时组件发生漂移，拒绝删除: {destination.name}"
            )
        destination.unlink()
        if destination.exists() or destination.is_symlink():
            raise HoshimemoPortraitTransactionError(
                f"运行时组件回滚删除失败: {destination.name}"
            )
        return "removed"
    backup = Path(str(file_record["backup"]))
    before_sha = str(before["sha256"])
    if not backup.is_file() or _sha256_file(backup) != before_sha:
        raise HoshimemoPortraitTransactionError(
            f"备份哈希不匹配，无法恢复: {destination.name}"
        )
    if not destination.is_file():
        raise HoshimemoPortraitTransactionError(
            f"事务目标已丢失，无法恢复: {destination.name}"
        )
    current_sha = _sha256_file(destination)
    if current_sha == before_sha:
        return "already_restored"
    if current_sha != after_sha:
        raise HoshimemoPortraitTransactionError(
            f"事务后文件发生漂移，拒绝覆盖: {destination.name}"
        )
    temporary = destination.with_name(
        f".{destination.name}.rollback-{transaction_id}-{uuid4().hex}.tmp"
    )
    try:
        shutil.copy2(backup, temporary)
        if _sha256_file(temporary) != before_sha:
            raise HoshimemoPortraitTransactionError(
                f"恢复临时文件校验失败: {destination.name}"
            )
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    if _sha256_file(destination) != before_sha:
        raise HoshimemoPortraitTransactionError(
            f"恢复后哈希校验失败: {destination.name}"
        )
    return "restored"


def install_portrait_transaction(
    plan: HoshimemoPortraitPatchPlan,
    target: PortraitTransactionTarget,
    outputs: ValidatedPortraitOutputs,
    *,
    transaction_id: str | None = None,
    commit_hook: Callable[[str, Path], None] | None = None,
) -> dict[str, Any]:
    """Install two validated candidates with journaled compensating rollback.

    ``commit_hook`` exists for deterministic failure-injection tests.  Product
    callers should leave it as ``None``.
    """

    dry_run = prepare_portrait_transaction(plan, target, outputs)
    tx_id = _validate_transaction_id(transaction_id)
    backup_root = target.root / PORTRAIT_TRANSACTION_BACKUP_DIR / tx_id
    if backup_root.exists():
        raise HoshimemoPortraitTransactionError(
            f"事务备份目录已存在: {backup_root}"
        )
    backup_root.mkdir(parents=True, exist_ok=False)
    manifest_path = backup_root / PORTRAIT_TRANSACTION_MANIFEST

    output_by_kind = {"hcb": outputs.hcb, "graph_bs": outputs.graph_bs}
    dry_by_kind = {item["kind"]: item for item in dry_run["files"]}
    records: dict[str, dict[str, Any]] = {}
    staged_paths: list[Path] = []
    try:
        for kind in ("hcb", "graph_bs"):
            source = Path(str(dry_by_kind[kind]["path"]))
            backup = backup_root / source.name
            staged = target.root / f".{source.name}.{tx_id}.candidate.tmp"
            if staged.exists():
                raise HoshimemoPortraitTransactionError(
                    f"候选临时文件已存在: {staged}"
                )
            shutil.copy2(source, backup)
            if _sha256_file(backup) != dry_by_kind[kind]["before"]["sha256"]:
                raise HoshimemoPortraitTransactionError(
                    f"备份校验失败: {source.name}"
                )
            _write_bytes_fsynced(staged, output_by_kind[kind])
            staged_paths.append(staged)
            if _sha256_file(staged) != dry_by_kind[kind]["after"]["sha256"]:
                raise HoshimemoPortraitTransactionError(
                    f"候选临时文件校验失败: {source.name}"
                )
            records[kind] = {
                "kind": kind,
                "destination": str(source),
                "backup": str(backup),
                "staged": str(staged),
                "before": dict(dry_by_kind[kind]["before"]),
                "after": dict(dry_by_kind[kind]["after"]),
            }

        manifest: dict[str, Any] = {
            "schema": PORTRAIT_TRANSACTION_SCHEMA,
            "transaction_id": tx_id,
            "status": "prepared",
            "created_at": _utc_now(),
            "target_root": str(target.root),
            "profile_id": plan.profile.profile_id,
            "plan_sha256": dry_run["plan_sha256"],
            "emitter": dry_run["emitter"],
            "commit_order": ["graph_bs", "hcb"],
            "committed_files": [],
            "files": [records["hcb"], records["graph_bs"]],
        }
        _write_manifest(manifest_path, manifest)

        for kind in ("graph_bs", "hcb"):
            record = records[kind]
            destination = Path(record["destination"])
            staged = Path(record["staged"])
            if commit_hook is not None:
                commit_hook(kind, destination)
            os.replace(staged, destination)
            if _sha256_file(destination) != record["after"]["sha256"]:
                raise HoshimemoPortraitTransactionError(
                    f"提交后哈希校验失败: {destination.name}"
                )
            manifest["status"] = "committing"
            manifest["committed_files"].append(kind)
            manifest["updated_at"] = _utc_now()
            _write_manifest(manifest_path, manifest)

        manifest["status"] = "committed"
        manifest["committed_at"] = _utc_now()
        manifest["updated_at"] = manifest["committed_at"]
        _write_manifest(manifest_path, manifest)
        return {
            **manifest,
            "manifest": str(manifest_path),
            "writes_performed": True,
        }
    except Exception as exc:
        rollback_errors: list[str] = []
        if manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                manifest = {
                    "schema": PORTRAIT_TRANSACTION_SCHEMA,
                    "transaction_id": tx_id,
                    "target_root": str(target.root),
                    "files": list(records.values()),
                    "committed_files": [],
                }
        else:
            manifest = {
                "schema": PORTRAIT_TRANSACTION_SCHEMA,
                "transaction_id": tx_id,
                "target_root": str(target.root),
                "files": list(records.values()),
                "committed_files": [],
            }

        for record in reversed(list(records.values())):
            try:
                _restore_one(record, transaction_id=tx_id)
            except Exception as rollback_exc:  # preserve every recovery error
                rollback_errors.append(str(rollback_exc))
        manifest["status"] = "rollback_failed" if rollback_errors else "rolled_back"
        manifest["failed_at"] = _utc_now()
        manifest["error"] = str(exc)
        manifest["rollback_errors"] = rollback_errors
        try:
            _write_manifest(manifest_path, manifest)
        except Exception as manifest_exc:
            rollback_errors.append(f"无法写入失败清单: {manifest_exc}")
        detail = f"立绘事务失败，已回滚: {exc}"
        if rollback_errors:
            detail = f"立绘事务失败且回滚不完整: {exc}; {'; '.join(rollback_errors)}"
        raise HoshimemoPortraitTransactionError(
            detail,
            manifest_path=manifest_path if manifest_path.exists() else None,
        ) from exc
    finally:
        for staged in staged_paths:
            staged.unlink(missing_ok=True)


def _load_manifest(manifest_path: Path) -> tuple[Path, dict[str, Any]]:
    manifest_path = Path(manifest_path).expanduser().resolve()
    if manifest_path.name != PORTRAIT_TRANSACTION_MANIFEST or not manifest_path.is_file():
        raise HoshimemoPortraitTransactionError(
            f"需要有效的 {PORTRAIT_TRANSACTION_MANIFEST}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HoshimemoPortraitTransactionError(
            f"无法读取事务清单: {exc}"
        ) from exc
    if manifest.get("schema") != PORTRAIT_TRANSACTION_SCHEMA:
        raise HoshimemoPortraitTransactionError("事务清单 schema 不受支持")
    target_root = Path(str(manifest.get("target_root", ""))).expanduser().resolve()
    tx_id = str(manifest.get("transaction_id", ""))
    if not _TX_ID_RE.fullmatch(tx_id):
        raise HoshimemoPortraitTransactionError("事务清单 ID 不安全")
    expected = (
        target_root
        / PORTRAIT_TRANSACTION_BACKUP_DIR
        / tx_id
        / PORTRAIT_TRANSACTION_MANIFEST
    ).resolve()
    if manifest_path != expected:
        raise HoshimemoPortraitTransactionError("事务清单路径与目标目录不匹配")
    return manifest_path, manifest


def inspect_portrait_transaction(manifest_path: Path) -> dict[str, Any]:
    """Read and hash-check an existing transaction without changing files."""

    manifest_path, manifest = _load_manifest(manifest_path)
    target_root = Path(str(manifest["target_root"])).resolve()
    backup_root = manifest_path.parent
    files: list[dict[str, Any]] = []
    for record in manifest.get("files", []):
        if not isinstance(record, dict):
            raise HoshimemoPortraitTransactionError("事务文件记录格式错误")
        destination = Path(str(record.get("destination", ""))).resolve()
        backup = Path(str(record.get("backup", ""))).resolve()
        if destination.parent != target_root or backup.parent != backup_root:
            raise HoshimemoPortraitTransactionError("事务文件路径越出目标或备份目录")
        before_sha = str(record.get("before", {}).get("sha256", ""))
        after_sha = str(record.get("after", {}).get("sha256", ""))
        _normalise_sha256(before_sha, "事务前哈希")
        _normalise_sha256(after_sha, "事务后哈希")
        if not backup.is_file() or _sha256_file(backup) != before_sha:
            raise HoshimemoPortraitTransactionError(
                f"事务备份缺失或漂移: {backup.name}"
            )
        if not destination.is_file():
            state = "missing"
            current_sha = None
        else:
            current_sha = _sha256_file(destination)
            if current_sha == after_sha:
                state = "installed"
            elif current_sha == before_sha:
                state = "restored"
            else:
                state = "drifted"
        files.append(
            {
                "kind": record.get("kind"),
                "destination": str(destination),
                "backup": str(backup),
                "state": state,
                "current_sha256": current_sha,
                "before_sha256": before_sha,
                "after_sha256": after_sha,
            }
        )
    if len(files) != 2 or {item["kind"] for item in files} != {"hcb", "graph_bs"}:
        raise HoshimemoPortraitTransactionError(
            "事务清单必须恰好记录 HCB 与 graph_bs 两个文件"
        )
    unsafe = {"missing", "drifted"}
    return {
        "schema": PORTRAIT_TRANSACTION_SCHEMA,
        "manifest": str(manifest_path),
        "transaction_id": manifest["transaction_id"],
        "status": manifest.get("status"),
        "target_root": str(target_root),
        "ready_to_rollback": not any(item["state"] in unsafe for item in files),
        "all_installed": all(item["state"] == "installed" for item in files),
        "all_restored": all(item["state"] == "restored" for item in files),
        "files": files,
    }


def rollback_portrait_transaction(manifest_path: Path) -> dict[str, Any]:
    """Restore both source files, refusing to overwrite post-install drift."""

    inspection = inspect_portrait_transaction(manifest_path)
    unsafe = next(
        (item for item in inspection["files"] if item["state"] in {"missing", "drifted"}),
        None,
    )
    if unsafe is not None:
        raise HoshimemoPortraitTransactionError(
            f"事务文件为 {unsafe['state']}，拒绝回滚: {unsafe['destination']}"
        )
    manifest_path, manifest = _load_manifest(Path(inspection["manifest"]))
    tx_id = str(manifest["transaction_id"])
    by_kind = {str(item["kind"]): item for item in manifest["files"]}
    restored: list[dict[str, str]] = []
    # Reverse of install: restore HCB first, then graph_bs.
    for kind in ("hcb", "graph_bs"):
        state = _restore_one(by_kind[kind], transaction_id=tx_id)
        restored.append({"kind": kind, "state": state})
    manifest["status"] = "rolled_back"
    manifest["rolled_back_at"] = _utc_now()
    manifest["rollback_files"] = restored
    _write_manifest(manifest_path, manifest)
    after = inspect_portrait_transaction(manifest_path)
    if not after["all_restored"]:
        raise HoshimemoPortraitTransactionError(
            "事务回滚结束但文件未全部恢复",
            manifest_path=manifest_path,
        )
    return {**after, "rollback_files": restored}


def _validate_scene_target(
    target: SceneTransactionTarget,
    *,
    required_archives: tuple[str, ...] = (),
) -> tuple[Path, dict[str, Path], list[str], str]:
    """Resolve the runtime-active HCB without guessing between overlays."""

    root = target.root
    if not root.is_dir():
        raise HoshimemoPortraitTransactionError(
            f"隔离测试副本目录不存在: {root}"
        )
    if root.is_symlink():
        raise HoshimemoPortraitTransactionError(
            f"隔离测试副本目录是符号链接，拒绝事务写入: {root}"
        )
    exact_active_root_authorization_used = False
    for protected in target.protected_roots:
        if _paths_overlap(root, protected):
            if target.active_source_root_authorized and root == protected:
                exact_active_root_authorization_used = True
                continue
            raise HoshimemoPortraitTransactionError(
                f"目标目录与只读来源或受保护目录重叠，拒绝写入: {protected}"
            )
    if (
        target.active_source_root_authorized
        and not exact_active_root_authorization_used
    ):
        raise HoshimemoPortraitTransactionError(
            "活动来源根目录授权没有绑定到一个完全相等的受保护目标根"
        )

    candidates = sorted(
        (
            item
            for item in root.iterdir()
            if item.is_file()
            and item.suffix.casefold() in _SCENE_SCRIPT_SUFFIXES
        ),
        key=lambda item: item.name.casefold(),
    )
    names = [item.name for item in candidates]
    if not candidates:
        raise HoshimemoPortraitTransactionError(
            f"隔离副本根目录没有 HCB/BCH 剧情脚本: {root}"
        )

    explicit_active = None
    if target.active_hcb_name is not None:
        matches = [
            item
            for item in candidates
            if item.name.casefold() == target.active_hcb_name.casefold()
        ]
        if len(matches) != 1:
            raise HoshimemoPortraitTransactionError(
                "目标副本缺少 profile 明确指定的活动剧情脚本: "
                f"{target.active_hcb_name}；候选为: {', '.join(names)}"
            )
        explicit_active = matches[0]
    hidden_hoshimemo = next(
        (item for item in candidates if item.name.casefold() == ".hoshimemo_hd.hcb"),
        None,
    )
    if explicit_active is not None:
        active = explicit_active
        resolution = (
            "profile_explicit_active_bch"
            if active.suffix.casefold() == ".bch"
            else "profile_explicit_active_hcb"
        )
    elif target.profile_id.casefold().startswith("hoshimemo-") and hidden_hoshimemo is not None:
        active = hidden_hoshimemo
        resolution = "hoshimemo_hidden_overlay"
    elif len(candidates) == 1:
        active = candidates[0]
        resolution = (
            "single_root_bch"
            if active.suffix.casefold() == ".bch"
            else "single_root_hcb"
        )
    else:
        raise HoshimemoPortraitTransactionError(
            "无法唯一判定游戏实际加载的活动 HCB/BCH；候选为: "
            f"{', '.join(names)}"
        )
    if active.is_symlink() or active.resolve().parent != root:
        raise HoshimemoPortraitTransactionError(
            f"活动剧情脚本不是目标根目录直属普通文件: {active}"
        )
    archive_paths: dict[str, Path] = {}
    for raw_name in required_archives:
        name = _safe_filename(raw_name, "剧情资源归档文件名").casefold()
        candidate = target.resource_archive_path(name)
        if candidate.is_symlink():
            raise HoshimemoPortraitTransactionError(
                f"{name} 是符号链接，拒绝事务写入: {candidate}"
            )
        resolved = candidate.resolve()
        if resolved.parent != root or not resolved.is_file():
            raise HoshimemoPortraitTransactionError(
                f"隔离副本缺少根目录直属 {name}: {candidate}"
            )
        if name in archive_paths:
            raise HoshimemoPortraitTransactionError(
                f"剧情资源归档重复: {name}"
            )
        archive_paths[name] = resolved
    return active.resolve(), archive_paths, names, resolution


def prepare_scene_transaction(
    target: SceneTransactionTarget,
    outputs: ValidatedSceneOutput,
) -> dict[str, Any]:
    """Perform the complete read-only unified-scene install preflight."""

    if outputs.profile_id != target.profile_id:
        raise HoshimemoPortraitTransactionError(
            "剧情候选 profile 与目标事务 profile 不一致"
        )
    archive_names = _scene_resource_names(outputs)
    runtime_names = _scene_runtime_companion_names(outputs)
    with_resources = bool(archive_names)
    with_runtime_companion = bool(runtime_names)
    hcb_path, archive_paths, candidate_names, resolution = _validate_scene_target(
        target,
        required_archives=archive_names,
    )
    before = hcb_path.read_bytes()
    before_sha256 = _sha256_bytes(before)
    if before_sha256 != outputs.source_sha256:
        raise HoshimemoPortraitTransactionError(
            "目标副本的活动 HCB 与候选源哈希不一致。"
            f"活动文件 {hcb_path.name} 为 {before_sha256}，候选要求 {outputs.source_sha256}；"
            "请先在工作台打开与目标活动 HCB 完全一致的只读来源，再重新选择挂接点。"
        )
    if outputs.hcb == before:
        raise HoshimemoPortraitTransactionError("剧情候选 HCB 没有任何变化")

    archive_before: dict[str, dict[str, Any]] = {}
    archive_after: dict[str, dict[str, Any]] = {}
    for name in archive_names:
        archive_path = archive_paths[name]
        before_fingerprint = _fingerprint_file_dict(archive_path)
        before_archive_sha256 = str(before_fingerprint["sha256"])
        expected_source_sha256 = outputs.resource_archive_source_sha256[name]
        if before_archive_sha256 != expected_source_sha256:
            raise HoshimemoPortraitTransactionError(
                f"目标副本 {name} 与候选源哈希不一致。"
                f"实际为 {before_archive_sha256}，候选要求 {expected_source_sha256}"
            )
        reported_source_size = outputs.resource_archive_source_size.get(name)
        if (
            reported_source_size is not None
            and reported_source_size != int(before_fingerprint["size"])
        ):
            raise HoshimemoPortraitTransactionError(
                f"目标副本 {name} 源大小与候选报告不一致。"
                f"实际为 {before_fingerprint['size']} bytes，候选报告为 {reported_source_size} bytes"
            )
        after_fingerprint = _scene_resource_after_fingerprint(outputs, name)
        reported_added = outputs.resource_archive_added_bytes.get(name)
        actual_added = int(after_fingerprint["size"]) - int(before_fingerprint["size"])
        if reported_added is not None and reported_added != actual_added:
            raise HoshimemoPortraitTransactionError(
                f"目标副本 {name} 增量字节与候选报告不一致。"
                f"实际为 {actual_added} bytes，候选报告为 {reported_added} bytes"
            )
        if after_fingerprint == before_fingerprint:
            raise HoshimemoPortraitTransactionError(
                f"剧情候选 {name} 没有任何变化"
            )
        archive_before[name] = before_fingerprint
        archive_after[name] = after_fingerprint

    runtime_paths: dict[str, Path] = {}
    for name in runtime_names:
        runtime_path = target.root / name
        if runtime_path.is_symlink() or runtime_path.exists():
            raise HoshimemoPortraitTransactionError(
                "目标目录已存在运行时文字伴随组件，拒绝覆盖或混用: "
                f"{runtime_path}"
            )
        resolved_parent = runtime_path.parent.resolve()
        if resolved_parent != target.root:
            raise HoshimemoPortraitTransactionError(
                f"运行时文字伴随组件路径越出目标根目录: {runtime_path}"
            )
        runtime_paths[name] = runtime_path

    files = [
        {
            "kind": "hcb",
            "path": str(hcb_path),
            "before": _fingerprint_dict(before),
            "after": _fingerprint_dict(outputs.hcb),
        }
    ]
    for name in archive_names:
        archive_path = archive_paths[name]
        files.append(
            {
                "kind": _scene_archive_kind(name),
                "archive_name": name,
                "path": str(archive_path),
                "before": dict(archive_before[name]),
                "after": dict(archive_after[name]),
            }
        )
    for name in runtime_names:
        files.append(
            {
                "kind": _scene_runtime_kind(name),
                "runtime_name": name,
                "path": str(runtime_paths[name]),
                "before": {"exists": False},
                "after": _fingerprint_dict(outputs.runtime_text_companion_files[name]),
            }
        )
    commit_order = (
        [_scene_runtime_kind(name) for name in runtime_names]
        + [_scene_archive_kind(name) for name in archive_names]
        + ["hcb"]
    )

    return {
        "schema": SCENE_TRANSACTION_SCHEMA,
        "mode": "dry-run",
        "writes_performed": False,
        "profile_id": outputs.profile_id,
        "plan_sha256": outputs.plan_sha256,
        "target_root": str(target.root),
        "active_hcb": str(hcb_path),
        "active_hcb_name": hcb_path.name,
        "active_hcb_resolution": resolution,
        "hcb_candidates": candidate_names,
        "emitter": {
            "id": outputs.emitter_id,
            "validation": dict(outputs.validation),
        },
        "commit_order": commit_order,
        "files": files,
        "safety": {
            "runtime_active_hcb_resolved": True,
            "protected_roots_checked": True,
            "active_source_root_authorized": (
                target.active_source_root_authorized
            ),
            "active_source_root_exact_match": (
                target.active_source_root_authorized
            ),
            "source_fingerprint_matches_active_hcb": True,
            "candidate_validation_passed": True,
            "hcb_only_transaction": not with_resources and not with_runtime_companion,
            "graph_bs_and_hcb_transaction": set(archive_names) == {"graph_bs.bin"},
            "resource_archive_count": len(archive_names),
            "resource_archives_and_hcb_transaction": with_resources,
            "resource_before_script_commit_order": with_resources,
            "runtime_text_companion_count": len(runtime_names),
            "runtime_text_companion_created": with_runtime_companion,
            "runtime_text_companion_before_script_commit_order": (
                with_runtime_companion
            ),
            "game_files_written": False,
        },
    }


def install_scene_transaction(
    target: SceneTransactionTarget,
    outputs: ValidatedSceneOutput,
    *,
    transaction_id: str | None = None,
    commit_hook: Callable[[str, Path], None] | None = None,
) -> dict[str, Any]:
    """Install one validated scene with journaled compensating rollback."""

    dry_run = prepare_scene_transaction(target, outputs)
    tx_id = _validate_transaction_id(transaction_id)
    backup_root = target.root / PORTRAIT_TRANSACTION_BACKUP_DIR / tx_id
    if backup_root.exists():
        raise HoshimemoPortraitTransactionError(
            f"事务备份目录已存在: {backup_root}"
        )
    backup_root.mkdir(parents=True, exist_ok=False)
    manifest_path = backup_root / SCENE_TRANSACTION_MANIFEST
    output_by_kind: dict[str, bytes] = {"hcb": outputs.hcb}
    for name, payload in outputs.resource_archives.items():
        output_by_kind[_scene_archive_kind(name)] = payload
    for name, payload in outputs.runtime_text_companion_files.items():
        output_by_kind[_scene_runtime_kind(name)] = payload
    output_file_by_kind: dict[str, Path] = {
        _scene_archive_kind(name): path
        for name, path in outputs.resource_archive_files.items()
    }
    dry_by_kind = {str(item["kind"]): item for item in dry_run["files"]}
    commit_order = [str(item) for item in dry_run["commit_order"]]
    records: dict[str, dict[str, Any]] = {}
    staged_paths: list[Path] = []
    try:
        for kind in dry_by_kind:
            source = Path(str(dry_by_kind[kind]["path"]))
            before = dict(dry_by_kind[kind]["before"])
            before_exists = before.get("exists", True) is not False
            backup = backup_root / source.name if before_exists else None
            staged = target.root / f".{source.name}.{tx_id}.scene-candidate.tmp"
            if staged.exists():
                raise HoshimemoPortraitTransactionError(
                    f"候选临时文件已存在: {staged}"
                )
            if backup is not None:
                shutil.copy2(source, backup)
            after = dict(dry_by_kind[kind]["after"])
            if backup is not None and _sha256_file(backup) != before["sha256"]:
                raise HoshimemoPortraitTransactionError(
                    f"剧情事务备份校验失败: {source.name}"
                )
            file_candidate = output_file_by_kind.get(kind)
            if file_candidate is not None:
                _copy_file_fsynced(file_candidate, staged)
            else:
                _write_bytes_fsynced(staged, output_by_kind[kind])
            staged_paths.append(staged)
            if _sha256_file(staged) != after["sha256"]:
                raise HoshimemoPortraitTransactionError(
                    f"剧情候选临时文件校验失败: {source.name}"
                )
            records[kind] = {
                "kind": kind,
                "destination": str(source),
                "backup": str(backup) if backup is not None else None,
                "staged": str(staged),
                "before": before,
                "after": after,
            }
            if "archive_name" in dry_by_kind[kind]:
                records[kind]["archive_name"] = dry_by_kind[kind]["archive_name"]
            if "runtime_name" in dry_by_kind[kind]:
                records[kind]["runtime_name"] = dry_by_kind[kind]["runtime_name"]

        manifest: dict[str, Any] = {
            "schema": SCENE_TRANSACTION_SCHEMA,
            "transaction_id": tx_id,
            "status": "prepared",
            "created_at": _utc_now(),
            "target_root": str(target.root),
            "profile_id": outputs.profile_id,
            "plan_sha256": outputs.plan_sha256,
            "active_hcb_name": dry_run["active_hcb_name"],
            "active_hcb_resolution": dry_run["active_hcb_resolution"],
            "hcb_candidates": dry_run["hcb_candidates"],
            "emitter": dry_run["emitter"],
            "safety": dict(dry_run["safety"]),
            "commit_order": commit_order,
            "committed_files": [],
            "files": [records[str(item["kind"])] for item in dry_run["files"]],
        }
        _write_manifest(manifest_path, manifest)

        for kind in commit_order:
            record = records[kind]
            destination = Path(str(record["destination"]))
            staged = Path(str(record["staged"]))
            if commit_hook is not None:
                commit_hook(kind, destination)
            if record["before"].get("exists", True) is False:
                if destination.is_symlink() or destination.exists():
                    raise HoshimemoPortraitTransactionError(
                        "剧情事务提交前目标新增了同名运行时组件，拒绝覆盖: "
                        f"{destination.name}"
                    )
            elif _sha256_file(destination) != record["before"]["sha256"]:
                raise HoshimemoPortraitTransactionError(
                    f"剧情事务提交前目标发生外部变化，拒绝覆盖: {destination.name}"
                )
            os.replace(staged, destination)
            if _sha256_file(destination) != record["after"]["sha256"]:
                raise HoshimemoPortraitTransactionError(
                    f"剧情事务提交后哈希校验失败: {destination.name}"
                )
            manifest["status"] = "committing"
            manifest["committed_files"].append(kind)
            manifest["updated_at"] = _utc_now()
            _write_manifest(manifest_path, manifest)

        manifest["status"] = "committed"
        manifest["safety"]["game_files_written"] = True
        manifest["committed_at"] = _utc_now()
        manifest["updated_at"] = manifest["committed_at"]
        _write_manifest(manifest_path, manifest)
        return {
            **manifest,
            "manifest": str(manifest_path),
            "writes_performed": True,
        }
    except Exception as exc:
        rollback_errors: list[str] = []
        manifest = {
            "schema": SCENE_TRANSACTION_SCHEMA,
            "transaction_id": tx_id,
            "target_root": str(target.root),
            "profile_id": outputs.profile_id,
            "plan_sha256": outputs.plan_sha256,
            "files": list(records.values()),
            "committed_files": [],
            "commit_order": commit_order,
        }
        if manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        for kind in reversed(commit_order):
            record = records.get(kind)
            if record is None:
                continue
            try:
                _restore_one(record, transaction_id=tx_id)
            except Exception as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        manifest["status"] = "rollback_failed" if rollback_errors else "rolled_back"
        manifest["failed_at"] = _utc_now()
        manifest["error"] = str(exc)
        manifest["rollback_errors"] = rollback_errors
        try:
            _write_manifest(manifest_path, manifest)
        except Exception as manifest_exc:
            rollback_errors.append(f"无法写入失败清单: {manifest_exc}")
        detail = f"剧情事务失败，已回滚: {exc}"
        if rollback_errors:
            detail = f"剧情事务失败且回滚不完整: {exc}; {'; '.join(rollback_errors)}"
        raise HoshimemoPortraitTransactionError(
            detail,
            manifest_path=manifest_path if manifest_path.exists() else None,
        ) from exc
    finally:
        for staged in staged_paths:
            staged.unlink(missing_ok=True)


def _load_scene_manifest(manifest_path: Path) -> tuple[Path, dict[str, Any]]:
    manifest_path = Path(manifest_path).expanduser().resolve()
    if manifest_path.name != SCENE_TRANSACTION_MANIFEST or not manifest_path.is_file():
        raise HoshimemoPortraitTransactionError(
            f"需要有效的 {SCENE_TRANSACTION_MANIFEST}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HoshimemoPortraitTransactionError(
            f"无法读取剧情事务清单: {exc}"
        ) from exc
    if manifest.get("schema") != SCENE_TRANSACTION_SCHEMA:
        raise HoshimemoPortraitTransactionError("剧情事务清单 schema 不受支持")
    target_root = Path(str(manifest.get("target_root", ""))).expanduser().resolve()
    tx_id = str(manifest.get("transaction_id", ""))
    if not _TX_ID_RE.fullmatch(tx_id):
        raise HoshimemoPortraitTransactionError("剧情事务清单 ID 不安全")
    expected = (
        target_root
        / PORTRAIT_TRANSACTION_BACKUP_DIR
        / tx_id
        / SCENE_TRANSACTION_MANIFEST
    ).resolve()
    if manifest_path != expected:
        raise HoshimemoPortraitTransactionError(
            "剧情事务清单路径与目标目录不匹配"
        )
    return manifest_path, manifest


def inspect_scene_transaction(manifest_path: Path) -> dict[str, Any]:
    """Read and hash-check one installed scene transaction."""

    manifest_path, manifest = _load_scene_manifest(manifest_path)
    target_root = Path(str(manifest["target_root"])).resolve()
    backup_root = manifest_path.parent
    records = manifest.get("files")
    if not isinstance(records, list) or not records:
        raise HoshimemoPortraitTransactionError("剧情事务清单没有文件记录")
    files: list[dict[str, Any]] = []
    kinds: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise HoshimemoPortraitTransactionError("剧情事务文件记录格式错误")
        kind = str(record.get("kind") or "").strip().casefold()
        archive_name = _scene_kind_archive_name(kind)
        runtime_name = _scene_kind_runtime_name(kind)
        if (
            (kind != "hcb" and archive_name is None and runtime_name is None)
            or kind in kinds
        ):
            raise HoshimemoPortraitTransactionError(
                f"剧情事务文件类型无效或重复: {kind or '<缺失>'}"
            )
        kinds.add(kind)
        destination = Path(str(record.get("destination", ""))).resolve()
        before = record.get("before")
        if not isinstance(before, Mapping):
            raise HoshimemoPortraitTransactionError("剧情事务前状态记录格式错误")
        before_exists = before.get("exists", True) is not False
        raw_backup = record.get("backup")
        backup = (
            Path(str(raw_backup)).resolve()
            if before_exists and raw_backup not in (None, "")
            else None
        )
        if destination.parent != target_root or (
            backup is not None and backup.parent != backup_root
        ):
            raise HoshimemoPortraitTransactionError(
                "剧情事务文件路径越出目标或备份目录"
            )
        if backup is not None and backup.name != destination.name:
            raise HoshimemoPortraitTransactionError(
                "剧情事务备份文件名与目标文件不一致"
            )
        if archive_name is not None:
            recorded_archive = str(record.get("archive_name") or archive_name).casefold()
            if recorded_archive != archive_name or destination.name.casefold() != archive_name:
                raise HoshimemoPortraitTransactionError(
                    f"剧情事务资源归档名称与文件类型不一致: {kind}"
                )
        if runtime_name is not None:
            recorded_runtime = str(record.get("runtime_name") or runtime_name)
            if (
                recorded_runtime.casefold() != runtime_name.casefold()
                or destination.name.casefold() != runtime_name.casefold()
                or before_exists
                or raw_backup not in (None, "")
            ):
                raise HoshimemoPortraitTransactionError(
                    f"剧情事务运行时组件记录不一致: {kind}"
                )
        elif not before_exists:
            raise HoshimemoPortraitTransactionError(
                f"只有运行时文字伴随组件允许安装前不存在: {kind}"
            )
        before_sha = (
            _normalise_sha256(
                str(before.get("sha256", "")),
                "剧情事务前哈希",
            )
            if before_exists
            else None
        )
        after_sha = _normalise_sha256(
            str(record.get("after", {}).get("sha256", "")),
            "剧情事务后哈希",
        )
        if before_exists and (
            backup is None
            or not backup.is_file()
            or _sha256_file(backup) != before_sha
        ):
            raise HoshimemoPortraitTransactionError(
                f"剧情事务备份缺失或漂移: {destination.name}"
            )
        if destination.is_symlink():
            state = "drifted"
            current_sha = None
        elif not destination.is_file():
            state = "restored" if not before_exists else "missing"
            current_sha = None
        else:
            current_sha = _sha256_file(destination)
            if current_sha == after_sha:
                state = "installed"
            elif before_exists and current_sha == before_sha:
                state = "restored"
            else:
                state = "drifted"
        files.append(
            {
                "kind": kind,
                "destination": str(destination),
                "backup": str(backup) if backup is not None else None,
                "state": state,
                "current_sha256": current_sha,
                "before_sha256": before_sha,
                "before_exists": before_exists,
                "after_sha256": after_sha,
            }
        )
    if "hcb" not in kinds:
        raise HoshimemoPortraitTransactionError(
            "剧情事务必须记录活动 HCB"
        )
    commit_order = [str(item).strip().casefold() for item in manifest.get("commit_order", [])]
    runtime_kinds = [
        _scene_runtime_kind(name)
        for name in _RUNTIME_TEXT_COMPANION_NAMES
        if _scene_runtime_kind(name) in kinds
    ]
    archive_kinds = sorted(
        kind for kind in kinds - {"hcb"} if _scene_kind_archive_name(kind) is not None
    )
    expected_order = runtime_kinds + archive_kinds + ["hcb"]
    if commit_order != expected_order:
        raise HoshimemoPortraitTransactionError(
            "剧情事务提交顺序必须是运行时组件、资源归档在前，HCB 在后"
        )
    unsafe = {"missing", "drifted"}
    return {
        "schema": SCENE_TRANSACTION_SCHEMA,
        "manifest": str(manifest_path),
        "transaction_id": manifest["transaction_id"],
        "status": manifest.get("status"),
        "target_root": str(target_root),
        "active_hcb_name": manifest.get("active_hcb_name"),
        "ready_to_rollback": not any(item["state"] in unsafe for item in files),
        "all_installed": all(item["state"] == "installed" for item in files),
        "all_restored": all(item["state"] == "restored" for item in files),
        "files": files,
    }


def rollback_scene_transaction(manifest_path: Path) -> dict[str, Any]:
    """Restore scene files without overwriting external post-install drift."""

    inspection = inspect_scene_transaction(manifest_path)
    unsafe = next(
        (
            item
            for item in inspection["files"]
            if item["state"] in {"missing", "drifted"}
        ),
        None,
    )
    if unsafe is not None:
        raise HoshimemoPortraitTransactionError(
            f"剧情事务文件为 {unsafe['state']}，拒绝回滚: "
            f"{unsafe['destination']}"
        )
    manifest_path, manifest = _load_scene_manifest(Path(inspection["manifest"]))
    tx_id = str(manifest["transaction_id"])
    by_kind = {str(item["kind"]): item for item in manifest["files"]}
    commit_order = [str(item) for item in manifest.get("commit_order", ["hcb"])]
    restored: list[dict[str, str]] = []
    for kind in reversed(commit_order):
        if kind not in by_kind:
            raise HoshimemoPortraitTransactionError(
                f"剧情事务回滚顺序引用了缺失文件: {kind}"
            )
        state = _restore_one(by_kind[kind], transaction_id=tx_id)
        restored.append({"kind": kind, "state": state})
    manifest["status"] = "rolled_back"
    manifest["rolled_back_at"] = _utc_now()
    manifest["rollback_files"] = restored
    _write_manifest(manifest_path, manifest)
    after = inspect_scene_transaction(manifest_path)
    if not after["all_restored"]:
        raise HoshimemoPortraitTransactionError(
            "剧情事务回滚结束但文件未全部恢复",
            manifest_path=manifest_path,
        )
    return {**after, "rollback_files": restored}
