"""Read-only evidence bridge for translated Hoshimemo Overlay HCB files.

The Chinese launcher reads ``.Hoshimemo_HD.hcb``.  That file preserves the
original code addresses, but many original ``push_string`` instructions have
already been replaced by five-byte jumps into appended translation stubs.  A
generic linear decoder therefore (correctly) reports lost instruction
boundaries and must never be used to rebuild the file.

Hoshimemo distributions keep the clean Japanese ``Hoshimemo_HD.hcb`` beside
the translated file.  This module accepts that companion only as read-only
control-flow/ABI evidence after checking the complete header contract and the
project index compatibility gate.  Callers still patch and hash the hidden
file itself; the clean companion is never an output target.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from .hcb import HcbDocument, HcbError, load


HOSHIMEMO_HIDDEN_HCB = ".Hoshimemo_HD.hcb"
HOSHIMEMO_CLEAN_HCB = "Hoshimemo_HD.hcb"


class HoshimemoOverlayError(HcbError):
    """Raised when a hidden Overlay cannot be tied to clean HCB evidence."""


def _compatibility(profile: Any, document: HcbDocument) -> dict[str, Any]:
    checker = getattr(profile, "compatibility_for", None)
    if callable(checker):
        value = checker(document)
        if isinstance(value, Mapping):
            return dict(value)
    warning_count = len(document.warnings)
    return {
        "safe": warning_count == 0,
        "reason": (
            "HCB 可完整线性解析"
            if warning_count == 0
            else f"HCB 解析产生 {warning_count:,} 个未知/失步警告"
        ),
        "warning_count": warning_count,
        "source_sha256": document.source_sha256,
    }


@lru_cache(maxsize=8)
def _load_clean_cached(
    path_text: str,
    size: int,
    mtime_ns: int,
) -> HcbDocument:
    # ``size`` and ``mtime_ns`` deliberately participate in the cache key.
    # The arguments are otherwise unused because ``load`` resolves the path.
    del size, mtime_ns
    return load(Path(path_text), "sjis")


def _clean_companion(path: Path) -> HcbDocument:
    clean_path = path.with_name(HOSHIMEMO_CLEAN_HCB)
    if not clean_path.is_file():
        raise HoshimemoOverlayError(
            f"中文隐藏 HCB 缺少同目录只读原版证据: {clean_path}"
        )
    stat = clean_path.stat()
    return _load_clean_cached(str(clean_path.resolve()), stat.st_size, stat.st_mtime_ns)


def _header_signature(document: HcbDocument) -> tuple[Any, ...]:
    header = document.header
    syscall_signature = tuple(
        (int(item.args), bytes(item.raw_name)) for item in header.syscalls
    )
    return (
        int(header.sysdesc_offset),
        int(header.entry_point),
        int(header.non_volatile_globals),
        int(header.volatile_globals),
        int(header.game_mode),
        int(header.game_mode_reserved),
        int(header.custom_syscall_count),
        bytes(header.title_raw),
        syscall_signature,
    )


def resolve_hoshimemo_analysis_document(
    document: HcbDocument,
    profile: Any,
    *,
    expected_clean_sha256: str | None = None,
) -> tuple[HcbDocument, dict[str, Any]]:
    """Return trusted instruction evidence without changing the active source.

    A normally parseable HCB is returned unchanged.  An unsafe document is
    accepted only when it is the exact Hoshimemo hidden filename and a clean,
    profile-compatible sibling proves the same VM header/address contract.
    """

    direct = _compatibility(profile, document)
    if direct.get("safe", False):
        report = dict(direct)
        report.update(
            {
                "mode": "linear",
                "source_sha256": document.source_sha256,
                "analysis_source_sha256": document.source_sha256,
                "analysis_path": str(document.path) if document.path is not None else None,
            }
        )
        return document, report

    # A generic FVP target may provide the active translated Overlay and its
    # clean linear analysis HCB entirely in memory.  The profile-owned bridge
    # must verify both identities/header contracts itself; this module only
    # accepts an explicit safe result and never discovers a companion path by
    # game name.  Hoshimemo keeps its older, filename-bound fallback below.
    memory_resolver = getattr(profile, "analysis_document_for", None)
    if callable(memory_resolver):
        resolved = memory_resolver(document)
        if (
            not isinstance(resolved, tuple)
            or len(resolved) != 2
            or not isinstance(resolved[0], HcbDocument)
            or not isinstance(resolved[1], Mapping)
        ):
            raise HoshimemoOverlayError(
                "目标 profile 的内存分析 HCB bridge 返回值无效"
            )
        analysis_document, memory_report = resolved
        report = dict(memory_report)
        if not report.get("safe"):
            raise HoshimemoOverlayError(
                "目标 profile 的内存分析 HCB bridge 未通过安全门禁"
            )
        if analysis_document.warnings:
            raise HoshimemoOverlayError(
                "目标 profile 提供的内存分析 HCB 含解析警告"
            )
        report.setdefault("source_sha256", document.source_sha256)
        report.setdefault(
            "analysis_source_sha256", analysis_document.source_sha256
        )
        report.setdefault("analysis_path", None)
        return analysis_document, report

    path = document.path
    if path is None or path.name.casefold() != HOSHIMEMO_HIDDEN_HCB.casefold():
        raise HoshimemoOverlayError(
            "当前 HCB 与剧情索引边界不一致："
            f"{direct.get('reason') or '兼容性检查未通过'}"
        )
    if document.encoding != "gb18030":
        raise HoshimemoOverlayError(
            "中文隐藏 HCB 必须用 GBK / GB18030 打开，不能按 Shift-JIS 构建新增台词"
        )

    clean = _clean_companion(path)
    clean_compatibility = _compatibility(profile, clean)
    if not clean_compatibility.get("safe", False):
        raise HoshimemoOverlayError(
            "同目录原版 HCB 不能作为剧情控制流证据："
            f"{clean_compatibility.get('reason') or '兼容性检查未通过'}"
        )
    expected_hash = str(expected_clean_sha256 or "").strip().casefold()
    if expected_hash and clean.source_sha256.casefold() != expected_hash:
        raise HoshimemoOverlayError(
            "同目录原版 HCB 指纹不是当前 Hoshimemo 场景 ABI 基线："
            f"需要 {expected_hash}，实际 {clean.source_sha256}"
        )
    if _header_signature(document) != _header_signature(clean):
        raise HoshimemoOverlayError(
            "中文隐藏 HCB 与同目录原版的入口、全局变量或 syscall 头部不一致"
        )
    if len(document.original_bytes) < len(clean.original_bytes):
        raise HoshimemoOverlayError("中文隐藏 HCB 比原版更短，不能证明 Overlay 只做定长覆盖/尾部追加")

    return clean, {
        "safe": True,
        "reason": (
            "中文隐藏 Overlay 已绑定同目录原版控制流；候选只允许精确五字节覆盖和 EOF 追加"
        ),
        "mode": "hoshimemo_hidden_overlay",
        "warning_count": len(document.warnings),
        "parsed_string_count": int(getattr(document, "string_count", 0) or 0),
        "source_sha256": document.source_sha256,
        "analysis_source_sha256": clean.source_sha256,
        "analysis_path": str(clean.path) if clean.path is not None else None,
        "index_fingerprint": str(getattr(profile, "index_fingerprint", "") or ""),
    }
