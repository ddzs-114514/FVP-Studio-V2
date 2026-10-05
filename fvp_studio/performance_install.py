"""Hash-bound performance installation to a brand-new Hoshimemo test copy."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import ctypes
import os
import json
from pathlib import Path
import shutil
import stat
import subprocess
import secrets

from .performance_compile import SOURCE_SHA, EXE_SHA, PROFILE, EMITTER, sha, validate_program
from .performance_workflow import digest
from .hoshimemo_portrait_transaction import (SceneTransactionTarget, ValidatedSceneOutput,
    install_scene_transaction, _sha256_file)

def _safe(path, *, file=False, independent=True):
    """Reject links/reparse points before normalizing an explicit local path."""
    raw = Path(path)
    if not raw.is_absolute() or str(raw).startswith(("\\\\", "//")) or "\x00" in str(raw):
        raise ValueError("须使用本机绝对路径，不接受相对路径或网络共享")
    raw = Path(os.path.abspath(raw))
    for part in [*reversed(raw.parents), raw]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"路径包含符号链接或目录联接: {part}")
    if not raw.exists():
        raise ValueError(f"路径不存在: {raw}")
    if file:
        info = raw.stat()
        if not stat.S_ISREG(info.st_mode) or (independent and info.st_nlink != 1):
            raise ValueError(f"不是独立普通文件: {raw}")
    return raw.resolve(strict=True)


def _fingerprint(path, *, independent):
    path = _safe(path, file=True, independent=independent)
    before = path.stat()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    digest = _sha256_file(path)
    after = path.stat()
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError(f"读取时文件发生变化: {path}")
    return {"sha256": digest, "size": before.st_size}

TEST_PARENT = Path(os.environ.get("FVP_STUDIO_TEST_ROOT", "").strip()
                   or Path.home() / "FVPStudio" / "test-copies").expanduser().absolute()


def checked_new_target(source, target, parent=None):
    """Pure new-copy gate; never creates a directory or touches a game."""
    source = _safe(source)
    parent = _safe(parent or TEST_PARENT)
    raw = Path(target)
    if not raw.is_absolute() or raw.is_symlink() or ".." in raw.parts:
        raise ValueError("新副本须为明确本机绝对路径，不能含链接或父目录跳转")
    _safe(raw.parent)
    target = raw.resolve()
    if target.parent != parent or target.exists() or target.is_symlink() or not target.name:
        raise ValueError("只能创建指定测试根下全新的独立目录；不覆盖任何旧副本")
    if source == target or source in target.parents or target in source.parents:
        raise ValueError("新副本与来源目录重叠")
    return target


def _robocopy_executable() -> str:
    """Use the Windows system copy tool even if ComfyUI changed its PATH."""
    if os.name != "nt":
        raise ValueError("独立副本复制只支持具备 robocopy 的 Windows 主机")
    system_dir = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(system_dir, len(system_dir))
    if not 0 < length < len(system_dir):
        raise ValueError("无法确定 Windows 系统目录，拒绝复制独立副本")
    executable = Path(system_dir.value) / "robocopy.exe"
    if not executable.is_file():
        raise ValueError(f"Windows 系统目录缺少 robocopy.exe: {executable}")
    return str(executable)


def new_test_target(plan_sha256: str) -> Path:
    """Choose, but never create, a collision-resistant child of the test root."""
    if not isinstance(plan_sha256, str) or len(plan_sha256) != 64 or not all(
        char in "0123456789abcdef" for char in plan_sha256.lower()
    ):
        raise ValueError("候选计划摘要无效，不能生成测试副本名称")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return TEST_PARENT / f"Hoshimemo_HD_Run_{stamp}_{plan_sha256[:12]}_{secrets.token_hex(4)}"


def load_candidate(folder):
    folder = _safe(Path(folder).absolute())
    for name in ("report.json", "program.json", "candidate.hcb"):
        _safe(folder / name, file=True)
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    program = json.loads((folder / "program.json").read_text(encoding="utf-8"))
    validate_program(program)
    if report.get("dry_run_passed") is not True or report.get("install_ready") is not True:
        raise ValueError("候选尚未通过完整静态自检与安装安全门；拒绝写入")
    if report.get("plan_sha256") != digest(program) or report.get("profile_id") != PROFILE or report.get("emitter_id") != EMITTER:
        raise ValueError("候选/程序身份不匹配")
    identity = json.dumps({"report": report, "program": program}, ensure_ascii=False,
                          sort_keys=True, separators=(",", ":")).encode()
    expected_folder = report["plan_sha256"][:20] + "-" + sha(identity)[:12]
    if folder.name != expected_folder or report.get("schema") != "fvp-studio.performance-candidate.v1":
        raise ValueError("候选目录身份或报告格式不匹配；请重新构建")
    source_archives = report.get("source", {}).get("resource_archives", {})
    output_archives = report.get("output", {}).get("resource_archives", {})
    if (not isinstance(source_archives, dict) or not isinstance(output_archives, dict)
            or set(source_archives) != set(output_archives)
            or not {"graph.bin", "graph_bs.bin"} <= set(source_archives)):
        raise ValueError("候选资源归档集合不完整或前后不一致")
    allowed = {"graph.bin", "graph_bs.bin", "graph_vis.bin", "graph_vis1.bin", "graph_vis2.bin"}
    if set(output_archives) - allowed:
        raise ValueError("候选包含未审核的资源归档名称")
    changed = {}
    for name, entry in output_archives.items():
        path = folder / name
        if path.is_symlink() or not path.is_file() or _sha256_file(path) != entry.get("sha256"):
            raise ValueError(f"候选 {name} 丢失或哈希与报告不一致")
        if entry.get("sha256") != source_archives[name].get("sha256"):
            changed[name] = path
    output = ValidatedSceneOutput(hcb=(folder / "candidate.hcb").read_bytes(), source_sha256=SOURCE_SHA,
        plan_sha256=digest(program), emitter_id=EMITTER, profile_id=PROFILE, validation=report,
        resource_archive_files=changed,
        resource_archive_source_sha256={n: source_archives[n]["sha256"] for n in changed})
    return output, program


def inventory(root, independent):
    paths = sorted(p for p in root.rglob("*") if p.is_file())
    def entry(p):
        _safe(p)
        return str(p.relative_to(root)), _fingerprint(p, independent=independent)
    with ThreadPoolExecutor(max_workers=3) as pool:
        return dict(pool.map(entry, paths))


def preflight(folder, target):
    robocopy_executable = _robocopy_executable()
    try:
        import psutil  # noqa: F401 - ensure process gate exists before copying
    except ImportError as exc:
        raise ValueError("缺少进程检查依赖 psutil，拒绝准备写入") from exc
    outputs, program = load_candidate(folder)
    source = _safe(Path(program["source_root"]))
    target = checked_new_target(source, target)
    from .local_binding import require_binding
    require_binding(root=source)
    protected = tuple(p for p in TEST_PARENT.iterdir() if p.is_dir())
    if (Path(folder) / "installation.json").exists():
        raise ValueError("该候选已有安装记录；先查看或回滚原事务")
    protected_hashes = {str(p / ".Hoshimemo_HD.hcb"): _sha256_file(_safe(p / ".Hoshimemo_HD.hcb", file=True, independent=False))
                        for p in protected if (p / ".Hoshimemo_HD.hcb").exists()}
    def protect():
        if _sha256_file(source / ".Hoshimemo_HD.hcb") != SOURCE_SHA or _sha256_file(source / "Hoshimemo_HD.exe") != EXE_SHA:
            raise ValueError("原作母本身份漂移")
        for name, record in outputs.validation["source"]["resource_archives"].items():
            if _sha256_file(_safe(source / name, file=True, independent=False)) != record["sha256"]:
                raise ValueError(f"原作母本资源归档漂移: {name}")
        for p, expected in protected_hashes.items():
            if _sha256_file(Path(p)) != expected:
                raise ValueError("已接受/旧副本发生变化")
    protect()
    required = sum(p.stat().st_size for p in source.rglob("*") if p.is_file()) + 4 * 1024**3
    if shutil.disk_usage(TEST_PARENT).free < required:
        raise ValueError("独立副本和可回滚安装空间不足")
    return dict(outputs=outputs, program=program, source=source, target=target,
                protected_roots=protected,
                protect=protect, protected_hashes=protected_hashes, required_bytes=required,
                robocopy_executable=robocopy_executable)


def install(folder, target):
    checked = preflight(folder, target)
    outputs, source, target = checked["outputs"], checked["source"], checked["target"]
    protect = checked["protect"]
    # Reserve the exact new directory atomically. If another task created it
    # after preflight, fail before robocopy can merge into an existing game.
    target.mkdir(exist_ok=False)
    _safe(target)
    print(json.dumps({"stage": "copy-new-independent-game", "target": str(target)}, ensure_ascii=False), flush=True)
    result = subprocess.run([checked["robocopy_executable"], str(source), str(target), "/E", "/COPY:DAT", "/DCOPY:DAT", "/XJ",
        "/R:1", "/W:1", "/NFL", "/NDL", "/NP", "/NJH", "/NJS"], capture_output=True)
    if result.returncode >= 8:
        raise RuntimeError(f"独立复制失败({result.returncode})；保留不完整目录供检查")
    _safe(target)
    print(json.dumps({"stage": "hash-full-copy"}), flush=True)
    before = inventory(source, False)
    copied = inventory(target, True)
    if copied != before:
        raise ValueError("独立副本完整性不符；没有安装补丁")
    protect()
    if _sha256_file(target / ".Hoshimemo_HD.hcb") != SOURCE_SHA or _sha256_file(target / "Hoshimemo_HD.exe") != EXE_SHA:
        raise ValueError("安装前目标身份漂移")
    import psutil
    for process in psutil.process_iter(["exe"]):
        try:
            exe = process.info.get("exe")
            if exe and target in Path(exe).resolve().parents:
                raise ValueError("新副本游戏已在运行；请先关闭该副本再安装")
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as exc:
            raise ValueError("无法确认目标游戏进程是否关闭，拒绝写入") from exc
    print(json.dumps({"stage": "journaled-install"}), flush=True)
    transaction = install_scene_transaction(SceneTransactionTarget(target, PROFILE,
        protected_roots=(source, *checked["protected_roots"]), active_hcb_name=".Hoshimemo_HD.hcb"), outputs)
    protect()
    record = {"schema": "fvp-performance-install.v1", "target_root": str(target), "source_root": str(source),
        "candidate_directory": str(folder), "runtime_verified": False,
        "copy_file_count": len(copied), "copy_bytes": sum(v["size"] for v in copied.values()),
        "copy_all_sha256_equal": True, "copy_all_files_single_link": True,
        "protected_hashes": checked["protected_hashes"], "transaction": transaction}
    with (Path(folder) / "installation.json").open("x", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"stage": "installed-not-launched", "target": str(target),
        "receipt": str(Path(folder) / "installation.json"), "runtime_verified": False}, ensure_ascii=False), flush=True)
    return record
