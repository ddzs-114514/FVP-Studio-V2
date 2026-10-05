"""Explicit, hash-gated local Hoshimemo connection binding.

No game instruction bytes or connection offsets are distributed. The user
supplies their independently verified local offsets; expected bytes are read
from the read-only, supported source and retained only in process memory.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from .hcb import parse_bytes

SCHEMA = "fvp-hoshi-local-binding/1"
# Digests are version identity guards, not game content. Never auto-trust a
# modified game by replacing these guards with whatever was just read.
SUPPORTED = {
    ".Hoshimemo_HD.hcb": "224ecf63f635d3229de0022ce880932fd034f20cb7985960ee68a9a38d7edc5c",
    "Hoshimemo_HD.hcb": "e23b7958f897392e3535370956b7c9a722c562f0a6d65e91d589cfdd2b741802",
    "Hoshimemo_HD.exe": "d195c8916ba32089347b79e0ee24c505a6cd2cd230c6f3b1d97584c9fa9f8b0c",
}
ENTRY_DIGEST = "acf975fc8d18bf59b8d3fcf456b31a26d4c62a2ef64effda27766f6dcb7d1a24"
LAYOUT_DIGEST = "de445112e6bf437225dc253f58d0cada2a84168a816b66b1b0265fcd04e9bac4"
FIELDS = ("entry_offset", "continue_offset", "resume_start", "resume_visible")

def stat_identity(info):
    """Content/identity metadata, excluding access time changed by our reads."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            getattr(info, "st_file_attributes", 0))

def safe_local(path, *, file=False):
    raw = Path(path).expanduser()
    if not raw.is_absolute() or str(raw).startswith(("\\\\", "//")) or "\0" in str(raw):
        raise ValueError("本机绑定须使用明确的本地绝对路径")
    for part in (*reversed(raw.parents), raw):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("本机绑定拒绝链接或目录联接")
    resolved = raw.resolve(strict=True)
    if file and (not resolved.is_file() or resolved.stat().st_nlink != 1):
        raise ValueError("绑定文件须为独立普通文件")
    return resolved

def _read_stable(path):
    path = safe_local(path, file=True)
    before = path.stat()
    if before.st_size > 32 * 1024 * 1024:
        raise ValueError("绑定文件超出已审核的大小边界")
    data = path.read_bytes()
    if stat_identity(before) != stat_identity(path.stat()):
        raise ValueError("读取本机绑定时文件发生变化")
    return data

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("绑定配置含重复字段")
        result[key] = value
    return result

@dataclass(frozen=True)
class LocalBinding:
    source_root: Path
    entry_offset: int
    continue_offset: int
    resume_start: int
    resume_visible: int
    entry_bytes: bytes
    config_path: Path | None = None
    config_digest: str | None = None

    def verify(self, *, root=None, source=None, clean=None):
        if self.config_path is not None and hashlib.sha256(_read_stable(self.config_path)).hexdigest() != self.config_digest:
            raise ValueError("本机绑定配置已变化；须重新启动这个独立服务")
        if root is not None and safe_local(root) != self.source_root:
            raise ValueError("输出来源与明确绑定的只读母本不一致")
        if source is not None and hashlib.sha256(source).hexdigest() != SUPPORTED[".Hoshimemo_HD.hcb"]:
            raise ValueError("绑定的原始脚本身份漂移")
        if clean is not None and hashlib.sha256(clean).hexdigest() != SUPPORTED["Hoshimemo_HD.hcb"]:
            raise ValueError("绑定的分析脚本身份漂移")
        for name, expected in SUPPORTED.items():
            if hashlib.sha256(_read_stable(self.source_root / name)).hexdigest() != expected:
                raise ValueError("绑定的脚本或启动程序身份漂移")

def validate_binding(config):
    if not isinstance(config, dict) or set(config) != {"schema", "source_root", *FIELDS} or config["schema"] != SCHEMA:
        raise ValueError("本机绑定格式或字段不正确")
    if not isinstance(config["source_root"], str) or not config["source_root"]:
        raise ValueError("空配置不是可用绑定；请明确登记本机母本")
    if any(type(config[k]) is not int or not 4 <= config[k] <= 0xFFFFFFFF for k in FIELDS):
        raise ValueError("接入/恢复位置须为独立核对的整数偏移")
    root = safe_local(config["source_root"])
    if not root.is_dir():
        raise ValueError("绑定来源不是目录")
    data = {name: _read_stable(root / name) for name in SUPPORTED}
    if any(hashlib.sha256(data[name]).hexdigest() != expected for name, expected in SUPPORTED.items()):
        raise ValueError("来源不是已审核的原始脚本/程序配对，拒绝绑定")
    entry, continuation, start, visible = (config[k] for k in FIELDS)
    layout = json.dumps([entry, continuation, start, visible], separators=(",", ":")).encode()
    if hashlib.sha256(layout).hexdigest() != LAYOUT_DIGEST:
        raise ValueError("接入/恢复布局不属于已审核版本；拒绝换用相似位置")
    if not start <= entry < visible < continuation < len(data[".Hoshimemo_HD.hcb"]):
        raise ValueError("接入与原剧情恢复区间不闭合")
    document = parse_bytes(data["Hoshimemo_HD.hcb"], encoding="shift_jis")
    by_offset = {i.offset: i for i in document.instructions}
    if any(offset not in by_offset for offset in (entry, entry + 5, continuation, start, visible)):
        raise ValueError("接入/恢复位置不在已解析的原生指令边界")
    spans = [i for i in document.instructions if entry <= i.offset < entry + 5]
    expected = data[".Hoshimemo_HD.hcb"][entry:entry + 5]
    if (document.warnings or not spans or any(not i.known for i in spans)
            or b"".join(i.raw for i in spans) != expected
            or hashlib.sha256(expected).hexdigest() != ENTRY_DIGEST):
        raise ValueError("本机接入指纹或原生指令不匹配，拒绝猜测")
    return LocalBinding(root, entry, continuation, start, visible, expected)

def load_binding(path):
    path = safe_local(path, file=True)
    raw = _read_stable(path)
    if len(raw) > 64 * 1024:
        raise ValueError("本机绑定配置过大")
    config = json.loads(raw, object_pairs_hook=unique_object,
                        parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("绑定不接受非有限值")))
    binding = validate_binding(config)
    return LocalBinding(**{**binding.__dict__, "config_path": path,
                           "config_digest": hashlib.sha256(raw).hexdigest()})

configured = os.environ.get("FVP_STUDIO_HOSHI_BINDING", "").strip()
BINDING = load_binding(configured) if configured else None

def require_binding(*, root=None, source=None, clean=None):
    if BINDING is None:
        raise ValueError("星空输出需要明确的本机接入绑定；未配置时不允许编译或安装")
    BINDING.verify(root=root, source=source, clean=clean)
    return BINDING
