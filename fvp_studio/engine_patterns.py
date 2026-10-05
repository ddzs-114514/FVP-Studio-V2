"""Hash-gated local recognition signatures, never a distributed EXE dump."""
# SPDX-License-Identifier: GPL-3.0-or-later
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
from .engine_pattern_manifest import APPROVED
from .local_binding import safe_local, unique_object, stat_identity

SCHEMA = "fvp-engine-patterns/1"

def validate_patterns(config):
    if not isinstance(config, dict) or set(config) != {"schema", "patterns"} or config["schema"] != SCHEMA:
        raise ValueError("本机引擎签名配置格式不正确")
    rows = config["patterns"]
    if not isinstance(rows, dict) or set(rows) - APPROVED.keys():
        raise ValueError("本机引擎签名含未审核项")
    result = {}
    for key, encoded in rows.items():
        if not isinstance(encoded, str) or not encoded or len(encoded) > 8192:
            raise ValueError("本机引擎签名值不合法")
        data = bytes.fromhex(encoded)
        if hashlib.sha256(data).hexdigest() != APPROVED[key]:
            raise ValueError("本机引擎签名与原有审核算法不一致；拒绝放宽识别")
        result[key] = data
    return result

@lru_cache(maxsize=2)
def _read(path, identity):
    raw = Path(path).read_bytes()
    if len(raw) > 128 * 1024:
        raise ValueError("本机引擎签名配置过大")
    if stat_identity(Path(path).stat()) != identity:
        raise ValueError("读取时本机引擎签名发生变化")
    return validate_patterns(json.loads(raw, object_pairs_hook=unique_object))

def engine_pattern(key):
    configured = os.environ.get("FVP_STUDIO_ENGINE_PATTERNS", "").strip()
    if not configured:
        raise ValueError("未配置本机引擎识别签名；尺寸/原生输出拒绝猜测。请设置 FVP_STUDIO_ENGINE_PATTERNS。")
    path = safe_local(configured, file=True)
    rows = _read(str(path), stat_identity(path.stat()))
    if key not in rows:
        raise ValueError("本机配置缺少此引擎识别签名；拒绝使用其他目标的规则")
    return rows[key]
