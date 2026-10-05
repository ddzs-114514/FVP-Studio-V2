"""Prepare/check explicit private bindings; never create a game copy."""
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import ast
import hashlib
import json
from pathlib import Path
from .engine_pattern_manifest import APPROVED
from .engine_patterns import SCHEMA, validate_patterns
from .local_binding import load_binding, safe_local, validate_binding, SCHEMA as HOSHI_SCHEMA

def collect_patterns(source_dir):
    """Accept only exactly the already-audited self-written reader signatures.

    This does not copy the external adapter/HCB parser or import user scripts.
    AST literals are read, never evaluated as executable Python.
    """
    root = safe_local(source_dir)
    found = {}
    for module in sorted({key.split(":")[0] for key in APPROVED}):
        path = safe_local(root / (module + ".py"), file=True)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, bytes):
                continue
            key = f"{module}:{node.lineno}:{node.col_offset}"
            if key in APPROVED:
                if hashlib.sha256(node.value).hexdigest() != APPROVED[key]:
                    raise ValueError("输入签名与既有审核算法不一致，拒绝导入")
                found[key] = node.value.hex()
    if set(found) != set(APPROVED):
        raise ValueError("本机输入缺少审核过的识别签名；不生成不完整替代规则")
    result = {"schema": SCHEMA, "patterns": found}
    validate_patterns(result)
    return result

def collect_hoshi_config(private_reader, source_root):
    """Read only audited offset metadata, then validate actual local files."""
    path = safe_local(private_reader, file=True)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assignments = {ast.unparse(n.targets[0]): n.value for n in tree.body if isinstance(n, ast.Assign)}
    try:
        entry = assignments["(ENTRY, ENTRY_BYTES, CONTINUE)"]
        resume = assignments["(RESUME_START, RESUME_VISIBLE)"]
        values = [ast.literal_eval(entry.elts[0]), ast.literal_eval(entry.elts[2]),
                  ast.literal_eval(resume.elts[0]), ast.literal_eval(resume.elts[1])]
    except (KeyError, AttributeError, TypeError, ValueError, IndexError) as exc:
        raise ValueError("私有读取器没有明确审核的接入元数据；拒绝执行脚本或猜测") from exc
    config = dict(schema=HOSHI_SCHEMA, source_root=str(safe_local(source_root)),
                  entry_offset=values[0], continue_offset=values[1], resume_start=values[2], resume_visible=values[3])
    validate_binding(config)
    return config

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--patterns-from", type=Path, help="用户明确指定的私有已审核读取器目录")
    group.add_argument("--hoshi-from", type=Path, help="明确指定的私有已审核 performance_compile.py")
    group.add_argument("--check-hoshi-binding", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-root", type=Path)
    args = parser.parse_args()
    if args.check_hoshi_binding:
        if args.output or args.source_root:
            parser.error("绑定检查只读，不接受输出路径")
        load_binding(args.check_hoshi_binding)
        print("PASS: explicit Hoshimemo binding, fingerprints and instruction boundaries")
        return
    if args.output is None or not args.output.name.endswith(".local.json"):
        parser.error("签名只写入明确的 *.local.json 私人配置")
    if args.hoshi_from and args.source_root is None:
        parser.error("本机接入绑定需要明确 --source-root")
    if args.patterns_from and args.source_root is not None:
        parser.error("引擎签名准备不接受游戏来源路径")
    config = (collect_hoshi_config(args.hoshi_from, args.source_root) if args.hoshi_from
              else collect_patterns(args.patterns_from))
    output = args.output.absolute()
    source = safe_local(args.source_root if args.hoshi_from else args.patterns_from)
    if output.exists() or output.is_symlink() or source in output.resolve().parents:
        parser.error("只允许来源目录之外的新私人配置；拒绝覆盖")
    output.parent.mkdir(parents=True, exist_ok=True)
    safe_local(output.parent)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(config, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print("Prepared validated private configuration; not an upload artifact.")

if __name__ == "__main__":
    main()
