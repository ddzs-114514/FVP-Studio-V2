"""Explicit per-export native entry selection, never paths or registry writes.

Discovery still proves the selected script/executable/ABI. Choosing a basename
does not prove compatibility, enable an unsupported feature, or launch it.
"""
from dataclasses import replace
from pathlib import Path

from .gui_runtime import GuiRuntimeError


SCHEMA = "fvp-gui-export-entry/1"
FILE_OPTIONS = {"target_script": {".hcb", ".bch"}, "target_executable": {".exe"}}
ENCODINGS = ("shift_jis", "cp932", "gbk", "utf-8")
OPTION_FIELDS = (*FILE_OPTIONS, "target_encoding")


def validate_entry_name(value, key):
    if (key not in FILE_OPTIONS or type(value) is not str or not 1 <= len(value) <= 128
            or value in {".", ".."} or any(ord(c) < 32 for c in value)
            or any(c in value for c in '/\\:<>"|?*') or Path(value).name != value
            or Path(value).suffix.casefold() not in FILE_OPTIONS[key]
            or value[-1:] in {".", " "}):
        raise GuiRuntimeError("invalid_target_selection", "游戏入口只能选择已登记游戏目录里的剧情文件或启动程序，不能输入路径。")
    return value


def validate_options(options):
    if type(options) is not dict or set(options) - set(OPTION_FIELDS):
        raise GuiRuntimeError("invalid_target_selection", "输出入口选项不正确。")
    result = {}
    for key, value in options.items():
        if key in FILE_OPTIONS:
            result[key] = validate_entry_name(value, key)
        elif type(value) is not str or value not in ENCODINGS:
            raise GuiRuntimeError("invalid_target_encoding", "文字编码只接受明确选择的 Shift-JIS、CP932、GBK 或 UTF-8。")
        else:
            result[key] = value
    return result


def select_source(source, options):
    options = validate_options(options)
    if not options:
        return source
    if source.id == "hoshi":
        raise GuiRuntimeError("invalid_target_selection", "星空沿用现有独立测试入口，不接受其他游戏的入口覆盖。")
    changed = dict(options)
    for key in FILE_OPTIONS.keys() & options.keys():
        path = Path(source.root) / options[key]
        if path.is_symlink() or not path.is_file():
            raise GuiRuntimeError("target_entry_unavailable", "选中的游戏入口不存在或不是普通文件，请重新选择。", 409)
    if "target_encoding" in changed:
        from .hcb import normalize_encoding
        changed["target_encoding"] = normalize_encoding(changed["target_encoding"])
    return replace(source, **changed)


def entry_choices(source, options):
    """Names only; never read binary contents or guess the correct entry."""
    choices = {key: [] for key in FILE_OPTIONS}
    for path in Path(source.root).iterdir():
        if not path.is_file() or path.is_symlink():
            continue
        for key, suffixes in FILE_OPTIONS.items():
            if path.suffix.casefold() in suffixes:
                try:
                    validate_entry_name(path.name, key)
                except GuiRuntimeError:
                    continue
                choices[key].append(path.name)
                if len(choices[key]) > 64:
                    raise GuiRuntimeError("too_many_target_entries", "这个目录里的游戏入口过多，请先在本机登记中明确入口。", 422)
    return dict(schema=SCHEMA, files={key: sorted(names, key=str.casefold) for key, names in choices.items()},
        registered={key: getattr(source, key, None) for key in OPTION_FIELDS},
        requested=dict(options), session_only=True, persists_in_project=False,
        original_game_read_only=True)
