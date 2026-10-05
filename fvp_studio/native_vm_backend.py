"""Target-bound FVP VM backend, without game-name branches or game writes.

The first layer deliberately separates bytecode/arity validation from semantic
scene support. It can emit and reparse an unreachable, in-memory function using
the exact target's syscall table and native function entries. It cannot install
a scene, choose primitive ownership, or declare runtime acceptance.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import struct
from typing import Any, Mapping, Sequence

from .hcb import HcbError, normalize_encoding, parse_bytes
from .native_call_flow import NativeFunctionFlow
from .native_target_discovery import NativeTargetDiscoveryError, discover_fvp_target
from .native_target_profile import build_native_target_profile_template


BACKEND_SCHEMA = "fvp-native-vm-backend/1"
FRAGMENT_SCHEMA = "fvp-native-memory-fragment/1"
_SCRIPT_SUFFIXES = {".hcb", ".bch"}


class NativeVmBackendError(HcbError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: Any) -> str:
    return _sha(json.dumps(value, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode("utf-8"))


def _encoding(name: str) -> str:
    if not isinstance(name, str):
        raise NativeVmBackendError("文本编码必须明确指定为字符串")
    try:
        return normalize_encoding(name)
    except HcbError as exc:
        raise NativeVmBackendError(str(exc)) from exc


@dataclass(frozen=True)
class NativeMemoryFragment:
    code: bytes
    report: Mapping[str, Any]


class NativeVmBackend:
    """An immutable-byte target context; no file installation API is provided."""

    def __init__(self, source: bytes, encoding: str, *, encoding_confirmed: bool = True):
        if type(source) is not bytes or not source:
            raise NativeVmBackendError("后端需要非空、不可变的 HCB bytes")
        if type(encoding_confirmed) is not bool:
            raise NativeVmBackendError("encoding_confirmed 必须是布尔值")
        self._source = source
        self._encoding = _encoding(encoding)
        self._encoding_confirmed = encoding_confirmed
        self._document = parse_bytes(source, self.encoding)
        self._source_sha256 = _sha(source)
        self._flow = NativeFunctionFlow(self._document)
        self._syscalls: dict[str, list[tuple[int, int]]] = {}
        for index, syscall in enumerate(self._document.header.syscalls):
            self._syscalls.setdefault(syscall.name, []).append((index, syscall.args))
        self._syscall_table = tuple((index, syscall.name, syscall.args)
                                   for index, syscall in enumerate(self._document.header.syscalls))
        self._binding_sha256 = _digest({
            "source_sha256": self.source_sha256, "encoding": self.encoding,
            "encoding_confirmed": encoding_confirmed, "syscall_table": self.syscall_table,
            "function_entries": sorted(self._flow.entries),
        })

    @property
    def encoding(self) -> str:
        return self._encoding

    @property
    def encoding_confirmed(self) -> bool:
        return self._encoding_confirmed

    @property
    def source_sha256(self) -> str:
        return self._source_sha256

    @property
    def binding_sha256(self) -> str:
        return self._binding_sha256

    @property
    def syscall_table(self) -> tuple[tuple[int, str, int], ...]:
        return self._syscall_table

    def describe(self) -> dict[str, Any]:
        return {
            "schema": BACKEND_SCHEMA, "mode": "memory_only", "writes_performed": False,
            "source_sha256": self.source_sha256, "binding_sha256": self.binding_sha256,
            "encoding": self.encoding, "encoding_confirmed": self.encoding_confirmed,
            "game_mode": self._document.header.game_mode,
            "parse_warning_count": len(self._document.warnings),
            "function_entry_count": len(self._flow.entries),
            "syscalls": [{"id": i, "name": n, "argument_count": a,
                          "status": "unique_header_binding" if len(self._syscalls[n]) == 1
                                    else "ambiguous_duplicate_name",
                          "parameter_semantics_reviewed": False}
                         for i, n, a in self.syscall_table],
            "capabilities": {
                "vm_literal_call_emission": "available_memory_only" if not self._document.warnings else "blocked",
                "non_ascii_text_emission": self.encoding_confirmed and not self._document.warnings,
                "high_level_scene_compiler": False, "original_writeback": False,
            },
            "write_gate": {"enabled": False, "blockers": [
                "generic_scene_semantics_not_reviewed", "actual_runtime_not_verified",
                "resource_and_primitive_ownership_not_reviewed", "lifecycle_acceptance_not_completed",
            ]},
        }

    def trace_function(self, address: int) -> dict[str, Any]:
        return self._flow.trace(address)

    def _literal(self, value: Any) -> bytes:
        if value is None:
            return b"\x08"
        if value is True:
            return b"\x09"
        if value is False:
            value = 0
        if type(value) is int:
            for low, high, opcode, fmt in (
                (-128, 127, b"\x0c", "<b"), (-32768, 32767, b"\x0b", "<h"),
                (-2147483648, 2147483647, b"\x0a", "<i"),
            ):
                if low <= value <= high:
                    return opcode + struct.pack(fmt, value)
            raise NativeVmBackendError("整数超出 HCB i32 范围")
        if type(value) is float:
            if not math.isfinite(value):
                raise NativeVmBackendError("HCB 数值不能包含 NaN/Infinity")
            try:
                payload = struct.pack("<f", value)
            except (OverflowError, struct.error) as exc:
                raise NativeVmBackendError("浮点数超出 HCB f32 范围") from exc
            if not math.isfinite(struct.unpack("<f", payload)[0]):
                raise NativeVmBackendError("浮点数超出 HCB f32 范围")
            return b"\x0d" + payload
        if type(value) is str:
            if "\0" in value:
                raise NativeVmBackendError("HCB 字符串不能含内嵌 NUL")
            if not self.encoding_confirmed and not value.isascii():
                raise NativeVmBackendError("未确认文本编码；拒绝发射非 ASCII 文本")
            try:
                payload = value.encode(self.encoding) + b"\0"
            except UnicodeEncodeError as exc:
                raise NativeVmBackendError("文本不能无损编码到目标 HCB") from exc
            if len(payload) > 255:
                raise NativeVmBackendError("HCB 字符串超过 255 字节长度字段")
            return b"\x0e" + bytes((len(payload),)) + payload
        raise NativeVmBackendError("HCB 入参只接受 Nil、布尔、整数、浮点和字符串")

    def compile_fragment(
        self, operations: Sequence[Mapping[str, Any]], *, source_sha256: str,
        binding_sha256: str,
    ) -> NativeMemoryFragment:
        """Emit only target-exact literal calls; never attach them to the story.

        Requiring both fingerprints prevents UI state from one game or encoding
        being reused against another. Header arity does not certify call meaning.
        """
        if source_sha256 != self.source_sha256 or binding_sha256 != self.binding_sha256:
            raise NativeVmBackendError("目标 HCB/编码绑定已变更，拒绝跨目标复用")
        if self._document.warnings:
            raise NativeVmBackendError("目标 HCB 含解析警告，拒绝生成内存候选")
        if not isinstance(operations, (list, tuple)) or not 1 <= len(operations) <= 256:
            raise NativeVmBackendError("内存片段需要 1～256 个调用")
        code = bytearray(b"\x01\x00\x00")
        emitted = []
        for operation in operations:
            if not isinstance(operation, Mapping):
                raise NativeVmBackendError("内存调用必须是对象")
            kind = operation.get("kind")
            arguments = operation.get("arguments")
            if not isinstance(arguments, (list, tuple)):
                raise NativeVmBackendError("调用参数必须是数组，不能推断或自动补齐")
            if kind == "syscall":
                if set(operation) != {"kind", "name", "arguments"}:
                    raise NativeVmBackendError("系统调用含未定义字段")
                name = operation["name"]
                if not isinstance(name, str):
                    raise NativeVmBackendError("系统调用名必须是字符串")
                matches = self._syscalls.get(name, [])
                if len(matches) != 1:
                    raise NativeVmBackendError("系统调用名未唯一绑定到目标 HCB: " + name)
                syscall_id, argc = matches[0]
                instruction = b"\x03" + struct.pack("<H", syscall_id)
                identity = {"kind": kind, "name": name, "syscall_id": syscall_id}
            elif kind == "function":
                if set(operation) != {"kind", "address", "arguments"}:
                    raise NativeVmBackendError("函数调用含未定义字段")
                address = operation["address"]
                if type(address) is not int or address not in self._flow.entries:
                    raise NativeVmBackendError("调用地址不是当前 HCB 的精确函数入口")
                entry = self._document.instructions[self._flow.entries[address][0]]
                argc = int(entry.operands["args"])
                instruction = b"\x02" + struct.pack("<I", address)
                identity = {"kind": kind, "address": address}
            else:
                raise NativeVmBackendError("仅支持已绑定的 syscall/function 字面量调用")
            if len(arguments) != argc:
                raise NativeVmBackendError(f"目标调用需要 {argc} 个参数，收到 {len(arguments)} 个；不补参")
            wire_arguments = []
            for value in arguments:
                code.extend(self._literal(value))
                wire_value = (0 if value is False else struct.unpack("<f", struct.pack("<f", value))[0]
                              if type(value) is float else value)
                wire_arguments.append({"kind": "literal", "type": type(wire_value).__name__,
                                       "value": wire_value})
            code.extend(instruction)
            emitted.append({**identity, "argument_count": argc, "wire_arguments": wire_arguments})
        code.extend(b"\x04")
        fragment = bytes(code)
        start = self._document.header.sysdesc_offset
        original_header = self._source[start:]
        # Append before sysdesc. Existing instructions and their absolute
        # targets are not relocated; the original entry remains unchanged.
        probe = (struct.pack("<I", start + len(fragment)) + self._source[4:start]
                 + fragment + original_header)
        reparsed = parse_bytes(probe, self.encoding)
        flow = NativeFunctionFlow(reparsed).trace(start)
        if reparsed.warnings or flow["status"] != "proven_static_argument_flow":
            raise NativeVmBackendError("内存片段未通过字节码/参数栈复核")
        actual = flow["calls"]
        if len(actual) != len(emitted) or any(
            a["argument_count"] != e["argument_count"]
            or a["arguments"] != e["wire_arguments"]
            or (a.get("syscall_id") != e.get("syscall_id") if e["kind"] == "syscall"
                else a.get("address") != e.get("address"))
            for a, e in zip(actual, emitted)
        ):
            raise NativeVmBackendError("内存调用回读与发射计划不一致")
        unchanged = (probe[4:start] == self._source[4:start]
                     and probe[start + len(fragment):] == original_header
                     and reparsed.header.entry_point == self._document.header.entry_point)
        if not unchanged:
            raise NativeVmBackendError("内存候选改变了原有入口/代码/头部")
        return NativeMemoryFragment(fragment, {
            "schema": FRAGMENT_SCHEMA, "mode": "unreachable_memory_fragment",
            "source_sha256": self.source_sha256, "binding_sha256": self.binding_sha256,
            "fragment_sha256": _sha(fragment), "fragment_size": len(fragment),
            "in_memory_function_address": start, "encoding": self.encoding,
            "calls": emitted, "validation": {
                "bytecode_reparse": "passed", "stack_and_call_arity": "passed",
                "literal_roundtrip": "passed",
                "original_entry_and_code_unchanged": True,
            },
            "writes_performed": False, "install_ready": False,
            "runtime_acceptance": "not_run", "semantics_reviewed": False,
            "write_gate": {"enabled": False, "blockers": [
                "low_level_fragment_is_not_a_complete_scene", "actual_runtime_not_verified",
                "resource_and_primitive_ownership_not_reviewed", "lifecycle_acceptance_not_completed",
            ]},
        })


def _root_filename(name: str, suffixes: set[str]) -> str:
    if (not isinstance(name, str) or not name or ":" in name or "/" in name or "\\" in name
            or Path(name).name != name or Path(name).suffix.casefold() not in suffixes):
        raise NativeVmBackendError("只能指定游戏根目录直属的脚本/EXE 文件名")
    return name.casefold()


def _binary_script_evidence(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 64 * 1024 * 1024:
        return {"name": path.name, "status": "binary_probe_size_limit", "references": []}
    payload = path.read_bytes()
    references = []
    for suffix in (".hcb", ".bch"):
        for codec in ("ascii", "utf-16le"):
            token = suffix.encode(codec) + (b"\0" if codec == "ascii" else b"\0\0")
            offset = payload.lower().find(token)
            if offset >= 0:
                references.append({"suffix": suffix, "encoding": codec, "offset": offset})
    return {"name": path.name, "sha256": _sha(payload), "references": references,
            "status": "string_evidence_only", "runtime_verified": False}


def inspect_native_backend(
    game_dir: str | Path, *, analysis_script_name: str | None = None,
    analysis_encoding: str | None = None, executable_name: str | None = None,
    max_function_flows: int = 24,
) -> dict[str, Any]:
    """Conservative, UI-usable inventory with explicit ambiguity and no writes."""
    raw_root = Path(game_dir).expanduser()
    if raw_root.is_symlink():
        raise NativeVmBackendError("拒绝分析符号链接游戏根目录")
    root = raw_root.resolve()
    if not root.is_dir():
        raise NativeVmBackendError("FVP 游戏目录不存在")
    if type(max_function_flows) is not int or not 0 <= max_function_flows <= 64:
        raise NativeVmBackendError("单次参数流核对范围必须是 0～64")
    files = {x.name.casefold(): x for x in root.iterdir() if x.is_file() and not x.is_symlink()}
    scripts = sorted((x for x in files.values() if x.suffix.casefold() in _SCRIPT_SUFFIXES), key=lambda x: x.name.casefold())
    binaries = sorted((x for x in files.values() if x.suffix.casefold() == ".exe"), key=lambda x: x.name.casefold())
    evidence = [_binary_script_evidence(x) for x in binaries]
    selected_exe = None
    if executable_name is not None:
        selected_exe = files.get(_root_filename(executable_name, {".exe"}))
        if selected_exe is None:
            raise NativeVmBackendError("游戏根目录缺少明确指定的 EXE")
    explicit = None
    selection_kind = "conservative_layout"
    if analysis_script_name is not None:
        explicit = files.get(_root_filename(analysis_script_name, _SCRIPT_SUFFIXES))
        if explicit is None:
            raise NativeVmBackendError("游戏根目录缺少明确指定的脚本")
        selection_kind = "explicit_analysis_script"
    if explicit is None and selected_exe is not None:
        record = next(x for x in evidence if x["name"] == selected_exe.name)
        suffixes = {x["suffix"] for x in record["references"]}
        matched = [x for x in scripts if x.suffix.casefold() in suffixes and not x.name.startswith(".")]
        if len(suffixes) == 1 and len(matched) == 1:
            explicit = matched[0]
            selection_kind = "explicit_exe_unique_extension_candidate"
    if explicit is not None and selected_exe is not None:
        record = next(x for x in evidence if x["name"] == selected_exe.name)
        suffixes = {x["suffix"] for x in record["references"]}
        if suffixes and explicit.suffix.casefold() not in suffixes:
            raise NativeVmBackendError("指定 EXE 的脚本扩展名证据与分析脚本冲突")
    requested_encoding = _encoding(analysis_encoding) if analysis_encoding is not None else "shift_jis"
    base = {
        "schema": BACKEND_SCHEMA, "game_dir": str(root), "mode": "read_only_discovery",
        "writes_performed": False, "script_candidates": [x.name for x in scripts],
        "executable_candidates": evidence,
        "encoding": {"name": requested_encoding, "status": "explicit_analysis_configuration"
                     if analysis_encoding is not None else "unconfirmed_structure_only_default"},
        "activation": {"executable": selected_exe.name if selected_exe else None,
                       "selection_basis": selection_kind, "runtime_verified": False},
    }
    # More than one visible analysis script is a choice, even if one of them
    # also happens to have an overlay. Never choose the first matching pair.
    visible = [x for x in scripts if not x.name.startswith(".")]
    if explicit is None and len(visible) != 1 and len(scripts) != 1:
        return {**base, "status": "selection_required", "capabilities": {},
                "write_gate": {"enabled": False, "blockers": ["analysis_script_ambiguous"]}}
    try:
        discovery = discover_fvp_target(root, active_script_name=explicit.name if explicit else None,
                                        analysis_encoding=requested_encoding)
    except NativeTargetDiscoveryError as exc:
        return {**base, "status": "blocked", "capabilities": {},
                "write_gate": {"enabled": False, "blockers": [str(exc)]}}
    name = discovery["hcb"]["analysis_source"]
    source = (root / name).read_bytes()
    backend = NativeVmBackend(source, requested_encoding, encoding_confirmed=analysis_encoding is not None)
    expected = next(x["sha256"] for x in discovery["hcb"]["candidates"] if x["analysis_source"])
    if backend.source_sha256 != expected:
        raise NativeVmBackendError("分析过程中目标脚本已变化，请重新扫描")
    profile = build_native_target_profile_template(discovery)
    flows = {}
    addresses = set()
    for role, binding in profile["scene_bindings"].items():
        if not isinstance(binding, Mapping) or type(binding.get("address")) is not int:
            continue
        address = binding["address"]
        if address not in addresses and len(addresses) >= max_function_flows:
            continue
        if max_function_flows == 0:
            continue
        addresses.add(address)
        flows[role] = backend.trace_function(address)
    described = backend.describe()
    from .native_background_backend import NativeBackgroundBackend, NativeBackgroundBackendError

    route_role = profile.get("archive_routing", {}).get("background", {})
    archive_selectors = {
        route["archive"]: (route.get("selector_value") if route.get("selector_kind") == "integer" else None)
        for route in route_role.get("routes", ())
        if route.get("selector_kind") in {"integer", "default_fallthrough"}
    }
    try:
        native_background = NativeBackgroundBackend(
            backend._document, backend._document, archive_selectors=archive_selectors,
        )
        background_report = {"status": "bound_analysis_memory_only", **native_background.describe()}
    except NativeBackgroundBackendError as exc:
        background_report = {"status": "unavailable", "reason": str(exc)}
    capabilities = {**described["capabilities"],
                    "native_background_memory_emission": background_report["status"] == "bound_analysis_memory_only"}
    return {**base, "status": "inspected", "target_id": discovery["target_id"],
            "analysis_script": name, "engine_family_id": discovery["engine"]["family_id"],
            "vm": described, "capabilities": capabilities,
            "native_background_backend": background_report,
            "function_flows": flows, "discovery": discovery, "profile_template": profile,
            "write_gate": {"enabled": False, "blockers": sorted(set(
                discovery["write_gate"]["blockers"] + described["write_gate"]["blockers"]))}}
