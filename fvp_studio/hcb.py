"""A loss-aware HCB reader and reassembler for FVP Studio.

This is the first editor core.  It follows the opcode layouts used by RFVP,
but does not import the RFVP crate or assume a particular game's function
addresses.  Unknown opcodes are retained as raw one-byte instructions and are
reported as warnings instead of being silently discarded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import copy
import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Iterable


ENCODINGS = {
    "sjis": "shift_jis",
    "shift_jis": "shift_jis",
    "cp932": "cp932",
    "gbk": "gb18030",
    "gb18030": "gb18030",
    "utf8": "utf-8",
    "utf-8": "utf-8",
}


OPCODE_NAMES = {
    0x00: "nop",
    0x01: "init_stack",
    0x02: "call",
    0x03: "syscall",
    0x04: "ret",
    0x05: "retv",
    0x06: "jmp",
    0x07: "jz",
    0x08: "push_nil",
    0x09: "push_true",
    0x0A: "push_i32",
    0x0B: "push_i16",
    0x0C: "push_i8",
    0x0D: "push_f32",
    0x0E: "push_string",
    0x0F: "push_global",
    0x10: "push_stack",
    0x11: "push_global_table",
    0x12: "push_local_table",
    0x13: "push_top",
    0x14: "push_return",
    0x15: "pop_global",
    0x16: "pop_stack",
    0x17: "pop_global_table",
    0x18: "pop_local_table",
    0x19: "neg",
    0x1A: "add",
    0x1B: "sub",
    0x1C: "mul",
    0x1D: "div",
    0x1E: "mod",
    0x1F: "bit_test",
    0x20: "and",
    0x21: "or",
    0x22: "set_e",
    0x23: "set_ne",
    0x24: "set_g",
    0x25: "set_ge",
    0x26: "set_l",
    0x27: "set_le",
}

_OPERAND_FORMATS = {
    0x01: "init",
    0x02: "u32_target",
    0x03: "u16_syscall",
    0x06: "u32_target",
    0x07: "u32_target",
    0x0A: "i32",
    0x0B: "i16",
    0x0C: "i8",
    0x0D: "f32",
    0x0F: "u16",
    0x10: "i8",
    0x11: "u16",
    0x12: "i8",
    0x15: "u16",
    0x16: "i8",
    0x17: "u16",
    0x18: "i8",
}


class HcbError(ValueError):
    """Raised when an HCB cannot be safely parsed or rebuilt."""


def normalize_encoding(name: str) -> str:
    try:
        return ENCODINGS[name.strip().casefold()]
    except KeyError as exc:
        raise HcbError(f"unsupported encoding: {name}") from exc


def decode_bytes(value: bytes, encoding: str) -> str:
    return value.decode(normalize_encoding(encoding), errors="replace")


def encode_text(value: str, encoding: str) -> bytes:
    try:
        return value.encode(normalize_encoding(encoding))
    except UnicodeEncodeError as exc:
        raise HcbError(f"text cannot be encoded as {encoding}: {value!r}") from exc


def _decode_header_title(value: bytes, encoding: str) -> tuple[str, str]:
    """Decode an HCB title without losing a mixed-encoding header.

    Translated Hoshimemo HCBs keep the original title in Shift-JIS while
    dialogue overlays use GBK/GB18030.  Decoding the whole file with the
    selected GBK project encoding turns ``星空のメモリア`` into mojibake.  The
    title is metadata, so use a conservative Shift-JIS fallback only when it
    clearly contains Japanese kana and the selected decoding does not.
    """

    normalized = normalize_encoding(encoding)
    selected = value.decode(normalized, errors="replace")
    if normalized == "shift_jis":
        return selected, "shift_jis"

    sjis = value.decode("shift_jis", errors="replace")
    kana = sum(
        ("\u3040" <= char <= "\u30ff")
        for char in sjis
    )
    selected_kana = sum(
        ("\u3040" <= char <= "\u30ff")
        for char in selected
    )
    if kana >= 1 and selected_kana == 0 and "\ufffd" not in sjis:
        return sjis, "shift_jis"
    return selected, normalized


@dataclass
class Syscall:
    args: int
    name: str
    raw_name: bytes

    def to_public(self, index: int) -> dict[str, Any]:
        return {"index": index, "args": self.args, "name": self.name}


@dataclass
class HcbHeader:
    sysdesc_offset: int
    entry_point: int
    non_volatile_globals: int
    volatile_globals: int
    game_mode: int
    game_mode_reserved: int
    title: str
    syscalls: list[Syscall]
    custom_syscall_count: int
    # Preserve the exact header bytes.  Hybrid translated HCBs may keep a
    # Shift-JIS title while the selected project text encoding is GB18030.
    title_raw: bytes = b""
    title_encoding: str = ""
    trailing: bytes = b""


@dataclass
class Instruction:
    offset: int
    opcode: int
    mnemonic: str
    operands: dict[str, Any]
    raw: bytes
    text: str | None = None
    dirty: bool = False
    warning: str | None = None
    address_role: str | None = None

    @property
    def known(self) -> bool:
        return self.opcode in OPCODE_NAMES

    @property
    def size(self) -> int:
        return len(self.raw)

    def public(self, syscall_names: dict[int, str] | None = None) -> dict[str, Any]:
        operands = dict(self.operands)
        if self.opcode == 0x03 and syscall_names:
            syscall_id = int(operands.get("id", -1))
            operands["name"] = syscall_names.get(syscall_id, "<unknown>")
        return {
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:X}",
            "opcode": self.opcode,
            "mnemonic": self.mnemonic,
            "operands": operands,
            "text": self.text,
            "size": self.size,
            "raw_hex": self.raw.hex(" "),
            "known": self.known,
            "warning": self.warning,
            "address_role": self.address_role,
            "dirty": self.dirty,
        }

    def encode(
        self,
        mapping: dict[int, int],
        encoding: str,
        syscall_names: dict[int, str] | None = None,
    ) -> bytes:
        """Encode this instruction, remapping code addresses where applicable."""

        # Most real HCB instructions are untouched.  Reusing their original
        # bytes avoids millions of struct/format operations during a one-line
        # edit while retaining exact bytes for unknown and game-specific ops.
        if not self.dirty and self.opcode not in (0x02, 0x06, 0x07):
            if self.address_role != "thread_start_function_pointer":
                return self.raw

        if not self.known:
            return self.raw

        op = bytes([self.opcode])
        fmt = _OPERAND_FORMATS.get(self.opcode)
        if self.opcode == 0x0E:
            value = self.text if self.text is not None else ""
            payload = encode_text(value, encoding) + b"\0"
            if len(payload) > 0xFF:
                raise HcbError(
                    f"string at 0x{self.offset:X} exceeds the HCB 255-byte length field"
                )
            return op + bytes([len(payload)]) + payload
        if fmt is None:
            return op
        if fmt == "init":
            return op + bytes(
                [
                    int(self.operands.get("args", 0)) & 0xFF,
                    int(self.operands.get("locals", 0)) & 0xFF,
                ]
            )
        if fmt == "u32_target":
            target = int(self.operands.get("target", 0))
            target = mapping.get(target, target)
            return op + struct.pack("<I", target)
        if fmt == "u16_syscall":
            return op + struct.pack("<H", int(self.operands.get("id", 0)) & 0xFFFF)
        if fmt == "u16":
            return op + struct.pack("<H", int(self.operands.get("value", 0)) & 0xFFFF)
        if fmt == "i8":
            return op + struct.pack("<b", int(self.operands.get("value", 0)))
        if fmt == "i16":
            return op + struct.pack("<h", int(self.operands.get("value", 0)))
        if fmt == "i32":
            value = int(self.operands.get("value", 0))
            if self.address_role == "thread_start_function_pointer":
                value = mapping.get(value, value)
            return op + struct.pack("<i", value)
        if fmt == "f32":
            return op + struct.pack("<f", float(self.operands.get("value", 0.0)))
        raise HcbError(f"unhandled operand format {fmt!r} for opcode {self.opcode}")

    def encoded_size(self, encoding: str) -> int:
        """Return the post-edit size without allocating a full code buffer."""

        if not self.dirty:
            return len(self.raw)
        return len(self.encode({}, encoding))


@dataclass
class RawInsertion:
    """A bytecode block inserted before an existing code address.

    ``target_offsets`` maps a little-endian u32 position inside ``data`` to
    the original HCB address it refers to.  This lets a generated function
    call follow the same relocation rules as parsed ``call`` instructions.
    Opaque blocks are deliberately gated by ``allow_unknown`` at rebuild time;
    they are an expert escape hatch for game-specific FVP functions rather
    than something the editor should silently reinterpret.
    """

    anchor_offset: int
    data: bytes
    target_offsets: dict[int, int] = field(default_factory=dict)
    note: str = ""
    opaque: bool = False
    instruction_count: int | None = None
    string_count: int | None = None
    jump_kind: str | None = None

    def encode(self, mapping: dict[int, int]) -> bytes:
        payload = bytearray(self.data)
        for relative, target in self.target_offsets.items():
            if relative < 0 or relative + 4 > len(payload):
                raise HcbError(f"插入字节码的目标字段越界: +0x{relative:X}")
            struct.pack_into("<I", payload, relative, mapping.get(target, target))
        return bytes(payload)

    def to_json(self) -> dict[str, Any]:
        return {
            "anchor_offset": self.anchor_offset,
            "anchor_offset_hex": f"0x{self.anchor_offset:X}",
            "raw_hex": self.data.hex(" "),
            "size": len(self.data),
            "target_offsets": {
                f"0x{relative:X}": target for relative, target in self.target_offsets.items()
            },
            "note": self.note,
            "opaque": self.opaque,
            "instruction_count": self.instruction_count,
            "string_count": self.string_count,
            "jump_kind": self.jump_kind,
        }


@dataclass
class FixedPatch:
    """An exact-width byte patch for an already overlaid HCB.

    Some translation patches turn original instructions into trampolines and
    append replacement code after the normal code stream.  Reassembling such
    a file would move addresses the overlay owns.  A fixed patch therefore
    verifies the original bytes and changes exactly five bytes in place.
    """

    offset: int
    expected: bytes
    data: bytes
    target: int | None
    jump_kind: str
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:X}",
            "expected_hex": self.expected.hex(" "),
            "raw_hex": self.data.hex(" "),
            "size": len(self.data),
            "target": self.target,
            "target_hex": f"0x{self.target:X}" if self.target is not None else None,
            "jump_kind": self.jump_kind,
            "note": self.note,
        }


@dataclass
class OverlayTextRelocation:
    """A variable-length text replacement for a translated HCB overlay.

    The original ``push_string`` bytes stay in place and are replaced only at
    their first five bytes by an absolute ``jmp``.  The new string and a jump
    back to the instruction after the original slot are appended at the end
    of the file.  The system-description block and every existing overlay
    stub therefore keep their original offsets.
    """

    offset: int
    expected: bytes
    text: str
    return_offset: int
    note: str = ""

    def payload(self, encoding: str) -> bytes:
        encoded = encode_text(self.text, encoding)
        payload = encoded + b"\0"
        if len(payload) > 0xFF:
            raise HcbError(
                f"relocated string at 0x{self.offset:X} exceeds the HCB 255-byte length field"
            )
        return payload

    def to_json(self, encoding: str, code_end: int, stub_offset: int | None = None) -> dict[str, Any]:
        payload = self.payload(encoding)
        return {
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:X}",
            "expected_hex": self.expected.hex(" "),
            "slot_size": len(self.expected) - 2,
            "text": self.text,
            "encoded_size": len(payload),
            "return_offset": self.return_offset,
            "return_offset_hex": f"0x{self.return_offset:X}",
            "stub_offset": stub_offset,
            "stub_offset_hex": f"0x{stub_offset:X}" if stub_offset is not None else None,
            "code_end": code_end,
            "note": self.note,
        }


@dataclass
class HcbDocument:
    path: Path | None
    encoding: str
    header: HcbHeader
    instructions: list[Instruction]
    original_bytes: bytes
    warnings: list[str] = field(default_factory=list)
    modified: bool = False
    insertions: list[RawInsertion] = field(default_factory=list)
    fixed_patches: list[FixedPatch] = field(default_factory=list)
    overlay_text_relocations: list[OverlayTextRelocation] = field(default_factory=list)

    @property
    def code_end(self) -> int:
        return self.header.sysdesc_offset

    @property
    def syscall_names(self) -> dict[int, str]:
        return {index: item.name for index, item in enumerate(self.header.syscalls)}

    @property
    def string_count(self) -> int:
        return sum(item.opcode == 0x0E for item in self.instructions)

    @property
    def source_sha256(self) -> str:
        return hashlib.sha256(self.original_bytes).hexdigest()

    def summary(self) -> dict[str, Any]:
        # A malformed/foreign HCB can produce tens of thousands of warnings.
        # Keep the status response small while preserving enough examples for
        # the UI and the complete list for validation/debugging callers.
        warning_count = len(self.warnings)
        return {
            "path": str(self.path) if self.path else None,
            "encoding": self.encoding,
            "file_size": len(self.original_bytes),
            "source_sha256": self.source_sha256,
            "code_end": self.code_end,
            "code_end_hex": f"0x{self.code_end:X}",
            "entry_point": self.header.entry_point,
            "entry_point_hex": f"0x{self.header.entry_point:X}",
            "title": self.header.title,
            "title_encoding": self.header.title_encoding or self.encoding,
            "instruction_count": len(self.instructions),
            "string_count": self.string_count,
            "syscall_count": len(self.header.syscalls),
            "custom_syscall_count": self.header.custom_syscall_count,
            "warning_count": warning_count,
            "warnings": list(self.warnings[:64]),
            "parse_safe": warning_count == 0,
            "modified": self.modified,
            "insertion_count": len(self.insertions),
            "fixed_patch_count": len(self.fixed_patches),
            "overlay_text_relocation_count": len(self.overlay_text_relocations),
        }

    def iter_events(self) -> Iterable[dict[str, Any]]:
        """Yield UI-friendly events without allocating a second instruction list."""

        for index, item in enumerate(self.instructions):
            yield self.event_at(index)

    def event_at(self, index: int) -> dict[str, Any]:
        """Build one public event by instruction index."""

        item = self.instructions[index]
        public = item.public(self.syscall_names)
        if item.opcode == 0x0E:
            public["kind"] = "string"
        elif item.opcode in (0x06, 0x07):
            public["kind"] = "control_flow"
        elif item.opcode == 0x03:
            public["kind"] = "syscall"
        elif item.opcode == 0x02:
            public["kind"] = "call"
        else:
            public["kind"] = "instruction"
        public["index"] = index
        return public

    def events(self) -> list[dict[str, Any]]:
        """Return all events for small exports; the web API uses iter_events()."""

        return list(self.iter_events())

    def function_index(self, query: str = "") -> list[dict[str, Any]]:
        """Summarize function targets referenced by parsed ``call`` opcodes."""

        query = str(query or "").casefold()
        instructions_by_offset = {item.offset: item for item in self.instructions}
        grouped: dict[int, dict[str, Any]] = {}
        for item in self.instructions:
            if item.opcode != 0x02:
                continue
            target = int(item.operands.get("target", 0))
            record = grouped.setdefault(
                target,
                {
                    "target": target,
                    "target_hex": f"0x{target:X}",
                    "call_count": 0,
                    "caller_offsets": [],
                },
            )
            record["call_count"] += 1
            if len(record["caller_offsets"]) < 8:
                record["caller_offsets"].append(item.offset)
        result: list[dict[str, Any]] = []
        for target, record in grouped.items():
            target_instruction = instructions_by_offset.get(target)
            record["target_mnemonic"] = target_instruction.mnemonic if target_instruction else "<非指令边界>"
            record["target_known"] = bool(target_instruction and target_instruction.known)
            haystack = " ".join(
                [
                    record["target_hex"],
                    str(target),
                    record["target_mnemonic"],
                    *(f"0x{offset:X}" for offset in record["caller_offsets"]),
                ]
            ).casefold()
            if query and query not in haystack:
                continue
            result.append(record)
        result.sort(key=lambda item: item["target"])
        return result

    def flow_index(self, query: str = "") -> list[dict[str, Any]]:
        """Return explicit HCB jump edges for the flow/choice inspector.

        Only encoded control-flow edges are reported.  The editor does not
        guess that a game-specific syscall is a choice; callers can inspect
        the surrounding syscall and edit the target safely instead.
        """

        query = str(query or "").casefold().strip()
        instructions_by_offset = {item.offset: item for item in self.instructions}
        result: list[dict[str, Any]] = []
        for item in self.instructions:
            if item.opcode not in (0x06, 0x07):
                continue
            target = int(item.operands.get("target", 0))
            target_item = instructions_by_offset.get(target)
            record: dict[str, Any] = {
                "offset": item.offset,
                "offset_hex": f"0x{item.offset:X}",
                "opcode": item.opcode,
                "mnemonic": item.mnemonic,
                "condition": "zero" if item.opcode == 0x07 else "always",
                "target": target,
                "target_hex": f"0x{target:X}",
                "target_exists": target_item is not None,
                "target_mnemonic": target_item.mnemonic if target_item else "<非指令边界>",
                "target_text": target_item.text if target_item and target_item.opcode == 0x0E else None,
                "next_offset": item.offset + item.size,
            }
            haystack = " ".join(
                str(value or "")
                for value in (
                    record["offset_hex"],
                    record["offset"],
                    record["mnemonic"],
                    record["condition"],
                    record["target_hex"],
                    record["target"],
                    record["target_mnemonic"],
                    record["target_text"],
                )
            ).casefold()
            if query and query not in haystack:
                continue
            result.append(record)
        result.sort(key=lambda item: item["offset"])
        return result

    def find(self, offset: int) -> Instruction:
        return self.find_with_index(offset)[1]

    def find_with_index(self, offset: int) -> tuple[int, Instruction]:
        for index, item in enumerate(self.instructions):
            if item.offset == offset:
                return index, item
        raise HcbError(f"instruction 0x{offset:X} not found")

    def edit_string(self, offset: int, text: str) -> Instruction:
        if self.fixed_patches or self.overlay_text_relocations:
            raise HcbError("overlay patches cannot be mixed with normal string edits")
        item = self.find(offset)
        if item.opcode != 0x0E:
            raise HcbError(f"0x{offset:X} is not a push_string instruction")
        # Validate encoding before touching the document.
        encode_text(text, self.encoding)
        if len(encode_text(text, self.encoding)) + 1 > 0xFF:
            raise HcbError(f"string at 0x{offset:X} exceeds the HCB length field")
        item.text = text
        item.dirty = True
        self.modified = True
        return item

    def edit_target(self, offset: int, target: int) -> Instruction:
        if self.fixed_patches or self.overlay_text_relocations:
            raise HcbError("overlay patches cannot be mixed with relocated target edits")
        item = self.find(offset)
        if item.opcode not in (0x02, 0x06, 0x07):
            raise HcbError(f"0x{offset:X} 不是 call/jmp/jz 指令")
        if target < 4 or target >= self.code_end:
            raise HcbError(f"目标偏移超出代码区: 0x{target:X}")
        item.operands["target"] = int(target)
        item.dirty = True
        self.modified = True
        return item

    def insert_raw(
        self,
        anchor_offset: int,
        data: bytes,
        *,
        target_offsets: dict[int, int] | None = None,
        note: str = "",
        opaque: bool = True,
        instruction_count: int | None = None,
        string_count: int | None = None,
    ) -> RawInsertion:
        """Insert a bytecode block before an instruction or at code end.

        This is intentionally separate from parsed instruction editing.  It
        is useful for game-specific FVP function calls that are not expressible
        through the generic opcode table, while the explicit ``opaque`` flag
        prevents an accidental normal save from pretending those bytes were
        understood by the editor.
        """

        if self.fixed_patches or self.overlay_text_relocations:
            raise HcbError("overlay patches cannot be mixed with inserted bytecode")
        try:
            anchor = int(anchor_offset)
        except (TypeError, ValueError) as exc:
            raise HcbError("插入位置必须是整数偏移") from exc
        valid_anchors = {item.offset for item in self.instructions}
        valid_anchors.add(self.code_end)
        if anchor not in valid_anchors:
            raise HcbError(f"插入位置不是指令边界或代码尾: 0x{anchor:X}")
        payload = bytes(data)
        if not payload:
            raise HcbError("插入字节码不能为空")
        if len(payload) > 1024 * 1024:
            raise HcbError("单次插入字节码不能超过 1 MiB")
        targets = {int(relative): int(target) for relative, target in (target_offsets or {}).items()}
        for relative, target in targets.items():
            if relative < 0 or relative + 4 > len(payload):
                raise HcbError(f"插入字节码的目标字段越界: +0x{relative:X}")
            if target < 4 or target >= self.code_end:
                raise HcbError(f"插入字节码的目标超出代码区: 0x{target:X}")
        insertion = RawInsertion(
            anchor,
            payload,
            targets,
            str(note),
            bool(opaque),
            int(instruction_count) if instruction_count is not None else None,
            int(string_count) if string_count is not None else None,
        )
        self.insertions.append(insertion)
        self.modified = True
        return insertion

    def patch_jump_in_place(
        self,
        offset: int,
        target: int,
        expected: bytes,
        *,
        conditional: bool = False,
        note: str = "",
        expected_source_sha256: str | None = None,
    ) -> FixedPatch:
        """Overwrite one five-byte instruction with an absolute jmp/jz.

        Unlike :meth:`insert_jump`, this mode never relocates any address and
        is intended for an HCB that already contains translation trampolines.
        The caller must provide the exact five source bytes, preventing a
        patch made for another game build from being applied silently.
        """

        if self.insertions or any(item.dirty for item in self.instructions) or self.overlay_text_relocations:
            raise HcbError("overlay fixed patches cannot be mixed with normal HCB rebuild edits")
        try:
            offset = int(offset)
            target = int(target)
        except (TypeError, ValueError) as exc:
            raise HcbError("fixed jump offset and target must be integers") from exc
        expected = bytes(expected)
        if len(expected) != 5:
            raise HcbError("fixed jump expected bytes must contain exactly 5 bytes")
        if offset < 4 or offset + 5 > self.code_end:
            raise HcbError(f"fixed jump offset is outside the code area: 0x{offset:X}")
        if target < 4 or target >= self.code_end:
            raise HcbError(f"fixed jump target is outside the code area: 0x{target:X}")
        if expected_source_sha256:
            supplied_hash = str(expected_source_sha256).strip().casefold()
            if supplied_hash != self.source_sha256.casefold():
                raise HcbError(
                    "source HCB SHA-256 does not match the fixed-jump patch: "
                    f"expected {supplied_hash}, opened {self.source_sha256}"
                )
        actual = self.original_bytes[offset : offset + 5]
        if actual != expected:
            raise HcbError(
                f"source bytes at 0x{offset:X} do not match: "
                f"expected {expected.hex(' ')}, found {actual.hex(' ')}"
            )
        for existing in self.fixed_patches:
            if not (offset + 5 <= existing.offset or existing.offset + 5 <= offset):
                raise HcbError(f"fixed jump overlaps the patch at 0x{existing.offset:X}")
        opcode = 0x07 if conditional else 0x06
        payload = bytes([opcode]) + struct.pack("<I", target)
        patch = FixedPatch(
            offset=offset,
            expected=expected,
            data=payload,
            target=target,
            jump_kind="zero" if conditional else "always",
            note=str(note),
        )
        self.fixed_patches.append(patch)
        self.modified = True
        return patch

    def patch_call_in_place(
        self,
        offset: int,
        target: int,
        expected: bytes,
        *,
        note: str = "",
        expected_source_sha256: str | None = None,
    ) -> FixedPatch:
        """Overwrite one five-byte absolute ``call`` without relocating code.

        This is the call-preserving counterpart to
        :meth:`patch_jump_in_place`.  It is intentionally strict: only an
        existing ``0x02`` call may be retargeted, the source bytes must match
        exactly, and the replacement is always the same five-byte width.  In
        particular, this must not be implemented as a JMP: wrapper functions
        need the original call/return frame to resume the script safely.
        """

        if self.insertions or any(item.dirty for item in self.instructions) or self.overlay_text_relocations:
            raise HcbError("overlay fixed patches cannot be mixed with normal HCB rebuild edits")
        try:
            offset = int(offset)
            target = int(target)
        except (TypeError, ValueError) as exc:
            raise HcbError("fixed call offset and target must be integers") from exc
        expected = bytes(expected)
        if len(expected) != 5:
            raise HcbError("fixed call expected bytes must contain exactly 5 bytes")
        if expected[0] != 0x02:
            raise HcbError(
                "fixed call source must be opcode 0x02; use patch_jump_in_place for a JMP"
            )
        if offset < 4 or offset + 5 > self.code_end:
            raise HcbError(f"fixed call offset is outside the code area: 0x{offset:X}")
        if target < 4 or target >= self.code_end:
            raise HcbError(f"fixed call target is outside the code area: 0x{target:X}")
        if expected_source_sha256:
            supplied_hash = str(expected_source_sha256).strip().casefold()
            if supplied_hash != self.source_sha256.casefold():
                raise HcbError(
                    "source HCB SHA-256 does not match the fixed-call patch: "
                    f"expected {supplied_hash}, opened {self.source_sha256}"
                )
        actual = self.original_bytes[offset : offset + 5]
        if actual != expected:
            raise HcbError(
                f"source bytes at 0x{offset:X} do not match: "
                f"expected {expected.hex(' ')}, found {actual.hex(' ')}"
            )
        for existing in self.fixed_patches:
            if not (offset + 5 <= existing.offset or existing.offset + len(existing.expected) <= offset):
                raise HcbError(f"fixed call overlaps the patch at 0x{existing.offset:X}")
        payload = bytes([0x02]) + struct.pack("<I", target)
        patch = FixedPatch(
            offset=offset,
            expected=expected,
            data=payload,
            target=target,
            jump_kind="call",
            note=str(note),
        )
        self.fixed_patches.append(patch)
        self.modified = True
        return patch

    def patch_bytes_in_place(
        self,
        offset: int,
        expected: bytes,
        replacement: bytes,
        *,
        note: str = "",
        expected_source_sha256: str | None = None,
    ) -> FixedPatch:
        """Apply an exact-width audited byte patch without relocating code.

        Semantic jump recipes sometimes need to change a state/effect argument
        in addition to writing a five-byte branch.  Requiring exact source
        bytes and equal-width replacement bytes keeps that operation as strict
        as :meth:`patch_jump_in_place` while avoiding a full overlay rebuild.
        """

        if self.insertions or any(item.dirty for item in self.instructions) or self.overlay_text_relocations:
            raise HcbError("overlay fixed patches cannot be mixed with normal HCB rebuild edits")
        try:
            offset = int(offset)
        except (TypeError, ValueError) as exc:
            raise HcbError("fixed byte patch offset must be an integer") from exc
        expected = bytes(expected)
        replacement = bytes(replacement)
        if not expected or len(expected) != len(replacement):
            raise HcbError("fixed byte patch expected/replacement must have the same non-zero length")
        if offset < 4 or offset + len(expected) > self.code_end:
            raise HcbError(f"fixed byte patch is outside the code area: 0x{offset:X}")
        if expected_source_sha256:
            supplied_hash = str(expected_source_sha256).strip().casefold()
            if supplied_hash != self.source_sha256.casefold():
                raise HcbError(
                    "source HCB SHA-256 does not match the fixed byte patch: "
                    f"expected {supplied_hash}, opened {self.source_sha256}"
                )
        actual = self.original_bytes[offset : offset + len(expected)]
        if actual != expected:
            raise HcbError(
                f"source bytes at 0x{offset:X} do not match: "
                f"expected {expected.hex(' ')}, found {actual.hex(' ')}"
            )
        for existing in self.fixed_patches:
            if not (
                offset + len(expected) <= existing.offset
                or existing.offset + len(existing.expected) <= offset
            ):
                raise HcbError(f"fixed byte patch overlaps the patch at 0x{existing.offset:X}")
        patch = FixedPatch(
            offset=offset,
            expected=expected,
            data=replacement,
            target=None,
            jump_kind="bytes",
            note=str(note),
        )
        self.fixed_patches.append(patch)
        self.modified = True
        return patch

    def patch_text_in_place(
        self,
        offset: int,
        text: str,
        *,
        note: str = "",
        expected_source_sha256: str | None = None,
    ) -> FixedPatch:
        """Replace a push_string payload without relocating any HCB bytes.

        This is intentionally separate from :meth:`edit_string`: translated
        Hoshimemo overlays contain opaque instruction regions, so a normal
        rebuild would invalidate addresses.  The existing length byte is
        retained and the new NUL-terminated payload is space-padded inside the
        original slot.  The caller therefore gets the same strict source-byte
        and overlap checks as other fixed overlay patches.
        """

        if not isinstance(text, str):
            raise HcbError("overlay text must be a string")
        item = self.find(int(offset))
        if item.opcode != 0x0E:
            raise HcbError(f"0x{int(offset):X} is not a push_string instruction")
        raw = bytes(item.raw)
        if len(raw) < 3 or raw[0] != 0x0E or raw[1] != len(raw) - 2:
            raise HcbError(
                f"push_string at 0x{int(offset):X} has an invalid fixed slot"
            )
        encoded = encode_text(text, self.encoding)
        if b"\x00" in encoded:
            raise HcbError("overlay text cannot contain a NUL byte")
        payload = encoded + b"\x00"
        slot_size = int(raw[1])
        if len(payload) > slot_size:
            raise HcbError(
                f"overlay text at 0x{int(offset):X} exceeds its fixed slot: "
                f"{len(payload)}/{slot_size} bytes"
            )
        replacement = bytearray(raw)
        padding = b" " * (slot_size - len(payload))
        replacement[2 : 2 + slot_size] = encoded + padding + b"\x00"
        return self.patch_bytes_in_place(
            int(offset),
            raw,
            bytes(replacement),
            note=note or f"overlay text 0x{int(offset):X}",
            expected_source_sha256=expected_source_sha256,
        )

    def patch_text_relocated(
        self,
        offset: int,
        text: str,
        *,
        note: str = "",
        expected_source_sha256: str | None = None,
    ) -> OverlayTextRelocation:
        """Move an overlong overlay string to an appended trampoline block.

        This mode deliberately does not use the normal linear HCB rebuild.  It
        leaves every original file address unchanged, appends a small
        ``push_string`` + ``jmp return`` block at EOF, and turns the original
        instruction into a five-byte absolute jump.  Existing fixed-width
        text patches on the same slot are replaced by this relocation so a
        user can grow a string in one editing session without reopening the
        file.  Appending at EOF is important for translated overlays: the
        bytes after ``sysdesc_offset`` already contain executable trampoline
        stubs, and inserting before them would invalidate their absolute
        targets.
        """

        if self.insertions or any(item.dirty for item in self.instructions):
            raise HcbError("overlay text relocation cannot be mixed with normal HCB rebuild edits")
        try:
            offset = int(offset)
        except (TypeError, ValueError) as exc:
            raise HcbError("overlay text offset must be an integer") from exc
        if not isinstance(text, str):
            raise HcbError("overlay text must be a string")
        item = self.find(offset)
        if item.opcode != 0x0E:
            raise HcbError(f"0x{offset:X} is not a push_string instruction")
        raw = bytes(item.raw)
        if len(raw) < 5 or raw[0] != 0x0E or raw[1] != len(raw) - 2:
            raise HcbError(f"push_string at 0x{offset:X} has an invalid fixed slot")
        payload = encode_text(text, self.encoding) + b"\0"
        if b"\0" in payload[:-1]:
            raise HcbError("overlay text cannot contain a NUL byte")
        if len(payload) <= int(raw[1]):
            raise HcbError(
                f"overlay text at 0x{offset:X} fits its fixed slot; use fixed-width overlay instead"
            )
        if len(payload) > 0xFF:
            raise HcbError(
                f"relocated string at 0x{offset:X} exceeds the HCB 255-byte length field"
            )
        if offset < 4 or offset + 5 > self.code_end:
            raise HcbError(f"overlay text offset is outside the code area: 0x{offset:X}")
        return_offset = offset + len(raw)
        boundaries = {entry.offset for entry in self.instructions}
        if return_offset not in boundaries:
            raise HcbError(
                f"overlay text return address is not an instruction boundary: 0x{return_offset:X}"
            )
        if expected_source_sha256:
            supplied_hash = str(expected_source_sha256).strip().casefold()
            if supplied_hash != self.source_sha256.casefold():
                raise HcbError(
                    "source HCB SHA-256 does not match the text relocation: "
                    f"expected {supplied_hash}, opened {self.source_sha256}"
                )
        for existing in self.overlay_text_relocations:
            if existing.offset == offset:
                raise HcbError(f"overlay text relocation already exists at 0x{offset:X}")
            if not (offset + len(raw) <= existing.offset or existing.offset + len(existing.expected) <= offset):
                raise HcbError(f"overlay text relocation overlaps 0x{existing.offset:X}")
        # A previous fixed-width edit on this exact slot is safe to replace;
        # any other overlap is ambiguous and must be undone explicitly.
        for existing in list(self.fixed_patches):
            overlaps = not (
                offset + len(raw) <= existing.offset
                or existing.offset + len(existing.expected) <= offset
            )
            if not overlaps:
                continue
            if existing.offset == offset and existing.expected == raw:
                self.fixed_patches.remove(existing)
            else:
                raise HcbError(f"overlay text relocation overlaps fixed patch at 0x{existing.offset:X}")
        actual = self.original_bytes[offset : offset + len(raw)]
        if actual != raw:
            raise HcbError(
                f"source bytes at 0x{offset:X} changed before relocation: "
                f"expected {raw.hex(' ')}, found {actual.hex(' ')}"
            )
        relocation = OverlayTextRelocation(
            offset=offset,
            expected=raw,
            text=text,
            return_offset=return_offset,
            note=note or f"relocated overlay text 0x{offset:X}",
        )
        self.overlay_text_relocations.append(relocation)
        self.modified = True
        return relocation

    def insert_call(
        self,
        anchor_offset: int,
        target: int,
        args: list[dict[str, Any]] | None = None,
        *,
        note: str = "",
    ) -> RawInsertion:
        """Generate a normal FVP call (push arguments followed by 0x02).

        The argument vocabulary intentionally mirrors the primitive HCB stack
        values: ``nil``, ``true``, ``i8``, ``i16``, ``i32``, ``f32`` and
        ``string``.  The call target is recorded for address relocation when a
        preceding text edit shifts the function.
        """

        target = int(target)
        if target < 4 or target >= self.code_end:
            raise HcbError(f"函数目标超出代码区: 0x{target:X}")
        payload = bytearray()
        string_count = 0
        for argument in args or []:
            if not isinstance(argument, dict):
                raise HcbError("函数参数必须是对象数组")
            arg_type = str(argument.get("type", "")).strip().casefold()
            value = argument.get("value")
            if arg_type == "nil":
                payload.append(0x08)
            elif arg_type == "true":
                payload.append(0x09)
            elif arg_type == "i8":
                try:
                    number = int(value)
                    if not -128 <= number <= 127:
                        raise ValueError
                except (TypeError, ValueError) as exc:
                    raise HcbError("i8 参数必须在 -128..127") from exc
                payload.extend((0x0C, number & 0xFF))
            elif arg_type == "i16":
                try:
                    number = int(value)
                    if not -32768 <= number <= 32767:
                        raise ValueError
                except (TypeError, ValueError) as exc:
                    raise HcbError("i16 参数必须在 -32768..32767") from exc
                payload.append(0x0B)
                payload.extend(struct.pack("<h", number))
            elif arg_type == "i32":
                try:
                    number = int(value)
                    if not -(1 << 31) <= number <= (1 << 31) - 1:
                        raise ValueError
                except (TypeError, ValueError) as exc:
                    raise HcbError("i32 参数超出有符号 32 位范围") from exc
                payload.append(0x0A)
                payload.extend(struct.pack("<i", number))
            elif arg_type == "f32":
                try:
                    number = float(value)
                except (TypeError, ValueError) as exc:
                    raise HcbError("f32 参数必须是数字") from exc
                payload.append(0x0D)
                payload.extend(struct.pack("<f", number))
            elif arg_type == "string":
                if not isinstance(value, str):
                    raise HcbError("string 参数必须是字符串")
                encoded = encode_text(value, self.encoding) + b"\0"
                if len(encoded) > 0xFF:
                    raise HcbError("string 函数参数超过 HCB 1 字节长度字段")
                payload.extend((0x0E, len(encoded)))
                payload.extend(encoded)
                string_count += 1
            else:
                raise HcbError(f"不支持的函数参数类型: {arg_type or '<empty>'}")
        call_operand = len(payload) + 1
        payload.append(0x02)
        payload.extend(struct.pack("<I", target))
        return self.insert_raw(
            anchor_offset,
            bytes(payload),
            target_offsets={call_operand: target},
            note=note or f"call 0x{target:X}",
            opaque=False,
            instruction_count=len(args or []) + 1,
            string_count=string_count,
        )

    def insert_jump(
        self,
        anchor_offset: int,
        target: int,
        *,
        conditional: bool = False,
        note: str = "",
    ) -> RawInsertion:
        """Generate a relocatable unconditional or zero-conditional jump.

        FVP stores both ``jmp`` (0x06) and ``jz`` (0x07) targets as absolute
        little-endian u32 code offsets.  The target must be an existing
        instruction boundary; accepting an arbitrary byte offset here would
        create a script that the editor can export but the VM cannot safely
        enter.  The insertion is represented as a known one-instruction
        block, so normal saves relocate it together with all existing code.
        """

        try:
            target = int(target)
        except (TypeError, ValueError) as exc:
            raise HcbError("跳转目标必须是整数偏移") from exc
        if target < 4 or target >= self.code_end:
            raise HcbError(f"跳转目标超出代码区: 0x{target:X}")
        if target not in {item.offset for item in self.instructions}:
            raise HcbError(f"跳转目标不是指令边界: 0x{target:X}")
        opcode = 0x07 if conditional else 0x06
        insertion = self.insert_raw(
            anchor_offset,
            bytes([opcode]) + b"\x00\x00\x00\x00",
            target_offsets={1: target},
            note=note or (f"jz 0x{target:X}" if conditional else f"jmp 0x{target:X}"),
            opaque=False,
            instruction_count=1,
        )
        insertion.jump_kind = "zero" if conditional else "always"
        return insertion

    def remove_last_insertion(self) -> RawInsertion:
        """Remove the most recently inserted custom block for this session."""

        if not self.insertions:
            raise HcbError("当前没有可撤销的自定义插入")
        insertion = self.insertions.pop()
        self.modified = bool(self.insertions) or any(item.dirty for item in self.instructions)
        return insertion

    def remove_last_overlay_text_relocation(self) -> OverlayTextRelocation:
        """Remove the most recently queued variable-length text relocation."""

        if not self.overlay_text_relocations:
            raise HcbError("no overlay text relocation can be undone")
        relocation = self.overlay_text_relocations.pop()
        self.modified = bool(
            self.insertions
            or self.fixed_patches
            or self.overlay_text_relocations
            or any(item.dirty for item in self.instructions)
        )
        return relocation

    def clone(self) -> "HcbDocument":
        return copy.deepcopy(self)

    def _build_overlay_text_relocations(self) -> bytes:
        """Build fixed patches plus appended variable-length text stubs."""

        original = self.original_bytes
        code_end = self.code_end
        rebuilt = bytearray(original)
        for patch in self.fixed_patches:
            actual = bytes(rebuilt[patch.offset : patch.offset + len(patch.expected)])
            if actual != patch.expected:
                raise HcbError(
                    f"fixed patch source changed at 0x{patch.offset:X}: "
                    f"expected {patch.expected.hex(' ')}, found {actual.hex(' ')}"
                )
            rebuilt[patch.offset : patch.offset + len(patch.data)] = patch.data

        extension = bytearray()
        for relocation in self.overlay_text_relocations:
            actual = original[relocation.offset : relocation.offset + len(relocation.expected)]
            if actual != relocation.expected:
                raise HcbError(
                    f"text relocation source changed at 0x{relocation.offset:X}: "
                    f"expected {relocation.expected.hex(' ')}, found {actual.hex(' ')}"
                )
            if relocation.offset + 5 > code_end:
                raise HcbError(f"text relocation is outside the code area: 0x{relocation.offset:X}")
            # Existing translated HCBs commonly jump into the trailing block
            # after ``sysdesc_offset`` using absolute offsets.  Do not insert
            # before that block; append new code after every existing byte.
            stub_offset = len(original) + len(extension)
            payload = relocation.payload(self.encoding)
            stub = (
                b"\x0E"
                + bytes([len(payload)])
                + payload
                + b"\x06"
                + struct.pack("<I", relocation.return_offset)
            )
            jump = b"\x06" + struct.pack("<I", stub_offset)
            rebuilt[relocation.offset : relocation.offset + 5] = jump
            extension.extend(stub)

        if not extension:
            raise HcbError("no text relocation was queued")
        # Preserve the header, system-description block, and all existing
        # overlay bytes byte-for-byte.  Only the source jump patches change in
        # the original region; the new stubs live at EOF.
        return bytes(rebuilt + extension)

    def build(self, allow_unknown: bool = False) -> bytes:
        """Build a new HCB, relocating known code addresses after edits.

        Unknown opcodes are retained byte-for-byte, but their operand layout is
        not known to this editor.  Refuse a modified rebuild by default rather
        than silently shifting a target through an instruction we could not
        parse.  ``allow_unknown`` is an explicit expert escape hatch for a
        game-specific opcode table that the caller has independently checked.
        """

        if not self.modified:
            return self.original_bytes
        if self.overlay_text_relocations:
            if self.insertions or any(item.dirty for item in self.instructions):
                raise HcbError("overlay text relocations cannot be mixed with a relocated HCB rebuild")
            return self._build_overlay_text_relocations()
        if self.fixed_patches:
            if self.insertions or any(item.dirty for item in self.instructions):
                raise HcbError("overlay fixed patches cannot be mixed with a relocated HCB rebuild")
            rebuilt = bytearray(self.original_bytes)
            for patch in self.fixed_patches:
                actual = bytes(rebuilt[patch.offset : patch.offset + len(patch.expected)])
                if actual != patch.expected:
                    raise HcbError(
                        f"fixed jump source changed at 0x{patch.offset:X}: "
                        f"expected {patch.expected.hex(' ')}, found {actual.hex(' ')}"
                    )
                rebuilt[patch.offset : patch.offset + len(patch.data)] = patch.data
            return bytes(rebuilt)
        if self.warnings and not allow_unknown:
            raise HcbError(
                "HCB 含未知操作码，拒绝安全重建；请先补充该游戏的指令定义，"
                "或显式启用 allow_unknown"
            )
        if any(item.opaque for item in self.insertions) and not allow_unknown:
            raise HcbError(
                "HCB 含未解析的自定义插入字节码，拒绝安全重建；"
                "请确认该游戏的指令定义后再启用 allow_unknown"
            )

        mapping: dict[int, int] = {}
        next_offset = 4
        insertions_by_anchor: dict[int, list[RawInsertion]] = {}
        for insertion in self.insertions:
            insertions_by_anchor.setdefault(insertion.anchor_offset, []).append(insertion)
        for item in self.instructions:
            next_offset += sum(len(insertion.data) for insertion in insertions_by_anchor.get(item.offset, ()))
            mapping[item.offset] = next_offset
            next_offset += item.encoded_size(self.encoding)
        next_offset += sum(len(insertion.data) for insertion in insertions_by_anchor.get(self.code_end, ()))

        parts: list[bytes] = []
        for item in self.instructions:
            parts.extend(
                insertion.encode(mapping)
                for insertion in insertions_by_anchor.get(item.offset, ())
            )
            # Keep the hot path free of a Python method call for the large
            # population of unchanged instructions.  Only edited strings and
            # instructions carrying an address need re-encoding.
            if (
                not item.dirty
                and item.opcode not in (0x02, 0x06, 0x07)
                and item.address_role != "thread_start_function_pointer"
            ):
                parts.append(item.raw)
            else:
                parts.append(item.encode(mapping, self.encoding, self.syscall_names))
        parts.extend(
            insertion.encode(mapping)
            for insertion in insertions_by_anchor.get(self.code_end, ())
        )
        code = b"".join(parts)
        new_sysdesc_offset = 4 + len(code)
        entry_point = mapping.get(self.header.entry_point, self.header.entry_point)
        # An insertion anchored at the old entry point is meant to run before
        # the original entry instruction.  Existing address mapping normally
        # maps an anchor to the first *original* instruction after its
        # inserted bytes, which would silently skip a generated entry jump.
        # Point the header at the beginning of the inserted block instead.
        entry_insertions = insertions_by_anchor.get(self.header.entry_point, ())
        if entry_insertions:
            entry_point -= sum(len(item.data) for item in entry_insertions)
        sysdesc = self._build_sysdesc(new_sysdesc_offset, entry_point)
        return struct.pack("<I", new_sysdesc_offset) + code + sysdesc

    def _build_sysdesc(self, sysdesc_offset: int, entry_point: int) -> bytes:
        buf = bytearray()
        buf.extend(struct.pack("<I", entry_point))
        buf.extend(struct.pack("<H", self.header.non_volatile_globals))
        buf.extend(struct.pack("<H", self.header.volatile_globals))
        buf.extend(bytes([self.header.game_mode & 0xFF, self.header.game_mode_reserved & 0xFF]))
        # The editor currently exposes no header-title mutation control.  Keep
        # the original bytes so parsing a mixed HCB and editing one dialogue
        # cannot silently rewrite its Shift-JIS title as GB18030.
        title = self.header.title_raw or (encode_text(self.header.title, self.encoding) + b"\0")
        if len(title) > 0xFF:
            raise HcbError("title exceeds the HCB length field")
        buf.extend(bytes([len(title)]))
        buf.extend(title)
        buf.extend(struct.pack("<H", len(self.header.syscalls)))
        for syscall in self.header.syscalls:
            name = encode_text(syscall.name, self.encoding) + b"\0"
            if len(name) > 0xFF:
                raise HcbError(f"syscall name is too long: {syscall.name!r}")
            buf.extend(bytes([syscall.args & 0xFF, len(name)]))
            buf.extend(name)
        buf.extend(struct.pack("<H", self.header.custom_syscall_count))
        buf.extend(self.header.trailing)
        return bytes(buf)

    def save(self, output_path: Path, overwrite: bool = False, allow_unknown: bool = False) -> Path:
        output_path = output_path.resolve()
        if self.path and output_path == self.path.resolve() and not overwrite:
            raise HcbError("refusing to overwrite the source HCB without overwrite=true")
        if output_path.exists() and not overwrite:
            raise HcbError(f"output already exists: {output_path}")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(self.build(allow_unknown=allow_unknown))
        return output_path

    def to_json(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "header": {
                "entry_point": self.header.entry_point,
                "non_volatile_globals": self.header.non_volatile_globals,
                "volatile_globals": self.header.volatile_globals,
                "game_mode": self.header.game_mode,
                "title": self.header.title,
                "syscalls": [item.to_public(i) for i, item in enumerate(self.header.syscalls)],
                "custom_syscall_count": self.header.custom_syscall_count,
            },
            "insertions": [item.to_json() for item in self.insertions],
            "fixed_patches": [item.to_json() for item in self.fixed_patches],
            "overlay_text_relocations": [
                item.to_json(self.encoding, self.code_end)
                for item in self.overlay_text_relocations
            ],
            "instructions": self.events(),
        }


def _need(data: bytes, offset: int, size: int, end: int, label: str) -> None:
    if offset + size > end:
        raise HcbError(f"truncated {label} at 0x{offset:X}")


def _read_operand(data: bytes, cursor: int, fmt: str, end: int) -> tuple[dict[str, Any], int]:
    if fmt == "init":
        _need(data, cursor, 2, end, "init_stack")
        return {"args": data[cursor], "locals": data[cursor + 1]}, cursor + 2
    if fmt == "u32_target":
        _need(data, cursor, 4, end, "u32 target")
        return {"target": struct.unpack_from("<I", data, cursor)[0]}, cursor + 4
    if fmt == "u16_syscall":
        _need(data, cursor, 2, end, "syscall id")
        return {"id": struct.unpack_from("<H", data, cursor)[0]}, cursor + 2
    if fmt == "u16":
        _need(data, cursor, 2, end, "u16 operand")
        return {"value": struct.unpack_from("<H", data, cursor)[0]}, cursor + 2
    if fmt == "i8":
        _need(data, cursor, 1, end, "i8 operand")
        return {"value": struct.unpack_from("<b", data, cursor)[0]}, cursor + 1
    if fmt == "i16":
        _need(data, cursor, 2, end, "i16 operand")
        return {"value": struct.unpack_from("<h", data, cursor)[0]}, cursor + 2
    if fmt == "i32":
        _need(data, cursor, 4, end, "i32 operand")
        return {"value": struct.unpack_from("<i", data, cursor)[0]}, cursor + 4
    if fmt == "f32":
        _need(data, cursor, 4, end, "f32 operand")
        return {"value": struct.unpack_from("<f", data, cursor)[0]}, cursor + 4
    raise HcbError(f"unknown operand format {fmt!r}")


def parse_bytes(data: bytes, encoding: str = "sjis", path: Path | None = None) -> HcbDocument:
    """Parse an HCB byte buffer into a loss-aware document."""

    if len(data) < 8:
        raise HcbError("file is too small to be an HCB")
    sysdesc_offset = struct.unpack_from("<I", data, 0)[0]
    if sysdesc_offset < 4 or sysdesc_offset > len(data):
        raise HcbError(
            f"invalid sysdesc offset 0x{sysdesc_offset:X} for file size 0x{len(data):X}"
        )

    cursor = sysdesc_offset
    _need(data, cursor, 10, len(data), "HCB sysdesc")
    entry_point = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    non_volatile = struct.unpack_from("<H", data, cursor)[0]
    cursor += 2
    volatile = struct.unpack_from("<H", data, cursor)[0]
    cursor += 2
    game_mode = data[cursor]
    reserved = data[cursor + 1]
    cursor += 2

    title_len = data[cursor]
    cursor += 1
    _need(data, cursor, title_len, len(data), "title")
    title_raw = data[cursor : cursor + title_len]
    cursor += title_len
    title, title_encoding = _decode_header_title(title_raw.rstrip(b"\0"), encoding)

    _need(data, cursor, 2, len(data), "syscall count")
    syscall_count = struct.unpack_from("<H", data, cursor)[0]
    cursor += 2
    syscalls: list[Syscall] = []
    for index in range(syscall_count):
        _need(data, cursor, 2, len(data), f"syscall {index} header")
        args = data[cursor]
        name_len = data[cursor + 1]
        cursor += 2
        _need(data, cursor, name_len, len(data), f"syscall {index} name")
        raw_name = data[cursor : cursor + name_len]
        cursor += name_len
        syscalls.append(Syscall(args, decode_bytes(raw_name.rstrip(b"\0"), encoding), raw_name))

    _need(data, cursor, 2, len(data), "custom syscall count")
    custom_count = struct.unpack_from("<H", data, cursor)[0]
    cursor += 2
    trailing = data[cursor:]
    header = HcbHeader(
        sysdesc_offset=sysdesc_offset,
        entry_point=entry_point,
        non_volatile_globals=non_volatile,
        volatile_globals=volatile,
        game_mode=game_mode,
        game_mode_reserved=reserved,
        title=title,
        syscalls=syscalls,
        custom_syscall_count=custom_count,
        title_raw=title_raw,
        title_encoding=title_encoding,
        trailing=trailing,
    )

    instructions: list[Instruction] = []
    warnings: list[str] = []
    pos = 4
    while pos < sysdesc_offset:
        start = pos
        opcode = data[pos]
        pos += 1
        mnemonic = OPCODE_NAMES.get(opcode, f"unknown_0x{opcode:02X}")
        if opcode == 0x0E:
            _need(data, pos, 1, sysdesc_offset, "push_string length")
            length = data[pos]
            pos += 1
            _need(data, pos, length, sysdesc_offset, "push_string payload")
            payload = data[pos : pos + length]
            pos += length
            raw_text = payload[:-1] if payload.endswith(b"\0") else payload
            instructions.append(
                Instruction(
                    start,
                    opcode,
                    mnemonic,
                    {"length": length},
                    data[start:pos],
                    decode_bytes(raw_text, encoding),
                )
            )
            continue
        if opcode not in OPCODE_NAMES:
            warning = f"unknown opcode 0x{opcode:02X} at 0x{start:X}; retained as one raw byte"
            warnings.append(warning)
            instructions.append(
                Instruction(start, opcode, mnemonic, {}, data[start:pos], warning=warning)
            )
            continue
        fmt = _OPERAND_FORMATS.get(opcode)
        operands: dict[str, Any] = {}
        if fmt:
            operands, pos = _read_operand(data, pos, fmt, sysdesc_offset)
        instructions.append(Instruction(start, opcode, mnemonic, operands, data[start:pos]))

    document = HcbDocument(path, normalize_encoding(encoding), header, instructions, data, warnings)
    # ThreadStart receives a function pointer as push_i32 immediately before the syscall.
    for index, item in enumerate(document.instructions[:-1]):
        following = document.instructions[index + 1]
        if (
            item.opcode == 0x0A
            and following.opcode == 0x03
            and document.syscall_names.get(int(following.operands.get("id", -1)), "")
            == "ThreadStart"
        ):
            item.address_role = "thread_start_function_pointer"
    return document


def load(path: Path, encoding: str = "sjis") -> HcbDocument:
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise HcbError(f"HCB file not found: {path}")
    return parse_bytes(path.read_bytes(), encoding=encoding, path=path)


def dump_json(document: HcbDocument, path: Path) -> None:
    path.write_text(json.dumps(document.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")
