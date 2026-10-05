"""Owned story-state tail allocation and plain FVP arithmetic bytecode.

Extend only the volatile count in a NEW candidate. Existing global indexes,
non-volatile/save-unlock values, functions and syscall descriptors never move.
This is not a claim of native save/load or rewind compatibility.
"""
from copy import deepcopy
import struct

from .gui_story_logic import COMPARE, INT_LIMIT, effect, predicate, variables
from .portrait_emitter import _encode_push


class StoryVariableBank:
    def __init__(self, emitter, definitions):
        self.e = emitter
        self.definitions = variables(definitions)
        header = emitter.document.header
        table = struct.unpack_from("<I", emitter.source)[0]
        if table != header.sysdesc_offset or table + 8 > len(emitter.source):
            raise ValueError("剧情变量不能分配：脚本头发生变化。")
        nonvolatile, volatile = struct.unpack_from("<HH", emitter.source, table + 4)
        if (nonvolatile, volatile) != (header.non_volatile_globals, header.volatile_globals):
            raise ValueError("剧情变量不能分配：原作变量表发生变化。")
        total, count = nonvolatile + volatile, len(self.definitions)
        if total + count > 65535 or volatile + count > 65535:
            raise ValueError("脚本变量表已满，不能再添加剧情变量。")
        referenced = [i.operands["value"] for i in emitter.document.instructions
                      if i.opcode in (0x0F, 0x11, 0x15, 0x17)]
        if referenced and max(referenced) >= total:
            raise ValueError("原作使用了声明范围以外的变量，不能猜测可用编号。")
        self.slots = {key: total + number for number, key in enumerate(sorted(self.definitions))}
        self.header_offset = table + 6
        self.before, self.after = volatile, volatile + count
        self.total_before = total
        self.max_original_direct_global = max(referenced, default=-1)
        self.initialization = None

    def initialize(self):
        # Only the test/story ENTRY reaches this once. Scene labels and backward
        # jumps start later and must NOT reset a choice's recorded value.
        struct.pack_into("<H", self.e.output, self.header_offset, self.after)
        start = len(self.e.output)
        for key in sorted(self.definitions):
            self.set_value(key, self.definitions[key]["initial"])
        self.initialization = [start, len(self.e.output)]

    def load(self, key):
        return b"\x0f" + struct.pack("<H", self.slots[key])

    def set_value(self, key, value):
        # Store both booleans as numeric 0/1. Comparisons never mix FVP's True,
        # Nil and Int variants; the public project contract remains boolean.
        self.e.output.extend(_encode_push(int(value), "gbk") + b"\x15" + struct.pack("<H", self.slots[key]))

    def compare(self, test):
        test = predicate(test, self.definitions)
        return self.load(test["variable"]) + _encode_push(int(test["value"]), "gbk") + bytes([COMPARE[test["op"]]])

    def emit_effect(self, fields):
        fields = effect(fields, self.definitions)
        key, value = fields["variable"], fields["value"]
        if fields["op"] == "set":
            self.set_value(key, value)
            return
        # All inputs are within +/-1e6, so the addition cannot overflow i32.
        # Clamp the stored state so even an intentionally looping route stays
        # within that guarantee. This matches the target-independent runner.
        self.e.output.extend(self.load(key) + _encode_push(value, "gbk") + b"\x1a\x15" + struct.pack("<H", self.slots[key]))
        for op, bound in (("gt", INT_LIMIT), ("lt", -INT_LIMIT)):
            self.e.output.extend(self.compare(dict(variable=key, op=op, value=bound)))
            at = len(self.e.output)
            self.e.output.extend(b"\x07\0\0\0\0")
            self.set_value(key, bound)
            struct.pack_into("<I", self.e.output, at + 1, len(self.e.output))

    def validate_header(self, payload):
        if struct.unpack_from("<H", payload, self.header_offset)[0] != self.after:
            raise ValueError("剧情变量表长度与分配结果不一致。")
        if self.initialization is None or set(self.slots) != set(self.definitions):
            raise ValueError("剧情变量没有正确初始化。")
        return self.header_offset, struct.pack("<H", self.before)

    def report(self):
        return dict(schema="fvp-gui-story-state-native/1", variables=deepcopy(self.definitions),
            slots=dict(self.slots), total_before=self.total_before,
            max_original_direct_global=self.max_original_direct_global,
            header_changes=[] if self.before == self.after else [dict(offset=self.header_offset,
                field="volatile_globals", before=self.before, after=self.after)],
            initialization=self.initialization, reset_on_scene_entry=False,
            original_variable_slots_unchanged=True, non_volatile_globals_unchanged=True,
            integer_range=[-INT_LIMIT, INT_LIMIT], integer_add_policy="saturate",
            runtime_verified=False, save_load_verified=False, rewind_verified=False)
