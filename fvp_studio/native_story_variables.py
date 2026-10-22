"""Chapter-owned variables in the paired native scene's shared private tail.

Use the same VM arithmetic as Hoshi, but relocate jumps into an appended code
fragment. The scene assembler alone extends the header for ALL reservations.
"""
from copy import deepcopy
from types import SimpleNamespace
import struct

from .gui_story_logic import INT_LIMIT, variables
from .gui_story_program import StoryVariableBank
from .native_cg_snapshot_storage import NativeCGSnapshotStorage


class NativeStoryVariableBank(StoryVariableBank):
    def __init__(self, target, output, definitions, storage):
        self.definitions = variables(definitions)
        if not isinstance(storage, NativeCGSnapshotStorage):
            raise ValueError("通用剧情变量需要本场景配对的私有状态存储。")
        self.e = SimpleNamespace(output=output)
        self.address_base = len(target.context.document.original_bytes)
        self.storage = storage
        group = storage.reserve_private(len(self.definitions), "chapter_story_variables") if self.definitions else None
        self.slots = dict(zip(sorted(self.definitions), group["private_global_ids"])) if group else {}
        self.initialization, self.cleanup = None, None

    def initialize(self):
        if self.initialization is not None:
            raise ValueError("剧情变量只能在章节首次入口初始化。")
        start = len(self.e.output)
        for key in sorted(self.definitions):
            self.set_value(key, self.definitions[key]["initial"])
        self.initialization = [start, len(self.e.output)]

    def clear(self):
        start = len(self.e.output)
        for slot in self.slots.values():
            self.e.output.extend(b"\x08\x15" + struct.pack("<H", slot))
        self.cleanup = [start, len(self.e.output)]

    def report(self):
        return dict(schema="fvp-native-chapter-story-state/1",
            variables=deepcopy(self.definitions), slots=dict(self.slots),
            initialization=self.initialization, cleanup=self.cleanup,
            address_base=self.address_base, allocation="shared_scene_private_volatile_tail",
            reset_on_scene_entry=False, original_variable_slots_unchanged=True,
            non_volatile_globals_unchanged=True, cleared_at_final_exit=self.cleanup is not None,
            integer_range=[-INT_LIMIT, INT_LIMIT], integer_add_policy="saturate",
            runtime_verified=False, save_load_verified=False, rewind_verified=False)
