"""Private CG-owned snapshot cells, not an inherited/scheduler ownership grant.

All original write-state cells are retained; large snapshots must not consume
the thread's finite expression stack throughout the scene. Each save/restore
uses one transient value, with distinct cells for each authored snapshot. Only
the private whole-scene image may extend its native volatile-global header.
"""
from copy import deepcopy
import hashlib

from .hoshimemo_scene_hook import _push_global,_pop_global
from .native_cg_thread_handoff import NativeCGThreadHandoff

SCHEMA = "fvp-native-cg-snapshot-storage/1"


class NativeCGSnapshotStorage:
    def __init__(self,handoff):
        if not isinstance(handoff,NativeCGThreadHandoff):
            raise ValueError("CG 状态暂存必须使用同一场景的原生交接绑定。")
        self.handoff = handoff
        self.base = handoff.total_globals+int(bool(handoff.roots))
        self.groups = []

    @property
    def additional_volatile(self):
        return int(bool(self.handoff.roots))+sum(len(g["private_global_ids"]) for g in self.groups)

    def validate(self,handoff=None):
        if handoff is not None and handoff is not self.handoff:
            raise ValueError("CG 状态暂存不属于当前原生场景。")
        self.handoff.validate()
        expected = self.handoff.total_globals+int(bool(self.handoff.roots))
        if expected != self.base:
            raise ValueError("CG 状态暂存的原变量边界已经变化。")
        for group in self.groups:
            ids = group["private_global_ids"]
            if ids != list(range(expected,expected+len(ids))):
                raise ValueError("CG 状态暂存变量重复或越过已分配范围。")
            expected += len(ids)
        if expected > 0x8000 or self.handoff.source.header.volatile_globals+self.additional_volatile > 0x7fff:
            raise ValueError("CG 状态暂存超出本机原生 signed-word 变量范围。")

    def reserve(self,snapshot,scope):
        self.validate()
        ids = snapshot["report"]["global_ids"]
        if (not isinstance(scope,str) or not scope or any(g["scope"] == scope for g in self.groups)
                or any(type(g) is not int or not 0 <= g < self.handoff.total_globals for g in ids)
                or ids != sorted(set(ids))
                or snapshot["snapshot"] != b"".join(_push_global(g) for g in ids)
                or snapshot["restore"] != b"".join(_pop_global(g) for g in reversed(ids))):
            raise ValueError("CG 状态暂存没有完整匹配本场景的原生快照。")
        start = self.handoff.total_globals+self.additional_volatile
        private = list(range(start,start+len(ids)))
        if private and private[-1] > 0x7fff:
            raise ValueError("CG 状态暂存没有可用的原生变量位置。")
        group = dict(scope=scope,source_global_ids=list(ids),private_global_ids=private)
        self.groups.append(group)
        try:
            self.validate()
        except ValueError:
            self.groups.pop()
            raise
        save = b"".join(_push_global(source)+_pop_global(target) for source,target in zip(ids,private))
        restore = b"".join(_push_global(target)+_pop_global(source)+b"\x08"+_pop_global(target)
                           for source,target in reversed(list(zip(ids,private))))
        report = deepcopy(snapshot["report"])
        report.update(storage=SCHEMA,private_global_ids=private,operand_stack_value_count=0,
            maximum_transient_operand_values=int(bool(ids)),all_original_snapshot_values_preserved=True,
            header_unchanged=False,private_cells_cleared_after_restore=True,
            exclusive_authored_scene_owner_required=True,concurrent_or_reentrant_ownership_proven=False,
            code_sha256={n:hashlib.sha256(c).hexdigest() for n,c in (("snapshot",save),("restore",restore))})
        return dict(snapshot=save,restore=restore,report=report)

    def reserve_private(self,count,scope):
        """Allocate persistent journal cells without borrowing original globals."""
        self.validate()
        if (type(count) is not int or not 1 <= count <= 1024
                or not isinstance(scope,str) or not scope
                or any(g["scope"] == scope for g in self.groups)):
            raise ValueError("CG 私有记录变量的数量或用途无效。")
        start = self.handoff.total_globals+self.additional_volatile
        group = dict(scope=scope,source_global_ids=[],
                     private_global_ids=list(range(start,start+count)),persistent_journal=True)
        self.groups.append(group)
        try:
            self.validate()
        except ValueError:
            self.groups.pop()
            raise
        return deepcopy(group)

    def report(self):
        self.validate()
        return dict(schema=SCHEMA,groups=deepcopy(self.groups),additional_volatile_globals=self.additional_volatile,
            original_global_ids_unchanged=True,all_original_snapshot_values_preserved=True,
            maximum_transient_operand_values=int(any(g["private_global_ids"] for g in self.groups)),
            native_allocation_bound_by_scene_assembler_required=True,
            concurrent_or_reentrant_ownership_proven=False,runtime_verified=False,scene_export_connected=False)
