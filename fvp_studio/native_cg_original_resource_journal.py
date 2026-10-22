"""Bounded resource restoration when the paired native bridge owns scalars.

The native bridge restores geometry, group links, Parts assignment/selection
and motion records directly. Keep only the latest Graph/Parts load and Graph
RGB request for each overwritten slot. UI frame callbacks still run normally,
without creating a growing script table. Reload resources BEFORE the bridge
rebuilds expression pixels; no resource pointers are copied or reused.
"""
from copy import deepcopy
import struct

from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_cg_original_graph_journal import NativeCGOriginalGraphJournal
from .portrait_emitter import _encode_push


class NativeCGOriginalResourceJournal(NativeCGOriginalGraphJournal):
    def __init__(self, handoff, storage, graphs, *, parts=()):
        if handoff.table.get('GraphRGB', (None, None))[1] != 4:
            raise ValueError('原生 CG 资源恢复需要本目标的 GraphRGB 参数。')
        parts = tuple(parts)
        if (len(parts) > 64 or len(set(parts)) != len(parts)
                or any(type(p) is not int or not 0 <= p < 2**31 for p in parts)
                or parts and handoff.table.get('PartsLoad', (None, None))[1] != 2):
            raise ValueError('原生 CG 表情资源恢复需要本目标的 Parts 槽和加载入口。')
        super().__init__(handoff, storage, graphs,
                         observed_syscalls=('GraphRGB', 'PartsLoad') if parts else ('GraphRGB',))
        self.rgb_id = handoff.table['GraphRGB'][0]
        cells = storage.reserve_private(4 * len(self.graphs), 'original_graph_rgb_snapshot')
        ids = cells['private_global_ids']
        self.rgb_slots = {g: dict(known=ids[4*n], values=tuple(ids[4*n+1:4*n+4]))
                          for n, g in enumerate(self.graphs)}
        self._rgb_identity = deepcopy((self.rgb_id, self.rgb_slots))
        self.parts = tuple(sorted(parts))
        self.parts_id = handoff.table['PartsLoad'][0] if parts else None
        self.parts_slots = {}
        if parts:
            cells = storage.reserve_private(2 * len(parts), 'original_parts_load_snapshot')
            ids = cells['private_global_ids']
            self.parts_slots = {p: dict(resource=ids[2*n], known=ids[2*n+1])
                                for n, p in enumerate(self.parts)}
        self._parts_identity = deepcopy((self.parts, self.parts_id, self.parts_slots))

    def validate(self):
        super().validate()
        if not hasattr(self, '_rgb_identity'):
            return
        group = next((g for g in self.storage.groups
                      if g['scope'] == 'original_graph_rgb_snapshot'), None)
        ids = [i for row in self.rgb_slots.values() for i in (row['known'], *row['values'])]
        if (group is None or group['private_global_ids'] != ids
                or (self.rgb_id, self.rgb_slots) != self._rgb_identity
                or self.handoff.table['GraphRGB'] != (self.rgb_id, 4)):
            raise ValueError('原生 CG 资源快照不属于当前目标。')
        if not hasattr(self, '_parts_identity'):
            return
        if (self.parts, self.parts_id, self.parts_slots) != self._parts_identity:
            raise ValueError('原生 CG 表情资源快照的绑定已改变。')
        if self.parts:
            group = next((g for g in self.storage.groups
                          if g['scope'] == 'original_parts_load_snapshot'), None)
            ids = [i for row in self.parts_slots.values() for i in (row['resource'], row['known'])]
            if (group is None or group['private_global_ids'] != ids
                    or self.handoff.table['PartsLoad'] != (self.parts_id, 2)):
                raise ValueError('原生 CG 表情资源快照不属于当前目标。')

    def _prepare_recorders(self, base):
        code, report = super()._prepare_recorders(base)
        h = self.handoff
        integer = lambda v: _encode_push(v, h.source.encoding)
        stack = lambda v: b'\x10' + struct.pack('<b', v)
        syscall = lambda v: b'\x03' + struct.pack('<H', v)
        def jump(op):
            at = len(code)
            code.extend(bytes((op,)) + b'\0' * 4)
            return at
        def target(at, offset):
            struct.pack_into('<I', code, at + 1, base + offset)

        entry = base + len(code)
        code.extend(b'\x01\x04\0')
        for n in range(4):
            code.extend(stack(n - 5))
        code.extend(syscall(self.rgb_id) + b'\x14')
        code.extend(_push_global(self.pause_slot))
        record = jump(7)
        paused = jump(6)
        target(record, len(code))
        finishes = []
        for graph, row in self.rgb_slots.items():
            code.extend(stack(-5) + integer(graph) + b'\x22')
            other = jump(7)
            for n, slot in enumerate(row['values']):
                code.extend(stack(n - 4) + _pop_global(slot))
            code.extend(b'\x09' + _pop_global(row['known']))
            finishes.append(jump(6))
            target(other, len(code))
        target(paused, len(code))
        for branch in finishes:
            target(branch, len(code))
        code.extend(b'\x05')
        report['syscall_recorders']['GraphRGB'] = dict(id=self.rgb_id, args=4, entry=entry)
        if self.parts:
            entry = base + len(code)
            code.extend(b'\x01\x02\0' + stack(-3) + stack(-2) + syscall(self.parts_id) + b'\x14')
            code.extend(_push_global(self.pause_slot))
            record = jump(7)
            paused = jump(6)
            target(record, len(code))
            finishes = []
            for part, row in self.parts_slots.items():
                code.extend(stack(-3) + integer(part) + b'\x22')
                other = jump(7)
                code.extend(stack(-2) + _pop_global(row['resource']))
                code.extend(b'\x09' + _pop_global(row['known']))
                finishes.append(jump(6))
                target(other, len(code))
            target(paused, len(code))
            for branch in finishes:
                target(branch, len(code))
            code.extend(b'\x05')
            report['syscall_recorders']['PartsLoad'] = dict(id=self.parts_id, args=2, entry=entry)
        graph_restore = report['restore_entry']
        restore = base + len(code)
        code.extend(b'\x01\0\0' + _call(graph_restore))
        for graph, row in self.rgb_slots.items():
            code.extend(_push_global(row['known']))
            unknown = jump(7)
            code.extend(integer(graph))
            for slot in row['values']:
                code.extend(_push_global(slot))
            code.extend(syscall(self.rgb_id))
            target(unknown, len(code))
        # The paired native restore owns assignment, expression selection and
        # animation clocks. Only reconstruct the allocated Parts buffers here.
        for part, row in self.parts_slots.items():
            code.extend(_push_global(row['known']))
            unknown = jump(7)
            code.extend(integer(part) + _push_global(row['resource']) + syscall(self.parts_id))
            target(unknown, len(code))
        code.extend(b'\x04')
        report.update(restore_entry=restore, original_graph_restore_entry=graph_restore,
            original_resource_restore_entry=restore,
            bounded_current_resource_snapshot=True,
            scalar_and_group_restore_requires_paired_native_bridge=True,
            chronological_UI_command_table_emitted=False,
            graph_load_recording_scoped_to_authored_slots=list(self.graphs),
            parts_load_recording_scoped_to_authored_slots=list(self.parts),
            resource_snapshot_maximum_retained_strings=len(self.graphs) + len(self.parts))
        return code, report

    def report(self):
        result = super().report()
        result.update(schema='fvp-native-cg-original-resource-journal/1',
            graph_journal_schema=result['schema'], rgb_slots=deepcopy(self.rgb_slots),
            parts_slots=deepcopy(self.parts_slots),
            bounded_current_resource_snapshot=True,
            scalar_and_group_restore_requires_paired_native_bridge=True,
            unrelated_UI_resource_strings_retained=False,
            original_parts_resources_not_replaced=not bool(self.parts),
            parts_resource_requests_restored_before_native_selection=bool(self.parts),
            parts_assignment_selection_restore_requires_paired_native_bridge=bool(self.parts))
        return result
