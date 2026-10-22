"""Restore original native visual commands after an authored CG scene.

The journal starts with the original script, not with the authored scene.
Arguments are retained as VM values, including Nil, strings and floats. Native
creation, geometry and group commands are replayed in their original order:
collapsing these to a parent map would lose sibling order and kind changes.
This is command restoration, not a pixel snapshot or an asynchronous-motion
snapshot. It deliberately does not replay dialogue, sounds or movie commands.
"""
from copy import deepcopy
import struct

from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_cg_original_graph_journal import NativeCGOriginalGraphJournal
from .portrait_emitter import _encode_push


SCHEMA = 'fvp-native-cg-original-stage-journal/1'
VISUAL_CALLS = {
    'GraphLoad':2,
    'PrimSetNull':1, 'PrimSetGroup':1, 'PrimSetSprt':4, 'PrimSetTile':6,
    'PrimSetText':4, 'PrimSetXY':3, 'PrimSetWH':3, 'PrimSetUV':3,
    'PrimSetZ':2, 'PrimSetRS':3, 'PrimSetRS2':4, 'PrimSetOP':3,
    'PrimSetAlpha':2, 'PrimSetDraw':2, 'PrimSetClip':1,
    'PrimGroup':2, 'PrimGroupIn':2, 'PrimGroupOut':1, 'PrimGroupMove':2,
    'GraphRGB':4, 'PartsLoad':2, 'PartsAssign':2, 'PartsSelect':2,
    'PartsRGB':4, 'ColorSet':5,
    'V3DSet':3, 'MotionPause':2, 'PartsMotionPause':2,
}


class NativeCGOriginalStageJournal(NativeCGOriginalGraphJournal):
    def __init__(self,handoff,storage,graphs,*,authored_primitives=()):
        visual = {name:handoff.table[name] for name,argc in VISUAL_CALLS.items()
                  if name in handoff.table}
        if not visual or any(row[1] != VISUAL_CALLS[name] for name,row in visual.items()):
            raise ValueError('原剧情画面恢复需要本目标自己的图层操作参数。')
        authored_primitives = tuple(sorted(set(authored_primitives)))
        if (any(type(p) is not int or not 0 < p < 0x8000 for p in authored_primitives)
                or authored_primitives and visual.get('PrimGroupOut',(None,None))[1] != 1):
            raise ValueError('CG 原剧情恢复没有可用的本目标图层移出入口。')
        super().__init__(handoff,storage,graphs,observed_syscalls=tuple(visual))
        self.visual_calls = visual
        self.authored_primitives = authored_primitives
        self.width = 1+max(row[1] for row in visual.values())
        cells = storage.reserve_private(2,'original_visual_command_journal')
        self.stage_ids = tuple(cells['private_global_ids'])
        self.count_slot,self.commands_slot = self.stage_ids
        self._stage_identity = deepcopy((visual,authored_primitives,self.width,self.stage_ids))

    @property
    def startup(self):
        # Called only by the new native entry, never after a scene returns.
        return (self.resume+_encode_push(0,self.handoff.source.encoding)
                +_pop_global(self.count_slot)+b'\x08'+_pop_global(self.commands_slot))

    def validate(self):
        super().validate()
        # Base construction calls validate before these cells are reserved.
        if not hasattr(self,'_stage_identity'):
            return
        actual = (self.visual_calls,self.authored_primitives,self.width,self.stage_ids)
        group = next((g for g in self.storage.groups
                      if g['scope']=='original_visual_command_journal'),None)
        if (actual != self._stage_identity or group is None
                or tuple(group['private_global_ids']) != self.stage_ids
                or (self.count_slot,self.commands_slot) != self.stage_ids
                or any(self.handoff.table.get(name) != row for name,row in self.visual_calls.items())):
            raise ValueError('原剧情画面记录的参数、变量或原生入口已经变化。')

    def _prepare_recorders(self,base):
        code,report = super()._prepare_recorders(base)
        h = self.handoff
        integer = lambda value:_encode_push(value,h.source.encoding)
        stack = lambda value:b'\x10'+struct.pack('<b',value)
        syscall = lambda ident:b'\x03'+struct.pack('<H',ident)
        read_table = b'\x11'+struct.pack('<H',self.commands_slot)
        write_table = b'\x17'+struct.pack('<H',self.commands_slot)
        def jump(op):
            at = len(code)
            code.extend(bytes((op,))+b'\0'*4)
            return at
        def target(at,offset):
            struct.pack_into('<I',code,at+1,base+offset)
        def write(column,value):
            code.extend(_push_global(self.count_slot)+integer(self.width)+b'\x1c')
            if column:
                code.extend(integer(column)+b'\x1a')
            code.extend(value+write_table)
        def read(column):
            code.extend(stack(0)+integer(self.width)+b'\x1c')
            if column:
                code.extend(integer(column)+b'\x1a')
            code.extend(read_table)

        for name,(ident,argc) in sorted(self.visual_calls.items(),key=lambda item:item[1][0]):
            entry = base+len(code)
            report['syscall_recorders'][name] = dict(id=ident,args=argc,entry=entry)
            code.extend(bytes((1,argc,0)))
            for n in range(argc):
                code.extend(stack(n-argc-1))
            native = _call(report['recorder_entry']) if name=='GraphLoad' else syscall(ident)
            code.extend(native+b'\x14')  # Keep the real native return value.
            code.extend(_push_global(self.pause_slot))
            record = jump(7)
            paused = jump(6)
            target(record,len(code))
            foreign_graph = None
            if name == 'GraphLoad':
                # The authored scene only overwrites its declared image slots.
                # Keeping every menu/UI filename alive exhausts FVP's small
                # VM string pool before the title screen (128 on modern FVP).
                # Still execute/forward every native call; omit only its
                # unrelated restoration record, as the base journal does.
                owned = []
                for graph in self.graphs:
                    code.extend(stack(-argc-1)+integer(graph)+b'\x22')
                    different = jump(7)
                    owned.append(jump(6))
                    target(different,len(code))
                foreign_graph = jump(6)
                for branch in owned:
                    target(branch,len(code))
            # Also tolerate the native Nil initialization on a direct entry.
            code.extend(_push_global(self.count_slot)+b'\x08\x22')
            initialized = jump(7)
            code.extend(integer(0)+_pop_global(self.count_slot))
            target(initialized,len(code))
            write(0,integer(ident))
            for n in range(argc):
                write(1+n,stack(n-argc-1))
            code.extend(_push_global(self.count_slot)+integer(1)+b'\x1a'+_pop_global(self.count_slot))
            target(paused,len(code))
            if foreign_graph is not None:
                target(foreign_graph,len(code))
            code.extend(b'\x05')

        graph_restore = report['restore_entry']
        restore = base+len(code)
        code.extend(b'\x01\0\x01')  # One transient local replay cursor.
        # Remove authored links first. This avoids leaving hidden CG children
        # attached between the original siblings when GroupIn appends at tail.
        if self.authored_primitives:
            out_id = self.visual_calls['PrimGroupOut'][0]
            for primitive in self.authored_primitives:
                code.extend(integer(primitive)+syscall(out_id))
        # GraphLoad is part of the same history. Loading its last request here
        # first would issue it twice and disturb load/unload/RGB ordering.
        code.extend(integer(0)+b'\x16\0')
        loop = len(code)
        code.extend(stack(0)+_push_global(self.count_slot)+b'\x26')
        done = jump(7)
        advance = []
        for name,(ident,argc) in sorted(self.visual_calls.items(),key=lambda item:item[1][0]):
            read(0)
            code.extend(integer(ident)+b'\x22')
            other = jump(7)
            for n in range(argc):
                read(1+n)
            code.extend(syscall(ident))
            advance.append(jump(6))
            target(other,len(code))
        for at in advance:
            target(at,len(code))
        code.extend(stack(0)+integer(1)+b'\x1a\x16\0')
        back = jump(6)
        target(back,loop)
        target(done,len(code))
        code.extend(b'\x04')
        report.update(restore_entry=restore,original_graph_restore_entry=graph_restore,
            original_stage_restore_entry=restore,original_stage_command_restore_emitted=True,
            native_creation_and_property_order_retained=True,
            native_group_command_order_retained=True,
            graph_requests_replayed_in_original_visual_order=True,
            graph_load_recording_scoped_to_authored_slots=list(self.graphs),
            unrelated_UI_resource_strings_retained=False,
            separate_duplicate_graph_reload_emitted=False,
            authored_links_removed_before_original_command_replay=list(self.authored_primitives))
        return code,report

    def report(self):
        result = super().report()
        result.update(schema=SCHEMA,graph_journal_schema=result['schema'],
            visual_calls={name:dict(id=row[0],args=row[1]) for name,row in self.visual_calls.items()},
            command_storage=dict(count_global=self.count_slot,table_global=self.commands_slot,
                record_width=self.width,private_global_ids=list(self.stage_ids)),
            visual_arguments_kept_as_native_values=True,
            native_camera_set_recorded='V3DSet' in self.visual_calls,
            native_pause_requests_recorded=[name for name in ('MotionPause','PartsMotionPause')
                if name in self.visual_calls],
            recording_starts_before_original_script=True,
            author_commands_cannot_overwrite_original_history=True,
            chronological_command_replay_not_parent_map=True,
            original_stage_command_restore_emitted=False,
            engine_motion_snapshot_restored=False,parts_animation_clock_restored=False,
            resource_load_commit_proven=False,pixel_snapshot=False)
        return result
