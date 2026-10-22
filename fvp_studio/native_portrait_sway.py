"""Target-owned persistent R/vertical workers, not finite dialogue waits."""
from copy import deepcopy
import struct

from .gui_actor_sway import START, STOP, event_values, validate_events, contract
from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_cg_motion_stop_binding import NativeCGMotionStopBinding
from .native_portrait_motion import NativePortraitMotion, _converted_coordinate
from .portrait_emitter import _encode_push


class NativePortraitSway:
    def __init__(self, target, owner, events, output, rotation):
        validate_events(events)
        starts = [e for e in events if e['kind'] == START]
        self.axes = {e.get('axis', 'r') for e in starts}
        if (not starts or owner is None or owner.target is not target
                or owner.snapshot_storage is None or owner.guard is None):
            raise ValueError('持续运动需要本目标配对的原生状态和台词保护。')
        if 'r' in self.axes:
            if rotation is None:
                raise ValueError('左右摇摆需要本目标的原生角度换算。')
            rotation.assert_target(target)
        self.target, self.owner, self.output = target, owner, output
        self.source = target.context.document
        self.rotation = rotation
        self.slots = owner.thread_slots
        self.table = self.slots.table
        channels = {'xy' if a == 'y' else 'r' for a in self.axes}
        required = dict(ThreadStart=2, ThreadExit=1, ThreadNext=0)
        if 'r' in channels:
            required.update(MotionMoveRTest=1, MotionMoveRStop=1)
        if 'xy' in channels:
            required.update(MotionMoveTest=1, MotionMoveStop=1, PrimSetXY=3)
        for name, count in required.items():
            if self.table.get(name, (None, None))[1] != count:
                raise ValueError('持续摇摆尚未绑定目标原生接口：' + name)
        self.motion = NativePortraitMotion(self.source, target.context.analysis_document,
            channels, runtime_context=target.context)
        self.current_rotation_proof = self.motion.prove_current_rotation() if 'r' in channels else None
        self.stop_channels = {}
        for channel in channels:
            name = 'MotionMoveRStop' if channel == 'r' else 'MotionMoveStop'
            self.stop_channels[channel] = dict(stop=name, stop_arity=1, stop_syscall_id=self.table[name][0])
        self.stop_binding = NativeCGMotionStopBinding(
            (target.root / target.executable).read_bytes(), self.stop_channels)
        self.rows, self.active, self.operations = {}, {}, []
        for actor, axis in sorted({(e['actor'], e.get('axis', 'r')) for e in starts}):
            # Sequential axes share one worker slot, but have separate active
            # flags so a Y loop cannot bypass an unrelated RTest (or vice versa).
            slot = self.slots.reserve_private('portrait_sway_' + str(actor))
            cells = owner.snapshot_storage.reserve_private(2,
                'portrait_sway_' + str(actor) + '_' + axis)['private_global_ids']
            self.rows[self.row_key(actor, axis)] = dict(slot=slot, flag=cells[0], primitive=cells[1],
                axis=axis, channel='xy' if axis == 'y' else 'r')
            for cell in cells:
                output.extend(b'\x08' + _pop_global(cell))
        owner.guard.bind_motion_loops({channel: [(r['flag'], r['primitive'])
            for r in self.rows.values() if r['channel'] == channel] for channel in channels})
        self.portraits = None

    @staticmethod
    def row_key(actor, axis):
        return str(actor) + ':' + axis

    def bind_portraits(self, portraits):
        if portraits is None or portraits.target is not self.target or portraits.motion is None:
            raise ValueError('持续运动缺少本场景自己的角色和运动包装。')
        primitives = set()
        for binding in portraits.loader.assignments.values():
            primitives.update(binding.evidence['dispatcher_handles']['primitive_ids'])
        self.stop_binding.validate(self.stop_channels, primitives)
        self.portraits, self.motion = portraits, portraits.motion

    @property
    def address(self):
        return len(self.source.original_bytes) + len(self.output)

    def push(self, value):
        return _encode_push(value, self.source.encoding)

    def syscall(self, name, *args):
        ident, count = self.table[name]
        if count != len(args):
            raise ValueError('摇摆原生调用参数不匹配。')
        return b''.join(args) + b'\x03' + struct.pack('<H', ident)

    def patch(self, pos, target=None):
        struct.pack_into('<I', self.output, pos, self.address if target is None else target)

    def branch(self, op):
        self.output.extend(bytes((op,)) + bytes(4))
        return len(self.output) - 4

    def wait_motion(self, primitive, channel):
        # Yield even if a native submission fails/finishes immediately; a
        # private loop may never spin without returning to the VM scheduler.
        start = self.address
        self.output.extend(self.syscall('ThreadNext'))
        name = 'MotionMoveRTest' if channel == 'r' else 'MotionMoveTest'
        self.output.extend(self.syscall(name, primitive) + b'\x14')
        done = self.branch(7)
        self.output.extend(b'\x06' + struct.pack('<I', start))
        self.patch(done)

    def emit(self, event):
        fields = event_values(event['kind'], {k: v for k, v in event.items() if k != 'kind'})
        if self.portraits is None:
            raise ValueError('尚未绑定摇摆角色。')
        if event['kind'] == START:
            self.start(fields)
        else:
            self.stop(fields)

    def start(self, e):
        actor = e['actor']
        axis = e.get('axis', 'r')
        key = self.row_key(actor, axis)
        if actor in self.active or actor not in self.portraits.states or key not in self.rows:
            raise ValueError('摇摆角色尚未入场，或已经在摇摆。')
        for a, channel in list(self.portraits.pending):
            if a == actor and channel != 'parts':
                self.portraits.join(actor, channel)
        state = self.portraits.states[actor]
        amp = e['amplitude'] * e['direction']
        row = self.rows[key]
        if axis == 'r':
            base = state.get('rotation', 0)
            if type(base) is not int or any(not -1000 <= v <= 1000 for v in (base - amp, base + amp)):
                raise ValueError('摇摆极值越过原生旋转范围，请减小初始倾角或幅度。')
            destinations = (base + amp, base, base - amp, base)
            detail = dict(starting_R=base)
        else:
            base = (state['x'], state['y'])
            # Editor-pixel amplitude uses the current native transform, never
            # the imported image height or a size override. Preserve exact raw
            # X and baseline Y rather than round-tripping them through pixels.
            geometry = self.portraits.geometry
            x, y = geometry.editor_position(state)
            origin_y = geometry.native_xy(state, x, y)[1]
            first = (base[0], base[1] + geometry.native_xy(state, x, y + amp)[1] - origin_y)
            second = (base[0], base[1] + geometry.native_xy(state, x, y - amp)[1] - origin_y)
            destinations = (first, base, second, base)
            if any(type(v) is not int or not -32768 <= v <= 32767
                   for point in destinations for v in point):
                raise ValueError('上下往复极值超出原生坐标范围，请减小幅度或调整位置。')
            detail = dict(starting_XY=list(base), native_extremes=[list(first), list(second)],
                amplitude_units='editor_pixels_1280x720', original_scale_preserved=True)
        primitive = _push_global(row['primitive'])
        # Skip the callback body on the authored scene's main path.
        skip = self.branch(6)
        entry = self.address
        self.output.extend(b'\x01\0\0')
        cycle = self.address
        finished = []
        previous = base
        for destination in destinations:
            self.output.extend(_push_global(row['flag']) + b'\x09\x22')
            finished.append(self.branch(7))
            if axis == 'r':
                payload = self.motion.compile('r', primitive,
                    (None, destination, e['period_ms'] // 4, e['curve'], True), allow_current_rotation=True)
            else:
                # No assumed Nil/current-XY semantics: converted original XY
                # wrappers may coerce Nil to zero. Every leg has known endpoints.
                points = (*previous, *destination)
                if self.motion.xy_converted:
                    fx, fy = self.motion.xy_factors['x'], self.motion.xy_factors['y']
                    points = tuple(_converted_coordinate(v, f)
                        for v, f in zip(points, (fx, fy, fx, fy)))
                payload = self.motion.compile('xy', primitive,
                    (*points, e['period_ms'] // 4, e['curve'], True))
            self.output.extend(payload)
            self.wait_motion(primitive, row['channel'])
            previous = destination
        self.output.extend(b'\x06' + struct.pack('<I', cycle))
        for pos in finished:
            self.patch(pos)
        self.output.extend(b'\x04')
        self.patch(skip)
        self.output.extend(self.portraits.prim(actor) + _pop_global(row['primitive']))
        self.output.extend(b'\x09' + _pop_global(row['flag']))
        self.output.extend(self.syscall('ThreadStart', self.push(row['slot']), self.push(entry)))
        self.active[actor] = dict(loop_id=e['loop_id'], axis=axis, base=base)
        self.operations.append(dict(kind=START, **e, **detail, worker_entry=entry,
            worker_slot=row['slot'], captured_current_buffer=True, finite_join_registered=False))

    def cancel(self, row):
        # Explicitly separate resubmit permission, worker lifetime and native
        # trajectory lifetime. ThreadExit alone does not stop native motion.
        self.output.extend(b'\x08' + _pop_global(row['flag']))
        self.output.extend(self.syscall('ThreadExit', self.push(row['slot'])))
        name = 'MotionMoveRStop' if row['channel'] == 'r' else 'MotionMoveStop'
        self.output.extend(self.syscall(name, _push_global(row['primitive'])))

    def stop(self, e):
        actor = e['actor']
        active = self.active.get(actor)
        if active is None or active['loop_id'] != e['loop_id']:
            raise ValueError('停止事件与当前摇摆不匹配。')
        axis = active['axis']
        row = self.rows[self.row_key(actor, axis)]
        self.cancel(row)
        primitive = _push_global(row['primitive'])
        if axis == 'r':
            self.output.extend(self.motion.compile('r', primitive,
                (None, active['base'], 1, 1, True), allow_current_rotation=True))
            self.wait_motion(primitive, 'r')
            self.portraits.states[actor]['rotation'] = active['base']
            detail = dict(restored_R=active['base'], assignment_ms=1)
        else:
            # Commit the exact starting position after stopping the track.
            # A zero-duration MotionMove is not assumed to perform assignment.
            self.output.extend(self.syscall('PrimSetXY', primitive, *(self.push(v) for v in active['base'])))
            self.portraits.states[actor].update(zip(('x', 'y'), active['base']))
            detail = dict(restored_XY=list(active['base']), native_assignment='PrimSetXY')
        self.output.extend(b'\x08' + _pop_global(row['primitive']))
        self.operations.append(dict(kind=STOP, **e, axis=axis, **detail))
        del self.active[actor]

    def finish(self):
        if self.active:
            raise ValueError('场景结束前仍有未停止的摇摆。')
        # Also reachable via the pre-existing animation-abort cleanup label.
        # At that point restore the original native scene, not an authored pose.
        for row in self.rows.values():
            self.output.extend(_push_global(row['flag']) + b'\x09\x22')
            skip = self.branch(7)
            self.cancel(row)
            self.patch(skip)
            self.output.extend(b'\x08' + _pop_global(row['primitive']))

    def report(self):
        return dict(**contract(), operations=deepcopy(self.operations),
            native_stop_binding=self.stop_binding.report(),
            source_thread_ids_not_reused=True, native_global_loop_flags_reused=False,
            compiled_axes=sorted(self.axes),
            current_rotation_argument_proven=self.current_rotation_proof is not None,
            vertical_start_arguments='explicit_native_endpoints', private_workers=deepcopy(self.rows),
            dialogue_wait_bypass='only_active_captured_primitive_and_channel', compiled=True)
