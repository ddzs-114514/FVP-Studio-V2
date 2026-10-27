"""Target-owned persistent R/vertical workers, not finite dialogue waits."""
from copy import deepcopy
import struct

from .gui_actor_sway import START, STOP, NOD, event_values, validate_events, contract
from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_cg_motion_stop_binding import NativeCGMotionStopBinding
from .native_portrait_motion import NativePortraitMotion, _converted_coordinate
from .portrait_emitter import _encode_push
from .gui_actor_nod import PIXEL_UNITS, SCRIPT_UNITS


def _script_y_destination(base, amplitude, factor):
    """Offset in the bound XY wrapper's units, preserving its f32/truncate rule."""
    if factor == 1:
        return base + amplitude
    logical = _converted_coordinate(base, factor)
    endpoint = struct.unpack('<f', struct.pack('<f', logical + amplitude))[0]
    converted = struct.unpack('<f', struct.pack('<f', endpoint * factor))[0]
    return int(converted)


class NativePortraitSway:
    def __init__(self, target, owner, events, output, rotation):
        validate_events(events)
        starts = [dict(e, axis='y') if e['kind'] == NOD else e for e in events if e['kind'] in {START, NOD}]
        self.nod_actors = {e['actor'] for e in starts if e['kind'] == NOD}
        self.nod_primitives = {}
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
        if any(e['kind'] == NOD and e.get('duration_mode') == 'original' for e in starts):
            required['V3DMotionTest'] = 0
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
            paired = axis == 'y' and actor in self.nod_actors
            cells = owner.snapshot_storage.reserve_private(4 if paired else 2,
                'portrait_sway_' + str(actor) + '_' + axis)['private_global_ids']
            self.rows[self.row_key(actor, axis)] = dict(slot=slot, flag=cells[0], primitive=cells[1],
                axis=axis, channel='xy' if axis == 'y' else 'r')
            if paired:
                self.rows[self.row_key(actor, axis)].update(peer_flag=cells[2], peer_primitive=cells[3])
            for cell in cells:
                output.extend(b'\x08' + _pop_global(cell))
        owner.guard.bind_motion_loops({channel: [pair
            for r in self.rows.values() if r['channel'] == channel
            for pair in ([(r['flag'], r['primitive'])] +
                         ([(r['peer_flag'], r['peer_primitive'])] if 'peer_flag' in r else []))]
            for channel in channels})
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
        for actor in self.nod_actors:
            pair = portraits.loader.assignments[portraits.actors[actor]].evidence['dispatcher_handles']['primitive_ids']
            if len(pair) != 2 or len(set(pair)) != 2 or any(type(p) is not int for p in pair):
                raise ValueError('点头尚未证明本目标角色的两套独立立绘缓冲。')
            self.nod_primitives[actor] = tuple(pair)
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
        if event['kind'] in {START, NOD}:
            self.start(fields, finite=event['kind'] == NOD)
        else:
            self.stop(fields)

    def start(self, e, *, finite=False):
        actor = e['actor']
        axis = 'y' if finite else e.get('axis', 'r')
        self.join_finite(actor)
        key = self.row_key(actor, axis)
        if actor in self.active or actor not in self.portraits.states or key not in self.rows:
            raise ValueError('摇摆角色尚未入场，或已经在摇摆。')
        for a, channel in list(self.portraits.pending):
            if a == actor and channel != 'parts':
                self.portraits.join(actor, channel)
        state = self.portraits.states[actor]
        amp = e['amplitude'] * (1 if finite else e['direction'])
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
            units = e.get('amplitude_units', PIXEL_UNITS) if finite else PIXEL_UNITS
            if units == SCRIPT_UNITS:
                factor = self.motion.xy_factors['y']
                first = (base[0], _script_y_destination(base[1], amp, factor))
                second = base  # Finite nod has no upward overshoot.
            else:
                geometry = self.portraits.geometry
                x, y = geometry.editor_position(state)
                origin_y = geometry.native_xy(state, x, y)[1]
                first = (base[0], base[1] + geometry.native_xy(state, x, y + amp)[1] - origin_y)
                second = (base[0], base[1] + geometry.native_xy(state, x, y - amp)[1] - origin_y)
            destinations = (first, base) if finite else (first, base, second, base)
            if any(type(v) is not int or not -32768 <= v <= 32767
                   for point in destinations for v in point):
                raise ValueError('上下往复极值超出原生坐标范围，请减小幅度或调整位置。')
            detail = dict(starting_XY=list(base), native_extremes=[list(first), list(second)],
                amplitude_units=units, original_scale_preserved=True)
            if units == SCRIPT_UNITS:
                detail['script_y_factor'] = factor
        primitive = _push_global(row['primitive'])
        operands = [primitive]
        if finite:
            if actor not in self.nod_primitives or 'peer_primitive' not in row:
                raise ValueError('点头缺少已绑定的角色双缓冲。')
            operands.append(_push_global(row['peer_primitive']))
            destinations = (first, base)
        # Skip the callback body on the authored scene's main path.
        skip = self.branch(6)
        entry = self.address
        self.output.extend(b'\x01\0\0')
        cycle = self.address
        finished = []
        def emit_legs(duration):
            previous = base
            for destination in destinations:
                self.output.extend(_push_global(row['flag']) + b'\x09\x22')
                finished.append(self.branch(7))
                if axis == 'r':
                    payload = self.motion.compile('r', primitive,
                        (None, destination, duration, e['curve'], True), allow_current_rotation=True)
                else:
                    # Preserve explicit exact endpoints through the target's
                    # XY conversion; Nil is not assumed to mean current XY.
                    points = (*previous, *destination)
                    if self.motion.xy_converted:
                        fx, fy = self.motion.xy_factors['x'], self.motion.xy_factors['y']
                        points = tuple(_converted_coordinate(v, f)
                            for v, f in zip(points, (fx, fy, fx, fy)))
                    payload = b''.join(self.motion.compile('xy', operand,
                        (*points, duration, e['curve'], True)) for operand in operands)
                self.output.extend(payload)
                for operand in operands:
                    self.wait_motion(operand, row['channel'])
                previous = destination

        if finite and e.get('duration_mode') == 'original':
            if self.table.get('V3DMotionTest', (None, None))[1] != 0:
                raise ValueError('原作点头自动时长尚未绑定目标V3DMotionTest。')
            self.output.extend(self.syscall('V3DMotionTest') + b'\x14')
            idle = self.branch(7)
            emit_legs(250)
            finish_moving = self.branch(6)
            self.patch(idle)
            emit_legs(225)
            self.patch(finish_moving)
            detail['original_timing_sample'] = 'worker_start_once'
        else:
            emit_legs(e['duration_ms'] // 2 if finite else e['period_ms'] // 4)
        if not finite:
            self.output.extend(b'\x06' + struct.pack('<I', cycle))
        for pos in finished:
            self.patch(pos)
        if finite:
            self.output.extend(b'\x08' + _pop_global(row['flag']) + b'\x08' + _pop_global(row['peer_flag']))
        self.output.extend(b'\x04')
        self.patch(skip)
        self.output.extend(self.portraits.prim(actor) + _pop_global(row['primitive']))
        if finite:
            # The slot proof identifies exactly two carriers. Select the other
            # from the runtime current carrier, never a hard-coded game id.
            self.output.extend(self.push(sum(self.nod_primitives[actor])) + primitive + b'\x1b'
                + _pop_global(row['peer_primitive']) + b'\x09' + _pop_global(row['peer_flag']))
        self.output.extend(b'\x09' + _pop_global(row['flag']))
        self.output.extend(self.syscall('ThreadStart', self.push(row['slot']), self.push(entry)))
        self.active[actor] = dict(loop_id=e.get('loop_id'), axis=axis, base=base, finite=finite)
        self.operations.append(dict(kind=NOD if finite else START, **(e | detail), worker_entry=entry,
            worker_slot=row['slot'], captured_current_buffer=True, finite_join_registered=finite,
            paired_buffers=finite, smooth_return=finite))

    def join_finite(self, actor=None):
        for a, active in list(self.active.items()):
            if not active.get('finite') or actor is not None and a != actor:
                continue
            row = self.rows[self.row_key(a, active['axis'])]
            start = self.address
            self.output.extend(_push_global(row['flag']) + b'\x09\x22')
            done = self.branch(7)
            self.output.extend(self.syscall('ThreadNext') + b'\x06' + struct.pack('<I', start))
            self.patch(done)
            del self.active[a]

    def before_event(self, event):
        kind = event['kind']
        if kind in {'Text', 'Speech', 'GuiVoiceLine', 'CameraShot', 'GuiBGM', 'GuiSE'}:
            return  # A finite gesture may finish naturally while dialogue runs.
        actor = event.get('portrait', {}).get('actor') if kind == 'GuiActorSwap' else event.get('actor')
        if actor is not None:
            if kind == 'Action' and event.get('channels') == 'parts':
                return
            self.join_finite(actor)
        else:
            self.join_finite()  # Wait, branch, scene, CG and full-screen changes.

    def cancel(self, row):
        # Explicitly separate resubmit permission, worker lifetime and native
        # trajectory lifetime. ThreadExit alone does not stop native motion.
        self.output.extend(b'\x08' + _pop_global(row['flag']))
        self.output.extend(self.syscall('ThreadExit', self.push(row['slot'])))
        name = 'MotionMoveRStop' if row['channel'] == 'r' else 'MotionMoveStop'
        self.output.extend(self.syscall(name, _push_global(row['primitive'])))
        if 'peer_flag' in row:
            self.output.extend(_push_global(row['peer_flag']) + b'\x09\x22')
            skip = self.branch(7)
            self.output.extend(b'\x08' + _pop_global(row['peer_flag']))
            self.output.extend(self.syscall(name, _push_global(row['peer_primitive'])))
            self.patch(skip)

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
        self.join_finite()
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
