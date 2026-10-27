"""Persistent actor rotation / vertical movement, stopped at an authored beat.

This is an authored contract, not a claim that original ThreadExit resets R.
Only the paired, target-bound native exporter may lower these events.
"""
from copy import deepcopy
import math
import re
from .gui_actor_nod import KIND as NOD, values as nod_values

START = 'GuiActorSwayStart'
STOP = 'GuiActorSwayStop'
KINDS = {START, STOP, NOD}
ID = re.compile(r'[A-Za-z0-9_-]{1,160}\Z')


def _id(value, label):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError(label + '不合法。')
    return value


def authored(action):
    p = action.get('p')
    if not isinstance(p, dict) or set(p) != {'axis', 'dir', 'amp', 'periodMs', 'stopBeat'}:
        raise ValueError('摇摆须指定方向、幅度、周期以及停止节拍。')
    axis = p['axis']
    if axis not in ('r', 'y') or p['dir'] not in (
            {'left', 'right'} if axis == 'r' else {'up', 'down'}):
        raise ValueError('左右倾斜请选择左／右，上下往复请选择上／下。')
    maximum = 15 if axis == 'r' else 120
    if (type(p['amp']) not in (int, float) or not math.isfinite(p['amp'])
            or not 1 <= p['amp'] <= maximum):
        raise ValueError('左右摇摆幅度须为 1～15 度。' if axis == 'r'
                         else '上下往复幅度须为 1～120 编辑像素（1280×720 基准）。')
    if type(p['periodMs']) is not int or not 400 <= p['periodMs'] <= 6000 or p['periodMs'] % 4:
        raise ValueError('完整往返周期须为 400～6000ms，并能被 4 整除。')
    if type(action.get('dur')) is not int or action['dur'] != 0 or action.get('curve') not in (2, 3):
        raise ValueError('持续摇摆的动作时长须为 0，使用周期和停止节拍控制；曲线为 2 或 3。')
    _id(p['stopBeat'], '停止节拍')
    return deepcopy(p)


def plan_tracks(beats):
    """Every loop is balanced within its own linear track, before branching.

    Expressions may coexist. Transform/body changes must be at or after the
    stop beat so no old worker can resubmit against an obsolete physical slot.
    """
    stops, starts, ids = {}, {}, set()

    def visit(track, depth=0):
        from .native_scene_choice_structure import MAX_NESTING
        if depth > MAX_NESTING:
            raise ValueError('摇摆所在分支超过当前支持的嵌套层数。')
        if not isinstance(track, list):
            raise ValueError('摇摆所在节拍轨道不是数组。')
        positions = {}
        for i, beat in enumerate(track):
            if not isinstance(beat, dict):
                raise ValueError('摇摆所在节拍必须为对象。')
            bid = _id(beat.get('id'), '节拍 ID')
            if bid in ids:
                raise ValueError('摇摆停止位置要求各分支节拍 ID 唯一。')
            ids.add(bid)
            positions[bid] = i
            if not isinstance(beat.get('actions'), list) or any(not isinstance(a, dict) for a in beat['actions']):
                raise ValueError('节拍动作必须是对象数组。')
        spans = []
        for i, beat in enumerate(track):
            for action in beat.get('actions', []):
                if action.get('type') != 'sway':
                    continue
                p = authored(action)
                aid, target = _id(action.get('id'), '摇摆动作 ID'), _id(action.get('target'), '摇摆角色')
                end = positions.get(p['stopBeat'], -1)
                if end <= i:
                    raise ValueError('摇摆停止位置必须在同一条轨道的后续节拍，不能指向自己、前一拍或另一分支。')
                if aid in starts:
                    raise ValueError('摇摆动作 ID 重复。')
                for b in track[i:end]:
                    if b.get('kind') not in {'line', 'wait'}:
                        raise ValueError('进入选项或整幕转场前须停止摇摆，不能让循环跨分支或场景。')
                    for other in b.get('actions', []):
                        if other is action:
                            continue
                        if (other.get('type') in {'cg', 'cgxf', 'cgexit', 'enter', 'exit', 'swap'} or
                                other.get('target') == target and other.get('type') != 'expr'):
                            raise ValueError('摇摆期间同角色只能切表情；角色入场、换装、退场请先停止摇摆。')
                if any(t == target and i < e and s < end for s, e, t in spans):
                    raise ValueError('同一角色不能同时运行两条摇摆。')
                spans.append((i, end, target))
                starts[aid] = p
                stops.setdefault(p['stopBeat'], []).append(dict(action_id=aid, target=target))
            if beat.get('kind') == 'choice':
                options = beat.get('options')
                if not isinstance(options, list) or any(not isinstance(o, dict) for o in options):
                    raise ValueError('选项必须是对象数组。')
                for option in options:
                    if 'beats' in option:
                        visit(option['beats'], depth+1)
    visit(beats)
    return dict(starts=starts, stops=stops)


def event_values(kind, fields):
    if kind == NOD:
        return nod_values(fields)
    allowed = {'actor', 'loop_id'} | ({'amplitude', 'direction', 'period_ms', 'curve'} if kind == START else set())
    # Old internal R events omitted axis. Keep them readable, while every new
    # event explicitly identifies its units (native R versus editor Y pixels).
    optional = {'axis'} if kind == START else set()
    if (kind not in KINDS or not isinstance(fields, dict)
            or not allowed <= set(fields) or set(fields) - allowed - optional):
        raise ValueError('原生摇摆事件字段不完整。')
    if type(fields['actor']) is not int or not 1 <= fields['actor'] <= 4:
        raise ValueError('摇摆角色槽不合法。')
    _id(fields['loop_id'], '摇摆 ID')
    if kind == START:
        axis, amplitude = fields.get('axis', 'r'), fields['amplitude']
        if axis not in ('r', 'y'):
            raise ValueError('摇摆轴只能是左右倾斜或上下位移。')
        if axis == 'r':
            if type(amplitude) is not int or not 1 <= amplitude <= 1000:
                raise ValueError('摇摆原生角度幅度超出已绑定范围。')
        elif (type(amplitude) not in (int, float) or not math.isfinite(amplitude)
                or not 1 <= amplitude <= 120):
            raise ValueError('上下往复幅度须为 1～120 编辑像素。')
        if type(fields['direction']) is not int or fields['direction'] not in (-1, 1):
            raise ValueError('摇摆初始方向不合法。')
        if (type(fields['period_ms']) is not int or not 400 <= fields['period_ms'] <= 6000
                or fields['period_ms'] % 4 or type(fields['curve']) is not int or fields['curve'] not in (2, 3)):
            raise ValueError('摇摆周期或曲线不合法。')
    return deepcopy(fields)


def validate_events(events):
    active = {}
    for event in events:
        kind = event['kind']
        if kind in KINDS:
            e = event_values(kind, {k: v for k, v in event.items() if k != 'kind'})
            a = e['actor']
            if kind == NOD:
                if a in active:
                    raise ValueError('同一角色请先停止持续摇摆，再点头。')
                continue
            if kind == START:
                if a in active:
                    raise ValueError('同角色摇摆重叠。')
                active[a] = e['loop_id']
            elif active.pop(a, None) != e['loop_id']:
                raise ValueError('停止事件没有匹配当前角色的摇摆。')
            continue
        if not active:
            continue
        if kind in {'Scene', 'End', 'Transition', 'GuiNativeChapterExit', 'Portrait', 'Hide', 'GuiActorSwap'} or kind.startswith(('GuiChoice', 'Choice', 'GuiCG')):
            raise ValueError('摇摆必须在分支、CG、转场或场景边界之前明确停止。')
        actor = event.get('portrait', {}).get('actor') if kind == 'GuiActorSwap' else event.get('actor')
        if actor in active and not (kind == 'Action' and event.get('channels') == 'parts'):
            raise ValueError('摇摆期间同角色只允许表情动作。')
    if active:
        raise ValueError('摇摆缺少停止事件。')


def contract():
    return dict(schema='fvp-gui-actor-sway/1', axes=['r', 'y'], persistent_across_dialogue=True,
        stop_at='before_selected_future_beat_actions_and_text', return_to='starting_pose',
        return_to_by_axis=dict(r='starting_angle', y='starting_position'),
        direction_by_axis=dict(r=['left', 'right'], y=['up', 'down']),
        amplitude_pixels=[1, 120], amplitude_pixel_viewport=[1280, 720],
        same_actor_simultaneous_axes=False,
        vertical_scale_changes=False, vertical_reset='target_native_PrimSetXY',
        reset_assignment_ms=1, reset_assignment_ms_by_axis=dict(r=1, y=0),
        authored_duration_ms=0, period_ms=[400, 6000],
        amplitude_degrees=[1, 15], same_actor_parallel=['expr'], cross_track=False,
        stop_before_actor_load_swap_exit=True,
        paired_native_state_required=True, target_binding_required=True, runtime_verified=False)
