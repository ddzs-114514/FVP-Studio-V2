"""Own one contiguous, beat-local current-buffer motion launch.

Only absolute XY with S2/Z needs this resolver. No body, camera, alpha,
dialogue, choice boundary or second launch may be hidden in a motion group.
"""
from .gui_runtime import ID_RE


def bind_motion_groups(events, groups, occupied=()):
    if not isinstance(groups, list):
        raise ValueError('普通同拍运动的提交组必须是列表。')
    starts, consumed, used, beats = {}, {}, set(occupied), set()
    for group in groups:
        if not isinstance(group, dict) or set(group) != {'beat_id', 'action_indexes'}:
            raise ValueError('普通同拍运动缺少明确的节拍身份。')
        beat, indexes = group['beat_id'], group['action_indexes']
        if (not isinstance(beat, str) or not ID_RE.fullmatch(beat) or beat in beats
                or not isinstance(indexes, list) or not 2 <= len(indexes) <= 16
                or any(type(i) is not int or not 0 <= i < len(events) or i in used for i in indexes)
                or indexes != list(range(indexes[0], indexes[-1] + 1))):
            raise ValueError('普通同拍运动不能重复、跨台词、跨分支或跨另一提交组。')
        channels = {}
        for index in indexes:
            event = events[index]
            if (event.get('kind') not in {'GuiActorMove', 'Action'}
                    or type(event.get('actor')) is not int or not 1 <= event['actor'] <= 4):
                raise ValueError('普通同拍运动只接已在场角色的移动、缩放、景深和倾斜。')
            raw = event.get('channels', '')
            if event['kind'] == 'Action' and not isinstance(raw, str):
                raise ValueError('普通同拍运动的通道需要明确的文字定义。')
            names = ['xy'] if event['kind'] == 'GuiActorMove' else raw.split('+')
            allowed = {'xy'} if event['kind'] == 'GuiActorMove' else {'s2', 'z', 'r'}
            if not names or set(names) - allowed or len(names) != len(set(names)):
                raise ValueError('普通同拍运动不能包含透明度、表情或未知通道。')
            own = channels.setdefault(event['actor'], set())
            if own.intersection(names):
                raise ValueError('普通同拍运动的同一角色同一通道不能重复。')
            own.update(names)
        if not any('xy' in row and row.intersection({'s2', 'z'}) for row in channels.values()):
            raise ValueError('普通运动提交组需要明确的移动加缩放或景深。')
        starts[indexes[0]] = [events[i] for i in indexes]
        consumed.update((i, indexes[0]) for i in indexes[1:])
        used.update(indexes)
        beats.add(beat)
    return starts, consumed
