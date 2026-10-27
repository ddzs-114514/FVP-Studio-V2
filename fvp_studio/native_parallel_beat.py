"""Beat-local launch boundaries for independent native stage channels.

Resources are prepared before this boundary. Only nonblocking motion starts
run inside it; the authored transition/line/wait owns completion. No body or
CG/portrait overlay is manufactured to simulate concurrency.
"""
from .gui_runtime import ID_RE


STAGE_KINDS = {'Action', 'GuiActorMove', 'GuiActorSlide', 'CameraShot',
               'GuiBackgroundBlur', 'Transition'}


def bind_groups(events, groups, *, occupied=(), cg_lines=False):
    if not isinstance(groups, list):
        raise ValueError('同拍提交组必须是列表。')
    starts, consumed, used, beats = {}, {}, set(occupied), set()
    for group in groups:
        if not isinstance(group, dict) or set(group) != {'beat_id', 'action_indexes'}:
            raise ValueError('同拍提交组缺少明确的节拍身份。')
        beat, indexes = group['beat_id'], group['action_indexes']
        if (not isinstance(beat, str) or not ID_RE.fullmatch(beat) or beat in beats
                or not isinstance(indexes, list) or not (2 if cg_lines else 1) <= len(indexes) <= 32
                or any(type(i) is not int or not 0 <= i < len(events) or i in used for i in indexes)
                or indexes != list(range(indexes[0], indexes[-1] + 1))):
            raise ValueError('同拍提交不能重复、跨台词、跨分支或跨另一提交组。')
        rows = [events[i] for i in indexes]
        if cg_lines:
            if len(rows) != 2 or rows[0]['kind'] != 'GuiCGExit' or rows[1]['kind'] not in {'Text', 'Speech', 'GuiVoiceLine'}:
                raise ValueError('CG 退场配台词须是相邻的一次退场和一句台词。')
        else:
            channels = set()
            for pos, event in enumerate(rows):
                kind = event.get('kind')
                if kind not in STAGE_KINDS or kind == 'Transition' and pos != len(rows) - 1:
                    raise ValueError('舞台同拍只接角色运动、镜头、模糊与末尾的整幕转场。')
                if kind in {'Action', 'GuiActorMove', 'GuiActorSlide'}:
                    actor = event.get('actor')
                    if type(actor) is not int or not 1 <= actor <= 4:
                        raise ValueError('同拍动作须引用已准备的角色槽。')
                    raw = event.get('channels')
                    names = (raw.split('+') if isinstance(raw, str) else []) if kind == 'Action' else (
                        ['xy', 'alpha'] if kind == 'GuiActorSlide' else ['xy'])
                    allowed = {'s2', 'z', 'r', 'alpha', 'parts'} if kind == 'Action' else {'xy', 'alpha'}
                    if not names or set(names) - allowed:
                        raise ValueError('同拍角色通道未接通。')
                    keys = [(actor, name) for name in names]
                else:
                    keys = [(kind, None)]
                for key in keys:
                    if key in channels:
                        raise ValueError('同一拍同一对象同一通道不能重复。')
                    channels.add(key)
        starts[indexes[0]] = rows
        consumed.update((i, indexes[0]) for i in indexes[1:])
        used.update(indexes)
        beats.add(beat)
    return starts, consumed


def bind_backgrounds(events, groups):
    """Bind a prepared BG to one launch and its own line/wait completion."""
    if not isinstance(groups, list):
        raise ValueError('同拍背景提交必须是列表。')
    loads, starts, ends, used, beats = {}, {}, {}, set(), set()
    for row in groups:
        if not isinstance(row, dict) or set(row) != {'beat_id', 'background_index', 'launch_index', 'complete_index'}:
            raise ValueError('同拍背景缺少明确的加载、启动、完成边界。')
        b, s, e = (row[k] for k in ('background_index', 'launch_index', 'complete_index'))
        beat = row['beat_id']
        if (not isinstance(beat, str) or not ID_RE.fullmatch(beat) or beat in beats
                or any(type(i) is not int or not 0 <= i < len(events) for i in (b, s, e))
                or not b < s <= e or used.intersection(range(b, e+1))
                or events[b]['kind'] != 'GuiBackgroundChange' or events[b].get('duration_ms', 0) <= 0
                or events[e]['kind'] not in {'Text', 'Speech', 'GuiVoiceLine', 'Wait'}
                or events[s]['kind'] not in (STAGE_KINDS - {'Transition'}) | {'GuiActorSwap', 'Text', 'Speech', 'GuiVoiceLine', 'Wait'}
                or any(v['kind'] not in (STAGE_KINDS - {'Transition'}) | {'Portrait', 'GuiActorSwap'}
                    for v in events[b+1:e])):
            raise ValueError('同拍背景不能跨台词、分支、另一背景或叠加第二条整幕转场。')
        loads[b], starts[s], ends[e] = row, row, row
        used.update(range(b, e+1))
        beats.add(beat)
    return loads, starts, ends


def launch_stage(events, *, portraits=None, camera=None, blur=None, screen=None, background_launch=None):
    """Prepare old state first, start all new tracks, then join if a transition."""
    bind_groups(events, [dict(beat_id='current', action_indexes=list(range(len(events))))])
    actors = [e for e in events if e['kind'] in {'Action', 'GuiActorMove', 'GuiActorSlide'}]
    shot = next((e for e in events if e['kind'] == 'CameraShot'), None)
    soft = next((e for e in events if e['kind'] == 'GuiBackgroundBlur'), None)
    transition = next((e for e in events if e['kind'] == 'Transition'), None)
    if ((actors and portraits is None) or (shot and camera is None)
            or (soft and blur is None) or (transition and screen is None)):
        raise ValueError('同拍动作缺少当前目标对应的原生绑定。')
    # Do not accidentally wait for a new channel while preparing another.
    for owner in (portraits, camera, blur):
        if owner is not None:
            owner.join()
    soft_code = blur.prepare_event(soft) if soft else None
    fade_code = screen.prepare_parallel(transition) if transition else None
    if actors:
        actors = portraits.prepare_slides(actors)
        channels = {}
        for event in actors:
            channels.setdefault(event['actor'], set()).update(
                ['xy'] if event['kind'] == 'GuiActorMove' else event['channels'].split('+'))
        compound = any('xy' in row and row.intersection({'s2', 'z'}) for row in channels.values())
        if compound:
            portraits.motion_batch(actors)
        else:
            for event in actors:
                portraits.emit(event)
    if shot:
        if shot['duration_ms'] == 0 and (screen is None or screen.covered is None):
            raise ValueError('可见镜头运动不能用遮盖内的零时长设置。')
        camera.emit(shot, portraits.states.values() if portraits else ())
    if soft_code is not None:
        blur.output.extend(soft_code)
    elif shot and blur is not None:
        blur.reassert()  # Only old blur exists here, already joined above.
    if fade_code is not None:
        screen.output.extend(fade_code)
        screen.finish_parallel()
        for owner in (portraits, camera, blur):
            if owner is not None:
                owner.join()
    if background_launch is not None:
        if transition is not None or screen is None:
            raise ValueError('背景渐变不能再叠加第二条整幕转场。')
        screen.output.extend(background_launch)
    return dict(native_parallel_stage=True, launch_before_first_new_wait=True,
        event_kinds=[e['kind'] for e in events], source_size_rule_changed=False,
        runtime_verified=False)


def contract():
    return dict(schema='fvp-native-parallel-stage/1', supported=True,
        actions=['move', 'scale', 'depth', 'tilt', 'expr', 'fade', 'enter', 'exit', 'camera', 'bgblur'],
        transition_methods=['black_out', 'white_out', 'reveal', 'black_return', 'white_return', 'mask'],
        masks_require_target_catalog=True,
        background_change_with_actions=True, background_change_with_blur=True,
        cg_exit_with_line=True, duplicate_channels=False, second_fullscreen_transition=False,
        target_info_required=True, native_state_pair_required=True, runtime_verified=False)
