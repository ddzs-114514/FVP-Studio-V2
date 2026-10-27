"""A finite down-and-return gesture; not an indefinite vertical sway."""
from copy import deepcopy
import math

KIND = 'GuiActorNod'
PIXEL_UNITS = 'editor_pixels_1280x720'
SCRIPT_UNITS = 'target_script_xy'


def values(fields):
    required = {'actor', 'amplitude', 'duration_ms', 'curve'}
    if (not isinstance(fields, dict) or not required <= set(fields)
            or set(fields) - required - {'amplitude_units', 'duration_mode'}):
        raise ValueError('点头须指定角色、幅度、总时长和曲线。')
    if type(fields['actor']) is not int or not 1 <= fields['actor'] <= 4:
        raise ValueError('点头角色槽不合法。')
    amp, duration = fields['amplitude'], fields['duration_ms']
    unit = fields.get('amplitude_units', PIXEL_UNITS)
    timing = fields.get('duration_mode', 'fixed')
    if unit not in (PIXEL_UNITS, SCRIPT_UNITS) or timing not in ('fixed', 'original'):
        raise ValueError('点头幅度单位或时长模式不支持；不能把原作脚本单位当作像素。')
    if type(amp) not in (int, float) or not math.isfinite(amp) or not 1 <= amp <= 120:
        raise ValueError('点头幅度须为 1～120；单位由原作脚本/编辑像素模式明确指定。')
    if unit == SCRIPT_UNITS and type(amp) is not int:
        raise ValueError('原作脚本单位的点头幅度须为整数。')
    if type(duration) is not int or not 200 <= duration <= 6000 or duration % 2:
        raise ValueError('点头总时长须为 200～6000ms 偶数，两程各一半。')
    if type(fields['curve']) is not int or fields['curve'] not in (2, 3):
        raise ValueError('点头曲线须为 2 或 3。')
    if timing == 'original' and duration != 450:
        raise ValueError('原作自动时长的工程标称值为450ms；手动改时长请切换为固定时长。')
    return deepcopy(fields)


def authored(action, actor):
    p = action.get('p')
    if not isinstance(p, dict) or 'amp' not in p or set(p) - {'amp', 'unit', 'timing'}:
        raise ValueError('点头只需幅度；执行一次后自动回位，无需停止节拍。')
    result = dict(actor=actor, amplitude=p['amp'], duration_ms=action.get('dur'), curve=action.get('curve'))
    if 'unit' in p:
        if p['unit'] not in ('pixels', 'script'):
            raise ValueError('点头幅度单位只支持pixels或script。')
        result['amplitude_units'] = SCRIPT_UNITS if p['unit'] == 'script' else PIXEL_UNITS
    if 'timing' in p:
        result['duration_mode'] = p['timing']
    return values(result)


def contract():
    return dict(schema='fvp-native-actor-nod/2', action='nod', event=KIND,
        amplitude_units=SCRIPT_UNITS, amplitude_range=[1, 120],
        supported_amplitude_units=[SCRIPT_UNITS, PIXEL_UNITS],
        legacy_missing_unit=PIXEL_UNITS, legacy_missing_timing='fixed',
        default=dict(amp=75, unit='script', timing='original', duration_ms=450, curve=3),
        default_is_authoring_choice_not_original_script_units=False,
        default_reference='iroseka_hd_observed_nod_preset_1',
        default_is_each_target_original_preset_verified=False,
        original_timing=dict(query='V3DMotionTest', sample='worker_start_once',
            idle_leg_ms=225, moving_leg_ms=250, total_ms=[450, 500]),
        sequence=['down', 'return_to_start'], count=1, duration_is_total=True,
        stops_automatically=True, smooth_return=True, stop_beat_required=False,
        parallel_with_dialogue=True, paired_buffers=True,
        join_before_actor_geometry_swap_exit=True, target_info_required=True,
        source_size_rule_changed=False, runtime_verified=False)
