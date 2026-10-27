"""One target-owned transition for a CG change, not two stacked fades."""
from copy import deepcopy

from .gui_chapter_transition import transition_values, METHODS


def values(value):
    if not isinstance(value, dict):
        raise ValueError('CG 转场需要明确的方式和时间。')
    method = value.get('type')
    if method in {'black_out', 'white_out', 'reveal'}:
        if set(value) != {'type', 'duration_ms'} or type(value['duration_ms']) is not int or not 100 <= value['duration_ms'] <= 3000:
            raise ValueError('CG 遮盖／恢复转场时间须为 100～3000ms。')
        return deepcopy(value)
    return transition_values(value)


def from_beat(beat):
    method = {'black_return': 'black', 'white_return': 'white'}.get(beat.get('method'), beat.get('method'))
    result = dict(type=method, duration_ms=beat.get('dur'))
    if 'mask' in beat:
        result['mask'] = beat['mask']
    return values(result)


def contract():
    return dict(schema='fvp-native-cg-transition/1', action_field='p.transition',
        methods=list(METHODS) + ['black_out', 'white_out', 'reveal'],
        operations=['load', 'difference', 'exit', 'transform'],
        same_transition_beat=True, load_with_transform=True,
        transition_owns_fade=True, implicit_cg_fade=False,
        covered_load_requires_explicit_transition=True,
        mask_catalog_endpoint='chapter-transition-catalog',
        masks_require_target_catalog=True, target_info_required=True,
        runtime_verified=False)
