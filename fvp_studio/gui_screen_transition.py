"""Ordinary scene mask transitions: one target-owned reveal per beat."""
from copy import deepcopy

from .gui_chapter_transition import transition_values
from .gui_runtime import ID_RE


def mask_values(fields):
    if not isinstance(fields, dict) or set(fields) != {'method', 'duration_ms', 'mask'} or fields['method'] != 'mask':
        raise ValueError('场景内原作遮罩需要明确的 mask、遮罩 ID 和时长。')
    transition_values(dict(type='mask', mask=fields['mask'], duration_ms=fields['duration_ms']))
    return deepcopy(fields)


def bind_mask_beats(events, groups):
    """Bound the resource preparation, including cuts, before the one reveal.

    Explicit boundaries survive branch/chapter remapping. Never infer the
    start by scanning backwards across a line or an unrelated stage change.
    """
    from .native_parallel_beat import STAGE_KINDS
    if not isinstance(groups, list):
        raise ValueError('原作遮罩节拍边界必须是列表。')
    starts, used, ends, beats = {}, set(), set(), set()
    for group in groups:
        if not isinstance(group, dict) or set(group) != {'beat_id', 'prepare_index', 'transition_index'}:
            raise ValueError('原作遮罩缺少准备和转场的节拍边界。')
        start, end, beat = group['prepare_index'], group['transition_index'], group['beat_id']
        if (not isinstance(beat, str) or not ID_RE.fullmatch(beat) or beat in beats
                or any(type(i) is not int or not 0 <= i < len(events) for i in (start, end))
                or start > end or used.intersection(range(start, end + 1))
                or events[end].get('kind') != 'Transition'):
            raise ValueError('原作遮罩的节拍边界越界、重叠或没有对应转场。')
        mask_values({k: v for k, v in events[end].items() if k != 'kind'})
        if any(e.get('kind') not in (STAGE_KINDS - {'Transition'}) | {
                'GuiBackgroundChange', 'Portrait', 'GuiActorSwap', 'Hide'} for e in events[start:end]):
            raise ValueError('原作遮罩不能跨台词、选项、场景、CG 或另一条整幕转场。')
        if any(e['kind'] == 'GuiBackgroundChange' and e.get('duration_ms') != 0 for e in events[start:end]):
            raise ValueError('遮罩拍内换背景须直接加载，不能叠加背景渐变。')
        starts[start] = group
        used.update(range(start, end + 1))
        ends.add(end)
        beats.add(beat)
    if ends != {i for i, e in enumerate(events) if e.get('kind') == 'Transition' and e.get('method') == 'mask'}:
        raise ValueError('每个场景内遮罩都必须有自己的完整节拍边界。')
    return starts
