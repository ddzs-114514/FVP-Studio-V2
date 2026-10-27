"""Route new typed features through target binding, including older clients."""


def needs_native_gestures_or_cg_transition(scene):
    pending = list(scene.get('beats', []))
    for _ in range(512):
        if not pending:
            return False
        beat = pending.pop()
        if not isinstance(beat, dict):
            continue  # Full input validation belongs to the selected exporter.
        if beat.get('kind') == 'transition' and (beat.get('method') == 'mask' or 'mask' in beat):
            return True
        for action in beat.get('actions', []):
            if not isinstance(action, dict):
                continue
            if action.get('type') == 'nod':
                return True
            if action.get('type') in {'cg', 'cgxf', 'cgexit'} and (
                    beat.get('kind') == 'transition' or 'transition' in (action.get('p') or {})):
                return True
        for option in beat.get('options', []):
            if isinstance(option, dict) and isinstance(option.get('beats'), list):
                pending.extend(option['beats'])
    return True  # Let the native validator reject an oversized nested input.
