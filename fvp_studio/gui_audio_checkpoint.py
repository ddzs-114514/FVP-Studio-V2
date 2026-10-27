"""Release boundary: unfinished cross-process audio checkpoints are absent."""
# SPDX-License-Identifier: GPL-3.0-or-later
from .gui_runtime import GuiRuntimeError

REQUEST_FIELD = 'experimental_audio_checkpoint'
SCHEMA = 'fvp-gui-audio-checkpoint-test-export/1'


def bridge_options(selected):
    if type(selected) is not bool:
        raise ValueError('音频存读档实验选项只接受布尔值。')
    if selected:
        raise GuiRuntimeError('audio_checkpoint_not_distributed',
            '此发布版未包含跨进程音频存读档实验；拒绝生成实验副本。', 422)
    return {}


def enabled(request):
    value = request.get(REQUEST_FIELD, False)
    if type(value) is not bool:
        raise GuiRuntimeError('invalid_request', '音频存读档实验选项只接受 true 或 false。')
    bridge_options(value)
    return False


def contract():
    return dict(schema=SCHEMA, request_field=REQUEST_FIELD, default=False,
        supported=False, implementation_distributed=False, session_only=True,
        persists_in_project=False, new_test_copy_only=True,
        production_export_enabled=False, runtime_verified=False,
        save_load_verified=False, reason='unfinished_experiment_excluded_from_release')


def paired_report(selected, bridge):
    bridge_options(selected)
    return None


def require_audio_program(selected, events):
    bridge_options(selected)


def attach_report(report, selected, bridge):
    return paired_report(selected, bridge)
