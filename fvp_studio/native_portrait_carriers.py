"""Read-only carrier ABI views, separate from the enabled output compiler.

The 14-argument dual-sprite family has an extra runtime field and an optional
_ru resource layer. Identifying it must not make the older 12/13 compiler call
it with the wrong arity. Production portrait acceptance stays independently
gated; this module only decodes exact native registration forwarders.
"""
from .native_portrait_acceptance import (
    NativePortraitAcceptanceError, _DispatcherStackLayout, _dispatcher_stack_layout,
    _integer_value, _wrapper_constants_for_dispatcher,
    _lifecycle_call_records, _lifecycle_targets, _lifecycle_apply_argument_count,
    _region_from_discovery,
)


def carrier_layout(argument_count):
    if argument_count in (12, 13):
        return _dispatcher_stack_layout(argument_count)
    if argument_count == 14:
        # Source wrappers prepend four integer resource selectors and then
        # forward ten frame arguments in order. The form slot is independently
        # checked by the body's paired-load/geometry branches during discovery.
        return _DispatcherStackLayout(14, 10, -15, -14, -13, -12, -11)
    raise NativePortraitAcceptanceError("未识别的原生立绘载体参数布局。")


def plain_carrier_constants(span, dispatcher, argc):
    if argc != 14:
        return _wrapper_constants_for_dispatcher(span, dispatcher, argc)
    layout = carrier_layout(argc)
    body = span.instructions
    call_index = 5 + layout.runtime_count
    if (span.args != layout.runtime_count or span.locals != 0 or span.calls != (dispatcher,)
            or len(body) <= call_index + 1 or body[0].mnemonic != "init_stack"):
        return None
    constants = tuple(_integer_value(x) for x in body[1:5])
    if (any(x is None for x in constants)
            or any(x.mnemonic != "push_stack" for x in body[5:call_index])
            or tuple(x.operands.get("value") for x in body[5:call_index]) != tuple(range(-11, -1))
            or body[call_index].mnemonic != "call"
            or body[call_index].operands.get("target") != dispatcher
            or any(x.mnemonic != "ret" for x in body[call_index + 1:])):
        return None
    return constants


def carrier_lifecycle_targets(discovery):
    clear, apply = _lifecycle_call_records(discovery)
    if int(apply.get("args", -1)) == 4:
        portrait = _region_from_discovery(discovery, "portrait_dispatcher")
        lifecycle = _region_from_discovery(discovery, "portrait_lifecycle_family")
        if (int(clear.get("args", -1)) != 2 or int(portrait.get("args", -1)) != 14
                or lifecycle.get("engine_variant") != "composite_fvp"
                or not lifecycle.get("delegates", {}).get("apply_cleanup")):
            raise NativePortraitAcceptanceError("四参数应用调用缺少原生双阶段清理链。")
        return int(clear["start"]), int(apply["start"]), 4
    clear_target, apply_target = _lifecycle_targets(discovery)
    return clear_target, apply_target, _lifecycle_apply_argument_count(discovery)
