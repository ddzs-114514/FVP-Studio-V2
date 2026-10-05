"""Ordinary mid-scene BG changes, independent of portrait import geometry.

The GUI event is portable; this bytecode adapter is still the hash-bound Hoshi
target. Its native BG wrappers are copied into the appended region, preserving
their local frames and jumps. Only the wrapper's camera reset is redirected.
"""
from copy import deepcopy
import hashlib
import math
import struct

from .performance_compile import args, call, jump
from .performance_workflow import values

CONTRACT = "fvp-gui-background-change/1"
KINDS = {"GuiBackgroundChange"}
SPECS = (("bg", 0x52BBA, 0x52CCF), ("bg_blur", 0x52CCF, 0x52DD0))
CAMERA_RESET = 0x5465A


def event_values(kind, fields):
    if kind not in KINDS or set(fields) != {
            "source_game", "archive", "resource", "fit", "duration_ms"}:
        raise ValueError("换背景的参数不完整。")
    duration = fields["duration_ms"]
    if (type(duration) is not int or not math.isfinite(duration)
            or duration != 0 and not 100 <= duration <= 6000):
        raise ValueError("直接换背景请设为 0；渐变时长为 100～6000 毫秒。")
    parsed = values("Background", {k: v for k, v in fields.items() if k != "duration_ms"})
    return {**parsed, "duration_ms": duration}


def _copy_wrapper(emitter, role, start, end, address, camera_stub, *, explicit_blur=False):
    source = emitter.source[start:end]
    if source != emitter.clean[start:end] or source[:3] != bytes((1, 9, 2)):
        raise ValueError("换背景的原作调用发生变化。")
    cursor, instructions = start, []
    while cursor < end:
        instruction = emitter.by_offset.get(cursor)
        if not instruction or not instruction.raw:
            raise ValueError("换背景的原作函数边界发生变化。")
        instructions.append(instruction)
        cursor += len(instruction.raw)
    if cursor != end or instructions[-1].mnemonic != "ret":
        raise ValueError("换背景的原作函数不完整。")
    if explicit_blur and (role != "bg_blur" or start != 0x52CCF
            or [i.mnemonic for i in instructions[:6]] !=
            ["init_stack", "push_global", "push_true", "set_e", "jz", "push_i16"]
            or instructions[1].operands.get("value") != 1637
            or instructions[4].operands.get("target") != 0x52DCE
            or instructions[5].operands.get("value") != 187):
        raise ValueError("模糊背景的原作开关调用发生变化。")
    mapping = {ins.offset: address + ins.offset - start for ins in instructions}
    out, edits, camera_calls = bytearray(), [], 0
    for instruction in instructions:
        raw = instruction.raw
        if instruction.opcode in (2, 6, 7):
            target = instruction.operands["target"]
            if instruction.opcode in (6, 7):
                if target not in mapping:
                    raise ValueError("换背景函数出现未支持的外部跳转。")
                # Only this appended copy bypasses the game's blur preference.
                # Keep the condition/pop semantics; both routes load layer 187.
                redirected = mapping[instructions[5].offset if explicit_blur
                    and instruction.offset == instructions[4].offset else target]
            elif target == CAMERA_RESET:
                camera_calls += 1
                redirected = camera_stub
            else:
                redirected = target
            if redirected != target:
                raw = bytes((instruction.opcode,)) + struct.pack("<I", redirected)
                edits.append(dict(source=instruction.offset, target=target, redirected=redirected))
        out.extend(raw)
    if camera_calls != (1 if role == "bg" else 0):
        raise ValueError("换背景时重置镜头的位置发生变化。")
    return bytes(out), dict(role=role, source=[start, end], address=address,
        size=len(out), source_sha256=hashlib.sha256(source).hexdigest(), address_edits=edits,
        explicit_blur=explicit_blur, original_configuration_unchanged=True)


def loader(emitter):
    key = ("gui_background_loader", CONTRACT)
    if key in emitter.helpers:
        return emitter.helpers[key]["bindings"]
    reset = emitter.by_offset.get(CAMERA_RESET)
    if not reset or reset.raw[:3] != bytes((1, 4, 0)):
        raise ValueError("换背景的镜头保护调用发生变化。")
    skip = len(emitter.output)
    emitter.output.extend(jump(0))
    stub = len(emitter.output)
    # HCB ret unwinds the declared four arguments. No globals/V3D are changed.
    emitter.output.extend(bytes((1, 4, 0, 4)))
    bindings, copies = {}, []
    for role, start, end in SPECS:
        address = len(emitter.output)
        block, report = _copy_wrapper(emitter, role, start, end, address, stub)
        emitter.output.extend(block)
        bindings[role] = address
        copies.append(report)
    struct.pack_into("<I", emitter.output, skip + 1, len(emitter.output))
    emitter.helpers[key] = dict(bindings=bindings, copies=copies, camera_stub=stub,
        camera_preserved=True, portrait_geometry_unchanged=True,
        transition_owner="native_Dissolve_7_args", runtime_verified=False)
    return bindings


def emit_background(emitter, event, resources):
    if event["kind"] not in KINDS:
        return False
    event_values(event["kind"], {k: v for k, v in event.items() if k != "kind"})
    if emitter.cg is not None:
        raise ValueError("请先让 CG 退场，再换普通背景。")
    if event["duration_ms"] and emitter.covered:
        raise ValueError("黑白场下请直接换背景，再用淡入恢复画面。")
    emitter.join()
    emitter.clear_background_blur()
    resource = resources.bg(event)
    bindings = loader(emitter)
    parameters = [resource, None, 50, None, None, None, None, None, 1]
    for role, address in bindings.items():
        emitter.output.extend(args(parameters) + call(address))
        emitter.calls.append(dict(function="gui_background_" + role,
                                  address=address, arguments=parameters))
    # Hoshi 4466's mode 0 reaches 0x4ADB7 -> Dissolve(duration, graph/diss00,
    # True, Nil x4). Call that same syscall without 4466's CG/portrait refresh
    # branches or user-settings overrides. Original code remains untouched.
    # Zero means a cut: the original wrapper clamps instant dissolve to 1 ms.
    # Under an existing cover, load only; an explicit Reveal owns uncovering.
    if not emitter.covered:
        native_duration = max(1, event["duration_ms"])
        dissolve_args = (native_duration, "graph/diss00", True, None, None, None, None)
        emitter.output.extend(emitter.syscall("Dissolve", dissolve_args))
        emitter.calls.append(dict(function="gui_background_dissolve",
            syscall=emitter.syscalls["Dissolve"][0], arguments=list(dissolve_args)))
        emitter.bg_dissolve_pending = True
        if event["duration_ms"] == 0:
            emitter.join()
    emitter.gui_background = (event["archive"], event["resource"], event["fit"])
    emitter.background_loaded = True
    # Do not reset camera/reference, reload actors, resize or realign faces.
    return True


def report(emitter):
    return dict(schema=CONTRACT, target="hoshi", camera_preserved=True,
        portrait_geometry_unchanged=True, parallel_text=True,
        adapters=deepcopy([v for k, v in emitter.helpers.items()
            if isinstance(k, tuple) and k[0] == "gui_background_loader"]),
        runtime_verified=False)
