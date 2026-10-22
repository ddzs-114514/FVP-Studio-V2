"""Own ThreadStart reset/spawn semantics, not bootstrap/scheduler acceptance.

Bind complete native helpers behind the already verified slot handler. On a
normal spawn return, nonnegative callee argc determines NIL prefill and SP.
This does not prove initial HCB/main-thread creation, reference destruction,
return/FP/yield initialisation or ownership of an already active slot.
"""
from .engine_patterns import engine_pattern

import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _function, _relocated
from .native_cg_thread_handoff import _next_binding
from .native_cg_thread_slots import _capacity
from .native_cg_vm_frames import bind_native_cg_vm_frames

SCHEMA = "fvp-native-cg-thread-entry/1"


def _word(value):
    return re.escape(struct.pack("<I", value))


def _one_call(code, address, pattern, label):
    matches = list(re.finditer(pattern, code, re.DOTALL))
    if len(matches) != 1:
        raise ValueError("CG 线程入口没有唯一的本机调用："+label)
    match = matches[0]
    return address+match.end("call")+struct.unpack("<i", match["call"])[0]


def _branches(match, pairs):
    for branch, label in pairs:
        if match.end(branch)+struct.unpack("<b", match[branch])[0] != match.start(label):
            raise ValueError("CG 原生线程入口分支没有接回自己的完整辅助函数。")


def bind_native_cg_thread_entry(executable, vm, frames):
    raw = bytes(executable)
    digest = hashlib.sha256(raw).hexdigest()
    if vm["exe_sha256"] != digest or frames != bind_native_cg_vm_frames(raw, vm):
        raise ValueError("CG 线程入口和原生调用帧不是同一份引擎。")
    next_binding = _next_binding(raw)
    capacity = _capacity(raw, next_binding)
    image, sections = _pe_sections(raw)
    base, stride = (_word(capacity[k]) for k in ("native_base", "native_stride"))
    start_address, exit_address = (capacity[k]["address"] for k in ("ThreadStart", "ThreadExit"))
    _, start_code = _function(raw, image, sections, start_address)
    _, exit_code = _function(raw, image, sections, exit_address)
    reset_pattern = engine_pattern('native_cg_thread_entry:51:20')+stride
    reset = _one_call(start_code, start_address, reset_pattern, "启动前重置")
    exit_reset = _one_call(exit_code, exit_address, reset_pattern, "全线程退出重置")
    local_exit = _one_call(exit_code, exit_address,
        engine_pattern('native_cg_thread_entry:55:8')+stride+engine_pattern('native_cg_thread_entry:55:28')+base+engine_pattern('native_cg_thread_entry:55:50'), "单线程退出重置")
    spawn = _one_call(start_code, start_address,
        engine_pattern('native_cg_thread_entry:57:8')+base+engine_pattern('native_cg_thread_entry:57:40'), "创建线程")
    if reset != exit_reset or reset != local_exit or reset == spawn:
        raise ValueError("CG 线程创建／退出没有共用本机已确认的独立重置入口。")
    fields = vm["thread_frame_fields"]
    sp, pc, fp, rv, yield_byte = (fields[k] for k in ("sp", "pc", "fp", "return_value", "yield_byte"))
    active, first_refs, second_refs = yield_byte-8, fp+4, fp+4+0x100
    SP, PC, ACTIVE, Y, ONE, TWO = map(_word, (sp, pc, active, yield_byte, first_refs, second_refs))
    spawn_at, spawn_code = _function(raw, image, sections, spawn)
    prefix = engine_pattern('native_cg_thread_entry:65:13')
    layouts = {
        "one-register-SP-increment": (
            engine_pattern('native_cg_thread_entry:68:12')+ACTIVE+engine_pattern('native_cg_thread_entry:69:32')+PC+engine_pattern('native_cg_thread_entry:69:48')+SP+
            engine_pattern('native_cg_thread_entry:70:12')+SP+engine_pattern('native_cg_thread_entry:71:38')+SP+
            engine_pattern('native_cg_thread_entry:72:12')),
        "load-increment-store-SP": (
            engine_pattern('native_cg_thread_entry:74:12')+ACTIVE+engine_pattern('native_cg_thread_entry:74:68')+PC+engine_pattern('native_cg_thread_entry:75:28')+SP+engine_pattern('native_cg_thread_entry:75:44')+SP+engine_pattern('native_cg_thread_entry:76:38')+SP+
            engine_pattern('native_cg_thread_entry:77:12')+SP+engine_pattern('native_cg_thread_entry:77:36'))}
    found = [(name, re.fullmatch(prefix+tail, spawn_code, re.DOTALL)) for name, tail in layouts.items()]
    found = [(name, match) for name, match in found if match is not None]
    if len(found) != 1:
        raise ValueError("CG 原生线程创建的参数预填／起始栈还没有完整绑定。")
    layout, match = found[0]
    if (bool(match["saved_edi"]) != (layout == "one-register-SP-increment")
            or spawn+match.end("reset")+struct.unpack("<i", match["reset"])[0] != reset):
        raise ValueError("CG 原生线程创建没有先调用同一个重置入口。")
    _branches(match, (("zero", "done"), ("again", "loop")))

    reset_at, reset_code = _function(raw, image, sections, reset)
    modern = (
        engine_pattern('native_cg_thread_entry:90:8')+ACTIVE+engine_pattern('native_cg_thread_entry:90:40')+ACTIVE+engine_pattern('native_cg_thread_entry:91:28')+Y+engine_pattern('native_cg_thread_entry:91:51')+ONE+
        engine_pattern('native_cg_thread_entry:92:8')+TWO+
        engine_pattern('native_cg_thread_entry:96:8'))
    legacy = (
        engine_pattern('native_cg_thread_entry:101:8')+ACTIVE+engine_pattern('native_cg_thread_entry:101:40')+ACTIVE+engine_pattern('native_cg_thread_entry:102:28')+Y+engine_pattern('native_cg_thread_entry:102:51')+ONE+
        engine_pattern('native_cg_thread_entry:103:8')+TWO+
        engine_pattern('native_cg_thread_entry:107:8'))
    # Old compilers sometimes place only one INT3 between two functions.
    # Match the complete closed function (every jump checked), not the
    # arbitrary 512-byte disassembly window or a bare reset prefix.
    reset_pattern = modern if layout == "one-register-SP-increment" else legacy
    reset_match = re.match(reset_pattern, reset_code, re.DOTALL)
    if reset_match is None:
        raise ValueError("CG 原生线程重置的引用清理循环还没有完整绑定。")
    _branches(reset_match, (("idle", "done"), ("first_zero", "first_step"),
        ("first_again", "first_loop"), ("second_zero", "second_step"), ("second_again", "second_loop")))
    counts = {k: struct.unpack("<I", reset_match[name])[0]
              for k, name in ((1, "first_count"), (2, "second_count"))}
    if (counts[1]*2 != second_refs-first_refs or not 1 <= counts[2] <= 0x10000
            or second_refs+counts[2]*2 > capacity["native_stride"]):
        raise ValueError("CG 原生线程引用清理越过了自己的存储边界。")
    helpers = {}
    for k, name in ((1, "first_release"), (2, "second_release")):
        target = reset+reset_match.end(name)+struct.unpack("<i", reset_match[name])[0]
        _relocated(raw, image, sections, target, executable=True)
        expected = frames["retained_reference_mutators"].get(k, frames["retained_reference_mutators"].get(str(k)))
        if expected is None or target != expected["address"]:
            raise ValueError("CG 线程入口没有沿用本机调用帧的引用清理入口。")
        helpers[k] = target
    reset_code = reset_match[0]
    return dict(schema=SCHEMA, exe_sha256=digest, layout=layout,
        native_ThreadStart_address=start_address, native_ThreadExit_address=exit_address,
        native_spawn=dict(address=spawn, offset=spawn_at, code_bytes=len(spawn_code),
            code_sha256=hashlib.sha256(spawn_code).hexdigest()),
        native_reset=dict(address=reset, offset=reset_at, code_bytes=len(reset_code),
            code_sha256=hashlib.sha256(reset_code).hexdigest(), reference_slots=counts,
            object_release_helpers=helpers),
        active_field=active, thread_SP_field=sp, thread_PC_field=pc,
        callee_argc_signed_bits=8, callee_argc_offset_from_entry=1,
        argument_value_bytes=8, argument_value_base=8, initialized_argument_tag=0,
        complete_ThreadStart_spawn_static_bound=True,
        shared_ThreadStart_ThreadExit_reset_static_bound=True,
        complete_slot_reset_reference_loops_static_bound=True,
        nonnegative_argc_NIL_prefill_and_SP_static_bound=True,
        zero_argument_ThreadStart_entry_SP_static_bound=True,
        previous_SP_is_replaced_after_reset_returns=True,
        start_PC_is_the_supplied_entry=True,
        spawn_initializes_FP=False, spawn_initializes_return_register=False,
        spawn_clears_yield_byte=False,
        bootstrap_HCB_entry_creation_static_bound=False,
        all_external_root_SP_proven=False, native_scheduler_entry_state_complete=False,
        zero_count_destructor_audit_complete=False, reset_helper_side_effects_complete=False,
        native_slot_concurrent_or_reentrant_ownership_proven=False,
        runtime_verified=False, scene_export_connected=False)
