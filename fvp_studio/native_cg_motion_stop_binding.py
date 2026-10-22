"""Bind complete target-owned primitive stop handlers and record removal.

Stops remove the first active record for the exact positive primitive. They
do not join threads, flush rendering, finish a motion, or establish a valid
free-list/unique-record invariant. In particular, Test return conventions
are not borrowed to manufacture a generic drain loop.
"""
from .engine_patterns import engine_pattern

from copy import deepcopy
import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_rotation_degrees import _code, _registration


SCHEMA = "fvp-native-cg-motion-stop-binding/1"
def _release_pattern_value__HANDLER():
    return re.compile(engine_pattern('native_cg_motion_stop_binding:19:4'), re.DOTALL)
def _release_pattern_value__WORD_RECORD():
    return re.compile(engine_pattern('native_cg_motion_stop_binding:23:4'), re.DOTALL)
def _release_pattern_value__BYTE_WORD_RECORD():
    return re.compile(engine_pattern('native_cg_motion_stop_binding:31:4'), re.DOTALL)
def _release_pattern_value__BYTE_DWORD_RECORD():
    return re.compile(engine_pattern('native_cg_motion_stop_binding:38:4'), re.DOTALL)


def _u32(value):
    return struct.unpack("<I", value)[0]


def _record(address, offset, code):
    return dict(address=address, offset=offset, length=len(code),
                sha256=hashlib.sha256(code).hexdigest())


def _leaf(code):
    candidates = [(pattern.match(code), width, key_width) for pattern, width, key_width in (
        (_release_pattern_value__WORD_RECORD(), 2, 2), (_release_pattern_value__BYTE_WORD_RECORD(), 1, 2), (_release_pattern_value__BYTE_DWORD_RECORD(), 1, 4))]
    found = [(match, width, key_width) for match, width, key_width in candidates if match]
    if len(found) != 1:
        raise ValueError("CG 动画停止的完整记录移除函数未识别。")
    match, width, key_width = found[0]
    branches = []
    for name, target in (("enter", "loop"), ("skip", "next"), ("match", "found"), ("back", "loop")):
        if name not in match.groupdict():
            continue
        destination = match.end(name)+struct.unpack("<b", match[name])[0]
        if destination != match.start(target):
            raise ValueError("CG 动画停止有未闭合的分支路径。")
        branches.append(dict(offset=match.start(name)-1, target=destination))
    if width == 2:
        advance, limit = match["advance"], match["limit"]
        stride = advance[2] if advance[:2] == b"\x83\xc0" else _u32(advance[1:])
        capacity = _u32(limit[2:]) if limit[:2] == b"\x81\xfa" else limit[2]
    else:
        stride, capacity = match["stride"][0], match["capacity"][0]
    count, free = _u32(match["count"]), _u32(match["free"])
    key, index = match["key"][0], match["index"][0]
    # Short ADD/CMP operands are sign-extended by the actual instructions.
    short_stride = width == 1 or match["advance"][:2] == b"\x83\xc0"
    short_limit = width == 1 or match["limit"][:2] == b"\x83\xfa"
    if (not 0 < capacity < 2**(8*width-1) or (short_limit and capacity > 127)
            or not 8 < stride < 2**31 or (short_stride and stride > 127)
            or free != 4+stride*capacity or count != free+width*capacity
            or not 5 <= key <= stride-key_width or not 5 <= index <= stride-width
            or not (key+key_width <= index or index+width <= key)):
        raise ValueError("CG 动画停止的记录、计数和空闲槽布局未配对。")
    return match.end(), dict(record_base_offset=4, record_stride=stride, record_capacity=capacity,
        active_offset=4, primitive_offset=key, primitive_width=key_width,
        primitive_comparison="signed_integer_equality", free_index_offset=index,
        free_index_width=width, free_list_offset=free, counter_offset=count, counter_width=width,
        counter_decrement_wrap_bits=8*width, freed_slot_index_sign_extended=True,
        complete_branches=branches, removes_first_matching_active_record=True,
        remaining_matching_records_scanned=False, no_match_leaves_channel_state_unchanged=True,
        final_motion_value_applied=False, primitive_properties_written=False,
        graph_or_parts_resources_released=False, native_calls_or_imports_present=False,
        channel_extent=count+width)


class NativeCGMotionStopBinding:
    def __init__(self, executable, channels):
        if not isinstance(executable, bytes) or not executable or not channels:
            raise ValueError("CG 动画停止需要当前目标的原生程序和已配对调用。")
        image, sections = _pe_sections(executable)
        self._executable = executable
        self.executable_sha256 = hashlib.sha256(executable).hexdigest()
        self._roles = {}
        ranges, primitive_maxima = [], set()
        for channel, row in channels.items():
            if row.get("stop_arity") != 1 or type(row.get("stop_syscall_id")) is not int:
                raise ValueError("CG 动画停止的脚本调用布局无效。")
            registration = _registration(executable, image, sections, row["stop"], 1)
            offset, code = _code(executable, image, sections, registration["address"], 42)
            handler = _release_pattern_value__HANDLER().fullmatch(code)
            if handler is None:
                raise ValueError("CG 动画停止的类型、图层范围或委派入口未闭合。")
            maximum, state = _u32(handler["maximum"]), _u32(handler["channel"])
            if not 0 < maximum <= 32767 or state < 4:
                raise ValueError("CG 动画停止的有符号图层范围无效。")
            delegate = registration["address"]+handler.end("delegate")+struct.unpack("<i", handler["delegate"])[0]
            leaf_offset, body = _code(executable, image, sections, delegate, 128)
            length, layout = _leaf(body)
            if state+layout["channel_extent"] >= 2**31:
                raise ValueError("CG 动画停止的本机记录范围溢出。")
            primitive_maxima.add(maximum)
            ranges.append((state, state+layout["channel_extent"]))
            self._roles[channel] = dict(stop=row["stop"], stop_syscall_id=row["stop_syscall_id"],
                registration=deepcopy(registration), handler=_record(registration["address"], offset, code),
                delegate=_record(delegate, leaf_offset, body[:length]),
                primitive_minimum=1, primitive_maximum=maximum, argument_native_type=2,
                invalid_argument_returns_without_record_write=True, callee_stack_cleanup_bytes=4,
                channel_context_offset=state, layout=layout)
        if len(primitive_maxima) != 1 or any(a < d and c < b
                for index, (a, b) in enumerate(ranges) for c, d in ranges[index+1:]):
            raise ValueError("CG 动画停止的图层范围不一致或动作通道重叠。")
        self.primitive_maximum = next(iter(primitive_maxima))

    def validate(self, channels, primitives):
        if hashlib.sha256(self._executable).hexdigest() != self.executable_sha256:
            raise ValueError("CG 动画停止的原生程序证据已经变化。")
        if (set(channels) != set(self._roles) or any(
                row.get("stop") != self._roles[channel]["stop"]
                or row.get("stop_arity") != 1
                or row.get("stop_syscall_id") != self._roles[channel]["stop_syscall_id"]
                for channel, row in channels.items())):
            raise ValueError("CG 动画停止的调用绑定已经变化。")
        if any(type(primitive) is not int or not 1 <= primitive <= self.primitive_maximum
               for primitive in primitives):
            raise ValueError("CG 图层超过本目标原生停止入口接受的范围。")

    def report(self):
        return dict(schema=SCHEMA, executable_sha256=self.executable_sha256,
            roles=deepcopy(self._roles), primitive_maximum=self.primitive_maximum,
            complete_stop_handlers_and_delegates_bound=True,
            first_match_only=True, all_matching_records_removed=False,
            motion_start_uniqueness_proven=False, active_counter_and_free_list_invariant_proven=False,
            concurrent_engine_threads_owned=False, native_render_state_flushed=False,
            scene_export_connected=False, runtime_verified=False)


_RELEASE_PATTERN_FACTORIES = {'_HANDLER': _release_pattern_value__HANDLER, '_WORD_RECORD': _release_pattern_value__WORD_RECORD, '_BYTE_WORD_RECORD': _release_pattern_value__BYTE_WORD_RECORD, '_BYTE_DWORD_RECORD': _release_pattern_value__BYTE_DWORD_RECORD}
def __getattr__(name):
    factory = _RELEASE_PATTERN_FACTORIES.get(name)
    if factory is None:
        raise AttributeError(name)
    return factory()
