"""Target-native sprite/position/group helpers and portrait memory fragments.

Matches the complete helper/dependency semantics, not function numbers or game
names. Two closed Nil-guard layouts are equivalent: assigning Nil in each else,
or initialising both locals to Nil before the guarded conversions. All branches,
frame slots and syscall arities are still checked. The two exact FloatToInt
axis multipliers are target parameters only;
they never determine imported portrait height. This layer does not reserve
primitives, alter the scene entry, access resources, or grant install rights.
The caller must supply its own reviewed slot and frozen resource references.
"""
from dataclasses import dataclass
import hashlib
import math
import struct
from types import MappingProxyType
from typing import Mapping

from .native_stage_motion import _SemanticImage, NativeStageMotionError, _digest
from .native_vm_backend import NativeVmBackend
from .hcb import parse_bytes, HcbError

SCHEMA = "fvp-native-stage-helpers/1"
ROLES = {"sprite": 4, "xy_set": 3, "group": 2}


class NativeStageHelperError(ValueError):
    pass


def _numeric_range(value):
    if type(value) is int and not -2147483648 <= value <= 2147483647:
        raise NativeStageHelperError("立绘数值超出原生整数范围。")
    if type(value) is float:
        try:
            wire = struct.unpack("<f", struct.pack("<f", value))[0]
        except (OverflowError, struct.error) as exc:
            raise NativeStageHelperError("立绘数值超出原生浮点范围。") from exc
        if not math.isfinite(wire):
            raise NativeStageHelperError("立绘数值必须有限，不能静默夹紧。")


def _runtime_header_matches(document, runtime):
    # Header-only reparse: no expensive second decode of the entire story.
    # Entry/title may differ in a translated overlay, but syscall IDs/arity,
    # global allocation and game mode may not change underneath native calls.
    try:
        offset = struct.unpack_from("<I", runtime, 0)[0]
        if not 4 <= offset < len(runtime):
            raise ValueError("invalid header offset")
        header = bytearray(runtime[offset:])
        struct.pack_into("<I", header, 0, 4)
        found = parse_bytes(struct.pack("<I", 8) + b"\x01\0\0\x04" + header, "shift_jis").header
    except (HcbError, ValueError, struct.error, IndexError) as exc:
        raise NativeStageHelperError("当前游戏的函数表无法确认。") from exc
    expected = document.header
    if ([(s.args, s.raw_name) for s in found.syscalls] != [(s.args, s.raw_name) for s in expected.syscalls]
            or (found.non_volatile_globals, found.volatile_globals, found.game_mode, found.custom_syscall_count) !=
               (expected.non_volatile_globals, expected.volatile_globals, expected.game_mode, expected.custom_syscall_count)):
        raise NativeStageHelperError("当前脚本的系统调用表或原生状态分配已改变。")


def _sprite_layouts():
    """Exact CFG templates, not a general opcode/branch normaliser."""
    result = {}
    for initial_nil in (False, True):
        tokens = [["init_stack", dict(args=4, locals=2)]]
        if initial_nil:
            for local in (0, 1):
                tokens.extend([["push_nil", {}], ["pop_stack", dict(value=local)]])
        for frame, local, axis in ((-3, 0, "x"), (-2, 1, "y")):
            tokens.extend([["push_stack", dict(value=frame)], ["push_nil", {}], ["set_ne", {}]])
            branch = len(tokens)
            tokens.append(["jz", {}])
            tokens.extend([["push_stack", dict(value=frame)],
                ["push_f32", dict(value="native_axis_" + axis)], ["mul", {}],
                ["syscall", dict(name="FloatToInt", args=1)], ["push_return", {}],
                ["pop_stack", dict(value=local)]])
            if initial_nil:
                nil_branch = len(tokens)
            else:
                finish = len(tokens)
                tokens.append(["jmp", {}])
                nil_branch = len(tokens)
                tokens.extend([["push_nil", {}], ["pop_stack", dict(value=local)]])
                tokens[finish][1] = dict(target_instruction=len(tokens))
            tokens[branch][1] = dict(target_instruction=nil_branch)
        tokens.extend([["push_stack", dict(value=frame)] for frame in (-5, -4, 0, 1)])
        tokens.extend([["syscall", dict(name="PrimSetSprt", args=4)], ["ret", {}], ["ret", {}]])
        result["initial_nil" if initial_nil else "explicit_else_nil"] = tokens
    return result


_SPRITE_LAYOUTS = _sprite_layouts()


class _HelperImage(_SemanticImage):
    def __init__(self, document):
        super().__init__(document)
        self.sprite_guard_layout = {}

    def function(self, address):
        if address in self.cache:
            return self.cache[address]
        region = self.entries.get(address)
        if region and (region.args, region.locals, region.syscalls) == (
                4, 2, ("FloatToInt", "FloatToInt", "PrimSetSprt")):
            body = self.document.instructions[region.instruction_start_index:region.instruction_end_index]
            coefficients = self._xy_parameters(region, body)
            offsets = {item.offset: index for index, item in enumerate(body)}
            tokens = []
            for item in body:
                if item.warning or item.dirty or not item.known:
                    break
                operands = dict(item.operands)
                if item.mnemonic == "syscall":
                    ident = operands.get("id")
                    if type(ident) is not int or not 0 <= ident < len(self.document.header.syscalls):
                        break
                    entry = self.document.header.syscalls[ident]
                    operands = dict(name=entry.name, args=entry.args)
                elif item.mnemonic in ("jmp", "jz"):
                    if operands["target"] not in offsets:
                        break
                    operands = dict(target_instruction=offsets[operands["target"]])
                elif item.offset in coefficients:
                    operands = dict(value=coefficients[item.offset])
                tokens.append([item.mnemonic, operands])
            for layout, expected in _SPRITE_LAYOUTS.items():
                if len(tokens) == len(body) and tokens == expected:
                    # Both exact layouts produce the same four observable
                    # argument cases (x/y independently Nil or converted),
                    # with identical FloatToInt and PrimSetSprt calls. No other
                    # reordering, dead code, calls or global state is ignored.
                    result = _digest(_SPRITE_LAYOUTS["explicit_else_nil"]), frozenset({address})
                    self.sprite_guard_layout[address] = layout
                    self.cache[address] = result
                    return result
        return super().function(address)

    def _xy_parameters(self, region, body):
        # Parameterisation is limited to the exact multiply/FloatToInt/store
        # pattern. The remainder, including Nil guards, is hashed unchanged.
        if ((region.args, region.locals, region.syscalls) not in
                ((4, 2, ("FloatToInt", "FloatToInt", "PrimSetSprt")),
                 (3, 2, ("FloatToInt", "FloatToInt", "PrimSetXY")))):
            return super()._xy_parameters(region, body)
        points = [(i, ins) for i, ins in enumerate(body) if ins.mnemonic == "push_f32"]
        if len(points) != 2:
            return {}
        factors, offsets = {}, {}
        for (i, ins), frame, local, axis in zip(points, (-3, -2), (0, 1), ("x", "y")):
            before, after = body[i-1], body[i+1:i+5]
            value = ins.operands["value"]
            if (before.mnemonic != "push_stack" or before.operands["value"] != frame
                    or [p.mnemonic for p in after] != ["mul", "syscall", "push_return", "pop_stack"]
                    or self.document.header.syscalls[after[1].operands["id"]].name != "FloatToInt"
                    or after[3].operands["value"] != local
                    or not math.isfinite(value) or not 0 < value <= 32):
                return {}
            factors[axis] = value
            offsets[ins.offset] = "native_axis_" + axis
        self.xy_factors[region.start] = factors
        return offsets


@dataclass(frozen=True)
class NativeStageHelperContract:
    source_sha256: str
    shapes: Mapping[str, tuple]
    isolated_semantics: Mapping[str, str]
    shared_semantics: Mapping[str, str]


def stage_helper_contract(document, bindings):
    """Called only with an already understood reference's helper bindings."""
    if set(bindings) != set(ROLES):
        raise NativeStageHelperError("缺少立绘加载、位置或分组函数的已确认契约。")
    shared = _HelperImage(document)
    shapes, isolated, together = {}, {}, {}
    for role, count in ROLES.items():
        address = bindings[role]
        if type(address) is not int or address not in shared.entries:
            raise NativeStageHelperError("参考地址不是已确认的函数入口。")
        region = shared.entries[address]
        if region.args != count:
            raise NativeStageHelperError("参考函数的参数数目不正确。")
        shapes[role] = (region.args, region.locals, region.syscalls)
        isolated[role] = _HelperImage(document).function(address)[0]
        together[role] = shared.function(address)[0]
    return NativeStageHelperContract(document.source_sha256,
        MappingProxyType(shapes), MappingProxyType(isolated), MappingProxyType(together))


class NativeStageHelpers:
    def __init__(self, document, runtime_bytes, contract):
        if not isinstance(contract, NativeStageHelperContract) or type(runtime_bytes) is not bytes:
            raise NativeStageHelperError("缺少目标脚本或已确认的立绘调用契约。")
        image = _HelperImage(document)
        _runtime_header_matches(document, runtime_bytes)
        selected, identities = {}, {}
        for role, count in ROLES.items():
            candidates = []
            for region in image.regions:
                if (region.args, region.locals, region.syscalls) != contract.shapes[role]:
                    continue
                candidate = _HelperImage(document)
                try:
                    digest, _ = candidate.function(region.start)
                except NativeStageMotionError:
                    continue
                if digest == contract.isolated_semantics[role]:
                    candidates.append(region.start)
            if len(candidates) != 1:
                raise NativeStageHelperError("目标立绘调用未唯一匹配：" + role)
            address = candidates[0]
            semantic, dependencies = image.function(address)
            if semantic != contract.shared_semantics[role]:
                raise NativeStageHelperError("目标立绘函数共享状态的含义不一致。")
            for target in dependencies:
                dependency = image.entries[target]
                if runtime_bytes[dependency.start:dependency.end] != document.original_bytes[dependency.start:dependency.end]:
                    raise NativeStageHelperError("当前脚本的立绘依赖函数已经改变。")
            selected[role] = (address, count)
            identities[role] = dict(address=address, args=count, semantic_sha256=semantic,
                                    dependency_count=len(dependencies))
        factors = [image.xy_factors.get(selected[role][0]) for role in ("sprite", "xy_set")]
        if not factors[0] or factors[0] != factors[1]:
            raise NativeStageHelperError("立绘加载与位置函数的原生轴系数不一致。")
        self._document, self._runtime = document, runtime_bytes
        self.bindings = MappingProxyType(selected)
        self._report = dict(schema=SCHEMA, target_hcb_sha256=hashlib.sha256(runtime_bytes).hexdigest(),
            analysis_hcb_sha256=document.source_sha256, reference_sha256=contract.source_sha256,
            roles=identities, native_xy_factors=dict(factors[0]), game_name_switch_used=False,
            primitive_ownership_granted=False, imported_size_changed=False,
            scene_entry_changed=False, runtime_verified=False)
        layout = image.sprite_guard_layout.get(selected['sprite'][0])
        if layout:
            self._report['roles']['sprite']['checked_nil_guard_layout'] = layout

    def report(self):
        from copy import deepcopy
        return deepcopy(self._report)

    def operation(self, role, arguments):
        if role not in self.bindings:
            raise NativeStageHelperError("立绘调用通道未接通。")
        address, count = self.bindings[role]
        if not isinstance(arguments, (tuple, list)) or len(arguments) != count:
            raise NativeStageHelperError("立绘调用参数数目不正确。")
        if any(value is not None and type(value) not in (bool, int, float) for value in arguments):
            raise NativeStageHelperError("立绘调用只接受数值或空值。")
        for value in arguments:
            _numeric_range(value)
        return dict(kind="function", address=address, arguments=list(arguments))

    def call(self, role, arguments):
        from .portrait_emitter import _encode_push
        operation = self.operation(role, arguments)
        return b"".join(_encode_push(v, "shift_jis") for v in operation["arguments"]) + b"\x02" + struct.pack("<I", operation["address"])

    def portrait_fragment(self, *, primitive, graphics, parts, group, namespace,
                          body, face, expression, frame_count, native):
        """Load then clear an explicit slot in an unreachable memory function.

        Uses supplied native geometry verbatim. Resource registration, slot
        ownership and the safe scene attachment must be resolved by the caller.
        No file is opened, resource name generated or sprite size inferred here.
        """
        for value in (primitive, graphics, parts, group):
            if type(value) is not int or not 0 <= value <= 255:
                raise NativeStageHelperError("须提供目标自己的立绘资源槽。")
        if (namespace not in ("graph", "graph_bs") or
                any(not isinstance(v, str) or not v or any(c in v for c in "/\\:\0") for v in (body, face))):
            raise NativeStageHelperError("立绘资源引用不正确。")
        if (type(frame_count) is not int or not 1 <= frame_count <= 256
                or type(expression) is not int or not 0 <= expression < frame_count):
            raise NativeStageHelperError("表情帧越界。")
        if (not isinstance(native, dict) or
                set(native) != {"x", "y", "z", "scale", "rotation", "alpha", "pivot"}):
            raise NativeStageHelperError("必须明确提供原生位置和大小；不会猜测。")
        pivot = native["pivot"]
        if not isinstance(pivot, (tuple, list)) or len(pivot) != 2:
            raise NativeStageHelperError("立绘原点不正确。")
        geometry = [native[key] for key in ("x", "y", "z", "rotation")] + list(pivot)
        if any(type(value) not in (int, float) for value in geometry):
            raise NativeStageHelperError("立绘位置、深度、旋转和原点须为数值。")
        for value in geometry:
            _numeric_range(value)
        if (type(native["scale"]) is not int or not 1 <= native["scale"] <= 4000
                or type(native["alpha"]) is not int or not 0 <= native["alpha"] <= 255):
            raise NativeStageHelperError("立绘大小或透明度超出支持范围。")
        def syscall(name, *values):
            return dict(kind="syscall", name=name, arguments=list(values))
        clear = [syscall(name, parts if name == "PartsMotionStop" else primitive) for name in
                 ("MotionMoveStop", "MotionMoveZStop", "MotionMoveRStop", "MotionMoveS2Stop", "MotionAlphaStop", "PartsMotionStop")]
        clear.append(syscall("PrimSetNull", primitive))
        operations = clear + [syscall("GraphLoad", graphics, namespace + "/" + body),
            syscall("PartsLoad", parts, namespace + "/" + face),
            self.operation("sprite", (primitive, graphics, None, None)),
            syscall("PartsAssign", graphics, parts), syscall("PartsSelect", parts, expression),
            self.operation("group", (primitive, group)), syscall("PrimSetOP", primitive, *pivot),
            self.operation("xy_set", (primitive, native["x"], native["y"])),
            syscall("PrimSetZ", primitive, native["z"]),
            syscall("PrimSetRS", primitive, native["rotation"], native["scale"]),
            syscall("PrimSetAlpha", primitive, native["alpha"]), syscall("PrimSetDraw", primitive, True)] + clear
        backend = NativeVmBackend(self._runtime, "shift_jis")
        fragment = backend.compile_fragment(operations, source_sha256=backend.source_sha256,
                                            binding_sha256=backend.binding_sha256)
        return fragment
