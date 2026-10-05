"""Target-bound native motion calls, independent of game names/addresses.

The known motion ABI is matched by its complete instruction semantics, including
literal constants, frame slots, jumps, syscall arities and transitive helpers.
Global-state slots use one consistent target-local bijection, never source IDs.
The exact four FloatToInt axis conversions form explicit target parameters;
their values are extracted from the original code, not inherited or estimated.
A similar five-function shape alone never certifies argument meaning. The
caller supplies a trusted reference contract; this module grants no file writes
or primitive ownership and does not choose an entry point or stage geometry.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import struct
from types import MappingProxyType
from typing import Mapping

from .hcb import HcbDocument
from .native_target_discovery import _function_regions, _discover_transform_family
from .portrait_emitter import _encode_push

CONTRACT = "fvp-native-stage-motion/1"
ROLES = {"alpha": ("opacity", 8), "xy": ("xy", 10), "z": ("z", 8),
         "s2": ("scale", 10), "r": ("rotation", 8)}


class NativeStageMotionError(ValueError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode()).hexdigest()


class _SemanticImage:
    def __init__(self, document):
        if not isinstance(document, HcbDocument) or document.warnings or document.modified:
            raise NativeStageMotionError("目标动作脚本未完整解析，不能生成动作。")
        self.document = document
        self.regions = _function_regions(document)
        self.entries = {region.start: region for region in self.regions}
        self.cache, self.visiting = {}, set()
        self.global_slots = {}
        self.xy_factors = {}
        if len({entry.name for entry in document.header.syscalls}) != len(document.header.syscalls):
            raise NativeStageMotionError("动作系统调用名重复，不能确定当前目标。")

    def function(self, address):
        if address in self.cache:
            return self.cache[address]
        if address not in self.entries or address in self.visiting or len(self.visiting) >= 12:
            raise NativeStageMotionError("动作依赖不是有效函数，或存在递归依赖。")
        region = self.entries[address]
        if region.instruction_count > 2048:
            raise NativeStageMotionError("动作函数过大，不能直接复用。")
        self.visiting.add(address)
        body = self.document.instructions[region.instruction_start_index:region.instruction_end_index]
        coefficient_offsets = self._xy_parameters(region, body)
        offsets = {item.offset: index for index, item in enumerate(body)}
        tokens, dependencies = [], {address}
        for item in body:
            if item.warning or item.dirty or not item.known:
                raise NativeStageMotionError("动作函数含未解析或被修改的指令。")
            operands = dict(item.operands)
            if item.mnemonic == "push_f32" and not math.isfinite(operands["value"]):
                raise NativeStageMotionError("原生动作函数含无效浮点常量。")
            if item.mnemonic == "syscall":
                ident = operands.get("id")
                if type(ident) is not int or not 0 <= ident < len(self.document.header.syscalls):
                    raise NativeStageMotionError("动作系统调用编号无效。")
                syscall = self.document.header.syscalls[ident]
                operands = dict(name=syscall.name, args=syscall.args)
            elif item.mnemonic == "call":
                child, required = self.function(operands["target"])
                dependencies.update(required)
                operands = dict(function_sha256=child)
            elif item.mnemonic in ("jmp", "jz"):
                target = operands["target"]
                if target not in offsets:
                    raise NativeStageMotionError("动作函数含跳出函数的分支。")
                operands = dict(target_instruction=offsets[target])
            elif item.mnemonic == "push_string":
                # Do not normalise literal values, frame IDs or maths.
                operands = dict(text=item.text)
            elif item.offset in coefficient_offsets:
                operands = dict(value=coefficient_offsets[item.offset])
            elif item.mnemonic in ("push_global", "pop_global", "push_global_table", "pop_global_table"):
                # Equivalent native functions relocate their global state too.
                # A shared bijection preserves every alias/read/write relation
                # across the entire family and all transitive helper functions.
                slot = operands["value"]
                self.global_slots.setdefault(slot, len(self.global_slots))
                operands = dict(value="target_global_" + str(self.global_slots[slot]))
            tokens.append([item.mnemonic, operands])
        self.visiting.remove(address)
        result = _digest(tokens), frozenset(dependencies)
        self.cache[address] = result
        return result

    def _xy_parameters(self, region, body):
        if (region.args, region.locals, region.syscalls) != (8, 4,
                ("FloatToInt", "FloatToInt", "FloatToInt", "FloatToInt", "MotionMove")):
            return {}
        points = [(index, item) for index, item in enumerate(body) if item.mnemonic == "push_f32"]
        if len(points) != 4:
            return {}
        values, offsets = [], {}
        for (index, item), slot, axis in zip(points, (-8, -7, -6, -5), ("x", "y", "x", "y")):
            before, after = body[index-1], body[index+1:index+5]
            value = item.operands["value"]
            if (before.mnemonic != "push_stack" or before.operands["value"] != slot
                    or [ins.mnemonic for ins in after] != ["mul", "syscall", "push_return", "pop_stack"]
                    or self.document.header.syscalls[after[1].operands["id"]].name != "FloatToInt"
                    or type(value) is not float or not math.isfinite(value) or not 0 < value <= 32):
                return {}
            values.append(value)
            offsets[item.offset] = "native_axis_" + axis
        if values[:2] != values[2:]:
            return {}
        self.xy_factors[region.start] = dict(x=values[0], y=values[1])
        return offsets

    def family(self):
        selected = _discover_transform_family(self.regions).get("selected")
        if not selected:
            raise NativeStageMotionError("这个版本的原生动作函数尚未接通；不会借用其他游戏地址。")
        return {name: selected[role]["start"] for name, (role, _arity) in ROLES.items()}


@dataclass(frozen=True)
class NativeMotionContract:
    source_sha256: str
    roles: Mapping[str, str]


def motion_contract(document):
    """Derive a contract only from a caller-trusted, already understood ABI."""
    image = _SemanticImage(document)
    roles = {name: image.function(address)[0] for name, address in image.family().items()}
    return NativeMotionContract(document.source_sha256, MappingProxyType(roles))


class NativeStageMotion:
    def __init__(self, document, runtime_bytes, contract):
        if not isinstance(contract, NativeMotionContract) or set(contract.roles) != set(ROLES):
            raise NativeStageMotionError("缺少已确认的动作参数契约。")
        if type(runtime_bytes) is not bytes:
            raise NativeStageMotionError("缺少当前游戏的动作脚本内容。")
        image = _SemanticImage(document)
        addresses = image.family()
        identities = {}
        for name, address in addresses.items():
            semantic_sha, dependencies = image.function(address)
            region = image.entries[address]
            if region.args != ROLES[name][1] or semantic_sha != contract.roles[name]:
                raise NativeStageMotionError("原生动作参数含义尚未确认：" + name)
            for target in dependencies:
                required = image.entries[target]
                if (runtime_bytes[required.start:required.end]
                        != document.original_bytes[required.start:required.end]):
                    raise NativeStageMotionError("活动脚本的动作函数已改变，不能用原版函数地址。")
            identities[name] = dict(address=address, args=region.args,
                semantic_sha256=semantic_sha, dependency_count=len(dependencies))
        self._bindings = MappingProxyType({name: (addresses[name], ROLES[name][1]) for name in ROLES})
        self._report = dict(schema=CONTRACT, target_hcb_sha256=hashlib.sha256(runtime_bytes).hexdigest(),
            analysis_hcb_sha256=document.source_sha256,
            reference_sha256=contract.source_sha256, roles=identities,
            native_global_slots={str(value): slot for slot, value in image.global_slots.items()},
            native_xy_factors={str(address): factors for address, factors in image.xy_factors.items()},
            game_name_switch_used=False, runtime_verified=False,
            argument_space="target_native_helper",
            primitive_ownership_granted=False, stage_geometry_changed=False)

    @property
    def bindings(self):
        return self._bindings

    def report(self):
        return json.loads(json.dumps(self._report))

    def call(self, name, arguments):
        if name not in self._bindings:
            raise NativeStageMotionError("没有接通这个动作通道。")
        address, count = self._bindings[name]
        if not isinstance(arguments, (list, tuple)) or len(arguments) != count:
            raise NativeStageMotionError("原生动作参数数目不正确。")
        if any(value is not None and type(value) not in (bool, int, float) for value in arguments):
            raise NativeStageMotionError("原生动作参数只允许有限数值或空值。")
        for value in arguments:
            if type(value) is float:
                try:
                    wire = struct.unpack("<f", struct.pack("<f", value))[0]
                except (OverflowError, struct.error) as exc:
                    raise NativeStageMotionError("动作数值超出游戏范围。") from exc
                if not math.isfinite(wire):
                    raise NativeStageMotionError("动作数值必须为有限数值。")
        return b"".join(_encode_push(value, "shift_jis") for value in arguments) + b"\x02" + struct.pack("<I", address)
