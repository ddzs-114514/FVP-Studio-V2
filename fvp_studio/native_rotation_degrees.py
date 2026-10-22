"""Target-owned GUI degrees -> native portrait R.

The registered setters and MotionMoveR must use the same primitive field.
Its primitive walker must pass that object to a renderer whose complete angle
argument reaches a named PE import. No executable identities, addresses,
game names, or foreign renderer constants select a conversion rule.

API units: Microsoft D3DXMatrixRotationZ takes radians; GdipRotateMatrix
(Matrix::Rotate) takes degrees. Capstone is NOT a runtime dependency.
"""
from __future__ import annotations
from .engine_patterns import engine_pattern


from copy import deepcopy
import hashlib
import math
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_legacy_size_discovery import _relocated, _function
from .native_portrait_motion import NativePortraitMotion
from .performance_compile import rounded
from .runtime_text_companion import _PEImage


SCHEMA = "fvp-native-rotation-degrees/1"


def _u32(value):
    return struct.unpack("<I", value)[0]


def _one(items, message):
    if len(items) != 1:
        raise ValueError(message)
    return items[0]


def _registration(raw, image, sections, label, argc):
    candidates = []
    patterns = [re.compile(pattern,re.DOTALL) for pattern in (
        engine_pattern('native_rotation_degrees:42:8')
        + bytes((argc,)) + engine_pattern('native_rotation_degrees:43:27'),
        engine_pattern('native_rotation_degrees:44:8')
        + bytes((argc,)) + engine_pattern('native_rotation_degrees:45:27'))]
    for _, rva, length, pointer, flags in sections:
        if not flags & 0x20000000:
            continue
        founds = [found for pattern in patterns for found in pattern.finditer(raw[pointer:pointer+length])]
        for found in founds:
            try:
                name = _relocated(raw,image,sections,_u32(found["label"]),
                    executable=False,length=len(label)+1)
                if raw[name:name+len(label)+1] != label.encode("ascii")+b"\0":
                    continue
                address = _u32(found["handler"])
                offset = _relocated(raw,image,sections,address,executable=True)
                registrar = image+rva+found.end()+struct.unpack("<i",found["register"])[0]
                _relocated(raw,image,sections,registrar,executable=True)
            except ValueError:
                continue
            candidates.append(dict(address=address,offset=offset,registrar=registrar,
                                   registration_offset=pointer+found.start()))
    return _one(candidates, f"{label} 没有唯一的本机原生注册。")


def _code(raw,image,sections,address,limit):
    at = _relocated(raw,image,sections,address,executable=True)
    section = next(s for s in sections if s[3] <= at < s[3]+s[2])
    return at,raw[at:min(at+limit,section[3]+section[2])]


def _callee(address, match, name="call"):
    return address+match.end(name)+struct.unpack("<i",match[name])[0]


def _imports(raw,image):
    pe = _PEImage.parse(raw)
    if pe.thunk_size != 4:
        raise ValueError("旋转换算只接受已经识别的 x86 调用链。")
    rva,length = pe.directory(1)
    rows = {}
    terminated = False
    for i in range(min(length//20,4096)):
        original,time,forward,name,first = struct.unpack("<IIIII",pe.read_rva(rva+i*20,20))
        if not any((original,time,forward,name,first)):
            terminated = True
            break
        dll = pe.c_string_rva(name,label="旋转 DLL").decode("ascii").casefold()
        for j in range(65536):
            item = _u32(pe.read_rva((original or first)+j*4,4))
            if not item:
                break
            if item & 0x80000000:
                continue  # Ordinal numbers are not cross-version API evidence.
            label = pe.c_string_rva(item+2,label="旋转 API").decode("ascii")
            address = image+first+j*4
            if address in rows:
                raise ValueError("旋转导入表有重叠的 IAT。")
            rows[address] = (dll,label)
        else:
            raise ValueError("旋转导入表没有结束标记。")
    if not terminated:
        raise ValueError("旋转导入描述符没有结束标记。")
    return rows


def _api(raw,image,sections,imports,address):
    at,code = _code(raw,image,sections,address,6)
    if len(code) != 6 or code[:2] != b"\xff\x25":
        raise ValueError("原生旋转没有直接绑定命名导入。")
    iat = _u32(code[2:])
    _relocated(raw,image,sections,iat,executable=False,length=4)
    if iat not in imports:
        raise ValueError("原生旋转的 IAT 不属于当前导入表。")
    return dict(dll=imports[iat][0],name=imports[iat][1],iat=iat,thunk_offset=at)


def _setter_layout(code):
    if not code.startswith(engine_pattern('native_rotation_degrees:120:27')):
        raise ValueError("旋转设置器的参数类型未识别。")
    stride = _one(re.findall(engine_pattern('native_rotation_degrees:122:29'),code,re.DOTALL),"旋转图元步长不唯一。")[0]
    base = _u32(_one(re.findall(engine_pattern('native_rotation_degrees:123:32'),code,re.DOTALL),"旋转图元数组不唯一。"))
    rotation = _one(list(re.finditer(
        engine_pattern('native_rotation_degrees:125:8'),code,re.DOTALL)),"原生旋转字段未闭合。")
    field,period = rotation["field"][0],_u32(rotation["period"])
    if not 0 < field < stride-1 or not 0 < period <= 32767:
        raise ValueError("旋转字段或周期无效。")
    return stride,base,field,period


def _motion(raw,image,sections,registration,layout):
    at,code = _function(raw,image,sections,registration["address"])
    stride,base,field,_ = layout
    # Optional from/to consume the raw values, defaulting to the SAME word
    # field as PrimSetRS. Both known instruction orders retain type guards.
    read = b"\x0f\xbf\x94\x0a"+struct.pack("<I",base+field)
    if b"\x6b\xd2"+bytes((stride,)) not in code or code.count(read) != 1:
        raise ValueError("旋转运动与旋转设置器没有共享字段。")
    prefix = re.escape(b"\x6b\xd2"+bytes((stride,)))
    current = re.escape(read)
    _one(list(re.finditer(prefix+engine_pattern('native_rotation_degrees:144:33')+current+
        engine_pattern('native_rotation_degrees:145:8')+current+engine_pattern('native_rotation_degrees:145:36'),code,re.DOTALL)),
        "旋转运动起止参数没有保留原生单位。")
    call = _one(list(re.finditer(
        engine_pattern('native_rotation_degrees:149:8'),
        code,re.DOTALL)),"旋转运动的原生委派未闭合。")
    delegate = _callee(registration["address"],call)
    delegate_at,body = _function(raw,image,sections,delegate)
    records = list(re.finditer(
        engine_pattern('native_rotation_degrees:155:8'),
        body,re.DOTALL))
    record = _one(records,"旋转运动记录对起止值做了未识别的换算。")
    if record["to"][0] != record["from"][0]+2 or body.count(bytes.fromhex("8d04528d44c104")) != 1:
        raise ValueError("旋转运动记录字段不一致。")
    return dict(handler_offset=at,delegate_offset=delegate_at,
        receiver_offset=_u32(call["state"]),record_fields=[record["from"][0],record["to"][0]])


def _walkers(raw,image,sections,layout):
    stride,base,field,_ = layout
    # Both walkers follow native aliases/groups and pass the same ESI object
    # as the third renderer argument. Their actual array and stride must match
    # the registered setter, not a coincidentally similar word in another type.
    prefixes = (
        engine_pattern('native_rotation_degrees:173:8'),
        engine_pattern('native_rotation_degrees:175:8'),
    )
    own = b"\x6b\xc0"+bytes((stride,))+b"\x8d\x84\x38"+struct.pack("<I",base)
    rows = []
    for _,rva,length,pointer,flags in sections:
        if not flags&0x20000000:
            continue
        for prefix in prefixes:
            for match in re.finditer(prefix+re.escape(own),raw[pointer:pointer+length],re.DOTALL):
                address = image+rva+match.start()
                at,code = _code(raw,image,sections,address,1024)
                calls = list(re.finditer(
                    engine_pattern('native_rotation_degrees:188:20'),
                    code,re.DOTALL))
                if len(calls) != 1:
                    continue
                call = calls[0]
                name = "call" if call["call"] is not None else "oldcall"
                rows.append(dict(walker_offset=at,renderer=_callee(address,call,name)))
    return _one(rows,"旋转图元没有唯一的原生渲染调用链。")


def extract_rotation_degrees(raw):
    image,sections = _pe_sections(raw)
    registrations = {name:_registration(raw,image,sections,name,argc)
        for name,argc in (("PrimSetRS",3),("PrimSetRS2",4),("MotionMoveR",6))}
    if len({r["registrar"] for r in registrations.values()}) != 1:
        raise ValueError("原生旋转调用不属于同一分派器。")
    layouts = [_setter_layout(_function(raw,image,sections,registrations[n]["address"])[1])
               for n in ("PrimSetRS","PrimSetRS2")]
    if layouts[0] != layouts[1]:
        raise ValueError("两种原生旋转设置器的存储布局不一致。")
    layout = layouts[0]
    motion = _motion(raw,image,sections,registrations["MotionMoveR"],layout)
    walker = _walkers(raw,image,sections,layout)
    renderer_at,code = _code(raw,image,sections,walker["renderer"],4096)
    imports = _imports(raw,image)
    field = bytes((layout[2],))
    candidates = []
    modern = re.compile(
        engine_pattern('native_rotation_degrees:217:8')+re.escape(field)+engine_pattern('native_rotation_degrees:217:42'),re.DOTALL)
    if code.startswith(engine_pattern('native_rotation_degrees:221:23')) and bytes.fromhex("8b7d10807f0700") in code[:64]:
        for found in modern.finditer(code):
            api = _api(raw,image,sections,imports,_callee(walker["renderer"],found))
            if not re.fullmatch(r"d3dx9_[0-9]+\.dll",api["dll"]) or api["name"] != "D3DXMatrixRotationZ":
                continue
            values = []
            for key in ("divisor","pi"):
                off = _relocated(raw,image,sections,_u32(found[key]),executable=False,length=8)
                values.append(struct.unpack("<d",raw[off:off+8])[0])
            divisor,pi = values
            unit = divisor/180
            if (not math.isfinite(unit) or not 0 < unit <= 20 or unit != int(unit)
                    or not math.isclose(pi,math.pi,rel_tol=4e-8,abs_tol=0)):
                continue
            candidates.append(dict(units_per_degree=int(unit),renderer_api=api,
                angle_formula="raw_R / native_divisor * native_pi_radians",
                divisor=divisor,pi=pi,angle_reader_offset=renderer_at+found.start()))
    old = re.compile(
        engine_pattern('native_rotation_degrees:239:8')+re.escape(field)+engine_pattern('native_rotation_degrees:239:42'),re.DOTALL)
    if code.startswith(engine_pattern('native_rotation_degrees:245:23')) and bytes.fromhex("568b74244c") in code[:40]:
        for found in old.finditer(code):
            helper = _callee(walker["renderer"],found)
            _,body = _function(raw,image,sections,helper)
            forwarded = re.fullmatch(
                engine_pattern('native_rotation_degrees:250:16'),body,re.DOTALL)
            if forwarded is None:
                continue
            api = _api(raw,image,sections,imports,_callee(helper,forwarded))
            if (api["dll"],api["name"]) != ("gdiplus.dll","GdipRotateMatrix"):
                continue
            off = _relocated(raw,image,sections,_u32(found["factor"]),executable=False,length=4)
            constant = raw[off:off+4]
            factor = struct.unpack("<f",constant)[0]
            if not math.isfinite(factor) or factor <= 0:
                continue
            unit = round(1/factor)
            if not 0 < unit <= 20 or struct.pack("<f",1/unit) != constant:
                continue
            candidates.append(dict(units_per_degree=unit,renderer_api=api,
                angle_formula="raw_R * native_factor_degrees",factor=factor,
                angle_reader_offset=renderer_at+found.start()))
    proof = _one(candidates,"此版本的原生旋转角度换算尚未识别。")
    return dict(schema=SCHEMA,exe_sha256=hashlib.sha256(raw).hexdigest(),
        primitive_stride=layout[0],primitive_array_offset=layout[1],rotation_field=layout[2],
        setter_period=layout[3],registrations=registrations,native_motion=motion,
        walker_offset=walker["walker_offset"],renderer_offset=renderer_at,**proof,
        uses_game_name_switch=False,uses_foreign_engine_units=False,runtime_verified=False)


class NativeRotationDegrees:
    """Trusted local binding; never accepts a browser-provided scale factor."""
    def __init__(self,target):
        target.check_unchanged()
        raw = (target.root/target.executable).read_bytes()
        if hashlib.sha256(raw).hexdigest() != target.executable_sha256:
            raise ValueError("旋转换算所依据的目标程序已变化。")
        proof = extract_rotation_degrees(raw)
        context = target.context
        motion = NativePortraitMotion(context.document,context.analysis_document,{"r"},runtime_context=context)
        proof.update(target_id=context.target_id,hcb_sha256=context.document.source_sha256,
                     native_helper=motion.report()["roles"]["r"]["helper"])
        target.check_unchanged()
        self._target,self._proof = target,proof

    def __call__(self,degrees):
        if type(degrees) not in (int,float) or not math.isfinite(degrees) or not -50 <= degrees <= 50:
            raise ValueError("倾斜角度须为 -50～50 的有限数值。")
        self._target.check_unchanged()
        return rounded(degrees*self._proof["units_per_degree"])

    def report(self):
        return deepcopy(self._proof)

    def assert_target(self,target):
        if target is not self._target:
            raise ValueError("旋转换算不属于本次绑定的目标。")
        target.check_unchanged()

    def setter_changes_angle(self,raw_R):
        # Some setters wrap at a half-turn, while MotionMoveR preserves signed
        # raw words. Do not reapply a negative motion result via that setter.
        return raw_R < 0 and self._proof["setter_period"] % (360*self._proof["units_per_degree"]) != 0
