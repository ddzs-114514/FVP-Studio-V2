"""Private CG loading chain: hidden until ready, one native transition owner.

The original functions stay byte-identical. Stable-pose inheritance is tracked
by this linear workflow; it is not an arbitrary live-camera snapshot facility.
"""
import hashlib
import struct

from .portrait_emitter import _encode_push

SPECS = ((4395, 0x5368B, 0x53A6D, 10), (4396, 0x53A6D, 0x53B26, 8),
         (4397, 0x53B26, 0x53B8E, 3), (4173, 0x37104, 0x3716A, 3))
WRAPPERS = {'MARE_e01a': (29, 0x1A20, 0x1A57, 6),
            'MARE_e01b': (30, 0x1A57, 0x1A8E, 6), 'MARE_e01c': (31, 0x1A8E, 0x1AC5, 6)}
HIDE_AT = 0x3714A


def arguments(values):
    return b''.join(_encode_push(v, 'gbk') for v in values)


def call(target):
    return b'\x02' + struct.pack('<I', target)


def jump(target):
    return b'\x06' + struct.pack('<I', target)


def stack(slot):
    return b'\x10' + struct.pack('<b', slot)


def hidden_gate(emitter):
    if any(emitter.syscalls[name][1] != 2 for name in ('PrimSetAlpha', 'PrimSetDraw')):
        raise ValueError('CG隐藏初始化syscall ABI漂移')
    return b''.join(stack(-4) + arguments([0]) + b'\x03' + struct.pack('<H', emitter.syscalls[name][0])
                    for name in ('PrimSetAlpha', 'PrimSetDraw'))


def relocate(emitter, spec, address, routes):
    number, start, end, arity = spec
    # This is a contiguous, audited function body. Walking its offsets avoids
    # rescanning the entire HCB instruction table for every CG adapter.
    instructions = []
    offset = start
    while offset < end:
        instruction = emitter.by_offset.get(offset)
        if instruction is None or not instruction.raw:
            raise ValueError(f'CG私有适配原函数边界漂移: {number}')
        instructions.append(instruction)
        offset += len(instruction.raw)
    source = emitter.source[start:end]
    if source != emitter.clean[start:end] or source[:3] != bytes((1, arity, 0)) or not instructions or offset != end:
        raise ValueError(f'CG私有适配原函数指纹/边界漂移: {number}')
    gate = hidden_gate(emitter) if number == 4173 else b''
    mapping, cursor = {}, address
    for i in instructions:
        mapping[i.offset] = cursor
        cursor += len(i.raw) + (len(gate) if i.offset == HIDE_AT else 0)
    out, edits = bytearray(), []
    for i in instructions:
        if gate and i.offset == HIDE_AT:
            out.extend(gate)
        raw = i.raw
        if i.opcode in (2, 6, 7):
            target = i.operands['target']
            if i.opcode in (6, 7):
                if target not in mapping:
                    raise ValueError('CG私有函数出现未审核的外部跳转')
                new = mapping[target]
            else:
                new = routes.get(target, target)
            if new != target:
                raw = bytes((i.opcode,)) + struct.pack('<I', new)
                edits.append(dict(source=i.offset, target=target, redirected=new))
        out.extend(raw)
    return bytes(out), dict(function=number, source=[start,end], address=address, size=len(out),
        source_sha256=hashlib.sha256(source).hexdigest(), address_edits=edits,
        hidden_gate=mapping.get(HIDE_AT) if gate else None)


def make_adapter(emitter, resource, pose, keep_camera):
    key = ('cg_adapter', resource, pose['x'], pose['y'], pose['z'], pose['r'], keep_camera)
    if key in emitter.helpers:
        return emitter.helpers[key]['wrapper']
    # Helpers are skipped in the main path. All internal branches land on the
    # visibility insertion, including the three original sprite-create paths.
    skip = len(emitter.output)
    emitter.output.extend(jump(0))
    stubs = {}
    if keep_camera:
        for target, arity in ((0x5465A, 4), (0x4B47E, 3)):
            if emitter.by_offset[target].operands['args'] != arity:
                raise ValueError('CG镜头保护调用ABI漂移')
            stubs[target] = len(emitter.output)
            emitter.output.extend(bytes((1,arity,0,4)))
    shim = len(emitter.output)
    body = bytearray(bytes((1,3,0)))
    body.extend(arguments([191,pose['x'],pose['y']]) + call(emitter.call_table['xy_set'][0]))
    body.extend(emitter.syscall('PrimSetZ', (191,pose['z'])))
    body.extend(emitter.syscall('PrimSetRS', (191,pose['r'],1000)))
    for glob, value in ((157,pose['z']),(158,pose['z']),(159,pose['r']),(160,pose['r']),(161,pose['x']),(162,pose['y'])):
        body.extend(arguments([value]) + b'\x15' + struct.pack('<H',glob))
    for name, params in (('MotionAlphaStop',(190,)),('MotionAlphaStop',(191,)),
            ('PrimSetDraw',(190,0)),('PrimSetAlpha',(190,0)),('PrimSetAlpha',(191,0)),('PrimSetDraw',(191,1))):
        body.extend(emitter.syscall(name,params))
    # Original 859 decides defaults/settings and performs 4466. No extra
    # reveal, sleep or drawing frame is introduced between arm and transition.
    body.extend(stack(-4)+stack(-3)+stack(-2)+call(0xCF0E)+b'\x04')
    emitter.output.extend(body)
    specs = (*SPECS, WRAPPERS[resource])
    routes, cursor = {**stubs, 0xCF0E:shim}, len(emitter.output)
    for number, start, end, arity in specs:
        routes[start] = cursor
        cursor += end-start + (len(hidden_gate(emitter)) if number == 4173 else 0)
    copies = []
    for spec in specs:
        block, report = relocate(emitter,spec,routes[spec[1]],routes)
        emitter.output.extend(block)
        copies.append(report)
    struct.pack_into('<I', emitter.output, skip+1, len(emitter.output))
    wrapper = routes[WRAPPERS[resource][1]]
    emitter.helpers[key] = dict(wrapper=wrapper, shim=shim, shim_end=shim+len(body),
        keep_camera=keep_camera, skipped_camera_calls={str(k):v for k,v in stubs.items()}, pose=dict(pose), copies=copies,
        transition_owner='original_859', runtime_verified=False)
    return wrapper
