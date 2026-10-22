"""Own-EXE group insertion, unlink and primitive-kind conversion semantics.

GroupIn converts the destination to a group, unlinks the child, then appends
it. Reapplying a parent mapping is therefore NOT an ordered state restore.
This binding emits no mutation and grants no ownership of the root/group or
its children. Runtime child order and geometry still require actual capture.
"""
from .engine_patterns import engine_pattern

from copy import deepcopy
import hashlib
import re
import struct

from .native_import_size_discovery import _pe_sections
from .native_rotation_degrees import _registration,_code

SCHEMA = 'fvp-native-cg-primitive-group-semantics/1'
def _release_pattern_value__IN():
    return re.compile(engine_pattern('native_cg_primitive_groups:18:4'), re.DOTALL)
def _release_pattern_value__OUT():
    return re.compile(engine_pattern('native_cg_primitive_groups:22:4'), re.DOTALL)
def _release_pattern_value__INSERT_HEAD():
    return engine_pattern('native_cg_primitive_groups:25:4')
def _release_pattern_value__INSERT_MODERN():
    return re.compile(_release_pattern_value__INSERT_HEAD() + engine_pattern('native_cg_primitive_groups:31:4'), re.DOTALL)
def _release_pattern_value__INSERT_LEGACY():
    return re.compile(_release_pattern_value__INSERT_HEAD() + engine_pattern('native_cg_primitive_groups:37:4'), re.DOTALL)
def _release_pattern_value__UNLINK_MODERN():
    return re.compile(engine_pattern('native_cg_primitive_groups:43:4'), re.DOTALL)
def _release_pattern_value__UNLINK_LEGACY():
    return re.compile(engine_pattern('native_cg_primitive_groups:57:4'), re.DOTALL)
def _release_pattern_value__CREATE_HEAD():
    return engine_pattern('native_cg_primitive_groups:71:4')
def _release_pattern_value__CREATE_MODERN():
    return re.compile(_release_pattern_value__CREATE_HEAD() + engine_pattern('native_cg_primitive_groups:78:4'), re.DOTALL)
def _release_pattern_value__CREATE_LEGACY():
    return re.compile(_release_pattern_value__CREATE_HEAD() + engine_pattern('native_cg_primitive_groups:84:4'), re.DOTALL)


def _u32(raw):
    return struct.unpack('<I',raw)[0]


def _branches(match,pairs):
    result = []
    for name,label in pairs:
        target = len(match[0])-3 if label=='return' else match.start(label)
        destination = match.end(name)+struct.unpack('<b',match[name])[0]
        if destination!=target:
            raise ValueError('CG 原生分组函数包含未闭合的跳转。')
        result.append(dict(offset=match.start(name)-1,target=target))
    return result


class NativeCGPrimitiveGroups:
    def __init__(self,executable):
        if not isinstance(executable,bytes) or not executable:
            raise ValueError('CG 原生分组需要目标自身的程序。')
        self.executable = executable
        self.executable_sha256 = hashlib.sha256(executable).hexdigest()
        image,sections = _pe_sections(executable)
        registrations = {n:_registration(executable,image,sections,n,a)
                         for n,a in (('PrimGroupIn',2),('PrimGroupOut',1))}
        if len({r['registrar'] for r in registrations.values()})!=1:
            raise ValueError('CG 分组入口不属于同一份原生分派器。')
        windows = {}
        def exact(role,address,patterns,limit):
            offset,body = _code(executable,image,sections,address,limit)
            matches = [m for p in patterns if (m:=p.match(body)) is not None]
            if len(matches)!=1:
                raise ValueError('CG 原生分组完整函数未识别：'+role)
            match = matches[0]
            windows[role] = dict(address=address,offset=offset,length=match.end(),
                                sha256=hashlib.sha256(body[:match.end()]).hexdigest())
            return match
        incoming = exact('group_in',registrations['PrimGroupIn']['address'],[_release_pattern_value__IN()],len(_release_pattern_value__IN().pattern))
        outgoing = exact('group_out',registrations['PrimGroupOut']['address'],[_release_pattern_value__OUT()],len(_release_pattern_value__OUT().pattern))
        maximum = _u32(incoming['maximum'])
        if maximum!=_u32(outgoing['maximum']) or not 1<maximum<=32768:
            raise ValueError('CG 分组原生有符号图层范围不一致。')
        relative = lambda address,m,n:address+m.end(n)+struct.unpack('<i',m[n])[0]
        insertion = relative(registrations['PrimGroupIn']['address'],incoming,'delegate')
        unlink = relative(registrations['PrimGroupOut']['address'],outgoing,'delegate')
        ins = exact('insert',insertion,[_release_pattern_value__INSERT_MODERN(),_release_pattern_value__INSERT_LEGACY()],192)
        if relative(insertion,ins,'unlink')!=unlink:
            raise ValueError('CG 挂组和移出没有共用同一原生移除函数。')
        out = exact('unlink',unlink,[_release_pattern_value__UNLINK_MODERN(),_release_pattern_value__UNLINK_LEGACY()],192)
        creation = relative(insertion,ins,'create')
        create = exact('create',creation,[_release_pattern_value__CREATE_MODERN(),_release_pattern_value__CREATE_LEGACY()],192)
        if relative(creation,create,'unlink')!=unlink:
            raise ValueError('CG 组类型转换会调用另一份原生移除函数。')
        stride,array = ins['stride'][0],_u32(ins['array'])
        fields = {k:ins[k][0] for k in ('parent','previous','next','head','tail')}
        fields.update(x=create['x'][0],y=create['y'][0],auxiliary=create['auxiliary'][0])
        if (not 8<stride<128 or array<4 or array+maximum*stride>=2**31
                or out['stride'][0]!=stride or create['stride'][0]!=stride
                or _u32(out['array'])!=array or _u32(create['array'])!=array
                or len(set(fields.values()))!=len(fields)
                or any(not 6<o<=stride-2 for o in fields.values())
                or any(a+2>b for a,b in zip(sorted(fields.values()),sorted(fields.values())[1:]))):
            raise ValueError('CG 分组图元字段或数组布局不完整。')
        for name in ('parent','previous','next'):
            if out[name][0]!=fields[name]:
                raise ValueError('CG 分组插入和移出使用不同的成员字段。')
        for name in ('head','tail'):
            if create[name][0]!=fields[name]:
                raise ValueError('CG 分组类型转换使用不同的子图层字段。')
        for match,names in ((ins,('next',)),(out,('parent','previous','next','head','tail')),
                            (create,('next',))):
            for name in names:
                if _u32(match[name+'_absolute'])!=array+fields[name]:
                    raise ValueError('CG 分组数组读取和写入没有对应同一字段。')
        branches = dict(
            insert=_branches(ins,[('nonempty','append')]),
            unlink=_branches(out,[('unparented','return'),('has_previous','previous_link'),
                                  ('join','joined'),('has_next','next_link')]),
            create=_branches(create,[('same','end'),('not_group','assign'),('empty','finished'),
                                     ('back','loop'),('not_new_group','end')]))
        self._report = dict(schema=SCHEMA,executable_sha256=self.executable_sha256,
            registrations=registrations,source_windows=windows,complete_branches=branches,
            primitive_range=[1,maximum-1],parent_range=[0,maximum-1],
            primitive_stride=stride,primitive_array_offset=array,word_fields=fields,
            type_field=4,draw_field=5,flags_field=6,unparented_sentinel=-1,root_parent_allowed=0,
            group_kind=1,destination_converted_to_group_before_child_unlink=True,
            child_unlinked_before_tail_append=True,reinserted_child_appended_not_old_index=True,
            unlink_clears_parent_only_not_sibling_words=True,
            kind_change_from_group_detaches_existing_children=True,
            same_kind_group_preserves_existing_children=True,
            newly_converted_group_draw=1,newly_converted_group_xy=[0,0],
            inherited_sibling_order_capture_required=True,
            parent_map_alone_is_not_state_restore=True,native_calls_emitted=False,
            root_or_group_ownership_granted=False,original_membership_restored=False,
            primitive_properties_restored=False,original_images_restored=False,
            scene_export_connected=False,runtime_verified=False)
        self._initial_report = deepcopy(self._report)

    def validate(self,executable=None):
        raw = self.executable if executable is None else executable
        if hashlib.sha256(raw).hexdigest()!=self.executable_sha256:
            raise ValueError('CG 原生分组不是同一份程序。')
        if self._report!=self._initial_report:
            raise ValueError('CG 原生分组布局证据已经变化。')
        for row in self._report['source_windows'].values():
            if hashlib.sha256(raw[row['offset']:row['offset']+row['length']]).hexdigest()!=row['sha256']:
                raise ValueError('CG 原生分组函数证据已经变化。')

    def validate_pair(self,child,parent):
        self.validate()
        maximum = self._report['primitive_range'][1]
        if (type(child) is not int or type(parent) is not int
                or not 1<=child<=maximum or not 0<=parent<=maximum):
            raise ValueError('CG 子图层或父组超出目标自己的原生范围。')

    def report(self):
        self.validate()
        return deepcopy(self._report)


_RELEASE_PATTERN_FACTORIES = {'_IN': _release_pattern_value__IN, '_OUT': _release_pattern_value__OUT, '_INSERT_HEAD': _release_pattern_value__INSERT_HEAD, '_INSERT_MODERN': _release_pattern_value__INSERT_MODERN, '_INSERT_LEGACY': _release_pattern_value__INSERT_LEGACY, '_UNLINK_MODERN': _release_pattern_value__UNLINK_MODERN, '_UNLINK_LEGACY': _release_pattern_value__UNLINK_LEGACY, '_CREATE_HEAD': _release_pattern_value__CREATE_HEAD, '_CREATE_MODERN': _release_pattern_value__CREATE_MODERN, '_CREATE_LEGACY': _release_pattern_value__CREATE_LEGACY}
def __getattr__(name):
    factory = _RELEASE_PATTERN_FACTORIES.get(name)
    if factory is None:
        raise AttributeError(name)
    return factory()
