"""Finite scalar contents of private script tables, derived from every write.

This is a whole-candidate may-value analysis, not an immutable table snapshot.
Mutable/aliased tables and unknown writes never supply branch facts. Calls only
forward scalar argument constraints; native return values stay unknown.
"""
from .engine_patterns import engine_pattern

from collections import defaultdict
import hashlib
import re
import struct

from .native_legacy_size_discovery import _function


def bind_native_table_scalar_access(raw, image, sections, addresses, fields, release):
    """Recognize the actual table read/move paths in the target opcode table.

Unsupported opcode implementations simply supply no table facts. The existing
stack analysis still runs in that case, without this optional precision.
    """
    def body(op):
        offset, code = _function(raw, image, sections, addresses[op])
        end = min((a-addresses[op] for a in addresses
                   if addresses[op] < a < addresses[op]+len(code)), default=len(code))
        return offset, code[:end].rstrip(b'\xcc')
    sp, pc = (re.escape(struct.pack('<I', fields[k])) for k in ('sp','pc'))
    get_prefix = (engine_pattern('native_cg_table_values:27:18')+sp+engine_pattern('native_cg_table_values:27:46')+pc+engine_pattern('native_cg_table_values:28:34')+pc+
                  engine_pattern('native_cg_table_values:29:18'))
    get_pattern = (get_prefix+engine_pattern('native_cg_table_values:30:30'))
    get_at, get_code = body(17)
    get = re.fullmatch(get_pattern, get_code, re.DOTALL)
    if get is None:
        return None
    target = lambda address, match, name: address+match.end(name)+struct.unpack('<i',match[name])[0]
    if target(addresses[17],get,'release') != release:
        return None
    globals_ = re.escape(get['globals']); pool = re.escape(get['pool'])
    set_prefix = (engine_pattern('native_cg_table_values:43:18')+sp+engine_pattern('native_cg_table_values:43:54')+sp+engine_pattern('native_cg_table_values:44:36')+pc+
        engine_pattern('native_cg_table_values:45:8')+pc)
    modern = (engine_pattern('native_cg_table_values:46:14')+globals_+engine_pattern('native_cg_table_values:46:50')+pool+engine_pattern('native_cg_table_values:50:30'))
    older = (engine_pattern('native_cg_table_values:52:13')+globals_+engine_pattern('native_cg_table_values:52:35')+pool+engine_pattern('native_cg_table_values:56:30'))
    end = (engine_pattern('native_cg_table_values:58:11'))
    put_at, put_code = body(23)
    put = (re.fullmatch(set_prefix+modern+end,put_code,re.DOTALL)
           or re.fullmatch(set_prefix+older+end,put_code,re.DOTALL))
    if put is None or any(target(addresses[23],put,k) != release
                          for k in ('release1','release2','release3','release4')):
        return None
    # The read helper is the target's own binary search over scalar cells.
    find = target(addresses[17],get,'find')
    find_at, find_code = _function(raw,image,sections,find)
    patterns = (
        '535556578b790833db83ef01895904782c8b69108d041f992bc2d1f8'
        '8d14408d7495008941048b56083b54241474177d058d5801eb038d78ff'
        '3bfb7dd75f5e5d33c05bc204005f8bc65e5d5bc20400',
        '535556578b790433db4f89590c78308b69108d041f992bc2d1f8'
        '8d14408d74950089410c8b56083b542414741b3b5424147d058d5801'
        'eb038d78ff3bfb7dd35f5e5d33c05bc204005f8bc65e5d5bc20400')
    matched = next((bytes.fromhex(p) for p in patterns
                    if find_code.startswith(bytes.fromhex(p))),None)
    if matched is None:
        return None
    return dict(read_address=addresses[17],write_address=addresses[23],find_address=find,
        read_sha256=hashlib.sha256(get_code).hexdigest(),
        write_sha256=hashlib.sha256(put_code).hexdigest(),
        find_sha256=hashlib.sha256(matched).hexdigest(),
        missing_or_non_table_read_is_nil=True,stored_scalar_type_and_value_preserved=True)


_NIL = ('nil',)
_TRUE = ('true',)
_BINARY = {'add','sub','mul','div','mod','bit_test','and','or','set_e','set_ne',
           'set_l','set_le','set_g','set_ge'}


def infer_scalar_table_values(instructions, syscalls, *, instruction_resolver=None, external_entries=()):
    """Infer over all actual functions and all writes, including copied code.

Facts are finite unions of primitive literals and formal-argument references.
None is top. No arithmetic, native result, mutable table value or global value
is folded. Aliases, unknown producers and parameter cycles without an external
literal source invalidate a table's finite contents.
    """
    code = {i.offset:i for i in instructions}
    resolve = instruction_resolver or code.get
    entries = {pc:i for pc,i in code.items() if i.mnemonic == 'init_stack'}
    escaped = {i.operands['value'] for i in code.values()
               if i.mnemonic in {'push_global','pop_global'}}
    writes = {pc:None for pc,i in code.items() if i.mnemonic == 'pop_global_table'}
    calls = {pc:None for pc,i in code.items() if i.mnemonic == 'call'}
    seen_writes,seen_calls = set(),set()
    def union(a,b):
        return None if a is None or b is None else a|b
    def record(bank,seen,pc,value):
        bank[pc] = union(bank[pc],value) if pc in seen else value
        seen.add(pc)
    def merge(a,b):
        if len(a[0])!=len(b[0]) or len(a[1])!=len(b[1]):
            raise ValueError('inconsistent candidate frame')
        return tuple(tuple(union(x,y) for x,y in zip(left,right)) for left,right in zip(a,b))
    for entry,first in entries.items():
        argc,local = first.operands['args'],first.operands['locals']
        if not 0<=argc<=127 or not 0<=local<=127:
            return {},dict(reason='unknown_frame')
        initial = ((),tuple(frozenset({('argument',entry,n)}) for n in range(argc))+(None,)*local)
        pending=[(entry+first.size,initial)]; states={}
        try:
            while pending:
                pc,state=pending.pop()
                if pc in states:
                    state=merge(states[pc],state)
                    if state==states[pc]:continue
                states[pc]=state
                i=resolve(pc)
                if i is None or not i.known or i.warning or i.dirty:
                    raise ValueError('unknown candidate instruction')
                name=i.mnemonic; stack=list(state[0]); slots=list(state[1])
                def pop(count=1):
                    if len(stack)<count:raise ValueError('candidate operand underflow')
                    result=stack[-count:] if count else []
                    if count:del stack[-count:]
                    return result
                def slot():
                    n=i.operands['value']
                    if not (0<=n<local or -argc-1<=n<=-2):raise ValueError('candidate slot')
                    return argc+n if n>=0 else argc+1+n
                if name in {'push_i8','push_i16','push_i32'}:
                    stack.append(frozenset({('integer',i.operands['value'])}))
                elif name in {'push_nil','push_true'}:
                    stack.append(frozenset({_NIL if name=='push_nil' else _TRUE}))
                elif name in {'push_f32','push_string','push_global','push_return'}:
                    stack.append(None)
                elif name=='push_stack':stack.append(slots[slot()])
                elif name=='pop_stack':slots[slot()]=pop()[0]
                elif name=='push_top':
                    if not stack:raise ValueError('candidate duplicate underflow')
                    stack.append(stack[-1])
                elif name in {'push_global_table','push_local_table','neg'}:
                    pop(); stack.append(None)
                elif name in _BINARY:
                    pop(2); stack.append(None)
                elif name in {'pop_global','jz'}:pop()
                elif name in {'pop_global_table','pop_local_table'}:
                    _,value=pop(2)
                    if name=='pop_global_table':record(writes,seen_writes,pc,value)
                    else:slots[slot()]=None
                elif name in {'call','syscall'}:
                    if name=='call':
                        target=i.operands['target']; header=resolve(target)
                        if header is None or header.mnemonic!='init_stack':raise ValueError('candidate callee')
                        count=header.operands['args']; values=tuple(pop(count))
                        if pc in seen_calls:
                            values=tuple(union(a,b) for a,b in zip(calls[pc],values))
                        calls[pc]=values; seen_calls.add(pc)
                    else:pop(syscalls[i.operands['id']].args)
                elif name in {'ret','retv'}:continue
                elif name not in {'nop','jmp'}:raise ValueError('unknown candidate stack effect')
                out=(tuple(stack),tuple(slots))
                if name in {'jmp','jz'}:
                    pending.append((i.operands['target'],out))
                    if name=='jmp':continue
                pending.append((pc+i.size,out))
        except (ValueError,KeyError,IndexError) as error:
            # A partial value inventory must never authorize pruning.
            return {},dict(reason='incomplete_candidate_value_flow',entry=entry,
                           instruction=pc,detail=str(error))
    constraints=defaultdict(set)
    unknown={('argument',entry,n) for entry in external_entries if entry in entries
             for n in range(entries[entry].operands['args'])}
    for pc in seen_calls:
        values=calls[pc]
        i=resolve(pc); target=i.operands['target']; count=resolve(target).operands['args']
        for n in range(count):
            key=('argument',target,n)
            if values is None or values[n] is None:unknown.add(key)
            else:constraints[key].update(values[n])
    def concrete(facts):
        if facts is None:return None
        pending=list(facts); visited=set(); result=set()
        while pending:
            fact=pending.pop()
            if fact[0]!='argument':result.add(fact);continue
            if fact in unknown or fact not in constraints:return None
            if fact in visited:continue
            visited.add(fact);pending.extend(constraints[fact])
        return frozenset(result) if result else None
    tables={}; rejected=set(escaped)
    for pc in seen_writes:
        facts=writes[pc]
        slot=resolve(pc).operands['value']; values=concrete(facts)
        if values is None:rejected.add(slot)
        else:tables[slot]=tables.get(slot,frozenset({_NIL}))|values
    tables={slot:values for slot,values in tables.items() if slot not in rejected}
    return tables,dict(functions_scanned=len(entries),table_write_sites=len(seen_writes),
        unreachable_call_sites=len(calls)-len(seen_calls),
        unreachable_table_writes=len(writes)-len(seen_writes),
        closed_table_count=len(tables),escaped_or_unknown_tables=len(rejected),
        all_candidate_table_writes_included=True,syscall_results_used=False,
        tables={str(slot):[dict(kind=f[0],**({'value':f[1]} if len(f)==2 else {}))
                          for f in sorted(values)] for slot,values in sorted(tables.items())})
