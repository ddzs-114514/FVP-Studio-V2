"""Whole reachable HCB frame/operand stack accounting, never scheduler proof.

Jumps can share a tail or skip inline libraries, so function summaries follow
instruction boundaries rather than contiguous INIT-to-INIT file ranges.
Calls are summarized per incoming parameter facts. Only a separately bound
own-EXE INT/INT comparison can prune integer conditions. Unknown recursion
still fails closed. Only non-escaping tables whose complete candidate writes
have finite primitive contents can contribute table-read facts.
"""
from dataclasses import dataclass
import hashlib
import struct
from .native_cg_table_values import infer_scalar_table_values

SCHEMA = "fvp-native-cg-stack-usage/2"
_PUSH = {"push_nil","push_true","push_i32","push_i16","push_i8","push_f32",
         "push_string","push_global","push_stack","push_return"}
_BINARY = {"add","sub","mul","div","mod","bit_test","and","or",
           "set_e","set_ne","set_g","set_ge","set_l","set_le"}


class CGStackUsageError(ValueError):
    def __init__(self,message,context):
        super().__init__(message)
        self.context = context


@dataclass
class _Summary:
    entry: int
    argc: int
    locals: int
    extra_peak: int
    operand_peak: int
    instruction_heights: dict
    calls: dict
    syscalls: set
    arguments: tuple
    constant_conditions: list
    original_cycles_deferred: bool = False


_UNKNOWN = ("unknown",)
_NIL = ("nil",)
_TRUE = ("true",)


@dataclass(frozen=True)
class _State:
    stack: tuple
    slots: tuple
    returned: tuple = _UNKNOWN


def _join(left, right):
    if len(left.stack) != len(right.stack) or len(left.slots) != len(right.slots):
        raise ValueError("CG 分支／循环接回时的栈高度不同，不能安全保存原剧情参数。")
    merge = lambda a,b: a if a == b else _UNKNOWN
    return _State(tuple(merge(a,b) for a,b in zip(left.stack,right.stack)),
                  tuple(merge(a,b) for a,b in zip(left.slots,right.slots)),
                  merge(left.returned,right.returned))


def _public(fact):
    if fact[0] == 'alternatives':
        return dict(kind='alternatives',values=[_public(f) for f in fact[1]])
    return dict(kind=fact[0], **({"value":fact[1]} if fact[0] == "integer" else {}))


def bind_cg_stack_usage(instructions,syscalls,roots,capacity,*,syscall_arities=None,
                        native_syscall_arities_bound=False,external_root_stack_proven=False,
                        instruction_resolver=None,native_integer_conditions_bound=False,
                        native_primitive_equality_results=None,thread_start_syscall_id=None,
                        native_table_scalar_access_bound=False,
                        deferred_source_calls=None,source_function_origins=None):
    if type(capacity) is not int or not 1 <= capacity < 2**16:
        raise ValueError("CG 栈容量必须来自本游戏已确认的原生存储区。")
    if any(type(value) is not bool for value in (native_syscall_arities_bound,
            external_root_stack_proven,native_integer_conditions_bound,native_table_scalar_access_bound)):
        raise ValueError("原生栈分析的已确认条件必须明确为布尔值。")
    if instruction_resolver is not None and not callable(instruction_resolver):
        raise ValueError("CG 实际指令读取器必须能核对已到达的来源位置。")
    if ((deferred_source_calls is None) != (source_function_origins is None)
            or deferred_source_calls is not None and (
                type(deferred_source_calls) is not dict or type(source_function_origins) is not dict)):
        raise ValueError('原作循环续作必须同时提供实际调用位置和原函数来源。')
    equality = {"2,2":"integer_value"} if native_integer_conditions_bound else {}
    if native_primitive_equality_results is not None:
        expected = {str(a)+","+str(b) for a in range(3) for b in range(3)}
        if (not native_integer_conditions_bound or type(native_primitive_equality_results) is not dict
                or set(native_primitive_equality_results) != expected
                or any(v not in {"always_equal","never_equal","integer_value"} for v in native_primitive_equality_results.values())
                or any(v == "integer_value" and k != "2,2" for k,v in native_primitive_equality_results.items())):
            raise ValueError("CG 基础类型条件没有完整的本机 NIL／TRUE／INT 比较结果。")
        equality = dict(native_primitive_equality_results)
    code = {}
    for item in instructions:
        if item.offset in code and item != code[item.offset]:
            raise ValueError("CG 栈分析遇到同一位置的不同指令。")
        code[item.offset] = item
    if not code:
        raise ValueError("CG 栈分析没有可执行指令。")
    offsets = sorted(code)
    # No overlapping opcode spans, even when several CFGs share instructions.
    for left,right in zip(offsets,offsets[1:]):
        if left+code[left].size > right:
            raise ValueError("CG 栈分析的指令边界重叠。")
    supplied = {n:desc.args for n,desc in enumerate(syscalls)}
    arities = dict(supplied if syscall_arities is None else syscall_arities)
    if syscall_arities is not None and any(supplied.get(n) != count for n,count in arities.items()):
        raise ValueError("脚本与原生分派的参数数量不一致，不能据此计算栈空间。")
    if thread_start_syscall_id is not None:
        sid = thread_start_syscall_id
        if (type(sid) is not int or not 0 <= sid < len(syscalls) or sid > 0x7fff
                or syscalls[sid].name != "ThreadStart" or arities.get(sid) != 2):
            raise ValueError("CG 线程入口发现必须绑定本目标的双参数启动调用。")
    selected = tuple(sorted(set(roots)))
    if not selected:
        raise ValueError("CG 栈分析缺少真正的线程／场景入口。")
    table_values,table_report = ({},None)
    if native_table_scalar_access_bound and native_primitive_equality_results is not None:
        table_values,table_report = infer_scalar_table_values(code.values(),syscalls,
            instruction_resolver=instruction_resolver,external_entries=selected)
    summaries,active,call_path = {},[],[]
    deferred_cycles = {}
    callback_entries,callback_sites = set(),set()
    def instruction(pc):
        item = code.get(pc) if instruction_resolver is None else instruction_resolver(pc)
        if item is not None and item.offset != pc:
            raise ValueError("CG 实际指令读取器返回了其他位置的指令。")
        return item
    def header(entry):
        item = instruction(entry)
        if item is None or item.mnemonic != "init_stack" or not item.known or item.warning or item.dirty:
            raise ValueError("CG 调用没有本机已解析的独立栈帧入口。")
        argc,local = item.operands["args"],item.operands["locals"]
        if any(type(n) is not int or not 0 <= n <= 127 for n in (argc,local)):
            raise ValueError("CG 参数／局部数量超出原生 signed-byte 范围。")
        return item,argc,local
    def profile(entry,arguments):
        key = (entry,arguments)
        if key in summaries:
            return summaries[key]
        if key in active:
            start = active.index(key)
            cycle = [a[0] for a in active[start:]]+[entry]
            calls = call_path[start:]
            origins = [source_function_origins.get(a) for a in cycle] if source_function_origins is not None else []
            if (origins and all(a is not None for a in origins) and len(calls)==len(cycle)-1
                    and all(deferred_source_calls.get(pc)==(left,right)
                            for pc,left,right in zip(calls,origins,origins[1:]))):
                _,argc,local = header(entry)
                deferred_cycles[(tuple(cycle),tuple(calls))] = dict(
                    candidate_cycle=cycle,source_cycle=origins,call_sites=list(calls),
                    maximum_depth_proven=False,requires_runtime_confirmation=True)
                # This is NOT a bound on the old recursive path. Propagate the
                # deferred flag to every caller and suppress its bound fields.
                # The remaining CFG still checks stack effects and new edges.
                return _Summary(entry,argc,local,0,0,{}, {},set(),arguments,[],True)
            raise CGStackUsageError("CG 调用链存在递归，需要先确定原生最大深度，不能假定栈不会满。",
                dict(kind="recursive_call",entry=entry,active_call_entries=[a[0] for a in active],
                     argument_facts=[_public(f) for f in arguments],
                     cycle=[a[0] for a in active[active.index(key):]]+[entry]))
        if len(active) >= capacity:
            # Each active CALL owns at least one native metadata cell. This
            # limit comes from physical capacity, not an invented depth.
            raise CGStackUsageError("CG 调用帧数量已经超过原生栈容量。",
                dict(kind="frame_depth_over_capacity",entry=entry,capacity=capacity,
                     active_call_entries=[a[0] for a in active]))
        first,argc,local = header(entry)
        if len(arguments) != argc:
            raise ValueError("CG 参数事实与原生调用帧的参数数量不同。")
        active.append(key)
        frame_base = 1+local
        if argc+frame_base > capacity:
            raise ValueError("CG 原生栈空间不足，连入口参数、元数据与局部值也放不下。")
        heights,callees,used,states = {},{},set(),{}
        pending = [(entry+first.size,_State((),arguments+(_UNKNOWN,)*local))]
        conditions = set()
        peak,operand_peak,returns = frame_base,0,0
        deferred = False
        while pending:
            pc,state = pending.pop()
            if pc in states:
                joined = _join(states[pc],state)
                if joined == states[pc]:
                    continue
                state = joined
            states[pc] = state
            height = len(state.stack)
            item = instruction(pc)
            if item is None or not item.known or item.warning or item.dirty:
                raise ValueError("CG 栈分析遇到未绑定或已变化的控制指令。")
            if item.mnemonic == "init_stack":
                raise ValueError("CG 跳转直接进入另一栈帧，必须使用原生 CALL。")
            heights[pc] = height
            name,next_pc = item.mnemonic,pc+item.size
            operands,slots = list(state.stack),list(state.slots)
            returned,condition = state.returned,_UNKNOWN
            peak = max(peak,frame_base+height)
            operand_peak = max(operand_peak,height)
            need,delta = 0,0
            if name == "push_stack" or name == "pop_stack" or name in {"push_local_table","pop_local_table"}:
                index = item.operands["value"]
                if not (0 <= index < local or -argc-1 <= index <= -2):
                    raise ValueError("CG 读写了未声明的参数、局部值或调用帧元数据。")
            if name in _PUSH:
                delta = 1
            elif name == "push_top":
                need,delta = 1,1
            elif name in {"pop_global","pop_stack","jz"}:
                need,delta = 1,-1
            elif name in {"push_global_table","push_local_table","neg"}:
                need = 1
            elif name in {"pop_global_table","pop_local_table"}:
                need,delta = 2,-2
            elif name in _BINARY:
                need,delta = 2,-1
            elif name == "call":
                target = item.operands["target"]
                _,count,_ = header(target)
                if height < count:
                    raise ValueError("CG 表达式栈缺少参数，不能从原调用帧借用值。")
                call_path.append(pc)
                try:
                    child = profile(target,tuple(operands[-count:]) if count else ())
                finally:
                    call_path.pop()
                deferred = deferred or child.original_cycles_deferred
                need,delta = count,-count
                peak = max(peak,frame_base+height+child.extra_peak)
                callees[pc] = (target,max(callees.get(pc,(target,0))[1],child.extra_peak))
            elif name == "syscall":
                sid = item.operands["id"]
                if not 0 <= sid <= 0x7fff or sid not in arities:
                    raise ValueError("CG 系统调用缺少已确认的参数数量。")
                count = arities[sid]
                if type(count) is not int or not 0 <= count <= 127:
                    raise ValueError("CG 系统调用参数数量超出已确认的范围。")
                need,delta = count,-count
                used.add(sid)
            elif name in {"ret","retv"}:
                if height != (1 if name == "retv" else 0):
                    raise ValueError("CG 返回时还有多余／缺少的表达式，会破坏原生局部或参数释放。")
                returns += 1
                continue
            elif name not in {"nop","jmp"}:
                raise ValueError("CG 指令的原生栈作用尚未确认："+name)
            if height < need:
                raise ValueError("CG 表达式栈缺少参数，不能从原调用帧借用值。")
            if name == "syscall" and item.operands["id"] == thread_start_syscall_id:
                # A wrapper may forward the pointer through PUSH_STACK and
                # CALL. Do not rely on the parser's adjacent-literal role, or
                # root every ordinary function in that wrapper's clone graph.
                pointer = operands[-1]
                if pointer[0] != "integer":
                    raise CGStackUsageError("CG 已到达的线程启动缺少确定的原生回调入口。",
                        dict(kind="unknown_thread_callback",entry=entry,instruction=pc,
                             syscall_id=thread_start_syscall_id,callback_fact=_public(pointer)))
                destination = pointer[1]
                _,count,_ = header(destination)
                if count != 0:
                    raise ValueError("CG 线程回调必须使用零参数入口，普通函数不能当成外部线程。")
                callback_entries.add(destination)
                callback_sites.add((pc,destination))
            if name in _PUSH:
                if name == "push_nil": fact = _NIL
                elif name == "push_true": fact = _TRUE
                elif name == "push_stack":
                    index = item.operands["value"]
                    fact = slots[argc+index if index >= 0 else argc+1+index]
                elif name == "push_return":
                    fact,returned = returned,_NIL  # native move/nil, not a clone
                elif name in {"push_i8","push_i16","push_i32"} and native_integer_conditions_bound:
                    value = item.operands["value"]
                    fact = ("integer",value) if type(value) is int and -(2**31) <= value < 2**31 else _UNKNOWN
                else: fact = _UNKNOWN
                operands.append(fact)
            elif name == "push_top":
                operands.append(operands[-1])
            elif name in {"pop_global","pop_stack","jz"}:
                fact = operands.pop()
                if name == "pop_stack":
                    index = item.operands["value"]
                    slots[argc+index if index >= 0 else argc+1+index] = fact
                elif name == "jz":
                    if fact[0] == 'alternatives':
                        nils = [v == _NIL for v in fact[1]]
                        condition = _NIL if all(nils) else _UNKNOWN if any(nils) else _TRUE
                    else: condition = fact
            elif name in {"push_global_table","push_local_table","neg"}:
                values = table_values.get(item.operands.get('value')) if name=='push_global_table' else None
                operands[-1] = ((next(iter(values)) if len(values)==1 else ('alternatives',tuple(sorted(values))))
                                if values else _UNKNOWN)
            elif name in {"pop_global_table","pop_local_table"}:
                del operands[-2:]
                if name == "pop_local_table":
                    index = item.operands["value"]
                    slots[argc+index if index >= 0 else argc+1+index] = _UNKNOWN
            elif name in _BINARY:
                right,left = operands.pop(),operands.pop()
                fact = _UNKNOWN
                if name in {"set_e","set_ne"}:
                    tags = {"nil":0,"true":1,"integer":2}
                    outcomes=set()
                    for a in (left[1] if left[0]=='alternatives' else (left,)):
                        for b in (right[1] if right[0]=='alternatives' else (right,)):
                            pair = str(tags.get(a[0],-1))+","+str(tags.get(b[0],-1))
                            mode = equality.get(pair)
                            if mode is None:outcomes.add(_UNKNOWN)
                            else:
                                equal = a[1] == b[1] if mode == "integer_value" else mode == "always_equal"
                                outcomes.add(_TRUE if (equal if name == "set_e" else not equal) else _NIL)
                    if len(outcomes)==1:fact=next(iter(outcomes))
                operands.append(fact)
            elif name in {"call","syscall"}:
                if need: del operands[-need:]
                returned = _UNKNOWN  # no guessed callee/engine return value
            after = height+delta
            if len(operands) != after:
                raise ValueError("CG 参数事实与物理表达式栈的作用不一致。")
            next_state = _State(tuple(operands),tuple(slots),returned)
            peak = max(peak,frame_base+after)
            operand_peak = max(operand_peak,after)
            if argc+peak > capacity:
                raise CGStackUsageError("CG 原生栈空间不足，不能再插入暂停／场景转接函数。",
                    dict(entry=entry,instruction=pc,mnemonic=name,args=argc,locals=local,
                         operand_height=height,peak_cells_from_zero_entry=argc+peak,capacity=capacity,
                         active_call_entries=[a[0] for a in active],callee=callees.get(pc),
                         callees={at:dict(entry=dest,extra_peak=extra)
                                  for at,(dest,extra) in callees.items()}))
            if name in {"jmp","jz"}:
                if name == "jmp" or condition in {_NIL,_UNKNOWN}:
                    pending.append((item.operands["target"],next_state))
                if name == "jz" and condition != _UNKNOWN:
                    conditions.add((pc,condition,item.operands["target"] if condition == _NIL else next_pc))
                if name == "jmp":
                    continue
                if condition == _NIL:
                    continue
            pending.append((next_pc,next_state))
        active.pop()
        # An intentional worker loop need not RET, but every known instruction
        # still needs stable stack height and every nested CALL must be bound.
        result = _Summary(entry,argc,local,peak,operand_peak,heights,callees,used,arguments,
            [dict(instruction=pc,condition=_public(fact),selected_target=target)
             for pc,fact,target in sorted(conditions)],deferred)
        summaries[key] = result
        return result
    requirements = []
    pending_roots,checked_roots = set(selected),set()
    while pending_roots:
        entry = min(pending_roots)
        pending_roots.remove(entry)
        _,count,_ = header(entry)
        if thread_start_syscall_id is not None and count != 0:
            raise ValueError("CG 真正的线程／场景入口必须是零参数函数。")
        summary = profile(entry,(_UNKNOWN,)*count)
        requirements.append(dict(entry=entry,args=summary.argc,locals=summary.locals,
            peak_cells_from_zero_entry=None if summary.original_cycles_deferred else summary.argc+summary.extra_peak,
            extra_peak_above_incoming_SP=None if summary.original_cycles_deferred else summary.extra_peak,
            original_cycle_depth_deferred=summary.original_cycles_deferred,
            external_entry_SP_assumed=summary.argc))
        checked_roots.add(entry)
        pending_roots.update(callback_entries-checked_roots)
    used = sorted(set().union(*(s.syscalls for s in summaries.values())))
    functions = {}
    for s in summaries.values():
        row = functions.setdefault(s.entry,dict(args=s.argc,locals=s.locals,
            extra_peak_above_incoming_SP=0,operand_peak=0,instruction_heights={},callees={},specializations=[]))
        row["extra_peak_above_incoming_SP"] = max(row["extra_peak_above_incoming_SP"],s.extra_peak)
        row["operand_peak"] = max(row["operand_peak"],s.operand_peak)
        for pc,height in s.instruction_heights.items():
            row["instruction_heights"][pc] = max(row["instruction_heights"].get(pc,0),height)
        row["callees"].update({at:dest for at,(dest,_) in s.calls.items()})
        row["specializations"].append(dict(arguments=[_public(f) for f in s.arguments],
            extra_peak_above_incoming_SP=None if s.original_cycles_deferred else s.extra_peak,
            original_cycle_depth_deferred=s.original_cycles_deferred,instruction_count=len(s.instruction_heights),
            instruction_height_sha256=hashlib.sha256(b"".join(struct.pack("<II",pc,height)
                for pc,height in sorted(s.instruction_heights.items()))).hexdigest(),
            constant_conditions=s.constant_conditions))
    for row in functions.values():
        if any(s['original_cycle_depth_deferred'] for s in row['specializations']):
            row['extra_peak_above_incoming_SP'] = None
    # The booleans describe proof INPUTS; a header alone is never native arity
    # proof, and a hypothetical zero-entry calculation is not a scheduler bind.
    return dict(schema=SCHEMA,stack_capacity_cells=capacity,root_requirements=requirements,
        initial_root_entries=list(selected),discovered_thread_callback_entries=sorted(callback_entries),
        thread_callback_sites=[dict(instruction=pc,entry=dest) for pc,dest in sorted(callback_sites)],
        reached_ThreadStart_callback_discovery_enabled=thread_start_syscall_id is not None,
        maximum_relative_peak_cells=None if deferred_cycles else max(r["peak_cells_from_zero_entry"] for r in requirements),
        function_count=len(functions),specialization_count=len(summaries),
        instruction_count=sum(len(s["instruction_heights"]) for s in functions.values()),
        used_syscall_ids=used,syscall_arity_basis="native_bound" if native_syscall_arities_bound else "source_header_only",
        native_syscall_arities_bound=native_syscall_arities_bound,
        external_root_stack_proven=external_root_stack_proven,
        native_integer_parameter_conditions_bound=native_integer_conditions_bound,
        native_primitive_equality_results=equality,
        complete_primitive_equality_table_bound=native_primitive_equality_results is not None,
        function_instruction_heights_are_context_maxima=True,
        global_syscall_and_object_value_facts_used=False,
        closed_scalar_table_values_used=bool(table_values),
        closed_scalar_table_values=table_report,
        recursive_contexts_must_have_proven_finite_expansion=not bool(deferred_cycles),
        preserved_original_cycles_deferred=list(deferred_cycles.values()),
        relative_frame_and_operand_heights_bound=not bool(deferred_cycles),
        complete_native_stack_bound=not deferred_cycles and native_syscall_arities_bound and external_root_stack_proven,
        functions=functions,runtime_verified=False,scene_export_connected=False)
