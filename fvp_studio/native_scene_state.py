"""Reuse the paired native state bridge for ordinary, non-CG scenes.

Binding only reads the registered target. Generated EXE/HCB bytes may enter a
fresh test copy together; no original file is changed. CG loading, geometry
and presentation are deliberately NOT prerequisites for this restoration.
"""
from copy import deepcopy

from .hoshimemo_scene_hook import _push_global, _pop_global
from .native_background_layers import NativeBackgroundLayers
from .native_cg_motion_quiescence import CHANNELS
from .native_cg_motion_stop_binding import NativeCGMotionStopBinding
from .native_cg_original_resource_journal import NativeCGOriginalResourceJournal
from .native_cg_primitive_groups import NativeCGPrimitiveGroups
from .native_cg_scene_thread_image import NativeCGSceneThreadImage
from .native_cg_snapshot_storage import NativeCGSnapshotStorage
from .native_cg_thread_handoff import NativeCGThreadHandoff
from .native_cg_thread_slots import NativeCGThreadSlots
from .native_portrait_dialogue import NativePortraitDialogue
from .native_portrait_slots import NativePortraitSlots
from .native_script_state import NativeScriptStateClosure


SCHEMA = "fvp-native-scene-state/1"


class NativeSceneState:
    def __init__(self, target):
        self.target, self.context = target, target.context
        self.source, self.analysis = self.context.document, self.context.analysis_document
        executable = (target.root / target.executable).read_bytes()
        self.thread_handoff = NativeCGThreadHandoff(self.context, executable)
        self.snapshot_storage = NativeCGSnapshotStorage(self.thread_handoff)
        self.thread_slots = NativeCGThreadSlots(self.context, self.thread_handoff)
        self.native_groups = NativeCGPrimitiveGroups(executable)
        self.layers = NativeBackgroundLayers(self.context)
        self.catalog = NativePortraitSlots(self.source, self.analysis, target.discovery,
            with_handle_flow=True, runtime_context=self.context)
        primitives = {r['primitive'] for r in self.layers.layers.values()}
        graphs = {r['graph'] for r in self.layers.layers.values()}
        parts = set()
        for slot in self.catalog.slots:
            handles = slot.evidence['dispatcher_handles']
            primitives.update(handles['primitive_ids'])
            graphs.update(handles['graph_ids'])
            parts.update(handles['parts_ids'])
        if 0 in primitives:
            raise ValueError("普通场景不能将原生全局图层 0 当作自己的角色或背景。")
        self.primitives, self.graphs = tuple(sorted(primitives)), tuple(sorted(graphs))
        self.original_graph_journal = NativeCGOriginalResourceJournal(
            self.thread_handoff, self.snapshot_storage, self.graphs, parts=sorted(parts))
        self.channels = {}
        table = self.thread_handoff.table
        reviewed = {name for start, _, stop in CHANNELS.values()
                    for name in (start, stop, start + 'Test')} | {'MotionPause'}
        unknown = sorted(n for n in table if n.startswith('Motion') and n not in reviewed)
        if unknown:
            raise ValueError("普通场景状态恢复尚未配对这些原生动画：" + "、".join(unknown))
        for name, (start, arities, stop) in CHANNELS.items():
            if start not in table:
                continue
            if table[start][1] not in arities or table.get(stop, (None, None))[1] != 1:
                raise ValueError("普通场景状态恢复的动画通道未配对：" + start)
            self.channels[name] = dict(start=start, start_arity=table[start][1],
                stop=stop, stop_arity=1, stop_syscall_id=table[stop][0])
        self.motion_binding = NativeCGMotionStopBinding(executable, self.channels)
        self.motion_binding.validate(self.channels, self.primitives)
        backend = self.layers.backend
        roots = [backend.primary_target, backend.dissolve_target]
        if backend.blur_target is not None:
            roots.append(backend.blur_target)
        self.background_state = NativeScriptStateClosure(self.source, self.analysis,
            sorted(set(roots)), runtime_context=self.context)
        lifecycle = self.catalog.compile_known_entry_lifecycle(self.source)
        ids = sorted(set(lifecycle['report']['global_ids']) | set(self.background_state.global_ids))
        self.snapshot = self.snapshot_storage.reserve(dict(
            snapshot=b''.join(_push_global(g) for g in ids),
            restore=b''.join(_pop_global(g) for g in reversed(ids)),
            report=dict(global_ids=ids)), 'original_non_cg_scene_globals')
        self.output = self.guard = self.dialogue = None
        self.thread_cleanups = []
        self.thread_image_report = None
        self.check_unchanged()

    def start(self, output):
        if self.output is not None or not isinstance(output, bytearray) or output != b'\x01\0\0':
            raise ValueError("普通场景状态恢复需要尚未使用的独立原生函数入口。")
        self.output = output
        output.extend(self.snapshot['snapshot'])

    def bind_camera(self, camera):
        from .native_scene_dialogue_guard import NativeSceneDialogueGuard
        if self.output is None or self.guard is not None:
            raise ValueError("普通场景的台词保护不能重复绑定。")
        self.guard = NativeSceneDialogueGuard(self.context, primitives=self.primitives,
            graphs=self.graphs, thread_slots=self.thread_slots, camera=camera)

    def bind_retained_scene(self, portraits):
        if self.guard is None or self.dialogue is not None:
            raise ValueError("普通场景的台词线程必须先绑定，再接入一次。")
        if portraits is not None:
            if portraits.loader.catalog is not self.catalog:
                raise ValueError("普通场景的角色槽与原剧情资源快照不一致。")
            self.dialogue = portraits.dialogue
        else:
            family = self.target.discovery['profile_seed']['native_symbols']['portrait_lifecycle_family']
            self.dialogue = NativePortraitDialogue(self.context, family, self.output, cg_guard=self.guard)

    def cleanup_owned_threads(self, *, reason):
        cleanup = self.thread_slots.cleanup()
        before = len(self.output)
        self.output.extend(cleanup)
        if cleanup:
            self.thread_cleanups.append(dict(reason=reason, byte_range=[before, len(self.output)],
                owned_slots=sorted(self.thread_slots.owned_slots), global_zero_exit_emitted=False))

    def finish(self):
        self.output.extend(self.snapshot['restore'])
        self.check_unchanged()

    def prepare_threaded_scene_image(self, payload, anchor, *, _defer_preserved_source_cycles=False):
        self.check_unchanged()
        image, report = NativeCGSceneThreadImage(self.thread_handoff, self.thread_slots,
            snapshot_storage=self.snapshot_storage, original_graph_journal=self.original_graph_journal).assemble(
            payload, anchor, cleanup_sites=self.thread_cleanups,
            _defer_preserved_source_cycles=_defer_preserved_source_cycles)
        self.thread_image_report = deepcopy(report)
        return image, report

    def build_bridge(self, payload, thread_image):
        from .native_cg_state_bridge import build_state_bridge, link_state_bridge
        self.check_unchanged()
        bridge = build_state_bridge((self.target.root / self.target.executable).read_bytes(),
            self.native_groups.report(), self.motion_binding.report(),
            thread_image['native_vm_syscall_catalogue'],
            original_volatile_globals=self.analysis.header.volatile_globals)
        image, report = link_state_bridge(payload, thread_image, bridge, encoding=self.source.encoding)
        self.check_unchanged()
        return image, dict(executable=bridge.executable, report=report)

    def check_unchanged(self):
        self.target.check_unchanged()
        self.thread_handoff.validate()
        self.thread_slots.validate()
        self.original_graph_journal.validate()
        self.layers.validate()
        self.motion_binding.validate(self.channels, self.primitives)
        self.background_state.compile_snapshot(self.source)

    def report(self):
        return dict(schema=SCHEMA, cg_loading_required=False, cg_events_added=False,
            owned_primitives=list(self.primitives), resource_graphs=list(self.graphs),
            original_resource_journal=self.original_graph_journal.report(),
            original_scene_globals=deepcopy(self.snapshot['report']),
            owned_dialogue_guard=self.guard.report() if self.guard else None,
            authored_thread_cleanup_sites=deepcopy(self.thread_cleanups),
            native_thread_image=deepcopy(self.thread_image_report),
            target_native_animation_binding=self.motion_binding.report(),
            paired_executable_required=True, original_game_modified=False,
            runtime_verified=False, scene_export_connected=False)
