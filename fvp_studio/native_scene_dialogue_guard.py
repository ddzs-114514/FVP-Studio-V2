"""Explicit scene-handle/UI-thread guards without a CG display binding.

Only private native dialogue/menu copies are guarded. The caller supplies
owned background/portrait handles and target-bound thread capacity; inherited
threads, resources and camera ownership still require separate acquisition.
"""
from copy import deepcopy

from .native_cg_dialogue_guard import _NativeDialogueGuard
from .native_cg_thread_slots import NativeCGThreadSlots
from .native_script_state import validate_native_script_pair


SCHEMA = "fvp-native-scene-dialogue-guard/1"


def _owned_handles(values):
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError("场景交接需要明确的正整数图元／图像集合。")
    try:
        handles = tuple(values)
    except TypeError as error:
        raise ValueError("场景交接需要明确的正整数图元／图像集合。") from error
    if any(type(h) is not int or not 0 < h < 2**31 for h in handles):
        raise ValueError("场景交接的图元／图像身份必须是原生正整数。")
    return frozenset(handles)


class NativeSceneDialogueGuard(_NativeDialogueGuard):
    _scope = "场景"

    def __init__(self, context, *, primitives, graphs, thread_slots, camera=None):
        self.context = context
        self.source, self.analysis = context.document, context.analysis_document
        validate_native_script_pair(self.source, self.analysis, runtime_context=context)
        self.primitives, self.graphs = _owned_handles(primitives), _owned_handles(graphs)
        if (not isinstance(thread_slots, NativeCGThreadSlots) or thread_slots.context is not context
                or thread_slots.source is not self.source or thread_slots.handoff.analysis is not self.analysis):
            raise ValueError("场景台词／选项线程必须绑定当前目标自己的原生容量。")
        thread_slots.validate()
        self.thread_slots = thread_slots
        # A supplied primitive is not evidence of ownership of its parent.
        self.parent_groups = frozenset()
        self.camera, self.isolate_camera = camera, camera is not None
        self.camera_cache_slots = ()
        if camera is not None:
            from .native_scene_camera import NativeSceneCamera
            if (not isinstance(camera, NativeSceneCamera)
                    or camera.source is not self.source or camera.analysis is not self.analysis):
                raise ValueError("场景镜头缓存保护必须绑定本目标自己的镜头调用链。")
            slots = tuple(camera.cache_slots)
            total = self.source.header.non_volatile_globals + self.source.header.volatile_globals
            if (len(slots) != 3 or any(type(g) is not int or not 0 <= g < total for g in slots)
                    or len(set(slots)) != 3):
                raise ValueError("场景镜头缓存不是本目标已绑定的三个坐标变量。")
            self.camera_cache_slots = tuple(sorted(slots))
        self.table = {d.name: (i, d.args) for i, d in enumerate(self.source.header.syscalls)}
        if len(self.table) != len(self.source.header.syscalls):
            raise ValueError("场景交接的原生系统调用名重复。")
        self.return_summaries = {}

    def _validate_ownership(self):
        if self.context.document is not self.source or self.context.analysis_document is not self.analysis:
            raise ValueError("场景交接的来源脚本配对已经变化。")
        validate_native_script_pair(self.source, self.analysis, runtime_context=self.context)
        if (self.thread_slots.context is not self.context or self.thread_slots.source is not self.source
                or self.thread_slots.handoff.analysis is not self.analysis or self.table != self.thread_slots.table):
            raise ValueError("场景台词／选项线程的目标绑定已经变化。")
        self.thread_slots.validate()
        if self.camera is not None and (self.camera.source is not self.source
                or self.camera.analysis is not self.analysis
                or tuple(sorted(self.camera.cache_slots)) != self.camera_cache_slots):
            raise ValueError("场景镜头缓存的目标绑定已经变化。")

    def report(self):
        self._validate_ownership()
        return deepcopy(dict(schema=SCHEMA,
            source_sha256=self.source.source_sha256, analysis_sha256=self.analysis.source_sha256,
            owned_primitives=sorted(self.primitives), owned_graphs=sorted(self.graphs),
            authored_thread_slots=self.thread_slots.report(), private_authored_thread_controls_remapped=True,
            parent_and_ancestor_ownership_granted=False,
            handle_namespaces_kept_separate=True, other_handles_forwarded=True,
            non_owned_handles_and_parent_targets_forwarded=True,
            guard_result_use_checked_locally=True, caller_result_use_reviewed=True,
            entry_root_results_checked_on_rewrite=True,
            return_convention="hcb_04_ret_nil_05_retv_stack_value", native_ret_handler_byte_verified=False,
            input_text_queries_waits_preserved=True, camera_ownership_granted=False,
            active_owned_rotation_wait_bypassed=bool(getattr(self, 'rotation_loop_cells', ())),
            rotation_wait_scope='only_active_captured_primitive_R',
            active_owned_translation_wait_bypassed=bool(getattr(self, 'translation_loop_cells', ())),
            translation_wait_scope='only_active_captured_primitive_XY',
            private_camera_mutations_isolated=self.isolate_camera, native_camera_queries_preserved=True,
            native_camera_pause_nil_query_forwarded=True, native_camera_cache_writes_preserved=True,
            camera_cache_global_ids=list(self.camera_cache_slots),
            camera_cache_entry_snapshot_available=bool(self.camera_cache_slots),
            camera_join_or_stop_required_before_use=self.isolate_camera,
            fixed_non_owned_sites_kept_original=getattr(self, "other_handle_sites", []),
            preexisting_engine_thread_ownership_proven=False, preexisting_engine_motion_ownership_proven=False,
            original_functions_patched=False, scene_export_connected=False, runtime_verified=False))
