"""Retained scene layers around an owned CG presentation.

This component does not acquire the original engine's running threads or
parent groups. Its caller must first own/quiesce the scene. Shared BG/CG slots
require a captured source-bound background reload; they are NOT Draw-only
handoffs. Public scene export stays closed until the remaining owners bind.
"""
from copy import deepcopy

from .hoshimemo_scene_hook import _call, _push_global, _pop_global
from .native_background_layers import NativeBackgroundLayers
from .native_portrait_loading import NativePortraitLoading
from .native_scene_camera import NativeSceneCamera
from .native_script_state import NativeScriptStateClosure
from .portrait_emitter import _encode_push


SCHEMA = "fvp-native-cg-retained-underlay/1"


class NativeCGUnderlay:
    """Capture compiler-owned layers after all scene motions have joined.

    blur_present means the OWNED image plane exists, not that its alpha is
    nonzero. A loaded blur plane switched off with alpha=0 should still be
    retained here, so a later native alpha change can make it visible again.
    """
    def __init__(self, presentation, background_layers, *, camera, portrait_loader=None,
                 visible_actors=(), background_present=True, blur_present=False, background_reload=None):
        context = presentation.context
        if (not isinstance(background_layers, NativeBackgroundLayers)
                or background_layers.context is not context):
            raise ValueError("CG 舞台交接缺少当前目标的背景图层绑定。")
        self.presentation, self.layers = presentation, background_layers
        cg_primitives = set(presentation.backend.planes)
        cg_graphs = {r["graph"] for r in presentation.backend.resource_graphs}
        for rows in presentation.companions.values():
            cg_primitives.update(rows)
            cg_graphs.update(rows)
        self.ownership = background_layers.cg_handoff(cg_graphs=cg_graphs, cg_primitives=cg_primitives)
        if type(background_present) is not bool or type(blur_present) is not bool:
            raise ValueError("背景显隐状态必须明确。")
        self.background_reload = background_reload
        if background_reload is not None:
            from .native_cg_background_reload import NativeCGBackgroundRestore
            if (not isinstance(background_reload, NativeCGBackgroundRestore)
                    or background_reload.binding.stage is not presentation.stage
                    or background_reload.binding.layers is not background_layers):
                raise ValueError("CG 背景恢复必须捕获同一目标的当前场景背景。")
            if not self.ownership["background_reload_required"] or not background_present:
                raise ValueError("当前舞台无需重载背景，不能额外加入另一份图像恢复。")
            background_reload.binding._validate()
        if self.ownership["background_reload_required"] and background_present and background_reload is None:
            raise ValueError("目标背景与 CG 共用图像／图层槽，需要原生重载背景；不能只恢复显示。")
        if (not isinstance(camera, NativeSceneCamera) or camera.source is not context.document
                or camera.analysis is not context.analysis_document or camera.pending):
            raise ValueError("CG 舞台交接需要当前目标已等待完成的原生镜头。")
        # Exact source dependencies, including the reset helper/delegate, are
        # checked again. A cached camera object is not a permission bypass.
        camera.closure.compile_snapshot(context.document)
        self.camera = camera
        self.camera_reset_closure = NativeScriptStateClosure(context.document, context.analysis_document,
            (camera.reset_address,), runtime_context=context)
        self.camera_reset_globals = tuple(g for g in self.camera_reset_closure.global_ids if g not in camera.cache_slots)
        self.camera_state = tuple(camera.current)
        if len(self.camera_state) != 3 or any(type(v) is not int for v in self.camera_state):
            raise ValueError("CG 退出时的镜头原生坐标尚未确定。")
        self.background_present, self.blur_present = background_present, blur_present
        if blur_present and (not background_present or "blur" not in self.layers.layers):
            raise ValueError("当前场景没有可保留的原生模糊层。")
        self.loader = portrait_loader
        self.visible_actors = tuple(visible_actors)
        if len(set(self.visible_actors)) != len(self.visible_actors):
            raise ValueError("CG 退出角色不能重复。")
        if portrait_loader is not None:
            if (not isinstance(portrait_loader, NativePortraitLoading)
                    or portrait_loader._source is not context.document
                    or portrait_loader._analysis is not context.analysis_document):
                raise ValueError("CG 角色显隐必须使用同一目标的原生角色槽。")
            portrait_loader._check(context.document)
            if not set(self.visible_actors) <= portrait_loader.assignments.keys():
                raise ValueError("CG 退出角色不在当前场景拥有的槽位内。")
        elif self.visible_actors:
            raise ValueError("CG 退出角色缺少原生槽位。")
        self.portrait_primitives = set()
        self.portrait_graphs = set()
        self.binding_globals = set()
        if self.loader is not None:
            for slot in self.loader.assignments.values():
                self.portrait_primitives.update(slot.primitive_ids)
                proof = slot.evidence["dispatcher_handles"]
                self.portrait_graphs.update(b["graph"] for b in proof["buffers"])
                self.binding_globals.update(proof["binding_global_ids"])
        bg_prim = {v["primitive"] for v in self.layers.layers.values()}
        bg_graph = {v["graph"] for v in self.layers.layers.values()}
        if (self.portrait_primitives & (cg_primitives | bg_prim)
                or self.portrait_graphs & (cg_graphs | bg_graph)):
            raise ValueError("背景、CG 和角色资源槽冲突，不能保留原图交接。")
        # Presentation restores these globals after reveal. Such a restore
        # must not undo the current scene's camera or active-buffer identity.
        if set(presentation.fade_globals) & (set(camera.cache_slots) | self.binding_globals):
            raise ValueError("CG 渐变缓存与当前镜头／角色槽状态冲突。")

    def _validate(self, presentation):
        if presentation is not self.presentation:
            raise ValueError("CG 舞台交接不属于当前显示库。")
        self.layers.validate()
        if self.background_reload is not None:
            self.background_reload.binding._validate()
        if self.camera.pending or tuple(self.camera.current) != self.camera_state:
            raise ValueError("CG 交接后镜头状态已改变，需要重新捕获当前舞台。")
        self.camera.closure.compile_snapshot(presentation.source)
        for address in self.camera.closure.dependencies:
            span = self.layers.spans[address]
            if any(i.dirty or i.warning or not i.known for i in span.instructions):
                raise ValueError("CG 恢复镜头的原生证据已变化。")
        if self.loader is not None:
            self.loader._check(presentation.source)

    def fragments(self, presentation):
        self._validate(presentation)
        stage = presentation.stage
        # Quiescing this owned camera prevents an old V3D motion from applying
        # again after CG's zero baseline. Portrait/blur motions must have been
        # joined by the enclosing scene before entering this helper.
        before_display = bytearray(self.camera.syscall("V3DMotionStop"))
        before_hide = bytearray()
        for role, layer in self.layers.layers.items():
            before_display.extend(stage.syscall("PrimSetDraw", [layer["primitive"], 0]))
            visible = self.background_present if role == "background" else self.blur_present
            before_hide.extend(stage.syscall("PrimSetDraw", [layer["primitive"], int(visible)]))
        for primitive in sorted(self.portrait_primitives):
            before_display.extend(stage.syscall("PrimSetDraw", [primitive, 0]))
            before_hide.extend(stage.syscall("PrimSetDraw", [primitive, 0]))
        if self.loader is not None:
            for actor in self.visible_actors:
                primitive = self.loader._active_primitive(self.loader.assignments[actor])
                before_hide.extend(self.loader._syscall("PrimSetDraw", [primitive, _encode_push(1, "shift_jis")]))
        # Use the target's bound coordinate wrapper and the SAME logical cache
        # units as NativeSceneCamera.restore_current, not a guessed raw Z/XY.
        values = (*self.camera.logical_coordinates(self.camera_state), 0)
        before_hide.extend(b"".join(_push_global(g) for g in self.camera_reset_globals))
        before_hide.extend(b"".join(_encode_push(v, "shift_jis") for v in values) + _call(self.camera.reset_address))
        for slot, value in zip(self.camera.cache_slots, values[:3]):
            before_hide.extend(_encode_push(value, "shift_jis") + _pop_global(slot))
        before_hide.extend(b"".join(_pop_global(g) for g in reversed(self.camera_reset_globals)))
        return dict(before_display=bytes(before_display), before_hide=bytes(before_hide),
            background_reload=self.background_reload,
            report=dict(schema=SCHEMA, ownership=deepcopy(self.ownership),
                camera_nominal_raw=list(self.camera_state), camera_logical=list(values[:3]),
                target_camera_is_nominal=bool(self.camera.factors != (1.,1.)),
                source_native_coordinate_quantizer_preserved=True,
                native_camera_reset=self.camera.reset_address,
                camera_cache_slots=list(self.camera.cache_slots),
                native_camera_dependencies=self.camera.closure.describe(),
                camera_reset_other_global_snapshot_ids=list(self.camera_reset_globals),
                portrait_primitives=sorted(self.portrait_primitives), visible_actors=list(self.visible_actors),
                current_portrait_buffer_resolved_at_runtime=True,
                background_present=self.background_present, blur_present=self.blur_present,
                underlying_resources_reloaded=self.background_reload is not None,
                underlying_alpha_changed=None if self.background_reload is not None else False,
                background_reconstruction_precedes_camera_and_actor_restore=self.background_reload is not None,
                portrait_geometry_or_expression_changed=False, source_size_rule_changed=False,
                caller_must_join_portrait_and_blur_motions=True,
                original_engine_threads_and_parent_groups_owned=False,
                camera_refresh_in_dialogue_isolated=False,
                pending_cg_cache_commit_proven=False,
                original_images_restored=False, scene_export_connected=False, runtime_verified=False))
