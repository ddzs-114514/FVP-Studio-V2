"""Interleave target-native CG, retained scene layers and selected routes.

This is the internal, in-memory part of the scene compiler. It is NOT an
ownership grant for inherited VM threads, groups or pending CG caches. The
public exporter must remain closed until those owners are bound. Original
resources/functions and image pixels are unchanged; helper addresses never
participate in a branch's logical state comparison.
"""
from copy import deepcopy
from pathlib import Path

from .gui_native_cg import event_values
from .hoshimemo_scene_hook import _call
from .native_background_layers import NativeBackgroundLayers
from .native_cg_backend import NativeCGBackend
from .native_cg_background_reload import NativeCGBackgroundReload
from .native_cg_dialogue_guard import NativeCGDialogueGuard
from .native_cg_geometry import NativeCGGeometry
from .native_cg_motion import NativeCGMotion
from .native_cg_group_ancestry import NativeCGGroupAncestry
from .native_cg_primitive_groups import NativeCGPrimitiveGroups
from .native_cg_presentation import NativeCGPresentation
from .native_cg_staged_load import NativeCGStagedLoad
from .native_cg_thread_handoff import NativeCGThreadHandoff
from .native_cg_thread_slots import NativeCGThreadSlots
from .native_cg_scene_thread_image import NativeCGSceneThreadImage
from .native_cg_snapshot_storage import NativeCGSnapshotStorage
from .native_cg_original_stage_journal import NativeCGOriginalStageJournal
from .native_cg_original_resource_journal import NativeCGOriginalResourceJournal
from .native_cg_underlay import NativeCGUnderlay
from .native_graphics_imports import NativeGraphicsImports
from .native_portrait_dialogue import NativePortraitDialogue
from .performance_install import _safe


SCHEMA = "fvp-native-scene-cg/1"
BRANCH_KINDS = {"GuiCGLoad", "GuiCGExit", "GuiCGTransform"}
STAGE_EVENTS = {"Background", "GuiBackgroundChange", "GuiBackgroundBlur",
    "Portrait", "Hide", "GuiActorSwap", "Action", "GuiActorMove",
    "GuiActorSlide", "GuiActorPoseSet", "GuiActorSwayStart", "GuiActorSwayStop", "GuiActorNod", "CameraShot"}


class NativeSceneCG:
    branch_kinds = BRANCH_KINDS

    def __init__(self, target, output, imports=None, *, source_targets=None,use_snapshot_storage=False,
                 use_original_graph_journal=False, use_native_resource_snapshot=False):
        self.target, self.context, self.output = target, target.context, output
        if (type(use_snapshot_storage) is not bool or type(use_original_graph_journal) is not bool
                or type(use_native_resource_snapshot) is not bool
                or use_original_graph_journal and not use_snapshot_storage
                or use_native_resource_snapshot and not use_original_graph_journal):
            raise ValueError("CG 状态暂存必须由私有整场景编译器明确选择。")
        self.backend = NativeCGBackend(self.context)
        self.layers = NativeBackgroundLayers(self.context)
        geometry = NativeCGGeometry.from_target(target, self.backend)
        executable = (target.root / target.executable).read_bytes()
        self.stage = NativeCGStagedLoad(self.context, self.backend, geometry, executable=executable)
        native_groups = NativeCGPrimitiveGroups(executable) if use_original_graph_journal else None
        self.group_ancestry = NativeCGGroupAncestry(self.stage,
            **(dict(native_groups=native_groups) if native_groups is not None else {}))
        self.presentation = NativeCGPresentation(self.context, self.stage, executable=executable)
        self.thread_handoff = NativeCGThreadHandoff(self.context, executable)
        self.snapshot_storage = NativeCGSnapshotStorage(self.thread_handoff) if use_snapshot_storage else None
        self.thread_slots = NativeCGThreadSlots(self.context, self.thread_handoff)
        target.check_unchanged()
        primitives = set(self.backend.planes)
        graphs = {r["graph"] for r in self.backend.resource_graphs}
        for rows in self.presentation.companions.values():
            primitives.update(rows)
            graphs.update(rows)
        journal_graphs = graphs | {row['graph'] for row in self.layers.layers.values()}
        restore_primitives = (primitives | set(self.group_ancestry.ancestors)
            | {row['primitive'] for row in self.layers.layers.values()})-{0}
        # Portrait entry cleanup can touch every catalogued carrier, including
        # ones not assigned to an authored actor. Bind the bounded snapshot
        # after that catalogue exists, before assembling the scene image.
        self._resource_snapshot_graphs = tuple(sorted(journal_graphs)) if use_native_resource_snapshot else None
        self.original_graph_journal = (
            NativeCGOriginalStageJournal(self.thread_handoff, self.snapshot_storage,
                sorted(journal_graphs), authored_primitives=restore_primitives)
            if use_original_graph_journal and not use_native_resource_snapshot else None)
        self.ownership = self.layers.cg_handoff(cg_graphs=graphs, cg_primitives=primitives)
        self.requires_retained_camera = not self.ownership["background_reload_required"]
        self.background_reload = (NativeCGBackgroundReload(self.layers, self.stage)
            if self.ownership["background_reload_required"] else None)
        self.imports = imports if imports is not None else NativeGraphicsImports(target.root, {
            "background": self.layers.backend.archive_selectors,
            "event_visual": self.backend.archive_selectors})
        if (self.imports.root != target.root
                or self.imports.routes.get("event_visual") != self.backend.archive_selectors
                or self.imports.routes.get("background") != self.layers.backend.archive_selectors):
            raise ValueError("CG 素材打包器必须绑定当前目标自己的背景和 CG 路由。")
        self.source_targets = dict(source_targets or {})
        self.source_backends = {target.root: self.backend}
        self.checked_sources = {}
        self.references, self.operations, self.libraries = [], [], []
        self.thread_cleanups = []
        self.thread_image_report = None
        self.resources = {}
        self.background, self.active = None, None
        self.camera = self.screen = self.portraits = self.blur = None
        self.guard = self.dialogue = None
        self.motion = None

    def bind_motion(self, *, capture=True):
        if self.motion is None:
            self.motion = NativeCGMotion(self.context, self.stage, self.output)
        if capture and self.motion.snapshot is None:
            self.motion.snapshot_state(self.snapshot_storage)
        return self.motion

    def bind_camera(self, camera, screen):
        if self.guard is not None:
            raise ValueError("CG 场景已经绑定镜头保护，不能重复绑定。")
        if self.requires_retained_camera and camera is None:
            raise ValueError("此目标的 CG 舞台恢复需要它自己的原生镜头调用链。")
        self.camera, self.screen = camera, screen
        self.guard = NativeCGDialogueGuard(self.context, self.presentation,
            isolate_camera=True, camera=camera, protect_cg_parents=True,
            group_ancestry=self.group_ancestry, thread_slots=self.thread_slots)

    def bind_retained_scene(self, portraits, blur):
        self.portraits, self.blur = portraits, blur
        if self.camera is None and (portraits is not None or blur is not None):
            raise ValueError("共用背景槽的旧版 CG 尚未接通角色／模糊层的完整恢复，不借用新版镜头。")
        if self._resource_snapshot_graphs is not None:
            if self.original_graph_journal is not None:
                raise ValueError("CG 原剧情资源快照已经绑定，不能重复分配。")
            graphs, parts = set(self._resource_snapshot_graphs), set()
            if portraits is not None:
                for slot in portraits.loader.catalog.slots:
                    handles = slot.evidence['dispatcher_handles']
                    graphs.update(handles['graph_ids'])
                    parts.update(handles['parts_ids'])
            self.original_graph_journal = NativeCGOriginalResourceJournal(
                self.thread_handoff, self.snapshot_storage, sorted(graphs), parts=sorted(parts))
        if portraits is None:
            self.dialogue = NativePortraitDialogue(self.context, {}, self.output,
                cg_guard=self.guard)
        else:
            # One graph owns both protections. Rewriting already copied roots
            # through a second independent bridge would bypass that bridge.
            self.dialogue = portraits.dialogue

    def background_loaded(self, reference):
        if self.active is not None:
            raise ValueError("CG 显示期间不能覆盖保留的背景，请先让 CG 退场。")
        self.background = (reference["target_archive"], reference["target_resource_name"])

    def _retained_state(self):
        return dict(background=deepcopy(self.background),
            camera=tuple(self.camera.current) if self.camera else None,
            actors=deepcopy(self.portraits.states) if self.portraits else {},
            loader=deepcopy(self.portraits.loader._active) if self.portraits else {},
            blur=self.blur.state() if self.blur else None)

    def state(self):
        return dict(background=deepcopy(self.background), active=deepcopy(self.active))

    def restore_compiler_state(self, state):
        # Only bookkeeping is rewound while compiling another mutually
        # exclusive route. No resource, draw flag or runtime pose is rewound.
        self.background, self.active = deepcopy(state["background"]), deepcopy(state["active"])

    def join(self):
        if self.motion is not None:
            self.motion.join()

    def assert_stage_event(self, kind):
        if self.active is not None and kind in STAGE_EVENTS:
            raise ValueError("CG 显示期间的舞台动作还需绑定完整交接，请先让 CG 退场；不会省略该动作。")

    def _capture_underlay(self, retained):
        if self._retained_state() != retained:
            raise ValueError("CG 保留的背景、角色、模糊或镜头已改变，不能恢复另一条路线的画面。")
        reload = (self.background_reload.capture(*self.background)
            if self.background_reload is not None and self.background is not None else None)
        if self.camera is None:
            return dict(background_reload=reload)
        underlay = NativeCGUnderlay(self.presentation, self.layers, camera=self.camera,
            portrait_loader=self.portraits.loader if self.portraits else None,
            visible_actors=tuple(self.portraits.actors[actor] for actor in self.portraits.states)
                if self.portraits else (),
            background_present=self.background is not None,
            blur_present=bool(self.blur and self.blur.current is not None), background_reload=reload)
        return dict(underlay=underlay)

    def _bind_resource(self, event):
        path = _safe(Path(event["archive"]), file=True, independent=False)
        source = self.source_targets.get(event["source_game"])
        if source is None:
            if path.parent != self.target.root:
                raise ValueError("跨游戏 CG 需要本机已登记来源游戏自己的原生调用链。")
            source = self.target
        if source.root != path.parent:
            raise ValueError("CG 来源游戏与素材目录不一致，不能串用另一份原生配对。")
        source.check_unchanged()
        backend = self.source_backends.get(source.root)
        if backend is None:
            backend = NativeCGBackend(source.context)
            self.source_backends[source.root] = backend
        reference = self.imports.bind_cg(self.backend, path, event["resource"], source_backend=backend)
        source.check_unchanged()
        self.checked_sources[source.root] = source
        identity = (reference["target_archive"], reference["target_resource_name"])
        previous = self.resources.get(identity)
        if previous is not None and previous["metadata_by_suffix"] != reference["metadata_by_suffix"]:
            raise ValueError("同一 CG 资源身份对应了不同的原生图像。")
        self.resources[identity] = reference
        self.references.append(deepcopy(reference))
        return identity

    def _library(self, active, duration_ms, *, display_launch=b''):
        identity = tuple(active["identity"])
        reference = self.resources[identity]
        view = active.get("view", dict(x=0, y=0, s=100))
        library = self.presentation.compile(*identity, reference["metadata_by_suffix"],
            x=view["x"], y=view["y"], percentage=view["s"], depth_zoom=self.motion is not None,
            duration_ms=duration_ms, append_offset=len(self.context.document.original_bytes)+len(self.output),
            release_resources=True, display_launch=display_launch, **self._capture_underlay(active["retained"]))
        self.output.extend(library.code)
        self.libraries.append(deepcopy(library.report))
        return library

    def emit_load_with_transform(self, event, transform):
        event_values('GuiCGLoad', {k:v for k,v in event.items() if k!='kind'})
        event_values('GuiCGTransform', {k:v for k,v in transform.items() if k!='kind'})
        transition = event.get('transition')
        if transform.get('transition') is not None:
            raise ValueError('同拍加载与构图只允许一份统一转场。')
        if not transition and self.screen and self.screen.covered is not None:
            raise ValueError('黑白场下请先淡入恢复，再启动 CG。')
        self.join()
        if transition:
            self._transition_before(transition)
        motion = self.bind_motion()
        identity = self._bind_resource(event)
        retained = self.active['retained'] if self.active else self._retained_state()
        start = deepcopy(self.active['view']) if self.active else dict(x=0,y=0,s=100)
        end = {k:transform[k] for k in ('x','y','s')}
        active = dict(identity=identity,retained=deepcopy(retained),fit=event['fit'],view=start)
        # Native motion contains no new wait after the previous CG is joined.
        # Embed it after slot preparation/reveal, not ahead of slot reset.
        before = len(self.output)
        motion.emit(identity[0],self.resources[identity]['metadata_by_suffix'],start,end,
            transform['duration_ms'],transform['curve'])
        launch = bytes(self.output[before:])
        del self.output[before:]
        library = self._library(active,0 if transition else event['duration_ms'],display_launch=launch)
        self.output.extend(_call(library.report['entries']['display']))
        if transition:
            self._transition_after(transition)
        active['view'] = end
        self.active = active
        self.operations.append(dict(kind='GuiCGLoadWithTransform',identity=identity,
            duration_ms=event['duration_ms'],motion_duration_ms=transform['duration_ms'],
            view=deepcopy(end),native_motion_before_reveal_wait=True))

    def _transition_before(self, transition):
        from .gui_cg_transition import values
        transition = values(transition)
        if self.screen is None:
            raise ValueError('CG 组合转场需要目标自己的整幕转场绑定。')
        method = transition['type']
        if method in {'black_out', 'white_out'}:
            transition = dict(transition, type=method.split('_')[0])
        elif method == 'reveal':
            transition = dict(transition, type='dissolve')
        self.screen.chapter_before(transition)

    def _transition_after(self, transition):
        method = transition['type']
        if method not in {'black_out', 'white_out'}:
            self.screen.chapter_after(dict(transition, type='dissolve') if method == 'reveal' else transition)
        self.operations.append(dict(kind='CGTransition', transition=deepcopy(transition),
            implicit_cg_fade=False, single_transition_owner=True))

    def emit_transition(self, event):
        """Prepare the new frame, then let exactly one transition reveal it."""
        transition, kind = event['transition'], event['kind']
        if kind != 'GuiCGLoad' and self.active is None:
            raise ValueError('CG 退场／构图需要已显示的 CG。')
        self.join()
        self._transition_before(transition)
        if kind == 'GuiCGLoad':
            identity = self._bind_resource(event)
            retained = self.active['retained'] if self.active else self._retained_state()
            view = deepcopy(self.active['view']) if self.active else dict(x=0, y=0, s=100)
            active = dict(identity=identity, retained=deepcopy(retained), fit=event['fit'], view=view)
            library = self._library(active, 0)
            self.output.extend(_call(library.report['entries']['display']))
            self.active = active
            self.operations.append(dict(kind=kind, identity=identity, setup_without_reveal=True))
        elif kind == 'GuiCGExit':
            self._hide(reason='GuiCGExitTransition')
        else:
            # Motion starts before the transition wait, not after it.
            self.emit({k: v for k, v in event.items() if k != 'transition'})
        self._transition_after(transition)

    def emit(self, event):
        kind = event["kind"]
        event_values(kind, {k: v for k, v in event.items() if k != "kind"})
        if 'transition' in event:
            self.emit_transition(event)
            return
        if kind == "GuiCGSetup" and (self.active is not None or self.background is None
                or (self.portraits is not None and self.portraits.states)):
            raise ValueError("开场 CG 需要已布置的背景，且不能同时布置另一张 CG 或在场立绘。")
        if kind == "GuiCGTransform":
            if self.active is None:
                raise ValueError("没有正在显示的 CG，不能改变构图。")
            motion = self.bind_motion()
            reference = self.resources[tuple(self.active["identity"])]
            view = {key:event[key] for key in ("x", "y", "s")}
            motion.emit(self.active["identity"][0], reference["metadata_by_suffix"],
                self.active["view"], view, event["duration_ms"], event["curve"])
            self.active["view"] = view
            self.operations.append(dict(kind=kind, view=deepcopy(view), duration_ms=event["duration_ms"]))
            return
        self.join()
        if kind in {"GuiCGSetup", "GuiCGLoad"}:
            if kind == "GuiCGLoad" and self.screen and self.screen.covered is not None:
                raise ValueError("黑白场下的 CG 渐变尚需独立绑定，请先淡入恢复画面。")
            identity = self._bind_resource(event)
            retained = self.active["retained"] if self.active else self._retained_state()
            view = deepcopy(self.active["view"]) if self.active else dict(x=0, y=0, s=100)
            active = dict(identity=identity, retained=deepcopy(retained), fit=event["fit"], view=view)
            library = self._library(active, event["duration_ms"])
            self.output.extend(_call(library.report["entries"]["display"]))
            self.active = active
            self.operations.append(dict(kind=kind, identity=identity, duration_ms=event["duration_ms"],
                entry=library.report["entries"]["display"]))
            if kind == "GuiCGSetup":
                # Zero-time presentation loads the resource without revealing
                # it. The chapter exit remains the sole transition owner.
                self.operations[-1]["setup_without_reveal"] = True
        else:
            if self.active is None:
                raise ValueError("没有已显示的 CG 可退场。")
            if self.screen is None:
                raise ValueError("CG 黑／白退场需要当前目标自己的原生整幕转场。")
            # Exactly one requested colour fade/wait precedes the zero-time
            # hide. BG/actors are restored under that cover, never revealed by
            # a second fade before the authored black/white transition.
            self.screen.emit(dict(kind="Transition", method=event["colour"]+"_out",
                                  duration_ms=event["duration_ms"]))
            self._hide(reason=kind)

    def begin_exit_line(self, event):
        event_values('GuiCGExit', {k: v for k, v in event.items() if k != 'kind'})
        if event.get('kind') != 'GuiCGExit' or self.active is None or self.screen is None:
            raise ValueError('CG 退场配台词需要当前CG和本目标整幕转场。')
        self.join()
        start = self.screen.prepare_parallel(dict(kind='Transition',
            method=event['colour']+'_out', duration_ms=event['duration_ms']))
        self.output.extend(start)

    def finish_exit_line(self):
        # Do not free/reload a CG while Dissolve or this line still owns it.
        self.screen.finish_parallel()
        self._hide(reason='GuiCGExitWithLine')

    def _hide(self, *, reason):
        if self.active is None:
            return
        self.join()
        library = self._library(self.active, 0)
        self.output.extend(_call(library.report["entries"]["hide"]))
        self.operations.append(dict(kind=reason, identity=tuple(self.active["identity"]),
            duration_ms=0, entry=library.report["entries"]["hide"], resources_released=True,
            scene_background_reloaded=library.report["compiler_owned_background_reloaded_on_hide"]))
        self.active = None

    def finish_branch(self):
        # End-mode alternatives may own different aliased BG/CG images. Each
        # SELECTED route cleans its own CG before jumping to the common tail;
        # the tail must not execute the last compiled route's BG reload.
        self._hide(reason="selected_route_end_cleanup")

    def leave_scene(self):
        # The chapter exit has already captured/covered the source frame.
        # Retire this route's CG before changing its retained stage. The
        # inherited story snapshot remains alive until the final chapter tail.
        self._hide(reason="chapter_scene_exit")

    def cleanup_owned_threads(self, *, reason):
        # Only authored UI workers may end here. Inherited callbacks stay
        # parked until the final native scene/global-state restoration.
        cleanup = self.thread_slots.cleanup()
        before = len(self.output)
        self.output.extend(cleanup)
        if cleanup:
            self.thread_cleanups.append(dict(reason=reason,byte_range=[before,len(self.output)],
                owned_slots=sorted(self.thread_slots.owned_slots),global_zero_exit_emitted=False))

    def finish(self):
        self.join()
        self.cleanup_owned_threads(reason="before_scene_end_restore")
        self._hide(reason="scene_end_cleanup")
        if self.motion is not None:
            self.motion.finish()
        self.check_unchanged()

    def prepare_inherited_threads(self):
        # The assembler still needs to reserve/install this packet, its new
        # volatile flag and an UNGATED owned print/menu callback graph.
        # Binding/preparing a packet does not pause an existing process.
        self.check_unchanged()
        return self.thread_handoff.prepare(len(self.context.document.original_bytes)+len(self.output))

    def prepare_threaded_scene_image(self,payload,anchor,*,_defer_preserved_source_cycles=False,
                                    voice_replay=None):
        self.check_unchanged()
        image,report = NativeCGSceneThreadImage(self.thread_handoff,self.thread_slots,
            snapshot_storage=self.snapshot_storage,original_graph_journal=self.original_graph_journal).assemble(
            payload,anchor,cleanup_sites=self.thread_cleanups,
            _defer_preserved_source_cycles=_defer_preserved_source_cycles, voice_replay=voice_replay)
        self.thread_image_report = deepcopy(report)
        self.check_unchanged()
        return image,report

    def check_unchanged(self):
        self.target.check_unchanged()
        self.thread_handoff.validate()
        self.thread_slots.validate()
        if self.original_graph_journal is not None:
            self.original_graph_journal.validate()
        for source in self.checked_sources.values():
            source.check_unchanged()
        self.imports.check_unchanged()

    def report(self):
        return dict(schema=SCHEMA, memory_only=True, assembly_connected=True,
            scene_export_connected=False, runtime_verified=False,
            original_engine_threads_and_parent_groups_owned=False,
            camera_and_pending_cg_cache_commit_proven=False,
            geometry=self.stage.geometry.describe(), background_layers=self.layers.report(),
            motion=self.motion.report() if self.motion is not None else None,
            source_group_ancestry=self.group_ancestry.report(),
            native_thread_handoff=self.thread_handoff.report(),
            original_visual_journal=(self.original_graph_journal.report()
                if self.original_graph_journal is not None else None),
            authored_thread_slots=self.thread_slots.report(),
            authored_thread_cleanup_sites=deepcopy(self.thread_cleanups),
            private_scene_thread_image=deepcopy(self.thread_image_report),
            authored_ui_cleanup_before_retained_stage_restore=True,
            ownership=deepcopy(self.ownership), operations=deepcopy(self.operations),
            presentation_libraries=deepcopy(self.libraries),
            native_dialogue=self.dialogue.report() if self.dialogue else None,
            branch_state_includes_cg_and_retained_stage=True,
            helper_addresses_in_branch_state=False, selected_route_end_cleanup=True,
            original_functions_patched=bool(self.thread_image_report and self.original_graph_journal),
            native_gallery_flags_emitted=False,
            original_images_restored=False, image_resampled=False,
            source_size_rule_changed=False, public_export_requires_remaining_native_owners=True)
