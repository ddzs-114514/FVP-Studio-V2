"""Read-only, target-bound capabilities for the explicit GUI export picker.

Registration is not compatibility. Probe the same native adapters used by
scene output in RAM, never compile a game copy, write a BIN or launch an EXE.
Do not use title switches, foreign addresses, or source-size guesses.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from threading import RLock

from .gui_runtime import GuiRuntimeError, fingerprint
from .gui_scene_export import ExportError
from .gui_native_scene_export import bind_target, select_hook, SCOPE
from .native_graphics_imports import NativeGraphicsImports
from .native_portrait_alpha import NativePortraitAlpha
from .native_portrait_motion import NativePortraitMotion
from .native_rotation_degrees import NativeRotationDegrees
from .native_portrait_scene import NativePortraitScene
from .native_portrait_slots import allocate_native_slots
from .native_scene_camera import NativeSceneCamera
from .native_scene_cg import NativeSceneCG
from .native_scene_state import NativeSceneState
from .native_background_blur import NativeBackgroundBlur
from .native_screen_transition import NativeScreenTransition, METHODS as SCREEN_TRANSITION_METHODS
from .native_scene_choice_tracks import bind_scene_menu, BRANCH_KINDS as CHOICE_BRANCH_KINDS
from .native_scene_choice_structure import MAX_NESTING
from .gui_target_selection import select_source, entry_choices, validate_options


SCHEMA = "fvp-gui-export-target/1"


def _sway_axis_capability(target, counts, axis, *, nod=False):
    from .gui_actor_sway import START, STOP, NOD
    from .native_portrait_sway import NativePortraitSway
    from .native_portrait_dialogue import NativePortraitDialogue
    if not counts:
        raise ValueError('目标没有可用角色槽。')
    state = NativeSceneState(target)
    code = bytearray(b'\x01\0\0')
    state.start(code)
    state.bind_camera(None)
    events = []
    for actor in range(1, max(counts) + 1):
        if nod:
            events.append(dict(kind=NOD, actor=actor, amplitude=24, duration_ms=450, curve=3))
            continue
        fields = dict(actor=actor, loop_id='probe_' + str(actor))
        events.extend([dict(kind=START, **fields, axis=axis, amplitude=1, direction=1, period_ms=1600, curve=3),
                       dict(kind=STOP, **fields)])
    rotation = NativeRotationDegrees(target) if axis == 'r' else None
    sway = NativePortraitSway(target, state, events, code, rotation)
    sway.stop_binding.validate(sway.stop_channels, state.primitives)
    if nod:
        assignments = allocate_native_slots(state.catalog.slots, ['nod_probe_' + str(i) for i in range(max(counts))])
        for slot in assignments.values():
            pair = slot.evidence['dispatcher_handles']['primitive_ids']
            if len(pair) != 2 or len(set(pair)) != 2:
                raise ValueError('点头需要两套已绑定的角色缓冲。')
    # Bind the same per-line native query graph, not only a syscall-name list.
    NativePortraitDialogue(target.context, {}, code, cg_guard=state.guard)
    result = dict(supported=True, max_actors=max(counts),
        native_thread_slots=sorted({r['slot'] for r in sway.rows.values()}), runtime_verified=False)
    if nod:
        result.update(script_units_supported=True, script_y_factor=sway.motion.xy_factors['y'],
            original_timing_supported=sway.table.get('V3DMotionTest', (None, None))[1] == 0)
    return result


def _sway_capability(target, counts):
    from .gui_actor_sway import contract
    details = {}
    for axis in ('r', 'y'):
        try:
            details[axis] = _sway_axis_capability(target, counts, axis)
        except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
            details[axis] = dict(supported=False, message=str(exc), runtime_verified=False)
    axes = [axis for axis, detail in details.items() if detail['supported']]
    result = contract()
    # The contract describes available axes in the implementation, not a
    # promise that this specific target can bind them. Never require R for Y.
    result.update(supported=bool(axes), axes=axes, axis_details=details,
        max_actors=max((details[a]['max_actors'] for a in axes), default=0),
        native_thread_slots=sorted({s for a in axes for s in details[a]['native_thread_slots']}))
    if not axes:
        result['message'] = '此目标暂未绑定持续倾斜或上下往复：' + '；'.join(
            a + '：' + details[a]['message'] for a in details)
    return result


def _parallel_body_motion_capability(target, channels, counts):
    """Read-only admission of the paired state and target-native trajectories."""
    channels = sorted(set(channels) & {'xy','z','s2','r'})
    if not channels or not counts:
        raise ValueError('此目标还没有可用的原生同拍角色运动。')
    state = NativeSceneState(target)
    admitted = []
    for count in counts:
        allocate_native_slots(state.catalog.slots,['parallel_probe_'+str(i) for i in range(count)])
        admitted.append(count)
    NativePortraitMotion(target.context.document,target.context.analysis_document,
        channels,runtime_context=target.context)
    return dict(supported=True,channels=channels,multiple_swaps=max(admitted)>1,
        other_loaded_actors=max(admitted)>1,xy_with_scale_or_depth='xy' in channels
            and bool(set(channels)&{'s2','z'}),
        native_state_pair_required=True,runtime_verified=False)


def _parallel_stage_capability(target, report):
    from .native_portrait_acceptance import _function_spans
    from .native_script_state import NativeScriptStateClosure
    from .native_cg_dialogue_guard import _return_inventory, _return_unused
    state = NativeSceneState(target)
    context = target.context
    closure = NativeScriptStateClosure(context.document,context.analysis_document,
        [state.catalog.apply_target],runtime_context=context)
    spans = {s.start:s for s in _function_spans(context.analysis_document)}
    names = {context.analysis_document.header.syscalls[i.operands['id']].name
        for address in closure.dependencies for i in spans[address].instructions if i.mnemonic=='syscall'}
    camera = bool(report['camera']['supported'] and not names.intersection({'V3DSet','V3DMotion','V3DMotionStop'}))
    fade = slide = expression = False
    if 'native_expression_blend' in report.get('allowed_features', []) and max(report['portrait']['supported_actor_counts'], default=0)>1:
        try:
            inventory = _return_inventory(spans,set(closure.dependencies),set())
            for address in closure.dependencies:
                for position,item in enumerate(spans[address].instructions):
                    if (item.mnemonic=='syscall' and context.analysis_document.header.syscalls[item.operands['id']].name == 'PartsMotion'):
                        _return_unused(spans,spans[address],position,inventory)
            expression = True
        except ValueError:
            pass
    if max(report['portrait']['supported_actor_counts'],default=0)>1:
        try:
            inventory = _return_inventory(spans,set(closure.dependencies),set())
            for address in closure.dependencies:
                for position,item in enumerate(spans[address].instructions):
                    if (item.mnemonic=='syscall' and context.analysis_document.header.syscalls[item.operands['id']].name
                            in {'MotionAlpha','MotionAlphaStop'}):
                        _return_unused(spans,spans[address],position,inventory)
            fade = True
            if {'alpha','xy'} <= set(report['native_motion_channels']):
                for address in closure.dependencies:
                    for position,item in enumerate(spans[address].instructions):
                        if (item.mnemonic=='syscall' and context.analysis_document.header.syscalls[item.operands['id']].name
                                == 'MotionMoveStop'):
                            _return_unused(spans,spans[address],position,inventory)
                slide = True
        except ValueError:
            pass
    return dict(supported=camera or bool(report['background_blur']['supported']) or fade or expression
            or bool(report.get('screen_transition', {}).get('portraits_compatible')),
        camera=camera,background_blur=bool(report['background_blur']['supported']),
        other_actor_fade=fade,same_actor_alpha=False,other_actor_slide=slide,
        other_actor_expression=expression, slide_with_geometry=slide,
        screen_transition=bool(report.get('screen_transition', {}).get('portraits_compatible')),
        background_change=bool(report.get('screen_transition', {}).get('portraits_compatible')),
        native_apply_frontier=True,native_state_pair_required=True,runtime_verified=False)


class NativeExportTargetCatalog:
    def __init__(self, runtime):
        self.runtime, self._cache, self._lock = runtime, {}, RLock()

    @staticmethod
    def _stamp(source):
        root = Path(source.root)
        files = tuple(sorted((p.name, fingerprint(p)) for p in root.iterdir()
            if p.is_file() and p.suffix.casefold() in {".hcb", ".bch", ".exe", ".dll", ".bin"}))
        registration = tuple(getattr(source, key, None) for key in (
            "target_script", "target_executable", "target_encoding",
            "target_analysis_encoding", "target_hook_offset"))
        return fingerprint(root), registration, files

    def info(self, source_id, **options):
        registered = self.runtime._source(source_id)
        # Capability discovery is read-only for every registered target.
        # Ordinary legacy exports keep their routing; OP uses these bindings.
        options = validate_options(options)
        source = select_source(registered, options)
        cache_key = (source_id, tuple(sorted(options.items())))
        with self._lock:
            before = self._stamp(source)
            cached = self._cache.get(cache_key)
            if cached and cached[0] == before:
                return deepcopy(cached[1])
            report = self._inspect(source)
            report["entry_selection"] = entry_choices(registered, options)
            if before != self._stamp(source):
                raise GuiRuntimeError("source_changed", "游戏文件刚发生变化，请重新选择输出游戏。", 409)
            self._cache[cache_key] = before, deepcopy(report)
            if len(self._cache) > 64:
                self._cache.pop(next(iter(self._cache)))
            return report

    @staticmethod
    def _inspect(source):
        report = dict(ok=True, schema=SCHEMA, source=source.id, name=source.name, scope=SCOPE,
            status="unavailable", allowed_features=[], native_motion_channels=[],
            native_raw_motion_channels=[], rotation_degrees_supported=False,
            camera=dict(supported=False, source_size_rule_changed=False, runtime_verified=False),
            background_blur=dict(supported=False, native_preblurred_image=True,
                portraits_compatible=False, supported_actor_counts=[], runtime_verified=False),
            screen_transition=dict(supported=False, methods=[], portraits_compatible=False,
                supported_actor_counts=[], runtime_verified=False),
            choices=dict(supported=False, maximum_options=0, nested_choices=False,
                branch_resource_changes=False, cg_compatible=False, runtime_verified=False),
            cg=dict(supported=False, geometry_supported=False, off_center_zoom_supported=False,
                portraits_compatible=False, native_state_bridge_required=True,
                new_test_copy_only=True, runtime_verified=False),
            audio=dict(schema='fvp-native-audio-capability/1',supported=False,kinds=[],voice=False,
                local_choice_branches=False,original_playback_restore=False,
                paired_native_state_required=True,runtime_verified=False),
            movie=dict(schema='fvp-native-movie-capability/1',supported=False,
                standalone_op_scene_only=True,chapter_mainline=False,mixed_beats=False,
                sequential_movie_beats=False,
                same_target_files_only=True,registered_source_import=False,external_transcoding=False,
                runtime_verified=False),
            portrait=dict(supported=False, capacity=0, expression_default_ms=200,
                body_swap_blend=False, body_swap_duration_control=False,
                body_swap_alpha_fusion=dict(supported=False,duration_policy='max',
                    actions=['fade','enter_fade','exit_fade'],event_field='target_alpha',runtime_verified=False),
                body_swap_preserves_nonuniform_scale=False,
                body_swap_parallel_motion=dict(supported=False,channels=[],multiple_swaps=False,
                    other_loaded_actors=False,xy_with_scale_or_depth=False,
                    native_state_pair_required=True,runtime_verified=False),
                body_swap_parallel_stage=dict(supported=False,camera=False,background_blur=False,
                    other_actor_fade=False,same_actor_alpha=False,other_actor_slide=False,
                    other_actor_expression=False,slide_with_geometry=False,screen_transition=False,background_change=False),
                parallel_motion=dict(supported=False, channels=[], multiple_actors=False,
                    xy_with_scale_or_depth=False, companion_channels=[],
                    native_state_pair_required=True, runtime_verified=False),
                instant_body_swap_proven=False, sway=dict(supported=False)),
            same_beat=dict(supported=False, actions=[], transition_methods=[], cg_exit_with_line=False,
                background_change_with_actions=False, background_change_with_blur=False,
                target_info_required=True, native_state_pair_required=True, runtime_verified=False),
            encoding_confirmed=False, runtime_verified=False, probe_is_read_only=True,
            writes_game_files=False, standalone_startup=False, chapter_export=False,
            limitations=["测试场景插在原作某句台词前，保留原作开头；不是启动后直接进入测试场景。",
                "结束后旧剧情图像的恢复尚未接完，请只在新生成的测试副本里使用。",
                "音乐、音效、配音台词、CG、镜头、模糊、转场和选项按当前游戏版本分别识别。"])
        try:
            target = bind_target(source)
            anchor = select_hook(target.context, getattr(source, "target_hook_offset", None))
        except ExportError as exc:
            report.update(status="needs_configuration" if exc.code in {
                "target_selection_needed", "target_encoding_needed", "invalid_target_registration"}
                else "unavailable", code=exc.code, message=str(exc))
            return report
        except (ValueError, KeyError):
            report.update(code="native_target_unavailable", message="此版本的原生输出入口尚未接通。")
            return report
        context = target.context
        report.update(status="bound", target_id=context.target_id,
                      encoding_confirmed=target.encoding_confirmed,
                      allowed_features=["native_speech", "wait"])
        if not target.encoding_confirmed:
            report["limitations"].append("输出中文或日文台词前，请选择这份游戏脚本使用的文字编码。")
        backend = context.abi.native_background_backend
        if backend is not None:
            report["allowed_features"].extend(["background", "background_change"])
        else:
            # The current native compiler requires a bound background chain,
            # including for text-only scenes. Do not advertise a false route.
            report.update(status="unavailable", allowed_features=[],
                code="background_not_supported", message="此版本的原生背景加载尚未接通。")
            return report
        blur = None
        try:
            blur = NativeBackgroundBlur(context)
            report["allowed_features"].append("background_blur")
            report["background_blur"].update(supported=True,
                binding="target_native_preblurred_layer_and_alpha_child", changes_camera=False,
                original_preference_unchanged=True, original_pair_required=True,
                source_size_rule_changed=False)
        except (ValueError, KeyError) as exc:
            report["background_blur"]["message"] = str(exc)
        screen = None
        try:
            screen = NativeScreenTransition(context)
            screen.prepare_colour(bytearray())
            screen.prepare_reveal(bytearray())
            report["allowed_features"].append("screen_transition")
            report["screen_transition"].update(supported=True, methods=list(SCREEN_TRANSITION_METHODS),
                binding="target_native_colour_and_isolated_reveal", waits_each_leg=True,
                original_preference_unchanged=True, native_duration_policy_preserved=True,
                source_size_rule_changed=False, camera_unchanged=True,
                inherited_cg_refresh_isolated=True, mask_dissolve_supported=False)
        except (ValueError, KeyError) as exc:
            screen = None
            report["screen_transition"]["message"] = str(exc)
        # Ordinary scenes and CG use the same target-owned catalog. Do not
        # make ordinary masks depend on whether that target supports CG.
        masks, mask_message = None, None
        if screen is not None:
            try:
                from .native_transition_masks import NativeTransitionMasks
                masks = NativeTransitionMasks(screen, backend, target.root)
                masks.prepare(bytearray(), nonblocking=True)
                report['screen_transition']['methods'].append('mask')
                report['screen_transition'].update(mask_dissolve_supported=True,
                    masks=sorted(masks.items), mask_catalog_endpoint='chapter-transition-catalog',
                    masks_require_target_catalog=True, mask_names_are_not_directions=True,
                    mask_owns_background_reveal=True)
            except (AttributeError, TypeError, ValueError, KeyError, OSError) as exc:
                masks, mask_message = None, str(exc)
                report['screen_transition'].update(masks=[], mask_message=mask_message)
        record = target.discovery.get("profile_seed", {}).get("native_symbols", {}).get("portrait_dispatcher")
        try:
            menu = bind_scene_menu(context)
            report["allowed_features"].append("choices")
            report["choices"].update(supported=True, maximum_options=min(4, menu.capacity),
                branch_resource_changes=True,
                nested_choices=True, max_nesting=MAX_NESTING,
                nested_completion="merge_within_selected_parent_route",
                waits_for_selection=True, selected_route_only=True,
                branch_events=sorted(CHOICE_BRANCH_KINDS), merge_requires_equal_state=True,
                prompt_requires_extra_click=False,
                menu_state_restored_before_selected_route=True,
                binding="target_native_registration_input_and_result")
            family = target.discovery.get("profile_seed", {}).get("native_symbols", {}).get("portrait_lifecycle_family", {})
            # Probe the exact adapter that scene output will use, rather than
            # treating an inherited portrait refresh as a title-wide refusal.
            try:
                menu.protect_scene_portraits(family, bytearray())
                report["choices"]["portraits_compatible"] = True
                report["choices"]["owned_portrait_refresh_isolated"] = True
            except (ValueError, KeyError) as exc:
                report["choices"]["portraits_compatible"] = False
                report["choices"]["portrait_handoff_message"] = str(exc)
            report["limitations"].append("选项分支支持换背景、原生换身体、角色进退场和分支内嵌套选项；嵌套选项须接回所在分支，接公共节拍时素材和状态须一致。")
        except (ValueError, KeyError) as exc:
            report["choices"]["message"] = str(exc)
        camera = None
        try:
            camera = NativeSceneCamera(target, bytearray())
            camera_report = camera.report()
            report["allowed_features"].append("camera")
            report["camera"].update(supported=True,
                reference_plane_z=camera_report["reference_plane_z"],
                baseline=camera_report["baseline"], viewport=camera_report["viewport"],
                zoom_range=camera_report["zoom_range"])
        except (ValueError, KeyError):
            report["camera"]["message"] = "此版本的原生镜头运动尚未接通。"
        if record:
            routes = {record["resource_namespace"].rstrip("/\\").casefold() + ".bin": None}
            try:
                imports = NativeGraphicsImports(target.root, {"portrait": routes})
                scene = NativePortraitScene(target, [dict(kind="Portrait", actor=1)],
                                            anchor, imports, bytearray())
                supported_counts = []
                for count in range(1, 5):
                    try:
                        allocate_native_slots(scene.loader.catalog.slots,
                                              ["probe_actor_" + str(i) for i in range(count)])
                        supported_counts.append(count)
                    except ValueError:
                        continue
                if supported_counts:
                    report["portrait"].update(supported=True, capacity=max(supported_counts),
                                              supported_actor_counts=supported_counts)
                    report["allowed_features"].extend(["target_native_portrait",
                        "native_expression_blend", "native_body_swap", "portrait_hide"])
                    try:
                        body_swap = scene.body_swap_capability()
                        if body_swap.get("supported") is True:
                            report["portrait"].update(body_swap_blend=True,
                                body_swap_duration_control=True, body_swap_default_ms=200,
                                body_swap_preserves_nonuniform_scale=body_swap.get('preserves_nonuniform_scale') is True)
                            report['portrait']['body_swap_alpha_fusion']['supported']=True
                            report["allowed_features"].append("native_body_swap_blend")
                        else:
                            report["portrait"]["body_swap_message"] = "此版本的原生换装渐变尚未接通。"
                    except (AttributeError, KeyError, TypeError, ValueError) as exc:
                        report["portrait"]["body_swap_message"] = str(exc)
                if blur is not None:
                    compatible = []
                    for count in supported_counts:
                        try:
                            assigned = allocate_native_slots(scene.loader.catalog.slots,
                                ["scene_actor_"+str(i) for i in range(1, count+1)])
                            blur.assert_portrait_ownership(assigned.values())
                            compatible.append(count)
                        except (ValueError, KeyError) as exc:
                            report["background_blur"]["portrait_handoff_message"] = str(exc)
                    report["background_blur"].update(supported_actor_counts=compatible,
                        portraits_compatible=bool(supported_counts) and compatible == supported_counts)
                if screen is not None:
                    compatible = []
                    for count in supported_counts:
                        try:
                            assigned = allocate_native_slots(scene.loader.catalog.slots,
                                ["scene_actor_"+str(i) for i in range(1, count+1)])
                            screen.portrait_cache_protection(assigned.values())
                            compatible.append(count)
                        except (ValueError, KeyError) as exc:
                            report["screen_transition"]["portrait_handoff_message"] = str(exc)
                    report["screen_transition"].update(supported_actor_counts=compatible,
                        portraits_compatible=bool(supported_counts) and compatible == supported_counts)
                source_doc, analysis_doc = context.document, context.analysis_document
                for channel in ("alpha", "xy", "z", "s2"):
                    try:
                        if channel == "alpha":
                            NativePortraitAlpha(source_doc, analysis_doc, runtime_context=context)
                        else:
                            NativePortraitMotion(source_doc, analysis_doc, {channel}, runtime_context=context)
                        report["native_motion_channels"].append(channel)
                    except ValueError:
                        continue
                report["native_raw_motion_channels"] = list(report["native_motion_channels"])
                try:
                    rotation = NativePortraitMotion(source_doc, analysis_doc, {"r"}, runtime_context=context)
                    report["native_raw_motion_channels"].append("r")
                    report["portrait"]["raw_rotation"] = dict(supported=True,
                        units="target_native_raw_R_not_degrees", gui_degrees_supported=False,
                        helper=rotation.report()["roles"]["r"]["helper"])
                    try:
                        conversion = NativeRotationDegrees(target)
                        report["rotation_degrees_supported"] = True
                        report["native_motion_channels"].append("r")
                        report["allowed_features"].append("portrait_tilt")
                        report["portrait"]["raw_rotation"].update(gui_degrees_supported=True,
                            degree_conversion=conversion.report())
                    except (ValueError,KeyError) as exc:
                        report["portrait"]["raw_rotation"]["message"] = str(exc)
                except ValueError:
                    report["portrait"]["raw_rotation"] = dict(supported=False,
                        units="target_native_raw_R_not_degrees", gui_degrees_supported=False)
            except (ValueError, KeyError):
                report["portrait"]["message"] = "此版本的立绘加载、站位或独立角色槽尚未接通。"
        if report["portrait"]["supported"]:
            from .gui_actor_nod import contract as nod_contract
            report['portrait']['nod'] = nod_contract()
            try:
                report['portrait']['nod'].update(_sway_axis_capability(
                    target, report['portrait']['supported_actor_counts'], 'y', nod=True))
                report['allowed_features'].append('portrait_nod')
            except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
                report['portrait']['nod'].update(supported=False, message=str(exc))
            try:
                report['portrait']['sway'] = _sway_capability(target, report['portrait']['supported_actor_counts'])
                if report['portrait']['sway']['supported']:
                    report['allowed_features'].append('portrait_sway')
            except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
                report['portrait']['sway'] = dict(supported=False, message=str(exc))
            try:
                parallel = _parallel_body_motion_capability(
                    target,report['native_motion_channels'],report['portrait']['supported_actor_counts'])
                report['portrait']['parallel_motion'] = dict(supported=True,
                    channels=parallel['channels'], multiple_actors=parallel['other_loaded_actors'],
                    xy_with_scale_or_depth=parallel['xy_with_scale_or_depth'],
                    companion_channels=(
                        (['parts'] if 'native_expression_blend' in report['allowed_features'] else [])
                        + (['alpha'] if 'alpha' in report['native_motion_channels'] else [])
                        if parallel['xy_with_scale_or_depth'] else []),
                    native_state_pair_required=True, runtime_verified=False)
                if parallel['xy_with_scale_or_depth']:
                    report['allowed_features'].append('native_portrait_parallel_motion')
                if report['portrait']['body_swap_blend']:
                    report['portrait']['body_swap_parallel_motion'] = parallel
                    if 'xy' in parallel['channels']:
                        report['portrait']['body_swap_alpha_fusion']['actions'].extend(['enter_slide','exit_slide'])
                    report['allowed_features'].append('native_body_swap_parallel_motion')
                    report['portrait']['body_swap_parallel_stage'] = _parallel_stage_capability(target,report)
            except (AttributeError,KeyError,OSError,TypeError,ValueError) as exc:
                report['portrait']['parallel_motion_message'] = str(exc)
        if report["portrait"]["supported"]:
            if not report["portrait"]["body_swap_duration_control"]:
                report["limitations"].append("换身体沿用原作处理，目前不能指定换装渐变时长。")
            if not report["rotation_degrees_supported"]:
                report["limitations"].append("此版本的 GUI 倾斜角度换算尚未接入。")
        else:
            report["limitations"].append("此版本暂不能输出角色立绘，仍可使用已接通的背景和台词。")
        if screen is not None and getattr(target, "executable", None):
            try:
                cg = NativeSceneCG(target, bytearray(), use_snapshot_storage=True,
                    use_original_graph_journal=True, use_native_resource_snapshot=True)
                cg.bind_camera(camera, None)
                cg.bind_retained_scene(None, None)
                report["allowed_features"].append("cg")
                report["cg"].update(supported=True,
                    operations=["load", "difference", "exit"],
                    binding="target_native_load_hidden_prepare_reveal_and_restore",
                    cross_game_source_binding=True, source_size_rule_changed=False,
                    portraits_compatible=camera is not None and report["portrait"]["supported"],
                    background_retained=camera is not None,
                    shared_background_slot=cg.ownership["background_reload_required"],
                    support_confirmed_on_export=True)
                from .gui_native_cg import opening_setup_contract
                report["cg"]["opening_setup"] = opening_setup_contract()
                from .gui_cg_transition import contract as cg_transition_contract
                report['cg']['transitions'] = cg_transition_contract()
                report['cg']['transitions'].update(supported=True,
                    methods=['cut', 'black', 'white', 'dissolve', 'black_out', 'white_out', 'reveal'],
                    masks=[])
                if masks is not None:
                    report['cg']['transitions']['methods'].append('mask')
                    report['cg']['transitions']['masks'] = sorted(masks.items)
                else:
                    report['cg']['transitions']['mask_message'] = mask_message or '此目标尚无已绑定的原作遮罩。'
                from .gui_cg_stage_handoff import contract as cg_exit_setup_contract, pose_capability
                setup = cg_exit_setup_contract()
                actions = ["bg"]
                if camera is not None:
                    actions.append("camera")
                    if report["portrait"]["supported"]:
                        actions += ["enter", "exit", "swap", "expr"]
                        setup["pose_set"] = pose_capability(target.context.document,
                            rotation_degrees_supported=report["rotation_degrees_supported"])
                        actions += setup["pose_set"]["actions"]
                    if report["background_blur"]["supported"]:
                        actions.append("bgblur")
                setup["stage_actions"] = [a for a in setup["stage_actions"] if a in actions]
                report["cg"]["exit_stage_setup"] = setup
                try:
                    cg.bind_motion(capture=False)
                    report["cg"].update(geometry_supported=True, off_center_zoom_supported=True,
                        load_with_transform=True,
                        motion_channels=["xy", "z"],
                        zoom_channel="z", variant_preserves_geometry=True)
                    report["cg"]["operations"].append("transform")
                except (ValueError, KeyError) as exc:
                    report["cg"]["geometry_message"] = str(exc)
                if not report["cg"]["geometry_supported"]:
                    report["limitations"].append("CG 已接加载、换差分和退场；此版本的构图运动尚未匹配。")
                if report["choices"]["supported"]:
                    try:
                        # The portrait-only probe may have copied its menu already.
                        # Scene output composes both protections on one fresh menu.
                        menu = bind_scene_menu(context)
                        menu.protect_scene_graphics(family if report["portrait"]["supported"] else {},
                            bytearray(), cg_guard=cg.guard)
                        branch_events = set(report["choices"]["branch_events"])
                        branch_events.update({"GuiCGLoad", "GuiCGExit"})
                        if report["cg"]["geometry_supported"]:
                            branch_events.add("GuiCGTransform")
                        report["choices"].update(cg_compatible=True, branch_events=sorted(branch_events))
                    except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
                        report["choices"].update(cg_compatible=False, cg_handoff_message=str(exc))
            except (ValueError, KeyError, OSError) as exc:
                report["cg"]["message"] = str(exc)
        paired_audio_state = False
        if screen is not None:
            try:
                NativeSceneState(target)
                paired_audio_state = True
                from .native_parallel_beat import contract as parallel_contract
                parallel = parallel_contract()
                actions = []
                if report['portrait']['supported']:
                    actions = [name for name, channel in (('move','xy'),('scale','s2'),('depth','z'),
                        ('tilt','r'),('fade','alpha')) if channel in report['native_motion_channels']
                        and (name != 'tilt' or report['rotation_degrees_supported'])]
                    if 'native_expression_blend' in report['allowed_features']:
                        actions.append('expr')
                    actions += ['enter','exit']
                if report['camera']['supported']:
                    actions.append('camera')
                if report['background_blur']['supported']:
                    actions.append('bgblur')
                parallel.update(supported=bool(actions), actions=actions,
                    transition_methods=list(report['screen_transition']['methods']),
                    cg_exit_with_line=bool(report['cg']['supported']),
                    background_change_with_actions=bool(actions),
                    background_change_with_blur=bool(report['background_blur']['supported']),
                    portrait_transition_counts=report['screen_transition'].get('supported_actor_counts', []))
                report['same_beat'] = parallel
                from .gui_chapter_transition import contract
                report.update(chapter_export=True, chapter_transitions=contract())
                report["chapter"] = dict(supported=True, exit_modes=["next", "jump", "condition", "end"]
                    + (["choice"] if report["choices"]["supported"] else []),
                    endpoint="native-chapter-export", cross_chapter_routes=True,
                    source_exit_transition=True, mask_support_confirmed_by_catalog=True,
                    cg=report["cg"]["supported"], audio=False,
                    local_beat_choices=report["choices"]["supported"],
                    cg_with_local_choices=report["cg"]["supported"] and report["choices"]["cg_compatible"],
                    variables=True, option_effects=report["choices"]["supported"], beat_effects=True,
                    conditional_routes=True, loops=True, paired_native_state_required=True,
                    state_storage="private_volatile_tail", reset_variables_on_scene_entry=False,
                    save_load_verified=False, rewind_verified=False,
                    support_confirmed_on_export=True, runtime_verified=False)
                report["limitations"] = [s for s in report["limitations"] if "整章输出仍待接入" not in s]
                report["limitations"].append("多场景已接变量、条件、循环及已匹配的 CG 和选项；声音按目标能力开放，存读档与回溯尚未实机确认。")
            except (ValueError, KeyError, OSError) as exc:
                report["chapter_message"] = str(exc)
        try:
            from .native_audio import NativeAudioBackend
            audio = NativeAudioBackend(context)
            kinds = sorted(kind for kind,row in audio.bindings.items()
                if any((target.root/name).is_file() for name in row['routes']))
            if kinds:
                if not paired_audio_state:
                    NativeSceneState(target)
                voice_history, voice_history_message = None, None
                if 'voice' in kinds:
                    try:
                        voice_history = audio.voice.bind_backlog()
                    except ValueError as exc:
                        voice_history_message = str(exc)
                report['audio'].update(supported=True,kinds=kinds,
                    native=audio.report(),chapter_mainline=True,
                    voice='voice' in kinds,voice_backlog_replay=voice_history is not None,
                    voice_backlog=voice_history.report() if voice_history else None,
                    voice_backlog_message=voice_history_message,
                    voice_current_line_replay=bool(voice_history and voice_history.current),
                    voice_current_line=voice_history.current.report() if voice_history and voice_history.current else None,
                    voice_current_line_message=voice_history.current_blocker if voice_history else voice_history_message,
                    local_choice_branches=report['choices']['supported'],support_confirmed_on_export=True)
                from .gui_audio_program import playback_contract
                report['audio']['playback'] = playback_contract(kinds, voice_backlog_replay=voice_history is not None,
                    voice_current_line_replay=bool(voice_history and voice_history.current))
                from .native_audio_resume import NativeAudioResumeBinding
                try:
                    resume=NativeAudioResumeBinding((target.root/target.executable).read_bytes())
                except (ValueError,KeyError,OSError) as exc:
                    report['audio']['original_playback_restore_message']=str(exc)
                else:
                    report['audio'].update(original_playback_restore=True,
                        original_audio_resume=resume.report(),original_playback_restore_runtime_verified=False)
                report['allowed_features'].extend('audio_'+kind for kind in kinds)
                if report.get('chapter',{}).get('supported'):
                    # The legacy boolean means all audio, including voice.
                    report['chapter']['audio_kinds']=kinds
                    report['chapter']['audio']={'bgm','se','voice'} <= set(kinds)
                report['limitations'].append('声音按实际执行的原生槽隔离，结束后接回原剧情播放位置；配套测试副本的实机听感与存读档待验收。'
                    if report['audio']['original_playback_restore'] else
                    '此目标尚未匹配原剧情音频断点续播；场内分支只执行选中路线的声音，结束时清理使用过的类型。')
                if 'voice' in kinds:
                    report['limitations'].append('原生回看配音已匹配，实际回放与存读档尚待实机验收。'
                        if voice_history else '此目标的原生回看配音尚未匹配：'+str(voice_history_message))
            else:
                report['audio'].update(native=audio.report(),message='当前目标尚无可用的音乐／音效绑定与资源包。')
        except (ValueError, KeyError, OSError) as exc:
            report['audio']['message'] = str(exc)
        if report['audio']['supported'] and report['audio']['original_playback_restore']:
            try:
                from .native_movie import NativeMovieBinding
                movie = NativeMovieBinding(context)
                movie.assert_audio(audio)
                if screen is None:
                    raise ValueError('此目标的 OP 安全转场助手尚未匹配。')
                movie.screen_sites(screen)
                report['movie'].update(supported=True, native=movie.report(),
                    endpoint='scene-export', beat_kind='movie',
                    chapter_mainline=True, chapter_endpoint='native-chapter-export',
                    chapter_single_movie_beat=False, sequential_movie_beats=True,
                    same_target_files_only=False, registered_source_import=True,
                    target_native_extensions=movie.suffixes, decoder_compatibility_verified=False,
                    sequence_transition='first_entry_last_exit', between_movies='cut', skippable_per_movie=True,
                    movie_exit_choices=False,
                    movie_exit_conditions=False, transition_handoff='native_ready_and_before_stop',
                    skippable=True, waits_for_native_end=True,
                    duration_is_preview_estimate=True, support_confirmed_on_export=True)
                report['allowed_features'].append('movie_standalone_op')
                report['allowed_features'].append('movie_chapter_op')
            except (ValueError, KeyError, OSError) as exc:
                report['movie']['message'] = str(exc)
        target.check_unchanged()
        return report
