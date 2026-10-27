"""Target-native blocking choices and mutually exclusive scene routes.

Only the target's proven registration/input/result chain is used. No game
names, Hoshi globals, scratch variables or browser function addresses qualify.
Branches retain target-owned resource and actor changes. A common continuation
requires the same final resource/pose state. Nested menus merge into their own
selected parent route without reusing a result or executing other routes.
"""
from copy import deepcopy
import struct

from .gui_choice_tracks import KINDS as GUI_KINDS, base_event
from .native_dialogue_backend import choice_prompt_abi
from .native_scene_menu import NativeSceneMenu
from .performance_choices import CHOICE_KINDS, choice_options
from .native_scene_choice_structure import MAX_NESTING, validate_scene_choices
from .portrait_emitter import _encode_push


KINDS = GUI_KINDS | CHOICE_KINDS
BRANCH_KINDS = {"Text", "Speech", "Wait", "Action", "GuiActorMove", "GuiActorSlide", "CameraShot",
                "Portrait", "Hide", "GuiActorSwap", "GuiActorPoseSet", "GuiActorSwayStart", "GuiActorSwayStop", "GuiActorNod", "Background", "GuiBackgroundChange", "GuiBackgroundBlur", "Transition"}


def bind_scene_menu(context):
    prompt_abi, prompt_binding = choice_prompt_abi(context)
    menu = NativeSceneMenu(context)
    menu.prompt_abi = prompt_abi
    menu.prompt_binding = prompt_binding
    return menu


class NativeSceneChoiceTracks:
    def __init__(self, target, events, output, *, portraits=None, camera=None, blur=None, screen=None, cg=None,
                 scene_state=None, scene_end_indexes=(), story_effects=False, audio=None):
        # This is structural validation. The menu uses the TARGET's encoding
        # and dialogue uses its text bridge; neither inherits Hoshi's GBK check.
        self.branch_kinds = BRANCH_KINDS | (cg.branch_kinds if cg is not None else set())
        self.audio = audio
        if audio is not None:
            from .native_audio_program import NativeAudioProgram, KINDS as AUDIO_KINDS
            if not isinstance(audio, NativeAudioProgram) or audio.target is not target or audio.output is not output:
                raise ValueError("选项声音程序不属于当前目标或当前章节。")
            # Audio state lives in runtime private cells, not this compiler's
            # visual branch snapshot. Only selected routes execute the calls;
            # the next common beat retains that route's playing track/SE.
            self.branch_kinds |= AUDIO_KINDS
        if story_effects:
            from .gui_story_logic import KINDS as LOGIC_KINDS
            self.branch_kinds |= LOGIC_KINDS
        validate_scene_choices(events, self.branch_kinds, scene_end_indexes=scene_end_indexes)
        self.menu = bind_scene_menu(target.context)
        self.output, self.base = output, len(target.context.document.original_bytes)
        self.menu.prepare(output)
        if scene_state is not None:
            from .native_scene_state import NativeSceneState
            if cg is not None or not isinstance(scene_state, NativeSceneState) or scene_state.target is not target:
                raise ValueError("选项的原剧情状态恢复不属于当前目标。")
        if portraits or cg is not None or scene_state is not None:
            family = target.discovery.get("profile_seed", {}).get("native_symbols", {}).get("portrait_lifecycle_family", {})
            self.menu.protect_scene_graphics(family if portraits else {}, output,
                cg_guard=cg.guard if cg is not None else scene_state.guard if scene_state is not None else None)
        self.encoding = target.context.document.encoding
        self.portraits, self.camera, self.blur = portraits, camera, blur
        self.screen = screen
        self.cg = cg
        self.thread_owner = cg if cg is not None else scene_state
        self.background = None
        self.active, self.choices = None, []
        self.parents = []

    def join(self):
        if self.portraits:
            self.portraits.join()
        if self.camera:
            self.camera.join()
        if self.blur:
            self.blur.join()
        if self.cg is not None:
            self.cg.join()

    def state(self):
        state = dict(actors=deepcopy(self.portraits.states) if self.portraits else {},
                    loader=deepcopy(self.portraits.loader._active) if self.portraits else {},
                    camera=deepcopy(self.camera.current) if self.camera else None,
                    background=deepcopy(self.background),
                    blur=self.blur.state() if self.blur else None,
                    screen=self.screen.state() if self.screen else None)
        if self.cg is not None:
            state["cg"] = self.cg.state()
        return state

    def background_loaded(self, reference):
        # The caller supplies an already bound native destination, not an
        # untrusted GUI alias or filename found in a different game's pack.
        self.background = (reference["target_archive"], reference["target_resource_name"])

    def restore_compiler_state(self, state):
        # Rewind compiler bookkeeping only, NOT pose/code/resource addresses.
        # Every route actually starts from the same runtime menu-entry pose.
        if self.portraits:
            self.portraits.states = deepcopy(state["actors"])
            self.portraits.loader._active = deepcopy(state["loader"])
            self.portraits.loader._state_revision += 1
        if self.camera:
            self.camera.current = deepcopy(state["camera"])
        self.background = deepcopy(state["background"])
        if self.blur:
            self.blur.restore_compiler_state(state["blur"])
        if self.screen:
            self.screen.restore_compiler_state(state["screen"])
        if self.cg is not None:
            self.cg.restore_compiler_state(state["cg"])

    def patch(self, position, relative):
        struct.pack_into("<I", self.output, position+1, self.base+relative)

    def branch_end(self):
        block = self.active
        if not block["case"]:
            return
        self.join()
        if block["completion"] == "end" and self.cg is not None:
            self.cg.finish_branch()
        state = self.state()
        if (block["completion"] == "merge" and block["end_state"] is not None
                and state != block["end_state"]):
            raise ValueError("选项分支接入公共节拍前，立绘、背景、CG、镜头和黑白场状态须一致；不会自动换素材、改表情、坐标或大小。")
        block["end_state"] = state
        block["report"]["branches"][-1]["byte_end"] = len(self.output)
        block["ends"].append(len(self.output))
        self.output.extend(b"\x06\0\0\0\0")

    def emit(self, event, prompt_compiler):
        kind = event["kind"]
        parsed = base_event(event, encoding=None) if kind in GUI_KINDS else event
        base_kind = parsed["kind"]
        if base_kind == "Choice":
            self.join()
            if self.screen and self.screen.covered is not None:
                raise ValueError("显示选项前请先淡入恢复画面，不能在黑白场下等待选择。")
            options = choice_options(parsed, encoding=self.encoding)
            prompt, prompt_report = prompt_compiler(parsed["prompt"], parsed["choice_id"])
            menu_code = self.menu.compile(options)
            # Snapshot ONCE outside the retry loop. On each matching route,
            # consume it BEFORE the route body: restoring at the common tail
            # could undo a branch motion's writes to shared native caches.
            self.output.extend(self.menu.snapshot["snapshot"])
            start = len(self.output)
            self.output.extend(prompt+menu_code)
            parent_id = self.active["report"]["choice_id"] if self.active else None
            if self.active:
                self.parents.append(self.active)
            report = dict(choice_id=parsed["choice_id"], option_count=len(options),
                completion=event.get("completion", "merge"), native_prompt=prompt_report,
                parent_choice_id=parent_id, nesting_depth=len(self.parents)+1,
                prompt_requires_extra_click=False, branches=[])
            self.active = dict(start=start, baseline=self.state(), case=0, skip=None,
                ends=[], end_state=None, completion=report["completion"], report=report)
            self.choices.append(report)
        elif base_kind == "ChoiceCase":
            self.branch_end()
            block = self.active
            if block["skip"] is not None:
                self.patch(block["skip"], len(self.output))
            self.restore_compiler_state(block["baseline"])
            block["case"] = parsed["option_index"]
            self.output.extend(b"\x0f"+struct.pack("<H", self.menu.result)
                +_encode_push(block["case"], self.encoding)+b"\x22")
            block["skip"] = len(self.output)
            self.output.extend(b"\x07\0\0\0\0")
            if self.thread_owner is not None:
                # Only the selected route executes this. Preserve retry and
                # result comparison, then retire authored workers BEFORE
                # consuming shared native menu globals from the snapshot.
                self.thread_owner.cleanup_owned_threads(reason="before_selected_menu_restore")
            self.output.extend(self.menu.snapshot["restore"])
            if self.blur:
                # Only inside the selected route, after the native menu's
                # snapshot is consumed. Its shared alpha controller must not
                # overwrite the scene's authored manual strength.
                self.blur.reassert()
            block["report"]["branches"].append(dict(option_index=block["case"],
                track_id=event.get("track_id"), byte_start=len(self.output)))
        else:
            self.branch_end()
            block = self.active
            # Cancel/unknown results retry; no stale or arbitrary selection.
            self.patch(block["skip"], block["start"])
            for position in block["ends"]:
                self.patch(position, len(self.output))
            # End-mode routes share only unconditional cleanup of ALL allocated
            # slots. Their membership/pose may differ; no common pose is made up.
            self.restore_compiler_state(block["end_state"])
            self.active = self.parents.pop() if self.parents else None

    def report(self):
        return dict(schema="fvp-native-scene-choice-tracks/1", native_menu=self.menu.report(),
            native_prompt_binding=deepcopy(self.menu.prompt_binding),
            choices=deepcopy(self.choices), waits_for_selection=True, selected_route_only=True,
            unknown_result_retries_menu=True, menu_state_restored_before_selected_route=True,
            native_result_global_restored=True, extra_globals_allocated=False,
            owned_portrait_protection_requested=bool(self.portraits),
            owned_portrait_refresh_isolated=bool(self.portraits),
            original_menu_functions_patched=False,
            owned_cg_menu_refresh_isolated=self.cg is not None,
            owned_ui_cleanup_compiled_before_selected_menu_restore=self.thread_owner is not None,
            ordinary_scene_menu_refresh_isolated=self.cg is None and self.thread_owner is not None,
            selected_route_cg_cleanup_before_branch_jump=self.cg is not None,
            branch_motion_events=sorted(self.branch_kinds), branch_resource_changes=True,
            branch_audio=self.audio is not None, branch_audio_continues_after_merge=self.audio is not None,
            nested_choices=True, max_nesting=MAX_NESTING,
            nested_completion="merge_within_selected_parent_route", runtime_verified=False)
