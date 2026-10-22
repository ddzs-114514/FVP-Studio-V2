"""Portable scene exits using the selected target's own blocking menu.

Each scene label is emitted once. Every exit covers and clears its actual
source stage before jumping; compilation order is never runtime route order.
Only the common final tail restores the inherited story's native snapshot.
"""
from copy import deepcopy
import struct

from .native_scene_choice_tracks import NativeSceneChoiceTracks
from .portrait_emitter import _encode_push
from .gui_chapter_transition import transition_values


EXIT_KIND = "GuiNativeChapterExit"


class NativeChapterRoutes(NativeSceneChoiceTracks):
    def __init__(self, target, events, output, *, boundary_ms, subroutine_entries=False,
                 menu_required=True, story_bank=None, **components):
        if menu_required:
            super().__init__(target, events, output,
                scene_end_indexes={i for i, e in enumerate(events) if e["kind"] == EXIT_KIND},
                story_effects=story_bank is not None, **components)
        else:
            # A straight route does not acquire a native menu requirement.
            from .native_scene_state import NativeSceneState
            from .native_scene_cg import NativeSceneCG
            self.cg = components.get("cg")
            self.thread_owner = self.cg if self.cg is not None else components.get("scene_state")
            owner_type = NativeSceneCG if self.cg is not None else NativeSceneState
            if not isinstance(self.thread_owner, owner_type) or self.thread_owner.target is not target:
                raise ValueError("章节恢复接口不属于当前目标。")
            self.output, self.base = output, len(target.context.document.original_bytes)
            self.encoding = target.context.document.encoding
            self.menu, self.background = None, None
            self.active, self.choices, self.parents = None, [], []
            self.portraits, self.camera, self.blur, self.screen = (
                components.get(k) for k in ("portraits", "camera", "blur", "screen"))
        if self.screen is None or self.thread_owner is None:
            raise ValueError("场景路由需要当前目标配对的转场和状态恢复接口。")
        self.boundary_ms = boundary_ms
        self.labels, self.transfers, self.exits = {}, [], []
        self.entry_state = None
        self.subroutine_entries = subroutine_entries
        self.setup_labels, self.setup_calls = {}, []
        self.current_scene = None
        self.scene_routes = {e["scene_id"]: e for e in events if e["kind"] == EXIT_KIND}
        self.local_scene_ended = False
        self.local_prompt_compiler = None
        self.story_bank = story_bank

    def call_setup(self, scene_id, transition):
        at = len(self.output)
        self.output.extend(b"\x02\0\0\0\0")
        self.setup_calls.append((at, scene_id))
        self.screen.chapter_after(transition)
        at = len(self.output)
        self.output.extend(b"\x06\0\0\0\0")
        self.transfers.append((at, scene_id))
        return at

    def enter(self, scene_id):
        if self.active is not None or self.parents:
            raise ValueError("场内选项必须先结束，不能跨入另一场景。")
        if scene_id in self.labels or scene_id in self.setup_labels:
            raise ValueError("场景入口不能重复编译。")
        if self.entry_state is None:
            if self.screen.covered != "black":
                raise ValueError("章节入口须先遮盖，再设置场景。")
            self.entry_state = self.state()
            if self.subroutine_entries:
                self.call_setup(scene_id, None)
        else:
            # Every incoming edge has already retired its source's workers and
            # resources under cover. Rewind bookkeeping only, not native state.
            self.restore_compiler_state(self.entry_state)
        if self.subroutine_entries:
            self.setup_labels[scene_id] = len(self.output)
            self.output.extend(b"\x01\0\0")
            self.screen.restore_compiler_state("black")
        else:
            self.labels[scene_id] = len(self.output)
        self.current_scene = scene_id
        self.local_scene_ended = False

    def ready(self):
        self.join()
        self.output.extend(b"\x04")
        self.labels[self.current_scene] = len(self.output)
        self.screen.restore_compiler_state(None)

    def transfer(self, target, transition=None):
        self.join()
        transition = transition_values(transition if target is not None else None)
        if self.subroutine_entries:
            self.screen.chapter_before(transition)
        else:
            self.screen.emit(dict(kind="Transition", method="black_out", duration_ms=self.boundary_ms))
        if self.cg is not None:
            self.cg.leave_scene()
        if self.portraits:
            for actor in sorted(self.portraits.states):
                self.portraits.emit(dict(kind="Hide", actor=actor))
        if self.blur:
            self.blur.clear()
        if self.camera:
            self.camera.finish()
        self.thread_owner.cleanup_owned_threads(reason="chapter_selected_scene_exit")
        if self.subroutine_entries and target is not None:
            return self.call_setup(target, transition)
        at = len(self.output)
        self.output.extend(b"\x06\0\0\0\0")
        self.transfers.append((at, target))
        return at

    def exit(self, route, prompt_compiler):
        if self.local_scene_ended:
            return
        self.join()
        report = dict(scene_id=route["scene_id"], mode=route["mode"], routes=[],
            transition=transition_values(route.get("transition")))
        if route["mode"] == "condition":
            if self.story_bank is None:
                raise ValueError("条件出口缺少本章节的剧情变量。")
            self.output.extend(self.story_bank.compare(route["test"]))
            skipped = len(self.output)
            self.output.extend(b"\x07\0\0\0\0")
            baseline = self.state()
            at = self.transfer(route["then"], route.get("transition"))
            report["routes"].append(dict(condition=True, target=route["then"], jump_offset=at))
            self.patch(skipped, len(self.output))
            self.restore_compiler_state(baseline)
            at = self.transfer(route["else"], route.get("transition"))
            report["routes"].append(dict(condition=False, target=route["else"], jump_offset=at))
            report.update(test=deepcopy(route["test"]),
                variable_slot=self.story_bank.slots[route["test"]["variable"]])
        elif route["mode"] != "choice":
            at = self.transfer(route["target"], route.get("transition"))
            report["routes"].append(dict(target=route["target"], jump_offset=at))
        else:
            if self.screen.covered is not None:
                raise ValueError("场景末尾显示选项前请先淡入恢复画面。")
            options = [o["label"] for o in route["options"]]
            prompt, prompt_report = prompt_compiler(route["prompt"], route["scene_id"])
            menu = self.menu.compile(options)
            # Retry does not allocate a second snapshot; consume it exactly once
            # inside the matching route, before that route changes shared caches.
            self.output.extend(self.menu.snapshot["snapshot"])
            start = len(self.output)
            self.output.extend(prompt + menu)
            baseline, skipped = self.state(), None
            for number, option in enumerate(route["options"], 1):
                if skipped is not None:
                    self.patch(skipped, len(self.output))
                    self.restore_compiler_state(baseline)
                self.output.extend(b"\x0f" + struct.pack("<H", self.menu.result)
                    + _encode_push(number, self.encoding) + b"\x22")
                skipped = len(self.output)
                self.output.extend(b"\x07\0\0\0\0")
                self.thread_owner.cleanup_owned_threads(reason="before_selected_menu_restore")
                self.output.extend(self.menu.snapshot["restore"])
                if self.blur:
                    self.blur.reassert()
                for item in option.get("effects", []):
                    if self.story_bank is None:
                        raise ValueError("选项赋值缺少本章节的剧情变量。")
                    self.story_bank.emit_effect(item)
                at = self.transfer(option["target"], route.get("transition"))
                report["routes"].append(dict(option_index=number, target=option["target"], jump_offset=at,
                    effects=deepcopy(option.get("effects", []))))
            self.patch(skipped, start)
            report.update(native_prompt=prompt_report, menu_offset=start,
                prompt_requires_extra_click=False, unknown_result="retry_menu")
        self.exits.append(report)

    def branch_end(self):
        block = self.active
        if block["completion"] != "end":
            return super().branch_end()
        if not block["case"]:
            return
        # End-mode alternatives need no fabricated common actor/CG state.
        # Each selected branch executes its own scene exit (including any
        # scene-exit menu), then jumps directly to a target setup/final tail.
        self.exit(self.scene_routes[self.current_scene], self.local_prompt_compiler)
        block["end_state"] = self.state()
        block["report"]["branches"][-1]["byte_end"] = len(self.output)

    def emit(self, event, prompt_compiler):
        ends_scene = (event["kind"] in {"ChoiceEnd", "GuiChoiceEnd"}
            and self.active is not None and self.active["completion"] == "end")
        self.local_prompt_compiler = prompt_compiler
        super().emit(event, prompt_compiler)
        if ends_scene:
            self.local_scene_ended = True

    def finalize(self, final_offset):
        for at, target in self.setup_calls:
            if target not in self.setup_labels:
                raise ValueError("场景开场子程序未绑定。")
            self.patch(at, self.setup_labels[target])
        for at, target in self.transfers:
            if target is not None and target not in self.labels:
                raise ValueError("场景跳转没有绑定到本次编译的稳定入口。")
            self.patch(at, final_offset if target is None else self.labels[target])

    def report(self):
        return dict(schema="fvp-native-chapter-routes/1", native_menu=self.menu.report() if self.menu else None,
            native_prompt_binding=deepcopy(self.menu.prompt_binding) if self.menu else None, exits=deepcopy(self.exits),
            scene_labels=deepcopy(self.labels), selected_route_only=True,
            source_exit_transition=self.subroutine_entries, setup_labels=deepcopy(self.setup_labels),
            setup_subroutine_calls=len(self.setup_calls),
            shared_scene_compiled_once=True, unknown_result_retries_menu=True,
            menu_state_restored_before_selected_route=True, extra_globals_allocated=bool(self.story_bank),
            prior_scene_workers_and_resources_cleared_before_setup=True,
            local_choices=deepcopy(self.choices), local_scene_end_uses_selected_route=True,
            cg_cleanup_before_target_setup=self.cg is not None,
            paired_native_state_required=True, loops_supported=True, conditional_routes_supported=True,
            variables_preserved_across_scene_jumps=True, runtime_verified=False)
