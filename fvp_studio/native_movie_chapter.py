"""Deferred movie reveal and source-owned exits, using proven screen helpers.

The native movie starts its decoder and waits for readiness before invoking
our reveal callback. Chapter setup must not reveal an empty OP stage first.
Callbacks replace the original broad fade wrappers (which can unload CGs).
"""
from copy import deepcopy
import json
import struct

from .gui_chapter_transition import transition_values
from .hoshimemo_scene_hook import _arguments, _call, _push_global, _pop_global
from .native_audio import _stack


def transition_key(value):
    return json.dumps(transition_values(value), sort_keys=True)


class NativeMovieChapter:
    def __init__(self, binding, owner, screen, chapter, movie_scenes):
        if screen.target is not owner.target or screen.binding.source is not binding.source:
            raise ValueError('影片和章节转场不属于同一原生目标。')
        self.binding, self.screen, self.output = binding, screen, screen.output
        self.base = len(binding.source.original_bytes)
        self.sites = binding.screen_sites(screen.binding)
        self.chapter, self.movie_scenes = chapter, set(movie_scenes)
        self.routes = {r['scene_id']: r for r in chapter['routes']} if chapter else {}
        self.transitions = [transition_values()]
        for route in self.routes.values():
            value = transition_values(route.get('transition'))
            if value not in self.transitions:
                self.transitions.append(value)
        self.indexes = {transition_key(t): n for n, t in enumerate(self.transitions)}
        self.cell = (owner.snapshot_storage.reserve_private(1, 'movie_incoming_transition')['private_global_ids'][0]
                     if chapter else None)
        if self.cell is not None:
            self.output.extend(_arguments([0]) + _pop_global(self.cell))
        self.enter_address = self._entry_callback()
        self.sequence_enter_address = None
        self.exit_addresses = {}

    def _function(self, argc, emit):
        start = len(self.output)
        self.output.extend(b'\x06' + bytes(4))
        address = self.base + len(self.output)
        self.output.extend(bytes((1, argc, 0)))
        state = self.screen.state()
        emit()
        self.output.extend(b'\x04')
        struct.pack_into('<I', self.output, start+1, self.base+len(self.output))
        self.screen.restore_compiler_state(state)
        return address

    def _entry_callback(self):
        def emit():
            if self.cell is None:
                self._forward('reveal')
                return
            for n, transition in enumerate(self.transitions):
                self.output.extend(_push_global(self.cell)+_arguments([n])+b'\x22')
                skip = len(self.output)
                self.output.extend(b'\x07'+bytes(4))
                self.screen.chapter_after(transition)
                self.output.extend(b'\x04')
                struct.pack_into('<I',self.output,skip+1,self.base+len(self.output))
            # All assigned values are from the closed table. Still reveal
            # safely if a corrupted private cell reaches the default path.
            self.screen.chapter_after(None)
        return self._function(self.sites['reveal_args'], emit)

    def _forward(self, name):
        count = self.sites[name+'_args']
        root = getattr(self.screen.binding, name)
        # Keep native duration/colour but use the isolated screen helper's
        # proven auxiliary mode, not the broad original UI/CG refresh mode.
        parameters = (_stack(-count-1)+_arguments([1] if root.args==2 else []) if name=='reveal' else
            b''.join(_stack(k-count-1) for k in range(5))
            + _arguments([1,0,-1] if root.args==8 else []))
        self.output.extend(parameters + _call(getattr(self.screen,name))
            + self.screen.binding.syscall('DissolveWait',(True,)))
        self.screen.operations.append(dict(kind='MovieNativeTransition', method=name))

    def overrides(self, scene_id, *, first=True, last=True):
        enter_address = self.enter_address
        if not first:
            if self.sequence_enter_address is None:
                # Internal clips cut in only after their own native ready
                # wait; do not replay the chapter's incoming transition.
                self.sequence_enter_address = self._function(self.sites['reveal_args'],
                    lambda: self.screen.chapter_after(dict(type='cut', duration_ms=0)))
            enter_address = self.sequence_enter_address
        key = (scene_id, last)
        if key not in self.exit_addresses:
            transition = (transition_values(self.routes[scene_id].get('transition')) if self.chapter and last
                          else dict(type='cut', duration_ms=0))
            if self.chapter and last and self.routes[scene_id]['mode'] == 'end':
                transition = transition_values()
            def emit():
                if not self.chapter and last:
                    self._forward('colour')
                    return
                self.screen.restore_compiler_state(None)
                self.screen.chapter_before(transition)
            self.exit_addresses[key] = self._function(self.sites['colour_args'], emit)
        return {**{at: enter_address for at in self.sites['reveal_calls']},
                **{at: self.exit_addresses[key] for at in self.sites['colour_calls']}}

    def enter_transition(self, scene_id, transition):
        if scene_id not in self.movie_scenes:
            return False
        self.output.extend(_arguments([self.indexes[transition_key(transition)]])+_pop_global(self.cell))
        return True

    def after_movie(self, scene_id, *, last=True):
        if not last:
            self.screen.restore_compiler_state(None)
            return
        value = transition_values(self.routes[scene_id].get('transition')) if self.chapter else dict(type='white')
        if self.chapter and self.routes[scene_id]['mode'] == 'end':
            value = transition_values()
        self.screen.restore_compiler_state(value['type'] if value['type'] in ('black','white') else None)

    def finish(self):
        if self.cell is not None:
            self.output.extend(_arguments([None])+_pop_global(self.cell))

    def report(self):
        return dict(chapter_mainline=bool(self.chapter), movie_scene_ids=sorted(self.movie_scenes),
            deferred_reveal_until_movie_ready=True, source_transition_before_movie_stop=True,
            original_broad_screen_cleanup_replaced=True, screen_sites=deepcopy(self.sites),
            incoming_transitions=deepcopy(self.transitions),
            sequential_movie_beats=True, sequence_transition='first_entry_last_exit', between_movies='cut',
            movie_exit_choices=False, mixed_beats=False, runtime_verified=False)
