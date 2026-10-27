"""Portable chapters in one paired scene, never one hook per scene.

Explicit links, CG and local/scene-exit choices may cross scene boundaries.
Variables and loops retain their authored control flow; audio is not omitted.
"""
from copy import deepcopy

from .gui_chapter import BOUNDARY_MS, MAX_EVENTS, chapter_plan
from .gui_native_preflight import FrozenResources, SceneBuilder, canonical, checksum, ident
from .gui_native_scene_export import FEATURES, NativeSceneExporter
from .gui_runtime import GuiRuntimeError
from .gui_scene_export import ExportError, ExportJobs, export_snapshot, REQUEST_SCHEMA as SCENE_REQUEST
from .gui_target_selection import FILE_OPTIONS
from .gui_audio_checkpoint import REQUEST_FIELD as CHECKPOINT_FIELD
from .native_scene_choice_tracks import KINDS as CHOICE_KINDS
from .native_chapter_routes import EXIT_KIND
from .gui_native_cg import KINDS as CG_KINDS, validate_opening_cg
from .gui_chapter_transition import transition_values
from .gui_story_logic import KINDS as LOGIC_KINDS, variables, route_targets, event_values as logic_values


REQUEST_SCHEMA = "fvp-gui-native-chapter-export-request/1"
PROGRAM_SCHEMA = "fvp-native-linear-chapter/1"
ROUTED_SCHEMA = "fvp-native-routed-chapter/1"
ALLOWED_KINDS = FEATURES | CG_KINDS


def linear_plan(document, chapter_id):
    plan = chapter_plan(document, chapter_id)
    if document["project"].get("source") == "hoshi":
        raise ExportError("unsupported_target", "星空章节请沿用已有的章节输出入口。")
    if plan["variables"] or any(r["mode"] not in {"next", "jump", "end"} for r in plan["routes"]):
        raise ExportError("native_chapter_route_not_connected", "通用章节先支持顺接、明确跳转和结束；选项、条件或路线变量尚未接入，不会删减输出。")
    routes = {r["scene_id"]: r for r in plan["routes"]}
    ordered, current = [], plan["entry_scene_id"]
    while current is not None:
        if current in ordered:
            raise ExportError("native_chapter_loop_not_connected", "通用章节的循环跳转尚未接入，不会截断成一次播放。")
        ordered.append(current)
        current = routes[current]["target"]
    if set(ordered) != set(plan["scene_ids"]):
        raise ExportError("native_chapter_route_not_connected", "本次章节的连线不是单一明确路线。")
    return dict(plan, scene_ids=ordered)


def native_chapter_plan(document, chapter_id):
    plan = chapter_plan(document, chapter_id)
    scenes = [document['project']['scenes'][sid] for sid in plan['scene_ids']]
    from .gui_native_feature_routing import needs_native_gestures_or_cg_transition
    if document["project"].get("source") == "hoshi" and not any(
            (isinstance(scene.get('setup'), dict) and scene['setup'].get('cg') is not None)
            or any(isinstance(b, dict) and b.get('kind') == 'movie' for b in scene.get('beats', []))
            or needs_native_gestures_or_cg_transition(scene)
            for scene in scenes):
        raise ExportError("unsupported_target", "星空章节请沿用已有的章节输出入口。")
    # Keep the old compact straight-line form. Everything else gets explicit
    # labels, including backward edges; never unroll a user's cycle.
    if not plan["variables"] and all(r["mode"] in {"next", "jump", "end"} for r in plan["routes"]):
        by_id = {r["scene_id"]: r for r in plan["routes"]}
        current, ordered = plan["entry_scene_id"], []
        while current is not None and current not in ordered:
            ordered.append(current)
            current = by_id[current]["target"]
        if current is None:
            return dict(plan, scene_ids=ordered)
    return dict(plan, requires_routes=True, scene_ids=[plan["entry_scene_id"]]
        + [s for s in plan["scene_ids"] if s != plan["entry_scene_id"]])


def native_chapter_snapshot(request):
    if not isinstance(request, dict):
        raise GuiRuntimeError("invalid_request", "通用章节请求必须为对象。")
    required = {"schema", "request_id", "chapter_id", "document"}
    if (request.get("schema") != REQUEST_SCHEMA or not required.issubset(request)
            or set(request) - required - {"target_encoding", CHECKPOINT_FIELD, *FILE_OPTIONS}):
        raise GuiRuntimeError("invalid_request", "通用章节请求缺少内容或包含未允许的选项。")
    plan = native_chapter_plan(request["document"], request["chapter_id"])
    scene_request = {k: deepcopy(v) for k, v in request.items() if k not in {"schema", "chapter_id"}}
    scene_request.update(schema=SCENE_REQUEST, scene_id=plan["entry_scene_id"])
    # Reuse the exact bounded request, encoding, local filename and ID rules.
    export_snapshot(scene_request)
    return deepcopy(request)


def validate_linear_program(program):
    metadata = program.get("native_chapter")
    if metadata is None:
        return None
    required = {"schema", "chapter_id", "scene_ids", "scenes", "boundary_ms"}
    if (not isinstance(metadata, dict) or set(metadata) != required
            or metadata["schema"] != PROGRAM_SCHEMA or metadata["boundary_ms"] != BOUNDARY_MS):
        raise ExportError("invalid_native_chapter", "通用章节的内部编译范围不完整。")
    ident(metadata["chapter_id"], "章节 ID")
    events, rows = program["events"], metadata["scenes"]
    if (not isinstance(rows, list) or not 1 <= len(rows) <= 64
            or not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS
            or any(e.get("kind") not in ALLOWED_KINDS for e in events)
            or [e["kind"] for e in events].count("End") != 1 or events[-1]["kind"] != "End"):
        raise ExportError("invalid_native_chapter", "通用章节含有未接通的指令，或不是一个完整结束的场景流。")
    indexes = [i for i, e in enumerate(events) if e["kind"] == "Scene"]
    if (any(not isinstance(row, dict) or set(row) != {"scene_id", "event_index", "setup_end"}
                or type(row["event_index"]) is not int or type(row["setup_end"]) is not int for row in rows)
            or indexes != [row["event_index"] for row in rows] or indexes[0] != 0
            or metadata["scene_ids"] != [row["scene_id"] for row in rows]
            or len(set(metadata["scene_ids"])) != len(rows)):
        raise ExportError("invalid_native_chapter", "通用章节的稳定场景 ID 与入口不一致。")
    black = dict(kind="Transition", method="black_out", duration_ms=BOUNDARY_MS)
    reveal = dict(kind="Transition", method="reveal", duration_ms=BOUNDARY_MS)
    for n, row in enumerate(rows):
        start, setup_end = row["event_index"], row["setup_end"]
        end = indexes[n+1]-1 if n+1 < len(indexes) else len(events)-1
        setup_start = start+2 if n == 0 else start+1
        if (events[start].get("scene_id") != row["scene_id"]
                or not setup_start < setup_end < end or events[setup_end] != reveal
                or (events[start+1] if n == 0 else events[start-1]) != black
                or events[setup_start]["kind"] != "Background"
                or any(e["kind"] not in {"Background", "Portrait"} for e in events[setup_start:setup_end])):
            raise ExportError("invalid_native_chapter", "场景必须在遮盖下重置开场布置，再淡入恢复。")
    return deepcopy(metadata)


def validate_native_chapter_program(program):
    metadata = program.get("native_chapter")
    if not isinstance(metadata, dict) or metadata.get("schema") != ROUTED_SCHEMA:
        return validate_linear_program(program)
    required = {"schema", "chapter_id", "entry_scene_id", "scene_ids", "scenes", "routes", "boundary_ms"}
    events, rows = program.get("events"), metadata.get("scenes")
    if (set(metadata) not in (required, required | {"variables"}) or metadata["boundary_ms"] != BOUNDARY_MS
            or not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS
            or not isinstance(rows, list) or not 1 <= len(rows) <= 64
            or any(not isinstance(e, dict) or e.get("kind") not in ALLOWED_KINDS | LOGIC_KINDS | {EXIT_KIND} for e in events)
            or [e["kind"] for e in events].count("End") != 1 or events[-1]["kind"] != "End"):
        raise ExportError("invalid_native_chapter", "场景分支的内部编译范围不完整。")
    ident(metadata["chapter_id"], "章节 ID")
    try:
        definitions = variables(metadata.get("variables", {}))
        for event in events:
            if event["kind"] in LOGIC_KINDS:
                logic_values(event["kind"], {k: v for k, v in event.items() if k != "kind"}, definitions)
    except (ValueError, TypeError, KeyError) as exc:
        raise ExportError("invalid_native_chapter", str(exc)) from exc
    if any(not isinstance(r, dict) or set(r) != {"scene_id", "event_index", "setup_end", "exit_index"}
            or any(type(r[k]) is not int for k in ("event_index", "setup_end", "exit_index")) for r in rows):
        raise ExportError("invalid_native_chapter", "场景分支缺少入口、开场或出口位置。")
    ids = [r["scene_id"] for r in rows]
    if (metadata["scene_ids"] != ids or len(set(ids)) != len(ids)
            or metadata["entry_scene_id"] != ids[0]
            or [i for i, e in enumerate(events) if e["kind"] == "Scene"] != [r["event_index"] for r in rows]
            or [i for i, e in enumerate(events) if e["kind"] == EXIT_KIND] != [r["exit_index"] for r in rows]
            or rows[0]["event_index"] != 1
            or events[0] != dict(kind="Transition", method="black_out", duration_ms=BOUNDARY_MS)):
        raise ExportError("invalid_native_chapter", "场景分支的稳定 ID 与入口不一致。")
    routes = metadata["routes"]
    if not isinstance(routes, list) or len(routes) != len(rows):
        raise ExportError("invalid_native_chapter", "场景分支缺少对应出口。")
    from .gui_chapter_program import exit_values
    for n, (row, route) in enumerate(zip(rows, routes)):
        start, setup_end, exit_index = (row[k] for k in ("event_index", "setup_end", "exit_index"))
        after = rows[n+1]["event_index"] if n+1 < len(rows) else len(events)-1
        movie_body = events[setup_end+1:exit_index]
        empty_movie_setup = (start+1 == setup_end and bool(movie_body)
                             and all(e['kind'] == 'GuiMovie' for e in movie_body))
        if (not 0 < start+1 <= setup_end < exit_index == after-1 < len(events)-1
                or events[start].get("scene_id") != row["scene_id"]
                or not isinstance(route, dict) or route.get("scene_id") != row["scene_id"]
                or events[exit_index] != dict(kind=EXIT_KIND, **route)
                or (not empty_movie_setup and events[start+1]["kind"] != "Background")
                or any(e["kind"] not in {"Background", "Portrait", "GuiCGSetup"} for e in events[start+1:setup_end])
                or events[setup_end] != dict(kind="Transition", method="reveal", duration_ms=BOUNDARY_MS)):
            raise ExportError("invalid_native_chapter", "场景须在遮盖下布置、淡入，并通过自己的出口转移。")
        try:
            # Structural parser only; target-specific encoding/menu binding is
            # done later by the portable native menu, never Hoshi's emitter.
            exit_values(dict(kind="GuiChapterExit", **route), definitions, encoding=None)
        except (ValueError, TypeError, KeyError) as exc:
            raise ExportError("invalid_native_chapter", str(exc)) from exc
        if any(t not in ids for t in route_targets(route)):
            raise ExportError("invalid_native_chapter", "场景分支指向本次没有编译的入口。")
    try:
        validate_opening_cg(program, metadata)
    except (ValueError, TypeError, KeyError) as exc:
        raise ExportError("invalid_native_chapter", str(exc)) from exc
    visited = set()
    by_id = {r["scene_id"]: r for r in routes}

    def visit(sid):
        if sid in visited:
            return
        visited.add(sid)
        route = by_id[sid]
        for target in route_targets(route):
            visit(target)

    visit(ids[0])
    if visited != set(ids):
        raise ExportError("invalid_native_chapter", "场景分支不完整或含有未连接入口。")
    from .gui_movie_program import movie_scene_ids
    try:
        movie_scene_ids(program,metadata)
    except ValueError as exc:
        raise ExportError('native_movie_scope',str(exc)) from exc
    return deepcopy(metadata)


class NativeChapterBuilder:
    def __init__(self, runtime, document, chapter_id, *, native_rotation_converter=None):
        self.runtime, self.document = runtime, document
        self.plan = native_chapter_plan(document, chapter_id)
        self.converter = native_rotation_converter
        self.resources = FrozenResources()
        self.issues, self.mapping, self.rotation_conversions = list(self.plan["warnings"]), [], []

    @property
    def has_errors(self):
        return any(i["level"] == "error" for i in self.issues)

    def translate(self):
        events, rows, roots, swaps, motions, cg_groups = [], [], set(), [], [], []
        stages, cg_lines, backgrounds, masks = [], [], [], []
        project = self.document["project"]
        black = dict(kind="Transition", method="black_out", duration_ms=BOUNDARY_MS)
        reveal = dict(kind="Transition", method="reveal", duration_ms=BOUNDARY_MS)
        compiled = []
        for sid in self.plan["scene_ids"]:
            scene = project["scenes"][sid]
            if len(canonical(scene)) > 512*1024:
                raise ExportError("scene_size", "场景过大，请先拆分。")
            builder = SceneBuilder(self.runtime, project, scene, native_export_target=True,
                native_rotation_converter=self.converter, story_variables=self.plan["variables"])
            block = builder.translate()
            self.issues.extend(i for i in builder.issues if i["code"] != "scope_isolated")
            if builder.has_errors or block is None:
                continue
            unsupported = [i for i, e in enumerate(block["events"]) if e["kind"] not in ALLOWED_KINDS | LOGIC_KINDS]
            if unsupported:
                for i in unsupported:
                    where = next((m for m in builder.mapping if i in m["event_indexes"]), {})
                    self.issues.append(dict(level="error", code="native_chapter_feature_not_connected",
                        **{k: v for k, v in where.items() if k != "event_indexes"},
                        message="通用多场景中的声音或该类事件尚未接入，不会省略后输出。"))
                continue
            compiled.append((sid, builder, block))
        if self.has_errors:
            return None
        rich_scenes = any(e["kind"] in CG_KINDS | CHOICE_KINDS | {'GuiMovie'}
            for _, _, block in compiled for e in block["events"])
        routed = self.plan.get("requires_routes", False) or rich_scenes or any("transition" in r for r in self.plan["routes"])
        routes = {r["scene_id"]: deepcopy(r) for r in self.plan["routes"]}
        if rich_scenes:
            # Selected local end branches must own their scene exit. Use the
            # same setup subroutines as explicit transitions, including old
            # documents whose default transition was never persisted.
            for route in routes.values():
                route.setdefault("transition", transition_values())
        if routed:
            events.append(deepcopy(black))
        for ordinal, (sid, builder, block) in enumerate(compiled):
            roots.add(block["source_root"])
            if ordinal and not routed:
                events.append(deepcopy(black))
            start, remap = len(events), {}
            initial_end = next((m["event_indexes"][0] for m in builder.mapping if "beat_id" in m),
                len(block["events"])-1)
            row = dict(scene_id=sid, event_index=start, setup_end=None)
            for i, event in enumerate(block["events"][:-1]):
                if i == initial_end:
                    row["setup_end"] = len(events)
                    events.append(deepcopy(reveal))
                remap[i] = len(events)
                event = deepcopy(event)
                if event["kind"] in CHOICE_KINDS:
                    for key in ("choice_id", "track_id", "merge_beat_id"):
                        if event.get(key) is not None:
                            event[key] = "C"+checksum([sid, key, event[key]])[:30]
                events.append(event)
                if i == 0 and not ordinal and not routed:
                    events.append(deepcopy(black))
            if row["setup_end"] is None:
                row["setup_end"] = len(events)
                events.append(deepcopy(reveal))
            if routed:
                row["exit_index"] = len(events)
                events.append(dict(kind=EXIT_KIND, **deepcopy(routes[sid])))
                self.mapping.append(dict(scene_id=sid, chapter_id=self.plan["scene_chapters"][sid],
                    field="exit", event_indexes=[row["exit_index"]]))
            rows.append(row)
            for mapping in builder.mapping:
                kept = [remap[i] for i in mapping["event_indexes"] if i in remap]
                if kept:
                    self.mapping.append({**deepcopy(mapping), "event_indexes": kept,
                        "chapter_id": self.plan["scene_chapters"][sid]})
            for name, destination in (("native_parallel_swaps", swaps), ("native_parallel_motion", motions),
                    ("native_parallel_cg", cg_groups), ('native_parallel_stage', stages),
                    ('native_cg_exit_lines', cg_lines), ('native_parallel_backgrounds', backgrounds),
                    ('native_mask_transitions', masks)):
                for group in block.get(name, []):
                    group = deepcopy(group)
                    group["beat_id"] = "chapter_"+checksum([sid, group["beat_id"]])[:48]
                    for key in ("swap_index", "swap_indexes", "action_indexes", 'background_index', 'launch_index', 'complete_index',
                            'prepare_index', 'transition_index'):
                        if key in group:
                            group[key] = ([remap[i] for i in group[key]] if isinstance(group[key], list)
                                else remap[group[key]])
                    destination.append(group)
            for name in ("backgrounds", "portraits", "cgs", "audios", "movies", "speakers"):
                destination = getattr(self.resources, name)
                for key, value in getattr(builder.resources, name).items():
                    if key in destination and destination[key] != value:
                        raise ExportError("source_changed", "同一素材在章节生成期间发生变化。")
                    destination[key] = value
            self.resources.references.extend(builder.resources.references)
            self.rotation_conversions.extend(builder.rotation_conversions)
        if self.has_errors:
            return None
        if len(roots) != 1:
            raise ExportError("native_chapter_source_mismatch", "章节场景没有绑定同一输出目标。")
        events.append(dict(kind="End"))
        self.resources.audio_target_root = next(iter(roots))
        program = dict(schema="fvp-gui-native-routed-chapter-program/1" if routed
                else "fvp-gui-native-linear-chapter-program/1", source_root=next(iter(roots)),
            title=self.plan["title"], events=events,
            native_chapter=dict(schema=PROGRAM_SCHEMA, chapter_id=self.plan["chapter_id"],
                scene_ids=list(self.plan["scene_ids"]), scenes=rows, boundary_ms=BOUNDARY_MS))
        if routed:
            program["native_chapter"].update(schema=ROUTED_SCHEMA, entry_scene_id=self.plan["entry_scene_id"],
                routes=[deepcopy(routes[s]) for s in self.plan["scene_ids"]])
            if self.plan["variables"]:
                program["native_chapter"]["variables"] = deepcopy(self.plan["variables"])
        if swaps:
            program["native_parallel_swaps"] = swaps
        if motions:
            program["native_parallel_motion"] = motions
        if cg_groups:
            program['native_parallel_cg'] = cg_groups
        if stages:
            program['native_parallel_stage'] = stages
        if cg_lines:
            program['native_cg_exit_lines'] = cg_lines
        if backgrounds:
            program['native_parallel_backgrounds'] = backgrounds
        if masks:
            program['native_mask_transitions'] = masks
        validate_native_chapter_program(program)
        return program


class NativeChapterExporter(NativeSceneExporter):
    requires_paired_scene_state = True
    extra_event_kinds = {EXIT_KIND} | LOGIC_KINDS

    def make_builder(self, request, *, native_rotation_converter):
        return NativeChapterBuilder(self.runtime, request["document"], request["chapter_id"],
            native_rotation_converter=native_rotation_converter)

    def build(self, request, update, **options):
        request = native_chapter_snapshot(request)
        request["scene_id"] = native_chapter_plan(request["document"], request["chapter_id"])["entry_scene_id"]
        return super().build(request, update, _scene_native_state_candidate=True, **options)

    def run(self, request, update):
        built = self.build(request, update)
        result = self.install(built, update)
        result["native_chapter"] = deepcopy(built.report["native_chapter"])
        return result, built.issues


class NativeChapterExportJobs(ExportJobs):
    job_schema = "fvp-gui-native-chapter-export-job/1"
    snapshot = staticmethod(native_chapter_snapshot)

    def job_metadata(self, snapshot):
        plan = native_chapter_plan(snapshot["document"], snapshot["chapter_id"])
        result = dict(chapter_id=plan["chapter_id"], chapter_title=plan["title"],
            scene_ids=plan["scene_ids"], entry_scene_id=plan["entry_scene_id"],
            target_source=snapshot["document"]["project"]["source"])
        for key in ("target_encoding", CHECKPOINT_FIELD, *FILE_OPTIONS):
            if key in snapshot:
                result[key] = snapshot[key]
        return result
