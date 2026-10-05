"""Chapter routes from the existing GUI scene.exit data, independent of ABI.

The graph does not sort a story into a linear script or run every option. It
keeps stable scene IDs, follows only connected scenes, and preserves loops.
The Hoshi-specific SceneBuilder remains a separate backend adapter.
"""
from collections import deque
from copy import deepcopy

from .gui_native_preflight import (MAX_BYTES, PROJECT_SCHEMA, SCENE_RE, FrozenResources,
                                   SceneBuilder, canonical, checksum, ident, object_only)
from .gui_runtime import GuiRuntimeError
from .gui_story_logic import effects, predicate, route_targets, variables

PLAN_SCHEMA = "fvp-gui-chapter-plan/1"
PROGRAM_SCHEMA = "fvp-gui-chapter-program/1"
REQUEST_SCHEMA = "fvp-gui-chapter-export-request/1"
MAX_SCENES = 64
MAX_EVENTS = 16000
BOUNDARY_MS = 800


def reject(code, message, *, chapter_id=None, scene_id=None, field="exit"):
    error = GuiRuntimeError(code, message, 422)
    error.issues = [dict(level="error", code=code, message=message, chapter_id=chapter_id,
                         scene_id=scene_id, field=field)]
    raise error


def chapter_plan(document, chapter_id):
    """Follow explicit scene links, including other chapters, read-only.

    `next` remains chapter-local. Crossing a chapter boundary always requires
    an explicit stable-ID jump, option or condition; chapter order is not flow.
    """
    object_only(document, "工程文件")
    if document.get("schema") != PROJECT_SCHEMA:
        raise GuiRuntimeError("invalid_request", "工程文件格式不支持。")
    ident(chapter_id, "章节 ID")
    project = object_only(document.get("project"), "工程")
    chapters = project.get("chapters")
    scenes = object_only(project.get("scenes"), "场景表")
    if not isinstance(chapters, list) or len(chapters) > 256:
        raise GuiRuntimeError("invalid_request", "章节表不正确。")
    try:
        definitions = variables(project.get("variables", {}))
    except (ValueError, TypeError) as exc:
        reject("invalid_variables", str(exc), chapter_id=chapter_id, field="variables")
    indexed, owners, indexes = {}, {}, {}
    for candidate in chapters:
        object_only(candidate, "章节")
        cid = ident(candidate.get("id"), "章节 ID")
        if cid in indexed:
            reject("ambiguous_chapter", "章节 ID 重复，请先调整。", chapter_id=cid, field="chapters")
        members = candidate.get("scenes")
        if (not isinstance(members, list)
                or any(not isinstance(s, str) or not SCENE_RE.fullmatch(s) for s in members)
                or len(set(members)) != len(members)):
            reject("invalid_scene_ids", "章节里的场景 ID 不正确或重复。", chapter_id=cid, field="scenes")
        indexed[cid] = candidate
        for index, sid in enumerate(members):
            if sid in owners:
                reject("ambiguous_chapter", "同一个场景被放进了多个章节，请先调整。", chapter_id=cid, scene_id=sid, field="scenes")
            owners[sid], indexes[sid] = cid, index
    if chapter_id not in indexed:
        raise GuiRuntimeError("chapter_not_found", "找不到这个章节，或章节 ID 重复。", 404)
    chapter = indexed[chapter_id]
    ids = chapter.get("scenes")
    if not ids:
        reject("chapter_size", "这个章节还没有场景。", chapter_id=chapter_id, field="scenes")
    title = chapter.get("title")
    if not isinstance(title, str) or not title.strip() or len(title) > 512:
        reject("invalid_title", "章节需要一个有效标题。", chapter_id=chapter_id, field="title")
    routes, successors = {}, {}

    def target(value, sid):
        if not isinstance(value, str) or value not in owners or value not in scenes:
            reject("route_target_missing", "这条连线的目标场景不存在，或尚未放进章节，请重新连接。", chapter_id=owners[sid], scene_id=sid)
        return value

    def resolve(sid):
        cid = owners[sid]
        scene = scenes.get(sid)
        if not isinstance(scene, dict) or scene.get("id") != sid:
            reject("scene_not_found", "章节里有场景已被删除或 ID 不一致。", chapter_id=cid, scene_id=sid, field="scenes")
        exit_ = scene.get("exit")
        if not isinstance(exit_, dict) or exit_.get("type") not in ("next", "jump", "choice", "condition", "end"):
            reject("invalid_exit", "场景结束后要去哪里尚未设置。", chapter_id=cid, scene_id=sid)
        kind = exit_["type"]
        allowed = ({"type", "target"} if kind == "jump" else
                   {"type", "prompt", "options"} if kind == "choice" else
                   {"type", "test", "then", "else"} if kind == "condition" else {"type"})
        if set(exit_) != allowed:
            reject("invalid_exit", "场景出口的设置不完整，请重新设置。", chapter_id=cid, scene_id=sid)
        route = dict(scene_id=sid, mode=kind, target=None, prompt="", options=[])
        if kind == "next":
            members, index = indexed[cid]["scenes"], indexes[sid]
            route["target"] = members[index + 1] if index + 1 < len(members) else None
            if route["target"] is None:
                route["mode"] = "end"
        elif kind == "jump":
            route["target"] = target(exit_["target"], sid)
        elif kind == "condition":
            try:
                route.update(test=predicate(exit_["test"], definitions),
                             then=target(exit_["then"], sid), **{"else": target(exit_["else"], sid)})
            except (ValueError, TypeError) as exc:
                reject("invalid_condition", str(exc), chapter_id=cid, scene_id=sid)
        elif kind == "choice":
            prompt, options = exit_.get("prompt"), exit_.get("options")
            if (not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 512
                    or not isinstance(options, list) or not 2 <= len(options) <= 4):
                reject("invalid_choice", "场景级选项需要提示文字和 2～4 个选项。", chapter_id=cid, scene_id=sid)
            labels = set()
            for option in options:
                if not isinstance(option, dict) or set(option) not in ({"label", "target"}, {"label", "target", "effects"}):
                    reject("invalid_choice", "选项缺少标题或目标场景。", chapter_id=cid, scene_id=sid)
                label = option["label"]
                if not isinstance(label, str) or not label.strip() or len(label) > 512 or label.strip() in labels:
                    reject("invalid_choice", "选项标题不能为空或重复。", chapter_id=cid, scene_id=sid)
                labels.add(label.strip())
                parsed = dict(label=label, target=target(option["target"], sid))
                if "effects" in option:
                    try:
                        parsed["effects"] = effects(option["effects"], definitions)
                    except (ValueError, TypeError) as exc:
                        reject("invalid_effects", str(exc), chapter_id=cid, scene_id=sid)
                route["options"].append(parsed)
            route["prompt"] = prompt
        routes[sid] = route
        successors[sid] = route_targets(route)

    # Keep the original chapter's route checks, but don't inspect the content
    # of unrelated chapters or compile their disconnected example scenes.
    for sid in ids:
        resolve(sid)

    reached, queue = set(), deque([ids[0]])
    while queue:
        sid = queue.popleft()
        if sid in reached:
            continue
        if sid not in routes:
            resolve(sid)
        reached.add(sid)
        if len(reached) > MAX_SCENES:
            reject("chapter_size", "本次连通的路线超过 64 个场景，请拆成较小测试。", chapter_id=chapter_id, field="scenes")
        queue.extend(successors[sid])
    order = [chapter_id] + [c for c in indexed if c != chapter_id]
    included = [s for c in order for s in indexed[c]["scenes"] if s in reached]
    excluded = [s for s in ids if s not in reached]
    predecessors = {s: [] for s in included}
    for sid in included:
        for dest in successors[sid]:
            predecessors[dest].append(sid)
    ending, queue = set(), deque(s for s in included if routes[s]["mode"] == "end")
    while queue:
        sid = queue.popleft()
        if sid in ending:
            continue
        ending.add(sid)
        queue.extend(predecessors[sid])
    warnings = []
    if excluded:
        warnings.append(dict(level="warning", code="unconnected_scenes", chapter_id=chapter_id,
                             scene_ids=excluded, field="scenes", message="有场景尚未接入这章的路线，这次不会输出。"))
    trapped = [s for s in included if s not in ending]
    if trapped:
        warnings.append(dict(level="warning", code="loop_without_end", chapter_id=chapter_id,
                             scene_ids=trapped, field="exit", message="部分路线会循环而不会结束；若不是有意返回，请调整连线。"))
    return dict(ok=True, schema=PLAN_SCHEMA, chapter_id=chapter_id, title=title,
                chapter_ids=[c for c in order if any(owners[s] == c for s in included)],
                scene_chapters={s: owners[s] for s in included}, variables=definitions,
                entry_scene_id=ids[0], scene_ids=included, excluded_scene_ids=excluded,
                routes=[deepcopy(routes[s]) for s in included], warnings=warnings,
                original_game_written=False, candidate_generated=False,
                scene_boundary=dict(colour="black", duration_ms=BOUNDARY_MS,
                                    reset="scene_setup", preserve_audio=True))


def chapter_snapshot(request):
    try:
        object_only(request, "请求")
        if set(request) != {"schema", "request_id", "chapter_id", "document"} or request["schema"] != REQUEST_SCHEMA:
            raise ValueError("章节生成请求不正确。")
        ident(request["request_id"], "请求 ID")
        if len(canonical(request)) > MAX_BYTES:
            raise GuiRuntimeError("request_too_large", "工程超过 16 MiB。", 413)
        chapter_plan(request["document"], request["chapter_id"])
        if request["document"]["project"].get("source") != "hoshi":
            raise GuiRuntimeError("unsupported_target", "目前章节游戏输出只接通星空 HD，其他目标还没接好。", 422)
        return deepcopy(request)
    except GuiRuntimeError:
        raise
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        raise GuiRuntimeError("invalid_request", str(exc)[:300]) from exc


class ChapterBuilder:
    def __init__(self, runtime, document, chapter_id):
        self.runtime, self.document = runtime, document
        self.plan = chapter_plan(document, chapter_id)
        self.issues, self.mapping = list(self.plan["warnings"]), []
        self.resources = FrozenResources()

    @property
    def has_errors(self):
        return any(i["level"] == "error" for i in self.issues)

    def translate(self):
        project, events = self.document["project"], []
        roots = set()
        routes = {r["scene_id"]: r for r in self.plan["routes"]}
        for sid in self.plan["scene_ids"]:
            scene = project["scenes"][sid]
            if len(canonical(scene)) > 512 * 1024:
                reject("scene_size", "这个场景太大，请拆成较小场景。", chapter_id=self.plan["chapter_id"], scene_id=sid, field="beats")
            builder = SceneBuilder(self.runtime, project, scene, story_variables=self.plan["variables"])
            block = builder.translate()
            self.issues.extend(i for i in builder.issues if i["code"] != "scope_isolated")
            if builder.has_errors or block is None:
                continue
            roots.add(block["source_root"])
            offset = len(events)
            initial_end = next((m["event_indexes"][0] for m in builder.mapping if "beat_id" in m), len(block["events"]) - 1)
            body = deepcopy(block["events"][:-1])
            body[0]["kind"] = "GuiChapterScene"
            body.insert(initial_end, dict(kind="Transition", method="reveal", duration_ms=BOUNDARY_MS))
            body.append(dict(kind="GuiChapterExit", **deepcopy(routes[sid])))
            events.extend(body)
            for m in builder.mapping:
                if m["event_indexes"][0] >= len(block["events"]) - 1:
                    continue
                self.mapping.append({**deepcopy(m), "chapter_id": self.plan["scene_chapters"][sid],
                    "event_indexes": [offset + i + (1 if i >= initial_end else 0) for i in m["event_indexes"]]})
            self.mapping.append(dict(chapter_id=self.plan["scene_chapters"][sid], scene_id=sid, field="exit",
                                     event_indexes=[len(events) - 1]))
            for name in ("backgrounds", "portraits", "cgs", "audios", "speakers"):
                destination, additions = getattr(self.resources, name), getattr(builder.resources, name)
                for key, value in additions.items():
                    if key in destination and destination[key] != value:
                        reject("source_changed", "同一素材在生成期间发生变化，请重新导入。", chapter_id=self.plan["chapter_id"], scene_id=sid)
                    destination[key] = value
            self.resources.references.extend(builder.resources.references)
        if self.has_errors:
            return None
        if len(roots) != 1 or not 1 <= len(events) <= MAX_EVENTS:
            reject("chapter_size", "这章暂时不能一次生成，请分成较小章节。", chapter_id=self.plan["chapter_id"], field="scenes")
        root = roots.pop()
        self.resources.audio_target_root = root
        program = dict(schema=PROGRAM_SCHEMA, source_root=root, title=self.plan["title"],
                    chapter_id=self.plan["chapter_id"], entry_scene_id=self.plan["entry_scene_id"],
                    boundary_ms=BOUNDARY_MS, events=events)
        if self.plan["variables"]:
            program["variables"] = deepcopy(self.plan["variables"])
        return program

    def metadata(self):
        entry = self.plan["entry_scene_id"]
        return dict(chapter_id=self.plan["chapter_id"], chapter_title=self.plan["title"],
                    chapter_ids=list(self.plan["chapter_ids"]), scene_chapters=deepcopy(self.plan["scene_chapters"]),
                    entry_scene_id=entry, scene_id=entry, scene_ids=list(self.plan["scene_ids"]),
                    chapter_sha256=checksum(dict(variables=self.plan["variables"], routes=self.plan["routes"],
                        scenes=[self.document["project"]["scenes"][s] for s in self.plan["scene_ids"]])),
                    scene_sha256=checksum(self.document["project"]["scenes"][entry]),
                    routes=deepcopy(self.plan["routes"]), mapping=deepcopy(self.mapping))
