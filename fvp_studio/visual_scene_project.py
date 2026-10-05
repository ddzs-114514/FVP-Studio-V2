"""State model for the V2 visual scene and its story project.

The existing V2 stage is deliberately independent from the active HCB.  This
module adds a second, equally explicit boundary: every story scene is a frozen
snapshot of one selected dialogue anchor plus the scene state the user chose
for that point.  Editing the live stage afterwards does not silently rewrite
captured cues, and opening another HCB invalidates only source-bound anchors
and cues while preserving user-authored scene order and dialogue lines.

No function in this module reads or writes a game file.  HCB-specific anchor
inspection and byte generation live in :mod:`fvp_studio.hoshimemo_scene_hook`.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping

from .hcb import HcbError


LEGACY_STORY_SCHEMA = "fvp-studio-v2.story-attachment.v1"
STORY_SCHEMA = "fvp-studio-v2.story-project.v2"
STORY_SCENE_SCHEMA = "fvp-studio-v2.story-scene.v1"
STORY_TIMINGS = frozenset({"before", "after"})
MAX_INSERTED_DIALOGUE_LINES = 32
MAX_STORY_SCENES = 64
SCENE_ID_PREFIX = "story-scene-"
MAX_SCENE_ID_LENGTH = 128

SPEAKER_LABELS: Mapping[str, str] = {
    "narration": "旁白",
    "yume": "梦",
    "meya": "梅娅",
    "you": "洋",
}


class VisualSceneProjectError(HcbError):
    """Raised when a story project would lose stable scene identity."""


def _validate_scene_id(value: Any, *, field: str = "scene_id") -> str:
    """Validate an immutable scene identity without silently coercing it."""

    if not isinstance(value, str):
        raise VisualSceneProjectError(f"{field} 必须是非空字符串")
    token = value.strip()
    if (
        not token
        or token != value
        or len(token) > MAX_SCENE_ID_LENGTH
        or any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in token
        )
    ):
        raise VisualSceneProjectError(f"{field} 非法")
    return token


def _coerce_positive_serial(value: Any, *, default: int, field: str) -> int:
    if value is None:
        result = default
    elif isinstance(value, bool):
        raise VisualSceneProjectError(f"{field} 必须是正整数")
    elif isinstance(value, int):
        result = value
    elif isinstance(value, str) and value and value == value.strip():
        try:
            result = int(value)
        except ValueError as exc:
            raise VisualSceneProjectError(f"{field} 必须是正整数") from exc
    else:
        raise VisualSceneProjectError(f"{field} 必须是正整数")
    if result < 1:
        raise VisualSceneProjectError(f"{field} 必须是正整数")
    return result


def _coerce_nonnegative_counter(value: Any, *, default: int, field: str) -> int:
    if value is None:
        result = default
    elif isinstance(value, bool):
        raise VisualSceneProjectError(f"{field} 必须是非负整数")
    elif isinstance(value, int):
        result = value
    elif isinstance(value, str) and value and value == value.strip():
        try:
            result = int(value)
        except ValueError as exc:
            raise VisualSceneProjectError(f"{field} 必须是非负整数") from exc
    else:
        raise VisualSceneProjectError(f"{field} 必须是非负整数")
    if result < 0:
        raise VisualSceneProjectError(f"{field} 必须是非负整数")
    return result


def _scene_id_for_serial(serial: int) -> str:
    return f"{SCENE_ID_PREFIX}{serial:04d}"


def _serial_from_scene_id(scene_id: str) -> int | None:
    if not scene_id.startswith(SCENE_ID_PREFIX):
        return None
    suffix = scene_id[len(SCENE_ID_PREFIX) :]
    if not suffix.isdigit():
        return None
    return int(suffix)


def _next_available_scene_serial(
    scenes: list[Mapping[str, Any]], start: int
) -> int:
    used_ids = {
        str(item.get("scene_id"))
        for item in scenes
        if isinstance(item, Mapping) and item.get("scene_id") is not None
    }
    serial = max(1, int(start))
    while _scene_id_for_serial(serial) in used_ids:
        serial += 1
    return serial


def _normalise_next_scene_serial(
    value: Any, scenes: list[Mapping[str, Any]]
) -> int:
    requested = _coerce_positive_serial(
        value,
        default=1,
        field="剧情工程 next_scene_serial",
    )
    highest_existing = max(
        (
            serial
            for item in scenes
            if (serial := _serial_from_scene_id(str(item["scene_id"]))) is not None
        ),
        default=0,
    )
    serial = max(requested, len(scenes) + 1, highest_existing + 1)
    return _next_available_scene_serial(scenes, serial)


def _new_story_scene(serial: int, *, title: str | None = None) -> dict[str, Any]:
    serial = _coerce_positive_serial(
        serial,
        default=1,
        field="剧情场景 serial",
    )
    return {
        "schema": STORY_SCENE_SCHEMA,
        "scene_id": _scene_id_for_serial(serial),
        "title": str(title or f"场景 {serial}"),
        "anchor": None,
        "cue": None,
        "inserted_lines": [],
        "next_line_serial": 1,
        "revision": 0,
    }


def _normalise_story_scene(value: Mapping[str, Any], serial: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise VisualSceneProjectError("剧情场景必须是对象")
    scene = copy.deepcopy(dict(value))
    if "scene_id" not in scene:
        raise VisualSceneProjectError("剧情场景缺少稳定 scene_id")
    scene_id = _validate_scene_id(
        scene.get("scene_id"),
        field=f"剧情场景 {serial} 的 scene_id",
    )
    lines = scene.get("inserted_lines")
    if not isinstance(lines, list):
        raise VisualSceneProjectError(f"剧情场景 {scene_id} 的新增台词必须是数组")
    anchor = scene.get("anchor")
    cue = scene.get("cue")
    if anchor is not None and not isinstance(anchor, Mapping):
        raise VisualSceneProjectError(f"剧情场景 {scene_id} 的挂接点无效")
    if cue is not None and not isinstance(cue, Mapping):
        raise VisualSceneProjectError(f"剧情场景 {scene_id} 的舞台快照无效")
    scene.update(
        {
            "schema": STORY_SCENE_SCHEMA,
            "scene_id": scene_id,
            "title": str(scene.get("title") or f"场景 {serial}"),
            "anchor": copy.deepcopy(dict(anchor)) if isinstance(anchor, Mapping) else None,
            "cue": copy.deepcopy(dict(cue)) if isinstance(cue, Mapping) else None,
            "inserted_lines": copy.deepcopy(lines),
            "next_line_serial": _coerce_positive_serial(
                scene.get("next_line_serial"),
                default=1,
                field=f"剧情场景 {scene_id} 的 next_line_serial",
            ),
            "revision": _coerce_nonnegative_counter(
                scene.get("revision"),
                default=0,
                field=f"剧情场景 {scene_id} 的 revision",
            ),
        }
    )
    return scene


def _sync_active_story_view(story: dict[str, Any]) -> dict[str, Any]:
    """Expose the active scene through the legacy top-level read view.

    The canonical state lives in ``scenes``.  The four legacy keys remain as
    direct references so the existing UI can migrate incrementally without
    losing the active scene selected in the new timeline.
    """

    scenes = story.get("scenes")
    if not isinstance(scenes, list) or not scenes:
        raise VisualSceneProjectError("剧情工程至少需要一个场景")
    scene_ids = []
    for item in scenes:
        if not isinstance(item, Mapping):
            raise VisualSceneProjectError("剧情工程 scenes 含无效场景")
        scene_id = _validate_scene_id(item.get("scene_id"))
        if scene_id != item.get("scene_id"):
            raise VisualSceneProjectError("剧情工程含非法 scene_id")
        scene_ids.append(scene_id)
    if len(scene_ids) != len(set(scene_ids)):
        raise VisualSceneProjectError("剧情工程含重复 scene_id")
    raw_active_id = story.get("active_scene_id")
    if raw_active_id is None:
        active_id = scene_ids[0]
    else:
        active_id = _validate_scene_id(
            raw_active_id,
            field="剧情工程 active_scene_id",
        )
        if active_id not in scene_ids:
            raise VisualSceneProjectError(
                f"剧情工程 active_scene_id 不存在: {active_id}"
            )
    active = next(item for item in scenes if item.get("scene_id") == active_id)
    story["active_scene_id"] = active_id
    story["anchor"] = active["anchor"]
    story["cue"] = active["cue"]
    story["inserted_lines"] = active["inserted_lines"]
    story["next_line_serial"] = active["next_line_serial"]
    story["active_scene_revision"] = active["revision"]
    return active


def _find_story_scene(story: Mapping[str, Any], scene_id: Any) -> dict[str, Any]:
    token = _validate_scene_id(scene_id)
    scenes = story.get("scenes")
    if not isinstance(scenes, list):
        raise VisualSceneProjectError("剧情工程 scenes 必须是数组")
    item = next(
        (entry for entry in scenes if entry.get("scene_id") == token),
        None,
    )
    if item is None:
        raise VisualSceneProjectError(f"找不到剧情场景: {token}")
    return item


def _resolve_story_scene(
    story: dict[str, Any], scene_id: str | None = None
) -> dict[str, Any]:
    """Resolve a target from canonical scenes without changing selection."""

    if scene_id is None:
        return _sync_active_story_view(story)
    return _find_story_scene(story, scene_id)


def new_story_attachment() -> dict[str, Any]:
    """Return an empty, JSON-safe multi-scene story project."""

    first = _new_story_scene(1)
    story = {
        "schema": STORY_SCHEMA,
        "scenes": [first],
        "active_scene_id": first["scene_id"],
        "next_scene_serial": 2,
        "revision": 0,
    }
    _sync_active_story_view(story)
    return story


def ensure_story_attachment(scene: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical story project, accepting only known schemas."""

    if not isinstance(scene, dict):
        raise VisualSceneProjectError("V2 场景必须是对象")
    if "story" not in scene:
        story = new_story_attachment()
        scene["story"] = story
        return story

    raw = scene.get("story")
    if not isinstance(raw, Mapping):
        raise VisualSceneProjectError("剧情工程必须是对象")
    if not isinstance(raw, dict):
        raw = dict(raw)
        scene["story"] = raw

    schema = raw.get("schema")
    if schema == STORY_SCHEMA:
        raw_scenes = raw.get("scenes")
        if not isinstance(raw_scenes, list):
            raise VisualSceneProjectError("剧情工程 scenes 必须是数组")
        if len(raw_scenes) > MAX_STORY_SCENES:
            raise VisualSceneProjectError(
                f"剧情工程最多包含 {MAX_STORY_SCENES} 个场景"
            )
        if not raw_scenes:
            raise VisualSceneProjectError("剧情工程至少需要一个场景")
        scenes = [
            _normalise_story_scene(item, index + 1)
            for index, item in enumerate(raw_scenes)
        ]
        scene_ids = [str(item["scene_id"]) for item in scenes]
        if len(scene_ids) != len(set(scene_ids)):
            raise VisualSceneProjectError("剧情工程含重复 scene_id")
        raw["scenes"] = scenes
        raw["active_scene_id"] = (
            scene_ids[0]
            if raw.get("active_scene_id") is None
            else _validate_scene_id(
                raw.get("active_scene_id"),
                field="剧情工程 active_scene_id",
            )
        )
        if raw["active_scene_id"] not in scene_ids:
            raise VisualSceneProjectError(
                f"剧情工程 active_scene_id 不存在: {raw['active_scene_id']}"
            )
        raw["next_scene_serial"] = _normalise_next_scene_serial(
            raw.get("next_scene_serial"),
            scenes,
        )
        raw["revision"] = _coerce_nonnegative_counter(
            raw.get("revision"),
            default=0,
            field="剧情工程 revision",
        )
        story = raw
    elif schema == LEGACY_STORY_SCHEMA:
        # Legacy v1 represents one active scene.  Preserve its authored fields
        # while giving the migrated scene a stable ID in the canonical list.
        legacy_lines = raw.get("inserted_lines", [])
        if not isinstance(legacy_lines, list):
            raise VisualSceneProjectError("剧情新增台词必须是数组")
        legacy_anchor = raw.get("anchor")
        legacy_cue = raw.get("cue")
        if legacy_anchor is not None and not isinstance(legacy_anchor, Mapping):
            raise VisualSceneProjectError("剧情挂接点无效")
        if legacy_cue is not None and not isinstance(legacy_cue, Mapping):
            raise VisualSceneProjectError("剧情舞台快照无效")
        migrated = _new_story_scene(1)
        migrated.update(
            {
                "anchor": copy.deepcopy(dict(legacy_anchor))
                if isinstance(legacy_anchor, Mapping)
                else None,
                "cue": copy.deepcopy(dict(legacy_cue))
                if isinstance(legacy_cue, Mapping)
                else None,
                "inserted_lines": copy.deepcopy(legacy_lines),
                "next_line_serial": _coerce_positive_serial(
                    raw.get("next_line_serial"),
                    default=1,
                    field="剧情工程 next_line_serial",
                ),
                "revision": _coerce_nonnegative_counter(
                    raw.get("revision"),
                    default=0,
                    field="剧情工程 revision",
                ),
            }
        )
        story = {
            "schema": STORY_SCHEMA,
            "scenes": [migrated],
            "active_scene_id": migrated["scene_id"],
            "next_scene_serial": 2,
            "revision": migrated["revision"],
            "migrated_from": LEGACY_STORY_SCHEMA,
        }
        scene["story"] = story
    else:
        raise VisualSceneProjectError(
            f"不支持的剧情工程 schema: {schema or '<空>'}"
        )
    _sync_active_story_view(story)
    return story


def active_story_scene(scene: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical mutable active scene."""

    return _resolve_story_scene(ensure_story_attachment(scene))


def story_scenes(scene: dict[str, Any]) -> list[dict[str, Any]]:
    """Return isolated scene snapshots in user-visible timeline order."""

    story = ensure_story_attachment(scene)
    return copy.deepcopy(story["scenes"])


def _touch_story_scene(story: dict[str, Any], item: dict[str, Any]) -> None:
    item["revision"] = int(item.get("revision") or 0) + 1
    story["revision"] = int(story.get("revision") or 0) + 1
    _sync_active_story_view(story)


def add_story_scene(
    scene: dict[str, Any],
    *,
    duplicate_active: bool = False,
    title: str | None = None,
) -> dict[str, Any]:
    """Append one scene and make it active.

    Duplicating intentionally preserves the anchor and cue.  The compiler will
    reject duplicate hook offsets until the user chooses a new anchor, making
    the temporary conflict visible instead of silently discarding intent.
    """

    story = ensure_story_attachment(scene)
    scenes = story["scenes"]
    if len(scenes) >= MAX_STORY_SCENES:
        raise VisualSceneProjectError(
            f"剧情工程最多包含 {MAX_STORY_SCENES} 个场景"
        )
    serial = _next_available_scene_serial(
        scenes,
        _coerce_positive_serial(
            story.get("next_scene_serial"),
            default=1,
            field="剧情工程 next_scene_serial",
        ),
    )
    if duplicate_active:
        source = _sync_active_story_view(story)
        item = copy.deepcopy(source)
        item["scene_id"] = _scene_id_for_serial(serial)
        item["title"] = str(title or f"{source.get('title') or '场景'} 副本")
        item["revision"] = 0
    else:
        item = _new_story_scene(serial, title=title)
    scenes.append(item)
    story["active_scene_id"] = item["scene_id"]
    story["next_scene_serial"] = _next_available_scene_serial(scenes, serial + 1)
    story["revision"] = int(story.get("revision") or 0) + 1
    _sync_active_story_view(story)
    return copy.deepcopy(item)


def select_story_scene(scene: dict[str, Any], scene_id: str) -> dict[str, Any]:
    story = ensure_story_attachment(scene)
    token = _validate_scene_id(scene_id)
    item = _find_story_scene(story, token)
    story["active_scene_id"] = token
    _sync_active_story_view(story)
    return copy.deepcopy(item)


def rename_story_scene(
    scene: dict[str, Any], scene_id: str, title: str
) -> dict[str, Any]:
    story = ensure_story_attachment(scene)
    token = _validate_scene_id(scene_id)
    label = str(title or "").strip()
    if not label:
        raise VisualSceneProjectError("剧情场景标题不能为空")
    if len(label) > 120:
        raise VisualSceneProjectError("剧情场景标题过长")
    item = _find_story_scene(story, token)
    if item.get("title") != label:
        item["title"] = label
        _touch_story_scene(story, item)
    return copy.deepcopy(item)


def move_story_scene(
    scene: dict[str, Any], scene_id: str, new_index: int
) -> dict[str, Any]:
    story = ensure_story_attachment(scene)
    token = _validate_scene_id(scene_id)
    scenes = story["scenes"]
    _find_story_scene(story, token)
    current = next(index for index, entry in enumerate(scenes) if entry.get("scene_id") == token)
    target = max(0, min(len(scenes) - 1, int(new_index)))
    if target != current:
        item = scenes.pop(current)
        scenes.insert(target, item)
        story["revision"] = int(story.get("revision") or 0) + 1
        _sync_active_story_view(story)
    return copy.deepcopy(story)


def remove_story_scene(scene: dict[str, Any], scene_id: str) -> dict[str, Any]:
    story = ensure_story_attachment(scene)
    token = _validate_scene_id(scene_id)
    scenes = story["scenes"]
    _find_story_scene(story, token)
    index = next(index for index, entry in enumerate(scenes) if entry.get("scene_id") == token)
    removed = scenes.pop(index)
    if not scenes:
        serial = _next_available_scene_serial(
            scenes,
            _coerce_positive_serial(
                story.get("next_scene_serial"),
                default=1,
                field="剧情工程 next_scene_serial",
            ),
        )
        scenes.append(_new_story_scene(serial))
        story["next_scene_serial"] = _next_available_scene_serial(
            scenes,
            serial + 1,
        )
    active_id = str(story.get("active_scene_id") or "")
    if active_id == token:
        story["active_scene_id"] = scenes[min(index, len(scenes) - 1)]["scene_id"]
    story["revision"] = int(story.get("revision") or 0) + 1
    _sync_active_story_view(story)
    return copy.deepcopy(removed)


def replace_story_project(
    scene: dict[str, Any], payload: Mapping[str, Any]
) -> dict[str, Any]:
    """Replace the story project from an explicit JSON payload."""

    if not isinstance(payload, Mapping):
        raise VisualSceneProjectError("剧情工程 JSON 必须是对象")
    schema = payload.get("schema")
    if schema not in (STORY_SCHEMA, LEGACY_STORY_SCHEMA):
        raise VisualSceneProjectError(f"不支持的剧情工程 schema: {schema or '<空>'}")
    previous_revision = int(ensure_story_attachment(scene).get("revision") or 0)
    candidate_holder = {"story": copy.deepcopy(dict(payload))}
    story = ensure_story_attachment(candidate_holder)
    story["revision"] = max(previous_revision, int(story.get("revision") or 0)) + 1
    _sync_active_story_view(story)
    scene["story"] = candidate_holder["story"]
    return copy.deepcopy(story)


def story_snapshot(scene: dict[str, Any]) -> dict[str, Any]:
    """Return an isolated copy of the current story attachment."""

    return copy.deepcopy(ensure_story_attachment(scene))


def reset_story_binding(scene: dict[str, Any], *, preserve_lines: bool = True) -> dict[str, Any]:
    """Invalidate every source-bound anchor/cue while preserving the timeline."""

    story = ensure_story_attachment(scene)
    changed = False
    for item in story["scenes"]:
        item_changed = False
        if item.get("anchor") is not None or item.get("cue") is not None:
            item_changed = True
        item["anchor"] = None
        item["cue"] = None
        if not preserve_lines:
            if item.get("inserted_lines"):
                item_changed = True
            item["inserted_lines"] = []
            item["next_line_serial"] = 1
        if item_changed:
            item["revision"] = int(item.get("revision") or 0) + 1
            changed = True
    if changed:
        story["revision"] = int(story.get("revision") or 0) + 1
    _sync_active_story_view(story)
    return copy.deepcopy(story)


def set_story_anchor(
    scene: dict[str, Any],
    anchor: Mapping[str, Any],
    scene_id: str | None = None,
) -> dict[str, Any]:
    """Bind the story to one inspected HCB dialogue anchor.

    A new anchor always clears the captured cue.  This prevents a background
    snapshot made for one line from silently following the selection to a
    different line.
    """

    if not isinstance(anchor, Mapping):
        raise VisualSceneProjectError("剧情挂接点必须是对象")
    timing = str(anchor.get("timing") or "").strip().casefold()
    if timing not in STORY_TIMINGS:
        raise VisualSceneProjectError("第一版剧情时序只支持本句之前或本句之后")
    anchor_id = str(anchor.get("anchor_id") or "").strip()
    if not anchor_id:
        raise VisualSceneProjectError("剧情挂接点缺少稳定 anchor_id")
    story = ensure_story_attachment(scene)
    item = _resolve_story_scene(story, scene_id)
    item["anchor"] = copy.deepcopy(dict(anchor))
    item["cue"] = None
    _touch_story_scene(story, item)
    return copy.deepcopy(story)


def clear_story_anchor(
    scene: dict[str, Any], scene_id: str | None = None
) -> dict[str, Any]:
    story = ensure_story_attachment(scene)
    item = _resolve_story_scene(story, scene_id)
    if item.get("anchor") is not None or item.get("cue") is not None:
        item["anchor"] = None
        item["cue"] = None
        _touch_story_scene(story, item)
    return copy.deepcopy(story)


def _actor_cue(actor: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze the exact layered pair and visual state needed by the compiler.

    The live editor draft is mutable and shared with the selected stage tab.
    A story cue must therefore retain its own body/face entry identities,
    form selector and scale envelope rather than re-reading whichever draft is
    selected when dry-run happens later.
    """

    actor_id = str(actor.get("actor_id") or "").strip()
    if not actor_id:
        raise VisualSceneProjectError("舞台角色缺少稳定 actor_id")
    draft = actor.get("draft") if isinstance(actor.get("draft"), Mapping) else {}
    identity = actor.get("identity") if isinstance(actor.get("identity"), Mapping) else {}
    return {
        "actor_id": actor_id,
        "identity": {
            "character_id": str(identity.get("character_id") or ""),
            "display_name": str(identity.get("display_name") or ""),
            "label": str(identity.get("label") or identity.get("display_name") or actor_id),
        },
        "source_archive_path": str(actor.get("source_archive_path") or ""),
        "expression_frame": max(0, int(actor.get("expression_frame") or 0)),
        "visible": bool(actor.get("visible", True)),
        "draft_schema": str(draft.get("schema") or ""),
        "form_code": int(draft.get("form_code", 0)),
        "form_id": str(draft.get("form_id") or ""),
        "locked_pair": copy.deepcopy(
            draft.get("locked_pair")
            if isinstance(draft.get("locked_pair"), Mapping)
            else {}
        ),
        "variant": copy.deepcopy(draft.get("variant") if isinstance(draft.get("variant"), Mapping) else {}),
        "transform": copy.deepcopy(draft.get("transform") if isinstance(draft.get("transform"), Mapping) else {}),
        "scale_policy": copy.deepcopy(
            draft.get("scale_policy")
            if isinstance(draft.get("scale_policy"), Mapping)
            else {}
        ),
        "stage_reference": copy.deepcopy(
            draft.get("stage_reference")
            if isinstance(draft.get("stage_reference"), Mapping)
            else {}
        ),
    }


def capture_story_cue(
    scene: dict[str, Any], scene_id: str | None = None
) -> dict[str, Any]:
    """Capture the current stage for a dialogue without file I/O."""

    story = ensure_story_attachment(scene)
    item = _resolve_story_scene(story, scene_id)
    anchor = item.get("anchor")
    if not isinstance(anchor, Mapping):
        raise VisualSceneProjectError("请先选择剧情台词，再应用舞台")
    background = scene.get("background")
    event_visual = scene.get("event_visual")
    audio = scene.get("audio")
    actors = scene.get("actors")
    if not isinstance(actors, list):
        raise VisualSceneProjectError("舞台角色状态损坏")
    if not isinstance(audio, Mapping):
        # Older exported projects predate the independent BGM / SE layer.
        # Migrating them to an explicit no-op state prevents a later compiler
        # from confusing "keep the current BGM" with "stop the BGM".
        from .audio_workspace import stage_audio_defaults

        audio = stage_audio_defaults()
    cue = {
        "schema": "fvp-studio-v2.story-cue.v1",
        "cue_id": f"cue-{anchor['anchor_id']}",
        "anchor_id": str(anchor["anchor_id"]),
        "stage_revision": int(scene.get("revision") or 0),
        "background": copy.deepcopy(background) if isinstance(background, Mapping) else None,
        # A CG is a full-screen native event visual.  It visually suppresses
        # the background/actors at this cue, but those underlying live-stage
        # objects remain frozen too so clearing the CG restores the layout.
        "event_visual": (
            copy.deepcopy(event_visual) if isinstance(event_visual, Mapping) else None
        ),
        # Audio is frozen beside the visual layers, but remains an independent
        # state machine: BGM ``keep`` and SE ``none`` are intentional no-ops,
        # not missing data.  This copy is never rebound to the live controls.
        "audio": copy.deepcopy(dict(audio)),
        "actors": [_actor_cue(actor) for actor in actors if isinstance(actor, Mapping)],
        # One frozen cue is the atomic user intent.  The compiler may still
        # produce an HCB-only transaction when no visible actor is present,
        # but it may not silently defer actors that are part of this snapshot.
        "compile_scope": (
            "native_event_visual_and_dialogue"
            if isinstance(event_visual, Mapping)
            else "native_background_portraits_and_dialogue"
        ),
    }
    item["cue"] = cue
    _touch_story_scene(story, item)
    return copy.deepcopy(cue)


def _normalise_inserted_line(
    value: Mapping[str, Any],
    line_id: str,
    *,
    trusted_speaker: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    speaker_id = str(value.get("speaker_id") or "narration").strip().casefold()
    if trusted_speaker is None:
        if speaker_id not in SPEAKER_LABELS:
            raise VisualSceneProjectError(f"不支持的新增台词说话人: {speaker_id or '<空>'}")
        speaker = {
            "speaker_id": speaker_id,
            "display_name": SPEAKER_LABELS[speaker_id],
            "scanned_name": "",
            "speaker_function": None,
            "name_selector": None,
            "compile_ready": True,
            "voice_ready": speaker_id != "narration",
            "reason": "旧版内置说话人",
        }
    else:
        trusted_id = str(trusted_speaker.get("speaker_id") or "").strip().casefold()
        if not trusted_id or trusted_id != speaker_id:
            raise VisualSceneProjectError("说话人稳定身份与当前索引解析结果不一致")
        speaker = dict(trusted_speaker)
        if not str(speaker.get("display_name") or "").strip():
            raise VisualSceneProjectError("当前说话人缺少可显示名字")
    text = value.get("text")
    if not isinstance(text, str) or not text.strip():
        raise VisualSceneProjectError("新增台词内容不能为空")
    if len(text) > 4096:
        raise VisualSceneProjectError("新增台词过长")
    raw_voice = value.get("voice_id")
    voice_id: int | None
    if raw_voice in (None, ""):
        voice_id = None
    else:
        try:
            voice_id = int(raw_voice)
        except (TypeError, ValueError) as exc:
            raise VisualSceneProjectError("语音 ID 必须是非负整数") from exc
        if not 0 <= voice_id <= 0x7FFFFFFF:
            raise VisualSceneProjectError("语音 ID 超出正 i32 范围")
    if speaker_id == "narration" and voice_id is not None:
        raise VisualSceneProjectError("旁白模式不能直接绑定角色语音 ID")
    if voice_id is not None and not bool(speaker.get("voice_ready")):
        raise VisualSceneProjectError(
            f"{speaker.get('display_name') or speaker_id} 的语音参数尚未验证；请先留空语音 ID"
        )
    return {
        "line_id": line_id,
        "speaker_id": speaker_id,
        "speaker": str(speaker.get("display_name") or speaker_id),
        "scanned_name": str(speaker.get("scanned_name") or ""),
        "show_name": speaker_id != "narration",
        "text": text,
        "voice_id": voice_id,
        "speaker_function": speaker.get("speaker_function"),
        "name_selector": speaker.get("name_selector"),
        "compile_ready": bool(speaker.get("compile_ready")),
        "compile_reason": str(speaker.get("reason") or ""),
    }


def _actor_binding_value(actor: Mapping[str, Any], field: str) -> Any:
    """Read one stable source-binding field from a live or frozen actor."""

    draft = actor.get("draft") if isinstance(actor.get("draft"), Mapping) else {}
    if field == "source_archive_path":
        return str(actor.get(field) or "").replace("\\", "/").casefold()
    if field == "variant_id":
        variant = (
            actor.get("variant")
            if isinstance(actor.get("variant"), Mapping)
            else draft.get("variant")
            if isinstance(draft.get("variant"), Mapping)
            else {}
        )
        return str(variant.get("variant_id") or "")
    if field == "form_code":
        raw = actor.get(field, draft.get(field))
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None
    locked = (
        actor.get("locked_pair")
        if isinstance(actor.get("locked_pair"), Mapping)
        else draft.get("locked_pair")
        if isinstance(draft.get("locked_pair"), Mapping)
        else {}
    )
    return locked.get(field)


def _actor_source_binding_matches(
    live_actor: Mapping[str, Any], frozen_actor: Mapping[str, Any]
) -> bool:
    """Compare identity-bearing fields while allowing older sparse snapshots."""

    fields = (
        "source_archive_path",
        "variant_id",
        "form_code",
        "body_entry",
        "face_entry",
        "body_payload_sha256",
        "face_payload_sha256",
    )
    for field in fields:
        live_value = _actor_binding_value(live_actor, field)
        frozen_value = _actor_binding_value(frozen_actor, field)
        if live_value in (None, "") or frozen_value in (None, ""):
            continue
        if live_value != frozen_value:
            return False
    return True


def _line_actor_expression_snapshot(
    scene: Mapping[str, Any], cue: Mapping[str, Any] | None
) -> list[dict[str, Any]]:
    """Freeze only stable actor IDs and frames for one authored dialogue line.

    Geometry and resource bindings remain owned by the cue.  This keeps a
    line-specific expression independent from the mutable shared stage draft
    while preventing a later actor/source swap from inheriting an old frame.
    """

    actors_value = scene.get("actors")
    actors = [] if actors_value is None else actors_value
    if not isinstance(actors, list):
        raise VisualSceneProjectError("舞台角色状态损坏")
    if isinstance(cue, Mapping) and isinstance(cue.get("event_visual"), Mapping):
        return []
    live_visible = [
        actor
        for actor in actors
        if isinstance(actor, Mapping) and bool(actor.get("visible", True))
    ]
    frozen_visible: list[Mapping[str, Any]] = []
    if isinstance(cue, Mapping):
        cue_actors = cue.get("actors")
        if not isinstance(cue_actors, list):
            raise VisualSceneProjectError("冻结舞台角色状态损坏，请重新应用舞台")
        frozen_visible = [
            actor
            for actor in cue_actors
            if isinstance(actor, Mapping) and bool(actor.get("visible", True))
        ]
    frozen_by_id = {
        str(actor.get("actor_id") or "").strip(): actor for actor in frozen_visible
    }
    live_ids: list[str] = []
    snapshot: list[dict[str, Any]] = []
    for actor in live_visible:
        actor_id = str(actor.get("actor_id") or "").strip()
        if not actor_id:
            raise VisualSceneProjectError("舞台角色缺少稳定 actor_id")
        if actor_id in live_ids:
            raise VisualSceneProjectError(f"舞台角色 actor_id 重复: {actor_id}")
        live_ids.append(actor_id)
        if frozen_by_id:
            frozen_actor = frozen_by_id.get(actor_id)
            if frozen_actor is None:
                raise VisualSceneProjectError(
                    f"角色 {actor_id} 不在当前剧情舞台快照中，请重新应用舞台"
                )
            if not _actor_source_binding_matches(actor, frozen_actor):
                raise VisualSceneProjectError(
                    f"角色 {actor_id} 的来源身份已变化，请重新应用舞台"
                )
        try:
            expression_frame = int(actor.get("expression_frame", 0))
        except (TypeError, ValueError) as exc:
            raise VisualSceneProjectError(
                f"角色 {actor_id} 的表情帧不是整数"
            ) from exc
        if expression_frame < 0:
            raise VisualSceneProjectError(f"角色 {actor_id} 的表情帧不能为负数")
        snapshot.append(
            {"actor_id": actor_id, "expression_frame": expression_frame}
        )
    if frozen_by_id and set(live_ids) != set(frozen_by_id):
        raise VisualSceneProjectError("当前可见角色与剧情舞台快照不一致，请重新应用舞台")
    return snapshot


def add_inserted_dialogue(
    scene: dict[str, Any],
    value: Mapping[str, Any],
    *,
    trusted_speaker: Mapping[str, Any] | None = None,
    scene_id: str | None = None,
) -> dict[str, Any]:
    story = ensure_story_attachment(scene)
    item = _resolve_story_scene(story, scene_id)
    lines = item["inserted_lines"]
    if len(lines) >= MAX_INSERTED_DIALOGUE_LINES:
        raise VisualSceneProjectError(
            f"第一版每个挂接点最多新增 {MAX_INSERTED_DIALOGUE_LINES} 句台词"
        )
    serial = max(1, int(item.get("next_line_serial") or 1))
    line = _normalise_inserted_line(
        value,
        f"story-line-{serial:04d}",
        trusted_speaker=trusted_speaker,
    )
    line["actor_expressions"] = _line_actor_expression_snapshot(
        scene,
        item.get("cue") if isinstance(item.get("cue"), Mapping) else None,
    )
    lines.append(line)
    item["next_line_serial"] = serial + 1
    _touch_story_scene(story, item)
    return copy.deepcopy(line)


def remove_inserted_dialogue(
    scene: dict[str, Any],
    line_id: str,
    scene_id: str | None = None,
) -> dict[str, Any]:
    story = ensure_story_attachment(scene)
    item = _resolve_story_scene(story, scene_id)
    token = str(line_id or "").strip()
    index = next(
        (index for index, line in enumerate(item["inserted_lines"]) if line.get("line_id") == token),
        None,
    )
    if index is None:
        raise VisualSceneProjectError(f"找不到新增台词: {token or '<空>'}")
    removed = item["inserted_lines"].pop(index)
    _touch_story_scene(story, item)
    return copy.deepcopy(removed)


def clear_inserted_dialogue(
    scene: dict[str, Any], scene_id: str | None = None
) -> dict[str, Any]:
    story = ensure_story_attachment(scene)
    item = _resolve_story_scene(story, scene_id)
    if item["inserted_lines"]:
        item["inserted_lines"] = []
        _touch_story_scene(story, item)
    return copy.deepcopy(story)


def buildable_story_scenes(story: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Validate and return non-empty scenes in deterministic hook order."""

    if not isinstance(story, Mapping):
        raise VisualSceneProjectError("剧情工程状态必须是对象")
    holder = {"story": copy.deepcopy(dict(story))}
    project = ensure_story_attachment(holder)
    buildable: list[dict[str, Any]] = []
    anchor_ids: set[str] = set()
    hook_ranges: list[tuple[int, int, str]] = []
    for item in project["scenes"]:
        anchor = item.get("anchor")
        cue = item.get("cue")
        lines = item.get("inserted_lines") or []
        if anchor is None and cue is None and not lines:
            continue
        if not isinstance(anchor, Mapping):
            raise VisualSceneProjectError(
                f"剧情场景 {item['title']} 尚未选择挂接点"
            )
        if not isinstance(cue, Mapping):
            raise VisualSceneProjectError(
                f"剧情场景 {item['title']} 尚未应用舞台快照"
            )
        anchor_id = str(anchor.get("anchor_id") or "")
        if not anchor_id:
            raise VisualSceneProjectError(f"剧情场景 {item['title']} 缺少 anchor_id")
        cue_anchor_id = str(cue.get("anchor_id") or "")
        if cue_anchor_id != anchor_id:
            raise VisualSceneProjectError(
                f"剧情场景 {item['title']} 的 cue.anchor_id 与 anchor.anchor_id 不一致"
            )
        if anchor_id in anchor_ids:
            raise VisualSceneProjectError(f"剧情工程重复使用挂接点 {anchor_id}")
        try:
            patch_offset = int(
                (anchor.get("patch") or {}).get("patch_offset", anchor.get("hcb_offset"))
            )
        except (TypeError, ValueError, AttributeError) as exc:
            raise VisualSceneProjectError(
                f"剧情场景 {item['title']} 缺少可排序的挂接偏移"
            ) from exc
        patch_range = (patch_offset, patch_offset + 5)
        for previous_start, previous_end, previous_title in hook_ranges:
            if patch_range[0] < previous_end and patch_range[1] > previous_start:
                raise VisualSceneProjectError(
                    "剧情工程挂接区间重叠："
                    f"{previous_title} 0x{previous_start:X}-0x{previous_end:X} 与 "
                    f"{item['title']} 0x{patch_range[0]:X}-0x{patch_range[1]:X}"
                )
        anchor_ids.add(anchor_id)
        hook_ranges.append((patch_range[0], patch_range[1], str(item["title"])))
        buildable.append(copy.deepcopy(item))
    if not buildable:
        raise VisualSceneProjectError("剧情工程没有可构建的完整场景")
    buildable.sort(
        key=lambda item: int(
            (item["anchor"].get("patch") or {}).get(
                "patch_offset", item["anchor"].get("hcb_offset")
            )
        )
    )
    return buildable
