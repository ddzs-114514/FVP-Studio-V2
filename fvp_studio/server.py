"""Local-only HTTP application server for FVP Studio.

The editor deliberately keeps the browser layer thin.  HCB parsing, address
relocation and safe export live in :mod:`fvp_studio.hcb`; this module exposes
those operations to the UTF-8 web UI without adding third-party dependencies.
"""

from __future__ import annotations

import argparse
import copy
from collections import deque
from datetime import datetime
import hashlib
import json
import mimetypes
from pathlib import Path
import re
import shutil
import struct
import subprocess
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlparse
from uuid import uuid4
import webbrowser

from .hcb import HcbDocument, HcbError, dump_json, encode_text, load, parse_bytes
from .profile import ProjectIndex, ProfileError, default_index_dir


WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
V2_AUDIO_LIBRARY_ROOT = WEB_ROOT.parent / "projects" / "audio"
V2_AUDIO_BUILD_ROOT = V2_AUDIO_LIBRARY_ROOT / "builds"
_JUMP_LABEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _remove_v2_audio_build(path_value: str | Path | None) -> None:
    """Remove only one V2-owned candidate directory, never a game path."""

    if path_value in (None, ""):
        return
    build_root = V2_AUDIO_BUILD_ROOT.resolve()
    candidate = Path(path_value).expanduser().resolve()
    if (
        candidate.parent != build_root
        or not candidate.name.startswith("candidate-")
        or candidate == build_root
    ):
        return
    if candidate.is_dir() and not candidate.is_symlink():
        shutil.rmtree(candidate)


def _same_resolved_path(left: str | Path | None, right: str | Path | None) -> bool:
    if left is None or right is None:
        return False
    try:
        return Path(left).expanduser().resolve().samefile(
            Path(right).expanduser().resolve()
        )
    except OSError:
        return (
            str(Path(left).expanduser().resolve()).casefold()
            == str(Path(right).expanduser().resolve()).casefold()
        )


def _portrait_text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _portrait_actor_identity_from_draft(draft: Any) -> dict[str, str]:
    character = draft.get("character") if isinstance(draft, dict) else None
    if not isinstance(character, dict):
        character = {}
    character_id = _portrait_text(character.get("character_id"))
    display_name = _portrait_text(character.get("display_name"))
    return {
        "character_id": character_id,
        "display_name": display_name,
        "label": display_name or character_id or "未命名角色",
    }


def _portrait_actor_identity(value: Any, fallback: Any = None) -> dict[str, str]:
    identity = value if isinstance(value, dict) else {}
    previous = fallback if isinstance(fallback, dict) else {}
    character_id = _portrait_text(identity.get("character_id")) or _portrait_text(
        previous.get("character_id")
    )
    display_name = _portrait_text(identity.get("display_name")) or _portrait_text(
        previous.get("display_name")
    )
    label = (
        _portrait_text(identity.get("label"))
        or display_name
        or character_id
        or _portrait_text(previous.get("label"))
        or "未命名角色"
    )
    return {
        "character_id": character_id,
        "display_name": display_name,
        "label": label,
    }


def _portrait_actor_label(actor: dict[str, Any]) -> str:
    identity = actor.get("identity")
    if isinstance(identity, dict):
        label = _portrait_text(identity.get("label")) or _portrait_text(
            identity.get("display_name")
        ) or _portrait_text(identity.get("character_id"))
        if label:
            return label
    return _portrait_text(actor.get("actor_id")) or "未命名角色"


def _portrait_actor_depth(actor: dict[str, Any]) -> int:
    """Return one actor's native Z depth, using the stage default if absent."""

    draft = actor.get("draft")
    transform = draft.get("transform") if isinstance(draft, dict) else None
    try:
        return int(transform.get("z", 1500)) if isinstance(transform, dict) else 1500
    except (TypeError, ValueError):
        return 1500


def _portrait_layer_depths(actors: list[dict[str, Any]]) -> list[int]:
    """Return secondary native Z hints for actors ordered back to front.

    The existing ascending depth values are kept whenever possible; duplicate
    values receive the smallest positive integer tie-breaker.  Native
    Hoshimemo semantics put smaller Z values in front, so the back-to-front
    actor array receives the normalized values in descending order.  Real-game
    acceptance proved that Z alone does not reorder independent portrait
    slots; the actor array remains authoritative and the compiler converts it
    to the target's front-to-back registration chain.
    """

    depths = sorted(_portrait_actor_depth(actor) for actor in actors)
    for index in range(1, len(depths)):
        depths[index] = max(depths[index], depths[index - 1] + 1)
    return list(reversed(depths))


class EditorSession:
    """Thread-safe document session shared by the local HTTP handlers."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.document: HcbDocument | None = None
        self.profile: ProjectIndex | None = None
        # Generic native-target discovery is separate from the optional
        # dialogue/resource ProjectIndex.  It records structural capabilities
        # for any FVP-like game root but never grants write permission.
        self.native_target_discovery: dict[str, Any] | None = None
        # A submitted target profile is reviewed only in memory.  The review
        # can describe remaining evidence, but API data can never self-enable
        # a writer or enter the trusted profile registry.
        self.native_target_profile_review: dict[str, Any] | None = None
        # A generic target's runtime/analysis HCB bridge is expensive to
        # construct (large translated games can contain more than a million
        # instructions), so retain one exact-identity, read-only context.  It
        # is never a trusted writer and is invalidated whenever its document,
        # discovery report, project index, or review changes.
        self.native_scene_memory_context: Any | None = None
        self.native_scene_memory_context_key: tuple[Any, ...] | None = None
        self.plan: dict[str, Any] = {
            "schema": "fvp-studio-replacement-plan.v1",
            "hcb": None,
            "text_edits": [],
            "visual_replacements": [],
            "portrait_sets": [],
            "audio_replacements": [],
        }
        # Labels are session-local symbolic names for code offsets.  They are
        # deliberately not written into HCB bytes; the generated 0x06/0x07
        # instruction stores the resolved absolute target and participates in
        # the normal relocation pass on save.
        self.jump_labels: dict[str, int] = {}
        # V2 layered-portrait work is kept in a separate, read-only draft.
        # It is intentionally not part of the legacy replacement plan and is
        # never written to HCB/BIN merely by selecting or analysing assets.
        self.portrait_v2_draft: dict[str, Any] | None = None
        # A source-game portrait archive is a separate, read-only workspace.
        # Keep it independent from the active target HCB so opening a target
        # project cannot accidentally turn the source game into a write target.
        self.portrait_v2_source: dict[str, Any] | None = None
        # Background discovery has its own source selection because graph.bin
        # / graph_bg.bin may come from the active target or from another FVP
        # game.  It remains read-only; cross-game entries are only marked as
        # migration candidates until a later, explicit candidate build.
        self.background_v2_source: dict[str, Any] | None = None
        # Event-CG discovery is isolated from both the generic asset index and
        # the background source.  graph_vis* archives remain read-only until
        # an explicit cross-game candidate is built in memory.
        self.cg_v2_source: dict[str, Any] | None = None
        # BGM/SE discovery is likewise independent from the legacy generic
        # audio replacement plan.  Scanning and auditioning never turns an
        # archive into a write target; only current-game numeric entries may
        # later be emitted as native story calls.
        self.audio_v2_source: dict[str, Any] | None = None
        from .audio_workspace import stage_audio_defaults

        # The V2 stage is a scene-local collection of independent actor
        # instances.  Each actor owns a copy of its layered portrait draft and
        # the absolute source archive needed to render it.  This deliberately
        # stays separate from the active HCB: changing the target script must
        # not discard or rebind actors already arranged on the stage.
        self.portrait_v2_scene: dict[str, Any] = {
            "schema": "fvp-studio-v2.visual-scene.v1",
            "background": None,
            "event_visual": None,
            "audio": stage_audio_defaults(),
            "actors": [],
            "selected_actor_id": None,
            "story": {
                "schema": "fvp-studio-v2.story-attachment.v1",
                "anchor": None,
                "cue": None,
                "inserted_lines": [],
                "next_line_serial": 1,
                "revision": 0,
            },
            "revision": 0,
        }
        self.portrait_v2_actor_serial = 0
        # HCB-only scene candidates stay in memory until the user explicitly
        # downloads them.  Scene editing and dry-run generation never write a
        # game path, and any source/story drift invalidates this cache.
        self.visual_scene_candidate: dict[str, Any] | None = None
        self.runner_lock = threading.RLock()
        self.runner: subprocess.Popen[str] | None = None
        self.runner_command: list[str] = []
        self.runner_started_at: float | None = None
        self.runner_log: deque[str] = deque(maxlen=300)
        self.last_action = "等待打开 HCB"
        self.last_error: str | None = None
        self.started_at = time.time()
        # The workspace already contains the Hoshimemo analysis indexes.  Load
        # them as an optional profile when present; a generic HCB installation
        # simply starts with no profile.
        if default_index_dir().is_dir():
            try:
                self.profile = ProjectIndex(default_index_dir())
                self.last_action = "已载入默认 Hoshimemo 分析索引"
            except ProfileError as exc:
                self.last_error = str(exc)

    def set_document(self, document: HcbDocument) -> None:
        with self.lock:
            self.document = document
            self.invalidate_native_scene_memory_context()
            current_root = (
                document.path.expanduser().resolve().parent
                if document.path is not None
                else None
            )
            discovered_root = (
                Path(str(self.native_target_discovery.get("game_dir"))).resolve()
                if isinstance(self.native_target_discovery, dict)
                and self.native_target_discovery.get("game_dir")
                else None
            )
            if discovered_root is not None and discovered_root != current_root:
                self.native_target_discovery = None
                self.native_target_profile_review = None
            source = self.cg_v2_source
            if (
                isinstance(source, dict)
                and bool(source.get("is_current_game"))
                and not _same_resolved_path(source.get("project_dir"), current_root)
            ):
                self.cg_v2_source = None
            audio_source = self.audio_v2_source
            if (
                isinstance(audio_source, dict)
                and bool(audio_source.get("is_current_game"))
                and not _same_resolved_path(
                    audio_source.get("project_dir"), current_root
                )
            ):
                self.audio_v2_source = None
            event_visual = self.portrait_v2_scene.get("event_visual")
            cleared_direct_cg = False
            if (
                isinstance(event_visual, dict)
                and str(event_visual.get("build_mode") or "").strip().casefold()
                == "direct_reference"
                and not _same_resolved_path(
                    event_visual.get("project_dir"),
                    current_root,
                )
            ):
                self.portrait_v2_scene["event_visual"] = None
                self.portrait_v2_scene["revision"] = int(
                    self.portrait_v2_scene.get("revision") or 0
                ) + 1
                cleared_direct_cg = True
            audio_state = self.portrait_v2_scene.get("audio")
            cleared_direct_audio = False
            if isinstance(audio_state, dict):
                for track_name in ("bgm", "se"):
                    track = audio_state.get(track_name)
                    if not isinstance(track, dict):
                        continue
                    asset = track.get("asset")
                    if (
                        isinstance(asset, dict)
                        and str(asset.get("build_mode") or "").strip().casefold()
                        == "direct_reference"
                        and not _same_resolved_path(
                            asset.get("project_dir"), current_root
                        )
                    ):
                        from .audio_workspace import stage_audio_defaults

                        self.portrait_v2_scene["audio"] = stage_audio_defaults()
                        self.portrait_v2_scene["revision"] = int(
                            self.portrait_v2_scene.get("revision") or 0
                        ) + 1
                        cleared_direct_audio = True
                        break
            self.plan = {
                "schema": "fvp-studio-replacement-plan.v1",
                "hcb": str(document.path) if document.path is not None else None,
                "text_edits": [],
                "visual_replacements": [],
                "portrait_sets": [],
                "audio_replacements": [],
            }
            self.jump_labels = {}
            from .visual_scene_project import reset_story_binding

            reset_story_binding(self.portrait_v2_scene, preserve_lines=True)
            prior_candidate = self.visual_scene_candidate
            if isinstance(prior_candidate, dict):
                _remove_v2_audio_build(prior_candidate.get("audio_build_root"))
            self.visual_scene_candidate = None
            cleared_layers: list[str] = []
            if cleared_direct_cg:
                cleared_layers.append("CG")
            if cleared_direct_audio:
                cleared_layers.append("音频")
            self.last_action = f"已打开 {document.path or '<memory>'}" + (
                f"；旧目标的本作直引 {' / '.join(cleared_layers)} 已清除"
                if cleared_layers
                else ""
            )
            self.last_error = None

    def portrait_scene_snapshot(self) -> dict[str, Any]:
        """Return an isolated copy of the current V2 visual scene."""

        with self.lock:
            from .visual_scene_project import ensure_story_attachment

            ensure_story_attachment(self.portrait_v2_scene)
            self.portrait_v2_scene.setdefault("background", None)
            self.portrait_v2_scene.setdefault("event_visual", None)
            if not isinstance(self.portrait_v2_scene.get("audio"), dict):
                from .audio_workspace import stage_audio_defaults

                self.portrait_v2_scene["audio"] = stage_audio_defaults()
            for actor in self.portrait_v2_scene["actors"]:
                identity = actor.get("identity")
                actor["identity"] = (
                    _portrait_actor_identity(identity, identity)
                    if isinstance(identity, dict)
                    else _portrait_actor_identity_from_draft(actor.get("draft"))
                )
            return copy.deepcopy(self.portrait_v2_scene)

    def visual_story_snapshot(self) -> dict[str, Any]:
        """Return story state and a byte-free candidate summary."""

        from .visual_scene_project import story_snapshot

        with self.lock:
            candidate = self.visual_scene_candidate
            return {
                "story": story_snapshot(self.portrait_v2_scene),
                "candidate": copy.deepcopy(candidate.get("report"))
                if isinstance(candidate, dict)
                else None,
            }

    def invalidate_visual_scene_candidate(self) -> None:
        with self.lock:
            candidate = self.visual_scene_candidate
            if isinstance(candidate, dict):
                _remove_v2_audio_build(candidate.get("audio_build_root"))
            self.visual_scene_candidate = None

    def invalidate_native_scene_memory_context(self) -> None:
        """Drop only the cached generic ABI/dialogue bridge."""

        with self.lock:
            self.native_scene_memory_context = None
            self.native_scene_memory_context_key = None

    def visual_scene_set_background(
        self,
        asset: dict[str, Any],
        *,
        fit: str = "cover",
        variant: str = "primary",
    ) -> dict[str, Any]:
        """Place one validated source background below every stage actor."""

        from .background_workspace import (
            BackgroundWorkspaceError,
            stage_background_from_asset,
        )

        try:
            background = stage_background_from_asset(asset, fit, variant=variant)
        except BackgroundWorkspaceError as exc:
            raise HcbError(str(exc)) from exc
        with self.lock:
            self.portrait_v2_scene["background"] = background
            self.portrait_v2_scene["revision"] += 1
            return copy.deepcopy(background)

    def visual_scene_update_background_fit(self, fit: str) -> dict[str, Any]:
        """Update only the stage fit policy; the source identity stays stable."""

        from .background_workspace import BACKGROUND_FITS

        fit_value = str(fit or "cover").strip().casefold()
        if fit_value not in BACKGROUND_FITS:
            raise HcbError("背景显示方式必须是 cover、contain 或 stretch")
        with self.lock:
            background = self.portrait_v2_scene.get("background")
            if not isinstance(background, dict):
                raise HcbError("舞台尚未设置背景")
            background["fit"] = fit_value
            self.portrait_v2_scene["revision"] += 1
            return copy.deepcopy(background)

    def visual_scene_clear_background(self) -> None:
        """Clear the background without touching actors or source archives."""

        with self.lock:
            if self.portrait_v2_scene.get("background") is not None:
                self.portrait_v2_scene["background"] = None
                self.portrait_v2_scene["revision"] += 1

    def visual_scene_set_cg(
        self,
        asset: dict[str, Any],
        *,
        display_mode: str = "standard",
    ) -> dict[str, Any]:
        """Place one validated native event visual above the stage."""

        from .cg_workspace import CgWorkspaceError, stage_cg_from_asset

        try:
            event_visual = stage_cg_from_asset(asset, display_mode=display_mode)
        except CgWorkspaceError as exc:
            raise HcbError(str(exc)) from exc
        with self.lock:
            self.portrait_v2_scene["event_visual"] = event_visual
            self.portrait_v2_scene["revision"] += 1
            return copy.deepcopy(event_visual)

    def visual_scene_update_cg(
        self,
        *,
        display_mode: str | None = None,
        transform: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Change only CG display parameters; its source identity stays fixed."""

        from .cg_workspace import CgWorkspaceError, update_stage_cg_display

        with self.lock:
            current = self.portrait_v2_scene.get("event_visual")
            try:
                event_visual = update_stage_cg_display(
                    current,
                    display_mode=display_mode,
                    transform=transform,
                )
            except CgWorkspaceError as exc:
                raise HcbError(str(exc)) from exc
            self.portrait_v2_scene["event_visual"] = event_visual
            self.portrait_v2_scene["revision"] += 1
            return copy.deepcopy(event_visual)

    def visual_scene_clear_cg(self) -> None:
        """Remove only the CG overlay, restoring background and actor preview."""

        with self.lock:
            if self.portrait_v2_scene.get("event_visual") is not None:
                self.portrait_v2_scene["event_visual"] = None
                self.portrait_v2_scene["revision"] += 1

    def visual_scene_update_audio(
        self,
        track: str,
        *,
        asset: dict[str, Any] | None = None,
        action: str | None = None,
        volume: Any = None,
        transition_ms: Any = None,
        loop: Any = None,
    ) -> dict[str, Any]:
        """Update BGM/SE state without holding the scene lock during payload freeze."""

        from .audio_workspace import AudioWorkspaceError, update_stage_audio

        with self.lock:
            current = copy.deepcopy(self.portrait_v2_scene.get("audio"))
        try:
            updated = update_stage_audio(
                current,
                track,
                asset=asset,
                action=action,
                volume=volume,
                transition_ms=transition_ms,
                loop=loop,
                project_library_root=V2_AUDIO_LIBRARY_ROOT,
            )
        except AudioWorkspaceError as exc:
            raise HcbError(str(exc)) from exc
        with self.lock:
            if self.portrait_v2_scene.get("audio") != current:
                raise HcbError("音频舞台已被另一项操作更新，请重试")
            self.portrait_v2_scene["audio"] = updated
            self.portrait_v2_scene["revision"] = int(
                self.portrait_v2_scene.get("revision") or 0
            ) + 1
            return copy.deepcopy(updated)

    def _portrait_scene_actor(self, actor_id: str) -> dict[str, Any]:
        for actor in self.portrait_v2_scene["actors"]:
            if actor["actor_id"] == actor_id:
                identity = actor.get("identity")
                actor["identity"] = (
                    _portrait_actor_identity(identity, identity)
                    if isinstance(identity, dict)
                    else _portrait_actor_identity_from_draft(actor.get("draft"))
                )
                return actor
        raise HcbError(f"找不到舞台角色: {actor_id}")

    def portrait_scene_add(
        self,
        draft: dict[str, Any],
        source_archive_path: str | Path,
        expression_frame: int = 0,
    ) -> dict[str, Any]:
        """Add a new actor instance without replacing existing actors."""

        archive = Path(source_archive_path).expanduser().resolve()
        if not archive.is_file() or archive.suffix.casefold() != ".bin":
            raise HcbError(f"舞台角色来源视觉 BIN 不存在: {archive}")
        if not isinstance(draft, dict) or not draft.get("variant"):
            raise HcbError("舞台角色缺少有效的分层立绘草稿")
        try:
            frame = max(0, int(expression_frame))
        except (TypeError, ValueError) as exc:
            raise HcbError("表情帧必须是非负整数") from exc
        with self.lock:
            self.portrait_v2_actor_serial += 1
            actor_id = f"actor-{self.portrait_v2_actor_serial:04d}"
            actor = {
                "actor_id": actor_id,
                "identity": _portrait_actor_identity_from_draft(draft),
                "draft": copy.deepcopy(draft),
                "source_archive_path": str(archive),
                "expression_frame": frame,
                "visible": True,
            }
            self.portrait_v2_scene["actors"].append(actor)
            self.portrait_v2_scene["selected_actor_id"] = actor_id
            self.portrait_v2_scene["revision"] += 1
            self.portrait_v2_draft = copy.deepcopy(actor["draft"])
            return copy.deepcopy(actor)

    def portrait_scene_select(self, actor_id: str) -> dict[str, Any]:
        with self.lock:
            actor = self._portrait_scene_actor(actor_id)
            self.portrait_v2_scene["selected_actor_id"] = actor_id
            self.portrait_v2_draft = copy.deepcopy(actor["draft"])
            return copy.deepcopy(actor)

    def portrait_scene_update(
        self,
        actor_id: str,
        *,
        draft: dict[str, Any] | None = None,
        identity: dict[str, Any] | None = None,
        expression_frame: int | None = None,
        visible: bool | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            actor = self._portrait_scene_actor(actor_id)
            if draft is not None:
                if not isinstance(draft, dict) or not draft.get("variant"):
                    raise HcbError("舞台角色缺少有效的分层立绘草稿")
                actor["draft"] = copy.deepcopy(draft)
            if identity is not None:
                if not isinstance(identity, dict):
                    raise HcbError("舞台角色 identity 必须是对象")
                actor["identity"] = _portrait_actor_identity(identity, actor.get("identity"))
            if expression_frame is not None:
                try:
                    actor["expression_frame"] = max(0, int(expression_frame))
                except (TypeError, ValueError) as exc:
                    raise HcbError("表情帧必须是非负整数") from exc
            if visible is not None:
                actor["visible"] = bool(visible)
            self.portrait_v2_scene["revision"] += 1
            # Updating an actor is not a selection operation.  In particular, a
            # delayed browser save for actor A must not steal selection from
            # actor B after the user has switched tabs; doing so lets the shared
            # editor draft get written into the wrong actor on the next input.
            if self.portrait_v2_scene["selected_actor_id"] == actor_id:
                self.portrait_v2_draft = copy.deepcopy(actor["draft"])
            return copy.deepcopy(actor)

    def portrait_scene_reorder(self, actor_ids: Any) -> dict[str, Any]:
        """Persist the exact back-to-front actor order without rebinding identity.

        The visual list is ordered from back to front and is the authoritative
        layer identity.  The native compiler later reverses the complete actor
        chain for Hoshimemo.  Reassign the existing sorted depth range only as
        a secondary transform hint; equal depths receive the smallest possible
        integer tie-breaker.  Actor IDs, sources, labels and drafts stay bound
        to the same actor objects throughout the reorder.
        """

        if not isinstance(actor_ids, list):
            raise HcbError("角色层级顺序必须是 actor_id 数组")
        ordered_ids: list[str] = []
        for value in actor_ids:
            if not isinstance(value, str) or not value.strip():
                raise HcbError("角色层级顺序包含无效 actor_id")
            ordered_ids.append(value.strip())
        if len(ordered_ids) != len(set(ordered_ids)):
            raise HcbError("角色层级顺序不能包含重复 actor_id")

        with self.lock:
            actors = self.portrait_v2_scene["actors"]
            current_ids = [str(actor.get("actor_id") or "") for actor in actors]
            if len(ordered_ids) != len(current_ids) or set(ordered_ids) != set(current_ids):
                raise HcbError("角色层级顺序必须完整包含当前舞台的全部 actor_id")
            by_id = {actor["actor_id"]: actor for actor in actors}
            reordered = [by_id[actor_id] for actor_id in ordered_ids]
            transforms: list[dict[str, Any]] = []
            for actor in reordered:
                draft = actor.get("draft")
                transform = draft.get("transform") if isinstance(draft, dict) else None
                if not isinstance(transform, dict):
                    raise HcbError(
                        f"舞台角色 {actor.get('actor_id')} 缺少可调整的 transform"
                    )
                transforms.append(transform)

            depths = _portrait_layer_depths(reordered)
            changed = ordered_ids != current_ids or any(
                _portrait_actor_depth(actor) != depth
                for actor, depth in zip(reordered, depths)
            )
            if changed:
                for transform, depth in zip(transforms, depths):
                    transform["z"] = depth
                self.portrait_v2_scene["actors"] = reordered
                self.portrait_v2_scene["revision"] += 1
                selected_id = self.portrait_v2_scene.get("selected_actor_id")
                selected = by_id.get(selected_id) if selected_id else None
                if selected is not None:
                    self.portrait_v2_draft = copy.deepcopy(selected["draft"])
                # A previously generated HCB/resource candidate represents the
                # older frozen layer order.  Keep the cue itself immutable, but
                # require a fresh Apply + dry-run before it can be used again.
                self.invalidate_visual_scene_candidate()
            return self.portrait_scene_snapshot()

    def portrait_scene_remove(self, actor_id: str) -> dict[str, Any] | None:
        with self.lock:
            actors = self.portrait_v2_scene["actors"]
            index = next(
                (index for index, actor in enumerate(actors) if actor["actor_id"] == actor_id),
                None,
            )
            if index is None:
                raise HcbError(f"找不到舞台角色: {actor_id}")
            actors.pop(index)
            selected = actors[min(index, len(actors) - 1)] if actors else None
            self.portrait_v2_scene["selected_actor_id"] = (
                selected["actor_id"] if selected is not None else None
            )
            self.portrait_v2_scene["revision"] += 1
            self.portrait_v2_draft = (
                copy.deepcopy(selected["draft"]) if selected is not None else None
            )
            return copy.deepcopy(selected)

    def require_document(self) -> HcbDocument:
        with self.lock:
            if self.document is None:
                raise HcbError("尚未打开 HCB 文件")
            return self.document

    def compatibility(self) -> dict[str, Any]:
        with self.lock:
            document = self.document
            profile = self.profile
            if document is None:
                return {"safe": False, "reason": "尚未打开 HCB", "warning_count": 0}
            if profile is not None:
                return profile.compatibility_for(document)
            warning_count = len(document.warnings)
            return {
                "safe": warning_count == 0,
                "reason": "HCB 未发现解析警告" if warning_count == 0 else f"HCB 解析产生 {warning_count:,} 个警告",
                "warning_count": warning_count,
                "parsed_string_count": document.string_count,
                "expected_string_count": None,
                "source_sha256": document.source_sha256,
            }

    def require_editable(self, body: dict[str, Any] | None = None) -> HcbDocument:
        document = self.require_document()
        compatibility = self.compatibility()
        # Explicit API callers can acknowledge the risk for experimental
        # formats. The normal UI never sends this flag.
        if not compatibility.get("safe", False) and not bool((body or {}).get("allow_unsafe")):
            raise HcbError(
                "当前 HCB 与线性解析器边界不一致，已进入只读保护；"
                "请使用原版 HCB/正确编码，或由高级脚本显式传入 allow_unsafe=true"
            )
        return document

    def status(self) -> dict[str, Any]:
        with self.lock:
            result: dict[str, Any] = {
                "loaded": self.document is not None,
                "last_action": self.last_action,
                "last_error": self.last_error,
                "uptime_seconds": round(time.time() - self.started_at, 2),
            }
            if self.document is not None:
                result.update(self.document.summary())
            result["compatibility"] = self.compatibility()
            result["profile"] = self.profile.summary if self.profile is not None else None
            # Discovery/review reports are immutable session snapshots.  Do
            # not recursively copy their large function-evidence trees on
            # every status poll; JSON serialization is already read-only.
            result["native_target"] = self.native_target_discovery
            result["native_target_profile_review"] = (
                self.native_target_profile_review
            )
            native_context = self.native_scene_memory_context
            result["native_scene_memory_context"] = (
                copy.deepcopy(dict(native_context.report))
                if native_context is not None
                and isinstance(getattr(native_context, "report", None), dict)
                else None
            )
            result["default_profile_dir"] = str(default_index_dir())
            result["plan_counts"] = {
                key: len(value) for key, value in self.plan.items() if isinstance(value, list)
            }
            result["jump_labels"] = {
                name: offset for name, offset in sorted(self.jump_labels.items())
            }
            result["portrait_v2_has_draft"] = self.portrait_v2_draft is not None
            result["portrait_v2_scene"] = {
                "actor_count": len(self.portrait_v2_scene["actors"]),
                "has_background": isinstance(self.portrait_v2_scene.get("background"), dict),
                "has_event_visual": isinstance(
                    self.portrait_v2_scene.get("event_visual"), dict
                ),
                "selected_actor_id": self.portrait_v2_scene["selected_actor_id"],
                "has_story_anchor": bool(
                    isinstance(self.portrait_v2_scene.get("story"), dict)
                    and isinstance(self.portrait_v2_scene["story"].get("anchor"), dict)
                ),
                "has_story_candidate": self.visual_scene_candidate is not None,
                "revision": self.portrait_v2_scene["revision"],
            }
            with self.runner_lock:
                result["runner"] = {
                    "running": self.runner is not None and self.runner.poll() is None,
                    "pid": self.runner.pid if self.runner is not None else None,
                    "command": list(self.runner_command),
                    "started_at": self.runner_started_at,
                    "exit_code": self.runner.poll() if self.runner is not None else None,
                    "log": list(self.runner_log)[-80:],
                }
            return result


SESSION = EditorSession()


def _active_document_parent() -> Path | None:
    """Return the directory that owns the currently opened HCB.

    A loaded HCB is the authoritative source for resources and for the game
    directory used by the local runner.  ``ProjectIndex.game_dir`` can point
    at the original analysis copy (for example an H: drive install) while the
    user is editing a copied HCB on another drive, so it must never win over
    this path.  Returning ``None`` for an unusable/in-memory document keeps
    generic profile-only sessions working.
    """

    with SESSION.lock:
        document = SESSION.document
        path = getattr(document, "path", None) if document is not None else None
    if path is None:
        return None
    try:
        parent = Path(path).expanduser().resolve().parent
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return parent if parent.is_dir() else None


def _profile_game_dir() -> Path | None:
    """Return the optional profile game directory as a fallback only."""

    with SESSION.lock:
        profile = SESSION.profile
        game_dir = getattr(profile, "game_dir", None) if profile is not None else None
    if game_dir is None:
        return None
    try:
        resolved = Path(game_dir).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return resolved if resolved.is_dir() else None


def _profile_fallback_matches_active_hcb(profile_dir: Path) -> bool:
    """Allow a resource fallback only for the same named game HCB.

    A translated/test HCB is often opened from an ``_hcb_artifacts`` backup
    directory while its BIN archives remain in the game root described by
    the profile.  Falling back unconditionally would make two different FVP
    games with a common archive name (for example ``graph.bin``) easy to mix
    up, so require a matching HCB stem before using the profile directory.
    """

    with SESSION.lock:
        document = SESSION.document
        active_path = getattr(document, "path", None) if document is not None else None
    if active_path is None:
        return False
    try:
        active_stem = Path(active_path).stem.casefold().lstrip(".")
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    if not active_stem:
        return False
    try:
        profile_hcbs = profile_dir.glob("*.hcb")
        for candidate in profile_hcbs:
            profile_stem = candidate.stem.casefold().lstrip(".")
            if profile_stem and (profile_stem == active_stem or profile_stem in active_stem or active_stem in profile_stem):
                return True
    except OSError:
        return False
    return False


def _default_project_dir() -> Path | None:
    """Choose the project directory for APIs that do not receive one.

    The active document's parent is deliberately first.  The profile path is
    retained only for sessions without a file-backed HCB (or an in-memory HCB)
    so generic profile browsing remains usable.
    """

    return _active_document_parent() or _profile_game_dir()


def _stable_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _stable_target_file_bytes(
    root_value: str | Path,
    filename: str,
    *,
    label: str,
) -> bytes:
    """Read one direct child while rejecting links, escapes and live changes."""

    name = str(filename).strip()
    if (
        not name
        or name in {".", ".."}
        or Path(name).name != name
        or any(separator in name for separator in ("/", "\\"))
    ):
        raise HcbError(f"{label}文件名无效")
    try:
        root = Path(root_value).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HcbError(f"{label}目标目录无效: {exc}") from exc
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise HcbError(f"{label}不存在或是符号链接: {path}")
    try:
        if path.resolve().parent != root:
            raise HcbError(f"{label}逃逸目标目录")
        before = path.stat()
        payload = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        raise HcbError(f"无法稳定读取{label}: {exc}") from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(payload) != after.st_size
    ):
        raise HcbError(f"读取期间{label}已变化，请重试")
    return payload


def _pe_imported_symbol_names(payload: bytes) -> frozenset[str]:
    """Read PE import names with stdlib only; reject malformed layouts."""

    if not isinstance(payload, bytes) or len(payload) < 0x100 or payload[:2] != b"MZ":
        raise HcbError("目标 EXE 不是有效 PE 文件")
    try:
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        if payload[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise HcbError("目标 EXE 缺少 PE 签名")
        coff = pe_offset + 4
        section_count = struct.unpack_from("<H", payload, coff + 2)[0]
        optional_size = struct.unpack_from("<H", payload, coff + 16)[0]
        optional = coff + 20
        magic = struct.unpack_from("<H", payload, optional)[0]
        if magic == 0x10B:
            data_directories = optional + 96
            thunk_size = 4
            ordinal_mask = 0x80000000
            thunk_format = "<I"
        elif magic == 0x20B:
            data_directories = optional + 112
            thunk_size = 8
            ordinal_mask = 0x8000000000000000
            thunk_format = "<Q"
        else:
            raise HcbError("目标 EXE 的 PE optional header 类型不受支持")
        import_rva, import_size = struct.unpack_from(
            "<II", payload, data_directories + 8
        )
        section_table = optional + optional_size
        sections: list[tuple[int, int, int, int]] = []
        if not 0 < section_count <= 96:
            raise HcbError("目标 EXE 的 PE section 数量无效")
        for index in range(section_count):
            entry = section_table + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", payload, entry + 8
            )
            sections.append(
                (virtual_address, max(virtual_size, raw_size), raw_offset, raw_size)
            )
    except (struct.error, IndexError) as exc:
        raise HcbError("目标 EXE 的 PE 头已截断") from exc

    def rva_to_offset(rva: int) -> int:
        for virtual_address, mapped_size, raw_offset, raw_size in sections:
            if virtual_address <= rva < virtual_address + mapped_size:
                relative = rva - virtual_address
                if relative >= raw_size:
                    break
                offset = raw_offset + relative
                if not 0 <= offset < len(payload):
                    break
                return offset
        raise HcbError("目标 EXE 的 PE RVA 不能映射到文件")

    if import_rva == 0 or import_size == 0:
        return frozenset()
    descriptor_offset = rva_to_offset(import_rva)
    names: set[str] = set()
    for descriptor_index in range(4096):
        entry = descriptor_offset + descriptor_index * 20
        try:
            original_thunk, _, _, _, first_thunk = struct.unpack_from(
                "<IIIII", payload, entry
            )
        except struct.error as exc:
            raise HcbError("目标 EXE 的 PE import descriptor 已截断") from exc
        if original_thunk == 0 and first_thunk == 0:
            return frozenset(names)
        thunk_rva = original_thunk or first_thunk
        thunk_offset = rva_to_offset(thunk_rva)
        for thunk_index in range(65536):
            offset = thunk_offset + thunk_index * thunk_size
            try:
                value = struct.unpack_from(thunk_format, payload, offset)[0]
            except struct.error as exc:
                raise HcbError("目标 EXE 的 PE import thunk 已截断") from exc
            if value == 0:
                break
            if value & ordinal_mask:
                continue
            name_offset = rva_to_offset(int(value)) + 2
            end = payload.find(b"\0", name_offset, min(len(payload), name_offset + 512))
            if end < 0:
                raise HcbError("目标 EXE 的 PE import 名称未终止")
            try:
                names.add(payload[name_offset:end].decode("ascii"))
            except UnicodeDecodeError as exc:
                raise HcbError("目标 EXE 的 PE import 名称不是 ASCII") from exc
        else:
            raise HcbError("目标 EXE 的 PE import thunk 数量异常")
    raise HcbError("目标 EXE 的 PE import descriptor 数量异常")


def _system_ansi_code_page() -> int:
    try:
        import ctypes

        return int(ctypes.windll.kernel32.GetACP())
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise HcbError(f"无法读取当前 Windows ANSI 代码页: {exc}") from exc


def _target_owned_drawtexta_executable(root: Path) -> Mapping[str, Any]:
    matches: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.exe"), key=lambda item: item.name.casefold()):
        if path.is_symlink() or not path.is_file() or path.resolve().parent != root:
            continue
        payload = _stable_target_file_bytes(root, path.name, label="目标文本渲染 EXE")
        imports = _pe_imported_symbol_names(payload)
        if "DrawTextA" not in imports:
            continue
        matches.append(
            {
                "name": path.name,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if len(matches) != 1:
        raise HcbError(
            "目标目录必须且只能有一个导入 DrawTextA 的游戏 EXE，"
            f"实际 {len(matches)} 个"
        )
    return matches[0]


def _runtime_text_bridge_for_target(
    root_value: str | Path,
    *,
    encoding: str,
    requested_encoding: str | None = None,
) -> Mapping[str, Any] | None:
    """Build one explicit target-owned runtime text route without writes."""

    try:
        root = Path(root_value).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HcbError(f"UIF 文本桥目标目录无效: {exc}") from exc
    config_path = root / "uif_config.json"
    requested = str(requested_encoding or "inherit").strip().casefold()
    if requested in {"", "auto", "source"}:
        requested = "inherit"
    if requested not in {"inherit", "gbk", "cp936"}:
        raise HcbError("新增台词运行时编码只允许继承 HCB 或 GBK/CP936")
    from .hoshimemo_scene_hook import (
        HoshimemoSceneHookError,
        build_native_ansi_drawtexta_text_bridge,
        build_uif_drawtexta_text_bridge,
    )
    if config_path.exists():
        payload = _stable_target_file_bytes(
            root,
            "uif_config.json",
            label="UIF 文本桥配置",
        )
        try:
            return build_uif_drawtexta_text_bridge(
                payload,
                encoding=encoding,
                config_name="uif_config.json",
            )
        except HoshimemoSceneHookError as exc:
            raise HcbError(f"目标 UIF 文本桥复检失败: {exc}") from exc
    if requested == "inherit":
        return None
    normalized_source = str(encoding or "").strip().casefold()
    if normalized_source not in {"shift_jis", "sjis"}:
        raise HcbError("GBK 新增台词通道只用于 Shift-JIS 来源 HCB")
    launcher_markers = {
        item.name.casefold()
        for item in root.iterdir()
        if item.is_file()
    }.intersection(
        {"fvploadergui.exe", "fvplog.ini", "xmoe_fvp.dll"}
    )
    if launcher_markers:
        raise HcbError(
            "检测到外部 FVP loader；宿主 Windows 代码页不能证明游戏进程的 "
            "DrawTextA 代码页，请改用 UIF 中文桥"
        )
    code_page = _system_ansi_code_page()
    if code_page != 936:
        raise HcbError(
            "当前 Windows ANSI 代码页不是 936；"
            "不能证明目标 DrawTextA 会把新增字节解释为 GBK"
        )
    executable = _target_owned_drawtexta_executable(root)
    try:
        return build_native_ansi_drawtexta_text_bridge(
            source_encoding="shift_jis",
            runtime_encoding="gbk",
            code_page=code_page,
            executable_name=str(executable["name"]),
            executable_size=int(executable["size"]),
            executable_sha256=str(executable["sha256"]),
        )
    except (KeyError, TypeError, ValueError, HoshimemoSceneHookError) as exc:
        raise HcbError(f"目标 ANSI DrawTextA 文本通道复检失败: {exc}") from exc


def _runtime_text_companion_for_target(
    root_value: str | Path,
    package_root_value: str | Path,
    display_texts: Sequence[str],
    source_hcb: bytes,
    *,
    encoding: str,
) -> tuple[Mapping[str, Any], dict[str, bytes], Mapping[str, Any]]:
    """Build a transaction-owned UIF carrier bridge without touching paths."""

    normalized_source = str(encoding or "").strip().casefold()
    if normalized_source not in {"shift_jis", "sjis"}:
        raise HcbError("UIF 中文桥目前只用于 Shift-JIS 来源 HCB")
    texts = [str(value) for value in display_texts if isinstance(value, str) and value]
    if not texts:
        raise HcbError("UIF 中文桥没有可映射的新增台词")
    try:
        root = Path(root_value).expanduser().resolve()
        package_root = Path(package_root_value).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HcbError(f"UIF 中文桥路径无效: {exc}") from exc
    executable = _target_owned_drawtexta_executable(root)
    target_exe = root / str(executable["name"])
    try:
        from .runtime_text_companion import (
            RuntimeTextCompanionError,
            build_runtime_text_companion_candidate,
        )

        companion = build_runtime_text_companion_candidate(
            package_root,
            target_exe,
            texts,
            source_hcb,
            source_encoding="shift_jis",
        )
        from .hoshimemo_scene_hook import (
            HoshimemoSceneHookError,
            build_uif_drawtexta_text_bridge,
        )

        bridge = build_uif_drawtexta_text_bridge(
            bytes(companion["config_bytes"]),
            encoding="shift_jis",
            config_name="uif_config.json",
        )
    except (KeyError, TypeError, ValueError, RuntimeTextCompanionError, HoshimemoSceneHookError) as exc:
        raise HcbError(f"UIF 中文桥候选生成失败: {exc}") from exc
    files = {
        str(name): bytes(payload)
        for name, payload in dict(companion["candidate_files"]).items()
    }
    report = copy.deepcopy(dict(companion["report"]))
    report["mode"] = "transaction_owned_uif_drawtexta_replace_chars"
    report["target_install_root"] = str(root)
    report["source_package_root"] = str(package_root)
    return bridge, files, report


def _verify_runtime_text_bridge_target(
    root_value: str | Path,
    report: Mapping[str, Any] | None,
    *,
    companion_files: Mapping[str, bytes] | None = None,
    companion_report: Mapping[str, Any] | None = None,
) -> None:
    """Re-hash the target config immediately before prepare/apply transactions."""

    if not isinstance(report, Mapping) or report.get("enabled") is not True:
        if companion_files:
            raise HcbError("剧情候选携带 UIF 文件，但运行时文本桥未启用")
        return
    mode = str(report.get("mode") or "")
    if mode == "target_owned_drawtexta_acp":
        if report.get("schema") != "fvp-studio-v2.native-ansi-drawtexta.v1":
            raise HcbError("剧情候选的 ANSI DrawTextA 文本通道报告无效")
        name = str(report.get("executable_name") or "")
        expected_sha256 = str(report.get("executable_sha256") or "").casefold()
        try:
            expected_size = int(report.get("executable_size"))
            code_page = int(report.get("code_page"))
        except (TypeError, ValueError) as exc:
            raise HcbError("剧情候选的 ANSI 文本通道数值字段无效") from exc
        if (
            report.get("api") != "DrawTextA"
            or report.get("source_encoding") != "shift_jis"
            or report.get("encoding") != "gbk"
            or report.get("strict_two_byte_dbcs") is not True
            or report.get("user_selected") is not True
            or code_page != 936
            or not name
            or Path(name).name != name
            or Path(name).suffix.casefold() != ".exe"
            or any(separator in name for separator in ("/", "\\"))
            or expected_size <= 0
            or len(expected_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_sha256)
        ):
            raise HcbError("剧情候选的 ANSI DrawTextA 文本通道身份无效")
        payload = _stable_target_file_bytes(
            root_value,
            name,
            label="ANSI DrawTextA 游戏 EXE",
        )
        if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise HcbError("ANSI DrawTextA 游戏 EXE 已变化，请重新生成候选")
        if "DrawTextA" not in _pe_imported_symbol_names(payload):
            raise HcbError("目标游戏 EXE 已不再导入 DrawTextA")
        if _system_ansi_code_page() != code_page:
            raise HcbError("Windows ANSI 代码页已变化，请重新生成候选")
        return
    if companion_files:
        if (
            report.get("schema")
            != "fvp-studio-v2.uif-drawtexta-replace-chars.v1"
            or mode != "target_owned_uif_drawtexta_replace_chars"
        ):
            raise HcbError("剧情候选的 UIF 文本桥报告无效")
        if not isinstance(companion_report, Mapping) or (
            companion_report.get("schema")
            != "fvp-studio-v2.runtime-text-companion.v1"
        ):
            raise HcbError("剧情候选缺少 UIF 伴随组件审计报告")
        expected_records = companion_report.get("candidate_files")
        if not isinstance(expected_records, Mapping):
            raise HcbError("UIF 伴随组件审计报告缺少文件身份")
        supplied = {str(name).casefold(): bytes(payload) for name, payload in companion_files.items()}
        required = {
            "winmm.dll",
            "loaderdll.dll",
            "localeemulator.dll",
            "uif_config.json",
        }
        if set(supplied) != required:
            raise HcbError("UIF 伴随组件文件集合不完整")
        for raw_name, raw_record in expected_records.items():
            name = str(raw_name).casefold()
            if name not in supplied or not isinstance(raw_record, Mapping):
                raise HcbError(f"UIF 伴随组件 {raw_name} 身份报告无效")
            payload = supplied[name]
            try:
                expected_size = int(raw_record.get("size"))
            except (TypeError, ValueError) as exc:
                raise HcbError(f"UIF 伴随组件 {raw_name} 大小报告无效") from exc
            if (
                len(payload) != expected_size
                or hashlib.sha256(payload).hexdigest()
                != str(raw_record.get("sha256") or "").casefold()
            ):
                raise HcbError(f"UIF 伴随组件 {raw_name} 候选负载已变化")
        config_payload = supplied["uif_config.json"]
        if (
            len(config_payload) != int(report.get("config_size") or -1)
            or hashlib.sha256(config_payload).hexdigest()
            != str(report.get("config_sha256") or "").casefold()
        ):
            raise HcbError("UIF 候选配置与剧情文本桥不一致")
        target_identity = companion_report.get("target_exe_identity")
        if not isinstance(target_identity, Mapping):
            raise HcbError("UIF 伴随组件缺少目标 EXE 身份")
        target_name = str(target_identity.get("name") or "")
        if (
            not target_name
            or Path(target_name).name != target_name
            or any(separator in target_name for separator in ("/", "\\"))
        ):
            raise HcbError("UIF 伴随组件目标 EXE 名无效")
        target_payload = _stable_target_file_bytes(
            root_value,
            target_name,
            label="UIF DrawTextA 游戏 EXE",
        )
        if (
            len(target_payload) != int(target_identity.get("size") or -1)
            or hashlib.sha256(target_payload).hexdigest()
            != str(target_identity.get("sha256") or "").casefold()
        ):
            raise HcbError("UIF DrawTextA 游戏 EXE 已变化，请重新生成候选")
        try:
            from .runtime_text_companion import (
                RuntimeTextCompanionError,
                validate_target_proxy_imports,
            )

            validate_target_proxy_imports(target_payload, supplied["winmm.dll"])
        except RuntimeTextCompanionError as exc:
            raise HcbError(f"UIF winmm proxy 覆盖复检失败: {exc}") from exc
        return
    if (
        report.get("schema")
        != "fvp-studio-v2.uif-drawtexta-replace-chars.v1"
        or mode != "target_owned_uif_drawtexta_replace_chars"
    ):
        raise HcbError("剧情候选的运行时文本桥报告无效")
    name = str(report.get("config_name") or "")
    expected_sha256 = str(report.get("config_sha256") or "").casefold()
    try:
        expected_size = int(report.get("config_size"))
    except (TypeError, ValueError) as exc:
        raise HcbError("剧情候选的 UIF 配置大小无效") from exc
    if (
        not name
        or Path(name).name != name
        or any(separator in name for separator in ("/", "\\"))
        or len(expected_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_sha256)
        or expected_size <= 0
    ):
        raise HcbError("剧情候选的 UIF 配置身份无效")
    payload = _stable_target_file_bytes(
        root_value,
        name,
        label="UIF 文本桥配置",
    )
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if len(payload) != expected_size or actual_sha256 != expected_sha256:
        raise HcbError("目标 UIF 文本桥配置已变化，候选已失效")


def _native_discovery_cache_identity(value: Mapping[str, Any]) -> str:
    """Hash the discovery's own immutable identity, not its large evidence UI."""

    hcb = value.get("hcb") if isinstance(value.get("hcb"), Mapping) else {}
    runtime = (
        hcb.get("runtime_resolution")
        if isinstance(hcb.get("runtime_resolution"), Mapping)
        else {}
    )
    return _stable_json_sha256(
        {
            "schema": value.get("schema"),
            "target_id": value.get("target_id"),
            "manifest_sha256": value.get("manifest_sha256"),
            "game_dir": value.get("game_dir"),
            "analysis_source": hcb.get("analysis_source"),
            "active_candidate": runtime.get("active_candidate"),
        }
    )


def _trusted_hoshimemo_scene_profile(profile: Any) -> bool:
    """Return whether the established Hoshimemo ABI may remain in use."""

    index_dir = getattr(profile, "index_dir", None)
    if index_dir is None:
        return False
    try:
        return Path(index_dir).expanduser().resolve() == default_index_dir().resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def _native_story_archive_names(story: Mapping[str, Any]) -> set[str]:
    """Return only the target archives referenced by complete story scenes."""

    from .visual_scene_project import VisualSceneProjectError, buildable_story_scenes

    try:
        scenes = buildable_story_scenes(story)
    except VisualSceneProjectError as exc:
        raise HcbError(str(exc)) from exc
    result: set[str] = set()
    for item in scenes:
        cue = item.get("cue") if isinstance(item.get("cue"), Mapping) else {}
        actors = cue.get("actors") if isinstance(cue.get("actors"), list) else []
        for actor in actors:
            if not isinstance(actor, Mapping):
                raise HcbError("剧情立绘快照不是对象")
            locked = (
                actor.get("locked_pair")
                if isinstance(actor.get("locked_pair"), Mapping)
                else {}
            )
            archive_name = str(locked.get("archive") or "").strip().casefold()
            if archive_name:
                result.add(archive_name)
        event_visual = (
            cue.get("event_visual")
            if isinstance(cue.get("event_visual"), Mapping)
            else None
        )
        visual = event_visual
        if visual is None:
            visual = (
                cue.get("background")
                if isinstance(cue.get("background"), Mapping)
                else None
            )
        if not isinstance(visual, Mapping):
            continue
        archive_name = str(visual.get("archive_name") or "").strip().casefold()
        if archive_name:
            result.add(archive_name)
    return result


def _native_story_resource_catalog(
    story: Mapping[str, Any],
    discovery: Mapping[str, Any],
    game_root: Path,
    *,
    allow_cross_game_portraits: bool = False,
) -> dict[str, Sequence[str]]:
    """Read and identity-check only BIN directories needed by one dry-run."""

    from .bin_archive import BinArchiveError, archive_directory_identity_file
    from .native_target_profile import build_native_target_profile_template

    required = _native_story_archive_names(story)
    target_profile = build_native_target_profile_template(discovery)
    routing = target_profile.get("archive_routing")
    routing_value = routing if isinstance(routing, Mapping) else {}
    identities: dict[str, Mapping[str, Any]] = {}
    for role in ("background", "portrait", "event_visual"):
        role_value = routing_value.get(role)
        routes = role_value.get("routes") if isinstance(role_value, Mapping) else None
        if not isinstance(routes, list):
            continue
        for route in routes:
            if not isinstance(route, Mapping):
                continue
            archive_name = str(route.get("archive") or "").strip().casefold()
            identity = route.get("archive_identity")
            if archive_name and isinstance(identity, Mapping):
                previous = identities.get(archive_name)
                if previous is not None and dict(previous) != dict(identity):
                    raise HcbError(f"原生目标归档 {archive_name} 的发现身份互相冲突")
                identities[archive_name] = identity

    result: dict[str, Sequence[str]] = {}
    root = game_root.expanduser().resolve()
    from .visual_scene_project import VisualSceneProjectError, buildable_story_scenes

    try:
        scenes = buildable_story_scenes(story)
    except VisualSceneProjectError as exc:
        raise HcbError(str(exc)) from exc
    portrait_locks: dict[str, list[tuple[str, int, int]]] = {}
    cross_game_portrait_archives: set[str] = set()
    visual_archive_names: set[str] = set()
    for scene in scenes:
        cue = scene.get("cue") if isinstance(scene.get("cue"), Mapping) else {}
        visual = (
            cue.get("event_visual")
            if isinstance(cue.get("event_visual"), Mapping)
            else cue.get("background")
            if isinstance(cue.get("background"), Mapping)
            else None
        )
        if isinstance(visual, Mapping):
            visual_archive_name = str(
                visual.get("archive_name") or ""
            ).strip().casefold()
            if visual_archive_name:
                visual_archive_names.add(visual_archive_name)
        actors = cue.get("actors") if isinstance(cue.get("actors"), list) else []
        for actor in actors:
            if not isinstance(actor, Mapping):
                raise HcbError("剧情立绘快照不是对象")
            actor_id = str(actor.get("actor_id") or "").strip()
            if not actor_id:
                raise HcbError("剧情立绘快照缺少稳定 actor_id")
            locked = (
                actor.get("locked_pair")
                if isinstance(actor.get("locked_pair"), Mapping)
                else None
            )
            if not isinstance(locked, Mapping):
                raise HcbError(f"角色 {actor_id} 缺少冻结身体/表情配对")
            archive_name = str(locked.get("archive") or "").strip().casefold()
            if archive_name not in {"graph.bin", "graph_bs.bin"}:
                raise HcbError(
                    f"角色 {actor_id} 的来源不是受支持的 FVP 角色归档"
                )
            source_value = str(actor.get("source_archive_path") or "").strip()
            if not source_value:
                raise HcbError(f"角色 {actor_id} 缺少冻结来源归档路径")
            source_path = Path(source_value).expanduser()
            expected_path = root / archive_name
            if source_path.is_symlink() or not source_path.is_file():
                raise HcbError(f"角色 {actor_id} 来源归档不存在或是符号链接")
            source_is_target = _same_resolved_path(source_path, expected_path)
            if not source_is_target and not allow_cross_game_portraits:
                raise HcbError(
                    f"角色 {actor_id} 来源于其他游戏；通用候选只允许当前目标本作直引"
                )
            try:
                archive_size = int(locked.get("archive_size"))
                archive_mtime_ns = int(locked.get("archive_mtime_ns"))
            except (TypeError, ValueError) as exc:
                raise HcbError(f"角色 {actor_id} 冻结归档身份无效") from exc
            if archive_size < 1 or archive_mtime_ns < 0:
                raise HcbError(f"角色 {actor_id} 冻结归档身份无效")
            if source_is_target:
                portrait_locks.setdefault(archive_name, []).append(
                    (actor_id, archive_size, archive_mtime_ns)
                )
            else:
                cross_game_portrait_archives.add(archive_name)
                try:
                    source_stat = source_path.stat()
                except OSError as exc:
                    raise HcbError(
                        f"无法复检角色 {actor_id} 的跨游戏来源归档: {exc}"
                    ) from exc
                if (
                    int(source_stat.st_size) != archive_size
                    or int(source_stat.st_mtime_ns) != archive_mtime_ns
                ):
                    raise HcbError(
                        f"角色 {actor_id} 的跨游戏来源归档身份已漂移，请重新分析"
                    )
    for archive_name in cross_game_portrait_archives:
        if (
            archive_name not in portrait_locks
            and archive_name not in visual_archive_names
        ):
            required.discard(archive_name)
    for archive_name in sorted(required):
        if Path(archive_name).name.casefold() != archive_name or any(
            separator in archive_name for separator in ("/", "\\")
        ):
            raise HcbError(f"剧情资源归档名称越界: {archive_name}")
        expected = identities.get(archive_name)
        if expected is None:
            raise HcbError(f"原生目标发现报告没有锁定资源归档 {archive_name}")
        archive_path = root / archive_name
        if archive_path.is_symlink() or not archive_path.is_file():
            raise HcbError(f"原生目标资源归档不存在或是符号链接: {archive_path}")
        try:
            if archive_path.resolve().parent != root:
                raise HcbError(f"原生目标资源归档逃逸游戏目录: {archive_path}")
            stat = archive_path.stat()
            names, directory_sha256 = archive_directory_identity_file(archive_path)
        except (OSError, BinArchiveError) as exc:
            raise HcbError(f"无法只读核对 {archive_name}: {exc}") from exc
        expected_size = expected.get("size")
        expected_count = expected.get("entry_count")
        expected_directory = str(expected.get("directory_sha256") or "")
        if expected_size is not None and int(expected_size) != int(stat.st_size):
            raise HcbError(f"原生目标资源归档 {archive_name} 的文件大小已漂移")
        if expected_count is not None and int(expected_count) != len(names):
            raise HcbError(f"原生目标资源归档 {archive_name} 的目录项数已漂移")
        if expected_directory and expected_directory != directory_sha256:
            raise HcbError(f"原生目标资源归档 {archive_name} 的目录哈希已漂移")
        for actor_id, frozen_size, frozen_mtime_ns in portrait_locks.get(
            archive_name, []
        ):
            if (
                int(stat.st_size) != frozen_size
                or int(stat.st_mtime_ns) != frozen_mtime_ns
            ):
                raise HcbError(
                    f"角色 {actor_id} 的 {archive_name} 冻结身份已漂移，请重新分析"
                )
        result[archive_name] = names
    return result


def _native_acceptance_audio_is_noop(value: Any) -> bool:
    audio = value if isinstance(value, Mapping) else {}
    bgm = audio.get("bgm") if isinstance(audio.get("bgm"), Mapping) else {}
    se = audio.get("se") if isinstance(audio.get("se"), Mapping) else {}
    return (
        str(bgm.get("action") or "keep").strip().casefold() == "keep"
        and str(se.get("action") or "none").strip().casefold() == "none"
    )


def _native_acceptance_replay_patch_is_safe(
    patch: Mapping[str, Any],
    source_bytes: bytes,
) -> bool:
    """Accept an exact source replay behind one five-byte jump window.

    Generic translated overlays historically hook the five-byte terminal jump
    that replaced the selected source string.  A ``before`` hook may instead
    move one instruction earlier so the inserted narration runs before the
    native speaker setter.  That second form is deliberately limited to one
    exact CALL which is replayed and then falls through to the selected string.
    An ``after`` hook is likewise limited to the exact five-byte native wait
    CALL: it is replayed first, then the custom scene runs, and control returns
    to the immediately following source instruction.
    A linear old-FVP HCB may instead hook the selected ``push_string`` itself;
    that form is accepted only when its complete variable-width instruction is
    replayed byte-for-byte and its encoded length/terminator are self-consistent.
    """

    try:
        patch_offset = int(patch.get("patch_offset"))
        replay_offset = int(patch.get("replay_offset"))
        replay_size = int(patch.get("replay_size"))
        return_offset = int(patch.get("return_offset"))
        expected = bytes.fromhex(str(patch.get("expected_hex") or ""))
        replay = bytes.fromhex(str(patch.get("replay_hex") or ""))
    except (TypeError, ValueError):
        return False
    if (
        patch_offset < 0
        or patch_offset != replay_offset
        or replay_size < 5
        or len(expected) != 5
        or len(replay) != replay_size
        or patch.get("replay_order")
        not in {"custom_then_original", "original_then_custom"}
        or source_bytes[patch_offset : patch_offset + 5] != expected
        or source_bytes[replay_offset : replay_offset + replay_size] != replay
    ):
        return False
    if patch.get("replay_terminal") is True:
        return (
            patch.get("replay_order") == "custom_then_original"
            and replay_size == 5
            and replay == expected
        )
    if (
        patch.get("replay_terminal") is False
        and patch.get("replay_order") == "custom_then_original"
        and str(patch.get("hook_mode") or "") == "pre_speaker_call"
        and replay_size == 5
        and replay == expected
        and expected[0] == 0x02
        and return_offset == patch_offset + 5
    ):
        return True
    if (
        patch.get("replay_terminal") is False
        and patch.get("replay_order") == "original_then_custom"
        and str(patch.get("hook_mode") or "") == "dialogue_wait_call"
        and replay_size == 5
        and replay == expected
        and expected[0] == 0x02
        and return_offset == patch_offset + 5
    ):
        return True
    return (
        patch.get("replay_terminal") is False
        and patch.get("replay_order") == "custom_then_original"
        and str(patch.get("hook_mode") or "") == "dialogue_instruction"
        and str(patch.get("source_dialogue_mode") or "")
        == "fixed_width_string"
        and replay[0] == 0x0E
        and replay_size == 2 + int(replay[1])
        and replay[-1] == 0
        and expected == replay[:5]
        and return_offset == patch_offset + replay_size
    )


def _native_portrait_cleanup_handoff_is_safe(
    cleanup: Mapping[str, Any],
    profile_lifecycle: Mapping[str, Any],
) -> bool:
    """Validate the exact native lifecycle handoff selected for one target.

    A registration boundary inherits the selector geometry restored by the main
    scene trampoline, so it must perform the explicit Nil-layout handoff before
    replay.  An apply boundary already has its original target-specific
    arguments on the VM stack; it must clear the imported selector and replay that exact native
    apply without emitting a second apply call.  Visual-reset handoffs remain
    outside the portrait acceptance write gate.
    """

    clear = cleanup.get("clear") if isinstance(cleanup.get("clear"), Mapping) else {}
    apply = cleanup.get("apply") if isinstance(cleanup.get("apply"), Mapping) else {}
    restored = (
        cleanup.get("restored_layout_apply_before_replay")
        if isinstance(cleanup.get("restored_layout_apply_before_replay"), Mapping)
        else {}
    )
    try:
        clear_target = int(profile_lifecycle.get("clear_target"))
        apply_target = int(profile_lifecycle.get("apply_target"))
        apply_argument_count = int(
            profile_lifecycle.get("apply_argument_count", 3)
        )
        report_clear_target = int(clear.get("target"))
        report_apply_target = int(apply.get("target"))
        replayed_target = int(cleanup.get("replayed_target"))
        patch_offset = int(cleanup.get("patch_offset"))
        return_offset = int(cleanup.get("return_offset"))
        expected = bytes.fromhex(str(cleanup.get("expected_hex") or ""))
    except (TypeError, ValueError):
        return False
    if (
        clear_target < 0
        or apply_target < 0
        or report_clear_target != clear_target
        or report_apply_target != apply_target
        or clear.get("argument_count") != 2
        or apply_argument_count not in {2, 3}
        or apply.get("argument_count") != apply_argument_count
        or len(expected) != 5
        or expected[0] != 0x02
        or int.from_bytes(expected[1:5], "little") != replayed_target
        or return_offset != patch_offset + 5
    ):
        return False

    kind = str(cleanup.get("kind") or "")
    if kind == "portrait_apply":
        return (
            replayed_target == apply_target
            and clear.get("performed") is True
            and restored.get("enabled") is False
            and restored.get("target") == apply_target
            and cleanup.get("explicit_apply_before_replay") is False
            and cleanup.get("explicit_apply_reason") is None
            and cleanup.get("explicit_apply_duration") is None
        )
    if kind == "portrait_registration":
        try:
            registration_target_count = int(
                profile_lifecycle.get("registration_target_count")
            )
        except (TypeError, ValueError):
            return False
        return (
            registration_target_count >= 1
            and replayed_target != apply_target
            and clear.get("performed") is False
            and restored.get("enabled") is True
            and restored.get("target") == apply_target
            and restored.get("arguments") == [None] * apply_argument_count
            and restored.get("reason") == "preserve_nil_inherited_native_geometry"
            and cleanup.get("explicit_apply_before_replay") is True
            and cleanup.get("explicit_apply_reason")
            == "restored_native_layout_handoff"
            and cleanup.get("explicit_apply_duration") is None
        )
    return False


def _native_active_target_override_is_safe(
    body: Mapping[str, Any],
    report: Mapping[str, Any],
    *,
    target_root: str | Path,
    document_path: Path | None,
    profile_game_dir: str | Path | None,
) -> bool:
    """Allow only one explicit, acceptance-only write to the exact active root."""

    if body.get("allow_active_target") is not True:
        return False
    if document_path is None or profile_game_dir is None:
        return False
    try:
        raw_target = Path(target_root).expanduser()
        if raw_target.is_symlink():
            return False
        target = raw_target.resolve()
        document = Path(document_path).expanduser().resolve()
        profile_root = Path(profile_game_dir).expanduser().resolve()
        source_path = Path(
            str(
                (
                    report.get("source")
                    if isinstance(report.get("source"), Mapping)
                    else {}
                ).get("path")
                or ""
            )
        ).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    if (
        not target.is_dir()
        or target != document.parent
        or target != profile_root
        or source_path != document
    ):
        return False

    write_gate = (
        report.get("write_gate")
        if isinstance(report.get("write_gate"), Mapping)
        else {}
    )
    native_candidate = (
        report.get("native_target_candidate")
        if isinstance(report.get("native_target_candidate"), Mapping)
        else {}
    )
    native_output = (
        native_candidate.get("output")
        if isinstance(native_candidate.get("output"), Mapping)
        else {}
    )
    acceptance = (
        report.get("acceptance")
        if isinstance(report.get("acceptance"), Mapping)
        else {}
    )
    return (
        report.get("install_ready") is True
        and write_gate.get("enabled") is True
        and write_gate.get("scope") == "acceptance_only"
        and write_gate.get("policy")
        == "isolated_copy_native_portrait_acceptance"
        and isinstance(write_gate.get("blockers"), list)
        and not write_gate.get("blockers")
        and native_candidate.get("acceptance_only") is True
        and native_candidate.get("writes_performed") is False
        and native_candidate.get("mode")
        == "isolated_native_portrait_acceptance"
        and int(native_output.get("resource_archive_count") or 0) == 1
        and int(native_output.get("portrait_resource_count") or 0) == 2
        and acceptance.get("mode") == "isolated_copy_hcb_and_graph.bin"
        and acceptance.get("production_write_gate_unchanged") is True
    )


def _native_hcb_acceptance_issues(
    story: Mapping[str, Any],
    *,
    duration_ms: int,
    document: HcbDocument,
    discovery: Mapping[str, Any],
    native_context: Any,
    candidate_report: Mapping[str, Any],
    portrait_mode: bool = False,
) -> list[str]:
    """Return blockers for one deliberately narrow isolated-copy acceptance.

    This does not trust a generic target for normal authoring.  It preserves
    the original HCB-only acceptance route, while ``portrait_mode`` narrows the
    same reversible experiment to one exact-profile portrait plus an
    append-only target portrait-archive body/face pair.
    """

    from .visual_scene_project import VisualSceneProjectError, buildable_story_scenes

    issues: list[str] = []
    if duration_ms != 0:
        issues.append("背景转场必须为 0 ms")
    if document.path is None:
        issues.append("运行 HCB 没有可核对的磁盘文件名")
        return issues
    source_path = document.path.expanduser().resolve()
    try:
        game_root = Path(str(discovery.get("game_dir") or "")).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        game_root = Path()
    if not game_root.is_dir() or source_path.parent != game_root:
        issues.append("运行 HCB 与原生目标目录不一致")

    hcb = discovery.get("hcb") if isinstance(discovery.get("hcb"), Mapping) else {}
    runtime = (
        hcb.get("runtime_resolution")
        if isinstance(hcb.get("runtime_resolution"), Mapping)
        else {}
    )
    active_name = str(runtime.get("active_candidate") or "").strip()
    if not active_name or active_name.casefold() != source_path.name.casefold():
        issues.append("发现报告没有把当前文件锁定为运行活动 HCB")
    candidates = hcb.get("candidates") if isinstance(hcb.get("candidates"), list) else []
    active_record = next(
        (
            item
            for item in candidates
            if isinstance(item, Mapping)
            and str(item.get("name") or "").casefold() == source_path.name.casefold()
        ),
        None,
    )
    if not isinstance(active_record, Mapping) or str(
        active_record.get("sha256") or ""
    ).casefold() != document.source_sha256.casefold():
        issues.append("运行活动 HCB 的发现哈希与当前来源不一致")

    context_report = (
        native_context.report
        if isinstance(getattr(native_context, "report", None), Mapping)
        else {}
    )
    if str(context_report.get("analysis_mode") or "") not in {
        "linear",
        "generic_hidden_overlay_memory",
    }:
        issues.append("运行/分析 HCB 内存桥未通过")
    try:
        scenes = buildable_story_scenes(story)
    except VisualSceneProjectError as exc:
        issues.append(str(exc))
        return issues
    if len(scenes) != 1:
        issues.append("首轮实机验收必须恰好包含 1 个完整场景")
    for scene in scenes:
        anchor = scene.get("anchor") if isinstance(scene.get("anchor"), Mapping) else {}
        if anchor.get("safe") is not True:
            issues.append("剧情挂接点未通过安全校验")
        patch = anchor.get("patch") if isinstance(anchor.get("patch"), Mapping) else {}
        if not _native_acceptance_replay_patch_is_safe(
            patch,
            document.original_bytes,
        ):
            issues.append("剧情挂接点不是可验证的五字节重放跳板")
        if str(anchor.get("source_sha256") or "").casefold() != document.source_sha256.casefold():
            issues.append("剧情挂接点不属于当前运行 HCB")
        cue = scene.get("cue") if isinstance(scene.get("cue"), Mapping) else {}
        background = (
            cue.get("background")
            if isinstance(cue.get("background"), Mapping)
            else None
        )
        if not isinstance(background, Mapping) and not portrait_mode:
            issues.append("实机验收场景必须使用一个本作背景")
        elif isinstance(background, Mapping) and not portrait_mode:
            if str(background.get("build_mode") or "").strip().casefold() != "direct_reference":
                issues.append("实机验收背景必须为本作原生直引")
            project_dir = str(background.get("project_dir") or "").strip()
            if project_dir:
                try:
                    if Path(project_dir).expanduser().resolve() != game_root:
                        issues.append("实机验收背景不属于当前目标游戏")
                except (OSError, RuntimeError, TypeError, ValueError):
                    issues.append("实机验收背景目录无效")
        if isinstance(cue.get("event_visual"), Mapping):
            issues.append("首轮实机验收不允许 CG")
        actors = cue.get("actors") if isinstance(cue.get("actors"), list) else []
        visible_actors = [
            actor
            for actor in actors
            if isinstance(actor, Mapping) and bool(actor.get("visible", True))
        ]
        if portrait_mode:
            if len(actors) != 1 or len(visible_actors) != 1:
                issues.append("原生立绘验收必须恰好包含 1 个可见角色")
        elif actors:
            issues.append("HCB-only 实机验收不允许携带舞台角色")
        if not _native_acceptance_audio_is_noop(cue.get("audio")):
            issues.append("首轮实机验收不允许 BGM/SE 变更")
        lines = (
            scene.get("inserted_lines")
            if isinstance(scene.get("inserted_lines"), list)
            else []
        )
        if not lines:
            issues.append("实机验收必须新增至少 1 句测试台词")
        for line in lines:
            if not isinstance(line, Mapping):
                issues.append("新增台词格式无效")
                continue
            if line.get("compile_ready") is not True:
                issues.append("新增台词没有通过当前目标说话人编译门禁")
            if line.get("voice_id") not in (None, ""):
                issues.append("首轮实机验收台词不能携带语音 ID")

    if not portrait_mode:
        native_candidate = (
            candidate_report.get("native_target_candidate")
            if isinstance(candidate_report.get("native_target_candidate"), Mapping)
            else {}
        )
        native_output = (
            native_candidate.get("output")
            if isinstance(native_candidate.get("output"), Mapping)
            else {}
        )
        try:
            resource_count = int(native_output.get("resource_archive_count") or 0)
            portrait_resource_count = int(
                native_output.get("portrait_resource_count") or 0
            )
        except (TypeError, ValueError):
            resource_count = -1
            portrait_resource_count = -1
        if resource_count != 0 or portrait_resource_count != 0:
            issues.append("HCB-only 实机验收候选不得输出资源归档")
        return list(dict.fromkeys(issues))

    background_report = (
        candidate_report.get("background")
        if isinstance(candidate_report.get("background"), Mapping)
        else {}
    )
    background_mode = str(
        background_report.get("build_mode") or ""
    ).strip().casefold()
    if background_mode == "inherit_current":
        if not (
            background_report.get("inherited") is True
            and background_report.get("emitted") is False
            and int(background_report.get("byte_count") or 0) == 0
            and background_report.get("dissolve") is None
            and background_report.get("dissolve_target") is None
        ):
            issues.append("继承当前背景的候选意外发射了背景或转场字节")
    elif background_mode == "generic_native_background":
        backend = getattr(getattr(native_context, "abi", None), "native_background_backend", None)
        try:
            if backend is None:
                raise HcbError("当前目标缺少已绑定的背景后端")
            expected_background = backend.compile_load(
                document,
                resource_name=str(background_report.get("resource_name") or ""),
                archive_name=str(background_report.get("archive_name") or ""),
                blur_resource_name=background_report.get("runtime_blur_resource_name"),
                duration_ms=duration_ms,
            )
            if dict(expected_background.report) != background_report.get("generic_background"):
                raise HcbError("候选背景调用与当前目标的原生调用链不同")
        except HcbError as exc:
            issues.append(f"原生背景调用核对失败: {exc}")
    elif background_mode not in {"direct_reference", "generic_direct_reference"}:
        issues.append("原生立绘验收没有形成可审计的背景策略")

    portrait_plan = candidate_report.get("native_portrait_plan")
    if (
        not isinstance(portrait_plan, Mapping)
        or str(portrait_plan.get("mode") or "") != "exact_target_emission"
        or int(portrait_plan.get("visible_actor_snapshot_count") or 0) != 1
    ):
        issues.append("候选没有形成单角色精确目标发射计划")
    portrait_profile = (
        candidate_report.get("native_portrait_acceptance_profile")
        if isinstance(
            candidate_report.get("native_portrait_acceptance_profile"),
            Mapping,
        )
        else {}
    )
    if str(portrait_profile.get("target_id") or "") != str(
        discovery.get("target_id") or ""
    ):
        issues.append("立绘验收 profile 不属于当前原生目标")
    if str(portrait_profile.get("source_hcb_sha256") or "").casefold() != document.source_sha256.casefold():
        issues.append("立绘验收 profile 的活动 HCB 身份不一致")
    carrier = (
        portrait_profile.get("carrier")
        if isinstance(portrait_profile.get("carrier"), Mapping)
        else {}
    )
    try:
        carrier_selector = int(carrier.get("selector"))
        primitive_ids = [int(value) for value in carrier.get("primitive_ids", [])]
    except (TypeError, ValueError):
        carrier_selector = -1
        primitive_ids = []
    if carrier_selector < 0 or len(primitive_ids) != 2 or len(set(primitive_ids)) != 2:
        issues.append("立绘验收 profile 缺少唯一 selector/primitive 对")

    portraits = (
        candidate_report.get("portraits")
        if isinstance(candidate_report.get("portraits"), Mapping)
        else {}
    )
    if (
        int(portraits.get("visible_actor_count") or 0) != 1
        or portraits.get("actors_emitted") is not True
    ):
        issues.append("候选没有实际发射单个可见角色")
    emitter = (
        portraits.get("emitter_validation")
        if isinstance(portraits.get("emitter_validation"), Mapping)
        else {}
    )
    graph_validation = (
        emitter.get("graph_bs")
        if isinstance(emitter.get("graph_bs"), Mapping)
        else {}
    )
    added = graph_validation.get("added")
    if (
        emitter.get("passed") is not True
        or not isinstance(added, list)
        or len(added) != 2
        or int(graph_validation.get("final_entry_count") or 0)
        != int(graph_validation.get("original_entry_count") or -2) + 2
    ):
        issues.append("graph_bs 没有通过仅追加身体/表情两层的验证")
    else:
        kinds = sorted(
            int(item.get("hzc", {}).get("kind", -1))
            for item in added
            if isinstance(item, Mapping)
            and isinstance(item.get("hzc"), Mapping)
        )
        if kinds != [1, 2]:
            issues.append("graph_bs 新增资源不是身体 kind=1 + 表情 kind=2")
    hook = (
        candidate_report.get("hook")
        if isinstance(candidate_report.get("hook"), Mapping)
        else {}
    )
    cleanup = (
        hook.get("lifecycle_cleanup")
        if isinstance(hook.get("lifecycle_cleanup"), Mapping)
        else {}
    )
    try:
        cleanup_selectors = [int(value) for value in cleanup.get("selectors", [])]
    except (TypeError, ValueError):
        cleanup_selectors = []
    if cleanup_selectors != [carrier_selector] or int(cleanup.get("byte_count") or 0) < 1:
        issues.append("候选没有在已证明的原生边界交还本次 selector")
    profile_state = (
        portrait_profile.get("state_isolation")
        if isinstance(portrait_profile.get("state_isolation"), Mapping)
        else {}
    )
    hook_state = (
        hook.get("portrait_state_isolation")
        if isinstance(hook.get("portrait_state_isolation"), Mapping)
        else {}
    )
    cleanup_state = (
        cleanup.get("state_restore_before_replay")
        if isinstance(cleanup.get("state_restore_before_replay"), Mapping)
        else {}
    )
    cleanup_rearm = (
        cleanup.get("cache_rearm_before_native_replay")
        if isinstance(cleanup.get("cache_rearm_before_native_replay"), Mapping)
        else {}
    )
    restored_handoff = (
        cleanup.get("restored_layout_apply_before_replay")
        if isinstance(cleanup.get("restored_layout_apply_before_replay"), Mapping)
        else {}
    )
    profile_lifecycle = (
        portrait_profile.get("lifecycle")
        if isinstance(portrait_profile.get("lifecycle"), Mapping)
        else {}
    )
    profile_preclear = (
        profile_lifecycle.get("pre_scene_clear")
        if isinstance(profile_lifecycle.get("pre_scene_clear"), Mapping)
        else {}
    )
    hook_preclear = (
        hook.get("portrait_pre_scene_clear")
        if isinstance(hook.get("portrait_pre_scene_clear"), Mapping)
        else {}
    )
    output = (
        candidate_report.get("output")
        if isinstance(candidate_report.get("output"), Mapping)
        else {}
    )
    try:
        profile_state_selector = int(profile_state.get("selector"))
        profile_globals = [int(value) for value in profile_state.get("global_ids", [])]
        profile_cache_global = int(profile_state.get("cache_global_id"))
        hook_state_selector = int(hook_state.get("selector"))
        hook_globals = [int(value) for value in hook_state.get("source_global_ids", [])]
        stack_value_count = int(hook_state.get("stack_value_count"))
        snapshot_byte_count = int(hook_state.get("snapshot_byte_count"))
        restore_byte_count = int(hook_state.get("restore_byte_count"))
        cache_rearm_byte_count = int(hook_state.get("cache_rearm_byte_count"))
        cleanup_state_selector = int(cleanup_state.get("selector"))
        cleanup_cache_global = int(cleanup_state.get("cache_global_id"))
        cleanup_rearm_selector = int(cleanup_rearm.get("selector"))
        cleanup_rearm_cache_global = int(cleanup_rearm.get("cache_global_id"))
        cleanup_rearm_byte_count = int(cleanup_rearm.get("byte_count"))
        profile_preclear_selector = int(profile_preclear.get("selector"))
        profile_preclear_count = int(profile_preclear.get("source_sequence_count"))
        hook_preclear_selector = int(hook_preclear.get("selector"))
        hook_preclear_count = int(hook_preclear.get("source_sequence_count"))
        hook_preclear_byte_count = int(hook_preclear.get("byte_count"))
        output_preclear_byte_count = int(output.get("portrait_pre_scene_clear_bytes"))
        apply_argument_count = int(
            profile_lifecycle.get("apply_argument_count", 3)
        )
    except (TypeError, ValueError):
        profile_state_selector = hook_state_selector = cleanup_state_selector = -1
        cleanup_rearm_selector = -1
        profile_preclear_selector = hook_preclear_selector = -1
        profile_preclear_count = hook_preclear_count = -1
        hook_preclear_byte_count = output_preclear_byte_count = -1
        apply_argument_count = -1
        profile_cache_global = cleanup_cache_global = -1
        cleanup_rearm_cache_global = -1
        profile_globals = []
        hook_globals = []
        stack_value_count = snapshot_byte_count = restore_byte_count = -1
        cache_rearm_byte_count = cleanup_rearm_byte_count = -1
    cleanup_handoff_safe = _native_portrait_cleanup_handoff_is_safe(
        cleanup,
        profile_lifecycle,
    )
    state_isolated = (
        profile_state_selector == carrier_selector
        and hook_state_selector == carrier_selector
        and cleanup_state_selector == carrier_selector
        and cleanup_rearm_selector == carrier_selector
        and profile_globals
        and profile_globals == hook_globals
        and profile_globals == sorted(set(profile_globals))
        and profile_cache_global in profile_globals
        and cleanup_cache_global == profile_cache_global
        and cleanup_rearm_cache_global == profile_cache_global
        and profile_state.get("scratch_allocation") == "vm_operand_stack"
        and hook_state.get("scratch_allocation") == "vm_operand_stack"
        and profile_state.get("strategy")
        == "snapshot_on_operand_stack_restore_before_original_replay"
        and hook_state.get("strategy")
        == "snapshot_on_operand_stack_restore_before_original_replay"
        and profile_state.get("cache_rearm")
        == "set_nil_at_cleanup_before_native_replay"
        and hook_state.get("cache_rearm")
        == "set_nil_at_cleanup_before_native_replay"
        and stack_value_count == len(profile_globals)
        and hook_state.get("header_unchanged") is True
        and snapshot_byte_count == len(profile_globals) * 3
        and restore_byte_count == len(profile_globals) * 3
        and cache_rearm_byte_count == 4
        and len(str(hook_state.get("snapshot_sha256") or "")) == 64
        and len(str(hook_state.get("restore_sha256") or "")) == 64
        and hook_state.get("restore_placement")
        == "after_custom_scene_before_original_replay"
        and cleanup_state.get("enabled") is False
        and cleanup_state.get("placement")
        == "scene_trampoline_before_original_replay"
        and cleanup_rearm.get("enabled") is True
        and cleanup_rearm_byte_count == 4
        and cleanup_handoff_safe
        and profile_preclear_selector == carrier_selector
        and hook_preclear_selector == carrier_selector
        and profile_preclear_count >= 1
        and hook_preclear_count == profile_preclear_count
        and hook_preclear.get("passed") is True
        and hook_preclear.get("strategy")
        == "clear_then_nil_apply_before_visual"
        and hook_preclear.get("placement")
        == "after_state_snapshot_before_audio_and_visual"
        and apply_argument_count in {2, 3}
        and profile_preclear.get("apply_argument_count", apply_argument_count)
        == apply_argument_count
        and hook_preclear.get("apply_argument_count") == apply_argument_count
        and profile_preclear.get("apply_arguments")
        == [None] * apply_argument_count
        and hook_preclear.get("apply_arguments")
        == [None] * apply_argument_count
        and hook_preclear_byte_count == 13 + apply_argument_count
        and output_preclear_byte_count == 13 + apply_argument_count
    )
    if not state_isolated:
        state_diagnostic = {
            "carrier_selector": carrier_selector,
            "profile_selector": profile_state_selector,
            "hook_selector": hook_state_selector,
            "cleanup_selector": cleanup_state_selector,
            "rearm_selector": cleanup_rearm_selector,
            "profile_globals": profile_globals,
            "hook_globals": hook_globals,
            "profile_cache_global": profile_cache_global,
            "cleanup_cache_global": cleanup_cache_global,
            "rearm_cache_global": cleanup_rearm_cache_global,
            "stack_value_count": stack_value_count,
            "snapshot_byte_count": snapshot_byte_count,
            "restore_byte_count": restore_byte_count,
            "cache_rearm_byte_count": cache_rearm_byte_count,
            "cleanup_rearm_byte_count": cleanup_rearm_byte_count,
            "cleanup_state_enabled": cleanup_state.get("enabled"),
            "cleanup_state_placement": cleanup_state.get("placement"),
            "cleanup_rearm_enabled": cleanup_rearm.get("enabled"),
            "clear_performed": (
                cleanup.get("clear", {}).get("performed")
                if isinstance(cleanup.get("clear"), Mapping)
                else None
            ),
            "restored_handoff_enabled": restored_handoff.get("enabled"),
            "cleanup_kind": cleanup.get("kind"),
            "cleanup_replayed_target": cleanup.get("replayed_target"),
            "profile_clear_target": profile_lifecycle.get("clear_target"),
            "profile_apply_target": profile_lifecycle.get("apply_target"),
            "cleanup_handoff_safe": cleanup_handoff_safe,
            "explicit_apply_reason": cleanup.get("explicit_apply_reason"),
            "profile_preclear_count": profile_preclear_count,
            "hook_preclear_count": hook_preclear_count,
            "hook_preclear_bytes": hook_preclear_byte_count,
            "output_preclear_bytes": output_preclear_byte_count,
        }
        issues.append(
            "候选没有通过 VM 操作数栈隔离并恢复原生 selector 状态："
            + json.dumps(
                state_diagnostic,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    native_candidate = (
        candidate_report.get("native_target_candidate")
        if isinstance(candidate_report.get("native_target_candidate"), Mapping)
        else {}
    )
    native_output = (
        native_candidate.get("output")
        if isinstance(native_candidate.get("output"), Mapping)
        else {}
    )
    portrait_acceptance_profile = (
        candidate_report.get("native_portrait_acceptance_profile")
        if isinstance(
            candidate_report.get("native_portrait_acceptance_profile"), Mapping
        )
        else {}
    )
    expected_portrait_archive = str(
        portrait_acceptance_profile.get("resource_archive_name") or ""
    ).strip().casefold()
    resource_outputs = native_output.get("resource_archives")
    if (
        expected_portrait_archive not in {"graph.bin", "graph_bs.bin"}
        or
        int(native_output.get("resource_archive_count") or 0) != 1
        or not isinstance(resource_outputs, Mapping)
        or set(str(name).casefold() for name in resource_outputs)
        != {expected_portrait_archive}
        or int(native_output.get("portrait_resource_count") or 0) != 2
        or native_output.get("portrait_hcb_emission_ready") is not True
    ):
        issues.append("实机验收候选资源范围不是唯一目标角色归档身体/表情追加")
    return list(dict.fromkeys(issues))


def _parse_offset(value: str | int | None) -> int:
    if value is None:
        raise HcbError("缺少 offset")
    if isinstance(value, int):
        return value
    value = str(value).strip()
    try:
        return int(value, 0)
    except ValueError as exc:
        raise HcbError(f"无效偏移: {value}") from exc


def build_rewind_target(document: HcbDocument, offset: int, profile: Any = None) -> dict[str, Any]:
    """Describe one RFVP semantic checkpoint without emitting raw jump bytecode.

    RFVP stores checkpoints by the exact HCB ``push_string`` content address.
    The editor cannot know whether a running process has already captured that
    checkpoint, so the response deliberately separates static eligibility from
    runtime capture. This endpoint is metadata only; it never patches HCB.
    """

    index, item = document.find_with_index(int(offset))
    target: dict[str, Any] = {
        "kind": "rfvp_checkpoint",
        "selection_rule": "exact_hcb_content_offset",
        "hcb_offset": item.offset,
        "offset_hex": f"0x{item.offset:X}",
        "instruction_index": index,
        "mnemonic": item.mnemonic,
        "content": item.text if item.opcode == 0x0E else None,
        "name": "",
        "dialogue": None,
        "profile_linked": False,
        "voice_links": [],
        "visual_links": [],
        "static_status": "not_push_string",
        "runtime_status": "not_captured",
        "runtime_capture_required": True,
        "runtime_ambiguity_policy": "reject_ambiguous_offset",
        "source_sha256": document.source_sha256,
        "safe": False,
        "reasons": [],
    }
    if item.opcode != 0x0E:
        target["reasons"] = ["selected instruction is not a push_string dialogue content"]
        return target

    target["static_status"] = "eligible"
    profile_record = profile.record_for_offset(item.offset) if profile is not None else None
    if profile_record is not None:
        target["profile_linked"] = True
        target["dialogue"] = bool(profile_record.get("dialogue"))
        target["name"] = str(profile_record.get("name") or profile_record.get("raw_name") or "")
        target["voice_links"] = list(profile_record.get("voice_links") or [])
        target["visual_links"] = list(profile_record.get("visual_links") or [])
        if not target["dialogue"]:
            target["static_status"] = "not_dialogue"
            target["reasons"] = ["profile marks this string as non-dialogue"]
            return target
    else:
        target["static_status"] = "requires_profile_confirmation"
        target["reasons"] = ["profile is not linked; load a dialogue index before exporting a safe target"]
        target["static_occurrence_count"] = None
        return target

    # Route-level duplicates can only be observed by RFVP. RFVP rejects an
    # ambiguous match instead of guessing which occurrence the user intended.
    if profile is not None:
        occurrences = sum(
            1 for record in getattr(profile, "records", ()) if record.get("slot_offset") == item.offset
        )
        target["static_occurrence_count"] = occurrences
        if occurrences > 1:
            target["static_status"] = "ambiguous_static_offset"
            target["reasons"] = ["profile contains more than one record at this HCB offset"]
            return target
    target["safe"] = True
    return target


def _resolve_jump_target(document: HcbDocument, value: Any, labels: dict[str, int]) -> tuple[int, str | None]:
    """Resolve a numeric offset or a session-local jump label."""

    if isinstance(value, str):
        raw = value.strip()
        if raw in labels:
            return int(labels[raw]), raw
        try:
            return _parse_offset(raw), None
        except HcbError as exc:
            raise HcbError(f"未知跳转标签或偏移: {raw}") from exc
    return _parse_offset(value), None


def select_install_hcb(
    target: Path,
    *,
    source_path: Path | None,
    recipe_id: str,
    requested_name: str = "",
) -> tuple[Path, list[str]]:
    """Choose the HCB that a jump recipe will overwrite in a test copy.

    Hoshimemo's Chinese launcher prefers the hidden ``.Hoshimemo_HD.hcb``
    overlay.  The editor often indexes the visible Japanese HCB, so deriving
    the destination solely from the opened source file is unsafe.  An
    explicitly supplied name remains authoritative for advanced users.
    """

    candidates = sorted(
        (item for item in target.iterdir() if item.is_file() and item.suffix.casefold() == ".hcb"),
        key=lambda item: item.name.casefold(),
    )
    candidate_names = [item.name for item in candidates]
    name = str(requested_name or "").strip()
    if not name:
        hidden_hoshimemo = next(
            (item for item in candidates if item.name.casefold() == ".hoshimemo_hd.hcb"),
            None,
        )
        if hidden_hoshimemo is not None and str(recipe_id).casefold().startswith("hoshimemo."):
            name = hidden_hoshimemo.name
        elif source_path is not None:
            name = source_path.name
        elif hidden_hoshimemo is not None:
            name = hidden_hoshimemo.name
        else:
            name = ".Hoshimemo_HD.hcb"
    if Path(name).name != name:
        raise HcbError("hcb_name 必须是文件名")
    destination = target / name
    if not destination.is_file():
        raise HcbError(
            f"测试副本中找不到目标 HCB: {destination.name}；候选文件: "
            f"{', '.join(candidate_names) or '<none>'}"
        )
    return destination, candidate_names


def _require_installable_jump_recipe(recipe: dict[str, Any], document: HcbDocument) -> None:
    """Reject recipes that do not prove a complete, runtime-tested state."""

    if not recipe.get("installable"):
        missing = ", ".join(recipe.get("missing_requirements", [])) or "runtime verification"
        raise HcbError(
            "该跳转尚未满足完整状态契约，禁止应用或安装；"
            f"缺少：{missing}"
        )
    source_hashes = {str(value).casefold() for value in recipe.get("source_sha256", [])}
    if not source_hashes or document.source_sha256.casefold() not in source_hashes:
        raise HcbError(
            "当前 HCB 不属于该跳转已验证的源版本；"
            f"当前 SHA-256：{document.source_sha256}"
        )


def _apply_jump_recipe_patch(
    document: HcbDocument,
    recipe_id: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    expected = bytes.fromhex(str(item["expected_hex"]))
    note = str(item.get("note", "")).strip() or f"recipe:{recipe_id}"
    if str(item.get("patch_type", "jump")).casefold() == "bytes":
        patch = document.patch_bytes_in_place(
            int(item["offset"]),
            expected,
            bytes.fromhex(str(item["replacement_hex"])),
            note=note,
        )
    else:
        patch = document.patch_jump_in_place(
            int(item["offset"]),
            int(item["target"]),
            expected,
            conditional=str(item.get("kind", "always")).casefold() in {"zero", "jz", "0x07"},
            note=note,
        )
    return patch.to_json()


def _verify_jump_recipe_result(recipe: dict[str, Any], built: bytes) -> str:
    expected = str(recipe.get("result_sha256", "")).strip().casefold()
    actual = hashlib.sha256(built).hexdigest()
    if not expected or actual != expected:
        raise HcbError(
            "跳转配方生成结果没有通过已验证哈希；"
            f"expected={expected or '<missing>'}, actual={actual}"
        )
    return actual


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def validate_plan_hcb_binding(plan: dict[str, Any], document: HcbDocument) -> None:
    """Reject a plan loaded from a different HCB before any edit/build."""

    source_value = plan.get("hcb")
    if not source_value or document.path is None:
        return
    try:
        source = Path(str(source_value)).expanduser().resolve()
        current = document.path.expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HcbError(f"无法解析替换计划的 HCB 来源: {source_value}") from exc
    if source != current:
        raise HcbError(
            "替换计划来自另一份 HCB，已拒绝应用；"
            f"计划来源={source}，当前文件={current}"
        )


class Handler(BaseHTTPRequestHandler):
    server_version = "FVPStudio/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the terminal useful while avoiding noisy default timestamps.
        print(f"[FVP Studio V2] {format % args}")

    @property
    def api_path(self) -> str:
        return urlparse(self.path).path

    def _send_json(self, value: Any, status: int = HTTPStatus.OK) -> None:
        payload = _json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        # The editor is a local, request/response UI.  Explicitly close each
        # response so a cancelled preview or a stale browser tab cannot leave
        # an idle connection occupying a ThreadingHTTPServer worker forever.
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(payload)))
        try:
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            # Switching resources intentionally cancels the previous image
            # request.  A disconnected browser is not a preview failure.
            return

    def _send_error(self, message: str, status: int = HTTPStatus.BAD_REQUEST) -> None:
        SESSION.last_error = message
        self._send_json({"ok": False, "error": message}, status)

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 8 * 1024 * 1024:
                raise HcbError("请求体过大")
            raw = self.rfile.read(length)
            value = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HcbError("请求不是有效的 UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise HcbError("JSON 请求必须是对象")
        return value

    def _read_bytes(self, maximum: int) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise HcbError("Content-Length 无效") from exc
        if length <= 0:
            raise HcbError("上传文件为空")
        if length > int(maximum):
            raise HcbError(f"上传文件超过 {int(maximum) // (1024 * 1024)} MiB 上限")
        payload = self.rfile.read(length)
        if len(payload) != length:
            raise HcbError("上传文件读取不完整")
        return payload

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/api/health":
                self._send_json({"ok": True, "version": "0.1"})
                return
            if parsed.path == "/api/status":
                self._send_json({"ok": True, **SESSION.status()})
                return
            if parsed.path == "/api/events":
                self._events(parse_qs(parsed.query))
                return
            if parsed.path == "/api/functions":
                self._functions(parse_qs(parsed.query))
                return
            if parsed.path == "/api/flow":
                self._flow(parse_qs(parsed.query))
                return
            if parsed.path == "/api/jump-labels":
                self._jump_labels()
                return
            if parsed.path == "/api/instruction":
                self._instruction(parse_qs(parsed.query))
                return
            if parsed.path == "/api/rewind-target":
                self._rewind_target(parse_qs(parsed.query))
                return
            if parsed.path == "/api/header":
                self._header()
                return
            if parsed.path == "/api/profile/status":
                self._profile_status()
                return
            if parsed.path == "/api/v2/native-target/status":
                self._native_target_status()
                return
            if parsed.path == "/api/v2/native-target/profile-template":
                self._native_target_profile_template()
                return
            if parsed.path == "/api/v2/portrait/status":
                self._portrait_v2_status()
                return
            if parsed.path == "/api/v2/portrait/scene":
                self._portrait_v2_scene_status()
                return
            if parsed.path == "/api/v2/portrait/source/status":
                self._portrait_v2_source_status()
                return
            if parsed.path == "/api/v2/portrait/source/preview":
                self._portrait_v2_source_preview(parse_qs(parsed.query))
                return
            if parsed.path == "/api/v2/portrait/source/composite":
                self._portrait_v2_source_composite(parse_qs(parsed.query))
                return
            if parsed.path == "/api/v2/background/source/status":
                self._background_v2_source_status()
                return
            if parsed.path == "/api/v2/background/preview":
                self._background_v2_preview(parse_qs(parsed.query))
                return
            if parsed.path == "/api/v2/cg/source/status":
                self._cg_v2_source_status()
                return
            if parsed.path == "/api/v2/cg/preview":
                self._cg_v2_preview(parse_qs(parsed.query))
                return
            if parsed.path == "/api/v2/audio/source/status":
                self._audio_v2_source_status()
                return
            if parsed.path == "/api/v2/audio/preview":
                self._audio_v2_preview(parse_qs(parsed.query))
                return
            if parsed.path == "/api/v2/scene/status":
                self._visual_scene_status()
                return
            if parsed.path == "/api/v2/scene/dialogues":
                self._visual_scene_dialogues(parse_qs(parsed.query))
                return
            if parsed.path == "/api/v2/scene/speakers":
                self._visual_scene_speakers()
                return
            if parsed.path == "/api/v2/scene/backlog/avatar":
                self._visual_scene_backlog_avatar(parse_qs(parsed.query))
                return
            if parsed.path == "/api/v2/scene/candidate/download":
                self._visual_scene_candidate_download()
                return
            if parsed.path == "/api/texts":
                self._texts(parse_qs(parsed.query))
                return
            if parsed.path == "/api/assets":
                self._assets(parse_qs(parsed.query))
                return
            if parsed.path == "/api/asset-preview":
                self._asset_preview(parse_qs(parsed.query))
                return
            if parsed.path == "/api/asset-info":
                self._asset_info(parse_qs(parsed.query))
                return
            if parsed.path == "/api/audio-preview":
                self._audio_preview(parse_qs(parsed.query))
                return
            if parsed.path == "/api/links":
                self._links(parse_qs(parsed.query))
                return
            if parsed.path == "/api/jump-recipes":
                self._jump_recipes(parse_qs(parsed.query))
                return
            if parsed.path == "/api/plan":
                self._plan_status()
                return
            if parsed.path == "/api/runner/status":
                self._runner_status()
                return
            self._static(parsed.path)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return
        except HcbError as exc:
            self._send_error(str(exc))
        except Exception as exc:  # keep the local UI alive after a bad request
            self._send_error(f"内部错误: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            if self.api_path == "/api/open":
                self._open(self._read_json())
            elif self.api_path == "/api/profile/open":
                self._profile_open(self._read_json())
            elif self.api_path == "/api/profile/scan":
                self._profile_scan(self._read_json())
            elif self.api_path == "/api/v2/native-target/discover":
                self._native_target_discover(self._read_json())
            elif self.api_path == "/api/v2/native-target/profile/review":
                self._native_target_profile_review(self._read_json())
            elif self.api_path == "/api/v2/portrait/analyse":
                self._portrait_v2_analyse(self._read_json())
            elif self.api_path == "/api/v2/portrait/clear":
                self._portrait_v2_clear()
            elif self.api_path == "/api/v2/portrait/scene/add":
                self._portrait_v2_scene_add(self._read_json())
            elif self.api_path == "/api/v2/portrait/scene/select":
                self._portrait_v2_scene_select(self._read_json())
            elif self.api_path == "/api/v2/portrait/scene/update":
                self._portrait_v2_scene_update(self._read_json())
            elif self.api_path == "/api/v2/portrait/scene/reorder":
                self._portrait_v2_scene_reorder(self._read_json())
            elif self.api_path == "/api/v2/portrait/scene/remove":
                self._portrait_v2_scene_remove(self._read_json())
            elif self.api_path == "/api/v2/portrait/source/open":
                self._portrait_v2_source_open(self._read_json())
            elif self.api_path == "/api/v2/portrait/source/clear":
                self._portrait_v2_source_clear()
            elif self.api_path == "/api/v2/background/source/open":
                self._background_v2_source_open(self._read_json())
            elif self.api_path == "/api/v2/background/source/clear":
                self._background_v2_source_clear()
            elif self.api_path == "/api/v2/background/scene/set":
                self._background_v2_scene_set(self._read_json())
            elif self.api_path == "/api/v2/background/scene/fit":
                self._background_v2_scene_fit(self._read_json())
            elif self.api_path == "/api/v2/background/scene/clear":
                self._background_v2_scene_clear()
            elif self.api_path == "/api/v2/cg/source/open":
                self._cg_v2_source_open(self._read_json())
            elif self.api_path == "/api/v2/cg/source/clear":
                self._cg_v2_source_clear()
            elif self.api_path == "/api/v2/cg/scene/set":
                self._cg_v2_scene_set(self._read_json())
            elif self.api_path == "/api/v2/cg/scene/update":
                self._cg_v2_scene_update(self._read_json())
            elif self.api_path == "/api/v2/cg/scene/clear":
                self._cg_v2_scene_clear()
            elif self.api_path == "/api/v2/audio/project/import":
                from .audio_project import PROJECT_AUDIO_MAX_BYTES

                self._audio_v2_project_import(
                    parse_qs(urlparse(self.path).query),
                    self._read_bytes(PROJECT_AUDIO_MAX_BYTES),
                )
            elif self.api_path == "/api/v2/audio/source/open":
                self._audio_v2_source_open(self._read_json())
            elif self.api_path == "/api/v2/audio/source/clear":
                self._audio_v2_source_clear()
            elif self.api_path == "/api/v2/audio/scene/update":
                self._audio_v2_scene_update(self._read_json())
            elif self.api_path == "/api/v2/scene/project/add":
                self._visual_scene_project_add(self._read_json())
            elif self.api_path == "/api/v2/scene/project/select":
                self._visual_scene_project_select(self._read_json())
            elif self.api_path == "/api/v2/scene/project/rename":
                self._visual_scene_project_rename(self._read_json())
            elif self.api_path == "/api/v2/scene/project/move":
                self._visual_scene_project_move(self._read_json())
            elif self.api_path == "/api/v2/scene/project/remove":
                self._visual_scene_project_remove(self._read_json())
            elif self.api_path == "/api/v2/scene/project/replace":
                self._visual_scene_project_replace(self._read_json())
            elif self.api_path == "/api/v2/scene/anchor":
                self._visual_scene_anchor(self._read_json())
            elif self.api_path == "/api/v2/scene/anchor/clear":
                self._visual_scene_anchor_clear(self._read_json())
            elif self.api_path == "/api/v2/scene/cue/capture":
                self._visual_scene_cue_capture(self._read_json())
            elif self.api_path == "/api/v2/scene/dialogue/add":
                self._visual_scene_dialogue_add(self._read_json())
            elif self.api_path == "/api/v2/scene/dialogue/remove":
                self._visual_scene_dialogue_remove(self._read_json())
            elif self.api_path == "/api/v2/scene/dialogue/clear":
                self._visual_scene_dialogue_clear(self._read_json())
            elif self.api_path == "/api/v2/scene/candidate/dry-run":
                self._visual_scene_candidate_dry_run(self._read_json())
            elif self.api_path == "/api/v2/scene/install/prepare":
                self._visual_scene_install_prepare(self._read_json())
            elif self.api_path == "/api/v2/scene/install/apply":
                self._visual_scene_install_apply(self._read_json())
            elif self.api_path == "/api/v2/scene/install/inspect":
                self._visual_scene_install_inspect(self._read_json())
            elif self.api_path == "/api/v2/scene/install/rollback":
                self._visual_scene_install_rollback(self._read_json())
            elif self.api_path == "/api/edit":
                self._edit(self._read_json())
            elif self.api_path == "/api/edit-overlay-text":
                self._edit_overlay_text(self._read_json())
            elif self.api_path == "/api/edit-overlay-text-relocate":
                self._edit_overlay_text_relocate(self._read_json())
            elif self.api_path == "/api/edit-target":
                self._edit_target(self._read_json())
            elif self.api_path == "/api/jump-label":
                self._jump_label(self._read_json())
            elif self.api_path == "/api/insert-jump":
                self._insert_jump(self._read_json())
            elif self.api_path == "/api/patch-jump-in-place":
                self._patch_jump_in_place(self._read_json())
            elif self.api_path == "/api/jump-recipe/apply":
                self._jump_recipe_apply(self._read_json())
            elif self.api_path == "/api/jump-recipe/install":
                self._jump_recipe_install(self._read_json())
            elif self.api_path == "/api/jump-recipe/rollback":
                self._jump_recipe_rollback(self._read_json())
            elif self.api_path == "/api/insert-call":
                self._insert_call(self._read_json())
            elif self.api_path == "/api/insert-raw":
                self._insert_raw(self._read_json())
            elif self.api_path == "/api/insertions/remove-last":
                self._remove_last_insertion()
            elif self.api_path == "/api/save":
                self._save(self._read_json())
            elif self.api_path == "/api/revert":
                self._revert(self._read_json())
            elif self.api_path == "/api/validate":
                self._validate(self._read_json())
            elif self.api_path == "/api/export-json":
                self._export_json(self._read_json())
            elif self.api_path == "/api/plan/add":
                self._plan_add(self._read_json())
            elif self.api_path == "/api/plan/remove":
                self._plan_remove(self._read_json())
            elif self.api_path == "/api/plan/clear":
                self._plan_clear(self._read_json())
            elif self.api_path == "/api/plan/save":
                self._plan_save(self._read_json())
            elif self.api_path == "/api/plan/load":
                self._plan_load(self._read_json())
            elif self.api_path == "/api/plan/validate":
                self._plan_validate()
            elif self.api_path == "/api/plan/apply-text":
                self._plan_apply_text()
            elif self.api_path == "/api/runner/start":
                self._runner_start(self._read_json())
            elif self.api_path == "/api/runner/stop":
                self._runner_stop()
            elif self.api_path == "/api/resource/build":
                self._resource_build(self._read_json())
            elif self.api_path == "/api/install-copy":
                self._install_copy(self._read_json())
            elif self.api_path == "/api/install-copy/rollback":
                self._rollback_copy_install(self._read_json())
            elif self.api_path == "/api/install-copy/inspect":
                self._inspect_copy_install(self._read_json())
            else:
                self._send_error("未知 API", HTTPStatus.NOT_FOUND)
        except HcbError as exc:
            self._send_error(str(exc))
        except Exception as exc:
            self._send_error(f"内部错误: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)

    def _open(self, body: dict[str, Any]) -> None:
        path_value = str(body.get("path", "")).strip()
        if not path_value:
            raise HcbError("请填写 HCB/BCH 剧情脚本路径")
        encoding = str(body.get("encoding", "sjis"))
        document = load(Path(path_value), encoding)
        SESSION.set_document(document)
        self._send_json({"ok": True, "summary": document.summary(), "compatibility": SESSION.compatibility()})

    def _profile_required(self) -> ProjectIndex:
        with SESSION.lock:
            if SESSION.profile is None:
                raise ProfileError("尚未加载项目分析索引")
            return SESSION.profile

    def _native_scene_memory_context_optional(self) -> Any | None:
        """Return the generic compile-only context for the active target.

        A registered Hoshimemo analysis index continues to use its established
        implementation.  A file-backed generic resource index, however, must
        be paired with the exact read-only native-target discovery for the
        same game root; it is never allowed to fall through to Hoshimemo ABI
        constants.
        """

        from .native_scene_candidate import (
            prepare_native_scene_memory_context_from_documents,
        )
        from .native_target_profile import build_native_target_profile_template

        with SESSION.lock:
            document = SESSION.document
            project_profile = SESSION.profile
            discovery = SESSION.native_target_discovery
            review = SESSION.native_target_profile_review
            cached = SESSION.native_scene_memory_context
            cached_key = SESSION.native_scene_memory_context_key
        if document is None or project_profile is None:
            return None
        document_path = document.path
        profile_game_dir = getattr(project_profile, "game_dir", None)
        # In-memory fixtures and hand-authored profiles retain the established
        # code path.  Real generic scans always carry both a file-backed HCB
        # and ``ProjectIndex.game_dir``.
        if document_path is None or profile_game_dir is None:
            return None
        if _trusted_hoshimemo_scene_profile(project_profile):
            return None
        try:
            game_root = document_path.expanduser().resolve().parent
            indexed_root = Path(profile_game_dir).expanduser().resolve()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HcbError(f"无法确认通用 FVP 游戏目录: {exc}") from exc
        if indexed_root != game_root:
            raise HcbError(
                "当前通用资源索引不属于已打开 HCB；请重新扫描当前游戏目录"
            )
        if not isinstance(discovery, dict):
            raise HcbError("当前通用 FVP 目标尚未完成原生函数只读分析")
        try:
            discovered_root = Path(str(discovery.get("game_dir") or "")).resolve()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HcbError(f"原生目标发现目录无效: {exc}") from exc
        if discovered_root != game_root:
            raise HcbError("原生目标发现结果不属于已打开 HCB，请重新分析当前游戏")

        target_profile = build_native_target_profile_template(discovery)
        analysis = target_profile.get("analysis_hcb")
        analysis_value = analysis if isinstance(analysis, Mapping) else {}
        analysis_name = str(analysis_value.get("name") or "").strip()
        expected_analysis_sha256 = str(
            analysis_value.get("sha256") or ""
        ).strip().casefold()
        if (
            not analysis_name
            or Path(analysis_name).name != analysis_name
            or any(separator in analysis_name for separator in ("/", "\\"))
        ):
            raise HcbError("原生目标发现结果中的分析 HCB 名称越界")
        analysis_path = game_root / analysis_name
        if analysis_path.is_symlink() or not analysis_path.is_file():
            raise HcbError(f"原生目标缺少只读分析 HCB: {analysis_path}")
        try:
            if analysis_path.resolve().parent != game_root:
                raise HcbError("原生目标分析 HCB 逃逸游戏目录")
            analysis_stat = analysis_path.stat()
        except OSError as exc:
            raise HcbError(f"无法读取原生目标分析 HCB 状态: {exc}") from exc

        discovery_sha256 = _native_discovery_cache_identity(discovery)
        review_sha256 = _stable_json_sha256(review)
        profile_sha256 = _stable_json_sha256(target_profile)
        context_key = (
            id(document),
            document.source_sha256,
            document.encoding,
            id(project_profile),
            discovery_sha256,
            profile_sha256,
            review_sha256,
            str(analysis_path.resolve()),
            int(analysis_stat.st_size),
            int(analysis_stat.st_mtime_ns),
        )
        if cached is not None and cached_key == context_key:
            return cached

        if document.source_sha256.casefold() == expected_analysis_sha256:
            if document.encoding != "shift_jis":
                raise HcbError(
                    "线性分析 HCB 必须按 Shift-JIS 打开后才能生成通用剧情候选"
                )
            analysis_document = document
        else:
            try:
                before = analysis_path.stat()
                analysis_bytes = analysis_path.read_bytes()
                after = analysis_path.stat()
            except OSError as exc:
                raise HcbError(f"无法读取只读分析 HCB: {exc}") from exc
            if (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or len(analysis_bytes) != after.st_size
            ):
                raise HcbError("读取期间分析 HCB 已变化，请重试")
            analysis_document = parse_bytes(analysis_bytes, "sjis")

        context = prepare_native_scene_memory_context_from_documents(
            document,
            analysis_document,
            discovery,
            target_profile,
            target_profile_review=review,
        )
        with SESSION.lock:
            current_discovery = SESSION.native_target_discovery
            current_review = SESSION.native_target_profile_review
            if (
                SESSION.document is not document
                or SESSION.profile is not project_profile
                or not isinstance(current_discovery, dict)
                or _native_discovery_cache_identity(current_discovery)
                != discovery_sha256
                or _stable_json_sha256(current_review) != review_sha256
            ):
                raise HcbError("构建通用剧情上下文期间目标状态已变化，请重试")
            SESSION.native_scene_memory_context = context
            SESSION.native_scene_memory_context_key = context_key
        return context

    def _profile_status(self) -> None:
        with SESSION.lock:
            self._send_json(
                {
                    "ok": True,
                    "loaded": SESSION.profile is not None,
                    "summary": SESSION.profile.summary if SESSION.profile is not None else None,
                    "default_index_dir": str(default_index_dir()),
                }
            )

    def _native_target_status(self) -> None:
        with SESSION.lock:
            report = SESSION.native_target_discovery
        self._send_json(
            {
                "ok": True,
                "loaded": report is not None,
                "discovery": report,
            }
        )

    def _native_target_discover(self, body: dict[str, Any]) -> None:
        raw = str(body.get("game_dir", "")).strip()
        if not raw:
            raise HcbError("原生目标能力分析需要 game_dir")
        from .native_target_discovery import discover_fvp_target

        game_root = Path(raw).expanduser().resolve()
        active_script_name = str(body.get("active_script_name") or "").strip()
        if not active_script_name:
            with SESSION.lock:
                document = SESSION.document
            document_path = document.path if document is not None else None
            if document_path is not None:
                resolved_document = document_path.expanduser().resolve()
                if (
                    resolved_document.parent == game_root
                    and resolved_document.suffix.casefold() in {".hcb", ".bch"}
                ):
                    active_script_name = resolved_document.name
        report = discover_fvp_target(
            game_root,
            active_script_name=active_script_name or None,
        )
        with SESSION.lock:
            SESSION.native_target_discovery = report
            SESSION.native_target_profile_review = None
            SESSION.invalidate_native_scene_memory_context()
            SESSION.last_action = (
                "已只读分析 FVP 原生目标能力 "
                f"{report.get('display_name') or report.get('game_dir')}"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "discovery": report})

    def _native_target_profile_template(self) -> None:
        from .native_target_profile import build_native_target_profile_template

        with SESSION.lock:
            discovery = SESSION.native_target_discovery
        if discovery is None:
            raise HcbError("请先只读分析一个 FVP 原生目标")
        profile = build_native_target_profile_template(discovery)
        self._send_json(
            {
                "ok": True,
                "profile": profile,
                "write_enabled": False,
            }
        )

    def _native_target_profile_review(self, body: dict[str, Any]) -> None:
        from .native_target_profile import review_native_target_profile

        profile = body.get("profile")
        if not isinstance(profile, dict):
            raise HcbError("目标 profile review 需要 profile JSON 对象")
        with SESSION.lock:
            discovery = SESSION.native_target_discovery
        if discovery is None:
            raise HcbError("请先只读分析一个 FVP 原生目标")
        review = review_native_target_profile(discovery, profile)
        with SESSION.lock:
            SESSION.native_target_profile_review = review
            SESSION.invalidate_native_scene_memory_context()
            SESSION.last_action = (
                "已只读核对 FVP 目标 profile；"
                + (
                    "候选资料完整但仍需可信注册"
                    if review.get("candidate_ready_for_registry")
                    else "仍有审核项未完成"
                )
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "review": review})

    def _profile_open(self, body: dict[str, Any]) -> None:
        raw = str(body.get("index_dir", "")).strip()
        index_dir = Path(raw).expanduser() if raw else default_index_dir()
        profile = ProjectIndex(index_dir)
        with SESSION.lock:
            from .visual_scene_project import reset_story_binding

            SESSION.profile = profile
            SESSION.invalidate_native_scene_memory_context()
            reset_story_binding(SESSION.portrait_v2_scene, preserve_lines=True)
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已加载项目索引 {profile.index_dir}"
            SESSION.last_error = None
        self._send_json({"ok": True, "summary": profile.summary})

    def _profile_scan(self, body: dict[str, Any]) -> None:
        raw = str(body.get("game_dir", "")).strip()
        if not raw:
            raise ProfileError("扫描需要 game_dir")
        profile = ProjectIndex.from_game_dir(Path(raw))
        with SESSION.lock:
            from .visual_scene_project import reset_story_binding

            SESSION.profile = profile
            SESSION.invalidate_native_scene_memory_context()
            reset_story_binding(SESSION.portrait_v2_scene, preserve_lines=True)
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已扫描通用 FVP 资源 {profile.game_dir}"
            SESSION.last_error = None
        self._send_json({"ok": True, "summary": profile.summary})

    def _edit(self, body: dict[str, Any]) -> None:
        document = SESSION.require_editable(body)
        offset = _parse_offset(body.get("offset"))
        text = body.get("text")
        if not isinstance(text, str):
            raise HcbError("text 必须是字符串")
        with SESSION.lock:
            item = document.edit_string(offset, text)
            SESSION.last_action = f"已修改 {offset:#x} 的字符串"
            SESSION.last_error = None
        self._send_json({"ok": True, "instruction": item.public(document.syscall_names), "summary": document.summary()})

    def _edit_overlay_text(self, body: dict[str, Any]) -> None:
        """Apply a fixed-width text patch to an existing push_string slot.

        This endpoint is deliberately explicit: it never invokes the linear
        HCB rebuild path and requires the UI's confirmation flag.  It is the
        safe text-edit counterpart to the fixed overlay jump workflow used by
        translated Hoshimemo files.
        """

        if body.get("confirm") is not True:
            raise HcbError("overlay text requires confirm=true")
        document = SESSION.require_document()
        offset = _parse_offset(body.get("offset"))
        text = body.get("text")
        if not isinstance(text, str):
            raise HcbError("text 必须是字符串")
        with SESSION.lock:
            patch = document.patch_text_in_place(
                offset,
                text,
                note=str(body.get("note", "")),
                expected_source_sha256=str(body.get("source_sha256", "")).strip() or None,
            )
            item = document.find(offset)
            SESSION.last_action = f"已定长覆盖 {offset:#x} 的字符串"
            SESSION.last_error = None
            summary = document.summary()
        self._send_json(
            {
                "ok": True,
                "patch": patch.to_json(),
                "instruction": item.public(document.syscall_names),
                "summary": summary,
            }
        )

    def _edit_overlay_text_relocate(self, body: dict[str, Any]) -> None:
        """Apply an overlong text replacement through an overlay trampoline."""

        if body.get("confirm") is not True:
            raise HcbError("text relocation requires confirm=true")
        document = SESSION.require_document()
        offset = _parse_offset(body.get("offset"))
        text = body.get("text")
        if not isinstance(text, str):
            raise HcbError("text must be a string")
        with SESSION.lock:
            relocation = document.patch_text_relocated(
                offset,
                text,
                note=str(body.get("note", "")),
                expected_source_sha256=str(body.get("source_sha256", "")).strip() or None,
            )
            item = document.find(offset)
            instruction = item.public(document.syscall_names)
            instruction["text"] = text
            instruction["overlay_mode"] = "relocated"
            SESSION.last_action = f"relocated variable-length text at {offset:#x}"
            SESSION.last_error = None
            summary = document.summary()
        self._send_json(
            {
                "ok": True,
                "mode": "relocated",
                "relocation": relocation.to_json(document.encoding, document.code_end),
                "instruction": instruction,
                "summary": summary,
            }
        )

    def _edit_target(self, body: dict[str, Any]) -> None:
        raise HcbError("任意目标修改已禁用；请使用通过完整状态契约的语义跳转配方")
        document = SESSION.require_editable(body)
        offset = _parse_offset(body.get("offset"))
        target = _parse_offset(body.get("target"))
        with SESSION.lock:
            item = document.edit_target(offset, target)
            SESSION.last_action = f"已修改 {offset:#x} 的跳转目标为 {target:#x}"
            SESSION.last_error = None
        self._send_json({"ok": True, "instruction": item.public(document.syscall_names), "summary": document.summary()})

    def _jump_labels(self) -> None:
        """Return symbolic jump labels kept by the current editing session."""

        with SESSION.lock:
            self._send_json(
                {
                    "ok": True,
                    "labels": {
                        name: offset for name, offset in sorted(SESSION.jump_labels.items())
                    },
                }
            )

    def _jump_label(self, body: dict[str, Any]) -> None:
        """Create or update a symbolic label at an instruction boundary."""

        document = SESSION.require_document()
        name = str(body.get("name", "")).strip()
        if not _JUMP_LABEL_RE.fullmatch(name):
            raise HcbError("标签名必须以字母或下划线开头，且只包含 ASCII 字母、数字和下划线")
        offset = _parse_offset(body.get("offset"))
        try:
            document.find(offset)
        except HcbError as exc:
            raise HcbError(f"标签位置必须是已有指令边界: 0x{offset:X}") from exc
        with SESSION.lock:
            SESSION.jump_labels[name] = offset
            SESSION.last_action = f"已设置跳转标签 {name}=0x{offset:X}"
            SESSION.last_error = None
            labels = {
                label: value for label, value in sorted(SESSION.jump_labels.items())
            }
        self._send_json({"ok": True, "name": name, "offset": offset, "labels": labels})

    def _insert_jump(self, body: dict[str, Any]) -> None:
        """Generate a relocatable 0x06/0x07 jump before an instruction.

        ``target`` accepts either an absolute HCB offset (``0x3267``) or a
        session label previously created through ``/api/jump-label``.  The
        generated block is parsed as a known instruction and therefore does
        not require the unsafe raw-bytecode rebuild switch.
        """

        raise HcbError("任意偏移跳转已禁用；请使用通过完整状态契约的语义跳转配方")
        document = SESSION.require_editable(body)
        anchor = _parse_offset(body.get("offset"))
        kind = str(body.get("kind", "always")).strip().casefold()
        if kind in {"always", "jmp", "unconditional", "0x06"}:
            conditional = False
            kind = "always"
        elif kind in {"zero", "jz", "conditional", "0x07"}:
            conditional = True
            kind = "zero"
        else:
            raise HcbError("kind 必须是 always/jmp 或 zero/jz")
        with SESSION.lock:
            target, label = _resolve_jump_target(document, body.get("target"), SESSION.jump_labels)
            target_item = document.find(target)
            target_warning: str | None = None
            if target_item.opcode == 0x01 and int(target_item.operands.get("args", 0)):
                target_warning = (
                    f"目标 0x{target:X} 的 init_stack 声明了 "
                    f"{int(target_item.operands.get('args', 0))} 个栈参数；"
                    "直接 jmp 不会自动准备参数，请优先在已有参数准备的调用点测试。"
                )
            insertion = document.insert_jump(
                anchor,
                target,
                conditional=conditional,
                note=str(body.get("note", "")),
            )
            SESSION.last_action = (
                f"已生成 {('jz' if conditional else 'jmp')} 0x{target:X}"
                f" 于 0x{anchor:X}"
            )
            SESSION.last_error = None
            summary = document.summary()
            labels = {
                name: offset for name, offset in sorted(SESSION.jump_labels.items())
            }
        self._send_json(
            {
                "ok": True,
                "insertion": insertion.to_json(),
                "anchor": anchor,
                "target": target,
                "target_label": label,
                "kind": kind,
                "warning": target_warning,
                "labels": labels,
                "summary": summary,
            }
        )

    def _patch_jump_in_place(self, body: dict[str, Any]) -> None:
        """Patch an existing five-byte instruction without relocating HCB data."""

        raise HcbError("任意 Overlay 跳转已禁用；请使用通过完整状态契约的语义跳转配方")
        if body.get("confirm") is not True:
            raise HcbError("overlay fixed jump requires confirm=true")
        document = SESSION.require_document()
        offset = _parse_offset(body.get("offset"))
        target = _parse_offset(body.get("target"))
        kind = str(body.get("kind", "always")).strip().casefold()
        if kind in {"always", "jmp", "unconditional", "0x06"}:
            conditional = False
            kind = "always"
        elif kind in {"zero", "jz", "conditional", "0x07"}:
            conditional = True
            kind = "zero"
        else:
            raise HcbError("kind must be always/jmp or zero/jz")
        raw_value = re.sub(r"[^0-9A-Fa-f]", "", str(body.get("expected_hex", "")))
        if len(raw_value) != 10:
            raise HcbError("expected_hex must contain exactly 5 bytes")
        try:
            expected = bytes.fromhex(raw_value)
        except ValueError as exc:
            raise HcbError("expected_hex contains invalid hexadecimal data") from exc
        with SESSION.lock:
            patch = document.patch_jump_in_place(
                offset,
                target,
                expected,
                conditional=conditional,
                note=str(body.get("note", "")),
                expected_source_sha256=str(body.get("source_sha256", "")).strip() or None,
            )

            SESSION.last_action = (
                f"fixed overlay {('jz' if conditional else 'jmp')} "
                f"0x{offset:X} -> 0x{target:X}"
            )
            SESSION.last_error = None
            summary = document.summary()
        self._send_json({"ok": True, "patch": patch.to_json(), "kind": kind, "summary": summary})

    def _jump_recipes(self, query: dict[str, list[str]]) -> None:
        profile = self._profile_required()
        needle = (query.get("query") or [""])[0]
        self._send_json({"ok": True, **profile.search_jump_recipes(needle)})

    def _jump_recipe_apply(self, body: dict[str, Any]) -> None:
        """Apply one audited fixed-overlay recipe without relocating HCB data."""

        document = SESSION.require_document()
        profile = self._profile_required()
        recipe_id = str(body.get("recipe_id", "")).strip()
        recipe = next((item for item in profile.jump_recipes if item.get("id") == recipe_id), None)
        if recipe is None:
            raise HcbError("未找到指定的安全跳转配方")
        if str(recipe.get("mode", "")) != "overlay_fixed":
            raise HcbError("当前配方不是固定长度 Overlay 配方")
        if body.get("confirm") is not True:
            raise HcbError("应用安全跳转配方需要 confirm=true")
        _require_installable_jump_recipe(recipe, document)
        applied: list[dict[str, Any]] = []
        with SESSION.lock:
            for item in recipe.get("patches", []):
                applied.append(_apply_jump_recipe_patch(document, recipe_id, item))
            _verify_jump_recipe_result(recipe, document.build())
            SESSION.last_action = f"已应用安全跳转配方 {recipe.get('label', recipe_id)}"
            SESSION.last_error = None
            summary = document.summary()
        self._send_json({"ok": True, "recipe": recipe, "patches": applied, "summary": summary})

    def _jump_recipe_install(self, body: dict[str, Any]) -> None:
        """Build one audited recipe and install it into a test copy atomically.

        The open document is cloned before applying the recipe, so the session
        remains unchanged.  The destination HCB is backed up first and an
        install manifest records the source hash, recipe patches and generated
        hash for rollback/audit purposes.
        """

        if body.get("confirm") is not True:
            raise HcbError("应用跳转配方到测试副本需要 confirm=true")
        target_value = str(body.get("target_dir", "")).strip()
        if not target_value:
            raise HcbError("安装跳转配方需要 target_dir")
        target = Path(target_value).expanduser().resolve()
        if not target.is_dir():
            raise HcbError(f"目标游戏目录不存在: {target}")

        with SESSION.lock:
            source_document = SESSION.require_document()
            profile = self._profile_required()
            recipe_id = str(body.get("recipe_id", "")).strip()
            recipe = next((item for item in profile.jump_recipes if item.get("id") == recipe_id), None)
            source_path = source_document.path.resolve() if source_document.path else None
            known_originals: set[Path] = set()
            if source_path is not None:
                known_originals.add(source_path.parent)
            if profile.game_dir is not None and profile.game_dir.exists():
                known_originals.add(profile.game_dir.resolve())
            if recipe is None:
                raise HcbError("未找到指定的安全跳转配方")
            if str(recipe.get("mode", "")) != "overlay_fixed":
                raise HcbError("当前配方不是固定长度 Overlay 配方")
            if any(
                target == original
                or target.is_relative_to(original)
                or original.is_relative_to(target)
                for original in known_originals
            ):
                raise HcbError("拒绝安装到已知原始游戏目录、其子目录或父目录，请先复制测试目录")

            source_sha256 = source_document.source_sha256

        destination, candidate_names = select_install_hcb(
            target,
            source_path=source_path,
            recipe_id=recipe_id,
            requested_name=str(body.get("hcb_name", "")),
        )
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_root = target / ".fvpstudio-backups" / stamp
        backup_root.mkdir(parents=True, exist_ok=True)
        backup = backup_root / "hcb" / destination.name
        backup.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_file():
            shutil.copy2(destination, backup)
        # Apply the fixed overlay to the destination bytes themselves.  A
        # visible Japanese HCB and the hidden translated HCB share these
        # audited offsets, but their remaining bytes are intentionally
        # different.  Rebuilding from the editor's source document would
        # silently replace the translated script with the Japanese one.
        target_document = parse_bytes(destination.read_bytes(), source_document.encoding, path=destination)
        patched = target_document
        _require_installable_jump_recipe(recipe, patched)
        applied: list[dict[str, Any]] = []
        for item in recipe.get("patches", []):
            applied.append(_apply_jump_recipe_patch(patched, recipe_id, item))
        generated = patched.build()
        generated_sha256 = _verify_jump_recipe_result(recipe, generated)
        target_source_sha256 = hashlib.sha256(destination.read_bytes()).hexdigest()
        staged = backup_root / "generated" / destination.name
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(generated)
        shutil.copy2(staged, destination)
        installed_sha256 = hashlib.sha256(destination.read_bytes()).hexdigest()
        if installed_sha256 != generated_sha256:
            shutil.copy2(backup, destination)
            raise HcbError("安装后的 HCB 哈希与已验证生成结果不一致，已恢复备份")
        manifest = {
            "schema": "fvp-studio-jump-install.v1",
            "target_dir": str(target),
            "source_hcb": str(source_path) if source_path is not None else None,
            "source_sha256": source_sha256,
            "target_candidates": candidate_names,
            "target_hcb_name": destination.name,
            "target_source_sha256": target_source_sha256,
            "recipe": recipe,
            "patches": applied,
            "hcb": {
                "destination": str(destination),
                "backup": str(backup) if backup.is_file() else None,
                "backup_sha256": hashlib.sha256(backup.read_bytes()).hexdigest() if backup.is_file() else None,
                "generated": str(staged),
                "size": len(generated),
                "sha256": generated_sha256,
            },
            "rollback": "restore hcb.backup to hcb.destination when backup is present",
        }
        manifest_path = backup_root / "jump-install-manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        with SESSION.lock:
            SESSION.last_action = f"已安装跳转配方到测试副本 {target}"
            SESSION.last_error = None
        self._send_json({"ok": True, **manifest, "manifest": str(manifest_path)})

    def _jump_recipe_rollback(self, body: dict[str, Any]) -> None:
        """Restore the HCB recorded by a jump-install manifest."""

        if body.get("confirm") is not True:
            raise HcbError("回滚跳转补丁需要 confirm=true")
        manifest_value = str(body.get("manifest", "")).strip()
        if not manifest_value:
            raise HcbError("回滚需要 jump-install-manifest.json 路径")
        manifest_path = Path(manifest_value).expanduser().resolve()
        if manifest_path.name != "jump-install-manifest.json" or not manifest_path.is_file():
            raise HcbError("无效的跳转安装清单")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HcbError(f"无法读取跳转安装清单: {exc}") from exc
        if manifest.get("schema") != "fvp-studio-jump-install.v1":
            raise HcbError("清单版本不是可回滚的跳转安装格式")
        target = Path(str(manifest.get("target_dir", ""))).expanduser().resolve()
        backup_root = manifest_path.parent
        if backup_root.parent != target / ".fvpstudio-backups":
            raise HcbError("清单位置与目标目录不匹配")
        hcb = manifest.get("hcb") if isinstance(manifest.get("hcb"), dict) else {}
        destination = Path(str(hcb.get("destination", ""))).expanduser().resolve()
        backup = Path(str(hcb.get("backup", ""))).expanduser().resolve()
        if destination.parent != target or backup_root not in backup.parents or not backup.is_file():
            raise HcbError("清单中的备份 HCB 不存在或路径不安全")
        expected_backup_hash = str(hcb.get("backup_sha256", "")).strip().casefold()
        actual_backup_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
        if expected_backup_hash and expected_backup_hash != actual_backup_hash:
            raise HcbError("备份 HCB 哈希不匹配，拒绝回滚")
        shutil.copy2(backup, destination)
        restored_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
        manifest["rollback_performed_at"] = datetime.now().isoformat(timespec="seconds")
        manifest["rollback_restored_sha256"] = restored_hash
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        with SESSION.lock:
            SESSION.last_action = f"已从清单回滚跳转补丁 {destination}"
            SESSION.last_error = None
        self._send_json({"ok": True, "manifest": str(manifest_path), "destination": str(destination), "restored_sha256": restored_hash})

    def _insert_call(self, body: dict[str, Any]) -> None:
        """Insert a relocatable, primitive FVP function call.

        This endpoint is the safe high-level counterpart to the reference
        project's hand-written function builders: callers provide the anchor,
        function offset and typed stack arguments instead of pasting opaque
        bytes.  The generated call target participates in HCB relocation.
        """

        document = SESSION.require_editable(body)
        anchor = _parse_offset(body.get("offset"))
        target = _parse_offset(body.get("target"))
        args = body.get("args", [])
        if not isinstance(args, list):
            raise HcbError("args 必须是对象数组")
        with SESSION.lock:
            insertion = document.insert_call(
                anchor,
                target,
                args,
                note=str(body.get("note", "")),
            )
            SESSION.last_action = f"已插入 FVP 函数调用 0x{target:X} 于 0x{anchor:X}"
            SESSION.last_error = None
            summary = document.summary()
        self._send_json({"ok": True, "insertion": insertion.to_json(), "summary": summary})

    def _insert_raw(self, body: dict[str, Any]) -> None:
        """Insert an explicitly confirmed custom bytecode block.

        Raw insertion is deliberately opt-in and requires ``confirm=true``.
        Optional relative u32 target fields can be supplied so known call/jump
        operands are relocated after text edits; unknown layouts still require
        the existing ``allow_unknown`` checkbox during export.
        """

        document = SESSION.require_editable(body)
        if body.get("confirm") is not True:
            raise HcbError("原始字节码插入必须显式 confirm=true")
        anchor = _parse_offset(body.get("offset"))
        raw_value = str(body.get("hex", "")).strip().replace(" ", "").replace("\r", "").replace("\n", "")
        if not raw_value or len(raw_value) % 2:
            raise HcbError("hex 必须是偶数长度的十六进制字符串")
        try:
            payload = bytes.fromhex(raw_value)
        except ValueError as exc:
            raise HcbError("hex 含有非法字符") from exc
        target_fields: dict[int, int] = {}
        supplied = body.get("target_offsets", {})
        if isinstance(supplied, dict):
            for relative, target in supplied.items():
                target_fields[_parse_offset(relative)] = _parse_offset(target)
        elif isinstance(supplied, list):
            for item in supplied:
                if not isinstance(item, dict):
                    raise HcbError("target_offsets 数组项必须是对象")
                target_fields[_parse_offset(item.get("relative"))] = _parse_offset(item.get("target"))
        else:
            raise HcbError("target_offsets 必须是对象或数组")
        with SESSION.lock:
            insertion = document.insert_raw(
                anchor,
                payload,
                target_offsets=target_fields,
                note=str(body.get("note", "")),
                opaque=True,
            )
            SESSION.last_action = f"已插入自定义字节码 {len(payload)} bytes 于 0x{anchor:X}"
            SESSION.last_error = None
            summary = document.summary()
        self._send_json({"ok": True, "insertion": insertion.to_json(), "summary": summary})

    def _remove_last_insertion(self) -> None:
        document = SESSION.require_editable()
        with SESSION.lock:
            insertion = document.remove_last_insertion()
            SESSION.last_action = f"已撤销自定义插入 0x{insertion.anchor_offset:X}"
            SESSION.last_error = None
            summary = document.summary()
        self._send_json({"ok": True, "removed": insertion.to_json(), "summary": summary})

    def _save(self, body: dict[str, Any]) -> None:
        document = SESSION.require_document()
        with SESSION.lock:
            source = document.path
            requested = str(body.get("path", "")).strip()
            if requested:
                output = Path(requested).expanduser().resolve()
            elif source is not None:
                output = source.with_name(f"{source.stem}.fvpstudio.hcb")
            else:
                raise HcbError("没有默认输出路径，请填写 path")
            overwrite = bool(body.get("overwrite", False))
            saved = document.save(
                output,
                overwrite=overwrite,
                allow_unknown=bool(body.get("allow_unknown", False)),
            )
            SESSION.last_action = f"已导出 {saved}"
            SESSION.last_error = None
            payload = saved.read_bytes()
        self._send_json(
            {
                "ok": True,
                "path": str(saved),
                "size": len(payload),
                "sha256": __import__("hashlib").sha256(payload).hexdigest(),
                "summary": document.summary(),
            }
        )

    def _revert(self, body: dict[str, Any]) -> None:
        """Discard all unsaved HCB edits and restore the opened bytes.

        The browser has an explicit confirmation step, and the server also
        requires ``confirm=true`` so a stray request cannot silently erase an
        editing session.  The original source path and encoding are retained;
        the optional project profile is deliberately left untouched.
        """

        if body.get("confirm") is not True:
            raise HcbError("撤销未保存修改必须显式 confirm=true")
        document = SESSION.require_document()
        with SESSION.lock:
            was_modified = bool(document.modified)
            restored = parse_bytes(
                document.original_bytes,
                document.encoding,
                path=document.path,
            )
            SESSION.document = restored
            SESSION.plan = {
                "schema": "fvp-studio-replacement-plan.v1",
                "hcb": str(restored.path) if restored.path is not None else None,
                "text_edits": [],
                "visual_replacements": [],
                "portrait_sets": [],
                "audio_replacements": [],
            }
            SESSION.jump_labels = {}
            SESSION.last_action = "已撤销所有未保存修改" if was_modified else "当前没有未保存修改"
            SESSION.last_error = None
        self._send_json({"ok": True, "reverted": was_modified, "summary": restored.summary()})

    def _validate(self, body: dict[str, Any] | None = None) -> None:
        document = SESSION.require_document()
        body = body or {}
        with SESSION.lock:
            built = document.build(allow_unknown=bool(body.get("allow_unknown", False)))
            if document.overlay_text_relocations:
                original = document.original_bytes
                old_code_end = document.code_end
                original_size = len(original)
                new_sysdesc = int.from_bytes(built[:4], "little")
                changed = [
                    index
                    for index, (left, right) in enumerate(zip(original, built[:original_size]))
                    if left != right
                ]
                allowed: set[int] = set()
                for patch in document.fixed_patches:
                    allowed.update(range(patch.offset, patch.offset + len(patch.data)))
                for relocation in document.overlay_text_relocations:
                    allowed.update(range(relocation.offset, relocation.offset + 5))
                relocation_checks = []
                extension_size = 0
                for relocation in document.overlay_text_relocations:
                    payload = relocation.payload(document.encoding)
                    stub_offset = original_size + extension_size
                    stub = (
                        b"\x0E"
                        + bytes([len(payload)])
                        + payload
                        + b"\x06"
                        + struct.pack("<I", relocation.return_offset)
                    )
                    jump = b"\x06" + struct.pack("<I", stub_offset)
                    relocation_checks.append(
                        {
                            "offset": relocation.offset,
                            "stub_offset": stub_offset,
                            "jump_match": built[relocation.offset : relocation.offset + 5] == jump,
                            "stub_match": built[stub_offset : stub_offset + len(stub)] == stub,
                            "return_offset": relocation.return_offset,
                            "encoded_size": len(payload),
                        }
                    )
                    extension_size += len(stub)
                checks = {
                    "size": len(built),
                    "source_size": len(original),
                    "size_increased": len(built) == len(original) + extension_size,
                    "sysdesc_offset": new_sysdesc,
                    "sysdesc_offset_expected": old_code_end,
                    "source_prefix_changes": len(changed),
                    "changes_within_overlay_ranges": set(changed).issubset(allowed),
                    "fixed_patches_match": all(
                        built[item.offset : item.offset + len(item.data)] == item.data
                        for item in document.fixed_patches
                    ),
                    "relocations": relocation_checks,
                    "ok": bool(
                        len(built) == len(original) + extension_size
                        and new_sysdesc == old_code_end
                        and set(changed).issubset(allowed)
                        and all(item["jump_match"] and item["stub_match"] for item in relocation_checks)
                    ),
                }
                SESSION.last_action = "overlay variable-length text validation complete"
                SESSION.last_error = None
                self._send_json(checks)
                return
            if document.fixed_patches:
                original = document.original_bytes
                changed = [index for index, (left, right) in enumerate(zip(original, built)) if left != right]
                allowed = {
                    index
                    for patch in document.fixed_patches
                    for index in range(patch.offset, patch.offset + len(patch.data))
                }
                checks = {
                    "size": len(built),
                    "source_size": len(original),
                    "size_unchanged": len(built) == len(original),
                    "sysdesc_offset": int.from_bytes(built[:4], "little"),
                    "sysdesc_offset_unchanged": built[:4] == original[:4],
                    "fixed_patch_count": len(document.fixed_patches),
                    "changed_byte_count": len(changed),
                    "changes_within_fixed_patches": set(changed).issubset(allowed),
                    "fixed_patches_match": all(
                        built[item.offset : item.offset + len(item.data)] == item.data
                        for item in document.fixed_patches
                    ),
                }
                checks["ok"] = bool(
                    checks["size_unchanged"]
                    and checks["sysdesc_offset_unchanged"]
                    and checks["changes_within_fixed_patches"]
                    and checks["fixed_patches_match"]
                )
                SESSION.last_action = "overlay fixed patch validation complete"
                SESSION.last_error = None
                self._send_json(checks)
                return
            reparsed = parse_bytes(built, document.encoding)
            checks = {
                "size": len(built),
                "sysdesc_offset": reparsed.header.sysdesc_offset,
                "instruction_count": len(reparsed.instructions),
                "string_count": reparsed.string_count,
                "entry_point": reparsed.header.entry_point,
                "warnings": reparsed.warnings,
            }
            known_inserted = sum(
                int(item.instruction_count or 0)
                for item in document.insertions
                if not item.opaque
            )
            known_inserted_strings = sum(
                int(item.string_count or 0)
                for item in document.insertions
                if not item.opaque
            )
            has_opaque_insertions = any(item.opaque for item in document.insertions)
            expected_instruction_count = len(document.instructions) + known_inserted
            checks["expected_instruction_count"] = expected_instruction_count
            checks["expected_string_count"] = document.string_count + known_inserted_strings
            checks["instruction_count_match"] = (
                len(reparsed.instructions) == expected_instruction_count
                if not has_opaque_insertions
                else len(reparsed.instructions) >= len(document.instructions)
            )
            if has_opaque_insertions:
                checks["instruction_count_note"] = "含自定义原始字节码，指令数仅做下限校验"
            checks["string_count_match"] = (
                reparsed.string_count == document.string_count + known_inserted_strings
                if not has_opaque_insertions
                else reparsed.string_count >= document.string_count
            )
            checks["ok"] = bool(checks["instruction_count_match"] and checks["string_count_match"])
            SESSION.last_action = "校验完成"
            SESSION.last_error = None
        self._send_json(checks)

    def _export_json(self, body: dict[str, Any]) -> None:
        document = SESSION.require_document()
        with SESSION.lock:
            source = document.path
            requested = str(body.get("path", "")).strip()
            if requested:
                output = Path(requested).expanduser().resolve()
            elif source is not None:
                output = source.with_name(f"{source.stem}.fvpstudio.json")
            else:
                raise HcbError("没有默认 JSON 输出路径，请填写 path")
            if output.exists() and not bool(body.get("overwrite", False)):
                raise HcbError(f"输出已存在: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            dump_json(document, output)
            SESSION.last_action = f"已导出 JSON {output}"
            SESSION.last_error = None
        self._send_json({"ok": True, "path": str(output), "size": output.stat().st_size})

    def _events(self, query: dict[str, list[str]]) -> None:
        document = SESSION.require_document()
        q = (query.get("q", [""])[0] or "").casefold()
        kind = (query.get("kind", [""])[0] or "").casefold()
        try:
            offset = max(0, int(query.get("offset", ["0"])[0]))
            limit = min(500, max(1, int(query.get("limit", ["200"])[0])))
        except ValueError as exc:
            raise HcbError("offset/limit 必须是整数") from exc
        # The common unfiltered view must be O(page size), not O(instruction
        # count); real HCBs can contain more than a million instructions.
        if not q and not kind:
            total = len(document.instructions)
            filtered = [
                document.event_at(index)
                for index in range(offset, min(offset + limit, total))
            ]
        else:
            filtered = []
            total = 0
            # Do not materialize a million-instruction HCB as a second list.
            # Filter cheap instruction fields first, then build public JSON
            # only for the page that will actually be returned.
            for index, item in enumerate(document.instructions):
                if item.opcode == 0x0E:
                    item_kind = "string"
                elif item.opcode in (0x06, 0x07):
                    item_kind = "control_flow"
                elif item.opcode == 0x03:
                    item_kind = "syscall"
                elif item.opcode == 0x02:
                    item_kind = "call"
                else:
                    item_kind = "instruction"
                if kind and item_kind.casefold() != kind:
                    continue
                if q:
                    searchable = (
                        f"0x{item.offset:X} {item.mnemonic} "
                        f"{item.text or ''} {item.operands}"
                    ).casefold()
                    if q not in searchable:
                        continue
                if total >= offset and len(filtered) < limit:
                    filtered.append(document.event_at(index))
                total += 1
        if SESSION.profile is not None:
            for event in filtered:
                if event.get("kind") == "string":
                    profile_record = SESSION.profile.record_for_offset(int(event["offset"]))
                    if profile_record is not None:
                        event["profile"] = profile_record
        self._send_json(
            {
                "ok": True,
                "total": total,
                "offset": offset,
                "limit": limit,
                "events": filtered,
            }
        )

    def _functions(self, query: dict[str, list[str]]) -> None:
        document = SESSION.require_document()
        q = query.get("q", [""])[0] or ""
        try:
            offset = max(0, int(query.get("offset", ["0"])[0]))
            limit = min(500, max(1, int(query.get("limit", ["200"])[0])))
        except ValueError as exc:
            raise HcbError("函数分页参数无效") from exc
        with SESSION.lock:
            all_functions = document.function_index(q)
        total = len(all_functions)
        self._send_json(
            {
                "ok": True,
                "functions": all_functions[offset : offset + limit],
                "total": total,
                "offset": offset,
                "limit": limit,
            }
        )

    def _flow(self, query: dict[str, list[str]]) -> None:
        document = SESSION.require_document()
        q = query.get("q", [""])[0] or ""
        try:
            offset = max(0, int(query.get("offset", ["0"])[0]))
            limit = min(500, max(1, int(query.get("limit", ["200"])[0])))
        except ValueError as exc:
            raise HcbError("流程分页参数无效") from exc
        with SESSION.lock:
            all_edges = document.flow_index(q)
        self._send_json(
            {
                "ok": True,
                "edges": all_edges[offset : offset + limit],
                "total": len(all_edges),
                "offset": offset,
                "limit": limit,
            }
        )

    def _instruction(self, query: dict[str, list[str]]) -> None:
        document = SESSION.require_document()
        raw = query.get("offset", [""])[0]
        index, item = document.find_with_index(_parse_offset(raw))
        event = document.event_at(index)
        if SESSION.profile is not None:
            profile = SESSION.profile.record_for_offset(item.offset)
            if profile is not None:
                event["profile"] = profile
        self._send_json({"ok": True, "instruction": event})

    def _rewind_target(self, query: dict[str, list[str]]) -> None:
        document = SESSION.require_document()
        offset = _parse_offset(query.get("offset", [""])[0])
        with SESSION.lock:
            profile = SESSION.profile
        target = build_rewind_target(document, offset, profile)
        self._send_json({"ok": True, "target": target})

    def _texts(self, query: dict[str, list[str]]) -> None:
        profile = self._profile_required()
        try:
            offset = max(0, int(query.get("offset", ["0"])[0]))
            limit = min(500, max(1, int(query.get("limit", ["200"])[0])))
        except ValueError as exc:
            raise ProfileError("offset/limit 必须是整数") from exc
        result = profile.search_text(
            query=query.get("q", [""])[0],
            speaker=query.get("speaker", [""])[0],
            dialogue_only=query.get("dialogue_only", ["0"])[0].casefold() in {"1", "true", "yes"},
            offset=offset,
            limit=limit,
        )
        self._send_json({"ok": True, **result})

    def _assets(self, query: dict[str, list[str]]) -> None:
        profile = self._profile_required()
        try:
            offset = max(0, int(query.get("offset", ["0"])[0]))
            limit = min(500, max(1, int(query.get("limit", ["200"])[0])))
        except ValueError as exc:
            raise ProfileError("offset/limit 必须是整数") from exc
        result = profile.search_assets(
            query=query.get("q", [""])[0],
            category=query.get("category", [""])[0],
            archive=query.get("archive", [""])[0],
            offset=offset,
            limit=limit,
        )
        self._send_json({"ok": True, **result})

    def _portrait_v2_status(self) -> None:
        """Return the current read-only layered-portrait draft."""

        with SESSION.lock:
            draft = SESSION.portrait_v2_draft
        self._send_json({"ok": True, "draft": draft})

    def _portrait_v2_analyse(self, body: dict[str, Any]) -> None:
        """Analyse a strongly-bound body/face pair without writing files."""

        try:
            from .portrait_project import PortraitProjectError
            from .portrait_workspace import build_layered_portrait_draft
            from .resource_builder import ResourceBuildError
        except ImportError as exc:
            raise HcbError(f"V2 分层立绘分析模块不可用: {exc}") from exc

        archive_name = str(body.get("archive", "")).strip()
        project_dir = body.get("project_dir")
        archive = self._resolve_archive(archive_name, project_dir)
        try:
            draft = build_layered_portrait_draft(body, archive)
        except (PortraitProjectError, ResourceBuildError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.portrait_v2_draft = draft
            SESSION.last_action = (
                f"V2 已分析分层立绘 {draft['character']['display_name']} / "
                f"{draft['variant']['variant_id']}（未写入文件）"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "draft": draft})

    def _portrait_v2_clear(self) -> None:
        with SESSION.lock:
            SESSION.portrait_v2_draft = None
            SESSION.last_action = "已清空 V2 分层立绘草稿（未写入文件）"
            SESSION.last_error = None
        self._send_json({"ok": True, "draft": None})

    def _portrait_v2_scene_status(self) -> None:
        """Return every independent actor currently placed on the V2 stage."""

        self._send_json({"ok": True, "scene": SESSION.portrait_scene_snapshot()})

    def _portrait_v2_scene_add(self, body: dict[str, Any]) -> None:
        """Add the current candidate as a new stage actor."""

        with SESSION.lock:
            draft = body.get("draft") or SESSION.portrait_v2_draft
            source = SESSION.portrait_v2_source
        source_archive_path = str(body.get("source_archive_path", "")).strip()
        if not source_archive_path and source:
            source_archive_path = str(source.get("archive_path", ""))
        if not draft:
            raise HcbError("尚未生成可加入舞台的分层立绘")
        if not source_archive_path:
            raise HcbError("当前分层立绘缺少来源视觉 BIN")
        actor = SESSION.portrait_scene_add(
            draft,
            source_archive_path,
            expression_frame=body.get("expression_frame", 0),
        )
        with SESSION.lock:
            SESSION.last_action = (
                f"已将 {_portrait_actor_label(actor)} 加入舞台为独立角色"
            )
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "actor": actor,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _portrait_v2_scene_select(self, body: dict[str, Any]) -> None:
        actor_id = str(body.get("actor_id", "")).strip()
        if not actor_id:
            raise HcbError("缺少 actor_id")
        actor = SESSION.portrait_scene_select(actor_id)
        with SESSION.lock:
            SESSION.last_action = (
                f"已选择舞台角色 {_portrait_actor_label(actor)}"
            )
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "actor": actor,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _portrait_v2_scene_update(self, body: dict[str, Any]) -> None:
        actor_id = str(body.get("actor_id", "")).strip()
        if not actor_id:
            raise HcbError("缺少 actor_id")
        actor = SESSION.portrait_scene_update(
            actor_id,
            draft=body.get("draft") if "draft" in body else None,
            identity=body.get("identity") if "identity" in body else None,
            expression_frame=(
                body.get("expression_frame") if "expression_frame" in body else None
            ),
            visible=body.get("visible") if "visible" in body else None,
        )
        with SESSION.lock:
            SESSION.last_action = (
                f"已更新舞台角色 {_portrait_actor_label(actor)}"
            )
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "actor": actor,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _portrait_v2_scene_reorder(self, body: dict[str, Any]) -> None:
        scene = SESSION.portrait_scene_reorder(body.get("actor_ids"))
        labels = [_portrait_actor_label(actor) for actor in scene["actors"]]
        with SESSION.lock:
            SESSION.last_action = "已调整立绘层级（后 → 前）：" + "、".join(labels)
            SESSION.last_error = None
        self._send_json({"ok": True, "scene": scene})

    def _portrait_v2_scene_remove(self, body: dict[str, Any]) -> None:
        actor_id = str(body.get("actor_id", "")).strip()
        if not actor_id:
            raise HcbError("缺少 actor_id")
        selected = SESSION.portrait_scene_remove(actor_id)
        with SESSION.lock:
            SESSION.last_action = f"已从舞台删除角色 {actor_id}"
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "selected_actor": selected,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _portrait_v2_source_status(self) -> None:
        """Return the current read-only portrait-source BIN scan."""

        with SESSION.lock:
            source = SESSION.portrait_v2_source
        self._send_json({"ok": True, "source": source})

    def _portrait_v2_source_open(self, body: dict[str, Any]) -> None:
        """Open and index another FVP game's portrait archive read-only."""

        try:
            from .portrait_project import PortraitProjectError
            from .portrait_workspace import scan_portrait_source
            from .resource_builder import ResourceBuildError
        except ImportError as exc:
            raise HcbError(f"V2 来源立绘扫描模块不可用: {exc}") from exc

        raw_path = str(body.get("path", "")).strip()
        if not raw_path:
            raise HcbError("请填写来源游戏目录或视觉 BIN 路径")
        try:
            source = scan_portrait_source(Path(raw_path))
        except (PortraitProjectError, ResourceBuildError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        archive = Path(str(source["archive_path"]))
        with SESSION.lock:
            SESSION.portrait_v2_source = source
            SESSION.portrait_v2_draft = None
            SESSION.last_action = (
                f"V2 已只读扫描来源 {source['source_game']} / {archive.name}："
                f"{source['portrait_pair_count']} 组分层立绘"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "source": source})

    def _portrait_v2_source_clear(self) -> None:
        with SESSION.lock:
            SESSION.portrait_v2_source = None
            SESSION.portrait_v2_draft = None
            SESSION.last_action = "已清空 V2 来源游戏选择（未写入文件）"
            SESSION.last_error = None
        self._send_json({"ok": True, "source": None})

    def _portrait_v2_source_preview(self, query: dict[str, list[str]]) -> None:
        try:
            from .resource_builder import ResourceBuildError, preview_bin_entry
        except ImportError as exc:
            raise HcbError(f"V2 来源立绘预览模块不可用: {exc}") from exc
        with SESSION.lock:
            source = SESSION.portrait_v2_source
        if not source:
            raise HcbError("尚未扫描来源视觉 BIN")
        archive = Path(str(source["archive_path"]))
        try:
            entry_index = int(query.get("entry_index", [""])[0])
            frame = int(query.get("frame", ["0"])[0])
            thumb = query.get("thumb", [""])[0].casefold() in {"1", "true", "yes"}
            payload, _ = preview_bin_entry(
                archive,
                entry_index,
                frame,
                max_dimension=480 if thumb else None,
            )
        except (ValueError, ResourceBuildError) as exc:
            raise HcbError(str(exc)) from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        version = query.get("v", [""])[0].strip()
        self.send_header(
            "Cache-Control",
            "private, max-age=31536000, immutable" if version else "no-store",
        )
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _background_v2_current_game_dir(self) -> Path | None:
        """Resolve the active game's resource root without crossing profiles."""

        active = _active_document_parent()
        profile = _profile_game_dir()
        candidates: list[Path] = []
        if active is not None:
            candidates.append(active)
        if profile is not None and (
            active is None
            or profile == active
            or _profile_fallback_matches_active_hcb(profile)
        ):
            candidates.append(profile)
        for candidate in candidates:
            if any((candidate / name).is_file() for name in ("graph.bin", "graph_bg.bin")):
                return candidate
        return active or (profile if active is None else None)

    def _background_v2_source_status(self) -> None:
        with SESSION.lock:
            source = copy.deepcopy(SESSION.background_v2_source)
        self._send_json({"ok": True, "source": source})

    def _background_v2_source_open(self, body: dict[str, Any]) -> None:
        """Scan native or cross-game background archives without writing."""

        try:
            from .background_workspace import (
                BackgroundWorkspaceError,
                scan_background_source,
            )
        except ImportError as exc:
            raise HcbError(f"V2 背景扫描模块不可用: {exc}") from exc

        current_game_dir = self._background_v2_current_game_dir()
        use_current = bool(body.get("current_game"))
        raw_path = str(body.get("path", "")).strip()
        if use_current:
            if current_game_dir is None:
                raise HcbError("尚未打开可定位资源目录的目标 HCB")
            source_path: str | Path = current_game_dir
        elif raw_path:
            source_path = raw_path
        else:
            raise HcbError("请填写 FVP 游戏目录，或选择“当前游戏”")
        try:
            source = scan_background_source(
                source_path,
                current_game_dir=current_game_dir,
            )
        except (BackgroundWorkspaceError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.background_v2_source = source
            SESSION.last_action = (
                f"V2 已只读扫描 {source['source_game']} 背景："
                f"{source['background_count']} 个候选，耗时 {source['scan_seconds']:.3f}s"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "source": source})

    def _background_v2_source_clear(self) -> None:
        with SESSION.lock:
            SESSION.background_v2_source = None
            SESSION.last_action = "已清空背景来源列表；舞台构图未改变（未写入文件）"
            SESSION.last_error = None
        self._send_json({"ok": True, "source": None})

    @staticmethod
    def _background_v2_find_asset(asset_id: str, *, include_scene: bool) -> dict[str, Any]:
        token = str(asset_id or "").strip()
        if not token:
            raise HcbError("缺少背景 asset_id")
        with SESSION.lock:
            source = SESSION.background_v2_source
            if source:
                for item in source.get("entries", []):
                    if isinstance(item, dict) and item.get("asset_id") == token:
                        return copy.deepcopy(item)
            if include_scene:
                background = SESSION.portrait_v2_scene.get("background")
                if isinstance(background, dict) and background.get("asset_id") == token:
                    return copy.deepcopy(background)
        raise HcbError(f"找不到背景资源: {token}")

    def _background_v2_scene_set(self, body: dict[str, Any]) -> None:
        asset = self._background_v2_find_asset(
            str(body.get("asset_id", "")), include_scene=False
        )
        background = SESSION.visual_scene_set_background(
            asset,
            fit=str(body.get("fit", "cover")),
            variant=body.get("variant", "primary"),
        )
        with SESSION.lock:
            SESSION.last_action = f"已在可视化舞台设置背景 {background['label']}（未写入文件）"
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "background": background,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _background_v2_scene_fit(self, body: dict[str, Any]) -> None:
        background = SESSION.visual_scene_update_background_fit(
            str(body.get("fit", "cover"))
        )
        with SESSION.lock:
            SESSION.last_action = f"背景显示方式已切换为 {background['fit']}（未写入文件）"
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "background": background,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _background_v2_scene_clear(self) -> None:
        SESSION.visual_scene_clear_background()
        with SESSION.lock:
            SESSION.last_action = "已清除可视化舞台背景；立绘保持不变（未写入文件）"
            SESSION.last_error = None
        self._send_json({"ok": True, "scene": SESSION.portrait_scene_snapshot()})

    def _background_v2_preview(self, query: dict[str, list[str]]) -> None:
        try:
            from .resource_builder import ResourceBuildError, preview_bin_entry
        except ImportError as exc:
            raise HcbError(f"V2 背景预览模块不可用: {exc}") from exc
        asset = self._background_v2_find_asset(
            query.get("asset_id", [""])[0], include_scene=True
        )
        try:
            frame = int(query.get("frame", ["0"])[0])
            thumb = query.get("thumb", [""])[0].casefold() in {"1", "true", "yes"}
            payload, _ = preview_bin_entry(
                Path(str(asset["archive_path"])),
                int(asset["entry_index"]),
                frame,
                max_dimension=640 if thumb else None,
            )
        except (KeyError, TypeError, ValueError, ResourceBuildError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        version = query.get("v", [""])[0].strip()
        self.send_header(
            "Cache-Control",
            "private, max-age=31536000, immutable" if version else "no-store",
        )
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _cg_v2_current_game_dir(self) -> Path | None:
        """Resolve the active game's graph_vis root without crossing profiles."""

        active = _active_document_parent()
        profile = _profile_game_dir()
        candidates: list[Path] = []
        if active is not None:
            candidates.append(active)
        if profile is not None and (
            active is None
            or profile == active
            or _profile_fallback_matches_active_hcb(profile)
        ):
            candidates.append(profile)
        for candidate in candidates:
            if any(
                (candidate / name).is_file()
                for name in ("graph_vis.bin", "graph_vis1.bin", "graph_vis2.bin")
            ):
                return candidate
        return active or (profile if active is None else None)

    def _cg_v2_source_status(self) -> None:
        with SESSION.lock:
            source = copy.deepcopy(SESSION.cg_v2_source)
        self._send_json({"ok": True, "source": source})

    def _cg_v2_source_open(self, body: dict[str, Any]) -> None:
        """Scan native or cross-game graph_vis archives without writing."""

        try:
            from .cg_workspace import CgWorkspaceError, scan_cg_source
        except ImportError as exc:
            raise HcbError(f"V2 CG 扫描模块不可用: {exc}") from exc
        current_game_dir = self._cg_v2_current_game_dir()
        use_current = bool(body.get("current_game"))
        raw_path = str(body.get("path", "")).strip()
        if use_current:
            if current_game_dir is None:
                raise HcbError("尚未打开可定位 graph_vis 资源的目标 HCB")
            source_path: str | Path = current_game_dir
        elif raw_path:
            source_path = raw_path
        else:
            raise HcbError("请填写 FVP 游戏目录，或选择“当前游戏”")
        try:
            source = scan_cg_source(source_path, current_game_dir=current_game_dir)
        except (CgWorkspaceError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.cg_v2_source = source
            SESSION.last_action = (
                f"V2 已只读扫描 {source['source_game']} CG："
                f"{source['cg_count']} 个候选，耗时 {source['scan_seconds']:.3f}s"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "source": source})

    def _cg_v2_source_clear(self) -> None:
        with SESSION.lock:
            SESSION.cg_v2_source = None
            SESSION.last_action = "已清空 CG 来源列表；舞台构图未改变（未写入文件）"
            SESSION.last_error = None
        self._send_json({"ok": True, "source": None})

    @staticmethod
    def _cg_v2_find_asset(asset_id: str, *, include_scene: bool) -> dict[str, Any]:
        token = str(asset_id or "").strip()
        if not token:
            raise HcbError("缺少 CG asset_id")
        with SESSION.lock:
            source = SESSION.cg_v2_source
            if source:
                for item in source.get("entries", []):
                    if isinstance(item, dict) and item.get("asset_id") == token:
                        return copy.deepcopy(item)
            if include_scene:
                event_visual = SESSION.portrait_v2_scene.get("event_visual")
                if isinstance(event_visual, dict) and event_visual.get("asset_id") == token:
                    return copy.deepcopy(event_visual)
        raise HcbError(f"找不到 CG 资源: {token}")

    def _cg_v2_scene_set(self, body: dict[str, Any]) -> None:
        asset = self._cg_v2_find_asset(str(body.get("asset_id", "")), include_scene=False)
        if str(asset.get("build_mode") or "").strip().casefold() == "direct_reference":
            current_game_dir = self._cg_v2_current_game_dir()
            if current_game_dir is None or not _same_resolved_path(
                asset.get("project_dir"),
                current_game_dir,
            ):
                raise HcbError("本作直引 CG 不属于当前目标游戏，请重新扫描")
        event_visual = SESSION.visual_scene_set_cg(
            asset,
            display_mode=str(body.get("display_mode") or "standard"),
        )
        with SESSION.lock:
            SESSION.last_action = f"已在可视化舞台设置 CG {event_visual['label']}（未写入文件）"
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "event_visual": event_visual,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _cg_v2_scene_update(self, body: dict[str, Any]) -> None:
        transform = body.get("transform")
        if transform is not None and not isinstance(transform, dict):
            raise HcbError("CG transform 必须是对象")
        event_visual = SESSION.visual_scene_update_cg(
            display_mode=(
                str(body["display_mode"]) if body.get("display_mode") is not None else None
            ),
            transform=transform,
        )
        with SESSION.lock:
            SESSION.last_action = "CG 舞台显示参数已更新（未写入文件）"
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "event_visual": event_visual,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _cg_v2_scene_clear(self) -> None:
        SESSION.visual_scene_clear_cg()
        with SESSION.lock:
            SESSION.last_action = "已清除 CG 覆盖层；背景与立绘布局已恢复（未写入文件）"
            SESSION.last_error = None
        self._send_json({"ok": True, "scene": SESSION.portrait_scene_snapshot()})

    def _cg_v2_preview(self, query: dict[str, list[str]]) -> None:
        try:
            from .resource_builder import ResourceBuildError, preview_bin_entry
        except ImportError as exc:
            raise HcbError(f"V2 CG 预览模块不可用: {exc}") from exc
        asset = self._cg_v2_find_asset(
            query.get("asset_id", [""])[0], include_scene=True
        )
        try:
            frame = int(query.get("frame", ["0"])[0])
            thumb = query.get("thumb", [""])[0].casefold() in {"1", "true", "yes"}
            payload, _ = preview_bin_entry(
                Path(str(asset["archive_path"])),
                int(asset["entry_index"]),
                frame,
                max_dimension=640 if thumb else None,
            )
        except (KeyError, TypeError, ValueError, ResourceBuildError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        version = query.get("v", [""])[0].strip()
        self.send_header(
            "Cache-Control",
            "private, max-age=31536000, immutable" if version else "no-store",
        )
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _audio_v2_current_game_dir(self) -> Path | None:
        """Resolve the active game's BGM/SE root without crossing profiles."""

        active = _active_document_parent()
        profile = _profile_game_dir()
        candidates: list[Path] = []
        if active is not None:
            candidates.append(active)
        if profile is not None and (
            active is None
            or profile == active
            or _profile_fallback_matches_active_hcb(profile)
        ):
            candidates.append(profile)
        for candidate in candidates:
            if any(
                (candidate / name).is_file()
                for name in ("bgm.bin", "bgm2.bin", "se.bin")
            ):
                return candidate
        return active or (profile if active is None else None)

    @staticmethod
    def _audio_v2_source_payload(
        scanned_source: dict[str, Any] | None,
    ) -> dict[str, Any]:
        try:
            from .audio_project import (
                ProjectAudioError,
                list_project_audio_assets,
            )

            project = list_project_audio_assets(
                V2_AUDIO_LIBRARY_ROOT,
                verify_payloads=False,
            )
        except (ProjectAudioError, OSError) as exc:
            raise HcbError(f"无法读取 V2 项目音频库: {exc}") from exc
        source = copy.deepcopy(scanned_source) if scanned_source else {
            "schema": "fvp-studio-v2.audio-source.v1",
            "project_dir": str(V2_AUDIO_LIBRARY_ROOT),
            "source_game": "V2 项目音频",
            "source_kind": "project_audio_library",
            "source_mode": "project_library",
            "build_mode": "additive_resource",
            "is_current_game": False,
            "read_only": True,
            "archives": [],
            "skipped_count": 0,
            "cache_hit": True,
            "cache_hits": 0,
            "scan_seconds": 0.0,
            "entries": [],
        }
        native_entries = [
            copy.deepcopy(item)
            for item in source.get("entries", [])
            if isinstance(item, dict)
        ]
        project_entries = [
            copy.deepcopy(item)
            for item in project.get("entries", [])
            if isinstance(item, dict)
        ]
        source["entries"] = [*project_entries, *native_entries]
        if scanned_source and project_entries:
            source["source_kind"] = "combined_audio_source"
            source["build_mode"] = "mixed_native_and_additive"
        source["native_audio_count"] = len(native_entries)
        source["project_audio_count"] = len(project_entries)
        source["audio_count"] = len(source["entries"])
        source["compile_ready_count"] = sum(
            bool(item.get("compile_ready")) for item in source["entries"]
        )
        source["preview_only_count"] = sum(
            bool(item.get("preview_only")) for item in source["entries"]
        )
        revision_material = [str(source.get("revision") or "")]
        revision_material.extend(
            f"{item.get('asset_id')}:{item.get('payload_sha256')}"
            for item in project_entries
        )
        source["revision"] = hashlib.sha256(
            "|".join(revision_material).encode("utf-8")
        ).hexdigest()[:16]
        source["project_library"] = str(V2_AUDIO_LIBRARY_ROOT)
        return source

    def _audio_v2_source_status(self) -> None:
        with SESSION.lock:
            source = copy.deepcopy(SESSION.audio_v2_source)
        self._send_json(
            {"ok": True, "source": self._audio_v2_source_payload(source)}
        )

    def _audio_v2_source_open(self, body: dict[str, Any]) -> None:
        """Scan BGM/SE archive metadata read-only; payloads remain lazy."""

        try:
            from .audio_workspace import AudioWorkspaceError, scan_audio_source
        except ImportError as exc:
            raise HcbError(f"V2 音频扫描模块不可用: {exc}") from exc
        current_game_dir = self._audio_v2_current_game_dir()
        use_current = bool(body.get("current_game"))
        raw_path = str(body.get("path", "")).strip()
        if use_current:
            if current_game_dir is None:
                raise HcbError("尚未打开可定位 BGM / SE 资源的目标 HCB")
            source_path: str | Path = current_game_dir
        elif raw_path:
            source_path = raw_path
        else:
            raise HcbError("请填写 FVP 游戏目录或 BGM / SE BIN 路径")
        try:
            source = scan_audio_source(
                source_path,
                current_game_dir=current_game_dir,
            )
        except (AudioWorkspaceError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.audio_v2_source = source
            SESSION.last_action = (
                f"V2 已只读扫描 {source['source_game']} 音频："
                f"{source['audio_count']} 个 BGM / SE，耗时 "
                f"{source['scan_seconds']:.3f}s"
            )
            SESSION.last_error = None
        self._send_json(
            {"ok": True, "source": self._audio_v2_source_payload(source)}
        )

    def _audio_v2_source_clear(self) -> None:
        with SESSION.lock:
            SESSION.audio_v2_source = None
            SESSION.last_action = "已清空音频来源列表；舞台 BGM / SE 状态未改变（未写入文件）"
            SESSION.last_error = None
        self._send_json(
            {"ok": True, "source": self._audio_v2_source_payload(None)}
        )

    def _audio_v2_project_import(
        self,
        query: dict[str, list[str]],
        payload: bytes,
    ) -> None:
        track = str(query.get("track", [""])[0]).strip().casefold()
        filename = str(query.get("filename", [""])[0]).strip()
        if track not in {"bgm", "se"}:
            raise HcbError("项目音频 track 必须是 bgm 或 se")
        if not filename or "\x00" in filename:
            raise HcbError("项目音频文件名无效")
        label = Path(filename).name
        try:
            from .audio_project import (
                ProjectAudioError,
                import_project_audio_bytes,
            )

            reference = import_project_audio_bytes(
                V2_AUDIO_LIBRARY_ROOT,
                payload,
                track=track,
                label=label,
            )
        except (ProjectAudioError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            scanned = copy.deepcopy(SESSION.audio_v2_source)
            SESSION.last_action = (
                f"已导入项目音频 {label}；构建时将新增原生资源，不覆盖旧槽位"
            )
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "asset": reference,
                "source": self._audio_v2_source_payload(scanned),
            }
        )

    @staticmethod
    def _audio_v2_find_asset(
        asset_id: str,
        *,
        include_scene: bool,
    ) -> dict[str, Any]:
        token = str(asset_id or "").strip()
        if not token:
            raise HcbError("缺少音频 asset_id")
        with SESSION.lock:
            source = SESSION.audio_v2_source
            if source:
                for item in source.get("entries", []):
                    if isinstance(item, dict) and item.get("asset_id") == token:
                        return copy.deepcopy(item)
            if include_scene:
                audio = SESSION.portrait_v2_scene.get("audio")
                if isinstance(audio, dict):
                    for track_name in ("bgm", "se"):
                        track = audio.get(track_name)
                        if not isinstance(track, dict):
                            continue
                        nested = track.get("asset")
                        candidate = nested if isinstance(nested, dict) else track
                        if candidate.get("asset_id") == token:
                            return copy.deepcopy(candidate)
        try:
            from .audio_project import (
                ProjectAudioError,
                list_project_audio_assets,
            )

            project_source = list_project_audio_assets(
                V2_AUDIO_LIBRARY_ROOT,
                verify_payloads=False,
            )
        except (ProjectAudioError, OSError) as exc:
            raise HcbError(f"无法读取 V2 项目音频库: {exc}") from exc
        for item in project_source.get("entries", []):
            if isinstance(item, dict) and item.get("asset_id") == token:
                return copy.deepcopy(item)
        raise HcbError(f"找不到音频资源: {token}")

    def _audio_v2_scene_update(self, body: dict[str, Any]) -> None:
        track = str(body.get("track") or "").strip().casefold()
        if track not in {"bgm", "se"}:
            raise HcbError("音频 track 必须是 bgm 或 se")
        action = str(body.get("action") or "").strip().casefold() or None
        asset_id = str(body.get("asset_id") or "").strip()
        asset = (
            self._audio_v2_find_asset(asset_id, include_scene=False)
            if asset_id
            else None
        )
        if asset is not None:
            asset_track = str(asset.get("track") or "").strip().casefold()
            if asset_track != track:
                raise HcbError("所选音频资源与 BGM / SE 轨道不匹配")
            if str(asset.get("build_mode") or "").strip().casefold() == "direct_reference":
                current_game_dir = self._audio_v2_current_game_dir()
                if current_game_dir is None or not _same_resolved_path(
                    asset.get("project_dir"),
                    current_game_dir,
                ):
                    raise HcbError("本作直引音频不属于当前目标游戏，请重新扫描")
        audio = SESSION.visual_scene_update_audio(
            track,
            asset=asset,
            action=action,
            volume=body.get("volume") if "volume" in body else None,
            transition_ms=(
                body.get("transition_ms") if "transition_ms" in body else None
            ),
            loop=body.get("loop") if "loop" in body else None,
        )
        current = audio[track]
        with SESSION.lock:
            SESSION.last_action = (
                f"已更新舞台 {track.upper()}：{current.get('action')}（未写入文件）"
            )
            SESSION.last_error = None
        self._send_json(
            {
                "ok": True,
                "audio": audio,
                "scene": SESSION.portrait_scene_snapshot(),
            }
        )

    def _audio_v2_preview(self, query: dict[str, list[str]]) -> None:
        asset = self._audio_v2_find_asset(
            query.get("asset_id", [""])[0],
            include_scene=True,
        )
        build_mode = str(asset.get("build_mode") or "").strip().casefold()
        if build_mode == "additive_resource":
            try:
                from .audio_project import (
                    PROJECT_AUDIO_ASSETS_DIR,
                    ProjectAudioError,
                    validate_project_audio_asset,
                )

                validation = validate_project_audio_asset(
                    asset,
                    V2_AUDIO_LIBRARY_ROOT,
                )
                reference = dict(validation["asset_ref"])
                assets_root = (
                    V2_AUDIO_LIBRARY_ROOT / PROJECT_AUDIO_ASSETS_DIR
                ).resolve()
                payload_path = assets_root.joinpath(
                    *str(reference["relative_path"]).split("/")
                ).resolve()
                if (
                    not payload_path.is_relative_to(assets_root)
                    or payload_path.is_symlink()
                    or not payload_path.is_file()
                    or payload_path.stat().st_size != int(reference["size"])
                ):
                    raise ProjectAudioError("项目音频预览负载已漂移")
            except (KeyError, ProjectAudioError, OSError, TypeError, ValueError) as exc:
                raise HcbError(str(exc)) from exc
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", str(reference["mime"]))
            self.send_header("Content-Disposition", "inline")
            version = query.get("v", [""])[0].strip()
            self.send_header(
                "Cache-Control",
                "private, max-age=31536000, immutable" if version else "no-store",
            )
            self.send_header("Connection", "close")
            self.send_header("Content-Length", str(reference["size"]))
            try:
                self.end_headers()
                with payload_path.open("rb") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                return
            except (
                BrokenPipeError,
                ConnectionAbortedError,
                ConnectionResetError,
                OSError,
            ):
                return
        try:
            from .resource_builder import ResourceBuildError, preview_audio_entry
        except ImportError as exc:
            raise HcbError(f"V2 音频预览模块不可用: {exc}") from exc
        try:
            payload, info = preview_audio_entry(
                Path(str(asset["archive_path"])),
                int(asset["entry_index"]),
            )
        except (KeyError, TypeError, ValueError, ResourceBuildError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", str(info["mime"]))
        self.send_header("Content-Disposition", "inline")
        version = query.get("v", [""])[0].strip()
        self.send_header(
            "Cache-Control",
            "private, max-age=31536000, immutable" if version else "no-store",
        )
        self.send_header("Content-Length", str(len(payload)))
        try:
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            return

    def _visual_scene_status(self) -> None:
        snapshot = SESSION.visual_story_snapshot()
        self._send_json({"ok": True, **snapshot})

    def _visual_scene_dialogues(self, query: dict[str, list[str]]) -> None:
        """Page profile-confirmed dialogue rows without materialising all rows."""

        native_context = self._native_scene_memory_context_optional()
        profile = (
            native_context.dialogue_profile
            if native_context is not None
            else self._profile_required()
        )
        try:
            offset = max(0, int(query.get("offset", ["0"])[0]))
            limit = min(100, max(1, int(query.get("limit", ["40"])[0])))
        except ValueError as exc:
            raise HcbError("剧情台词分页参数无效") from exc
        result = profile.search_text(
            query=query.get("q", [""])[0],
            speaker=query.get("speaker", [""])[0],
            dialogue_only=True,
            offset=offset,
            limit=limit,
        )
        with SESSION.lock:
            from .visual_scene_project import story_snapshot

            story = story_snapshot(SESSION.portrait_v2_scene)
            document = SESSION.document
        self._send_json(
            {
                "ok": True,
                **result,
                "document_loaded": document is not None,
                "source_sha256": document.source_sha256 if document is not None else None,
                "selected_anchor": story.get("anchor"),
                "native_target_context": (
                    copy.deepcopy(dict(native_context.report))
                    if native_context is not None
                    else None
                ),
            }
        )

    def _visual_scene_speakers(self) -> None:
        """Expose every runtime-index name with its native-call safety state."""

        native_context = self._native_scene_memory_context_optional()
        if native_context is not None:
            from .native_scene_candidate import native_story_speaker_catalog

            self._send_json(
                {"ok": True, **native_story_speaker_catalog(native_context)}
            )
            return
        from .hoshimemo_overlay import resolve_hoshimemo_analysis_document
        from .story_backlog import attach_story_backlog_avatars
        from .story_speakers import discover_story_speakers

        with SESSION.lock:
            document = SESSION.document
            profile = SESSION.profile
        catalog = discover_story_speakers(document, profile)
        backlog_document = document
        if document is not None and profile is not None:
            try:
                backlog_document, _ = resolve_hoshimemo_analysis_document(document, profile)
            except HcbError:
                pass
        catalog = attach_story_backlog_avatars(catalog, backlog_document)
        self._send_json({"ok": True, **catalog})

    def _visual_scene_backlog_avatar(self, query: dict[str, list[str]]) -> None:
        """Return one server-selected native B.LOG avatar cell as PNG."""

        try:
            from .resource_builder import ResourceBuildError, preview_bin_entry_crop
            from .hoshimemo_overlay import resolve_hoshimemo_analysis_document
            from .story_backlog import (
                HOSHIMEMO_BACKLOG_ATLAS_SIZE,
                StoryBacklogError,
                resolve_story_backlog_avatar,
            )
            from .story_speakers import discover_story_speakers
        except ImportError as exc:
            raise HcbError(f"B.LOG 头像预览模块不可用: {exc}") from exc

        speaker_id = str(query.get("speaker_id", [""])[0]).strip()
        if not speaker_id:
            raise HcbError("缺少 B.LOG 头像说话人")
        with SESSION.lock:
            document = SESSION.document
            profile = SESSION.profile
            catalog = discover_story_speakers(document, profile)
            backlog_document = document
            if document is not None and profile is not None:
                try:
                    backlog_document, _ = resolve_hoshimemo_analysis_document(document, profile)
                except HcbError:
                    pass
            _, avatar = resolve_story_backlog_avatar(catalog, backlog_document, speaker_id)
            archive = self._resolve_archive(str(avatar["archive"]))
            if SESSION.document is not document or SESSION.profile is not profile:
                raise HcbError("解析 B.LOG 头像期间 HCB 或项目索引已变化，请重试")
        try:
            payload, info = preview_bin_entry_crop(
                archive,
                int(avatar["entry_index"]),
                left=int(avatar["selected_x"]),
                top=int(avatar["y"]),
                width=int(avatar["width"]),
                height=int(avatar["height"]),
            )
        except (KeyError, TypeError, ValueError, ResourceBuildError, StoryBacklogError) as exc:
            raise HcbError(str(exc)) from exc
        actual_size = (int(info["original_width"]), int(info["original_height"]))
        if actual_size != HOSHIMEMO_BACKLOG_ATLAS_SIZE:
            raise HcbError(
                "当前 graph.bin 的 B.LOG 图集尺寸不匹配："
                f"需要 {HOSHIMEMO_BACKLOG_ATLAS_SIZE[0]}x{HOSHIMEMO_BACKLOG_ATLAS_SIZE[1]}，"
                f"实际 {actual_size[0]}x{actual_size[1]}"
            )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _visual_scene_anchor(self, body: dict[str, Any]) -> None:
        from .hoshimemo_scene_hook import inspect_hoshimemo_dialogue_anchor
        from .native_scene_candidate import inspect_native_scene_anchor
        from .visual_scene_project import set_story_anchor, story_snapshot

        offset = _parse_offset(body.get("offset"))
        timing = str(body.get("timing", "before"))
        native_context = self._native_scene_memory_context_optional()
        with SESSION.lock:
            document = SESSION.require_document()
            profile = (
                native_context.dialogue_profile
                if native_context is not None
                else self._profile_required()
            )
            before_story = story_snapshot(SESSION.portrait_v2_scene)
            scene_id = str(
                body.get("scene_id") or before_story.get("active_scene_id") or ""
            )
            source_sha256 = document.source_sha256
        if native_context is not None:
            anchor = inspect_native_scene_anchor(native_context, offset, timing)
        else:
            anchor = inspect_hoshimemo_dialogue_anchor(
                document,
                profile,
                offset,
                timing,
            )
        with SESSION.lock:
            if (
                SESSION.document is not document
                or SESSION.require_document().source_sha256 != source_sha256
            ):
                raise HcbError("解析挂接点期间 HCB 或项目索引已变化，请重试")
            if native_context is not None:
                if SESSION.native_scene_memory_context is not native_context:
                    raise HcbError("解析挂接点期间原生目标上下文已变化，请重试")
            elif SESSION.profile is not profile:
                raise HcbError("解析挂接点期间项目分析索引已变化，请重试")
            story = set_story_anchor(
                SESSION.portrait_v2_scene,
                anchor,
                scene_id=scene_id,
            )
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = (
                f"已选择剧情台词 {anchor['hcb_offset_hex']}（"
                f"{'可安全挂接' if anchor.get('safe') else '当前被门禁阻止'}）"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "anchor": anchor, "story": story})

    def _visual_scene_project_add(self, body: dict[str, Any]) -> None:
        from .visual_scene_project import add_story_scene, story_snapshot

        with SESSION.lock:
            item = add_story_scene(
                SESSION.portrait_v2_scene,
                duplicate_active=bool(body.get("duplicate_active", False)),
                title=(str(body.get("title")) if body.get("title") is not None else None),
            )
            story = story_snapshot(SESSION.portrait_v2_scene)
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已新增剧情场景 {item['title']}"
            SESSION.last_error = None
        self._send_json({"ok": True, "scene_item": item, "story": story})

    def _visual_scene_project_select(self, body: dict[str, Any]) -> None:
        from .visual_scene_project import select_story_scene, story_snapshot

        with SESSION.lock:
            item = select_story_scene(
                SESSION.portrait_v2_scene,
                str(body.get("scene_id") or ""),
            )
            story = story_snapshot(SESSION.portrait_v2_scene)
            # Selection changes the legacy active-scene view.  Until every
            # caller is project-aware, discarding the cached candidate is the
            # safest behaviour and never writes a target file.
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已切换到剧情场景 {item['title']}"
            SESSION.last_error = None
        self._send_json({"ok": True, "scene_item": item, "story": story})

    def _visual_scene_project_rename(self, body: dict[str, Any]) -> None:
        from .visual_scene_project import rename_story_scene, story_snapshot

        with SESSION.lock:
            item = rename_story_scene(
                SESSION.portrait_v2_scene,
                str(body.get("scene_id") or ""),
                str(body.get("title") or ""),
            )
            story = story_snapshot(SESSION.portrait_v2_scene)
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已重命名剧情场景为 {item['title']}"
            SESSION.last_error = None
        self._send_json({"ok": True, "scene_item": item, "story": story})

    def _visual_scene_project_move(self, body: dict[str, Any]) -> None:
        from .visual_scene_project import move_story_scene

        try:
            new_index = int(body.get("new_index"))
        except (TypeError, ValueError) as exc:
            raise HcbError("剧情场景目标顺序必须是整数") from exc
        with SESSION.lock:
            story = move_story_scene(
                SESSION.portrait_v2_scene,
                str(body.get("scene_id") or ""),
                new_index,
            )
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = "已调整剧情场景顺序"
            SESSION.last_error = None
        self._send_json({"ok": True, "story": story})

    def _visual_scene_project_remove(self, body: dict[str, Any]) -> None:
        from .visual_scene_project import remove_story_scene, story_snapshot

        with SESSION.lock:
            removed = remove_story_scene(
                SESSION.portrait_v2_scene,
                str(body.get("scene_id") or ""),
            )
            story = story_snapshot(SESSION.portrait_v2_scene)
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已删除剧情场景 {removed['title']}"
            SESSION.last_error = None
        self._send_json({"ok": True, "removed": removed, "story": story})

    def _visual_scene_project_replace(self, body: dict[str, Any]) -> None:
        from .visual_scene_project import replace_story_project

        project = body.get("project")
        if not isinstance(project, dict):
            raise HcbError("缺少剧情工程 project JSON")
        with SESSION.lock:
            story = replace_story_project(SESSION.portrait_v2_scene, project)
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已载入剧情工程，共 {len(story['scenes'])} 个场景"
            SESSION.last_error = None
        self._send_json({"ok": True, "story": story})

    def _visual_scene_anchor_clear(self, body: dict[str, Any] | None = None) -> None:
        from .visual_scene_project import clear_story_anchor

        with SESSION.lock:
            from .visual_scene_project import story_snapshot

            before_story = story_snapshot(SESSION.portrait_v2_scene)
            scene_id = str(
                (body or {}).get("scene_id")
                or before_story.get("active_scene_id")
                or ""
            )
            story = clear_story_anchor(
                SESSION.portrait_v2_scene,
                scene_id=scene_id,
            )
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = "已清除剧情挂接点；舞台和新增台词保持不变"
            SESSION.last_error = None
        self._send_json({"ok": True, "story": story})

    def _visual_scene_cue_capture(self, body: dict[str, Any] | None = None) -> None:
        from .visual_scene_project import capture_story_cue, story_snapshot

        with SESSION.lock:
            before_story = story_snapshot(SESSION.portrait_v2_scene)
            scene_id = str(
                (body or {}).get("scene_id")
                or before_story.get("active_scene_id")
                or ""
            )
            cue = capture_story_cue(
                SESSION.portrait_v2_scene,
                scene_id=scene_id,
            )
            story = story_snapshot(SESSION.portrait_v2_scene)
            SESSION.invalidate_visual_scene_candidate()
            background = cue.get("background")
            background_label = (
                str(background.get("label") or background.get("resource_name") or "背景")
                if isinstance(background, dict)
                else "无背景"
            )
            SESSION.last_action = (
                f"已把当前舞台应用到剧情：{background_label}，"
                f"{len(cue.get('actors') or [])} 个角色快照（未写入文件）"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "cue": cue, "story": story})

    def _visual_scene_dialogue_add(self, body: dict[str, Any]) -> None:
        from .story_speakers import discover_story_speakers, resolve_story_speaker
        from .visual_scene_project import add_inserted_dialogue, story_snapshot

        native_context = self._native_scene_memory_context_optional()
        with SESSION.lock:
            document = SESSION.document
            profile = SESSION.profile
            before_story = story_snapshot(SESSION.portrait_v2_scene)
            scene_id = str(
                body.get("scene_id")
                or before_story.get("active_scene_id")
                or ""
            )
        if native_context is not None:
            from .native_scene_candidate import native_story_speaker_catalog

            catalog = native_story_speaker_catalog(native_context)
        else:
            catalog = discover_story_speakers(document, profile)
        speaker = resolve_story_speaker(
            catalog,
            str(body.get("speaker_id") or "narration"),
        )
        with SESSION.lock:
            if SESSION.document is not document or SESSION.profile is not profile:
                raise HcbError("解析说话人期间 HCB 或项目索引已变化，请重试")
            if (
                native_context is not None
                and SESSION.native_scene_memory_context is not native_context
            ):
                raise HcbError("解析说话人期间通用目标上下文已变化，请重试")
            line = add_inserted_dialogue(
                SESSION.portrait_v2_scene,
                body,
                trusted_speaker=speaker,
                scene_id=scene_id,
            )
            story = story_snapshot(SESSION.portrait_v2_scene)
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已新增剧情台词 {line['line_id']}（未写入文件）"
            SESSION.last_error = None
        self._send_json({"ok": True, "line": line, "story": story})

    def _visual_scene_dialogue_remove(self, body: dict[str, Any]) -> None:
        from .visual_scene_project import remove_inserted_dialogue, story_snapshot

        with SESSION.lock:
            before_story = story_snapshot(SESSION.portrait_v2_scene)
            scene_id = str(
                body.get("scene_id")
                or before_story.get("active_scene_id")
                or ""
            )
            removed = remove_inserted_dialogue(
                SESSION.portrait_v2_scene,
                str(body.get("line_id", "")),
                scene_id=scene_id,
            )
            story = story_snapshot(SESSION.portrait_v2_scene)
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = f"已删除剧情台词 {removed['line_id']}"
            SESSION.last_error = None
        self._send_json({"ok": True, "removed": removed, "story": story})

    def _visual_scene_dialogue_clear(self, body: dict[str, Any] | None = None) -> None:
        from .visual_scene_project import clear_inserted_dialogue, story_snapshot

        with SESSION.lock:
            before_story = story_snapshot(SESSION.portrait_v2_scene)
            scene_id = str(
                (body or {}).get("scene_id")
                or before_story.get("active_scene_id")
                or ""
            )
            story = clear_inserted_dialogue(
                SESSION.portrait_v2_scene,
                scene_id=scene_id,
            )
            SESSION.invalidate_visual_scene_candidate()
            SESSION.last_action = "已清空当前场景新增台词"
            SESSION.last_error = None
        self._send_json({"ok": True, "story": story})

    def _visual_scene_native_candidate_dry_run(
        self,
        native_context: Any,
        duration_ms: int,
        *,
        acceptance_mode: bool = False,
        dialogue_encoding: str | None = None,
        runtime_companion_source_dir: str | None = None,
    ) -> None:
        """Build one discovered-target HCB candidate.

        Normal generic candidates remain compile-only.  An explicit acceptance
        request may open only the isolated-copy HCB transaction path after the
        narrow narration/background-only audit succeeds.
        """

        from .native_scene_candidate import (
            build_native_story_memory_candidate,
            inspect_native_scene_anchor,
        )
        from .visual_scene_project import story_snapshot

        with SESSION.lock:
            document = SESSION.require_document()
            if SESSION.native_scene_memory_context is not native_context:
                raise HcbError("通用剧情上下文已变化，请重试")
            discovery = SESSION.native_target_discovery
            if not isinstance(discovery, dict):
                raise HcbError("通用剧情 dry-run 缺少原生目标发现报告")
            story = story_snapshot(SESSION.portrait_v2_scene)
            story_revision = int(story.get("revision") or 0)
            source_sha256 = document.source_sha256
            profile = SESSION.profile
            profile_fingerprint = str(
                getattr(profile, "index_fingerprint", "") or ""
            )
            profile_background_assets = tuple(
                {
                    "archive": item.get("archive"),
                    "archive_name": item.get("archive_name"),
                    "category": item.get("category"),
                    "width": item.get("width"),
                    "height": item.get("height"),
                    "frame_count": item.get("frame_count"),
                }
                for item in (getattr(profile, "assets", ()) or ())
                if isinstance(item, Mapping)
                and str(item.get("category") or "").strip().casefold()
                == "background"
            )
        try:
            game_root = Path(str(discovery.get("game_dir") or "")).resolve()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise HcbError(f"通用剧情目标目录无效: {exc}") from exc
        portrait_acceptance = None
        target_graph_bs: bytes | None = None
        portrait_archive_name: str | None = None
        portrait_acceptance_mode = False
        runtime_text_bridge: Mapping[str, Any] | None = None
        runtime_text_companion_files: dict[str, bytes] = {}
        runtime_text_companion_report: Mapping[str, Any] | None = None
        if acceptance_mode:
            from .native_portrait_acceptance import (
                NativePortraitAcceptanceError,
                build_native_portrait_acceptance_profile,
            )
            from .visual_scene_project import (
                VisualSceneProjectError,
                buildable_story_scenes,
            )

            try:
                acceptance_scenes = buildable_story_scenes(story)
            except VisualSceneProjectError as exc:
                raise HcbError(str(exc)) from exc
            if len(acceptance_scenes) != 1:
                raise HcbError("原生立绘隔离验收必须恰好包含 1 个完整场景")
            acceptance_scene = acceptance_scenes[0]
            acceptance_cue = (
                acceptance_scene.get("cue")
                if isinstance(acceptance_scene.get("cue"), Mapping)
                else {}
            )
            actor_values = (
                acceptance_cue.get("actors")
                if isinstance(acceptance_cue.get("actors"), list)
                else []
            )
            visible_actors = [
                actor
                for actor in actor_values
                if isinstance(actor, Mapping) and bool(actor.get("visible", True))
            ]
            if actor_values:
                if len(actor_values) != 1 or len(visible_actors) != 1:
                    raise HcbError(
                        "原生立绘隔离验收只能保留 1 个可见角色；"
                        "空舞台仍可使用原有 HCB-only 验收"
                    )
                portrait_acceptance_mode = True
                acceptance_anchor = (
                    acceptance_scene.get("anchor")
                    if isinstance(acceptance_scene.get("anchor"), Mapping)
                    else {}
                )
                try:
                    anchor_offset = int(acceptance_anchor.get("hcb_offset"))
                except (TypeError, ValueError) as exc:
                    raise HcbError("原生立绘隔离验收挂点偏移无效") from exc
                anchor_timing = str(
                    acceptance_anchor.get("timing") or "before"
                ).strip().casefold()
                try:
                    fresh_acceptance_anchor = inspect_native_scene_anchor(
                        native_context,
                        anchor_offset,
                        anchor_timing,
                    )
                    fresh_patch = (
                        fresh_acceptance_anchor.get("patch")
                        if isinstance(fresh_acceptance_anchor.get("patch"), Mapping)
                        else {}
                    )
                    hook_return_offset = int(fresh_patch.get("return_offset"))
                except (HcbError, TypeError, ValueError) as exc:
                    raise HcbError(
                        f"无法复核原生立绘验收挂接返回地址: {exc}"
                    ) from exc
                if not fresh_acceptance_anchor.get("safe"):
                    raise HcbError("原生立绘验收挂点复核未通过")
                profile_seed = (
                    discovery.get("profile_seed")
                    if isinstance(discovery.get("profile_seed"), Mapping)
                    else {}
                )
                native_symbols = (
                    profile_seed.get("native_symbols")
                    if isinstance(profile_seed.get("native_symbols"), Mapping)
                    else {}
                )
                portrait_dispatcher = (
                    native_symbols.get("portrait_dispatcher")
                    if isinstance(native_symbols.get("portrait_dispatcher"), Mapping)
                    else {}
                )
                portrait_archive_name = str(
                    portrait_dispatcher.get("resource_archive_name") or ""
                ).strip().casefold()
                if portrait_archive_name not in {"graph.bin", "graph_bs.bin"}:
                    raise HcbError("目标发现报告没有唯一锁定角色资源归档")
                if profile is None:
                    raise HcbError("原生立绘隔离验收缺少当前目标的资源索引")
                try:
                    profile_game_dir = Path(
                        str(getattr(profile, "game_dir", "") or "")
                    ).expanduser().resolve()
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    raise HcbError(f"当前资源索引的游戏目录无效: {exc}") from exc
                if profile_game_dir != game_root:
                    raise HcbError(
                        "当前资源索引不属于原生目标目录，请重新扫描目标游戏"
                    )
                target_visual_assets = tuple(
                    dict(item)
                    for item in profile_background_assets
                    if str(
                        item.get("archive") or item.get("archive_name") or ""
                    ).strip().casefold()
                    == portrait_archive_name
                )
                graph_path = game_root / portrait_archive_name
                if graph_path.is_symlink() or not graph_path.is_file():
                    raise HcbError(
                        f"当前目标游戏缺少角色资源归档 {portrait_archive_name}: "
                        f"{graph_path}"
                    )
                try:
                    if graph_path.resolve().parent != game_root:
                        raise HcbError("目标角色资源归档逃逸原生目标目录")
                    graph_before = graph_path.stat()
                    target_graph_bs = graph_path.read_bytes()
                    graph_after = graph_path.stat()
                except OSError as exc:
                    raise HcbError(
                        f"无法稳定读取目标角色资源归档 {portrait_archive_name}: {exc}"
                    ) from exc
                if (
                    graph_before.st_size != graph_after.st_size
                    or graph_before.st_mtime_ns != graph_after.st_mtime_ns
                    or len(target_graph_bs) != graph_after.st_size
                ):
                    raise HcbError("读取期间目标角色资源归档已变化，请重试")
                try:
                    portrait_acceptance = build_native_portrait_acceptance_profile(
                        document,
                        native_context.analysis_document,
                        discovery,
                        target_graph_bs,
                        anchor_offset=anchor_offset,
                        hook_return_offset=hook_return_offset,
                        target_visual_assets=target_visual_assets,
                    )
                except NativePortraitAcceptanceError as exc:
                    raise HcbError(f"目标原生立绘 profile 抽取失败: {exc}") from exc
        if acceptance_mode:
            requested_runtime = str(
                dialogue_encoding or "inherit"
            ).strip().casefold()
            if requested_runtime == "uif":
                if not runtime_companion_source_dir:
                    raise HcbError("UIF 中文桥需要伴随组件来源目录")
                display_texts = [
                    str(line.get("text") or "")
                    for scene in acceptance_scenes
                    for line in (
                        scene.get("inserted_lines")
                        if isinstance(scene.get("inserted_lines"), list)
                        else []
                    )
                    if isinstance(line, Mapping) and str(line.get("text") or "")
                ]
                (
                    runtime_text_bridge,
                    runtime_text_companion_files,
                    runtime_text_companion_report,
                ) = _runtime_text_companion_for_target(
                    game_root,
                    runtime_companion_source_dir,
                    display_texts,
                    document.original_bytes,
                    encoding=document.encoding,
                )
            else:
                runtime_text_bridge = _runtime_text_bridge_for_target(
                    game_root,
                    encoding=document.encoding,
                    requested_encoding=dialogue_encoding,
                )
        available_resources = _native_story_resource_catalog(
            story,
            discovery,
            game_root,
            allow_cross_game_portraits=portrait_acceptance_mode,
        )
        candidate = build_native_story_memory_candidate(
            native_context,
            story,
            available_resources=available_resources,
            duration_ms=duration_ms,
            portrait_acceptance=portrait_acceptance,
            target_graph_bs=target_graph_bs,
            runtime_text_bridge=runtime_text_bridge,
        )
        report = copy.deepcopy(dict(candidate.report))
        if runtime_text_companion_files:
            if not isinstance(runtime_text_companion_report, Mapping):
                raise HcbError("UIF 中文桥候选缺少伴随组件报告")
            candidate_file_report = runtime_text_companion_report.get(
                "candidate_files"
            )
            if not isinstance(candidate_file_report, Mapping):
                raise HcbError("UIF 中文桥候选缺少文件身份报告")
            output_report = (
                dict(report.get("output"))
                if isinstance(report.get("output"), Mapping)
                else {}
            )
            output_report["runtime_text_companion_files"] = copy.deepcopy(
                dict(candidate_file_report)
            )
            report["output"] = output_report
            report["runtime_text_companion"] = copy.deepcopy(
                dict(runtime_text_companion_report)
            )
        candidate_kind = "native_compile_only"
        active_hcb_name: str | None = None
        if acceptance_mode:
            issues = _native_hcb_acceptance_issues(
                story,
                duration_ms=duration_ms,
                document=document,
                discovery=discovery,
                native_context=native_context,
                candidate_report=report,
                portrait_mode=portrait_acceptance_mode,
            )
            if issues:
                raise HcbError(
                    "通用 FVP 实机验收候选已阻止：" + "；".join(issues)
                )
            if document.path is None:
                raise HcbError("通用 FVP 实机验收缺少活动 HCB 文件名")
            active_hcb_name = document.path.name
            candidate_kind = (
                "native_portrait_acceptance"
                if portrait_acceptance_mode
                else "native_hcb_acceptance"
            )
            native_report = (
                report.get("native_target_candidate")
                if isinstance(report.get("native_target_candidate"), dict)
                else {}
            )
            native_report["mode"] = (
                "isolated_native_portrait_acceptance"
                if portrait_acceptance_mode
                else "isolated_hcb_acceptance"
            )
            native_report["acceptance_only"] = True
            native_report["active_hcb_name"] = active_hcb_name
            report["native_target_candidate"] = native_report
            compiled_background = (
                report.get("background")
                if isinstance(report.get("background"), Mapping)
                else {}
            )
            portrait_background_constraint = (
                "inherit_current_runtime_background"
                if str(compiled_background.get("build_mode") or "")
                .strip()
                .casefold()
                == "inherit_current"
                else "target_owned_background_direct_reference"
            )
            report["acceptance"] = {
                "schema": (
                    "fvp-studio-v2.native-portrait-acceptance.v1"
                    if portrait_acceptance_mode
                    else "fvp-studio-v2.native-hcb-acceptance.v1"
                ),
                "mode": (
                    f"isolated_copy_hcb_and_{portrait_archive_name}"
                    if portrait_acceptance_mode
                    else "isolated_copy_hcb_only"
                ),
                "active_hcb_name": active_hcb_name,
                "source_hcb_sha256": document.source_sha256,
                "constraints": (
                    [
                        "single_scene",
                        "single_visible_portrait",
                        portrait_background_constraint,
                        "zero_duration",
                        "dialogue_without_voice",
                        "exact_target_dispatcher_clone",
                        f"append_only_{portrait_archive_name}_body_face_pair",
                        "proven_native_lifecycle_cleanup",
                        "no_cg",
                        "no_audio_change",
                    ]
                    if portrait_acceptance_mode
                    else [
                        "single_scene",
                        "empty_stage",
                        "target_owned_background_direct_reference",
                        "zero_duration",
                        "dialogue_without_voice",
                        "hcb_only",
                        "no_cg",
                        "no_audio_change",
                    ]
                ),
                "production_write_gate_unchanged": True,
                "runtime_text_mode": (
                    str(runtime_text_bridge.get("mode"))
                    if isinstance(runtime_text_bridge, Mapping)
                    else "direct_hcb_encoding"
                ),
            }
            report["install_ready"] = True
            report["write_gate"] = {
                "enabled": True,
                "policy": (
                    "isolated_copy_native_portrait_acceptance"
                    if portrait_acceptance_mode
                    else "isolated_copy_hcb_only_acceptance"
                ),
                "scope": "acceptance_only",
                "blockers": [],
                "deferred_production_blockers": list(native_context.blockers),
            }
        else:
            report["install_ready"] = False
        report["download_ready"] = False
        with SESSION.lock:
            current_story = story_snapshot(SESSION.portrait_v2_scene)
            if SESSION.document is not document or document.source_sha256 != source_sha256:
                raise HcbError("通用 dry-run 期间来源 HCB 已变化，请重试")
            if SESSION.native_scene_memory_context is not native_context:
                raise HcbError("通用 dry-run 期间原生目标上下文已变化，请重试")
            if (
                SESSION.profile is not profile
                or str(getattr(SESSION.profile, "index_fingerprint", "") or "")
                != profile_fingerprint
            ):
                raise HcbError("通用 dry-run 期间目标资源索引已变化，请重试")
            if int(current_story.get("revision") or 0) != story_revision:
                raise HcbError("通用 dry-run 期间剧情草稿已变化，请重试")
            prior_candidate = SESSION.visual_scene_candidate
            if isinstance(prior_candidate, dict):
                _remove_v2_audio_build(prior_candidate.get("audio_build_root"))
            SESSION.visual_scene_candidate = {
                "candidate_kind": candidate_kind,
                "hcb": candidate.hcb,
                "graph_bs": candidate.graph_bs,
                "graph_bs_source_sha256": candidate.graph_bs_source_sha256,
                "resource_archives": dict(candidate.resource_archives),
                "resource_archive_files": dict(candidate.resource_archive_files),
                "resource_archive_source_sha256": dict(
                    candidate.resource_archive_source_sha256
                ),
                "runtime_text_companion_files": dict(
                    runtime_text_companion_files
                ),
                "report": report,
                "source_sha256": source_sha256,
                "story_revision": story_revision,
                "native_profile_sha256": native_context.profile_sha256,
                "active_hcb_name": active_hcb_name,
                "scene_count": int(
                    report.get("story_project", {}).get("scene_count", 1)
                    if isinstance(report.get("story_project"), dict)
                    else 1
                ),
                "audio_build_root": None,
            }
            output = report.get("output") if isinstance(report.get("output"), dict) else {}
            portrait_plan = (
                report.get("native_portrait_plan")
                if isinstance(report.get("native_portrait_plan"), dict)
                else None
            )
            portrait_note = (
                f"立绘 {int(portrait_plan.get('visible_actor_snapshot_count') or 0)} "
                "个快照已生成生命周期计划（尚未发射 HCB）；"
                if portrait_plan is not None
                else ""
            )
            if acceptance_mode:
                SESSION.last_action = (
                    "通用 FVP 单角色隔离验收候选通过：HCB 追加 "
                    f"{int(output.get('appended_bytes') or 0)} 字节；"
                    f"{portrait_archive_name} 仅追加身体/表情资源；"
                    "只开放带备份与回滚的事务安装"
                )
            else:
                SESSION.last_action = (
                    "通用 FVP 剧情编译验证通过：HCB 内存候选追加 "
                    f"{int(output.get('appended_bytes') or 0)} 字节；"
                    f"{portrait_note}"
                    "下载与安装仍由可信 profile / 实机验收门禁锁定"
                )
            SESSION.last_error = None
        self._send_json({"ok": True, "candidate": report})

    def _visual_scene_candidate_dry_run(self, body: dict[str, Any]) -> None:
        """Build every complete scene in memory; never write a target path."""

        from .hoshimemo_scene_hook import build_hoshimemo_story_project_candidate
        from .visual_scene_project import (
            VisualSceneProjectError,
            buildable_story_scenes,
            story_snapshot,
        )

        try:
            duration_ms = int(body.get("duration_ms", 1000))
        except (TypeError, ValueError) as exc:
            raise HcbError("场景转场时长必须是整数毫秒") from exc
        native_context = self._native_scene_memory_context_optional()
        if native_context is not None:
            self._visual_scene_native_candidate_dry_run(
                native_context,
                duration_ms,
                acceptance_mode=body.get("acceptance_mode") is True,
                dialogue_encoding=(
                    None
                    if body.get("dialogue_encoding") in (None, "")
                    else str(body.get("dialogue_encoding"))
                ),
                runtime_companion_source_dir=(
                    None
                    if body.get("runtime_companion_source_dir") in (None, "")
                    else str(body.get("runtime_companion_source_dir"))
                ),
            )
            return
        with SESSION.lock:
            document = SESSION.require_document()
            profile = SESSION.profile
            if profile is None:
                raise HcbError("尚未加载项目分析索引")
            story = story_snapshot(SESSION.portrait_v2_scene)
            story_revision = int(story.get("revision") or 0)
            source_sha256 = document.source_sha256
            profile_fingerprint = str(getattr(profile, "index_fingerprint", "") or "")
        try:
            buildable_scenes = buildable_story_scenes(story)
        except VisualSceneProjectError as exc:
            raise HcbError(str(exc)) from exc
        from .hoshimemo_audio_compile import (
            HOSHIMEMO_SCENE_PROFILE_ID,
            HoshimemoAudioCompileError,
            build_hoshimemo_audio_resources,
            collect_project_audio_references,
        )

        custom_audio_refs = collect_project_audio_references(buildable_scenes)
        if custom_audio_refs:
            profile_index = getattr(profile, "index_dir", None)
            if profile_index is None or Path(profile_index).expanduser().resolve() != default_index_dir().resolve():
                raise HcbError(
                    "当前项目不是已登记的 Hoshimemo 原生 target profile；"
                    "自定义 BGM / SE 仅可试听，拒绝猜测其它 FVP 游戏的加载 ABI"
                )

        needs_graph = False
        needs_graph_bs = False
        event_archive_names: set[str] = set()
        direct_event_visuals: list[dict[str, Any]] = []
        visible_actor_count = 0
        event_visual_count = 0
        for item in buildable_scenes:
            cue = item.get("cue") if isinstance(item.get("cue"), dict) else {}
            event_visual = (
                cue.get("event_visual")
                if isinstance(cue.get("event_visual"), dict)
                else {}
            )
            event_mode = str(event_visual.get("build_mode") or "").strip().casefold()
            if event_visual:
                event_visual_count += 1
                if event_mode == "direct_reference":
                    direct_event_visuals.append(event_visual)
                elif event_mode == "copy_hzc":
                    archive_name = str(
                        event_visual.get("archive_name") or ""
                    ).strip().casefold()
                    if archive_name not in {
                        "graph_vis.bin",
                        "graph_vis1.bin",
                        "graph_vis2.bin",
                    }:
                        raise HcbError("跨游戏 CG 的目标 graph_vis 归档类型无效")
                    event_archive_names.add(archive_name)
                continue
            background = (
                cue.get("background")
                if isinstance(cue.get("background"), dict)
                else {}
            )
            if str(background.get("build_mode") or "").strip().casefold() == "copy_hzc":
                needs_graph = True
            actors = cue.get("actors") if isinstance(cue.get("actors"), list) else []
            current_visible = [
                actor
                for actor in actors
                if isinstance(actor, dict) and bool(actor.get("visible", True))
            ]
            visible_actor_count += len(current_visible)
            needs_graph_bs = needs_graph_bs or bool(current_visible)

        game_dir = (
            document.path.expanduser().resolve().parent
            if document.path is not None
            else None
        )
        if (
            needs_graph
            or needs_graph_bs
            or event_archive_names
            or direct_event_visuals
            or custom_audio_refs
        ) and game_dir is None:
            raise HcbError("多场景构建含资源时，当前 HCB 必须来自可定位的游戏目录")
        target_graph: bytes | None = None
        if needs_graph:
            assert game_dir is not None
            graph_path = game_dir / "graph.bin"
            if not graph_path.is_file():
                raise HcbError(f"当前目标游戏缺少 graph.bin: {graph_path}")
            target_graph = graph_path.read_bytes()
        target_graph_bs: bytes | None = None
        if needs_graph_bs:
            assert game_dir is not None
            graph_path = game_dir / "graph_bs.bin"
            if not graph_path.is_file():
                raise HcbError(f"当前目标游戏缺少 graph_bs.bin: {graph_path}")
            target_graph_bs = graph_path.read_bytes()
        target_event_visual_archives: dict[str, bytes] = {}
        if direct_event_visuals:
            assert game_dir is not None
            from .cg_workspace import CgWorkspaceError, validate_staged_cg_source

            for event_visual in direct_event_visuals:
                try:
                    validate_staged_cg_source(
                        event_visual,
                        current_game_dir=game_dir,
                    )
                except CgWorkspaceError as exc:
                    raise HcbError(f"本作直引 CG 冻结身份复检失败: {exc}") from exc
        for archive_name in sorted(event_archive_names):
            assert game_dir is not None
            archive_path = game_dir / archive_name
            if not archive_path.is_file():
                raise HcbError(f"当前目标游戏缺少 {archive_name}: {archive_path}")
            target_event_visual_archives[archive_name] = archive_path.read_bytes()
        audio_build = None
        audio_build_root: Path | None = None
        if custom_audio_refs:
            assert game_dir is not None
            if V2_AUDIO_BUILD_ROOT.is_symlink():
                raise HcbError("V2 音频候选根不能是符号链接")
            V2_AUDIO_BUILD_ROOT.mkdir(parents=True, exist_ok=True)
            audio_build_root = (
                V2_AUDIO_BUILD_ROOT / f"candidate-{uuid4().hex}"
            ).resolve()
            try:
                audio_build = build_hoshimemo_audio_resources(
                    buildable_scenes,
                    target_game_dir=game_dir,
                    library_root=V2_AUDIO_LIBRARY_ROOT,
                    build_root=audio_build_root,
                    scene_profile_id=HOSHIMEMO_SCENE_PROFILE_ID,
                )
            except (HoshimemoAudioCompileError, OSError) as exc:
                _remove_v2_audio_build(audio_build_root)
                raise HcbError(str(exc)) from exc
        try:
            candidate = build_hoshimemo_story_project_candidate(
                document,
                profile,
                story,
                duration_ms=duration_ms,
                target_graph=target_graph,
                target_graph_bs=target_graph_bs,
                target_event_visual_archives=target_event_visual_archives,
                target_audio_build=audio_build,
            )
            with SESSION.lock:
                current_story = story_snapshot(SESSION.portrait_v2_scene)
                current_document = SESSION.require_document()
                if current_document.source_sha256 != source_sha256:
                    raise HcbError("dry-run 期间来源 HCB 已变化，请重试")
                if SESSION.profile is not profile or str(
                    getattr(SESSION.profile, "index_fingerprint", "") or ""
                ) != profile_fingerprint:
                    raise HcbError("dry-run 期间项目分析索引已变化，请重试")
                if int(current_story.get("revision") or 0) != story_revision:
                    raise HcbError("dry-run 期间剧情草稿已变化，请重试")
                prior_candidate = SESSION.visual_scene_candidate
                if isinstance(prior_candidate, dict):
                    _remove_v2_audio_build(prior_candidate.get("audio_build_root"))
                SESSION.visual_scene_candidate = {
                    "hcb": candidate.hcb,
                    "graph_bs": getattr(candidate, "graph_bs", None),
                    "graph_bs_source_sha256": getattr(
                        candidate,
                        "graph_bs_source_sha256",
                        None,
                    ),
                    "resource_archives": dict(
                        getattr(candidate, "resource_archives", {}) or {}
                    ),
                    "resource_archive_files": {
                        str(name): str(path)
                        for name, path in dict(
                            getattr(candidate, "resource_archive_files", {}) or {}
                        ).items()
                    },
                    "resource_archive_source_sha256": dict(
                        getattr(
                            candidate,
                            "resource_archive_source_sha256",
                            {},
                        )
                        or {}
                    ),
                    "report": copy.deepcopy(dict(candidate.report)),
                    "source_sha256": source_sha256,
                    "story_revision": story_revision,
                    "profile_fingerprint": profile_fingerprint,
                    "scene_count": len(buildable_scenes),
                    "filename": "fvp-studio-v2-story-project-candidate.hcb",
                    "audio_build_root": (
                        str(audio_build_root)
                        if audio_build_root is not None
                        else None
                    ),
                }
                SESSION.last_action = (
                    f"V2 剧情工程 dry-run 通过：{len(buildable_scenes)} 个挂接点，追加 "
                    f"{candidate.report['output']['appended_bytes']} 字节，"
                    f"{event_visual_count} 个 CG、{visible_actor_count} 个舞台角色、"
                    f"{len(custom_audio_refs)} 个项目音频（尚未写入游戏）"
                )
                SESSION.last_error = None
        except Exception:
            if audio_build_root is not None:
                _remove_v2_audio_build(audio_build_root)
            raise
        self._send_json({"ok": True, "candidate": candidate.report})

    def _visual_scene_candidate_download(self) -> None:
        """Download the current in-memory candidate without installing it."""

        from .visual_scene_project import story_snapshot

        with SESSION.lock:
            candidate = SESSION.visual_scene_candidate
            if not isinstance(candidate, dict):
                raise HcbError("尚未生成通过门禁的剧情候选")
            candidate_report = candidate.get("report")
            if (
                candidate.get("candidate_kind") == "native_compile_only"
                or isinstance(candidate_report, Mapping)
                and candidate_report.get("download_ready") is False
            ):
                raise HcbError(
                    "通用 FVP 候选当前仅供内存编译验证；可信 profile 与实机验收完成前不开放下载"
                )
            document = SESSION.require_document()
            story = story_snapshot(SESSION.portrait_v2_scene)
            if candidate.get("source_sha256") != document.source_sha256:
                SESSION.invalidate_visual_scene_candidate()
                raise HcbError("来源 HCB 已变化，候选已失效")
            if int(candidate.get("story_revision", -1)) != int(story.get("revision") or 0):
                SESSION.invalidate_visual_scene_candidate()
                raise HcbError("剧情草稿已变化，候选已失效")
            if candidate.get("profile_fingerprint") is not None and str(
                candidate.get("profile_fingerprint") or ""
            ) != str(getattr(SESSION.profile, "index_fingerprint", "") or ""):
                SESSION.invalidate_visual_scene_candidate()
                raise HcbError("项目分析索引已变化，候选已失效")
            payload = bytes(candidate["hcb"])
            filename = str(candidate.get("filename") or "fvp-studio-v2-scene-candidate.hcb")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _visual_scene_transaction_inputs(
        self,
        body: dict[str, Any],
    ) -> tuple[Any, Any]:
        """Snapshot one fresh candidate and its explicit isolated target."""

        from .hoshimemo_portrait_transaction import (
            HoshimemoPortraitTransactionError,
            SceneTransactionTarget,
            ValidatedSceneOutput,
        )
        from .visual_scene_project import story_snapshot

        target_value = str(body.get("target_dir", "")).strip()
        if not target_value:
            raise HcbError("隔离副本预检需要 target_dir")
        with SESSION.lock:
            candidate = SESSION.visual_scene_candidate
            if not isinstance(candidate, dict):
                raise HcbError("尚未生成通过门禁的剧情候选")
            candidate_report = candidate.get("report")
            if (
                candidate.get("candidate_kind") == "native_compile_only"
                or isinstance(candidate_report, Mapping)
                and candidate_report.get("install_ready") is False
            ):
                raise HcbError(
                    "通用 FVP 候选当前仅完成内存编译验证；可信 profile 与实机验收完成前禁止安装"
                )
            document = SESSION.require_document()
            story = story_snapshot(SESSION.portrait_v2_scene)
            if candidate.get("source_sha256") != document.source_sha256:
                SESSION.invalidate_visual_scene_candidate()
                raise HcbError("来源 HCB 已变化，剧情候选已失效")
            if int(candidate.get("story_revision", -1)) != int(story.get("revision") or 0):
                SESSION.invalidate_visual_scene_candidate()
                raise HcbError("剧情草稿已变化，剧情候选已失效")
            if candidate.get("profile_fingerprint") is not None and str(
                candidate.get("profile_fingerprint") or ""
            ) != str(getattr(SESSION.profile, "index_fingerprint", "") or ""):
                SESSION.invalidate_visual_scene_candidate()
                raise HcbError("项目分析索引已变化，剧情候选已失效")
            report = copy.deepcopy(candidate.get("report"))
            payload = bytes(candidate.get("hcb") or b"")
            active_hcb_name = candidate.get("active_hcb_name")
            graph_value = candidate.get("graph_bs")
            graph_payload = bytes(graph_value) if isinstance(graph_value, bytes) else None
            graph_source_sha256 = candidate.get("graph_bs_source_sha256")
            raw_resource_archives = candidate.get("resource_archives")
            raw_resource_archive_files = candidate.get("resource_archive_files")
            raw_resource_sources = candidate.get(
                "resource_archive_source_sha256"
            )
            raw_runtime_text_companion_files = candidate.get(
                "runtime_text_companion_files"
            )
            resource_archives: dict[str, bytes] = {}
            if raw_resource_archives is not None:
                if not isinstance(raw_resource_archives, dict):
                    raise HcbError("剧情候选资源归档集合无效")
                for raw_name, raw_payload in raw_resource_archives.items():
                    if not isinstance(raw_payload, bytes):
                        raise HcbError(f"剧情候选资源归档 {raw_name} 不是 bytes")
                    resource_archives[str(raw_name)] = raw_payload
            resource_archive_files: dict[str, Path] = {}
            if raw_resource_archive_files is not None:
                if not isinstance(raw_resource_archive_files, dict):
                    raise HcbError("剧情候选文件资源归档集合无效")
                for raw_name, raw_path in raw_resource_archive_files.items():
                    candidate_path = Path(str(raw_path)).expanduser()
                    if candidate_path.is_symlink():
                        raise HcbError(
                            f"剧情候选资源归档 {raw_name} 不能是符号链接"
                        )
                    candidate_path = candidate_path.resolve()
                    if not candidate_path.is_file():
                        raise HcbError(
                            f"剧情候选资源归档文件已失效: {candidate_path}"
                        )
                    resource_archive_files[str(raw_name)] = candidate_path
            resource_archive_sources: dict[str, str] = {}
            if raw_resource_sources is not None:
                if not isinstance(raw_resource_sources, dict):
                    raise HcbError("剧情候选资源归档源哈希集合无效")
                resource_archive_sources = {
                    str(name): str(value)
                    for name, value in raw_resource_sources.items()
                }
            runtime_text_companion_files: dict[str, bytes] = {}
            if raw_runtime_text_companion_files is not None:
                if not isinstance(raw_runtime_text_companion_files, dict):
                    raise HcbError("剧情候选运行时文字伴随组件集合无效")
                for raw_name, raw_payload in raw_runtime_text_companion_files.items():
                    if not isinstance(raw_payload, bytes):
                        raise HcbError(
                            f"运行时文字伴随组件 {raw_name} 不是 bytes"
                        )
                    runtime_text_companion_files[str(raw_name)] = raw_payload
            runtime_text_companion_report = (
                report.get("runtime_text_companion")
                if isinstance(report, Mapping)
                and isinstance(report.get("runtime_text_companion"), Mapping)
                else None
            )
            protected_roots: set[Path] = set()
            if V2_AUDIO_LIBRARY_ROOT.exists():
                protected_roots.add(V2_AUDIO_LIBRARY_ROOT.resolve())
            if document.path is not None:
                protected_roots.add(document.path.expanduser().resolve().parent)
            profile = SESSION.profile
            profile_game_dir = getattr(profile, "game_dir", None)
            active_target_override = _native_active_target_override_is_safe(
                body,
                report,
                target_root=target_value,
                document_path=document.path,
                profile_game_dir=profile_game_dir,
            )
            if (
                body.get("allow_active_target") is True
                and not active_target_override
            ):
                raise HcbError(
                    "显式活动目标授权未通过 acceptance-only 精确根目录门禁"
                )
            if profile_game_dir is not None:
                profile_root = Path(profile_game_dir).expanduser().resolve()
                if profile_root.exists():
                    protected_roots.add(profile_root)
            if isinstance(runtime_text_companion_report, Mapping):
                companion_source = str(
                    runtime_text_companion_report.get("source_package_root") or ""
                ).strip()
                if companion_source:
                    companion_source_path = Path(companion_source).expanduser().resolve()
                    if companion_source_path.exists():
                        protected_roots.add(companion_source_path)
            cue = story.get("cue") if isinstance(story.get("cue"), dict) else {}
            cue_background = (
                cue.get("background")
                if isinstance(cue.get("background"), dict)
                else {}
            )
            background_refs = [cue_background]
            if isinstance(cue_background.get("blur"), dict):
                background_refs.append(cue_background["blur"])
            for background_ref in background_refs:
                source_archive = str(
                    background_ref.get("archive_path") or ""
                ).strip()
                if not source_archive:
                    continue
                source_path = Path(source_archive).expanduser().resolve()
                if source_path.is_file():
                    protected_roots.add(source_path.parent)
            cue_event_visual = (
                cue.get("event_visual")
                if isinstance(cue.get("event_visual"), dict)
                else {}
            )
            cg_source_archive = str(
                cue_event_visual.get("archive_path") or ""
            ).strip()
            if cg_source_archive:
                cg_source_path = Path(cg_source_archive).expanduser().resolve()
                if cg_source_path.is_file():
                    protected_roots.add(cg_source_path.parent)
            cue_actors = cue.get("actors") if isinstance(cue.get("actors"), list) else []
            for actor in cue_actors:
                if not isinstance(actor, dict):
                    continue
                source_archive = str(actor.get("source_archive_path") or "").strip()
                if not source_archive:
                    continue
                source_path = Path(source_archive).expanduser().resolve()
                if source_path.is_file():
                    protected_roots.add(source_path.parent)
        if not isinstance(report, dict):
            raise HcbError("剧情候选缺少可审计报告")
        runtime_text_bridge_report = (
            report.get("runtime_text_bridge")
            if isinstance(report.get("runtime_text_bridge"), Mapping)
            else None
        )
        _verify_runtime_text_bridge_target(
            target_value,
            runtime_text_bridge_report,
            companion_files=runtime_text_companion_files,
            companion_report=runtime_text_companion_report,
        )
        try:
            source = report.get("source") if isinstance(report.get("source"), dict) else {}
            outputs = ValidatedSceneOutput(
                hcb=payload,
                source_sha256=str(source.get("hcb_sha256") or ""),
                plan_sha256=str(report.get("plan_sha256") or ""),
                emitter_id=str(report.get("emitter_id") or ""),
                profile_id=str(report.get("profile_id") or ""),
                validation=report,
                graph_bs=graph_payload,
                graph_bs_source_sha256=(
                    None
                    if graph_payload is None
                    else str(graph_source_sha256 or "")
                ),
                resource_archives=resource_archives,
                resource_archive_files=resource_archive_files,
                resource_archive_source_sha256=resource_archive_sources,
                runtime_text_companion_files=runtime_text_companion_files,
            )
            target = SceneTransactionTarget(
                root=Path(target_value),
                profile_id=outputs.profile_id,
                protected_roots=tuple(sorted(protected_roots, key=lambda item: str(item).casefold())),
                active_hcb_name=(
                    str(active_hcb_name)
                    if active_hcb_name not in (None, "")
                        else None
                    ),
                active_source_root_authorized=active_target_override,
            )
        except HoshimemoPortraitTransactionError as exc:
            raise HcbError(str(exc)) from exc
        return target, outputs

    def _visual_scene_install_prepare(self, body: dict[str, Any]) -> None:
        from .hoshimemo_portrait_transaction import (
            HoshimemoPortraitTransactionError,
            prepare_scene_transaction,
        )

        target, outputs = self._visual_scene_transaction_inputs(body)
        try:
            report = prepare_scene_transaction(target, outputs)
        except HoshimemoPortraitTransactionError as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.last_action = (
                f"剧情候选安装预检通过：活动 HCB {report['active_hcb_name']}（未写盘）"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "preflight": report})

    def _visual_scene_install_apply(self, body: dict[str, Any]) -> None:
        from .hoshimemo_portrait_transaction import (
            HoshimemoPortraitTransactionError,
            install_scene_transaction,
        )

        if body.get("confirm") is not True:
            raise HcbError("安装剧情候选需要 confirm=true")
        target, outputs = self._visual_scene_transaction_inputs(body)
        try:
            report = install_scene_transaction(target, outputs)
        except HoshimemoPortraitTransactionError as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.last_action = (
                f"已备份并安装剧情候选到隔离副本 {report['target_root']}"
            )
            SESSION.last_error = None
        self._send_json({"ok": True, "install": report})

    def _visual_scene_install_inspect(self, body: dict[str, Any]) -> None:
        from .hoshimemo_portrait_transaction import (
            HoshimemoPortraitTransactionError,
            inspect_scene_transaction,
        )

        manifest_value = str(body.get("manifest", "")).strip()
        if not manifest_value:
            raise HcbError("检查剧情事务需要 scene-transaction.json 路径")
        try:
            report = inspect_scene_transaction(Path(manifest_value))
        except HoshimemoPortraitTransactionError as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.last_action = f"已检查剧情事务清单 {report['manifest']}"
            SESSION.last_error = None
        self._send_json({"ok": True, "inspection": report})

    def _visual_scene_install_rollback(self, body: dict[str, Any]) -> None:
        from .hoshimemo_portrait_transaction import (
            HoshimemoPortraitTransactionError,
            rollback_scene_transaction,
        )

        if body.get("confirm") is not True:
            raise HcbError("回滚剧情候选需要 confirm=true")
        manifest_value = str(body.get("manifest", "")).strip()
        if not manifest_value:
            raise HcbError("回滚剧情候选需要 scene-transaction.json 路径")
        try:
            report = rollback_scene_transaction(Path(manifest_value))
        except HoshimemoPortraitTransactionError as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.last_action = f"已从剧情事务清单恢复隔离副本 {report['target_root']}"
            SESSION.last_error = None
        self._send_json({"ok": True, "rollback": report})

    def _portrait_v2_source_composite(self, query: dict[str, list[str]]) -> None:
        """Render a candidate or one scene actor without writing files."""

        try:
            from .portrait_project import PortraitProjectError
            from .portrait_workspace import render_layered_portrait_preview
            from .resource_builder import ResourceBuildError
        except ImportError as exc:
            raise HcbError(f"V2 分层立绘合成预览模块不可用: {exc}") from exc
        actor_id = query.get("actor_id", [""])[0].strip()
        if actor_id:
            scene = SESSION.portrait_scene_snapshot()
            actor = next(
                (item for item in scene["actors"] if item["actor_id"] == actor_id),
                None,
            )
            if actor is None:
                raise HcbError(f"找不到舞台角色: {actor_id}")
            source_archive_path = actor["source_archive_path"]
            draft = actor["draft"]
            default_frame = actor["expression_frame"]
        else:
            with SESSION.lock:
                source = SESSION.portrait_v2_source
                draft = copy.deepcopy(SESSION.portrait_v2_draft)
            if not source:
                raise HcbError("尚未扫描来源视觉 BIN")
            source_archive_path = source["archive_path"]
            default_frame = 0
        if not draft:
            raise HcbError("尚未生成分层立绘草稿")
        try:
            expression_frame = int(
                query.get(
                    "expression_frame",
                    query.get("frame", [str(default_frame)]),
                )[0]
            )
            payload, metadata = render_layered_portrait_preview(
                draft,
                Path(str(source_archive_path)),
                expression_frame=expression_frame,
            )
        except (ValueError, PortraitProjectError, ResourceBuildError, OSError) as exc:
            raise HcbError(str(exc)) from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        version = query.get("v", [""])[0].strip()
        self.send_header(
            "Cache-Control",
            "private, max-age=31536000, immutable" if version else "no-store",
        )
        self.send_header("X-FVP-Expression-Frame", str(metadata["expression_frame"]))
        self.send_header("X-FVP-Face-Offset", ",".join(map(str, metadata["face_offset"])))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _resolve_archive(self, archive_name: str, project_dir: str | Path | None = None) -> Path:
        name = str(archive_name).strip()
        if not name or Path(name).name != name or name in {".", ".."}:
            raise HcbError("archive 必须是单个文件名")
        explicit = str(project_dir or "").strip()
        active_parent = _active_document_parent()
        profile_dir = _profile_game_dir()
        if explicit:
            base = Path(explicit).expanduser().resolve()
            if not base.is_dir():
                raise HcbError(f"资源 project_dir 不存在: {base}")
            candidates = [base / name]
            # The UI may pass the active HCB/runner directory explicitly. If
            # that directory is an artifact-only folder, use a same-game
            # profile root; a deliberately different directory stays
            # authoritative and is never mixed with the profile install.
            if (
                active_parent is not None
                and base == active_parent
                and profile_dir is not None
                and profile_dir != base
                and _profile_fallback_matches_active_hcb(profile_dir)
            ):
                candidates.append(profile_dir / name)
        else:
            # A profile may describe the original analysis install while the
            # opened HCB belongs to a translated/test copy. Once a file HCB
            # is open, prefer that copy and only use a same-game profile
            # fallback when the active parent has no matching archive.
            candidates = [active_parent / name] if active_parent is not None else []
            if active_parent is None and profile_dir is not None:
                candidates.append(profile_dir / name)
            elif (
                active_parent is not None
                and profile_dir is not None
                and profile_dir != active_parent
                and _profile_fallback_matches_active_hcb(profile_dir)
            ):
                candidates.append(profile_dir / name)
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        raise HcbError(f"找不到资源归档: {name}；请先打开对应游戏的 HCB")

    def _asset_preview(self, query: dict[str, list[str]]) -> None:
        try:
            from .resource_builder import ResourceBuildError, preview_bin_entry
        except ImportError as exc:
            raise HcbError(f"资源预览模块不可用: {exc}") from exc
        archive = self._resolve_archive(
            query.get("archive", [""])[0],
            query.get("project_dir", [""])[0] or None,
        )
        try:
            entry_index = int(query.get("entry_index", [""])[0])
            frame = int(query.get("frame", ["0"])[0])
            # Thumbnails use a bounded PNG while the inspector can request
            # the original by omitting ``thumb``.  This keeps a 3840×2160 CG
            # from blocking the UI during page browsing and avoids rendering
            # stale/identical-looking previews caused by overlapping requests.
            thumb = query.get("thumb", [""])[0].casefold() in {"1", "true", "yes"}
            payload, info = preview_bin_entry(archive, entry_index, frame, max_dimension=640 if thumb else None)
        except (ValueError, ResourceBuildError) as exc:
            raise HcbError(str(exc)) from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _asset_info(self, query: dict[str, list[str]]) -> None:
        try:
            from .resource_builder import ResourceBuildError, inspect_bin_entry
        except ImportError as exc:
            raise HcbError(f"资源信息模块不可用: {exc}") from exc
        archive = self._resolve_archive(
            query.get("archive", [""])[0],
            query.get("project_dir", [""])[0] or None,
        )
        try:
            entry_index = int(query.get("entry_index", [""])[0])
            info = inspect_bin_entry(archive, entry_index)
        except (ValueError, ResourceBuildError) as exc:
            raise HcbError(str(exc)) from exc
        self._send_json({"ok": True, "info": info})

    def _audio_preview(self, query: dict[str, list[str]]) -> None:
        try:
            from .resource_builder import ResourceBuildError, preview_audio_entry
        except ImportError as exc:
            raise HcbError(f"音频预览模块不可用: {exc}") from exc
        archive = self._resolve_archive(
            query.get("archive", [""])[0],
            query.get("project_dir", [""])[0] or None,
        )
        try:
            entry_index = int(query.get("entry_index", [""])[0])
            payload, info = preview_audio_entry(archive, entry_index)
        except (ValueError, ResourceBuildError) as exc:
            raise HcbError(str(exc)) from exc
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", str(info["mime"]))
        self.send_header("Content-Disposition", "inline")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        try:
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            return

    def _links(self, query: dict[str, list[str]]) -> None:
        profile = self._profile_required()
        raw = query.get("offset", [""])[0]
        self._send_json({"ok": True, **profile.links_for_offset(_parse_offset(raw))})

    def _plan_status(self) -> None:
        with SESSION.lock:
            plan = json.loads(json.dumps(SESSION.plan, ensure_ascii=False))
            if SESSION.document is not None and SESSION.document.path is not None:
                plan["current_hcb"] = str(SESSION.document.path)
            self._send_json({"ok": True, "plan": plan})

    def _plan_add(self, body: dict[str, Any]) -> None:
        kind = str(body.get("kind", "")).strip().casefold()
        if kind not in {"text", "visual", "portrait_set", "audio"}:
            raise HcbError("kind 必须是 text、visual、portrait_set 或 audio")
        if kind == "portrait_set":
            source_archive = str(body.get("source_archive", "")).strip()
            target_archive = str(body.get("target_archive", "")).strip()
            if not source_archive or not target_archive:
                raise HcbError("整套立绘计划需要来源与目标 archive")
            try:
                indexes = {
                    key: int(body[key])
                    for key in (
                        "source_body_index",
                        "source_expression_index",
                        "target_body_index",
                        "target_expression_index",
                    )
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise HcbError("整套立绘计划需要四个有效的 archive index") from exc
            if any(index < 0 for index in indexes.values()):
                raise HcbError("整套立绘 archive index 不能为负数")
            if indexes["source_body_index"] == indexes["source_expression_index"]:
                raise HcbError("来源身体和表情不能是同一个条目")
            if indexes["target_body_index"] == indexes["target_expression_index"]:
                raise HcbError("目标身体和表情不能是同一个条目")
            offsets: dict[str, list[int]] = {}
            for key, label in (
                ("source_face_offset", "来源脸部坐标"),
                ("target_face_offset", "目标脸部坐标"),
            ):
                raw = body.get(key)
                if raw in (None, ""):
                    continue
                if not isinstance(raw, (list, tuple)) or len(raw) != 2:
                    raise HcbError(f"{label}必须是 [x, y]")
                try:
                    value = [int(raw[0]), int(raw[1])]
                except (TypeError, ValueError) as exc:
                    raise HcbError(f"{label}必须是两个整数") from exc
                if any(coordinate < 0 for coordinate in value):
                    raise HcbError(f"{label}不能为负数")
                offsets[key] = value
            raw_sync_log_avatar = body.get("sync_log_avatar", True)
            if isinstance(raw_sync_log_avatar, bool):
                sync_log_avatar = raw_sync_log_avatar
            elif isinstance(raw_sync_log_avatar, str) and raw_sync_log_avatar.strip().casefold() in {
                "true", "false", "1", "0", "yes", "no", "on", "off"
            }:
                sync_log_avatar = raw_sync_log_avatar.strip().casefold() in {
                    "true", "1", "yes", "on"
                }
            else:
                raise HcbError("sync_log_avatar 必须是布尔值")
            entry = {
                "source_archive": source_archive,
                "source_body_index": indexes["source_body_index"],
                "source_expression_index": indexes["source_expression_index"],
                "source_body_name": str(body.get("source_body_name", "")),
                "source_expression_name": str(body.get("source_expression_name", "")),
                "target_archive": target_archive,
                "target_body_index": indexes["target_body_index"],
                "target_expression_index": indexes["target_expression_index"],
                "target_body_name": str(body.get("target_body_name", "")),
                "target_expression_name": str(body.get("target_expression_name", "")),
                "frame_mode": "same_index",
                "sync_log_avatar": sync_log_avatar,
                "notes": str(body.get("notes", "")),
                **offsets,
            }
            target = SESSION.plan["portrait_sets"]
            target[:] = [
                item
                for item in target
                if (
                    item.get("target_archive"),
                    item.get("target_body_index"),
                    item.get("target_expression_index"),
                )
                != (
                    entry["target_archive"],
                    entry["target_body_index"],
                    entry["target_expression_index"],
                )
            ]
            target.append(entry)
            with SESSION.lock:
                SESSION.last_action = "已加入整套立绘替换计划"
                SESSION.last_error = None
                plan = json.loads(json.dumps(SESSION.plan, ensure_ascii=False))
            self._send_json({"ok": True, "plan": plan})
            return
        # Resource-only visual plans can originate from the asset index and do
        # not necessarily have a script call-site. Text/audio plans still need
        # an HCB string slot so they can be tied back to the script.
        raw_offset = body.get("offset")
        if kind in {"visual", "audio"} and raw_offset in (None, ""):
            offset: int | None = None
        else:
            try:
                offset = _parse_offset(raw_offset)
            except HcbError:
                raise HcbError("替换计划需要有效的 HCB offset")
        replacement_path = str(body.get("replacement_path", "")).strip()
        if kind != "text":
            if not replacement_path:
                raise HcbError("资源/语音计划需要 replacement_path")
            candidate = Path(replacement_path).expanduser().resolve()
            if not candidate.is_file():
                raise HcbError(f"替换文件不存在: {candidate}")
        if kind == "text":
            value = body.get("text")
            if not isinstance(value, str):
                raise HcbError("文本计划需要 text 字符串")
            entry: dict[str, Any] = {"offset": offset, "text": value}
            target = SESSION.plan["text_edits"]
        elif kind == "visual":
            raw_frame = body.get("frame")
            if raw_frame in (None, ""):
                frame = None
            else:
                try:
                    frame = int(raw_frame)
                except (TypeError, ValueError) as exc:
                    raise HcbError("视觉计划 frame 必须是非负整数") from exc
                if frame < 0:
                    raise HcbError("视觉计划 frame 必须是非负整数")
            entry = {
                "script_slot_offset": offset,
                "replacement_path": str(Path(replacement_path).expanduser().resolve()),
                "resource_name": str(body.get("resource_name", "")),
                "archive": str(body.get("archive", "")),
                "archive_index": body.get("archive_index"),
                "frame": frame,
                "fit": str(body.get("fit", "contain")),
                "notes": str(body.get("notes", "")),
            }
            target = SESSION.plan["visual_replacements"]
        else:
            entry = {
                "text_slot_offset": offset,
                "replacement_path": str(Path(replacement_path).expanduser().resolve()),
                "voice_id": body.get("voice_id"),
                "voice_name": str(body.get("voice_name", "")),
                "archive": str(body.get("archive", "voice.bin")),
                "archive_index": body.get("archive_index"),
                "notes": str(body.get("notes", "")),
            }
            target = SESSION.plan["audio_replacements"]
        key = "offset" if kind == "text" else "script_slot_offset" if kind == "visual" else "text_slot_offset"
        if kind in {"visual", "audio"} and offset is None:
            archive_key = (
                entry.get("archive"),
                entry.get("archive_index"),
                entry.get("frame") if kind == "visual" else None,
            )
            target[:] = [
                item for item in target
                if (
                    item.get("archive"),
                    item.get("archive_index"),
                    item.get("frame") if kind == "visual" else None,
                ) != archive_key
            ]
        else:
            target[:] = [item for item in target if item.get(key) != offset]
        target.append(entry)
        with SESSION.lock:
            location = f"0x{offset:X}" if offset is not None else "资源条目"
            SESSION.last_action = f"已加入 {kind} 替换计划 {location}"
            SESSION.last_error = None
        self._send_json({"ok": True, "plan": SESSION.plan})

    def _plan_remove(self, body: dict[str, Any]) -> None:
        kind = str(body.get("kind", "")).strip().casefold()
        targets = {
            "text": "text_edits",
            "visual": "visual_replacements",
            "portrait_set": "portrait_sets",
            "audio": "audio_replacements",
        }
        key = targets.get(kind)
        if key is None:
            raise HcbError("kind 必须是 text、visual、portrait_set 或 audio")
        try:
            index = int(body.get("index"))
        except (TypeError, ValueError) as exc:
            raise HcbError("计划条目 index 无效") from exc
        with SESSION.lock:
            items = SESSION.plan[key]
            if index < 0 or index >= len(items):
                raise HcbError("计划条目不存在或已经被移除")
            removed = items.pop(index)
            SESSION.last_action = f"已移除 {kind} 替换计划 #{index + 1}"
            SESSION.last_error = None
            plan = json.loads(json.dumps(SESSION.plan, ensure_ascii=False))
        self._send_json({"ok": True, "removed": removed, "plan": plan})

    def _plan_clear(self, body: dict[str, Any]) -> None:
        kind = str(body.get("kind", "all")).strip().casefold() or "all"
        targets = {
            "text": ("text_edits",),
            "visual": ("visual_replacements", "portrait_sets"),
            "portrait_set": ("portrait_sets",),
            "audio": ("audio_replacements",),
            "all": ("text_edits", "visual_replacements", "portrait_sets", "audio_replacements"),
        }
        keys = targets.get(kind)
        if keys is None:
            raise HcbError("kind 必须是 text、visual、portrait_set、audio 或 all")
        with SESSION.lock:
            removed = sum(len(SESSION.plan[key]) for key in keys)
            for key in keys:
                SESSION.plan[key].clear()
            SESSION.last_action = f"已清空 {removed} 条替换计划"
            SESSION.last_error = None
            plan = json.loads(json.dumps(SESSION.plan, ensure_ascii=False))
        self._send_json({"ok": True, "removed": removed, "plan": plan})

    def _plan_save(self, body: dict[str, Any]) -> None:
        with SESSION.lock:
            source = SESSION.document.path if SESSION.document is not None else None
            requested = str(body.get("path", "")).strip()
            if requested:
                output = Path(requested).expanduser().resolve()
            elif source is not None:
                output = source.with_name(f"{source.stem}.fvpstudio.plan.json")
            else:
                raise HcbError("没有默认计划输出路径，请填写 path")
            if output.exists() and not bool(body.get("overwrite", False)):
                raise HcbError(f"输出已存在: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            payload = dict(SESSION.plan)
            payload["hcb"] = str(source) if source is not None else None
            payload["profile"] = SESSION.profile.summary if SESSION.profile is not None else None
            output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            SESSION.last_action = f"已保存替换计划 {output}"
            SESSION.last_error = None
        self._send_json({"ok": True, "path": str(output), "size": output.stat().st_size})

    def _plan_load(self, body: dict[str, Any]) -> None:
        raw = str(body.get("path", "")).strip()
        if not raw:
            raise HcbError("加载计划需要 path")
        path = Path(raw).expanduser().resolve()
        if not path.is_file():
            raise HcbError(f"计划文件不存在: {path}")
        try:
            plan = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HcbError(f"计划 JSON 无法读取: {exc}") from exc
        if not isinstance(plan, dict) or not isinstance(plan.get("text_edits", []), list) or not isinstance(plan.get("visual_replacements", []), list) or not isinstance(plan.get("portrait_sets", []), list) or not isinstance(plan.get("audio_replacements", []), list):
            raise HcbError("计划 JSON 格式不正确")
        with SESSION.lock:
            SESSION.plan = {
                "schema": str(plan.get("schema", "fvp-studio-replacement-plan.v1")),
                "hcb": str(plan.get("hcb")) if plan.get("hcb") else None,
                "text_edits": list(plan.get("text_edits", [])),
                "visual_replacements": list(plan.get("visual_replacements", [])),
                "portrait_sets": list(plan.get("portrait_sets", [])),
                "audio_replacements": list(plan.get("audio_replacements", [])),
            }
            SESSION.last_action = f"已加载替换计划 {path}"
            SESSION.last_error = None
        self._send_json({"ok": True, "path": str(path), "plan": SESSION.plan})

    def _plan_validate(self) -> None:
        errors: list[str] = []
        warnings: list[str] = []
        resolved: dict[str, int] = {"text": 0, "visual": 0, "portrait_set": 0, "audio": 0}
        document = SESSION.document
        if document is None:
            errors.append("尚未打开 HCB，无法验证偏移")
        else:
            try:
                validate_plan_hcb_binding(SESSION.plan, document)
            except HcbError as exc:
                errors.append(str(exc))
        text_offsets: set[int] = set()
        visual_offsets: set[int] = set()
        audio_offsets: set[int] = set()
        visual_targets: set[tuple[str, int, int]] = set()
        log_avatar_targets: dict[tuple[str, int, int], str] = {}
        for item in SESSION.plan.get("text_edits", []):
            try:
                offset = _parse_offset(item.get("offset"))
                text = item.get("text")
                if not isinstance(text, str):
                    raise HcbError("text 不是字符串")
                if offset in text_offsets:
                    errors.append(f"文本计划重复偏移 0x{offset:X}")
                text_offsets.add(offset)
                if document is not None:
                    instruction = document.find(offset)
                    if instruction.opcode != 0x0E:
                        errors.append(f"文本计划 0x{offset:X} 不是 push_string")
                    if len(encode_text(text, document.encoding)) + 1 > 0xFF:
                        errors.append(f"文本计划 0x{offset:X} 超过长度字段")
                resolved["text"] += 1
            except (HcbError, KeyError, TypeError, ValueError) as exc:
                errors.append(f"文本计划无效: {exc}")
        for item in SESSION.plan.get("visual_replacements", []):
            try:
                raw_offset = item.get("script_slot_offset")
                offset = None if raw_offset in (None, "") else _parse_offset(raw_offset)
                if offset is not None:
                    if offset in visual_offsets:
                        errors.append(f"视觉计划重复偏移 0x{offset:X}")
                    visual_offsets.add(offset)
                replacement = Path(str(item.get("replacement_path", ""))).expanduser()
                if not replacement.is_file():
                    errors.append(f"视觉替换文件不存在: {replacement}")
                if not item.get("archive"):
                    errors.append(f"视觉计划 {('0x%X' % offset) if offset is not None else '<资源>'} 缺少 archive")
                if item.get("archive_index") is None:
                    errors.append(f"视觉计划 {('0x%X' % offset) if offset is not None else '<资源>'} 缺少 archive_index")
                raw_frame = item.get("frame")
                if raw_frame not in (None, "") and int(raw_frame) < 0:
                    errors.append(f"视觉计划 {('0x%X' % offset) if offset is not None else '<资源>'} 的 frame 无效")
                if item.get("archive") and item.get("archive_index") is not None:
                    visual_targets.add(
                        (
                            str(item["archive"]),
                            int(item["archive_index"]),
                            int(raw_frame or 0),
                        )
                    )
                if SESSION.profile is not None and offset is not None:
                    links = SESSION.profile.visuals_by_offset.get(offset, ())
                    if not links:
                        warnings.append(f"视觉计划 0x{offset:X} 没有索引关联，构建前请确认它是资源调用偏移")
                    elif item.get("resource_name") and item.get("resource_name") not in {str(link.get("resource_name", "")) for link in links}:
                        warnings.append(f"视觉计划 0x{offset:X} 的 resource_name 与索引关联不同")
                resolved["visual"] += 1
            except (HcbError, KeyError, TypeError, ValueError) as exc:
                errors.append(f"视觉计划无效: {exc}")
        for item in SESSION.plan.get("portrait_sets", []):
            try:
                from .resource_builder import ResourceBuildError, inspect_bin_entry, inspect_portrait_set

                source_name = str(item.get("source_archive", "")).strip()
                target_name = str(item.get("target_archive", "")).strip()
                if not source_name or not target_name:
                    raise HcbError("缺少来源或目标 archive")
                source_archive = self._resolve_archive(source_name, {})
                target_archive = self._resolve_archive(target_name, {})
                inspection = inspect_portrait_set(source_archive, target_archive, item)
                target_keys = {
                    (target_name, int(inspection["target_body_index"]), 0),
                    *{
                        (target_name, int(inspection["target_expression_index"]), frame)
                        for frame in range(int(inspection["mapped_frames"]))
                    },
                }
                overlap = sorted(target_keys.intersection(visual_targets))
                if overlap:
                    archive_name, entry_index, frame = overlap[0]
                    errors.append(
                        f"整套立绘与其它计划重复替换 {archive_name}#{entry_index} frame {frame}"
                    )
                visual_targets.update(target_keys)
                unused = int(inspection.get("unused_source_frames", 0))
                if unused:
                    warnings.append(f"整套立绘来源多出 {unused} 帧；只映射目标需要的帧")
                log_mapping = inspection.get("log_avatar_sync")
                if log_mapping is not None:
                    log_archive_name = str(log_mapping["archive"])
                    log_entry_index = int(log_mapping["entry_index"])
                    log_key = (log_archive_name, log_entry_index, 0)
                    mapping_id = str(log_mapping["mapping_id"])
                    previous_mapping_id = log_avatar_targets.get(log_key)
                    if previous_mapping_id is not None:
                        if previous_mapping_id != mapping_id:
                            errors.append(
                                f"LOG 头像图集映射冲突: {previous_mapping_id} / {mapping_id}"
                            )
                    elif log_key in visual_targets:
                        errors.append(
                            f"整套立绘与其它计划重复替换 {log_archive_name}#{log_entry_index} frame 0"
                        )
                    else:
                        log_archive = self._resolve_archive(log_archive_name, {})
                        log_info = inspect_bin_entry(log_archive, log_entry_index)
                        expected_width, expected_height = (
                            int(value) for value in log_mapping["atlas_size"]
                        )
                        if int(log_info["frame_count"]) != 1 or (
                            int(log_info["width"]), int(log_info["height"])
                        ) != (expected_width, expected_height):
                            raise ResourceBuildError(
                                f"LOG 头像图集 {log_archive_name}#{log_entry_index} 结构不匹配"
                            )
                        log_avatar_targets[log_key] = mapping_id
                        visual_targets.add(log_key)
                resolved["portrait_set"] += 1
            except (HcbError, ResourceBuildError, KeyError, TypeError, ValueError) as exc:
                errors.append(f"整套立绘计划无效: {exc}")
        for item in SESSION.plan.get("audio_replacements", []):
            try:
                raw_offset = item.get("text_slot_offset")
                offset = None if raw_offset in (None, "") else _parse_offset(raw_offset)
                if offset is not None:
                    if offset in audio_offsets:
                        errors.append(f"语音计划重复偏移 0x{offset:X}")
                    audio_offsets.add(offset)
                replacement = Path(str(item.get("replacement_path", ""))).expanduser()
                if not replacement.is_file():
                    errors.append(f"语音替换文件不存在: {replacement}")
                if not item.get("archive"):
                    errors.append(f"语音计划 {('0x%X' % offset) if offset is not None else '<资源>'} 缺少 archive")
                if item.get("archive_index") is None:
                    errors.append(f"语音计划 {('0x%X' % offset) if offset is not None else '<资源>'} 缺少 archive_index")
                resolved["audio"] += 1
            except (HcbError, KeyError, TypeError, ValueError) as exc:
                errors.append(f"语音计划无效: {exc}")
        result = {"ok": not errors, "errors": errors, "warnings": warnings, "resolved": resolved}
        SESSION.last_action = "替换计划校验完成"
        SESSION.last_error = errors[0] if errors else None
        self._send_json(result)

    def _plan_apply_text(self) -> None:
        document = SESSION.require_editable()
        validate_plan_hcb_binding(SESSION.plan, document)
        edits = SESSION.plan.get("text_edits", [])
        candidate = document.clone()
        try:
            for item in edits:
                value = item.get("text")
                if not isinstance(value, str):
                    raise HcbError("文本计划 text 必须是字符串")
                candidate.edit_string(_parse_offset(item.get("offset")), value)
        except (HcbError, KeyError, TypeError, ValueError) as exc:
            raise HcbError(f"文本计划未应用，当前 HCB 未改变: {exc}") from exc
        with SESSION.lock:
            SESSION.document = candidate
            SESSION.last_action = f"已将 {len(edits)} 条文本计划应用到 HCB"
            SESSION.last_error = None
        self._send_json({"ok": True, "applied": len(edits), "summary": candidate.summary()})

    def _runner_defaults(self) -> dict[str, str | None]:
        executable = Path(__file__).resolve().parents[2] / "fvp_repos" / "rfvp" / "target" / "release" / "rfvp.exe"
        project = _default_project_dir()
        return {
            "executable": str(executable) if executable.is_file() else None,
            "project_dir": str(project) if project is not None else None,
        }

    def _runner_snapshot(self) -> dict[str, Any]:
        # Keep the lock order consistent with EditorSession.status(): acquire
        # the document/session lock (inside _runner_defaults) before the runner
        # lock.  The UI requests /api/status and /api/runner/status in parallel;
        # doing this lookup while holding runner_lock can deadlock those two
        # requests (session -> runner versus runner -> session).
        defaults = self._runner_defaults()
        with SESSION.runner_lock:
            process = SESSION.runner
            return {
                "running": process is not None and process.poll() is None,
                "pid": process.pid if process is not None else None,
                "command": list(SESSION.runner_command),
                "started_at": SESSION.runner_started_at,
                "exit_code": process.poll() if process is not None else None,
                "log": list(SESSION.runner_log)[-80:],
                "defaults": defaults,
            }

    def _runner_status(self) -> None:
        self._send_json({"ok": True, **self._runner_snapshot()})

    def _runner_reader(self, process: subprocess.Popen[str]) -> None:
        stream = process.stdout
        if stream is not None:
            for line in stream:
                with SESSION.runner_lock:
                    SESSION.runner_log.append(line.rstrip("\r\n"))
        code = process.wait()
        with SESSION.runner_lock:
            SESSION.runner_log.append(f"[FVP Studio V2] RFVP 已退出，exit_code={code}")
            SESSION.last_action = f"RFVP 已退出 ({code})"

    def _runner_start(self, body: dict[str, Any]) -> None:
        with SESSION.runner_lock:
            if SESSION.runner is not None and SESSION.runner.poll() is None:
                raise HcbError("RFVP 已在运行")
        defaults = self._runner_defaults()
        executable = Path(str(body.get("executable") or defaults["executable"] or "")).expanduser().resolve()
        project_dir = Path(str(body.get("project_dir") or defaults["project_dir"] or "")).expanduser().resolve()
        if not executable.is_file():
            raise HcbError(f"RFVP 可执行文件不存在: {executable}")
        if not project_dir.is_dir():
            raise HcbError(f"游戏目录不存在: {project_dir}")
        nls = str(body.get("encoding", "sjis")).casefold()
        if nls not in {"sjis", "gbk", "utf8"}:
            raise HcbError("RFVP 编码必须是 sjis、gbk 或 utf8")
        extra = body.get("extra_args", [])
        if not isinstance(extra, list) or len(extra) > 20 or any(not isinstance(item, str) for item in extra):
            raise HcbError("extra_args 必须是最多 20 个字符串的数组")
        command = [str(executable), "--project-dir", str(project_dir), "--nls", nls, *extra]
        if bool(body.get("system_font", False)):
            command.append("--system-font")
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            process = subprocess.Popen(
                command,
                cwd=str(project_dir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creationflags,
            )
        except OSError as exc:
            raise HcbError(f"启动 RFVP 失败: {exc}") from exc
        with SESSION.runner_lock:
            SESSION.runner = process
            SESSION.runner_command = command
            SESSION.runner_started_at = time.time()
            SESSION.runner_log.clear()
            SESSION.runner_log.append("[FVP Studio V2] 启动: " + " ".join(command))
        threading.Thread(target=self._runner_reader, args=(process,), daemon=True).start()
        self._send_json({"ok": True, **self._runner_snapshot()})

    def _runner_stop(self) -> None:
        with SESSION.runner_lock:
            process = SESSION.runner
        if process is None or process.poll() is not None:
            self._send_json({"ok": True, "stopped": False, **self._runner_snapshot()})
            return
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        with SESSION.runner_lock:
            SESSION.runner_log.append("[FVP Studio V2] 已请求停止 RFVP")
        self._send_json({"ok": True, "stopped": True, **self._runner_snapshot()})

    def _resource_build(self, body: dict[str, Any]) -> None:
        try:
            from .resource_builder import ResourceBuildError, build_archive_patch, build_plan
        except ImportError as exc:
            raise HcbError(f"资源构建模块不可用: {exc}") from exc
        output_value = str(body.get("output", "")).strip()
        if not output_value:
            raise HcbError("资源构建需要 output 路径")
        output = Path(output_value).expanduser().resolve()
        direct_replacements = isinstance(body.get("replacements"), list)
        if direct_replacements and output.exists() and not bool(body.get("overwrite", False)):
            raise HcbError(f"输出已存在: {output}")
        try:
            if direct_replacements:
                archive = Path(str(body.get("archive", ""))).expanduser().resolve()
                report = build_archive_patch(archive, body["replacements"], output)
            else:
                with SESSION.lock:
                    plan = body.get("plan") if isinstance(body.get("plan"), dict) else SESSION.plan
                project_value = str(body.get("project_dir", "")).strip()
                # An explicit request wins; otherwise the file-backed HCB's
                # parent is authoritative.  The profile directory is only a
                # fallback for a session without a usable HCB path.
                project_dir = (
                    Path(project_value).expanduser().resolve()
                    if project_value
                    else _default_project_dir()
                )
                if project_dir is None:
                    raise HcbError("计划构建需要 project_dir")
                report = build_plan(plan, project_dir, output)
        except ResourceBuildError as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.last_action = f"已构建资源补丁 {output}"
            SESSION.last_error = None
        self._send_json({"ok": True, "report": report})

    def _install_copy(self, body: dict[str, Any]) -> None:
        if body.get("confirm") is not True:
            raise HcbError("安装到游戏副本必须显式 confirm=true")
        target_value = str(body.get("target_dir", "")).strip()
        if not target_value:
            raise HcbError("安装需要 target_dir")
        target = Path(target_value).expanduser().resolve()
        if not target.is_dir():
            raise HcbError(f"目标游戏目录不存在: {target}")
        known_originals: set[Path] = set()
        with SESSION.lock:
            if SESSION.document is not None and SESSION.document.path is not None:
                known_originals.add(SESSION.document.path.parent.resolve())
            if SESSION.profile is not None and SESSION.profile.game_dir is not None and SESSION.profile.game_dir.exists():
                known_originals.add(SESSION.profile.game_dir.resolve())
        if any(
            target == original
            or target.is_relative_to(original)
            or original.is_relative_to(target)
            for original in known_originals
        ):
            raise HcbError("拒绝安装到已知原始游戏目录、其子目录或父目录，请先复制出一个测试目录")
        hcb_output = str(body.get("hcb_output", "")).strip()
        patch_dir_value = str(body.get("patch_dir", "")).strip()
        if not hcb_output and not patch_dir_value:
            raise HcbError("至少提供 hcb_output 或 patch_dir")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_root = target / ".fvpstudio-backups" / stamp
        backup_root.mkdir(parents=True, exist_ok=True)
        installed_hcb: dict[str, Any] | None = None
        if hcb_output:
            source_hcb = Path(hcb_output).expanduser().resolve()
            if not source_hcb.is_file():
                raise HcbError(f"HCB 输出不存在: {source_hcb}")
            hcb_name = str(body.get("hcb_name", source_hcb.name))
            if Path(hcb_name).name != hcb_name:
                raise HcbError("hcb_name 必须是文件名")
            destination = target / hcb_name
            backup = backup_root / "hcb" / destination.name
            backup.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_file():
                shutil.copy2(destination, backup)
            shutil.copy2(source_hcb, destination)
            installed_hcb = {
                "source": str(source_hcb),
                "destination": str(destination),
                "backup": str(backup) if backup.is_file() else None,
                "backup_sha256": hashlib.sha256(backup.read_bytes()).hexdigest() if backup.is_file() else None,
                "installed_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            }
        archive_report: dict[str, Any] | None = None
        if patch_dir_value:
            try:
                from .resource_builder import ResourceBuildError, install_patch_set
                archive_report = install_patch_set(Path(patch_dir_value), target, backup_root / "archives")
            except (ImportError, ResourceBuildError) as exc:
                raise HcbError(str(exc)) from exc
        manifest = {"schema": "fvp-studio-copy-install.v1", "target_dir": str(target), "backup_root": str(backup_root), "hcb": installed_hcb, "archives": archive_report}
        manifest_path = backup_root / "install-manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        SESSION.last_action = f"已安装到游戏副本 {target}"
        SESSION.last_error = None
        self._send_json({"ok": True, **manifest, "manifest": str(manifest_path)})

    def _rollback_copy_install(self, body: dict[str, Any]) -> None:
        if body.get("confirm") is not True:
            raise HcbError("恢复测试副本必须显式 confirm=true")
        manifest_value = str(body.get("manifest", "")).strip()
        if not manifest_value:
            raise HcbError("恢复需要 install-manifest.json 路径")
        manifest_path = Path(manifest_value).expanduser().resolve()
        try:
            manifest_preview = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HcbError(f"无法读取安装清单: {exc}") from exc
        target = Path(str(manifest_preview.get("target_dir", ""))).expanduser().resolve()
        known_originals: set[Path] = set()
        with SESSION.lock:
            if SESSION.document is not None and SESSION.document.path is not None:
                known_originals.add(SESSION.document.path.parent.resolve())
            if SESSION.profile is not None and SESSION.profile.game_dir is not None and SESSION.profile.game_dir.exists():
                known_originals.add(SESSION.profile.game_dir.resolve())
        if any(target == original or target.is_relative_to(original) or original.is_relative_to(target) for original in known_originals):
            raise HcbError("拒绝恢复已知原始游戏目录、其子目录或父目录")
        try:
            from .resource_builder import ResourceBuildError, restore_copy_install
            report = restore_copy_install(manifest_path)
        except (ImportError, ResourceBuildError) as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.last_action = f"已恢复测试副本 {report['target_dir']}"
            SESSION.last_error = None
        self._send_json({"ok": True, **report})

    def _inspect_copy_install(self, body: dict[str, Any]) -> None:
        manifest_value = str(body.get("manifest", "")).strip()
        if not manifest_value:
            raise HcbError("检查需要 install-manifest.json 路径")
        try:
            from .resource_builder import ResourceBuildError, inspect_copy_install
            report = inspect_copy_install(Path(manifest_value))
        except (ImportError, ResourceBuildError) as exc:
            raise HcbError(str(exc)) from exc
        with SESSION.lock:
            SESSION.last_action = f"已检查安装清单 {report['manifest']}"
            SESSION.last_error = None
        self._send_json({"ok": True, **report})

    def _header(self) -> None:
        document = SESSION.require_document()
        self._send_json(
            {
                "ok": True,
                "header": document.to_json()["header"],
                "warnings": document.warnings,
            }
        )

    def _static(self, request_path: str) -> None:
        relative = request_path.lstrip("/") or "index.html"
        candidate = (WEB_ROOT / relative).resolve()
        if WEB_ROOT not in candidate.parents and candidate != WEB_ROOT:
            self._send_error("非法路径", HTTPStatus.NOT_FOUND)
            return
        if not candidate.is_file():
            self._send_error("页面不存在", HTTPStatus.NOT_FOUND)
            return
        payload = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or candidate.suffix in {".js", ".json"}:
            content_type += "; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def run_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = False,
    initial_file: Path | None = None,
    encoding: str = "sjis",
) -> None:
    if initial_file is not None:
        try:
            SESSION.set_document(load(initial_file, encoding))
        except HcbError as exc:
            SESSION.last_error = str(exc)
            print(f"[FVP Studio V2] 初始文件打开失败: {exc}")
    server = ThreadingHTTPServer((host, port), Handler)
    address = f"http://{host}:{port}/"
    print(f"FVP Studio running at {address}")
    if open_browser:
        threading.Timer(0.25, lambda: webbrowser.open(address)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nFVP Studio stopped")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="FVP Studio local HCB editor")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", help="open the web UI")
    parser.add_argument("--file", type=Path, help="open an HCB on startup")
    parser.add_argument("--encoding", default="sjis", choices=["sjis", "gbk", "utf8"])
    args = parser.parse_args()
    run_server(args.host, args.port, args.open, args.file, args.encoding)


if __name__ == "__main__":
    main()
